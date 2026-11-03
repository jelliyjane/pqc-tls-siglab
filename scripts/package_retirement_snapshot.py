#!/usr/bin/env python3
"""Package source/data snapshots, excluding credentials and runtime binaries.

This is an archival filter, not a general-purpose secret detection guarantee.
Review the exclusion report before publication. The full local backup is kept.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile

EXTENSIONS = {'.c','.h','.cc','.cpp','.hpp','.s','.S','.asm','.py','.sh','.bash',
              '.pl','.pm','.cmake','.in','.patch','.diff','.rs','.toml','.cfg',
              '.conf','.ini','.yml','.yaml','.json','.jsonl','.csv','.tsv',
              '.model','.npz','.npy','.txt','.md','.rst','.bt','.def','.map',
              '.mk','.make','.bat','.ps1','.pqi','.pyi'}
NAMES = {'Makefile','CMakeLists.txt','Configure','config','configure','LICENSE',
         'LICENSE.txt','LICENSE.md','COPYING','NOTICE','AUTHORS','README'}
PRUNE = {'.git','.ssh','.aws','.config','.cache','__pycache__','node_modules',
         '.codex','certs','certificates','pcaps','install','backups'}
BLOCK_NAMES = {'AGENTS.md','CODEX_HANDOFF.md','.env','.git-credentials','.netrc',
               'credentials','known_hosts','authorized_keys','id_rsa','id_ed25519'}
SECRET = re.compile(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|'
                    rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b|'
                    rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|'
                    rb'\b(?:CLIENT_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET) [0-9a-fA-F]{32,}|'
                    rb'^\s*(?:aws_secret_access_key|aws_session_token)\s*=\s*\S+', re.MULTILINE)
PERSONAL = re.compile(rb'(?:010[- ]?6566[- ]?7847|\+82[- ]?10[- ]?6566[- ]?7847)')

def inspect(path):
    if path.name in BLOCK_NAMES or path.name.startswith('.env'):
        return None,'credential-or-instruction-name'
    if path.is_symlink() or not path.is_file():
        return None,'not-regular-file'
    packed=path.name.endswith(('.csv.gz','.json.gz','.jsonl.gz','.tsv.gz'))
    if path.suffix not in EXTENSIONS and path.name not in NAMES and not packed:
        return None,'non-source-data-format'
    payload=path.read_bytes()
    try:
        check=gzip.decompress(payload) if packed else payload
    except Exception:
        return None,'unreadable-compressed-data'
    if path.suffix in {'.npz','.npy'}:
        # NumPy numeric checkpoints are accepted; pickle payloads are not.
        import zipfile
        if path.suffix=='.npz':
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                    if any(not n.endswith('.npy') for n in z.namelist()):
                        return None,'non-numeric-npz-member'
                    checks=[z.read(n) for n in z.namelist()]
            except Exception:
                return None,'invalid-npz'
        else:
            checks=[payload]
        if any(re.search(rb"['\"]descr['\"]\s*:\s*['\"][|<>]?O",b[:1024]) for b in checks):
            return None,'numpy-object-pickle'
        check=b'\n'.join(checks)
    elif b'\x00' in check:
        return None,'binary-in-text-format'
    if SECRET.search(check) or PERSONAL.search(check):
        return None,'sensitive-content'
    return payload,None

def package(roots,out,name):
    out.mkdir(parents=True,exist_ok=True)
    archive=out/(name+'.tar.gz')
    if archive.exists():
        raise SystemExit('Refusing to overwrite '+str(archive))
    files=[]; skipped=[]; counts=Counter()
    with tarfile.open(archive,'w:gz',compresslevel=3) as tar:
        for prefix,root in roots:
            walk = os.walk(root) if root.is_dir() else [(str(root.parent),[],[root.name])]
            for base,dirs,names in walk:
                dirs[:]=sorted(d for d in dirs if d not in PRUNE and not d.startswith('.'))
                for filename in sorted(names):
                    path=Path(base)/filename
                    rel=str(Path(prefix)/path.relative_to(root)) if root.is_dir() else str(Path(prefix)/root.name)
                    payload,reason=inspect(path)
                    if reason:
                        counts[reason]+=1
                        if reason!='non-source-data-format': skipped.append({'path':rel,'reason':reason})
                        continue
                    item=tarfile.TarInfo(rel)
                    item.size=len(payload); item.mtime=int(path.stat().st_mtime)
                    item.mode=0o755 if os.access(path,os.X_OK) else 0o644
                    tar.addfile(item,io.BytesIO(payload))
                    files.append({'path':rel,'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()})
        manifest=json.dumps({'schema':1,'purpose':'archival snapshot, not a new approved model release',
            'files':files,'excluded_counts':counts},ensure_ascii=False,indent=2).encode()
        info=tarfile.TarInfo('SNAPSHOT-MANIFEST.json'); info.size=len(manifest)
        tar.addfile(info,io.BytesIO(manifest))
    # Re-read the completed archive and independently verify every member.
    expected={f['path']:f for f in files}
    with tarfile.open(archive,'r:gz') as tar:
        seen=set()
        for item in tar:
            if item.name=='SNAPSHOT-MANIFEST.json': continue
            data=tar.extractfile(item).read()
            assert hashlib.sha256(data).hexdigest()==expected[item.name]['sha256']
            seen.add(item.name)
        assert seen==set(expected)
    report={'archive':archive.name,'files':len(files),'source_bytes':sum(f['bytes'] for f in files),
            'archive_bytes':archive.stat().st_size,'excluded_counts':counts,'verified':True,
            'sha256':hashlib.file_digest(archive.open('rb'),'sha256').hexdigest() if hasattr(hashlib,'file_digest') else sha256_file(archive)}
    (out/(name+'.report.json')).write_text(json.dumps(report,indent=2))
    (out/(name+'.private-exclusions.json')).write_text(json.dumps(skipped,ensure_ascii=False,indent=2))
    print(json.dumps(report),flush=True)
    return report

def sha256_file(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',action='append',required=True,help='PREFIX=PATH')
    p.add_argument('--output',type=Path,required=True);p.add_argument('--name',required=True)
    a=p.parse_args()
    package([(s.split('=',1)[0],Path(s.split('=',1)[1])) for s in a.root],a.output,a.name)
