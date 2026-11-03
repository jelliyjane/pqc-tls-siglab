"""Compare compiled C scoring with frozen checkpoint vectors, without NumPy."""
import argparse
import json
import math
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(); ap.add_argument('--models',type=Path,required=True); args=ap.parse_args()
fixtures=json.loads((args.models/'fixtures.json').read_text())
with tempfile.TemporaryDirectory(prefix='cats-model-') as tmp:
    tmp=Path(tmp); binary=tmp/'score'
    subprocess.run(['cc','-O2','-std=c11','-Wall','-Wextra','-Werror',str(ROOT/'src/test_cats_model.c'),'-lm','-o',str(binary)],check=True)
    count=0; max_relative=0; max_absolute=0
    for level,rows in fixtures.items():
        source=args.models/(level+'.model')
        r=subprocess.run([str(binary),str(source),level],input=''.join(' '.join(format(v,'.17g') for v in row['input'])+'\n' for row in rows),text=True,capture_output=True,check=True)
        lines=r.stdout.splitlines(); assert len(lines)==len(rows)
        for line,row in zip(lines,rows):
            values=list(map(float,line.split())); assert len(values)==5
            for got,want in zip(values,row['expected']):
                assert math.isclose(got,want,rel_tol=2e-11,abs_tol=1e-8),(level,got,want,row)
                max_absolute=max(max_absolute,abs(got-want)); max_relative=max(max_relative,abs(got-want)/max(1,abs(want)))
            count+=1
        for x in [[0,0,0,1,1,1,1],[0,1,-1,1,1,1,1],[0,1,1.1,1,1,1,1],[0,1,0,0,1,1,1],[0,1,0,1,-1,1,1],[0,1,0,1,1,1,float('nan')]]:
            r=subprocess.run([str(binary),str(source),level],input=' '.join(map(str,x))+'\n',text=True,capture_output=True)
            assert r.returncode==3
        text=source.read_text()
        for bad in [text.replace('CAP2','CAP4'),text.replace('END',''),text+'junk',text.replace('END','END\x00'),text.replace('\n','\r\n'),text.replace('L'+level[1],'XX',1)]:
            path=tmp/'bad'; path.write_text(bad)
            assert subprocess.run([str(binary),str(path),level],input='',text=True,capture_output=True).returncode==2
        lines=text.splitlines(); lines[2]='0 '+' '.join(lines[2].split()[1:])
        (tmp/'bad').write_text('\n'.join(lines)+'\n')
        assert subprocess.run([str(binary),str(tmp/'bad'),level],input='',text=True,capture_output=True).returncode==2
        lines=text.splitlines()
        lines[4:24]=['0 0 0 0']*20
        (tmp/'zero').write_text('\n'.join(lines)+'\n')
        r=subprocess.run([str(binary),str(tmp/'zero'),level],input='10 100 0.01 10000 2 3 20000\n',text=True,capture_output=True,check=True)
        assert list(map(float,r.stdout.split()))==[16.6,1.,1.,1.,1.]
    print(json.dumps(dict(status='PASS',vectors=count,max_absolute_error=max_absolute,max_scaled_error=max_relative,invalid_models_and_inputs_rejected=True)))
