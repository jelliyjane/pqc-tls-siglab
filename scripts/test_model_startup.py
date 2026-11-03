"""Model configuration failures must abort, not fall back to a legacy scorer."""
import argparse
import json
import os
import subprocess

p=argparse.ArgumentParser()
for key in ['server','manifest','provider','models']: p.add_argument('--'+key,required=True)
a=p.parse_args()
base={k:v for k,v in os.environ.items() if not k.startswith(('CATS_','TLS_'))}
cases=[({'CATS_MODEL_DIR':a.models+'/nonexistent'},'MODEL missing or invalid'),
       ({'CATS_MODEL_DIR':''},'must be nonempty'),
       ({'CATS_MODEL_DIR':a.models,'TLS_RL_SOCKET':'/unused-cats-test.sock'},'cannot be combined')]
for setting,message in cases:
    r=subprocess.run([a.server,'44334',a.manifest,a.provider,'X25519','1'],
        env=dict(base,**setting),text=True,capture_output=True,timeout=5)
    assert r.returncode!=0 and message in r.stderr and 'READY' not in r.stderr,(setting,r.returncode,r.stderr)
print(json.dumps(dict(status='PASS',model_startup_failure_cases=len(cases))))
