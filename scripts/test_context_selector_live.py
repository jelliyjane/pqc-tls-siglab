#!/usr/bin/env python3
"""Test context integration in the selector server, without an RL sidecar."""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True)
    p.add_argument('--openssl-prefix',type=Path,required=True)
    args=p.parse_args()
    env=os.environ.copy()
    lib=args.openssl_prefix/'lib64'
    if not lib.is_dir(): lib=args.openssl_prefix/'lib'
    env['LD_LIBRARY_PATH']=str(lib)
    openssl=str(args.openssl_prefix/'bin/openssl')
    for algorithm in ['ECDSA','ML-DSA-44']:
        with tempfile.TemporaryDirectory(prefix='cats-selector-') as directory:
            task=Path(directory)
            key,cert=task/'key.pem',task/'cert.pem'
            gen=['-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256'] if algorithm=='ECDSA' else ['-newkey','ML-DSA-44']
            subprocess.run([openssl,'req','-x509',*gen,'-noenc','-subj','/CN=localhost',
                            '-days','1','-keyout',str(key),'-out',str(cert)],
                           env=env,check=True,capture_output=True)
            scheme='ecdsa_secp256r1_sha256' if algorithm=='ECDSA' else 'mldsa44'
            der=subprocess.check_output([openssl,'x509','-in',str(cert),'-outform','DER'],env=env)
            manifest=task/'manifest.tsv'
            manifest.write_text('algorithm\tlevel\tmode\tcert\tkey\tchain\tbytes\tsig_bytes\tcount\tsign_ms\tverify_ms\n'+
                f'{scheme}\tL1\troot_direct\t{cert}\t{key}\t-\t{len(der)}\t2420\t1\t1\t1\n')
            with socket.socket() as port_socket:
                port_socket.bind(('127.0.0.1',0)); port=port_socket.getsockname()[1]
            server_env=env|dict(LD_PRELOAD=str(args.build/'libcats_sign_timer.so'),
                TLS_REQUIRE_OQSPROVIDER='0',TLS_SELECTOR_REQUIRE_CLIENT_SIGALG_MATCH='1',
                TLS_SELECTOR_LISTEN_HOST='127.0.0.1',CATS_BW_HISTORY=str(task/'bw.cache'))
            # Remove inherited sidecar settings: this tests acquisition, not training.
            server_env.pop('TLS_RL_SOCKET',None)
            command=[str(args.build/'tls_context_selector_server'),str(port),str(manifest),
                     str(lib/'ossl-modules'),'X25519','3']
            # Files avoid pipe backpressure; no active readiness probe consumes an accept.
            with (task/'stderr').open('w+') as stderr, (task/'stdout').open('w+') as stdout:
                server=subprocess.Popen(command,env=server_env,stdout=stdout,stderr=stderr)
                try:
                    import time
                    deadline=time.monotonic()+10
                    while time.monotonic()<deadline:
                        stderr.seek(0)
                        if 'READY' in stderr.read(): break
                        if server.poll() is not None: raise RuntimeError('selector exited before READY')
                        time.sleep(.02)
                    else: raise TimeoutError('selector readiness')
                    client=[openssl,'s_client','-connect',f'127.0.0.1:{port}',
                            '-tls1_3','-groups','X25519','-CAfile',str(cert),'-verify_return_error']
                    for _ in range(2):
                        r=subprocess.run(client,input='',text=True,env=env,capture_output=True,timeout=10)
                        # Server closes without close_notify; inspect actual authenticated handshake.
                        assert 'Verification: OK' in r.stdout, r.stdout+r.stderr
                        assert 'New, TLSv1.3, Cipher is TLS_' in r.stdout, r.stdout+r.stderr
                    # Third connection fails before certificate selection; no stale context.
                    with socket.create_connection(('127.0.0.1',port),timeout=5) as s:
                        s.sendall(b'not TLS\n')
                    server.wait(timeout=10)
                    stdout.seek(0); output=stdout.read()
                    stderr.seek(0); diagnostics=stderr.read()
                    assert server.returncode==0,diagnostics
                    rows=[dict(item.split('=',1) for item in line.split()[1:])
                          for line in output.splitlines() if line.startswith('CONTEXT ')]
                    assert len(rows)==3,output+diagnostics
                    assert all(r['acquisition_valid']=='1' and r['sign_calls']=='1' and
                               int(r['actual_sign_ns'])>0 for r in rows[:2]),output+diagnostics
                    assert rows[-1]['acquisition_valid']=='0' and rows[-1]['acquisition_ns']=='0',output
                    assert float(rows[0]['selected_sign_estimate_ms']) == 1.0
                    expected=.8 + .2 * int(rows[0]['actual_sign_ns']) / 1e6
                    assert abs(float(rows[1]['selected_sign_estimate_ms'])-expected) < 1e-8
                    assert (task/'bw.cache').is_file()
                    print(f'PASS: selector {algorithm}: 2 authenticated TLS handshakes, exact signing hook, invalid-CH reset, BW checkpoint')
                finally:
                    if server.poll() is None:
                        server.terminate(); server.wait(timeout=5)


if __name__=='__main__': main()
