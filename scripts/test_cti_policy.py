#!/usr/bin/env python3
"""Unit + real loopback TLS tests for STIX-to-certificate-callback enforcement.

Run with Python 3.10+, cc, and OpenSSL 3.x development headers:
  python3 scripts/test_cti_policy.py --openssl-prefix /opt/homebrew/opt/openssl@3
No external servers, PQ provider, or existing experiment data are used.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import compile_cti_policy as policy

ROOT = Path(__file__).resolve().parents[1]
CREATOR = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
OTHER = "identity--841e1011-02fb-4732-8bfe-b366d69b9b2d"
VULN = "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"
ED = "ed25519"
EC = "ecdsa_secp256r1_sha256"
PREFIX = None
SERVER_BINARY = None
SIGN_TIMER = None
PQC = False


def fixture():
    now = datetime.now(timezone.utc)
    stamp = (now - timedelta(seconds=5)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    bundle = {"type": "bundle", "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d", "objects": [
        {"type": "vulnerability", "spec_version": "2.1", "id": VULN,
         "created": stamp, "modified": stamp, "created_by_ref": CREATOR,
         "name": "SYNTHETIC TEST ONLY - not an actual cryptographic vulnerability"}]}
    config = {"schema": "cats-stix-policy.v1", "valid_until": (now + timedelta(hours=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
              "allowed_algorithms": [ED, EC], "trusted_creators": [CREATOR],
              "rules": [{"stix_id": VULN, "deny_algorithms": [ED]}]}
    return bundle, config


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.bundle, self.config = fixture()

    def test_deny_exact_algorithm(self):
        text, audit = policy.compile_policy(self.bundle, self.config)
        self.assertEqual(audit["allowed_algorithms"], [EC])
        self.assertEqual(audit["denied_algorithms"], [ED])
        self.assertNotIn("\n" + ED + "\n", text)

    def test_hybrid_must_be_explicitly_mapped(self):
        self.config["allowed_algorithms"].append("p256_mldsa44")
        self.config["rules"][0]["deny_algorithms"].append("p256_mldsa44")
        _, audit = policy.compile_policy(self.bundle, self.config)
        self.assertEqual(audit["allowed_algorithms"], [EC])

    def test_revocation_and_latest_version(self):
        original = self.bundle["objects"][0]
        revoked = dict(original, revoked=True, modified=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
        self.bundle["objects"] = [revoked, original]  # order must not matter
        _, audit = policy.compile_policy(self.bundle, self.config)
        self.assertEqual(set(audit["allowed_algorithms"]), {ED, EC})

    def test_version_after_revocation_rejected(self):
        original = self.bundle["objects"][0]
        original["revoked"] = True
        newer = dict(original, revoked=False, modified=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
        self.bundle["objects"].append(newer)
        with self.assertRaises(policy.PolicyError): policy.compile_policy(self.bundle, self.config)

    def test_conflicting_version_rejected(self):
        self.bundle["objects"].append(dict(self.bundle["objects"][0], revoked=True))
        with self.assertRaises(policy.PolicyError): policy.compile_policy(self.bundle, self.config)

    def test_untrusted_publisher_rejected(self):
        self.bundle["objects"][0]["created_by_ref"] = OTHER
        with self.assertRaises(policy.PolicyError): policy.compile_policy(self.bundle, self.config)

    def test_missing_mapped_object_rejected(self):
        self.bundle["objects"] = []
        with self.assertRaises(policy.PolicyError): policy.compile_policy(self.bundle, self.config)

    def test_expired_rules_rejected(self):
        self.config["valid_until"] = "2000-01-01T00:00:00.000Z"
        with self.assertRaises(policy.PolicyError): policy.compile_policy(self.bundle, self.config)

    def test_invalid_configs_and_objects(self):
        cases = [
            ("config", "allowed_algorithms", [ED, ED]),
            ("config", "allowed_algorithms", ["bad\nname"]),
            ("config", "trusted_creators", []),
            ("object", "revoked", "false"),
            ("object", "spec_version", "2.0"),
            ("object", "modified", "2999-01-01T00:00:00.000Z"),
            ("object", "created", "bad"),
        ]
        for target, key, value in cases:
            with self.subTest(key=key, value=value):
                b, c = copy.deepcopy(self.bundle), copy.deepcopy(self.config)
                (c if target == "config" else b["objects"][0])[key] = value
                with self.assertRaises(policy.PolicyError): policy.compile_policy(b, c)

    def test_unknown_name_and_all_denied(self):
        self.config["rules"][0]["deny_algorithms"] = ["typo"]
        with self.assertRaises(policy.PolicyError): policy.compile_policy(self.bundle, self.config)
        self.config["rules"][0]["deny_algorithms"] = [ED, EC]
        text, audit = policy.compile_policy(self.bundle, self.config)
        self.assertEqual(audit["allowed_algorithms"], [])
        self.assertTrue(text.endswith("\nEND\n"))

    def test_cli_failure_invalidates_previous_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / "rules.json").write_text(json.dumps(self.config))
            (d / "bundle.json").write_text('{"type":"bundle","type":"bundle"}')
            (d / "runtime").write_text(policy.compile_policy(self.bundle, self.config)[0])
            r = subprocess.run([sys.executable, str(ROOT / "scripts/compile_cti_policy.py"),
                                "--bundle", str(d / "bundle.json"), "--rules", str(d / "rules.json"),
                                "--output", str(d / "runtime")], capture_output=True)
            self.assertEqual(r.returncode, 1)
            self.assertTrue((d / "runtime").read_text().startswith("CATS-CTI-1\t0\t0\t"))

    def test_watch_recompiles_and_invalidates(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            bundle_path, rules_path, output = d / "bundle.json", d / "rules.json", d / "runtime"
            policy.publish(bundle_path, json.dumps(self.bundle))
            policy.publish(rules_path, json.dumps(self.config))
            with (d / "log").open("w") as log:
                process = subprocess.Popen([sys.executable, str(ROOT / "scripts/compile_cti_policy.py"),
                    "--bundle", str(bundle_path), "--rules", str(rules_path), "--output", str(output), "--watch", "0.1"],
                    stdout=log, stderr=log)
                def wait_for(expected):
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if output.exists() and expected(output.read_text()): return
                        if process.poll() is not None: self.fail((d / "log").read_text())
                        time.sleep(.02)
                    self.fail("watch did not publish expected update")
                try:
                    wait_for(lambda text: "\n" + EC + "\n" in text)
                    self.config["rules"][0]["deny_algorithms"] = [ED, EC]
                    policy.publish(rules_path, json.dumps(self.config))
                    wait_for(lambda text: "\t0\t" in text and not text.startswith("CATS-CTI-1\t0\t"))
                    policy.publish(bundle_path, "{invalid")
                    wait_for(lambda text: text.startswith("CATS-CTI-1\t0\t"))
                finally:
                    process.terminate()
                    process.wait(timeout=5)


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="cats-cti-")
        cls.d = Path(cls.temp.name)
        cls.parser = cls.d / "parser"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I" + str(ROOT / "src"),
                        str(ROOT / "src/test_cats_cti_policy.c"), "-o", str(cls.parser)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check_snapshot(self, text):
        path = self.d / "runtime"
        path.write_bytes(text if isinstance(text, bytes) else text.encode())
        return subprocess.run([str(self.parser), str(path), str(int(time.time())), ED, EC, "unknown"], capture_output=True, text=True)

    def test_valid_and_unknown_denied(self):
        text, _ = policy.compile_policy(*fixture())
        r = self.check_snapshot(text)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, f"{ED}=0\n{EC}=1\nunknown=0\n")

    def test_malformed_snapshots(self):
        text, _ = policy.compile_policy(*fixture())
        cases = [text[:-1], text.replace("END", "BAD"), text + "junk\n", text.replace("CATS-CTI-1", "OTHER"),
                 text.replace("\t1\t", "\t2\t"), text.replace("\t1\t", "\t513\t"),
                 text.replace(EC, "x" * 512), text.replace(EC, "a b"), text.replace(EC, "a\x00b"),
                 text.replace("\n", "\r\n"), text.replace("\t1\t", "\t+1\t"),
                 "CATS-CTI-1\t0\t0\t" + "0" * 64 + "\nEND\n"]
        for bad in cases:
            with self.subTest(snapshot=repr(bad[:70])):
                self.assertEqual(self.check_snapshot(bad).returncode, 2)

    def test_missing_file(self):
        r = subprocess.run([str(self.parser), str(self.d / "absent"), str(int(time.time()))])
        self.assertEqual(r.returncode, 2)

    def test_empty_and_duplicate_allowlist(self):
        b, c = fixture()
        c["rules"][0]["deny_algorithms"] = [ED, EC]
        self.assertEqual(self.check_snapshot(policy.compile_policy(b, c)[0]).returncode, 0)
        text, _ = policy.compile_policy(*fixture())
        text = text.replace("\t1\t", "\t2\t").replace("END\n", EC + "\nEND\n")
        self.assertEqual(self.check_snapshot(text).returncode, 2)


class TLSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if PREFIX is None:
            raise unittest.SkipTest("supply --openssl-prefix for real TLS tests")
        cls.temp = tempfile.TemporaryDirectory(prefix="cats-cti-tls-")
        cls.d = Path(cls.temp.name)
        cls.lib = PREFIX / ("lib64" if (PREFIX / "lib64").is_dir() else "lib")
        cls.openssl = str(PREFIX / "bin/openssl")
        cls.server = SERVER_BINARY or cls.d / "server"
        if SERVER_BINARY is None:
            subprocess.run(["cc", "-O1", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-I" + str(PREFIX / "include"), "-L" + str(cls.lib), "-Wl,-rpath," + str(cls.lib),
                        str(ROOT / "src/tls_context_selector_server.c"), "-lssl", "-lcrypto", "-lm", "-o", str(cls.server)], check=True)
        rows, ca = [], ""
        for name, generation, signing in [(ED, ["-newkey", "ML-DSA-44" if PQC else "ed25519"], 1),
                                          (EC, ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"], 1000)]:
            cert, key = cls.d / (name + ".crt"), cls.d / (name + ".key")
            subprocess.run([cls.openssl, "req", "-x509", *generation, "-noenc", "-subj", "/CN=localhost", "-days", "1",
                            "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
            der = subprocess.check_output([cls.openssl, "x509", "-in", str(cert), "-outform", "DER"])
            rows.append(f"{name}\tL1\troot_direct\t{cert}\t{key}\t-\t{len(der)}\t72\t1\t{signing}\t1\n")
            ca += cert.read_text()
        (cls.d / "ca.pem").write_text(ca)
        (cls.d / "manifest.tsv").write_text("algorithm\tlevel\tmode\tcert\tkey\tchain\tbytes\tsig_bytes\tcount\tsign_ms\tverify_ms\n" + "".join(rows))

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"): cls.temp.cleanup()

    def setUp(self):
        self.bundle, self.config = fixture()
        self.runtime = self.d / "policy"
        self.log = self.d / "stdout"
        self.err = self.d / "stderr"
        self.proc = None
        self.files = []

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        for stream in self.files: stream.close()

    def publish(self):
        policy.publish(self.runtime, policy.compile_policy(self.bundle, self.config)[0])

    def start(self, **extra):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        env = {k: v for k, v in os.environ.items() if not k.startswith(("TLS_", "CATS_"))}
        env.update(TLS_REQUIRE_OQSPROVIDER="0", TLS_SELECTOR_LISTEN_HOST="127.0.0.1",
                   TLS_SELECTOR_WINDOW_SIZE_BYTES="65535", CATS_CTI_POLICY=str(self.runtime), **extra)
        if SIGN_TIMER:
            env["LD_PRELOAD"] = str(SIGN_TIMER)
            env.pop("TLS_SELECTOR_WINDOW_SIZE_BYTES", None)
        self.files = [self.log.open("w"), self.err.open("w")]
        self.proc = subprocess.Popen([str(self.server), str(self.port), str(self.d / "manifest.tsv"),
                                      str(self.lib / "ossl-modules"), "X25519", "0"],
                                     env=env, stdout=self.files[0], stderr=self.files[1])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if "READY" in self.err.read_text(): return
            if self.proc.poll() is not None: self.fail(self.err.read_text())
            time.sleep(.02)
        self.fail("server readiness timeout")

    def connect(self, expected=None, sigalgs=None):
        before = len(self.log.read_text())
        session = self.d / "session.pem"
        if session.exists(): session.unlink()
        cmd = [self.openssl, "s_client", "-connect", f"127.0.0.1:{self.port}", "-tls1_3", "-groups", "X25519",
               "-CAfile", str(self.d / "ca.pem"), "-verify_return_error", "-sess_out", str(session)]
        if sigalgs: cmd += ["-sigalgs", sigalgs]
        r = subprocess.run(cmd, input="", text=True, capture_output=True, timeout=10)
        if expected:
            self.assertIn("Verification: OK", r.stdout, r.stdout + r.stderr)
            self.assertIn("New, TLSv1.3, Cipher is TLS_", r.stdout, r.stdout + r.stderr)
            self.assertIn(f"status ok algorithm={expected} ", self.log.read_text()[before:])
            self.assertFalse(session.exists(), "CTI mode must not issue resumable tickets")
            if SIGN_TIMER:
                deadline = time.monotonic() + 2
                while "CONTEXT acquisition_valid=1" not in self.log.read_text()[before:] and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertIn("CONTEXT acquisition_valid=1", self.log.read_text()[before:])
        else:
            self.assertNotIn("status ok", self.log.read_text()[before:])
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_hot_reload_revocation_and_fail_closed(self):
        self.config["rules"] = []
        self.publish()
        self.start()
        self.connect(ED)
        self.config["rules"] = [{"stix_id": VULN, "deny_algorithms": [ED]}]
        self.publish()
        self.connect(EC)
        self.connect(sigalgs=ED)  # compatibility intersection is empty
        self.config["rules"][0]["deny_algorithms"] = [ED, EC]
        self.publish()
        self.connect()
        policy.publish(self.runtime, "malformed\n")
        self.connect()
        policy.publish(self.runtime, "CATS-CTI-1\t0\t0\t" + "0" * 64 + "\nEND\n")
        self.connect()
        self.runtime.unlink()
        self.connect()
        self.bundle["objects"][0]["revoked"] = True
        self.publish()
        self.connect(ED)
        self.assertIn("CTI revision=", self.err.read_text())

    def test_unavailable_sidecar_fallback_respects_policy(self):
        self.publish()
        self.start(TLS_RL_SOCKET=str(self.d / "absent.sock"))
        self.connect(EC)
        self.assertIn("RL fallback", self.err.read_text())

    def test_sidecar_cannot_return_blocked_algorithm(self):
        self.publish()
        # macOS UNIX socket paths are short; use a separate /tmp directory.
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="cti-sock-") as directory:
            path = str(Path(directory) / "s")
            requests = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(2)
                listener.settimeout(5)
                def reply():
                    try:
                        for _ in range(2):
                            conn, _ = listener.accept()
                            with conn:
                                conn.settimeout(5)
                                requests.append(conn.recv(16384).decode())
                                conn.sendall(f"OK\tid\tarm\t{ED}\tx\tx\tx\tx\n".encode())
                    except (TimeoutError, OSError):
                        pass
                thread = threading.Thread(target=reply)
                thread.start()
                self.start(TLS_RL_SOCKET=path)
                self.connect()
                thread.join(timeout=6)
                self.assertTrue(requests)
                self.assertNotIn(ED, requests[0])
                self.assertIn(EC, requests[0])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl-prefix", type=Path)
    parser.add_argument("--server-binary", type=Path, help="test an already built deployment binary")
    parser.add_argument("--sign-timer", type=Path, help="preload timer for the context-acquisition build")
    parser.add_argument("--pqc", action="store_true", help="use native ML-DSA-44 instead of Ed25519")
    args, rest = parser.parse_known_args()
    PREFIX = args.openssl_prefix
    SERVER_BINARY = args.server_binary.resolve() if args.server_binary else None
    SIGN_TIMER = args.sign_timer.resolve() if args.sign_timer else None
    PQC = args.pqc
    if PQC:
        ED = "mldsa44"
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
