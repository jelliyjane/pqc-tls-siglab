#!/usr/bin/env python3
"""Compile a local STIX 2.1 vulnerability bundle + operator rules for CATS.

This is a restricted STIX consumer, not a general STIX validator or TAXII client.
The allow/deny mapping and runtime snapshot format are CATS-specific policy.
No natural-language interpretation, name guessing, or network fetching is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from uuid import UUID

MAX_BYTES = 10 * 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9_.+\-]{1,511}\Z")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,6}Z\Z")


class PolicyError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PolicyError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "input exceeds 10 MiB")
    def bad_constant(value):
        raise PolicyError(f"invalid JSON number: {value}")
    value = json.loads(data, object_pairs_hook=unique_object, parse_constant=bad_constant)
    require(isinstance(value, dict), "input must be a JSON object")
    return value


def identifier(value, kind):
    require(isinstance(value, str) and value.startswith(kind + "--"), f"expected {kind} identifier")
    try:
        uuid = UUID(value[len(kind) + 2:])
    except ValueError as error:
        raise PolicyError("invalid STIX UUID") from error
    require(str(uuid) == value[len(kind) + 2:] and uuid.variant == "specified in RFC 4122", "invalid STIX UUID")
    return value


def timestamp(value):
    # The supported profile accepts UTC timestamps with millisecond through
    # microsecond precision. Reject other representations rather than truncate.
    require(isinstance(value, str) and STAMP.fullmatch(value), "expected UTC STIX timestamp with 3-6 fractional digits")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PolicyError("invalid timestamp") from error


def names(value):
    require(isinstance(value, list) and len(value) <= 512, "expected at most 512 algorithm names")
    require(all(isinstance(s, str) and NAME.fullmatch(s) for s in value), "invalid exact algorithm name")
    require(len(value) == len(set(value)), "duplicate algorithm name")
    return set(value)


def compile_policy(bundle, config, now=None):
    now = now or datetime.now(timezone.utc)
    require(config.get("schema") == "cats-stix-policy.v1", "unsupported operator policy schema")
    require(set(config) == {"schema", "valid_until", "allowed_algorithms", "trusted_creators", "rules"}, "unexpected/missing policy fields")
    expires = timestamp(config["valid_until"])
    require(expires > now, "operator policy expired")
    allowed = names(config["allowed_algorithms"])
    creators = config["trusted_creators"]
    require(isinstance(creators, list) and creators, "trusted_creators must be nonempty")
    trusted = {identifier(x, "identity") for x in creators}
    require(bundle.get("type") == "bundle", "expected STIX bundle")
    identifier(bundle.get("id"), "bundle")
    require("spec_version" not in bundle, "STIX 2.1 bundle has no spec_version; set it on objects")
    objects = bundle.get("objects", [])
    require(isinstance(objects, list), "bundle objects must be a list")
    versions = {}
    for obj in objects:
        require(isinstance(obj, dict), "STIX object must be an object")
        # Other standard STIX objects may accompany vulnerabilities. They do not
        # create algorithm restrictions in this profile.
        if obj.get("type") != "vulnerability":
            continue
        oid = identifier(obj.get("id"), "vulnerability")
        require(obj.get("spec_version") == "2.1", "expected STIX 2.1 vulnerability")
        require(isinstance(obj.get("name"), str) and obj["name"].strip(), "vulnerability name required")
        created, modified = timestamp(obj.get("created")), timestamp(obj.get("modified"))
        require(created <= modified <= now, "invalid/future vulnerability version")
        require(type(obj.get("revoked", False)) is bool, "revoked must be boolean")
        creator = identifier(obj.get("created_by_ref"), "identity")
        versions.setdefault(oid, []).append((modified, created, creator, obj))
    latest = {}
    for oid, entries in versions.items():
        entries.sort(key=lambda entry: entry[0])
        original_created, original_creator = entries[0][1:3]
        previous = None
        for modified, created, creator, obj in entries:
            require((created, creator) == (original_created, original_creator), "immutable STIX properties changed")
            if previous is not None:
                require(modified != previous[0] or obj == previous[3], "conflicting STIX object versions")
                require(not previous[3].get("revoked", False) or obj == previous[3], "version after permanent STIX revocation")
            previous = (modified, created, creator, obj)
        latest[oid] = entries[-1][3]
    rules = config["rules"]
    require(isinstance(rules, list), "rules must be a list")
    decisions, denied = [], set()
    seen = set()
    for rule in rules:
        require(isinstance(rule, dict) and set(rule) == {"stix_id", "deny_algorithms"}, "invalid mapping rule")
        oid = identifier(rule["stix_id"], "vulnerability")
        require(oid not in seen, "duplicate mapping rule")
        seen.add(oid)
        targets = names(rule["deny_algorithms"])
        require(targets and targets <= allowed, "deny targets must be in explicit operator allowlist")
        require(oid in latest, "mapped vulnerability missing; supply a complete bundle, not a delta")
        obj = latest[oid]
        require(obj["created_by_ref"] in trusted, "mapped CTI publisher is not trusted")
        active = not obj.get("revoked", False)
        if active:
            denied |= targets
        decisions.append({"stix_id": oid, "modified": obj["modified"], "active": active,
                          "deny_algorithms": sorted(targets) if active else []})
    eligible = sorted(allowed - denied)
    revision = hashlib.sha256(json.dumps({"bundle": bundle, "rules": config},
                                        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    expiry = int(expires.timestamp())
    require(expiry > int(now.timestamp()), "operator policy expires too soon")
    snapshot = f"CATS-CTI-1\t{expiry}\t{len(eligible)}\t{revision}\n"
    snapshot += "".join(name + "\n" for name in eligible) + "END\n"
    audit = {"revision": revision, "valid_until": config["valid_until"],
             "allowed_algorithms": eligible, "denied_algorithms": sorted(denied),
             "decisions": decisions, "unmapped_vulnerability_ids": sorted(set(latest) - seen)}
    return snapshot, audit


def publish(path, text):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--watch", type=float, metavar="SECONDS",
                        help="recompile periodically; invalid updates publish an expired deny-all snapshot")
    args = parser.parse_args()
    if args.watch is not None and not (0.1 <= args.watch <= 86400):
        parser.error("--watch must be between 0.1 and 86400 seconds")
    if args.output.resolve() in {args.bundle.resolve(), args.rules.resolve()}:
        parser.error("output must not overwrite either input")
    previous = None
    while True:
        try:
            snapshot, audit = compile_policy(read_json(args.bundle), read_json(args.rules))
            if snapshot != previous:
                publish(args.output, snapshot)
                print(json.dumps(audit, sort_keys=True), flush=True)
                previous = snapshot
        except (OSError, ValueError, TypeError, OverflowError, RecursionError) as error:
            # A broken replacement must not leave the last permissive snapshot
            # indefinitely active. Publish a syntactically valid expired one.
            try:
                publish(args.output, "CATS-CTI-1\t0\t0\t" + "0" * 64 + "\nEND\n")
                previous = None
            except OSError as publish_error:
                print(f"cannot invalidate runtime snapshot: {publish_error}", file=sys.stderr)
                return 1
            print(f"CTI policy rejected: {error}", file=sys.stderr, flush=True)
            if args.watch is None:
                return 1
        if args.watch is None:
            return 0
        time.sleep(args.watch)


if __name__ == "__main__":
    sys.exit(main())
