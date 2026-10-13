#!/usr/bin/env python3
"""Retain scoped arena qualification diagnostics from the repository root.

Requires Python3.11/pytest, Rust1.93.1, and the separately built/pinned oracle.
No environment variables, builds or production writes. Output replaces only
this directory's current validation reports/logs. A timeout leaves a child
running and records its PID; this runner never signals another process.
"""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
COMMANDS = [
    ("source-model", ["python3.11", "scripts/check_parliament_ballot_arena_sufficiency.py", "--rustdoc-root", "/Users/mtakemiya/.rustup/toolchains/1.93.1-aarch64-apple-darwin/share/doc/rust/html/src", "--output", str(OUT / "source-model.json"), "--require-qualified"], 2),
    ("native-oracle", ["python3.11", "scripts/check_parliament_ballot_arena_oracle.py", "--oracle", "/tmp/parliament-arena-trace-replay", "--output", str(OUT / "native-oracle.json")], 0),
    ("python-tests", ["python3.11", "-m", "pytest", "-q", "scripts/tests/parliament_ballot_arena_model_test.py", "scripts/tests/parliament_ballot_arena_backend_test.py", "scripts/tests/parliament_ballot_arena_frontend_test.py", "scripts/tests/parliament_ballot_arena_sufficiency_test.py", "scripts/tests/parliament_ballot_arena_oracle_test.py", "scripts/tests/parliament_ballot_stack_audit_test.py"], 0),
    ("rustfmt", ["rustfmt", "--edition", "2024", "--check", "crates/iroha_parliament_ballot_proof/examples/arena_trace_replay.rs"], 0),
    ("codec", ["bash", "scripts/check_no_legacy_codec.sh"], 0),
    ("core-source-contract", ["python3.11", "scripts/formal/check_sora_parliament_source_contract.py"], None),
]
if __name__ == "__main__":
    scope = sorted({p for glob in ("scripts/*parliament_ballot_arena*.py", "scripts/tests/*parliament_ballot_arena*_test.py", "scripts/*parliament_ballot_stack*.py", "scripts/tests/*parliament_ballot_stack*_test.py") for p in ROOT.glob(glob)} | {ROOT / "crates/iroha_parliament_ballot_proof/examples/arena_trace_replay.rs", Path(__file__)})
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in scope}
    rows = []
    for label, command, expected in COMMANDS:
        start = time.monotonic()
        log = OUT / (label + ".txt")
        utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with log.open("w") as handle:
            child = subprocess.Popen(command, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT)
            try:
                code = child.wait(timeout=1200)
            except subprocess.TimeoutExpired:
                code = None
        changed = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in scope if hashlib.sha256(p.read_bytes()).hexdigest() != hashes[str(p.relative_to(ROOT))]}
        row = {"label": label, "command": command, "started_utc": utc, "elapsed_seconds": time.monotonic() - start, "exit": code, "expected_exit": expected, "source_changes": changed, "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
        if code is None:
            row["still_running_pid"] = child.pid
        rows.append(row)
        report = {"sources": hashes, "commands": rows, "profile_qualified": False, "complete_workspace_certificate": False}
        (OUT / "validation-receipt.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(row), flush=True)
        if code is None or changed or (expected is not None and code != expected):
            raise SystemExit(1)
