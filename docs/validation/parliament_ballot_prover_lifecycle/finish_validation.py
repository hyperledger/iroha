#!/usr/bin/env python3
"""Finish accelerated example/lint checks without repeating completed tests.

Requires Python 3.11+, the pinned Rust toolchain and the completed test-campaign
receipt. Writes supplemental/ and /tmp/parliament-prover-lifecycle/supplement.
A 20-minute wait timeout records but never kills a child. This is controlled
diagnostic build linkage, not qualification or a hermetic build attestation.
"""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess
import time


def sha(path):
    """Hash one source, log, or binary."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    """Freeze current inputs and run the remaining, separately attributed checks."""
    root = Path(__file__).resolve().parents[3]
    evidence = Path(__file__).resolve().parent
    output = evidence / "supplemental"
    output.mkdir(exist_ok=True)
    names = {line.split("  ", 1)[1] for line in (evidence / "test-campaign/source.sha256").read_text().splitlines()}
    names.add(str(Path(__file__).resolve().relative_to(root)))
    # Include new package modules even if the preceding campaign never saw them.
    for name in tuple(names):
        if name.endswith("/Cargo.toml"):
            package = (root / name).parent
            names.update(str(path.relative_to(root)) for path in (package / "src").rglob("*.rs") if path.is_file())
            if (package / "build.rs").is_file():
                names.add(str((package / "build.rs").relative_to(root)))
    sources = {name: sha(root / name) for name in sorted(names)}
    manifest = output / "source.sha256"
    manifest.write_text("".join(f"{value}  {name}\n" for name, value in sources.items()))
    shutil.copyfile(root / "crates/norito/src/lib.rs", output / "build-norito-lib.rs.template")
    shutil.copyfile(root / "Cargo.lock", output / "build-Cargo.lock.template")
    receipt = {
        "scope": "Supplemental accelerated example/lint build; does not rerun or reattribute completed b7d64 tests.",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_count": len(sources), "source_manifest_sha256": sha(manifest),
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "commands": [], "source_changes": {}, "passed": False,
        "profile_qualified": False, "whole_secret_erasure_qualified": False,
    }

    def save():
        (output / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")

    def guard():
        delta = {name: {"expected": value, "actual": sha(root / name)} for name, value in sources.items() if sha(root / name) != value}
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        if head != receipt["head"]:
            delta["git_HEAD"] = {"expected": receipt["head"], "actual": head}
        if delta:
            receipt["source_changes"] = delta
            raise RuntimeError(f"Supplement source changed: {delta}")

    def run(name, command):
        guard()
        path = output / f"{name}.txt"
        entry = {"command": command, "log": path.name, "before_guard_matched": True}
        receipt["commands"].append(entry)
        started = time.monotonic()
        with path.open("w") as log:
            child = subprocess.Popen(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                code = child.wait(timeout=1200)
            except subprocess.TimeoutExpired:
                entry.update({"pid_left_running": child.pid, "signal_sent": False, "timeout_seconds": 1200})
                raise RuntimeError("Supplement child exceeded wait budget; left running") from None
        entry.update({"exit": code, "elapsed_seconds": time.monotonic() - started, "log_sha256": sha(path)})
        guard()
        entry["after_guard_matched"] = True
        save()
        if code:
            raise RuntimeError(f"{name} failed: {code}")
        return path.read_text()

    cargo = ["scripts/cargo_fast.sh", "--target-slot", "parliament-lifecycle", "--incremental", "--"]
    package = ["--release", "--locked", "-p", "iroha_parliament_ballot_proof", "--features", "accel"]
    try:
        run("clippy-accel", cargo + ["clippy"] + package + ["--test", "prover_lifecycle", "--example", "prover_lifecycle", "--", "-D", "warnings"])
        run("build-accel", cargo + ["build"] + package + ["--example", "prover_lifecycle"])
        built = root / "target/cargo-fast/parliament-lifecycle/release/examples/prover_lifecycle"
        binary = Path("/tmp/parliament-prover-lifecycle/supplement/example-accel")
        binary.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, binary)
        receipt["binary"] = {"built_path": str(built.relative_to(root)), "retained_path": str(binary), "sha256": sha(binary)}
        for mode, expected in [("publish", "published"), ("cancel", "proved_and_discarded"), ("cancel-after-wait", "proved_and_discarded"), ("drop", "dropped_and_joined")]:
            result = json.loads(run(f"example-accel-{mode}", [str(binary), "candidate", "registration", mode]))
            assert result["outcome"] == expected and result["backend"] == "accel"
            assert result["cancellation_after_completion"] == "TooLate"
            assert result["released_proof_bytes"] == (160148 if mode == "publish" else 0)
        rust = ["crates/iroha_parliament_ballot_proof/" + suffix for suffix in ["examples/prover_lifecycle.rs", "examples/prover_lifecycle/job.rs", "tests/prover_lifecycle.rs", "tests/prover_lifecycle/allocator_probe.rs"]]
        run("rustfmt", ["rustfmt", "--check", "--edition", "2024"] + rust)
        run("no-legacy-codec", ["bash", "scripts/check_no_legacy_codec.sh"])
        guard()
        receipt["passed"] = True
    except Exception as error:
        receipt["failure"] = str(error)
        raise
    finally:
        receipt["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    print(json.dumps({"supplement_passed": True, "source_count": len(sources), "source_changes": receipt["source_changes"]}))


if __name__ == "__main__":
    main()
