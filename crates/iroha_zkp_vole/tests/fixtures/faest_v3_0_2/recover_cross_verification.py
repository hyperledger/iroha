#!/usr/bin/env python3
"""Recover a positive cross-verification corpus after the recorded lock drift.

This is a separate run against the retained executables. It never relabels the
original rejected publication as successful and never invents lost C return
codes. Original Rust signatures are retained; C signatures are regenerated and
positively cross-verified again. The original 384 C negatives are not replayed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import cross_verify_upstream as cross


def recover(work: Path, output: Path) -> dict:
    evidence = cross.HERE / "cross_verification_evidence"
    original = evidence / "rejected_publication"
    build = json.loads((original / "build_receipt.json").read_text())
    rejection = json.loads((original / "rejection.json").read_text())
    frozen_lock = original / "build-root-Cargo.lock.template"
    if cross.sha256(frozen_lock.read_bytes()) != build["build_inputs_sha256"]["Cargo.lock"]:
        raise ValueError("frozen build lock does not match original receipt")
    for name, digest in build["build_inputs_sha256"].items():
        if name != "Cargo.lock" and cross.sha256((cross.ROOT / name).read_bytes()) != digest:
            raise ValueError(f"build input changed: {name}")
    binaries = {mode: work / ("rust-" + mode) for mode in ("portable", "accel")}
    library = work / "build/libfaest.2.dylib"
    expected = {str(path): build["binary_sha256"][path.name] for path in binaries.values()}
    expected[str(library)] = rejection["upstream_library_sha256_at_recovery"]
    expected[str(frozen_lock)] = build["build_inputs_sha256"]["Cargo.lock"]
    # Live Cargo.lock is not an input to these already-built executables. Its
    # discrepancy is recorded explicitly; the exact build lock is retained.
    guarded_paths = [Path(path) for path in expected]
    guarded_paths += [cross.ROOT / name for name in cross.source_inventory() if name != "Cargo.lock"]
    guarded_paths += [Path(__file__).resolve(), original / "driver_used.py"]
    before = {str(path): cross.sha256(path.read_bytes()) for path in guarded_paths}
    if any(before[path] != digest for path, digest in expected.items()):
        raise ValueError("frozen executable/library/lock receipt mismatch")
    if cross.sha256((work / "upstream.tar.gz").read_bytes()) != cross.ARCHIVE_SHA256:
        raise ValueError("upstream archive mismatch")
    commands = cross.Commands(work / "recovery_commands.txt")
    checkpoint = work / "recovery_cases.jsonl"
    checkpoint.write_text("", encoding="utf-8")
    for mode, binary in binaries.items():
        if commands.run([binary, "identity"]) != mode:
            raise ValueError("wrong Rust binary feature mode")
    records = []
    for name in cross.SETS:
        retained = work / name
        row = work / "recovery" / name
        row.mkdir(parents=True, exist_ok=True)
        sk, pk = (retained / "sk").read_bytes(), (retained / "pk").read_bytes()
        if sk != cross.fresh_secret_key(name):
            raise ValueError("retained test key differs from original recipe")
        layout = [(label, int(offset), int(length)) for label, offset, length in
                  (line.split() for line in commands.run([binaries["portable"], "layout", name]).splitlines())]
        size = sum(length for _, _, length in layout)
        upstream = cross.Upstream(library, name, size)
        if upstream.validate_fn(pk, sk) != 0:
            raise ValueError("retained keypair rejected")
        for origin, msg_len in (("upstream", 137), ("rust", 273)):
            msg = cross.material(name + "/" + origin + "/message", msg_len)
            rho = cross.material(name + "/" + origin + "/rho", int(name.split("_")[-1][:-1]) // 8)
            if origin == "upstream":
                sig = upstream.sign(sk, msg, rho)
                provenance = "regenerated C signature; original bytes were not retained"
            else:
                sig = (retained / "signature").read_bytes()
                if msg != (retained / "message").read_bytes() or rho != (retained / "rho").read_bytes():
                    raise ValueError("retained Rust input differs from original recipe")
                if sig != (retained / "accelerated-signature").read_bytes():
                    raise ValueError("original Rust signing modes differ")
                provenance = "original retained Rust signature; original accel bytes identical"
            record = {"set": name, "origin": origin, "provenance": provenance,
                      "secret_key_hex": sk.hex(), "public_key_hex": pk.hex(),
                      "message_hex": msg.hex(), "rho_hex": rho.hex(), "signature_hex": sig.hex(),
                      "signature_bytes": len(sig), "signature_sha256": cross.sha256(sig),
                      "field_layout": layout, "negative_reverification_performed": False}
            # Preserve bytes before any verifier call can fail.
            cross.append_case(checkpoint, dict(record, state="inputs_retained"))
            (row / "pk").write_bytes(pk)
            (row / "message").write_bytes(msg)
            (row / "signature").write_bytes(sig)
            code = upstream.verify(pk, msg, sig)
            if code != 0:
                raise ValueError(f"C recovery verification failed: {name}/{origin}/{code}")
            record["upstream_verify_return"] = code
            record["rust_verify_exits"] = {}
            for mode, binary in binaries.items():
                commands.run([binary, "verify", name, row / "pk", row / "message", row / "signature"])
                record["rust_verify_exits"][mode] = 0
            if origin == "rust":
                code = upstream.verify(pk, msg, (retained / "accelerated-signature").read_bytes())
                if code != 0:
                    raise ValueError("C rejected retained accelerated Rust signature")
                record["upstream_accel_verify_return"] = code
            cross.append_case(checkpoint, dict(record, state="positive_verification_complete"))
            records.append(record)
            print(f"{name} {origin}: positive recovery checks passed", flush=True)
    report = {"scope": "separate positive recovery run; original full campaign publication remains rejected",
              "upstream_commit": cross.COMMIT, "upstream_archive_sha256": cross.ARCHIVE_SHA256,
              "original_driver_sha256": cross.sha256((original / "driver_used.py").read_bytes()),
              "recovery_driver_sha256": cross.sha256(Path(__file__).read_bytes()),
              "frozen_build_lock_sha256": cross.sha256(frozen_lock.read_bytes()),
              "live_lock_sha256_observed": cross.sha256((cross.ROOT / "Cargo.lock").read_bytes()),
              "guard_scope": "frozen binaries/library/build-lock plus current backend source and diagnostic drivers; live lock is separately recorded, not an execution input",
              "guarded_inputs_sha256": before,
              "recovery_command_log_sha256": cross.sha256(commands.log.read_bytes()),
              "recovery_case_jsonl_sha256": cross.sha256(checkpoint.read_bytes()),
              "positive_verify_calls": {"upstream": 36, "rust_portable": 24, "rust_accel": 24, "total": 84},
              "direct_cross_implementation_positive_verify_calls": 48,
              "negative_verify_calls_in_recovery": 0,
              "original_upstream_negative_return_codes_lost": True,
              "records": records}
    after = {str(path): cross.sha256(path.read_bytes()) for path in guarded_paths}
    cross.retain_report(output, report, before, after)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    recover(args.work_dir.resolve(), args.output.resolve())
