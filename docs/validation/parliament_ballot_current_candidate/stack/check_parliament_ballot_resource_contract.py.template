#!/usr/bin/env python3
"""Exercise the experimental ballot reservation/worker contract, never qualify it.

Requires Python 3.11+, explicitly supplied portable/accelerated native
resource_contract binaries and their frozen build receipt. No environment variables, network access,
production writes or package installation are used. Public fixture records are
rebuilt and checked against their independent recorded digests. Completed cases
are flushed before continuing; a failure or source change retains an explicitly
unsuccessful report. Output must be a new directory (no evidence overwrite).
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path("crates/iroha_parliament_ballot_proof/tests/fixtures")
MAX_INPUT_BYTES = 262_144 + 163_840
WORKSPACE_LIMIT = 64 * 1024 * 1024


def digest(data):
    """Return a source/input identity, not an authenticity attestation."""
    return hashlib.sha256(data).hexdigest()


def fields(path):
    """Read unique hexadecimal public fixture fields."""
    result = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, value = line.split(" = ", 1)
        if key in result:
            raise ValueError(f"duplicate fixture field {key}")
        result[key] = bytes.fromhex(value)
    return result


def frame(tag, values):
    """Encode only the existing length-framed standalone test statement."""
    return (struct.pack("<H", len(tag)) + tag + struct.pack("<H", len(values))
            + b"".join(struct.pack("<I", len(value)) + value for value in values))


def fixture_record(root, row, seats):
    """Rebuild a record from existing proof bytes; never generate a new proof."""
    label = "fast" if row == "candidate" else "comparator"
    stem = f"reg_{label}" if seats == 0 else f"vote_S{seats}_i{seats // 2}_{label}"
    vector = fields(root / FIXTURES / (stem + ".txt"))
    proof = (root / FIXTURES / (stem + ".proof")).read_bytes()
    if hashlib.shake_256(proof).digest(64) != vector["proof_shake256_64"]:
        raise ValueError(f"proof fixture digest mismatch: {stem}")
    if seats == 0:
        keys = ["D", "enc_body_context", "enc_network_id", "enc_authority",
                "enc_assignment_id", "enc_governance_attempt_id", "enc_election_attempt_id",
                "enc_body_role", "B", "C", "auth"]
        statement = frame(b"PARL/TEST/REG/v1", [vector[key] for key in keys])
        role = "registration"
    else:
        # Reproduce the public fixture recipe, independently checking the list
        # and complete record digests. These public test secrets are not keys.
        commitments = []
        for index in range(seats):
            secret = hashlib.shake_256(
                b"PARL-ballot-proto/fixture/v1/" + f"member-sk-{index}".encode()
            ).digest(48)
            commitments.append(hashlib.shake_256(
                b"PCR1" + vector["P16"] + secret + vector["B"]
            ).digest(128))
        listing = b"".join(sorted(commitments))
        if hashlib.shake_256(listing).digest(64) != vector["list_concat_shake256_64"]:
            raise ValueError(f"list fixture digest mismatch: {stem}")
        statement = frame(b"PARL/TEST/VOTE/v1", [vector["D"], vector["B"],
            vector["scope"], vector["R"], vector["S_u16"], listing, vector["nf"],
            vector["auth_v"], vector["vote_u8"], vector["policy_hash"]])
        role = "vote"
    record = struct.pack("<I", len(statement)) + statement + struct.pack("<I", len(proof)) + proof
    if hashlib.shake_256(statement).digest(64) != vector["test_statement_shake256_64"]:
        raise ValueError(f"statement fixture digest mismatch: {stem}")
    if hashlib.shake_256(record).digest(64) != vector["test_record_shake256_64"]:
        raise ValueError(f"record fixture digest mismatch: {stem}")
    return stem, role, record, 8 + len(statement), vector


def cases(root):
    """Yield valid, malformed, admission and explicit allocation-failure cases."""
    for row in ("candidate", "comparator"):
        for seats in (0, 3, 500, 1000):
            stem, role, record, proof_start, vector = fixture_record(root, row, seats)
            base = {"fixture": stem, "row": row, "role": role, "seats": seats}
            late = bytearray(record)
            late[proof_start + int.from_bytes(vector["field_a_tilde_1_6_offset_u32"], "little")] ^= 1
            malformed_length = bytearray(record)
            malformed_length[proof_start - 4:proof_start] = b"\xff" * 4
            variants = [
                ("valid", record, [], "accepted", 0, 1),
                ("late_invalid_coefficient", bytes(late), [], "rejected", 1, 1),
                ("truncated_record", record[:-1], [], "rejected", 1, 1),
                ("impossible_proof_length", bytes(malformed_length), [], "rejected", 1, 1),
                ("work_short", record, ["--units", "0"], "admission_rejected", 2, 0),
                ("byte_short", record, ["--input-bytes", str(len(record) - 1)], "admission_rejected", 2, 0),
                ("arena_exhaustion", record, ["--heap-limit", "1"], "resource_exhausted", 73, 1),
            ]
            for label, data, flags, outcome, code, charge in variants:
                yield {**base, "case": label, "input": data, "flags": flags,
                       "expected_outcome": outcome, "expected_exit": code, "expected_charge": charge}
    stem, role, record, _, _ = fixture_record(root, "candidate", 0)
    yield {"fixture": stem, "row": "candidate", "role": role, "seats": 0,
           "case": "long_path_work_short", "input": record, "flags": ["--units", "0"],
           "long_path": True, "expected_outcome": "admission_rejected", "expected_exit": 2,
           "expected_charge": 0}
    yield {"fixture": None, "row": "candidate", "role": "registration", "seats": 0,
           "case": "fifo_input", "input": b"", "flags": [], "fifo": True,
           "expected_outcome": "input_error", "expected_exit": 3, "expected_charge": 0}
    yield {"fixture": None, "row": "candidate", "role": "registration", "seats": 0,
           "case": "empty_input", "input": b"", "flags": [],
           "expected_outcome": "rejected", "expected_exit": 1, "expected_charge": 1}
    yield {"fixture": None, "row": "candidate", "role": "registration", "seats": 0,
           "case": "oversized_input", "input": bytes(MAX_INPUT_BYTES + 1), "flags": [],
           "expected_outcome": "admission_rejected", "expected_exit": 2, "expected_charge": 0}


def source_inventory(root):
    """Conservatively pin the earlier full dependency scope plus current additions."""
    old = root / "docs/validation/parliament_ballot_b6/malformed-source.sha256"
    paths = {line.split("  ", 1)[1] for line in old.read_text().splitlines()}
    for directory in ["crates/iroha_parliament_ballot_proof/src",
                      "crates/iroha_parliament_ballot_proof/examples/resource_contract",
                      "crates/iroha_zkp_vole/src", "crates/norito/src", "vendor/aes/src"]:
        paths.update(p.relative_to(root).as_posix() for p in (root / directory).rglob("*.rs"))
    paths.update(p.relative_to(root).as_posix() for p in (root / FIXTURES).glob("*.proof"))
    paths.update(p.relative_to(root).as_posix() for p in (root / FIXTURES).glob("*.txt"))
    paths.update(["crates/iroha_parliament_ballot_proof/examples/resource_contract.rs",
                  "scripts/check_parliament_ballot_resource_contract.py",
                  "scripts/tests/parliament_ballot_resource_contract_test.py",
                  "specs/parliament_ballot_resource_contract.md"])
    return {name: digest((root / name).read_bytes()) for name in sorted(paths)}


def validate_observation(case, returncode, value, mode=None):
    """Reject mismatched outcomes, debit changes and inflated containment claims."""
    if not isinstance(value, dict):
        raise ValueError("worker JSON must be an object")
    if returncode != case["expected_exit"] or value.get("outcome") != case["expected_outcome"]:
        raise ValueError("unexpected worker outcome/exit (signals are not proof rejection or OOM)")
    units = case["expected_charge"]
    if value.get("charged_units") != units or value.get("charged_bytes") != (len(case["input"]) if units else 0):
        raise ValueError("worker debit mismatch")
    if value.get("complete_workspace_certificate") is not False or value.get("profile_qualified") is not False:
        raise ValueError("worker must preserve qualification gates")
    if mode is not None and returncode != 73 and value.get("accelerated") is not (mode == "accel"):
        raise ValueError("worker feature mode does not match its campaign slot")
    if case["case"] == "late_invalid_coefficient" and value.get("verifier_stage") != "proof":
        raise ValueError("late-invalid fixture did not reach proof verification")
    if returncode == 2 and value.get("arena_allocations") != 0:
        raise ValueError("admission refusal allocated verifier workspace")
    if returncode in (0, 1):
        parts = ["heap_reserved_bytes", "metadata_reserved_bytes", "stack_usable_bytes",
                 "guard_bytes", "control_reserved_bytes"]
        for key in parts:
            if type(value.get(key)) is not int or value[key] < 0:
                raise ValueError(f"invalid mapping component {key}")
        total = sum(value[key] for key in parts)
        if total != value.get("workspace_reserved_bytes") or not 0 < total <= WORKSPACE_LIMIT:
            raise ValueError("workspace mapping sum exceeds contract")
        fixed = {"heap_reserved_bytes": 32 * 1024 * 1024,
                 "metadata_reserved_bytes": 1024 * 1024,
                 "stack_usable_bytes": 8 * 1024 * 1024,
                 "control_reserved_bytes": 64 * 1024,
                 "guard_bytes": 2 * os.sysconf("SC_PAGESIZE"),
                 "heap_limit_bytes": 32 * 1024 * 1024}
        if any(value.get(key) != expected for key, expected in fixed.items()):
            raise ValueError("worker fixed partition does not match the contract")
        if value.get("arena_enforced") is not True:
            raise ValueError("arena was not enforced")
        if not 0 <= value["arena_peak_requested_bytes"] <= value["arena_peak_block_bytes"] <= value["heap_limit_bytes"]:
            raise ValueError("arena peaks exceed enforced quota")
        if value["arena_live_exit_requested_bytes"] != 0 or value["arena_live_exit_block_bytes"] != 0:
            raise ValueError("verifier-owned values survived the invocation")


def validate_build_provenance(receipt, sources, binary_hashes):
    """Bind observed executables to the retained successful compiled-source scope."""
    if (receipt.get("build_passed") is not True or receipt.get("failure") is not None
            or receipt.get("source_changes") != {}):
        raise ValueError("build receipt is not a successful frozen build")
    compiled = receipt.get("started_source_sha256")
    if not isinstance(compiled, dict) or not compiled:
        raise ValueError("build receipt has no compiled-source snapshot")
    # This is the reviewed conservative inventory, not independent discovery of
    # rustc's dependency graph. A receipt must cover it completely: accepting an
    # arbitrary nonempty subset could omit precisely the source that changed.
    observed_only = {"scripts/check_parliament_ballot_resource_contract.py",
                     "scripts/tests/parliament_ballot_resource_contract_test.py",
                     "specs/parliament_ballot_resource_contract.md"}
    expected = {path for path in sources if path not in observed_only
                and not path.startswith(FIXTURES.as_posix() + "/")}
    if set(compiled) != expected:
        raise ValueError("build receipt does not cover the complete reviewed source scope")
    if any(sources.get(path) != expected for path, expected in compiled.items()):
        raise ValueError("campaign sources do not match the retained build snapshot")
    for mode, expected in binary_hashes.items():
        if receipt["binaries"][mode]["sha256"] != expected:
            raise ValueError("campaign executable does not match its build receipt")


def campaign(root, binaries, output, build_receipt, timeout=120, execute=subprocess.run):
    """Persist every observation, including failures; never overwrite an old run."""
    output.mkdir(parents=True, exist_ok=False)
    before, binary_hashes = {}, {}
    observations = []
    failure = None
    snapshot_complete = False
    receipt_hash = None
    # Create the journal before fallible setup, so a failed setup has a durable
    # empty journal and explicit failed report rather than disappearing.
    journal_path = output / "cases.jsonl"
    journal_path.touch()
    try:
        if set(binaries) != {"portable", "accel"}:
            raise ValueError("campaign requires both distinct feature-mode slots")
        before = source_inventory(root)
        binary_hashes = {mode: digest(path.read_bytes()) for mode, path in binaries.items()}
        receipt_bytes = build_receipt.read_bytes()
        receipt_hash = digest(receipt_bytes)
        validate_build_provenance(json.loads(receipt_bytes), before, binary_hashes)
        snapshot_complete = True
        with tempfile.TemporaryDirectory(prefix="parliament-resource-inputs-") as temp:
            with journal_path.open("a") as journal:
                for case in cases(root):
                    path = Path(temp) / "record.bin"
                    if case.get("long_path"):
                        path = Path(temp).joinpath(*(["x" * 64] * 7), "record.bin")
                        path.parent.mkdir(parents=True)
                    if case.get("fifo"):
                        path = Path(temp) / "record.fifo"
                        os.mkfifo(path)
                    else:
                        path.write_bytes(case["input"])
                    for mode, binary in binaries.items():
                        command = [str(binary), case["row"], case["role"], str(path), *case["flags"]]
                        record = {key: value for key, value in case.items() if key != "input"}
                        record.update(mode=mode, command=command, input_bytes=len(case["input"]),
                                      input_sha256=digest(case["input"]))
                        try:
                            result = execute(command, capture_output=True, text=True, timeout=timeout)
                            record.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
                            value = json.loads(result.stdout)
                            validate_observation(case, result.returncode, value, mode)
                            record["worker"] = value
                            record["check_passed"] = True
                        except (Exception, KeyboardInterrupt) as error:
                            record["check_passed"] = False
                            record["failure"] = f"{type(error).__name__}: {error}"
                            if isinstance(error, subprocess.TimeoutExpired):
                                for key, partial in (("stdout", error.stdout), ("stderr", error.stderr)):
                                    record[key] = partial.decode(errors="replace") if isinstance(partial, bytes) else partial
                        observations.append(record)
                        journal.write(json.dumps(record, sort_keys=True) + "\n")
                        journal.flush()
                        os.fsync(journal.fileno())
                        if not record["check_passed"]:
                            raise ValueError(record["failure"])
    except (Exception, KeyboardInterrupt) as error:
        failure = f"{type(error).__name__}: {error}"
    source_changes, binary_changes = {}, []
    try:
        if snapshot_complete:
            after = source_inventory(root)
            source_changes = {key: {"before": before.get(key), "after": after.get(key)}
                              for key in sorted(before.keys() | after.keys()) if before.get(key) != after.get(key)}
            binary_changes = [mode for mode, path in binaries.items() if digest(path.read_bytes()) != binary_hashes[mode]]
            if digest(build_receipt.read_bytes()) != receipt_hash:
                failure = failure or "build provenance receipt changed during campaign"
    except Exception as error:
        failure = failure or f"source recheck failed: {error}"
    paired = {}
    for record in observations:
        if not record["check_passed"]:
            continue
        key = (record["fixture"], record["case"])
        value = record.get("worker", {})
        signature = (record["input_sha256"], value.get("outcome"), value.get("verifier_stage"),
                     value.get("charged_units"), value.get("charged_bytes"))
        paired.setdefault(key, {})[record["mode"]] = signature
    complete_pairs = [value for value in paired.values() if set(value) == {"portable", "accel"}]
    if any(value["portable"] != value["accel"] for value in complete_pairs):
        failure = failure or "portable/accelerated result, stage or debit mismatch"
    if not complete_pairs or len(complete_pairs) * 2 != len(observations):
        failure = failure or "campaign has no cases or incomplete feature-mode pairs"
    complete = snapshot_complete and failure is None and not source_changes and not binary_changes
    report = {"status": "diagnostic_complete" if complete else "diagnostic_failed",
              "failure": failure, "source_changes": source_changes, "binary_changes": binary_changes,
              "source_sha256": before, "binaries_sha256": binary_hashes,
              "build_receipt_sha256": receipt_hash, "build_snapshot_matched": snapshot_complete,
              "observations": len(observations), "feature_mode_pairs": len(complete_pairs),
              "records_sha256": digest(journal_path.read_bytes()),
              "reservation_campaign_passed": complete,
              "complete_workspace_certificate": False, "physical_cost_calibrated": False,
              "profile_qualified": False}
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    """Parse explicit artifact paths and return a failing status for incomplete runs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--portable", required=True, type=Path)
    parser.add_argument("--accel", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--build-receipt", required=True, type=Path)
    args = parser.parse_args()
    binaries = {"portable": args.portable.resolve(), "accel": args.accel.resolve()}
    report = campaign(ROOT, binaries, args.output_dir, args.build_receipt)
    print(json.dumps({key: value for key, value in report.items() if key != "source_sha256"}, sort_keys=True))
    return 0 if report["reservation_campaign_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
