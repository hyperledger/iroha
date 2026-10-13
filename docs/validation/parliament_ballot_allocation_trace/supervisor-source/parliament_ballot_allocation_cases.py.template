#!/usr/bin/env python3
"""Build public allocation-correspondence cases from existing ballot fixtures.

Python 3.11+, adjacent frozen resource/frontend/backend helpers and repository
fixtures. No environment variables, proofs generated, network, devices or writes.
Malformed cases identify an expected allocation boundary; only actual execution
and stream matching can establish that the bytes exercise it in the built worker.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

import check_parliament_ballot_resource_contract as resource
import parliament_ballot_arena_frontend as frontend
import parliament_ballot_arena_backend as backend

ROOT = Path(__file__).resolve().parents[1]


def split_record(record: bytes) -> tuple[bytes, list[bytes], bytes]:
    """Parse known public fixtures exactly before constructing a changed frame."""
    length, = struct.unpack_from("<I", record)
    statement = record[4:4 + length]
    proof_length, = struct.unpack_from("<I", record, 4 + length)
    proof = record[8 + length:]
    if len(proof) != proof_length:
        raise ValueError("fixture record proof length mismatch")
    tag_length, = struct.unpack_from("<H", statement)
    tag = statement[2:2 + tag_length]
    count, = struct.unpack_from("<H", statement, 2 + tag_length)
    offset = 4 + tag_length
    fields = []
    for _ in range(count):
        size, = struct.unpack_from("<I", statement, offset)
        offset += 4
        fields.append(statement[offset:offset + size])
        if len(fields[-1]) != size:
            raise ValueError("fixture frame truncated")
        offset += size
    if offset != len(statement):
        raise ValueError("fixture frame trailing bytes")
    return tag, fields, proof


def pack(statement: bytes, proof: bytes) -> bytes:
    """Use the existing explicit TEST_RECORD framing only."""
    return struct.pack("<I", len(statement)) + statement + struct.pack("<I", len(proof)) + proof


def build_cases(root: Path = ROOT) -> list[dict]:
    """Return unique concrete inputs covering full, early-return and read-failure paths."""
    result = []
    for row in ("candidate", "comparator"):
        for seats in (0, 3, 500, 1000):
            stem, role, record, proof_start, vector = resource.fixture_record(root, row, seats)
            tag, fields, proof = split_record(record)
            lengths = tuple(map(len, fields[1:8])) if not seats else frontend.REG_CAPS
            base = {"row": row, "role": role, "seats": seats, "fixture": stem,
                    "registration_lengths": list(lengths), "expected_charge": 1,
                    "expected_outcome": "rejected", "expected_exit": 1,
                    "flags": [], "stop": "backend", "expected_stage": "proof"}

            def add(name: str, data: bytes, **values) -> None:
                result.append({**base, "name": f"{row}-{role}-{seats}-{name}", "case": name, "input": data, **values})

            def changed(name: str, modified: list[bytes], **values) -> None:
                add(name, pack(resource.frame(tag, modified), proof), **values)

            add("valid", record, expected_outcome="accepted", expected_exit=0, expected_stage="complete")
            late = bytearray(record)
            late[proof_start + int.from_bytes(vector["field_a_tilde_1_6_offset_u32"], "little")] ^= 1
            add("late_invalid_coefficient", bytes(late))
            if seats not in (0, 3):
                continue
            frame = resource.frame(tag, fields)
            bad = bytearray(frame); bad[2] ^= 1
            add("frame_header", pack(bytes(bad), proof), stop="frame_header", expected_stage="codec")
            add("frame_body", pack(frame[:-1], proof), stop="frame_body", expected_stage="codec")
            copied = fields.copy(); copied[0] = bytes([copied[0][0] ^ 1]) + copied[0][1:]
            changed("descriptor", copied, stop="descriptor", expected_stage="codec")
            if seats:
                for name, field, replacement, stop in (
                    ("vote_before_list", 4, b"\x03", "vote_before_list"),
                    ("vote_after_list", 6, fields[6][:-1], "vote_after_list"),
                    ("vote_validation", 8, b"\x03", "vote_validation"),
                    ("vote_digest", 3, bytes([fields[3][0] ^ 1]) + fields[3][1:], "vote_digest"),
                ):
                    copied = fields.copy(); copied[field] = replacement
                    changed(name, copied, stop=stop, expected_stage="codec")
                continue
            for index, cap in enumerate(frontend.REG_CAPS):
                copied = fields.copy(); copied[index + 1] = bytes(cap + 1)
                changed(f"registration_field_{index}", copied, stop=f"registration_field_{index}", expected_stage="codec")
            copied = fields.copy(); copied[9] = fields[9][:-1]
            changed("registration_fixed", copied, stop="registration_fixed", expected_stage="codec")
            copied = fields.copy(); copied[8] = bytes([fields[8][0] ^ 1]) + fields[8][1:]
            changed("registration_digest", copied, stop="registration_digest", expected_stage="codec")
            for label, sizes in (("zero", (0,) * 7), ("maximum", frontend.REG_CAPS),
                                 ("interior", (257, 65, 129, 17, 33, 1, 255))):
                copied = fields.copy()
                copied[1:8] = [bytes([index + 1]) * size for index, size in enumerate(sizes)]
                copied[8] = hashlib.sha3_512(resource.frame(b"PARL/BODY/v1", [vector["P16"], copied[1]])).digest()
                changed("registration_lengths_" + label, copied, registration_lengths=list(sizes))
            add("work_short", record, flags=["--units", "0"], expected_charge=0,
                expected_outcome="admission_rejected", expected_exit=2, expected_stage="reserve", stop="admission")
            for mode in ("eof", "eio"):
                add("charged_read_" + mode, record, flags=["--read-mode", mode],
                    expected_outcome="input_error", expected_exit=3, expected_stage="read", stop="read")
    if len(result) != 66 or len({case["name"] for case in result}) != 66:
        raise ValueError("allocation case inventory incomplete or duplicated")
    return result


def grammar(case: dict, accelerated: bool) -> list[dict]:
    """Compose the already reviewed allocation grammar for an expected boundary."""
    front = frontend.frontend_trace(case["row"], case["role"], record_bytes=len(case["input"]),
                                    registration_lengths=tuple(case["registration_lengths"]),
                                    seats=case["seats"] or 3, stop=case["stop"])
    if case["stop"] != "backend":
        return front["prefix"]
    return front["prefix"] + backend.backend_trace(case["row"], case["role"], seats=case["seats"] or 3,
                                                   accel=accelerated) + front["suffix"]


def main() -> int:
    """Describe the finite corpus without executing or qualifying it."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    cases = build_cases()
    print(json.dumps({"cases": [{**{key: value for key, value in case.items() if key != "input"},
                                  "input_bytes": len(case["input"]), "input_sha256": hashlib.sha256(case["input"]).hexdigest()}
                                 for case in cases], "profile_qualified": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
