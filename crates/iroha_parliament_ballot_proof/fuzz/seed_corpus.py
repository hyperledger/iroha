#!/usr/bin/env python3
"""Build reproducible parser seeds from archived public fixture bytes (no proving)."""

import argparse
import hashlib
from pathlib import Path


def fields(frame):
    """Read an existing trusted fixture frame."""
    at = 2 + int.from_bytes(frame[:2], "little")
    count = int.from_bytes(frame[at:at + 2], "little")
    at += 2
    out = []
    for _ in range(count):
        size = int.from_bytes(frame[at:at + 4], "little")
        at += 4
        out.append(frame[at:at + size])
        at += size
    assert at == len(frame)
    return out


def frame(tag, parts):
    """Encode the test Frame format."""
    return len(tag).to_bytes(2, "little") + tag + len(parts).to_bytes(2, "little") + b"".join(
        len(part).to_bytes(4, "little") + part for part in parts
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    fixtures = Path(__file__).resolve().parents[1] / "tests/fixtures"
    seeds = {"empty": b""}
    for row, name in enumerate(("fast", "comparator")):
        for role, prefix in ((0, "reg"), (1, "vote_S3_i1"), (1, "vote_S1000_i500")):
            case = f"{prefix}_{name}"
            vector = dict(line.split(" = ") for line in (fixtures / f"{case}.txt").read_text().splitlines()
                          if line and not line.startswith("#"))
            vector = {key: bytes.fromhex(value) for key, value in vector.items()}
            kind = "REG" if role == 0 else "VOTE"
            if f"F_{kind}" in vector:
                parts = fields(vector[f"F_{kind}"])
            else:
                # The large fixtures pin the frame/list digests instead of duplicating
                # their full bytes. Reproduce only public commitment labels here.
                size = int.from_bytes(vector["S_u16"], "little")
                members = []
                for member in range(size):
                    secret = hashlib.shake_256(b"PARL-ballot-proto/fixture/v1/" + f"member-sk-{member}".encode()).digest(48)
                    members.append(hashlib.shake_256(b"PCR1" + vector["P16"] + secret + vector["B"]).digest(128))
                public_list = b"".join(sorted(members))
                assert hashlib.shake_256(public_list).digest(64) == vector["list_concat_shake256_64"]
                parts = [vector[key] for key in ("B", "scope", "R", "S_u16")]
                parts += [public_list] + [vector[key] for key in ("nf", "auth_v", "vote_u8", "policy_hash")]
            statement = frame(f"PARL/TEST/{kind}/v1".encode(), [vector["D"]] + parts)
            assert hashlib.shake_256(statement).digest(64) == vector["test_statement_shake256_64"]
            proof = (fixtures / f"{case}.proof").read_bytes()
            record = len(statement).to_bytes(4, "little") + statement + len(proof).to_bytes(4, "little") + proof
            assert hashlib.shake_256(record).digest(64) == vector["test_record_shake256_64"]
            for mode, data in enumerate((statement, proof, record)):
                seeds[f"{case}_{mode}"] = bytes([row + 2 * role + 4 * mode]) + data
            invalid = bytearray(proof)
            invalid[-4:] = (1 << 20).to_bytes(4, "little")
            seeds[f"{case}_counter"] = bytes([row + 2 * role + 4]) + invalid
            invalid = bytearray(proof)
            at = int.from_bytes(vector["field_a_tilde_1_6_offset_u32"], "little")
            invalid[at] ^= 1
            seeds[f"{case}_coefficient"] = bytes([row + 2 * role + 4]) + invalid
    for name, data in seeds.items():
        (args.output_dir / name).write_bytes(data)
    print(f"wrote {len(seeds)} seeds, {sum(map(len, seeds.values()))} bytes")


if __name__ == "__main__":
    main()
