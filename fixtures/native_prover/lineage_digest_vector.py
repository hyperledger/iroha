#!/usr/bin/env python3
"""Emit the independent two-control KAGEMUSHA lineage digest encoding vector.

Run with Python 3.10+ and its standard library from any working directory:
    python3 fixtures/native_prover/lineage_digest_vector.py

The maintained integer RP57 reference reads the retained constant corpus. This
producer checks that its Fp table has the pinned digest and equals the native
binary table, but never calls Rust, reads a Rust result, or generates a proof.
Output is JSON on stdout; no files or environment variables are modified.
The mask-7 result is a raw hashing control, not an admitted lineage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from reference_verifier import require
from reference_verifier.curve import P
from reference_verifier.transcript import KATS, Sponge


def main() -> None:
    """Derive and check both vectors, emitting every input and parameter pin."""
    argparse.ArgumentParser(description=__doc__).parse_args()
    fixture_dir = Path(__file__).resolve().parent
    root = fixture_dir.parents[1]
    constants = KATS["poseidon_constants"]
    require(constants["full_rounds"] == 8 and constants["partial_rounds"] == 57,
            "RP57 round counts")
    rows, matrix = constants["fp"]["round_constants"], constants["fp"]["mds"]
    require(len(rows) == 65 and len(matrix) == 3 and
            all(len(row) == 3 for row in rows + matrix), "RP57 table dimensions")
    words = [bytes.fromhex(value) for row in rows + matrix for value in row]
    require(all(len(word) == 32 and int.from_bytes(word, "little") < P for word in words),
            "canonical RP57 Fp constants")
    table = b"".join(words)
    table_pin = "9193ac5da831ecf38647ad4050ce4c557d688c4aabc12fe75e3b1e090c454a20"
    require(len(table) == 6528 and hashlib.sha256(table).hexdigest() == table_pin,
            "retained RP57 Fp table pin")
    native_table = "crates/iroha_pasta/src/poseidon/rp57_fp.bin"
    require((root / native_table).read_bytes() == table, "native RP57 Fp table equality")

    # The public prefix is specified by Lambda/Omega §3.2: byte-string halves
    # are little endian; SEC1 coordinates are big-endian integers split at bit 128.
    halves = (1 << 128) - 1
    scheme = int.from_bytes(bytes(range(32)), "little")
    relation = int.from_bytes(bytes(reversed(range(32))), "little")
    wallet = int.from_bytes(bytes([0x42]) * 32, "little")
    key_x = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
    key_y = int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
    prefix = [
        ("version", 1),
        ("scheme_id.lo128", scheme & halves), ("scheme_id.hi128", scheme >> 128),
        ("relation_id.lo128", relation & halves), ("relation_id.hi128", relation >> 128),
        ("head", 3),
        ("wallet_id.lo128", wallet & halves), ("wallet_id.hi128", wallet >> 128),
        ("credential_digest", 5),
        ("payment_key.x.lo128", key_x & halves), ("payment_key.x.hi128", key_x >> 128),
        ("payment_key.y.lo128", key_y & halves), ("payment_key.y.hi128", key_y >> 128),
        ("lifecycle | policy_epoch<<8 | enabled_controls<<72", 0),
        ("burned_total", 0x112233445566778899AABBCCDDEEFF00),
        ("pending_outgoing_root", 9), ("credit_digest_root", 10),
        ("omega_verifying_key_digest", 11),
    ]
    require(len(prefix) == 18, "native public prefix length")
    claim = [("pallas.g.x", P - 1), ("pallas.g.y", 2)]
    for challenge in range(1, 17):
        claim.extend([(f"pallas.challenge[{challenge - 1}].lo128", challenge),
                      (f"pallas.challenge[{challenge - 1}].hi128", 0)])
    require((2 * 2 - ((P - 1) ** 3 + 5)) % P == 0, "finite Pallas encoding point")

    domain = int.from_bytes(b"kgwomg_1", "little")
    cases = []
    for mask, expected in [
        (3, "4501dca8d1da0168c8000e3bcb18c2178e5258e5bff684a07a6bc1fed852780f"),
        (7, "9570139378353ed3bfd6a661281cbc42989a3f5493be973914a21c94a04fc407"),
    ]:
        fields = prefix + claim
        fields[13] = (prefix[13][0], 1 | (0x0102030405060708 << 8) | (mask << 72))
        require(len(fields) == 52, "lineage digest field count")
        sponge = Sponge(P)
        for value in [domain, len(fields)] + [value for _, value in fields]:
            sponge.absorb(value)
        digest = sponge.squeeze().to_bytes(32, "little").hex()
        require(digest == expected, f"independent mask-{mask} known answer")
        cases.append({
            "enabled_controls": mask,
            "control_status": "current two-control encoding" if mask == 3 else
                              "retired raw-hash control; native lineage admission must reject",
            "fields": [{"index": i, "name": name, "integer": str(value),
                        "le32_hex": value.to_bytes(32, "little").hex()}
                       for i, (name, value) in enumerate(fields)],
            "digest_le32_hex": digest,
        })
    changed = [i for i in range(52) if cases[0]["fields"][i] != cases[1]["fields"][i]]
    require(changed == [13], "only the packed control word changes")
    print(json.dumps({
        "schema": "iroha.kagemusha.lineage-digest-integer-vector.v1",
        "purpose": "encoding KAT only; no accumulator decide or monetary acceptance",
        "field_modulus_hex": f"{P:064x}",
        "rp57": {"width": 3, "rate": 2, "full_rounds": 8, "partial_rounds": 57,
                  "native_table": native_table, "table_bytes": len(table),
                  "table_sha256": table_pin,
                  "retained_constants": "fixtures/native_prover/kats_v1.json#poseidon_constants.fp",
                  "retained_corpus_sha256": hashlib.sha256(
                      (fixture_dir / "kats_v1.json").read_bytes()).hexdigest(),
                  "integer_reference": "fixtures/native_prover/reference_verifier/transcript.py",
                  "integer_reference_sha256": hashlib.sha256(
                      (fixture_dir / "reference_verifier/transcript.py").read_bytes()).hexdigest()},
        "sponge": {"initial_state": [str(1 << 64), "0", "0"],
                   "absorbed_prefix": [str(domain), "52"], "domain_ascii": "kgwomg_1",
                   "padding": "append field 1; absorb pairs into state[1:3]; output state[1]"},
        "cases": cases,
    }, indent=2) + "\n", end="")


if __name__ == "__main__":
    main()
