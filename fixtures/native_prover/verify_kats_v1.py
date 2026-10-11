#!/usr/bin/env python3
"""Independent check of fixtures/native_prover/kats_v1.json.

The fixture is generated from the vendored halo2 stack by
`crates/iroha_plonk_oracle/tests/native_prover_kats.rs`. This script re-derives
what it can with the Python standard library only, so the vectors stay checkable
after the vendored stack is deleted:

- Pasta point decompression for every recorded point;
- `ParamsIPA` byte lengths;
- the Blake2b transcript: every challenge from `hashlib.blake2b` with the
  `Halo2-Transcript` personalization, the absorbed bytes of every operation and
  the written stream;
- the Poseidon permutation from the pinned unoptimized constants with the
  snark-verifier sponge rules: every KAGEMUSHA and confidential hash, both tree
  roots, every Poseidon transcript challenge and its absorbed elements;
- the transcript decoding rejections: every rejected scalar is at least the
  modulus, every rejected point is the identity, has a non-canonical x or has
  no curve point, and no two rejections of a list share an input.

Hash-to-curve generation of the generators is not re-derived here.

Prerequisites: Python 3.9+ (standard library only). No environment variables.
Usage: python3 fixtures/native_prover/verify_kats_v1.py [path/to/kats_v1.json]
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

P = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
Q = 0x40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001
CURVE_B = 5
# (scalar modulus, base modulus) per cycle: Eq/Vesta has scalar Fp and base Fq.
CURVES = {"eq": (P, Q), "ep": (Q, P)}
FIELDS = {"fp": P, "fq": Q}


def le(hex_value: str) -> int:
    """Little-endian integer of a hex string."""
    return int.from_bytes(bytes.fromhex(hex_value), "little")


def le_hex(value: int) -> str:
    """32-byte little-endian hex of an integer."""
    return value.to_bytes(32, "little").hex()


def sqrt_mod(value: int, modulus: int) -> int | None:
    """Tonelli-Shanks square root, or None for a non-residue."""
    value %= modulus
    if value == 0:
        return 0
    if pow(value, (modulus - 1) // 2, modulus) != 1:
        return None
    s, t = 0, modulus - 1
    while t % 2 == 0:
        s, t = s + 1, t // 2
    z = 2
    while pow(z, (modulus - 1) // 2, modulus) == 1:
        z += 1
    m, c, r, x = s, pow(z, t, modulus), pow(value, (t + 1) // 2, modulus), pow(value, t, modulus)
    while x != 1:
        i, probe = 0, x
        while probe != 1:
            probe, i = probe * probe % modulus, i + 1
        b = pow(c, 1 << (m - i - 1), modulus)
        m, c, r, x = i, b * b % modulus, r * b % modulus, x * b * b % modulus
    return r


def decompress(hex_value: str, base: int) -> tuple[int, int] | None:
    """Affine coordinates of a compressed Pasta point; None for the identity."""
    raw = bytearray(bytes.fromhex(hex_value))
    sign = raw[31] >> 7
    raw[31] &= 0x7F
    x = int.from_bytes(raw, "little")
    if x == 0 and sign == 0:
        return None
    assert x < base, f"non-canonical x in {hex_value}"
    y = sqrt_mod(pow(x, 3, base) + CURVE_B, base)
    assert y is not None, f"{hex_value} is not on the curve"
    if y % 2 != sign:
        y = base - y
    return x, y


class Sponge:
    """snark-verifier native Poseidon sponge over the plain permutation."""

    def __init__(self, document: dict, field: str) -> None:
        constants = document["poseidon_constants"]
        self.modulus = FIELDS[field]
        self.round_constants = [[le(x) for x in row] for row in constants[field]["round_constants"]]
        self.mds = [[le(x) for x in row] for row in constants[field]["mds"]]
        self.full = constants["full_rounds"]
        self.partial = constants["partial_rounds"]
        self.state = [1 << 64, 0, 0]
        self.buffer: list[int] = []

    def permute(self) -> None:
        """Apply the plain width-3 x^5 permutation."""
        m, s = self.modulus, self.state
        for index, constants in enumerate(self.round_constants):
            s = [(value + constant) % m for value, constant in zip(s, constants)]
            full = index < self.full // 2 or index >= self.full // 2 + self.partial
            s = [pow(v, 5, m) for v in s] if full else [pow(s[0], 5, m)] + s[1:]
            s = [sum(a * b for a, b in zip(row, s)) % m for row in self.mds]
        self.state = s

    def squeeze(self, elements: list[int]) -> int:
        """Absorb `elements` with the sponge padding and return state[1]."""
        buffer = self.buffer + elements
        self.buffer = []
        for start in range(0, len(buffer), 2):
            chunk = buffer[start : start + 2]
            for offset, value in enumerate(chunk):
                self.state[1 + offset] = (self.state[1 + offset] + value) % self.modulus
            if len(chunk) < 2:
                self.state[1 + len(chunk)] = (self.state[1 + len(chunk)] + 1) % self.modulus
            self.permute()
        if len(buffer) % 2 == 0:
            self.state[1] = (self.state[1] + 1) % self.modulus
            self.permute()
        return self.state[1]


def domain_hash(document: dict, field: str, tag: str, inputs: list[int]) -> int:
    """`hash(domain, inputs)` over a fresh sponge: [domain, len, inputs...]."""
    word = int.from_bytes(tag.encode("ascii"), "little")
    return Sponge(document, field).squeeze([word, len(inputs), *inputs])


def check_points(document: dict) -> int:
    """Every recorded generator decompresses to a curve point."""
    count = 0
    for curve, (_, base) in CURVES.items():
        section = document["generators"][curve]
        for point in [*section["g"], section["w"], section["u"]]:
            assert decompress(point, base) is not None
            count += 1
    return count


def check_params(document: dict) -> int:
    """`ParamsIPA` byte length is 4 + 64 * 2^k + 64."""
    entries = [entry for curve in CURVES for entry in document["params_ipa"][curve]]
    for entry in entries:
        assert entry["byte_len"] == 4 + 64 * (1 << entry["k"]) + 64, entry
    return len(entries)


def blake2b_absorbed(op: dict, base: int) -> bytes:
    """Bytes the Blake2b transcript absorbs for one operation."""
    if op["op"] == "squeeze":
        return b"\x00"
    if op["op"].endswith("scalar"):
        return b"\x02" + bytes.fromhex(op["value"])
    x, y = decompress(op["value"], base)
    return b"\x01" + x.to_bytes(32, "little") + y.to_bytes(32, "little")


def check_blake2b(document: dict) -> int:
    """Recompute every Blake2b challenge, absorbed byte and stream."""
    count = 0
    for curve, (scalar, base) in CURVES.items():
        for script in document["blake2b_transcript"][curve]["scripts"]:
            absorbed = b"".join(blake2b_absorbed(op, base) for op in script["ops"])
            assert absorbed.hex() == script["absorbed_hex"], script["name"]
            written = "".join(op["value"] for op in script["ops"] if op["op"].startswith("write_"))
            assert written == script["stream_hex"], script["name"]
            for op in script["ops"]:
                if op["op"] != "squeeze":
                    continue
                digest = hashlib.blake2b(
                    absorbed[: op["absorbed"]], digest_size=64, person=b"Halo2-Transcript"
                ).digest()
                assert le_hex(int.from_bytes(digest, "little") % scalar) == op["challenge"]
                count += 1
    return count


def check_poseidon_transcript(document: dict) -> int:
    """Recompute every Poseidon transcript challenge and absorbed element."""
    count = 0
    for curve, (scalar, base) in CURVES.items():
        field = "fp" if scalar == P else "fq"
        for script in document["poseidon_transcript"][curve]["scripts"]:
            expected: list[int] = []
            for op in script["ops"]:
                if op["op"].endswith("scalar"):
                    expected.append(le(op["value"]))
                elif op["op"] != "squeeze":
                    x, y = decompress(op["value"], base)
                    expected += [x % scalar, y % scalar]
            absorbed = [le(value) for value in script["absorbed"]]
            assert absorbed == expected, script["name"]
            sponge, consumed = Sponge(document, field), 0
            for op in script["ops"]:
                if op["op"] == "squeeze":
                    challenge = sponge.squeeze(absorbed[consumed : op["absorbed"]])
                    consumed = op["absorbed"]
                    assert le_hex(challenge) == op["challenge"], script["name"]
                    count += 1
            written = "".join(op["value"] for op in script["ops"] if op["op"].startswith("write_"))
            assert written == script["stream_hex"], script["name"]
    return count


def check_native_hashes(document: dict) -> int:
    """Recompute every KAGEMUSHA and confidential hash and both tree roots."""
    count = 0
    for section in ("kagemusha_v1_poseidon", "confidential_v3_poseidon"):
        for field in FIELDS:
            for vector in document[section][field]["vectors"]:
                inputs = [le(value) for value in vector["inputs"]]
                output = domain_hash(document, field, vector["domain"], inputs)
                assert le_hex(output) == vector["output"], (section, field, vector["domain"])
                count += 1
    for field in FIELDS:
        root = domain_hash(document, field, "kgmemp_1", [])
        for _ in range(256):
            root = domain_hash(document, field, "kgmnode1", [root, root])
        assert le_hex(root) == document["kagemusha_v1_poseidon"][field]["empty_replay_root"]
        roots = [domain_hash(document, field, "cfleaf03", [0])]
        for _ in range(16):
            roots.append(domain_hash(document, field, "cfnode03", [roots[-1], roots[-1]]))
        assert [le_hex(r) for r in roots] == document["confidential_v3_poseidon"][field]["empty_subtree_roots"]
        count += 2
    return count


def point_rejected(hex_value: str, base: int) -> bool:
    """True when a compressed encoding is the identity, non-canonical or off the curve."""
    raw = bytearray(bytes.fromhex(hex_value))
    raw[31] &= 0x7F
    x = int.from_bytes(raw, "little")
    if hex_value == "00" * 32 or x >= base:
        return True
    return sqrt_mod(pow(x, 3, base) + CURVE_B, base) is None


def check_confidential_vectors(document: dict, vectors: dict) -> int:
    """Independently rederive the complete retired confidential oracle corpus."""
    assert vectors["schema"] == "iroha.native_prover.confidential_poseidon.v1"
    cases = [
        ("cfownr03", [3, 5]), ("cfnote03", [3, 5, 8, 13]),
        ("cfnull03", [3, 5, 8, 13]), ("cfleaf03", [3]),
        ("cfnode03", [3, 5]), ("cfasst03", [3]), ("cfnet_03", [3]),
    ]
    assert vectors["domain_cases"] == [{"tag": tag, "inputs": inputs} for tag, inputs in cases]
    domains = [0, (1 << 64) - 1, int.from_bytes(b"cfnote03", "little")]
    assert vectors["boundary_domains"] == domains
    assert set(vectors["fields"]) == set(FIELDS)
    count = 0
    for field, modulus in FIELDS.items():
        outputs = vectors["fields"][field]
        assert len(outputs["domain_outputs"]) == len(cases)
        assert len(outputs["boundary_outputs"]) == 34
        for (tag, inputs), expected in zip(cases, outputs["domain_outputs"]):
            assert le_hex(domain_hash(document, field, tag, inputs)) == expected
            count += 1
        for length, expected in enumerate(outputs["boundary_outputs"]):
            assert len(expected) == len(domains)
            inputs = [
                (0, 1, modulus - 1, index)[index % 4]
                for index in range(length)
            ]
            for domain, output in zip(domains, expected):
                actual = Sponge(document, field).squeeze([domain, length, *inputs])
                assert le_hex(actual) == output, (field, length, domain)
                count += 1
    return count


def check_rejections(document: dict) -> int:
    """Every recorded transcript rejection is a malformed input, without repeats."""
    count = 0
    for section in ("blake2b_transcript", "poseidon_transcript"):
        for curve, (scalar, base) in CURVES.items():
            inputs = []
            for rejection in document[section][curve]["rejections"]:
                assert rejection["result"] == "rejected", rejection
                if "input_hex" not in rejection:
                    continue
                value = rejection["input_hex"]
                assert value not in inputs, (section, curve, rejection["name"])
                inputs.append(value)
                if rejection["op"] == "read_scalar":
                    assert le(value) >= scalar, (section, curve, rejection["name"])
                else:
                    assert point_rejected(value, base), (section, curve, rejection["name"])
                count += 1
    return count


def main(argv: list[str]) -> int:
    """Check the fixture and print what was verified."""
    path = Path(argv[1]) if len(argv) > 1 else Path(__file__).with_name("kats_v1.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["format"] == "iroha.native_prover.kats.v1"
    for table in document["golden_proofs"].values():
        for case in table["cases"]:
            assert len(bytes.fromhex(case["sha256"])) == 32, case
    results = {
        "points": check_points(document),
        "params": check_params(document),
        "blake2b_challenges": check_blake2b(document),
        "poseidon_transcript_challenges": check_poseidon_transcript(document),
        "native_hashes": check_native_hashes(document),
        "confidential_boundary_vectors": check_confidential_vectors(
            document,
            json.loads(Path(__file__).with_name("confidential_poseidon_v1.json").read_text(encoding="utf-8")),
        ),
        "rejections": check_rejections(document),
    }
    print(f"{path}: verified " + ", ".join(f"{name}={count}" for name, count in results.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
