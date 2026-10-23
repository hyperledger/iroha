#!/usr/bin/env python3
"""Deterministic inputs and official digests of the ML-KEM and ML-DSA known-answer tests.

Requires Python 3.9+ and its standard library only. Nothing is downloaded and no
environment variable is read. This is the post-quantum half of task H.1 of
specs/zk_delivery_plan.md; scripts/check_zk_primitive_workloads.py imports it.

The official vector is the first response (`count = 0`) of the NIST
known-answer generator as PQClean runs it (`test/crypto_kem/nistkat.c` and
`test/crypto_sign/nistkat.c`): an AES-256 CTR_DRBG seeded with the bytes
`00..2f` supplies the 48-byte seed, the DRBG is re-seeded with it, and the
algorithm draws its randomness from that second DRBG. PQClean records the
SHA-256 of the printed response as `nistkat-sha256` in each scheme's `META.yml`;
those files ship inside the `pqcrypto-mlkem` and `pqcrypto-mldsa` crates that
Cargo.lock pins.

This module
* reimplements AES-256 and the CTR_DRBG to derive the exact randomness each
  algorithm consumes (`inputs.txt`), so the Rust tests can call the
  derandomized entry points of `soranet_pq` without a DRBG of their own;
* holds the six official digests;
* checks that each tracked response file hashes to its official digest.

The Rust tests in crates/soranet_pq compare the output of the implementation
with the tracked response files byte for byte. Together the two checks show that
the implementation reproduces the official response. These count-zero checks do
not cover NIST ACVP vectors. The separate check_soranet_pq_acvp.py checker and
soranet_pq ACVP tests cover a pinned subset of external pure-message vectors,
key checks and context/message substitution. Prehash and internal-interface
ACVP groups remain outside that subset.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = "crates/soranet_pq/tests/fixtures/nistkat"
INPUTS_FIXTURE = f"{FIXTURE_DIR}/inputs.txt"

# `nistkat-sha256` of PQClean's META.yml, as vendored in pqcrypto-mlkem 0.1.1
# (pq-crystals/kyber 10b478fc3cc4ff6215eb0b6a11bd758bf0929cbd) and
# pqcrypto-mldsa 0.1.2 (pq-crystals/dilithium
# cbcd8753a43402885c90343cd6335fb54712cda1).
OFFICIAL_NISTKAT_SHA256 = {
    "ml-kem-512": "c70041a761e01cd6426fa60e9fd6a4412c2be817386c8d0f3334898082512782",
    "ml-kem-768": "5352539586b6c3df58be6158a6250aeff402bd73060b0a3de68850ac074c17c3",
    "ml-kem-1024": "f580d851e5fb27e6876e5e203fa18be4cdbfd49e05d48fec3d3992c8f43a13e6",
    "ml-dsa-44": "9a196e7fb32fbc93757dc2d8dc1924460eab66303c0c08aeb8b798fb8d8f8cf3",
    "ml-dsa-65": "7cb96242eac9907a55b5c84c202f0ebd552419c50b2e986dc2e28f07ecebf072",
    "ml-dsa-87": "4537905d2aabcf302fab2f242baed293459ecda7c230e6a67063b02c7e2840ed",
}
# Byte lengths fixed by FIPS 203 (public key, secret key, ciphertext, shared
# secret) and FIPS 204 (public key, secret key, signature).
FIPS_LENGTHS = {
    "ml-kem-512": (800, 1632, 768, 32),
    "ml-kem-768": (1184, 2400, 1088, 32),
    "ml-kem-1024": (1568, 3168, 1568, 32),
    "ml-dsa-44": (1312, 2560, 2420),
    "ml-dsa-65": (1952, 4032, 3309),
    "ml-dsa-87": (2592, 4896, 4627),
}
SIGNED_MESSAGE_BYTES = 33


# ---------------------------------------------------------------------------
# AES-256 block encryption (FIPS 197), table-free except for the S-box
# ---------------------------------------------------------------------------


def _build_sbox() -> list[int]:
    # Multiplicative inverse in GF(2^8) followed by the affine transformation.
    exp, log = [0] * 510, [0] * 256
    value = 1
    for index in range(255):
        exp[index] = value
        log[value] = index
        value ^= (value << 1) ^ (0x11B if value & 0x80 else 0)
        value &= 0xFF
    for index in range(255, 510):
        exp[index] = exp[index - 255]
    sbox = []
    for byte in range(256):
        inverse = 0 if byte == 0 else exp[255 - log[byte]]
        result = inverse
        for shift in (1, 2, 3, 4):
            result ^= ((inverse << shift) | (inverse >> (8 - shift))) & 0xFF
        sbox.append(result ^ 0x63)
    return sbox


_SBOX = _build_sbox()


def _xtime(value: int) -> int:
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


def _expand_key(key: bytes) -> list[list[int]]:
    words = [list(key[index : index + 4]) for index in range(0, 32, 4)]
    rcon = 1
    for index in range(8, 60):
        word = list(words[index - 1])
        if index % 8 == 0:
            word = [_SBOX[word[1]] ^ rcon, _SBOX[word[2]], _SBOX[word[3]], _SBOX[word[0]]]
            rcon = _xtime(rcon)
        elif index % 8 == 4:
            word = [_SBOX[value] for value in word]
        words.append([a ^ b for a, b in zip(words[index - 8], word)])
    return [sum(words[round_ * 4 : round_ * 4 + 4], []) for round_ in range(15)]


def aes256_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block with a 32-byte key."""
    if len(key) != 32 or len(block) != 16:
        raise ValueError("AES-256 needs a 32-byte key and a 16-byte block")
    round_keys = _expand_key(key)
    state = [value ^ round_keys[0][index] for index, value in enumerate(block)]
    for round_ in range(1, 15):
        state = [_SBOX[value] for value in state]
        # ShiftRows on a column-major state.
        state = [state[(index + 4 * (index % 4)) % 16] for index in range(16)]
        if round_ != 14:
            mixed = []
            for column in range(4):
                a = state[4 * column : 4 * column + 4]
                total = a[0] ^ a[1] ^ a[2] ^ a[3]
                mixed.extend(a[i] ^ total ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4))
            state = mixed
        state = [value ^ round_keys[round_][index] for index, value in enumerate(state)]
    return bytes(state)


# ---------------------------------------------------------------------------
# NIST known-answer CTR_DRBG (rng.c of the PQC submission package)
# ---------------------------------------------------------------------------


class NistKatDrbg:
    """AES-256 CTR_DRBG without derivation function, as the KAT generator uses it."""

    def __init__(self, entropy: bytes) -> None:
        if len(entropy) != 48:
            raise ValueError("the KAT DRBG is seeded with 48 bytes")
        self._key = bytes(32)
        self._counter = bytes(16)
        self._update(entropy)

    def _increment(self) -> None:
        self._counter = ((int.from_bytes(self._counter, "big") + 1) % (1 << 128)).to_bytes(
            16, "big"
        )

    def _update(self, provided: bytes | None) -> None:
        stream = b""
        for _ in range(3):
            self._increment()
            stream += aes256_encrypt_block(self._key, self._counter)
        if provided is not None:
            stream = bytes(a ^ b for a, b in zip(stream, provided))
        self._key, self._counter = stream[:32], stream[32:]

    def random_bytes(self, count: int) -> bytes:
        """Return `count` bytes; every call ends with a state update."""
        output = b""
        while len(output) < count:
            self._increment()
            output += aes256_encrypt_block(self._key, self._counter)
        self._update(None)
        return output[:count]


def kat_inputs() -> dict[str, bytes]:
    """Randomness the `count = 0` response consumes, in consumption order."""
    outer = NistKatDrbg(bytes(range(48)))
    seed = outer.random_bytes(48)
    message = outer.random_bytes(SIGNED_MESSAGE_BYTES)
    kem = NistKatDrbg(seed)
    keypair_coins = kem.random_bytes(64)  # d || z
    encapsulation_coins = kem.random_bytes(32)  # m
    sign = NistKatDrbg(seed)
    keygen_seed = sign.random_bytes(32)  # xi
    signing_randomness = sign.random_bytes(32)  # rnd
    return {
        "seed": seed,
        "mlkem_keypair_coins": keypair_coins,
        "mlkem_encapsulation_coins": encapsulation_coins,
        "mldsa_message": message,
        "mldsa_keygen_seed": keygen_seed,
        "mldsa_signing_randomness": signing_randomness,
    }


def render_inputs_fixture() -> str:
    """Render the inputs as the line-oriented fixture the Rust tests read."""
    lines = [
        "# Randomness of the NIST known-answer response `count = 0` (DRBG seed 00..2f).",
        "# Generated by `python3 scripts/zk_pq_kat_reference.py --write-inputs`.",
        "# Upper-case hex, as the response files print it. Do not edit by hand.",
    ]
    lines.extend(f"{name} {value.hex().upper()}" for name, value in kat_inputs().items())
    return "\n".join(lines) + "\n"


def response_path(suite: str) -> str:
    """Tracked response file of one parameter set."""
    return f"{FIXTURE_DIR}/{suite}.rsp"


def check_fixtures(root: Path = ROOT) -> list[str]:
    """Return every inconsistency between the tracked fixtures and the official digests."""
    errors = []
    try:
        if (root / INPUTS_FIXTURE).read_text(encoding="utf-8") != render_inputs_fixture():
            errors.append(f"{INPUTS_FIXTURE} differs from the DRBG-derived inputs")
    except OSError as error:
        errors.append(f"{INPUTS_FIXTURE}: {error}")
    inputs = kat_inputs()
    for suite, official in OFFICIAL_NISTKAT_SHA256.items():
        path = response_path(suite)
        try:
            data = (root / path).read_bytes()
        except OSError as error:
            errors.append(f"{path}: {error}")
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest != official:
            errors.append(
                f"{path}: SHA-256 {digest} differs from the official nistkat-sha256 {official}"
            )
            continue
        fields = dict(
            line.split(" = ", 1) for line in data.decode("ascii").splitlines() if " = " in line
        )
        if bytes.fromhex(fields["seed"]) != inputs["seed"]:
            errors.append(f"{path}: the seed is not the first output of the 00..2f DRBG")
        lengths = FIPS_LENGTHS[suite]
        if suite.startswith("ml-kem"):
            actual = tuple(len(fields[name]) // 2 for name in ("pk", "sk", "ct", "ss"))
        else:
            actual = (
                len(fields["pk"]) // 2,
                len(fields["sk"]) // 2,
                len(fields["sm"]) // 2 - SIGNED_MESSAGE_BYTES,
            )
            if int(fields["smlen"]) != lengths[2] + SIGNED_MESSAGE_BYTES:
                errors.append(f"{path}: smlen differs from signature plus message length")
        if actual != lengths:
            errors.append(f"{path}: encoded lengths {actual} differ from FIPS lengths {lengths}")
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    """Check the tracked fixtures or rewrite the inputs fixture."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument(
        "--write-inputs", action="store_true", help=f"rewrite {INPUTS_FIXTURE}"
    )
    args = parser.parse_args(argv)
    if args.write_inputs:
        target = args.root / INPUTS_FIXTURE
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_inputs_fixture(), encoding="utf-8")
        return 0
    errors = check_fixtures(args.root)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"PQ known-answer fixtures: {len(OFFICIAL_NISTKAT_SHA256)} responses match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
