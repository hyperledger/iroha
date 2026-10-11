"""BLS min-pk signatures under the IETF proof-of-possession ciphersuite.

`specs/sccp.md` §3.8 and `specs/sumeragi.md` §1 item 6: public keys are
compressed G1 points (48 bytes), signatures compressed G2 points (96 bytes),
and consensus signatures are `sk · hash_to_G2(SHA-256(P), DST_SIG)`. This
module implements the draft-irtf-cfrg-bls-signature-05 operations used by the
SCCP vectors: `KeyGen`, `SkToPk`, `KeyValidate`, `Sign`, `Verify`,
`Aggregate`, `FastAggregateVerify` and `AggregateVerify`.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Iterable, Optional, Sequence

from .bls12_381 import (
    G1_GENERATOR,
    R,
    G1Point,
    G2Point,
    PointEncodingError,
    g1_add,
    g1_compress,
    g1_decompress,
    g1_in_subgroup,
    g1_mul,
    g1_neg,
    g2_add,
    g2_compress,
    g2_decompress,
    g2_in_subgroup,
    g2_mul,
    pairing_product_is_one,
)
from .hash_to_curve import DST_SIG, hash_to_g2

KEYGEN_SALT = b"BLS-SIG-KEYGEN-SALT-"


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def keygen(ikm: bytes, key_info: bytes = b"") -> int:
    """draft-irtf-cfrg-bls-signature-05 §2.3 `KeyGen` (HKDF-SHA-256, L = 48)."""
    if len(ikm) < 32:
        raise ValueError("IKM must be at least 32 bytes")
    salt = KEYGEN_SALT
    sk = 0
    while sk == 0:
        salt = hashlib.sha256(salt).digest()
        prk = _hkdf_extract(salt, ikm + b"\x00")
        okm = _hkdf_expand(prk, key_info + (48).to_bytes(2, "big"), 48)
        sk = int.from_bytes(okm, "big") % R
    return sk


def sk_to_pk_point(sk: int) -> G1Point:
    """`SkToPk` as a point."""
    return g1_mul(G1_GENERATOR, sk % R)


def sk_to_pk(sk: int) -> bytes:
    """`SkToPk`: the 48-byte compressed public key."""
    return g1_compress(sk_to_pk_point(sk))


def key_validate(pk: bytes) -> Optional[G1Point]:
    """`KeyValidate`: canonical encoding, not the identity, in the subgroup."""
    try:
        point = g1_decompress(pk)
    except PointEncodingError:
        return None
    if point is None or not g1_in_subgroup(point):
        return None
    return point


def signature_validate(sig: bytes) -> Optional[G2Point]:
    """Signature check of §3.8: canonical, in the subgroup and not the identity."""
    try:
        point = g2_decompress(sig)
    except PointEncodingError:
        return None
    if point is None or not g2_in_subgroup(point):
        return None
    return point


def sign_point(sk: int, msg: bytes, dst: bytes = DST_SIG) -> G2Point:
    """`CoreSign` as a point."""
    return g2_mul(hash_to_g2(msg, dst), sk % R)


def sign(sk: int, msg: bytes, dst: bytes = DST_SIG) -> bytes:
    """`Sign`: the 96-byte compressed signature."""
    return g2_compress(sign_point(sk, msg, dst))


def aggregate_points(points: Iterable[G2Point]) -> G2Point:
    """`Aggregate` over decoded signatures."""
    acc: G2Point = None
    for point in points:
        acc = g2_add(acc, point)
    return acc


def aggregate(signatures: Sequence[bytes]) -> bytes:
    """`Aggregate`: sum of the decoded signatures, compressed."""
    if not signatures:
        raise ValueError("Aggregate needs at least one signature")
    points = []
    for sig in signatures:
        point = g2_decompress(sig)
        points.append(point)
    return g2_compress(aggregate_points(points))


def core_verify_point(apk: G1Point, msg: bytes, sig: G2Point, dst: bytes = DST_SIG) -> bool:
    """`e(apk, H(m)) = e(g1, σ)` as `e(apk, H(m)) · e(−g1, σ) = 1`."""
    if apk is None or sig is None:
        return False
    return pairing_product_is_one([(apk, hash_to_g2(msg, dst)), (g1_neg(G1_GENERATOR), sig)])


def verify(pk: bytes, msg: bytes, sig: bytes, dst: bytes = DST_SIG) -> bool:
    """`Verify` with `KeyValidate` and the signature check."""
    pk_point = key_validate(pk)
    sig_point = signature_validate(sig)
    if pk_point is None or sig_point is None:
        return False
    return core_verify_point(pk_point, msg, sig_point, dst)


def fast_aggregate_verify(pks: Sequence[bytes], msg: bytes, sig: bytes, dst: bytes = DST_SIG) -> bool:
    """`FastAggregateVerify` (§3.8): k ≥ 1 valid keys, apk ≠ O, valid σ ≠ O."""
    if not pks:
        return False
    apk: G1Point = None
    for pk in pks:
        point = key_validate(pk)
        if point is None:
            return False
        apk = g1_add(apk, point)
    sig_point = signature_validate(sig)
    if apk is None or sig_point is None:
        return False
    return core_verify_point(apk, msg, sig_point, dst)


def aggregate_verify(pks: Sequence[bytes], msgs: Sequence[bytes], sig: bytes, dst: bytes = DST_SIG) -> bool:
    """`AggregateVerify` with the distinct-message rule of the PoP scheme's base check."""
    if not pks or len(pks) != len(msgs) or len(set(msgs)) != len(msgs):
        return False
    sig_point = signature_validate(sig)
    if sig_point is None:
        return False
    pairs = []
    for pk, msg in zip(pks, msgs):
        point = key_validate(pk)
        if point is None:
            return False
        pairs.append((point, hash_to_g2(msg, dst)))
    pairs.append((g1_neg(G1_GENERATOR), sig_point))
    return pairing_product_is_one(pairs)


TAG_SIG = b"sumeragi/sig"
AVAILABILITY_TAG = b"sumeragi/availability/sign"


def consensus_digest(preimage: bytes) -> Optional[bytes]:
    """`ConsensusDigest::from_preimage` (`specs/sumeragi.md` §1 item 6): `SHA-256(P)` iff `P` is allowlisted.

    Rows: Proposal `TAG_SIG ‖ 0x01` (165 bytes); Prepare/Commit `TAG_SIG ‖ 0x02/0x03`
    (165); Timeout `TAG_SIG ‖ 0x04` (102 with byte 101 = 0x00, or 110 with byte
    101 = 0x01); Echo `TAG_SIG ‖ 0x05` (101); RS16 manifest/row
    `"sumeragi/availability/sign" ‖ 0x00/0x01` (179/219).
    """
    n = len(preimage)
    allowed = False
    if preimage[: len(TAG_SIG)] == TAG_SIG and n > len(TAG_SIG):
        kind = preimage[len(TAG_SIG)]
        allowed = (
            (kind == 0x01 and n == 165)
            or (kind in (0x02, 0x03) and n == 165)
            or (kind == 0x04 and ((n == 102 and preimage[101] == 0x00) or (n == 110 and preimage[101] == 0x01)))
            or (kind == 0x05 and n == 101)
        )
    elif preimage[: len(AVAILABILITY_TAG)] == AVAILABILITY_TAG and n > len(AVAILABILITY_TAG):
        kind = preimage[len(AVAILABILITY_TAG)]
        allowed = (kind == 0x00 and n == 179) or (kind == 0x01 and n == 219)
    return hashlib.sha256(preimage).digest() if allowed else None
