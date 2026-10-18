"""Offline reproduction of Ethereum BLS malformed/deserialization input classes.

The upstream release archive is not available locally. These are deterministic
encodings built from its already-pinned standard key/signature, not an assertion
that the archive's case names or complete byte corpus have been imported.
"""

from . import bls12_381 as curve
from .bls_sig import core_verify_point, key_validate, signature_validate, sign, sk_to_pk, verify
from .common import hx
from .hash_to_curve import iso_map_g2, map_to_curve_sswu
from .imported_vectors import ETHEREUM_STANDARD_MESSAGES, ETHEREUM_STANDARD_PRIVKEYS


def _non_subgroup(group: int) -> bytes:
    """Deterministically construct a curve point outside the prime-order subgroup."""
    if group == 2:
        return curve.g2_compress(iso_map_g2(map_to_curve_sswu((5, 7))))
    x = 1
    while True:
        y = curve.fp_sqrt(x**3 + 4)
        if y is not None and not curve.g1_in_subgroup((x, y)):
            return curve.g1_compress((x, y))
        x += 1


def _off_curve(group: int) -> bytes:
    """Find the first nonnegative real x with no curve y; retain the compressed flag."""
    x = 0
    while True:
        if group == 1:
            exists = curve.fp_sqrt(x**3 + 4) is not None
            encoded = x.to_bytes(48, "big")
        else:
            exists = curve.f2_sqrt(curve.f2_add((x**3, 0), curve.G2_B)) is not None
            encoded = bytes(48) + x.to_bytes(48, "big")
        if not exists:
            return bytes([encoded[0] | 0x80]) + encoded[1:]
        x += 1


def _encodings(valid: bytes, group: int) -> list[tuple[str, bytes]]:
    """Fixed length/flag/infinity/field/curve/subgroup boundaries, with valid controls."""
    size = len(valid)
    infinity = bytes([0xC0]) + bytes(size - 1)
    rows = [
        ("valid", valid),
        ("negated", bytes([valid[0] ^ 0x20]) + valid[1:]),
        ("infinity", infinity),
        ("empty", b""),
        ("short", valid[:-1]),
        ("long", valid + b"\x00"),
        ("all_zero", bytes(size)),
        ("all_ones", b"\xff" * size),
        ("compression_clear", bytes([valid[0] & 0x7F]) + valid[1:]),
        ("infinity_with_x", bytes([valid[0] | 0x40]) + valid[1:]),
        ("infinity_with_sign", bytes([0xE0]) + bytes(size - 1)),
        ("infinity_dirty", infinity[:-1] + b"\x01"),
        ("x_equals_p", bytes([0x80 | (curve.P >> 376)]) + curve.P.to_bytes(48, "big")[1:] + valid[48:]),
        ("x_above_p", bytes([0x80 | (curve.P >> 376)]) + (curve.P + 1).to_bytes(48, "big")[1:] + valid[48:]),
        ("off_curve", _off_curve(group)),
        ("non_subgroup", _non_subgroup(group)),
    ]
    if group == 2:
        rows += [("x_c0_equals_p", valid[:48] + curve.P.to_bytes(48, "big")),
                 ("x_c0_above_p", valid[:48] + (curve.P + 1).to_bytes(48, "big"))]
    return rows


def _affine(encoding: bytes, group: int):
    """Mirror the fixture ABI translation, retaining invalid coordinates for EIP-2537.

    Invalid y recovery uses y=0. If x is also zero this is EIP-2537's infinity,
    so the pairing parser accepts it although the compressed parser refuses it.
    This is an arithmetic-helper outcome, never destination key admission.
    """
    sign_bit = bool(encoding[0] & 0x20)
    infinity = bool(encoding[0] & 0x40)
    raw = bytes([encoding[0] & 0x1F]) + encoding[1:]
    if group == 1:
        x = int.from_bytes(raw, "big")
        if x >= curve.P:
            return False, None
        y = 0 if infinity else (curve.fp_sqrt(x**3 + 4) or 0)
        if y and (y > curve.HALF_P) != sign_bit:
            y = curve.P - y
        point = (x, y) if x or y else None
        return curve.g1_is_on_curve(point) and curve.g1_in_subgroup(point), point
    x = (int.from_bytes(raw[48:], "big"), int.from_bytes(raw[:48], "big"))
    if any(limb >= curve.P for limb in x):
        return False, None
    y = (0, 0) if infinity else (curve.f2_sqrt(curve.f2_add(curve.f2_mul(curve.f2_sqr(x), x), curve.G2_B)) or (0, 0))
    if ((y[1] if y[1] else y[0]) > curve.HALF_P) != sign_bit:
        y = curve.f2_neg(y)
    point = (x, y) if any(x + y) else None
    return curve.g2_is_on_curve(point) and curve.g2_in_subgroup(point), point


def build() -> dict:
    """Reproduce compressed parser, nonidentity validation and verification outcomes."""
    secret = int(ETHEREUM_STANDARD_PRIVKEYS[0], 16)
    message = bytes.fromhex(ETHEREUM_STANDARD_MESSAGES[0])
    public_key, signature = sk_to_pk(secret), sign(secret, message)
    result = {
        "source_kind": "deterministic_offline_reproduction",
        "source": "ethereum/bls12-381-tests malformed-input and deserialization categories; release archive unavailable offline. "
        "These deterministic boundary encodings use its pinned standard private key 0 and message 0, not imported archive bytes or case names.",
        "conventions": "deserialize includes the subgroup check and accepts canonical infinity; validate additionally rejects infinity. "
        "verify checks the recorded key, 32-byte message and signature. EVM affine pairing ignores compressed metadata and has no representation "
        "for wrong compressed lengths (null); infinity is a valid affine point. TON opcode returns -9 for short slices and reads only the "
        "first 48/96 bytes of long slices; SCCP admission enforces exact sizes before that opcode.",
        "baseline": {"pk": hx(public_key), "msg": hx(message), "signature": hx(signature)},
    }
    for group, valid in ((1, public_key), (2, signature)):
        decode = curve.g1_decompress if group == 1 else curve.g2_decompress
        subgroup = curve.g1_in_subgroup if group == 1 else curve.g2_in_subgroup
        validate = key_validate if group == 1 else signature_validate
        rows = []
        for label, encoding in _encodings(valid, group):
            try:
                point = decode(encoding)
                deserialized = subgroup(point)
            except curve.PointEncodingError:
                deserialized = False
            accepted = validate(encoding) is not None
            pk, sig = (encoding, signature) if group == 1 else (public_key, encoding)
            verified = verify(pk, message, sig)
            assert deserialized == (label in ("valid", "negated", "infinity")), (group, label)
            assert accepted == (label in ("valid", "negated")), (group, label)
            assert verified == (label == "valid"), (group, label)
            sized = len(encoding) == len(valid)
            affine_valid, affine_point = _affine(encoding, group) if sized else (False, None)
            affine_key = affine_point if group == 1 else curve.g1_decompress(public_key)
            affine_signature = affine_point if group == 2 else curve.g2_decompress(signature)
            affine_verify = affine_valid and core_verify_point(affine_key, message, affine_signature)
            rows.append({
                "label": label, "encoding": hx(encoding), "deserialize": deserialized,
                "validate": accepted, "verify": verified,
                "evm_affine_pairing": affine_valid if sized else None,
                "evm_affine_verify": affine_verify if sized else None,
                "ton_verify": -9 if len(encoding) < len(valid) else int(label in ("valid", "long")),
            })
        result[f"g{group}_deserialization"] = rows
    return result
