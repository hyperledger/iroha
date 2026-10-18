"""SCCP-specific encoding boundary cases not covered by the upstream corpus."""

from . import bls12_381 as curve
from .bls_sig import core_verify_point, key_validate, signature_validate, sign, sk_to_pk, verify
from .common import hx
from .imported_vectors import load_ethereum_vectors


def _encodings(valid: bytes) -> list[tuple[str, bytes]]:
    """Extra cases absent upstream: empty/extreme encodings, negation and valid prefixes."""
    return [
        ("negated", bytes([valid[0] ^ 0x20]) + valid[1:]),
        ("empty", b""),
        ("all_zero", bytes(len(valid))),
        ("all_ones", b"\xff" * len(valid)),
        ("long", valid + b"\x00"),
    ]


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
    upstream = next(row for row in load_ethereum_vectors()["sign"] if row["label"] == "sign_case_c82df61aa3ee60fb")
    secret = int(upstream["input"]["privkey"], 16)
    message = bytes.fromhex(upstream["input"]["message"][2:])
    public_key, signature = sk_to_pk(secret), sign(secret, message)
    result = {
        "source_kind": "sccp_extra_cases",
        "source": "SCCP-specific cases beyond ethereum/bls12-381-tests v0.1.2: negated valid points, empty/all-zero/all-one "
        "encodings and a valid signature or key with a trailing byte. The upstream long encodings have invalid prefixes; "
        "these additional valid-prefix cases distinguish TON opcode prefix consumption from SCCP exact-length admission.",
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
        for label, encoding in _encodings(valid):
            try:
                point = decode(encoding)
                deserialized = subgroup(point)
            except curve.PointEncodingError:
                deserialized = False
            accepted = validate(encoding) is not None
            pk, sig = (encoding, signature) if group == 1 else (public_key, encoding)
            verified = verify(pk, message, sig)
            assert deserialized == (label == "negated"), (group, label)
            assert accepted == (label == "negated"), (group, label)
            assert not verified, (group, label)
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
                "ton_verify": -9 if len(encoding) < len(valid) else int(label == "long"),
            })
        result[f"g{group}_deserialization"] = rows
    return result
