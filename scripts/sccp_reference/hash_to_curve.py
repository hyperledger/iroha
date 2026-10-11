"""RFC 9380 hash_to_curve for BLS12-381 G2 (`BLS12381G2_XMD:SHA-256_SSWU_RO_`).

`specs/sccp.md` §3.8 step 8 pins exactly this construction for the consensus
signature suite: `expand_message_xmd` with SHA-256 and 256 output bytes,
`hash_to_field` into two Fp2 elements, the simplified SWU map onto the
3-isogenous curve E2', the 3-isogeny to E2, and cofactor clearing by `h_eff`
(the EIP-2537 `MAP_FP2_TO_G2` precompile maps one Fp2 element including the
clearing, so `Q = map(u0) + map(u1)`).
"""

from __future__ import annotations

import hashlib
from typing import Tuple

from .bls12_381 import (
    F2_ZERO,
    H_EFF_G2,
    P,
    Fp2,
    G2Point,
    f2,
    f2_add,
    f2_inv,
    f2_is_square,
    f2_is_zero,
    f2_mul,
    f2_neg,
    f2_sgn0,
    f2_sqr,
    f2_sqrt,
    g2_add,
    g2_is_on_curve,
    g2_mul,
)

DST_SIG = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
"""The consensus signature DST of `specs/sccp.md` §3.8 (43 bytes)."""

# E2': y^2 = x^3 + A' x + B' with A' = 240 u, B' = 1012 (1 + u); Z = -(2 + u).
ISO_A: Fp2 = (0, 240)
ISO_B: Fp2 = (1012, 1012)
SSWU_Z: Fp2 = f2(-2, -1)

# RFC 9380 Appendix E.3: the 3-isogeny E2' -> E2, coefficients from degree 0 up.
_ISO_X_NUM = (
    (
        889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542,
        889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235542,
    ),
    (
        0,
        2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706522,
    ),
    (
        2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706526,
        1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853261,
    ),
    (
        3557697382419259905260257622876359250272784728834673675850718343221361467102966990615722337003569479144794908942033,
        0,
    ),
)
_ISO_X_DEN = (
    (
        0,
        4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559715,
    ),
    (
        12,
        4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559775,
    ),
    (1, 0),
)
_ISO_Y_NUM = (
    (
        3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558,
        3261222600550988246488569487636662646083386001431784202863158481286248011511053074731078808919938689216061999863558,
    ),
    (
        0,
        889424345604814976315064405719089812568196182208668418962679585805340366775741747653930584250892369786198727235518,
    ),
    (
        2668273036814444928945193217157269437704588546626005256888038757416021100327225242961791752752677109358596181706524,
        1334136518407222464472596608578634718852294273313002628444019378708010550163612621480895876376338554679298090853263,
    ),
    (
        2816510427748580758331037284777117739799287910327449993381818688383577828123182200904113516794492504322962636245776,
        0,
    ),
)
_ISO_Y_DEN = (
    (
        4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355,
        4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559355,
    ),
    (
        0,
        4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559571,
    ),
    (
        18,
        4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559769,
    ),
    (1, 0),
)


def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """RFC 9380 §5.3.1 `expand_message_xmd` with SHA-256."""
    b_in_bytes, s_in_bytes = 32, 64
    ell = -(-len_in_bytes // b_in_bytes)
    if ell > 255 or len_in_bytes > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd parameters out of range")
    dst_prime = dst + bytes([len(dst)])
    z_pad = bytes(s_in_bytes)
    l_i_b_str = len_in_bytes.to_bytes(2, "big")
    b0 = hashlib.sha256(z_pad + msg + l_i_b_str + b"\x00" + dst_prime).digest()
    blocks = [hashlib.sha256(b0 + b"\x01" + dst_prime).digest()]
    for i in range(2, ell + 1):
        mixed = bytes(x ^ y for x, y in zip(b0, blocks[-1]))
        blocks.append(hashlib.sha256(mixed + bytes([i]) + dst_prime).digest())
    return b"".join(blocks)[:len_in_bytes]


def hash_to_field_fp2(msg: bytes, dst: bytes, count: int = 2) -> list[Fp2]:
    """RFC 9380 §5.2 `hash_to_field` for Fp2 with L = 64."""
    length = 64
    uniform = expand_message_xmd(msg, dst, count * 2 * length)
    out = []
    for i in range(count):
        c0 = int.from_bytes(uniform[length * (2 * i) : length * (2 * i + 1)], "big") % P
        c1 = int.from_bytes(uniform[length * (2 * i + 1) : length * (2 * i + 2)], "big") % P
        out.append((c0, c1))
    return out


def map_to_curve_sswu(u: Fp2) -> Tuple[Fp2, Fp2]:
    """Simplified SWU map onto E2' (RFC 9380 §6.6.2, straight-line form)."""
    z_u2 = f2_mul(SSWU_Z, f2_sqr(u))
    tv1 = f2_add(f2_sqr(z_u2), z_u2)
    if f2_is_zero(tv1):
        x1 = f2_mul(ISO_B, f2_inv(f2_mul(SSWU_Z, ISO_A)))
    else:
        x1 = f2_mul(f2_mul(f2_neg(ISO_B), f2_inv(ISO_A)), f2_add((1, 0), f2_inv(tv1)))
    gx1 = f2_add(f2_add(f2_mul(f2_sqr(x1), x1), f2_mul(ISO_A, x1)), ISO_B)
    if f2_is_square(gx1):
        x, y = x1, f2_sqrt(gx1)
    else:
        x2 = f2_mul(z_u2, x1)
        gx2 = f2_add(f2_add(f2_mul(f2_sqr(x2), x2), f2_mul(ISO_A, x2)), ISO_B)
        x, y = x2, f2_sqrt(gx2)
    assert y is not None
    if f2_sgn0(u) != f2_sgn0(y):
        y = f2_neg(y)
    return (x, y)


def _poly(coeffs: tuple, x: Fp2) -> Fp2:
    acc = F2_ZERO
    for c in reversed(coeffs):
        acc = f2_add(f2_mul(acc, x), c)
    return acc


def iso_map_g2(pt: Tuple[Fp2, Fp2]) -> G2Point:
    """The 3-isogeny E2' -> E2 (RFC 9380 Appendix E.3)."""
    xp, yp = pt
    x_den = _poly(_ISO_X_DEN, xp)
    y_den = _poly(_ISO_Y_DEN, xp)
    if f2_is_zero(x_den) or f2_is_zero(y_den):
        return None
    x = f2_mul(_poly(_ISO_X_NUM, xp), f2_inv(x_den))
    y = f2_mul(yp, f2_mul(_poly(_ISO_Y_NUM, xp), f2_inv(y_den)))
    out = (x, y)
    assert g2_is_on_curve(out)
    return out


def clear_cofactor_g2(pt: G2Point) -> G2Point:
    """RFC 9380 `clear_cofactor`: multiplication by `h_eff`."""
    return g2_mul(pt, H_EFF_G2)


def map_fp2_to_g2(u: Fp2) -> G2Point:
    """EIP-2537 `MAP_FP2_TO_G2`: SSWU, isogeny, then cofactor clearing."""
    return clear_cofactor_g2(iso_map_g2(map_to_curve_sswu(u)))


def hash_to_g2(msg: bytes, dst: bytes = DST_SIG) -> G2Point:
    """RFC 9380 `hash_to_curve` (random oracle) into G2."""
    u0, u1 = hash_to_field_fp2(msg, dst)
    q0 = iso_map_g2(map_to_curve_sswu(u0))
    q1 = iso_map_g2(map_to_curve_sswu(u1))
    return clear_cofactor_g2(g2_add(q0, q1))


def hash_to_g2_trace(msg: bytes, dst: bytes = DST_SIG) -> dict:
    """All intermediate values of `hash_to_g2`, for vectors and EVM precompile tests."""
    uniform = expand_message_xmd(msg, dst, 256)
    u0, u1 = hash_to_field_fp2(msg, dst)
    q0 = iso_map_g2(map_to_curve_sswu(u0))
    q1 = iso_map_g2(map_to_curve_sswu(u1))
    mapped0 = clear_cofactor_g2(q0)
    mapped1 = clear_cofactor_g2(q1)
    point = clear_cofactor_g2(g2_add(q0, q1))
    assert g2_add(mapped0, mapped1) == point
    return {
        "uniform_bytes": uniform,
        "u0": u0,
        "u1": u1,
        "q0": q0,
        "q1": q1,
        "map_u0": mapped0,
        "map_u1": mapped1,
        "point": point,
    }
