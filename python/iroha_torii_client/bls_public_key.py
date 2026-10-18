"""Canonical BLS-Normal public-key curve/subgroup admission."""
from __future__ import annotations

import functools
import re
from typing import Tuple

_BLS_NORMAL_PEER_ID_RE = re.compile(r"(ea0130[0-9A-F]{96})")
_BLS12_381_BASE_FIELD = int(
    "1A0111EA397FE69A4B1BA7B6434BACD7"
    "64774B84F38512BF6730D2A0F6B0F624"
    "1EABFFFEB153FFFFB9FEFFFFFFFFAAAB",
    16,
)
_BLS12_381_SCALAR_FIELD = int(
    "73EDA753299D7D483339D80809A1D805"
    "53BDA402FFFE5BFEFFFFFFFF00000001",
    16,
)
def _jacobian_double(
    point: Tuple[int, int, int],
) -> Tuple[int, int, int]:
    x, y, z = point
    if z == 0 or y == 0:
        return (0, 1, 0)
    modulus = _BLS12_381_BASE_FIELD
    a = x * x % modulus
    b = y * y % modulus
    c = b * b % modulus
    d = 2 * ((x + b) * (x + b) - a - c) % modulus
    e = 3 * a % modulus
    f = e * e % modulus
    return (
        (f - 2 * d) % modulus,
        (e * (d - (f - 2 * d)) - 8 * c) % modulus,
        2 * y * z % modulus,
    )


def _jacobian_add_affine(
    point: Tuple[int, int, int],
    affine: Tuple[int, int],
) -> Tuple[int, int, int]:
    x1, y1, z1 = point
    x2, y2 = affine
    if z1 == 0:
        return (x2, y2, 1)
    modulus = _BLS12_381_BASE_FIELD
    z1_squared = z1 * z1 % modulus
    u2 = x2 * z1_squared % modulus
    s2 = y2 * z1_squared * z1 % modulus
    h = (u2 - x1) % modulus
    if h == 0:
        return _jacobian_double(point) if s2 == y1 else (0, 1, 0)
    hh = h * h % modulus
    i = 4 * hh % modulus
    j = h * i % modulus
    r = 2 * (s2 - y1) % modulus
    v = x1 * i % modulus
    x3 = (r * r - j - 2 * v) % modulus
    y3 = (r * (v - x3) - 2 * y1 * j) % modulus
    z3 = ((z1 + h) * (z1 + h) - z1_squared - hh) % modulus
    return (x3, y3, z3)


def _is_in_bls12_381_g1_subgroup(point: Tuple[int, int]) -> bool:
    result = (0, 1, 0)
    for bit in bin(_BLS12_381_SCALAR_FIELD)[2:]:
        result = _jacobian_double(result)
        if bit == "1":
            result = _jacobian_add_affine(result, point)
    return result[2] == 0


@functools.lru_cache(maxsize=512)
def _decode_bls_normal_peer_id_core(bare: str) -> Tuple[str, bytes]:
    compressed = bytes.fromhex(bare[6:])
    first = compressed[0]
    compressed_flag = bool(first & 0x80)
    infinity_flag = bool(first & 0x40)
    sign_flag = bool(first & 0x20)
    x = int.from_bytes(bytes([first & 0x1F]) + compressed[1:], "big")
    modulus = _BLS12_381_BASE_FIELD
    if not compressed_flag or infinity_flag or x >= modulus:
        raise ValueError("contains an invalid BLS-Normal public key")
    rhs = (pow(x, 3, modulus) + 4) % modulus
    y = pow(rhs, (modulus + 1) // 4, modulus)
    if y * y % modulus != rhs:
        raise ValueError("contains an invalid BLS-Normal public key")
    if (y * 2 > modulus) != sign_flag:
        y = modulus - y
    if not _is_in_bls12_381_g1_subgroup((x, y)):
        raise ValueError("contains a non-subgroup BLS-Normal public key")
    return bare, b"\x02" + compressed


def decode_bls_normal_peer_id(value: str, context: str = "validator") -> Tuple[str, bytes]:
    """Decode one canonical BLS-Normal ``PeerId``.

    The returned bytes are the public-key compact encoding used by Rust's
    ``PeerId`` ordering and Norito codec.
    """

    if not isinstance(value, str):
        raise TypeError(f"{context} must be a canonical BLS-Normal PeerId string")
    if value.strip() != value:
        raise ValueError(f"{context} must not contain surrounding whitespace")
    matched = _BLS_NORMAL_PEER_ID_RE.fullmatch(value)
    if matched is None:
        raise ValueError(f"{context} must be a canonical BLS-Normal PeerId")
    try:
        return _decode_bls_normal_peer_id_core(matched.group(1))
    except ValueError as exc:
        raise ValueError(f"{context} {exc}") from exc


