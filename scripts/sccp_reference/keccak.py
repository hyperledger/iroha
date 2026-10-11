"""Independent pure-Python Keccak-256 (Ethereum Keccak, not FIPS 202 SHA3-256).

SCCP contract-visible hashes use Ethereum Keccak-256 (`specs/sccp.md` §0). The
standard library only ships SHA3-256, whose padding differs (domain byte 0x06
instead of 0x01), so this module implements the Keccak-f[1600] permutation
directly from the Keccak reference. It is slow but small and readable, which is
the point of an independent reference.
"""

from __future__ import annotations

_RATE_BYTES = 136  # 1600 - 2 * 256 bits
_MASK64 = (1 << 64) - 1

_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

# Rotation offsets r[x][y] of the rho step, indexed as lane x + 5 * y.
_ROTATIONS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)


# rho-pi as (destination lane, source lane, rotation): B[y, 2x + 3y] = rot(A[x, y], r[x, y]).
_RHO_PI = tuple(
    (y + 5 * ((2 * x + 3 * y) % 5), x + 5 * y, _ROTATIONS[x + 5 * y]) for x in range(5) for y in range(5)
)


def keccak_f1600(state: list[int]) -> None:
    """Apply the 24-round Keccak-f[1600] permutation in place (lane `x + 5y`)."""
    mask = _MASK64
    b = [0] * 25
    for rc in _ROUND_CONSTANTS:
        # theta
        c0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20]
        c1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21]
        c2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22]
        c3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23]
        c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24]
        d = (
            c4 ^ (((c1 << 1) | (c1 >> 63)) & mask),
            c0 ^ (((c2 << 1) | (c2 >> 63)) & mask),
            c1 ^ (((c3 << 1) | (c3 >> 63)) & mask),
            c2 ^ (((c4 << 1) | (c4 >> 63)) & mask),
            c3 ^ (((c0 << 1) | (c0 >> 63)) & mask),
        )
        # rho and pi
        for dst, src, rot in _RHO_PI:
            v = state[src] ^ d[src % 5]
            b[dst] = ((v << rot) | (v >> (64 - rot))) & mask if rot else v
        # chi
        for y in range(0, 25, 5):
            b0, b1, b2, b3, b4 = b[y], b[y + 1], b[y + 2], b[y + 3], b[y + 4]
            state[y] = b0 ^ ((~b1) & b2)
            state[y + 1] = b1 ^ ((~b2) & b3)
            state[y + 2] = b2 ^ ((~b3) & b4)
            state[y + 3] = b3 ^ ((~b4) & b0)
            state[y + 4] = b4 ^ ((~b0) & b1)
        # iota
        state[0] ^= rc


def keccak256(*parts: bytes) -> bytes:
    """Return Ethereum Keccak-256 of the concatenation of `parts`."""
    data = b"".join(parts)
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _RATE_BYTES:
        padded.append(0x00)
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), _RATE_BYTES):
        block = padded[offset : offset + _RATE_BYTES]
        for i in range(_RATE_BYTES // 8):
            state[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        keccak_f1600(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def selector(signature: str) -> bytes:
    """Return the 4-byte Solidity selector of a canonical function signature."""
    return keccak256(signature.encode("ascii"))[:4]


def event_topic(signature: str) -> bytes:
    """Return topic0 of a canonical Solidity event signature."""
    return keccak256(signature.encode("ascii"))
