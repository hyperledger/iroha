"""Independent Pasta integer and Jacobian group arithmetic, using the spec.

All arithmetic is deliberately portable Python. Complete exceptional-case
handling is explicit; this test verifier makes no timing or secrecy claim.
"""
from __future__ import annotations

from . import require

P = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
Q = 0x40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001
Point = tuple[int, int, int]
IDENTITY: Point = (0, 1, 0)


def inverse(value: int, modulus: int) -> int:
    """Invert a nonzero residue, rejecting degenerate verifier challenges."""
    require(value % modulus != 0, 'zero denominator')
    return pow(value, -1, modulus)


def square_root(value: int, modulus: int) -> int:
    """Tonelli-Shanks square root of a quadratic residue."""
    value %= modulus
    if value == 0:
        return 0
    require(pow(value, (modulus - 1) // 2, modulus) == 1, 'non-curve point')
    exponent = modulus - 1
    power = 0
    while exponent % 2 == 0:
        exponent //= 2
        power += 1
    nonresidue = 2
    while pow(nonresidue, (modulus - 1) // 2, modulus) != modulus - 1:
        nonresidue += 1
    c = pow(nonresidue, exponent, modulus)
    root = pow(value, (exponent + 1) // 2, modulus)
    residue = pow(value, exponent, modulus)
    while residue != 1:
        i = 0
        probe = residue
        while probe != 1 and i < power:
            probe = probe * probe % modulus
            i += 1
        require(i < power, 'non-curve point')
        b = pow(c, 1 << (power - i - 1), modulus)
        root = root * b % modulus
        c = b * b % modulus
        residue = residue * c % modulus
        power = i
    return root


class Curve:
    """One explicit Pasta curve; Pallas has Fp coordinates and Fq scalars."""

    def __init__(self, tag: int):
        require(type(tag) is int and tag in (0, 1), 'curve tag')
        self.tag = tag
        self.name = 'ep' if tag == 0 else 'eq'
        self.base, self.scalar = (P, Q) if tag == 0 else (Q, P)

    def scalar_bytes(self, raw: bytes) -> int:
        """Decode a canonical scalar without modular reduction."""
        require(len(raw) == 32, 'scalar width')
        value = int.from_bytes(raw, 'little')
        require(value < self.scalar, 'noncanonical scalar')
        return value

    def decode(self, raw: bytes, *, identity: bool = False) -> Point:
        """Decode canonical compressed coordinates and explicit identity policy."""
        require(len(raw) == 32, 'point width')
        encoded = int.from_bytes(raw, 'little')
        if encoded == 0:
            require(identity, 'identity point')
            return IDENTITY
        parity = encoded >> 255
        x = encoded & ((1 << 255) - 1)
        require(x < self.base, 'noncanonical point')
        y = square_root((x * x * x + 5) % self.base, self.base)
        if (y & 1) != parity:
            y = self.base - y
        require(y < self.base and (y & 1) == parity, 'point sign')
        return (x, y, 1)

    def affine(self, point: Point) -> tuple[int, int]:
        """Normalize a nonidentity Jacobian point."""
        x, y, z = point
        inv = inverse(z, self.base)
        return x * inv * inv % self.base, y * inv * inv * inv % self.base

    def encode(self, point: Point) -> bytes:
        """Canonical compressed representation, including explicit identity."""
        if point[2] == 0:
            return bytes(32)
        x, y = self.affine(point)
        return (x | ((y & 1) << 255)).to_bytes(32, 'little')

    def equal(self, left: Point, right: Point) -> bool:
        """Projective equality without an inversion."""
        if left[2] == 0 or right[2] == 0:
            return left[2] == right[2] == 0
        m = self.base
        x, y, z = left
        a, b, c = right
        return (x*c*c-a*z*z) % m == 0 and (y*c*c*c-b*z*z*z) % m == 0

    def double(self, point: Point) -> Point:
        """Tangent addition with explicit vertical/identity cases."""
        x, y, z = point
        if z == 0 or y == 0:
            return IDENTITY
        m = self.base
        yy = y*y % m
        s = 4*x*yy % m
        slope = 3*x*x % m
        nx = (slope*slope-2*s) % m
        return nx, (slope*(s-nx)-8*yy*yy) % m, 2*y*z % m

    def add(self, left: Point, right: Point) -> Point:
        """Secant addition, including equal and opposite points."""
        if left[2] == 0:
            return right
        if right[2] == 0:
            return left
        m = self.base
        x, y, z = left
        a, b, c = right
        u = x*c*c % m
        v = a*z*z % m
        s = y*c*c*c % m
        t = b*z*z*z % m
        if u == v:
            return self.double(left) if s == t else IDENTITY
        h = (v-u) % m
        r = (t-s) % m
        hh = h*h % m
        hhh = h*hh % m
        nx = (r*r-hhh-2*u*hh) % m
        return nx, (r*(u*hh-nx)-s*hhh) % m, h*z*c % m

    def multiply(self, point: Point, scalar: int) -> Point:
        """Portable double-and-add in the prime-order Pasta group."""
        scalar %= self.scalar
        result = IDENTITY
        while scalar:
            if scalar & 1:
                result = self.add(result, point)
            point = self.double(point)
            scalar >>= 1
        return result

    def sum(self, terms) -> Point:
        """A deterministic sum of scalar-point products."""
        result = IDENTITY
        for scalar, point in terms:
            result = self.add(result, self.multiply(point, scalar))
        return result

    def omega(self, k: int) -> int:
        """The canonical 5-generated 2^k root from the field conventions."""
        require(type(k) is int and 1 <= k <= 32, 'root exponent')
        value = pow(5, (self.scalar - 1) >> k, self.scalar)
        require(pow(value, 1 << k, self.scalar) == 1 and
                pow(value, 1 << (k - 1), self.scalar) != 1, 'root order')
        return value
