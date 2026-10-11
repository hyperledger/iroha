"""Exact source SWU map and complete single-map inverse for diagnostic controls.

This is public integer algebra, with explicit test randomness. It is not a
production hash oracle, a discrete-log extractor, or an indifferentiability
argument. No release parameters or verifier authority are changed.
"""
from __future__ import annotations

import hashlib
from ..kagemusha_pasta import auxiliary as arithmetic
from .custody import ROOT, require, reference_curve


def roots(value, modulus):
    """All square roots, without turning nonsquares into exceptions."""
    value %= modulus
    if value == 0:
        return (0,)
    if pow(value, (modulus - 1) // 2, modulus) != 1:
        return ()
    root = reference_curve().square_root(value, modulus)
    return tuple(sorted({root, (-root) % modulus}))


def quadratic(a, b, c, modulus):
    """All roots of a nonzero polynomial of degree at most two."""
    a, b, c = (value % modulus for value in (a, b, c))
    if a == 0:
        if b == 0:
            require(c != 0, 'zero polynomial has no bounded root list')
            return ()
        return ((-c * pow(b, -1, modulus)) % modulus,)
    inverse = pow(2 * a, -1, modulus)
    return tuple(sorted({(-b + d) * inverse % modulus
                         for d in roots(b * b - 4 * a * c, modulus)}))


class Swu:
    """The source's two Pasta auxiliary curves and exact rational maps."""

    MAX_SINGLE_PREIMAGES = 9

    def __init__(self, tag):
        self.curve = reference_curve().Curve(tag)
        self.p = self.curve.base
        self.name = ('pallas', 'vesta')[tag]
        p, self.a, self.b, self.z, constants = arithmetic.constants(self.name, ('fp', 'fq')[tag])
        self.iso = tuple(constants)
        require(p == self.p, 'source and reference base field agree')
        require(self.p % 4 == 1 and pow(self.z, (self.p - 1) // 2, self.p) == self.p - 1,
                'Pasta exceptional-map assumptions')
        require(not roots(-pow(self.z, -1, self.p), self.p), 't=-1 unreachable')

    def on_curve(self, point):
        """Check canonical affine auxiliary-curve points, including infinity."""
        return point is None or (isinstance(point, tuple) and len(point) == 2 and
            all(type(v) is int and 0 <= v < self.p for v in point) and
            (point[1] ** 2 - point[0] ** 3 - self.a * point[0] - self.b) % self.p == 0)

    def forward(self, u):
        """Affine form of native generalized SWU with identical output sign."""
        require(type(u) is int and 0 <= u < self.p, 'canonical SWU input')
        p = self.p
        t = self.z * u * u % p
        ta = (t * t + t) % p
        numerator = self.b * (ta + 1) % p
        denominator = self.a * (self.z if ta == 0 else -ta) % p
        x1 = numerator * pow(denominator, -1, p) % p
        first = roots(x1 ** 3 + self.a * x1 + self.b, p)
        x = x1 if first else t * x1 % p
        candidates = first if first else roots(x ** 3 + self.a * x + self.b, p)
        require(bool(candidates), 'SWU square branch exists')
        candidates = [y for y in candidates if y & 1 == u & 1]
        require(len(candidates) == 1, 'unique native SWU sign')
        return x, candidates[0]

    def inverse(self, point):
        """Enumerate the complete single-map fiber using two quadratics in t."""
        require(self.on_curve(point), 'canonical auxiliary point')
        if point is None:
            return ()
        p, x = self.p, point[0]
        # u=0 is the sole ta=0 input in these two fields. All others follow
        # x1 or x2: (A*x+B)(t^2+t)+B=0, or B*t^2+(B+A*x)t+B+A*x=0.
        candidates = {0}
        axb = (self.a * x + self.b) % p
        t_values = (*quadratic(axb, axb, self.b, p),
                    *quadratic(self.b, axb, axb, p))
        for t in t_values:
            if t not in (0, p - 1):
                candidates.update(roots(t * pow(self.z, -1, p), p))
        result = tuple(sorted(u for u in candidates if self.forward(u) == point))
        require(len(result) <= self.MAX_SINGLE_PREIMAGES, 'bounded complete fiber')
        return result

    def negate(self, point):
        """Auxiliary-curve inverse, preserving infinity."""
        require(self.on_curve(point), 'canonical auxiliary point')
        return None if point is None else (point[0], (-point[1]) % self.p)

    def add(self, left, right):
        """Complete affine group addition on the auxiliary curve."""
        require(self.on_curve(left) and self.on_curve(right), 'canonical auxiliary points')
        return arithmetic.point_add(left, right, self.a, self.b, self.p)

    def multiply(self, point, scalar):
        """Public scalar multiplication, independent of the Pasta A=0 helper."""
        require(self.on_curve(point) and type(scalar) is int and 0 <= scalar < 1 << 256,
                'bounded public multiplier')
        return arithmetic.point_mul(point, scalar, self.a, self.b, self.p)

    def isogeny(self, point):
        """Native rational isogeny in affine coordinates."""
        require(self.on_curve(point), 'canonical auxiliary point')
        if point is None:
            return (0, 1, 0)
        x, y = point
        c, p = self.iso, self.p
        numerator_x = ((c[0] * x + c[1]) * x + c[2]) * x + c[3]
        denominator_x = (x + c[4]) * x + c[5]
        numerator_y = (((c[6] * x + c[7]) * x + c[8]) * x + c[9]) * y
        denominator_y = ((x + c[10]) * x + c[11]) * x + c[12]
        if denominator_x % p == 0 or denominator_y % p == 0:
            return (0, 1, 0)
        xx = numerator_x * pow(denominator_x, -1, p) % p
        yy = numerator_y * pow(denominator_y, -1, p) % p
        require((yy * yy - xx ** 3 - 5) % p == 0, 'isogeny Pasta point')
        return xx, yy, 1

    def hash_to_field(self, message, domain='Halo2-Parameters'):
        """Exact public XMD byte recipe, solely for retained KAT comparison."""
        dst = (domain + '-' + self.name + '_XMD:BLAKE2b_SSWU_RO_').encode()
        require(len(dst) <= 255, 'DST length')
        dst += bytes([len(dst)])
        b0 = hashlib.blake2b(bytes(128) + message + bytes([0, 128, 0]) + dst).digest()
        b1 = hashlib.blake2b(b0 + bytes([1]) + dst).digest()
        b2 = hashlib.blake2b(bytes(a ^ b for a, b in zip(b0, b1)) + bytes([2]) + dst).digest()
        return tuple(int.from_bytes(block, 'big') % self.p for block in (b1, b2))

    def hash_to_curve(self, message):
        """Exact forward recipe used to compare existing independent originals."""
        u, v = self.hash_to_field(message)
        return self.isogeny(self.add(self.forward(u), self.forward(v)))

