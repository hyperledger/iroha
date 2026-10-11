"""Self-contained BLS12-381 arithmetic for the SCCP Python reference.

Readable, not fast and not constant time: it exists to re-derive the
contract-visible SCCP vectors independently of `blst` (`specs/sccp.md` §3.8,
§11.4). It provides

* the fields Fp, Fp2 = Fp[u]/(u^2 + 1), Fp6 = Fp2[v]/(v^3 - (u + 1)) and
  Fp12 = Fp6[w]/(w^2 - v), with elements as plain tuples of Python integers;
* the groups G1 (y^2 = x^3 + 4 over Fp) and G2 (y^2 = x^3 + 4(u + 1) over Fp2)
  in affine coordinates, with `None` as the point at infinity;
* the optimal ate pairing (Miller loop in affine coordinates on the twist,
  final exponentiation by `(p^12 - 1) / r`);
* the ZCash compressed serialization (48-byte G1, 96-byte G2) and the EIP-2537
  uncompressed forms (128-byte G1, 256-byte G2).

Every operation is deterministic and depends only on its inputs.
"""

from __future__ import annotations

from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Constants (specs/sccp.md §0 pins p, HALF_P, g1 and -g1.y)
# ---------------------------------------------------------------------------

P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
"""Base field modulus p."""

R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
"""Prime order r of G1, G2 and GT."""

HALF_P = (P - 1) // 2
"""(p - 1) / 2: a coordinate is "lexicographically largest" iff it exceeds this."""

BLS_X = -0xD201000000010000
"""The BLS12 curve parameter x (negative for BLS12-381)."""

H_EFF_G2 = 0xBC69F08F2EE75B3584C6A0EA91B352888E2A8E9145AD7689986FF031508FFE1329C2F178731DB956D82BF015D1212B02EC0EC69D7477C1AE954CBC06689F6A359894C0ADEBBF6B4E8020005AAA95551
"""RFC 9380 §8.8.2 effective cofactor h_eff for G2."""

G1_X = 0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB
G1_Y = 0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1

G2_X = (
    352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160,
    3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758,
)
G2_Y = (
    1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905,
    927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582,
)

Fp2 = Tuple[int, int]
Fp6 = Tuple[Fp2, Fp2, Fp2]
Fp12 = Tuple[Fp6, Fp6]
G1Point = Optional[Tuple[int, int]]
G2Point = Optional[Tuple[Fp2, Fp2]]

# ---------------------------------------------------------------------------
# Fp
# ---------------------------------------------------------------------------


def fp_inv(a: int) -> int:
    """Inverse in Fp (a must be nonzero)."""
    if a % P == 0:
        raise ZeroDivisionError("inverse of zero in Fp")
    return pow(a, P - 2, P)


def fp_is_square(a: int) -> bool:
    """Euler's criterion (0 counts as a square)."""
    a %= P
    return a == 0 or pow(a, (P - 1) // 2, P) == 1


def fp_sqrt(a: int) -> Optional[int]:
    """A square root in Fp (p = 3 mod 4), or None when `a` is not a square."""
    a %= P
    root = pow(a, (P + 1) // 4, P)
    return root if root * root % P == a else None


# ---------------------------------------------------------------------------
# Fp2 = Fp[u] / (u^2 + 1)
# ---------------------------------------------------------------------------

F2_ZERO: Fp2 = (0, 0)
F2_ONE: Fp2 = (1, 0)
XI: Fp2 = (1, 1)  # u + 1, the non-residue of the tower


def f2(c0: int, c1: int = 0) -> Fp2:
    """Build a reduced Fp2 element."""
    return (c0 % P, c1 % P)


def f2_add(a: Fp2, b: Fp2) -> Fp2:
    return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)


def f2_sub(a: Fp2, b: Fp2) -> Fp2:
    return ((a[0] - b[0]) % P, (a[1] - b[1]) % P)


def f2_neg(a: Fp2) -> Fp2:
    return (-a[0] % P, -a[1] % P)


def f2_mul(a: Fp2, b: Fp2) -> Fp2:
    t0 = a[0] * b[0]
    t1 = a[1] * b[1]
    return ((t0 - t1) % P, ((a[0] + a[1]) * (b[0] + b[1]) - t0 - t1) % P)


def f2_sqr(a: Fp2) -> Fp2:
    return ((a[0] + a[1]) * (a[0] - a[1]) % P, 2 * a[0] * a[1] % P)


def f2_mul_fp(a: Fp2, k: int) -> Fp2:
    return (a[0] * k % P, a[1] * k % P)


def f2_mul_xi(a: Fp2) -> Fp2:
    """Multiply by u + 1."""
    return ((a[0] - a[1]) % P, (a[0] + a[1]) % P)


def f2_conj(a: Fp2) -> Fp2:
    return (a[0], -a[1] % P)


def f2_inv(a: Fp2) -> Fp2:
    norm = (a[0] * a[0] + a[1] * a[1]) % P
    inv = fp_inv(norm)
    return (a[0] * inv % P, -a[1] * inv % P)


def f2_pow(a: Fp2, e: int) -> Fp2:
    result = F2_ONE
    base = a
    while e:
        if e & 1:
            result = f2_mul(result, base)
        base = f2_sqr(base)
        e >>= 1
    return result


def f2_is_zero(a: Fp2) -> bool:
    return a[0] % P == 0 and a[1] % P == 0


def f2_is_square(a: Fp2) -> bool:
    """`a` is a square in Fp2 iff its norm is a square in Fp."""
    return fp_is_square(a[0] * a[0] + a[1] * a[1])


def f2_sqrt(a: Fp2) -> Optional[Fp2]:
    """A square root in Fp2 (the "complex method" for p = 3 mod 4), or None."""
    a0, a1 = a[0] % P, a[1] % P
    if a1 == 0:
        root = fp_sqrt(a0)
        if root is not None:
            return (root, 0)
        root = fp_sqrt(-a0)
        return None if root is None else (0, root)
    alpha = fp_sqrt(a0 * a0 + a1 * a1)
    if alpha is None:
        return None
    inv2 = fp_inv(2)
    delta = (a0 + alpha) * inv2 % P
    x0 = fp_sqrt(delta)
    if x0 is None:
        delta = (a0 - alpha) * inv2 % P
        x0 = fp_sqrt(delta)
        if x0 is None:
            return None
    x1 = a1 * fp_inv(2 * x0) % P
    candidate = (x0, x1)
    return candidate if f2_sqr(candidate) == (a0, a1) else None


def f2_sgn0(a: Fp2) -> int:
    """RFC 9380 §4.1 sgn0 for m = 2."""
    sign_0 = a[0] % 2
    zero_0 = a[0] == 0
    sign_1 = a[1] % 2
    return sign_0 | (zero_0 & sign_1)


# ---------------------------------------------------------------------------
# Fp6 = Fp2[v] / (v^3 - xi) and Fp12 = Fp6[w] / (w^2 - v)
# ---------------------------------------------------------------------------

F6_ZERO: Fp6 = (F2_ZERO, F2_ZERO, F2_ZERO)
F6_ONE: Fp6 = (F2_ONE, F2_ZERO, F2_ZERO)
F12_ONE: Fp12 = (F6_ONE, F6_ZERO)


def f6_add(a: Fp6, b: Fp6) -> Fp6:
    return (f2_add(a[0], b[0]), f2_add(a[1], b[1]), f2_add(a[2], b[2]))


def f6_sub(a: Fp6, b: Fp6) -> Fp6:
    return (f2_sub(a[0], b[0]), f2_sub(a[1], b[1]), f2_sub(a[2], b[2]))


def f6_neg(a: Fp6) -> Fp6:
    return (f2_neg(a[0]), f2_neg(a[1]), f2_neg(a[2]))


def f6_mul(a: Fp6, b: Fp6) -> Fp6:
    a0, a1, a2 = a
    b0, b1, b2 = b
    t0 = f2_mul(a0, b0)
    t1 = f2_mul(a1, b1)
    t2 = f2_mul(a2, b2)
    c0 = f2_add(t0, f2_mul_xi(f2_sub(f2_sub(f2_mul(f2_add(a1, a2), f2_add(b1, b2)), t1), t2)))
    c1 = f2_add(f2_sub(f2_sub(f2_mul(f2_add(a0, a1), f2_add(b0, b1)), t0), t1), f2_mul_xi(t2))
    c2 = f2_add(f2_sub(f2_sub(f2_mul(f2_add(a0, a2), f2_add(b0, b2)), t0), t2), t1)
    return (c0, c1, c2)


def f6_mul_v(a: Fp6) -> Fp6:
    """Multiply by v."""
    return (f2_mul_xi(a[2]), a[0], a[1])


def f6_inv(a: Fp6) -> Fp6:
    a0, a1, a2 = a
    c0 = f2_sub(f2_sqr(a0), f2_mul_xi(f2_mul(a1, a2)))
    c1 = f2_sub(f2_mul_xi(f2_sqr(a2)), f2_mul(a0, a1))
    c2 = f2_sub(f2_sqr(a1), f2_mul(a0, a2))
    t = f2_add(f2_mul(a0, c0), f2_mul_xi(f2_add(f2_mul(a2, c1), f2_mul(a1, c2))))
    t_inv = f2_inv(t)
    return (f2_mul(c0, t_inv), f2_mul(c1, t_inv), f2_mul(c2, t_inv))


def f12_mul(a: Fp12, b: Fp12) -> Fp12:
    t0 = f6_mul(a[0], b[0])
    t1 = f6_mul(a[1], b[1])
    c0 = f6_add(t0, f6_mul_v(t1))
    c1 = f6_sub(f6_sub(f6_mul(f6_add(a[0], a[1]), f6_add(b[0], b[1])), t0), t1)
    return (c0, c1)


def f12_sqr(a: Fp12) -> Fp12:
    t = f6_mul(a[0], a[1])
    c0 = f6_sub(f6_sub(f6_mul(f6_add(a[0], a[1]), f6_add(a[0], f6_mul_v(a[1]))), t), f6_mul_v(t))
    return (c0, f6_add(t, t))


def f12_conj(a: Fp12) -> Fp12:
    """The p^6-power Frobenius: w -> -w."""
    return (a[0], f6_neg(a[1]))


def f12_inv(a: Fp12) -> Fp12:
    t = f6_sub(f6_mul(a[0], a[0]), f6_mul_v(f6_mul(a[1], a[1])))
    t_inv = f6_inv(t)
    return (f6_mul(a[0], t_inv), f6_neg(f6_mul(a[1], t_inv)))


def f12_pow(a: Fp12, e: int) -> Fp12:
    result = F12_ONE
    for bit in bin(e)[2:]:
        result = f12_sqr(result)
        if bit == "1":
            result = f12_mul(result, a)
    return result


def f12_from_fp2(a: Fp2) -> Fp12:
    return ((a, F2_ZERO, F2_ZERO), F6_ZERO)


def f12_is_one(a: Fp12) -> bool:
    return a == F12_ONE


_W: Fp12 = (F6_ZERO, F6_ONE)
_W_INV: Fp12 = f12_inv(_W)
_W_INV3: Fp12 = f12_mul(f12_mul(_W_INV, _W_INV), _W_INV)
_XI_INV: Fp2 = f2_inv(XI)
assert _W_INV == (F6_ZERO, (F2_ZERO, F2_ZERO, _XI_INV)) and _W_INV3 == (F6_ZERO, (F2_ZERO, _XI_INV, F2_ZERO))

# ---------------------------------------------------------------------------
# Jacobian scalar multiplication shared by G1 and G2 (curves with a = 0)
# ---------------------------------------------------------------------------


class _FieldOps:
    """The field operations the Jacobian formulas need, for Fp or Fp2."""

    def __init__(self, zero, one, add, sub, mul, sqr, inv):
        self.zero = zero
        self.one = one
        self.add = add
        self.sub = sub
        self.mul = mul
        self.sqr = sqr
        self.inv = inv


_FP_OPS = _FieldOps(
    0,
    1,
    lambda a, b: (a + b) % P,
    lambda a, b: (a - b) % P,
    lambda a, b: a * b % P,
    lambda a: a * a % P,
    fp_inv,
)


def _jacobian_double(ops: _FieldOps, pt):
    if pt is None:
        return None
    x1, y1, z1 = pt
    if y1 == ops.zero:
        return None
    a = ops.sqr(x1)
    b = ops.sqr(y1)
    c = ops.sqr(b)
    d = ops.sub(ops.sub(ops.sqr(ops.add(x1, b)), a), c)
    d = ops.add(d, d)
    e = ops.add(ops.add(a, a), a)
    f = ops.sqr(e)
    x3 = ops.sub(f, ops.add(d, d))
    c8 = ops.add(c, c)
    c8 = ops.add(c8, c8)
    c8 = ops.add(c8, c8)
    y3 = ops.sub(ops.mul(e, ops.sub(d, x3)), c8)
    yz = ops.mul(y1, z1)
    return (x3, y3, ops.add(yz, yz))


def _jacobian_add(ops: _FieldOps, a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1, z1 = a
    x2, y2, z2 = b
    z1z1 = ops.sqr(z1)
    z2z2 = ops.sqr(z2)
    u1 = ops.mul(x1, z2z2)
    u2 = ops.mul(x2, z1z1)
    s1 = ops.mul(ops.mul(y1, z2), z2z2)
    s2 = ops.mul(ops.mul(y2, z1), z1z1)
    h = ops.sub(u2, u1)
    r = ops.sub(s2, s1)
    if h == ops.zero:
        return _jacobian_double(ops, a) if r == ops.zero else None
    i = ops.sqr(ops.add(h, h))
    j = ops.mul(h, i)
    r = ops.add(r, r)
    v = ops.mul(u1, i)
    x3 = ops.sub(ops.sub(ops.sqr(r), j), ops.add(v, v))
    s1j = ops.mul(s1, j)
    y3 = ops.sub(ops.mul(r, ops.sub(v, x3)), ops.add(s1j, s1j))
    z3 = ops.mul(ops.sub(ops.sub(ops.sqr(ops.add(z1, z2)), z1z1), z2z2), h)
    return (x3, y3, z3)


def _jacobian_mul(ops: _FieldOps, pt, k: int):
    if pt is None or k == 0:
        return None
    base = (pt[0], pt[1], ops.one)
    acc = None
    for bit in bin(k)[2:]:
        acc = _jacobian_double(ops, acc)
        if bit == "1":
            acc = _jacobian_add(ops, acc, base)
    if acc is None:
        return None
    x, y, z = acc
    if z == ops.zero:
        return None
    zi = ops.inv(z)
    zi2 = ops.sqr(zi)
    return (ops.mul(x, zi2), ops.mul(y, ops.mul(zi2, zi)))


# ---------------------------------------------------------------------------
# G1 over Fp: y^2 = x^3 + 4
# ---------------------------------------------------------------------------

G1_B = 4
G1_GENERATOR: G1Point = (G1_X, G1_Y)


def g1_is_on_curve(pt: G1Point) -> bool:
    if pt is None:
        return True
    x, y = pt
    return (y * y - x * x * x - G1_B) % P == 0


def g1_neg(pt: G1Point) -> G1Point:
    return None if pt is None else (pt[0], -pt[1] % P)


def g1_add(a: G1Point, b: G1Point) -> G1Point:
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = 3 * x1 * x1 * fp_inv(2 * y1) % P
    else:
        lam = (y2 - y1) * fp_inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def g1_mul(pt: G1Point, k: int) -> G1Point:
    """Scalar multiplication `k * pt` (Jacobian double-and-add, one final inversion)."""
    if k < 0:
        return g1_mul(g1_neg(pt), -k)
    return _jacobian_mul(_FP_OPS, pt, k)


def g1_in_subgroup(pt: G1Point) -> bool:
    return g1_is_on_curve(pt) and g1_mul(pt, R) is None


_FP2_OPS = _FieldOps(F2_ZERO, F2_ONE, f2_add, f2_sub, f2_mul, f2_sqr, f2_inv)

# ---------------------------------------------------------------------------
# G2 over Fp2: y^2 = x^3 + 4(u + 1)
# ---------------------------------------------------------------------------

G2_B: Fp2 = (4, 4)
G2_GENERATOR: G2Point = (G2_X, G2_Y)


def g2_is_on_curve(pt: G2Point) -> bool:
    if pt is None:
        return True
    x, y = pt
    return f2_sub(f2_sqr(y), f2_add(f2_mul(f2_sqr(x), x), G2_B)) == F2_ZERO


def g2_neg(pt: G2Point) -> G2Point:
    return None if pt is None else (pt[0], f2_neg(pt[1]))


def g2_add(a: G2Point, b: G2Point) -> G2Point:
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2:
        if f2_add(y1, y2) == F2_ZERO:
            return None
        lam = f2_mul(f2_mul_fp(f2_sqr(x1), 3), f2_inv(f2_add(y1, y1)))
    else:
        lam = f2_mul(f2_sub(y2, y1), f2_inv(f2_sub(x2, x1)))
    x3 = f2_sub(f2_sub(f2_sqr(lam), x1), x2)
    return (x3, f2_sub(f2_mul(lam, f2_sub(x1, x3)), y1))


def g2_mul(pt: G2Point, k: int) -> G2Point:
    """Scalar multiplication `k * pt` (Jacobian double-and-add, one final inversion)."""
    if k < 0:
        return g2_mul(g2_neg(pt), -k)
    return _jacobian_mul(_FP2_OPS, pt, k)


def g2_in_subgroup(pt: G2Point) -> bool:
    return g2_is_on_curve(pt) and g2_mul(pt, R) is None


# ---------------------------------------------------------------------------
# Optimal ate pairing
# ---------------------------------------------------------------------------


def _line(lam: Fp2, xt: Fp2, yt: Fp2, p: Tuple[int, int]) -> Fp12:
    """Line through psi(T) with twist slope `lam`, evaluated at P in G1.

    With the untwist psi(x', y') = (x' w^-2, y' w^-3) the slope on E is
    `lam * w^-1`, so the line value is
    `yP - lam * xP * w^-1 + (lam * xT - yT) * w^-3`. Vertical lines lie in Fp6
    and are dropped: the final exponentiation maps them to 1.
    """
    xp, yp = p
    # w^-1 = w^5 / xi = (v^2 w) / xi and w^-3 = w^3 / xi = (v w) / xi.
    c_w1 = f2_mul(f2_neg(f2_mul_fp(lam, xp)), _XI_INV)
    c_w3 = f2_mul(f2_sub(f2_mul(lam, xt), yt), _XI_INV)
    return (((yp % P, 0), F2_ZERO, F2_ZERO), (F2_ZERO, c_w3, c_w1))


def miller_loop(p: G1Point, q: G2Point) -> Fp12:
    """Miller loop f_{|x|, Q}(P), conjugated because x < 0."""
    if p is None or q is None:
        return F12_ONE
    f = F12_ONE
    t = q
    bits = bin(-BLS_X)[3:]
    for bit in bits:
        xt, yt = t
        lam = f2_mul(f2_mul_fp(f2_sqr(xt), 3), f2_inv(f2_add(yt, yt)))
        f = f12_mul(f12_sqr(f), _line(lam, xt, yt, p))
        t = g2_add(t, t)
        if bit == "1":
            xt, yt = t
            xq, yq = q
            lam = f2_mul(f2_sub(yq, yt), f2_inv(f2_sub(xq, xt)))
            f = f12_mul(f, _line(lam, xt, yt, p))
            t = g2_add(t, q)
    return f12_conj(f)


_FINAL_HARD_EXPONENT = (P**4 - P**2 + 1) // R
assert (P**4 - P**2 + 1) % R == 0

# f^(p^2) multiplies the coefficient of w^k (k = i + 2j for the slot (i, j)) by
# gamma^k with gamma = xi^((p^2 - 1) / 6), because w^6 = xi and Fp2 is fixed by p^2.
_FROB2_GAMMA = [f2_pow(XI, k * (P * P - 1) // 6) for k in range(6)]


def f12_frobenius_p2(a: Fp12) -> Fp12:
    """The p^2-power Frobenius map."""
    g = _FROB2_GAMMA
    return (
        (a[0][0], f2_mul(a[0][1], g[2]), f2_mul(a[0][2], g[4])),
        (f2_mul(a[1][0], g[1]), f2_mul(a[1][1], g[3]), f2_mul(a[1][2], g[5])),
    )


def final_exponentiation(f: Fp12) -> Fp12:
    """f^((p^12 - 1) / r): easy part f^((p^6 - 1)(p^2 + 1)), then the hard part (p^4 - p^2 + 1) / r."""
    easy = f12_mul(f12_conj(f), f12_inv(f))
    easy = f12_mul(f12_frobenius_p2(easy), easy)
    return f12_pow(easy, _FINAL_HARD_EXPONENT)


def pairing(p: G1Point, q: G2Point) -> Fp12:
    """The reduced optimal ate pairing e(P, Q)."""
    return final_exponentiation(miller_loop(p, q))


def pairing_product_is_one(pairs: list[tuple[G1Point, G2Point]]) -> bool:
    """Whether prod e(P_i, Q_i) = 1, with one shared final exponentiation."""
    f = F12_ONE
    for p, q in pairs:
        f = f12_mul(f, miller_loop(p, q))
    return f12_is_one(final_exponentiation(f))


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

FLAG_COMPRESSED = 0x80
FLAG_INFINITY = 0x40
FLAG_SIGN = 0x20


class PointEncodingError(ValueError):
    """A point encoding is malformed, non-canonical or not on the curve."""


def g1_compress(pt: G1Point) -> bytes:
    """ZCash 48-byte compressed G1 encoding."""
    if pt is None:
        return bytes([FLAG_COMPRESSED | FLAG_INFINITY]) + bytes(47)
    x, y = pt
    out = bytearray(x.to_bytes(48, "big"))
    out[0] |= FLAG_COMPRESSED
    if y > HALF_P:
        out[0] |= FLAG_SIGN
    return bytes(out)


def g1_decompress(data: bytes) -> G1Point:
    """Decode a ZCash compressed G1 point (on-curve; no subgroup check)."""
    if len(data) != 48:
        raise PointEncodingError("G1 encoding must be 48 bytes")
    flags = data[0]
    if not flags & FLAG_COMPRESSED:
        raise PointEncodingError("compression flag unset")
    if flags & FLAG_INFINITY:
        if flags & FLAG_SIGN or any(data[1:]) or flags & 0x1F:
            raise PointEncodingError("non-canonical infinity")
        return None
    x = int.from_bytes(bytes([flags & 0x1F]) + data[1:], "big")
    if x >= P:
        raise PointEncodingError("x not reduced")
    y = fp_sqrt(x * x * x + G1_B)
    if y is None:
        raise PointEncodingError("x not on curve")
    if (y > HALF_P) != bool(flags & FLAG_SIGN):
        y = P - y
    return (x, y)


def _g2_y_is_larger(y: Fp2) -> bool:
    return y[1] > HALF_P if y[1] != 0 else y[0] > HALF_P


def g2_compress(pt: G2Point) -> bytes:
    """ZCash 96-byte compressed G2 encoding (`x.c1 ‖ x.c0`)."""
    if pt is None:
        return bytes([FLAG_COMPRESSED | FLAG_INFINITY]) + bytes(95)
    x, y = pt
    out = bytearray(x[1].to_bytes(48, "big") + x[0].to_bytes(48, "big"))
    out[0] |= FLAG_COMPRESSED
    if _g2_y_is_larger(y):
        out[0] |= FLAG_SIGN
    return bytes(out)


def g2_decompress(data: bytes) -> G2Point:
    """Decode a ZCash compressed G2 point (on-curve; no subgroup check)."""
    if len(data) != 96:
        raise PointEncodingError("G2 encoding must be 96 bytes")
    flags = data[0]
    if not flags & FLAG_COMPRESSED:
        raise PointEncodingError("compression flag unset")
    if flags & FLAG_INFINITY:
        if flags & FLAG_SIGN or any(data[1:]) or flags & 0x1F:
            raise PointEncodingError("non-canonical infinity")
        return None
    x1 = int.from_bytes(bytes([flags & 0x1F]) + data[1:48], "big")
    x0 = int.from_bytes(data[48:], "big")
    if x0 >= P or x1 >= P:
        raise PointEncodingError("x not reduced")
    x = (x0, x1)
    y = f2_sqrt(f2_add(f2_mul(f2_sqr(x), x), G2_B))
    if y is None:
        raise PointEncodingError("x not on curve")
    if _g2_y_is_larger(y) != bool(flags & FLAG_SIGN):
        y = f2_neg(y)
    return (x, y)


def fp_to_bytes48(a: int) -> bytes:
    return (a % P).to_bytes(48, "big")


def fp_to_bytes64(a: int) -> bytes:
    """EIP-2537 field element: 16 zero bytes then the 48-byte big-endian value."""
    return bytes(16) + fp_to_bytes48(a)


def g1_to_eip2537(pt: G1Point) -> bytes:
    """EIP-2537 128-byte G1 encoding (`x ‖ y`, 64 bytes each); infinity is all zero."""
    if pt is None:
        return bytes(128)
    return fp_to_bytes64(pt[0]) + fp_to_bytes64(pt[1])


def g2_to_eip2537(pt: G2Point) -> bytes:
    """EIP-2537 256-byte G2 encoding (`x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`)."""
    if pt is None:
        return bytes(256)
    (x0, x1), (y0, y1) = pt
    return fp_to_bytes64(x0) + fp_to_bytes64(x1) + fp_to_bytes64(y0) + fp_to_bytes64(y1)


def g2_to_evm192(pt: G2Point) -> bytes:
    """SCCP EVM calldata signature form: `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`, 48 bytes each (§3.7)."""
    if pt is None:
        return bytes(192)
    (x0, x1), (y0, y1) = pt
    return fp_to_bytes48(x0) + fp_to_bytes48(x1) + fp_to_bytes48(y0) + fp_to_bytes48(y1)


def g2_from_evm192(data: bytes) -> G2Point:
    """Decode the 192-byte EVM signature form (limbs < p, on curve; no subgroup check)."""
    if len(data) != 192:
        raise PointEncodingError("EVM signature must be 192 bytes")
    limbs = [int.from_bytes(data[48 * i : 48 * i + 48], "big") for i in range(4)]
    if any(limb >= P for limb in limbs):
        raise PointEncodingError("limb not reduced")
    if not any(limbs):
        return None
    pt = ((limbs[0], limbs[1]), (limbs[2], limbs[3]))
    if not g2_is_on_curve(pt):
        raise PointEncodingError("not on curve")
    return pt


def g2_uncompressed_zcash(pt: G2Point) -> bytes:
    """ZCash 192-byte uncompressed G2 (`x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0`, no flags), for RFC vectors."""
    (x0, x1), (y0, y1) = pt
    return fp_to_bytes48(x1) + fp_to_bytes48(x0) + fp_to_bytes48(y1) + fp_to_bytes48(y0)
