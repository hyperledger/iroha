#!/usr/bin/env python3
"""Independent Python re-implementation of the FAEST v3.0.2 CRT / VOLE-multiplication
table construction (reference generator: tables/vole_mult_tables.cpp).

Standard library only.  Run with:  python3 -I crt_tables_ref.py [--out DIR] [profile ...]

Conventions: a polynomial over F_2 and a bit-vector are both Python ints, bit i =
coefficient of x^i = vector coordinate i.  A matrix is a list of row ints.
See ALGORITHM.md (same directory) for the step-by-step description.
"""
import hashlib
import os
import sys
from functools import lru_cache

# ----------------------------------------------------------------------------- profiles
# name -> (lambda, tau, w_grind).  FAEST-EM-128s/f and FAEST-EM-256s/f reuse the 128s/f
# and 256s/f tables (same triple).
PROFILES = {
    "128s": (128, 11, 7),
    "128f": (128, 17, 8),
    "192s": (192, 16, 12),
    "192f": (192, 24, 8),
    "256s": (256, 22, 6),
    "256f": (256, 33, 8),
    "em_192s": (192, 16, 8),
    "em_192f": (192, 25, 8),
}
FIELD_MODULUS = {
    128: (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1,
    192: (1 << 192) | (1 << 7) | (1 << 2) | (1 << 1) | 1,
    256: (1 << 256) | (1 << 10) | (1 << 5) | (1 << 2) | 1,
}
MAX_E = 10
MAX_D = 10
TOWER_COST = {6: 15, 8: 24}


# ----------------------------------------------------------------------------- F_2[x]
def bits(x):
    """Indices of set bits, ascending."""
    out = []
    i = 0
    while x:
        if x & 1:
            out.append(i)
        x >>= 1
        i += 1
    return out


def pdeg(a):
    return a.bit_length() - 1


def pmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
    return r


def pdivmod(a, b):
    db = pdeg(b)
    q = 0
    while a and pdeg(a) >= db:
        s = pdeg(a) - db
        q |= 1 << s
        a ^= b << s
    return q, a


def pmod(a, m):
    return pdivmod(a, m)[1]


def pmulmod(a, b, m):
    return pmod(pmul(a, b), m)


def pgcd(a, b):
    while b:
        a, b = b, pmod(a, b)
    return a


def pinvmod(a, m):
    r0, r1, s0, s1 = m, pmod(a, m), 0, 1
    while r1:
        q, r = pdivmod(r0, r1)
        r0, r1 = r1, r
        s0, s1 = s1, s0 ^ pmul(q, s1)
    assert r0 == 1
    return pmod(s0, m)


def ppow(p, e):
    r = 1
    for _ in range(e):
        r = pmul(r, p)
    return r


def prime_factors(n):
    fs = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            fs.add(d)
            n //= d
        d += 1
    if n > 1:
        fs.add(n)
    return fs


def is_irreducible(f):
    n = pdeg(f)
    if n <= 0:
        return False
    if n == 1:
        return True
    if not f & 1:
        return False

    def x_pow_2k(k):
        r = pmod(2, f)
        for _ in range(k):
            r = pmulmod(r, r, f)
        return r

    if x_pow_2k(n) != pmod(2, f):
        return False
    for q in prime_factors(n):
        if pgcd(f, pmod(x_pow_2k(n // q) ^ 2, f)) != 1:
            return False
    return True


@lru_cache(maxsize=None)
def irreducibles_of_degree(d):
    """All monic irreducibles of degree d, ascending as integers."""
    return tuple(f for f in range((1 << d) | 1, 1 << (d + 1)) if is_irreducible(f))


# ----------------------------------------------------------------------------- F_2 linear algebra
def combine(mask, rows):
    out = 0
    for i in bits(mask):
        out ^= rows[i]
    return out


def reduction_rows(q, ncols):
    """d x ncols matrix R (d = deg q): R[i] bit j = coefficient i of (x^j mod q)."""
    rows = [0] * pdeg(q)
    cur = 1
    for j in range(ncols):
        for i in bits(cur):
            rows[i] |= 1 << j
        cur = pmod(cur << 1, q)
    return rows


def pascal_rows(e):
    rows = []
    for i in range(e):
        row = 0
        for j in range(i, e):
            if (i & j) == i:
                row |= 1 << j
        rows.append(row)
    return rows


class ConstructionError(ValueError):
    """An invariant of the reference construction does not hold (never for the eight profiles)."""


def checked_place(pk, na, nb):
    """place_alg plus the invariant the reference relies on silently: the place returns exactly
    one gate mask per evaluation row.  The reference appends EVERY row of alg.w to resmasks and
    every row of ev to evrows, so a mismatch (a multiplicity-2 inf / x / x+1 place, whose short
    plan is Full and has 3 rows of w for 2 rows of ev) would shift all later residue rows."""
    (pg, pw), ev = place_alg(pk, na, nb)
    if len(pw) != len(ev):
        raise ConstructionError("place %r: %d gate-mask rows for %d evaluation rows"
                                % (pk, len(pw), len(ev)))
    return (pg, pw), ev


def square_left_inverse(rows, ncols):
    """left_inverse restricted to the only case the construction ever produces: a square system.
    Then X is the unique inverse and the pivot rule of left_inverse cannot influence any table."""
    if len(rows) != ncols:
        raise ConstructionError("evaluation matrix is %d x %d, expected square"
                                % (len(rows), ncols))
    return left_inverse(rows, ncols)


def left_inverse(rows, ncols):
    """rows: m x ncols (m >= ncols, full column rank).  Returns X (ncols masks over the m
    rows) with XOR_{i in X[c]} rows[i] = e_c.  Pivot rule: for column c = 0, 1, ... take the
    lowest-index row not yet used as a pivot that has a 1 in column c."""
    m = len(rows)
    a = list(rows)
    t = [1 << i for i in range(m)]
    used = [False] * m
    piv_of_col = []
    for c in range(ncols):
        piv = None
        for i in range(m):
            if not used[i] and (a[i] >> c) & 1:
                piv = i
                break
        assert piv is not None, "not full rank"
        used[piv] = True
        piv_of_col.append(piv)
        pr, pt = a[piv], t[piv]
        for i in range(m):
            if i != piv and (a[i] >> c) & 1:
                a[i] ^= pr
                t[i] ^= pt
    return [t[p] for p in piv_of_col]


# ----------------------------------------------------------------------------- F_4 and F_4[y]
# F_4 = {0, 1, w, w+1} encoded 0, 1, 2, 3 (bit 0 = coefficient of 1, bit 1 = coefficient of w),
# w^2 = w + 1.  Addition is XOR.
F4M = ((0, 0, 0, 0), (0, 1, 2, 3), (0, 2, 3, 1), (0, 3, 1, 2))
F4INV = (0, 1, 3, 2)


def f4_pow(t, j):
    r = 1
    for _ in range(j):
        r = F4M[r][t]
    return r


def f4_pmul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                out[i + j] ^= F4M[ai][bj]
    return out


def f4_pmod(a, q):
    dq = len(q) - 1
    work = list(a)
    for i in range(len(work) - 1, dq - 1, -1):
        c = work[i]
        if c:
            for j in range(dq + 1):
                work[i - dq + j] ^= F4M[c][q[j]]
    work = work[:dq] + [0] * max(0, dq - len(work))
    return work


def f4_peval(p, t):
    acc = 0
    for c in reversed(p):
        acc = F4M[acc][t] ^ c
    return acc


def f4_tuples(length):
    """All tuples in F_4^length, index 0 varying slowest (lexicographic)."""
    if length == 0:
        yield []
        return
    for v in range(4):
        for rest in f4_tuples(length - 1):
            yield [v] + rest


def f4_has_roots(p):
    return any(f4_peval(p, u) == 0 for u in range(4))


@lru_cache(maxsize=None)
def f4_irreducibles(m):
    """Monic irreducibles of degree m in F_4[y] (m in {2, 3, 4}), coefficient lists low to
    high, in lexicographic order of (c_0, c_1, ..., c_{m-1})."""
    quads = []
    if m == 4:
        quads = [t + [1] for t in f4_tuples(2) if not f4_has_roots(t + [1])]
    out = []
    for t in f4_tuples(m):
        p = t + [1]
        if f4_has_roots(p):
            continue
        if m == 4 and any(not any(f4_pmod(p, q2)) for q2 in quads):
            continue
        out.append(tuple(p))
    return tuple(out)


def f4_xpow_cols(q, count):
    dq = len(q) - 1
    cur = [1] + [0] * (dq - 1)
    cols = []
    for _ in range(count):
        cols.append(cur)
        cur = f4_pmod([0] + cur, q)
    return cols


def f4_matinv(mat):
    n = len(mat)
    a = [list(row) + [1 if j == i else 0 for j in range(n)] for i, row in enumerate(mat)]
    for c in range(n):
        piv = next(i for i in range(c, n) if a[i][c])
        a[c], a[piv] = a[piv], a[c]
        inv = F4INV[a[c][c]]
        a[c] = [F4M[inv][v] for v in a[c]]
        for i in range(n):
            if i != c and a[i][c]:
                fac = a[i][c]
                a[i] = [v ^ F4M[fac][pv] for v, pv in zip(a[i], a[c])]
    return [row[n:] for row in a]


def f4_full_product_alg(m):
    """Bilinear algorithm over F_4 for the full product of two degree-<m polynomials in F_4[y].
    Returns (gates4, w4): gate g multiplies <gates4[g], a> by <gates4[g], b>; product coefficient
    k is sum_g w4[k][g] * gate_g.  m = 3: 5 gates, m = 4: 8 gates."""
    gates4, ev, r4 = [], [], []
    npts = 2 if m == 2 else 4
    for t in range(npts):
        r4.append([(len(gates4), 1)])
        gates4.append([f4_pow(t, j) for j in range(m)])
        ev.append([f4_pow(t, j) for j in range(2 * m - 1)])
    r4.append([(len(gates4), 1)])
    gates4.append([0] * (m - 1) + [1])
    ev.append([0] * (2 * m - 2) + [1])
    if m == 4:
        q2 = f4_irreducibles(2)[0]
        beta, alpha = q2[0], q2[1]
        cols_in = f4_xpow_cols(q2, m)
        ga = len(gates4)
        gates4.append([c[0] for c in cols_in])
        gates4.append([c[1] for c in cols_in])
        gates4.append([c[0] ^ c[1] for c in cols_in])
        cols_out = f4_xpow_cols(q2, 2 * m - 1)
        ev.append([c[0] for c in cols_out])
        ev.append([c[1] for c in cols_out])
        r4.append([(ga, 1), (ga + 1, beta)])
        r4.append([(ga, 1), (ga + 1, 1 ^ alpha), (ga + 2, 1)])
    inv = f4_matinv(ev)
    ng = len(gates4)
    w4 = [[0] * ng for _ in range(2 * m - 1)]
    for k in range(2 * m - 1):
        for j, terms in enumerate(r4):
            c = inv[k][j]
            if c:
                for g, coeff in terms:
                    w4[k][g] ^= F4M[c][coeff]
    return gates4, w4


# ----------------------------------------------------------------------------- algorithms
# Alg = (gates, w): gates = list of (fa, fb) input masks; w = list of output masks over gates.
# Place = (kind, poly, e), kind in {"inf", "lin", "irr"}.
BASE_ALG = ([(1, 1)], [1])
MONT5_GATES = (0b11111, 0b11101, 0b10111, 0b11011, 0b01101, 0b10110, 0b11000, 0b00011,
               0b10001, 0b10000, 0b01000, 0b00010, 0b00001)
MONT5_W = ((12,), (7, 11, 12), (2, 5, 7, 8, 9, 12), (0, 1, 3, 6, 8, 9),
           (0, 4, 5, 6, 7, 9, 10, 11, 12), (0, 2, 3, 7, 8, 12), (1, 4, 6, 8, 9, 12),
           (6, 9, 10), (9,))


def precompose(alg, ar, br):
    gates, w = alg
    return ([(combine(fa, ar), combine(fb, br)) for fa, fb in gates], list(w))


def place_gate_cost(pk):
    kind, poly, e = pk
    if kind in ("inf", "lin"):
        return short_cost(e)[0]
    d = pdeg(poly)
    tc = TOWER_COST.get(d, 0)
    if e == 1 and tc:
        return min(tc, full_cost(d)[0])
    return full_cost(d * e)[0]


def crt_search(target, maxe_lin, cap_irr, irr_pools):
    """Grouped knapsack.  irr_pools: dict degree -> list of polys.  Returns (cost, picks) or None."""
    groups = []
    for kind, poly in (("inf", 0), ("lin", 0b10), ("lin", 0b11)):
        opts = [(e, short_cost(e)[0], [(kind, poly, e)]) for e in range(1, maxe_lin + 1)]
        if opts:
            groups.append(opts)
    for d in sorted(irr_pools):
        pool = irr_pools[d]
        if not pool:
            continue
        opts = []
        if d == 2:
            e = 1
            while d * e <= cap_irr:
                pk = ("irr", pool[0], e)
                opts.append((d * e, place_gate_cost(pk), [pk]))
                e += 1
        else:
            per = place_gate_cost(("irr", pool[0], 1))
            maxt = min(len(pool), target // d + 1)
            for t in range(1, maxt + 1):
                opts.append((t * d, t * per, [("irr", pool[i], 1) for i in range(t)]))
        if opts:
            groups.append(opts)

    dp = {0: (0, [])}
    for opts in groups:
        ndp = dict(dp)
        for deg0 in sorted(dp):
            cost0, picks0 = dp[deg0]
            for odeg, ocost, opicks in opts:
                nd = min(deg0 + odeg, target)
                nc = cost0 + ocost
                if nd not in ndp or nc < ndp[nd][0]:
                    ndp[nd] = (nc, picks0 + opicks)
        dp = ndp
    return dp.get(target)


@lru_cache(maxsize=None)
def full_cost(n):
    """(gates, plan) for the full product of two n-coefficient polynomials."""
    if n == 1:
        return (1, ("base",))
    best = None
    if n == 5:
        best = (13, ("mont5",))
    for s in range(2, n):
        m = (n + s - 1) // s
        c = full_cost(s)[0] * full_cost(m)[0]
        if best is None or c < best[0]:
            best = (c, ("split", s, m))
    pools = {d: list(irreducibles_of_degree(d)) for d in range(2, n)}
    res = crt_search(2 * n - 1, n - 1, n - 1, pools)
    if res is not None and (best is None or res[0] < best[0]):
        best = (res[0], ("crt", tuple(res[1])))
    assert best is not None
    return best


@lru_cache(maxsize=None)
def short_cost(n):
    """(gates, plan) for the low n coefficients of the product of two n-coefficient polynomials."""
    if n == 1:
        return (1, ("base",))
    best = (full_cost(n)[0], ("full",))
    for m in range((n + 1) // 2, n):
        c = full_cost(m)[0] + 2 * short_cost(n - m)[0]
        if c < best[0]:
            best = (c, ("shortsplit", m))
    return best


@lru_cache(maxsize=None)
def full_alg(n):
    plan = full_cost(n)[1]
    if plan[0] == "base":
        return BASE_ALG
    if plan[0] == "mont5":
        return ([(g, g) for g in MONT5_GATES], [sum(1 << g for g in row) for row in MONT5_W])
    if plan[0] == "split":
        _, s, m = plan
        ogates, ow = full_alg(s)
        igates, iw = full_alg(m)
        ngi = len(igates)
        gates = []
        for fo, go in ogates:
            ar = [0] * m
            br = [0] * m
            for i in range(m):
                for t in bits(fo):
                    if t * m + i < n:
                        ar[i] |= 1 << (t * m + i)
                for t in bits(go):
                    if t * m + i < n:
                        br[i] |= 1 << (t * m + i)
            for fi, gi in igates:
                gates.append((combine(fi, ar), combine(gi, br)))
        w = []
        for q in range(2 * n - 1):
            row = 0
            for r in range(2 * s - 1):
                if r * m > q:
                    continue
                i = q - r * m
                if i <= 2 * m - 2:
                    for o in bits(ow[r]):
                        row ^= iw[i] << (o * ngi)
            w.append(row)
        return (gates, w)
    if plan[0] == "crt":
        gates, resmasks, evrows = [], [], []
        for pk in plan[1]:
            (pg, pw), ev = checked_place(pk, n, n)
            off = len(gates)
            gates.extend(pg)
            resmasks.extend(row << off for row in pw)
            evrows.extend(ev)
        x = square_left_inverse(evrows, 2 * n - 1)
        return (gates, [combine(x[q], resmasks) for q in range(2 * n - 1)])
    raise AssertionError(plan)


@lru_cache(maxsize=None)
def short_alg(n):
    plan = short_cost(n)[1]
    if plan[0] == "base":
        return BASE_ALG
    if plan[0] == "full":
        return full_alg(n)
    _, m = plan
    lo = [1 << i for i in range(m)]
    g1 = precompose(full_alg(m), lo, lo)
    s = short_alg(n - m)
    lo2 = [1 << i for i in range(n - m)]
    hi2 = [1 << (m + i) for i in range(n - m)]
    g2 = precompose(s, lo2, hi2)
    g3 = precompose(s, hi2, lo2)
    o2 = len(g1[0])
    o3 = o2 + len(g2[0])
    gates = g1[0] + g2[0] + g3[0]
    w = []
    for j in range(n):
        row = 0
        if j <= 2 * m - 2:
            row ^= g1[1][j]
        if j >= m:
            row ^= (g2[1][j - m] << o2) ^ (g3[1][j - m] << o3)
        w.append(row)
    return (gates, w)


def tower_place_alg(q, na, nb):
    """Place F_2[x]/(q), deg q = d in {6, 8}, computed in F_4[y]/(T) with m = d/2."""
    d = pdeg(q)
    m = d // 2
    tm = list(f4_irreducibles(m)[0])
    gates4, w4 = f4_full_product_alg(m)
    ng4 = len(gates4)
    rq = f4_xpow_cols(tm, 2 * m - 1)
    w4m = [[0] * ng4 for _ in range(m)]
    for k in range(m):
        for j in range(2 * m - 1):
            c = rq[j][k]
            for g in range(ng4):
                w4m[k][g] ^= F4M[c][w4[j][g]]
    rho = None
    for cand in f4_tuples(m):
        acc = [0] * m
        for i in range(d, -1, -1):
            acc = f4_pmod(f4_pmul(acc, cand), tm)
            if (q >> i) & 1:
                acc[0] ^= 1
        if not any(acc):
            rho = cand
            break
    assert rho is not None
    cols = []
    power = [1]
    for _ in range(d):
        cols.append(sum(v << (2 * j) for j, v in enumerate(power)))
        power = f4_pmod(f4_pmul(power, rho), tm)
    mrows = [sum(((cols[i] >> r) & 1) << i for i in range(d)) for r in range(d)]
    minv = square_left_inverse(mrows, d)
    red_a = reduction_rows(q, na)
    red_b = reduction_rows(q, nb)
    trow_a = [combine(mrows[r], red_a) for r in range(d)]
    trow_b = [combine(mrows[r], red_b) for r in range(d)]

    def form_bits(lin, trow):
        p = r = 0
        for j, c in enumerate(lin):
            if not c:
                continue
            pj, rj = trow[2 * j], trow[2 * j + 1]
            if c & 1:
                p ^= pj
                r ^= rj
            if c & 2:
                p ^= rj
                r ^= pj ^ rj
        return p, r

    gates, comp = [], []
    for lin in gates4:
        pa, ra = form_bits(lin, trow_a)
        pb, rb = form_bits(lin, trow_b)
        b = len(gates)
        gates += [(pa, pb), (ra, rb), (pa ^ ra, pb ^ rb)]
        comp.append(((1 << b) | (1 << (b + 1)), (1 << b) | (1 << (b + 2))))
    towout = [0] * d
    for k in range(m):
        o0 = o1 = 0
        for g in range(ng4):
            c = w4m[k][g]
            if not c:
                continue
            g0, g1 = comp[g]
            if c & 1:
                o0 ^= g0
                o1 ^= g1
            if c & 2:
                o0 ^= g1
                o1 ^= g0 ^ g1
        towout[2 * k] = o0
        towout[2 * k + 1] = o1
    w = [combine(minv[r], towout) for r in range(d)]
    return (gates, w), reduction_rows(q, na + nb - 1)


def place_alg(pk, na, nb):
    """Returns ((gates, w), ev): gates on na/nb-bit inputs, w = residue-coordinate masks over the
    place's gates, ev = the same residue coordinates as linear forms on the n2 = na+nb-1 product
    coefficients."""
    kind, poly, e = pk
    n2 = na + nb - 1
    if kind == "inf":
        assert e <= min(na, nb)
        ra = [1 << (na - 1 - i) for i in range(e)]
        rb = [1 << (nb - 1 - i) for i in range(e)]
        ev = [1 << (n2 - 1 - i) for i in range(e)]
        return precompose(short_alg(e), ra, rb), ev
    if kind == "lin":
        q = ppow(poly, e)
        ra, rb, rev = reduction_rows(q, na), reduction_rows(q, nb), reduction_rows(q, n2)
        if poly == 0b10:
            return precompose(short_alg(e), ra, rb), rev
        p = pascal_rows(e)
        return (precompose(short_alg(e), [combine(mk, ra) for mk in p],
                           [combine(mk, rb) for mk in p]),
                [combine(mk, rev) for mk in p])
    d0 = pdeg(poly)
    tc = TOWER_COST.get(d0, 0)
    if e == 1 and tc and tc < full_cost(d0)[0]:
        return tower_place_alg(poly, na, nb)
    q = ppow(poly, e)
    d = pdeg(q)
    gates, w0 = precompose(full_alg(d), reduction_rows(q, na), reduction_rows(q, nb))
    rout = reduction_rows(q, 2 * d - 1)
    return (gates, [combine(rout[i], w0) for i in range(d)]), reduction_rows(q, n2)


# ----------------------------------------------------------------------------- top level
def tree_spec(lam, tau, wgrind):
    n = lam - wgrind
    d1 = n // tau + 1
    tau1 = n % tau
    spec = []
    if tau1:
        spec.append((d1, tau1))
    spec.append((d1 - 1, tau - tau1))
    return spec


def mtree_poly(tree_moduli):
    r = 1
    for m in tree_moduli:
        r = pmul(r, m)
    return r


def crt_lift_cols(tree_moduli):
    mtree = mtree_poly(tree_moduli)
    cols = []
    for m in tree_moduli:
        q, rem = pdivmod(mtree, m)
        assert rem == 0
        e = pmulmod(q, pinvmod(q, m), mtree)
        for b in range(pdeg(m)):
            cols.append(pmulmod(e, 1 << b, mtree))
    return cols


def parity(x):
    return bin(x).count("1") & 1


def prune(f, g, wg):
    canon = {}
    for i in range(len(f)):
        if f[i] and g[i]:
            canon.setdefault((f[i], g[i]), i)
    wg1 = []
    for row in wg:
        nr = 0
        for i in bits(row):
            if f[i] and g[i]:
                nr ^= 1 << canon[(f[i], g[i])]
        wg1.append(nr)
    used = 0
    for row in wg1:
        used |= row
    newidx = {}
    f2, g2 = [], []
    for i in bits(used):
        newidx[i] = len(f2)
        f2.append(f[i])
        g2.append(g[i])
    wg2 = [sum(1 << newidx[i] for i in bits(row)) for row in wg1]
    return f2, g2, wg2


def generate(name):
    lam, tau, wgrind = PROFILES[name]
    na, nb = lam, lam - wgrind
    n2 = na + nb - 1
    spec = tree_spec(lam, tau, wgrind)
    tree_moduli = []
    for d, c in spec:
        pool = irreducibles_of_degree(d)
        assert c <= len(pool)
        tree_moduli.extend(pool[:c])
    ntree = sum(pdeg(m) for m in tree_moduli)
    assert ntree == nb
    deficit = n2 - ntree
    treeset = set(tree_moduli)
    pools = {}
    for d in range(2, MAX_D + 1):
        lst = [q for q in irreducibles_of_degree(d) if q not in treeset]
        if lst:
            pools[d] = lst
    res = crt_search(deficit, MAX_E, MAX_D, pools)
    assert res is not None
    cost, picks = res

    evrows = []
    for m in tree_moduli:
        evrows.extend(reduction_rows(m, n2))
    gates, resmasks, report = [], [], []
    for pk in picks:
        (pg, pw), ev = checked_place(pk, na, nb)
        off = len(gates)
        gates.extend(pg)
        resmasks.extend(row << off for row in pw)
        evrows.extend(ev)
        report.append((pk, len(pg)))
    x = square_left_inverse(evrows, n2)
    red = reduction_rows(FIELD_MODULUS[lam], n2)
    wt = [0] * lam
    wg = [0] * lam
    for r in range(lam):
        sel = combine(red[r], x)
        for idx in bits(sel):
            if idx < ntree:
                wt[r] |= 1 << idx
            else:
                wg[r] ^= resmasks[idx - ntree]
    cols = crt_lift_cols(tree_moduli)
    f = [fa for fa, _ in gates]
    g = [sum(parity(fb & cols[j]) << j for j in range(nb)) for _, fb in gates]
    raw_gates = len(f)
    f, g, wg = prune(f, g, wg)
    wcrt = [sum(((cols[j] >> r) & 1) << j for j in range(len(cols))) for r in range(lam)]
    return {
        "name": name, "lambda": lam, "tau": tau, "w_grind": wgrind, "n_delta": nb,
        "tree_spec": spec, "tree_moduli": tree_moduli, "m_tree": mtree_poly(tree_moduli),
        "picks": picks, "report": report, "search_cost": cost, "raw_gates": raw_gates,
        "n_mult": len(f), "F": f, "G": g, "W_TREE": wt, "W_GATE": wg, "W_CRT": wcrt,
    }


# ----------------------------------------------------------------------------- serialisation
def words_of(width):
    return (width + 63) // 64


def row_bytes(row, nbytes):
    return row.to_bytes(nbytes, "little")


def table_layout(t):
    """name -> (rows, cols(bits), words per row, list of row ints) exactly as the reference emits."""
    lam, nb, ng = t["lambda"], t["n_delta"], t["n_mult"]
    return [
        ("F", ng, lam, words_of(lam), t["F"]),
        ("G", ng, nb, words_of(nb), t["G"]),
        ("W_TREE", lam, nb, words_of(nb), t["W_TREE"]),
        ("W_GATE", lam, ng, words_of(ng), t["W_GATE"]),
        ("W_CRT", lam, nb, words_of(nb), t["W_CRT"]),
    ]


def table_blob(rows, words):
    """Canonical binary image: rows in order, each row `words` little-endian uint64 words."""
    return b"".join(row_bytes(r, 8 * words) for r in rows)


def emit(t, outdir):
    """Text format, one file per profile:
         # comment lines
         key = value                         scalars (decimal) / hex polynomials
         TREE_MODULI = hex,hex,...           tau values, each the full polynomial (bit i = x^i)
         M_TREE = hex                        product polynomial, degree n_delta
         [TABLE rows cols words sha256]      header of a matrix section
         <hex>                               one line per row: the row as a big-endian hex integer
                                             of exactly 16*words digits (bit i of the integer =
                                             column i).  sha256 is over the canonical binary image
                                             (rows in order, each row as `words` little-endian u64).
    """
    lines = [
        "# FAEST v3.0.2 CRT / VOLE-multiplication tables, profile " + t["name"],
        "# regenerated by crt_tables_ref.py (independent Python port of tables/vole_mult_tables.cpp)",
        "# row lines: big-endian hex integer, bit i of the integer = column i",
        "name = " + t["name"],
        "lambda = %d" % t["lambda"],
        "tau = %d" % t["tau"],
        "w_grind = %d" % t["w_grind"],
        "n_delta = %d" % t["n_delta"],
        "n_mult = %d" % t["n_mult"],
        "TREE_MODULI = " + ",".join("%x" % m for m in t["tree_moduli"]),
        "M_TREE = %x" % t["m_tree"],
        "m_tree_words = %d" % words_of(pdeg(t["m_tree"]) + 1),
    ]
    digest_all = hashlib.sha256()
    hashes = {}
    for nm, rows, cols, words, data in table_layout(t):
        assert len(data) == rows and all(r >> cols == 0 for r in data)
        blob = table_blob(data, words)
        h = hashlib.sha256(blob).hexdigest()
        hashes[nm] = (rows, cols, words, len(blob), h)
        digest_all.update(blob)
        lines.append("[%s %d %d %d %s]" % (nm, rows, cols, words, h))
        lines.extend("%0*x" % (16 * words, r) for r in data)
    tm_blob = b"".join(m.to_bytes(2, "little") for m in t["tree_moduli"])
    mt_blob = t["m_tree"].to_bytes(8 * words_of(pdeg(t["m_tree"]) + 1), "little")
    hashes["TREE_MODULI"] = (t["tau"], 16, 0, len(tm_blob), hashlib.sha256(tm_blob).hexdigest())
    hashes["M_TREE"] = (1, t["n_delta"] + 1, len(mt_blob) // 8, len(mt_blob),
                        hashlib.sha256(mt_blob).hexdigest())
    digest_all.update(tm_blob)
    digest_all.update(mt_blob)
    hashes["ALL"] = (0, 0, 0, 0, digest_all.hexdigest())
    text = "\n".join(lines) + "\n"
    path = os.path.join(outdir, "faest_%s_tables.txt" % t["name"])
    with open(path, "w") as fh:
        fh.write(text)
    return path, hashlib.sha256(text.encode()).hexdigest(), len(text), hashes


def describe_pick(pk):
    kind, poly, e = pk
    if kind == "inf":
        return "inf^%d" % e
    return "(%s)^%d" % (hex(poly), e)


def main(argv):
    outdir = None
    names = []
    i = 1
    while i < len(argv):
        if argv[i] == "--out":
            outdir = argv[i + 1]
            i += 2
        else:
            names.append(argv[i])
            i += 1
    names = names or list(PROFILES)
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    manifest = []
    shake = []
    for name in names:
        t = generate(name)
        print("%-8s lambda=%d tau=%d w_grind=%d tree_spec=%s deficit=%d search_cost=%d raw_gates=%d n_mult=%d"
              % (name, t["lambda"], t["tau"], t["w_grind"], t["tree_spec"],
                 t["lambda"] - 1, t["search_cost"], t["raw_gates"], t["n_mult"]))
        print("   picks: " + " ".join("%s[%d]" % (describe_pick(pk), n) for pk, n in t["report"]))
        if outdir:
            path, fsha, flen, hashes = emit(t, outdir)
            manifest.append("%s  %s  (%d bytes)" % (fsha, os.path.basename(path), flen))
            for nm, (rows, cols, words, blen, h) in hashes.items():
                manifest.append("    %-8s %-11s rows=%d cols=%d words=%d bytes=%d sha256=%s"
                                % (t["name"], nm, rows, cols, words, blen, h))
            for nm, _rows, _cols, words, data in table_layout(t):
                shake.append("%-8s %-7s shake256_32=%s" % (
                    t["name"], nm, hashlib.shake_256(table_blob(data, words)).hexdigest(32)))
    if outdir:
        with open(os.path.join(outdir, "SHA256SUMS.txt"), "w") as fh:
            fh.write("\n".join(manifest) + "\n")
        print("\n".join(manifest))
        # SHAKE256 (32-byte output) of the same canonical binary images, for crates that have
        # SHAKE but no SHA-2.
        with open(os.path.join(outdir, "SHAKE256SUMS.txt"), "w") as fh:
            fh.write("\n".join(shake) + "\n")


if __name__ == "__main__":
    main(sys.argv)
