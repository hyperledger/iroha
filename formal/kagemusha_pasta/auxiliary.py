"""Bounded exact auxiliary-curve certificate; caller must first prove prime p/r.

No point counting, factoring, randomness, setup artifact import or native build.
The combined check.py verifies source pins and primality before calling certify.
"""
from pathlib import Path
import math
import re

ROOT = Path(__file__).resolve().parents[2]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def limbs(text):
    values = [int(t.strip().replace('_', ''), 0) for t in text.split(',') if t.strip()]
    require(len(values) == 4 and all(0 <= x < 2**64 for x in values), 'canonical limbs')
    return sum(v << (64*i) for i, v in enumerate(values))


def trim(a, p):
    a = [x % p for x in a]
    while a and a[-1] == 0:
        a.pop()
    return a


def add(a, b, p, sign=1):
    return trim([(a[i] if i < len(a) else 0) + sign*(b[i] if i < len(b) else 0)
                 for i in range(max(len(a), len(b)))], p)


def mul(a, b, p):
    if not a or not b:
        return []
    c = [0]*(len(a)+len(b)-1)
    for i, u in enumerate(a):
        for j, v in enumerate(b):
            c[i+j] += u*v
    return trim(c, p)


def power(a, n, p):
    out = [1]
    for _ in range(n):
        out = mul(out, a, p)
    return out


def rem(a, b, p):
    a, b = trim(a, p), trim(b, p)
    require(bool(b), 'nonzero divisor')
    while len(a) >= len(b):
        shift = len(a)-len(b)
        c = a[-1]*pow(b[-1], -1, p) % p
        a = add(a, [0]*shift + [c*x for x in b], p, -1)
    return a


def gcd(a, b, p):
    while b:
        a, b = b, rem(a, b, p)
    return trim([x*pow(a[-1], -1, p) for x in a], p) if a else []


def evaluate(a, x, p):
    y = 0
    for c in reversed(a):
        y = (y*x+c) % p
    return y


def on_curve(point, a, b, p):
    return point is None or (all(type(x) is int and 0 <= x < p for x in point)
                            and (point[1]**2-point[0]**3-a*point[0]-b) % p == 0)


def point_add(left, right, a, b, p):
    require(on_curve(left, a, b, p) and on_curve(right, a, b, p), 'curve arguments')
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u and (y+v) % p == 0:
        return None
    slope = ((3*x*x+a)*pow(2*y, -1, p) if left == right else
             (v-y)*pow(u-x, -1, p)) % p
    xx = (slope*slope-x-u) % p
    result = (xx, (slope*(x-xx)-y) % p)
    require(on_curve(result, a, b, p), 'curve sum')
    return result


def point_mul(point, n, a, b, p):
    require(type(n) is int and 0 <= n < 2**256, 'bounded multiplier')
    out = None
    for i in range(256):
        if n >> i & 1:
            out = point_add(out, point, a, b, p)
        point = point_add(point, point, a, b, p)
    return out


def square_root(value, p):
    """Bounded Tonelli-Shanks using source generator 5, conditional on prime p."""
    value %= p
    if value == 0:
        return 0
    require(pow(value, (p-1)//2, p) == 1, 'square required')
    odd = (p-1) >> 32
    require(odd & 1 and odd << 32 == p-1, 'exact two-adicity32')
    require(pow(5, (p-1)//2, p) == p-1, 'nonresidue5')
    c, x, t, m = pow(5, odd, p), pow(value, (odd+1)//2, p), pow(value, odd, p), 32
    for _ in range(32):
        if t == 1:
            require(x*x % p == value, 'root result')
            return x
        probe = t
        for i in range(1, m):
            probe = probe*probe % p
            if probe == 1:
                break
        else:
            raise ValueError('no Tonelli-Shanks descent')
        d = pow(c, 1 << (m-i-1), p)
        x, c = x*d % p, d*d % p
        t, m = t*c % p, i
    raise ValueError('root iteration bound')


def constants(name, field):
    field_source = (ROOT/f'crates/iroha_pasta/src/field/{field}.rs').read_text()
    matches = re.findall(r'const MODULUS_STR: &str = "0x([0-9a-f]+)";', field_source)
    require(len(matches) == 1, 'one field modulus')
    p = int(matches[0], 16)
    source = (ROOT/f'crates/iroha_pasta/src/curve/{name}.rs').read_text()
    def named(key):
        values = re.findall(r'const '+key+r': F[pq] = F[pq]::from_raw\(\[(.*?)\]\);', source, re.S)
        require(len(values) == 1, 'one named constant')
        return limbs(values[0])
    a, b, z = (named(key) for key in ('ISO_A', 'ISO_B', 'Z'))
    body = source.split('const ISOGENY_CONSTANTS:', 1)[1].split('\n    ];', 1)[0]
    c = [limbs(s) for s in re.findall(r'F[pq]::from_raw\(\[(.*?)\]\)', body, re.S)]
    require(len(c) == 13 and all(0 <= x < p for x in [a,b,z,*c]), 'canonical constants')
    require(b == 1265 and z == p-13, 'exact source auxiliary family')
    return p, a, b, z, c


def algebra(p, a, b, c):
    """Polynomial certificate for all affine points, not a sampled check."""
    require((4*a**3+27*b*b) % p != 0 and 27*25 % p != 0, 'both nonsingular')
    nx, dx = list(reversed(c[:4])), [c[5], c[4], 1]
    ny, dy = list(reversed(c[6:10])), [c[12], c[11], c[10], 1]
    q = [b, a, 0, 1]
    require(len(trim(nx,p)) == 4 and len(trim(ny,p)) == 4, 'leading coefficients')
    require(gcd(nx,dx,p) == [1] and gcd(ny,dy,p) == [1], 'reduced maps')
    # q(x) Ny(x)^2 Dx(x)^3 = (Nx(x)^3+5 Dx(x)^3) Dy(x)^2.
    lhs = mul(mul(q,power(ny,2,p),p),power(dx,3,p),p)
    rhs = mul(add(power(nx,3,p),mul([5],power(dx,3,p),p),p),power(dy,2,p),p)
    require(add(lhs,rhs,p,-1) == [], 'complete curve-map identity')
    derivative_nx = [(i+1)*nx[i+1] for i in range(len(nx)-1)]
    derivative_dx = [(i+1)*dx[i+1] for i in range(len(dx)-1)]
    require(add(mul(derivative_nx,dx,p),mul(nx,derivative_dx,p),p,-1) != [], 'separable x map')
    return nx, dx, ny, dy


def certify(name, p, r, a, b, z, c):
    nx, dx, ny, dy = algebra(p,a,b,c)
    # Independent u=1 evaluation only chooses an explicit point certificate.
    t = z
    d = (t*t+t) % p
    require(d != 0, 'u1 ordinary SWU branch')
    x1 = b*(d+1)*pow(-a*d,-1,p) % p
    f1 = (x1**3+a*x1+b) % p
    x = x1 if f1 == 0 or pow(f1,(p-1)//2,p) == 1 else t*x1 % p
    y = square_root(x**3+a*x+b,p)
    if not y & 1:
        y = (-y) % p
    require(y & 1 and on_curve((x,y),a,b,p), 'explicit odd-sign nonidentity point')
    point = (x,y)
    require(point_mul(point,r,a,b,p) is None, 'r torsion certificate')
    h = math.isqrt(4*p)
    lower,upper = p+1-h,p+1+h
    require((lower+r-1)//r == 1 and upper//r == 1, 'unique Hasse multiple r')
    require(math.gcd(3,r) == 1 and p > 3, 'separable degree coprime order')
    require(evaluate(dx,x,p) != 0 and evaluate(dy,x,p) != 0, 'certificate image finite')
    image = (evaluate(nx,x,p)*pow(evaluate(dx,x,p),-1,p) % p,
             y*evaluate(ny,x,p)*pow(evaluate(dy,x,p),-1,p) % p)
    require(on_curve(image,0,5,p), 'explicit nonidentity image')
    require(point_mul(image,r,0,5,p) is None, 'image r torsion')
    return {'curve':name,'base':hex(p),'order':hex(r),'aux_a':hex(a),'aux_b':b,
            'point':[hex(x),hex(y)],'image':[hex(v) for v in image],
            'hasse_lower':str(lower),'hasse_upper':str(upper),'only_multiple':'r',
            'x_map_degree':3,'y_map_degree_pair':[3,3],
            'polynomial_identity':True,'x_derivative_nonzero':True,
            'auxiliary_and_target_order':'r, conditional on accepted p/r primality',
            'rational_point_isomorphism':'conditional algebraic consequence, no sampled-homomorphism premise'}
