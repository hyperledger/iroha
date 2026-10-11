"""Small native-shaped parameter family; source-map logs stay private."""
from dataclasses import dataclass
from .custody import require

SMALL_MAX_K = 6

@dataclass(frozen=True)
class Parameters:
    """Private small setup and logs; no release authority is changed."""
    curve_tag: int
    k: int
    base: tuple
    raw: bytes
    logs: dict


class ParameterFamily:
    """Actual native messages and parameter ordering for bounded k<=6 controls.

    One supplied raw oracle spans both curves and every request. Existing
    contexts replay exact words/logs; smaller prefixes never receive new draws.
    The O(n^2) direct scalar IFFT is deliberately restricted to small controls.
    """

    def __init__(self, raw, oracle, sampler):
        self.raw, self.oracle, self.sampler = raw, oracle, sampler

    def point(self, tag, message):
        """Expand through raw queries and independently verify the retained log."""
        model = self.sampler.models[tag]
        first, second = self.oracle.expand(tag, message)
        u, v = (int.from_bytes(word, 'big') % model.p for word in (first, second))
        point = model.isogeny(model.add(model.forward(u), model.forward(v)))
        scalar = self.oracle.logs[(tag, message)]
        require(type(scalar) is int and 0 <= scalar < model.curve.scalar,
                'canonical private parameter log')
        base = model.isogeny(model.forward(1))
        require(model.curve.equal(point, model.curve.multiply(base, scalar)),
                'raw setup words and retained log agree')
        return point, scalar

    def derive(self, tag, k):
        """Derive one native-shaped encoding; keep every identity refusal.

        All g requests are made before selecting their first invalid index,
        matching native parallel generator collection. W/U are requested after
        Lagrange derivation and before the remaining encoding-order check.
        """
        require(type(tag) is int and tag in (0, 1), 'exact curve tag')
        require(type(k) is int and 0 <= k <= SMALL_MAX_K, 'small setup k<=6 only')
        model, n = self.sampler.models[tag], 1 << k
        curve, r = model.curve, model.curve.scalar
        base = model.isogeny(model.forward(1))
        values = [self.point(tag, b'\x00'+i.to_bytes(4, 'little')) for i in range(n)]
        for i, (point, _) in enumerate(values):
            if point[2] == 0:
                raise self.raw.Refused('native parameter identity at index '+str(i))
        g = tuple(value for _, value in values)
        omega, scale = (1 if k == 0 else curve.omega(k)), pow(n, -1, r)
        lagrange = tuple(sum(g[i]*pow(omega, (-i*j) % n, r) for i in range(n))*scale % r
                         for j in range(n))
        lagrange_points = [curve.multiply(base, value) for value in lagrange]
        w, w_log = self.point(tag, b'\x01')
        u, u_log = self.point(tag, b'\x02')
        points = [point for point, _ in values]+lagrange_points+[w, u]
        for index, point in enumerate(points):
            if point[2] == 0:
                raise self.raw.Refused('native parameter identity at index '+str(index))
        encoded = k.to_bytes(4, 'little')+b''.join(curve.encode(point) for point in points)
        require(len(encoded) == 64*n+68, 'exact native parameter length')
        return Parameters(tag, k, base, encoded,
                          {'g': g, 'lagrange': lagrange, 'w': w_log, 'u': u_log})
