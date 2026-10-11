"""Exact finite-map model for the fresh-target simulator; no cryptographic code."""
from collections import Counter
from fractions import Fraction
from math import gcd


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pair_counts(mapping, order, slots=9, generator=1):
    """Count accepted triples; every returned pair must have one witness triple."""
    require(order >= 2 and gcd(generator, order) == 1, 'full-order generator')
    require(bool(mapping) and slots > 0, 'nonempty bounded domain')
    require(all(type(x) is int and 0 <= x < order for x in mapping), 'canonical map')
    fibers = [[i for i, value in enumerate(mapping) if value == point]
              for point in range(order)]
    require(max(map(len, fibers)) <= slots, 'complete inverse fits every slot')
    counts = Counter()
    for t in range(order):
        target = t * generator % order
        for u, point in enumerate(mapping):
            fiber = fibers[(target-point) % order]
            for slot in range(slots):
                if slot < len(fiber):
                    v = fiber[slot]
                    require((point+mapping[v]) % order == target, 'known-log equation')
                    counts[u,v] += 1
    return counts


def finite_law(domain_size, order, slots, attempts, caps):
    """Exact common pair mass and retained failure with immediate cap abort."""
    require(domain_size > 0 and order > 0 and slots > 0 and attempts >= 0,
            'finite positive dimensions')
    require(len(caps) == 3 and all(Fraction(0) <= e <= Fraction(1) for e in caps),
            'three cap failure probabilities')
    success = Fraction(domain_size, order*slots)
    require(success <= 1, 'fiber-count premise')
    alpha = (1-caps[0])*(1-caps[1])*(1-caps[2])
    common, continuation = Fraction(0), Fraction(1)
    for _ in range(attempts):
        common += continuation*alpha/Fraction(order*domain_size*slots)
        continuation *= alpha*(1-success)
    failure = 1-domain_size**2*common
    bound = min(Fraction(1), (1-success)**attempts + attempts*sum(caps))
    return common, failure, bound
