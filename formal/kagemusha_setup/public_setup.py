"""Public PIPAPK01 tables for the private fixed-RP57 known-log simulator.

This reader consumes a caller-pinned original, never a witness. It does not
replace native installed-circuit synthesis or signed-package authentication.
"""
from dataclasses import dataclass
import hashlib

from .custody import require


def weights(k, curve, at):
    """Evaluate all domain Lagrange polynomials with one batch inversion.

    Domain points are handled exactly instead of dividing by zero. The output
    is in ordinary increasing row order, including every blinding row.
    """
    require(type(k) is int and 1 <= k <= 16, 'public table exponent')
    m, n = curve.scalar, 1 << k
    require(type(at) is int and 0 <= at < m, 'canonical evaluation point')
    omega = curve.omega(k)
    roots, prefixes, product, root = [], [], 1, 1
    for _ in range(n):
        if at == root:
            result = [0] * n
            result[len(roots)] = 1
            return result
        roots.append(root)
        prefixes.append(product)
        product = product * (at - root) % m
        root = root * omega % m
    inverse_product = pow(product, -1, m)
    scale = (pow(at, n, m) - 1) * pow(n, -1, m) % m
    result = [0] * n
    for i in reversed(range(n)):
        result[i] = roots[i] * scale * prefixes[i] * inverse_product % m
        inverse_product = inverse_product * (at - roots[i]) % m
    return result


@dataclass(frozen=True)
class PublicSetup:
    """Authenticated-original fixed/sigma evaluations, not secret advice."""
    descriptor: object
    fixed: tuple
    sigma: tuple
    copy_digest: bytes
    original_sha256: str
    key_sha256: str

    @classmethod
    def decode(cls, raw, descriptor, key, expected_sha256):
        """Check exact extent, digest, descriptor, VK, and canonical scalars."""
        d = descriptor
        require(isinstance(raw, bytes) and isinstance(key, bytes), 'original byte inputs')
        columns = d['num_fixed_columns'] + len(d['permutation'])
        require(len(raw) == 44 + len(key) + 32 + columns * d.n * 32,
                'exact public original extent')
        require(len(expected_sha256) == 64 and hashlib.sha256(raw).hexdigest() == expected_sha256,
                'pinned public original digest')
        require(raw[:8] == b'PIPAPK01' and raw[8:40] == d.digest,
                'original descriptor binding')
        require(int.from_bytes(raw[40:44], 'little') == len(key) and raw[44:44+len(key)] == key,
                'original key binding')
        offset = 44 + len(key)
        copy_digest = raw[offset:offset+32]
        offset += 32
        tables = []
        for _ in range(columns):
            column = tuple(int.from_bytes(raw[i:i+32], 'little')
                           for i in range(offset, offset + 32*d.n, 32))
            require(all(value < d.curve.scalar for value in column), 'original canonical scalar')
            tables.append(column)
            offset += 32*d.n
        count = d['num_fixed_columns']
        return cls(d, tuple(tables[:count]), tuple(tables[count:]), copy_digest,
                   expected_sha256, hashlib.sha256(key).hexdigest())

    def at(self, point, slots):
        """Evaluate requested fixed/sigma columns at one canonical point."""
        d = self.descriptor
        coefficients = weights(d['k'], d.curve, point)
        values = []
        for family, index in slots:
            require(family in ('fixed', 'sigma'), 'public polynomial family')
            columns = self.fixed if family == 'fixed' else self.sigma
            require(type(index) is int and 0 <= index < len(columns), 'public polynomial index')
            values.append(sum(a*b for a, b in zip(columns[index], coefficients)) % d.curve.scalar)
        return values

    def query_evaluations(self, x):
        """Return fixed queries in descriptor order and all sigmas at x."""
        d, by_rotation = self.descriptor, {}
        for index, rotation in d['fixed_queries']:
            by_rotation.setdefault(rotation, []).append(index)
        answers = {}
        for rotation, indices in by_rotation.items():
            point = x * pow(d.curve.omega(d['k']), rotation % d.n, d.curve.scalar) % d.curve.scalar
            for index, value in zip(indices, self.at(point, [('fixed', i) for i in indices])):
                answers[index, rotation] = value
        fixed = [answers[query] for query in d['fixed_queries']]
        return fixed, self.at(x, [('sigma', i) for i in range(len(d['permutation']))])
