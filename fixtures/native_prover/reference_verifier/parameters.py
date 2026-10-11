"""Exact pinned public parameter admission and the independent generator decision."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from . import require
from .curve import Curve
from .transcript import KATS


@dataclass(frozen=True)
class Parameters:
    """A public immutable pinned parameter set, including the Lagrange basis."""
    curve: Curve
    k: int
    g: tuple
    lagrange: tuple
    w: tuple
    u: tuple
    digest: bytes

    @classmethod
    def decode(cls, raw: bytes, curve: Curve, k: int):
        """Require the exact existing compiled-table digest before using any point."""
        require(type(k) is int and 1 <= k <= 10, 'reference parameter exponent')
        pinned = [entry for entry in KATS['params_ipa'][curve.name] if entry['k'] == k]
        require(len(pinned) == 1, 'no pinned parameter authority for this exponent')
        require(isinstance(raw, bytes) and len(raw) == 4 + 64 * (1 << k) + 64 and
                int.from_bytes(raw[:4], 'little') == k, 'parameter framing')
        digest = hashlib.sha256(raw).digest()
        require(digest.hex() == pinned[0]['sha256'], 'unpinned parameters')
        points = tuple(curve.decode(raw[i:i + 32]) for i in range(4, len(raw), 32))
        n = 1 << k
        return cls(curve, k, points[:n], points[n:2*n], points[-2], points[-1], digest)


def _decide(params: Parameters, encoded_point: bytes, challenges):
    """Enforce G = <s(u),g>; a succinct equation alone never accepts a proof."""
    curve = params.curve
    require(isinstance(encoded_point, bytes), 'encoded generator claim required')
    point = curve.decode(encoded_point)
    require(isinstance(challenges, (list, tuple)) and len(challenges) == params.k and
            all(type(u) is int and 0 < u < curve.scalar for u in challenges),
            'generator claim challenges')
    # Each next challenge occupies the next (descending) generator-index bit.
    weights = [1]
    for challenge in challenges:
        weights = [value for weight in weights for value in (weight, weight*challenge % curve.scalar)]
    expected = curve.sum(zip(weights, params.g))
    require(curve.equal(expected, point), 'generator decision')
    return expected


def decide(parameter_bytes: bytes, curve_tag: int, k: int, encoded_point: bytes, challenges):
    """Admit pinned parameter bytes and completely decide one encoded claim.

    No caller-created Python point or parameter object is an authority boundary.
    This does not decode AccumulatorV1 or implement batch acceptance.
    """
    params = Parameters.decode(parameter_bytes, Curve(curve_tag), k)
    return _decide(params, encoded_point, challenges)


def seed_parameters_k6(curve: Curve) -> bytes:
    """Reconstruct k6 bytes independently from captured g/W/U and a group IFFT.

    This is a test utility. Its output still passes the ordinary pinned digest
    check; it cannot supply new verifier parameter authority.
    """
    source = KATS['generators'][curve.name]
    bases = [curve.decode(bytes.fromhex(point)) for point in source['g']]
    require(len(bases) == 64, 'captured generator count')
    values = list(bases)
    for i in range(64):
        j = int(f'{i:06b}'[::-1], 2)
        if i < j:
            values[i], values[j] = values[j], values[i]
    root = pow(curve.omega(6), -1, curve.scalar)
    width = 2
    while width <= 64:
        step = pow(root, 64 // width, curve.scalar)
        for start in range(0, 64, width):
            power = 1
            for offset in range(width // 2):
                left = values[start + offset]
                right = curve.multiply(values[start + offset + width // 2], power)
                values[start + offset] = curve.add(left, right)
                values[start + offset + width // 2] = curve.add(left, curve.multiply(right, -1))
                power = power * step % curve.scalar
        width *= 2
    scale = pow(64, -1, curve.scalar)
    lagrange = [curve.multiply(point, scale) for point in values]
    return (6).to_bytes(4, 'little') + b''.join(curve.encode(p) for p in bases + lagrange) + \
        bytes.fromhex(source['w']) + bytes.fromhex(source['u'])
