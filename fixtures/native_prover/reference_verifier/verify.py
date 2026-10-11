"""Independent full PLONK/IPA verifier from PIPA §2 and §7–§11.

The evaluator uses integer field arithmetic, explicit interpolation and
independent point addition. It imports no native proof implementation. Its
public verifier returns only after the complete generator decision succeeds.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import require
from .codec import Cursor
from .curve import IDENTITY, inverse
from .descriptor import Descriptor
from .parameters import Parameters, _decide
from .transcript import Transcript


@dataclass(frozen=True)
class Verified:
    """Observed public challenges and a generator already independently decided."""
    descriptor_digest: bytes
    challenges: tuple[int, ...]
    generator: tuple
    rounds: tuple[int, ...]


def key_points(d: Descriptor, raw: bytes):
    """Decode exact processed VK bytes and reproduce its selector metadata."""
    r = Cursor(raw)
    require(r.integer(1) == 2 and r.integer(4) == d['k'], 'key version/domain')
    compress = r.integer(1)
    require(compress == d['selectors'][0], 'key selector compression')
    count = r.integer(4)
    require(count == d['num_fixed_columns'], 'key fixed count')
    fixed = [d.curve.decode(r.read(32)) for _ in range(count)]
    sigmas = [d.curve.decode(r.read(32)) for _ in d['permutation']]
    if compress:
        bitmaps = [r.read((d.n + 7) // 8) for _ in d['selectors'][2]]
        patterns = [{i for i in range(d.n) if bitmap[i // 8] & (1 << (i % 8))}
                    for bitmap in bitmaps]
        degrees = [degree for degree, _, _ in d['selectors'][2]]
        groups = [[i] for i, degree in enumerate(degrees) if degree == 0]
        assigned = {i for group in groups for i in group}
        for i, degree in enumerate(degrees):
            if i in assigned:
                continue
            members = [i]
            assigned.add(i)
            largest = degree - 1
            for j in range(i + 1, len(degrees)):
                if largest + len(members) == d['degree']:
                    break
                if j in assigned or any(patterns[j] & patterns[m] for m in members):
                    continue
                if max(largest, degrees[j] - 1) + len(members) + 1 > d['degree']:
                    continue
                members.append(j)
                assigned.add(j)
                largest = max(largest, degrees[j] - 1)
            groups.append(members)
        reconstructed = [None] * len(degrees)
        for combination, members in enumerate(groups):
            for root, member in enumerate(members, 1):
                reconstructed[member] = (degrees[member], combination, root)
        require(reconstructed == d['selectors'][2], 'selector compression reconstruction')
    r.finish()
    return fixed, sigmas


def opening_shape(d: Descriptor):
    """Static slot/rotation list and point sets; commitment values play no role."""
    queries = []
    if d['instance_mode'] == 0:
        queries += [(('instance', index), rotation) for index, rotation in d['instance_queries']]
    queries += [(('advice', index), rotation) for index, rotation in d['advice_queries']]
    nz = d.permutation_sets
    for i in range(nz):
        queries += [(('permutation', i), 0), (('permutation', i), 1)]
    queries += [(('permutation', i), -(d['blinding_factors'] + 1)) for i in reversed(range(nz - 1))]
    for i in range(len(d['lookups'])):
        queries += [(('lookup', i), 0), (('input', i), 0), (('table', i), 0),
                    (('input', i), -1), (('lookup', i), 1)]
    queries += [(('fixed', index), rotation) for index, rotation in d['fixed_queries']]
    queries += [(('sigma', i), 0) for i in range(len(d['permutation']))]
    queries += [(('h', 0), 0), (('random', 0), 0)]
    rotations, slots = [], {}
    for slot, rotation in queries:
        if rotation not in rotations:
            rotations.append(rotation)
        point = rotations.index(rotation)
        if slot not in slots:
            slots[slot] = []
        if point not in slots[slot]:
            slots[slot].append(point)
    sets = []
    membership = {}
    for slot, indices in slots.items():
        indices = tuple(sorted(indices))
        if indices not in sets:
            sets.append(indices)
        membership[slot] = sets.index(indices)
    return queries, rotations, list(slots), sets, membership


def lagrange(d, x, xn, row):
    """One domain Lagrange polynomial at the sampled non-domain point."""
    m = d.curve.scalar
    root = pow(d.curve.omega(d['k']), row % d.n, m)
    return root * (xn - 1) * inverse(d.n * (x - root), m) % m


def evaluate_constraints(d, fixed, advice, instances, sigma, products, lookups,
                         theta, beta, gamma, x, xn, y):
    """Gate, permutation and lookup constraints in the exact normative order."""
    m = d.curve.scalar
    first = lagrange(d, x, xn, 0)
    last = lagrange(d, x, xn, d.usable)
    blind = sum(lagrange(d, x, xn, i) for i in range(d.usable + 1, d.n)) % m
    active = (1 - last - blind) % m
    terms = [d.expression(expr, [fixed, advice, instances]) for gate in d['gates'] for expr in gate]
    if products:
        terms += [first * (1 - products[0][0]), last * (products[-1][0] ** 2 - products[-1][0])]
        terms += [first * (products[i][0] - products[i - 1][2]) for i in range(1, len(products))]
        delta = pow(5, 1 << 32, m)
        columns = d['permutation']
        tables = [(d['advice_queries'], advice), (d['fixed_queries'], fixed),
                  (d['instance_queries'], instances)]
        chunk = d['permutation_chunk_len']
        for i, (current, following, _) in enumerate(products):
            left, right = following, current
            for j in range(i * chunk, min((i + 1) * chunk, len(columns))):
                kind, index = columns[j]
                table, values = tables[kind]
                value = values[table.index((index, 0))]
                left = left * (value + beta * sigma[j] + gamma) % m
                right = right * (value + beta * pow(delta, j, m) * x + gamma) % m
            terms.append(active * (left - right))
    for (input_exprs, table_exprs), (z, zn, a, ap, s) in zip(d['lookups'], lookups):
        def compressed(expressions):
            value = 0
            for expr in expressions:
                value = (value * theta + d.expression(expr, [fixed, advice, instances])) % m
            return value
        source, target = compressed(input_exprs), compressed(table_exprs)
        terms += [first * (1 - z), last * (z*z - z),
                  active * (zn * (a + beta) * (s + gamma) - z * (source + beta) * (target + gamma)),
                  first * (a - s), active * (a - s) * (a - ap)]
    folded = 0
    for term in terms:
        folded = (folded * y + term) % m
    return folded * inverse(xn - 1, m) % m


def interpolate(points, values, at, modulus):
    """Naive Lagrange interpolation, intentionally separate from FFT kernels."""
    value = 0
    for i, (point, evaluation) in enumerate(zip(points, values)):
        numerator, denominator = 1, 1
        for j, other in enumerate(points):
            if i != j:
                numerator = numerator * (at - other) % modulus
                denominator = denominator * (point - other) % modulus
        value = (value + evaluation * numerator * inverse(denominator, modulus)) % modulus
    return value


def _verify(descriptor: bytes, version: int, key: bytes, parameter_bytes: bytes,
            instances, proof: bytes, oracle_repr):
    d = Descriptor.decode(descriptor, version)
    curve, m = d.curve, d.curve.scalar
    params = Parameters.decode(parameter_bytes, curve, d['k'])
    require(params.digest == d['params_digest'], 'descriptor parameter binding')
    fixed_points, sigma_points = key_points(d, key)
    d.check_instances(instances)
    queries, rotations, slots, sets, membership = opening_shape(d)
    nz, nl = d.permutation_sets, len(d['lookups'])
    point_count = d['num_advice_columns'] + 3*nl + nz + d['degree'] + 2 + 2*d['k'] + d['proof_suffix']
    scalar_count = ((len(d['instance_queries']) if d['instance_mode'] == 0 else 0) +
                    len(d['advice_queries']) + len(d['fixed_queries']) + 1 + len(d['permutation']) +
                    max(3*nz - 1, 0) + 5*nl + len(sets) + 2)
    require(len(proof) == 32 * (point_count + scalar_count), 'proof length')
    transcript = Transcript(curve, d['transcript'], proof, oracle=oracle_repr is not None)
    if oracle_repr is not None:
        require(version == 1, 'oracle descriptor profile')
        transcript.common_scalar(oracle_repr)
    else:
        transcript.common_native(d.repr(key))
        for word in [int.from_bytes(b'pipainst', 'little'), len(instances), *d['instance_lengths']]:
            transcript.common_native(word)
        if version == 2:
            for tag, bits in d['instance_types']:
                transcript.common_native(tag if tag < 2 else 2 + bits)
    commitments = {}
    if d['instance_mode'] == 0:
        for i, column in enumerate(instances):
            point = curve.add(curve.sum(zip(column, params.lagrange)), params.w)
            transcript.common_point(point)
            commitments[('instance', i)] = point
    else:
        for column in instances:
            for scalar in column:
                transcript.common_scalar(scalar)
    for i in range(d['num_advice_columns']):
        commitments[('advice', i)] = transcript.point()
    theta = transcript.squeeze()
    for i in range(nl):
        commitments[('input', i)], commitments[('table', i)] = transcript.point(), transcript.point()
    beta, gamma = transcript.squeeze(), transcript.squeeze()
    for i in range(nz):
        commitments[('permutation', i)] = transcript.point()
    for i in range(nl):
        commitments[('lookup', i)] = transcript.point()
    commitments[('random', 0)] = transcript.point()
    y = transcript.squeeze()
    h_points = [transcript.point() for _ in range(d['quotient_pieces'])]
    x = transcript.squeeze()
    xn = pow(x, d.n, m)
    require(x != 0 and xn != 1, 'degenerate evaluation challenge')
    commitments[('h', 0)] = curve.sum((pow(xn, i, m), point) for i, point in enumerate(h_points))
    commitments.update({('fixed', i): p for i, p in enumerate(fixed_points)})
    commitments.update({('sigma', i): p for i, p in enumerate(sigma_points)})
    if d['instance_mode'] == 0:
        instance_evals = [transcript.scalar() for _ in d['instance_queries']]
    else:
        instance_evals = [sum(value * lagrange(d, x, xn, row - rotation)
                             for row, value in enumerate(instances[column])) % m
                          for column, rotation in d['instance_queries']]
    advice_evals = [transcript.scalar() for _ in d['advice_queries']]
    fixed_evals = [transcript.scalar() for _ in d['fixed_queries']]
    random_eval = transcript.scalar()
    sigma_evals = [transcript.scalar() for _ in d['permutation']]
    products = [(transcript.scalar(), transcript.scalar(), transcript.scalar() if i < nz - 1 else None)
                for i in range(nz)]
    lookups = [tuple(transcript.scalar() for _ in range(5)) for _ in range(nl)]
    h_eval = evaluate_constraints(d, fixed_evals, advice_evals, instance_evals, sigma_evals,
                                  products, lookups, theta, beta, gamma, x, xn, y)
    evaluations = list(instance_evals) if d['instance_mode'] == 0 else []
    evaluations += advice_evals
    evaluations += [value for product in products for value in product[:2]]
    evaluations += [products[i][2] for i in reversed(range(nz - 1))]
    for z, zn, a, ap, s in lookups:
        evaluations += [z, a, s, ap, zn]
    evaluations += fixed_evals + sigma_evals + [h_eval, random_eval]
    require(len(evaluations) == len(queries), 'opening query count')
    point_values = [x * pow(curve.omega(d['k']), rotation % d.n, m) % m for rotation in rotations]
    individual = {}
    for (slot, rotation), evaluation in zip(queries, evaluations):
        identity = (slot, rotations.index(rotation))
        require(identity not in individual or individual[identity] == evaluation, 'overwritten evaluation')
        individual[identity] = evaluation
    x1, x2 = transcript.squeeze(), transcript.squeeze()
    qprime = transcript.point()
    x3 = transcript.squeeze()
    require(all(x3 != point for point in point_values), 'opening point collision')
    qt = [transcript.scalar() for _ in sets]
    x4 = transcript.squeeze()
    grouped_points = [IDENTITY] * len(sets)
    grouped_evals = [[0] * len(indices) for indices in sets]
    powers = [1] * len(sets)
    for slot in reversed(slots):
        group = membership[slot]
        power = powers[group]
        grouped_points[group] = curve.add(grouped_points[group], curve.multiply(commitments[slot], power))
        for i, point in enumerate(sets[group]):
            grouped_evals[group][i] = (grouped_evals[group][i] + power * individual[(slot, point)]) % m
        powers[group] = power * x1 % m
    msm_eval = 0
    for group, indices in enumerate(sets):
        points = [point_values[i] for i in indices]
        remainder = interpolate(points, grouped_evals[group], x3, m)
        denominator = 1
        for point in points:
            denominator = denominator * (x3 - point) % m
        msm_eval = (msm_eval * x2 + (qt[group] - remainder) * inverse(denominator, m)) % m
    opening = curve.multiply(qprime, pow(x4, len(sets), m))
    value = pow(x4, len(sets), m) * msm_eval % m
    for i, point in enumerate(grouped_points):
        weight = pow(x4, len(sets) - 1 - i, m)
        opening = curve.add(opening, curve.multiply(point, weight))
        value = (value + weight * qt[i]) % m
    cs = transcript.point()
    xi, zeta = transcript.squeeze(), transcript.squeeze()
    terms = [(1, opening), (-value, params.g[0]), (xi, cs)]
    rounds = []
    for _ in range(d['k']):
        left, right = transcript.point(), transcript.point()
        u = transcript.squeeze()
        require(u != 0, 'zero IPA challenge')
        rounds.append(u)
        terms += [(inverse(u, m), left), (u, right)]
    c, f = transcript.scalar(), transcript.scalar()
    suffix = transcript.point(absorb=False) if d['proof_suffix'] else None
    transcript.finish()
    weights = [1]
    for u in rounds:
        weights = [element for weight in weights for element in (weight, weight*u % m)]
    generator = curve.sum(zip(weights, params.g))
    if suffix is not None:
        _decide(params, curve.encode(suffix), rounds)
        generator = suffix
    b = 1
    power = x3
    for u in reversed(rounds):
        b = b * (1 + u * power) % m
        power = power * power % m
    terms += [(-c, generator), (-c*b*zeta, params.u), (-f, params.w)]
    require(curve.sum(terms)[2] == 0, 'IPA group equation')
    return Verified(d.digest, tuple(transcript.challenges), generator, tuple(rounds))


def verify(descriptor: bytes, version: int, key: bytes, parameter_bytes: bytes,
           instances, proof: bytes) -> Verified:
    """Verify an explicit production profile through its complete group decision."""
    return _verify(descriptor, version, key, parameter_bytes, instances, proof, None)


def verify_captured_oracle(descriptor: bytes, key: bytes, parameter_bytes: bytes,
                           instances, proof: bytes, transcript_repr: int) -> Verified:
    """Historical test-only framing, explicit and separate from production admission."""
    require(type(transcript_repr) is int, 'explicit canonical oracle binding')
    return _verify(descriptor, 1, key, parameter_bytes, instances, proof, transcript_repr)
