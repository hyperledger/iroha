"""Generic known-log public-prefix simulator using unchanged fixed RP57.

No transcript or permutation is programmed. This tests the final algebra under
an explicitly different setup authority, not the current pinned setup or ZK.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from .custody import checked_sources, require, write_new, save
from .case import draw, uint


@dataclass(frozen=True)
class LoggedPoint:
    """Point together with its scalar representation relative to the admitted base."""
    point: tuple
    scalar: int


def rank_collapsed(rounds, at, modulus):
    """Exact condition ell_u|K_at=0, with challenge order unchanged."""
    require(bool(rounds) and all(type(u) is int and 0 < u < modulus for u in rounds),
            'nonzero canonical rounds')
    require(type(at) is int and 0 <= at < modulus, 'canonical opening point')
    return all(pow(u, -1, modulus) == pow(at, 1 << (len(rounds)-1-j), modulus)
               for j, u in enumerate(rounds))


def folded_coefficient(coefficients, rounds, modulus):
    """Independent direct coefficient recurrence, used by the rank control."""
    require(len(coefficients) == 1 << len(rounds), 'fold coefficient length')
    values = list(coefficients)
    for challenge in rounds:
        require(0 < challenge < modulus, 'fold coefficient challenge')
        half = len(values)//2
        inv = pow(challenge, -1, modulus)
        values = [(values[i]+inv*values[i+half]) % modulus for i in range(half)]
    return values[0]


def sample_budget(case):
    """Descriptor-specific simulated draws, distinct from native witness RNG.

    Each fresh point or random evaluation consumes one bounded scalar sample.
    Every such sample is serialized as a 32-byte proof message; public-only
    group values, fixed/sigma evaluations, final f and G consume no sample.
    """
    d = case.descriptor
    require(1 <= d['k'] <= 16 and d['transcript'] == 2 and
            d['instance_mode'] == 1 and d['proof_suffix'] == 1, 'direct PIPA-R profile')
    _, _, slots, sets, membership = case.verifier.opening_shape(d)
    masked = sum(any(slot[0] not in ('fixed', 'sigma')
                     for slot in slots if membership[slot] == index)
                 for index in range(len(sets)))
    nz, nl = d.permutation_sets, len(d['lookups'])
    fresh_points = d['num_advice_columns']+3*nl+nz+d['quotient_pieces']+3+2*d['k']
    evaluations = len(d['advice_queries'])+1+max(3*nz-1,0)+5*nl+masked
    samples = fresh_points+evaluations+1  # final c is zero on collapsed rank
    point_count = d['num_advice_columns']+3*nl+nz+d['degree']+2+2*d['k']+1
    scalar_count = (len(d['advice_queries'])+len(d['fixed_queries'])+1+
                    len(d['permutation'])+max(3*nz-1,0)+5*nl+len(sets)+2)
    proof_bytes = 32*(point_count+scalar_count)
    require(proof_bytes <= 10000 and samples <= point_count+scalar_count,
            'bounded simulated proof and sample inventory')
    return {'fresh_point_samples':fresh_points, 'evaluation_samples':evaluations,
            'masked_groups':masked, 'final_coefficient_samples_max':1,
            'scalar_samples_max':samples, 'source_calls_max':128*samples,
            'expected_proof_bytes':proof_bytes, 'native_polynomial_draws_counted':False}


def simulate(case, instances, coins, *, allow_large=False):
    """Emit one finite-attempt proof and run the full private reference verifier.

    The caller supplies one explicit bit source; no default seed or per-call
    reseeding exists. The public setup supplies every fixed/sigma polynomial.
    No witness is supplied.
    Point identity, zero IPA challenge and prefix denominator/xi exceptions stop
    this attempt; no favorable whole-proof retry is performed.
    """
    checked_sources()
    require(type(allow_large) is bool, 'explicit large flag')
    require(case.descriptor['k'] <= 6 or allow_large, 'large simulation requires opt-in')
    budget = sample_budget(case)
    d, verifier, params = case.descriptor, case.verifier, case.params
    curve, m = d.curve, d.curve.scalar
    require(1 <= d['k'] <= 16 and d['transcript'] == 2 and
            d['instance_mode'] == 1 and d['proof_suffix'] == 1, 'direct PIPA-R profile')
    setup = case.public_setup
    require(setup.descriptor.raw == d.raw and
            setup.key_sha256 == hashlib.sha256(case.key).hexdigest() and
            type(case.public_original) is bytes and
            setup.original_sha256 == hashlib.sha256(case.public_original).hexdigest(),
            'public setup binding')
    require(not (case.directory/'proof.bin').exists() and
            not (case.directory/'simulation.json').exists(), 'fresh proof output required')
    d.check_instances(instances)
    rng = coins
    ledger = {}

    class Writer(case.transcript.Transcript):
        """Only write methods added; inherited fixed RP57 squeeze is untouched."""
        def __init__(self):
            super().__init__(curve, 2, b'')
            self.output = bytearray()

        def write_point(self, point, absorb=True):
            require(point[2] != 0, 'native point identity stop')
            self.output.extend(curve.encode(point))
            if absorb:
                self.common_point(point)

        def write_scalar(self, value):
            require(type(value) is int and 0 <= value < m, 'write canonical scalar')
            self.output.extend(uint(value, 32))
            self.common_scalar(value)

    t = Writer()
    rand = lambda: draw(m, rng)

    def retain(label, point, scalar):
        require(label not in ledger, 'duplicate logged point label')
        scalar %= m
        require(curve.equal(point, curve.multiply(case.base, scalar)),
                'derived point/log mismatch: '+label)
        ledger[label] = {'point': curve.encode(point).hex(), 'log': scalar}
        return LoggedPoint(point, scalar)

    def fresh(label):
        scalar = rand()
        require(scalar != 0, 'native point identity stop')
        return retain(label, curve.multiply(case.base, scalar), scalar)

    def total(label, terms):
        terms = list(terms)
        return retain(label, curve.sum((a, p.point) for a, p in terms),
                      sum(a*p.scalar for a, p in terms))

    t.common_native(d.repr(case.key))
    for value in [int.from_bytes(b'pipainst', 'little'), len(instances), *d['instance_lengths']]:
        t.common_native(value)
    for tag, bits in d['instance_types']:
        t.common_native(tag if tag < 2 else 2+bits)
    for column in instances:
        for value in column:
            t.common_scalar(value)
    commitments = {}

    def commit(slot):
        commitments[slot] = fresh('%s/%s' % slot)
        t.write_point(commitments[slot].point)

    nz, nl = d.permutation_sets, len(d['lookups'])
    for i in range(d['num_advice_columns']):
        commit(('advice', i))
    theta = t.squeeze()
    for i in range(nl):
        commit(('input', i)); commit(('table', i))
    beta, gamma = t.squeeze(), t.squeeze()
    for i in range(nz):
        commit(('permutation', i))
    for i in range(nl):
        commit(('lookup', i))
    commit(('random', 0))
    y = t.squeeze()
    h_points = [fresh('h_piece/%d' % i) for i in range(d['quotient_pieces'])]
    for point in h_points:
        t.write_point(point.point)
    x = t.squeeze(); xn = pow(x, d.n, m)
    require(x != 0 and xn != 1, 'prefix evaluation challenge stop')
    fixed, sigma = verifier.key_points(d, case.key)
    commitments['h', 0] = total('h_combined', [(pow(xn, i, m), p) for i, p in enumerate(h_points)])
    for family, points in [('fixed', fixed), ('sigma', sigma)]:
        for i, point in enumerate(points):
            commitments[family, i] = retain('%s/%d' % (family, i), point, case.logs[family][i])
    fixed_evals, sigma_evals = setup.query_evaluations(x)
    instance_evals = [sum(value*verifier.lagrange(d, x, xn, row-rotation)
                         for row, value in enumerate(instances[column])) % m
                      for column, rotation in d['instance_queries']]
    advice_evals, random_eval = [rand() for _ in d['advice_queries']], rand()
    products = [(rand(), rand(), rand() if i < nz-1 else None) for i in range(nz)]
    lookups = [tuple(rand() for _ in range(5)) for _ in range(nl)]
    for value in [*advice_evals, *fixed_evals, random_eval, *sigma_evals]:
        t.write_scalar(value)
    for product in products:
        for value in product:
            if value is not None:
                t.write_scalar(value)
    for lookup in lookups:
        for value in lookup:
            t.write_scalar(value)
    h_eval = verifier.evaluate_constraints(d, fixed_evals, advice_evals, instance_evals,
                                         sigma_evals, products, lookups, theta, beta,
                                         gamma, x, xn, y)
    queries, rotations, slots, sets, membership = verifier.opening_shape(d)
    evaluations = [*advice_evals, *[v for product in products for v in product[:2]],
                   *[products[i][2] for i in reversed(range(nz-1))]]
    for z, zn, a, ap, s in lookups:
        evaluations += [z, a, s, ap, zn]
    evaluations += [*fixed_evals, *sigma_evals, h_eval, random_eval]
    require(len(queries) == len(evaluations), 'exact query inventory')
    points = [x*pow(curve.omega(d['k']), rotation % d.n, m) % m for rotation in rotations]
    individual = {(slot, rotations.index(rot)): ev for (slot, rot), ev in zip(queries, evaluations)}
    x1, x2 = t.squeeze(), t.squeeze()
    require(x1 != 0, 'prefix grouping challenge stop')
    qprime = fresh('qprime'); t.write_point(qprime.point)
    x3 = t.squeeze()
    require(x3 not in points and pow(x3, d.n, m) != 1, 'prefix opening challenge stop')
    qt, public_only_sets = [], []
    for i in range(len(sets)):
        members = [slot for slot in slots if membership[slot] == i]
        if all(slot[0] in ('fixed', 'sigma') for slot in members):
            public_only_sets.append(i)
            value = 0
            for public_value in setup.at(x3, members):
                value = (value*x1+public_value) % m
            qt.append(value)
        else:
            require(any(slot[0] in ('advice', 'input', 'table', 'permutation', 'lookup', 'random')
                        for slot in members), 'masked opening set')
            qt.append(rand())
    for value in qt:
        t.write_scalar(value)
    x4 = t.squeeze()
    group_terms = [[] for _ in sets]
    group_evals = [[0]*len(ps) for ps in sets]
    powers = [1]*len(sets)
    for slot in reversed(slots):
        group, power = membership[slot], powers[membership[slot]]
        group_terms[group].append((power, commitments[slot]))
        group_evals[group] = [(old+power*individual[(slot, p)]) % m
                              for old, p in zip(group_evals[group], sets[group])]
        powers[group] = power*x1 % m
    group_points = [total('opening_group/%d' % i, terms) for i, terms in enumerate(group_terms)]
    msm_eval = 0
    for group, indices in enumerate(sets):
        ps = [points[i] for i in indices]
        denominator = 1
        for point in ps:
            denominator = denominator*(x3-point) % m
        remainder = verifier.interpolate(ps, group_evals[group], x3, m)
        msm_eval = (msm_eval*x2 + (qt[group]-remainder)*pow(denominator, -1, m)) % m
    terms = [(pow(x4, len(sets), m), qprime)]
    value = pow(x4, len(sets), m)*msm_eval % m
    for group, point in enumerate(group_points):
        weight = pow(x4, len(sets)-1-group, m)
        terms.append((weight, point))
        value = (value+weight*qt[group]) % m
    opening = total('opening', terms)
    cs = fresh('S'); t.write_point(cs.point)
    xi, zeta = t.squeeze(), t.squeeze()
    require(xi != 0, 'prefix masking challenge stop')
    g0 = retain('ipa_g0', params.g[0], case.logs['g'][0])
    ipa_terms = [(1, opening), (-value, g0), (xi, cs)]
    rounds = []
    for j in range(d['k']):
        # Both points are sampled before the ordinary fixed-Poseidon challenge.
        left, right = fresh('L/%d' % j), fresh('R/%d' % j)
        t.write_point(left.point); t.write_point(right.point)
        challenge = t.squeeze()
        require(challenge != 0, 'native zero IPA challenge stop')
        rounds.append(challenge)
        ipa_terms += [(pow(challenge, -1, m), left), (challenge, right)]
    lhs = total('ipa_lhs', ipa_terms)
    weights = [1]
    for challenge in rounds:
        weights = [v for weight in weights for v in (weight, weight*challenge % m)]
    generator = retain('folded_G', curve.sum(zip(weights, params.g)),
                       sum(weight*log for weight, log in zip(weights, case.logs['g'])))
    require(generator.point[2] != 0, 'native folded generator identity stop')
    b, power = 1, x3
    for challenge in reversed(rounds):
        b = b*(1+challenge*power) % m
        power = power*power % m
    collapsed = rank_collapsed(rounds, x3, m)
    c = 0 if collapsed else rand()
    f = ((lhs.scalar - c*generator.scalar - c*b*zeta*case.logs['u']) *
         pow(case.logs['w'], -1, m)) % m
    t.write_scalar(c); t.write_scalar(f); t.write_point(generator.point, absorb=False)
    proof = bytes(t.output)
    args = dict(descriptor=d.raw, version=2, key=case.key, parameter_bytes=case.raw_params,
                instances=instances, proof=proof)
    # Preserve the constructed proof even when complete verification fails.
    write_new(case.directory/'proof.bin', proof)
    require(len(proof) == budget['expected_proof_bytes'], 'exact simulated proof extent')
    # No verifier symbol, Transcript, Sponge, decision or constant is replaced.
    result = verifier.verify(**args)
    require(result.rounds == tuple(rounds) and result.challenges == tuple(t.challenges),
            'ordinary fixed-Poseidon transcript replay')
    require(curve.equal(result.generator, generator.point), 'complete generator replay')
    record = {'scope': 'Historical public relation under chosen outer setup only; no C12/current-parameter claim',
              'proof_bytes': len(proof), 'simulated_draw_budget': budget,
              'contradictory': getattr(case, 'contradictory', False),
              'source_descriptor_sha256': case.source_descriptor_sha256,
              'public_only_sets': public_only_sets,
              'point_set_evaluations': qt, 'grouping_challenge': x1,
              'public_original_sha256': setup.original_sha256,
              'proof_sha256': hashlib.sha256(proof).hexdigest(), 'fixed_poseidon': True,
              'oracle_programs': 0, 'rounds': rounds, 'challenges': list(t.challenges),
              'opening_point': x3, 'rank_collapsed': collapsed, 'c': c, 'f': f,
              'opening_sets': [list(v) for v in sets], 'derived_logs': ledger,
              'descriptor_sha256': hashlib.sha256(d.raw).hexdigest(),
              'parameter_sha256': hashlib.sha256(case.raw_params).hexdigest()}
    save(case.directory/'simulation.json', record)
    return args, result, record
