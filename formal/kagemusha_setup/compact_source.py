"""Small explicit-source reconstruction for the current compact original format.

The supplied rows are mathematical inputs, not a claim to have run the installed
native circuit. This model never mints native source authority or consults the
compiled source registry. It demonstrates what public data a setup simulator
still needs after the dense artifact transport has been removed.
"""
import hashlib

from .custody import require
from .public_setup import PublicSetup


def packed_selectors(selectors, rows):
    """Canonical low-bit-first selector stream, matching native expanded hashing."""
    require(type(rows) is int and 1 <= rows <= 64, 'small selector rows')
    require(type(selectors) is tuple and len(selectors) <= 256, 'selector columns')
    packed = []
    for column in selectors:
        require(type(column) is tuple and len(column) == rows and
                all(type(value) is bool for value in column), 'selector activations')
        packed.append(bytes(sum(int(value) << bit for bit, value in enumerate(column[i:i+8]))
                            for i in range(0, rows, 8)))
    return tuple(packed)


def fingerprint(descriptor, copy_digest, selectors, fixed, sigma):
    """Hash exact explicit public rows using the current native SourceHasher frame.

    Fixed/sigma values must already be finalized circuit tables. In particular,
    this function does not infer a copy permutation from the declared digest.
    """
    d = descriptor
    require(type(d['k']) is int and 1 <= d['k'] <= 6 and d.n == 1 << d['k'],
            'small source domain')
    require(type(d.raw) is bytes and type(copy_digest) is bytes and len(copy_digest) == 32,
            'source framing inputs')
    require(type(fixed) is tuple and type(sigma) is tuple and
            len(fixed) == d['num_fixed_columns'] and len(sigma) == len(d['permutation']),
            'source column counts')
    require(len(fixed) + len(sigma) <= 256, 'bounded source columns')
    for column in (*fixed, *sigma):
        require(type(column) is tuple and len(column) == d.n and
                all(type(v) is int and 0 <= v < d.curve.scalar for v in column),
                'canonical source column')
    packed = packed_selectors(selectors, d.n)
    require(len(packed) == (len(d['selectors'][2]) if d['selectors'][0] else 0),
            'source selector count')
    hash_ = hashlib.sha256(b'iroha:pipa:source-lookup:v1\0')
    hash_.update(len(d.raw).to_bytes(8, 'little'))
    hash_.update(d.raw)
    hash_.update(copy_digest)
    for count in (len(fixed), len(sigma), d.n, len(packed)):
        hash_.update(count.to_bytes(8, 'little'))
    for bitmap in packed:
        hash_.update(d.n.to_bytes(8, 'little'))
        hash_.update(bitmap)
    for column in (*fixed, *sigma):
        for value in column:
            hash_.update(value.to_bytes(32, 'little'))
    return hash_.digest()


def reconstruct(raw, descriptor, key, expected_sha256, *, copy_digest,
                selectors, fixed, sigma, parameters, key_points):
    """Bind supplied public rows to a current compact original and every VK point.

    Parameters and the descriptor are trusted decoded inputs of this diagnostic.
    The unchanged reference key reader supplies canonical point/selector checks.
    This models the algebraic suffix of strict source admission; native synthesis,
    source provenance, row usability and circuit completeness remain premises.
    """
    d = descriptor
    source_digest = fingerprint(d, copy_digest, selectors, fixed, sigma)
    require(type(raw) is bytes and type(key) is bytes and len(raw) == 108 + len(key),
            'compact original extent')
    require(type(expected_sha256) is str and len(expected_sha256) == 64 and
            all(c in '0123456789abcdef' for c in expected_sha256) and
            hashlib.sha256(raw).hexdigest() == expected_sha256, 'compact original digest')
    require(raw[:8] == b'PIPACPK1' and raw[8:40] == d.digest and
            int.from_bytes(raw[40:44], 'little') == len(key) and
            raw[44:44+len(key)] == key, 'compact original binding')
    require(raw[44+len(key):76+len(key)] == copy_digest and
            raw[76+len(key):] == source_digest, 'compact source preimage')
    require(parameters.k == d['k'] and parameters.digest == d['params_digest'] and
            parameters.curve.name == d.curve.name and len(parameters.lagrange) == d.n,
            'compact parameter binding')
    fixed_points, sigma_points = key_points(d, key)
    require(len(fixed_points) == len(fixed) and len(sigma_points) == len(sigma),
            'compact commitment counts')
    suffix = 10 + 32 * (len(fixed) + len(sigma))
    require(key[suffix:] == b''.join(packed_selectors(selectors, d.n)),
            'compact selector originals')
    for column, expected in zip((*fixed, *sigma), (*fixed_points, *sigma_points)):
        actual = d.curve.add(d.curve.sum(zip(column, parameters.lagrange)), parameters.w)
        require(d.curve.equal(actual, expected), 'compact public commitment')
    return PublicSetup(d, fixed, sigma, copy_digest, expected_sha256,
                       hashlib.sha256(key).hexdigest())
