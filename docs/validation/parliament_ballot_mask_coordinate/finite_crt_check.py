#!/usr/bin/env python3
"""Independent finite linear identities for the two pinned ballot CRT tables.

Read-only local mathematical check, not compiled-source or security qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

SOURCES = [
    'crates/iroha_zkp_vole/src/crt/generated/faest_256f_tables.rs',
    'crates/iroha_zkp_vole/src/crt/generated/faest_256s_tables.rs',
    'crates/iroha_zkp_vole/src/crt/generated.rs',
    'crates/iroha_zkp_vole/src/crt/tables.rs',
    'crates/iroha_zkp_vole/src/crt/matrix.rs',
    'crates/iroha_zkp_vole/src/vole.rs',
    'crates/iroha_zkp_vole/src/vole/bits.rs',
    'crates/iroha_zkp_vole/src/vole/convert.rs',
    'crates/iroha_zkp_vole/src/field.rs',
    'crates/iroha_zkp_vole/src/params.rs',
    'crates/iroha_parliament_ballot_proof/src/profile.rs',
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def words(text, name):
    match = re.search(r'pub static ' + name + r': \[u(?:16|64); (\d+)\] = \[(.*?)\];', text, re.S)
    assert match, name
    values = [int(value.replace('_', ''), 16) for value in re.findall(r'0x[0-9a-f_]+', match[2])]
    assert len(values) == int(match[1]), name
    return values


def matrix_columns(text, name, height, width):
    values = words(text, name)
    stride = (width + 63) // 64
    assert len(values) == height * stride
    rows = [sum(value << (64 * j) for j, value in enumerate(values[i:i + stride]))
            for i in range(0, len(values), stride)]
    assert all(row >> width == 0 for row in rows)
    return [sum(((row >> column) & 1) << i for i, row in enumerate(rows))
            for column in range(width)]


def apply(columns, bits):
    result = 0
    while bits:
        lowest = bits & -bits
        result ^= columns[lowest.bit_length() - 1]
        bits ^= lowest
    return result


def polynomial_mul(left, right):
    result = 0
    while right:
        if right & 1:
            result ^= left
        left <<= 1
        right >>= 1
    return result


def polynomial_rem(value, modulus):
    while value.bit_length() >= modulus.bit_length():
        value ^= modulus << (value.bit_length() - modulus.bit_length())
    return value


def rank(columns):
    pivots = {}
    for column in columns:
        while column:
            top = column.bit_length() - 1
            if top not in pivots:
                pivots[top] = column
                break
            column ^= pivots[top]
    return len(pivots)


def basis_equal(wc, wt, wg, fc, gc, moduli, a, b):
    """Direct polynomial evaluation, independent of the full check's x-step loop."""
    offset = 0
    for modulus in moduli:
        degree = modulus.bit_length() - 1
        if offset <= b < offset + degree:
            residue = polynomial_rem(1 << (a + b - offset), modulus) << offset
            observed = apply(wt, residue) ^ apply(wg, fc[a] & gc[b])
            expected = polynomial_rem(polynomial_mul(1 << a, wc[b]), (1 << 256) | 0x425)
            return observed == expected
        offset += degree
    raise AssertionError('basis outside actual tree residues')


def self_validation():
    """Asymmetric orientation, cross-word packing and elementary arithmetic controls."""
    narrow = 'pub static TOY: [u64; 2] = [0x5, 0x6];'
    assert matrix_columns(narrow, 'TOY', 2, 3) == [1, 2, 3]
    assert apply(matrix_columns(narrow, 'TOY', 2, 3), 3) == 3
    wide = 'pub static TOY: [u64; 4] = [0x1, 0x1, 0x2, 0x0];'
    columns = matrix_columns(wide, 'TOY', 2, 65)
    assert columns[0] == 1 and columns[1] == 2 and columns[64] == 1
    assert all(columns[i] == 0 for i in range(2, 64))
    assert apply(columns, (1 << 64) | 2) == 3
    assert rank([1, 2, 4]) == 3 and rank([1, 2, 3]) == 2
    assert rank([3, 5, 6]) == 2 and rank([0, 0]) == 0
    assert polynomial_mul(3, 3) == 5 and polynomial_rem(8, 7) == 1
    assert polynomial_rem(polynomial_mul(1 << 255, 2), (1 << 256) | 0x425) == 0x425
    return ['asymmetric two-by-three matrix orientation', '65-bit little-endian word boundary',
            'independent and dependent rank controls', 'GF(2) product and remainder examples',
            'source GF(2^256) reduction taps']


def check(root, profile, expected):
    path = root / f'crates/iroha_zkp_vole/src/crt/generated/faest_{profile}_tables.rs'
    text = path.read_text()
    n = int(re.search(r'N_DELTA: u32 = (\d+)', text)[1])
    g = int(re.search(r'N_MULT: u32 = (\d+)', text)[1])
    w = int(re.search(r'W_GRIND: u32 = (\d+)', text)[1])
    assert (n, g, w) == expected and n + w == 256
    wc = matrix_columns(text, 'W_CRT', 256, n)
    wt = matrix_columns(text, 'W_TREE', 256, n)
    wg = matrix_columns(text, 'W_GATE', 256, g)
    fc = matrix_columns(text, 'F', g, 256)
    gc = matrix_columns(text, 'G', g, n)
    moduli = words(text, 'TREE_MODULI')
    mt = sum(value << (64 * i) for i, value in enumerate(words(text, 'M_TREE')))
    product = 1
    for modulus in moduli:
        product = polynomial_mul(product, modulus)
    assert product == mt and mt.bit_length() - 1 == n
    assert all(column >> n == 0 for column in wc)
    high = [mt << j for j in range(w)]
    assert max(column.bit_length() - 1 for column in high) == 255
    assert rank(wc) == n and rank(high) == w and rank(wc + high) == 256
    offset = residue_checks = bilinear_checks = 0
    for instance, modulus in enumerate(moduli):
        degree = modulus.bit_length() - 1
        powers = [1]
        for _ in range(255 + degree):
            following = powers[-1] << 1
            if following >> degree:
                following ^= modulus
            powers.append(following)
        for bit in range(degree):
            b = offset + bit
            for other, other_modulus in enumerate(moduli):
                assert polynomial_rem(wc[b], other_modulus) == ((1 << bit) if instance == other else 0)
                residue_checks += 1
            expected_product = wc[b]
            for a in range(256):
                observed = apply(wt, powers[a + bit] << offset) ^ apply(wg, fc[a] & gc[b])
                assert observed == expected_product, (profile, a, b)
                expected_product <<= 1
                if expected_product >> 256:
                    expected_product ^= (1 << 256) | 0x425
                bilinear_checks += 1
        offset += degree
    assert offset == n
    negative_controls = []
    for name in ('W_CRT', 'W_TREE', 'W_GATE'):
        changed_wc, changed_wt, changed_wg = wc.copy(), wt.copy(), wg.copy()
        if name == 'W_CRT':
            changed_wc[0] ^= 1
            a = b = 0
        elif name == 'W_TREE':
            changed_wt[0] ^= 1
            a = b = 0
        else:
            # Flip output row zero at gate column zero. Select actual nonzero
            # entries of that gate's F/G forms to ensure the mutated bit is used.
            changed_wg[0] ^= 1
            a = next(i for i, column in enumerate(fc) if column & 1)
            b = next(i for i, column in enumerate(gc) if column & 1)
        assert basis_equal(wc, wt, wg, fc, gc, moduli, a, b)
        assert not basis_equal(changed_wc, changed_wt, changed_wg, fc, gc, moduli, a, b)
        negative_controls.append({'matrix': name, 'source_row': 0, 'source_column': 0,
                                  'flipped_bit': 0, 'failing_input_basis': [a, b]})
    return {
        'profile': profile,
        'source_sha256': digest(path),
        'n_delta': n, 'w_grind': w, 'n_mult': g,
        'low_rank': rank(wc), 'high_rank': rank(high), 'joint_rank': rank(wc + high),
        'M_TREE_degree': n, 'max_high_degree': 255,
        'CRT_unit_residue_checks': residue_checks,
        'bilinear_basis_pairs': bilinear_checks,
        'single_actual_table_bit_mutations_rejected': negative_controls,
    }


def main():
    if not __debug__:
        raise RuntimeError('Run this assertion-based finite checker without Python -O or -OO.')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True, help='Explicit repository checkout to inspect')
    root = parser.parse_args().root.resolve()
    before = {name: digest(root / name) for name in SOURCES}
    controls = self_validation()
    rows = [check(root, '256f', (248, 704, 8)), check(root, '256s', (250, 696, 6))]
    after = {name: digest(root / name) for name in SOURCES}
    assert before == after
    print(json.dumps({
        'schema': 'parliament-crt-mask-independent-finite-review-v1',
        'root': str(root),
        'rows': rows,
        'source_sha256': before,
        'source_stable': True,
        'self_validation': controls,
        'self_validation_scope': 'Finite selected sanity and real-table mutation controls, not formal verification of this Python checker.',
        'identity': 'W_TREE*tree_residues(a*beta) XOR W_GATE*((F*a)&(G*beta)) == a*(W_CRT*beta)',
        'field_polynomial': 'x^256+x^10+x^5+x^2+1',
        'identity_scope': 'Both sides bilinear over GF(2); all 256*n_delta standard-basis pairs checked per profile.',
        'compiled_source_execution_proved': False,
        'ideal_entry_proved': False,
        'independent_cryptographic_review': False,
        'profile_qualified': False,
    }, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
