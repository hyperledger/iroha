"""Bounded Lucas certificate verification from supplied primary factor data.

No factoring of large numbers, probabilistic primality, external dependencies,
Lean execution, source-module imports, or cryptographic proof production.
"""
from pathlib import Path
import math
import re

ROOT = Path(__file__).resolve().parents[2]
MAX_LEAF = 400_000_000
MAX_NODES = 32


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value):
    require(type(value) is str and re.fullmatch('[1-9][0-9]{0,77}',value) is not None,
            'bounded canonical positive decimal')
    n = int(value)
    require(n < 2**256, '256bit certificate bound')
    return n


def leaf_prime(n):
    """Deterministic trial division only for explicitly small certificate leaves."""
    require(type(n) is int and 2 <= n <= MAX_LEAF, 'small leaf bound')
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    return all(n % d != 0 for d in range(3, math.isqrt(n)+1, 2))


def roots_from_source():
    out = []
    for field in ('fp','fq'):
        text = (ROOT/f'crates/iroha_pasta/src/field/{field}.rs').read_text()
        values = re.findall(r'const MODULUS_STR: &str = "0x([0-9a-f]+)";',text)
        require(len(values) == 1,'exact source modulus')
        out.append(int(values[0],16))
    return out


def verify(data, expected_roots):
    require(type(data) is dict and set(data) == {'schema','primary_source','roots','nodes'},'certificate grammar')
    require(data['schema'] == 'kagemusha.pasta.supplied-lucas-data.v1','schema')
    require(type(data['roots']) is list and [integer(x) for x in data['roots']] == expected_roots,
            'exact root moduli/order')
    require(type(data['nodes']) is dict and 1 <= len(data['nodes']) <= MAX_NODES,'node bound')
    nodes = {integer(n): row for n,row in data['nodes'].items()}
    proved, active, used_nodes, leaves = set(), set(), set(), set()
    def check(n):
        if n in proved:
            return
        require(n not in active,'certificate cycle')
        if n not in nodes:
            require(leaf_prime(n),'composite leaf')
            leaves.add(n);proved.add(n)
            return
        used_nodes.add(n);active.add(n)
        row = nodes[n]
        require(type(row) is dict and set(row) == {'witness','factors'},'node grammar')
        witness = integer(row['witness'])
        require(1 < witness < n,'nontrivial canonical witness')
        factors = row['factors']
        require(type(factors) is list and 1 <= len(factors) <= 16,'factor bound')
        product = 1;qs = []
        for item in factors:
            require(type(item) is list and len(item) == 2,'factor pair')
            q = integer(item[0]);exponent=item[1]
            require(type(exponent) is int and 1 <= exponent <= 255 and q < n,'descending prime power')
            require(q not in qs,'duplicate factor');qs.append(q)
            require(q.bit_length()*exponent <= 511,'bounded prime power')
            product *= q**exponent
            require(product <= n-1,'partial factor product')
            check(q)
        require(product == n-1,'complete factorization of n-1')
        require(pow(witness,n-1,n) == 1,'Fermat witness')
        for q in qs:
            require(math.gcd(pow(witness,(n-1)//q,n)-1,n) == 1,'Lucas order witness')
        active.remove(n);proved.add(n)
    for n in expected_roots:
        check(n)
    require(used_nodes == set(nodes),'no unselected certificate nodes')
    return {'primality_proved':True,'roots':[str(n) for n in expected_roots],
            'supplied_nodes':len(used_nodes),'small_prime_leaves':sorted(leaves),
            'largest_leaf':max(leaves),'max_trial_divisor':math.isqrt(max(leaves)),
            'method':'Complete supplied n-1 factorizations, recursive Lucas witnesses, bounded exact trial division for small leaves.',
            'factorization_performed':False,'probabilistic_primality_used':False}
