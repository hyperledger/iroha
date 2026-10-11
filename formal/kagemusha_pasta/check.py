"""Verify source-bound Pasta primes, auxiliary groups and SWU cover arithmetic."""
from pathlib import Path
import hashlib
import json
import sys

import auxiliary
import cover
import primes

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def main():
    primes.require(sys.flags.optimize == 0, 'unoptimized certificate execution only')
    manifest = json.loads((HERE/'source_manifest.json').read_text())
    primes.require(set(manifest) == {'schema','sources','files'}, 'source manifest grammar')
    primes.require(manifest['schema'] == 'kagemusha.pasta.algebra-certificate-sources.v1', 'source manifest schema')
    expected_sources = {f'crates/iroha_pasta/src/{name}.rs' for name in
                        ('curve/hash_to_curve','curve/pallas','curve/vesta','field/fp','field/fq',
                         'field/mod','field/cios')}
    expected_files = {'check.py','primes.py','auxiliary.py','test_certificates.py',
                      'supplied_primes.json','README.md','cover.py','test_cover_hypotheses.py',
                      'REGULARITY.md'}
    primes.require(set(manifest['sources']) == expected_sources, 'exact source inventory')
    primes.require(set(manifest['files']) == expected_files, 'exact certificate inventory')
    for base, rows in ((ROOT,manifest['sources']),(HERE,manifest['files'])):
        for name, digest in rows.items():
            primes.require(hashlib.sha256((base/name).read_bytes()).hexdigest() == digest,
                           'changed pinned file '+name)
    prime_result = primes.verify(json.loads((HERE/'supplied_primes.json').read_text()),
                                 primes.roots_from_source())
    rows = [auxiliary.constants('pallas','fp'),auxiliary.constants('vesta','fq')]
    primes.require([row[0] for row in rows] == [int(n) for n in prime_result['roots']],
                   'same proved base-field moduli')
    certificates = [auxiliary.certify(name, row[0], rows[1-i][0], *row[1:])
                    for i,(name,row) in enumerate(zip(('pallas','vesta'),rows))]
    for certificate in certificates:
        certificate['auxiliary_and_target_order'] = 'r, with p/r primality verified in this execution'
        certificate['rational_point_isomorphism'] = 'degree-three isogeny plus proved prime-order rational groups'
    cover_results = [dict(curve=name, **cover.certify(*row[:4]))
                     for name,row in zip(('pallas','vesta'),rows)]
    print(json.dumps({'primes':prime_result,'auxiliary_certificates':certificates,
                      'cover_hypotheses':cover_results,
                      'cover_arithmetic_verified':True,'character_sum_theorem_executed':False,
                      'primality_proved':True,'regularity_proved':False,'C12_closed':False,
                      'scope':'Exact source primes, groups and cover arithmetic; REGULARITY.md separately applies cited geometric and character-sum theorems. No geometry theorem execution, prover, setup generation or release qualification.'},
                     indent=2,sort_keys=True))


if __name__ == '__main__':
    main()
