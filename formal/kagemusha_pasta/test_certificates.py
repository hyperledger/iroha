"""Small deterministic supplied-certificate controls; no prover/native artifacts."""
from pathlib import Path
import json
import unittest
import primes as verify
import auxiliary as check


class Certificate(unittest.TestCase):
    def setUp(self):
        self.data=json.loads((Path(__file__).parent/'supplied_primes.json').read_text())
        self.roots=verify.roots_from_source()

    def test_exact_supplied_roots(self):
        self.assertTrue(verify.verify(self.data,self.roots)['primality_proved'])

    def test_changed_witness_refuses(self):
        self.data['nodes'][str(self.roots[0])]['witness']='1'
        with self.assertRaises(ValueError):verify.verify(self.data,self.roots)

    def test_missing_factor_refuses(self):
        self.data['nodes'][str(self.roots[0])]['factors'].pop()
        with self.assertRaises(ValueError):verify.verify(self.data,self.roots)

    def test_changed_prime_factor_refuses(self):
        factors=self.data['nodes'][str(self.roots[0])]['factors']
        factors[1]=['341',1]
        with self.assertRaises(ValueError):verify.verify(self.data,self.roots)

    def test_wrong_roots_and_extra_node_refuse(self):
        with self.assertRaises(ValueError):verify.verify(self.data,list(reversed(self.roots)))
        self.data['nodes']['257']={'witness':'3','factors':[['2',8]]}
        with self.assertRaises(ValueError):verify.verify(self.data,self.roots)

    def test_fermat_pseudoprime_fails_lucas_order(self):
        data={'schema':'kagemusha.pasta.supplied-lucas-data.v1',
              'primary_source':'synthetic mathematical rejection control',
              'roots':['341'],
              'nodes':{'341':{'witness':'2','factors':[['2',2],['5',1],['17',1]]}}}
        self.assertEqual(pow(2,340,341),1)
        with self.assertRaisesRegex(ValueError,'Lucas order witness'):
            verify.verify(data,[341])

    def test_composite_fails_fermat_condition(self):
        data={'schema':'kagemusha.pasta.supplied-lucas-data.v1',
              'primary_source':'synthetic mathematical rejection control',
              'roots':['15'],
              'nodes':{'15':{'witness':'2','factors':[['2',1],['7',1]]}}}
        self.assertNotEqual(pow(2,14,15),1)
        with self.assertRaisesRegex(ValueError,'Fermat witness'):
            verify.verify(data,[15])

    def test_leaf_controls(self):
        for n in [2,3,89,463,1709]:self.assertTrue(verify.leaf_prime(n))
        for n in [4,9,341,561,1105,1729]:self.assertFalse(verify.leaf_prime(n))
        for n in [1,400_000_001]:
            with self.assertRaises(ValueError):verify.leaf_prime(n)



class Certificates(unittest.TestCase):
    def test_exact_both_auxiliary_certificates(self):
        rows = [check.constants('pallas','fp'),check.constants('vesta','fq')]
        for i, (name, row) in enumerate(zip(('pallas','vesta'),rows)):
            result = check.certify(name, row[0], rows[1-i][0], *row[1:])
            self.assertEqual(result['x_map_degree'],3)
            self.assertTrue(result['polynomial_identity'])

    def test_mutated_numerator_fails_exact_identity(self):
        for name,field in [('pallas','fp'),('vesta','fq')]:
            p,a,b,z,c = check.constants(name,field)
            changed = c.copy();changed[3] = (changed[3]+1) % p
            with self.assertRaises(ValueError):
                check.algebra(p,a,b,changed)

    def test_constant_degree_and_wrong_order_refuse(self):
        row = check.constants('pallas','fp'); p,a,b,z,c = row
        changed = c.copy();changed[0] = 0
        with self.assertRaises(ValueError):
            check.algebra(p,a,b,changed)
        with self.assertRaises(ValueError):
            check.certify('pallas',p,1,a,b,z,c)

    def test_off_curve_refuses(self):
        p,a,b,z,c = check.constants('pallas','fp')
        with self.assertRaises(ValueError):
            check.point_add((0,0),None,a,b,p)



if __name__ == '__main__':
    verify.require(__debug__, 'unoptimized certificate controls only')
    unittest.main()
