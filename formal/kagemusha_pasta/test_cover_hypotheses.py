"""Small exact-polynomial controls; no native prover or imported external code."""
import unittest
import cover as h


class Covers(unittest.TestCase):
    def test_exact_both_families(self):
        for curve,field in [('pallas','fp'),('vesta','fq')]:
            p,A,B,Z,_ = h.a.constants(curve,field)
            self.assertEqual(h.certify(p,A,B,Z)['model_degrees'],[14,14])

    def test_mutated_model_breaks_identity(self):
        p,A,B,Z,_ = h.a.constants('pallas','fp')
        d = h.build_models(p,A,B,Z)
        bad = d['h1'].copy();bad[0] = (bad[0]+1) % p
        with self.assertRaisesRegex(ValueError,'exact model identity'):
            h.model_identity(p,A,B,d['n1'],d['denominator1'],d['scale1'],bad)

    def test_square_Z_refuses(self):
        p,A,B,_,_ = h.a.constants('vesta','fq')
        with self.assertRaisesRegex(ValueError,'nonexceptional nonsquare Z'):
            h.certify(p,A,B,1)

    def test_repeated_polynomial_not_squarefree(self):
        p,A,B,Z,_ = h.a.constants('pallas','fp')
        d = h.build_models(p,A,B,Z)
        repeated = h.a.power(d['phi'],2,p)
        self.assertNotEqual(h.a.gcd(repeated,h.derivative(repeated),p),[1])


if __name__ == '__main__':
    h.a.require(__debug__,'unoptimized cover-hypothesis controls only')
    unittest.main()
