"""Exhaustive finite-map and exact rational controls for refreshing the target."""
from fractions import Fraction
from itertools import product
import unittest

from . import finite as f


class FreshTarget(unittest.TestCase):
    def test_every_small_map_has_exact_uniform_pair_mass(self):
        for p in range(1,5):
            for r in range(2,6):
                for mapping in product(range(r), repeat=p):
                    counts = f.pair_counts(mapping,r)
                    self.assertEqual(len(counts),p*p)
                    self.assertEqual(set(counts.values()),{1})
                    self.assertEqual(Fraction(sum(counts.values()),9*r*p),Fraction(p,9*r))

    def test_holes_and_unequal_fibers_do_not_need_regularity(self):
        mapping = [0,0,0,1]
        counts = f.pair_counts(mapping,5)
        target_counts = [sum(n for (u,v),n in counts.items()
                             if (mapping[u]+mapping[v]) % 5 == t) for t in range(5)]
        self.assertEqual(target_counts,[9,6,1,0,0])
        self.assertEqual(set(counts.values()),{1})
        self.assertNotEqual(target_counts,[16//5]*5)

    def test_finite_caps_keep_failure_atom_and_equal_pair_mass(self):
        for p,r,m in [(1,5,9),(4,5,9),(9,2,9),(18,2,9)]:
            for j in [0,1,2,4,9]:
                for caps in [(Fraction(0),)*3,(Fraction(1,16),Fraction(1,8),Fraction(1,4)),
                             (Fraction(1),Fraction(0),Fraction(0))]:
                    mass,failure,bound = f.finite_law(p,r,m,j,caps)
                    self.assertEqual(p*p*mass+failure,1)
                    self.assertGreaterEqual(failure,0)
                    self.assertLessEqual(failure,bound)
                    # Include failure in TV against an always-successful uniform pair.
                    tv = (p*p*abs(mass-Fraction(1,p*p))+failure)/2
                    self.assertEqual(tv,failure)

    def test_full_order_base_is_required(self):
        mapping = [0,1,2]
        self.assertEqual(f.pair_counts(mapping,5,generator=2),f.pair_counts(mapping,5))
        with self.assertRaisesRegex(ValueError,'full-order generator'):
            f.pair_counts(mapping,6,generator=2)
        with self.assertRaisesRegex(ValueError,'full-order generator'):
            f.pair_counts(mapping,5,generator=0)

    def test_truncating_inverse_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'complete inverse'):
            f.pair_counts([0]*10,5)
        with self.assertRaisesRegex(ValueError,'canonical map'):
            f.pair_counts([5],5)

