//! The gate-count search that fixes the shape of every multiplication algorithm:
//! `mu(n)` for a full product, `mu_sh(n)` for a short product, and the knapsack
//! that picks the places of a CRT portfolio (FAEST v3.0 Appendix B.3).
//!
//! Every comparison is strict, so the first candidate wins ties; the knapsack visits
//! its groups and its partial solutions in ascending order. These rules decide the
//! order of the gates and therefore the tables.

use std::collections::BTreeMap;

use super::{
    bits::{index, wide},
    error::CrtError,
};
use crate::field::{
    FieldError,
    poly::{MAX_IRREDUCIBLE_DEGREE, is_irreducible},
};

/// The kind of a place of a CRT portfolio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceKind {
    /// The place at infinity: the leading coefficients of the product.
    Infinity,
    /// A power of `x` or of `x + 1`.
    Linear,
    /// A power of an irreducible polynomial of degree at least two.
    Irreducible,
}

/// One place of a CRT portfolio: a modulus the product is evaluated at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    /// Kind of the place.
    pub kind: PlaceKind,
    /// The polynomial as an integer, bit `i` being the coefficient of `x^i`; zero
    /// for the place at infinity.
    pub poly: u32,
    /// Multiplicity of the place.
    pub multiplicity: u32,
}

impl Place {
    /// The place at infinity with the given multiplicity.
    pub const fn infinity(multiplicity: u32) -> Self {
        Self {
            kind: PlaceKind::Infinity,
            poly: 0,
            multiplicity,
        }
    }

    /// A power of the linear polynomial `poly` (`x` is 2 and `x + 1` is 3).
    pub const fn linear(poly: u32, multiplicity: u32) -> Self {
        Self {
            kind: PlaceKind::Linear,
            poly,
            multiplicity,
        }
    }

    /// A power of the irreducible polynomial `poly`.
    pub const fn irreducible(poly: u32, multiplicity: u32) -> Self {
        Self {
            kind: PlaceKind::Irreducible,
            poly,
            multiplicity,
        }
    }
}

/// How the full product of two polynomials of `n` coefficients is computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FullPlan {
    /// One gate, for `n = 1`.
    Base,
    /// Montgomery's 13-gate algorithm, for `n = 5`.
    Mont5,
    /// `outer` blocks of `inner` coefficients, one algorithm nested in the other.
    Split {
        /// Number of blocks.
        outer: usize,
        /// Coefficients per block.
        inner: usize,
    },
    /// Evaluation at the listed places and interpolation.
    Crt(Vec<Place>),
}

/// How the low `n` coefficients of a product are computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortPlan {
    /// One gate, for `n = 1`.
    Base,
    /// The full product.
    Full,
    /// A full product of the low `m` coefficients and two short cross products.
    ShortSplit(usize),
}

/// A candidate of the knapsack: coordinates covered, gates, and the places.
type Choice = (usize, u64, Vec<Place>);

/// Gate count of the `F_4` tower construction for a place of the given degree, or
/// zero if there is none.
pub const fn tower_cost(degree: usize) -> u64 {
    match degree {
        6 => 15,
        8 => 24,
        _ => 0,
    }
}

/// Degree of a non-zero polynomial held in a `u32`; zero for the zero polynomial.
pub fn degree_u32(poly: u32) -> usize {
    index(31u32.saturating_sub(poly.leading_zeros()))
}

/// `left + right` on gate counts.
fn add(left: u64, right: u64) -> Result<u64, CrtError> {
    left.checked_add(right).ok_or(OVERFLOW)
}

/// `left * right` on gate counts.
fn times(left: u64, right: u64) -> Result<u64, CrtError> {
    left.checked_mul(right).ok_or(OVERFLOW)
}

/// The error of a gate count that does not fit 64 bits.
const OVERFLOW: CrtError = CrtError::Construction {
    what: "a gate count overflows",
};

/// Memoised cost search. One value serves one table construction; there is no
/// shared or global state.
#[derive(Debug, Default)]
pub struct CostTable {
    full: BTreeMap<usize, (u64, FullPlan)>,
    short: BTreeMap<usize, (u64, ShortPlan)>,
    irreducibles: BTreeMap<usize, Vec<u32>>,
}

impl CostTable {
    /// Every irreducible polynomial of exactly `degree >= 2` over `GF(2)`, in
    /// ascending integer order.
    pub fn irreducibles_of_degree(&mut self, degree: usize) -> Result<Vec<u32>, CrtError> {
        if let Some(found) = self.irreducibles.get(&degree) {
            return Ok(found.clone());
        }
        let small = u32::try_from(degree).unwrap_or(u32::MAX);
        if !(2..=MAX_IRREDUCIBLE_DEGREE).contains(&small) {
            return Err(CrtError::Field(FieldError::UnsupportedDegree {
                degree: small,
                max: MAX_IRREDUCIBLE_DEGREE,
            }));
        }
        let found: Vec<u32> = ((1u32 << small) | 1..(1u32 << (small + 1)))
            .filter(|poly| is_irreducible(*poly))
            .collect();
        self.irreducibles.insert(degree, found.clone());
        Ok(found)
    }

    /// Gate count and plan of the full product of two polynomials of `size`
    /// coefficients: `mu(size)`.
    pub fn full_cost(&mut self, size: usize) -> Result<(u64, FullPlan), CrtError> {
        if size == 0 {
            return Err(CrtError::Construction {
                what: "a product of zero coefficients",
            });
        }
        if let Some(found) = self.full.get(&size) {
            return Ok(found.clone());
        }
        let best = if size == 1 {
            (1, FullPlan::Base)
        } else {
            let mut best: Option<(u64, FullPlan)> = (size == 5).then_some((13, FullPlan::Mont5));
            for outer in 2..size {
                let inner = size.div_ceil(outer);
                let cost = times(self.full_cost(outer)?.0, self.full_cost(inner)?.0)?;
                if best.as_ref().is_none_or(|(current, _)| cost < *current) {
                    best = Some((cost, FullPlan::Split { outer, inner }));
                }
            }
            let mut pools = BTreeMap::new();
            for degree in 2..size {
                pools.insert(degree, self.irreducibles_of_degree(degree)?);
            }
            if let Some((cost, places)) =
                self.crt_search(2 * size - 1, size - 1, size - 1, &pools)?
                && best.as_ref().is_none_or(|(current, _)| cost < *current)
            {
                best = Some((cost, FullPlan::Crt(places)));
            }
            best.ok_or(CrtError::NoPortfolio {
                target: 2 * size - 1,
            })?
        };
        self.full.insert(size, best.clone());
        Ok(best)
    }

    /// Gate count and plan of the low `size` coefficients of the product of two
    /// polynomials of `size` coefficients: `mu_sh(size)`.
    pub fn short_cost(&mut self, size: usize) -> Result<(u64, ShortPlan), CrtError> {
        if let Some(found) = self.short.get(&size) {
            return Ok(*found);
        }
        let best = if size == 1 {
            (1, ShortPlan::Base)
        } else {
            let mut best = (self.full_cost(size)?.0, ShortPlan::Full);
            for low in size.div_ceil(2)..size {
                let cost = add(
                    self.full_cost(low)?.0,
                    times(2, self.short_cost(size - low)?.0)?,
                )?;
                if cost < best.0 {
                    best = (cost, ShortPlan::ShortSplit(low));
                }
            }
            best
        };
        self.short.insert(size, best);
        Ok(best)
    }

    /// Gate count of one place.
    pub fn place_gate_cost(&mut self, place: Place) -> Result<u64, CrtError> {
        let multiplicity = index(place.multiplicity);
        if place.kind != PlaceKind::Irreducible {
            return Ok(self.short_cost(multiplicity)?.0);
        }
        let degree = degree_u32(place.poly);
        let tower = tower_cost(degree);
        if multiplicity == 1 && tower != 0 {
            return Ok(tower.min(self.full_cost(degree)?.0));
        }
        Ok(self.full_cost(degree * multiplicity)?.0)
    }

    /// The grouped knapsack that picks a portfolio of places covering `target`
    /// residue coordinates at the least gate count.
    ///
    /// Groups, in this order: the place at infinity, `x`, `x + 1` (multiplicities
    /// `1..=max_linear`), then each degree of `pools` in ascending order. The
    /// degree-2 pool offers powers of its first polynomial while twice the exponent
    /// is at most `cap`; a larger degree offers prefixes of its pool. At most one
    /// option per group is taken, partial solutions are visited in ascending
    /// coverage, coverage is clamped at `target`, and a candidate replaces an
    /// earlier one only if it is strictly cheaper.
    ///
    /// Returns `None` if no selection reaches `target`.
    pub fn crt_search(
        &mut self,
        target: usize,
        max_linear: usize,
        cap: usize,
        pools: &BTreeMap<usize, Vec<u32>>,
    ) -> Result<Option<(u64, Vec<Place>)>, CrtError> {
        let mut groups: Vec<Vec<Choice>> = Vec::new();
        let linear: [fn(u32) -> Place; 3] = [
            Place::infinity,
            |multiplicity| Place::linear(0b10, multiplicity),
            |multiplicity| Place::linear(0b11, multiplicity),
        ];
        for make in linear {
            let mut options = Vec::new();
            for multiplicity in 1..=max_linear {
                let place = make(u32::try_from(multiplicity).map_err(|_| OVERFLOW)?);
                options.push((multiplicity, self.short_cost(multiplicity)?.0, vec![place]));
            }
            if !options.is_empty() {
                groups.push(options);
            }
        }
        for (degree, pool) in pools {
            let Some(first) = pool.first().copied() else {
                continue;
            };
            if *degree < 2 {
                return Err(CrtError::Construction {
                    what: "a pool of polynomials of degree below two",
                });
            }
            let mut options = Vec::new();
            if *degree == 2 {
                let mut multiplicity = 1usize;
                while 2 * multiplicity <= cap {
                    let place = Place::irreducible(
                        first,
                        u32::try_from(multiplicity).map_err(|_| OVERFLOW)?,
                    );
                    options.push((2 * multiplicity, self.place_gate_cost(place)?, vec![place]));
                    multiplicity += 1;
                }
            } else {
                let each = self.place_gate_cost(Place::irreducible(first, 1))?;
                let most = pool.len().min(target / degree + 1);
                for count in 1..=most {
                    let places = pool
                        .iter()
                        .take(count)
                        .map(|poly| Place::irreducible(*poly, 1))
                        .collect();
                    options.push((count * degree, times(wide(count), each)?, places));
                }
            }
            if !options.is_empty() {
                groups.push(options);
            }
        }

        let mut best: BTreeMap<usize, (u64, Vec<Place>)> = BTreeMap::new();
        best.insert(0, (0, Vec::new()));
        for options in &groups {
            let mut next = best.clone();
            for (covered, (cost, places)) in &best {
                for (option_degree, option_cost, option_places) in options {
                    let reached = covered.saturating_add(*option_degree).min(target);
                    let total = add(*cost, *option_cost)?;
                    if next
                        .get(&reached)
                        .is_none_or(|(current, _)| total < *current)
                    {
                        let mut chosen = places.clone();
                        chosen.extend_from_slice(option_places);
                        next.insert(reached, (total, chosen));
                    }
                }
            }
            best = next;
        }
        Ok(best.remove(&target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A portfolio written as `(kind, poly, multiplicity)` with kind 0 for infinity,
    /// 1 for linear and 2 for irreducible.
    fn places(list: &[(u8, u32, u32)]) -> Vec<Place> {
        list.iter()
            .map(|(kind, poly, multiplicity)| match kind {
                0 => Place::infinity(*multiplicity),
                1 => Place::linear(*poly, *multiplicity),
                _ => Place::irreducible(*poly, *multiplicity),
            })
            .collect()
    }

    #[test]
    fn place_constructors() {
        assert_eq!(
            Place::infinity(3),
            Place {
                kind: PlaceKind::Infinity,
                poly: 0,
                multiplicity: 3
            }
        );
        assert_eq!(Place::linear(2, 5).kind, PlaceKind::Linear);
        assert_eq!(Place::irreducible(7, 2).poly, 7);
    }

    #[test]
    fn small_helpers() {
        assert_eq!(tower_cost(6), 15);
        assert_eq!(tower_cost(8), 24);
        assert_eq!(tower_cost(7), 0);
        assert_eq!(degree_u32(0x11b), 8);
        assert_eq!(degree_u32(1), 0);
        assert_eq!(degree_u32(0), 0);
        assert_eq!(add(2, 3), Ok(5));
        assert_eq!(add(u64::MAX, 1), Err(OVERFLOW));
        assert_eq!(times(2, 3), Ok(6));
        assert_eq!(times(u64::MAX, 2), Err(OVERFLOW));
    }

    #[test]
    fn irreducible_counts_and_first_entries() {
        let mut table = CostTable::default();
        let counts: Vec<usize> = (2..=12)
            .map(|degree| {
                table
                    .irreducibles_of_degree(degree)
                    .expect("supported")
                    .len()
            })
            .collect();
        assert_eq!(counts, vec![1, 2, 3, 6, 9, 18, 30, 56, 99, 186, 335]);
        assert_eq!(table.irreducibles_of_degree(4), Ok(vec![0x13, 0x19, 0x1f]));
        assert_eq!(
            table.irreducibles_of_degree(6),
            Ok(vec![0x43, 0x49, 0x57, 0x5b, 0x61, 0x67, 0x6d, 0x73, 0x75])
        );
        let eleven = table.irreducibles_of_degree(11).expect("supported");
        assert_eq!(eleven[..4], [0x805, 0x817, 0x82b, 0x82d]);
        // Memoised: the second call returns the same list.
        assert_eq!(table.irreducibles_of_degree(11), Ok(eleven));
        assert!(matches!(
            table.irreducibles_of_degree(1),
            Err(CrtError::Field(_))
        ));
        assert!(matches!(
            table.irreducibles_of_degree(17),
            Err(CrtError::Field(_))
        ));
    }

    #[test]
    fn cost_anchors_of_appendix_b3() {
        let mut table = CostTable::default();
        let full: Vec<u64> = (1..=12)
            .map(|size| table.full_cost(size).expect("cost").0)
            .collect();
        assert_eq!(full, vec![1, 3, 6, 9, 13, 18, 22, 26, 30, 35, 39, 44]);
        let short: Vec<u64> = (1..=12)
            .map(|size| table.short_cost(size).expect("cost").0)
            .collect();
        assert_eq!(short, vec![1, 3, 5, 8, 11, 15, 19, 23, 28, 32, 36, 40]);
        assert!(table.full_cost(0).is_err());
    }

    #[test]
    fn full_plans_match_the_reference() {
        let mut table = CostTable::default();
        let common = [(2, 7, 1), (2, 0xb, 1), (2, 0xd, 1)];
        let with = |head: &[(u8, u32, u32)], tail: &[(u8, u32, u32)]| {
            let mut list = head.to_vec();
            list.extend_from_slice(&common);
            list.extend_from_slice(tail);
            FullPlan::Crt(places(&list))
        };
        let expected = [
            FullPlan::Base,
            FullPlan::Crt(places(&[(0, 0, 1), (1, 2, 1), (1, 3, 1)])),
            FullPlan::Crt(places(&[(0, 0, 1), (1, 2, 1), (1, 3, 1), (2, 7, 1)])),
            FullPlan::Split { outer: 2, inner: 2 },
            FullPlan::Mont5,
            FullPlan::Split { outer: 2, inner: 3 },
            with(&[(0, 0, 1), (1, 2, 1), (1, 3, 3)], &[]),
            with(&[(0, 0, 1), (1, 2, 3), (1, 3, 3)], &[]),
            with(&[(0, 0, 3), (1, 2, 3), (1, 3, 3)], &[]),
            with(&[(0, 0, 1), (1, 2, 3), (1, 3, 3)], &[(2, 0x13, 1)]),
            with(&[(0, 0, 3), (1, 2, 3), (1, 3, 3)], &[(2, 0x13, 1)]),
            with(
                &[(0, 0, 1), (1, 2, 3), (1, 3, 3)],
                &[(2, 0x13, 1), (2, 0x19, 1)],
            ),
        ];
        for (size, plan) in (1..=12).zip(expected) {
            assert_eq!(table.full_cost(size).expect("cost").1, plan, "n = {size}");
        }
    }

    #[test]
    fn short_plans_match_the_reference() {
        let mut table = CostTable::default();
        let expected = [
            ShortPlan::Base,
            ShortPlan::Full,
            ShortPlan::ShortSplit(2),
            ShortPlan::ShortSplit(3),
            ShortPlan::ShortSplit(4),
            ShortPlan::ShortSplit(4),
            ShortPlan::ShortSplit(4),
            ShortPlan::ShortSplit(5),
            ShortPlan::ShortSplit(6),
            ShortPlan::ShortSplit(7),
            ShortPlan::ShortSplit(8),
            ShortPlan::ShortSplit(9),
        ];
        for (size, plan) in (1..=12).zip(expected) {
            assert_eq!(table.short_cost(size).expect("cost").1, plan, "n = {size}");
        }
    }

    #[test]
    fn place_costs() {
        let mut table = CostTable::default();
        assert_eq!(table.place_gate_cost(Place::infinity(3)), Ok(5));
        assert_eq!(table.place_gate_cost(Place::linear(3, 5)), Ok(11));
        assert_eq!(table.place_gate_cost(Place::irreducible(7, 2)), Ok(9));
        assert_eq!(table.place_gate_cost(Place::irreducible(0x25, 1)), Ok(13));
        // Degrees 6 and 8 use the tower: 15 < 18 and 24 < 26.
        assert_eq!(table.place_gate_cost(Place::irreducible(0x43, 1)), Ok(15));
        assert_eq!(table.place_gate_cost(Place::irreducible(0x11b, 1)), Ok(24));
        assert_eq!(table.place_gate_cost(Place::irreducible(0x83, 1)), Ok(22));
        assert_eq!(table.place_gate_cost(Place::irreducible(0x203, 1)), Ok(30));
    }

    #[test]
    fn knapsack_rules() {
        let mut table = CostTable::default();
        // Nothing but the three linear groups: 2 + 2 + 2 coordinates at most.
        let none = BTreeMap::new();
        assert_eq!(table.crt_search(7, 2, 0, &none), Ok(None));
        let (cost, picks) = table
            .crt_search(3, 1, 0, &none)
            .expect("search")
            .expect("reachable");
        assert_eq!(cost, 3);
        assert_eq!(picks, places(&[(0, 0, 1), (1, 2, 1), (1, 3, 1)]));
        // An empty pool is skipped, a pool of degree one is an error.
        let mut pools = BTreeMap::new();
        pools.insert(3, Vec::new());
        assert_eq!(
            table.crt_search(3, 1, 0, &pools).expect("search"),
            Some((3, picks))
        );
        pools.insert(1, vec![2]);
        assert!(table.crt_search(3, 1, 0, &pools).is_err());
    }
}
