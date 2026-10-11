//! Independent serial-Horner checks over both fields, tiled roots and filters.

use std::cell::RefCell;

use super::*;
use crate::protocol::AllTerms;
use iroha_pasta::{Fp, Fq};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

struct RecordedFilter {
    omit_residue: usize,
    visited: RefCell<Vec<usize>>,
}

impl ConstraintFilter for RecordedFilter {
    fn keeps(&self, term: ConstraintTerm) -> bool {
        let ConstraintTerm::Gate { polynomial } = term else {
            panic!("gate fold visited a non-gate term");
        };
        self.visited.borrow_mut().push(polynomial);
        polynomial % 3 != self.omit_residue
    }
}

fn check<F: PastaField>() {
    let mut rng = ChaCha20Rng::from_seed([0x6d; 32]);
    for challenge in [F::ZERO, F::ONE, -F::ONE, F::random(&mut rng)] {
        let fold = GateFold::new(challenge);
        for (index, power) in fold.powers.iter().enumerate() {
            assert_eq!(*power, challenge.pow_vartime([index as u64]));
        }
        for stride in [1, 4] {
            let values: Vec<_> = (0..23 * stride).map(|_| F::random(&mut rng)).collect();
            for lane in 0..stride {
                let row = EvaluatedRow::new(&values, stride, lane);
                for count in 0..146 {
                    // Scrambled and repeated roots exercise the actual indirect,
                    // possibly tiled evaluator layout, rather than a flat vector.
                    let roots: Vec<_> = (0..count)
                        .map(|i| u32::try_from((i * 7 + 3) % 23).expect("root below 23"))
                        .collect();
                    let expected = roots.iter().fold(F::ZERO, |value, &root| {
                        value * challenge + row[root as usize]
                    });
                    assert_eq!(fold.evaluate(&roots, row, &AllTerms), expected);
                    for omit_residue in 0..3 {
                        let filter = RecordedFilter {
                            omit_residue,
                            visited: RefCell::new(Vec::new()),
                        };
                        let expected =
                            roots.iter().enumerate().fold(F::ZERO, |value, (i, &root)| {
                                value * challenge
                                    + if i % 3 == omit_residue {
                                        F::ZERO
                                    } else {
                                        row[root as usize]
                                    }
                            });
                        let actual = fold.evaluate(&roots, row, &filter);
                        assert_eq!(actual, expected);
                        assert_eq!(*filter.visited.borrow(), (0..count).collect::<Vec<_>>());
                    }
                }
            }
        }
    }
}

#[test]
fn grouped_gates_match_serial_horner_and_filter_order_in_fp() {
    check::<Fp>();
}

#[test]
fn grouped_gates_match_serial_horner_and_filter_order_in_fq() {
    check::<Fq>();
}
