//! The halo2 IPA multi-point opening with static query grouping (spec section
//! 9.1, soundness invariants S1-S3).
//!
//! # Static grouping
//!
//! A query `(slot, rotation)` names the opened polynomial by a [`Slot`] — a
//! kind and an index taken from the circuit descriptor — never by the value
//! of its commitment. The vendored grouping merges queries whose commitments
//! compare equal and lets a later evaluation overwrite an earlier one; it is
//! safe there only because the comparison is pointer identity. A port that
//! compared values would let a prover commit one polynomial to two advice
//! columns and claim different evaluations, one of which is never checked.
//! Here equal commitments always stay separate slots (S1).
//!
//! [`OpeningPlan::new`] fixes everything that depends only on the query list:
//!
//! - point indices follow the first appearance of each rotation;
//! - slots are ordered by first appearance;
//! - a slot's point set is its sorted list of point indices;
//! - sets are numbered by first appearance in slot order, and each lists its
//!   points by point index.
//!
//! For descriptor-derived query lists this reproduces the vendored order, so
//! the proof bytes are identical. A repeated `(slot, rotation)` query is
//! recorded as a repeat: the verifier drops it if its evaluation is
//! bit-identical to the first one and rejects it otherwise (S3, never an
//! overwrite).
//!
//! # Protocol
//!
//! The prover ([`prover::create_proof`]) and verifier
//! ([`verifier::verify`]) squeeze `x_1`, `x_2`; the prover commits
//! `q' = sum_t x_2^{n_s-1-t} (q_t - r_t) / prod_{p in t} (X - p)` where
//! `q_t = sum_{slots in t} x_1^{e} p_slot`; then `x_3`, the evaluations
//! `q_t(x_3)`, `x_4`, and one IPA opening of
//! `x_4^{n_s} q' + sum_t x_4^{n_s-1-t} q_t` at `x_3`.

use core::fmt;
use std::collections::BTreeMap;

use ff::Field;

use super::ipa::IpaError;
use crate::transcript::TranscriptError;

pub mod prover;
#[cfg(test)]
mod soundness_tests;
pub mod verifier;

/// Largest number of queries a plan accepts.
pub const MAX_QUERIES: usize = 1 << 20;

/// What kind of polynomial a slot names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SlotKind {
    /// An instance column (Committed mode only).
    Instance,
    /// An advice column.
    Advice,
    /// A fixed column (selectors included).
    Fixed,
    /// A permutation grand product `z_s`.
    PermutationProduct,
    /// A lookup grand product `z`.
    LookupProduct,
    /// A permuted lookup input `A'`.
    LookupPermutedInput,
    /// A permuted lookup table `S'`.
    LookupPermutedTable,
    /// A permutation polynomial `sigma_j`.
    PermutationSigma,
    /// The quotient `h` (its pieces combined).
    Vanishing,
    /// The random polynomial `R`.
    Random,
}

/// The polynomial a query opens: a kind and an index (S1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot {
    /// The kind.
    pub kind: SlotKind,
    /// The index within the kind.
    pub index: u32,
}

impl Slot {
    /// A slot of `kind` at `index`.
    #[must_use]
    pub const fn new(kind: SlotKind, index: u32) -> Self {
        Self { kind, index }
    }
}

/// A query: a slot opened at `x * omega^rotation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OpeningQuery {
    /// The opened polynomial.
    pub slot: Slot,
    /// The rotation of the opening point.
    pub rotation: i32,
}

impl OpeningQuery {
    /// The query of `slot` at `rotation`.
    #[must_use]
    pub const fn new(slot: Slot, rotation: i32) -> Self {
        Self { slot, rotation }
    }
}

/// A multiopen operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiopenError {
    /// The caller cancelled this operation; it has no completed proof result.
    Cancelled,
    /// The plan has no queries.
    NoQueries,
    /// The plan has more than [`MAX_QUERIES`] queries.
    TooManyQueries,
    /// An input does not match the plan's shape.
    Shape {
        /// What has the wrong length.
        what: ShapeItem,
        /// The length the plan requires.
        expected: usize,
        /// The supplied length.
        actual: usize,
    },
    /// Two rotations map to the same opening point.
    PointCollision,
    /// A repeated `(slot, rotation)` query claims a different evaluation
    /// (S3).
    ConflictingEvaluations {
        /// The repeated query.
        query: usize,
    },
    /// `x_3` equals an opening point.
    DegenerateChallenge,
    /// The inner-product argument failed.
    Ipa(IpaError),
}

/// The input whose length did not match an [`OpeningPlan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShapeItem {
    /// The opening points (one per rotation).
    Points,
    /// The slot commitments or polynomials (one per slot).
    Slots,
    /// The evaluations (one per query).
    Evaluations,
    /// A polynomial's coefficients (`n`).
    Coefficients,
}

impl MultiopenError {
    /// Whether this failure is cooperative cancellation, never an invalid proof.
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Cancelled => true,
            Self::Ipa(error) => error.is_cancelled(),
            _ => false,
        }
    }
}

impl fmt::Display for MultiopenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("operation cancelled"),
            Self::NoQueries => f.write_str("the opening has no queries"),
            Self::TooManyQueries => f.write_str("the opening has too many queries"),
            Self::Shape {
                what,
                expected,
                actual,
            } => write!(f, "{what:?}: {actual} supplied, {expected} expected"),
            Self::PointCollision => f.write_str("two rotations open at the same point"),
            Self::ConflictingEvaluations { query } => {
                write!(
                    f,
                    "query {query} repeats a query with a different evaluation"
                )
            }
            Self::DegenerateChallenge => f.write_str("x_3 equals an opening point"),
            Self::Ipa(error) => write!(f, "IPA: {error}"),
        }
    }
}

impl std::error::Error for MultiopenError {}

impl From<iroha_pasta::Cancelled> for MultiopenError {
    fn from(_: iroha_pasta::Cancelled) -> Self {
        Self::Cancelled
    }
}

impl From<IpaError> for MultiopenError {
    fn from(error: IpaError) -> Self {
        if matches!(error, IpaError::Cancelled) {
            Self::Cancelled
        } else {
            Self::Ipa(error)
        }
    }
}

impl From<TranscriptError> for MultiopenError {
    fn from(error: TranscriptError) -> Self {
        Self::Ipa(IpaError::Transcript(error))
    }
}

/// A slot of the plan with its point set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedSlot {
    /// The slot.
    pub slot: Slot,
    /// The index of its point set.
    pub set: usize,
    /// Its point indices, sorted.
    pub points: Vec<usize>,
}

/// Where a query's evaluation goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlannedQuery {
    /// The first query of `(slot, rotation)`: slot index and position in the
    /// slot's sorted points.
    First {
        /// The slot index in plan order.
        slot: usize,
        /// The position in the slot's point list.
        position: usize,
    },
    /// A repeat of an earlier query (its evaluation must be identical).
    Repeat {
        /// The index of the first query.
        of: usize,
    },
}

/// The static grouping of a query list (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpeningPlan {
    rotations: Vec<i32>,
    slots: Vec<PlannedSlot>,
    sets: Vec<Vec<usize>>,
    queries: Vec<PlannedQuery>,
}

impl OpeningPlan {
    /// Plans `queries`, which are taken in the spec 9.1 order.
    ///
    /// # Errors
    ///
    /// [`MultiopenError::NoQueries`] or [`MultiopenError::TooManyQueries`].
    pub fn new(queries: &[OpeningQuery]) -> Result<Self, MultiopenError> {
        if queries.is_empty() {
            return Err(MultiopenError::NoQueries);
        }
        if queries.len() > MAX_QUERIES {
            return Err(MultiopenError::TooManyQueries);
        }
        let mut point_of_rotation: BTreeMap<i32, usize> = BTreeMap::new();
        let mut rotations = Vec::new();
        let mut slot_of: BTreeMap<Slot, usize> = BTreeMap::new();
        let mut slot_points: Vec<(Slot, Vec<usize>)> = Vec::new();
        let mut first_query: BTreeMap<(usize, usize), usize> = BTreeMap::new();
        // (slot, point, repeat-of) per query.
        let mut raw = Vec::with_capacity(queries.len());
        for (index, query) in queries.iter().enumerate() {
            let point = *point_of_rotation.entry(query.rotation).or_insert_with(|| {
                rotations.push(query.rotation);
                rotations.len() - 1
            });
            let slot = *slot_of.entry(query.slot).or_insert_with(|| {
                slot_points.push((query.slot, Vec::new()));
                slot_points.len() - 1
            });
            let repeat = first_query.get(&(slot, point)).copied();
            if repeat.is_none() {
                first_query.insert((slot, point), index);
                slot_points[slot].1.push(point);
            }
            raw.push((slot, point, repeat));
        }
        let mut set_of: BTreeMap<Vec<usize>, usize> = BTreeMap::new();
        let mut sets = Vec::new();
        let mut slots = Vec::with_capacity(slot_points.len());
        for (slot, mut points) in slot_points {
            points.sort_unstable();
            let set = *set_of.entry(points.clone()).or_insert_with(|| {
                sets.push(points.clone());
                sets.len() - 1
            });
            slots.push(PlannedSlot { slot, set, points });
        }
        let queries = raw
            .into_iter()
            .map(|(slot, point, repeat)| {
                repeat.map_or_else(
                    || PlannedQuery::First {
                        slot,
                        // The point was inserted into this slot's list above.
                        position: slots[slot]
                            .points
                            .iter()
                            .position(|p| *p == point)
                            .unwrap_or(0),
                    },
                    |of| PlannedQuery::Repeat { of },
                )
            })
            .collect();
        Ok(Self {
            rotations,
            slots,
            sets,
            queries,
        })
    }

    /// The rotation of each point index.
    #[must_use]
    pub fn rotations(&self) -> &[i32] {
        &self.rotations
    }

    /// The slots in plan order.
    #[must_use]
    pub fn slots(&self) -> &[PlannedSlot] {
        &self.slots
    }

    /// The point sets (sorted point indices), in set order.
    #[must_use]
    pub fn sets(&self) -> &[Vec<usize>] {
        &self.sets
    }

    /// Where each query's evaluation goes, in query order.
    #[must_use]
    pub fn queries(&self) -> &[PlannedQuery] {
        &self.queries
    }

    /// The opening points `x * omega^rotation`, one per point index.
    #[must_use]
    pub fn points<F: Field>(&self, x: F, omega: F) -> Vec<F> {
        let omega_inv = omega.invert().unwrap_or(F::ZERO);
        self.rotations
            .iter()
            .map(|rotation| {
                let (base, exponent) = if *rotation >= 0 {
                    (omega, rotation.unsigned_abs())
                } else {
                    (omega_inv, rotation.unsigned_abs())
                };
                x * base.pow_vartime([u64::from(exponent)])
            })
            .collect()
    }

    /// Checks an input length against the plan.
    pub(crate) fn check_len(
        what: ShapeItem,
        expected: usize,
        actual: usize,
    ) -> Result<(), MultiopenError> {
        if expected == actual {
            Ok(())
        } else {
            Err(MultiopenError::Shape {
                what,
                expected,
                actual,
            })
        }
    }

    /// Checks one opening point per rotation, all distinct.
    pub(crate) fn check_points<F: Field>(&self, points: &[F]) -> Result<(), MultiopenError> {
        Self::check_len(ShapeItem::Points, self.rotations.len(), points.len())?;
        for (i, point) in points.iter().enumerate() {
            if points[..i].contains(point) {
                return Err(MultiopenError::PointCollision);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use iroha_pasta::Fq;

    use super::*;

    fn advice(index: u32) -> Slot {
        Slot::new(SlotKind::Advice, index)
    }

    #[test]
    fn plan_follows_first_appearance_and_sorted_point_sets() {
        let z = Slot::new(SlotKind::PermutationProduct, 0);
        let queries = [
            OpeningQuery::new(advice(0), 0),
            OpeningQuery::new(advice(1), 1),
            OpeningQuery::new(advice(1), 0),
            OpeningQuery::new(z, 0),
            OpeningQuery::new(z, 1),
            OpeningQuery::new(advice(0), -1),
            OpeningQuery::new(advice(2), 0),
        ];
        let plan = OpeningPlan::new(&queries).expect("plan");
        assert_eq!(plan.rotations(), &[0, 1, -1]);
        let slots: Vec<(Slot, usize, Vec<usize>)> = plan
            .slots()
            .iter()
            .map(|s| (s.slot, s.set, s.points.clone()))
            .collect();
        assert_eq!(
            slots,
            vec![
                (advice(0), 0, vec![0, 2]),
                (advice(1), 1, vec![0, 1]),
                (z, 1, vec![0, 1]),
                (advice(2), 2, vec![0]),
            ]
        );
        assert_eq!(plan.sets(), &[vec![0, 2], vec![0, 1], vec![0]]);
        assert_eq!(
            plan.queries(),
            &[
                PlannedQuery::First {
                    slot: 0,
                    position: 0
                },
                PlannedQuery::First {
                    slot: 1,
                    position: 1
                },
                PlannedQuery::First {
                    slot: 1,
                    position: 0
                },
                PlannedQuery::First {
                    slot: 2,
                    position: 0
                },
                PlannedQuery::First {
                    slot: 2,
                    position: 1
                },
                PlannedQuery::First {
                    slot: 0,
                    position: 1
                },
                PlannedQuery::First {
                    slot: 3,
                    position: 0
                },
            ]
        );
    }

    #[test]
    fn repeats_are_recorded_not_merged() {
        let queries = [
            OpeningQuery::new(advice(0), 0),
            OpeningQuery::new(advice(1), 0),
            OpeningQuery::new(advice(0), 0),
        ];
        let plan = OpeningPlan::new(&queries).expect("plan");
        assert_eq!(plan.slots().len(), 2);
        assert_eq!(plan.queries()[2], PlannedQuery::Repeat { of: 0 });
        assert_eq!(OpeningPlan::new(&[]), Err(MultiopenError::NoQueries));
    }

    #[test]
    fn points_rotate_and_collisions_are_detected() {
        let queries = [
            OpeningQuery::new(advice(0), 0),
            OpeningQuery::new(advice(0), 2),
            OpeningQuery::new(advice(0), -3),
        ];
        let plan = OpeningPlan::new(&queries).expect("plan");
        let omega = Fq::from(5);
        let x = Fq::from(7);
        let points = plan.points(x, omega);
        assert_eq!(points[0], x);
        assert_eq!(points[1], x * omega.square());
        assert_eq!(points[2] * omega.pow_vartime([3]), x);
        assert_eq!(plan.check_points(&points), Ok(()));
        assert_eq!(
            plan.check_points(&[x, x, Fq::ONE]),
            Err(MultiopenError::PointCollision)
        );
        assert_eq!(
            plan.check_points(&points[..2]),
            Err(MultiopenError::Shape {
                what: ShapeItem::Points,
                expected: 3,
                actual: 2
            })
        );
    }
}
