//! Declarative verifier tables (soundness invariant S11): the constraint fold
//! of spec section 2 and the transcript schedule of spec sections 6.3 and 7,
//! as data derived from the descriptor alone.
//!
//! Every verifier of PIPA-v1 walks the same two tables:
//!
//! - [`ConstraintTerm`]: the constraints in fold order (gate polynomials, the
//!   permutation items 1-4, then the five constraints of every lookup). The
//!   native verifier folds `E = fold(acc * y + c_j)` by interpreting this
//!   list term by term; the prover's quotient uses the same order, which
//!   every honest proof checks.
//! - [`TranscriptStep`]: every absorb, message and squeeze of a production
//!   proof, in order: the prelude, rows 1-16 and the unabsorbed suffix. The
//!   native prover and verifier are tested operation for operation against
//!   it, and the exact proof length is its message count.
//!
//! An in-circuit verifier (`iroha_plonk_recursion`) interprets these tables
//! instead of re-deriving sections 6-9 by hand, and must pass the same
//! schedule and term tests. TODO(T18): a native-versus-loader parity test
//! over the same proofs and tamper corpora lands with that loader.
//!
//! [`ConstraintFilter`] is a crate-internal hook: production folds keep every
//! term ([`AllTerms`], inlined to nothing); the malicious-prover tests omit
//! the terms a forged witness violates, on the prover side to build a
//! quotient that is a polynomial, and on the verifier side to show that the
//! verifier rejects exactly because of those terms.

use crate::cs::ProtocolDescriptor;

use super::{ProtocolError, Shape};

/// One of the five halo2 lookup constraints, in spec section 2 order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LookupConstraint {
    /// `l_0 (1 - z)`.
    First,
    /// `l_last (z^2 - z)`.
    Last,
    /// `(1 - l_last - l_blind) (z(omega x)(A' + beta)(S' + gamma) - z (A +
    /// beta)(S + gamma))`.
    Product,
    /// `l_0 (A' - S')`.
    Start,
    /// `(1 - l_last - l_blind)(A' - S')(A' - A'(omega^-1 x))`.
    Step,
}

impl LookupConstraint {
    /// The five constraints in fold order.
    pub const ALL: [Self; 5] = [
        Self::First,
        Self::Last,
        Self::Product,
        Self::Start,
        Self::Step,
    ];
}

/// One constraint of the fold `E = fold(acc * y + c_j)` (spec section 2
/// "Degree and vanishing", spec section 8 step 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConstraintTerm {
    /// The gate polynomial at `polynomial` in `descriptor.gates` flattened
    /// (gate by gate, polynomial by polynomial).
    Gate {
        /// The flattened polynomial index.
        polynomial: usize,
    },
    /// Permutation item 1: `l_0 (1 - z_0)`.
    PermutationFirst,
    /// Permutation item 2: `l_last (z_{n_z-1}^2 - z_{n_z-1})`.
    PermutationLast,
    /// Permutation item 3: `l_0 (z_set - z_{set-1}(omega^{-(b+1)} x))`.
    PermutationLink {
        /// The set, `1 <= set < n_z`.
        set: usize,
    },
    /// Permutation item 4: the product rule of one set.
    PermutationProduct {
        /// The set.
        set: usize,
    },
    /// One constraint of one lookup.
    Lookup {
        /// The lookup.
        lookup: usize,
        /// Which of the five constraints.
        part: LookupConstraint,
    },
}

/// Which constraint terms a fold includes (crate-internal test hook; see the
/// module documentation).
pub(crate) trait ConstraintFilter {
    /// Whether `term` contributes to the fold (`false` contributes zero while
    /// keeping its power of `y`).
    fn keeps(&self, term: ConstraintTerm) -> bool;
}

/// The production filter: every term.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AllTerms;

impl ConstraintFilter for AllTerms {
    #[inline]
    fn keeps(&self, _term: ConstraintTerm) -> bool {
        true
    }
}

/// A public input absorbed by prover and verifier alike (spec 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommonInput {
    /// `transcript_repr`.
    TranscriptRepr,
    /// The instance-frame tag `pipainst`.
    FrameTag,
    /// The instance-column count.
    FrameColumns,
    /// The declared length of one instance column.
    FrameLength {
        /// The instance column.
        column: usize,
    },
    /// The declared V2 type of one instance column.
    FrameType {
        /// The instance column.
        column: usize,
    },
    /// The verifier-computed commitment of one instance column (Committed).
    InstanceCommitment {
        /// The instance column.
        column: usize,
    },
    /// One instance value (Direct), column-major.
    InstanceValue {
        /// The instance column.
        column: usize,
        /// The row.
        row: usize,
    },
}

/// Which evaluation of a permutation product (spec section 7 row 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PermutationAt {
    /// `z_s(x)`.
    Current,
    /// `z_s(omega x)`.
    Next,
    /// `z_s(omega^{-(b+1)} x)`, every set but the last.
    Last,
}

/// Which evaluation of a lookup (spec section 7 row 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LookupAt {
    /// `z(x)`.
    Product,
    /// `z(omega x)`.
    ProductNext,
    /// `A'(x)`.
    Input,
    /// `A'(omega^-1 x)`.
    InputPrevious,
    /// `S'(x)`.
    Table,
}

/// Which side of an IPA round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoundSide {
    /// `L_j`.
    Left,
    /// `R_j`.
    Right,
}

/// A proof message (spec section 7), read and then absorbed by the verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProofMessage {
    /// Row 1: an advice commitment.
    AdviceCommitment(usize),
    /// Row 2: a lookup's `A'` commitment.
    LookupPermutedInput(usize),
    /// Row 2: a lookup's `S'` commitment.
    LookupPermutedTable(usize),
    /// Row 3: a permutation product commitment.
    PermutationProduct(usize),
    /// Row 4: a lookup product commitment.
    LookupProduct(usize),
    /// Row 5: the random polynomial `R`.
    Random,
    /// Row 6: a quotient piece `H_i`.
    QuotientPiece(usize),
    /// Row 7 (Committed): the evaluation of an instance query.
    InstanceEval(usize),
    /// Row 8: the evaluation of an advice query.
    AdviceEval(usize),
    /// Row 8: the evaluation of a fixed query.
    FixedEval(usize),
    /// Row 9: `R(x)`.
    RandomEval,
    /// Row 9: `sigma_j(x)`.
    SigmaEval(usize),
    /// Row 10: an evaluation of a permutation product.
    PermutationEval {
        /// The set.
        set: usize,
        /// Which evaluation.
        at: PermutationAt,
    },
    /// Row 11: an evaluation of a lookup polynomial.
    LookupEval {
        /// The lookup.
        lookup: usize,
        /// Which evaluation.
        at: LookupAt,
    },
    /// Row 12: the multiopen commitment `q'`.
    MultiopenQuotient,
    /// Row 13: `q_t(x_3)` of a point set.
    PointSetEval(usize),
    /// Row 14: the IPA commitment `C_s`.
    IpaCommitment,
    /// Row 15: one side of an IPA round.
    IpaRound {
        /// The round.
        round: usize,
        /// Which side.
        side: RoundSide,
    },
    /// Row 16: `c`.
    IpaC,
    /// Row 16: `f`.
    IpaF,
}

impl ProofMessage {
    /// Whether the message is a point (otherwise a scalar).
    #[must_use]
    pub const fn is_point(&self) -> bool {
        matches!(
            self,
            Self::AdviceCommitment(_)
                | Self::LookupPermutedInput(_)
                | Self::LookupPermutedTable(_)
                | Self::PermutationProduct(_)
                | Self::LookupProduct(_)
                | Self::Random
                | Self::QuotientPiece(_)
                | Self::MultiopenQuotient
                | Self::IpaCommitment
                | Self::IpaRound { .. }
        )
    }
}

/// A squeezed challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Challenge {
    /// `theta` (lookup compression).
    Theta,
    /// `beta`.
    Beta,
    /// `gamma`.
    Gamma,
    /// `y` (constraint fold).
    Y,
    /// `x` (evaluation point).
    X,
    /// `x_1` (multiopen slot compression).
    X1,
    /// `x_2` (multiopen set compression).
    X2,
    /// `x_3` (multiopen evaluation point).
    X3,
    /// `x_4` (multiopen set combination).
    X4,
    /// `xi` (IPA commitment weight).
    Xi,
    /// `zeta_ipa` (IPA `U` weight).
    ZetaIpa,
    /// `u_j`, the challenge of IPA round `j`.
    Round(usize),
}

/// One transcript step of a production proof (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TranscriptStep {
    /// A public input absorbed by both sides.
    Common(CommonInput),
    /// Native base-field context of a PIPA-R proof.
    CommonBase(CommonInput),
    /// A proof message, decoded and absorbed.
    Message(ProofMessage),
    /// A challenge squeezed.
    Squeeze(Challenge),
    /// Row 17: the `FoldedGenerator` suffix `G'_0`, read but never absorbed.
    Suffix,
}

/// What a step does to the hash state (the schedule as the hash sees it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashOperation {
    /// A point is absorbed.
    AbsorbPoint,
    /// A scalar is absorbed.
    AbsorbScalar,
    /// A native base-field context element is absorbed.
    AbsorbBase,
    /// A challenge is squeezed.
    Squeeze,
}

impl TranscriptStep {
    /// The hash operation of this step, `None` for the unabsorbed suffix.
    #[must_use]
    pub const fn hash_operation(&self) -> Option<HashOperation> {
        match self {
            Self::Common(CommonInput::InstanceCommitment { .. }) => {
                Some(HashOperation::AbsorbPoint)
            }
            Self::Common(_) => Some(HashOperation::AbsorbScalar),
            Self::CommonBase(_) => Some(HashOperation::AbsorbBase),
            Self::Message(message) => Some(if message.is_point() {
                HashOperation::AbsorbPoint
            } else {
                HashOperation::AbsorbScalar
            }),
            Self::Squeeze(_) => Some(HashOperation::Squeeze),
            Self::Suffix => None,
        }
    }

    /// Whether this step is a 32-byte proof message (the suffix included).
    #[must_use]
    pub const fn is_proof_bytes(&self) -> bool {
        matches!(self, Self::Message(_) | Self::Suffix)
    }
}

/// The constraint terms of `descriptor` in fold order.
///
/// # Errors
///
/// [`ProtocolError::Overflow`] when the gate polynomial count overflows.
pub(super) fn constraint_terms(
    descriptor: &ProtocolDescriptor,
    shape: &Shape,
) -> Result<Vec<ConstraintTerm>, ProtocolError> {
    let polynomials = descriptor
        .gates
        .iter()
        .try_fold(0_usize, |total, gate| total.checked_add(gate.len()))
        .ok_or(ProtocolError::Overflow)?;
    let mut terms = Vec::new();
    terms.extend((0..polynomials).map(|polynomial| ConstraintTerm::Gate { polynomial }));
    if shape.permutation_sets > 0 {
        terms.push(ConstraintTerm::PermutationFirst);
        terms.push(ConstraintTerm::PermutationLast);
        terms
            .extend((1..shape.permutation_sets).map(|set| ConstraintTerm::PermutationLink { set }));
        terms.extend(
            (0..shape.permutation_sets).map(|set| ConstraintTerm::PermutationProduct { set }),
        );
    }
    for lookup in 0..shape.lookups {
        terms.extend(
            LookupConstraint::ALL
                .iter()
                .map(|part| ConstraintTerm::Lookup {
                    lookup,
                    part: *part,
                }),
        );
    }
    Ok(terms)
}

/// The transcript schedule of a production proof (see the module
/// documentation), for `point_sets` multiopen point sets.
pub(super) fn transcript_schedule(
    descriptor: &ProtocolDescriptor,
    shape: &Shape,
    point_sets: usize,
) -> Vec<TranscriptStep> {
    use TranscriptStep::{Common, Message, Squeeze};
    let mut steps = vec![
        Common(CommonInput::TranscriptRepr),
        Common(CommonInput::FrameTag),
        Common(CommonInput::FrameColumns),
    ];
    steps.extend((0..shape.num_instance).map(|column| Common(CommonInput::FrameLength { column })));
    if descriptor.instance_types.is_some() {
        steps.extend(
            (0..shape.num_instance).map(|column| Common(CommonInput::FrameType { column })),
        );
    }
    if descriptor.transcript == crate::cs::TranscriptV2::KagemushaPoseidonRp57Base {
        for step in &mut steps {
            if let Common(input) = *step {
                *step = TranscriptStep::CommonBase(input);
            }
        }
    }
    if shape.committed_instances {
        steps.extend(
            (0..shape.num_instance)
                .map(|column| Common(CommonInput::InstanceCommitment { column })),
        );
    } else {
        for (column, length) in descriptor.instance_lengths.iter().enumerate() {
            let rows = usize::try_from(*length).unwrap_or(usize::MAX);
            steps.extend((0..rows).map(|row| Common(CommonInput::InstanceValue { column, row })));
        }
    }
    // Rows 1-6.
    steps.extend((0..shape.num_advice).map(|i| Message(ProofMessage::AdviceCommitment(i))));
    steps.push(Squeeze(Challenge::Theta));
    for lookup in 0..shape.lookups {
        steps.push(Message(ProofMessage::LookupPermutedInput(lookup)));
        steps.push(Message(ProofMessage::LookupPermutedTable(lookup)));
    }
    steps.push(Squeeze(Challenge::Beta));
    steps.push(Squeeze(Challenge::Gamma));
    steps.extend(
        (0..shape.permutation_sets).map(|set| Message(ProofMessage::PermutationProduct(set))),
    );
    steps.extend((0..shape.lookups).map(|lookup| Message(ProofMessage::LookupProduct(lookup))));
    steps.push(Message(ProofMessage::Random));
    steps.push(Squeeze(Challenge::Y));
    steps.extend((0..shape.quotient_pieces).map(|i| Message(ProofMessage::QuotientPiece(i))));
    steps.push(Squeeze(Challenge::X));
    // Rows 7-11.
    if shape.committed_instances {
        steps.extend((0..shape.instance_queries).map(|q| Message(ProofMessage::InstanceEval(q))));
    }
    steps.extend((0..shape.advice_queries).map(|q| Message(ProofMessage::AdviceEval(q))));
    steps.extend((0..shape.fixed_queries).map(|q| Message(ProofMessage::FixedEval(q))));
    steps.push(Message(ProofMessage::RandomEval));
    steps.extend((0..shape.permutation_columns).map(|j| Message(ProofMessage::SigmaEval(j))));
    for set in 0..shape.permutation_sets {
        steps.push(Message(ProofMessage::PermutationEval {
            set,
            at: PermutationAt::Current,
        }));
        steps.push(Message(ProofMessage::PermutationEval {
            set,
            at: PermutationAt::Next,
        }));
        if set + 1 < shape.permutation_sets {
            steps.push(Message(ProofMessage::PermutationEval {
                set,
                at: PermutationAt::Last,
            }));
        }
    }
    for lookup in 0..shape.lookups {
        for at in [
            LookupAt::Product,
            LookupAt::ProductNext,
            LookupAt::Input,
            LookupAt::InputPrevious,
            LookupAt::Table,
        ] {
            steps.push(Message(ProofMessage::LookupEval { lookup, at }));
        }
    }
    // Rows 12-16.
    steps.push(Squeeze(Challenge::X1));
    steps.push(Squeeze(Challenge::X2));
    steps.push(Message(ProofMessage::MultiopenQuotient));
    steps.push(Squeeze(Challenge::X3));
    steps.extend((0..point_sets).map(|set| Message(ProofMessage::PointSetEval(set))));
    steps.push(Squeeze(Challenge::X4));
    steps.push(Message(ProofMessage::IpaCommitment));
    steps.push(Squeeze(Challenge::Xi));
    steps.push(Squeeze(Challenge::ZetaIpa));
    let rounds = usize::try_from(shape.k).unwrap_or(usize::MAX);
    for round in 0..rounds {
        steps.push(Message(ProofMessage::IpaRound {
            round,
            side: RoundSide::Left,
        }));
        steps.push(Message(ProofMessage::IpaRound {
            round,
            side: RoundSide::Right,
        }));
        steps.push(Squeeze(Challenge::Round(round)));
    }
    steps.push(Message(ProofMessage::IpaC));
    steps.push(Message(ProofMessage::IpaF));
    // Row 17.
    if shape.folded_generator_suffix {
        steps.push(TranscriptStep::Suffix);
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_know_their_kind() {
        assert!(ProofMessage::AdviceCommitment(0).is_point());
        assert!(
            ProofMessage::IpaRound {
                round: 1,
                side: RoundSide::Right
            }
            .is_point()
        );
        assert!(!ProofMessage::IpaC.is_point());
        assert!(
            !ProofMessage::LookupEval {
                lookup: 0,
                at: LookupAt::Table
            }
            .is_point()
        );
        assert!(!ProofMessage::PointSetEval(2).is_point());
    }

    #[test]
    fn steps_map_to_hash_operations() {
        use HashOperation::{AbsorbPoint, AbsorbScalar, Squeeze};
        let commitment = TranscriptStep::Common(CommonInput::InstanceCommitment { column: 0 });
        assert_eq!(commitment.hash_operation(), Some(AbsorbPoint));
        let value = TranscriptStep::Common(CommonInput::InstanceValue { column: 0, row: 1 });
        assert_eq!(value.hash_operation(), Some(AbsorbScalar));
        assert_eq!(
            TranscriptStep::Common(CommonInput::FrameTag).hash_operation(),
            Some(AbsorbScalar)
        );
        assert_eq!(
            TranscriptStep::Message(ProofMessage::Random).hash_operation(),
            Some(AbsorbPoint)
        );
        assert_eq!(
            TranscriptStep::Squeeze(Challenge::Round(3)).hash_operation(),
            Some(Squeeze)
        );
        assert_eq!(TranscriptStep::Suffix.hash_operation(), None);
        assert!(TranscriptStep::Suffix.is_proof_bytes());
        assert!(!TranscriptStep::Squeeze(Challenge::X).is_proof_bytes());
        assert!(AllTerms.keeps(ConstraintTerm::PermutationFirst));
        assert_eq!(LookupConstraint::ALL.len(), 5);
    }
}
