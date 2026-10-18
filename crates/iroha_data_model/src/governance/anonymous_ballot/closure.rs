//! The closure record of one binding body's ballot (design §3.8, integration decision 9).

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    BallotOutcomeV1, BallotScopeV1, BallotTallyErrorV1, Digest512, FrozenBallotPolicyErrorV1,
    FrozenBallotPolicyV1, ParliamentDecisionRuleV1, ProofProfileIdV1, digests::result_root_v1,
    framing::AnonymousBallotCodecErrorV1,
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, NetworkId,
    governance::{
        GovernanceAnchorV1,
        types::{
            BodyElectionAttemptId, BodyInstanceId, GovernanceAttemptId, ParliamentBody,
            ProposalContentId, RiskTierV1,
        },
    },
};

/// Why a closure record is not consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BallotClosureErrorV1 {
    /// The proof profile is not [`ProofProfileIdV1::V1`].
    #[error("the proof profile is not the V1 profile")]
    UnknownProfile,
    /// The counts are not a closable tally.
    #[error(transparent)]
    Tally(#[from] BallotTallyErrorV1),
    /// `aye + nay + abstain` is not `accepted_ballots`.
    #[error("{accepted} accepted ballots but the choices total {counted}")]
    CountMismatch {
        /// Accepted ballots `M`.
        accepted: u32,
        /// `A + N + X`.
        counted: u64,
    },
    /// The casting clock is not the block after the opening block.
    #[error("the casting clock must be established at the opening height plus one")]
    CastingClockHeight,
    /// The casting clock's time precedes the opening.
    #[error("the casting clock's time precedes the opening")]
    CastingClockTime,
    /// `closing_ms` is not the casting clock's time plus the casting window.
    #[error("closing_ms must be the casting clock's time plus the casting window")]
    ClosingTime,
    /// The closure is not in a later block than the casting clock, or precedes
    /// `closing_ms`.
    #[error("the closure must be a later block whose time reaches closing_ms")]
    ClosureAnchor,
    /// The recorded outcome is not the recomputed one.
    #[error("the recorded outcome {recorded:?} is not the recomputed {expected:?}")]
    Outcome {
        /// Recomputed outcome.
        expected: BallotOutcomeV1,
        /// Recorded outcome.
        recorded: BallotOutcomeV1,
    },
    /// The recorded narrow flag is not the recomputed one.
    #[error("the recorded narrow flag is not the recomputed one")]
    Narrow,
    /// The frozen policy the record is checked against is invalid.
    #[error(transparent)]
    Policy(#[from] FrozenBallotPolicyErrorV1),
    /// A record field disagrees with the frozen policy.
    #[error("the closure record's {field} disagrees with its frozen policy")]
    PolicyMismatch {
        /// The disagreeing field.
        field: &'static str,
    },
}

/// The closure record committed when a binding body's casting window closes
/// (integration decision 9), in its exact field order.
///
/// It references the sealed list by `list_digest` and carries no nullifier or `auth_v`;
/// those are in the corpus entries. `result_root = H(Frame("PARL/RESULT/v1";
/// Enc(record)))` ([`Self::result_root`]) is what the anonymous body-result certificate
/// binding commits.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::BallotClosureRecordV1")]
pub struct BallotClosureRecordV1 {
    /// Genesis-bound network identity.
    pub network_id: NetworkId,
    /// Immutable proposal content identifier.
    pub proposal_content_id: ProposalContentId,
    /// `proposal_digest` of the full canonical proposal.
    pub proposal_digest: Digest512,
    /// Governance attempt.
    pub governance_attempt_id: GovernanceAttemptId,
    /// Body-election attempt that sealed the body.
    pub election_attempt_id: BodyElectionAttemptId,
    /// Sealed body instance.
    pub body_instance_id: BodyInstanceId,
    /// Binding jury role.
    pub body_role: ParliamentBody,
    /// Ballot scope.
    pub scope: BallotScopeV1,
    /// Sealed seats `S`.
    pub seats: u16,
    /// Proof profile.
    pub profile_id: ProofProfileIdV1,
    /// `policy_hash` of the frozen policy snapshot.
    pub policy_hash: Digest512,
    /// Sealed-list digest `R`.
    pub list_digest: Digest512,
    /// Registration-mapping digest of the sealed `(assignment_id, C)` pairs.
    pub registration_mapping_digest: Digest512,
    /// Casting-open anchor `s0`.
    pub opening_anchor: GovernanceAnchorV1,
    /// Height `h_open + 1` whose block-start prelude established the casting clock.
    pub casting_clock_height: u64,
    /// Block time of `casting_clock_height`.
    pub casting_clock_timestamp_ms: u64,
    /// Frozen casting window.
    pub casting_window_ms: u64,
    /// `casting_clock_timestamp_ms + casting_window_ms`; the window is half-open.
    pub closing_ms: u64,
    /// Anchor of the closure transition.
    pub closure_anchor: GovernanceAnchorV1,
    /// Corpus root `root_M`.
    pub corpus_root: Digest512,
    /// Accepted ballots `M`.
    pub accepted_ballots: u32,
    /// Aye count `A`.
    pub aye: u32,
    /// Nay count `N`.
    pub nay: u32,
    /// Abstain count `X`.
    pub abstain: u32,
    /// Outcome.
    pub outcome: BallotOutcomeV1,
    /// Whether an approval is narrow.
    pub narrow: bool,
}

impl BallotClosureRecordV1 {
    /// Check the record against the frozen ballot policy of its body: the policy itself, the
    /// body role, the V1 profile, the casting duration and the seat cap of the policy; the
    /// casting-clock and closure anchors; count conservation and `M ≤ S`; and the exact
    /// recomputation of the outcome and the narrow flag under `policy.risk_tier` with
    /// checked integers.
    ///
    /// The record binds its policy only through `policy_hash`, which the data model cannot
    /// compute (it binds the construction domain `P16` and belongs to the proof crate).
    /// `iroha_parliament_ballot`'s closure validation runs this check and also recomputes
    /// and compares `policy_hash`; callers that hold an unauthenticated policy must use it.
    ///
    /// # Errors
    /// The first violated rule as a [`BallotClosureErrorV1`].
    pub fn validate(&self, policy: &FrozenBallotPolicyV1) -> Result<(), BallotClosureErrorV1> {
        policy.validate()?;
        if self.body_role != policy.body_role {
            return Err(BallotClosureErrorV1::PolicyMismatch { field: "body_role" });
        }
        if !self.profile_id.is_v1() {
            return Err(BallotClosureErrorV1::UnknownProfile);
        }
        if self.profile_id != policy.binding.profile_id {
            return Err(BallotClosureErrorV1::PolicyMismatch {
                field: "profile_id",
            });
        }
        if self.casting_window_ms != policy.binding.casting_window_ms {
            return Err(BallotClosureErrorV1::PolicyMismatch {
                field: "casting_window_ms",
            });
        }
        if policy
            .body_target_seats()
            .is_none_or(|target_seats| self.seats > target_seats)
        {
            return Err(BallotClosureErrorV1::PolicyMismatch { field: "seats" });
        }
        self.validate_under_tier(policy.risk_tier)
    }

    /// The anchor, count and outcome checks of [`Self::validate`] under a bare risk tier.
    fn validate_under_tier(&self, risk_tier: RiskTierV1) -> Result<(), BallotClosureErrorV1> {
        if self.opening_anchor.height.checked_add(1) != Some(self.casting_clock_height) {
            return Err(BallotClosureErrorV1::CastingClockHeight);
        }
        if self.casting_clock_timestamp_ms < self.opening_anchor.timestamp_ms {
            return Err(BallotClosureErrorV1::CastingClockTime);
        }
        if self
            .casting_clock_timestamp_ms
            .checked_add(self.casting_window_ms)
            != Some(self.closing_ms)
        {
            return Err(BallotClosureErrorV1::ClosingTime);
        }
        if self.closure_anchor.height <= self.casting_clock_height
            || self.closure_anchor.timestamp_ms < self.closing_ms
        {
            return Err(BallotClosureErrorV1::ClosureAnchor);
        }
        let counted = u64::from(self.aye) + u64::from(self.nay) + u64::from(self.abstain);
        if counted != u64::from(self.accepted_ballots) {
            return Err(BallotClosureErrorV1::CountMismatch {
                accepted: self.accepted_ballots,
                counted,
            });
        }
        let decision = ParliamentDecisionRuleV1::V1.decide(
            self.body_role,
            risk_tier,
            self.seats,
            self.aye,
            self.nay,
            self.abstain,
        )?;
        if decision.outcome != self.outcome {
            return Err(BallotClosureErrorV1::Outcome {
                expected: decision.outcome,
                recorded: self.outcome,
            });
        }
        if decision.narrow != self.narrow {
            return Err(BallotClosureErrorV1::Narrow);
        }
        Ok(())
    }

    /// `result_root = H(Frame("PARL/RESULT/v1"; Enc(self)))`.
    ///
    /// # Errors
    /// [`AnonymousBallotCodecErrorV1`] if `Enc(self)` cannot be produced.
    pub fn result_root(&self) -> Result<Digest512, AnonymousBallotCodecErrorV1> {
        result_root_v1(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::anonymous_ballot::{
        framing::{decode_enc, enc},
        test_fixtures::{anchor, attempt_policy, closure, policy},
    };

    /// The fixture's Policy Jury policy under `tier`.
    fn policy_under(tier: RiskTierV1) -> FrozenBallotPolicyV1 {
        attempt_policy()
            .ballot_policy(tier, ParliamentBody::PolicyJury)
            .expect("policy")
    }

    #[test]
    fn a_consistent_record_validates_and_round_trips() {
        let record = closure(9, 6, 2, 1);
        assert_eq!(record.outcome, BallotOutcomeV1::Approved);
        assert_eq!(record.validate(&policy()), Ok(()));
        assert_eq!(
            decode_enc::<BallotClosureRecordV1>(&enc(&record).expect("enc")),
            Ok(record)
        );
        let json = norito::json::to_json(&record).expect("json");
        assert_eq!(
            norito::json::from_str::<BallotClosureRecordV1>(&json).expect("json"),
            record
        );
        assert_eq!(record.result_root(), result_root_v1(&record));
    }

    #[test]
    fn the_design_boundaries_recompute_exactly() {
        let standard = policy();
        // S = 3 with full turnout and a tie-free split; a tie; M = max(3, Q) - 1.
        assert_eq!(closure(3, 2, 1, 0).validate(&standard), Ok(()));
        assert_eq!(closure(3, 2, 1, 0).outcome, BallotOutcomeV1::Approved);
        assert_eq!(closure(3, 1, 1, 1).outcome, BallotOutcomeV1::Rejected);
        assert_eq!(closure(3, 2, 0, 0).outcome, BallotOutcomeV1::NoQuorum);
        assert_eq!(
            closure(1_000, 400, 266, 0).outcome,
            BallotOutcomeV1::NoQuorum
        );
        assert_eq!(
            closure(1_000, 400, 267, 0).outcome,
            BallotOutcomeV1::Approved
        );
        // The narrow edge.
        let narrow = closure(30, 11, 10, 0);
        assert!(narrow.narrow);
        assert_eq!(narrow.validate(&standard), Ok(()));
        // The emergency quorum A = Q changes the recomputed Policy outcome only below Q.
        let emergency = policy_under(RiskTierV1::Emergency);
        let at_quorum = closure(9, 6, 3, 0);
        assert_eq!(at_quorum.validate(&emergency), Ok(()));
        let below_quorum = closure(9, 5, 3, 1);
        assert_eq!(below_quorum.validate(&standard), Ok(()));
        assert_eq!(
            below_quorum.validate(&emergency),
            Err(BallotClosureErrorV1::Outcome {
                expected: BallotOutcomeV1::Rejected,
                recorded: BallotOutcomeV1::Approved
            })
        );
    }

    #[test]
    fn the_record_must_agree_with_its_frozen_policy() {
        let record = closure(9, 6, 2, 1);
        // An invalid policy is refused before anything is compared.
        let mut invalid = policy();
        invalid.minimum_turnout = 2;
        assert_eq!(
            record.validate(&invalid),
            Err(BallotClosureErrorV1::Policy(
                FrozenBallotPolicyErrorV1::Constant {
                    field: "minimum_turnout"
                }
            ))
        );
        // The Confirmation policy of the same attempt is another body.
        let confirmation = attempt_policy()
            .ballot_policy(RiskTierV1::Standard, ParliamentBody::ConfirmationJury)
            .expect("policy");
        assert_eq!(
            record.validate(&confirmation),
            Err(BallotClosureErrorV1::PolicyMismatch { field: "body_role" })
        );
        let mut confirmed = record;
        confirmed.body_role = ParliamentBody::ConfirmationJury;
        assert_eq!(confirmed.validate(&confirmation), Ok(()));
        // The casting duration is the frozen one.
        let mut changed = record;
        changed.casting_window_ms -= 1;
        changed.closing_ms -= 1;
        assert_eq!(
            changed.validate(&policy()),
            Err(BallotClosureErrorV1::PolicyMismatch {
                field: "casting_window_ms"
            })
        );
        // Sealed seats never exceed the body's frozen target: 500 for the Policy Jury and
        // 1,000 for the Confirmation Jury.
        let largest_policy = closure(500, 300, 100, 0);
        assert_eq!(largest_policy.validate(&policy()), Ok(()));
        let oversized = closure(501, 300, 100, 0);
        assert_eq!(
            oversized.validate(&policy()),
            Err(BallotClosureErrorV1::PolicyMismatch { field: "seats" })
        );
        let mut largest_confirmation = closure(1_000, 400, 267, 0);
        largest_confirmation.body_role = ParliamentBody::ConfirmationJury;
        assert_eq!(largest_confirmation.validate(&confirmation), Ok(()));
    }

    #[test]
    fn inconsistent_counts_outcomes_and_flags_are_refused() {
        let record = closure(9, 6, 2, 1);
        let standard = policy();
        let mut changed = record;
        changed.accepted_ballots = 10;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::CountMismatch {
                accepted: 10,
                counted: 9
            })
        );
        let mut changed = record;
        changed.seats = 8;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::Tally(
                BallotTallyErrorV1::CorpusExceedsSeats {
                    accepted: 9,
                    seats: 8
                }
            ))
        );
        let mut changed = record;
        changed.outcome = BallotOutcomeV1::Rejected;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::Outcome {
                expected: BallotOutcomeV1::Approved,
                recorded: BallotOutcomeV1::Rejected
            })
        );
        let mut changed = record;
        changed.narrow = true;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::Narrow)
        );
        // A public body cannot close a binding ballot, under its own policy or any other.
        let mut changed = record;
        changed.body_role = ParliamentBody::InterestPanel;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::PolicyMismatch { field: "body_role" })
        );
        assert!(matches!(
            changed.validate_under_tier(RiskTierV1::Standard),
            Err(BallotClosureErrorV1::Tally(
                BallotTallyErrorV1::NotBindingBody { .. }
            ))
        ));
        let mut changed = record;
        changed.profile_id = ProofProfileIdV1::new([0; 64]);
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::UnknownProfile)
        );
    }

    #[test]
    fn the_clock_and_closure_anchors_are_checked() {
        let record = closure(9, 6, 2, 1);
        let standard = policy();
        let mut changed = record;
        changed.casting_clock_height = record.opening_anchor.height;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::CastingClockHeight)
        );
        let mut changed = record;
        changed.casting_clock_height = record.opening_anchor.height + 2;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::CastingClockHeight)
        );
        let mut changed = record;
        changed.opening_anchor = anchor(u64::MAX, 0, 0);
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::CastingClockHeight)
        );
        let mut changed = record;
        changed.casting_clock_timestamp_ms = record.opening_anchor.timestamp_ms - 1;
        changed.closing_ms = changed.casting_clock_timestamp_ms + changed.casting_window_ms;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::CastingClockTime)
        );
        let mut changed = record;
        changed.closing_ms += 1;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::ClosingTime)
        );
        let mut changed = record;
        changed.casting_window_ms = u64::MAX;
        assert_eq!(
            changed.validate_under_tier(RiskTierV1::Standard),
            Err(BallotClosureErrorV1::ClosingTime)
        );
        // The closure block's time reaching closing_ms exactly is enough; earlier is not.
        let mut changed = record;
        changed.closure_anchor.timestamp_ms = record.closing_ms;
        assert_eq!(changed.validate(&standard), Ok(()));
        changed.closure_anchor.timestamp_ms = record.closing_ms - 1;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::ClosureAnchor)
        );
        let mut changed = record;
        changed.closure_anchor.height = record.casting_clock_height;
        assert_eq!(
            changed.validate(&standard),
            Err(BallotClosureErrorV1::ClosureAnchor)
        );
    }
}
