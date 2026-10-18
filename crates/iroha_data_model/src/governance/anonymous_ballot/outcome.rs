//! Closure outcome and the checked decision arithmetic of design §3.7.
//!
//! ```text
//! Q     = ceil(2*S/3)
//! floor = max(3, Q)
//!
//! if M < floor:                                     NoQuorum
//! else if body == PolicyJury and tier == Emergency: Approved if A > N and A >= Q else Rejected
//! else:                                             Approved if A > N else Rejected
//!
//! narrow = outcome == Approved and 100*(A-N) < 5*(A+N)
//! ```
//!
//! Abstentions count toward turnout and a tie rejects. Low turnout is `NoQuorum`, not a
//! malformed tally. Every operation is checked integer arithmetic.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{MAX_SEALED_SEATS_V1, MIN_SEALED_SEATS_V1, MIN_TURNOUT_V1};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    governance::types::{ParliamentBody, RiskTierV1, parliament_quorum_seats_v1},
};

/// The deterministic outcome of one binding body's ballot.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::BallotOutcomeV1")]
pub enum BallotOutcomeV1 {
    /// Quorate and the decision rule is met.
    #[codec(index = 0)]
    Approved,
    /// Quorate and the decision rule is not met (a tie rejects).
    #[codec(index = 1)]
    Rejected,
    /// Accepted ballots below `max(3, Q)`.
    #[codec(index = 2)]
    NoQuorum,
}

/// The outcome and the narrow flag of one closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BallotDecisionV1 {
    /// The outcome.
    pub outcome: BallotOutcomeV1,
    /// Whether an approval has a strictly sub-five-percent margin (never for another
    /// outcome).
    pub narrow: bool,
}

/// Why counts are not a closable tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BallotTallyErrorV1 {
    /// The body is not a binding jury.
    #[error("{body:?} is not a binding jury")]
    NotBindingBody {
        /// The body supplied.
        body: ParliamentBody,
    },
    /// Sealed seats outside `3..=1000`.
    #[error("{seats} sealed seats are outside 3..=1000")]
    SeatsOutOfRange {
        /// Seats supplied.
        seats: u16,
    },
    /// The choice counts do not sum to the accepted ballots.
    #[error("{accepted} accepted ballots but the choices total {counted}")]
    CountMismatch {
        /// Accepted ballots `M`.
        accepted: u32,
        /// `A + N + X`.
        counted: u64,
    },
    /// More accepted ballots than sealed seats.
    #[error("{accepted} accepted ballots exceed {seats} sealed seats")]
    CorpusExceedsSeats {
        /// Accepted ballots `M`.
        accepted: u64,
        /// Sealed seats `S`.
        seats: u16,
    },
    /// A checked operation overflowed (unreachable for counts within the seat bound).
    #[error("checked tally arithmetic overflowed")]
    Overflow,
}

/// The sole V1 decision rule (integration decision 7). Its one variant fixes the
/// majority, emergency, narrow-result and disjoint-Confirmation rules; there is no
/// tunable threshold.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::ParliamentDecisionRuleV1")]
pub enum ParliamentDecisionRuleV1 {
    /// Turnout `M ≥ max(3, ceil(2S/3))`; approval iff `A > N` (a tie rejects); a Policy
    /// Jury under the emergency tier also needs `A ≥ Q`; an approval is narrow iff
    /// `100(A − N) < 5(A + N)`; a narrow approved Policy result needs approval by a
    /// Confirmation Jury drawn disjoint from every sealed Policy member, and a
    /// Confirmation result is final.
    #[codec(index = 0)]
    StrictAyeMajority,
}

impl ParliamentDecisionRuleV1 {
    /// The rule of every V1 binding policy.
    pub const V1: Self = Self::StrictAyeMajority;

    /// Decide a closure of `seats` sealed seats with the counts `aye`, `nay`, `abstain`.
    ///
    /// # Errors
    /// [`BallotTallyErrorV1`] for a non-binding body, seats outside `3..=1000` or more
    /// ballots than seats.
    pub fn decide(
        self,
        body: ParliamentBody,
        risk_tier: RiskTierV1,
        seats: u16,
        aye: u32,
        nay: u32,
        abstain: u32,
    ) -> Result<BallotDecisionV1, BallotTallyErrorV1> {
        // A future rule must be decided here explicitly.
        let Self::StrictAyeMajority = self;
        if !super::context::is_binding_body(body) {
            return Err(BallotTallyErrorV1::NotBindingBody { body });
        }
        if !(MIN_SEALED_SEATS_V1..=MAX_SEALED_SEATS_V1).contains(&seats) {
            return Err(BallotTallyErrorV1::SeatsOutOfRange { seats });
        }
        let (aye, nay, abstain) = (u64::from(aye), u64::from(nay), u64::from(abstain));
        let accepted = aye
            .checked_add(nay)
            .and_then(|sum| sum.checked_add(abstain))
            .ok_or(BallotTallyErrorV1::Overflow)?;
        if accepted > u64::from(seats) {
            return Err(BallotTallyErrorV1::CorpusExceedsSeats { accepted, seats });
        }
        let quorum = u64::from(parliament_quorum_seats_v1(u32::from(seats)));
        let floor = quorum.max(u64::from(MIN_TURNOUT_V1));
        let outcome = if accepted < floor {
            BallotOutcomeV1::NoQuorum
        } else if body == ParliamentBody::PolicyJury && risk_tier == RiskTierV1::Emergency {
            if aye > nay && aye >= quorum {
                BallotOutcomeV1::Approved
            } else {
                BallotOutcomeV1::Rejected
            }
        } else if aye > nay {
            BallotOutcomeV1::Approved
        } else {
            BallotOutcomeV1::Rejected
        };
        // Only an approval has `A > N`, so the margin cannot underflow.
        let narrow = outcome == BallotOutcomeV1::Approved && {
            let margin = aye
                .checked_sub(nay)
                .and_then(|margin| margin.checked_mul(100))
                .ok_or(BallotTallyErrorV1::Overflow)?;
            let decisive = aye
                .checked_add(nay)
                .and_then(|decisive| decisive.checked_mul(5))
                .ok_or(BallotTallyErrorV1::Overflow)?;
            margin < decisive
        };
        Ok(BallotDecisionV1 { outcome, narrow })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::anonymous_ballot::framing::{decode_enc, enc};

    fn decide(
        body: ParliamentBody,
        tier: RiskTierV1,
        seats: u16,
        (aye, nay, abstain): (u32, u32, u32),
    ) -> Result<BallotDecisionV1, BallotTallyErrorV1> {
        ParliamentDecisionRuleV1::V1.decide(body, tier, seats, aye, nay, abstain)
    }

    const fn decision(outcome: BallotOutcomeV1, narrow: bool) -> BallotDecisionV1 {
        BallotDecisionV1 { outcome, narrow }
    }

    const POLICY: ParliamentBody = ParliamentBody::PolicyJury;
    const CONFIRMATION: ParliamentBody = ParliamentBody::ConfirmationJury;
    const APPROVED: BallotOutcomeV1 = BallotOutcomeV1::Approved;
    const REJECTED: BallotOutcomeV1 = BallotOutcomeV1::Rejected;
    const NO_QUORUM: BallotOutcomeV1 = BallotOutcomeV1::NoQuorum;

    #[test]
    fn three_seats_need_all_three_ballots() {
        // S = 3: Q = 2, floor = max(3, 2) = 3.
        let standard = RiskTierV1::Standard;
        assert_eq!(
            decide(POLICY, standard, 3, (2, 0, 0)),
            Ok(decision(NO_QUORUM, false))
        );
        assert_eq!(
            decide(POLICY, standard, 3, (1, 1, 0)),
            Ok(decision(NO_QUORUM, false))
        );
        assert_eq!(
            decide(POLICY, standard, 3, (2, 1, 0)),
            Ok(decision(APPROVED, false))
        );
        assert_eq!(
            decide(POLICY, standard, 3, (1, 0, 2)),
            Ok(decision(APPROVED, false))
        );
        assert_eq!(
            decide(POLICY, standard, 3, (1, 1, 1)),
            Ok(decision(REJECTED, false))
        );
        // Strategic abstention at S = 3 is NoQuorum, not a retry.
        assert_eq!(
            decide(POLICY, standard, 3, (0, 0, 2)),
            Ok(decision(NO_QUORUM, false))
        );
        assert_eq!(
            decide(POLICY, standard, 3, (0, 0, 3)),
            Ok(decision(REJECTED, false))
        );
    }

    #[test]
    fn ties_reject_for_every_body_and_tier() {
        for body in [POLICY, CONFIRMATION] {
            for tier in [
                RiskTierV1::Routine,
                RiskTierV1::Standard,
                RiskTierV1::Constitutional,
                RiskTierV1::Emergency,
            ] {
                assert_eq!(
                    decide(body, tier, 10, (4, 4, 0)),
                    Ok(decision(REJECTED, false))
                );
                assert_eq!(
                    decide(body, tier, 10, (3, 3, 4)),
                    Ok(decision(REJECTED, false))
                );
            }
        }
    }

    #[test]
    fn the_emergency_quorum_applies_to_the_policy_jury_only() {
        // S = 9: Q = 6.
        let emergency = RiskTierV1::Emergency;
        assert_eq!(
            decide(POLICY, emergency, 9, (6, 3, 0)),
            Ok(decision(APPROVED, false))
        );
        assert_eq!(
            decide(POLICY, emergency, 9, (5, 3, 1)),
            Ok(decision(REJECTED, false))
        );
        assert_eq!(
            decide(POLICY, RiskTierV1::Standard, 9, (5, 3, 1)),
            Ok(decision(APPROVED, false))
        );
        assert_eq!(
            decide(CONFIRMATION, emergency, 9, (5, 3, 1)),
            Ok(decision(APPROVED, false))
        );
        // A = Q exactly is enough; A = Q - 1 is not, even with no Nay.
        assert_eq!(
            decide(POLICY, emergency, 9, (6, 0, 0)),
            Ok(decision(APPROVED, false))
        );
        assert_eq!(
            decide(POLICY, emergency, 9, (5, 0, 1)),
            Ok(decision(REJECTED, false))
        );
    }

    #[test]
    fn the_narrow_edge_is_strictly_below_five_percent() {
        // S = 30: Q = 20.
        let standard = RiskTierV1::Standard;
        // 100 * 1 < 5 * 21 = 105: narrow.
        assert_eq!(
            decide(POLICY, standard, 30, (11, 10, 0)),
            Ok(decision(APPROVED, true))
        );
        // 100 * 1 < 5 * 19 = 95 is false: not narrow.
        assert_eq!(
            decide(POLICY, standard, 30, (10, 9, 1)),
            Ok(decision(APPROVED, false))
        );
        // S = 60: Q = 40. At the edge 100 * 2 = 5 * 40 the approval is not narrow; one
        // more Nay makes 100 * 1 < 5 * 41 = 205 narrow.
        assert_eq!(
            decide(POLICY, standard, 60, (21, 19, 0)),
            Ok(decision(APPROVED, false))
        );
        assert_eq!(
            decide(POLICY, standard, 60, (21, 20, 0)),
            Ok(decision(APPROVED, true))
        );
        // An emergency Policy approval needs A >= Q >= 2S/3, so N <= S/3 and it is never
        // narrow; the same counts are narrow for Confirmation.
        assert_eq!(
            decide(POLICY, RiskTierV1::Emergency, 30, (20, 10, 0)),
            Ok(decision(APPROVED, false))
        );
        assert_eq!(
            decide(POLICY, RiskTierV1::Emergency, 30, (11, 10, 0)),
            Ok(decision(REJECTED, false))
        );
        assert_eq!(
            decide(CONFIRMATION, RiskTierV1::Emergency, 30, (11, 10, 0)),
            Ok(decision(APPROVED, true))
        );
        // Only approvals are narrow.
        assert_eq!(
            decide(POLICY, standard, 30, (10, 11, 0)),
            Ok(decision(REJECTED, false))
        );
        // Unanimity is never narrow.
        assert_eq!(
            decide(POLICY, standard, 1_000, (1_000, 0, 0)),
            Ok(decision(APPROVED, false))
        );
    }

    #[test]
    fn turnout_one_below_the_floor_is_no_quorum() {
        // S = 1000: Q = 667 = floor.
        let standard = RiskTierV1::Standard;
        assert_eq!(
            decide(POLICY, standard, 1_000, (666, 0, 0)),
            Ok(decision(NO_QUORUM, false))
        );
        assert_eq!(
            decide(POLICY, standard, 1_000, (667, 0, 0)),
            Ok(decision(APPROVED, false))
        );
        // S = 4: Q = 3 = floor.
        assert_eq!(
            decide(POLICY, standard, 4, (2, 0, 0)),
            Ok(decision(NO_QUORUM, false))
        );
        assert_eq!(
            decide(POLICY, standard, 4, (2, 0, 1)),
            Ok(decision(APPROVED, false))
        );
        // S = 5: Q = 4.
        assert_eq!(
            decide(POLICY, standard, 5, (3, 0, 0)),
            Ok(decision(NO_QUORUM, false))
        );
        assert_eq!(
            decide(POLICY, standard, 5, (3, 1, 0)),
            Ok(decision(APPROVED, false))
        );
    }

    #[test]
    fn malformed_tallies_are_errors() {
        let standard = RiskTierV1::Standard;
        assert_eq!(
            decide(ParliamentBody::ReviewPanel, standard, 10, (5, 0, 0)),
            Err(BallotTallyErrorV1::NotBindingBody {
                body: ParliamentBody::ReviewPanel
            })
        );
        for seats in [0, 2, 1_001, u16::MAX] {
            assert_eq!(
                decide(POLICY, standard, seats, (0, 0, 0)),
                Err(BallotTallyErrorV1::SeatsOutOfRange { seats })
            );
        }
        assert_eq!(
            decide(POLICY, standard, 3, (2, 1, 1)),
            Err(BallotTallyErrorV1::CorpusExceedsSeats {
                accepted: 4,
                seats: 3
            })
        );
        // No u32 count can overflow the 64-bit checked sums.
        assert_eq!(
            decide(POLICY, standard, 1_000, (u32::MAX, u32::MAX, u32::MAX)),
            Err(BallotTallyErrorV1::CorpusExceedsSeats {
                accepted: 3 * u64::from(u32::MAX),
                seats: 1_000
            })
        );
    }

    #[test]
    fn outcomes_and_the_rule_round_trip() {
        for outcome in [APPROVED, REJECTED, NO_QUORUM] {
            assert_eq!(
                decode_enc::<BallotOutcomeV1>(&enc(&outcome).expect("enc")),
                Ok(outcome)
            );
            let json = norito::json::to_json(&outcome).expect("json");
            assert_eq!(
                norito::json::from_str::<BallotOutcomeV1>(&json).expect("json"),
                outcome
            );
        }
        let rule = ParliamentDecisionRuleV1::V1;
        assert_eq!(
            decode_enc::<ParliamentDecisionRuleV1>(&enc(&rule).expect("enc")),
            Ok(rule)
        );
        let json = norito::json::to_json(&rule).expect("json");
        assert_eq!(json, r#"{"kind":"strict_aye_majority","detail":null}"#);
        assert_eq!(
            norito::json::from_str::<ParliamentDecisionRuleV1>(&json).expect("json"),
            rule
        );
    }
}
