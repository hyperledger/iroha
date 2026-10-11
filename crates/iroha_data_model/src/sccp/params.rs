//! SCCP v1 consensus parameters (`specs/sccp.md` §4.1).
//!
//! [`SccpParametersV1`] is one Taira-internal value stored in dedicated world state. It is written
//! only by the genesis-only `InitializeSccpV1` instruction and by the Parliament-enacted
//! `SetParameters` action, and both check every rule of the §4.1 table, including the joint
//! rules, against the complete new value.
//!
//! [`SccpParametersV1::validate`] checks the rules that read only the value. Two rules read a
//! value owned elsewhere: the lower bound of `fast_pause_hold_ms` (the Parliament attempt
//! latency) and the staking floor L1 of `committee_validity_ms` (the unbonding delay of the
//! genesis-pinned staking policy). [`SccpParametersV1::validate_against`] checks the whole table
//! with those two values supplied in a [`SccpParameterContextV1`].

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// `MAX_VALIDITY_MS` (30 d, §3.9): the immutable destination bound on the validity a rotation
/// grants a committee generation, and the cap of `committee_validity_ms`.
pub const SCCP_MAX_VALIDITY_MS_V1: u64 =
    crate::sumeragi_finality::certified_result::MAX_VALIDITY_MS;
/// `MAX_FAST_PAUSE_MS` (30 d, §3.9): the immutable destination clamp on a fast pause.
pub const SCCP_MAX_FAST_PAUSE_MS_V1: u64 = 2_592_000_000;
/// `SCCP_MIN_EPOCH_MS` (1 h, §3.9): the smallest epoch duration while SCCP exists (§4.2) and
/// the smallest admitted `fast_pause_panel_term_ms`.
pub const SCCP_MIN_EPOCH_MS_V1: u64 = 3_600_000;
/// `SCCP_MIN_HEARTBEAT_MS` (1 h, §3.9): the smallest admitted `committee_heartbeat_ms`.
pub const SCCP_MIN_HEARTBEAT_MS_V1: u64 = 3_600_000;
/// `SCCP_PIN_MARGIN_MS` (1 d, §3.9): the margin a committee pin keeps beyond one heartbeat
/// (§4.14.3 P2), and the margin of the joint `committee_validity_ms` lower bound that keeps P2
/// satisfiable.
pub const SCCP_PIN_MARGIN_MS_V1: u64 = 86_400_000;
/// Maximum SCCP messages (transfers and controls together) committed by one Taira block (§3.4).
pub const SCCP_MESSAGES_MAX_PER_BLOCK_V1: u32 = 512;
/// Smallest admitted `forgery_evidence_grace_ms` (1 d).
pub const SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1: u64 = 86_400_000;
/// Largest admitted `forgery_evidence_grace_ms` (30 d).
pub const SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1: u64 = 2_592_000_000;
/// Largest admitted `destination_progress_cap_ms` (30 d, §4.8 L5).
pub const SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1: u64 = 2_592_000_000;
/// Smallest admitted `outbound_ttl_ms` (1 d).
pub const SCCP_MIN_OUTBOUND_TTL_MS_V1: u64 = 86_400_000;
/// Largest admitted `outbound_ttl_ms` (90 d).
pub const SCCP_MAX_OUTBOUND_TTL_MS_V1: u64 = 7_776_000_000;
/// Largest admitted `min_outbound_amount` in Taira units (1 000 000 XOR).
pub const SCCP_MAX_MIN_OUTBOUND_AMOUNT_V1: u128 = 1_000_000_000_000_000;
/// Largest admitted `inbound_self_claim_fee` in Taira units (10 XOR).
pub const SCCP_MAX_INBOUND_SELF_CLAIM_FEE_V1: u128 = 10_000_000_000;
/// Sum of the fixed per-class exempt quotas of one block (§4.19): `Keepalive` 1,
/// `ForgeryEvidence` 1 and `KeeperAdvance` 1 for each of the three external networks.
pub const SCCP_FIXED_EXEMPT_QUOTAS_PER_BLOCK_V1: u32 = 5;
/// Smallest admitted `max_exempt_transactions_per_block`.
pub const SCCP_MIN_EXEMPT_TRANSACTIONS_PER_BLOCK_V1: u32 = 8;
/// Largest admitted `max_exempt_transactions_per_block`.
pub const SCCP_MAX_EXEMPT_TRANSACTIONS_PER_BLOCK_V1: u32 = 1_024;
/// The admitted values of `fast_pause_panel_seats`.
pub const SCCP_FAST_PAUSE_PANEL_SEATS_V1: [u32; 3] = [5, 7, 9];
/// Smallest admitted `fast_pause_seat_accept_window_ms` (10 min).
pub const SCCP_MIN_FAST_PAUSE_SEAT_ACCEPT_WINDOW_MS_V1: u64 = 600_000;
/// Smallest admitted `fast_pause_endorse_window_ms` (5 min).
pub const SCCP_MIN_FAST_PAUSE_ENDORSE_WINDOW_MS_V1: u64 = 300_000;
/// Largest admitted `fast_pause_endorse_window_ms` (6 h).
pub const SCCP_MAX_FAST_PAUSE_ENDORSE_WINDOW_MS_V1: u64 = 21_600_000;
/// Margin `fast_pause_hold_ms` keeps below [`SCCP_MAX_FAST_PAUSE_MS_V1`] (1 d).
pub const SCCP_FAST_PAUSE_HOLD_MARGIN_MS_V1: u64 = 86_400_000;

// §4.1: every admitted `max_exempt_transactions_per_block` is at least the fixed per-class
// quotas plus one, so every admitted value leaves room for self-claims.
const _: () =
    assert!(SCCP_MIN_EXEMPT_TRANSACTIONS_PER_BLOCK_V1 > SCCP_FIXED_EXEMPT_QUOTAS_PER_BLOCK_V1);

/// SCCP consensus parameters (`sccp_parameters` world state, §4.1).
///
/// Every field is Parliament-settable within its rule. Windows are milliseconds of Taira block
/// time, never block counts, because Iroha produces no empty blocks.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sccp::params::SccpParametersV1")]
pub struct SccpParametersV1 {
    /// Value-moving switch: when false, recording fails and inbound settlement and outbound
    /// refunds stay `Pending`; generations, finality headers, light clients, evidence, fast
    /// pauses and Parliament enactment keep running.
    pub enabled: bool,
    /// Validity a rotation grants the successor committee generation
    /// (`deadline_ms = start_timestamp_ms + validity`).
    pub committee_validity_ms: u64,
    /// Heartbeat: a generation this old ends at the next block even when its keys stay.
    pub committee_heartbeat_ms: u64,
    /// Time after a generation's deadline during which forgery evidence against it still slashes.
    pub forgery_evidence_grace_ms: u64,
    /// Longest time the destination-progress gate keeps an ended generation liable (§4.8 L5).
    pub destination_progress_cap_ms: u64,
    /// Outbound deadline offset from the record block's creation time.
    pub outbound_ttl_ms: u64,
    /// Floor per outbound message, in Taira units (a decimal string in JSON).
    #[norito(json = "crate::json_helpers::u128_string")]
    pub min_outbound_amount: u128,
    /// Fee deducted from the proceeds of a fee-exempt inbound self-claim, in Taira units (a
    /// decimal string in JSON).
    #[norito(json = "crate::json_helpers::u128_string")]
    pub inbound_self_claim_fee: u128,
    /// Cap on fee-exempt SCCP transactions per block.
    pub max_exempt_transactions_per_block: u32,
    /// Seats `k` of the primary and of the backup fast pause panel (§4.14.7).
    pub fast_pause_panel_seats: u32,
    /// Term of a seated fast pause panel; a new panel is drawn at the first epoch boundary at or
    /// after its end.
    pub fast_pause_panel_term_ms: u64,
    /// Time after seating during which a drawn member accepts its seat before it passes on.
    pub fast_pause_seat_accept_window_ms: u64,
    /// Lifetime of one fast pause endorsement round.
    pub fast_pause_endorse_window_ms: u64,
    /// Lead before a fast pause lapses from which a renewal round may open.
    pub fast_pause_renew_lead_ms: u64,
    /// Time one fast pause enactment holds a network.
    pub fast_pause_hold_ms: u64,
}

/// Values the §4.1 table reads from outside [`SccpParametersV1`].
///
/// Core fills it at `InitializeSccpV1` and at `SetParameters` enactment: the latency from its
/// one Parliament seam (`sccp::parliament_iface`) and the delay from the node's staking policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SccpParameterContextV1 {
    /// `parliament_sccp_attempt_latency_ms()` (§4.1, §10.1): the latency of one full-track SCCP
    /// Parliament attempt, or `None` while the Parliament pipeline does not provide it.
    ///
    /// `None` defers the lower bound of `fast_pause_hold_ms`: it is never read as zero.
    pub parliament_sccp_attempt_latency_ms: Option<u64>,
    /// `nexus.staking.unbonding_delay_ms` of the genesis-pinned staking policy (§4.8 L1).
    pub unbonding_delay_ms: u64,
}

/// A violated rule of the §4.1 parameter table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SccpParametersError {
    /// `fast_pause_hold_ms + 2 × committee_heartbeat_ms + 86 400 000` exceeds
    /// `committee_validity_ms`.
    #[error(
        "committee_validity_ms must be at least fast_pause_hold_ms + 2 × committee_heartbeat_ms + 86 400 000 ms"
    )]
    CommitteeValidityTooShort,
    /// `committee_validity_ms` exceeds [`SCCP_MAX_VALIDITY_MS_V1`].
    #[error("committee_validity_ms must not exceed 2 592 000 000 ms")]
    CommitteeValidityTooLong,
    /// `committee_validity_ms + forgery_evidence_grace_ms` exceeds the unbonding delay of the
    /// pinned staking policy (§4.8 L1).
    #[error(
        "committee_validity_ms + forgery_evidence_grace_ms must not exceed the staking unbonding_delay_ms"
    )]
    UnbondingDelayTooShort,
    /// `committee_heartbeat_ms` is below [`SCCP_MIN_HEARTBEAT_MS_V1`].
    #[error("committee_heartbeat_ms must be at least 3 600 000 ms")]
    CommitteeHeartbeatTooShort,
    /// `forgery_evidence_grace_ms` is outside 1 d..=30 d.
    #[error("forgery_evidence_grace_ms must be within 86 400 000..=2 592 000 000 ms")]
    ForgeryEvidenceGraceOutOfRange,
    /// `destination_progress_cap_ms` exceeds [`SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1`].
    #[error("destination_progress_cap_ms must not exceed 2 592 000 000 ms")]
    DestinationProgressCapTooLong,
    /// `outbound_ttl_ms` is outside 1 d..=90 d.
    #[error("outbound_ttl_ms must be within 86 400 000..=7 776 000 000 ms")]
    OutboundTtlOutOfRange,
    /// `min_outbound_amount` is outside `1..=10^15`.
    #[error("min_outbound_amount must be within 1..=10^15 Taira units")]
    MinOutboundAmountOutOfRange,
    /// `inbound_self_claim_fee` exceeds `10^10`.
    #[error("inbound_self_claim_fee must not exceed 10^10 Taira units")]
    InboundSelfClaimFeeTooLarge,
    /// `max_exempt_transactions_per_block` is outside `8..=1 024`.
    #[error("max_exempt_transactions_per_block must be within 8..=1 024")]
    ExemptTransactionsOutOfRange,
    /// `fast_pause_panel_seats` is not 5, 7 or 9.
    #[error("fast_pause_panel_seats must be 5, 7 or 9")]
    FastPausePanelSeatsNotAdmitted,
    /// `fast_pause_panel_term_ms` is below [`SCCP_MIN_EPOCH_MS_V1`].
    #[error("fast_pause_panel_term_ms must be at least 3 600 000 ms")]
    FastPausePanelTermTooShort,
    /// `fast_pause_seat_accept_window_ms` is outside `600 000..=fast_pause_panel_term_ms / 2`.
    #[error(
        "fast_pause_seat_accept_window_ms must be within 600 000..=fast_pause_panel_term_ms / 2 ms"
    )]
    FastPauseSeatAcceptWindowOutOfRange,
    /// `fast_pause_endorse_window_ms` is outside `300 000..=21 600 000`.
    #[error("fast_pause_endorse_window_ms must be within 300 000..=21 600 000 ms")]
    FastPauseEndorseWindowOutOfRange,
    /// `fast_pause_renew_lead_ms` is outside
    /// `2 × fast_pause_endorse_window_ms..=fast_pause_hold_ms / 2`.
    #[error(
        "fast_pause_renew_lead_ms must be within 2 × fast_pause_endorse_window_ms..=fast_pause_hold_ms / 2 ms"
    )]
    FastPauseRenewLeadOutOfRange,
    /// `fast_pause_hold_ms` is below the Parliament attempt latency.
    #[error("fast_pause_hold_ms must be at least the Parliament SCCP attempt latency")]
    FastPauseHoldBelowAttemptLatency,
    /// `fast_pause_hold_ms` exceeds [`SCCP_MAX_FAST_PAUSE_MS_V1`] minus
    /// [`SCCP_FAST_PAUSE_HOLD_MARGIN_MS_V1`].
    #[error("fast_pause_hold_ms must not exceed 2 505 600 000 ms")]
    FastPauseHoldTooLong,
}

impl SccpParametersV1 {
    /// Return the Taira genesis values of the §4.1 table.
    #[must_use]
    pub const fn taira_default() -> Self {
        Self {
            enabled: true,
            committee_validity_ms: 1_209_600_000,
            committee_heartbeat_ms: 86_400_000,
            forgery_evidence_grace_ms: 604_800_000,
            destination_progress_cap_ms: 2_592_000_000,
            outbound_ttl_ms: 604_800_000,
            min_outbound_amount: 1_000_000_000,
            inbound_self_claim_fee: 10_000_000,
            max_exempt_transactions_per_block: 32,
            fast_pause_panel_seats: 9,
            fast_pause_panel_term_ms: 604_800_000,
            fast_pause_seat_accept_window_ms: 43_200_000,
            fast_pause_endorse_window_ms: 1_800_000,
            fast_pause_renew_lead_ms: 86_400_000,
            fast_pause_hold_ms: 864_000_000,
        }
    }

    /// Return the quorum of one fast pause panel: `parliament_quorum_seats_v1` of
    /// `fast_pause_panel_seats`, which is 4, 5 and 6 for the admitted 5, 7 and 9 seats.
    #[must_use]
    pub const fn fast_pause_panel_quorum(&self) -> u32 {
        crate::governance::types::parliament_quorum_seats_v1(self.fast_pause_panel_seats)
    }

    /// Check every rule of the §4.1 table that reads only this value, including the joint rules.
    ///
    /// Joint bounds use checked arithmetic: a lower bound that overflows `u64` can never be met,
    /// so it reports the same violation as any other value below the bound.
    ///
    /// The two rules that read a value from outside the table are checked by
    /// [`Self::validate_against`].
    ///
    /// # Errors
    ///
    /// Returns the first violated rule: every field's own bound in table order, then the joint
    /// rules in table order.
    pub fn validate(&self) -> Result<(), SccpParametersError> {
        self.check_own_bounds()?;
        self.check_joint_rules(None)
    }

    /// Check every rule of the §4.1 table, including the staking floor L1 (§4.8) and the lower
    /// bound of `fast_pause_hold_ms`, against `context`.
    ///
    /// While `context.parliament_sccp_attempt_latency_ms` is `None` the lower bound of
    /// `fast_pause_hold_ms` is deferred, never treated as met by a zero latency: no route can be
    /// registered before the launch gate opens (§10.2), and the gate needs the Parliament
    /// pipeline that provides the latency.
    ///
    /// TODO: WP-S5: require the latency when the launch gate opens, so no fast pause protects a
    /// route with a hold shorter than one Parliament attempt.
    ///
    /// L1 also bounds `validity_ms + grace_ms` of every retained committee generation and
    /// requires `nexus.staking.max_slash_bps ≥ 1`; those parts read state and node configuration
    /// and are checked by Core.
    ///
    /// TODO: WP-S6: the retained-generation and slash-rate parts of L1.
    ///
    /// # Errors
    ///
    /// Returns the first violated rule: every field's own bound in table order, then the joint
    /// rules in table order, with L1 after the validity floor and the attempt latency last.
    pub fn validate_against(
        &self,
        context: &SccpParameterContextV1,
    ) -> Result<(), SccpParametersError> {
        self.check_own_bounds()?;
        self.check_joint_rules(Some(context))
    }

    /// Check the bounds that read one field alone, in table order.
    fn check_own_bounds(&self) -> Result<(), SccpParametersError> {
        if self.committee_validity_ms > SCCP_MAX_VALIDITY_MS_V1 {
            return Err(SccpParametersError::CommitteeValidityTooLong);
        }
        if self.committee_heartbeat_ms < SCCP_MIN_HEARTBEAT_MS_V1 {
            return Err(SccpParametersError::CommitteeHeartbeatTooShort);
        }
        if !(SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1..=SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1)
            .contains(&self.forgery_evidence_grace_ms)
        {
            return Err(SccpParametersError::ForgeryEvidenceGraceOutOfRange);
        }
        if self.destination_progress_cap_ms > SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1 {
            return Err(SccpParametersError::DestinationProgressCapTooLong);
        }
        if !(SCCP_MIN_OUTBOUND_TTL_MS_V1..=SCCP_MAX_OUTBOUND_TTL_MS_V1)
            .contains(&self.outbound_ttl_ms)
        {
            return Err(SccpParametersError::OutboundTtlOutOfRange);
        }
        if !(1..=SCCP_MAX_MIN_OUTBOUND_AMOUNT_V1).contains(&self.min_outbound_amount) {
            return Err(SccpParametersError::MinOutboundAmountOutOfRange);
        }
        if self.inbound_self_claim_fee > SCCP_MAX_INBOUND_SELF_CLAIM_FEE_V1 {
            return Err(SccpParametersError::InboundSelfClaimFeeTooLarge);
        }
        if !(SCCP_MIN_EXEMPT_TRANSACTIONS_PER_BLOCK_V1..=SCCP_MAX_EXEMPT_TRANSACTIONS_PER_BLOCK_V1)
            .contains(&self.max_exempt_transactions_per_block)
        {
            return Err(SccpParametersError::ExemptTransactionsOutOfRange);
        }
        if !SCCP_FAST_PAUSE_PANEL_SEATS_V1.contains(&self.fast_pause_panel_seats) {
            return Err(SccpParametersError::FastPausePanelSeatsNotAdmitted);
        }
        if self.fast_pause_panel_term_ms < SCCP_MIN_EPOCH_MS_V1 {
            return Err(SccpParametersError::FastPausePanelTermTooShort);
        }
        if self.fast_pause_seat_accept_window_ms < SCCP_MIN_FAST_PAUSE_SEAT_ACCEPT_WINDOW_MS_V1 {
            return Err(SccpParametersError::FastPauseSeatAcceptWindowOutOfRange);
        }
        if !(SCCP_MIN_FAST_PAUSE_ENDORSE_WINDOW_MS_V1..=SCCP_MAX_FAST_PAUSE_ENDORSE_WINDOW_MS_V1)
            .contains(&self.fast_pause_endorse_window_ms)
        {
            return Err(SccpParametersError::FastPauseEndorseWindowOutOfRange);
        }
        if self.fast_pause_hold_ms > SCCP_MAX_FAST_PAUSE_MS_V1 - SCCP_FAST_PAUSE_HOLD_MARGIN_MS_V1 {
            return Err(SccpParametersError::FastPauseHoldTooLong);
        }
        Ok(())
    }

    /// Check the rules that relate two fields, or a field and `context`, in table order; the
    /// rules that read `context` are skipped without one.
    fn check_joint_rules(
        &self,
        context: Option<&SccpParameterContextV1>,
    ) -> Result<(), SccpParametersError> {
        let validity_floor = self
            .committee_heartbeat_ms
            .checked_mul(2)
            .and_then(|value| value.checked_add(self.fast_pause_hold_ms))
            .and_then(|value| value.checked_add(SCCP_PIN_MARGIN_MS_V1));
        if validity_floor.is_none_or(|floor| floor > self.committee_validity_ms) {
            return Err(SccpParametersError::CommitteeValidityTooShort);
        }
        if let Some(context) = context {
            let liable_ms = self
                .committee_validity_ms
                .checked_add(self.forgery_evidence_grace_ms);
            if liable_ms.is_none_or(|liable| liable > context.unbonding_delay_ms) {
                return Err(SccpParametersError::UnbondingDelayTooShort);
            }
        }
        if self.fast_pause_seat_accept_window_ms > self.fast_pause_panel_term_ms / 2 {
            return Err(SccpParametersError::FastPauseSeatAcceptWindowOutOfRange);
        }
        let renew_lead_floor = self.fast_pause_endorse_window_ms.checked_mul(2);
        if renew_lead_floor.is_none_or(|floor| floor > self.fast_pause_renew_lead_ms)
            || self.fast_pause_renew_lead_ms > self.fast_pause_hold_ms / 2
        {
            return Err(SccpParametersError::FastPauseRenewLeadOutOfRange);
        }
        let attempt_latency_ms =
            context.and_then(|context| context.parliament_sccp_attempt_latency_ms);
        if attempt_latency_ms.is_some_and(|latency| self.fast_pause_hold_ms < latency) {
            return Err(SccpParametersError::FastPauseHoldBelowAttemptLatency);
        }
        Ok(())
    }

    /// Return the first `u64` field above `maximum`, naming it for the proposal invariant.
    ///
    /// Parliament proposals must keep every `u64` exact in IEEE-754 binary64 SDK runtimes
    /// (`first_release_exact_json_u64_invariant_error`). The table rules already imply the bound
    /// for valid values; this check is independent of [`Self::validate`].
    #[must_use]
    pub fn first_json_u64_violation(&self, maximum: u64) -> Option<&'static str> {
        [
            (
                self.committee_validity_ms,
                "SCCP parameters committee_validity_ms exceeds the exact JSON integer maximum",
            ),
            (
                self.committee_heartbeat_ms,
                "SCCP parameters committee_heartbeat_ms exceeds the exact JSON integer maximum",
            ),
            (
                self.forgery_evidence_grace_ms,
                "SCCP parameters forgery_evidence_grace_ms exceeds the exact JSON integer maximum",
            ),
            (
                self.destination_progress_cap_ms,
                "SCCP parameters destination_progress_cap_ms exceeds the exact JSON integer maximum",
            ),
            (
                self.outbound_ttl_ms,
                "SCCP parameters outbound_ttl_ms exceeds the exact JSON integer maximum",
            ),
            (
                self.fast_pause_panel_term_ms,
                "SCCP parameters fast_pause_panel_term_ms exceeds the exact JSON integer maximum",
            ),
            (
                self.fast_pause_seat_accept_window_ms,
                "SCCP parameters fast_pause_seat_accept_window_ms exceeds the exact JSON integer maximum",
            ),
            (
                self.fast_pause_endorse_window_ms,
                "SCCP parameters fast_pause_endorse_window_ms exceeds the exact JSON integer maximum",
            ),
            (
                self.fast_pause_renew_lead_ms,
                "SCCP parameters fast_pause_renew_lead_ms exceeds the exact JSON integer maximum",
            ),
            (
                self.fast_pause_hold_ms,
                "SCCP parameters fast_pause_hold_ms exceeds the exact JSON integer maximum",
            ),
        ]
        .into_iter()
        .find_map(|(value, message)| (value > maximum).then_some(message))
    }
}

#[cfg(test)]
mod tests;
