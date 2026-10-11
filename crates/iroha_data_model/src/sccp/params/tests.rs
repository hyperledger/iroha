//! Unit tests for the SCCP v1 consensus parameters: every rule of the `specs/sccp.md` §4.1 table.

use super::*;
use crate::sccp::registry::SCCP_ROUTE_NETWORKS_V1;
use norito::codec::DecodeAll as _;

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;
const JSON_MAX: u64 = (1_u64 << 53) - 1;
/// Unbonding delay of the SCCP staking profile (21 d, §4.8 L1).
const SCCP_UNBONDING_DELAY_MS: u64 = 1_814_400_000;

fn with(update: impl FnOnce(&mut SccpParametersV1)) -> SccpParametersV1 {
    let mut parameters = SccpParametersV1::taira_default();
    update(&mut parameters);
    parameters
}

/// The context of the SCCP staking profile with the given Parliament attempt latency.
fn context(parliament_sccp_attempt_latency_ms: Option<u64>) -> SccpParameterContextV1 {
    SccpParameterContextV1 {
        parliament_sccp_attempt_latency_ms,
        unbonding_delay_ms: SCCP_UNBONDING_DELAY_MS,
    }
}

#[test]
fn constants_match_the_spec_constant_summary() {
    assert_eq!(SCCP_MAX_VALIDITY_MS_V1, 30 * DAY_MS);
    assert_eq!(SCCP_MAX_FAST_PAUSE_MS_V1, 30 * DAY_MS);
    assert_eq!(SCCP_MIN_EPOCH_MS_V1, HOUR_MS);
    assert_eq!(SCCP_MIN_HEARTBEAT_MS_V1, HOUR_MS);
    assert_eq!(SCCP_PIN_MARGIN_MS_V1, DAY_MS);
    assert_eq!(SCCP_MESSAGES_MAX_PER_BLOCK_V1, 512);
    assert_eq!(SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1, DAY_MS);
    assert_eq!(SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1, 30 * DAY_MS);
    assert_eq!(SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1, 30 * DAY_MS);
    assert_eq!(SCCP_MIN_OUTBOUND_TTL_MS_V1, DAY_MS);
    assert_eq!(SCCP_MAX_OUTBOUND_TTL_MS_V1, 90 * DAY_MS);
    assert_eq!(SCCP_MAX_MIN_OUTBOUND_AMOUNT_V1, 10_u128.pow(15));
    assert_eq!(SCCP_MAX_INBOUND_SELF_CLAIM_FEE_V1, 10_u128.pow(10));
    assert_eq!(SCCP_MIN_EXEMPT_TRANSACTIONS_PER_BLOCK_V1, 8);
    assert_eq!(SCCP_MAX_EXEMPT_TRANSACTIONS_PER_BLOCK_V1, 1_024);
    assert_eq!(SCCP_FAST_PAUSE_PANEL_SEATS_V1, [5, 7, 9]);
    assert_eq!(SCCP_MIN_FAST_PAUSE_SEAT_ACCEPT_WINDOW_MS_V1, 10 * MINUTE_MS);
    assert_eq!(SCCP_MIN_FAST_PAUSE_ENDORSE_WINDOW_MS_V1, 5 * MINUTE_MS);
    assert_eq!(SCCP_MAX_FAST_PAUSE_ENDORSE_WINDOW_MS_V1, 6 * HOUR_MS);
    assert_eq!(SCCP_FAST_PAUSE_HOLD_MARGIN_MS_V1, DAY_MS);
}

#[test]
fn fixed_exempt_quotas_are_one_keepalive_one_evidence_and_one_advance_per_network() {
    let networks = u32::try_from(SCCP_ROUTE_NETWORKS_V1.len()).expect("three networks");
    assert_eq!(SCCP_FIXED_EXEMPT_QUOTAS_PER_BLOCK_V1, 1 + 1 + networks);
    assert_eq!(SCCP_FIXED_EXEMPT_QUOTAS_PER_BLOCK_V1, 5);
    // Every admitted cap leaves at least one self-claim slot beside the fixed quotas.
    assert!(SCCP_MIN_EXEMPT_TRANSACTIONS_PER_BLOCK_V1 > SCCP_FIXED_EXEMPT_QUOTAS_PER_BLOCK_V1);
}

#[test]
fn taira_default_is_the_genesis_table_and_valid() {
    let parameters = SccpParametersV1::taira_default();
    assert_eq!(
        parameters,
        SccpParametersV1 {
            enabled: true,
            committee_validity_ms: 14 * DAY_MS,
            committee_heartbeat_ms: DAY_MS,
            forgery_evidence_grace_ms: 7 * DAY_MS,
            destination_progress_cap_ms: 30 * DAY_MS,
            outbound_ttl_ms: 7 * DAY_MS,
            min_outbound_amount: 10_u128.pow(9),
            inbound_self_claim_fee: 10_u128.pow(7),
            max_exempt_transactions_per_block: 32,
            fast_pause_panel_seats: 9,
            fast_pause_panel_term_ms: 7 * DAY_MS,
            fast_pause_seat_accept_window_ms: 12 * HOUR_MS,
            fast_pause_endorse_window_ms: 30 * MINUTE_MS,
            fast_pause_renew_lead_ms: DAY_MS,
            fast_pause_hold_ms: 10 * DAY_MS,
        }
    );
    assert_eq!(parameters.validate(), Ok(()));
    assert_eq!(with(|p| p.enabled = false).validate(), Ok(()));
    // §4.1: the validity rule gives 10 d + 2 × 1 d + 1 d = 13 d ≤ 14 d, and the unbonding rule
    // gives 14 d + 7 d = 21 d, which the SCCP staking profile meets exactly.
    assert_eq!(
        parameters.fast_pause_hold_ms + 2 * parameters.committee_heartbeat_ms + DAY_MS,
        13 * DAY_MS
    );
    assert_eq!(
        parameters.committee_validity_ms + parameters.forgery_evidence_grace_ms,
        SCCP_UNBONDING_DELAY_MS
    );
    assert_eq!(parameters.validate_against(&context(None)), Ok(()));
}

#[test]
fn committee_validity_joint_lower_bound() {
    // 10 d + 2 × 1 d + 1 d.
    let floor = 13 * DAY_MS;
    assert_eq!(with(|p| p.committee_validity_ms = floor).validate(), Ok(()));
    assert_eq!(
        with(|p| p.committee_validity_ms = floor - 1).validate(),
        Err(SccpParametersError::CommitteeValidityTooShort)
    );
    // Raising the hold moves the joint floor with it.
    assert_eq!(
        with(|p| {
            p.committee_validity_ms = floor;
            p.fast_pause_hold_ms = 10 * DAY_MS + 1;
        })
        .validate(),
        Err(SccpParametersError::CommitteeValidityTooShort)
    );
    assert_eq!(
        with(|p| {
            p.committee_validity_ms = floor + 1;
            p.fast_pause_hold_ms = 10 * DAY_MS + 1;
        })
        .validate(),
        Ok(())
    );
    // Raising the heartbeat moves the joint floor twice as fast.
    assert_eq!(
        with(|p| {
            p.committee_validity_ms = floor + 1;
            p.committee_heartbeat_ms = DAY_MS + 1;
        })
        .validate(),
        Err(SccpParametersError::CommitteeValidityTooShort)
    );
    assert_eq!(
        with(|p| {
            p.committee_validity_ms = floor + 2;
            p.committee_heartbeat_ms = DAY_MS + 1;
        })
        .validate(),
        Ok(())
    );
    // The largest heartbeat that still fits under the 30 d cap with the default hold.
    let largest_heartbeat = (SCCP_MAX_VALIDITY_MS_V1 - 10 * DAY_MS - DAY_MS) / 2;
    assert_eq!(
        with(|p| {
            p.committee_validity_ms = SCCP_MAX_VALIDITY_MS_V1;
            p.committee_heartbeat_ms = largest_heartbeat;
        })
        .validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| {
            p.committee_validity_ms = SCCP_MAX_VALIDITY_MS_V1;
            p.committee_heartbeat_ms = largest_heartbeat + 1;
        })
        .validate(),
        Err(SccpParametersError::CommitteeValidityTooShort)
    );
}

#[test]
fn committee_validity_joint_bound_overflow_is_a_violation() {
    let hold = SccpParametersV1::taira_default().fast_pause_hold_ms;
    // 2 × heartbeat overflows.
    assert_eq!(
        with(|p| p.committee_heartbeat_ms = u64::MAX / 2 + 1).validate(),
        Err(SccpParametersError::CommitteeValidityTooShort)
    );
    // Adding the hold overflows.
    assert_eq!(
        with(|p| p.committee_heartbeat_ms = u64::MAX / 2).validate(),
        Err(SccpParametersError::CommitteeValidityTooShort)
    );
    // Adding the margin overflows.
    assert_eq!(
        with(|p| p.committee_heartbeat_ms = (u64::MAX - hold) / 2).validate(),
        Err(SccpParametersError::CommitteeValidityTooShort)
    );
}

#[test]
fn committee_validity_upper_bound() {
    assert_eq!(
        with(|p| p.committee_validity_ms = SCCP_MAX_VALIDITY_MS_V1).validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| p.committee_validity_ms = SCCP_MAX_VALIDITY_MS_V1 + 1).validate(),
        Err(SccpParametersError::CommitteeValidityTooLong)
    );
}

#[test]
fn committee_heartbeat_boundary() {
    // Shrinking the heartbeat to its floor keeps the joint validity rule satisfied.
    assert_eq!(
        with(|p| p.committee_heartbeat_ms = HOUR_MS).validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| p.committee_heartbeat_ms = HOUR_MS - 1).validate(),
        Err(SccpParametersError::CommitteeHeartbeatTooShort)
    );
    assert_eq!(
        with(|p| p.committee_heartbeat_ms = 0).validate(),
        Err(SccpParametersError::CommitteeHeartbeatTooShort)
    );
}

#[test]
fn forgery_evidence_grace_bounds() {
    for (value, expected) in [
        (DAY_MS, Ok(())),
        (
            DAY_MS - 1,
            Err(SccpParametersError::ForgeryEvidenceGraceOutOfRange),
        ),
        (0, Err(SccpParametersError::ForgeryEvidenceGraceOutOfRange)),
        (30 * DAY_MS, Ok(())),
        (
            30 * DAY_MS + 1,
            Err(SccpParametersError::ForgeryEvidenceGraceOutOfRange),
        ),
    ] {
        assert_eq!(
            with(|p| p.forgery_evidence_grace_ms = value).validate(),
            expected,
            "grace = {value}"
        );
    }
}

#[test]
fn destination_progress_cap_bounds() {
    // Zero is admitted: the gate then never extends a generation's liability (§4.8 L5).
    assert_eq!(
        with(|p| p.destination_progress_cap_ms = 0).validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| p.destination_progress_cap_ms = 30 * DAY_MS).validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| p.destination_progress_cap_ms = 30 * DAY_MS + 1).validate(),
        Err(SccpParametersError::DestinationProgressCapTooLong)
    );
}

#[test]
fn outbound_ttl_bounds() {
    assert_eq!(with(|p| p.outbound_ttl_ms = DAY_MS).validate(), Ok(()));
    assert_eq!(
        with(|p| p.outbound_ttl_ms = DAY_MS - 1).validate(),
        Err(SccpParametersError::OutboundTtlOutOfRange)
    );
    assert_eq!(
        with(|p| p.outbound_ttl_ms = 0).validate(),
        Err(SccpParametersError::OutboundTtlOutOfRange)
    );
    // No other field bounds the TTL: the 90 d ceiling stands alone.
    assert_eq!(with(|p| p.outbound_ttl_ms = 90 * DAY_MS).validate(), Ok(()));
    assert_eq!(
        with(|p| p.outbound_ttl_ms = 90 * DAY_MS + 1).validate(),
        Err(SccpParametersError::OutboundTtlOutOfRange)
    );
}

#[test]
fn min_outbound_amount_bounds() {
    assert_eq!(with(|p| p.min_outbound_amount = 1).validate(), Ok(()));
    assert_eq!(
        with(|p| p.min_outbound_amount = 0).validate(),
        Err(SccpParametersError::MinOutboundAmountOutOfRange)
    );
    assert_eq!(
        with(|p| p.min_outbound_amount = 10_u128.pow(15)).validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| p.min_outbound_amount = 10_u128.pow(15) + 1).validate(),
        Err(SccpParametersError::MinOutboundAmountOutOfRange)
    );
    assert_eq!(
        with(|p| p.min_outbound_amount = u128::MAX).validate(),
        Err(SccpParametersError::MinOutboundAmountOutOfRange)
    );
}

#[test]
fn inbound_self_claim_fee_bound() {
    assert_eq!(with(|p| p.inbound_self_claim_fee = 0).validate(), Ok(()));
    assert_eq!(
        with(|p| p.inbound_self_claim_fee = 10_u128.pow(10)).validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| p.inbound_self_claim_fee = 10_u128.pow(10) + 1).validate(),
        Err(SccpParametersError::InboundSelfClaimFeeTooLarge)
    );
}

#[test]
fn exempt_transactions_bounds() {
    for (value, expected) in [
        (8, Ok(())),
        (7, Err(SccpParametersError::ExemptTransactionsOutOfRange)),
        // The fixed quotas alone, and one self-claim slot beside them, are both below the range.
        (5, Err(SccpParametersError::ExemptTransactionsOutOfRange)),
        (6, Err(SccpParametersError::ExemptTransactionsOutOfRange)),
        (0, Err(SccpParametersError::ExemptTransactionsOutOfRange)),
        (1_024, Ok(())),
        (
            1_025,
            Err(SccpParametersError::ExemptTransactionsOutOfRange),
        ),
    ] {
        assert_eq!(
            with(|p| p.max_exempt_transactions_per_block = value).validate(),
            expected,
            "exempt = {value}"
        );
    }
}

#[test]
fn fast_pause_panel_seats_are_five_seven_or_nine_with_their_quorums() {
    for (seats, quorum) in [(5, 4), (7, 5), (9, 6)] {
        let parameters = with(|p| p.fast_pause_panel_seats = seats);
        assert_eq!(parameters.validate(), Ok(()), "seats = {seats}");
        assert_eq!(
            parameters.fast_pause_panel_quorum(),
            quorum,
            "seats = {seats}"
        );
    }
    for seats in [0, 1, 3, 4, 6, 8, 10, 11, u32::MAX] {
        assert_eq!(
            with(|p| p.fast_pause_panel_seats = seats).validate(),
            Err(SccpParametersError::FastPausePanelSeatsNotAdmitted),
            "seats = {seats}"
        );
    }
}

#[test]
fn fast_pause_panel_term_boundary() {
    // A term of one minimal epoch draws at every boundary; the accept window must then fit in
    // half of it.
    assert_eq!(
        with(|p| {
            p.fast_pause_panel_term_ms = HOUR_MS;
            p.fast_pause_seat_accept_window_ms = 30 * MINUTE_MS;
        })
        .validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| {
            p.fast_pause_panel_term_ms = HOUR_MS - 1;
            p.fast_pause_seat_accept_window_ms = 10 * MINUTE_MS;
        })
        .validate(),
        Err(SccpParametersError::FastPausePanelTermTooShort)
    );
    assert_eq!(
        with(|p| p.fast_pause_panel_term_ms = u64::MAX).validate(),
        Ok(())
    );
}

#[test]
fn fast_pause_seat_accept_window_bounds() {
    // The default term is 7 d, so the window ends at 3.5 d.
    let ceiling = 7 * DAY_MS / 2;
    for (value, expected) in [
        (10 * MINUTE_MS, Ok(())),
        (
            10 * MINUTE_MS - 1,
            Err(SccpParametersError::FastPauseSeatAcceptWindowOutOfRange),
        ),
        (
            0,
            Err(SccpParametersError::FastPauseSeatAcceptWindowOutOfRange),
        ),
        (ceiling, Ok(())),
        (
            ceiling + 1,
            Err(SccpParametersError::FastPauseSeatAcceptWindowOutOfRange),
        ),
    ] {
        assert_eq!(
            with(|p| p.fast_pause_seat_accept_window_ms = value).validate(),
            expected,
            "accept window = {value}"
        );
    }
    // Shrinking the term moves the ceiling with it; an odd term rounds the ceiling down.
    assert_eq!(
        with(|p| {
            p.fast_pause_panel_term_ms = 2 * HOUR_MS + 1;
            p.fast_pause_seat_accept_window_ms = HOUR_MS;
        })
        .validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| {
            p.fast_pause_panel_term_ms = 2 * HOUR_MS + 1;
            p.fast_pause_seat_accept_window_ms = HOUR_MS + 1;
        })
        .validate(),
        Err(SccpParametersError::FastPauseSeatAcceptWindowOutOfRange)
    );
}

#[test]
fn fast_pause_endorse_window_bounds() {
    for (value, expected) in [
        (5 * MINUTE_MS, Ok(())),
        (
            5 * MINUTE_MS - 1,
            Err(SccpParametersError::FastPauseEndorseWindowOutOfRange),
        ),
        (
            0,
            Err(SccpParametersError::FastPauseEndorseWindowOutOfRange),
        ),
        (6 * HOUR_MS, Ok(())),
        (
            6 * HOUR_MS + 1,
            Err(SccpParametersError::FastPauseEndorseWindowOutOfRange),
        ),
        (
            u64::MAX,
            Err(SccpParametersError::FastPauseEndorseWindowOutOfRange),
        ),
    ] {
        assert_eq!(
            with(|p| p.fast_pause_endorse_window_ms = value).validate(),
            expected,
            "endorse window = {value}"
        );
    }
}

#[test]
fn fast_pause_renew_lead_joint_bounds() {
    // Defaults: 2 × 30 min = 1 h ..= 10 d / 2 = 5 d.
    for (value, expected) in [
        (HOUR_MS, Ok(())),
        (
            HOUR_MS - 1,
            Err(SccpParametersError::FastPauseRenewLeadOutOfRange),
        ),
        (0, Err(SccpParametersError::FastPauseRenewLeadOutOfRange)),
        (5 * DAY_MS, Ok(())),
        (
            5 * DAY_MS + 1,
            Err(SccpParametersError::FastPauseRenewLeadOutOfRange),
        ),
    ] {
        assert_eq!(
            with(|p| p.fast_pause_renew_lead_ms = value).validate(),
            expected,
            "renew lead = {value}"
        );
    }
    // Raising the endorse window moves the floor twice as fast.
    assert_eq!(
        with(|p| {
            p.fast_pause_renew_lead_ms = HOUR_MS;
            p.fast_pause_endorse_window_ms = 30 * MINUTE_MS + 1;
        })
        .validate(),
        Err(SccpParametersError::FastPauseRenewLeadOutOfRange)
    );
    // Shrinking the hold moves the ceiling; an odd hold rounds it down.
    assert_eq!(
        with(|p| {
            p.fast_pause_hold_ms = 2 * DAY_MS + 1;
            p.fast_pause_renew_lead_ms = DAY_MS;
        })
        .validate(),
        Ok(())
    );
    assert_eq!(
        with(|p| {
            p.fast_pause_hold_ms = 2 * DAY_MS + 1;
            p.fast_pause_renew_lead_ms = DAY_MS + 1;
        })
        .validate(),
        Err(SccpParametersError::FastPauseRenewLeadOutOfRange)
    );
    // A hold too short for any lead: 2 × 5 min exceeds half of it.
    assert_eq!(
        with(|p| {
            p.fast_pause_endorse_window_ms = 5 * MINUTE_MS;
            p.fast_pause_hold_ms = 20 * MINUTE_MS - 1;
            p.fast_pause_renew_lead_ms = 10 * MINUTE_MS;
        })
        .validate(),
        Err(SccpParametersError::FastPauseRenewLeadOutOfRange)
    );
}

#[test]
fn fast_pause_hold_upper_bound() {
    // 30 d − 1 d.
    let ceiling = SCCP_MAX_FAST_PAUSE_MS_V1 - SCCP_FAST_PAUSE_HOLD_MARGIN_MS_V1;
    assert_eq!(ceiling, 29 * DAY_MS);
    assert_eq!(ceiling, 2_505_600_000);
    let at = |hold| {
        with(|p| {
            p.fast_pause_hold_ms = hold;
            p.committee_heartbeat_ms = HOUR_MS;
            p.committee_validity_ms = SCCP_MAX_VALIDITY_MS_V1;
        })
        .validate()
    };
    assert_eq!(
        at(ceiling + 1),
        Err(SccpParametersError::FastPauseHoldTooLong)
    );
    assert_eq!(at(u64::MAX), Err(SccpParametersError::FastPauseHoldTooLong));
    // The ceiling itself passes the hold's own bound, but the validity floor of 29 d + 2 h + 1 d
    // is above the 30 d cap, so the joint rule refuses it.
    assert_eq!(
        at(ceiling),
        Err(SccpParametersError::CommitteeValidityTooShort)
    );
    // The largest hold the whole table admits: 30 d − 1 d − 2 × 1 h.
    let largest = SCCP_MAX_VALIDITY_MS_V1 - DAY_MS - 2 * HOUR_MS;
    assert!(largest < ceiling);
    assert_eq!(at(largest), Ok(()));
    assert_eq!(
        at(largest + 1),
        Err(SccpParametersError::CommitteeValidityTooShort)
    );
    // A zero hold has no admitted renew lead.
    assert_eq!(
        with(|p| p.fast_pause_hold_ms = 0).validate(),
        Err(SccpParametersError::FastPauseRenewLeadOutOfRange)
    );
}

#[test]
fn rules_report_own_bounds_then_joint_rules_in_table_order() {
    use SccpParametersError as E;
    // Every field breaks its own bound, and the fields without one break their joint rule.
    let mut parameters = SccpParametersV1 {
        enabled: true,
        committee_validity_ms: u64::MAX,
        committee_heartbeat_ms: 0,
        forgery_evidence_grace_ms: 0,
        destination_progress_cap_ms: u64::MAX,
        outbound_ttl_ms: 0,
        min_outbound_amount: 0,
        inbound_self_claim_fee: u128::MAX,
        max_exempt_transactions_per_block: 0,
        fast_pause_panel_seats: 0,
        fast_pause_panel_term_ms: 0,
        fast_pause_seat_accept_window_ms: 0,
        fast_pause_endorse_window_ms: 0,
        fast_pause_renew_lead_ms: 0,
        fast_pause_hold_ms: u64::MAX,
    };
    let valid = SccpParametersV1::taira_default();
    let repairs: [(E, fn(&mut SccpParametersV1, &SccpParametersV1)); 16] = [
        // Own bounds. Validity and the accept window are repaired to values inside their own
        // bound that still break their joint rule.
        (E::CommitteeValidityTooLong, |p, _| {
            p.committee_validity_ms = 1;
        }),
        (E::CommitteeHeartbeatTooShort, |p, v| {
            p.committee_heartbeat_ms = v.committee_heartbeat_ms;
        }),
        (E::ForgeryEvidenceGraceOutOfRange, |p, v| {
            p.forgery_evidence_grace_ms = v.forgery_evidence_grace_ms;
        }),
        (E::DestinationProgressCapTooLong, |p, v| {
            p.destination_progress_cap_ms = v.destination_progress_cap_ms;
        }),
        (E::OutboundTtlOutOfRange, |p, v| {
            p.outbound_ttl_ms = v.outbound_ttl_ms;
        }),
        (E::MinOutboundAmountOutOfRange, |p, v| {
            p.min_outbound_amount = v.min_outbound_amount;
        }),
        (E::InboundSelfClaimFeeTooLarge, |p, v| {
            p.inbound_self_claim_fee = v.inbound_self_claim_fee;
        }),
        (E::ExemptTransactionsOutOfRange, |p, v| {
            p.max_exempt_transactions_per_block = v.max_exempt_transactions_per_block;
        }),
        (E::FastPausePanelSeatsNotAdmitted, |p, v| {
            p.fast_pause_panel_seats = v.fast_pause_panel_seats;
        }),
        (E::FastPausePanelTermTooShort, |p, v| {
            p.fast_pause_panel_term_ms = v.fast_pause_panel_term_ms;
        }),
        (E::FastPauseSeatAcceptWindowOutOfRange, |p, v| {
            p.fast_pause_seat_accept_window_ms = v.fast_pause_panel_term_ms;
        }),
        (E::FastPauseEndorseWindowOutOfRange, |p, v| {
            p.fast_pause_endorse_window_ms = v.fast_pause_endorse_window_ms;
        }),
        (E::FastPauseHoldTooLong, |p, v| {
            p.fast_pause_hold_ms = v.fast_pause_hold_ms;
        }),
        // Joint rules.
        (E::CommitteeValidityTooShort, |p, v| {
            p.committee_validity_ms = v.committee_validity_ms;
        }),
        (E::FastPauseSeatAcceptWindowOutOfRange, |p, v| {
            p.fast_pause_seat_accept_window_ms = v.fast_pause_seat_accept_window_ms;
        }),
        (E::FastPauseRenewLeadOutOfRange, |p, v| {
            p.fast_pause_renew_lead_ms = v.fast_pause_renew_lead_ms;
        }),
    ];
    for (step, (expected, repair)) in repairs.into_iter().enumerate() {
        assert_eq!(parameters.validate(), Err(expected), "step {step}");
        repair(&mut parameters, &valid);
    }
    assert_eq!(parameters, valid);
    assert_eq!(parameters.validate(), Ok(()));
}

#[test]
fn context_rules_report_at_their_table_position() {
    use SccpParametersError as E;
    let hostile = SccpParameterContextV1 {
        parliament_sccp_attempt_latency_ms: Some(u64::MAX),
        unbonding_delay_ms: 0,
    };
    // An own bound reports before any joint rule.
    assert_eq!(
        with(|p| p.fast_pause_endorse_window_ms = 0).validate_against(&hostile),
        Err(E::FastPauseEndorseWindowOutOfRange)
    );
    // The validity floor reports before L1.
    assert_eq!(
        with(|p| p.committee_validity_ms = 1).validate_against(&hostile),
        Err(E::CommitteeValidityTooShort)
    );
    // L1 reports before the later joint rules.
    assert_eq!(
        with(|p| {
            p.fast_pause_seat_accept_window_ms = 4 * DAY_MS;
            p.fast_pause_renew_lead_ms = 0;
        })
        .validate_against(&hostile),
        Err(E::UnbondingDelayTooShort)
    );
    // The attempt latency reports last.
    let latency_only = SccpParameterContextV1 {
        unbonding_delay_ms: u64::MAX,
        ..hostile
    };
    assert_eq!(
        with(|p| p.fast_pause_seat_accept_window_ms = 4 * DAY_MS).validate_against(&latency_only),
        Err(E::FastPauseSeatAcceptWindowOutOfRange)
    );
    assert_eq!(
        with(|p| p.fast_pause_renew_lead_ms = 0).validate_against(&latency_only),
        Err(E::FastPauseRenewLeadOutOfRange)
    );
    assert_eq!(
        SccpParametersV1::taira_default().validate_against(&latency_only),
        Err(E::FastPauseHoldBelowAttemptLatency)
    );
}

#[test]
fn staking_floor_bounds_validity_plus_grace() {
    let parameters = SccpParametersV1::taira_default();
    let at = SccpParameterContextV1 {
        parliament_sccp_attempt_latency_ms: None,
        unbonding_delay_ms: 21 * DAY_MS,
    };
    assert_eq!(parameters.validate_against(&at), Ok(()));
    let below = SccpParameterContextV1 {
        unbonding_delay_ms: 21 * DAY_MS - 1,
        ..at
    };
    assert_eq!(
        parameters.validate_against(&below),
        Err(SccpParametersError::UnbondingDelayTooShort)
    );
    // The global default unbonding delay of chains without SCCP never satisfies L1.
    let zero = SccpParameterContextV1 {
        unbonding_delay_ms: 0,
        ..at
    };
    assert_eq!(
        parameters.validate_against(&zero),
        Err(SccpParametersError::UnbondingDelayTooShort)
    );
    // Raising either term moves the bound.
    assert_eq!(
        with(|p| p.forgery_evidence_grace_ms = 7 * DAY_MS + 1).validate_against(&at),
        Err(SccpParametersError::UnbondingDelayTooShort)
    );
    assert_eq!(
        with(|p| p.committee_validity_ms = 14 * DAY_MS + 1).validate_against(&at),
        Err(SccpParametersError::UnbondingDelayTooShort)
    );
    assert_eq!(
        with(|p| {
            p.committee_validity_ms = 30 * DAY_MS;
            p.forgery_evidence_grace_ms = 30 * DAY_MS;
        })
        .validate_against(&SccpParameterContextV1 {
            unbonding_delay_ms: 60 * DAY_MS,
            ..at
        }),
        Ok(())
    );
    // A value that breaks a rule of the value itself is refused whatever the context.
    assert_eq!(
        with(|p| p.committee_validity_ms = 30 * DAY_MS + 1).validate_against(
            &SccpParameterContextV1 {
                unbonding_delay_ms: u64::MAX,
                ..at
            }
        ),
        Err(SccpParametersError::CommitteeValidityTooLong)
    );
}

#[test]
fn hold_covers_the_parliament_attempt_latency_when_it_is_available() {
    let parameters = SccpParametersV1::taira_default();
    assert_eq!(
        parameters.validate_against(&context(Some(10 * DAY_MS))),
        Ok(())
    );
    assert_eq!(parameters.validate_against(&context(Some(0))), Ok(()));
    assert_eq!(
        parameters.validate_against(&context(Some(10 * DAY_MS + 1))),
        Err(SccpParametersError::FastPauseHoldBelowAttemptLatency)
    );
    // An attempt longer than the largest admitted hold leaves no valid table (§4.1: "SCCP cannot
    // be configured and the ballot timings must change").
    assert_eq!(
        parameters.validate_against(&context(Some(u64::MAX))),
        Err(SccpParametersError::FastPauseHoldBelowAttemptLatency)
    );
    // Unavailable latency defers the lower bound; it is not a zero latency that any hold meets
    // by accident, and every other rule still runs.
    assert_eq!(parameters.validate_against(&context(None)), Ok(()));
    assert_eq!(
        with(|p| p.fast_pause_panel_seats = 8).validate_against(&context(None)),
        Err(SccpParametersError::FastPausePanelSeatsNotAdmitted)
    );
}

#[test]
fn validate_is_the_context_free_part_of_validate_against() {
    // Whatever `validate` refuses, `validate_against` refuses with the same error under a context
    // that satisfies both context rules.
    let lenient = SccpParameterContextV1 {
        parliament_sccp_attempt_latency_ms: Some(0),
        unbonding_delay_ms: u64::MAX,
    };
    let updates: [fn(&mut SccpParametersV1); 8] = [
        |_| {},
        |p| p.enabled = false,
        |p| p.committee_heartbeat_ms = 1,
        |p| p.outbound_ttl_ms = 0,
        |p| p.max_exempt_transactions_per_block = 7,
        |p| p.fast_pause_panel_seats = 6,
        |p| p.fast_pause_endorse_window_ms = 1,
        |p| p.fast_pause_hold_ms = 0,
    ];
    for update in updates {
        let parameters = with(update);
        assert_eq!(
            parameters.validate_against(&lenient),
            parameters.validate(),
            "{parameters:?}"
        );
    }
}

#[test]
fn json_u64_violation_names_the_first_field_over_the_bound() {
    assert_eq!(
        SccpParametersV1::taira_default().first_json_u64_violation(JSON_MAX),
        None
    );
    let fields: [(&str, fn(&mut SccpParametersV1, u64)); 10] = [
        ("committee_validity_ms", |p, v| p.committee_validity_ms = v),
        ("committee_heartbeat_ms", |p, v| {
            p.committee_heartbeat_ms = v;
        }),
        ("forgery_evidence_grace_ms", |p, v| {
            p.forgery_evidence_grace_ms = v;
        }),
        ("destination_progress_cap_ms", |p, v| {
            p.destination_progress_cap_ms = v;
        }),
        ("outbound_ttl_ms", |p, v| p.outbound_ttl_ms = v),
        ("fast_pause_panel_term_ms", |p, v| {
            p.fast_pause_panel_term_ms = v;
        }),
        ("fast_pause_seat_accept_window_ms", |p, v| {
            p.fast_pause_seat_accept_window_ms = v;
        }),
        ("fast_pause_endorse_window_ms", |p, v| {
            p.fast_pause_endorse_window_ms = v;
        }),
        ("fast_pause_renew_lead_ms", |p, v| {
            p.fast_pause_renew_lead_ms = v;
        }),
        ("fast_pause_hold_ms", |p, v| p.fast_pause_hold_ms = v),
    ];
    let mut at_bound = SccpParametersV1::taira_default();
    for (_, set) in fields {
        set(&mut at_bound, JSON_MAX);
    }
    assert_eq!(at_bound.first_json_u64_violation(JSON_MAX), None);
    for (name, set) in fields {
        let mut over = SccpParametersV1::taira_default();
        set(&mut over, JSON_MAX + 1);
        let message = over
            .first_json_u64_violation(JSON_MAX)
            .expect("value above 2^53 - 1 must be reported");
        assert!(
            message.contains(&format!(" {name} ")),
            "{message} should name {name}"
        );
    }
    // With several fields over the bound the first in table order is named.
    let mut all_over = SccpParametersV1::taira_default();
    for (_, set) in fields {
        set(&mut all_over, JSON_MAX + 1);
    }
    assert!(
        all_over
            .first_json_u64_violation(JSON_MAX)
            .expect("reported")
            .contains("committee_validity_ms")
    );
}

#[test]
fn binary_and_json_roundtrip() {
    for parameters in [
        SccpParametersV1::taira_default(),
        with(|p| {
            p.enabled = false;
            p.min_outbound_amount = u128::MAX;
            p.committee_validity_ms = u64::MAX;
            p.fast_pause_panel_seats = u32::MAX;
            p.fast_pause_hold_ms = u64::MAX;
        }),
    ] {
        let encoded = parameters.encode();
        assert_eq!(
            SccpParametersV1::decode_all(&mut encoded.as_slice()).expect("decode"),
            parameters
        );
        let framed = norito::to_bytes(&parameters).expect("frame");
        assert_eq!(
            norito::decode_from_bytes::<SccpParametersV1>(&framed).expect("decode frame"),
            parameters
        );
        let json = norito::json::to_json(&parameters).expect("serialize");
        assert_eq!(
            norito::json::from_json::<SccpParametersV1>(&json).expect("deserialize"),
            parameters
        );
    }
}

#[test]
fn json_names_exactly_the_fifteen_fields_of_the_table() {
    let value = norito::json::to_value(&SccpParametersV1::taira_default()).expect("to value");
    let names: Vec<&str> = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected = [
        "enabled",
        "committee_validity_ms",
        "committee_heartbeat_ms",
        "forgery_evidence_grace_ms",
        "destination_progress_cap_ms",
        "outbound_ttl_ms",
        "min_outbound_amount",
        "inbound_self_claim_fee",
        "max_exempt_transactions_per_block",
        "fast_pause_panel_seats",
        "fast_pause_panel_term_ms",
        "fast_pause_seat_accept_window_ms",
        "fast_pause_endorse_window_ms",
        "fast_pause_renew_lead_ms",
        "fast_pause_hold_ms",
    ];
    assert_eq!(expected.len(), 15);
    // The JSON object is keyed in lexicographic order.
    expected.sort_unstable();
    assert_eq!(names, expected);
}

#[test]
fn json_amounts_are_exact_decimal_strings() {
    let parameters = with(|p| p.min_outbound_amount = u128::MAX);
    let json = norito::json::to_json(&parameters).expect("serialize");
    assert!(
        json.contains(r#""min_outbound_amount":"340282366920938463463374607431768211455""#),
        "{json}"
    );
    assert!(
        json.contains(r#""inbound_self_claim_fee":"10000000""#),
        "{json}"
    );
    let numeric = json.replace(
        r#""inbound_self_claim_fee":"10000000""#,
        r#""inbound_self_claim_fee":10000000"#,
    );
    assert!(norito::json::from_json::<SccpParametersV1>(&numeric).is_err());
}

#[test]
fn json_rejects_unknown_and_missing_fields() {
    let mut value = norito::json::to_value(&SccpParametersV1::taira_default()).expect("to value");
    let object = value.as_object_mut().expect("object");
    object.insert(
        "min_generation_interval_ms".to_owned(),
        norito::json::Value::from(1_u64),
    );
    let hostile = norito::json::to_json(&value).expect("serialize");
    assert!(norito::json::from_json::<SccpParametersV1>(&hostile).is_err());

    let mut value = norito::json::to_value(&SccpParametersV1::taira_default()).expect("to value");
    value
        .as_object_mut()
        .expect("object")
        .remove("fast_pause_hold_ms");
    let missing = norito::json::to_json(&value).expect("serialize");
    assert!(norito::json::from_json::<SccpParametersV1>(&missing).is_err());
}

#[test]
fn parameters_reject_the_retired_roster_and_attestation_fields() {
    // The five fields of the attestation transport are not part of the table: a value that still
    // carries one, beside or instead of the current fields, does not decode.
    let retired = [
        ("roster_max_age_ms", "committee_heartbeat_ms"),
        ("roster_validity_ms", "committee_validity_ms"),
        ("attestation_retention_ms", "forgery_evidence_grace_ms"),
        ("attestation_stall_ms", "fast_pause_endorse_window_ms"),
        (
            "max_attestation_entries_per_instruction",
            "max_exempt_transactions_per_block",
        ),
    ];
    for (name, replaced) in retired {
        let mut value =
            norito::json::to_value(&SccpParametersV1::taira_default()).expect("to value");
        value
            .as_object_mut()
            .expect("object")
            .insert(name.to_owned(), norito::json::Value::from(86_400_000_u64));
        let beside = norito::json::to_json(&value).expect("serialize");
        assert!(
            norito::json::from_json::<SccpParametersV1>(&beside).is_err(),
            "{name} beside the table"
        );
        let object = value.as_object_mut().expect("object");
        object.remove(replaced).expect("current field");
        let instead = norito::json::to_json(&value).expect("serialize");
        assert!(
            norito::json::from_json::<SccpParametersV1>(&instead).is_err(),
            "{name} instead of {replaced}"
        );
    }
    // The ten values of the retired table, encoded field by field in its order, are not a value
    // of the table.
    let retired: Vec<u8> = [
        true.encode(),
        86_400_000_u64.encode(),
        1_209_600_000_u64.encode(),
        604_800_000_u64.encode(),
        10_u128.pow(9).encode(),
        10_u128.pow(7).encode(),
        2_592_000_000_u64.encode(),
        600_000_u64.encode(),
        256_u32.encode(),
        128_u32.encode(),
    ]
    .concat();
    assert!(SccpParametersV1::decode_all(&mut retired.as_slice()).is_err());
}

#[test]
fn errors_name_their_field() {
    for (error, field) in [
        (
            SccpParametersError::CommitteeValidityTooShort,
            "committee_validity_ms",
        ),
        (
            SccpParametersError::CommitteeValidityTooLong,
            "committee_validity_ms",
        ),
        (
            SccpParametersError::UnbondingDelayTooShort,
            "unbonding_delay_ms",
        ),
        (
            SccpParametersError::CommitteeHeartbeatTooShort,
            "committee_heartbeat_ms",
        ),
        (
            SccpParametersError::ForgeryEvidenceGraceOutOfRange,
            "forgery_evidence_grace_ms",
        ),
        (
            SccpParametersError::DestinationProgressCapTooLong,
            "destination_progress_cap_ms",
        ),
        (
            SccpParametersError::OutboundTtlOutOfRange,
            "outbound_ttl_ms",
        ),
        (
            SccpParametersError::MinOutboundAmountOutOfRange,
            "min_outbound_amount",
        ),
        (
            SccpParametersError::InboundSelfClaimFeeTooLarge,
            "inbound_self_claim_fee",
        ),
        (
            SccpParametersError::ExemptTransactionsOutOfRange,
            "max_exempt_transactions_per_block",
        ),
        (
            SccpParametersError::FastPausePanelSeatsNotAdmitted,
            "fast_pause_panel_seats",
        ),
        (
            SccpParametersError::FastPausePanelTermTooShort,
            "fast_pause_panel_term_ms",
        ),
        (
            SccpParametersError::FastPauseSeatAcceptWindowOutOfRange,
            "fast_pause_seat_accept_window_ms",
        ),
        (
            SccpParametersError::FastPauseEndorseWindowOutOfRange,
            "fast_pause_endorse_window_ms",
        ),
        (
            SccpParametersError::FastPauseRenewLeadOutOfRange,
            "fast_pause_renew_lead_ms",
        ),
        (
            SccpParametersError::FastPauseHoldBelowAttemptLatency,
            "fast_pause_hold_ms",
        ),
        (
            SccpParametersError::FastPauseHoldTooLong,
            "fast_pause_hold_ms",
        ),
    ] {
        let message = error.to_string();
        assert!(message.contains(field), "{message} should name {field}");
    }
}
