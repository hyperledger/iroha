//! Scalar forgery-hold and reconciliation observations for one committed parent.

use iroha_data_model::{
    bridge::SccpNetworkV1,
    sccp::{native::SccpQuarantineV1, reconciliation::SccpReconciliationStateV1},
};
use norito::codec::{Decode, Encode};

/// Default and maximum number of scalar revision rows in one hold observation.
pub const MAX_FORGERY_HOLD_PAGE: usize = 64;

/// Exclusive lexicographic cursor of a bounded hold page.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpForgeryHoldCursorV1")]
pub struct SccpForgeryHoldCursorV1 {
    /// External network of the last included row.
    pub network: SccpNetworkV1,
    /// Nonzero last included revision.
    pub revision: u32,
}

/// Typed local query selectors; this is not an encoded authority or continuation token.
#[derive(Debug, Clone, Copy)]
pub struct SccpForgeryHoldQuery {
    /// Restrict rows to one external network.
    pub network: Option<SccpNetworkV1>,
    /// Restrict to one nonzero revision; requires `network`.
    pub revision: Option<u32>,
    /// Resume strictly after this network/revision pair.
    pub after: Option<SccpForgeryHoldCursorV1>,
    /// Requested row count in `1..=MAX_FORGERY_HOLD_PAGE`.
    pub limit: usize,
}

impl Default for SccpForgeryHoldQuery {
    fn default() -> Self {
        Self {
            network: None,
            revision: None,
            after: None,
            limit: MAX_FORGERY_HOLD_PAGE,
        }
    }
}

/// Committed hold and reconciliation state of one route revision.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpForgeryHoldRevisionV1")]
pub struct SccpForgeryHoldRevisionV1 {
    /// External destination network.
    pub network: SccpNetworkV1,
    /// Immutable deployment revision.
    pub revision: u32,
    /// First generation whose retained forgery holds this revision.
    pub forgery_floor: u64,
    /// Effective Taira hold, including activation, global enablement and pause tracks.
    pub held: bool,
    /// Permanent quarantine, retained after reconciliation.
    #[norito(required)]
    pub quarantine: Option<SccpQuarantineV1>,
    /// Scalar window and payout state; proof history is never copied into a status query.
    #[norito(required)]
    pub reconciliation: Option<SccpReconciliationStateV1>,
}

/// `GET /v1/sccp/forgery-hold`, ordered by network and revision.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_sccp::api::SccpForgeryHoldViewV1")]
pub struct SccpForgeryHoldViewV1 {
    /// Largest generation with retained authenticated forgery evidence.
    #[norito(required)]
    pub max_generation: Option<u64>,
    /// At most 64 registered revisions with effective holds and reconciliation state.
    pub revisions: Vec<SccpForgeryHoldRevisionV1>,
    /// Exclusive cursor for the next matching page; absent when this view is exhausted.
    #[norito(required)]
    pub next: Option<SccpForgeryHoldCursorV1>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sccp::reconciliation::SccpReconciliationRatioV1;

    #[test]
    fn reconciliation_status_roundtrips_open_and_settled_rates() {
        for rho in [
            None,
            Some(SccpReconciliationRatioV1 {
                backing: 7,
                denominator: 10,
            }),
        ] {
            let view = SccpForgeryHoldViewV1 {
                max_generation: Some(9),
                revisions: vec![SccpForgeryHoldRevisionV1 {
                    network: SccpNetworkV1::EthereumMainnet,
                    revision: 1,
                    forgery_floor: 3,
                    held: rho.is_none(),
                    quarantine: None,
                    reconciliation: Some(SccpReconciliationStateV1 {
                        opened_at_ms: 10,
                        closes_at_ms: 20,
                        forged_supply: 3,
                        rho,
                        settled_face: 0,
                    }),
                }],
                next: None,
            };
            assert_eq!(
                SccpForgeryHoldViewV1::decode(&mut &view.encode()[..]).unwrap(),
                view
            );
            let json = norito::json::to_json(&view).unwrap();
            assert_eq!(
                norito::json::from_str::<SccpForgeryHoldViewV1>(&json).unwrap(),
                view
            );
        }
    }
}
