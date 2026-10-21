//! Explicit, revision-pinned opt-in to native linked-FI settlement of a lock.
//!
//! This module is registered with the coordinated controlled-lock/FI candidate.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};

/// Requested linked-FI settlement under the current payout owner's consent.
///
/// The executor derives the payout owner from the native operation: the lock's
/// destination on drawdown, or its original seller on cancellation and expiry.
/// It derives the financial institution from that owner's authenticated link.
/// Callers cannot supply a different recipient, FI, transfer amount, or authority.
/// Revisions must match the installed policy and consent at execution; this value
/// does not itself authenticate either or bypass a native balance constraint.
///
/// Absence on a controlled drawdown/cancellation/expiry retains ordinary native
/// settlement. Presence explicitly selects the current approved waterfall. A
/// refund or same-UID release adds no beneficial incoming value; the executor
/// recomputes any existing excess from its current state. Expiry captures the
/// authoritative whole remainder internally, without a caller-supplied CAS.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::escrow::control::AssetLockWaterfallSettlementV1")]
pub struct AssetLockWaterfallSettlementV1 {
    /// Exact current revision of the lock asset's installed UID holding policy.
    pub expected_policy_revision: u64,
    /// Exact current revision of the payout owner's approved FI link.
    pub expected_link_revision: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waterfall_revision_pins_preserve_full_u64_and_reject_supplied_authority() {
        let pins = AssetLockWaterfallSettlementV1 {
            expected_policy_revision: u64::MAX,
            expected_link_revision: u64::MAX - 1,
        };
        let bytes = norito::encode_canonical(&pins).unwrap();
        assert_eq!(
            norito::decode_canonical::<AssetLockWaterfallSettlementV1>(&bytes).unwrap(),
            pins,
        );
        let json = norito::json::to_json(&pins).unwrap();
        assert_eq!(
            norito::json::from_str::<AssetLockWaterfallSettlementV1>(&json).unwrap(),
            pins,
        );
        for extra in ["beneficiary", "fi_account", "authority", "amount"] {
            let mut value: norito::json::Value = norito::json::from_str(&json).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(extra.into(), norito::json::Value::from("supplied"));
            assert!(
                norito::json::from_str::<AssetLockWaterfallSettlementV1>(
                    &norito::json::to_json(&value).unwrap()
                )
                .is_err(),
                "caller field {extra} must not become settlement authority",
            );
        }
    }
}
