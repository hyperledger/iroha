//! Immutable contract control terms for native asset locks.
//!
//! The native escrow record continues to identify the original funding owner
//! as its seller. A controller is an authorization boundary, not a substitute
//! beneficial owner. These terms do not grant transfer permission or authenticate
//! an invocation; the native executor must establish both independently.

use core::num::NonZeroU64;

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, smart_contract::ContractAddress};

/// Derive a contract-scoped lock identity from an opaque application key.
///
/// Canonical contract literals are length-prefixed; key bytes occupy the remaining
/// suffix. Equal keys in different contract instances cannot address the same lock.
#[must_use]
pub fn controlled_asset_lock_id(controller: &ContractAddress, key: &[u8]) -> super::EscrowId {
    let address: &str = controller.as_ref();
    super::EscrowId::new(iroha_crypto::Hash::new_from_chunks(&[
        b"iroha:controlled-asset-lock:v1\0",
        &(address.len() as u64).to_be_bytes(),
        address.as_bytes(),
        key,
    ]))
}

/// Immutable policy attached to a native lock controlled by one contract.
///
/// A generic revocable lock leaves `cancel_not_before_ms` absent. A purchase
/// can fix a later refund time independently of its earlier claim deadline.
/// This separation preserves, for example, a three-day delivery condition
/// window and a seven-day refund without shortening the latter.
#[derive(
    Clone,
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
#[norito_schema(name = "iroha_data_model::escrow::control::AssetLockControlV1")]
pub struct AssetLockControlV1 {
    /// Exact deployed instance whose authenticated invocation may mutate the lock.
    pub controller: ContractAddress,
    /// Last permitted claim time, inclusive; absent means no native claim deadline.
    pub release_until_ms: Option<NonZeroU64>,
    /// First permitted cancellation time, inclusive; absent permits early cancellation.
    ///
    /// A strictly-after business expiry is represented by `expiry + 1`, checked
    /// for overflow when the instruction is constructed.
    pub cancel_not_before_ms: Option<NonZeroU64>,
}

impl AssetLockControlV1 {
    /// Whether the immutable claim window includes the committed block time.
    ///
    /// Contract policy, positive amount, remainder and authority checks still apply.
    #[must_use]
    pub fn permits_claim_at(&self, block_time_ms: u64) -> bool {
        self.release_until_ms
            .is_none_or(|deadline| block_time_ms <= deadline.get())
    }

    /// Whether immutable cancellation terms permit the committed block time.
    ///
    /// This does not authorize a payer to bypass the controlling contract.
    #[must_use]
    pub fn permits_cancel_at(&self, block_time_ms: u64) -> bool {
        self.cancel_not_before_ms
            .is_none_or(|deadline| block_time_ms >= deadline.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkId, account::AccountId, block::BlockHeader};
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_model_base::topology::DataSpaceId;

    fn control(release: Option<u64>, cancel: Option<u64>) -> AssetLockControlV1 {
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new(b"escrow-control-tests"),
        ));
        let key = KeyPair::try_from_seed(vec![9; 32], Algorithm::Ed25519).expect("fixed test key");
        let account = AccountId::new(key.public_key().clone());
        AssetLockControlV1 {
            controller: ContractAddress::derive(&network, &account, 1, DataSpaceId::UNIVERSAL)
                .expect("fixed test contract"),
            release_until_ms: release
                .map(|value| NonZeroU64::new(value).expect("positive deadline")),
            cancel_not_before_ms: cancel
                .map(|value| NonZeroU64::new(value).expect("positive deadline")),
        }
    }

    #[test]
    fn claim_and_refund_windows_are_independent_at_each_boundary() {
        let terms = control(Some(300), Some(701));
        assert!(terms.permits_claim_at(299));
        assert!(terms.permits_claim_at(300));
        assert!(!terms.permits_claim_at(301));
        assert!(!terms.permits_cancel_at(300));
        assert!(!terms.permits_cancel_at(700));
        assert!(terms.permits_cancel_at(701));
        assert!(terms.permits_cancel_at(u64::MAX));
    }

    #[test]
    fn revocable_unbounded_terms_preserve_generic_lock_policy() {
        let terms = control(None, None);
        for time in [0, 1, u64::MAX] {
            assert!(terms.permits_claim_at(time));
            assert!(terms.permits_cancel_at(time));
        }
    }

    #[test]
    fn control_terms_roundtrip_without_changing_controller_or_windows() {
        for original in [control(None, None), control(Some(300), Some(701))] {
            let binary = norito::encode_canonical(&original).expect("encode terms");
            let decoded: AssetLockControlV1 =
                norito::decode_canonical(&binary).expect("decode terms");
            assert_eq!(decoded, original);
            let json = norito::json::to_json(&original).expect("encode JSON terms");
            let decoded: AssetLockControlV1 =
                norito::json::from_str(&json).expect("decode JSON terms");
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn lock_identity_is_deterministic_and_bound_to_instance_and_exact_key() {
        let first = control(None, None).controller;
        let key = KeyPair::try_from_seed(vec![10; 32], Algorithm::Ed25519).unwrap();
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new(b"escrow-control-tests"),
        ));
        let second = ContractAddress::derive(
            &network,
            &AccountId::new(key.public_key().clone()),
            1,
            DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        let id = controlled_asset_lock_id(&first, b"ns:1/lock");
        assert_eq!(id, controlled_asset_lock_id(&first, b"ns:1/lock"));
        assert_ne!(id, controlled_asset_lock_id(&first, b"ns:2/lock"));
        assert_ne!(id, controlled_asset_lock_id(&second, b"ns:1/lock"));
        assert_ne!(id, controlled_asset_lock_id(&first, b"ns:1/lock\0"));
    }
}
