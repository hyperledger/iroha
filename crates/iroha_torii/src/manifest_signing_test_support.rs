//! Finite original signing grants for nonshipping Torii contract fixtures.

use iroha_allocation::{AllocationBudget, AllocationReservation};
use norito::core::DecodeBudgetContext;

/// Retain one cumulative counter and its original physical grant through fixture consumption.
///
/// Existing fixture graphs and signature backend internals have their own owners. This grant
/// funds at most two complete canonical frames and one compact signer per declared signature.
pub(crate) struct ManifestSigningFixture {
    context: DecodeBudgetContext,
    _scratch: AllocationReservation,
    _pool: AllocationBudget,
    max_frame_bytes: usize,
}

impl ManifestSigningFixture {
    /// Fund the caller's finite signature count without resetting cumulative codec accounting.
    pub(crate) fn new(signature_count: usize) -> Self {
        assert!(
            signature_count > 0,
            "fixture declares at least one signature"
        );
        let max_frame_bytes = usize::try_from(
            iroha_config::parameters::defaults::transaction::ivm_bytecode_size().get(),
        )
        .expect("configured fixture frame bound fits usize");
        let signer_bytes = iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES
            .checked_add(1)
            .expect("compact signer includes its algorithm tag");
        let scratch_bytes = max_frame_bytes
            .checked_mul(2)
            .and_then(|frames| frames.checked_add(signer_bytes))
            .and_then(|one_signature| one_signature.checked_mul(signature_count))
            .expect("finite fixture signing grant fits usize");
        let max_elements = usize::try_from(
            iroha_config::parameters::defaults::transaction::max_instructions().get(),
        )
        .expect("configured fixture element bound fits usize")
        .checked_mul(signature_count)
        .expect("finite cumulative fixture element count fits usize");
        let pool_bytes = scratch_bytes
            .checked_add(DecodeBudgetContext::allocation_layout().size())
            .expect("fixture grant and counter fit usize");
        let pool = AllocationBudget::new(pool_bytes);
        let scratch = pool
            .try_reserve_bytes(scratch_bytes)
            .expect("fund original fixture signing scratch");
        let mut counter = pool
            .try_reserve(DecodeBudgetContext::allocation_layout())
            .expect("fund original fixture signing counter");
        let context = DecodeBudgetContext::from_reservation(
            norito::DecodeLimits::new(
                max_elements,
                max_frame_bytes,
                max_elements,
                scratch_bytes,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            ),
            &mut counter,
        )
        .expect("construct the original prepaid fixture counter");
        Self {
            context,
            _scratch: scratch,
            _pool: pool,
            max_frame_bytes,
        }
    }

    /// Borrow the original cumulative context; clones cannot grant new allocation credit.
    pub(crate) fn context(&self) -> &DecodeBudgetContext {
        &self.context
    }

    /// Return the configured finite complete signing frame ceiling.
    pub(crate) fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::smart_contract::manifest::{ContractManifest, ManifestSigningError};
    use norito::core::BoundedEncodeError;

    fn manifest(name: String) -> ContractManifest {
        ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: Some(name),
            code_hash: Some(Hash::new(b"Torii fixture code")),
            abi_hash: Some(Hash::new(b"Torii fixture ABI")),
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            provenance: None,
            error_types: None,
            error_messages: None,
            kotoba: None,
        }
    }

    #[test]
    fn torii_fixture_signing_authenticates_its_bounded_canonical_frame() {
        let signing = ManifestSigningFixture::new(1);
        let key = KeyPair::try_from_seed(vec![73; 32], Algorithm::Ed25519).unwrap();
        let manifest = manifest("funded Torii fixture".into())
            .try_signed(signing.context(), signing.max_frame_bytes(), &key)
            .unwrap();
        let payload = manifest
            .signature_payload_bytes(signing.context(), signing.max_frame_bytes())
            .unwrap();
        let provenance = manifest.provenance.as_ref().unwrap();
        assert_eq!(&provenance.signer, key.public_key());
        provenance
            .signature
            .verify(key.public_key(), &payload)
            .unwrap();
        assert!(signing.context().consumed_allocated_bytes() > 0);
        assert!(signing._pool.reserved_bytes() > signing.max_frame_bytes());
    }

    #[test]
    fn torii_fixture_signing_preserves_the_original_frame_refusal() {
        let signing = ManifestSigningFixture::new(1);
        let key = KeyPair::try_from_seed(vec![74; 32], Algorithm::Ed25519).unwrap();
        let frame_bound = 128;
        let error = manifest("x".repeat(frame_bound))
            .try_signed(signing.context(), frame_bound, &key)
            .unwrap_err();
        assert!(matches!(
            error,
            ManifestSigningError::Encoding(BoundedEncodeError::FrameTooLarge {
                encoded_bytes,
                max_bytes,
            }) if encoded_bytes > frame_bound && max_bytes == frame_bound
        ));
    }

    #[test]
    fn torii_fixture_context_clone_keeps_only_its_original_counter_after_owner_drop() {
        let signing = ManifestSigningFixture::new(2);
        let pool = signing._pool.clone();
        let counter = signing.context().clone();
        assert_eq!(
            pool.reserved_bytes(),
            2 * (2 * signing.max_frame_bytes() + iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES + 1)
                + DecodeBudgetContext::allocation_layout().size(),
        );
        drop(signing);
        assert_eq!(
            pool.reserved_bytes(),
            DecodeBudgetContext::allocation_layout().size()
        );
        drop(counter);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
