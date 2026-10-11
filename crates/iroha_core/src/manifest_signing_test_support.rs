//! Funded, bounded canonical signing for nonshipping Core contract fixtures.

use iroha_allocation::{AllocationBudget, AllocationReservation};
use norito::core::DecodeBudgetContext;

/// Own the original counter and signing scratch through the fixture's consumption.
///
/// The fixture already owns its manifest graph. This owner separately retains a finite
/// physical grant for the canonical signing frame and signer clone; accounting limits
/// are never treated as an independent allocation or release authority.
pub(crate) struct ManifestSigningFixture {
    context: DecodeBudgetContext,
    _scratch: AllocationReservation,
    _pool: AllocationBudget,
    max_frame_bytes: usize,
}

impl ManifestSigningFixture {
    /// Fund one signing scope using the maintained transaction admission defaults.
    pub(crate) fn new() -> Self {
        let max_frame_bytes = usize::try_from(
            iroha_config::parameters::defaults::transaction::ivm_bytecode_size().get(),
        )
        .expect("configured fixture frame bound fits usize");
        let max_elements = usize::try_from(
            iroha_config::parameters::defaults::transaction::max_instructions().get(),
        )
        .expect("configured fixture element bound fits usize");
        // Match the finite eight-frame overlap and depth of the data model's signing tests.
        let scratch_bytes = max_frame_bytes
            .checked_mul(8)
            .expect("finite fixture signing grant fits usize");
        let pool_bytes = scratch_bytes
            .checked_add(DecodeBudgetContext::allocation_layout().size())
            .expect("fixture grant and original counter fit usize");
        let pool = AllocationBudget::new(pool_bytes);
        let scratch = pool
            .try_reserve_bytes(scratch_bytes)
            .expect("fund original fixture signing scratch");
        let context = DecodeBudgetContext::try_new_owned(
            norito::DecodeLimits::new(
                max_elements,
                max_frame_bytes,
                max_elements,
                scratch_bytes,
                256,
            ),
            &pool,
        )
        .expect("fund original fixture signing counter");
        Self {
            context,
            _scratch: scratch,
            _pool: pool,
            max_frame_bytes,
        }
    }

    /// Borrow the original cumulative context without creating new allocation credit.
    pub(crate) fn context(&self) -> &DecodeBudgetContext {
        &self.context
    }

    /// Return the finite complete-frame limit for this original fixture owner.
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
            code_hash: Some(Hash::new(b"bounded Core fixture code")),
            abi_hash: Some(Hash::new(b"bounded Core fixture ABI")),
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
    fn funded_fixture_signing_verifies_and_rejects_changed_content() {
        let signing = ManifestSigningFixture::new();
        assert_eq!(
            signing.max_frame_bytes() as u64,
            iroha_config::parameters::defaults::transaction::ivm_bytecode_size().get(),
        );
        let key = KeyPair::try_from_seed(vec![37; 32], Algorithm::Ed25519)
            .expect("checked deterministic fixture signer");
        let mut signed = manifest("fixture".to_owned())
            .try_signed(signing.context(), signing.max_frame_bytes(), &key)
            .expect("funded canonical fixture signature");
        let payload = signed
            .signature_payload_bytes(signing.context(), signing.max_frame_bytes())
            .expect("bounded verification frame");
        let provenance = signed.provenance.as_ref().expect("fixture provenance");
        assert_eq!(&provenance.signer, key.public_key());
        provenance
            .signature
            .verify(key.public_key(), &payload)
            .unwrap();
        assert!(signing.context().consumed_allocated_bytes() > 0);
        assert!(signing._pool.reserved_bytes() > signing.max_frame_bytes());
        signed.seiyaku_name = Some("altered fixture".to_owned());
        let altered_payload = signed
            .signature_payload_bytes(signing.context(), signing.max_frame_bytes())
            .expect("bounded altered verification frame");
        assert!(
            signed
                .provenance
                .as_ref()
                .unwrap()
                .signature
                .verify(key.public_key(), &altered_payload)
                .is_err()
        );
    }

    #[test]
    fn funded_fixture_signing_refuses_oversized_frame() {
        let signing = ManifestSigningFixture::new();
        let key = KeyPair::try_from_seed(vec![38; 32], Algorithm::Ed25519)
            .expect("checked deterministic fixture signer");
        let frame_bound = signing.max_frame_bytes() / 2;
        let result =
            manifest("x".repeat(frame_bound)).try_signed(signing.context(), frame_bound, &key);
        assert!(matches!(
            result,
            Err(ManifestSigningError::Encoding(BoundedEncodeError::FrameTooLarge {
                max_bytes, ..
            })) if max_bytes == frame_bound
        ));
    }

    #[test]
    fn funded_fixture_retains_and_releases_its_original_physical_grant() {
        let signing = ManifestSigningFixture::new();
        let original_pool = signing._pool.clone();
        let funded_bytes = original_pool.reserved_bytes();
        let shared_context = signing.context().clone();
        assert!(funded_bytes > signing.max_frame_bytes());
        drop(signing);
        assert_eq!(
            original_pool.reserved_bytes(),
            DecodeBudgetContext::allocation_layout().size(),
            "a retained context keeps exactly its original counter backing",
        );
        drop(shared_context);
        assert_eq!(original_pool.reserved_bytes(), 0);
    }
}
