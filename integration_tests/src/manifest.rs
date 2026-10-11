//! Finite signing budgets retained by integration fixture callers.

use eyre::{Result, eyre};
use iroha_allocation::{AllocationBudget, AllocationReservation};
use norito::core::DecodeBudgetContext;

/// Own the original cumulative allowance and physical codec backing for a fixture.
///
/// Construct this owner before the native manifest graphs, and retain it until
/// those graphs and their signing or verification payloads have been consumed.
/// Returning a signed graph requires borrowing the destination caller's owner.
/// Artifact storage and cryptographic backend allocations retain their existing
/// owners; this budget covers the codec's tracked allocations and compact signer.
pub struct ManifestEncodingBudget {
    context: DecodeBudgetContext,
    _codec_grant: AllocationReservation,
    max_frame_bytes: usize,
}

impl ManifestEncodingBudget {
    /// Prepay one finite fixture allowance before any codec allocation.
    ///
    /// A signing frame is limited to 1 MiB and to the canonical transaction
    /// ceiling. The entire fixture shares 4 MiB of cumulative codec work;
    /// temporary output refunds never renew that cumulative allowance.
    ///
    /// # Errors
    /// Returns a native allocation refusal or an invalid bound.
    pub fn new() -> Result<Self> {
        let canonical = usize::try_from(
            iroha_data_model::parameter::system::TransactionParameters::default()
                .max_tx_bytes
                .get(),
        )?;
        let max_frame_bytes = canonical.min(1 << 20);
        let cumulative_bytes = 4 << 20;
        let pool = AllocationBudget::new(Self::pool_bytes(cumulative_bytes)?);
        Self::from_pool(&pool, max_frame_bytes, cumulative_bytes)
    }

    fn pool_bytes(cumulative_bytes: usize) -> Result<usize> {
        cumulative_bytes
            .checked_add(DecodeBudgetContext::allocation_layout().size())
            .ok_or_else(|| eyre!("fixture codec allowance overflow"))
    }

    fn from_pool(
        pool: &AllocationBudget,
        max_frame_bytes: usize,
        cumulative_bytes: usize,
    ) -> Result<Self> {
        if max_frame_bytes == 0 || cumulative_bytes < max_frame_bytes {
            return Err(eyre!("fixture codec allowance must cover a nonzero frame"));
        }
        let mut grant = pool.try_reserve_bytes(Self::pool_bytes(cumulative_bytes)?)?;
        let context = DecodeBudgetContext::from_reservation(
            norito::DecodeLimits::new(
                max_frame_bytes,
                max_frame_bytes,
                max_frame_bytes,
                cumulative_bytes,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            ),
            &mut grant,
        )?;
        Ok(Self {
            context,
            _codec_grant: grant,
            max_frame_bytes,
        })
    }

    /// Borrow the original cumulative context; clones share its consumed credit.
    pub fn context(&self) -> &DecodeBudgetContext {
        &self.context
    }

    /// Return the explicit canonical frame ceiling for this fixture operation.
    pub fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, KeyPair};
    use iroha_data_model::smart_contract::manifest::ContractManifest;

    fn manifest(name: &str) -> ContractManifest {
        ContractManifest {
            seiyaku_name: Some(name.into()),
            code_hash: Some(Hash::new(b"integration manifest code")),
            abi_hash: Some(Hash::new(b"integration manifest ABI")),
            compiler_fingerprint: None,
            features_bitmap: Some(0),
            access_set_hints: None,
            permissions: Vec::new(),
            events: Vec::new(),
            entrypoints: None,
            states: None,
            error_messages: None,
            error_types: None,
            enum_types: Vec::new(),
            kotoba: None,
            provenance: None,
        }
    }

    #[test]
    fn fixture_owner_preserves_signing_verification_and_tamper_refusal() {
        let owner = ManifestEncodingBudget::new().unwrap();
        let key = KeyPair::try_from_seed(vec![0x71; 32], Algorithm::Ed25519).unwrap();
        let mut signed = manifest("original")
            .try_signed(owner.context(), owner.max_frame_bytes(), &key)
            .unwrap();
        for changed in [false, true] {
            if changed {
                signed.seiyaku_name = Some("changed".into());
            }
            let payload = signed
                .signature_payload_bytes(owner.context(), owner.max_frame_bytes())
                .unwrap();
            let provenance = signed.provenance.as_ref().unwrap();
            assert_eq!(
                provenance
                    .signature
                    .verify(&provenance.signer, &payload)
                    .is_ok(),
                !changed,
            );
        }
        assert!(owner.context().consumed_allocated_bytes() > 0);
    }

    #[test]
    fn original_pool_remains_reserved_until_graph_and_owner_are_dropped() {
        let cumulative = 4096;
        let pool = AllocationBudget::new(ManifestEncodingBudget::pool_bytes(cumulative).unwrap());
        let owner = ManifestEncodingBudget::from_pool(&pool, 2048, cumulative).unwrap();
        let held = pool.reserved_bytes();
        assert_eq!(held, pool.limit_bytes());
        assert!(owner._codec_grant.belongs_to(&pool));
        let key = KeyPair::try_from_seed(vec![0x72; 32], Algorithm::Ed25519).unwrap();
        let signed = manifest("retained")
            .try_signed(owner.context(), owner.max_frame_bytes(), &key)
            .unwrap();
        let payload = signed
            .signature_payload_bytes(owner.context(), owner.max_frame_bytes())
            .unwrap();
        assert_eq!(pool.reserved_bytes(), held);
        drop(payload);
        drop(signed);
        assert_eq!(pool.reserved_bytes(), held);
        drop(owner);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn short_or_saturated_original_pool_refuses_before_codec_work() {
        let bytes = ManifestEncodingBudget::pool_bytes(4096).unwrap();
        let short = AllocationBudget::new(bytes - 1);
        assert!(ManifestEncodingBudget::from_pool(&short, 2048, 4096).is_err());
        assert_eq!(short.reserved_bytes(), 0);
        let pool = AllocationBudget::new(bytes);
        let owner = ManifestEncodingBudget::from_pool(&pool, 2048, 4096).unwrap();
        assert!(ManifestEncodingBudget::from_pool(&pool, 2048, 4096).is_err());
        assert_eq!(pool.reserved_bytes(), bytes);
        assert_eq!(owner.context().consumed_allocated_bytes(), 0);
    }

    #[test]
    fn frame_ceiling_refuses_without_materializing_output() {
        let pool = AllocationBudget::new(ManifestEncodingBudget::pool_bytes(4096).unwrap());
        let owner = ManifestEncodingBudget::from_pool(&pool, 32, 4096).unwrap();
        assert!(
            manifest("larger than a 32-byte canonical frame")
                .signature_payload_bytes(owner.context(), owner.max_frame_bytes())
                .is_err(),
        );
        assert_eq!(owner.context().consumed_allocated_bytes(), 0);
    }

    #[test]
    fn cloned_context_cannot_renew_cumulative_credit_after_output_is_freed() {
        let source = manifest("cumulative");
        let measuring = ManifestEncodingBudget::new().unwrap();
        let bytes = source
            .signature_payload_bytes(measuring.context(), measuring.max_frame_bytes())
            .unwrap()
            .len();
        let pool = AllocationBudget::new(ManifestEncodingBudget::pool_bytes(bytes).unwrap());
        let owner = ManifestEncodingBudget::from_pool(&pool, bytes, bytes).unwrap();
        let cloned_context = owner.context().clone();
        let payload = source
            .signature_payload_bytes(owner.context(), owner.max_frame_bytes())
            .unwrap();
        assert_eq!(owner.context().consumed_allocated_bytes(), bytes as u64);
        drop(payload);
        assert!(
            source
                .signature_payload_bytes(&cloned_context, owner.max_frame_bytes())
                .is_err(),
        );
        assert_eq!(owner.context().consumed_allocated_bytes(), bytes as u64);
        drop(cloned_context);
    }
}
