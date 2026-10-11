//! Finite original allocation ownership for CLI manifest signing.

use eyre::{Result, eyre};
use iroha::data_model::smart_contract::manifest::ContractManifest;
use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_crypto::PublicKey;
use norito::core::DecodeBudgetContext;

/// Admit one signing payload and retain its original cumulative accounting.
/// The caller keeps signer slices alive through native or JSON consumption.
pub(super) struct ManifestSigningBudget {
    context: DecodeBudgetContext,
    grant: AllocationReservation,
    max_frame_bytes: usize,
}

impl ManifestSigningBudget {
    /// Use the canonical native transaction ceiling for this CLI operation.
    pub(super) fn new() -> Result<Self> {
        let max_frame_bytes = usize::try_from(
            iroha::data_model::parameter::system::TransactionParameters::default()
                .max_tx_bytes
                .get(),
        )?;
        // Current borrowed manifest fields stream their existing graph. This
        // operation produces one payload and one compact public-key backing;
        // any codec scratch consumes the same already-funded finite allowance.
        let cumulative_bytes = max_frame_bytes
            .checked_add(iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES + 1)
            .ok_or_else(|| eyre!("manifest allocation allowance overflow"))?;
        let pool = AllocationBudget::new(Self::pool_bytes(cumulative_bytes)?);
        Self::from_pool(&pool, max_frame_bytes, cumulative_bytes)
    }

    fn pool_bytes(cumulative_bytes: usize) -> Result<usize> {
        cumulative_bytes
            .checked_add(DecodeBudgetContext::allocation_layout().size())
            .ok_or_else(|| eyre!("manifest physical allowance overflow"))
    }

    fn from_pool(
        pool: &AllocationBudget,
        max_frame_bytes: usize,
        cumulative_bytes: usize,
    ) -> Result<Self> {
        if max_frame_bytes == 0 {
            return Err(eyre!("manifest frame ceiling must be nonzero"));
        }
        let mut prepaid = pool.try_reserve_bytes(Self::pool_bytes(cumulative_bytes)?)?;
        let context = DecodeBudgetContext::from_reservation(
            norito::DecodeLimits::new(
                max_frame_bytes,
                max_frame_bytes,
                max_frame_bytes,
                cumulative_bytes,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            ),
            &mut prepaid,
        )?;
        Ok(Self {
            context,
            grant: prepaid,
            max_frame_bytes,
        })
    }

    /// Admit the exact canonical payload before allocating it.
    pub(super) fn reserve_frame(
        &mut self,
        manifest: &ContractManifest,
    ) -> Result<AllocationReservation> {
        let bytes = self.context.with(|| {
            let _canonical =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            norito::core::encoded_frame_len_bounded(
                &manifest.signature_payload(),
                self.max_frame_bytes,
            )
        })?;
        Ok(self.grant.try_partition_bytes(bytes)?)
    }

    /// Retain this exact slice until the signed manifest has been consumed.
    pub(super) fn reserve_signer(&mut self, signer: &PublicKey) -> Result<AllocationReservation> {
        Ok(self
            .grant
            .try_partition_bytes(signer.retained_allocation_layout().size())?)
    }

    /// Borrow the original cumulative context; it grants no renewal.
    pub(super) fn context(&self) -> &DecodeBudgetContext {
        &self.context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};

    fn source(name: &str) -> ContractManifest {
        ContractManifest {
            seiyaku_name: Some(name.into()),
            code_hash: None,
            abi_hash: None,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            permissions: Vec::new(),
            events: Vec::new(),
            enum_types: Vec::new(),
            entrypoints: None,
            states: None,
            error_messages: None,
            error_types: None,
            kotoba: None,
            provenance: None,
        }
    }

    #[test]
    fn original_signing_pool_is_exact_and_refunded_after_manifest_consumption() {
        let key = KeyPair::try_from_seed(vec![0xCA; 32], Algorithm::Ed25519).unwrap();
        let cumulative = 4096;
        let bytes = ManifestSigningBudget::pool_bytes(cumulative).unwrap();
        let pool = AllocationBudget::new(bytes);
        {
            let mut owner = ManifestSigningBudget::from_pool(&pool, 4096, cumulative).unwrap();
            assert_eq!(pool.reserved_bytes(), bytes);
            let signer = owner.reserve_signer(key.public_key()).unwrap();
            let manifest = source("funded");
            let frame = owner.reserve_frame(&manifest).unwrap();
            let exact = frame.remaining_bytes();
            assert_eq!(owner.context().consumed_allocated_bytes(), 0);
            let signed = manifest.try_signed(owner.context(), exact, &key).unwrap();
            assert_eq!(
                owner.context().consumed_allocated_bytes(),
                u64::try_from(exact + signer.remaining_bytes()).unwrap()
            );
            drop(frame);
            assert_eq!(pool.reserved_bytes(), bytes - exact);
            let rendered = norito::json::to_json_pretty(&signed).unwrap();
            assert!(rendered.contains("provenance"));
            drop(signed);
            drop(signer);
        }
        assert_eq!(pool.reserved_bytes(), 0);
        let whole = pool.try_reserve_bytes(bytes).unwrap();
        assert_eq!(whole.remaining_bytes(), bytes);
    }

    #[test]
    fn short_original_pool_and_oversize_payload_refuse_without_renewal() {
        let cumulative = 4096;
        let physical = ManifestSigningBudget::pool_bytes(cumulative).unwrap();
        let short = AllocationBudget::new(physical - 1);
        assert!(ManifestSigningBudget::from_pool(&short, 4096, cumulative).is_err());
        assert_eq!(short.reserved_bytes(), 0);
        let pool = AllocationBudget::new(physical);
        let mut owner = ManifestSigningBudget::from_pool(&pool, 64, cumulative).unwrap();
        let before = owner.grant.remaining_bytes();
        assert!(owner.reserve_frame(&source(&"x".repeat(128))).is_err());
        assert_eq!(owner.grant.remaining_bytes(), before);
        assert_eq!(owner.context().consumed_allocated_bytes(), 0);
        assert!(ManifestSigningBudget::from_pool(&pool, 64, cumulative).is_err());
        assert_eq!(pool.reserved_bytes(), physical);
    }

    #[test]
    fn context_clone_refuses_a_second_payload_after_exact_cumulative_consumption() {
        let manifest = source("one original operation");
        // A separate fully funded measurement establishes the finite geometry
        // for this control. The tested operation gets exactly one output.
        let exact = {
            let mut measurement = ManifestSigningBudget::new().unwrap();
            measurement
                .reserve_frame(&manifest)
                .unwrap()
                .remaining_bytes()
        };
        let pool = AllocationBudget::new(ManifestSigningBudget::pool_bytes(exact).unwrap());
        let mut owner = ManifestSigningBudget::from_pool(&pool, exact, exact).unwrap();
        let first = owner.reserve_frame(&manifest).unwrap();
        let context = owner.context().clone();
        let payload = manifest.signature_payload_bytes(&context, exact).unwrap();
        drop(payload);
        drop(first);
        assert_eq!(owner.context().consumed_allocated_bytes(), exact as u64);
        // Physical capacity is genuinely available again, but the original
        // cumulative counter still refuses another materialization.
        let second = pool.try_reserve_bytes(exact).unwrap();
        assert!(manifest.signature_payload_bytes(&context, exact).is_err());
        assert_eq!(owner.context().consumed_allocated_bytes(), exact as u64);
        assert_eq!(context.consumed_allocated_bytes(), exact as u64);
        assert_eq!(second.remaining_bytes(), exact);
    }

    #[test]
    fn cli_signing_uses_canonical_transaction_and_nesting_limits() {
        let owner = ManifestSigningBudget::new().unwrap();
        assert_eq!(
            owner.max_frame_bytes,
            usize::try_from(
                iroha::data_model::parameter::system::TransactionParameters::default()
                    .max_tx_bytes
                    .get()
            )
            .unwrap()
        );
        assert_eq!(
            owner.grant.remaining_bytes(),
            owner.max_frame_bytes + iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES + 1
        );
    }
}
