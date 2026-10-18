//! Exact original receipt custody for bounded native retail collection.

use super::*;
use iroha_data_model::fastpq::TransferDeltaTranscript;

/// One non-cloneable original idle-batch source. No public constructor exists.
/// The ordered original receipt commitment, moved deltas and opaque journal identity
/// stay together until State admission; no receipt byte vectors are cloned.
pub(crate) struct RetailNativeMaintenancePermit {
    source: crate::state::native_maintenance::RetailMaintenanceSource,
    entries: Vec<(AccountId, Hash, TransferDeltaTranscript)>,
    receipt_commitment: Hash,
}

impl RetailNativeMaintenancePermit {
    pub(super) fn issue(stx: &mut StateTransaction<'_, '_>) -> Result<Self, FeeReadError> {
        let source = stx.retain_retail_maintenance_source()?;
        let allowance = stx.retail_maintenance_entry_allowance()?;
        if u64::try_from(stx.world.retail_fee_pending_transcripts.len())
            .map_err(|_| "retail source entry count exceeds u64")?
            > allowance
        {
            return Err("retail source batch exceeds its original native allowance".into());
        }
        let registry = registry(&stx.world)?.ok_or("retail source has no original policy")?;
        let mut receipt_commitment = Hash::new([]);
        for (authority, hash, delta) in &stx.world.retail_fee_pending_transcripts {
            let path: StatePath = format!(
                "{}{}",
                receipt_prefix(&delta.from_account),
                hex::encode(hash.as_ref())
            )
            .parse()
            .map_err(|error| format!("invalid retail source receipt path: {error}"))?;
            let bytes = stx
                .world
                .smart_contract_state
                .get(&path)
                .ok_or("retail source receipt is absent from its original State journal")?;
            let receipt: RetailFeeReceiptV1 =
                norito::core::classify_decode_attempt(|| norito::decode_from_bytes(bytes))
                    .map_err(|error| {
                        crate::execution_attempt::canonical_decode_attempt_error(error, |error| {
                            error.to_string()
                        })
                    })?;
            let policy = registry
                .registered_policies
                .iter()
                .find(|entry| entry.policy.policy_version == receipt.policy_revision)
                .ok_or("retail source receipt has no retained earning policy")?;
            if receipt.kind != RetailFeeReceiptKindV1::Maintenance
                || Hash::prehashed(receipt.receipt_id) != *hash
                || receipt.account_id != delta.from_account
                || receipt.source_transaction_hash.is_some()
                || receipt.recorded_at_height != stx.block_height()
                || receipt
                    .effective_at_ms
                    .is_none_or(|at| at > stx.block_unix_timestamp_ms())
                || receipt.collected_minor == 0
                || quantity(receipt.collected_minor) != delta.amount
                || receipt.policy_hash != policy.policy_hash
                || policy.policy.ds_asset_id != delta.asset_definition
                || policy.policy.treasury_account_id != *authority
                || delta.to_account != *authority
            {
                return Err(
                    "retail source differs from its exact original receipt and policy".into(),
                );
            }
            receipt_commitment = append_receipt_commitment(receipt_commitment, bytes);
        }
        Ok(Self {
            source,
            entries: std::mem::take(&mut stx.world.retail_fee_pending_transcripts),
            receipt_commitment,
        })
    }

    /// Recheck the original allocation, State generation and exact retained receipt bytes.
    pub(crate) fn into_entries(
        self,
        stx: &StateTransaction<'_, '_>,
    ) -> Result<Vec<(AccountId, Hash, TransferDeltaTranscript)>, FeeReadError> {
        self.source.authenticate(stx)?;
        if !stx.world.retail_fee_pending_transcripts.is_empty() {
            return Err("retail source acquired an unowned later transcript".into());
        }
        let mut receipt_commitment = Hash::new([]);
        for (_, hash, delta) in &self.entries {
            let path: StatePath = format!(
                "{}{}",
                receipt_prefix(&delta.from_account),
                hex::encode(hash.as_ref())
            )
            .parse()
            .map_err(|error| format!("invalid retail source receipt path: {error}"))?;
            let bytes = stx
                .world
                .smart_contract_state
                .get(&path)
                .ok_or("retail source lost its original receipt")?;
            receipt_commitment = append_receipt_commitment(receipt_commitment, bytes);
        }
        if receipt_commitment != self.receipt_commitment {
            return Err("retail source receipt journal changed after original preparation".into());
        }
        Ok(self.entries)
    }
}

// Local preparation custody only; this digest is never a State root or wire authority.
fn append_receipt_commitment(prefix: Hash, bytes: &[u8]) -> Hash {
    let frame = Hash::new(bytes);
    let mut pair = [0_u8; 64];
    pair[..32].copy_from_slice(prefix.as_ref());
    pair[32..].copy_from_slice(frame.as_ref());
    Hash::new(pair)
}

#[cfg(test)]
#[path = "native_maintenance_tests.rs"]
mod tests;
