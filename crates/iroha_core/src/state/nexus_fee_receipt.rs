//! Actual fee settlement custody between execution and its consensus output.

use super::StateTransaction;
use iroha_crypto::Hash;
use iroha_data_model::block::consensus::RootFeePolicy;
use iroha_data_model::{
    ValidationFail,
    account::AccountId,
    asset::AssetDefinitionId,
    block::consensus::{NexusFeeReceipt, NexusFeeScheduleInputs, NexusFeeSettlementV1},
    nexus::{FeeDebitSource, FeeSponsorProgramId},
    transaction::SignedTransaction,
};
use iroha_primitives::numeric::Quantity;

impl StateTransaction<'_, '_> {
    /// Prepare the exact receipt before any nonzero fee debit. It becomes pending
    /// only after the real balance/supply burn succeeds in this same overlay.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_actual_nexus_fee_receipt(
        &self,
        authority: &AccountId,
        signed: &SignedTransaction,
        sponsor: Option<&FeeSponsorProgramId>,
        asset: &AssetDefinitionId,
        amount: &Quantity,
        cfg: &RootFeePolicy,
        tx_bytes_len: usize,
        instruction_count: usize,
        gas_used: u64,
    ) -> Result<NexusFeeReceipt, ValidationFail> {
        let fail = |reason: &str| ValidationFail::InternalError(reason.to_owned());
        if self.pending_nexus_fee_receipt.is_some() || self.pending_nexus_fee_event.is_some() {
            return Err(fail(
                "actual Nexus fee is already settled for this execution",
            ));
        }
        if authority != signed.authority()
            || self.current_entrypoint_index.is_none()
            || self.current_dataspace_id != self.world.current_dataspace_id
            || self.current_tx_hash != Some(signed.hash())
            || self.tx_call_hash != Some(Hash::from(signed.hash_as_entrypoint()))
        {
            return Err(fail(
                "Nexus settlement differs from its actual signed execution owner",
            ));
        }
        let source = self
            .current_network_entrypoint_hash
            .ok_or_else(|| fail("Nexus settlement has no actual Network source"))?;
        let (debit_source, program_revision) = match signed.fee_payment_intent().sponsor_program() {
            Some((program, revision)) if sponsor == Some(program) => (
                FeeDebitSource::SponsorProgram(program.clone()),
                Some(revision),
            ),
            None if sponsor.is_none() => (FeeDebitSource::Account(authority.clone()), None),
            _ => {
                return Err(fail(
                    "Nexus settlement sponsor differs from the original signed intent",
                ));
            }
        };
        let receipt = NexusFeeReceipt {
            version: NexusFeeReceipt::VERSION,
            source_id: *Hash::from(source).as_ref(),
            dataspace_id: self
                .current_dataspace_id
                .ok_or_else(|| fail("Nexus settlement has no frozen physical dataspace"))?,
            lane_id: self
                .current_lane_id
                .ok_or_else(|| fail("Nexus settlement has no frozen physical lane"))?,
            block_height: self.block_height(),
            debit_source,
            fee_asset_id: asset.clone(),
            program_revision,
            lease_id: None,
            fee_amount: amount.clone(),
            settlement: NexusFeeSettlementV1::Burn,
            schedule: NexusFeeScheduleInputs {
                tx_bytes_len: u64::try_from(tx_bytes_len)
                    .map_err(|_| fail("Nexus payload length exceeds u64"))?,
                instruction_count: u64::try_from(instruction_count)
                    .map_err(|_| fail("Nexus instruction count exceeds u64"))?,
                gas_used,
                base_fee: cfg.base_fee.clone(),
                per_byte_fee: cfg.per_byte_fee.clone(),
                per_instruction_fee: cfg.per_instruction_fee.clone(),
                per_gas_unit_fee: cfg.per_gas_unit_fee.clone(),
            },
        };
        if amount.is_zero()
            || receipt.block_height == 0
            || norito::canonical_frame_len(&receipt)
                .map_err(|_| fail("Nexus receipt encoding failed"))?
                > iroha_data_model::block::consensus::MAX_NEXUS_FEE_RECEIPT_BYTES
            || norito::canonical_frame_len(signed.payload())
                .map_err(|_| fail("Nexus payload encoding failed"))?
                != tx_bytes_len
        {
            return Err(fail(
                "actual Nexus receipt has invalid amount, metering or bound",
            ));
        }
        Ok(receipt)
    }
}
