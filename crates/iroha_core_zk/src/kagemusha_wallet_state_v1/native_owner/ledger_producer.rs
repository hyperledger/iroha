//! Current ledger instruction preparation and native Unload confirmation.
use super::*;
mod projection;
mod unload_session;
use iroha_data_model::{
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
    sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
};
pub use projection::NativePreparedLedgerLoadV1;
/// One complete current ledger instruction, including its original signed transport.
pub const LEDGER_INSTRUCTION_MAX_BYTES_V1: usize = 64 * 1024;

/// Exact transaction-and-claim-bound Unload settlement state selected by Native custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnloadFinalityProgressV1 {
    /// No independently verified history has been retained for this transaction.
    NotStarted,
    /// A genuine prefix is retained, but successful inclusion is not yet established.
    Verifying(LedgerProgressV1),
    /// Exact successful inclusion was authenticated and durably retained.
    Confirmed(LedgerProgressV1),
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::LedgerLoadPlanV1")]
struct LoadPlan {
    request: [u8; 32],
    amount: u128,
    ordinal: u128,
    instruction: Vec<u8>,
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::UnloadConfirmationV1")]
struct UnloadConfirmation {
    original_digest: [u8; 32],
    height: u64,
    block_hash: [u8; 32],
}

impl UnloadConfirmation {
    fn progress(&self, original_digest: &[u8; 32]) -> Result<LedgerProgressV1, Error> {
        if self.original_digest != *original_digest || self.height < 2 || self.block_hash == [0; 32]
        {
            return Err(Error::WitnessLost("retained Unload confirmation"));
        }
        Ok(LedgerProgressV1 {
            height: self.height,
            block_hash: self.block_hash,
        })
    }
}

fn retained_unload_confirmation(
    archive: &mut impl index::ObjectStore,
    confirmations: &index::IndexRoot,
    transaction: &[u8; 32],
    original_digest: &[u8; 32],
) -> Result<Option<LedgerProgressV1>, Error> {
    confirmations
        .get(archive, transaction)?
        .map(|bytes| archive::decode::<UnloadConfirmation>(&bytes)?.progress(original_digest))
        .transpose()
}

// Inclusion is checked while each certified original is selected, before its cursor can move.
// Absence is ordinary history; a located but foreign or unsuccessful input is an error.
fn contains_successful_unload(
    verified: &iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock,
    network: &iroha_data_model::NetworkId,
    scheme: [u8; 32],
    account: &iroha_data_model::account::AccountId,
    transaction: &[u8; 32],
    original: &[u8],
) -> Result<bool, Error> {
    use iroha_crypto::HashOf;
    use iroha_data_model::{query::CommittedTransaction, transaction::TransactionEntrypoint};
    let block = verified.block();
    let Some(index) = block
        .network_entrypoints()
        .position(|input| input.hash().as_ref() == transaction)
    else {
        return Ok(false);
    };
    let input_index = u32::try_from(index).map_err(|_| Error::Invalid("Unload input index"))?;
    let entrypoint = block
        .network_entrypoint_at(index)
        .ok_or(Error::Proof("Unload input"))?
        .clone();
    let TransactionEntrypoint::External(signed) = &entrypoint else {
        return Err(Error::Invalid("Unload external input"));
    };
    if signed.authority() != account
        || !signed
            .instructions()
            .explicit_instructions()
            .any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<KagemushaWalletLedgerV1>()
                    .is_some_and(|instruction| {
                        instruction.scheme == scheme
                            && matches!(&instruction.action,
                    KagemushaWalletLedgerActionV1::Unload(bytes) if bytes == original)
                    })
            })
    {
        return Err(Error::Invalid("Unload exact original instruction"));
    }
    let (output_index, _) = block
        .network_output_at(input_index)
        .ok_or(Error::Proof("Unload execution output"))?;
    let output = block
        .execution_outputs()
        .get(output_index as usize)
        .ok_or(Error::Proof("Unload output index"))?
        .clone();
    let committed = CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block
            .network_input_proof(input_index)
            .ok_or(Error::Proof("Unload input membership"))?,
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block
            .output_proof(output_index)
            .ok_or(Error::Proof("Unload output membership"))?,
        output,
    };
    verified
        .verify_committed_transaction(network, &committed)
        .map_err(|_| Error::Proof("Unload successful authenticated execution"))?;
    Ok(true)
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Freeze the actual next native Load ordinal and instruction under a stable caller request.
    /// Retrying the same request returns its original instruction, even after credit changes the head.
    /// # Errors
    /// Missing/replaced custody, changed request amount, invalid lifecycle or durable publication failure.
    pub fn prepare_ledger_load(
        &mut self,
        request: [u8; 32],
        amount: u128,
    ) -> Result<Vec<u8>, Error> {
        let _payment = self.scheduler.payment();
        if request == [0; 32] || amount == 0 {
            return Err(Error::Invalid("ledger Load request"));
        }
        let (root, mut manifest) = self.sync_manifest()?;
        self.require_ledger_activation(&manifest)?;
        let scope = self.load_plan_scope();
        if let Some(plan) = projection::selected_load_plan(
            &mut self.archive,
            &manifest.ledger_load_plans,
            &manifest.ledger_load_ordinals,
            &request,
            scope,
        )? {
            if plan.amount != amount {
                return Err(Error::Invalid("changed ledger Load request"));
            }
            return Ok(plan.instruction_original);
        }
        let released = self.indexed_step(&manifest, manifest.indexed.ok_or(Error::NoHead)?)?;
        let core = &released.frozen.capsule.successor_state.core;
        if core.lifecycle != KagemushaWalletLifecycleV1::Active {
            return Err(Error::Invalid("ledger Load lifecycle"));
        }
        let instruction = KagemushaWalletLedgerV1 {
            scheme: self.scheme_id,
            action: KagemushaWalletLedgerActionV1::IssueLoad {
                wallet: self.wallet_id,
                asset: self.proofs.asset.asset_digest(),
                ordinal: core.next_load,
                request_id: request,
                amount,
                charge: None,
            },
        };
        let plan = LoadPlan {
            request,
            amount,
            ordinal: core.next_load,
            instruction: archive::encode(&instruction)?,
        };
        projection::reserve_load_plan(
            &mut self.archive,
            &mut manifest.ledger_load_plans,
            &mut manifest.ledger_load_ordinals,
            &plan,
            scope,
        )?;
        self.publish_manifest(root, &manifest)?;
        Ok(plan.instruction)
    }
    /// Wrap a complete canonical Native transport in the current closed ledger instruction.
    /// This conversion supplies no ledger acceptance or proof authority.
    /// # Errors
    /// Wrong transport kind, malformed original or another wallet incarnation.
    pub fn ledger_instruction(&self, kind: u64, original: &[u8]) -> Result<Vec<u8>, Error> {
        if original.is_empty() || original.len() > LEDGER_INSTRUCTION_MAX_BYTES_V1 {
            return Err(Error::Invalid("ledger transport bound"));
        }
        let action = match kind {
            1 => {
                let frame = valid(KagemushaWalletActivationV1::decode_canonical(
                    original,
                    &self.scheme_id,
                ))?;
                if frame.credential.body.wallet_id != self.wallet_id {
                    return Err(Error::Invalid("activation wallet"));
                }
                KagemushaWalletLedgerActionV1::Activate(original.to_vec())
            }
            2 => {
                let frame = valid(KagemushaWalletUnloadClaimV1::decode_canonical(
                    original,
                    &self.scheme_id,
                ))?;
                if frame.credential.body.wallet_id != self.wallet_id {
                    return Err(Error::Invalid("Unload wallet"));
                }
                KagemushaWalletLedgerActionV1::Unload(original.to_vec())
            }
            3 => {
                let frame = valid(KagemushaWalletCloseLoadsV1::decode_canonical(
                    original,
                    &self.scheme_id,
                ))?;
                if frame.credential.body.wallet_id != self.wallet_id {
                    return Err(Error::Invalid("CloseLoads wallet"));
                }
                KagemushaWalletLedgerActionV1::CloseLoads(original.to_vec())
            }
            _ => return Err(Error::Invalid("ledger transport kind")),
        };
        archive::encode(&KagemushaWalletLedgerV1 {
            scheme: self.scheme_id,
            action,
        })
    }
    /// Return the durably retained exact successful Unload input/output inclusion.
    /// The transaction hash is a locator. The complete retained block, signature, execution
    /// result and original Unload claim independently authenticate the returned confirmation.
    /// # Errors
    /// Absent/rejected transaction, another claim or wallet, invalid inclusion or changed source.
    pub fn confirm_ledger_unload(
        &mut self,
        transaction: [u8; 32],
        original: &[u8],
    ) -> Result<LedgerProgressV1, Error> {
        let claim = valid(KagemushaWalletUnloadClaimV1::decode_canonical(
            original,
            &self.scheme_id,
        ))?;
        if transaction == [0; 32]
            || claim.credential.body.wallet_id != self.wallet_id
            || claim.credential.body.account_digest != self.proofs.enrollment.body.account_digest
        {
            return Err(Error::Invalid("Unload confirmation scope"));
        }
        let original_digest = self.unload_original_digest(&transaction, original)?;
        let (selected, mut manifest) = self.sync_manifest()?;
        if let Some(confirmed) = retained_unload_confirmation(
            &mut self.archive,
            &manifest.ledger_unload_confirmations,
            &transaction,
            &original_digest,
        )? {
            return Ok(confirmed);
        }
        let genesis = Arc::clone(&self.proofs.genesis);
        let (verifier, checkpoint) =
            self.selected_unload_cursor(&manifest, &transaction, &original_digest)?;
        let checkpoint = checkpoint.ok_or(Error::Invalid("Unload confirmation ledger absent"))?;
        let verified = verifier
            .verify_retained_decision(checkpoint.tip())
            .map_err(|_| Error::Proof("Unload selected native decision"))?;
        if !contains_successful_unload(
            &verified,
            &genesis.initial_epoch().network_id,
            self.scheme_id,
            &claim.account,
            &transaction,
            original,
        )? {
            return Err(Error::Invalid(
                "Unload transaction absent from selected block",
            ));
        }
        if self.manifest()?.0 != selected {
            return Err(Error::WitnessLost("Unload confirmation source changed"));
        }
        let progress = ledger::progress(&checkpoint);
        let confirmation = UnloadConfirmation {
            original_digest,
            height: progress.height,
            block_hash: progress.block_hash,
        };
        manifest.ledger_unload_confirmations = manifest.ledger_unload_confirmations.set(
            &mut self.archive,
            transaction,
            &archive::encode(&confirmation)?,
        )?;
        self.publish_manifest(selected, &manifest)?;
        Ok(progress)
    }
}
