//! Exact signed Activate inclusion and source-selected durable confirmation.
use super::*;
mod cursor;
use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
    query::CommittedTransaction,
    sumeragi_finality::{
        MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint, VerifiedSumeragiBlock,
    },
    transaction::{Executable, SignedTransaction, TransactionEntrypoint},
};
use iroha_version::codec::DecodeVersioned;

// Shared with the actual Core signed-ledger transport; Activate itself is at most 16 KiB.
const TRANSACTION_MAX: usize = 64 * 1024;
const CONFIRMATION_MAX: usize = TRANSACTION_MAX + 1024;

/// Durable status of a retained outer attempt or the common inner Activate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationFinalityProgressV1 {
    /// No cursor has been selected for this original.
    NotStarted,
    /// Verified history has reached this height without this transaction's successful inclusion.
    Verifying(LedgerProgressV1),
    /// This registered outer attempt has exact authenticated rejected execution.
    /// Its checkpoint remains retained; another attempt may still activate the wallet.
    Rejected(LedgerProgressV1),
    /// One retained attempt's exact successful inclusion durably activated the wallet.
    /// This does not assert successful execution of every outer attempt.
    Confirmed(LedgerProgressV1),
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ActivationConfirmationV1")]
pub(super) struct Confirmation {
    version: u16,
    activation: [u8; 32],
    signed_transaction: Vec<u8>,
    height: u64,
    block_hash: [u8; 32],
    checkpoint: [u8; 32],
}
impl Confirmation {
    fn require(&self, plan: &Plan) -> Result<(), Error> {
        if self.version != 1
            || Some(self.activation) != plan.output
            || self.activation == [0; 32]
            || self.signed_transaction.is_empty()
            || self.signed_transaction.len() > TRANSACTION_MAX
            || self.height < 2
            || self.block_hash == [0; 32]
            || self.checkpoint == [0; 32]
        {
            return Err(Error::WitnessLost("activation confirmation binding"));
        }
        Ok(())
    }
    fn progress(&self) -> LedgerProgressV1 {
        LedgerProgressV1 {
            height: self.height,
            block_hash: self.block_hash,
        }
    }
}

/// DATA intake. The exact account, scheme, network and Activate original come from Native.
fn signed_activate(
    bytes: &[u8],
    network: &NetworkId,
    scheme: &[u8; 32],
    account_digest: &[u8; 32],
    activation: &[u8],
) -> Result<SignedTransaction, Error> {
    if bytes.is_empty() || bytes.len() > TRANSACTION_MAX {
        return Err(Error::Invalid("activation signed transaction bound"));
    }
    let transaction =
        norito::with_decode_limits_scope(norito::canonical_decode_limits(bytes.len()), || {
            SignedTransaction::decode_all_versioned(bytes)
        })
        .map_err(|_| Error::Invalid("activation signed transaction encoding"))?;
    let public = transaction
        .authority()
        .try_signatory()
        .ok_or(Error::Invalid("activation single account key"))?;
    let (algorithm, key) = public
        .try_to_bytes()
        .map_err(|_| Error::Invalid("activation account key"))?;
    if transaction
        .encode_wire_v1()
        .map_err(|_| Error::Invalid("activation wire"))?
        != bytes
        || transaction.network_id() != Some(network)
        || transaction.multisig_signatures().is_some()
        || transaction.signature_count() != 1
        || transaction.attachments().is_some()
        || algorithm != iroha_crypto::Algorithm::Ed25519
        || key.len() != 32
        || valid(kagemusha_wallet_account_digest_v1(transaction.authority()))? != *account_digest
    {
        return Err(Error::Invalid("activation signed transaction authority"));
    }
    transaction
        .verify_signature()
        .map_err(|_| Error::Proof("activation account signature"))?;
    transaction
        .payload()
        .validate_fee_payment_intent()
        .map_err(|_| Error::Invalid("activation fee intent"))?;
    let Executable::Instructions(instructions) = transaction.instructions() else {
        return Err(Error::Invalid("activation explicit instruction"));
    };
    if instructions.len() != 1 {
        return Err(Error::Invalid("activation sole instruction"));
    }
    let instruction = instructions[0]
        .as_any()
        .downcast_ref::<KagemushaWalletLedgerV1>()
        .ok_or(Error::Invalid("activation instruction type"))?;
    if instruction.scheme != *scheme
        || !matches!(&instruction.action, KagemushaWalletLedgerActionV1::Activate(bytes) if bytes == activation)
    {
        return Err(Error::Invalid("activation exact retained original"));
    }
    Ok(transaction)
}

fn successful_inclusion(
    verified: &VerifiedSumeragiBlock,
    network: &NetworkId,
    signed: SignedTransaction,
) -> Result<LedgerProgressV1, Error> {
    let (progress, accepted) = authenticated_inclusion(verified, network, signed)?;
    if !accepted {
        return Err(Error::Proof(
            "activation successful authenticated execution",
        ));
    }
    Ok(progress)
}

/// Classify only the outcome of an exact input/output whose ordinary finality has
/// already been genuinely verified. A proof failure is never classified as rejection.
fn authenticated_inclusion(
    verified: &VerifiedSumeragiBlock,
    network: &NetworkId,
    signed: SignedTransaction,
) -> Result<(LedgerProgressV1, bool), Error> {
    if verified.height() < 2
        || signed.network_id() != Some(network)
        || signed.verify_signature().is_err()
    {
        return Err(Error::Proof("activation authenticated transaction binding"));
    }
    let expected = TransactionEntrypoint::External(signed);
    let block = verified.block();
    let index = block
        .network_entrypoints()
        .position(|value| value.hash() == expected.hash())
        .ok_or(Error::Invalid("activation absent from selected block"))?;
    let input_index = u32::try_from(index).map_err(|_| Error::Invalid("activation input index"))?;
    let entrypoint = block
        .network_entrypoint_at(index)
        .ok_or(Error::Proof("activation input"))?
        .clone();
    // Bind the actual original, not a caller-provided transaction hash.
    if entrypoint != expected {
        return Err(Error::Proof("activation exact input"));
    }
    let (output_index, _) = block
        .network_output_at(input_index)
        .ok_or(Error::Proof("activation execution output"))?;
    let output = block
        .execution_outputs()
        .get(output_index as usize)
        .ok_or(Error::Proof("activation output index"))?
        .clone();
    let committed = CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block
            .network_input_proof(input_index)
            .ok_or(Error::Proof("activation input membership"))?,
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block
            .output_proof(output_index)
            .ok_or(Error::Proof("activation output membership"))?,
        output,
    };
    if !committed.verify_inclusion_in_block(block) {
        return Err(Error::Proof(
            "activation authenticated input/output membership",
        ));
    }
    let accepted = committed.result().is_ok();
    if accepted {
        verified
            .verify_committed_transaction(network, &committed)
            .map_err(|_| Error::Proof("activation successful authenticated execution"))?;
    }
    Ok((
        LedgerProgressV1 {
            height: verified.height(),
            block_hash: *block.hash().as_ref(),
        },
        accepted,
    ))
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    fn require_activation_confirmation_original(
        &mut self,
        plan: &Plan,
        value: &Confirmation,
    ) -> Result<(), Error> {
        value.require(plan)?;
        let attempt = self
            .retained_activation_attempt(plan, &value.signed_transaction)?
            .ok_or(Error::WitnessLost("activation confirming attempt absent"))?;
        if attempt.rejected {
            return Err(Error::WitnessLost("activation confirming attempt rejected"));
        }
        let original = self
            .archive
            .read_object(&value.checkpoint, MAX_FINALITY_CHECKPOINT_BYTES)?;
        if crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(&original)
            != value.checkpoint
        {
            return Err(Error::WitnessLost(
                "activation confirming checkpoint digest",
            ));
        }
        let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&original)
            .map_err(|_| Error::WitnessLost("activation confirming checkpoint"))?;
        if ledger::progress(&checkpoint) != value.progress() {
            return Err(Error::WitnessLost(
                "activation confirming checkpoint binding",
            ));
        }
        Ok(())
    }
    pub(super) fn retained_activation_confirmation(
        &mut self,
        plan: &Plan,
    ) -> Result<Option<Confirmation>, Error> {
        let Some(address) = plan.confirmation else {
            return Ok(None);
        };
        let value: Confirmation =
            archive::decode(&self.archive.read_object(&address, CONFIRMATION_MAX)?)?;
        self.require_activation_confirmation_original(plan, &value)?;
        Ok(Some(value))
    }
    fn publish_activation_confirmation(
        &mut self,
        root: [u8; 32],
        mut manifest: manifest::Manifest,
        plan: &Plan,
        confirmation: &Confirmation,
    ) -> Result<(), Error> {
        self.require_activation_confirmation_original(plan, confirmation)?;
        let selected = manifest
            .activation
            .ok_or(Error::WitnessLost("activation plan absent"))?;
        if self.manifest()?.0 != root
            || plan.confirmation.is_some()
            || self.archive.read_object(&selected, PLAN_MAX)? != archive::encode(plan)?
        {
            return Err(Error::WitnessLost("activation confirmation source changed"));
        }
        let mut confirmed = plan.clone();
        // Every attempt keeps its own selected prefix; the winning checkpoint is
        // an independent immutable original, never an alias to a global cursor.
        confirmed.confirmation = Some(
            self.archive
                .write_object(&archive::encode(confirmation)?, CONFIRMATION_MAX)?,
        );
        manifest.activation = Some(
            self.archive
                .write_object(&archive::encode(&confirmed)?, PLAN_MAX)?,
        );
        self.publish_manifest(root, &manifest)?;
        Ok(())
    }
    /// Require the immutable fact born only after Native verified exact successful inclusion.
    /// This is local custody, with no current issuer, ledger, or online freshness requirement.
    pub(in crate::kagemusha_wallet_state_v1) fn require_ledger_activation(
        &mut self,
        manifest: &manifest::Manifest,
    ) -> Result<(), Error> {
        let address = manifest
            .activation
            .ok_or(Error::Invalid("ledger activation unconfirmed"))?;
        let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)?;
        plan.require(&self.scheme_id, &self.wallet_id, &plan.asset)?;
        self.retained_activation(&plan)?
            .ok_or(Error::WitnessLost("activation output absent"))?;
        self.retained_activation_confirmation(&plan)?
            .ok_or(Error::Invalid("ledger activation unconfirmed"))?;
        Ok(())
    }
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Confirm a registered signed Activate against its cursor or the selected native ledger tip.
    /// Successful return follows durable publication. Exact retry remains local after restart
    /// or later ledger advancement. HTTP receipts and caller transaction hashes are not authority.
    /// # Errors
    /// Missing/mismatched originals, another transaction, failed execution, unverified prefix,
    /// changed selection, unavailable custody, or uncertain publication never allow first Load.
    pub fn confirm_ledger_activation(
        &mut self,
        signed_wire: &[u8],
    ) -> Result<LedgerProgressV1, Error> {
        let _payment = self.scheduler.payment();
        self.clean_activation_cursor(signed_wire)?;
        let (root, manifest) = self.sync_manifest()?;
        let address = manifest
            .activation
            .ok_or(Error::Invalid("activation plan absent"))?;
        let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)?;
        plan.require(&self.scheme_id, &self.wallet_id, &self.proofs.asset)?;
        self.authenticate_activation_plan(&plan)?;
        let activation = self
            .retained_activation(&plan)?
            .ok_or(Error::Invalid("activation output absent"))?;
        let genesis = Arc::clone(&self.proofs.genesis);
        let network = &genesis.initial_epoch().network_id;
        let signed = signed_activate(
            signed_wire,
            network,
            &self.scheme_id,
            &plan.credential.body.account_digest,
            &activation,
        )?;
        if let Some(confirmed) = self.retained_activation_confirmation(&plan)? {
            return Ok(confirmed.progress());
        }
        // Prefer the independent cursor. The global tip is only a convenience when
        // no cursor exists, and cannot overwrite or skip a selected activation cursor.
        let (verifier, checkpoint) =
            if let Some(cursor) = self.retained_activation_cursor(&plan, signed_wire)? {
                let (verifier, checkpoint) = self.restore_activation_cursor(&cursor)?;
                (verifier, checkpoint)
            } else {
                let (verifier, checkpoint) = self.selected_ledger(&manifest, &genesis)?;
                let checkpoint = checkpoint.ok_or(Error::Invalid("activation ledger absent"))?;
                (verifier, checkpoint)
            };
        let verified = verifier
            .verify_retained_decision(checkpoint.tip())
            .map_err(|_| Error::Proof("activation selected native decision"))?;
        let progress = successful_inclusion(&verified, network, signed)?;
        let confirmation = Confirmation {
            version: 1,
            activation: plan
                .output
                .ok_or(Error::WitnessLost("activation output absent"))?,
            signed_transaction: signed_wire.to_vec(),
            height: progress.height,
            block_hash: progress.block_hash,
            checkpoint: self.archive.write_object(
                &checkpoint
                    .encode_canonical()
                    .map_err(|_| Error::Proof("activation confirmation checkpoint encoding"))?,
                MAX_FINALITY_CHECKPOINT_BYTES,
            )?,
        };
        self.publish_activation_confirmation(root, manifest, &plan, &confirmation)?;
        Ok(progress)
    }
}

#[cfg(test)]
mod tests;
