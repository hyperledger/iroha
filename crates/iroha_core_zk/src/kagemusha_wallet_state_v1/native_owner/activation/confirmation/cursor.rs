//! Activation-bound native verification: later global ledger activity cannot skip Activate.
use super::*;
use iroha_data_model::sumeragi_finality::{
    MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint,
};

const CURSOR_MAX: usize = TRANSACTION_MAX + MAX_FINALITY_CHECKPOINT_BYTES + 4096;

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ActivationAttemptV1")]
pub(super) struct Attempt {
    activation: [u8; 32],
    // Exact immutable signed wire stored once, separately from compact progress selectors.
    signed_transaction: [u8; 32],
    cursor: Option<[u8; 32]>,
    retired_cursor: Option<[u8; 32]>,
    pub(super) rejected: bool,
}
impl Attempt {
    fn require(&self, plan: &Plan, signed_wire: &[u8]) -> Result<(), Error> {
        if Some(self.activation) != plan.output
            || self.activation == [0; 32]
            || self.signed_transaction == [0; 32]
            || self.cursor == Some([0; 32])
            || self.retired_cursor == Some([0; 32])
            || (self.rejected && self.cursor.is_none())
            || (self.retired_cursor.is_some() && self.cursor == self.retired_cursor)
        {
            return Err(Error::WitnessLost("activation attempt binding"));
        }
        if self.signed_transaction != attempt_key(signed_wire)? {
            return Err(Error::OperationConflict);
        }
        Ok(())
    }
}
fn attempt_key(signed_wire: &[u8]) -> Result<[u8; 32], Error> {
    if signed_wire.is_empty() || signed_wire.len() > TRANSACTION_MAX {
        return Err(Error::Invalid("activation attempt original bound"));
    }
    Ok(crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(signed_wire))
}

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ActivationVerifierCursorV1")]
pub(super) struct Cursor {
    activation: [u8; 32],
    signed_transaction: Vec<u8>,
    // Owned complete originals, never aliases to a global checkpoint which cleanup can retire.
    checkpoint: Vec<u8>,
}
/// Decode the sole current cursor schema. An unknown or corrupt original never
/// means absence and cannot restart verification from genesis.
fn decode_cursor(bytes: &[u8]) -> Result<Cursor, Error> {
    archive::decode(bytes)
}

impl Cursor {
    fn require(&self, plan: &Plan, signed_wire: &[u8]) -> Result<(), Error> {
        if Some(self.activation) != plan.output
            || self.activation == [0; 32]
            || self.signed_transaction.is_empty()
            || self.signed_transaction.len() > TRANSACTION_MAX
            || self.checkpoint.is_empty()
            || self.checkpoint.len() > MAX_FINALITY_CHECKPOINT_BYTES
        {
            return Err(Error::WitnessLost("activation cursor binding"));
        }
        if self.signed_transaction != signed_wire {
            return Err(Error::OperationConflict);
        }
        Ok(())
    }
    // Only called for a checkpoint from a custody-selected exact original. No
    // foreign checkpoint/HTTP verdict reaches this local recovery boundary.
    fn restore(
        &self,
        genesis: &SumeragiFinalityVerifier,
    ) -> Result<(SumeragiFinalityVerifier, SumeragiFinalityCheckpoint), Error> {
        let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&self.checkpoint)
            .map_err(|_| Error::WitnessLost("activation cursor checkpoint"))?;
        let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            &checkpoint,
            &genesis.initial_epoch().network_id,
            &genesis.chain_id(),
        )
        .map_err(|_| Error::WitnessLost("activation cursor checkpoint root"))?;
        if verifier.initial_epoch() != genesis.initial_epoch()
            || verifier.instance() != genesis.instance()
        {
            return Err(Error::WitnessLost("activation cursor genesis binding"));
        }
        Ok((verifier, checkpoint))
    }
}
impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    pub(super) fn retained_activation_attempt(
        &mut self,
        plan: &Plan,
        signed_wire: &[u8],
    ) -> Result<Option<Attempt>, Error> {
        let Some(value) = plan
            .attempts
            .get(&mut self.archive, &attempt_key(signed_wire)?)?
        else {
            return Ok(None);
        };
        let attempt: Attempt = archive::decode(&value)?;
        attempt.require(plan, signed_wire)?;
        if self
            .archive
            .read_object(&attempt.signed_transaction, TRANSACTION_MAX)?
            != signed_wire
        {
            return Err(Error::WitnessLost("activation attempt original"));
        }
        Ok(Some(attempt))
    }
    fn plan_with_attempt(&mut self, plan: &Plan, attempt: &Attempt) -> Result<Plan, Error> {
        let original = self
            .archive
            .read_object(&attempt.signed_transaction, TRANSACTION_MAX)?;
        attempt.require(plan, &original)?;
        let mut next = plan.clone();
        // IndexRoot enforces a <=512-byte leaf and <=256 bounded nodes per access.
        // COW metadata never repeats the up-to-64KiB signed transaction per block.
        next.attempts = plan.attempts.set(
            &mut self.archive,
            attempt.signed_transaction,
            &archive::encode(attempt)?,
        )?;
        Ok(next)
    }
    pub(super) fn publish_activation_attempt(
        &mut self,
        root: [u8; 32],
        mut manifest: manifest::Manifest,
        plan: &Plan,
        signed_wire: &[u8],
    ) -> Result<(), Error> {
        let selected = manifest
            .activation
            .ok_or(Error::WitnessLost("activation attempt plan"))?;
        if self.manifest()?.0 != root
            || plan.confirmation.is_some()
            || self.archive.read_object(&selected, PLAN_MAX)? != archive::encode(plan)?
            || self
                .retained_activation_attempt(plan, signed_wire)?
                .is_some()
        {
            return Err(Error::OperationConflict);
        }
        let attempt = Attempt {
            activation: plan
                .output
                .ok_or(Error::Invalid("activation output absent"))?,
            signed_transaction: self.archive.write_object(signed_wire, TRANSACTION_MAX)?,
            cursor: None,
            retired_cursor: None,
            rejected: false,
        };
        let next = self.plan_with_attempt(plan, &attempt)?;
        manifest.activation = Some(
            self.archive
                .write_object(&archive::encode(&next)?, PLAN_MAX)?,
        );
        self.publish_manifest(root, &manifest)?;
        Ok(())
    }
    pub(super) fn retained_activation_cursor(
        &mut self,
        plan: &Plan,
        signed_wire: &[u8],
    ) -> Result<Option<Cursor>, Error> {
        let attempt = self
            .retained_activation_attempt(plan, signed_wire)?
            .ok_or(Error::Invalid("activation attempt not retained"))?;
        let Some(address) = attempt.cursor else {
            return Ok(None);
        };
        let cursor = decode_cursor(&self.archive.read_object(&address, CURSOR_MAX)?)?;
        cursor.require(plan, signed_wire)?;
        Ok(Some(cursor))
    }
    pub(super) fn clean_activation_cursor(&mut self, signed_wire: &[u8]) -> Result<(), Error> {
        let (root, mut manifest) = self.sync_manifest()?;
        let address = manifest
            .activation
            .ok_or(Error::Invalid("activation plan absent"))?;
        let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)?;
        plan.require(&self.scheme_id, &self.wallet_id, &plan.asset)?;
        let mut attempt = self
            .retained_activation_attempt(&plan, signed_wire)?
            .ok_or(Error::Invalid("activation attempt not retained"))?;
        if let Some(retired) = attempt.retired_cursor {
            if attempt.cursor == Some(retired)
                || plan.output == Some(retired)
                || plan.confirmation == Some(retired)
                || self
                    .retained_activation_confirmation(&plan)?
                    .is_some_and(|c| c.checkpoint == retired)
            {
                return Err(Error::WitnessLost(
                    "activation cleanup selects current original",
                ));
            }
            if let Some(bytes) = self.archive.get(ArchiveKey::Object(retired), CURSOR_MAX)? {
                let actual =
                    crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(
                        &bytes,
                    );
                if actual != retired {
                    return Err(Error::WitnessLost("activation retired cursor digest"));
                }
                let cursor = decode_cursor(&bytes)?;
                // An address belonging to another attempt can never authorize its deletion.
                cursor.require(&plan, signed_wire)?;
                self.archive.remove(ArchiveKey::Object(retired))?;
            }
            attempt.retired_cursor = None;
            let next = self.plan_with_attempt(&plan, &attempt)?;
            manifest.activation = Some(
                self.archive
                    .write_object(&archive::encode(&next)?, PLAN_MAX)?,
            );
            self.publish_manifest(root, &manifest)?;
        }
        Ok(())
    }
    fn publish_activation_cursor(
        &mut self,
        root: [u8; 32],
        mut manifest: manifest::Manifest,
        plan: &Plan,
        cursor: &Cursor,
        rejected: bool,
    ) -> Result<(), Error> {
        cursor.require(plan, &cursor.signed_transaction)?;
        let selected = manifest
            .activation
            .ok_or(Error::WitnessLost("activation cursor plan"))?;
        let mut attempt = self
            .retained_activation_attempt(plan, &cursor.signed_transaction)?
            .ok_or(Error::Invalid("activation attempt not retained"))?;
        if self.manifest()?.0 != root
            || plan.confirmation.is_some()
            || attempt.retired_cursor.is_some()
            || attempt.rejected
            || self.archive.read_object(&selected, PLAN_MAX)? != archive::encode(plan)?
        {
            return Err(Error::WitnessLost("activation cursor source changed"));
        }
        let address = self
            .archive
            .write_object(&archive::encode(cursor)?, CURSOR_MAX)?;
        attempt.retired_cursor = attempt.cursor.filter(|previous| *previous != address);
        attempt.cursor = Some(address);
        attempt.rejected = rejected;
        let next = self.plan_with_attempt(plan, &attempt)?;
        manifest.activation = Some(
            self.archive
                .write_object(&archive::encode(&next)?, PLAN_MAX)?,
        );
        self.publish_manifest(root, &manifest)?;
        self.clean_activation_cursor(&cursor.signed_transaction)
    }
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    fn activation_cursor_root(&self) -> Result<(), Error> {
        let genesis = &self.proofs.genesis;
        let (scheme, chain) = self.proofs.ledger_scope()?;
        if scheme.scheme_id() != self.scheme_id
            || chain != genesis.chain_id()
            || genesis.initial_epoch().network_id.as_bytes() != &scheme.network_id
            || genesis.root_scope() != iroha_data_model::block::consensus::SumeragiRootScope::Global
        {
            return Err(Error::Proof("activation cursor root scope"));
        }
        Ok(())
    }
    pub(super) fn restore_activation_cursor(
        &self,
        cursor: &Cursor,
    ) -> Result<(SumeragiFinalityVerifier, SumeragiFinalityCheckpoint), Error> {
        self.activation_cursor_root()?;
        cursor.restore(&self.proofs.genesis)
    }
    fn activation_cursor_intake(
        &mut self,
        plan: &Plan,
        signed_wire: &[u8],
    ) -> Result<SignedTransaction, Error> {
        plan.require(&self.scheme_id, &self.wallet_id, &self.proofs.asset)?;
        self.authenticate_activation_plan(plan)?;
        self.activation_cursor_root()?;
        let original = self
            .retained_activation(plan)?
            .ok_or(Error::Invalid("activation output absent"))?;
        signed_activate(
            signed_wire,
            &self.proofs.genesis.initial_epoch().network_id,
            &self.scheme_id,
            &plan.credential.body.account_digest,
            &original,
        )
    }
    /// Retain one exact account-authorized outer transaction over the immutable Activate.
    /// This is DATA intake, not expiry, non-inclusion or financial authority. Every first
    /// POST must follow successful retention. Repeating known bytes is local and idempotent.
    /// # Errors
    /// Wrong account/network/inner original, new intake after family confirmation, unavailable
    /// or uncertain custody, or a changed selected plan never authorize a replacement or reset.
    pub fn retain_activation_attempt(
        &mut self,
        signed_wire: &[u8],
    ) -> Result<ActivationFinalityProgressV1, Error> {
        let _payment = self.scheduler.payment();
        let (root, manifest) = self.sync_manifest()?;
        let address = manifest
            .activation
            .ok_or(Error::Invalid("activation plan absent"))?;
        let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)?;
        self.activation_cursor_intake(&plan, signed_wire)?;
        if self
            .retained_activation_attempt(&plan, signed_wire)?
            .is_none()
        {
            self.publish_activation_attempt(root, manifest, &plan, signed_wire)?;
        }
        self.activation_finality_progress(signed_wire)
    }
    /// Read this registered attempt's cursor, or the immutable family activation confirmation.
    /// Confirmed never asserts that every outer attempt executed successfully.
    /// # Errors
    /// Changed transaction, missing selected original, corrupt cursor or untrusted installation.
    pub fn activation_finality_progress(
        &mut self,
        signed_wire: &[u8],
    ) -> Result<ActivationFinalityProgressV1, Error> {
        let (_, manifest) = self.sync_manifest()?;
        let address = manifest
            .activation
            .ok_or(Error::Invalid("activation plan absent"))?;
        let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)?;
        self.activation_cursor_intake(&plan, signed_wire)?;
        let attempt = self
            .retained_activation_attempt(&plan, signed_wire)?
            .ok_or(Error::Invalid("activation attempt not retained"))?;
        if let Some(confirmed) = self.retained_activation_confirmation(&plan)? {
            return Ok(ActivationFinalityProgressV1::Confirmed(
                confirmed.progress(),
            ));
        }
        let Some(cursor) = self.retained_activation_cursor(&plan, signed_wire)? else {
            return Ok(ActivationFinalityProgressV1::NotStarted);
        };
        let (_, checkpoint) = self.restore_activation_cursor(&cursor)?;
        let progress = ledger::progress(&checkpoint);
        Ok(if attempt.rejected {
            ActivationFinalityProgressV1::Rejected(progress)
        } else {
            ActivationFinalityProgressV1::Verifying(progress)
        })
    }
    /// Verify one exact next block, then atomically retain progress or its exact execution outcome.
    /// Authenticated rejected execution is terminal only for this attempt; it never opens Load.
    /// This cursor never advances past the matching transaction without retaining its outcome.
    /// # Errors
    /// Gaps, invalid finality, changed transaction, missing selected originals, or uncertain
    /// publication remain errors and never become an authenticated Rejected status.
    pub fn ingest_activation_finality(
        &mut self,
        signed_wire: &[u8],
        original: &[u8],
    ) -> Result<ActivationFinalityProgressV1, Error> {
        let _payment = self.scheduler.payment();
        let candidate = ledger::proof_original(original)?;
        self.clean_activation_cursor(signed_wire)?;
        let (root, manifest) = self.sync_manifest()?;
        let address = manifest
            .activation
            .ok_or(Error::Invalid("activation plan absent"))?;
        let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)?;
        let signed = self.activation_cursor_intake(&plan, signed_wire)?;
        if let Some(confirmed) = self.retained_activation_confirmation(&plan)? {
            return Ok(ActivationFinalityProgressV1::Confirmed(
                confirmed.progress(),
            ));
        }
        let attempt = self
            .retained_activation_attempt(&plan, signed_wire)?
            .ok_or(Error::Invalid("activation attempt not retained"))?;
        let selected = self.retained_activation_cursor(&plan, signed_wire)?;
        let (mut verifier, previous) = if let Some(cursor) = &selected {
            let (verifier, checkpoint) = self.restore_activation_cursor(cursor)?;
            (verifier, Some(checkpoint))
        } else {
            (self.proofs.genesis.as_ref().clone(), None)
        };
        if let Some(previous) = &previous {
            if attempt.rejected {
                return Ok(ActivationFinalityProgressV1::Rejected(ledger::progress(
                    previous,
                )));
            }
            if candidate.height() == previous.height() {
                verifier
                    .verify_retained_decision(&candidate)
                    .map_err(|_| Error::Proof("activation cursor retry"))?;
                return Ok(ActivationFinalityProgressV1::Verifying(ledger::progress(
                    previous,
                )));
            }
            if previous.height().checked_add(1) != Some(candidate.height()) {
                return Err(Error::Invalid("activation cursor exact next height"));
            }
        } else if candidate.height() != 1 {
            return Err(Error::Invalid("activation cursor starts at genesis"));
        }
        let verified = if previous.is_none() {
            verifier
                .verify_retained_decision(&candidate)
                .or_else(|_| verifier.verify(&candidate))
                .map_err(|_| Error::Proof("activation cursor genesis"))?
        } else {
            verifier
                .verify(&candidate)
                .map_err(|_| Error::Proof("activation cursor continuity"))?
        };
        let expected = TransactionEntrypoint::External(signed.clone());
        let included = verified
            .block()
            .network_entrypoints()
            .any(|entry| entry.hash() == expected.hash());
        // Only an authenticated rejection is a terminal attempt-local result. Invalid
        // membership, substituted input and failed finality remain errors, never Rejected.
        let inclusion = if included {
            Some(authenticated_inclusion(
                &verified,
                &self.proofs.genesis.initial_epoch().network_id,
                signed,
            )?)
        } else {
            None
        };
        if let Some((progress, true)) = inclusion {
            let confirmation = Confirmation {
                version: 1,
                activation: plan
                    .output
                    .ok_or(Error::WitnessLost("activation output absent"))?,
                signed_transaction: signed_wire.to_vec(),
                height: progress.height,
                block_hash: progress.block_hash,
                checkpoint: self.archive.write_object(
                    &verifier
                        .export_checkpoint(&candidate)
                        .map_err(|_| Error::Proof("activation confirmation checkpoint"))?
                        .encode_canonical()
                        .map_err(|_| Error::Proof("activation confirmation checkpoint encoding"))?,
                    MAX_FINALITY_CHECKPOINT_BYTES,
                )?,
            };
            self.publish_activation_confirmation(root, manifest, &plan, &confirmation)?;
            return Ok(ActivationFinalityProgressV1::Confirmed(progress));
        }
        let checkpoint = verifier
            .export_checkpoint(&candidate)
            .map_err(|_| Error::Proof("activation cursor checkpoint"))?;
        let cursor = Cursor {
            activation: plan
                .output
                .ok_or(Error::WitnessLost("activation output absent"))?,
            signed_transaction: signed_wire.to_vec(),
            checkpoint: checkpoint
                .encode_canonical()
                .map_err(|_| Error::Proof("activation cursor checkpoint encoding"))?,
        };
        let rejected = inclusion.is_some_and(|(_, accepted)| !accepted);
        self.publish_activation_cursor(root, manifest, &plan, &cursor, rejected)?;
        let progress = ledger::progress(&checkpoint);
        Ok(if rejected {
            ActivationFinalityProgressV1::Rejected(progress)
        } else {
            ActivationFinalityProgressV1::Verifying(progress)
        })
    }
}

#[cfg(test)]
mod tests;
