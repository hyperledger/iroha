//! Exact signed Activate attempts and their direct ledger finality outcomes.
use super::super::ledger_outcome::{
    self, LedgerAttemptIngestV1, LedgerAttemptOutcomeV1, LedgerOutcome, OfferedOutcome,
};
use super::*;
use crate::kagemusha_wallet_state_v1::decode_attempt_error;
use iroha_data_model::{
    NetworkId,
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
    transaction::{Executable, SignedTransaction},
};
use iroha_version::codec::DecodeVersioned;

// Shared with the actual Core signed-ledger transport; Activate itself is at most 16 KiB.
const TRANSACTION_MAX: usize = 64 * 1024;
const CONFIRMATION_MAX: usize = TRANSACTION_MAX + 1024;

/// One retained outer attempt over the wallet's single immutable Activate.
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ActivationAttemptV1")]
pub(super) struct Attempt {
    activation: [u8; 32],
    // Exact immutable signed wire stored once, separately from its compact outcome.
    signed_transaction: [u8; 32],
    // The first authenticated rejected execution of this attempt, never replaced. Another
    // attempt may still activate the wallet.
    pub(super) rejection: Option<LedgerOutcome>,
}
impl Attempt {
    fn require(&self, plan: &Plan, signed_wire: &[u8]) -> Result<(), Error> {
        if Some(self.activation) != plan.output
            || self.activation == [0; 32]
            || self.signed_transaction == [0; 32]
            || self.rejection.is_some_and(|outcome| outcome.accepted())
        {
            return Err(Error::WitnessLost("activation attempt binding"));
        }
        if let Some(rejection) = &self.rejection {
            rejection.require()?;
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
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::ActivationConfirmationV1")]
pub(super) struct Confirmation {
    version: u16,
    activation: [u8; 32],
    signed_transaction: Vec<u8>,
    outcome: LedgerOutcome,
}
impl Confirmation {
    fn require(&self, plan: &Plan) -> Result<(), Error> {
        self.outcome.require()?;
        if self.version != 1
            || Some(self.activation) != plan.output
            || self.activation == [0; 32]
            || self.signed_transaction.is_empty()
            || self.signed_transaction.len() > TRANSACTION_MAX
            || !self.outcome.accepted()
        {
            return Err(Error::WitnessLost("activation confirmation binding"));
        }
        Ok(())
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
        .map_err(|error| match error {
            iroha_version::error::Error::NoritoResourceLimit(original) => decode_attempt_error(
                original,
                Error::Invalid("activation signed transaction encoding"),
            ),
            _ => Error::Invalid("activation signed transaction encoding"),
        })?;
    let public = transaction
        .authority()
        .try_signatory()
        .ok_or(Error::Invalid("activation single account key"))?;
    let (algorithm, key) = public
        .try_to_bytes()
        .map_err(|_| Error::Invalid("activation account key"))?;
    let canonical = norito::core::classify_decode_attempt(|| transaction.encode_wire_v1())
        .map_err(|error| decode_attempt_error(error, Error::Invalid("activation wire")))?;
    if canonical != bytes
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
    drop(canonical);
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
        // COW metadata never repeats the up-to-64KiB signed transaction per attempt.
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
            rejection: None,
        };
        let next = self.plan_with_attempt(plan, &attempt)?;
        manifest.activation = Some(
            self.archive
                .write_object(&archive::encode(&next)?, PLAN_MAX)?,
        );
        self.publish_manifest(root, &manifest)?;
        Ok(())
    }
    // Retain the first authenticated rejection of one attempt under the same fences as a
    // confirmation: unchanged root, unchanged selected plan bytes and no family confirmation.
    fn publish_activation_rejection(
        &mut self,
        root: [u8; 32],
        mut manifest: manifest::Manifest,
        plan: &Plan,
        attempt: &Attempt,
    ) -> Result<(), Error> {
        let selected = manifest
            .activation
            .ok_or(Error::WitnessLost("activation attempt plan"))?;
        if self.manifest()?.0 != root
            || plan.confirmation.is_some()
            || self.archive.read_object(&selected, PLAN_MAX)? != archive::encode(plan)?
        {
            return Err(Error::WitnessLost("activation outcome source changed"));
        }
        let next = self.plan_with_attempt(plan, attempt)?;
        manifest.activation = Some(
            self.archive
                .write_object(&archive::encode(&next)?, PLAN_MAX)?,
        );
        self.publish_manifest(root, &manifest)?;
        Ok(())
    }
    // Recheck the retained winning attempt and the complete exact finality original read from
    // its immutable archive address. This is custody validation, not new finality authority.
    fn require_activation_confirmation_original(
        &mut self,
        plan: &Plan,
        value: &Confirmation,
    ) -> Result<(), Error> {
        value.require(plan)?;
        let attempt = self
            .retained_activation_attempt(plan, &value.signed_transaction)?
            .ok_or(Error::WitnessLost("activation confirming attempt absent"))?;
        if attempt.rejection.is_some() {
            return Err(Error::WitnessLost("activation confirming attempt rejected"));
        }
        let entrypoint = ledger_outcome::retained_entrypoint(&value.signed_transaction)?;
        self.retained_ledger_original(&value.outcome, &entrypoint)
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
        // Every attempt keeps its own originals; the winning finality original is an
        // independent immutable object, never an alias to a global checkpoint.
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
    fn selected_activation_plan(&mut self, manifest: &manifest::Manifest) -> Result<Plan, Error> {
        let address = manifest
            .activation
            .ok_or(Error::Invalid("activation plan absent"))?;
        archive::decode(&self.archive.read_object(&address, PLAN_MAX)?)
    }
    // The family confirmation, else this attempt's retained rejection, else Awaiting under the
    // entrypoint hash Native derived from the retained wire. Reads never verify or write.
    fn activation_outcome(
        &mut self,
        plan: &Plan,
        signed_wire: &[u8],
        signed: &SignedTransaction,
    ) -> Result<LedgerAttemptOutcomeV1, Error> {
        let attempt = self
            .retained_activation_attempt(plan, signed_wire)?
            .ok_or(Error::Invalid("activation attempt not retained"))?;
        if let Some(confirmed) = self.retained_activation_confirmation(plan)? {
            return Ok(LedgerAttemptOutcomeV1::Confirmed(
                confirmed.outcome.commit(),
            ));
        }
        let entrypoint = ledger_outcome::entrypoint(signed)?;
        if let Some(rejection) = &attempt.rejection {
            self.retained_ledger_original(rejection, &entrypoint)?;
            return Ok(rejection.attempt());
        }
        Ok(LedgerAttemptOutcomeV1::Awaiting { entrypoint })
    }
    // Offer one original for an intake-checked attempt. A family confirmation answers every
    // original without verification or a write. A retained rejection is reconciled and never
    // replaced. Otherwise exactly one original is verified, written and selected with its
    // outcome by one fenced manifest publication.
    #[allow(clippy::too_many_arguments)]
    fn ingest_activation_original(
        &mut self,
        root: [u8; 32],
        manifest: manifest::Manifest,
        genesis: &SumeragiFinalityVerifier,
        plan: &Plan,
        signed_wire: &[u8],
        signed: &SignedTransaction,
        bytes: &[u8],
    ) -> Result<LedgerAttemptIngestV1, Error> {
        if let Some(confirmed) = self.retained_activation_confirmation(plan)? {
            return Ok(LedgerAttemptIngestV1::Outcome(
                LedgerAttemptOutcomeV1::Confirmed(confirmed.outcome.commit()),
            ));
        }
        let mut attempt = self
            .retained_activation_attempt(plan, signed_wire)?
            .ok_or(Error::Invalid("activation attempt not retained"))?;
        let entrypoint = ledger_outcome::entrypoint(signed)?;
        if let Some(rejection) = attempt.rejection {
            self.retained_ledger_original(&rejection, &entrypoint)?;
            return self
                .reconcile_ledger_original(&manifest, genesis, &rejection, signed, bytes)
                .map(LedgerAttemptIngestV1::Outcome);
        }
        let verified = match self.verify_ledger_original(&manifest, genesis, signed, bytes)? {
            OfferedOutcome::EpochRequired(target_height) => {
                return Ok(LedgerAttemptIngestV1::EpochRequired { target_height });
            }
            OfferedOutcome::Verified(verified) => verified,
        };
        let outcome = self.write_ledger_original(&verified, bytes)?;
        if outcome.accepted() {
            let confirmation = Confirmation {
                version: 1,
                activation: plan
                    .output
                    .ok_or(Error::WitnessLost("activation output absent"))?,
                signed_transaction: signed_wire.to_vec(),
                outcome,
            };
            self.publish_activation_confirmation(root, manifest, plan, &confirmation)?;
        } else {
            attempt.rejection = Some(outcome);
            self.publish_activation_rejection(root, manifest, plan, &attempt)?;
        }
        Ok(LedgerAttemptIngestV1::Outcome(outcome.attempt()))
    }
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    // Full intake on every call, before any retained outcome is consulted: the selected plan,
    // the admitted incarnation, credential set and Bootstrap package proofs, then the exact
    // signed outer transaction over the retained Activate.
    fn activation_intake(
        &mut self,
        plan: &Plan,
        signed_wire: &[u8],
    ) -> Result<SignedTransaction, Error> {
        plan.require(&self.scheme_id, &self.wallet_id, &self.proofs.asset)?;
        self.authenticate_activation_plan(plan)?;
        let genesis = Arc::clone(&self.proofs.genesis);
        self.require_ledger_root(&genesis)?;
        let original = self
            .retained_activation(plan)?
            .ok_or(Error::Invalid("activation output absent"))?;
        signed_activate(
            signed_wire,
            &genesis.initial_epoch().network_id,
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
    ) -> Result<LedgerAttemptOutcomeV1, Error> {
        let (root, manifest) = self.sync_manifest()?;
        let plan = self.selected_activation_plan(&manifest)?;
        let signed = self.activation_intake(&plan, signed_wire)?;
        if self
            .retained_activation_attempt(&plan, signed_wire)?
            .is_none()
        {
            self.publish_activation_attempt(root, manifest, &plan, signed_wire)?;
        }
        let (_, manifest) = self.sync_manifest()?;
        let plan = self.selected_activation_plan(&manifest)?;
        self.activation_outcome(&plan, signed_wire, &signed)
    }
    /// Read this retained attempt's outcome: the wallet's family activation, this attempt's
    /// authenticated rejection, or Awaiting with the natively derived entrypoint hash that
    /// selects its finality read. Confirmed never asserts that every attempt executed.
    /// # Errors
    /// Changed transaction, missing selected original, lost custody or untrusted installation.
    pub fn activation_attempt_outcome(
        &mut self,
        signed_wire: &[u8],
    ) -> Result<LedgerAttemptOutcomeV1, Error> {
        let (_, manifest) = self.sync_manifest()?;
        let plan = self.selected_activation_plan(&manifest)?;
        let signed = self.activation_intake(&plan, signed_wire)?;
        self.activation_outcome(&plan, signed_wire, &signed)
    }
    /// Verify one direct ledger finality original for this retained attempt under the
    /// manifest-selected epoch, then atomically retain its first authenticated outcome. An
    /// authenticated rejection is terminal only for this attempt and never opens Load.
    /// # Errors
    /// Invalid, foreign or forged originals, another transaction, a conflicting outcome, lost
    /// custody or uncertain publication remain errors and never become a Rejected outcome.
    pub fn ingest_activation_finality(
        &mut self,
        signed_wire: &[u8],
        finality: &[u8],
    ) -> Result<LedgerAttemptIngestV1, Error> {
        let (root, manifest) = self.sync_manifest()?;
        let plan = self.selected_activation_plan(&manifest)?;
        let signed = self.activation_intake(&plan, signed_wire)?;
        let genesis = Arc::clone(&self.proofs.genesis);
        self.ingest_activation_original(
            root,
            manifest,
            &genesis,
            &plan,
            signed_wire,
            &signed,
            finality,
        )
    }
}

#[cfg(test)]
mod tests;
