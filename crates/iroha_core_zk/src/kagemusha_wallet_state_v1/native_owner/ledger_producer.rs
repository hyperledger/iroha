//! Current ledger instruction preparation and native Unload direct finality outcomes.
use super::ledger_outcome::{
    self, LedgerAttemptIngestV1, LedgerAttemptOutcomeV1, LedgerOutcome, OfferedOutcome,
};
use super::*;
mod projection;
use iroha_data_model::{
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
    transaction::SignedTransaction,
};
pub use projection::NativePreparedLedgerLoadV1;
/// One complete current ledger instruction, including its original signed transport.
pub const LEDGER_INSTRUCTION_MAX_BYTES_V1: usize = 64 * 1024;

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::LedgerLoadPlanV1")]
struct LoadPlan {
    request: [u8; 32],
    amount: u128,
    ordinal: u128,
    instruction: Vec<u8>,
}

/// First authenticated outcome of one exact signed Unload envelope over one exact claim,
/// keyed by the envelope's natively derived entrypoint hash.
#[derive(Clone, Copy, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::UnloadOutcomeV1")]
struct UnloadOutcome {
    original_digest: [u8; 32],
    outcome: LedgerOutcome,
}

/// DATA intake of one exact signed envelope carrying the exact retained claim. Any account
/// may submit (relay) the claim: the claim's own canonical validation binds the paid account
/// to its credential, and the caller binds that credential to this wallet. Certified
/// execution then authenticates the exact instruction and its result.
fn signed_unload(
    bytes: &[u8],
    network: &iroha_data_model::NetworkId,
    scheme: &[u8; 32],
    claim: &[u8],
) -> Result<SignedTransaction, Error> {
    let transaction = ledger_outcome::signed_original(bytes)?;
    let public = transaction
        .authority()
        .try_signatory()
        .ok_or(Error::Invalid("Unload single account key"))?;
    let (algorithm, key) = public
        .try_to_bytes()
        .map_err(|_| Error::Invalid("Unload account key"))?;
    if transaction.network_id() != Some(network)
        || transaction.multisig_signatures().is_some()
        || transaction.signature_count() != 1
        || algorithm != iroha_crypto::Algorithm::Ed25519
        || key.len() != 32
    {
        return Err(Error::Invalid("Unload signed transaction authority"));
    }
    transaction
        .verify_signature()
        .map_err(|_| Error::Proof("Unload submitter signature"))?;
    if !transaction
        .instructions()
        .explicit_instructions()
        .any(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<KagemushaWalletLedgerV1>()
                .is_some_and(|instruction| {
                    instruction.scheme == *scheme
                        && matches!(&instruction.action,
                    KagemushaWalletLedgerActionV1::Unload(bytes) if bytes == claim)
                })
        })
    {
        return Err(Error::Invalid("Unload exact original instruction"));
    }
    Ok(transaction)
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    // The retained first outcome for this envelope, rechecked against its exact original.
    // The same envelope can never be reread under another claim.
    fn retained_unload_outcome(
        &mut self,
        manifest: &manifest::Manifest,
        entrypoint: &[u8; 32],
        original_digest: &[u8; 32],
    ) -> Result<Option<LedgerOutcome>, Error> {
        let Some(bytes) = manifest
            .ledger_unload_outcomes
            .get(&mut self.archive, entrypoint)?
        else {
            return Ok(None);
        };
        let row: UnloadOutcome = archive::decode(&bytes)?;
        if row.original_digest != *original_digest {
            return Err(Error::OperationConflict);
        }
        self.retained_ledger_original(&row.outcome, entrypoint)?;
        Ok(Some(row.outcome))
    }
    // Read only: the retained outcome, else Awaiting under the natively derived entrypoint.
    fn unload_outcome(
        &mut self,
        manifest: &manifest::Manifest,
        original_digest: &[u8; 32],
        signed: &SignedTransaction,
    ) -> Result<LedgerAttemptOutcomeV1, Error> {
        let entrypoint = ledger_outcome::entrypoint(signed)?;
        Ok(
            match self.retained_unload_outcome(manifest, &entrypoint, original_digest)? {
                Some(outcome) => outcome.attempt(),
                None => LedgerAttemptOutcomeV1::Awaiting { entrypoint },
            },
        )
    }
    // Offer one original for an intake-checked envelope. A retained outcome is reconciled and
    // never replaced. Otherwise exactly one original is verified, written and selected with
    // its outcome row by one fenced manifest publication. A rejected row has no other reader:
    // it never restores balance, releases, replaces or retargets the claim.
    fn ingest_unload_original(
        &mut self,
        root: [u8; 32],
        mut manifest: manifest::Manifest,
        genesis: &SumeragiFinalityVerifier,
        original_digest: [u8; 32],
        signed: &SignedTransaction,
        bytes: &[u8],
    ) -> Result<LedgerAttemptIngestV1, Error> {
        let entrypoint = ledger_outcome::entrypoint(signed)?;
        if let Some(retained) =
            self.retained_unload_outcome(&manifest, &entrypoint, &original_digest)?
        {
            return self
                .reconcile_ledger_original(&manifest, genesis, &retained, signed, bytes)
                .map(LedgerAttemptIngestV1::Outcome);
        }
        let verified = match self.verify_ledger_original(&manifest, genesis, signed, bytes)? {
            OfferedOutcome::EpochRequired(target_height) => {
                return Ok(LedgerAttemptIngestV1::EpochRequired { target_height });
            }
            OfferedOutcome::Verified(verified) => verified,
        };
        let outcome = self.write_ledger_original(&verified, bytes)?;
        if self.manifest()?.0 != root {
            return Err(Error::WitnessLost("Unload outcome source changed"));
        }
        manifest.ledger_unload_outcomes = manifest.ledger_unload_outcomes.set(
            &mut self.archive,
            entrypoint,
            &archive::encode(&UnloadOutcome {
                original_digest,
                outcome,
            })?,
        )?;
        self.publish_manifest(root, &manifest)?;
        Ok(LedgerAttemptIngestV1::Outcome(outcome.attempt()))
    }
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
        let core = &released.frozen.capsule.body().successor_state.core;
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
                let frame = read_model_original(
                    || KagemushaWalletActivationV1::decode_canonical(original, &self.scheme_id),
                    Error::Invalid("G1 validation"),
                )?;
                if frame.credential.body.wallet_id != self.wallet_id {
                    return Err(Error::Invalid("activation wallet"));
                }
                KagemushaWalletLedgerActionV1::Activate(original.to_vec())
            }
            2 => {
                let frame = read_model_original(
                    || KagemushaWalletUnloadClaimV1::decode_canonical(original, &self.scheme_id),
                    Error::Invalid("G1 validation"),
                )?;
                if frame.credential.body.wallet_id != self.wallet_id {
                    return Err(Error::Invalid("Unload wallet"));
                }
                KagemushaWalletLedgerActionV1::Unload(original.to_vec())
            }
            3 => {
                let frame = read_model_original(
                    || KagemushaWalletCloseLoadsV1::decode_canonical(original, &self.scheme_id),
                    Error::Invalid("G1 validation"),
                )?;
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
    // Claim intake: canonical claim validation, then this wallet's enrollment scope. The
    // claim digest binds every outcome row to the exact retained claim bytes.
    fn unload_original_digest(&self, original: &[u8]) -> Result<[u8; 32], Error> {
        if original.is_empty() || original.len() > KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1 {
            return Err(Error::Invalid("Unload claim bound"));
        }
        let claim = read_model_original(
            || KagemushaWalletUnloadClaimV1::decode_canonical(original, &self.scheme_id),
            Error::Invalid("G1 validation"),
        )?;
        if claim.credential.body.wallet_id != self.wallet_id
            || claim.credential.body.account_digest != self.proofs.enrollment.body.account_digest
        {
            return Err(Error::Invalid("Unload claim wallet scope"));
        }
        Ok(*iroha_crypto::Hash::new(original).as_ref())
    }
    fn unload_intake(
        &self,
        claim: &[u8],
        signed_wire: &[u8],
    ) -> Result<([u8; 32], SignedTransaction), Error> {
        let original_digest = self.unload_original_digest(claim)?;
        self.require_ledger_root(&self.proofs.genesis)?;
        let signed = signed_unload(
            signed_wire,
            &self.proofs.genesis.initial_epoch().network_id,
            &self.scheme_id,
            claim,
        )?;
        Ok((original_digest, signed))
    }
    /// Read the retained outcome of this exact signed envelope over this exact claim, or
    /// Awaiting with the entrypoint hash Native derived from the envelope. Only a Confirmed
    /// outcome establishes the payout; a Rejected one closes this envelope only.
    /// # Errors
    /// Foreign/changed claim or envelope, lost custody or an invalid selected genesis.
    pub fn unload_attempt_outcome(
        &mut self,
        claim: &[u8],
        signed_wire: &[u8],
    ) -> Result<LedgerAttemptOutcomeV1, Error> {
        let (original_digest, signed) = self.unload_intake(claim, signed_wire)?;
        let (_, manifest) = self.sync_manifest()?;
        self.unload_outcome(&manifest, &original_digest, &signed)
    }
    /// Verify one direct ledger finality original for this exact envelope under the
    /// manifest-selected epoch and retain its first authenticated outcome. No caller height,
    /// transaction hash or HTTP status supplies inclusion or rejection authority.
    /// # Errors
    /// Invalid, foreign or forged originals, a conflicting outcome, lost custody or uncertain
    /// publication remain errors and never become an outcome.
    pub fn ingest_unload_finality(
        &mut self,
        claim: &[u8],
        signed_wire: &[u8],
        finality: &[u8],
    ) -> Result<LedgerAttemptIngestV1, Error> {
        let (original_digest, signed) = self.unload_intake(claim, signed_wire)?;
        let (root, manifest) = self.sync_manifest()?;
        let genesis = Arc::clone(&self.proofs.genesis);
        self.ingest_unload_original(root, manifest, &genesis, original_digest, &signed, finality)
    }
}

#[cfg(test)]
mod tests;
