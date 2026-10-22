//! One admitted native wallet owner for preparation, proof imports and folding.

use super::*;
mod activation;
pub use activation::ActivationFinalityProgressV1;
mod close_loads;
mod deletion;
pub(super) mod epochs;
pub use epochs::NativeEpochProgressV1;
mod ledger;
mod ledger_producer;
mod unload;
pub use ledger::{LEDGER_PROOF_MAX_BYTES_V1, LedgerProgressV1, PAYOUT_RECORD_MAX_BYTES_V1};
pub use ledger_producer::{
    LEDGER_INSTRUCTION_MAX_BYTES_V1, NativePreparedLedgerLoadV1, UnloadFinalityProgressV1,
};
mod output;
pub use output::{NativeReleasedOutputV1, NativeWalletMetadataV1};
mod bootstrap;
mod request_fee;
mod review;
mod runtime;
pub(super) mod sessions;
use crate::{
    kagemusha_wallet_advance_v1::{KagemushaWalletFsV1, KagemushaWalletPlatformV1},
    kagemusha_wallet_artifacts_v1::{
        InstalledVerifierPackV1,
        producer_inventory::{OriginalSourceV1, QualifiedWalletSourcesV1},
    },
    kagemusha_wallet_intake_v1::AdmittedWalletV1,
    kagemusha_wallet_preparation_v1::{
        NativeAdvanceCheckV1, NativeChoicesV1, NativePreparedOperationV1, OperationPreparationV1,
        PreparationV1, PreparedOperationV1,
    },
    kagemusha_wallet_proofs_v1::Error as ProofError,
};
use iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier;
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::keys::pk::artifact::ReadConfig;
pub use review::{
    NativeOperationReviewV1, ReviewedOperationV1, SpeculativeProofV1, SpeculativeSendJobV1,
    SpeculativeSendV1,
};
use runtime::RuntimeCustodyV1;
pub use runtime::{
    NativeInstallationConfigV1, NativeOpenErrorV1, NativeOpenFailureV1, NativeStartupFailureV1,
    NativeWalletCoordinatorV1, NativeWalletRuntimeV1, PendingNativeWalletOpenV1,
};
use std::sync::{Arc, Mutex};

/// Concrete native owner constructed only by consuming actual original admission.
/// The original proving store and custody provider each have one exclusive owner.
pub struct NativeWalletProofsV1<F: KagemushaWalletFsV1, P, S> {
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    originals: Mutex<S>,
    observations: NativeObservationsV1<F, P>,
    worker: NativeFoldWorkerV1,
    read: ReadConfig,
    budget: MemoryBudget,
    chain: String,
    genesis: Arc<SumeragiFinalityVerifier>,
    enrollment: KagemushaWalletCredentialV1,
    asset: KagemushaWalletAssetScopeV1,
    account: iroha_data_model::account::AccountId,
    account_original: Vec<u8>,
    asset_original: Vec<u8>,
    enrollment_certificates: Vec<u8>,
    capacity:
        std::sync::OnceLock<crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1>,
    proving_memory:
        std::sync::OnceLock<crate::kagemusha_wallet_capacity_v1::KagemushaWalletProvingMemoryV1>,
}

fn proof<T>(value: Result<T, ProofError>) -> Result<T, Error> {
    value.map_err(|error| match error {
        ProofError::DecodeResource(original) => Error::DecodeResource(original),
        ProofError::Unavailable => Error::ArtifactsUnavailable("native operation artifact"),
        ProofError::Cancelled => Error::Cancelled,
        ProofError::Blocked(field) => Error::Blocked(field),
        ProofError::Entropy => {
            crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderErrorV1::Unavailable(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Platform(0),
            )
            .into()
        }
        _ => Error::Proof("native operation source or proof"),
    })
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> AdmittedWalletV1<F, P> {
    /// Consume original admission and bind the one complete producer grant to its native root.
    /// No production wallet can be created from a foreign verifier verdict or loose key list.
    ///
    /// # Errors
    /// Changed installation/genesis, unavailable custody or inconsistent native state.
    fn into_coordinator<S: OriginalSourceV1 + Send>(
        self,
        native_genesis: &Arc<SumeragiFinalityVerifier>,
        originals: S,
        read: ReadConfig,
        budget: MemoryBudget,
    ) -> Result<
        Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>,
        (RuntimeCustodyV1<F, P>, S, Error),
    > {
        let (
            provider,
            installed,
            sources,
            slot,
            enrollment,
            account,
            asset,
            _,
            certificates,
            account_original,
            asset_original,
        ) = self.into_parts();
        let verified = (|| {
            let selected = sources.finality().verifier();
            if native_genesis.instance() != selected.instance()
                || native_genesis.chain_id() != selected.chain_id()
                || native_genesis.initial_epoch() != selected.initial_epoch()
            {
                return Err(Error::Proof("native finality source binding"));
            }
            NativeFoldWorkerV1::new(Arc::clone(&installed), Arc::clone(&sources), read, budget)
        })();
        let worker = match verified {
            Ok(worker) => worker,
            Err(error) => return Err((RuntimeCustodyV1::Exclusive(provider), originals, error)),
        };
        let handle = AdvanceHandle::new(provider, slot);
        let archive = handle.archive(enrollment.body.scheme_id, enrollment.body.wallet_id);
        let owner = NativeWalletProofsV1 {
            installed,
            sources,
            originals: Mutex::new(originals),
            observations: handle.observations(),
            worker,
            read,
            budget,
            chain: native_genesis.chain_id().to_owned(),
            genesis: Arc::clone(native_genesis),
            enrollment,
            asset,
            account,
            account_original,
            asset_original,
            enrollment_certificates: certificates,
            capacity: std::sync::OnceLock::new(),
            proving_memory: std::sync::OnceLock::new(),
        };
        let mut wallet = Coordinator {
            custody: handle,
            archive,
            proofs: owner,
            scheme_id: enrollment.body.scheme_id,
            wallet_id: enrollment.body.wallet_id,
            scheduler: Scheduler::new(),
            verified_folds: BTreeMap::new(),
        };
        if let Err(error) = wallet.initialize() {
            let Coordinator {
                custody,
                archive,
                proofs,
                ..
            } = wallet;
            let NativeWalletProofsV1 {
                originals,
                observations,
                ..
            } = proofs;
            drop(archive);
            drop(observations);
            let originals = originals
                .into_inner()
                .unwrap_or_else(|error| error.into_inner());
            let custody = match custody.try_into_provider() {
                Ok(provider) => RuntimeCustodyV1::Exclusive(provider),
                Err(handle) => RuntimeCustodyV1::Shared(handle),
            };
            return Err((custody, originals, error));
        }
        Ok(wallet)
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    NativeWalletProofsV1<F, P, S>
{
    /// Both quotient plans' peak proving memory of this installation, computed once.
    fn proving_memory(
        &self,
    ) -> Result<crate::kagemusha_wallet_capacity_v1::KagemushaWalletProvingMemoryV1, Error> {
        if let Some(memory) = self.proving_memory.get() {
            return Ok(*memory);
        }
        let memory = self
            .sources
            .proving_memory()
            .map_err(|_| Error::Proof("installed relation capacity bound"))?;
        Ok(*self.proving_memory.get_or_init(|| memory))
    }

    fn derive(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        bytes: &[u8],
    ) -> Result<PreparedOperationV1, Error> {
        let _observation = iroha_plonk::work_metrics::WorkTimer::start(
            iroha_plonk::work_metrics::WorkPhase::SourceRestore,
        );
        let preparation = proof(PreparationV1::new(&self.installed))?;
        let choices = NativeChoicesV1::decode(
            bytes,
            self.installed.verifier().manifest_digest(),
            request,
            source,
        )?;
        preparation.prepare_operation(
            request,
            source,
            custody,
            &OperationPreparationV1 {
                sources: &self.sources,
                choices: &choices,
                budget: self.budget,
            },
        )
    }

    // The call-scoped token binds the exact plan bytes, source and installation it used.
    fn derive_retained(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        bytes: &[u8],
    ) -> Result<NativePreparedOperationV1, Error> {
        let prepared = self.derive(request, source, custody, bytes)?;
        Ok(NativePreparedOperationV1::new(
            prepared,
            bytes,
            source.released().frozen.capsule.custody_digest(),
            self.installed.verifier().manifest_digest(),
        ))
    }

    // Check the durable plan and release this call's derivation for exactly that plan.
    fn redeem_for(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        prepared: NativePreparedOperationV1,
        plan: &[u8],
    ) -> Result<PreparedOperationV1, Error> {
        let manifest = self.installed.verifier().manifest_digest();
        NativeChoicesV1::decode(plan, manifest, request, source)?;
        prepared.redeem(
            plan,
            source.released().frozen.capsule.custody_digest(),
            manifest,
        )
    }

    // The sole original store is lent to this proof's import only.
    fn prove_redeemed(
        &self,
        preparation: &PreparationV1<'_>,
        prepared: &PreparedOperationV1,
    ) -> Result<FrozenTransition, Error> {
        let mut originals = self
            .originals
            .lock()
            .map_err(|_| Error::ArtifactsUnavailable("proving original owner poisoned"))?;
        prepared.prove(
            preparation,
            &self.sources,
            &mut *originals,
            self.read,
            self.budget,
        )
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    NativePreparation for NativeWalletProofsV1<F, P, S>
{
    type Prepared = NativePreparedOperationV1;
    fn plan_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
    ) -> Result<(Vec<u8>, Self::Prepared), Error> {
        let choices = NativeChoicesV1::fresh(
            self.installed.verifier().manifest_digest(),
            request,
            source,
            &self.observations,
        )?;
        let bytes = choices.encode()?;
        let prepared = self.derive_retained(request, source, custody, &bytes)?;
        Ok((bytes, prepared))
    }
    fn validate_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        plan: &[u8],
    ) -> Result<Self::Prepared, Error> {
        self.derive_retained(request, source, custody, plan)
    }
    fn prove_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        prepared: Self::Prepared,
        plan: &[u8],
    ) -> Result<FrozenTransition, Error> {
        let prepared = self.redeem_for(request, source, prepared, plan)?;
        self.prove_redeemed(&proof(PreparationV1::new(&self.installed))?, &prepared)
    }

    type Speculative = review::SpeculativeSendV1;

    fn plan_speculated(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        speculative: &Self::Speculative,
    ) -> Result<(Vec<u8>, Self::Prepared), Error> {
        let manifest = self.installed.verifier().manifest_digest();
        if !speculative.made_for(manifest, request, source) {
            return self.plan_preparation(request, source, custody);
        }
        let bytes = NativeChoicesV1::speculated(manifest, request, source, speculative.nonce())?
            .encode()?;
        let prepared = self.derive_retained(request, source, custody, &bytes)?;
        Ok((bytes, prepared))
    }

    fn prove_speculated(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        prepared: Self::Prepared,
        plan: &[u8],
        speculative: Self::Speculative,
    ) -> Result<FrozenTransition, Error> {
        let manifest = self.installed.verifier().manifest_digest();
        let prepared = self.redeem_for(request, source, prepared, plan)?;
        let preparation = proof(PreparationV1::new(&self.installed))?;
        if speculative.made_for(manifest, request, source) {
            // Another statement or relation, or a σ the frozen body does not verify, leaves
            // the speculation unused: this call then proves the step itself.
            if let Ok(Some(frozen)) =
                prepared.freeze_speculated(&preparation, speculative.into_sigma(), self.budget)
            {
                return Ok(frozen);
            }
        }
        self.prove_redeemed(&preparation, &prepared)
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send> NativeProofs
    for NativeWalletProofsV1<F, P, S>
{
    type AdvanceCheck = NativeAdvanceCheckV1;
    fn enrollment_certificates(
        &self,
        credential: &KagemushaWalletCredentialV1,
    ) -> Result<Vec<u8>, Error> {
        if credential != &self.enrollment {
            return Err(Error::Proof("enrollment original credential"));
        }
        Ok(self.enrollment_certificates.clone())
    }
    fn ledger_scope(&self) -> Result<(KagemushaWalletSchemeV1, String), Error> {
        Ok((*self.installed.verifier().scheme(), self.chain.clone()))
    }
    fn verify_transition(
        &self,
        next: &FrozenTransition,
        predecessor: Option<&ReleasedStep>,
        folded: Option<&KagemushaWalletFoldRecordV1>,
        custody: &mut TransitionCustodyV1<'_>,
    ) -> Result<Self::AdvanceCheck, Error> {
        next.validate()?;
        let preparation = proof(PreparationV1::new(&self.installed))?;
        if next.capsule.body().kind == KagemushaWalletOperationKindV1::Bootstrap {
            if predecessor.is_some()
                || folded.is_some()
                || custody.prepared().is_some()
                || next.credential != self.enrollment
            {
                return Err(Error::Proof("bootstrap native admission"));
            }
            let owner = preparation.authenticate_credential_set(
                &valid(next.credential.to_canonical_bytes())?,
                &self.enrollment_certificates,
            )?;
            let KagemushaWalletEffectV1::Bootstrap {
                enrollment_marker, ..
            } = next.capsule.body().statement.effect
            else {
                return Err(Error::Proof("Bootstrap effect"));
            };
            let expected = proof(preparation.prepare_bootstrap(
                &owner,
                enrollment_marker,
                next.capsule.body().successor_state.core.state_nonce,
            ))?;
            let frozen = proof(preparation.body_bootstrap(
                &owner,
                &expected,
                next.capsule.body().step_proof.clone(),
                self.budget,
            ))?;
            proof(frozen.require_matches(next))?;
            return Ok(NativeAdvanceCheckV1::without_time());
        }
        let source = PreparationSourceV1 {
            released: predecessor.ok_or(Error::NoHead)?,
            folded,
        };
        let (request, plan, selected) = custody
            .prepared()
            .ok_or(Error::WitnessLost("ordinary native preparation"))?;
        let prepared = self.derive(request, &source, selected, plan)?;
        prepared.verify_frozen(&preparation, next, self.budget)?;
        prepared.advance_check(&preparation, selected)
    }
    fn check_advance(&self, check: Self::AdvanceCheck) -> Result<(), Error> {
        check.check(&self.observations)
    }
    fn verify_lineage(
        &self,
        lineage: &KagemushaWalletLineageV1,
        cancellation: Option<&Cancellation>,
    ) -> Result<(), Error> {
        proof(self.installed.verifier().verify_lineage_cancellable(
            lineage,
            self.budget,
            cancellation.map(Cancellation::prover_token),
        ))
    }
    fn verify_credited(
        &self,
        credited: &KagemushaWalletCreditedV1,
        request: &KagemushaWalletRequestV1,
        payment: &KagemushaWalletPaymentV1,
    ) -> Result<(), Error> {
        valid(credited.verify_for(self.installed.verifier().scheme(), request, payment))?;
        match &credited.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => {
                proof(self.installed.verifier().verify_package_proofs_cancellable(
                    package,
                    self.budget,
                    None,
                ))
            }
            KagemushaWalletCreditedEvidenceV1::Status { status } => {
                self.verify_lineage(&status.lineage, None)
            }
        }
    }
    fn runtime_capacity(
        &self,
    ) -> Result<crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1, Error> {
        if let Some(capacity) = self.capacity.get() {
            return Ok(*capacity);
        }
        // Fixed for this installation: computed once from its authenticated descriptors and
        // checkpoint layouts, never from the phone. Memory admits the lean quotient plan, so a
        // phone that cannot hold the fused one still folds, more slowly.
        let capacity = crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1 {
            storage_bytes: self.worker.fold_witness_bytes()?,
            memory_bytes: self.proving_memory()?.lean_bytes,
        };
        Ok(*self.capacity.get_or_init(|| capacity))
    }
    fn fold_schedule(
        &self,
        witness: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        custody: Option<&mut FoldCustodyV1<'_>>,
    ) -> Result<Vec<CheckpointLayout>, Error> {
        self.worker.schedule(
            witness,
            predecessor,
            custody.ok_or(Error::WitnessLost("native fold custody"))?,
        )
    }
    fn fold_prepare(
        &self,
        witness: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        checkpoints: Vec<PrivateArchiveBytes>,
        custody: Option<&mut FoldCustodyV1<'_>>,
        retained: Option<FoldRetentionV1>,
        cancellation: &Cancellation,
    ) -> Result<Box<dyn NativeFoldJobV1>, Error> {
        // Prove fused when this phone has the memory for it now, else in passes as wide as
        // its memory allows.
        let worker = self.worker.with_quotient_columns(
            self.proving_memory()?
                .quotient_columns(self.observations.available_memory()),
        );
        // The original store is lent to the locked prepare only; the job never holds it.
        let mut originals = self
            .originals
            .lock()
            .map_err(|_| Error::ArtifactsUnavailable("proving original owner poisoned"))?;
        worker.prepare(
            witness,
            predecessor,
            checkpoints,
            retained,
            cancellation,
            &mut *originals,
            custody.ok_or(Error::WitnessLost("native fold custody"))?,
        )
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;

    #[test]
    fn proof_mapping_keeps_original_read_refusal_and_semantic_verdicts() {
        let bytes = norito::encode_canonical(&vec![7u8; 128]).unwrap();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let captured = norito::with_decode_limits_scope(limits, || {
            norito::decode_canonical_for_admission::<Vec<u8>>(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
        })
        .unwrap_err()
        .into_local_refusal()
        .unwrap();
        let expected = captured.clone();
        let error = proof::<()>(Err(ProofError::DecodeResource(captured))).unwrap_err();
        assert!(matches!(error, Error::DecodeResource(original) if original == expected));
        assert!(matches!(
            proof::<()>(Err(ProofError::Cancelled)),
            Err(Error::Cancelled)
        ));
        assert!(matches!(
            proof::<()>(Err(ProofError::Authority)),
            Err(Error::Proof("native operation source or proof"))
        ));
    }
}
