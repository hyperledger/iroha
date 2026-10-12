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
        NativeAdvanceCheckV1, NativeChoicesV1, PreparationV1, PreparedOperationV1,
    },
    kagemusha_wallet_proofs_v1::Error as ProofError,
};
use iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier;
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::keys::pk::artifact::ReadConfig;
pub use review::{NativeOperationReviewV1, ReviewedOperationV1};
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
}

fn proof<T>(value: Result<T, ProofError>) -> Result<T, Error> {
    value.map_err(|error| match error {
        ProofError::DecodeResource(original) => Error::DecodeResource(original),
        ProofError::Unavailable => Error::ArtifactsUnavailable("native operation artifact"),
        ProofError::Cancelled => Error::Cancelled,
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
    fn derive(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        bytes: &[u8],
    ) -> Result<PreparedOperationV1, Error> {
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
            &self.sources,
            choices.nonce(),
            choices.time().as_ref(),
            self.budget,
        )
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    NativePreparation for NativeWalletProofsV1<F, P, S>
{
    fn plan_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
    ) -> Result<Vec<u8>, Error> {
        let choices = NativeChoicesV1::fresh(
            self.installed.verifier().manifest_digest(),
            request,
            source,
            &self.observations,
        )?;
        let bytes = choices.encode()?;
        self.derive(request, source, custody, &bytes)?;
        Ok(bytes)
    }
    fn validate_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        plan: &[u8],
    ) -> Result<(), Error> {
        self.derive(request, source, custody, plan).map(|_| ())
    }
    fn prove_preparation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        plan: &[u8],
    ) -> Result<FrozenTransition, Error> {
        let prepared = self.derive(request, source, custody, plan)?;
        let mut originals = self
            .originals
            .lock()
            .map_err(|_| Error::ArtifactsUnavailable("proving original owner poisoned"))?;
        prepared.prove(
            &proof(PreparationV1::new(&self.installed))?,
            &self.sources,
            &mut *originals,
            self.read,
            self.budget,
        )
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
                    Some(&request.body),
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
        // checkpoint layouts, never from the phone.
        let capacity = crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1 {
            storage_bytes: self.worker.fold_witness_bytes()?,
            memory_bytes: self
                .sources
                .peak_proving_memory_bytes()
                .map_err(|_| Error::Proof("installed relation capacity bound"))?,
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
    fn fold_next(
        &self,
        witness: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        checkpoints: &[Vec<u8>],
        custody: Option<&mut FoldCustodyV1<'_>>,
        cancellation: &Cancellation,
    ) -> Result<FoldProgress, Error> {
        let mut originals = self
            .originals
            .lock()
            .map_err(|_| Error::ArtifactsUnavailable("proving original owner poisoned"))?;
        self.worker.next(
            witness,
            predecessor,
            checkpoints,
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
