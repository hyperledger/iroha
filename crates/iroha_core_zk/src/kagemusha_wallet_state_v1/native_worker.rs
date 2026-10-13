//! Bounded native fold execution from the sole complete authenticated source grant.
//!
//! The wallet owner lends its original store for one task. This worker retains
//! borrowed sealed metadata, verifies every restored source in order, and releases the active
//! proving key before verification and yielding a durable checkpoint. Sealed
//! custody selects inputs;
//! neither checkpoint metadata nor an operation caller supplies proof acceptance.

use std::sync::Arc;

use ff::PrimeField;
use iroha_kagemusha_proof::{
    a_relation::{
        native::{archive, bootstrap, consuming, load, receive, refresh, send},
        schedule::compiled::{OperationRoute, compiled_routes},
    },
    omega::native as omega,
};
use iroha_pasta::{CancellationToken, Fp, Fq, msm::MemoryBudget};
use iroha_plonk::{ProverConfig, ProverRandomness, keys::pk::artifact::ReadConfig};
use iroha_plonk_recursion::FoldConfig;
use sha2::{Digest, Sha256};

use super::{Cancellation, CheckpointLayout, Error};
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletProviderErrorV1, KagemushaWalletUnavailableV1,
};
use crate::kagemusha_wallet_artifacts_v1::{
    InstalledVerifierPackV1,
    producer_inventory::{
        OriginalSourceV1, QualifiedOperationOwnerV1, QualifiedWalletSourcesV1, WalletSourcesErrorV1,
    },
};
use crate::kagemusha_wallet_proofs_v1::randomness;

mod incoming;
mod incoming_inputs;
mod inputs;
mod q;
mod q_checkpoint;
mod stages;

/// Metadata-only execution owner; the admitted wallet retains the only original store.
pub(crate) struct NativeFoldWorkerV1 {
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    read: ReadConfig,
    budget: MemoryBudget,
}

/// Already reconstructed typed native inputs. Native `prepare` remains mandatory
/// and verifies all Q originals, predecessor evidence and source-bound context.
#[allow(
    clippy::large_enum_variant,
    reason = "bounded operation input is moved into the active native session"
)]
pub(crate) enum OperationInputsV1 {
    Bootstrap(bootstrap::Inputs),
    Load(load::Inputs),
    Send(send::Inputs),
    Receive(receive::Inputs),
    Archive(archive::Inputs),
    Consuming(consuming::Inputs),
    Refresh(refresh::Inputs),
}

pub(crate) enum NativeStageProgressV1 {
    Checkpoint(Vec<u8>),
    Terminal(omega::Input),
}

#[cfg(not(test))]
use proof_result as proof;

// Engineering diagnostics reveal only typed error classes and static source locations.
// The production mapping and every native verification remain unchanged.
#[cfg(test)]
#[track_caller]
fn proof<T, E: crate::kagemusha_wallet_proofs_v1::NativeProofError + core::fmt::Debug>(
    result: Result<T, E>,
) -> Result<T, Error> {
    if let Err(error) = &result {
        eprintln!(
            "NATIVE_FOLD_FAILURE location={} error={error:?}",
            core::panic::Location::caller(),
        );
    }
    proof_result(result)
}

fn proof_result<T, E: crate::kagemusha_wallet_proofs_v1::NativeProofError>(
    result: Result<T, E>,
) -> Result<T, Error> {
    result.map_err(|error| {
        if error.is_cancelled() {
            Error::Cancelled
        } else {
            Error::Proof("native fold source or proof")
        }
    })
}
fn artifact(error: WalletSourcesErrorV1) -> Error {
    if error.is_cancelled() {
        Error::Cancelled
    } else if error.is_unavailable() {
        Error::ArtifactsUnavailable("native proving original")
    } else {
        Error::Proof("native proving source")
    }
}

fn salt_error(error: randomness::Error) -> Error {
    match error {
        randomness::Error::Cancelled => Error::Cancelled,
        randomness::Error::Unavailable => {
            KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Platform(0))
                .into()
        }
    }
}

fn fresh_fold_salt<F: PrimeField<Repr = [u8; 32]>>(
    cancellation: &CancellationToken,
) -> Result<F, Error> {
    randomness::sample(Some(cancellation), randomness::os_entropy).map_err(salt_error)
}

fn layout(
    descriptor: &[u8; 32],
    key: &[u8; 32],
    role: u8,
    stage: u32,
    payload_bytes: usize,
) -> Result<CheckpointLayout, Error> {
    let payload_bytes =
        u32::try_from(payload_bytes).map_err(|_| Error::Proof("checkpoint bound"))?;
    if payload_bytes == 0 {
        return Err(Error::Proof("checkpoint bound"));
    }
    let mut digest = Sha256::new();
    digest.update(b"KAGEMUSHA native fold checkpoint v1");
    digest.update(descriptor);
    digest.update(key);
    digest.update([role]);
    digest.update(stage.to_le_bytes());
    digest.update(payload_bytes.to_le_bytes());
    Ok(CheckpointLayout {
        artifact_digest: digest.finalize().into(),
        payload_bytes,
    })
}

impl NativeFoldWorkerV1 {
    pub(crate) fn new(
        installed: Arc<InstalledVerifierPackV1>,
        sources: Arc<QualifiedWalletSourcesV1>,
        read: ReadConfig,
        budget: MemoryBudget,
    ) -> Result<Self, Error> {
        if sources.installation()
            != (
                installed.verifier().scheme().scheme_id(),
                installed.verifier().manifest_digest(),
            )
        {
            return Err(Error::Proof("native source installation"));
        }
        Ok(Self {
            installed,
            sources,
            read,
            budget,
        })
    }

    /// Design §5.3: the largest custody bytes one step's fold adds until a durable Ω covers it,
    /// over every compiled route: each checkpoint payload with its archive metadata, then the
    /// Ω fold record. Derived from the installed layouts only.
    pub(crate) fn fold_witness_bytes(&self) -> Result<u64, Error> {
        let metadata = u64::try_from(super::archive::METADATA_BOUND)
            .map_err(|_| Error::Proof("checkpoint bound"))?;
        let record =
            u64::try_from(iroha_data_model::kagemusha::KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1)
                .map_err(|_| Error::Proof("checkpoint bound"))?;
        let mut largest = 0_u64;
        for route in compiled_routes() {
            let total = self
                .route_schedule(route)?
                .iter()
                .try_fold(0_u64, |sum, layout| {
                    sum.checked_add(u64::from(layout.payload_bytes))?
                        .checked_add(metadata)
                })
                .ok_or(Error::Proof("checkpoint bound"))?;
            largest = largest.max(total);
        }
        largest
            .checked_add(record)
            .and_then(|bytes| bytes.checked_add(metadata))
            .ok_or(Error::Proof("checkpoint bound"))
    }

    /// Exact ordered Q and A/W layouts, ending before the sole final Omega task.
    pub(crate) fn route_schedule(
        &self,
        route: OperationRoute,
    ) -> Result<Vec<CheckpointLayout>, Error> {
        let q = proof(self.sources.q(route))?;
        let mut result = q
            .keys()
            .iter()
            .enumerate()
            .map(|(stage, key)| q_checkpoint::Layout::new(stage, key).map(|l| l.custody))
            .collect::<Result<Vec<_>, _>>()?;
        result.extend(self.stage_schedule(route)?);
        Ok(result)
    }

    fn stage_schedule(&self, route: OperationRoute) -> Result<Vec<CheckpointLayout>, Error> {
        macro_rules! layouts {
            ($owner:expr) => {
                proof($owner.checkpoint_layouts())?
                    .iter()
                    .enumerate()
                    .map(|(stage, entry)| {
                        layout(
                            entry.descriptor_digest(),
                            entry.verifying_key_digest(),
                            2,
                            u32::try_from(stage).map_err(|_| Error::Proof("stage count"))?,
                            entry.payload_bytes(),
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?
            };
        }
        // Position is included below because each native family has its own typed
        // A/W enum. Descriptor/key and source-verified carrier remain mandatory.
        let mut result = match proof(self.sources.route(route))?.owner() {
            QualifiedOperationOwnerV1::Bootstrap(owner) => {
                proof(owner.prover().checkpoint_layouts())?
                    .iter()
                    .enumerate()
                    .map(|(stage, entry)| {
                        layout(
                            entry.descriptor_digest(),
                            entry.verifying_key_digest(),
                            2,
                            stage as u32,
                            entry.payload_bytes(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            QualifiedOperationOwnerV1::Load(owner) => layouts!(owner),
            QualifiedOperationOwnerV1::Send(owner) => layouts!(owner),
            QualifiedOperationOwnerV1::Receive(owner) => layouts!(owner),
            QualifiedOperationOwnerV1::Archive(owner) => layouts!(owner),
            QualifiedOperationOwnerV1::Consuming(owner) => layouts!(owner),
            QualifiedOperationOwnerV1::Refresh(owner) => layouts!(owner),
        };
        for (position, entry) in result.iter_mut().enumerate() {
            let mut digest = Sha256::new();
            digest.update(b"KAGEMUSHA ordered native stage v1");
            digest.update(entry.artifact_digest);
            digest.update(
                u32::try_from(position)
                    .map_err(|_| Error::Proof("stage count"))?
                    .to_le_bytes(),
            );
            entry.artifact_digest = digest.finalize().into();
        }
        Ok(result)
    }

    fn fold_config(&self, cancellation: &Cancellation) -> FoldConfig {
        FoldConfig {
            kernel_budget: self.budget,
            cancellation: Some(cancellation.prover_token().clone()),
            ..FoldConfig::default()
        }
    }
    fn prover_config<'a>(&self, cancellation: &'a Cancellation) -> ProverConfig<'a> {
        ProverConfig {
            msm_budget: self.budget,
            cancellation: Some(cancellation.prover_token()),
        }
    }

    /// One final Omega proof from the verified terminal and complete installed catalog.
    pub(crate) fn finish(
        &self,
        input: omega::Input,
        originals: &mut dyn OriginalSourceV1,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, Error> {
        cancellation.check()?;
        let owner = self
            .sources
            .import_omega_cancellable(originals, self.read, Some(cancellation.prover_token()))
            .map_err(artifact)?;
        cancellation.check()?;
        let salt = fresh_fold_salt::<Fq>(cancellation.prover_token())?.to_repr();
        let session = proof(owner.prepare_cancellable(
            input,
            salt,
            self.budget,
            Some(cancellation.prover_token()),
        ))?;
        cancellation.check()?;
        let output =
            proof(session.prove(ProverRandomness::os(), self.prover_config(cancellation)))?;
        let bytes = output.transport();
        proof(session.restore_transport_cancellable(
            &bytes,
            self.budget,
            Some(cancellation.prover_token()),
        ))?;
        cancellation.check()?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_failures_preserve_unavailable_and_cancellation() {
        assert!(matches!(
            salt_error(randomness::Error::Cancelled),
            Error::Cancelled
        ));
        assert!(matches!(
            salt_error(randomness::Error::Unavailable),
            Error::Provider(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Platform(0)
            ))
        ));
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            fresh_fold_salt::<Fp>(&cancellation),
            Err(Error::Cancelled)
        ));
        assert!(matches!(
            fresh_fold_salt::<Fq>(&cancellation),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn checkpoint_identity_binds_both_keys_role_order_and_size() {
        let original = layout(&[1; 32], &[2; 32], 2, 3, 64).unwrap();
        for changed in [
            layout(&[3; 32], &[2; 32], 2, 3, 64),
            layout(&[1; 32], &[3; 32], 2, 3, 64),
            layout(&[1; 32], &[2; 32], 3, 3, 64),
            layout(&[1; 32], &[2; 32], 2, 4, 64),
            layout(&[1; 32], &[2; 32], 2, 3, 65),
        ] {
            assert_ne!(original.artifact_digest, changed.unwrap().artifact_digest);
        }
        assert!(layout(&[1; 32], &[2; 32], 2, 3, 0).is_err());
        assert!(layout(&[1; 32], &[2; 32], 2, 3, usize::MAX).is_err());
    }
}
