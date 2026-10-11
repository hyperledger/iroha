//! Strict one-at-a-time original Archive PK intake against every compiled owner.

use super::*;
use ff::Field;
use iroha_plonk::{Protocol, frontend::Circuit, keys::pk::artifact::ReadConfig};

fn original_bounds(original: &[u8], rows: usize, config: ReadConfig) -> Result<(), Error> {
    if original.is_empty() || original.len() > config.maximum_bytes || rows > config.maximum_rows {
        return Err(Error::Artifact);
    }
    Ok(())
}

impl Prover {
    /// Import one original A PK using this fixed owner's unknown source.
    /// The import drops its PK and returns only a compact source-admission seal.
    /// # Errors
    /// Wrong stage/cap, changed source/copy/selector tables or installed verifier.
    pub fn import_a(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        self.import_a_cancellable(stage, original, config, None)
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    pub fn import_a_cancellable(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Eq>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let artifact = self.a.get(stage).ok_or(Error::Artifact)?;
        original_bounds(original, artifact.binding().n(), config)?;
        let source = self.plan.source_circuit(
            stage,
            stage
                .checked_sub(1)
                .map(|previous| self.wrappers[previous].clone()),
        )?;
        let key = ProvingKey::from_artifact_v2_cancellable(
            original,
            artifact.binding(),
            &self.plan.vesta,
            &source,
            config,
            cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Artifact
            }
        })?;
        artifact.require_prover(&key).map_err(|_| Error::Artifact)?;
        let metadata =
            SourceAdmissionSealV2::from_proving_key(&key, cancellation).map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Artifact
                }
            })?;
        drop(key);
        Ok(metadata)
    }

    /// Import one original W PK bound to the exact preceding A verifier and stage.
    /// The returned key is the only proving buffer owned by this call.
    /// # Errors
    /// Wrong stage/cap, changed original source tables or installed verifier.
    pub fn import_w(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
    ) -> Result<SourceAdmissionSealV2<Ep>, Error> {
        self.import_w_cancellable(stage, original, config, None)
    }
    /// Import the same original with an explicit operation cancellation signal.
    /// # Errors
    /// As the ordinary import, or cancellation without a partial installed key.
    pub fn import_w_cancellable(
        &self,
        stage: usize,
        original: &[u8],
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceAdmissionSealV2<Ep>, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let artifact = self.w.get(stage).ok_or(Error::Artifact)?;
        original_bounds(original, artifact.binding().n(), config)?;
        let a = &self.a[stage];
        let circuit = self.plan.wrapper_source(stage, a.binding(), a.key())?;
        let key = ProvingKey::from_artifact_v2_cancellable(
            original,
            artifact.binding(),
            &self.plan.pallas,
            &circuit,
            config,
            cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Artifact
            }
        })?;
        artifact.require_prover(&key).map_err(|_| Error::Artifact)?;
        let metadata =
            SourceAdmissionSealV2::from_proving_key(&key, cancellation).map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Artifact
                }
            })?;
        drop(key);
        Ok(metadata)
    }
}

impl Plan {
    /// Reconstruct the unknown W source bound to this stage's exact A verifier.
    /// The strict original importer uses this same source factory.
    /// # Errors
    /// Terminal/out-of-range stage, foreign source profile or invalid A verifier.
    pub fn wrapper_source(
        &self,
        stage: usize,
        binding: &DescriptorBinding,
        key: &VerifyingKey<Eq>,
    ) -> Result<WCircuit, Error> {
        if stage >= A_STAGE_COUNT - 1
            || binding
                != &crate::a_relation::native::artifact::source_descriptor::<StageCircuit>(
                    INTERNAL_RANGE_BUSES,
                )
                .ok_or(Error::Artifact)?
        {
            return Err(Error::Artifact);
        }
        let allowed = key.kagemusha_digest(binding).map_err(|_| Error::Artifact)?;
        let length = Protocol::new(binding.descriptor())
            .map_err(|_| Error::Artifact)?
            .proof_length();
        let circuit = WCircuit::new(
            self.context(),
            stage,
            binding.clone(),
            self.vesta.clone(),
            vec![allowed],
            OmegaWitness {
                key: key.clone(),
                instances: vec![Fp::ZERO; 69],
                proof: vec![0; length],
                length: u32::try_from(length).map_err(|_| Error::Artifact)?,
                fold: [0; 1120],
            },
        )
        .map_err(|_| Error::Artifact)?
        .without_witnesses();
        Ok(circuit)
    }

    /// Reconstruct one exact unknown owner source for sequential artifact tooling.
    /// A1 takes no wrapper; every successor pins its actual preceding W verifier.
    /// This contains no usable witness, accepted `Prepared` value or checkpoint.
    /// # Errors
    /// Wrong stage, missing/extra wrapper or another fixed context/stage identity.
    pub fn source_circuit(
        &self,
        stage: usize,
        previous: Option<WKey>,
    ) -> Result<StageCircuit, Error> {
        if stage >= A_STAGE_COUNT || (stage == 0) != previous.is_none() {
            return Err(Error::Artifact);
        }
        let source = Prepared::unknown_source(self)?;
        let (pallas, vesta) = source.predecessor_claims().clone();
        let continuation = if stage == 0 {
            None
        } else {
            let plan = SplitPlan::new(
                self.context().clone(),
                stage,
                previous.ok_or(Error::Artifact)?,
                &self.pallas,
            )
            .map_err(|_| Error::Artifact)?;
            Some(Continuation {
                proof: vec![0; plan.wrap().verifier().proof_length()],
                carried: pallas.clone(),
                vesta: vesta.clone(),
                plan,
            })
        };
        Ok(StageCircuit {
            inner: Stage {
                source,
                continuation,
                pallas: pallas.clone(),
                fold: vec![0; 1120],
                known: false,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_bounds_reject_empty_oversized_and_over_domain_inputs() {
        let config = ReadConfig {
            maximum_bytes: 16,
            maximum_rows: 1 << 16,
            coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        assert_eq!(original_bounds(&[], 1 << 16, config), Err(Error::Artifact));
        assert_eq!(
            original_bounds(&[0; 17], 1 << 16, config),
            Err(Error::Artifact)
        );
        assert_eq!(
            original_bounds(&[0; 16], (1 << 16) + 1, config),
            Err(Error::Artifact)
        );
        assert_eq!(original_bounds(&[0; 16], 1 << 16, config), Ok(()));
        // Passing an envelope check does not parse or authenticate these dummy bytes.
    }
}
