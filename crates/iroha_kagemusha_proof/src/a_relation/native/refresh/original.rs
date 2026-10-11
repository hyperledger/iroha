//! One-at-a-time original-key intake for the exact installed Refresh stage sources.
//!
//! Metadata installation retains no PK or original bytes. Each importer builds the
//! exact unknown source, validates original tables and installed VK, and returns one
//! compact source-admission seal after dropping that PK. Proving reconstructs only this
//! admitted source and releases its temporary PK before verification and decisions.

use super::*;
use iroha_plonk::{
    cs::{CurveV1, InstanceModeV1, ProofSuffixV1, TranscriptV2},
    keys::pk::artifact::ReadConfig,
};
const DESCRIPTOR_MAX_BYTES: usize = 1 << 20;
const VERIFYING_KEY_MAX_BYTES: usize = 1 << 18;

fn metadata<C: iroha_pasta::PastaCurve>(
    artifact: &KeyArtifact<C>,
    curve: CurveV1,
    lengths: &[u32],
    types: &[InstanceType],
) -> Result<(), Error> {
    let binding = artifact.binding();
    let d = binding.descriptor();
    if binding.encoded().len() > DESCRIPTOR_MAX_BYTES
        || artifact.key().to_bytes().len() > VERIFYING_KEY_MAX_BYTES
        || d.k != 16
        || d.curve != curve
        || d.transcript != TranscriptV2::KagemushaPoseidonRp57Base
        || d.instance_mode != InstanceModeV1::Direct
        || d.proof_suffix != ProofSuffixV1::FoldedGenerator
        || d.instance_lengths.as_slice() != lengths
        || d.instance_types.as_deref() != Some(types)
    {
        return Err(Error::Artifact);
    }
    Ok(())
}
fn original_bounds(original: &[u8], rows: usize, config: ReadConfig) -> Result<(), Error> {
    if original.is_empty() || original.len() > config.maximum_bytes || rows > config.maximum_rows {
        return Err(Error::Artifact);
    }
    Ok(())
}

impl Prover {
    /// Install complete four- or seven-stage verifier metadata without retaining any PK.
    ///
    /// The owner authenticates the scheme, provider, root and exact compiled-source
    /// catalog before calling this constructor. Metadata matching alone is not original
    /// source verification. Use `import_a`/`import_w` for strict original-key intake;
    /// every proving call checks the full admitted D/V identity before any fold.
    /// No operation input chooses the profile or stage schedule.
    /// # Errors
    /// Missing source, nonuniform A profile, curve/public schema or W schema.
    pub fn from_artifacts(
        plan: Plan,
        a: Vec<KeyArtifact<Eq>>,
        w: Vec<KeyArtifact<Ep>>,
    ) -> Result<Self, Error> {
        let count = plan.context.stage_count();
        if !matches!(count, BASIC_A_STAGE_COUNT | QUOTA_A_STAGE_COUNT)
            || a.len() != count
            || w.len() + 1 != count
        {
            return Err(Error::Artifact);
        }
        let expected =
            super::super::artifact::source_descriptor::<StageCircuit>(()).ok_or(Error::Artifact)?;
        for artifact in &a {
            metadata(artifact, CurveV1::Vesta, &[69], &[InstanceType::Bounded])?;
            if artifact.binding() != &expected {
                return Err(Error::Artifact);
            }
        }
        let mut wrappers = Vec::with_capacity(w.len());
        for (stage, artifact) in w.iter().enumerate() {
            metadata(
                artifact,
                CurveV1::Pallas,
                &[1, 2, 16],
                &crate::omega::OmegaPlan::instance_types(),
            )?;
            wrappers.push(
                WKey::from_artifact(
                    &plan.context,
                    stage,
                    artifact.binding().clone(),
                    plan.pallas.clone(),
                    artifact.key().clone(),
                )
                .map_err(|_| Error::Artifact)?,
            );
        }
        Ok(Self {
            plan,
            a,
            w,
            wrappers,
        })
    }

    /// Import one original A PK against the exact compiled stage and installed verifier.
    ///
    /// Unknown source inputs cannot create a `Prepared` operation or accepted claim.
    /// The imported proving buffers are dropped before returning a compact source-admission seal;
    /// the producer retains neither proving buffers nor original bytes.
    /// # Errors
    /// Wrong stage/cap, changed source/copy/selector/commitment tables or installed VK.
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
        let circuit = self.plan.source_circuit(
            stage,
            stage
                .checked_sub(1)
                .map(|previous| self.wrappers[previous].clone()),
        )?;
        let key = ProvingKey::from_artifact_v2_cancellable(
            original,
            artifact.binding(),
            &self.plan.vesta,
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

    /// Import one original W PK bound to this exact preceding A verifier and stage.
    /// The producer keeps only verifier metadata after this returned key is released.
    /// # Errors
    /// Wrong stage/cap, changed source/copy/selector/commitment tables or installed VK.
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
    /// Reconstruct one compiled unknown A source for sequential offline tooling.
    /// A1 takes no wrapper; every continuation pins its immediately preceding W.
    /// This creates no prepared operation, accepted claim or monetary authority.
    /// # Errors
    /// Out-of-range stage, missing/extra wrapper or wrong fixed stage/context.
    pub fn source_circuit(
        &self,
        stage: usize,
        previous: Option<WKey>,
    ) -> Result<StageCircuit, Error> {
        if stage >= self.context.stage_count() || (stage == 0) != previous.is_none() {
            return Err(Error::Artifact);
        }
        let first = FirstCircuit::blank(self)?;
        Ok(if stage == 0 {
            StageCircuit {
                inner: StageData::First(Box::new(first)),
            }
        } else {
            let split = SplitPlan::new(
                self.context.clone(),
                stage,
                previous.ok_or(Error::Artifact)?,
                &self.pallas,
            )
            .map_err(|_| Error::Artifact)?;
            StageCircuit {
                inner: StageData::Continued(Box::new(ContinuationCircuit::blank(first, split)?)),
            }
        })
    }

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
        if stage >= self.context.stage_count().saturating_sub(1)
            || binding
                != &super::super::artifact::source_descriptor::<StageCircuit>(())
                    .ok_or(Error::Artifact)?
        {
            return Err(Error::Artifact);
        }
        wrapper_source(self, stage, binding, key)
    }
}

fn wrapper_source(
    plan: &Plan,
    stage: usize,
    binding: &DescriptorBinding,
    key: &VerifyingKey<Eq>,
) -> Result<WCircuit, Error> {
    let allowed = key.kagemusha_digest(binding).map_err(|_| Error::Artifact)?;
    let length = iroha_plonk::Protocol::new(binding.descriptor())
        .map_err(|_| Error::Artifact)?
        .proof_length();
    WCircuit::new(
        &plan.context,
        stage,
        binding.clone(),
        plan.vesta.clone(),
        vec![allowed],
        OmegaWitness {
            key: key.clone(),
            instances: vec![Fp::ZERO; 69],
            proof: vec![0; length],
            length: u32::try_from(length).map_err(|_| Error::Artifact)?,
            fold: [0; 1120],
        },
    )
    .map(|source| source.without_witnesses())
    .map_err(|_| Error::Artifact)
}

impl FirstCircuit {
    fn blank(plan: &Plan) -> Result<Self, Error> {
        use crate::admin_sigma::{RefreshKind, RefreshUpdateWitness};
        let operation = plan.context.operation();
        let variant = operation.frame().variant();
        let kinds = object_kinds(variant)?;
        let class = operation.sigma.class(0).ok_or(Error::Artifact)?;
        let predecessor = operation.omega().ok_or(Error::Artifact)?;
        let state = StateWitness {
            core: [Fp::ZERO; 33],
            rest: [Fp::ZERO; 8],
            lineage: [Fp::ZERO; 18],
        };
        let mut q_instances = Vec::new();
        let mut q_proofs = Vec::new();
        for index in 0..3 {
            let q = operation.q(index).ok_or(Error::Artifact)?;
            q_instances.push(
                q.verifier()
                    .binding()
                    .descriptor()
                    .instance_lengths
                    .iter()
                    .map(|length| {
                        usize::try_from(*length)
                            .map(|length| vec![Fq::ZERO; length])
                            .map_err(|_| Error::Artifact)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
            q_proofs.push(vec![0; q.verifier().proof_length()]);
        }
        let kind = match variant {
            Variant::RefreshCredential => RefreshKind::Credential,
            Variant::RefreshSchemePolicy => RefreshKind::SchemePolicy,
            Variant::RefreshBlacklist => RefreshKind::Blacklist,
            Variant::RefreshQuotaShare => RefreshKind::QuotaShare,
            Variant::RefreshTimeAnchor => RefreshKind::TimeAnchor,
            _ => return Err(Error::Artifact),
        };
        let source = CircuitSources {
            maps: Maps {
                witness: RefreshWitness {
                    predecessor: state,
                    successor: state,
                    statement: [Fp::ZERO; 26],
                    update: RefreshUpdateWitness {
                        kind,
                        digest: Fp::ZERO,
                        scheme: [Fp::ZERO; 2],
                        asset: [Fp::ZERO; 2],
                        wallet: [Fp::ZERO; 2],
                        counter: Fp::ZERO,
                        issued_at_ms: Fp::ZERO,
                        expires_at_ms: Fp::ZERO,
                        root: Fp::ZERO,
                        controls: Fp::ZERO,
                        fee_schedule: Fp::ZERO,
                    },
                },
                blacklist: (variant == Variant::RefreshBlacklist).then_some(IndexedInsert {
                    leaf: crate::tree::IndexedLeaf::default(),
                    leaf_slot: 0,
                    leaf_siblings: [Fp::ZERO; 32],
                    slot: 1,
                    slot_siblings: [Fp::ZERO; 32],
                }),
                quota: (variant == Variant::RefreshQuotaShare).then_some(QuotaInput {
                    old: [[Fp::ZERO; 4]; 64],
                    windows: [[Fp::ZERO; 4]; 64],
                    used: [Fp::ZERO; 64],
                    issued: Fp::ZERO,
                    window_count: Fp::ZERO,
                }),
                known: false,
            },
            objects: kinds.map(|kind| SignedTape {
                kind,
                bytes: vec![0; kind.body_len() + 64],
            }),
            variant,
            sigma: vec![0; class.verifier().proof_length()],
            q_instances,
            q_proofs,
            signature_schemas: plan.signatures.clone(),
            predecessor: CircuitPredecessor {
                key: plan.predecessor_key.clone(),
                proof: vec![0; predecessor.proof_length()],
                pallas: None,
                vesta: None,
            },
            params: plan.pallas.clone(),
            policy: plan.policy,
        };
        Ok(Self {
            source: Arc::new(source),
            plan: plan.context.clone(),
            fold: vec![0; 1120],
            known: false,
        })
    }
}
impl ContinuationCircuit {
    fn blank(first: FirstCircuit, plan: SplitPlan) -> Result<Self, Error> {
        if !(1..first.plan.stage_count()).contains(&plan.stage()) {
            return Err(Error::Artifact);
        }
        Ok(Self {
            first,
            wrapper: vec![0; plan.wrap().verifier().proof_length()],
            vesta: None,
            fold: vec![0; 1120],
            carried: None,

            plan,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_bounds_reject_missing_oversized_and_over_domain_tables() {
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
        // Passing envelope checks alone does not parse or admit an original key.
    }
}

#[cfg(test)]
mod original_metadata_tests {
    use super::*;

    #[test]
    fn malformed_original_metadata_rejects_before_source_or_prover_admission() {
        // Raw codec refusals migrated from the superseded all-keys-at-once
        // constructor. The current catalog bounds these originals before reading;
        // metadata installation and one-key source imports remain separate owners.
        for bytes in [vec![], vec![1], vec![0; DESCRIPTOR_MAX_BYTES + 1]] {
            assert!(DescriptorBinding::decode_v2(&bytes).is_err());
        }
        let binding = super::super::super::artifact::source_descriptor::<StageCircuit>(()).unwrap();
        for bytes in [vec![], vec![1], vec![0; VERIFYING_KEY_MAX_BYTES + 1]] {
            assert!(VerifyingKey::<Eq>::read(&bytes, &binding).is_err());
        }
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
    }
}
