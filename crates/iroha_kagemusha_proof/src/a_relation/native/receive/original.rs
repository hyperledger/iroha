//! One-stage original Receive key intake against its immutable complete source.

use super::*;
use crate::tree::IndexedLeaf;
use group::prime::PrimeCurveAffine;
use iroha_plonk::{Protocol, frontend::Circuit, keys::pk::artifact::ReadConfig};

fn original_bounds(original: &[u8], rows: usize, config: ReadConfig) -> Result<(), Error> {
    if original.is_empty() || original.len() > config.maximum_bytes || rows > config.maximum_rows {
        return Err(Error::Artifact);
    }
    Ok(())
}

impl Prover {
    /// Import one original A key against this fixed owner's unknown source.
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

    /// Import one original W key bound to its exact source A verifier and stage.
    /// The returned seal retains no proving buffers, descriptor or verifier copy.
    /// # Errors
    /// Wrong stage/cap, changed source tables, or another installed verifier.
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
        let source = self.plan.wrapper_source(stage, a.binding(), a.key())?;
        let key = ProvingKey::from_artifact_v2_cancellable(
            original,
            artifact.binding(),
            &self.plan.pallas,
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
        let length = Protocol::new(binding.descriptor())
            .map_err(|_| Error::Artifact)?
            .proof_length();
        let allowed = key.kagemusha_digest(binding).map_err(|_| Error::Artifact)?;
        let source = WCircuit::new(
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
        Ok(source)
    }

    /// Reconstruct one fixed unknown source for sequential artifact tooling.
    /// A1 requires no wrapper; each successor pins its immediately preceding W.
    /// This returns no accepted witness, checkpoint or monetary authority.
    /// # Errors
    /// Wrong stage, missing/extra wrapper or a different context/stage identity.
    pub fn source_circuit(
        &self,
        stage: usize,
        previous: Option<WKey>,
    ) -> Result<StageCircuit, Error> {
        if stage >= A_STAGE_COUNT || (stage == 0) != previous.is_none() {
            return Err(Error::Artifact);
        }
        let source = unknown_source(self)?;
        let pallas = source.predecessor.pallas.clone();
        let vesta = source.predecessor.vesta.clone();
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
                pallas,
                fold: vec![0; 1120],
                known: false,
            },
        })
    }
}

// Syntax-only factory, never called by prepare or passed to any decide boundary.
// Every witness is hidden by Stage.known=false; metadata fixes all tape capacities,
// owner/Q partitions, descriptor views and the internal/terminal range profile.
fn unknown_source(plan: &Plan) -> Result<Arc<Source>, Error> {
    let operation = plan.context().operation();
    let specs = plan.context().object_specs();
    let p = AccumulatorT::<Ep>::new(EpAffine::generator(), [Fq::ONE; 16])
        .map_err(|_| Error::Artifact)?;
    let v = AccumulatorT::<Eq>::new(EqAffine::generator(), [Fp::ONE; 16])
        .map_err(|_| Error::Artifact)?;
    let state = StateWitness {
        core: [Fp::ZERO; 33],
        rest: [Fp::ZERO; 8],
        lineage: [Fp::ZERO; 18],
    };
    let insertion = IndexedInsert {
        leaf: IndexedLeaf::default(),
        leaf_slot: 0,
        leaf_siblings: [Fp::ZERO; 32],
        slot: 1,
        slot_siblings: [Fp::ZERO; 32],
    };
    let head = Head {
        state,
        key: plan.predecessor_key.clone(),
        proof: vec![0; operation.omega().ok_or(Error::Artifact)?.proof_length()],
        pallas: p.clone(),
        vesta: v.clone(),
        opening: p.as_input(),
    };
    let mut q = Vec::with_capacity(3);
    for index in 0..3 {
        let fixed = operation.q(index).ok_or(Error::Artifact)?;
        let verifier = fixed.verifier();
        q.push(QSource {
            plan: fixed.clone(),
            proof: vec![0; verifier.proof_length()],
            instances: verifier
                .binding()
                .descriptor()
                .instance_lengths
                .iter()
                .map(|length| {
                    usize::try_from(*length)
                        .map(|n| vec![Fq::ZERO; n])
                        .map_err(|_| Error::Artifact)
                })
                .collect::<Result<_, _>>()?,
            opening: FoldInput::from_opening(
                *p.g(),
                &vec![Fq::ONE; verifier.binding().descriptor().k as usize],
            )
            .map_err(|_| Error::Artifact)?,
        });
    }
    let objects = core::array::from_fn(|index| {
        if matches!(index, 4 | 5) {
            vec![]
        } else {
            vec![0; specs[index].capacity as usize]
        }
    });
    Ok(Arc::new(Source {
        own: Own {
            witness: Transition {
                before: state,
                after: state,
                statement: [Fp::ZERO; 26],
                consumed: insertion,
                credit: insertion,
                blacklist: insertion,
                insert: false,
            },
            send: SendStatement {
                statement: [Fp::ZERO; 26],
            },
            sigma: vec![
                0;
                operation
                    .sigma
                    .class(0)
                    .ok_or(Error::Artifact)?
                    .verifier()
                    .proof_length()
            ],
            incoming_sigma: vec![],
            sigma_plan: operation.sigma.clone(),
            part: v.as_input(),
        },
        predecessor: head.clone(),
        incoming_head: head,
        q,
        plan: plan.stage.clone(),
        policy: plan.policy,
        variant: operation.frame().variant(),
        objects,
        commitments: vec![[Fp::ZERO; 3]; specs.len()],
        incoming: vec![],
        params: plan.pallas.clone(),
        vparams: plan.vesta.clone(),
        results: [false; 5],
        modes: [IncomingMode::Trivial; 4],
        public_valid: false,
        pallas_corrections: [*p.g(); 2],
        vesta_correction: *v.g(),
        selected_pallas: [p.as_input(), p.as_input()],
    }))
}

#[cfg(test)]
#[path = "original/tests.rs"]
mod tests;
