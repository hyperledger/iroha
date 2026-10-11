//! Genuine Refresh originals and fixed owners; component checks grant no lineage.

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)] // Shared signing functions also serve independent Bootstrap consumers.
pub(crate) mod bootstrap_objects;
mod common;
#[path = "common/refresh_objects.rs"]
pub(crate) mod refresh_objects;

use std::sync::Arc;

use ff::Field;
use iroha_kagemusha_proof::{
    a_relation::{
        AProofPlan, LineagePublicCells, ProofMessageCells, QProofPlan, SigmaBindingCells,
        VestaClaimCells, bind_signature_q,
        context::{ContextInputs, ContextPlan, ContextPredecessor, ContextState},
        refresh::{QuotaCommitmentCells, RefreshObjects, RefreshStagePlan, RefreshStageWitness},
        schedule::{OperationTask, sigma_selector},
        verify_q,
    },
    admin_sigma::{RefreshCircuit, StateWitness},
    operation_relation::{
        map_effects::InsertCells, quota_refresh::QuotaRebuildCells, state::StateCells,
        statement::StatementCells,
    },
    q_sigma::{QSigmaPlan, SigmaClass, SigmaSlotWitness, native::QSigmaProver},
    q_signature::{QSignatureCircuit, QSignaturePlan},
};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig, Witness,
    check::{CheckMode, check_circuit},
    create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    bytes::{
        element::le_message_segments,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    imt::{LeafCells, OpeningCells, PathCells},
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    FoldConfig, FoldInput,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};

/// Genuine sigma and signature-Q sources, with all native openings decided.
#[derive(Clone)]
pub(crate) struct Sources {
    pub(crate) fixture: refresh_objects::RefreshFixture,
    pub(crate) objects: [bootstrap_objects::Signed; 5],
    pub(crate) sigma: Vec<u8>,
    pub(crate) plan: RefreshStagePlan,
    pub(crate) q_instances: Vec<Vec<Vec<Fq>>>,
    pub(crate) q_proofs: Vec<Vec<u8>>,
    pub(crate) q_openings: Vec<FoldInput<Ep>>,
    pub(crate) part: FoldInput<Eq>,
    pub(crate) schemas: [QSignaturePlan; 2],
}

fn tasks(variant: Variant) -> Vec<Vec<OperationTask>> {
    let mut tasks = vec![
        vec![OperationTask::RefreshEffects],
        vec![OperationTask::RefreshUpdateAuthorization],
        vec![OperationTask::RefreshCurrentAuthorization],
    ];
    if variant == Variant::RefreshBlacklist {
        tasks.push(vec![OperationTask::RefreshBlacklist]);
    }
    if variant == Variant::RefreshQuotaShare {
        tasks.extend(
            [
                OperationTask::RefreshQuotaPreviousRoot,
                OperationTask::RefreshQuotaWindowRoot,
                OperationTask::RefreshQuotaUsageRoot,
                OperationTask::RefreshQuotaMerge,
            ]
            .map(|task| vec![task]),
        );
    }
    tasks
}

/// Prepare genuine source proofs. The caller independently supplies the Ω program.
/// Every sigma/Q proof is genuine and natively decided. Isolated signature/effect
/// owner checks still do not accept a predecessor or complete the recursive chain.
pub(crate) fn sources(
    fixture: refresh_objects::RefreshFixture,
    omega: VerifierPlan<Ep>,
) -> Sources {
    let leaf = RefreshCircuit::new(&fixture.witness);
    let lp = common::vesta_params(12);
    let key = keygen_pk_v2(
        &lp,
        &leaf,
        &KeygenConfigV2::pipa_r(RefreshCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let sigma = create_proof_owned_with_claim(
        &lp,
        &key,
        Witness::from_circuit(&key, &leaf, &leaf.instances()).unwrap(),
        common::recovery(241),
        ProverConfig::default(),
    )
    .unwrap()
    .proof;
    let claim = accumulate_generator(
        &lp,
        key.binding(),
        key.vk(),
        &leaf.instances(),
        &sigma,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    claim.decide(&lp, MemoryBudget::DEFAULT).unwrap();
    let objects = fixture.objects(&sigma);
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let v = common::vesta_params(16);
    let sigma_plan = QSigmaPlan::new(
        SigmaClass::new(
            VerifierPlan::new(key.binding().clone(), lp).unwrap(),
            vec![(
                sigma_selector(7, 0).unwrap(),
                key.vk().kagemusha_digest(key.binding()).unwrap(),
            )],
        )
        .unwrap(),
        None,
        &v,
    )
    .unwrap();
    let prepared = sigma_plan
        .prepare(
            SigmaSlotWitness {
                key: key.vk().clone(),
                statement: leaf.instances()[0][0],
                length: u32::try_from(sigma.len()).unwrap(),
                proof: sigma.clone(),
            },
            None,
            &v,
            Fq::from(402),
            &FoldConfig::default(),
        )
        .unwrap();
    let q0 = QSigmaProver::keygen_serialized_foreign(&prepared, p.clone(), 2).unwrap();
    let mut q = vec![
        QProofPlan::new(
            VerifierPlan::new(q0.binding().clone(), p.clone()).unwrap(),
            q0.verifying_key().clone(),
        )
        .unwrap(),
    ];
    let q0_proof = q0
        .prove(&prepared, common::recovery(242), ProverConfig::default())
        .unwrap();
    let claim = accumulate_generator(
        &p,
        q0.binding(),
        q0.verifying_key(),
        &q0_proof.instances,
        &q0_proof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    claim.decide(&p, MemoryBudget::DEFAULT).unwrap();
    let mut openings = vec![FoldInput::from_opening(*claim.g(), claim.challenges()).unwrap()];
    let mut proofs = vec![q0_proof.bytes];
    let mut q_instances = vec![q0_proof.instances];
    let schemas = RefreshStagePlan::signature_schemas(refresh_objects::policy()).unwrap();
    for (schema, indices) in schemas.iter().zip([vec![2, 1, 0], vec![4, 3]]) {
        let circuit = QSignatureCircuit::new(
            schema.clone(),
            indices.into_iter().map(|i| objects[i].signature).collect(),
        )
        .unwrap();
        let instances = circuit
            .instances(&vec![true; schema.slots().len()])
            .unwrap();
        let key = keygen_pk_v2(
            &p,
            &circuit,
            &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
        )
        .unwrap();
        let proof = create_proof_owned_with_claim(
            &p,
            &key,
            Witness::from_circuit(&key, &circuit, &instances).unwrap(),
            common::recovery(243),
            ProverConfig::default(),
        )
        .unwrap()
        .proof;
        let claim = accumulate_generator(
            &p,
            key.binding(),
            key.vk(),
            &instances,
            &proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        claim.decide(&p, MemoryBudget::DEFAULT).unwrap();
        openings.push(FoldInput::from_opening(*claim.g(), claim.challenges()).unwrap());
        q.push(
            QProofPlan::new(
                VerifierPlan::new(key.binding().clone(), p.clone()).unwrap(),
                key.vk().clone(),
            )
            .unwrap(),
        );
        q_instances.push(instances.to_vec());
        proofs.push(proof);
    }
    let operation = AProofPlan::new(fixture.variant, sigma_plan, q, Some(omega), &p).unwrap();
    let groups = tasks(fixture.variant);
    let mut partition = vec![vec![0], vec![1], vec![2]];
    partition.resize_with(groups.len(), Vec::new);
    let context = ContextPlan::with_schedule(
        operation,
        partition,
        Some(0),
        RefreshObjects::context_specs(fixture.variant).unwrap(),
    )
    .unwrap()
    .with_operation_tasks(groups)
    .unwrap();
    let source = Sources {
        fixture,
        objects,
        sigma,
        plan: RefreshStagePlan::new(context, refresh_objects::policy()).unwrap(),
        q_instances,
        q_proofs: proofs,
        q_openings: openings,
        part: prepared.part().clone(),
        schemas,
    };
    assert_eq!(
        source.q_openings.len(),
        source.plan.context().operation().q_count()
    );
    assert_eq!(source.part.source_k(), 12);
    for (i, proof) in source.q_proofs.iter().enumerate() {
        assert_eq!(
            proof.len(),
            source
                .plan
                .context()
                .operation()
                .q(i)
                .unwrap()
                .verifier()
                .proof_length()
        );
    }
    source
}

/// One actual fixed owner; there is no predecessor proof or completed A claim.
#[derive(Clone)]
pub(crate) struct Owner {
    pub(crate) source: Arc<Sources>,
    pub(crate) stage: usize,
    pub(crate) known: bool,
    pub(crate) mutation: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
/// Exact optional map witnesses assigned by their fixed owning stage.
pub(crate) struct AssignedMaps {
    pub(crate) blacklist: Option<InsertCells>,
    pub(crate) quota: Option<QuotaRebuildCells>,
}
impl Owner {
    pub(crate) fn value<T: Copy>(&self, v: T) -> Value<T> {
        if self.known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    }
    pub(crate) fn scalar(
        &self,
        chip: &mut VerifierChip<Ep>,
        r: &mut Region<'_, Fp>,
        value: Fq,
    ) -> Result<ScalarCells<Ep>, Error> {
        let [lo, hi] = foreign_limbs(&value);
        let lo = chip.uint().assign::<128>(r, self.value(lo))?;
        let hi = chip.uint().assign::<127>(r, self.value(hi))?;
        ScalarCells::from_limbs(&mut chip.uint(), r, &lo, &hi)
    }
    pub(crate) fn state(
        &self,
        chip: &mut VerifierChip<Ep>,
        r: &mut Region<'_, Fp>,
        w: &StateWitness,
    ) -> Result<(StateCells, LineagePublicCells), Error> {
        let core = chip
            .uint()
            .glue()
            .witnesses(r, &w.core.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let rest = chip
            .uint()
            .glue()
            .witnesses(r, &w.rest.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let state = StateCells::constrain_with_verifier(chip, r, &core, &rest)?;
        let lineage = chip
            .uint()
            .glue()
            .witnesses(r, &w.lineage.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        Ok((
            state,
            LineagePublicCells::constrain(&mut chip.uint(), r, &lineage)?,
        ))
    }
    pub(crate) fn proof(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        r: &mut Region<'_, Fp>,
        raw: &[u8],
    ) -> Result<ProofMessageCells, Error> {
        let mut source = u32::try_from(raw.len()).unwrap().to_le_bytes().to_vec();
        source.extend(raw);
        let source = source
            .into_iter()
            .map(|v| self.value(v))
            .collect::<Vec<_>>();
        let mut segments = vec![SegmentSpec::little(0, 4)];
        segments.extend(le_message_segments(4, raw.len() / 32));
        let run = bytes.run(
            r,
            &source,
            &source
                .chunks(31)
                .map(<[Value<u8>]>::len)
                .collect::<Vec<_>>(),
            &segments,
        )?;
        ProofMessageCells::from_run(chip, r, &run, 0, raw.len())
    }
    pub(crate) fn sigma(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        r: &mut Region<'_, Fp>,
        statement: &StatementCells,
    ) -> Result<SigmaBindingCells, Error> {
        let raw = &self.source.sigma;
        let mut source = u32::try_from(raw.len()).unwrap().to_le_bytes().to_vec();
        source.extend(raw);
        if self.mutation == 6 {
            source[40] ^= 1;
        }
        let source = source
            .into_iter()
            .map(|v| self.value(v))
            .collect::<Vec<_>>();
        let run = bytes.run(
            r,
            &source,
            &source
                .chunks(31)
                .map(<[Value<u8>]>::len)
                .collect::<Vec<_>>(),
            &[SegmentSpec::little(0, 4)],
        )?;
        let index = chip
            .uint()
            .glue()
            .constant(r, Fp::from(u64::from(sigma_selector(7, 0).unwrap())))?;
        SigmaBindingCells::from_run(chip, r, statement, index, &run)
    }
    pub(crate) fn quota_commitment(
        &self,
        chip: &mut VerifierChip<Ep>,
        r: &mut Region<'_, Fp>,
    ) -> Result<Option<QuotaCommitmentCells>, Error> {
        self.source
            .fixture
            .quota
            .as_ref()
            .map(|q| {
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(r, &q.commitments().map(|v| self.value(v)))?;
                Ok(QuotaCommitmentCells {
                    previous_usage: fields[0].clone(),
                    windows: fields[1].clone(),
                    successor_usage: fields[2].clone(),
                    issued: fields[3].clone(),
                    window_count: fields[4].clone(),
                })
            })
            .transpose()
    }
    pub(crate) fn maps(
        &self,
        chip: &mut VerifierChip<Ep>,
        r: &mut Region<'_, Fp>,
    ) -> Result<AssignedMaps, Error> {
        let source = &self.source;
        let task = source
            .plan
            .context()
            .operation_tasks(self.stage)
            .ok_or(Error::Synthesis)?;
        let blacklist = if task.contains(&OperationTask::RefreshBlacklist) {
            let mut proof = source.fixture.blacklist.ok_or(Error::Synthesis)?;
            if self.mutation == 8 {
                proof.slot_siblings[31] += Fp::ONE;
            }
            let fields = [proof.leaf.key, proof.leaf.value, proof.leaf.next_key];
            let leaf = LeafCells::from_words(
                chip.uint()
                    .glue()
                    .witnesses(r, &fields.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?,
            );
            let mut paths = Vec::new();
            for (index, siblings) in [
                (proof.leaf_slot, proof.leaf_siblings),
                (proof.slot, proof.slot_siblings),
            ] {
                let index = chip
                    .uint()
                    .glue()
                    .witness(r, self.value(Fp::from(u64::from(index))))?;
                let siblings = chip
                    .uint()
                    .glue()
                    .witnesses(r, &siblings.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                paths.push(PathCells::from_words(
                    &mut chip.uint(),
                    r,
                    &index,
                    siblings,
                )?);
            }
            let [low, slot] = paths.try_into().map_err(|_| Error::Synthesis)?;
            Some(InsertCells {
                low: OpeningCells { leaf, path: low },
                slot,
            })
        } else {
            None
        };
        let quota = if task.iter().any(|task| {
            matches!(
                task,
                OperationTask::RefreshQuotaMerge
                    | OperationTask::RefreshQuotaPreviousRoot
                    | OperationTask::RefreshQuotaWindowRoot
                    | OperationTask::RefreshQuotaUsageRoot
            )
        }) {
            let mut q = source.fixture.quota.clone().ok_or(Error::Synthesis)?;
            if self.mutation == 8 {
                if task.contains(&OperationTask::RefreshQuotaPreviousRoot) {
                    q.old[0][3] += Fp::ONE;
                } else if task.contains(&OperationTask::RefreshQuotaWindowRoot) {
                    q.windows[0][3] += Fp::ONE;
                } else {
                    q.used[0] += Fp::ONE;
                }
            }
            if self.mutation == 9 {
                q.count += Fp::ONE;
            }
            let values = q
                .old
                .iter()
                .flatten()
                .chain(q.windows.iter().flatten())
                .chain(&q.used)
                .chain([&q.issued, &q.count])
                .map(|v| self.value(*v))
                .collect::<Vec<_>>();
            let words = chip.uint().glue().witnesses(r, &values)?;
            Some(QuotaRebuildCells {
                old: ::core::array::from_fn(|i| {
                    ::core::array::from_fn(|j| words[4 * i + j].clone())
                }),
                windows: ::core::array::from_fn(|i| {
                    ::core::array::from_fn(|j| words[256 + 4 * i + j].clone())
                }),
                used: ::core::array::from_fn(|i| words[512 + i].clone()),
                issued: words[576].clone(),
                window_count: words[577].clone(),
            })
        } else {
            None
        };
        Ok(AssignedMaps { blacklist, quota })
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        let mut objects = self.source.objects.clone();
        if (1..=5).contains(&self.mutation) {
            objects[usize::from(self.mutation - 1)].bytes[40] ^= 1;
        }
        vec![
            objects
                .iter()
                .map(bootstrap_objects::Signed::digest)
                .collect(),
        ]
    }
}
impl Circuit<Fp> for Owner {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(5);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "genuine fixed Refresh owner",
            |mut r| {
                let source = &self.source;
                let w = &source.fixture.witness;
                let (before, previous) = self.state(&mut chip, &mut r, &w.predecessor)?;
                let (after, next) = self.state(&mut chip, &mut r, &w.successor)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut r, &w.statement.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut r,
                    source.fixture.variant,
                    &fields,
                )?;
                let mut originals = source.objects.clone();
                if (1..=5).contains(&self.mutation) {
                    originals[usize::from(self.mutation - 1)].bytes[40] ^= 1;
                }
                let tapes = originals
                    .each_ref()
                    .map(|o| o.bytes.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
                let mut objects = RefreshObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut r,
                    source.fixture.variant,
                    tapes.each_ref().map(Vec::as_slice),
                )?;
                if let Some(commitment) = self.quota_commitment(&mut chip, &mut r)? {
                    objects = objects.with_quota_commitment(&mut chip, &mut r, &commitment)?;
                }
                let q_instances = source
                    .q_instances
                    .iter()
                    .map(|columns| {
                        columns
                            .iter()
                            .map(|column| {
                                column
                                    .iter()
                                    .map(|v| self.scalar(&mut chip, &mut r, *v))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, Error>>()?;
                let task = source
                    .plan
                    .context()
                    .operation_tasks(self.stage)
                    .ok_or(Error::Synthesis)?;
                let update = task.contains(&OperationTask::RefreshUpdateAuthorization);
                let current = task.contains(&OperationTask::RefreshCurrentAuthorization);
                let sigma = if update {
                    Some(self.sigma(&mut chip, &mut bytes, &mut r, &statement)?)
                } else {
                    None
                };
                let signatures = if update || current {
                    let index = if update { 1 } else { 2 };
                    let mut proof = source.q_proofs[index].clone();
                    if self.mutation == 7 {
                        proof[32] ^= 1;
                    }
                    let proof = self.proof(&mut chip, &mut bytes, &mut r, &proof)?;
                    let q = verify_q(
                        &mut chip,
                        &mut r,
                        source.plan.context().operation(),
                        index,
                        &q_instances[index],
                        &proof,
                    )?;
                    Some(bind_signature_q(
                        &mut chip,
                        &mut r,
                        source.plan.context().operation(),
                        index,
                        &source.schemas[index - 1],
                        &q,
                    )?)
                } else {
                    None
                };
                // These deciding fillers populate unused component context fields only.
                // No predecessor proof is created or accepted by this owner circuit.
                let point = iroha_plonk::transcript::decode_point::<Ep>(
                    &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
                )
                .map_err(|_| Error::Synthesis)?;
                let point = chip.constant_point(&mut r, &Ep::from(point))?;
                let one = self.scalar(&mut chip, &mut r, Fq::ONE)?;
                let pallas = FoldInputCells::from_normalized(
                    &mut chip,
                    &mut r,
                    16,
                    point,
                    ::core::array::from_fn(|_| one.clone()),
                )?;
                let vesta = VestaClaimCells::trivial(&mut chip, &mut r)?;
                let maps = self.maps(&mut chip, &mut r)?;
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: None,
                    predecessor: Some(ContextPredecessor {
                        state: &before,
                        public: &previous,
                        pallas: &pallas,
                        vesta: &vesta,
                    }),
                    successor: ContextState {
                        state: &after,
                        public: &next,
                    },
                    incoming: None,
                    q_instances: &q_instances,
                    objects: objects.context(),
                    modes: &[],
                    pallas_corrections: &[],
                    vesta_corrections: &[],
                    receive_results: None,
                };
                source.plan.constrain_stage(
                    &mut chip,
                    &mut r,
                    self.stage,
                    &objects,
                    &input,
                    RefreshStageWitness {
                        sigma: sigma.as_ref(),
                        signatures: signatures.as_ref(),
                        blacklist: maps.blacklist.as_ref(),
                        quota: maps.quota.as_ref(),
                    },
                )?;
                Ok(objects
                    .context()
                    .iter()
                    .take(5)
                    .map(|o| o.authenticated_digest().clone())
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, value) in out.iter().enumerate() {
            layouter.constrain_instance(value.cell(), config.public, i)?;
        }
        Ok(())
    }
}

// Constructor-only Ω metadata: no key or proof from this program is accepted.
fn predecessor_metadata() -> VerifierPlan<Ep> {
    #[derive(Clone)]
    struct Metadata;
    impl Circuit<Fq> for Metadata {
        type Config = ();
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            self.clone()
        }
        fn configure(meta: &mut ConstraintSystem<Fq>) {
            for n in [1, 2, 16] {
                meta.instance_column(n);
            }
        }
        fn synthesize(&self, (): (), _: impl Layouter<Fq>) -> Result<(), Error> {
            Ok(())
        }
    }
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let (binding, _) = keygen_vk_with_binding_v2(
        &params,
        &Metadata,
        &KeygenConfigV2::pipa_r(vec![
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bounded,
        ]),
    )
    .unwrap();
    VerifierPlan::new(binding, params).unwrap()
}

#[test]
fn genuinely_signed_refresh_fixtures_match_every_shared_sigma_branch() {
    for variant in refresh_objects::VARIANTS {
        let fixture = refresh_objects::fixture(variant);
        let circuit = RefreshCircuit::new(&fixture.witness);
        let report = check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict).unwrap();
        assert!(report.is_satisfied(), "{variant:?}: {report:?}");
    }
}

#[test]
#[ignore = "genuine sigma/signature Q proofs and all fixed Refresh owners; run optimized"]
fn genuine_refresh_owners_bind_all_originals_and_report_capacity() {
    for variant in refresh_objects::VARIANTS {
        check_genuine_owners(variant);
    }
}

#[test]
#[ignore = "genuine Quota sigma/signature Q proofs and each fixed root/merge owner; run optimized"]
fn genuine_quota_split_owners_bind_all_arrays_and_report_capacity() {
    check_genuine_owners(Variant::RefreshQuotaShare);
}

fn check_genuine_owners(variant: Variant) {
    let source = Arc::new(sources(
        refresh_objects::fixture(variant),
        predecessor_metadata(),
    ));
    for stage in 0..source.plan.context().stage_count() {
        let circuit = Owner {
            source: source.clone(),
            stage,
            known: true,
            mutation: 0,
        };
        // k17 is a diagnostic ceiling. A component above k16 requires splitting;
        // this test does not qualify its admission as a source A stage.
        let known = synthesize(&circuit, 17, Some(&circuit.public())).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 17, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        let rows = known
            .tables
            .advice_assigned()
            .iter()
            .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
            .collect::<Vec<_>>();
        let report = check_circuit(&circuit, 17, &circuit.public(), CheckMode::Strict).unwrap();
        assert!(
            report.is_satisfied(),
            "{variant:?} stage{stage}: {report:?}"
        );
        eprintln!(
            "REFRESH_OWNER variant={variant:?} stage={stage} rows={rows:?} k16_fit={} full_A=false",
            rows.iter().all(|r| *r < 65529)
        );
        drop(known);
        drop(unknown);
        let mutations: &[u8] = match stage {
            0 => &[2],
            1 => &[1, 2, 3, 6, 7],
            2 => &[4, 5, 7],
            _ if variant == Variant::RefreshBlacklist => &[8],
            _ => &[8, 9],
        };
        for &mutation in mutations {
            let wrong = Owner {
                mutation,
                ..circuit.clone()
            };
            assert!(
                !check_circuit(&wrong, 17, &wrong.public(), CheckMode::Strict)
                    .is_ok_and(|r| r.is_satisfied()),
                "{variant:?} stage{stage} original{mutation}"
            );
        }
    }
}
