//! Genuine Bootstrap-rooted Refresh Q/A/W chains with all fixed hard owners.
//! The predecessor catalog admits Bootstrap only; these component chains do not
//! admit Refresh terminal keys or establish a complete release catalog.
#![allow(clippy::duplicate_mod)]
/// Genuine Bootstrap and compact outer proof construction.
#[path = "bootstrap_omega.rs"]
pub mod bootstrap_outer;
mod common;
/// Shared signed Refresh source proofs and exact owner witness assignment.
#[path = "a_refresh.rs"]
pub mod components;
#[path = "common/native_source_factory_checks.rs"]
mod native_source_factory_checks;

use components::{Owner, refresh_objects};
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::{
        VestaClaimCells, bind_signature_q,
        context::{ContextInputs, ContextPlan, ContextPredecessor, ContextState},
        refresh::{RefreshObjects, RefreshStagePlan, RefreshStageWitness},
        schedule::OperationTask,
        split::{SplitPlan, WCircuit, WKey, close_first, close_stage, resume_context},
        verify_predecessor, verify_q, verify_sigma,
    },
    admin_sigma::StateWitness,
    omega::{OmegaPlan, OmegaWitness},
    operation_relation::statement::StatementCells,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    DescriptorBinding, ProverConfig, ProverOutput, ProvingKey, VerifyingKey, Witness,
    check::{CheckMode, check, check_circuit},
    create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    bytes::tape::{BytesChip, BytesConfig},
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput,
    accumulation_circuit::FoldInputCells,
    create_fold,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};
use std::sync::Arc;

fn object_claims(source: &components::Sources) -> Vec<[Fp; 3]> {
    let mut words = Vec::new();
    for (object, spec) in source
        .objects
        .iter()
        .zip(RefreshObjects::context_specs(source.fixture.variant).unwrap())
    {
        let mut tape = vec![
            Fp::from(u64::from(spec.tag)),
            Fp::from(u64::from(spec.capacity)),
        ];
        let mut framed = u32::try_from(object.bytes.len())
            .unwrap()
            .to_le_bytes()
            .to_vec();
        framed.extend(&object.bytes);
        for chunk in framed.chunks(31) {
            let mut repr = [0; 32];
            repr[..chunk.len()].copy_from_slice(chunk);
            tape.push(Fp::from_repr(repr).unwrap());
        }
        words.push([
            object.digest(),
            Fp::from(u64::from(spec.capacity)),
            hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &tape),
        ]);
    }
    if let Some(quota) = &source.fixture.quota {
        let mut framed = vec![Fp::from(6), Fp::from(5)];
        framed.extend(quota.commitments());
        let digest = hash_with_domain(u64::from_le_bytes(*b"kgwciw_1"), &framed);
        words.push([digest, Fp::from(160), digest]);
    }
    words
}

#[derive(Clone)]
struct Predecessor {
    key: VerifyingKey<Ep>,
    proof: Vec<u8>,
    pallas: AccumulatorT<Ep>,
    vesta: AccumulatorT<Eq>,
}
#[derive(Clone)]
struct Resume {
    plan: SplitPlan,
    wrapper: Vec<u8>,
    carried: AccumulatorT<Ep>,
    vesta: AccumulatorT<Eq>,
}
#[derive(Clone)]
struct Stage {
    owner: Owner,
    predecessor: Arc<Predecessor>,
    pallas: AccumulatorT<Ep>,
    fold: Vec<u8>,
    resume: Option<Resume>,
    omit_q: Option<usize>,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl Stage {
    fn context(&self) -> &ContextPlan {
        self.owner.source.plan.context()
    }
    fn pallas_cells(
        &self,
        chip: &mut VerifierChip<Ep>,
        r: &mut Region<'_, Fp>,
        claim: &FoldInput<Ep>,
    ) -> Result<FoldInputCells<Ep>, Error> {
        let g = chip.witness_point(r, self.owner.value(Ep::from(*claim.g())))?;
        let challenges = claim
            .challenges()
            .iter()
            .map(|v| self.owner.scalar(chip, r, *v))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        FoldInputCells::from_normalized(chip, r, 16, g, challenges)
    }
    fn vesta_cells(
        &self,
        chip: &mut VerifierChip<Ep>,
        r: &mut Region<'_, Fp>,
        claim: &AccumulatorT<Eq>,
    ) -> Result<VestaClaimCells, Error> {
        let (x, y) = Option::from(claim.g().coordinates()).ok_or(Error::Synthesis)?;
        let coordinates = [
            self.owner.scalar(chip, r, x)?,
            self.owner.scalar(chip, r, y)?,
        ];
        let challenges = chip
            .uint()
            .glue()
            .witnesses(r, &claim.challenges().map(|v| self.owner.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        VestaClaimCells::constrain(chip, r, 16, coordinates, challenges)
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        let Some(resume) = &self.resume else {
            return internal_public(
                stage_digest(self.context(), 0, self.context_digest(), &self.pallas),
                &self.owner.source.part,
            );
        };
        if resume.plan.is_terminal() {
            let mut lineage = self.owner.source.fixture.witness.successor.lineage.to_vec();
            let (x, y) = self.pallas.g().coordinates().unwrap();
            lineage.extend([x, y]);
            for u in self.pallas.challenges() {
                lineage.extend(foreign_limbs(u).map(Fp::from_u128));
            }
            let digest = hash_with_domain(u64::from_le_bytes(*b"kgwomg_1"), &lineage);
            let mut out = vec![digest, Fp::from(16)];
            out.extend(vesta_words(&resume.vesta.as_input()));
            out.extend(vesta_words(&self.predecessor.vesta.as_input()));
            let trivial =
                AccumulatorT::trivial(&common::vesta_params(16), MemoryBudget::DEFAULT).unwrap();
            let words = vesta_words(&trivial.as_input());
            out.extend(&words);
            out.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
            out.extend(&words[..4]);
            assert_eq!(out.len(), 69);
            return vec![out];
        }
        let digest = stage_digest(
            self.context(),
            self.owner.stage,
            self.context_digest(),
            &self.pallas,
        );
        internal_public(digest, &resume.vesta.as_input())
    }
    fn context_digest(&self) -> Fp {
        let source = &self.owner.source;
        let w = &source.fixture.witness;
        let mut words = self.context().schema().to_vec();
        words.extend(w.statement);
        words.extend(w.predecessor.core);
        words.extend(w.predecessor.rest);
        words.extend(w.predecessor.lineage);
        push_pallas(&mut words, &self.predecessor.pallas.as_input());
        words.extend(vesta_words(&self.predecessor.vesta.as_input()));
        words.extend(w.successor.core);
        words.extend(w.successor.rest);
        words.extend(w.successor.lineage);
        for v in source.q_instances.iter().flatten().flatten() {
            words.extend(foreign_limbs(v).map(Fp::from_u128));
        }
        words.extend(object_claims(source).into_iter().flatten());
        hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words)
    }
}
impl Circuit<Fp> for Stage {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            owner: Owner {
                known: false,
                ..self.owner.clone()
            },
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(69);
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
            || "complete genuine Refresh stage",
            |mut r| {
                let o = &self.owner;
                let source = &o.source;
                let w = &source.fixture.witness;
                let (before, previous) = o.state(&mut chip, &mut r, &w.predecessor)?;
                let (after, next) = o.state(&mut chip, &mut r, &w.successor)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut r, &w.statement.map(|v| o.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut r,
                    source.fixture.variant,
                    &fields,
                )?;
                let sigma = o.sigma(&mut chip, &mut bytes, &mut r, &statement)?;
                let objects = if RefreshObjects::quota_root_only(self.context(), o.stage) {
                    let commitment = o
                        .quota_commitment(&mut chip, &mut r)?
                        .ok_or(Error::Synthesis)?;
                    let claims = object_claims(source)
                        .into_iter()
                        .map(|triple| triple.map(|v| o.value(v)))
                        .collect::<Vec<_>>();
                    RefreshObjects::quota_root_claims(
                        &mut chip,
                        &mut r,
                        self.context(),
                        o.stage,
                        &claims,
                        &commitment,
                    )?
                } else {
                    let tapes = source
                        .objects
                        .each_ref()
                        .map(|object| object.bytes.iter().map(|v| o.value(*v)).collect::<Vec<_>>());
                    let mut objects = RefreshObjects::decode(
                        &mut chip,
                        &mut bytes,
                        &mut r,
                        source.fixture.variant,
                        tapes.each_ref().map(Vec::as_slice),
                    )?;
                    if let Some(commitment) = o.quota_commitment(&mut chip, &mut r)? {
                        objects = objects.with_quota_commitment(&mut chip, &mut r, &commitment)?;
                    }
                    objects
                };
                let q_instances = source
                    .q_instances
                    .iter()
                    .map(|columns| {
                        columns
                            .iter()
                            .map(|column| {
                                column
                                    .iter()
                                    .map(|v| o.scalar(&mut chip, &mut r, *v))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, Error>>()?;
                let pp =
                    self.pallas_cells(&mut chip, &mut r, &self.predecessor.pallas.as_input())?;
                let pv = self.vesta_cells(&mut chip, &mut r, &self.predecessor.vesta)?;
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: None,
                    predecessor: Some(ContextPredecessor {
                        state: &before,
                        public: &previous,
                        pallas: &pp,
                        vesta: &pv,
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
                let mut verified = Vec::new();
                let mut signatures = None;
                for &index in self
                    .context()
                    .q_partition(o.stage)
                    .ok_or(Error::Synthesis)?
                {
                    if self.omit_q == Some(index) {
                        continue;
                    }
                    let proof = o.proof(&mut chip, &mut bytes, &mut r, &source.q_proofs[index])?;
                    let q = if index == 0 {
                        verify_sigma(
                            &mut chip,
                            &mut r,
                            self.context().operation(),
                            &q_instances[index],
                            &proof,
                            core::slice::from_ref(&sigma),
                        )?
                        .0
                    } else {
                        let q = verify_q(
                            &mut chip,
                            &mut r,
                            self.context().operation(),
                            index,
                            &q_instances[index],
                            &proof,
                        )?;
                        signatures = Some(bind_signature_q(
                            &mut chip,
                            &mut r,
                            self.context().operation(),
                            index,
                            &source.schemas[index - 1],
                            &q,
                        )?);
                        q
                    };
                    verified.push(q);
                }
                let maps = o.maps(&mut chip, &mut r)?;
                source.plan.constrain_stage(
                    &mut chip,
                    &mut r,
                    o.stage,
                    &objects,
                    &input,
                    RefreshStageWitness {
                        sigma: self
                            .context()
                            .operation_tasks(o.stage)
                            .ok_or(Error::Synthesis)?
                            .contains(&OperationTask::RefreshUpdateAuthorization)
                            .then_some(&sigma),
                        signatures: signatures.as_ref(),
                        blacklist: maps.blacklist.as_ref(),
                        quota: maps.quota.as_ref(),
                    },
                )?;
                let fold = o.proof(&mut chip, &mut bytes, &mut r, &self.fold)?;
                if let Some(resume) = &self.resume {
                    let cp = self.pallas_cells(&mut chip, &mut r, &resume.carried.as_input())?;
                    let cv = self.vesta_cells(&mut chip, &mut r, &resume.vesta)?;
                    let wrapper = o.proof(&mut chip, &mut bytes, &mut r, &resume.wrapper)?;
                    let resumed = resume_context(
                        &mut chip,
                        &mut r,
                        &resume.plan,
                        &input,
                        &cp,
                        &cv,
                        &wrapper,
                        core::slice::from_ref(&sigma),
                    )?;
                    let closed = close_stage(
                        &mut chip,
                        &mut r,
                        &resume.plan,
                        &resumed,
                        None,
                        None,
                        None,
                        &verified,
                        &fold,
                    )?;
                    if resume.plan.is_terminal() {
                        closed.words(&mut chip, &mut r, &next)
                    } else {
                        closed.continuation()?.words(&mut chip, &mut r)
                    }
                } else {
                    let vk = &self.predecessor.key;
                    let iroha_plonk::transcript::TranscriptRepr::Base(repr) = *vk.transcript_repr()
                    else {
                        return Err(Error::Synthesis);
                    };
                    let fixed = vk
                        .fixed_commitments()
                        .iter()
                        .map(|p| o.value(Ep::from(*p)))
                        .collect::<Vec<_>>();
                    let permutation = vk
                        .permutation_commitments()
                        .iter()
                        .map(|p| o.value(Ep::from(*p)))
                        .collect::<Vec<_>>();
                    let key = chip.witness_key(&mut r, o.value(repr), &fixed, &permutation)?;
                    let proof = o.proof(&mut chip, &mut bytes, &mut r, &self.predecessor.proof)?;
                    let pred = verify_predecessor(
                        &mut chip,
                        &mut r,
                        self.context().operation(),
                        &key,
                        &previous,
                        &next,
                        &pp,
                        &pv,
                        &proof,
                    )?;
                    let first = close_first(
                        &mut chip,
                        &mut r,
                        self.context(),
                        &input,
                        Some(&pred),
                        &verified,
                        core::slice::from_ref(&sigma),
                        Some(&fold),
                        &PinnedParams::<Ep>::derive(16).map_err(|_| Error::Synthesis)?,
                    )?;
                    first.words(&mut chip, &mut r)
                }
            },
        )?;
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
fn push_pallas(words: &mut Vec<Fp>, claim: &FoldInput<Ep>) {
    words.push(Fp::from(16));
    let (x, y) = claim.g().coordinates().unwrap();
    words.extend([x, y]);
    for u in claim.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
}
fn vesta_words(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = claim.g().coordinates().unwrap();
    let mut words = Vec::new();
    for v in [x, y] {
        words.extend(foreign_limbs(&v).map(Fp::from_u128));
    }
    words.extend(claim.challenges());
    words
}
fn internal_public(digest: Fp, part: &FoldInput<Eq>) -> Vec<Vec<Fp>> {
    let mut words = vec![digest, Fp::from(u64::from(part.source_k()))];
    words.extend(vesta_words(part));
    let trivial =
        AccumulatorT::<Eq>::trivial(&common::vesta_params(16), MemoryBudget::DEFAULT).unwrap();
    let t = vesta_words(&trivial.as_input());
    words.extend(&t);
    words.extend(&t);
    words.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    words.extend(&t[..4]);
    assert_eq!(words.len(), 69);
    vec![words]
}
fn stage_digest(plan: &ContextPlan, stage: usize, base: Fp, current: &AccumulatorT<Ep>) -> Fp {
    assert!(stage + 1 < plan.stage_count());
    let mut words = vec![
        Fp::ONE,
        plan.schema()[1],
        Fp::from(u64::try_from(stage + 1).unwrap()),
        base,
    ];
    push_pallas(&mut words, &current.as_input());
    hash_with_domain(u64::from_le_bytes(*b"kgwlink1"), &words)
}

/// Actual Refresh terminal A and decided pending claims, without Ω admission.
#[derive(Clone)]
#[allow(dead_code)] // The upcoming common terminal catalog consumes this artifact.
pub(crate) struct AuthenticatedRefresh {
    pub(crate) key: VerifyingKey<Eq>,
    pub(crate) binding: DescriptorBinding,
    pub(crate) proof: Vec<u8>,
    pub(crate) instances: Vec<Fp>,
    pub(crate) opening: FoldInput<Eq>,
    pub(crate) pallas: AccumulatorT<Ep>,
    pub(crate) vesta_part: AccumulatorT<Eq>,
    pub(crate) predecessor_vesta: AccumulatorT<Eq>,
    pub(crate) state: StateWitness,
}
fn rejected(circuit: &Stage, public: &[Vec<Fp>]) -> bool {
    !check_circuit(circuit, 16, public, CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
}
fn prove_stage(
    circuit: &Stage,
    expected: Option<&DescriptorBinding>,
    planned: Option<&PlannedKey<Eq>>,
) -> (ProvingKey<Eq>, ProverOutput<Eq>) {
    let public = circuit.public();
    let (assigned, k) = match synthesize(circuit, 16, Some(&public)) {
        Ok(a) => (a, 16),
        Err(error) => {
            eprintln!(
                "REFRESH_A_CAPACITY variant={:?} stage={} k16_error={error:?}",
                circuit.owner.source.fixture.variant, circuit.owner.stage
            );
            (synthesize(circuit, 18, Some(&public)).unwrap(), 18)
        }
    };
    let rows = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect::<Vec<_>>();
    eprintln!(
        "REFRESH_A variant={:?} stage={} rows={rows:?} production_k16_fit={}",
        circuit.owner.source.fixture.variant,
        circuit.owner.stage,
        k == 16
    );
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let unknown = synthesize(&circuit.without_witnesses(), k, None).unwrap();
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    drop(assigned);
    drop(unknown);
    assert_eq!(k, 16, "hard source capacity cannot be relaxed");
    let mut cfg = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    cfg.compress_selectors = false;
    let params = common::vesta_params(16);
    let key = keygen_pk_v2(&params, circuit, &cfg).unwrap();
    if let Some(expected) = expected {
        assert_eq!(key.binding(), expected);
    }
    if let Some(planned) = planned {
        planned.require(&key);
    }
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, circuit, &public).unwrap(),
        common::recovery(245 + u8::try_from(circuit.owner.stage).unwrap()),
        ProverConfig::default(),
    )
    .unwrap();
    let opening = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(&params, MemoryBudget::DEFAULT).unwrap();
    assert_eq!(proof.proof.len(), 7744);
    eprintln!(
        "REFRESH_A_PROOF variant={:?} stage={} bytes={} all_openings_decided=true",
        circuit.owner.source.fixture.variant,
        circuit.owner.stage,
        proof.proof.len()
    );
    (key, proof)
}

/// Completes every stage against an actual immutable Bootstrap predecessor key.
/// No Load object or publisher-trust assumption enters this chain.
pub(crate) fn refresh_from_bootstrap(
    rooted: &bootstrap_outer::RootedBootstrapOmega,
    variant: Variant,
    adversarial: bool,
) -> AuthenticatedRefresh {
    build_refresh(rooted, variant, adversarial, false)
}

fn prepare_refresh(rooted: &bootstrap_outer::RootedBootstrapOmega, variant: Variant) -> Stage {
    assert_eq!(
        bootstrap_outer::bootstrap_chain::SourceProfile::Tagged { buses: 3 }.range_buses(),
        3
    );
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let (_, certificate, credential) = components::bootstrap_objects::enrollment();
    let fixture =
        refresh_objects::authorized(&rooted.source.state, &certificate, &credential, variant);
    let mut source = components::sources(
        fixture,
        VerifierPlan::new(rooted.binding.clone(), p.clone()).unwrap(),
    );
    let mut tasks = vec![
        vec![OperationTask::RefreshEffects],
        vec![],
        vec![OperationTask::RefreshUpdateAuthorization],
        vec![OperationTask::RefreshCurrentAuthorization],
    ];
    let mut partition = vec![vec![], vec![0], vec![1], vec![2]];
    if variant == Variant::RefreshBlacklist {
        tasks[0].push(OperationTask::RefreshBlacklist);
    }
    if variant == Variant::RefreshQuotaShare {
        // Root hashing must precede long continuation histories. The first
        // stage has room for Effects and the old usage root alongside the hard
        // predecessor; the other roots then retain only exact object proposals.
        tasks = vec![
            vec![
                OperationTask::RefreshEffects,
                OperationTask::RefreshQuotaPreviousRoot,
            ],
            vec![OperationTask::RefreshQuotaWindowRoot],
            vec![OperationTask::RefreshQuotaUsageRoot],
            vec![],
            vec![OperationTask::RefreshUpdateAuthorization],
            vec![OperationTask::RefreshCurrentAuthorization],
            vec![OperationTask::RefreshQuotaMerge],
        ];
        partition = vec![vec![], vec![], vec![], vec![0], vec![1], vec![2], vec![]];
    }
    let context = ContextPlan::with_schedule(
        source.plan.context().operation().clone(),
        partition,
        Some(0),
        RefreshObjects::context_specs(variant).unwrap(),
    )
    .unwrap()
    .with_operation_tasks(tasks)
    .unwrap();
    source.plan = RefreshStagePlan::new(context, refresh_objects::policy()).unwrap();
    let claims = [rooted.source.pallas.as_input(), rooted.opening.clone()];
    let (fold, pallas) =
        create_fold(&p, &claims, Fp::from(244).to_repr(), &FoldConfig::default()).unwrap();
    pallas.decide(&p, MemoryBudget::DEFAULT).unwrap();
    let source = Arc::new(source);
    Stage {
        owner: Owner {
            source: source.clone(),
            stage: 0,
            known: true,
            mutation: 0,
        },
        predecessor: Arc::new(Predecessor {
            key: rooted.key.clone(),
            proof: rooted.proof.clone(),
            pallas: rooted.source.pallas.clone(),
            vesta: rooted.vesta.clone(),
        }),

        pallas: pallas.clone(),
        fold: fold.to_bytes().to_vec(),
        resume: None,
        omit_q: None,
    }
}

// Unknown-source planning retains only exact sequential verifier identities. It
// never produces accepted proofs or checkpoints. Every actual A/W PK must match
// this plan before its proof is generated; descriptors alone are insufficient.
struct PlannedKey<C: iroha_pasta::PastaCurve> {
    binding: DescriptorBinding,
    key: VerifyingKey<C>,
}
impl<C: iroha_pasta::PastaCurve> PlannedKey<C> {
    fn require(&self, key: &ProvingKey<C>) {
        assert_eq!(key.binding(), &self.binding);
        assert_eq!(key.vk().to_bytes(), self.key.to_bytes());
    }
}
struct PlannedKeys {
    a: Vec<PlannedKey<Eq>>,
    w: Vec<PlannedKey<Ep>>,
}
fn preflight_stage_layouts(first: &Stage) -> PlannedKeys {
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let v = common::vesta_params(16);
    let mut a_config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    a_config.compress_selectors = false;
    let mut w_config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
    w_config.compress_selectors = false;
    let trivial_v = AccumulatorT::trivial(&v, MemoryBudget::DEFAULT).unwrap();
    let vclaims: [FoldInput<Eq>; 4] = core::array::from_fn(|_| trivial_v.as_input());
    let (vf, _) = create_fold(
        &v,
        &vclaims,
        Fq::from(199).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    let mut planned = PlannedKeys {
        a: vec![],
        w: vec![],
    };
    let mut current = first.without_witnesses();
    for stage in 0..first.context().stage_count() {
        let (assigned, fits) = match synthesize(&current, 16, None) {
            Ok(a) => (a, true),
            Err(error) => {
                eprintln!("REFRESH_PREFLIGHT_FAILURE stage={stage} k16_error={error:?}");
                (synthesize(&current, 18, None).unwrap(), false)
            }
        };
        let rows = assigned
            .tables
            .advice_assigned()
            .iter()
            .map(|column| column.iter().rposition(|v| *v).map_or(0, |i| i + 1))
            .collect::<Vec<_>>();
        eprintln!(
            "REFRESH_LAYOUT_PREFLIGHT variant={:?} stage={stage} rows={rows:?} production_k16_fit={fits} exact_sequential_verifiers=true unknown_witness_only=true proof_qualification=false",
            first.owner.source.fixture.variant
        );
        drop(assigned);
        assert!(fits, "every exact source must fit before full proving");
        let (binding, key) = keygen_vk_with_binding_v2(&v, &current, &a_config).unwrap();
        planned.a.push(PlannedKey {
            binding: binding.clone(),
            key: key.clone(),
        });
        if stage + 1 == first.context().stage_count() {
            break;
        }
        let length = VerifierPlan::new(binding.clone(), v.clone())
            .unwrap()
            .proof_length();
        let wc = WCircuit::new(
            first.context(),
            stage,
            binding.clone(),
            v.clone(),
            vec![key.kagemusha_digest(&binding).unwrap()],
            OmegaWitness {
                key,
                instances: vec![Fp::ZERO; 69],
                length: u32::try_from(length).unwrap(),
                proof: vec![0; length],
                fold: vf.to_bytes(),
            },
        )
        .unwrap()
        .without_witnesses();
        let (binding, key) = keygen_vk_with_binding_v2(&p, &wc, &w_config).unwrap();
        planned.w.push(PlannedKey {
            binding: binding.clone(),
            key: key.clone(),
        });
        let wrapper_key =
            WKey::from_artifact(first.context(), stage, binding, p.clone(), key).unwrap();
        let next = stage + 1;
        let mut claims = vec![first.pallas.as_input(); 2];
        claims.extend(
            first
                .context()
                .q_partition(next)
                .unwrap()
                .iter()
                .map(|i| first.owner.source.q_openings[*i].clone()),
        );
        let (fold, pallas) =
            create_fold(&p, &claims, Fp::from(198).to_repr(), &FoldConfig::default()).unwrap();
        current = Stage {
            owner: Owner {
                stage: next,
                known: false,
                ..first.owner.clone()
            },
            pallas,
            fold: fold.to_bytes().to_vec(),
            resume: Some(Resume {
                plan: SplitPlan::new(first.context().clone(), next, wrapper_key.clone(), &p)
                    .unwrap(),
                wrapper: vec![0; wrapper_key.verifier().proof_length()],
                carried: first.pallas.clone(),
                vesta: trivial_v.clone(),
            }),
            ..first.clone()
        };
    }
    assert_eq!(planned.a.len(), first.context().stage_count());
    assert_eq!(planned.w.len() + 1, planned.a.len());
    planned
}

fn build_refresh(
    rooted: &bootstrap_outer::RootedBootstrapOmega,
    variant: Variant,
    adversarial: bool,
    native: bool,
) -> AuthenticatedRefresh {
    let first = prepare_refresh(rooted, variant);
    let planned = (variant == Variant::RefreshQuotaShare).then(|| preflight_stage_layouts(&first));
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let v = common::vesta_params(16);
    let source = first.owner.source.clone();
    let pallas = first.pallas.clone();
    let claims = [rooted.source.pallas.as_input(), rooted.opening.clone()];
    let (mut key, mut proof) = prove_stage(&first, None, planned.as_ref().map(|keys| &keys.a[0]));
    let binding = key.binding().clone();
    let mut internal_keys = vec![key.vk().clone()];
    let mut recorded = NativeRecord::default();
    if native {
        recorded.a.push(Arc::new(key.clone()));
        recorded
            .proofs
            .push((proof.proof.clone(), pallas.to_bytes()));
    }
    let mut public = first.public();
    let mut carried = pallas;
    let mut part = source.part.clone();
    if adversarial {
        if variant == Variant::RefreshQuotaShare {
            for mutation in [8, 9] {
                let mut bad = first.clone();
                bad.owner.mutation = mutation;
                assert!(
                    rejected(&bad, &public),
                    "changed initial quota root witness {mutation}"
                );
            }
        }
        let mut bad = first.clone();
        let mut pred = (*bad.predecessor).clone();
        pred.proof[0] ^= 1;
        bad.predecessor = Arc::new(pred);
        assert!(rejected(&bad, &public), "malformed hard predecessor");
        for omitted in 0..claims.len() {
            let kept = claims
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != omitted)
                .map(|(_, c)| c.clone())
                .collect::<Vec<_>>();
            let (fold, _) =
                create_fold(&p, &kept, Fp::from(244).to_repr(), &FoldConfig::default()).unwrap();
            let mut bad = first.clone();
            bad.fold = fold.to_bytes().to_vec();
            assert!(rejected(&bad, &public), "dropped predecessor claim");
        }
    }
    for stage in 1..first.context().stage_count() {
        let own = FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges()).unwrap();
        let trivial = AccumulatorT::trivial(&v, MemoryBudget::DEFAULT)
            .unwrap()
            .as_input();
        let (vfold, vesta) = create_fold(
            &v,
            &[part, own, trivial.clone(), trivial],
            Fq::from(410 + u64::try_from(stage).unwrap()).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        vesta.decide(&v, MemoryBudget::DEFAULT).unwrap();
        let witness = OmegaWitness {
            key: key.vk().clone(),
            instances: public[0].clone(),
            length: u32::try_from(proof.proof.len()).unwrap(),
            proof: proof.proof,
            fold: vfold.to_bytes(),
        };
        let accepted = vec![key.vk().kagemusha_digest(key.binding()).unwrap()];
        assert!(
            WCircuit::new(
                first.context(),
                first.context().stage_count() - 1,
                key.binding().clone(),
                v.clone(),
                accepted.clone(),
                witness.clone()
            )
            .is_err(),
            "terminal source cannot be an intermediate W"
        );
        let wc = WCircuit::new(
            first.context(),
            stage - 1,
            key.binding().clone(),
            v.clone(),
            accepted,
            witness,
        )
        .unwrap();
        let (wkey, wprover) = WKey::keygen(&wc, &p).unwrap();
        if let Some(planned) = &planned {
            planned.w[stage - 1].require(&wprover);
        }
        for wrong in 0..=first.context().stage_count() {
            if wrong != stage {
                assert!(SplitPlan::new(first.context().clone(), wrong, wkey.clone(), &p).is_err());
            }
        }
        let (x, y) = vesta.g().coordinates().unwrap();
        let wp = vec![
            vec![Fq::from_repr(public[0][0].to_repr()).unwrap()],
            vec![x, y],
            vesta
                .challenges()
                .iter()
                .map(|u| Fq::from_repr(u.to_repr()).unwrap())
                .collect(),
        ];
        let wrapper = create_proof_owned_with_claim(
            &p,
            &wprover,
            Witness::from_circuit(&wprover, &wc, &wp).unwrap(),
            common::recovery(220 + u8::try_from(stage).unwrap()),
            ProverConfig::default(),
        )
        .unwrap();
        if native {
            recorded.w.push(Arc::new(wprover.clone()));
            recorded
                .wrappers
                .push((wrapper.proof.clone(), vesta.to_bytes()));
        }
        let opening = accumulate_generator(
            &p,
            wprover.binding(),
            wprover.vk(),
            &wp,
            &wrapper.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        opening.decide(&p, MemoryBudget::DEFAULT).unwrap();
        let indices = first.context().q_partition(stage).unwrap();
        let mut claims = vec![
            carried.as_input(),
            FoldInput::from_opening(*opening.g(), opening.challenges()).unwrap(),
        ];
        claims.extend(indices.iter().map(|i| source.q_openings[*i].clone()));
        let salt = Fp::from(420 + u64::try_from(stage).unwrap()).to_repr();
        let (fold, pallas) = create_fold(&p, &claims, salt, &FoldConfig::default()).unwrap();
        pallas.decide(&p, MemoryBudget::DEFAULT).unwrap();
        let current = Stage {
            owner: Owner {
                stage,
                ..first.owner.clone()
            },
            pallas: pallas.clone(),
            fold: fold.to_bytes().to_vec(),
            resume: Some(Resume {
                plan: SplitPlan::new(first.context().clone(), stage, wkey, &p).unwrap(),
                wrapper: wrapper.proof,
                carried: carried.clone(),
                vesta: vesta.clone(),
            }),
            ..first.clone()
        };
        public = current.public();
        let (next_key, next_proof) = prove_stage(
            &current,
            Some(&binding),
            planned.as_ref().map(|keys| &keys.a[stage]),
        );
        if native {
            recorded.a.push(Arc::new(next_key.clone()));
            recorded
                .proofs
                .push((next_proof.proof.clone(), pallas.to_bytes()));
        }
        if adversarial {
            for omitted in 0..claims.len() {
                let kept = claims
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != omitted)
                    .map(|(_, c)| c.clone())
                    .collect::<Vec<_>>();
                let (fold, _) = create_fold(&p, &kept, salt, &FoldConfig::default()).unwrap();
                let mut bad = current.clone();
                bad.fold = fold.to_bytes().to_vec();
                assert!(
                    rejected(&bad, &public),
                    "dropped stage{stage} claim{omitted}"
                );
            }
            for &index in indices {
                let mut bad = current.clone();
                bad.omit_q = Some(index);
                assert!(rejected(&bad, &public), "dropped Q{index}");
                let mut changed = (*source).clone();
                changed.q_proofs[index][0] ^= 1;
                let mut bad = current.clone();
                bad.owner.source = Arc::new(changed);
                assert!(rejected(&bad, &public), "mutated Q{index}");
            }
            if variant == Variant::RefreshQuotaShare && indices.is_empty() {
                for mutation in [8, 9] {
                    let mut bad = current.clone();
                    bad.owner.mutation = mutation;
                    assert!(
                        rejected(&bad, &public),
                        "changed quota owner witness stage{stage} mutation{mutation}"
                    );
                }
                // Rehash a replacement proposal as well: an owner cannot splice
                // private arrays across the retained W/context boundary even if
                // its particular root does not read the changed array.
                let mut changed = (*source).clone();
                changed.fixture.quota.as_mut().unwrap().used[0] += Fp::ONE;
                let mut bad = current.clone();
                bad.owner.source = Arc::new(changed);
                assert!(
                    rejected(&bad, &bad.public()),
                    "rehashed quota proposal cannot replace earlier context stage{stage}"
                );
            }
            for replace_pallas in [true, false] {
                let mut bad = current.clone();
                let resume = bad.resume.as_mut().unwrap();
                if replace_pallas {
                    resume.carried = AccumulatorT::trivial(&p, MemoryBudget::DEFAULT).unwrap();
                } else {
                    resume.vesta = AccumulatorT::trivial(&v, MemoryBudget::DEFAULT).unwrap();
                }
                assert!(
                    rejected(&bad, &public),
                    "substituted current P/V obligation"
                );
            }
            if indices.contains(&1) || indices.contains(&2) {
                let mut changed = (*source).clone();
                changed.objects[2].bytes[40] ^= 1;
                let mut bad = current.clone();
                bad.owner.source = Arc::new(changed);
                assert!(
                    rejected(&bad, &bad.public()),
                    "changed original receipt with rebound context"
                );
            }
        }
        let terminal = current.resume.as_ref().unwrap().plan.is_terminal();
        if terminal {
            let digest = next_key.vk().kagemusha_digest(next_key.binding()).unwrap();
            let catalog =
                OmegaPlan::new(next_key.binding().clone(), v.clone(), vec![digest]).unwrap();
            assert!(
                catalog
                    .clone()
                    .with_key_catalog(vec![next_key.vk().clone()])
                    .is_ok()
            );
            for internal in &internal_keys {
                assert!(
                    catalog
                        .clone()
                        .with_key_catalog(vec![internal.clone()])
                        .is_err(),
                    "intermediate A cannot be admitted as a terminal"
                );
            }
            eprintln!(
                "REFRESH_COMPLETE variant={variant:?} stages={} hard_predecessor=true actual_originals=5 hard3V2F=true all_q_openings=true full_catalog=false release_qualified=false",
                first.context().stage_count()
            );
            if native {
                recorded.check(rooted, &source, &first);
            }
            return AuthenticatedRefresh {
                key: next_key.vk().clone(),
                binding: next_key.binding().clone(),
                opening: FoldInput::from_opening(
                    *next_proof.opening.g(),
                    next_proof.opening.challenges(),
                )
                .unwrap(),
                proof: next_proof.proof,
                instances: public[0].clone(),
                pallas,
                vesta_part: vesta,
                predecessor_vesta: first.predecessor.vesta.clone(),
                state: source.fixture.witness.successor,
            };
        }
        internal_keys.push(next_key.vk().clone());
        carried = pallas;
        part = vesta.as_input();
        key = next_key;
        proof = next_proof;
    }
    unreachable!("fixed Refresh schedule has one terminal")
}
#[test]
#[ignore = "genuine compact Bootstrap followed by all Credential/Policy/TimeAnchor Q/A/W stages; optimized only"]
fn compact_bootstrap_completes_credential_policy_and_anchor_refresh() {
    let rooted = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    for variant in [
        Variant::RefreshCredential,
        Variant::RefreshSchemePolicy,
        Variant::RefreshTimeAnchor,
    ] {
        refresh_from_bootstrap(&rooted, variant, true);
    }
}
#[test]
#[ignore = "genuine compact Bootstrap and full Blacklist/Quota map owners; diagnostic capacity does not relax k16"]
fn compact_bootstrap_measures_blacklist_and_quota_refresh_capacity() {
    let rooted = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    for variant in [Variant::RefreshBlacklist, Variant::RefreshQuotaShare] {
        refresh_from_bootstrap(&rooted, variant, true);
    }
}

#[test]
#[ignore = "genuine compact Bootstrap plus seven fixed Quota Q/A/W stages and all64 slots; optimized only"]
fn compact_bootstrap_completes_split_quota_refresh() {
    let rooted = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    refresh_from_bootstrap(&rooted, Variant::RefreshQuotaShare, true);
}

/// Actual diagnostic artifacts retained only by the explicit native parity run.
#[derive(Clone)]
struct NativeRefreshOriginal {
    descriptor: Vec<u8>,
    vk: Vec<u8>,
    pk: Vec<u8>,
}
impl NativeRefreshOriginal {
    fn from_key<C: iroha_pasta::PastaCurve>(key: &iroha_plonk::ProvingKey<C>) -> Self {
        Self {
            descriptor: key.binding().encoded().to_vec(),
            vk: key.vk().to_bytes().to_vec(),
            pk: key.artifact_bytes_v2().unwrap(),
        }
    }
    fn borrow(&self) -> NativeRefreshView<'_> {
        NativeRefreshView {
            descriptor: &self.descriptor,
            verifying_key: &self.vk,
            proving_key: &self.pk,
        }
    }
}
// Test storage of original files is separate from the metadata-only producer.
// No original byte slice or PK is retained by a native session or checkpoint.
#[derive(Clone, Copy)]
struct NativeRefreshView<'a> {
    descriptor: &'a [u8],
    verifying_key: &'a [u8],
    proving_key: &'a [u8],
}
impl NativeRefreshView<'_> {
    fn metadata<C: iroha_pasta::PastaCurve>(
        self,
    ) -> Result<
        iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact<C>,
        iroha_kagemusha_proof::a_relation::native::refresh::Error,
    > {
        use iroha_kagemusha_proof::a_relation::native::{artifact::KeyArtifact, refresh::Error};
        let binding = DescriptorBinding::decode_v2(self.descriptor).map_err(|_| Error::Artifact)?;
        let key = VerifyingKey::read(self.verifying_key, &binding).map_err(|_| Error::Artifact)?;
        KeyArtifact::new(binding, key).map_err(|_| Error::Artifact)
    }
}

#[derive(Default)]
struct NativeRecord {
    a: Vec<Arc<iroha_plonk::ProvingKey<Eq>>>,
    w: Vec<Arc<iroha_plonk::ProvingKey<Ep>>>,
    proofs: Vec<(Vec<u8>, [u8; 544])>,
    wrappers: Vec<(Vec<u8>, [u8; 544])>,
}
impl NativeRecord {
    fn check(
        self,
        rooted: &bootstrap_outer::RootedBootstrapOmega,
        source: &components::Sources,
        first: &Stage,
    ) {
        use iroha_kagemusha_proof::a_relation::native::refresh as native;
        let budget = MemoryBudget::DEFAULT;
        let plan = native::Plan::new(
            source.plan.context().operation().clone(),
            refresh_objects::policy(),
            rooted.key.clone(),
            PinnedParams::<Ep>::derive(16).unwrap(),
            common::vesta_params(16),
        )
        .unwrap();
        assert_eq!(plan.context().schema(), source.plan.context().schema());
        native_source_factory_checks::assert_factories(
            plan.context(),
            &PinnedParams::<Ep>::derive(16).unwrap(),
            &common::vesta_params(16),
            &self
                .a
                .iter()
                .map(|key| {
                    iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact::new(
                        key.binding().clone(),
                        key.vk().clone(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>(),
            &self
                .w
                .iter()
                .map(|key| {
                    iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact::new(
                        key.binding().clone(),
                        key.vk().clone(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>(),
            |stage, previous| plan.source_circuit(stage, previous),
            |stage, binding, key| plan.wrapper_source(stage, binding, key),
        );
        let input = native::Inputs {
            state: source.fixture.witness,
            sigma: source.sigma.clone(),
            objects: source.objects.each_ref().map(|o| o.bytes.clone()),
            blacklist: source.fixture.blacklist,
            quota: source.fixture.quota.as_ref().map(|q| native::QuotaInput {
                old: q.old,
                windows: q.windows,
                used: q.used,
                issued: q.issued,
                window_count: q.count,
            }),
            q: core::array::from_fn(|i| native::QInput {
                proof: source.q_proofs[i].clone(),
                instances: source.q_instances[i].clone(),
            }),
            predecessor: native::PredecessorInput {
                proof: rooted.proof.clone(),
                pallas: rooted.source.pallas.to_bytes(),
                vesta: rooted.vesta.to_bytes(),
            },
        };
        let prepared = plan.prepare(input.clone(), budget).unwrap();
        let (candidate, public) = prepared
            .first_circuit(Fp::from(244), &FoldConfig::default())
            .unwrap();
        assert_eq!(public, first.public()[0]);
        let expected = synthesize(first, 16, Some(&first.public())).unwrap();
        let actual = synthesize(&candidate, 16, Some(std::slice::from_ref(&public))).unwrap();
        let unknown = synthesize(&candidate.without_witnesses(), 16, None).unwrap();
        assert_eq!(expected.tables.fixed(), actual.tables.fixed());
        assert_eq!(expected.tables.permutation(), actual.tables.permutation());
        assert_eq!(
            expected.tables.advice_assigned(),
            actual.tables.advice_assigned()
        );
        assert_eq!(actual.tables.fixed(), unknown.tables.fixed());
        assert_eq!(actual.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            actual.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        drop((expected, actual, unknown));
        // Mount only exact installed originals. The importer has no witness or
        // Prepared argument and reconstructs every A/W source from fixed metadata.
        let originals_a = self
            .a
            .iter()
            .map(|key| NativeRefreshOriginal::from_key(key.as_ref()))
            .collect::<Vec<_>>();
        let originals_w = self
            .w
            .iter()
            .map(|key| NativeRefreshOriginal::from_key(key.as_ref()))
            .collect::<Vec<_>>();
        drop((self.a, self.w));
        let a = originals_a
            .iter()
            .map(NativeRefreshOriginal::borrow)
            .collect::<Vec<_>>();
        let w = originals_w
            .iter()
            .map(NativeRefreshOriginal::borrow)
            .collect::<Vec<_>>();
        let read = iroha_plonk::keys::pk::artifact::ReadConfig {
            maximum_bytes: originals_a
                .iter()
                .chain(&originals_w)
                .map(|o| o.pk.len())
                .max()
                .unwrap(),
            maximum_rows: 1 << 16,
            coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
            msm_budget: budget,
        };
        let install =
            |plan: native::Plan, a: &[NativeRefreshView<'_>], w: &[NativeRefreshView<'_>]| {
                native::Prover::from_artifacts(
                    plan,
                    a.iter()
                        .map(|v| v.metadata())
                        .collect::<Result<Vec<_>, _>>()?,
                    w.iter()
                        .map(|v| v.metadata())
                        .collect::<Result<Vec<_>, _>>()?,
                )
            };
        let check_originals = |plan: native::Plan,
                               a: &[NativeRefreshView<'_>],
                               w: &[NativeRefreshView<'_>]|
         -> Result<(), native::Error> {
            let prover = install(plan, a, w)?;
            for (stage, source) in a.iter().enumerate() {
                drop(prover.import_a(stage, source.proving_key, read)?);
                if let Some(source) = w.get(stage) {
                    drop(prover.import_w(stage, source.proving_key, read)?);
                }
            }
            Ok(())
        };
        assert!(install(plan.clone(), &a[..a.len() - 1], &w).is_err());
        assert!(install(plan.clone(), &a, &w[..w.len() - 1]).is_err());
        for mutation in 0..6 {
            let mut bad_a = a.clone();
            let mut bad_w = w.clone();
            match mutation {
                0 => bad_a.swap(0, 1),
                1 => bad_w.swap(0, 1),
                2 => bad_a[0].verifying_key = a[1].verifying_key,
                3 => bad_w[0].verifying_key = w[1].verifying_key,
                4 => bad_a[0].descriptor = w[0].descriptor,
                _ => bad_a[0].proving_key = &a[0].proving_key[..a[0].proving_key.len() - 1],
            }
            assert!(
                check_originals(plan.clone(), &bad_a, &bad_w).is_err(),
                "original Refresh mutation {mutation}"
            );
        }
        let mut changed_pk = originals_a[0].pk.clone();
        changed_pk[44 + originals_a[0].vk.len()] ^= 1;
        let mut bad_a = a.clone();
        bad_a[0].proving_key = &changed_pk;
        assert!(check_originals(plan.clone(), &bad_a, &w).is_err());
        drop(bad_a);
        drop(changed_pk);
        let prover = install(plan, &a, &w).unwrap();
        assert!(prover.import_a(a.len(), a[0].proving_key, read).is_err());
        assert!(prover.import_w(w.len(), w[0].proving_key, read).is_err());
        assert!(
            prover
                .import_a(
                    0,
                    a[0].proving_key,
                    iroha_plonk::keys::pk::artifact::ReadConfig {
                        maximum_bytes: 0,
                        ..read
                    }
                )
                .is_err()
        );
        assert!(
            prover
                .import_w(
                    0,
                    w[0].proving_key,
                    iroha_plonk::keys::pk::artifact::ReadConfig {
                        maximum_rows: (1 << 16) - 1,
                        ..read
                    }
                )
                .is_err()
        );
        assert_eq!(prover.descriptors().len(), self.proofs.len() * 2 - 1);
        let layouts = prover.checkpoint_layouts().unwrap();
        assert_eq!(layouts.len(), self.proofs.len() * 2 - 1);
        let mut changed = input.clone();
        changed.q[0].proof[0] ^= 1;
        assert!(prover.prepare(changed, budget).is_err());
        let session = prover.prepare(input, budget).unwrap();
        let fold = FoldConfig::default();
        let foreign_seal = prover.import_a(1, a[1].proving_key, read).unwrap();
        let foreign = prover.bind_a(1, &foreign_seal, None).unwrap();
        assert!(matches!(
            session.first(
                &foreign,
                Fp::from(244),
                &fold,
                common::recovery(245),
                ProverConfig::default()
            ),
            Err(native::Error::Artifact)
        ));
        drop(foreign_seal);
        let key_seal = prover.import_a(0, a[0].proving_key, read).unwrap();
        let key = prover.bind_a(0, &key_seal, None).unwrap();
        let mut checkpoint = session
            .first(
                &key,
                Fp::from(244),
                &fold,
                common::recovery(245),
                ProverConfig::default(),
            )
            .unwrap();
        drop(key_seal);
        assert_eq!(checkpoint.proof(), self.proofs[0].0);
        assert_eq!(checkpoint.pallas_bytes(), self.proofs[0].1);
        assert!(session.terminal(&checkpoint, budget).is_err());
        let mut bad = self.proofs[0].0.clone();
        bad[0] ^= 1;
        assert!(
            session
                .restore_first(bad, &self.proofs[0].1, budget)
                .is_err()
        );
        checkpoint = session
            .restore_first(self.proofs[0].0.clone(), &self.proofs[0].1, budget)
            .unwrap();
        let first_payload = session.encode_a_checkpoint(&checkpoint, budget).unwrap();
        assert_eq!(first_payload.len(), layouts[0].payload_bytes());
        assert!(
            session
                .restore_first_checkpoint(&first_payload[..first_payload.len() - 1], budget)
                .is_err()
        );
        let mut bad_payload = first_payload.clone();
        *bad_payload.last_mut().unwrap() ^= 1;
        assert!(
            session
                .restore_first_checkpoint(&bad_payload, budget)
                .is_err()
        );
        checkpoint = session
            .restore_first_checkpoint(&first_payload, budget)
            .unwrap();
        assert_eq!(checkpoint.proof(), self.proofs[0].0);
        for stage in 1..self.proofs.len() {
            let salt = u64::try_from(stage).unwrap();
            if stage == 1 {
                let foreign_seal = prover.import_w(1, w[1].proving_key, read).unwrap();
                let foreign = prover.bind_w(1, &foreign_seal, None).unwrap();
                assert!(matches!(
                    session.wrapper(
                        &checkpoint,
                        &foreign,
                        Fq::from(410 + salt),
                        &fold,
                        common::recovery(221),
                        ProverConfig::default()
                    ),
                    Err(native::Error::Artifact)
                ));
                drop(foreign_seal);
            }
            let key_seal = prover
                .import_w(stage - 1, w[stage - 1].proving_key, read)
                .unwrap();
            let key = prover.bind_w(stage - 1, &key_seal, None).unwrap();
            let wrapper = session
                .wrapper(
                    &checkpoint,
                    &key,
                    Fq::from(410 + salt),
                    &fold,
                    common::recovery(220 + u8::try_from(stage).unwrap()),
                    ProverConfig::default(),
                )
                .unwrap();
            drop(key_seal);
            assert_eq!(wrapper.proof(), self.wrappers[stage - 1].0);
            assert_eq!(wrapper.vesta_bytes(), self.wrappers[stage - 1].1);
            let wrapper = session
                .restore_wrapper(
                    &checkpoint,
                    self.wrappers[stage - 1].0.clone(),
                    &self.wrappers[stage - 1].1,
                    budget,
                )
                .unwrap();
            let payload = session.encode_wrapper_checkpoint(&wrapper, budget).unwrap();
            assert_eq!(payload.len(), layouts[2 * stage - 1].payload_bytes());
            assert!(session.restore_first_checkpoint(&payload, budget).is_err());
            let wrapper = session
                .restore_wrapper_checkpoint(&checkpoint, &payload, budget)
                .unwrap();
            assert_eq!(wrapper.proof(), self.wrappers[stage - 1].0);
            assert!(
                session
                    .restore_a_checkpoint(&wrapper, &first_payload, budget)
                    .is_err()
            );
            if stage == 1 {
                let foreign_seal = prover.import_a(0, a[0].proving_key, read).unwrap();
                let foreign = prover.bind_a(0, &foreign_seal, None).unwrap();
                assert!(matches!(
                    session.advance(
                        &wrapper,
                        &foreign,
                        Fp::from(420 + salt),
                        &fold,
                        common::recovery(246),
                        ProverConfig::default()
                    ),
                    Err(native::Error::Artifact)
                ));
                drop(foreign_seal);
            }
            let key_seal = prover.import_a(stage, a[stage].proving_key, read).unwrap();
            let key = prover.bind_a(stage, &key_seal, None).unwrap();
            let next = session
                .advance(
                    &wrapper,
                    &key,
                    Fp::from(420 + salt),
                    &fold,
                    common::recovery(245 + u8::try_from(stage).unwrap()),
                    ProverConfig::default(),
                )
                .unwrap();
            drop(key_seal);
            assert_eq!(next.proof(), self.proofs[stage].0);
            assert_eq!(next.pallas_bytes(), self.proofs[stage].1);
            let mut bad = self.proofs[stage].0.clone();
            bad[0] ^= 1;
            assert!(
                session
                    .restore_a(&wrapper, bad, &self.proofs[stage].1, budget)
                    .is_err()
            );
            checkpoint = session
                .restore_a(
                    &wrapper,
                    self.proofs[stage].0.clone(),
                    &self.proofs[stage].1,
                    budget,
                )
                .unwrap();
            let payload = session.encode_a_checkpoint(&checkpoint, budget).unwrap();
            assert_eq!(payload.len(), layouts[2 * stage].payload_bytes());
            let mut bad_payload = payload.clone();
            *bad_payload.last_mut().unwrap() ^= 1;
            assert!(
                session
                    .restore_a_checkpoint(&wrapper, &bad_payload, budget)
                    .is_err()
            );
            checkpoint = session
                .restore_a_checkpoint(&wrapper, &payload, budget)
                .unwrap();
            assert_eq!(checkpoint.proof(), self.proofs[stage].0);
        }
        let terminal = session.terminal(&checkpoint, budget).unwrap();
        assert_eq!(terminal.proof, self.proofs.last().unwrap().0);
        let key_seal = prover.import_w(0, w[0].proving_key, read).unwrap();
        let key = prover.bind_w(0, &key_seal, None).unwrap();
        assert!(
            session
                .wrapper(
                    &checkpoint,
                    &key,
                    Fq::ONE,
                    &fold,
                    common::recovery(200),
                    ProverConfig::default()
                )
                .is_err()
        );
        eprintln!(
            "NATIVE_REFRESH_PARITY variant={:?} stages={} exact_original_keys_and_proofs=true original_pk_source_import=true borrowed_stage_PK=true metadata_only_producer=true checkpoints_restored=true canonical_payloads_restored=true full_catalog=false",
            source.fixture.variant,
            self.proofs.len()
        );
    }
}

#[test]
#[ignore = "genuine Credential source plus installed native A/W proving and exact original checkpoints; optimized only"]
fn installed_native_credential_refresh_matches_genuine_relation_and_checkpoints() {
    let rooted = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    build_refresh(&rooted, Variant::RefreshCredential, false, true);
}

#[test]
#[ignore = "genuine seven-stage Quota source and installed native exact-proof/checkpoint parity; optimized only"]
fn installed_native_quota_refresh_matches_genuine_relation_and_checkpoints() {
    let rooted = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    build_refresh(&rooted, Variant::RefreshQuotaShare, true, true);
}

#[test]
#[ignore = "actual Bootstrap and Q sources followed by all seven unknown-witness source layouts; no Refresh proofs"]
fn compact_bootstrap_preflights_split_quota_refresh() {
    let rooted = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    preflight_stage_layouts(&prepare_refresh(&rooted, Variant::RefreshQuotaShare));
}

#[test]
#[ignore = "genuine Policy, Anchor and Blacklist installed native A/W exact-proof/checkpoint parity; optimized only"]
fn installed_native_policy_anchor_blacklist_match_genuine_relations_and_checkpoints() {
    let rooted = bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    for variant in [
        Variant::RefreshSchemePolicy,
        Variant::RefreshTimeAnchor,
        Variant::RefreshBlacklist,
    ] {
        build_refresh(&rooted, variant, false, true);
    }
}
