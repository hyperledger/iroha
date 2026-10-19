//! Genuine lean Unload/Retiring: one terminal A proves the transition beside the hard
//! predecessor and authenticates the own receipt under the carried payment key (no own
//! sigma verifier, no W, no credential or certificate re-check). The two-terminal
//! predecessor catalog is a component scope, not the complete release catalog. Every
//! source proof, pending claim and operation task is real.
#![allow(clippy::duplicate_mod)]
#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
/// Genuine immutable Bootstrap/Load catalog and its recursive fixtures.
#[path = "compact_catalog.rs"]
pub mod catalog;
mod common;
#[path = "common/load_objects.rs"]
#[allow(dead_code)]
mod load_objects;
#[path = "a_consuming_recursive/native_load_tests.rs"]
mod native_load_tests;
use catalog::{LoadFixture, send_chain::load_outer};
use load_outer::load_chain::bootstrap_outer::bootstrap_chain::SourceProfile;
#[path = "common/unload_objects.rs"]
mod unload_objects;
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::{
        AProofPlan, LineagePublicCells, ProofMessageCells, QProofPlan, VestaClaimCells,
        bind_signature_q,
        context::{ContextInputs, ContextPlan, ContextPredecessor, ContextState},
        schedule::OperationTask,
        split::close_single,
        unload::{UnloadObjects, UnloadStagePlan, UnloadStageWitness},
        verify_predecessor, verify_q,
    },
    admin_sigma::{ConsumingWitness, RetiringCircuit, StateWitness, UnloadCircuit},
    operation_relation::{map_effects::InsertCells, state::StateCells, statement::StatementCells},
    tree::IndexedInsert,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig, VerifyingKey, Witness,
    check::{CheckMode, check},
    create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    UintChip,
    bytes::{
        element::le_message_segments,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    imt::{LeafCells, OpeningCells, PathCells},
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    create_fold,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};
use std::sync::Arc;

#[derive(Clone)]
struct Predecessor {
    key: VerifyingKey<Ep>,
    program: VerifierPlan<Ep>,
    proof: Vec<u8>,
    pallas: AccumulatorT<Ep>,
    opening: FoldInput<Ep>,
    vesta: AccumulatorT<Eq>,
}
/// Exact authenticated predecessor projection, independent of its prior operation.
/// This copies no witness into a proof and never creates a loaded balance.
struct Head<'a> {
    state: StateWitness,
    load_receipt: Option<&'a [u8; 282]>,
    binding: &'a iroha_plonk::DescriptorBinding,
    key: &'a VerifyingKey<Ep>,
    proof: &'a [u8],
    pallas: &'a AccumulatorT<Ep>,
    vesta: &'a AccumulatorT<Eq>,
    opening: &'a FoldInput<Ep>,
}
impl<'a> Head<'a> {
    fn loaded(artifact: &'a load_outer::DiagnosticLoadOmega) -> Self {
        Self {
            state: artifact.source.state,
            load_receipt: Some(&artifact.source.receipt),
            binding: &artifact.binding,
            key: &artifact.key,
            proof: &artifact.proof,
            pallas: &artifact.source.pallas,
            vesta: &artifact.vesta,
            opening: &artifact.opening,
        }
    }
}

#[derive(Clone)]
struct Sources {
    maps: Maps,
    /// The own receipt, the only signed object Λ consumes.
    objects: [bootstrap_objects::Signed; 1],
    variant: Variant,
    plan: AProofPlan,
    q_instances: Vec<Vec<Vec<Fq>>>,
    q_proofs: Vec<Vec<u8>>,
    q_openings: Vec<FoldInput<Ep>>,
    signature_schema: iroha_kagemusha_proof::q_signature::QSignaturePlan,
    part: FoldInput<Eq>,
    predecessor: Predecessor,
    params: PinnedParams<Ep>,
}
fn lineage_bytes(
    f: &[Fp; 18],
    proof: &[u8],
    p: &AccumulatorT<Ep>,
    v: &AccumulatorT<Eq>,
) -> Vec<u8> {
    let mut out = 1u16.to_le_bytes().to_vec();
    for i in [1, 2, 3, 4] {
        out.extend(&f[i].to_repr()[..16]);
    }
    out.extend(f[5].to_repr());
    for i in [6, 7] {
        out.extend(&f[i].to_repr()[..16]);
    }
    out.extend(f[8].to_repr());
    out.push(4);
    for i in [10, 9, 12, 11] {
        out.extend(f[i].to_repr()[..16].iter().rev());
    }
    out.extend(&f[13].to_repr()[..13]);
    out.extend(&f[14].to_repr()[..16]);
    out.extend(f[15].to_repr());
    out.extend(f[16].to_repr());
    assert_eq!(out.len(), 320);
    out.extend(proof);
    out.extend(p.to_bytes());
    out.extend(v.to_bytes());
    out
}
#[derive(Clone)]
struct Maps {
    witness: ConsumingWitness,
    recovery: Option<IndexedInsert<Fp>>,
    known: bool,
}
impl Maps {
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    pub(crate) fn state(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        witness: &StateWitness,
    ) -> Result<(StateCells, LineagePublicCells), Error> {
        let core = chip
            .uint()
            .glue()
            .witnesses(region, &witness.core.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let rest = chip
            .uint()
            .glue()
            .witnesses(region, &witness.rest.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let state = StateCells::constrain_with_verifier(chip, region, &core, &rest)?;
        let public = chip
            .uint()
            .glue()
            .witnesses(region, &witness.lineage.map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let public = LineagePublicCells::constrain(&mut chip.uint(), region, &public)?;
        Ok((state, public))
    }
    pub(crate) fn insertion(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<InsertCells, Error> {
        let insertion = self.recovery.as_ref().ok_or(Error::Synthesis)?;
        let leaf = insertion.leaf;
        let words = uint
            .glue()
            .witnesses(
                region,
                &[leaf.key, leaf.value, leaf.next_key].map(|v| self.value(v)),
            )?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let leaf = LeafCells::from_words(words);
        let mut paths = Vec::new();
        for (index, siblings) in [
            (insertion.leaf_slot, insertion.leaf_siblings),
            (insertion.slot, insertion.slot_siblings),
        ] {
            let index = uint
                .glue()
                .witness(region, self.value(Fp::from(u64::from(index))))?;
            let siblings = uint
                .glue()
                .witnesses(region, &siblings.map(|v| self.value(v)))?
                .try_into()
                .map_err(|_| Error::Synthesis)?;
            paths.push(PathCells::from_words(uint, region, &index, siblings)?);
        }
        let [low, slot] = paths.try_into().map_err(|_| Error::Synthesis)?;
        Ok(InsertCells {
            low: OpeningCells { leaf, path: low },
            slot,
        })
    }
}
fn leaf<C: Circuit<Fp>>(circuit: &C, public: &[Vec<Fp>]) -> (Vec<u8>, iroha_plonk::ProvingKey<Eq>) {
    let params = common::vesta_params(12);
    let key = keygen_pk_v2(
        &params,
        circuit,
        &KeygenConfigV2::pipa_r(UnloadCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, circuit, public).unwrap(),
        common::fresh_randomness(),
        ProverConfig::default(),
    )
    .unwrap();
    let opening = accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        public,
        &proof.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    opening.decide(&params, MemoryBudget::DEFAULT).unwrap();
    (proof.proof, key)
}
fn sources(artifact: &Head<'_>, retiring: bool) -> Sources {
    let variant = if retiring {
        Variant::Retiring
    } else {
        Variant::Unload
    };
    assert_eq!(
        artifact.state.lineage[17],
        artifact.key.kagemusha_digest(artifact.binding).unwrap()
    );
    let (witness, recovery) =
        unload_objects::transition(&artifact.state, artifact.load_receipt, retiring);
    let public = [vec![hash_with_domain(
        iroha_plonk_gadgets::statement::STATEMENT_DOMAIN,
        &witness.statement,
    )]];
    // The ledger still verifies sigma natively; Λ proves the transition directly,
    // so sigma enters only the receipt's proof digest.
    let (sigma, _) = if retiring {
        leaf(&RetiringCircuit::new(&witness), &public)
    } else {
        leaf(&UnloadCircuit::new(&witness), &public)
    };
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let vparams = common::vesta_params(16);
    // No own sigma verifier and no W: the part slot is the pinned trivial claim.
    let part = AccumulatorT::<Eq>::trivial(&vparams, MemoryBudget::DEFAULT)
        .unwrap()
        .as_input();
    let omega = lineage_bytes(
        &witness.predecessor.lineage,
        artifact.proof,
        artifact.pallas,
        artifact.vesta,
    );
    // The credential is carried by continuity from the predecessor lineage.
    let (_, _, credential) = bootstrap_objects::enrollment();
    assert_eq!(witness.predecessor.core[7], credential.digest());
    let receipt = unload_objects::receipt(&witness, &omega, &sigma);
    let (signature, instances) = load_objects::own_signature(receipt.signature);
    let key = keygen_pk_v2(
        &params,
        &signature,
        &KeygenConfigV2::pipa_r(
            iroha_kagemusha_proof::q_signature::QSignaturePlan::instance_types().to_vec(),
        ),
    )
    .unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &signature, &instances).unwrap(),
        common::fresh_randomness(),
        ProverConfig::default(),
    )
    .unwrap();
    proof
        .opening
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
    let signature_q = QProofPlan::new(
        VerifierPlan::new(key.binding().clone(), params.clone()).unwrap(),
        key.vk().clone(),
    )
    .unwrap();
    let predecessor = Predecessor {
        key: artifact.key.clone(),
        program: VerifierPlan::new(artifact.binding.clone(), params.clone()).unwrap(),
        proof: artifact.proof.to_vec(),
        pallas: artifact.pallas.clone(),
        opening: artifact.opening.clone(),
        vesta: artifact.vesta.clone(),
    };
    let plan = AProofPlan::inline(
        variant,
        vec![signature_q],
        Some(predecessor.program.clone()),
        &params,
    )
    .unwrap();
    Sources {
        maps: Maps {
            witness,
            recovery,
            known: true,
        },
        objects: [receipt],
        variant,
        plan,
        q_instances: vec![instances.to_vec()],
        q_proofs: vec![proof.proof],
        q_openings: vec![
            FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges()).unwrap(),
        ],
        signature_schema: signature.plan().clone(),
        part,
        predecessor,
        params,
    }
}
#[derive(Clone)]
struct Single {
    source: Arc<Sources>,
    profile: SourceProfile,
    plan: ContextPlan,
    pallas: AccumulatorT<Ep>,
    fold: iroha_kagemusha_proof::private_fold::PrivateFoldBytes,
    known: bool,
    // Adversarial control only: skip verifying the own receipt Q0 in place.
    omit_q: bool,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl Single {
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn scalar(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        v: Fq,
    ) -> Result<ScalarCells<Ep>, Error> {
        let [lo, hi] = foreign_limbs(&v);
        let lo = chip.uint().assign::<128>(region, self.value(lo))?;
        let hi = chip.uint().assign::<127>(region, self.value(hi))?;
        ScalarCells::from_limbs(&mut chip.uint(), region, &lo, &hi)
    }
    fn pallas(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: &FoldInput<Ep>,
    ) -> Result<FoldInputCells<Ep>, Error> {
        let g = chip.witness_generator(region, self.value(Ep::from(*input.g())))?;
        let challenges = input
            .challenges()
            .iter()
            .map(|v| self.scalar(chip, region, *v))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        FoldInputCells::from_normalized(chip, region, 16, g, challenges)
    }
    fn vesta(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        input: &AccumulatorT<Eq>,
    ) -> Result<VestaClaimCells, Error> {
        let (x, y) = iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Eq>(input.g());
        let coordinates = [self.scalar(chip, region, x)?, self.scalar(chip, region, y)?];
        let challenges = chip
            .uint()
            .glue()
            .witnesses(region, &input.challenges().map(|v| self.value(v)))?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        VestaClaimCells::constrain(chip, region, 16, coordinates, challenges)
    }
    fn carrier(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        body: &[u8],
    ) -> Result<ProofMessageCells, Error> {
        let length = u32::try_from(body.len()).map_err(|_| Error::BoundsFailure)?;
        let source = length
            .to_le_bytes()
            .into_iter()
            .chain(body.iter().copied())
            .map(|v| self.value(v))
            .collect::<Vec<_>>();
        let mut segments = vec![SegmentSpec::little(0, 4)];
        segments.extend(le_message_segments(4, body.len() / 32));
        let run = bytes.run(
            region,
            &source,
            &source
                .chunks(31)
                .map(<[Value<u8>]>::len)
                .collect::<Vec<_>>(),
            &segments,
        )?;
        ProofMessageCells::from_run(chip, region, &run, 0, body.len())
    }
}
impl Single {
    fn objects(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
    ) -> Result<UnloadObjects, Error> {
        let sources = self
            .source
            .objects
            .each_ref()
            .map(|o| o.bytes.iter().map(|v| self.value(*v)).collect::<Vec<_>>());
        UnloadObjects::decode(chip, bytes, region, sources.each_ref().map(Vec::as_slice))
    }
}

impl Circuit<Fp> for Single {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = SourceProfile;
    fn params(&self) -> SourceProfile {
        self.profile
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Self::configure_with_params(meta, SourceProfile::Generic)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, profile: SourceProfile) -> Config {
        let verifier = profile.configure(meta);
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
            || "genuine consuming terminal relation",
            |mut region| {
                let mut maps = self.source.maps.clone();
                maps.known = self.known;
                let (old, pred_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.predecessor)?;
                let (new, next_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.successor)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &maps.witness.statement.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    self.source.variant,
                    &fields,
                )?;
                let objects = self.objects(&mut chip, &mut bytes, &mut region)?;
                let context_objects = objects.context();
                let q_instances = self
                    .source
                    .q_instances
                    .iter()
                    .map(|cols| {
                        cols.iter()
                            .map(|column| {
                                column
                                    .iter()
                                    .map(|v| self.scalar(&mut chip, &mut region, *v))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, _>>()?;
                let pp = self.pallas(
                    &mut chip,
                    &mut region,
                    &self.source.predecessor.pallas.as_input(),
                )?;
                let pv = self.vesta(&mut chip, &mut region, &self.source.predecessor.vesta)?;
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: None,
                    predecessor: Some(ContextPredecessor {
                        state: &old,
                        public: &pred_public,
                        pallas: &pp,
                        vesta: &pv,
                    }),
                    successor: ContextState {
                        state: &new,
                        public: &next_public,
                    },
                    incoming: None,
                    q_instances: &q_instances,
                    objects: context_objects,
                    modes: &[],
                    pallas_corrections: &[],
                    vesta_corrections: &[],
                    receive_results: None,
                };
                let vk = &self.source.predecessor.key;
                let iroha_plonk::transcript::TranscriptRepr::Base(repr) = *vk.transcript_repr()
                else {
                    return Err(Error::Synthesis);
                };
                let fixed = vk
                    .fixed_commitments()
                    .iter()
                    .map(|p| self.value(Ep::from(*p)))
                    .collect::<Vec<_>>();
                let permutation = vk
                    .permutation_commitments()
                    .iter()
                    .map(|p| self.value(Ep::from(*p)))
                    .collect::<Vec<_>>();
                let key = chip.witness_key(&mut region, self.value(repr), &fixed, &permutation)?;
                let proof = self.carrier(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    &self.source.predecessor.proof,
                )?;
                let pred = verify_predecessor(
                    &mut chip,
                    &mut region,
                    self.plan.operation(),
                    &key,
                    &pred_public,
                    &next_public,
                    &pp,
                    &pv,
                    &proof,
                )?;
                // The one stage proves the transition beside the hard predecessor and
                // verifies the own receipt Q0 in place; its hard slot authorizes the
                // receipt under the carried payment key.
                let tasks = self.plan.operation_tasks(0).ok_or(Error::Synthesis)?;
                let recovery = if tasks.contains(&OperationTask::UnloadRecovery) {
                    Some(maps.insertion(&mut chip.uint(), &mut region)?)
                } else {
                    None
                };
                assert_eq!(self.plan.q_partition(0), Some([0_usize].as_slice()));
                let mut verified = Vec::new();
                let mut slots = None;
                if !self.omit_q {
                    let proof =
                        self.carrier(&mut chip, &mut bytes, &mut region, &self.source.q_proofs[0])?;
                    let q = verify_q(
                        &mut chip,
                        &mut region,
                        self.plan.operation(),
                        0,
                        &q_instances[0],
                        &proof,
                    )?;
                    let bound = bind_signature_q(
                        &mut chip,
                        &mut region,
                        self.plan.operation(),
                        0,
                        &self.source.signature_schema,
                        &q,
                    )?;
                    verified.push(bound.verified().clone());
                    slots = Some(bound);
                }
                UnloadStagePlan::new(self.plan.clone(), load_objects::policy())?.constrain_stage(
                    &mut chip,
                    &mut region,
                    0,
                    &objects,
                    &input,
                    UnloadStageWitness {
                        recovery: recovery.as_ref(),
                        signatures: slots.as_ref(),
                    },
                )?;
                let fold = self.carrier(&mut chip, &mut bytes, &mut region, &self.fold)?;
                close_single(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    &input,
                    &pred,
                    &verified,
                    &fold,
                    &self.source.params,
                    &next_public,
                )
            },
        )?;
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
/// The exact final frame `close_single` emits: `D_A` over the successor lineage and the
/// folded Pallas claim, the pinned trivial part (no own sigma verifier and no W), the
/// predecessor Vesta claim and the absent incoming slot with its Trivial mode.
fn terminal_public(single: &Single) -> Vec<Vec<Fp>> {
    let mut lineage = single.source.maps.witness.successor.lineage.to_vec();
    let (x, y) =
        iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Ep>(single.pallas.g());
    lineage.extend([x, y]);
    for u in single.pallas.challenges() {
        lineage.extend(foreign_limbs(u).map(Fp::from_u128));
    }
    let digest = hash_with_domain(u64::from_le_bytes(*b"kgwomg_1"), &lineage);
    let mut out = vec![digest, Fp::from(16)];
    out.extend(vesta_words(&single.source.part));
    out.extend(vesta_words(&single.source.predecessor.vesta.as_input()));
    let trivial = AccumulatorT::trivial(&common::vesta_params(16), MemoryBudget::DEFAULT).unwrap();
    let words = vesta_words(&trivial.as_input());
    out.extend(&words);
    out.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    out.extend(&words[..4]);
    assert_eq!(out.len(), 69);
    vec![out]
}
/// Genuine authenticated Unload/Retiring terminal artifacts for outer/next-operation tests.
/// The supplied predecessor's catalog/profile provenance is retained unchanged;
/// this fixture does not declare the resulting lineage admitted by a final catalog.
/// The frame's part slot is the pinned trivial claim, so no part obligation is carried.
#[derive(Clone)]
#[allow(dead_code)] // Outer and next-operation tests consume all carried artifacts.
pub(crate) struct AuthenticatedConsuming {
    pub(crate) key: VerifyingKey<Eq>,
    pub(crate) binding: iroha_plonk::DescriptorBinding,
    pub(crate) proof: Vec<u8>,
    pub(crate) instances: Vec<Fp>,
    pub(crate) opening: FoldInput<Eq>,
    pub(crate) pallas: AccumulatorT<Ep>,
    pub(crate) predecessor_vesta: AccumulatorT<Eq>,
    pub(crate) state: iroha_kagemusha_proof::admin_sigma::StateWitness,
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}
fn proof_identity(bytes: &[u8]) -> Fp {
    let mut framed = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
    framed.extend(bytes);
    let words = framed
        .chunks(31)
        .map(|chunk| {
            let mut repr = [0; 32];
            repr[..chunk.len()].copy_from_slice(chunk);
            Fp::from_repr(repr).unwrap()
        })
        .collect::<Vec<_>>();
    hash_with_domain(u64::from_le_bytes(*b"kgwtstp1"), &words)
}
fn artifact_diagnostics(
    stage: usize,
    key: &iroha_plonk::ProvingKey<Eq>,
    proof: &[u8],
    range_buses: usize,
) {
    eprintln!(
        "CONSUMING_A_ARTIFACT stage={} range_buses={} shape={:?} descriptor_personalized_blake2b={} vk_kgwvkey1={} proof_pbytes_kgwtstp1={} proof_bytes={} diagnostic_only=true",
        stage + 1,
        range_buses,
        iroha_plonk::protocol::Protocol::new(key.binding().descriptor())
            .unwrap()
            .shape(),
        hex(key.binding().digest()),
        hex(&key.vk().kagemusha_digest(key.binding()).unwrap().to_repr()),
        hex(&proof_identity(proof).to_repr()),
        proof.len()
    );
}
/// Every claim, tape and proof the one terminal A consumes is hard: dropping or doubling
/// a fold claim, omitting or corrupting Q0, or substituting the receipt tape or a
/// predecessor obligation leaves the stage unsatisfiable.
fn adversarial_terminal(single: &Single, claims: &[FoldInput<Ep>], required: usize) {
    let params = &single.source.params;
    let vparams = common::vesta_params(16);
    let public = terminal_public(single);
    let unsatisfied = |bad: &Single, public: &[Vec<Fp>]| {
        !iroha_plonk::check::check_circuit(bad, 16, public, CheckMode::Strict)
            .is_ok_and(|r| r.is_satisfied())
    };
    let mut changed = (*single.source).clone();
    let last = changed.objects[0].bytes.len() - 1;
    changed.objects[0].bytes[last] ^= 1;
    let mut cross_receipt = single.clone();
    cross_receipt.source = Arc::new(changed);
    assert!(
        unsatisfied(&cross_receipt, &terminal_public(&cross_receipt)),
        "the terminal A cannot substitute the context-committed receipt tape"
    );
    for omitted in 0..required {
        let mut kept = claims.to_vec();
        kept[omitted] = AccumulatorT::trivial(params, MemoryBudget::DEFAULT)
            .unwrap()
            .as_input();
        let (fold, _) = create_fold(
            params,
            &kept,
            common::public_fixture_tape(122),
            iroha_plonk_recursion::FoldPurpose::ATerminal,
            &FoldConfig::default(),
        )
        .unwrap();
        let mut bad = single.clone();
        bad.fold = iroha_kagemusha_proof::private_fold::PrivateFoldBytes::from_owned(
            fold.to_private_bytes(),
        );
        assert!(
            unsatisfied(&bad, &public),
            "dropped terminal claim{omitted}"
        );
    }
    let mut doubled = claims.to_vec();
    doubled[1] = claims[0].clone();
    let (fold, _) = create_fold(
        params,
        &doubled,
        common::public_fixture_tape(122),
        iroha_plonk_recursion::FoldPurpose::ATerminal,
        &FoldConfig::default(),
    )
    .unwrap();
    let mut bad = single.clone();
    bad.fold =
        iroha_kagemusha_proof::private_fold::PrivateFoldBytes::from_owned(fold.to_private_bytes());
    assert!(
        unsatisfied(&bad, &public),
        "double-consumed predecessor claim"
    );
    let mut bad = single.clone();
    bad.omit_q = true;
    assert!(
        unsatisfied(&bad, &public),
        "the terminal A cannot omit the own receipt Q0"
    );
    let mut source = (*single.source).clone();
    source.q_proofs[0][0] ^= 1;
    let mut bad = single.clone();
    bad.source = Arc::new(source);
    assert!(unsatisfied(&bad, &public), "wrong own receipt Q0 proof");
    for replace_pallas in [true, false] {
        let mut source = (*single.source).clone();
        if replace_pallas {
            source.predecessor.pallas =
                AccumulatorT::trivial(params, MemoryBudget::DEFAULT).unwrap();
        } else {
            source.predecessor.vesta =
                AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT).unwrap();
        }
        let mut bad = single.clone();
        bad.source = Arc::new(source);
        assert!(
            unsatisfied(&bad, &terminal_public(&bad)),
            "substituted predecessor P/V obligation"
        );
    }
}
fn vesta_words(claim: &FoldInput<Eq>) -> Vec<Fp> {
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Eq>(claim.g());
    let mut words = vec![];
    for v in [x, y] {
        words.extend(foreign_limbs(&v).map(Fp::from_u128));
    }
    words.extend(claim.challenges());
    words
}

/// Run the retained composition assertions with genuine native Load originals.
pub fn compact_loaded_wallet_proves_unload_and_retiring_with_all_owners(fixture: &LoadFixture) {
    let rooted = catalog::compact_payer_load(fixture);
    for retiring in [false, true] {
        run_consuming_from_load(&rooted, retiring, false);
    }
}

fn run_consuming_from_load(
    rooted: &load_outer::DiagnosticLoadOmega,
    retiring: bool,
    native_differential: bool,
) -> AuthenticatedConsuming {
    run_consuming_from_head(&Head::loaded(rooted), retiring, native_differential)
}

fn run_consuming_from_head(
    head: &Head<'_>,
    retiring: bool,
    native_differential: bool,
) -> AuthenticatedConsuming {
    let source = Arc::new(sources(head, retiring));
    let context = ContextPlan::with_schedule(
        source.plan.clone(),
        vec![vec![0]],
        Some(0),
        UnloadObjects::context_specs().unwrap().to_vec(),
    )
    .unwrap()
    .with_operation_tasks(vec![vec![
        if retiring {
            OperationTask::RetiringState
        } else {
            OperationTask::UnloadRecovery
        },
        OperationTask::UnloadAuthorization,
    ]])
    .unwrap();
    UnloadStagePlan::new(context.clone(), load_objects::policy()).unwrap();
    let profile = SourceProfile::Tagged { buses: 3 };
    // The fixed terminal fold: the hard predecessor's carried claim and opening, then the
    // own receipt Q0 opening, padded with the pinned trivial claim to four.
    let mut claims = vec![
        source.predecessor.pallas.as_input(),
        source.predecessor.opening.clone(),
        source.q_openings[0].clone(),
    ];
    let required = claims.len();
    let filler = AccumulatorT::trivial(&source.params, MemoryBudget::DEFAULT).unwrap();
    while claims.len() < 4 {
        claims.push(filler.as_input());
    }
    let (fold, pallas) = create_fold(
        &source.params,
        &claims,
        common::public_fixture_tape(122),
        iroha_plonk_recursion::FoldPurpose::ATerminal,
        &FoldConfig::default(),
    )
    .unwrap();
    pallas
        .decide(&source.params, MemoryBudget::DEFAULT)
        .unwrap();
    let single = Single {
        source: source.clone(),
        profile,
        plan: context,
        pallas,
        fold: iroha_kagemusha_proof::private_fold::PrivateFoldBytes::from_owned(
            fold.to_private_bytes(),
        ),
        known: true,
        omit_q: false,
    };
    let public = terminal_public(&single);
    let (assigned, k) = match synthesize(&single, 16, Some(&public)) {
        Ok(a) => (a, 16),
        Err(error) => {
            eprintln!("Consuming terminal A k16 capacity failure {error:?}");
            (synthesize(&single, 18, Some(&public)).unwrap(), 18)
        }
    };
    let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let lanes = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect::<Vec<_>>();
    eprintln!(
        "GENUINE_CONSUMING_TERMINAL lanes={lanes:?} production_k16_fit={}",
        k == 16
    );
    assert_eq!(k, 16, "hard capacity cannot be relaxed");
    // The one stage proves the transition and authenticates the receipt, including its
    // sigma-only proof digest, by the own-receipt signature under the carried payment
    // key; the adversarial checks below reject a substituted receipt.
    let mut changed = (*source).clone();
    changed.maps.witness.successor.core[iroha_kagemusha_proof::witness::core_index::BALANCE] +=
        Fp::ONE;
    let mut wrong_effect = single.clone();
    wrong_effect.source = Arc::new(changed);
    assert!(
        !iroha_plonk::check::check_circuit(
            &wrong_effect,
            16,
            &terminal_public(&wrong_effect),
            CheckMode::Strict,
        )
        .is_ok_and(|r| r.is_satisfied()),
        "the terminal A must reject a successor balance the transition does not prove"
    );
    let unknown = synthesize(&single.without_witnesses(), 16, None).unwrap();
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    drop((assigned, unknown));
    adversarial_terminal(&single, &claims, required);
    let mut cfg = KeygenConfigV2::pipa_r(vec![iroha_plonk::cs::InstanceType::Bounded]);
    cfg.compress_selectors = false;
    let vparams = common::vesta_params(16);
    let key = keygen_pk_v2(&vparams, &single, &cfg).unwrap();
    let proof = create_proof_owned_with_claim(
        &vparams,
        &key,
        Witness::from_circuit(&key, &single, &public).unwrap(),
        common::fresh_randomness(),
        ProverConfig::default(),
    )
    .unwrap();
    proof
        .opening
        .decide(&vparams, MemoryBudget::DEFAULT)
        .unwrap();
    eprintln!(
        "actual consuming terminal A proof={}B; final Omega/full catalog still pending",
        proof.proof.len()
    );
    artifact_diagnostics(0, &key, &proof.proof, single.profile.range_buses());
    let final_digest = key.vk().kagemusha_digest(key.binding()).unwrap();
    let final_catalog = iroha_kagemusha_proof::omega::OmegaPlan::new(
        key.binding().clone(),
        vparams.clone(),
        vec![final_digest],
    )
    .unwrap();
    assert!(
        final_catalog
            .with_key_catalog(vec![key.vk().clone()])
            .is_ok()
    );
    let output = AuthenticatedConsuming {
        key: key.vk().clone(),
        binding: key.binding().clone(),
        opening: FoldInput::from_opening(*proof.opening.g(), proof.opening.challenges()).unwrap(),
        proof: proof.proof.clone(),
        instances: public[0].clone(),
        pallas: single.pallas.clone(),
        predecessor_vesta: source.predecessor.vesta.clone(),
        state: source.maps.witness.successor,
    };
    if native_differential {
        native_installed_consuming_differential(
            &single,
            key,
            &(proof.proof, single.pallas.to_bytes()),
        );
    }
    assert_eq!(output.state.core, source.maps.witness.successor.core);
    assert_eq!(output.state.rest, source.maps.witness.successor.rest);
    assert_eq!(output.state.lineage, source.maps.witness.successor.lineage);
    eprintln!(
        "CONSUMING_COMPLETE_TASK_COMPONENT hard_predecessor=true one_terminal_a=true lean_inline_transition=true mandatory_own_receipt_1V=true all_maps=true all_openings=true full_catalog=false release_qualified=false"
    );
    output
}

/// The same component assertions from the two-terminal common-key Load catalog, whose
/// outer predicate needs no compact secondary layout. That Load Ω exceeds the consuming
/// transport cap, so the native plan, which enforces the cap, is not exercised here.
pub fn two_terminal_loaded_wallet_proves_unload_and_retiring_with_all_owners(
    fixture: &LoadFixture,
) {
    let rooted = load_outer::two_terminal_load_omega(fixture).artifact;
    for retiring in [false, true] {
        run_consuming_from_load(&rooted, retiring, false);
    }
}

/// Run the retained composition assertions with genuine native Load originals.
pub fn installed_native_consuming_proves_and_restores_every_stage(fixture: &LoadFixture) {
    let rooted = catalog::compact_payer_load(fixture);
    for retiring in [false, true] {
        run_consuming_from_load(&rooted, retiring, true);
    }
}

#[test]
#[ignore = "genuine compact Bootstrap and lean one-stage Retiring proofs, strict import and canonical fresh-session replay; run optimized"]
fn installed_native_retiring_from_bootstrap_preserves_every_original_and_checkpoint() {
    use iroha_kagemusha_proof::witness::core_index as core;
    let rooted =
        load_outer::load_chain::bootstrap_outer::compact_bootstrap::rooted_compact_bootstrap();
    let before = StateWitness::from(&rooted.source.state);
    assert_eq!(before.core[core::BALANCE], Fp::ZERO);
    assert_eq!(before.lineage[14], Fp::ZERO);
    let head = Head {
        state: before,
        load_receipt: None,
        binding: &rooted.binding,
        key: &rooted.key,
        proof: &rooted.proof,
        pallas: &rooted.source.pallas,
        vesta: &rooted.vesta,
        opening: &rooted.opening,
    };
    let retired = run_consuming_from_head(&head, true, true);
    assert_eq!(retired.state.core[core::LIFECYCLE], Fp::from(2));
    assert_eq!(retired.state.core[core::BALANCE], Fp::ZERO);
    for (index, old) in before.core.iter().enumerate() {
        if !matches!(
            index,
            core::SEQUENCE
                | core::STATE_NONCE
                | core::LIFECYCLE
                | core::BURNED_TOTAL
                | core::PENDING_OUTGOING_ROOT
        ) {
            assert_eq!(*old, retired.state.core[index], "unchanged core {index}");
        }
    }
    assert_eq!(retired.state.rest, before.rest);
    assert_eq!(retired.state.core[core::BURNED_TOTAL], before.lineage[14]);
    assert_eq!(
        retired.state.core[core::PENDING_OUTGOING_ROOT],
        before.lineage[15]
    );
    assert_eq!(retired.state.lineage[17], before.lineage[17]);
    eprintln!(
        "BOOTSTRAP_RETIRING_COMPONENT zero_balance_preserved=true genuine_predecessor=true native_original_imports=true canonical_replay=true final_omega_admitted=false full_catalog=false"
    );
}

fn native_installed_consuming_differential(
    single: &Single,
    proving_key: iroha_plonk::ProvingKey<Eq>,
    original: &(Vec<u8>, [u8; 544]),
) {
    use iroha_kagemusha_proof::a_relation::{native::consuming as native, own::OwnPolicy};
    use iroha_plonk::cs::{
        CircuitDescriptorV2, CurveV1, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV2,
    };
    assert_eq!(
        single.profile,
        SourceProfile::Tagged {
            buses: native::SOURCE_RANGE_BUSES,
        }
    );
    let source = &single.source;
    let input = native::Inputs {
        state: source.maps.witness,
        objects: core::array::from_fn(|i| source.objects[i].bytes.clone()),
        recovery: source.maps.recovery,
        q: core::array::from_fn(|i| native::QInput {
            proof: source.q_proofs[i].clone(),
            instances: source.q_instances[i].clone(),
        }),
        predecessor: native::PredecessorInput {
            proof: source.predecessor.proof.clone(),
            pallas: source.predecessor.pallas.to_bytes(),
            vesta: source.predecessor.vesta.to_bytes(),
        },
    };
    let plan = native::Plan::new(
        source.plan.clone(),
        load_objects::policy(),
        source.signature_schema.clone(),
        source.predecessor.key.clone(),
        source.params.clone(),
        common::vesta_params(16),
    )
    .unwrap();
    assert_eq!(plan.context().schema(), single.plan.schema());
    assert_eq!(plan.context().stage_count(), native::A_STAGE_COUNT);
    // The offline source factory reconstructs exactly the genuinely proved source key.
    let mut a_config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    a_config.compress_selectors = false;
    let (binding, key) = keygen_vk_with_binding_v2(
        &common::vesta_params(16),
        &plan.source_circuit().unwrap(),
        &a_config,
    )
    .unwrap();
    assert_eq!(&binding, proving_key.binding(), "terminal A descriptor");
    assert_eq!(
        key.to_bytes(),
        proving_key.vk().to_bytes(),
        "terminal A key"
    );
    let terminal = NativeConsumingOriginal::from_key(&proving_key);
    // Test-owned original files survive, but no diagnostic proving polynomials
    // remain during the metadata-only producer's import/proof replay.
    drop(proving_key);
    let config = iroha_plonk::keys::pk::artifact::ReadConfig {
        maximum_bytes: terminal.pk.len(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let install = |plan: native::Plan,
                   terminal: &NativeConsumingOriginal,
                   config|
     -> Result<native::Prover, native::Error> {
        let prover = native::Prover::from_artifacts(plan, terminal.metadata()?)?;
        prover.import_terminal(&terminal.pk, config)?;
        Ok(prover)
    };
    let installed = install(plan.clone(), &terminal, config).unwrap();
    for mutation in 0..5 {
        let mut bad = terminal.clone();
        match mutation {
            0 => bad.pk[44 + terminal.vk.len()] ^= 1,
            1 => bad.pk[44 + terminal.vk.len() + 32] ^= 1,
            2 => {
                bad.pk.pop();
            }
            3 => bad.pk.push(0),
            _ => bad.vk[0] ^= 1,
        }
        assert!(
            install(plan.clone(), &bad, config).is_err(),
            "consuming original mutation{mutation}"
        );
    }
    let descriptor = CircuitDescriptorV2::decode(&terminal.descriptor).unwrap();
    for mutation in 0..6 {
        let mut wrong = descriptor.clone();
        match mutation {
            0 => wrong.instance_types[0] = InstanceType::Field,
            1 => wrong.transcript = TranscriptV2::KagemushaPoseidonRp57,
            2 => wrong.instance_mode = InstanceModeV1::Committed,
            3 => wrong.proof_suffix = ProofSuffixV1::None,
            4 => wrong.instance_lengths[0] = 68,
            _ => wrong.curve = CurveV1::Pallas,
        }
        let mut bad = terminal.clone();
        bad.descriptor = wrong.encode().unwrap();
        assert!(
            install(plan.clone(), &bad, config).is_err(),
            "consuming profile mutation{mutation}"
        );
    }
    let changed_policy = OwnPolicy::new([33, 34], bootstrap_objects::key(23)).unwrap();
    let changed = native::Plan::new(
        source.plan.clone(),
        changed_policy,
        UnloadStagePlan::signature_schema().unwrap(),
        source.predecessor.key.clone(),
        source.params.clone(),
        common::vesta_params(16),
    )
    .unwrap();
    // The receipt binding pins the provider, so a changed policy changes the source.
    assert!(install(changed.clone(), &terminal, config).is_err());
    // A valid key of the same descriptor for another provider policy is never this
    // source's key: neither its VK beside this original nor, below, its bound view.
    let other_policy = NativeConsumingOriginal::from_key(
        &keygen_pk_v2(
            &common::vesta_params(16),
            &changed.source_circuit().unwrap(),
            &a_config,
        )
        .unwrap(),
    );
    assert_eq!(
        other_policy.descriptor, terminal.descriptor,
        "same terminal descriptor"
    );
    assert_ne!(other_policy.vk, terminal.vk, "another policy's key");
    let mut bad = terminal.clone();
    bad.vk.clone_from(&other_policy.vk);
    assert!(
        install(plan.clone(), &bad, config).is_err(),
        "foreign verifying key"
    );
    assert!(
        installed
            .import_terminal(
                &terminal.pk,
                iroha_plonk::keys::pk::artifact::ReadConfig {
                    maximum_bytes: 0,
                    ..config
                }
            )
            .is_err()
    );
    assert!(
        installed
            .import_terminal(
                &terminal.pk,
                iroha_plonk::keys::pk::artifact::ReadConfig {
                    maximum_rows: (1 << 16) - 1,
                    ..config
                }
            )
            .is_err()
    );
    assert_eq!(installed.descriptors().len(), 1);
    let [layout] = installed.checkpoint_layouts().unwrap();
    let budget = MemoryBudget::DEFAULT;
    let mut session = installed.prepare(input.clone(), budget).unwrap();
    let unrelated_session = installed.prepare(input.clone(), budget).unwrap();
    // D6a (DP §7.4 test 8): a detached session resumes only on the prover instance
    // that prepared it, never on another instance installed from the same original.
    let other = install(plan.clone(), &terminal, config).unwrap();
    let detached = installed
        .prepare(input.clone(), budget)
        .unwrap()
        .into_retained();
    assert!(matches!(other.resume(detached), Err(native::Error::Input)));
    drop(other);
    let fold = FoldConfig::default();
    let key_seal = installed.import_terminal(&terminal.pk, config).unwrap();
    let key = installed.bind_terminal(&key_seal, None).unwrap();
    {
        let foreign_prover = install(changed, &other_policy, config).unwrap();
        let foreign_seal = foreign_prover
            .import_terminal(&other_policy.pk, config)
            .unwrap();
        let foreign_key = foreign_prover.bind_terminal(&foreign_seal, None).unwrap();
        assert!(matches!(
            session.terminal(
                &foreign_key,
                common::public_fixture_tape(122),
                &fold,
                common::fresh_randomness(),
                ProverConfig::default(),
            ),
            Err(native::Error::Artifact)
        ));
    }
    // The same public tape reproduces the reference fold, so only the proof differs.
    let generated = session
        .terminal(
            &key,
            common::public_fixture_tape(122),
            &fold,
            common::fresh_randomness(),
            ProverConfig::default(),
        )
        .unwrap();
    assert_ne!(generated.proof, original.0, "fresh proof attempt");
    let restored = session
        .restore_terminal(original.0.clone(), &original.1, budget)
        .unwrap();
    assert_eq!(restored.proof, original.0, "exact retained original");
    assert_eq!(generated.instances, restored.instances);
    assert_eq!(generated.pallas, restored.pallas);
    assert_eq!(restored.instances, terminal_public(single)[0]);
    assert_eq!(restored.predecessor_vesta, source.predecessor.vesta);
    restored.pallas.decide(&source.params, budget).unwrap();
    let vparams = common::vesta_params(16);
    restored.predecessor_vesta.decide(&vparams, budget).unwrap();
    restored.opening.decide(&vparams, budget).unwrap();
    let mut changed = original.0.clone();
    changed[0] ^= 1;
    assert!(
        session
            .restore_terminal(changed, &original.1, budget)
            .is_err()
    );
    assert!(
        session
            .restore_terminal(original.0.clone(), &original.1[..543], budget)
            .is_err()
    );
    let mut claim = original.1;
    claim[40] ^= 1;
    assert!(
        session
            .restore_terminal(original.0.clone(), &claim, budget)
            .is_err()
    );
    let payload = session
        .encode_terminal_checkpoint(&restored, budget)
        .unwrap();
    assert_eq!(payload.len(), layout.payload_bytes());
    assert!(
        session
            .restore_terminal_checkpoint(&payload[..payload.len() - 1], budget)
            .is_err()
    );
    let mut changed = payload.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        session
            .restore_terminal_checkpoint(&changed, budget)
            .is_err()
    );
    let current = session
        .restore_terminal_checkpoint(&payload, budget)
        .unwrap();
    assert_eq!(current.proof, original.0, "exact retained original");
    let generated_payload = session
        .encode_terminal_checkpoint(&generated, budget)
        .unwrap();
    assert_eq!(generated_payload.len(), layout.payload_bytes());
    let mut substituted = current.clone();
    substituted.instances[0] += Fp::ONE;
    assert!(
        session
            .encode_terminal_checkpoint(&substituted, budget)
            .is_err()
    );
    // A checkpoint names its source, not a session: another session prepared from the
    // same originals on this prover restores it too.
    let foreign = unrelated_session
        .restore_terminal_checkpoint(&payload, budget)
        .unwrap();
    assert_eq!(foreign.instances, current.instances);
    // D6a: the session detached and resumed between fold calls restores the same payload.
    session = installed.resume(session.into_retained()).unwrap();
    let resumed = session
        .restore_terminal_checkpoint(&payload, budget)
        .unwrap();
    assert_eq!(resumed.proof, current.proof);
    let restarted = installed.prepare(input.clone(), budget).unwrap();
    let replayed = restarted
        .restore_terminal_checkpoint(&payload, budget)
        .unwrap();
    assert_eq!(replayed.proof, current.proof);
    assert_eq!(replayed.instances, current.instances);
    assert_eq!(replayed.pallas, current.pallas);
    assert_eq!(replayed.predecessor_vesta, current.predecessor_vesta);
    assert_eq!(replayed.opening, current.opening);
    assert_eq!(
        restarted
            .encode_terminal_checkpoint(&replayed, budget)
            .unwrap(),
        payload,
        "exact checkpoint bytes after cold replay"
    );
    eprintln!(
        "NATIVE_CONSUMING_PARITY metadata_only_producer=true borrowed_stage_PK=true exact_original_proof_bytes=true canonical_fresh_session_replay=true"
    );
    for object in 0..input.objects.len() {
        for offset in [0, input.objects[object].len() - 1] {
            let mut bad = input.clone();
            bad.objects[object][offset] ^= 1;
            assert!(
                installed.prepare(bad, budget).is_err(),
                "own tape {object}/{offset}"
            );
        }
    }
    for mutation in 0..9 {
        let mut bad = input.clone();
        match mutation {
            0 => bad.state.predecessor.lineage[9] += Fp::ONE,
            1 => bad.predecessor.proof[0] ^= 1,
            2 => bad.q[0].proof[0] ^= 1,
            3 => bad.state.predecessor.lineage[17] += Fp::ONE,
            4 => {
                bad.recovery = if bad.recovery.is_some() {
                    None
                } else {
                    Some(IndexedInsert {
                        leaf: iroha_kagemusha_proof::tree::IndexedLeaf::default(),
                        leaf_slot: 0,
                        leaf_siblings: [Fp::ZERO; 32],
                        slot: 1,
                        slot_siblings: [Fp::ZERO; 32],
                    })
                }
            }
            5 => bad.predecessor.pallas[0] ^= 1,
            6 => bad.predecessor.vesta[0] ^= 1,
            7 => bad.q[0].instances[0][0] += Fq::ONE,
            _ => {
                bad.objects[0].pop();
            }
        }
        assert!(
            installed.prepare(bad, budget).is_err(),
            "consuming input mutation{mutation}"
        );
    }
}

#[derive(Clone)]
struct NativeConsumingOriginal {
    descriptor: Vec<u8>,
    vk: Vec<u8>,
    pk: Vec<u8>,
}
impl NativeConsumingOriginal {
    fn from_key<C: iroha_pasta::PastaCurve>(key: &iroha_plonk::ProvingKey<C>) -> Self {
        Self {
            descriptor: key.binding().encoded().to_vec(),
            vk: key.vk().to_bytes().to_vec(),
            pk: key.artifact_bytes_v2().unwrap(),
        }
    }
    fn metadata<C: iroha_pasta::PastaCurve>(
        &self,
    ) -> Result<
        iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact<C>,
        iroha_kagemusha_proof::a_relation::native::consuming::Error,
    > {
        use iroha_kagemusha_proof::a_relation::native::{artifact::KeyArtifact, consuming::Error};
        let binding = iroha_plonk::DescriptorBinding::decode_v2(&self.descriptor)
            .map_err(|_| Error::Artifact)?;
        let key =
            iroha_plonk::VerifyingKey::read(&self.vk, &binding).map_err(|_| Error::Artifact)?;
        KeyArtifact::new(binding, key).map_err(|_| Error::Artifact)
    }
}
