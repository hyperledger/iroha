//! Genuine Archive own-sigma and C4 owners; no predecessor or full lineage admission.

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
mod common;
#[path = "common/send_objects.rs"]
#[allow(dead_code)]
mod send_objects;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::{
        AProofPlan, LineagePublicCells, ProofMessageCells, QProofPlan, SigmaBindingCells,
        VestaClaimCells,
        archive::{
            authorization::ArchiveAuthorizationObjects,
            incoming::ArchiveIncomingObjects,
            results::{ArchiveResultClaims, ArchiveResultPlan},
        },
        bind_signature_q,
        context::{
            ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan, ContextPredecessor,
            ContextState,
        },
        own::OwnPolicy,
        schedule::OperationTask,
        verify_q,
    },
    admin_sigma::{ArchiveCircuit, ArchiveWitness, StateWitness},
    operation_relation::{objects::ObjectKind, state::StateCells, statement::StatementCells},
    q_sigma::{QSigmaPlan, SigmaClass, SigmaSlotWitness, native::QSigmaProver},
    q_signature::{QSignatureCircuit, QSignaturePlan},
    witness::core_index as core,
};
use iroha_pasta::{Ep, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain};
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
        p_bytes_native,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    statement::{STATEMENT_DOMAIN, foreign_limbs},
};
use iroha_plonk_recursion::{
    FoldConfig,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};
use std::sync::Arc;

fn policy() -> OwnPolicy {
    OwnPolicy::new([31, 32], bootstrap_objects::key(23)).unwrap()
}
fn transition() -> (ArchiveWitness, [bootstrap_objects::Signed; 2]) {
    let (before, certificate, credential) = bootstrap_objects::enrollment();
    let mut after = before;
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    // This component checks own authorization, not a pending-map removal or ancestry.
    after.statement = [Fp::ZERO; 26];
    after.statement[0] = Fp::ONE;
    after.statement[14] = before.lineage[5];
    after.statement[16] = Fp::from(5);
    after.statement[17] = Fp::from(181);
    after.statement[18] = Fp::from(182);
    bootstrap::rebind(&mut after);
    (
        ArchiveWitness {
            predecessor: StateWitness::from(&before),
            successor: StateWitness::from(&after),
            statement: after.statement,
        },
        [credential, certificate],
    )
}
fn receipt(w: &ArchiveWitness, sigma: &[u8]) -> bootstrap_objects::Signed {
    let mut tape = u32::try_from(sigma.len()).unwrap().to_le_bytes().to_vec();
    tape.extend(sigma);
    let digest = p_bytes_native(u64::from_le_bytes(*b"kgwstep1"), &tape);
    let operation = hash_with_domain(
        u64::from_le_bytes(*b"kgwopid1"),
        &[
            w.predecessor.core[5],
            w.predecessor.core[6],
            Fp::from(5),
            w.statement[18],
        ],
    );
    let mut body = 1u16.to_le_bytes().to_vec();
    body.extend(bootstrap_objects::id(
        w.predecessor.core[1],
        w.predecessor.core[2],
    ));
    body.extend(bootstrap_objects::id(
        w.predecessor.core[5],
        w.predecessor.core[6],
    ));
    body.extend(bootstrap_objects::small_id(31, 32));
    body.extend(&w.statement[9].to_repr()[..16]);
    for v in [
        operation,
        w.statement[14],
        w.statement[15],
        hash_with_domain(STATEMENT_DOMAIN, &w.statement),
        digest,
    ] {
        body.extend(v.to_repr());
    }
    body.extend(bootstrap_objects::small_id(451, 452));
    body.extend(Fp::ZERO.to_repr());
    bootstrap_objects::sign(ObjectKind::Receipt, body, 29, 79)
}
struct Sources {
    witness: ArchiveWitness,
    objects: [bootstrap_objects::Signed; 3],
    sigma: Vec<u8>,
    context: ContextPlan,
    q_instances: Vec<Vec<Vec<Fq>>>,
    signature_proof: Vec<u8>,
    schema: QSignaturePlan,
    sigma_plan: QSigmaPlan,
}
fn sources() -> Sources {
    let (witness, [credential, certificate]) = transition();
    let leaf = ArchiveCircuit::new(&witness);
    let lp = common::vesta_params(12);
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let v = common::vesta_params(16);
    let key = keygen_pk_v2(
        &lp,
        &leaf,
        &KeygenConfigV2::pipa_r(ArchiveCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let sigma = create_proof_owned_with_claim(
        &lp,
        &key,
        Witness::from_circuit(&key, &leaf, &leaf.instances()).unwrap(),
        common::recovery(221),
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
    let objects = [credential, certificate, receipt(&witness, &sigma)];
    let sigma_plan = QSigmaPlan::new(
        SigmaClass::new(
            VerifierPlan::new(key.binding().clone(), lp).unwrap(),
            vec![(12, key.vk().kagemusha_digest(key.binding()).unwrap())],
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
                length: sigma.len().try_into().unwrap(),
                proof: sigma.clone(),
            },
            None,
            &v,
            Fq::from(403),
            &FoldConfig::default(),
        )
        .unwrap();
    let q0 = QSigmaProver::keygen_serialized_foreign(&prepared, p.clone(), 2).unwrap();
    let q0_proof = q0
        .prove(&prepared, common::recovery(222), ProverConfig::default())
        .unwrap();
    accumulate_generator(
        &p,
        q0.binding(),
        q0.verifying_key(),
        &q0_proof.instances,
        &q0_proof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap()
    .decide(&p, MemoryBudget::DEFAULT)
    .unwrap();
    let [schema, _] = ArchiveAuthorizationObjects::signature_schemas(policy()).unwrap();
    let circuit = QSignatureCircuit::new(
        schema.clone(),
        [2, 0, 1].map(|i| objects[i].signature).to_vec(),
    )
    .unwrap();
    let instances = circuit.instances(&[true; 3]).unwrap();
    let qkey = keygen_pk_v2(
        &p,
        &circuit,
        &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
    )
    .unwrap();
    let signature_proof = create_proof_owned_with_claim(
        &p,
        &qkey,
        Witness::from_circuit(&qkey, &circuit, &instances).unwrap(),
        common::recovery(223),
        ProverConfig::default(),
    )
    .unwrap()
    .proof;
    accumulate_generator(
        &p,
        qkey.binding(),
        qkey.vk(),
        &instances,
        &signature_proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap()
    .decide(&p, MemoryBudget::DEFAULT)
    .unwrap();
    let q = vec![
        QProofPlan::new(
            VerifierPlan::new(q0.binding().clone(), p.clone()).unwrap(),
            q0.verifying_key().clone(),
        )
        .unwrap(),
        QProofPlan::new(
            VerifierPlan::new(qkey.binding().clone(), p.clone()).unwrap(),
            qkey.vk().clone(),
        )
        .unwrap(),
    ];
    // Constructor metadata/fillers below are never accepted as an incoming or predecessor proof.
    // The remaining operation owners are declared but deliberately not executed in this component test.
    let operation = AProofPlan::new(
        Variant::ArchiveStatus,
        sigma_plan.clone(),
        q,
        Some(predecessor_metadata()),
        &p,
    )
    .unwrap();
    let context = ContextPlan::with_schedule(
        operation,
        vec![vec![0], vec![1], vec![]],
        Some(0),
        ArchiveAuthorizationObjects::context_specs()
            .unwrap()
            .to_vec(),
    )
    .unwrap()
    .with_operation_tasks(vec![
        vec![OperationTask::ArchiveOwnProof],
        vec![OperationTask::ArchiveAuthorization],
        vec![
            OperationTask::ArchiveRetainedPayment,
            OperationTask::ArchiveEvidence,
            OperationTask::ArchiveProofs,
            OperationTask::ArchiveSignatures,
            OperationTask::ArchiveEffects,
            OperationTask::ArchiveRetainedProofs,
            OperationTask::ArchiveCorePending,
            OperationTask::ArchiveLineagePending,
        ],
    ])
    .unwrap();
    Sources {
        witness,
        objects,
        sigma,
        context,
        q_instances: vec![q0_proof.instances, instances.to_vec()],
        signature_proof,
        schema,
        sigma_plan,
    }
}
#[derive(Clone)]
struct Owner {
    source: Arc<Sources>,
    stage: usize,
    mutation: u8,
    known: bool,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl Owner {
    fn value<T: Copy>(&self, v: T) -> Value<T> {
        if self.known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    }
    fn scalar(
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
    fn state(
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
    fn proof(
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

    fn originals(&self) -> [bootstrap_objects::Signed; 3] {
        let mut objects = self.source.objects.clone();
        if (1..=3).contains(&self.mutation) {
            objects[usize::from(self.mutation - 1)].bytes[40] ^= 1;
        }
        if self.mutation == 4 {
            objects[2].bytes[ObjectKind::Receipt.body_len()] ^= 1;
        }
        objects
    }
    fn public(&self) -> [Vec<Fp>; 1] {
        [self
            .originals()
            .iter()
            .map(bootstrap_objects::Signed::digest)
            .collect()]
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
        let public = meta.instance_column(3);
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
            || "Archive hard own owner",
            |mut r| {
                let source = &self.source;
                let (before, previous) =
                    self.state(&mut chip, &mut r, &source.witness.predecessor)?;
                let (after, next) = self.state(&mut chip, &mut r, &source.witness.successor)?;
                let mut fields = source.witness.statement;
                if self.mutation == 9 {
                    fields[17] += Fp::ONE;
                }
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut r, &fields.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut r,
                    Variant::ArchiveStatus,
                    &fields,
                )?;
                let raw = self.originals().map(|o| {
                    o.bytes
                        .into_iter()
                        .map(|b| self.value(b))
                        .collect::<Vec<_>>()
                });
                let objects = ArchiveAuthorizationObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut r,
                    Variant::ArchiveStatus,
                    raw.each_ref().map(Vec::as_slice),
                )?;
                let mut qi = source.q_instances.clone();
                if self.mutation == 7 {
                    qi[0][2][0] += Fq::ONE;
                }
                if self.mutation == 8 {
                    qi[0][0][1] += Fq::ONE;
                }
                let q_instances = qi
                    .iter()
                    .map(|columns| {
                        columns
                            .iter()
                            .map(|c| {
                                c.iter()
                                    .map(|v| self.scalar(&mut chip, &mut r, *v))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, Error>>()?;
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
                let stage = u32::try_from(if self.mutation == 10 { 2 } else { self.stage })
                    .map_err(|_| Error::BoundsFailure)?;
                if self.stage == 0 {
                    let mut raw = u32::try_from(source.sigma.len())
                        .unwrap()
                        .to_le_bytes()
                        .to_vec();
                    raw.extend(&source.sigma);
                    if self.mutation == 5 {
                        raw[40] ^= 1;
                    }
                    let raw = raw.into_iter().map(|b| self.value(b)).collect::<Vec<_>>();
                    let run = bytes.run(
                        &mut r,
                        &raw,
                        &raw.chunks(31).map(<[Value<u8>]>::len).collect::<Vec<_>>(),
                        &[SegmentSpec::little(0, 4)],
                    )?;
                    let index = chip.uint().glue().constant(&mut r, Fp::from(12))?;
                    let sigma =
                        SigmaBindingCells::from_run(&mut chip, &mut r, &statement, index, &run)?;
                    objects.constrain_own_proof(
                        &mut chip,
                        &mut r,
                        &source.context,
                        stage,
                        &input,
                        &sigma,
                    )?;
                } else {
                    let mut proof = source.signature_proof.clone();
                    if self.mutation == 6 {
                        proof[32] ^= 1;
                    }
                    let proof = self.proof(&mut chip, &mut bytes, &mut r, &proof)?;
                    let q = verify_q(
                        &mut chip,
                        &mut r,
                        source.context.operation(),
                        1,
                        &q_instances[1],
                        &proof,
                    )?;
                    let bundle = bind_signature_q(
                        &mut chip,
                        &mut r,
                        source.context.operation(),
                        1,
                        &source.schema,
                        &q,
                    )?;
                    let policy = if self.mutation == 11 {
                        OwnPolicy::new([31, 32], bootstrap_objects::key(19)).unwrap()
                    } else {
                        policy()
                    };
                    objects.constrain_current(
                        &mut chip,
                        &mut r,
                        &source.context,
                        stage,
                        &input,
                        (policy, &bundle),
                    )?;
                }
                Ok(objects
                    .context()
                    .iter()
                    .map(|o| o.authenticated_digest().clone())
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, v) in out.iter().enumerate() {
            layouter.constrain_instance(v.cell(), config.public, i)?;
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
fn archive_fixture_is_a_valid_shared_leaf_without_claiming_pending_membership() {
    let (w, _) = transition();
    let c = ArchiveCircuit::new(&w);
    assert!(
        check_circuit(&c, 12, &c.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let [own, incoming] = ArchiveAuthorizationObjects::signature_schemas(policy()).unwrap();
    assert_eq!(own.slots().len(), 3);
    assert_eq!(incoming.slots().len(), 1);
}
#[test]
#[ignore = "genuine sigma/Q proof creation plus original-source adversarial owners"]
fn genuine_archive_own_qs_bind_current_authorization_and_sigma_only_receipt() {
    let source = Arc::new(sources());
    for stage in 0..2 {
        let c = Owner {
            source: source.clone(),
            stage,
            mutation: 0,
            known: true,
        };
        let report = check_circuit(&c, 16, &c.public(), CheckMode::Strict).unwrap();
        assert!(report.is_satisfied(), "{report:?}");
        let known = synthesize(&c, 16, None).unwrap();
        let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        eprintln!(
            "ARCHIVE_OWN_COMPONENT stage={stage} rows={:?} genuine_sources=true full_chain=false",
            known
                .tables
                .advice_assigned()
                .iter()
                .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
                .collect::<Vec<_>>()
        );
        let mutations: &[u8] = if stage == 0 {
            &[5, 7, 8, 9, 10]
        } else {
            &[1, 2, 3, 4, 6, 9, 10, 11]
        };
        for &mutation in mutations {
            let bad = Owner {
                mutation,
                ..c.clone()
            };
            assert!(
                !check_circuit(&bad, 16, &bad.public(), CheckMode::Strict)
                    .is_ok_and(|r| r.is_satisfied()),
                "stage={stage} mutation={mutation}"
            );
        }
    }
}

struct IncomingSignatureSources {
    own: Arc<Sources>,
    originals: [Vec<u8>; 3],
    context: ContextPlan,
    schema: QSignaturePlan,
    public: Vec<Vec<Fq>>,
    proof: Vec<u8>,
    valid: bool,
}
fn incoming_signature_sources(own: Arc<Sources>, valid: bool) -> IncomingSignatureSources {
    let mut before = own.witness.predecessor;
    before.core[core::BALANCE] = Fp::from(100);
    let send = send_objects::from_load(&before);
    let receiver = send_objects::receiver_credential();
    let mut receipt = bootstrap_objects::sign(
        ObjectKind::Receipt,
        own.objects[2].bytes[..ObjectKind::Receipt.body_len()].to_vec(),
        43,
        83,
    );
    if !valid {
        receipt.signature.signature[0] = [0; 4];
        receipt.bytes[ObjectKind::Receipt.body_len()..ObjectKind::Receipt.body_len() + 32].fill(0);
    }
    let schema = ArchiveAuthorizationObjects::signature_schemas(policy()).unwrap()[1].clone();
    let circuit = QSignatureCircuit::new(schema.clone(), vec![receipt.signature]).unwrap();
    let public = circuit.instances(&[valid]).unwrap().to_vec();
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(QSignaturePlan::instance_types().to_vec()),
    )
    .unwrap();
    let proof = create_proof_owned_with_claim(
        &params,
        &key,
        Witness::from_circuit(&key, &circuit, &public).unwrap(),
        common::recovery(if valid { 224 } else { 225 }),
        ProverConfig::default(),
    )
    .unwrap()
    .proof;
    accumulate_generator(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap()
    .decide(&params, MemoryBudget::DEFAULT)
    .unwrap();
    let old = own.context.operation();
    let operation = AProofPlan::new(
        Variant::ArchiveStatus,
        own.sigma_plan.clone(),
        vec![
            old.q(0).unwrap().clone(),
            old.q(1).unwrap().clone(),
            QProofPlan::new(
                VerifierPlan::new(key.binding().clone(), params.clone()).unwrap(),
                key.vk().clone(),
            )
            .unwrap(),
        ],
        old.omega().cloned(),
        &params,
    )
    .unwrap();
    // Only Q2 and its exact original sources execute here. Other named owners
    // are constructor metadata, with explicit dummy context categories; this
    // component cannot authenticate a complete Archive or a lineage head.
    let mut specs = (1..=13)
        .map(|tag| ContextObjectSpec { tag, capacity: 32 })
        .collect::<Vec<_>>();
    for (index, spec) in [3, 6, 12]
        .into_iter()
        .zip(ArchiveIncomingObjects::context_specs().unwrap())
    {
        specs[index] = spec;
    }
    specs.push(ArchiveResultPlan::context_spec(Variant::ArchiveStatus, 14).unwrap());
    let context =
        ContextPlan::with_schedule(operation, vec![vec![0, 1], vec![2], vec![]], Some(0), specs)
            .unwrap()
            .with_operation_tasks(vec![
                vec![
                    OperationTask::ArchiveRetainedPayment,
                    OperationTask::ArchiveEvidence,
                    OperationTask::ArchiveProofs,
                    OperationTask::ArchiveAuthorization,
                    OperationTask::ArchiveOwnProof,
                ],
                vec![OperationTask::ArchiveSignatures],
                vec![
                    OperationTask::ArchiveEffects,
                    OperationTask::ArchiveRetainedProofs,
                    OperationTask::ArchiveCorePending,
                    OperationTask::ArchiveLineagePending,
                ],
            ])
            .unwrap();
    IncomingSignatureSources {
        own,
        originals: [send.objects[1].clone(), receiver.bytes, receipt.bytes],
        context,
        schema,
        public,
        proof,
        valid,
    }
}
#[derive(Clone)]
struct IncomingSignatureOwner {
    source: Arc<IncomingSignatureSources>,
    mutation: u8,
    known: bool,
}
impl Circuit<Fp> for IncomingSignatureOwner {
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
        Owner::configure(meta)
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let helper = Owner {
            source: self.source.own.clone(),
            stage: 0,
            mutation: 0,
            known: self.known,
        };
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "Archive actual incoming Q2 owner",
            |mut r| {
                let source = &self.source;
                let (state, next) =
                    helper.state(&mut chip, &mut r, &source.own.witness.successor)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(
                        &mut r,
                        &source.own.witness.statement.map(|v| helper.value(v)),
                    )?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut r,
                    Variant::ArchiveStatus,
                    &fields,
                )?;
                let originals = self.originals();
                let raw = originals
                    .each_ref()
                    .map(|raw| raw.iter().map(|b| helper.value(*b)).collect::<Vec<_>>());
                let objects = ArchiveIncomingObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut r,
                    raw.each_ref().map(Vec::as_slice),
                )?;
                let mut qi = source.own.q_instances.clone();
                qi.push(source.public.clone());
                if self.mutation == 4 {
                    qi[2][0][9] = Fq::from(u64::from(!source.valid));
                }
                let q_instances = qi
                    .iter()
                    .map(|columns| {
                        columns
                            .iter()
                            .map(|c| {
                                c.iter()
                                    .map(|v| helper.scalar(&mut chip, &mut r, *v))
                                    .collect()
                            })
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<Vec<_>>>, Error>>()?;
                let point = iroha_plonk::transcript::decode_point::<Ep>(
                    &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
                )
                .map_err(|_| Error::Synthesis)?;
                let point = chip.constant_point(&mut r, &Ep::from(point))?;
                let one = helper.scalar(&mut chip, &mut r, Fq::ONE)?;
                let opening = FoldInputCells::from_normalized(
                    &mut chip,
                    &mut r,
                    16,
                    point,
                    ::core::array::from_fn(|_| one.clone()),
                )?;
                let result_plan = ArchiveResultPlan::new(&source.context, 13)?;
                let results = ArchiveResultClaims::assign(
                    &mut chip,
                    &mut r,
                    result_plan,
                    [
                        true,
                        true,
                        if self.mutation == 5 {
                            !source.valid
                        } else {
                            source.valid
                        },
                    ]
                    .map(|v| helper.value(v)),
                    Some(&opening),
                )?;
                let zero = chip.uint().glue().constant(&mut r, Fp::ZERO)?;
                let mut contexts = Vec::new();
                for (index, spec) in source.context.object_specs().iter().enumerate() {
                    let actual = if let Some(i) = [3, 6, 12].iter().position(|i| *i == index) {
                        objects.context()[i].clone()
                    } else if index == 13 {
                        results.context().clone()
                    } else {
                        ContextObjectCells::from_internal_words(
                            &mut chip,
                            &mut r,
                            *spec,
                            std::slice::from_ref(&zero),
                        )?
                    };
                    contexts.push(actual);
                }
                if self.mutation == 6 {
                    contexts.swap(3, 6);
                }
                let input = ContextInputs {
                    own_statement: &statement,
                    incoming_statement: None,
                    predecessor: None,
                    successor: ContextState {
                        state: &state,
                        public: &next,
                    },
                    incoming: None,
                    q_instances: &q_instances,
                    objects: &contexts,
                    modes: &[],
                    pallas_corrections: &[],
                    vesta_corrections: &[],
                    receive_results: None,
                };
                let mut raw = source.proof.clone();
                if self.mutation == 7 {
                    raw[32] ^= 1;
                }
                if self.mutation == 8 {
                    raw.pop();
                }
                let proof = helper.proof(&mut chip, &mut bytes, &mut r, &raw)?;
                let q = verify_q(
                    &mut chip,
                    &mut r,
                    source.context.operation(),
                    2,
                    &q_instances[2],
                    &proof,
                )?;
                let bundle = bind_signature_q(
                    &mut chip,
                    &mut r,
                    source.context.operation(),
                    2,
                    &source.schema,
                    &q,
                )?;
                objects.constrain_signature(
                    &mut r,
                    &source.context,
                    if self.mutation == 9 { 2 } else { 1 },
                    &input,
                    &results,
                    &bundle,
                )?;
                Ok(objects
                    .context()
                    .iter()
                    .map(|o| o.authenticated_digest().clone())
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}
impl IncomingSignatureOwner {
    fn originals(&self) -> [Vec<u8>; 3] {
        let mut originals = self.source.originals.clone();
        match self.mutation {
            1 => originals[2][40] ^= 1,
            2 => originals[2][ObjectKind::Receipt.body_len() + 17] ^= 1,
            3 => {
                // A genuinely different quoted credential plus a matching
                // Request address still cannot change Q2's verified key.
                let key = bootstrap_objects::sec1(bootstrap_objects::key(19));
                originals[1][130..195].copy_from_slice(&key);
                let changed = bootstrap_objects::Signed {
                    kind: ObjectKind::Credential,
                    bytes: originals[1].clone(),
                    signature: self.source.own.objects[0].signature,
                }
                .digest();
                originals[0][210..242].copy_from_slice(&changed.to_repr());
            }
            _ => {}
        }
        originals
    }
    fn public(&self) -> [Vec<Fp>; 1] {
        [self
            .originals()
            .iter()
            .zip([
                ObjectKind::Request,
                ObjectKind::Credential,
                ObjectKind::Receipt,
            ])
            .map(|(raw, kind)| {
                bootstrap_objects::Signed {
                    kind,
                    bytes: raw.clone(),
                    signature: self.source.own.objects[0].signature,
                }
                .digest()
            })
            .collect()]
    }
}
#[test]
#[ignore = "actual own and incoming Q proofs plus strict original-source owner mutations"]
fn genuine_archive_incoming_q2_binds_receipt_key_originals_and_soft_result() {
    let own = Arc::new(sources());
    for valid in [true, false] {
        let source = Arc::new(incoming_signature_sources(own.clone(), valid));
        let c = IncomingSignatureOwner {
            source,
            mutation: 0,
            known: true,
        };
        let report = check_circuit(&c, 16, &c.public(), CheckMode::Strict).unwrap();
        assert!(report.is_satisfied(), "{report:?}");
        let known = synthesize(&c, 16, None).unwrap();
        let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        eprintln!(
            "ARCHIVE_Q2_COMPONENT signature_valid={valid} proof_bytes={} rows={:?} full_chain=false",
            c.source.proof.len(),
            known
                .tables
                .advice_assigned()
                .iter()
                .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
                .collect::<Vec<_>>()
        );
        for mutation in 1..=9 {
            let wrong = IncomingSignatureOwner {
                mutation,
                ..c.clone()
            };
            assert!(
                !check_circuit(&wrong, 16, &wrong.public(), CheckMode::Strict)
                    .is_ok_and(|r| r.is_satisfied()),
                "valid{valid} mutation{mutation}"
            );
        }
    }
}
