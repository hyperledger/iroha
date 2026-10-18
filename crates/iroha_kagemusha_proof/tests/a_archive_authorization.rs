//! Genuine Archive merged signature leaf: the hard own-receipt and soft
//! incoming-receipt owners on one Q; no predecessor or full lineage admission.

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
        AProofPlan, LineagePublicCells, ProofMessageCells, QProofPlan, VestaClaimCells,
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
    p256::VerifyMode,
    statement::{STATEMENT_DOMAIN, foreign_limbs},
};
use iroha_plonk_recursion::{
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};
use std::sync::Arc;

// The stage owning Authorization, Signatures and the merged leaf in this fixture.
const LEAF_STAGE: u32 = 1;
// The result object follows eleven source categories in this component context.
const RESULT_SLOT: usize = 11;
// Context slots of the held Request, quoted receiver credential and incoming receipt.
const INCOMING_SLOTS: [usize; 3] = [1, 4, 10];

fn policy() -> OwnPolicy {
    OwnPolicy::new([31, 32], bootstrap_objects::key(23)).unwrap()
}
fn transition() -> ArchiveWitness {
    let (before, _, _) = bootstrap_objects::enrollment();
    let mut after = before;
    after.core[core::SEQUENCE] += Fp::ONE;
    after.core[core::STATE_NONCE] += Fp::ONE;
    // This component checks the merged leaf, not a pending-map removal or ancestry.
    after.statement = [Fp::ZERO; 26];
    after.statement[0] = Fp::ONE;
    after.statement[14] = before.lineage[5];
    after.statement[16] = Fp::from(5);
    after.statement[17] = Fp::from(181);
    after.statement[18] = Fp::from(182);
    bootstrap::rebind(&mut after);
    ArchiveWitness {
        predecessor: StateWitness::from(&before),
        successor: StateWitness::from(&after),
        statement: after.statement,
    }
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
    own: bootstrap_objects::Signed,
    // Original Request, quoted receiver credential and incoming receipt.
    incoming: [Vec<u8>; 3],
    context: ContextPlan,
    instances: Vec<Vec<Fq>>,
    proof: Vec<u8>,
    schema: QSignaturePlan,
    valid: bool,
}
fn sources(valid: bool) -> Sources {
    let witness = transition();
    // sigma_archive is produced natively and named by the receipt's proof digest.
    // A proves the step inline and never verifies it, so an opaque stand-in suffices.
    let own = receipt(&witness, &[0x5a; 96]);
    let mut before = witness.predecessor;
    before.core[core::BALANCE] = Fp::from(100);
    let send = send_objects::from_load(&before);
    let receiver = send_objects::receiver_credential();
    let mut incoming = bootstrap_objects::sign(
        ObjectKind::Receipt,
        own.bytes[..ObjectKind::Receipt.body_len()].to_vec(),
        43,
        83,
    );
    if !valid {
        incoming.signature.signature[0] = [0; 4];
        incoming.bytes[ObjectKind::Receipt.body_len()..ObjectKind::Receipt.body_len() + 32].fill(0);
    }
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let schema = ArchiveAuthorizationObjects::signature_schema().unwrap();
    let circuit =
        QSignatureCircuit::new(schema.clone(), vec![own.signature, incoming.signature]).unwrap();
    let instances = circuit.instances(&[true, valid]).unwrap().to_vec();
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
        common::fresh_randomness(),
        ProverConfig::default(),
    )
    .unwrap()
    .proof;
    accumulate_generator(
        &p,
        key.binding(),
        key.vk(),
        &instances,
        &proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap()
    .decide(&p, MemoryBudget::DEFAULT)
    .unwrap();
    // Lean: A proves the own step inline and Status has no Q_sigma, so the
    // merged leaf is the only Q. The predecessor is constructor metadata.
    let operation = AProofPlan::inline(
        Variant::ArchiveStatus,
        vec![
            QProofPlan::new(
                VerifierPlan::new(key.binding().clone(), p.clone()).unwrap(),
                key.vk().clone(),
            )
            .unwrap(),
        ],
        Some(predecessor_metadata()),
        &p,
    )
    .unwrap();
    // Only the merged leaf and its two owners execute here. Other named owners
    // are constructor metadata with explicit dummy context categories; this
    // component cannot authenticate a complete Archive or a lineage head.
    let mut specs = (1..=11)
        .map(|tag| ContextObjectSpec { tag, capacity: 32 })
        .collect::<Vec<_>>();
    specs[0] = ArchiveAuthorizationObjects::context_specs().unwrap()[0];
    for (index, spec) in INCOMING_SLOTS
        .into_iter()
        .zip(ArchiveIncomingObjects::context_specs().unwrap())
    {
        specs[index] = spec;
    }
    specs.push(ArchiveResultPlan::context_spec(Variant::ArchiveStatus, 12).unwrap());
    let context =
        ContextPlan::with_schedule(operation, vec![vec![], vec![0], vec![]], Some(0), specs)
            .unwrap()
            .with_operation_tasks(vec![
                vec![
                    OperationTask::ArchiveRetainedPayment,
                    OperationTask::ArchiveEvidence,
                    OperationTask::ArchiveProofs,
                ],
                vec![
                    OperationTask::ArchiveSignatures,
                    OperationTask::ArchiveAuthorization,
                ],
                vec![
                    OperationTask::ArchiveEffects,
                    OperationTask::ArchiveRetainedProofs,
                    OperationTask::ArchiveCorePending,
                    OperationTask::ArchiveLineagePending,
                ],
            ])
            .unwrap();
    Sources {
        witness,
        own,
        incoming: [send.objects[1].clone(), receiver.bytes, incoming.bytes],
        context,
        instances,
        proof,
        schema,
        valid,
    }
}
#[derive(Clone)]
struct Owner {
    source: Arc<Sources>,
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
    fn own(&self) -> bootstrap_objects::Signed {
        let mut own = self.source.own.clone();
        match self.mutation {
            1 => own.bytes[40] ^= 1,
            2 => own.bytes[ObjectKind::Receipt.body_len()] ^= 1,
            _ => {}
        }
        own
    }
    fn originals(&self) -> [Vec<u8>; 3] {
        let mut originals = self.source.incoming.clone();
        match self.mutation {
            3 => originals[2][40] ^= 1,
            4 => originals[2][ObjectKind::Receipt.body_len() + 17] ^= 1,
            5 => {
                // A genuinely different quoted credential plus a matching
                // Request address still cannot change the leaf's verified key.
                let key = bootstrap_objects::sec1(bootstrap_objects::key(19));
                originals[1][130..195].copy_from_slice(&key);
                let changed = bootstrap_objects::Signed {
                    kind: ObjectKind::Credential,
                    bytes: originals[1].clone(),
                    signature: self.source.own.signature,
                }
                .digest();
                originals[0][210..242].copy_from_slice(&changed.to_repr());
            }
            _ => {}
        }
        originals
    }
    fn public(&self) -> [Vec<Fp>; 1] {
        let mut out = vec![self.own().digest()];
        out.extend(
            self.originals()
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
                        signature: self.source.own.signature,
                    }
                    .digest()
                }),
        );
        [out]
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
        let public = meta.instance_column(4);
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
            || "Archive merged signature leaf owners",
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
                let raw = self
                    .own()
                    .bytes
                    .into_iter()
                    .map(|b| self.value(b))
                    .collect::<Vec<_>>();
                let own = ArchiveAuthorizationObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut r,
                    Variant::ArchiveStatus,
                    [raw.as_slice()],
                )?;
                let originals = self.originals();
                let raw = originals
                    .each_ref()
                    .map(|raw| raw.iter().map(|b| self.value(*b)).collect::<Vec<_>>());
                let incoming = ArchiveIncomingObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut r,
                    raw.each_ref().map(Vec::as_slice),
                )?;
                let mut instances = source.instances.clone();
                if self.mutation == 8 {
                    // The soft incoming verdict is the leaf's last exported word.
                    let last = instances[0].len() - 1;
                    instances[0][last] = Fq::from(u64::from(!source.valid));
                }
                let q_instances = vec![
                    instances
                        .iter()
                        .map(|c| {
                            c.iter()
                                .map(|v| self.scalar(&mut chip, &mut r, *v))
                                .collect()
                        })
                        .collect::<Result<Vec<Vec<_>>, Error>>()?,
                ];
                let point = iroha_plonk::transcript::decode_point::<Ep>(
                    &iroha_plonk_recursion::PALLAS_TRIVIAL_GENERATOR,
                )
                .map_err(|_| Error::Synthesis)?;
                let point = chip.constant_generator(&mut r, &Ep::from(point))?;
                let one = self.scalar(&mut chip, &mut r, Fq::ONE)?;
                let pallas = FoldInputCells::from_normalized(
                    &mut chip,
                    &mut r,
                    16,
                    point,
                    ::core::array::from_fn(|_| one.clone()),
                )?;
                let vesta = VestaClaimCells::trivial(&mut chip, &mut r)?;
                let results = ArchiveResultClaims::assign(
                    &mut chip,
                    &mut r,
                    ArchiveResultPlan::new(&source.context, RESULT_SLOT)?,
                    [
                        true,
                        true,
                        if self.mutation == 12 {
                            !source.valid
                        } else {
                            source.valid
                        },
                    ]
                    .map(|v| self.value(v)),
                    Some(&pallas),
                )?;
                let zero = chip.uint().glue().constant(&mut r, Fp::ZERO)?;
                let mut contexts = Vec::new();
                for (index, spec) in source.context.object_specs().iter().enumerate() {
                    let actual = if index == 0 {
                        own.context()[0].clone()
                    } else if let Some(i) = INCOMING_SLOTS.iter().position(|i| *i == index) {
                        incoming.context()[i].clone()
                    } else if index == RESULT_SLOT {
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
                match self.mutation {
                    13 => contexts.swap(1, 4),
                    14 => contexts.swap(0, 2),
                    _ => {}
                }
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
                    objects: &contexts,
                    modes: &[],
                    pallas_corrections: &[],
                    vesta_corrections: &[],
                    receive_results: None,
                };
                let mut raw = source.proof.clone();
                if self.mutation == 6 {
                    raw[32] ^= 1;
                }
                if self.mutation == 7 {
                    raw.pop();
                }
                let proof = self.proof(&mut chip, &mut bytes, &mut r, &raw)?;
                let q = verify_q(
                    &mut chip,
                    &mut r,
                    source.context.operation(),
                    0,
                    &q_instances[0],
                    &proof,
                )?;
                let bundle = bind_signature_q(
                    &mut chip,
                    &mut r,
                    source.context.operation(),
                    0,
                    &source.schema,
                    &q,
                )?;
                let stage = if self.mutation == 10 {
                    LEAF_STAGE + 1
                } else {
                    LEAF_STAGE
                };
                let policy = if self.mutation == 11 {
                    OwnPolicy::new([33, 34], bootstrap_objects::key(23)).unwrap()
                } else {
                    policy()
                };
                own.constrain_current(
                    &mut chip,
                    &mut r,
                    &source.context,
                    stage,
                    &input,
                    (policy, &bundle),
                )?;
                incoming.constrain_signature(
                    &mut r,
                    &source.context,
                    stage,
                    &input,
                    &results,
                    &bundle,
                )?;
                let mut out = vec![own.context()[0].authenticated_digest().clone()];
                out.extend(
                    incoming
                        .context()
                        .iter()
                        .map(|o| o.authenticated_digest().clone()),
                );
                Ok(out)
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
    let w = transition();
    let c = ArchiveCircuit::new(&w);
    assert!(
        check_circuit(&c, 12, &c.instances(), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let schema = ArchiveAuthorizationObjects::signature_schema().unwrap();
    assert_eq!(
        schema
            .slots()
            .iter()
            .map(|slot| slot.mode)
            .collect::<Vec<_>>(),
        [VerifyMode::Hard, VerifyMode::Soft]
    );
}
#[test]
#[ignore = "genuine merged-leaf Q proofs plus strict original-source owner mutations"]
fn genuine_archive_merged_leaf_binds_own_receipt_hard_and_incoming_receipt_soft() {
    for valid in [true, false] {
        let c = Owner {
            source: Arc::new(sources(valid)),
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
            "ARCHIVE_MERGED_LEAF_COMPONENT signature_valid={valid} proof_bytes={} rows={:?} full_chain=false",
            c.source.proof.len(),
            known
                .tables
                .advice_assigned()
                .iter()
                .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
                .collect::<Vec<_>>()
        );
        for mutation in 1..=14 {
            let bad = Owner {
                mutation,
                ..c.clone()
            };
            assert!(
                !check_circuit(&bad, 16, &bad.public(), CheckMode::Strict)
                    .is_ok_and(|r| r.is_satisfied()),
                "valid{valid} mutation{mutation}"
            );
        }
    }
}
