//! Genuine Receive step relation, incoming-only sigma Q, merged signature leaf and
//! depth32 accept/burn map composition (lean lineage: A proves the own step inline).
//!
//! These are source and map components. They do not authenticate a predecessor
//! Omega or authorize the terminal branch without the four fixed A result owners.

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
mod common;
#[path = "common/load_objects.rs"]
#[allow(dead_code)]
mod load_objects;
#[path = "common/receive_objects.rs"]
mod receive_objects;
#[path = "common/send_objects.rs"]
#[allow(dead_code)]
mod send_objects;

use ff::Field;
use iroha_kagemusha_proof::{
    Mutation, PrefixMode, RelationShape, SigmaProver, SigmaRelation, StepWitness,
    a_relation::{
        LineagePublicCells, QProofPlan, own::OwnPolicy, receive::ReceiveStagePlan,
        schedule::sigma_selector, transition::TransitionInputs,
    },
    admin_sigma::StateWitness,
    operation_relation::{
        map_effects::{InsertCells, MapEffectsChip, MapState, MapTransition, ReceiveMapWitness},
        objects::ObjectKind,
        state::StateCells,
        statement::StatementCells,
    },
    q_sigma::{
        QSigmaPlan, SigmaClass, SigmaSlotWitness,
        native::{IncomingMode, IncomingSigma, QSigmaProver},
    },
    q_signature::{QSignatureCircuit, SLOT_WORDS, SignatureKey, SignatureSlot, SignatureWitness},
    sample_witness,
    tree::IndexedInsert,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig,
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{
        AssignedTables, Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize,
    },
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    UintChip,
    imt::{LeafCells, OpeningCells, PathCells},
    p256::VerifyMode,
    statement::STATEMENT_DOMAIN,
};
use iroha_plonk_recursion::{
    FoldConfig, FoldInput,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};

#[derive(Clone)]
struct Maps {
    witness: receive_objects::ReceiveFixture,
    known: bool,
    verdict: bool,
}
#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    public: Column<Instance>,
}
impl Maps {
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn state(
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
    fn insertion(
        &self,
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        witness: &IndexedInsert<Fp>,
    ) -> Result<InsertCells, Error> {
        let leaf = witness.leaf;
        let words = uint
            .glue()
            .witnesses(
                region,
                &[leaf.key, leaf.value, leaf.next_key].map(|v| self.value(v)),
            )?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let mut paths = Vec::new();
        for (index, siblings) in [
            (witness.leaf_slot, witness.leaf_siblings),
            (witness.slot, witness.slot_siblings),
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
            low: OpeningCells {
                leaf: LeafCells::from_words(words),
                path: low,
            },
            slot,
        })
    }
}
impl Circuit<Fp> for Maps {
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
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        Config { verifier, public }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        let result = layouter.assign_region(
            || "genuine Receive maps",
            |mut region| {
                let (before, pred) = self.state(&mut chip, &mut region, &self.witness.before)?;
                let (after, next) = self.state(&mut chip, &mut region, &self.witness.after)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &self.witness.statement.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    Variant::Receive,
                    &fields,
                )?;
                let consumed =
                    self.insertion(&mut chip.uint(), &mut region, &self.witness.consumed)?;
                let credit = self.insertion(&mut chip.uint(), &mut region, &self.witness.credit)?;
                let mut uint = chip.uint();
                let inserted_key = uint
                    .glue()
                    .witness(&mut region, self.value(self.witness.statement[17]))?;
                let inserted_value = uint.glue().witness(
                    &mut region,
                    self.value(iroha_pasta::poseidon::hash_with_domain(
                        iroha_kagemusha_proof::operation_relation::map_effects::CONSUMED_DOMAIN,
                        &[
                            self.witness.statement[17],
                            self.witness.statement[20],
                            self.witness.statement[9],
                        ],
                    )),
                )?;
                let insert_word = uint.glue().witness(
                    &mut region,
                    self.value(Fp::from(u64::from(self.witness.insert))),
                )?;
                let insert = uint.glue().assert_bool(&mut region, &insert_word)?;
                let payment_digest = uint
                    .glue()
                    .witness(&mut region, self.value(self.witness.payment))?;
                let verdict = uint
                    .glue()
                    .witness(&mut region, self.value(Fp::from(u64::from(self.verdict))))?;
                let verdict = uint.glue().assert_bool(&mut region, &verdict)?;
                let witness = ReceiveMapWitness {
                    consumed,
                    credit,
                    inserted_key,
                    inserted_value,
                    insert,
                    payment_digest,
                };
                let lanes = chip.operation_lanes()?;
                let transition = MapTransition {
                    statement: &statement,
                    predecessor: MapState {
                        state: &before,
                        lineage: &pred,
                    },
                    successor: MapState {
                        state: &after,
                        lineage: &next,
                    },
                };
                // This component exposes the terminal verdict publicly. Full A must
                // derive it from the four fixed result owners before calling receive.
                let mut maps = MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash);
                maps.receive(&mut region, &transition, &witness, &verdict)?;
                Ok([statement.digest().clone(), verdict.word().clone()])
            },
        )?;
        for (i, word) in result.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}
fn fixture(
    valid: bool,
    insert: bool,
) -> (send_objects::SendFixture, receive_objects::ReceiveFixture) {
    let (payer, _, _) = bootstrap_objects::enrollment();
    let (loaded, _, _) = load_objects::funded(&payer);
    let send = send_objects::from_load(&loaded.successor);
    let (receiver, _, _) = receive_objects::receiver();
    let receive = receive_objects::from_send(
        &send,
        &StateWitness::from(&receiver),
        Fp::from(401),
        valid,
        insert,
    );
    (send, receive)
}
fn public(circuit: &Maps) -> Vec<Vec<Fp>> {
    vec![vec![
        iroha_pasta::poseidon::hash_with_domain(
            iroha_plonk_gadgets::statement::STATEMENT_DOMAIN,
            &circuit.witness.statement,
        ),
        Fp::from(u64::from(circuit.verdict)),
    ]]
}
#[test]
fn real_request_receive_accept_and_burn_preserve_core_and_adjusted_maps() {
    for (valid, insert) in [(true, true), (false, true), (false, false)] {
        let (_, witness) = fixture(valid, insert);
        let circuit = Maps {
            witness,
            known: true,
            verdict: valid,
        };
        let report = check_circuit(&circuit, 16, &public(&circuit), CheckMode::Strict).unwrap();
        assert!(
            report.is_satisfied(),
            "{:?}",
            &report.failures()[..report.failures().len().min(8)]
        );
        let known = synthesize(&circuit, 16, None).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        let rows: Vec<_> = known
            .tables
            .advice_assigned()
            .iter()
            .map(|column| column.iter().rposition(|v| *v).map_or(0, |r| r + 1))
            .collect();
        eprintln!("Receive genuine map valid={valid} insert={insert} lanes={rows:?}");
        for mutation in 0..7 {
            let mut changed = circuit.clone();
            match mutation {
                0 => changed.verdict = !valid,
                1 => changed.witness.after.lineage[14] += Fp::ONE,
                2 => changed.witness.after.lineage[16] += Fp::ONE,
                3 => changed.witness.credit.leaf_siblings[31] += Fp::ONE,
                4 => changed.witness.consumed.leaf_siblings[0] += Fp::ONE,
                5 => changed.witness.payment += Fp::ONE,
                _ => changed.witness.statement[17] += Fp::ONE,
            }
            assert!(
                !check_circuit(&changed, 16, &public(&changed), CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "valid={valid} insert={insert} mutation={mutation}"
            );
        }
    }
}

/// The own Receive step relation A1 lays out inline (`ReceiveTransition`) against
/// the validated own statement, whose digest is the only public input. Without
/// the relation only the statement's self-contained field rules remain.
#[derive(Clone)]
struct InlineStep {
    variant: Variant,
    statement: [Fp; 26],
    step: StepWitness<Fp>,
    known: bool,
    relation: bool,
}
impl InlineStep {
    fn new(variant: Variant, fixture: &receive_objects::ReceiveFixture) -> Self {
        Self {
            variant,
            statement: fixture.statement,
            step: fixture.step.clone(),
            known: true,
            relation: true,
        }
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        vec![vec![hash_with_domain(STATEMENT_DOMAIN, &self.statement)]]
    }
    fn satisfied(&self) -> bool {
        check_circuit(self, 16, &self.public(), CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
}
impl Circuit<Fp> for InlineStep {
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
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        Config { verifier, public }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        chip.load_tables(&mut layouter)?;
        // The native evaluation the A1 source retains beside its step; key
        // generation lays out the same relation without either.
        let native = self.step.evaluate(SigmaRelation::RECEIVE);
        let digest = layouter.assign_region(
            || "inline Receive step relation",
            |mut region| {
                let values = self.statement.map(|v| {
                    if self.known {
                        Value::known(v)
                    } else {
                        Value::unknown()
                    }
                });
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &values)?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    self.variant,
                    &fields,
                )?;
                if self.relation {
                    TransitionInputs {
                        shape: RelationShape::new(SigmaRelation::RECEIVE, PrefixMode::Absorbed),
                        witness: self.known.then_some((&self.step, &native)),
                    }
                    .constrain(&mut chip, &mut region, &statement)?;
                }
                Ok(statement.digest().clone())
            },
        )?;
        layouter.constrain_instance(digest.cell(), config.public, 0)
    }
}
fn max_rows(tables: &AssignedTables<Fp>) -> usize {
    tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().rposition(|v| *v).map_or(0, |r| r + 1))
        .max()
        .unwrap_or(0)
}
/// A genuine own Receive step. Ordinary Receive quotes the receiver's current
/// credential and accepts with a consumed insertion; renewed quotes the
/// re-signed credential and burns without one, so both statement shapes occur.
fn step_fixture(variant: Variant) -> receive_objects::ReceiveFixture {
    let (payer, _, _) = bootstrap_objects::enrollment();
    let (loaded, _, _) = load_objects::funded(&payer);
    let renewed = variant == Variant::ReceiveRenewed;
    let send = if renewed {
        send_objects::from_load_with_receiver_credential(
            &loaded.successor,
            &receive_objects::renewed_credential(),
        )
    } else {
        send_objects::from_load(&loaded.successor)
    };
    let (receiver, _, _) = receive_objects::receiver();
    receive_objects::from_send(
        &send,
        &StateWitness::from(&receiver),
        Fp::from(401),
        !renewed,
        !renewed,
    )
}

/// A1's inline relation proves exactly the statement `σ_recv` certifies, for
/// genuine ordinary and renewed witnesses; it lays out the same cells without
/// a witness, and refuses another honest step, an overflowing step and a Send step.
#[test]
fn receive_transition_binds_the_genuine_own_statement_inline() {
    let shape = common::pinned_shape(common::folded(SigmaRelation::RECEIVE), (12, 1));
    for variant in [Variant::Receive, Variant::ReceiveRenewed] {
        let fixture = step_fixture(variant);
        let native = fixture.step.evaluate(SigmaRelation::RECEIVE);
        assert!(native.is_honest(), "{variant:?} {:?}", native.violations);
        assert_eq!(native.statement, fixture.statement);
        // σ_recv's single public input is the digest of exactly these fields.
        assert_eq!(
            native.public().instance(),
            [hash_with_domain(STATEMENT_DOMAIN, &fixture.statement)]
        );
        assert!(common::check_witness(&shape, &fixture.step).is_satisfied());
        let circuit = InlineStep::new(variant, &fixture);
        let report = check_circuit(&circuit, 16, &circuit.public(), CheckMode::Strict).unwrap();
        assert!(
            report.is_satisfied(),
            "{variant:?} {:?}",
            &report.failures()[..report.failures().len().min(8)]
        );
        let known = synthesize(&circuit, 16, None).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        let bare = InlineStep {
            relation: false,
            ..circuit.clone()
        };
        let bare = synthesize(&bare, 16, None).unwrap();
        eprintln!(
            "RECEIVE_TRANSITION {variant:?} rows_with_relation={} rows_statement_only={} known_unknown_layout_equal=true",
            max_rows(&known.tables),
            max_rows(&bare.tables)
        );
        for (case, step) in [
            (
                "another honest Receive step",
                sample_witness::<Fp>(99, SigmaRelation::RECEIVE, Mutation::None),
            ),
            (
                "an overflowing receiver balance",
                sample_witness::<Fp>(1, SigmaRelation::RECEIVE, Mutation::Overflow),
            ),
            (
                "a Send step",
                sample_witness::<Fp>(5, SigmaRelation::SEND, Mutation::None),
            ),
        ] {
            let wrong = InlineStep {
                step,
                ..circuit.clone()
            };
            assert!(!wrong.satisfied(), "{variant:?} accepted {case}");
        }
    }
}

/// Every single own-statement field substitution is refused by A1's inline
/// relation, while the statement rules alone accept a substituted credential,
/// predecessor or successor commitment or credit id: only the relation binds them.
#[test]
#[ignore = "all 26 own-statement fields of both Receive variants at k16; run optimized"]
fn receive_transition_rejects_every_single_statement_field_mutation() {
    for variant in [Variant::Receive, Variant::ReceiveRenewed] {
        let circuit = InlineStep::new(variant, &step_fixture(variant));
        assert!(circuit.satisfied(), "{variant:?} genuine");
        for field in 0..circuit.statement.len() {
            let mut changed = circuit.clone();
            changed.statement[field] += Fp::ONE;
            assert!(!changed.satisfied(), "{variant:?} statement field{field}");
        }
        for field in [7, 14, 15, 17] {
            let mut bare = InlineStep {
                relation: false,
                ..circuit.clone()
            };
            bare.statement[field] += Fp::ONE;
            assert!(
                bare.satisfied(),
                "{variant:?} statement rules alone, field{field}"
            );
        }
        eprintln!(
            "RECEIVE_TRANSITION {variant:?} all_26_single_field_mutations_rejected=true relation_only_fields=[7,14,15,17]"
        );
    }
}

/// Genuine signatures for every slot of the merged Receive Q1, own receipt
/// first: the own receipt under the receiver payment key, the Send receipt
/// under the payer key and the Request under the quoted receiver key; renewed
/// adds the quoted credential under its issuer key and the certificate under
/// the root. Slot semantics are bound by A's owners, not by these bodies.
fn merged_signatures(variant: Variant) -> Vec<SignatureWitness> {
    let sign = |kind: ObjectKind, fill: u8, secret: u64, nonce: u64| {
        bootstrap_objects::sign(kind, vec![fill; kind.body_len()], secret, nonce).signature
    };
    let receiver = bootstrap_objects::Identity::Receiver.secret();
    let payer = bootstrap_objects::Identity::Payer.secret();
    let mut signatures = vec![
        sign(ObjectKind::Receipt, 1, receiver, 73),
        sign(ObjectKind::Receipt, 2, payer, 71),
        sign(ObjectKind::Request, 3, receiver, 59),
    ];
    if variant == Variant::ReceiveRenewed {
        let (_, certificate, _) = receive_objects::receiver();
        signatures.extend([
            receive_objects::renewed_credential().signature,
            certificate.signature,
        ]);
    }
    signatures
}

/// Merged Q1 keeps the own receipt hard in slot 0: a malformed own receipt has
/// no native Q1 export at all, while each malformed incoming slot exports only
/// its own false soft verdict.
#[test]
fn merged_signature_leaf_refuses_a_bad_own_receipt_and_keeps_incoming_slots_soft() {
    let policy = OwnPolicy::new([31, 32], bootstrap_objects::key(23)).unwrap();
    for (variant, slots) in [(Variant::Receive, 3), (Variant::ReceiveRenewed, 5)] {
        let schema = ReceiveStagePlan::signature_schema_for(variant, policy).unwrap();
        assert_eq!(schema.slots().len(), slots);
        assert_eq!(
            schema.slots()[0],
            SignatureSlot {
                mode: VerifyMode::Hard,
                key: SignatureKey::Variable,
            }
        );
        assert!(
            schema.slots()[1..]
                .iter()
                .all(|slot| slot.mode == VerifyMode::Soft)
        );
        let witnesses = merged_signatures(variant);
        let verdicts = |witnesses: &[SignatureWitness]| {
            schema.native_instances(witnesses).map(|[public]| {
                public
                    .chunks_exact(SLOT_WORDS)
                    .map(|slot| slot[SLOT_WORDS - 1])
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(verdicts(&witnesses[..]).unwrap(), vec![Fq::ONE; slots]);
        let mut forged = witnesses.clone();
        forged[0].signature[1][0] ^= 1;
        assert!(
            verdicts(&forged[..]).is_err(),
            "{variant:?} malformed own receipt in merged slot 0"
        );
        for slot in 1..slots {
            let mut malformed = witnesses.clone();
            malformed[slot].signature[1][0] ^= 1;
            let mut expected = vec![Fq::ONE; slots];
            expected[slot] = Fq::ZERO;
            assert_eq!(
                verdicts(&malformed[..]).unwrap(),
                expected,
                "{variant:?} soft incoming slot{slot}"
            );
        }
    }
}

/// The k16 merged leaves constrain the same split: no claimed verdict satisfies
/// a malformed own receipt, and a malformed incoming slot is satisfiable only
/// with its false soft verdict.
#[test]
#[ignore = "merged 3V and 4V1F Receive signature leaves at k16; run optimized"]
fn merged_signature_leaf_circuit_constrains_the_own_slot_hard_and_incoming_slots_soft() {
    let policy = OwnPolicy::new([31, 32], bootstrap_objects::key(23)).unwrap();
    for variant in [Variant::Receive, Variant::ReceiveRenewed] {
        let schema = ReceiveStagePlan::signature_schema_for(variant, policy).unwrap();
        let witnesses = merged_signatures(variant);
        let satisfied = |witnesses: &[SignatureWitness], verdicts: &[bool]| {
            let circuit = QSignatureCircuit::new(schema.clone(), witnesses.to_vec()).unwrap();
            let public = circuit.instances(verdicts).unwrap().to_vec();
            check_circuit(&circuit, 16, &public, CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
        };
        let genuine = vec![true; witnesses.len()];
        assert!(
            satisfied(&witnesses[..], &genuine[..]),
            "{variant:?} genuine leaf"
        );
        let mut forged = witnesses.clone();
        forged[0].signature[1][0] ^= 1;
        let mut disowned = genuine.clone();
        disowned[0] = false;
        for claimed in [&genuine, &disowned] {
            assert!(
                !satisfied(&forged[..], &claimed[..]),
                "{variant:?} malformed own receipt in merged slot 0"
            );
        }
        let mut malformed = witnesses.clone();
        malformed[1].signature[1][0] ^= 1;
        let mut soft = genuine.clone();
        soft[1] = false;
        assert!(
            satisfied(&malformed[..], &soft[..]),
            "{variant:?} malformed Send receipt stays soft"
        );
        assert!(
            !satisfied(&malformed[..], &genuine[..]),
            "{variant:?} malformed Send receipt cannot claim true"
        );
        let rows = synthesize(
            &QSignatureCircuit::new(schema.clone(), witnesses.clone()).unwrap(),
            16,
            None,
        )
        .unwrap()
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().rposition(|v| *v).map_or(0, |r| r + 1))
        .max()
        .unwrap_or(0);
        eprintln!(
            "RECEIVE_MERGED_Q1 {variant:?} slots={} rows={rows} own_slot_hard=true incoming_slots_soft=true",
            witnesses.len()
        );
    }
}

/// Real own Receive step and incoming-only Send sigma Q source; its global mode
/// remains subject to A's complete four-result rule, not selected by this
/// constructor. A proves the own step inline (`ReceiveTransition`); the own
/// `σ_recv` is still produced from the same step, because the own receipt signs
/// its digest and the payer's `ArchiveReceive` verifies it.
#[allow(dead_code)]
pub(crate) struct ReceiveQ {
    pub(crate) witness: receive_objects::ReceiveFixture,
    pub(crate) send: send_objects::SendFixture,
    /// Actual own `σ_recv`, retained but never verified by the Receive A.
    pub(crate) sigma: Vec<u8>,
    pub(crate) incoming_sigma: Vec<u8>,
    /// Incoming-only `Q_sigma`: one soft Send slot folded with the pinned trivial claim.
    pub(crate) sigma_plan: QSigmaPlan,
    pub(crate) q: QProofPlan,
    pub(crate) key: iroha_plonk::VerifyingKey<Ep>,
    pub(crate) proof: Vec<u8>,
    pub(crate) instances: Vec<Vec<Fq>>,
    pub(crate) opening: FoldInput<Ep>,
    pub(crate) part: FoldInput<Eq>,
}
pub(crate) fn genuine_receive_source(valid: bool, insert: bool, mode: IncomingMode) -> ReceiveQ {
    let (receiver, _, _) = receive_objects::receiver();
    genuine_receive_source_for(&StateWitness::from(&receiver), valid, insert, mode)
}
/// Generate the same real source relation for an authenticated receiver head.
pub(crate) fn genuine_receive_source_for(
    before: &StateWitness,
    valid: bool,
    insert: bool,
    mode: IncomingMode,
) -> ReceiveQ {
    let (payer, _, _) = bootstrap_objects::enrollment();
    let (loaded, _, _) = load_objects::funded(&payer);
    genuine_receive_source_for_heads(before, &loaded.successor, valid, insert, mode)
}

/// Generate both real sigma sources for the exact independently authenticated
/// receiver and payer heads. This keeps the incoming Send state commitment tied
/// to the payer's actual Load Omega instead of a separately constructed fixture.
pub(crate) fn genuine_receive_source_for_heads(
    before: &StateWitness,
    payer: &StateWitness,
    valid: bool,
    insert: bool,
    mode: IncomingMode,
) -> ReceiveQ {
    genuine_receive_source_for_send(
        before,
        send_objects::from_load(payer),
        valid,
        insert,
        mode,
        true,
    )
}

/// Generate real sources for an exact Request carrying a supplied quoted credential.
#[allow(dead_code)] // Used by the recursive fixture which includes this module.
pub(crate) fn genuine_receive_source_for_quoted(
    before: &StateWitness,
    payer: Option<&StateWitness>,
    quoted_bytes: &[u8],
    valid: bool,
    insert: bool,
    mode: IncomingMode,
) -> ReceiveQ {
    let (enrolled, _, _) = bootstrap_objects::enrollment();
    let (loaded, _, _) = load_objects::funded(&enrolled);
    let payer = payer.unwrap_or(&loaded.successor);
    let quoted = bootstrap_objects::sign(
        iroha_kagemusha_proof::operation_relation::objects::ObjectKind::Credential,
        quoted_bytes[..iroha_kagemusha_proof::operation_relation::objects::ObjectKind::Credential
            .body_len()]
            .to_vec(),
        17,
        79,
    );
    assert_eq!(quoted.bytes, quoted_bytes);
    genuine_receive_source_for_send(
        before,
        send_objects::from_load_with_receiver_credential(payer, &quoted),
        valid,
        insert,
        mode,
        true,
    )
}

/// Reject an altered incoming sigma with the actual total Q verifier. The local
/// Send fixture supplies only adversarial bytes; no funded payer lineage is
/// authenticated or admitted by this burn-only constructor.
pub(crate) fn genuine_receive_source_with_invalid_sigma(before: &StateWitness) -> ReceiveQ {
    let (payer, _, _) = bootstrap_objects::enrollment();
    let (loaded, _, _) = load_objects::funded(&payer);
    genuine_receive_source_for_send(
        before,
        send_objects::from_load(&loaded.successor),
        false,
        false,
        IncomingMode::Trivial,
        false,
    )
}

fn genuine_receive_source_for_send(
    before: &StateWitness,
    send: send_objects::SendFixture,
    valid: bool,
    insert: bool,
    mode: IncomingMode,
    incoming_valid: bool,
) -> ReceiveQ {
    let witness = receive_objects::from_send(&send, before, Fp::from(401), valid, insert);
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let vparams = common::vesta_params(16);
    // The wallet still proves σ_recv natively: the own receipt signs its digest
    // and the payer's ArchiveReceive verifies it. Receive A never verifies it.
    let own = SigmaProver::<Eq>::keygen_with_params(
        common::pinned_shape(common::folded(SigmaRelation::RECEIVE), (12, 1)),
        common::vesta_params(12),
    )
    .unwrap();
    let incoming = SigmaProver::<Eq>::keygen_with_params(
        common::pinned_shape(common::folded(SigmaRelation::SEND), (12, 1)),
        common::vesta_params(12),
    )
    .unwrap();
    let own_proof = own
        .prove(&witness.step, common::fresh_randomness())
        .unwrap();
    // σ_recv certifies exactly the statement digest whose fields A1's inline
    // relation binds, so dropping its re-verification loses no own constraint.
    assert_eq!(
        own_proof.public.instance(),
        [hash_with_domain(STATEMENT_DOMAIN, &witness.statement)]
    );
    let incoming_proof = incoming
        .prove(&send.step, common::fresh_randomness())
        .unwrap();
    let mut incoming_sigma = incoming_proof.bytes;
    if !incoming_valid {
        // The first commitment encoding is noncanonical in either Pasta field;
        // the total incoming verifier must export false, not a deferred claim.
        incoming_sigma[..32].fill(0xff);
    }
    let incoming_verifier = incoming.verifier();
    let sigma_plan = QSigmaPlan::incoming_only(
        SigmaClass::from_verifiers(&[(sigma_selector(3, 0).unwrap(), &incoming_verifier)]).unwrap(),
        &vparams,
    )
    .unwrap();
    assert!(!sigma_plan.has_own());
    assert_eq!(sigma_plan.position(QSigmaPlan::INCOMING), Some(0));
    assert_eq!(sigma_plan.part_source_k(), 16);
    let prepared = sigma_plan
        .prepare(
            None,
            Some(IncomingSigma {
                sigma: SigmaSlotWitness {
                    key: incoming.proving_key().vk().clone(),
                    statement: incoming_proof.public.instance()[0],
                    length: incoming_sigma.len().try_into().unwrap(),
                    proof: incoming_sigma.clone(),
                },
                mode,
            }),
            &vparams,
            iroha_kagemusha_proof::q_sigma::native::QSigmaFoldSource::Fresh(
                common::public_fixture_tape(243),
            ),
            &FoldConfig::default(),
        )
        .unwrap();
    let q = QSigmaProver::keygen_serialized_foreign(&prepared, params.clone(), 2).unwrap();
    let proof = q
        .prove(
            &prepared,
            common::fresh_randomness(),
            ProverConfig::default(),
        )
        .unwrap();
    let claim = accumulate_generator(
        &params,
        q.binding(),
        q.verifying_key(),
        &proof.instances,
        &proof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    claim.decide(&params, MemoryBudget::DEFAULT).unwrap();
    prepared
        .part()
        .decide(&vparams, MemoryBudget::DEFAULT)
        .unwrap();
    // One incoming slot: its Send selector, then its soft verdict and the
    // one-hot Accept/Trivial/Corrected mode. No own row precedes it.
    assert_eq!(proof.instances[2], [Fq::from(2)]);
    let mut verdict_and_mode = vec![Fq::from(u64::from(incoming_valid))];
    verdict_and_mode.extend(
        match mode {
            IncomingMode::Accept => [1_u64, 0, 0],
            IncomingMode::Trivial => [0, 1, 0],
            IncomingMode::Corrected => [0, 0, 1],
        }
        .map(Fq::from),
    );
    assert_eq!(proof.instances[3], verdict_and_mode);
    assert_eq!(proof.instances[4], [Fq::from(16)]);
    eprintln!(
        "Receive genuine own_sigma={} (retained, inline in A) incoming_sigma={} Q={} sourcek={} mode={mode:?}",
        own_proof.bytes.len(),
        incoming_sigma.len(),
        proof.bytes.len(),
        prepared.part().source_k()
    );
    ReceiveQ {
        witness,
        send,
        sigma: own_proof.bytes,
        incoming_sigma,
        sigma_plan,
        key: q.verifying_key().clone(),
        q: QProofPlan::new(
            VerifierPlan::new(q.binding().clone(), params).unwrap(),
            q.verifying_key().clone(),
        )
        .unwrap(),
        proof: proof.bytes,
        instances: proof.instances,
        opening: FoldInput::from_opening(*claim.g(), claim.challenges()).unwrap(),
        part: prepared.part().clone(),
    }
}
impl ReceiveQ {
    /// Bind the immutable credit-record witness after deriving the Payment from
    /// actual incoming proof/receipt tapes. Sigma does not read this adjusted
    /// lineage root; its complete state and statement must remain identical.
    #[allow(dead_code)] // Used by the recursive fixture which includes this module.
    pub(crate) fn bind_payment(&mut self, payment: Fp, valid: bool, insert: bool) {
        let updated =
            receive_objects::from_send(&self.send, &self.witness.before, payment, valid, insert);
        assert_eq!(updated.statement, self.witness.statement);
        assert_eq!(updated.after.core, self.witness.after.core);
        assert_eq!(updated.after.rest, self.witness.after.rest);
        self.witness = updated;
    }
}

#[test]
#[ignore = "actual own step and altered incoming Send sigma under the complete soft Q verifier"]
fn altered_send_sigma_has_false_q_verdict_and_no_spendable_credit() {
    let (receiver, _, _) = receive_objects::receiver();
    let source = genuine_receive_source_with_invalid_sigma(&StateWitness::from(&receiver));
    // The only Q0 slot is the incoming one: its soft verdict is false and the
    // global mode is Trivial. No own sigma verdict exists to be forced true.
    assert_eq!(source.instances[3], [Fq::ZERO, Fq::ZERO, Fq::ONE, Fq::ZERO]);
    assert_eq!(source.witness.before.core[8], Fp::ZERO);
    assert_eq!(
        source.witness.after.core[8] - source.witness.after.lineage[14],
        Fp::ZERO
    );
    assert_eq!(
        source.witness.after.core[16],
        source.witness.before.core[16]
    );
    let maps = Maps {
        witness: source.witness,
        known: true,
        verdict: false,
    };
    assert!(
        check_circuit(&maps, 16, &public(&maps), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}

#[test]
#[ignore = "actual incoming Send sigma and incoming-only Q proof; run optimized"]
fn actual_incoming_only_send_q_binds_every_incoming_export() {
    for (valid, insert, mode) in [
        (true, true, IncomingMode::Accept),
        (false, false, IncomingMode::Trivial),
    ] {
        let source = genuine_receive_source(valid, insert, mode);
        let params = source.q.verifier().params();
        let row = source.sigma_plan.position(QSigmaPlan::INCOMING).unwrap();
        let chunk = source
            .sigma_plan
            .chunk_range(QSigmaPlan::INCOMING)
            .unwrap()
            .start;
        // Incoming statement, first proof chunk, selector, soft verdict, first
        // mode bit and the folded part's source k are all hard Q public inputs.
        for (column, index) in [
            (0, row),
            (0, chunk),
            (2, row),
            (3, row),
            (3, row + 1),
            (4, 0),
        ] {
            let mut changed = source.instances.clone();
            changed[column][index] += Fq::ONE;
            assert!(
                accumulate_generator(
                    params,
                    source.q.verifier().binding(),
                    &source.key,
                    &changed,
                    &source.proof,
                    MemoryBudget::DEFAULT
                )
                .is_err()
            );
        }
        let maps = Maps {
            witness: source.witness,
            known: true,
            verdict: valid,
        };
        assert!(
            check_circuit(&maps, 16, &public(&maps), CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
}
