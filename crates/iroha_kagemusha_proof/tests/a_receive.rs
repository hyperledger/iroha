//! Genuine Receive sigma/Q and depth32 accept/burn map composition.
//!
//! These are source and map components. They do not authenticate a predecessor
//! Omega or authorize the terminal branch without the five fixed A result owners.

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
    SigmaProver, SigmaRelation,
    a_relation::{LineagePublicCells, QProofPlan, schedule::sigma_selector},
    admin_sigma::StateWitness,
    operation_relation::{
        map_effects::{InsertCells, MapEffectsChip, MapState, MapTransition, ReceiveMapWitness},
        state::StateCells,
        statement::StatementCells,
    },
    q_sigma::{
        QSigmaPlan, SigmaClass, SigmaSlotWitness,
        native::{IncomingMode, IncomingSigma, QSigmaProver},
    },
    tree::IndexedInsert,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, msm::MemoryBudget};
use iroha_plonk::{
    ProverConfig,
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, synthesize},
    pcs::ipa::PinnedParams,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    UintChip,
    imt::{LeafCells, OpeningCells, PathCells},
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
                // derive it from the five fixed result owners before calling receive.
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

/// Real own Receive and incoming Send sigma Q source; its global mode remains
/// subject to A's complete five-result rule, not selected by this constructor.
#[allow(dead_code)]
pub(crate) struct ReceiveQ {
    pub(crate) witness: receive_objects::ReceiveFixture,
    pub(crate) send: send_objects::SendFixture,
    pub(crate) sigma: Vec<u8>,
    pub(crate) incoming_sigma: Vec<u8>,
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
    let own_proof = own.prove(&witness.step, common::recovery(241)).unwrap();
    let incoming_proof = incoming.prove(&send.step, common::recovery(242)).unwrap();
    let mut incoming_sigma = incoming_proof.bytes;
    if !incoming_valid {
        // The first commitment encoding is noncanonical in either Pasta field;
        // the total incoming verifier must export false, not a deferred claim.
        incoming_sigma[..32].fill(0xff);
    }
    let own_verifier = own.verifier();
    let incoming_verifier = incoming.verifier();
    let sigma_plan = QSigmaPlan::new(
        SigmaClass::from_verifiers(&[(sigma_selector(4, 0).unwrap(), &own_verifier)]).unwrap(),
        Some(
            SigmaClass::from_verifiers(&[(sigma_selector(3, 0).unwrap(), &incoming_verifier)])
                .unwrap(),
        ),
        &vparams,
    )
    .unwrap();
    let prepared = sigma_plan
        .prepare(
            SigmaSlotWitness {
                key: own.proving_key().vk().clone(),
                statement: own_proof.public.instance()[0],
                length: own_proof.bytes.len().try_into().unwrap(),
                proof: own_proof.bytes.clone(),
            },
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
            Fq::from(243),
            &FoldConfig::default(),
        )
        .unwrap();
    let q = QSigmaProver::keygen_serialized_foreign(&prepared, params.clone(), 2).unwrap();
    let proof = q
        .prove(&prepared, common::recovery(244), ProverConfig::default())
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
    assert_eq!(proof.instances[2], [Fq::from(10), Fq::from(2)]);
    assert_eq!(proof.instances[3][0], Fq::ONE);
    assert_eq!(proof.instances[3][1], Fq::from(u64::from(incoming_valid)));
    eprintln!(
        "Receive genuine sigma={} incoming_sigma={} Q={} sourcek={} mode={mode:?}",
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
#[ignore = "actual own sigma and altered incoming Send sigma under the complete soft Q verifier"]
fn altered_send_sigma_has_false_q_verdict_and_no_spendable_credit() {
    let (receiver, _, _) = receive_objects::receiver();
    let source = genuine_receive_source_with_invalid_sigma(&StateWitness::from(&receiver));
    assert_eq!(
        source.instances[3],
        [Fq::ONE, Fq::ZERO, Fq::ZERO, Fq::ONE, Fq::ZERO]
    );
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
#[ignore = "actual Receive/Send sigma and two-slot Q proof; run optimized"]
fn actual_receive_and_incoming_send_q_retains_both_opening_obligations() {
    for (valid, insert, mode) in [
        (true, true, IncomingMode::Accept),
        (false, false, IncomingMode::Trivial),
    ] {
        let source = genuine_receive_source(valid, insert, mode);
        let params = source.q.verifier().params();
        for column in [0, 2, 3] {
            let mut changed = source.instances.clone();
            changed[column][1] += Fq::ONE;
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
