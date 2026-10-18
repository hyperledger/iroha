// Shared genuine builder items. Registered tests remain in the integration harness.
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    Mutation, SigmaRelation,
    a_relation::{
        AOutputCells, AProofPlan, LINEAGE_DOMAIN, LineagePublicCells, ProofMessageCells,
        QProofPlan, SigmaBindingCells, VestaClaimCells, fold_pallas, lineage_digest,
        verify_predecessor, verify_sigma,
    },
    operation_relation::statement::StatementCells,
    q_sigma::{
        QSigmaPlan, SigmaClass, SigmaSlotWitness,
        native::{QSigmaFoldSource, QSigmaProver},
    },
    sample_witness,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    ProverConfig, VerifyingKey, Witness,
    check::{CheckMode, check_circuit},
    create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    transcript::TranscriptRepr,
    verifier::accumulate_generator,
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig,
    bytes::{
        element::le_message_segments,
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, FoldConfig, FoldInput, VESTA_TRIVIAL_GENERATOR,
    accumulation_circuit::FoldInputCells,
    codec::ScalarCells,
    obligation::ledger::Variant,
    verifier::{VerifierChip, VerifierConfig, VerifierPlan},
};

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
#[derive(Clone)]
struct Recursive {
    plan: AProofPlan,
    q: Vec<u8>,
    q_length: u32,
    instances: Vec<Vec<Fq>>,
    sigma: Vec<u8>,
    statement: [Fp; 26],
    fields: [Fp; 18],
    known: bool,
    route: u8,
    predecessor: Option<Predecessor>,
}
impl Recursive {
    fn value<T: Copy>(&self, v: T) -> Value<T> {
        if self.known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    }
}
fn carrier(
    chip: &mut VerifierChip<Ep>,
    bytes: &mut BytesChip<Fp>,
    region: &mut iroha_plonk::frontend::Region<'_, Fp>,
    body: &[u8],
    length: u32,
    known: bool,
) -> Result<ProofMessageCells, Error> {
    let raw = length
        .to_le_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .map(|v| {
            if known {
                Value::known(v)
            } else {
                Value::unknown()
            }
        })
        .collect::<Vec<_>>();
    let mut segments = vec![SegmentSpec::little(0, 4)];
    segments.extend(le_message_segments(4, body.len() / 32));
    let run = bytes.run(
        region,
        &raw,
        &raw.chunks(31).map(<[Value<u8>]>::len).collect::<Vec<_>>(),
        &segments,
    )?;
    ProofMessageCells::from_run(chip, region, &run, 0, body.len())
}
#[derive(Clone)]
struct Predecessor {
    key: VerifyingKey<Ep>,
    fields: [Fp; 18],
    pallas: FoldInput<Ep>,
    proof: Vec<u8>,
    length: u32,
    fold: iroha_kagemusha_proof::private_fold::PrivateFoldBytes,
    fold_length: u32,
}
struct Fixture {
    circuit: Recursive,
    values: [Vec<Fp>; 1],
    sigma_plan: QSigmaPlan,
    q_plan: QProofPlan,
    q_opening: FoldInput<Ep>,
    part: FoldInput<Eq>,
    params: PinnedParams<Ep>,
}

fn scalar(
    chip: &mut VerifierChip<Ep>,
    region: &mut iroha_plonk::frontend::Region<'_, Fp>,
    v: Value<Fq>,
) -> Result<ScalarCells<Ep>, Error> {
    let lo = chip
        .uint()
        .assign::<128>(region, v.map(|v| foreign_limbs(&v)[0]))?;
    let hi = chip
        .uint()
        .assign::<127>(region, v.map(|v| foreign_limbs(&v)[1]))?;
    ScalarCells::from_limbs(&mut chip.uint(), region, &lo, &hi)
}
impl Circuit<Fp> for Recursive {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure(meta);
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
            || "A owns real Q opening",
            |mut region| {
                let proof = carrier(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    &self.q,
                    self.q_length,
                    self.known,
                )?;
                let mut instances = Vec::new();
                for column in &self.instances {
                    let mut values = Vec::new();
                    for value in column {
                        values.push(scalar(&mut chip, &mut region, self.value(*value))?);
                    }
                    instances.push(values);
                }
                let sigma = self
                    .sigma
                    .iter()
                    .map(|v| self.value(*v))
                    .collect::<Vec<_>>();
                let chunks = bytes.run(
                    &mut region,
                    &sigma,
                    &sigma.chunks(31).map(<[Value<u8>]>::len).collect::<Vec<_>>(),
                    &[],
                )?;
                let statement = self
                    .statement
                    .iter()
                    .map(|v| chip.uint().glue().witness(&mut region, self.value(*v)))
                    .collect::<Result<Vec<_>, _>>()?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    Variant::Send,
                    &statement.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                let index = chip.uint().glue().constant(&mut region, Fp::from(5))?;
                let binding = SigmaBindingCells::from_statement(
                    &statement,
                    index,
                    chunks.primary().iter().map(|s| s.word().clone()).collect(),
                );
                let (q, sigma) = verify_sigma(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    &instances,
                    &proof,
                    &[binding],
                )?;
                let q = match self.route {
                    0 => vec![q],
                    1 => vec![],
                    _ => vec![q.clone(), q],
                };
                let fields = self
                    .fields
                    .iter()
                    .map(|v| chip.uint().glue().witness(&mut region, self.value(*v)))
                    .collect::<Result<Vec<_>, _>>()?;
                let public = LineagePublicCells::constrain(
                    &mut chip.uint(),
                    &mut region,
                    &fields.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                let (predecessor, fold) = if let Some(source) = &self.predecessor {
                    let TranscriptRepr::Base(repr) = *source.key.transcript_repr() else {
                        return Err(Error::Synthesis);
                    };
                    let fixed = source
                        .key
                        .fixed_commitments()
                        .iter()
                        .map(|p| self.value(Ep::from(*p)))
                        .collect::<Vec<_>>();
                    let permutation = source
                        .key
                        .permutation_commitments()
                        .iter()
                        .map(|p| self.value(Ep::from(*p)))
                        .collect::<Vec<_>>();
                    let key =
                        chip.witness_key(&mut region, self.value(repr), &fixed, &permutation)?;
                    let fields = source
                        .fields
                        .iter()
                        .map(|v| chip.uint().glue().witness(&mut region, self.value(*v)))
                        .collect::<Result<Vec<_>, _>>()?;
                    let previous = LineagePublicCells::constrain(
                        &mut chip.uint(),
                        &mut region,
                        &fields.try_into().map_err(|_| Error::Synthesis)?,
                    )?;
                    let g = chip
                        .witness_generator(&mut region, self.value(Ep::from(*source.pallas.g())))?;
                    let challenges = source
                        .pallas
                        .challenges()
                        .iter()
                        .map(|v| scalar(&mut chip, &mut region, self.value(*v)))
                        .collect::<Result<Vec<_>, _>>()?;
                    let claim = FoldInputCells::from_normalized(
                        &mut chip,
                        &mut region,
                        16,
                        g,
                        challenges.try_into().map_err(|_| Error::Synthesis)?,
                    )?;
                    let vesta = VestaClaimCells::trivial(&mut chip, &mut region)?;
                    let proof = carrier(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &source.proof,
                        source.length,
                        self.known,
                    )?;
                    let predecessor = verify_predecessor(
                        &mut chip,
                        &mut region,
                        &self.plan,
                        &key,
                        &previous,
                        &public,
                        &claim,
                        &vesta,
                        &proof,
                    )?;
                    let fold = carrier(
                        &mut chip,
                        &mut bytes,
                        &mut region,
                        &source.fold,
                        source.fold_length,
                        self.known,
                    )?;
                    (Some(predecessor), Some(fold))
                } else {
                    (None, None)
                };
                let pallas = fold_pallas(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    predecessor.as_ref(),
                    None,
                    &q,
                    fold.as_ref(),
                )?;
                let digest = lineage_digest(&mut chip, &mut region, &public, &pallas)?;
                AOutputCells {
                    digest,
                    sigma_part: sigma.part,
                    predecessor: predecessor.map(|p| p.vesta().clone()),
                    incoming: None,
                }
                .words(&mut chip, &mut region, self.plan.frame())
            },
        )?;
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
fn public(
    fields: &[Fp; 18],
    pallas: &FoldInput<Ep>,
    part: &iroha_plonk_recursion::FoldInput<iroha_pasta::Eq>,
) -> Vec<Fp> {
    let mut words = fields.to_vec();
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Ep>(pallas.g());
    words.extend([x, y]);
    for value in pallas.challenges() {
        words.extend(foreign_limbs(value).map(Fp::from_u128));
    }
    let mut out = vec![
        hash_with_domain(LINEAGE_DOMAIN, &words),
        Fp::from(u64::from(part.source_k())),
    ];
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Eq>(part.g());
    for coordinate in [x, y] {
        out.extend(foreign_limbs(&coordinate).map(Fp::from_u128));
    }
    out.extend(part.challenges());
    let trivial =
        iroha_plonk::transcript::decode_point::<iroha_pasta::Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap();
    let (x, y) = trivial.coordinates().unwrap();
    let coordinates = [x, y]
        .into_iter()
        .flat_map(|v| foreign_limbs(&v).map(Fp::from_u128))
        .collect::<Vec<_>>();
    for _ in 0..2 {
        out.extend(coordinates.clone());
        out.extend([Fp::ONE; 16]);
    }
    out.extend([Fp::ZERO, Fp::ONE, Fp::ZERO]);
    out.extend(coordinates);
    out
}
fn satisfied(circuit: &Recursive, instances: &[Vec<Fp>]) -> bool {
    check_circuit(circuit, 16, instances, CheckMode::Strict)
        .map(|r| r.is_satisfied())
        .unwrap_or(false)
}

fn fixture() -> Fixture {
    let sigma = common::vesta_prover(common::pinned_shape(
        common::folded(SigmaRelation::SEND),
        (12, 1),
    ));
    let witness = sample_witness::<Fp>(common::CHECK_SEED + 2, SigmaRelation::SEND, Mutation::None);
    let proof = sigma.prove(&witness, common::fresh_randomness()).unwrap();
    let verifier = sigma.verifier();
    let class = SigmaClass::from_verifiers(&[(5, &verifier)]).unwrap();
    let params = common::vesta_params(16);
    let plan = QSigmaPlan::new(class, None, &params).unwrap();
    let slot = SigmaSlotWitness {
        key: verifier.vk().clone(),
        statement: proof.public.statement,
        proof: proof.bytes.clone(),
        length: u32::try_from(proof.bytes.len()).unwrap(),
    };
    let prepared = plan
        .prepare(
            Some(slot),
            None,
            &params,
            QSigmaFoldSource::NoIncoming,
            &FoldConfig::default(),
        )
        .unwrap();
    let pallas_params = PinnedParams::<Ep>::derive(16).unwrap();
    let prover = QSigmaProver::keygen(&prepared, pallas_params.clone()).unwrap();
    let q = prover
        .prove(
            &prepared,
            common::fresh_randomness(),
            ProverConfig::default(),
        )
        .unwrap();
    let claim = accumulate_generator(
        &pallas_params,
        prover.binding(),
        prover.verifying_key(),
        &q.instances,
        &q.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    let pallas = FoldInput::from_opening(*claim.g(), claim.challenges()).unwrap();
    pallas
        .decide(&pallas_params, MemoryBudget::DEFAULT)
        .unwrap();
    let fixed = QProofPlan::new(
        VerifierPlan::new(prover.binding().clone(), pallas_params.clone()).unwrap(),
        prover.verifying_key().clone(),
    )
    .unwrap();
    let aplan = AProofPlan::new(
        Variant::Bootstrap,
        plan.clone(),
        vec![fixed.clone()],
        None,
        &pallas_params,
    )
    .unwrap();
    assert!(
        AProofPlan::new(
            Variant::Bootstrap,
            plan.clone(),
            vec![fixed.clone(), fixed.clone()],
            None,
            &pallas_params
        )
        .is_ok()
    );
    assert!(
        AProofPlan::new(
            Variant::Send,
            plan.clone(),
            vec![fixed.clone()],
            None,
            &pallas_params
        )
        .is_err()
    );
    assert_eq!(aplan.q_count(), 1);
    assert!(aplan.omega().is_none());
    assert!(aplan.q(1).is_none());
    assert_eq!(aplan.frame().variant(), Variant::Bootstrap);
    let mut fields = core::array::from_fn(|i| Fp::from(u64::try_from(i + 1).unwrap()));
    fields[0] = Fp::ONE;
    let native = witness.evaluate(SigmaRelation::SEND);
    let statement = native.statement;
    let sigma_bytes = u32::try_from(proof.bytes.len())
        .unwrap()
        .to_le_bytes()
        .into_iter()
        .chain(proof.bytes)
        .collect();
    let circuit = Recursive {
        plan: aplan,
        q_length: u32::try_from(q.bytes.len()).unwrap(),
        q: q.bytes,
        instances: q.instances,
        sigma: sigma_bytes,
        statement,
        fields,
        known: true,
        route: 0,
        predecessor: None,
    };
    let values = [public(&fields, &pallas, &q.part)];
    Fixture {
        circuit,
        values,
        sigma_plan: plan,
        q_plan: fixed,
        q_opening: pallas,
        part: q.part,
        params: pallas_params,
    }
}

// An actual k16 proof with Omega's typed schema, deliberately isolating the
// consumer contract. This fixture does not assert the production Omega relation.
#[derive(Clone)]
struct OmegaFrame {
    instances: Vec<Vec<Fq>>,
    known: bool,
}
impl Circuit<Fq> for OmegaFrame {
    type Config = (GlueConfig, [Column<Instance>; 3]);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let public = [
            meta.instance_column(1),
            meta.instance_column(2),
            meta.instance_column(16),
        ];
        for column in public {
            meta.enable_equality(column);
        }
        (glue, public)
    }
    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config);
        let words = layouter.assign_region(
            || "Omega consumer fixture",
            |mut region| {
                self.instances
                    .iter()
                    .flatten()
                    .map(|v| {
                        glue.witness(
                            &mut region,
                            if self.known {
                                Value::known(*v)
                            } else {
                                Value::unknown()
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        let mut offset = 0;
        for (column, values) in public.iter().zip(&self.instances) {
            for row in 0..values.len() {
                layouter.constrain_instance(words[offset + row].cell(), *column, row)?;
            }
            offset += values.len();
        }
        Ok(())
    }
}
fn digest(fields: &[Fp; 18], pallas: &FoldInput<Ep>) -> Fp {
    let mut words = fields.to_vec();
    let (x, y) = iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Ep>(pallas.g());
    words.extend([x, y]);
    for u in pallas.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
    hash_with_domain(LINEAGE_DOMAIN, &words)
}

// Context framing in isolation: Q data below comes from a genuine Q fixture,
// but this test checks its context commitment, not an A proof or operation.
#[derive(Clone)]
struct ContextCircuit {
    plan: iroha_kagemusha_proof::a_relation::context::ContextPlan,
    statement: [Fp; 26],
    core: [Fp; 29],
    rest: [Fp; 6],
    public: [Fp; 18],
    q: Vec<Vec<Vec<Fq>>>,
    object: [u8; 36],
    object_digest: Fp,
    pallas: FoldInput<Ep>,
    known: bool,
    wrong_order: bool,
}
impl ContextCircuit {
    fn value<T: Copy>(&self, v: T) -> Value<T> {
        if self.known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    }
    fn digest(&self) -> Fp {
        let mut words = self.plan.schema().to_vec();
        words.extend(self.statement);
        words.extend(self.core);
        words.extend(self.rest);
        words.extend(self.public);
        for value in self.q.iter().flatten().flatten() {
            words.extend(foreign_limbs(value).map(Fp::from_u128));
        }
        let mut tape = vec![Fp::from(7), Fp::from(32)];
        for chunk in self.object.chunks(31) {
            tape.push(iroha_plonk_gadgets::bytes::le_value::<Fp>(chunk).unwrap());
        }
        words.extend([
            self.object_digest,
            Fp::from(u64::from(u32::from_le_bytes(
                self.object[..4].try_into().unwrap(),
            ))),
            hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &tape),
        ]);
        let base = hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words);
        let mut words = vec![Fp::ONE, self.plan.schema()[1], Fp::ONE, base];
        let (x, y) =
            iroha_plonk::transcript::generator_coordinates::<iroha_pasta::Ep>(self.pallas.g());
        words.extend([Fp::from(16), x, y]);
        for u in self.pallas.challenges() {
            words.extend(foreign_limbs(u).map(Fp::from_u128));
        }
        hash_with_domain(u64::from_le_bytes(*b"kgwlink1"), &words)
    }
}

impl ContextCircuit {
    fn assign(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut iroha_plonk::frontend::Region<'_, Fp>,
    ) -> Result<Vec<iroha_plonk_gadgets::Word<Fp>>, Error> {
        use iroha_kagemusha_proof::{
            a_relation::context::{
                ContextInputs, ContextObjectCells, ContextObjectSpec, ContextState,
            },
            operation_relation::state::StateCells,
        };

        let core = chip
            .uint()
            .glue()
            .witnesses(region, &self.core.map(|v| self.value(v)))?;
        let rest = chip
            .uint()
            .glue()
            .witnesses(region, &self.rest.map(|v| self.value(v)))?;
        let state = StateCells::constrain_with_verifier(
            chip,
            region,
            &core.try_into().map_err(|_| Error::Synthesis)?,
            &rest.try_into().map_err(|_| Error::Synthesis)?,
        )?;
        let public = chip
            .uint()
            .glue()
            .witnesses(region, &self.public.map(|v| self.value(v)))?;
        let public = LineagePublicCells::constrain(
            &mut chip.uint(),
            region,
            &public.try_into().map_err(|_| Error::Synthesis)?,
        )?;
        let statement = chip
            .uint()
            .glue()
            .witnesses(region, &self.statement.map(|v| self.value(v)))?;
        let statement = StatementCells::constrain_with_verifier(
            chip,
            region,
            Variant::Bootstrap,
            &statement.try_into().map_err(|_| Error::Synthesis)?,
        )?;
        let mut instances = Vec::new();
        for proof in &self.q {
            let mut columns = Vec::new();
            for column in proof {
                let mut values = Vec::new();
                for value in column {
                    values.push(scalar(chip, region, self.value(*value))?);
                }
                columns.push(values);
            }
            instances.push(columns);
        }
        let tape = bytes.run(
            region,
            &self.object.map(|v| self.value(v)),
            &[31, 5],
            &[SegmentSpec::little(0, 4)],
        )?;
        let object_digest = chip
            .uint()
            .glue()
            .witness(region, self.value(self.object_digest))?;
        let tag = if self.wrong_order { 8 } else { 7 };
        let context_objects = vec![ContextObjectCells::from_run(
            chip,
            region,
            ContextObjectSpec { tag, capacity: 32 },
            &object_digest,
            &tape,
        )?];
        let point = chip.witness_generator(region, self.value(Ep::from(*self.pallas.g())))?;
        let challenges = self
            .pallas
            .challenges()
            .iter()
            .map(|v| scalar(chip, region, self.value(*v)))
            .collect::<Result<Vec<_>, _>>()?;
        let pallas = FoldInputCells::from_normalized(
            chip,
            region,
            16,
            point,
            challenges.try_into().map_err(|_| Error::Synthesis)?,
        )?;
        let input = ContextInputs {
            own_statement: &statement,
            incoming_statement: None,
            predecessor: None,
            successor: ContextState {
                state: &state,
                public: &public,
            },
            incoming: None,
            q_instances: &instances,
            objects: &context_objects,
            modes: &[],
            pallas_corrections: &[],
            vesta_corrections: &[],
            receive_results: None,
        };
        let base = self.plan.digest(chip, region, &input)?;
        Ok(vec![
            self.plan.stage_digest(chip, region, 0, &base, &pallas)?,
        ])
    }
}
impl Circuit<Fp> for ContextCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure(meta);
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(1);
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
            || "complete split context",
            |mut region| self.assign(&mut chip, &mut bytes, &mut region),
        )?;
        layouter.constrain_instance(out[0].cell(), config.public, 0)
    }
}
fn context_fixture(base: Fixture) -> ContextCircuit {
    use iroha_kagemusha_proof::a_relation::context::{ContextObjectSpec, ContextPlan};
    use iroha_kagemusha_proof::witness::{CORE_DOMAIN, REST_DOMAIN};
    let spec = ContextObjectSpec {
        tag: 7,
        capacity: 32,
    };
    assert!(ContextPlan::new(base.circuit.plan.clone(), 0, vec![spec]).is_err());
    assert!(ContextPlan::new(base.circuit.plan.clone(), 2, vec![spec]).is_err());
    assert!(ContextPlan::new(base.circuit.plan.clone(), 1, vec![spec, spec]).is_err());
    let plan = ContextPlan::new(base.circuit.plan, 1, vec![spec]).unwrap();
    let mut core = [Fp::ZERO; 29];
    core[0] = Fp::ONE;
    for (i, v) in core.iter_mut().enumerate().take(8).skip(1) {
        *v = Fp::from(i as u64);
    }
    for (i, v) in core.iter_mut().enumerate().take(21).skip(16) {
        *v = Fp::from(i as u64);
    }
    core[28] = Fp::from(77);
    let rest = [Fp::ZERO; 6];
    let mut preimage = core.to_vec();
    preimage.push(hash_with_domain(REST_DOMAIN, &rest));
    let head = hash_with_domain(CORE_DOMAIN, &preimage);
    let mut public = [Fp::ONE; 18];
    public[1] = core[1];
    public[2] = core[2];
    public[3] = Fp::from(9);
    public[4] = Fp::from(10);
    public[5] = head;
    public[6] = core[5];
    public[7] = core[6];
    public[8] = core[7];
    public[14] = Fp::ZERO;
    public[15] = core[17];
    public[16] = Fp::from(89);
    public[17] = Fp::from(91);
    let mut statement = [Fp::ZERO; 26];
    statement[0] = Fp::ONE;
    statement[1] = public[3];
    statement[2] = public[4];
    statement[3..8].copy_from_slice(&core[1..6]);
    statement[7] = core[7];
    statement[8] = Fp::ONE;
    statement[15] = head;
    statement[16] = Fp::ONE;
    statement[17..21].copy_from_slice(&[Fp::ONE, Fp::from(2), Fp::from(3), Fp::from(4)]);
    let mut object = core::array::from_fn(|i| u8::try_from(i).unwrap());
    object[..4].copy_from_slice(&32u32.to_le_bytes());
    ContextCircuit {
        plan,
        statement,
        core,
        rest,
        public,
        q: vec![base.circuit.instances],
        object,
        object_digest: Fp::from(111),
        pallas: base.q_opening,
        known: true,
        wrong_order: false,
    }
}

/// Explicit source-A candidate; existing helpers retain their scalar-bank profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SourceProfile {
    /// Original wide diagnostic profile.
    #[default]
    Generic,
    /// Parallel serialized arithmetic with ordinary pooled range buses.
    Serialized {
        /// Independent pooled range lookup count.
        buses: usize,
    },
    /// Parallel serialized arithmetic with exact tagged width/value range buses.
    Tagged {
        /// Independent pooled tagged lookup count.
        buses: usize,
    },
}
impl SourceProfile {
    /// Preserve the existing zero=generic, positive=ordinary serialized helper contract.
    pub const fn ordinary(buses: usize) -> Self {
        if buses == 0 {
            Self::Generic
        } else {
            Self::Serialized { buses }
        }
    }
    /// Number of independent range buses, zero only for the generic profile.
    pub const fn range_buses(self) -> usize {
        match self {
            Self::Generic => 0,
            Self::Serialized { buses } | Self::Tagged { buses } => buses,
        }
    }
    /// Configure the exact named artifact profile.
    pub fn configure(self, meta: &mut ConstraintSystem<Fp>) -> VerifierConfig<Ep> {
        let buses = self.range_buses();
        match self {
            Self::Generic => VerifierConfig::configure(meta),
            Self::Serialized { .. } => {
                VerifierConfig::configure_serialized_foreign(meta, buses).unwrap()
            }
            Self::Tagged { .. } => {
                VerifierConfig::configure_serialized_foreign_tagged(meta, buses).unwrap()
            }
        }
    }
}

/// Independent reference for the production unsplit Bootstrap A: the same
/// assignment order as `native::bootstrap::StageCircuit`, under an explicit
/// source profile, with every authentication input exposed to mutation.
#[derive(Clone)]
struct TerminalCircuit {
    profile: SourceProfile,
    plan: AProofPlan,
    signature_schema: iroha_kagemusha_proof::q_signature::QSignaturePlan,
    signature_order: [usize; 3],
    state: iroha_kagemusha_proof::admin_sigma::BootstrapWitness,
    q: Vec<Vec<Fq>>,
    proof: Vec<u8>,
    length: u32,
    objects: [bootstrap_objects::Signed; 3],
    known: bool,
}
impl TerminalCircuit {
    fn value<T: Copy>(&self, v: T) -> Value<T> {
        if self.known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    }
    fn assign(
        &self,
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut iroha_plonk::frontend::Region<'_, Fp>,
    ) -> Result<Vec<iroha_plonk_gadgets::Word<Fp>>, Error> {
        use iroha_kagemusha_proof::{
            a_relation::{
                bind_signature_q,
                bootstrap::{BootstrapInputs, BootstrapObjects},
                bounded_word, close_unsplit, verify_q,
            },
            operation_relation::state::StateCells,
        };

        let core = chip
            .uint()
            .glue()
            .witnesses(region, &self.state.core.map(|v| self.value(v)))?;
        let rest = chip
            .uint()
            .glue()
            .witnesses(region, &self.state.rest.map(|v| self.value(v)))?;
        let state = StateCells::constrain_with_verifier(
            chip,
            region,
            &core.try_into().map_err(|_| Error::Synthesis)?,
            &rest.try_into().map_err(|_| Error::Synthesis)?,
        )?;
        let public = chip
            .uint()
            .glue()
            .witnesses(region, &self.state.lineage.map(|v| self.value(v)))?;
        let public = LineagePublicCells::constrain(
            &mut chip.uint(),
            region,
            &public.try_into().map_err(|_| Error::Synthesis)?,
        )?;
        let statement = chip
            .uint()
            .glue()
            .witnesses(region, &self.state.statement.map(|v| self.value(v)))?;
        let statement = StatementCells::constrain_with_verifier(
            chip,
            region,
            Variant::Bootstrap,
            &statement.try_into().map_err(|_| Error::Synthesis)?,
        )?;
        let mut q = Vec::new();
        for column in &self.q {
            let mut values = Vec::new();
            for value in column {
                values.push(scalar(chip, region, self.value(*value))?);
            }
            q.push(values);
        }
        let values = self.objects.each_ref().map(|object| {
            object
                .bytes
                .iter()
                .map(|byte| self.value(*byte))
                .collect::<Vec<_>>()
        });
        let objects =
            BootstrapObjects::decode(chip, bytes, region, values.each_ref().map(Vec::as_slice))?;
        let proof = carrier(chip, bytes, region, &self.proof, self.length, self.known)?;
        let verified = verify_q(chip, region, &self.plan, 0, &q, &proof)?;
        let slots = bind_signature_q(
            chip,
            region,
            &self.plan,
            0,
            &self.signature_schema,
            &verified,
        )?;
        let ordered = self
            .signature_order
            .iter()
            .map(|i| slots.slots().get(*i).cloned().ok_or(Error::Synthesis))
            .collect::<Result<Vec<_>, _>>()?;
        objects.authenticate(
            chip,
            region,
            bootstrap_objects::policy(),
            BootstrapInputs {
                state: &state,
                lineage: &public,
                statement: &statement,
                signatures: &ordered,
            },
        )?;
        for (slot, words) in slots.slots().iter().zip(q[0].chunks_exact(10)) {
            let actual = std::iter::once(slot.message())
                .chain(slot.key())
                .chain(slot.signature())
                .chain(std::iter::once(slot.valid().word()));
            for (actual, scalar) in actual.zip(words) {
                let expected = bounded_word(chip, region, scalar)?;
                GlueChip::assert_equal(region, actual, &expected)?;
            }
        }
        close_unsplit(chip, region, &self.plan, &public, &verified)
    }
}
impl Circuit<Fp> for TerminalCircuit {
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
        if profile == SourceProfile::Generic {
            return Recursive::configure(meta);
        }
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
            || "unsplit Bootstrap A",
            |mut region| self.assign(&mut chip, &mut bytes, &mut region),
        )?;
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
// The production unsplit frame: `D_A` over the lineage and the forwarded Q
// opening, then the pinned trivial part and the absent predecessor/incoming slots.
fn unsplit_public(fields: &[Fp; 18], pallas: &FoldInput<Ep>) -> Vec<Fp> {
    let trivial =
        iroha_plonk::transcript::decode_point::<iroha_pasta::Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap();
    public(
        fields,
        pallas,
        &FoldInput::from_normalized(trivial, 16, [Fp::ONE; 16]).unwrap(),
    )
}

/// Genuine authenticated Bootstrap artifacts for following operation/outer tests.
#[derive(Clone)]
#[allow(dead_code)] // Consumed by following-operation and outer integration tests.
pub(crate) struct AuthenticatedBootstrap {
    pub(crate) key: VerifyingKey<Eq>,
    pub(crate) binding: iroha_plonk::DescriptorBinding,
    pub(crate) proof: Vec<u8>,
    pub(crate) instances: Vec<Fp>,
    pub(crate) opening: FoldInput<Eq>,
    /// The signature Q's decided opening, forwarded unfolded as A's Pallas claim.
    pub(crate) pallas: AccumulatorT<Ep>,
    pub(crate) state: iroha_kagemusha_proof::admin_sigma::BootstrapWitness,
    /// Sigma, signature Q and A exact key bytes, for scheme-cycle regressions.
    pub(crate) source_keys: [Vec<u8>; 3],
}

/// Build actual sigma, signature Q and unsplit A proofs; optional tests do not alter the relation.
pub(crate) fn authenticated_bootstrap(adversarial: bool) -> AuthenticatedBootstrap {
    authenticated_bootstrap_with_omega(adversarial, Fp::from(91))
}

/// Rebind the witness-only carried normal Omega identity without changing A keys.
pub(crate) fn authenticated_bootstrap_with_omega(
    adversarial: bool,
    omega_digest: Fp,
) -> AuthenticatedBootstrap {
    authenticated_bootstrap_with_layout(adversarial, omega_digest, 0)
}

/// Explicit source-A artifact profile; zero retains the generic diagnostic.
pub(crate) fn authenticated_bootstrap_with_layout(
    adversarial: bool,
    omega_digest: Fp,
    range_buses: usize,
) -> AuthenticatedBootstrap {
    authenticated_bootstrap_with_q_layout(adversarial, omega_digest, range_buses, None)
}

/// Explicit A profile experiment. Lean Bootstrap's only Q is the signature leaf,
/// whose one profile is fixed, so `q_range_buses` is reported for diagnostics only.
pub(crate) fn authenticated_bootstrap_with_q_layout(
    adversarial: bool,
    omega_digest: Fp,
    range_buses: usize,
    q_range_buses: Option<usize>,
) -> AuthenticatedBootstrap {
    authenticated_bootstrap_with_profile(
        adversarial,
        omega_digest,
        SourceProfile::ordinary(range_buses),
        q_range_buses,
    )
}

/// Named profile experiment for the unsplit terminal A.
pub(crate) fn authenticated_bootstrap_with_profile(
    adversarial: bool,
    omega_digest: Fp,
    profile: SourceProfile,
    q_range_buses: Option<usize>,
) -> AuthenticatedBootstrap {
    authenticated_bootstrap_with_identity(
        adversarial,
        omega_digest,
        profile,
        q_range_buses,
        BootstrapIdentity::Payer,
    )
}

/// Distinct genuine wallet identities; neither is an admitted release artifact.
pub(crate) use bootstrap_objects::Identity as BootstrapIdentity;

/// Same fixed Bootstrap relation for a separately enrolled receiver wallet.
pub(crate) fn authenticated_bootstrap_with_identity(
    adversarial: bool,
    omega_digest: Fp,
    profile: SourceProfile,
    q_range_buses: Option<usize>,
    identity: BootstrapIdentity,
) -> AuthenticatedBootstrap {
    authenticated_bootstrap_for_schemes(
        adversarial,
        omega_digest,
        profile,
        q_range_buses,
        identity,
        [1, 2],
        [1, 2],
    )
    .expect("matching signed Bootstrap scheme")
}

fn authenticated_bootstrap_for_schemes(
    adversarial: bool,
    omega_digest: Fp,
    profile: SourceProfile,
    q_range_buses: Option<usize>,
    identity: BootstrapIdentity,
    scheme: [u128; 2],
    certificate_scheme: [u128; 2],
) -> Option<AuthenticatedBootstrap> {
    use iroha_kagemusha_proof::admin_sigma::{BOOTSTRAP_K, BootstrapCircuit};
    // The lean signature leaf has one fixed profile: `q_range_buses` selects nothing.
    eprintln!("BOOTSTRAP_SOURCE_PROFILE {profile:?} Q_buses={q_range_buses:?}");
    let (mut initial, certificate, credential) =
        bootstrap_objects::enrollment_for_schemes(identity, scheme, certificate_scheme);
    initial.lineage[17] = omega_digest;
    // Native still produces sigma_bootstrap (owner decision R-O2), so the signed
    // receipt keeps naming its digest; A proves the transition and verifies no sigma.
    let sigma = BootstrapCircuit::new(&initial);
    let sigma_params = common::vesta_params(BOOTSTRAP_K);
    let sigma_instances = sigma.instances();
    let sigma_key = keygen_pk_v2(
        &sigma_params,
        &sigma,
        &KeygenConfigV2::pipa_r(BootstrapCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let sigma_bytes = create_proof_owned_with_claim(
        &sigma_params,
        &sigma_key,
        Witness::from_circuit(&sigma_key, &sigma, &sigma_instances).unwrap(),
        common::fresh_randomness(),
        ProverConfig::default(),
    )
    .unwrap()
    .proof;
    let vparams = common::vesta_params(16);
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let receipt = bootstrap_objects::receipt_for(&initial, &sigma_bytes, identity);
    let objects = [certificate, credential, receipt];
    let (signature, siginstances) = bootstrap_objects::signatures(&objects);
    let signature_key = keygen_pk_v2(
        &params,
        &signature,
        &KeygenConfigV2::pipa_r(
            iroha_kagemusha_proof::q_signature::QSignaturePlan::instance_types().to_vec(),
        ),
    )
    .unwrap();
    let signature_proof = create_proof_owned_with_claim(
        &params,
        &signature_key,
        Witness::from_circuit(&signature_key, &signature, &siginstances).unwrap(),
        common::fresh_randomness(),
        ProverConfig::default(),
    )
    .unwrap();
    let q_opening = FoldInput::from_opening(
        *signature_proof.opening.g(),
        signature_proof.opening.challenges(),
    )
    .unwrap();
    q_opening.decide(&params, MemoryBudget::DEFAULT).unwrap();
    let pallas = AccumulatorT::new(*q_opening.g(), *q_opening.challenges()).unwrap();
    let signature_plan = QProofPlan::new(
        VerifierPlan::new(signature_key.binding().clone(), params.clone()).unwrap(),
        signature_key.vk().clone(),
    )
    .unwrap();
    // Lean lineage: one unsplit terminal A over the single hard signature leaf.
    let operation =
        AProofPlan::inline(Variant::Bootstrap, vec![signature_plan], None, &params).unwrap();
    let terminal = TerminalCircuit {
        profile,
        plan: operation.clone(),
        signature_schema: signature.plan().clone(),
        signature_order: [0, 1, 2],
        state: initial,
        q: siginstances.to_vec(),
        length: u32::try_from(signature_proof.proof.len()).unwrap(),
        proof: signature_proof.proof.clone(),
        objects: objects.clone(),
        known: true,
    };
    let public = [unsplit_public(&initial.lineage, &q_opening)];
    let check = check_circuit(&terminal, 16, &public, CheckMode::Strict).unwrap_or_else(|error| {
        let diagnostic = synthesize(&terminal, 17, Some(&public)).unwrap();
        let lanes: Vec<_> = diagnostic
            .tables
            .advice_assigned()
            .iter()
            .map(|col| col.iter().rposition(|v| *v).map_or(0, |row| row + 1))
            .collect();
        panic!("unsplit Bootstrap A k16 capacity failure {error:?}: lanes{lanes:?}");
    });
    if scheme != certificate_scheme {
        assert!(
            !check.is_satisfied(),
            "valid signatures must not authorize a foreign certificate scheme"
        );
        eprintln!(
            "BOOTSTRAP_FOREIGN_SCHEME_REJECTED signed_originals=true actual_sigma_q=true terminal_proof=false"
        );
        return None;
    }
    assert!(
        check.is_satisfied(),
        "{:?}",
        &check.failures()[..check.failures().len().min(8)]
    );
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    let akey = keygen_pk_v2(&vparams, &terminal, &config).unwrap();
    let a = create_proof_owned_with_claim(
        &vparams,
        &akey,
        Witness::from_circuit(&akey, &terminal, &public).unwrap(),
        common::fresh_randomness(),
        ProverConfig::default(),
    )
    .unwrap();
    let aclaim = accumulate_generator(
        &vparams,
        akey.binding(),
        akey.vk(),
        &public,
        &a.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    aclaim.decide(&vparams, MemoryBudget::DEFAULT).unwrap();
    pallas.decide(&params, MemoryBudget::DEFAULT).unwrap();
    let output = AuthenticatedBootstrap {
        key: akey.vk().clone(),
        binding: akey.binding().clone(),
        proof: a.proof.clone(),
        instances: public[0].clone(),
        opening: FoldInput::from_opening(*aclaim.g(), aclaim.challenges()).unwrap(),
        pallas: pallas.clone(),
        state: initial,
        source_keys: [
            sigma_key.vk().to_bytes().to_vec(),
            signature_key.vk().to_bytes().to_vec(),
            akey.vk().to_bytes().to_vec(),
        ],
    };
    let mut installed_native_source = None;
    if adversarial
        && profile
            == (SourceProfile::Tagged {
                buses: iroha_kagemusha_proof::a_relation::native::bootstrap::SOURCE_RANGE_BUSES,
            })
    {
        use iroha_kagemusha_proof::a_relation::native::bootstrap as native;
        let native_plan = native::Plan::new(
            operation.clone(),
            bootstrap_objects::policy(),
            signature.plan().clone(),
            params.clone(),
            vparams.clone(),
        )
        .unwrap();
        // The offline factory independently reconstructs this exact A source.
        let (binding, key) = iroha_plonk::keys::keygen_vk_with_binding_v2(
            &vparams,
            &native_plan.source_circuit().unwrap(),
            &config,
        )
        .unwrap();
        assert_eq!(&binding, akey.binding(), "A descriptor");
        assert_eq!(key.to_bytes(), akey.vk().to_bytes(), "A key");
        // Installation has no operation input: fixed source, Q/root policy and
        // authenticated verifier identity are selected before native prepare.
        let original = NativeBootstrapOriginal::from_key(&akey);
        let read = native_bootstrap_read_config(&original);
        let installed = install_native_bootstrap(native_plan.clone(), &original, read).unwrap();
        assert_eq!(installed.descriptors(), [akey.binding()]);
        let foreign = NativeBootstrapOriginal::from_key(&sigma_key);
        for mutation in 0..6 {
            let mut bad = original.clone();
            match mutation {
                0 => bad.vk.clone_from(&foreign.vk),
                1 => bad.pk[44 + original.vk.len()] ^= 1, // exact copy digest
                2 => bad.pk[44 + original.vk.len() + 32] ^= 1, // source fingerprint
                3 => bad.descriptor.clone_from(&foreign.descriptor),
                4 => bad.pk.push(0),
                _ => {
                    bad.pk.pop();
                }
            }
            assert!(
                install_native_bootstrap(native_plan.clone(), &bad, read).is_err(),
                "installed Bootstrap original mutation{mutation}"
            );
        }
        for maximum_rows in [0, (1 << 16) - 1] {
            assert!(
                install_native_bootstrap(
                    native_plan.clone(),
                    &original,
                    iroha_plonk::keys::pk::artifact::ReadConfig {
                        maximum_rows,
                        ..read
                    }
                )
                .is_err()
            );
        }
        assert!(
            install_native_bootstrap(
                native_plan.clone(),
                &original,
                iroha_plonk::keys::pk::artifact::ReadConfig {
                    maximum_bytes: 0,
                    ..read
                }
            )
            .is_err()
        );
        let descriptor =
            iroha_plonk::cs::CircuitDescriptorV2::decode(&original.descriptor).unwrap();
        for mutation in 0..5 {
            let mut wrong = descriptor.clone();
            match mutation {
                0 => wrong.instance_types[0] = InstanceType::Field,
                1 => wrong.transcript = iroha_plonk::cs::TranscriptV2::KagemushaPoseidonRp57,
                2 => wrong.instance_mode = iroha_plonk::cs::InstanceModeV1::Committed,
                3 => wrong.proof_suffix = iroha_plonk::cs::ProofSuffixV1::None,
                _ => wrong.instance_lengths[0] = 68,
            }
            let mut bad = original.clone();
            bad.descriptor = wrong.encode().unwrap();
            assert!(
                install_native_bootstrap(native_plan.clone(), &bad, read).is_err(),
                "installed Bootstrap profile mutation{mutation}"
            );
        }
        let changed_policy = native::Plan::new(
            operation.clone(),
            iroha_kagemusha_proof::a_relation::bootstrap::BootstrapPolicy::new(
                [31, 32],
                bootstrap_objects::key(19),
            )
            .unwrap(),
            signature.plan().clone(),
            params.clone(),
            vparams.clone(),
        )
        .unwrap();
        assert!(
            install_native_bootstrap(changed_policy, &original, read).is_err(),
            "installed policy constants must match A's exact source"
        );
        let input = native::Inputs {
            state: initial,
            objects: objects.each_ref().map(|object| object.bytes.clone()),
            q: [native::QInput {
                proof: signature_proof.proof.clone(),
                instances: siginstances.to_vec(),
            }],
        };
        let prepared = native_plan
            .prepare(input.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        let session = installed
            .prepare(input.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        // D6a (DP §7.4 test 8): a detached session resumes only on the prover
        // instance that prepared it, never on an identically installed one.
        let other =
            native::Prover::from_artifacts(native_plan.clone(), original.metadata().unwrap())
                .unwrap();
        let detached = installed
            .prepare(input.clone(), MemoryBudget::DEFAULT)
            .unwrap()
            .into_retained();
        assert!(matches!(other.resume(detached), Err(native::Error::Input)));
        drop(other);
        let (actual, actual_public) = prepared.terminal_circuit().unwrap();
        assert_eq!(actual_public, public[0], "native unsplit frame");
        // The reference source artifact must match the production fixed tables and copies.
        Witness::from_circuit(&akey, &actual, &public).unwrap();
        let actual_check = check_circuit(&actual, 16, &public, CheckMode::Strict).unwrap();
        assert!(
            actual_check.is_satisfied(),
            "production A retains all original constraints"
        );
        let known = synthesize(&actual, 16, Some(&public)).unwrap();
        let unknown = synthesize(&actual.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        drop((known, unknown));
        assert!(matches!(
            session.terminal(
                &iroha_plonk::keys::SourceBoundVerifyingKeyV2::from_proving_key(&sigma_key, None)
                    .unwrap()
                    .view(),
                common::fresh_randomness(),
                ProverConfig::default()
            ),
            Err(native::Error::Artifact)
        ));
        let terminal_seal = installed.import_terminal(&original.pk, read).unwrap();
        let terminal_key = installed.bind_terminal(&terminal_seal, None).unwrap();
        // Cancellation before reconstruction never reaches the producer.
        let cancelled = iroha_pasta::CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            session.terminal(
                &terminal_key,
                iroha_plonk::ProverRandomness::hedged(),
                ProverConfig {
                    cancellation: Some(&cancelled),
                    ..ProverConfig::default()
                }
            ),
            Err(native::Error::Cancelled)
        ));
        // D6a: the terminal runs on a session detached and resumed between fold calls.
        let session = installed.resume(session.into_retained()).unwrap();
        let native_terminal = session
            .terminal(
                &terminal_key,
                common::fresh_randomness(),
                ProverConfig::default(),
            )
            .unwrap();
        assert_ne!(native_terminal.proof, a.proof, "fresh terminal attempt");
        assert_eq!(native_terminal.instances, public[0]);
        assert_eq!(native_terminal.pallas, pallas);
        native_terminal
            .pallas
            .decide(&params, MemoryBudget::DEFAULT)
            .unwrap();
        native_terminal
            .opening
            .decide(&vparams, MemoryBudget::DEFAULT)
            .unwrap();
        eprintln!(
            "NATIVE_BOOTSTRAP_PARITY metadata_only_producer=true temporary_source_bound_PK=true fresh_terminal_verified=true"
        );
        for mutation in 0..3 {
            let mut altered = input.clone();
            match mutation {
                0 => altered.q[0].instances[0][1] += Fq::ONE,
                1 => altered.q[0].proof[64] ^= 1,
                _ => {
                    altered.objects[2].pop();
                }
            }
            assert!(
                native_plan.prepare(altered, MemoryBudget::DEFAULT).is_err(),
                "production source mutation{mutation}"
            );
        }
        installed_native_source = Some((installed, input));
    }
    if adversarial {
        for mutation in 0..12 {
            let mut bad = terminal.clone();
            match mutation {
                0 => bad.objects[1].bytes[100] ^= 1,
                1 => bad.state.lineage[17] += Fp::ONE,
                2 => bad.proof[100] ^= 1,
                3 => bad.length -= 1,
                4 => bad.q[0][0] += Fq::ONE,
                5 => bad.q[0][9] += Fq::ONE,
                6 => {
                    let slot = bad.signature_schema.slots()[0];
                    bad.signature_schema =
                        iroha_kagemusha_proof::q_signature::QSignaturePlan::new(vec![slot])
                            .unwrap();
                }
                7 | 8 => {
                    let mut slots = bad.signature_schema.slots().to_vec();
                    slots[2].key = if mutation == 7 {
                        iroha_kagemusha_proof::q_signature::SignatureKey::Fixed(
                            iroha_plonk_gadgets::p256::native::Affine::GENERATOR,
                        )
                    } else {
                        iroha_kagemusha_proof::q_signature::SignatureKey::Variable
                    };
                    bad.signature_schema =
                        iroha_kagemusha_proof::q_signature::QSignaturePlan::new(slots).unwrap();
                }
                9 => bad.signature_order = [1, 0, 2],
                10 => bad.objects[2].bytes[242] ^= 1,
                _ => bad.state.statement[17] += Fp::ONE,
            }
            assert!(
                !check_circuit(&bad, 16, &public, CheckMode::Strict)
                    .is_ok_and(|r| r.is_satisfied()),
                "unsplit mutation {mutation}"
            );
        }
        // The frame binds `D_A` over the forwarded Q opening and the pinned trivial part.
        for index in [0, 1, 6] {
            let mut wrong = public.clone();
            wrong[0][index] += Fp::ONE;
            assert!(
                !check_circuit(&terminal, 16, &wrong, CheckMode::Strict)
                    .is_ok_and(|r| r.is_satisfied()),
                "unsplit frame word {index}"
            );
        }
    }
    let known = synthesize(&terminal, 16, None).unwrap();
    let lanes: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|column| column.iter().rposition(|v| *v).map_or(0, |row| row + 1))
        .collect();
    eprintln!("unsplit Bootstrap A with 2V1F signature Q lanes={lanes:?}");
    let unknown = synthesize(&terminal.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.cs, unknown.cs);
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    if let Some((prover, input)) = installed_native_source {
        let [layout] = prover.checkpoint_layouts().unwrap();
        assert_eq!(prover.descriptors().len(), 1);
        assert_eq!(
            layout.verifying_key_digest(),
            &akey
                .vk()
                .kagemusha_digest(akey.binding())
                .unwrap()
                .to_repr()
        );
        assert_eq!(layout.proof_bytes(), output.proof.len());
        assert_eq!(layout.descriptor_digest(), prover.descriptors()[0].digest());
        // These are the maintained genuine signed Bootstrap sources, the original
        // imported key and the actual reference A proof. No codec DATA becomes authority.
        let session = prover
            .prepare(input.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        let terminal = session
            .restore_terminal(output.proof.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(terminal.instances, output.instances);
        assert_eq!(terminal.pallas, output.pallas);
        // The checkpoint retains only the original proof; frame and claims are rederived.
        let payload = session
            .encode_terminal_checkpoint(&terminal, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(payload.len(), layout.payload_bytes());
        let restored = session
            .restore_terminal_checkpoint(&payload, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(restored.proof, output.proof);
        assert_eq!(restored.instances, output.instances);
        assert_eq!(restored.pallas, output.pallas);
        assert_eq!(
            session
                .encode_terminal_checkpoint(&restored, MemoryBudget::DEFAULT)
                .unwrap(),
            payload
        );
        let mut extra = payload.clone();
        extra.push(0);
        for bad in [&[][..], &payload[..payload.len() - 1], &extra[..]] {
            assert!(
                session
                    .restore_terminal_checkpoint(bad, MemoryBudget::DEFAULT)
                    .is_err()
            );
        }
        for mutation in 0..3 {
            let mut changed = terminal.clone();
            match mutation {
                0 => changed.instances[0] += Fp::ONE,
                1 => {
                    let mut challenges = *changed.pallas.challenges();
                    challenges[0] += Fq::ONE;
                    changed.pallas = AccumulatorT::new(*changed.pallas.g(), challenges).unwrap();
                }
                _ => {
                    let mut challenges = *changed.opening.challenges();
                    challenges[0] += Fp::ONE;
                    changed.opening =
                        FoldInput::from_opening(*changed.opening.g(), &challenges).unwrap();
                }
            }
            assert!(
                session
                    .encode_terminal_checkpoint(&changed, MemoryBudget::DEFAULT)
                    .is_err(),
                "terminal metadata mutation {mutation}"
            );
        }
        let mut wrong_proof = output.proof.clone();
        wrong_proof[96] ^= 1;
        assert!(
            session
                .restore_terminal(wrong_proof, MemoryBudget::DEFAULT)
                .is_err()
        );
        // A session over a changed original Receipt tape still verifies the same Q
        // but cannot adopt this checkpoint: its source context binds every original.
        let mut altered = input;
        altered.objects[2][242] ^= 1;
        let altered = prover.prepare(altered, MemoryBudget::DEFAULT).unwrap();
        assert!(
            altered
                .restore_terminal_checkpoint(&payload, MemoryBudget::DEFAULT)
                .is_err(),
            "original Receipt tape cannot change under a retained checkpoint"
        );
    }
    Some(output)
}

#[derive(Clone)]
struct NativeBootstrapOriginal {
    descriptor: Vec<u8>,
    vk: Vec<u8>,
    pk: Vec<u8>,
}
impl NativeBootstrapOriginal {
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
        iroha_kagemusha_proof::a_relation::native::bootstrap::Error,
    > {
        use iroha_kagemusha_proof::a_relation::native::{artifact::KeyArtifact, bootstrap::Error};
        let binding = iroha_plonk::DescriptorBinding::decode_v2(&self.descriptor)
            .map_err(|_| Error::Artifact)?;
        let key =
            iroha_plonk::VerifyingKey::read(&self.vk, &binding).map_err(|_| Error::Artifact)?;
        KeyArtifact::new(binding, key).map_err(|_| Error::Artifact)
    }
}
// The test owns the original file, imports/releases its PK and returns only metadata.
fn install_native_bootstrap(
    plan: iroha_kagemusha_proof::a_relation::native::bootstrap::Plan,
    original: &NativeBootstrapOriginal,
    config: iroha_plonk::keys::pk::artifact::ReadConfig,
) -> Result<
    iroha_kagemusha_proof::a_relation::native::bootstrap::Prover,
    iroha_kagemusha_proof::a_relation::native::bootstrap::Error,
> {
    use iroha_kagemusha_proof::a_relation::native::bootstrap::Prover;
    let prover = Prover::from_artifacts(plan, original.metadata()?)?;
    prover.import_terminal(&original.pk, config)?;
    Ok(prover)
}
fn native_bootstrap_read_config(
    original: &NativeBootstrapOriginal,
) -> iroha_plonk::keys::pk::artifact::ReadConfig {
    iroha_plonk::keys::pk::artifact::ReadConfig {
        maximum_bytes: original.pk.len(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}
