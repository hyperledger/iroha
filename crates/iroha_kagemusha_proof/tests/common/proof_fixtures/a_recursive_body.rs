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
    q_sigma::{QSigmaPlan, SigmaClass, SigmaSlotWitness, native::QSigmaProver},
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
    create_fold,
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
    fold: Vec<u8>,
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
                    let g =
                        chip.witness_point(&mut region, self.value(Ep::from(*source.pallas.g())))?;
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
    let (x, y) = pallas.g().coordinates().unwrap();
    words.extend([x, y]);
    for value in pallas.challenges() {
        words.extend(foreign_limbs(value).map(Fp::from_u128));
    }
    let mut out = vec![
        hash_with_domain(LINEAGE_DOMAIN, &words),
        Fp::from(u64::from(part.source_k())),
    ];
    let (x, y) = part.g().coordinates().unwrap();
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
    let proof = sigma.prove(&witness, common::recovery(71)).unwrap();
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
        .prepare(slot, None, &params, Fq::from(17), &FoldConfig::default())
        .unwrap();
    let pallas_params = PinnedParams::<Ep>::derive(16).unwrap();
    let prover = QSigmaProver::keygen(&prepared, pallas_params.clone()).unwrap();
    let q = prover
        .prove(&prepared, common::recovery(72), ProverConfig::default())
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
    let (x, y) = pallas.g().coordinates().unwrap();
    words.extend([x, y]);
    for u in pallas.challenges() {
        words.extend(foreign_limbs(u).map(Fp::from_u128));
    }
    hash_with_domain(LINEAGE_DOMAIN, &words)
}

// Context framing in isolation: Q data below comes from a genuine Q fixture,
// but this test checks its context commitment, not an A1 proof or operation.
#[derive(Clone)]
struct ContextCircuit {
    plan: iroha_kagemusha_proof::a_relation::context::ContextPlan,
    statement: [Fp; 26],
    core: [Fp; 33],
    rest: [Fp; 8],
    public: [Fp; 18],
    q: Vec<Vec<Vec<Fq>>>,
    object: [u8; 36],
    object_digest: Fp,
    authentication: Option<[bootstrap_objects::Signed; 3]>,
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
        if let Some(objects) = &self.authentication {
            for (i, object) in objects.iter().enumerate() {
                let length = u32::try_from(object.bytes.len()).unwrap();
                let mut raw = length.to_le_bytes().to_vec();
                raw.extend_from_slice(&object.bytes);
                let mut tape = vec![
                    Fp::from(u64::try_from(i + 1).unwrap()),
                    Fp::from(u64::from(length)),
                ];
                tape.extend(
                    raw.chunks(31)
                        .map(|chunk| iroha_plonk_gadgets::bytes::le_value::<Fp>(chunk).unwrap()),
                );
                words.extend([
                    object.digest(),
                    Fp::from(u64::from(length)),
                    hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &tape),
                ]);
            }
        } else {
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
        }
        let base = hash_with_domain(u64::from_le_bytes(*b"kgwctx_1"), &words);
        let mut words = vec![Fp::ONE, self.plan.schema()[1], Fp::ONE, base];
        let (x, y) = self.pallas.g().coordinates().unwrap();
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
        action: ContextAction<'_>,
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
        let authentication = self
            .authentication
            .as_ref()
            .map(|objects| {
                let values = objects.each_ref().map(|object| {
                    object
                        .bytes
                        .iter()
                        .map(|byte| self.value(*byte))
                        .collect::<Vec<_>>()
                });
                iroha_kagemusha_proof::a_relation::bootstrap::BootstrapObjects::decode(
                    chip,
                    bytes,
                    region,
                    values.each_ref().map(Vec::as_slice),
                )
            })
            .transpose()?;
        let context_objects = if let Some(objects) = &authentication {
            objects.context().to_vec()
        } else {
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
            let object = ContextObjectCells::from_run(
                chip,
                region,
                ContextObjectSpec { tag, capacity: 32 },
                &object_digest,
                &tape,
            )?;
            vec![object]
        };
        let point = chip.witness_point(region, self.value(Ep::from(*self.pallas.g())))?;
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

        match action {
            ContextAction::Digest => {
                let base = self.plan.digest(chip, region, &input)?;
                Ok(vec![
                    self.plan.stage_digest(chip, region, 0, &base, &pallas)?,
                ])
            }
            ContextAction::First(source) => {
                let proof = carrier(
                    chip,
                    bytes,
                    region,
                    &source.proof,
                    source.length,
                    self.known,
                )?;
                let bindings = stage_sigma_binding(
                    chip,
                    bytes,
                    region,
                    &statement,
                    &source.sigma,
                    self.known,
                )?;
                let (instances, _) = verify_sigma(
                    chip,
                    region,
                    self.plan.operation(),
                    &input.q_instances[0],
                    &proof,
                    &bindings,
                )?;
                let first = iroha_kagemusha_proof::a_relation::split::close_first(
                    chip,
                    region,
                    &self.plan,
                    &input,
                    None,
                    &[instances],
                    &bindings,
                    None,
                    &source.params,
                )?;
                first.words(chip, region)
            }
            ContextAction::Last(last) => {
                let LastContext {
                    plan,
                    source,
                    fold,
                    vesta,
                } = *last;
                let proof = carrier(
                    chip,
                    bytes,
                    region,
                    &source.proof,
                    source.length,
                    self.known,
                )?;
                let bindings = stage_sigma_binding(
                    chip,
                    bytes,
                    region,
                    &statement,
                    &source.sigma,
                    self.known,
                )?;
                let (x, y) =
                    Option::<(Fq, Fq)>::from(vesta.g().coordinates()).ok_or(Error::Synthesis)?;
                let coordinates = [
                    scalar(chip, region, self.value(x))?,
                    scalar(chip, region, self.value(y))?,
                ];
                let challenges = vesta
                    .challenges()
                    .iter()
                    .map(|v| chip.uint().glue().witness(region, self.value(*v)))
                    .collect::<Result<Vec<_>, _>>()?;
                let vesta = VestaClaimCells::constrain(
                    chip,
                    region,
                    16,
                    coordinates,
                    challenges.try_into().map_err(|_| Error::Synthesis)?,
                )?;
                let resumed = iroha_kagemusha_proof::a_relation::split::resume_context(
                    chip, region, plan, &input, &pallas, &vesta, &proof, &bindings,
                )?;
                if authentication.is_some() && source.signature_schema.is_none() {
                    return Err(Error::Synthesis);
                }
                let mut remaining = Vec::new();
                for (offset, (raw, length)) in source.remaining.iter().enumerate() {
                    let index = plan.context().first_q_count() + offset;
                    let proof = carrier(chip, bytes, region, raw, *length, self.known)?;
                    let verified = iroha_kagemusha_proof::a_relation::verify_q(
                        chip,
                        region,
                        plan.context().operation(),
                        index,
                        input.q_instances.get(index).ok_or(Error::Synthesis)?,
                        &proof,
                    )?;
                    if let Some(schema) = &source.signature_schema {
                        let slots = iroha_kagemusha_proof::a_relation::bind_signature_q(
                            chip,
                            region,
                            plan.context().operation(),
                            index,
                            schema,
                            &verified,
                        )?;
                        if let Some(objects) = &authentication {
                            let ordered = source
                                .signature_order
                                .iter()
                                .map(|i| slots.slots().get(*i).cloned().ok_or(Error::Synthesis))
                                .collect::<Result<Vec<_>, _>>()?;
                            objects.authenticate(
                                chip,
                                region,
                                bootstrap_objects::policy(),
                                iroha_kagemusha_proof::a_relation::bootstrap::BootstrapInputs {
                                    state: &state,
                                    lineage: &public,
                                    sigma: &bindings[0],
                                    signatures: &ordered,
                                },
                            )?;
                        }
                        for (slot, words) in slots
                            .slots()
                            .iter()
                            .zip(input.q_instances[index][0].chunks_exact(10))
                        {
                            let actual = std::iter::once(slot.message())
                                .chain(slot.key())
                                .chain(slot.signature())
                                .chain(std::iter::once(slot.valid().word()));
                            for (actual, scalar) in actual.zip(words) {
                                let expected = iroha_kagemusha_proof::a_relation::bounded_word(
                                    chip, region, scalar,
                                )?;
                                GlueChip::assert_equal(region, actual, &expected)?;
                            }
                        }
                    }
                    remaining.push(verified);
                }
                let fold = carrier(chip, bytes, region, fold, 1120, self.known)?;
                let output = iroha_kagemusha_proof::a_relation::split::close_stage(
                    chip, region, plan, &resumed, None, None, None, &remaining, &fold,
                )?;
                output.words(chip, region, &public)
            }
        }
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
            |mut region| self.assign(&mut chip, &mut bytes, &mut region, ContextAction::Digest),
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
    let mut core = [Fp::ZERO; 33];
    core[0] = Fp::ONE;
    for (i, v) in core.iter_mut().enumerate().take(8).skip(1) {
        *v = Fp::from(i as u64);
    }
    for (i, v) in core.iter_mut().enumerate().take(21).skip(16) {
        *v = Fp::from(i as u64);
    }
    core[32] = Fp::from(77);
    let mut rest = [Fp::ZERO; 8];
    rest[7] = Fp::from(88);
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
        authentication: None,
        pallas: base.q_opening,
        known: true,
        wrong_order: false,
    }
}

#[derive(Clone)]
struct StageProof {
    proof: Vec<u8>,
    length: u32,
    sigma: Vec<u8>,
    params: PinnedParams<Ep>,
    remaining: Vec<(Vec<u8>, u32)>,
    signature_schema: Option<iroha_kagemusha_proof::q_signature::QSignaturePlan>,
    signature_order: [usize; 3],
}
struct LastContext<'a> {
    plan: &'a iroha_kagemusha_proof::a_relation::split::SplitPlan,
    source: &'a StageProof,
    fold: &'a [u8],
    vesta: &'a AccumulatorT<Eq>,
}
enum ContextAction<'a> {
    Digest,
    First(&'a StageProof),
    Last(Box<LastContext<'a>>),
}
fn stage_sigma_binding(
    chip: &mut VerifierChip<Ep>,
    bytes: &mut BytesChip<Fp>,
    region: &mut iroha_plonk::frontend::Region<'_, Fp>,
    statement: &StatementCells,
    sigma: &[u8],
    known: bool,
) -> Result<Vec<SigmaBindingCells>, Error> {
    let raw = sigma
        .iter()
        .map(|v| {
            if known {
                Value::known(*v)
            } else {
                Value::unknown()
            }
        })
        .collect::<Vec<_>>();
    let tape = bytes.run(
        region,
        &raw,
        &raw.chunks(31).map(<[Value<u8>]>::len).collect::<Vec<_>>(),
        &[SegmentSpec::little(0, 4)],
    )?;
    let selector = iroha_kagemusha_proof::a_relation::schedule::sigma_selector(1, 0)
        .expect("canonical Bootstrap selector");
    let key = chip
        .uint()
        .glue()
        .constant(region, Fp::from(u64::from(selector)))?;
    Ok(vec![SigmaBindingCells::from_run(
        chip, region, statement, key, &tape,
    )?])
}
#[derive(Clone)]
enum Stage {
    First,
    Last {
        plan: Box<iroha_kagemusha_proof::a_relation::split::SplitPlan>,
        fold: Vec<u8>,
        vesta: Box<AccumulatorT<Eq>>,
    },
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
#[derive(Clone)]
struct StageCircuit {
    profile: SourceProfile,
    context: ContextCircuit,
    source: StageProof,
    stage: Stage,
}
impl Circuit<Fp> for StageCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = SourceProfile;
    fn params(&self) -> SourceProfile {
        self.profile
    }
    fn without_witnesses(&self) -> Self {
        Self {
            context: self.context.without_witnesses(),
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
            || "split stage",
            |mut region| {
                let action = match &self.stage {
                    Stage::First => ContextAction::First(&self.source),
                    Stage::Last { plan, fold, vesta } => {
                        ContextAction::Last(Box::new(LastContext {
                            plan,
                            source: &self.source,
                            fold,
                            vesta,
                        }))
                    }
                };
                self.context
                    .assign(&mut chip, &mut bytes, &mut region, action)
            },
        )?;
        for (row, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
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
    pub(crate) pallas: AccumulatorT<Ep>,
    pub(crate) vesta_part: AccumulatorT<Eq>,
    pub(crate) state: iroha_kagemusha_proof::admin_sigma::BootstrapWitness,
    /// σ, Q0, Q1, A1, W and A2 exact key bytes, for scheme-cycle regressions.
    pub(crate) source_keys: [Vec<u8>; 6],
}

/// Build actual sigma/Q/A1/W/A2 proofs; optional tests do not alter the relation.
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

/// Explicit Q/A profile experiment; existing helpers keep their original Q key.
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

/// Named profile experiment, used identically for A1 and terminal A2.
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
    use iroha_kagemusha_proof::a_relation::{
        context::ContextPlan,
        split::{SplitPlan, WCircuit, WKey},
    };
    use iroha_kagemusha_proof::admin_sigma::{BOOTSTRAP_K, BootstrapCircuit};
    use iroha_kagemusha_proof::omega::OmegaWitness;
    eprintln!("BOOTSTRAP_SOURCE_PROFILE {profile:?} Q_buses={q_range_buses:?}");
    let (mut initial, certificate, credential) =
        bootstrap_objects::enrollment_for_schemes(identity, scheme, certificate_scheme);
    initial.lineage[17] = omega_digest;
    let sigma = BootstrapCircuit::new(&initial);
    let sigma_params = common::vesta_params(BOOTSTRAP_K);
    let sigma_instances = sigma.instances();
    let sigma_key = keygen_pk_v2(
        &sigma_params,
        &sigma,
        &KeygenConfigV2::pipa_r(BootstrapCircuit::instance_types().to_vec()),
    )
    .unwrap();
    let sigma_proof = create_proof_owned_with_claim(
        &sigma_params,
        &sigma_key,
        Witness::from_circuit(&sigma_key, &sigma, &sigma_instances).unwrap(),
        common::recovery(187),
        ProverConfig::default(),
    )
    .unwrap();
    let sigma_bytes = sigma_proof.proof;
    let vparams = common::vesta_params(16);
    let params = PinnedParams::<Ep>::derive(16).unwrap();
    let bootstrap_selector = iroha_kagemusha_proof::a_relation::schedule::sigma_selector(1, 0)
        .expect("canonical Bootstrap selector");
    assert_eq!(bootstrap_selector, 0);
    let sigma_plan = QSigmaPlan::new(
        SigmaClass::new(
            VerifierPlan::new(sigma_key.binding().clone(), sigma_params).unwrap(),
            vec![(
                bootstrap_selector,
                sigma_key
                    .vk()
                    .kagemusha_digest(sigma_key.binding())
                    .unwrap(),
            )],
        )
        .unwrap(),
        None,
        &vparams,
    )
    .unwrap();
    let prepared = sigma_plan
        .prepare(
            SigmaSlotWitness {
                key: sigma_key.vk().clone(),
                statement: sigma_instances[0][0],
                length: u32::try_from(sigma_bytes.len()).unwrap(),
                proof: sigma_bytes.clone(),
            },
            None,
            &vparams,
            Fq::from(71),
            &FoldConfig::default(),
        )
        .unwrap();
    assert_eq!(
        prepared.instances()[2][0],
        Fq::from(u64::from(bootstrap_selector))
    );
    let part = prepared.part().clone();
    let q = q_range_buses
        .map_or_else(
            || QSigmaProver::keygen(&prepared, params.clone()),
            |buses| QSigmaProver::keygen_serialized_foreign(&prepared, params.clone(), buses),
        )
        .unwrap();
    let qproof = q
        .prove(&prepared, common::recovery(75), ProverConfig::default())
        .unwrap();
    let qclaim = accumulate_generator(
        &params,
        q.binding(),
        q.verifying_key(),
        &qproof.instances,
        &qproof.bytes,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    let q_opening = FoldInput::from_opening(*qclaim.g(), qclaim.challenges()).unwrap();
    let fixed = QProofPlan::new(
        VerifierPlan::new(q.binding().clone(), params.clone()).unwrap(),
        q.verifying_key().clone(),
    )
    .unwrap();
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
        common::recovery(118),
        ProverConfig::default(),
    )
    .unwrap();
    let signature_claim = FoldInput::from_opening(
        *signature_proof.opening.g(),
        signature_proof.opening.challenges(),
    )
    .unwrap();
    let signature_plan = QProofPlan::new(
        VerifierPlan::new(signature_key.binding().clone(), params.clone()).unwrap(),
        signature_key.vk().clone(),
    )
    .unwrap();
    let operation = AProofPlan::new(
        Variant::Bootstrap,
        sigma_plan,
        vec![fixed, signature_plan],
        None,
        &params,
    )
    .unwrap();
    let context_plan = ContextPlan::new(
        operation,
        1,
        iroha_kagemusha_proof::a_relation::bootstrap::BootstrapObjects::context_specs()
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let mut object = core::array::from_fn(|i| u8::try_from(i).unwrap());
    object[..4].copy_from_slice(&32u32.to_le_bytes());
    let context_plan = context_plan
        .with_operation_tasks(vec![
            vec![],
            vec![
                iroha_kagemusha_proof::a_relation::schedule::OperationTask::BootstrapState,
                iroha_kagemusha_proof::a_relation::schedule::OperationTask::BootstrapAuthorization,
            ],
        ])
        .unwrap();
    let context = ContextCircuit {
        plan: context_plan,
        statement: initial.statement,
        core: initial.core,
        rest: initial.rest,
        public: initial.lineage,
        q: vec![qproof.instances, siginstances.to_vec()],
        object,
        object_digest: Fp::from(111),
        authentication: Some(objects),
        pallas: q_opening,
        known: true,
        wrong_order: false,
    };
    let source = StageProof {
        length: u32::try_from(qproof.bytes.len()).unwrap(),
        proof: qproof.bytes,
        sigma: u32::try_from(sigma_bytes.len())
            .unwrap()
            .to_le_bytes()
            .into_iter()
            .chain(sigma_bytes)
            .collect(),
        params: params.clone(),
        remaining: Vec::new(),
        signature_schema: None,
        signature_order: [0, 1, 2],
    };
    let first = StageCircuit {
        profile,
        context: context.clone(),
        source,
        stage: Stage::First,
    };
    let mut first_public = public(&context.public, &context.pallas, &part);
    first_public[0] = context.digest();
    let first_instances = [first_public.clone()];
    let first_check = check_circuit(&first, 16, &first_instances, CheckMode::Strict).unwrap();
    assert!(
        first_check.is_satisfied(),
        "{:?}",
        &first_check.failures()[..first_check.failures().len().min(8)]
    );
    let vparams = common::vesta_params(16);
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    let a1key = keygen_pk_v2(&vparams, &first, &config).unwrap();
    let witness = Witness::from_circuit(&a1key, &first, &first_instances).unwrap();
    let a1 = create_proof_owned_with_claim(
        &vparams,
        &a1key,
        witness,
        common::recovery(76),
        ProverConfig::default(),
    )
    .unwrap();
    let own = FoldInput::from_opening(*a1.opening.g(), a1.opening.challenges()).unwrap();
    let trivial = AccumulatorT::trivial(&vparams, MemoryBudget::DEFAULT)
        .unwrap()
        .as_input();
    let (vfold, vout) = create_fold(
        &vparams,
        &[part, own, trivial.clone(), trivial],
        Fq::from(31).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    let witness = OmegaWitness {
        key: a1key.vk().clone(),
        instances: first_public,
        proof: a1.proof.clone(),
        length: u32::try_from(a1.proof.len()).unwrap(),
        fold: vfold.to_bytes(),
    };
    let allow = a1key.vk().kagemusha_digest(a1key.binding()).unwrap();
    let wcircuit = WCircuit::new(
        &context.plan,
        0,
        a1key.binding().clone(),
        vparams.clone(),
        vec![allow],
        witness.clone(),
    )
    .unwrap();
    let (wkey, wprover) = WKey::keygen(&wcircuit, &params).unwrap();
    let (x, y) = vout.g().coordinates().unwrap();
    let wpublic = vec![
        vec![Fq::from_repr(context.digest().to_repr()).unwrap()],
        vec![x, y],
        vout.challenges()
            .iter()
            .map(|v| Fq::from_repr(v.to_repr()).unwrap())
            .collect(),
    ];
    assert!(
        check_circuit(&wcircuit, 16, &wpublic, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let wrapper_witness = Witness::from_circuit(&wprover, &wcircuit, &wpublic).unwrap();
    let wrapped = create_proof_owned_with_claim(
        &params,
        &wprover,
        wrapper_witness,
        common::recovery(77),
        ProverConfig::default(),
    )
    .unwrap();
    let wopening =
        FoldInput::from_opening(*wrapped.opening.g(), wrapped.opening.challenges()).unwrap();
    let (pfold, pout) = create_fold(
        &params,
        &[
            context.pallas.clone(),
            wopening.clone(),
            signature_claim.clone(),
        ],
        Fp::from(32).to_repr(),
        &FoldConfig::default(),
    )
    .unwrap();
    let plan = SplitPlan::new(context.plan.clone(), 1, wkey, &params).unwrap();
    let last = StageCircuit {
        profile,
        context: context.clone(),
        source: StageProof {
            length: u32::try_from(wrapped.proof.len()).unwrap(),
            proof: wrapped.proof,
            sigma: first.source.sigma.clone(),
            params: params.clone(),
            remaining: vec![(
                signature_proof.proof.clone(),
                u32::try_from(signature_proof.proof.len()).unwrap(),
            )],
            signature_schema: Some(signature.plan().clone()),
            signature_order: [0, 1, 2],
        },
        stage: Stage::Last {
            plan: Box::new(plan),
            fold: pfold.to_bytes().to_vec(),
            vesta: Box::new(vout.clone()),
        },
    };
    let last_public = [public(&context.public, &pout.as_input(), &vout.as_input())];
    let last_check =
        check_circuit(&last, 16, &last_public, CheckMode::Strict).unwrap_or_else(|error| {
            let diagnostic = synthesize(&last, 17, Some(&last_public)).unwrap();
            let lanes: Vec<_> = diagnostic
                .tables
                .advice_assigned()
                .iter()
                .map(|col| col.iter().rposition(|v| *v).map_or(0, |row| row + 1))
                .collect();
            panic!("A2 with signature leaf k16 capacity failure {error:?}: lanes{lanes:?}");
        });
    if scheme != certificate_scheme {
        assert!(
            !last_check.is_satisfied(),
            "valid signatures must not authorize a foreign certificate scheme"
        );
        eprintln!(
            "BOOTSTRAP_FOREIGN_SCHEME_REJECTED signed_originals=true actual_sigma_q_a1_w=true terminal_proof=false"
        );
        return None;
    }
    assert!(
        last_check.is_satisfied(),
        "{:?}",
        &last_check.failures()[..last_check.failures().len().min(8)]
    );
    let a2key = keygen_pk_v2(&vparams, &last, &config).unwrap();
    assert_eq!(
        a1key.binding().descriptor(),
        a2key.binding().descriptor(),
        "uniform A1/A2 descriptor"
    );
    let a2witness = Witness::from_circuit(&a2key, &last, &last_public).unwrap();
    let a2 = create_proof_owned_with_claim(
        &vparams,
        &a2key,
        a2witness,
        common::recovery(78),
        ProverConfig::default(),
    )
    .unwrap();
    let a2claim = accumulate_generator(
        &vparams,
        a2key.binding(),
        a2key.vk(),
        &last_public,
        &a2.proof,
        MemoryBudget::DEFAULT,
    )
    .unwrap();
    a2claim.decide(&vparams, MemoryBudget::DEFAULT).unwrap();
    pout.decide(&params, MemoryBudget::DEFAULT).unwrap();
    vout.decide(&vparams, MemoryBudget::DEFAULT).unwrap();
    let mut installed_native_source = None;
    if adversarial
        && profile
            == (SourceProfile::Tagged {
                buses: iroha_kagemusha_proof::a_relation::native::bootstrap::SOURCE_RANGE_BUSES,
            })
    {
        use iroha_kagemusha_proof::a_relation::native::bootstrap as native;
        let native_plan = native::Plan::new(
            context.plan.operation().clone(),
            bootstrap_objects::policy(),
            signature.plan().clone(),
            params.clone(),
            vparams.clone(),
        )
        .unwrap();
        native_source_factory_checks::assert_factories(
            native_plan.context(),
            &params,
            &vparams,
            &[&a1key, &a2key].map(|key| {
                iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact::new(
                    key.binding().clone(),
                    key.vk().clone(),
                )
                .unwrap()
            }),
            &[
                iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact::new(
                    wprover.binding().clone(),
                    wprover.vk().clone(),
                )
                .unwrap(),
            ],
            |stage, previous| native_plan.source_circuit(stage, previous),
            |stage, binding, key| native_plan.wrapper_source(stage, binding, key),
        );
        // Installation has no operation input: fixed source, Q/root policy and
        // authenticated verifier identities are selected before native prepare.
        let originals = [
            NativeBootstrapOriginal::from_key(&a1key),
            NativeBootstrapOriginal::from_key(&wprover),
            NativeBootstrapOriginal::from_key(&a2key),
        ];
        let config = native_bootstrap_read_config(&originals);
        let install = install_native_bootstrap;
        let installed = install(native_plan.clone(), &originals, config).unwrap();
        assert_eq!(
            installed.descriptors(),
            [a1key.binding(), wprover.binding(), a2key.binding()]
        );
        for mutation in 0..8 {
            let mut bad = originals.clone();
            match mutation {
                0 => bad[0].vk.clone_from(&originals[2].vk),
                1 => bad[0].pk[44 + originals[0].vk.len()] ^= 1, // exact copy digest
                2 => bad[0].pk[44 + originals[0].vk.len() + 32] ^= 1, // fixed table
                3 => bad.swap(0, 2), // same descriptor, different installed stage source
                4 => bad[1].descriptor.clone_from(&originals[0].descriptor),
                5 => bad[0].pk.push(0),
                6 => {
                    bad[0].pk.pop();
                }
                _ => bad[2].vk.clone_from(&originals[0].vk),
            }
            assert!(
                install(native_plan.clone(), &bad, config).is_err(),
                "installed Bootstrap original mutation{mutation}"
            );
        }
        for maximum_rows in [0, (1 << 16) - 1] {
            assert!(
                install(
                    native_plan.clone(),
                    &originals,
                    iroha_plonk::keys::pk::artifact::ReadConfig {
                        maximum_rows,
                        ..config
                    }
                )
                .is_err()
            );
        }
        assert!(
            install(
                native_plan.clone(),
                &originals,
                iroha_plonk::keys::pk::artifact::ReadConfig {
                    maximum_bytes: 0,
                    ..config
                }
            )
            .is_err()
        );
        let descriptor =
            iroha_plonk::cs::CircuitDescriptorV2::decode(&originals[0].descriptor).unwrap();
        for mutation in 0..5 {
            let mut wrong = descriptor.clone();
            match mutation {
                0 => wrong.instance_types[0] = InstanceType::Field,
                1 => wrong.transcript = iroha_plonk::cs::TranscriptV2::KagemushaPoseidonRp57,
                2 => wrong.instance_mode = iroha_plonk::cs::InstanceModeV1::Committed,
                3 => wrong.proof_suffix = iroha_plonk::cs::ProofSuffixV1::None,
                _ => wrong.instance_lengths[0] = 68,
            }
            let mut bad = originals.clone();
            bad[0].descriptor = wrong.encode().unwrap();
            assert!(
                install(native_plan.clone(), &bad, config).is_err(),
                "installed Bootstrap profile mutation{mutation}"
            );
        }
        let changed_policy = native::Plan::new(
            context.plan.operation().clone(),
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
            install(changed_policy, &originals, config).is_err(),
            "installed policy constants must match A2's exact source"
        );
        let input = native::Inputs {
            state: initial,
            sigma: first.source.sigma[4..].to_vec(),
            objects: context
                .authentication
                .as_ref()
                .unwrap()
                .each_ref()
                .map(|object| object.bytes.clone()),
            q: [
                native::QInput {
                    proof: first.source.proof.clone(),
                    instances: context.q[0].clone(),
                },
                native::QInput {
                    proof: last.source.remaining[0].0.clone(),
                    instances: context.q[1].clone(),
                },
            ],
        };
        let prepared = native_plan
            .prepare(input.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        let session = installed
            .prepare(input.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        let actual_first = prepared.first_circuit();
        // Offline fixture keys supply independent source/copy differentials;
        // all native proofs below use keys mounted by the original-only owner.
        let mounted_first = originals[0].metadata::<Eq>().unwrap();
        // Existing source artifacts must match the actual production fixed tables and copies.
        Witness::from_circuit(&a1key, &actual_first, &first_instances).unwrap();
        let first_check =
            check_circuit(&actual_first, 16, &first_instances, CheckMode::Strict).unwrap();
        assert!(
            first_check.is_satisfied(),
            "production A1 retains all original constraints"
        );
        assert!(matches!(
            session.first(
                &iroha_plonk::keys::SourceBoundVerifyingKeyV2::from_proving_key(&a2key, None)
                    .unwrap()
                    .view(),
                common::recovery(76),
                ProverConfig::default()
            ),
            Err(native::Error::Artifact)
        ));
        let first_key_seal = installed.import_first(&originals[0].pk, config).unwrap();
        let first_key = installed.bind_first(&first_key_seal, None).unwrap();
        // Cancellation before reconstruction consumes no recovery stream.
        let cancelled = iroha_pasta::CancellationToken::new();
        cancelled.cancel();
        let early = iroha_plonk::ProverRandomness::recovery(
            |_: &[u8; 32]| -> Result<rand_chacha::ChaCha20Rng, std::convert::Infallible> {
                panic!("pre-cancelled A1 must not request recovery entropy")
            },
        );
        assert!(matches!(
            session.first(
                &first_key,
                early,
                ProverConfig {
                    cancellation: Some(&cancelled),
                    ..ProverConfig::default()
                }
            ),
            Err(native::Error::Cancelled)
        ));
        // The recovery derivation occurs after exact source reconstruction and
        // witness assignment. A cancellation there must drop the temporary PK;
        // the following existing parity proof reuses the unchanged metadata.
        let late_cancel = iroha_pasta::CancellationToken::new();
        let requested = std::sync::atomic::AtomicBool::new(false);
        let late = iroha_plonk::ProverRandomness::recovery(|_: &[u8; 32]| {
            requested.store(true, std::sync::atomic::Ordering::SeqCst);
            late_cancel.cancel();
            Ok::<rand_chacha::ChaCha20Rng, std::convert::Infallible>(
                rand_chacha::rand_core::SeedableRng::from_seed([76; 32]),
            )
        });
        assert!(matches!(
            session.first(
                &first_key,
                late,
                ProverConfig {
                    cancellation: Some(&late_cancel),
                    ..ProverConfig::default()
                }
            ),
            Err(native::Error::Cancelled)
        ));
        assert!(requested.load(std::sync::atomic::Ordering::SeqCst));
        let native_first = session
            .first(&first_key, common::recovery(76), ProverConfig::default())
            .unwrap();
        drop(first_key_seal);
        assert_eq!(native_first.proof(), a1.proof);
        let (wrapper_circuit, _, _) = prepared
            .wrapper_circuit(
                &native_first,
                &mounted_first,
                Fq::from(31),
                &FoldConfig::default(),
            )
            .unwrap();
        let mounted_wrapper = &wprover;
        assert!(matches!(
            session.wrapper(
                &native_first,
                &iroha_plonk::keys::SourceBoundVerifyingKeyV2::from_proving_key(
                    &signature_key,
                    None
                )
                .unwrap()
                .view(),
                Fq::from(31),
                &FoldConfig::default(),
                common::recovery(77),
                ProverConfig::default()
            ),
            Err(native::Error::Artifact)
        ));
        let wrapper_key_seal = installed.import_wrapper(&originals[1].pk, config).unwrap();
        let wrapper_key = installed.bind_wrapper(&wrapper_key_seal, None).unwrap();
        let native_wrapper = session
            .wrapper(
                &native_first,
                &wrapper_key,
                Fq::from(31),
                &FoldConfig::default(),
                common::recovery(77),
                ProverConfig::default(),
            )
            .unwrap();
        drop(wrapper_key_seal);
        assert_eq!(native_wrapper.proof(), last.source.proof);
        let wrapper_public = vec![
            vec![Fq::from_repr(native_wrapper.context().to_repr()).unwrap()],
            {
                let (x, y) =
                    Option::<(Fq, Fq)>::from(native_wrapper.vesta().g().coordinates()).unwrap();
                vec![x, y]
            },
            native_wrapper
                .vesta()
                .challenges()
                .iter()
                .map(|value| Fq::from_repr(value.to_repr()).unwrap())
                .collect(),
        ];
        Witness::from_circuit(mounted_wrapper, &wrapper_circuit, &wrapper_public).unwrap();
        let imported = WKey::from_artifact(
            &context.plan,
            0,
            wprover.binding().clone(),
            params.clone(),
            wprover.vk().clone(),
        )
        .unwrap();
        assert!(
            WKey::from_artifact(
                &context.plan,
                1,
                wprover.binding().clone(),
                params.clone(),
                wprover.vk().clone(),
            )
            .is_err(),
            "terminal stage cannot import W"
        );
        assert!(
            WKey::from_artifact(
                &context.plan,
                0,
                signature_key.binding().clone(),
                params.clone(),
                signature_key.vk().clone(),
            )
            .is_err(),
            "same-curve signature key cannot become W"
        );
        let known = synthesize(&actual_first, 16, Some(&first_instances)).unwrap();
        let unknown = synthesize(&actual_first.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        let (terminal_circuit, terminal_instances, _) = prepared
            .terminal_circuit(
                &native_wrapper,
                &imported,
                Fp::from(32),
                &FoldConfig::default(),
            )
            .unwrap();
        Witness::from_circuit(&a2key, &terminal_circuit, &[terminal_instances]).unwrap();
        assert!(matches!(
            session.terminal(
                &native_wrapper,
                &iroha_plonk::keys::SourceBoundVerifyingKeyV2::from_proving_key(&a1key, None)
                    .unwrap()
                    .view(),
                Fp::from(32),
                &FoldConfig::default(),
                common::recovery(78),
                ProverConfig::default()
            ),
            Err(native::Error::Artifact)
        ));
        let terminal_key_seal = installed.import_terminal(&originals[2].pk, config).unwrap();
        let terminal_key = installed.bind_terminal(&terminal_key_seal, None).unwrap();
        let terminal = session
            .terminal(
                &native_wrapper,
                &terminal_key,
                Fp::from(32),
                &FoldConfig::default(),
                common::recovery(78),
                ProverConfig::default(),
            )
            .unwrap();
        drop(terminal_key_seal);
        assert_eq!(terminal.proof, a2.proof);
        eprintln!(
            "NATIVE_BOOTSTRAP_PARITY metadata_only_producer=true temporary_source_bound_PK=true exact_original_proof_bytes=true"
        );
        installed_native_source = Some((installed, native_plan.clone(), input.clone()));
        terminal
            .pallas
            .decide(&params, MemoryBudget::DEFAULT)
            .unwrap();
        terminal
            .vesta
            .decide(&vparams, MemoryBudget::DEFAULT)
            .unwrap();
        terminal
            .opening
            .decide(&vparams, MemoryBudget::DEFAULT)
            .unwrap();
        for mutation in 0..3 {
            let mut altered = input.clone();
            match mutation {
                0 => altered.sigma[128] ^= 1,
                1 => altered.q[0].instances[0][1] += Fq::ONE,
                _ => altered.q[1].proof[64] ^= 1,
            }
            assert!(
                native_plan.prepare(altered, MemoryBudget::DEFAULT).is_err(),
                "production source mutation{mutation}"
            );
        }
        let mut altered = input;
        altered.objects[2][242] ^= 1;
        let altered = native_plan.prepare(altered, MemoryBudget::DEFAULT).unwrap();
        assert!(
            altered
                .resume_wrapper(&imported, native_wrapper, MemoryBudget::DEFAULT)
                .is_err(),
            "original Receipt tape cannot change across a retained W"
        );
    }
    if adversarial {
        let (dropped, _) = create_fold(
            &params,
            std::slice::from_ref(&wopening),
            Fp::from(32).to_repr(),
            &FoldConfig::default(),
        )
        .unwrap();
        let wrong_w = WCircuit::new(
            &context.plan,
            0,
            a1key.binding().clone(),
            vparams,
            vec![allow + Fq::ONE],
            witness,
        )
        .unwrap();
        let (wrong_key, wrong_prover) = WKey::keygen(&wrong_w, &params).unwrap();
        if let Some((_, native_plan, _)) = &installed_native_source {
            let originals = [
                NativeBootstrapOriginal::from_key(&a1key),
                NativeBootstrapOriginal::from_key(&wrong_prover),
                NativeBootstrapOriginal::from_key(&a2key),
            ];
            assert!(
                install_native_bootstrap(
                    native_plan.clone(),
                    &originals,
                    native_bootstrap_read_config(&originals),
                )
                .is_err(),
                "W0 original must retain the exact preceding A1 key digest"
            );
            let mut substituted_vk = originals.clone();
            substituted_vk[1].pk = wprover.artifact_bytes_v2().unwrap();
            assert!(
                install_native_bootstrap(
                    native_plan.clone(),
                    &substituted_vk,
                    native_bootstrap_read_config(&substituted_vk),
                )
                .is_err(),
                "W0 PK must retain the independently installed W verifying key"
            );
        }
        for mutation in 0..15 {
            let mut bad = last.clone();
            match mutation {
                0 => bad.context.authentication.as_mut().unwrap()[1].bytes[100] ^= 1,
                1 => bad.context.public[17] += Fp::ONE,
                2 => bad.source.proof[100] ^= 1,
                3 => bad.source.length -= 1,
                4 => {
                    if let Stage::Last { fold, .. } = &mut bad.stage {
                        *fold = dropped.to_bytes().to_vec();
                    }
                }
                5 => {
                    if let Stage::Last { plan, .. } = &mut bad.stage {
                        **plan =
                            SplitPlan::new(context.plan.clone(), 1, wrong_key.clone(), &params)
                                .unwrap();
                    }
                }
                6 => bad.context.q[0][0][0] += Fq::ONE,
                7 => bad.source.remaining.clear(),
                8 => bad.source.remaining[0].0[100] ^= 1,
                9 => bad.context.q[1][0][9] += Fq::ONE,
                10 => {
                    let slot = bad.source.signature_schema.as_ref().unwrap().slots()[0];
                    bad.source.signature_schema = Some(
                        iroha_kagemusha_proof::q_signature::QSignaturePlan::new(vec![slot])
                            .unwrap(),
                    );
                }
                11 | 12 => {
                    let mut slots = bad
                        .source
                        .signature_schema
                        .as_ref()
                        .unwrap()
                        .slots()
                        .to_vec();
                    slots[2].key = if mutation == 11 {
                        iroha_kagemusha_proof::q_signature::SignatureKey::Fixed(
                            iroha_plonk_gadgets::p256::native::Affine::GENERATOR,
                        )
                    } else {
                        iroha_kagemusha_proof::q_signature::SignatureKey::Variable
                    };
                    bad.source.signature_schema = Some(
                        iroha_kagemusha_proof::q_signature::QSignaturePlan::new(slots).unwrap(),
                    );
                }
                13 => bad.source.signature_order = [1, 0, 2],
                _ => bad.source.signature_schema = None,
            }
            assert!(
                !check_circuit(&bad, 16, &last_public, CheckMode::Strict)
                    .is_ok_and(|r| r.is_satisfied()),
                "split mutation {mutation}"
            );
        }
        let obligations = [context.pallas.clone(), wopening.clone(), signature_claim];
        for omitted in 0..obligations.len() {
            let claims: Vec<_> = obligations
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, claim)| claim.clone())
                .collect();
            let (fold, _) = create_fold(
                &params,
                &claims,
                Fp::from(32).to_repr(),
                &FoldConfig::default(),
            )
            .unwrap();
            let mut bad = last.clone();
            if let Stage::Last { fold: proof, .. } = &mut bad.stage {
                *proof = fold.to_bytes().to_vec();
            }
            assert!(
                !check_circuit(&bad, 16, &last_public, CheckMode::Strict)
                    .is_ok_and(|r| r.is_satisfied()),
                "dropped split obligation {omitted}"
            );
        }
    }
    for (stage, circuit) in [(1, &first), (2, &last)] {
        let known = synthesize(circuit, 16, None).unwrap();
        let lanes: Vec<_> = known
            .tables
            .advice_assigned()
            .iter()
            .map(|column| column.iter().rposition(|v| *v).map_or(0, |row| row + 1))
            .collect();
        eprintln!("split A{stage} with 2V1F signature Q lanes={lanes:?}");
        {
            let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
            assert_eq!(known.cs, unknown.cs);
            assert_eq!(known.tables.fixed(), unknown.tables.fixed());
            assert_eq!(known.tables.selectors(), unknown.tables.selectors());
            assert_eq!(known.tables.permutation(), unknown.tables.permutation());
            assert_eq!(
                known.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
        }
    }
    let output = AuthenticatedBootstrap {
        key: a2key.vk().clone(),
        binding: a2key.binding().clone(),
        proof: a2.proof,
        instances: last_public[0].clone(),
        opening: FoldInput::from_opening(*a2claim.g(), a2claim.challenges()).unwrap(),
        pallas: pout,
        vesta_part: vout,
        state: initial,
        source_keys: [
            sigma_key.vk().to_bytes().to_vec(),
            q.verifying_key().to_bytes().to_vec(),
            signature_key.vk().to_bytes().to_vec(),
            a1key.vk().to_bytes().to_vec(),
            wprover.vk().to_bytes().to_vec(),
            a2key.vk().to_bytes().to_vec(),
        ],
    };
    if let Some((prover, _, input)) = installed_native_source {
        use iroha_kagemusha_proof::a_relation::native::bootstrap::CheckpointKind;
        let first_key_digest = a1key
            .vk()
            .kagemusha_digest(a1key.binding())
            .unwrap()
            .to_repr();
        let wrapper_key_digest = wprover
            .vk()
            .kagemusha_digest(wprover.binding())
            .unwrap()
            .to_repr();
        assert_eq!(prover.descriptors().len(), 3);
        let session = prover.prepare(input, MemoryBudget::DEFAULT).unwrap();
        let first_checkpoint = session
            .restore_first(a1.proof.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        let wrapper_checkpoint = session
            .restore_wrapper(
                last.source.proof.clone(),
                &output.vesta_part.to_bytes(),
                MemoryBudget::DEFAULT,
            )
            .unwrap();
        // These are the maintained genuine signed Bootstrap sources, original
        // imported keys and actual A1/W proofs. No codec DATA becomes authority.
        let layouts = prover.checkpoint_layouts().unwrap();
        assert_eq!(layouts[0].kind(), CheckpointKind::First);
        assert_eq!(layouts[1].kind(), CheckpointKind::Wrapper);
        assert_eq!(layouts[0].verifying_key_digest(), &first_key_digest);
        assert_eq!(layouts[1].verifying_key_digest(), &wrapper_key_digest);
        assert_eq!(layouts[0].proof_bytes(), a1.proof.len());
        assert_eq!(layouts[1].proof_bytes(), last.source.proof.len());
        assert_eq!(
            layouts[0].descriptor_digest(),
            prover.descriptors()[0].digest()
        );
        assert_eq!(
            layouts[1].descriptor_digest(),
            prover.descriptors()[1].digest()
        );
        let first_payload = session
            .encode_first_checkpoint(&first_checkpoint, MemoryBudget::DEFAULT)
            .unwrap();
        let wrapper_payload = session
            .encode_wrapper_checkpoint(&wrapper_checkpoint, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(first_payload.len(), layouts[0].payload_bytes());
        assert_eq!(wrapper_payload.len(), layouts[1].payload_bytes());
        let restored_first = session
            .restore_first_checkpoint(&first_payload, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(restored_first.proof(), first_checkpoint.proof());
        assert_eq!(restored_first.instances(), first_checkpoint.instances());
        assert_eq!(
            session
                .encode_first_checkpoint(&restored_first, MemoryBudget::DEFAULT)
                .unwrap(),
            first_payload
        );
        let restored_wrapper = session
            .restore_wrapper_checkpoint(&wrapper_payload, MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(restored_wrapper.proof(), wrapper_checkpoint.proof());
        assert_eq!(restored_wrapper.vesta(), wrapper_checkpoint.vesta());
        assert_eq!(restored_wrapper.context(), wrapper_checkpoint.context());
        assert_eq!(
            session
                .encode_wrapper_checkpoint(&restored_wrapper, MemoryBudget::DEFAULT)
                .unwrap(),
            wrapper_payload
        );
        assert!(
            session
                .restore_first_checkpoint(&wrapper_payload, MemoryBudget::DEFAULT)
                .is_err()
        );
        assert!(
            session
                .restore_wrapper_checkpoint(&first_payload, MemoryBudget::DEFAULT)
                .is_err()
        );
        for payload in [&first_payload, &wrapper_payload] {
            let mut extra = payload.clone();
            extra.push(0);
            for bad in [&[][..], &payload[..payload.len() - 1], &extra[..]] {
                assert!(
                    session
                        .restore_first_checkpoint(bad, MemoryBudget::DEFAULT)
                        .is_err()
                );
                assert!(
                    session
                        .restore_wrapper_checkpoint(bad, MemoryBudget::DEFAULT)
                        .is_err()
                );
            }
        }
        assert_eq!(layouts[2].kind(), CheckpointKind::Terminal);
        assert_eq!(layouts[2].proof_bytes(), output.proof.len());
        assert_eq!(
            layouts[2].descriptor_digest(),
            prover.descriptors()[2].digest()
        );
        let terminal = session
            .restore_terminal(
                &restored_wrapper,
                output.proof.clone(),
                Fp::from(32),
                MemoryBudget::DEFAULT,
            )
            .unwrap();
        assert_eq!(terminal.instances, output.instances);
        assert_eq!(terminal.vesta, output.vesta_part);
        let terminal_payload = session
            .encode_terminal_checkpoint(
                &restored_wrapper,
                &terminal,
                Fp::from(32),
                MemoryBudget::DEFAULT,
            )
            .unwrap();
        assert_eq!(terminal_payload.len(), layouts[2].payload_bytes());
        let restored_terminal = session
            .restore_terminal_checkpoint(
                &restored_wrapper,
                &terminal_payload,
                MemoryBudget::DEFAULT,
            )
            .unwrap();
        assert_eq!(restored_terminal.proof, output.proof);
        assert_eq!(restored_terminal.instances, output.instances);
        assert_eq!(restored_terminal.pallas, output.pallas);
        assert_eq!(
            session
                .encode_terminal_checkpoint(
                    &restored_wrapper,
                    &restored_terminal,
                    Fp::from(32),
                    MemoryBudget::DEFAULT
                )
                .unwrap(),
            terminal_payload
        );
        for wrong_kind in [&first_payload, &wrapper_payload] {
            assert!(
                session
                    .restore_terminal_checkpoint(
                        &restored_wrapper,
                        wrong_kind,
                        MemoryBudget::DEFAULT
                    )
                    .is_err()
            );
        }
        let mut trailing = terminal_payload.clone();
        trailing.push(0);
        for original in [
            &[][..],
            &terminal_payload[..terminal_payload.len() - 1],
            &trailing,
        ] {
            assert!(
                session
                    .restore_terminal_checkpoint(&restored_wrapper, original, MemoryBudget::DEFAULT)
                    .is_err()
            );
        }
        for mutation in 0..4 {
            let mut changed = terminal.clone();
            match mutation {
                0 => changed.instances[0] += Fp::ONE,
                1 => {
                    let mut challenges = *changed.pallas.challenges();
                    challenges[0] += Fq::ONE;
                    changed.pallas = AccumulatorT::new(*changed.pallas.g(), challenges).unwrap();
                }
                2 => {
                    let mut challenges = *changed.vesta.challenges();
                    challenges[0] += Fp::ONE;
                    changed.vesta = AccumulatorT::new(*changed.vesta.g(), challenges).unwrap();
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
                    .encode_terminal_checkpoint(
                        &restored_wrapper,
                        &changed,
                        Fp::from(32),
                        MemoryBudget::DEFAULT,
                    )
                    .is_err(),
                "terminal metadata mutation {mutation}"
            );
        }
        assert!(
            session
                .restore_terminal(
                    &restored_wrapper,
                    output.proof.clone(),
                    Fp::from(33),
                    MemoryBudget::DEFAULT
                )
                .is_err()
        );
        let mut wrong_proof = output.proof.clone();
        wrong_proof[96] ^= 1;
        assert!(
            session
                .restore_terminal(
                    &restored_wrapper,
                    wrong_proof,
                    Fp::from(32),
                    MemoryBudget::DEFAULT
                )
                .is_err()
        );
        let mut wrong = a1.proof;
        wrong[96] ^= 1;
        assert!(session.restore_first(wrong, MemoryBudget::DEFAULT).is_err());
        let mut wrong = output.vesta_part.to_bytes();
        wrong[32..64].fill(0);
        assert!(
            session
                .restore_wrapper(last.source.proof, &wrong, MemoryBudget::DEFAULT)
                .is_err()
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
// The test owns original files, imports/releases each PK and returns only metadata.
fn install_native_bootstrap(
    plan: iroha_kagemusha_proof::a_relation::native::bootstrap::Plan,
    originals: &[NativeBootstrapOriginal; 3],
    config: iroha_plonk::keys::pk::artifact::ReadConfig,
) -> Result<
    iroha_kagemusha_proof::a_relation::native::bootstrap::Prover,
    iroha_kagemusha_proof::a_relation::native::bootstrap::Error,
> {
    use iroha_kagemusha_proof::a_relation::native::bootstrap::Prover;
    let prover = Prover::from_artifacts(
        plan,
        originals[0].metadata()?,
        originals[1].metadata()?,
        originals[2].metadata()?,
    )?;
    drop(prover.import_first(&originals[0].pk, config)?);
    drop(prover.import_wrapper(&originals[1].pk, config)?);
    drop(prover.import_terminal(&originals[2].pk, config)?);
    Ok(prover)
}
fn native_bootstrap_read_config(
    originals: &[NativeBootstrapOriginal; 3],
) -> iroha_plonk::keys::pk::artifact::ReadConfig {
    iroha_plonk::keys::pk::artifact::ReadConfig {
        maximum_bytes: originals
            .iter()
            .map(|original| original.pk.len())
            .max()
            .unwrap(),
        maximum_rows: 1 << 16,
        coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}
