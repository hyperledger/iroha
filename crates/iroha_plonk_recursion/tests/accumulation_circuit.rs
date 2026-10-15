//! Full k16 circuit/native PIPA-AS parity and adversarial binding tests.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{Ep, Eq, PastaCurve, PastaField, msm::MemoryBudget, poseidon::PoseidonField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
    pcs::ipa::{PinnedParams, commit::msm_complete, fold_evaluation, fold_scalars},
    transcript::{
        BasePoseidonHash, Transcript, TranscriptWrite, TranscriptWriter, encode_point,
        generator_coordinates,
    },
};
use iroha_plonk_gadgets::{
    bytes::{
        element::{decode_le_element, le_message_segments},
        tape::{BytesChip, BytesConfig},
    },
    statement::{bytes_to_limbs, foreign_limbs},
    tamper::{Tamper, assigned_advice_cells, check_tampered},
};
use iroha_plonk_recursion::{
    AccumulatorT, FOLD_BODY_BYTES, FOLD_WITNESS_BYTES, FoldConfig, FoldInput, FoldPurpose,
    FoldTape, FoldWitness, K,
    accumulation::{combined_commitment, context, digest_limbs, input_digest},
    accumulation_circuit::{FoldInputCells, FoldInputDecodePlan, FoldPlan, FoldSource},
    create_fold,
    obligation::{ModeCells, constrain_incoming_modes},
    verifier::{VerificationMode, VerifierChip, VerifierConfig},
    verify_fold,
};

use zeroize::Zeroizing;

// Public deterministic fixtures only; these coins are never production entropy.
fn fixture_tape<C: PastaCurve>(start: u64) -> FoldTape<C> {
    let mut value = start;
    FoldTape::try_fill::<()>(|coin| {
        *coin = C::ScalarExt::from(value);
        value += 1;
        Ok(())
    })
    .expect("public fixture tape")
}

fn fixture_purpose<C: PastaCurve>() -> FoldPurpose {
    if C::CURVE_ID == "pallas" {
        FoldPurpose::AInitial
    } else {
        FoldPurpose::SigmaBatch
    }
}

fn private_fixture_bytes<C: PastaCurve>(witness: &FoldWitness<C>) -> Zeroizing<Vec<u8>> {
    let private = witness.to_private_bytes();
    let mut bytes = Zeroizing::new(vec![0; FOLD_WITNESS_BYTES]);
    bytes.copy_from_slice(&private);
    bytes
}

#[derive(Clone, Default)]
struct Shape {
    messages: usize,
    mode_words: usize,
}

#[derive(Clone)]
struct Selection<C: PastaCurve> {
    bits: [u8; 3],
    corrected: FoldInput<C>,
}

#[derive(Clone)]
struct IncomingDecode<C: PastaCurve> {
    plan: FoldInputDecodePlan<C>,
    length: u32,
    expected_valid: bool,
}

#[derive(Clone, Debug)]
struct Config<C: PastaCurve> {
    verifier: VerifierConfig<C>,
    bytes: BytesConfig,
    public: Column<Instance>,
}

#[derive(Clone)]
struct FoldCircuit<C: PastaCurve> {
    plan: FoldPlan<C>,
    inputs: Vec<FoldInput<C>>,
    input_bytes: Vec<Vec<u8>>,
    proof: Zeroizing<Vec<u8>>,
    length: u32,
    mode: VerificationMode,
    known: bool,
    selection: Option<Selection<C>>,
    incoming_decode: Option<IncomingDecode<C>>,
}

impl<C: PastaCurve> FoldCircuit<C> {
    fn bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            self.input_bytes.iter().map(Vec::len).sum::<usize>()
                + usize::from(self.selection.is_some()) * 32 * (K + 1)
                + FOLD_WITNESS_BYTES,
        ));
        for input in &self.input_bytes {
            bytes.extend_from_slice(input);
        }
        if let Some(selection) = &self.selection {
            bytes.extend(input_bytes(&selection.corrected));
        }
        bytes.extend_from_slice(&self.proof);
        bytes
    }
    fn witness<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn instances(&self, valid: bool, output: &AccumulatorT<C>) -> Vec<C::Base> {
        // Bind public deterministic fixture bytes for mutation tests. This test-only
        // instance layout is not the private production fold interface.
        let mut values = self
            .bytes()
            .chunks_exact(32)
            .flat_map(|bytes| {
                let bytes: [u8; 32] = bytes.try_into().unwrap();
                bytes_to_limbs(&bytes).map(C::Base::from_u128)
            })
            .collect::<Vec<_>>();
        if let Some(decode) = &self.incoming_decode {
            values.extend([
                C::Base::from(u64::from(decode.length)),
                C::Base::from(u64::from(decode.expected_valid)),
            ]);
        }
        if let Some(selection) = &self.selection {
            values.extend(selection.bits.map(|bit| C::Base::from(u64::from(bit))));
        }
        values.extend([
            C::Base::from(u64::from(self.length)),
            C::Base::from(u64::from(valid)),
        ]);
        let (x, y) = generator_coordinates::<C>(output.g());
        values.extend([x, y]);
        for value in output.challenges() {
            values.extend(foreign_limbs(value).map(C::Base::from_u128));
        }
        values
    }
}

impl<C: PastaCurve> Circuit<C::Base> for FoldCircuit<C> {
    type Config = Config<C>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Shape;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn params(&self) -> Shape {
        Shape {
            messages: self.bytes().len() / 32,
            mode_words: 3 * usize::from(self.selection.is_some())
                + 2 * usize::from(self.incoming_decode.is_some()),
        }
    }
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Config<C> {
        Self::configure_with_params(meta, Shape::default())
    }
    fn configure_with_params(meta: &mut ConstraintSystem<C::Base>, shape: Shape) -> Config<C> {
        let verifier = VerifierConfig::configure(meta);
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(2 * shape.messages + 36 + shape.mode_words);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(
        &self,
        config: Config<C>,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "k16 accumulation",
            |mut region| {
                let raw = self.bytes();
                let count = raw.len() / 32;
                let values = raw
                    .iter()
                    .map(|byte| self.witness(*byte))
                    .collect::<Vec<_>>();
                let run = bytes.run(
                    &mut region,
                    &values,
                    &vec![16; 2 * count],
                    &le_message_segments(0, count),
                )?;
                let mut outputs = run
                    .primary()
                    .iter()
                    .map(|segment| segment.word().cell())
                    .collect::<Vec<_>>();
                let mut elements = Vec::with_capacity(count);
                for index in 0..count {
                    elements.push(decode_le_element(
                        &mut chip.uint(),
                        &mut region,
                        &run,
                        index * 32,
                    )?);
                }
                let mut inputs = Vec::with_capacity(self.inputs.len());
                let mut incoming_valid = None;
                for (index, input) in self.inputs.iter().enumerate() {
                    if index == 0
                        && let Some(decode) = &self.incoming_decode
                    {
                        let length = chip
                            .uint()
                            .assign::<32>(&mut region, self.witness(u128::from(decode.length)))?;
                        let decoded = FoldInputCells::decode_soft(
                            &mut chip,
                            &mut region,
                            &decode.plan,
                            &elements[..=K],
                            &length,
                        )?;
                        outputs.extend([length.cell(), decoded.valid.cell()]);
                        incoming_valid = Some(decoded.valid);
                        inputs.push(decoded.value);
                        continue;
                    }
                    inputs.push(FoldInputCells::decode(
                        &mut chip,
                        &mut region,
                        input.source_k(),
                        &elements[index * (K + 1)..(index + 1) * (K + 1)],
                    )?);
                }
                let mut proof_offset = self.inputs.len() * (K + 1);
                if let Some(selection) = &self.selection {
                    let corrected = FoldInputCells::decode(
                        &mut chip,
                        &mut region,
                        selection.corrected.source_k(),
                        &elements[proof_offset..=proof_offset + K],
                    )?;
                    proof_offset += K + 1;
                    let mut words = Vec::new();
                    for bit in selection.bits {
                        words.push(
                            chip.uint().glue().witness(
                                &mut region,
                                self.witness(C::Base::from(u64::from(bit))),
                            )?,
                        );
                    }
                    outputs.extend(words.iter().map(iroha_plonk_gadgets::Word::cell));
                    let modes = ModeCells::constrain(
                        chip.uint().glue(),
                        &mut region,
                        &words.try_into().map_err(|_| Error::Synthesis)?,
                    )?;
                    if let Some(valid) = incoming_valid.as_ref() {
                        constrain_incoming_modes(
                            chip.uint().glue(),
                            &mut region,
                            core::slice::from_ref(valid),
                            core::slice::from_ref(&modes),
                        )?;
                    }
                    inputs[0] = FoldInputCells::select_incoming(
                        &mut chip,
                        &mut region,
                        &inputs[0],
                        corrected.g(),
                        &modes,
                    )?;
                }
                let length = chip
                    .uint()
                    .assign::<32>(&mut region, self.witness(u128::from(self.length)))?;
                let fold = chip.verify_fold(
                    &mut region,
                    &self.plan,
                    &inputs,
                    &elements[proof_offset..],
                    &length,
                    self.mode,
                )?;
                let forwarded = FoldInputCells::from_claim(&mut chip, &mut region, &fold.claim)?;
                outputs.extend([
                    length.cell(),
                    fold.valid.cell(),
                    forwarded.g().x().cell(),
                    forwarded.g().y().cell(),
                ]);
                for value in forwarded.challenges() {
                    outputs.extend([value.lo().cell(), value.hi().cell()]);
                }
                Ok(outputs)
            },
        )?;
        for (row, cell) in outputs.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.public, row)?;
        }
        Ok(())
    }
}

fn input_bytes<C: PastaCurve>(input: &FoldInput<C>) -> Vec<u8> {
    let mut out = encode_point::<C>(input.g()).to_vec();
    for value in input.challenges() {
        out.extend(value.to_repr());
    }
    out
}

fn check<C: PastaCurve>(circuit: &FoldCircuit<C>, valid: bool, output: &AccumulatorT<C>) -> bool {
    check_circuit(
        circuit,
        16,
        &[circuit.instances(valid, output)],
        CheckMode::Strict,
    )
    .expect("circuit layout")
    .is_satisfied()
}

fn modulus<F: PastaField>() -> [u8; 32] {
    let mut bytes = (-F::ONE).to_repr();
    for byte in &mut bytes {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
    bytes
}

fn forged<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    purpose: FoldPurpose,
) -> FoldWitness<C>
where
    C::Base: PoseidonField,
{
    let tape = fixture_tape::<C>(181);
    let digest = input_digest(params, inputs, &tape, purpose);
    let [low, high] = digest_limbs::<C>(digest);
    let d = (params.params().g()[0].to_curve() * low
        + params.params().g()[1].to_curve() * high
        + params.params().w().to_curve() * *tape.rho())
    .to_affine();
    let mut transcript = TranscriptWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    // Write the exact protocol context without native full-length-input admission:
    // the all-short adversarial case must reach and fail the circuit predicate.
    for word in context(params, purpose, inputs.len()) {
        transcript.common_base(&word).unwrap();
    }
    transcript.write_point(&d).unwrap();
    let [alpha, z, zeta] = core::array::from_fn(|_| transcript.squeeze_challenge());
    let value = inputs.iter().rev().fold(C::ScalarExt::ZERO, |v, input| {
        v * alpha + fold_evaluation(z, input.challenges())
    });
    let mut equation =
        combined_commitment(inputs, alpha) - params.params().g()[0].to_curve() * value;
    let mut challenges = [C::ScalarExt::ZERO; K];
    let mut gamma = C::ScalarExt::ZERO;
    for (round, challenge) in challenges.iter_mut().enumerate() {
        let left =
            (C::generator() + params.params().w().to_curve() * tape.masks()[2 * round]).to_affine();
        let right = (C::generator() * C::ScalarExt::from(2_u64)
            + params.params().w().to_curve() * tape.masks()[2 * round + 1])
            .to_affine();
        transcript.write_point(&left).expect("left");
        transcript.write_point(&right).expect("right");
        *challenge =
            iroha_plonk::transcript::pipa_r::nonzero_challenge(transcript.squeeze_challenge());
        gamma += tape.masks()[2 * round] * challenge.invert().unwrap()
            + tape.masks()[2 * round + 1] * *challenge;
        equation = equation
            + left.to_curve() * challenge.invert().unwrap()
            + right.to_curve() * *challenge;
    }
    transcript.write_scalar(&C::ScalarExt::ONE);
    equation -= params.params().w().to_curve() * gamma;
    equation -= params.params().u().to_curve() * (fold_evaluation(z, &challenges) * zeta);
    transcript
        .append_unabsorbed_generator(&equation.to_affine())
        .expect("solved suffix");
    let body = Zeroizing::new(transcript.finish());
    let coins = tape.to_private_bytes();
    let mut bytes = Zeroizing::new(vec![0; FOLD_WITNESS_BYTES]);
    bytes[..FOLD_BODY_BYTES].copy_from_slice(&body);
    bytes[FOLD_BODY_BYTES..].copy_from_slice(&coins);
    FoldWitness::from_private_bytes(&bytes).expect("canonical forgery")
}

fn run<C: PastaCurve>()
where
    C::Base: PoseidonField,
{
    let purpose = fixture_purpose::<C>();
    let params = PinnedParams::<C>::derive(16).unwrap();
    assert!(matches!(
        FoldPlan::new(&params, vec![3], purpose),
        Err(iroha_plonk_recursion::Error::MissingFullLengthInput)
    ));
    assert!(FoldPlan::new(&params, vec![], purpose).is_err());
    assert!(FoldPlan::new(&params, vec![0, 16], purpose).is_err());
    let source = [
        C::ScalarExt::from(2),
        C::ScalarExt::from(3),
        C::ScalarExt::from(5),
    ];
    let coefficients = fold_scalars(&source, C::ScalarExt::ONE);
    let g = msm_complete::<C>(
        &coefficients,
        &params.params().g()[..8],
        MemoryBudget::DEFAULT,
    )
    .to_affine();
    let trivial = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let inputs = vec![
        FoldInput::from_opening(g, &source).unwrap(),
        trivial.as_input(),
    ];
    let config = FoldConfig::default();
    let (proof, output) =
        create_fold(&params, &inputs, fixture_tape::<C>(123), purpose, &config).unwrap();
    let circuit = FoldCircuit {
        plan: FoldPlan::new(&params, vec![3, 16], purpose).unwrap(),
        input_bytes: inputs.iter().map(input_bytes).collect(),
        inputs,
        proof: private_fixture_bytes(&proof),
        length: FOLD_WITNESS_BYTES as u32,
        mode: VerificationMode::Soft,
        known: true,
        selection: None,
        incoming_decode: None,
    };
    assert!(check(&circuit, true, &output));
    assert!(
        !check(&circuit, false, &trivial),
        "a prover cannot soft-reject an honest fold"
    );
    let mut hard = circuit.clone();
    hard.mode = VerificationMode::Hard;
    assert!(check(&hard, true, &output));
    let hard_instances = [hard.instances(true, &output)];
    let hard_known = synthesize(&hard, 16, Some(&hard_instances)).unwrap();
    let hard_unknown = synthesize(&hard.without_witnesses(), 16, None).unwrap();
    assert_eq!(hard_known.tables.fixed(), hard_unknown.tables.fixed());
    assert_eq!(
        hard_known.tables.permutation(),
        hard_unknown.tables.permutation()
    );
    assert_eq!(
        hard_known.tables.advice_assigned(),
        hard_unknown.tables.advice_assigned()
    );
    let instances = [circuit.instances(true, &output)];
    let known = synthesize(&circuit, 16, Some(&instances)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    let cells = assigned_advice_cells(&circuit, 16, &instances).unwrap();
    let rows = cells.iter().map(|(_, row)| row + 1).max().unwrap();
    // TODO: retain this exact old-layout oracle until coordinated source01b
    // synthesis records reviewed replacements for both curves. These numbers
    // are deliberately not guessed or replaced with weaker capacity bounds.
    let inventory = if C::CURVE_ID == "pallas" {
        (6246, 90_270)
    } else {
        (7386, 90_235)
    };
    assert_eq!(
        (rows, cells.len()),
        inventory,
        "k3+k16 fold with output forwarding"
    );
    // Target the first and last assigned cell in every lane column. The byte,
    // codec, arithmetic and ECC components separately run every-cell audits.
    for column in 0..known.tables.advice_assigned().len() {
        let positions = cells
            .iter()
            .filter(|(c, _)| *c == column)
            .map(|(_, row)| *row)
            .collect::<Vec<_>>();
        for row in positions
            .first()
            .into_iter()
            .chain(positions.last())
            .copied()
        {
            assert!(
                !check_tampered(
                    &circuit,
                    16,
                    &instances,
                    Some(Tamper {
                        column,
                        row,
                        delta: C::Base::ONE
                    })
                )
                .unwrap()
                .is_satisfied()
            );
        }
    }
    for index in [0, 1, 2, 16, 32, 33, 34, 35, FOLD_WITNESS_BYTES / 32 - 1] {
        let mut bad = circuit.clone();
        let replacement = if index == 33 || index >= FOLD_BODY_BYTES / 32 {
            modulus::<C::ScalarExt>()
        } else {
            // D/L/R are finite points; G is scoped full-group. ff32 is invalid
            // for both encodings, whereas zero32 is now a canonical G identity.
            [0xff; 32]
        };
        bad.proof[index * 32..(index + 1) * 32].copy_from_slice(&replacement);
        assert!(check(&bad, false, &trivial), "malformed message {index}");
        bad.mode = VerificationMode::Hard;
        assert!(!check(&bad, false, &trivial));
    }
    let mut bad = circuit.clone();
    bad.length = FOLD_WITNESS_BYTES as u32 - 1;
    assert!(check(&bad, false, &trivial));
    let mut bad = circuit.clone();
    let rho = Option::<C::ScalarExt>::from(C::ScalarExt::from_repr(
        bad.proof[FOLD_BODY_BYTES..FOLD_BODY_BYTES + 32]
            .try_into()
            .unwrap(),
    ))
    .unwrap();
    bad.proof[FOLD_BODY_BYTES..FOLD_BODY_BYTES + 32]
        .copy_from_slice(&(rho + C::ScalarExt::ONE).to_repr());
    assert!(check(&bad, false, &trivial));
    let mut bad = circuit.clone();
    bad.input_bytes[0][..32].copy_from_slice(&encode_point::<C>(&C::generator().to_affine()));
    assert!(check(&bad, false, &trivial));
    let mut bad = circuit.clone();
    bad.input_bytes[0][32..64].copy_from_slice(&C::ScalarExt::ONE.to_repr());
    assert!(!check(&bad, false, &trivial), "padding");
    let mut bad = circuit.clone();
    bad.input_bytes[0][K * 32..(K + 1) * 32].fill(0);
    assert!(!check(&bad, false, &trivial), "nonzero source suffix");
    let forged = forged(&params, &circuit.inputs, purpose);
    let pending = verify_fold(&params, &circuit.inputs, &forged, purpose, &config).unwrap();
    assert!(pending.decide(&params, MemoryBudget::DEFAULT).is_err());
    let mut forged_circuit = circuit.clone();
    forged_circuit.proof = private_fixture_bytes(&forged);
    assert!(
        check(&forged_circuit, true, &pending),
        "same succinct predicate, still undecided"
    );
    selected_modes(&params, &circuit, &trivial, &output);
}

fn selected_modes<C: PastaCurve>(
    params: &PinnedParams<C>,
    original: &FoldCircuit<C>,
    trivial: &AccumulatorT<C>,
    honest_output: &AccumulatorT<C>,
) where
    C::Base: PoseidonField,
{
    let purpose = fixture_purpose::<C>();
    let config = FoldConfig::default();
    let honest_source = original.inputs[0].clone();
    let mut selected = original.clone();
    selected.plan = FoldPlan::with_sources(
        params,
        vec![FoldSource::Incoming(3), FoldSource::Fixed(16)],
        purpose,
    )
    .unwrap();
    selected.selection = Some(Selection {
        bits: [1, 0, 0],
        corrected: honest_source.clone(),
    });
    assert!(
        check(&selected, true, honest_output),
        "Accept keeps original k3"
    );
    let false_source = FoldInput::from_opening(
        (honest_source.g().to_curve() + C::generator()).to_affine(),
        &honest_source.challenges()[K - 3..],
    )
    .unwrap();
    selected.inputs[0] = false_source.clone();
    selected.input_bytes[0] = input_bytes(&false_source);
    selected.selection.as_mut().unwrap().bits = [0, 0, 1];
    assert!(
        check(&selected, true, honest_output),
        "Corrected keeps original k3/challenges and changes G"
    );
    selected.selection.as_mut().unwrap().corrected = false_source;
    assert!(
        !check(&selected, false, trivial),
        "a correction equal to its original is forbidden"
    );

    // Actual sigma source metadata k12/k14 must switch to k16 for Trivial,
    // with all sixteen challenges one (no retained zero prefix).
    let (trivial_fold, trivial_output) = create_fold(
        params,
        &[trivial.as_input(), trivial.as_input()],
        fixture_tape::<C>(124),
        purpose,
        &config,
    )
    .unwrap();
    for source_k in [12, 14] {
        let source = FoldInput::from_opening(
            C::generator().to_affine(),
            &vec![C::ScalarExt::ONE; source_k],
        )
        .unwrap();
        selected.inputs[0] = source.clone();
        selected.input_bytes[0] = input_bytes(&source);
        selected.selection = Some(Selection {
            bits: [0, 1, 0],
            corrected: source,
        });
        selected.plan = FoldPlan::with_sources(
            params,
            vec![
                FoldSource::Incoming(u32::try_from(source_k).unwrap()),
                FoldSource::Fixed(16),
            ],
            purpose,
        )
        .unwrap();
        selected.proof = private_fixture_bytes(&trivial_fold);
        assert!(
            check(&selected, true, &trivial_output),
            "Trivial changes selected source to k16"
        );
        let instances = [selected.instances(true, &trivial_output)];
        let known = synthesize(&selected, 16, Some(&instances)).unwrap();
        let unknown = synthesize(&selected.without_witnesses(), 16, None).unwrap();
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        selected.selection.as_mut().unwrap().bits = [1, 0, 0];
        assert!(
            check(&selected, false, trivial),
            "the same proof cannot relabel Trivial as Accept"
        );
        selected.selection.as_mut().unwrap().bits = [1, 1, 0];
        assert!(!check(&selected, false, trivial), "mode one-hot binding");
    }

    // With a conditional slot alone, the same schema allows full Trivial and
    // rejects short Accept even when an attacker solves its succinct equation.
    selected.inputs = vec![honest_source.clone()];
    selected.input_bytes = vec![input_bytes(&honest_source)];
    selected.plan = FoldPlan::with_sources(params, vec![FoldSource::Incoming(3)], purpose).unwrap();
    selected.selection = Some(Selection {
        bits: [1, 0, 0],
        corrected: honest_source.clone(),
    });
    selected.proof = private_fixture_bytes(&forged(params, &[honest_source], purpose));
    assert!(
        check(&selected, false, trivial),
        "all-short selected inputs must reject independently of the equation"
    );
    selected.selection.as_mut().unwrap().bits = [0, 1, 0];
    let (proof, output) = create_fold(
        params,
        &[trivial.as_input()],
        fixture_tape::<C>(125),
        purpose,
        &config,
    )
    .unwrap();
    selected.proof = private_fixture_bytes(&proof);
    assert!(check(&selected, true, &output));
}

#[test]
#[ignore = "full k16 circuit; run optimized with --include-ignored"]
fn pallas_accumulation_circuit_matches_native_and_binds_every_input() {
    run::<Ep>();
}

#[test]
#[ignore = "full k16 circuit; run optimized with --include-ignored"]
fn vesta_accumulation_circuit_matches_native_and_binds_every_input() {
    run::<Eq>();
}

fn malformed_incoming_burn<C: PastaCurve>()
where
    C::Base: PoseidonField,
{
    let purpose = fixture_purpose::<C>();
    let params = PinnedParams::<C>::derive(16).unwrap();
    let trivial = AccumulatorT::trivial(&params, MemoryBudget::DEFAULT).unwrap();
    let (proof, output) = create_fold(
        &params,
        &[trivial.as_input(), trivial.as_input()],
        fixture_tape::<C>(126),
        purpose,
        &FoldConfig::default(),
    )
    .unwrap();
    for source_k in [12, 14, 16] {
        let source = FoldInput::from_opening(
            C::generator().to_affine(),
            &vec![C::ScalarExt::ONE; source_k as usize],
        )
        .unwrap();
        let original = FoldCircuit {
            plan: FoldPlan::with_sources(
                &params,
                vec![FoldSource::Incoming(source_k), FoldSource::Fixed(16)],
                purpose,
            )
            .unwrap(),
            inputs: vec![source.clone(), trivial.as_input()],
            input_bytes: vec![input_bytes(&source), input_bytes(&trivial.as_input())],
            proof: private_fixture_bytes(&proof),
            length: FOLD_WITNESS_BYTES as u32,
            mode: VerificationMode::Hard,
            known: true,
            selection: Some(Selection {
                bits: [0, 1, 0],
                corrected: source,
            }),
            incoming_decode: Some(IncomingDecode {
                plan: FoldInputDecodePlan::new(&params, source_k).unwrap(),
                length: 544,
                expected_valid: false,
            }),
        };
        let mut cases = Vec::new();
        let mut bad_point = original.clone();
        bad_point.input_bytes[0][..32].fill(0xff);
        cases.push(bad_point);
        let mut zero_challenge = original.clone();
        zero_challenge.input_bytes[0][K * 32..(K + 1) * 32].fill(0);
        cases.push(zero_challenge);
        let mut noncanonical = original.clone();
        noncanonical.input_bytes[0][K * 32..(K + 1) * 32]
            .copy_from_slice(&modulus::<C::ScalarExt>());
        cases.push(noncanonical);
        if source_k < 16 {
            let mut prefix = original.clone();
            prefix.input_bytes[0][32..64].copy_from_slice(&C::ScalarExt::ONE.to_repr());
            cases.push(prefix);
        }
        let mut wrong_length = original.clone();
        wrong_length.incoming_decode.as_mut().unwrap().length = 543;
        cases.push(wrong_length);
        for circuit in &cases {
            assert!(
                check(circuit, true, &output),
                "malformed incoming claim must support Trivial burn and a hard honest fold"
            );
        }
        let mut forged_bit = cases[0].clone();
        forged_bit.incoming_decode.as_mut().unwrap().expected_valid = true;
        assert!(!check(&forged_bit, true, &output));
        let mut forged_accept = cases[0].clone();
        forged_accept.selection.as_mut().unwrap().bits = [1, 0, 0];
        assert!(!check(&forged_accept, true, &output));
        let mut unnecessary_burn = original;
        unnecessary_burn
            .incoming_decode
            .as_mut()
            .unwrap()
            .expected_valid = true;
        assert!(
            !check(&unnecessary_burn, true, &output),
            "honest decoding alone cannot justify Trivial mode"
        );
    }
}

#[test]
#[ignore = "full k16 circuit; run optimized with --include-ignored"]
fn malformed_incoming_accumulator_allows_only_bound_burn_and_hard_fold() {
    malformed_incoming_burn::<Ep>();
    malformed_incoming_burn::<Eq>();
}
