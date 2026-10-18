//! Actual A carrier decoding and mode selection preserve full-group G obligations.

use super::*;
use iroha_plonk::transcript::{decode_generator, generator_coordinates};
use iroha_plonk_gadgets::bytes::element::le_message_segments;
use iroha_plonk_recursion::obligation::ModeCells;

#[derive(Clone)]
struct Claims {
    plan: FoldInputDecodePlan<Ep>,
    pallas: Vec<u8>,
    vesta: Vec<u8>,
    correction: [Fp; 2],
    mode: [Fp; 3],
    hard: bool,
    known: bool,
}

impl Circuit<Fp> for Claims {
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
        let verifier = VerifierConfig::configure(meta);
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(96);
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
        let words = layouter.assign_region(
            || "same-tape full-group G claim and correction",
            |mut region| {
                let mut messages = Vec::new();
                for raw in [&self.pallas, &self.vesta] {
                    let values = raw.iter().map(|v| self.value(*v)).collect::<Vec<_>>();
                    let run = bytes.run(
                        &mut region,
                        &values,
                        &chunk_segments(0, raw.len()),
                        &le_message_segments(0, 17),
                    )?;
                    messages.push(ProofMessageCells::fixed_slice(
                        &mut chip,
                        &mut region,
                        &run,
                        0,
                        ACCUMULATOR_BYTES,
                    )?);
                }
                let p = FoldInputCells::decode_soft(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    messages[0].messages(),
                    messages[0].length(),
                )?;
                let (v, valid_v) = VestaClaimCells::decode_soft(
                    &mut chip,
                    &mut region,
                    messages[1].messages(),
                    messages[1].length(),
                )?;
                if self.hard {
                    // The native-curve hard API must admit the same canonical
                    // identity; the foreign A bridge makes its total bit mandatory.
                    let hard_p =
                        FoldInputCells::decode(&mut chip, &mut region, 16, messages[0].messages())?;
                    GlueChip::assert_equal(&mut region, p.value.g().x(), hard_p.g().x())?;
                    GlueChip::assert_equal(&mut region, p.value.g().y(), hard_p.g().y())?;
                    GlueChip::assert_constant(&mut region, p.valid.word(), Fp::ONE)?;
                    GlueChip::assert_constant(&mut region, valid_v.word(), Fp::ONE)?;
                }
                let x = chip
                    .uint()
                    .glue()
                    .witness(&mut region, self.value(self.correction[0]))?;
                let y = chip
                    .uint()
                    .glue()
                    .witness(&mut region, self.value(self.correction[1]))?;
                let correction = chip.constrain_generator(&mut region, &x, &y)?;
                let modes = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &self.mode.map(|v| self.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let mode = ModeCells::constrain(chip.uint().glue(), &mut region, &modes)?;
                let selected = FoldInputCells::select_incoming(
                    &mut chip,
                    &mut region,
                    &p.value,
                    &correction,
                    &mode,
                )?;
                let mut words = vec![p.valid.word().clone(), valid_v.word().clone()];
                append_p(&mut words, &p.value);
                words.extend(v.words());
                append_p(&mut words, &selected);
                let zero = chip.uint().glue().constant(&mut region, Fp::ZERO)?;
                words.resize(96, zero);
                Ok(words)
            },
        )?;
        for (row, word) in words.into_iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}

fn append_p(words: &mut Vec<Word<Fp>>, claim: &FoldInputCells<Ep>) {
    words.extend([
        claim.source_k().clone(),
        claim.g().x().clone(),
        claim.g().y().clone(),
    ]);
    for challenge in claim.challenges() {
        words.extend([challenge.lo().word().clone(), challenge.hi().word().clone()]);
    }
}

impl Claims {
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }

    fn identity() -> Self {
        let params = PinnedParams::<Ep>::derive(16).unwrap();
        let pallas =
            AccumulatorT::<Ep>::new(decode_generator::<Ep>(&[0; 32]).unwrap(), [Fq::from(3); 16])
                .unwrap();
        let vesta =
            AccumulatorT::<Eq>::new(decode_generator::<Eq>(&[0; 32]).unwrap(), [Fp::from(5); 16])
                .unwrap();
        let correction =
            generator_coordinates::<Ep>(&decode_point::<Ep>(&PALLAS_TRIVIAL_GENERATOR).unwrap());
        Self {
            plan: FoldInputDecodePlan::new(&params, 16).unwrap(),
            pallas: pallas.to_bytes().to_vec(),
            vesta: vesta.to_bytes().to_vec(),
            correction: [correction.0, correction.1],
            mode: [Fp::ONE, Fp::ZERO, Fp::ZERO],
            hard: false,
            known: true,
        }
    }

    fn instances(&self) -> Vec<Vec<Fp>> {
        let p = AccumulatorT::<Ep>::from_bytes(&self.pallas);
        let v = AccumulatorT::<Eq>::from_bytes(&self.vesta);
        let mut words = vec![
            Fp::from(u64::from(p.is_ok())),
            Fp::from(u64::from(v.is_ok())),
        ];
        let trivial_p = || {
            AccumulatorT::<Ep>::new(
                decode_point::<Ep>(&PALLAS_TRIVIAL_GENERATOR).unwrap(),
                [Fq::ONE; 16],
            )
            .unwrap()
        };
        let p = p.unwrap_or_else(|_| trivial_p());
        let v = v.unwrap_or_else(|_| {
            AccumulatorT::<Eq>::new(
                decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap(),
                [Fp::ONE; 16],
            )
            .unwrap()
        });
        let append = |out: &mut Vec<Fp>, point: [Fp; 2], challenges: &[Fq; 16]| {
            out.push(Fp::from(16));
            out.extend(point);
            for challenge in challenges {
                out.extend(foreign_limbs(challenge).map(Fp::from_u128));
            }
        };
        let (x, y) = generator_coordinates::<Ep>(p.g());
        append(&mut words, [x, y], p.challenges());
        let (x, y) = generator_coordinates::<Eq>(v.g());
        for coordinate in [x, y] {
            words.extend(foreign_limbs(&coordinate).map(Fp::from_u128));
        }
        words.extend(v.challenges());
        let p = if self.mode[1] == Fp::ONE {
            trivial_p()
        } else {
            p
        };
        let (x, y) = generator_coordinates::<Ep>(p.g());
        let point = if self.mode[2] == Fp::ONE {
            self.correction
        } else {
            [x, y]
        };
        append(&mut words, point, p.challenges());
        words.resize(96, Fp::ZERO);
        vec![words]
    }

    fn satisfied(&self, public: &[Vec<Fp>]) -> bool {
        check_circuit(self, 16, public, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    }
}

#[test]
fn generator_identity_hard_soft_decoders_preserve_pending_obligations() {
    let identity = Claims::identity();
    let public = identity.instances();
    assert_eq!(&public[0][0..2], &[Fp::ONE; 2]);
    assert_eq!(&public[0][3..5], &[Fp::ZERO; 2]);
    assert_eq!(&public[0][37..41], &[Fp::ZERO; 4]);
    for hard in [false, true] {
        let circuit = Claims {
            hard,
            ..identity.clone()
        };
        assert!(circuit.satisfied(&public), "identity hard={hard}");
        let mut forged = public.clone();
        forged[0][0] = Fp::ZERO;
        assert!(
            !circuit.satisfied(&forged),
            "identity decoder bit hard={hard}"
        );
    }
    for foreign in [false, true] {
        let mut malformed = identity.clone();
        let raw = if foreign {
            &mut malformed.vesta
        } else {
            &mut malformed.pallas
        };
        // Zero x with the sign bit set is not the canonical identity encoding.
        raw[31] = 128;
        let expected = malformed.instances();
        let bit = usize::from(foreign);
        assert_eq!(expected[0][bit], Fp::ZERO);
        assert!(
            malformed.satisfied(&expected),
            "total decoder foreign={foreign}"
        );
        let mut forged = expected.clone();
        forged[0][bit] = Fp::ONE;
        assert!(
            !malformed.satisfied(&forged),
            "forged decoder bit foreign={foreign}"
        );
        malformed.hard = true;
        assert!(
            !malformed.satisfied(&expected),
            "hard malformed foreign={foreign}"
        );
    }
    let known = synthesize(&identity, 16, None).unwrap();
    let unknown = synthesize(&identity.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}

#[test]
fn generator_identity_correction_modes_preserve_challenges_and_require_distinctness() {
    let identity = Claims::identity();
    let mut corrected = identity.clone();
    corrected.pallas[..32].copy_from_slice(&PALLAS_TRIVIAL_GENERATOR);
    corrected.correction = [Fp::ZERO; 2];
    corrected.mode = [Fp::ZERO, Fp::ZERO, Fp::ONE];
    let expected = corrected.instances();
    assert_eq!(&expected[0][58..60], &[Fp::ZERO; 2]);
    assert_eq!(&expected[0][60..92], &expected[0][5..37]);
    assert!(corrected.satisfied(&expected));
    let mut changed = expected.clone();
    changed[0][60] += Fp::ONE;
    assert!(
        !corrected.satisfied(&changed),
        "correction cannot replace challenges"
    );
    let duplicate = Claims {
        pallas: identity.pallas.clone(),
        ..corrected.clone()
    };
    assert!(
        !duplicate.satisfied(&duplicate.instances()),
        "identity is not a distinct correction to itself"
    );
    let malformed = Claims {
        correction: [Fp::ZERO, Fp::ONE],
        ..corrected.clone()
    };
    assert!(
        !malformed.satisfied(&malformed.instances()),
        "half-zero coordinates are not a G encoding"
    );
    let trivial = Claims {
        mode: [Fp::ZERO, Fp::ONE, Fp::ZERO],
        ..identity.clone()
    };
    assert!(
        trivial.satisfied(&trivial.instances()),
        "Trivial preserves its deciding filler"
    );
    let invalid_mode = Claims {
        mode: [Fp::ONE, Fp::ZERO, Fp::ONE],
        ..corrected
    };
    assert!(
        !invalid_mode.satisfied(&invalid_mode.instances()),
        "modes remain one-hot"
    );
}
