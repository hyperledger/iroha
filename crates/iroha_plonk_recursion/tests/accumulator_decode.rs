//! Total incoming accumulator decoding, source normalization and deciding dummies.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{Ep, Eq, PastaAffine, PastaCurve, PastaField, msm::MemoryBudget};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
    pcs::ipa::PinnedParams,
    transcript::{decode_point, decode_scalar, encode_point},
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
    ACCUMULATOR_BYTES, FoldInput, K,
    accumulation_circuit::{FoldInputCells, FoldInputDecodePlan},
    verifier::{VerifierChip, VerifierConfig},
};

#[derive(Clone, Debug)]
struct Config<C: PastaCurve> {
    verifier: VerifierConfig<C>,
    bytes: BytesConfig,
    instance: Column<Instance>,
}

#[derive(Clone)]
struct Decode<C: PastaCurve> {
    plan: FoldInputDecodePlan<C>,
    bytes: [u8; ACCUMULATOR_BYTES],
    length: u32,
    known: bool,
}

impl<C: PastaCurve> Decode<C> {
    fn witness<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn instances(&self, valid: bool, input: &FoldInput<C>) -> Vec<C::Base> {
        let mut out = self
            .bytes
            .chunks_exact(32)
            .flat_map(|bytes| bytes_to_limbs(&bytes.try_into().unwrap()).map(C::Base::from_u128))
            .collect::<Vec<_>>();
        out.extend([
            C::Base::from(u64::from(self.length)),
            C::Base::from(u64::from(valid)),
        ]);
        let (x, y) = Option::from(input.g().coordinates()).unwrap();
        out.extend([x, y]);
        for value in input.challenges() {
            out.extend(foreign_limbs(value).map(C::Base::from_u128));
        }
        out
    }
}

impl<C: PastaCurve> Circuit<C::Base> for Decode<C> {
    type Config = Config<C>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Config<C> {
        let verifier = VerifierConfig::configure(meta);
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let instance = meta.instance_column(70);
        meta.enable_equality(instance);
        Config {
            verifier,
            bytes,
            instance,
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
        let out = layouter.assign_region(
            || "total incoming accumulator",
            |mut region| {
                let input = self.bytes.map(|byte| self.witness(byte));
                let run = bytes.run(&mut region, &input, &[16; 34], &le_message_segments(0, 17))?;
                let mut out = run
                    .primary()
                    .iter()
                    .map(|segment| segment.word().cell())
                    .collect::<Vec<_>>();
                let mut messages = Vec::new();
                for i in 0..17 {
                    messages.push(decode_le_element(
                        &mut chip.uint(),
                        &mut region,
                        &run,
                        i * 32,
                    )?);
                }
                let length = chip
                    .uint()
                    .assign::<32>(&mut region, self.witness(u128::from(self.length)))?;
                let decoded = FoldInputCells::decode_soft(
                    &mut chip,
                    &mut region,
                    &self.plan,
                    &messages,
                    &length,
                )?;
                out.extend([
                    length.cell(),
                    decoded.valid.cell(),
                    decoded.value.g().x().cell(),
                    decoded.value.g().y().cell(),
                ]);
                for value in decoded.value.challenges() {
                    out.extend([value.lo().cell(), value.hi().cell()]);
                }
                Ok(out)
            },
        )?;
        for (row, cell) in out.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instance, row)?;
        }
        Ok(())
    }
}

fn encode<C: PastaCurve>(input: &FoldInput<C>) -> [u8; ACCUMULATOR_BYTES] {
    let mut out = [0; ACCUMULATOR_BYTES];
    out[..32].copy_from_slice(&encode_point::<C>(input.g()));
    for (chunk, value) in out[32..].chunks_exact_mut(32).zip(input.challenges()) {
        chunk.copy_from_slice(&value.to_repr());
    }
    out
}

fn native<C: PastaCurve>(bytes: &[u8; ACCUMULATOR_BYTES], k: u32) -> Option<FoldInput<C>> {
    let g = decode_point::<C>(&bytes[..32].try_into().ok()?).ok()?;
    let mut challenges = [C::ScalarExt::ZERO; K];
    for (chunk, value) in bytes[32..].chunks_exact(32).zip(&mut challenges) {
        *value = decode_scalar(&chunk.try_into().ok()?).ok()?;
    }
    FoldInput::from_normalized(g, k, challenges).ok()
}

fn modulus<F: PastaField>() -> [u8; 32] {
    let mut out = (-F::ONE).to_repr();
    for byte in &mut out {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
    out
}

fn run<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(16).unwrap();
    assert!(FoldInputDecodePlan::new(&params, 0).is_err());
    assert!(FoldInputDecodePlan::new(&params, 17).is_err());
    for k in [12, 14, 16] {
        let dummy_g = params.params().g()[..1 << k]
            .iter()
            .fold(C::identity(), |sum, g| sum + g.to_curve())
            .to_affine();
        let dummy = FoldInput::from_opening(dummy_g, &vec![C::ScalarExt::ONE; k as usize]).unwrap();
        dummy.decide(&params, MemoryBudget::DEFAULT).unwrap();
        let honest = FoldInput::from_opening(
            C::generator().to_affine(),
            &vec![C::ScalarExt::from(3); k as usize],
        )
        .unwrap();
        let original = Decode {
            plan: FoldInputDecodePlan::new(&params, k).unwrap(),
            bytes: encode(&honest),
            length: 544,
            known: true,
        };
        assert_eq!(original.plan.source_k(), k);
        let mut cases = vec![original.clone()];
        for index in [0, 1, 2, 15, 16] {
            let mut invalid = original.clone();
            invalid.bytes[index * 32..(index + 1) * 32].fill(0);
            cases.push(invalid);
            let mut invalid = original.clone();
            let modulus = if index == 0 {
                modulus::<C::Base>()
            } else {
                modulus::<C::ScalarExt>()
            };
            invalid.bytes[index * 32..(index + 1) * 32].copy_from_slice(&modulus);
            cases.push(invalid);
        }
        if k < 16 {
            let mut bad = original.clone();
            bad.bytes[32..64].copy_from_slice(&C::ScalarExt::ONE.to_repr());
            cases.push(bad);
        }
        for length in [0, 543, 545, u32::MAX] {
            let mut bad = original.clone();
            bad.length = length;
            cases.push(bad);
        }
        for circuit in cases {
            let decoded = if circuit.length == 544 {
                native::<C>(&circuit.bytes, k)
            } else {
                None
            };
            let valid = decoded.is_some();
            let expected = decoded.as_ref().unwrap_or(&dummy);
            let instances = [circuit.instances(valid, expected)];
            assert!(
                check_circuit(&circuit, 16, &instances, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "total decoder k{k}"
            );
            let mut forged = instances.clone();
            forged[0][35] = C::Base::ONE - forged[0][35];
            assert!(
                !check_circuit(&circuit, 16, &forged, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "verdict is not optional"
            );
        }
        if k == 16 {
            let instances = [original.instances(true, &honest)];
            let known = synthesize(&original, 16, Some(&instances)).unwrap();
            let unknown = synthesize(&original.without_witnesses(), 16, None).unwrap();
            assert_eq!(
                known.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
            assert_eq!(known.tables.fixed(), unknown.tables.fixed());
            let cells = assigned_advice_cells(&original, 16, &instances).unwrap();
            let expected_cells = if C::CURVE_ID == "pallas" { 3849 } else { 3945 };
            assert_eq!(
                (cells.iter().map(|(_, r)| r + 1).max().unwrap(), cells.len()),
                (1378, expected_cells)
            );
            for column in 0..known.tables.advice_assigned().len() {
                if let Some((_, row)) = cells.iter().rev().find(|(c, _)| *c == column) {
                    assert!(
                        !check_tampered(
                            &original,
                            16,
                            &instances,
                            Some(Tamper {
                                column,
                                row: *row,
                                delta: C::Base::ONE
                            })
                        )
                        .unwrap()
                        .is_satisfied()
                    );
                }
            }
        }
    }
}

#[test]
#[ignore = "k16 malformed accumulator matrix; run optimized with --include-ignored"]
fn malformed_incoming_accumulators_soft_fail_and_select_deciding_dummies() {
    run::<Ep>();
    run::<Eq>();
}
