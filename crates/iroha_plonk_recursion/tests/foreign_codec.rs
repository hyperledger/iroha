//! Total Vesta transport decoding in Fp, including false-rejection adversaries.

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, PastaField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
    transcript::{decode_point, encode_point},
};
use iroha_plonk_gadgets::{
    bytes::{
        element::{decode_le_element, le_message_segments},
        tape::{BytesChip, BytesConfig, SegmentSpec},
    },
    statement::{bytes_to_limbs, foreign_limbs},
    tamper::{Tamper, assigned_advice_cells, check_tampered},
};
use iroha_plonk_recursion::{
    AccumulatorT, K, VESTA_TRIVIAL_GENERATOR,
    verifier::{VerifierChip, VerifierConfig},
};

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
#[derive(Clone)]
struct Decode {
    bytes: Vec<u8>,
    length: u32,
    accumulator: bool,
    known: bool,
}
impl Decode {
    fn value<T: Copy>(&self, v: T) -> Value<T> {
        if self.known {
            Value::known(v)
        } else {
            Value::unknown()
        }
    }
    fn native(&self) -> (bool, [Fq; 2], [Fp; 16]) {
        if self.accumulator {
            let decoded = if self.length == 544 {
                AccumulatorT::<Eq>::from_bytes(&self.bytes).ok()
            } else {
                None
            };
            let valid = decoded.is_some();
            let (x, y) = decoded.as_ref().map_or_else(
                || {
                    decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR)
                        .unwrap()
                        .coordinates()
                        .unwrap()
                },
                |v| v.g().coordinates().unwrap(),
            );
            (
                valid,
                [x, y],
                decoded.map_or([Fp::ONE; K], |v| *v.challenges()),
            )
        } else {
            let point = decode_point::<Eq>(&self.bytes[..32].try_into().unwrap()).ok();
            let valid = point.is_some();
            let (x, y) =
                point.map_or_else(|| (-Fq::ONE, Fq::from(2)), |p| p.coordinates().unwrap());
            (valid, [x, y], [Fp::ZERO; K])
        }
    }
    fn instances(&self) -> Vec<Fp> {
        let mut out = vec![Fp::from(u64::from(self.length))];
        for chunk in self.bytes.chunks_exact(32) {
            out.extend(bytes_to_limbs(&chunk.try_into().unwrap()).map(Fp::from_u128));
        }
        let (valid, xy, u) = self.native();
        out.push(Fp::from(u64::from(valid)));
        for coordinate in xy {
            out.extend(foreign_limbs(&coordinate).map(Fp::from_u128));
        }
        if self.accumulator {
            out.extend(u);
        }
        out
    }
}
impl Circuit<Fp> for Decode {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = bool;
    fn params(&self) -> bool {
        self.accumulator
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Self::configure_with_params(meta, false)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, accumulator: bool) -> Config {
        let verifier = VerifierConfig::configure(meta);
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(if accumulator { 56 } else { 8 });
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
            || "foreign total decode",
            |mut region| {
                let count = self.bytes.len() / 32;
                let raw = self
                    .length
                    .to_le_bytes()
                    .into_iter()
                    .chain(self.bytes.iter().copied())
                    .map(|v| self.value(v))
                    .collect::<Vec<_>>();
                let primary = core::iter::once(4)
                    .chain(core::iter::repeat_n(16, 2 * count))
                    .collect::<Vec<_>>();
                let secondary = core::iter::once(SegmentSpec::little(0, 4))
                    .chain(le_message_segments(4, count))
                    .collect::<Vec<_>>();
                let run = bytes.run(&mut region, &raw, &primary, &secondary)?;
                let mut out = run
                    .primary()
                    .iter()
                    .map(|s| s.word().cell())
                    .collect::<Vec<_>>();
                let mut messages = Vec::new();
                for i in 0..count {
                    messages.push(decode_le_element(
                        &mut chip.uint(),
                        &mut region,
                        &run,
                        4 + i * 32,
                    )?);
                }
                if self.accumulator {
                    let length = chip
                        .uint()
                        .range_check::<32>(&mut region, run.primary()[0].word())?;
                    let decoded = chip.decode_vesta_accumulator(&mut region, &messages, &length)?;
                    out.push(decoded.valid.cell());
                    for coordinate in decoded.coordinates {
                        out.extend([coordinate.lo().cell(), coordinate.hi().cell()]);
                    }
                    out.extend(
                        decoded
                            .challenges
                            .iter()
                            .map(iroha_plonk_gadgets::Word::cell),
                    );
                } else {
                    let decoded = chip.decode_vesta_point_soft(&mut region, &messages[0])?;
                    out.push(decoded.valid.cell());
                    for coordinate in decoded.coordinates {
                        out.extend([coordinate.lo().cell(), coordinate.hi().cell()]);
                    }
                }
                Ok(out)
            },
        )?;
        for (row, cell) in out.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.public, row)?;
        }
        Ok(())
    }
}
fn check(circuit: &Decode) {
    let values = [circuit.instances()];
    assert!(
        check_circuit(circuit, 16, &values, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let mut forged = values;
    let index = 1 + 2 * (circuit.bytes.len() / 32);
    forged[0][index] = Fp::ONE - forged[0][index];
    assert!(
        !check_circuit(circuit, 16, &forged, CheckMode::Strict)
            .unwrap()
            .is_satisfied(),
        "valid point cannot manufacture false rejection"
    );
}
fn modulus<F: PrimeField<Repr = [u8; 32]>>() -> [u8; 32] {
    let mut b = (-F::ONE).to_repr();
    for byte in &mut b {
        let (v, carry) = byte.overflowing_add(1);
        *byte = v;
        if !carry {
            break;
        }
    }
    b
}

#[test]
#[ignore = "k16 foreign decoder matrix; run optimized with --include-ignored"]
fn vesta_points_decode_totally_in_fp_without_optional_rejection() {
    assert!(!bool::from(Fq::from(5).sqrt().is_some()));
    let mut vectors = vec![
        VESTA_TRIVIAL_GENERATOR,
        [0; 32],
        [255; 32],
        modulus::<Fq>(),
        modulus::<Fp>(),
    ];
    for n in 1_u64..8 {
        let mut b = [0; 32];
        b[..8].copy_from_slice(&n.to_le_bytes());
        vectors.push(b);
        b[31] |= 128;
        vectors.push(b);
    }
    let mut signed_zero = [0; 32];
    signed_zero[31] = 128;
    vectors.push(signed_zero);
    for bytes in vectors {
        check(&Decode {
            bytes: bytes.to_vec(),
            length: 32,
            accumulator: false,
            known: true,
        });
    }
    let circuit = Decode {
        bytes: VESTA_TRIVIAL_GENERATOR.to_vec(),
        length: 32,
        accumulator: false,
        known: true,
    };
    let values = [circuit.instances()];
    let known = synthesize(&circuit, 16, Some(&values)).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    let cells = assigned_advice_cells(&circuit, 16, &values).unwrap();
    let rows = cells.iter().map(|(_, r)| r + 1).max().unwrap();
    println!("foreign Vesta point rows={rows} cells={}", cells.len());
    assert!(
        rows <= 287 && cells.len() <= 1391,
        "decoder inventory regression"
    );
    for column in 0..known.tables.advice_assigned().len() {
        for (_, row) in cells
            .iter()
            .filter(|(c, _)| *c == column)
            .take(1)
            .chain(cells.iter().rev().filter(|(c, _)| *c == column).take(1))
        {
            assert!(
                !check_tampered(
                    &circuit,
                    16,
                    &values,
                    Some(Tamper {
                        column,
                        row: *row,
                        delta: Fp::ONE
                    })
                )
                .unwrap()
                .is_satisfied()
            );
        }
    }
    // VerifierConfig allocates the glue boolean selector first, on advice0.
    // Tamper every boolean there, including square/nonsquare and both signs.
    let mut targets = std::collections::BTreeSet::new();
    for (row, enabled) in known.tables.selectors()[0].iter().enumerate() {
        if *enabled {
            targets.insert((0, row));
        }
    }
    let (x, _) = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR)
        .unwrap()
        .coordinates()
        .unwrap();
    let root = (x.square() * x + Fq::from(5)).sqrt().unwrap();
    let integer = iroha_plonk_gadgets::ff::Nat::from_words(root.to_canonical_limbs());
    let mut root_limbs = foreign_limbs(&root).to_vec();
    for shift in [0, 87, 174] {
        root_limbs.push(integer.shr(shift).low_u128() & ((1_u128 << 87) - 1));
    }
    let root_values = root_limbs
        .into_iter()
        .map(Fp::from_u128)
        .collect::<Vec<_>>();
    for (column, row) in &cells {
        if root_values.contains(&known.tables.advice().unwrap()[*column][*row]) {
            targets.insert((*column, *row));
        }
    }
    assert!(targets.len() >= 8, "square, root and sign targets present");
    for (column, row) in targets {
        assert!(
            !check_tampered(
                &circuit,
                16,
                &values,
                Some(Tamper {
                    column,
                    row,
                    delta: Fp::ONE
                })
            )
            .unwrap()
            .is_satisfied(),
            "root/square/sign {column}:{row}"
        );
    }
}

#[test]
#[ignore = "k16 foreign decoder matrix; run optimized with --include-ignored"]
fn vesta_accumulators_decode_totally_with_exact_bytes_and_length() {
    let point = decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap();
    let mut bytes = encode_point::<Eq>(&point).to_vec();
    for _ in 0..K {
        bytes.extend(Fp::from(7).to_repr());
    }
    let original = Decode {
        bytes,
        length: 544,
        accumulator: true,
        known: true,
    };
    check(&original);
    for index in [0, 1, 8, 16] {
        for fill in [[0; 32], [255; 32], modulus::<Fp>()] {
            let mut bad = original.clone();
            bad.bytes[index * 32..(index + 1) * 32].copy_from_slice(&fill);
            check(&bad);
        }
    }
    for length in [0, 543, 545, u32::MAX] {
        let mut bad = original.clone();
        bad.length = length;
        check(&bad);
    }
}
