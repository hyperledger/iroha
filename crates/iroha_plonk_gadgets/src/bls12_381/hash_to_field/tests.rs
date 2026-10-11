//! Arkworks differential oracle and linked-byte adversarial checks.

use ark_bls12_381::Fq2;
use ark_ff::{
    PrimeField as ArkPrimeField,
    fields::field_hashers::{DefaultFieldHasher, HashToField},
};
use ff::Field;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use sha2::{Digest, Sha256};

use super::*;
use crate::{
    GlueConfig,
    range::{LimbBits, RunningSumChip, RunningSumConfig},
    sha256::Sha256Config,
    tamper::{Tamper, assigned_advice_cells, check_tampered, undetected_tampers},
};

fn xmd(message: &[u8]) -> [u8; 256] {
    let mut frame = vec![0; 64];
    frame.extend_from_slice(W3F_SIGNING_PREFIX);
    frame.extend_from_slice(message);
    frame.extend_from_slice(&[1, 0, 0, 1, 1]);
    let b0 = Sha256::digest(&frame);
    let mut uniform = [0; 256];
    let mut previous = b0.to_vec();
    for counter in 1..=8_u8 {
        let mut frame = if counter == 1 {
            b0.to_vec()
        } else {
            b0.iter().zip(&previous).map(|(a, b)| a ^ b).collect()
        };
        frame.extend_from_slice(&[counter, 1, 1]);
        previous = Sha256::digest(&frame).to_vec();
        uniform[(usize::from(counter) - 1) * 32..usize::from(counter) * 32]
            .copy_from_slice(&previous);
    }
    uniform
}

fn public<F: PastaField>(message: &[u8]) -> Vec<F> {
    let mut frame = W3F_SIGNING_PREFIX.to_vec();
    frame.extend_from_slice(message);
    let oracle = <DefaultFieldHasher<Sha256> as HashToField<Fq2>>::new(&[1]);
    let expected: Vec<Fq2> = oracle.hash_to_field(&frame, 2);
    let mut public: Vec<_> = message
        .iter()
        .copied()
        .chain(xmd(message))
        .map(|byte| F::from(u64::from(byte)))
        .collect();
    for element in expected {
        for coefficient in [element.c0, element.c1] {
            public.extend(coefficient.into_bigint().0.map(F::from));
        }
    }
    public
}

#[derive(Clone)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    sha: Sha256Config,
    public: Column<Instance>,
}

#[derive(Clone)]
struct HashCircuit<F: PastaField> {
    message: Vec<F>,
    known: bool,
}

impl<F: PastaField> Circuit<F> for HashCircuit<F> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = usize;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn params(&self) -> usize {
        self.message.len()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        Self::configure_with_params(meta, 0)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, len: usize) -> Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let column = meta.advice_column();
        let range =
            RunningSumConfig::configure(meta, column, LimbBits::new(8).expect("byte limbs"));
        let advice = core::array::from_fn(|_| meta.advice_column());
        let sha = Sha256Config::configure(meta, advice, constants);
        let public = meta.instance_column(len + 280);
        meta.enable_equality(public);
        Config {
            glue,
            range,
            sha,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        let mut sha = Sha256Chip::new(&config.sha);
        range.load_table(&mut layouter)?;
        sha.load_table(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "W3f hash-to-field",
            |mut region| {
                let values: Vec<_> = self
                    .message
                    .iter()
                    .map(|value| {
                        if self.known {
                            Value::known(*value)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect();
                let mut outputs = glue.witnesses(&mut region, &values)?;
                let mut field = Bls381Chip::new(&mut glue, &mut range);
                let uniform = expand_message(&mut field, &mut sha, &mut region, &outputs)?;
                let elements = reduce_uniform(&mut field, &mut region, &uniform)?;
                outputs.extend(uniform);
                for element in elements {
                    for coefficient in element.coefficients() {
                        outputs.extend_from_slice(coefficient.limbs());
                    }
                }
                Ok(outputs)
            },
        )?;
        for (i, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

fn circuit<F: PastaField>(message: &[u8]) -> HashCircuit<F> {
    HashCircuit {
        message: message
            .iter()
            .map(|byte| F::from(u64::from(*byte)))
            .collect(),
        known: true,
    }
}

#[test]
fn independent_xmd_reference_matches_pinned_python_hashlib_receipt() {
    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut output = String::new();
        for byte in bytes {
            write!(output, "{byte:02x}").expect("write to a string");
        }
        output
    }
    let expanded = xmd(b"abc");
    assert_eq!(
        hex(&expanded[..32]),
        "5b95366258b14b0a1aae5404841ccfc37f526cf719d577d6510375bf501700e6"
    );
    assert_eq!(
        hex(&expanded[224..]),
        "7a95d2e4854626478671f56bf97b130cbe662f2c1ee9b769d22d56a8547c4b0a"
    );
    assert_eq!(
        hex(&Sha256::digest(expanded)),
        "8746d4a583118fc89bf3a6e7f8737edbf1c44a87325312e3d40f52367086c4eb"
    );
}

#[test]
fn exact_w3f_xmd_and_field_reductions_match_arkworks_at_sha_boundaries() {
    // b0's unpadded transcript is 132+len bytes; len=43/44 and 107/108
    // straddle the SHA trailer boundary in successive blocks.
    for len in [0, 3, 43, 44, 107, 108] {
        let message: Vec<_> = (0..len)
            .map(|i| u8::try_from(i).expect("fixture byte"))
            .collect();
        assert!(
            check_circuit(
                &circuit::<Fp>(&message),
                15,
                &[public::<Fp>(&message)],
                CheckMode::Strict
            )
            .expect("XMD layout")
            .is_satisfied(),
            "length {len}"
        );
    }
    assert!(
        check_circuit(
            &circuit::<Fq>(b"abc"),
            15,
            &[public::<Fq>(b"abc")],
            CheckMode::Strict
        )
        .expect("Fq XMD")
        .is_satisfied()
    );
}

#[test]
fn expanded_bytes_field_coefficients_and_message_are_publicly_bound() {
    let circuit = circuit::<Fp>(b"abc");
    let public = public::<Fp>(b"abc");
    for index in [0, 3, 34, 227, 258, 259, 270, 282] {
        let mut wrong = public.clone();
        wrong[index] += Fp::ONE;
        assert!(
            !check_circuit(&circuit, 15, &[wrong], CheckMode::Strict)
                .expect("bound transcript")
                .is_satisfied()
        );
    }
    let mut forged = circuit.clone();
    let mut wrong = public.clone();
    forged.message[0] += Fp::from(256);
    wrong[0] += Fp::from(256);
    assert!(
        !check_circuit(&forged, 15, &[wrong], CheckMode::Strict)
            .expect("not a byte")
            .is_satisfied()
    );
}

#[test]
fn xmd_unknown_witnesses_have_identical_shape_and_assigned_cells_reject_tampering() {
    let circuit = circuit::<Fp>(b"abc");
    let public = public::<Fp>(b"abc");
    let known = synthesize(&circuit, 15, Some(core::slice::from_ref(&public))).expect("known");
    let unknown = synthesize(&circuit.without_witnesses(), 15, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    let cells = assigned_advice_cells(&circuit, 15, core::slice::from_ref(&public)).expect("cells");
    // Unit-level sweeps cover every XOR/codec cell below and every SHA/base
    // arithmetic cell in their own suites. Sample all composed lane ends here.
    for column in 0..known.tables.advice_assigned().len() {
        let assigned: Vec<_> = cells.iter().filter(|(c, _)| *c == column).collect();
        for cell in [assigned.first(), assigned.last()].into_iter().flatten() {
            let tamper = Tamper {
                column,
                row: cell.1,
                delta: Fp::ONE,
            };
            assert!(
                !check_tampered(&circuit, 15, core::slice::from_ref(&public), Some(tamper))
                    .expect("composed tamper")
                    .is_satisfied()
            );
        }
    }
}

#[derive(Clone)]
struct XorCircuit<F: PastaField> {
    a: F,
    b: F,
}

#[derive(Clone)]
struct XorConfig {
    glue: GlueConfig,
    range: RunningSumConfig,
    public: Column<Instance>,
}

impl<F: PastaField> Circuit<F> for XorCircuit<F> {
    type Config = XorConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> XorConfig {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let advice = meta.advice_column();
        let range =
            RunningSumConfig::configure(meta, advice, LimbBits::new(4).expect("small table"));
        let public = meta.instance_column(3);
        meta.enable_equality(public);
        XorConfig {
            glue,
            range,
            public,
        }
    }
    fn synthesize(&self, config: XorConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        range.load_table(&mut layouter)?;
        let result = layouter.assign_region(
            || "linked XMD XOR",
            |mut region| {
                let a = glue.witness(&mut region, Value::known(self.a))?;
                let b = glue.witness(&mut region, Value::known(self.b))?;
                let mut field = Bls381Chip::new(&mut glue, &mut range);
                let aa = byte_bits(&mut field, &mut region, &a)?;
                let bb = byte_bits(&mut field, &mut region, &b)?;
                let out = xor_byte(&mut field, &mut region, &aa, &bb)?;
                Ok([a, b, out])
            },
        )?;
        for (i, word) in result.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

#[test]
fn every_xmd_byte_xor_cell_is_pinned_on_both_fields() {
    fn exercise<F: PastaField>() {
        let circuit = XorCircuit {
            a: F::from(0xa5),
            b: F::from(0x3c),
        };
        assert!(
            undetected_tampers(
                &circuit,
                7,
                &[vec![circuit.a, circuit.b, F::from(0xa5 ^ 0x3c)]]
            )
            .expect("XOR sweep")
            .is_empty()
        );
        let circuit = XorCircuit {
            a: F::from(256),
            b: F::ZERO,
        };
        assert!(
            !check_circuit(
                &circuit,
                7,
                &[vec![circuit.a, circuit.b, F::ZERO]],
                CheckMode::Strict
            )
            .expect("forged byte")
            .is_satisfied()
        );
    }
    exercise::<Fp>();
    exercise::<Fq>();
}
