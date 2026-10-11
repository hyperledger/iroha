//! Receipt tape parity, malformed terms and advice-cell tampering.

use super::*;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value},
};
use iroha_plonk_gadgets::{
    GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip, RunningSumConfig,
    SpongeChip, SpongeConfig,
    bytes::{
        p_bytes_native,
        tape::{BytesChip, BytesConfig},
    },
    tamper::undetected_tampers,
};

#[derive(Clone)]
struct ReceiptCircuit {
    bytes: Vec<u8>,
    known: bool,
}
#[derive(Clone, Debug)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    bytes: BytesConfig,
    hash: SpongeConfig<Fp>,
    instance: Column<Instance>,
}

impl Circuit<Fp> for ReceiptCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let range_column = meta.advice_column();
        let range = RunningSumConfig::configure(meta, range_column, LimbBits::new(8).unwrap());
        let z = meta.advice_column();
        let w = meta.advice_column();
        let bytes = BytesConfig::configure(meta, z, w);
        let columns = Pow5Columns::allocate(meta);
        let constants = RoundConstantColumns::allocate(meta);
        let hash = SpongeConfig::configure(meta, columns, constants, &[]);
        let instance = meta.instance_column(20);
        meta.enable_equality(instance);
        Config {
            glue,
            range,
            bytes,
            hash,
            instance,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        let mut bytes = BytesChip::new(config.bytes);
        let mut hash = SpongeChip::new(config.hash);
        range.load_table(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "ordinary Load receipt",
            |mut region| {
                let input = self
                    .bytes
                    .iter()
                    .map(|b| {
                        if self.known {
                            Value::known(*b)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect::<Vec<_>>();
                let run = bytes.run(
                    &mut region,
                    &input,
                    &LoadReceiptCells::primary_segments(),
                    &LoadReceiptCells::secondary_segments(),
                )?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let receipt = LoadReceiptCells::from_run(&mut uint, &mut hash, &mut region, &run)?;
                let mut outputs = vec![receipt.digest().clone()];
                for id in [
                    receipt.scheme(),
                    receipt.asset(),
                    receipt.wallet(),
                    receipt.request(),
                    receipt.transaction(),
                    receipt.payer(),
                ] {
                    outputs.extend_from_slice(id);
                }
                outputs.extend([
                    receipt.ordinal().word().clone(),
                    receipt.amount().word().clone(),
                    receipt.online_charge().word().clone(),
                    receipt.charge_quote().clone(),
                    receipt.height().word().clone(),
                ]);
                // The remaining two public slots pin explicit derived arithmetic outputs.
                outputs.push(
                    uint.checked_add_constant(&mut region, receipt.ordinal(), 1)?
                        .word()
                        .clone(),
                );
                outputs.push(
                    uint.checked_add(&mut region, receipt.amount(), receipt.online_charge())?
                        .word()
                        .clone(),
                );
                Ok(outputs)
            },
        )?;
        for (row, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, row)?;
        }
        Ok(())
    }
}

fn sample() -> Vec<u8> {
    let mut bytes = vec![0; LoadReceiptCells::BYTES];
    bytes[..2].copy_from_slice(&1_u16.to_le_bytes());
    for (value, offset) in [2, 34, 66, 98, 210, 250].into_iter().enumerate() {
        bytes[offset..offset + 32].fill(u8::try_from(value + 1).unwrap());
    }
    bytes[130..146].copy_from_slice(&9_u128.to_le_bytes());
    bytes[146..162].copy_from_slice(&100_u128.to_le_bytes());
    bytes[242..250].copy_from_slice(&2_u64.to_le_bytes());
    bytes
}

fn integer(bytes: &[u8]) -> Fp {
    bytes.iter().rev().fold(Fp::ZERO, |value, byte| {
        value * Fp::from(256) + Fp::from(u64::from(*byte))
    })
}

fn public(bytes: &[u8]) -> Vec<Vec<Fp>> {
    let mut out = vec![p_bytes_native(LoadReceiptCells::DOMAIN, bytes)];
    for offset in [2, 34, 66, 98, 210, 250] {
        out.push(integer(&bytes[offset..offset + 16]));
        out.push(integer(&bytes[offset + 16..offset + 32]));
    }
    let ordinal = integer(&bytes[130..146]);
    let amount = integer(&bytes[146..162]);
    let charge = integer(&bytes[162..178]);
    out.extend([
        ordinal,
        amount,
        charge,
        integer(&bytes[178..210]),
        integer(&bytes[242..250]),
        ordinal + Fp::ONE,
        amount + charge,
    ]);
    vec![out]
}

fn valid(bytes: &[u8], instances: &[Vec<Fp>]) -> bool {
    check_circuit(
        &ReceiptCircuit {
            bytes: bytes.to_vec(),
            known: true,
        },
        10,
        instances,
        CheckMode::Strict,
    )
    .expect("strict receipt layout")
    .is_satisfied()
}

#[test]
fn receipt_terms_and_digest_are_the_same_exact_transcript() {
    let mut bytes = sample();
    assert!(valid(&bytes, &public(&bytes)));
    bytes[162..178].copy_from_slice(&7_u128.to_le_bytes());
    bytes[178] = 8;
    assert!(valid(&bytes, &public(&bytes)));
    let original = public(&bytes);
    for offset in [2, 34, 66, 98, 130, 146, 162, 178, 210, 242, 250] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(!valid(&changed, &original), "unbound field {offset}");
    }
}

#[test]
fn malformed_terms_reject_even_with_recomputed_digest_and_public_fields() {
    let mut cases = Vec::new();
    for (start, end) in [
        (2, 34),
        (34, 66),
        (66, 98),
        (98, 130),
        (210, 242),
        (146, 162),
    ] {
        let mut bytes = sample();
        bytes[start..end].fill(0);
        cases.push(bytes);
    }
    let mut bytes = sample();
    bytes[0] = 2;
    cases.push(bytes);
    let mut bytes = sample();
    bytes[130..146].fill(255);
    cases.push(bytes);
    let mut bytes = sample();
    bytes[242] = 1;
    cases.push(bytes);
    let mut bytes = sample();
    bytes[162] = 1;
    cases.push(bytes);
    let mut bytes = sample();
    bytes[178] = 1;
    cases.push(bytes);
    let mut bytes = sample();
    bytes[146..162].fill(255);
    bytes[162] = 1;
    bytes[178] = 1;
    cases.push(bytes);
    let mut bytes = sample();
    bytes[162] = 1;
    bytes[178..210].fill(255);
    cases.push(bytes);
    for (i, bytes) in cases.iter().enumerate() {
        assert!(!valid(bytes, &public(bytes)), "malformed {i}");
    }
}

#[test]
fn every_receipt_advice_cell_is_constrained() {
    let bytes = sample();
    let circuit = ReceiptCircuit {
        bytes: bytes.clone(),
        known: true,
    };
    assert!(
        undetected_tampers(&circuit, 10, &public(&bytes))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn native_model_receipt_fixture_matches_the_circuit() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/kagemusha/ordinary_load_receipt_v1.json");
    let text = std::fs::read_to_string(path).expect("native-generated receipt fixture");
    let fixture: norito::json::Value = norito::json::from_str(&text).unwrap();
    let decode = |name: &str| {
        let text = fixture
            .get(name)
            .and_then(norito::json::Value::as_str)
            .unwrap();
        assert_eq!(text.len() % 2, 0);
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let bytes = decode("receipt_transcript_hex");
    assert_eq!(bytes.len(), LoadReceiptCells::BYTES);
    let digest = decode("receipt_digest_hex");
    let instances = public(&bytes);
    assert_eq!(instances[0][0].to_repr().as_ref(), digest.as_slice());
    assert!(valid(&bytes, &instances));
}
