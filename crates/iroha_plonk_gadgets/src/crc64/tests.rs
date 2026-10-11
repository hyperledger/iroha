//! Native Norito parity, conditional scan boundaries and hostile state/byte cells.

use super::*;
use crate::{GlueConfig, LimbBits, RunningSumChip, RunningSumConfig};
use ff::Field;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};

#[derive(Clone)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    public: Column<Instance>,
}
#[derive(Clone)]
struct Crc<F: PastaField> {
    bytes: Vec<F>,
    active: Vec<bool>,
    state: F,
    known: bool,
}
impl<F: PastaField> Circuit<F> for Crc<F> {
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
        self.bytes.len()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        Self::configure_with_params(meta, 0)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, bytes: usize) -> Config {
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constants);
        let column = meta.advice_column();
        let range = RunningSumConfig::configure(meta, column, LimbBits::new(8).unwrap());
        let public = meta.instance_column(2 * bytes + 3);
        meta.enable_equality(public);
        Config {
            glue,
            range,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        range.load_table(&mut layouter)?;
        let value = |v| {
            if self.known {
                Value::known(v)
            } else {
                Value::unknown()
            }
        };
        let output = layouter.assign_region(
            || "CRC64-XZ linked scan",
            |mut region| {
                let bytes = glue.witnesses(
                    &mut region,
                    &self.bytes.iter().copied().map(value).collect::<Vec<_>>(),
                )?;
                let mut active = Vec::new();
                for bit in &self.active {
                    active.push(glue.boolean(
                        &mut region,
                        if self.known {
                            Value::known(*bit)
                        } else {
                            Value::unknown()
                        },
                    )?);
                }
                let imported = glue.witness(&mut region, value(self.state))?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let mut state = Crc64State::from_word(&mut uint, &mut region, &imported)?;
                let initial =
                    Crc64State::initial(&mut uint, &mut region)?.word(&mut uint, &mut region)?;
                GlueChip::assert_equal(&mut region, &imported, initial.word())?;
                for (byte, active) in bytes.iter().zip(&active) {
                    state = state.update(&mut uint, &mut region, byte, active)?;
                }
                let raw = state.word(&mut uint, &mut region)?;
                // Round-trip the exact checkpoint word before finalization.
                let restored = Crc64State::from_word(&mut uint, &mut region, raw.word())?;
                let checksum = restored.checksum(&mut uint, &mut region)?;
                let mut out = bytes;
                out.extend(active.iter().map(|b| b.word().clone()));
                out.extend([imported, raw.word().clone(), checksum.word().clone()]);
                Ok(out)
            },
        )?;
        for (index, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, index)?;
        }
        Ok(())
    }
}
fn public<F: PastaField>(circuit: &Crc<F>, checksum: u64) -> Vec<Vec<F>> {
    let mut words = circuit.bytes.clone();
    words.extend(circuit.active.iter().map(|b| F::from(u64::from(*b))));
    words.extend([circuit.state, F::from(!checksum), F::from(checksum)]);
    vec![words]
}
fn parity<F: PastaField>() {
    for bytes in [
        vec![],
        b"123456789".to_vec(),
        (0..32).collect(),
        vec![255; 32],
    ] {
        let crc = norito::crc64_fallback(&bytes);
        if bytes == b"123456789" {
            assert_eq!(crc, 0x995d_c9bb_df19_39fa);
        }
        let circuit = Crc {
            bytes: bytes.iter().map(|b| F::from(u64::from(*b))).collect(),
            active: vec![true; bytes.len()],
            state: F::from(u64::MAX),
            known: true,
        };
        assert!(
            check_circuit(&circuit, 16, &public(&circuit, crc), CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
}
#[test]
fn norito_crc64_xz_vectors_match_both_cycle_fields() {
    parity::<Fp>();
    parity::<Fq>();
}

#[test]
fn byte_enables_state_and_checksum_are_all_bound() {
    let mut circuit = Crc {
        bytes: vec![Fp::from(7), Fp::from(19), Fp::from(31)],
        active: vec![true, false, true],
        state: Fp::from(u64::MAX),
        known: true,
    };
    let checksum = norito::crc64_fallback(&[7, 31]);
    let expected = public(&circuit, checksum);
    assert!(
        check_circuit(&circuit, 14, &expected, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    for index in [0, 3, 6, 7, 8] {
        let mut wrong = expected.clone();
        wrong[0][index] += Fp::ONE;
        assert!(
            !check_circuit(&circuit, 14, &wrong, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
    circuit.bytes[1] = Fp::from(256);
    assert!(
        !check_circuit(&circuit, 14, &public(&circuit, checksum), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    circuit.bytes[1] = Fp::from(19);
    circuit.state = Fp::from(u64::MAX) + Fp::ONE;
    assert!(
        !check_circuit(&circuit, 14, &public(&circuit, checksum), CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}

#[test]
fn crc_scan_shape_is_independent_of_bytes_enables_and_checkpoint() {
    let circuit = Crc {
        bytes: vec![Fp::from(91); 32],
        active: vec![true; 32],
        state: Fp::from(u64::MAX),
        known: true,
    };
    let known = synthesize(&circuit, 16, None).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    let other = synthesize(
        &Crc {
            bytes: vec![Fp::ZERO; 32],
            active: vec![false; 32],
            ..circuit
        },
        16,
        None,
    )
    .unwrap();
    for other in [&unknown, &other] {
        assert_eq!(known.tables.fixed(), other.tables.fixed());
        assert_eq!(
            known.tables.advice_assigned(),
            other.tables.advice_assigned()
        );
    }
}
