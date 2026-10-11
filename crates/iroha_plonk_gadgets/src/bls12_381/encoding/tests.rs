//! Exact ark/W3f compressed bytes, flags, sign order and nonidentity rejection.

use super::*;
use crate::{
    GlueConfig, LimbBits, RunningSumChip, RunningSumConfig,
    bls12_381::curve::{G1AffineWitness, G2AffineWitness},
    tamper::{Tamper, assigned_advice_cells, check_tampered},
};
use ark_bls12_381::{G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use core::marker::PhantomData;
use ff::Field;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value},
};

#[derive(Clone)]
struct EncodingCircuit<F> {
    one: G1Affine,
    two: G2Affine,
    g2: bool,
    known: bool,
    field: PhantomData<F>,
}
impl<F: PastaField> EncodingCircuit<F> {
    fn fixture(g2: bool, multiple: u64) -> Self {
        Self {
            one: G1Affine::generator().mul_bigint([multiple]).into_affine(),
            two: G2Affine::generator().mul_bigint([multiple]).into_affine(),
            g2,
            known: true,
            field: PhantomData,
        }
    }
    fn public(&self) -> Vec<Vec<F>> {
        let mut bytes = Vec::new();
        if self.g2 {
            self.two.serialize_compressed(&mut bytes).unwrap();
        } else {
            self.one.serialize_compressed(&mut bytes).unwrap();
            bytes.resize(96, 0);
        }
        vec![bytes.into_iter().map(|b| F::from(u64::from(b))).collect()]
    }
    fn witness<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
}
impl<F: PastaField> Circuit<F> for EncodingCircuit<F> {
    type Config = (GlueConfig, RunningSumConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constants);
        let column = meta.advice_column();
        let range = RunningSumConfig::configure(meta, column, LimbBits::new(8).unwrap());
        let instance = meta.instance_column(96);
        meta.enable_equality(instance);
        (glue, range, instance)
    }
    fn synthesize(
        &self,
        (glue, range, instance): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(glue);
        let mut range = RunningSumChip::new(range);
        range.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "native BLS compressed point",
            |mut region| {
                let mut chip = Bls381Chip::new(&mut glue, &mut range);
                if self.g2 {
                    let witness = G2AffineWitness {
                        x: if self.two.infinity {
                            [native::ZERO; 2]
                        } else {
                            [self.two.x.c0.into_bigint().0, self.two.x.c1.into_bigint().0]
                        },
                        y: if self.two.infinity {
                            [native::ZERO; 2]
                        } else {
                            [self.two.y.c0.into_bigint().0, self.two.y.c1.into_bigint().0]
                        },
                        infinity: self.two.infinity,
                    };
                    let point = chip.assign_g2(&mut region, self.witness(witness))?;
                    Ok(chip.compressed_g2(&mut region, &point)?.to_vec())
                } else {
                    let witness = G1AffineWitness {
                        x: if self.one.infinity {
                            native::ZERO
                        } else {
                            self.one.x.into_bigint().0
                        },
                        y: if self.one.infinity {
                            native::ZERO
                        } else {
                            self.one.y.into_bigint().0
                        },
                        infinity: self.one.infinity,
                    };
                    let point = chip.assign_g1(&mut region, self.witness(witness))?;
                    let mut bytes = chip.compressed_g1(&mut region, &point)?.to_vec();
                    let zero = chip.glue().constant(&mut region, F::ZERO)?;
                    bytes.resize(96, zero);
                    Ok(bytes)
                }
            },
        )?;
        for (i, byte) in output.iter().enumerate() {
            layouter.constrain_instance(byte.cell(), instance, i)?;
        }
        Ok(())
    }
}
fn satisfies<F: PastaField>(circuit: &EncodingCircuit<F>, public: &[Vec<F>]) -> bool {
    check_circuit(circuit, 14, public, CheckMode::Strict)
        .unwrap()
        .is_satisfied()
}
fn parity<F: PastaField>() {
    for g2 in [false, true] {
        for multiple in [1, 2, 7] {
            let mut circuit = EncodingCircuit::<F>::fixture(g2, multiple);
            assert!(satisfies(&circuit, &circuit.public()));
            circuit.one = -circuit.one;
            circuit.two = -circuit.two;
            assert!(satisfies(&circuit, &circuit.public()));
            for mask in [32, 64, 128] {
                let mut forged = circuit.public();
                let b = crate::cells::low_u128(&forged[0][0]).to_le_bytes()[0];
                forged[0][0] = F::from(u64::from(b ^ mask));
                assert!(!satisfies(&circuit, &forged));
            }
            let mut forged = circuit.public();
            forged[0][47] += F::ONE;
            assert!(!satisfies(&circuit, &forged));
            if g2 {
                let mut forged = circuit.public();
                let (a, b) = forged[0].split_at_mut(48);
                a.swap_with_slice(b);
                assert!(!satisfies(&circuit, &forged));
            }
        }
        let zero = EncodingCircuit::<F>::fixture(g2, 0);
        assert!(!satisfies(&zero, &zero.public()));
    }
}
#[test]
fn native_compressed_point_parity_and_flag_rejection_both_fields() {
    parity::<Fp>();
    parity::<Fq>();
}

#[test]
fn encoding_copy_arithmetic_and_byte_cells_reject_tampering() {
    for g2 in [false, true] {
        let circuit = EncodingCircuit::<Fp>::fixture(g2, 7);
        let public = circuit.public();
        let cells = assigned_advice_cells(&circuit, 14, &public).unwrap();
        for &(column, row) in cells.iter().step_by(97).chain(cells.iter().rev().take(48)) {
            assert!(
                !check_tampered(
                    &circuit,
                    14,
                    &public,
                    Some(Tamper {
                        column,
                        row,
                        delta: Fp::ONE
                    })
                )
                .unwrap()
                .is_satisfied()
            );
        }
    }
}
