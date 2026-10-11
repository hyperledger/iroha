//! Bounded reduction's exact CRT envelope and adversarial root tests.

use super::*;
use crate::{
    GlueConfig,
    cells::{RowCursor, SharedRows},
    ff::{FfChip, ForeignModulus, OPERAND_LIMB_MAX, from_limbs},
    range::{LimbBits, RunningSumConfig},
    tamper::undetected_tampers,
};
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::ConstraintSystem,
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attack {
    None,
    NativeOnly,
    LowOnly,
    Quotient,
    Carry,
    Bounds,
    Unconfigured,
    Alias,
    CanonicalAlias,
}
#[derive(Clone)]
struct Reduction<F> {
    modulus: ForeignModulus,
    input: [u128; 3],
    attack: Attack,
    known: bool,
    rows: Option<(usize, usize)>,
    marker: core::marker::PhantomData<F>,
}
impl<F: PastaField> Circuit<F> for Reduction<F> {
    type Config = (GlueConfig, RunningSumConfig);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let range_column = meta.advice_column();
        let range =
            RunningSumConfig::configure_compact(meta, range_column, LimbBits::new(7).unwrap());
        (glue, range)
    }
    fn synthesize(
        &self,
        (glue, range): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::with_shared_cursor(
            glue,
            &SharedRows::new(self.rows.map_or_else(
                || RowCursor::starting_at(0),
                |(start, end)| RowCursor::bounded(start, end),
            )),
        );
        let mut range =
            RunningSumChip::with_shared_cursor(range, &SharedRows::new(RowCursor::starting_at(0)));
        range.load_table(&mut layouter)?;
        layouter.assign_region(
            || "bounded reduction",
            |mut region| {
                let values = if self.known {
                    Value::known(self.input.map(F::from_u128))
                } else {
                    Value::unknown()
                };
                let limbs = ranged(&mut range, &mut region, values, [94; 3])?;
                let value = FfValue::from_parts(
                    limbs,
                    if self.attack == Attack::Bounds {
                        [1 << 94; 3]
                    } else {
                        [OPERAND_LIMB_MAX; 3]
                    },
                    self.modulus,
                    Form::Bounded,
                );
                let configured = if self.attack == Attack::Unconfigured {
                    if self.modulus == ForeignModulus::PASTA_FP {
                        ForeignModulus::PASTA_FQ
                    } else {
                        ForeignModulus::PASTA_FP
                    }
                } else {
                    self.modulus
                };
                let mut ff = FfChip::serialized(glue.clone(), range.clone(), &[configured]);
                let result = if matches!(
                    self.attack,
                    Attack::None | Attack::Bounds | Attack::Unconfigured
                ) {
                    ff.reduce(&mut region, &value)?
                } else {
                    let witness = witness(&value).map(|mut witness| {
                        match self.attack {
                            Attack::NativeOnly => {
                                witness.result = limb_fields(
                                    &Nat::from_field(&(-F::ONE)).wrapping_add(&Nat::ONE),
                                );
                                witness.quotient = F::ZERO;
                                witness.carry = F::from(1 << 17);
                            }
                            Attack::LowOnly => witness.result[1] += F::ONE,
                            Attack::Quotient => witness.quotient = F::from(1 << 17),
                            Attack::Carry => witness.carry = F::from(1 << 18),
                            Attack::Alias | Attack::CanonicalAlias => {
                                witness.result = limb_fields(&self.modulus.nat());
                                witness.quotient = F::ZERO;
                                witness.carry = F::from(1 << 17);
                            }
                            _ => unreachable!(),
                        }
                        witness
                    });
                    constrain(&mut glue, &mut range, &mut region, &value, witness)?
                };
                assert_eq!(result.form(), Form::Proper);
                assert_eq!(
                    result.bounds(),
                    if self.modulus.nat().cmp_vartime(&Nat::pow2(255)).is_lt() {
                        NARROW_PROPER_BOUNDS
                    } else {
                        PROPER_BOUNDS
                    }
                );
                if self.attack == Attack::CanonicalAlias {
                    ff.assert_canonical(&mut region, &result)?;
                }
                if self.attack == Attack::None {
                    let expected = self.modulus.reduce(&from_limbs(&self.input));
                    for (limb, expected) in result.limbs().iter().zip(limb_fields::<F>(&expected)) {
                        glue.enforce_constant(&mut region, limb, expected)?;
                    }
                }
                Ok(())
            },
        )
    }
}

fn cases<F: PastaField>() {
    for modulus in [
        ForeignModulus::PASTA_FP,
        ForeignModulus::PASTA_FQ,
        ForeignModulus::P256_BASE,
        ForeignModulus::P256_ORDER,
        ForeignModulus::new([1, 0, 0, 1 << 60]).unwrap(),
    ] {
        let mut inputs = vec![[0; 3], [1, 0, 0], [OPERAND_LIMB_MAX; 3]];
        for delta in [Nat::ZERO, Nat::ONE] {
            inputs.push(super::super::to_limbs(&modulus.nat().wrapping_add(&delta)).unwrap());
        }
        inputs.push(super::super::to_limbs(&modulus.nat().wrapping_sub(&Nat::ONE)).unwrap());
        for input in inputs {
            let circuit = Reduction::<F> {
                modulus,
                input,
                attack: Attack::None,
                known: true,
                rows: None,
                marker: core::marker::PhantomData,
            };
            assert!(
                check_circuit(&circuit, 10, &[], CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "{modulus:?} {input:?}"
            );
            if input == [OPERAND_LIMB_MAX; 3] {
                let assigned = synthesize(&circuit, 10, Some(&[])).unwrap();
                let unknown = synthesize(&circuit.without_witnesses(), 10, None).unwrap();
                assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
                assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
                assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
                assert_eq!(
                    assigned.tables.advice_assigned(),
                    unknown.tables.advice_assigned()
                );
                assert!(undetected_tampers(&circuit, 10, &[]).unwrap().is_empty());
            }
        }
        let circuit = Reduction::<F> {
            modulus,
            input: [0; 3],
            attack: Attack::None,
            known: true,
            rows: None,
            marker: core::marker::PhantomData,
        };
        for attack in [
            Attack::NativeOnly,
            Attack::LowOnly,
            Attack::Quotient,
            Attack::Carry,
        ] {
            assert!(
                !check_circuit(
                    &Reduction {
                        attack,
                        ..circuit.clone()
                    },
                    10,
                    &[],
                    CheckMode::Strict
                )
                .unwrap()
                .is_satisfied(),
                "{modulus:?} {attack:?}"
            );
        }
        assert!(
            synthesize(
                &Reduction {
                    attack: Attack::Bounds,
                    ..circuit.clone()
                },
                10,
                Some(&[])
            )
            .is_err()
        );
        assert!(
            synthesize(
                &Reduction {
                    attack: Attack::Unconfigured,
                    ..circuit.clone()
                },
                10,
                Some(&[])
            )
            .is_err()
        );
        let alias = Reduction {
            input: modulus.limbs(),
            attack: Attack::Alias,
            ..circuit.clone()
        };
        assert!(
            check_circuit(&alias, 10, &[], CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        assert!(
            !check_circuit(
                &Reduction {
                    attack: Attack::CanonicalAlias,
                    ..alias
                },
                10,
                &[],
                CheckMode::Strict
            )
            .unwrap()
            .is_satisfied()
        );
        let assigned = synthesize(&circuit, 10, Some(&[])).unwrap();
        let used = assigned.tables.advice_assigned()[0]
            .iter()
            .rposition(|x| *x)
            .unwrap()
            + 1;
        let usable = assigned.tables.usable_rows();
        assert!(
            check_circuit(
                &Reduction {
                    rows: Some((usable - used, usable)),
                    ..circuit.clone()
                },
                10,
                &[],
                CheckMode::Strict
            )
            .unwrap()
            .is_satisfied()
        );
        assert!(
            synthesize(
                &Reduction {
                    rows: Some((usable - used + 1, usable)),
                    ..circuit
                },
                10,
                Some(&[])
            )
            .is_err()
        );
    }
}
#[test]
fn unsigned_lazy_reduction_exact_bounds_and_every_cell_fp() {
    cases::<Fp>();
}
#[test]
fn unsigned_lazy_reduction_exact_bounds_and_every_cell_fq() {
    cases::<Fq>();
}

#[test]
fn unsigned_lazy_reduction_integer_envelope() {
    let maximum = from_limbs(&[OPERAND_LIMB_MAX; 3]);
    assert!(maximum.cmp_vartime(&Nat::pow2(269)).is_lt());
    for modulus in [
        ForeignModulus::PASTA_FP,
        ForeignModulus::PASTA_FQ,
        ForeignModulus::P256_BASE,
        ForeignModulus::P256_ORDER,
        ForeignModulus::new([1, 0, 0, 1 << 60]).unwrap(),
    ] {
        let (quotient, remainder) = maximum.div_rem(&modulus.nat()).unwrap();
        assert!(quotient.cmp_vartime(&Nat::pow2(17)).is_lt());
        let low = Nat::from_u128(OPERAND_LIMB_MAX)
            .wrapping_sub(&Nat::from_u128(remainder.low_bits_u128(LIMB_BITS)))
            .wrapping_sub(&quotient.wrapping_mul(&Nat::from_u128(modulus.limbs()[0])));
        assert_eq!(low.low_bits_u128(LIMB_BITS), 0);
        let encoded = low.sar(LIMB_BITS).wrapping_add(&Nat::pow2(17));
        assert!(encoded.cmp_vartime(&Nat::pow2(18)).is_lt());
    }
    for native in [ForeignModulus::PASTA_FP, ForeignModulus::PASTA_FQ] {
        assert!(Nat::pow2(106).cmp_vartime(&native.nat()).is_lt());
        assert!(
            Nat::pow2(274)
                .cmp_vartime(&native.nat().shl(LIMB_BITS))
                .is_lt()
        );
    }
}
