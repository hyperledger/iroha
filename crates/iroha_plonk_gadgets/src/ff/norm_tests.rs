//! Both-field exact padded norm, overlay, mutation and shape controls.
use super::*;
use crate::{
    GlueConfig,
    cells::SharedRows,
    ecc::EccConfig,
    phase::PhaseColumns,
    range::{LimbBits, RunningSumChip, RunningSumConfig},
    tamper::undetected_tampers,
};
use ::ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, PastaCurve};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::ConstraintSystem,
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
#[derive(Clone)]
struct Norm<C: PastaCurve> {
    modulus: ForeignModulus,
    values: [u128; 3],
    widths: [usize; 3],
    known: bool,
    plain: bool,
    reference: bool,
    operation: u8,
    attack: u8,
    marker: core::marker::PhantomData<C>,
}
impl<C: PastaCurve> Circuit<C::Base> for Norm<C> {
    type Config = (GlueConfig, RunningSumConfig, rotated::RotatedFfConfig);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Option<ForeignModulus>;
    fn params(&self) -> Self::Params {
        Some(self.modulus)
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
        Self::configure_with_params(meta, None)
    }
    fn configure_with_params(
        meta: &mut ConstraintSystem<C::Base>,
        m: Self::Params,
    ) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let phases = PhaseColumns::allocate(meta);
        let constants = meta.fixed_column();
        let ports = core::array::from_fn(|i| advice[i]);
        let glue = GlueConfig::configure_phased(meta, ports, constants, phases);
        let _ecc = EccConfig::<C>::configure_phased(meta, advice, phases);
        let kernel = rotated::RotatedFfConfig::configure_staged_packed_phased(
            meta,
            ports,
            core::array::from_fn(|i| advice[i + 5]),
            m.unwrap_or(ForeignModulus::PASTA_FP),
            phases,
            advice[4],
        );
        let r = meta.advice_column();
        let range = RunningSumConfig::configure_compact(meta, r, LimbBits::new(7).unwrap());
        (glue, range, kernel)
    }
    fn synthesize(
        &self,
        (glue_config, range_config, kernel): Self::Config,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<(), Error> {
        let mut glue =
            GlueChip::with_shared_cursor(glue_config, &SharedRows::new(RowCursor::starting_at(0)));
        let mut range = RunningSumChip::new(range_config);
        range.load_table(&mut layouter)?;
        layouter.assign_region(
            || "norm",
            |mut region| {
                let values = if self.known {
                    Value::known(self.values.map(C::Base::from_u128))
                } else {
                    Value::unknown()
                };
                let limbs = serialized::ranged(&mut range, &mut region, values, self.widths)?;
                let a = FfValue::from_parts(
                    limbs,
                    self.widths.map(|w| (1u128 << w) - 1),
                    self.modulus,
                    if self.widths == [87, 87, 81] {
                        Form::Proper
                    } else {
                        Form::Bounded
                    },
                );
                let ff = FfChip::serialized(glue.clone(), range.clone(), &[self.modulus]);
                let mut ff = if self.plain {
                    ff
                } else {
                    ff.with_rotated_kernel(&kernel)?
                };
                let out = if self.reference {
                    let sq = ff.square(&mut region, &a)?;
                    let five =
                        ff.constant(&mut glue, &mut region, self.modulus, &Nat::from_u128(5))?;
                    ff.sub(&mut glue, &mut region, &sq, &five)?
                } else if self.attack == 0 {
                    match self.operation {
                        0 => ff.norm(&mut glue, &mut region, &a)?,
                        1 => ff.mul(&mut region, &a, &a)?,
                        2 => ff.div(&mut region, &a, &a)?,
                        _ => return Err(Error::Synthesis),
                    }
                } else {
                    let w = a.limb_values().map(|v| {
                        let mut w = norm_witness::<C::Base>(self.modulus, &v);
                        match self.attack {
                            1 => w.c[0] += C::Base::ONE,
                            2 => w.q[0] += C::Base::ONE,
                            3 => w.u[0] += C::Base::ONE,
                            4 => {
                                w.u[2] =
                                    C::Base::from_u128((1u128 << CARRY_OFFSET_BITS) + (1u128 << 92))
                            }
                            _ => {}
                        }
                        w
                    });
                    let layout = FfChip::<C::Base>::carry_layout(
                        Mode::Mul,
                        self.modulus,
                        Operand::value(&a),
                        Operand::value(&a),
                    );
                    let limbs = kernel.constrain_short_product_padding(
                        &mut glue,
                        &mut range,
                        &mut region,
                        FusedPadding {
                            mode: Mode::Mul,
                            layout,
                            norm: self.attack != 5,
                        },
                        (&a.limbs, &a.limbs),
                        w,
                    )?;
                    FfValue::from_parts(limbs, kernel.result_bounds(), self.modulus, Form::Proper)
                };
                let out = ff.assert_canonical(&mut region, &out)?;
                let value = from_limbs(&self.values);
                let expect = match self.operation {
                    0 => self.modulus.reduce(
                        &value
                            .wrapping_mul(&value)
                            .wrapping_add(&self.modulus.nat())
                            .wrapping_sub(&Nat::from_u128(5)),
                    ),
                    1 => self.modulus.mul(&value, &value),
                    2 => self.modulus.div(&value, &value).unwrap(),
                    _ => unreachable!(),
                };
                let constant = ff.constant(&mut glue, &mut region, self.modulus, &expect)?;
                FfChip::assert_equal(&mut region, &out, &constant)
            },
        )
    }
}
fn cases<C: PastaCurve>() {
    for modulus in [ForeignModulus::PASTA_FP, ForeignModulus::PASTA_FQ] {
        let blank = Norm::<C> {
            modulus,
            values: [0; 3],
            widths: [88, 88, 80],
            known: true,
            plain: false,
            reference: false,
            operation: 0,
            attack: 0,
            marker: core::marker::PhantomData,
        };
        let modulus_value = modulus.nat();
        let points = [
            Nat::ZERO,
            Nat::ONE,
            Nat::from_u128(2),
            Nat::from_u128(3),
            modulus_value.wrapping_sub(&Nat::ONE),
            modulus_value,
            modulus_value.wrapping_add(&Nat::ONE),
            Nat::pow2(255).wrapping_sub(&Nat::ONE),
        ];
        for value in points {
            let mut circuit = blank.clone();
            circuit.values = to_limbs(&value).unwrap();
            circuit.widths = [88, 88, 81];
            let report = check_circuit(&circuit, 10, &[], CheckMode::Strict).unwrap();
            assert!(report.is_satisfied(), "{:?}", report.failures().first());
        }
        for widths in [[87, 87, 81], [88, 88, 80], [94, 94, 80]] {
            let circuit = Norm {
                values: widths.map(|w| (1u128 << w) - 1),
                widths,
                ..blank.clone()
            };
            let rep = check_circuit(&circuit, 10, &[], CheckMode::Strict).unwrap();
            assert!(
                rep.is_satisfied(),
                "{widths:?}: {:?}",
                rep.failures().first()
            );
            let assigned = synthesize(&circuit, 10, Some(&[])).unwrap();
            let unknown = synthesize(&circuit.without_witnesses(), 10, None).unwrap();
            assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
            assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
            assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
            assert_eq!(
                assigned.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
            if widths == [88, 88, 80] {
                assert!(undetected_tampers(&circuit, 10, &[]).unwrap().is_empty());
                for attack in 1..=5 {
                    let tampered = Norm {
                        attack,
                        ..circuit.clone()
                    };
                    assert!(
                        !check_circuit(&tampered, 10, &[], CheckMode::Strict)
                            .unwrap()
                            .is_satisfied(),
                        "attack {attack}"
                    );
                }
            }
        }
    }
}
#[test]
fn fused_norm_pallas() {
    cases::<Ep>();
}
#[test]
fn fused_norm_vesta() {
    cases::<Eq>();
}

#[test]
fn fused_norm_actual_gate_degree() {
    fn check<C: PastaCurve>() {
        let mut cs = ConstraintSystem::<C::Base>::default();
        Norm::<C>::configure_with_params(&mut cs, Some(ForeignModulus::PASTA_FP));
        let actual = cs
            .gates()
            .iter()
            .flat_map(iroha_plonk::cs::Gate::polynomials)
            .map(iroha_plonk::Expression::degree)
            .max()
            .unwrap();
        assert_eq!(actual, crate::phase::MAX_COMPACT_GATE_DEGREE);
        assert_eq!(actual, 10);
    }
    check::<Ep>();
    check::<Eq>();
}

#[test]
fn packed_product_division_and_wide_fallback_both_fields() {
    fn run<C: PastaCurve>() {
        for modulus in [ForeignModulus::PASTA_FP, ForeignModulus::PASTA_FQ] {
            for operation in [1, 2] {
                for widths in [[87, 87, 81], [88, 88, 80], [94, 94, 87]] {
                    let c = Norm::<C> {
                        modulus,
                        values: widths.map(|w| (1u128 << w) - 1),
                        widths,
                        known: true,
                        plain: false,
                        reference: false,
                        operation,
                        attack: 0,
                        marker: core::marker::PhantomData,
                    };
                    let r = check_circuit(&c, 10, &[], CheckMode::Strict).unwrap();
                    assert!(
                        r.is_satisfied(),
                        "op{operation} widths{widths:?} {:?}",
                        r.failures().first()
                    );
                    let k = synthesize(&c, 10, Some(&[])).unwrap();
                    let u = synthesize(&c.without_witnesses(), 10, None).unwrap();
                    assert_eq!(k.tables.fixed(), u.tables.fixed());
                    assert_eq!(k.tables.permutation(), u.tables.permutation());
                    assert_eq!(k.tables.advice_assigned(), u.tables.advice_assigned());
                    assert!(undetected_tampers(&c, 10, &[]).unwrap().is_empty());
                }
            }
        }
    }
    run::<Ep>();
    run::<Eq>();
}

#[test]
fn ordinary_serialized_norm_both_fields() {
    fn run<C: PastaCurve>() {
        for modulus in [ForeignModulus::PASTA_FP, ForeignModulus::PASTA_FQ] {
            for widths in [[87, 87, 81], [88, 88, 80]] {
                for value in [Nat::ZERO, Nat::ONE, modulus.nat().wrapping_sub(&Nat::ONE)] {
                    let c = Norm::<C> {
                        modulus,
                        values: to_limbs(&value).unwrap(),
                        widths,
                        known: true,
                        plain: true,
                        reference: false,
                        operation: 0,
                        attack: 0,
                        marker: core::marker::PhantomData,
                    };
                    assert!(
                        check_circuit(&c, 10, &[], CheckMode::Strict)
                            .unwrap()
                            .is_satisfied()
                    );
                    let k = synthesize(&c, 10, Some(&[])).unwrap();
                    let u = synthesize(&c.without_witnesses(), 10, None).unwrap();
                    assert_eq!(k.tables.fixed(), u.tables.fixed());
                    assert_eq!(k.tables.permutation(), u.tables.permutation());
                    assert_eq!(k.tables.advice_assigned(), u.tables.advice_assigned());
                    assert!(undetected_tampers(&c, 10, &[]).unwrap().is_empty());
                }
            }
        }
    }
    run::<Ep>();
    run::<Eq>();
}
