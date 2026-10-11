//! Tracked bounded Pasta multiplication and padded-division CRT tests.

use super::*;
use crate::{
    GlueConfig,
    cells::SharedRows,
    phase::PhaseColumns,
    range::{LimbBits, RunningSumChip, RunningSumConfig},
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
    Carry,
    Quotient,
    Native,
}
#[derive(Clone)]
struct Bounded<F> {
    serialized: bool,
    modulus: ForeignModulus,
    mode: Mode,
    left: [u128; 3],
    right: [u128; 3],
    left_bits: [usize; 3],
    right_bits: [usize; 3],
    short: bool,
    attack: Attack,
    known: bool,
    rows: Option<(usize, usize)>,
    marker: core::marker::PhantomData<F>,
}
impl<F: PastaField> Circuit<F> for Bounded<F> {
    type Config = (
        GlueConfig,
        RunningSumConfig,
        Option<rotated::RotatedFfConfig>,
    );
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Option<(ForeignModulus, bool)>;
    fn params(&self) -> Self::Params {
        Some((self.modulus, self.serialized))
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, None)
    }
    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        modulus: Self::Params,
    ) -> Self::Config {
        let ports = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let phases = PhaseColumns::allocate(meta);
        let glue = GlueConfig::configure_phased(meta, ports, constants, phases);
        let (modulus, serialized) = modulus.unwrap_or((ForeignModulus::PASTA_FP, false));
        let kernel = (!serialized).then(|| {
            let sums = core::array::from_fn(|_| meta.advice_column());
            rotated::RotatedFfConfig::configure_staged_phased(meta, ports, sums, modulus, phases)
        });
        let column = meta.advice_column();
        let range = RunningSumConfig::configure_compact(meta, column, LimbBits::new(7).unwrap());
        (glue, range, kernel)
    }
    fn synthesize(
        &self,
        (glue, range, kernel): Self::Config,
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
            || "bounded Pasta CRT",
            |mut region| {
                let mut inputs = Vec::new();
                for (values, widths) in [(self.left, self.left_bits), (self.right, self.right_bits)]
                {
                    let values = if self.known {
                        Value::known(values.map(F::from_u128))
                    } else {
                        Value::unknown()
                    };
                    let limbs = serialized::ranged(&mut range, &mut region, values, widths)?;
                    inputs.push(FfValue::from_parts(
                        limbs,
                        widths.map(|bits| (1 << bits) - 1),
                        self.modulus,
                        Form::Bounded,
                    ));
                }
                let (left, right) = (&inputs[0], &inputs[1]);
                let admitted = match self.mode {
                    Mode::Mul => FfChip::<F>::bounded_product_admissible(
                        self.modulus,
                        &left.bounds,
                        &right.bounds,
                    ),
                    Mode::Div => FfChip::<F>::bounded_division_admissible(
                        self.modulus,
                        &left.bounds,
                        &right.bounds,
                    ),
                };
                assert_eq!(admitted, self.short);
                let before = range.next_row();
                let result = if self.attack == Attack::None {
                    let mut ff = FfChip::serialized(glue.clone(), range.clone(), &[self.modulus]);
                    if let Some(kernel) = kernel {
                        ff = ff.with_rotated_kernel(&kernel)?;
                    }
                    match self.mode {
                        Mode::Mul => ff.mul(&mut region, left, right)?,
                        Mode::Div => ff.div(&mut region, left, right)?,
                    }
                } else {
                    let values =
                        left.limb_values()
                            .zip(right.limb_values())
                            .map(|(left, right)| {
                                let mut value = match self.mode {
                                    Mode::Mul => mul_witness(self.modulus, &left, &right),
                                    Mode::Div => div_witness(self.modulus, &left, &right),
                                };
                                match self.attack {
                                    Attack::Carry => {
                                        value.u[2] =
                                            F::from_u128((1 << CARRY_OFFSET_BITS) + (1 << 92))
                                    }
                                    Attack::Quotient => value.q[2] = F::from_u128(1 << 85),
                                    Attack::Native => {
                                        value.c[1] += F::ONE;
                                    }
                                    Attack::None => unreachable!(),
                                }
                                value
                            });
                    let limbs = if let Some(kernel) = kernel {
                        kernel.constrain_short_product(
                            &mut glue,
                            &mut range,
                            &mut region,
                            self.mode,
                            (&left.limbs, &right.limbs),
                            values,
                            CarryLayout::BoundedPasta,
                        )?
                    } else {
                        serialized::constrain_fused(
                            &mut glue,
                            &mut range,
                            &mut region,
                            self.mode,
                            self.modulus,
                            (&left.limbs, &right.limbs),
                            values,
                            CarryLayout::BoundedPasta,
                        )?
                    };
                    FfValue::from_parts(
                        limbs,
                        if self.serialized {
                            PROPER_BOUNDS
                        } else {
                            NARROW_PROPER_BOUNDS
                        },
                        self.modulus,
                        Form::Proper,
                    )
                };
                if self.attack == Attack::None && self.short {
                    assert_eq!(range.next_row() - before, 128);
                }
                if self.attack == Attack::None {
                    let left = from_limbs(&self.left);
                    let right = from_limbs(&self.right);
                    let expected = match self.mode {
                        Mode::Mul => self.modulus.mul(&left, &right),
                        Mode::Div => self
                            .modulus
                            .mul(&left, &self.modulus.fermat_inverse(&right)),
                    };
                    for (word, value) in result.limbs().iter().zip(limb_fields::<F>(&expected)) {
                        GlueChip::assert_constant(&mut region, word, value)?;
                    }
                }
                Ok(())
            },
        )
    }
}
fn cases<F: PastaField>(serialized: bool) {
    for modulus in [ForeignModulus::PASTA_FP, ForeignModulus::PASTA_FQ] {
        for mode in [Mode::Mul, Mode::Div] {
            let (left_bits, right_bits) = if mode == Mode::Mul {
                ([88, 88, 80], [88, 88, 80])
            } else {
                ([94; 3], [89, 89, 82])
            };
            let circuit = Bounded::<F> {
                serialized,
                modulus,
                mode,
                left: left_bits.map(|n| (1 << n) - 1),
                right: right_bits.map(|n| (1 << n) - 1),
                left_bits,
                right_bits,
                short: true,
                attack: Attack::None,
                known: true,
                rows: None,
                marker: core::marker::PhantomData,
            };
            for (left, right) in [
                (circuit.left, circuit.right),
                ([0; 3], circuit.right),
                ([0; 3], [0; 3]),
                ([1, 0, 0], [1, 0, 0]),
            ] {
                let honest = Bounded {
                    left,
                    right,
                    ..circuit.clone()
                };
                let report = check_circuit(&honest, 10, &[], CheckMode::Strict).unwrap();
                assert!(
                    report.is_satisfied(),
                    "{modulus:?} {mode:?}: {:?}",
                    report.failures().first()
                );
            }
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
            for attack in [Attack::Carry, Attack::Quotient, Attack::Native] {
                assert!(
                    !check_circuit(
                        &Bounded {
                            attack,
                            ..circuit.clone()
                        },
                        10,
                        &[],
                        CheckMode::Strict
                    )
                    .unwrap()
                    .is_satisfied()
                );
            }
            if mode == Mode::Div {
                assert!(
                    !check_circuit(
                        &Bounded {
                            left: [1, 0, 0],
                            right: [0; 3],
                            ..circuit.clone()
                        },
                        10,
                        &[],
                        CheckMode::Strict
                    )
                    .unwrap()
                    .is_satisfied()
                );
            }
            let used = assigned.tables.advice_assigned()[0]
                .iter()
                .rposition(|v| *v)
                .unwrap()
                + 1;
            let usable = assigned.tables.usable_rows();
            assert!(
                check_circuit(
                    &Bounded {
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
                    &Bounded {
                        rows: Some((usable - used + 1, usable)),
                        ..circuit.clone()
                    },
                    10,
                    Some(&[])
                )
                .is_err()
            );
            let wide = Bounded {
                left_bits: if mode == Mode::Div {
                    [94; 3]
                } else {
                    [90, 90, 84]
                },
                right_bits: [90, 90, 84],
                short: false,
                ..circuit
            };
            let report = check_circuit(&wide, 10, &[], CheckMode::Strict).unwrap();
            assert!(
                report.is_satisfied(),
                "{modulus:?} {mode:?}: {:?}",
                report.failures().first()
            );
        }
    }
}
#[test]
fn tracked_bounded_pasta_three_carries_and_all_cells_fp() {
    cases::<Fp>(false);
}
#[test]
fn tracked_bounded_pasta_three_carries_and_all_cells_fq() {
    cases::<Fq>(false);
}

#[test]
fn serialized_bounded_pasta_three_carries_and_all_cells_fp() {
    cases::<Fp>(true);
}
#[test]
fn serialized_bounded_pasta_three_carries_and_all_cells_fq() {
    cases::<Fq>(true);
}

#[test]
fn tracked_bounded_pasta_admission_is_structural_and_exact() {
    for modulus in [ForeignModulus::PASTA_FP, ForeignModulus::PASTA_FQ] {
        let narrow = [(1 << 88) - 1, (1 << 88) - 1, (1 << 80) - 1];
        assert!(FfChip::<Fp>::bounded_product_admissible(
            modulus, &narrow, &narrow
        ));
        let mut wide = narrow;
        wide[0] = 1 << 88;
        assert!(!FfChip::<Fp>::bounded_product_admissible(
            modulus, &wide, &narrow
        ));
        let over = [(1 << 88) - 1, (1 << 88) - 1, (1 << 83) - 1];
        assert!(!FfChip::<Fp>::bounded_product_admissible(
            modulus, &over, &over
        ));
        let numerator = [OPERAND_LIMB_MAX; 3];
        let divisor = [(1 << 89) - 1, (1 << 89) - 1, (1 << 82) - 1];
        assert!(FfChip::<Fp>::bounded_division_admissible(
            modulus, &numerator, &divisor
        ));
        let mut wide = divisor;
        wide[0] = 1 << 89;
        assert!(!FfChip::<Fp>::bounded_division_admissible(
            modulus, &numerator, &wide
        ));
        wide = divisor;
        wide[2] = 1 << 83;
        assert!(!FfChip::<Fp>::bounded_division_admissible(
            modulus, &numerator, &wide
        ));
        assert!(!FfChip::<Fp>::bounded_division_admissible(
            modulus,
            &[1 << 94; 3],
            &divisor
        ));
    }
    for modulus in [
        ForeignModulus::P256_BASE,
        ForeignModulus::P256_ORDER,
        ForeignModulus::new([1, 0, 0, 1 << 60]).unwrap(),
    ] {
        assert!(!FfChip::<Fp>::bounded_product_admissible(
            modulus, &[1; 3], &[1; 3]
        ));
        assert!(!FfChip::<Fp>::bounded_division_admissible(
            modulus, &[1; 3], &[1; 3]
        ));
    }
}
