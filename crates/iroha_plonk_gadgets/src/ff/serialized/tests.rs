//! Serialized CRT parity, bounds and adversarial witness tests.

use super::*;
use crate::{
    GlueConfig,
    cells::{RowCursor, SharedRows},
    ff::rotated::RotatedFfConfig,
    phase::PhaseColumns,
    range::{LimbBits, RunningSumConfig},
    tamper::{Tamper, check_tampered, undetected_tampers},
};
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::ConstraintSystem,
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestMode {
    Mul,
    Div,
    Canonical,
    NativeForgery,
    CarryOverflow,
    ProperNativeForgery,
    ProperCarryOverflow,
    ProperQuotientOverflow,
    LazyMul,
    WidenedMul,
    MixedModulus,
    Inadmissible,
}
#[derive(Clone)]
struct Kernel<F: PastaField> {
    modulus: ForeignModulus,
    mode: TestMode,
    left: [u64; 4],
    right: [u64; 4],
    known: bool,
    rotated: u8,
    rows: Option<(usize, usize)>,
    marker: core::marker::PhantomData<F>,
}
impl<F: PastaField> Kernel<F> {
    fn value<T>(&self, x: T) -> Value<T> {
        if self.known {
            Value::known(x)
        } else {
            Value::unknown()
        }
    }
}
impl<F: PastaField> Circuit<F> for Kernel<F> {
    type Config = (GlueConfig, RunningSumConfig, Option<RotatedFfConfig>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Option<(ForeignModulus, u8)>;
    fn params(&self) -> Self::Params {
        Some((self.modulus, self.rotated))
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
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let (modulus, rotated) = params.unwrap_or((ForeignModulus::PASTA_FP, 0));
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constant = meta.fixed_column();
        let phases = PhaseColumns::allocate(meta);
        let glue = GlueConfig::configure_phased(meta, advice, constant, phases);
        let range_column = meta.advice_column();
        let range =
            RunningSumConfig::configure_compact(meta, range_column, LimbBits::new(7).unwrap());
        let kernel = if rotated == 2 {
            let sums = core::array::from_fn(|_| meta.advice_column());
            Some(RotatedFfConfig::configure_staged_phased(
                meta, advice, sums, modulus, phases,
            ))
        } else {
            (rotated == 1).then(|| RotatedFfConfig::configure_phased(meta, advice, modulus, phases))
        };
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
            || "serialized CRT",
            |mut region| {
                let mut left = SerializedFf::witness(
                    &mut range,
                    &mut region,
                    self.modulus,
                    self.value(self.left),
                )?;
                if self.mode == TestMode::Inadmissible {
                    left.bounds = [1 << 94; LIMBS];
                }
                if self.mode == TestMode::LazyMul {
                    left.form = Form::Bounded;
                }
                if self.mode == TestMode::WidenedMul {
                    left.bounds[2] = (1 << 83) - 1;
                }
                if self.mode == TestMode::Canonical {
                    SerializedFf::assert_canonical(&mut glue, &mut range, &mut region, &left)?;
                    return Ok(());
                }
                let right_modulus = if self.mode == TestMode::MixedModulus {
                    if self.modulus == ForeignModulus::PASTA_FP {
                        ForeignModulus::PASTA_FQ
                    } else {
                        ForeignModulus::PASTA_FP
                    }
                } else {
                    self.modulus
                };
                let right = SerializedFf::witness(
                    &mut range,
                    &mut region,
                    right_modulus,
                    self.value(self.right),
                )?;
                let mut ff = kernel
                    .map(|kernel| {
                        FfChip::serialized(glue.clone(), range.clone(), &[self.modulus])
                            .with_rotated_kernel(&kernel)
                    })
                    .transpose()?;
                let start_glue = glue.next_row();
                let start_range = range.next_row();
                let result = match self.mode {
                    TestMode::Mul
                    | TestMode::LazyMul
                    | TestMode::WidenedMul
                    | TestMode::MixedModulus
                    | TestMode::Inadmissible => {
                        if let Some(ff) = &mut ff {
                            ff.mul(&mut region, &left, &right)?
                        } else {
                            SerializedFf::mul(&mut glue, &mut range, &mut region, &left, &right)?
                        }
                    }
                    TestMode::Div => {
                        if let Some(ff) = &mut ff {
                            ff.div(&mut region, &left, &right)?
                        } else {
                            SerializedFf::div(&mut glue, &mut range, &mut region, &left, &right)?
                        }
                    }
                    TestMode::NativeForgery | TestMode::CarryOverflow => {
                        let witness = if self.mode == TestMode::NativeForgery {
                            FusedWitness {
                                c: [F::ZERO; LIMBS],
                                q: [F::ZERO; LIMBS],
                                u: [F::from_u128(1 << CARRY_OFFSET_BITS); CARRIES],
                            }
                        } else {
                            let mut witness = mul_witness(
                                self.modulus,
                                &super::super::nat_limbs(&Nat::from_words(self.left)),
                                &super::super::nat_limbs(&Nat::from_words(self.right)),
                            );
                            witness.u[3] = F::from_u128(1 << (CARRY_OFFSET_BITS + 1));
                            witness
                        };
                        if let Some(kernel) = kernel {
                            let result = kernel.constrain(
                                &mut glue,
                                &mut range,
                                &mut region,
                                Mode::Mul,
                                (&left.limbs, &right.limbs),
                                self.value(witness),
                            )?;
                            FfValue::from_parts(result, PROPER_BOUNDS, self.modulus, Form::Proper)
                        } else {
                            fused(
                                &mut glue,
                                &mut range,
                                &mut region,
                                Mode::Mul,
                                &left,
                                &right,
                                self.value(witness),
                                CarryLayout::Full,
                            )?
                        }
                    }
                    TestMode::ProperNativeForgery
                    | TestMode::ProperCarryOverflow
                    | TestMode::ProperQuotientOverflow => {
                        let mut witness = mul_witness(
                            self.modulus,
                            &super::super::nat_limbs(&Nat::from_words(self.left)),
                            &super::super::nat_limbs(&Nat::from_words(self.right)),
                        );
                        match self.mode {
                            TestMode::ProperNativeForgery => {
                                witness.c = [F::ZERO; LIMBS];
                                witness.q = [F::ZERO; LIMBS];
                                witness.u = [F::from_u128(1 << CARRY_OFFSET_BITS); CARRIES];
                            }
                            TestMode::ProperCarryOverflow => {
                                witness.u[2] = F::from_u128((1 << CARRY_OFFSET_BITS) + (1 << 89))
                            }
                            TestMode::ProperQuotientOverflow => {
                                witness.q[2] = F::from_u128(1 << 84)
                            }
                            _ => unreachable!(),
                        }
                        let result = if let Some(kernel) = kernel {
                            kernel.constrain_short_product(
                                &mut glue,
                                &mut range,
                                &mut region,
                                Mode::Mul,
                                (&left.limbs, &right.limbs),
                                self.value(witness),
                                CarryLayout::ProperProduct,
                            )?
                        } else {
                            constrain_fused(
                                &mut glue,
                                &mut range,
                                &mut region,
                                Mode::Mul,
                                self.modulus,
                                (&left.limbs, &right.limbs),
                                self.value(witness),
                                CarryLayout::ProperProduct,
                            )?
                        };
                        FfValue::from_parts(result, PROPER_BOUNDS, self.modulus, Form::Proper)
                    }
                    TestMode::Canonical => unreachable!(),
                };
                if matches!(
                    self.mode,
                    TestMode::Mul | TestMode::Div | TestMode::LazyMul | TestMode::WidenedMul
                ) {
                    let proper = self.rotated != 1
                        && self.mode == TestMode::Mul
                        && self.modulus.nat().cmp_vartime(&Nat::pow2(254)).is_gt();
                    let bounded = self.rotated != 1
                        && matches!(self.mode, TestMode::Div | TestMode::LazyMul)
                        && self.modulus.nat().cmp_vartime(&Nat::pow2(255)).is_lt();
                    assert_eq!(
                        glue.next_row() - start_glue,
                        if self.rotated != 0 {
                            4
                        } else if proper || bounded {
                            16
                        } else {
                            19
                        }
                    );
                    assert_eq!(
                        range.next_row() - start_range,
                        if proper {
                            123
                        } else if bounded {
                            128
                        } else {
                            143
                        }
                    );
                    let result = if self.rows.is_some() {
                        result
                    } else {
                        SerializedFf::assert_canonical(&mut glue, &mut range, &mut region, &result)?
                    };
                    let left = Nat::from_words(self.left);
                    let right = Nat::from_words(self.right);
                    let expected = self.modulus.mul(
                        &left,
                        &if self.mode == TestMode::Div {
                            self.modulus.fermat_inverse(&right)
                        } else {
                            right
                        },
                    );
                    let expected = limb_fields::<F>(&expected);
                    for (actual, expected) in result.limbs.iter().zip(expected) {
                        GlueChip::assert_constant(&mut region, actual, expected)?;
                    }
                }
                Ok(())
            },
        )
    }
}
fn fixture<F: PastaField>(
    rotated: u8,
    modulus: ForeignModulus,
    mode: TestMode,
    left: Nat,
    right: Nat,
) -> Kernel<F> {
    Kernel {
        modulus,
        mode,
        left: left.words()[..4].try_into().unwrap(),
        right: right.words()[..4].try_into().unwrap(),
        known: true,
        rotated,
        rows: None,
        marker: core::marker::PhantomData,
    }
}
fn satisfies<F: PastaField>(circuit: &Kernel<F>) -> bool {
    check_circuit(circuit, 10, &[], CheckMode::Strict)
        .unwrap()
        .is_satisfied()
}
fn run<F: PastaField>(rotated: u8) {
    for modulus in [
        ForeignModulus::PASTA_FP,
        ForeignModulus::PASTA_FQ,
        ForeignModulus::P256_BASE,
        ForeignModulus::P256_ORDER,
    ] {
        let maximum = modulus.nat().wrapping_sub(&Nat::ONE);
        for mode in [TestMode::Mul, TestMode::Div] {
            let circuit = fixture::<F>(rotated, modulus, mode, maximum, Nat::from_u128(17));
            assert!(satisfies(&circuit), "{modulus:?} {mode:?}");
            let known = synthesize(&circuit, 10, Some(&[])).unwrap();
            let unknown = synthesize(&circuit.without_witnesses(), 10, None).unwrap();
            assert_eq!(known.tables.fixed(), unknown.tables.fixed());
            assert_eq!(known.tables.selectors(), unknown.tables.selectors());
            assert_eq!(known.tables.permutation(), unknown.tables.permutation());
            assert_eq!(
                known.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
            assert!(undetected_tampers(&circuit, 10, &[]).unwrap().is_empty());
        }
        for value in [Nat::ZERO, maximum] {
            assert!(satisfies(&fixture::<F>(
                rotated,
                modulus,
                TestMode::Canonical,
                value,
                Nat::ONE
            )));
        }
        for value in [modulus.nat(), modulus.nat().wrapping_add(&Nat::ONE)] {
            assert!(!satisfies(&fixture::<F>(
                rotated,
                modulus,
                TestMode::Canonical,
                value,
                Nat::ONE
            )));
        }
        // Only the native residue sees the B^4 product; the four low carry
        // equations, zero result/quotient and offset carries are consistent.
        let forged = fixture::<F>(
            rotated,
            modulus,
            TestMode::NativeForgery,
            Nat::pow2(174),
            Nat::pow2(174),
        );
        assert!(!satisfies(&forged));
        assert!(!satisfies(&fixture::<F>(
            rotated,
            modulus,
            TestMode::CarryOverflow,
            Nat::ONE,
            Nat::ONE
        )));
        assert!(!satisfies(&fixture::<F>(
            rotated,
            modulus,
            TestMode::Div,
            Nat::ONE,
            Nat::ZERO
        )));
        assert!(
            synthesize(
                &fixture::<F>(rotated, modulus, TestMode::MixedModulus, Nat::ONE, Nat::ONE),
                10,
                Some(&[])
            )
            .is_err()
        );
    }
}
#[test]
fn serialized_ff_matches_integer_reference_and_rejects_aliases_pasta_fp() {
    run::<Fp>(0);
}
#[test]
fn serialized_ff_matches_integer_reference_and_rejects_aliases_pasta_fq() {
    run::<Fq>(0);
}

#[test]
fn rotated_ff_matches_integer_reference_and_rejects_aliases_pasta_fp() {
    run::<Fp>(1);
}
#[test]
fn rotated_ff_matches_integer_reference_and_rejects_aliases_pasta_fq() {
    run::<Fq>(1);
}

fn rotated_boundary<F: PastaField>(profile: u8) {
    for modulus in [
        ForeignModulus::PASTA_FP,
        ForeignModulus::PASTA_FQ,
        ForeignModulus::P256_BASE,
        ForeignModulus::P256_ORDER,
    ] {
        let mut meta = ConstraintSystem::<F>::default();
        let _ = Kernel::<F>::configure_with_params(&mut meta, Some((modulus, profile)));
        let end = meta.usable_rows(10).unwrap();
        for mode in [TestMode::Mul, TestMode::Div] {
            let mut circuit = fixture::<F>(
                profile,
                modulus,
                mode,
                modulus.nat().wrapping_sub(&Nat::ONE),
                Nat::from_u128(17),
            );
            for start in [0, end - 4] {
                circuit.rows = Some((start, start + 4));
                assert!(satisfies(&circuit));
                let assigned = synthesize(&circuit, 10, Some(&[])).unwrap();
                // The centered selector is always off at global row zero, so
                // the negative rotation cannot link into blinding/wraparound rows.
                assert_eq!(assigned.tables.fixed()[1][0], F::ZERO);
                assert_eq!(assigned.tables.fixed()[2][0], F::ZERO);
                let unknown = synthesize(&circuit.without_witnesses(), 10, None).unwrap();
                assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
                assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
                assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
                assert_eq!(
                    assigned.tables.advice_assigned(),
                    unknown.tables.advice_assigned()
                );
                // Both staged short products have three carry roots. Pasta
                // division now shares that layout; P-256 division retains four.
                for i in 0..if profile == 2
                    && (mode == TestMode::Mul
                        || matches!(modulus, ForeignModulus::PASTA_FP | ForeignModulus::PASTA_FQ))
                {
                    15
                } else {
                    16
                } {
                    let report = check_tampered(
                        &circuit,
                        10,
                        &[],
                        Some(Tamper {
                            column: i % 4,
                            row: start + i / 4,
                            delta: F::ONE,
                        }),
                    )
                    .unwrap();
                    assert!(
                        !report.is_satisfied(),
                        "copied root {i} in block at {start}"
                    );
                }
            }
            // A bounded cursor fails before any kernel root is copied.
            circuit.rows = Some((end - 3, end));
            assert!(matches!(
                synthesize(&circuit, 10, Some(&[])),
                Err(Error::BoundsFailure)
            ));
            // Even an incorrectly unbounded caller cannot assign blinding rows.
            circuit.rows = Some((end - 3, usize::MAX));
            assert!(synthesize(&circuit, 10, Some(&[])).is_err());
        }
        assert!(
            synthesize(
                &fixture::<F>(profile, modulus, TestMode::Inadmissible, Nat::ONE, Nat::ONE),
                10,
                Some(&[])
            )
            .is_err()
        );
    }
}

#[test]
fn rotated_final_usable_row_and_admission_both_fields() {
    rotated_boundary::<Fp>(1);
    rotated_boundary::<Fq>(1);
}

fn rotated_attachment<F: PastaField>() {
    let mut meta = ConstraintSystem::<F>::default();
    let ports = core::array::from_fn(|_| meta.advice_column());
    let fixed = meta.fixed_column();
    let glue = GlueConfig::configure(&mut meta, ports, fixed);
    let column = meta.advice_column();
    let range = RunningSumConfig::configure_compact(&mut meta, column, LimbBits::new(7).unwrap());
    let modulus = ForeignModulus::PASTA_FP;
    let kernel = RotatedFfConfig::configure(&mut meta, ports, modulus);
    let serialized = |moduli: &[ForeignModulus]| {
        FfChip::<F>::serialized(GlueChip::new(glue), RunningSumChip::new(range), moduli)
    };
    assert!(serialized(&[modulus]).with_rotated_kernel(&kernel).is_ok());
    for moduli in [
        vec![],
        vec![ForeignModulus::PASTA_FQ],
        vec![modulus, ForeignModulus::PASTA_FQ],
        vec![modulus, modulus],
    ] {
        assert!(serialized(&moduli).with_rotated_kernel(&kernel).is_err());
    }
    let other = core::array::from_fn(|_| meta.advice_column());
    let other = RotatedFfConfig::configure(&mut meta, other, modulus);
    assert!(serialized(&[modulus]).with_rotated_kernel(&other).is_err());
    let columns = core::array::from_fn(|_| meta.advice_column());
    let fused = super::super::FfConfig::configure(&mut meta, columns, &[modulus]);
    assert!(
        FfChip::<F>::new(fused)
            .with_rotated_kernel(&kernel)
            .is_err()
    );
}

#[test]
fn rotated_attachment_rejects_profile_modulus_and_port_mismatch() {
    rotated_attachment::<Fp>();
    rotated_attachment::<Fq>();
}

#[test]
fn staged_rotated_ff_all_fields_moduli_cells_and_boundaries() {
    run::<Fp>(2);
    run::<Fq>(2);
    rotated_boundary::<Fp>(2);
    rotated_boundary::<Fq>(2);
}

fn proper_product<F: PastaField>(profile: u8) {
    let maximum = Nat::pow2(256).wrapping_sub(&Nat::ONE);
    for modulus in [
        ForeignModulus::PASTA_FP,
        ForeignModulus::PASTA_FQ,
        ForeignModulus::P256_BASE,
        ForeignModulus::P256_ORDER,
    ] {
        for mode in [TestMode::Mul, TestMode::LazyMul, TestMode::WidenedMul] {
            for (left, right) in [
                (maximum, maximum),
                (Nat::ZERO, maximum),
                (maximum, Nat::ONE),
            ] {
                let circuit = fixture::<F>(profile, modulus, mode, left, right);
                assert!(satisfies(&circuit), "{modulus:?} {mode:?}");
                let known = synthesize(&circuit, 10, Some(&[])).unwrap();
                let unknown = synthesize(&circuit.without_witnesses(), 10, None).unwrap();
                assert_eq!(known.tables.fixed(), unknown.tables.fixed());
                assert_eq!(known.tables.permutation(), unknown.tables.permutation());
                assert_eq!(
                    known.tables.advice_assigned(),
                    unknown.tables.advice_assigned()
                );
            }
        }
        for mode in [
            TestMode::ProperCarryOverflow,
            TestMode::ProperQuotientOverflow,
        ] {
            assert!(!satisfies(&fixture::<F>(
                profile,
                modulus,
                mode,
                Nat::ONE,
                Nat::ONE
            )));
        }
        // Low three columns vanish, so this forgery is caught only by the
        // native residual. Conversely N*1 vanishes natively but not modulo B^3.
        for (left, right) in [
            (Nat::pow2(174), Nat::pow2(87)),
            (
                Nat::from_field(&(-F::ONE)).wrapping_add(&Nat::ONE),
                Nat::ONE,
            ),
        ] {
            assert!(!satisfies(&fixture::<F>(
                profile,
                modulus,
                TestMode::ProperNativeForgery,
                left,
                right
            )));
        }
        let circuit = fixture::<F>(profile, modulus, TestMode::Mul, maximum, maximum);
        assert!(undetected_tampers(&circuit, 10, &[]).unwrap().is_empty());
    }
    // Small custom odd moduli remain valid for the original four-carry
    // multiplication; they must never enter the narrower product finish.
    let small = ForeignModulus::new([1, 0, 0, 1 << 60]).unwrap();
    assert!(satisfies(&fixture::<F>(
        profile,
        small,
        TestMode::Mul,
        maximum,
        maximum
    )));
    assert!(
        synthesize(
            &fixture::<F>(
                profile,
                small,
                TestMode::ProperNativeForgery,
                Nat::ONE,
                Nat::ONE
            ),
            10,
            Some(&[])
        )
        .is_err()
    );
}

#[test]
fn staged_proper_product_bounds_aliases_and_all_cells_both_fields() {
    proper_product::<Fp>(2);
    proper_product::<Fq>(2);
}

#[test]
fn serialized_proper_product_bounds_aliases_and_all_cells_both_fields() {
    proper_product::<Fp>(0);
    proper_product::<Fq>(0);
}
