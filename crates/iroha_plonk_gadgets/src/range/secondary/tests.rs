//! Exact mixed-radix bounds, shared-control cases and every-cell mutations.

use super::*;
use ff::Field;
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::Instance,
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};

#[derive(Clone)]
struct CircuitUnderTest<F: PastaField> {
    phase: SecondaryPhase,
    bits: usize,
    value: Value<F>,
    start: usize,
    end: usize,
    forced: bool,
    conflict: u8,
}
impl<F: PastaField> Circuit<F> for CircuitUnderTest<F> {
    type Config = (SecondaryRangeConfig, RunningSumConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let ports = core::array::from_fn(|_| meta.advice_column());
        let bus = meta.advice_column();
        let phases = PhaseColumns::allocate_with_idle_ecc(meta);
        let range = RunningSumConfig::configure_tagged(meta, bus);
        let secondary = SecondaryRangeConfig::configure(meta, ports, phases, range).unwrap();
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        (secondary, range, public)
    }
    fn synthesize(
        &self,
        (config, range, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        super::super::RunningSumChip::new(range).load_table(&mut layouter)?;
        let mut rows = RowCursor::bounded(self.start, self.end);
        let steps = self.bits.div_ceil(self.phase.radix_bits()) - 1;
        let forced = (0..steps)
            .map(|i| self.forced && i % 2 == 0)
            .collect::<Vec<_>>();
        let word = layouter.assign_region(
            || "secondary exact range",
            |mut region| {
                // Zero fixed columns are the explicit idle-ECC phase,
                // including unused and blinding rows.
                for row in self.start..=(self.start + steps + 1).min(self.end) {
                    assign_word(&mut region, range.column(), row, Value::known(F::ZERO))?;
                }
                if self.conflict == 1 {
                    assign_word(
                        &mut region,
                        config.ports[4],
                        self.start,
                        Value::known(F::ZERO),
                    )?;
                } else if self.conflict == 3 {
                    config
                        .phases
                        .enable(1, None)
                        .enable(&mut region, self.start)?;
                }
                let word = config.assign(
                    &mut region,
                    &mut rows,
                    self.phase,
                    self.bits,
                    self.value,
                    &forced,
                )?;
                if self.conflict == 2 {
                    assign_word(
                        &mut region,
                        config.ports[4],
                        self.start,
                        Value::known(F::ZERO),
                    )?;
                } else if self.conflict == 4 {
                    config
                        .phases
                        .enable(1, None)
                        .enable(&mut region, self.start)?;
                }
                Ok(word)
            },
        )?;
        layouter.constrain_instance(word.cell(), public, 0)
    }
}

fn cases<F: PastaField>() {
    let mut meta = ConstraintSystem::<F>::default();
    let _ = CircuitUnderTest::<F>::configure(&mut meta);
    assert_eq!(meta.degree(), 9);
    assert_eq!(meta.lookups().len(), 1);
    let end = meta.usable_rows(16).unwrap() - 1;
    for phase in [
        SecondaryPhase::Glue,
        SecondaryPhase::Poseidon,
        SecondaryPhase::PairedPoseidon,
    ] {
        for bits in [81, 87, 93, 128] {
            if bits == 93 && phase != SecondaryPhase::Glue {
                continue;
            }
            let limit = F::from(2).pow_vartime([bits as u64]);
            let honest = CircuitUnderTest {
                phase,
                bits,
                value: Value::known(limit - F::ONE),
                start: 8,
                end,
                forced: true,
                conflict: 0,
            };
            let public = [vec![limit - F::ONE]];
            let report = check_circuit(&honest, 16, &public, CheckMode::Strict).unwrap();
            assert!(
                report.is_satisfied(),
                "{phase:?}/{bits}: {:?}",
                report.failures().first()
            );
            let known = synthesize(&honest, 16, Some(&public)).unwrap();
            let unknown = synthesize(&honest.without_witnesses(), 16, None).unwrap();
            assert_eq!(known.tables.fixed(), unknown.tables.fixed());
            assert_eq!(known.tables.permutation(), unknown.tables.permutation());
            assert_eq!(
                known.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
            // The primary zero stream is an independent owner's fixture;
            // sweep every cell assigned by the secondary component itself.
            for (column, assigned) in known.tables.advice_assigned().iter().enumerate().take(10) {
                for (row, present) in assigned.iter().enumerate() {
                    if *present {
                        let report = crate::tamper::check_tampered(
                            &honest,
                            16,
                            &public,
                            Some(crate::tamper::Tamper {
                                column,
                                row,
                                delta: F::ONE,
                            }),
                        )
                        .unwrap();
                        assert!(
                            !report.is_satisfied(),
                            "unbound secondary cell {column}/{row}"
                        );
                    }
                }
            }
            for value in [limit, -F::ONE] {
                let bad = CircuitUnderTest {
                    value: Value::known(value),
                    ..honest.clone()
                };
                assert!(
                    !check_circuit(&bad, 16, &[vec![value]], CheckMode::Strict)
                        .unwrap()
                        .is_satisfied()
                );
            }
            let rows = bits.div_ceil(phase.radix_bits());
            let boundary = CircuitUnderTest {
                start: end - rows,
                ..honest.clone()
            };
            assert!(
                check_circuit(&boundary, 16, &public, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
            assert!(
                synthesize(
                    &CircuitUnderTest {
                        start: boundary.start + 1,
                        ..boundary
                    },
                    16,
                    Some(&public)
                )
                .is_err()
            );
            let at_zero = CircuitUnderTest {
                start: 0,
                ..honest.clone()
            };
            assert!(
                check_circuit(&at_zero, 16, &public, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
            let unsupported = CircuitUnderTest {
                bits: 86,
                ..honest.clone()
            };
            assert!(synthesize(&unsupported, 16, Some(&public)).is_err());
            let zero = CircuitUnderTest {
                value: Value::known(F::ZERO),
                forced: false,
                ..honest
            };
            assert!(
                check_circuit(&zero, 16, &[vec![F::ZERO]], CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
    }
}

#[test]
fn secondary_exact_bounds_all_cells_and_shape_fp() {
    cases::<Fp>();
}
#[test]
fn secondary_exact_bounds_all_cells_and_shape_fq() {
    cases::<Fq>();
}

#[test]
fn secondary_configuration_rejects_wrong_primary_or_overlapping_ports() {
    let mut meta = ConstraintSystem::<Fp>::default();
    let ports = core::array::from_fn(|_| meta.advice_column());
    let column = meta.advice_column();
    let phases = PhaseColumns::allocate_with_idle_ecc(&mut meta);
    let scalar = RunningSumConfig::configure_compact(&mut meta, column, LimbBits::new(15).unwrap());
    assert!(SecondaryRangeConfig::configure(&mut meta, ports, phases, scalar).is_err());
    let tagged = RunningSumConfig::configure_tagged(&mut meta, column);
    let old_encoding = PhaseColumns::allocate(&mut meta);
    assert!(SecondaryRangeConfig::configure(&mut meta, ports, old_encoding, tagged).is_err());
    let mut wrong = ports;
    wrong[9] = wrong[0];
    assert!(SecondaryRangeConfig::configure(&mut meta, wrong, phases, tagged).is_err());
    wrong = ports;
    wrong[9] = column;
    assert!(SecondaryRangeConfig::configure(&mut meta, wrong, phases, tagged).is_err());
}

fn native<C: iroha_pasta::PastaCurve>() {
    use iroha_plonk::{
        ProverConfig, ProverRandomness, Witness, create_proof_owned,
        cs::InstanceType,
        keys::{KeygenConfigV2, keygen_pk_v2},
        pcs::ipa::PinnedParams,
    };
    let value = C::ScalarExt::from(2).pow_vartime([128]) - C::ScalarExt::ONE;
    let circuit = CircuitUnderTest {
        phase: SecondaryPhase::PairedPoseidon,
        bits: 128,
        value: Value::known(value),
        start: 0,
        end: 65_529,
        forced: true,
        conflict: 0,
    };
    let public = [vec![value]];
    let params = PinnedParams::<C>::derive(16).unwrap();
    let key = keygen_pk_v2(
        &params,
        &circuit,
        &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
    )
    .unwrap();
    let proof = create_proof_owned(
        &params,
        &key,
        Witness::from_circuit(&key, &circuit, &public).unwrap(),
        ProverRandomness::os(),
        ProverConfig::default(),
    )
    .unwrap();
    iroha_plonk::verify_full(
        &params,
        key.binding(),
        key.vk(),
        &public,
        &proof,
        iroha_pasta::msm::MemoryBudget::DEFAULT,
    )
    .unwrap();
    assert!(
        iroha_plonk::verify_full(
            &params,
            key.binding(),
            key.vk(),
            &[vec![value + C::ScalarExt::ONE]],
            &proof,
            iroha_pasta::msm::MemoryBudget::DEFAULT
        )
        .is_err()
    );
}
#[test]
fn secondary_native_proof_binds_exact_range_both_curves() {
    native::<iroha_pasta::Ep>();
    native::<iroha_pasta::Eq>();
}

fn forged_glue_top<F: PastaField>() {
    for bits in [81_usize, 93] {
        let circuit = CircuitUnderTest {
            phase: SecondaryPhase::Glue,
            bits,
            value: Value::known(F::ZERO),
            start: 0,
            end: 65_529,
            forced: false,
            conflict: 0,
        };
        let limbs = bits.div_ceil(12);
        let mut tampers = (0..limbs)
            .map(|row| crate::tamper::Tamper {
                column: 4,
                row,
                delta: F::from(2).pow_vartime([(bits - 12 * row) as u64]),
            })
            .collect::<Vec<_>>();
        // Coordinate every running state and the forged high digit. Without
        // the dedicated one-bit top gate this is a satisfying82/94-bit alias,
        // even though the honest witness masks that digit to one bit.
        tampers.push(crate::tamper::Tamper {
            column: 7,
            row: limbs - 1,
            delta: F::from(2),
        });
        let report = crate::tamper::check_tampers(
            &circuit,
            16,
            &[vec![F::from(2).pow_vartime([bits as u64])]],
            &tampers,
        )
        .unwrap();
        assert!(!report.is_satisfied());
        assert!(
            report
                .failures()
                .iter()
                .any(|failure| format!("{failure:?}").contains("secondary exact small digits"))
        );
    }
}
#[test]
fn secondary_coordinated_top81_and_top93_overflow_both_fields() {
    forged_glue_top::<Fp>();
    forged_glue_top::<Fq>();
}

#[test]
fn secondary_guards_reject_earlier_and_later_advice_and_fixed_collisions() {
    for conflict in 1..=4 {
        let circuit = CircuitUnderTest::<Fp> {
            phase: SecondaryPhase::Glue,
            bits: 87,
            value: Value::known(Fp::ZERO),
            start: 0,
            end: 65_529,
            forced: false,
            conflict,
        };
        for known in [true, false] {
            let candidate = if known {
                circuit.clone()
            } else {
                circuit.without_witnesses()
            };
            let public = [vec![Fp::ZERO]];
            assert!(matches!(
                synthesize(&candidate, 16, known.then_some(public.as_slice())),
                Err(Error::LayoutConflict { .. })
            ));
        }
    }
}
