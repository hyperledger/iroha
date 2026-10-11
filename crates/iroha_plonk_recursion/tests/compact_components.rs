//! Executable compact-lane feasibility prototype, not a recursive verifier.
//!
//! These are actual Glue, complete ECC, transcript and algebraic/running range
//! constraints on eleven shared advice columns. Public words use direct gates,
//! so their three instance columns do not enter the permutation. Six fixed
//! coefficient columns are shared with the Poseidon rounds. The actual FF
//! carry/native-residue kernel is serialized onto the same Glue and range
//! ports. The phase profile uses the same four-row CRT gate as the complete
//! interpreter. This component test does not qualify composed wrapper rows.

use core::marker::PhantomData;
use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, Fp, PastaCurve};
use iroha_plonk::{
    Protocol,
    check::{CheckMode, check_circuit},
    cs::{
        Advice, CircuitDescriptorV1, CircuitDescriptorV2, Column, ConstraintSystem, CurveV1,
        DescriptorConfig, Expression, Fixed, InstanceModeV1, InstanceType, ProofSuffixV1, Rotation,
        TranscriptV1, TranscriptV2,
    },
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, RowCursor,
    cells::SharedRows,
    ecc::{EccChip, EccConfig, ScalarLimbs},
    ff::{CanonicalS6, FfChip, rotated::RotatedFfConfig, serialized::SerializedFf},
    phase::PhaseColumns,
    poseidon::{Pow5Columns, RoundConstantColumns},
    pow5_fq::{DuplexChip, DuplexConfig},
    range::{
        LimbBits, RunningSumChip, RunningSumConfig, UintChip,
        algebraic15::{Algebraic15Chip, Algebraic15Config},
    },
    tamper::undetected_tampers,
};

#[derive(Clone)]
struct Prototype<C: PastaCurve> {
    degree: usize,
    shared: bool,
    phased: bool,
    range_bits: usize,
    known: bool,
    marker: PhantomData<C>,
}
#[derive(Clone)]
struct Config<C: PastaCurve> {
    glue: GlueConfig,
    range: RunningSumConfig,
    algebraic: Algebraic15Config,
    ecc: EccConfig<C>,
    duplex: DuplexConfig<C::Base>,
    public: [Column<Advice>; 3],
    public_pattern: Column<Fixed>,
    kernel: Option<RotatedFfConfig>,
}

impl<C: PastaCurve> Prototype<C> {
    fn witness<T>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
}
impl<C: PastaCurve> Circuit<C::Base> for Prototype<C> {
    type Config = Config<C>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = (usize, bool, bool, usize);
    fn params(&self) -> Self::Params {
        (self.degree, self.shared, self.phased, self.range_bits)
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
        Self::configure_with_params(meta, (7, true, false, 15))
    }
    fn configure_with_params(
        meta: &mut ConstraintSystem<C::Base>,
        (degree, shared, phased, range_bits): Self::Params,
    ) -> Self::Config {
        meta.set_minimum_degree(degree);
        let advice: [Column<Advice>; 11] = core::array::from_fn(|_| meta.advice_column());
        let constants = (!phased).then(|| meta.fixed_column());
        let phase_columns = phased.then(|| PhaseColumns::allocate(meta));
        let coefficients = phase_columns.map_or_else(
            || core::array::from_fn(|_| meta.fixed_column()),
            PhaseColumns::coefficients,
        );
        let ports = [advice[0], advice[1], advice[2], advice[3]];
        let glue = if let Some(phases) = phase_columns {
            GlueConfig::configure_phased_without_constants(meta, ports, phases)
        } else if shared {
            GlueConfig::configure_with_shared_coefficients(
                meta,
                ports,
                constants.unwrap(),
                coefficients,
            )
        } else {
            GlueConfig::configure(meta, ports, constants.unwrap())
        };
        let kernel = phase_columns.map(|phases| {
            RotatedFfConfig::configure_staged_phased(
                meta,
                ports,
                [advice[4], advice[6], advice[7], advice[8], advice[9]],
                CanonicalS6::<C::Base>::field_modulus::<C::ScalarExt>(),
                phases,
            )
        });
        let range = RunningSumConfig::configure_compact(
            meta,
            advice[10],
            LimbBits::new(range_bits).unwrap(),
        );
        let algebraic = if let Some(phases) = phase_columns {
            Algebraic15Config::configure_phased(meta, core::array::from_fn(|i| advice[i]), phases)
        } else {
            Algebraic15Config::configure(meta, core::array::from_fn(|i| advice[i]))
        };
        let ecc = if let Some(phases) = phase_columns {
            EccConfig::configure_phased(meta, core::array::from_fn(|i| advice[i]), phases)
        } else {
            EccConfig::configure(meta, core::array::from_fn(|i| advice[i]))
        };
        // ECC already queries state columns 6..8 at current/next; port 3 is
        // already equality-enabled. The public prefix occupies ports 0..2.
        let lane = Pow5Columns {
            state: [advice[6], advice[7], advice[8]],
            aux: advice[3],
        };
        let duplex = if let Some(phases) = phase_columns {
            DuplexConfig::configure_phased(meta, lane, phases)
        } else {
            DuplexConfig::configure(
                meta,
                lane,
                RoundConstantColumns::from_columns(coefficients),
                &[],
            )
        };
        let public = [advice[0], advice[1], advice[2]];
        let (range_pattern, factor) = range.compact_patterns().unwrap();
        let public_pattern = if phased { factor } else { meta.fixed_column() };
        for i in 0..3 {
            let instance = meta.instance_column([1, 2, 16][i]);
            meta.create_gate("direct compact public binding", |cells| {
                let h = cells.query_fixed(public_pattern, Rotation::cur());
                // Fixed h=1 on row0, h=2 on row1, h=3 on rows2..15;
                // h=0 elsewhere. Only nonzeroness of each enable is needed.
                let q = match i {
                    0 => {
                        h.clone()
                            * (h.clone() - Expression::Constant(C::Base::from(2)))
                            * (h - Expression::Constant(C::Base::from(3)))
                    }
                    1 => h.clone() * (h - Expression::Constant(C::Base::from(3))),
                    _ => h,
                };
                let q = if phased {
                    let range = cells.query_fixed(range_pattern, Rotation::cur());
                    q * (range.clone() - Expression::Constant(C::Base::ONE))
                        * (range - Expression::Constant(C::Base::from(2)))
                } else {
                    q
                };
                let value = cells.query_advice(public[i], Rotation::cur());
                let expected = cells.query_instance(instance, Rotation::cur());
                vec![("same public word", q * (value - expected))]
            });
        }
        Config {
            glue,
            range,
            algebraic,
            ecc,
            duplex,
            public,
            public_pattern,
            kernel,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<(), Error> {
        let mut range = RunningSumChip::with_shared_cursor(
            config.range,
            &SharedRows::new(RowCursor::starting_at(16)),
        );
        range.load_table(&mut layouter)?;
        layouter.assign_region(
            || "shared compact component schedule",
            |mut region| {
                let mut glue = GlueChip::with_shared_cursor(
                    config.glue,
                    &SharedRows::new(RowCursor::bounded(256, 512)),
                );
                let one = glue.constant(&mut region, C::Base::ONE)?;
                let x = glue.witness(&mut region, self.witness(C::Base::from(21845)))?;
                let zero = glue.is_zero(&mut region, &x)?;
                let chosen = glue.select(&mut region, &zero, &one, &x)?;
                GlueChip::assert_equal(&mut region, &chosen, &x)?;
                for (i, length) in [1, 2, 16].into_iter().enumerate() {
                    for row in 0..length {
                        one.assigned()
                            .copy_advice(&mut region, config.public[i], row)?;
                    }
                }
                for row in 0..16 {
                    region.assign_fixed(
                        config.public_pattern,
                        row,
                        C::Base::from(if row == 0 {
                            1
                        } else if row == 1 {
                            2
                        } else {
                            3
                        }),
                    )?;
                }
                let duplex = DuplexChip::new(config.duplex);
                let mut duplex = if self.phased {
                    duplex.with_constant_source(glue.clone())?
                } else {
                    duplex
                };
                duplex.absorb(&x);
                let first = duplex.squeeze(&mut region)?;
                duplex.absorb(&first);
                let last = duplex.squeeze_and_clear(&mut region)?;
                let mut native = iroha_pasta::poseidon::Sponge::<C::Base>::new();
                native.update(&[C::Base::from(21845)]);
                let first_native = native.squeeze();
                native.update(&[first_native]);
                glue.enforce_constant(&mut region, &last, native.squeeze())?;
                assert!(duplex.lane().rows_used() < 256);
                let (lo, hi) = {
                    let mut uint = UintChip::new(&mut glue, &mut range);
                    (
                        uint.assign::<128>(&mut region, self.witness(21845_u128))?,
                        uint.assign::<127>(&mut region, self.witness(0_u128))?,
                    )
                };
                let modulus = CanonicalS6::<C::Base>::field_modulus::<C::ScalarExt>();
                let a = SerializedFf::witness(
                    &mut range,
                    &mut region,
                    modulus,
                    self.witness([21845, 0, 0, 0]),
                )?;
                let b = SerializedFf::witness(
                    &mut range,
                    &mut region,
                    modulus,
                    self.witness([17, 0, 0, 0]),
                )?;
                let start_glue = glue.next_row();
                let start_range = range.next_row();
                let mut ff = config
                    .kernel
                    .map(|kernel| {
                        FfChip::serialized(glue.clone(), range.clone(), &[modulus])
                            .with_rotated_kernel(&kernel)
                    })
                    .transpose()?;
                let product = if let Some(ff) = &mut ff {
                    ff.mul(&mut region, &a, &b)?
                } else {
                    SerializedFf::mul(&mut glue, &mut range, &mut region, &a, &b)?
                };
                assert_eq!(
                    glue.next_row() - start_glue,
                    if self.phased { 4 } else { 19 }
                );
                assert_eq!(
                    range.next_row() - start_range,
                    if self.phased {
                        if self.range_bits == 15 { 60 } else { 123 }
                    } else if self.range_bits == 15 {
                        70
                    } else {
                        143
                    }
                );
                let recovered = if let Some(ff) = &mut ff {
                    ff.div(&mut region, &product, &b)?
                } else {
                    SerializedFf::div(&mut glue, &mut range, &mut region, &product, &b)?
                };
                let recovered =
                    SerializedFf::assert_canonical(&mut glue, &mut range, &mut region, &recovered)?;
                for (limb, value) in recovered.limbs().iter().zip([21845, 0, 0]) {
                    glue.enforce_constant(&mut region, limb, C::Base::from(value))?;
                }
                let zero_word = glue.constant(&mut region, C::Base::ZERO)?;
                let zero_bit = glue.is_zero(&mut region, &zero_word)?;
                let chosen_zero = glue.select(&mut region, &zero_bit, &one, &zero_word)?;
                GlueChip::assert_equal(&mut region, &chosen_zero, &one)?;
                for boolean in [true, false] {
                    let bit = glue.boolean(&mut region, self.witness(boolean))?;
                    glue.enforce_constant(
                        &mut region,
                        bit.word(),
                        C::Base::from(u64::from(boolean)),
                    )?;
                }
                if let Some(ff) = &mut ff {
                    // The shared ECC/CRT/Glue phase fixture exercises both
                    // the three-carry product and the stronger bounded dot.
                    let narrow_a = ff.assert_canonical(&mut region, &a)?;
                    let narrow_b = ff.assert_canonical(&mut region, &b)?;
                    let batch = ff.dot_proper(&mut region, &[(&narrow_a, &narrow_b); 8])?;
                    for (limb, value) in batch.limbs().iter().zip([21845 * 17 * 8, 0, 0]) {
                        glue.enforce_constant(&mut region, limb, C::Base::from(value))?;
                    }
                }
                let ecc = EccChip::<C>::starting_at(&config.ecc, 512);
                let mut ecc = if self.phased {
                    ecc.with_constant_source(glue.clone())?
                } else {
                    ecc
                };
                let fixed_point = ecc.constant_point(&mut region, &C::generator())?;
                let point = ecc.witness_non_identity(&mut region, self.witness(C::generator()))?;
                EccChip::<C>::assert_equal(&mut region, &fixed_point, point.point())?;
                let checked = ecc
                    .mul_non_identity(&mut region, &mut range, ScalarLimbs::new(&lo, &hi), &point)?
                    .0;
                let checked_guarded = ecc
                    .mul(
                        &mut region,
                        &mut range,
                        ScalarLimbs::new(&lo, &hi),
                        point.point(),
                    )?
                    .0;
                EccChip::<C>::assert_equal(&mut region, &checked, &checked_guarded)?;
                assert!(ecc.next_row() < 1024);
                let mut algebraic =
                    Algebraic15Chip::with_cursor(config.algebraic, RowCursor::bounded(1024, 1026));
                algebraic.range_check(&mut region, &x)?;
                assert_eq!(algebraic.next_row(), 1025);
                Ok(())
            },
        )
    }
}

fn exercise<C: PastaCurve>() {
    let instances = [
        vec![C::Base::ONE],
        vec![C::Base::ONE; 2],
        vec![C::Base::ONE; 16],
    ];
    for (degree, shared, phased) in [
        (7, false, false),
        (7, true, false),
        (8, true, false),
        (9, true, true),
    ] {
        let circuit = Prototype::<C> {
            degree,
            shared,
            phased,
            range_bits: 15,
            known: true,
            marker: PhantomData,
        };
        let report = check_circuit(&circuit, 16, &instances, CheckMode::Strict).unwrap();
        assert!(report.is_satisfied(), "{:?}", report.failures().first());
        let assigned = synthesize(&circuit, 16, Some(&instances)).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
        assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
        assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            assigned.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        let finalized = assigned
            .cs
            .finalize(assigned.tables.selectors(), true)
            .unwrap();
        let layout = CircuitDescriptorV1::from_constraint_system(
            &finalized,
            DescriptorConfig {
                curve: if C::Base::MODULUS == Fp::MODULUS {
                    CurveV1::Vesta
                } else {
                    CurveV1::Pallas
                },
                k: 16,
                transcript: TranscriptV1::Blake2bChallenge255,
                instance_mode: InstanceModeV1::Direct,
                proof_suffix: ProofSuffixV1::FoldedGenerator,
            },
        )
        .unwrap();
        let descriptor = CircuitDescriptorV2::from_layout(
            layout,
            TranscriptV2::KagemushaPoseidonRp57Base,
            vec![
                InstanceType::Bounded,
                InstanceType::Field,
                InstanceType::Bounded,
            ],
        )
        .unwrap();
        let protocol = Protocol::new(&descriptor).unwrap();
        println!(
            "COMPACT_COMPONENTS curve={} degree={degree} shared={shared} phased={phased} shape={:?} proof_bytes={} transport_bytes={} full_verifier=false ff_kernel=true",
            C::CURVE_ID,
            protocol.shape(),
            protocol.proof_length(),
            protocol.proof_length() + 1088
        );
        assert_eq!(protocol.shape().num_advice, 11);
        assert_eq!(protocol.shape().lookups, 1);
        assert_eq!(
            protocol.shape().permutation_columns,
            if phased { 5 } else { 6 }
        );
        if phased {
            assert_eq!(protocol.shape().degree, 9);
            assert_eq!(protocol.shape().num_fixed, 11);
            assert_eq!(protocol.shape().advice_queries, 26);
            assert_eq!(protocol.proof_length() + 1088, 4768);
            assert!(
                undetected_tampers(
                    &Prototype {
                        range_bits: 7,
                        ..circuit.clone()
                    },
                    11,
                    &instances
                )
                .unwrap()
                .is_empty()
            );
        }
        let mut changed = instances.clone();
        changed[2][15] += C::Base::ONE;
        assert!(
            !check_circuit(&circuit, 16, &changed, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
}

#[test]
fn shared_compact_components_have_one_lookup_and_exact_public_bindings() {
    exercise::<Ep>();
    exercise::<Eq>();
}

/// Constant assignment cannot silently attach an unbounded or foreign lane.
#[test]
fn compact_constant_sources_require_exact_shared_ports_and_bounds() {
    fn run<C: PastaCurve>() {
        let mut meta = ConstraintSystem::<C::Base>::default();
        let columns = core::array::from_fn::<_, 10, _>(|_| meta.advice_column());
        let phases = PhaseColumns::allocate(&mut meta);
        let ports = [columns[0], columns[1], columns[2], columns[3]];
        let glue = GlueConfig::configure_phased_without_constants(&mut meta, ports, phases);
        let ecc = EccConfig::<C>::configure_phased(&mut meta, columns, phases);
        let duplex = DuplexConfig::configure_phased(
            &mut meta,
            Pow5Columns {
                state: [columns[6], columns[7], columns[8]],
                aux: columns[3],
            },
            phases,
        );
        let valid =
            GlueChip::with_shared_cursor(glue, &SharedRows::new(RowCursor::bounded(256, 512)));
        assert!(
            EccChip::new(&ecc)
                .with_constant_source(valid.clone())
                .is_ok()
        );
        assert!(
            DuplexChip::new(duplex.clone())
                .with_constant_source(valid)
                .is_ok()
        );
        let unbounded =
            GlueChip::with_shared_cursor(glue, &SharedRows::new(RowCursor::starting_at(256)));
        let missing = GlueChip::new(glue);
        let other_ports = core::array::from_fn(|_| meta.advice_column());
        let foreign =
            GlueConfig::configure_phased_without_constants(&mut meta, other_ports, phases);
        let foreign =
            GlueChip::with_shared_cursor(foreign, &SharedRows::new(RowCursor::bounded(256, 512)));
        let constant = meta.fixed_column();
        let old = GlueConfig::configure_phased(&mut meta, ports, constant, phases);
        let old = GlueChip::with_shared_cursor(old, &SharedRows::new(RowCursor::bounded(256, 512)));
        for invalid in [unbounded, missing, foreign, old] {
            assert!(
                EccChip::new(&ecc)
                    .with_constant_source(invalid.clone())
                    .is_err()
            );
            assert!(
                DuplexChip::new(duplex.clone())
                    .with_constant_source(invalid)
                    .is_err()
            );
        }
    }
    run::<Ep>();
    run::<Eq>();
}
