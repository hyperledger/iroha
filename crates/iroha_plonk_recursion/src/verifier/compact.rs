//! Explicit shared-column layout for the unchanged complete verifier program.
//!
//! The first implementation gives Poseidon, Glue/serialized FF and ECC
//! disjoint fixed spans. The single range bus has its own cursor. The spans
//! are circuit metadata, never inferred from secret witness values.

use super::*;
use iroha_plonk::cs::{Advice, Column, Expression, Fixed, Instance, Rotation};
use iroha_plonk_gadgets::range::secondary::{SecondaryPlan, SecondaryRangeConfig};
use iroha_plonk_gadgets::{RowCursor, cells::SharedRows, phase::PhaseColumns};

/// Fixed half-open phase intervals: Poseidon `[0,sponge)`, arithmetic
/// `[sponge,arithmetic)` and ECC `[arithmetic,curve)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactSpans {
    sponge: usize,
    arithmetic: usize,
    curve: usize,
}
impl CompactSpans {
    /// Validates ordered, nonempty spans. The synthesis domain independently
    /// enforces its actual usable-row limit; choosing k17 diagnostic spans
    /// does not authorize a production k change.
    ///
    /// # Errors
    /// Spans overlap, are empty, or leave no room for the 16-row public prefix.
    pub fn new(sponge: usize, arithmetic: usize, curve: usize) -> Result<Self, Error> {
        if sponge < 16 || arithmetic <= sponge || curve <= arithmetic {
            return Err(Error::Synthesis);
        }
        Ok(Self {
            sponge,
            arithmetic,
            curve,
        })
    }
    /// Exclusive phase ends, in Poseidon/arithmetic/ECC order.
    #[must_use]
    pub const fn ends(self) -> [usize; 3] {
        [self.sponge, self.arithmetic, self.curve]
    }
}
/// Actual next-row counters; arithmetic includes the serialized FF kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierUsage {
    /// Poseidon reserved rows from zero.
    pub sponge: usize,
    /// Absolute next Glue/FF row.
    pub arithmetic: usize,
    /// Absolute next ECC row.
    pub curve: usize,
    /// Absolute next single-bus row (16 prefix rows are reserved).
    pub range: usize,
}
/// Direct public gates and shared fixed prefix. Instance columns never enter
/// the permutation; all copied values use the existing arithmetic ports.
#[derive(Clone, Copy, Debug)]
pub struct CompactPublicConfig {
    ports: [Column<Advice>; 3],
    prefix: Column<Fixed>,
    public: [Column<Instance>; 3],
}
impl CompactPublicConfig {
    /// The homogeneous `[1,2,16]` public columns.
    #[must_use]
    pub const fn columns(&self) -> [Column<Instance>; 3] {
        self.public
    }
    /// Binds exactly 19 computed words to their fixed public rows.
    ///
    /// # Errors
    /// Wrong column lengths or layout errors.
    pub fn assign<F: iroha_pasta::PastaField>(
        &self,
        region: &mut Region<'_, F>,
        words: [&[Word<F>]; 3],
    ) -> Result<(), Error> {
        if words.iter().map(|v| v.len()).collect::<Vec<_>>() != [1, 2, 16] {
            return Err(Error::Synthesis);
        }
        for (port, words) in self.ports.into_iter().zip(words) {
            for (row, word) in words.iter().enumerate() {
                word.assigned().copy_advice(region, port, row)?;
            }
        }
        for row in 0..16 {
            region.assign_fixed(
                self.prefix,
                row,
                F::from(if row == 0 {
                    1
                } else if row == 1 {
                    2
                } else {
                    3
                }),
            )?;
        }
        Ok(())
    }
}
impl<C: PastaCurve> VerifierConfig<C> {
    /// Configures the same complete interpreter on 11 advice columns, one range
    /// lookup and 12 fixed columns, using explicit degree-nine phase gates.
    /// Returned direct public gates have the fixed Omega `[1,2,16]` schema.
    pub fn configure_compact(
        meta: &mut ConstraintSystem<C::Base>,
        spans: CompactSpans,
    ) -> (Self, CompactPublicConfig) {
        Self::configure_compact_on(meta, spans, false, None)
    }

    /// Configures the guarded secondary stream on the same shared ports.
    /// The fixed plan must originate from a complete structural synthesis;
    /// runtime reservations and exact event replay independently reject stale
    /// or conflicting metadata. This is an explicit candidate profile.
    ///
    /// # Errors
    /// Shared spans exceed the plan domain or lack the public-prefix gap.
    pub fn configure_compact_secondary(
        meta: &mut ConstraintSystem<C::Base>,
        spans: CompactSpans,
        plan: SecondaryPlan,
    ) -> Result<(Self, CompactPublicConfig), Error> {
        if spans.curve > plan.capacity() || spans.sponge <= 37 {
            return Err(Error::Synthesis);
        }
        Ok(Self::configure_compact_on(meta, spans, true, Some(plan)))
    }

    fn configure_compact_on(
        meta: &mut ConstraintSystem<C::Base>,
        spans: CompactSpans,
        secondary_component: bool,
        plan: Option<SecondaryPlan>,
    ) -> (Self, CompactPublicConfig) {
        meta.set_minimum_degree(9);
        let advice: [Column<Advice>; 11] = core::array::from_fn(|_| meta.advice_column());
        let phases = if secondary_component {
            PhaseColumns::allocate_with_idle_ecc(meta)
        } else {
            PhaseColumns::allocate(meta)
        };
        let glue = GlueConfig::configure_phased_without_constants(
            meta,
            [advice[0], advice[1], advice[2], advice[3]],
            phases,
        );
        let kernel = RotatedFfConfig::configure_staged_phased(
            meta,
            glue.advice(),
            [advice[4], advice[6], advice[7], advice[8], advice[9]],
            Arithmetic::<C>::modulus(),
            phases,
        );
        let range = RunningSumConfig::configure_tagged(meta, advice[10]);
        let secondary = if secondary_component {
            let config = SecondaryRangeConfig::configure(
                meta,
                advice[..10].try_into().expect("ten shared ports"),
                phases,
                range,
            )
            .expect("matching compact tagged range and phase ports");
            plan.map(|plan| Box::new((config, plan)))
        } else {
            None
        };
        let ecc = EccConfig::configure_phased(meta, core::array::from_fn(|i| advice[i]), phases);
        let duplex = DuplexConfig::configure_phased(
            meta,
            Pow5Columns {
                state: [advice[6], advice[7], advice[8]],
                aux: advice[3],
            },
            phases,
        );
        let (pattern, prefix) = range.compact_patterns().expect("compact range config");
        let ports = [advice[0], advice[1], advice[2]];
        let public = core::array::from_fn(|i| {
            let instance = meta.instance_column([1, 2, 16][i]);
            meta.create_gate("compact direct public", |cells| {
                let h = cells.query_fixed(prefix, Rotation::cur());
                let q = match i {
                    0 => {
                        h.clone()
                            * (h.clone() - Expression::Constant(C::Base::from(2)))
                            * (h - Expression::Constant(C::Base::from(3)))
                    }
                    1 => h.clone() * (h - Expression::Constant(C::Base::from(3))),
                    _ => h,
                };
                let active = cells.query_fixed(pattern, Rotation::cur());
                let q = (1..=range.compact_pattern_codes()).fold(q, |value, code| {
                    value * (active.clone() - Expression::Constant(C::Base::from(code)))
                });
                let value = cells.query_advice(ports[i], Rotation::cur());
                let expected = cells.query_instance(instance, Rotation::cur());
                vec![q * (value - expected)]
            });
            instance
        });
        (
            Self {
                glue,
                range,
                ff: ArithmeticLayout::Serialized {
                    spans,
                    kernel,
                    secondary,
                },
                ecc,
                ecc_start_row: spans.arithmetic,
                duplex,
            },
            CompactPublicConfig {
                ports,
                prefix,
                public,
            },
        )
    }
}
impl<C: PastaCurve> VerifierChip<C> {
    pub(super) fn new_compact(
        glue: GlueConfig,
        range: RunningSumConfig,
        ecc: &EccConfig<C>,
        duplex: DuplexConfig<C::Base>,
        spans: CompactSpans,
        kernel: &RotatedFfConfig,
        secondary: Option<(SecondaryRangeConfig, SecondaryPlan)>,
    ) -> Self {
        let arithmetic_rows = SharedRows::new(RowCursor::bounded(spans.sponge, spans.arithmetic));
        let range_rows = SharedRows::new(RowCursor::starting_at(16));
        let glue = GlueChip::with_shared_cursor(glue, &arithmetic_rows)
            .with_shared_constant_cache()
            .expect("bounded compact arithmetic lane");
        let mut range = RunningSumChip::with_shared_cursor(range, &range_rows);
        let has_secondary = secondary.is_some();
        if let Some((config, plan)) = secondary {
            range = range
                .with_secondary_plan(config, plan)
                .expect("matching fixed range plan");
        }
        let ff = FfChip::serialized(glue.clone(), range.clone(), &[Arithmetic::<C>::modulus()])
            .with_rotated_kernel(kernel)
            .expect("matching fixed modulus and ports");
        let ecc = EccChip::with_cursor(ecc, RowCursor::bounded(spans.arithmetic, spans.curve))
            .with_constant_source(glue.clone())
            .expect("same compact ports and bounded cursor");
        let mut duplex = DuplexChip::bounded(duplex, spans.sponge)
            .with_constant_source(glue.clone())
            .expect("same compact copy port and bounded cursor");
        if has_secondary {
            duplex.start_at(37).expect("fixed public prefix");
        }
        Self {
            glue,
            range,
            arithmetic: Arithmetic::new(ff),
            ecc,
            duplex: Some(duplex),
            scalar_splits: std::collections::BTreeMap::new(),
        }
    }
    /// Finishes the shared secondary range program, if selected.
    ///
    /// # Errors
    /// Stale event metadata, cell collisions, missing requests or duplicate finish.
    pub fn finish_compact(&self, region: &mut Region<'_, C::Base>) -> Result<(), Error> {
        self.range.finish_secondary(region)
    }

    /// Reports actual structural row use after a complete transcript.
    ///
    /// # Errors
    /// An in-progress verifier currently owns the duplex.
    pub fn usage(&self) -> Result<VerifierUsage, Error> {
        Ok(VerifierUsage {
            sponge: self
                .duplex
                .as_ref()
                .ok_or(Error::Synthesis)?
                .lane()
                .rows_used(),
            arithmetic: self.glue.next_row(),
            curve: self.ecc.next_row(),
            range: self.range.next_row(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_pasta::{Ep, Eq};
    use iroha_plonk::{
        Protocol,
        cs::{
            CircuitDescriptorV1, CircuitDescriptorV2, CurveV1, DescriptorConfig, DescriptorError,
            DescriptorRule, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV1,
            TranscriptV2,
        },
    };

    #[derive(Clone, Copy, Debug)]
    enum Trade {
        Base,
        ExistingPort,
        ExistingPortDegreeTen,
        SecondaryComponent,
        NewAdvice,
        NewState,
    }
    fn protocol<C: PastaCurve>(curve: CurveV1, trade: Trade) -> Result<Protocol, DescriptorError> {
        let mut meta = ConstraintSystem::<C::Base>::default();
        let (config, _) = VerifierConfig::<C>::configure_compact_on(
            &mut meta,
            CompactSpans {
                sponge: 16384,
                arithmetic: 32768,
                curve: 65530,
            },
            matches!(trade, Trade::SecondaryComponent),
            None,
        );
        match trade {
            Trade::Base | Trade::SecondaryComponent => {}
            Trade::ExistingPort | Trade::ExistingPortDegreeTen => {
                meta.enable_equality(config.ecc.advice()[5]);
                if matches!(trade, Trade::ExistingPortDegreeTen) {
                    meta.set_minimum_degree(10);
                }
            }
            Trade::NewAdvice | Trade::NewState => {
                let extra = meta.advice_column();
                let state = matches!(trade, Trade::NewState);
                if state {
                    meta.enable_equality(extra);
                }
                // Query-count experiment only, not a proposed range predicate.
                meta.create_gate("extra-column inventory", |cells| {
                    let current = cells.query_advice(extra, Rotation::cur());
                    vec![if state {
                        current - cells.query_advice(extra, Rotation::next())
                    } else {
                        current
                    }]
                });
            }
        }
        let selectors = vec![vec![false; 1 << 16]; meta.num_selectors()];
        let finalized = meta.finalize(&selectors, true).unwrap();
        let layout = CircuitDescriptorV1::from_constraint_system(
            &finalized,
            DescriptorConfig {
                curve,
                k: 16,
                transcript: TranscriptV1::Blake2bChallenge255,
                instance_mode: InstanceModeV1::Direct,
                proof_suffix: ProofSuffixV1::FoldedGenerator,
            },
        )?;
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
        Ok(Protocol::new(&descriptor).unwrap())
    }
    fn descriptor<C: PastaCurve>(curve: CurveV1) {
        let protocol = protocol::<C>(curve, Trade::Base).unwrap();
        assert_eq!(protocol.shape().num_advice, 11);
        assert_eq!(protocol.shape().num_fixed, 12);
        assert_eq!(protocol.shape().advice_queries, 25);
        assert_eq!(protocol.shape().permutation_columns, 5);
        assert_eq!(protocol.shape().degree, 9);
        assert_eq!(protocol.shape().lookups, 1);
        assert_eq!(protocol.proof_length() + 1088, 4768);
    }

    #[test]
    fn complete_compact_configuration_preserves_exact_transport_budget() {
        descriptor::<Ep>(CurveV1::Vesta);
        descriptor::<Eq>(CurveV1::Pallas);
    }

    #[test]
    fn compact_range_column_and_degree_trade_inventory() {
        for (trade, expected) in [
            (Trade::ExistingPort, 4800),
            (Trade::SecondaryComponent, 4800),
            (Trade::NewAdvice, 4832),
            (Trade::NewState, 4896),
        ] {
            let protocol = protocol::<Eq>(CurveV1::Pallas, trade).unwrap();
            eprintln!(
                "COMPACT_RANGE_TRADE {trade:?} shape={:?} transport={} predicate=false",
                protocol.shape(),
                protocol.proof_length() + 1088
            );
            assert_eq!(protocol.proof_length() + 1088, expected);
        }
        assert!(matches!(
            protocol::<Eq>(CurveV1::Pallas, Trade::ExistingPortDegreeTen),
            Err(DescriptorError::Invalid(DescriptorRule::Degree))
        ));
    }
}
