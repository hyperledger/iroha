//! Circuit shapes: [`SigmaShape`] (parameters and `k`), the fixed PIPA-R profile,
//! and the shape selector [`select_shape`].
//!
//! A shape *fits* when a key-generation synthesis at its `k` succeeds: every
//! lane block, glue row, range-check row, constant and the limb table lies in
//! the usable rows. Its proof length is exact: it comes from the descriptor
//! the keys would be generated for (spec section 7), so no proof is needed.
//!
//! The selector walks `k` upwards and, for each `k`, the lane count upwards,
//! with `(k - 1)`-bit range-check limbs (the M8 choice, the widest table the
//! domain holds). It returns the first shape that fits and meets the proof
//! byte budget: the smallest `k`, then the fewest lanes. Without a budget
//! that is the smallest `k` that fits.

use iroha_pasta::{PastaCurve, poseidon::PoseidonField};
use iroha_plonk::{
    Protocol,
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, CsError, DescriptorConfig, InstanceModeV1,
        InstanceType, ProofSuffixV1, TranscriptV1, TranscriptV2,
    },
    frontend::{Assembly, Error, SingleChipLayouter, configure, synthesize},
    pcs::curve_v1,
};

use crate::{
    SigmaError,
    circuit::{Inventory, MAX_LANES, RelationShape, SigmaCircuit, SigmaParams},
};

/// The proof-size gate of the split-lineage recommendation (3.5 KB, from
/// M7).
pub const PROOF_BYTES_GATE: usize = 3_500;

/// A complete circuit shape: the parameters and `k`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SigmaShape {
    /// The configuration parameters.
    pub params: SigmaParams,
    /// `log2` of the domain size.
    pub k: u32,
}

/// Whether a synthesis error means "the shape does not fit `k`".
fn is_fit_error(error: &Error) -> bool {
    match error {
        Error::NotEnoughRowsAvailable { .. } | Error::RowOutOfRange { .. } | Error::Table(_) => {
            true
        }
        Error::ConstraintSystem(error) => matches!(
            **error,
            CsError::NotEnoughRows { .. } | CsError::InstanceTooLong { .. }
        ),
        _ => false,
    }
}

impl SigmaShape {
    /// A shape.
    #[must_use]
    pub const fn new(params: SigmaParams, k: u32) -> Self {
        Self { params, k }
    }

    /// Lays the relation out in key-generation mode at `k` and returns its
    /// inventory.
    ///
    /// # Errors
    ///
    /// [`SigmaError::DoesNotFit`] when the relation does not fit `k`, and
    /// [`SigmaError::Synthesis`] for any other synthesis failure.
    pub fn inventory<F: PoseidonField>(&self) -> Result<Inventory, SigmaError> {
        let fit = |error: Error| {
            if is_fit_error(&error) {
                SigmaError::DoesNotFit { k: self.k }
            } else {
                SigmaError::Synthesis(error)
            }
        };
        let circuit = SigmaCircuit::<F>::keygen(self.params);
        let (cs, config) = configure(&circuit).map_err(fit)?;
        let mut assembly = Assembly::new(&cs, self.k, None).map_err(fit)?;
        let mut layouter = SingleChipLayouter::new(&mut assembly, cs.constants().to_vec());
        let output = circuit.lay_out(config, &mut layouter).map_err(fit)?;
        assembly.finish().map_err(fit)?;
        Ok(output.inventory)
    }

    /// The descriptor keys for this shape are generated against (selector
    /// compression on) with the PIPA-R transcript and one Bounded instance column.
    ///
    /// # Errors
    ///
    /// [`SigmaError`] when the shape does not fit or the descriptor is
    /// invalid.
    pub fn descriptor<C: PastaCurve>(&self) -> Result<CircuitDescriptorV2, SigmaError>
    where
        C::ScalarExt: PoseidonField,
    {
        let circuit = SigmaCircuit::<C::ScalarExt>::keygen(self.params);
        let synthesized = synthesize(&circuit, self.k, None).map_err(|error| {
            if is_fit_error(&error) {
                SigmaError::DoesNotFit { k: self.k }
            } else {
                SigmaError::Synthesis(error)
            }
        })?;
        let finalized = synthesized
            .cs
            .finalize(synthesized.tables.selectors(), true)
            .map_err(SigmaError::ConstraintSystem)?;
        let curve = curve_v1::<C>().ok_or(SigmaError::UnknownCurve)?;
        let layout = CircuitDescriptorV1::from_constraint_system(
            &finalized,
            DescriptorConfig {
                curve,
                k: self.k,
                transcript: TranscriptV1::Blake2bChallenge255,
                instance_mode: InstanceModeV1::Direct,
                proof_suffix: ProofSuffixV1::FoldedGenerator,
            },
        )
        .map_err(SigmaError::Descriptor)?;
        CircuitDescriptorV2::from_layout(
            layout,
            TranscriptV2::KagemushaPoseidonRp57Base,
            vec![InstanceType::Bounded],
        )
        .map_err(SigmaError::Descriptor)
    }

    /// The exact proof length in bytes.
    ///
    /// # Errors
    ///
    /// As [`Self::descriptor`], and [`SigmaError::Protocol`].
    pub fn proof_length<C: PastaCurve>(&self) -> Result<usize, SigmaError>
    where
        C::ScalarExt: PoseidonField,
    {
        let descriptor = self.descriptor::<C>()?;
        Ok(Protocol::new(&descriptor)
            .map_err(SigmaError::Protocol)?
            .proof_length())
    }
}

/// The range-check limb width the selector uses at `k`: `k - 1`, within
/// `1..=24`.
#[must_use]
pub fn limb_bits_for(k: u32) -> usize {
    usize::try_from(k.saturating_sub(1)).map_or(24, |bits| bits.clamp(1, 24))
}

/// The fixed one-lane monetary source admitted by the native wallet profile.
/// Quota-enabled Send uses k14; the other Send masks and both Receive selectors
/// use k12. Every source uses folded prefixes and `k - 1`-bit range limbs.
/// This selects a compiled recipe; it does not generate or qualify a key.
///
/// # Errors
/// Rejects an undefined control mask.
pub fn wallet_monetary_shape(
    relation: crate::witness::SigmaRelation,
) -> Result<SigmaShape, crate::circuit::ParamsError> {
    let k = if relation.enforces(crate::witness::CONTROL_QUOTAS) {
        14
    } else {
        12
    };
    let params = SigmaParams::new(
        RelationShape::new(relation, crate::circuit::PrefixMode::Folded),
        1,
        limb_bits_for(k),
    )?;
    Ok(SigmaShape::new(params, k))
}

/// What [`select_shape`] searches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapePolicy {
    /// The smallest `k` tried.
    pub min_k: u32,
    /// The largest `k` tried (the pinned parameters cover 6..=16).
    pub max_k: u32,
    /// The most Pow5 lanes tried.
    pub max_lanes: usize,
    /// The proof byte budget, if any.
    pub max_proof_bytes: Option<usize>,
}

impl Default for ShapePolicy {
    /// `k` in `9..=16`, up to [`MAX_LANES`] lanes, the [`PROOF_BYTES_GATE`]
    /// budget and the KAGEMUSHA step format.
    fn default() -> Self {
        Self {
            min_k: 9,
            max_k: 16,
            max_lanes: MAX_LANES,
            max_proof_bytes: Some(PROOF_BYTES_GATE),
        }
    }
}

impl ShapePolicy {
    /// The policy without a proof byte budget (the smallest `k` that fits).
    #[must_use]
    pub const fn smallest_k() -> Self {
        Self {
            min_k: 9,
            max_k: 16,
            max_lanes: MAX_LANES,
            max_proof_bytes: None,
        }
    }
}

/// A selected shape with its inventory and exact proof length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapeChoice {
    /// The shape.
    pub shape: SigmaShape,
    /// The rows it uses.
    pub inventory: Inventory,
    /// The exact proof length in bytes.
    pub proof_bytes: usize,
}

/// The first shape of `relation` under `policy`: the smallest `k`, then the
/// fewest lanes, that fits and meets the proof byte budget.
///
/// # Errors
///
/// [`SigmaError::NoShape`] when nothing in the policy's range qualifies, and
/// any other [`SigmaError`] from synthesis or the descriptor.
pub fn select_shape<C: PastaCurve>(
    relation: RelationShape,
    policy: &ShapePolicy,
) -> Result<ShapeChoice, SigmaError>
where
    C::ScalarExt: PoseidonField,
{
    for k in policy.min_k..=policy.max_k {
        for lanes in 1..=policy.max_lanes.min(MAX_LANES) {
            let params =
                SigmaParams::new(relation, lanes, limb_bits_for(k)).map_err(SigmaError::Params)?;
            let shape = SigmaShape::new(params, k);
            let inventory = match shape.inventory::<C::ScalarExt>() {
                Ok(inventory) => inventory,
                Err(SigmaError::DoesNotFit { .. }) => continue,
                Err(error) => return Err(error),
            };
            let proof_bytes = shape.proof_length::<C>()?;
            if policy
                .max_proof_bytes
                .is_none_or(|budget| proof_bytes <= budget)
            {
                return Ok(ShapeChoice {
                    shape,
                    inventory,
                    proof_bytes,
                });
            }
        }
    }
    Err(SigmaError::NoShape)
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Eq, Fp};

    use super::*;
    use crate::{circuit::PrefixMode, witness::SigmaRelation};

    #[test]
    fn wallet_recipe_covers_exactly_the_ten_monetary_selectors() {
        for relation in (0..8)
            .map(SigmaRelation::send)
            .chain((0..2).map(SigmaRelation::receive))
        {
            let shape = wallet_monetary_shape(relation).unwrap();
            assert_eq!(
                shape.k,
                if relation.enforces(crate::witness::CONTROL_QUOTAS) {
                    14
                } else {
                    12
                }
            );
            assert_eq!(shape.params.lanes(), 1);
            assert_eq!(shape.params.limb_bits(), limb_bits_for(shape.k));
            assert_eq!(
                shape.params.relation(),
                RelationShape::new(relation, PrefixMode::Folded)
            );
        }
        for relation in [
            SigmaRelation::send(8),
            SigmaRelation::receive(2),
            SigmaRelation::receive(7),
        ] {
            assert_eq!(
                wallet_monetary_shape(relation),
                Err(crate::circuit::ParamsError::Relation(relation))
            );
        }
    }

    #[test]
    fn limb_widths_follow_k() {
        assert_eq!(limb_bits_for(11), 10);
        assert_eq!(limb_bits_for(1), 1);
        assert_eq!(limb_bits_for(0), 1);
        assert_eq!(limb_bits_for(40), 24);
        assert_eq!(
            ShapePolicy::default().max_proof_bytes,
            Some(PROOF_BYTES_GATE)
        );
        assert_eq!(ShapePolicy::smallest_k().max_proof_bytes, None);
    }

    #[test]
    fn fit_errors_are_recognised() {
        assert!(is_fit_error(&Error::RowOutOfRange {
            row: 2_000,
            usable_rows: 1_000
        }));
        assert!(is_fit_error(&Error::NotEnoughRowsAvailable {
            current_k: 3
        }));
        assert!(!is_fit_error(&Error::Synthesis));
        assert!(is_fit_error(&Error::ConstraintSystem(Box::new(
            CsError::NotEnoughRows {
                k: 2,
                minimum_rows: 8
            }
        ))));
    }

    #[test]
    fn a_receive_needs_four_lanes_at_k10() {
        // 67 folded permutations (2,479 lane rows) and the glue rows do not
        // fit three lanes of 1,024 rows.
        let relation = RelationShape::new(SigmaRelation::RECEIVE, PrefixMode::Folded);
        for lanes in [1, 2, 3] {
            let params = SigmaParams::new(relation, lanes, 9).expect("params");
            assert_eq!(
                SigmaShape::new(params, 10).inventory::<Fp>(),
                Err(SigmaError::DoesNotFit { k: 10 }),
                "{lanes} lanes"
            );
        }
        let four = SigmaParams::new(relation, 4, 9).expect("params");
        let inventory = SigmaShape::new(four, 10).inventory::<Fp>().expect("fits");
        assert_eq!(inventory.permutations(), relation.permutations());
        assert!(inventory.rows() < 1 << 10);
        let bytes = SigmaShape::new(four, 10)
            .proof_length::<Eq>()
            .expect("length");
        assert!(bytes > 0 && bytes.is_multiple_of(32), "{bytes}");
    }
}
