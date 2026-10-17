//! Additive checked construction helpers for future compiled execution adapters.
//!
//! The retained `RaceV1` profiles do not use this module and do not commit its source.
//! Existing `IntegerAirV1` interval metadata is not a range proof. These helpers emit
//! actual equations, but do not install arbitrary relations or qualify a new profile.

use super::integer_air::{IntegerAirV1, Value};

/// Conservative endpoint cap. A signed interval spans at most 2^46, leaving both
/// decomposition slack and every helper's host operation far below 2^50 and p.
const MAX_ENDPOINT: i64 = 1_i64 << 45;

/// A checked constructor rejected an interval before mutating the arithmetic graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum CheckedIntegerAirErrorV1 {
    /// Endpoints are reversed or outside the helper's conservative integer domain.
    #[error("checked AIR endpoints must be ordered and within +/-2^45")]
    Bounds,
}

/// A Boolean field value whose equation was emitted by a checked constructor.
///
/// Like the private raw `Value`, this token belongs to the graph that created it.
/// Checked selection emits its own Boolean equation as well; interval metadata or
/// a token from a different graph is never sufficient to omit that equation.
#[derive(Clone, Copy, Debug)]
pub(super) struct CheckedBooleanV1(Value);

impl CheckedBooleanV1 {
    /// Use the constrained Boolean as an ordinary operand in the same graph.
    pub(super) fn value(self) -> Value {
        self.0
    }
}

fn validate_bounds(low: i64, high: i64) -> Result<i64, CheckedIntegerAirErrorV1> {
    if low > high || low < -MAX_ENDPOINT || high > MAX_ENDPOINT {
        return Err(CheckedIntegerAirErrorV1::Bounds);
    }
    let width = i128::from(high) - i128::from(low);
    i64::try_from(width).map_err(|_| CheckedIntegerAirErrorV1::Bounds)
}

/// Introduce an input and constrain its exact signed integer interval.
///
/// Dividing `x-low` by one forces a nonnegative Boolean/radix-four decomposition,
/// rather than relying on its declared interval. The quotient has at most 47 bits.
/// The final comparison excludes power-of-two slack above `high-low`. Its offset
/// accommodates that *actual* decomposed quotient range, not only the metadata.
/// The represented intervals and all reconstruction sums are less than p, so no
/// second field representative can satisfy the signed bounds.
///
/// # Errors
/// Returns `Bounds` before adding any node for reversed or oversized endpoints.
pub(super) fn bounded_input_v1(
    air: &mut IntegerAirV1,
    low: i64,
    high: i64,
) -> Result<Value, CheckedIntegerAirErrorV1> {
    let width = validate_bounds(low, high)?;
    let value = air.input(low, high);
    let shifted = air.sub_constant(value, low);
    let (decomposed, _) = air.divmod_unsigned(shifted, 1);
    let inside = air.less(decomposed, Value::constant(width + 1));
    air.equate(inside, Value::constant(1));
    Ok(value)
}

fn enforce_boolean(air: &mut IntegerAirV1, value: Value) {
    // Normalizing metadata here does not assert Booleanity: the polynomial below
    // proves it. It also prevents untrusted broad metadata from overflowing host
    // interval multiplication while constructing this exact degree-two equation.
    let boolean = Value {
        low: 0,
        high: 1,
        ..value
    };
    let complement = air.not(boolean);
    let product = air.mul(boolean, complement);
    air.equate(product, Value::constant(0));
}

/// Introduce an input constrained to the exact field values zero or one.
pub(super) fn boolean_input_v1(air: &mut IntegerAirV1) -> CheckedBooleanV1 {
    let value = air.input(0, 1);
    constrain_boolean_v1(air, value)
}

/// Constrain an existing same-graph operand to zero or one, regardless of its
/// former interval metadata, and return a token usable by checked selection.
pub(super) fn constrain_boolean_v1(air: &mut IntegerAirV1, value: Value) -> CheckedBooleanV1 {
    enforce_boolean(air, value);
    CheckedBooleanV1(Value {
        low: 0,
        high: 1,
        ..value
    })
}

/// Select a branch while independently enforcing the selector's Boolean equation.
///
/// Branch integer ranges must already be established by checked inputs or the
/// adapter's verified arithmetic induction; this helper does not turn arbitrary
/// branch metadata into a range proof. Values must belong to this same graph.
///
/// # Errors
/// Returns `Bounds` before adding a node if branch metadata exceeds the checked
/// constructor domain. No caller-selected verifier or wire format is introduced.
pub(super) fn select_v1(
    air: &mut IntegerAirV1,
    condition: CheckedBooleanV1,
    yes: Value,
    no: Value,
) -> Result<Value, CheckedIntegerAirErrorV1> {
    validate_bounds(yes.low, yes.high)?;
    validate_bounds(no.low, no.high)?;
    enforce_boolean(air, condition.value());
    Ok(air.select(condition.value(), yes, no))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        execution_proofs::integer_air::{Source, field},
        privacy_engines::transparent_stark::GoldilocksFieldV1 as F,
    };

    fn accepts(air: &IntegerAirV1, input: i64) -> bool {
        let row = air
            .witness(&[input], &[])
            .into_iter()
            .map(field)
            .collect::<Vec<_>>();
        air.residues(&row, &row, &[])
            .iter()
            .all(|value| *value == F::ZERO)
    }

    /// Recompute all algebraic operations at an arbitrary field input. Quotients,
    /// remainders and digits are chosen from canonical nonnegative field residues.
    /// This constructs a complete adversarial assignment, without reusing the
    /// host selector branch that assumes an ordinary Boolean input.
    fn field_assignment(air: &IntegerAirV1, input: F) -> Vec<F> {
        let outputs = (0..air.width())
            .map(|index| Value {
                source: Source::Column(index),
                low: 0,
                high: 0,
            })
            .collect::<Vec<_>>();
        let (nodes, outputs) = air.export_graph(&outputs);
        fn read(value: &[i64], nodes: &[F], input: F) -> F {
            match value[0] {
                0 => field(value[1]),
                2 => nodes[value[1] as usize],
                3 => {
                    assert_eq!(value[1], 0);
                    input
                }
                _ => panic!("unexpected fixed operand in selector fixture"),
            }
        }
        let mut fields = Vec::new();
        for node in nodes {
            let operands = node[1..]
                .chunks_exact(2)
                .map(|operand| read(operand, &fields, input))
                .collect::<Vec<_>>();
            fields.push(match node[0] {
                0 => operands[0].add(operands[1]),
                1 => operands[0].sub(operands[1]),
                2 => operands[0].mul(operands[1]),
                3 => operands[2].add(operands[0].mul(operands[1].sub(operands[2]))),
                4 => F(operands[0].0 / operands[1].0),
                5 => F(operands[0].0 % operands[1].0),
                6 => F((operands[0].0 >> operands[1].0) & 1),
                7 => F((operands[0].0 >> operands[1].0) & 3),
                8 => F(u64::from(operands[0] == operands[1])),
                _ => panic!("unexpected graph opcode"),
            });
        }
        outputs
            .iter()
            .map(|operand| read(operand, &fields, input))
            .collect()
    }

    #[test]
    fn checked_signed_input_rejects_outside_both_bounds_and_singleton_aliases() {
        let mut air = IntegerAirV1::default();
        bounded_input_v1(&mut air, -10, 17).unwrap();
        for value in -40..=45 {
            assert_eq!(accepts(&air, value), (-10..=17).contains(&value), "{value}");
        }
        let mut singleton = IntegerAirV1::default();
        bounded_input_v1(&mut singleton, 7, 7).unwrap();
        assert!(accepts(&singleton, 7));
        assert!(!accepts(&singleton, 6));
        assert!(!accepts(&singleton, 8));
    }

    #[test]
    fn checked_input_construction_rejects_unsafe_bounds_without_mutating_graph() {
        let mut air = IntegerAirV1::default();
        for (low, high) in [
            (1, 0),
            (i64::MIN, 0),
            (0, i64::MAX),
            (-MAX_ENDPOINT - 1, 0),
            (0, MAX_ENDPOINT + 1),
        ] {
            assert!(matches!(
                bounded_input_v1(&mut air, low, high),
                Err(CheckedIntegerAirErrorV1::Bounds)
            ));
            assert_eq!(air.width(), 0);
        }
        bounded_input_v1(&mut air, -MAX_ENDPOINT, MAX_ENDPOINT).unwrap();
        assert!(accepts(&air, -MAX_ENDPOINT));
        assert!(accepts(&air, MAX_ENDPOINT));
        assert!(!accepts(&air, -MAX_ENDPOINT - 1));
        assert!(!accepts(&air, MAX_ENDPOINT + 1));
    }

    #[test]
    fn checked_range_rejects_large_field_residues_with_recomputed_auxiliaries() {
        let mut air = IntegerAirV1::default();
        bounded_input_v1(&mut air, -10, 17).unwrap();
        for input in [field(-10), field(-1), F::ZERO, field(17)] {
            let row = field_assignment(&air, input);
            assert!(
                air.residues(&row, &row, &[])
                    .iter()
                    .all(|value| *value == F::ZERO)
            );
        }
        for input in [field(-11), field(18), field(2).inv().unwrap()] {
            let row = field_assignment(&air, input);
            assert!(
                air.residues(&row, &row, &[])
                    .iter()
                    .any(|value| *value != F::ZERO)
            );
        }
    }

    #[test]
    fn checked_select_rejects_recomputed_fractional_witness_accepted_by_metadata_only_graph() {
        let half = field(2).inv().unwrap();
        let mut legacy = IntegerAirV1::default();
        let condition = legacy.input(0, 1);
        let output = legacy.select(condition, Value::constant(2), Value::constant(0));
        let row = field_assignment(&legacy, half);
        let Source::Column(index) = output.source else {
            panic!("output column")
        };
        assert_eq!(row[index], F::ONE);
        assert!(
            legacy
                .residues(&row, &row, &[])
                .iter()
                .all(|value| *value == F::ZERO)
        );

        let mut checked = IntegerAirV1::default();
        let condition = boolean_input_v1(&mut checked);
        select_v1(
            &mut checked,
            condition,
            Value::constant(2),
            Value::constant(0),
        )
        .unwrap();
        for input in [F::ZERO, F::ONE] {
            let row = field_assignment(&checked, input);
            assert!(
                checked
                    .residues(&row, &row, &[])
                    .iter()
                    .all(|value| *value == F::ZERO)
            );
        }
        for input in [half, field(-1), field(2)] {
            let row = field_assignment(&checked, input);
            assert!(
                checked
                    .residues(&row, &row, &[])
                    .iter()
                    .any(|value| *value != F::ZERO)
            );
        }
    }
}
