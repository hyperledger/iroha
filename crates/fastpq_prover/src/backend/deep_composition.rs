//! Checked OOD interpolation and exact-degree DEEP composition arithmetic.
//!
//! This owner combines 301 projected trace columns and two coefficient halves
//! of a degree-<2N quotient. It does not authenticate openings, sample challenges,
//! prove low degree, mask witnesses, or select a production transcript/profile.
//! Callers must bind both source roots before the OOD point and all OOD answers
//! before the composition challenge. The supplied trace root must come from the
//! caller's authenticated geometry; exact-order validation alone is not binding.
//!
//! The power-batched order is `(h_j, X^2 h_j)` for every projected column, then
//! `(t_0, X t_0, t_1, X t_1)`. Here `h_j` divides by the two OOD roots and `t_k`
//! divides by the first. The shifts enforce the distinct reconstructed degree
//! obligations; dropping them is not an equivalent composition.
//! The point evaluator is for bounded verifier queries. The honest producer must
//! form the combined coefficient polynomial, divide exactly and LDE that result,
//! rather than repeat this inversion and 606-term batch at every LDE point.
//! TODO: Integrate reviewed OOD/transcript, polynomial-opening and masking
//! ownership before this arithmetic participates in proof admission.

use super::polynomial_field::PolynomialField;
use crate::{Error, Result, field::GoldilocksFp4V1 as F};

/// Exact projected trace width for the proposed one-delta relation.
pub(super) const TRACE_COLUMNS: usize = super::compact_public_columns::COMMITTED_COLUMN_COUNT;
/// Number of components in the fixed power batch.
pub(super) const COMPONENTS: usize = 2 * TRACE_COLUMNS + 4;
const TRACE_ROWS: u64 = 65_536;

/// Canonical distinct extension points z and omega*z, with a shared inverse.
#[derive(Clone, Copy, Debug)]
pub(super) struct OodPair {
    points: [F; 2],
    inverse_span: F,
}

impl OodPair {
    /// Check z is outside the base field and omega has exact order 65,536.
    pub(super) fn new(z: F, trace_root: u64) -> Result<Self> {
        z.validate("deep_ood_point", &[])?;
        trace_root.validate("deep_trace_root", &[])?;
        if z.coefficients()[1..].iter().all(|&word| word == 0) {
            return Err(shape("DEEP OOD point must be outside the base field"));
        }
        if trace_root.power(TRACE_ROWS) != 1 || trace_root.power(TRACE_ROWS / 2) == 1 {
            return Err(shape("DEEP trace root must have exact order 65536"));
        }
        let next = z.mul_base(trace_root);
        let inverse_span = next
            .sub(z)
            .inverse()
            .ok_or_else(|| shape("DEEP OOD interpolation points must be distinct"))?;
        Ok(Self {
            points: [z, next],
            inverse_span,
        })
    }

    /// Return z followed by the authenticated trace-generator rotation omega*z.
    pub(super) fn points(self) -> [F; 2] {
        self.points
    }

    /// Interpolate two canonical answers without reducing extension coordinates.
    pub(super) fn interpolate(self, first: F, second: F) -> Result<OodInterpolation> {
        first.validate("deep_ood_interpolation", &[0])?;
        second.validate("deep_ood_interpolation", &[1])?;
        let slope = second.sub(first).mul(self.inverse_span);
        Ok(OodInterpolation {
            constant: first.sub(slope.mul(self.points[0])),
            slope,
        })
    }
}

/// The unique degree-<2 polynomial through one checked OOD answer pair.
#[derive(Clone, Copy, Debug)]
pub(super) struct OodInterpolation {
    constant: F,
    slope: F,
}

impl OodInterpolation {
    /// Evaluate the interpolation polynomial at a canonical field point.
    pub(super) fn value_at(self, point: F) -> Result<F> {
        point.validate("deep_interpolation_evaluation_point", &[])?;
        Ok(self.slope.mul(point).add(self.constant))
    }
}

/// Checked OOD answers prepared once for repeated bounded opening evaluations.
#[derive(Clone, Debug)]
pub(super) struct DeepComposition {
    points: OodPair,
    trace: Vec<OodInterpolation>,
    quotient_ood: [F; 2],
}

impl DeepComposition {
    /// Validate the complete fixed shape and all coordinates before allocation.
    pub(super) fn new(
        points: OodPair,
        trace_current: &[F],
        trace_next: &[F],
        quotient_ood: &[F],
    ) -> Result<Self> {
        if trace_current.len() != TRACE_COLUMNS
            || trace_next.len() != TRACE_COLUMNS
            || quotient_ood.len() != 2
        {
            return Err(shape(
                "DEEP OOD answers require two 301-column rows and two quotient halves",
            ));
        }
        for (row, values) in [trace_current, trace_next].into_iter().enumerate() {
            for (column, &value) in values.iter().enumerate() {
                value.validate("deep_ood_trace_answers", &[row, column])?;
            }
        }
        for (part, &value) in quotient_ood.iter().enumerate() {
            value.validate("deep_ood_quotient_answers", &[part])?;
        }
        let trace = trace_current
            .iter()
            .zip(trace_next)
            .map(|(&first, &second)| points.interpolate(first, second))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            points,
            trace,
            quotient_ood: [quotient_ood[0], quotient_ood[1]],
        })
    }

    /// Evaluate all 606 components from canonical extension-field values.
    ///
    /// This arithmetic also accepts non-LDE points for independent polynomial
    /// checks; the caller authenticates the query domain and source openings.
    #[cfg(test)]
    pub(super) fn value_at(&self, point: F, trace: &[F], quotient: &[F], lambda: F) -> Result<F> {
        if trace.len() != TRACE_COLUMNS || quotient.len() != 2 {
            return Err(shape(
                "DEEP evaluation requires 301 trace values and two quotient halves",
            ));
        }
        point.validate("deep_evaluation_point", &[])?;
        lambda.validate("deep_composition_challenge", &[])?;
        for (column, &value) in trace.iter().enumerate() {
            value.validate("deep_trace_opening", &[column])?;
        }
        for (part, &value) in quotient.iter().enumerate() {
            value.validate("deep_quotient_opening", &[part])?;
        }
        self.batch_at(
            point,
            trace.iter().copied(),
            [quotient[0], quotient[1]],
            lambda,
        )
    }

    /// Evaluate a base-field row without allocating or widening a row buffer.
    pub(super) fn base_value_at(
        &self,
        point: u64,
        trace: &[u64],
        quotient: &[F],
        lambda: F,
    ) -> Result<F> {
        if trace.len() != TRACE_COLUMNS || quotient.len() != 2 {
            return Err(shape(
                "DEEP evaluation requires 301 trace values and two quotient halves",
            ));
        }
        point.validate("deep_evaluation_point", &[])?;
        lambda.validate("deep_composition_challenge", &[])?;
        for (column, &value) in trace.iter().enumerate() {
            value.validate("deep_trace_opening", &[column])?;
        }
        for (part, &value) in quotient.iter().enumerate() {
            value.validate("deep_quotient_opening", &[part])?;
        }
        self.batch_at(
            F::embed_base(point),
            trace.iter().map(|&value| F::embed_base(value)),
            [quotient[0], quotient[1]],
            lambda,
        )
    }

    // Inputs are canonical and exact-width at both callers. One inverse serves
    // every trace and quotient term, and no component vector is allocated.
    fn batch_at(
        &self,
        point: F,
        trace: impl Iterator<Item = F>,
        quotient: [F; 2],
        lambda: F,
    ) -> Result<F> {
        let first_factor = point.sub(self.points.points[0]);
        let second_factor = point.sub(self.points.points[1]);
        let inverse_pair = first_factor
            .mul(second_factor)
            .inverse()
            .ok_or_else(|| shape("DEEP evaluation point coincides with an OOD point"))?;
        let inverse_first = second_factor.mul(inverse_pair);
        let squared_point = point.mul(point);
        let mut power = F::ONE;
        let mut result = F::ZERO;
        let mut absorb = |component: F| {
            result = result.add(power.mul(component));
            power = power.mul(lambda);
        };
        for (value, interpolation) in trace.zip(&self.trace) {
            let interpolated = interpolation.slope.mul(point).add(interpolation.constant);
            let h = value.sub(interpolated).mul(inverse_pair);
            absorb(h);
            absorb(squared_point.mul(h));
        }
        for (value, ood_value) in quotient.into_iter().zip(self.quotient_ood) {
            let t = value.sub(ood_value).mul(inverse_first);
            absorb(t);
            absorb(point.mul(t));
        }
        Ok(result)
    }
}

fn shape(details: &'static str) -> Error {
    Error::InvalidTraceShape {
        details: details.to_owned(),
    }
}

#[cfg(test)]
#[path = "deep_composition/tests.rs"]
mod tests;
