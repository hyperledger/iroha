//! Polynomial commitments and openings (spec section 9).
//!
//! - [`ipa`]: commitments, the BGH19 inner-product argument (the prover
//!   returns the folded generator `G'_0`), succinct verification into a
//!   pending accumulator, and `decide`/`batch_decide`;
//! - [`multiopen`]: the halo2 multi-point opening with **static** query
//!   grouping (soundness invariants S1-S3): queries are grouped by the slot
//!   that names the polynomial, never by commitment value.

use iroha_pasta::PastaCurve;

use crate::cs::CurveV1;

pub mod ipa;
pub mod multiopen;

/// The descriptor curve of `C` (`None` only for a curve this crate does not
/// know, which the sealed `PastaCurve` trait excludes).
#[must_use]
pub fn curve_v1<C: PastaCurve>() -> Option<CurveV1> {
    match C::CURVE_ID {
        "pallas" => Some(CurveV1::Pallas),
        "vesta" => Some(CurveV1::Vesta),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Ep, Eq};

    use super::*;

    #[test]
    fn curve_ids_map_to_descriptor_curves() {
        assert_eq!(curve_v1::<Ep>(), Some(CurveV1::Pallas));
        assert_eq!(curve_v1::<Eq>(), Some(CurveV1::Vesta));
    }
}

#[cfg(test)]
mod refusal_tests;
