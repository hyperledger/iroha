//! Per-factor nonvanishing norm in the two admitted Pasta scalar fields.

/// Apply after tuple compression and affine challenge addition, before multiplying factors.
pub(crate) fn norm_factor<F: ff::PrimeField>(value: F) -> F {
    value.square() - F::from(5)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn check<F: iroha_pasta::PastaField>() {
        assert!(bool::from(F::from(5).sqrt().is_none()), "five is nonsquare");
        for value in [F::ZERO, F::ONE, -F::ONE, F::from(5), F::from(73)] {
            assert_eq!(norm_factor(value), value * value - F::from(5));
            assert!(!bool::from(norm_factor(value).is_zero()));
        }
    }
    #[test]
    fn norm_factors_are_nonzero_in_both_admitted_fields() {
        check::<iroha_pasta::Fp>();
        check::<iroha_pasta::Fq>();
    }
}
