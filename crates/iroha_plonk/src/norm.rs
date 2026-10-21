//! Per-factor nonvanishing norm in the two admitted Pasta scalar fields.

/// Apply after tuple compression and affine challenge addition, before multiplying factors.
#[inline]
pub fn norm_factor<F: iroha_pasta::PastaField>(value: F) -> F {
    // The sealed Pasta fields both pin their generator to five. Use its
    // precomputed field representation instead of converting each factor.
    value.square() - F::MULTIPLICATIVE_GENERATOR
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    fn check<F: iroha_pasta::PastaField>() {
        assert_eq!(F::MULTIPLICATIVE_GENERATOR, F::from(5));
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

    fn check_full_width<F: iroha_pasta::PastaField>() {
        // Exercise every limb boundary, the top canonical bit and values near
        // the modulus. The oracle keeps the original multiplication/conversion.
        let mut power = F::ONE;
        for bit in 0..F::NUM_BITS {
            for value in [power - F::ONE, power, power + F::ONE, -power] {
                let actual = norm_factor(value);
                assert_eq!(actual, value * value - F::from(5), "bit {bit}");
                assert!(!bool::from(actual.is_zero()), "bit {bit}");
            }
            power = power.double();
        }
        // Include dense full-width values, beyond the boundary patterns above.
        let mut rng = ChaCha20Rng::from_seed([0x35; 32]);
        for index in 0..128 {
            let value = F::random(&mut rng);
            let actual = norm_factor(value);
            assert_eq!(actual, value * value - F::from(5), "sample {index}");
            assert!(!bool::from(actual.is_zero()), "sample {index}");
        }
    }

    #[test]
    fn norm_factors_match_full_width_oracle_in_both_admitted_fields() {
        check_full_width::<iroha_pasta::Fp>();
        check_full_width::<iroha_pasta::Fq>();
    }
}
