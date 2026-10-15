//! Common opening-point refusal for both native transcript directions.
use ff::PrimeField;

use super::MultiopenError;

pub(super) fn validate_challenge<F: PrimeField>(
    k: u32,
    point: F,
    earlier: &[F],
) -> Result<(), MultiopenError> {
    if k > iroha_pasta::params::MAX_K || k > F::S {
        return Err(MultiopenError::UnsupportedDomain { k });
    }
    let mut power = point;
    for _ in 0..k {
        power = power.square();
    }
    if power == F::ONE || earlier.contains(&point) {
        return Err(MultiopenError::DegenerateChallenge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_pasta::{Fp, Fq};

    fn every_domain<F: PrimeField>() {
        for k in 0..=iroha_pasta::params::MAX_K.min(F::S) {
            let mut root = F::ROOT_OF_UNITY;
            for _ in k..F::S {
                root = root.square();
            }
            assert_eq!(
                validate_challenge(k, F::ONE, &[]),
                Err(MultiopenError::DegenerateChallenge)
            );
            assert_eq!(
                validate_challenge(k, root, &[]),
                Err(MultiopenError::DegenerateChallenge)
            );
            assert_eq!(validate_challenge(k, F::ZERO, &[F::ONE]), Ok(()));
            assert_eq!(
                validate_challenge(k, F::ZERO, &[F::ZERO]),
                Err(MultiopenError::DegenerateChallenge)
            );
            for earlier in [F::from(2), F::from(7), F::from(23)] {
                assert_eq!(
                    validate_challenge(k, earlier, &[earlier]),
                    Err(MultiopenError::DegenerateChallenge)
                );
            }
            // A generator of the full multiplicative group lies outside each
            // admitted power-of-two subgroup in both actual Pasta fields.
            assert_eq!(
                validate_challenge(k, F::MULTIPLICATIVE_GENERATOR, &[F::ONE]),
                Ok(())
            );
        }
        assert_eq!(
            validate_challenge(u32::MAX, F::ZERO, &[]),
            Err(MultiopenError::UnsupportedDomain { k: u32::MAX })
        );
    }

    #[test]
    fn fp_all_supported_subgroups_and_earlier_point_refusals() {
        every_domain::<Fp>();
    }

    #[test]
    fn fq_all_supported_subgroups_and_earlier_point_refusals() {
        every_domain::<Fq>();
    }
}
