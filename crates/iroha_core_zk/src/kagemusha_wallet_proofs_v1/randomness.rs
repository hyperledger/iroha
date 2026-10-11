//! Fallible, bounded and cancellable uniform salt sampling for both Pasta fields.

use ff::PrimeField;
use iroha_pasta::CancellationToken;
use rand::rand_core::TryRngCore as _;

/// Sampling cannot turn an entropy/resource failure into an invalid-proof verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// The caller cancelled before a canonical salt was returned.
    Cancelled,
    /// OS entropy failed or the bounded rejection sampler exhausted its attempts.
    Unavailable,
}

/// Fill one candidate from the OS without panicking on entropy failure.
pub(crate) fn os_entropy(bytes: &mut [u8; 32]) -> Result<(), Error> {
    rand::rngs::OsRng
        .try_fill_bytes(bytes)
        .map_err(|_| Error::Unavailable)
}

/// Uniform canonical Pasta salt, including zero. Both Pasta moduli exceed 2^254;
/// clearing only bit 255 leaves uniform candidates, so 128 consecutive rejections
/// have probability below 2^-128 for a healthy source. No modular reduction is used.
pub(crate) fn sample<F: PrimeField<Repr = [u8; 32]>>(
    cancellation: Option<&CancellationToken>,
    mut fill: impl FnMut(&mut [u8; 32]) -> Result<(), Error>,
) -> Result<F, Error> {
    for _ in 0..128 {
        CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let mut salt = [0; 32];
        fill(&mut salt)?;
        CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        salt[31] &= 0x7f;
        if let Some(value) = Option::<F>::from(F::from_repr(salt)) {
            return Ok(value);
        }
    }
    Err(Error::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_pasta::{Fp, Fq};

    fn boundaries<F: PrimeField<Repr = [u8; 32]>>() {
        let cancellation = CancellationToken::new();
        let maximum = (-F::ONE).to_repr();
        let mut modulus = maximum;
        for byte in &mut modulus {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        assert!(bool::from(F::from_repr(modulus).is_none()));
        let mut inputs = [modulus, [0xff; 32], [0; 32]].into_iter();
        assert_eq!(
            sample::<F>(Some(&cancellation), |bytes| {
                *bytes = inputs.next().expect("bounded rejection sequence");
                Ok(())
            })
            .unwrap(),
            F::ZERO
        );
        assert!(inputs.next().is_none());
        assert_eq!(
            sample::<F>(None, |bytes| {
                *bytes = maximum;
                bytes[31] |= 0x80;
                Ok(())
            })
            .unwrap()
            .to_repr(),
            maximum
        );
    }

    fn unavailable<F: PrimeField<Repr = [u8; 32]>>() {
        let mut calls = 0;
        let exhausted = sample::<F>(None, |bytes| {
            calls += 1;
            *bytes = [0xff; 32];
            Ok(())
        });
        assert_eq!(calls, 128);
        assert_eq!(exhausted, Err(Error::Unavailable));
        calls = 0;
        let failed = sample::<F>(None, |_| {
            calls += 1;
            Err(Error::Unavailable)
        });
        assert_eq!(calls, 1);
        assert_eq!(failed, Err(Error::Unavailable));
    }

    fn cancellation<F: PrimeField<Repr = [u8; 32]>>() {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            sample::<F>(Some(&cancelled), |_| panic!("cancelled before entropy")),
            Err(Error::Cancelled)
        );
        let during = CancellationToken::new();
        assert_eq!(
            sample::<F>(Some(&during), |bytes| {
                *bytes = [0; 32];
                during.cancel();
                Ok(())
            }),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn fp_salt_boundaries_and_zero_are_canonical() {
        boundaries::<Fp>();
    }
    #[test]
    fn fq_salt_boundaries_and_zero_are_canonical() {
        boundaries::<Fq>();
    }
    #[test]
    fn fp_salt_exhaustion_and_entropy_failure_are_unavailable() {
        unavailable::<Fp>();
    }
    #[test]
    fn fq_salt_exhaustion_and_entropy_failure_are_unavailable() {
        unavailable::<Fq>();
    }
    #[test]
    fn fp_salt_cancels_before_and_during_entropy() {
        cancellation::<Fp>();
    }
    #[test]
    fn fq_salt_cancels_before_and_during_entropy() {
        cancellation::<Fq>();
    }
}
