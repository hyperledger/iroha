//! Fallible independent canonical fold coins, bounded rejection and clearing owners.
#[cfg(test)]
use ff::PrimeField;
use iroha_pasta::{CancellationToken, PastaCurve, PastaField};
use iroha_plonk_recursion::FoldTape;
use rand::rand_core::TryRngCore as _;
use zeroize::Zeroizing;

/// Resource and cancellation errors are not a proof-invalid verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// The attempt's cancellation owner stopped the operation.
    Cancelled,
    /// The OS refused entropy or the bounded sampler exhausted its draws.
    Unavailable,
}
/// Obtain one OS candidate; no silent infallible RNG fallback.
pub(crate) fn os_entropy(bytes: &mut [u8; 32]) -> Result<(), Error> {
    rand::rngs::OsRng
        .try_fill_bytes(bytes)
        .map_err(|_| Error::Unavailable)
}
/// Sample into the caller-owned scalar. Zero remains an ordinary valid scalar.
///
/// Clearing bit255 makes each candidate uniform in [0,2^255). Both moduli exceed
/// 2^254; 134 rejected candidates cost less than2^-134 with healthy independent
/// OS bytes. Accepted values are not reduced, and no full tape is retried.
fn sample_into<F: PastaField>(
    destination: &mut F,
    cancellation: Option<&CancellationToken>,
    fill: &mut impl FnMut(&mut [u8; 32]) -> Result<(), Error>,
) -> Result<(), Error> {
    for _ in 0..134 {
        CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let mut candidate = Zeroizing::new([0; 32]);
        fill(&mut candidate)?;
        CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        candidate[31] &= 0x7f;
        if let Some(value) = Option::<F>::from(F::from_repr(*candidate)) {
            let guarded = Zeroizing::new(value);
            *destination = *guarded;
            return Ok(());
        }
    }
    Err(Error::Unavailable)
}
/// Create exactly one private33-coin tape. Failure wipes partial retained state.
///
/// The union bound for rejection exhaustion is below33*2^-134 <2^-128 per requested tape.
/// This statement assumes healthy independent OS bytes; tests cannot establish that
/// platform assumption. Checkpoint replay must restore retained bytes, never call this.
/// # Errors
/// Preserves cancellation and fallible entropy refusal; there is no retry-on-failure.
pub(crate) fn sample_tape<C: PastaCurve>(
    cancellation: Option<&CancellationToken>,
    mut fill: impl FnMut(&mut [u8; 32]) -> Result<(), Error>,
) -> Result<FoldTape<C>, Error> {
    FoldTape::try_fill(|coin| sample_into(coin, cancellation, &mut fill))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use iroha_pasta::{Ep, Eq};
    fn schedule<C: PastaCurve>() {
        let mut calls = 0;
        let tape = sample_tape::<C>(None, |bytes| {
            let n = calls;
            calls += 1;
            *bytes = if n == 0 {
                [255; 32]
            } else {
                C::ScalarExt::from(n as u64 - 1).to_repr()
            };
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 34);
        assert_eq!(*tape.rho(), C::ScalarExt::ZERO);
        for (position, coin) in tape.masks().iter().enumerate() {
            assert_eq!(*coin, C::ScalarExt::from(position as u64 + 1));
        }
        let mut maximum = (-C::ScalarExt::ONE).to_repr();
        maximum[31] |= 0x80;
        let tape = sample_tape::<C>(None, |bytes| {
            *bytes = maximum;
            Ok(())
        })
        .unwrap();
        assert_eq!(*tape.rho(), -C::ScalarExt::ONE);
        assert!(tape.masks().iter().all(|x| *x == -C::ScalarExt::ONE));
    }
    fn refusal<C: PastaCurve>() {
        for failure_position in 0..33 {
            let mut calls = 0;
            let result = sample_tape::<C>(None, |bytes| {
                let n = calls;
                calls += 1;
                *bytes = [0; 32];
                if n == failure_position {
                    Err(Error::Unavailable)
                } else {
                    Ok(())
                }
            });
            assert!(matches!(result, Err(Error::Unavailable)));
            assert_eq!(calls, failure_position + 1);
        }
        let mut calls = 0;
        let result = sample_tape::<C>(None, |bytes| {
            calls += 1;
            *bytes = [255; 32];
            Ok(())
        });
        assert!(matches!(result, Err(Error::Unavailable)));
        assert_eq!(calls, 134);
        let mut calls = 0;
        let result = sample_tape::<C>(None, |bytes| {
            calls += 1;
            *bytes = if calls <= 32 { [0; 32] } else { [255; 32] };
            Ok(())
        });
        assert!(matches!(result, Err(Error::Unavailable)));
        assert_eq!(calls, 32 + 134);
    }
    fn cancellation<C: PastaCurve>() {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            sample_tape::<C>(Some(&cancelled), |_| panic!("must not call entropy")),
            Err(Error::Cancelled)
        ));
        for position in 0..33 {
            let cancellation = CancellationToken::new();
            let mut calls = 0;
            let result = sample_tape::<C>(Some(&cancellation), |bytes| {
                let n = calls;
                calls += 1;
                *bytes = [0; 32];
                if n == position {
                    cancellation.cancel()
                };
                Ok(())
            });
            assert!(matches!(result, Err(Error::Cancelled)));
            assert_eq!(calls, position + 1);
        }
    }
    #[test]
    fn pallas_exact_independent_draw_schedule() {
        schedule::<Ep>();
    }
    #[test]
    fn vesta_exact_independent_draw_schedule() {
        schedule::<Eq>();
    }
    #[test]
    fn pallas_entropy_failure_and_exhaustion_keep_closed_outcome() {
        refusal::<Ep>();
    }
    #[test]
    fn vesta_entropy_failure_and_exhaustion_keep_closed_outcome() {
        refusal::<Eq>();
    }
    #[test]
    fn pallas_cancellation_at_every_coin_boundary() {
        cancellation::<Ep>();
    }
    #[test]
    fn vesta_cancellation_at_every_coin_boundary() {
        cancellation::<Eq>();
    }
}

#[cfg(test)]
mod scalar_tests {
    use super::*;
    use iroha_pasta::{Fp, Fq};

    fn sample<F: PastaField>(
        cancellation: Option<&CancellationToken>,
        mut fill: impl FnMut(&mut [u8; 32]) -> Result<(), Error>,
    ) -> Result<F, Error> {
        let mut value = Zeroizing::new(F::ZERO);
        sample_into(&mut *value, cancellation, &mut fill)?;
        Ok(*value)
    }

    fn boundaries<F: PastaField>() {
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

    fn unavailable<F: PastaField>() {
        let mut calls = 0;
        let exhausted = sample::<F>(None, |bytes| {
            calls += 1;
            *bytes = [0xff; 32];
            Ok(())
        });
        assert_eq!(calls, 134);
        assert_eq!(exhausted, Err(Error::Unavailable));
        calls = 0;
        let failed = sample::<F>(None, |_| {
            calls += 1;
            Err(Error::Unavailable)
        });
        assert_eq!(calls, 1);
        assert_eq!(failed, Err(Error::Unavailable));
    }

    fn cancellation<F: PastaField>() {
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
    fn fp_coin_boundaries_and_zero_are_canonical() {
        boundaries::<Fp>();
    }
    #[test]
    fn fq_coin_boundaries_and_zero_are_canonical() {
        boundaries::<Fq>();
    }
    #[test]
    fn fp_coin_exhaustion_and_entropy_failure_are_unavailable() {
        unavailable::<Fp>();
    }
    #[test]
    fn fq_coin_exhaustion_and_entropy_failure_are_unavailable() {
        unavailable::<Fq>();
    }
    #[test]
    fn fp_coin_cancels_before_and_during_entropy() {
        cancellation::<Fp>();
    }
    #[test]
    fn fq_coin_cancels_before_and_during_entropy() {
        cancellation::<Fq>();
    }
}
