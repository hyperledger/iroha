//! Upstream relation, original RNG/error order and physical-allocation controls.

use super::super::{
    implementation::BlsImpl, normal::NormalConfiguration, small::SmallConfiguration,
};
use super::*;
use crate::{KeyGenOption, test_allocations::without_allocations};
use w3f_bls::{SecretKey, SerializableToBytes as _};

fn key<C: BlsConfiguration>(seed: u8) -> super::super::implementation::ManagedSecretKey<C> {
    BlsImpl::<C>::try_keypair(KeyGenOption::UseSeed(vec![seed; 32]))
        .unwrap()
        .1
}

fn upstream_once<C: BlsConfiguration>(bytes: &[u8], message: &[u8]) -> Vec<u8> {
    let mut key = SecretKey::<C::Engine>::from_bytes(bytes).unwrap();
    key.sign_once(&w3f_bls::Message::new(
        super::super::implementation::MESSAGE_CONTEXT,
        message,
    ))
    .to_bytes()
}

fn deterministic_relation<C: BlsConfiguration>() {
    for seed in [1, 0x47, 0xfe] {
        let key = key::<C>(seed);
        for size in [0, 1, 32, 55, 64, 127, 1024, 4097] {
            let message: Vec<_> = (0..size)
                .map(|offset| u8::try_from(offset % 251).unwrap())
                .collect();
            let reference = upstream_once::<C>(key.as_bytes(), &message);
            let actual = without_allocations(|| sign_once::<C>(key.as_bytes(), &message)).unwrap();
            assert_eq!(actual.as_slice(), reference);
            let public = BlsImpl::<C>::derive_public_key(&key).unwrap().to_bytes();
            let orientation =
                super::super::uncached::Orientation::for_algorithm(C::ALGORITHM).unwrap();
            super::super::uncached::verify_facade(
                orientation,
                &public,
                actual.as_slice(),
                &message,
            )
            .unwrap();
            let mut changed = message.clone();
            changed.push(0x9c);
            assert!(
                super::super::uncached::verify_facade(
                    orientation,
                    &public,
                    actual.as_slice(),
                    &changed
                )
                .is_err()
            );
        }
    }
}

#[test]
fn fixed_signing_matches_upstream_normal_and_small_without_heap_backing() {
    deterministic_relation::<NormalConfiguration>();
    deterministic_relation::<SmallConfiguration>();
}

#[cfg(feature = "rand")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntropyFailure(u8);
#[cfg(feature = "rand")]
impl std::fmt::Display for EntropyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original entropy failure {}", self.0)
    }
}
#[cfg(feature = "rand")]
impl std::error::Error for EntropyFailure {}

#[cfg(feature = "rand")]
#[derive(Clone)]
struct Draw {
    fill: u8,
    failure: Option<EntropyFailure>,
    calls: usize,
    length: usize,
}
#[cfg(feature = "rand")]
impl rand_core::TryRngCore for Draw {
    type Error = EntropyFailure;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("signing draws one byte slice")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("signing draws one byte slice")
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.calls += 1;
        self.length = bytes.len();
        bytes.fill(self.fill);
        self.failure.map_or(Ok(()), Err)
    }
}
#[cfg(feature = "rand")]
impl rand_core::TryCryptoRng for Draw {}

#[cfg(feature = "rand")]
fn upstream_random<C: BlsConfiguration>(
    bytes: &[u8],
    message: &[u8],
    rng: &mut Draw,
) -> Result<Vec<u8>, Error> {
    use rand_core::TryRngCore as _;
    let mut key = SecretKey::<C::Engine>::from_bytes(bytes)
        .map_err(|error| Error::Signing(error.to_string()))?;
    let message = w3f_bls::Message::new(super::super::implementation::MESSAGE_CONTEXT, message);
    let mut seed = Zeroizing::new(vec![0; 32]);
    rng.try_fill_bytes(&mut seed).map_err(|error| {
        Error::Signing(
            Error::KeyGen(format!(
                "BLS OS RNG failed during signing key split: {error}"
            ))
            .to_string(),
        )
    })?;
    if seed.iter().all(|byte| *byte == 0) {
        return Err(Error::Signing(
            Error::KeyGen("BLS signing key split seed material must not be all zero".into())
                .to_string(),
        ));
    }
    Ok(key
        .sign(&message, crate::rng::rng_from_seed_slice(&seed))
        .to_bytes())
}

#[cfg(feature = "rand")]
fn randomized_relation<C: BlsConfiguration>() {
    let key = key::<C>(0x35);
    for fill in [1, 0x37, 0xff] {
        for message in [&b""[..], &b"contextual BLS signing"[..], &[0x5a; 3073][..]] {
            let mut original_rng = Draw {
                fill,
                failure: None,
                calls: 0,
                length: 0,
            };
            let mut fixed_rng = original_rng.clone();
            let original =
                upstream_random::<C>(key.as_bytes(), message, &mut original_rng).unwrap();
            let fixed = without_allocations(|| {
                sign_with_rng::<C, _>(key.as_bytes(), message, &mut fixed_rng)
            })
            .unwrap();
            assert_eq!(fixed.as_slice(), original);
            assert_eq!((fixed_rng.calls, fixed_rng.length), (1, 32));
            assert_eq!(
                (fixed_rng.calls, fixed_rng.length),
                (original_rng.calls, original_rng.length)
            );
        }
    }
    for failure in [None, Some(EntropyFailure(19))] {
        let mut original_rng = Draw {
            fill: 0,
            failure,
            calls: 0,
            length: 0,
        };
        let mut fixed_rng = original_rng.clone();
        let original = upstream_random::<C>(key.as_bytes(), b"original failure", &mut original_rng)
            .unwrap_err();
        let fixed = without_allocations(|| {
            sign_with_rng::<C, _>(key.as_bytes(), b"original failure", &mut fixed_rng)
        })
        .unwrap_err();
        match (&fixed, failure) {
            (BlsSigningError::ZeroEntropy, None) => {
                assert!(std::error::Error::source(&fixed).is_none());
            }
            (BlsSigningError::Entropy(error), Some(expected)) => {
                assert_eq!(*error, expected);
                assert_eq!(
                    std::error::Error::source(&fixed)
                        .and_then(|cause| cause.downcast_ref::<EntropyFailure>()),
                    Some(&expected)
                );
            }
            _ => panic!("the actual entropy cause must be preserved"),
        }
        assert_eq!(fixed.into_public_error(), original);
        assert_eq!(
            (fixed_rng.calls, fixed_rng.length),
            (original_rng.calls, original_rng.length)
        );
    }
    for bytes in [&[][..], &[0x11; 31][..], &[0xff; 32][..]] {
        let mut original_rng = Draw {
            fill: 7,
            failure: Some(EntropyFailure(29)),
            calls: 0,
            length: 0,
        };
        let mut fixed_rng = original_rng.clone();
        let original =
            upstream_random::<C>(bytes, b"invalid key before RNG", &mut original_rng).unwrap_err();
        let fixed = without_allocations(|| {
            sign_with_rng::<C, _>(bytes, b"invalid key before RNG", &mut fixed_rng)
        })
        .unwrap_err();
        assert!(matches!(&fixed, BlsSigningError::PrivateKey(_)));
        assert_eq!(fixed.into_public_error(), original);
        assert_eq!((fixed_rng.calls, original_rng.calls), (0, 0));
    }
}

#[cfg(feature = "rand")]
#[test]
fn fixed_signing_preserves_both_upstream_split_rng_and_original_failures() {
    randomized_relation::<NormalConfiguration>();
    randomized_relation::<SmallConfiguration>();
}

#[test]
fn fixed_signing_checked_scalar_parser_preserves_upstream_rejections() {
    for bytes in [&[][..], &[0x33; 31][..], &[0xff; 32][..]] {
        let original = match SecretKey::<w3f_bls::ZBLS>::from_bytes(bytes) {
            Err(error) => error,
            Ok(_) => panic!("malformed original scalar"),
        };
        let fixed =
            without_allocations(|| sign_once::<NormalConfiguration>(bytes, b"invalid scalar"))
                .unwrap_err();
        assert!(matches!(&fixed, BlsSigningError::PrivateKey(_)));
        assert_eq!(
            fixed.into_public_error(),
            Error::Signing(original.to_string())
        );
    }
}

fn scalar_boundaries<C: BlsConfiguration>() {
    let one = <C::Engine as w3f_bls::EngineBLS>::Scalar::from(1u64);
    let message = b"canonical scalar boundaries";
    for scalar in [
        <C::Engine as w3f_bls::EngineBLS>::Scalar::from(0u64),
        one,
        -one,
    ] {
        let mut bytes = Vec::new();
        scalar.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 32);
        let original = upstream_once::<C>(&bytes, message);
        let actual = without_allocations(|| sign_once::<C>(&bytes, message)).unwrap();
        assert_eq!(actual.as_slice(), original);

        // The retained key constructor still excludes all-zero secret material;
        // the internal scalar decoder itself must match upstream, including zero.
        if bytes.iter().all(|byte| *byte == 0) {
            assert!(
                super::super::implementation::ManagedSecretKey::<C>::from_bytes(&bytes).is_err()
            );
        } else {
            let managed =
                super::super::implementation::ManagedSecretKey::<C>::from_bytes(&bytes).unwrap();
            assert_eq!(managed.as_bytes(), bytes);
            let mut trailing = bytes.clone();
            trailing.extend_from_slice(&[0, 0xff, 0x79]);
            let original_trailing = upstream_once::<C>(&trailing, message);
            let actual_trailing =
                without_allocations(|| sign_once::<C>(&trailing, message)).unwrap();
            assert_eq!(actual_trailing.as_slice(), original_trailing);
            assert_eq!(actual_trailing.as_slice(), actual.as_slice());
            // Existing Ark scalar parsing consumes one scalar; the managed owner
            // canonicalizes it. Do not introduce a divergent parser in signing.
            let managed_trailing =
                super::super::implementation::ManagedSecretKey::<C>::from_bytes(&trailing).unwrap();
            assert_eq!(managed_trailing.as_bytes(), bytes);
        }

        #[cfg(feature = "rand")]
        {
            let mut original_rng = Draw {
                fill: 0x91,
                failure: None,
                calls: 0,
                length: 0,
            };
            let mut actual_rng = original_rng.clone();
            let original_random = upstream_random::<C>(&bytes, message, &mut original_rng).unwrap();
            let (actual_random, draws) = observe_entropy_draws(|| {
                without_allocations(|| sign_with_rng::<C, _>(&bytes, message, &mut actual_rng))
            });
            assert_eq!(actual_random.unwrap().as_slice(), original_random);
            assert_eq!(draws, 1);
            assert_eq!((actual_rng.calls, actual_rng.length), (1, 32));
            assert_eq!(
                (actual_rng.calls, actual_rng.length),
                (original_rng.calls, original_rng.length)
            );
        }
    }

    // Construct exactly q from the canonical (q-1) encoding without relying on
    // another scalar parser. The boundary must be rejected before any entropy.
    let mut modulus = Vec::new();
    (-one).serialize_compressed(&mut modulus).unwrap();
    for byte in &mut modulus {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    let original = match SecretKey::<C::Engine>::from_bytes(&modulus) {
        Err(error) => error,
        Ok(_) => panic!("the scalar modulus is not a canonical scalar"),
    };
    let actual = without_allocations(|| sign_once::<C>(&modulus, message)).unwrap_err();
    assert!(matches!(&actual, BlsSigningError::PrivateKey(_)));
    assert_eq!(
        actual.into_public_error(),
        Error::Signing(original.to_string())
    );
    #[cfg(feature = "rand")]
    {
        let mut rng = Draw {
            fill: 0x91,
            failure: Some(EntropyFailure(41)),
            calls: 0,
            length: 0,
        };
        let (actual, draws) = observe_entropy_draws(|| {
            without_allocations(|| sign_with_rng::<C, _>(&modulus, message, &mut rng))
        });
        assert!(matches!(actual, Err(BlsSigningError::PrivateKey(_))));
        assert_eq!((draws, rng.calls, rng.length), (0, 0, 0));
    }
}

#[test]
fn fixed_signing_preserves_scalar_boundaries_and_upstream_trailing_consumption() {
    scalar_boundaries::<NormalConfiguration>();
    scalar_boundaries::<SmallConfiguration>();
}

#[cfg(not(feature = "rand"))]
#[test]
fn fixed_signing_without_rand_matches_upstream_and_public_producer() {
    fn check<C: BlsConfiguration>() {
        let private = key::<C>(0x37);
        let message = b"deterministic no-rand BLS producer";
        let original = upstream_once::<C>(private.as_bytes(), message);
        let (fixed, draws) =
            observe_entropy_draws(|| without_allocations(|| private.try_sign_fixed(message)));
        assert_eq!(fixed.unwrap().as_slice(), original);
        assert_eq!(draws, 0);
        let (ordinary, draws) = observe_entropy_draws(|| BlsImpl::<C>::try_sign(message, &private));
        assert_eq!(ordinary.unwrap(), original);
        assert_eq!(draws, 0);
    }
    check::<NormalConfiguration>();
    check::<SmallConfiguration>();
}

#[test]
fn entropy_observation_retires_on_unwind_before_unchanged_signing_retry() {
    let private = key::<NormalConfiguration>(0x53);
    let message = b"entropy observer unwind";
    let expected = upstream_once::<NormalConfiguration>(private.as_bytes(), message);
    let result = std::panic::catch_unwind(|| {
        observe_entropy_draws(|| {
            private.try_sign_fixed(message).unwrap();
            panic!("intentional entropy observer unwind");
        });
    });
    assert!(result.is_err());
    let (retry, draws) =
        observe_entropy_draws(|| without_allocations(|| private.try_sign_fixed(message)));
    assert_eq!(retry.unwrap().as_slice(), expected);
    assert_eq!(draws, usize::from(cfg!(feature = "rand")));
}
