//! Original initialized backing, canonical parity and refusal retirement controls.

use std::alloc::Layout;

use iroha_allocation::{ChargedBufferFromChargeError, release::ReleaseRegistration};
use norito::core::{DecodeFlagsGuard, DecodeFromSlice, DecodeLimits, header_flags};

use super::*;
use crate::{Algorithm, KeyPair, Signature, test_allocations::*};

fn charge(pool: &AllocationBudget, bytes: usize) -> AllocationCharge {
    let layout = Layout::array::<u8>(bytes).unwrap();
    pool.try_reserve(layout).unwrap().try_split(layout).unwrap()
}
fn signature(pool: &AllocationBudget, bytes: usize) -> PreparedSignatureDecode {
    PreparedSignatureDecode::try_from_charge(bytes, pool, charge(pool, bytes))
        .unwrap_or_else(|(_, error)| panic!("{error}"))
}
fn public_key(pool: &AllocationBudget, bytes: usize) -> PreparedPublicKeyDecode {
    PreparedPublicKeyDecode::try_from_charge(bytes, pool, charge(pool, bytes))
        .unwrap_or_else(|(_, error)| panic!("{error}"))
}
fn encode(value: &impl SerializePayload) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut Encoder::for_buffer(&mut bytes))
        .unwrap();
    bytes
}

#[test]
fn prepared_signature_decodes_and_seals_exact_original_backing_without_allocation() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        for len in [48, 64, 96] {
            let value = Signature::from_bytes(&vec![0x53; len]);
            let bytes = encode(&value);
            let pool = AllocationBudget::new(len);
            let mut destination = signature(&pool, len);
            let pointer = destination.0.bytes.as_slice().as_ptr();
            pool.set_limit_bytes(0);
            without_allocations(|| destination.decode_payload(&bytes)).unwrap();
            assert!(destination.belongs_to(&pool));
            assert_eq!(destination.decoded_payload(), Some(value.payload()));
            let mut encoded = Vec::with_capacity(bytes.len());
            without_allocations(|| destination.serialize(&mut Encoder::for_buffer(&mut encoded)))
                .unwrap();
            assert_eq!(encoded, bytes);
            let bound = without_allocations(|| destination.finish())
                .unwrap_or_else(|_| panic!("complete leaf must seal"));
            assert_eq!(bound.get(), &value);
            assert_eq!(bound.get().payload().as_ptr(), pointer);
            assert!(bound.belongs_to(&pool));
            assert_eq!(pool.reserved_bytes(), len);
            let ((), frees) = with_deallocation_observation(len, || drop(bound));
            assert_eq!(frees, 1);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn prepared_public_key_matches_canonical_validator_and_exact_owned_bytes() {
    let algorithms = [Algorithm::Ed25519, Algorithm::Secp256k1].into_iter();
    #[cfg(feature = "bls")]
    let algorithms = algorithms.chain([Algorithm::BlsNormal, Algorithm::BlsSmall]);
    for algorithm in algorithms {
        let pair = KeyPair::from_seed(vec![0x59; 32], algorithm);
        let key = pair.public_key();
        let len = key.retained_allocation_layout().size();
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            let bytes = encode(key);
            let pool = AllocationBudget::new(len);
            let mut destination = public_key(&pool, len);
            let pointer = destination.0.bytes.as_slice().as_ptr();
            pool.set_limit_bytes(0);
            without_allocations(|| destination.decode_payload(&bytes)).unwrap();
            assert!(destination.belongs_to(&pool));
            assert_eq!(
                destination.decoded_compact(),
                Some(key.0.algorithm_and_payload.as_ref())
            );
            let mut encoded = Vec::with_capacity(bytes.len());
            without_allocations(|| destination.serialize(&mut Encoder::for_buffer(&mut encoded)))
                .unwrap();
            assert_eq!(encoded, bytes);
            let bound = without_allocations(|| destination.finish())
                .unwrap_or_else(|_| panic!("validated key must seal"));
            assert_eq!(bound.get(), key);
            assert_eq!(bound.get().0.algorithm_and_payload.as_ptr(), pointer);
            assert_eq!(pool.reserved_bytes(), len);
            drop(bound);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn prepared_key_retains_canonical_late_allocation_limit_and_original_retry_backing() {
    let pair = KeyPair::from_seed(vec![0x61; 32], Algorithm::Ed25519);
    let key = pair.public_key();
    let len = key.retained_allocation_layout().size();
    let pool = AllocationBudget::new(len);
    let mut destination = public_key(&pool, len);
    let pointer = destination.0.bytes.as_slice().as_ptr();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let bytes = encode(key);
        // The shared parser charges the sequence count and every declared
        // one-byte element payload, then the validated compact owner charges
        // its retained storage. All three costs survive prepaid backing.
        let required = 3 * len;
        for allowed in [len, 2 * len - 1, 2 * len, required - 1] {
            without_allocations(|| destination.decode_payload(&bytes)).unwrap();
            let limits = DecodeLimits::new(1024, 4096, 1024, allowed, 32);
            let protocol = DecodeLimits::new(1024, 4096, 1024, required, 32);
            // The observer must see the new protocol scope inside the attempt;
            // the stricter caller scope remains outside it. A bare leaf alone
            // cannot authenticate a fresh decode-budget family.
            let ordinary = norito::core::with_decode_limits_scope(limits, || {
                norito::core::classify_decode_attempt(|| {
                    norito::core::with_decode_limits_scope(protocol, || {
                        PublicKey::decode_from_slice(&bytes)
                    })
                })
            })
            .unwrap_err();
            let prepared = norito::core::with_decode_limits_scope(limits, || {
                norito::core::classify_decode_attempt(|| {
                    norito::core::with_decode_limits_scope(protocol, || {
                        match destination.decode_payload(&bytes) {
                            Err(PreparedCryptoDecodeError::Codec(error)) => Err::<(), _>(error),
                            result => {
                                panic!("canonical retained-key charge must refuse: {result:?}")
                            }
                        }
                    })
                })
            })
            .unwrap_err();
            // Both enclosing scopes have ended before inspecting their original
            // resource classification; no error is reconstructed from numbers.
            assert_eq!(
                ordinary.kind(),
                norito::core::DecodeAttemptErrorKind::EnclosingLimit
            );
            assert_eq!(prepared.kind(), ordinary.kind());
            assert_eq!(prepared.to_string(), ordinary.to_string());
            assert_eq!(
                prepared.into_error().decode_resource_error(),
                ordinary.into_error().decode_resource_error()
            );
            assert!(destination.decoded_compact().is_none());
            assert_eq!(destination.0.bytes.as_slice().as_ptr(), pointer);
            assert_eq!(pool.reserved_bytes(), len);
        }
        let exact = DecodeLimits::new(1024, 4096, 1024, required, 32);
        let (ordinary, ordinary_usage) = norito::core::with_decode_limits_measured(exact, || {
            PublicKey::decode_from_slice(&bytes)
        });
        let (ordinary, used) = ordinary.unwrap();
        assert_eq!(ordinary, *key);
        assert_eq!(used, bytes.len());
        let (prepared, prepared_usage) =
            norito::core::with_decode_limits_measured(exact, || destination.decode_payload(&bytes));
        prepared.unwrap();
        assert_eq!(ordinary_usage.total_allocated_bytes(), required);
        assert_eq!(prepared_usage, ordinary_usage);
        assert_eq!(destination.decoded_compact().unwrap().as_ptr(), pointer);
        assert_eq!(
            destination.decoded_compact(),
            Some(key.0.algorithm_and_payload.as_ref())
        );
    }
    pool.set_limit_bytes(0);
    let bound = without_allocations(|| destination.finish())
        .unwrap_or_else(|_| panic!("exact retry must seal"));
    assert_eq!(bound.get(), key);
    assert_eq!(bound.get().0.algorithm_and_payload.as_ptr(), pointer);
    drop(bound);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn malformed_signature_attempts_clear_validity_and_reuse_original_allocation() {
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let valid = encode(&Signature::from_bytes(&[0x75; 64]));
        let zero = encode(&Signature::from_bytes(&[0; 64]));
        let pool = AllocationBudget::new(64);
        let mut destination = signature(&pool, 64);
        let pointer = destination.0.bytes.as_slice().as_ptr();
        without_allocations(|| destination.decode_payload(&valid)).unwrap();
        assert!(matches!(
            without_allocations(|| destination.decode_payload(&zero)),
            Err(PreparedCryptoDecodeError::Signature(
                SignaturePayloadError::AllZero
            ))
        ));
        assert!(destination.decoded_payload().is_none());
        destination = destination
            .finish()
            .err()
            .expect("invalid leaf retains owner");
        for length in 0..valid.len() {
            let prepared = without_allocations(|| destination.decode_payload(&valid[..length]));
            let ordinary = Signature::decode_from_slice(&valid[..length]);
            let Err(PreparedCryptoDecodeError::Codec(prepared)) = prepared else {
                panic!("truncation must be canonical framing error")
            };
            assert_eq!(prepared.to_string(), ordinary.unwrap_err().to_string());
            assert!(destination.decoded_payload().is_none());
            assert_eq!(destination.0.bytes.as_slice().as_ptr(), pointer);
            assert_eq!(pool.reserved_bytes(), 64);
        }
        without_allocations(|| destination.decode_payload(&valid)).unwrap();
        without_allocations(|| destination.reset());
        assert!(destination.finish().is_err());
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let pool = AllocationBudget::new(0);
    let mut empty = signature(&pool, 0);
    let bytes = encode(&Signature::from_bytes(&[]));
    assert!(matches!(
        without_allocations(|| empty.decode_payload(&bytes)),
        Err(PreparedCryptoDecodeError::Signature(
            SignaturePayloadError::Empty
        ))
    ));
}

#[test]
fn key_invalid_point_tag_trailing_and_truncation_keep_canonical_error_precedence() {
    let pair = KeyPair::from_seed(vec![0x62; 32], Algorithm::Ed25519);
    let key = pair.public_key();
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let valid = encode(key);
        let pool = AllocationBudget::new(33);
        let mut destination = public_key(&pool, 33);
        let mut malformed = vec![vec![0; 8]];
        let mut invalid_tag = key.0.algorithm_and_payload.to_vec();
        invalid_tag[0] = 0xff;
        let mut invalid_point = invalid_tag.clone();
        invalid_point[0] = PublicKeyCompact::algorithm_tag(Algorithm::Ed25519);
        invalid_point[1..].fill(0);
        for compact in [invalid_tag, invalid_point] {
            let mut encoded = Vec::new();
            norito::core::write_element_sequence::<u8, _>(
                &mut Encoder::for_buffer(&mut encoded),
                compact.iter(),
            )
            .unwrap();
            malformed.push(encoded);
        }
        malformed.extend((0..valid.len()).map(|length| valid[..length].to_vec()));
        let mut trailing = valid.clone();
        trailing.push(0x73);
        malformed.push(trailing);
        for bytes in malformed {
            let prepared = without_allocations(|| destination.decode_payload(&bytes));
            let ordinary =
                public_key_decode::with_decoded_compact(&bytes, true, |_, _| Ok::<_, Error>(()));
            let Err(PreparedCryptoDecodeError::Codec(prepared)) = prepared else {
                panic!("same canonical key relation must reject malformed input")
            };
            assert_eq!(prepared.to_string(), ordinary.unwrap_err().to_string());
            assert!(destination.decoded_compact().is_none());
        }
        without_allocations(|| destination.decode_payload(&valid)).unwrap();
        destination.reset();
        assert!(destination.finish().is_err());
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn geometry_and_original_scope_refusal_preserve_initialized_storage_for_retry() {
    let bytes = encode(&Signature::from_bytes(&[0x41; 64]));
    let pool = AllocationBudget::new(129);
    let mut wrong = signature(&pool, 65);
    assert!(matches!(
        without_allocations(|| wrong.decode_payload(&bytes)),
        Err(PreparedCryptoDecodeError::Geometry {
            expected: 65,
            offered: 64
        })
    ));
    assert!(wrong.decoded_payload().is_none());
    let mut destination = signature(&pool, 64);
    let pointer = destination.0.bytes.as_slice().as_ptr();
    let error = norito::core::with_decode_limits_scope(
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || {
            norito::core::classify_decode_attempt(|| {
                // The ordinary scope owner is outside this leaf-only allocator
                // observation. The future prepared frame workspace must replace
                // this scope's physical allocations before production use.
                norito::core::with_decode_limits_scope(
                    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
                    || match without_allocations(|| destination.decode_payload(&bytes)) {
                        Err(PreparedCryptoDecodeError::Codec(error)) => Err::<(), _>(error),
                        _ => panic!(
                            "actual enclosing source must refuse before destination mutation"
                        ),
                    },
                )
            })
        },
    )
    .unwrap_err();
    assert_eq!(
        error.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(destination.decoded_payload().is_none());
    assert_eq!(destination.0.bytes.as_slice().as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), 129);
    pool.set_limit_bytes(0);
    without_allocations(|| destination.decode_payload(&bytes)).unwrap();
    assert_eq!(destination.decoded_payload().unwrap().as_ptr(), pointer);
    drop((destination, wrong));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn preparation_returns_exact_charge_on_foreign_layout_and_physical_allocator_refusal() {
    let pool = AllocationBudget::new(96);
    let foreign = AllocationBudget::new(96);
    let original = charge(&pool, 96);
    let (original, failure) = PreparedSignatureDecode::try_from_charge(96, &foreign, original)
        .err()
        .unwrap();
    assert_eq!(failure, SignatureAllocationError::ForeignPool);
    assert!(original.belongs_to(&pool));
    let (original, failure) = PreparedSignatureDecode::try_from_charge(95, &pool, original)
        .err()
        .unwrap();
    assert!(matches!(
        failure,
        SignatureAllocationError::Allocation(ChargedBufferFromChargeError::LayoutMismatch { .. })
    ));
    let (original, failure) = with_allocation_failure(96, || {
        PreparedSignatureDecode::try_from_charge(96, &pool, original)
    })
    .err()
    .unwrap();
    assert_eq!(
        failure,
        SignatureAllocationError::Allocation(ChargedBufferFromChargeError::Allocator {
            layout: Layout::array::<u8>(96).unwrap()
        })
    );
    assert!(original.belongs_to(&pool));
    assert_eq!(pool.reserved_bytes(), 96);
    pool.set_limit_bytes(0);
    let destination = PreparedSignatureDecode::try_from_charge(96, &pool, original)
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    drop(destination);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(foreign.reserved_bytes(), 0);

    let pool = AllocationBudget::new(33);
    let original = charge(&pool, 33);
    let (original, failure) = with_allocation_failure(33, || {
        PreparedPublicKeyDecode::try_from_charge(33, &pool, original)
    })
    .err()
    .unwrap();
    assert_eq!(
        failure,
        PublicKeyAllocationError::Allocation(ChargedBufferFromChargeError::Allocator {
            layout: Layout::array::<u8>(33).unwrap()
        })
    );
    assert_eq!(pool.reserved_bytes(), 33);
    drop(
        PreparedPublicKeyDecode::try_from_charge(33, &pool, original)
            .unwrap_or_else(|(_, error)| panic!("{error}")),
    );
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn prepared_leaf_unwind_deallocates_backing_before_original_pool_notification() {
    use std::{
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };
    struct Check {
        pool: AllocationBudget,
    }
    impl Wake for Check {
        fn wake(self: Arc<Self>) {
            assert!(
                observed_deallocations() > 0,
                "backing is physically gone before refund wake"
            );
            assert_eq!(
                self.pool.reserved_bytes(),
                ReleaseRegistration::allocation_layout().size()
            );
        }
    }
    let registration_bytes = ReleaseRegistration::allocation_layout().size();
    let pool = AllocationBudget::new(96 + registration_bytes);
    let mut prepaid = pool
        .try_reserve(ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
    drop(prepaid);
    let destination = signature(&pool, 96);
    let failure = pool
        .try_reserve(Layout::array::<u8>(1).unwrap())
        .unwrap_err();
    let iroha_allocation::AllocationRefusal::Capacity { release: wait, .. } = failure else {
        panic!("the live original destination must be the capacity blocker")
    };
    let waker = Waker::from(Arc::new(Check { pool: pool.clone() }));
    assert_eq!(
        registration.poll_wait(&wait, &mut Context::from_waker(&waker)),
        Poll::Pending
    );
    let ((unwind, _), _) = with_deallocation_observation(96, || {
        allocations_during(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _owner = destination;
                panic!("prepared destination interrupted")
            }))
        })
    });
    assert!(unwind.is_err());
    registration.cancel();
    drop((wait, registration));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn one_pass_public_key_admission_matches_canonical_work_and_exact_physical_backing() {
    for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1] {
        let pair = KeyPair::from_seed(vec![0x63; 32], algorithm);
        let key = pair.public_key();
        let exact = key.retained_allocation_layout();
        for flags in [0, header_flags::COMPACT_LEN] {
            let _flags = DecodeFlagsGuard::enter(flags);
            let bytes = encode(key);
            let original = (bytes.as_ptr(), bytes.len());
            let limits = DecodeLimits::new(1024, 4096, 1024, 3 * exact.size(), 32);
            let ordinary = norito::core::DecodeBudgetContext::new(limits);
            let (decoded, used) = ordinary
                .with(|| PublicKey::decode_from_slice(&bytes))
                .unwrap();
            assert_eq!(used, bytes.len());
            let context = norito::core::DecodeBudgetContext::new(limits);
            let pool = AllocationBudget::new(exact.size());
            let (owner, requests) = context.with(|| {
                allocations_during(|| PreparedPublicKeyDecode::try_decode_payload(&bytes, &pool))
            });
            let owner = owner.unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(
                requests, 1,
                "only the exact final compact backing is allocated"
            );
            assert_eq!(owner.get(), &decoded);
            assert_eq!(owner.get(), key);
            assert!(owner.belongs_to(&pool));
            assert_eq!(owner.get().retained_allocation_layout(), exact);
            assert_eq!(pool.reserved_bytes(), exact.size());
            assert_eq!(
                context.consumed_allocated_bytes(),
                ordinary.consumed_allocated_bytes()
            );
            assert_eq!(
                context.consumed_allocated_bytes(),
                u64::try_from(3 * exact.size()).unwrap()
            );
            assert_eq!((bytes.as_ptr(), bytes.len()), original);
            assert_eq!(encode(owner.get()), bytes);
            pool.set_limit_bytes(0);
            let ((), freed) = with_deallocation_observation(exact.size(), || drop(owner));
            assert_eq!(freed, 1);
            assert_eq!(pool.reserved_bytes(), 0);
        }
    }
}

#[test]
fn one_pass_public_key_admission_preserves_failed_prefix_before_later_invalid_key() {
    let pair = KeyPair::from_seed(vec![0x64; 32], Algorithm::Ed25519);
    let key = pair.public_key();
    let exact = key.retained_allocation_layout();
    let unlimited = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
    for flags in [0, header_flags::COMPACT_LEN] {
        let _flags = DecodeFlagsGuard::enter(flags);
        let valid = encode(key);
        let mut compact = key.0.algorithm_and_payload.to_vec();
        compact[0] = 0xff;
        let mut invalid = Vec::new();
        norito::core::write_element_sequence::<u8, _>(
            &mut Encoder::for_buffer(&mut invalid),
            compact.iter(),
        )
        .unwrap();
        let original = (invalid.as_ptr(), invalid.len());
        let oracle = norito::core::DecodeBudgetContext::new(unlimited);
        let _oracle_first = oracle
            .with(|| PublicKey::decode_from_slice(&valid))
            .unwrap();
        let first_work = oracle.consumed_allocated_bytes();
        let rejected = oracle
            .with(|| PublicKey::decode_from_slice(&invalid))
            .unwrap_err();
        assert!(!rejected.is_decode_resource_limit());
        let prefix_work = oracle.consumed_allocated_bytes();
        assert!(
            prefix_work > first_work,
            "failed later key retains successful prefix work"
        );
        let limit = usize::try_from(prefix_work - 1).unwrap();
        let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, 32);
        let ordinary = norito::core::DecodeBudgetContext::new(limits);
        let _ordinary_first = ordinary
            .with(|| PublicKey::decode_from_slice(&valid))
            .unwrap();
        let expected = ordinary
            .with(|| PublicKey::decode_from_slice(&invalid))
            .unwrap_err();
        assert!(
            expected.is_decode_resource_limit(),
            "earlier quota refusal precedes invalid tag"
        );
        let context = norito::core::DecodeBudgetContext::new(limits);
        let shared = context.clone();
        let pool = AllocationBudget::new(2 * exact.size());
        let first = context
            .with(|| PreparedPublicKeyDecode::try_decode_payload(&valid, &pool))
            .unwrap_or_else(|error| panic!("{error}"));
        let failure = shared
            .with(|| {
                without_allocations(|| PreparedPublicKeyDecode::try_decode_payload(&invalid, &pool))
            })
            .err()
            .expect("original cumulative quota must refuse");
        let PublicKeyDecodeAdmissionError::Codec(actual) = failure else {
            panic!("later invalid key must not bypass original quota")
        };
        assert_eq!(
            actual.decode_resource_error(),
            expected.decode_resource_error()
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        assert!(context.consumed_allocated_bytes() > first_work);
        assert_eq!(pool.reserved_bytes(), exact.size());
        assert!(first.belongs_to(&pool));
        let expected_retry = ordinary
            .with(|| PublicKey::decode_from_slice(&valid))
            .unwrap_err();
        let failure = shared
            .with(|| {
                without_allocations(|| PreparedPublicKeyDecode::try_decode_payload(&valid, &pool))
            })
            .err()
            .expect("failed work cannot replenish retry credit");
        let PublicKeyDecodeAdmissionError::Codec(actual_retry) = failure else {
            panic!("retry must retain original logical refusal")
        };
        assert_eq!(
            actual_retry.decode_resource_error(),
            expected_retry.decode_resource_error()
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        assert_eq!((invalid.as_ptr(), invalid.len()), original);
        drop(first);
        assert_eq!(pool.reserved_bytes(), 0);

        // Independent unlimited contexts show the deterministic failure also
        // keeps prefix work, followed by a real successful cumulative retry.
        let ordinary = norito::core::DecodeBudgetContext::new(unlimited);
        let context = norito::core::DecodeBudgetContext::new(unlimited);
        let _ordinary_first = ordinary
            .with(|| PublicKey::decode_from_slice(&valid))
            .unwrap();
        let first = context
            .with(|| PreparedPublicKeyDecode::try_decode_payload(&valid, &pool))
            .unwrap_or_else(|error| panic!("{error}"));
        let expected = ordinary
            .with(|| PublicKey::decode_from_slice(&invalid))
            .unwrap_err();
        let failure = context
            .with(|| {
                without_allocations(|| PreparedPublicKeyDecode::try_decode_payload(&invalid, &pool))
            })
            .err()
            .expect("invalid tag must refuse");
        let PublicKeyDecodeAdmissionError::Codec(actual) = failure else {
            panic!("canonical deterministic cause must remain intact")
        };
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(
            context.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        let (expected_retry, _) = ordinary
            .with(|| PublicKey::decode_from_slice(&valid))
            .unwrap();
        let retry = context
            .with(|| PreparedPublicKeyDecode::try_decode_payload(&valid, &pool))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(retry.get(), &expected_retry);
        assert_eq!(
            context.consumed_allocated_bytes(),
            ordinary.consumed_allocated_bytes()
        );
        assert_eq!(pool.reserved_bytes(), 2 * exact.size());
        drop((retry, first));
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn one_pass_public_key_capacity_and_allocator_refusals_preserve_cumulative_work() {
    let _flags = DecodeFlagsGuard::enter(0);
    let pair = KeyPair::from_seed(vec![0x65; 32], Algorithm::Ed25519);
    let key = pair.public_key();
    let bytes = encode(key);
    let original = (bytes.as_ptr(), bytes.len());
    let exact = key.retained_allocation_layout();
    let limits = DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 32);
    let context = norito::core::DecodeBudgetContext::new(limits);
    let pool = AllocationBudget::new(exact.size());
    let first = context
        .with(|| PreparedPublicKeyDecode::try_decode_payload(&bytes, &pool))
        .unwrap_or_else(|error| panic!("{error}"));
    let expected = pool.try_reserve(exact).unwrap_err();
    let (failure, requests) = context
        .with(|| allocations_during(|| PreparedPublicKeyDecode::try_decode_payload(&bytes, &pool)));
    assert_eq!(
        requests, 0,
        "capacity is refused before the physical request"
    );
    let failure = failure
        .err()
        .expect("live original key must occupy the pool");
    let PublicKeyDecodeAdmissionError::Allocation(ChargedBufferError::Admission(actual)) = failure
    else {
        panic!("capacity refusal must keep its exact original pool observation")
    };
    assert_eq!(actual, expected);
    assert_eq!(pool.reserved_bytes(), exact.size());
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(6 * exact.size()).unwrap()
    );
    drop(first);
    assert_eq!(pool.reserved_bytes(), 0);
    let (failure, requests) = with_allocation_failure(exact.size(), || {
        context.with(|| {
            allocations_during(|| PreparedPublicKeyDecode::try_decode_payload(&bytes, &pool))
        })
    });
    let failure = failure
        .err()
        .expect("actual physical backing request must refuse");
    assert_eq!(requests, 1);
    assert!(matches!(failure,
        PublicKeyDecodeAdmissionError::Allocation(ChargedBufferError::Allocator { requested_bytes })
        if requested_bytes == exact.size()
    ));
    assert_eq!(
        pool.reserved_bytes(),
        0,
        "unused physical charge is refunded"
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(9 * exact.size()).unwrap()
    );
    let retry = context
        .with(|| PreparedPublicKeyDecode::try_decode_payload(&bytes, &pool))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(retry.get(), key);
    assert!(retry.belongs_to(&pool));
    assert_eq!(
        context.consumed_allocated_bytes(),
        u64::try_from(12 * exact.size()).unwrap()
    );
    assert_eq!((bytes.as_ptr(), bytes.len()), original);
    assert_eq!(pool.reserved_bytes(), exact.size());
    drop(retry);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn one_pass_public_key_unwind_deallocates_before_original_pool_notification() {
    use std::{
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };
    struct Check {
        pool: AllocationBudget,
    }
    impl Wake for Check {
        fn wake(self: Arc<Self>) {
            assert_eq!(
                observed_deallocations(),
                1,
                "the original key is gone before refund wake"
            );
            assert_eq!(
                self.pool.reserved_bytes(),
                ReleaseRegistration::allocation_layout().size()
            );
        }
    }
    let _flags = DecodeFlagsGuard::enter(0);
    let pair = KeyPair::from_seed(vec![0x66; 32], Algorithm::Ed25519);
    let key = pair.public_key();
    let bytes = encode(key);
    let exact = key.retained_allocation_layout();
    let registration_layout = ReleaseRegistration::allocation_layout();
    let pool = AllocationBudget::new(exact.size() + registration_layout.size());
    let mut reservation = pool.try_reserve(registration_layout).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    drop(reservation);
    let owner = PreparedPublicKeyDecode::try_decode_payload(&bytes, &pool)
        .unwrap_or_else(|error| panic!("{error}"));
    let refusal = pool.try_reserve(exact).unwrap_err();
    let iroha_allocation::AllocationRefusal::Capacity { release: wait, .. } = refusal else {
        panic!("the original key must block this exact layout")
    };
    let waker = Waker::from(Arc::new(Check { pool: pool.clone() }));
    assert_eq!(
        registration.poll_wait(&wait, &mut Context::from_waker(&waker)),
        Poll::Pending
    );
    let (unwind, frees) = with_deallocation_observation(exact.size(), || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _owner = owner;
            panic!("one-pass key owner interrupted")
        }))
    });
    assert!(unwind.is_err());
    assert_eq!(frees, 1);
    assert_eq!(
        registration.poll_wait(&wait, &mut Context::from_waker(&waker)),
        Poll::Ready(())
    );
    registration.cancel();
    drop((wait, registration));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn funded_raw_material_key_preserves_validator_pool_and_exact_physical_backing() {
    let algorithms = [Algorithm::Ed25519, Algorithm::Secp256k1].into_iter();
    #[cfg(feature = "bls")]
    let algorithms = algorithms.chain([Algorithm::BlsNormal, Algorithm::BlsSmall]);
    for algorithm in algorithms {
        let pair = KeyPair::from_seed(vec![0x83; 32], algorithm);
        let source = pair.public_key();
        let (actual_algorithm, material) = source.borrowed_parts().unwrap();
        let pointer = material.as_ptr();
        let exact = source.retained_allocation_layout();
        let pool = AllocationBudget::new(exact.size());
        let context = norito::core::DecodeBudgetContext::new(DecodeLimits::new(0, 0, 0, 0, 0));
        let key = context
            .with(|| PreparedPublicKeyDecode::try_from_material(actual_algorithm, material, &pool))
            .unwrap();
        assert_eq!(key.get(), source);
        assert!(key.belongs_to(&pool));
        assert_eq!(context.consumed_allocated_bytes(), 0);
        assert_eq!(pool.reserved_bytes(), exact.size());
        let expected = pool.try_reserve(exact).unwrap_err();
        let (result, requests) = allocations_during(|| {
            PreparedPublicKeyDecode::try_from_material(actual_algorithm, material, &pool)
        });
        assert_eq!(requests, 0);
        assert!(
            matches!(result, Err(PublicKeyDecodeAdmissionError::Allocation(
            ChargedBufferError::Admission(actual))) if actual == expected)
        );
        let invalid = [0; 1];
        let failure = without_allocations(|| {
            PreparedPublicKeyDecode::try_from_material(actual_algorithm, &invalid, &pool)
        });
        assert!(
            matches!(failure, Err(PublicKeyDecodeAdmissionError::Codec(_))),
            "canonical invalid material precedes the occupied-pool refusal"
        );
        let ((), freed) = with_deallocation_observation(exact.size(), || drop(key));
        assert_eq!(freed, 1);
        assert_eq!(pool.reserved_bytes(), 0);
        let failure = with_allocation_failure(exact.size(), || {
            PreparedPublicKeyDecode::try_from_material(actual_algorithm, material, &pool)
        });
        assert!(
            matches!(failure, Err(PublicKeyDecodeAdmissionError::Allocation(
            ChargedBufferError::Allocator { requested_bytes })) if requested_bytes == exact.size())
        );
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(material.as_ptr(), pointer);
        let retried =
            PreparedPublicKeyDecode::try_from_material(actual_algorithm, material, &pool).unwrap();
        assert_eq!(retried.get(), source);
        drop(retried);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn json_key_destination_preserves_canonical_text_escape_and_original_pool() {
    use norito::json::JsonDeserialize as _;
    let pair = KeyPair::from_seed(vec![0x9a; 32], Algorithm::Ed25519);
    let plain = norito::json::to_json(pair.public_key()).unwrap();
    let mut escaped = String::from("\"");
    for byte in pair.public_key().to_string().bytes() {
        use std::fmt::Write as _;
        write!(&mut escaped, "\\u{byte:04X}").unwrap();
    }
    escaped.push('"');
    for source in [plain.as_str(), escaped.as_str()] {
        let pool = AllocationBudget::new(1 << 20);
        let foreign = AllocationBudget::new(pool.limit_bytes());
        let mut parser = norito::json::Parser::new(source);
        let key = PreparedPublicKeyDecode::try_from_json(&mut parser, &pool).unwrap();
        assert_eq!(key.get(), pair.public_key());
        assert!(key.belongs_to(&pool));
        assert!(!key.belongs_to(&foreign));
        assert!(parser.eof());
        assert_eq!(
            pool.reserved_bytes(),
            pair.public_key().retained_allocation_layout().size()
        );
        let ordinary = PublicKey::json_deserialize(&mut norito::json::Parser::new(source)).unwrap();
        assert_eq!(key.get(), &ordinary);
        drop(key);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn json_key_destination_refuses_string_and_late_compact_in_original_pool() {
    let pair = KeyPair::from_seed(vec![0x9b; 32], Algorithm::Ed25519);
    let source = norito::json::to_json(pair.public_key()).unwrap();
    let text_bytes = pair.public_key().to_string().len();
    let key_layout = pair.public_key().retained_allocation_layout();
    let pool = AllocationBudget::new(1 << 20);
    let blocker = pool.try_reserve_bytes(pool.limit_bytes()).unwrap();
    let result = without_allocations(|| {
        PreparedPublicKeyDecode::try_from_json(&mut norito::json::Parser::new(&source), &pool)
    });
    assert!(
        matches!(result, Err(PublicKeyJsonAdmissionError::Allocation(
        ChargedBufferError::Admission(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. })
    )) if requested_bytes == text_bytes)
    );
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(blocker);
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - text_bytes)
        .unwrap();
    let result =
        PreparedPublicKeyDecode::try_from_json(&mut norito::json::Parser::new(&source), &pool);
    // The temporary text consumes the remaining credit before compact admission.
    let Err(PublicKeyJsonAdmissionError::Allocation(ChargedBufferError::Admission(actual))) =
        result
    else {
        panic!("late compact backing must refuse")
    };
    assert!(
        matches!(actual, iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. } if requested_bytes == key_layout.size())
    );
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes() - text_bytes);
    drop(blocker);
    let key =
        PreparedPublicKeyDecode::try_from_json(&mut norito::json::Parser::new(&source), &pool)
            .unwrap();
    assert!(key.belongs_to(&pool));
    drop(key);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn json_key_destination_preserves_active_logical_prefix_and_late_invalid_key_order() {
    let pair = KeyPair::from_seed(vec![0x9c; 32], Algorithm::Ed25519);
    let source = norito::json::to_json(pair.public_key()).unwrap();
    let text_bytes = pair.public_key().to_string().len();
    let key_bytes = pair.public_key().retained_allocation_layout().size();
    let pool = AllocationBudget::new(1 << 20);
    let limits = DecodeLimits::new(4096, 4096, 4096, text_bytes, 64);
    norito::core::with_decode_limits_scope(limits, || {
        let first =
            PreparedPublicKeyDecode::try_from_json(&mut norito::json::Parser::new(&source), &pool);
        assert!(
            matches!(first, Err(PublicKeyJsonAdmissionError::Codec(ref error)) if error.is_decode_resource_limit())
        );
        assert_eq!(pool.reserved_bytes(), 0);
        // Successful string work is not replenished by physical retirement.
        let retry =
            PreparedPublicKeyDecode::try_from_json(&mut norito::json::Parser::new(&source), &pool);
        assert!(
            matches!(retry, Err(PublicKeyJsonAdmissionError::Json(ref error)) if error.is_decode_resource_limit())
        );
    });
    let admitted = DecodeLimits::new(4096, 4096, 4096, text_bytes + key_bytes, 64);
    norito::core::with_decode_limits_scope(admitted, || {
        let key =
            PreparedPublicKeyDecode::try_from_json(&mut norito::json::Parser::new(&source), &pool)
                .unwrap();
        assert_eq!(key.get(), pair.public_key());
        drop(key);
    });
    let invalid = "not a public key";
    let result =
        PreparedPublicKeyDecode::try_from_canonical_text(invalid, &AllocationBudget::new(0));
    assert!(matches!(
        result,
        Err(PublicKeyDecodeAdmissionError::Codec(
            Error::InvalidValue { .. }
        ))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn json_key_canonical_invalid_point_preserves_compact_admission_before_validation() {
    let pair = KeyPair::from_seed(vec![0x9d; 32], Algorithm::Secp256k1);
    let canonical = pair.public_key().to_string();
    let decoded = crate::multihash::decode_public_key_str_borrowed(&canonical).unwrap();
    let mut invalid = canonical[..canonical.len() - decoded.payload_hex.len()].to_owned();
    invalid.push_str(&"0".repeat(decoded.payload_hex.len()));
    assert!(crate::multihash::decode_public_key_str_borrowed(&invalid).is_some());
    let exact = pair.public_key().retained_allocation_layout();
    let pool = AllocationBudget::new(exact.size());
    let blocker = pool.try_reserve(exact).unwrap();
    let failure = PreparedPublicKeyDecode::try_from_canonical_text(&invalid, &pool);
    assert!(
        matches!(failure, Err(PublicKeyDecodeAdmissionError::Allocation(
        ChargedBufferError::Admission(iroha_allocation::AllocationRefusal::Capacity { requested_bytes, .. })
    )) if requested_bytes == exact.size())
    );
    drop(blocker);
    let failure = with_allocation_failure(exact.size(), || {
        PreparedPublicKeyDecode::try_from_canonical_text(&invalid, &pool)
    });
    assert!(
        matches!(failure, Err(PublicKeyDecodeAdmissionError::Allocation(
        ChargedBufferError::Allocator { requested_bytes }
    )) if requested_bytes == exact.size())
    );
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(matches!(
        PreparedPublicKeyDecode::try_from_canonical_text(&invalid, &pool),
        Err(PublicKeyDecodeAdmissionError::Codec(_))
    ));
    assert!(invalid.parse::<PublicKey>().is_err());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn json_key_physical_text_and_compact_refusals_keep_exact_cause_and_retire_text() {
    let pair = KeyPair::from_seed(vec![0x9e; 32], Algorithm::Ed25519);
    let source = norito::json::to_json(pair.public_key()).unwrap();
    let text_bytes = pair.public_key().to_string().len();
    let compact_bytes = pair.public_key().retained_allocation_layout().size();
    let pool = AllocationBudget::new(1 << 20);
    let failure = with_allocation_failure(text_bytes, || {
        PreparedPublicKeyDecode::try_from_json(&mut norito::json::Parser::new(&source), &pool)
    });
    assert!(
        matches!(failure, Err(PublicKeyJsonAdmissionError::Allocation(ChargedBufferError::Allocator {requested_bytes})) if requested_bytes == text_bytes)
    );
    assert_eq!(pool.reserved_bytes(), 0);
    let (failure, retired_text) = with_deallocation_observation(text_bytes, || {
        with_allocation_failure(compact_bytes, || {
            PreparedPublicKeyDecode::try_from_json(&mut norito::json::Parser::new(&source), &pool)
        })
    });
    assert!(
        matches!(failure, Err(PublicKeyJsonAdmissionError::Allocation(ChargedBufferError::Allocator {requested_bytes})) if requested_bytes == compact_bytes)
    );
    assert_eq!(retired_text, 1);
    assert_eq!(pool.reserved_bytes(), 0);
    let key =
        PreparedPublicKeyDecode::try_from_json(&mut norito::json::Parser::new(&source), &pool)
            .unwrap();
    assert!(key.belongs_to(&pool));
    drop(key);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn borrowed_public_key_recheck_preserves_canonical_limits_and_original_backing() {
    let pair = KeyPair::from_seed(vec![0x59; 32], Algorithm::Ed25519);
    let original = pair.public_key();
    let _flags = DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let bytes = encode(original);
    let pool = AllocationBudget::new(original.retained_allocation_layout().size());
    let owner = PreparedPublicKeyDecode::try_decode_payload(&bytes, &pool).unwrap();
    let pointer = owner.get().to_bytes().1.as_ptr();
    let reserved = pool.reserved_bytes();
    without_allocations(|| PreparedPublicKeyDecode::recheck_payload(&bytes, owner.get())).unwrap();
    let ceiling = DecodeLimits::new(0, usize::MAX, usize::MAX, usize::MAX, 64);
    let ordinary = norito::core::with_decode_limits_scope(ceiling, || {
        PreparedPublicKeyDecode::try_decode_payload(&bytes, &pool)
    });
    let Err(PublicKeyDecodeAdmissionError::Codec(ordinary)) = ordinary else {
        panic!("canonical sequence ceiling precedes physical storage");
    };
    let actual = norito::core::with_decode_limits_scope(ceiling, || {
        PreparedPublicKeyDecode::recheck_payload(&bytes, owner.get())
    })
    .unwrap_err();
    assert_eq!(
        actual.decode_resource_error(),
        ordinary.decode_resource_error()
    );
    let other = KeyPair::from_seed(vec![0x5a; 32], Algorithm::Ed25519);
    assert!(matches!(
        PreparedPublicKeyDecode::recheck_payload(&bytes, other.public_key()),
        Err(Error::InvalidValue {
            context: "public key"
        })
    ));
    assert_eq!(owner.get().to_bytes().1.as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), reserved);
    without_allocations(|| PreparedPublicKeyDecode::recheck_payload(&bytes, owner.get())).unwrap();
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}
