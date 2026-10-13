//! Captured verification codec owners never become proof verdicts or reconstructed scopes.

use super::*;
use norito::core::{DecodeLimits, DecodeLocalRefusalKind, reserve_decode_allocation};

fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

#[test]
fn local_attempt_retains_exact_owner_after_retirement_and_foreign_equal_limits() {
    let attempt = norito::with_decode_limits_scope(limits(0), || {
        codec_attempt(|| reserve_decode_allocation(1), |_| "completed invalid")
    })
    .unwrap_err();
    let expected = attempt.local_refusal().unwrap().clone();
    assert_eq!(expected.kind(), DecodeLocalRefusalKind::EnclosingLimit);
    let VerificationAttemptError::Deferred(owner) = &attempt else {
        panic!("lost local owner");
    };
    assert_eq!(
        owner.kind(),
        VerificationRefusalKind::Decode(DecodeLocalRefusalKind::EnclosingLimit)
    );
    let mapped =
        attempt.map_rejection(|_| panic!("local attempts cannot invoke rejection formatting"));
    norito::with_decode_limits_scope(limits(0), || {
        assert_eq!(mapped.local_refusal(), Some(&expected));
        let other =
            codec_attempt(|| reserve_decode_allocation(1), |_| "completed invalid").unwrap_err();
        assert_eq!(
            other.local_refusal().unwrap().resource_error(),
            expected.resource_error()
        );
        assert_ne!(other.local_refusal(), Some(&expected));
    });
    assert!(codec_attempt(|| reserve_decode_allocation(1), |_| "completed invalid").is_ok());
}

#[test]
fn intrinsic_scope_and_reconstructed_equal_numbers_stay_completed_rejections() {
    let intrinsic = norito::with_decode_limits_scope(limits(0), || {
        codec_attempt(
            || norito::with_decode_limits_scope(limits(0), || reserve_decode_allocation(1)),
            |_| "intrinsic limit",
        )
    })
    .unwrap_err();
    assert_eq!(expect_rejected(intrinsic), "intrinsic limit");
    let reconstructed = norito::with_decode_limits_scope(limits(0), || {
        codec_attempt(
            || {
                Err::<(), _>(norito::Error::TotalAllocationExceeded {
                    attempted: 1,
                    limit: 0,
                })
            },
            |_| "reconstructed",
        )
    })
    .unwrap_err();
    assert_eq!(expect_rejected(reconstructed), "reconstructed");
}

#[test]
fn stale_raw_cause_cannot_be_recaptured_as_a_new_local_owner() {
    let stale =
        norito::with_decode_limits_scope(limits(0), || reserve_decode_allocation(1)).unwrap_err();
    let mapped = norito::with_decode_limits_scope(limits(0), || {
        codec_attempt(|| Err::<(), _>(stale), |_| "stale original scope")
    })
    .unwrap_err();
    assert_eq!(expect_rejected(mapped), "stale original scope");
}

#[test]
fn malformed_frame_is_invalid_under_foreign_zero_budget() {
    let invalid = norito::with_decode_limits_scope(limits(0), || {
        codec_attempt(
            || norito::decode_canonical::<u64>(b"bad"),
            |_| "malformed frame",
        )
    })
    .unwrap_err();
    assert_eq!(expect_rejected(invalid), "malformed frame");
}

#[test]
fn captured_allocator_report_keeps_bytes_without_claiming_physical_origin() {
    // The existing Norito classifier accepts public AllocationFailed reports;
    // this verifies retention, not unforgeable physical allocator provenance.
    let error = codec_attempt(
        || Err::<(), _>(norito::Error::AllocationFailed { bytes: 73 }),
        |_| "invalid",
    )
    .unwrap_err();
    let original = error.local_refusal().unwrap();
    assert_eq!(original.kind(), DecodeLocalRefusalKind::Allocator);
    assert_eq!(original.allocation_bytes(), Some(73));
}

#[test]
fn nested_original_native_cause_moves_without_cloning_its_batch_owner() {
    use crate::{pcs::ipa::IpaError, verifier::VerifyError};
    use iroha_pasta::msm::{MemoryBudget, MsmError};
    let budget = MemoryBudget::new(0).check(37).unwrap_err();
    let nested = Box::new(VerifyError::Ipa(IpaError::Msm(MsmError::Budget(budget))));
    let original_address: *const VerifyError = &raw const *nested;
    let original = VerifyError::BatchItem {
        index: 3,
        error: nested,
    };
    let mapped = native_verification_error(original, |_| -> () {
        panic!("an unfinished native operation cannot become a proof rejection")
    });
    let VerificationAttemptError::Deferred(owner) = mapped else {
        panic!("lost native cause");
    };
    assert!(owner.decode_refusal().is_none());
    assert_eq!(owner.kind(), VerificationRefusalKind::NativeMemoryBudget);
    let Some(VerifyError::BatchItem { index, error }) = owner.native_verification_error() else {
        panic!("lost original outer native failure");
    };
    assert_eq!(*index, 3);
    let retained_address: *const VerifyError = &raw const **error;
    assert_eq!(retained_address, original_address);
    assert!(
        matches!(&**error, VerifyError::Ipa(IpaError::Msm(MsmError::Budget(original)))
        if *original == budget)
    );
    assert!(owner.into_decode_refusal().is_err());
}

#[test]
fn cancellation_and_completed_native_failures_have_disjoint_outcomes() {
    use crate::{
        pcs::{ipa::IpaError, multiopen::MultiopenError},
        protocol::ProtocolError,
        verifier::VerifyError,
    };
    use iroha_pasta::msm::MsmError;
    for original in [
        VerifyError::Cancelled,
        VerifyError::Ipa(IpaError::Cancelled),
        VerifyError::Ipa(IpaError::Msm(MsmError::Cancelled)),
        VerifyError::Multiopen(MultiopenError::Cancelled),
        VerifyError::Protocol(ProtocolError::Plan(MultiopenError::Ipa(
            IpaError::Cancelled,
        ))),
    ] {
        let expected = original.clone();
        let refusal = completed_result::<(), _>(Err(native_verification_error(original, |_| ())))
            .unwrap_err();
        assert_eq!(refusal.native_verification_error(), Some(&expected));
        assert_eq!(refusal.kind(), VerificationRefusalKind::NativeCancelled);
        assert!(std::error::Error::source(&refusal).is_some());
    }
    for original in [
        VerifyError::ProofLength {
            expected: 5,
            actual: 4,
        },
        VerifyError::Ipa(IpaError::OpeningFailed),
        VerifyError::Ipa(IpaError::Msm(MsmError::TooLarge { n: 7 })),
        VerifyError::BatchRejected,
    ] {
        assert!(
            completed_result::<(), _>(Err(native_verification_error(original, |_| ())))
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(completed_result::<_, ()>(Ok(9)).unwrap(), Some(9));
}

#[test]
fn original_initializer_codec_cause_survives_parent_projection() {
    let captured = norito::with_decode_limits_scope(limits(0), || {
        norito::core::classify_decode_attempt(|| reserve_decode_allocation(11))
    })
    .unwrap_err();
    let expected = captured.local_refusal().unwrap();
    let owner = VerificationRefusal::initialization(NativeVerifierInitError::Codec(captured));
    assert_eq!(owner.decode_refusal(), Some(&expected));
    norito::with_decode_limits_scope(limits(0), || {
        assert_eq!(owner.decode_refusal(), Some(&expected));
    });
    let moved = owner.into_decode_refusal().unwrap();
    assert_eq!(moved, expected);
}

#[test]
fn trusted_compiled_key_failures_never_become_incoming_proof_verdicts() {
    let malformed =
        norito::core::classify_decode_attempt(|| Err::<(), _>(norito::Error::NonCanonicalEncoding))
            .unwrap_err();
    let original = VerificationRefusal::initialization(NativeVerifierInitError::Codec(malformed));
    assert!(original.decode_refusal().is_none());
    assert!(matches!(
        original.initialization_error(),
        Some(NativeVerifierInitError::Codec(_))
    ));
    assert!(std::error::Error::source(&original).is_some());
    assert!(completed_result::<(), ()>(Err(VerificationAttemptError::Deferred(original))).is_err());
    assert!(
        completed_result::<(), ()>(Err(VerificationAttemptError::Deferred(
            VerificationRefusal::initialization(NativeVerifierInitError::Invariant(
                "compiled native key exceeds registry bound"
            )),
        )))
        .is_err()
    );
}

#[test]
fn initializer_diagnostics_borrow_exact_causes_without_inventing_capacity_owners() {
    use crate::keys::KeyError;
    use iroha_pasta::msm::{MemoryBudget, MsmError};
    let budget = MemoryBudget::new(0).check(23).unwrap_err();
    let original = VerificationRefusal::initialization(NativeVerifierInitError::Key(
        KeyError::Msm(MsmError::Budget(budget)),
    ));
    assert_eq!(original.kind(), VerificationRefusalKind::NativeMemoryBudget);
    assert!(
        matches!(original.initialization_error(), Some(NativeVerifierInitError::Key(KeyError::Msm(MsmError::Budget(actual)))) if *actual == budget)
    );
    assert!(original.decode_refusal().is_none());
    for cause in [
        NativeVerifierInitError::Invariant("compiled key identity"),
        NativeVerifierInitError::CachePoisoned,
    ] {
        assert_eq!(
            VerificationRefusal::initialization(cause).kind(),
            VerificationRefusalKind::LocalInvariantViolation
        );
    }
    let cancelled =
        VerificationRefusal::initialization(NativeVerifierInitError::Key(KeyError::Cancelled));
    assert_eq!(cancelled.kind(), VerificationRefusalKind::NativeCancelled);
    let unavailable = VerificationRefusal::initialization(NativeVerifierInitError::Params(
        crate::pcs::ipa::ParamsTrustError::UnknownCurve,
    ));
    assert_eq!(
        unavailable.kind(),
        VerificationRefusalKind::InitializationUnavailable
    );
}

#[test]
fn original_owner_layout_diagnostics() {
    // Diagnostic only: no ABI size or whole-node memory qualification is inferred.
    println!(
        "original-owner-layout refusal={} initializer={} native={} decoder={}",
        core::mem::size_of::<VerificationRefusal>(),
        core::mem::size_of::<NativeVerifierInitError>(),
        core::mem::size_of::<crate::verifier::VerifyError>(),
        core::mem::size_of::<DecodeLocalRefusal>(),
    );
}

#[test]
fn actual_bounded_output_cap_and_trusted_serializer_defect_require_recovery() {
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_plonk::verification_attempt::tests::BrokenTrustedWriter")]
    struct BrokenTrustedWriter;

    impl norito::core::SerializePayload for BrokenTrustedWriter {
        fn serialize(&self, _: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
            Err(norito::Error::LengthMismatch)
        }
    }

    let over_bound = norito::core::to_bytes_bounded(&7_u64, 0).unwrap_err();
    let broken = norito::core::to_bytes_bounded(&BrokenTrustedWriter, 64).unwrap_err();
    assert!(matches!(
        over_bound,
        norito::core::BoundedEncodeError::FrameTooLarge { max_bytes: 0, .. }
    ));
    assert!(matches!(
        broken,
        norito::core::BoundedEncodeError::Serialization(norito::Error::LengthMismatch)
    ));
    for original in [over_bound, broken] {
        let owner =
            VerificationRefusal::initialization(NativeVerifierInitError::Encoding(original));
        assert_eq!(
            owner.kind(),
            VerificationRefusalKind::LocalInvariantViolation
        );
        assert!(owner.decode_refusal().is_none());
        let owner = owner.into_decode_refusal().unwrap_err();
        assert!(matches!(
            owner.initialization_error(),
            Some(NativeVerifierInitError::Encoding(_))
        ));
        assert!(
            std::error::Error::source(owner.initialization_error().unwrap())
                .unwrap()
                .downcast_ref::<norito::core::BoundedEncodeError>()
                .is_some()
        );
        assert!(
            completed_result::<(), ()>(Err(VerificationAttemptError::Deferred(owner))).is_err()
        );
    }
}

#[test]
fn bounded_writer_preserves_real_nested_scope_without_decoder_reclassification() {
    let original = norito::with_decode_limits_scope(limits(0), || {
        norito::core::classify_decode_attempt(|| Ok(norito::core::to_bytes_bounded(&7_u64, 64)))
            .unwrap()
            .unwrap_err()
    });
    let norito::core::BoundedEncodeError::Serialization(norito::Error::ScopedDecodeResource(scope)) =
        &original
    else {
        panic!("actual bounded writer reservation must retain its original scope");
    };
    let expected = scope.clone();
    let owner = VerificationRefusal::initialization(NativeVerifierInitError::Encoding(original));
    assert_eq!(
        owner.kind(),
        VerificationRefusalKind::InitializationUnavailable
    );
    assert!(owner.decode_refusal().is_none());
    let owner = owner.into_decode_refusal().unwrap_err();
    norito::with_decode_limits_scope(limits(0), || {
        assert!(matches!(owner.initialization_error(),
            Some(NativeVerifierInitError::Encoding(norito::core::BoundedEncodeError::Serialization(norito::Error::ScopedDecodeResource(actual))))
            if actual == &expected));
    });
    assert!(norito::core::to_bytes_bounded(&7_u64, 64).is_ok());
}
