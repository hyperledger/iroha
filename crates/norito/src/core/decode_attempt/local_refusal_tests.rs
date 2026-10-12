//! Retained original refusal ownership, diagnostics and fresh-attempt negative controls.

use super::*;
use crate::core::{DecodeLimits, reserve_decode_allocation, with_decode_limits_scope};

fn limit(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}

fn enclosing_refusal() -> DecodeAttemptError {
    with_decode_limits_scope(limit(0), || {
        classify_decode_attempt(|| reserve_decode_allocation(1))
    })
    .unwrap_err()
}

#[test]
fn local_owner_keeps_exact_scope_after_retirement_and_clone() {
    let captured = enclosing_refusal();
    let Error::ScopedDecodeResource(original) = captured.error() else {
        panic!("enclosing refusal has its original scope owner");
    };
    let original = original.clone();
    let borrowed = captured.local_refusal().unwrap();
    let retained = captured.into_local_refusal().unwrap();
    assert_eq!(retained, borrowed);
    assert_eq!(retained, retained.clone());
    assert_eq!(retained.kind(), DecodeLocalRefusalKind::EnclosingLimit);
    assert_eq!(retained.allocation_bytes(), None);
    assert_eq!(retained.resource_error(), original.resource());
    assert_eq!(retained.to_string(), original.to_string());
    assert!(std::error::Error::source(&retained).is_some());
    let separate = enclosing_refusal().into_local_refusal().unwrap();
    assert_eq!(retained.resource_error(), separate.resource_error());
    assert_ne!(
        retained, separate,
        "equal limits do not share scope identity"
    );
    let Error::ScopedDecodeResource(returned) = retained.into_error() else {
        panic!("moving a retained refusal must preserve the scoped variant");
    };
    assert_eq!(returned, original);
    assert!(returned.family.counters.ptr_eq(&original.family.counters));
    assert_eq!(returned.family.attempt, original.family.attempt);
    assert_eq!(returned.identity, original.identity);
}

#[test]
fn local_owner_retains_allocator_report_without_claiming_physical_provenance() {
    // This public error remains a trusted decoder report, not an unforgeable
    // allocator capability. Extraction must preserve its exact original demand.
    let captured = classify_decode_attempt(|| Err::<(), _>(Error::AllocationFailed { bytes: 137 }))
        .unwrap_err();
    let borrowed = captured.local_refusal().unwrap();
    let retained = captured.into_local_refusal().unwrap();
    assert_eq!(retained, borrowed);
    assert_eq!(retained.kind(), DecodeLocalRefusalKind::Allocator);
    assert_eq!(retained.allocation_bytes(), Some(137));
    assert_eq!(
        retained.resource_error(),
        DecodeResourceError::AllocationFailed { bytes: 137 }
    );
    assert_eq!(
        retained.to_string(),
        Error::AllocationFailed { bytes: 137 }.to_string()
    );
    assert!(std::error::Error::source(&retained).is_none());
    assert!(matches!(
        retained.clone().into_error(),
        Error::AllocationFailed { bytes: 137 }
    ));
    assert!(matches!(
        retained.into_error(),
        Error::AllocationFailed { bytes: 137 }
    ));
}

#[test]
fn local_owner_rejects_malformed_protocol_and_reconstructed_budget_causes() {
    let protocol = with_decode_limits_scope(limit(0), || {
        classify_decode_attempt(|| {
            with_decode_limits_scope(limit(0), || reserve_decode_allocation(1))
        })
    })
    .unwrap_err();
    let reconstructed = classify_decode_attempt(|| {
        Err::<(), _>(Error::from(
            enclosing_refusal().error().decode_resource_error().unwrap(),
        ))
    })
    .unwrap_err();
    let malformed = classify_decode_attempt(|| Err::<(), _>(Error::InvalidMagic)).unwrap_err();
    for captured in [protocol, reconstructed, malformed] {
        assert_eq!(captured.kind(), DecodeAttemptErrorKind::Invalid);
        let diagnostic = captured.error().decode_resource_error();
        let scoped = match captured.error() {
            Error::ScopedDecodeResource(original) => Some(original.clone()),
            _ => None,
        };
        assert_eq!(captured.local_refusal(), None);
        let returned = captured.into_local_refusal().unwrap_err();
        assert_eq!(returned.kind(), DecodeAttemptErrorKind::Invalid);
        assert_eq!(returned.error().decode_resource_error(), diagnostic);
        if let Some(original) = scoped {
            let Error::ScopedDecodeResource(returned) = returned.into_error() else {
                panic!("invalid protocol error must keep its original scoped cause");
            };
            assert_eq!(returned, original);
        } else if diagnostic.is_none() {
            assert!(matches!(returned.into_error(), Error::InvalidMagic));
        }
    }
}

#[test]
fn retained_owner_cannot_reclassify_a_stale_scope_as_a_new_refusal() {
    with_decode_limits_scope(limit(0), || {
        let captured = classify_decode_attempt(|| reserve_decode_allocation(1)).unwrap_err();
        let retained = captured.local_refusal().unwrap();
        for swallow_current in [false, true] {
            let stale = classify_decode_attempt(|| {
                if swallow_current {
                    drop(reserve_decode_allocation(1).unwrap_err());
                }
                Err::<(), _>(retained.clone().into_error())
            })
            .unwrap_err();
            assert_eq!(stale.kind(), DecodeAttemptErrorKind::Invalid);
            assert_eq!(stale.local_refusal(), None);
            let rejected = stale.into_local_refusal().unwrap_err();
            let (Error::ScopedDecodeResource(rejected), Error::ScopedDecodeResource(original)) =
                (rejected.into_error(), retained.clone().into_error())
            else {
                panic!("a stale error stays scoped without gaining new authority");
            };
            assert_eq!(rejected, original);
        }
        assert_eq!(
            captured.into_local_refusal().unwrap(),
            retained,
            "the original captured attempt remains retainable after a later attempt"
        );
    });
}

#[test]
fn retained_descendant_owner_returns_to_its_original_active_parent() {
    let parent = with_decode_limits_scope(limit(0), || {
        classify_decode_attempt(|| {
            let child = classify_decode_attempt(|| reserve_decode_allocation(1)).unwrap_err();
            let original = child.into_local_refusal().unwrap();
            Err::<(), _>(original.into_error())
        })
    })
    .unwrap_err();
    assert_eq!(parent.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(
        parent.into_local_refusal().unwrap().kind(),
        DecodeLocalRefusalKind::EnclosingLimit
    );
}
