//! Native budget exhaustion retains its typed meaning independently of custody validity.

use super::{require_deadline, require_retained_material};
use crate::managed::{Error, ManagedAttachmentFailure, ManagedBootstrapFailure, ManagedContext};
use std::time::{Duration, Instant};

const NATIVE_DEADLINE: &str = "native operation I/O deadline elapsed; retain original journals";

#[test]
fn zero_and_elapsed_native_budgets_refuse_with_the_original_exact_diagnostic() {
    let zero = Instant::now();
    let elapsed = zero.checked_sub(Duration::from_secs(1)).unwrap();
    for deadline in [zero, elapsed] {
        let error = require_deadline(deadline).unwrap_err();
        assert!(matches!(error, Error::NativeDeadline));
        assert_eq!(error.to_string(), NATIVE_DEADLINE);
    }
    require_deadline(Instant::now() + Duration::from_secs(60)).unwrap();
}

#[test]
fn retained_validation_preserves_native_deadlines_and_every_original_bootstrap_reason() {
    let error = require_retained_material(require_deadline(Instant::now())).unwrap_err();
    assert!(matches!(error, Error::NativeDeadline));
    assert_eq!(error.to_string(), NATIVE_DEADLINE);
    assert!(!error.to_string().contains("missing or invalid"));
    assert_eq!(require_retained_material(Ok(17_u32)).unwrap(), 17);

    for reason in [
        ManagedBootstrapFailure::RetainedMaterial,
        ManagedBootstrapFailure::Cancelled,
        ManagedBootstrapFailure::AuthorizationExpired,
        ManagedBootstrapFailure::TransitionPending,
        ManagedBootstrapFailure::PayloadExpired,
        ManagedBootstrapFailure::SignedUnresolved,
        ManagedBootstrapFailure::EnrollmentExpired,
        ManagedBootstrapFailure::EnrollmentObservationExpired,
        ManagedBootstrapFailure::EnrollmentPredecessorChanged,
        ManagedBootstrapFailure::ProfileExpired,
        ManagedBootstrapFailure::EpochLimit,
        ManagedBootstrapFailure::ReplacementLimit,
    ] {
        let error = require_retained_material::<()>(Err(Error::Bootstrap(reason))).unwrap_err();
        assert!(matches!(error, Error::Bootstrap(actual) if actual == reason));
        assert_eq!(error.to_string(), reason.to_string());
    }

    let invalid =
        crate::managed::decode::<ManagedContext>(b"invalid retained metadata").unwrap_err();
    assert!(matches!(invalid, Error::Invalid(_)));
    let owner = tempfile::tempdir().unwrap();
    let missing = std::fs::read(owner.path().join("missing-retained-material")).unwrap_err();
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
    for original in [invalid, Error::Io(missing)] {
        let error = require_retained_material::<()>(Err(original)).unwrap_err();
        assert!(matches!(
            error,
            Error::Bootstrap(ManagedBootstrapFailure::RetainedMaterial)
        ));
    }
}

#[test]
fn native_deadline_maps_to_the_existing_nonterminal_public_code_and_roundtrips() {
    for original in [
        Error::NativeDeadline,
        Error::ParentDeadline,
        Error::Timeout(Duration::ZERO),
    ] {
        let failure = ManagedAttachmentFailure::from(original);
        assert_eq!(failure, ManagedAttachmentFailure::AwaitingCompletion);
        assert_eq!(failure.as_str(), "awaiting_completion");
        assert!(!failure.is_terminal_operation());
        let bytes = norito::json::to_vec(&failure).unwrap();
        assert_eq!(bytes, b"\"awaiting_completion\"");
        assert_eq!(
            norito::json::from_slice::<ManagedAttachmentFailure>(&bytes).unwrap(),
            failure
        );
    }
}
