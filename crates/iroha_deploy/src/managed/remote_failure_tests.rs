//! Public diagnostics retain operation meaning without forwarding source error text.

use super::*;

#[test]
fn preparation_recovery_and_native_finality_have_distinct_safe_codes() {
    for (error, expected) in [
        (
            ProvisioningError::FaucetPreparation,
            ManagedAttachmentFailure::PreparationFailed,
        ),
        (
            ProvisioningError::NamespacePreparation,
            ManagedAttachmentFailure::PreparationFailed,
        ),
        (
            ProvisioningError::FaucetRecovery,
            ManagedAttachmentFailure::RecoveryFailed,
        ),
        (
            ProvisioningError::NamespaceRecovery,
            ManagedAttachmentFailure::RecoveryFailed,
        ),
        (
            ProvisioningError::NamespaceQuote,
            ManagedAttachmentFailure::QuoteUnavailable,
        ),
        (
            ProvisioningError::NamespaceObservation,
            ManagedAttachmentFailure::NamespaceUnverified,
        ),
        (
            ProvisioningError::Deadline,
            ManagedAttachmentFailure::AwaitingCompletion,
        ),
        (
            ProvisioningError::Cancelled,
            ManagedAttachmentFailure::SupervisorStopped,
        ),
        (
            ProvisioningError::Attachment(AttachmentError::Cancelled),
            ManagedAttachmentFailure::SupervisorStopped,
        ),
        (
            ProvisioningError::Bootstrap(BootstrapError::Finality(FinalityError::CatchingUp {
                verified: 7,
                claimed: 9,
            })),
            ManagedAttachmentFailure::ParentCatchingUp,
        ),
        (
            ProvisioningError::Attachment(AttachmentError::Finality(FinalityError::WrongGenesis)),
            ManagedAttachmentFailure::EvidenceRejected,
        ),
    ] {
        assert_eq!(ManagedAttachmentFailure::from(error), expected);
    }
}

#[test]
fn retained_bootstrap_failures_preserve_unresolved_journals_without_signed_terminal_claims() {
    for reason in [
        ManagedBootstrapFailure::RetainedMaterial,
        ManagedBootstrapFailure::Cancelled,
        ManagedBootstrapFailure::TransitionPending,
        ManagedBootstrapFailure::SignedUnresolved,
        ManagedBootstrapFailure::AuthorizationExpired,
        ManagedBootstrapFailure::PayloadExpired,
        ManagedBootstrapFailure::EnrollmentExpired,
        ManagedBootstrapFailure::EnrollmentObservationExpired,
        ManagedBootstrapFailure::EnrollmentPredecessorChanged,
        ManagedBootstrapFailure::ProfileExpired,
        ManagedBootstrapFailure::EpochLimit,
        ManagedBootstrapFailure::ReplacementLimit,
    ] {
        let failure = ManagedAttachmentFailure::from(Error::Bootstrap(reason));
        assert_eq!(failure, ManagedAttachmentFailure::Bootstrap(reason));
        assert!(!failure.is_terminal_operation());
        let original = norito::json::to_vec(&failure).unwrap();
        assert_eq!(
            norito::json::from_slice::<ManagedAttachmentFailure>(&original).unwrap(),
            failure,
        );
    }
}

#[test]
fn public_failure_codes_roundtrip_and_reject_arbitrary_text() {
    for failure in [
        ManagedAttachmentFailure::PreparationFailed,
        ManagedAttachmentFailure::RecoveryFailed,
        ManagedAttachmentFailure::OperationExpired,
        ManagedAttachmentFailure::OperationRejected,
        ManagedAttachmentFailure::QuoteUnavailable,
        ManagedAttachmentFailure::NamespaceUnverified,
        ManagedAttachmentFailure::ContextRejected,
        ManagedAttachmentFailure::CustodyUnavailable,
        ManagedAttachmentFailure::ParentAuthenticationFailed,
        ManagedAttachmentFailure::ParentUnavailable,
        ManagedAttachmentFailure::ParentCatchingUp,
        ManagedAttachmentFailure::EvidenceRejected,
        ManagedAttachmentFailure::ObservationLimit,
        ManagedAttachmentFailure::RelayIncomplete,
        ManagedAttachmentFailure::AwaitingCompletion,
        ManagedAttachmentFailure::SupervisorStopped,
        ManagedAttachmentFailure::WorkerUnavailable,
    ] {
        let bytes = norito::json::to_vec(&failure).unwrap();
        assert_eq!(
            norito::json::from_slice::<ManagedAttachmentFailure>(&bytes).unwrap(),
            failure,
        );
        assert!(failure.as_str().len() < 40);
        assert!(failure.to_string().len() < 128);
        assert!(!failure.to_string().is_empty());
    }
    for raw in [
        r#""server sent secret""#,
        r#"{"code":"preparation_failed"}"#,
        "null",
    ] {
        assert!(norito::json::from_str::<ManagedAttachmentFailure>(raw).is_err());
    }
}

#[test]
fn public_failure_never_contains_underlying_paths_credentials_or_response_bodies() {
    const PRIVATE: &str = "Authorization: Bearer fixture-secret; /private/owner/key; response-body";
    let errors = [
        ManagedAttachmentFailure::from(ProvisioningError::Io(std::io::Error::other(PRIVATE))),
        ManagedAttachmentFailure::from(ProvisioningError::Invalid(PRIVATE)),
        ManagedAttachmentFailure::from(BootstrapError::Invalid(PRIVATE)),
        ManagedAttachmentFailure::from(AttachmentError::Operation(PRIVATE)),
        ManagedAttachmentFailure::from(FinalityError::Source(Box::new(std::io::Error::other(
            PRIVATE,
        )))),
        ManagedAttachmentFailure::from(FinalityError::ResourceLimit(PRIVATE)),
        ManagedAttachmentFailure::from(Error::Invalid(PRIVATE.into())),
        ManagedAttachmentFailure::from(Error::Busy(PRIVATE.into())),
    ];
    for failure in errors {
        let encoded = String::from_utf8(norito::json::to_vec(&failure).unwrap()).unwrap();
        for public in [format!("{failure:?}"), failure.to_string(), encoded] {
            for fragment in [
                "Authorization",
                "fixture-secret",
                "/private",
                "response-body",
            ] {
                assert!(
                    !public.contains(fragment),
                    "source details escaped: {public}"
                );
            }
        }
    }
}

#[test]
fn administrative_native_attachment_errors_preserve_closed_classification_without_terminal_claims()
{
    const PRIVATE: &str = "Authorization: Bearer fixture-secret; /private/owner/key; response-body";
    for (error, expected) in [
        (
            Error::NoSelection,
            ManagedAttachmentFailure::ContextRejected,
        ),
        (
            Error::Io(std::io::Error::other(PRIVATE)),
            ManagedAttachmentFailure::CustodyUnavailable,
        ),
        (
            Error::Invalid(PRIVATE.into()),
            ManagedAttachmentFailure::ContextRejected,
        ),
        (
            Error::ContractCall {
                journal: std::path::PathBuf::from("/private/owner/key"),
                source: color_eyre::eyre::eyre!(PRIVATE),
            },
            ManagedAttachmentFailure::ContextRejected,
        ),
        (
            Error::Busy(PRIVATE.into()),
            ManagedAttachmentFailure::CustodyUnavailable,
        ),
        (
            Error::Timeout(std::time::Duration::from_secs(1)),
            ManagedAttachmentFailure::AwaitingCompletion,
        ),
        (
            Error::NativeDeadline,
            ManagedAttachmentFailure::AwaitingCompletion,
        ),
        (
            Error::ParentDeadline,
            ManagedAttachmentFailure::AwaitingCompletion,
        ),
        (
            Error::WorkerFailure {
                failure: PRIVATE.into(),
                cleanup: Some(Box::new(Error::Invalid(PRIVATE.into()))),
                publication: Some(Box::new(Error::Io(std::io::Error::other(PRIVATE)))),
            },
            ManagedAttachmentFailure::ContextRejected,
        ),
        (
            Error::Bootstrap(ManagedBootstrapFailure::SignedUnresolved),
            ManagedAttachmentFailure::Bootstrap(ManagedBootstrapFailure::SignedUnresolved),
        ),
    ] {
        let failure = ManagedAttachmentFailure::from(AttachmentError::NativeOperation(error));
        assert_eq!(failure, expected);
        assert!(!failure.is_terminal_operation());
        let encoded = String::from_utf8(norito::json::to_vec(&failure).unwrap()).unwrap();
        assert_eq!(
            norito::json::from_str::<ManagedAttachmentFailure>(&encoded).unwrap(),
            expected,
        );
        for public in [format!("{failure:?}"), failure.to_string(), encoded] {
            for fragment in [
                "Authorization",
                "fixture-secret",
                "/private",
                "response-body",
            ] {
                assert!(
                    !public.contains(fragment),
                    "source details escaped: {public}"
                );
            }
        }
    }
}

#[test]
fn administrative_native_attachment_progress_preserves_only_existing_closed_terminal_outcomes() {
    for expected in [
        ManagedAttachmentFailure::AwaitingCompletion,
        ManagedAttachmentFailure::RecoveryFailed,
        ManagedAttachmentFailure::ContextRejected,
        ManagedAttachmentFailure::OperationExpired,
        ManagedAttachmentFailure::OperationRejected,
    ] {
        let original = Error::ParentProgressDeadline {
            stage: super::super::ManagedAttachmentPhase::Registering,
            failure: expected,
        };
        let failure = ManagedAttachmentFailure::from(AttachmentError::NativeOperation(original));
        assert_eq!(failure, expected);
        assert_eq!(
            failure.is_terminal_operation(),
            matches!(
                expected,
                ManagedAttachmentFailure::OperationExpired
                    | ManagedAttachmentFailure::OperationRejected
            ),
        );
    }
}
