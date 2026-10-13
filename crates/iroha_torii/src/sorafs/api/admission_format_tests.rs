#[test]
fn formats_admission_error_reasons() {
    let provider_id = [0u8; 32];
    assert_eq!(
        admission_error_reason(&AdvertError::AdmissionMissing { provider_id }),
        "admission_missing"
    );
    assert_eq!(
        admission_error_reason(&AdvertError::AdmissionFailed {
            provider_id,
            error: Box::new(
                crate::sorafs::ProviderAdmissionAdvertError::NetworkMismatch {
                    expected: [0xA1; 32],
                    provided: [0xB2; 32],
                }
            ),
        }),
        "network_mismatch"
    );
    let expired = AdvertError::Validation(AdvertValidationError::Expired {
        now: 11,
        expires_at: 10,
    });
    assert_eq!(admission_error_reason(&expired), "stale",);
    let future = AdvertError::Validation(AdvertValidationError::IssuedInFuture {
        now: 10,
        issued_at: 11,
    });
    assert_eq!(admission_error_reason(&future), "future_issued");
    assert_eq!(
        admission_error_reason(&AdvertError::SignaturePolicyDisabled),
        "signature_policy_disabled"
    );
    assert_eq!(
        admission_error_reason(&AdvertError::ValidationPolicyChanged),
        "validation_policy_changed"
    );
    assert_eq!(
        admission_error_reason(&AdvertError::NonMonotonicIssuedAt {
            provider_id,
            current_issued_at: 11,
            incoming_issued_at: 10,
        }),
        "non_monotonic_issued_at"
    );
    assert_eq!(
        admission_error_reason(&AdvertError::ReplayCheckpoint(
            crate::sorafs::ReplayCheckpointError::CapacityExceeded { maximum: 1 }
        )),
        "replay_checkpoint"
    );
}
