//! Framing/shape tests only; synthetic bytes are never treated as signed native originals.
use super::*;
#[test]
fn request_actions_roundtrip_exactly_with_full_original_caps() {
    for action in [
        EnrollmentServiceActionV1::PreKey,
        EnrollmentServiceActionV1::Evidence,
        EnrollmentServiceActionV1::Issue,
        EnrollmentServiceActionV1::Deliver,
    ] {
        let value = EnrollmentServiceRequestV1 {
            version: 1,
            action,
            dispatch_original: vec![1; ENROLLMENT_DISPATCH_MAX_BYTES_V1],
            evidence_original: if action == EnrollmentServiceActionV1::Evidence {
                vec![2; ENROLLMENT_EVIDENCE_REQUEST_MAX_BYTES_V1]
            } else {
                vec![]
            },
        };
        let original = value.canonical_wire().unwrap();
        assert!(original.len() <= ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1);
        assert_eq!(
            EnrollmentServiceRequestV1::decode_canonical(&original).unwrap(),
            value
        );
        let mut trailing = original;
        trailing.push(0);
        assert!(EnrollmentServiceRequestV1::decode_canonical(&trailing).is_err());
    }
}
#[test]
fn request_rejects_cross_action_inputs_versions_and_overflow() {
    let original = EnrollmentServiceRequestV1 {
        version: 1,
        action: EnrollmentServiceActionV1::PreKey,
        dispatch_original: vec![1],
        evidence_original: vec![],
    };
    for mutation in 0..6 {
        let mut bad = original.clone();
        match mutation {
            0 => bad.version = 2,
            1 => bad.dispatch_original.clear(),
            2 => bad.dispatch_original = vec![1; ENROLLMENT_DISPATCH_MAX_BYTES_V1 + 1],
            3 => bad.evidence_original = vec![1],
            4 => bad.action = EnrollmentServiceActionV1::Evidence,
            _ => {
                bad.action = EnrollmentServiceActionV1::Evidence;
                bad.evidence_original = vec![1; ENROLLMENT_EVIDENCE_REQUEST_MAX_BYTES_V1 + 1];
            }
        }
        assert!(bad.canonical_wire().is_err());
    }
    assert!(EnrollmentServiceRequestV1::decode_canonical(&[]).is_err());
    assert!(
        EnrollmentServiceRequestV1::decode_canonical(&vec![
            0;
            ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1
                + 1
        ])
        .is_err()
    );
}
#[test]
fn response_roundtrips_each_status_and_keeps_exact_original_boundaries() {
    for value in [
        EnrollmentServiceResponseV1::Permit(vec![1; 2048]),
        EnrollmentServiceResponseV1::EvidenceReady,
        EnrollmentServiceResponseV1::Pending,
        EnrollmentServiceResponseV1::CredentialReady,
        EnrollmentServiceResponseV1::Credential(vec![2; ENROLLMENT_RESULT_MAX_BYTES_V1]),
    ] {
        let original = value.canonical_wire().unwrap();
        assert_eq!(
            EnrollmentServiceResponseV1::decode_canonical(&original).unwrap(),
            value
        );
        let mut trailing = original;
        trailing.push(0);
        assert!(EnrollmentServiceResponseV1::decode_canonical(&trailing).is_err());
    }
    for value in [
        EnrollmentServiceResponseV1::Permit(vec![]),
        EnrollmentServiceResponseV1::Permit(vec![0; 2049]),
        EnrollmentServiceResponseV1::Credential(vec![]),
        EnrollmentServiceResponseV1::Credential(vec![0; ENROLLMENT_RESULT_MAX_BYTES_V1 + 1]),
    ] {
        assert!(value.canonical_wire().is_err());
    }
    assert!(EnrollmentServiceResponseV1::decode_canonical(&[]).is_err());
}

#[test]
fn outcome_headers_are_exact_closed_and_status_bound() {
    use iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1 as Refusal;
    for outcome in Refusal::ALL
        .iter()
        .map(|reason| EnrollmentServiceOutcomeV1::Refused(*reason))
        .chain([
            EnrollmentServiceOutcomeV1::DeliveryWithheld(Refusal::AccountNotApproved),
            EnrollmentServiceOutcomeV1::DeliveryWithheld(Refusal::AccountFrozen),
            EnrollmentServiceOutcomeV1::OutcomeUnknown,
        ])
    {
        let (name, value) = outcome.header();
        let upper = name.to_ascii_uppercase();
        for name in [name, upper.as_str()] {
            assert_eq!(
                EnrollmentServiceOutcomeV1::from_headers(
                    outcome.status(),
                    [
                        ("content-type", b"text/plain".as_slice()),
                        (name, value.as_bytes())
                    ],
                )
                .unwrap(),
                Some(outcome)
            );
        }
        // The same status with another outcome, or another status, never matches.
        assert!(EnrollmentServiceOutcomeV1::from_headers(503, [(name, value.as_bytes())]).is_err());
        assert!(
            EnrollmentServiceOutcomeV1::from_headers(
                outcome.status(),
                [(name, value.as_bytes()), (name, value.as_bytes())]
            )
            .is_err()
        );
    }
    // Identical 403 statuses carry different, distinguishable outcomes.
    assert_ne!(
        EnrollmentServiceOutcomeV1::from_headers(
            403,
            [(ENROLLMENT_REFUSAL_CODE_HEADER_V1, b"12".as_slice())]
        )
        .unwrap(),
        EnrollmentServiceOutcomeV1::from_headers(
            403,
            [(ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1, b"12".as_slice())]
        )
        .unwrap()
    );
    assert_eq!(
        EnrollmentServiceOutcomeV1::from_headers(503, [("retry-after", b"1".as_slice())]).unwrap(),
        None
    );
    for (name, value) in [
        (ENROLLMENT_REFUSAL_CODE_HEADER_V1, b"0".as_slice()),
        (ENROLLMENT_REFUSAL_CODE_HEADER_V1, b"13"),
        (ENROLLMENT_REFUSAL_CODE_HEADER_V1, b"012"),
        (ENROLLMENT_REFUSAL_CODE_HEADER_V1, b"+1"),
        (ENROLLMENT_REFUSAL_CODE_HEADER_V1, b""),
        (ENROLLMENT_REFUSAL_CODE_HEADER_V1, b"65536"),
        (ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1, b"1"),
        (ENROLLMENT_OUTCOME_HEADER_V1, b"Unknown"),
    ] {
        assert!(
            EnrollmentServiceOutcomeV1::from_headers(403, [(name, value)]).is_err(),
            "{name}: {value:?}"
        );
    }
    assert!(
        EnrollmentServiceOutcomeV1::from_headers(
            403,
            [
                (ENROLLMENT_REFUSAL_CODE_HEADER_V1, b"11".as_slice()),
                (ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1, b"11".as_slice()),
            ]
        )
        .is_err()
    );
}
