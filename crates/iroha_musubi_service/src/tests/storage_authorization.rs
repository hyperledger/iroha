// Real private-route authentication preserves the finite call bound at storage dispatch.

use super::*;
use std::time::Instant;

struct ObservedStorageCall {
    request: MusubiStorageCoordinationRequestV1,
    digest: [u8; 32],
    issued: u64,
    expires: u64,
    observed: u64,
    deadline: Instant,
}
struct ObserveStorageAuthorization(Arc<Mutex<Vec<ObservedStorageCall>>>);
impl MusubiStorageCoordinationBackendV1 for ObserveStorageAuthorization {
    fn verify_current_registration(
        &self,
        _: &MusubiStorageCoordinationRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        panic!("this backend never returns a cacheable success")
    }
    fn coordinate_storage(
        &mut self,
        verified: &VerifiedStorageCoordinationRequestV1<'_>,
    ) -> Result<MusubiStorageCoordinationResponseV1, MusubiPublicationServiceBackendErrorV1> {
        self.0.lock().unwrap().push(ObservedStorageCall {
            request: verified.request().clone(),
            digest: verified.canonical_request_digest(),
            issued: verified.authorization_issued_at_ms(),
            expires: verified.authorization_expires_at_ms(),
            observed: verified.observed_at_unix_ms(),
            deadline: verified.deadline(),
        });
        Err(MusubiPublicationServiceBackendErrorV1::Retryable)
    }
}

#[test]
fn authenticated_storage_dispatch_carries_exact_request_and_original_call_bounds() {
    let mut fixture = control_service_fixture(false, false);
    let calls = Arc::new(Mutex::new(Vec::new()));
    fixture.service.storage = Box::new(ObserveStorageAuthorization(Arc::clone(&calls)));
    let request = fixture.storage_request.clone();
    let body = norito::encode_canonical(&request).unwrap();
    let expected_digest = request_digest(
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        &body,
    )
    .unwrap();
    let before = Instant::now();
    let response = control_storage_response(&mut fixture, &request, 2_000);
    let after = Instant::now();
    assert_eq!(response.status, 503);
    {
        let observed = calls.lock().unwrap();
        let call = &observed[0];
        assert_eq!(observed.len(), 1);
        assert_eq!(call.request, request);
        assert_eq!(call.digest, expected_digest);
        assert_eq!(call.issued, 2_000);
        assert_eq!(call.expires, 2_000 + DEFAULT_AUTHORIZATION_LIFETIME_MS);
        assert_eq!(call.observed, 2_001);
        let remaining = Duration::from_millis(call.expires - call.observed);
        assert!(call.deadline >= before + remaining);
        assert!(call.deadline <= after + remaining);
    }
    // The HTTP journal allows a new authenticated observation after a retryable result. Both
    // calls expose their actual bounds; retaining original paid-operation limits is the native
    // coordinator's separate responsibility, never inferred from this fresh transport request.
    assert_eq!(
        control_storage_response(&mut fixture, &request, 3_000).status,
        503
    );
    let observed = calls.lock().unwrap();
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[1].digest, observed[0].digest);
    assert_eq!(observed[1].request, observed[0].request);
    assert_eq!(observed[1].issued, 3_000);
    assert_eq!(
        observed[1].expires,
        3_000 + DEFAULT_AUTHORIZATION_LIFETIME_MS
    );
    assert_eq!(
        observed[0].expires,
        2_000 + DEFAULT_AUTHORIZATION_LIFETIME_MS
    );
}

#[test]
fn elapsed_authenticated_storage_call_never_reaches_effectful_backend() {
    let mut fixture = control_service_fixture(false, false);
    let calls = Arc::new(Mutex::new(Vec::new()));
    fixture.service.storage = Box::new(ObserveStorageAuthorization(Arc::clone(&calls)));
    let request = fixture.storage_request.clone();
    let body = norito::encode_canonical(&request).unwrap();
    let header = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        request.operation_id,
        &body,
        2_000,
    );
    let started = Instant::now()
        .checked_sub(Duration::from_millis(MAX_AUTHORIZATION_LIFETIME_MS + 1))
        .expect("fixture clock supports expired authorization");
    let error = fixture
        .service
        .handle_storage_coordination(
            MusubiPublicationPrivateHttpRequestV1 {
                method: "POST",
                path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
                content_type: APPLICATION_NORITO,
                authorization: Some(&header),
                seed_ingress_metadata: None,
                body: &body,
            },
            2_001,
            started,
        )
        .expect_err("elapsed original monotonic interval refuses dispatch");
    assert_eq!(
        error.code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationExpired
    );
    assert!(calls.lock().unwrap().is_empty());
    // Refusal releases the journal's pending reservation but preserves authorization replay.
    assert_eq!(
        control_storage_response(&mut fixture, &request, 3_000).status,
        503
    );
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn changed_request_and_exact_expiry_cannot_mint_storage_dispatch() {
    let mut fixture = control_service_fixture(false, false);
    let calls = Arc::new(Mutex::new(Vec::new()));
    fixture.service.storage = Box::new(ObserveStorageAuthorization(Arc::clone(&calls)));
    let mut request = fixture.storage_request.clone();
    let original_body = norito::encode_canonical(&request).unwrap();
    let header = control_authorization_header(
        &fixture.runtime,
        MusubiPublicationRuntimeOperationV1::StorageCoordination,
        request.operation_id,
        &original_body,
        2_000,
    );
    request.expected_policy_revision += 1;
    let changed_body = norito::encode_canonical(&request).unwrap();
    let http = |body| MusubiPublicationPrivateHttpRequestV1 {
        method: "POST",
        path: MUSUBI_PUBLICATION_STORAGE_COORDINATION_PATH_V1,
        content_type: APPLICATION_NORITO,
        authorization: Some(&header),
        seed_ingress_metadata: None,
        body,
    };
    let changed = fixture
        .service
        .handle_storage_coordination(http(&changed_body), 2_001, Instant::now())
        .expect_err("signature does not authorize substituted request bytes");
    assert_eq!(
        changed.code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationInvalid
    );
    assert!(calls.lock().unwrap().is_empty());
    let expired = fixture
        .service
        .handle_storage_coordination(
            http(&original_body),
            2_000 + DEFAULT_AUTHORIZATION_LIFETIME_MS,
            Instant::now(),
        )
        .expect_err("inclusive transport boundary has no remaining paid-work interval");
    assert_eq!(
        expired.code,
        MusubiPublicationServiceErrorCodeV1::AuthorizationExpired
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn closed_backend_errors_preserve_class_and_expose_no_payload() {
    for (error, text) in [
        (
            MusubiPublicationServiceBackendErrorV1::Retryable,
            "Musubi publication backend is temporarily unavailable",
        ),
        (
            MusubiPublicationServiceBackendErrorV1::Permanent,
            "Musubi publication backend requires configuration or state changes",
        ),
    ] {
        assert_eq!(error.to_string(), text);
        let erased: &dyn std::error::Error = &error;
        assert!(erased.source().is_none());
        let reported = eyre::Report::new(error);
        assert_eq!(reported.to_string(), text);
        assert_eq!(
            reported.downcast_ref::<MusubiPublicationServiceBackendErrorV1>(),
            Some(&error)
        );
    }
}
