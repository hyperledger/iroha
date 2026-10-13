// Actual CAR route custody cutoff tests; the quota/callback path uses a durable provider fixture.
use crate::sorafs::stream_token_admission::tests::ServingAdmissionFixture;
use iroha_data_model::sorafs::reputation::{
    StreamTokenExcludedKindV1 as CustodyExcluded, StreamTokenValidationStatusV1 as CustodyStatus,
};
use sorafs_manifest::signer::stream_token_evidence::SignerStreamTokenObservationPhaseV1 as CustodyPhase;

fn custody_admission_context() -> (
    TokenTestContext,
    Arc<SignedFixture>,
    ServingAdmissionFixture,
    RangeCleanupTestOwner,
) {
    custody_admission_context_at(None)
}
fn custody_admission_context_at(
    now: Option<u64>,
) -> (
    TokenTestContext,
    Arc<SignedFixture>,
    ServingAdmissionFixture,
    RangeCleanupTestOwner,
) {
    let mut context = token_test_context();
    let mut app = Arc::try_unwrap(context.app).unwrap_or_else(|_| panic!("exclusive test app"));
    let fixture = now.map_or_else(
        || SignedFixture::for_api([0xAB; 32], 7, TestSignerMode::Sign),
        |now| SignedFixture::for_api_at([0xAB; 32], 7, TestSignerMode::Sign, now),
    );
    let issuer = fixture.issuer().unwrap();
    assert_eq!(
        context.verifying_key_hex,
        hex::encode(issuer.verifying_key_bytes())
    );
    app.stream_token_issuer = Some(Arc::new(issuer));
    let admission = ServingAdmissionFixture::new();
    app.stream_token_admission_capture = Some(admission.capture.clone());
    let cleanup = RangeCleanupTestOwner::install(&mut app, 64);
    context.app = Arc::new(app);
    (context, fixture, admission, cleanup)
}
fn custody_route_headers(context: &TokenTestContext, token: &str, nonce: &str) -> HeaderMap {
    let manifest = context.manifest();
    alias_bound_car_range_headers(
        manifest.chunk_profile_handle(),
        manifest.content_length(),
        token,
        nonce,
    )
}
fn assert_custody_exclusion(admission: &ServingAdmissionFixture, token: &StreamTokenV1) {
    let expected = CustodyStatus::Excluded(CustodyExcluded::SignerAuthorityUnavailable);
    let requests = admission.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].status, expected);
    assert_eq!(
        requests[0].token_body_digest,
        Some(*token.body_hash().unwrap().as_bytes())
    );
    assert_eq!(
        requests[0].token_key_version,
        Some(token.body.token_pk_version)
    );
    assert_eq!(admission.active_leases(), 0);
    let outcomes = admission.outcomes();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].status, expected);
    assert_eq!(outcomes[0].token_body_digest, requests[0].token_body_digest);
    assert_eq!(
        outcomes[0].validated_at_unix_ms,
        requests[0].validated_at_unix_ms
    );
    assert!(!outcomes[0].status.counts_for_provider());
    assert!(!outcomes[0].status.is_violation());
}
#[tokio::test]
async fn car_route_current_custody_cutoff_excludes_revoked_unavailable_stale_and_wrong_phase() {
    for fault in [
        ObserverFault::SignerRevoked,
        ObserverFault::AttesterRevoked,
        ObserverFault::Unavailable,
        ObserverFault::Stale,
        ObserverFault::WrongPhase,
        ObserverFault::WrongRequest,
    ] {
        let (context, signer, admission, cleanup) = custody_admission_context();
        let encoded = issue_token_base64(&context, TokenOverrides::default()).await;
        let token = decode_token_base64(&encoded).unwrap();
        let before = signer
            .observer_calls
            .load(std::sync::atomic::Ordering::SeqCst);
        signer.faults.lock().unwrap().insert(before + 1, fault);
        let response = context
            .car_range(
                custody_route_headers(&context, &encoded, "custody-denied"),
                8097,
            )
            .await;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{fault:?}"
        );
        assert_custody_exclusion(&admission, &token);
        assert_eq!(
            signer
                .observer_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            before + 1
        );
        assert_eq!(
            signer.requests.lock().unwrap().last().unwrap().phase,
            CustodyPhase::BeforeAdmission
        );
        assert_eq!(signer.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        cleanup.finish().await;
    }
}
#[tokio::test]
async fn car_route_fresh_admissions_have_unique_challenges_and_exact_final_quota_time() {
    let host_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let (context, signer, admission, cleanup) =
        custody_admission_context_at(Some(host_ms.checked_sub(1_000).unwrap()));
    let encoded = issue_token_base64(&context, TokenOverrides::default()).await;
    let before = signer
        .observer_calls
        .load(std::sync::atomic::Ordering::SeqCst);
    let final_ms = signer.clock.now.load(std::sync::atomic::Ordering::SeqCst) + 100;
    *signer.finality.advance_clock.lock().unwrap() = Some((
        signer
            .finality
            .validations
            .load(std::sync::atomic::Ordering::SeqCst)
            + 2,
        signer.clock.clone(),
        final_ms,
    ));
    for nonce in ["fresh-custody-1", "fresh-custody-2"] {
        let response = context
            .car_range(custody_route_headers(&context, &encoded, nonce), 8098)
            .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        let bytes = body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(!bytes.is_empty());
    }
    {
        let requests = signer.requests.lock().unwrap();
        let admissions = &requests[before..];
        assert_eq!(admissions.len(), 2);
        assert!(
            admissions
                .iter()
                .all(|request| request.phase == CustodyPhase::BeforeAdmission)
        );
        assert_ne!(admissions[0].challenge, admissions[1].challenge);
    }
    let requests = admission.requests();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.status, CustodyStatus::Accepted);
        assert_eq!(request.validated_at_unix_ms, final_ms);
        assert_eq!(request.quota.unwrap().observed_at_epoch, final_ms / 1_000);
    }
    let outcomes = admission.outcomes();
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.status == CustodyStatus::Accepted
                && outcome.validated_at_unix_ms == final_ms)
    );
    cleanup.finish().await;
    assert_eq!(admission.active_leases(), 0);
    assert_eq!(signer.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}
#[tokio::test]
async fn car_route_expiry_during_observer_wait_is_excluded_without_accepted_lease() {
    let (context, signer, admission, cleanup) = custody_admission_context();
    let encoded = issue_token_base64(
        &context,
        TokenOverrides {
            ttl_secs: Some(60),
            ..TokenOverrides::default()
        },
    )
    .await;
    let token = decode_token_base64(&encoded).unwrap();
    let expiry = token.body.ttl_epoch * 1_000;
    // Keep the freshly signed observation valid across the simulated 100 ms wait; only token
    // expiry crosses this boundary. Wall-clock sleeps and manufactured token signatures are absent.
    signer
        .clock
        .now
        .store(expiry - 100, std::sync::atomic::Ordering::SeqCst);
    let next = signer
        .observer_calls
        .load(std::sync::atomic::Ordering::SeqCst)
        + 1;
    signer
        .observer_return_clock
        .lock()
        .unwrap()
        .insert(next, expiry);
    let response = context
        .car_range(
            custody_route_headers(&context, &encoded, "expiry-in-observer"),
            8099,
        )
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_custody_exclusion(&admission, &token);
    assert_eq!(
        signer
            .observer_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        next
    );
    cleanup.finish().await;
}
#[tokio::test]
async fn car_route_late_finality_and_clock_drift_never_admit_or_penalize_provider() {
    for boundary in 0..3 {
        let (context, signer, admission, cleanup) = custody_admission_context();
        let encoded = issue_token_base64(
            &context,
            TokenOverrides {
                ttl_secs: Some(60),
                ..TokenOverrides::default()
            },
        )
        .await;
        let token = decode_token_base64(&encoded).unwrap();
        let next = signer
            .observer_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            + 1;
        match boundary {
            0 => {
                signer.observer_return_tip.lock().unwrap().insert(next, 101);
            }
            1 => {
                let now = signer.clock.now.load(std::sync::atomic::Ordering::SeqCst);
                signer
                    .observer_return_clock
                    .lock()
                    .unwrap()
                    .insert(next, now - 1);
            }
            _ => {
                let expiry = token.body.ttl_epoch * 1_000;
                signer
                    .clock
                    .now
                    .store(expiry - 100, std::sync::atomic::Ordering::SeqCst);
                *signer.finality.advance_clock.lock().unwrap() = Some((
                    signer
                        .finality
                        .validations
                        .load(std::sync::atomic::Ordering::SeqCst)
                        + 2,
                    signer.clock.clone(),
                    expiry,
                ));
            }
        }
        let response = context
            .car_range(
                custody_route_headers(&context, &encoded, "late-authority-change"),
                8100,
            )
            .await;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "boundary {boundary}"
        );
        assert_custody_exclusion(&admission, &token);
        cleanup.finish().await;
    }
}
#[tokio::test]
async fn car_route_static_token_rejections_perform_zero_observer_io() {
    for attack in 0..4 {
        let (context, signer, admission, cleanup) = custody_admission_context();
        let encoded = issue_token_base64(&context, TokenOverrides::default()).await;
        let mut token = decode_token_base64(&encoded).unwrap();
        let (encoded, expected) = match attack {
            0 => ("malformed%%%".to_owned(), StatusCode::BAD_REQUEST),
            1 => {
                token.signature[0] ^= 1;
                (
                    encode_token_base64(&token).unwrap(),
                    StatusCode::UNAUTHORIZED,
                )
            }
            2 => {
                token.body.token_pk_version += 1;
                (signed_test_token(token.body), StatusCode::UNAUTHORIZED)
            }
            _ => {
                token.body.max_streams = 0;
                (signed_test_token(token.body), StatusCode::BAD_REQUEST)
            }
        };
        let before = signer
            .observer_calls
            .load(std::sync::atomic::Ordering::SeqCst);
        let response = context
            .car_range(
                custody_route_headers(&context, &encoded, "static-rejection"),
                8101,
            )
            .await;
        assert_eq!(response.status(), expected, "attack {attack}");
        assert_eq!(
            signer
                .observer_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            before
        );
        assert_eq!(admission.active_leases(), 0);
        let outcomes = admission.outcomes();
        assert_eq!(outcomes.len(), 1);
        assert!(
            outcomes
                .iter()
                .all(|outcome| !outcome.status.counts_for_provider()
                    && !outcome.status.is_violation())
        );
        cleanup.finish().await;
    }
}
#[tokio::test]
async fn car_route_authority_and_audit_outage_cannot_fabricate_terminal_or_accepted_admission() {
    let (context, signer, admission, cleanup) = custody_admission_context();
    let encoded = issue_token_base64(&context, TokenOverrides::default()).await;
    let next = signer
        .observer_calls
        .load(std::sync::atomic::Ordering::SeqCst)
        + 1;
    signer
        .faults
        .lock()
        .unwrap()
        .insert(next, ObserverFault::Unavailable);
    admission.unavailable();
    let response = context
        .car_range(
            custody_route_headers(&context, &encoded, "double-outage"),
            8102,
        )
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(admission.requests().is_empty());
    assert!(admission.outcomes().is_empty());
    assert_eq!(admission.active_leases(), 0);
    cleanup.finish().await;
}
