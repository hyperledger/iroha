//! Token issuance policy assertions migrated from the retired raw-signature fixture.

use super::*;
use ed25519_dalek::SigningKey;
struct FailingTryRng;
#[derive(Debug)]
struct FailingTryRngError;
impl std::fmt::Display for FailingTryRngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failing stream token RNG")
    }
}
impl TryRngCore for FailingTryRng {
    type Error = FailingTryRngError;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(FailingTryRngError)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(FailingTryRngError)
    }
    fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
        Err(FailingTryRngError)
    }
}
impl TryCryptoRng for FailingTryRng {}
use super::signer_test_support::*;
use sorafs_manifest::signer::stream_token::SignerStreamTokenExpectedV1;
use sorafs_manifest::signer::stream_token_evidence::SignerStreamTokenObservationPhaseV1 as Phase;

fn issuer_and_signer(limit: u32, mode: TestSignerMode) -> (StreamTokenIssuer, Arc<SignedFixture>) {
    let signer = SignedFixture::new(limit, mode);
    let issuer = signer
        .issuer()
        .expect("independent signed startup evidence");
    (issuer, signer)
}
fn sample_body() -> StreamTokenBodyV1 {
    StreamTokenBodyV1 {
        token_id: "0123456789abcdef0123456789abcdef".to_string(),
        manifest_cid: vec![0x01, 0x55, 0x01],
        provider_id: [0xAA; 32],
        profile_handle: "sorafs.sf1@1.0.0".to_string(),
        max_streams: 4,
        ttl_epoch: 1_731_234_567,
        rate_limit_bytes: 10 * 1024 * 1024,
        issued_at: 1_731_234_000,
        requests_per_minute: 120,
        token_pk_version: 3,
    }
}
#[test]
fn sign_and_verify_roundtrip() {
    let signing = SigningKey::from_bytes(&[0x42; 32]);
    let verifying = signing.verifying_key();
    let body = sample_body();
    let token = StreamTokenV1::sign(body.clone(), &signing).expect("sign");
    token.verify(&verifying).expect("verify");
    assert_eq!(token.body, body);
    let hash = token.body_hash().expect("hash");
    let bytes = body.to_canonical_bytes().expect("bytes");
    assert_eq!(hash.as_bytes(), blake3::hash(&bytes).as_bytes());
}
#[test]
fn new_token_id_reports_rng_failure() {
    let mut rng = FailingTryRng;
    match new_token_id_with_rng(&mut rng) {
        Err(StreamTokenIssuerError::RandomBytes { operation, message }) => {
            assert_eq!(operation, "issuing stream token id");
            assert!(message.contains("failing stream token RNG"));
        }
        Ok(_) => panic!("RNG failure must be reported"),
        Err(other) => panic!("expected RNG failure, got {other:?}"),
    }
}
#[test]
fn signer_qualification_rejects_zero_public_fields() {
    // Retired self-reported revision/digest markers are replaced by mandatory complete public pins.
    for zero_revision in [true, false] {
        let mut storage = storage_config(2);
        let signer_backend = storage.stream_tokens.signer.as_mut().unwrap();
        if zero_revision {
            signer_backend.key_revision = 0;
        } else {
            signer_backend.policy_digest = [0; 32];
        }
        assert!(matches!(
            StreamTokenSignerPinsV1::from_config(&storage, CHAIN, NETWORK),
            Err(StreamTokenIssuerError::InvalidSignerConfig)
        ));
    }
}
#[test]
fn disabled_issuance_rejects_an_unexpected_runtime_signer() {
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    let state = Arc::new(State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    ));
    let signer = SignedFixture::new(2, TestSignerMode::Sign);
    let approved =
        StreamTokenApprovedCustodyAnchorV1::new(signer.pins.config_digest(), anchor(100)).unwrap();
    let mut disabled = signer.storage.clone();
    disabled.stream_tokens.enabled = false;
    disabled.stream_tokens.signer = None;
    assert!(
        StreamTokenIssuer::from_config(&disabled, CHAIN, NETWORK, None, None, None, state.clone())
            .unwrap()
            .is_none()
    );
    for dependency in 0..3 {
        let client: Option<Arc<dyn StreamTokenSignerClientV1>> =
            (dependency == 0).then(|| -> Arc<dyn StreamTokenSignerClientV1> { signer.clone() });
        let observer: Option<Arc<dyn StreamTokenStateObserverClientV1>> =
            (dependency == 1).then(|| -> Arc<dyn StreamTokenStateObserverClientV1> {
                Arc::new(SignedObserver(signer.clone()))
            });
        assert!(matches!(
            StreamTokenIssuer::from_config(
                &disabled,
                CHAIN,
                NETWORK,
                client,
                observer,
                (dependency == 2).then_some(approved),
                state.clone()
            ),
            Err(StreamTokenIssuerError::UnexpectedSignerDependency)
        ));
    }
    assert!(matches!(
        StreamTokenIssuer::from_config(
            &signer.storage,
            CHAIN,
            NETWORK,
            None,
            None,
            None,
            state.clone()
        ),
        Err(StreamTokenIssuerError::MissingSignerClient)
    ));
    assert!(matches!(
        StreamTokenIssuer::from_config(
            &signer.storage,
            CHAIN,
            NETWORK,
            Some(signer.clone()),
            None,
            None,
            state.clone()
        ),
        Err(StreamTokenIssuerError::MissingStateObserver)
    ));
    assert!(matches!(
        StreamTokenIssuer::from_config(
            &signer.storage,
            CHAIN,
            NETWORK,
            Some(signer.clone()),
            Some(Arc::new(SignedObserver(signer.clone()))),
            None,
            state.clone()
        ),
        Err(StreamTokenIssuerError::MissingApprovedAnchor)
    ));
    assert!(matches!(
        StreamTokenIssuer::from_config(
            &signer.storage,
            CHAIN,
            NETWORK,
            Some(signer.clone()),
            Some(Arc::new(SignedObserver(signer.clone()))),
            Some(approved),
            state
        ),
        Err(StreamTokenIssuerError::SignerBindingMismatch)
    ));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.observer_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn runtime_signer_binding_fails_closed() {
    let signer = SignedFixture::new(2, TestSignerMode::Sign);
    signer
        .issuer()
        .expect("canonical signer_backend binding and signed evidence");
    let mut storage = signer.storage.clone();
    storage.stream_tokens.signer = None;
    assert!(matches!(
        StreamTokenSignerPinsV1::from_config(&storage, CHAIN, NETWORK),
        Err(StreamTokenIssuerError::InvalidSignerConfig)
    ));
    for invalid_handle in [
        "mock-stream-token",
        "https://operator:secret@signer",
        "https://signer/path?credential=secret",
        "https://signer/path#fragment",
        "provider:prod/%73tream-token/v1",
        "provider:prod\\stream-token\\v1",
        "software://sorafs/stream-token/primary?credential=secret",
    ] {
        let mut storage = signer.storage.clone();
        storage
            .stream_tokens
            .signer
            .as_mut()
            .unwrap()
            .runtime_handle = invalid_handle.into();
        assert!(matches!(
            signer.issuer_with_storage(&storage),
            Err(StreamTokenIssuerError::InvalidSignerConfig)
        ));
    }
    let mut mismatched = SignedFixture::new(2, TestSignerMode::Sign);
    Arc::get_mut(&mut mismatched).unwrap().handle = "hsm://sorafs/other-token/primary".into();
    assert!(matches!(
        mismatched.issuer(),
        Err(StreamTokenIssuerError::SignerBindingMismatch)
    ));
    let mut storage = signer.storage.clone();
    let mut weak = [0; 32];
    weak[0] = 1;
    storage.stream_tokens.signer.as_mut().unwrap().public_key = weak;
    assert!(matches!(
        signer.issuer_with_storage(&storage),
        Err(StreamTokenIssuerError::InvalidSignerConfig)
    ));
    storage.stream_tokens.signer.as_mut().unwrap().public_key = SigningKey::from_bytes(&[0x34; 32])
        .verifying_key()
        .to_bytes();
    assert!(matches!(
        signer.issuer_with_storage(&storage),
        Err(StreamTokenIssuerError::SignerEvidenceInvalid)
    ));
}
#[test]
fn runtime_signer_qualification_fails_closed_at_startup() {
    let signer = SignedFixture::new(2, TestSignerMode::Sign);
    for field in 0..3 {
        let mut storage = signer.storage.clone();
        let signer_backend = storage.stream_tokens.signer.as_mut().unwrap();
        match field {
            0 => signer_backend.key_revision = 0,
            1 => signer_backend.policy_digest = [0; 32],
            _ => signer_backend.attester.authority.policy_digest = [0; 32],
        }
        assert!(matches!(
            signer.issuer_with_storage(&storage),
            Err(StreamTokenIssuerError::InvalidSignerConfig)
        ));
    }
    let mut drifted = signer.storage.clone();
    drifted.stream_tokens.signer.as_mut().unwrap().key_revision += 1;
    assert!(matches!(
        signer.issuer_with_storage(&drifted),
        Err(StreamTokenIssuerError::SignerEvidenceInvalid)
    ));
    for fault in [
        ObserverFault::WrongKey,
        ObserverFault::SignerRevoked,
        ObserverFault::AttesterRevoked,
        ObserverFault::WrongRecord,
        ObserverFault::WrongChain,
        ObserverFault::WrongRequest,
        ObserverFault::WrongPhase,
        ObserverFault::Stale,
    ] {
        let signer = SignedFixture::new(2, TestSignerMode::Sign);
        signer.faults.lock().unwrap().insert(1, fault);
        assert!(matches!(
            signer.issuer(),
            Err(StreamTokenIssuerError::SignerEvidenceInvalid)
        ));
        assert_eq!(signer.calls.load(Ordering::Relaxed), 0);
    }
    let unavailable = SignedFixture::new(2, TestSignerMode::Sign);
    unavailable
        .faults
        .lock()
        .unwrap()
        .insert(1, ObserverFault::Unavailable);
    assert!(matches!(
        unavailable.issuer(),
        Err(StreamTokenIssuerError::RuntimeSignerUnavailable)
    ));
    let mut test_marked = SignedFixture::new(2, TestSignerMode::Sign);
    Arc::get_mut(&mut test_marked).unwrap().handle = "hsm://test/stream-token/primary".into();
    assert!(matches!(
        test_marked.issuer(),
        Err(StreamTokenIssuerError::SignerBindingMismatch)
    ));
}
#[test]
fn verify_rejects_modified_body() {
    let signing = SigningKey::from_bytes(&[0x24; 32]);
    let verifying = signing.verifying_key();
    let token = StreamTokenV1::sign(sample_body(), &signing).expect("sign");
    let mut tampered = token.clone();
    tampered.body.max_streams = 8;
    let err = tampered.verify(&verifying).expect_err("should fail");
    assert!(matches!(err, StreamTokenError::SignatureInvalid(_)));
}
fn issuer_with_limit(limit: u32) -> StreamTokenIssuer {
    issuer_with_capacity(limit, MAX_ISSUANCE_SUBJECTS)
}
fn issuer_with_capacity(limit: u32, max_issuance_budgets: usize) -> StreamTokenIssuer {
    let (mut issuer, _) = issuer_and_signer(limit, TestSignerMode::Sign);
    issuer.max_issuance_budgets = max_issuance_budgets;
    issuer
}
fn quota_subject(label: &str) -> StreamTokenQuotaSubject {
    let seed = *blake3::hash(label.as_bytes()).as_bytes();
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = PublicKey::from_bytes(
        iroha_crypto::Algorithm::Ed25519,
        &signing_key.verifying_key().to_bytes(),
    )
    .expect("derived operator fixture key");
    StreamTokenQuotaSubject::from_authenticated_operator(&public_key)
}
#[test]
fn issuer_signs_exact_payload_and_verifies_before_release() {
    let (issuer, signer) = issuer_and_signer(2, TestSignerMode::Sign);
    let issue = issuer
        .issue_token(
            quota_subject("credential-exact"),
            vec![0xAA],
            [0x11; 32],
            "sorafs.sf1@1.0.0".to_owned(),
            TokenOverrides::default(),
            None,
        )
        .expect("issue verified token");
    let payloads = signer
        .signing_payloads
        .lock()
        .expect("captured signing payloads");
    assert_eq!(
        payloads.as_slice(),
        [issue
            .token
            .body
            .signing_payload_bytes()
            .expect("canonical signing payload")]
    );
    issue
        .token
        .verify(issuer.verifying_key())
        .expect("issuer must release only a strictly verified token");
    assert_eq!(
        signer.observer_calls.load(Ordering::Relaxed),
        4,
        "startup, BeforeProvider, AfterCommit and BeforeRelease require distinct signed observations"
    );
    let requests = signer.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.phase)
            .collect::<Vec<_>>(),
        vec![
            Phase::Startup,
            Phase::BeforeProvider,
            Phase::AfterCommit,
            Phase::BeforeRelease
        ]
    );
    assert_eq!(
        requests
            .iter()
            .map(|request| request.challenge)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
}
#[test]
fn admitted_account_policy_limits_the_shared_issuer_and_isolates_quotas() {
    use sorafs_manifest::provider_advert::account_read::RegisteredAccountReadV1;
    let (issuer, _) = issuer_and_signer(5, TestSignerMode::Sign);
    let public =
        iroha_crypto::KeyPair::try_from_seed(vec![0x51; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let account = iroha_data_model::account::AccountId::new(public.public_key().clone());
    let network = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"account quota network",
        )),
    );
    let subject = StreamTokenQuotaSubject::from_authenticated_account(network, &account);
    assert_ne!(
        subject,
        StreamTokenQuotaSubject::from_authenticated_operator(public.public_key())
    );
    let policy = RegisteredAccountReadV1 {
        https_host: "storage.example.com".into(),
        https_port: 443,
        ttl_secs: 10,
        max_streams: 1,
        rate_limit_bytes: 1024,
        requests_per_minute: 1,
    };
    let issue = issuer
        .issue_token(
            subject,
            vec![0xAA],
            [0x11; 32],
            "sorafs.sf1@1.0.0".into(),
            TokenOverrides::default(),
            Some(&policy),
        )
        .unwrap();
    assert_eq!(issue.token.body.max_streams, 1);
    assert_eq!(issue.token.body.rate_limit_bytes, 1024);
    assert_eq!(issue.token.body.ttl_epoch - issue.token.body.issued_at, 10);
    assert_eq!(issue.remaining_quota, 0);
    assert!(matches!(
        issuer.issue_token(
            subject,
            vec![0xAA],
            [0x11; 32],
            "sorafs.sf1@1.0.0".into(),
            TokenOverrides::default(),
            Some(&policy)
        ),
        Err(StreamTokenIssuerError::IssuanceQuotaExceeded { limit: 1, .. })
    ));
    let excessive = TokenOverrides {
        max_streams: Some(2),
        ..Default::default()
    };
    assert!(matches!(
        issuer.issue_token(
            subject,
            vec![0xAA],
            [0x11; 32],
            "sorafs.sf1@1.0.0".into(),
            excessive,
            Some(&policy)
        ),
        Err(StreamTokenIssuerError::InvalidPolicy { .. })
    ));
}
#[test]
fn runtime_signer_qualification_is_fenced_before_and_after_signing() {
    for (label, call, expected_sign_calls) in [
        ("before signing", 2, 0),
        ("after commit", 3, 1),
        ("before release", 4, 1),
    ] {
        let signer = SignedFixture::new(1, TestSignerMode::Sign);
        signer
            .faults
            .lock()
            .unwrap()
            .insert(call, ObserverFault::SignerRevoked);
        let issuer = signer.issuer().expect("independent signed startup");
        assert!(
            matches!(
                issuer.issue_token(
                    quota_subject("credential-drift"),
                    vec![0xAA],
                    PROVIDER,
                    "sorafs.sf1@1.0.0".into(),
                    TokenOverrides::default(),
                    None,
                ),
                Err(StreamTokenIssuerError::SignerEvidenceInvalid)
            ),
            "{label}"
        );
        assert_eq!(
            signer.calls.load(Ordering::Relaxed),
            expected_sign_calls,
            "{label}"
        );
        assert!(matches!(
            issuer.issue_token(
                quota_subject("credential-drift"),
                vec![0xAA],
                PROVIDER,
                "sorafs.sf1@1.0.0".into(),
                TokenOverrides::default(),
                None,
            ),
            Err(StreamTokenIssuerError::IssuanceQuotaExceeded { .. })
        ));
    }
}
#[test]
fn unavailable_completed_proof_source_prevents_provider_call() {
    let signer = SignedFixture::new(1, TestSignerMode::Sign);
    let issuer = signer.issuer().expect("signed startup");
    signer
        .finality
        .completed_proof_source_available
        .store(false, Ordering::SeqCst);
    assert!(matches!(
        issuer.issue_token(
            quota_subject("missing-completion-source"),
            vec![0xAA],
            PROVIDER,
            "sorafs.sf1@1.0.0".into(),
            TokenOverrides::default(),
            None,
        ),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.recover_calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.observer_calls.load(Ordering::SeqCst), 1);
    assert!(issuer.issuance_budgets.lock().unwrap().is_empty());
}
#[test]
fn signer_rechecks_completed_proof_source_before_provider_io() {
    let signer = SignedFixture::new(1, TestSignerMode::Sign);
    let issuer = signer.issuer().expect("signed startup");
    let mut body = sample_body();
    body.provider_id = PROVIDER;
    body.token_pk_version = u32::try_from(issuer.signer.pins().binding().key_revision)
        .expect("fixture key revision fits token field");
    body.issued_at = NOW_MS / 1_000;
    body.ttl_epoch = body.issued_at + 60;
    SignerStreamTokenExpectedV1::new(&body, issuer.signer.pins().binding())
        .expect("fixture reaches the completed-proof preflight");
    signer
        .finality
        .completed_proof_source_available
        .store(false, Ordering::SeqCst);
    assert!(matches!(
        issuer.signer.sign(body),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.recover_calls.load(Ordering::SeqCst), 0);
    assert_eq!(signer.observer_calls.load(Ordering::SeqCst), 1);
}
#[test]
fn runtime_signer_probe_unavailability_before_signing_is_payload_free() {
    let signer = SignedFixture::new(1, TestSignerMode::Sign);
    signer
        .faults
        .lock()
        .unwrap()
        .insert(2, ObserverFault::Unavailable);
    let issuer = signer.issuer().expect("signed startup");
    let error = issuer
        .issue_token(
            quota_subject("credential-unavailable-probe"),
            vec![0xAA],
            PROVIDER,
            "sorafs.sf1@1.0.0".into(),
            TokenOverrides::default(),
            None,
        )
        .expect_err("fresh observer unavailable");
    assert!(matches!(
        error,
        StreamTokenIssuerError::RuntimeSignerUnavailable
    ));
    assert_eq!(error.to_string(), "stream-token signer runtime unavailable");
    assert_eq!(signer.calls.load(Ordering::Relaxed), 0);
}
#[test]
fn runtime_signer_failures_are_payload_free_and_consume_reserved_quota() {
    for (mode, expected) in [
        (
            TestSignerMode::Unavailable,
            StreamTokenIssuerError::RuntimeSignerUnavailable,
        ),
        (
            TestSignerMode::Refused,
            StreamTokenIssuerError::RuntimeSignerRefused,
        ),
    ] {
        let (issuer, signer) = issuer_and_signer(1, mode);
        let error = issuer
            .issue_token(
                quota_subject("credential-provider"),
                vec![0xAA],
                [0x11; 32],
                "sorafs.sf1@1.0.0".to_owned(),
                TokenOverrides::default(),
                None,
            )
            .expect_err("runtime signer failure must fail issuance");
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected)
        );
        assert_eq!(error.to_string(), expected.to_string());
        assert_eq!(signer.calls.load(Ordering::Relaxed), 1);
        assert!(matches!(
            issuer.issue_token(
                quota_subject("credential-provider"),
                vec![0xAA],
                [0x11; 32],
                "sorafs.sf1@1.0.0".to_owned(),
                TokenOverrides::default(),
                None,
            ),
            Err(StreamTokenIssuerError::IssuanceQuotaExceeded { .. })
        ));
        assert_eq!(
            signer.calls.load(Ordering::Relaxed),
            1,
            "quota must be reserved before calling the external signer"
        );
    }
}
#[test]
fn invalid_runtime_signer_output_never_releases_a_token() {
    for mode in [TestSignerMode::WrongKey, TestSignerMode::Malformed] {
        let (issuer, signer) = issuer_and_signer(2, mode);
        let error = issuer
            .issue_token(
                quota_subject("credential-invalid-output"),
                vec![0xAA],
                [0x11; 32],
                "sorafs.sf1@1.0.0".to_owned(),
                TokenOverrides::default(),
                None,
            )
            .expect_err("invalid signer_backend output cannot release a token");
        match mode {
            TestSignerMode::WrongKey => assert!(matches!(
                error,
                StreamTokenIssuerError::RuntimeSignerOutputInvalid
            )),
            TestSignerMode::Malformed => assert!(matches!(
                error,
                StreamTokenIssuerError::SignerEvidenceInvalid
            )),
            _ => unreachable!(),
        }
        assert_eq!(signer.calls.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn ambiguous_completion_recovers_exact_body_once_and_preserves_reserved_quota() {
    for mode in [
        TestSignerMode::Ambiguous,
        TestSignerMode::AmbiguousRecoverFailure,
    ] {
        let (issuer, signer) = issuer_and_signer(1, mode);
        let result = issuer.issue_token(
            quota_subject("ambiguous-operation"),
            vec![0xaa],
            PROVIDER,
            "sorafs.sf1@1.0.0".into(),
            TokenOverrides::default(),
            None,
        );
        match mode {
            TestSignerMode::Ambiguous => {
                let issuance_result =
                    result.expect("read-only recovery of exact immutable completed operation");
                issuance_result
                    .token
                    .verify(issuer.verifying_key())
                    .unwrap();
                assert_eq!(
                    signer.signing_payloads.lock().unwrap().as_slice(),
                    [issuance_result.token.body.signing_payload_bytes().unwrap()]
                );
                assert_eq!(signer.observer_calls.load(Ordering::SeqCst), 4);
            }
            _ => assert!(matches!(
                result,
                Err(StreamTokenIssuerError::RuntimeSignerUnavailable)
            )),
        }
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(signer.recover_calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            issuer.issue_token(
                quota_subject("ambiguous-operation"),
                vec![0xaa],
                PROVIDER,
                "sorafs.sf1@1.0.0".into(),
                TokenOverrides::default(),
                None,
            ),
            Err(StreamTokenIssuerError::IssuanceQuotaExceeded { .. })
        ));
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(signer.recover_calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn signed_completed_observations_require_exact_receipt_and_separate_release_phase() {
    for (call, fault) in [
        (3, ObserverFault::WrongCompletion),
        (4, ObserverFault::WrongCompletion),
        (4, ObserverFault::WrongRequest),
        (4, ObserverFault::WrongPhase),
        (4, ObserverFault::Stale),
    ] {
        let signer = SignedFixture::new(1, TestSignerMode::Sign);
        signer.faults.lock().unwrap().insert(call, fault);
        let issuer = signer.issuer().unwrap();
        assert!(matches!(
            issuer.issue_token(
                quota_subject("completed-observation"),
                vec![0xaa],
                PROVIDER,
                "sorafs.sf1@1.0.0".into(),
                TokenOverrides::default(),
                None,
            ),
            Err(StreamTokenIssuerError::SignerEvidenceInvalid)
        ));
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(signer.observer_calls.load(Ordering::SeqCst), call);
    }
}

#[test]
fn valid_same_key_renewal_cannot_relabel_a_pending_operation() {
    for call in [3, 4] {
        let signer = SignedFixture::new(1, TestSignerMode::Sign);
        let (_, current) = signer.renewed_custody();
        assert_eq!(current.active_head.sequence, 2);
        assert_eq!(current.current_anchor, anchor(101));
        let issuer = signer
            .issuer()
            .expect("original custody remains eligible at startup");
        signer
            .faults
            .lock()
            .unwrap()
            .insert(call, ObserverFault::RenewedCustody);
        assert!(matches!(
            issuer.issue_token(
                quota_subject("renewed-pending-operation"),
                vec![0xaa],
                PROVIDER,
                "sorafs.sf1@1.0.0".into(),
                TokenOverrides::default(),
                None,
            ),
            Err(StreamTokenIssuerError::SignerEvidenceInvalid)
        ));
        assert_eq!(signer.finality.tip.load(Ordering::SeqCst), 101);
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(signer.recover_calls.load(Ordering::SeqCst), 0);
        assert_eq!(signer.observer_calls.load(Ordering::SeqCst), call);
        signer.assert_original_receipt_retained();
        assert!(matches!(
            issuer.issue_token(
                quota_subject("renewed-pending-operation"),
                vec![0xaa],
                PROVIDER,
                "sorafs.sf1@1.0.0".into(),
                TokenOverrides::default(),
                None,
            ),
            Err(StreamTokenIssuerError::IssuanceQuotaExceeded { .. })
        ));
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(signer.recover_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn current_custody_is_eligible_across_the_entire_clock_uncertainty_interval() {
    // The attested record was issued exactly one second before the fixture clock.
    assert!(
        SignedFixture::with_clock_uncertainty(1_000)
            .issuer()
            .is_ok()
    );
    assert!(matches!(
        SignedFixture::with_clock_uncertainty(1_001).issuer(),
        Err(StreamTokenIssuerError::SignerEvidenceInvalid)
    ));
    // Observation, record, attester and observer expiration are all exclusive.
    for case in 1..=4 {
        let fixture = SignedFixture::with_expiry_case(case);
        let mut storage = fixture.storage.clone();
        storage
            .stream_tokens
            .signer
            .as_mut()
            .unwrap()
            .clock_uncertainty_ms = 399;
        assert!(fixture.issuer_with_storage(&storage).is_ok(), "case {case}");
        storage
            .stream_tokens
            .signer
            .as_mut()
            .unwrap()
            .clock_uncertainty_ms = 400;
        assert!(
            matches!(
                fixture.issuer_with_storage(&storage),
                Err(StreamTokenIssuerError::SignerEvidenceInvalid)
            ),
            "case {case}"
        );
    }
}

#[test]
fn independent_local_finality_and_clock_fences_reject_signed_but_ineligible_history() {
    for fault in 0..3 {
        let signer = SignedFixture::new(1, TestSignerMode::Sign);
        let issuer = signer.issuer().unwrap();
        match fault {
            0 => signer.finality.tip.store(101, Ordering::SeqCst),
            1 => {
                signer
                    .faults
                    .lock()
                    .unwrap()
                    .insert(4, ObserverFault::WrongFinality);
            }
            _ => signer.clock.now.store(NOW_MS - 1, Ordering::SeqCst),
        }
        let result = issuer.issue_token(
            quota_subject("history-fence"),
            vec![0xaa],
            PROVIDER,
            "sorafs.sf1@1.0.0".into(),
            TokenOverrides::default(),
            None,
        );
        if fault == 2 {
            assert!(matches!(
                result,
                Err(StreamTokenIssuerError::SignerClockRollback)
            ));
        } else {
            assert!(matches!(
                result,
                Err(StreamTokenIssuerError::SignerFinalityUnavailable)
            ));
        }
        assert_eq!(signer.calls.load(Ordering::SeqCst), usize::from(fault == 1));
    }
}

#[test]
fn bounded_transport_claims_do_not_construct_any_verification_authority() {
    assert!(StreamTokenSignerReceiptV1::new(Vec::new()).is_err());
    assert!(StreamTokenSignerReceiptV1::new(vec![0; 65_537]).is_err());
    let claim = StreamTokenSignerReceiptV1::new(b"untrusted-receipt-content".to_vec()).unwrap();
    assert!(!format!("{claim:?}").contains("untrusted-receipt-content"));
    assert!(StreamTokenObserverReplyV1::current(vec![1; 16_385], vec![2]).is_err());
    assert!(StreamTokenObserverReplyV1::completed(vec![1; 65_537]).is_err());
    let current = StreamTokenObserverReplyV1::current(vec![1], vec![2]).unwrap();
    assert!(current.completed_observation().is_none());
    let completed = StreamTokenObserverReplyV1::completed(vec![2]).unwrap();
    assert!(completed.current_evidence().is_none());
}

#[test]
fn token_expiry_during_finality_read_is_rechecked_before_release() {
    for case in 0..5 {
        let short = TokenOverrides {
            ttl_secs: Some(1),
            ..TokenOverrides::default()
        };
        let positive = SignedFixture::with_expiry_case(case);
        positive
            .issuer()
            .unwrap()
            .issue_token(
                quota_subject("short-positive"),
                vec![0xaa],
                PROVIDER,
                "sorafs.sf1@1.0.0".into(),
                short.clone(),
                None,
            )
            .expect("every signed fixture is eligible before its exclusive deadline");
        let signer = SignedFixture::with_expiry_case(case);
        let issuer = signer.issuer().unwrap();
        let expires = if case == 0 {
            (NOW_MS / 1000 + 1) * 1000
        } else {
            NOW_MS + 400
        };
        // Token, observation, custody, attester and observer deadlines are exercised respectively.
        // Shared admission requires custody/observation validity to fit authority eligibility;
        // the authority cases intentionally share their subordinate artifact's cutoff.
        if case == 0 {
            assert!(expires < NOW_MS + 1000);
        }
        *signer.finality.advance_clock.lock().unwrap() = Some((8, signer.clock.clone(), expires));
        assert!(matches!(
            issuer.issue_token(
                quota_subject("short-expired"),
                vec![0xaa],
                PROVIDER,
                "sorafs.sf1@1.0.0".into(),
                short,
                None,
            ),
            Err(StreamTokenIssuerError::SignerEvidenceInvalid)
        ));
        assert_eq!(signer.finality.validations.load(Ordering::SeqCst), 8);
        assert_eq!(signer.observer_calls.load(Ordering::SeqCst), 4);
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn signed_lower_historical_hashes_require_local_membership_even_with_valid_current_floor() {
    let mut custody = SignedFixture::new(1, TestSignerMode::Sign);
    Arc::get_mut(&mut custody)
        .unwrap()
        .substitute_historical_custody();
    assert!(matches!(
        custody.issuer(),
        Err(StreamTokenIssuerError::SignerFinalityUnavailable)
    ));
    assert_eq!(custody.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        custody.requests.lock().unwrap()[0].minimum_anchor,
        anchor(100)
    );
    for mode in [
        TestSignerMode::HistoricalSigning,
        TestSignerMode::HistoricalCompletion,
    ] {
        let signer = SignedFixture::new(1, mode);
        let issuer = signer
            .issuer()
            .expect("unchanged current anchor100 and genuine custody positive");
        assert!(matches!(
            issuer.issue_token(
                quota_subject("historical-member"),
                vec![0xaa],
                PROVIDER,
                "sorafs.sf1@1.0.0".into(),
                TokenOverrides::default(),
                None,
            ),
            Err(StreamTokenIssuerError::SignerFinalityUnavailable)
        ));
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
        let requests = signer.requests.lock().unwrap();
        assert_eq!(requests.last().unwrap().phase, Phase::AfterCommit);
        assert!(
            requests
                .iter()
                .all(|request| request.minimum_anchor == anchor(100))
        );
    }
}
#[test]
fn authenticated_subject_quota_is_enforced() {
    let issuer = issuer_with_limit(2);
    let provider = [0x11; 32];
    let subject = quota_subject("credential-a");
    let overrides = TokenOverrides {
        requests_per_minute: Some(2),
        ..TokenOverrides::default()
    };
    let first = issuer
        .issue_token(
            subject,
            vec![0xAA],
            provider,
            "sorafs.sf1@1.0.0".to_string(),
            overrides.clone(),
            None,
        )
        .expect("first token");
    assert_eq!(first.remaining_quota, 1);
    let second = issuer
        .issue_token(
            subject,
            vec![0xAA],
            provider,
            "sorafs.sf1@1.0.0".to_string(),
            overrides.clone(),
            None,
        )
        .expect("second token");
    assert_eq!(second.remaining_quota, 0);
    let err = issuer
        .issue_token(
            subject,
            vec![0xAA],
            provider,
            "sorafs.sf1@1.0.0".to_string(),
            overrides.clone(),
            None,
        )
        .expect_err("quota exceeded");
    assert!(matches!(
        err,
        StreamTokenIssuerError::IssuanceQuotaExceeded { .. }
    ));
    if let Some(entry) = issuer
        .issuance_budgets
        .lock()
        .expect("issuance budgets")
        .get_mut(&subject)
    {
        if let Some(reset) =
            Instant::now().checked_sub(ISSUANCE_QUOTA_WINDOW + Duration::from_secs(1))
        {
            entry.window_start = reset;
        }
        entry.used = 2;
    }
    let refreshed = issuer
        .issue_token(
            subject,
            vec![0xAA],
            provider,
            "sorafs.sf1@1.0.0".to_string(),
            overrides,
            None,
        )
        .expect("quota reset");
    assert_eq!(refreshed.remaining_quota, 1);
}
#[test]
fn zero_and_above_ceiling_overrides_fail_closed() {
    let issuer = issuer_with_limit(2);
    let provider = PROVIDER;
    for overrides in [
        TokenOverrides {
            ttl_secs: Some(0),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            ttl_secs: Some(901),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            max_streams: Some(0),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            max_streams: Some(3),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            rate_limit_bytes: Some(0),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            rate_limit_bytes: Some(512 * 1024 + 1),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            requests_per_minute: Some(0),
            ..TokenOverrides::default()
        },
        TokenOverrides {
            requests_per_minute: Some(3),
            ..TokenOverrides::default()
        },
    ] {
        assert!(matches!(
            issuer.issue_token(
                quota_subject("credential-free"),
                vec![0xBB],
                provider,
                "sorafs.sf1@1.0.0".to_string(),
                overrides,
                None,
            ),
            Err(StreamTokenIssuerError::InvalidPolicy { .. })
        ));
    }
    let valid = issuer
        .issue_token(
            quota_subject("credential-free"),
            vec![0xBB],
            provider,
            "sorafs.sf1@1.0.0".to_string(),
            TokenOverrides::default(),
            None,
        )
        .expect("invalid requests must not consume issuance quota");
    assert_eq!(valid.remaining_quota, 1);
}
#[test]
fn issuance_state_capacity_fails_closed_and_prunes_idle_subjects() {
    let issuer = issuer_with_capacity(2, 2);
    for credential in ["credential-a", "credential-b"] {
        issuer
            .issue_token(
                quota_subject(credential),
                vec![0xBB],
                PROVIDER,
                "sorafs.sf1@1.0.0".to_string(),
                TokenOverrides::default(),
                None,
            )
            .expect("client admitted");
    }
    assert!(matches!(
        issuer.issue_token(
            quota_subject("credential-c"),
            vec![0xBB],
            PROVIDER,
            "sorafs.sf1@1.0.0".to_string(),
            TokenOverrides::default(),
            None,
        ),
        Err(StreamTokenIssuerError::IssuanceQuotaCapacityExceeded { capacity: 2 })
    ));
    let stale = Instant::now()
        .checked_sub(ISSUANCE_QUOTA_WINDOW + Duration::from_secs(1))
        .expect("stale instant");
    issuer
        .issuance_budgets
        .lock()
        .expect("issuance budgets")
        .get_mut(&quota_subject("credential-a"))
        .expect("credential-a")
        .window_start = stale;
    issuer
        .issue_token(
            quota_subject("credential-c"),
            vec![0xBB],
            PROVIDER,
            "sorafs.sf1@1.0.0".to_string(),
            TokenOverrides::default(),
            None,
        )
        .expect("stale client pruned before capacity check");
}
#[test]
fn concurrent_issuance_never_exceeds_authenticated_subject_budget() {
    use std::{
        sync::{Arc, Condvar, Mutex, atomic::AtomicUsize, atomic::Ordering},
        thread,
    };
    const THREADS: usize = 32;
    const LIMIT: u32 = 7;
    let issuer = Arc::new(issuer_with_limit(LIMIT));
    let gate = Arc::new((Mutex::new(0_usize), Condvar::new()));
    let successes = Arc::new(AtomicUsize::new(0));
    let mut joins = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let issuer = Arc::clone(&issuer);
        let gate = Arc::clone(&gate);
        let successes = Arc::clone(&successes);
        joins.push(thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (arrivals, ready) = &*gate;
            let mut arrivals = arrivals.lock().unwrap();
            *arrivals += 1;
            ready.notify_all();
            while *arrivals < THREADS {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .expect("bounded issuance workers must all reach the gate");
                let (next, timeout) = ready.wait_timeout(arrivals, remaining).unwrap();
                arrivals = next;
                assert!(
                    !timeout.timed_out() || *arrivals == THREADS,
                    "issuance gate timed out"
                );
            }
            assert_eq!(*arrivals, THREADS);
            drop(arrivals);
            match issuer.issue_token(
                quota_subject("credential-race"),
                vec![0xBB],
                PROVIDER,
                "sorafs.sf1@1.0.0".to_string(),
                TokenOverrides::default(),
                None,
            ) {
                Ok(_) => {
                    successes.fetch_add(1, Ordering::Relaxed);
                }
                Err(StreamTokenIssuerError::IssuanceQuotaExceeded { .. }) => {}
                Err(other) => panic!("unexpected issuance error: {other}"),
            }
        }));
    }
    for join in joins {
        join.join().expect("issuance worker");
    }
    assert_eq!(successes.load(Ordering::Relaxed), LIMIT as usize);
}
#[test]
fn poisoned_issuance_state_fails_closed() {
    use std::{sync::Arc, thread};
    let issuer = Arc::new(issuer_with_limit(2));
    let poisoner = Arc::clone(&issuer);
    let poison_task = thread::spawn(move || {
        let _guard = poisoner.issuance_budgets.lock().expect("issuance lock");
        panic!("poison issuance state");
    })
    .join();
    assert!(poison_task.is_err(), "poisoning worker must panic");
    assert!(matches!(
        issuer.issue_token(
            quota_subject("credential-a"),
            vec![0xBB],
            PROVIDER,
            "sorafs.sf1@1.0.0".to_string(),
            TokenOverrides::default(),
            None,
        ),
        Err(StreamTokenIssuerError::IssuanceQuotaStateUnavailable)
    ));
}
#[test]
fn issuance_wall_clock_rollback_fails_closed() {
    let issuer = issuer_with_limit(2);
    issuer.observe_epoch(100).expect("initial epoch");
    assert!(matches!(
        issuer.observe_epoch(99),
        Err(StreamTokenIssuerError::ClockRollback {
            observed_epoch: 100,
            current_epoch: 99,
        })
    ));
}
#[test]
fn canonical_body_validation_rejects_each_unsafe_dimension() {
    let mut cases = Vec::new();
    let mut body = sample_body();
    body.token_id = "ABC".to_string();
    cases.push((body, StreamTokenBodyError::TokenId));
    let mut body = sample_body();
    body.manifest_cid.clear();
    cases.push((body, StreamTokenBodyError::ManifestCid));
    let mut body = sample_body();
    body.provider_id = [0; 32];
    cases.push((body, StreamTokenBodyError::ProviderId));
    let mut body = sample_body();
    body.profile_handle = "sorafs profile".to_string();
    cases.push((body, StreamTokenBodyError::ProfileHandle));
    let mut body = sample_body();
    body.max_streams = 0;
    cases.push((body, StreamTokenBodyError::MaxStreams));
    let mut body = sample_body();
    body.ttl_epoch = body.issued_at;
    cases.push((body, StreamTokenBodyError::Lifetime));
    let mut body = sample_body();
    body.rate_limit_bytes = 0;
    cases.push((body, StreamTokenBodyError::RateLimit));
    let mut body = sample_body();
    body.requests_per_minute = 0;
    cases.push((body, StreamTokenBodyError::RequestsPerMinute));
    let mut body = sample_body();
    body.token_pk_version = 0;
    cases.push((body, StreamTokenBodyError::KeyVersion));
    for (body, expected) in cases {
        assert_eq!(validate_token_body(&body), Err(expected));
    }
}
#[test]
fn canonical_body_accepts_exact_maximum_lifetime_and_rejects_max_plus_one() {
    let mut maximum = sample_body();
    maximum.issued_at = 1_700_000_000;
    maximum.ttl_epoch = maximum.issued_at + STREAM_TOKEN_MAX_TTL_SECS_V1;
    validate_token_body(&maximum).expect("exact maximum lifetime");
    maximum.ttl_epoch += 1;
    assert_eq!(
        validate_token_body(&maximum),
        Err(StreamTokenBodyError::Lifetime)
    );
}
#[test]
fn base64_decoder_enforces_canonical_bounded_frame_and_body() {
    let signing = SigningKey::from_bytes(&[0x42; 32]);
    let token = StreamTokenV1::sign(sample_body(), &signing).expect("sign");
    let encoded = encode_token_base64(&token).expect("encode");
    assert_eq!(decode_token_base64(&encoded).expect("decode"), token);
    assert!(matches!(
        decode_token_base64(&"A".repeat(MAX_STREAM_TOKEN_BASE64_BYTES + 1)),
        Err(StreamTokenHeaderError::HeaderTooLong { .. })
    ));
    let oversized_wire =
        base64::engine::general_purpose::STANDARD
            .encode(vec![0_u8; MAX_STREAM_TOKEN_WIRE_BYTES + 1]);
    assert!(matches!(
        decode_token_base64(&oversized_wire),
        Err(StreamTokenHeaderError::PayloadTooLong { .. })
    ));
    let mut invalid_body = sample_body();
    invalid_body.provider_id = [0; 32];
    let invalid_token = StreamTokenV1::sign(invalid_body, &signing).expect("sign invalid body");
    let invalid_encoded = encode_token_base64(&invalid_token).expect("encode invalid body");
    assert!(matches!(
        decode_token_base64(&invalid_encoded),
        Err(StreamTokenHeaderError::InvalidBody(
            StreamTokenBodyError::ProviderId
        ))
    ));
    let mut short_signature = token;
    short_signature.signature.pop();
    let short_encoded = encode_token_base64(&short_signature).expect("encode short signature");
    assert!(matches!(
        decode_token_base64(&short_encoded),
        Err(StreamTokenHeaderError::InvalidSignatureLength)
    ));
}
