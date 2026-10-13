//! Operator authentication boundary tests.

use super::*;
use axum::http::HeaderValue;
use ciborium::ser::into_writer;
use ed25519_dalek::Signer as _;
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use rand::rand_core::{TryCryptoRng, TryRngCore};
use rand::rngs::OsRng as FallibleOsRng;
const ED25519_SMALL_ORDER_POINT: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const ED25519_NONCANONICAL_IDENTITY: [u8; 32] = [
    0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
#[derive(Debug)]
struct FailingOperatorAuthRng;
#[derive(Debug)]
struct FailingOperatorAuthRngError;
impl std::fmt::Display for FailingOperatorAuthRngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failing operator auth RNG")
    }
}
impl std::error::Error for FailingOperatorAuthRngError {}
impl TryRngCore for FailingOperatorAuthRng {
    type Error = FailingOperatorAuthRngError;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(FailingOperatorAuthRngError)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(FailingOperatorAuthRngError)
    }
    fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Self::Error> {
        Err(FailingOperatorAuthRngError)
    }
}
impl TryCryptoRng for FailingOperatorAuthRng {}
fn base_webauthn_config(algorithms: Vec<OperatorWebAuthnAlgorithm>) -> OperatorWebAuthnConfig {
    OperatorWebAuthnConfig {
        rp_id: "example.com".to_owned(),
        rp_name: "Iroha Operator".to_owned(),
        origins: vec![Url::parse("https://example.com").expect("origin")],
        user_id: b"operator".to_vec(),
        user_name: "operator".to_owned(),
        user_display_name: "Operator".to_owned(),
        challenge_ttl: Duration::from_secs(120),
        session_ttl: Duration::from_secs(600),
        require_user_verification: true,
        allowed_algorithms: algorithms,
    }
}
fn base_operator_auth_config(
    tokens: Vec<String>,
    lockout: OperatorAuthLockout,
    algorithms: Vec<OperatorWebAuthnAlgorithm>,
) -> ToriiOperatorAuth {
    let tokens = if tokens.is_empty() {
        vec![test_bootstrap_token("default")]
    } else {
        tokens
            .into_iter()
            .map(|token| test_bootstrap_token(&token))
            .collect()
    };
    ToriiOperatorAuth {
        enabled: true,
        require_mtls: false,
        mtls_trusted_proxy_cidrs:
            iroha_config::parameters::defaults::torii::operator_auth::mtls_trusted_proxy_cidrs(),
        tokens,
        rate_per_minute: None,
        burst: None,
        ephemeral_state_capacity: NonZeroUsize::new(4_096).expect("non-zero capacity"),
        credential_capacity: NonZeroUsize::new(64).expect("non-zero capacity"),
        lockout,
        webauthn: Some(base_webauthn_config(algorithms)),
    }
}
fn test_bootstrap_token(label: &str) -> String {
    format!("iroha-test-bootstrap-token-{label}-0123456789")
}
fn test_session_token(seed: u8) -> String {
    encode_b64url(&[seed; SESSION_TOKEN_BYTES])
}
fn build_operator_auth(config: ToriiOperatorAuth, data_dir: &Path) -> OperatorAuth {
    OperatorAuth::new(config, data_dir.to_path_buf(), MaybeTelemetry::disabled())
        .expect("operator auth")
}
fn session_authority(auth: &OperatorAuth) -> EnrollmentAuthority {
    EnrollmentAuthority::Session(
        auth.credential_revocation_generation
            .load(Ordering::Acquire),
    )
}
fn credential_management_authority(auth: &OperatorAuth) -> u64 {
    auth.credential_revocation_generation
        .load(Ordering::Acquire)
}
fn write_credentials_fixture(data_dir: &Path, body: &str) {
    let path = operator_credentials_path(data_dir);
    let parent = path.parent().expect("credentials parent");
    fs::create_dir_all(parent).expect("create credentials directory");
    fs::write(&path, body).expect("write credentials fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .expect("make credentials fixture directory private");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("make credentials fixture private");
    }
}
fn es256_credential(id: &[u8], sign_count: u32, created_at_ms: u64) -> StoredCredential {
    let signing_key = SigningKey::random(&mut OsRng);
    StoredCredential {
        id: id.to_vec(),
        public_key: signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        alg: OperatorWebAuthnAlgorithm::Es256,
        sign_count,
        created_at_ms,
    }
}
fn base_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        limits::REMOTE_ADDR_HEADER,
        HeaderValue::from_static("127.0.0.1"),
    );
    headers
}
fn loopback_ip() -> IpAddr {
    "127.0.0.1".parse().expect("loopback ip")
}
fn loopback_connect_info() -> ConnectInfo<std::net::SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse().expect("loopback socket"))
}
#[test]
fn credential_inventory_is_stable_and_never_exposes_public_keys() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    auth.insert_credential(
        es256_credential(b"z-credential", 7, 200),
        session_authority(&auth),
    )
    .expect("insert z credential");
    auth.insert_credential(
        es256_credential(b"a-credential", 3, 100),
        session_authority(&auth),
    )
    .expect("insert a credential");

    let inventory = auth.credential_inventory().expect("credential inventory");
    assert_eq!(inventory["credentials_total"].as_u64(), Some(2));
    let credentials = inventory["credentials"]
        .as_array()
        .expect("credentials array");
    let a_credential_id = encode_b64url(b"a-credential");
    let z_credential_id = encode_b64url(b"z-credential");
    assert_eq!(
        credentials[0]["credential_id"].as_str(),
        Some(a_credential_id.as_str())
    );
    assert_eq!(credentials[0]["algorithm"].as_str(), Some("es256"));
    assert_eq!(credentials[0]["sign_count"].as_u64(), Some(3));
    assert_eq!(credentials[0]["created_at_ms"].as_u64(), Some(100));
    assert_eq!(
        credentials[1]["credential_id"].as_str(),
        Some(z_credential_id.as_str())
    );
    for credential in credentials {
        let object = credential.as_object().expect("credential metadata");
        assert_eq!(object.len(), 4);
        assert!(!object.contains_key("public_key"));
        assert!(!object.contains_key("public_key_b64"));
    }
}
#[test]
fn credential_deletion_requires_a_canonical_bounded_known_id() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    auth.insert_credential(
        es256_credential(b"delete-me", 0, 1),
        session_authority(&auth),
    )
    .expect("insert credential to delete");
    auth.insert_credential(es256_credential(b"keep-me", 0, 2), session_authority(&auth))
        .expect("insert credential to keep");

    for malformed in [
        String::new(),
        "ZGVsZXRlLW1l=".to_owned(),
        encode_b64url(&vec![0; MAX_CREDENTIAL_ID_BYTES + 1]),
    ] {
        let error = auth
            .delete_credential(&malformed, credential_management_authority(&auth))
            .expect_err("noncanonical or oversized id must fail");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "operator_webauthn_payload_invalid");
    }
    let unknown = auth
        .delete_credential(
            &encode_b64url(b"not-enrolled"),
            credential_management_authority(&auth),
        )
        .expect_err("unknown credential must fail");
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.code, "operator_webauthn_credential_not_found");

    let deleted = auth
        .delete_credential(
            &encode_b64url(b"delete-me"),
            credential_management_authority(&auth),
        )
        .expect("canonical enrolled id deletes");
    assert_eq!(deleted.credential_id, encode_b64url(b"delete-me"));
    assert_eq!(deleted.credentials_total, 1);
    assert_eq!(auth.credentials_read().expect("credential state").len(), 1);
}
#[test]
fn last_credential_requires_a_bootstrap_recovery_path() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    auth.insert_credential(
        es256_credential(b"only-credential", 0, 1),
        session_authority(&auth),
    )
    .expect("persist sole credential");
    drop(auth);

    let mut no_bootstrap = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    no_bootstrap.tokens.clear();
    let restarted = build_operator_auth(no_bootstrap, tempdir.path());
    let error = restarted
        .delete_credential(
            &encode_b64url(b"only-credential"),
            credential_management_authority(&restarted),
        )
        .expect_err("last credential needs a bootstrap recovery path");
    assert_eq!(error.status, StatusCode::CONFLICT);
    assert_eq!(error.code, "operator_webauthn_last_credential");
    assert_eq!(
        restarted
            .credentials_read()
            .expect("credential state")
            .len(),
        1
    );
    drop(restarted);

    let with_bootstrap = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let restarted = build_operator_auth(with_bootstrap, tempdir.path());
    let deleted = restarted
        .delete_credential(
            &encode_b64url(b"only-credential"),
            credential_management_authority(&restarted),
        )
        .expect("bootstrap token permits deleting the last credential");
    assert_eq!(deleted.credentials_total, 0);
}
#[test]
fn credential_deletion_is_persisted_across_restart() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    auth.insert_credential(es256_credential(b"removed", 0, 1), session_authority(&auth))
        .expect("insert removed credential");
    auth.insert_credential(
        es256_credential(b"retained", 0, 2),
        session_authority(&auth),
    )
    .expect("insert retained credential");
    auth.delete_credential(
        &encode_b64url(b"removed"),
        credential_management_authority(&auth),
    )
    .expect("delete persisted credential");
    drop(auth);

    let mut restart = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    restart.tokens.clear();
    let restarted = build_operator_auth(restart, tempdir.path());
    let credentials = restarted.credentials_read().expect("credential state");
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].id, b"retained");
}
#[test]
fn credential_deletion_changes_nothing_when_persistence_fails() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let mut auth = build_operator_auth(config, tempdir.path());
    auth.insert_credential(
        es256_credential(b"delete-me", 0, 1),
        session_authority(&auth),
    )
    .expect("insert deleted credential");
    auth.insert_credential(es256_credential(b"keep-me", 0, 2), session_authority(&auth))
        .expect("insert retained credential");
    let persisted_path = auth.credentials_path.clone();
    let persisted_before = fs::read(&persisted_path).expect("persisted credentials");
    let ctx = AuthContext {
        key: "credential-delete-rollback".to_owned(),
        enrollment_authority: session_authority(&auth),
    };
    auth.webauthn_authentication_options(&ctx)
        .expect("authentication challenge");
    let mut rng = FallibleOsRng;
    let session = auth
        .issue_session_with_rng(b"delete-me", Duration::from_secs(60), &mut rng)
        .expect("operator session");
    let generation_before = auth
        .credential_revocation_generation
        .load(Ordering::Acquire);
    let blocked_parent = tempdir.path().join("delete-not-a-directory");
    fs::write(&blocked_parent, b"block directory creation").expect("blocker file");
    auth.credentials_path = blocked_parent.join(CREDENTIALS_FILENAME);

    let error = auth
        .delete_credential(&encode_b64url(b"delete-me"), generation_before)
        .expect_err("failed persistence must abort deletion");
    assert_eq!(error.code, "operator_webauthn_persist_failed");
    assert_eq!(auth.credentials_read().expect("credential state").len(), 2);
    assert_eq!(
        fs::read(persisted_path).expect("persisted credentials"),
        persisted_before
    );
    assert_eq!(auth.challenges.lock().len(), 1);
    assert!(auth.session_valid(&session.session_token));
    assert_eq!(
        auth.credential_revocation_generation
            .load(Ordering::Acquire),
        generation_before
    );
}
#[test]
fn credential_deletion_invalidates_all_sessions_and_challenges() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    auth.insert_credential(es256_credential(b"revoked", 0, 1), session_authority(&auth))
        .expect("insert revoked credential");
    auth.insert_credential(
        es256_credential(b"remaining", 0, 2),
        session_authority(&auth),
    )
    .expect("insert remaining credential");
    let ctx = AuthContext {
        key: "credential-revocation".to_owned(),
        enrollment_authority: session_authority(&auth),
    };
    auth.webauthn_registration_options(&ctx)
        .expect("registration challenge");
    auth.webauthn_authentication_options(&ctx)
        .expect("authentication challenge");
    let mut rng = FallibleOsRng;
    let session = auth
        .issue_session_with_rng(b"revoked", Duration::from_secs(60), &mut rng)
        .expect("operator session");
    assert_eq!(auth.challenges.lock().len(), 2);
    assert_eq!(auth.sessions.lock().len(), 1);

    auth.delete_credential(
        &encode_b64url(b"revoked"),
        credential_management_authority(&auth),
    )
    .expect("delete credential");
    assert_eq!(auth.challenges.lock().len(), 0);
    assert_eq!(auth.sessions.lock().len(), 0);
    assert!(!auth.session_valid(&session.session_token));
}
#[test]
fn credential_deletion_rechecks_each_captured_session_generation() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    auth.insert_credential(
        es256_credential(b"first-delete", 0, 1),
        session_authority(&auth),
    )
    .expect("insert first credential to delete");
    auth.insert_credential(
        es256_credential(b"second-delete", 0, 2),
        session_authority(&auth),
    )
    .expect("insert second credential to delete");
    auth.insert_credential(
        es256_credential(b"retained", 0, 3),
        session_authority(&auth),
    )
    .expect("insert retained credential");

    let generation = credential_management_authority(&auth);
    let now = Instant::now();
    let first_session = test_session_token(1);
    let second_session = test_session_token(2);
    {
        let mut sessions = auth.sessions.lock();
        for token in [&first_session, &second_session] {
            sessions
                .insert(
                    token.clone(),
                    SessionEntry {
                        credential_revocation_generation: generation,
                    },
                    now + Duration::from_secs(60),
                    now,
                )
                .expect("test session fits bounded state");
        }
    }
    let mut first_headers = HeaderMap::new();
    first_headers.insert(
        HEADER_OPERATOR_SESSION,
        HeaderValue::from_str(&first_session).expect("first session header"),
    );
    let mut second_headers = HeaderMap::new();
    second_headers.insert(
        HEADER_OPERATOR_SESSION,
        HeaderValue::from_str(&second_session).expect("second session header"),
    );
    let first_authority = auth
        .credential_management_generation(&first_headers)
        .expect("first deletion authority");
    let second_authority = auth
        .credential_management_generation(&second_headers)
        .expect("second deletion authority captured before revocation");
    assert_eq!(first_authority, second_authority);

    auth.delete_credential(&encode_b64url(b"first-delete"), first_authority)
        .expect("first deletion succeeds");
    let generation_after_first = credential_management_authority(&auth);
    let persisted_after_first =
        fs::read(&auth.credentials_path).expect("credentials persisted after first deletion");
    let credential_ids_after_first = auth
        .credentials_read()
        .expect("credential state after first deletion")
        .iter()
        .map(|credential| credential.id.clone())
        .collect::<Vec<_>>();

    let error = auth
        .delete_credential(&encode_b64url(b"second-delete"), second_authority)
        .expect_err("stale second deletion authority must be rejected");
    assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "operator_session_invalid");
    assert_eq!(
        credential_management_authority(&auth),
        generation_after_first
    );
    assert_eq!(
        fs::read(&auth.credentials_path).expect("credentials remain persisted"),
        persisted_after_first
    );
    assert_eq!(
        auth.credentials_read()
            .expect("credential state remains readable")
            .iter()
            .map(|credential| credential.id.clone())
            .collect::<Vec<_>>(),
        credential_ids_after_first
    );
}
#[test]
fn credential_deletion_rejects_an_in_flight_stale_session_enrollment() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    auth.insert_credential(es256_credential(b"revoked", 0, 1), session_authority(&auth))
        .expect("insert revoked credential");
    auth.insert_credential(
        es256_credential(b"remaining", 0, 2),
        session_authority(&auth),
    )
    .expect("insert remaining credential");
    let stale_session_authority = session_authority(&auth);

    auth.delete_credential(
        &encode_b64url(b"revoked"),
        credential_management_authority(&auth),
    )
    .expect("delete credential");
    let error = auth
        .insert_credential(
            es256_credential(b"stale-enrollment", 0, 3),
            stale_session_authority,
        )
        .expect_err("a session captured before deletion must not enroll a credential");
    assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "operator_session_invalid");
    let credentials = auth.credentials_read().expect("credential state");
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].id, b"remaining");
}
#[test]
fn origin_allows_default_port_and_trailing_slash() {
    let allowed = vec![Url::parse("https://example.com").expect("origin")];
    assert!(origin_allowed("https://example.com/", &allowed));
    assert!(origin_allowed("https://example.com:443", &allowed));
    assert!(!origin_allowed("https://example.com:444", &allowed));
    for malformed in [
        "https://user@example.com/",
        "https://example.com/path",
        "https://example.com/?query",
        "https://example.com/#fragment",
    ] {
        assert!(!origin_allowed(malformed, &allowed));
    }
}
#[test]
fn credential_id_requires_matching_id_and_raw_id() {
    let encoded = encode_b64url(b"credential");
    let payload = json_object(vec![
        json_entry("id", encoded.clone()),
        json_entry("rawId", encoded),
    ]);
    let object = payload.as_object().expect("credential object");
    assert_eq!(
        parse_credential_id(object).expect("matching identifiers"),
        b"credential"
    );

    let mismatch = json_object(vec![
        json_entry("id", encode_b64url(b"credential-a")),
        json_entry("rawId", encode_b64url(b"credential-b")),
    ]);
    let error = parse_credential_id(mismatch.as_object().expect("credential object"))
        .expect_err("mismatched identifiers must fail closed");
    assert_eq!(error.code, "operator_webauthn_payload_invalid");

    let missing_raw_id = json_object(vec![json_entry("id", encode_b64url(b"credential"))]);
    assert!(parse_credential_id(missing_raw_id.as_object().expect("credential object")).is_err());
}
#[test]
fn webauthn_verify_payloads_require_exact_v1_fields() {
    let mut assertion = build_assertion_payload(b"credential", b"client", b"auth", b"sig");
    parse_assertion_payload(&assertion).expect("canonical assertion envelope");
    assertion
        .as_object_mut()
        .expect("assertion object")
        .insert("legacy".to_owned(), true.into());
    assert!(parse_assertion_payload(&assertion).is_err());

    let mut registration = build_registration_payload(b"credential", b"client", b"attestation");
    parse_registration_payload(&registration).expect("canonical registration envelope");
    registration
        .as_object_mut()
        .expect("registration object")
        .insert("type".to_owned(), "not-public-key".into());
    assert!(parse_registration_payload(&registration).is_err());

    let mut response_extra = build_assertion_payload(b"credential", b"client", b"auth", b"sig");
    response_extra
        .get_mut("response")
        .and_then(norito::json::Value::as_object_mut)
        .expect("assertion response")
        .insert("userHandle".to_owned(), norito::json::Value::Null);
    assert!(parse_assertion_payload(&response_extra).is_err());
}
#[tokio::test]
async fn webauthn_options_require_an_exact_empty_body() {
    require_empty_options_body(Body::empty())
        .await
        .expect("empty options body");
    let error = require_empty_options_body(Body::from("x"))
        .await
        .expect_err("nonempty options body must fail");
    assert_eq!(error.code, "operator_webauthn_payload_invalid");
}
#[test]
fn client_data_rejects_cross_origin_contexts() {
    for extra in [
        json_entry("crossOrigin", true),
        json_entry("topOrigin", "https://embedder.example"),
    ] {
        let payload = json_object(vec![
            json_entry("type", "webauthn.get"),
            json_entry("challenge", "challenge"),
            json_entry("origin", "https://example.com"),
            extra,
        ]);
        let bytes = norito::json::to_vec(&payload).expect("clientDataJSON");
        let error = match parse_client_data(&bytes, "webauthn.get") {
            Ok(_) => panic!("cross-origin context must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.code, "operator_webauthn_payload_invalid");
    }
}
#[test]
fn credentials_lock_fails_closed_after_poison() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout {
            failures: None,
            window: Duration::from_secs(0),
            duration: Duration::from_secs(0),
        },
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    {
        let mut creds = auth.credentials_write().expect("credential lock");
        creds.push(StoredCredential {
            id: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            alg: OperatorWebAuthnAlgorithm::Es256,
            sign_count: 0,
            created_at_ms: 0,
        });
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = auth.credentials.write().expect("lock");
        panic!("poison");
    }));
    let err = auth
        .has_credentials()
        .expect_err("poisoned credential state must fail closed");
    assert_eq!(err.code, "operator_webauthn_state_unavailable");
}
#[test]
fn credential_store_uncertainty_quarantines_memory_and_authorizations() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    auth.credentials_write()
        .expect("credential lock")
        .push(es256_credential(b"quarantine", 0, 1));
    let ctx = AuthContext {
        key: "quarantine".to_owned(),
        enrollment_authority: EnrollmentAuthority::None,
    };
    auth.webauthn_authentication_options(&ctx)
        .expect("challenge");
    let mut rng = FallibleOsRng;
    let session = auth
        .issue_session_with_rng(b"quarantine", Duration::from_secs(60), &mut rng)
        .expect("session");
    let generation = auth
        .credential_revocation_generation
        .load(Ordering::Acquire);

    auth.quarantine_credential_state();

    let error = auth
        .credentials_read()
        .expect_err("quarantined credential memory must fail closed");
    assert_eq!(error.code, "operator_webauthn_state_unavailable");
    assert_eq!(auth.challenges.lock().len(), 0);
    assert!(!auth.session_valid(&session.session_token));
    assert_eq!(
        auth.credential_revocation_generation
            .load(Ordering::Acquire),
        generation + 1
    );
}
#[test]
fn operator_auth_rejects_zero_ephemeral_duration() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let mut config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    config
        .webauthn
        .as_mut()
        .expect("WebAuthn config")
        .challenge_ttl = Duration::ZERO;

    let error = match OperatorAuth::new(
        config,
        tempdir.path().to_path_buf(),
        MaybeTelemetry::disabled(),
    ) {
        Ok(_) => panic!("zero challenge TTL must fail initialization"),
        Err(error) => error,
    };
    assert!(matches!(error, OperatorAuthInitError::InvalidPolicy(_)));
}
#[test]
fn operator_auth_requires_an_exact_first_enrollment_path() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let mut config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    config.tokens.clear();
    assert!(matches!(
        OperatorAuth::new(
            config,
            tempdir.path().to_path_buf(),
            MaybeTelemetry::disabled(),
        ),
        Err(OperatorAuthInitError::InvalidPolicy(_))
    ));

    for tokens in [
        vec!["short".to_owned()],
        vec![" token-with-whitespace-012345678901".to_owned()],
        vec![
            test_bootstrap_token("duplicate"),
            test_bootstrap_token("duplicate"),
        ],
    ] {
        assert!(matches!(
            validate_bootstrap_tokens(true, &tokens),
            Err(OperatorAuthInitError::InvalidPolicy(_))
        ));
    }

    let mut too_many_tokens = Vec::new();
    for index in 0..=iroha_config::parameters::defaults::torii::operator_auth::MAX_BOOTSTRAP_TOKENS
    {
        too_many_tokens.push(test_bootstrap_token(&format!("token-{index}")));
    }
    assert!(matches!(
        validate_bootstrap_tokens(true, &too_many_tokens),
        Err(OperatorAuthInitError::InvalidPolicy(_))
    ));

    let mut oversized_capacity = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    oversized_capacity.credential_capacity = NonZeroUsize::new(
        iroha_config::parameters::defaults::torii::operator_auth::MAX_CREDENTIAL_CAPACITY + 1,
    )
    .expect("non-zero capacity");
    assert!(matches!(
        OperatorAuth::new(
            oversized_capacity,
            tempdir.path().to_path_buf(),
            MaybeTelemetry::disabled(),
        ),
        Err(OperatorAuthInitError::InvalidPolicy(_))
    ));
}
#[test]
fn enrolled_operator_auth_restarts_without_a_bootstrap_token() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["bootstrap".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let signing_key = SigningKey::random(&mut OsRng);
    auth.insert_credential(
        StoredCredential {
            id: b"restart-credential".to_vec(),
            public_key: signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            alg: OperatorWebAuthnAlgorithm::Es256,
            sign_count: 0,
            created_at_ms: 1,
        },
        EnrollmentAuthority::BootstrapToken,
    )
    .expect("persist first credential");
    drop(auth);

    let mut restart = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    restart.tokens.clear();
    let restarted = OperatorAuth::new(
        restart,
        tempdir.path().to_path_buf(),
        MaybeTelemetry::disabled(),
    )
    .expect("persisted credential owns restart admission");
    assert!(restarted.has_credentials().expect("credential state"));
}
#[tokio::test]
async fn operator_auth_preserves_fractional_per_minute_rate() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let mut config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    config.rate_per_minute = std::num::NonZeroU32::new(1);
    config.burst = std::num::NonZeroU32::new(1);
    let auth = build_operator_auth(config, tempdir.path());

    assert!(auth.limiter.allow("operator").await);
    assert!(!auth.limiter.allow("operator").await);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(
        !auth.limiter.allow("operator").await,
        "a one-request-per-minute limit must not refill after one second"
    );
}
#[test]
fn registration_options_reports_challenge_rng_failure() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let ctx = AuthContext {
        key: "registration-rng".to_owned(),
        enrollment_authority: EnrollmentAuthority::None,
    };
    let err = auth
        .webauthn_registration_options_with_rng(&ctx, &mut FailingOperatorAuthRng)
        .expect_err("registration challenge RNG failure");
    assert_eq!(err.code, "operator_auth_random_bytes_failed");
    assert!(err.message.contains("failing operator auth RNG"));
    assert_eq!(auth.challenges.lock().len(), 0);
}
#[test]
fn authentication_options_reports_challenge_rng_failure() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    auth.credentials_write()
        .expect("credential lock")
        .push(StoredCredential {
            id: vec![1, 2, 3],
            public_key: Vec::new(),
            alg: OperatorWebAuthnAlgorithm::Es256,
            sign_count: 0,
            created_at_ms: 0,
        });
    let ctx = AuthContext {
        key: "authentication-rng".to_owned(),
        enrollment_authority: EnrollmentAuthority::None,
    };
    let err = auth
        .webauthn_authentication_options_with_rng(&ctx, &mut FailingOperatorAuthRng)
        .expect_err("authentication challenge RNG failure");
    assert_eq!(err.code, "operator_auth_random_bytes_failed");
    assert!(err.message.contains("failing operator auth RNG"));
    assert_eq!(auth.challenges.lock().len(), 0);
}
#[test]
fn challenge_and_session_admission_fail_closed_at_capacity() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let mut config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    config.ephemeral_state_capacity = NonZeroUsize::new(1).expect("non-zero capacity");
    let auth = build_operator_auth(config, tempdir.path());
    auth.credentials_write()
        .expect("credential lock")
        .push(StoredCredential {
            id: vec![1],
            public_key: Vec::new(),
            alg: OperatorWebAuthnAlgorithm::Es256,
            sign_count: 0,
            created_at_ms: 0,
        });
    let ctx = AuthContext {
        key: "capacity-test".to_owned(),
        enrollment_authority: EnrollmentAuthority::None,
    };

    auth.webauthn_authentication_options(&ctx)
        .expect("first challenge");
    let challenge_error = auth
        .webauthn_authentication_options(&ctx)
        .expect_err("second live challenge must exceed capacity");
    assert_eq!(
        challenge_error.code,
        "operator_auth_state_capacity_exhausted"
    );

    let mut rng = FallibleOsRng;
    auth.issue_session_with_rng(b"credential", Duration::from_secs(60), &mut rng)
        .expect("first session");
    let session_error =
        match auth.issue_session_with_rng(b"credential", Duration::from_secs(60), &mut rng) {
            Ok(_) => panic!("second live session must exceed capacity"),
            Err(error) => error,
        };
    assert_eq!(session_error.code, "operator_auth_state_capacity_exhausted");
}
#[test]
fn issue_session_reports_token_rng_failure() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let err = match auth.issue_session_with_rng(
        b"credential-id",
        Duration::from_secs(60),
        &mut FailingOperatorAuthRng,
    ) {
        Ok(_) => panic!("session token RNG failure must be reported"),
        Err(err) => err,
    };
    assert_eq!(err.code, "operator_auth_random_bytes_failed");
    assert!(err.message.contains("failing operator auth RNG"));
    assert_eq!(auth.sessions.lock().len(), 0);
}
fn headers_with_operator_token(token: &str) -> HeaderMap {
    let mut headers = base_headers();
    let token = test_bootstrap_token(token);
    headers.insert(
        HEADER_OPERATOR_TOKEN,
        HeaderValue::from_str(&token).expect("token"),
    );
    headers
}
#[test]
fn operator_bootstrap_token_rejects_duplicate_header_lines() {
    let mut headers = HeaderMap::new();
    headers.append(HEADER_OPERATOR_TOKEN, HeaderValue::from_static("first"));
    headers.append(HEADER_OPERATOR_TOKEN, HeaderValue::from_static("second"));
    assert!(
        single_header_text(&headers, HEADER_OPERATOR_TOKEN).is_none(),
        "duplicate operator bootstrap token header lines must fail closed"
    );
}
#[test]
fn operator_session_header_accepts_only_one_canonical_32_byte_token() {
    let canonical = test_session_token(0);
    assert_eq!(canonical.len(), SESSION_TOKEN_B64URL_BYTES);

    let mut headers = HeaderMap::new();
    assert_eq!(session_from_headers(&headers), SessionHeader::Missing);
    headers.insert(
        HEADER_OPERATOR_SESSION,
        HeaderValue::from_str(&canonical).expect("canonical session header"),
    );
    assert_eq!(
        session_from_headers(&headers),
        SessionHeader::Valid(canonical.as_str())
    );

    let mut noncanonical = canonical.clone();
    noncanonical.replace_range(SESSION_TOKEN_B64URL_BYTES - 1.., "B");
    for malformed in [
        String::new(),
        encode_b64url(&[0_u8; SESSION_TOKEN_BYTES - 1]),
        encode_b64url(&[0_u8; SESSION_TOKEN_BYTES + 1]),
        format!("{canonical}="),
        "*".repeat(SESSION_TOKEN_B64URL_BYTES),
        noncanonical,
        "A".repeat(64 * 1_024),
    ] {
        headers.insert(
            HEADER_OPERATOR_SESSION,
            HeaderValue::from_str(&malformed).expect("syntactically valid HTTP header"),
        );
        assert_eq!(
            session_from_headers(&headers),
            SessionHeader::Invalid,
            "malformed session header must fail closed: length {}",
            malformed.len()
        );
    }

    headers.insert(
        HEADER_OPERATOR_SESSION,
        HeaderValue::from_bytes(&[0x80; SESSION_TOKEN_B64URL_BYTES])
            .expect("opaque non-ASCII HTTP header"),
    );
    assert_eq!(session_from_headers(&headers), SessionHeader::Invalid);

    headers.clear();
    let canonical_header = HeaderValue::from_str(&canonical).expect("canonical session header");
    headers.append(HEADER_OPERATOR_SESSION, canonical_header.clone());
    headers.append(HEADER_OPERATOR_SESSION, canonical_header);
    assert_eq!(session_from_headers(&headers), SessionHeader::Invalid);
}
#[tokio::test]
async fn session_header_missing_and_invalid_errors_are_exact_across_auth_paths() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let auth = build_operator_auth(
        base_operator_auth_config(
            vec!["bootstrap".to_owned()],
            OperatorAuthLockout {
                failures: None,
                ..OperatorAuthLockout::default()
            },
            vec![OperatorWebAuthnAlgorithm::Es256],
        ),
        tempdir.path(),
    );

    let missing = base_headers();
    let error = auth
        .authorize_operator_endpoint(&missing, Some(loopback_ip()))
        .await
        .expect_err("ordinary operator routes require a session");
    assert_eq!(error.code, "operator_session_missing");
    let error = auth
        .credential_management_generation(&missing)
        .expect_err("credential management requires a session");
    assert_eq!(error.code, "operator_session_missing");

    let mut invalid = base_headers();
    invalid.insert(HEADER_OPERATOR_SESSION, HeaderValue::from_static(""));
    let error = auth
        .authorize_operator_endpoint(&invalid, Some(loopback_ip()))
        .await
        .expect_err("a supplied malformed session is invalid, not missing");
    assert_eq!(error.code, "operator_session_invalid");
    let error = auth
        .credential_management_generation(&invalid)
        .expect_err("credential management rejects malformed sessions as invalid");
    assert_eq!(error.code, "operator_session_invalid");

    let canonical = test_session_token(7);
    let canonical_header = HeaderValue::from_str(&canonical).expect("canonical session header");
    let mut duplicate = base_headers();
    duplicate.append(HEADER_OPERATOR_SESSION, canonical_header.clone());
    duplicate.append(HEADER_OPERATOR_SESSION, canonical_header);
    let error = auth
        .authorize_operator_endpoint(&duplicate, Some(loopback_ip()))
        .await
        .expect_err("duplicate session headers are invalid");
    assert_eq!(error.code, "operator_session_invalid");

    let bootstrap = headers_with_operator_token("bootstrap");
    auth.authorize_bootstrap(&bootstrap, Some(loopback_ip()), ACTION_REGISTER_OPTIONS)
        .await
        .expect("a missing session preserves first-credential token bootstrap");
    let mut unknown_session_bootstrap = bootstrap.clone();
    unknown_session_bootstrap.insert(
        HEADER_OPERATOR_SESSION,
        HeaderValue::from_str(&canonical).expect("canonical unknown session header"),
    );
    let error = auth
        .authorize_bootstrap(
            &unknown_session_bootstrap,
            Some(loopback_ip()),
            ACTION_REGISTER_OPTIONS,
        )
        .await
        .expect_err("bootstrap must not override a supplied unknown session");
    assert_eq!(error.code, "operator_session_invalid");
    let mut malformed_bootstrap = bootstrap;
    malformed_bootstrap.insert(HEADER_OPERATOR_SESSION, HeaderValue::from_static(""));
    let error = auth
        .authorize_bootstrap(
            &malformed_bootstrap,
            Some(loopback_ip()),
            ACTION_REGISTER_OPTIONS,
        )
        .await
        .expect_err("bootstrap must not hide a supplied malformed session");
    assert_eq!(error.code, "operator_session_invalid");
}
fn extract_challenge(payload: &norito::json::Value) -> String {
    let obj = payload.as_object().expect("payload object");
    let public_key = obj
        .get("publicKey")
        .and_then(norito::json::Value::as_object)
        .expect("publicKey object");
    public_key
        .get("challenge")
        .and_then(norito::json::Value::as_str)
        .expect("challenge")
        .to_string()
}
fn build_client_data(challenge: &str, origin: &str, ty: &str) -> Vec<u8> {
    let payload = json_object(vec![
        json_entry("type", ty),
        json_entry("challenge", challenge),
        json_entry("origin", origin),
    ]);
    let json = norito::json::to_json(&payload).expect("clientDataJSON");
    json.into_bytes()
}
fn build_attestation_object(auth_data: Vec<u8>) -> Vec<u8> {
    let map = vec![
        (
            CborValue::Text("fmt".to_owned()),
            CborValue::Text("none".to_owned()),
        ),
        (
            CborValue::Text("attStmt".to_owned()),
            CborValue::Map(Vec::new()),
        ),
        (
            CborValue::Text("authData".to_owned()),
            CborValue::Bytes(auth_data),
        ),
    ];
    let mut bytes = Vec::new();
    into_writer(&CborValue::Map(map), &mut bytes).expect("attestationObject");
    bytes
}
fn build_cose_key_es256(signing_key: &SigningKey) -> Vec<u8> {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = point.x().expect("x coordinate").to_vec();
    let y = point.y().expect("y coordinate").to_vec();
    let map = vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
        (
            CborValue::Integer(3.into()),
            CborValue::Integer((-7).into()),
        ),
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(1.into()),
        ),
        (CborValue::Integer((-2).into()), CborValue::Bytes(x)),
        (CborValue::Integer((-3).into()), CborValue::Bytes(y)),
    ];
    let mut bytes = Vec::new();
    into_writer(&CborValue::Map(map), &mut bytes).expect("cose key");
    bytes
}
fn build_auth_data_registration(
    policy: &WebAuthnPolicy,
    credential_id: &[u8],
    cose_key: &[u8],
    sign_count: u32,
) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&policy.rp_id_hash);
    let mut flags = FLAG_USER_PRESENT | FLAG_ATTESTED_CREDENTIAL_DATA;
    if policy.require_user_verification {
        flags |= FLAG_USER_VERIFIED;
    }
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(cose_key);
    auth_data
}
fn build_auth_data_assertion(policy: &WebAuthnPolicy, sign_count: u32) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&policy.rp_id_hash);
    let mut flags = FLAG_USER_PRESENT;
    if policy.require_user_verification {
        flags |= FLAG_USER_VERIFIED;
    }
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data
}
fn build_registration_payload(
    credential_id: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
) -> norito::json::Value {
    let response = json_object(vec![
        json_entry("clientDataJSON", encode_b64url(client_data_json)),
        json_entry("attestationObject", encode_b64url(attestation_object)),
    ]);
    let credential_id = encode_b64url(credential_id);
    json_object(vec![
        json_entry("id", credential_id.clone()),
        json_entry("rawId", credential_id),
        json_entry("response", response),
        json_entry("type", "public-key"),
    ])
}
fn build_assertion_payload(
    credential_id: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
) -> norito::json::Value {
    let response = json_object(vec![
        json_entry("clientDataJSON", encode_b64url(client_data_json)),
        json_entry("authenticatorData", encode_b64url(authenticator_data)),
        json_entry("signature", encode_b64url(signature)),
    ]);
    let credential_id = encode_b64url(credential_id);
    json_object(vec![
        json_entry("id", credential_id.clone()),
        json_entry("rawId", credential_id),
        json_entry("response", response),
        json_entry("type", "public-key"),
    ])
}
#[test]
fn attestation_object_requires_the_exact_none_profile() {
    let canonical = build_attestation_object(vec![1, 2, 3]);
    assert_eq!(
        parse_attestation_object(&canonical)
            .expect("canonical none attestation")
            .auth_data,
        [1, 2, 3]
    );

    let malformed = [
        CborValue::Map(vec![
            (
                CborValue::Text("fmt".to_owned()),
                CborValue::Text("packed".to_owned()),
            ),
            (
                CborValue::Text("attStmt".to_owned()),
                CborValue::Map(Vec::new()),
            ),
            (
                CborValue::Text("authData".to_owned()),
                CborValue::Bytes(vec![1]),
            ),
        ]),
        CborValue::Map(vec![
            (
                CborValue::Text("fmt".to_owned()),
                CborValue::Text("none".to_owned()),
            ),
            (
                CborValue::Text("attStmt".to_owned()),
                CborValue::Map(Vec::new()),
            ),
            (
                CborValue::Text("authData".to_owned()),
                CborValue::Bytes(vec![1]),
            ),
            (CborValue::Text("legacy".to_owned()), CborValue::Null),
        ]),
    ];
    for value in malformed {
        let mut encoded = Vec::new();
        into_writer(&value, &mut encoded).expect("malformed attestation fixture");
        assert!(parse_attestation_object(&encoded).is_err());
    }

    let mut trailing = canonical;
    trailing.push(0);
    assert!(parse_attestation_object(&trailing).is_err());
}
#[test]
fn authenticator_data_rejects_unconsumed_or_invalid_flags() {
    let policy =
        WebAuthnPolicy::from_config(base_webauthn_config(vec![OperatorWebAuthnAlgorithm::Es256]))
            .expect("policy");
    let mut assertion = build_auth_data_assertion(&policy, 1);
    assertion.push(0);
    assert!(parse_auth_data_assertion(&assertion, &policy).is_err());

    let mut assertion = build_auth_data_assertion(&policy, 1);
    assertion[32] |= RESERVED_AUTHENTICATOR_FLAGS & 0x02;
    assert!(parse_auth_data_assertion(&assertion, &policy).is_err());

    let mut assertion = build_auth_data_assertion(&policy, 1);
    assertion[32] |= FLAG_BACKUP_STATE;
    assert!(parse_auth_data_assertion(&assertion, &policy).is_err());

    let signing_key = SigningKey::random(&mut OsRng);
    let cose_key = build_cose_key_es256(&signing_key);
    let mut registration = build_auth_data_registration(&policy, b"credential", &cose_key, 1);
    registration.push(0);
    assert!(parse_auth_data_registration(&registration, &policy).is_err());

    let mut registration = build_auth_data_registration(&policy, b"credential", &cose_key, 1);
    registration[32] |= FLAG_EXTENSION_DATA;
    assert!(parse_auth_data_registration(&registration, &policy).is_err());
}
#[tokio::test]
async fn operator_auth_registration_login_and_rollover_es256() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["bootstrap".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let headers = headers_with_operator_token("bootstrap");
    let ctx = auth
        .authorize_bootstrap(&headers, Some(loopback_ip()), ACTION_REGISTER_OPTIONS)
        .await
        .expect("bootstrap allowed");
    let options = auth.webauthn_registration_options(&ctx).expect("options");
    let challenge = extract_challenge(&options);
    let signing_key = SigningKey::random(&mut OsRng);
    let credential_id = random_bytes(16).expect("credential id");
    let policy = auth.webauthn_policy().expect("policy");
    let cose_key = build_cose_key_es256(&signing_key);
    let auth_data = build_auth_data_registration(policy, &credential_id, &cose_key, 1);
    let client_data_json = build_client_data(&challenge, "https://example.com", "webauthn.create");
    let attestation_object = build_attestation_object(auth_data);
    let payload =
        build_registration_payload(&credential_id, &client_data_json, &attestation_object);
    let outcome = auth
        .webauthn_finish_registration(&ctx, &payload)
        .expect("registration");
    assert_eq!(outcome.credentials_total, 1);
    let err = auth
        .authorize_bootstrap(&headers, Some(loopback_ip()), ACTION_REGISTER_OPTIONS)
        .await
        .expect_err("token bootstrap denied after enrollment");
    assert_eq!(err.code, "operator_session_missing");
    let login_ctx = auth
        .authorize_login(&base_headers(), Some(loopback_ip()), ACTION_LOGIN_OPTIONS)
        .await
        .expect("login allowed");
    let login_options = auth
        .webauthn_authentication_options(&login_ctx)
        .expect("login options");
    let login_challenge = extract_challenge(&login_options);
    let assertion_auth_data = build_auth_data_assertion(policy, 2);
    let client_data_json =
        build_client_data(&login_challenge, "https://example.com", "webauthn.get");
    let client_hash = Sha256::digest(&client_data_json);
    let mut signed_bytes =
        Vec::with_capacity(assertion_auth_data.len() + client_hash.as_slice().len());
    signed_bytes.extend_from_slice(&assertion_auth_data);
    signed_bytes.extend_from_slice(&client_hash);
    let signature: p256::ecdsa::Signature = signing_key.sign(&signed_bytes);
    let signature = signature.normalize_s().unwrap_or(signature);
    let payload = build_assertion_payload(
        &credential_id,
        &client_data_json,
        &assertion_auth_data,
        signature.to_der().as_bytes(),
    );
    let session = auth
        .webauthn_finish_authentication(&login_ctx, &payload)
        .expect("login verify");
    assert!(auth.session_valid(&session.session_token));
    let mut session_headers = base_headers();
    session_headers.insert(
        HEADER_OPERATOR_SESSION,
        HeaderValue::from_str(&session.session_token).expect("session token"),
    );
    auth.authorize_operator_endpoint(&session_headers, Some(loopback_ip()))
        .await
        .expect("session accepted");
    let ctx = auth
        .authorize_bootstrap(
            &session_headers,
            Some(loopback_ip()),
            ACTION_REGISTER_OPTIONS,
        )
        .await
        .expect("session bootstrap");
    let options = auth.webauthn_registration_options(&ctx).expect("options");
    let challenge = extract_challenge(&options);
    let signing_key = SigningKey::random(&mut OsRng);
    let credential_id = random_bytes(16).expect("credential id");
    let cose_key = build_cose_key_es256(&signing_key);
    let auth_data = build_auth_data_registration(policy, &credential_id, &cose_key, 1);
    let client_data_json = build_client_data(&challenge, "https://example.com", "webauthn.create");
    let attestation_object = build_attestation_object(auth_data);
    let payload =
        build_registration_payload(&credential_id, &client_data_json, &attestation_object);
    let outcome = auth
        .webauthn_finish_registration(&ctx, &payload)
        .expect("rollover registration");
    assert_eq!(outcome.credentials_total, 2);
}
#[test]
fn authentication_counter_changes_only_after_persistence_succeeds() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["bootstrap".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let mut auth = build_operator_auth(config, tempdir.path());
    let signing_key = SigningKey::random(&mut OsRng);
    let credential_id = random_bytes(16).expect("credential id");
    auth.credentials_write()
        .expect("credential lock")
        .push(StoredCredential {
            id: credential_id.clone(),
            public_key: signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            alg: OperatorWebAuthnAlgorithm::Es256,
            sign_count: 1,
            created_at_ms: 0,
        });
    let ctx = AuthContext {
        key: "persistence-failure".to_owned(),
        enrollment_authority: EnrollmentAuthority::None,
    };
    let options = auth
        .webauthn_authentication_options(&ctx)
        .expect("login options");
    let challenge = extract_challenge(&options);
    let policy = auth.webauthn_policy().expect("policy");
    let authenticator_data = build_auth_data_assertion(policy, 2);
    let client_data_json = build_client_data(&challenge, "https://example.com", "webauthn.get");
    let client_hash = Sha256::digest(&client_data_json);
    let mut signed_bytes =
        Vec::with_capacity(authenticator_data.len() + client_hash.as_slice().len());
    signed_bytes.extend_from_slice(&authenticator_data);
    signed_bytes.extend_from_slice(&client_hash);
    let signature: p256::ecdsa::Signature = signing_key.sign(&signed_bytes);
    let signature = signature.normalize_s().unwrap_or(signature);
    let payload = build_assertion_payload(
        &credential_id,
        &client_data_json,
        &authenticator_data,
        signature.to_der().as_bytes(),
    );
    let blocked_parent = tempdir.path().join("not-a-directory");
    fs::write(&blocked_parent, b"block directory creation").expect("blocker file");
    auth.credentials_path = blocked_parent.join(CREDENTIALS_FILENAME);

    let err = match auth.webauthn_finish_authentication(&ctx, &payload) {
        Ok(_) => panic!("credential persistence must fail"),
        Err(err) => err,
    };
    assert_eq!(err.code, "operator_webauthn_persist_failed");
    assert_eq!(
        auth.credentials_read().expect("credential lock")[0].sign_count,
        1,
        "failed persistence must not advance the in-memory signature counter"
    );
}
#[test]
fn authentication_counter_cannot_fall_back_to_zero() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["bootstrap".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let signing_key = SigningKey::random(&mut OsRng);
    let credential_id = random_bytes(16).expect("credential id");
    let credential = StoredCredential {
        id: credential_id.clone(),
        public_key: signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        alg: OperatorWebAuthnAlgorithm::Es256,
        sign_count: 1,
        created_at_ms: 0,
    };
    persist_credentials(&auth.credentials_path, std::slice::from_ref(&credential))
        .expect("persist initial counter");
    *auth.credentials_write().expect("credential lock") = vec![credential];
    let persisted_before = fs::read(&auth.credentials_path).expect("persisted credential");

    let ctx = AuthContext {
        key: "counter-rollback".to_owned(),
        enrollment_authority: EnrollmentAuthority::None,
    };
    let options = auth
        .webauthn_authentication_options(&ctx)
        .expect("login options");
    let challenge = extract_challenge(&options);
    let policy = auth.webauthn_policy().expect("policy");
    let authenticator_data = build_auth_data_assertion(policy, 0);
    let client_data_json = build_client_data(&challenge, "https://example.com", "webauthn.get");
    let client_hash = Sha256::digest(&client_data_json);
    let mut signed_bytes =
        Vec::with_capacity(authenticator_data.len() + client_hash.as_slice().len());
    signed_bytes.extend_from_slice(&authenticator_data);
    signed_bytes.extend_from_slice(&client_hash);
    let signature: p256::ecdsa::Signature = signing_key.sign(&signed_bytes);
    let signature = signature.normalize_s().unwrap_or(signature);
    let payload = build_assertion_payload(
        &credential_id,
        &client_data_json,
        &authenticator_data,
        signature.to_der().as_bytes(),
    );

    let error = match auth.webauthn_finish_authentication(&ctx, &payload) {
        Ok(_) => panic!("a used counter cannot revert to zero"),
        Err(error) => error,
    };
    assert_eq!(error.code, "operator_webauthn_payload_invalid");
    assert_eq!(
        auth.credentials_read().expect("credential lock")[0].sign_count,
        1
    );
    assert_eq!(
        fs::read(&auth.credentials_path).expect("persisted credential"),
        persisted_before
    );
}
#[test]
fn persisted_credentials_are_validated_strictly_at_startup() {
    let signing_key = SigningKey::random(&mut OsRng);
    let public_key = encode_b64url(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let valid_entry = |id: &str, sign_count: u64| {
        format!(
            r#"{{"id_b64":"{id}","public_key_b64":"{public_key}","alg":"es256","sign_count":{sign_count},"created_at_ms":1}}"#
        )
    };
    let duplicate = valid_entry(&encode_b64url(b"same-id"), 0);
    let fixtures = [
        (
            "duplicate id",
            format!(r#"{{"version":1,"credentials":[{duplicate},{duplicate}]}}"#),
        ),
        (
            "empty id",
            format!(r#"{{"version":1,"credentials":[{}]}}"#, valid_entry("", 0)),
        ),
        (
            "oversized counter",
            format!(
                r#"{{"version":1,"credentials":[{}]}}"#,
                valid_entry(&encode_b64url(b"counter"), u64::MAX)
            ),
        ),
        (
            "invalid key",
            format!(
                r#"{{"version":1,"credentials":[{{"id_b64":"{}","public_key_b64":"{}","alg":"es256","sign_count":0,"created_at_ms":1}}]}}"#,
                encode_b64url(b"invalid-key"),
                encode_b64url(&[1; P256_UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN])
            ),
        ),
        (
            "unknown field",
            r#"{"version":1,"credentials":[],"legacy":true}"#.to_owned(),
        ),
    ];

    for (label, body) in fixtures {
        let tempdir = tempfile::tempdir().expect("tempdir");
        write_credentials_fixture(tempdir.path(), &body);
        let config = base_operator_auth_config(
            Vec::new(),
            OperatorAuthLockout::default(),
            vec![OperatorWebAuthnAlgorithm::Es256],
        );
        let error = match OperatorAuth::new(
            config,
            tempdir.path().to_path_buf(),
            MaybeTelemetry::disabled(),
        ) {
            Ok(_) => panic!("{label} must fail startup"),
            Err(error) => error,
        };
        assert!(
            matches!(error, OperatorAuthInitError::CredentialLoad(_)),
            "{label}: {error}"
        );
    }
}
#[test]
fn persisted_credential_file_is_bounded_before_json_allocation() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let capacity = NonZeroUsize::new(1).expect("non-zero capacity");
    let bytes = max_credentials_file_bytes(capacity).expect("file bound");
    let oversized = "x".repeat(usize::try_from(bytes + 1).expect("test bound fits usize"));
    write_credentials_fixture(tempdir.path(), &oversized);
    let mut config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    config.credential_capacity = capacity;
    assert!(matches!(
        OperatorAuth::new(
            config,
            tempdir.path().to_path_buf(),
            MaybeTelemetry::disabled(),
        ),
        Err(OperatorAuthInitError::CredentialLoad(_))
    ));
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_store_rejects_symlink_file_without_clobbering_target() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = operator_credentials_path(tempdir.path());
    let parent = path.parent().expect("credential parent");
    fs::create_dir(parent).expect("credential parent");
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .expect("private credential parent");
    let target = tempdir.path().join("symlink-target.json");
    let sentinel = b"do not replace";
    fs::write(&target, sentinel).expect("symlink target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .expect("private symlink target");
    symlink(&target, &path).expect("credential symlink");
    let capacity = NonZeroUsize::new(1).expect("capacity");

    assert!(load_credentials(&path, &[OperatorWebAuthnAlgorithm::Es256], capacity).is_err());
    let error = persist_credentials(&path, &[]).expect_err("symlink destination must fail");
    assert_eq!(error.code, "operator_webauthn_persist_failed");
    assert_eq!(fs::read(target).expect("unchanged target"), sentinel);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_store_rejects_non_regular_destination() {
    use std::os::unix::fs::PermissionsExt as _;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = operator_credentials_path(tempdir.path());
    let parent = path.parent().expect("credential parent");
    fs::create_dir(parent).expect("credential parent");
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .expect("private credential parent");
    fs::create_dir(&path).expect("directory at credential destination");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("private non-regular destination");
    let sentinel = path.join("sentinel");
    fs::write(&sentinel, b"do not replace").expect("sentinel");
    let capacity = NonZeroUsize::new(1).expect("capacity");

    assert!(load_credentials(&path, &[OperatorWebAuthnAlgorithm::Es256], capacity).is_err());
    assert!(persist_credentials(&path, &[]).is_err());
    assert_eq!(
        fs::read(sentinel).expect("unchanged sentinel"),
        b"do not replace"
    );
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_store_rejects_symlink_parent_without_clobbering_target() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let tempdir = tempfile::tempdir().expect("tempdir");
    let external = tempdir.path().join("external-operator-auth");
    fs::create_dir(&external).expect("external directory");
    fs::set_permissions(&external, fs::Permissions::from_mode(0o700))
        .expect("private external directory");
    let target = external.join(CREDENTIALS_FILENAME);
    let sentinel = b"do not replace";
    fs::write(&target, sentinel).expect("external credential target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .expect("private external target");
    let parent = operator_credentials_path(tempdir.path())
        .parent()
        .expect("credential parent")
        .to_path_buf();
    symlink(&external, &parent).expect("credential parent symlink");
    let path = parent.join(CREDENTIALS_FILENAME);
    let capacity = NonZeroUsize::new(1).expect("capacity");

    assert!(load_credentials(&path, &[OperatorWebAuthnAlgorithm::Es256], capacity).is_err());
    let error = persist_credentials(&path, &[]).expect_err("symlink parent must fail");
    assert_eq!(error.code, "operator_webauthn_persist_failed");
    assert_eq!(fs::read(target).expect("unchanged target"), sentinel);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_store_rejects_public_directory_and_file_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let capacity = NonZeroUsize::new(1).expect("capacity");
    let public_directory = tempfile::tempdir().expect("tempdir");
    write_credentials_fixture(public_directory.path(), r#"{"version":1,"credentials":[]}"#);
    let directory_path = operator_credentials_path(public_directory.path());
    fs::set_permissions(
        directory_path.parent().expect("credential parent"),
        fs::Permissions::from_mode(0o770),
    )
    .expect("group-writable credential parent");
    assert!(
        load_credentials(
            &directory_path,
            &[OperatorWebAuthnAlgorithm::Es256],
            capacity,
        )
        .is_err()
    );
    assert!(persist_credentials(&directory_path, &[]).is_err());

    let public_file = tempfile::tempdir().expect("tempdir");
    write_credentials_fixture(public_file.path(), r#"{"version":1,"credentials":[]}"#);
    let file_path = operator_credentials_path(public_file.path());
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644))
        .expect("public credential file");
    assert!(load_credentials(&file_path, &[OperatorWebAuthnAlgorithm::Es256], capacity,).is_err());
    assert!(persist_credentials(&file_path, &[]).is_err());
}
#[cfg(target_os = "macos")]
#[test]
fn credential_store_rejects_extended_allow_acl_without_clobbering() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_credentials_fixture(tempdir.path(), r#"{"version":1,"credentials":[]}"#);
    let path = operator_credentials_path(tempdir.path());
    let before = fs::read(&path).expect("credential contents");
    let status = std::process::Command::new("/bin/chmod")
        .arg("+a")
        .arg("everyone allow read")
        .arg(&path)
        .status()
        .expect("run chmod to add an extended ACL");
    assert!(status.success(), "chmod failed with {status}");
    let capacity = NonZeroUsize::new(1).expect("capacity");

    assert!(load_credentials(&path, &[OperatorWebAuthnAlgorithm::Es256], capacity).is_err());
    assert!(persist_credentials(&path, &[]).is_err());
    assert_eq!(fs::read(path).expect("unchanged credential file"), before);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_store_tightens_legacy_readable_directory_permissions() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let tempdir = tempfile::tempdir().expect("tempdir");
    write_credentials_fixture(tempdir.path(), r#"{"version":1,"credentials":[]}"#);
    let path = operator_credentials_path(tempdir.path());
    let parent = path.parent().expect("credential parent");
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
        .expect("legacy credential parent mode");
    let capacity = NonZeroUsize::new(1).expect("capacity");

    let credentials = load_credentials(&path, &[OperatorWebAuthnAlgorithm::Es256], capacity)
        .expect("legacy readable directory is safely tightened");
    assert!(credentials.is_empty());
    assert_eq!(
        fs::metadata(parent).expect("tightened parent").mode() & 0o7777,
        0o700
    );
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_store_rejects_hard_link_destination() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_credentials_fixture(tempdir.path(), r#"{"version":1,"credentials":[]}"#);
    let path = operator_credentials_path(tempdir.path());
    let alias = tempdir.path().join("credential-hard-link.json");
    fs::hard_link(&path, &alias).expect("credential hard link");
    let before = fs::read(&alias).expect("hard-link contents");
    let capacity = NonZeroUsize::new(1).expect("capacity");

    assert!(load_credentials(&path, &[OperatorWebAuthnAlgorithm::Es256], capacity).is_err());
    assert!(persist_credentials(&path, &[]).is_err());
    assert_eq!(fs::read(alias).expect("unchanged hard link"), before);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_store_creates_private_single_link_entries() {
    use std::os::unix::fs::MetadataExt as _;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = operator_credentials_path(tempdir.path());
    persist_credentials(&path, &[]).expect("persist empty credential store");

    let directory = fs::metadata(path.parent().expect("credential parent"))
        .expect("credential parent metadata");
    let file = fs::metadata(path).expect("credential metadata");
    assert_eq!(directory.mode() & 0o7777, 0o700);
    assert_eq!(file.mode() & 0o7777, 0o600);
    assert_eq!(file.nlink(), 1);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_store_rejects_a_second_live_owner() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let owner = build_operator_auth(config.clone(), tempdir.path());

    let error = match OperatorAuth::new(
        config.clone(),
        tempdir.path().to_path_buf(),
        MaybeTelemetry::disabled(),
    ) {
        Ok(_) => panic!("a second credential-store owner must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, OperatorAuthInitError::CredentialLoad(_)));

    drop(owner);
    OperatorAuth::new(
        config,
        tempdir.path().to_path_buf(),
        MaybeTelemetry::disabled(),
    )
    .expect("credential-store ownership is released on drop");
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_no_clobber_publication_preserves_racing_destination() {
    use std::os::unix::fs::PermissionsExt as _;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = operator_credentials_path(tempdir.path());
    let parent = open_credential_store_parent(&path, true)
        .expect("open credential parent")
        .expect("created credential parent");
    assert!(
        inspect_credential_file(&parent.directory, &parent.filename, &path, None)
            .expect("inspect absent destination")
            .is_none()
    );
    let (mut temporary, temporary_name) =
        create_credential_temp_file(&parent.directory, &parent.filename)
            .expect("credential temporary file");
    temporary
        .write_all(b"new credentials")
        .expect("write temporary");
    temporary.sync_all().expect("sync temporary");
    validate_credential_temp_file(
        &parent.directory,
        &temporary_name,
        &path,
        &temporary,
        b"new credentials".len(),
    )
    .expect("valid temporary");
    drop(temporary);

    let racing = b"racing destination";
    fs::write(&path, racing).expect("racing destination");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("private racing destination");
    assert!(
        publish_new_credential_file(&parent.directory, &temporary_name, &parent.filename).is_err()
    );
    assert_eq!(fs::read(&path).expect("racing destination remains"), racing);
    rustix::fs::unlinkat(
        &parent.directory,
        &temporary_name,
        rustix::fs::AtFlags::empty(),
    )
    .expect("remove unpublished temporary");
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_store_rejects_intermediate_symlink_ancestor() {
    use std::os::unix::fs::symlink;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let real_data = tempdir.path().join("real-data");
    write_credentials_fixture(&real_data, r#"{"version":1,"credentials":[]}"#);
    let linked_data = tempdir.path().join("linked-data");
    symlink(&real_data, &linked_data).expect("intermediate symlink");
    let path = operator_credentials_path(&linked_data);
    let target = operator_credentials_path(&real_data);
    let before = fs::read(&target).expect("target credentials");
    let capacity = NonZeroUsize::new(1).expect("capacity");

    assert!(load_credentials(&path, &[OperatorWebAuthnAlgorithm::Es256], capacity).is_err());
    assert!(persist_credentials(&path, &[]).is_err());
    assert_eq!(fs::read(target).expect("unchanged target"), before);
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_parent_binding_rejects_absent_file_after_directory_swap() {
    use std::os::unix::fs::PermissionsExt as _;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = operator_credentials_path(tempdir.path());
    let parent = open_credential_store_parent(&path, true)
        .expect("open credential parent")
        .expect("created credential parent");
    assert!(
        inspect_credential_file(&parent.directory, &parent.filename, &path, None)
            .expect("inspect absent file")
            .is_none()
    );

    let configured_parent = path.parent().expect("credential parent");
    let displaced_parent = tempdir.path().join("displaced-operator-auth");
    fs::rename(configured_parent, &displaced_parent).expect("displace credential parent");
    fs::create_dir(configured_parent).expect("replacement credential parent");
    fs::set_permissions(configured_parent, fs::Permissions::from_mode(0o700))
        .expect("private replacement parent");
    fs::write(&path, r#"{"version":1,"credentials":[]}"#).expect("replacement credential file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("private replacement file");

    assert!(validate_credential_store_parent(&parent, &path).is_err());
}
#[cfg(any(target_vendor = "apple", target_os = "linux"))]
#[test]
fn credential_base_binding_rejects_data_directory_swap() {
    use std::os::unix::fs::PermissionsExt as _;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let data_dir = tempdir.path().join("data");
    fs::create_dir(&data_dir).expect("data directory");
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))
        .expect("private data directory");
    let path = operator_credentials_path(&data_dir);
    let parent = open_credential_store_parent(&path, true)
        .expect("open credential parent")
        .expect("created credential parent");

    let displaced_data_dir = tempdir.path().join("displaced-data");
    fs::rename(&data_dir, &displaced_data_dir).expect("displace data directory");
    fs::create_dir(&data_dir).expect("replacement data directory");
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))
        .expect("private replacement data directory");
    let replacement_parent = operator_credentials_path(&data_dir)
        .parent()
        .expect("replacement credential parent")
        .to_path_buf();
    fs::create_dir(&replacement_parent).expect("replacement credential parent");
    fs::set_permissions(&replacement_parent, fs::Permissions::from_mode(0o700))
        .expect("private replacement credential parent");

    assert!(validate_credential_store_parent(&parent, &path).is_err());
}
#[test]
fn credential_capacity_is_enforced_for_load_and_rollover() {
    let signing_key = SigningKey::random(&mut OsRng);
    let public_key = encode_b64url(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let entry = |id: &[u8]| {
        format!(
            r#"{{"id_b64":"{}","public_key_b64":"{public_key}","alg":"es256","sign_count":0,"created_at_ms":1}}"#,
            encode_b64url(id)
        )
    };
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_credentials_fixture(
        tempdir.path(),
        &format!(
            r#"{{"version":1,"credentials":[{},{}]}}"#,
            entry(b"one"),
            entry(b"two")
        ),
    );
    let mut config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    config.credential_capacity = NonZeroUsize::new(1).expect("non-zero capacity");
    let error = match OperatorAuth::new(
        config,
        tempdir.path().to_path_buf(),
        MaybeTelemetry::disabled(),
    ) {
        Ok(_) => panic!("oversized credential store must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, OperatorAuthInitError::CredentialLoad(_)));

    let empty = tempfile::tempdir().expect("tempdir");
    let mut config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    config.credential_capacity = NonZeroUsize::new(1).expect("non-zero capacity");
    let auth = build_operator_auth(config, empty.path());
    let credential = |id| StoredCredential {
        id: vec![id],
        public_key: signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        alg: OperatorWebAuthnAlgorithm::Es256,
        sign_count: 0,
        created_at_ms: 1,
    };
    auth.insert_credential(credential(1), session_authority(&auth))
        .expect("first credential");
    let duplicate = auth
        .insert_credential(credential(1), session_authority(&auth))
        .expect_err("duplicate credential identifiers must not replace keys or counters");
    assert_eq!(duplicate.code, "operator_webauthn_credential_duplicate");
    let error = auth
        .insert_credential(credential(2), session_authority(&auth))
        .expect_err("rollover beyond capacity must fail");
    assert_eq!(
        error.code,
        "operator_webauthn_credential_capacity_exhausted"
    );
}
#[test]
fn persisted_credential_algorithm_must_match_active_policy() {
    let signing_key = SigningKey::random(&mut OsRng);
    let body = format!(
        r#"{{"version":1,"credentials":[{{"id_b64":"{}","public_key_b64":"{}","alg":"es256","sign_count":0,"created_at_ms":1}}]}}"#,
        encode_b64url(b"es256-id"),
        encode_b64url(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
        )
    );
    let tempdir = tempfile::tempdir().expect("tempdir");
    write_credentials_fixture(tempdir.path(), &body);
    let config = base_operator_auth_config(
        Vec::new(),
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Ed25519],
    );
    let error = match OperatorAuth::new(
        config,
        tempdir.path().to_path_buf(),
        MaybeTelemetry::disabled(),
    ) {
        Ok(_) => panic!("credential outside active algorithm policy must fail startup"),
        Err(error) => error,
    };
    assert!(matches!(error, OperatorAuthInitError::CredentialLoad(_)));
}
#[tokio::test]
async fn operator_token_only_bootstraps_credential_enrollment() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["operator-token".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let headers = headers_with_operator_token("operator-token");
    auth.authorize_bootstrap(&headers, Some(loopback_ip()), ACTION_REGISTER_OPTIONS)
        .await
        .expect("operator token bootstraps first credential");
    let error = auth
        .authorize_operator_endpoint(&headers, Some(loopback_ip()))
        .await
        .expect_err("operator token must never authorize an operator route");
    assert_eq!(error.code, "operator_session_missing");
}
#[test]
fn bootstrap_enrollment_cannot_race_past_first_credential() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["bootstrap".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let public_key = SigningKey::random(&mut OsRng)
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let credential = |id| StoredCredential {
        id: vec![id],
        public_key: public_key.clone(),
        alg: OperatorWebAuthnAlgorithm::Es256,
        sign_count: 0,
        created_at_ms: 0,
    };

    assert_eq!(
        auth.insert_credential(credential(1), EnrollmentAuthority::BootstrapToken)
            .expect("bootstrap may persist the first credential"),
        1
    );
    let error = auth
        .insert_credential(credential(2), EnrollmentAuthority::BootstrapToken)
        .expect_err("a concurrent bootstrap must not persist a rollover credential");
    assert_eq!(error.code, "operator_session_missing");
    assert_eq!(auth.credentials_read().expect("credential state").len(), 1);
    assert_eq!(
        auth.insert_credential(credential(2), session_authority(&auth))
            .expect("an authenticated session may persist a rollover credential"),
        2
    );
}
#[tokio::test]
async fn persisted_first_credential_disables_bootstrap_after_restart() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["bootstrap".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config.clone(), tempdir.path());
    let public_key = SigningKey::random(&mut OsRng)
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    auth.insert_credential(
        StoredCredential {
            id: vec![1],
            public_key,
            alg: OperatorWebAuthnAlgorithm::Es256,
            sign_count: 0,
            created_at_ms: 0,
        },
        EnrollmentAuthority::BootstrapToken,
    )
    .expect("first credential should persist");
    drop(auth);

    let restarted = build_operator_auth(config, tempdir.path());
    let headers = headers_with_operator_token("bootstrap");
    let error = restarted
        .authorize_bootstrap(&headers, Some(loopback_ip()), ACTION_REGISTER_OPTIONS)
        .await
        .expect_err("persisted enrollment must disable bootstrap after restart");
    assert_eq!(error.code, "operator_session_missing");
}
#[tokio::test]
async fn api_token_never_bootstraps_operator_auth() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["bootstrap".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let mut headers = base_headers();
    headers.insert("x-api-token", HeaderValue::from_static("bootstrap"));
    let error = auth
        .authorize_bootstrap(&headers, Some(loopback_ip()), ACTION_REGISTER_OPTIONS)
        .await
        .expect_err("Torii API tokens must not bootstrap operator auth");
    assert_eq!(error.code, "operator_token_missing");
}
#[tokio::test]
async fn operator_auth_enforces_mtls_and_lockout() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let lockout = OperatorAuthLockout {
        failures: std::num::NonZeroU32::new(2),
        ..OperatorAuthLockout::default()
    };
    let mut config = base_operator_auth_config(
        vec!["valid".to_owned()],
        lockout,
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    config.require_mtls = true;
    let auth = build_operator_auth(config, tempdir.path());
    let err = auth
        .authorize_login(&base_headers(), None, ACTION_LOGIN_OPTIONS)
        .await
        .expect_err("missing mTLS");
    assert_eq!(err.code, "operator_mtls_required");
    assert_eq!(
        auth.lockout.entries.lock().len(),
        0,
        "callers outside the trusted mTLS boundary must not consume lockout state"
    );
    let mut headers = base_headers();
    headers.insert(
        HEADER_MTLS_FORWARD,
        HeaderValue::from_static("cert=present"),
    );
    let _ = auth
        .authorize_operator_endpoint(&headers, Some(loopback_ip()))
        .await;
    let _ = auth
        .authorize_operator_endpoint(&headers, Some(loopback_ip()))
        .await;
    let err = auth
        .authorize_operator_endpoint(&headers, Some(loopback_ip()))
        .await
        .expect_err("locked out");
    assert_eq!(err.code, "operator_auth_locked");
}
#[test]
fn login_options_do_not_clear_assertion_failures() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let lockout = OperatorAuthLockout {
        failures: std::num::NonZeroU32::new(2),
        ..OperatorAuthLockout::default()
    };
    let config =
        base_operator_auth_config(Vec::new(), lockout, vec![OperatorWebAuthnAlgorithm::Es256]);
    let auth = build_operator_auth(config, tempdir.path());
    auth.credentials_write()
        .expect("credential lock")
        .push(StoredCredential {
            id: vec![1],
            public_key: vec![2],
            alg: OperatorWebAuthnAlgorithm::Es256,
            sign_count: 0,
            created_at_ms: 0,
        });
    let ctx = AuthContext {
        key: "caller".to_owned(),
        enrollment_authority: EnrollmentAuthority::None,
    };

    auth.record_failure(&ctx, ACTION_LOGIN_VERIFY, "invalid_assertion")
        .expect("lockout state has capacity");
    auth.webauthn_authentication_options(&ctx)
        .expect("issue another login challenge");
    auth.record_failure(&ctx, ACTION_LOGIN_VERIFY, "invalid_assertion")
        .expect("lockout state has capacity");

    assert!(auth.lockout.is_locked(&ctx.key));
}
#[test]
fn operational_errors_do_not_advance_lockout() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let lockout = OperatorAuthLockout {
        failures: std::num::NonZeroU32::new(1),
        ..OperatorAuthLockout::default()
    };
    let config =
        base_operator_auth_config(Vec::new(), lockout, vec![OperatorWebAuthnAlgorithm::Es256]);
    let auth = build_operator_auth(config, tempdir.path());
    let ctx = AuthContext {
        key: "caller".to_owned(),
        enrollment_authority: EnrollmentAuthority::None,
    };

    let operational = OperatorAuthError::random_bytes_failure("entropy unavailable");
    let returned = auth.record_error(&ctx, ACTION_LOGIN_VERIFY, operational);
    assert_eq!(returned.code, "operator_auth_random_bytes_failed");
    assert!(!auth.lockout.is_locked(&ctx.key));

    let denial = OperatorAuthError::signature_invalid();
    let returned = auth.record_error(&ctx, ACTION_LOGIN_VERIFY, denial);
    assert_eq!(returned.code, "operator_webauthn_signature_invalid");
    assert!(auth.lockout.is_locked(&ctx.key));
}
#[tokio::test]
async fn full_lockout_state_does_not_starve_valid_unseen_identity() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let lockout = OperatorAuthLockout {
        failures: std::num::NonZeroU32::new(10),
        ..OperatorAuthLockout::default()
    };
    let mut config =
        base_operator_auth_config(Vec::new(), lockout, vec![OperatorWebAuthnAlgorithm::Es256]);
    config.ephemeral_state_capacity = NonZeroUsize::new(1).expect("non-zero capacity");
    let auth = build_operator_auth(config, tempdir.path());
    auth.lockout
        .record_failure("198.51.100.1")
        .expect("first identity fits");
    let ctx = AuthContext {
        key: "198.51.100.2".to_owned(),
        enrollment_authority: EnrollmentAuthority::None,
    };

    let returned = auth.record_error(
        &ctx,
        ACTION_LOGIN_VERIFY,
        OperatorAuthError::signature_invalid(),
    );
    assert_eq!(returned.code, "operator_webauthn_signature_invalid");
    assert_eq!(auth.lockout.entries.lock().len(), 1);
    assert!(!auth.lockout.is_locked(&ctx.key));

    let now = Instant::now();
    let session = test_session_token(3);
    auth.sessions
        .lock()
        .insert(
            session.clone(),
            SessionEntry {
                credential_revocation_generation: auth
                    .credential_revocation_generation
                    .load(Ordering::Acquire),
            },
            now + Duration::from_secs(60),
            now,
        )
        .expect("session store has its independent capacity");
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_OPERATOR_SESSION,
        HeaderValue::from_str(&session).expect("session header"),
    );
    auth.authorize_operator_endpoint(
        &headers,
        Some("198.51.100.2".parse().expect("unseen caller IP")),
    )
    .await
    .expect("full attacker-selected lockout state must not reject a valid unseen caller");
}
#[test]
fn lockout_identity_state_is_bounded_and_preserves_tracked_locks() {
    let tracker = LockoutTracker::new(
        OperatorAuthLockout {
            failures: std::num::NonZeroU32::new(2),
            window: Duration::from_secs(60),
            duration: Duration::from_secs(60),
        },
        NonZeroUsize::new(2).expect("non-zero capacity"),
    );

    assert_eq!(tracker.record_failure("caller-a"), Ok(false));
    assert_eq!(tracker.record_failure("caller-b"), Ok(false));
    assert_eq!(tracker.entries.lock().len(), 2);
    assert!(!tracker.is_locked("caller-c"));
    assert_eq!(tracker.record_failure("caller-c"), Ok(false));
    assert_eq!(tracker.entries.lock().len(), 2);
    assert_eq!(tracker.record_failure("caller-a"), Ok(true));
    assert!(tracker.is_locked("caller-a"));

    tracker.clear("caller-a");
    assert!(!tracker.is_locked("caller-c"));
    assert_eq!(tracker.record_failure("caller-c"), Ok(false));
    assert_eq!(tracker.entries.lock().len(), 2);
}
#[test]
fn ephemeral_store_reclaims_expired_entries_without_evicting_live_state() {
    let capacity = NonZeroUsize::new(2).expect("non-zero capacity");
    let mut store = BoundedExpiringStore::new(capacity);
    let now = Instant::now();
    let soon = now + Duration::from_secs(1);
    let later = now + Duration::from_secs(10);

    store
        .insert("soon".to_owned(), 1, soon, now)
        .expect("first entry");
    store
        .insert("later".to_owned(), 2, later, now)
        .expect("second entry");
    assert_eq!(
        store.insert("live-eviction".to_owned(), 3, later, now),
        Err(ExpiringStoreAtCapacity)
    );

    let after_soon = soon + Duration::from_nanos(1);
    store
        .insert("replacement".to_owned(), 3, later, after_soon)
        .expect("expired entry releases capacity");
    assert_eq!(store.get("soon", after_soon), None);
    assert_eq!(store.get("later", after_soon), Some(&2));
    assert_eq!(store.get("replacement", after_soon), Some(&3));
}
#[test]
fn concurrent_ephemeral_admission_never_exceeds_capacity() {
    let capacity = NonZeroUsize::new(8).expect("non-zero capacity");
    let store = Mutex::new(BoundedExpiringStore::new(capacity));
    let now = Instant::now();
    let expires_at = now + Duration::from_secs(60);

    std::thread::scope(|scope| {
        for index in 0..64 {
            let store = &store;
            scope.spawn(move || {
                let _ = store
                    .lock()
                    .insert(format!("caller-{index}"), index, expires_at, now);
            });
        }
    });

    assert_eq!(store.lock().len(), capacity.get());
}
#[tokio::test]
async fn operator_auth_rejects_forwarded_mtls_from_untrusted_proxy() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let mut config = base_operator_auth_config(
        vec!["valid".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    config.require_mtls = true;
    let auth = build_operator_auth(config, tempdir.path());
    let mut headers = base_headers();
    headers.insert(
        HEADER_MTLS_FORWARD,
        HeaderValue::from_static("cert=present"),
    );
    let err = auth
        .authorize_login(
            &headers,
            Some("198.51.100.10".parse().expect("untrusted proxy")),
            ACTION_LOGIN_OPTIONS,
        )
        .await
        .expect_err("untrusted proxy must not satisfy mTLS");
    assert_eq!(err.code, "operator_mtls_required");
}
#[tokio::test]
async fn operator_auth_key_uses_remote_ip_when_internal_header_missing() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["valid".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let remote_ip: IpAddr = "198.51.100.33".parse().expect("remote ip");
    let ctx = auth
        .authorize_login(&HeaderMap::new(), Some(remote_ip), ACTION_LOGIN_OPTIONS)
        .await
        .expect("login key derivation should succeed");
    assert_eq!(ctx.key, remote_ip.to_string());
}
#[tokio::test]
async fn operator_auth_key_prefers_injected_header_over_transport_remote_ip() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let config = base_operator_auth_config(
        vec!["valid".to_owned()],
        OperatorAuthLockout::default(),
        vec![OperatorWebAuthnAlgorithm::Es256],
    );
    let auth = build_operator_auth(config, tempdir.path());
    let mut headers = HeaderMap::new();
    headers.insert(
        limits::REMOTE_ADDR_HEADER,
        HeaderValue::from_static("203.0.113.77"),
    );
    let ctx = auth
        .authorize_login(
            &headers,
            Some("198.51.100.33".parse().expect("transport remote ip")),
            ACTION_LOGIN_OPTIONS,
        )
        .await
        .expect("login key derivation should succeed");
    assert_eq!(ctx.key, "203.0.113.77");
}
#[test]
fn ed25519_cose_key_and_signature_verify() {
    let mut rng = OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key().to_bytes();
    let map = vec![
        (CborValue::Integer(1.into()), CborValue::Integer(1.into())),
        (
            CborValue::Integer(3.into()),
            CborValue::Integer((-8).into()),
        ),
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(6.into()),
        ),
        (
            CborValue::Integer((-2).into()),
            CborValue::Bytes(public_key.to_vec()),
        ),
    ];
    let cose_key = CborValue::Map(map);
    let parsed =
        parse_cose_key(&cose_key, &[OperatorWebAuthnAlgorithm::Ed25519]).expect("parse cose key");
    assert_eq!(parsed.alg, OperatorWebAuthnAlgorithm::Ed25519);
    assert_eq!(parsed.public_key, public_key.to_vec());
    let message = b"operator-auth-test";
    let signature = signing_key.sign(message).to_bytes();
    verify_signature(
        OperatorWebAuthnAlgorithm::Ed25519,
        &public_key,
        message,
        &signature,
    )
    .expect("signature ok");
}
#[test]
fn es256_cose_key_rejects_all_zero_public_key_material() {
    let map = vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
        (
            CborValue::Integer(3.into()),
            CborValue::Integer((-7).into()),
        ),
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(1.into()),
        ),
        (
            CborValue::Integer((-2).into()),
            CborValue::Bytes(vec![0u8; 32]),
        ),
        (
            CborValue::Integer((-3).into()),
            CborValue::Bytes(vec![0u8; 32]),
        ),
    ];
    let cose_key = CborValue::Map(map);
    let err = match parse_cose_key(&cose_key, &[OperatorWebAuthnAlgorithm::Es256]) {
        Ok(_) => panic!("all-zero ES256 public key material must be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code, "operator_webauthn_payload_invalid");
    assert_eq!(err.metric_label, "invalid_payload");
}
#[test]
fn es256_signature_verify_rejects_all_zero_signature_material() {
    let signing_key = SigningKey::random(&mut OsRng);
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let signature = [0u8; 64];
    let err = verify_signature(
        OperatorWebAuthnAlgorithm::Es256,
        public_key.as_bytes(),
        b"operator-auth-test",
        &signature,
    )
    .expect_err("all-zero ES256 signature material must be rejected");
    assert_eq!(err.code, "operator_webauthn_signature_invalid");
    assert_eq!(err.metric_label, "signature_invalid");
}
#[test]
fn es256_signature_verify_rejects_all_zero_public_key_material() {
    let signing_key = SigningKey::random(&mut OsRng);
    let message = b"operator-auth-test";
    let signature: p256::ecdsa::Signature = signing_key.sign(message);
    let mut public_key = Vec::with_capacity(P256_UNCOMPRESSED_SEC1_PUBLIC_KEY_LEN);
    public_key.push(0x04);
    public_key.extend_from_slice(&[0u8; 64]);
    let err = verify_signature(
        OperatorWebAuthnAlgorithm::Es256,
        &public_key,
        message,
        signature.to_der().as_bytes(),
    )
    .expect_err("all-zero ES256 public key material must be rejected");
    assert_eq!(err.code, "operator_webauthn_payload_invalid");
    assert_eq!(err.metric_label, "invalid_payload");
}
#[test]
fn es256_signature_verify_rejects_high_s_signature_material() {
    const P256_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let signing_key = SigningKey::random(&mut OsRng);
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let message = b"operator-auth-test-high-s";
    let low_s = {
        let signature: P256Signature = signing_key.sign(message);
        signature.normalize_s().unwrap_or(signature)
    };
    let low_s_bytes = low_s.to_bytes();
    let mut high_s_bytes = [0_u8; 64];
    high_s_bytes[..32].copy_from_slice(&low_s_bytes[..32]);
    let mut borrow = 0_u16;
    for i in (0..32).rev() {
        let minuend = i16::from(P256_ORDER[i]) - i16::from(borrow as u8);
        let subtrahend = i16::from(low_s_bytes[32 + i]);
        if minuend >= subtrahend {
            high_s_bytes[32 + i] =
                u8::try_from(minuend - subtrahend).expect("nonnegative byte difference");
            borrow = 0;
        } else {
            high_s_bytes[32 + i] =
                u8::try_from(minuend + 256 - subtrahend).expect("borrowed byte difference");
            borrow = 1;
        }
    }
    assert_eq!(borrow, 0);
    let high_s = P256Signature::from_slice(&high_s_bytes).expect("high-S signature");
    assert!(high_s.normalize_s().is_some());
    let err = verify_signature(
        OperatorWebAuthnAlgorithm::Es256,
        public_key.as_bytes(),
        message,
        high_s.to_der().as_bytes(),
    )
    .expect_err("high-S ES256 signature material must be rejected");
    assert_eq!(err.code, "operator_webauthn_signature_invalid");
    assert_eq!(err.metric_label, "signature_invalid");
}
#[test]
fn ed25519_signature_verify_rejects_all_zero_signature_material() {
    let mut rng = OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key().to_bytes();
    let signature = [0u8; 64];
    let err = verify_signature(
        OperatorWebAuthnAlgorithm::Ed25519,
        &public_key,
        b"operator-auth-test",
        &signature,
    )
    .expect_err("all-zero signature material must be rejected");
    assert_eq!(err.code, "operator_webauthn_signature_invalid");
    assert_eq!(err.metric_label, "signature_invalid");
}
#[test]
fn ed25519_signature_verify_rejects_all_zero_public_key_material() {
    let mut rng = OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let message = b"operator-auth-test";
    let signature = signing_key.sign(message).to_bytes();
    let err = verify_signature(
        OperatorWebAuthnAlgorithm::Ed25519,
        &[0u8; 32],
        message,
        &signature,
    )
    .expect_err("all-zero Ed25519 public key material must be rejected");
    assert_eq!(err.code, "operator_webauthn_signature_invalid");
    assert_eq!(err.metric_label, "signature_invalid");
}
#[test]
fn ed25519_signature_verify_rejects_weak_or_noncanonical_public_key_material() {
    let mut rng = OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let message = b"operator-auth-test";
    let signature = signing_key.sign(message).to_bytes();
    for (label, public_key_bytes) in [
        ("small-order", ED25519_SMALL_ORDER_POINT),
        ("noncanonical", ED25519_NONCANONICAL_IDENTITY),
    ] {
        let err = verify_signature(
            OperatorWebAuthnAlgorithm::Ed25519,
            &public_key_bytes,
            message,
            &signature,
        )
        .expect_err("malformed Ed25519 public key material must be rejected");
        assert_eq!(
            err.code, "operator_webauthn_signature_invalid",
            "{label} public key should fail"
        );
        assert_eq!(
            err.metric_label, "signature_invalid",
            "{label} public key should map to signature_invalid"
        );
    }
}
#[test]
fn ed25519_signature_verify_rejects_malformed_signature_r() {
    let mut rng = OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let public_key = signing_key.verifying_key().to_bytes();
    let message = b"operator-auth-test";
    for (label, replacement_r) in [
        ("small-order", ED25519_SMALL_ORDER_POINT),
        ("noncanonical", ED25519_NONCANONICAL_IDENTITY),
    ] {
        let mut signature = signing_key.sign(message).to_bytes();
        signature[..32].copy_from_slice(&replacement_r);
        let err = verify_signature(
            OperatorWebAuthnAlgorithm::Ed25519,
            &public_key,
            message,
            &signature,
        )
        .expect_err("malformed Ed25519 signature R must be rejected");
        assert_eq!(
            err.code, "operator_webauthn_signature_invalid",
            "{label} signature R should fail"
        );
        assert_eq!(
            err.metric_label, "signature_invalid",
            "{label} signature R should map to signature_invalid"
        );
    }
}
#[tokio::test]
async fn operator_auth_handlers_reject_when_disabled() {
    let app = crate::tests_runtime_handlers::mk_app_state_for_tests();
    let headers = HeaderMap::new();
    let err = handle_operator_register_options(
        State(app.clone()),
        loopback_connect_info(),
        headers.clone(),
        Body::empty(),
    )
    .await
    .err()
    .expect("register options disabled");
    assert_eq!(err.code, "operator_auth_disabled");
    let err = handle_operator_login_options(
        State(app.clone()),
        loopback_connect_info(),
        headers.clone(),
        Body::empty(),
    )
    .await
    .err()
    .expect("login options disabled");
    assert_eq!(err.code, "operator_auth_disabled");
    let err = handle_operator_credentials(State(app.clone()))
        .await
        .err()
        .expect("credential inventory disabled");
    assert_eq!(err.code, "operator_webauthn_disabled");
    let err = handle_operator_credential_delete(
        State(app),
        AxumPath(encode_b64url(b"credential")),
        headers,
    )
    .await
    .err()
    .expect("credential deletion disabled");
    assert_eq!(err.code, "operator_webauthn_disabled");
}
#[test]
fn operator_auth_error_response_sets_status() {
    let response = OperatorAuthError::missing_token().into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
