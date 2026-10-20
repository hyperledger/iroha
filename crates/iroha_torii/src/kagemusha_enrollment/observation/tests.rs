//! Actual local TLS exchanges, bounded responses and retained credential mutation cases.

use super::*;
use std::{
    io::Write as _,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
    thread::{self, JoinHandle},
};
use tokio_rustls::rustls::{
    ServerConfig, ServerConnection, StreamOwned, crypto::ring, pki_types::PrivatePkcs8KeyDer,
};

fn credential(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/qualification/enrollment-observation-tests");
    std::fs::create_dir_all(&base).unwrap();
    let base = base.canonicalize().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("private-")
        .tempdir_in(base)
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let owner = iroha_fs::PrivateDirectory::open(directory.path()).unwrap();
    owner
        .write_atomic("transport", bytes, iroha_fs::PublishMode::CreateNew)
        .unwrap();
    let path = directory.path().join("transport");
    (directory, path)
}

struct Server {
    endpoint: Url,
    certificate: reqwest::Certificate,
    task: JoinHandle<io::Result<Vec<u8>>>,
}

impl Server {
    fn start(response: Vec<u8>, before_reply: impl FnOnce() + Send + 'static) -> Self {
        Self::respond(move |_| {
            before_reply();
            response
        })
    }

    fn respond(respond: impl FnOnce(&[u8]) -> Vec<u8> + Send + 'static) -> Self {
        let identity = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let certificate = reqwest::Certificate::from_der(identity.cert.der()).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("https://{}/eligibility", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let task = thread::spawn(move || {
            let (socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;
            let connection = ServerConnection::new(Arc::new(config)).map_err(io::Error::other)?;
            let mut stream = StreamOwned::new(connection, socket);
            let request = read_request(&mut stream)?;
            let response = respond(&request);
            stream.write_all(&response)?;
            stream.flush()?;
            Ok(request)
        });
        Self {
            endpoint,
            certificate,
            task,
        }
    }

    fn open(&self, path: &Path) -> ObservationHttp {
        ObservationHttp::open(
            &self.endpoint,
            path,
            client_builder().add_root_certificate(self.certificate.clone()),
        )
        .unwrap()
    }
}

fn read_request(stream: &mut StreamOwned<ServerConnection, TcpStream>) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut byte = [0; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        request.push(byte[0]);
        if request.len() > 8192 {
            return Err(io::Error::other("test header cap"));
        }
    }
    let headers = String::from_utf8(request.clone()).map_err(io::Error::other)?;
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    assert!(length <= KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1);
    let start = request.len();
    request.resize(start + length, 0);
    stream.read_exact(&mut request[start..])?;
    Ok(request)
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: {MIME}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(body);
    response
}

#[test]
fn exact_request_and_bearer_reach_verified_tls_and_exact_response_returns() {
    let (_root, path) = credential(b"test-only-token_1+/=");
    let server = Server::start(ok(b"exact-response-DATA"), || {});
    let owner = server.open(&path);
    assert_eq!(
        owner
            .observe(b"exact-request-DATA", Duration::from_secs(3))
            .unwrap(),
        b"exact-response-DATA"
    );
    let request = server.task.join().unwrap().unwrap();
    let request = String::from_utf8(request).unwrap();
    assert!(request.starts_with("POST /eligibility HTTP/1.1\r\n"));
    assert!(request.contains("authorization: Bearer test-only-token_1+/=\r\n"));
    assert!(request.contains("content-type: application/x-norito\r\n"));
    assert!(request.contains("accept: application/x-norito\r\n"));
    assert!(request.ends_with("\r\n\r\nexact-request-DATA"));
}

#[test]
fn untrusted_tls_and_deadline_expiry_are_unavailable_without_a_verdict() {
    let (_root, path) = credential(b"test-only-token");
    let server = Server::start(ok(b"response"), || {});
    // Production trust configuration must reject this untrusted test-only self-signed root.
    let owner = ObservationHttp::open(&server.endpoint, &path, client_builder()).unwrap();
    assert!(matches!(
        owner.observe(b"request", Duration::from_secs(3)),
        Err(Error::Unavailable)
    ));
    assert!(server.task.join().unwrap().is_err());

    let server = Server::start(ok(b"response"), || {
        thread::sleep(Duration::from_millis(250));
    });
    assert!(matches!(
        server
            .open(&path)
            .observe(b"request", Duration::from_millis(100)),
        Err(Error::Unavailable)
    ));
    // A timed-out client may close before the test server writes its delayed response.
    let _ = server.task.join().unwrap();
}

#[test]
fn bounded_responses_reject_missing_type_encoding_oversize_and_truncation() {
    let (_root, path) = credential(b"test-only-token");
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-norito\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-norito\r\nContent-Type: application/x-norito\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),
        ok(&[]),
        ok(&vec![1; KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 + 1]),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/x-norito\r\nContent-Length: 32\r\nConnection: close\r\n\r\nshort".to_vec(),
        [b"HTTP/1.1 200 OK\r\nContent-Type: application/x-norito\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n801\r\n".as_slice(),
          &vec![1; 2049], b"\r\n0\r\n\r\n"].concat(),
    ] {
        let server = Server::start(response, || {});
        assert!(server.open(&path).observe(b"request", Duration::from_secs(3)).is_err());
        server.task.join().unwrap().unwrap();
    }
    assert_eq!(bounded_body(&vec![3; 2048][..]).unwrap().len(), 2048);
    assert!(bounded_body(&vec![3; 2049][..]).is_err());
}

#[test]
fn redirects_and_error_statuses_never_become_observations_or_forward_credentials() {
    let (_root, path) = credential(b"test-only-token");
    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    for status in [301, 302, 307, 308, 401, 403, 404, 429, 500, 503] {
        let reply = format!(
            "HTTP/1.1 {status} unavailable\r\nLocation: https://{}/capture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            destination.local_addr().unwrap()
        );
        let server = Server::start(reply.into_bytes(), || {});
        assert!(matches!(
            server
                .open(&path)
                .observe(b"request", Duration::from_secs(3)),
            Err(Error::Unavailable)
        ));
        server.task.join().unwrap().unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn credentials_are_required_bounded_private_and_stable_before_and_after_io() {
    for token in [
        Vec::new(),
        vec![b'a'; 4097],
        b"test\ntoken".to_vec(),
        b" test".to_vec(),
        vec![255],
    ] {
        let (_root, path) = credential(&token);
        assert!(matches!(Credential::open(&path), Err(Error::Invalid)));
    }
    let (_root, path) = credential(b"test-only-token");
    let owner = Credential::open(&path).unwrap();
    let header = owner.authorization().unwrap();
    assert!(header.is_sensitive());
    let missing = path.with_file_name("missing");
    assert!(matches!(
        Credential::open(&missing),
        Err(Error::Unavailable)
    ));
    assert!(!missing.exists());
    assert!(matches!(
        Credential::open(Path::new("relative")),
        Err(Error::Selection)
    ));
    // Same inode, length and permissions: immutable source contents still cannot be replaced.
    std::fs::write(&path, b"changed--token!").unwrap();
    assert!(owner.authorization().is_err());

    let (_root, path) = credential(b"test-only-token");
    let changed = path.clone();
    let server = Server::start(ok(b"response"), move || {
        std::fs::write(changed, b"changed--token!").unwrap();
    });
    assert!(
        server
            .open(&path)
            .observe(b"request", Duration::from_secs(3))
            .is_err()
    );
    server.task.join().unwrap().unwrap();
}

#[cfg(unix)]
#[test]
fn credential_path_replacement_links_and_permissions_are_refused() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    for case in 0..4 {
        let (_root, path) = credential(b"test-only-token");
        let owner = Credential::open(&path).unwrap();
        let alternate = path.with_file_name("alternate");
        match case {
            0 => {
                std::fs::rename(&path, &alternate).unwrap();
                std::fs::write(&path, b"test-only-token").unwrap();
            }
            1 => {
                std::fs::rename(&path, &alternate).unwrap();
                symlink(&alternate, &path).unwrap();
            }
            2 => {
                std::fs::hard_link(&path, &alternate).unwrap();
            }
            _ => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap(),
        }
        assert!(owner.revalidate().is_err());
        assert!(owner.authorization().is_err());
    }
}

#[test]
fn plaintext_credentials_in_urls_and_unbounded_requests_are_refused() {
    let (_root, path) = credential(b"test-only-token");
    for endpoint in [
        "http://example.com/",
        "https://user@example.com/",
        "https://example.com/?token=secret",
        "https://example.com/#fragment",
    ] {
        assert!(matches!(
            ObservationHttp::open(&endpoint.parse().unwrap(), &path, client_builder()),
            Err(Error::Selection)
        ));
    }
    let owner = ObservationHttp::open(
        &"https://127.0.0.1:1/".parse().unwrap(),
        &path,
        client_builder(),
    )
    .unwrap();
    for original in [Vec::new(), vec![0; 2049]] {
        assert!(matches!(
            owner.observe(&original, Duration::from_secs(1)),
            Err(Error::Invalid)
        ));
    }
    for timeout in [Duration::ZERO, Duration::from_secs(61)] {
        assert!(matches!(
            owner.observe(b"request", timeout),
            Err(Error::Invalid)
        ));
    }
}

#[test]
fn outer_transport_retains_exact_provider_selection_before_any_request() {
    let (_root, path) = credential(b"test-only-token");
    let mut selected = super::super::test_fixture::provider(path.with_file_name("unused.scalar"));
    selected.observation_credential = path.clone();
    let owner = EligibilityObservationTransport::open(&selected).unwrap();
    owner.revalidate(&selected).unwrap();
    let asset = super::super::test_fixture::asset(41, 0);
    for case in 0..6 {
        let mut changed = selected.clone();
        match case {
            0 => {
                changed.observation_endpoint =
                    "https://foreign.example/eligibility".parse().unwrap()
            }
            1 => changed.observation_credential = path.with_file_name("foreign-credential"),
            2 => changed.eligibility.revision += 1,
            3 => {
                changed.eligibility.authority =
                    iroha_data_model::kagemusha::KagemushaEligibilityAuthorityV1::SchemeOperator {
                        operator_digest: selected.eligibility.authority.scope_digest(),
                    };
            }
            4 => changed.certificate.body.serial += 1,
            _ => changed.release_digest[0] ^= 1,
        }
        assert!(matches!(owner.revalidate(&changed), Err(Error::Selection)));
        // Changed selection must reject before canonical decoding or any HTTPS dispatch.
        assert!(matches!(
            owner.observe(&changed, &asset, b"malformed", Duration::from_secs(1)),
            Err(Error::Selection)
        ));
    }
}

#[test]
fn outer_transport_rejects_invalid_policy_and_foreign_request_before_network() {
    use iroha_data_model::kagemusha::KagemushaEligibilityPurposeV1;

    let (_root, path) = credential(b"test-only-token");
    let mut selected = super::super::test_fixture::provider(path.with_file_name("unused.scalar"));
    selected.observation_credential = path;
    for case in 0..4 {
        let mut invalid = selected.clone();
        match case {
            0 => invalid.eligibility.version = 0,
            1 => invalid.eligibility.scheme_id = [0; 32],
            2 => invalid.eligibility.public_key = [0; 32],
            _ => invalid.eligibility.maximum_response_ms = 0,
        }
        assert!(matches!(
            EligibilityObservationTransport::open(&invalid),
            Err(Error::Invalid)
        ));
    }
    let owner = EligibilityObservationTransport::open(&selected).unwrap();
    let asset = super::super::test_fixture::asset(5, 2);
    let mut foreign = selected.eligibility.for_asset(&asset).unwrap();
    foreign.revision += 1;
    let foreign_request = KagemushaEligibilityRequestV1 {
        version: 1,
        policy_digest: foreign.policy_digest().unwrap(),
        account_digest: [22; 32],
        actor_digest: [23; 32],
        attempt_id: [24; 32],
        nonce: [25; 32],
        operation_digest: [26; 32],
        purpose: KagemushaEligibilityPurposeV1::VerifyEvidence,
        requested_at_ms: 1000,
        expires_at_ms: 2000,
    }
    .encode_canonical(&foreign)
    .unwrap();
    for original in [
        vec![],
        b"malformed".to_vec(),
        vec![0; 2049],
        foreign_request,
    ] {
        assert!(matches!(
            owner.observe(&selected, &asset, &original, Duration::from_secs(1)),
            Err(Error::Invalid)
        ));
    }
}

#[test]
fn actual_tls_carries_canonical_asset_context_bound_to_selected_template() {
    use iroha_data_model::kagemusha::{
        KagemushaEligibilityObservationV1, KagemushaEligibilityPurposeV1,
    };
    let (_root, path) = credential(b"test-only-token");
    let server = Server::start(ok(b"response DATA"), || {});
    let mut provider = super::super::test_fixture::provider(path.with_file_name("unused.scalar"));
    provider.observation_credential = path.clone();
    provider.observation_endpoint = server.endpoint.clone();
    let asset = super::super::test_fixture::asset(51, 28);
    let policy = provider.eligibility.for_asset(&asset).unwrap();
    let request = KagemushaEligibilityRequestV1 {
        version: 1,
        policy_digest: policy.policy_digest().unwrap(),
        account_digest: [22; 32],
        actor_digest: [23; 32],
        attempt_id: [24; 32],
        nonce: [25; 32],
        operation_digest: [26; 32],
        purpose: KagemushaEligibilityPurposeV1::VerifyEvidence,
        requested_at_ms: 1000,
        expires_at_ms: 2000,
    };
    let owner = EligibilityObservationTransport {
        selected: provider.clone(),
        http: server.open(&path),
    };
    assert_eq!(
        owner
            .observe(
                &provider,
                &asset,
                &request.encode_canonical(&policy).unwrap(),
                Duration::from_secs(3)
            )
            .unwrap(),
        b"response DATA"
    );
    let sent = server.task.join().unwrap().unwrap();
    let start = sent.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
    let decoded =
        KagemushaEligibilityObservationV1::decode_canonical(&sent[start..], &provider.eligibility)
            .unwrap();
    assert_eq!(decoded.asset, asset);
    assert_eq!(decoded.request, request);
    assert_eq!(decoded.policy(&provider.eligibility).unwrap(), policy);
}

/// Authenticate the test issuer transport before handing its exact body to middleware.
fn authenticated_observation_body(request: &[u8]) -> &[u8] {
    let start = request.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
    let headers = std::str::from_utf8(&request[..start]).unwrap();
    assert!(headers.starts_with("POST /eligibility HTTP/1.1\r\n"));
    for header in [
        "authorization: Bearer test-only-token",
        "content-type: application/x-norito",
        "accept: application/x-norito",
    ] {
        assert_eq!(headers.lines().filter(|line| *line == header).count(), 1);
    }
    &request[start..]
}

#[test]
fn actual_middleware_signs_fresh_bank_and_operator_observations_across_tls() {
    use iroha::kagemusha_enrollment::{
        CurrentEnrollmentEligibilityV1, answer_enrollment_eligibility_v1,
        sign_enrollment_eligibility_v1,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::kagemusha::{
        KagemushaEligibilityAuthorityV1 as Authority, KagemushaEligibilityDecisionV1 as Decision,
        KagemushaEligibilityPurposeV1 as Purpose, KagemushaEligibilityResponseV1,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    for authority in [
        Authority::Bank { fi_digest: [8; 32] },
        Authority::SchemeOperator {
            operator_digest: [8; 32],
        },
    ] {
        let (_root, path) = credential(b"test-only-token");
        let mut provider =
            super::super::test_fixture::provider(path.with_file_name("unused.scalar"));
        provider.observation_credential = path.clone();
        provider.eligibility.authority = authority;
        // One independently selected provider template serves unrelated exact token scopes.
        let mut other_asset_response: Option<Vec<u8>> = None;
        for (seed, scale) in [(61, 0), (83, 2), (107, 28)] {
            let asset = super::super::test_fixture::asset(seed, scale);
            let template = provider.eligibility;
            let policy = template.for_asset(&asset).unwrap();
            let reads = Arc::new(AtomicUsize::new(0));
            let signs = Arc::new(AtomicUsize::new(0));
            let clocks = Arc::new(AtomicUsize::new(0));
            let current = Arc::new(Mutex::new(CurrentEnrollmentEligibilityV1 {
                approved: false,
                frozen: false,
                revision: 1,
                observed_at_ms: 1101,
            }));
            let mut previous: Option<Vec<u8>> = None;
            for (index, (purpose, approved, frozen, decision)) in [
                (
                    Purpose::PreKeyPermit,
                    true,
                    false,
                    Decision::ApprovedUnfrozen,
                ),
                (Purpose::VerifyEvidence, true, true, Decision::Frozen),
                (
                    Purpose::IssueCredential,
                    false,
                    false,
                    Decision::NotApproved,
                ),
                (
                    Purpose::DeliverCredential,
                    true,
                    false,
                    Decision::ApprovedUnfrozen,
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let revision = u64::try_from(index + 1).unwrap();
                *current.lock().unwrap() = CurrentEnrollmentEligibilityV1 {
                    approved,
                    frozen,
                    revision,
                    observed_at_ms: 1101,
                };
                let request = KagemushaEligibilityRequestV1 {
                    version: 1,
                    policy_digest: policy.policy_digest().unwrap(),
                    account_digest: [22; 32],
                    actor_digest: [23; 32],
                    attempt_id: [24; 32],
                    nonce: [u8::try_from(index + 1).unwrap(); 32],
                    operation_digest: [u8::try_from(index + 41).unwrap(); 32],
                    purpose,
                    requested_at_ms: 1000,
                    expires_at_ms: 2000,
                };
                let expected_asset = asset.clone();
                let read_count = reads.clone();
                let sign_count = signs.clone();
                let clock_count = clocks.clone();
                let source = current.clone();
                let server = Server::respond(move |wire| {
                    let original = authenticated_observation_body(wire);
                    let key = KeyPair::from_seed(vec![7; 32], Algorithm::Ed25519);
                    assert_eq!(key.public_key().to_bytes().1, template.public_key);
                    let mut times = [1100, 1101, 1102].into_iter();
                    let response = answer_enrollment_eligibility_v1(
                        &template,
                        original,
                        || {
                            clock_count.fetch_add(1, Ordering::SeqCst);
                            Ok(times.next().unwrap())
                        },
                        |actual_asset, actual_policy, actual_request| {
                            read_count.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(actual_asset, &expected_asset);
                            assert_eq!(actual_policy, &policy);
                            assert_eq!(actual_request, &request);
                            Ok(*source.lock().unwrap())
                        },
                        |message| {
                            sign_count.fetch_add(1, Ordering::SeqCst);
                            sign_enrollment_eligibility_v1(&key, message)
                        },
                    )
                    .unwrap();
                    ok(&response)
                });
                provider.observation_endpoint = server.endpoint.clone();
                let owner = EligibilityObservationTransport {
                    selected: provider.clone(),
                    http: server.open(&path),
                };
                let original = owner
                    .observe(
                        &provider,
                        &asset,
                        &request.encode_canonical(&policy).unwrap(),
                        Duration::from_secs(3),
                    )
                    .unwrap();
                let response = KagemushaEligibilityResponseV1::decode_canonical(
                    &original, &policy, &request, 1102,
                )
                .unwrap();
                assert_eq!(response.encode_canonical().unwrap(), original);
                assert_eq!(response.body.decision, decision);
                assert_eq!(response.body.source_revision, revision);
                assert_eq!(
                    response.body.request_digest,
                    request.request_digest(&policy).unwrap()
                );
                assert_eq!(response.body.observed_at_ms, 1101);
                assert_eq!(response.body.valid_until_ms, 2000);
                if let Some(foreign) = other_asset_response.as_deref() {
                    assert!(
                        KagemushaEligibilityResponseV1::decode_canonical(
                            foreign, &policy, &request, 1102,
                        )
                        .is_err()
                    );
                }
                let sent = server.task.join().unwrap().unwrap();
                let observed = KagemushaEligibilityObservationV1::decode_canonical(
                    authenticated_observation_body(&sent),
                    &template,
                )
                .unwrap();
                assert_eq!(observed.asset, asset);
                assert_eq!(observed.request, request);
                // Rebinding otherwise valid signatures to another nonce or purpose must fail.
                let mut changed = request;
                changed.nonce[0] ^= 0x80;
                assert!(
                    KagemushaEligibilityResponseV1::decode_canonical(
                        &original, &policy, &changed, 1102,
                    )
                    .is_err()
                );
                let mut changed = request;
                changed.purpose = if purpose == Purpose::PreKeyPermit {
                    Purpose::DeliverCredential
                } else {
                    Purpose::PreKeyPermit
                };
                assert!(
                    KagemushaEligibilityResponseV1::decode_canonical(
                        &original, &policy, &changed, 1102,
                    )
                    .is_err()
                );
                if let Some(old) = previous {
                    assert!(
                        KagemushaEligibilityResponseV1::decode_canonical(
                            &old, &policy, &request, 1102,
                        )
                        .is_err()
                    );
                }
                previous = Some(original);
                assert_eq!(reads.load(Ordering::SeqCst), index + 1);
                assert_eq!(signs.load(Ordering::SeqCst), index + 1);
                assert_eq!(clocks.load(Ordering::SeqCst), 3 * (index + 1));
            }
            other_asset_response = previous;
        }
    }
}

#[test]
fn actual_middleware_refuses_substituted_assets_and_unavailable_sources_across_tls() {
    use iroha::kagemusha_enrollment::{
        EnrollmentEligibilityMiddlewareErrorV1 as MiddlewareError, answer_enrollment_eligibility_v1,
    };
    use iroha_data_model::kagemusha::{
        KagemushaEligibilityAuthorityV1 as Authority, KagemushaEligibilityPurposeV1 as Purpose,
    };

    for authority in [
        Authority::Bank { fi_digest: [8; 32] },
        Authority::SchemeOperator {
            operator_digest: [8; 32],
        },
    ] {
        let (_root, path) = credential(b"test-only-token");
        let mut provider =
            super::super::test_fixture::provider(path.with_file_name("unused.scalar"));
        provider.observation_credential = path.clone();
        provider.eligibility.authority = authority;
        let template = provider.eligibility;
        let asset = super::super::test_fixture::asset(61, 2);
        let policy = template.for_asset(&asset).unwrap();
        let request = KagemushaEligibilityRequestV1 {
            version: 1,
            policy_digest: policy.policy_digest().unwrap(),
            account_digest: [22; 32],
            actor_digest: [23; 32],
            attempt_id: [24; 32],
            nonce: [25; 32],
            operation_digest: [26; 32],
            purpose: Purpose::VerifyEvidence,
            requested_at_ms: 1000,
            expires_at_ms: 2000,
        };
        // All three exact asset coordinates are authenticated by the retained inner request.
        for case in 0..4 {
            let mut observation = KagemushaEligibilityObservationV1 {
                version: 1,
                asset: asset.clone(),
                request,
            };
            let foreign = super::super::test_fixture::asset(83, 28);
            match case {
                0 => observation.asset.asset = foreign.asset,
                1 => observation.asset.asset_incarnation = foreign.asset_incarnation,
                2 => observation.asset.scale = foreign.scale,
                _ => {}
            }
            // The first three use canonical framing but intentionally bypass semantic validation
            // to exercise the independent middleware boundary after genuine HTTPS transport.
            let original = norito::encode_canonical(&observation).unwrap();
            let server = Server::respond(move |wire| {
                let mut clocks = 0;
                let mut reads = 0;
                let result = answer_enrollment_eligibility_v1(
                    &template,
                    authenticated_observation_body(wire),
                    || {
                        clocks += 1;
                        Ok(1100)
                    },
                    |_, _, _| {
                        reads += 1;
                        Err(MiddlewareError::Unavailable)
                    },
                    |_| panic!("invalid or unavailable current authority must never sign"),
                );
                assert_eq!(
                    result,
                    Err(if case == 3 {
                        MiddlewareError::Unavailable
                    } else {
                        MiddlewareError::InvalidRequest
                    })
                );
                assert_eq!(reads, usize::from(case == 3));
                assert_eq!(clocks, usize::from(case == 3));
                // An unavailable observation is an HTTP error, not a signed decision arm.
                b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec()
            });
            assert!(matches!(
                server
                    .open(&path)
                    .observe(&original, Duration::from_secs(3)),
                Err(Error::Unavailable)
            ));
            let sent = server.task.join().unwrap().unwrap();
            assert_eq!(authenticated_observation_body(&sent), original);
        }
    }
}
