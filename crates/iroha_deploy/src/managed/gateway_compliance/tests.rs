//! Real generated signing material over scripted runtime HTTP observations; no native Serving claim.

use super::*;
use crate::{
    localnet::{LocalnetServiceProfile, prepare_localnet_at},
    managed::native_operation::test_support::wallet_http::{WalletHttpRequest, wallet_request},
};
use iroha_torii_shared::{
    route_catalog::contracts_and_verification_keys as routes,
    sorafs_gateway_compliance_api::{
        GATEWAY_COMPLIANCE_ACTION_SCHEMA_V1, GATEWAY_COMPLIANCE_STATUS_SCHEMA_V1,
        GatewayComplianceActionResponseV1, GatewayComplianceLatestActionStatusV1,
        request_idempotency_binding,
    },
};
use std::{
    collections::VecDeque,
    io::{self, Write as _},
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

// This guard tests publisher refusal paths only. It does not substitute for the
// worker's actual owned-Child/revision guard or confer any native eligibility.
#[derive(Default)]
struct TestLive {
    checks: usize,
    fail_at: Option<usize>,
}
impl LiveGatewayProcess for TestLive {
    fn validate(&mut self, _: &PreparedLocalnet, _: &RetainedGatewayCompliancePlan) -> Result<()> {
        self.checks += 1;
        if self.fail_at.is_some_and(|at| self.checks >= at) {
            Err(invalid("test live gateway is no longer owned"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    Stage,
    Ack,
    Promote,
}
impl Mutation {
    fn action(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Ack => "acknowledge",
            Self::Promote => "promote",
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::Stage => routes::SORAFS_GATEWAY_COMPLIANCE_STAGE_POST.path(),
            Self::Ack => routes::SORAFS_GATEWAY_COMPLIANCE_ACKNOWLEDGE_POST.path(),
            Self::Promote => routes::SORAFS_GATEWAY_COMPLIANCE_PROMOTE_POST.path(),
        }
    }
}

#[derive(Clone, Copy)]
enum Observation {
    Empty,
    Candidate { ack: bool },
    Promoted,
    ForeignPolicy,
    ForeignCandidate,
    ForeignHead,
    Stale,
}
#[derive(Clone, Copy)]
enum RetainedChange {
    DeleteOriginal,
    ReplaceOriginal,
    CorruptAck,
}
enum Step {
    Status(Observation),
    Mutation(Mutation, bool),
    ChangeAfterStatus(Observation, RetainedChange),
    ChangeDuringAckReply,
}

struct RuntimeHttp {
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<WalletHttpRequest>>>,
    remaining: Arc<Mutex<VecDeque<Step>>>,
    worker: Option<JoinHandle<io::Result<()>>>,
    quiet: Vec<TcpListener>,
}
impl RuntimeHttp {
    fn start(
        prepared: &PreparedLocalnet,
        provider: ProviderId,
        operation: &Path,
        script: Vec<Step>,
    ) -> Self {
        Self::start_selected(prepared, provider, operation, script, false)
    }
    fn start_selected(
        prepared: &PreparedLocalnet,
        provider: ProviderId,
        operation: &Path,
        script: Vec<Step>,
        only_selected: bool,
    ) -> Self {
        let plan = prepared.gateway_compliance_plan(provider).unwrap().unwrap();
        let operation = operation.to_path_buf();
        let peer_index = prepared
            .provider_service_plan(provider)
            .unwrap()
            .unwrap()
            .peer_index();
        let mut listeners: Vec<_> = prepared
            .peers
            .iter()
            .enumerate()
            .filter(|(index, _)| !only_selected || *index == peer_index)
            .map(|(_, peer)| {
                let url: url::Url = peer.torii_url.parse().unwrap();
                assert_eq!(url.scheme(), "http");
                assert_eq!(url.host_str(), Some("127.0.0.1"));
                let listener =
                    TcpListener::bind((Ipv4Addr::LOCALHOST, url.port().unwrap())).unwrap();
                listener.set_nonblocking(true).unwrap();
                listener
            })
            .collect();
        let listener = listeners.remove(if only_selected { 0 } else { peer_index });
        let quiet = listeners;
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let remaining = Arc::new(Mutex::new(VecDeque::from(script)));
        let worker_stop = Arc::clone(&stop);
        let worker_requests = Arc::clone(&requests);
        let worker_remaining = Arc::clone(&remaining);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        // macOS inherits the listener's nonblocking mode; request reads use the
                        // bounded socket timeouts rather than failing between packet arrivals.
                        socket.set_nonblocking(false)?;
                        let request = wallet_request(&mut socket)?;
                        let step = worker_remaining
                            .lock()
                            .unwrap()
                            .pop_front()
                            .ok_or_else(|| io::Error::other("unexpected compliance HTTP retry"))?;
                        let (step, change) = match step {
                            Step::ChangeAfterStatus(observation, change) => {
                                (Step::Status(observation), Some(change))
                            }
                            Step::ChangeDuringAckReply => (
                                Step::Mutation(Mutation::Ack, false),
                                Some(RetainedChange::CorruptAck),
                            ),
                            step => (step, None),
                        };
                        let now = now_ms().unwrap() / 1_000;
                        let response = match step {
                            Step::Status(observation) => {
                                assert_eq!(request.method, "GET");
                                assert_eq!(
                                    request.target.path(),
                                    routes::SORAFS_GATEWAY_COMPLIANCE_STATUS_GET.path()
                                );
                                assert_eq!(request.target.query(), None);
                                assert!(request.body.is_empty());
                                let status = status_fixture(observation, &plan, &operation, now);
                                status.validate().unwrap();
                                Some(("200 OK", json(&status)))
                            }
                            Step::Mutation(kind, lost_reply) => {
                                assert_eq!(request.method, "POST");
                                assert_eq!(request.target.path(), kind.path());
                                // This read happens while the real SDK request is in flight. The
                                // original must already be durable, before any mutation dispatch.
                                let catalog: GatewayComplianceCatalogV1 =
                                    retained(&operation, "original.nrt");
                                let digest = catalog.verify(plan.trust_policy(), now, 0).unwrap();
                                match kind {
                                    Mutation::Stage => {
                                        assert_eq!(request.target.query(), None);
                                        assert_eq!(request.body, json(&catalog));
                                    }
                                    Mutation::Ack => {
                                        assert_eq!(request.target.query(), None);
                                        let ack: GatewayComplianceAcknowledgementV1 =
                                            retained(&operation, "acknowledgement.nrt");
                                        ack.verify(
                                            plan.trust_policy(),
                                            digest,
                                            now,
                                            CLOCK_SKEW_SECONDS,
                                        )
                                        .unwrap();
                                        assert_eq!(ack.payload.gateway_id, plan.gateway_label());
                                        assert!(ack.payload.accepted);
                                        assert_eq!(request.body, json(&ack));
                                    }
                                    Mutation::Promote => {
                                        assert!(request.body.is_empty());
                                        let expected = GatewayCompliancePromoteExpectationV1 {
                                            catalog_digest: digest,
                                            sequence: catalog.payload.sequence,
                                        };
                                        assert_eq!(
                                            request.target.query(),
                                            Some(expected.canonical_query().unwrap().as_str())
                                        );
                                    }
                                }
                                let target = &request.target
                                    [url::Position::BeforePath..url::Position::AfterQuery];
                                let report = GatewayComplianceActionResponseV1 {
                                    schema: GATEWAY_COMPLIANCE_ACTION_SCHEMA_V1.to_owned(),
                                    action: kind.action().to_owned(),
                                    catalog_digest_hex: hex::encode(digest),
                                    idempotency_key: hex::encode(request_idempotency_binding(
                                        kind.action(),
                                        target,
                                        &request.body,
                                    )),
                                    operation_timestamp_unix: now,
                                };
                                report.validate().unwrap();
                                (!lost_reply).then(|| {
                                    (
                                        if kind == Mutation::Promote {
                                            "200 OK"
                                        } else {
                                            "202 Accepted"
                                        },
                                        json(&report),
                                    )
                                })
                            }
                            Step::ChangeAfterStatus(_, _) | Step::ChangeDuringAckReply => {
                                unreachable!("fixture fault normalized above")
                            }
                        };
                        if let Some(change) = change {
                            let child = PrivateDirectory::open_exact(
                                operation.join("catalogs").join(catalog_name(1)),
                            )
                            .unwrap();
                            match change {
                                RetainedChange::DeleteOriginal => {
                                    std::fs::remove_file(child.path().join("original.nrt")).unwrap()
                                }
                                RetainedChange::ReplaceOriginal => child
                                    .write_atomic(
                                        "original.nrt",
                                        b"replaced during status",
                                        PublishMode::Replace,
                                    )
                                    .unwrap(),
                                RetainedChange::CorruptAck => child
                                    .write_atomic(
                                        "acknowledgement.nrt",
                                        b"changed during ACK reply",
                                        PublishMode::Replace,
                                    )
                                    .unwrap(),
                            }
                        }
                        let mut seen = worker_requests.lock().unwrap();
                        if seen.len() >= 64 {
                            return Err(io::Error::other("compliance fixture request bound"));
                        }
                        seen.push(request);
                        drop(seen);
                        if let Some((status, body)) = response {
                            assert!(body.len() <= iroha_torii_shared::sorafs_gateway_compliance_api::GATEWAY_COMPLIANCE_RESPONSE_MAX_BYTES_V1);
                            write!(
                                socket,
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )?;
                            socket.write_all(&body)?;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Self {
            stop,
            requests,
            remaining,
            worker: Some(worker),
            quiet,
        }
    }
    fn finish(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap().unwrap();
        assert!(
            self.remaining.lock().unwrap().is_empty(),
            "script must be consumed exactly"
        );
        for peer in &self.quiet {
            assert_eq!(peer.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
    }
}
impl Drop for RuntimeHttp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn json<T: norito::json::JsonSerialize>(value: &T) -> Vec<u8> {
    norito::json::to_json_bounded(value, MAX_RECORD_BYTES)
        .unwrap()
        .into_bytes()
}

fn retained<T: norito::NoritoSerialize + for<'a> norito::NoritoDeserialize<'a>>(
    operation: &Path,
    name: &str,
) -> T {
    let directory =
        PrivateDirectory::open_exact(operation.join("catalogs").join(catalog_name(1))).unwrap();
    decode(&directory.read(name, MAX_RECORD_BYTES).unwrap()).unwrap()
}
fn catalog_status(catalog: &GatewayComplianceCatalogV1) -> GatewayComplianceCatalogStatusV1 {
    GatewayComplianceCatalogStatusV1 {
        digest_hex: hex::encode(catalog.payload.catalog_digest().unwrap()),
        sequence: catalog.payload.sequence,
        generated_at_unix: catalog.payload.generated_at_unix,
        valid_until_unix: catalog.payload.valid_until_unix,
    }
}
fn status_fixture(
    observation: Observation,
    plan: &RetainedGatewayCompliancePlan,
    operation: &Path,
    now: u64,
) -> GatewayComplianceStatusResponseV1 {
    let mut status = GatewayComplianceStatusResponseV1 {
        schema: GATEWAY_COMPLIANCE_STATUS_SCHEMA_V1.to_owned(),
        checkpoint_version: 1,
        policy_digest_hex: hex::encode(plan.trust_policy().canonical_digest().unwrap()),
        observed_at_unix: now,
        serving_ready: false,
        chain_head: None,
        serving: None,
        previous_serving: None,
        candidate: None,
        acknowledgement_count: 0,
        accepted_acknowledgement_count: 0,
        rejected_acknowledgement_count: 0,
        history_count: 0,
        idempotency_record_count: 0,
        latest_action: None,
    };
    match observation {
        Observation::Empty => {}
        Observation::Candidate { ack } => {
            let catalog = retained(operation, "original.nrt");
            status.candidate = Some(catalog_status(&catalog));
            status.acknowledgement_count = u64::from(ack);
            status.accepted_acknowledgement_count = u64::from(ack);
            status.idempotency_record_count = 1 + u64::from(ack);
        }
        Observation::Promoted => {
            let catalog = retained(operation, "original.nrt");
            let projected = catalog_status(&catalog);
            let expectation = GatewayCompliancePromoteExpectationV1 {
                catalog_digest: catalog.payload.catalog_digest().unwrap(),
                sequence: catalog.payload.sequence,
            };
            let target = format!(
                "{}?{}",
                Mutation::Promote.path(),
                expectation.canonical_query().unwrap()
            );
            status.latest_action = Some(GatewayComplianceLatestActionStatusV1 {
                operation_id_hex: hex::encode(request_idempotency_binding("promote", &target, &[])),
                action: "promotion".to_owned(),
                previous_serving_digest_hex: None,
                serving_digest_hex: projected.digest_hex.clone(),
                recorded_at_unix: now,
                reason_code: "gateway-quorum".to_owned(),
            });
            status.serving_ready =
                projected.generated_at_unix <= now && now < projected.valid_until_unix;
            status.chain_head = Some(projected.clone());
            status.serving = Some(projected);
            status.history_count = 1;
            status.idempotency_record_count = 3;
        }
        Observation::ForeignPolicy => status.policy_digest_hex = hex::encode([0xC3; 32]),
        Observation::ForeignCandidate | Observation::ForeignHead => {
            let foreign = GatewayComplianceCatalogStatusV1 {
                digest_hex: hex::encode([0xD4; 32]),
                sequence: 1,
                generated_at_unix: now,
                valid_until_unix: now + 60,
            };
            if matches!(observation, Observation::ForeignCandidate) {
                status.candidate = Some(foreign);
            } else {
                status.chain_head = Some(foreign.clone());
                status.serving = Some(foreign);
                status.serving_ready = true;
            }
        }
        Observation::Stale => status.observed_at_unix = now.saturating_sub(CLOCK_SKEW_SECONDS + 10),
    }
    status
}
fn fixture(name: &str) -> (tempfile::TempDir, PreparedLocalnet) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        name,
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    (temporary, prepared)
}
fn provider(prepared: &PreparedLocalnet) -> ProviderId {
    prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[2]
        .provider_id
}
fn operation(publisher: &ManagedGatewayCompliance) -> PathBuf {
    publisher.authority.directory.path().to_path_buf()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn complete_script() -> Vec<Step> {
    vec![
        Step::Status(Observation::Empty),
        Step::Mutation(Mutation::Stage, false),
        Step::Status(Observation::Candidate { ack: false }),
        Step::Mutation(Mutation::Ack, false),
        Step::Mutation(Mutation::Promote, false),
        Step::Status(Observation::Promoted),
    ]
}
fn bytes(operation: &Path, name: &str) -> zeroize::Zeroizing<Vec<u8>> {
    PrivateDirectory::open_exact(operation.join("catalogs").join(catalog_name(1)))
        .unwrap()
        .read(name, MAX_RECORD_BYTES)
        .unwrap()
}
fn retain_catalog(
    publisher: &ManagedGatewayCompliance,
    sequence: u64,
    catalog: &GatewayComplianceCatalogV1,
) -> PrivateDirectory {
    let child = publisher
        .authority
        .directory
        .ensure_child("catalogs")
        .unwrap()
        .ensure_child(&catalog_name(sequence))
        .unwrap();
    child
        .write_atomic(
            "original.nrt",
            &encode(catalog, MAX_RECORD_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    child
}

#[test]
fn publication_promotes_exact_original_then_reopens_with_one_status_only() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("compliance-publish");
    for original in prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers
    {
        let provider = original.provider_id;
        let (publisher, parses) =
            crate::localnet::service_authorities::count_profile_validations(|| {
                ManagedGatewayCompliance::open(&prepared, provider).unwrap()
            });
        assert_eq!(parses, 1);
        assert!(ManagedGatewayCompliance::open(&prepared, provider).is_err());
        let (_, parses) = crate::localnet::service_authorities::count_profile_validations(|| {
            publisher
                .validate(&mut TestLive::default(), deadline())
                .unwrap()
        });
        assert_eq!(parses, 0);
        let path = operation(&publisher);
        let mut script = complete_script();
        script.push(Step::Status(Observation::Promoted));
        let mut http = RuntimeHttp::start(&prepared, provider, &path, script);
        let (report, parses) =
            crate::localnet::service_authorities::count_profile_validations(|| {
                publisher
                    .advance(&mut TestLive::default(), deadline())
                    .unwrap()
            });
        // Signing, historical verification and live-plan access retain full source/lock checks
        // on the held owner without another semantic profile parse.
        assert_eq!(parses, 0);
        let original = bytes(&path, "original.nrt");
        let acknowledgement = bytes(&path, "acknowledgement.nrt");
        let catalog: GatewayComplianceCatalogV1 = decode(&original).unwrap();
        assert_eq!(report.digest, catalog.payload.catalog_digest().unwrap());
        assert_eq!(report.sequence, 1);
        assert_eq!(report.valid_until_unix, catalog.payload.valid_until_unix);
        drop(publisher);
        let (reopened, parses) =
            crate::localnet::service_authorities::count_profile_validations(|| {
                ManagedGatewayCompliance::open(&prepared, provider).unwrap()
            });
        assert_eq!(parses, 1);
        assert_eq!(
            reopened
                .advance(&mut TestLive::default(), deadline())
                .unwrap(),
            report
        );
        assert_eq!(bytes(&path, "original.nrt"), original);
        assert_eq!(bytes(&path, "acknowledgement.nrt"), acknowledgement);
        http.finish();
        assert_eq!(http.requests.lock().unwrap().len(), 7);
    }
}

#[test]
fn lost_stage_ack_and_promote_replies_recover_exact_original_bytes() {
    let _resources = crate::managed::native_test_guard();
    for lost in [Mutation::Stage, Mutation::Ack, Mutation::Promote] {
        let (_temporary, prepared) = fixture("compliance-lost-reply");
        let provider = provider(&prepared);
        let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
        let path = operation(&publisher);
        let mut script = vec![
            Step::Status(Observation::Empty),
            Step::Mutation(Mutation::Stage, lost == Mutation::Stage),
        ];
        if lost != Mutation::Stage {
            script.extend([
                Step::Status(Observation::Candidate { ack: false }),
                Step::Mutation(Mutation::Ack, lost == Mutation::Ack),
            ]);
        }
        if lost == Mutation::Promote {
            script.push(Step::Mutation(Mutation::Promote, true));
        }
        if lost == Mutation::Promote {
            script.push(Step::Status(Observation::Promoted));
        } else {
            let observation = Observation::Candidate {
                ack: lost == Mutation::Ack,
            };
            script.extend([
                Step::Status(observation),
                Step::Mutation(Mutation::Stage, false),
                Step::Status(observation),
                Step::Mutation(Mutation::Ack, false),
                Step::Mutation(Mutation::Promote, false),
                Step::Status(Observation::Promoted),
            ]);
        }
        let mut http = RuntimeHttp::start(&prepared, provider, &path, script);
        assert!(
            publisher
                .advance(&mut TestLive::default(), deadline())
                .is_err()
        );
        let original = bytes(&path, "original.nrt");
        let ack = (lost != Mutation::Stage).then(|| bytes(&path, "acknowledgement.nrt"));
        drop(publisher);
        let reopened = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
        let result = reopened
            .advance(&mut TestLive::default(), deadline())
            .unwrap();
        let catalog: GatewayComplianceCatalogV1 = decode(&original).unwrap();
        assert_eq!(result, report(&catalog).unwrap());
        assert_eq!(bytes(&path, "original.nrt"), original);
        if let Some(ack) = ack {
            assert_eq!(bytes(&path, "acknowledgement.nrt"), ack);
        }
        http.finish();
        let seen = http.requests.lock().unwrap();
        for kind in [Mutation::Stage, Mutation::Ack, Mutation::Promote] {
            let requests: Vec<_> = seen
                .iter()
                .filter(|request| request.method == "POST" && request.target.path() == kind.path())
                .collect();
            if requests.len() == 2 {
                assert_eq!(requests[0].body, requests[1].body);
                assert_eq!(requests[0].target, requests[1].target);
            }
            assert_eq!(
                requests.len(),
                usize::from(
                    lost != Mutation::Promote
                        && (kind == Mutation::Stage
                            || (kind == Mutation::Ack && lost == Mutation::Ack))
                ) + 1
            );
        }
    }
}

#[test]
fn empty_final_catalog_slot_is_reused_without_creating_another_sequence() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("compliance-empty-slot");
    let provider = provider(&prepared);
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    publisher
        .authority
        .directory
        .ensure_child("catalogs")
        .unwrap()
        .ensure_child(&catalog_name(1))
        .unwrap();
    let mut http = RuntimeHttp::start(
        &prepared,
        provider,
        &operation(&publisher),
        complete_script(),
    );
    assert_eq!(
        publisher
            .advance(&mut TestLive::default(), deadline())
            .unwrap()
            .sequence,
        1
    );
    assert_eq!(
        publisher
            .authority
            .directory
            .open_child("catalogs")
            .unwrap()
            .entries(2)
            .unwrap(),
        [std::ffi::OsString::from(catalog_name(1))]
    );
    http.finish();
}

#[test]
fn malformed_foreign_trailing_oversized_and_gapped_originals_refuse_before_http() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("compliance-local-refusals");
    let provider = provider(&prepared);
    let (_foreign_temporary, foreign) = fixture("compliance-foreign");
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    let path = operation(&publisher);
    let selected = publisher
        .authority
        .sign_gateway_compliance_catalog(None, now_ms().unwrap() / 1_000)
        .unwrap();
    let foreign_publisher =
        ManagedGatewayCompliance::open(&foreign, self::provider(&foreign)).unwrap();
    let foreign_catalog = foreign_publisher
        .authority
        .sign_gateway_compliance_catalog(None, now_ms().unwrap() / 1_000)
        .unwrap();
    let exact = encode(&selected, MAX_RECORD_BYTES).unwrap();
    let mut trailing = exact.clone();
    trailing.push(0);
    let mut bad_signature = selected.clone();
    bad_signature.approvals[0].signature[0] ^= 1;
    let cases = vec![
        ("malformed", 1, b"not a catalog".to_vec()),
        ("trailing", 1, trailing),
        ("oversized", 1, vec![0; MAX_RECORD_BYTES + 1]),
        (
            "foreign",
            1,
            encode(&foreign_catalog, MAX_RECORD_BYTES).unwrap(),
        ),
        (
            "bad-signature",
            1,
            encode(&bad_signature, MAX_RECORD_BYTES).unwrap(),
        ),
        ("gap", 2, exact.clone()),
    ];
    let mut http = RuntimeHttp::start(&prepared, provider, &path, vec![]);
    for (label, sequence, bytes) in cases {
        let catalogs = publisher
            .authority
            .directory
            .ensure_child("catalogs")
            .unwrap();
        catalogs
            .ensure_child(&catalog_name(sequence))
            .unwrap()
            .write_atomic("original.nrt", &bytes, PublishMode::CreateNew)
            .unwrap();
        assert!(
            publisher
                .advance(&mut TestLive::default(), deadline())
                .is_err(),
            "{label}"
        );
        std::fs::remove_dir_all(path.join("catalogs")).unwrap();
    }
    let catalogs = publisher
        .authority
        .directory
        .ensure_child("catalogs")
        .unwrap();
    catalogs
        .ensure_child(&catalog_name(1))
        .unwrap()
        .write_atomic("acknowledgement.nrt", b"orphan", PublishMode::CreateNew)
        .unwrap();
    assert!(
        publisher
            .advance(&mut TestLive::default(), deadline())
            .is_err()
    );
    std::fs::remove_dir_all(path.join("catalogs")).unwrap();
    let catalogs = publisher
        .authority
        .directory
        .ensure_child("catalogs")
        .unwrap();
    catalogs.ensure_child(&catalog_name(1)).unwrap();
    catalogs
        .ensure_child(&catalog_name(2))
        .unwrap()
        .write_atomic("original.nrt", &exact, PublishMode::CreateNew)
        .unwrap();
    assert!(
        publisher
            .advance(&mut TestLive::default(), deadline())
            .is_err()
    );
    http.finish();
    assert!(http.requests.lock().unwrap().is_empty());
}

#[test]
fn corrupted_retained_ack_is_rejected_before_any_recovery_http() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("compliance-corrupt-ack");
    let provider = provider(&prepared);
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    let path = operation(&publisher);
    let mut script = complete_script();
    script.truncate(4);
    script[3] = Step::Mutation(Mutation::Ack, true);
    let mut http = RuntimeHttp::start(&prepared, provider, &path, script);
    assert!(
        publisher
            .advance(&mut TestLive::default(), deadline())
            .is_err()
    );
    let before = http.requests.lock().unwrap().len();
    let child = publisher
        .authority
        .directory
        .open_child("catalogs")
        .unwrap()
        .open_child(&catalog_name(1))
        .unwrap();
    let original = child.read("acknowledgement.nrt", MAX_RECORD_BYTES).unwrap();
    let mut ack: GatewayComplianceAcknowledgementV1 = decode(&original).unwrap();
    ack.signature[0] ^= 1;
    child
        .write_atomic(
            "acknowledgement.nrt",
            &encode(&ack, MAX_RECORD_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(
        publisher
            .advance(&mut TestLive::default(), deadline())
            .is_err()
    );
    assert_eq!(http.requests.lock().unwrap().len(), before);
    http.finish();
}

#[test]
fn stale_foreign_policy_candidate_and_head_observations_never_authorize_mutations() {
    let _resources = crate::managed::native_test_guard();
    for observation in [
        Observation::ForeignPolicy,
        Observation::ForeignCandidate,
        Observation::ForeignHead,
        Observation::Stale,
    ] {
        let (_temporary, prepared) = fixture("compliance-status-refusal");
        let provider = provider(&prepared);
        let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
        let mut http = RuntimeHttp::start(
            &prepared,
            provider,
            &operation(&publisher),
            vec![Step::Status(observation)],
        );
        assert!(
            publisher
                .advance(&mut TestLive::default(), deadline())
                .is_err()
        );
        http.finish();
        assert_eq!(http.requests.lock().unwrap().len(), 1);
        assert!(
            publisher
                .authority
                .directory
                .open_child("catalogs")
                .unwrap()
                .entries(1)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn dead_guard_deadline_and_guard_loss_after_status_refuse_before_mutation() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("compliance-live-refusal");
    let provider = provider(&prepared);
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    let mut http = RuntimeHttp::start(
        &prepared,
        provider,
        &operation(&publisher),
        vec![Step::Status(Observation::Empty)],
    );
    assert!(
        publisher
            .advance(
                &mut TestLive {
                    checks: 0,
                    fail_at: Some(1)
                },
                deadline()
            )
            .is_err()
    );
    assert!(
        publisher
            .advance(&mut TestLive::default(), Instant::now())
            .is_err()
    );
    assert!(http.requests.lock().unwrap().is_empty());
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let original_peer = generation.read("peer0.toml", 1024 * 1024).unwrap();
    generation
        .write_atomic("peer0.toml", b"changed original peer", PublishMode::Replace)
        .unwrap();
    assert!(
        publisher
            .advance(&mut TestLive::default(), deadline())
            .is_err()
    );
    assert!(http.requests.lock().unwrap().is_empty());
    generation
        .write_atomic("peer0.toml", &original_peer, PublishMode::Replace)
        .unwrap();
    assert!(
        publisher
            .advance(
                &mut TestLive {
                    checks: 0,
                    fail_at: Some(3)
                },
                deadline()
            )
            .is_err()
    );
    http.finish();
    assert_eq!(http.requests.lock().unwrap().len(), 1);
    assert!(
        publisher
            .authority
            .directory
            .open_child("catalogs")
            .unwrap()
            .entries(1)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn exact_promoted_catalog_expiry_boundary_and_pending_candidate_are_not_ready() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("compliance-expiry-boundary");
    let provider = provider(&prepared);
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    let catalog = publisher
        .authority
        .sign_gateway_compliance_catalog(None, now_ms().unwrap() / 1_000)
        .unwrap();
    retain_catalog(&publisher, 1, &catalog);
    let path = operation(&publisher);
    let mut http = RuntimeHttp::start(&prepared, provider, &path, vec![]);
    let before = catalog.payload.valid_until_unix - 1;
    let fresh = status_fixture(Observation::Promoted, &publisher.plan, &path, before);
    publisher
        .require_fresh_promoted(&fresh, &catalog, before)
        .unwrap();
    // A still-positive earlier node observation cannot override the caller's exact expiry cut.
    assert!(
        publisher
            .require_fresh_promoted(&fresh, &catalog, catalog.payload.valid_until_unix)
            .is_err()
    );
    let expired = status_fixture(
        Observation::Promoted,
        &publisher.plan,
        &path,
        catalog.payload.valid_until_unix,
    );
    assert!(!expired.serving_ready);
    assert!(
        publisher
            .require_fresh_promoted(&expired, &catalog, catalog.payload.valid_until_unix)
            .is_err()
    );
    let mut pending = fresh;
    pending.candidate = Some(catalog_status(&catalog));
    assert!(
        publisher
            .require_fresh_promoted(&pending, &catalog, before)
            .is_err()
    );
    http.finish();
    assert!(http.requests.lock().unwrap().is_empty());
}

#[test]
fn original_changed_during_initial_status_never_reaches_stage_or_promoted_return() {
    let _resources = crate::managed::native_test_guard();
    for change in [
        RetainedChange::DeleteOriginal,
        RetainedChange::ReplaceOriginal,
    ] {
        for observation in [Observation::Candidate { ack: false }, Observation::Promoted] {
            let (_temporary, prepared) = fixture("compliance-original-race");
            let provider = provider(&prepared);
            let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
            let catalog = publisher
                .authority
                .sign_gateway_compliance_catalog(None, now_ms().unwrap() / 1_000)
                .unwrap();
            retain_catalog(&publisher, 1, &catalog);
            let mut http = RuntimeHttp::start(
                &prepared,
                provider,
                &operation(&publisher),
                vec![Step::ChangeAfterStatus(observation, change)],
            );
            assert!(
                publisher
                    .advance(&mut TestLive::default(), deadline())
                    .is_err()
            );
            http.finish();
            let requests = http.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "GET");
            let path = operation(&publisher)
                .join("catalogs")
                .join(catalog_name(1))
                .join("original.nrt");
            match change {
                RetainedChange::DeleteOriginal => {
                    assert!(!path.exists(), "missing original must never be re-created")
                }
                RetainedChange::ReplaceOriginal => {
                    assert_eq!(std::fs::read(path).unwrap(), b"replaced during status")
                }
                RetainedChange::CorruptAck => unreachable!(),
            }
        }
    }
}

#[test]
fn acknowledgement_changed_during_its_reply_never_reaches_promotion() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("compliance-ack-race");
    let provider = provider(&prepared);
    let publisher = ManagedGatewayCompliance::open(&prepared, provider).unwrap();
    let path = operation(&publisher);
    let mut http = RuntimeHttp::start(
        &prepared,
        provider,
        &path,
        vec![
            Step::Status(Observation::Empty),
            Step::Mutation(Mutation::Stage, false),
            Step::Status(Observation::Candidate { ack: false }),
            Step::ChangeDuringAckReply,
        ],
    );
    assert!(
        publisher
            .advance(&mut TestLive::default(), deadline())
            .is_err()
    );
    http.finish();
    let seen = http.requests.lock().unwrap();
    assert_eq!(seen.len(), 4);
    assert!(
        seen.iter()
            .all(|request| request.target.path() != Mutation::Promote.path())
    );
    assert_eq!(
        bytes(&path, "acknowledgement.nrt").as_slice(),
        b"changed during ACK reply"
    );
}

#[path = "observation_tests.rs"]
mod observation_tests;

#[test]
fn joined_catalog_partial_publication_recovers_each_exact_original() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture("compliance-joined-recovery");
    let providers = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers
        .each_ref()
        .map(|plan| plan.provider_id);
    let publishers =
        providers.map(|provider| ManagedGatewayCompliance::open(&prepared, provider).unwrap());
    let paths = publishers.each_ref().map(|publisher| operation(publisher));
    let mut servers: [_; 3] = std::array::from_fn(|slot| {
        let script = if slot == 1 {
            vec![
                Step::Status(Observation::Empty),
                Step::Mutation(Mutation::Stage, true),
            ]
        } else {
            complete_script()
        };
        RuntimeHttp::start_selected(&prepared, providers[slot], &paths[slot], script, true)
    });
    let original_deadline = deadline();
    let result = crate::managed::provider_round::run(
        publishers,
        true,
        |publisher| publisher.advance(&mut TestLive::default(), original_deadline),
        || invalid("catalog worker did not complete"),
    );
    assert!(result.is_err(), "one lost response refuses the aggregate");
    for server in &mut servers {
        server.finish();
    }
    drop(servers);
    // All three original native purpose owners have closed before recovery. Other providers
    // completed despite the middle member's refusal; recovery never replaces any signed bytes.
    let originals = paths.each_ref().map(|path| bytes(path, "original.nrt"));
    let acknowledgements: [_; 3] =
        std::array::from_fn(|slot| (slot != 1).then(|| bytes(&paths[slot], "acknowledgement.nrt")));
    for slot in 0..3 {
        let publisher = ManagedGatewayCompliance::open(&prepared, providers[slot]).unwrap();
        let script = if slot == 1 {
            vec![
                Step::Status(Observation::Candidate { ack: false }),
                Step::Mutation(Mutation::Stage, false),
                Step::Status(Observation::Candidate { ack: false }),
                Step::Mutation(Mutation::Ack, false),
                Step::Mutation(Mutation::Promote, false),
                Step::Status(Observation::Promoted),
            ]
        } else {
            vec![Step::Status(Observation::Promoted)]
        };
        let mut server = RuntimeHttp::start(&prepared, providers[slot], &paths[slot], script);
        let catalog: GatewayComplianceCatalogV1 = decode(&originals[slot]).unwrap();
        assert_eq!(
            publisher
                .advance(&mut TestLive::default(), original_deadline)
                .unwrap(),
            report(&catalog).unwrap()
        );
        assert_eq!(bytes(&paths[slot], "original.nrt"), originals[slot]);
        if let Some(original) = &acknowledgements[slot] {
            assert_eq!(&bytes(&paths[slot], "acknowledgement.nrt"), original);
        }
        server.finish();
    }
}
