//! Closed administrative wallet intent and one-shot recovery controls; HTTP replies are hints.

use super::super::setup_test_support;
use super::*;
use iroha::http::{HttpTransport, Response, TransportFuture, TransportRequest};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

fn request() -> AmxDataspaceRegistrationRequest {
    AmxDataspaceRegistrationRequest {
        parent_chain_id: super::super::tests::fixture_config().chain.to_string(),
        registration: super::super::tests::private_root_fixture().1,
        deadline_unix_ms: current_unix_ms().unwrap() + 60_000,
        options: super::super::tests::private_options(),
    }
}

#[test]
fn administrative_amx_plan_preserves_exact_child_anchor_and_one_shot_recovery() {
    let (service, transport) = setup_test_support::service();
    let request = request();
    let root = tempfile::tempdir().unwrap();
    let journal = root.path().join("administrative-amx");
    assert_eq!(
        service
            .inspect_amx_dataspace_registration_preparation(&journal, &request)
            .unwrap()
            .phase(),
        NativePreparationPhase::Missing
    );
    assert_eq!(
        service
            .prepare_amx_dataspace_registration(&request, &journal)
            .unwrap()
            .status,
        OperationStatus::Prepared
    );
    let original = service
        .verify_amx_dataspace_registration_journal(&journal, &request)
        .unwrap();
    let wire = original.encode_wire_v1().unwrap();
    let Executable::Instructions(rows) = original.instructions() else {
        panic!("native instruction")
    };
    assert_eq!(rows.len(), 1);
    let row = rows[0]
        .as_any()
        .downcast_ref::<RegisterAmxDataspaceV1>()
        .unwrap();
    assert_eq!(row.dataspace, request.registration.scope.dataspace_id());
    assert_eq!(row.instance, request.registration.instance);
    assert_eq!(
        row.anchor,
        norito::encode_canonical(&request.registration.initial_epoch).unwrap()
    );
    assert_eq!(original.authority(), &service.config.account);
    assert_eq!(original.network_id(), Some(&service.config.network_id));
    assert!(
        service
            .submit(&journal, NativeOperationKind::AmxDataspaceRegistration)
            .is_err()
    );
    assert!(
        service
            .resume(&journal, NativeOperationKind::AmxDataspaceRegistration)
            .is_err()
    );
    *transport.journal.lock().unwrap() = Some(journal.clone());
    assert_eq!(
        service
            .submit_amx_dataspace_registration(&journal, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let before = transport.submissions.load(Ordering::SeqCst);
    let quotes = transport.quotes.load(Ordering::SeqCst);
    assert_eq!(before, 1);
    assert_eq!(
        service
            .resume_amx_dataspace_registration(&journal, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(
        service
            .submit_amx_dataspace_registration(&journal, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    service
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    assert_eq!(transport.submissions.load(Ordering::SeqCst), before);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), quotes);
    assert_eq!(
        service
            .verify_amx_dataspace_registration_journal(&journal, &request)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
}

#[test]
fn administrative_amx_journal_refuses_changed_source_signer_fees_and_time_before_http() {
    let (service, transport) = setup_test_support::service();
    let request = request();
    let root = tempfile::tempdir().unwrap();
    let journal = root.path().join("amx");
    service
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    let original = std::fs::read(journal.join("operation.json")).unwrap();
    for changed in [
        {
            let mut r = request.clone();
            r.parent_chain_id.push('x');
            r
        },
        {
            let mut r = request.clone();
            r.registration.instance[0] ^= 1;
            r
        },
        {
            let mut r = request.clone();
            r.deadline_unix_ms += 1;
            r
        },
        {
            let mut r = request.clone();
            r.options
                .max_total_fees
                .values_mut()
                .for_each(|v| *v = Quantity::from(11_u32));
            r
        },
    ] {
        let before = transport.requests.load(Ordering::SeqCst);
        assert!(
            service
                .inspect_amx_dataspace_registration_preparation(&journal, &changed)
                .is_err()
        );
        assert!(
            service
                .prepare_amx_dataspace_registration(&changed, &journal)
                .is_err()
        );
        assert!(
            service
                .submit_amx_dataspace_registration(&journal, &changed)
                .is_err()
        );
        assert!(
            service
                .resume_amx_dataspace_registration(&journal, &changed)
                .is_err()
        );
        assert_eq!(transport.requests.load(Ordering::SeqCst), before);
        assert_eq!(
            std::fs::read(journal.join("operation.json")).unwrap(),
            original
        );
    }
    let mut changed = service.config.clone();
    let key = iroha_crypto::KeyPair::from_seed(vec![222; 32], iroha_crypto::Algorithm::Ed25519);
    changed.account = AccountId::new(key.public_key().clone());
    changed.key_pair = key;
    let before = transport.requests.load(Ordering::SeqCst);
    let other = AccountService::new(changed).unwrap();
    assert!(
        other
            .inspect_amx_dataspace_registration_preparation(&journal, &request)
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), before);
}

#[test]
fn administrative_amx_bad_context_and_expired_authorization_do_not_prepare_or_quote() {
    let (service, transport) = setup_test_support::service();
    let request = request();
    let root = tempfile::tempdir().unwrap();
    for (index, changed) in [
        {
            let mut r = request.clone();
            r.deadline_unix_ms = current_unix_ms().unwrap();
            r
        },
        {
            let mut r = request.clone();
            r.deadline_unix_ms = u64::MAX;
            r
        },
        {
            let mut r = request.clone();
            r.parent_chain_id.push('x');
            r
        },
        {
            let mut r = request.clone();
            r.registration.scope = SumeragiRootScope::Global;
            r
        },
    ]
    .into_iter()
    .enumerate()
    {
        let journal = root.path().join(format!("bad-{index}"));
        assert!(
            service
                .prepare_amx_dataspace_registration(&changed, &journal)
                .is_err()
        );
        assert!(!journal.exists());
    }
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

#[derive(Debug, Default)]
struct RejectingTransport {
    base: setup_test_support::Transport,
    rejected: AtomicBool,
    permission_later_granted: AtomicBool,
    rejected_height: Option<u64>,
    details_response: Option<(u16, Vec<u8>)>,
    details_reads: AtomicUsize,
}
impl HttpTransport for RejectingTransport {
    fn send_blocking(&self, request: TransportRequest) -> Result<Response<Vec<u8>>> {
        if request.url.path()
            == iroha_torii_shared::route_catalog::pipeline::TRANSACTION_DETAILS.path()
        {
            self.details_reads.fetch_add(1, Ordering::SeqCst);
            let (status, body) = self
                .details_response
                .as_ref()
                .expect("explicit rejected detail response");
            return Ok(Response::builder()
                .status(*status)
                .header("Content-Type", "application/x-norito")
                .body(body.clone())?);
        }
        if request.url.path() == "/v1/pipeline/transactions/status"
            && self.rejected.load(Ordering::SeqCst)
            && !self.permission_later_granted.load(Ordering::SeqCst)
        {
            let hash = request
                .url
                .query_pairs()
                .find(|(k, _)| k == "hash")
                .unwrap()
                .1
                .into_owned();
            return Ok(Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(norito::json::to_vec(
                    &iroha_torii_shared::PipelineTransactionStatusResponse {
                        hash,
                        scope: "global".into(),
                        resolved_from: "state".into(),
                        status: iroha_torii_shared::PipelineTransactionStatus {
                            kind: "Rejected".into(),
                            block_height: self.rejected_height,
                        },
                    },
                )?)?);
        }
        let submission =
            request.url.path() == iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path();
        let response = self.base.send_blocking(request)?;
        if submission {
            self.rejected.store(true, Ordering::SeqCst);
        }
        Ok(response)
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

#[test]
fn administrative_amx_rejection_hint_never_resigns_or_resubmits_after_permission_grant() {
    let config = super::super::tests::fixture_config();
    let transport = Arc::new(RejectingTransport::default());
    let client = Client::with_http_transport(config.clone(), transport.clone()).unwrap();
    let service = AccountService {
        config,
        client,
        deadline: None,
        cancellation: None,
    };
    let request = request();
    let root = tempfile::tempdir().unwrap();
    let journal = root.path().join("amx");
    service
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    let wire = service
        .verify_amx_dataspace_registration_journal(&journal, &request)
        .unwrap()
        .encode_wire_v1()
        .unwrap();
    *transport.base.journal.lock().unwrap() = Some(journal.clone());
    assert_eq!(
        service
            .submit_amx_dataspace_registration(&journal, &request)
            .unwrap()
            .status,
        OperationStatus::Rejected
    );
    assert_eq!(
        service
            .rejected_amx_dataspace_registration_carrier_height(&journal, &request)
            .unwrap(),
        None
    );
    let quotes = transport.base.quotes.load(Ordering::SeqCst);
    transport
        .permission_later_granted
        .store(true, Ordering::SeqCst);
    // The now-absent status cannot create a second dispatch or a replacement authorization.
    assert_eq!(
        service
            .submit_amx_dataspace_registration(&journal, &request)
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    service
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    assert_eq!(transport.base.submissions.load(Ordering::SeqCst), 1);
    assert_eq!(transport.base.quotes.load(Ordering::SeqCst), quotes);
    assert_eq!(
        service
            .verify_amx_dataspace_registration_journal(&journal, &request)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
}

#[test]
fn administrative_amx_original_utc_expiry_allows_only_exact_read_only_reconciliation() {
    let (service, transport) = setup_test_support::service();
    let mut request = request();
    request.deadline_unix_ms = current_unix_ms().unwrap() + 5_000;
    let temporary = tempfile::tempdir().unwrap();
    let journal = temporary.path().join("original-expiring-amx");
    service
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    let original = service
        .verify_amx_dataspace_registration_journal(&journal, &request)
        .unwrap()
        .encode_wire_v1()
        .unwrap();
    let request_bytes = std::fs::read(journal.join("preparation.json")).unwrap();
    let operation_bytes = std::fs::read(journal.join("operation.json")).unwrap();
    let quotes = transport.quotes.load(Ordering::SeqCst);
    let wait = request
        .deadline_unix_ms
        .saturating_sub(current_unix_ms().unwrap());
    std::thread::sleep(std::time::Duration::from_millis(wait + 1));
    assert!(current_unix_ms().unwrap() >= request.deadline_unix_ms);
    // A new monotonic read budget never changes the original finite UTC authorization.
    request.options.deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    assert_eq!(
        service
            .inspect_amx_dataspace_registration_preparation(&journal, &request)
            .unwrap()
            .phase(),
        NativePreparationPhase::Signed
    );
    service
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    assert_eq!(
        service
            .resume_amx_dataspace_registration(&journal, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert_eq!(
        service
            .submit_amx_dataspace_registration(&journal, &request)
            .unwrap()
            .status,
        OperationStatus::Expired
    );
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 0);
    assert_eq!(transport.quotes.load(Ordering::SeqCst), quotes);
    assert_eq!(
        service
            .verify_amx_dataspace_registration_journal(&journal, &request)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        original
    );
    assert_eq!(
        std::fs::read(journal.join("preparation.json")).unwrap(),
        request_bytes
    );
    assert_eq!(
        std::fs::read(journal.join("operation.json")).unwrap(),
        operation_bytes
    );
}

#[test]
fn administrative_amx_rejected_carrier_preserves_typed_absence_and_refuses_malformed_errors() {
    let absent = norito::encode_canonical(&iroha_torii_shared::ErrorEnvelope::new(
        "transaction_details_not_found",
        "missing original carrier",
    ))
    .unwrap();
    let unrelated = norito::encode_canonical(&iroha_torii_shared::ErrorEnvelope::new(
        "internal_server_error",
        "carrier storage unavailable",
    ))
    .unwrap();
    for (status, body, expected_absent) in [
        (404, absent.clone(), true),
        (404, vec![0xff, 0], false),
        (404, unrelated, false),
        (500, absent, false),
    ] {
        let config = super::super::tests::fixture_config();
        let transport = Arc::new(RejectingTransport {
            rejected: AtomicBool::new(true),
            rejected_height: Some(42),
            details_response: Some((status, body)),
            ..Default::default()
        });
        let client = Client::with_http_transport(config.clone(), transport.clone()).unwrap();
        let service = AccountService {
            config,
            client,
            deadline: None,
            cancellation: None,
        };
        let request = request();
        let root = tempfile::tempdir().unwrap();
        let journal = root.path().join("rejected-carrier");
        service
            .prepare_amx_dataspace_registration(&request, &journal)
            .unwrap();
        let wire = service
            .verify_amx_dataspace_registration_journal(&journal, &request)
            .unwrap()
            .encode_wire_v1()
            .unwrap();
        let outcome =
            service.rejected_amx_dataspace_registration_carrier_height(&journal, &request);
        if expected_absent {
            assert_eq!(
                outcome.unwrap(),
                None,
                "only the canonical typed query absence is pending"
            );
        } else {
            let error = outcome
                .expect_err("malformed, unrelated or wrong-status errors must not become absence");
            assert!(!typed_not_found(&error));
            assert!(
                error
                    .to_string()
                    .contains("read exact rejected AMX transaction evidence")
            );
        }
        assert_eq!(transport.details_reads.load(Ordering::SeqCst), 1);
        assert_eq!(transport.base.submissions.load(Ordering::SeqCst), 0);
        assert_eq!(
            service
                .verify_amx_dataspace_registration_journal(&journal, &request)
                .unwrap()
                .encode_wire_v1()
                .unwrap(),
            wire
        );
    }
}
