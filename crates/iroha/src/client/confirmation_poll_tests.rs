//! Automatic submission confirmation retains its original deadline and native status authority.

use super::{
    AccountTransactionDraft, Client, HashOf, SignedTransaction, TransactionFinalityFailure,
    evidence_http_tests::{
        assert_status_scope, base_url, client_with_base_url, empty_response, json_response,
        mark_data_model_compatible,
    },
};
use crate::{
    http::{Method, Response, StatusCode},
    http_default::{DefaultHttpTransport, RequestSnapshot},
};
use iroha_data_model::{isi::InstructionBox, transaction::FeePaymentIntent};
use iroha_model_base::metadata::Metadata;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

fn transaction(client: &Client) -> SignedTransaction {
    let account = client.account_client().expect("account context");
    account
        .prepare_transaction(AccountTransactionDraft::new(
            Vec::<InstructionBox>::new(),
            FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        ))
        .and_then(|payload| account.sign_transaction(payload))
        .expect("signed transaction")
}

fn applied(hash: HashOf<SignedTransaction>, resolved_from: &str) -> Response<Vec<u8>> {
    json_response(
        StatusCode::OK,
        &norito::json::to_string(&norito::json!({
            "hash": (hash.to_string()),
            "status": {"kind": "Applied", "block_height": 7},
            "scope": "global",
            "resolved_from": resolved_from,
        }))
        .expect("canonical global status"),
    )
}

fn submit(
    client: Client,
    transaction: &SignedTransaction,
    asynchronous: bool,
) -> eyre::Result<HashOf<SignedTransaction>> {
    if asynchronous {
        let account = client.account_client().expect("account context");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("async confirmation runtime")
            .block_on(account.submit_transaction_and_wait(transaction))
    } else {
        crate::blocking::Client::from_client(client)
            .expect("blocking confirmation runtime")
            .submit_transaction_and_wait(transaction)
    }
}

fn assert_confirmation_timeout(error: &eyre::Report, hash: HashOf<SignedTransaction>) {
    let report = format!("{error:#}");
    assert!(
        report.contains(&format!(
            "transaction {hash} did not reach state-resolved Applied"
        )),
        "{report}"
    );
    assert!(report.contains("attempts=1"), "{report}");
    assert!(
        error
            .chain()
            .all(|cause| cause.downcast_ref::<TransactionFinalityFailure>().is_none()),
        "a deadline cannot fabricate a fixed finality failure: {report}"
    );
}

fn assert_one_submit_and_global_reads(
    snapshots: &[RequestSnapshot],
    hash: HashOf<SignedTransaction>,
) {
    assert_eq!(
        snapshots
            .iter()
            .filter(|request| request.method == Method::POST)
            .count(),
        1,
        "confirmation never repeats the paid submission",
    );
    assert_eq!(snapshots[0].method, Method::POST);
    assert_eq!(snapshots[0].url.path(), "/v1/pipeline/transactions");
    for request in &snapshots[1..] {
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.url.path(), "/v1/pipeline/transactions/status");
        assert_status_scope(request, "global");
        assert!(
            request
                .url
                .query_pairs()
                .any(|(key, value)| key == "hash" && value == hash.to_string())
        );
    }
}

#[test]
fn short_context_long_configured_wait_confirms_after_cached_applied_without_replay() {
    for asynchronous in [false, true] {
        let mut client = client_with_base_url(base_url());
        client.transaction_status_timeout = Duration::from_secs(300);
        let transaction = transaction(&client);
        let hash = transaction.hash();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let polls = Arc::new(AtomicUsize::new(0));
        let transport = {
            let observed = Arc::clone(&observed);
            let polls = Arc::clone(&polls);
            DefaultHttpTransport::mock(Arc::new(move |request| {
                let path = request.url.path().to_owned();
                observed
                    .lock()
                    .expect("requests")
                    .push((Instant::now(), request));
                match path.as_str() {
                    "/v1/pipeline/transactions" => Ok(empty_response(StatusCode::ACCEPTED)),
                    "/v1/pipeline/transactions/status" => {
                        let ordinal = polls.fetch_add(1, Ordering::SeqCst);
                        Ok(applied(hash, if ordinal == 0 { "cache" } else { "state" }))
                    }
                    other => panic!("unexpected request: {other}"),
                }
            }))
        };
        client = client.with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        // The old configured-timeout cadence slept two seconds after the cached response,
        // so it could not make its second authoritative read within this original context.
        let deadline = Instant::now() + Duration::from_millis(1_500);
        let client = client.with_request_deadline(deadline);
        assert_eq!(client.transaction_status_timeout, Duration::from_secs(300));
        assert_eq!(
            submit(client, &transaction, asynchronous).expect("fresh state confirmation"),
            hash
        );
        assert!(Instant::now() < deadline);
        assert_eq!(
            polls.load(Ordering::SeqCst),
            2,
            "cached Applied cannot finish confirmation"
        );
        let observed = observed.lock().expect("requests");
        assert!(observed[2].0.duration_since(observed[1].0) >= Duration::from_millis(150));
        for (started, request) in observed.iter() {
            let timeout = request
                .timeout
                .expect("original context bounds each dispatch");
            assert!(!timeout.is_zero() && *started < deadline);
            assert!(timeout <= Duration::from_millis(1_500));
        }
        let snapshots = observed
            .iter()
            .map(|(_, request)| request.clone())
            .collect::<Vec<_>>();
        assert_one_submit_and_global_reads(&snapshots, hash);
    }
}

#[test]
fn short_context_retry_after_retains_deadline_including_original_submission() {
    for asynchronous in [false, true] {
        let mut client = client_with_base_url(base_url());
        client.transaction_status_timeout = Duration::from_secs(300);
        let transaction = transaction(&client);
        let hash = transaction.hash();
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let transport = {
            let snapshots = Arc::clone(&snapshots);
            DefaultHttpTransport::mock(Arc::new(move |request| {
                let path = request.url.path().to_owned();
                snapshots.lock().expect("requests").push(request);
                match path.as_str() {
                    "/v1/pipeline/transactions" => {
                        std::thread::sleep(Duration::from_millis(200));
                        Ok(empty_response(StatusCode::ACCEPTED))
                    }
                    "/v1/pipeline/transactions/status" => {
                        let mut response = json_response(StatusCode::TOO_MANY_REQUESTS, "{}");
                        response
                            .headers_mut()
                            .insert(http::header::RETRY_AFTER, "1".parse().unwrap());
                        Ok(response)
                    }
                    other => panic!("unexpected request: {other}"),
                }
            }))
        };
        client = client.with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        let deadline = Instant::now() + Duration::from_millis(800);
        let client = client
            .with_request_deadline(deadline)
            .with_request_deadline(deadline + Duration::from_secs(300));
        let error = submit(client, &transaction, asynchronous)
            .expect_err("Retry-After exceeds original remaining deadline");
        assert_confirmation_timeout(&error, hash);
        assert!(Instant::now() >= deadline);
        let snapshots = snapshots.lock().expect("requests");
        assert_eq!(
            snapshots.len(),
            2,
            "Retry-After cannot be shortened into another status read"
        );
        assert!(
            snapshots[1].timeout.unwrap() < Duration::from_millis(650),
            "submission consumed the original context budget"
        );
        assert_one_submit_and_global_reads(&snapshots, hash);
    }
}

#[test]
fn short_context_rejects_late_state_applied_after_one_submission() {
    for asynchronous in [false, true] {
        let mut client = client_with_base_url(base_url());
        client.transaction_status_timeout = Duration::from_secs(300);
        let transaction = transaction(&client);
        let hash = transaction.hash();
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let transport = {
            let snapshots = Arc::clone(&snapshots);
            DefaultHttpTransport::mock(Arc::new(move |request| {
                let path = request.url.path().to_owned();
                snapshots.lock().expect("requests").push(request);
                match path.as_str() {
                    "/v1/pipeline/transactions" => Ok(empty_response(StatusCode::ACCEPTED)),
                    "/v1/pipeline/transactions/status" => {
                        // Deliberately noncooperative transport: the original wait must still
                        // refuse a late, otherwise valid state-resolved Applied document.
                        std::thread::sleep(Duration::from_millis(350));
                        Ok(applied(hash, "state"))
                    }
                    other => panic!("unexpected request: {other}"),
                }
            }))
        };
        client = client.with_test_http_transport(transport);
        mark_data_model_compatible(&client);
        let deadline = Instant::now() + Duration::from_millis(250);
        let error = submit(
            client.with_request_deadline(deadline),
            &transaction,
            asynchronous,
        )
        .expect_err("late state response cannot confirm finality");
        assert_confirmation_timeout(&error, hash);
        assert!(Instant::now() >= deadline);
        let snapshots = snapshots.lock().expect("requests");
        assert_eq!(snapshots.len(), 2);
        assert_one_submit_and_global_reads(&snapshots, hash);
    }
}
