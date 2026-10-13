//! Async transport, cursor ownership and typed query regression tests.

use super::*;
use crate::{
    client::{DataModelCompatibility, test_network_id},
    http::{HttpTransport, TransportFuture, TransportRequest},
};
use iroha_data_model::{
    Registrable,
    domain::Domain,
    parameter::Parameters,
    query::{
        QueryOutputBatchBox, SignedQuery,
        domain::FindDomains,
        executor::FindParameters,
        parameters::{FetchSize, Pagination},
    },
};
use iroha_model_base::chain::ChainId;
use iroha_service_model::soranet::{AnonymityPolicy, RolloutPhase};
use iroha_test_samples::gen_account_in;
use iroha_version::codec::DecodeVersioned;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::Poll,
};

fn config_factory() -> crate::config::Config {
    let (account, key_pair) = gen_account_in("wonderland");
    crate::config::Config {
        chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
        network_id: test_network_id(),
        account,
        account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
        key_pair,
        basic_auth: None,
        api_token: None,
        torii_api_url: "http://127.0.0.1:8080".parse().expect("test URL"),
        torii_request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
        transaction_ttl: std::time::Duration::from_secs(5),
        transaction_status_timeout: std::time::Duration::from_secs(10),
        transaction_add_nonce: false,
        sorafs_alias_cache: crate::client::default_alias_policy(),
        sorafs_anonymity_policy: AnonymityPolicy::GuardPq,
        http_transport_policy: crate::config::HttpTransportPolicy::Ordinary,
        sorafs_rollout_phase: RolloutPhase::Canary,
    }
}

#[derive(Debug)]
enum Reply {
    Response(http::Response<Vec<u8>>),
    Lost,
    Pending,
}
#[derive(Debug)]
struct AsyncOnlyTransport {
    replies: Mutex<VecDeque<Reply>>,
    requests: Mutex<Vec<TransportRequest>>,
}
impl HttpTransport for AsyncOnlyTransport {
    fn send_blocking(&self, _request: TransportRequest) -> Result<http::Response<Vec<u8>>> {
        panic!("async query used the blocking transport");
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        self.requests.lock().expect("requests").push(request);
        let reply = self
            .replies
            .lock()
            .expect("replies")
            .pop_front()
            .expect("no replay or extra query");
        Box::pin(async move {
            match reply {
                Reply::Response(response) => Ok(response),
                Reply::Lost => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "reply lost after dispatch",
                )
                .into()),
                Reply::Pending => std::future::pending().await,
            }
        })
    }
}
fn account(replies: Vec<Reply>) -> (AccountClient, Arc<AsyncOnlyTransport>) {
    let transport = Arc::new(AsyncOnlyTransport {
        replies: Mutex::new(replies.into()),
        requests: Mutex::new(Vec::new()),
    });
    let client = Client::builder(config_factory())
        .http_transport(transport.clone())
        .build()
        .expect("client");
    *client
        .data_model_compatibility
        .lock()
        .expect("compatibility") = DataModelCompatibility::SubmitCompatible;
    (client.account_client().expect("account binding"), transport)
}
fn response(value: &QueryResponse) -> Reply {
    Reply::Response(
        http::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, APPLICATION_NORITO)
            .body(norito::to_bytes(value).expect("query response"))
            .expect("response"),
    )
}
fn batch(names: &[&str], cursor: Option<u64>) -> Reply {
    response(&QueryResponse::Iterable(QueryOutput {
        batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Domain(
            names
                .iter()
                .map(|name| {
                    Domain::new(
                        iroha_model_base::domain::DomainId::try_new(*name, "universal")
                            .expect("domain id"),
                    )
                    .build(&iroha_test_samples::ALICE_ID)
                })
                .collect(),
        )),
        // Deliberately do not promise exact remote counts.
        remaining_items: None,
        has_more: cursor.is_some(),
        continue_cursor: cursor.map(|offset| ForwardCursor {
            query: "ab".repeat(32),
            cursor: NonZeroU64::new(offset).expect("cursor"),
            gas_budget: Some(55),
        }),
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn collects_typed_pages_with_fresh_signed_nonces_and_exact_cursor_authority() {
    fn assert_send<T: Send>(future: T) -> T {
        future
    }
    let (account, transport) = account(vec![
        batch(&[], Some(1)),
        batch(&[], Some(2)),
        batch(&["wonderland"], None),
    ]);
    let rows = assert_send(
        account
            .query(FindDomains)
            .with_pagination(Pagination {
                offset: 7,
                limit: NonZeroU64::new(9),
            })
            .with_fetch_size(FetchSize {
                fetch_size: NonZeroU64::new(2),
            })
            .execute_all(),
    )
    .await
    .expect("all pages");
    assert_eq!(rows.len(), 1);
    let requests = transport.requests.lock().expect("requests");
    assert_eq!(requests.len(), 3);
    let signed: Vec<_> = requests
        .iter()
        .map(|request| {
            assert_eq!(request.url.path(), "/v1/query");
            let signed = SignedQuery::decode_all_versioned(&request.body).expect("signed query");
            assert_eq!(signed.payload.network_id, *account.network_id());
            assert_eq!(&signed.payload.authority, account.authority());
            assert_ne!(signed.payload.nonce, [0; 32]);
            signed
        })
        .collect();
    assert_ne!(signed[0].payload.nonce, signed[1].payload.nonce);
    assert_ne!(signed[1].payload.nonce, signed[2].payload.nonce);
    match &signed[0].payload.request {
        QueryRequest::Start(query) => {
            assert_eq!(query.params.pagination.offset, 7);
            assert_eq!(query.params.pagination.limit, NonZeroU64::new(9));
            assert_eq!(query.params.fetch_size.fetch_size, NonZeroU64::new(2));
        }
        _ => panic!("first request must start exactly the configured query"),
    }
    for (index, signed) in signed.iter().enumerate().skip(1) {
        match &signed.payload.request {
            QueryRequest::Continue(cursor) => {
                assert_eq!(cursor.query, "ab".repeat(32));
                assert_eq!(cursor.cursor.get(), index as u64);
                assert_eq!(cursor.gas_budget, Some(55));
            }
            _ => panic!("a continuation must not restart the query"),
        }
    }
}

#[tokio::test]
async fn singular_parameters_preserve_json_negotiation_and_output_type() {
    let expected = Parameters::default();
    let value = QueryResponse::Singular(SingularQueryOutputBox::Parameters(expected.clone()));
    let reply = Reply::Response(
        http::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(json::to_vec(&value).expect("JSON response"))
            .expect("response"),
    );
    let (account, transport) = account(vec![reply]);
    assert_eq!(
        account
            .query_single(FindParameters)
            .await
            .expect("parameters"),
        expected
    );
    assert!(
        transport.requests.lock().expect("requests")[0]
            .headers
            .iter()
            .any(|(name, value)| name == http::header::ACCEPT && value == "application/json")
    );
}

#[tokio::test]
async fn singular_shape_mismatch_is_an_error_without_panic_or_retry() {
    let (account, transport) = account(vec![batch(&[], None)]);
    assert!(account.query_single(FindParameters).await.is_err());
    assert_eq!(transport.requests.lock().expect("requests").len(), 1);
}

#[tokio::test]
async fn start_failure_is_dispatched_once_for_transport_and_decode_errors() {
    for reply in [
        Reply::Lost,
        Reply::Response(
            http::Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, APPLICATION_NORITO)
                .body(vec![0xff])
                .expect("malformed response"),
        ),
    ] {
        let (account, transport) = account(vec![reply]);
        assert!(account.query(FindDomains).execute_all().await.is_err());
        assert_eq!(transport.requests.lock().expect("requests").len(), 1);
    }
}

#[tokio::test]
async fn malformed_and_lost_continuations_terminally_consume_the_cursor() {
    for reply in [
        Reply::Lost,
        response(&QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::String(vec![
                "hostile".to_owned(),
            ])),
            remaining_items: Some(10),
            has_more: true,
            continue_cursor: Some(ForwardCursor {
                query: "cd".repeat(32),
                cursor: NonZeroU64::new(2).expect("cursor"),
                gas_budget: None,
            }),
        })),
    ] {
        let (account, transport) = account(vec![batch(&[], Some(1)), reply]);
        let mut stream = account
            .query(FindDomains)
            .execute()
            .await
            .expect("initial typed batch");
        assert!(stream.next().await.expect("terminal result").is_err());
        assert!(stream.next().await.is_none());
        assert_eq!(transport.requests.lock().expect("requests").len(), 2);
    }
}

#[tokio::test]
async fn cancelled_continuation_cannot_replay_the_signed_nonce() {
    let (account, transport) = account(vec![batch(&[], Some(1)), Reply::Pending]);
    let mut stream = account
        .query(FindDomains)
        .execute()
        .await
        .expect("first batch");
    {
        let pending = stream.next();
        tokio::pin!(pending);
        assert!(matches!(
            futures_util::poll!(pending.as_mut()),
            Poll::Pending
        ));
    }
    assert_eq!(transport.requests.lock().expect("requests").len(), 2);
    assert!(stream.next().await.is_none());
    assert_eq!(transport.requests.lock().expect("requests").len(), 2);
}

#[tokio::test]
async fn invalid_fetch_size_fails_before_query_dispatch() {
    let (account, transport) = account(Vec::new());
    let result = account
        .query(FindDomains)
        .with_fetch_size(FetchSize {
            fetch_size: MAX_FETCH_SIZE.checked_add(1),
        })
        .execute_all()
        .await;
    assert!(matches!(
        result,
        Err(QueryError::Validation(ValidationFail::QueryFailed(
            QueryExecutionFail::FetchSizeTooBig
        )))
    ));
    assert!(transport.requests.lock().expect("requests").is_empty());
}

#[tokio::test]
async fn singular_constraints_check_across_empty_and_nonempty_pages() {
    let (client, _) = account(vec![batch(&[], Some(1)), batch(&["wonderland"], None)]);
    assert!(
        client
            .query(FindDomains)
            .execute_single_opt()
            .await
            .expect("zero or one")
            .is_some()
    );
    let (client, _) = account(vec![batch(&[], None)]);
    assert!(matches!(
        client.query(FindDomains).execute_single().await,
        Err(SingleQueryError::ExpectedOneGotNone)
    ));
    let (client, _) = account(vec![
        batch(&["wonderland"], Some(1)),
        batch(&["garden"], None),
    ]);
    assert!(matches!(
        client.query(FindDomains).execute_single().await,
        Err(SingleQueryError::ExpectedOneGotMany)
    ));
    let (client, _) = account(vec![
        batch(&["wonderland"], Some(1)),
        batch(&["garden"], None),
    ]);
    assert!(matches!(
        client.query(FindDomains).execute_single_opt().await,
        Err(SingleQueryError::ExpectedOneOrZeroGotMany)
    ));
}

#[tokio::test]
async fn compatibility_failure_uses_async_probe_and_never_submits_the_query() {
    let (account, transport) = account(vec![Reply::Lost]);
    *account
        .client()
        .data_model_compatibility
        .lock()
        .expect("cache") = DataModelCompatibility::Unchecked;
    assert!(account.query(FindDomains).execute_all().await.is_err());
    let requests = transport.requests.lock().expect("requests");
    assert_eq!(requests.len(), 1);
    assert_ne!(requests[0].url.path(), "/query");
}

fn truncated_batch(names: &[&str], remaining_items: Option<u64>) -> Reply {
    let Reply::Response(fixture) = batch(names, None) else {
        unreachable!("batch fixtures are responses")
    };
    let QueryResponse::Iterable(mut output) =
        norito::decode_from_bytes::<QueryResponse>(fixture.body()).expect("fixture response")
    else {
        unreachable!("batch fixtures are iterable")
    };
    // Ephemeral cursor mode: more rows exist, but no continuation is offered.
    output.has_more = true;
    output.remaining_items = remaining_items;
    response(&QueryResponse::Iterable(output))
}

#[tokio::test]
async fn truncated_results_yield_delivered_rows_then_fail_explicitly() {
    let (client, transport) = account(vec![truncated_batch(&["wonderland", "garden"], Some(3))]);
    let mut stream = client
        .query(FindDomains)
        .execute()
        .await
        .expect("first batch");
    assert!(stream.has_more());
    assert_eq!(stream.remaining_items(), Some(5));
    assert!(stream.next().await.expect("first row").is_ok());
    assert_eq!(stream.remaining_items(), Some(4));
    assert!(stream.next().await.expect("second row").is_ok());
    assert!(matches!(
        stream.next().await,
        Some(Err(QueryError::Truncated {
            remaining_items: Some(3)
        }))
    ));
    assert!(stream.next().await.is_none(), "truncation ends the stream");
    assert!(!stream.has_more());
    assert_eq!(
        transport.requests.lock().expect("requests").len(),
        1,
        "truncation never sends a continuation"
    );

    let (client, _) = account(vec![truncated_batch(&["wonderland"], None)]);
    assert!(matches!(
        client.query(FindDomains).execute_all().await,
        Err(QueryError::Truncated {
            remaining_items: None
        })
    ));
}

#[tokio::test]
async fn complete_streams_report_exact_remaining_rows() {
    let (client, _) = account(vec![batch(&["wonderland"], Some(1)), batch(&[], None)]);
    let mut stream = client
        .query(FindDomains)
        .execute()
        .await
        .expect("first batch");
    assert!(stream.has_more());
    assert_eq!(
        stream.remaining_items(),
        None,
        "the fixture does not promise exact remote counts"
    );
    assert!(stream.next().await.expect("row").is_ok());
    assert!(stream.next().await.is_none());
    assert_eq!(stream.remaining_items(), Some(0));
}
