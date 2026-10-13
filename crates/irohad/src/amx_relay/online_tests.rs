//! Runtime transport controls for the actual online relay source, independent of settlement.

use super::*;
use iroha::{
    config::{AliasCache, Config, HttpTransportPolicy},
    http::{HttpTransport, Method, Response, TransportFuture, TransportRequest},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;
use iroha_service_model::soranet::{AnonymityPolicy, RolloutPhase};
use iroha_torii_shared::{
    ErrorDetails, ErrorEnvelope, PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE,
    PipelineTransactionStatusNotFoundV1, route_catalog, status::Status,
};
use std::time::Duration;

#[derive(Debug)]
struct AsyncSourceTransport {
    proof: SumeragiFinalityProof,
    requests: Mutex<Vec<TransportRequest>>,
    proof_entered: tokio::sync::Notify,
    proof_released: tokio::sync::Notify,
}
impl HttpTransport for AsyncSourceTransport {
    fn send_blocking(&self, _: TransportRequest) -> Result<Response<Vec<u8>>> {
        panic!("online relay observation must use its owned asynchronous transport");
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            let path = request.url.path().to_owned();
            let (status, media, body) = if path.ends_with("/v1/node/capabilities") {
                (
                    200,
                    "application/json",
                    norito::json::to_vec(&norito::json!({
                        "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
                        "signed_transaction_schema_hash_hex": (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>())),
                    }))?,
                )
            } else if path.contains("/bridge/finality/") {
                self.proof_entered.notify_one();
                self.proof_released.notified().await;
                (
                    200,
                    "application/x-norito",
                    norito::encode_canonical(&self.proof)?,
                )
            } else if path.ends_with(route_catalog::diagnostic::STATUS.path())
                && !path.contains("/pipeline/")
            {
                let status = Status {
                    blocks: 9,
                    ..Status::default()
                };
                (200, "application/json", norito::json::to_vec(&status)?)
            } else if path.ends_with("/v1/pipeline/transactions/status") {
                let query = request.url.query_pairs().collect::<BTreeMap<_, _>>();
                let hash = query
                    .get("hash")
                    .unwrap()
                    .parse::<HashOf<SignedTransaction>>()?;
                let scope = query.get("scope").unwrap();
                let absence =
                    ErrorEnvelope::new(PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE, "No status.")
                        .with_details(ErrorDetails {
                            pipeline_transaction_status_not_found: Some(
                                PipelineTransactionStatusNotFoundV1::new(&hash, scope),
                            ),
                            ..ErrorDetails::default()
                        });
                (404, "application/json", norito::json::to_vec(&absence)?)
            } else {
                panic!("unexpected relay observation route: {path}");
            };
            self.requests.lock().unwrap().push(request);
            Ok(Response::builder()
                .status(status)
                .header("content-type", media)
                .body(body)?)
        })
    }
}
use std::collections::BTreeMap;

fn source() -> (OnlineSource, Arc<AsyncSourceTransport>) {
    let fixture = NativeFinalityFixture::start("relay-online-source");
    let key_pair = KeyPair::from_seed(vec![0xAB; 32], Algorithm::Ed25519);
    let config = Config {
        chain: fixture.chain_id().parse().unwrap(),
        network_id: fixture.network_id(),
        account: AccountId::new(key_pair.public_key().clone()),
        account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
        key_pair,
        basic_auth: None,
        api_token: None,
        torii_api_url: "http://relay.invalid/provider/v1/".parse().unwrap(),
        http_transport_policy: HttpTransportPolicy::Ordinary,
        torii_request_timeout: Duration::from_secs(2),
        transaction_ttl: Duration::from_secs(5),
        transaction_status_timeout: Duration::from_secs(10),
        transaction_add_nonce: false,
        sorafs_alias_cache: AliasCache::default().into_policy(),
        sorafs_anonymity_policy: AnonymityPolicy::default(),
        sorafs_rollout_phase: RolloutPhase::default(),
    };
    let transport = Arc::new(AsyncSourceTransport {
        proof: fixture.genesis_proof().clone(),
        requests: Mutex::new(Vec::new()),
        proof_entered: tokio::sync::Notify::new(),
        proof_released: tokio::sync::Notify::new(),
    });
    let client = Client::builder(config)
        .http_transport(transport.clone())
        .build()
        .unwrap();
    (
        OnlineSource {
            client: Arc::new(client),
            scope: SumeragiRootScope::Global,
        },
        transport,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn online_relay_reads_use_async_transport_inside_the_supervised_runtime() {
    let (mut source, transport) = source();
    {
        let read = source.proof(NonZeroU64::MIN);
        tokio::pin!(read);
        tokio::select! {
            result = &mut read => panic!("relay proof must yield to its asynchronous transport before completion: {result:?}"),
            () = transport.proof_entered.notified() => transport.proof_released.notify_one(),
        }
        assert_eq!(read.await.unwrap(), transport.proof);
    }
    assert_eq!(source.applied_height().await.unwrap(), 9);
    let hash = HashOf::from_untyped_unchecked(Hash::new(b"unsubmitted relay carrier"));
    assert!(matches!(
        source.locate(hash).await.unwrap(),
        Location::Absent
    ));
    source.scope = SumeragiRootScope::Dataspace {
        parent_network_id: *source.client.network_id(),
        dataspace_id: iroha_model_base::topology::DataSpaceId::new(119),
    };
    assert!(matches!(
        source.locate(hash).await.unwrap(),
        Location::Absent
    ));
    let requests = transport.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        5,
        "one compatibility probe and exactly four requested reads"
    );
    for request in requests.iter() {
        assert_eq!(request.method, Method::GET);
        assert!(request.url.path().starts_with("/provider/v1/"));
        assert!(request.body.is_empty());
        assert!(request.max_response_bytes > 0);
        assert!(request.timeout.is_some());
    }
    let proof = &requests[1];
    assert_eq!(
        proof.max_response_bytes,
        2 * iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES + 4 * 1024 * 1024
    );
    let scopes = requests[3..]
        .iter()
        .map(|request| {
            request
                .url
                .query_pairs()
                .find(|(key, _)| key == "scope")
                .unwrap()
                .1
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(scopes, ["global", "local"]);
}
