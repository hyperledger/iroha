//! Public SDK construction and transport fixtures for native orchestration tests.

use iroha::{
    client::Client,
    config::Config,
    http::{HttpTransport, TransportFuture, TransportRequest},
};
use std::sync::Arc;
use url::Url;

#[derive(Debug)]
struct NoTransport;

impl HttpTransport for NoTransport {
    fn send_blocking(&self, _: TransportRequest) -> eyre::Result<http::Response<Vec<u8>>> {
        panic!("fixture must not perform a blocking transport call")
    }

    fn send(&self, _: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async { panic!("fixture must not perform an unconfigured transport call") })
    }
}

pub(super) fn client_with_base_url(url: Url) -> Client {
    // Fixed public test keys use the same canonical configuration parser as external clients.
    // No private SDK fields or compatibility cache are changed by this fixture.
    let source = format!(
        r#"chain = "00000000-0000-0000-0000-000000000000"
network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
torii_url = "{url}"
[account]
chain_discriminant = 753
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
[transaction]
time_to_live_ms = 5000
status_timeout_ms = 10000
nonce = false
"#
    );
    let (config, _) = Config::load_bytes_with_musubi_publication(
        "private-settlement-test.toml",
        source.as_bytes(),
    )
    .expect("valid native integration test configuration");
    Client::builder(config)
        .http_transport(Arc::new(NoTransport))
        .build()
        .expect("valid immutable native integration client")
}

pub(super) fn compatible_capabilities_response() -> eyre::Result<http::Response<Vec<u8>>> {
    let hash = hex::encode(norito::schema::identity::frame_hash::<
        iroha_data_model::transaction::SignedTransaction,
    >());
    let body = norito::json::json!({
        "data_model_version": iroha_data_model::DATA_MODEL_VERSION,
        "signed_transaction_schema_hash_hex": hash,
    });
    Ok(http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(norito::json::to_vec(&body)?)?)
}
