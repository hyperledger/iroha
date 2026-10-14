//! App API canonical request auth smoke test: GET + POST endpoints accept the canonical signed
//! header set (`X-Iroha-Account`/`X-Iroha-Signature`/`X-Iroha-Timestamp-Ms`/`X-Iroha-Nonce`) over
//! the exact-network canonical method/path/query/body envelope plus freshness metadata.
use eyre::Result;
use integration_tests::sandbox;
use iroha_crypto::Signature;
use iroha_test_network::NetworkBuilder;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use iroha_torii::{
    HEADER_ACCOUNT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP_MS, Method, Uri,
    canonical_network_request_signature_message, filter::ListQuery, signature_header_value,
};
use norito::json::Value as JsonValue;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use std::time::{SystemTime, UNIX_EPOCH};
fn signing_uri(url: &reqwest::Url) -> Result<Uri> {
    match url.query() {
        Some(query) => Ok(format!("{}?{query}", url.path()).parse()?),
        None => Ok(url.path().parse()?),
    }
}
#[test]
fn app_api_accepts_canonical_headers_for_get_and_post() -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(
        builder,
        stringify!(app_api_accepts_canonical_headers_for_get_and_post),
    )?
    else {
        return Ok(());
    };
    let peer = network
        .peers()
        .first()
        .ok_or_else(|| eyre::eyre!("no peers available"))?;
    let network_id = network.network_id();
    let http = integration_tests::http::client();
    let account_literal = ALICE_ID.to_string();
    let account_header = ALICE_ID.to_canonical_hex()?;
    assert!(account_header.is_ascii());
    assert!(account_header.starts_with("0x"));
    assert!(
        account_header[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let timestamp_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    // GET /v1/accounts/{account}/assets with canonical signed headers.
    let mut assets_url = reqwest::Url::parse(&peer.torii_url())?;
    {
        let mut segments = assets_url
            .path_segments_mut()
            .map_err(|_| eyre::eyre!("torii URL cannot accept path segments"))?;
        segments.pop_if_empty();
        segments.push("v1");
        segments.push("accounts");
        segments.push(&account_literal);
        segments.push("assets");
    }
    assets_url.query_pairs_mut().append_pair("limit", "1");
    let assets_endpoint = assets_url.as_str().to_owned();
    let assets_uri = signing_uri(&assets_url)?;
    let assets_nonce = "app-api-canonical-auth-get";
    let assets_msg = canonical_network_request_signature_message(
        &network_id,
        &Method::GET,
        &assets_uri,
        &[],
        timestamp_ms,
        assets_nonce,
    )?;
    let assets_sig = Signature::try_new(ALICE_KEYPAIR.private_key(), &assets_msg)
        .expect("GET app-api signature");
    let mut assets_headers = HeaderMap::new();
    assets_headers.insert(
        HeaderName::from_bytes(HEADER_ACCOUNT.as_bytes())?,
        HeaderValue::from_str(&account_header)?,
    );
    assets_headers.insert(
        HeaderName::from_bytes(HEADER_SIGNATURE.as_bytes())?,
        HeaderValue::from_str(&signature_header_value(&assets_sig)?)?,
    );
    assets_headers.insert(
        HeaderName::from_bytes(HEADER_TIMESTAMP_MS.as_bytes())?,
        HeaderValue::from_str(&timestamp_ms.to_string())?,
    );
    assets_headers.insert(
        HeaderName::from_bytes(HEADER_NONCE.as_bytes())?,
        HeaderValue::from_static(assets_nonce),
    );
    let assets_body: String = rt.block_on(async {
        http.get(&assets_endpoint)
            .headers(assets_headers)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    })?;
    let assets_json: JsonValue = norito::json::from_str(&assets_body)?;
    let total_assets = assets_json
        .get("items")
        .and_then(JsonValue::as_array)
        .map_or(0, Vec::len);
    assert!(
        total_assets > 0,
        "assets endpoint should accept canonical auth"
    );
    // POST /v1/accounts/{account}/transactions/query with canonical signed headers + body hash
    let body = norito::json::to_vec(&ListQuery::new().limit(4).to_json_value())?;
    let mut tx_url = reqwest::Url::parse(&peer.torii_url())?;
    {
        let mut segments = tx_url
            .path_segments_mut()
            .map_err(|_| eyre::eyre!("torii URL cannot accept path segments"))?;
        segments.pop_if_empty();
        segments.push("v1");
        segments.push("accounts");
        segments.push(&account_literal);
        segments.push("transactions");
        segments.push("query");
    }
    let tx_uri = signing_uri(&tx_url)?;
    let tx_nonce = "app-api-canonical-auth-post";
    let tx_msg = canonical_network_request_signature_message(
        &network_id,
        &Method::POST,
        &tx_uri,
        &body,
        timestamp_ms,
        tx_nonce,
    )?;
    let tx_sig =
        Signature::try_new(ALICE_KEYPAIR.private_key(), &tx_msg).expect("POST app-api signature");
    let mut tx_headers = HeaderMap::new();
    tx_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    tx_headers.insert(
        HeaderName::from_bytes(HEADER_ACCOUNT.as_bytes())?,
        HeaderValue::from_str(&account_header)?,
    );
    tx_headers.insert(
        HeaderName::from_bytes(HEADER_SIGNATURE.as_bytes())?,
        HeaderValue::from_str(&signature_header_value(&tx_sig)?)?,
    );
    tx_headers.insert(
        HeaderName::from_bytes(HEADER_TIMESTAMP_MS.as_bytes())?,
        HeaderValue::from_str(&timestamp_ms.to_string())?,
    );
    tx_headers.insert(
        HeaderName::from_bytes(HEADER_NONCE.as_bytes())?,
        HeaderValue::from_static(tx_nonce),
    );
    let tx_body: String = rt.block_on(async {
        http.post(tx_url)
            .headers(tx_headers)
            .body(body)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    })?;
    let tx_json: JsonValue = norito::json::from_str(&tx_body)?;
    assert!(
        tx_json.get("items").is_some(),
        "transactions query should parse with canonical auth"
    );
    Ok(())
}
