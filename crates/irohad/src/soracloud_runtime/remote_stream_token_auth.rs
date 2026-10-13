//! Exact-network operator authentication for Soracloud remote stream-token requests.
use eyre::WrapErr as _;
use iroha_crypto::KeyPair;
use iroha_data_model::NetworkId;
const STREAM_TOKEN_PATH: &str = "/v1/sorafs/storage/token";
/// Runtime-only identity used to authenticate remote stream-token issuance.
pub(super) struct RemoteStreamTokenOperator {
    key_pair: KeyPair,
    network_id: NetworkId,
}
impl RemoteStreamTokenOperator {
    /// Bind a runtime key to one exact genesis-derived network identity.
    pub(super) fn new(key_pair: KeyPair, network_id: NetworkId) -> Self {
        Self {
            key_pair,
            network_id,
        }
    }
    /// Return the exact network identity included in every request signature.
    pub(super) fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
}
impl super::SoracloudRuntimeManager {
    /// Attach the runtime-only node identity used for remote stream-token issuance.
    #[must_use]
    pub(crate) fn with_remote_stream_token_operator(
        mut self,
        key_pair: KeyPair,
        network_id: NetworkId,
    ) -> Self {
        self.remote_stream_token_operator =
            Some(RemoteStreamTokenOperator::new(key_pair, network_id));
        self
    }
    /// Bind remote hydration to the daemon's runtime node key and genesis trust root.
    #[must_use]
    pub(crate) fn with_remote_stream_token_operator_from_config(
        self,
        config: &iroha_config::parameters::actual::Root,
    ) -> Self {
        self.with_remote_stream_token_operator(
            config.common.key_pair.clone(),
            NetworkId::from_genesis_hash(config.genesis.expected_hash),
        )
    }
    /// Attach a deterministic operator identity to inline runtime tests.
    #[cfg(test)]
    pub(super) fn with_test_remote_stream_token_operator(self, network_id: NetworkId) -> Self {
        self.with_remote_stream_token_operator(
            KeyPair::try_from_seed(vec![0x51; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("derive remote stream-token operator fixture"),
            network_id,
        )
    }
}
/// Fail startup when enabled remote hydration lacks its exact runtime identity.
pub(super) fn ensure_startup_binding(
    operator: Option<&RemoteStreamTokenOperator>,
    expected_network_id: &NetworkId,
    remote_hydration_enabled: bool,
) -> eyre::Result<()> {
    if !remote_hydration_enabled {
        return Ok(());
    }
    let operator = operator.ok_or_else(|| {
        eyre::eyre!("remote Soracloud hydration requires a runtime-only operator signer")
    })?;
    if operator.network_id() != expected_network_id {
        eyre::bail!("remote Soracloud hydration operator NetworkId does not match node state");
    }
    Ok(())
}
/// Build one signed request without performing network I/O.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_request(
    client: &reqwest::blocking::Client,
    operator: Option<&RemoteStreamTokenOperator>,
    url: reqwest::Url,
    manifest_id_hex: &str,
    provider_id: &[u8; 32],
    max_chunk_len: u64,
    chunk_count: usize,
    client_id: &str,
    nonce: &str,
) -> eyre::Result<reqwest::blocking::Request> {
    let operator = operator.ok_or_else(|| {
        eyre::eyre!("remote Soracloud hydration requires a runtime-only operator signer")
    })?;
    if url.path() != STREAM_TOKEN_PATH || url.query().is_some() || url.fragment().is_some() {
        eyre::bail!("remote Soracloud hydration token URL has a non-canonical path or query");
    }
    let mut request_body = norito::json::native::Map::new();
    request_body.insert(
        "manifest_id_hex".into(),
        norito::json::Value::from(manifest_id_hex),
    );
    request_body.insert(
        "provider_id_hex".into(),
        norito::json::Value::from(hex::encode(provider_id)),
    );
    request_body.insert("ttl_secs".into(), norito::json::Value::from(60_u64));
    request_body.insert("max_streams".into(), norito::json::Value::from(1_u16));
    request_body.insert(
        "rate_limit_bytes".into(),
        norito::json::Value::from(max_chunk_len.max(1)),
    );
    request_body.insert(
        "requests_per_minute".into(),
        norito::json::Value::from(u32::try_from(chunk_count.saturating_add(8)).unwrap_or(u32::MAX)),
    );
    let body = norito::json::to_vec(&norito::json::Value::Object(request_body))
        .wrap_err("encode remote Soracloud hydration token request")?;
    let uri: iroha_torii::Uri = STREAM_TOKEN_PATH
        .parse()
        .expect("canonical stream-token path is a valid URI");
    let method = iroha_torii::Method::POST;
    let headers = iroha_torii::operator_signed_request_headers(
        &operator.key_pair,
        &operator.network_id,
        &method,
        &uri,
        &body,
    )
    .wrap_err("sign remote Soracloud hydration token request")?;
    client
        .request(method, url)
        .headers(headers)
        .header("X-SoraFS-Client", client_id)
        .header("X-SoraFS-Nonce", nonce)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .build()
        .wrap_err("build remote Soracloud hydration token request")
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, PublicKey};
    use iroha_data_model::{NetworkId, block::BlockHeader};
    const PUBLIC_KEY: &str = "x-iroha-operator-public-key";
    const TIMESTAMP: &str = "x-iroha-operator-timestamp-ms";
    const NONCE: &str = "x-iroha-operator-nonce";
    const SIGNATURE: &str = "x-iroha-operator-signature";
    const DOMAIN: &[u8] = b"iroha.operator.http-request.network.v1\0";
    fn key_pair() -> KeyPair {
        KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519)
            .expect("derive remote stream-token operator fixture")
    }
    fn network_id(genesis: &[u8]) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            genesis,
        )))
    }
    fn client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .expect("build request-only client")
    }
    fn request(
        operator: Option<&RemoteStreamTokenOperator>,
    ) -> eyre::Result<reqwest::blocking::Request> {
        build_request(
            &client(),
            operator,
            "https://provider.example/v1/sorafs/storage/token".parse()?,
            &"11".repeat(32),
            &[0x22; 32],
            4_096,
            3,
            "soracloud-runtime-hydration",
            "diagnostic-nonce",
        )
    }
    fn decode_standard_base64(input: &str) -> Vec<u8> {
        fn value(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("invalid base64 fixture byte"),
            }
        }
        assert_eq!(input.len() % 4, 0);
        let mut decoded = Vec::with_capacity(input.len() / 4 * 3);
        for chunk in input.as_bytes().chunks_exact(4) {
            let a = value(chunk[0]);
            let b = value(chunk[1]);
            decoded.push((a << 2) | (b >> 4));
            if chunk[2] != b'=' {
                let c = value(chunk[2]);
                decoded.push((b << 4) | (c >> 2));
                if chunk[3] != b'=' {
                    decoded.push((c << 6) | value(chunk[3]));
                }
            }
        }
        decoded
    }
    fn header<'request>(
        request: &'request reqwest::blocking::Request,
        name: &str,
    ) -> &'request str {
        request
            .headers()
            .get(name)
            .expect("required operator header")
            .to_str()
            .expect("operator header is text")
    }
    fn signature_verifies(
        request: &reqwest::blocking::Request,
        network_id: &NetworkId,
        uri: &iroha_torii::Uri,
        body: &[u8],
    ) -> bool {
        let public_key: PublicKey = header(request, PUBLIC_KEY)
            .parse()
            .expect("operator public key");
        let signature = iroha_crypto::ed25519_parse_signature(&decode_standard_base64(header(
            request, SIGNATURE,
        )))
        .expect("operator Ed25519 signature");
        let canonical =
            iroha_torii::canonical_request_message(&iroha_torii::Method::POST, uri, body)
                .expect("canonical remote-stream fixture is within V1 limits");
        let mut message = Vec::new();
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(network_id.as_bytes());
        message.extend_from_slice(&canonical);
        message.extend_from_slice(b"\n");
        message.extend_from_slice(header(request, TIMESTAMP).as_bytes());
        message.extend_from_slice(b"\n");
        message.extend_from_slice(header(request, NONCE).as_bytes());
        signature.verify(&public_key, &message).is_ok()
    }
    #[test]
    fn signed_request_carries_exact_body_and_required_headers() -> eyre::Result<()> {
        let key_pair = key_pair();
        let network_id = network_id(b"remote-stream-token-genesis");
        let operator = RemoteStreamTokenOperator::new(key_pair.clone(), network_id);
        let request = request(Some(&operator))?;
        let body = request
            .body()
            .and_then(reqwest::blocking::Body::as_bytes)
            .expect("in-memory request body");
        let uri: iroha_torii::Uri = STREAM_TOKEN_PATH.parse()?;
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().path(), STREAM_TOKEN_PATH);
        assert_eq!(
            request.headers()[PUBLIC_KEY].to_str()?,
            key_pair.public_key().to_string()
        );
        for header in [
            TIMESTAMP,
            NONCE,
            SIGNATURE,
            "x-sorafs-client",
            "x-sorafs-nonce",
        ] {
            assert!(request.headers().contains_key(header), "missing {header}");
        }
        assert!(!request.headers().contains_key("x-api-token"));
        assert!(signature_verifies(&request, &network_id, &uri, body));
        Ok(())
    }
    #[test]
    fn signature_binds_genesis_path_and_raw_body_even_for_same_label() -> eyre::Result<()> {
        let consumer_label = String::from("sora-production");
        let provider_label = consumer_label.clone();
        assert_eq!(consumer_label, provider_label);
        let bound_network_id = network_id(b"remote-stream-token-genesis-a");
        let foreign_network_id = network_id(b"remote-stream-token-genesis-b");
        let operator = RemoteStreamTokenOperator::new(key_pair(), bound_network_id);
        let request = request(Some(&operator))?;
        let body = request
            .body()
            .and_then(reqwest::blocking::Body::as_bytes)
            .expect("in-memory request body");
        let uri: iroha_torii::Uri = STREAM_TOKEN_PATH.parse()?;
        let wrong_uri: iroha_torii::Uri = "/v1/sorafs/storage/token/other".parse()?;
        assert!(signature_verifies(&request, &bound_network_id, &uri, body));
        assert!(!signature_verifies(
            &request,
            &foreign_network_id,
            &uri,
            body
        ));
        assert!(!signature_verifies(
            &request,
            &bound_network_id,
            &wrong_uri,
            body
        ));
        assert!(!signature_verifies(
            &request,
            &bound_network_id,
            &uri,
            br#"{"manifest_id_hex":"substituted"}"#,
        ));
        Ok(())
    }
    #[test]
    fn missing_operator_fails_before_request_can_be_dispatched() {
        let error = request(None).expect_err("missing runtime signer must fail closed");
        assert!(error.to_string().contains("runtime-only operator signer"));
    }
    #[test]
    fn startup_binding_requires_signer_and_exact_genesis() {
        let expected = network_id(b"remote-stream-token-startup-genesis");
        let foreign = network_id(b"remote-stream-token-startup-foreign-genesis");
        let operator = RemoteStreamTokenOperator::new(key_pair(), expected);
        ensure_startup_binding(Some(&operator), &expected, true)
            .expect("exact runtime identity is accepted");
        assert!(ensure_startup_binding(None, &expected, true).is_err());
        assert!(ensure_startup_binding(Some(&operator), &foreign, true).is_err());
        ensure_startup_binding(None, &expected, false)
            .expect("disabled remote hydration needs no signer");
    }
    #[test]
    fn each_request_uses_a_fresh_operator_nonce() -> eyre::Result<()> {
        let operator = RemoteStreamTokenOperator::new(
            key_pair(),
            network_id(b"remote-stream-token-freshness-genesis"),
        );
        let first = request(Some(&operator))?;
        let second = request(Some(&operator))?;
        assert_ne!(first.headers()[NONCE], second.headers()[NONCE]);
        Ok(())
    }
}
