//! Bounded native account syntax inspection for clients without a native codec.
//!
//! This endpoint inspects only the supplied public literal. It never queries account
//! existence, permissions, aliases, or other ledger data and grants no read authority.

use super::*;
use iroha_data_model::account::AccountAddress;
use norito::json::{BoundedJsonError, FastJsonWrite, JsonSerialize, JsonWriteSink};

pub(super) const MAX_REQUEST_BYTES: usize = 4096;
pub(super) const BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ACCOUNT_BYTES: usize = 2048;
const MAX_RESPONSE_BYTES: usize = 8192;
const ENDPOINT: &str = "v1/accounts/inspect";

#[derive(crate::json_macros::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct AccountInspectionRequest {
    version: u8,
    network_id: String,
    request_id: String,
    nonce: String,
    account_id: String,
}

#[derive(crate::json_macros::JsonSerialize)]
struct AccountInspectionResponse {
    version: u8,
    network_id: String,
    request_id: String,
    nonce: String,
    account_id: String,
    canonical_hex: String,
    controller: ControllerProjection,
}

enum ControllerProjection {
    Single {
        algorithm: &'static str,
        public_key_hex: String,
    },
    Multisig,
}

impl FastJsonWrite for ControllerProjection {
    fn write_json(&self, out: &mut String) {
        norito::json::write_json_unbounded(self, out);
    }

    fn write_json_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        out.begin_container()?;
        let result = (|| {
            match self {
                Self::Single {
                    algorithm,
                    public_key_hex,
                } => {
                    out.push_str("{\"kind\":\"single\",\"algorithm\":")?;
                    algorithm.json_serialize_to(out)?;
                    out.push_str(",\"public_key_hex\":")?;
                    public_key_hex.json_serialize_to(out)?;
                    out.push('}')?;
                }
                Self::Multisig => out.push_str("{\"kind\":\"multisig\"}")?,
            }
            Ok(())
        })();
        out.end_container();
        result
    }
}

fn invalid(message: &'static str) -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(message.into()),
    ))
}

fn exact_request_id(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn exact_nonce(value: &str) -> bool {
    value.len() == 64
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn inspect(
    expected_network: &iroha_data_model::NetworkId,
    body: &[u8],
) -> Result<AccountInspectionResponse, Error> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(invalid("account inspection request exceeds 4096 bytes"));
    }
    // A stricter local scope composes with the original admitted query owner.
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(
            MAX_REQUEST_BYTES,
            MAX_REQUEST_BYTES,
            64 * 1024,
            64 * 1024,
            8,
        ),
        || {
            let request: AccountInspectionRequest = norito::json::from_slice(body)
                .map_err(|_| invalid("invalid closed account inspection request"))?;
            if request.version != 1 || request.network_id != expected_network.to_string() {
                return Err(invalid(
                    "account inspection version or network does not match",
                ));
            }
            if !exact_request_id(&request.request_id) || !exact_nonce(&request.nonce) {
                return Err(invalid(
                    "account inspection request_id or nonce is not canonical",
                ));
            }
            if request.account_id.is_empty() || request.account_id.len() > MAX_ACCOUNT_BYTES {
                return Err(invalid(
                    "account_id exceeds the native inspection literal bound",
                ));
            }
            // Native admission enforces the configured chain discriminant, exact roundtrip,
            // checksum, address header/controller and cryptographic public-key rules.
            let address = AccountAddress::from_i105(&request.account_id).map_err(|_| {
                invalid("account_id is not a canonical native account for this network")
            })?;
            let account = address
                .to_account_id()
                .map_err(|_| invalid("account_id has an invalid native controller"))?;
            let canonical_hex = address
                .canonical_hex()
                .map_err(|_| invalid("account_id cannot be rendered by the native codec"))?;
            let controller = match account.controller().single_signatory() {
                Some(key) => {
                    let (algorithm, bytes) = key
                        .try_to_bytes()
                        .map_err(|_| invalid("account_id has an invalid native public key"))?;
                    ControllerProjection::Single {
                        algorithm: algorithm.as_static_str(),
                        public_key_hex: hex::encode(bytes),
                    }
                }
                None => ControllerProjection::Multisig,
            };
            Ok(AccountInspectionResponse {
                version: 1,
                network_id: request.network_id,
                request_id: request.request_id,
                nonce: request.nonce,
                account_id: request.account_id,
                canonical_hex,
                controller,
            })
        },
    )
}

pub(super) async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    request: axum::http::Request<Body>,
) -> AxResponse {
    let mut response = match handle(app, remote.ip(), request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

async fn handle(
    app: SharedAppState,
    remote: std::net::IpAddr,
    request: axum::http::Request<Body>,
) -> Result<AxResponse, Error> {
    if let Err(response) = utils::canonical_json_request_content_type(request.headers()) {
        return Ok(response);
    }
    if !limits::is_allowed_by_cidr(
        request.headers(),
        Some(remote),
        &app.api_rate_limit_bypass_nets,
    ) {
        check_access(&app, request.headers(), Some(remote), ENDPOINT).await?;
    }
    let admission = acquire_query_admission(&app, true).await?;
    let request = match collect_bounded_body_with_deadline(
        request,
        MAX_REQUEST_BYTES,
        BODY_READ_TIMEOUT,
        BoundedBodyReadMessages {
            context: "native account inspection",
            too_large: "account inspection request exceeds 4096 bytes",
            protocol_error: "account inspection body stream ended with a protocol error",
            timeout: "account inspection body exceeded the read deadline",
        },
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return Ok(response),
    };
    let body = axum::body::to_bytes(request.into_body(), MAX_REQUEST_BYTES)
        .await
        .map_err(|_| invalid("account inspection body could not be read"))?;
    let network = *app.state.network_id_ref();
    routing::run_admitted_blocking(
        admission,
        "native account inspection worker failed",
        move || {
            let owner = crate::history_producer::HistoryProducerOwner::current()?;
            let inspected = inspect(&network, &body)?;
            owner.json_with_limit(&inspected, MAX_RESPONSE_BYTES)
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::{MultisigMember, MultisigPolicy},
        block::BlockHeader,
    };

    fn network(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
            [seed; 32],
        )))
    }

    fn account(seed: u8) -> AccountId {
        AccountId::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("native inspection key")
                .public_key()
                .clone(),
        )
    }

    fn body(network: &NetworkId, account: &str) -> Vec<u8> {
        norito::json::to_vec(&norito::json!({
            "version": 1,
            "network_id": network.to_string(),
            "request_id": "8a70f738-e08d-4d2c-bb07-f3eec382f441",
            "nonce": "a1".repeat(32),
            "account_id": account,
        }))
        .unwrap()
    }

    #[test]
    fn account_inspection_returns_native_identity_without_ledger_lookup() {
        let network = network(0xb1);
        let account = account(0xc1);
        let literal = account.to_string();
        let response = inspect(&network, &body(&network, &literal)).unwrap();
        let json = norito::json::to_value(&response).unwrap();
        let address = AccountAddress::from_account_id(&account).unwrap();
        assert_eq!(json["account_id"].as_str(), Some(literal.as_str()));
        assert_eq!(
            json["canonical_hex"].as_str(),
            Some(address.canonical_hex().unwrap().as_str())
        );
        assert_eq!(
            json["network_id"].as_str(),
            Some(network.to_string().as_str())
        );
        assert_eq!(
            json["request_id"].as_str(),
            Some("8a70f738-e08d-4d2c-bb07-f3eec382f441")
        );
        assert_eq!(json["nonce"].as_str(), Some("a1".repeat(32).as_str()));
        assert_eq!(json["controller"]["kind"].as_str(), Some("single"));
        assert_eq!(json["controller"]["algorithm"].as_str(), Some("ed25519"));
        let (_, bytes) = account
            .controller()
            .single_signatory()
            .unwrap()
            .try_to_bytes()
            .unwrap();
        assert_eq!(
            json["controller"]["public_key_hex"].as_str(),
            Some(hex::encode(bytes).as_str())
        );
        assert_eq!(json.as_object().unwrap().len(), 7);
    }

    #[test]
    fn account_inspection_marks_multisig_without_claiming_a_single_signer() {
        let policy = MultisigPolicy::new(
            1,
            vec![
                MultisigMember::new(
                    account(0xc2)
                        .controller()
                        .single_signatory()
                        .unwrap()
                        .clone(),
                    1,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let account = AccountId::new_multisig(policy);
        let network = network(0xb2);
        let response = inspect(&network, &body(&network, &account.to_string())).unwrap();
        let json = norito::json::to_value(&response).unwrap();
        assert_eq!(json["controller"], norito::json!({ "kind": "multisig" }));
        assert_eq!(
            json["canonical_hex"].as_str(),
            Some(
                AccountAddress::from_account_id(&account)
                    .unwrap()
                    .canonical_hex()
                    .unwrap()
                    .as_str()
            )
        );
    }

    #[test]
    fn account_inspection_rejects_foreign_prefix_checksum_alias_and_hex() {
        let network = network(0xb3);
        let account = account(0xc3);
        let address = AccountAddress::from_account_id(&account).unwrap();
        let canonical = account.to_string();
        let prefix = AccountAddress::i105_discriminant(&canonical).unwrap();
        let mut bad_checksum: Vec<_> = canonical.chars().collect();
        let last = bad_checksum.pop().unwrap();
        bad_checksum.push(if last == 'x' { 'y' } else { 'x' });
        for literal in [
            address.to_i105_for_discriminant(prefix ^ 1).unwrap(),
            bad_checksum.into_iter().collect(),
            "reader@private.dataspace".into(),
            address.canonical_hex().unwrap(),
            format!(" {canonical}"),
        ] {
            assert!(inspect(&network, &body(&network, &literal)).is_err());
        }
    }

    #[test]
    fn account_inspection_rejects_network_binding_unknown_duplicate_and_unbounded_requests() {
        let network = network(0xb4);
        let original = body(&network, &account(0xc4).to_string());
        assert!(inspect(&super::tests::network(0xb5), &original).is_err());
        let mut value: norito::json::Value = norito::json::from_slice(&original).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), norito::json::Value::Null);
        assert!(inspect(&network, &norito::json::to_vec(&value).unwrap()).is_err());
        let duplicate = String::from_utf8(original)
            .unwrap()
            .replacen("{", "{\"version\":1,", 1);
        assert!(inspect(&network, duplicate.as_bytes()).is_err());
        assert!(inspect(&network, &vec![b' '; MAX_REQUEST_BYTES + 1]).is_err());
        for (request_id, nonce) in [
            ("00000000-0000-0000-0000-000000000000", "a1".repeat(32)),
            ("8A70f738-e08d-4d2c-bb07-f3eec382f441", "a1".repeat(32)),
            ("8a70f738-e08d-4d2c-bb07-f3eec382f441", "00".repeat(32)),
            ("8a70f738-e08d-4d2c-bb07-f3eec382f441", "A1".repeat(32)),
        ] {
            let invalid = norito::json!({"version": 1, "network_id": network.to_string(),
                "request_id": request_id, "nonce": nonce, "account_id": account(0xc4).to_string()});
            assert!(inspect(&network, &norito::json::to_vec(&invalid).unwrap()).is_err());
        }
    }

    #[tokio::test]
    async fn account_inspection_http_bounds_media_and_keeps_responses_private() {
        let app = crate::mk_app_state_for_tests();
        let request_body = body(app.state.network_id_ref(), &account(0xc5).to_string());
        for (media, bytes, status) in [
            ("application/json", request_body, StatusCode::OK),
            (
                "text/plain",
                b"{}".to_vec(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                "application/json",
                vec![b' '; MAX_REQUEST_BYTES + 1],
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let request = axum::http::Request::post("/v1/accounts/inspect")
                .header(axum::http::header::CONTENT_TYPE, media)
                .body(Body::from(bytes))
                .unwrap();
            // A direct-handler test must provide the original owner that the
            // production route receives from outer HTTP admission.
            let reservation = try_acquire_new_query_fanout_memory(&app).unwrap();
            let response = COLLECTION_READ_MEMORY_RESERVATION
                .scope(
                    reservation,
                    handler(State(app.clone()), crate::loopback_connect_info(), request),
                )
                .await;
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers()[axum::http::header::CACHE_CONTROL],
                "private, no-store"
            );
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert!(bytes.len() <= MAX_RESPONSE_BYTES);
        }
    }
}
