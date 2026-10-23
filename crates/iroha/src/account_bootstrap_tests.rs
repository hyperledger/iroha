//! Bootstrap discovery rejects ambiguous trust inputs and never requires account credentials.

use super::*;
use crate::http::{TransportFuture, TransportRequest};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use std::sync::Mutex;

fn network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"wallet bootstrap tests",
    )))
}

fn capabilities() -> AccountCapabilitiesV1 {
    AccountCapabilitiesV1::from_policy(
        network(),
        369,
        &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            Algorithm::Ed25519,
        ])
        .unwrap(),
    )
}

#[derive(Debug)]
struct Transport {
    requests: Mutex<Vec<TransportRequest>>,
    body: Vec<u8>,
}

impl HttpTransport for Transport {
    fn send_blocking(&self, _: TransportRequest) -> Result<Response<Vec<u8>>> {
        panic!("bootstrap uses the async SDK transport")
    }

    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        self.requests.lock().unwrap().push(request);
        Box::pin(async {
            Ok(Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(self.body.clone())
                .unwrap())
        })
    }
}

#[test]
fn validates_trusted_origin_and_bounded_deadline() {
    for bad in [
        "http://example.org",
        "https://user:secret@example.org",
        "https://example.org?token=secret",
        "https://example.org#fragment",
        "file:///tmp/node",
    ] {
        assert!(validate_endpoint(&bad.parse().unwrap()).is_err());
        assert!(
            Client::new(bad.parse().unwrap(), Duration::from_secs(5)).is_err(),
            "{bad}"
        );
    }
    for allowed in [
        "https://taira.sora.org",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
    ] {
        assert!(validate_endpoint(&allowed.parse().unwrap()).is_ok());
        assert!(
            Client::new(allowed.parse().unwrap(), Duration::from_secs(5)).is_ok(),
            "{allowed}"
        );
    }
    assert!(
        validate_endpoint(
            &format!("https://taira.sora.org/{}", "a".repeat(2048))
                .parse()
                .unwrap()
        )
        .is_err()
    );
    assert!(Client::new("https://taira.sora.org".parse().unwrap(), Duration::ZERO).is_err());
    assert!(
        crate::blocking::account_bootstrap::Client::new(
            "https://taira.sora.org".parse().unwrap(),
            Duration::from_secs(5)
        )
        .is_ok()
    );
}

#[test]
fn rejects_ambiguous_or_oversized_discovery_responses() {
    let missing = validate_response(Response::builder().status(404).body(Vec::new()).unwrap(), 4)
        .wrap_err("GET /v1/accounts/faucet/policy")
        .unwrap_err();
    assert_eq!(
        missing.downcast_ref::<DiscoveryHttpError>().unwrap().status,
        404
    );
    assert!(
        validate_response(Response::builder().status(502).body(Vec::new()).unwrap(), 4).is_err()
    );
    assert!(
        validate_response(
            Response::builder()
                .header("content-type", "text/html")
                .body(Vec::new())
                .unwrap(),
            4
        )
        .is_err()
    );
    assert!(
        validate_response(
            Response::builder()
                .header("content-type", "application/json")
                .header("content-type", "application/json")
                .body(Vec::new())
                .unwrap(),
            4
        )
        .is_err()
    );
    assert!(
        validate_response(
            Response::builder()
                .header("content-type", "application/json")
                .body(vec![0; 5])
                .unwrap(),
            4
        )
        .is_err()
    );
    assert_eq!(
        validate_response(
            Response::builder()
                .header("content-type", "application/json; charset=utf-8")
                .body(b"{}".to_vec())
                .unwrap(),
            4
        )
        .unwrap(),
        b"{}"
    );
}

#[test]
fn rejects_unusable_or_noncanonical_signing_policy() {
    let valid = capabilities();
    validate_capabilities(&valid).unwrap();
    let mut bad = valid.clone();
    bad.schema_version = 2;
    assert!(validate_capabilities(&bad).is_err());
    let mut bad = valid.clone();
    bad.network_prefix = 0;
    assert!(validate_capabilities(&bad).is_err());
    let mut bad = valid.clone();
    bad.allowed_signing = vec!["secp256k1".into()];
    validate_capabilities(&bad).expect("explicit policy need not admit Ed25519");
    bad.allowed_signing = vec!["secp256k1".into(), "ed25519".into()];
    assert!(validate_capabilities(&bad).is_err());
    let mut bad = valid.clone();
    bad.allowed_signing.clear();
    assert!(validate_capabilities(&bad).is_err());
    let mut bad = valid.clone();
    bad.allowed_signing.push("ed25519".into());
    assert!(validate_capabilities(&bad).is_err());
    let mut bad = valid;
    bad.allowed_signing.push("unsupported".into());
    assert!(validate_capabilities(&bad).is_err());
}

#[tokio::test]
async fn public_capabilities_use_one_bounded_unsigned_request() {
    let transport = Arc::new(Transport {
        requests: Mutex::new(Vec::new()),
        body: norito::json::to_vec(&capabilities()).unwrap(),
    });
    let client = Client::with_transport(
        "https://taira.sora.org/".parse().unwrap(),
        Duration::from_secs(5),
        transport.clone(),
    )
    .unwrap();
    assert_eq!(client.capabilities().await.unwrap(), capabilities());
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(
        request.url.as_str(),
        "https://taira.sora.org/v1/accounts/capabilities"
    );
    assert_eq!(request.method, Method::GET);
    assert!(request.body.is_empty());
    assert_eq!(
        request.max_response_bytes,
        ACCOUNT_CAPABILITIES_MAX_BYTES_V1
    );
    assert_eq!(request.timeout, Some(Duration::from_secs(5)));
    assert_eq!(
        request.headers.len(),
        1,
        "only content negotiation, no account/signature/credentials"
    );
    assert_eq!(request.headers[0].0, "accept");
    assert!(
        crate::blocking::account_bootstrap::Client::new(
            "https://taira.sora.org".parse().unwrap(),
            Duration::from_secs(5)
        )
        .is_err(),
        "blocking facade rejects nested runtime"
    );
}

#[tokio::test]
async fn faucet_discovery_requires_pinned_network_and_valid_issuance() {
    let _profile = ChainDiscriminantGuard::enter(369);
    let key = KeyPair::random();
    let policy = AccountFaucetAdvertisement {
        schema_version: 1,
        network_id: network(),
        network_prefix: 369,
        authority: iroha_data_model::account::AccountId::new(key.public_key().clone()),
        asset_definition_id: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
        amount: "10".parse().unwrap(),
    };
    let transport = Arc::new(Transport {
        requests: Mutex::new(Vec::new()),
        body: norito::json::to_vec(&policy).unwrap(),
    });
    let client = Client::with_transport(
        "http://127.0.0.1:8080".parse().unwrap(),
        Duration::from_secs(5),
        transport.clone(),
    )
    .unwrap();
    assert_eq!(client.faucet_policy(network(), 369).await.unwrap(), policy);
    assert!(transport.requests.lock().unwrap()[0].direct_loopback);
    assert_eq!(
        transport.requests.lock().unwrap()[0].url.path(),
        route_catalog::application_api::ACCOUNTS_FAUCET_POLICY_GET.path()
    );
    assert!(client.faucet_policy(network(), 753).await.is_err());
    let other = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"different genesis",
    )));
    assert!(client.faucet_policy(other, 369).await.is_err());
    let mut bad = policy;
    bad.amount = "0".parse().unwrap();
    let invalid = Client::with_transport(
        "https://taira.sora.org".parse().unwrap(),
        Duration::from_secs(5),
        Arc::new(Transport {
            requests: Mutex::new(Vec::new()),
            body: norito::json::to_vec(&bad).unwrap(),
        }),
    )
    .unwrap();
    assert!(invalid.faucet_policy(network(), 369).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn faucet_discovery_requires_exact_canonical_v1_fields() {
    use iroha_data_model::account::{AccountId, MultisigMember, MultisigPolicy};
    use norito::json::Value;

    async fn discover(body: &Value) -> Result<AccountFaucetAdvertisement> {
        let original_profile = iroha_data_model::account::address::chain_discriminant();
        let transport = Arc::new(Transport {
            requests: Mutex::new(Vec::new()),
            body: norito::json::to_vec(body).unwrap(),
        });
        let client = Client::with_transport(
            "https://taira.sora.org".parse().unwrap(),
            Duration::from_secs(5),
            transport.clone(),
        )
        .unwrap();
        let result = client.faucet_policy(network(), 369).await;
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            original_profile,
            "discovery must restore the caller's profile on success and refusal"
        );
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.url.path(),
            route_catalog::application_api::ACCOUNTS_FAUCET_POLICY_GET.path()
        );
        assert!(request.body.is_empty());
        assert_eq!(request.max_response_bytes, ACCOUNT_FAUCET_POLICY_MAX_BYTES);
        assert_eq!(request.timeout, Some(Duration::from_secs(5)));
        assert_eq!(request.headers.len(), 1, "discovery remains signer-free");
        assert_eq!(request.headers[0].0, "accept");
        result
    }

    let _profile = ChainDiscriminantGuard::enter(369);
    let first = KeyPair::try_from_seed(vec![0x94; 32], Algorithm::Ed25519).unwrap();
    let second = KeyPair::try_from_seed(vec![0x95; 32], Algorithm::Ed25519).unwrap();
    let policy = AccountFaucetAdvertisement {
        schema_version: 1,
        network_id: network(),
        network_prefix: 369,
        authority: AccountId::new(first.public_key().clone()),
        asset_definition_id: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().unwrap(),
        amount: "25000".parse().unwrap(),
    };
    let canonical = norito::json::to_value(&policy).unwrap();
    let fields = [
        "schema_version",
        "network_id",
        "network_prefix",
        "authority",
        "asset_definition_id",
        "amount",
    ];
    assert_eq!(canonical.as_object().unwrap().len(), fields.len());
    assert!(
        fields
            .iter()
            .all(|field| canonical.as_object().unwrap().contains_key(*field))
    );
    assert_eq!(discover(&canonical).await.unwrap(), policy);
    for field in fields {
        let mut missing = canonical.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(discover(&missing).await.is_err(), "missing {field}");
        for wrong_type in [Value::Null, Value::Bool(true)] {
            let mut invalid = canonical.clone();
            invalid
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), wrong_type);
            assert!(discover(&invalid).await.is_err(), "wrong type for {field}");
        }
    }
    for unknown in ["unexpected", "schema", "chain_discriminant"] {
        let mut extended = canonical.clone();
        extended
            .as_object_mut()
            .unwrap()
            .insert(unknown.to_owned(), Value::from(1_u64));
        assert!(discover(&extended).await.is_err(), "unknown {unknown}");
    }
    let multisig = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(first.public_key().clone(), 1).unwrap(),
                MultisigMember::new(second.public_key().clone(), 1).unwrap(),
            ],
        )
        .unwrap(),
    );
    let other_network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"different policy genesis",
    )));
    let noncanonical_network = policy.network_id.to_string().to_lowercase();
    assert_ne!(noncanonical_network, policy.network_id.to_string());
    for (field, value) in [
        ("schema_version", Value::from(0_u64)),
        ("schema_version", Value::from(2_u64)),
        ("schema_version", Value::from("1")),
        ("schema_version", Value::from(65_536_u64)),
        ("network_id", Value::from("invalid-network")),
        ("network_id", Value::from(noncanonical_network)),
        ("network_id", Value::from(other_network.to_string())),
        ("network_id", Value::from(1_u64)),
        ("network_prefix", Value::from(65_536_u64)),
        ("network_prefix", Value::from("369")),
        ("network_prefix", Value::from(0_u64)),
        ("network_prefix", Value::from(753_u64)),
        ("authority", Value::from("faucet@sora")),
        (
            "authority",
            Value::from(format!(" {}", policy.authority.canonical_i105().unwrap())),
        ),
        ("authority", Value::from(multisig.canonical_i105().unwrap())),
        ("authority", Value::from(1_u64)),
        ("asset_definition_id", Value::from("xor#universal")),
        (
            "asset_definition_id",
            Value::from(format!(" {}", policy.asset_definition_id)),
        ),
        ("asset_definition_id", Value::from(1_u64)),
        ("amount", Value::from("0")),
        ("amount", Value::from("-1")),
        ("amount", Value::from("025000")),
        ("amount", Value::from("25000.0")),
        ("amount", Value::from(25_000_u64)),
    ] {
        let mut invalid = canonical.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), value);
        assert!(
            discover(&invalid).await.is_err(),
            "invalid {field}: {invalid:?}"
        );
    }
    for invalid in [Value::Null, Value::Array(Vec::new()), Value::from("policy")] {
        assert!(
            discover(&invalid).await.is_err(),
            "not an object: {invalid:?}"
        );
    }
    let _other_profile = ChainDiscriminantGuard::enter(0);
    assert_eq!(discover(&canonical).await.unwrap(), policy);
    let mut invalid = canonical;
    invalid
        .as_object_mut()
        .unwrap()
        .insert("schema_version".to_owned(), Value::from(2_u64));
    assert!(discover(&invalid).await.is_err());
}

#[test]
fn capabilities_accept_every_canonical_identity_in_tag_order_without_backend_filtering() {
    let policy = iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(
        Algorithm::ALL.to_vec(),
    )
    .unwrap();
    let capability = AccountCapabilitiesV1::from_policy(network(), 369, &policy);
    validate_capabilities(&capability).unwrap();
    let mut noncanonical = capability;
    noncanonical.allowed_signing.sort();
    assert!(validate_capabilities(&noncanonical).is_err());
}
