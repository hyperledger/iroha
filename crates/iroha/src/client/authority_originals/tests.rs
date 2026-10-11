//! Actual signed POSTs and genuine native node certificates over synthetic fixture data.
//! Provider success remains unverified transport and never grants ledger or release authority.
use super::super::evidence_http_tests::{capture_requests, client_with_base_url};
use super::super::tests::assert_canonical_account_signed_request;
use super::*;
use iroha_crypto::{Algorithm, Hash, KeyPair, SignatureOf};
use iroha_data_model::{
    account::{
        AccountDetails, AccountId,
        rekey::{AccountAlias, AccountRekeyRecord},
    },
    common::Owned,
    sumeragi::SumeragiStatus,
    sumeragi_finality::{
        SumeragiFinalityAttestation, SumeragiFinalityAttestationBody, WorldStateElementKindV1,
        WorldStateSnapshotEntryV1, WorldStateSnapshotV1, test_fixtures::NativeFinalityFixture,
        world_state_value_hash_v1,
    },
};
use iroha_model_base::{peer::PeerId, topology::DataSpaceId};
use iroha_torii_shared::authority_originals::*;
use norito::codec::Encode as _;
use std::sync::OnceLock;

fn account_fixture() -> &'static (
    NativeAuthorityOriginalsRequestV1,
    NativeAuthorityOriginalsV1,
) {
    static VALUE: OnceLock<(
        NativeAuthorityOriginalsRequestV1,
        NativeAuthorityOriginalsV1,
    )> = OnceLock::new();
    VALUE.get_or_init(|| {
        let alias = AccountAlias::new(
            "retail".parse().unwrap(),
            Some("leumi".parse().unwrap()),
            DataSpaceId::new(77),
        );
        let owner = AccountId::new(
            KeyPair::from_seed(vec![7; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let account_value = Owned::new(AccountDetails::new(
            iroha_model_base::metadata::Metadata::default(),
            Some(alias.clone()),
            None,
            vec![],
        ));
        let rekey_record = AccountRekeyRecord::new(alias.clone(), owner.clone());
        let snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"explicitly synthetic authority codec schema"),
            entries: vec![WorldStateSnapshotEntryV1 {
                field_id: "world.accounts".into(),
                kind: WorldStateElementKindV1::Table,
                key_hash: Some(world_state_value_hash_v1(&owner).unwrap()),
                value_hash: world_state_value_hash_v1(&account_value).unwrap(),
            }],
        };
        let mut native = NativeFinalityFixture::start("authority original codec fixture");
        let block = native.block_with_submitted_work(native.next_header());
        let proof = native.certify_with_world_root(block, snapshot.root().unwrap());
        let request = NativeAuthorityOriginalsRequestV1 {
            network_id: native.network_id(),
            challenge: [7; 32],
            selector: NativeAuthorityOriginalsSelectorV1::AccountAlias(
                "retail@leumi.is2".parse().unwrap(),
            ),
        };
        let (request_sha256, challenge) =
            native_authority_originals_request_digests_v1(&request.canonical_wire().unwrap())
                .unwrap();
        let node = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
        let node_id = PeerId::new(node.public_key().clone());
        let config = Hash::new(b"fixture node config");
        let body = SumeragiFinalityAttestationBody {
            observed_at_unix_ms: 1_000_000,
            challenge,
            network_id: native.network_id(),
            node_fingerprint: Hash::new(node_id.encode()),
            node_id,
            build_fingerprint: Hash::new(b"fixture binary"),
            config_fingerprint: config,
            genesis_block_hash: native.genesis().hash(),
            genesis_finality_proof: native.genesis_proof().clone(),
            status: SumeragiStatus {
                protocol_version: 1,
                config_fingerprint: config,
                beacon_horizon: None,
                instance: native.verifier().instance().0,
                height: 3,
                view: 0,
                stage: 0,
                leader: None,
                proxy_tail: None,
                high_qc_view: None,
                level: 0,
                start_level: 0,
                t_retx_ms: 100,
                committed_height: 2,
                applied_height: 2,
                awaiting: false,
                signer: Some(node.public_key().clone()),
                unanchored: false,
                abstaining: false,
                halted: None,
                footprint: iroha_data_model::sumeragi::SumeragiFootprint::default(),
            },
            finality_proof: proof,
        };
        let attestation = SumeragiFinalityAttestation {
            signature: SignatureOf::try_from_hash(node.private_key(), body.signing_hash()).unwrap(),
            body,
        };
        attestation.verify().unwrap();
        let response = NativeAuthorityOriginalsV1 {
            request_sha256,
            selector: request.selector.clone(),
            attestation,
            world_snapshot: snapshot,
            originals: NativeAuthorityOriginalsFamilyV1::AccountAlias(NativeAccountAliasStateV1 {
                alias: alias.clone(),
                binding_keys: vec![alias],
                selected: Some(NativeAccountAliasOriginalV1 {
                    bound_account: owner,
                    rekey_record,
                    account_value,
                    // These bytes test the data-only wire, not native NameRecord membership.
                    lease_value: vec![2, 4, 6],
                }),
            }),
        };
        response.validate_request_correlation(&request).unwrap();
        (request, response)
    })
}

fn configured() -> Client {
    let mut client = client_with_base_url(Url::parse("https://mock.local/").unwrap());
    client.network_id = account_fixture().0.network_id;
    client
}
fn successful(value: &NativeAuthorityOriginalsV1) -> Response<Vec<u8>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", APPLICATION_NORITO)
        .body(norito::encode_canonical(value).unwrap())
        .unwrap()
}
#[test]
fn native_authority_provider_preserves_exact_peer_prefix_in_signed_post() {
    let (request, value) = account_fixture();
    for prefix in [
        "native-peer-2/",
        "native-peer-3/",
        "native-peer-4/",
        "private/nested/",
    ] {
        let mut client = configured();
        client.torii_url = Url::parse(&format!("https://mock.local/{prefix}")).unwrap();
        let (result, snapshots) = capture_requests(successful(value), |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
        });
        let result = result.unwrap();
        assert_eq!(snapshots.len(), 1);
        let actual = &snapshots[0];
        assert_eq!(
            actual.url.path(),
            format!(
                "/{prefix}{}",
                NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1.trim_start_matches('/')
            )
        );
        assert_eq!(result.request_wire, request.canonical_wire().unwrap());
        assert_eq!(
            result.response_wire,
            norito::encode_canonical(value).unwrap()
        );
        assert_canonical_account_signed_request(&client, actual);
        let headers = actual
            .headers
            .iter()
            .map(|(key, value)| (key.to_ascii_lowercase(), value))
            .collect::<std::collections::HashMap<_, _>>();
        let mut stripped = actual.url.clone();
        stripped.set_path(NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1);
        let message = Client::exact_network_request_message(
            &client.network_id,
            &actual.method,
            &stripped,
            &actual.body,
            headers["x-iroha-timestamp-ms"].parse::<u64>().unwrap(),
            headers["x-iroha-nonce"],
        )
        .unwrap();
        let signature = base64::engine::general_purpose::STANDARD
            .decode(headers["x-iroha-signature"])
            .unwrap();
        assert!(
            iroha_crypto::Signature::from_bytes(&signature)
                .verify(client.key_pair.public_key(), &message)
                .is_err()
        );
    }
}
#[test]
fn native_authority_provider_dispatches_signed_post_and_retains_exact_request_preimage() {
    let client = configured();
    let (request, value) = account_fixture();
    let (result, snapshots) = capture_requests(successful(value), |transport| {
        client
            .clone()
            .with_test_http_transport(transport)
            .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
    });
    let result = result.unwrap();
    assert_eq!(snapshots.len(), 1);
    let actual = &snapshots[0];
    assert_eq!(actual.method, HttpMethod::POST);
    assert_eq!(actual.url.path(), NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1);
    assert!(actual.url.query().is_none());
    assert_eq!(actual.body, request.canonical_wire().unwrap());
    assert_eq!(
        actual.max_response_bytes,
        NATIVE_AUTHORITY_ORIGINALS_MAX_BYTES_V1
    );
    assert_eq!(result.request_wire, actual.body);
    assert_eq!(
        result.response_wire,
        norito::encode_canonical(value).unwrap()
    );
    assert_canonical_account_signed_request(&client, actual);
    let (_, derived) = native_authority_originals_request_digests_v1(&actual.body).unwrap();
    let headers = actual
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect::<std::collections::HashMap<_, _>>();
    for name in ["accept", "content-type", "x-iroha-finality-challenge"] {
        assert_eq!(
            actual
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                .count(),
            1
        );
    }
    assert_eq!(
        headers["x-iroha-finality-challenge"].as_str(),
        hex::encode(derived)
    );
    assert_ne!(
        headers["x-iroha-finality-challenge"].as_str(),
        hex::encode(request.challenge)
    );
    assert_eq!(headers["content-type"].as_str(), APPLICATION_NORITO);
    let timestamp = headers["x-iroha-timestamp-ms"].parse::<u64>().unwrap();
    let nonce = headers["x-iroha-nonce"];
    let signature = base64::engine::general_purpose::STANDARD
        .decode(headers["x-iroha-signature"])
        .unwrap();
    let mut substituted = request.clone();
    substituted.selector =
        NativeAuthorityOriginalsSelectorV1::AccountAlias("other@leumi.is2".parse().unwrap());
    let changed = Client::exact_network_request_message(
        &client.network_id,
        &actual.method,
        &actual.url,
        &substituted.canonical_wire().unwrap(),
        timestamp,
        nonce,
    )
    .unwrap();
    assert!(
        iroha_crypto::Signature::from_bytes(&signature)
            .verify(client.key_pair.public_key(), &changed)
            .is_err()
    );
    substituted = request.clone();
    substituted.challenge = [9; 32];
    let changed = Client::exact_network_request_message(
        &client.network_id,
        &actual.method,
        &actual.url,
        &substituted.canonical_wire().unwrap(),
        timestamp,
        nonce,
    )
    .unwrap();
    assert!(
        iroha_crypto::Signature::from_bytes(&signature)
            .verify(client.key_pair.public_key(), &changed)
            .is_err()
    );
    let changed = Client::exact_network_request_message(
        &client.network_id,
        &HttpMethod::GET,
        &actual.url,
        &actual.body,
        timestamp,
        nonce,
    )
    .unwrap();
    assert!(
        iroha_crypto::Signature::from_bytes(&signature)
            .verify(client.key_pair.public_key(), &changed)
            .is_err()
    );
}
#[test]
fn native_authority_provider_rejects_uncorrelated_digest_selector_and_unsigned_seed_statement() {
    let client = configured();
    let (request, value) = account_fixture();
    for index in 0..3 {
        let mut changed = value.clone();
        match index {
            0 => changed.request_sha256 = [0; 32],
            1 => {
                changed.selector = NativeAuthorityOriginalsSelectorV1::AccountAlias(
                    "other@leumi.is2".parse().unwrap(),
                )
            }
            _ => {
                changed.attestation.body.challenge = request.challenge;
                let node = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
                changed.attestation.signature = SignatureOf::try_from_hash(
                    node.private_key(),
                    changed.attestation.body.signing_hash(),
                )
                .unwrap();
            }
        }
        let (result, snapshots) = capture_requests(successful(&changed), |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
        });
        assert!(result.is_err());
        assert_eq!(snapshots.len(), 1);
    }
}
#[test]
fn native_authority_provider_refuses_zero_entropy_cleartext_prefix_and_foreign_credentials_before_io()
 {
    let client = configured();
    let (request, value) = account_fixture();
    for additions in [
        vec![("Authorization", "Bearer synthetic-fi-secret")],
        vec![("Cookie", "private")],
        vec![("Proxy-Authorization", "private")],
        vec![("X-Iroha-Finality-Challenge", "00")],
        vec![("Accept", "a"), ("accept", "b")],
        vec![("x-api-token", "a"), ("X-API-TOKEN", "b")],
    ] {
        let (result, snapshots) = capture_requests(successful(value), |transport| {
            let mut current = client.clone().with_test_http_transport(transport);
            for (k, v) in additions {
                current.headers.insert(k.into(), v.into());
            }
            current
                .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
        });
        assert!(result.is_err());
        assert!(snapshots.is_empty());
        assert!(!format!("{:#}", result.unwrap_err()).contains("synthetic-fi-secret"));
    }
    for root in [
        "http://mock.local/",
        "https://mock.local/private",
        "https://mock.local/?q=1",
        "https://mock.local/#x",
        "https://user:secret@mock.local/",
    ] {
        let (result, snapshots) = capture_requests(successful(value), |transport| {
            let mut current = client.clone().with_test_http_transport(transport);
            current.torii_url = Url::parse(root).unwrap();
            current
                .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
        });
        assert!(result.is_err());
        assert!(snapshots.is_empty());
    }
    let (result, snapshots) = capture_requests(successful(value), |transport| {
        client
            .clone()
            .with_test_http_transport(transport)
            .read_native_authority_originals_wire(request.selector.clone(), [0; 32])
    });
    assert!(result.is_err());
    assert!(snapshots.is_empty());
}
#[test]
fn native_authority_provider_refuses_redirect_noncanonical_and_private_http_error_bodies() {
    let client = configured();
    let (request, _) = account_fixture();
    for status in [
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::FORBIDDEN,
        StatusCode::OK,
    ] {
        let response = Response::builder()
            .status(status)
            .header("Content-Type", APPLICATION_NORITO)
            .body(b"private-provider-body-sentinel".to_vec())
            .unwrap();
        let (result, snapshots) = capture_requests(response, |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
        });
        assert!(result.is_err());
        assert_eq!(snapshots.len(), 1);
        assert!(!format!("{:#}", result.unwrap_err()).contains("private-provider-body-sentinel"));
    }
}
#[test]
fn native_authority_provider_normalizes_media_and_keeps_only_listener_token_context() {
    let (request, value) = account_fixture();
    let mut client = configured();
    client
        .headers
        .insert("X-API-Token".into(), "synthetic-native-listener".into());
    client
        .headers
        .insert("AcCePt".into(), APPLICATION_JSON.into());
    client
        .headers
        .insert("CONTENT-TYPE".into(), APPLICATION_JSON.into());
    let (result, snapshots) = capture_requests(successful(value), |transport| {
        client
            .clone()
            .with_test_http_transport(transport)
            .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
    });
    result.unwrap();
    let headers = &snapshots[0].headers;
    let only = |name: &str| {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(only("x-api-token"), vec!["synthetic-native-listener"]);
    assert_eq!(only("accept"), vec![APPLICATION_NORITO]);
    assert_eq!(only("content-type"), vec![APPLICATION_NORITO]);
    assert!(only("authorization").is_empty());
}
#[test]
fn native_authority_provider_refuses_duplicate_or_seed_response_header() {
    let client = configured();
    let (request, value) = account_fixture();
    let (_, derived) =
        native_authority_originals_request_digests_v1(&request.canonical_wire().unwrap()).unwrap();
    for duplicate in [false, true] {
        let mut response = successful(value);
        response.headers_mut().append(
            "X-Iroha-Finality-Challenge",
            http::HeaderValue::from_str(&hex::encode(if duplicate {
                derived
            } else {
                request.challenge
            }))
            .unwrap(),
        );
        if duplicate {
            response.headers_mut().append(
                "X-Iroha-Finality-Challenge",
                http::HeaderValue::from_str(&hex::encode(derived)).unwrap(),
            );
        }
        let (result, snapshots) = capture_requests(response, |transport| {
            client
                .clone()
                .with_test_http_transport(transport)
                .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
        });
        assert!(result.is_err());
        assert_eq!(snapshots.len(), 1);
    }
}

fn identifier_original_pair() -> (
    iroha_data_model::identifier::IdentifierPolicy,
    iroha_data_model::ram_lfe::RamLfeProgramPolicy,
) {
    use iroha_crypto::{PolicyCommitment, RamLfeBackend, RamLfeVerificationMode};
    use iroha_data_model::{
        identifier::{IdentifierNormalization, IdentifierPolicy},
        ram_lfe::RamLfeProgramPolicy,
    };
    let key = KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519);
    let owner = AccountId::new(key.public_key().clone());
    let program_id: iroha_data_model::ram_lfe::RamLfeProgramId =
        "original-program".parse().unwrap();
    let policy = IdentifierPolicy::new(
        "email#retail".parse().unwrap(),
        owner.clone(),
        IdentifierNormalization::EmailAddress,
        program_id.clone(),
    );
    let program = RamLfeProgramPolicy::new(
        program_id,
        owner,
        RamLfeBackend::HkdfSha3_512PrfV1,
        RamLfeVerificationMode::Proof,
        PolicyCommitment {
            backend: RamLfeBackend::HkdfSha3_512PrfV1,
            policy_hash: Hash::new(b"synthetic authority originals policy"),
            public_parameters: vec![3, 5, 7],
        },
        key.public_key().clone(),
    );
    (policy, program)
}

#[test]
fn native_authority_provider_carries_identifier_originals_and_refuses_cross_program_rows() {
    let client = configured();
    let (request, original) = account_fixture();
    let mut request = request.clone();
    let (policy, program) = identifier_original_pair();
    request.selector = NativeAuthorityOriginalsSelectorV1::IdentifierPolicy(policy.id.clone());
    let mut value = original.clone();
    let (digest, challenge) =
        native_authority_originals_request_digests_v1(&request.canonical_wire().unwrap()).unwrap();
    value.request_sha256 = digest;
    value.selector = request.selector.clone();
    value.attestation.body.challenge = challenge;
    let node = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
    value.attestation.signature =
        SignatureOf::try_from_hash(node.private_key(), value.attestation.body.signing_hash())
            .unwrap();
    value.originals =
        NativeAuthorityOriginalsFamilyV1::IdentifierPolicy(NativeIdentifierPolicyStateV1 {
            policy,
            program,
        });
    // Native transport validates correlation only; the application independently
    // verifies the selected originals' membership in its admitted current World.
    let (result, snapshots) = capture_requests(successful(&value), |transport| {
        client
            .clone()
            .with_test_http_transport(transport)
            .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
    });
    let result = result.unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(result.request_wire, request.canonical_wire().unwrap());
    assert_eq!(
        result.response_wire,
        norito::encode_canonical(&value).unwrap()
    );
    assert_canonical_account_signed_request(&client, &snapshots[0]);
    let NativeAuthorityOriginalsFamilyV1::IdentifierPolicy(state) = &mut value.originals else {
        unreachable!()
    };
    state.program.program_id = "foreign-program".parse().unwrap();
    let (result, snapshots) = capture_requests(successful(&value), |transport| {
        client
            .clone()
            .with_test_http_transport(transport)
            .read_native_authority_originals_wire(request.selector.clone(), request.challenge)
    });
    assert!(result.is_err());
    assert_eq!(snapshots.len(), 1);
}
