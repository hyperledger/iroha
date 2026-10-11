//! Canonical wallet load retrieval, immutable authority and asynchronous dispatch contracts.

use super::{
    Client, WireFormatPreference,
    capability_test_support::AsyncOnlyTransport,
    evidence_http_tests::{base_url, client_with_base_url},
    kagemusha::MAX_RESPONSE_BYTES,
};
use crate::{
    Error, TransportErrorKind, blocking,
    http::{Method, Response, TransportRequest},
};
use base64::Engine as _;
use iroha_crypto::{Hash, Signature};
use iroha_data_model::{
    NetworkId, isi::kagemusha_wallet::load_finality::KagemushaWalletLoadReceiptV1,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const OP: &str = "kagemusha.wallet.load_issuance.read";
const REQUEST: [u8; 32] = [3; 32];
type Requests = Arc<Mutex<Vec<TransportRequest>>>;

#[tokio::test]
async fn native_finality_read_binds_exact_receipt_and_refuses_proof_job_status() {
    use iroha_data_model::{
        kagemusha::{KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1, KagemushaWalletLoadFinalityV1},
        sumeragi_finality::SumeragiCommitCertificateV1,
    };
    let initial = client_with_base_url(base_url());
    let receipt = original(&initial.account);
    // These bytes test authenticated transport only; native BLS verification rejects them.
    let evidence = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest: receipt.receipt_digest().unwrap(),
        certificate: SumeragiCommitCertificateV1 {
            consensus_header: vec![1],
            commit_qc: vec![2],
            result_preimage: vec![3],
        },
        event_proof: iroha_crypto::MerkleProof::from_audit_path(0, vec![]),
    };
    let body = evidence.to_canonical_bytes().unwrap();
    let reply = Response::builder()
        .status(200)
        .header("content-type", "application/x-norito")
        .body(body.clone())
        .unwrap();
    let (client, requests, _) = attach(
        &initial,
        move |_| Ok(reply.clone()),
        Duration::ZERO,
        Duration::ZERO,
    );
    let actual = client
        .account_client()
        .unwrap()
        .kagemusha()
        .load_finality(&receipt)
        .await
        .unwrap();
    assert_eq!(actual, evidence);
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].url.path().ends_with("/finality"));
        assert_eq!(
            requests[0].max_response_bytes,
            KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1
        );
        assert_eq!(
            header(&requests[0], "x-iroha-account"),
            client.account.to_canonical_hex().unwrap()
        );
    }
    let mut changed = receipt;
    changed.amount += 1;
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .kagemusha()
            .load_finality(&changed)
            .await,
        Err(Error::ResponseBinding {
            field: "receipt_digest",
            ..
        })
    ));
    let reply = Response::builder()
        .status(202)
        .header("content-type", "application/x-norito")
        .body(body)
        .unwrap();
    let (client, requests, _) = attach(
        &initial,
        move |_| Ok(reply.clone()),
        Duration::ZERO,
        Duration::ZERO,
    );
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .kagemusha()
            .load_finality(&receipt)
            .await,
        Err(Error::Http { status: 202, .. })
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

fn original(payer: &iroha_data_model::account::AccountId) -> KagemushaWalletLoadReceiptV1 {
    // Transport DATA only; this fixture cannot establish consensus or authorize wallet value.
    KagemushaWalletLoadReceiptV1 {
        version: 1,
        scheme_id: [1; 32],
        asset_digest: [2; 32],
        wallet_id: [4; 32],
        request_id: REQUEST,
        ordinal: 0,
        amount: 100,
        online_charge: 0,
        charge_quote: [0; 32],
        transaction_hash: [5; 32],
        block_height: 2,
        payer_account_digest: iroha_data_model::kagemusha::kagemusha_wallet_account_digest_v1(
            payer,
        )
        .unwrap(),
    }
}

fn response(value: &KagemushaWalletLoadReceiptV1) -> Response<Vec<u8>> {
    Response::builder()
        .status(200)
        .header("content-type", "application/x-norito")
        .body(norito::to_bytes(value).unwrap())
        .unwrap()
}

fn attach(
    initial: &Client,
    responder: impl Fn(&TransportRequest) -> eyre::Result<Response<Vec<u8>>> + Send + Sync + 'static,
    delay: Duration,
    timeout: Duration,
) -> (Client, Requests, Arc<AtomicUsize>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(AsyncOnlyTransport {
        responder: Box::new(responder),
        requests: requests.clone(),
        completed: completed.clone(),
        delay,
    });
    let mut builder = initial.to_builder().http_transport(transport);
    builder.torii_request_timeout = timeout;
    builder
        .headers
        .insert("accept".to_owned(), "application/json".to_owned());
    builder
        .headers
        .insert("Content-Type".to_owned(), "application/json".to_owned());
    builder
        .headers
        .insert("X-Iroha-Account".to_owned(), "stale-account".to_owned());
    builder
        .headers
        .insert("X-Iroha-Signature".to_owned(), "stale-signature".to_owned());
    (builder.build().unwrap(), requests, completed)
}

fn header<'a>(request: &'a TransportRequest, name: &str) -> &'a str {
    let values: Vec<_> = request
        .headers
        .iter()
        .filter(|(key, _)| key.as_str() == name)
        .collect();
    assert_eq!(values.len(), 1, "one {name}");
    values[0].1.to_str().unwrap()
}

#[tokio::test]
async fn load_read_signs_exact_route_network_and_payer_and_preserves_receipt() {
    let initial = client_with_base_url(base_url());
    let expected = original(&initial.account);
    let reply = response(&expected);
    let (client, requests, _) = attach(
        &initial,
        move |_| Ok(reply.clone()),
        Duration::ZERO,
        Duration::ZERO,
    );
    for preference in [
        WireFormatPreference::JsonOnly,
        WireFormatPreference::NoritoOnly,
    ] {
        let mut builder = client.to_builder();
        builder.wire_format_preference = preference;
        let client = builder.build().unwrap();
        let actual = client
            .account_client()
            .unwrap()
            .kagemusha()
            .load_issuance(&expected.scheme_id, &expected.wallet_id, &REQUEST)
            .await
            .unwrap();
        assert_eq!(actual, expected);
    }
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.url.path(),
            format!(
                "/v1/kagemusha/{}/wallets/{}/loads/{}",
                hex::encode(expected.scheme_id),
                hex::encode(expected.wallet_id),
                hex::encode(REQUEST)
            )
        );
        assert!(request.url.query().is_none());
        assert!(request.body.is_empty());
        assert_eq!(request.max_response_bytes, MAX_RESPONSE_BYTES);
        assert_eq!(header(request, "accept"), "application/x-norito");
        assert_eq!(
            header(request, "x-iroha-account"),
            client.account.to_canonical_hex().unwrap()
        );
        assert!(
            !request
                .headers
                .iter()
                .any(|(name, _)| name.as_str() == "content-type")
        );
        let signature = Signature::try_from_bytes(
            &base64::engine::general_purpose::STANDARD
                .decode(header(request, "x-iroha-signature"))
                .unwrap(),
        )
        .unwrap();
        let timestamp = header(request, "x-iroha-timestamp-ms").parse().unwrap();
        let nonce = header(request, "x-iroha-nonce");
        let message = Client::exact_network_request_message(
            &client.network_id,
            &request.method,
            &request.url,
            &request.body,
            timestamp,
            nonce,
        )
        .unwrap();
        signature
            .verify(client.key_pair.public_key(), &message)
            .unwrap();
        let foreign = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new(b"foreign-wallet-network"),
        ));
        let message = Client::exact_network_request_message(
            &foreign,
            &request.method,
            &request.url,
            &request.body,
            timestamp,
            nonce,
        )
        .unwrap();
        assert!(
            signature
                .verify(client.key_pair.public_key(), &message)
                .is_err()
        );
        let mut altered = request.url.clone();
        altered.set_path("/v1/kagemusha/other");
        let message = Client::exact_network_request_message(
            &client.network_id,
            &request.method,
            &altered,
            &request.body,
            timestamp,
            nonce,
        )
        .unwrap();
        assert!(
            signature
                .verify(client.key_pair.public_key(), &message)
                .is_err()
        );
    }
    assert_ne!(
        header(&requests[0], "x-iroha-nonce"),
        header(&requests[1], "x-iroha-nonce")
    );
}

#[tokio::test]
async fn load_read_refuses_zero_ids_or_witness_authority_before_dispatch() {
    let (client, requests, _) = attach(
        &client_with_base_url(base_url()),
        |_| unreachable!("invalid input must not dispatch"),
        Duration::ZERO,
        Duration::ZERO,
    );
    let value = original(&client.account);
    for (scheme, wallet, request) in [
        ([0; 32], value.wallet_id, REQUEST),
        (value.scheme_id, [0; 32], REQUEST),
        (value.scheme_id, value.wallet_id, [0; 32]),
    ] {
        assert!(matches!(
            client
                .account_client()
                .unwrap()
                .kagemusha()
                .load_issuance(&scheme, &wallet, &request)
                .await,
            Err(Error::InvalidRequest { operation: OP, .. })
        ));
    }
    let mut builder = client.to_builder();
    builder
        .headers
        .insert("x-IrOhA-WiTnEsS".to_owned(), "untrusted".to_owned());
    let client = builder.build().unwrap();
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .kagemusha()
            .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST)
            .await,
        Err(Error::InvalidRequest { operation: OP, .. })
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn load_read_rejects_foreign_payer_request_wallet_and_invalid_receipt_fields() {
    let initial = client_with_base_url(base_url());
    let expected = original(&initial.account);
    for mutation in 0..10 {
        let mut changed = expected;
        match mutation {
            0 => changed.request_id[0] ^= 1,
            1 => changed.payer_account_digest[0] ^= 1,
            2 => changed.scheme_id[0] ^= 1,
            3 => changed.wallet_id[0] ^= 1,
            4 => changed.amount = 0,
            5 => changed.block_height = 0,
            6 => changed.asset_digest = [0; 32],
            7 => changed.transaction_hash = [0; 32],
            8 => changed.version = 0,
            9 => changed.online_charge = 1,
            _ => unreachable!(),
        }
        let reply = response(&changed);
        let (client, requests, _) = attach(
            &initial,
            move |_| Ok(reply.clone()),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert!(
            matches!(
                client
                    .account_client()
                    .unwrap()
                    .kagemusha()
                    .load_issuance(&expected.scheme_id, &expected.wallet_id, &REQUEST)
                    .await,
                Err(Error::ResponseBinding { operation: OP, .. })
            ),
            "mutation {mutation}"
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn load_read_requires_one_canonical_binary_frame_and_media_type() {
    let initial = client_with_base_url(base_url());
    let value = original(&initial.account);
    let mut replies = Vec::new();
    for types in [
        vec![],
        vec!["application/json"],
        vec!["application/x-norito", "application/x-norito"],
        vec!["application/x-norito, application/json"],
    ] {
        let mut reply = response(&value);
        reply.headers_mut().remove("content-type");
        for media in types {
            reply
                .headers_mut()
                .append("content-type", media.parse().unwrap());
        }
        replies.push(reply);
    }
    for bytes in [
        vec![],
        vec![0xff],
        [norito::to_bytes(&value).unwrap(), vec![0]].concat(),
    ] {
        let mut reply = response(&value);
        *reply.body_mut() = bytes;
        replies.push(reply);
    }
    for reply in replies {
        let (client, requests, _) = attach(
            &initial,
            move |_| Ok(reply.clone()),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert!(matches!(
            client
                .account_client()
                .unwrap()
                .kagemusha()
                .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST)
                .await,
            Err(Error::Decode { operation: OP, .. } | Error::CanonicalDecode { operation: OP, .. })
        ));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn load_read_preserves_http_transport_and_capacity_failures_without_replaying() {
    let initial = client_with_base_url(base_url());
    let value = original(&initial.account);
    for status in [401, 403, 404, 429, 503] {
        let (client, requests, _) = attach(
            &initial,
            move |_| {
                Ok(Response::builder()
                    .status(status)
                    .header("retry-after", "7")
                    .body(b"unavailable-issuance".to_vec())
                    .unwrap())
            },
            Duration::ZERO,
            Duration::ZERO,
        );
        let error = client
            .account_client()
            .unwrap()
            .kagemusha()
            .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST)
            .await
            .unwrap_err();
        assert!(
            matches!(error,Error::Http{operation:OP,status:actual,body,..} if actual==status && body==b"unavailable-issuance")
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
    let (client, requests, _) = attach(
        &initial,
        |_| Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into()),
        Duration::ZERO,
        Duration::ZERO,
    );
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .kagemusha()
            .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST)
            .await,
        Err(Error::Transport {
            operation: OP,
            kind: TransportErrorKind::Io(std::io::ErrorKind::ConnectionRefused),
            ..
        })
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
    for status in [200, 503] {
        let (client, requests, _) = attach(
            &initial,
            move |_| {
                Ok(Response::builder()
                    .status(status)
                    .body(vec![0; MAX_RESPONSE_BYTES + 1])
                    .unwrap())
            },
            Duration::ZERO,
            Duration::ZERO,
        );
        assert!(matches!(
            client
                .account_client()
                .unwrap()
                .kagemusha()
                .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST)
                .await,
            Err(Error::ResponseTooLarge {
                maximum: MAX_RESPONSE_BYTES,
                ..
            })
        ));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn load_read_obeys_absolute_deadline_and_cancels_pending_async_dispatch() {
    let initial = client_with_base_url(base_url());
    let value = original(&initial.account);
    let reply = response(&value);
    let (client, requests, completed) = attach(
        &initial,
        move |_| Ok(reply.clone()),
        Duration::from_secs(60),
        Duration::from_millis(10),
    );
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .kagemusha()
            .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST)
            .await,
        Err(Error::Timeout { operation: OP })
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    let client =
        client.with_request_deadline(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .kagemusha()
            .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST)
            .await,
        Err(Error::Timeout { operation: OP })
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn blocking_load_read_reuses_owned_runtime_and_rejects_nested_async_entry() {
    let initial = client_with_base_url(base_url());
    let value = original(&initial.account);
    let reply = response(&value);
    let (client, requests, _) = attach(
        &initial,
        move |_| Ok(reply.clone()),
        Duration::ZERO,
        Duration::ZERO,
    );
    let account = blocking::AccountClient::from_client(client.account_client().unwrap()).unwrap();
    assert_eq!(
        account
            .kagemusha()
            .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST)
            .unwrap(),
        value
    );
    assert_eq!(
        account
            .clone()
            .kagemusha()
            .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST)
            .unwrap(),
        value
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(matches!(
            account
                .kagemusha()
                .load_issuance(&value.scheme_id, &value.wallet_id, &REQUEST),
            Err(Error::Blocking(_))
        ));
        drop(account);
    });
    assert_eq!(requests.lock().unwrap().len(), 2);
}

mod finality;
mod finality_transport;
