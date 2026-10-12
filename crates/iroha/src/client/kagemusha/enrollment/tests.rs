//! Exact enrollment HTTP authentication, action binding, recovery originals and failure bounds.

use super::*;
use crate::{
    blocking,
    client::{
        WireFormatPreference,
        capability_test_support::AsyncOnlyTransport,
        evidence_http_tests::{base_url, client_with_base_url},
    },
    http::{Response as HttpResponse, TransportRequest},
};
use base64::Engine as _;
use iroha_crypto::{Hash, Signature};
use iroha_data_model::NetworkId;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

type Requests = Arc<Mutex<Vec<TransportRequest>>>;

fn request(action: Action) -> EnrollmentServiceRequestV1 {
    // Opaque transport DATA only; these bytes grant no native enrollment authority.
    EnrollmentServiceRequestV1 {
        version: 1,
        action,
        dispatch_original: vec![1, 2, 3],
        evidence_original: if action == Action::Evidence {
            vec![4, 5, 6]
        } else {
            vec![]
        },
    }
}
fn response(value: &Response) -> HttpResponse<Vec<u8>> {
    HttpResponse::builder()
        .status(200)
        .header("content-type", MIME)
        .body(value.canonical_wire().unwrap())
        .unwrap()
}
fn attach(
    reply: HttpResponse<Vec<u8>>,
    delay: Duration,
    timeout: Duration,
) -> (Client, Requests, Arc<AtomicUsize>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(AsyncOnlyTransport {
        responder: Box::new(move |_| Ok(reply.clone())),
        requests: requests.clone(),
        completed: completed.clone(),
        delay,
    });
    let mut builder = client_with_base_url(base_url())
        .to_builder()
        .http_transport(transport);
    builder.torii_request_timeout = timeout;
    for (name, value) in [
        ("Accept", "application/json"),
        ("Content-Type", "application/json"),
        ("X-Iroha-Account", "stale-account"),
        ("X-Iroha-Signature", "stale-signature"),
    ] {
        builder.headers.insert(name.into(), value.into());
    }
    (builder.build().unwrap(), requests, completed)
}
fn header<'a>(request: &'a TransportRequest, name: &str) -> &'a str {
    let values: Vec<_> = request
        .headers
        .iter()
        .filter(|(key, _)| key.as_str() == name)
        .collect();
    assert_eq!(values.len(), 1);
    values[0].1.to_str().unwrap()
}

#[tokio::test]
async fn signs_complete_action_and_originals_for_the_exact_account_network_route() {
    for (action, expected) in [
        (Action::PreKey, Response::Permit(vec![7, 8])),
        (Action::Evidence, Response::EvidenceReady),
        (Action::Evidence, Response::Pending),
        (Action::Issue, Response::CredentialReady),
        (Action::Deliver, Response::Credential(vec![9, 10])),
    ] {
        let value = request(action);
        let (client, requests, _) = attach(response(&expected), Duration::ZERO, Duration::ZERO);
        for preference in [
            WireFormatPreference::JsonOnly,
            WireFormatPreference::NoritoOnly,
        ] {
            let mut builder = client.to_builder();
            builder.wire_format_preference = preference;
            let client = builder.build().unwrap();
            assert_eq!(
                client
                    .account_client()
                    .unwrap()
                    .kagemusha()
                    .enrollment(&value)
                    .await
                    .unwrap(),
                expected
            );
        }
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].body, requests[1].body,
            "recovery keeps native originals"
        );
        assert_ne!(
            header(&requests[0], "x-iroha-nonce"),
            header(&requests[1], "x-iroha-nonce")
        );
        for sent in requests.iter() {
            assert_eq!(sent.method, Method::POST);
            assert_eq!(sent.url.path(), ENROLLMENT_SERVICE_ROUTE_V1);
            assert!(sent.url.query().is_none());
            assert_eq!(sent.body, value.canonical_wire().unwrap());
            assert_eq!(
                sent.max_response_bytes,
                ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1
            );
            assert_eq!(header(sent, "accept"), MIME);
            assert_eq!(header(sent, "content-type"), MIME);
            assert_eq!(
                header(sent, "x-iroha-account"),
                client.account.to_canonical_hex().unwrap()
            );
            let signature = Signature::try_from_bytes(
                &base64::engine::general_purpose::STANDARD
                    .decode(header(sent, "x-iroha-signature"))
                    .unwrap(),
            )
            .unwrap();
            let timestamp = header(sent, "x-iroha-timestamp-ms").parse().unwrap();
            let nonce = header(sent, "x-iroha-nonce");
            let message = Client::exact_network_request_message(
                &client.network_id,
                &sent.method,
                &sent.url,
                &sent.body,
                timestamp,
                nonce,
            )
            .unwrap();
            signature
                .verify(client.key_pair.public_key(), &message)
                .unwrap();
            for mutation in 0..5 {
                let mut network = client.network_id;
                let mut method = sent.method.clone();
                let mut url = sent.url.clone();
                let mut altered = value.clone();
                match mutation {
                    0 => {
                        network = NetworkId::from_genesis_hash(
                            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                                b"foreign-enrollment",
                            )),
                        )
                    }
                    1 => method = Method::GET,
                    2 => url.set_path("/v1/kagemusha/other"),
                    3 => {
                        altered.action = if action == Action::PreKey {
                            Action::Issue
                        } else {
                            Action::PreKey
                        };
                        altered.evidence_original.clear();
                    }
                    _ => altered.dispatch_original[0] ^= 1,
                }
                let message = Client::exact_network_request_message(
                    &network,
                    &method,
                    &url,
                    &altered.canonical_wire().unwrap(),
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
        }
    }
}

#[tokio::test]
async fn rejects_invalid_request_and_witness_before_transport() {
    let (client, requests, _) =
        attach(response(&Response::Pending), Duration::ZERO, Duration::ZERO);
    for mutation in 0..5 {
        let mut value = request(Action::PreKey);
        match mutation {
            0 => value.version = 2,
            1 => value.dispatch_original.clear(),
            2 => value.evidence_original.push(1),
            3 => value.action = Action::Evidence,
            _ => {
                value.dispatch_original = vec![
                    0;
                    iroha_torii_shared::kagemusha_enrollment::ENROLLMENT_DISPATCH_MAX_BYTES_V1
                        + 1
                ]
            }
        }
        assert!(matches!(
            client
                .account_client()
                .unwrap()
                .kagemusha()
                .enrollment(&value)
                .await,
            Err(Error::InvalidRequest { operation: OP, .. })
        ));
    }
    let mut builder = client.to_builder();
    builder
        .headers
        .insert("x-Iroha-Witness".into(), "untrusted".into());
    assert!(matches!(
        builder
            .build()
            .unwrap()
            .account_client()
            .unwrap()
            .kagemusha()
            .enrollment(&request(Action::PreKey))
            .await,
        Err(Error::InvalidRequest { operation: OP, .. })
    ));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_every_response_for_another_action() {
    for action in [
        Action::PreKey,
        Action::Evidence,
        Action::Issue,
        Action::Deliver,
    ] {
        for reply in [
            Response::Permit(vec![1]),
            Response::EvidenceReady,
            Response::Pending,
            Response::CredentialReady,
            Response::Credential(vec![2]),
        ] {
            let allowed = matches!(
                (action, &reply),
                (Action::PreKey, Response::Permit(_))
                    | (
                        Action::Evidence,
                        Response::EvidenceReady | Response::Pending
                    )
                    | (Action::Issue, Response::CredentialReady)
                    | (Action::Deliver, Response::Credential(_))
            );
            if allowed {
                continue;
            }
            let (client, requests, _) = attach(response(&reply), Duration::ZERO, Duration::ZERO);
            assert!(matches!(
                client
                    .account_client()
                    .unwrap()
                    .kagemusha()
                    .enrollment(&request(action))
                    .await,
                Err(Error::ResponseBinding {
                    operation: OP,
                    field: "enrollment action"
                })
            ));
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn rejects_invalid_response_frames_original_bounds_and_media_types() {
    let good = response(&Response::Permit(vec![1]));
    let mut replies = Vec::new();
    for types in [
        vec![],
        vec!["application/json"],
        vec![MIME, MIME],
        vec!["application/x-norito,application/json"],
    ] {
        let mut reply = good.clone();
        reply.headers_mut().remove("content-type");
        for value in types {
            reply
                .headers_mut()
                .append("content-type", value.parse().unwrap());
        }
        replies.push(reply);
    }
    for original in [
        vec![],
        vec![0xff],
        [good.body().clone(), vec![0]].concat(),
        norito::encode_canonical(&Response::Permit(vec![])).unwrap(),
        norito::encode_canonical(&Response::Permit(vec![0; 2049])).unwrap(),
    ] {
        let mut reply = good.clone();
        *reply.body_mut() = original;
        replies.push(reply);
    }
    for reply in replies {
        let (client, requests, _) = attach(reply, Duration::ZERO, Duration::ZERO);
        let error = client
            .account_client()
            .unwrap()
            .kagemusha()
            .enrollment(&request(Action::PreKey))
            .await
            .expect_err("malformed enrollment response");
        assert!(
            matches!(&error, Error::Decode { operation: OP, .. })
                || matches!(&error, Error::CanonicalDecode(failure) if failure.operation == OP)
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn identical_statuses_relay_distinct_typed_enrollment_outcomes() {
    use iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1 as Refusal;
    use iroha_torii_shared::kagemusha_enrollment::{
        ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1, ENROLLMENT_OUTCOME_HEADER_V1,
        ENROLLMENT_REFUSAL_CODE_HEADER_V1,
    };
    for (status, name, value, expected) in [
        (
            403,
            ENROLLMENT_REFUSAL_CODE_HEADER_V1,
            "12",
            Some(EnrollmentServiceOutcomeV1::Refused(Refusal::AccountFrozen)),
        ),
        (
            403,
            ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1,
            "12",
            Some(EnrollmentServiceOutcomeV1::DeliveryWithheld(
                Refusal::AccountFrozen,
            )),
        ),
        (
            403,
            ENROLLMENT_REFUSAL_CODE_HEADER_V1,
            "3",
            Some(EnrollmentServiceOutcomeV1::Refused(
                Refusal::from_code(3).unwrap(),
            )),
        ),
        (
            409,
            ENROLLMENT_OUTCOME_HEADER_V1,
            "unknown",
            Some(EnrollmentServiceOutcomeV1::OutcomeUnknown),
        ),
        // A malformed or status-inconsistent outcome is a decode failure, never generic HTTP.
        (403, ENROLLMENT_REFUSAL_CODE_HEADER_V1, "13", None),
        (403, ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1, "4", None),
        (503, ENROLLMENT_OUTCOME_HEADER_V1, "unknown", None),
    ] {
        let reply = HttpResponse::builder()
            .status(status)
            .header(name, value)
            .body(b"enrollment operation unavailable or rejected".to_vec())
            .unwrap();
        let (client, requests, _) = attach(reply, Duration::ZERO, Duration::ZERO);
        let result = client
            .account_client()
            .unwrap()
            .kagemusha()
            .enrollment(&request(Action::Deliver))
            .await;
        match expected {
            Some(expected) => assert!(
                matches!(result, Err(Error::EnrollmentOutcome { operation: OP, outcome }) if outcome == expected),
                "{name}: {value}"
            ),
            None => assert!(
                matches!(result, Err(Error::Decode { operation: OP, .. })),
                "{name}: {value}"
            ),
        }
        assert_eq!(requests.lock().unwrap().len(), 1, "never retried");
    }
    // A successful body carrying any outcome header, valid or malformed, is never success.
    for (name, value) in [
        (ENROLLMENT_REFUSAL_CODE_HEADER_V1, "12"),
        (ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1, "11"),
        (ENROLLMENT_OUTCOME_HEADER_V1, "unknown"),
        (ENROLLMENT_REFUSAL_CODE_HEADER_V1, "x"),
    ] {
        let mut reply = response(&Response::Credential(vec![9, 10]));
        reply
            .headers_mut()
            .insert(name, http::HeaderValue::from_static(value));
        let (client, _, _) = attach(reply, Duration::ZERO, Duration::ZERO);
        assert!(
            matches!(
                client
                    .account_client()
                    .unwrap()
                    .kagemusha()
                    .enrollment(&request(Action::Deliver))
                    .await,
                Err(Error::Decode { operation: OP, .. })
            ),
            "{name}: {value}"
        );
    }
    let mut reply = response(&Response::Credential(vec![9, 10]));
    for _ in 0..2 {
        reply.headers_mut().append(
            ENROLLMENT_OUTCOME_HEADER_V1,
            http::HeaderValue::from_static("unknown"),
        );
    }
    let (client, _, _) = attach(reply, Duration::ZERO, Duration::ZERO);
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .kagemusha()
            .enrollment(&request(Action::Deliver))
            .await,
        Err(Error::Decode { operation: OP, .. })
    ));
}

#[tokio::test]
async fn unavailable_and_oversized_responses_never_replay() {
    for status in [401, 403, 404, 429, 503] {
        let reply = HttpResponse::builder()
            .status(status)
            .header("retry-after", "7")
            .body(b"unavailable".to_vec())
            .unwrap();
        let (client, requests, _) = attach(reply, Duration::ZERO, Duration::ZERO);
        assert!(
            matches!(client.account_client().unwrap().kagemusha().enrollment(&request(Action::Evidence)).await,
            Err(Error::Http { operation: OP, status: actual, body, .. }) if actual == status && body == b"unavailable")
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
    for status in [200, 503] {
        let reply = HttpResponse::builder()
            .status(status)
            .body(vec![0; ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1 + 1])
            .unwrap();
        let (client, requests, _) = attach(reply, Duration::ZERO, Duration::ZERO);
        assert!(matches!(
            client
                .account_client()
                .unwrap()
                .kagemusha()
                .enrollment(&request(Action::PreKey))
                .await,
            Err(Error::ResponseTooLarge {
                maximum: ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1,
                ..
            })
        ));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn deadline_cancels_pending_transport_without_restarting_attempt() {
    let (client, requests, completed) = attach(
        response(&Response::Pending),
        Duration::from_secs(60),
        Duration::from_millis(10),
    );
    assert!(matches!(
        client
            .account_client()
            .unwrap()
            .kagemusha()
            .enrollment(&request(Action::Evidence))
            .await,
        Err(Error::Timeout { operation: OP })
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    let expired =
        client.with_request_deadline(Instant::now().checked_sub(Duration::from_secs(1)).unwrap());
    assert!(matches!(
        expired
            .account_client()
            .unwrap()
            .kagemusha()
            .enrollment(&request(Action::Evidence))
            .await,
        Err(Error::Timeout { operation: OP })
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn blocking_enrollment_uses_owned_runtime_and_rejects_async_reentry() {
    let (client, requests, _) =
        attach(response(&Response::Pending), Duration::ZERO, Duration::ZERO);
    let account = blocking::AccountClient::from_client(client.account_client().unwrap()).unwrap();
    let value = request(Action::Evidence);
    assert_eq!(
        account.kagemusha().enrollment(&value).unwrap(),
        Response::Pending
    );
    assert_eq!(
        account.kagemusha().enrollment(&value).unwrap(),
        Response::Pending
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(matches!(
            account.kagemusha().enrollment(&value),
            Err(Error::Blocking(_))
        ));
    });
    assert_eq!(requests.lock().unwrap().len(), 2);
}
