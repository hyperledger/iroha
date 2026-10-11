// Canonical Nexus committee observations; finality authorization stays with its verifier.
mod validator_committee_capability {
    use super::*;
    use crate::{
        Error,
        client::capability_test_support::{AsyncOnlyTransport, GatedTransport, TransportGate},
    };
    use iroha_data_model::nexus::ValidatorCommitteeStatusV1;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn status_fixture() -> ValidatorCommitteeStatusV1 {
        use crate::crypto::{Algorithm, KeyPair};
        use iroha_data_model::nexus::ValidatorCommitteeStatusV1;
        use iroha_data_model::{
            block::builder::BlockBuilder,
            sumeragi::finality::{NativeFinalityArtifact, NativeFinalityLimits},
        };
        // This is an HTTP carrier fixture, not a finality fixture: no QC is fabricated.
        // Authorization tests use the complete native journal consumer in Core.
        let key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let transaction = TransactionBuilder::new(
            test_network_id(),
            AccountId::new(key.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .try_sign(key.private_key())
        .unwrap();
        let mut builder = BlockBuilder::new(BlockHeader::new(
            NonZeroU64::new(2).unwrap(),
            Some(HashOf::from_untyped_unchecked(Hash::new(
                b"transport predecessor",
            ))),
            None,
            10,
            0,
        ));
        builder.push_transaction(transaction);
        let block = builder
            .try_build_with_signature(0, key.private_key())
            .unwrap();
        let artifact = NativeFinalityArtifact::from_block(
            &block,
            NativeFinalityLimits {
                block_bytes: 16 * 1024 * 1024,
                journal_bytes: 16 * 1024 * 1024,
                block_count: 256,
                allocated_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        ValidatorCommitteeStatusV1 {
            network_id: test_network_id(),
            target_epoch: 7,
            latest_finality: artifact,
            selected: None,
            pending_beacon_session: None,
        }
    }

    fn attach(
        responder: impl Fn(&crate::http::TransportRequest) -> Result<Response<Vec<u8>>>
        + Send
        + Sync
        + 'static,
        delay: Duration,
        timeout: Duration,
    ) -> (
        Client,
        Arc<Mutex<Vec<crate::http::TransportRequest>>>,
        Arc<AtomicUsize>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let completed = Arc::new(AtomicUsize::new(0));
        let transport = Arc::new(AsyncOnlyTransport {
            responder: Box::new(responder),
            requests: requests.clone(),
            completed: completed.clone(),
            delay,
        });
        let mut builder = client_with_base_url(base_url())
            .to_builder()
            .http_transport(transport);
        builder.network_id = test_network_id();
        builder.torii_request_timeout = timeout;
        (builder.build().unwrap(), requests, completed)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canonical_observation_binds_route_target_and_preserves_executor_progress() {
        fn require_send(_: impl Send) {}
        let status = status_fixture();
        let fixture = norito_response(StatusCode::OK, &status);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let completed = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(TransportGate::default());
        let transport = Arc::new(GatedTransport {
            inner: AsyncOnlyTransport {
                responder: Box::new(move |_| Ok(fixture.clone())),
                requests: requests.clone(),
                completed: completed.clone(),
                delay: Duration::ZERO,
            },
            gate: gate.clone(),
        });
        let mut builder = client_with_base_url(base_url())
            .to_builder()
            .http_transport(transport);
        builder.network_id = test_network_id();
        builder.torii_request_timeout = Duration::ZERO;
        let client = builder.build().unwrap();
        let nexus = client.nexus();
        require_send(nexus.validator_committee(Some(7)));
        let operation = nexus.validator_committee(Some(7));
        tokio::pin!(operation);
        tokio::select! {
            early = &mut operation => panic!("operation completed before transport release: {early:?}"),
            () = gate.wait_until_entered() => {}
        }
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "transport cannot finish before release"
        );
        gate.release();
        let result = operation.await;
        assert_eq!(result.unwrap(), status);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, HttpMethod::GET);
        assert_eq!(request.url.path(), "/v1/nexus/validator-committee");
        assert_eq!(request.url.query(), Some("target_epoch=7"));
        assert!(request.body.is_empty());
        assert_eq!(request.max_response_bytes, 16 * 1024 * 1024);
        let accepts: Vec<_> = request
            .headers
            .iter()
            .filter(|(name, _)| name == http::header::ACCEPT)
            .collect();
        assert_eq!(accepts.len(), 1);
        assert_eq!(accepts[0].1, APPLICATION_NORITO);
        assert_eq!(request.timeout, None);
    }

    #[tokio::test]
    async fn rejects_unbound_noncanonical_and_wrong_media_observations() {
        for mutation in 0..6 {
            let mut status = status_fixture();
            match mutation {
                0 => status.target_epoch = 8,
                1 => {
                    status.network_id = NetworkId::from_genesis_hash(
                        HashOf::from_untyped_unchecked(Hash::new(b"foreign committee network")),
                    )
                }
                4 => status.latest_finality.block_wire.push(0),
                5 => status.target_epoch = 0,
                _ => {}
            }
            let (client, _, _) = attach(
                move |_| {
                    Ok(match mutation {
                        2 => {
                            json_response(StatusCode::OK, &norito::json::to_json(&status).unwrap())
                        }
                        3 => empty_response(StatusCode::NOT_FOUND),
                        _ => norito_response(StatusCode::OK, &status),
                    })
                },
                Duration::ZERO,
                Duration::from_secs(1),
            );
            let error = client
                .nexus()
                .validator_committee(Some(7))
                .await
                .unwrap_err();
            assert!(
                match mutation {
                    0 | 1 | 5 => matches!(error, Error::ResponseBinding { .. }),
                    2 => matches!(error, Error::Decode { .. }),
                    4 => matches!(&error, Error::NativeFinalityDecode {
                        source: iroha_data_model::sumeragi::finality::NativeFinalityDecodeError::Malformed(source), ..
                    } if source.kind() == norito::core::DecodeAttemptErrorKind::Invalid),
                    3 => matches!(error, Error::Http { status: 404, .. }),
                    _ => unreachable!(),
                },
                "wrong error for mutation {mutation}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn zero_target_epoch_is_rejected_before_dispatch() {
        let (client, requests, _) = attach(
            |_| Ok(empty_response(StatusCode::NOT_FOUND)),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert!(matches!(
            client.nexus().validator_committee(Some(0)).await,
            Err(Error::InvalidRequest { .. })
        ));
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn omitted_epoch_remains_a_server_selected_observation() {
        let mut status = status_fixture();
        status.target_epoch = 1;
        let fixture = status.clone();
        let (client, requests, _) = attach(
            move |_| Ok(norito_response(StatusCode::OK, &fixture)),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert_eq!(
            client.nexus().validator_committee(None).await.unwrap(),
            status
        );
        assert!(requests.lock().unwrap()[0].url.query().is_none());
    }

    #[tokio::test]
    async fn retains_http_error_body_and_retry_after_without_replay() {
        let (client, requests, _) = attach(
            |_| {
                Ok(Response::builder()
                    .status(429)
                    .header("Retry-After", "3")
                    .body(b"capacity".to_vec())
                    .unwrap())
            },
            Duration::ZERO,
            Duration::ZERO,
        );
        {
            let actual_error = client.nexus().validator_committee(None).await.unwrap_err();
            let Error::Http {
                operation: actual_operation,
                status: actual_status,
                retry_after: actual_retry_after,
                body: actual_body,
            } = &actual_error
            else {
                panic!("unexpected SDK error: {actual_error:?}");
            };
            assert_eq!(
                (
                    actual_operation,
                    actual_status,
                    actual_retry_after,
                    actual_body,
                ),
                (
                    &("nexus.validator_committee.read"),
                    &(429),
                    &(Some(Duration::from_secs(3))),
                    &(b"capacity".to_vec()),
                )
            );
        };
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn injected_response_cannot_exceed_the_transport_bound() {
        let (client, requests, _) = attach(
            |_| {
                Ok(Response::builder()
                    .status(200)
                    .header("Content-Type", APPLICATION_NORITO)
                    .body(vec![0; 16 * 1024 * 1024 + 1])
                    .unwrap())
            },
            Duration::ZERO,
            Duration::ZERO,
        );
        assert!(matches!(
            client.nexus().validator_committee(None).await.unwrap_err(),
            Error::ResponseTooLarge {
                maximum: 16_777_216,
                actual: Some(16_777_217)
            }
        ));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn request_deadline_cancels_pending_transport_and_expired_context_never_sends() {
        let (client, requests, completed) = attach(
            |_| Ok(empty_response(StatusCode::NOT_FOUND)),
            Duration::from_secs(60),
            Duration::from_millis(10),
        );
        {
            let actual_error = client.nexus().validator_committee(None).await.unwrap_err();
            let Error::Timeout {
                operation: actual_operation,
            } = &actual_error
            else {
                panic!("unexpected SDK error: {actual_error:?}");
            };
            assert_eq!((actual_operation,), (&("nexus.validator_committee.read"),));
        };
        assert_eq!(requests.lock().unwrap().len(), 1);
        assert_eq!(completed.load(Ordering::SeqCst), 0);
        let client = client.with_request_deadline(std::time::Instant::now());
        {
            let actual_error = client.nexus().validator_committee(None).await.unwrap_err();
            let Error::Timeout {
                operation: actual_operation,
            } = &actual_error
            else {
                panic!("unexpected SDK error: {actual_error:?}");
            };
            assert_eq!((actual_operation,), (&("nexus.validator_committee.read"),));
        };
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn blocking_facade_rejects_async_entry_without_dispatch() {
        let (client, requests, _) = attach(
            |_| Ok(empty_response(StatusCode::NOT_FOUND)),
            Duration::ZERO,
            Duration::ZERO,
        );
        let client = crate::blocking::Client::from_client(client).unwrap();
        assert!(matches!(
            client.nexus().validator_committee(None),
            Err(Error::Blocking(_))
        ));
        assert!(requests.lock().unwrap().is_empty());
    }

    #[test]
    fn blocking_facade_reuses_its_owned_runtime_and_the_same_async_operation() {
        let status = status_fixture();
        let fixture = status.clone();
        let (client, requests, _) = attach(
            move |_| Ok(norito_response(StatusCode::OK, &fixture)),
            Duration::ZERO,
            Duration::ZERO,
        );
        let client = crate::blocking::Client::from_client(client).unwrap();
        for _ in 0..2 {
            assert_eq!(client.nexus().validator_committee(Some(7)).unwrap(), status);
        }
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
    fn allocation_limit(bytes: usize) -> norito::DecodeLimits {
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
    }

    fn original_decode(error: &Error) -> &norito::core::DecodeAttemptError {
        use iroha_data_model::sumeragi::finality::NativeFinalityDecodeError;
        match error {
            Error::CanonicalDecode { source, .. }
            | Error::NativeFinalityDecode {
                source:
                    NativeFinalityDecodeError::Resource(source)
                    | NativeFinalityDecodeError::Malformed(source),
                ..
            } => source,
            other => panic!("expected original decode attempt: {other:?}"),
        }
    }

    fn original_scope(error: &Error) -> norito::core::ScopedDecodeResourceError {
        let source = std::error::Error::source(original_decode(error)).unwrap();
        let norito::Error::ScopedDecodeResource(original) =
            source.downcast_ref::<norito::Error>().unwrap()
        else {
            panic!("refusal must retain the actual enclosing scope: {source:?}");
        };
        original.clone()
    }

    #[test]
    fn canonical_response_keeps_original_scope_through_query_and_dispatch_contexts() {
        use norito::core::{DecodeAttemptErrorKind, with_decode_limits_scope};
        let expected = status_fixture();
        let response = norito_response(StatusCode::OK, &expected);
        let before = response.body().clone();
        let failure = with_decode_limits_scope(allocation_limit(0), || {
            Client::decode_canonical_norito_response::<ValidatorCommitteeStatusV1>(
                &response,
                16 * 1024 * 1024,
                "nexus.validator_committee.read",
            )
        })
        .unwrap_err();
        assert_eq!(
            original_decode(&failure).kind(),
            DecodeAttemptErrorKind::EnclosingLimit
        );
        let original = original_scope(&failure);
        let query = crate::query::QueryError::from(failure);
        let reported = eyre::Report::new(query).wrap_err("exact query context");
        assert!(
            reported.chain().any(|cause| {
                cause
                    .downcast_ref::<norito::core::DecodeAttemptError>()
                    .is_some_and(|attempt| attempt.kind() == DecodeAttemptErrorKind::EnclosingLimit)
            }),
            "QueryError exposes the original typed source, not only a display message"
        );
        let query = reported.downcast::<crate::query::QueryError>().unwrap();
        let crate::query::QueryError::Sdk(failure) = query else {
            panic!("preserve SDK error owner");
        };
        let failure = dispatch::transport_error(
            "another.operation",
            eyre::Report::new(failure)
                .wrap_err("inner dispatch context")
                .wrap_err("outer dispatch context"),
        );
        assert_eq!(
            original_decode(&failure).kind(),
            DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(
            original_scope(&failure),
            original,
            "same opaque original scope, not reconstructed limits"
        );
        assert!(matches!(
            &failure,
            Error::CanonicalDecode {
                operation: "nexus.validator_committee.read",
                ..
            }
        ));
        let observed: ValidatorCommitteeStatusV1 = Client::decode_canonical_norito_response(
            &response,
            16 * 1024 * 1024,
            "nexus.validator_committee.read",
        )
        .unwrap();
        assert_eq!(observed, expected);
        assert_eq!(
            response.body(),
            &before,
            "retry the same original canonical response"
        );

        let malformed = Response::builder()
            .status(200)
            .header("Content-Type", APPLICATION_NORITO)
            .body(b"NRT0".to_vec())
            .unwrap();
        let failure = with_decode_limits_scope(allocation_limit(0), || {
            Client::decode_canonical_norito_response::<ValidatorCommitteeStatusV1>(
                &malformed,
                16 * 1024 * 1024,
                "nexus.validator_committee.read",
            )
        })
        .unwrap_err();
        assert_eq!(
            original_decode(&failure).kind(),
            DecodeAttemptErrorKind::Invalid,
            "intrinsically malformed frame does not become local refusal"
        );
    }

    #[test]
    fn committee_operation_preserves_outer_and_native_refusal_then_retries_unchanged_bytes() {
        use iroha_data_model::sumeragi::finality::NativeFinalityDecodeError;
        use norito::core::{DecodeAttemptErrorKind, with_decode_limits_scope};
        let expected = status_fixture();
        let response = norito_response(StatusCode::OK, &expected);
        let original_bytes = response.body().clone();
        // Measure the genuine outer DTO's minimum admission. That exact cumulative
        // allowance admits the outer response and refuses the subsequent native block.
        let outer_read = |limit| {
            with_decode_limits_scope(allocation_limit(limit), || {
                Client::decode_canonical_norito_response::<ValidatorCommitteeStatusV1>(
                    &response,
                    16 * 1024 * 1024,
                    "nexus.validator_committee.read",
                )
            })
        };
        let mut low = 0;
        let mut high = 64 * 1024 * 1024;
        assert_eq!(outer_read(high).unwrap(), expected);
        while low < high {
            let middle = low + (high - low) / 2;
            match outer_read(middle) {
                Ok(value) => {
                    assert_eq!(value, expected);
                    high = middle;
                }
                Err(error) => {
                    assert_eq!(
                        original_decode(&error).kind(),
                        DecodeAttemptErrorKind::EnclosingLimit
                    );
                    low = middle + 1;
                }
            }
        }
        assert!(low > 0);
        assert_eq!(outer_read(low).unwrap(), expected);
        assert_eq!(
            original_decode(&outer_read(low - 1).unwrap_err()).kind(),
            DecodeAttemptErrorKind::EnclosingLimit
        );
        let (client, requests, _) = attach(
            move |_| Ok(response.clone()),
            Duration::ZERO,
            Duration::ZERO,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outer = with_decode_limits_scope(allocation_limit(0), || {
            runtime.block_on(client.nexus().validator_committee(Some(7)))
        })
        .unwrap_err();
        assert!(matches!(&outer, Error::CanonicalDecode { .. }));
        assert_eq!(
            original_decode(&outer).kind(),
            DecodeAttemptErrorKind::EnclosingLimit
        );
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "local refusal never causes an automatic retry"
        );
        let native = with_decode_limits_scope(allocation_limit(low), || {
            runtime.block_on(client.nexus().validator_committee(Some(7)))
        })
        .unwrap_err();
        assert!(matches!(
            &native,
            Error::NativeFinalityDecode {
                source: NativeFinalityDecodeError::Resource(_),
                ..
            }
        ));
        assert_eq!(
            original_decode(&native).kind(),
            DecodeAttemptErrorKind::EnclosingLimit
        );
        let original = original_scope(&native);
        let moved = dispatch::transport_error(
            "another.operation",
            eyre::Report::new(native).wrap_err("native context"),
        );
        assert_eq!(original_scope(&moved), original);
        assert_eq!(requests.lock().unwrap().len(), 2);
        assert_eq!(
            runtime
                .block_on(client.nexus().validator_committee(Some(7)))
                .unwrap(),
            expected
        );
        assert_eq!(
            requests.lock().unwrap().len(),
            3,
            "only the explicit unchanged operation retries"
        );
        assert_eq!(norito::encode_canonical(&expected).unwrap(), original_bytes);
    }

    #[test]
    fn canonical_response_admission_preserves_predecode_media_body_and_status_checks() {
        use norito::core::with_decode_limits_scope;
        let canonical = norito_response(StatusCode::OK, &status_fixture()).into_body();
        for (status, media, body, maximum, expected) in [
            (
                200,
                vec![APPLICATION_NORITO],
                canonical.clone(),
                canonical.len() - 1,
                "exceeds",
            ),
            (
                404,
                vec![APPLICATION_NORITO],
                canonical.clone(),
                canonical.len(),
                "404",
            ),
            (
                200,
                vec![APPLICATION_NORITO, APPLICATION_NORITO],
                canonical.clone(),
                canonical.len(),
                "multiple Content-Type",
            ),
            (
                200,
                vec!["application/json"],
                canonical.clone(),
                canonical.len(),
                "invalid content-type",
            ),
            (
                200,
                vec![APPLICATION_NORITO],
                Vec::new(),
                canonical.len(),
                "empty",
            ),
        ] {
            let mut builder = Response::builder().status(status);
            for value in media {
                builder = builder.header("Content-Type", value);
            }
            let response = builder.body(body).unwrap();
            let error = with_decode_limits_scope(allocation_limit(0), || {
                Client::decode_canonical_norito_response::<ValidatorCommitteeStatusV1>(
                    &response,
                    maximum,
                    "nexus.validator_committee.read",
                )
            })
            .unwrap_err();
            let Error::Decode { operation, details } = error else {
                panic!("must reject before decoding: {error:?}");
            };
            assert_eq!(operation, "nexus.validator_committee.read");
            assert!(
                details.contains(expected),
                "missing exact predecode check: {details}"
            );
        }
    }

    #[test]
    fn blocking_committee_preserves_intrinsic_native_error_without_replay() {
        use iroha_data_model::sumeragi::finality::NativeFinalityDecodeError;
        let mut fixture = status_fixture();
        fixture.latest_finality.block_wire.push(0);
        let (client, requests, _) = attach(
            move |_| Ok(norito_response(StatusCode::OK, &fixture)),
            Duration::ZERO,
            Duration::ZERO,
        );
        let client = crate::blocking::Client::from_client(client).unwrap();
        let error = client.nexus().validator_committee(Some(7)).unwrap_err();
        assert!(matches!(&error, Error::NativeFinalityDecode {
            operation: "nexus.validator_committee.read", source: NativeFinalityDecodeError::Malformed(source)
        } if source.kind() == norito::core::DecodeAttemptErrorKind::Invalid));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}
