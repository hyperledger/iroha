// Full serve_client handoff tests with real UnixStream framing and one actual backend call.
use server_observation::test_hooks::{self as server_custody_probe, Mode as ServerMode};
use std::sync::atomic::AtomicBool;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ServerOutcome {
    Success,
    Current,
    DelayedProvider,
    ClosedPeer,
    ReplayId,
    Malformed,
    WrongBinding,
}
struct ServerReplyBackend {
    query: SignerStreamTokenObservationRequestV1,
    bytes: Vec<u8>,
    record: Option<Vec<u8>>,
    calls: AtomicU64,
    changed: Arc<AtomicBool>,
    delay: Duration,
}
impl StreamTokenStateObserverClientV1 for ServerReplyBackend {
    fn handle(&self) -> &str {
        if self.changed.load(Ordering::SeqCst) {
            "state://sorafs/stream-token/changed"
        } else {
            "state://sorafs/stream-token/observer-primary"
        }
    }
    fn finalize_check(
        &self,
        _: &iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority,
    ) -> Result<iroha_data_model::transaction::SignedTransaction, StreamTokenSignerCallErrorV1>
    {
        panic!("completed reply processing cannot dispatch Check");
    }
    fn observe(
        &self,
        query: &SignerStreamTokenObservationRequestV1,
    ) -> Result<StreamTokenObserverReplyV1, StreamTokenSignerCallErrorV1> {
        assert_eq!(query, &self.query);
        assert_eq!(
            self.calls.fetch_add(1, Ordering::SeqCst),
            0,
            "exactly one actual Observe"
        );
        std::thread::sleep(self.delay);
        self.record.as_ref().map_or_else(
            || StreamTokenObserverReplyV1::completed(self.bytes.clone()),
            |record| StreamTokenObserverReplyV1::current(record.clone(), self.bytes.clone()),
        )
    }
}
fn server_reply_case(mode: ServerMode, outcome: ServerOutcome) {
    let delayed_provider = outcome == ServerOutcome::DelayedProvider;
    let closed_peer = outcome == ServerOutcome::ClosedPeer;
    let (query, original_bytes) = if outcome == ServerOutcome::Current {
        let query = stream_token_signer_test_support::query();
        let bytes = stream_token_signer_test_support::state_claim(&query)
            .encode_canonical()
            .unwrap();
        (query, bytes)
    } else {
        completed_reply_case()
    };
    let record =
        (outcome == ServerOutcome::Current).then(|| vec![0xa1; SIGNER_CUSTODY_MAX_BYTES_V1]);
    let backend_bytes = match outcome {
        ServerOutcome::Malformed => vec![0xff],
        ServerOutcome::WrongBinding => {
            let mut changed =
                SignerStreamTokenStateObservationV1::decode_canonical(&original_bytes).unwrap();
            changed.body.request_digest = [0xa2; 32];
            changed.encode_canonical().unwrap()
        }
        _ => original_bytes.clone(),
    };
    let changed = Arc::new(AtomicBool::new(false));
    // This is a smaller configured admission budget, never a raised/default-reset deadline.
    let timeout = if matches!(
        mode,
        ServerMode::ExpireBeforeDispatch | ServerMode::ExpireAfterFrame
    ) || delayed_provider
    {
        Duration::from_secs(1)
    } else {
        BROKER_IO_TIMEOUT_V1
    };
    let backend = Arc::new(ServerReplyBackend {
        query: query.clone(),
        bytes: backend_bytes,
        record: record.clone(),
        calls: AtomicU64::new(0),
        changed: Arc::clone(&changed),
        delay: if delayed_provider {
            timeout + Duration::from_millis(20)
        } else {
            Duration::ZERO
        },
    });
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_stream_token_signer_client(Arc::new(UnusedReplySigner))
        .with_stream_token_state_observer(backend.clone());
    let binding = token_signer_binding();
    let metadata = make_server_observation(network_id(), &binding, &backends).unwrap();
    let metadata_digest = metadata.metadata_digest;
    let state = singleton_state(
        "stream-token-server-custody",
        binding.clone(),
        metadata,
        backends,
    );
    let lifecycle = Arc::new(RuntimeProviderBrokerLifecycleV1::new());
    assert!(lifecycle.publish_ready(|| {}));
    let server_lifecycle = Arc::clone(&lifecycle);
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(BROKER_IO_TIMEOUT_V1)).unwrap();
    peer.set_write_timeout(Some(BROKER_IO_TIMEOUT_V1)).unwrap();
    let worker = thread::spawn(move || {
        server_custody_probe::measure(mode, changed, || {
            serve_client(
                stream,
                &state,
                None,
                Arc::new(tokio::sync::Semaphore::new(1)),
                Arc::new(tokio::sync::Semaphore::new(
                    MAX_STREAM_TOKEN_HARDWARE_FRAME_BYTES_V1,
                )),
                server_lifecycle,
                timeout,
            )
        })
    });
    let handshake = make_handshake_request(
        "stream-token-server-custody",
        network_id(),
        vec![binding.clone()],
        [0xa1; 32],
    )
    .unwrap();
    let frame = encode_frame(
        FRAME_KIND_HANDSHAKE_REQUEST_V1,
        &handshake,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )
    .unwrap();
    write_length_prefixed(&mut peer, &frame, MAX_HANDSHAKE_FRAME_BYTES_V1).unwrap();
    let response_frame = read_length_prefixed(&mut peer, MAX_HANDSHAKE_FRAME_BYTES_V1).unwrap();
    let response = decode_frame::<HandshakeResponseV1>(
        &response_frame,
        FRAME_KIND_HANDSHAKE_RESPONSE_V1,
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )
    .unwrap();
    validate_handshake_response(&handshake, &response).unwrap();
    let request = make_operation_request(
        response.session_id,
        1,
        binding,
        metadata_digest,
        OPERATION_STREAM_TOKEN_OBSERVE_V1,
        query.encode_canonical().unwrap(),
    )
    .unwrap();
    let limit = operation_frame_limit(request.operation);
    let frame = encode_frame(FRAME_KIND_OPERATION_REQUEST_V1, &request, limit).unwrap();
    write_operation_request_frame(&mut peer, &request, &frame).unwrap();
    let received = if closed_peer {
        peer.shutdown(std::net::Shutdown::Both).unwrap();
        None
    } else {
        read_length_prefixed(&mut peer, limit).ok()
    };
    if let Some(frame) = &received {
        let response = decode_operation_frame::<OperationResponseV1>(
            frame,
            FRAME_KIND_OPERATION_RESPONSE_V1,
            request.operation,
        )
        .unwrap();
        validate_operation_response_envelope(&request, &response).unwrap();
        if mode == ServerMode::DriftAfterFrame {
            assert_eq!(response.status, STATUS_STALE_OR_REVOKED_V1);
        } else {
            assert_eq!(response.status, STATUS_OK_V1);
            let reply = decode_stream_token_observer_reply(
                &request.binding,
                &request.payload,
                &response.result,
            )
            .unwrap();
            if let Some(record) = &record {
                let (actual_record, actual_observation) = reply.current_evidence().unwrap();
                assert_eq!(actual_record, record);
                assert_eq!(actual_observation, original_bytes);
            } else {
                assert_eq!(reply.completed_observation().unwrap(), original_bytes);
            }
        }
    }
    if outcome == ServerOutcome::ReplayId {
        assert!(received.is_some(), "first admitted Observe completes");
        write_operation_request_frame(&mut peer, &request, &frame).unwrap();
        assert!(
            read_length_prefixed(&mut peer, limit).is_err(),
            "retired id is never admitted again"
        );
    }
    let _ = peer.shutdown(std::net::Shutdown::Both);
    let (server_result, audit) = worker.join().unwrap();
    assert_eq!(
        lifecycle.active_provider_call_count(),
        0,
        "original operation permit retires once"
    );
    let expected_calls = u64::from(mode != ServerMode::ExpireBeforeDispatch);
    assert_eq!(backend.calls.load(Ordering::SeqCst), expected_calls);
    if mode == ServerMode::RefuseObservation {
        assert_eq!(audit.refusals, 1);
        assert_eq!(audit.retry_checks, 1);
        assert_eq!(audit.successful_phases, [1; 12]);
        assert_eq!(audit.reply.as_ref().unwrap().1, original_bytes);
        assert_eq!(
            audit.record.as_ref().map(|(_, bytes)| bytes),
            record.as_ref()
        );
        assert_eq!(
            received.as_ref().unwrap().as_slice(),
            audit.encoded_frame.as_ref().unwrap().1.as_slice()
        );
    } else {
        assert_eq!(audit.refusals, 0);
    }
    if matches!(
        mode,
        ServerMode::ExpireBeforeDispatch | ServerMode::ExpireAfterFrame
    ) || delayed_provider
    {
        assert!(
            received.is_none(),
            "an expired admitted operation writes no reply"
        );
        assert!(std::time::Instant::now() >= audit.deadline.unwrap());
        if mode == ServerMode::ExpireAfterFrame {
            assert!(
                audit.encoded_frame.is_some(),
                "one complete frame survives until original expiry"
            );
            assert_eq!(audit.successful_phases[..11], [1; 11]);
            assert_eq!(audit.successful_phases[11], 0);
        }
        assert_eq!(server_result.err(), Some(BrokerError::Unavailable));
    } else if mode == ServerMode::DriftAfterFrame {
        assert!(
            audit.encoded_frame.is_some(),
            "actual success frame exists before immutable handle drift"
        );
        assert_eq!(audit.successful_phases[..11], [1; 11]);
        assert_eq!(audit.successful_phases[11], 0);
        assert!(server_result.is_ok());
    } else if matches!(
        outcome,
        ServerOutcome::ReplayId | ServerOutcome::Malformed | ServerOutcome::WrongBinding
    ) {
        assert_eq!(server_result.err(), Some(BrokerError::Protocol));
        if outcome != ServerOutcome::ReplayId {
            assert!(
                received.is_none(),
                "malformed provider output cannot publish a success frame"
            );
        }
    } else if closed_peer {
        assert!(
            server_result.is_err(),
            "one attempted write fails without redispatch"
        );
    } else {
        assert!(received.is_some());
    }
}
#[test]
fn full_server_retains_one_completed_reply_on_original_decode_refusal() {
    server_reply_case(ServerMode::RefuseObservation, ServerOutcome::Success);
    server_reply_case(ServerMode::RefuseObservation, ServerOutcome::Current);
}
#[test]
fn original_server_deadline_cannot_renew_before_dispatch_after_backend_or_after_frame() {
    server_reply_case(ServerMode::ExpireBeforeDispatch, ServerOutcome::Success);
    server_reply_case(ServerMode::None, ServerOutcome::DelayedProvider);
    server_reply_case(ServerMode::ExpireAfterFrame, ServerOutcome::Success);
}
#[test]
fn server_immutable_drift_and_closed_socket_never_reobserve() {
    server_reply_case(ServerMode::DriftAfterFrame, ServerOutcome::Success);
    server_reply_case(ServerMode::None, ServerOutcome::ClosedPeer);
}

#[test]
fn server_retired_request_ids_and_malformed_provider_replies_are_terminal() {
    server_reply_case(ServerMode::None, ServerOutcome::ReplayId);
    server_reply_case(ServerMode::None, ServerOutcome::Malformed);
    server_reply_case(ServerMode::None, ServerOutcome::WrongBinding);
}
