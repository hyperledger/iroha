// Actual observer client/socket/dispatch tests. Raw fixture claims do not establish
// native finality or independent signer qualification; this test owns only transport.
use received_exchange::test_hooks::{self as observer_custody_probe, Point as ReplyPoint};

fn completed_reply_case() -> (SignerStreamTokenObservationRequestV1, Vec<u8>) {
    use sorafs_manifest::signer::{
        receipt::{SignerCompletedOperationV1, SignerOperationFinalizedAnchorV1},
        stream_token_evidence::{
            SignerStreamTokenObservationPhaseV1, SignerStreamTokenStateSubjectV1,
        },
    };
    let expected = expected();
    let mut query = stream_token_signer_test_support::query();
    query.phase = SignerStreamTokenObservationPhaseV1::BeforeRelease;
    query.subject = SignerStreamTokenObservationRequestSubjectV1::CompletedOperation {
        binding_digest: expected.binding_digest(),
        operation_id: expected.operation_id(),
        signing_payload_digest: expected.signing_payload_digest(),
        signing_payload_size: expected.signing_payload_size(),
        receipt_digest: [0xac; 32],
        signatures_digest: [0xad; 32],
    };
    let receipt = stream_token_signer_test_support::receipt(&signing_payload());
    let mut observation = stream_token_signer_test_support::state_claim(&query);
    observation.body.subject = SignerStreamTokenStateSubjectV1::CompletedOperation {
        binding_digest: expected.binding_digest(),
        operation_id: expected.operation_id(),
        signing_payload_digest: expected.signing_payload_digest(),
        signing_payload_size: expected.signing_payload_size(),
        completed_operation: Box::new(SignerCompletedOperationV1 {
            operation_id: expected.operation_id(),
            intent_digest: receipt.intent.digest().unwrap(),
            original_custody: receipt.request.original_custody,
            reservation: receipt.reservation,
            commitment: receipt.commitment,
            signatures_digest: [0xad; 32],
            completed_at_unix_ms: query.not_before_unix_ms,
            anchor: SignerOperationFinalizedAnchorV1 {
                height: 11,
                block_hash: [0xae; 32],
                operation_state_digest: [0xaf; 32],
            },
        }),
    };
    (query, observation.encode_canonical().unwrap())
}

struct CompletedReplyBackend {
    query: SignerStreamTokenObservationRequestV1,
    observation: Vec<u8>,
    calls: AtomicU64,
}
impl StreamTokenStateObserverClientV1 for CompletedReplyBackend {
    fn handle(&self) -> &'static str {
        "state://sorafs/stream-token/observer-primary"
    }
    fn finalize_check(
        &self,
        _: &iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority,
    ) -> Result<iroha_data_model::transaction::SignedTransaction, StreamTokenSignerCallErrorV1>
    {
        panic!("reply admission never invokes finalize_check");
    }
    fn observe(
        &self,
        query: &SignerStreamTokenObservationRequestV1,
    ) -> Result<StreamTokenObserverReplyV1, StreamTokenSignerCallErrorV1> {
        assert_eq!(query, &self.query);
        assert_eq!(
            self.calls.fetch_add(1, Ordering::SeqCst),
            0,
            "exactly one backend observe"
        );
        StreamTokenObserverReplyV1::completed(self.observation.clone())
    }
}
struct UnusedReplySigner;
impl StreamTokenSignerClientV1 for UnusedReplySigner {
    fn handle(&self) -> &'static str {
        "hsm://sorafs/stream-token/primary-a"
    }
    fn sign(
        &self,
        _: &SignerStreamTokenExpectedV1,
        _: &sorafs_manifest::StreamTokenBodyV1,
    ) -> Result<StreamTokenSignerReceiptV1, StreamTokenSignerCallErrorV1> {
        panic!("reply admission never signs");
    }
    fn recover(
        &self,
        _: &SignerStreamTokenExpectedV1,
        _: &sorafs_manifest::StreamTokenBodyV1,
    ) -> Result<StreamTokenSignerReceiptV1, StreamTokenSignerCallErrorV1> {
        panic!("reply admission never calls recovery");
    }
}

fn received_reply_case(point: ReplyPoint, mutation: u8, expire: bool) {
    let mut fixture = fixture();
    let (query, observation_bytes) = completed_reply_case();
    let backend = Arc::new(CompletedReplyBackend {
        query: query.clone(),
        observation: observation_bytes.clone(),
        calls: AtomicU64::new(0),
    });
    let backends = RuntimeProviderBrokerBackendsV1::new()
        .with_stream_token_signer_client(Arc::new(UnusedReplySigner))
        .with_stream_token_state_observer(backend.clone());
    let binding = fixture.signer.binding.clone();
    let metadata = make_server_observation(network_id(), &binding, &backends).unwrap();
    assert_eq!(metadata.metadata_digest, fixture.signer.metadata_digest);
    let state = singleton_state(
        "stream-token-mutation-test-chain",
        binding.clone(),
        metadata,
        backends,
    );
    let observer = StreamTokenObserverBrokerClient {
        session: Arc::clone(&fixture.signer.session),
        binding: binding.clone(),
        metadata_digest: fixture.signer.metadata_digest,
        observer_handle: binding
            .stream_token_signer_binding
            .as_ref()
            .unwrap()
            .observer_handle()
            .to_owned(),
    };
    let expected_query = query.encode_canonical().unwrap();
    let observing = thread::spawn(move || {
        observer_custody_probe::measure(point, expire, || observer.observe(&query))
    });
    let mut peer = accept_read_session(&fixture);
    let request = read_request(&mut peer, 1, OPERATION_STREAM_TOKEN_OBSERVE_V1);
    assert_eq!(request.payload, expected_query);
    let result = dispatch_server_operation(&state, &request).unwrap();
    let mut response =
        make_operation_response_scrubbed(&request, STATUS_OK_V1, result, &state.network_id)
            .unwrap();
    if mutation == 1 {
        response.request_digest[0] ^= 1;
    } else if mutation == 2 {
        let mut observation =
            SignerStreamTokenStateObservationV1::decode_canonical(&observation_bytes).unwrap();
        observation.body.request_digest[0] ^= 1;
        let reply =
            StreamTokenObserverReplyV1::completed(observation.encode_canonical().unwrap()).unwrap();
        response.result = encode_stream_token_observer_reply(&backend.query, &reply).unwrap();
        response.result_digest = operation_result_digest(&response.result);
        let fields = OperationResponseFieldsV1 {
            session_id: response.session_id,
            request_id: response.request_id,
            request_digest: response.request_digest,
            observed_binding: response.observed_binding.clone(),
            provider_metadata_digest: response.provider_metadata_digest,
            operation: response.operation,
            payload_digest: response.payload_digest,
            status: response.status,
            result_digest: response.result_digest,
            result_len: u64::try_from(response.result.len()).unwrap(),
        };
        response.response_digest = operation_response_digest(&fields).unwrap();
    }
    write_response_frame(&mut peer, &response);
    // A complete reply already buffered before peer close remains recoverable locally.
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    let (result, audit) = observing.join().unwrap();
    assert_eq!(audit.refusals, 1);
    assert_eq!(audit.retry_identity_checks, usize::from(!expire));
    if expire {
        assert!(std::time::Instant::now() >= audit.deadline.unwrap());
        assert_eq!(
            result.err(),
            Some(StreamTokenSignerCallErrorV1::Unavailable)
        );
    } else if mutation == 0 {
        assert!(std::time::Instant::now() < audit.deadline.unwrap());
        let reply = result.unwrap();
        let actual = reply.completed_observation().unwrap();
        assert_eq!(actual, observation_bytes);
        if let Some((pointer, original)) = audit.reply {
            assert_eq!(actual.as_ptr() as usize, pointer);
            assert_eq!(actual, original);
        }
    } else {
        assert_eq!(
            result.err(),
            Some(StreamTokenSignerCallErrorV1::InvalidResponse)
        );
    }
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_no_request_bytes(&mut fixture.peer);
    let mut byte = [0; 1];
    assert_eq!(
        peer.read(&mut byte).unwrap(),
        0,
        "no second request on the completed connection"
    );
    assert_eq!(
        fixture.reconnect_listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "no replacement session"
    );
}

#[test]
fn exact_completed_reply_survives_each_received_decode_refusal_on_original_socket() {
    for point in [
        ReplyPoint::Frame,
        ReplyPoint::Response,
        ReplyPoint::Reply,
        ReplyPoint::Observation,
    ] {
        received_reply_case(point, 0, false);
    }
}

#[test]
fn wrong_envelope_and_observation_remain_terminal_after_local_reply_retry() {
    received_reply_case(ReplyPoint::Frame, 1, false);
    received_reply_case(ReplyPoint::Observation, 2, false);
}

#[test]
fn received_reply_retry_cannot_renew_the_original_socket_deadline() {
    // Deliberately wait out the existing 15-second source deadline; no test clock,
    // replacement deadline, policy increase or observer retry is used.
    received_reply_case(ReplyPoint::Observation, 0, true);
}
