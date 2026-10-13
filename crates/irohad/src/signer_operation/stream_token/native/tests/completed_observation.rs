//! Actual producer Check custody through post-finality preparation and exact reply refusal.

use super::super::observer::{
    NativeStreamTokenObserverV1,
    test_hooks::{self, Point},
};
use super::*;
use iroha_data_model::transaction::{Executable, TransactionEntrypoint};
use iroha_torii::sorafs::{
    StreamTokenSignerCallErrorV1, StreamTokenSignerPinsV1, StreamTokenStateObserverClientV1,
};
use sorafs_manifest::signer::{
    protocol::SignerOperationCommitmentV1,
    stream_token_evidence::{
        SignerStreamTokenObservationRequestSubjectV1, SignerStreamTokenObservationRequestV1,
        SignerStreamTokenStateObservationV1,
    },
};

fn completed_case() -> (
    tempfile::TempDir,
    Fixture,
    Arc<Queue>,
    NativeStreamTokenObserverV1,
    SignerStreamTokenObservationRequestV1,
) {
    let mut fixture = Fixture::new_at(now_ms() - 5_000);
    let queue = queue();
    let source = source_with_timeout(&fixture, Arc::clone(&queue), Duration::from_secs(10));
    let reviewed = reviewed(&source);
    let current = source.capture(reviewed.request.operation_id).unwrap();
    assert!(
        fixture.commit_instruction(
            MutateSorafsStreamTokenAuthority {
                request: StreamTokenAuthorityRequestV1 {
                    network_id: source.binding.network_id,
                    provider_id: fixture.provider,
                    expected_control_revision: current.control_revision,
                    expected_control_digest: current.anchor.state_digest,
                    action: Action::Reserve(reviewed),
                }
            }
            .into(),
            2,
            now_ms()
        )
    );
    let current = source.capture(reviewed.request.operation_id).unwrap();
    let reservation = current.operation.unwrap().operation.operation.reservation;
    assert!(
        fixture.commit_instruction(
            MutateSorafsStreamTokenAuthority {
                request: StreamTokenAuthorityRequestV1 {
                    network_id: source.binding.network_id,
                    provider_id: fixture.provider,
                    expected_control_revision: current.control_revision,
                    expected_control_digest: current.anchor.state_digest,
                    action: Action::Complete(StreamTokenCompleteRequestV1 {
                        reviewed,
                        reservation,
                        commitment: SignerOperationCommitmentV1 {
                            audit: SignerOperationAuditHeadV1 {
                                sequence: reviewed.intent.previous_audit.sequence + 1,
                                digest: [67; 32]
                            },
                            response_digest: [68; 32],
                        },
                        signatures_digest: [69; 32],
                    }),
                }
            }
            .into(),
            2,
            now_ms()
        )
    );
    let (directory, storage) = config(&fixture);
    let pins = StreamTokenSignerPinsV1::from_config(
        &storage,
        fixture.state.view().chain_id().as_ref(),
        *fixture.state.network_id_ref().as_bytes(),
    )
    .unwrap()
    .unwrap();
    let current = source.capture(reviewed.request.operation_id).unwrap();
    let request = SignerStreamTokenObservationRequestV1 {
        magic: SignerStreamTokenObservationRequestV1::magic(),
        phase: SignerStreamTokenObservationPhaseV1::BeforeRelease,
        subject: SignerStreamTokenObservationRequestSubjectV1::CompletedOperation {
            binding_digest: stream_token_binding_digest_v1(&source.binding).unwrap(),
            operation_id: reviewed.request.operation_id,
            signing_payload_digest: reviewed.request.signing_payload_digest,
            signing_payload_size: reviewed.request.signing_payload_size,
            receipt_digest: [70; 32],
            signatures_digest: [69; 32],
        },
        challenge: [71; 32],
        minimum_anchor: current.anchor,
        not_before_unix_ms: now_ms(),
    };
    let observer = NativeStreamTokenObserverV1 {
        source: Arc::new(source),
        handle: pins.observer_handle().to_owned(),
        trust: pins.observer_trust().clone(),
        record: fixture.record.clone(),
    };
    (directory, fixture, queue, observer, request)
}

fn apply_one_check(
    mut fixture: Fixture,
    queue: Arc<Queue>,
) -> std::thread::JoinHandle<(Fixture, TransactionEntrypoint)> {
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let transaction = {
                let view = fixture.state.view();
                queue
                    .all_transactions(&view)
                    .next()
                    .map(|tx| tx.external().unwrap().clone())
            };
            if let Some(signed) = transaction {
                let Executable::Instructions(instructions) = signed.instructions() else {
                    panic!("native instruction");
                };
                assert_eq!(instructions.len(), 1);
                let instruction = instructions[0]
                    .as_any()
                    .downcast_ref::<MutateSorafsStreamTokenAuthority>()
                    .unwrap();
                assert!(matches!(instruction.request.action, Action::Check(_)));
                assert!(fixture.commit_signed(signed.clone(), now_ms()));
                return (fixture, TransactionEntrypoint::External(signed));
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the original Check is actually submitted"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    })
}

#[test]
fn original_completed_check_and_exact_reply_survive_native_floor_capacity_refusal() {
    // An existing public MV reader retains the original epoch guard so unrelated
    // deferred State generations cannot refund capacity during the pressure probe.
    // This reader grants no State-pool capacity and holds no State publication lock.
    let retirement_owner = mv::cell::Cell::new(());
    let _retirement_view = retirement_owner.view();
    for phase in [
        SignerStreamTokenObservationPhaseV1::AfterCommit,
        SignerStreamTokenObservationPhaseV1::BeforeRelease,
    ] {
        for point in [Point::Body, Point::Encoded] {
            let (_directory, fixture, queue, observer, mut request) = completed_case();
            request.phase = phase;
            let request_before = request.encode_canonical().unwrap();
            let budget = fixture.state.ivm_execution_budget();
            let original_limit = budget.limit_bytes();
            let worker = apply_one_check(fixture, Arc::clone(&queue));
            let (reply, audit) =
                test_hooks::measure(budget.clone(), Some(point), || observer.observe(&request));
            let (fixture, applied) = worker.join().unwrap();
            let reply =
                reply.expect("same native attempt resumes after original pressure owner drops");
            assert_eq!(audit.refusals, 1);
            assert_eq!(
                audit.signatures, 1,
                "one completed observer signature, never repeated"
            );
            assert_eq!(budget.limit_bytes(), original_limit);
            assert_eq!(request.encode_canonical().unwrap(), request_before);
            assert_eq!(
                audit.check_bytes,
                norito::encode_canonical(&applied).unwrap()
            );
            assert!(std::time::Instant::now() < audit.deadline.unwrap());
            let bytes = reply.completed_observation().unwrap();
            if let Some((pointer, original)) = audit.reply {
                assert_eq!(bytes.as_ptr() as usize, pointer);
                assert_eq!(bytes, original);
            } else {
                assert_eq!(point, Point::Body);
            }
            let observation = SignerStreamTokenStateObservationV1::decode_canonical(bytes).unwrap();
            assert_eq!(observation.body.request_digest, request.digest().unwrap());
            assert_eq!(observation.body.phase, phase);
            Signature::try_from_bytes(&observation.signature)
                .unwrap()
                .verify(
                    &observer.trust.public_key,
                    &observation.body.signing_payload().unwrap(),
                )
                .unwrap();
            let view = fixture.state.view();
            let remaining = queue.all_transactions(&view).count();
            assert!(remaining == 0, "no replacement or second Check is queued");
        }
    }
}

#[test]
fn wrong_observer_floor_is_terminal_after_one_native_check_without_observation_signature() {
    let (_directory, fixture, queue, observer, mut request) = completed_case();
    request.minimum_anchor.block_hash[0] ^= 1;
    let original = request.encode_canonical().unwrap();
    let worker = apply_one_check(fixture, Arc::clone(&queue));
    let (result, audit) =
        test_hooks::measure(observer.source.state.ivm_execution_budget(), None, || {
            observer.observe(&request)
        });
    let (fixture, _) = worker.join().unwrap();
    assert_eq!(result.err(), Some(StreamTokenSignerCallErrorV1::Refused));
    assert_eq!(audit.refusals, 0, "semantic rejection has no local retry");
    assert_eq!(audit.signatures, 0, "the wrong floor cannot be signed");
    assert_eq!(request.encode_canonical().unwrap(), original);
    let view = fixture.state.view();
    assert_eq!(queue.all_transactions(&view).count(), 0);
}

#[test]
fn observation_signature_binds_exact_encoded_body_and_observer_key() {
    let (_directory, _fixture, _queue, observer, request) = completed_case();
    let binding_digest = stream_token_binding_digest_v1(&observer.source.binding).unwrap();
    let mut request = request;
    request.phase = SignerStreamTokenObservationPhaseV1::Startup;
    request.subject =
        SignerStreamTokenObservationRequestSubjectV1::CurrentCustody { binding_digest };
    let reply = observer.observe(&request).unwrap();
    let (_, bytes) = reply.current_evidence().unwrap();
    let observation = SignerStreamTokenStateObservationV1::decode_canonical(bytes).unwrap();
    let body = observation.body;
    let payload = body.signing_payload().unwrap();
    let original = payload.clone();
    let bytes = observer
        .source
        .transactions
        .sign_observation_payload(&payload)
        .unwrap();
    assert_eq!(
        payload, original,
        "the signing helper borrows the admitted bytes"
    );
    let signature = Signature::from_bytes(&bytes);
    signature
        .verify(Fixture::key(3).public_key(), &payload)
        .unwrap();
    assert!(
        signature
            .verify(Fixture::key(2).public_key(), &payload)
            .is_err()
    );
    let mut changed = payload;
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        signature
            .verify(Fixture::key(3).public_key(), &changed)
            .is_err()
    );
}
