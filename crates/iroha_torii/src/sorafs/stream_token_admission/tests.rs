//! Exact replay, crash recovery, and lease-boundary tests.
use super::*;
use iroha_data_model::sorafs::reputation::{
    StreamTokenExcludedKindV1, StreamTokenRequestRouteV1, StreamTokenValidationBindingV1,
    StreamTokenValidationOutcomeV1, StreamTokenValidationRequestContextV1,
    StreamTokenViolationKindV1,
};
use iroha_data_model::sorafs::{
    capacity::ProviderId,
    stream_token_gateway::{
        StreamTokenGatewayQuotaRequestV1, stream_token_gateway_lease_expiry_unix_ms_v1,
    },
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
const VALIDATED_AT_MS: u64 = 1_800_000_000_000;
/// Independent monotonic fixture budget; synthetic token timestamps remain unchanged.
pub(crate) fn test_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}
const HANDLE: &str = "sealed://sorafs/stream-admission/eu-1";
fn qualification() -> StreamTokenGatewayAdmissionQualificationV1 {
    StreamTokenGatewayAdmissionQualificationV1 {
        gateway_id: [0x31; 32],
        revision: 7,
        policy_digest: [0x32; 32],
        max_pending: 64,
        max_tracked_tokens: 64,
        lease_ttl_ms: 120_000,
    }
}
fn request(
    nonce: &str,
    validated_at_unix_ms: u64,
    expires_at_epoch: u64,
    max_streams: u16,
) -> StreamTokenGatewayAdmissionRequestV1 {
    StreamTokenGatewayAdmissionRequestV1 {
        serving_attempt_id: [0x61; 32],
        context: StreamTokenValidationRequestContextV1::try_new(
            ProviderId::new([0x41; 32]),
            [0x42; 32],
            sorafs_manifest::canonical_manifest_root_cid([0x43; 32]),
            "sorafs.sf1@1.0.0".to_owned(),
            nonce,
            Some(b"Q2Fub25pY2FsVG9rZW4="),
            StreamTokenRequestRouteV1::car_range(64, 1_023).expect("canonical route"),
        )
        .expect("canonical request context"),
        token_body_digest: Some([0x44; 32]),
        token_key_version: Some(3),
        validated_at_unix_ms,
        status: StreamTokenValidationStatusV1::Accepted,
        quota: Some(StreamTokenGatewayQuotaRequestV1 {
            token_id: "11".repeat(16),
            max_streams,
            requests_per_minute: 120,
            rate_limit_bytes: 1_048_576,
            requested_bytes: 960,
            expires_at_epoch,
            observed_at_epoch: validated_at_unix_ms / 1_000,
        }),
    }
}
fn record_for_request(
    request: &StreamTokenGatewayAdmissionRequestV1,
    sequence: u64,
    status: StreamTokenValidationStatusV1,
) -> StreamTokenGatewayAdmissionRecordV1 {
    let admitted = status == StreamTokenValidationStatusV1::Accepted;
    let token_expiry = admitted.then(|| {
        request
            .quota
            .as_ref()
            .expect("accepted request quota")
            .expires_at_epoch
    });
    StreamTokenGatewayAdmissionRecordV1 {
        serving_attempt_id: request.serving_attempt_id,
        admitted_under: qualification(),
        provider_id: request.context.provider_id(),
        outcome: StreamTokenValidationOutcomeV1 {
            binding: StreamTokenValidationBindingV1 {
                gateway_id: qualification().gateway_id,
                gateway_sequence: sequence,
                request_context_digest: request.context.digest().expect("request digest"),
            },
            token_body_digest: request.token_body_digest,
            token_key_version: request.token_key_version,
            validated_at_unix_ms: request.validated_at_unix_ms,
            status,
        },
        retry_after_secs: None,
        lease_id: admitted.then(|| [u8::try_from(sequence).expect("test sequence"); 32]),
        lease_expires_at_unix_ms: token_expiry.map(|expires| {
            stream_token_gateway_lease_expiry_unix_ms_v1(
                request.validated_at_unix_ms,
                expires,
                qualification().lease_ttl_ms,
            )
            .expect("canonical lease expiry")
        }),
        lease_token_expires_at_epoch: token_expiry,
    }
}
#[derive(Debug, Default)]
struct ReputationProbe {
    calls: Mutex<Vec<(StreamTokenGatewayAdmissionRecordV1, Instant)>>,
    wrong_binding: AtomicUsize,
    fail_next: AtomicUsize,
    trace: Mutex<Option<Arc<Mutex<Vec<&'static str>>>>>,
}
impl ReputationProbe {
    fn fail_once(&self) {
        self.fail_next.store(1, Ordering::Release);
    }
    fn calls(&self) -> Vec<(StreamTokenGatewayAdmissionRecordV1, Instant)> {
        self.calls.lock().expect("reputation calls").clone()
    }
}
impl StreamTokenReputationDeliveryV1 for ReputationProbe {
    fn configured_qualification(&self) -> StreamTokenGatewayAdmissionQualificationV1 {
        let mut expected = qualification();
        expected.revision += self.wrong_binding.load(Ordering::Acquire) as u64;
        expected
    }
    fn deliver(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<(), StreamTokenGatewayAdmissionErrorV1> {
        if self
            .fail_next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(StreamTokenGatewayAdmissionErrorV1::ReputationCallback);
        }
        if let Some(trace) = self.trace.lock().unwrap().as_ref() {
            trace.lock().unwrap().push("callback");
        }
        let mut calls = self.calls.lock().expect("reputation calls");
        calls.push((record, deadline));
        Ok(())
    }
}
#[derive(Debug, Default)]
struct DurableProviderState {
    requests: Vec<(
        StreamTokenGatewayAdmissionRequestV1,
        StreamTokenGatewayAdmissionRecordV1,
    )>,
    records: Vec<StreamTokenGatewayAdmissionRecordV1>,
    acknowledged_through: u64,
    active_leases: Vec<(String, [u8; 32], u64)>,
    released_leases: Vec<[u8; 32]>,
    pending_script: VecDeque<Option<StreamTokenGatewayAdmissionReadbackV1>>,
    admission_unavailable: bool,
    qualification_unavailable: bool,
    logical_now_unix_ms: u64,
    calls: Vec<(&'static str, Instant)>,
    trace: Option<Arc<Mutex<Vec<&'static str>>>>,
    serving_unavailable: bool,
    serving_substituted: bool,
}
#[derive(Debug)]
struct DurableProvider {
    configured_qualification: StreamTokenGatewayAdmissionQualificationV1,
    state: Mutex<DurableProviderState>,
}
impl DurableProvider {
    fn note_call(
        &self,
        name: &'static str,
        deadline: Instant,
    ) -> Result<(), StreamTokenGatewayAdmissionErrorV1> {
        let mut state = self.state.lock().unwrap();
        state.calls.push((name, deadline));
        if let Some(trace) = &state.trace {
            trace.lock().unwrap().push(name);
        }
        ensure_live(deadline)
    }

    fn new() -> Self {
        Self {
            configured_qualification: qualification(),
            state: Mutex::new(DurableProviderState::default()),
        }
    }
    fn script_pending(
        &self,
        script: impl IntoIterator<Item = Option<StreamTokenGatewayAdmissionReadbackV1>>,
    ) {
        self.state
            .lock()
            .expect("provider state")
            .pending_script
            .extend(script);
    }
    fn acknowledged_through(&self) -> u64 {
        self.state
            .lock()
            .expect("provider state")
            .acknowledged_through
    }
}
impl StreamTokenGatewayAdmissionProviderV1 for DurableProvider {
    fn handle(&self) -> &str {
        HANDLE
    }
    fn configured_qualification(&self) -> StreamTokenGatewayAdmissionQualificationV1 {
        self.configured_qualification
    }
    fn qualification(
        &self,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionQualificationV1, StreamTokenGatewayAdmissionErrorV1>
    {
        self.note_call("qualification", deadline)?;
        if self.state.lock().unwrap().qualification_unavailable {
            return Err(StreamTokenGatewayAdmissionErrorV1::Unavailable);
        }
        Ok(qualification())
    }
    fn admit(
        &self,
        request: &StreamTokenGatewayAdmissionRequestV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionResultV1, StreamTokenGatewayAdmissionErrorV1> {
        self.note_call("admit", deadline)?;
        request.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| StreamTokenGatewayAdmissionErrorV1::Unavailable)?;
        state.logical_now_unix_ms = state.logical_now_unix_ms.max(request.validated_at_unix_ms);
        if state.admission_unavailable {
            return Err(StreamTokenGatewayAdmissionErrorV1::Unavailable);
        }
        if let Some((stored_request, record)) = state
            .requests
            .iter()
            .find(|(stored, _)| stored.context.digest() == request.context.digest())
        {
            if stored_request != request {
                return Err(StreamTokenGatewayAdmissionErrorV1::Conflict);
            }
            let sequence = record.outcome.binding.gateway_sequence;
            let delivery_state = if sequence <= state.acknowledged_through {
                StreamTokenGatewayAdmissionDeliveryStateV1::AcknowledgedExactReplay {
                    acknowledged_through_sequence: state.acknowledged_through,
                }
            } else {
                StreamTokenGatewayAdmissionDeliveryStateV1::Pending {
                    predecessor_sequence: sequence - 1,
                }
            };
            return Ok(StreamTokenGatewayAdmissionResultV1 {
                record: *record,
                delivery_state,
            });
        }
        let sequence = u64::try_from(state.records.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(StreamTokenGatewayAdmissionErrorV1::Unavailable)?;
        let mut status = request.status;
        if status == StreamTokenValidationStatusV1::Accepted {
            let quota = request
                .quota
                .as_ref()
                .ok_or(StreamTokenGatewayAdmissionErrorV1::InvalidRequest)?;
            state
                .active_leases
                .retain(|(_, _, expires)| *expires > request.validated_at_unix_ms);
            let active = state
                .active_leases
                .iter()
                .filter(|(token_id, _, _)| token_id == &quota.token_id)
                .count();
            if active >= usize::from(quota.max_streams) {
                status = StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::ConcurrencyLimitExceeded,
                );
            }
        }
        let record = record_for_request(request, sequence, status);
        if let (Some(quota), Some(lease_id), Some(expires)) = (
            request.quota.as_ref(),
            record.lease_id,
            record.lease_expires_at_unix_ms,
        ) {
            state
                .active_leases
                .push((quota.token_id.clone(), lease_id, expires));
        }
        state.requests.push((request.clone(), record));
        state.records.push(record);
        Ok(StreamTokenGatewayAdmissionResultV1 {
            record,
            delivery_state: StreamTokenGatewayAdmissionDeliveryStateV1::Pending {
                predecessor_sequence: sequence - 1,
            },
        })
    }
    fn pending(
        &self,
        max_items: u32,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionReadbackV1, StreamTokenGatewayAdmissionErrorV1> {
        self.note_call("pending", deadline)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| StreamTokenGatewayAdmissionErrorV1::Unavailable)?;
        if let Some(scripted) = state.pending_script.pop_front() {
            if let Some(readback) = scripted {
                return Ok(readback);
            }
        }
        let acknowledged = usize::try_from(state.acknowledged_through)
            .map_err(|_| StreamTokenGatewayAdmissionErrorV1::Unavailable)?;
        Ok(StreamTokenGatewayAdmissionReadbackV1 {
            acknowledged_through_sequence: state.acknowledged_through,
            high_water_sequence: u64::try_from(state.records.len())
                .map_err(|_| StreamTokenGatewayAdmissionErrorV1::Unavailable)?,
            records: state
                .records
                .iter()
                .skip(acknowledged)
                .take(max_items as usize)
                .copied()
                .collect(),
        })
    }
    fn pending_for_background(
        &self,
        max_items: u32,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayReconciliationReadV1, StreamTokenGatewayAdmissionErrorV1> {
        self.note_call("background", deadline)?;
        if self.state.lock().unwrap().qualification_unavailable {
            return Err(StreamTokenGatewayAdmissionErrorV1::Unavailable);
        }
        let readback = self.pending(max_items, deadline)?;
        if readback.records.is_empty()
            && readback.high_water_sequence == readback.acknowledged_through_sequence
        {
            Ok(StreamTokenGatewayReconciliationReadV1::Idle)
        } else {
            Ok(StreamTokenGatewayReconciliationReadV1::Checked(readback))
        }
    }
    fn acknowledge(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionAckV1, StreamTokenGatewayAdmissionErrorV1> {
        self.note_call("acknowledge", deadline)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| StreamTokenGatewayAdmissionErrorV1::Unavailable)?;
        let sequence = record.outcome.binding.gateway_sequence;
        let index = usize::try_from(sequence - 1)
            .map_err(|_| StreamTokenGatewayAdmissionErrorV1::Conflict)?;
        if state.records.get(index) != Some(&record) {
            return Err(StreamTokenGatewayAdmissionErrorV1::Conflict);
        }
        if sequence <= state.acknowledged_through {
            return Ok(StreamTokenGatewayAdmissionAckV1::ExactReplay);
        }
        if state.acknowledged_through.checked_add(1) != Some(sequence) {
            return Err(StreamTokenGatewayAdmissionErrorV1::Conflict);
        }
        state.acknowledged_through = sequence;
        Ok(StreamTokenGatewayAdmissionAckV1::Acknowledged)
    }
    fn release_lease(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionAckV1, StreamTokenGatewayAdmissionErrorV1> {
        self.note_call("release_lease", deadline)?;
        let lease_id = record
            .lease_id
            .ok_or(StreamTokenGatewayAdmissionErrorV1::InvalidRequest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| StreamTokenGatewayAdmissionErrorV1::Unavailable)?;
        if state.released_leases.contains(&lease_id) {
            return Ok(StreamTokenGatewayAdmissionAckV1::ExactReplay);
        }
        let position = state
            .active_leases
            .iter()
            .position(|(_, active_id, _)| *active_id == lease_id)
            .ok_or(StreamTokenGatewayAdmissionErrorV1::Conflict)?;
        state.active_leases.remove(position);
        state.released_leases.push(lease_id);
        Ok(StreamTokenGatewayAdmissionAckV1::Acknowledged)
    }
    fn confirm_serving(
        &self,
        request: &StreamTokenGatewayAdmissionRequestV1,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionRecordV1, StreamTokenGatewayAdmissionErrorV1> {
        self.note_call("confirm_serving", deadline)?;
        let state = self.state.lock().unwrap();
        if state.serving_unavailable {
            return Err(StreamTokenGatewayAdmissionErrorV1::Unavailable);
        }
        if record.outcome.status != StreamTokenValidationStatusV1::Accepted
            || !state
                .requests
                .iter()
                .any(|(original, retained)| original == request && *retained == record)
            || state.acknowledged_through < record.outcome.binding.gateway_sequence
            || !state.active_leases.iter().any(|(_, id, expiry)| {
                Some(*id) == record.lease_id && *expiry > state.logical_now_unix_ms
            })
        {
            return Err(StreamTokenGatewayAdmissionErrorV1::Unavailable);
        }
        // This synthetic provider owns synthetic UTC. Wall-clock time never reinterprets the
        // fixed historical request times used by quota, recovery and frame fixtures.
        if state.serving_substituted {
            let mut different = record;
            different.serving_attempt_id[0] ^= 1;
            return Ok(different);
        }
        Ok(record)
    }
}
fn capture(
    provider: Arc<DurableProvider>,
    reputation: Arc<ReputationProbe>,
    reconcile_max_items: u32,
) -> StreamTokenAdmissionCaptureV1 {
    StreamTokenAdmissionCaptureV1::try_new(
        HANDLE,
        qualification(),
        reconcile_max_items,
        Duration::from_secs(60),
        provider,
        reputation,
    )
    .expect("qualified capture")
}
#[test]
fn acknowledged_admit_replay_replays_reputation_and_requires_exact_ack_readback() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let first = capture(Arc::clone(&provider), Arc::clone(&reputation), 8);
    let request = request(
        "nonce-replay",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    let inserted = first
        .admit(&request, test_deadline())
        .expect("first admission");
    assert_eq!(provider.acknowledged_through(), 1);
    let replica = capture(Arc::clone(&provider), Arc::clone(&reputation), 8);
    assert_eq!(
        replica
            .admit(&request, test_deadline())
            .expect("acknowledged replay"),
        inserted
    );
    assert_eq!(provider.acknowledged_through(), 1);
    assert_eq!(reputation.calls().len(), 2);
}
#[test]
fn omitted_required_row_is_rejected_before_any_callback() {
    let provider = Arc::new(DurableProvider::new());
    provider.script_pending([
        None,
        Some(StreamTokenGatewayAdmissionReadbackV1 {
            acknowledged_through_sequence: 0,
            high_water_sequence: 1,
            records: Vec::new(),
        }),
    ]);
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(Arc::clone(&provider), Arc::clone(&reputation), 8);
    let error = capture
        .admit(
            &request(
                "nonce-omitted",
                VALIDATED_AT_MS,
                VALIDATED_AT_MS / 1_000 + 600,
                2,
            ),
            test_deadline(),
        )
        .expect_err("omitted required row must fail");
    assert_eq!(
        error,
        StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome
    );
    assert!(reputation.calls().is_empty());
    assert_eq!(provider.acknowledged_through(), 0);
}
#[test]
fn later_sequence_cannot_substitute_for_required_row() {
    let provider = Arc::new(DurableProvider::new());
    let required = request(
        "nonce-required",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    let later = request(
        "nonce-later",
        VALIDATED_AT_MS + 1,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    provider.script_pending([
        None,
        Some(StreamTokenGatewayAdmissionReadbackV1 {
            acknowledged_through_sequence: 0,
            high_water_sequence: 2,
            records: vec![record_for_request(
                &later,
                2,
                StreamTokenValidationStatusV1::Accepted,
            )],
        }),
    ]);
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(Arc::clone(&provider), Arc::clone(&reputation), 8);
    assert_eq!(
        capture.admit(&required, test_deadline()),
        Err(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome)
    );
    assert!(reputation.calls().is_empty());
    assert_eq!(provider.acknowledged_through(), 0);
}
#[test]
fn complete_batch_is_validated_before_first_callback_or_ack() {
    let provider = Arc::new(DurableProvider::new());
    let first = request(
        "nonce-batch-a",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    let second = request(
        "nonce-batch-b",
        VALIDATED_AT_MS + 1,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    let first_record = provider
        .admit(&first, test_deadline())
        .expect("stage first")
        .record;
    let mut substituted = provider
        .admit(&second, test_deadline())
        .expect("stage second")
        .record;
    substituted.lease_expires_at_unix_ms = substituted
        .lease_expires_at_unix_ms
        .and_then(|expires| expires.checked_add(1));
    provider.script_pending([Some(StreamTokenGatewayAdmissionReadbackV1 {
        acknowledged_through_sequence: 0,
        high_water_sequence: 2,
        records: vec![first_record, substituted],
    })]);
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(Arc::clone(&provider), Arc::clone(&reputation), 8);
    assert_eq!(
        capture.reconcile_pending(),
        Err(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome)
    );
    assert!(reputation.calls().is_empty());
    assert_eq!(provider.acknowledged_through(), 0);
}
#[test]
fn callback_crash_retains_row_for_exact_restart_replay() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    reputation.fail_once();
    let request = request(
        "nonce-crash",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    assert_eq!(
        capture(Arc::clone(&provider), Arc::clone(&reputation), 8).admit(&request, test_deadline()),
        Err(StreamTokenGatewayAdmissionErrorV1::ReputationCallback)
    );
    assert_eq!(provider.acknowledged_through(), 0);
    let restarted = capture(Arc::clone(&provider), Arc::clone(&reputation), 8);
    assert_eq!(restarted.reconcile_pending().expect("restart replay"), 1);
    assert_eq!(provider.acknowledged_through(), 1);
    assert_eq!(reputation.calls().len(), 1);
}
#[test]
fn shared_provider_owns_concurrency_and_release_across_replicas() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let first_replica = capture(Arc::clone(&provider), Arc::clone(&reputation), 8);
    let second_replica = capture(Arc::clone(&provider), Arc::clone(&reputation), 8);
    let first = first_replica
        .admit(
            &request(
                "nonce-stream-a",
                VALIDATED_AT_MS,
                VALIDATED_AT_MS / 1_000 + 600,
                1,
            ),
            test_deadline(),
        )
        .expect("first lease");
    let blocked = second_replica
        .admit(
            &request(
                "nonce-stream-b",
                VALIDATED_AT_MS + 1,
                VALIDATED_AT_MS / 1_000 + 600,
                1,
            ),
            test_deadline(),
        )
        .expect("authenticated concurrency terminal");
    assert_eq!(
        blocked.outcome.status,
        StreamTokenValidationStatusV1::ProviderViolation(
            StreamTokenViolationKindV1::ConcurrencyLimitExceeded
        )
    );
    assert!(blocked.lease_id.is_none());
    assert_eq!(
        first_replica.release_lease(first),
        Ok(StreamTokenGatewayAdmissionAckV1::Acknowledged)
    );
    assert_eq!(
        second_replica
            .admit(
                &request(
                    "nonce-stream-c",
                    VALIDATED_AT_MS + 2,
                    VALIDATED_AT_MS / 1_000 + 600,
                    1,
                ),
                test_deadline()
            )
            .expect("lease after release")
            .outcome
            .status,
        StreamTokenValidationStatusV1::Accepted
    );
}
#[test]
fn crashed_lease_expires_at_exact_authenticated_deadline() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(Arc::clone(&provider), reputation, 8);
    let first = capture
        .admit(
            &request(
                "nonce-expiring-a",
                VALIDATED_AT_MS,
                VALIDATED_AT_MS / 1_000 + 600,
                1,
            ),
            test_deadline(),
        )
        .expect("first lease");
    let deadline = first
        .lease_expires_at_unix_ms
        .expect("authenticated lease deadline");
    assert_eq!(
        capture
            .admit(
                &request("nonce-expiring-b", deadline, deadline / 1_000 + 600, 1,),
                test_deadline()
            )
            .expect("lease at exact prior expiry")
            .outcome
            .status,
        StreamTokenValidationStatusV1::Accepted
    );
}

include!("serving_test_support.rs");

#[test]
fn stream_token_provider_frames_preserve_admission_acknowledgement_and_replay() {
    let provider = DurableProvider::new();
    let request = request(
        "nonce-current-frames",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    let request_frame = crate::frame_test_support::assert_current_frame(
        &request,
        "iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionRequestV1",
    );
    let decoded_request: StreamTokenGatewayAdmissionRequestV1 =
        norito::decode_canonical(&request_frame).expect("decode provider request");
    decoded_request.validate().expect("valid decoded request");
    let result = provider
        .admit(&decoded_request, test_deadline())
        .expect("atomic provider admission");
    let result_frame = crate::frame_test_support::assert_current_frame(
        &result,
        "iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionResultV1",
    );
    let decoded_result: StreamTokenGatewayAdmissionResultV1 =
        norito::decode_canonical(&result_frame).expect("decode admission result");
    decoded_result
        .validate_for_request(&request, qualification())
        .expect("exact result binding");
    let record_frame = crate::frame_test_support::assert_current_frame(
        &decoded_result.record,
        "iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionRecordV1",
    );
    let record: StreamTokenGatewayAdmissionRecordV1 =
        norito::decode_canonical(&record_frame).expect("decode callback record");
    record
        .validate_for_request(&request, qualification())
        .expect("exact callback binding");
    let readback = provider
        .pending(8, test_deadline())
        .expect("oldest pending prefix");
    let readback_frame = crate::frame_test_support::assert_current_frame(
        &readback,
        "iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionReadbackV1",
    );
    let decoded_readback: StreamTokenGatewayAdmissionReadbackV1 =
        norito::decode_canonical(&readback_frame).expect("decode pending prefix");
    decoded_readback
        .validate(8, qualification())
        .expect("exact contiguous prefix");
    assert_eq!(decoded_readback.records, vec![record]);
    let acknowledged = provider
        .acknowledge(record, test_deadline())
        .expect("acknowledge exact callback");
    assert_eq!(acknowledged, StreamTokenGatewayAdmissionAckV1::Acknowledged);
    crate::frame_test_support::assert_current_frame(
        &acknowledged,
        "iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionAckV1",
    );
    let replay_ack = provider
        .acknowledge(record, test_deadline())
        .expect("exact acknowledgement replay");
    assert_eq!(replay_ack, StreamTokenGatewayAdmissionAckV1::ExactReplay);
    crate::frame_test_support::assert_current_frame(
        &replay_ack,
        "iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionAckV1",
    );
    let replay = provider
        .admit(&decoded_request, test_deadline())
        .expect("exact admitted request replay");
    replay
        .validate_for_request(&decoded_request, qualification())
        .expect("valid replay binding");
    assert!(matches!(
        replay.delivery_state,
        StreamTokenGatewayAdmissionDeliveryStateV1::AcknowledgedExactReplay {
            acknowledged_through_sequence: 1
        }
    ));
    assert!(matches!(
        norito::decode_canonical::<StreamTokenGatewayAdmissionRecordV1>(&result_frame),
        Err(norito::Error::SchemaMismatch)
    ));
    assert_eq!(provider.acknowledged_through(), 1);
}

#[test]
fn expired_original_deadline_rejects_before_any_provider_or_callback_call() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(provider.clone(), reputation.clone(), 8);
    provider.state.lock().unwrap().calls.clear();
    let request = request(
        "expired-original-deadline",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    assert_eq!(
        capture.admit(&request, Instant::now() - Duration::from_millis(1)),
        Err(StreamTokenGatewayAdmissionErrorV1::Unavailable)
    );
    assert!(provider.state.lock().unwrap().calls.is_empty());
    assert!(reputation.calls().is_empty());
}

#[test]
fn one_absolute_deadline_reaches_every_phase_and_serving_follows_callback_acknowledgement() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let trace = Arc::new(Mutex::new(Vec::new()));
    provider.state.lock().unwrap().trace = Some(trace.clone());
    *reputation.trace.lock().unwrap() = Some(trace.clone());
    let capture = capture(provider.clone(), reputation.clone(), 8);
    provider.state.lock().unwrap().calls.clear();
    trace.lock().unwrap().clear();
    let deadline = test_deadline();
    let request = request(
        "one-original-deadline",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    let record = capture.admit(&request, deadline).unwrap();
    assert_eq!(
        record.outcome.status,
        StreamTokenValidationStatusV1::Accepted
    );
    assert_eq!(reputation.calls(), vec![(record, deadline)]);
    let state = provider.state.lock().unwrap();
    assert!(state.calls.iter().all(|(_, actual)| *actual == deadline));
    assert!(
        state
            .calls
            .iter()
            .all(|(phase, _)| *phase != "qualification"),
        "purpose proofs must not add redundant standalone Qualification transactions"
    );
    for phase in ["pending", "admit", "acknowledge", "confirm_serving"] {
        assert!(
            state.calls.iter().any(|(actual, _)| *actual == phase),
            "missing phase {phase}"
        );
    }
    assert_eq!(state.acknowledged_through, 1);
    drop(state);
    let trace = trace.lock().unwrap();
    let callback = trace.iter().position(|phase| *phase == "callback").unwrap();
    let ack = trace
        .iter()
        .position(|phase| *phase == "acknowledge")
        .unwrap();
    let serving = trace
        .iter()
        .position(|phase| *phase == "confirm_serving")
        .unwrap();
    assert!(callback < ack && ack < serving);
    assert_eq!(
        trace.last(),
        Some(&"confirm_serving"),
        "no provider or callback work follows the final serving handoff"
    );
}

#[test]
fn final_serving_proof_failure_prevents_accepted_return_after_callback_success() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(provider.clone(), reputation.clone(), 8);
    provider.state.lock().unwrap().serving_unavailable = true;
    let request = request(
        "failed-final-serving",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    assert_eq!(
        capture.admit(&request, test_deadline()),
        Err(StreamTokenGatewayAdmissionErrorV1::Unavailable)
    );
    assert_eq!(reputation.calls().len(), 1);
    assert_eq!(provider.acknowledged_through(), 1);
    assert_eq!(
        provider.state.lock().unwrap().calls.last().unwrap().0,
        "confirm_serving"
    );
}

#[test]
fn final_serving_record_substitution_prevents_accepted_return() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(provider.clone(), reputation.clone(), 8);
    provider.state.lock().unwrap().serving_substituted = true;
    let request = request(
        "substituted-final-serving",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    assert_eq!(
        capture.admit(&request, test_deadline()),
        Err(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome)
    );
    assert_eq!(reputation.calls().len(), 1);
    assert_eq!(provider.acknowledged_through(), 1);
}

#[test]
fn configured_identity_is_only_a_pin_and_startup_still_live_qualifies() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(provider.clone(), reputation.clone(), 8);
    assert_eq!(provider.configured_qualification(), qualification());
    assert_eq!(
        provider
            .state
            .lock()
            .unwrap()
            .calls
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
        vec!["qualification"],
        "construction performs exactly one live qualification"
    );
    capture
        .validate_expected_binding(HANDLE, qualification(), 8, Duration::from_secs(60))
        .unwrap();
    assert_eq!(provider.state.lock().unwrap().calls.len(), 2);
    provider.state.lock().unwrap().qualification_unavailable = true;
    assert_eq!(
        capture.validate_expected_binding(HANDLE, qualification(), 8, Duration::from_secs(60)),
        Err(StreamTokenGatewayAdmissionErrorV1::Unavailable),
        "matching configured pins cannot replace fresh launch authority"
    );
    provider.state.lock().unwrap().qualification_unavailable = false;
    provider.state.lock().unwrap().admission_unavailable = true;
    let request = request(
        "same-pins-unavailable-purpose",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    assert_eq!(
        capture.admit(&request, test_deadline()),
        Err(StreamTokenGatewayAdmissionErrorV1::Unavailable)
    );
    assert!(reputation.calls().is_empty());
    assert!(provider.state.lock().unwrap().records.is_empty());
}

#[test]
fn substituted_configured_identity_rejects_before_live_qualification() {
    let mut provider = DurableProvider::new();
    provider.configured_qualification.policy_digest[0] ^= 1;
    let provider = Arc::new(provider);
    assert!(matches!(
        StreamTokenAdmissionCaptureV1::try_new(
            HANDLE,
            qualification(),
            8,
            Duration::from_secs(60),
            provider.clone(),
            Arc::new(ReputationProbe::default()),
        ),
        Err(StreamTokenGatewayAdmissionErrorV1::BindingMismatch)
    ));
    assert!(provider.state.lock().unwrap().calls.is_empty());
}

#[test]
fn native_delivery_binding_substitution_rejects_startup() {
    let reputation = Arc::new(ReputationProbe::default());
    reputation.wrong_binding.store(1, Ordering::Release);
    let result = StreamTokenAdmissionCaptureV1::try_new(
        HANDLE,
        qualification(),
        8,
        Duration::from_secs(60),
        Arc::new(DurableProvider::new()),
        reputation,
    );
    assert!(matches!(
        result,
        Err(StreamTokenGatewayAdmissionErrorV1::BindingMismatch)
    ));
}

#[test]
fn native_delivery_binding_drift_rejects_before_any_operation_work() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(provider.clone(), reputation.clone(), 8);
    provider.state.lock().unwrap().calls.clear();
    reputation.wrong_binding.store(1, Ordering::Release);
    let request = request(
        "delivery-binding-drift",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    assert_eq!(
        capture.admit(&request, test_deadline()),
        Err(StreamTokenGatewayAdmissionErrorV1::StaleOrRevoked)
    );
    assert!(reputation.calls().is_empty());
    assert!(provider.state.lock().unwrap().calls.is_empty());
}

#[test]
fn background_idle_and_recovery_keep_binding_errors_and_one_deadline() {
    let provider = Arc::new(DurableProvider::new());
    let reputation = Arc::new(ReputationProbe::default());
    let capture = capture(provider.clone(), reputation.clone(), 8);
    assert_eq!(
        capture.reconcile_background().unwrap(),
        StreamTokenReconciliationOutcomeV1::Idle
    );
    assert!(reputation.calls().is_empty());
    provider.state.lock().unwrap().qualification_unavailable = true;
    assert_eq!(
        capture.reconcile_background(),
        Err(StreamTokenGatewayAdmissionErrorV1::Unavailable)
    );
    provider.state.lock().unwrap().qualification_unavailable = false;
    reputation.wrong_binding.store(1, Ordering::Release);
    assert_eq!(
        capture.reconcile_background(),
        Err(StreamTokenGatewayAdmissionErrorV1::StaleOrRevoked)
    );
    reputation.wrong_binding.store(0, Ordering::Release);

    // Work arrives via the shared provider after this capture has reported Idle.
    let request = request(
        "background-recovery",
        VALIDATED_AT_MS,
        VALIDATED_AT_MS / 1_000 + 600,
        2,
    );
    let record = provider.admit(&request, test_deadline()).unwrap().record;
    reputation.fail_once();
    assert_eq!(
        capture.reconcile_background(),
        Err(StreamTokenGatewayAdmissionErrorV1::ReputationCallback)
    );
    assert_eq!(provider.acknowledged_through(), 0);
    provider.state.lock().unwrap().calls.clear();
    assert_eq!(
        capture.reconcile_background().unwrap(),
        StreamTokenReconciliationOutcomeV1::Reconciled(1)
    );
    assert_eq!(provider.acknowledged_through(), 1);
    let state = provider.state.lock().unwrap();
    let deadline = state.calls[0].1;
    assert!(state.calls.iter().all(|(_, actual)| *actual == deadline));
    assert_eq!(reputation.calls(), vec![(record, deadline)]);
    drop(state);
    assert_eq!(
        capture.reconcile_background().unwrap(),
        StreamTokenReconciliationOutcomeV1::Idle
    );
}
