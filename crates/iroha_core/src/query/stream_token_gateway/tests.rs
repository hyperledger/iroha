//! Pure transition fixtures only; these maps provide no committed State or finality evidence.

use std::collections::{BTreeMap, BTreeSet};

use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    sorafs::{
        capacity::ProviderId,
        reputation::{
            ReputationJournalEventIdV1, StreamTokenExcludedKindV1, StreamTokenRequestRouteV1,
            StreamTokenValidationRequestContextV1, StreamTokenValidationStatusV1 as Status,
            StreamTokenViolationKindV1 as Violation, derive_stream_token_gateway_id_v1,
            stream_token_delivery::StreamTokenReputationDeliveryDispositionV1 as Disposition,
        },
        stream_token_gateway::{
            StreamTokenGatewayAdmissionAckV1 as Ack, StreamTokenGatewayAdmissionQualificationV1,
            StreamTokenGatewayAdmissionRecordV1 as Record,
            StreamTokenGatewayAdmissionRequestV1 as Request, StreamTokenGatewayQuotaRequestV1,
            native::{StreamTokenGatewayExecutionV1, StreamTokenGatewayPolicyV1},
        },
    },
};

use crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::DeliveryState;

use super::{
    rows::*,
    transition::{self, TransitionInputs},
};

const NOW: u64 = 1_000_000;

#[derive(Clone, Default)]
struct MemoryRows {
    values: BTreeMap<GatewayRowKey, GatewayRow>,
    scripted_expiry: Option<Vec<GatewayExpiryKeyV1>>,
}

impl GatewayRows for MemoryRows {
    fn read(&self, key: &GatewayRowKey) -> Result<Option<GatewayRow>, TransitionError> {
        Ok(self.values.get(key).cloned())
    }
    fn expiry_prefix(
        &self,
        now: u64,
        max_items: u32,
    ) -> Result<Vec<GatewayExpiryKeyV1>, TransitionError> {
        if let Some(keys) = &self.scripted_expiry {
            return Ok(keys.clone());
        }
        Ok(self
            .values
            .keys()
            .filter_map(|key| match key {
                GatewayRowKey::Expiry(key) if key.at_unix_ms <= now => Some(*key),
                _ => None,
            })
            .take(max_items as usize)
            .collect())
    }
}

fn account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

fn policy() -> StreamTokenGatewayPolicyV1 {
    let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"synthetic gateway transition network",
    )));
    let mut policy = StreamTokenGatewayPolicyV1 {
        network_id,
        compliance_gateway_id: "gateway.test-1".into(),
        qualification: StreamTokenGatewayAdmissionQualificationV1 {
            gateway_id: derive_stream_token_gateway_id_v1(&network_id, "gateway.test-1").unwrap(),
            revision: 1,
            policy_digest: [0; 32],
            max_pending: 64,
            max_tracked_tokens: 64,
            lease_ttl_ms: 120_000,
        },
        operators: BTreeSet::from([account(1)]),
        observers: BTreeSet::from([account(2)]),
        valid_from_unix_ms: 1,
        valid_until_unix_ms: NOW + 1_000_000,
        max_observation_age_ms: 300_000,
        admission_enabled: true,
    };
    policy.qualification.policy_digest = policy.calculate_policy_digest().unwrap();
    policy.validate().unwrap();
    policy
}

fn request(nonce: &str, now: u64) -> Request {
    Request {
        serving_attempt_id: *Hash::new(nonce.as_bytes()).as_ref(),
        context: StreamTokenValidationRequestContextV1::try_new(
            ProviderId::new([0x41; 32]),
            [0x42; 32],
            sorafs_manifest::canonical_manifest_root_cid([0x43; 32]),
            "sorafs.sf1@1.0.0".into(),
            nonce,
            Some(b"Q2Fub25pY2FsVG9rZW4="),
            StreamTokenRequestRouteV1::car_range(64, 1_023).unwrap(),
        )
        .unwrap(),
        token_body_digest: Some([0x44; 32]),
        token_key_version: Some(3),
        validated_at_unix_ms: now,
        status: Status::Accepted,
        quota: Some(StreamTokenGatewayQuotaRequestV1 {
            token_id: "11".repeat(16),
            max_streams: 4,
            requests_per_minute: 120,
            rate_limit_bytes: 1_048_576,
            requested_bytes: 960,
            expires_at_epoch: (NOW + 600_000) / 1_000,
            observed_at_epoch: now / 1_000,
        }),
    }
}

struct Fixture {
    policy: StreamTokenGatewayPolicyV1,
    head: GatewayHeadV1,
    rows: MemoryRows,
}

impl Fixture {
    fn new() -> Self {
        Self {
            policy: policy(),
            head: GatewayHeadV1::default(),
            rows: MemoryRows::default(),
        }
    }
    fn execution(&self, now: u64) -> StreamTokenGatewayExecutionV1 {
        StreamTokenGatewayExecutionV1 {
            height: self.head.revision + 1,
            transaction_hash: *Hash::new(self.head.revision.to_be_bytes()).as_ref(),
            entry_index: 0,
            instruction_index: 0,
            recorded_at_unix_ms: now,
            authority: account(1),
        }
    }
    fn input<'a>(&'a self, execution: &'a StreamTokenGatewayExecutionV1) -> TransitionInputs<'a> {
        TransitionInputs {
            policy: &self.policy,
            head: self.head,
            execution,
        }
    }
    fn apply(&mut self, delta: TransitionDelta) -> TransitionResult {
        assert_eq!(self.head, delta.before);
        assert!(delta.writes.len() <= MAX_TRANSITION_WRITES);
        assert!(
            delta
                .writes
                .windows(2)
                .all(|pair| pair[0].key < pair[1].key)
        );
        for write in &delta.writes {
            assert_eq!(self.rows.values.get(&write.key), write.before.as_ref());
        }
        for write in delta.writes {
            match write.after {
                Some(row) => {
                    self.rows.values.insert(write.key, row);
                }
                None => {
                    self.rows.values.remove(&write.key);
                }
            }
        }
        self.head = delta.after;
        delta.result
    }
    fn admit(&mut self, request: &Request, now: u64) -> Record {
        let execution = self.execution(now);
        let delta = transition::admit(self.input(&execution), &self.rows, request).unwrap();
        let TransitionResult::Admission(result) = self.apply(delta) else {
            panic!("admission result");
        };
        result.record
    }
    // This engine fixture supplies terminal inputs, not a claim of signed journal authority.
    // The World adapter and certified handler/proof fixtures authenticate the actual source.
    fn delivery(&self, record: &Record) -> DeliveryState {
        let source_digest = *Hash::new(norito::encode_canonical(record).unwrap()).as_ref();
        let original = match self.rows.values.get(&GatewayRowKey::Admission(
            record.outcome.binding.gateway_sequence,
        )) {
            Some(GatewayRow::Admission(original)) => original,
            _ => panic!("original engine source"),
        };
        DeliveryState {
            source_digest,
            disposition: if record.outcome.status.counts_for_provider() {
                Disposition::Delivered {
                    journal_sequence: record.outcome.binding.gateway_sequence,
                    event_id: ReputationJournalEventIdV1(source_digest),
                    execution: original.execution.clone(),
                }
            } else {
                Disposition::Excluded
            },
        }
    }
    fn ack(&mut self, record: &Record, now: u64) -> Ack {
        let execution = self.execution(now);
        let delta = transition::acknowledge(
            self.input(&execution),
            &self.rows,
            record,
            self.delivery(record),
        )
        .unwrap();
        let TransitionResult::Acknowledged(result) = self.apply(delta) else {
            panic!("ack result");
        };
        result
    }
    fn release(&mut self, record: &Record, now: u64) -> Ack {
        let execution = self.execution(now);
        let delta = transition::release_lease(self.input(&execution), &self.rows, record).unwrap();
        let TransitionResult::Released(result) = self.apply(delta) else {
            panic!("release result");
        };
        result
    }
    fn expire(&mut self, now: u64, limit: u32) -> u32 {
        let execution = self.execution(now);
        let delta = transition::expire(self.input(&execution), &self.rows, limit).unwrap();
        let TransitionResult::Expired(result) = self.apply(delta) else {
            panic!("expiry result");
        };
        result
    }
    fn revise_policy(&mut self, update: impl FnOnce(&mut StreamTokenGatewayPolicyV1)) {
        let original = self.policy.clone();
        self.policy.qualification.revision += 1;
        update(&mut self.policy);
        self.policy.qualification.policy_digest = self.policy.calculate_policy_digest().unwrap();
        self.policy.validate_replacement(&original).unwrap();
    }
}

#[test]
fn gateway_transition_replay_preserves_original_rows_and_acknowledged_result() {
    let mut fixture = Fixture::new();
    let request = request("nonce-original", NOW);
    let original = fixture.admit(&request, NOW + 100);
    let encoded = norito::encode_canonical(&original).unwrap();
    let rows = fixture.rows.values.clone();
    let head = fixture.head;
    assert_eq!(fixture.admit(&request, NOW + 200), original);
    assert_eq!(fixture.head, head);
    assert_eq!(fixture.rows.values, rows);
    assert_eq!(fixture.ack(&original, NOW + 201,), Ack::Acknowledged);
    let execution = fixture.execution(NOW + 202);
    let delta = transition::admit(fixture.input(&execution), &fixture.rows, &request).unwrap();
    let TransitionResult::Admission(replay) = &delta.result else {
        panic!("admission");
    };
    assert!(matches!(replay.delivery_state,
        iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionDeliveryStateV1::AcknowledgedExactReplay { acknowledged_through_sequence: 1 }));
    assert_eq!(norito::encode_canonical(&replay.record).unwrap(), encoded);
    assert!(delta.writes.is_empty());
    let mut changed = request;
    changed.validated_at_unix_ms += 1;
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &changed).unwrap_err(),
        TransitionError::Conflict
    );
}

#[test]
fn gateway_transition_quota_windows_use_execution_time_and_release_never_refunds() {
    let mut fixture = Fixture::new();
    let mut one = request("quota-one", NOW);
    one.quota.as_mut().unwrap().requests_per_minute = 1;
    let first = fixture.admit(&one, NOW + 5_000);
    assert_eq!(fixture.release(&first, NOW + 5_001,), Ack::Acknowledged);
    let mut two = request("quota-two", NOW + 60_000);
    two.quota = one.quota.clone();
    two.quota.as_mut().unwrap().observed_at_epoch = two.validated_at_unix_ms / 1_000;
    let denied = fixture.admit(&two, NOW + 60_000);
    assert_eq!(
        denied.outcome.status,
        Status::ProviderViolation(Violation::RequestQuotaExceeded)
    );
    assert_eq!(denied.retry_after_secs, Some(5));
    let mut three = request("quota-three", NOW + 65_000);
    three.quota = two.quota;
    three.quota.as_mut().unwrap().observed_at_epoch = three.validated_at_unix_ms / 1_000;
    assert_eq!(
        fixture.admit(&three, NOW + 65_000).outcome.status,
        Status::Accepted
    );
}

#[test]
fn gateway_transition_byte_rate_and_concurrency_are_atomic() {
    let mut fixture = Fixture::new();
    let mut first_request = request("bytes-first", NOW);
    first_request.quota.as_mut().unwrap().rate_limit_bytes = 960;
    first_request.quota.as_mut().unwrap().max_streams = 1;
    let first = fixture.admit(&first_request, NOW);
    let mut second = request("bytes-second", NOW);
    second.quota = first_request.quota.clone();
    let concurrent = fixture.admit(&second, NOW);
    assert_eq!(
        concurrent.outcome.status,
        Status::ProviderViolation(Violation::ConcurrencyLimitExceeded)
    );
    assert_eq!(fixture.release(&first, NOW,), Ack::Acknowledged);
    let mut third = request("bytes-third", NOW + 999);
    third.quota = first_request.quota.clone();
    let denied = fixture.admit(&third, NOW + 999);
    assert_eq!(
        denied.outcome.status,
        Status::ProviderViolation(Violation::ByteRateLimitExceeded)
    );
    assert_eq!(denied.retry_after_secs, Some(1));
    let mut fourth = request("bytes-fourth", NOW + 1_000);
    fourth.quota = first_request.quota;
    fourth.quota.as_mut().unwrap().observed_at_epoch += 1;
    assert_eq!(
        fixture.admit(&fourth, NOW + 1_000).outcome.status,
        Status::Accepted
    );
}

#[test]
fn gateway_transition_consensus_delay_never_rebases_original_lease() {
    let mut fixture = Fixture::new();
    fixture.revise_policy(|policy| policy.qualification.lease_ttl_ms = 1_000);
    let one = request("late-original", NOW);
    let execution = fixture.execution(NOW + 1_000);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &one).unwrap_err(),
        TransitionError::Unavailable
    );
    assert!(fixture.rows.values.is_empty());
    let record = fixture.admit(&one, NOW + 999);
    assert_eq!(record.lease_expires_at_unix_ms, Some(NOW + 1_000));
    assert_eq!(record.outcome.validated_at_unix_ms, NOW);
    let mut expired = request("invalid-expiry", NOW);
    expired.quota.as_mut().unwrap().expires_at_epoch = NOW / 1_000;
    let execution = fixture.execution(NOW + 999);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &expired).unwrap_err(),
        TransitionError::Invalid
    );
}

#[test]
fn gateway_transition_expiry_is_bounded_and_keeps_permanent_history() {
    let mut fixture = Fixture::new();
    let request = request("expire-original", NOW);
    let record = fixture.admit(&request, NOW);
    let at = record.lease_expires_at_unix_ms.unwrap();
    let fresh = request_with_nonce("expire-next", at);
    let execution = fixture.execution(at);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &fresh).unwrap_err(),
        TransitionError::MaintenanceRequired
    );
    assert_eq!(fixture.expire(at, 1), 1);
    assert_eq!(fixture.head.live_tokens, 1);
    assert_eq!(fixture.expire(at, 1), 1);
    assert_eq!(fixture.head.live_tokens, 0);
    assert_eq!(fixture.expire(at, 1), 0);
    assert_eq!(fixture.release(&record, at,), Ack::ExactReplay);
    let execution = fixture.execution(at);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &request).unwrap_err(),
        TransitionError::Unavailable
    );
    let Some(GatewayRow::Admission(original)) =
        fixture.rows.values.get(&GatewayRowKey::Admission(1))
    else {
        panic!("retained original");
    };
    assert_eq!(original.record, record);
    assert_eq!(
        fixture
            .rows
            .values
            .iter()
            .filter(|(key, _)| matches!(
                key,
                GatewayRowKey::Admission(_)
                    | GatewayRowKey::Acknowledgement(_)
                    | GatewayRowKey::Context(_)
                    | GatewayRowKey::TokenIdentity(_)
                    | GatewayRowKey::QuotaLifecycle(_)
                    | GatewayRowKey::Lease(_)
                    | GatewayRowKey::LeaseTerminal(_)
            ))
            .count(),
        6
    );
    assert_eq!(
        fixture.admit(&fresh, at).outcome.binding.gateway_sequence,
        2
    );
}

fn request_with_nonce(nonce: &str, now: u64) -> Request {
    request(nonce, now)
}

#[test]
fn gateway_transition_rotation_preserves_original_policy_and_drains_disabled_gateway() {
    let mut fixture = Fixture::new();
    let request = request("rotate-original", NOW);
    let record = fixture.admit(&request, NOW);
    fixture.revise_policy(|policy| {
        policy.qualification.lease_ttl_ms = 1_000;
        policy.qualification.max_pending = 1;
        policy.qualification.max_tracked_tokens = 1;
    });
    assert_eq!(fixture.admit(&request, NOW + 1), record);
    assert_ne!(record.admitted_under, fixture.policy.qualification);
    fixture.revise_policy(|policy| policy.admission_enabled = false);
    let execution = fixture.execution(NOW + 2);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &request).unwrap_err(),
        TransitionError::Unavailable
    );
    assert_eq!(fixture.ack(&record, NOW + 2,), Ack::Acknowledged);
    assert_eq!(fixture.release(&record, NOW + 2,), Ack::Acknowledged);
    assert_eq!(fixture.ack(&record, NOW + 3,), Ack::ExactReplay);
    assert_eq!(fixture.release(&record, NOW + 3,), Ack::ExactReplay);
}

#[test]
fn gateway_transition_capacity_never_evicts_pending_or_live_rows() {
    let mut fixture = Fixture::new();
    fixture.revise_policy(|policy| {
        policy.qualification.max_pending = 1;
        policy.qualification.max_tracked_tokens = 1;
    });
    let first = fixture.admit(&request("capacity-first", NOW), NOW);
    let second = request("capacity-second", NOW);
    let execution = fixture.execution(NOW);
    let before = fixture.rows.values.clone();
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &second).unwrap_err(),
        TransitionError::Capacity
    );
    assert_eq!(fixture.rows.values, before);
    fixture.ack(&first, NOW);
    let mut second = second;
    second.quota.as_mut().unwrap().token_id = "22".repeat(16);
    let execution = fixture.execution(NOW);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &second).unwrap_err(),
        TransitionError::Capacity
    );
    assert_eq!(fixture.head.live_tokens, 1);
    assert_eq!(fixture.head.high_water_sequence, 1);
}

#[test]
fn gateway_transition_ack_order_and_substituted_lease_fail_closed() {
    let mut fixture = Fixture::new();
    let first = fixture.admit(&request("ack-first", NOW), NOW);
    let second = fixture.admit(&request("ack-second", NOW), NOW);
    let execution = fixture.execution(NOW);
    assert_eq!(
        transition::acknowledge(
            fixture.input(&execution),
            &fixture.rows,
            &second,
            fixture.delivery(&second,)
        )
        .unwrap_err(),
        TransitionError::Conflict
    );
    let mut changed = first;
    changed.lease_id = second.lease_id;
    assert_eq!(
        transition::release_lease(fixture.input(&execution), &fixture.rows, &changed).unwrap_err(),
        TransitionError::Conflict
    );
    fixture.ack(&first, NOW);
    fixture.ack(&second, NOW);
    assert_eq!(fixture.head.acknowledged_through_sequence, 2);
}

#[test]
fn gateway_transition_permanent_identity_rejects_changed_token_after_live_retirement() {
    let mut fixture = Fixture::new();
    let record = fixture.admit(&request("identity-first", NOW), NOW);
    let expiry = record.lease_expires_at_unix_ms.unwrap();
    fixture.expire(expiry, 2);
    let mut changed = request("identity-changed", expiry);
    changed.token_body_digest = Some([0x55; 32]);
    let conflict = fixture.admit(&changed, expiry);
    assert_eq!(
        conflict.outcome.status,
        Status::ProviderViolation(Violation::IdentifierPolicyConflict)
    );
    assert_eq!(fixture.head.live_tokens, 0);
    assert!(conflict.lease_id.is_none());
}

#[test]
fn gateway_transition_rejects_bad_expiry_prefix_or_substituted_index_atomically() {
    let mut fixture = Fixture::new();
    let record = fixture.admit(&request("expiry-bad", NOW), NOW);
    let at = record.lease_expires_at_unix_ms.unwrap();
    let keys = fixture.rows.expiry_prefix(at, 3).unwrap();
    assert_eq!(keys.len(), 2);
    for bad in [
        vec![keys[0], keys[0]],
        vec![keys[1], keys[0]],
        vec![GatewayExpiryKeyV1 {
            at_unix_ms: at + 1,
            target: keys[0].target,
        }],
        vec![keys[0]; 3],
    ] {
        fixture.rows.scripted_expiry = Some(bad);
        let execution = fixture.execution(at);
        assert_eq!(
            transition::expire(fixture.input(&execution), &fixture.rows, 1).unwrap_err(),
            TransitionError::CorruptHistory
        );
    }
    fixture.rows.scripted_expiry = None;
    fixture
        .rows
        .values
        .insert(GatewayRowKey::Expiry(keys[0]), GatewayRow::Expiry(keys[1]));
    let execution = fixture.execution(at);
    assert_eq!(
        transition::expire(fixture.input(&execution), &fixture.rows, 2).unwrap_err(),
        TransitionError::CorruptHistory
    );
    assert_eq!(fixture.head.high_water_sequence, 1);
    assert_eq!(fixture.head.live_tokens, 1);
}

#[test]
fn gateway_transition_excluded_attestation_cannot_poison_quota_identity() {
    let mut fixture = Fixture::new();
    let mut excluded = request("invalid-signature", NOW);
    excluded.status = Status::Excluded(StreamTokenExcludedKindV1::InvalidSignature);
    let record = fixture.admit(&excluded, NOW);
    assert_eq!(record.outcome.status, excluded.status);
    assert_eq!(fixture.head.live_tokens, 0);
    assert!(!fixture.rows.values.keys().any(|key| matches!(
        key,
        GatewayRowKey::TokenIdentity(_) | GatewayRowKey::Lease(_)
    )));
    assert_eq!(
        fixture
            .admit(&request("valid-next", NOW), NOW)
            .outcome
            .status,
        Status::Accepted
    );
}

#[test]
fn gateway_transition_source_rows_roundtrip_and_old_deltas_conflict() {
    let mut fixture = Fixture::new();
    let execution = fixture.execution(NOW);
    let original = transition::admit(
        fixture.input(&execution),
        &fixture.rows,
        &request("race-one", NOW),
    )
    .unwrap();
    let other = transition::admit(
        fixture.input(&execution),
        &fixture.rows,
        &request("race-two", NOW),
    )
    .unwrap();
    fixture.apply(original);
    assert_ne!(fixture.head, other.before);
    assert!(
        other
            .writes
            .iter()
            .any(|write| fixture.rows.values.get(&write.key) != write.before.as_ref())
    );
    let Some(GatewayRow::Admission(row)) = fixture.rows.values.get(&GatewayRowKey::Admission(1))
    else {
        panic!("retained original");
    };
    let encoded = norito::encode_canonical(row).unwrap();
    assert_eq!(
        norito::decode_canonical::<AdmissionRowV1>(&encoded).unwrap(),
        *row
    );
    let encoded = norito::encode_canonical(&fixture.head).unwrap();
    assert_eq!(
        norito::decode_canonical::<GatewayHeadV1>(&encoded).unwrap(),
        fixture.head
    );
    let execution = fixture.execution(NOW - 1);
    assert_eq!(
        transition::expire(fixture.input(&execution), &fixture.rows, 1).unwrap_err(),
        TransitionError::CorruptHistory
    );
}

#[test]
fn gateway_transition_rejects_corrupt_terminal_history_and_impossible_clocks() {
    let mut fixture = Fixture::new();
    let record = fixture.admit(&request("terminal-original", NOW), NOW);
    fixture.release(&record, NOW + 1);
    let key = GatewayRowKey::LeaseTerminal(record.lease_id.unwrap());
    let Some(GatewayRow::LeaseTerminal(original)) = fixture.rows.values.get(&key).cloned() else {
        panic!("terminal fact");
    };
    let mut invalid = Vec::new();
    let mut terminal = original.clone();
    terminal.grant.sequence += 1;
    invalid.push(terminal);
    let mut terminal = original.clone();
    terminal.execution.height = 0;
    invalid.push(terminal);
    let mut terminal = original.clone();
    terminal.execution.transaction_hash = [0; 32];
    invalid.push(terminal);
    let mut terminal = original.clone();
    terminal.execution.recorded_at_unix_ms = fixture.head.last_execution_unix_ms + 1;
    invalid.push(terminal);
    let mut terminal = original.clone();
    terminal.expired = true;
    invalid.push(terminal);
    for terminal in invalid {
        fixture
            .rows
            .values
            .insert(key.clone(), GatewayRow::LeaseTerminal(terminal));
        let execution = fixture.execution(NOW + 2);
        assert_eq!(
            transition::release_lease(fixture.input(&execution), &fixture.rows, &record)
                .unwrap_err(),
            TransitionError::CorruptHistory
        );
    }
    fixture
        .rows
        .values
        .insert(key, GatewayRow::LeaseTerminal(original));
    let execution = fixture.execution(u64::MAX);
    assert_eq!(
        transition::expire(fixture.input(&execution), &fixture.rows, 1).unwrap_err(),
        TransitionError::CorruptHistory
    );
    fixture.head.last_execution_unix_ms = 0;
    let execution = fixture.execution(NOW + 2);
    assert_eq!(
        transition::expire(fixture.input(&execution), &fixture.rows, 1).unwrap_err(),
        TransitionError::CorruptHistory
    );
}

#[test]
fn gateway_transition_request_digest_and_maintenance_limits_are_independently_checked() {
    let fixture = Fixture::new();
    let mut invalid = request("digest-invalid", NOW);
    let original = transition::request_digest(&invalid).unwrap();
    invalid.token_body_digest = Some([0x77; 32]);
    assert_ne!(transition::request_digest(&invalid).unwrap(), original);
    invalid.quota.as_mut().unwrap().token_id = "x".repeat(100_000);
    assert_eq!(
        transition::request_digest(&invalid).unwrap_err(),
        TransitionError::Invalid
    );
    let execution = fixture.execution(NOW);
    let mut distant_expiry = request("distant-expiry", NOW);
    distant_expiry.quota.as_mut().unwrap().expires_at_epoch = NOW / 1_000
        + sorafs_manifest::token::STREAM_TOKEN_MAX_TTL_SECS_V1
        + sorafs_manifest::token::STREAM_TOKEN_MAX_FUTURE_SKEW_SECS_V1;
    let at_bound =
        transition::admit(fixture.input(&execution), &fixture.rows, &distant_expiry).unwrap();
    assert!(
        matches!(at_bound.result, TransitionResult::Admission(result) if result.record.outcome.status == Status::Accepted)
    );
    distant_expiry.quota.as_mut().unwrap().expires_at_epoch += 1;
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &distant_expiry).unwrap_err(),
        TransitionError::Invalid
    );
    assert!(fixture.rows.values.is_empty());
    for limit in [0, MAX_EXPIRY_ITEMS + 1, u32::MAX] {
        assert_eq!(
            transition::expire(fixture.input(&execution), &fixture.rows, limit).unwrap_err(),
            TransitionError::Invalid
        );
    }
    let mut expired_observation = request("old-observation", NOW);
    expired_observation.validated_at_unix_ms = NOW - fixture.policy.max_observation_age_ms - 1;
    expired_observation
        .quota
        .as_mut()
        .unwrap()
        .observed_at_epoch = expired_observation.validated_at_unix_ms / 1_000;
    assert_eq!(
        transition::admit(
            fixture.input(&execution),
            &fixture.rows,
            &expired_observation
        )
        .unwrap_err(),
        TransitionError::Unavailable
    );
    let future = request("future-observation", NOW + 1);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &future).unwrap_err(),
        TransitionError::Unavailable
    );
}

#[test]
fn gateway_transition_new_worker_or_terminal_lease_cannot_reuse_serving_admission() {
    let mut fixture = Fixture::new();
    let request = request("serving-original", NOW);
    let record = fixture.admit(&request, NOW);
    let mut another_worker = request.clone();
    another_worker.serving_attempt_id = [0x88; 32];
    let execution = fixture.execution(NOW);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &another_worker).unwrap_err(),
        TransitionError::Conflict
    );
    assert_eq!(fixture.release(&record, NOW + 1,), Ack::Acknowledged);
    let execution = fixture.execution(NOW + 2);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &request).unwrap_err(),
        TransitionError::Unavailable
    );
    let Some(GatewayRow::Admission(retained)) =
        fixture.rows.values.get(&GatewayRowKey::Admission(1))
    else {
        panic!("retained callback");
    };
    assert_eq!(retained.record, record);
    assert_eq!(fixture.ack(&record, NOW + 2,), Ack::Acknowledged);
}

#[test]
fn gateway_transition_missing_live_quota_does_not_reset_concurrency() {
    let mut fixture = Fixture::new();
    let mut one = request("missing-quota-original", NOW);
    one.quota.as_mut().unwrap().max_streams = 1;
    let record = fixture.admit(&one, NOW);
    let key = fixture
        .rows
        .values
        .keys()
        .find(|key| matches!(key, GatewayRowKey::Quota(_)))
        .unwrap()
        .clone();
    let original_quota = fixture.rows.values.remove(&key).unwrap();
    let mut another = request("missing-quota-second", NOW + 1);
    another.quota = one.quota.clone();
    let execution = fixture.execution(NOW + 1);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &another).unwrap_err(),
        TransitionError::CorruptHistory
    );
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &one).unwrap_err(),
        TransitionError::CorruptHistory
    );
    fixture.rows.values.insert(key, original_quota);
    let at = record.lease_expires_at_unix_ms.unwrap();
    fixture.expire(at, 2);
    assert!(fixture.rows.values.values().any(|row| matches!(
        row,
        GatewayRow::QuotaLifecycle(QuotaLifecycleV1 {
            generation: 1,
            active: false
        })
    )));
    let mut new = request("new-quota-generation", at);
    new.quota.as_mut().unwrap().max_streams = 1;
    fixture.admit(&new, at);
    assert!(fixture.rows.values.values().any(|row| matches!(
        row,
        GatewayRow::QuotaLifecycle(QuotaLifecycleV1 {
            generation: 2,
            active: true
        })
    )));
    assert_eq!(fixture.release(&record, at,), Ack::ExactReplay);
}

#[test]
fn gateway_transition_current_operator_and_retained_execution_positions_are_checked() {
    let mut fixture = Fixture::new();
    let record = fixture.admit(&request("authority-original", NOW), NOW);
    let mut execution = fixture.execution(NOW + 1);
    execution.authority = account(2);
    assert_eq!(
        transition::acknowledge(
            fixture.input(&execution),
            &fixture.rows,
            &record,
            fixture.delivery(&record,)
        )
        .unwrap_err(),
        TransitionError::BindingMismatch
    );
    fixture.revise_policy(|policy| {
        policy.operators = BTreeSet::from([account(3)]);
    });
    execution.authority = account(1);
    assert_eq!(
        transition::release_lease(fixture.input(&execution), &fixture.rows, &record).unwrap_err(),
        TransitionError::BindingMismatch
    );
    execution.authority = account(3);
    let key = GatewayRowKey::Admission(1);
    let Some(GatewayRow::Admission(original)) = fixture.rows.values.get(&key).cloned() else {
        panic!("original");
    };
    for position in [
        (execution.height + 1, 0, 0),
        (execution.height, 1, 0),
        (execution.height, 0, 1),
    ] {
        let mut changed = original.clone();
        (
            changed.execution.height,
            changed.execution.entry_index,
            changed.execution.instruction_index,
        ) = position;
        fixture
            .rows
            .values
            .insert(key.clone(), GatewayRow::Admission(changed));
        assert_eq!(
            transition::acknowledge(
                fixture.input(&execution),
                &fixture.rows,
                &record,
                fixture.delivery(&record,)
            )
            .unwrap_err(),
            TransitionError::CorruptHistory
        );
    }
    fixture
        .rows
        .values
        .insert(key, GatewayRow::Admission(original));
    let delta = transition::acknowledge(
        fixture.input(&execution),
        &fixture.rows,
        &record,
        fixture.delivery(&record),
    )
    .unwrap();
    assert_eq!(
        fixture.apply(delta),
        TransitionResult::Acknowledged(Ack::Acknowledged)
    );
}

#[test]
fn gateway_transition_lower_caps_preserve_usage_until_obligations_drain() {
    let mut fixture = Fixture::new();
    let first_request = request("cap-lowering-first", NOW);
    let first = fixture.admit(&first_request, NOW);
    let mut second_request = request("cap-lowering-second", NOW);
    second_request.quota.as_mut().unwrap().token_id = "22".repeat(16);
    second_request.token_body_digest = Some([0x66; 32]);
    let second = fixture.admit(&second_request, NOW);
    let permanent = fixture.rows.values.clone();
    fixture.revise_policy(|policy| {
        policy.qualification.max_pending = 1;
        policy.qualification.max_tracked_tokens = 1;
    });
    assert_eq!(fixture.head.live_tokens, 2);
    assert_eq!(fixture.rows.values, permanent);
    let next = request("cap-lowering-next", NOW + 1);
    let execution = fixture.execution(NOW + 1);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &next).unwrap_err(),
        TransitionError::Capacity
    );
    fixture.ack(&first, NOW + 1);
    fixture.ack(&second, NOW + 1);
    let mut third = next;
    third.quota.as_mut().unwrap().token_id = "33".repeat(16);
    third.token_body_digest = Some([0x77; 32]);
    let execution = fixture.execution(NOW + 1);
    assert_eq!(
        transition::admit(fixture.input(&execution), &fixture.rows, &third).unwrap_err(),
        TransitionError::Capacity
    );
    let at = first.lease_expires_at_unix_ms.unwrap();
    assert_eq!(fixture.expire(at, 4), 4);
    assert_eq!(fixture.head.live_tokens, 0);
    third.validated_at_unix_ms = at;
    third.quota.as_mut().unwrap().observed_at_epoch = at / 1_000;
    let third = fixture.admit(&third, at);
    assert_eq!(third.outcome.binding.gateway_sequence, 3);
    assert_eq!(fixture.head.live_tokens, 1);
    assert_eq!(fixture.head.acknowledged_through_sequence, 2);
}

#[test]
fn acknowledgement_retains_original_execution_and_rejects_missing_history() {
    let mut fixture = Fixture::new();
    let request = request("ack-retained", NOW);
    let record = fixture.admit(&request, NOW);
    assert_eq!(fixture.ack(&record, NOW + 1,), Ack::Acknowledged);
    let key = GatewayRowKey::Acknowledgement(1);
    let original = fixture
        .rows
        .values
        .get(&key)
        .cloned()
        .expect("original ack");
    assert_eq!(fixture.ack(&record, NOW + 2,), Ack::ExactReplay);
    assert_eq!(fixture.rows.values.get(&key), Some(&original));
    let execution = fixture.execution(NOW + 3);
    let mut substituted_delivery = fixture.delivery(&record);
    substituted_delivery.source_digest[0] ^= 1;
    assert_eq!(
        transition::acknowledge(
            fixture.input(&execution),
            &fixture.rows,
            &record,
            substituted_delivery
        ),
        Err(TransitionError::Conflict),
        "exact replay retains the original authenticated reputation disposition",
    );
    assert_eq!(fixture.rows.values.get(&key), Some(&original));
    fixture.rows.values.remove(&key);
    let execution = fixture.execution(NOW + 3);
    assert_eq!(
        transition::acknowledge(
            fixture.input(&execution),
            &fixture.rows,
            &record,
            fixture.delivery(&record,)
        ),
        Err(TransitionError::CorruptHistory)
    );
    let Some(GatewayRow::Acknowledgement(mut forged)) = Some(original) else {
        panic!("ack row");
    };
    forged.execution.height = execution.height + 1;
    fixture
        .rows
        .values
        .insert(key, GatewayRow::Acknowledgement(forged));
    assert_eq!(
        transition::acknowledge(
            fixture.input(&execution),
            &fixture.rows,
            &record,
            fixture.delivery(&record,)
        ),
        Err(TransitionError::CorruptHistory)
    );
}
