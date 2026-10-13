//! Deterministic bounded native gateway quota, callback and lease transitions.
//!
//! The permitted gateway's payload-free request is an attestation of Torii validation, not
//! validator-side verification of a bearer token. This engine neither signs nor authenticates
//! transactions. The native instruction supplies direct signed execution, governed permissions
//! and atomic World publication. TODO: qualify the separate challenged certified readback owner.

use std::collections::BTreeMap;

use iroha_crypto::Hash;
use iroha_data_model::sorafs::{
    reputation::{
        StreamTokenValidationBindingV1, StreamTokenValidationOutcomeV1,
        StreamTokenValidationStatusV1 as Status, StreamTokenViolationKindV1 as Violation,
    },
    stream_token_gateway::{
        StreamTokenGatewayAdmissionAckV1 as Ack, StreamTokenGatewayAdmissionDeliveryStateV1,
        StreamTokenGatewayAdmissionRecordV1 as Record,
        StreamTokenGatewayAdmissionRequestV1 as Request, StreamTokenGatewayAdmissionResultV1,
        native::{StreamTokenGatewayExecutionV1, StreamTokenGatewayPolicyV1},
    },
};
use sorafs_manifest::token::{
    STREAM_TOKEN_MAX_FUTURE_SKEW_SECS_V1, STREAM_TOKEN_MAX_RATE_LIMIT_BYTES_V1,
    STREAM_TOKEN_MAX_REQUESTS_PER_MINUTE_V1, STREAM_TOKEN_MAX_STREAMS_V1,
    STREAM_TOKEN_MAX_TTL_SECS_V1,
};

use super::{
    read::{self, GatewayReadCut},
    rows::*,
};

const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Independently loaded current policy, head and actual native execution coordinates.
pub(crate) struct TransitionInputs<'a> {
    /// Current governed policy; its identity does not authorize the signed caller by itself.
    pub policy: &'a StreamTokenGatewayPolicyV1,
    /// Exact same-State gateway head before this instruction.
    pub head: GatewayHeadV1,
    /// Actual direct signed native execution, never taken from submitted request fields.
    pub execution: &'a StreamTokenGatewayExecutionV1,
}

struct Prepared<'a, R> {
    input: TransitionInputs<'a>,
    rows: &'a R,
    writes: BTreeMap<GatewayRowKey, GatewayRowWrite>,
    head: GatewayHeadV1,
}

impl<'a, R: GatewayRows> Prepared<'a, R> {
    fn new(input: TransitionInputs<'a>, rows: &'a R) -> Result<Self, TransitionError> {
        input
            .policy
            .validate()
            .map_err(|_| TransitionError::BindingMismatch)?;
        if !input.policy.operators.contains(&input.execution.authority) {
            return Err(TransitionError::BindingMismatch);
        }
        let execution_precedes_head =
            input.execution.recorded_at_unix_ms < input.head.last_execution_unix_ms;
        if input.execution.height == 0
            || input.execution.transaction_hash == [0; 32]
            || input.execution.recorded_at_unix_ms == 0
            || input.execution.recorded_at_unix_ms == u64::MAX
            || execution_precedes_head
            || input.head.acknowledged_through_sequence > input.head.high_water_sequence
            || (input.head.revision == 0 && input.head != GatewayHeadV1::default())
            || (input.head.revision != 0 && input.head.last_execution_unix_ms == 0)
            || input.head.revision < input.head.high_water_sequence
            || u64::from(input.head.live_tokens) > input.head.high_water_sequence
        {
            return Err(TransitionError::CorruptHistory);
        }
        Ok(Self {
            head: input.head,
            input,
            rows,
            writes: BTreeMap::new(),
        })
    }

    fn get(&self, key: &GatewayRowKey) -> Result<Option<GatewayRow>, TransitionError> {
        match self.writes.get(key) {
            Some(write) => Ok(write.after.clone()),
            None => self.rows.read(key),
        }
    }

    fn put(
        &mut self,
        key: GatewayRowKey,
        after: Option<GatewayRow>,
    ) -> Result<(), TransitionError> {
        if let Some(write) = self.writes.get_mut(&key) {
            write.after = after;
            return Ok(());
        }
        if self.writes.len() >= MAX_TRANSITION_WRITES {
            return Err(TransitionError::Capacity);
        }
        let before = self.rows.read(&key)?;
        self.writes
            .insert(key.clone(), GatewayRowWrite { key, before, after });
        Ok(())
    }

    fn insert(&mut self, key: GatewayRowKey, row: GatewayRow) -> Result<(), TransitionError> {
        if self.get(&key)?.is_some() {
            return Err(TransitionError::CorruptHistory);
        }
        self.put(key, Some(row))
    }

    fn marker(&mut self, key: GatewayExpiryKeyV1) -> Result<(), TransitionError> {
        self.insert(GatewayRowKey::Expiry(key), GatewayRow::Expiry(key))
    }

    fn remove_marker(&mut self, key: GatewayExpiryKeyV1) -> Result<(), TransitionError> {
        if self.get(&GatewayRowKey::Expiry(key))? != Some(GatewayRow::Expiry(key)) {
            return Err(TransitionError::CorruptHistory);
        }
        self.put(GatewayRowKey::Expiry(key), None)
    }

    fn quota(&self, scope: [u8; 32]) -> Result<Option<QuotaRowV1>, TransitionError> {
        read::quota(scope, self.input.execution.recorded_at_unix_ms, |key| {
            self.get(key)
        })
    }

    fn lifecycle(&self, scope: [u8; 32]) -> Result<QuotaLifecycleV1, TransitionError> {
        read::lifecycle(scope, |key| self.get(key))
    }

    fn admission(&self, sequence: u64) -> Result<AdmissionRowV1, TransitionError> {
        read::admission(
            self.input.policy,
            self.head,
            GatewayReadCut::Execution(self.input.execution),
            sequence,
            |key| self.get(key),
        )
    }

    fn finish(mut self, result: TransitionResult) -> Result<TransitionDelta, TransitionError> {
        self.writes.retain(|_, write| write.before != write.after);
        if !self.writes.is_empty() || self.head != self.input.head {
            self.head.revision = self
                .input
                .head
                .revision
                .checked_add(1)
                .ok_or(TransitionError::Capacity)?;
            self.head.last_execution_unix_ms = self.input.execution.recorded_at_unix_ms;
        }
        Ok(TransitionDelta {
            before: self.input.head,
            after: self.head,
            writes: self.writes.into_values().collect(),
            result,
        })
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut framed = Vec::with_capacity(domain.len() + bytes.len());
    framed.extend_from_slice(domain);
    framed.extend_from_slice(bytes);
    *Hash::new(framed).as_ref()
}

/// Stable exact-request digest, independent of the later transaction envelope or policy rotation.
pub(crate) fn request_digest(request: &Request) -> Result<[u8; 32], TransitionError> {
    request.validate().map_err(|_| TransitionError::Invalid)?;
    if norito::canonical_frame_len(request).map_err(|_| TransitionError::Invalid)?
        > MAX_REQUEST_BYTES
    {
        return Err(TransitionError::Invalid);
    }
    let bytes = norito::encode_canonical(request).map_err(|_| TransitionError::Invalid)?;
    Ok(digest(b"iroha.sorafs.gateway.request.v1\0", &bytes))
}

// Only Accepted attestations (or their retained grants) enter this path. The serving policy
// allows bounded future issuance, so expiry may reach observation + maximum TTL + future skew.
// Diagnostic rejected-token records keep their original fields without creating quota state.
pub(super) fn token_identity(
    request: &Request,
) -> Result<([u8; 32], TokenIdentityV1), TransitionError> {
    let quota = request.quota.as_ref().ok_or(TransitionError::Invalid)?;
    if quota.max_streams > STREAM_TOKEN_MAX_STREAMS_V1
        || quota.requests_per_minute > STREAM_TOKEN_MAX_REQUESTS_PER_MINUTE_V1
        || quota.rate_limit_bytes > STREAM_TOKEN_MAX_RATE_LIMIT_BYTES_V1
        || quota
            .observed_at_epoch
            .checked_add(STREAM_TOKEN_MAX_TTL_SECS_V1)
            .and_then(|maximum| maximum.checked_add(STREAM_TOKEN_MAX_FUTURE_SKEW_SECS_V1))
            .is_none_or(|maximum| quota.expires_at_epoch > maximum)
    {
        return Err(TransitionError::Invalid);
    }
    let mut key = request.context.provider_id().as_bytes().to_vec();
    key.extend_from_slice(quota.token_id.as_bytes());
    Ok((
        digest(b"iroha.sorafs.gateway.token.v1\0", &key),
        TokenIdentityV1 {
            provider_id: request.context.provider_id(),
            token_id: quota.token_id.clone(),
            body_digest: request.token_body_digest.ok_or(TransitionError::Invalid)?,
            key_version: request.token_key_version.ok_or(TransitionError::Invalid)?,
            max_streams: quota.max_streams,
            requests_per_minute: quota.requests_per_minute,
            rate_limit_bytes: quota.rate_limit_bytes,
            expires_at_unix_ms: quota
                .expires_at_epoch
                .checked_mul(1_000)
                .ok_or(TransitionError::Invalid)?,
        },
    ))
}

pub(super) fn quota_expiry(scope: [u8; 32], at_unix_ms: u64) -> GatewayExpiryKeyV1 {
    GatewayExpiryKeyV1 {
        at_unix_ms,
        target: GatewayExpiryTargetV1::Quota(scope),
    }
}

pub(super) fn lease_expiry(id: [u8; 32], at_unix_ms: u64) -> GatewayExpiryKeyV1 {
    GatewayExpiryKeyV1 {
        at_unix_ms,
        target: GatewayExpiryTargetV1::Lease(id),
    }
}

fn due<R: GatewayRows>(
    rows: &R,
    now: u64,
    limit: u32,
) -> Result<Vec<GatewayExpiryKeyV1>, TransitionError> {
    let keys = rows.expiry_prefix(now, limit)?;
    if keys.len() > limit as usize
        || keys
            .iter()
            .any(|key| key.at_unix_ms == 0 || key.at_unix_ms > now)
        || !keys.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(TransitionError::CorruptHistory);
    }
    Ok(keys)
}

#[expect(
    clippy::large_types_passed_by_value,
    reason = "the exact admission record is transferred into its delivery result"
)]
fn admission_result(row: Record, head: GatewayHeadV1) -> StreamTokenGatewayAdmissionResultV1 {
    let sequence = row.outcome.binding.gateway_sequence;
    StreamTokenGatewayAdmissionResultV1 {
        record: row,
        delivery_state: if sequence <= head.acknowledged_through_sequence {
            StreamTokenGatewayAdmissionDeliveryStateV1::AcknowledgedExactReplay {
                acknowledged_through_sequence: head.acknowledged_through_sequence,
            }
        } else {
            StreamTokenGatewayAdmissionDeliveryStateV1::Pending {
                predecessor_sequence: sequence - 1,
            }
        },
    }
}

/// Atomically prepare exact replay or a new quota/lease/ordered-callback admission.
pub(crate) fn admit<R: GatewayRows>(
    input: TransitionInputs<'_>,
    rows: &R,
    request: &Request,
) -> Result<TransitionDelta, TransitionError> {
    let mut state = Prepared::new(input, rows)?;
    let policy = state.input.policy;
    let now = state.input.execution.recorded_at_unix_ms;
    request.validate().map_err(|_| TransitionError::Invalid)?;
    if !policy.allows_admission_at(now) {
        return Err(TransitionError::Unavailable);
    }
    let context = request
        .context
        .digest()
        .map_err(|_| TransitionError::Invalid)?;
    let request_hash = request_digest(request)?;
    match state.get(&GatewayRowKey::Context(context))? {
        Some(GatewayRow::Context(index)) => {
            let original = state.admission(index.sequence)?;
            if index.request_digest != request_hash || original.request != *request {
                return Err(TransitionError::Conflict);
            }
            if original.record.lease_id.is_some() {
                read::live_lease(&original, now, |key| state.get(key))?;
            }
            let result = admission_result(original.record, state.head);
            return state.finish(TransitionResult::Admission(result));
        }
        Some(_) => return Err(TransitionError::CorruptHistory),
        None => {}
    }
    if request.validated_at_unix_ms > now
        || now - request.validated_at_unix_ms > policy.max_observation_age_ms
    {
        return Err(TransitionError::Unavailable);
    }
    if state.head.high_water_sequence - state.head.acknowledged_through_sequence
        >= u64::from(policy.qualification.max_pending)
    {
        return Err(TransitionError::Capacity);
    }
    let sequence = state
        .head
        .high_water_sequence
        .checked_add(1)
        .ok_or(TransitionError::Capacity)?;
    let mut record = Record {
        serving_attempt_id: request.serving_attempt_id,
        admitted_under: policy.qualification,
        provider_id: request.context.provider_id(),
        outcome: StreamTokenValidationOutcomeV1 {
            binding: StreamTokenValidationBindingV1 {
                gateway_id: policy.qualification.gateway_id,
                gateway_sequence: sequence,
                request_context_digest: context,
            },
            token_body_digest: request.token_body_digest,
            token_key_version: request.token_key_version,
            validated_at_unix_ms: request.validated_at_unix_ms,
            status: request.status,
        },
        retry_after_secs: None,
        lease_id: None,
        lease_expires_at_unix_ms: None,
        lease_token_expires_at_epoch: None,
    };
    if request.status == Status::Accepted {
        admit_quota(&mut state, request, &mut record)?;
    }
    record
        .validate_for_request(request, policy.qualification)
        .map_err(|_| TransitionError::Invalid)?;
    state.insert(
        GatewayRowKey::Context(context),
        GatewayRow::Context(ContextRowV1 {
            sequence,
            request_digest: request_hash,
        }),
    )?;
    state.insert(
        GatewayRowKey::Admission(sequence),
        GatewayRow::Admission(AdmissionRowV1 {
            request: request.clone(),
            record,
            execution: state.input.execution.clone(),
        }),
    )?;
    state.head.high_water_sequence = sequence;
    let result = admission_result(record, state.head);
    state.finish(TransitionResult::Admission(result))
}

fn admit_quota<R: GatewayRows>(
    state: &mut Prepared<'_, R>,
    request: &Request,
    record: &mut Record,
) -> Result<(), TransitionError> {
    let now = state.input.execution.recorded_at_unix_ms;
    let (scope, identity) = token_identity(request)?;
    if identity.expires_at_unix_ms <= request.validated_at_unix_ms {
        return Err(TransitionError::Invalid);
    }
    let expiry = request
        .validated_at_unix_ms
        .checked_add(state.input.policy.qualification.lease_ttl_ms)
        .ok_or(TransitionError::Invalid)?
        .min(identity.expires_at_unix_ms);
    if now >= expiry {
        return Err(TransitionError::Unavailable);
    }
    match state.get(&GatewayRowKey::TokenIdentity(scope))? {
        Some(GatewayRow::TokenIdentity(original)) if original != identity => {
            record.outcome.status = Status::ProviderViolation(Violation::IdentifierPolicyConflict);
            return Ok(());
        }
        Some(GatewayRow::TokenIdentity(_)) => {}
        Some(_) => return Err(TransitionError::CorruptHistory),
        None => {
            state.insert(
                GatewayRowKey::TokenIdentity(scope),
                GatewayRow::TokenIdentity(identity.clone()),
            )?;
            state.insert(
                GatewayRowKey::QuotaLifecycle(scope),
                GatewayRow::QuotaLifecycle(QuotaLifecycleV1::default()),
            )?;
        }
    }
    if !due(state.rows, now, 1)?.is_empty() {
        return Err(TransitionError::MaintenanceRequired);
    }
    let previous = state.quota(scope)?;
    let mut quota = previous.unwrap_or(QuotaRowV1 {
        generation: 0,
        request_window_start_ms: now,
        requests_used: 0,
        byte_window_start_ms: now,
        bytes_used: 0,
        active_leases: 0,
        retire_at_unix_ms: 0,
    });
    if quota.active_leases > identity.max_streams
        || quota.requests_used > identity.requests_per_minute
        || quota.bytes_used > identity.rate_limit_bytes
    {
        return Err(TransitionError::CorruptHistory);
    }
    if now
        .checked_sub(quota.request_window_start_ms)
        .ok_or(TransitionError::CorruptHistory)?
        >= 60_000
    {
        quota.request_window_start_ms = now;
        quota.requests_used = 0;
    }
    if now
        .checked_sub(quota.byte_window_start_ms)
        .ok_or(TransitionError::CorruptHistory)?
        >= 1_000
    {
        quota.byte_window_start_ms = now;
        quota.bytes_used = 0;
    }
    let requested_bytes = request
        .quota
        .as_ref()
        .ok_or(TransitionError::Invalid)?
        .requested_bytes;
    let next_bytes = quota
        .bytes_used
        .checked_add(requested_bytes)
        .ok_or(TransitionError::Invalid)?;
    let violation = if quota.active_leases >= identity.max_streams {
        Some((Violation::ConcurrencyLimitExceeded, None))
    } else if quota.requests_used >= identity.requests_per_minute {
        Some((
            Violation::RequestQuotaExceeded,
            Some(retry_after(quota.request_window_start_ms, 60_000, now)?),
        ))
    } else if next_bytes > identity.rate_limit_bytes {
        Some((
            Violation::ByteRateLimitExceeded,
            Some(retry_after(quota.byte_window_start_ms, 1_000, now)?),
        ))
    } else {
        None
    };
    if let Some((violation, retry)) = violation {
        record.outcome.status = Status::ProviderViolation(violation);
        record.retry_after_secs = retry;
        return Ok(());
    }
    if previous.is_none()
        && state.head.live_tokens >= state.input.policy.qualification.max_tracked_tokens
    {
        return Err(TransitionError::Capacity);
    }
    quota.requests_used = quota
        .requests_used
        .checked_add(1)
        .ok_or(TransitionError::Invalid)?;
    quota.bytes_used = next_bytes;
    quota.active_leases = quota
        .active_leases
        .checked_add(1)
        .ok_or(TransitionError::Invalid)?;
    quota.retire_at_unix_ms = quota
        .retire_at_unix_ms
        .max(expiry)
        .max(
            quota
                .request_window_start_ms
                .checked_add(60_000)
                .ok_or(TransitionError::Invalid)?,
        )
        .max(
            quota
                .byte_window_start_ms
                .checked_add(1_000)
                .ok_or(TransitionError::Invalid)?,
        )
        .min(identity.expires_at_unix_ms);
    if let Some(old) = previous {
        state.remove_marker(quota_expiry(scope, old.retire_at_unix_ms))?;
    } else {
        let generation = state
            .lifecycle(scope)?
            .generation
            .checked_add(1)
            .ok_or(TransitionError::Capacity)?;
        quota.generation = generation;
        state.put(
            GatewayRowKey::QuotaLifecycle(scope),
            Some(GatewayRow::QuotaLifecycle(QuotaLifecycleV1 {
                generation,
                active: true,
            })),
        )?;
        state.head.live_tokens = state
            .head
            .live_tokens
            .checked_add(1)
            .ok_or(TransitionError::Capacity)?;
    }
    state.put(GatewayRowKey::Quota(scope), Some(GatewayRow::Quota(quota)))?;
    state.marker(quota_expiry(scope, quota.retire_at_unix_ms))?;
    let mut lease_material = state.input.policy.qualification.gateway_id.to_vec();
    lease_material.extend_from_slice(&record.outcome.binding.gateway_sequence.to_be_bytes());
    lease_material.extend_from_slice(&record.outcome.binding.request_context_digest);
    let lease_id = digest(b"iroha.sorafs.gateway.lease.v1\0", &lease_material);
    state.insert(
        GatewayRowKey::Lease(lease_id),
        GatewayRow::Lease(LeaseRowV1 {
            sequence: record.outcome.binding.gateway_sequence,
            token_scope: scope,
            quota_generation: quota.generation,
            expires_at_unix_ms: expiry,
        }),
    )?;
    state.marker(lease_expiry(lease_id, expiry))?;
    record.lease_id = Some(lease_id);
    record.lease_expires_at_unix_ms = Some(expiry);
    record.lease_token_expires_at_epoch =
        request.quota.as_ref().map(|quota| quota.expires_at_epoch);
    Ok(())
}

fn retry_after(start: u64, duration: u64, now: u64) -> Result<u32, TransitionError> {
    let remaining = start
        .checked_add(duration)
        .and_then(|end| end.checked_sub(now))
        .filter(|remaining| *remaining > 0)
        .ok_or(TransitionError::CorruptHistory)?;
    u32::try_from(remaining.div_ceil(1_000)).map_err(|_| TransitionError::Invalid)
}

/// Acknowledge only the exact next callback row, retaining all replay evidence.
pub(crate) fn acknowledge<R: GatewayRows>(
    input: TransitionInputs<'_>,
    rows: &R,
    record: &Record,
    reputation_delivery: crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery::DeliveryState,
) -> Result<TransitionDelta, TransitionError> {
    use iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryDispositionV1 as Disposition;

    let mut state = Prepared::new(input, rows)?;
    if reputation_delivery.source_digest == [0; 32]
        || matches!(reputation_delivery.disposition, Disposition::Pending)
        || matches!(reputation_delivery.disposition, Disposition::Excluded)
            == record.outcome.status.counts_for_provider()
    {
        return Err(TransitionError::BindingMismatch);
    }
    let sequence = record.outcome.binding.gateway_sequence;
    let original = state.admission(sequence)?;
    if &original.record != record {
        return Err(TransitionError::Conflict);
    }
    if sequence <= state.head.acknowledged_through_sequence {
        let existing = read::acknowledgement(
            &original,
            state.head,
            GatewayReadCut::Execution(state.input.execution),
            |key| state.get(key),
        )?;
        if existing.reputation_delivery != reputation_delivery {
            return Err(TransitionError::Conflict);
        }
        return state.finish(TransitionResult::Acknowledged(Ack::ExactReplay));
    }
    if state.head.acknowledged_through_sequence.checked_add(1) != Some(sequence) {
        return Err(TransitionError::Conflict);
    }
    state.insert(
        GatewayRowKey::Acknowledgement(sequence),
        GatewayRow::Acknowledgement(AcknowledgementRowV1 {
            record: *record,
            reputation_delivery,
            policy_revision: state.input.policy.qualification.revision,
            execution: state.input.execution.clone(),
        }),
    )?;
    state.head.acknowledged_through_sequence = sequence;
    state.finish(TransitionResult::Acknowledged(Ack::Acknowledged))
}

fn terminate_lease<R: GatewayRows>(
    state: &mut Prepared<'_, R>,
    id: [u8; 32],
    expired: bool,
) -> Result<Ack, TransitionError> {
    let Some(GatewayRow::Lease(lease)) = state.get(&GatewayRowKey::Lease(id))? else {
        return Err(TransitionError::CorruptHistory);
    };
    let original = state.admission(lease.sequence)?;
    if original.record.lease_id != Some(id)
        || original.record.lease_expires_at_unix_ms != Some(lease.expires_at_unix_ms)
        || token_identity(&original.request)?.0 != lease.token_scope
    {
        return Err(TransitionError::CorruptHistory);
    }
    if read::terminal(
        &original,
        state.head,
        GatewayReadCut::Execution(state.input.execution),
        |key| state.get(key),
    )?
    .is_some()
    {
        return Ok(Ack::ExactReplay);
    }
    if expired && state.input.execution.recorded_at_unix_ms < lease.expires_at_unix_ms {
        return Err(TransitionError::CorruptHistory);
    }
    let mut quota = state
        .quota(lease.token_scope)?
        .ok_or(TransitionError::CorruptHistory)?;
    if quota.generation != lease.quota_generation {
        return Err(TransitionError::CorruptHistory);
    }
    quota.active_leases = quota
        .active_leases
        .checked_sub(1)
        .ok_or(TransitionError::CorruptHistory)?;
    state.put(
        GatewayRowKey::Quota(lease.token_scope),
        Some(GatewayRow::Quota(quota)),
    )?;
    state.remove_marker(lease_expiry(id, lease.expires_at_unix_ms))?;
    state.insert(
        GatewayRowKey::LeaseTerminal(id),
        GatewayRow::LeaseTerminal(LeaseTerminalV1 {
            policy_revision: state.input.policy.qualification.revision,
            grant: lease,
            expired,
            execution: state.input.execution.clone(),
        }),
    )?;
    Ok(Ack::Acknowledged)
}

/// Release exactly the original grant without refunding request or byte quota.
pub(crate) fn release_lease<R: GatewayRows>(
    input: TransitionInputs<'_>,
    rows: &R,
    record: &Record,
) -> Result<TransitionDelta, TransitionError> {
    let mut state = Prepared::new(input, rows)?;
    if state
        .admission(record.outcome.binding.gateway_sequence)?
        .record
        != *record
    {
        return Err(TransitionError::Conflict);
    }
    let id = record.lease_id.ok_or(TransitionError::Invalid)?;
    let ack = terminate_lease(&mut state, id, false)?;
    state.finish(TransitionResult::Released(ack))
}

/// Retire an exact bounded due prefix; permanent grants, admissions and indexes survive.
pub(crate) fn expire<R: GatewayRows>(
    input: TransitionInputs<'_>,
    rows: &R,
    max_items: u32,
) -> Result<TransitionDelta, TransitionError> {
    if max_items == 0 || max_items > MAX_EXPIRY_ITEMS {
        return Err(TransitionError::Invalid);
    }
    let mut state = Prepared::new(input, rows)?;
    let keys = due(
        rows,
        state.input.execution.recorded_at_unix_ms,
        max_items + 1,
    )?;
    let mut removed = 0;
    for key in keys.into_iter().take(max_items as usize) {
        if state.get(&GatewayRowKey::Expiry(key))? != Some(GatewayRow::Expiry(key)) {
            return Err(TransitionError::CorruptHistory);
        }
        match key.target {
            GatewayExpiryTargetV1::Lease(id) => {
                let Some(GatewayRow::Lease(lease)) = state.get(&GatewayRowKey::Lease(id))? else {
                    return Err(TransitionError::CorruptHistory);
                };
                if lease.expires_at_unix_ms != key.at_unix_ms
                    || terminate_lease(&mut state, id, true)? != Ack::Acknowledged
                {
                    return Err(TransitionError::CorruptHistory);
                }
            }
            GatewayExpiryTargetV1::Quota(scope) => {
                let quota = state.quota(scope)?.ok_or(TransitionError::CorruptHistory)?;
                if quota.retire_at_unix_ms != key.at_unix_ms || quota.active_leases != 0 {
                    return Err(TransitionError::CorruptHistory);
                }
                state.remove_marker(key)?;
                state.put(GatewayRowKey::Quota(scope), None)?;
                state.put(
                    GatewayRowKey::QuotaLifecycle(scope),
                    Some(GatewayRow::QuotaLifecycle(QuotaLifecycleV1 {
                        generation: quota.generation,
                        active: false,
                    })),
                )?;
                state.head.live_tokens = state
                    .head
                    .live_tokens
                    .checked_sub(1)
                    .ok_or(TransitionError::CorruptHistory)?;
            }
        }
        removed += 1;
    }
    state.finish(TransitionResult::Expired(removed))
}
