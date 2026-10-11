//! Native stream-token quota, sequencing, and reputation-callback admission.
//!
//! Production gateways use the daemon-owned native [`StreamTokenGatewayAdmissionProviderV1`].
//! The provider owns the atomic quota decision, sealed monotonic gateway sequence, and durable
//! ordered callback outbox. Torii never reconstructs or rewrites the returned typed outcome;
//! [`StreamTokenAdmissionCaptureV1`] passes it unchanged with the original deadline to native
//! reputation delivery, and acknowledges the durable row only after that callback succeeds.
//! Accepted requests then require
//! a fresh current Serving observation under the same original operation deadline.
use iroha_config::parameters::is_production_runtime_handle;
use iroha_data_model::sorafs::reputation::StreamTokenValidationStatusV1;
use iroha_data_model::sorafs::stream_token_gateway::{
    STREAM_TOKEN_GATEWAY_RECONCILE_MAX_ITEMS_V1, StreamTokenGatewayAdmissionAckV1,
    StreamTokenGatewayAdmissionDeliveryStateV1, StreamTokenGatewayAdmissionErrorV1,
    StreamTokenGatewayAdmissionQualificationV1, StreamTokenGatewayAdmissionReadbackV1,
    StreamTokenGatewayAdmissionRecordV1, StreamTokenGatewayAdmissionRequestV1,
    StreamTokenGatewayAdmissionResultV1,
};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
/// Background scheduling decision, distinct from an authenticated empty pending result.
#[derive(Debug)]
pub enum StreamTokenGatewayReconciliationReadV1 {
    /// Complete native preparation found no local work. No Check was signed or consumed.
    Idle,
    /// Pending readback authenticated by the original signed native Check.
    Checked(StreamTokenGatewayAdmissionReadbackV1),
}
/// Outcome of one background callback-recovery tick; neither variant grants serving authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamTokenReconciliationOutcomeV1 {
    /// No work was scheduled; this is not proof of delivery or authenticated emptiness.
    Idle,
    /// One fully checked bounded batch completed, with this many delivered records.
    Reconciled(u32),
}
/// Pinned native quota, sealed sequence, and ordered-outbox boundary.
///
/// The local handle and configured qualification identify the selected owner; neither grants
/// authority. Every stateful operation must independently authenticate its exact purpose against
/// the configured qualification and current policy/account permissions. The daemon constructs the
/// native implementation from local Core; arbitrary external providers are rejected at startup.
pub trait StreamTokenGatewayAdmissionProviderV1: Send + Sync + fmt::Debug {
    /// Return the stable credential-free provider handle.
    fn handle(&self) -> &str;
    /// Return the immutable configured identity without I/O or live-authority claims.
    ///
    /// This value must remain fixed for the lifetime of the provider. It only detects a substituted
    /// owner; every operation still authenticates its own current purpose and exact policy pins.
    fn configured_qualification(&self) -> StreamTokenGatewayAdmissionQualificationV1;
    /// Read the current authenticated public binding for startup qualification.
    ///
    /// This read grants no serving permission. `admit` independently checks eligibility for new
    /// requests; retained pending rows, acknowledgements, and lease release remain recoverable.
    ///
    /// # Errors
    ///
    /// Fails when the authoritative binding is unavailable, stale, or malformed.
    fn qualification(
        &self,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionQualificationV1, StreamTokenGatewayAdmissionErrorV1>;
    /// Atomically apply quota, allocate a sealed monotonic sequence, and append
    /// one ordered pending callback row.
    ///
    /// Exact replay must return the byte-identical retained record. Substituted
    /// material for the same request context must fail closed.
    fn admit(
        &self,
        request: &StreamTokenGatewayAdmissionRequestV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionResultV1, StreamTokenGatewayAdmissionErrorV1>;
    /// Return the oldest pending callback rows in gateway-sequence order.
    fn pending(
        &self,
        max_items: u32,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionReadbackV1, StreamTokenGatewayAdmissionErrorV1>;
    /// Prepare background recovery under the original deadline, without signing an empty poll.
    ///
    /// Idle requires complete native preparation, including finality and current permissions;
    /// a preparation error must remain an error. Pending work requires the same signed Check
    /// as `pending`. This scheduling-only method must never replace startup or request proofs.
    fn pending_for_background(
        &self,
        max_items: u32,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayReconciliationReadV1, StreamTokenGatewayAdmissionErrorV1>;
    /// Durably acknowledge one callback only after reputation admission succeeds.
    fn acknowledge(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionAckV1, StreamTokenGatewayAdmissionErrorV1>;
    /// Idempotently release one accepted cross-replica concurrency lease.
    ///
    /// A crashed caller need not run this method: the deployment provider must expire the lease at
    /// `lease_expires_at_unix_ms` before admitting another stream against the signed ceiling.
    fn release_lease(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionAckV1, StreamTokenGatewayAdmissionErrorV1>;
    /// Authorize this same Accepted physical attempt after its reputation callback is acknowledged.
    ///
    /// The implementation must consume a fresh authenticated current Serving observation at its
    /// final synchronous handoff, checking the original lease, policy and account permissions.
    /// Historical admission or acknowledgement DTOs alone cannot authorize this operation.
    /// Reuse the caller's original absolute deadline for every proof and any retry.
    fn confirm_serving(
        &self,
        request: &StreamTokenGatewayAdmissionRequestV1,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionRecordV1, StreamTokenGatewayAdmissionErrorV1>;
}
/// Native reputation delivery for an exact consensus-owned admission record.
///
/// The daemon constructs this owner directly from native Core proof and software custody.
/// The configured binding identifies its gateway; it is never authority to sign or acknowledge.
/// Each call independently authenticates the original record, governed recorder intent and
/// current disposition using the caller's original deadline. Local queues and journals alone
/// cannot establish successful delivery.
pub trait StreamTokenReputationDeliveryV1: Send + Sync + fmt::Debug {
    /// Return the immutable configured gateway identity without I/O or an authority claim.
    fn configured_qualification(&self) -> StreamTokenGatewayAdmissionQualificationV1;
    /// Finish or recover the exact native delivery and authenticate its closed disposition.
    ///
    /// Counted outcomes must retain their original governed transaction payload across retries.
    /// A still-pending or merely expiry-eligible intent is not success: expiry must be committed
    /// and independently proven first. Native acknowledgement rechecks the disposition, and a
    /// subsequent Serving proof requires Delivered for an Accepted physical attempt.
    ///
    /// # Errors
    /// Rejects substituted records, unavailable or stale authority, unresolved delivery and
    /// expired deadlines. Recovery never extends the deadline or creates a replacement intent.
    fn deliver(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<(), StreamTokenGatewayAdmissionErrorV1>;
}
/// Qualified Torii capture boundary combining native admission with finalized reputation delivery.
#[derive(Clone)]
pub struct StreamTokenAdmissionCaptureV1 {
    provider: Arc<dyn StreamTokenGatewayAdmissionProviderV1>,
    reputation: Arc<dyn StreamTokenReputationDeliveryV1>,
    expected_handle: Arc<str>,
    expected_qualification: StreamTokenGatewayAdmissionQualificationV1,
    reconcile_max_items: u32,
    operation_timeout: Duration,
}
impl fmt::Debug for StreamTokenAdmissionCaptureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamTokenAdmissionCaptureV1")
            .field("expected_handle", &self.expected_handle)
            .field("expected_qualification", &self.expected_qualification)
            .field("reconcile_max_items", &self.reconcile_max_items)
            .field("operation_timeout", &self.operation_timeout)
            .finish_non_exhaustive()
    }
}
impl StreamTokenAdmissionCaptureV1 {
    /// Construct and live-qualify the strict production capture boundary.
    ///
    /// # Errors
    ///
    /// Rejects unavailable, substituted, stale, inert, or test-marked public bindings and a
    /// substituted native delivery binding. A current recovery-only binding is allowed;
    /// the provider independently authorizes new admissions.
    pub fn try_new(
        expected_handle: impl Into<String>,
        expected_qualification: StreamTokenGatewayAdmissionQualificationV1,
        reconcile_max_items: u32,
        operation_timeout: Duration,
        provider: Arc<dyn StreamTokenGatewayAdmissionProviderV1>,
        reputation: Arc<dyn StreamTokenReputationDeliveryV1>,
    ) -> Result<Self, StreamTokenGatewayAdmissionErrorV1> {
        let deadline = operation_deadline(operation_timeout)?;
        let expected_handle = expected_handle.into();
        expected_qualification.validate()?;
        if !is_production_runtime_handle(&expected_handle)
            || provider.handle() != expected_handle
            || provider.configured_qualification() != expected_qualification
            || reputation.configured_qualification() != expected_qualification
            || reconcile_max_items == 0
            || reconcile_max_items > STREAM_TOKEN_GATEWAY_RECONCILE_MAX_ITEMS_V1
        {
            return Err(StreamTokenGatewayAdmissionErrorV1::BindingMismatch);
        }
        if provider.qualification(deadline)? != expected_qualification {
            return Err(StreamTokenGatewayAdmissionErrorV1::BindingMismatch);
        }
        let capture = Self {
            provider,
            reputation,
            expected_handle: Arc::from(expected_handle),
            expected_qualification,
            reconcile_max_items,
            operation_timeout,
        };
        capture.ensure_configured_binding(deadline)?;
        Ok(capture)
    }
    /// Revalidate this capture against an independently derived launch binding.
    ///
    /// # Errors
    ///
    /// Rejects substituted launch inputs or live provider drift.
    pub fn validate_expected_binding(
        &self,
        expected_handle: &str,
        expected_qualification: StreamTokenGatewayAdmissionQualificationV1,
        expected_reconcile_max_items: u32,
        expected_operation_timeout: Duration,
    ) -> Result<(), StreamTokenGatewayAdmissionErrorV1> {
        expected_qualification.validate()?;
        if !is_production_runtime_handle(expected_handle)
            || self.expected_handle.as_ref() != expected_handle
            || self.expected_qualification != expected_qualification
            || self.reconcile_max_items != expected_reconcile_max_items
            || self.operation_timeout != expected_operation_timeout
        {
            return Err(StreamTokenGatewayAdmissionErrorV1::BindingMismatch);
        }
        let deadline = self.begin_operation()?;
        self.ensure_configured_binding(deadline)?;
        if self.provider.qualification(deadline)? != self.expected_qualification {
            return Err(StreamTokenGatewayAdmissionErrorV1::StaleOrRevoked);
        }
        self.ensure_configured_binding(deadline)
    }
    /// Establish the original deadline before admission work or blocking-worker queuing.
    ///
    /// # Errors
    /// Rejects an invalid configured duration or monotonic-clock overflow.
    pub fn begin_operation(&self) -> Result<Instant, StreamTokenGatewayAdmissionErrorV1> {
        operation_deadline(self.operation_timeout)
    }
    /// Commit one admission and synchronously deliver its exact typed outcome.
    ///
    /// The external row remains pending if reputation admission or durable
    /// acknowledgement fails, so a restart can replay it exactly.
    pub fn admit(
        &self,
        request: &StreamTokenGatewayAdmissionRequestV1,
        deadline: Instant,
    ) -> Result<StreamTokenGatewayAdmissionRecordV1, StreamTokenGatewayAdmissionErrorV1> {
        ensure_live(deadline)?;
        request.validate()?;
        self.reconcile_until(None, deadline)?;
        self.ensure_configured_binding(deadline)?;
        let admission = self.provider.admit(request, deadline)?;
        admission.validate_for_request(request, self.expected_qualification)?;
        self.ensure_configured_binding(deadline)?;
        match admission.delivery_state {
            StreamTokenGatewayAdmissionDeliveryStateV1::Pending { .. } => {
                self.reconcile_until(Some(admission.record), deadline)?;
            }
            StreamTokenGatewayAdmissionDeliveryStateV1::AcknowledgedExactReplay { .. } => {
                self.deliver_acknowledged_replay(admission.record, deadline)?;
            }
        }
        ensure_live(deadline)?;
        if admission.record.outcome.status == StreamTokenValidationStatusV1::Accepted {
            let serving = self
                .provider
                .confirm_serving(request, admission.record, deadline)?;
            if serving != admission.record {
                return Err(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome);
            }
        }
        ensure_live(deadline)?;
        Ok(admission.record)
    }
    /// Replay the oldest durable callback suffix after a crash or outage.
    ///
    /// # Errors
    ///
    /// Fails closed on provider drift, unordered/substituted pending rows,
    /// reputation rejection, or acknowledgement failure.
    pub fn reconcile_pending(&self) -> Result<u32, StreamTokenGatewayAdmissionErrorV1> {
        self.reconcile_one_batch(None, self.begin_operation()?)
            .map(|outcome| outcome.delivered)
    }
    /// Run one background tick, allowing native preparation to leave an empty poll unsigned.
    ///
    /// # Errors
    /// Preserves preparation, binding, deadline, readback, callback and acknowledgement errors.
    pub fn reconcile_background(
        &self,
    ) -> Result<StreamTokenReconciliationOutcomeV1, StreamTokenGatewayAdmissionErrorV1> {
        let deadline = self.begin_operation()?;
        self.ensure_configured_binding(deadline)?;
        let pending = self
            .provider
            .pending_for_background(self.reconcile_max_items, deadline)?;
        self.ensure_configured_binding(deadline)?;
        match pending {
            StreamTokenGatewayReconciliationReadV1::Idle => {
                Ok(StreamTokenReconciliationOutcomeV1::Idle)
            }
            StreamTokenGatewayReconciliationReadV1::Checked(pending) => self
                .reconcile_readback(None, deadline, pending)
                .map(|outcome| StreamTokenReconciliationOutcomeV1::Reconciled(outcome.delivered)),
        }
    }
    /// Release an accepted external concurrency lease idempotently.
    ///
    /// # Errors
    ///
    /// Rejects substituted records or a drifting/unavailable provider. A
    /// failed release remains bounded by the externally authenticated expiry.
    pub fn release_lease(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
    ) -> Result<StreamTokenGatewayAdmissionAckV1, StreamTokenGatewayAdmissionErrorV1> {
        let deadline = self.begin_operation()?;
        record.validate_shape(self.expected_qualification)?;
        if record.outcome.status != StreamTokenValidationStatusV1::Accepted {
            return Err(StreamTokenGatewayAdmissionErrorV1::InvalidRequest);
        }
        self.ensure_configured_binding(deadline)?;
        let released = self.provider.release_lease(record, deadline)?;
        self.ensure_configured_binding(deadline)?;
        Ok(released)
    }
    fn reconcile_until(
        &self,
        required_record: Option<StreamTokenGatewayAdmissionRecordV1>,
        deadline: Instant,
    ) -> Result<u32, StreamTokenGatewayAdmissionErrorV1> {
        let mut delivered = 0_u32;
        loop {
            let batch = self.reconcile_one_batch(required_record, deadline)?;
            delivered = delivered
                .checked_add(batch.delivered)
                .ok_or(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome)?;
            if required_record.is_none() && batch.delivered == 0 {
                return Ok(delivered);
            }
            if required_record.is_some() && batch.required_record_delivered {
                return Ok(delivered);
            }
            if batch.delivered == 0 || delivered > self.expected_qualification.max_pending {
                return Err(StreamTokenGatewayAdmissionErrorV1::Unavailable);
            }
        }
    }
    fn reconcile_one_batch(
        &self,
        required_record: Option<StreamTokenGatewayAdmissionRecordV1>,
        deadline: Instant,
    ) -> Result<StreamTokenReconcileBatchV1, StreamTokenGatewayAdmissionErrorV1> {
        self.ensure_configured_binding(deadline)?;
        let pending = self.provider.pending(self.reconcile_max_items, deadline)?;
        self.reconcile_readback(required_record, deadline, pending)
    }
    fn reconcile_readback(
        &self,
        required_record: Option<StreamTokenGatewayAdmissionRecordV1>,
        deadline: Instant,
        pending: StreamTokenGatewayAdmissionReadbackV1,
    ) -> Result<StreamTokenReconcileBatchV1, StreamTokenGatewayAdmissionErrorV1> {
        pending.validate(self.reconcile_max_items, self.expected_qualification)?;
        self.ensure_configured_binding(deadline)?;
        let mut delivery_count = pending.records.len();
        let mut required_record_delivered = false;
        if let Some(required) = required_record {
            let required_sequence = required.outcome.binding.gateway_sequence;
            if pending.acknowledged_through_sequence >= required_sequence {
                self.deliver_acknowledged_replay(required, deadline)?;
                return Ok(StreamTokenReconcileBatchV1 {
                    delivered: 0,
                    required_record_delivered: true,
                });
            }
            if pending.high_water_sequence < required_sequence {
                return Err(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome);
            }
            match pending
                .records
                .iter()
                .position(|record| record.outcome.binding.gateway_sequence == required_sequence)
            {
                Some(position) => {
                    if pending.records[position] != required {
                        return Err(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome);
                    }
                    delivery_count = position + 1;
                    required_record_delivered = true;
                }
                None if pending.records.len() == self.reconcile_max_items as usize => {}
                None => return Err(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome),
            }
        }
        for record in pending.records.iter().take(delivery_count) {
            self.deliver_record(*record, deadline)?;
        }
        self.ensure_configured_binding(deadline)?;
        Ok(StreamTokenReconcileBatchV1 {
            delivered: u32::try_from(delivery_count)
                .map_err(|_| StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome)?,
            required_record_delivered,
        })
    }
    fn deliver_acknowledged_replay(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<(), StreamTokenGatewayAdmissionErrorV1> {
        ensure_live(deadline)?;
        self.reputation.deliver(record, deadline)?;
        ensure_live(deadline)?;
        if self.provider.acknowledge(record, deadline)?
            != StreamTokenGatewayAdmissionAckV1::ExactReplay
        {
            return Err(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome);
        }
        self.ensure_configured_binding(deadline)
    }
    fn deliver_record(
        &self,
        record: StreamTokenGatewayAdmissionRecordV1,
        deadline: Instant,
    ) -> Result<(), StreamTokenGatewayAdmissionErrorV1> {
        ensure_live(deadline)?;
        self.reputation.deliver(record, deadline)?;
        ensure_live(deadline)?;
        self.provider.acknowledge(record, deadline)?;
        self.ensure_configured_binding(deadline)?;
        Ok(())
    }
    fn ensure_configured_binding(
        &self,
        deadline: Instant,
    ) -> Result<(), StreamTokenGatewayAdmissionErrorV1> {
        ensure_live(deadline)?;
        if self.provider.handle() != self.expected_handle.as_ref()
            || self.provider.configured_qualification() != self.expected_qualification
            || self.reputation.configured_qualification() != self.expected_qualification
        {
            return Err(StreamTokenGatewayAdmissionErrorV1::StaleOrRevoked);
        }
        ensure_live(deadline)
    }
}
fn operation_deadline(timeout: Duration) -> Result<Instant, StreamTokenGatewayAdmissionErrorV1> {
    if timeout.is_zero() || timeout > Duration::from_secs(60) {
        return Err(StreamTokenGatewayAdmissionErrorV1::InvalidRequest);
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(StreamTokenGatewayAdmissionErrorV1::Unavailable)
}
fn ensure_live(deadline: Instant) -> Result<(), StreamTokenGatewayAdmissionErrorV1> {
    if Instant::now() >= deadline {
        return Err(StreamTokenGatewayAdmissionErrorV1::Unavailable);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StreamTokenReconcileBatchV1 {
    delivered: u32,
    required_record_delivered: bool,
}
#[cfg(test)]
#[path = "stream_token_admission/tests.rs"]
pub(crate) mod tests;
