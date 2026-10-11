impl Error {
    fn status_code_for_queue_error(err: &queue::Error) -> StatusCode {
        match err {
            queue::Error::Deferred(_) => StatusCode::TOO_MANY_REQUESTS,
            queue::Error::Full
            | queue::Error::LatencySaturated
            | queue::Error::MaximumTransactionsPerUser => StatusCode::TOO_MANY_REQUESTS,
            queue::Error::Expired | queue::Error::TransactionDomainMismatch(_) => {
                StatusCode::BAD_REQUEST
            }
            queue::Error::UnsupportedTransactionAdmission { .. } => StatusCode::BAD_REQUEST,
            queue::Error::UnresolvedRoute { .. } => StatusCode::BAD_REQUEST,
            queue::Error::InBlockchain => StatusCode::CONFLICT,
            queue::Error::IsInQueue => StatusCode::CONFLICT,
            queue::Error::UnregisteredAuthority { .. } => StatusCode::FORBIDDEN,
            queue::Error::Governance(_) => StatusCode::INTERNAL_SERVER_ERROR,
            queue::Error::GovernanceNotPermitted { .. } => StatusCode::FORBIDDEN,
            queue::Error::LaneComplianceDenied { .. } => StatusCode::FORBIDDEN,
            queue::Error::LanePrivacyProofRejected { .. } => StatusCode::FORBIDDEN,
            queue::Error::NexusFeeAdmissionRejected { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            queue::Error::NexusFeeAdmissionConfigInvalid { .. } => StatusCode::SERVICE_UNAVAILABLE,
            queue::Error::AdmissionInvariant { .. } => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
    fn queue_error_summary(err: &queue::Error) -> (&'static str, &'static str) {
        match err {
            queue::Error::Deferred(_) => (
                "admission_deferred",
                "local admission capacity is unavailable; retry the same signed transaction",
            ),
            queue::Error::Full => ("queue_full", "transaction queue is at capacity"),
            queue::Error::TransactionDomainMismatch(_) => (
                "transaction_rejected",
                "signed transaction domain differs from committed admission state",
            ),
            queue::Error::LatencySaturated => (
                "queue_latency_saturated",
                "transaction queue latency budget is saturated",
            ),
            queue::Error::MaximumTransactionsPerUser => (
                "per_user_queue_limit",
                "authority reached its per-user queue capacity",
            ),
            queue::Error::Expired => (
                "transaction_expired",
                "transaction expired before admission",
            ),
            // The detail carries the exact reason: an unsupported intent or route, or a
            // transaction larger than any proposer can include.
            queue::Error::UnsupportedTransactionAdmission { .. } => (
                "unsupported_transaction_admission",
                "current consensus requires Ordinary admission, a single resolved route and a transaction a block can carry",
            ),
            queue::Error::UnresolvedRoute { .. } => (
                "queue_unresolved_route",
                "transaction route could not be resolved",
            ),
            queue::Error::InBlockchain => (
                "already_committed",
                "transaction already committed to the blockchain",
            ),
            queue::Error::IsInQueue => (
                "already_enqueued",
                "transaction already present in the queue",
            ),
            queue::Error::UnregisteredAuthority { .. } => (
                "unregistered_authority",
                "transaction authority is not registered",
            ),
            queue::Error::Governance(_) => (
                "queue_governance_invalid",
                "lane governance manifest is missing or invalid",
            ),
            queue::Error::GovernanceNotPermitted { .. } => (
                "queue_governance_rejected",
                "lane governance manifest rejected the transaction",
            ),
            queue::Error::LaneComplianceDenied { .. } => (
                "queue_lane_compliance_denied",
                "lane compliance policy rejected the transaction",
            ),
            queue::Error::LanePrivacyProofRejected { .. } => (
                "queue_lane_privacy_proof_rejected",
                "lane privacy proof rejected the transaction",
            ),
            queue::Error::NexusFeeAdmissionRejected { .. } => (
                "queue_nexus_fee_rejected",
                "transaction cannot cover the Nexus fee admission bound",
            ),
            queue::Error::NexusFeeAdmissionConfigInvalid { .. } => (
                "queue_nexus_fee_config_invalid",
                "node Nexus fee configuration is invalid",
            ),
            queue::Error::AdmissionInvariant { .. } => (
                "queue_admission_invariant",
                "transaction queue admission requires recovery",
            ),
        }
    }
    fn queue_error_envelope(
        err: &queue::Error,
        backpressure: Option<queue::BackpressureState>,
    ) -> ErrorEnvelope {
        let (code, message) = Self::queue_error_summary(err);
        iroha_logger::debug!(error = %err, "the queue rejected a transaction");
        let retry_after_seconds = match err {
            queue::Error::Full
            | queue::Error::LatencySaturated
            | queue::Error::MaximumTransactionsPerUser
            | queue::Error::Deferred(_) => Some(1),
            _ => None,
        };
        let (reject_code, _detail) = queue_rejection_metadata(err);
        let fee = match err {
            queue::Error::NexusFeeAdmissionRejected { code, .. }
            | queue::Error::NexusFeeAdmissionConfigInvalid { code, .. } => Some(FeeErrorDetails {
                code: code.as_str().to_owned(),
                retryable: fee_quote_rejection_retryable(*code),
                remediation: Some(fee_quote_remediation(*code).to_owned()),
                ..FeeErrorDetails::default()
            }),
            _ => None,
        };
        ErrorEnvelope::new(code, message).with_details(ErrorDetails {
            reject_code: (!matches!(err, queue::Error::Deferred(_)))
                .then(|| reject_code.to_owned()),
            queue: backpressure.map(|backpressure| {
                let saturated = backpressure.is_saturated();
                QueueErrorSnapshot {
                    state: if saturated {
                        "saturated".to_owned()
                    } else {
                        "healthy".to_owned()
                    },
                    queued: backpressure.queued() as u64,
                    capacity: backpressure.capacity().get() as u64,
                    saturated,
                }
            }),
            retry_after_seconds,
            fee,
            ..Default::default()
        })
    }
}
fn queue_rejection_metadata(err: &queue::Error) -> (&'static str, String) {
    match err {
        queue::Error::Deferred(_) => (
            "PRTRY:ADMISSION_DEFERRED",
            "local admission capacity is unavailable; retry the same signed transaction".to_owned(),
        ),
        queue::Error::Full => (
            "PRTRY:QUEUE_FULL",
            "transaction queue is at capacity".to_owned(),
        ),
        queue::Error::LatencySaturated => (
            "PRTRY:QUEUE_LATENCY",
            "transaction queue latency budget is saturated".to_owned(),
        ),
        queue::Error::MaximumTransactionsPerUser => (
            "PRTRY:QUEUE_RATE",
            "authority reached per-user queue capacity".to_owned(),
        ),
        queue::Error::Expired => ("ED07", "transaction expired before admission".to_owned()),
        queue::Error::TransactionDomainMismatch(mismatch) => (
            "transaction_rejected",
            format!("signed transaction domain differs from committed admission state: {mismatch}"),
        ),
        queue::Error::UnsupportedTransactionAdmission { reason } => {
            ("PRTRY:UNSUPPORTED_TRANSACTION_ADMISSION", reason.clone())
        }
        queue::Error::UnresolvedRoute { reason } => (
            "PRTRY:ROUTE_UNRESOLVED",
            format!("transaction route could not be resolved: {reason}"),
        ),
        queue::Error::InBlockchain => (
            "PRTRY:ALREADY_COMMITTED",
            "transaction already committed to the blockchain".to_owned(),
        ),
        queue::Error::IsInQueue => (
            "PRTRY:ALREADY_ENQUEUED",
            "transaction already present in the queue".to_owned(),
        ),
        queue::Error::UnregisteredAuthority { authority } => (
            "PRTRY:UNREGISTERED_AUTHORITY",
            format!("transaction authority is not registered: {authority}"),
        ),
        queue::Error::Governance(err) => (
            "PRTRY:QUEUE_GOVERNANCE_INVALID",
            format!("lane governance manifest invalid: {err}"),
        ),
        queue::Error::GovernanceNotPermitted { alias, reason } => (
            "PRTRY:QUEUE_GOVERNANCE_REJECTED",
            format!("lane governance rejected transaction for alias '{alias}': {reason}"),
        ),
        queue::Error::LaneComplianceDenied { alias, reason } => (
            "PRTRY:QUEUE_LANE_COMPLIANCE_DENIED",
            format!("lane compliance policy rejected transaction for alias '{alias}': {reason}"),
        ),
        queue::Error::LanePrivacyProofRejected { alias, reason } => (
            "PRTRY:QUEUE_LANE_PRIVACY_PROOF_REJECTED",
            format!("lane privacy proof rejected transaction for alias '{alias}': {reason}"),
        ),
        queue::Error::NexusFeeAdmissionRejected { code, .. } => (
            "PRTRY:NEXUS_FEE_ADMISSION_REJECTED",
            format!(
                "transaction rejected by Nexus fee admission: {}",
                code.as_str()
            ),
        ),
        queue::Error::NexusFeeAdmissionConfigInvalid { code, .. } => (
            "PRTRY:NEXUS_FEE_ADMISSION_CONFIG_INVALID",
            format!(
                "invalid Nexus fee admission configuration: {}",
                code.as_str()
            ),
        ),
        queue::Error::AdmissionInvariant { reason } => (
            "PRTRY:QUEUE_ADMISSION_INVARIANT",
            format!("transaction queue admission requires recovery: {reason}"),
        ),
    }
}
