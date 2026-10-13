//! Attempt-owned eligibility originals and one-time consumption in a single atomic record.
//!
//! The serving owner must independently reselect current authority/routing before consumption
//! and invoke only the bound operation after success. This storage component authenticates the
//! signature and ordering; caller-supplied policies do not establish authority. Exchanges are
//! append-only and share the journal's 3 MiB bound, with no eviction or separate nonce rows.

use super::*;
use iroha_core_zk::kagemusha_wallet_enrollment_v1::PreKeyDispatchV1;
use iroha_data_model::kagemusha::{
    KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1, KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
    KagemushaEligibilityDecisionV1, KagemushaEligibilityPolicyV1, KagemushaEligibilityPurposeV1,
    KagemushaEligibilityRequestV1, KagemushaEligibilityResponseV1, KagemushaWalletSchemeV1,
};

const MAX_EXCHANGE: usize = 8 * 1024;

#[derive(Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.eligibility_record.v1")]
pub(super) struct EligibilityRecord {
    version: u16,
    scope: [u8; 32],
    key: [u8; 32],
    nonce: [u8; 32],
    attempt_cursor: [u8; 32],
    scheme: Vec<u8>,
    policy: Vec<u8>,
    request: Vec<u8>,
    response: Vec<u8>,
    received_at_ms: u64,
    consumed_at_ms: u64,
}
impl EligibilityRecord {
    fn validate(&self) -> Result<(KagemushaEligibilityPolicyV1, KagemushaEligibilityRequestV1)> {
        if self.version != 1
            || self.scope == [0; 32]
            || self.key == [0; 32]
            || self.nonce == [0; 32]
            || self.attempt_cursor == [0; 32]
            || self.scheme.len() > KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1
            || self.policy.len() > KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1
            || self.request.len() > KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1
            || self.response.len() > KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1
        {
            return Err(Invalid);
        }
        let policy =
            KagemushaEligibilityPolicyV1::decode_canonical(&self.policy).map_err(|_| Invalid)?;
        let scheme = KagemushaWalletSchemeV1::decode_canonical(&self.scheme, &policy.scheme_id)
            .map_err(|_| Invalid)?;
        if scheme.network_id != policy.network_id {
            return Err(Invalid);
        }
        let request = KagemushaEligibilityRequestV1::decode_canonical(&self.request, &policy)
            .map_err(|_| Invalid)?;
        if request.nonce != self.nonce {
            return Err(Invalid);
        }
        if self.response.is_empty() {
            if self.received_at_ms != 0 || self.consumed_at_ms != 0 {
                return Err(Invalid);
            }
        } else {
            let response = KagemushaEligibilityResponseV1::decode_canonical(
                &self.response,
                &policy,
                &request,
                self.received_at_ms,
            )
            .map_err(|_| Invalid)?;
            if self.consumed_at_ms != 0
                && (self.consumed_at_ms < self.received_at_ms
                    || response
                        .verify(&policy, &request, self.consumed_at_ms)
                        .map_err(|_| Invalid)?
                        != KagemushaEligibilityDecisionV1::ApprovedUnfrozen)
            {
                return Err(Invalid);
            }
        }
        if norito::encode_canonical(self).map_err(|_| Invalid)?.len() > MAX_EXCHANGE {
            return Err(Invalid);
        }
        Ok((policy, request))
    }
}

pub(super) fn validate_index(record: &Record) -> Result<()> {
    let mut nonces = std::collections::BTreeSet::new();
    for exchange in &record.eligibility {
        let (policy, request) = exchange.validate()?;
        if exchange.scope != record.scope
            || exchange.key != record.selection.key
            || request.attempt_id != record.selection.attempt_id
            || request.account_digest != record.selection.challenge.account_digest
            || policy.scheme_id != record.selection.challenge.scheme_id
            || policy.asset_digest != record.selection.challenge.asset_digest
            || request.requested_at_ms < record.selection.created_at_ms
            || (matches!(
                request.purpose,
                KagemushaEligibilityPurposeV1::PreKeyPermit
                    | KagemushaEligibilityPurposeV1::VerifyEvidence
            ) && request.expires_at_ms > record.selection.expires_at_ms)
            || !nonces.insert(exchange.nonce)
        {
            return Err(Invalid);
        }
    }
    if record.refusal != 0 {
        // The terminal refusal names one exact retained, unconsumed signed denial whose
        // decision is its closed code.
        let exchange = record
            .eligibility
            .iter()
            .find(|entry| entry.nonce == record.refusal_nonce)
            .ok_or(Invalid)?;
        let (policy, request) = exchange.validate()?;
        if exchange.response.is_empty() || exchange.consumed_at_ms != 0 {
            return Err(Invalid);
        }
        let response = KagemushaEligibilityResponseV1::decode_canonical(
            &exchange.response,
            &policy,
            &request,
            exchange.received_at_ms,
        )
        .map_err(|_| Invalid)?;
        if refusal_of(response.body.decision).map(|refusal| refusal.code()) != Some(record.refusal)
        {
            return Err(Invalid);
        }
    }
    Ok(())
}

/// Closed refusal of a definitive denial; `None` for an approval.
fn refusal_of(
    decision: KagemushaEligibilityDecisionV1,
) -> Option<iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1> {
    use iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1 as Refusal;
    match decision {
        KagemushaEligibilityDecisionV1::ApprovedUnfrozen => None,
        KagemushaEligibilityDecisionV1::NotApproved => Some(Refusal::AccountNotApproved),
        KagemushaEligibilityDecisionV1::Frozen => Some(Refusal::AccountFrozen),
    }
}

fn attempt_digest(attempt: &EnrollmentAttemptV1) -> Result<[u8; 32]> {
    // Bind all substantive attempt state, excluding only this append-only exchange index.
    // Retaining an observation must not invalidate its own operation cursor. A phase,
    // preparation or original change still invalidates every preceding observation.
    let mut operation = attempt.record.clone();
    operation.eligibility.clear();
    let original = encode(&operation)?;
    let mut hash = Sha256::new();
    hash.update(b"iroha:kagemusha:eligibility:attempt-cursor:v1\0");
    hash.update((original.len() as u64).to_le_bytes());
    hash.update(&original);
    Ok(hash.finalize().into())
}
fn require_bound(
    attempt: &EnrollmentAttemptV1,
    dispatch: &PreKeyDispatchV1,
    policy: &KagemushaEligibilityPolicyV1,
    request: &KagemushaEligibilityRequestV1,
) -> Result<()> {
    use EnrollmentJournalPhaseV1 as Phase;

    request.validate(policy).map_err(|_| Invalid)?;
    let selection = attempt.selection();
    if dispatch.stable_selection().map_err(|_| Invalid)? != selection.stable_selection
        || policy.network_id != dispatch.scheme.network_id
        || policy.scheme_id != selection.challenge.scheme_id
        || policy.asset_digest != selection.challenge.asset_digest
        || request.account_digest != selection.challenge.account_digest
        || request.actor_digest != dispatch.actor_digest
        || request.attempt_id != selection.attempt_id
        || request.requested_at_ms < selection.created_at_ms
    {
        return Err(Conflict);
    }
    if policy.authority.scope_digest() != dispatch.fi_digest {
        return Err(Conflict);
    }
    let phase_allowed = match request.purpose {
        KagemushaEligibilityPurposeV1::PreKeyPermit => {
            attempt.phase() != Phase::Rejected && request.expires_at_ms <= selection.expires_at_ms
        }
        KagemushaEligibilityPurposeV1::VerifyEvidence => {
            matches!(attempt.phase(), Phase::Selected | Phase::Verifying)
                && request.expires_at_ms <= selection.expires_at_ms
        }
        // Evidence was checked while E1 was live. Issuance and exact E6 delivery may recover
        // later, but each operation still needs its own fresh policy-bounded observation.
        KagemushaEligibilityPurposeV1::IssueCredential => {
            matches!(attempt.phase(), Phase::Evidence | Phase::Signing)
        }
        KagemushaEligibilityPurposeV1::DeliverCredential => attempt.phase() == Phase::Issued,
    };
    if !phase_allowed {
        return Err(Conflict);
    }
    Ok(())
}

impl EnrollmentJournalV1 {
    fn read_eligibility<'a>(
        &self,
        attempt: &'a EnrollmentAttemptV1,
        nonce: &[u8; 32],
    ) -> Result<Option<&'a EligibilityRecord>> {
        self.require_current(attempt)?;
        if *nonce == [0; 32] {
            return Err(Invalid);
        }
        Ok(attempt
            .record
            .eligibility
            .iter()
            .find(|entry| entry.nonce == *nonce))
    }

    /// Retain the exact fresh eligibility request before the serving owner contacts middleware.
    ///
    /// The owner supplies a CSPRNG nonce, actual retained operation digest and independently
    /// authenticated current policy/routing. No failed read is translated into absence. Exact
    /// retries preserve the same request only while this attempt cursor is still selected.
    /// Every exchange remains in the bounded attempt record, including after consumption.
    /// # Errors
    /// Refuses a foreign scope/provider, stale phase/cursor, reused attempt nonce, non-live trusted
    /// time, a full journal record, or unsafe/uncertain custody. Pre-key and verification
    /// observations cannot extend E1; later issuance and delivery retain recovery semantics.
    pub fn retain_eligibility_request(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
        policy: &KagemushaEligibilityPolicyV1,
        request: &KagemushaEligibilityRequestV1,
        now_ms: u64,
    ) -> Result<()> {
        // A terminal refusal admits no further observation.
        if attempt.refusal().is_some() {
            return Err(Conflict);
        }
        self.require_current(attempt)?;
        require_bound(attempt, dispatch, policy, request)?;
        if now_ms < request.requested_at_ms || now_ms >= request.expires_at_ms {
            return Err(Invalid);
        }
        let request_original = request.encode_canonical(policy).map_err(|_| Invalid)?;
        let policy = policy.encode_canonical().map_err(|_| Invalid)?;
        let cursor = attempt_digest(attempt)?;
        if let Some(prior) = self.read_eligibility(attempt, &request.nonce)? {
            return if prior.attempt_cursor == cursor
                && prior.policy == policy
                && prior.request == request_original
                && prior.consumed_at_ms == 0
                && now_ms >= prior.received_at_ms
            {
                Ok(())
            } else {
                Err(Conflict)
            };
        }
        let mut record = attempt.record.clone();
        record.eligibility.push(EligibilityRecord {
            version: 1,
            scope: self.scope,
            key: attempt.selection().key,
            nonce: request.nonce,
            attempt_cursor: cursor,
            scheme: dispatch.scheme.to_canonical_bytes().map_err(|_| Invalid)?,
            policy,
            request: request_original,
            response: Vec::new(),
            received_at_ms: 0,
            consumed_at_ms: 0,
        });
        self.advance(attempt, record)
    }

    /// Retain an actual signed definitive observation, including denials, before consumption.
    /// Unavailable middleware outcomes must not call this method or reconstruct a lost request.
    /// # Errors
    /// Rejects unknown nonce, changed attempt, foreign/expired signatures, changed response
    /// retries, already consumed requests and uncertain publication.
    pub fn retain_eligibility_response(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        nonce: &[u8; 32],
        response: &[u8],
        now_ms: u64,
    ) -> Result<()> {
        if attempt.refusal().is_some() {
            return Err(Conflict);
        }
        let exchange = self.read_eligibility(attempt, nonce)?.ok_or(Conflict)?;
        if exchange.attempt_cursor != attempt_digest(attempt)?
            || exchange.consumed_at_ms != 0
            || now_ms < exchange.received_at_ms
        {
            return Err(Conflict);
        }
        let (policy, request) = exchange.validate()?;
        KagemushaEligibilityResponseV1::decode_canonical(response, &policy, &request, now_ms)
            .map_err(|_| Invalid)?;
        if !exchange.response.is_empty() {
            return if exchange.response == response {
                Ok(())
            } else {
                Err(Conflict)
            };
        }
        let mut record = attempt.record.clone();
        let exchange = record
            .eligibility
            .iter_mut()
            .find(|entry| entry.nonce == *nonce)
            .ok_or(Conflict)?;
        exchange.response = response.to_vec();
        exchange.received_at_ms = now_ms;
        self.advance(attempt, record)
    }

    /// Durably consume one approved observation before executing its single bound operation.
    ///
    /// The serving owner must independently reselect current authority and routing immediately
    /// before this call, derive `expected_request` from the operation it will actually invoke,
    /// and execute only after success. A crash after consumption requires a new observation;
    /// a consumed nonce never returns another success, including after restart. This primitive
    /// does not itself execute an enrollment operation or authenticate offered policy DATA.
    /// # Errors
    /// Rejects missing/denied/stale evidence, rotated policy/routing, operation substitution,
    /// clock rollback, replay and unsafe or uncertain publication.
    pub fn consume_eligibility(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
        current_policy: &KagemushaEligibilityPolicyV1,
        expected_request: &KagemushaEligibilityRequestV1,
        now_ms: u64,
    ) -> Result<()> {
        if attempt.refusal().is_some() {
            return Err(Conflict);
        }
        self.require_current(attempt)?;
        require_bound(attempt, dispatch, current_policy, expected_request)?;
        let exchange = self
            .read_eligibility(attempt, &expected_request.nonce)?
            .ok_or(Conflict)?;
        if exchange.attempt_cursor != attempt_digest(attempt)?
            || exchange.request
                != expected_request
                    .encode_canonical(current_policy)
                    .map_err(|_| Invalid)?
            || exchange.policy != current_policy.encode_canonical().map_err(|_| Invalid)?
            || exchange.consumed_at_ms != 0
            || now_ms < exchange.received_at_ms
        {
            return Err(Conflict);
        }
        let response = KagemushaEligibilityResponseV1::decode_canonical(
            &exchange.response,
            current_policy,
            expected_request,
            now_ms,
        )
        .map_err(|_| Invalid)?;
        if let Some(refusal) = refusal_of(response.body.decision) {
            // Before any credential can exist the definitive denial is retained atomically as
            // the attempt's terminal refusal, naming this exact signed observation. Afterwards
            // (issued, or possibly signed) it only withholds the current operation.
            if attempt.pre_issuance() {
                let mut record = attempt.record.clone();
                record.refusal = refusal.code();
                record.refusal_nonce = expected_request.nonce;
                self.advance(attempt, record)?;
            }
            return Err(EnrollmentJournalErrorV1::Ineligible(refusal));
        }
        let mut record = attempt.record.clone();
        let exchange = record
            .eligibility
            .iter_mut()
            .find(|entry| entry.nonce == expected_request.nonce)
            .ok_or(Conflict)?;
        exchange.consumed_at_ms = now_ms;
        self.advance(attempt, record)
    }
}

#[cfg(test)]
mod tests;
