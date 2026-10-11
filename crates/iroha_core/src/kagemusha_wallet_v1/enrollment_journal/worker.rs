//! Exact reconstruction of the selected private worker request during recovery.
use super::*;
use iroha_core_zk::kagemusha_wallet_enrollment_v1::{
    PreKeyDispatchV1, RequestV1, ResultV1,
    issuer_worker::{
        ActionV1, EvidenceProjectionV1, OutcomeV1, VerifierExchangeV1, VerifierRequestV1,
    },
};
use iroha_data_model::kagemusha::KagemushaWalletCredentialBodyV1;

impl EnrollmentJournalV1 {
    /// Reconstruct the exact private request from retained account-signed E5 and issuer time.
    /// The independently admitted process must match the original configuration pin. This
    /// returns codec state only: a reread `Verifying` attempt permits live `Recover` under
    /// fresh eligibility or passive `Inspect`, never another fresh E5 selection. Later terminal phases already have their original outcome in this journal.
    /// # Errors
    /// Refuses an unselected or stale attempt, configuration substitution, invalid E5, changed
    /// issuer bindings or any mismatch with the exact previously published worker request.
    pub fn retained_worker_request(
        &self,
        attempt: &EnrollmentAttemptV1,
        configuration: [u8; 32],
    ) -> Result<VerifierRequestV1> {
        self.require_current(attempt)?;
        if attempt.worker_configuration() != Some(configuration) || configuration == [0; 32] {
            return Err(Conflict);
        }
        let request = RequestV1::decode(&attempt.record.request).map_err(|_| Invalid)?;
        if request.body.challenge != attempt.selection().challenge
            || attempt
                .selection()
                .created_at_ms
                .checked_add(request.body.policy.challenge_lifetime_ms)
                != Some(attempt.selection().expires_at_ms)
        {
            return Err(Conflict);
        }
        let preparation = self.require_worker_prepared(attempt, configuration)?;
        let worker = VerifierRequestV1::from_prepared(
            request,
            &preparation,
            attempt.record.verification_time_ms,
        )
        .map_err(|_| Invalid)?;
        if worker.original() != attempt.record.worker_request {
            return Err(Invalid);
        }
        Ok(worker)
    }

    /// Bind one Complete/Recover/Inspect exchange to the durable preparation and exact account-signed
    /// E5. A reread attempt uses Recover or passive Inspect; only live Complete/Recover can
    /// atomically claim an unclaimed prepared
    /// row and never repeats verification after a claim, even when its result remains unknown.
    /// Inspect never claims or performs verification, including after E1 expiry.
    /// The caller supplies a fresh exchange nonce and trusted current dispatch time.
    /// # Errors
    /// Unprepared/mismatched originals, malformed time/nonce or unavailable custody.
    pub fn worker_exchange(
        &self,
        attempt: &EnrollmentAttemptV1,
        configuration: [u8; 32],
        action: ActionV1,
        exchange: [u8; 32],
        dispatch_time_ms: u64,
    ) -> Result<VerifierExchangeV1> {
        let worker = self.retained_worker_request(attempt, configuration)?;
        let incarnation = attempt
            .record
            .worker_preparation
            .as_ref()
            .ok_or(Conflict)?
            .incarnation;
        worker
            .packet(action, incarnation, exchange, dispatch_time_ms)
            .map_err(|_| Invalid)
    }

    /// Validate and retain an authenticated worker's exact reply before permitting signing.
    /// Worker custody remains the calling service's responsibility. Unknown/unavailable
    /// outcomes never clear the consumed attempt or authorize another E5 selection.
    /// # Errors
    /// Refuses a stale/configuration-substituted request, malformed response, changed result
    /// or failure to durably retain a definitive outcome.
    pub fn retain_worker_response(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        configuration: [u8; 32],
        exchange: &VerifierExchangeV1,
        frame: &[u8],
    ) -> Result<OutcomeV1> {
        let worker = self.retained_worker_request(attempt, configuration)?;
        let selected = attempt.record.worker_preparation.as_ref().ok_or(Conflict)?;
        if exchange.journal_incarnation() != Some(selected.incarnation) {
            return Err(Conflict);
        }
        let outcome = worker.response(exchange, frame).map_err(|_| Invalid)?;
        match &outcome {
            OutcomeV1::Evidence(projection) => {
                self.retain_worker_result(
                    attempt,
                    projection.original_result.clone(),
                    None,
                    projection.evidence.time_ms,
                )?;
            }
            // A fresh Recover exchange changes its envelope but cannot replace the first
            // terminal refusal original or its exchange, change its reason or restore this
            // attempt to Verifying.
            OutcomeV1::Refused(reason) if attempt.phase() == EnrollmentJournalPhaseV1::Rejected => {
                if self.retained_refusal(attempt, configuration)? != *reason {
                    return Err(Conflict);
                }
            }
            OutcomeV1::Refused(reason) => {
                self.retain_worker_result(
                    attempt,
                    frame.to_vec(),
                    Some((*reason, WorkerRefusalExchange::of(exchange)?)),
                    0,
                )?;
            }
            OutcomeV1::OutcomeUnknown | OutcomeV1::Unavailable => {}
        }
        Ok(outcome)
    }

    /// Closed reason of the exact retained terminal refusal; every retry returns it unchanged.
    /// # Errors
    /// Refuses an attempt without a retained refusal, a changed configuration or custody.
    pub fn retained_refusal(
        &self,
        attempt: &EnrollmentAttemptV1,
        configuration: [u8; 32],
    ) -> Result<iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1> {
        let retained = attempt.worker_refusal().ok_or(Conflict)?;
        let selection = attempt.record.worker_refusal_exchange.ok_or(Invalid)?;
        // Rebuild the exact exchange that produced the retained reply from the retained E5,
        // preparation, configuration and journal incarnation, check the reply against every
        // binding of that exchange, and require the stored code to be its reason.
        let worker = self.retained_worker_request(attempt, configuration)?;
        let incarnation = attempt
            .record
            .worker_preparation
            .as_ref()
            .ok_or(Conflict)?
            .incarnation;
        let exchange = worker
            .packet(
                selection.action()?,
                incarnation,
                selection.exchange,
                selection.dispatch_time_ms,
            )
            .map_err(|_| Invalid)?;
        if worker
            .retained_refusal(&exchange, &attempt.record.worker_result)
            .map_err(|_| Invalid)?
            != retained
        {
            return Err(Invalid);
        }
        Ok(retained)
    }

    /// The retained worker refusal of `attempt`, verified against its exact retained worker
    /// original through the stored configuration pin (no live worker dependency); `None` when
    /// the attempt holds no worker refusal.
    /// # Errors
    /// A stored code that differs from the retained original, an altered original, a stale
    /// cursor or unavailable custody.
    pub fn verified_worker_refusal(
        &self,
        attempt: &EnrollmentAttemptV1,
    ) -> Result<Option<iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1>> {
        if attempt.worker_refusal().is_none() {
            return Ok(None);
        }
        let configuration = attempt.worker_configuration().ok_or(Invalid)?;
        self.retained_refusal(attempt, configuration).map(Some)
    }

    /// Recheck the exact retained evidence against the original request and worker selection.
    /// This is consistency evidence, not proof of worker custody, KYC or current eligibility.
    /// # Errors
    /// Refuses an unfinished/rejected attempt, corrupt evidence, changed configuration or custody.
    pub fn retained_worker_evidence(
        &self,
        attempt: &EnrollmentAttemptV1,
        configuration: [u8; 32],
    ) -> Result<EvidenceProjectionV1> {
        use EnrollmentJournalPhaseV1::{Evidence, Issued, Signing};
        if !matches!(attempt.phase(), Evidence | Signing | Issued) {
            return Err(Conflict);
        }
        let evidence = self
            .retained_worker_request(attempt, configuration)?
            .retained_evidence(&attempt.record.worker_result)
            .map_err(|_| Invalid)?;
        if evidence.evidence.time_ms != attempt.record.worker_result_time_ms {
            return Err(Invalid);
        }
        Ok(evidence)
    }

    /// Freeze the exact initial credential body and original issue time before invoking the
    /// independently admitted Enrollment signer. Retries recover this body without refreshing
    /// its time. The service must recheck current eligibility before signing or delivery.
    /// # Errors
    /// Refuses missing permits/evidence, changed selections, invalid trusted time, overflow,
    /// corrupt retained bodies or uncertain publication. No error grants signing authority.
    pub fn select_credential_body(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
        configuration: [u8; 32],
        issued_at_ms: u64,
    ) -> Result<KagemushaWalletCredentialBodyV1> {
        self.permit(attempt, dispatch)?.ok_or(Conflict)?;
        let evidence = self.retained_worker_evidence(attempt, configuration)?;
        let request = RequestV1::decode(&attempt.record.request).map_err(|_| Invalid)?;
        let retained = if matches!(
            attempt.phase(),
            EnrollmentJournalPhaseV1::Signing | EnrollmentJournalPhaseV1::Issued
        ) {
            Some(
                norito::decode_canonical_with_limits::<KagemushaWalletCredentialBodyV1>(
                    &attempt.record.credential_body,
                    norito::canonical_decode_limits(ORIGINAL_MAX),
                )
                .map_err(|_| Invalid)?,
            )
        } else {
            None
        };
        let time = retained
            .as_ref()
            .map_or(issued_at_ms, |body| body.issued_at_ms);
        if time == 0
            || time < attempt.record.verification_time_ms
            || time < evidence.evidence.time_ms
        {
            return Err(Invalid);
        }
        let request = &request.body;
        let body = KagemushaWalletCredentialBodyV1 {
            version: 1,
            scheme_id: request.challenge.scheme_id,
            asset_digest: request.challenge.asset_digest,
            wallet_id: request.marker.wallet_id,
            account_digest: request.challenge.account_digest,
            payment_key: request.marker.payment_key,
            provider_contract: dispatch.scheme.provider_contract,
            evidence_kind: evidence.kind,
            enrollment_evidence: evidence.evidence,
            fresh_evidence: evidence.evidence,
            app_policy: request.challenge.app_policy,
            regulatory_policy: request.policy.regulatory_policy,
            enrollment_id: request.challenge.enrollment_id(&request.marker.payment_key),
            issued_at_ms: time,
            renewal_sequence: 0,
            lease_expires_at_ms: request.policy.lease_expires_at(time).map_err(|_| Invalid)?,
            issuer_certificate: dispatch.enrollment_certificate.certificate_digest(),
        };
        body.validate().map_err(|_| Invalid)?;
        if let Some(retained) = retained {
            return if retained == body {
                Ok(retained)
            } else {
                Err(Conflict)
            };
        }
        let mut record = attempt.record.clone();
        record.phase = EnrollmentJournalPhaseV1::Signing;
        record.credential_body = norito::encode_canonical(&body).map_err(|_| Invalid)?;
        self.advance(attempt, record)?;
        Ok(body)
    }

    /// Durably record that the Enrollment signer is about to be invoked for the frozen body of
    /// this `Signing` attempt. It is written immediately before the signer call, so a recovered
    /// attempt with it set never invokes the signer again.
    /// # Errors
    /// Refuses another phase, a stale cursor or failed publication.
    pub fn mark_signing_dispatched(&mut self, attempt: &mut EnrollmentAttemptV1) -> Result<()> {
        if attempt.phase() != EnrollmentJournalPhaseV1::Signing {
            return Err(Conflict);
        }
        if attempt.record.signing_dispatched {
            return self.require_current(attempt);
        }
        let mut record = attempt.record.clone();
        record.signing_dispatched = true;
        self.advance(attempt, record)
    }

    /// Whether the Enrollment signer may already have been invoked for this attempt.
    pub fn signing_dispatched(&self, attempt: &EnrollmentAttemptV1) -> bool {
        attempt.record.signing_dispatched
    }

    /// Verify the actual signed E6 against the frozen body, selected issuer and worker originals,
    /// then retain its exact bytes before delivery. A retry can never replace a signed original.
    /// # Errors
    /// Refuses missing signing selection, foreign signatures/evidence, stale custody or failed
    /// publication. The caller still owns current eligibility, signing custody and ledger claims.
    pub fn retain_credential(
        &mut self,
        attempt: &mut EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
        configuration: [u8; 32],
        original: Vec<u8>,
    ) -> Result<()> {
        if !matches!(
            attempt.phase(),
            EnrollmentJournalPhaseV1::Signing | EnrollmentJournalPhaseV1::Issued
        ) {
            return Err(Conflict);
        }
        let body = self.select_credential_body(attempt, dispatch, configuration, 0)?;
        let request = RequestV1::decode(&attempt.record.request).map_err(|_| Invalid)?;
        let evidence = self.retained_worker_evidence(attempt, configuration)?;
        let result = ResultV1::decode(&original).map_err(|_| Invalid)?;
        let credential = result
            .verify_for(&dispatch.scheme, &dispatch.enrollment_certificate, &request)
            .map_err(|_| Invalid)?;
        if credential.body != body || result.evidence != evidence.originals {
            return Err(Conflict);
        }
        self.retain_issued(attempt, original)
    }
}
