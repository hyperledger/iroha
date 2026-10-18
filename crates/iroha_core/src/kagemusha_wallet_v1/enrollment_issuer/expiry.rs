//! Nonmonetary issuer expiry evidence for Native's Accepted/no-Slot cleanup.

use super::*;

impl<R: EnrollmentIssuerRuntimeV1> EnrollmentIssuerV1<R> {
    /// Authenticate an exact account-signed Resume envelope for an existing expiry statement.
    /// This never selects a new attempt, qualifies an adapter, or consults live eligibility or
    /// worker custody. Existing exact signed permit custody remains mandatory; new proof signing
    /// additionally checks current selected signer authority in [`Self::expiry_proof`].
    /// # Errors
    /// Rejects invalid or foreign account authentication, changed stable selection, a missing
    /// attempt, non-Resume input, or unavailable journal custody.
    pub fn authenticate_expiry(
        &mut self,
        call: &R::Call,
        dispatch_original: &[u8],
    ) -> Result<EnrollmentIssuerSessionV1> {
        let dispatch = PreKeyDispatchV1::decode(dispatch_original).map_err(|_| Invalid)?;
        if dispatch.purpose != KagemushaEnrollmentPermitPurposeV1::Resume {
            return Err(Invalid);
        }
        let account = self.runtime.authenticate_call(call, dispatch_original)?;
        if account != dispatch.account {
            return Err(Selection);
        }
        let digest = kagemusha_wallet_account_digest_v1(&account).map_err(|_| Invalid)?;
        let key = self.journal.request_key(&digest, &dispatch.request_id)?;
        let attempt = self.journal.read(&key)?.ok_or(Selection)?;
        if attempt.selection().stable_selection
            != dispatch.stable_selection().map_err(|_| Invalid)?
        {
            return Err(Selection);
        }
        Ok(EnrollmentIssuerSessionV1 {
            issuer: self.incarnation,
            dispatch,
            attempt,
        })
    }

    /// Return an exact retained proof that the original Fresh E1 deadline has passed.
    ///
    /// The session must come from current account authentication of the exact Resume dispatch.
    /// This does not assert key absence: Native checks its retained Accepted original and actual
    /// no-Slot custody. No eligibility observation, worker action, enrollment phase transition,
    /// credential issuance or quota effect occurs. Advanced attempts keep their original outcome.
    ///
    /// # Errors
    /// Rejects a foreign/stale session, substituted or non-Resume originals, an unexpired E1,
    /// changed current signer selection, bad signatures or uncertain journal custody.
    pub fn expiry_proof(&mut self, session: &mut EnrollmentIssuerSessionV1) -> Result<Vec<u8>> {
        if session.issuer != self.incarnation {
            return Err(Selection);
        }
        // Eligibility refusals are not an assertion that E1 is still live. The immutable expiry
        // statement has no monetary effect and does not replace any retained refusal or E6.
        if let Some(original) = self
            .journal
            .expiry_proof(&session.attempt, &session.dispatch)?
        {
            return Ok(original);
        }
        let selected = self.current_expiry(&session.dispatch)?;
        let observed_at_ms = self.now()?;
        let body =
            self.journal
                .expiry_statement(&session.attempt, &session.dispatch, observed_at_ms)?;
        if self.current_expiry(&session.dispatch)? != selected {
            return Err(Selection);
        }
        self.now()?;
        let signature = self.runtime.sign_enrollment(
            &selected.provider,
            &body.signing_message().map_err(|_| Invalid)?,
        )?;
        let proof = KagemushaEnrollmentExpiryProofV1::from_issuer_der(
            body,
            &session.dispatch.enrollment_certificate,
            &signature,
        )
        .map_err(|_| Invalid)?;
        proof
            .verify(
                &session.dispatch.scheme,
                &session.dispatch.enrollment_certificate,
            )
            .map_err(|_| Invalid)?;
        let original = proof.encode_canonical().map_err(|_| Invalid)?;
        self.journal
            .retain_expiry_proof(&session.attempt, &session.dispatch, original.clone())?;
        if self.current_expiry(&session.dispatch)? != selected {
            return Err(Selection);
        }
        self.now()?;
        Ok(original)
    }
}
