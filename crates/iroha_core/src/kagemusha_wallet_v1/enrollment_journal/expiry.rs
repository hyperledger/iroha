//! Exact nonmonetary expiry statements, separate from enrollment phases and credential custody.

use super::*;
use iroha_core_zk::kagemusha_wallet_enrollment_v1::PreKeyDispatchV1;
use iroha_data_model::kagemusha::{
    KagemushaEnrollmentExpiryProofBodyV1, KagemushaEnrollmentExpiryProofV1,
};

const EXPIRY_RECORD_MAX: usize = 24 * 1024;

#[derive(Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.journal_expiry.v1")]
struct ExpiryRecord {
    version: u16,
    scope: [u8; 32],
    key: [u8; 32],
    dispatch: Vec<u8>,
    proof: Vec<u8>,
}

fn name(key: &[u8; 32], dispatch: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"iroha:kagemusha:issuer-expiry-dispatch:v1\0");
    hash.update(key);
    hash.update((dispatch.len() as u64).to_le_bytes());
    hash.update(dispatch);
    format!("expiry-{}.norito", hex::encode(hash.finalize()))
}

impl EnrollmentJournalV1 {
    /// Bind a trusted issuer clock observation to the exact retained Fresh permit and Resume.
    /// This statement proves only deadline passage. Native must separately establish its
    /// Accepted/no-Slot custody; this never changes an attempt phase or authorizes an effect.
    /// # Errors
    /// Rejects a non-Resume or substituted dispatch/permit, stale journal cursor, unavailable
    /// custody, and an observation before the original deadline.
    pub fn expiry_statement(
        &self,
        attempt: &EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
        observed_at_ms: u64,
    ) -> Result<KagemushaEnrollmentExpiryProofBodyV1> {
        let permit = self.expiry_permit(attempt, dispatch)?;
        let body = KagemushaEnrollmentExpiryProofBodyV1::new(
            dispatch.request_id,
            Sha256::digest(dispatch.encode().map_err(|_| Invalid)?).into(),
            Sha256::digest(dispatch.previous_permit.as_deref().ok_or(Invalid)?).into(),
            permit.body.attempt_id,
            permit.body.challenge.challenge_digest(),
            permit.body.expires_at_ms,
            observed_at_ms,
        );
        body.validate().map_err(|_| Invalid)?;
        Ok(body)
    }

    /// Recover this exact dispatch's durably retained expiry proof without consulting live
    /// eligibility, signing again, or changing its original observation time.
    /// # Errors
    /// Rejects changed dispatch/permit/proof bindings, invalid signer output, lost custody,
    /// stale attempt cursors or uncertain adoption. An I/O failure never means absence.
    pub fn expiry_proof(
        &self,
        attempt: &EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
    ) -> Result<Option<Vec<u8>>> {
        self.expiry_permit(attempt, dispatch)?;
        let original = dispatch.encode().map_err(|_| Invalid)?;
        let filename = name(&attempt.selection().key, &original);
        let bytes = self.directory.read_optional(&filename, EXPIRY_RECORD_MAX);
        self.require_custody()?;
        let Some(bytes) = bytes.map_err(|_| Unavailable)? else {
            return Ok(None);
        };
        let record: ExpiryRecord = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(EXPIRY_RECORD_MAX),
        )
        .map_err(|_| Invalid)?;
        if record.version != 1
            || record.scope != self.scope
            || record.key != attempt.selection().key
            || record.dispatch != original
        {
            return Err(Conflict);
        }
        self.require_expiry_proof(attempt, dispatch, &record.proof)?;
        self.adopt(&filename, &bytes)?;
        Ok(Some(record.proof))
    }

    fn require_expiry_proof(
        &self,
        attempt: &EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
        original: &[u8],
    ) -> Result<()> {
        let proof =
            KagemushaEnrollmentExpiryProofV1::decode_canonical(original).map_err(|_| Invalid)?;
        proof
            .verify(&dispatch.scheme, &dispatch.enrollment_certificate)
            .map_err(|_| Invalid)?;
        if proof.body != self.expiry_statement(attempt, dispatch, proof.body.observed_at_ms)? {
            return Err(Conflict);
        }
        Ok(())
    }

    /// Publish the actual verified signer output before returning expiry proof bytes to a holder.
    /// Existing exact originals are adopted; a different signature or observation conflicts.
    /// No enrollment phase, credential, quota share or refusal is modified.
    /// # Errors
    /// Rejects invalid, foreign or changed proof originals, stale attempts, unavailable custody
    /// or uncertain publication. Recovery must reopen after an uncertain write.
    pub fn retain_expiry_proof(
        &mut self,
        attempt: &EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
        original: Vec<u8>,
    ) -> Result<()> {
        self.require_expiry_proof(attempt, dispatch, &original)?;
        if let Some(prior) = self.expiry_proof(attempt, dispatch)? {
            return if prior == original {
                Ok(())
            } else {
                Err(Conflict)
            };
        }
        let record = ExpiryRecord {
            version: 1,
            scope: self.scope,
            key: attempt.selection().key,
            dispatch: dispatch.encode().map_err(|_| Invalid)?,
            proof: original,
        };
        let bytes = norito::encode_canonical(&record).map_err(|_| Invalid)?;
        if bytes.len() > EXPIRY_RECORD_MAX {
            return Err(Invalid);
        }
        self.publish(
            &name(&record.key, &record.dispatch),
            &bytes,
            PublishMode::CreateNew,
        )
    }
}

#[cfg(test)]
mod tests;
