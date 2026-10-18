//! Exact original pre-key permit publication and authenticated resume recovery.
use super::*;
use iroha_core_zk::kagemusha_wallet_enrollment_v1::PreKeyDispatchV1;
use iroha_data_model::kagemusha::{
    KagemushaEnrollmentPermitPurposeV1, KagemushaEnrollmentPermitV1,
};

#[derive(Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core.kagemusha.enrollment.journal_permit.v1")]
struct PermitRecord {
    version: u16,
    scope: [u8; 32],
    key: [u8; 32],
    dispatch: Vec<u8>,
    permit: Vec<u8>,
}
fn name(key: &[u8; 32], nonce: &[u8; 32]) -> Result<String> {
    if *key == [0; 32] || *nonce == [0; 32] {
        return Err(Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(b"iroha:kagemusha:issuer-permit-dispatch:v1\0");
    hash.update(key);
    hash.update(nonce);
    Ok(format!("permit-{}.norito", hex::encode(hash.finalize())))
}
fn selected(
    attempt: &EnrollmentAttemptV1,
    dispatch: &PreKeyDispatchV1,
    permit: &KagemushaEnrollmentPermitV1,
) -> Result<()> {
    dispatch.validate().map_err(|_| Invalid)?;
    dispatch
        .require_permit_selection(permit)
        .map_err(|_| Invalid)?;
    let selection = attempt.selection();
    if dispatch.stable_selection().map_err(|_| Invalid)? != selection.stable_selection
        || permit.body.attempt_id != selection.attempt_id
        || permit.body.challenge != selection.challenge
        || permit.body.created_at_ms != selection.created_at_ms
        || permit.body.expires_at_ms != selection.expires_at_ms
        || permit.body.purpose != dispatch.purpose
        || permit.body.native_dispatch_nonce != dispatch.native_dispatch_nonce
    {
        return Err(Conflict);
    }
    Ok(())
}
impl EnrollmentJournalV1 {
    /// Authenticate the retained Fresh permit named by a current Resume dispatch.
    /// This reads existing journal custody only and grants no live authorization.
    pub(super) fn expiry_permit(
        &self,
        attempt: &EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
    ) -> Result<KagemushaEnrollmentPermitV1> {
        self.require_current(attempt)?;
        dispatch.validate().map_err(|_| Invalid)?;
        if dispatch.stable_selection().map_err(|_| Invalid)? != attempt.selection().stable_selection
        {
            return Err(Conflict);
        }
        if dispatch.purpose != KagemushaEnrollmentPermitPurposeV1::Resume {
            return Err(Invalid);
        }
        let previous = KagemushaEnrollmentPermitV1::decode_canonical(
            dispatch.previous_permit.as_deref().ok_or(Invalid)?,
            &dispatch.scheme,
            &dispatch.enrollment_certificate,
        )
        .map_err(|_| Invalid)?;
        if previous.body.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
            || previous.body.native_dispatch_nonce == dispatch.native_dispatch_nonce
        {
            return Err(Conflict);
        }
        let retained = self
            .read_permit(attempt, &previous.body.native_dispatch_nonce)?
            .ok_or(Conflict)?;
        if Some(retained.permit.as_slice()) != dispatch.previous_permit.as_deref() {
            return Err(Conflict);
        }
        Ok(previous)
    }

    fn read_permit(
        &self,
        attempt: &EnrollmentAttemptV1,
        nonce: &[u8; 32],
    ) -> Result<Option<PermitRecord>> {
        self.require_current(attempt)?;
        let bytes = self
            .directory
            .read_optional(name(&attempt.selection().key, nonce)?, PERMIT_RECORD_MAX);
        self.require_custody()?;
        let Some(bytes) = bytes.map_err(|_| Unavailable)? else {
            return Ok(None);
        };
        let record: PermitRecord = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(PERMIT_RECORD_MAX),
        )
        .map_err(|_| Invalid)?;
        if record.version != 1
            || record.scope != self.scope
            || record.key != attempt.selection().key
        {
            return Err(Invalid);
        }
        let dispatch = PreKeyDispatchV1::decode(&record.dispatch).map_err(|_| Invalid)?;
        let permit = KagemushaEnrollmentPermitV1::decode_canonical(
            &record.permit,
            &dispatch.scheme,
            &dispatch.enrollment_certificate,
        )
        .map_err(|_| Invalid)?;
        selected(attempt, &dispatch, &permit)?;
        if dispatch.native_dispatch_nonce != *nonce {
            return Err(Conflict);
        }
        self.adopt(&name(&attempt.selection().key, nonce)?, &bytes)?;
        Ok(Some(record))
    }

    fn require_dispatch(
        &self,
        attempt: &EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
    ) -> Result<()> {
        self.require_current(attempt)?;
        if dispatch.stable_selection().map_err(|_| Invalid)? != attempt.selection().stable_selection
        {
            return Err(Conflict);
        }
        // No signed E1 can leave the service before its selected private worker has durably
        // prepared that exact operation under the incarnation retained in this journal.
        let preparation = attempt.record.worker_preparation.as_ref().ok_or(Conflict)?;
        self.require_worker_prepared(attempt, preparation.configuration)?;
        if dispatch.purpose == KagemushaEnrollmentPermitPurposeV1::Resume {
            let original = dispatch.previous_permit.as_ref().ok_or(Invalid)?;
            let previous = KagemushaEnrollmentPermitV1::decode_canonical(
                original,
                &dispatch.scheme,
                &dispatch.enrollment_certificate,
            )
            .map_err(|_| Invalid)?;
            let retained = self
                .read_permit(attempt, &previous.body.native_dispatch_nonce)?
                .ok_or(Conflict)?;
            if retained.permit != *original {
                return Err(Conflict);
            }
        }
        Ok(())
    }

    /// Recover this exact native dispatch's actual signed original before considering signing.
    /// Resume additionally requires the previous permit to exist byte-for-byte in this journal.
    /// Returning a retained permit does not bypass the native owner's current nonce/elapsed check.
    /// # Errors
    /// Refuses a stale attempt, changed dispatch, unknown previous permit or unavailable custody.
    pub fn permit(
        &self,
        attempt: &EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
    ) -> Result<Option<Vec<u8>>> {
        self.require_dispatch(attempt, dispatch)?;
        let original = dispatch.encode().map_err(|_| Invalid)?;
        self.read_permit(attempt, &dispatch.native_dispatch_nonce)?
            .map(|record| {
                if record.dispatch != original {
                    Err(Conflict)
                } else {
                    Ok(record.permit)
                }
            })
            .transpose()
    }

    /// Authenticate and durably freeze the actual rooted Enrollment signer output before delivery.
    /// This only checks the already selected originals; independent KYC/current service approval
    /// and authenticated signing custody are still required at the calling service boundary.
    /// # Errors
    /// Refuses another attempt/deadline/nonce/role/key, changed signature or uncertain publication.
    pub fn retain_permit(
        &mut self,
        attempt: &EnrollmentAttemptV1,
        dispatch: &PreKeyDispatchV1,
        original: Vec<u8>,
    ) -> Result<()> {
        self.require_dispatch(attempt, dispatch)?;
        if attempt.refusal().is_some() {
            return Err(Conflict);
        }
        let permit = KagemushaEnrollmentPermitV1::decode_canonical(
            &original,
            &dispatch.scheme,
            &dispatch.enrollment_certificate,
        )
        .map_err(|_| Invalid)?;
        selected(attempt, dispatch, &permit)?;
        if let Some(prior) = self.permit(attempt, dispatch)? {
            return if prior == original {
                Ok(())
            } else {
                Err(Conflict)
            };
        }
        let record = PermitRecord {
            version: 1,
            scope: self.scope,
            key: attempt.selection().key,
            dispatch: dispatch.encode().map_err(|_| Invalid)?,
            permit: original,
        };
        let bytes = norito::encode_canonical(&record).map_err(|_| Invalid)?;
        if bytes.len() > PERMIT_RECORD_MAX {
            return Err(Invalid);
        }
        self.publish(
            &name(&record.key, &dispatch.native_dispatch_nonce)?,
            &bytes,
            PublishMode::CreateNew,
        )
    }
}
