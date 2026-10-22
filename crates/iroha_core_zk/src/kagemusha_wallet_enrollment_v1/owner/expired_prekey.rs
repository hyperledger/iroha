//! Authenticated, immutable E1 expiry before any Slot or enrollment phase selection.

use super::{prekey_owner::Pending, *};

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> EnrollmentOwnerV1<F, P> {
    /// Authenticate a retained terminal proof. Its original dispatch nonce need not be the
    /// new process's nonce: the issuer signature, request and exact Accepted original bind the
    /// terminal statement permanently. It grants no live authorization or key effect.
    pub(super) fn client_expired(
        &mut self,
        dispatch: &PreKeyDispatchV1,
        client_digest: &[u8; 32],
    ) -> Result<bool, Error> {
        let Some(bytes) = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Expired)?
        else {
            return Ok(false);
        };
        self.require_expired_originals(dispatch, client_digest, &bytes, false)?;
        self.provider
            .prekey_adopt(&dispatch.request_id, &[PreKeyRecordV1::Expired])?;
        if self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Expired)?
            .as_deref()
            != Some(bytes.as_slice())
        {
            return Err(Error::Original("expired pre-key proof changed"));
        }
        Ok(true)
    }

    fn require_expired_originals(
        &mut self,
        dispatch: &PreKeyDispatchV1,
        client_digest: &[u8; 32],
        proof_bytes: &[u8],
        current_dispatch: bool,
    ) -> Result<(), Error> {
        if dispatch.purpose != KagemushaEnrollmentPermitPurposeV1::Resume {
            return Err(Error::Phase);
        }
        let accepted = dispatch.previous_permit.as_deref().ok_or(Error::Phase)?;
        let proof = original(KagemushaEnrollmentExpiryProofV1::decode_canonical(
            proof_bytes,
        ))?;
        if original(proof.encode_canonical())? != proof_bytes {
            return Err(Error::Original("pre-key expiry proof"));
        }
        original(proof.verify(&self.config.scheme, &self.config.enrollment_certificate))?;
        let id = dispatch.request_id;
        let client = self
            .provider
            .prekey_read(&id, PreKeyRecordV1::Client)?
            .ok_or(Error::Original("selected pre-key client lost"))?;
        let retained = PreKeyDispatchV1::decode(&client).map_err(Error::Original)?;
        if retained.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
            || retained.previous_permit.is_some()
            || retained.request_id != id
            || retained.stable_selection().map_err(Error::Original)?
                != dispatch.stable_selection().map_err(Error::Original)?
            || kagemusha_wallet_prekey_client_digest_v1(&client) != *client_digest
            || self
                .provider
                .prekey_read(&id, PreKeyRecordV1::Accepted)?
                .as_deref()
                != Some(accepted)
        {
            return Err(Error::Original("pre-key retained selection changed"));
        }
        let permit = original(KagemushaEnrollmentPermitV1::decode_canonical(
            accepted,
            &self.config.scheme,
            &self.config.enrollment_certificate,
        ))?;
        dispatch
            .require_permit_selection(&permit)
            .map_err(Error::Original)?;
        let permit_sha256: [u8; 32] = Sha256::digest(accepted).into();
        if permit.body.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
            || proof.body.request_id != id
            || proof.body.permit_sha256 != permit_sha256
            || proof.body.attempt_id != permit.body.attempt_id
            || proof.body.challenge_digest != permit.body.challenge.challenge_digest()
            || proof.body.expires_at_ms != permit.body.expires_at_ms
        {
            return Err(Error::Original("pre-key expiry proof binding"));
        }
        if current_dispatch {
            let dispatch_sha256: [u8; 32] =
                Sha256::digest(dispatch.encode().map_err(Error::Original)?).into();
            if proof.body.dispatch_sha256 != dispatch_sha256 {
                return Err(Error::Original("pre-key expiry dispatch binding"));
            }
        }
        self.require_expiry_unselected(&id)?;
        // A lost Slot/Phase association must not release actual custody. Missing intents are
        // not absence either, except for the already terminal provider no-marker form.
        for slot in self.provider.slots()? {
            match self.provider.read_intent_for_enrollment_search(&slot)? {
                Some(intent) if intent.challenge == permit.body.challenge => {
                    return Err(Error::Original("selected pre-key slot lost"));
                }
                Some(_) => {}
                None if self.provider.is_abandoned_without_marker(&slot)? => {}
                None => return Err(Error::Original("unselected custody intent lost")),
            }
        }
        self.provider
            .prekey_adopt(&id, &[PreKeyRecordV1::Client, PreKeyRecordV1::Accepted])?;
        self.require_expiry_unselected(&id)?;
        if self
            .provider
            .prekey_read(&id, PreKeyRecordV1::Client)?
            .as_deref()
            != Some(client.as_slice())
            || self
                .provider
                .prekey_read(&id, PreKeyRecordV1::Accepted)?
                .as_deref()
                != Some(accepted)
        {
            return Err(Error::Original("pre-key retained selection changed"));
        }
        Ok(())
    }

    fn require_expiry_unselected(&self, id: &[u8; 32]) -> Result<(), Error> {
        for role in [
            PreKeyRecordV1::Slot,
            PreKeyRecordV1::Phase,
            PreKeyRecordV1::Cancelled,
        ] {
            if self.provider.prekey_read(id, role)?.is_some() {
                return Err(Error::Phase);
            }
        }
        Ok(())
    }

    /// Fresh publication binds the exact current dispatch. Retry adopts the already signed
    /// terminal proof even after a new dispatch or a crash before app DATA publication.
    pub(super) fn abandon_expired_accepted(
        &mut self,
        proof_bytes: &[u8],
    ) -> Result<EnrollmentAbandonmentV1, Error> {
        let Some(Pending::Dispatch {
            dispatch,
            client_digest,
            ..
        }) = self.pending.clone()
        else {
            return Err(Error::Phase);
        };
        if !self.client_expired(&dispatch, &client_digest)? {
            self.require_expired_originals(&dispatch, &client_digest, proof_bytes, true)?;
            self.provider.prekey_retain(
                &dispatch.request_id,
                PreKeyRecordV1::Expired,
                proof_bytes,
            )?;
            if !self.client_expired(&dispatch, &client_digest)? {
                return Err(Error::Phase);
            }
        }
        // Keep the selected terminal dispatch so an immediate retry returns the same outcome.
        // Every key-effect entry point checks the durable marker before accepting authority.
        self.request = None;
        self.selected = None;
        Ok(EnrollmentAbandonmentV1::LocalAbandoned)
    }
}
