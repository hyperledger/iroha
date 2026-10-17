//! Live issuer permit admission and immutable client/attempt/slot selection.
use super::*;
use crate::kagemusha_wallet_enrollment_v1::prekey::{
    GenerationAuthorizationV1, PreKeyDispatchV1, require_elapsed,
};
use rand::rand_core::TryRngCore as _;

#[derive(Clone)]
pub(super) enum Pending {
    Dispatch {
        dispatch: Box<PreKeyDispatchV1>,
        started: LiveEnrollmentReadingV1,
        /// Digest of the exact Client original `begin` authenticated.
        client_digest: [u8; 32],
    },
    Account {
        dispatch: Box<PreKeyDispatchV1>,
        started: LiveEnrollmentReadingV1,
        permit: KagemushaEnrollmentPermitV1,
        original: Vec<u8>,
        message: [u8; 32],
        /// Digest of the exact Client original `begin` authenticated.
        client_digest: [u8; 32],
    },
}
use crate::kagemusha_wallet_advance_v1::PreKeySlotSelectionV1 as SlotSelection;
fn nonce() -> Result<[u8; 32], Error> {
    let mut value = [0; 32];
    while value == [0; 32] {
        rand::rngs::OsRng
            .try_fill_bytes(&mut value)
            .map_err(|_| Error::Original("native entropy unavailable"))?;
    }
    Ok(value)
}
fn scope(role: KagemushaEnrollmentPermitScopeRoleV1, bytes: &[u8]) -> Result<[u8; 32], Error> {
    original(kagemusha_enrollment_permit_scope_digest_v1(role, bytes))
}
impl EnrollmentConfigV1 {
    pub(super) fn verify_prekey(&self) -> Result<(), Error> {
        if self.installation.scheme_id != self.scheme.scheme_id()
            || self.installation.manifest_digest == [0; 32]
        {
            return Err(Error::Original("pre-key installed scope"));
        }
        original(
            self.enrollment_certificate
                .verify_role(&self.scheme, KagemushaWalletSignerRoleV1::Enrollment),
        )?;
        self.scopes().map(|_| ())
    }
    fn scopes(&self) -> Result<[[u8; 32]; 4], Error> {
        use KagemushaEnrollmentPermitScopeRoleV1 as R;
        Ok([
            scope(R::Release, &self.release)?,
            scope(R::ServiceOrigin, &self.service_origin)?,
            scope(R::Fi, &self.fi)?,
            scope(R::Actor, &self.actor)?,
        ])
    }
    fn dispatch(
        &self,
        request_id: [u8; 32],
        account: AccountId,
        asset: KagemushaWalletAssetScopeV1,
        client_nonce: [u8; 32],
        native_dispatch_nonce: [u8; 32],
        previous_permit: Option<Vec<u8>>,
    ) -> Result<PreKeyDispatchV1, Error> {
        let [
            release_digest,
            service_origin_digest,
            fi_digest,
            actor_digest,
        ] = self.scopes()?;
        let platform = match &self.policy.platform {
            KagemushaWalletEnrollmentPlatformV1::Android { .. } => {
                KagemushaEnrollmentPermitPlatformV1::Android
            }
            KagemushaWalletEnrollmentPlatformV1::Apple { .. } => {
                KagemushaEnrollmentPermitPlatformV1::Apple
            }
        };
        Ok(PreKeyDispatchV1 {
            version: 1,
            request_id,
            platform,
            purpose: if previous_permit.is_some() {
                KagemushaEnrollmentPermitPurposeV1::Resume
            } else {
                KagemushaEnrollmentPermitPurposeV1::Fresh
            },
            client_nonce,
            native_dispatch_nonce,
            manifest_digest: self.installation.manifest_digest,
            release_digest,
            service_origin_digest,
            fi_digest,
            actor_digest,
            scheme: self.scheme,
            app: self.app.clone(),
            policy: self.policy.clone(),
            enrollment_certificate: self.enrollment_certificate,
            account,
            asset,
            previous_permit,
        })
    }
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> EnrollmentOwnerV1<F, P> {
    /// Recheck terminal pre-permit control under the same exclusive provider owner used for
    /// permit admission and key effects. It is never supplied by the app or issuer.
    fn client_cancelled(
        &self,
        dispatch: &PreKeyDispatchV1,
        client_digest: &[u8; 32],
    ) -> Result<bool, Error> {
        let Some(cancelled) = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Cancelled)?
        else {
            return Ok(false);
        };
        let client = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Client)?
            .ok_or(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "cancelled pre-key client",
            })?;
        if cancelled.as_slice() != client_digest
            || kagemusha_wallet_prekey_client_digest_v1(&client) != *client_digest
        {
            return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "cancelled pre-key binding",
            }
            .into());
        }
        for role in [
            PreKeyRecordV1::Accepted,
            PreKeyRecordV1::Slot,
            PreKeyRecordV1::Phase,
        ] {
            if self
                .provider
                .prekey_read(&dispatch.request_id, role)?
                .is_some()
            {
                return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "cancelled pre-key selection",
                }
                .into());
            }
        }
        self.provider.prekey_adopt(
            &dispatch.request_id,
            &[PreKeyRecordV1::Client, PreKeyRecordV1::Cancelled],
        )?;
        Ok(true)
    }
    fn require_pending_uncancelled(&mut self) -> Result<(), Error> {
        let pending = self.pending.clone();
        let (dispatch, digest) = match &pending {
            Some(
                Pending::Dispatch {
                    dispatch,
                    client_digest,
                    ..
                }
                | Pending::Account {
                    dispatch,
                    client_digest,
                    ..
                },
            ) => (dispatch, client_digest),
            None => return Err(Error::Phase),
        };
        if self.client_cancelled(dispatch, digest)? || self.client_expired(dispatch, digest)? {
            return Err(Error::Phase);
        }
        Ok(())
    }
    pub(super) fn abandon_unselected_client(&mut self) -> Result<EnrollmentAbandonmentV1, Error> {
        let Some(Pending::Dispatch {
            dispatch,
            client_digest,
            ..
        }) = self.pending.clone()
        else {
            return Err(Error::Phase);
        };
        if self.client_expired(&dispatch, &client_digest)? {
            self.request = None;
            return Ok(EnrollmentAbandonmentV1::LocalAbandoned);
        }
        if dispatch.previous_permit.is_some()
            || dispatch.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
        {
            return Err(Error::Phase);
        }
        let client = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Client)?
            .ok_or(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "cancelled pre-key client",
            })?;
        let retained = PreKeyDispatchV1::decode(&client).map_err(|_| {
            KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "cancelled pre-key client",
            }
        })?;
        if kagemusha_wallet_prekey_client_digest_v1(&client) != client_digest
            || retained.stable_selection().map_err(Error::Original)?
                != dispatch.stable_selection().map_err(Error::Original)?
        {
            return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "cancelled pre-key binding",
            }
            .into());
        }
        if self.client_cancelled(&dispatch, &client_digest)? {
            return Ok(EnrollmentAbandonmentV1::LocalAbandoned);
        }
        self.provider
            .prekey_adopt(&dispatch.request_id, &[PreKeyRecordV1::Client])?;
        for role in [
            PreKeyRecordV1::Accepted,
            PreKeyRecordV1::Slot,
            PreKeyRecordV1::Phase,
        ] {
            if self
                .provider
                .prekey_read(&dispatch.request_id, role)?
                .is_some()
            {
                return Err(Error::Phase);
            }
        }
        match self.provider.prekey_retain(
            &dispatch.request_id,
            PreKeyRecordV1::Cancelled,
            &client_digest,
        )? {
            PreKeyPublicationV1::Published => {}
            PreKeyPublicationV1::Existing(bytes) if bytes == client_digest => {}
            PreKeyPublicationV1::Existing(_) => {
                return Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "cancelled pre-key binding",
                }
                .into());
            }
        }
        if !self.client_cancelled(&dispatch, &client_digest)? {
            return Err(Error::Phase);
        }
        self.request = None;
        Ok(EnrollmentAbandonmentV1::LocalAbandoned)
    }

    /// Native provisioning identity; foreign enrollment DATA cannot change it.
    #[must_use]
    pub fn installation(&self) -> crate::kagemusha_wallet_artifacts_v1::InstallationV1 {
        self.config.installation
    }

    /// Retain native client identity before issuer E1 and sample a fresh live dispatch.
    /// Repeated request IDs preserve exact originals/client nonce across uncertainty/restart.
    pub fn begin(
        &mut self,
        request_id: &[u8],
        account: &[u8],
        asset: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.flush_apple_returned()?;
        self.pending = None;
        self.request = None;
        self.selected = None;
        let id: [u8; 32] = request_id
            .try_into()
            .map_err(|_| Error::Original("pre-key request identity"))?;
        if id == [0; 32] {
            return Err(Error::Original("pre-key request identity"));
        }
        let account: AccountId = decode(account, 4096)?;
        let asset: KagemushaWalletAssetScopeV1 = decode(asset, 1024)?;
        let existing = self.provider.prekey_read(&id, PreKeyRecordV1::Client)?;
        let accepted = self.provider.prekey_read(&id, PreKeyRecordV1::Accepted)?;
        let slot = self.provider.prekey_read(&id, PreKeyRecordV1::Slot)?;
        let phase = self.provider.prekey_read(&id, PreKeyRecordV1::Phase)?;
        let cancelled = self.provider.prekey_read(&id, PreKeyRecordV1::Cancelled)?;
        let expired = self.provider.prekey_read(&id, PreKeyRecordV1::Expired)?;
        if existing.is_none()
            && (accepted.is_some()
                || slot.is_some()
                || phase.is_some()
                || cancelled.is_some()
                || expired.is_some())
        {
            return Err(Error::Original("selected pre-key client lost"));
        }
        if accepted.is_none() && (slot.is_some() || phase.is_some()) {
            return Err(Error::Original("selected pre-key permit lost"));
        }
        let client_nonce = match &existing {
            Some(bytes) => {
                let original = PreKeyDispatchV1::decode(bytes).map_err(Error::Original)?;
                if original.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
                    || original.previous_permit.is_some()
                {
                    return Err(Error::Original("pre-key initial dispatch"));
                }
                original.client_nonce
            }
            None => nonce()?,
        };
        let mut dispatch =
            self.config
                .dispatch(id, account, asset, client_nonce, nonce()?, None)?;
        let proposed = dispatch.encode().map_err(Error::Original)?;
        let retained = match self
            .provider
            .prekey_retain(&id, PreKeyRecordV1::Client, &proposed)?
        {
            PreKeyPublicationV1::Published => proposed,
            PreKeyPublicationV1::Existing(bytes) => bytes,
        };
        let initial = PreKeyDispatchV1::decode(&retained).map_err(Error::Original)?;
        if initial.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
            || initial.previous_permit.is_some()
            || initial.request_id != id
            || initial.client_nonce != client_nonce
            || initial.stable_selection().map_err(Error::Original)?
                != dispatch.stable_selection().map_err(Error::Original)?
        {
            return Err(Error::Original("pre-key request changed originals"));
        }
        let client_digest = kagemusha_wallet_prekey_client_digest_v1(&retained);
        self.client_cancelled(&dispatch, &client_digest)?;
        dispatch.previous_permit = accepted;
        if dispatch.previous_permit.is_some() {
            dispatch.purpose = KagemushaEnrollmentPermitPurposeV1::Resume;
        }
        dispatch.validate().map_err(Error::Original)?;
        // A terminal marker remains terminal across new dispatch nonces. `begin` exposes
        // recovery DATA only; permit/account admission below rechecks it before any effect.
        self.client_expired(&dispatch, &client_digest)?;
        if let (Some(original), Some(slot)) = (&dispatch.previous_permit, slot) {
            let selected = self.decode_slot(&dispatch, original, &slot)?;
            let permit = KagemushaEnrollmentPermitV1::decode_canonical(
                original,
                &self.config.scheme,
                &self.config.enrollment_certificate,
            )
            .map_err(|_| Error::Original("pre-key permit"))?;
            self.selected = Some((
                Scope {
                    request_id: dispatch.request_id,
                    challenge: permit.body.challenge,
                    dates: KagemushaWalletEnrollmentDatesV1 {
                        issued_at_ms: permit.body.created_at_ms,
                        expires_at_ms: permit.body.expires_at_ms,
                    },
                    account: dispatch.account.clone(),
                    asset: dispatch.asset.clone(),
                },
                KagemushaWalletSlotIdV1(selected.slot),
            ));
        } else {
            self.selected = None;
        }
        let started = self.provider.live_enrollment_reading()?;
        let bytes = dispatch.encode().map_err(Error::Original)?;
        self.pending = Some(Pending::Dispatch {
            dispatch: Box::new(dispatch),
            started,
            client_digest,
        });
        Ok(bytes)
    }

    /// Admit an issuer-signed permit for this live dispatch, then expose the exact existing-
    /// account signing challenge. No decoded permit or persisted clock becomes live authority.
    pub fn accept_permit(&mut self, bytes: &[u8]) -> Result<[u8; 32], Error> {
        self.require_pending_uncancelled()?;
        let retained = self.pending.clone();
        let result = self.accept_permit_retained(bytes);
        // Unavailable storage, clock or hardware keeps the exact live dispatch/account
        // challenge. Invalid authenticated inputs intentionally consume it.
        if matches!(result, Err(Error::Provider(_))) {
            self.pending = retained;
        }
        result
    }
    fn accept_permit_retained(&mut self, bytes: &[u8]) -> Result<[u8; 32], Error> {
        if let Some(Pending::Account {
            original, message, ..
        }) = &self.pending
        {
            if original == bytes {
                return Ok(*message);
            }
        }
        let Some(Pending::Dispatch {
            dispatch,
            started,
            client_digest,
        }) = self.pending.take()
        else {
            return Err(Error::Phase);
        };
        let permit = original(KagemushaEnrollmentPermitV1::decode_canonical(
            bytes,
            &self.config.scheme,
            &self.config.enrollment_certificate,
        ))?;
        dispatch
            .require_permit_selection(&permit)
            .map_err(Error::Original)?;
        if permit.body.native_dispatch_nonce != dispatch.native_dispatch_nonce
            || permit.body.purpose != dispatch.purpose
        {
            return Err(Error::Original("pre-key live dispatch"));
        }
        if permit.body.observed_at_ms < self.config.session_valid_from_ms
            || permit.body.observed_at_ms >= self.config.session_expires_at_ms
        {
            return Err(Error::Original("authenticated session observation"));
        }
        require_elapsed(
            &started,
            &self.provider.live_enrollment_reading()?,
            permit.body.observed_at_ms,
            permit
                .body
                .expires_at_ms
                .min(self.config.session_expires_at_ms),
        )
        .map_err(Error::Original)?;
        let selected = match &dispatch.previous_permit {
            Some(original) => original.as_slice(),
            None => bytes,
        };
        let retained = match self.provider.prekey_retain(
            &dispatch.request_id,
            PreKeyRecordV1::Accepted,
            selected,
        )? {
            PreKeyPublicationV1::Published => selected.to_vec(),
            PreKeyPublicationV1::Existing(original) => original,
        };
        let first = original(KagemushaEnrollmentPermitV1::decode_canonical(
            &retained,
            &self.config.scheme,
            &self.config.enrollment_certificate,
        ))?;
        dispatch
            .require_permit_selection(&first)
            .map_err(Error::Original)?;
        if first.body.attempt_id != permit.body.attempt_id
            || first.body.challenge != permit.body.challenge
            || first.body.created_at_ms != permit.body.created_at_ms
            || first.body.expires_at_ms != permit.body.expires_at_ms
        {
            return Err(Error::Original("pre-key original attempt changed"));
        }
        let transcript = norito::encode_canonical(&(
            dispatch.stable_selection().map_err(Error::Original)?,
            bytes.to_vec(),
        ))
        .map_err(|_| Error::Original("pre-key account transcript"))?;
        let message = kagemusha_wallet_provider_digest_v1("enrollment-local-account", &transcript);
        self.pending = Some(Pending::Account {
            dispatch,
            started,
            permit,
            original: bytes.to_vec(),
            message,
            client_digest,
        });
        Ok(message)
    }
    fn decode_slot(
        &self,
        dispatch: &PreKeyDispatchV1,
        permit: &[u8],
        bytes: &[u8],
    ) -> Result<SlotSelection, Error> {
        let slot: SlotSelection = decode(bytes, 1024)?;
        if slot.version != 1
            || slot.client_nonce != dispatch.client_nonce
            || slot.slot == [0; 32]
            || slot.permit_digest
                != kagemusha_wallet_provider_digest_v1("enrollment-pre-key-permit", permit)
            || KagemushaWalletKeyGenerationPolicyV1::from_tag(slot.generation_policy).is_none()
        {
            return Err(Error::Original("pre-key selected slot"));
        }
        Ok(slot)
    }
    /// Authenticate the retained pre-key Client, Accepted permit and Slot originals that
    /// select `scope` and `slot` (design §3.2 local-abandonment safeguard 1) and return the
    /// slot's authenticated durable enrollment phase. A missing original or phase is lost
    /// custody, never legitimate absence. Reads bracket protected storage and never probe a key.
    pub(super) fn require_selected_prekey(
        &self,
        scope: &Scope,
        slot: &KagemushaWalletSlotIdV1,
    ) -> Result<KagemushaWalletEnrollmentPhaseStateV1, Error> {
        let lost = |object| {
            Error::Provider(KagemushaWalletProviderErrorV1::UnavailableCustodyData { object })
        };
        let read = |record| self.provider.prekey_read(&scope.request_id, record);
        if read(PreKeyRecordV1::Expired)?.is_some() {
            return Err(lost("expired pre-key selection"));
        }
        let client = read(PreKeyRecordV1::Client)?.ok_or(lost("selected pre-key client"))?;
        let accepted = read(PreKeyRecordV1::Accepted)?.ok_or(lost("selected pre-key permit"))?;
        let selected = read(PreKeyRecordV1::Slot)?.ok_or(lost("selected pre-key slot"))?;
        let dispatch = PreKeyDispatchV1::decode(&client).map_err(Error::Original)?;
        if dispatch.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
            || dispatch.previous_permit.is_some()
            || dispatch.request_id != scope.request_id
            || dispatch.app != self.config.app
            || dispatch.policy != self.config.policy
            || dispatch.account != scope.account
            || dispatch.asset != scope.asset
        {
            return Err(Error::Original("pre-key request changed originals"));
        }
        let permit = KagemushaEnrollmentPermitV1::decode_canonical(
            &accepted,
            &self.config.scheme,
            &self.config.enrollment_certificate,
        )
        .map_err(|_| Error::Original("selected pre-key permit"))?;
        dispatch
            .require_permit_selection(&permit)
            .map_err(Error::Original)?;
        let selection = self.decode_slot(&dispatch, &accepted, &selected)?;
        if permit.body.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
            || permit.body.challenge != scope.challenge
            || permit.body.created_at_ms != scope.dates.issued_at_ms
            || permit.body.expires_at_ms != scope.dates.expires_at_ms
            || selection.slot != slot.0
        {
            return Err(Error::Original("pre-key retained selection changed"));
        }
        // Each read brackets protected storage; the originals must be unchanged afterwards.
        if read(PreKeyRecordV1::Client)?.as_deref() != Some(client.as_slice())
            || read(PreKeyRecordV1::Accepted)?.as_deref() != Some(accepted.as_slice())
            || read(PreKeyRecordV1::Slot)?.as_deref() != Some(selected.as_slice())
        {
            return Err(Error::Original("pre-key retained selection changed"));
        }
        // The authenticated originals are durable (fresh inode, once per process) before use.
        self.provider.prekey_adopt(
            &scope.request_id,
            &[
                PreKeyRecordV1::Client,
                PreKeyRecordV1::Accepted,
                PreKeyRecordV1::Slot,
            ],
        )?;
        self.require_enrollment_phase(
            &scope.request_id,
            &selection,
            &client,
            kagemusha_wallet_prekey_permit_digest_v1(&accepted),
            &scope.challenge,
            scope.dates,
        )
    }

    /// Authenticate the durable enrollment phase of a selected slot against its pre-key
    /// originals. A selected slot without its phase is lost custody, never `PreIntent`.
    #[allow(clippy::too_many_arguments)]
    fn require_enrollment_phase(
        &self,
        request_id: &[u8; 32],
        slot: &SlotSelection,
        client: &[u8],
        permit_digest: [u8; 32],
        challenge: &KagemushaWalletEnrollmentChallengeV1,
        dates: KagemushaWalletEnrollmentDatesV1,
    ) -> Result<KagemushaWalletEnrollmentPhaseStateV1, Error> {
        let state = self
            .provider
            .enrollment_phase(request_id)?
            .ok_or(Error::Provider(
                KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "enrollment phase",
                },
            ))?;
        let binding = &state.binding;
        if binding.slot != slot.slot
            || binding.client_digest != kagemusha_wallet_prekey_client_digest_v1(client)
            || binding.client_nonce != slot.client_nonce
            || binding.permit_digest != permit_digest
            || binding.challenge != *challenge
            || binding.dates != dates
            || binding.profile
                != super::super::credential::platform_key_profile(&self.config.policy.platform)
                    .tag()
            || binding.generation_policy != slot.generation_policy
            || binding.anchor_kind != self.provider.anchor_policy().tag()
        {
            // A phase naming other originals is lost custody, like a missing one.
            return Err(Error::Provider(
                KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "enrollment phase binding",
                },
            ));
        }
        Ok(state)
    }
    /// Prove only E5/E6 absence for an interrupted, still-begun pre-E2/E3 selection.
    /// Unknown key/storage answers remain errors; this never grants another key effect.
    pub(super) fn require_unissued_prekey(&mut self, intent_only: bool) -> Result<(), Error> {
        let Some(Pending::Dispatch { dispatch, .. }) = &self.pending else {
            return Err(Error::Phase);
        };
        let dispatch = dispatch.clone();
        let (scope, selected) = self.selected.clone().ok_or(Error::Phase)?;
        let client = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Client)?
            .ok_or(Error::Original("selected pre-key client lost"))?;
        let initial = PreKeyDispatchV1::decode(&client).map_err(Error::Original)?;
        if initial.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
            || initial.previous_permit.is_some()
            || initial.stable_selection().map_err(Error::Original)?
                != dispatch.stable_selection().map_err(Error::Original)?
        {
            return Err(Error::Original("pre-key request changed originals"));
        }
        let accepted = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Accepted)?
            .ok_or(Error::Original("selected pre-key permit lost"))?;
        let slot = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Slot)?
            .ok_or(Error::Original("selected pre-key slot lost"))?;
        if dispatch.previous_permit.as_deref() != Some(accepted.as_slice())
            || self.decode_slot(&dispatch, &accepted, &slot)?.slot != selected.0
        {
            return Err(Error::Original("pre-key retained selection changed"));
        }
        let intent = self.provider.read_intent(&selected)?;
        match &intent {
            Some(intent)
                if intent_only
                    && intent.challenge == scope.challenge
                    && intent.dates == scope.dates => {}
            None if !intent_only => {}
            _ => return Err(Error::Original("selected enrollment intent")),
        }
        if self.provider.enrollment_record(&selected)?.is_some()
            || self.provider.credential(&selected, 0)?.is_some()
        {
            return Err(Error::Original(
                "pre-key enrollment original without marker",
            ));
        }
        // Each pre-key read brackets protected-storage availability. Reconciliation
        // again catches changed marker/journal/key custody after the negative reads.
        if self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Client)?
            .as_deref()
            != Some(client.as_slice())
            || self
                .provider
                .prekey_read(&dispatch.request_id, PreKeyRecordV1::Accepted)?
                .as_deref()
                != Some(accepted.as_slice())
            || self
                .provider
                .prekey_read(&dispatch.request_id, PreKeyRecordV1::Slot)?
                .as_deref()
                != Some(slot.as_slice())
            || self.provider.read_intent(&selected)? != intent
            || !matches!(
                (self.provider.status(&selected)?, intent_only),
                (KagemushaWalletSlotStatusV1::Empty, false)
                    | (KagemushaWalletSlotStatusV1::IntentOnly, true)
            )
        {
            return Err(Error::Original("pre-key retained selection changed"));
        }
        Ok(())
    }
    /// Consume exact account authorization and recheck the permit at actual key generation.
    pub fn authorize(&mut self, signature: &[u8]) -> Result<EnrollmentProgressV1, Error> {
        self.require_pending_uncancelled()?;
        let retained = self.pending.clone();
        let result = self.authorize_retained(signature);
        // Unavailable storage, clock or hardware keeps the exact live dispatch/account
        // challenge. Invalid authenticated inputs intentionally consume it.
        if matches!(result, Err(Error::Provider(_))) {
            self.pending = retained;
        }
        result
    }
    fn authorize_retained(&mut self, signature: &[u8]) -> Result<EnrollmentProgressV1, Error> {
        let Some(Pending::Account {
            dispatch,
            started,
            permit,
            message,
            client_digest,
            ..
        }) = self.pending.take()
        else {
            return Err(Error::Phase);
        };
        authorize(&dispatch.account, &message, signature)?;
        // An already selected attempt cannot become a fresh selection if its originals
        // disappear during a same-owner retry, even when another orphan is present.
        if let Some((scope, slot)) = self.selected.clone() {
            self.require_selected_prekey(&scope, &slot)?;
        }
        // The Client original must still be exactly the one `begin` authenticated before any
        // recovery, selection or key effect binds it.
        let client = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Client)?
            .ok_or(Error::Original("selected pre-key client lost"))?;
        if kagemusha_wallet_prekey_client_digest_v1(&client) != client_digest {
            return Err(Error::Original("selected pre-key client changed"));
        }
        // Complete custody of this owner's actual vendor reply before any elapsed-time
        // refusal. The following session/permit checks still refuse expired authorization;
        // this branch cannot create a key, change an attempt, or refresh its dates.
        if let Some((scope, slot)) = &self.selected {
            if self.provider.has_retained_generation(slot) {
                if scope.challenge != permit.body.challenge
                    || scope.dates.issued_at_ms != permit.body.created_at_ms
                    || scope.dates.expires_at_ms != permit.body.expires_at_ms
                    || scope.account != dispatch.account
                    || scope.asset != dispatch.asset
                {
                    return Err(Error::Original("retained generation selection changed"));
                }
                self.provider.status(slot)?;
            }
        }
        if permit.body.observed_at_ms < self.config.session_valid_from_ms
            || permit.body.observed_at_ms >= self.config.session_expires_at_ms
        {
            return Err(Error::Original("authenticated session observation"));
        }
        require_elapsed(
            &started,
            &self.provider.live_enrollment_reading()?,
            permit.body.observed_at_ms,
            permit
                .body
                .expires_at_ms
                .min(self.config.session_expires_at_ms),
        )
        .map_err(Error::Original)?;
        let original = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Accepted)?
            .ok_or(Error::Original("selected pre-key permit lost"))?;
        let first = KagemushaEnrollmentPermitV1::decode_canonical(
            &original,
            &self.config.scheme,
            &self.config.enrollment_certificate,
        )
        .map_err(|_| Error::Original("selected pre-key permit"))?;
        dispatch
            .require_permit_selection(&first)
            .map_err(Error::Original)?;
        if first.body.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
            || first.body.attempt_id != permit.body.attempt_id
            || first.body.challenge != permit.body.challenge
            || first.body.created_at_ms != permit.body.created_at_ms
            || first.body.expires_at_ms != permit.body.expires_at_ms
        {
            return Err(Error::Original("pre-key original attempt changed"));
        }
        let existing = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Slot)?;
        let permit_digest = kagemusha_wallet_prekey_permit_digest_v1(&original);
        let dates = KagemushaWalletEnrollmentDatesV1 {
            issued_at_ms: first.body.created_at_ms,
            expires_at_ms: first.body.expires_at_ms,
        };
        let (slot, fresh) = match existing {
            Some(bytes) => {
                let slot = self.decode_slot(&dispatch, &original, &bytes)?;
                // A visible Slot selection (possibly left by an uncertain publication) is
                // made durable on a fresh inode with the originals it names before any use.
                self.provider.prekey_adopt(
                    &dispatch.request_id,
                    &[
                        PreKeyRecordV1::Client,
                        PreKeyRecordV1::Accepted,
                        PreKeyRecordV1::Slot,
                    ],
                )?;
                (slot, false)
            }
            None => {
                // A resumed permit with neither Slot nor Phase is ambiguous in the
                // presence of orphan custody. Keep the strict scan before selecting any
                // new binding; a lost original E1 must not mint a replacement key.
                if dispatch.previous_permit.is_some()
                    && self
                        .provider
                        .enrollment_phase(&dispatch.request_id)?
                        .is_none()
                {
                    self.provider.enrollment_slot(
                        &first.body.challenge,
                        super::super::credential::platform_key_profile(
                            &self.config.policy.platform,
                        ),
                        dates,
                    )?;
                }
                // The durable phase binding precedes the Slot selection; an interrupted
                // selection reuses the slot its binding already names.
                let binding = self.provider.select_enrollment_binding(
                    &KagemushaWalletEnrollmentBindingV1::new(
                        dispatch.request_id,
                        KagemushaWalletSlotIdV1::generate()
                            .map_err(KagemushaWalletProviderErrorV1::Unavailable)?
                            .0,
                        kagemusha_wallet_prekey_client_digest_v1(&client),
                        dispatch.client_nonce,
                        permit_digest,
                        first.body.challenge,
                        dates,
                        super::super::credential::platform_key_profile(
                            &self.config.policy.platform,
                        ),
                        self.provider.enrollment_generation_policy()?,
                        self.provider.anchor_policy(),
                    ),
                )?;
                // A Slot selection is first published only under an authenticated `PreIntent`
                // whose slot holds no custody; a lost Slot of a later phase is never rebuilt.
                let phase = self.provider.enrollment_phase(&dispatch.request_id)?;
                if !matches!(
                    phase.map(|state| state.phase),
                    Some(KagemushaWalletEnrollmentPhaseV1::PreIntent)
                ) || self
                    .provider
                    .slots()?
                    .contains(&KagemushaWalletSlotIdV1(binding.slot))
                {
                    return Err(Error::Provider(
                        KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                            object: "selected pre-key slot",
                        },
                    ));
                }
                let candidate = SlotSelection {
                    version: 1,
                    client_nonce: dispatch.client_nonce,
                    permit_digest,
                    slot: binding.slot,
                    generation_policy: binding.generation_policy,
                };
                let bytes = norito::encode_canonical(&candidate)
                    .map_err(|_| Error::Original("pre-key slot encoding"))?;
                match self.provider.prekey_retain(
                    &dispatch.request_id,
                    PreKeyRecordV1::Slot,
                    &bytes,
                )? {
                    PreKeyPublicationV1::Published => (candidate, true),
                    PreKeyPublicationV1::Existing(bytes) => {
                        (self.decode_slot(&dispatch, &original, &bytes)?, false)
                    }
                }
            }
        };
        // One profile per platform: StrongBox-then-TEE on Android, Secure Enclave on Apple.
        let profile = super::super::credential::platform_key_profile(&self.config.policy.platform);
        // Every selected slot carries its authenticated durable enrollment phase.
        self.require_enrollment_phase(
            &dispatch.request_id,
            &slot,
            &client,
            permit_digest,
            &first.body.challenge,
            dates,
        )?;
        let selected = KagemushaWalletSlotIdV1(slot.slot);
        self.selected = Some((
            Scope {
                request_id: dispatch.request_id,
                challenge: permit.body.challenge,
                dates: KagemushaWalletEnrollmentDatesV1 {
                    issued_at_ms: permit.body.created_at_ms,
                    expires_at_ms: permit.body.expires_at_ms,
                },
                account: dispatch.account.clone(),
                asset: dispatch.asset.clone(),
            },
            selected,
        ));
        self.request = None;
        self.apple_clock = Some(super::apple_collection::LiveClock {
            started,
            observed_at_ms: permit.body.observed_at_ms,
            expires_at_ms: permit
                .body
                .expires_at_ms
                .min(self.config.session_expires_at_ms),
        });
        let authorization = GenerationAuthorizationV1::new(
            self.provider.prekey_root_identity(),
            dispatch.request_id,
            &permit,
            profile,
            selected,
            KagemushaWalletKeyGenerationPolicyV1::from_tag(slot.generation_policy)
                .ok_or(Error::Original("pre-key creation policy"))?,
            fresh,
            started,
            self.config.session_expires_at_ms,
        );
        authorization.check(&self.provider)?;
        if fresh {
            self.provider.begin_enrollment_checked(authorization)?;
            return self.progress();
        }
        match self.provider.status(&selected)? {
            KagemushaWalletSlotStatusV1::Empty => {
                self.provider.begin_enrollment_checked(authorization)?;
            }
            KagemushaWalletSlotStatusV1::IntentOnly => {
                self.provider.resume_enrollment_checked(authorization)?;
            }
            _ => {}
        }
        self.progress()
    }
}
