//! Native E2-E6 orchestration over one exclusive retained hardware/provider owner.

use super::carrier::*;
use super::prekey::PreKeyDispatchV1;
use crate::kagemusha_wallet_advance_v1::*;
use iroha_crypto::{Algorithm, Signature};
use iroha_data_model::{account::AccountId, kagemusha::*};
mod apple_collection;
mod prekey_owner;
use sha2::{Digest as _, Sha256};

/// Operator-owned native provisioning. Foreign enrollment calls cannot choose these policies.
#[derive(Clone)]
pub struct EnrollmentConfigV1 {
    /// Independently authenticated deployment scheme, including Enrollment certificate root.
    pub scheme: KagemushaWalletSchemeV1,
    /// Exact approved app-policy preimage.
    pub app: KagemushaWalletAppPolicyV1,
    /// Exact approved enrollment-policy preimage, not a client liveness assertion.
    pub policy: KagemushaWalletEnrollmentPolicyV1,
    /// Exact independently approved Apple App Attestation root DER (1–16,384 bytes); a
    /// self-consistent pin is not approval. Always `None` on Android: a `KeyMint` chain carries
    /// its own root, which the issuer matches by SPKI against the policy's root set.
    pub attestation_root_der: Option<Vec<u8>>,
    /// Independently selected installed manifest, also required by the later source loader.
    pub installation: crate::kagemusha_wallet_artifacts_v1::InstallationV1,
    /// Exact rooted current Enrollment-role certificate.
    pub enrollment_certificate: KagemushaWalletSignerCertificateV1,
    /// Exact independently approved service-origin bytes.
    pub service_origin: Vec<u8>,
    /// Exact authenticated FI scope original.
    pub fi: Vec<u8>,
    /// Exact authenticated actor scope original.
    pub actor: Vec<u8>,
    /// Exact independently approved release-selection original.
    pub release: Vec<u8>,
    /// Independently authenticated session lower bound, in Unix milliseconds.
    pub session_valid_from_ms: u64,
    /// Exclusive session/proof deadline, carried through the immediate key-effect check.
    pub session_expires_at_ms: u64,
}
/// Refusal without converting unavailable custody to absence or issuer rejection.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum Error {
    /// Exact native provider error, including uncertain publication.
    #[error(transparent)]
    Provider(#[from] KagemushaWalletProviderErrorV1),
    /// Original/account/policy/credential authentication failed.
    #[error("enrollment original: {0}")]
    Original(&'static str),
    /// No pending account/evidence challenge or wrong lifecycle phase.
    #[error("enrollment phase")]
    Phase,
}
fn original<T>(value: Result<T, KagemushaWalletValidationErrorV1>) -> Result<T, Error> {
    value.map_err(|_| Error::Original("protocol original"))
}
fn decode<T>(bytes: &[u8], maximum: usize) -> Result<T, Error>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error::Original("frame bound"));
    }
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(maximum))
        .map_err(|_| Error::Original("canonical frame"))
}
fn authorize(account: &AccountId, message: &[u8; 32], signature: &[u8]) -> Result<(), Error> {
    let key = account
        .try_signatory()
        .filter(|key| key.algorithm() == Algorithm::Ed25519)
        .ok_or(Error::Original("existing account"))?;
    if signature.len() != 64 {
        return Err(Error::Original("account signature bound"));
    }
    Signature::from_bytes(signature)
        .verify(key, message)
        .map_err(|_| Error::Original("account signature"))
}
#[derive(Clone)]
struct Scope {
    /// Pre-key request identity whose retained Client, Accepted and Slot originals select
    /// this scope; kept independently of the live dispatch, which authorization consumes.
    request_id: [u8; 32],
    challenge: KagemushaWalletEnrollmentChallengeV1,
    dates: KagemushaWalletEnrollmentDatesV1,
    account: AccountId,
    asset: KagemushaWalletAssetScopeV1,
}

/// Native source-selected enrollment progress. It does not assert issuer approval.
#[derive(Debug, Clone)]
pub enum EnrollmentProgressV1 {
    /// Durable generation-zero marker; originals identify the exact key to attest.
    Evidence {
        /// Opaque random native slot for the platform evidence exporter.
        slot: [u8; 32],
        /// Exact generation-zero marker, not an App-supplied head.
        marker: KagemushaWalletMarkerV1,
        /// Exact challenge digest supplied during key generation.
        challenge_digest: [u8; 32],
    },
    /// Reconciliation did not establish an enrolled marker (slot `Empty` or `IntentOnly`).
    /// No key is regenerated here; abandoning it takes the local no-marker form.
    Pending,
    /// This exact attempt is terminal; a new issuer challenge is required.
    Abandoned,
    /// E7 already selected or completed; recover through strict original wallet open.
    BootstrapSelected,
}
/// Explicit result of abandoning an unused enrollment (design §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentAbandonmentV1 {
    /// No-marker form: the slot never had an enrollment marker, so no E5, credential or ledger
    /// record can name it. The holder-abandoned record is durable; there is nothing to submit.
    LocalAbandoned,
    /// Marker form: the exact retained Abandonment frame, signed by the payment key, which the
    /// holder's account submits until finalized inclusion is authenticated. Retries return the
    /// same bytes.
    Abandonment(Vec<u8>),
}
/// E5 returns either the exact selected request or an account signature challenge for new originals.
#[derive(Debug, Clone)]
pub enum RequestPreparationV1 {
    /// Existing request wins over newly supplied evidence, including after uncertain delivery.
    Retained(Vec<u8>),
    /// Exact E5 message over challenge, generated key, policies, account/asset and evidence.
    AccountChallenge([u8; 32]),
}

/// The sole provider owner for enrollment; construction is a trusted native startup operation.
pub struct EnrollmentOwnerV1<F: KagemushaWalletFsV1, P> {
    provider: KagemushaWalletProviderV1<F, P>,
    config: EnrollmentConfigV1,
    pending: Option<prekey_owner::Pending>,
    selected: Option<(Scope, KagemushaWalletSlotIdV1)>,
    request: Option<RequestBodyV1>,
    apple_clock: Option<apple_collection::LiveClock>,
    apple_returned: Option<(u8, Vec<u8>)>,
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> EnrollmentOwnerV1<F, P> {
    /// Bind existing exclusive custody to independently provisioned deployment originals.
    /// On refusal, the same provider remains owned by the caller.
    pub fn new(
        provider: KagemushaWalletProviderV1<F, P>,
        config: EnrollmentConfigV1,
    ) -> Result<Self, (KagemushaWalletProviderV1<F, P>, Error)> {
        let checked = (|| {
            original(config.scheme.validate())?;
            config.verify_prekey()?;
            if config.session_valid_from_ms >= config.session_expires_at_ms {
                return Err(Error::Original("authenticated session time window"));
            }
            original(config.policy.validate_for_app(&config.app))?;
            super::issuer_worker::require_qualified_android_adapters_v1(&config.policy.platform)
                .map_err(|_| Error::Original("approved Android adapter profile"))?;
            match (&config.policy.platform, &config.attestation_root_der) {
                (KagemushaWalletEnrollmentPlatformV1::Android { .. }, None) => {}
                (
                    KagemushaWalletEnrollmentPlatformV1::Apple {
                        attestation_root_sha256,
                    },
                    Some(root),
                ) if !root.is_empty()
                    && root.len() <= 16_384
                    && <[u8; 32]>::from(Sha256::digest(root)) == *attestation_root_sha256 => {}
                _ => return Err(Error::Original("approved root original")),
            }
            if config.scheme.scheme_id() != *provider.scheme_id()
                || config.policy.scheme_id != *provider.scheme_id()
            {
                return Err(Error::Original("native deployment scheme"));
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err((provider, error));
        }
        Ok(Self {
            provider,
            config,
            pending: None,
            selected: None,
            request: None,
            apple_clock: None,
            apple_returned: None,
        })
    }
    /// Release this opaque enrollment owner to the native artifact loader/open path.
    /// No account admission or Bootstrap authority transfers with this method.
    pub fn into_provider(self) -> KagemushaWalletProviderV1<F, P> {
        self.provider
    }

    /// Renew an independently authenticated session on this same exclusive owner.
    /// Every installed identity/policy stays exact; only its verified interval changes.
    /// Returned effects and durable E5/E6 remain retained. A fresh `begin` and signed
    /// permit are required before another effect, within the original attempt dates.
    pub fn renew_session(&mut self, config: EnrollmentConfigV1) -> Result<(), Error> {
        if config.scheme != self.config.scheme
            || config.app != self.config.app
            || config.policy != self.config.policy
            || config.attestation_root_der != self.config.attestation_root_der
            || config.installation != self.config.installation
            || config.enrollment_certificate != self.config.enrollment_certificate
            || config.service_origin != self.config.service_origin
            || config.fi != self.config.fi
            || config.actor != self.config.actor
            || config.release != self.config.release
            || config.session_valid_from_ms >= config.session_expires_at_ms
        {
            return Err(Error::Original(
                "renewed session changed enrollment selection",
            ));
        }
        self.flush_apple_returned()?;
        self.config.session_valid_from_ms = config.session_valid_from_ms;
        self.config.session_expires_at_ms = config.session_expires_at_ms;
        self.pending = None;
        self.request = None;
        self.apple_clock = None;
        Ok(())
    }

    /// Transfer the same exclusive provider to a native loader, restoring every private
    /// enrollment selection if that loader returns custody with an error. This grants no
    /// account or proof admission; the destination must perform its complete own checks.
    pub fn try_handoff<T, E>(
        self,
        load: impl FnOnce(
            KagemushaWalletProviderV1<F, P>,
        ) -> Result<T, (KagemushaWalletProviderV1<F, P>, E)>,
    ) -> Result<T, (Self, E)> {
        let Self {
            provider,
            config,
            pending,
            selected,
            request,
            apple_clock,
            apple_returned,
        } = self;
        match load(provider) {
            Ok(value) => Ok(value),
            Err((provider, error)) => Err((
                Self {
                    provider,
                    config,
                    pending,
                    selected,
                    request,
                    apple_clock,
                    apple_returned,
                },
                error,
            )),
        }
    }

    /// Recover source status without foreign liveness, client time or key-regeneration authority.
    pub fn progress(&mut self) -> Result<EnrollmentProgressV1, Error> {
        let (scope, slot) = self.selected.clone().ok_or(Error::Phase)?;
        // Authenticate the retained pre-key originals and the durable phase before any
        // recovery (which may restore a selected intent or marker) runs.
        self.require_selected_prekey(&scope, &slot)?;
        let slot = &slot;
        Ok(match self.provider.status(slot)? {
            KagemushaWalletSlotStatusV1::Enrollment(marker) => EnrollmentProgressV1::Evidence {
                slot: slot.0,
                marker: marker.marker().clone(),
                challenge_digest: scope.challenge.challenge_digest(),
            },
            KagemushaWalletSlotStatusV1::IntentOnly => EnrollmentProgressV1::Pending,
            KagemushaWalletSlotStatusV1::Pending(_) | KagemushaWalletSlotStatusV1::Released(_) => {
                EnrollmentProgressV1::BootstrapSelected
            }
            KagemushaWalletSlotStatusV1::SlotAbandoned
            | KagemushaWalletSlotStatusV1::Terminal(_) => EnrollmentProgressV1::Abandoned,
            // A selected pre-key slot may precede E2. It grants no generation authority.
            KagemushaWalletSlotStatusV1::Empty => EnrollmentProgressV1::Pending,
        })
    }
    /// Permanently abandon this unused enrollment (design §3.2). A slot with no enrollment
    /// marker is abandoned locally and returns [`EnrollmentAbandonmentV1::LocalAbandoned`];
    /// a slot whose generation-zero marker is current commits the terminal marker and returns
    /// the exact retained signed Abandonment frame. The provider refuses once Bootstrap is
    /// selected; retries never re-sign a selected output. Local abandonment never probes the
    /// key, so it also covers a selected slot whose key lookup is unknown. This is an explicit
    /// terminal action, distinct from closing the native handle; a fresh enrollment may start
    /// as soon as it returns.
    /// # Errors
    /// No authenticated retained client (`Phase`), lost or changed pre-key originals, committed Bootstrap,
    /// lost custody, unavailable or uncertain storage or hardware. Nothing is abandoned then.
    pub fn abandon(&mut self) -> Result<EnrollmentAbandonmentV1, Error> {
        let Some((scope, slot)) = self.selected.clone() else {
            return self.abandon_unselected_client();
        };
        // Authenticate the retained pre-key originals and the durable enrollment phase before
        // releasing any live selection.
        let phase = self.require_selected_prekey(&scope, &slot)?;
        self.pending = None;
        self.request = None;
        if !phase.phase.marker_selected() && !self.provider.has_enrollment_marker(&slot)? {
            self.provider
                .abandon_unmarked_enrollment(&slot, &scope.request_id)?;
            return Ok(EnrollmentAbandonmentV1::LocalAbandoned);
        }
        // A selected or current marker takes the signed marker form; reconciliation restores a
        // selected marker or fails closed for a lost committed one.
        let bytes = self.provider.abandon_enrollment(&slot)?;
        let result = original(KagemushaWalletAbandonmentV1::decode_canonical(
            &bytes,
            &self.config.scheme.scheme_id(),
        ))?;
        if result.challenge_digest != scope.challenge.challenge_digest()
            || result.control.body.wallet_id != scope.challenge.wallet_id(&result.payment_key)
        {
            return Err(Error::Original("selected abandonment"));
        }
        Ok(EnrollmentAbandonmentV1::Abandonment(bytes))
    }
    /// Permanently abandon this unused enrollment and frame its exact retained marker receipt
    /// for an ordinary account-signed ledger transaction. The local no-marker form has no
    /// ledger effect and returns `None`. Retrying preserves the signed inner receipt exactly;
    /// this framing is not evidence of submission or finalized execution.
    /// # Errors
    /// The same custody and lifecycle refusals as [`Self::abandon`], or an encoding failure.
    pub fn abandonment_ledger_instruction(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let EnrollmentAbandonmentV1::Abandonment(bytes) = self.abandon()? else {
            return Ok(None);
        };
        let instruction = iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1::new(
            self.config.scheme.scheme_id(),
            iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerActionV1::Abandon(bytes),
        );
        norito::encode_canonical(&instruction)
            .map(Some)
            .map_err(|_| Error::Original("abandonment ledger instruction"))
    }
    fn selected_marker(&mut self) -> Result<KagemushaWalletMarkerV1, Error> {
        let (scope, slot) = self.selected.as_ref().ok_or(Error::Phase)?;
        // Every E5/E6 recovery entry point authenticates the selected originals first.
        self.require_selected_prekey(scope, slot)?;
        let status = self.provider.status(slot)?;
        let marker = match status {
            KagemushaWalletSlotStatusV1::Enrollment(marker)
            | KagemushaWalletSlotStatusV1::Pending(marker)
            | KagemushaWalletSlotStatusV1::Released(marker) => marker,
            _ => return Err(Error::Phase),
        };
        let intent = self
            .provider
            .read_intent(slot)?
            .ok_or(Error::Original("selected enrollment intent"))?;
        if intent.challenge != scope.challenge
            || intent.dates != scope.dates
            || marker.marker().scheme_id != scope.challenge.scheme_id
            || marker.marker().asset_digest != scope.challenge.asset_digest
            || marker.marker().wallet_id != scope.challenge.wallet_id(marker.payment_key())
        {
            return Err(Error::Original("selected enrollment marker"));
        }
        match self.provider.probe_payment_key(slot)? {
            KagemushaWalletProbeV1::Present(key) if key == *marker.payment_key() => {}
            KagemushaWalletProbeV1::Present(_) | KagemushaWalletProbeV1::Absent => {
                return Err(KagemushaWalletProviderErrorV1::KeyLost.into());
            }
            KagemushaWalletProbeV1::Unavailable(reason) => {
                return Err(KagemushaWalletProviderErrorV1::Unavailable(reason).into());
            }
        }
        original(KagemushaWalletMarkerV1::enrollment(
            &scope.challenge,
            *marker.payment_key(),
        ))
    }
    /// Exact authenticated retained E5, if already durable. A begun dispatch with no
    /// selected slot can establish request absence only from its actual pre-key records;
    /// this is not payment-key absence, freshness or permission to generate anything.
    pub fn retained_request(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if let Some((scope, slot)) = &self.selected {
            self.require_selected_prekey(scope, slot)?;
            match self.provider.status(slot)? {
                KagemushaWalletSlotStatusV1::Empty => {
                    self.require_unissued_prekey(false)?;
                    return Ok(None);
                }
                KagemushaWalletSlotStatusV1::IntentOnly => {
                    self.require_unissued_prekey(true)?;
                    return Ok(None);
                }
                _ => return self.retained(),
            }
        }
        let Some(prekey_owner::Pending::Dispatch { dispatch, .. }) = &self.pending else {
            return Err(Error::Phase);
        };
        let client_original = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Client)?
            .ok_or(Error::Original("selected pre-key client lost"))?;
        let client = PreKeyDispatchV1::decode(&client_original).map_err(Error::Original)?;
        if client.purpose != KagemushaEnrollmentPermitPurposeV1::Fresh
            || client.previous_permit.is_some()
            || client.stable_selection().map_err(Error::Original)?
                != dispatch.stable_selection().map_err(Error::Original)?
        {
            return Err(Error::Original("pre-key request changed originals"));
        }
        let accepted = self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Accepted)?;
        if accepted != dispatch.previous_permit
            || self
                .provider
                .prekey_read(&dispatch.request_id, PreKeyRecordV1::Slot)?
                .is_some()
        {
            return Err(Error::Original("pre-key retained selection changed"));
        }
        if let Some(original) = &accepted {
            // Accepted is published before Slot. That interruption is resumable, but an
            // existing matching intent with its Slot association erased is custody loss.
            let permit = KagemushaEnrollmentPermitV1::decode_canonical(
                original,
                &self.config.scheme,
                &self.config.enrollment_certificate,
            )
            .map_err(|_| Error::Original("pre-key retained permit"))?;
            for slot in self.provider.slots()? {
                let Some(intent) = self.provider.read_intent(&slot)? else {
                    // A durable holder abandonment before E2 legitimately has no intent.
                    if self.provider.is_abandoned_without_marker(&slot)? {
                        continue;
                    }
                    return Err(Error::Original("unselected custody intent lost"));
                };
                if intent.challenge == permit.body.challenge {
                    return Err(Error::Original("selected pre-key slot lost"));
                }
            }
        }
        // Recheck storage and immutable records after inventory reads. No uncertain or
        // replaced original is converted to absence, even before any payment key exists.
        if self
            .provider
            .prekey_read(&dispatch.request_id, PreKeyRecordV1::Client)?
            .as_deref()
            != Some(client_original.as_slice())
            || self
                .provider
                .prekey_read(&dispatch.request_id, PreKeyRecordV1::Accepted)?
                != accepted
            || self
                .provider
                .prekey_read(&dispatch.request_id, PreKeyRecordV1::Slot)?
                .is_some()
        {
            return Err(Error::Original("pre-key retained selection changed"));
        }
        Ok(None)
    }
    fn retained(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let marker = self.selected_marker()?;
        let (scope, slot) = self.selected.as_ref().ok_or(Error::Phase)?;
        // Provider reconciles and durably adopts any uncertain E5 record before retransmission.
        let Some(record) = self.provider.enrollment_record(slot)? else {
            if self.provider.credential(slot, 0)?.is_some() {
                return Err(Error::Original("selected enrollment request lost"));
            }
            return Ok(None);
        };
        let request = RequestV1::decode(&record.request).map_err(Error::Original)?;
        if request.body.marker != marker
            || record.enrollment_marker_digest != original(marker.marker_digest())?
            || request.body.challenge != scope.challenge
            || request.body.account != scope.account
            || request.body.asset != scope.asset
            || request.body.app != self.config.app
            || request.body.policy != self.config.policy
        {
            return Err(Error::Original("retained enrollment request binding"));
        }
        Ok(Some(
            self.provider
                .retain_enrollment_request(slot, &record.request)?,
        ))
    }
    /// Recover the exact verified durable E6 winner without issuer/network input.
    /// A credential without its selected result remains custody loss, never absence.
    pub fn retained_result(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let Some(request) = self.retained_request()? else {
            return Ok(None);
        };
        let (_, slot) = self.selected.as_ref().ok_or(Error::Phase)?;
        let slot = *slot;
        let key = kagemusha_wallet_provider_digest_v1("enrollment-issuer-result", &request);
        let retained = self
            .provider
            .with_archive(&slot, |archive| archive.read_record(&key, RESULT_MAX_BYTES))?;
        let Some(bytes) = retained else {
            if self.provider.credential(&slot, 0)?.is_some() {
                return Err(Error::Original("selected enrollment result lost"));
            }
            return Ok(None);
        };
        // The same owner independently verifies and durably adopts its actual original.
        self.accept_credential(&bytes).map(Some)
    }

    /// Select exact E5 evidence before exposing its existing-account challenge. Retained requests always win.
    pub fn prepare_request(&mut self, evidence: &[u8]) -> Result<RequestPreparationV1, Error> {
        if let Some(bytes) = self.retained()? {
            return Ok(RequestPreparationV1::Retained(bytes));
        }
        let EnrollmentProgressV1::Evidence { marker, .. } = self.progress()? else {
            return Err(Error::Phase);
        };
        let decoded =
            PlatformEvidenceV1::decode(evidence, &self.config.policy).map_err(Error::Original)?;
        if let PlatformEvidenceV1::Apple {
            key_id,
            attestation,
            key_binding_assertion,
        } = decoded
        {
            self.require_apple_originals(&key_id, &attestation, &key_binding_assertion)?;
        }
        let (scope, _) = self.selected.as_ref().ok_or(Error::Phase)?;
        let body = RequestBodyV1 {
            version: 1,
            challenge: scope.challenge,
            marker,
            app: self.config.app.clone(),
            policy: self.config.policy.clone(),
            account: scope.account.clone(),
            asset: scope.asset.clone(),
            evidence: evidence.to_vec(),
        };
        let message = body.account_challenge().map_err(Error::Original)?;
        self.request = Some(body);
        Ok(RequestPreparationV1::AccountChallenge(message))
    }
    /// Retain the exact account-authorized E5 request durably before returning network bytes.
    pub fn retain_request(&mut self, signature: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(bytes) = self.retained()? {
            return Ok(bytes);
        }
        let body = self.request.as_ref().ok_or(Error::Phase)?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| Error::Original("E5 account signature bound"))?;
        let request = RequestV1 {
            body: body.clone(),
            account_signature: signature,
        };
        let bytes = request.encode().map_err(Error::Original)?;
        let (_, slot) = self.selected.as_ref().ok_or(Error::Phase)?;
        if matches!(
            self.config.policy.platform,
            KagemushaWalletEnrollmentPlatformV1::Apple { .. }
        ) {
            self.require_apple_live()?;
        }
        let exact = self.provider.retain_enrollment_request(slot, &bytes)?;
        if exact != bytes {
            return Err(Error::Original("concurrent enrollment request"));
        }
        self.request = None;
        Ok(exact)
    }
    /// Authenticate and durably retain E6 before selecting credential zero.
    /// Existing exact result bytes win on every retry, including after uncertain delivery.
    pub fn accept_credential(&mut self, supplied: &[u8]) -> Result<Vec<u8>, Error> {
        let request_bytes = self.retained()?.ok_or(Error::Phase)?;
        let request = RequestV1::decode(&request_bytes).map_err(Error::Original)?;
        let (_, slot) = self.selected.as_ref().ok_or(Error::Phase)?;
        let slot = *slot;
        let key = kagemusha_wallet_provider_digest_v1("enrollment-issuer-result", &request_bytes);
        let retained = self
            .provider
            .with_archive(&slot, |archive| archive.read_record(&key, RESULT_MAX_BYTES))?;
        if retained.is_none() && self.provider.credential(&slot, 0)?.is_some() {
            return Err(Error::Original("selected enrollment result lost"));
        }
        let bytes = retained.as_deref().unwrap_or(supplied);
        let result = ResultV1::decode(bytes).map_err(Error::Original)?;
        self.verify_result(&request, &result)?;
        self.provider
            .with_archive(&slot, |archive| archive.write_record(&key, bytes))?;
        self.provider
            .store_credential(&slot, 0, &result.credential)?;
        Ok(bytes.to_vec())
    }
    /// Exact retained originals for the separate account-admission boundary. This verifies
    /// and adopts E6 again; it grants no account or Bootstrap authority.
    pub fn open_originals(&mut self) -> Result<[Vec<u8>; 4], Error> {
        let selected = self.accept_credential(&[])?;
        let result = ResultV1::decode(&selected).map_err(Error::Original)?;
        let request =
            RequestV1::decode(&self.retained()?.ok_or(Error::Phase)?).map_err(Error::Original)?;
        Ok([
            result.credential,
            result.certificates,
            norito::encode_canonical(&request.body.account)
                .map_err(|_| Error::Original("account encoding"))?,
            norito::encode_canonical(&request.body.asset)
                .map_err(|_| Error::Original("asset encoding"))?,
        ])
    }

    fn verify_result(&mut self, request: &RequestV1, result: &ResultV1) -> Result<(), Error> {
        let credential = result
            .verify_for(
                &self.config.scheme,
                &self.config.enrollment_certificate,
                request,
            )
            .map_err(Error::Original)?;
        let (scope, slot) = self.selected.as_ref().ok_or(Error::Phase)?;
        let intent = self
            .provider
            .read_intent(slot)?
            .ok_or(Error::Original("selected enrollment intent"))?;
        if intent.challenge != scope.challenge
            || intent.dates != scope.dates
            || !super::credential::evidence_matches_policy(
                &self.config.policy.platform,
                intent.key_profile()?,
                credential.body.evidence_kind,
            )
            || !(intent.dates.issued_at_ms..intent.dates.expires_at_ms)
                .contains(&credential.body.issued_at_ms)
            || !(intent.dates.issued_at_ms..intent.dates.expires_at_ms)
                .contains(&credential.body.enrollment_evidence.time_ms)
        {
            return Err(Error::Original(
                "initial enrollment credential policy/dates",
            ));
        }
        let status = self.provider.status(slot)?;
        let marker = match status {
            KagemushaWalletSlotStatusV1::Enrollment(marker) => marker,
            KagemushaWalletSlotStatusV1::Pending(marker)
            | KagemushaWalletSlotStatusV1::Released(marker) => {
                if self.provider.credential(slot, 0)?.as_deref()
                    != Some(result.credential.as_slice())
                {
                    return Err(Error::Original(
                        "initial enrollment credential changed or lost",
                    ));
                }
                marker
            }
            _ => return Err(Error::Phase),
        };
        super::credential::verify_initial_credential_marker(
            &credential,
            &self.config.scheme,
            &self.config.enrollment_certificate,
            &scope.challenge,
            marker.marker(),
        )
    }
}
