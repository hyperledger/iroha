//! Native admission of an existing account and its actual enrolled custody slot.
//!
//! The installation owner supplies an authenticated immutable verifier and the canonical
//! complete source-qualified wallet graph, including all sigma, receipt, Q, operation
//! and Omega owners whose originals were strictly imported.
//! Foreign inputs supply original credential, Enrollment CertificateSet and AccountId
//! frames, never slot/scheme/wallet/artifact identifiers or a replacement account vault. Native
//! enumerates real provider slots, reconciles their markers, checks the positive hardware key,
//! retained intent/request/current credential and selected capsule, then asks the existing
//! Ed25519 account key to sign one fresh, source-bound Native challenge. Failed or abandoned
//! admission never generates a key, selects a monetary head, signs a payment or erases custody.
//!
//! Successful original admission feeds the concrete native operation owner. The embedding
//! app must first provision the complete signed artifact graph under independently selected
//! native configuration and authenticated genesis; no foreign input can substitute authority.

use std::sync::Arc;

use iroha_crypto::{Algorithm, Signature};
use iroha_data_model::{account::AccountId, kagemusha::kagemusha_wallet_v1::*};
use rand::rand_core::TryRngCore as _;

use crate::{
    kagemusha_wallet_advance_v1::{
        KagemushaWalletFsV1, KagemushaWalletMarkerRecordV1, KagemushaWalletPlatformV1,
        KagemushaWalletProbeV1, KagemushaWalletProviderErrorV1, KagemushaWalletProviderV1,
        KagemushaWalletSlotIdV1, KagemushaWalletSlotStatusV1, KagemushaWalletUnavailableV1,
        kagemusha_wallet_provider_digest_v1,
    },
    kagemusha_wallet_artifacts_v1::{
        InstalledVerifierPackV1, producer_inventory::QualifiedWalletSourcesV1,
    },
    kagemusha_wallet_preparation_v1::PreparationV1,
};

/// Bounded original single-key account frame, before canonical decoding.
pub const ACCOUNT_ORIGINAL_MAX_BYTES_V1: usize = 4096;
/// Bounded authoritative asset-scope original, before canonical decoding.
pub const ASSET_SCOPE_ORIGINAL_MAX_BYTES_V1: usize = 1024;

/// Native admission failure. Storage/key errors remain distinct from invalid ownership.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum Error {
    /// Provider reconciliation, unknown storage or key availability, or custody loss.
    #[error(transparent)]
    Provider(#[from] KagemushaWalletProviderErrorV1),
    /// Noncanonical or unauthenticated original, wrong installed source or account binding.
    #[error("wallet original intake rejected: {0}")]
    Authority(&'static str),
    /// No exact durable enrolled slot exists; enrollment/recovery is a separate workflow.
    #[error("no enrolled custody slot for the issued wallet")]
    NotEnrolled,
    /// More than one durable slot purports to own this exact wallet/key incarnation.
    #[error("ambiguous enrolled custody slots")]
    Ambiguous,
    /// The exact selected source changed while account authorization was pending.
    #[error("wallet source changed during original intake")]
    SourceChanged,
}

fn require_installation(
    installed: ([u8; 32], [u8; 32]),
    qualified: ([u8; 32], [u8; 32]),
    provider_scheme: [u8; 32],
) -> Result<(), Error> {
    if qualified != installed || provider_scheme != installed.0 {
        return Err(Error::Authority("installed producer/provider scope"));
    }
    Ok(())
}

// Shared original decoder for intake and an already authenticated Send destination.
// The caller must obtain expected_digest from authenticated Native originals.
pub(crate) fn account(original: &[u8], expected_digest: &[u8; 32]) -> Result<AccountId, Error> {
    if original.is_empty() || original.len() > ACCOUNT_ORIGINAL_MAX_BYTES_V1 {
        return Err(Error::Authority("account frame bound"));
    }
    let account: AccountId = norito::decode_canonical_with_limits(
        original,
        norito::canonical_decode_limits(original.len()),
    )
    .map_err(|_| Error::Authority("canonical account frame"))?;
    account
        .try_signatory()
        .filter(|key| key.algorithm() == Algorithm::Ed25519)
        .ok_or(Error::Authority("existing single Ed25519 account"))?;
    if kagemusha_wallet_account_digest_v1(&account)
        .map_err(|_| Error::Authority("account digest"))?
        != *expected_digest
    {
        return Err(Error::Authority("enrolled account"));
    }
    Ok(account)
}

fn asset_scope(original: &[u8], expected: &[u8; 32]) -> Result<KagemushaWalletAssetScopeV1, Error> {
    if original.is_empty() || original.len() > ASSET_SCOPE_ORIGINAL_MAX_BYTES_V1 {
        return Err(Error::Authority("asset scope original bound"));
    }
    let scope: KagemushaWalletAssetScopeV1 = norito::decode_canonical_with_limits(
        original,
        norito::canonical_decode_limits(original.len()),
    )
    .map_err(|_| Error::Authority("canonical asset scope original"))?;
    scope
        .validate()
        .map_err(|_| Error::Authority("asset scope"))?;
    if scope.asset_digest() != *expected {
        return Err(Error::Authority("issuer-authenticated asset scope/scale"));
    }
    Ok(scope)
}

fn bind_challenge(
    challenge: &KagemushaWalletEnrollmentChallengeV1,
    marker: &KagemushaWalletMarkerV1,
    credential: &KagemushaWalletCredentialV1,
) -> Result<(), Error> {
    challenge
        .validate()
        .map_err(|_| Error::Authority("retained enrollment challenge"))?;
    marker
        .validate()
        .map_err(|_| Error::Authority("actual custody marker"))?;
    let body = &credential.body;
    if challenge.scheme_id != body.scheme_id
        || challenge.asset_digest != body.asset_digest
        || challenge.account_digest != body.account_digest
        || challenge.app_policy != body.app_policy
        || challenge.enrollment_id(&body.payment_key) != body.enrollment_id
        || challenge.wallet_id(&body.payment_key) != body.wallet_id
        || marker.scheme_id != body.scheme_id
        || marker.asset_digest != body.asset_digest
        || marker.wallet_id != body.wallet_id
        || marker.payment_key != body.payment_key
    {
        return Err(Error::Authority("retained owner/key/intent"));
    }
    Ok(())
}

fn authorize_account(account: &AccountId, challenge: &[u8], original: &[u8]) -> Result<(), Error> {
    let key = account
        .try_signatory()
        .filter(|key| key.algorithm() == Algorithm::Ed25519)
        .ok_or(Error::Authority("existing single Ed25519 account"))?;
    if original.len() != 64 || challenge.len() != 32 {
        return Err(Error::Authority("original account authorization bound"));
    }
    Signature::from_bytes(original)
        .verify(key, challenge)
        .map_err(|_| Error::Authority("existing account authorization"))
}

fn open_message(
    nonce: &[u8; 32],
    manifest: &[u8; 32],
    slot: &KagemushaWalletSlotIdV1,
    marker_file_digest: &[u8; 32],
    credential_original: &[u8],
    certificate_set_original: &[u8],
    account_original: &[u8],
    asset_scope_original: &[u8],
) -> Vec<u8> {
    // Provider-local SHA framing, not a monetary G1 signature domain. Length-delimited
    // originals prevent cross-role/cross-incarnation reuse of the existing account loan.
    let mut transcript = b"iroha:kagemusha:wallet:original-open:v1\0".to_vec();
    transcript.extend_from_slice(nonce);
    transcript.extend_from_slice(manifest);
    transcript.extend_from_slice(&slot.0);
    transcript.extend_from_slice(marker_file_digest);
    for original in [
        credential_original,
        certificate_set_original,
        account_original,
        asset_scope_original,
    ] {
        transcript.extend_from_slice(&(original.len() as u64).to_le_bytes());
        transcript.extend_from_slice(original);
    }
    kagemusha_wallet_provider_digest_v1("original-open-account", &transcript).to_vec()
}

// Bounded carrier retention only. No decoded identity, slot or installation is minted here.
fn retain_originals(originals: [&[u8]; 4]) -> Option<[Vec<u8>; 4]> {
    let bounds = [
        KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
        ACCOUNT_ORIGINAL_MAX_BYTES_V1,
        ASSET_SCOPE_ORIGINAL_MAX_BYTES_V1,
    ];
    if originals
        .iter()
        .zip(bounds)
        .any(|(original, bound)| original.len() > bound)
    {
        return None;
    }
    Some(originals.map(|original| original.to_vec()))
}

// Move-only check boundary used by both genuine begin and finish. Checks may reconcile
// provider custody; their actual owner is returned on refusal rather than rolled back,
// fabricated or erased. It grants no authority independently of the supplied real checks.
fn retain_checked<O, T>(
    mut owner: O,
    check: impl FnOnce(&mut O) -> Result<T, Error>,
) -> Result<(O, T), (O, Error)> {
    match check(&mut owner) {
        Ok(value) => Ok((owner, value)),
        Err(error) => Err((owner, error)),
    }
}

fn same_originals(held: &[Vec<u8>; 4], proposed: [&[u8]; 4]) -> bool {
    held.iter()
        .zip(proposed)
        .all(|(before, after)| before.as_slice() == after)
}

fn pin_selected_source(
    retained: &mut Option<(KagemushaWalletSlotIdV1, [u8; 32])>,
    selected: (KagemushaWalletSlotIdV1, [u8; 32]),
) -> Result<(), Error> {
    match retained {
        Some(original) if *original != selected => Err(Error::SourceChanged),
        Some(_) => Ok(()),
        None => {
            *retained = Some(selected);
            Ok(())
        }
    }
}

// Native's existing begin is the only constructor. These private fields carry real
// exclusive provider ownership and original DATA; a failed check grants no admission.
struct WalletOpenIntakeV1<F: KagemushaWalletFsV1, P> {
    provider: KagemushaWalletProviderV1<F, P>,
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    originals: [Vec<u8>; 4],
    rejected_bound: bool,
    selected_source: Option<(KagemushaWalletSlotIdV1, [u8; 32])>,
}

/// Refused original intake retaining the SAME real provider and installed source owners.
/// There is no foreign/decoded constructor or serialized checkpoint. An oversized carrier
/// retains custody without copying its unbounded bytes and cannot become a different attempt.
pub struct WalletOpenBeginFailureV1<F: KagemushaWalletFsV1, P> {
    intake: WalletOpenIntakeV1<F, P>,
    error: Error,
}
impl<F: KagemushaWalletFsV1, P> WalletOpenBeginFailureV1<F, P> {
    /// Original refusal; reading it does not consume custody.
    #[must_use]
    pub const fn error(&self) -> Error {
        self.error
    }

    /// Compare transport DATA with the four exact bounded originals already owned.
    /// A rejected oversized carrier never matches or permits replacement originals.
    #[must_use]
    pub fn matches_originals(&self, proposed: [&[u8]; 4]) -> bool {
        !self.intake.rejected_bound && same_originals(&self.intake.originals, proposed)
    }
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> WalletOpenBeginFailureV1<F, P> {
    /// Recheck the SAME original intake against the SAME actual provider and source owners.
    /// A challenge is sampled only after all existing original/source checks succeed; no
    /// previous pending challenge is replaced and no enrollment side effect is dispatched.
    /// # Errors
    /// The new refusal retains this exact original custody again, including source/IO errors.
    pub fn retry(self) -> Result<PendingWalletOpenV1<F, P>, Self> {
        PendingWalletOpenV1::begin_retained(self.intake)
    }
}

/// Refused account authorization retaining the SAME actual pending owner and challenge.
/// No failed signature, changed source or unavailable key creates a new challenge/slot.
pub struct WalletOpenFinishFailureV1<F: KagemushaWalletFsV1, P> {
    pending: PendingWalletOpenV1<F, P>,
    error: Error,
}
impl<F: KagemushaWalletFsV1, P> WalletOpenFinishFailureV1<F, P> {
    /// Return the actual pending owner and the original refusal without reconstructing either.
    #[must_use]
    pub fn into_parts(self) -> (PendingWalletOpenV1<F, P>, Error) {
        (self.pending, self.error)
    }
}

/// Move-only account authorization challenge retaining exclusive real provider custody.
/// It cannot be reconstructed from a foreign handle/identifier or serialized checkpoint.
pub struct PendingWalletOpenV1<F: KagemushaWalletFsV1, P> {
    provider: KagemushaWalletProviderV1<F, P>,
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    slot: KagemushaWalletSlotIdV1,
    marker_file_digest: [u8; 32],
    credential: KagemushaWalletCredentialV1,
    credential_original: Vec<u8>,
    certificate_set_original: Vec<u8>,
    account: AccountId,
    account_original: Vec<u8>,
    asset_scope: KagemushaWalletAssetScopeV1,
    asset_scope_original: Vec<u8>,
    challenge: Vec<u8>,
}

/// Fully admitted original owner, awaiting the genuine native operation/folding owner.
/// Private fields confer no arbitrary signature, fabricated proof or replacement-key path.
pub struct AdmittedWalletV1<F: KagemushaWalletFsV1, P> {
    provider: KagemushaWalletProviderV1<F, P>,
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    slot: KagemushaWalletSlotIdV1,
    credential: KagemushaWalletCredentialV1,
    credential_original: Vec<u8>,
    certificate_set_original: Vec<u8>,
    account: AccountId,
    account_original: Vec<u8>,
    asset_scope: KagemushaWalletAssetScopeV1,
    asset_scope_original: Vec<u8>,
}

fn source<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1>(
    provider: &mut KagemushaWalletProviderV1<F, P>,
    slot: &KagemushaWalletSlotIdV1,
    credential: &KagemushaWalletCredentialV1,
    credential_original: &[u8],
) -> Result<KagemushaWalletMarkerRecordV1, Error> {
    let status = provider.status(slot)?;
    let marker = match status {
        KagemushaWalletSlotStatusV1::Enrollment(record)
        | KagemushaWalletSlotStatusV1::Pending(record)
        | KagemushaWalletSlotStatusV1::Released(record) => record,
        KagemushaWalletSlotStatusV1::Terminal(_) => {
            return Err(KagemushaWalletProviderErrorV1::Terminal.into());
        }
        _ => return Err(Error::NotEnrolled),
    };
    let intent = provider
        .read_intent(slot)?
        .ok_or(Error::Authority("missing actual enrollment intent"))?;
    bind_challenge(&intent.challenge, marker.marker(), credential)?;
    let enrollment = provider
        .enrollment_record(slot)?
        .ok_or(Error::Authority("missing retained enrollment request"))?;
    let original_marker =
        KagemushaWalletMarkerV1::enrollment(&intent.challenge, credential.body.payment_key)
            .map_err(|_| Error::Authority("enrollment marker original"))?;
    if enrollment.request.is_empty()
        || enrollment.enrollment_marker_digest
            != original_marker
                .marker_digest()
                .map_err(|_| Error::Authority("enrollment marker digest"))?
        || provider
            .credential(slot, credential.body.renewal_sequence)?
            .as_deref()
            != Some(credential_original)
    {
        return Err(Error::Authority("retained enrollment/credential original"));
    }
    // Reconciliation caches verified marker bytes. This fresh positive key read is needed
    // at both account-admission boundaries; null/error never becomes absence or freshness.
    match provider.probe_payment_key(slot)? {
        KagemushaWalletProbeV1::Present(key) if key == credential.body.payment_key => {}
        KagemushaWalletProbeV1::Present(_) | KagemushaWalletProbeV1::Absent => {
            return Err(KagemushaWalletProviderErrorV1::KeyLost.into());
        }
        KagemushaWalletProbeV1::Unavailable(reason) => {
            return Err(KagemushaWalletProviderErrorV1::Unavailable(reason).into());
        }
    }
    if let Some(capsule) = provider.current_capsule(slot)? {
        capsule
            .successor_state
            .validate_for_credential(credential)
            .map_err(|_| Error::Authority("source credential/state"))?;
        capsule
            .statement
            .validate_for_credential(credential)
            .map_err(|_| Error::Authority("source credential/statement"))?;
    } else if credential.body.renewal_sequence != 0 {
        return Err(Error::Authority("renewal without selected source"));
    }
    let after = provider.status(slot)?;
    if after.marker().map(|r| r.marker_file_digest()) != Some(marker.marker_file_digest()) {
        return Err(Error::SourceChanged);
    }
    Ok(marker)
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1> PendingWalletOpenV1<F, P> {
    /// Admit authenticated originals against a real durable slot and positive hardware key.
    /// The immutable installation capabilities come from Native's authenticated loader.
    /// No slot/wallet/scheme/manifest identity is accepted from the foreign caller.
    /// # Errors
    /// Every invalid original, unknown storage/key, changed source or nonce refusal returns
    /// the SAME exclusive provider, installation and source owners in an opaque failure.
    pub fn begin(
        provider: KagemushaWalletProviderV1<F, P>,
        installed: Arc<InstalledVerifierPackV1>,
        sources: Arc<QualifiedWalletSourcesV1>,
        credential_original: &[u8],
        certificate_set_original: &[u8],
        account_original: &[u8],
        asset_scope_original: &[u8],
    ) -> Result<Self, WalletOpenBeginFailureV1<F, P>> {
        let (originals, rejected_bound) = match retain_originals([
            credential_original,
            certificate_set_original,
            account_original,
            asset_scope_original,
        ]) {
            Some(originals) => (originals, false),
            None => (std::array::from_fn(|_| Vec::new()), true),
        };
        Self::begin_retained(WalletOpenIntakeV1 {
            provider,
            installed,
            sources,
            originals,
            rejected_bound,
            selected_source: None,
        })
    }

    fn begin_retained(
        intake: WalletOpenIntakeV1<F, P>,
    ) -> Result<Self, WalletOpenBeginFailureV1<F, P>> {
        let prepared = retain_checked(intake, |intake| {
            if intake.rejected_bound {
                return Err(Error::Authority("original intake frame bound"));
            }
            let provider = &mut intake.provider;
            let installed = &intake.installed;
            let sources = &intake.sources;
            let [
                credential_original,
                certificate_set_original,
                account_original,
                asset_scope_original,
            ] = &intake.originals;
            require_installation(
                (
                    installed.verifier().scheme().scheme_id(),
                    installed.verifier().manifest_digest(),
                ),
                sources.installation(),
                *provider.scheme_id(),
            )?;
            let preparation = PreparationV1::new(installed)
                .map_err(|_| Error::Authority("installed preparation source"))?;
            let authenticated = preparation
                .authenticate_credential_set(credential_original, certificate_set_original)
                .map_err(|_| Error::Authority("issuer-authenticated originals"))?;
            let credential = *authenticated.credential();
            let account = account(account_original, &credential.body.account_digest)?;
            let asset_scope = asset_scope(asset_scope_original, &credential.body.asset_digest)?;
            let mut selected = None;
            for slot in provider.slots()? {
                let status = provider.status(&slot)?;
                if status
                    .marker()
                    .is_some_and(|record| record.marker().wallet_id == credential.body.wallet_id)
                {
                    let marker = source(provider, &slot, &credential, credential_original)?;
                    if selected.is_some() {
                        return Err(Error::Ambiguous);
                    }
                    selected = Some((slot, *marker.marker_file_digest()));
                }
            }
            let (slot, marker_file_digest) = selected.ok_or(Error::NotEnrolled)?;
            // Once actual source validation succeeds, even a later RNG/platform refusal
            // cannot silently reselect another marker/source on retry.
            pin_selected_source(&mut intake.selected_source, (slot, marker_file_digest))?;
            let mut nonce = [0; 32];
            rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(|_| {
                KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Platform(
                    0,
                ))
            })?;
            if nonce == [0; 32] {
                return Err(Error::Authority("zero Native nonce"));
            }
            let challenge = open_message(
                &nonce,
                &installed.verifier().manifest_digest(),
                &slot,
                &marker_file_digest,
                credential_original,
                certificate_set_original,
                account_original,
                asset_scope_original,
            );
            Ok((
                slot,
                marker_file_digest,
                credential,
                account,
                asset_scope,
                challenge,
            ))
        });
        let (intake, (slot, marker_file_digest, credential, account, asset_scope, challenge)) =
            match prepared {
                Ok(selected) => selected,
                Err((intake, error)) => return Err(WalletOpenBeginFailureV1 { intake, error }),
            };
        let [
            credential_original,
            certificate_set_original,
            account_original,
            asset_scope_original,
        ] = intake.originals;
        Ok(Self {
            provider: intake.provider,
            installed: intake.installed,
            sources: intake.sources,
            slot,
            marker_file_digest,
            credential,
            credential_original,
            certificate_set_original,
            account,
            account_original,
            asset_scope,
            asset_scope_original,
            challenge,
        })
    }

    /// The exact fresh Native message for the selected existing Ed25519 account loan.
    #[must_use]
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    /// Explicitly abandon this account challenge while retaining the actual unadmitted provider.
    /// Ordinary validation/IO failures never invoke this deliberate cancellation path.
    #[must_use]
    pub fn abandon(self) -> KagemushaWalletProviderV1<F, P> {
        self.provider
    }

    /// Compare transport DATA with the exact originals bound by this pending challenge.
    /// This check does not reselect a slot, alter source authority or sample a nonce.
    #[must_use]
    pub fn matches_originals(&self, proposed: [&[u8]; 4]) -> bool {
        [
            self.credential_original.as_slice(),
            self.certificate_set_original.as_slice(),
            self.account_original.as_slice(),
            self.asset_scope_original.as_slice(),
        ] == proposed
    }

    /// Consume one authorization and recheck the exact source and actual payment key.
    /// Every refusal returns the SAME pending owner, preserving its exact original challenge.
    /// # Errors
    /// Wrong account signature, stale/changed source, unknown key/storage or lost custody.
    pub fn finish(
        self,
        account_signature: &[u8],
    ) -> Result<AdmittedWalletV1<F, P>, WalletOpenFinishFailureV1<F, P>> {
        let checked = retain_checked(self, |pending| {
            authorize_account(&pending.account, &pending.challenge, account_signature)?;
            let marker = source(
                &mut pending.provider,
                &pending.slot,
                &pending.credential,
                &pending.credential_original,
            )?;
            if marker.marker_file_digest() != &pending.marker_file_digest {
                return Err(Error::SourceChanged);
            }
            Ok(())
        });
        let (pending, ()) = match checked {
            Ok(checked) => checked,
            Err((pending, error)) => return Err(WalletOpenFinishFailureV1 { pending, error }),
        };
        Ok(AdmittedWalletV1 {
            provider: pending.provider,
            installed: pending.installed,
            sources: pending.sources,
            slot: pending.slot,
            credential: pending.credential,
            credential_original: pending.credential_original,
            certificate_set_original: pending.certificate_set_original,
            account: pending.account,
            account_original: pending.account_original,
            asset_scope: pending.asset_scope,
            asset_scope_original: pending.asset_scope_original,
        })
    }
}

impl<F: KagemushaWalletFsV1, P> AdmittedWalletV1<F, P> {
    /// Exact account identity admitted from its original and existing key authorization.
    #[must_use]
    pub const fn account(&self) -> &AccountId {
        &self.account
    }

    /// Exact issuer-authenticated credential of the actual selected source.
    #[must_use]
    pub const fn credential(&self) -> &KagemushaWalletCredentialV1 {
        &self.credential
    }

    /// Exact credential, Enrollment CertificateSet, account and asset-scope frames,
    /// retained for the authentic native operation owner.
    #[must_use]
    pub fn originals(&self) -> (&[u8], &[u8], &[u8], &[u8]) {
        (
            &self.credential_original,
            &self.certificate_set_original,
            &self.account_original,
            &self.asset_scope_original,
        )
    }

    /// Authoritative monetary asset and scale bound by the authenticated credential.
    /// Native immutable review metadata uses this original; the App never infers scope.
    #[must_use]
    pub const fn asset_scope(&self) -> &KagemushaWalletAssetScopeV1 {
        &self.asset_scope
    }

    /// Move the real admission into Native's operation owner, keeping exclusive custody
    /// and every exact owner original. This is crate-private and grants no foreign open.
    pub(crate) fn into_parts(
        self,
    ) -> (
        KagemushaWalletProviderV1<F, P>,
        Arc<InstalledVerifierPackV1>,
        Arc<QualifiedWalletSourcesV1>,
        KagemushaWalletSlotIdV1,
        KagemushaWalletCredentialV1,
        AccountId,
        KagemushaWalletAssetScopeV1,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) {
        (
            self.provider,
            self.installed,
            self.sources,
            self.slot,
            self.credential,
            self.account,
            self.asset_scope,
            self.credential_original,
            self.certificate_set_original,
            self.account_original,
            self.asset_scope_original,
        )
    }
}

#[cfg(test)]
#[path = "kagemusha_wallet_intake_v1/tests.rs"]
mod tests;
