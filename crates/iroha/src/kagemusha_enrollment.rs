//! Middleware adapter for current KAGEMUSHA enrollment eligibility.
//!
//! Mount this adapter behind the bank's authenticated issuer-to-middleware endpoint. Resolve
//! the canonical account and actor together in the bank's customer directory, then read current
//! approval and freeze state in one transaction. No KYC documents leave the bank. An operator
//! selected by the authenticated asset/scheme owner uses the same protocol and binding checks.
//!
//! The issuer authenticates current authority/routing independently, retains each fresh request
//! before dispatch, and consumes its response at the named durable enrollment boundary. This
//! adapter does not install a trust root or issue a wallet credential.

use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::kagemusha::{
    KagemushaEligibilityDecisionV1, KagemushaEligibilityObservationV1,
    KagemushaEligibilityPolicyTemplateV1, KagemushaEligibilityPolicyV1,
    KagemushaEligibilityRequestV1, KagemushaEligibilityResponseBodyV1,
    KagemushaEligibilityResponseV1, KagemushaWalletAssetScopeV1,
};

/// One atomic observation supplied by the selected provider's current middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentEnrollmentEligibilityV1 {
    /// Approval under this authority's current policy, including bank KYC where applicable.
    pub approved: bool,
    /// Any current subject, account or scoped-token freeze; freeze always takes precedence.
    pub frozen: bool,
    /// Positive source revision retained for audit. Every request still requires a fresh read.
    pub revision: u64,
    /// Trusted time of this atomic current-state read, never the record's last-update time.
    /// Must fall between the adapter's before-lookup and after-lookup clock samples.
    pub observed_at_ms: u64,
}

/// Closed middleware failures. No failure is converted into approval or cached success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnrollmentEligibilityMiddlewareErrorV1 {
    /// Malformed request, foreign policy/scope, or invalid configured policy.
    #[error("invalid enrollment eligibility request or policy")]
    InvalidRequest,
    /// Authentication, current account binding, approval/freeze storage or lookup is unavailable.
    #[error("current enrollment eligibility is unavailable")]
    Unavailable,
    /// Clock failed, moved backwards, or the request is not currently live.
    #[error("enrollment eligibility request is not live")]
    Clock,
    /// The current source returned an invalid revision or a time outside the actual read.
    #[error("invalid enrollment eligibility source observation")]
    InvalidObservation,
    /// The selected middleware signer is unavailable or failed.
    #[error("enrollment eligibility signing is unavailable")]
    Signing,
    /// Signer output does not verify under the selected middleware key.
    #[error("enrollment eligibility signer output was rejected")]
    Signature,
}
type Result<T> = core::result::Result<T, EnrollmentEligibilityMiddlewareErrorV1>;

/// Construct one exact signed response after a fresh, scoped middleware read.
///
/// `read_current` must independently bind the request's actor and canonical account to the
/// selected bank or scheme operator and atomically read approval and freeze state for the
/// exact asset incarnation and scale. The configured template applies to registered assets;
/// the envelope supplies asset DATA and never supplies authority or approval.
/// Unknown subjects, unavailable records and authentication failures return `Unavailable`.
/// The callback is invoked once, after canonical request admission and before signing. This
/// function performs no network retry or cache lookup. The caller authenticates the transport
/// before calling it. Select `template` from authenticated middleware configuration, never from
/// this request. Its exact derived policy must match the enclosed request before any lookup.
///
/// `clock` supplies genuine positive Unix milliseconds. `sign` may use authenticated software
/// custody or an external signer; its actual signature is always verified before returning.
///
/// # Errors
/// Rejects invalid/foreign/stale requests, unavailable reads, time rollback, invalid revision,
/// signing failure or foreign/malformed signer output. No response is emitted on these errors.
pub fn answer_enrollment_eligibility_v1(
    template: &KagemushaEligibilityPolicyTemplateV1,
    request_original: &[u8],
    mut clock: impl FnMut() -> Result<u64>,
    read_current: impl FnOnce(
        &KagemushaWalletAssetScopeV1,
        &KagemushaEligibilityPolicyV1,
        &KagemushaEligibilityRequestV1,
    ) -> Result<CurrentEnrollmentEligibilityV1>,
    sign: impl FnOnce(&[u8; 32]) -> Result<[u8; 64]>,
) -> Result<Vec<u8>> {
    use EnrollmentEligibilityMiddlewareErrorV1 as Error;
    let observation =
        KagemushaEligibilityObservationV1::decode_canonical(request_original, template)
            .map_err(|_| Error::InvalidRequest)?;
    let policy = observation
        .policy(template)
        .map_err(|_| Error::InvalidRequest)?;
    let request = observation.request;
    let started = clock()?;
    require_live(&request, started, request.requested_at_ms)?;
    let current = read_current(&observation.asset, &policy, &request)?;
    if current.revision == 0 {
        return Err(Error::InvalidObservation);
    }
    let read_completed = clock()?;
    require_live(&request, read_completed, started)?;
    if current.observed_at_ms < started || current.observed_at_ms > read_completed {
        return Err(Error::InvalidObservation);
    }
    let decision = if current.frozen {
        KagemushaEligibilityDecisionV1::Frozen
    } else if current.approved {
        KagemushaEligibilityDecisionV1::ApprovedUnfrozen
    } else {
        KagemushaEligibilityDecisionV1::NotApproved
    };
    let body = KagemushaEligibilityResponseBodyV1 {
        version: 1,
        request_digest: request
            .request_digest(&policy)
            .map_err(|_| Error::InvalidRequest)?,
        decision,
        source_revision: current.revision,
        observed_at_ms: current.observed_at_ms,
        valid_until_ms: request.expires_at_ms,
    };
    let signature = sign(
        &body
            .signing_message()
            .map_err(|_| Error::InvalidObservation)?,
    )?;
    let response = KagemushaEligibilityResponseV1 { body, signature };
    let completed = clock()?;
    require_live(&request, completed, read_completed)?;
    response
        .verify(&policy, &request, completed)
        .map_err(|_| Error::Signature)?;
    response.encode_canonical().map_err(|_| Error::Signature)
}

/// Convenience software-custody signer; the caller owns secure key loading and rotation.
///
/// No key is generated, persisted, logged or inferred from a request. Use the callback-based
/// adapter directly when the existing bank middleware owns signing through another provider.
/// # Errors
/// Rejects a non-Ed25519 key and every signing failure.
pub fn sign_enrollment_eligibility_v1(key_pair: &KeyPair, message: &[u8; 32]) -> Result<[u8; 64]> {
    use EnrollmentEligibilityMiddlewareErrorV1 as Error;
    if key_pair.public_key().algorithm() != Algorithm::Ed25519 {
        return Err(Error::Signing);
    }
    Signature::try_new(key_pair.private_key(), message)
        .map_err(|_| Error::Signing)?
        .payload()
        .try_into()
        .map_err(|_| Error::Signing)
}

fn require_live(request: &KagemushaEligibilityRequestV1, now: u64, floor: u64) -> Result<()> {
    if now < floor || now < request.requested_at_ms || now >= request.expires_at_ms {
        return Err(EnrollmentEligibilityMiddlewareErrorV1::Clock);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
