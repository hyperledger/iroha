//! Exact authenticated enrollment operation envelopes; parsing grants no enrollment authority.

use norito::{Decode, Encode, NoritoSchema};

/// Exact canonical POST target. Queries and alternative targets are not accepted.
pub const ENROLLMENT_SERVICE_ROUTE_V1: &str = "/v1/kagemusha/enrollment";
/// Native pre-key dispatch original bound, checked again by the native owner.
pub const ENROLLMENT_DISPATCH_MAX_BYTES_V1: usize = 16_384;
/// Native account-signed E5 original bound, checked again by the native owner.
pub const ENROLLMENT_EVIDENCE_REQUEST_MAX_BYTES_V1: usize = 524_288;
/// Complete request frame bound including the dispatch, E5 and bounded Norito framing.
pub const ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1: usize = 544 * 1024;
/// Native E6 original bound; this is an online enrollment message, not an offline Payment.
pub const ENROLLMENT_RESULT_MAX_BYTES_V1: usize = 262_144;
/// Complete response envelope bound including the original and Norito framing.
pub const ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1: usize = 264 * 1024;

/// One closed issuer action. The entire envelope is covered by native Torii account authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito_schema(name = "iroha.torii.kagemusha.enrollment.action.v1")]
pub enum EnrollmentServiceActionV1 {
    /// Obtain or recover the exact durable pre-key permit before mobile key generation.
    #[codec(index = 0)]
    PreKey,
    /// Submit/recover the exact account-signed evidence request; never reset a consumed attempt.
    #[codec(index = 1)]
    Evidence,
    /// Issue/recover the exact credential after retained platform evidence and fresh eligibility.
    #[codec(index = 2)]
    Issue,
    /// Deliver the exact retained E6 after fresh current eligibility.
    #[codec(index = 3)]
    Deliver,
}

/// Public request DATA; there are no key paths, worker selectors or caller verdict fields.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito_schema(name = "iroha.torii.kagemusha.enrollment.request.v1")]
pub struct EnrollmentServiceRequestV1 {
    /// Exactly one for the sole first-release format.
    pub version: u16,
    /// Exact operation covered by the account signature.
    pub action: EnrollmentServiceActionV1,
    /// Exact native `PreKeyDispatchV1` original used at every recovery boundary.
    pub dispatch_original: Vec<u8>,
    /// Exact native account-signed `RequestV1`, required only for Evidence.
    pub evidence_original: Vec<u8>,
}
fn invalid() -> norito::Error {
    norito::Error::Message("invalid enrollment service envelope".into())
}
impl EnrollmentServiceRequestV1 {
    /// Validate finite envelope shape only; native originals still require their complete checks.
    /// # Errors
    /// Unknown version, missing/oversized originals or evidence on the wrong action.
    pub fn validate(&self) -> Result<(), norito::Error> {
        if self.version != 1
            || self.dispatch_original.is_empty()
            || self.dispatch_original.len() > ENROLLMENT_DISPATCH_MAX_BYTES_V1
            || self.evidence_original.len() > ENROLLMENT_EVIDENCE_REQUEST_MAX_BYTES_V1
            || (self.action == EnrollmentServiceActionV1::Evidence)
                == self.evidence_original.is_empty()
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Encode exact bytes for canonical Torii account signing; there is no fallback format.
    /// # Errors
    /// Invalid shape, codec failure or complete frame beyond the fixed online bound.
    pub fn canonical_wire(&self) -> Result<Vec<u8>, norito::Error> {
        self.validate()?;
        if norito::canonical_frame_len(self)? > ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1 {
            return Err(invalid());
        }
        norito::encode_canonical(self)
    }
    /// Decode exactly one bounded canonical operation envelope.
    /// # Errors
    /// Malformed, noncanonical, trailing or excessive bytes or invalid field shape.
    pub fn decode_canonical(original: &[u8]) -> Result<Self, norito::Error> {
        if original.is_empty() || original.len() > ENROLLMENT_SERVICE_REQUEST_MAX_BYTES_V1 {
            return Err(invalid());
        }
        let value: Self = norito::decode_canonical_with_limits(
            original,
            norito::canonical_decode_limits(original.len()),
        )?;
        value.validate()?;
        Ok(value)
    }
}

/// Explicit operation result. A pending response never authorizes a new verification attempt.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito_schema(name = "iroha.torii.kagemusha.enrollment.response.v1")]
pub enum EnrollmentServiceResponseV1 {
    /// Exact durably retained canonical pre-key permit.
    #[codec(index = 0)]
    Permit(Vec<u8>),
    /// Exact platform evidence is durable; subsequent Issue remains separately authorized.
    #[codec(index = 1)]
    EvidenceReady,
    /// The exact attempt remains consumed; retry only recovers that operation.
    #[codec(index = 2)]
    Pending,
    /// E6 is durably retained; Deliver checks fresh eligibility before returning it.
    #[codec(index = 3)]
    CredentialReady,
    /// Exact original E6, never regenerated or refreshed on retry.
    #[codec(index = 4)]
    Credential(Vec<u8>),
}
impl EnrollmentServiceResponseV1 {
    fn validate(&self) -> Result<(), norito::Error> {
        match self {
            Self::Permit(original)
                if original.is_empty()
                    || original.len()
                        > iroha_data_model::kagemusha::KAGEMUSHA_ENROLLMENT_PERMIT_MAX_BYTES_V1 =>
            {
                Err(invalid())
            }
            Self::Credential(original)
                if original.is_empty() || original.len() > ENROLLMENT_RESULT_MAX_BYTES_V1 =>
            {
                Err(invalid())
            }
            _ => Ok(()),
        }
    }
    /// Encode bounded exact service output; callers separately verify signed originals.
    /// # Errors
    /// Missing/oversized originals, codec failure or excessive total frame.
    pub fn canonical_wire(&self) -> Result<Vec<u8>, norito::Error> {
        self.validate()?;
        if norito::canonical_frame_len(self)? > ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1 {
            return Err(invalid());
        }
        norito::encode_canonical(self)
    }
    /// Decode only the current complete canonical response format.
    /// # Errors
    /// Invalid shape, malformed/noncanonical bytes, trailing input or excessive frame.
    pub fn decode_canonical(original: &[u8]) -> Result<Self, norito::Error> {
        if original.is_empty() || original.len() > ENROLLMENT_SERVICE_RESPONSE_MAX_BYTES_V1 {
            return Err(invalid());
        }
        let value: Self = norito::decode_canonical_with_limits(
            original,
            norito::canonical_decode_limits(original.len()),
        )?;
        value.validate()?;
        Ok(value)
    }
}

/// Response header relaying a terminal refusal's closed reason code (1–12, canonical decimal).
pub const ENROLLMENT_REFUSAL_CODE_HEADER_V1: &str = "x-iroha-kagemusha-refusal-code";
/// Response header relaying the closed code (11 or 12) that withholds delivery of an Issued
/// outcome. The Issued outcome and its exact E6 stay retained; delivery may be retried.
pub const ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1: &str = "x-iroha-kagemusha-delivery-withheld-code";
/// Response header marking an outcome that is unknown after a possible effect.
pub const ENROLLMENT_OUTCOME_HEADER_V1: &str = "x-iroha-kagemusha-outcome";
/// The only value of [`ENROLLMENT_OUTCOME_HEADER_V1`].
pub const ENROLLMENT_OUTCOME_UNKNOWN_V1: &str = "unknown";

/// Closed non-success outcome of one enrollment operation (design §2.4), relayed by exactly one
/// response header. Identical HTTP statuses carry different outcomes, so clients must read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentServiceOutcomeV1 {
    /// HTTP 403: terminal refusal of this attempt with its closed reason; every retry returns
    /// it unchanged and a new attempt needs a new issuer challenge.
    Refused(iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1),
    /// HTTP 403: delivery of an Issued outcome is withheld by an authenticated eligibility
    /// observation (code 11 or 12). The exact E6 stays retained; delivery may be retried.
    DeliveryWithheld(iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1),
    /// HTTP 409: an effect may have taken place without a retained outcome. The holder recovers
    /// or abandons the attempt and never restarts it as a fresh one.
    OutcomeUnknown,
}

impl EnrollmentServiceOutcomeV1 {
    /// Exact HTTP status that carries this outcome.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::Refused(_) | Self::DeliveryWithheld(_) => 403,
            Self::OutcomeUnknown => 409,
        }
    }

    /// The one header that carries this outcome, with its exact value.
    #[must_use]
    pub fn header(self) -> (&'static str, String) {
        match self {
            Self::Refused(reason) => (ENROLLMENT_REFUSAL_CODE_HEADER_V1, reason.code().to_string()),
            Self::DeliveryWithheld(reason) => (
                ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1,
                reason.code().to_string(),
            ),
            Self::OutcomeUnknown => (
                ENROLLMENT_OUTCOME_HEADER_V1,
                ENROLLMENT_OUTCOME_UNKNOWN_V1.to_owned(),
            ),
        }
    }

    /// Strictly read the outcome of one non-success response from its `status` and headers
    /// (names compared case-insensitively). `Ok(None)` when no outcome header is present.
    ///
    /// # Errors
    /// More than one outcome header (including a repeated one), a noncanonical or unknown
    /// code, a withholding code other than 11/12, another unknown-outcome value, or a status
    /// that does not carry the outcome.
    pub fn from_headers<'a>(
        status: u16,
        headers: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> Result<Option<Self>, norito::Error> {
        use iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1 as Refusal;
        let code = |value: &[u8]| -> Result<Refusal, norito::Error> {
            let text = std::str::from_utf8(value).map_err(|_| invalid_outcome())?;
            if text.is_empty()
                || text.len() > 5
                || text.starts_with('0')
                || !text.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid_outcome());
            }
            let code: u16 = text.parse().map_err(|_| invalid_outcome())?;
            Refusal::from_code(code).ok_or_else(invalid_outcome)
        };
        let mut outcome = None;
        for (name, value) in headers {
            let parsed = if name.eq_ignore_ascii_case(ENROLLMENT_REFUSAL_CODE_HEADER_V1) {
                Self::Refused(code(value)?)
            } else if name.eq_ignore_ascii_case(ENROLLMENT_DELIVERY_WITHHELD_HEADER_V1) {
                let reason = code(value)?;
                if !reason.is_eligibility() {
                    return Err(invalid_outcome());
                }
                Self::DeliveryWithheld(reason)
            } else if name.eq_ignore_ascii_case(ENROLLMENT_OUTCOME_HEADER_V1) {
                if value != ENROLLMENT_OUTCOME_UNKNOWN_V1.as_bytes() {
                    return Err(invalid_outcome());
                }
                Self::OutcomeUnknown
            } else {
                continue;
            };
            if outcome.replace(parsed).is_some() {
                return Err(invalid_outcome());
            }
        }
        if outcome.is_some_and(|outcome| outcome.status() != status) {
            return Err(invalid_outcome());
        }
        Ok(outcome)
    }
}

fn invalid_outcome() -> norito::Error {
    norito::Error::Message("invalid enrollment service outcome".into())
}

#[cfg(test)]
mod tests;
