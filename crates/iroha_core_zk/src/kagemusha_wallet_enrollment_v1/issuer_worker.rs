//! Exact native boundary for the private E1 verifier process.
//!
//! This codec owns no issuer key and grants no platform or policy authority. The issuer must
//! authenticate its worker/runtime/configuration, retain the original request before dispatch,
//! enforce challenge single use and complete only a durably prepared operation. Recovery may
//! win an unclaimed preparation; an already claimed operation never repeats verification.
//! Inspection only reads an exact retained result and never claims an operation, including
//! when the issuer recovers an already consumed attempt after the challenge deadline.
//! The node journal retains these original requests and checked replies before signing.
//! Core now selects the current configured provider and exact registered asset; Torii owns
//! authenticated calls, the private worker process and the retained enrollment signer.
//! TODO: qualify actual Linux private-worker deployment and issuer recovery end to end.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_data_model::kagemusha::*;
use norito::json::{self, Value};
use sha2::{Digest as _, Sha256};

use super::{
    IssuerEvidenceV1, PlatformEvidenceV1, PreKeyDispatchV1, RequestV1,
    carrier::{ANDROID_CERTIFICATE_MAX_BYTES, ANDROID_CHAIN_MAX, ANDROID_CHAIN_MIN},
};

#[path = "issuer_worker_protocol.rs"]
mod protocol;
pub use protocol::{VerifierExchangeV1, VerifierPreparationV1};

#[path = "issuer_worker_configuration.rs"]
mod configuration;
pub use configuration::{
    ANDROID_VENDOR_ADAPTER_PROFILES_V1, VerifierConfigurationV1, VerifierRuntimeSelectionV1,
    require_qualified_android_adapters_v1,
};

const SCHEMA: &str = "iroha.kagemusha.wallet-e1-verifier.v1";
const MAX_REQUEST: usize = 320 * 1024;
const MAX_RESULT: usize = 360 * 1024;
/// Maximum private JSON packet, excluding its four-byte little-endian length.
pub const MAX_PACKET: usize = 768 * 1024;

/// Refused private frame or binding. Diagnostics never contain original platform evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("enrollment verifier boundary: {0}")]
pub struct Error(&'static str);

/// One retained private verifier request. Its timestamps are supplied by the issuer journal,
/// never by a mobile request. Construction checks consistency, not operator approval or KYC.
pub struct VerifierRequestV1 {
    request: RequestV1,
    original: Vec<u8>,
    configuration: [u8; 32],
    verification_time_ms: u64,
    preparation: VerifierPreparationV1,
}

/// Action selected by the durable issuer owner. Inspection cannot start verification.
#[derive(Debug, Clone, Copy)]
pub enum ActionV1 {
    /// Claim the durably prepared operation or return its exact retained outcome.
    Complete,
    /// Recover this exact prepared operation; only an unclaimed preparation can verify once.
    Recover,
    /// Read this exact retained result without preparing, claiming or verifying an operation.
    /// A missing or unclaimed operation is unavailable; a claimed operation without a result
    /// remains outcome-unknown. Reading after the challenge deadline grants no new attempt.
    Inspect,
    /// Refresh only revocation of an already successful Android enrollment. This never
    /// claims or changes an enrollment and cannot produce evidence for issuance.
    RecheckRevocation,
}

/// Fresh private-channel revocation decision, never enrollment evidence or a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationOutcomeV1 {
    /// The retained chain is not listed by its current selected revocation sources.
    Current,
    /// A current revocation source or successful retained enrollment is unavailable.
    Unavailable,
    /// The retained chain is currently listed.
    Revoked,
}

/// Separate worker outcome classes; none is a credential, approval, or permission to repeat
/// verification. Only `Refused` is a terminal E1 outcome here: `Evidence` is an intermediate
/// verification result that the issuer turns into Issued only by signing and retaining E6, and
/// `Unavailable`/`OutcomeUnknown` are recovery states, never retained as the answer.
#[derive(Debug)]
pub enum OutcomeV1 {
    /// The private worker retained this projection and its original evidence.
    Evidence(EvidenceProjectionV1),
    /// The worker claimed the operation and an effect may have taken place, but it holds no
    /// retained result. Recovery never verifies again as a first attempt.
    OutcomeUnknown,
    /// The worker could not decide before any effect. When durable worker state shows a
    /// pre-effect outage, `Complete`/`Recover` resume the same claim with the exact E5,
    /// configuration and first dispatch time.
    Unavailable,
    /// The worker refused the evidence with exactly one closed platform refusal reason
    /// (codes 1–10 of design §2.4). The challenge is consumed; every retry returns this code.
    Refused(KagemushaWalletEnrollmentRefusalV1),
}

/// Checked consistency of the worker's exact result. Only an authenticated worker channel
/// establishes its provenance; this value alone grants no authority to sign a credential.
#[derive(Debug)]
pub struct EvidenceProjectionV1 {
    /// Evidence kind returned by the configured platform verifier.
    pub kind: KagemushaWalletEvidenceKindV1,
    /// Model evidence with a digest independently derived from exact originals.
    pub evidence: KagemushaWalletEvidenceV1,
    /// Original platform objects: the exact Android chain, or the Apple originals.
    pub originals: IssuerEvidenceV1,
    /// Apple's retained key/counter pair; absent on Android.
    pub apple_counter: Option<([u8; 32], u32)>,
    /// Exact private result for the issuer's durable original archive.
    pub original_result: Vec<u8>,
}

fn encode(value: &Value, maximum: usize) -> Result<Vec<u8>, Error> {
    let bytes = json::to_vec(value).map_err(|_| Error("JSON encoding"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error("frame bound"));
    }
    Ok(bytes)
}
fn decode(bytes: &[u8], maximum: usize) -> Result<Value, Error> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error("frame bound"));
    }
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(maximum, maximum, maximum * 4, maximum * 8, 8),
        || json::from_slice(bytes),
    )
    .map_err(|_| Error("JSON decoding"))
}
fn fields(value: &Value, expected: &[&str]) -> Result<(), Error> {
    let object = value.as_object().ok_or(Error("JSON object"))?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(Error("JSON fields"));
    }
    Ok(())
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Error("text field"))
}
fn integer(value: &Value, key: &str) -> Result<u64, Error> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(Error("integer field"))
}
fn digest(value: &Value, key: &str) -> Result<[u8; 32], Error> {
    let value = text(value, key)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error("digest spelling"));
    }
    let mut output = [0; 32];
    hex::decode_to_slice(value, &mut output).map_err(|_| Error("digest encoding"))?;
    Ok(output)
}
fn binary(value: &str, maximum: usize) -> Result<Vec<u8>, Error> {
    if value.is_empty() || value.len() > maximum.div_ceil(3) * 4 {
        return Err(Error("binary bound"));
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| Error("binary encoding"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error("binary bound"));
    }
    if STANDARD.encode(&bytes) != value {
        return Err(Error("binary spelling"));
    }
    Ok(bytes)
}

impl VerifierRequestV1 {
    /// Bind an exact account-signed E5 to its selected pre-key preparation and issuer time.
    /// This checks DATA consistency; the durable journal must retain the preparation and
    /// authenticated worker acknowledgment before exposing the challenge or dispatching E5.
    /// # Errors
    /// Foreign account/policy/challenge, invalid signature, or time outside the selected window.
    pub fn from_prepared(
        request: RequestV1,
        preparation: &VerifierPreparationV1,
        verification_time_ms: u64,
    ) -> Result<Self, Error> {
        request.validate().map_err(Error)?;
        preparation.require_request(&request)?;
        let approved_policy = &preparation.policy;
        let challenge_created_at_ms = preparation.created_at_ms;
        approved_policy
            .require_live_challenge(challenge_created_at_ms, verification_time_ms)
            .map_err(|_| Error("retained challenge time"))?;
        let expires = preparation.expires_at_ms;
        // The authenticated session can shorten the policy lifetime. First capture must
        // fit that original deadline; restoring a captured request keeps its original time.
        if verification_time_ms >= expires {
            return Err(Error("retained preparation deadline"));
        }
        let mobile =
            PlatformEvidenceV1::decode(&request.body.evidence, approved_policy).map_err(Error)?;
        let (platform, evidence) = match mobile {
            PlatformEvidenceV1::Android { certificates } => (
                "android",
                norito::json!({
                    "chain_base64": (certificates.iter().map(|v| STANDARD.encode(v)).collect::<Vec<_>>()),
                }),
            ),
            PlatformEvidenceV1::Apple {
                key_id,
                attestation,
                key_binding_assertion,
            } => (
                "apple",
                norito::json!({
                    "key_id_hex": (hex::encode(key_id)),
                    "attestation_base64": (STANDARD.encode(attestation)),
                    "assertion_base64": (STANDARD.encode(key_binding_assertion)),
                }),
            ),
        };
        let original = encode(
            &norito::json!({
                "challenge_transcript_base64": (STANDARD.encode(request.body.challenge.transcript())),
                "payment_key_base64": (STANDARD.encode(request.body.marker.payment_key.as_sec1_bytes())),
                "issued_at_ms": (challenge_created_at_ms),
                "expires_at_ms": (expires),
                "trusted_time_ms": (verification_time_ms),
                "platform": (platform),
                "evidence": (evidence),
            }),
            MAX_REQUEST,
        )?;
        Ok(Self {
            request,
            original,
            configuration: preparation.configuration,
            verification_time_ms,
            preparation: preparation.clone(),
        })
    }

    /// The exact request to archive before dispatch and reuse for every recovery.
    pub fn original(&self) -> &[u8] {
        &self.original
    }

    /// Retain a complete, recovery or inspection exchange with a fresh nonzero identifier.
    /// The immutable request time is unchanged; this fresh issuer time selects the first
    /// verification time only if Complete or Recover wins the operation's atomic claim.
    /// Inspect uses the time only as an upper bound on a retained result, never for a claim.
    /// # Errors
    /// Empty identities, backwards dispatch time, or packet bounds.
    pub fn packet(
        &self,
        action: ActionV1,
        incarnation: [u8; 32],
        exchange: [u8; 32],
        dispatch_time_ms: u64,
    ) -> Result<VerifierExchangeV1, Error> {
        protocol::request_exchange(self, action, incarnation, exchange, dispatch_time_ms)
    }

    /// Check the exact exchange and every reply binding before projecting evidence.
    /// The caller must independently authenticate the worker channel and preserve its custody.
    /// # Errors
    /// A foreign exchange/request/preparation, malformed response, or invalid evidence binding.
    pub fn response(
        &self,
        exchange: &VerifierExchangeV1,
        frame: &[u8],
    ) -> Result<OutcomeV1, Error> {
        if matches!(exchange.action(), Some(ActionV1::RecheckRevocation)) {
            return Err(Error("revocation is not enrollment evidence"));
        }
        let (value, dispatch_time_ms) = exchange.request_response(self, frame)?;
        if text(&value, "outcome")? == "evidence" {
            if value.get("refusal_code") != Some(&Value::Null) {
                return Err(Error("evidence refusal code"));
            }
            let original = binary(text(&value, "evidence_base64")?, MAX_RESULT)?;
            return self
                .projection_at(original, dispatch_time_ms)
                .map(OutcomeV1::Evidence);
        }
        protocol::failure(&value, Some(self.is_android()))
    }

    /// Bind a fresh revocation-only reply to this exact retained request and exchange.
    /// The caller must authenticate the private channel; no cached reply grants freshness.
    /// # Errors
    /// Wrong action/platform, substituted bindings, evidence, or any non-revocation refusal.
    pub fn revocation_response(
        &self,
        exchange: &VerifierExchangeV1,
        frame: &[u8],
    ) -> Result<RevocationOutcomeV1, Error> {
        if !self.is_android() || !matches!(exchange.action(), Some(ActionV1::RecheckRevocation)) {
            return Err(Error("revocation exchange kind"));
        }
        let (value, _) = exchange.request_response(self, frame)?;
        if value.get("evidence_base64") != Some(&Value::Null) {
            return Err(Error("revocation carries evidence"));
        }
        match (text(&value, "outcome")?, value.get("refusal_code")) {
            ("current", Some(Value::Null)) => Ok(RevocationOutcomeV1::Current),
            ("unavailable", Some(Value::Null)) => Ok(RevocationOutcomeV1::Unavailable),
            ("refused", Some(code)) if code.as_u64() == Some(6) => Ok(RevocationOutcomeV1::Revoked),
            _ => Err(Error("revocation outcome")),
        }
    }

    /// Closed refusal reason of an exact refused reply that the issuer retained, together with
    /// the selection of the exchange that produced it, after [`Self::response`] authenticated
    /// it. `exchange` is that exchange rebuilt from this request with [`Self::packet`] and the
    /// retained action, journal incarnation, exchange identifier and dispatch time; the reply is
    /// checked again against every binding of that exchange (identifier, request digest,
    /// journal incarnation, configuration, platform code). Every retry of the consumed attempt
    /// returns this same reason; the frame is never re-verified as a new attempt.
    /// # Errors
    /// A frame that is not an exact refused reply to `exchange` for this request.
    pub fn retained_refusal(
        &self,
        exchange: &VerifierExchangeV1,
        frame: &[u8],
    ) -> Result<KagemushaWalletEnrollmentRefusalV1, Error> {
        match self.response(exchange, frame)? {
            OutcomeV1::Refused(reason) => Ok(reason),
            _ => Err(Error("retained refusal")),
        }
    }

    fn is_android(&self) -> bool {
        matches!(
            self.preparation.policy.platform,
            KagemushaWalletEnrollmentPlatformV1::Android { .. }
        )
    }

    /// Recheck an exact evidence original retained by the issuer after an authenticated reply.
    /// This proves the same request/configuration/time bindings as `response`; it does not
    /// authenticate arbitrary caller-supplied evidence or grant credential-signing authority.
    pub fn retained_evidence(&self, original: &[u8]) -> Result<EvidenceProjectionV1, Error> {
        if original.is_empty() || original.len() > MAX_RESULT {
            return Err(Error("frame bound"));
        }
        self.projection(original.to_vec())
    }

    fn projection(&self, original_result: Vec<u8>) -> Result<EvidenceProjectionV1, Error> {
        self.projection_at(original_result, u64::MAX)
    }

    fn projection_at(
        &self,
        original_result: Vec<u8>,
        latest_time_ms: u64,
    ) -> Result<EvidenceProjectionV1, Error> {
        let value = decode(&original_result, MAX_RESULT)?;
        fields(
            &value,
            &[
                "config_sha256",
                "challenge_digest",
                "key_binding",
                "payment_key_base64",
                "kind_tag",
                "time_ms",
                "facts",
                "os_patch_level",
                "vendor_patch_level",
                "boot_patch_level",
                "evidence_digest",
                "original_items_base64",
                "app_attest_key_id",
                "app_attest_counter",
            ],
        )?;
        let body = &self.request.body;
        let evidence_time_ms = integer(&value, "time_ms")?;
        if digest(&value, "config_sha256")? != self.configuration
            || digest(&value, "challenge_digest")? != body.challenge.challenge_digest()
            || digest(&value, "key_binding")?
                != kagemusha_wallet_enrollment_key_binding_v1(
                    &body.challenge.challenge_digest(),
                    &body.marker.payment_key,
                )
            || binary(text(&value, "payment_key_base64")?, 65)?
                != body.marker.payment_key.as_sec1_bytes()
            || evidence_time_ms < self.verification_time_ms
            || evidence_time_ms >= self.preparation.expires_at_ms
            || evidence_time_ms > latest_time_ms
        {
            return Err(Error("evidence identity"));
        }
        let kind = match integer(&value, "kind_tag")? {
            1 => KagemushaWalletEvidenceKindV1::AndroidKeyMintTee,
            2 => KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox,
            3 => KagemushaWalletEvidenceKindV1::AppleAppAttest,
            _ => return Err(Error("evidence kind")),
        };
        let encoded = value
            .get("original_items_base64")
            .and_then(Value::as_array)
            .ok_or(Error("evidence items"))?;
        let count = if kind.is_android() {
            ANDROID_CHAIN_MIN..=ANDROID_CHAIN_MAX
        } else {
            2..=2
        };
        if !count.contains(&encoded.len()) {
            return Err(Error("evidence item count"));
        }
        let mut items = encoded
            .iter()
            .enumerate()
            .map(|(index, v)| {
                let maximum = if kind.is_android() {
                    ANDROID_CERTIFICATE_MAX_BYTES
                } else if index == 0 {
                    65_536
                } else {
                    4_096
                };
                binary(v.as_str().ok_or(Error("evidence item"))?, maximum)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (originals, apple_counter) = match (&body.policy.platform, kind) {
            (
                KagemushaWalletEnrollmentPlatformV1::Android { .. },
                KagemushaWalletEvidenceKindV1::AndroidKeyMintTee
                | KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox,
            ) => {
                // The attested level chooses TEE or StrongBox; both are admitted.
                if value.get("app_attest_key_id") != Some(&Value::Null)
                    || value.get("app_attest_counter") != Some(&Value::Null)
                {
                    return Err(Error("Android evidence policy"));
                }
                (
                    IssuerEvidenceV1::Android {
                        certificates: items,
                    },
                    None,
                )
            }
            (
                KagemushaWalletEnrollmentPlatformV1::Apple { .. },
                KagemushaWalletEvidenceKindV1::AppleAppAttest,
            ) => {
                let key_id = digest(&value, "app_attest_key_id")?;
                let counter = u32::try_from(integer(&value, "app_attest_counter")?)
                    .map_err(|_| Error("Apple counter"))?;
                let PlatformEvidenceV1::Apple {
                    key_id: expected, ..
                } = PlatformEvidenceV1::decode(&body.evidence, &body.policy).map_err(Error)?
                else {
                    return Err(Error("Apple original kind"));
                };
                if key_id != expected || counter == 0 {
                    return Err(Error("Apple key/counter"));
                }
                let key_binding_assertion = items.pop().ok_or(Error("Apple assertion"))?;
                let attestation = items.pop().ok_or(Error("Apple attestation"))?;
                (
                    IssuerEvidenceV1::Apple {
                        attestation,
                        key_binding_assertion,
                    },
                    Some((key_id, counter)),
                )
            }
            _ => return Err(Error("configured platform differs")),
        };
        let evidence = KagemushaWalletEvidenceV1 {
            digest: originals.digest(body, kind).map_err(Error)?,
            time_ms: evidence_time_ms,
            facts: u32::try_from(integer(&value, "facts")?).map_err(|_| Error("fact range"))?,
            os_patch_level: u32::try_from(integer(&value, "os_patch_level")?)
                .map_err(|_| Error("patch range"))?,
            vendor_patch_level: u32::try_from(integer(&value, "vendor_patch_level")?)
                .map_err(|_| Error("patch range"))?,
            boot_patch_level: u32::try_from(integer(&value, "boot_patch_level")?)
                .map_err(|_| Error("patch range"))?,
        };
        evidence
            .validate_enrollment_for_kind(kind)
            .map_err(|_| Error("evidence facts"))?;
        // These are facts of the actual retained adapters, beyond the generic Model minimum.
        // Reserved fact bit 9 is already rejected by the shared evidence validator.
        let required = if kind.is_android() {
            KAGEMUSHA_WALLET_FACT_REVOCATION_LIST_CLEAR_V1
        } else {
            KAGEMUSHA_WALLET_FACT_APP_ATTEST_PRODUCTION_V1
        };
        let allowed = kind.required_enrollment_facts()
            | required
            | if kind.is_android() {
                KAGEMUSHA_WALLET_FACT_PATCH_POLICY_MET_V1
            } else {
                0
            };
        if evidence.facts & required != required
            || evidence.facts & !allowed != 0
            || digest(&value, "evidence_digest")? != evidence.digest
        {
            return Err(Error("evidence projection differs"));
        }
        Ok(EvidenceProjectionV1 {
            kind,
            evidence,
            originals,
            apple_counter,
            original_result,
        })
    }
}

#[cfg(test)]
#[path = "issuer_worker_tests.rs"]
mod tests;
