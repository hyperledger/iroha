//! Exact unsigned observations for one AMX approval proof read request.
//!
//! These failures only permit another bounded read. They never authenticate an
//! observed height, a permission, a balance, or a monetary outcome.

use iroha_crypto::Hash;
use iroha_data_model::{account::AccountId, sumeragi_amx::AmxDebitApprovalV1};
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};

/// Sole error-envelope code for a classified AMX approval read refusal.
pub const AMX_APPROVAL_READ_FAILURE_CODE: &str = "amx_approval_read_failure";
/// Maximum canonical failure envelope accepted before any decoding.
pub const AMX_APPROVAL_READ_FAILURE_MAX_BYTES: usize = 4096;

/// A local read refusal, distinct from a completed proof rejection.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito(tag = "kind", content = "details", deny_unknown_fields)]
#[norito_schema(name = "iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1")]
pub enum AmxApprovalReadReasonV1 {
    /// The applied State height differs from the independently selected request.
    CutChanged,
    /// The original finite read or worker admission could not complete.
    Capacity,
}
impl AmxApprovalReadReasonV1 {
    /// Required HTTP status; no generic status alone establishes retryability.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::CutChanged => 409,
            Self::Capacity => 429,
        }
    }
}

/// A bounded, request-bound, unsigned acquisition observation.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1")]
pub struct AmxApprovalReadFailureV1 {
    /// Digest of the exact canonical approval request, including both root identities.
    pub approval_hash: Hash,
    /// Digest of the exact canonical account header; not a claim of authentication.
    pub relay_header_hash: Hash,
    /// Height selected from the caller's independently authenticated bank finality.
    pub requested_height: u64,
    /// Closed local reason.
    pub reason: AmxApprovalReadReasonV1,
    /// Applied State height, present only for a differing-cut observation.
    pub observed_height: Option<u64>,
    /// Minimum read retry delay from the original finite egress owner, if supplied.
    pub retry_after_ms: Option<u64>,
}
impl AmxApprovalReadFailureV1 {
    /// Construct an unsigned observation bound to the exact request identity.
    /// # Errors
    /// Canonical request encoding refused or the reason/payload shape is invalid.
    pub fn new(
        approval: &AmxDebitApprovalV1,
        relay: &AccountId,
        requested_height: u64,
        reason: AmxApprovalReadReasonV1,
        observed_height: Option<u64>,
    ) -> Result<Self, String> {
        let approval_hash =
            Hash::new(norito::encode_canonical(approval).map_err(|error| error.to_string())?);
        let relay_header_hash = Hash::new(
            relay
                .to_canonical_hex()
                .map_err(|error| error.to_string())?,
        );
        let value = Self {
            approval_hash,
            relay_header_hash,
            requested_height,
            reason,
            observed_height,
            retry_after_ms: None,
        };
        if !value.is_valid() {
            return Err("invalid AMX approval acquisition observation".into());
        }
        Ok(value)
    }
    /// Check the exact shape without assigning authority to the observed height.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.requested_height >= 2
            && match (self.reason, self.observed_height) {
                (AmxApprovalReadReasonV1::CutChanged, Some(observed)) => {
                    observed > 0
                        && observed != self.requested_height
                        && self.retry_after_ms.is_none()
                }
                (AmxApprovalReadReasonV1::Capacity, None) => true,
                _ => false,
            }
    }
    /// Encode this observation as the sole typed detail in the normal error envelope.
    #[must_use]
    pub fn into_error_envelope(self) -> crate::ErrorEnvelope {
        crate::ErrorEnvelope::new(
            AMX_APPROVAL_READ_FAILURE_CODE,
            "AMX approval read could not acquire its requested cut.",
        )
        .with_details(crate::ErrorDetails {
            amx_approval_read_failure: Some(self),
            ..crate::ErrorDetails::default()
        })
    }
    /// Decode one canonical failure and bind it to the exact original request.
    ///
    /// Callers must independently require one Content-Type header. A returned value
    /// permits only bounded read scheduling; it does not establish proof absence.
    /// # Errors
    /// Wrong status/media/size/code/shape, extra details, or mismatched request binding.
    pub fn decode_response(
        status: u16,
        content_type: &str,
        bytes: &[u8],
        approval: &AmxDebitApprovalV1,
        relay: &AccountId,
        height: u64,
    ) -> Result<Self, String> {
        if !matches!(status, 409 | 429)
            || content_type != "application/x-norito"
            || bytes.is_empty()
            || bytes.len() > AMX_APPROVAL_READ_FAILURE_MAX_BYTES
        {
            return Err("invalid AMX approval failure HTTP boundary".into());
        }
        let envelope: crate::ErrorEnvelope = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(|error| error.to_string())?;
        if envelope.code() != AMX_APPROVAL_READ_FAILURE_CODE {
            return Err("unclassified AMX approval failure".into());
        }
        let mut details = envelope
            .details
            .ok_or("AMX approval failure omitted request bindings")?;
        let failure = details
            .amx_approval_read_failure
            .take()
            .ok_or("AMX approval failure omitted its typed observation")?;
        if !details.is_empty()
            || !failure.is_valid()
            || failure.reason.http_status() != status
            || failure.requested_height != height
            || failure.relay_header_hash
                != Hash::new(
                    relay
                        .to_canonical_hex()
                        .map_err(|error| error.to_string())?,
                )
            || failure.approval_hash
                != Hash::new(norito::encode_canonical(approval).map_err(|error| error.to_string())?)
        {
            return Err("AMX approval failure differs from the exact request".into());
        }
        Ok(failure)
    }
}
impl std::fmt::Display for AmxApprovalReadFailureV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AMX approval read {:?} at requested height {}, observed {:?}",
            self.reason, self.requested_height, self.observed_height
        )
    }
}
impl std::error::Error for AmxApprovalReadFailureV1 {}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};

    fn request() -> (AmxDebitApprovalV1, AccountId) {
        let relay = AccountId::new(
            KeyPair::from_seed(vec![91; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let dataspace = DataSpaceId::new(7);
        let approval = AmxDebitApprovalV1 {
            global_network: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"global"),
            )),
            participant_network: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"bank"),
            )),
            participant_instance: [7; 32],
            dataspace,
            transaction_id: [9; 32],
            debited_asset: AssetId::with_scope(
                AssetDefinitionId::derive_from_components(
                    DomainId::try_new("bank", "universal").unwrap(),
                    "cash".parse().unwrap(),
                ),
                relay.clone(),
                AssetBalanceScope::Dataspace(dataspace),
            ),
        };
        (approval, relay)
    }

    #[test]
    fn exact_failure_roundtrips_and_rejects_nonbinding_or_unclassified_envelopes() {
        let (approval, relay) = request();
        for (reason, observed) in [
            (AmxApprovalReadReasonV1::CutChanged, Some(1)),
            (AmxApprovalReadReasonV1::Capacity, None),
        ] {
            let failure =
                AmxApprovalReadFailureV1::new(&approval, &relay, 2, reason, observed).unwrap();
            let bytes = norito::encode_canonical(&failure.into_error_envelope()).unwrap();
            assert_eq!(
                AmxApprovalReadFailureV1::decode_response(
                    reason.http_status(),
                    "application/x-norito",
                    &bytes,
                    &approval,
                    &relay,
                    2
                )
                .unwrap(),
                failure
            );
            assert_eq!(
                norito::json::from_str::<AmxApprovalReadFailureV1>(
                    &norito::json::to_json(&failure).unwrap()
                )
                .unwrap(),
                failure
            );
            for (status, media, height) in [
                (503, "application/x-norito", 2),
                (reason.http_status(), "application/json", 2),
                (reason.http_status(), "application/x-norito", 3),
            ] {
                assert!(
                    AmxApprovalReadFailureV1::decode_response(
                        status, media, &bytes, &approval, &relay, height
                    )
                    .is_err()
                );
            }
            let mut wrong = failure;
            wrong.relay_header_hash = Hash::new(b"another signer");
            let bytes = norito::encode_canonical(&wrong.into_error_envelope()).unwrap();
            assert!(
                AmxApprovalReadFailureV1::decode_response(
                    reason.http_status(),
                    "application/x-norito",
                    &bytes,
                    &approval,
                    &relay,
                    2
                )
                .is_err()
            );
            let mut extra = failure.into_error_envelope();
            extra.details.as_mut().unwrap().layer = Some("unexpected".into());
            let bytes = norito::encode_canonical(&extra).unwrap();
            assert!(
                AmxApprovalReadFailureV1::decode_response(
                    reason.http_status(),
                    "application/x-norito",
                    &bytes,
                    &approval,
                    &relay,
                    2
                )
                .is_err()
            );
        }
        assert!(
            AmxApprovalReadFailureV1::new(
                &approval,
                &relay,
                2,
                AmxApprovalReadReasonV1::CutChanged,
                Some(2)
            )
            .is_err()
        );
        assert!(
            AmxApprovalReadFailureV1::new(
                &approval,
                &relay,
                2,
                AmxApprovalReadReasonV1::Capacity,
                Some(1)
            )
            .is_err()
        );
    }
}
