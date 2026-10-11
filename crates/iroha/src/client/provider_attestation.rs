//! Exact signed provider-attestation transport; native eligibility belongs to the caller's verifier.
use super::*;
use iroha_data_model::musubi::{
    MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1,
    MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleVerificationAttestationV1,
};

const REQUEST_MAX: usize = 4096;
const RESPONSE_MAX: usize = MUSUBI_MAX_PROVIDER_BUNDLE_ATTESTATION_CANONICAL_BYTES_V1;
const LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    RESPONSE_MAX,
    RESPONSE_MAX,
    RESPONSE_MAX,
    RESPONSE_MAX * 8,
    64,
);

impl Client {
    /// Read one exact already-retained provider attestation with canonical account authentication.
    ///
    /// The response's original signature, network and exact archive/order/provider key are checked.
    /// A signature authenticates the statement, not current provider eligibility, registry inclusion,
    /// or successful publication. The caller must join it to independently authenticated native
    /// state. `None` means only this live endpoint returned no retained item; it proves no absence.
    /// One request uses the original deadline, with no retries, signing of transactions or fallback.
    /// # Errors
    /// Refuses invalid selection, elapsed deadline, bounded transport/codec failure or substitution.
    pub fn get_sorafs_provider_attestation(
        &self,
        key: MusubiProviderBundleAttestationKeyV1,
    ) -> Result<Option<MusubiProviderBundleVerificationAttestationV1>> {
        key.validate()?;
        self.ensure_activation_evidence_deadline()?;
        norito::with_decode_limits_scope(LIMITS, || {
            let length = norito::canonical_frame_len(&key)?;
            if length > REQUEST_MAX {
                return Err(eyre!("provider attestation request exceeds bound"));
            }
            let body =
                norito::core::to_bytes_bounded(&key, length).map_err(|error| match error {
                    norito::core::BoundedEncodeError::Serialization(error)
                        if error.decode_resource_error().is_some() =>
                    {
                        eyre::Report::from(error)
                    }
                    error => eyre::Report::from(error),
                })?;
            let url = join_torii_url(
                &self.torii_url,
                iroha_torii_shared::route_catalog::sorafs::PROVIDER_ATTESTATION
                    .path()
                    .trim_start_matches('/'),
            );
            // Admit the bounded raw response before transport allocation. Its decoded graph
            // is charged separately by the same inherited Norito scope.
            norito::core::reserve_decode_allocation(RESPONSE_MAX)?;
            let response = self.send_builder(
                self.account_signed_request(HttpMethod::POST, url, body)?
                    .replace_header(http::header::CONTENT_TYPE, "application/x-norito")
                    .replace_header(http::header::ACCEPT, "application/x-norito")
                    .max_response_bytes(RESPONSE_MAX),
            )?;
            self.ensure_activation_evidence_deadline()?;
            if response.status() == StatusCode::NO_CONTENT {
                if !response.body().is_empty() {
                    return Err(eyre!("provider attestation empty response has a body"));
                }
                return Ok(None);
            }
            let body = Self::bounded_norito_response_body(
                &response,
                StatusCode::OK,
                RESPONSE_MAX,
                "provider attestation read failed",
            )?;
            let attestation: MusubiProviderBundleVerificationAttestationV1 =
                norito::decode_canonical(body)?;
            if attestation.key() != key || attestation.payload.binding.network_id != self.network_id
            {
                return Err(eyre!("provider attestation selection differs"));
            }
            attestation.verify(&attestation.payload.binding)?;
            self.ensure_activation_evidence_deadline()?;
            Ok(Some(attestation))
        })
    }
}

#[cfg(test)]
#[path = "provider_attestation_tests.rs"]
mod tests;
