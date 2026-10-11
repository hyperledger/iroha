//! Exact signed POST provider for scoped native authority originals.

use super::*;
use iroha_torii_shared::authority_originals::{
    NATIVE_AUTHORITY_ORIGINALS_MAX_BYTES_V1, NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1,
    NativeAuthorityOriginalsRequestV1, NativeAuthorityOriginalsSelectorV1,
    decode_unverified_native_authority_originals_v1, native_authority_originals_request_digests_v1,
};

/// Unverified original transport bytes; this pair grants no installed-node or ledger authority.
#[derive(Debug, Clone)]
pub struct NativeAuthorityOriginalsReadV1 {
    /// The exact canonical request signed by the configured native account holder.
    pub request_wire: Vec<u8>,
    /// Original bounded canonical response, awaiting independent four-node/cut verification.
    pub response_wire: Vec<u8>,
}

impl Client {
    /// Read one exact selected authority-originals family using this native account signer.
    ///
    /// This constructs the canonical request itself using the configured genesis-derived
    /// network, exact typed selector and fresh nonzero entropy. Torii separately requires
    /// that holder's current native `CanReadAllLedgerData` grant. The listener token is a
    /// distinct configured transport credential; an FI application bearer is rejected.
    /// The configured provider path prefix is preserved in the final URI.
    /// The canonical POST signs the entire original body plus exact URI/timestamp/nonce.
    /// Its body-derived challenge is echoed once in the finality header and native statement.
    ///
    /// This is data-only: callers must authenticate all four independently selected node
    /// statements with that derived challenge, full current finality and World schema,
    /// complete fixed keys, exact original values and independently admitted catalog.
    /// The retained request preimage must be compared, not replaced with a query challenge.
    ///
    /// # Errors
    /// Invalid native selector/challenge/root/default credentials, transport/signature failure,
    /// denied read root, non-success, changed correlation or noncanonical/oversized private wire.
    pub fn read_native_authority_originals_wire(
        &self,
        selector: NativeAuthorityOriginalsSelectorV1,
        challenge: [u8; 32],
    ) -> Result<NativeAuthorityOriginalsReadV1> {
        let request = NativeAuthorityOriginalsRequestV1 {
            network_id: self.network_id,
            challenge,
            selector,
        };
        let request_wire = request.canonical_wire().map_err(|_| {
            eyre!("native authority originals request is not bounded canonical data")
        })?;
        let (_, derived_challenge) =
            native_authority_originals_request_digests_v1(&request_wire)
                .map_err(|_| eyre!("native authority originals request digest was refused"))?;
        if self.torii_url.scheme() != "https"
            || !self.torii_url.path().ends_with('/')
            || self.torii_url.query().is_some()
            || self.torii_url.fragment().is_some()
            || !self.torii_url.username().is_empty()
            || self.torii_url.password().is_some()
        {
            return Err(eyre!(
                "native private authority originals provider requires a canonical HTTPS root ending in a slash"
            ));
        }
        let mut names = std::collections::HashSet::new();
        for name in self.headers.keys() {
            if !names.insert(name.to_ascii_lowercase()) {
                return Err(eyre!(
                    "native private authority originals provider rejects duplicate default headers"
                ));
            }
            if ![
                "x-api-token",
                "x-dataspace-id",
                "user-agent",
                "accept",
                "content-type",
                "cache-control",
            ]
            .iter()
            .any(|allowed| name.eq_ignore_ascii_case(allowed))
            {
                return Err(eyre!(
                    "native private authority originals provider rejects non-native default credential/header context"
                ));
            }
        }
        let mut native_client = self.clone();
        native_client.headers.retain(|name, _| {
            !name.eq_ignore_ascii_case("accept") && !name.eq_ignore_ascii_case("content-type")
        });
        let url = join_torii_url(&self.torii_url, NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1);
        let response = native_client.send_builder(
            native_client
                .account_signed_request(HttpMethod::POST, url, request_wire.clone())?
                .header("Accept", APPLICATION_NORITO)
                .header("Content-Type", APPLICATION_NORITO)
                .header(
                    "X-Iroha-Finality-Challenge",
                    &hex::encode(derived_challenge),
                )
                .max_response_bytes(NATIVE_AUTHORITY_ORIGINALS_MAX_BYTES_V1),
        )?;
        if response.status() != StatusCode::OK {
            return Err(eyre!(
                "native authority originals read returned HTTP {}",
                response.status()
            ));
        }
        let derived_hex = hex::encode(derived_challenge);
        let mut response_challenges = response
            .headers()
            .get_all("X-Iroha-Finality-Challenge")
            .iter();
        if let Some(value) = response_challenges.next()
            && (response_challenges.next().is_some()
                || value.to_str().ok() != Some(derived_hex.as_str()))
        {
            return Err(eyre!(
                "native authority originals response finality header changed exact derived challenge"
            ));
        }
        let media_type = Self::response_content_type(&response)
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if !media_type.eq_ignore_ascii_case(APPLICATION_NORITO) {
            return Err(eyre!(
                "native authority originals response requires canonical Norito content type"
            ));
        }
        let response_wire = response.into_body();
        let original =
            decode_unverified_native_authority_originals_v1(&response_wire).map_err(|_| {
                eyre!("native authority originals response is not exact bounded canonical data")
            })?;
        original.validate_request_correlation(&request)
            .map_err(|_| eyre!("native authority originals response changed exact signed request or private shape"))?;
        // A self-signed node statement supplies structure only; installed selection is external.
        original.attestation.verify().map_err(|_| {
            eyre!("native authority originals statement has invalid structure/signature")
        })?;
        Ok(NativeAuthorityOriginalsReadV1 {
            request_wire,
            response_wire,
        })
    }
}

#[cfg(test)]
#[path = "authority_originals/tests.rs"]
mod tests;
