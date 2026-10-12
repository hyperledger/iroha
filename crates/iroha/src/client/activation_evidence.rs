// Strict activation-evidence readers kept out of the main client module's source budget.

use crate::data_model::block::{
    decode_framed_signed_block, proofs::AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
};
use iroha_data_model::query::CommittedTransaction;

#[derive(Clone, Copy)]
enum ActivationEvidenceReadAuth {
    Public,
    Account,
}

/// One authenticated-ready result or an unsigned non-success observation.
#[derive(Debug)]
#[expect(
    variant_size_differences,
    reason = "The attestation is already boxed; keep the small failure reason allocation-free."
)]
pub enum GenesisFinalityReadiness {
    /// The original genesis and node independently authenticate this fresh statement.
    Ready(Box<iroha_data_model::sumeragi_finality::SumeragiFinalityAttestation>),
    /// A closed failure reason. Only explicit startup reasons permit bounded retries.
    NotReady(iroha_torii_shared::bridge_attestation::FinalityAttestationFailureReason),
}

/// A request-bound observation that the selected finality tip is still changing.
///
/// This is progress information, not a finality proof. A bounded caller may take a
/// fresh snapshot; unrelated HTTP errors and invalid attestations never produce it.
#[derive(Debug, Clone)]
pub struct BridgeFinalityAttestationTipMismatch {
    response: iroha_torii_shared::bridge_finality::BridgeFinalityAttestationTipMismatchV1,
}

impl BridgeFinalityAttestationTipMismatch {
    /// Validate progress against the exact request and independently selected identity.
    ///
    /// # Errors
    /// Rejects malformed progress or a different height, challenge, node, or network.
    pub fn from_response(
        response: iroha_torii_shared::bridge_finality::BridgeFinalityAttestationTipMismatchV1,
        height: NonZeroU64,
        challenge: [u8; 32],
        expected_node: &iroha_model_base::peer::PeerId,
        network: NetworkId,
    ) -> Result<Self> {
        if !response.matches(height.get(), challenge, expected_node, network) {
            return Err(eyre!(
                "finality tip progress differs from exact request bindings"
            ));
        }
        Ok(Self { response })
    }

    /// Return the exact validated request and observed height bindings.
    #[must_use]
    pub const fn response(
        &self,
    ) -> &iroha_torii_shared::bridge_finality::BridgeFinalityAttestationTipMismatchV1 {
        &self.response
    }
}

impl std::fmt::Display for BridgeFinalityAttestationTipMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "finality tip is changing: requested {}, applied {}, consensus status {}",
            self.response.requested_height,
            self.response.applied_height,
            self.response.status_height
        )
    }
}

impl std::error::Error for BridgeFinalityAttestationTipMismatch {}

impl Client {
    /// Decode the sole bounded failure schema with exact HTTP and request bindings.
    fn decode_finality_attestation_failure(
        response: &Response<Vec<u8>>,
        height: u64,
        challenge: [u8; 32],
        expected_node: &iroha_model_base::peer::PeerId,
        network_id: NetworkId,
    ) -> Result<iroha_torii_shared::bridge_attestation::FinalityAttestationFailure> {
        use iroha_torii_shared::bridge_attestation::{
            FINALITY_ATTESTATION_FAILURE_CODE, FINALITY_ATTESTATION_FAILURE_MAX_BYTES,
        };
        let status = response.status();
        if !matches!(
            status,
            StatusCode::CONFLICT
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::INTERNAL_SERVER_ERROR
        ) {
            return Err(eyre!(
                "unexpected finality attestation HTTP status {status}"
            ));
        }
        let content_type = exact_single_response_header(response, "content-type")?;
        if !content_type.eq_ignore_ascii_case(APPLICATION_NORITO) {
            return Err(eyre!(
                "finality failure requires exact application/x-norito"
            ));
        }
        let bytes = Self::bounded_norito_response_body(
            response,
            status,
            FINALITY_ATTESTATION_FAILURE_MAX_BYTES,
            "Failed to get finality attestation",
        )?;
        let envelope: iroha_torii_shared::ErrorEnvelope = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .wrap_err("failed to decode canonical finality failure envelope")?;
        if envelope.code() != FINALITY_ATTESTATION_FAILURE_CODE {
            return Err(eyre!(
                "finality error code does not establish a typed observation"
            ));
        }
        let mut details = envelope
            .details
            .ok_or_else(|| eyre!("finality failure omitted its detail"))?;
        let failure = details
            .finality_attestation_failure
            .take()
            .ok_or_else(|| eyre!("finality failure omitted its exact request bindings"))?;
        if !details.is_empty() {
            return Err(eyre!("finality failure carries conflicting error details"));
        }
        if failure.reason.http_status_code() != status.as_u16()
            || !failure.matches(height, challenge, expected_node, network_id)
        {
            return Err(eyre!(
                "finality failure differs from exact request/status bindings"
            ));
        }
        Ok(failure)
    }

    fn bounded_norito_response_body<'a>(
        response: &'a Response<Vec<u8>>,
        expected_status: StatusCode,
        maximum: usize,
        context: &'static str,
    ) -> Result<&'a [u8]> {
        if response.body().len() > maximum {
            return Err(eyre!(
                "{context}: response exceeds the {maximum}-byte limit"
            ));
        }
        if response.status() != expected_status {
            return Err(ResponseReport::with_msg(context, response)
                .unwrap_or_else(core::convert::identity)
                .into());
        }
        let content_type_values = response.headers().get_all(http::header::CONTENT_TYPE);
        let mut content_types = content_type_values.iter();
        let content_type = content_types
            .next()
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if content_types.next().is_some() {
            return Err(eyre!(
                "{context}: response carries multiple Content-Type headers"
            ));
        }
        if !Self::is_norito_content_type(content_type) {
            return Err(eyre!(
                "{context}: invalid content-type `{content_type}` (expected application/x-norito)"
            ));
        }
        if response.body().is_empty() {
            return Err(eyre!("{context}: response body is empty"));
        }
        Ok(response.body())
    }

    /// Decode one bounded, exact canonical Norito success response.
    pub(crate) fn decode_canonical_norito_response<T>(
        response: &Response<Vec<u8>>,
        maximum: usize,
        operation: &'static str,
    ) -> crate::Result<T>
    where
        T: norito::core::NoritoSerialize,
        for<'de> T: norito::core::NoritoDeserialize<'de>,
    {
        // Preserve the existing HTTP/media/body checks before decoding a success payload.
        // The canonical decoder captures its original cause before its scopes unwind.
        let body = Self::bounded_norito_response_body(response, StatusCode::OK, maximum, operation)
            .map_err(|error| crate::Error::Decode {
                operation,
                details: error.to_string(),
            })?;
        norito::decode_canonical_for_admission(body, norito::canonical_decode_limits(body.len()))
            .map_err(|source| {
                crate::Error::CanonicalDecode(Box::new(crate::CanonicalDecodeFailure {
                    operation,
                    source,
                }))
            })
    }

    fn canonical_norito_get_request(
        &self,
        path: &str,
        maximum: usize,
        auth: ActivationEvidenceReadAuth,
    ) -> Result<DefaultRequestBuilder> {
        let url = join_torii_url(&self.torii_url, path);
        let mut headers = match auth {
            ActivationEvidenceReadAuth::Public => self.headers_without_canonical_account_auth(),
            ActivationEvidenceReadAuth::Account => {
                self.account_signed_headers(&HttpMethod::GET, &url, &[])?
            }
        };
        headers.retain(|name, _| {
            !name.eq_ignore_ascii_case("accept")
                && !name.eq_ignore_ascii_case("content-type")
                && !name.eq_ignore_ascii_case("x-iroha-finality-challenge")
        });
        let mut builder = DefaultRequestBuilder::new(HttpMethod::GET, url)
            .with_transport(self.http_transport.clone())
            .headers(headers)
            .header("Accept", APPLICATION_NORITO)
            .max_response_bytes(maximum);
        if self.torii_request_timeout != Duration::ZERO {
            builder = builder.timeout(self.torii_request_timeout);
        }
        Ok(builder)
    }

    // Only an explicit operation deadline authorizes repeated reads. A one-shot
    // client still exposes backpressure immediately. Never retry transport,
    // authentication, codec or proof failures, and never resend a transaction.
    fn send_activation_evidence_read(
        &self,
        path: &str,
        maximum: usize,
        challenge: Option<[u8; 32]>,
        auth: ActivationEvidenceReadAuth,
    ) -> Result<Response<Vec<u8>>> {
        loop {
            self.ensure_activation_evidence_deadline()?;
            // Account authentication is constructed inside the retry loop: a 429
            // retry must carry a fresh nonce for the same exact-network GET.
            let mut request = self.canonical_norito_get_request(path, maximum, auth)?;
            if let Some(challenge) = challenge {
                request = request.header("X-Iroha-Finality-Challenge", &hex::encode(challenge));
            }
            let response = self.send_builder(request)?;
            if response.status() != StatusCode::TOO_MANY_REQUESTS {
                return Ok(response);
            }
            let Some(deadline) = self.http_transport.deadline() else {
                return Ok(response);
            };
            let minimum_delay = Duration::from_millis(100);
            let delay = transaction_wait::retry_after_delay(&response)?
                .unwrap_or(minimum_delay)
                .max(minimum_delay);
            if deadline.saturating_duration_since(std::time::Instant::now()) <= delay {
                return Err(eyre!(
                    "activation evidence deadline cannot accommodate HTTP 429 Retry-After"
                ));
            }
            std::thread::sleep(delay);
        }
    }

    fn ensure_activation_evidence_deadline(&self) -> Result<()> {
        if self
            .http_transport
            .deadline()
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return Err(eyre!("activation evidence deadline elapsed"));
        }
        Ok(())
    }

    /// Fetch canonical block wire bound to an independently authenticated execution commitment.
    ///
    /// The returned bytes are accepted only when the route yields bounded Norito, the block
    /// round-trips to the byte-identical canonical [`SignedBlock`] wire, its requested height and
    /// block hash match, its proposal inputs and execution context match the header commitments, its full typed output
    /// cache is consistent, and the supplied successful, signed transaction belongs to this
    /// client's `NetworkId` and verifies through its exact Network input-index join and separate
    /// input/output proofs.
    ///
    /// The required commitment must come from an independently verified, externally anchored
    /// native finality proof for this carrier. Its exact wire hash and length authenticate results
    /// and internal invocation outputs, which the consensus header hash alone does not bind. This reader verifies
    /// that binding; it does not establish finality or trust in a caller-supplied commitment.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, status, media-type, size, decode, canonicality, height,
    /// hash, result-shape, Merkle-cache, execution-commitment, transaction-result, or inclusion-proof
    /// failures.
    pub fn get_canonical_executed_block_wire(
        &self,
        height: NonZeroU64,
        committed: &CommittedTransaction,
        execution_commitment: &iroha_data_model::sumeragi_finality::ExecutionCommitment,
    ) -> Result<Vec<u8>> {
        self.ensure_data_model_compatibility()?;
        let path = iroha_torii_shared::route_catalog::core::LEDGER_EXECUTED_BLOCK_WIRE
            .path()
            .replace("{height}", &height.get().to_string());
        let response = self.send_activation_evidence_read(
            &path,
            AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
            None,
            ActivationEvidenceReadAuth::Account,
        )?;
        let body = Self::bounded_norito_response_body(
            &response,
            StatusCode::OK,
            AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1,
            "Failed to get canonical executed block wire",
        )?;
        let block = norito::core::with_decode_limits_scope(
            norito::canonical_decode_limits(body.len()),
            || decode_framed_signed_block(body),
        )
        .wrap_err("Failed to decode canonical executed block wire")?;
        if block.header().height() != height {
            return Err(eyre!(
                "executed block height {} does not match requested height {height}",
                block.header().height()
            ));
        }
        let block_hash = block.hash();
        if &block_hash != committed.block_hash() {
            return Err(eyre!(
                "executed block hash does not match the committed transaction carrier hash"
            ));
        }
        if !block.has_results() {
            return Err(eyre!("executed block response has no execution results"));
        }
        block
            .validate_proposal_commitments()
            .map_err(|error| eyre!("executed block proposal commitments are invalid: {error}"))?;
        block
            .validate_output_merkle_cache()
            .map_err(|error| eyre!("executed block output Merkle cache is invalid: {error}"))?;
        if committed.result().is_err() {
            return Err(eyre!(
                "committed transaction carries a rejected execution result"
            ));
        }
        if !committed.verify_inclusion_in_authenticated_execution(&block, execution_commitment) {
            return Err(eyre!(
                "committed transaction does not verify against the authenticated execution commitment"
            ));
        }
        if !committed.verify_selective_in_authenticated_execution(
            &self.network_id,
            &block.header(),
            execution_commitment,
        ) {
            return Err(eyre!(
                "committed transaction does not match the authenticated client network and execution"
            ));
        }
        self.ensure_activation_evidence_deadline()?;
        // The framed decoder already proved exact canonical equality of these bytes.
        Ok(response.into_body())
    }

    fn ensure_genesis_readiness_deadline(deadline: std::time::Instant) -> Result<()> {
        if std::time::Instant::now() >= deadline {
            return Err(eyre!("genesis readiness deadline elapsed"));
        }
        Ok(())
    }
}
