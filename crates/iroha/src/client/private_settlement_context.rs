// The current full-World context transport requires all-ledger read authority; selected
// bank permissions are insufficient. Scoped authenticated context reads remain unsupported.
// Bounded transport of an untrusted exact current-cut private context.
impl Client {
    /// Fetch original public context for every exact selected private pool at one cut at the requested current height.
    ///
    /// This returns untrusted data. The caller must verify the returned World proof, native
    /// assignment and key records against independently pinned Global finality and schema.
    /// The server requires current `CanReadAllLedgerData`: the complete World hash snapshot
    /// discloses unrelated row identities and low-entropy values. Selected-dataspace grants
    /// are insufficient. Persist authenticated original context before proving; this route
    /// does not archive older cuts.
    /// # Errors
    /// Noncanonical selector/response, unavailable exact cut, authorization failure, original
    /// request deadline/response cap or local decoding resource refusal.
    pub async fn get_private_settlement_context_async(
        &self,
        height: std::num::NonZeroU64,
        selectors: iroha_data_model::nexus::PrivateSettlementContextRequestV1,
    ) -> Result<iroha_data_model::nexus::PrivateSettlementContextsProofV1> {
        use iroha_data_model::{
            nexus::{
                PRIVATE_SETTLEMENT_CONTEXT_REQUEST_MAX_BYTES_V1, PrivateSettlementContextsProofV1,
            },
            sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_BYTES_V1,
        };
        if height.get() < 2 {
            return Err(eyre!("private context requires a non-genesis cut"));
        }
        selectors.validate().map_err(eyre::Report::new)?;
        self.ensure_activation_evidence_deadline()?;
        self.ensure_query_compatibility().await?;
        if norito::canonical_frame_len(&selectors)?
            > PRIVATE_SETTLEMENT_CONTEXT_REQUEST_MAX_BYTES_V1
        {
            return Err(eyre!("private context selector exceeds its fixed bound"));
        }
        let body = norito::encode_canonical(&selectors)?;
        let path = iroha_torii_shared::route_catalog::private_settlement::CONTEXT
            .path()
            .replace("{height}", &height.to_string());
        let url = join_torii_url(&self.torii_url, &path);
        loop {
            self.ensure_activation_evidence_deadline()?;
            let mut headers = self.account_signed_headers(&HttpMethod::POST, &url, &body)?;
            headers.retain(|name, _| {
                !name.eq_ignore_ascii_case("accept")
                    && !name.eq_ignore_ascii_case("content-type")
                    && !name.eq_ignore_ascii_case("x-iroha-finality-challenge")
            });
            let mut request = DefaultRequestBuilder::new(HttpMethod::POST, url.clone())
                .with_transport(self.http_transport.clone())
                .headers(headers)
                .header("Accept", APPLICATION_NORITO)
                .header("Content-Type", APPLICATION_NORITO)
                .body(body.clone())
                .max_response_bytes(MAX_WORLD_STATE_SNAPSHOT_BYTES_V1);
            if self.torii_request_timeout != Duration::ZERO {
                request = request.timeout(self.torii_request_timeout);
            }
            let response = self.dispatch_request(request.build()?).await?;
            if let Some(delay) = self.activation_evidence_retry_delay(&response)? {
                tokio::time::sleep(delay).await;
                continue;
            }
            let body = Self::bounded_norito_response_body(
                &response,
                StatusCode::OK,
                MAX_WORLD_STATE_SNAPSHOT_BYTES_V1,
                "Failed to read private context",
            )?;
            let proof = PrivateSettlementContextsProofV1::decode_frame(body)?;
            self.ensure_activation_evidence_deadline()?;
            return Ok(proof);
        }
    }
}
