// Exact owner-issued AMX consent, authenticated at the caller's selected bank decision.

impl Client {
    /// Read an exact direct AMX debit approval through this context's async transport.
    ///
    /// The selected relay must be this client's account. The caller supplies independently
    /// pinned bank finality and the qualified native World schema; no server root or status
    /// authenticates consent. This proves a historical grant only. Native Prepare rechecks
    /// the current permission before escrow, including revocation after this read.
    ///
    /// The current proof contains the complete World hash inventory. The relay therefore
    /// needs an explicit `CanReadAllLedgerData` grant, checked again before disclosure;
    /// the exact debit grant does not imply this read authority. A scoped proof is separate.
    ///
    /// # Errors
    /// Wrong network, account, scope or proof; unavailable current cut; noncanonical response;
    /// exceeded original transport deadline, body bound or local decoding resources.
    pub async fn get_amx_debit_approval_state_async(
        &self,
        expected_approval: &iroha_data_model::sumeragi_amx::AmxDebitApprovalV1,
        expected_relay: &iroha_data_model::account::AccountId,
        native_schema: iroha_crypto::Hash,
        block: &iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock,
    ) -> Result<iroha_data_model::sumeragi_amx::VerifiedAmxDebitApprovalV1> {
        use iroha_data_model::sumeragi_amx::{
            AmxDebitApprovalProofV1,
            approval_proof::{
                MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1, MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1,
            },
        };
        expected_approval.validate()?;
        if expected_relay != &self.account
            || expected_approval.participant_network != self.network_id
            || block.commitment().schedule.current.network_id != self.network_id
            || block.root_scope()
                != (iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
                    parent_network_id: expected_approval.global_network,
                    dataspace_id: expected_approval.dataspace,
                })
            || block.height() < 2
        {
            return Err(eyre!(
                "AMX approval read differs from this relay's pinned bank root"
            ));
        }
        self.ensure_activation_evidence_deadline()?;
        self.ensure_query_compatibility().await?;
        if norito::canonical_frame_len(expected_approval)?
            > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1
        {
            return Err(eyre!("AMX approval request exceeds its canonical bound"));
        }
        let body = norito::encode_canonical(expected_approval)?;
        let path = iroha_torii_shared::route_catalog::contracts_and_verification_keys::AMX_DEBIT_APPROVAL_PROOF_POST
            .path().replace("{height}", &block.height().to_string());
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
                .max_response_bytes(MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1);
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
                MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1,
                "Failed to read AMX debit approval",
            )?;
            let proof = AmxDebitApprovalProofV1::decode_frame(body)?;
            let verified = proof.verify(expected_approval, expected_relay, native_schema, block)?;
            self.ensure_activation_evidence_deadline()?;
            return Ok(verified);
        }
    }
}
