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
    /// A typed `AmxApprovalReadFailureV1` is an unsigned request-bound observation,
    /// not a proof; only an explicit caller deadline may schedule another read.
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
        const OPERATION: &str = "amx.debit_approval";
        expected_approval
            .validate()
            .map_err(|error| crate::Error::InvalidRequest {
                operation: OPERATION,
                details: error.to_string(),
            })?;
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
            return Err(crate::Error::ResponseBinding {
                operation: OPERATION,
                field: "relay, network and independently pinned bank root",
            }
            .into());
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
        {
            self.ensure_activation_evidence_deadline()?;
            let mut headers = self
                .account_signed_headers(&HttpMethod::POST, &url, &body)
                .map_err(|error| crate::Error::RequestSigning {
                    operation: OPERATION,
                    details: error.to_string(),
                })?;
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
            // Return one exact unsigned acquisition observation. The caller owns
            // the absolute retry deadline; generic 429/503 and proof errors are terminal.
            if matches!(
                response.status(),
                StatusCode::CONFLICT | StatusCode::TOO_MANY_REQUESTS
            ) {
                let media =
                    exact_single_response_header(&response, "content-type").map_err(|error| {
                        crate::Error::Decode {
                            operation: OPERATION,
                            details: error.to_string(),
                        }
                    })?;
                let failure = iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1::decode_response(
                    response.status().as_u16(), &media, response.body(), expected_approval,
                    expected_relay, block.height(),
                 ).map_err(|error| crate::Error::Decode {
                    operation: OPERATION,
                    details: error.to_string(),
                })?;
                return Err(failure.into());
            }
            // Keep original HTTP status and bounded owned response for operational
            // permission/listener diagnosis. It is not a proof or a capacity witness.
            if response.status() != StatusCode::OK {
                return Err(crate::error::http_error(OPERATION, response).into());
            }
            let body = Self::bounded_norito_response_body(
                &response,
                StatusCode::OK,
                MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1,
                "Failed to read AMX debit approval",
            )
            .map_err(|error| crate::Error::Decode {
                operation: OPERATION,
                details: error.to_string(),
            })?;
            let proof = norito::core::classify_decode_attempt(|| {
                AmxDebitApprovalProofV1::decode_frame(body)
            })
            .map_err(|source| {
                crate::Error::CanonicalDecode(Box::new(crate::CanonicalDecodeFailure {
                    operation: OPERATION,
                    source,
                }))
            })?;
            let verified = proof.verify(expected_approval, expected_relay, native_schema, block)?;
            self.ensure_activation_evidence_deadline()?;
            return Ok(verified);
        }
    }
}
