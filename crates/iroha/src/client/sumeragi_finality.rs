// Embedded-certificate finality transport; no alternate decoding or conversion.

const SUMERAGI_FINALITY_RESPONSE_MAX_BYTES: usize =
    2 * iroha_data_model::sumeragi_finality::MAX_FINALITY_BLOCK_BYTES + 4 * 1024 * 1024;

impl Client {
    /// Read current provider discovery and authenticate it against an independently selected block.
    ///
    /// The caller supplies its qualified native World schema and a fresh finality
    /// decision. Neither the endpoint nor this response can select those trust inputs.
    /// This returns no download token and grants no account spending authority.
    /// # Errors
    /// Invalid selectors, bounded transport/codec failure, stale or substituted
    /// native state, revoked admission, or a mismatched/invalid provider advert.
    pub fn get_provider_discovery(
        &self,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        native_schema: iroha_crypto::Hash,
        block: &iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock,
        now_unix_seconds: u64,
    ) -> Result<iroha_data_model::sorafs::provider_admission::discovery::VerifiedProviderDiscoveryV1>
    {
        let proof = self.read_provider_discovery_frame(provider, block)?;
        let verified = proof.verify(
            self.network_id,
            provider,
            native_schema,
            block,
            now_unix_seconds,
        )?;
        self.ensure_activation_evidence_deadline()?;
        Ok(verified)
    }

    /// Read the explicitly admitted account-download policy and current native token signer.
    /// The caller supplies its independently qualified schema and fresh certified decision.
    /// # Errors
    /// Refuses missing policy, expired/revoked custody, wrong exact scope, or bounded transport failure.
    pub fn get_account_read_provider_discovery(
        &self, provider: iroha_data_model::sorafs::capacity::ProviderId,
        native_schema: iroha_crypto::Hash,
        block: &iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock,
        now_unix_ms: u64,
    ) -> Result<iroha_data_model::sorafs::provider_admission::discovery::account_read::VerifiedAccountReadProviderV1>{
        let proof = self.read_provider_discovery_frame(provider, block)?;
        let verified = proof.verify_account_read(
            self.chain.as_ref(),
            self.network_id,
            provider,
            native_schema,
            block,
            now_unix_ms,
        )?;
        self.ensure_activation_evidence_deadline()?;
        Ok(verified)
    }

    /// Read current native `StreamToken` control for an independently selected signer binding.
    ///
    /// The caller supplies the complete expected binding, qualified World schema and fresh
    /// certified decision. This reuses the bounded provider-discovery transport and returns only
    /// authenticated control evidence. Unenrolled, expired and revoked custody remain readable;
    /// policy and revocation must be checked separately before enrollment or signing. No signing,
    /// enrollment, token, provider or account spending authority is granted by this read.
    ///
    /// # Errors
    /// Rejects invalid independent selectors before transport, exceeded request deadlines or
    /// response bounds, noncanonical evidence, wrong exact binding, stale/substituted control,
    /// and failed provider admission or advertisement verification.
    pub fn get_stream_token_custody_control(
        &self,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        expected_binding: &sorafs_manifest::signer::custody::SignerCustodyBindingV1,
        native_schema: iroha_crypto::Hash,
        block: &iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock,
        now_unix_ms: u64,
    ) -> Result<iroha_data_model::sorafs::provider_admission::discovery::stream_token_control::VerifiedStreamTokenCustodyControlV1>{
        use sorafs_manifest::signer::protocol::{SignerPurposeBindingV1, SignerRoleV1};
        expected_binding.validate()?;
        if expected_binding.chain_id != self.chain.to_string()
            || expected_binding.network_id != *self.network_id.as_bytes()
            || expected_binding.role != SignerRoleV1::StreamToken
            || expected_binding.purpose
                != (SignerPurposeBindingV1::StreamToken {
                    provider_id: *provider.as_bytes(),
                })
        {
            return Err(eyre!(
                "stream-token control requires an independent binding on this chain, network and provider"
            ));
        }
        let proof = self.read_provider_discovery_frame(provider, block)?;
        let verified = proof.verify_stream_token_custody_control(
            self.network_id,
            provider,
            native_schema,
            expected_binding,
            block,
            now_unix_ms,
        )?;
        self.ensure_activation_evidence_deadline()?;
        Ok(verified)
    }

    /// Read native custody presence or absence without requiring admission or an advertisement.
    ///
    /// The caller independently selects the exact owner, complete signer binding, qualified
    /// native World schema and fresh certified decision. An absent record is authenticated
    /// against the complete World; HTTP absence or failure never means unconfigured custody.
    /// This grants no enrollment, current-use, token or account spending authority.
    /// # Errors
    /// Invalid independent scope before dispatch, expired deadline, bounded transport/codec
    /// failure, concealed state, changed owner, substituted binding or native preimages.
    pub fn get_stream_token_custody_state(
        &self,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        expected_owner: &iroha_data_model::account::AccountId,
        expected_binding: &sorafs_manifest::signer::custody::SignerCustodyBindingV1,
        native_schema: iroha_crypto::Hash,
        block: &iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock,
    ) -> Result<
        iroha_data_model::sorafs::stream_token_custody::proof::VerifiedStreamTokenCustodyStateV1,
    > {
        use iroha_data_model::sorafs::stream_token_custody::proof::{
            MAX_STREAM_TOKEN_CUSTODY_PROOF_BYTES_V1, StreamTokenCustodyProofV1,
        };
        use sorafs_manifest::signer::protocol::{SignerPurposeBindingV1, SignerRoleV1};
        expected_binding.validate()?;
        block.verify_global_scope(self.network_id, self.chain.as_ref())?;
        if provider.as_bytes() == &[0; 32]
            || block.height() < 2
            || block.commitment().schedule.current.network_id != self.network_id
            || expected_binding.chain_id != self.chain.to_string()
            || expected_binding.network_id != *self.network_id.as_bytes()
            || expected_binding.role != SignerRoleV1::StreamToken
            || expected_binding.purpose
                != (SignerPurposeBindingV1::StreamToken {
                    provider_id: *provider.as_bytes(),
                })
        {
            return Err(eyre!(
                "custody state requires independently selected scope on this chain and network"
            ));
        }
        self.ensure_data_model_compatibility()?;
        let path = iroha_torii_shared::route_catalog::sorafs::STREAM_TOKEN_CUSTODY
            .path()
            .replace("{provider_id}", &hex::encode(provider.as_bytes()))
            .replace("{height}", &block.height().to_string());
        let response = self.send_activation_evidence_read(
            &path,
            MAX_STREAM_TOKEN_CUSTODY_PROOF_BYTES_V1,
            None,
            ActivationEvidenceReadAuth::Public,
        )?;
        let body = Self::bounded_norito_response_body(
            &response,
            StatusCode::OK,
            MAX_STREAM_TOKEN_CUSTODY_PROOF_BYTES_V1,
            "Failed to get native custody state",
        )?;
        let proof = StreamTokenCustodyProofV1::decode_frame(body)?;
        let verified = proof.verify(
            self.network_id,
            provider,
            expected_owner,
            expected_binding,
            native_schema,
            block,
        )?;
        self.ensure_activation_evidence_deadline()?;
        Ok(verified)
    }

    fn read_provider_discovery_frame(
        &self,
        provider: iroha_data_model::sorafs::capacity::ProviderId,
        block: &iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock,
    ) -> Result<iroha_data_model::sorafs::provider_admission::discovery::ProviderDiscoveryProofV1>
    {
        use iroha_data_model::sorafs::provider_admission::discovery::{
            MAX_PROVIDER_DISCOVERY_BYTES_V1, ProviderDiscoveryProofV1,
        };
        if provider.as_bytes() == &[0; 32]
            || block.height() < 2
            || block.commitment().schedule.current.network_id != self.network_id
        {
            return Err(eyre!(
                "provider discovery requires a nonzero provider and an independently verified block on this network"
            ));
        }
        self.ensure_data_model_compatibility()?;
        let path = iroha_torii_shared::route_catalog::sorafs::PROVIDER_DISCOVERY
            .path()
            .replace("{provider_id}", &hex::encode(provider.as_bytes()))
            .replace("{height}", &block.height().to_string());
        let response = self.send_activation_evidence_read(
            &path,
            MAX_PROVIDER_DISCOVERY_BYTES_V1,
            None,
            ActivationEvidenceReadAuth::Public,
        )?;
        let body = Self::bounded_norito_response_body(
            &response,
            StatusCode::OK,
            MAX_PROVIDER_DISCOVERY_BYTES_V1,
            "Failed to get provider discovery",
        )?;
        ProviderDiscoveryProofV1::decode_frame(body).map_err(Into::into)
    }

    /// Probe the original genesis tip under a caller-authenticated current genesis verifier.
    /// A successful node signature authenticates that node's observed genesis execution;
    /// callers requiring quorum readiness must collect independently selected nodes.
    ///
    /// # Errors
    /// Invalid independent inputs, elapsed deadline, transport, signature, root or instance mismatch.
    pub fn poll_sumeragi_genesis_readiness(
        &self,
        challenge: [u8; 32],
        expected_node: &iroha_model_base::peer::PeerId,
        trusted: &iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier,
        deadline: std::time::Instant,
    ) -> Result<GenesisFinalityReadiness> {
        if challenge == [0; 32]
            || expected_node.public_key().try_algorithm()? != iroha_crypto::Algorithm::BlsNormal
        {
            return Err(eyre!(
                "genesis readiness requires a nonzero challenge and selected BLS node"
            ));
        }
        let deadline = self
            .http_transport
            .deadline()
            .map_or(deadline, |prior| prior.min(deadline));
        Self::ensure_genesis_readiness_deadline(deadline)?;
        let client = self.with_request_deadline(deadline);
        client.ensure_data_model_compatibility()?;
        let path = iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY_ATTESTATION
            .path()
            .replace("{height}", "1");
        let response = client.send_activation_evidence_read(
            &path,
            SUMERAGI_FINALITY_RESPONSE_MAX_BYTES,
            Some(challenge),
            ActivationEvidenceReadAuth::Public,
        )?;
        Self::ensure_genesis_readiness_deadline(deadline)?;
        if response.status() != StatusCode::OK {
            let failure = Self::decode_finality_attestation_failure(
                &response,
                1,
                challenge,
                expected_node,
                self.network_id,
            )?;
            Self::ensure_genesis_readiness_deadline(deadline)?;
            return Ok(GenesisFinalityReadiness::NotReady(failure.reason));
        }
        let attestation: iroha_data_model::sumeragi_finality::SumeragiFinalityAttestation =
            Self::decode_canonical_norito_response(
                &response,
                SUMERAGI_FINALITY_RESPONSE_MAX_BYTES,
                "sumeragi.genesis_readiness.read",
            )?;
        attestation.verify()?;
        let body = &attestation.body;
        if body.challenge != challenge
            || body.node_id != *expected_node
            || body.network_id != self.network_id
            || body.status.instance != trusted.instance().0
            || body.finality_proof.height() != 1
        {
            return Err(eyre!(
                "genesis readiness differs from selected request, network or instance"
            ));
        }
        let mut candidate = trusted.clone();
        candidate.verify(&body.genesis_finality_proof)?;
        candidate.verify_same_decision(&body.genesis_finality_proof, &body.finality_proof)?;
        Self::ensure_genesis_readiness_deadline(deadline)?;
        Ok(GenesisFinalityReadiness::Ready(Box::new(attestation)))
    }
    /// Read and authenticate the selected node's fresh current-consensus tip statement.
    /// The caller's independently anchored verifier must authenticate the embedded chain.
    ///
    /// # Errors
    /// Bounded transport/codec failure, malformed proof, invalid node signature or wrong request binding.
    pub fn get_sumeragi_finality_attestation(
        &self,
        height: NonZeroU64,
        challenge: [u8; 32],
        expected_node: &iroha_model_base::peer::PeerId,
    ) -> Result<iroha_data_model::sumeragi_finality::SumeragiFinalityAttestation> {
        if challenge == [0; 32] {
            return Err(eyre!("finality challenge must be nonzero"));
        }
        self.ensure_data_model_compatibility()?;
        let path = iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY_ATTESTATION
            .path()
            .replace("{height}", &height.get().to_string());
        let response = self.send_activation_evidence_read(
            &path,
            SUMERAGI_FINALITY_RESPONSE_MAX_BYTES,
            Some(challenge),
            ActivationEvidenceReadAuth::Public,
        )?;
        if response.status() != StatusCode::OK {
            let failure = Self::decode_finality_attestation_failure(
                &response,
                height.get(),
                challenge,
                expected_node,
                self.network_id,
            )?;
            if let Some(progress) = failure.tip_mismatch {
                return Err(BridgeFinalityAttestationTipMismatch::from_response(
                    progress,
                    height,
                    challenge,
                    expected_node,
                    self.network_id,
                )?
                .into());
            }
            return Err(eyre!(
                "current finality attestation unavailable: {}",
                failure.reason.as_str()
            ));
        }
        let attestation: iroha_data_model::sumeragi_finality::SumeragiFinalityAttestation =
            Self::decode_canonical_norito_response(
                &response,
                SUMERAGI_FINALITY_RESPONSE_MAX_BYTES,
                "sumeragi.finality_attestation.read",
            )?;
        attestation.verify()?;
        if attestation.body.challenge != challenge
            || attestation.body.node_id != *expected_node
            || attestation.body.network_id != self.network_id
            || attestation.body.status.committed_height != height.get()
        {
            return Err(eyre!(
                "current finality attestation differs from exact request bindings"
            ));
        }
        self.ensure_activation_evidence_deadline()?;
        Ok(attestation)
    }

    /// Fetch one canonical current proof without choosing a trust root from the response.
    /// A structural certificate check does not authenticate its candidate committee.
    ///
    /// # Errors
    /// Bounded transport/codec error, wrong height or malformed current certificate.
    pub fn get_sumeragi_finality_proof(
        &self,
        height: NonZeroU64,
    ) -> Result<iroha_data_model::sumeragi_finality::SumeragiFinalityProof> {
        self.ensure_data_model_compatibility()?;
        let path = iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY
            .path()
            .replace("{height}", &height.get().to_string());
        let response = self.send_activation_evidence_read(
            &path,
            SUMERAGI_FINALITY_RESPONSE_MAX_BYTES,
            None,
            ActivationEvidenceReadAuth::Public,
        )?;
        let proof: iroha_data_model::sumeragi_finality::SumeragiFinalityProof =
            Self::decode_canonical_norito_response(
                &response,
                SUMERAGI_FINALITY_RESPONSE_MAX_BYTES,
                "sumeragi.finality_proof.read",
            )?;
        if proof.height() != height.get() {
            return Err(eyre!(
                "current finality proof differs from requested height"
            ));
        }
        proof.decode_checked()?;
        self.ensure_activation_evidence_deadline()?;
        Ok(proof)
    }

    /// Fetch this child's compact registration using the retained owner listener token.
    ///
    /// The bounded response must match this client's child network and chain label and the
    /// caller's independently selected parent/dataspace scope. This does not establish trust:
    /// compare the entire registration with the retained signed-genesis registration before
    /// authorizing it on the parent. No private genesis or transaction body is transported.
    ///
    /// # Errors
    /// Invalid scope, HTTP/media/deadline/size failure, malformed registration, or scope,
    /// network, or child-chain substitution.
    pub fn get_private_root_registration(
        &self,
        expected_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    ) -> Result<iroha_data_model::private_dataspace::PrivateDataspaceRegistration> {
        use iroha_data_model::{
            block::consensus::SumeragiRootScope,
            private_dataspace::{
                MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES, PrivateDataspaceRegistration,
            },
        };
        if !matches!(expected_scope, SumeragiRootScope::Dataspace { .. })
            || expected_scope.validate().is_err()
        {
            return Err(eyre!(
                "private-root registration requires an exact private scope"
            ));
        }
        self.ensure_data_model_compatibility()?;
        let response = self.send_activation_evidence_read(
            iroha_torii_shared::route_catalog::sumeragi::PRIVATE_ROOT_REGISTRATION.path(),
            MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES,
            None,
            ActivationEvidenceReadAuth::Public,
        )?;
        let body = Self::bounded_norito_response_body(
            &response,
            StatusCode::OK,
            MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES,
            "Failed to get private root registration",
        )?;
        let registration = PrivateDataspaceRegistration::decode(body)?;
        if registration.child_network_id != self.network_id
            || registration.child_chain_id != self.chain
            || registration.scope != expected_scope
        {
            return Err(eyre!(
                "private-root registration substitutes the selected child or scope"
            ));
        }
        self.ensure_activation_evidence_deadline()?;
        Ok(registration)
    }

    /// Fetch one bounded compact anchor using this child's retained owner listener token.
    ///
    /// This checks the exact selected parent/dataspace, child network, and claimed height.
    /// Transport grants no finality authority: apply the result to the independently authorized
    /// `PrivateDataspaceAnchorState` to authenticate its quorum and contiguous ancestry.
    ///
    /// # Errors
    /// Invalid scope/genesis height, HTTP/media/deadline/size failure, malformed public
    /// certificate, private-body witness, or requested binding substitution.
    pub fn get_private_root_anchor(
        &self,
        expected_scope: iroha_data_model::block::consensus::SumeragiRootScope,
        height: NonZeroU64,
    ) -> Result<iroha_data_model::private_dataspace::PrivateDataspaceAnchor> {
        use iroha_data_model::{
            block::consensus::SumeragiRootScope,
            private_dataspace::{MAX_PRIVATE_DATASPACE_ANCHOR_BYTES, PrivateDataspaceAnchor},
        };
        let SumeragiRootScope::Dataspace {
            parent_network_id,
            dataspace_id,
        } = expected_scope
        else {
            return Err(eyre!("private-root anchor requires an exact private scope"));
        };
        if expected_scope.validate().is_err() || height.get() < 2 {
            return Err(eyre!(
                "private-root anchor requires a nonzero dataspace and non-genesis height"
            ));
        }
        self.ensure_data_model_compatibility()?;
        let path = iroha_torii_shared::route_catalog::sumeragi::PRIVATE_ROOT_ANCHOR
            .path()
            .replace("{height}", &height.get().to_string());
        let response = self.send_activation_evidence_read(
            &path,
            MAX_PRIVATE_DATASPACE_ANCHOR_BYTES,
            None,
            ActivationEvidenceReadAuth::Public,
        )?;
        let body = Self::bounded_norito_response_body(
            &response,
            StatusCode::OK,
            MAX_PRIVATE_DATASPACE_ANCHOR_BYTES,
            "Failed to get private root anchor",
        )?;
        let anchor = PrivateDataspaceAnchor::decode(body)?;
        if anchor.child_network_id != self.network_id
            || anchor.parent_network_id != parent_network_id
            || anchor.dataspace_id != dataspace_id
            || anchor.height()? != height.get()
        {
            return Err(eyre!(
                "private-root anchor substitutes the selected child, scope, or height"
            ));
        }
        self.ensure_activation_evidence_deadline()?;
        Ok(anchor)
    }

    /// Fetch one bounded private-root record proof from its global parent.
    ///
    /// The response is structurally validated and bound to this client's parent network,
    /// the exact dataspace, and the requested carrier height. Transport does not authenticate
    /// finality: the recipient must independently authenticate the parent block, then call
    /// `proof.verify(dataspace_id, &verified_parent_block)` before trusting the record.
    ///
    /// # Errors
    /// Invalid selector, transport or media-type failure, oversized/noncanonical proof,
    /// malformed record, or substituted parent network, dataspace, or carrier height.
    pub fn get_private_dataspace_record_proof(
        &self,
        dataspace_id: iroha_model_base::topology::DataSpaceId,
        height: NonZeroU64,
    ) -> Result<iroha_data_model::private_dataspace::PrivateDataspaceRecordProof> {
        use iroha_data_model::private_dataspace::{
            MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES, PrivateDataspaceRecordProof,
        };
        if dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL || height.get() < 2 {
            return Err(eyre!(
                "private-root record proof requires a nonzero dataspace and non-genesis carrier"
            ));
        }
        self.ensure_data_model_compatibility()?;
        let path = iroha_torii_shared::route_catalog::sumeragi::PRIVATE_DATASPACE_RECORD_PROOF
            .path()
            .replace("{dataspace_id}", &dataspace_id.as_u64().to_string())
            .replace("{height}", &height.get().to_string());
        let response = self.send_activation_evidence_read(
            &path,
            MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES,
            None,
            ActivationEvidenceReadAuth::Public,
        )?;
        let body = Self::bounded_norito_response_body(
            &response,
            StatusCode::OK,
            MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES,
            "Failed to get private dataspace record proof",
        )?;
        let proof = PrivateDataspaceRecordProof::decode(body)?;
        if proof.parent_network_id != self.network_id
            || proof.parent_height != height.get()
            || proof.record.dataspace_id != dataspace_id
        {
            return Err(eyre!(
                "private-root record proof substitutes the requested parent, dataspace, or height"
            ));
        }
        self.ensure_activation_evidence_deadline()?;
        Ok(proof)
    }

    /// Fetch and admit the immediate successor into the caller's independently anchored prefix.
    ///
    /// # Errors
    /// Fetch failure, invalid certificate, wrong committee or discontinuous certified chain.
    pub fn get_next_sumeragi_finality_proof(
        &self,
        height: NonZeroU64,
        verifier: &mut iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier,
    ) -> Result<iroha_data_model::sumeragi_finality::SumeragiFinalityProof> {
        let proof = self.get_sumeragi_finality_proof(height)?;
        let mut candidate = verifier.clone();
        candidate.verify(&proof)?;
        self.ensure_activation_evidence_deadline()?;
        *verifier = candidate;
        Ok(proof)
    }
}
