#[derive(Clone)]
struct ProviderIngestBrokerSignerResolver {
    session: Arc<BrokerSession>,
    resolver_binding: ProviderBindingWireV1,
    resolver_metadata_digest: [u8; 32],
    signer_binding: ProviderBindingWireV1,
    signer_metadata_digest: [u8; 32],
    expected_signer_binding: sorafs_node::ProviderIngestCompletionSignerBindingV1,
}
impl_broker_debug_fields!(ProviderIngestBrokerSignerResolver as value {} => finish_non_exhaustive);
impl ProviderIngestBrokerSignerResolver {
    fn live_state(
        &self,
    ) -> Result<
        sorafs_node::provider_ingest_runtime::ProviderIngestRuntimeProviderQualificationV1,
        BrokerError,
    > {
        let payload = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)?;
        let result = self.session.call(
            &self.resolver_binding,
            self.resolver_metadata_digest,
            OPERATION_QUALIFY_V1,
            payload,
            false,
        )?;
        let observed = self
            .session
            .decode_result::<ProviderIngestResolverQualificationWireV1>(&result)?;
        let expected = qualification_from_binding(&self.resolver_binding)?;
        let expected_signer_wire = self
            .resolver_binding
            .provider_ingest_signer_binding
            .as_ref()
            .ok_or(BrokerError::BindingMismatch)?;
        if observed.revision != expected.revision
            || observed.policy_digest != expected.policy_digest
            || &observed.signer_binding != expected_signer_wire
            || observed.signer_binding.to_binding()? != self.expected_signer_binding
        {
            self.session.poison();
            return Err(BrokerError::StaleOrRevoked);
        }
        Ok(
            sorafs_node::provider_ingest_runtime::ProviderIngestRuntimeProviderQualificationV1::new(
                expected.revision,
                expected.policy_digest,
            ),
        )
    }
    fn resolve_blocking(
        &self,
        context: sorafs_node::ProviderIngestCompletionSignerResolutionContextV1,
    ) -> Result<
        Option<Arc<dyn sorafs_node::ProviderIngestCompletionSignerV1>>,
        sorafs_node::ProviderIngestCompletionSignerResolverErrorV1,
    > {
        if !context.is_valid()
            || !self
                .expected_signer_binding
                .qualification
                .matches_authority(&context.expected_authority.completion_signer)
            || self.expected_signer_binding.qualification.signer_policy
                != context.expected_authority.signer_policy
        {
            return Err(sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Rejected);
        }
        self.live_state().map_err(provider_ingest_resolver_error)?;
        let wire_context = provider_ingest_signer_context_to_wire(&context)
            .map_err(provider_ingest_resolver_error)?;
        let payload = encode_canonical(
            &ProviderIngestResolveSignerRequestWireV1 {
                context: wire_context,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .map_err(provider_ingest_resolver_error)?;
        let result = self
            .session
            .call(
                &self.resolver_binding,
                self.resolver_metadata_digest,
                OPERATION_PROVIDER_INGEST_RESOLVE_SIGNER_V1,
                payload,
                false,
            )
            .map_err(provider_ingest_resolver_error)?;
        let resolved = self
            .session
            .decode_result::<ProviderIngestResolveSignerResultWireV1>(&result)
            .map_err(provider_ingest_resolver_error)?;
        self.live_state().map_err(provider_ingest_resolver_error)?;
        if !resolved.eligible {
            return Ok(None);
        }
        Ok(Some(Arc::new(ProviderIngestBrokerCompletionSigner {
            session: Arc::clone(&self.session),
            resolver_binding: self.resolver_binding.clone(),
            resolver_metadata_digest: self.resolver_metadata_digest,
            signer_binding: self.signer_binding.clone(),
            signer_metadata_digest: self.signer_metadata_digest,
            expected_binding: self.expected_signer_binding.clone(),
            resolution_context: context,
        })))
    }
}
impl crate::sorafs_provider_ingest_runtime::ProviderIngestGovernedSignerResolverRuntimeV1
    for ProviderIngestBrokerSignerResolver
{
    fn runtime_handle(&self) -> &str {
        &self.resolver_binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::provider_ingest_runtime::ProviderIngestRuntimeProviderQualificationV1,
        sorafs_node::ProviderIngestCompletionSignerResolverErrorV1,
    > {
        self.live_state().map_err(provider_ingest_resolver_error)
    }
    fn signer_binding(
        &self,
    ) -> Result<
        sorafs_node::ProviderIngestCompletionSignerBindingV1,
        sorafs_node::ProviderIngestCompletionSignerResolverErrorV1,
    > {
        self.live_state().map_err(provider_ingest_resolver_error)?;
        Ok(self.expected_signer_binding.clone())
    }
    fn check_readiness(
        &self,
    ) -> Result<(), sorafs_node::ProviderIngestCompletionSignerResolverErrorV1> {
        self.live_state().map_err(provider_ingest_resolver_error)?;
        let payload = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)
            .map_err(provider_ingest_resolver_error)?;
        let result = self
            .session
            .call(
                &self.resolver_binding,
                self.resolver_metadata_digest,
                OPERATION_PROVIDER_INGEST_RESOLVER_READINESS_V1,
                payload,
                false,
            )
            .map_err(provider_ingest_resolver_error)?;
        self.session
            .decode_result::<()>(&result)
            .map_err(provider_ingest_resolver_error)?;
        self.live_state().map_err(provider_ingest_resolver_error)?;
        Ok(())
    }
    fn resolve(
        &self,
        context: sorafs_node::ProviderIngestCompletionSignerResolutionContextV1,
    ) -> sorafs_node::ProviderIngestFutureV1<
        '_,
        Result<
            Option<Arc<dyn sorafs_node::ProviderIngestCompletionSignerV1>>,
            sorafs_node::ProviderIngestCompletionSignerResolverErrorV1,
        >,
    > {
        let resolver = self.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    resolver.resolve_blocking(context)
                }),
            )
            .await
            .unwrap_or(Err(
                sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Unavailable,
            ))
        })
    }
}
#[derive(Clone)]
struct ProviderIngestBrokerCompletionSigner {
    session: Arc<BrokerSession>,
    resolver_binding: ProviderBindingWireV1,
    resolver_metadata_digest: [u8; 32],
    signer_binding: ProviderBindingWireV1,
    signer_metadata_digest: [u8; 32],
    expected_binding: sorafs_node::ProviderIngestCompletionSignerBindingV1,
    resolution_context: sorafs_node::ProviderIngestCompletionSignerResolutionContextV1,
}
impl ProviderIngestBrokerCompletionSigner {
    fn live_resolver_state(&self) -> Result<(), BrokerError> {
        let payload = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)?;
        let result = self.session.call(
            &self.resolver_binding,
            self.resolver_metadata_digest,
            OPERATION_QUALIFY_V1,
            payload,
            false,
        )?;
        let observed = self
            .session
            .decode_result::<ProviderIngestResolverQualificationWireV1>(&result)?;
        let expected = qualification_from_binding(&self.resolver_binding)?;
        if observed.revision != expected.revision
            || observed.policy_digest != expected.policy_digest
            || observed.signer_binding.to_binding()? != self.expected_binding
        {
            self.session.poison();
            return Err(BrokerError::StaleOrRevoked);
        }
        Ok(())
    }
    fn sign_blocking(
        &self,
        transaction_payload: &iroha_data_model::transaction::TransactionPayload,
    ) -> Result<
        iroha_data_model::transaction::SignedTransaction,
        sorafs_node::ProviderIngestCompletionSignerErrorV1,
    > {
        ensure_provider_ingest_completion_payload(
            transaction_payload,
            &self.resolution_context,
            &self.session.network_id,
        )
        .map_err(provider_ingest_signer_error)?;
        self.live_resolver_state()
            .map_err(provider_ingest_signer_error)?;
        let max_signed = usize::try_from(
            self.signer_binding
                .provider_ingest_max_signed_transaction_bytes
                .ok_or(sorafs_node::ProviderIngestCompletionSignerErrorV1::Rejected)?,
        )
        .map_err(|_| sorafs_node::ProviderIngestCompletionSignerErrorV1::Rejected)?;
        let transaction_payload_bytes = encode_canonical(transaction_payload, max_signed)
            .map_err(provider_ingest_signer_error)?;
        let context = provider_ingest_signer_context_to_wire(&self.resolution_context)
            .map_err(provider_ingest_signer_error)?;
        let payload = encode_canonical(
            &ProviderIngestSignRequestWireV1 {
                context,
                transaction_payload: transaction_payload_bytes,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .map_err(provider_ingest_signer_error)?;
        let result = self
            .session
            .call(
                &self.signer_binding,
                self.signer_metadata_digest,
                OPERATION_PROVIDER_INGEST_SIGN_V1,
                payload,
                false,
            )
            .map_err(provider_ingest_signer_error)?;
        let signed = {
            let _scope = result.enter_decode_admission();
            let decoded = self
                .session
                .decode_result::<ProviderIngestSignResultWireV1>(&result)
                .map_err(provider_ingest_signer_error)?;
            decode_canonical::<iroha_data_model::transaction::SignedTransaction>(
                &decoded.signed_transaction,
                max_signed,
            )
            .map_err(provider_ingest_signer_error)?
        };
        self.live_resolver_state()
            .map_err(provider_ingest_signer_error)?;
        if signed.payload() != transaction_payload {
            self.session.poison();
            return Err(sorafs_node::ProviderIngestCompletionSignerErrorV1::Rejected);
        }
        if ensure_provider_ingest_completion_transaction(
            &signed,
            &self.resolution_context,
            &self.session.network_id,
        )
        .is_err()
        {
            self.session.poison();
            return Err(sorafs_node::ProviderIngestCompletionSignerErrorV1::Rejected);
        }
        Ok(signed)
    }
}
impl sorafs_node::ProviderIngestCompletionSignerV1 for ProviderIngestBrokerCompletionSigner {
    fn runtime_handle(&self) -> &str {
        &self.expected_binding.runtime_handle
    }
    fn authority(&self) -> &iroha_data_model::account::AccountId {
        &self.resolution_context.expected_authority.completion_signer
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::ProviderIngestCompletionSignerQualificationV1,
        sorafs_node::ProviderIngestCompletionSignerErrorV1,
    > {
        Ok(self.expected_binding.qualification.clone())
    }
    fn signer_policy(
        &self,
    ) -> iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1 {
        self.expected_binding.qualification.signer_policy
    }
    fn current_eligibility(
        &self,
    ) -> Result<
        iroha_data_model::sorafs::pin_registry::ProviderIngestCompletionSignerPolicyV1,
        sorafs_node::ProviderIngestCompletionSignerErrorV1,
    > {
        // The runtime contract requires this path to be a non-blocking
        // local snapshot. The broker revalidates the exact live policy
        // atomically inside every resolve/sign request.
        Ok(self.expected_binding.qualification.signer_policy)
    }
    fn sign(
        &self,
        payload: iroha_data_model::transaction::TransactionPayload,
    ) -> sorafs_node::ProviderIngestFutureV1<
        '_,
        Result<
            iroha_data_model::transaction::SignedTransaction,
            sorafs_node::ProviderIngestCompletionSignerErrorV1,
        >,
    > {
        let signer = self.clone();
        Box::pin(async move {
            crate::panic_recovery::join_recoverable(
                crate::panic_recovery::spawn_blocking_recoverable(move || {
                    signer.sign_blocking(&payload)
                }),
            )
            .await
            .unwrap_or(Err(
                sorafs_node::ProviderIngestCompletionSignerErrorV1::Unavailable,
            ))
        })
    }
}
#[derive(Clone)]
struct ProviderIngestBrokerCheckpointStore {
    session: Arc<BrokerSession>,
    binding: ProviderBindingWireV1,
    metadata_digest: [u8; 32],
    checkpoint_max_bytes: u64,
}
impl_broker_debug_fields!(ProviderIngestBrokerCheckpointStore as value {} => finish_non_exhaustive);
impl ProviderIngestBrokerCheckpointStore {
    fn live_qualification(
        &self,
    ) -> Result<sorafs_node::ProviderIngestCheckpointProviderQualificationV1, BrokerError> {
        let payload = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)?;
        let result = provider_call!(self, call, OPERATION_QUALIFY_V1, payload, false,)?;
        let qualification = self
            .session
            .decode_result::<QualificationResultWireV1>(&result)?;
        let expected = qualification_from_binding(&self.binding)?;
        if qualification.revision != expected.revision
            || qualification.policy_digest != expected.policy_digest
        {
            self.session.poison();
            return Err(BrokerError::StaleOrRevoked);
        }
        Ok(
            sorafs_node::ProviderIngestCheckpointProviderQualificationV1::new(
                expected.revision,
                expected.policy_digest,
            ),
        )
    }
    fn load_latest_raw(
        &self,
    ) -> Result<Option<sorafs_node::ProviderIngestSealedCheckpointRecordV1>, BrokerError> {
        let payload = encode_canonical(
            &CHECKPOINT_LOAD_REQUEST_VERSION_V1,
            MAX_PROVIDER_INGEST_CHECKPOINT_FRAME_BYTES_V1,
        )?;
        let result = provider_call!(
            self,
            call,
            OPERATION_PROVIDER_INGEST_CHECKPOINT_LOAD_V1,
            payload,
            false,
        )?;
        let _scope = result.enter_decode_admission();
        let record_bytes = self.session.decode_result::<Option<Vec<u8>>>(&result)?;
        let checkpoint_limit =
            usize::try_from(self.checkpoint_max_bytes).map_err(|_| BrokerError::Protocol)?;
        record_bytes
            .map(|bytes| {
                reserve_external_canonical_decode(bytes.len(), checkpoint_limit)?;
                sorafs_node::ProviderIngestSealedCheckpointRecordV1::from_canonical_bytes(
                    &bytes,
                    self.checkpoint_max_bytes,
                )
                .map_err(|_| BrokerError::Protocol)
            })
            .transpose()
            .inspect_err(|_| self.session.poison())
    }
}
impl sorafs_node::ProviderIngestCheckpointRuntimeV1 for ProviderIngestBrokerCheckpointStore {
    fn handle(&self) -> &str {
        &self.binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::ProviderIngestCheckpointProviderQualificationV1,
        sorafs_node::ProviderIngestCheckpointExternalErrorV1,
    > {
        self.live_qualification()
            .map_err(provider_ingest_checkpoint_error)
    }
    fn load_latest(
        &self,
    ) -> Result<
        Option<sorafs_node::ProviderIngestSealedCheckpointRecordV1>,
        sorafs_node::ProviderIngestCheckpointExternalErrorV1,
    > {
        self.live_qualification()
            .map_err(provider_ingest_checkpoint_error)?;
        let record = self
            .load_latest_raw()
            .map_err(provider_ingest_checkpoint_error)?;
        self.live_qualification()
            .map_err(provider_ingest_checkpoint_error)?;
        Ok(record)
    }
    fn compare_and_swap_latest(
        &self,
        expected_revision: Option<[u8; 32]>,
        next: &sorafs_node::ProviderIngestSealedCheckpointRecordV1,
    ) -> Result<(), sorafs_node::ProviderIngestCheckpointExternalErrorV1> {
        if expected_revision == Some([0; 32]) || next.predecessor_revision != expected_revision {
            return Err(sorafs_node::ProviderIngestCheckpointExternalErrorV1::Rejected);
        }
        let next_record = next
            .to_canonical_bytes(self.checkpoint_max_bytes)
            .map_err(|_| sorafs_node::ProviderIngestCheckpointExternalErrorV1::Rejected)?;
        self.live_qualification()
            .map_err(provider_ingest_checkpoint_error)?;
        let current = self
            .load_latest_raw()
            .map_err(provider_ingest_checkpoint_error)?;
        let monotonic = current.as_ref().map_or_else(
            || {
                expected_revision.is_none()
                    && next.checkpoint_sequence == 1
                    && next.predecessor_revision.is_none()
                    && next.predecessor_checkpoint_digest.is_none()
            },
            |previous| {
                expected_revision == Some(previous.revision)
                    && previous
                        .checkpoint_sequence
                        .checked_add(1)
                        .is_some_and(|sequence| sequence == next.checkpoint_sequence)
                    && next.predecessor_revision == Some(previous.revision)
                    && next.predecessor_checkpoint_digest == Some(previous.checkpoint_digest)
            },
        );
        if !monotonic {
            return Err(sorafs_node::ProviderIngestCheckpointExternalErrorV1::Rejected);
        }
        let payload = encode_canonical(
            &ProviderIngestCheckpointCompareAndSwapRequestWireV1 {
                expected_revision,
                next_record,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .map_err(provider_ingest_checkpoint_error)?;
        provider_call!(
            self,
            call,
            OPERATION_PROVIDER_INGEST_CHECKPOINT_COMPARE_AND_SWAP_V1,
            payload,
            true,
        )
        .map_err(provider_ingest_checkpoint_error)
        .and_then(|result| {
            self.session.decode_result::<()>(&result).map_err(|_| {
                self.session.poison();
                sorafs_node::ProviderIngestCheckpointExternalErrorV1::Ambiguous
            })
        })?;
        let readback = self.load_latest_raw().map_err(|error| {
            self.session.poison();
            match error {
                BrokerError::StaleOrRevoked | BrokerError::Rejected => {
                    sorafs_node::ProviderIngestCheckpointExternalErrorV1::Rejected
                }
                _ => sorafs_node::ProviderIngestCheckpointExternalErrorV1::Ambiguous,
            }
        })?;
        self.live_qualification().map_err(|error| {
            self.session.poison();
            match error {
                BrokerError::StaleOrRevoked | BrokerError::Rejected => {
                    sorafs_node::ProviderIngestCheckpointExternalErrorV1::Rejected
                }
                _ => sorafs_node::ProviderIngestCheckpointExternalErrorV1::Ambiguous,
            }
        })?;
        if readback.as_ref() != Some(next) {
            self.session.poison();
            return Err(sorafs_node::ProviderIngestCheckpointExternalErrorV1::Ambiguous);
        }
        Ok(())
    }
}
#[derive(Clone)]
struct ProviderIngestBrokerRetentionAuthority {
    session: Arc<BrokerSession>,
    binding: ProviderBindingWireV1,
    metadata_digest: [u8; 32],
}
impl_broker_debug_fields!(ProviderIngestBrokerRetentionAuthority as value {} => finish_non_exhaustive);
impl ProviderIngestBrokerRetentionAuthority {
    fn expected_qualification(
        &self,
    ) -> Result<
        iroha_core::query::provider_ingest_finalized::
            ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1,
        BrokerError,
    >{
        let expected = qualification_from_binding(&self.binding)?;
        Ok(
            iroha_core::query::provider_ingest_finalized::
                ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1::new(
                    expected.revision,
                    expected.policy_digest,
                ),
        )
    }
    fn live_qualification(
        &self,
    ) -> Result<
        iroha_core::query::provider_ingest_finalized::
            ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1,
        BrokerError,
    >{
        let payload = encode_canonical(&(), MAX_OPERATION_FRAME_BYTES_V1)?;
        let result = provider_call!(self, call, OPERATION_QUALIFY_V1, payload, false,)?;
        let observed = self
            .session
            .decode_result::<QualificationResultWireV1>(&result)?;
        let expected = self.expected_qualification()?;
        if observed.revision != expected.revision()
            || observed.policy_digest != expected.policy_digest()
        {
            self.session.poison();
            return Err(BrokerError::StaleOrRevoked);
        }
        Ok(expected)
    }
    fn network_id_wire(&self, network_id: &NetworkId) -> Result<NetworkId, BrokerError> {
        if &self.session.network_id != network_id {
            return Err(BrokerError::BindingMismatch);
        }
        Ok(*network_id)
    }
    fn load_latest_raw(
        &self,
        network_id: &NetworkId,
    ) -> Result<
        Option<
            iroha_core::query::provider_ingest_finalized::
                ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
        >,
        BrokerError,
    >{
        let network_id = self.network_id_wire(network_id)?;
        let payload = encode_canonical(
            &ProviderIngestRetentionLoadRequestWireV1 { network_id },
            MAX_OPERATION_FRAME_BYTES_V1,
        )?;
        let result = provider_call!(
            self,
            call,
            OPERATION_PROVIDER_INGEST_RETENTION_LOAD_V1,
            payload,
            false,
        )?;
        let _scope = result.enter_decode_admission();
        let record_bytes = self.session.decode_result::<Option<Vec<u8>>>(&result)?;
        let record = record_bytes
            .map(|bytes| {
                if bytes.len() > MAX_PROVIDER_INGEST_RETENTION_APPROVAL_BYTES_V1 {
                    return Err(BrokerError::Protocol);
                }
                reserve_external_canonical_decode(
                    bytes.len(),
                    MAX_PROVIDER_INGEST_RETENTION_APPROVAL_BYTES_V1,
                )?;
                iroha_core::query::provider_ingest_finalized::
                    ProviderIngestFinalizedArchiveRetentionApprovalRecordV1::
                        from_canonical_bytes(&bytes)
                        .map_err(|_| BrokerError::Protocol)
            })
            .transpose()
            .inspect_err(|_| self.session.poison())?;
        if let Some(record) = &record {
            let expected = self.expected_qualification()?;
            let actual = record.authority_qualification();
            if actual != expected {
                self.session.poison();
                return Err(BrokerError::StaleOrRevoked);
            }
        }
        Ok(record)
    }
}
impl
    iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRetentionAuthorityV1
    for ProviderIngestBrokerRetentionAuthority
{
    fn handle(&self) -> &str {
        &self.binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        iroha_core::query::provider_ingest_finalized::
            ProviderIngestFinalizedArchiveRetentionAuthorityQualificationV1,
        iroha_core::query::provider_ingest_finalized::
            ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1,
    >{
        self.live_qualification()
            .map_err(provider_ingest_retention_error)
    }
    fn load_latest(
        &self,
        network_id: &NetworkId,
    ) -> Result<
        Option<
            iroha_core::query::provider_ingest_finalized::
                ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
        >,
        iroha_core::query::provider_ingest_finalized::
            ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1,
    >{
        self.live_qualification()
            .map_err(provider_ingest_retention_error)?;
        let record = self
            .load_latest_raw(network_id)
            .map_err(provider_ingest_retention_error)?;
        self.live_qualification()
            .map_err(provider_ingest_retention_error)?;
        Ok(record)
    }
    fn compare_and_swap_latest(
        &self,
        network_id: &NetworkId,
        expected_revision: Option<[u8; 32]>,
        next: &iroha_core::query::provider_ingest_finalized::
            ProviderIngestFinalizedArchiveRetentionApprovalRecordV1,
    ) -> Result<
        (),
        iroha_core::query::provider_ingest_finalized::
            ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1,
    >{
        use iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1 as Error;
        if expected_revision == Some([0; 32])
            || next.predecessor_revision() != expected_revision
            || next.authority_qualification()
                != self
                    .expected_qualification()
                    .map_err(provider_ingest_retention_error)?
        {
            return Err(Error::Rejected);
        }
        self.live_qualification()
            .map_err(provider_ingest_retention_error)?;
        let current = self
            .load_latest_raw(network_id)
            .map_err(provider_ingest_retention_error)?;
        let monotonic = current.as_ref().map_or_else(
            || {
                expected_revision.is_none()
                    && next.sequence() == 1
                    && next.predecessor_revision().is_none()
                    && next.predecessor_checkpoint_digest().is_none()
            },
            |previous| {
                previous.revision() == expected_revision.unwrap_or([0; 32])
                    && previous
                        .sequence()
                        .checked_add(1)
                        .is_some_and(|sequence| sequence == next.sequence())
                    && next.predecessor_revision() == Some(previous.revision())
                    && next.predecessor_checkpoint_digest()
                        == Some(previous.proposal().checkpoint_digest())
            },
        );
        if !monotonic {
            return Err(Error::Rejected);
        }
        let network_id = self
            .network_id_wire(network_id)
            .map_err(provider_ingest_retention_error)?;
        let next_record = next.to_canonical_bytes().map_err(|_| Error::Rejected)?;
        if next_record.len() > MAX_PROVIDER_INGEST_RETENTION_APPROVAL_BYTES_V1 {
            return Err(Error::Rejected);
        }
        let payload = encode_canonical(
            &ProviderIngestRetentionCompareAndSwapRequestWireV1 {
                network_id,
                expected_revision,
                next_record,
            },
            MAX_OPERATION_FRAME_BYTES_V1,
        )
        .map_err(provider_ingest_retention_error)?;
        provider_call!(
            self,
            call,
            OPERATION_PROVIDER_INGEST_RETENTION_COMPARE_AND_SWAP_V1,
            payload,
            true,
        )
        .map_err(provider_ingest_retention_error)
        .and_then(|result| {
            self.session.decode_result::<()>(&result).map_err(|_| {
                self.session.poison();
                Error::Ambiguous
            })
        })?;
        let readback = self.load_latest_raw(&network_id).map_err(|error| {
            self.session.poison();
            match error {
                BrokerError::StaleOrRevoked
                | BrokerError::BindingMismatch
                | BrokerError::Rejected => Error::Rejected,
                _ => Error::Ambiguous,
            }
        })?;
        self.live_qualification().map_err(|error| {
            self.session.poison();
            match error {
                BrokerError::StaleOrRevoked
                | BrokerError::BindingMismatch
                | BrokerError::Rejected => Error::Rejected,
                _ => Error::Ambiguous,
            }
        })?;
        if readback.as_ref() != Some(next) {
            self.session.poison();
            return Err(Error::Ambiguous);
        }
        Ok(())
    }
}
#[derive(Clone)]
struct ReputationBrokerRetentionAuthority {
    session: Arc<BrokerSession>,
    binding: ProviderBindingWireV1,
    metadata_digest: [u8; 32],
}
impl_broker_debug_fields!(ReputationBrokerRetentionAuthority as value {} => finish_non_exhaustive);
impl ReputationBrokerRetentionAuthority {
    fn expected_qualification(
        &self,
    ) -> Result<
        iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
        BrokerError,
    >{
        let expected = qualification_from_binding(&self.binding)?;
        Ok(
            iroha_core::query::reputation_finalized::
                ReputationFinalizedArchiveRetentionAuthorityQualificationV1::new(
                    expected.revision,
                    expected.policy_digest,
                ),
        )
    }
    fn live_qualification(
        &self,
    ) -> Result<
        iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
        BrokerError,
    >{
        let payload = encode_canonical(&(), MAX_REPUTATION_RETENTION_FRAME_BYTES_V1)?;
        let result = provider_call!(self, call, OPERATION_QUALIFY_V1, payload, false,)?;
        let observed = self
            .session
            .decode_result::<QualificationResultWireV1>(&result)?;
        let expected = self.expected_qualification()?;
        if observed.revision != expected.revision()
            || observed.policy_digest != expected.policy_digest()
        {
            self.session.poison();
            return Err(BrokerError::StaleOrRevoked);
        }
        Ok(expected)
    }
    fn network_id_wire(&self, network_id: &NetworkId) -> Result<NetworkId, BrokerError> {
        if &self.session.network_id != network_id {
            return Err(BrokerError::BindingMismatch);
        }
        Ok(*network_id)
    }
    fn load_latest_raw(
        &self,
        network_id: &NetworkId,
    ) -> Result<
        Option<
            iroha_core::query::reputation_finalized::
                ReputationFinalizedArchiveRetentionApprovalRecordV1,
        >,
        BrokerError,
    >{
        let network_id = self.network_id_wire(network_id)?;
        let payload = encode_canonical(
            &ReputationRetentionLoadRequestWireV1 { network_id },
            MAX_REPUTATION_RETENTION_FRAME_BYTES_V1,
        )?;
        let result = provider_call!(
            self,
            call,
            OPERATION_REPUTATION_RETENTION_LOAD_V1,
            payload,
            false,
        )?;
        let _scope = result.enter_decode_admission();
        let record_bytes = self.session.decode_result::<Option<Vec<u8>>>(&result)?;
        let record = record_bytes
            .map(|bytes| {
                if bytes.is_empty() || bytes.len() > MAX_REPUTATION_RETENTION_APPROVAL_BYTES_V1 {
                    return Err(BrokerError::Protocol);
                }
                reserve_external_canonical_decode(
                    bytes.len(),
                    MAX_REPUTATION_RETENTION_APPROVAL_BYTES_V1,
                )?;
                iroha_core::query::reputation_finalized::
                    ReputationFinalizedArchiveRetentionApprovalRecordV1::
                        from_canonical_bytes(&bytes)
                        .map_err(|_| BrokerError::Protocol)
            })
            .transpose()
            .inspect_err(|_| self.session.poison())?;
        if let Some(record) = &record {
            let expected = self.expected_qualification()?;
            if record.authority_qualification() != expected {
                self.session.poison();
                return Err(BrokerError::StaleOrRevoked);
            }
        }
        Ok(record)
    }
}
impl iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityV1
    for ReputationBrokerRetentionAuthority
{
    fn handle(&self) -> &str {
        &self.binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionAuthorityQualificationV1,
        iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
    >{
        self.live_qualification()
            .map_err(reputation_retention_error)
    }
    fn load_latest(
        &self,
        network_id: &NetworkId,
    ) -> Result<
        Option<
            iroha_core::query::reputation_finalized::
                ReputationFinalizedArchiveRetentionApprovalRecordV1,
        >,
        iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
    >{
        self.live_qualification()
            .map_err(reputation_retention_error)?;
        let record = self
            .load_latest_raw(network_id)
            .map_err(reputation_retention_error)?;
        self.live_qualification()
            .map_err(reputation_retention_error)?;
        Ok(record)
    }
    fn compare_and_swap_latest(
        &self,
        network_id: &NetworkId,
        expected_revision: Option<[u8; 32]>,
        next: &iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionApprovalRecordV1,
    ) -> Result<
        (),
        iroha_core::query::reputation_finalized::
            ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1,
    >{
        use iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1 as Error;
        if expected_revision == Some([0; 32])
            || next.predecessor_revision() != expected_revision
            || next.authority_qualification()
                != self
                    .expected_qualification()
                    .map_err(reputation_retention_error)?
        {
            return Err(Error::Rejected);
        }
        self.live_qualification()
            .map_err(reputation_retention_error)?;
        let current = self
            .load_latest_raw(network_id)
            .map_err(reputation_retention_error)?;
        let monotonic = current.as_ref().map_or_else(
            || {
                expected_revision.is_none()
                    && next.sequence() == 1
                    && next.predecessor_revision().is_none()
                    && next.predecessor_checkpoint_digest().is_none()
            },
            |previous| {
                previous.authority_qualification() == next.authority_qualification()
                    && previous
                        .revision()
                        .eq(&expected_revision.unwrap_or_default())
                    && previous
                        .sequence()
                        .checked_add(1)
                        .is_some_and(|sequence| sequence == next.sequence())
                    && next.predecessor_revision() == Some(previous.revision())
                    && next.predecessor_checkpoint_digest()
                        == Some(previous.proposal().checkpoint_digest())
            },
        );
        if !monotonic {
            return Err(Error::Rejected);
        }
        let network_id = self
            .network_id_wire(network_id)
            .map_err(reputation_retention_error)?;
        let next_record = next.to_canonical_bytes().map_err(|_| Error::Rejected)?;
        if next_record.is_empty() || next_record.len() > MAX_REPUTATION_RETENTION_APPROVAL_BYTES_V1
        {
            return Err(Error::Rejected);
        }
        let payload = encode_canonical(
            &ReputationRetentionCompareAndSwapRequestWireV1 {
                network_id,
                expected_revision,
                next_record,
            },
            MAX_REPUTATION_RETENTION_FRAME_BYTES_V1,
        )
        .map_err(reputation_retention_error)?;
        provider_call!(
            self,
            call,
            OPERATION_REPUTATION_RETENTION_COMPARE_AND_SWAP_V1,
            payload,
            true,
        )
        .map_err(reputation_retention_error)
        .and_then(|result| {
            self.session.decode_result::<()>(&result).map_err(|_| {
                self.session.poison();
                Error::Ambiguous
            })
        })?;
        let readback = self.load_latest_raw(&network_id).map_err(|error| {
            self.session.poison();
            match error {
                BrokerError::StaleOrRevoked
                | BrokerError::BindingMismatch
                | BrokerError::Rejected => Error::Rejected,
                _ => Error::Ambiguous,
            }
        })?;
        self.live_qualification().map_err(|error| {
            self.session.poison();
            match error {
                BrokerError::StaleOrRevoked
                | BrokerError::BindingMismatch
                | BrokerError::Rejected => Error::Rejected,
                _ => Error::Ambiguous,
            }
        })?;
        if readback.as_ref() != Some(next) {
            self.session.poison();
            return Err(Error::Ambiguous);
        }
        Ok(())
    }
}
#[derive(Clone)]
struct ReputationBrokerProvider {
    session: Arc<BrokerSession>,
    binding: ProviderBindingWireV1,
    metadata_digest: [u8; 32],
}
impl_broker_debug_fields!(ReputationBrokerProvider as value {
    "slot" => value.binding.slot,
} => finish_non_exhaustive);
impl ReputationBrokerProvider {
    fn live_qualification(
        &self,
    ) -> Result<
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1,
        BrokerError,
    > {
        let payload = encode_canonical(&(), MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1)?;
        let result = provider_call!(self, call, OPERATION_QUALIFY_V1, payload, false,)?;
        let observed = self
            .session
            .decode_result::<QualificationResultWireV1>(&result)?;
        let expected = reputation_qualification_from_binding(&self.binding)?;
        if observed.revision != expected.revision()
            || observed.policy_digest != expected.policy_digest()
        {
            self.session.poison();
            return Err(BrokerError::StaleOrRevoked);
        }
        Ok(expected)
    }
    fn external_failure(
        &self,
        error: BrokerError,
    ) -> sorafs_node::reputation::runtime::ReputationExternalFailureV1 {
        let code = match error {
            BrokerError::Protocol => 1_u8,
            BrokerError::BindingMismatch => 2,
            BrokerError::StaleOrRevoked => 3,
            BrokerError::Rejected => 4,
            BrokerError::Conflict => 5,
            BrokerError::Ambiguous => 6,
            BrokerError::Unavailable => 7,
        };
        let slot = self.binding.slot.to_be_bytes();
        let code = [code];
        let mut receipt = digest_parts(
            b"iroha.runtime-provider-broker.reputation-failure.v1",
            &[&slot, self.binding.handle.as_bytes(), &code],
        );
        if receipt == [0; 32] {
            receipt[31] = 1;
        }
        sorafs_node::reputation::runtime::ReputationExternalFailureV1::try_new(receipt)
            .expect("domain-separated reputation broker failure receipt is nonzero")
    }
    fn request_failure(
        idempotency_key: [u8; 32],
    ) -> sorafs_node::reputation::runtime::ReputationExternalFailureV1 {
        let mut receipt = idempotency_key;
        if receipt == [0; 32] {
            receipt = digest_parts(
                b"iroha.runtime-provider-broker.invalid-reputation-request.v1",
                &[&idempotency_key],
            );
            if receipt == [0; 32] {
                receipt[31] = 1;
            }
        }
        sorafs_node::reputation::runtime::ReputationExternalFailureV1::try_new(receipt)
            .expect("domain-separated reputation request failure receipt is nonzero")
    }
}
impl sorafs_node::reputation::runtime::ReputationRuntimeProviderV1 for ReputationBrokerProvider {
    fn handle(&self) -> &str {
        &self.binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1,
        sorafs_node::reputation::runtime::ReputationExternalFailureV1,
    > {
        self.live_qualification()
            .map_err(|error| self.external_failure(error))
    }
}
#[derive(Clone, Debug)]
struct ReputationJournalBrokerCheckpoint {
    provider: ReputationBrokerProvider,
}
impl ReputationJournalBrokerCheckpoint {
    fn load_latest_raw(
        &self,
    ) -> Result<
        Option<sorafs_node::reputation::runtime::ReputationJournalSealedCheckpointRecordV1>,
        BrokerError,
    > {
        let payload = encode_canonical(
            &CHECKPOINT_LOAD_REQUEST_VERSION_V1,
            MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
        )?;
        let result = self.provider.session.call(
            &self.provider.binding,
            self.provider.metadata_digest,
            OPERATION_REPUTATION_JOURNAL_CHECKPOINT_LOAD_V1,
            payload,
            false,
        )?;
        let _scope = result.enter_decode_admission();
        let record_bytes = self
            .provider
            .session
            .decode_result::<Option<Vec<u8>>>(&result)?;
        record_bytes
            .map(|bytes| {
                reserve_external_canonical_decode(
                    bytes.len(),
                    MAX_REPUTATION_JOURNAL_CHECKPOINT_RECORD_BYTES_V1,
                )?;
                sorafs_node::reputation::runtime::
                    ReputationJournalSealedCheckpointRecordV1::from_canonical_bytes(
                        &bytes,
                        sorafs_node::reputation::runtime::
                            REPUTATION_JOURNAL_PRODUCER_MAX_CHECKPOINT_BYTES_V1,
                    )
                    .map_err(|_| BrokerError::Protocol)
            })
            .transpose()
            .inspect_err(|_| self.provider.session.poison())
    }
}
impl sorafs_node::reputation::runtime::ReputationRuntimeProviderV1
    for ReputationJournalBrokerCheckpoint
{
    fn handle(&self) -> &str {
        &self.provider.binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1,
        sorafs_node::reputation::runtime::ReputationExternalFailureV1,
    > {
        sorafs_node::reputation::runtime::ReputationRuntimeProviderV1::qualification(&self.provider)
    }
}
impl sorafs_node::reputation::runtime::ReputationJournalCheckpointRuntimeV1
    for ReputationJournalBrokerCheckpoint
{
    fn load_latest(
        &self,
    ) -> Result<
        Option<sorafs_node::reputation::runtime::ReputationJournalSealedCheckpointRecordV1>,
        sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1,
    > {
        self.provider
            .live_qualification()
            .map_err(reputation_journal_checkpoint_error)?;
        let record = self
            .load_latest_raw()
            .map_err(reputation_journal_checkpoint_error)?;
        self.provider
            .live_qualification()
            .map_err(reputation_journal_checkpoint_error)?;
        Ok(record)
    }
    fn compare_and_swap_latest(
        &self,
        expected_revision: Option<[u8; 32]>,
        next: &sorafs_node::reputation::runtime::ReputationJournalSealedCheckpointRecordV1,
    ) -> Result<(), sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1>
    {
        use sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1 as Error;
        if expected_revision == Some([0; 32]) {
            return Err(Error::Rejected);
        }
        let next_record = next
            .to_canonical_bytes(
                sorafs_node::reputation::runtime::
                    REPUTATION_JOURNAL_PRODUCER_MAX_CHECKPOINT_BYTES_V1,
            )
            .map_err(|_| Error::Rejected)?;
        self.provider
            .live_qualification()
            .map_err(reputation_journal_checkpoint_error)?;
        let current = self
            .load_latest_raw()
            .map_err(reputation_journal_checkpoint_error)?;
        let monotonic = current.as_ref().map_or_else(
            || {
                expected_revision.is_none()
                    && next.checkpoint_sequence() == 1
                    && next.predecessor_checkpoint_digest().is_none()
            },
            |previous| {
                expected_revision == Some(previous.revision())
                    && previous
                        .checkpoint_sequence()
                        .checked_add(1)
                        .is_some_and(|sequence| sequence == next.checkpoint_sequence())
                    && next.predecessor_checkpoint_digest() == Some(previous.checkpoint_digest())
            },
        );
        if !monotonic {
            return Err(Error::Rejected);
        }
        let payload = encode_canonical(
            &ReputationJournalCheckpointCompareAndSwapRequestWireV1 {
                expected_revision,
                next_record,
            },
            MAX_REPUTATION_JOURNAL_CHECKPOINT_FRAME_BYTES_V1,
        )
        .map_err(reputation_journal_checkpoint_error)?;
        self.provider
            .session
            .call(
                &self.provider.binding,
                self.provider.metadata_digest,
                OPERATION_REPUTATION_JOURNAL_CHECKPOINT_COMPARE_AND_SWAP_V1,
                payload,
                true,
            )
            .map_err(reputation_journal_checkpoint_error)
            .and_then(|result| {
                self.provider
                    .session
                    .decode_result::<()>(&result)
                    .map_err(|_| {
                        self.provider.session.poison();
                        Error::Ambiguous
                    })
            })?;
        let readback = self.load_latest_raw().map_err(|error| {
            self.provider.session.poison();
            match error {
                BrokerError::BindingMismatch
                | BrokerError::StaleOrRevoked
                | BrokerError::Rejected => Error::Rejected,
                _ => Error::Ambiguous,
            }
        })?;
        self.provider.live_qualification().map_err(|error| {
            self.provider.session.poison();
            match error {
                BrokerError::BindingMismatch
                | BrokerError::StaleOrRevoked
                | BrokerError::Rejected => Error::Rejected,
                _ => Error::Ambiguous,
            }
        })?;
        if readback.as_ref() != Some(next) {
            self.provider.session.poison();
            return Err(Error::Ambiguous);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
struct ReputationJournalBrokerSubmitter {
    provider: ReputationBrokerProvider,
}
impl sorafs_node::reputation::runtime::ReputationRuntimeProviderV1
    for ReputationJournalBrokerSubmitter
{
    fn handle(&self) -> &str {
        &self.provider.binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1,
        sorafs_node::reputation::runtime::ReputationExternalFailureV1,
    > {
        sorafs_node::reputation::runtime::ReputationRuntimeProviderV1::qualification(&self.provider)
    }
}
impl sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitterV1
    for ReputationJournalBrokerSubmitter
{
    fn supports_authority(&self, authority: &iroha_data_model::account::AccountId) -> bool {
        let payload = encode_canonical(
            &ReputationJournalSupportsAuthorityRequestWireV1 {
                authority: authority.clone(),
            },
            MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
        );
        let Ok(payload) = payload else {
            return false;
        };
        let result = self.provider.session.call(
            &self.provider.binding,
            self.provider.metadata_digest,
            OPERATION_REPUTATION_JOURNAL_SUPPORTS_AUTHORITY_V1,
            payload,
            false,
        );
        let Ok(result) = result else {
            return false;
        };
        self.provider
            .session
            .decode_result::<bool>(&result)
            .unwrap_or_else(|_| {
                self.provider.session.poison();
                false
            })
    }
    fn submit(
        &self,
        request: &sorafs_node::reputation::runtime::ReputationJournalTransactionRequestV1,
    ) -> sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitOutcomeV1 {
        use sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitOutcomeV1 as Outcome;
        let payload = reputation_journal_request_to_wire(request)
            .and_then(|wire| encode_canonical(&wire, MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1));
        let payload = match payload {
            Ok(payload) => payload,
            Err(_) => {
                return Outcome::NotQueued {
                    receipt: ReputationBrokerProvider::request_failure(request.idempotency_key)
                        .receipt(),
                };
            }
        };
        let result = self.provider.session.call(
            &self.provider.binding,
            self.provider.metadata_digest,
            OPERATION_REPUTATION_JOURNAL_SUBMIT_V1,
            payload,
            true,
        );
        match result {
            Ok(result) => self
                .provider
                .session
                .decode_result::<ReputationJournalTransactionSubmitResultWireV1>(&result)
                .and_then(reputation_journal_submit_result_from_wire)
                .unwrap_or_else(|_| {
                    self.provider.session.poison();
                    Outcome::Ambiguous {
                        receipt: request.idempotency_key,
                    }
                }),
            Err(BrokerError::Rejected | BrokerError::Conflict) => Outcome::NotQueued {
                receipt: request.idempotency_key,
            },
            Err(_) => Outcome::Ambiguous {
                receipt: request.idempotency_key,
            },
        }
    }
}
#[derive(Clone, Debug)]
struct ReputationThresholdBrokerSigner {
    provider: ReputationBrokerProvider,
}
impl sorafs_node::reputation::runtime::ReputationRuntimeProviderV1
    for ReputationThresholdBrokerSigner
{
    fn handle(&self) -> &str {
        &self.provider.binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1,
        sorafs_node::reputation::runtime::ReputationExternalFailureV1,
    > {
        sorafs_node::reputation::runtime::ReputationRuntimeProviderV1::qualification(&self.provider)
    }
}
impl sorafs_node::reputation::runtime::ReputationThresholdSignerClientV1
    for ReputationThresholdBrokerSigner
{
    fn reconcile_signature(
        &self,
        request: &sorafs_node::reputation::runtime::ReputationThresholdSigningRequestV1,
    ) -> Result<
        Option<sorafs_manifest::reputation::signed::SignedReputationSnapshotV1>,
        sorafs_node::reputation::runtime::ReputationExternalFailureV1,
    > {
        let payload = reputation_threshold_request_to_wire(request)
            .and_then(|wire| encode_canonical(&wire, MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1))
            .map_err(|_| ReputationBrokerProvider::request_failure(request.idempotency_key))?;
        let result = self
            .provider
            .session
            .call(
                &self.provider.binding,
                self.provider.metadata_digest,
                OPERATION_REPUTATION_THRESHOLD_RECONCILE_V1,
                payload,
                true,
            )
            .map_err(|_| ReputationBrokerProvider::request_failure(request.idempotency_key))?;
        let _scope = result.enter_decode_admission();
        let wire = self
            .provider
            .session
            .decode_result::<ReputationReconcileResultWireV1>(&result)
            .map_err(|_| {
                self.provider.session.poison();
                ReputationBrokerProvider::request_failure(request.idempotency_key)
            })?;
        match wire.outcome {
            0 if wire.canonical_result.is_empty() && wire.failure_receipt == [0; 32] => Ok(None),
            1 if !wire.canonical_result.is_empty() && wire.failure_receipt == [0; 32] => {
                reserve_external_canonical_decode(
                    wire.canonical_result.len(),
                    MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
                )
                .map_err(|_| {
                    self.provider.session.poison();
                    ReputationBrokerProvider::request_failure(request.idempotency_key)
                })?;
                let signed =
                    sorafs_manifest::reputation::signed::decode_signed_reputation_snapshot(
                        &wire.canonical_result,
                    )
                    .map_err(|_| {
                        self.provider.session.poison();
                        ReputationBrokerProvider::request_failure(request.idempotency_key)
                    })?;
                validate_reputation_signature(request, &signed).map_err(|_| {
                    self.provider.session.poison();
                    ReputationBrokerProvider::request_failure(request.idempotency_key)
                })?;
                Ok(Some(signed))
            }
            2 if wire.canonical_result.is_empty() && wire.failure_receipt != [0; 32] => Err(
                sorafs_node::reputation::runtime::ReputationExternalFailureV1::try_new(
                    wire.failure_receipt,
                )
                .expect("validated nonzero reputation failure receipt"),
            ),
            _ => {
                self.provider.session.poison();
                Err(ReputationBrokerProvider::request_failure(
                    request.idempotency_key,
                ))
            }
        }
    }
}
#[derive(Clone, Debug)]
struct ReputationGovernanceBrokerClient {
    provider: ReputationBrokerProvider,
}
impl sorafs_node::reputation::runtime::ReputationRuntimeProviderV1
    for ReputationGovernanceBrokerClient
{
    fn handle(&self) -> &str {
        &self.provider.binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::reputation::runtime::ReputationRuntimeProviderQualificationV1,
        sorafs_node::reputation::runtime::ReputationExternalFailureV1,
    > {
        sorafs_node::reputation::runtime::ReputationRuntimeProviderV1::qualification(&self.provider)
    }
}
impl sorafs_node::reputation::runtime::ReputationGovernanceDagClientV1
    for ReputationGovernanceBrokerClient
{
    fn reconcile_publication(
        &self,
        request: &sorafs_node::reputation::runtime::ReputationGovernanceDagPublicationRequestV1,
    ) -> Result<
        Option<sorafs_node::reputation::runtime::ReputationGovernanceDagReadbackV1>,
        sorafs_node::reputation::runtime::ReputationExternalFailureV1,
    > {
        let payload = reputation_governance_request_to_wire(request)
            .and_then(|wire| encode_canonical(&wire, MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1))
            .map_err(|_| ReputationBrokerProvider::request_failure(request.idempotency_key))?;
        let result = self
            .provider
            .session
            .call(
                &self.provider.binding,
                self.provider.metadata_digest,
                OPERATION_REPUTATION_GOVERNANCE_RECONCILE_V1,
                payload,
                true,
            )
            .map_err(|_| ReputationBrokerProvider::request_failure(request.idempotency_key))?;
        let _scope = result.enter_decode_admission();
        let wire = self
            .provider
            .session
            .decode_result::<ReputationReconcileResultWireV1>(&result)
            .map_err(|_| {
                self.provider.session.poison();
                ReputationBrokerProvider::request_failure(request.idempotency_key)
            })?;
        match wire.outcome {
            0 if wire.canonical_result.is_empty() && wire.failure_receipt == [0; 32] => Ok(None),
            1 if !wire.canonical_result.is_empty() && wire.failure_receipt == [0; 32] => {
                let readback = decode_canonical::<
                    sorafs_node::reputation::runtime::ReputationGovernanceDagReadbackV1,
                >(
                    &wire.canonical_result,
                    MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
                )
                .map_err(|_| {
                    self.provider.session.poison();
                    ReputationBrokerProvider::request_failure(request.idempotency_key)
                })?;
                validate_reputation_governance_readback(&readback, &request.signed_result)
                    .map_err(|_| {
                        self.provider.session.poison();
                        ReputationBrokerProvider::request_failure(request.idempotency_key)
                    })?;
                Ok(Some(readback))
            }
            2 if wire.canonical_result.is_empty() && wire.failure_receipt != [0; 32] => Err(
                sorafs_node::reputation::runtime::ReputationExternalFailureV1::try_new(
                    wire.failure_receipt,
                )
                .expect("validated nonzero reputation failure receipt"),
            ),
            _ => {
                self.provider.session.poison();
                Err(ReputationBrokerProvider::request_failure(
                    request.idempotency_key,
                ))
            }
        }
    }
}
#[derive(Clone)]
struct BillingBrokerProvider {
    session: Arc<BrokerSession>,
    binding: ProviderBindingWireV1,
    metadata_digest: [u8; 32],
}
impl_broker_debug_fields!(BillingBrokerProvider as value {
    "slot" => value.binding.slot,
} => finish_non_exhaustive);
impl BillingBrokerProvider {
    fn expected_qualification(
        &self,
    ) -> Result<
        sorafs_node::hedging_billing_service::HedgingBillingRuntimeProviderQualificationV1,
        BrokerError,
    > {
        let qualification = qualification_from_binding(&self.binding)?;
        Ok(
            sorafs_node::hedging_billing_service::HedgingBillingRuntimeProviderQualificationV1::new(
                qualification.revision,
                qualification.policy_digest,
            ),
        )
    }
    fn live_qualification(
        &self,
    ) -> Result<
        sorafs_node::hedging_billing_service::HedgingBillingRuntimeProviderQualificationV1,
        BrokerError,
    > {
        let payload = encode_canonical(&(), MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
        let result = provider_call!(self, call, OPERATION_QUALIFY_V1, payload, false,)?;
        let observed = self
            .session
            .decode_operation_result::<QualificationResultWireV1>(&result, OPERATION_QUALIFY_V1)?;
        let expected = self.expected_qualification()?;
        if observed.revision != expected.revision()
            || observed.policy_digest != expected.policy_digest()
        {
            self.session.poison();
            return Err(BrokerError::StaleOrRevoked);
        }
        Ok(expected)
    }
    fn call_unit(&self, operation: u16) -> Result<(), BrokerError> {
        let payload = encode_canonical(&(), MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
        let result = provider_call!(self, call, operation, payload, false,)?;
        self.session
            .decode_operation_result::<()>(&result, operation)
    }
    fn ensure_network_id(
        &self,
        network_id: &iroha_data_model::NetworkId,
    ) -> Result<(), BrokerError> {
        if network_id != &self.session.network_id {
            return Err(BrokerError::BindingMismatch);
        }
        Ok(())
    }
    fn adapter_identity(&self) -> Result<BillingAdapterIdentityWireV1, BrokerError> {
        let payload = encode_canonical(&(), MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
        let result = provider_call!(self, call, OPERATION_BILLING_IDENTITY_V1, payload, false,)?;
        let identity = self
            .session
            .decode_operation_result::<BillingAdapterIdentityWireV1>(
                &result,
                OPERATION_BILLING_IDENTITY_V1,
            )?;
        if identity.handle != self.binding.handle {
            self.session.poison();
            return Err(BrokerError::BindingMismatch);
        }
        Ok(identity)
    }
    fn signer_identity(&self) -> Result<BillingStatementSignerIdentityWireV1, BrokerError> {
        let payload = encode_canonical(&(), MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
        let result = provider_call!(self, call, OPERATION_BILLING_IDENTITY_V1, payload, false,)?;
        let identity = self
            .session
            .decode_operation_result::<BillingStatementSignerIdentityWireV1>(
                &result,
                OPERATION_BILLING_IDENTITY_V1,
            )?;
        if identity.provider_handle != self.binding.handle
            || !validate_billing_public_identity_text(
                &identity.signer_id,
                sorafs_node::hedging_billing_service::BILLING_SIGNER_ID_MAX_BYTES_V1,
            )
            || iroha_crypto::ed25519_parse_public_key(&identity.public_key).is_err()
        {
            self.session.poison();
            return Err(BrokerError::BindingMismatch);
        }
        Ok(identity)
    }
    fn publisher_identity(&self) -> Result<BillingStatementPublisherIdentityWireV1, BrokerError> {
        let payload = encode_canonical(&(), MAX_BILLING_CONTROL_FRAME_BYTES_V1)?;
        let result = provider_call!(self, call, OPERATION_BILLING_IDENTITY_V1, payload, false,)?;
        let identity = self
            .session
            .decode_operation_result::<BillingStatementPublisherIdentityWireV1>(
                &result,
                OPERATION_BILLING_IDENTITY_V1,
            )?;
        if identity.provider_handle != self.binding.handle
            || !validate_billing_public_identity_text(
                &identity.publisher_id,
                sorafs_node::hedging_billing_service::BILLING_SIGNER_ID_MAX_BYTES_V1,
            )
            || !validate_billing_public_identity_text(
                &identity.route_id,
                sorafs_node::hedging_billing_service::BILLING_PUBLICATION_ROUTE_MAX_BYTES_V1,
            )
            || iroha_crypto::ed25519_parse_public_key(&identity.public_key).is_err()
        {
            self.session.poison();
            return Err(BrokerError::BindingMismatch);
        }
        Ok(identity)
    }
    fn lookup_publication_raw(
        &self,
        statement_id: [u8; 32],
        identity: &BillingStatementPublisherIdentityWireV1,
        after_write: bool,
    ) -> Result<
        Option<sorafs_node::hedging_billing_service::BillingStatementAuthoritativePublicationV1>,
        BrokerError,
    > {
        validate_billing_record_id(statement_id)?;
        let payload = encode_canonical(
            &BillingLookupRequestWireV1 {
                record_id: statement_id,
            },
            MAX_BILLING_CONTROL_FRAME_BYTES_V1,
        )?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_LOOKUP_PUBLICATION_V1,
            payload,
            false,
        );
        let result = match result {
            Ok(result) => result,
            Err(_) if after_write => return Err(BrokerError::Ambiguous),
            Err(error) => return Err(error),
        };
        let _scope = result.enter_decode_admission();
        let publication = self
            .session
            .decode_operation_result::<Option<BillingAuthoritativePublicationWireV1>>(
                &result,
                OPERATION_BILLING_LOOKUP_PUBLICATION_V1,
            )
            .map_err(|error| {
                self.session.poison();
                if after_write {
                    BrokerError::Ambiguous
                } else {
                    error
                }
            })?;
        publication
            .map(|publication| {
                validate_billing_publication_shape(
                    &publication,
                    statement_id,
                    identity,
                    self.session.network_id,
                )
                .map_err(|error| {
                    self.session.poison();
                    if after_write {
                        BrokerError::Ambiguous
                    } else {
                        error
                    }
                })?;
                Ok(
                    sorafs_node::hedging_billing_service::
                        BillingStatementAuthoritativePublicationV1 {
                            signed_statement: publication.signed_statement,
                            receipt: publication.receipt,
                        },
                )
            })
            .transpose()
    }
    fn load_epoch_record(
        &self,
        operation: u16,
        epoch_sequence: Option<u64>,
        after_write: bool,
    ) -> Result<
        Option<sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessRecordV1>,
        BrokerError,
    > {
        let payload = match epoch_sequence {
            Some(epoch_sequence) => {
                if epoch_sequence == 0 {
                    return Err(BrokerError::Rejected);
                }
                encode_canonical(
                    &BillingLoadEpochRequestWireV1 { epoch_sequence },
                    MAX_BILLING_CONTROL_FRAME_BYTES_V1,
                )?
            }
            None => encode_canonical(&(), MAX_BILLING_CONTROL_FRAME_BYTES_V1)?,
        };
        let result = provider_call!(self, call, operation, payload, false,);
        let result = match result {
            Ok(result) => result,
            Err(_) if after_write => return Err(BrokerError::Ambiguous),
            Err(error) => return Err(error),
        };
        let record = self
            .session
            .decode_operation_result::<Option<
                sorafs_node::hedging_billing_service::
                    HedgingBillingEpochWitnessRecordV1,
            >>(&result, operation)
            .map_err(|error| {
                self.session.poison();
                if after_write {
                    BrokerError::Ambiguous
                } else {
                    error
                }
            })?;
        if let Some(record) = record.as_ref() {
            if record.network_id != self.session.network_id {
                self.session.poison();
                return Err(if after_write {
                    BrokerError::Ambiguous
                } else {
                    BrokerError::BindingMismatch
                });
            }
            record
                .validate(
                    sorafs_node::hedging_billing_service::HEDGING_BILLING_MAX_CHECKPOINT_BYTES_V1,
                )
                .map_err(|_| {
                    self.session.poison();
                    if after_write {
                        BrokerError::Ambiguous
                    } else {
                        BrokerError::Protocol
                    }
                })?;
            if epoch_sequence.is_some_and(|expected| expected != record.epoch_sequence) {
                self.session.poison();
                return Err(if after_write {
                    BrokerError::Ambiguous
                } else {
                    BrokerError::Protocol
                });
            }
        }
        Ok(record)
    }
}
fn billing_client_external_error(
    error: BrokerError,
) -> sorafs_node::hedging_billing_service::HedgingBillingExternalError {
    match error {
        BrokerError::Unavailable => {
            sorafs_node::hedging_billing_service::HedgingBillingExternalError::Unavailable
        }
        BrokerError::Ambiguous => {
            sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous
        }
        BrokerError::Protocol
        | BrokerError::BindingMismatch
        | BrokerError::StaleOrRevoked
        | BrokerError::Rejected
        | BrokerError::Conflict => {
            sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected
        }
    }
}
impl sorafs_node::hedging_billing_service::HedgingBillingRuntimeProviderV1
    for BillingBrokerProvider
{
    fn handle(&self) -> &str {
        &self.binding.handle
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::hedging_billing_service::HedgingBillingRuntimeProviderQualificationV1,
        sorafs_node::hedging_billing_service::HedgingBillingRuntimeProviderReadinessErrorV1,
    > {
        self.live_qualification().map_err(|error| {
            match error {
            BrokerError::Unavailable | BrokerError::Ambiguous => {
                sorafs_node::hedging_billing_service::
                    HedgingBillingRuntimeProviderReadinessErrorV1::Unavailable
            }
            BrokerError::Protocol
            | BrokerError::BindingMismatch
            | BrokerError::StaleOrRevoked
            | BrokerError::Rejected
            | BrokerError::Conflict => {
                sorafs_node::hedging_billing_service::
                    HedgingBillingRuntimeProviderReadinessErrorV1::Rejected
            }
        }
        })
    }
}
impl sorafs_node::hedging_billing_service::HedgingBillingFinalizedQuery for BillingBrokerProvider {
    fn identity(
        &self,
    ) -> Result<
        sorafs_node::hedging_billing_service::HedgingBillingRuntimeAdapterIdentityV1,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        self.adapter_identity()
            .map(|identity| {
                sorafs_node::hedging_billing_service::HedgingBillingRuntimeAdapterIdentityV1 {
                    handle: identity.handle,
                }
            })
            .map_err(billing_client_external_error)
    }
    fn check_readiness(
        &self,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        self.call_unit(OPERATION_BILLING_READINESS_V1)
            .map_err(billing_client_external_error)
    }
    fn supplies_period_closes(&self) -> bool {
        let payload = match encode_canonical(&(), MAX_BILLING_CONTROL_FRAME_BYTES_V1) {
            Ok(payload) => payload,
            Err(_) => return false,
        };
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_QUERY_CAPABILITIES_V1,
            payload,
            false,
        );
        let Ok(result) = result else {
            return false;
        };
        self.session
            .decode_operation_result::<BillingFinalizedQueryCapabilitiesWireV1>(
                &result,
                OPERATION_BILLING_QUERY_CAPABILITIES_V1,
            )
            .map_or_else(
                |_| {
                    self.session.poison();
                    false
                },
                |capabilities| capabilities.supplies_period_closes,
            )
    }
    fn finalized_head(
        &self,
    ) -> Result<
        sorafs_node::hedging_billing_service::HedgingBillingFinalizedCursorV1,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        let payload = encode_canonical(&(), MAX_BILLING_CONTROL_FRAME_BYTES_V1)
            .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_FINALIZED_HEAD_V1,
            payload,
            false,
        )
        .map_err(billing_client_external_error)?;
        let head = self
            .session
            .decode_operation_result::<
                sorafs_node::hedging_billing_service::
                    HedgingBillingFinalizedCursorV1,
            >(&result, OPERATION_BILLING_FINALIZED_HEAD_V1)
            .map_err(billing_client_external_error)?;
        validate_billing_cursor(head).map_err(|error| {
            self.session.poison();
            billing_client_external_error(error)
        })?;
        Ok(head)
    }
    fn query_finalized_page(
        &self,
        position: sorafs_node::hedging_billing_service::HedgingBillingQueryPositionV1,
        max_events: u32,
    ) -> Result<
        Option<sorafs_node::hedging_billing_service::HedgingBillingFinalizedEventPageV1>,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        let position = billing_query_position_to_wire(position);
        validate_billing_query_position(position, self.session.network_id)
            .map_err(billing_client_external_error)?;
        if max_events == 0
            || max_events
                > sorafs_node::hedging_billing_service::HEDGING_BILLING_MAX_EVENTS_PER_PAGE_V1
        {
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        let payload = encode_canonical(
            &BillingQueryPageRequestWireV1 {
                position,
                max_events,
            },
            MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        )
        .map_err(billing_client_external_error)?;
        let result = provider_call!(self, call, OPERATION_BILLING_QUERY_PAGE_V1, payload, false,)
            .map_err(billing_client_external_error)?;
        let page = self
            .session
            .decode_operation_result::<Option<
                sorafs_node::hedging_billing_service::
                    HedgingBillingFinalizedEventPageV1,
            >>(&result, OPERATION_BILLING_QUERY_PAGE_V1)
            .map_err(billing_client_external_error)?;
        if let Some(page) = page.as_ref() {
            validate_billing_page_shape(page, Some((position, max_events))).map_err(|error| {
                self.session.poison();
                billing_client_external_error(error)
            })?;
            self.ensure_network_id(&page.network_id).map_err(|error| {
                self.session.poison();
                billing_client_external_error(error)
            })?;
        }
        Ok(page)
    }
    fn query_finalized_period_close(
        &self,
        period_end_unix: u64,
        position: sorafs_node::hedging_billing_service::HedgingBillingQueryPositionV1,
    ) -> Result<
        Option<sorafs_node::hedging_billing_service::HedgingBillingFinalizedPeriodCloseV1>,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        let position = billing_query_position_to_wire(position);
        validate_billing_query_position(position, self.session.network_id)
            .map_err(billing_client_external_error)?;
        if period_end_unix == 0 {
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        let payload = encode_canonical(
            &BillingQueryPeriodCloseRequestWireV1 {
                period_end_unix,
                position,
            },
            MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        )
        .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1,
            payload,
            false,
        )
        .map_err(billing_client_external_error)?;
        let close =
            self.session
                .decode_operation_result::<Option<
                    sorafs_node::hedging_billing_service::HedgingBillingFinalizedPeriodCloseV1,
                >>(&result, OPERATION_BILLING_QUERY_PERIOD_CLOSE_V1)
                .map_err(billing_client_external_error)?;
        if let Some(close) = close.as_ref() {
            validate_billing_period_close_shape(close, Some(period_end_unix)).map_err(|error| {
                self.session.poison();
                billing_client_external_error(error)
            })?;
            self.ensure_network_id(&close.network_id).map_err(|error| {
                self.session.poison();
                billing_client_external_error(error)
            })?;
        }
        Ok(close)
    }
}
impl sorafs_node::hedging_billing_service::HedgingBillingJournalVerifier for BillingBrokerProvider {
    fn identity(
        &self,
    ) -> Result<
        sorafs_node::hedging_billing_service::HedgingBillingRuntimeAdapterIdentityV1,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        self.adapter_identity()
            .map(|identity| {
                sorafs_node::hedging_billing_service::HedgingBillingRuntimeAdapterIdentityV1 {
                    handle: identity.handle,
                }
            })
            .map_err(billing_client_external_error)
    }
    fn check_readiness(
        &self,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        self.call_unit(OPERATION_BILLING_READINESS_V1)
            .map_err(billing_client_external_error)
    }
    fn verify_page(
        &self,
        network_id: &iroha_data_model::NetworkId,
        previous: Option<sorafs_node::hedging_billing_service::HedgingBillingJournalCommitmentV1>,
        page: &sorafs_node::hedging_billing_service::HedgingBillingFinalizedEventPageV1,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        self.ensure_network_id(network_id)
            .map_err(billing_client_external_error)?;
        if &page.network_id != network_id {
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        validate_billing_page_shape(page, None).map_err(billing_client_external_error)?;
        if let Some(previous) = previous {
            validate_billing_journal_commitment(previous, *network_id)
                .map_err(billing_client_external_error)?;
        }
        let payload = encode_canonical(
            &BillingVerifyPageRequestWireV1 {
                network_id: *network_id,
                previous,
                page: page.clone(),
            },
            MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        )
        .map_err(billing_client_external_error)?;
        let result = provider_call!(self, call, OPERATION_BILLING_VERIFY_PAGE_V1, payload, false,)
            .map_err(billing_client_external_error)?;
        self.session
            .decode_operation_result::<()>(&result, OPERATION_BILLING_VERIFY_PAGE_V1)
            .map_err(billing_client_external_error)
    }
    fn verify_period_close(
        &self,
        network_id: &iroha_data_model::NetworkId,
        close: &sorafs_node::hedging_billing_service::HedgingBillingFinalizedPeriodCloseV1,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        self.ensure_network_id(network_id)
            .map_err(billing_client_external_error)?;
        if &close.network_id != network_id {
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        validate_billing_period_close_shape(close, None).map_err(billing_client_external_error)?;
        let payload = encode_canonical(
            &BillingVerifyPeriodCloseRequestWireV1 {
                network_id: *network_id,
                close: close.clone(),
            },
            MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        )
        .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1,
            payload,
            false,
        )
        .map_err(billing_client_external_error)?;
        self.session
            .decode_operation_result::<()>(&result, OPERATION_BILLING_VERIFY_PERIOD_CLOSE_V1)
            .map_err(billing_client_external_error)
    }
    fn verify_epoch_transition(
        &self,
        network_id: &iroha_data_model::NetworkId,
        transition: &sorafs_node::hedging_billing_service::HedgingBillingEpochTransitionV1,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        self.ensure_network_id(network_id)
            .map_err(billing_client_external_error)?;
        transition.verify().map_err(|_| {
            sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected
        })?;
        if &transition.previous_service_policy.network_id != network_id
            || &transition.next_service_policy.network_id != network_id
        {
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        let payload = encode_canonical(
            &BillingVerifyEpochTransitionRequestWireV1 {
                network_id: *network_id,
                transition: transition.clone(),
            },
            MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        )
        .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1,
            payload,
            false,
        )
        .map_err(billing_client_external_error)?;
        self.session
            .decode_operation_result::<()>(&result, OPERATION_BILLING_VERIFY_EPOCH_TRANSITION_V1)
            .map_err(billing_client_external_error)
    }
}
impl sorafs_node::hedging_billing_service::BillingStatementRuntimeSigner for BillingBrokerProvider {
    fn identity(
        &self,
    ) -> Result<
        sorafs_node::hedging_billing_service::BillingStatementSignerIdentityV1,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        self.signer_identity()
            .map(|identity| {
                sorafs_node::hedging_billing_service::BillingStatementSignerIdentityV1 {
                    provider_handle: identity.provider_handle,
                    signer_id: identity.signer_id,
                    public_key: identity.public_key,
                }
            })
            .map_err(billing_client_external_error)
    }
    fn check_readiness(
        &self,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        self.call_unit(OPERATION_BILLING_READINESS_V1)
            .map_err(billing_client_external_error)
    }
    fn sign_digest(
        &self,
        digest: [u8; 32],
    ) -> Result<[u8; 64], sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        if digest == [0; 32] {
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        let identity = self
            .signer_identity()
            .map_err(billing_client_external_error)?;
        let payload = encode_canonical(
            &BillingSignDigestRequestWireV1 { digest },
            MAX_BILLING_CONTROL_FRAME_BYTES_V1,
        )
        .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1,
            payload,
            false,
        )
        .map_err(billing_client_external_error)?;
        let _scope = result.enter_decode_admission();
        let signed = self
            .session
            .decode_operation_result::<BillingSignDigestResultWireV1>(
                &result,
                OPERATION_BILLING_SIGN_STATEMENT_DIGEST_V1,
            )
            .map_err(billing_client_external_error)?;
        let identity_after = self.signer_identity().map_err(|error| {
            self.session.poison();
            billing_client_external_error(error)
        })?;
        if identity_after != identity
            || verify_evidence_viewer_ed25519_signature(
                identity.public_key,
                signed.signature,
                &digest,
            )
            .is_err()
        {
            self.session.poison();
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        Ok(signed.signature)
    }
}
impl sorafs_node::hedging_billing_service::BillingStatementPublisher for BillingBrokerProvider {
    fn identity(
        &self,
    ) -> Result<
        sorafs_node::hedging_billing_service::BillingStatementPublisherIdentityV1,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        self.publisher_identity()
            .map(|identity| {
                sorafs_node::hedging_billing_service::BillingStatementPublisherIdentityV1 {
                    provider_handle: identity.provider_handle,
                    publisher_id: identity.publisher_id,
                    route_id: identity.route_id,
                    public_key: identity.public_key,
                }
            })
            .map_err(billing_client_external_error)
    }
    fn check_readiness(
        &self,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        self.call_unit(OPERATION_BILLING_READINESS_V1)
            .map_err(billing_client_external_error)
    }
    fn publish(
        &self,
        idempotency_key: [u8; 32],
        signed_statement_digest: [u8; 32],
        statement: &sorafs_node::hedging_billing_service::SignedGovernedBillingStatementV1,
    ) -> Result<
        sorafs_node::hedging_billing_service::BillingStatementPublicationReceiptV1,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        let publish = BillingPublishStatementRequestWireV1 {
            idempotency_key,
            signed_statement_digest,
            statement: statement.clone(),
        };
        validate_billing_publish_request(&publish, self.session.network_id)
            .map_err(billing_client_external_error)?;
        let identity = self
            .publisher_identity()
            .map_err(billing_client_external_error)?;
        let payload = encode_canonical(&publish, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)
            .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_PUBLISH_STATEMENT_V1,
            payload,
            true,
        )
        .map_err(billing_client_external_error)?;
        let _scope = result.enter_decode_admission();
        let receipt = self
            .session
            .decode_operation_result::<
                sorafs_node::hedging_billing_service::
                    BillingStatementPublicationReceiptV1,
            >(&result, OPERATION_BILLING_PUBLISH_STATEMENT_V1)
            .map_err(|_| {
                self.session.poison();
                sorafs_node::hedging_billing_service::
                    HedgingBillingExternalError::Ambiguous
            })?;
        let readback = self
            .lookup_publication_raw(idempotency_key, &identity, true)
            .map_err(billing_client_external_error)?
            .ok_or(sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous)?;
        let identity_after = self.publisher_identity().map_err(|_| {
            self.session.poison();
            sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous
        })?;
        if identity_after != identity
            || readback.signed_statement != *statement
            || readback.receipt != receipt
        {
            self.session.poison();
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous,
            );
        }
        Ok(receipt)
    }
    fn lookup(
        &self,
        statement_id: [u8; 32],
    ) -> Result<
        Option<sorafs_node::hedging_billing_service::BillingStatementAuthoritativePublicationV1>,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        let identity = self
            .publisher_identity()
            .map_err(billing_client_external_error)?;
        let publication = self
            .lookup_publication_raw(statement_id, &identity, false)
            .map_err(billing_client_external_error)?;
        let identity_after = self.publisher_identity().map_err(|error| {
            self.session.poison();
            billing_client_external_error(error)
        })?;
        if identity_after != identity {
            self.session.poison();
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        Ok(publication)
    }
}
impl sorafs_node::hedging_billing_service::BillingStatementAcknowledgementAuthority
    for BillingBrokerProvider
{
    fn identity(
        &self,
    ) -> Result<
        sorafs_node::hedging_billing_service::BillingStatementAcknowledgementAuthorityIdentityV1,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        self.adapter_identity()
            .map(|identity| {
                sorafs_node::hedging_billing_service::
                    BillingStatementAcknowledgementAuthorityIdentityV1 {
                        provider_handle: identity.handle,
                    }
            })
            .map_err(billing_client_external_error)
    }
    fn check_readiness(
        &self,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        self.call_unit(OPERATION_BILLING_READINESS_V1)
            .map_err(billing_client_external_error)
    }
    fn verify(
        &self,
        statement: &sorafs_node::hedging_billing_service::SignedGovernedBillingStatementV1,
        acknowledgement: &sorafs_node::hedging_billing_service::BillingStatementAcknowledgementV1,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        let request = BillingAcknowledgementRequestWireV1 {
            statement: statement.clone(),
            acknowledgement: acknowledgement.clone(),
        };
        validate_billing_acknowledgement_request(&request, self.session.network_id)
            .map_err(billing_client_external_error)?;
        let payload = encode_canonical(&request, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)
            .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1,
            payload,
            false,
        )
        .map_err(billing_client_external_error)?;
        self.session
            .decode_operation_result::<()>(&result, OPERATION_BILLING_VERIFY_ACKNOWLEDGEMENT_V1)
            .map_err(billing_client_external_error)
    }
    fn record(
        &self,
        statement: &sorafs_node::hedging_billing_service::SignedGovernedBillingStatementV1,
        acknowledgement: &sorafs_node::hedging_billing_service::BillingStatementAcknowledgementV1,
    ) -> Result<
        sorafs_node::hedging_billing_service::BillingStatementAcknowledgementV1,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        let request = BillingAcknowledgementRequestWireV1 {
            statement: statement.clone(),
            acknowledgement: acknowledgement.clone(),
        };
        validate_billing_acknowledgement_request(&request, self.session.network_id)
            .map_err(billing_client_external_error)?;
        let payload = encode_canonical(&request, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)
            .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1,
            payload,
            true,
        )
        .map_err(billing_client_external_error)?;
        let _scope = result.enter_decode_admission();
        let recorded = self
            .session
            .decode_operation_result::<
                sorafs_node::hedging_billing_service::
                    BillingStatementAcknowledgementV1,
            >(&result, OPERATION_BILLING_RECORD_ACKNOWLEDGEMENT_V1)
            .map_err(|_| {
                self.session.poison();
                sorafs_node::hedging_billing_service::
                    HedgingBillingExternalError::Ambiguous
            })?;
        if &recorded != acknowledgement {
            self.session.poison();
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous,
            );
        }
        let readback =
            sorafs_node::hedging_billing_service::BillingStatementAcknowledgementAuthority::lookup(
                self,
                recorded.statement_id,
            )
            .map_err(|_| {
                self.session.poison();
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous
            })?;
        if readback.as_ref() != Some(&recorded) {
            self.session.poison();
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous,
            );
        }
        self.live_qualification().map_err(|_| {
            self.session.poison();
            sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous
        })?;
        Ok(recorded)
    }
    fn lookup(
        &self,
        statement_id: [u8; 32],
    ) -> Result<
        Option<sorafs_node::hedging_billing_service::BillingStatementAcknowledgementV1>,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        validate_billing_record_id(statement_id).map_err(billing_client_external_error)?;
        let payload = encode_canonical(
            &BillingLookupRequestWireV1 {
                record_id: statement_id,
            },
            MAX_BILLING_CONTROL_FRAME_BYTES_V1,
        )
        .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_LOOKUP_ACKNOWLEDGEMENT_V1,
            payload,
            false,
        )
        .map_err(billing_client_external_error)?;
        let _scope = result.enter_decode_admission();
        let acknowledgement =
            self.session
                .decode_operation_result::<Option<
                    sorafs_node::hedging_billing_service::BillingStatementAcknowledgementV1,
                >>(
                    &result, OPERATION_BILLING_LOOKUP_ACKNOWLEDGEMENT_V1
                )
                .map_err(billing_client_external_error)?;
        if let Some(acknowledgement) = acknowledgement.as_ref() {
            validate_billing_acknowledgement_shape(
                acknowledgement,
                statement_id,
                self.session.network_id,
            )
            .map_err(|error| {
                self.session.poison();
                billing_client_external_error(error)
            })?;
        }
        Ok(acknowledgement)
    }
}
impl sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessStore
    for BillingBrokerProvider
{
    fn check_readiness(
        &self,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        self.call_unit(OPERATION_BILLING_READINESS_V1)
            .map_err(billing_client_external_error)
    }
    fn load_latest(
        &self,
    ) -> Result<
        Option<sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessRecordV1>,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        self.load_epoch_record(OPERATION_BILLING_LOAD_LATEST_EPOCH_V1, None, false)
            .map_err(billing_client_external_error)
    }
    fn load_epoch(
        &self,
        epoch_sequence: u64,
    ) -> Result<
        Option<sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessRecordV1>,
        sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    > {
        self.load_epoch_record(OPERATION_BILLING_LOAD_EPOCH_V1, Some(epoch_sequence), false)
            .map_err(billing_client_external_error)
    }
    fn compare_and_swap_latest(
        &self,
        expected_revision: Option<[u8; 32]>,
        next: &sorafs_node::hedging_billing_service::HedgingBillingEpochWitnessRecordV1,
    ) -> Result<(), sorafs_node::hedging_billing_service::HedgingBillingExternalError> {
        if expected_revision == Some([0; 32])
            || next.network_id != self.session.network_id
            || next
                .validate(
                    sorafs_node::hedging_billing_service::HEDGING_BILLING_MAX_CHECKPOINT_BYTES_V1,
                )
                .is_err()
        {
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        let current = self
            .load_epoch_record(OPERATION_BILLING_LOAD_LATEST_EPOCH_V1, None, false)
            .map_err(billing_client_external_error)?;
        let monotonic = current.as_ref().map_or_else(
            || expected_revision.is_none() && next.epoch_sequence == 1,
            |current| {
                Some(current.revision) == expected_revision
                    && current
                        .epoch_sequence
                        .checked_add(1)
                        .is_some_and(|sequence| sequence == next.epoch_sequence)
            },
        );
        if !monotonic {
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected,
            );
        }
        let payload = encode_canonical(
            &BillingCompareAndSwapEpochRequestWireV1 {
                expected_revision,
                next: next.clone(),
            },
            MAX_BILLING_RUNTIME_FRAME_BYTES_V1,
        )
        .map_err(billing_client_external_error)?;
        let result = provider_call!(
            self,
            call,
            OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1,
            payload,
            true,
        )
        .map_err(billing_client_external_error)?;
        let _scope = result.enter_decode_admission();
        self.session
            .decode_operation_result::<()>(&result, OPERATION_BILLING_COMPARE_AND_SWAP_EPOCH_V1)
            .map_err(|_| {
                self.session.poison();
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous
            })?;
        let latest = self
            .load_epoch_record(OPERATION_BILLING_LOAD_LATEST_EPOCH_V1, None, true)
            .map_err(billing_client_external_error)?;
        let historical = self
            .load_epoch_record(
                OPERATION_BILLING_LOAD_EPOCH_V1,
                Some(next.epoch_sequence),
                true,
            )
            .map_err(billing_client_external_error)?;
        self.live_qualification().map_err(|_| {
            self.session.poison();
            sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous
        })?;
        if latest.as_ref() != Some(next) || historical.as_ref() != Some(next) {
            self.session.poison();
            return Err(
                sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous,
            );
        }
        Ok(())
    }
}
fn provider_ingest_resolver_error(
    error: BrokerError,
) -> sorafs_node::ProviderIngestCompletionSignerResolverErrorV1 {
    match error {
        BrokerError::Unavailable | BrokerError::Ambiguous => {
            sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Unavailable
        }
        BrokerError::Protocol
        | BrokerError::BindingMismatch
        | BrokerError::StaleOrRevoked
        | BrokerError::Rejected
        | BrokerError::Conflict => {
            sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Rejected
        }
    }
}
fn provider_ingest_signer_error(
    error: BrokerError,
) -> sorafs_node::ProviderIngestCompletionSignerErrorV1 {
    match error {
        BrokerError::Unavailable | BrokerError::Ambiguous => {
            sorafs_node::ProviderIngestCompletionSignerErrorV1::Unavailable
        }
        BrokerError::Protocol
        | BrokerError::BindingMismatch
        | BrokerError::StaleOrRevoked
        | BrokerError::Rejected
        | BrokerError::Conflict => sorafs_node::ProviderIngestCompletionSignerErrorV1::Rejected,
    }
}
fn provider_ingest_checkpoint_error(
    error: BrokerError,
) -> sorafs_node::ProviderIngestCheckpointExternalErrorV1 {
    match error {
        BrokerError::Unavailable => {
            sorafs_node::ProviderIngestCheckpointExternalErrorV1::Unavailable
        }
        BrokerError::Ambiguous => sorafs_node::ProviderIngestCheckpointExternalErrorV1::Ambiguous,
        BrokerError::Protocol
        | BrokerError::BindingMismatch
        | BrokerError::StaleOrRevoked
        | BrokerError::Rejected
        | BrokerError::Conflict => sorafs_node::ProviderIngestCheckpointExternalErrorV1::Rejected,
    }
}
fn reputation_journal_checkpoint_error(
    error: BrokerError,
) -> sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1 {
    use sorafs_node::reputation::runtime::ReputationJournalCheckpointExternalErrorV1 as Error;
    match error {
        BrokerError::Unavailable => Error::Unavailable,
        BrokerError::Ambiguous => Error::Ambiguous,
        BrokerError::Protocol
        | BrokerError::BindingMismatch
        | BrokerError::StaleOrRevoked
        | BrokerError::Rejected
        | BrokerError::Conflict => Error::Rejected,
    }
}
fn provider_ingest_retention_error(
    error: BrokerError,
) -> iroha_core::query::provider_ingest_finalized::
ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1{
    use iroha_core::query::provider_ingest_finalized::ProviderIngestFinalizedArchiveRetentionAuthorityExternalErrorV1 as Error;
    match error {
        BrokerError::Unavailable => Error::Unavailable,
        BrokerError::Ambiguous => Error::Ambiguous,
        BrokerError::Protocol
        | BrokerError::BindingMismatch
        | BrokerError::StaleOrRevoked
        | BrokerError::Rejected
        | BrokerError::Conflict => Error::Rejected,
    }
}
fn reputation_retention_error(
    error: BrokerError,
) -> iroha_core::query::reputation_finalized::
ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1{
    use iroha_core::query::reputation_finalized::ReputationFinalizedArchiveRetentionAuthorityExternalErrorV1 as Error;
    match error {
        BrokerError::Unavailable => Error::Unavailable,
        BrokerError::Ambiguous => Error::Ambiguous,
        BrokerError::Protocol
        | BrokerError::BindingMismatch
        | BrokerError::StaleOrRevoked
        | BrokerError::Rejected
        | BrokerError::Conflict => Error::Rejected,
    }
}
#[derive(Clone)]
struct GlobalBeaconBrokerPartialSigner {
    session: Arc<BrokerSession>,
    binding: ProviderBindingWireV1,
    metadata_digest: [u8; 32],
}

fn retry_consensus_signer_once_after_unavailable<T>(
    session: &BrokerSession,
    mut attempt: impl FnMut() -> Result<T, BrokerError>,
) -> Result<T, BrokerError> {
    match attempt() {
        Err(BrokerError::Unavailable) => {
            session.reconnect()?;
            attempt()
        }
        outcome => outcome,
    }
}

impl GlobalBeaconBrokerPartialSigner {
    fn attest_projected_capability(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1, BrokerError>
    {
        retry_consensus_signer_once_after_unavailable(self.session.as_ref(), || {
            iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1::for_validated_session(
                session,
                expected_signer_index,
            )
            .map_err(|_| BrokerError::Rejected)?;
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            let request_payload = encode_canonical(
                &GlobalBeaconCapabilityAttestRequestRefV1 {
                    session: norito::core::PayloadRef(session.record()),
                    signer_index: expected_signer_index,
                },
                MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
            )?;
            let result = provider_call!(
                self,
                call,
                OPERATION_GLOBAL_BEACON_CAPABILITY_ATTEST_V1,
                request_payload,
                false,
            )?;
            let attested = self
                .session
                .decode_result::<GlobalBeaconCapabilityAttestResultWireV1>(&result)?;
            let expected = iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1::for_validated_session(
                session,
                expected_signer_index,
            )
            .map_err(|_| BrokerError::Rejected)?;
            if attested.session_id != expected.session_id()
                || attested.transcript_hash != expected.transcript_hash()
                || attested.signer_index != expected.signer_index()
            {
                self.session.poison();
                return Err(BrokerError::Rejected);
            }
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            Ok(expected)
        })
    }
}

impl iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1 for GlobalBeaconBrokerPartialSigner {
    fn attest_partial_signing_capability(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1,
        iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1,
    > {
        iroha_core::beacon::GlobalThresholdBeaconPartialSigningCapabilityV1::for_validated_session(
            session,
            expected_signer_index,
        )?;
        self.attest_projected_capability(session, expected_signer_index)
            .map_err(|error| match error {
                BrokerError::Unavailable
                | BrokerError::Protocol
                | BrokerError::BindingMismatch
                | BrokerError::Ambiguous => {
                    iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1::Unavailable
                }
                BrokerError::StaleOrRevoked | BrokerError::Rejected | BrokerError::Conflict => {
                    iroha_core::beacon::GlobalThresholdBeaconCapabilityErrorV1::NotOwned
                }
            })
    }

    fn prove_seat_readiness(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        authority: &iroha_data_model::sumeragi::epoch::ValidatorGenerationV1,
        context: &iroha_data_model::nexus::ValidatorSeatReadinessContextV1,
    ) -> Result<
        iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1,
        iroha_core::beacon::seat_readiness::GlobalThresholdBeaconSeatReadinessErrorV1,
    > {
        use iroha_core::beacon::seat_readiness::{
            GlobalThresholdBeaconSeatReadinessErrorV1 as ReadyError,
            global_threshold_beacon_seat_readiness_challenge_v1,
            verify_global_threshold_beacon_seat_readiness_v1,
        };
        global_threshold_beacon_seat_readiness_challenge_v1(session, authority, context)?;
        retry_consensus_signer_once_after_unavailable(self.session.as_ref(), || {
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            let request = GlobalBeaconSeatReadinessRequestRefV1 {
                session: norito::core::PayloadRef(session.record()),
                authority: norito::core::PayloadRef(authority),
                context: *context,
            };
            let request_payload = encode_canonical(&request, MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1)?;
            let result = provider_call!(
                self,
                call,
                OPERATION_GLOBAL_BEACON_SEAT_READINESS_V1,
                request_payload,
                false,
            )?;
            let signed = self
                .session
                .decode_result::<GlobalBeaconPartialSignResultWireV1>(&result)?;
            verify_global_threshold_beacon_seat_readiness_v1(
                session,
                authority,
                context,
                &signed.partial,
            )
            .map_err(|_| {
                self.session.poison();
                BrokerError::Rejected
            })?;
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            Ok(signed.partial)
        })
        .map_err(|error| match error {
            BrokerError::Rejected | BrokerError::Conflict => ReadyError::InvalidProof,
            _ => ReadyError::CustodyUnavailable,
        })
    }

    fn sign_partial(
        &self,
        session: &iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<iroha_data_model::consensus::GlobalThresholdBeaconPartialSignatureV1, String> {
        retry_consensus_signer_once_after_unavailable(self.session.as_ref(), || {
            let slot =
                iroha_core::beacon::global_threshold_beacon_pulse_signing_slot_v1(session, payload)
                    .map_err(|_| BrokerError::Rejected)?;
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            let request = GlobalBeaconPartialSignRequestRefV1 {
                session: norito::core::PayloadRef(session.record()),
                height: slot.height,
                finalized_chain_anchor: slot.finalized_chain_anchor,
                context: slot.context,
            };
            let request_payload = encode_canonical(&request, MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1)?;
            let result = provider_call!(
                self,
                call,
                OPERATION_GLOBAL_BEACON_PARTIAL_SIGN_V1,
                request_payload,
                false,
            )?;
            let signed = self
                .session
                .decode_result::<GlobalBeaconPartialSignResultWireV1>(&result)?;
            let mut verifier = iroha_core::beacon::GlobalThresholdBeaconPulseAggregatorV1::new(
                session.clone(),
                slot.height,
                slot.finalized_chain_anchor,
                slot.context,
            )
            .map_err(|_| BrokerError::Rejected)?;
            verifier.accept_partial(signed.partial).map_err(|_| {
                self.session.poison();
                BrokerError::Rejected
            })?;
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            Ok(signed.partial)
        })
        .map_err(redacted_provider_error)
    }
}

#[derive(Clone)]
struct ParliamentTleBrokerPartialReleaseSigner {
    session: Arc<BrokerSession>,
    binding: ProviderBindingWireV1,
    metadata_digest: [u8; 32],
}

impl ParliamentTleBrokerPartialReleaseSigner {
    fn attest_projected_capability(
        &self,
        session: &iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1,
        expected_participant_index: u16,
    ) -> Result<iroha_core::tle_release::TlePartialReleaseCapabilityAttestationV1, BrokerError>
    {
        retry_consensus_signer_once_after_unavailable(self.session.as_ref(), || {
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            let request_payload = encode_canonical(
                &ParliamentTleCapabilityAttestRequestWireV1 {
                    key_session: session.public_state().clone(),
                    participant_index: expected_participant_index,
                },
                MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
            )?;
            let result = provider_call!(
                self,
                call,
                OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1,
                request_payload,
                false,
            )?;
            let attested = self
                .session
                .decode_result::<ParliamentTleCapabilityAttestResultWireV1>(&result)?;
            let expected = iroha_core::tle_release::TlePartialReleaseCapabilityAttestationV1::for_validated_session(
                session,
                expected_participant_index,
            )
            .map_err(|_| BrokerError::Rejected)?;
            if attested.key_session_id != expected.key_session_id()
                || attested.transcript_hash != expected.transcript_hash()
                || attested.participant_index != expected.participant_index()
            {
                self.session.poison();
                return Err(BrokerError::Rejected);
            }
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            Ok(expected)
        })
    }

    fn sign_projected_partial_release(
        &self,
        projection: &iroha_core_timed_ovn::tle::AuthorizedTleReleaseProjectionV1,
        session: &iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1,
        identity: &iroha_crypto::tle::TleReleaseIdentityV1,
        finalized_height: u64,
    ) -> Result<iroha_core_timed_ovn::tle::TlePartialReleaseShareV1, BrokerError> {
        retry_consensus_signer_once_after_unavailable(self.session.as_ref(), || {
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            let request_payload = encode_canonical(
                &ParliamentTlePartialReleaseSignRequestWireV1 {
                    projection: projection.clone(),
                },
                MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
            )?;
            let result = provider_call!(
                self,
                call,
                OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1,
                request_payload,
                false,
            )?;
            let signed = self
                .session
                .decode_result::<ParliamentTlePartialReleaseSignResultWireV1>(&result)?;
            session
                .verify_partial_release(identity, finalized_height, &signed.partial)
                .map_err(|_| {
                    self.session.poison();
                    BrokerError::Rejected
                })?;
            live_exact_qualification(self.session.as_ref(), &self.binding, self.metadata_digest)?;
            Ok(signed.partial)
        })
    }
}

impl iroha_core::tle_release::TlePartialReleaseSignerV1
    for ParliamentTleBrokerPartialReleaseSigner
{
    fn attest_partial_release_capability(
        &self,
        session: &iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1,
        expected_participant_index: u16,
    ) -> Result<
        iroha_core::tle_release::TlePartialReleaseCapabilityAttestationV1,
        iroha_core::tle_release::TlePartialReleaseCapabilityErrorV1,
    > {
        self.attest_projected_capability(session, expected_participant_index)
            .map_err(|error| match error {
                BrokerError::Unavailable
                | BrokerError::Protocol
                | BrokerError::BindingMismatch
                | BrokerError::Ambiguous => {
                    iroha_core::tle_release::TlePartialReleaseCapabilityErrorV1::Unavailable
                }
                BrokerError::StaleOrRevoked | BrokerError::Rejected | BrokerError::Conflict => {
                    iroha_core::tle_release::TlePartialReleaseCapabilityErrorV1::NotOwned
                }
            })
    }

    fn sign_partial_release(
        &self,
        context: &iroha_core::tle_release::AuthorizedTleReleaseContextV1,
    ) -> Result<iroha_core_timed_ovn::tle::TlePartialReleaseShareV1, String> {
        let projection = context
            .broker_projection_v1()
            .map_err(|_| redacted_provider_error(BrokerError::Rejected))?;
        self.sign_projected_partial_release(
            &projection,
            context.session(),
            context.identity(),
            context.finalized_height(),
        )
        .map_err(redacted_provider_error)
    }
}

fn redacted_provider_error(error: BrokerError) -> String {
    match error {
        BrokerError::StaleOrRevoked => ERROR_STALE_OR_REVOKED.to_owned(),
        BrokerError::Rejected => ERROR_REJECTED.to_owned(),
        BrokerError::Conflict => ERROR_CONFLICT.to_owned(),
        BrokerError::Ambiguous => ERROR_AMBIGUOUS.to_owned(),
        BrokerError::Unavailable | BrokerError::Protocol | BrokerError::BindingMismatch => {
            ERROR_UNAVAILABLE.to_owned()
        }
    }
}
fn registry_error(error: BrokerError) -> IrohaRuntimeProviderRegistryErrorV1 {
    match error {
        BrokerError::Unavailable | BrokerError::Ambiguous => {
            IrohaRuntimeProviderRegistryErrorV1::Unavailable
        }
        BrokerError::StaleOrRevoked | BrokerError::Rejected => {
            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
        }
        BrokerError::Protocol | BrokerError::BindingMismatch | BrokerError::Conflict => {
            IrohaRuntimeProviderRegistryErrorV1::BindingMismatch
        }
    }
}
/// Resolve supported bindings through an explicitly selected endpoint.
pub(super) fn resolve(
    bindings: &IrohaRuntimeProviderBindingsV1,
    endpoint: &EndpointPolicy,
) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
    resolve_with_decode_pool(bindings, endpoint, shared_decode_resource_pool())
}

fn resolve_with_decode_pool(
    bindings: &IrohaRuntimeProviderBindingsV1,
    endpoint: &EndpointPolicy,
    decode_pool: Arc<DecodeResourcePoolV1>,
) -> Result<IrohaRuntimeDeps, IrohaRuntimeProviderRegistryErrorV1> {
    let requested_catalog = bindings
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()?;
    if requested_catalog
        .iter()
        .any(|binding| !binding.has_exact_qualification())
    {
        return Err(IrohaRuntimeProviderRegistryErrorV1::InvalidBinding(
            bindings
                .iter()
                .find(|binding| binding.revision().is_none() || binding.policy_digest().is_none())
                .map_or(
                    IrohaRuntimeProviderSlotV1::GovernanceDagSigner,
                    IrohaRuntimeProviderBindingV1::slot,
                ),
        ));
    }
    let (session, observations) = BrokerSession::connect(
        endpoint,
        bindings.chain_id(),
        *bindings.network_id(),
        requested_catalog.clone(),
        decode_pool,
    )
    .map_err(registry_error)?;
    let mut dependencies = IrohaRuntimeDeps::default();
    let mut appeal_finance_signers: Vec<
        Arc<dyn iroha_torii::SoraFsAppealFinanceTransactionSigner>,
    > = Vec::new();
    let mut potr_gateway_signer: Option<Arc<dyn iroha_torii::sorafs::PotrGatewaySignerV1>> = None;
    let mut potr_provider_signer: Option<Arc<dyn iroha_torii::sorafs::PotrProviderSignerV1>> = None;
    let mut potr_runtime_binding: Option<PotrRuntimeBindingWireV1> = None;
    for (binding, observation) in requested_catalog.iter().zip(&observations) {
        match binding.runtime_slot().map_err(registry_error)?.wire_id() {
            slot if slot == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id() => {
                let signer = Arc::new(GlobalBeaconBrokerPartialSigner {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                });
                let first = live_exact_qualification(
                    signer.session.as_ref(),
                    &signer.binding,
                    signer.metadata_digest,
                )
                .map_err(registry_error)?;
                let second = live_exact_qualification(
                    signer.session.as_ref(),
                    &signer.binding,
                    signer.metadata_digest,
                )
                .map_err(registry_error)?;
                if first != second {
                    signer.session.poison();
                    return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
                }
                dependencies = dependencies.with_sumeragi_global_beacon_partial_signer(signer);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id() =>
            {
                let signer = Arc::new(ParliamentTleBrokerPartialReleaseSigner {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                });
                let first = live_exact_qualification(
                    signer.session.as_ref(),
                    &signer.binding,
                    signer.metadata_digest,
                )
                .map_err(registry_error)?;
                let second = live_exact_qualification(
                    signer.session.as_ref(),
                    &signer.binding,
                    signer.metadata_digest,
                )
                .map_err(registry_error)?;
                if first != second {
                    signer.session.poison();
                    return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
                }
                dependencies = dependencies.with_parliament_tle_partial_release_signer(signer);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry.wire_id() =>
            {
                let exact_bindings =
                    bootle_lantern_bindings_from_wire(binding).map_err(registry_error)?;
                let registry = Arc::new(BootleLanternBrokerProvider {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    exact_bindings,
                });
                registry.live_qualification().map_err(registry_error)?;
                dependencies =
                    dependencies.with_bootle_lantern_issuance_provider_registry(registry);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider.wire_id() => {
                let provider = Arc::new(resolved_provider!(
                    PrivacyCyclePrfBrokerProvider,
                    &session,
                    binding,
                    observation
                ));
                provider.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_privacy_cycle_prf_provider(provider);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::PrivacyReleaseAnchor.wire_id() => {
                transparency_runtime_binding_from_wire(binding).map_err(registry_error)?;
                let anchor = Arc::new(resolved_provider!(
                    PrivacyReleaseAnchorBroker,
                    &session,
                    binding,
                    observation
                ));
                anchor.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_privacy_release_anchor(anchor);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::TransparencyLeaderLease.wire_id() => {
                transparency_runtime_binding_from_wire(binding).map_err(registry_error)?;
                let provider = Arc::new(resolved_provider!(
                    TransparencyLeaderLeaseBroker,
                    &session,
                    binding,
                    observation
                ));
                provider.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_transparency_leader_lease_provider(provider);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher.wire_id() => {
                qualification_from_binding(binding).map_err(registry_error)?;
                let publisher = Arc::new(resolved_provider!(
                    FencedPrivacyPublisherBroker,
                    &session,
                    binding,
                    observation
                ));
                publisher.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_fenced_transparency_publisher(publisher);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader.wire_id() => {
                qualification_from_binding(binding).map_err(registry_error)?;
                let reader = Arc::new(resolved_provider!(
                    FencedPrivacyHeadReaderBroker,
                    &session,
                    binding,
                    observation
                ));
                reader.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_fenced_transparency_head_reader(reader);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id() => {
                let signer_backend = binding
                    .stream_token_signer_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                signer_backend
                    .validate_network(&session.chain_id, session.network_id.as_bytes())?;
                let client = Arc::new(StreamTokenSignerBrokerClient {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    latch: Arc::new(Mutex::new(StreamTokenSignLatchV1::Idle)),
                });
                client.metadata().map_err(registry_error)?;
                let observer = Arc::new(StreamTokenObserverBrokerClient {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    observer_handle: signer_backend.observer_handle().to_owned(),
                });
                dependencies = dependencies
                    .with_sorafs_stream_token_signer_client(client)
                    .with_sorafs_stream_token_state_observer(observer);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id() =>
            {
                let exact = binding
                    .appeal_finance_signer_binding
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let signer = Arc::new(AppealFinanceBrokerSigner {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    authority: exact.authority.clone(),
                    public_key: exact.public_key.clone(),
                });
                signer.live_qualification().map_err(registry_error)?;
                appeal_finance_signers.push(signer);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint.wire_id() => {
                let public_key = exact_ed25519_public_key_bytes(
                    &binding
                        .appeal_finance_checkpoint_binding
                        .as_ref()
                        .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?
                        .public_key,
                )
                .map_err(registry_error)?;
                let checkpoint = Arc::new(AppealFinanceBrokerCheckpoint {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    public_key,
                    checkpoint_max_bytes: binding
                        .appeal_finance_checkpoint_max_bytes
                        .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?,
                });
                checkpoint.live_identity().map_err(registry_error)?;
                dependencies =
                    dependencies.with_sorafs_appeal_finance_checkpoint_runtime(checkpoint);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::PotrGatewaySigner.wire_id() => {
                let runtime = binding
                    .potr_runtime_binding
                    .clone()
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                if potr_runtime_binding
                    .as_ref()
                    .is_some_and(|configured| configured != &runtime)
                {
                    return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
                }
                let public_key: [u8; 32] = observation
                    .potr_signer_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let signer = Arc::new(PotrGatewayBrokerSigner {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    public_key,
                    signer_id: runtime.gateway_signer_id,
                });
                potr_qualification(session.as_ref(), binding, observation.metadata_digest)
                    .map_err(registry_error)?;
                potr_runtime_binding = Some(runtime);
                potr_gateway_signer = Some(signer);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::PotrProviderSigner.wire_id() => {
                let runtime = binding
                    .potr_runtime_binding
                    .clone()
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                if potr_runtime_binding
                    .as_ref()
                    .is_some_and(|configured| configured != &runtime)
                {
                    return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
                }
                let signer = Arc::new(PotrProviderBrokerSigner {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    public_key: observation.potr_signer_public_key.clone(),
                    signer_id: runtime.provider_signer_id,
                    provider_id: runtime.baseline_admission_policy.provider_id,
                });
                potr_qualification(session.as_ref(), binding, observation.metadata_digest)
                    .map_err(registry_error)?;
                potr_runtime_binding = Some(runtime);
                potr_provider_signer = Some(signer);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry.wire_id() => {
                pop_runtime_bindings_from_wire(binding).map_err(registry_error)?;
                let registry = Arc::new(PopCredentialBrokerRegistry {
                    provider: resolved_provider!(PopBrokerProvider, &session, binding, observation),
                });
                iroha_torii::sorafs::pop_api::
                    PopCredentialRuntimeProviderRegistryV1::qualification(
                        registry.as_ref(),
                    )
                    .map_err(|error| match error {
                        iroha_torii::sorafs::pop_api::
                            PopCredentialRuntimeProviderRegistryErrorV1::Unavailable => {
                            IrohaRuntimeProviderRegistryErrorV1::Unavailable
                        }
                        iroha_torii::sorafs::pop_api::
                            PopCredentialRuntimeProviderRegistryErrorV1::StaleOrRevoked
                        | iroha_torii::sorafs::pop_api::
                            PopCredentialRuntimeProviderRegistryErrorV1::RejectedBindings => {
                            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                        }
                    })?;
                dependencies = dependencies.with_sorafs_pop_credential_provider_registry(registry);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::GatewayAcmeClient.wire_id() => {
                let client = Arc::new(resolved_provider!(
                    GatewayAcmeBrokerClient,
                    &session,
                    binding,
                    observation
                ));
                client.live_identity().map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_gateway_acme_client(client);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::GatewayComplianceFeedTransport.wire_id() =>
            {
                let transport = Arc::new(resolved_provider!(
                    GatewayComplianceBrokerFeedTransport,
                    &session,
                    binding,
                    observation
                ));
                transport.live_identity().map_err(registry_error)?;
                dependencies =
                    dependencies.with_sorafs_gateway_compliance_feed_transport(transport);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter.wire_id() =>
            {
                let submitter = Arc::new(ReputationJournalBrokerSubmitter {
                    provider: resolved_provider!(
                        ReputationBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                submitter
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies =
                    dependencies.with_sorafs_reputation_journal_transaction_submitter(submitter);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint.wire_id() => {
                let checkpoint = Arc::new(ReputationJournalBrokerCheckpoint {
                    provider: resolved_provider!(
                        ReputationBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                checkpoint
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                sorafs_node::reputation::runtime::
                    ReputationJournalCheckpointRuntimeV1::load_latest(
                        checkpoint.as_ref(),
                    )
                    .map_err(|error| match error {
                        sorafs_node::reputation::runtime::
                            ReputationJournalCheckpointExternalErrorV1::Unavailable => {
                            IrohaRuntimeProviderRegistryErrorV1::Unavailable
                        }
                        sorafs_node::reputation::runtime::
                            ReputationJournalCheckpointExternalErrorV1::Rejected
                        | sorafs_node::reputation::runtime::
                            ReputationJournalCheckpointExternalErrorV1::Ambiguous => {
                            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                        }
                    })?;
                dependencies =
                    dependencies.with_sorafs_reputation_journal_checkpoint_provider(checkpoint);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::ReputationThresholdSigner.wire_id() => {
                let signer = Arc::new(ReputationThresholdBrokerSigner {
                    provider: resolved_provider!(
                        ReputationBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                signer
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_reputation_threshold_signer(signer);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::ReputationGovernanceDag.wire_id() => {
                let governance_dag = Arc::new(ReputationGovernanceBrokerClient {
                    provider: resolved_provider!(
                        ReputationBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                governance_dag
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_reputation_governance_dag(governance_dag);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::BillingFinalizedQuery.wire_id() => {
                let query = Arc::new(resolved_provider!(
                    BillingBrokerProvider,
                    &session,
                    binding,
                    observation
                ));
                query.live_qualification().map_err(registry_error)?;
                query.adapter_identity().map_err(registry_error)?;
                query
                    .call_unit(OPERATION_BILLING_READINESS_V1)
                    .map_err(registry_error)?;
                if !sorafs_node::hedging_billing_service::
                    HedgingBillingFinalizedQuery::supplies_period_closes(query.as_ref())
                {
                    return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
                }
                dependencies = dependencies.with_sorafs_hedging_billing_finalized_query(query);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::BillingJournalVerifier.wire_id() => {
                let verifier = Arc::new(resolved_provider!(
                    BillingBrokerProvider,
                    &session,
                    binding,
                    observation
                ));
                verifier.live_qualification().map_err(registry_error)?;
                verifier.adapter_identity().map_err(registry_error)?;
                verifier
                    .call_unit(OPERATION_BILLING_READINESS_V1)
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_hedging_billing_journal_verifier(verifier);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::BillingStatementSigner.wire_id() => {
                let signer = Arc::new(resolved_provider!(
                    BillingBrokerProvider,
                    &session,
                    binding,
                    observation
                ));
                signer.live_qualification().map_err(registry_error)?;
                signer.signer_identity().map_err(registry_error)?;
                signer
                    .call_unit(OPERATION_BILLING_READINESS_V1)
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_billing_statement_signer(signer);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::BillingStatementPublisher.wire_id() => {
                let publisher = Arc::new(resolved_provider!(
                    BillingBrokerProvider,
                    &session,
                    binding,
                    observation
                ));
                publisher.live_qualification().map_err(registry_error)?;
                publisher.publisher_identity().map_err(registry_error)?;
                publisher
                    .call_unit(OPERATION_BILLING_READINESS_V1)
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_billing_statement_publisher(publisher);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::BillingAcknowledgementAuthority.wire_id() =>
            {
                let authority = Arc::new(resolved_provider!(
                    BillingBrokerProvider,
                    &session,
                    binding,
                    observation
                ));
                authority.live_qualification().map_err(registry_error)?;
                authority.adapter_identity().map_err(registry_error)?;
                authority
                    .call_unit(OPERATION_BILLING_READINESS_V1)
                    .map_err(registry_error)?;
                dependencies =
                    dependencies.with_sorafs_billing_acknowledgement_authority(authority);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::BillingEpochWitnessStore.wire_id() => {
                let store = Arc::new(resolved_provider!(
                    BillingBrokerProvider,
                    &session,
                    binding,
                    observation
                ));
                store.live_qualification().map_err(registry_error)?;
                store
                    .call_unit(OPERATION_BILLING_READINESS_V1)
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_hedging_billing_epoch_witness_store(store);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive.wire_id() => {
                let archive = Arc::new(resolved_provider!(
                    PorReplayArchiveBroker,
                    &session,
                    binding,
                    observation
                ));
                archive.live_binding().map_err(registry_error)?;
                sorafs_node::PorFinalizedReplayArchiveV1::check_readiness(archive.as_ref())
                    .map_err(|error| match error {
                        sorafs_node::PorFinalizedReplayArchiveExternalErrorV1::Unavailable => {
                            IrohaRuntimeProviderRegistryErrorV1::Unavailable
                        }
                        sorafs_node::PorFinalizedReplayArchiveExternalErrorV1::Rejected => {
                            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                        }
                    })?;
                dependencies = dependencies.with_sorafs_por_finalized_replay_archive(archive);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper.wire_id() =>
            {
                let active_key_id = observation
                    .moderation_quarantine_active_key_id
                    .clone()
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                validate_moderation_quarantine_key_id(&active_key_id).map_err(registry_error)?;
                let key_wrapper = Arc::new(ModerationQuarantineBrokerKeyWrapper {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    active_key_id,
                });
                key_wrapper.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_moderation_quarantine_key_wrapper(key_wrapper);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id() => {
                let metadata = observation
                    .signer_metadata
                    .as_ref()
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let publisher_peer_id = binding
                    .governance_dag_publisher_peer_id
                    .clone()
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let public_key = binding
                    .governance_dag_publisher_public_key
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                if metadata.publisher_peer_id.as_slice() != publisher_peer_id.as_slice()
                    || metadata.public_key != public_key
                {
                    return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
                }
                let signer = Arc::new(GovernanceDagBrokerSigner {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    publisher_peer_id,
                    public_key,
                });
                signer.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_governance_dag_signer(signer);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id()
                || slot == IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator.wire_id() =>
            {
                let ingress_binding =
                    governance_request_ingress_binding_from_provider_binding(binding)
                        .map_err(registry_error)?;
                let observed_qualification = governance_request_ingress_qualification_from_wire(
                    observation
                        .governance_request_ingress_qualification
                        .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?,
                )
                .map_err(registry_error)?;
                let authenticator = Arc::new(GovernanceDagBrokerRequestAuthenticator {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    ingress_binding,
                    ingress_qualification: observed_qualification,
                });
                if authenticator
                    .live_ingress_qualification()
                    .map_err(registry_error)?
                    != observed_qualification
                {
                    return Err(IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked);
                }
                dependencies = if slot
                    == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id()
                {
                    dependencies.with_sorafs_governance_dag_ipfs_authenticator(authenticator)
                } else {
                    dependencies.with_sorafs_governance_dag_head_authenticator(authenticator)
                };
            }
            slot if slot == IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore.wire_id() => {
                let store = Arc::new(resolved_provider!(
                    GovernanceDagBrokerCheckpointStore,
                    &session,
                    binding,
                    observation
                ));
                store.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_governance_dag_checkpoint_store(store);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::ModerationTransactionSigner.wire_id() => {
                let expected = qualification_from_binding(binding).map_err(registry_error)?;
                let expected =
                    sorafs_node::moderation_orchestrator::
                        ModerationRuntimeProviderQualificationV1::new(
                            expected.revision,
                            expected.policy_digest,
                        );
                let signer = Arc::new(resolved_provider!(
                    ModerationTransactionBrokerSigner,
                    &session,
                    binding,
                    observation
                ));
                sorafs_node::moderation_orchestrator::qualify_moderation_runtime_provider_v1(
                    &binding.handle,
                    expected,
                    signer.as_ref(),
                )
                .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
                dependencies = dependencies.with_sorafs_moderation_transaction_signer(signer);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id()
                || slot == IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id() =>
            {
                let expected = qualification_from_binding(binding).map_err(registry_error)?;
                let expected =
                    sorafs_node::moderation_orchestrator::
                        ModerationRuntimeProviderQualificationV1::new(
                            expected.revision,
                            expected.policy_digest,
                        );
                let boundary = Arc::new(ModerationHandoffBrokerBoundary {
                    provider: resolved_provider!(
                        ModerationDeliveryBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                sorafs_node::moderation_orchestrator::qualify_moderation_runtime_provider_v1(
                    &binding.handle,
                    expected,
                    boundary.as_ref(),
                )
                .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
                dependencies =
                    if slot == IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id() {
                        dependencies.with_sorafs_moderation_settlement_handoff(boundary)
                    } else {
                        dependencies.with_sorafs_moderation_publication_handoff(boundary)
                    };
            }
            slot if slot == IrohaRuntimeProviderSlotV1::ModerationPanelNotification.wire_id() => {
                let expected = qualification_from_binding(binding).map_err(registry_error)?;
                let expected =
                    sorafs_node::moderation_orchestrator::
                        ModerationRuntimeProviderQualificationV1::new(
                            expected.revision,
                            expected.policy_digest,
                        );
                let boundary = Arc::new(ModerationPanelNotificationBrokerBoundary {
                    provider: resolved_provider!(
                        ModerationDeliveryBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                sorafs_node::moderation_orchestrator::qualify_moderation_runtime_provider_v1(
                    &binding.handle,
                    expected,
                    boundary.as_ref(),
                )
                .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
                dependencies = dependencies.with_sorafs_moderation_panel_notification(boundary);
            }
            slot if native_transaction_signer_role_for_slot(slot).is_some() => {
                let exact_binding =
                    native_transaction_signer_binding_from_wire(binding).map_err(registry_error)?;
                let role = exact_binding.role();
                let core = NativeTransactionBrokerCore {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    exact_binding,
                };
                core.live_qualification().map_err(registry_error)?;
                dependencies = match role {
                    iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome => dependencies
                        .with_sorafs_proof_outcome_signer(Arc::new(ProofOutcomeBrokerSigner {
                            core,
                        })),
                    iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair => dependencies
                        .with_sorafs_repair_transaction_signer(Arc::new(RepairBrokerSigner {
                            core,
                        })),
                    iroha_torii::SorafsNativeTransactionSignerRoleV1::Reserve => dependencies
                        .with_sorafs_reserve_transaction_signer(Arc::new(ReserveBrokerSigner {
                            core,
                        })),
                    iroha_torii::SorafsNativeTransactionSignerRoleV1::Orderbook => dependencies
                        .with_sorafs_orderbook_transaction_signer(Arc::new(
                            OrderbookBrokerSigner { core },
                        )),
                };
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id() =>
            {
                let exact_binding =
                    soracloud_runtime_signer_binding_from_wire(binding).map_err(registry_error)?;
                let signer = Arc::new(SoracloudRuntimeBrokerSigner {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    exact_binding,
                });
                signer.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_soracloud_runtime_mutation_signer(signer);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id() =>
            {
                let source = Arc::new(ProviderIngestBrokerAuthenticatedSource {
                    session: Arc::clone(&session),
                    endpoint: endpoint.clone(),
                    chain_id: bindings.chain_id().to_owned(),
                    requested_catalog: requested_catalog.clone(),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    source_provider_ids: observation.provider_ingest_source_provider_ids.clone(),
                });
                source.live_qualification().map_err(registry_error)?;
                crate::sorafs_provider_ingest_runtime::
                    ProviderIngestAuthenticatedSourceRuntimeV1::check_readiness(
                        source.as_ref(),
                    )
                    .map_err(|error| match error {
                        sorafs_node::ProviderIngestSourceFetchErrorV1::Unavailable => {
                            IrohaRuntimeProviderRegistryErrorV1::Unavailable
                        }
                        sorafs_node::ProviderIngestSourceFetchErrorV1::ContentRejected
                        | sorafs_node::ProviderIngestSourceFetchErrorV1::Rejected => {
                            IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                        }
                    })?;
                dependencies =
                    dependencies.with_sorafs_provider_ingest_authenticated_source(source);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver.wire_id() =>
            {
                let (signer_binding, signer_observation) = requested_catalog
                    .iter()
                    .zip(&observations)
                    .find(|(candidate, _)| {
                        candidate.slot
                            == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner.wire_id()
                    })
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution)?;
                let expected_signer_binding =
                    provider_ingest_expected_signer_binding(binding).map_err(registry_error)?;
                if provider_ingest_expected_signer_binding(signer_binding)
                    .map_err(registry_error)?
                    != expected_signer_binding
                {
                    return Err(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch);
                }
                let resolver = Arc::new(ProviderIngestBrokerSignerResolver {
                    session: Arc::clone(&session),
                    resolver_binding: binding.clone(),
                    resolver_metadata_digest: observation.metadata_digest,
                    signer_binding: signer_binding.clone(),
                    signer_metadata_digest: signer_observation.metadata_digest,
                    expected_signer_binding,
                });
                resolver.live_state().map_err(registry_error)?;
                crate::sorafs_provider_ingest_runtime::
                    ProviderIngestGovernedSignerResolverRuntimeV1::check_readiness(
                        resolver.as_ref(),
                    )
                    .map_err(|_| {
                        IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked
                    })?;
                dependencies = dependencies.with_sorafs_provider_ingest_signer_resolver(resolver);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner.wire_id() =>
            {
                // The signer role is resolved through the paired
                // governed resolver and must never be installed as
                // process-local authority on its own.
            }
            slot if slot == IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore.wire_id() => {
                let checkpoint_max_bytes = binding
                    .provider_ingest_checkpoint_max_bytes
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let store = Arc::new(ProviderIngestBrokerCheckpointStore {
                    session: Arc::clone(&session),
                    binding: binding.clone(),
                    metadata_digest: observation.metadata_digest,
                    checkpoint_max_bytes,
                });
                store.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_provider_ingest_checkpoint_runtime(store);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::ProviderIngestRetentionAuthority.wire_id() =>
            {
                let authority = Arc::new(resolved_provider!(
                    ProviderIngestBrokerRetentionAuthority,
                    &session,
                    binding,
                    observation
                ));
                authority.live_qualification().map_err(registry_error)?;
                dependencies =
                    dependencies.with_sorafs_provider_ingest_retention_authority(authority);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::ReputationFinalizedArchiveRetentionAuthority
                    .wire_id() =>
            {
                let authority = Arc::new(resolved_provider!(
                    ReputationBrokerRetentionAuthority,
                    &session,
                    binding,
                    observation
                ));
                authority.live_qualification().map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_reputation_retention_authority(authority);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn.wire_id() => {
                let boundary = Arc::new(EvidenceViewerBrokerWebAuthn {
                    provider: resolved_provider!(
                        EvidenceViewerBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                boundary
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_evidence_viewer_webauthn(boundary);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority.wire_id() => {
                let boundary = Arc::new(EvidenceViewerBrokerGrants {
                    provider: resolved_provider!(
                        EvidenceViewerBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                boundary
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_evidence_viewer_grants(boundary);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner.wire_id() => {
                let public_key = observation
                    .evidence_viewer_receipt_signer_public_key
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let signer = Arc::new(EvidenceViewerBrokerReceiptSigner {
                    provider: resolved_provider!(
                        EvidenceViewerBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                    public_key,
                });
                signer
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_evidence_viewer_receipt_signer(signer);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerErasure.wire_id() => {
                let boundary = Arc::new(EvidenceViewerBrokerErasure {
                    provider: resolved_provider!(
                        EvidenceViewerBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                boundary
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_evidence_viewer_erasure(boundary);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore.wire_id() => {
                let store = Arc::new(EvidenceViewerBrokerCheckpointStore {
                    provider: resolved_provider!(
                        EvidenceViewerBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                store
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_evidence_viewer_checkpoint_store(store);
            }
            slot if slot == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id() => {
                let store = Arc::new(ModerationCheckpointBrokerStore {
                    provider: resolved_provider!(
                        EvidenceViewerBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                });
                sorafs_node::moderation_orchestrator::ModerationRuntimeProviderV1::qualification(
                    store.as_ref(),
                )
                .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
                dependencies = dependencies.with_sorafs_moderation_checkpoint_store(store);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id() =>
            {
                let archive_binding = observation
                    .moderation_panel_notification_archive_binding
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let archive = Arc::new(ModerationPanelNotificationBrokerArchive {
                    provider: resolved_provider!(
                        EvidenceViewerBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                    archive_id: archive_binding.archive_id,
                    public_key: archive_binding.public_key,
                });
                sorafs_node::moderation_orchestrator::ModerationRuntimeProviderV1::qualification(
                    archive.as_ref(),
                )
                .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::StaleOrRevoked)?;
                dependencies =
                    dependencies.with_sorafs_moderation_panel_notification_archive(archive);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive.wire_id() =>
            {
                let archive_id = observation
                    .evidence_viewer_archive_id
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let public_key = observation
                    .evidence_viewer_archive_public_key
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let archive = Arc::new(EvidenceViewerBrokerCompactionArchive {
                    provider: resolved_provider!(
                        EvidenceViewerBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                    archive_id,
                    public_key,
                });
                archive
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies = dependencies.with_sorafs_evidence_viewer_compaction_archive(archive);
            }
            slot if slot
                == IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher.wire_id() =>
            {
                let public_key = binding
                    .evidence_viewer_transparency_publisher_public_key
                    .ok_or(IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
                let publisher = Arc::new(EvidenceViewerBrokerTransparencyPublisher {
                    provider: resolved_provider!(
                        EvidenceViewerBrokerProvider,
                        &session,
                        binding,
                        observation
                    ),
                    public_key,
                });
                publisher
                    .provider
                    .live_qualification()
                    .map_err(registry_error)?;
                dependencies =
                    dependencies.with_sorafs_evidence_viewer_transparency_publisher(publisher);
            }
            _ => {
                return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution);
            }
        }
    }
    if !appeal_finance_signers.is_empty() {
        let signers = iroha_torii::SoraFsAppealFinanceRuntimeSignersV1::new(appeal_finance_signers)
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
        dependencies = dependencies.with_sorafs_appeal_finance_runtime_signers(Arc::new(signers));
    }
    match (
        potr_gateway_signer,
        potr_provider_signer,
        potr_runtime_binding,
    ) {
        (None, None, None) => {}
        (Some(gateway), Some(provider), Some(runtime)) => {
            let gateway_binding = iroha_torii::sorafs::PotrRuntimeProviderBindingV1::try_new(
                runtime.gateway_handle,
                runtime.gateway_signer_id,
                iroha_torii::sorafs::PotrRuntimeProviderQualificationV1::new(
                    runtime.gateway_revision,
                    runtime.gateway_policy_digest,
                ),
            )
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
            let provider_binding = iroha_torii::sorafs::PotrRuntimeProviderBindingV1::try_new(
                runtime.provider_handle,
                runtime.provider_signer_id,
                iroha_torii::sorafs::PotrRuntimeProviderQualificationV1::new(
                    runtime.provider_revision,
                    runtime.provider_policy_digest,
                ),
            )
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
            let reader_bindings = iroha_torii::sorafs::PotrRuntimeReaderBindingsV1::try_new(
                runtime.reader_id,
                runtime.source_id,
                runtime.resolver_id,
            )
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
            let roles = iroha_torii::sorafs::PotrRuntimeSignerRolesV1::try_new(
                gateway,
                provider,
                gateway_binding,
                provider_binding,
                runtime.gateway_public_key,
                runtime.baseline_admission_policy.to_binding(),
                reader_bindings,
            )
            .map_err(|_| IrohaRuntimeProviderRegistryErrorV1::BindingMismatch)?;
            dependencies = dependencies.with_sorafs_potr_runtime_signer_roles(Arc::new(roles));
        }
        _ => return Err(IrohaRuntimeProviderRegistryErrorV1::IncompleteResolution),
    }
    Ok(dependencies)
}
/// Serve the stock catalog on one validated endpoint.
pub(super) fn serve(
    bindings: &IrohaRuntimeProviderBindingsV1,
    policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    backends: RuntimeProviderBrokerBackendsV1,
) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
    serve_with_policy(
        bindings,
        backends,
        &EndpointPolicy::from_server_policy(policy)?,
        Arc::new(RuntimeProviderBrokerLifecycleV1::new()),
    )
}
/// Serve the stock catalog with a fallible readiness publication.
pub(super) fn serve_with_fallible_readiness<R>(
    bindings: &IrohaRuntimeProviderBindingsV1,
    policy: &iroha_config::parameters::actual::RuntimeProviderBroker,
    backends: RuntimeProviderBrokerBackendsV1,
    lifecycle: Arc<RuntimeProviderBrokerLifecycleV1>,
    on_ready: R,
) -> Result<(), RuntimeProviderBrokerServerErrorV1>
where
    R: FnOnce() -> Result<(), RuntimeProviderBrokerReadinessErrorV1>,
{
    serve_with_policy_and_fallible_readiness(
        bindings,
        backends,
        &EndpointPolicy::from_server_policy(policy)?,
        lifecycle,
        on_ready,
    )
}
