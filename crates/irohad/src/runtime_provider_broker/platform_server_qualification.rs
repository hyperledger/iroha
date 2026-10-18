#[derive(Clone)]
struct BrokerServerStateV1 {
    decode_pool: Arc<DecodeResourcePoolV1>,
    chain_id: String,
    network_id: NetworkId,
    catalog: Vec<ProviderBindingWireV1>,
    observations: Vec<ProviderObservationWireV1>,
    backends: RuntimeProviderBrokerBackendsV1,
}
macro_rules! broker_backend {
    ($state:expr, $field:ident) => {
        ($state)
            .backends
            .$field
            .as_ref()
            .ok_or(BrokerError::BindingMismatch)?
    };
}
macro_rules! server_backend {
    ($backends:expr, $field:ident) => {
        ($backends)
            .$field
            .as_ref()
            .ok_or(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)?
    };
}
macro_rules! provider_call {
    ($provider:expr, $call:ident, $operation:expr, $payload:expr, $mutating:expr $(,)?) => {
        ($provider).session.$call(
            &($provider).binding,
            ($provider).metadata_digest,
            $operation,
            $payload,
            $mutating,
        )
    };
}
macro_rules! resolved_provider {
    ($provider:ident, $session:expr, $binding:expr, $observation:expr) => {
        $provider {
            session: Arc::clone($session),
            binding: ($binding).clone(),
            metadata_digest: ($observation).metadata_digest,
        }
    };
}
#[derive(Default)]
struct PopBrokerServerSessionV1 {
    providers: Option<iroha_torii::sorafs::pop_api::PopCredentialRuntimeProvidersV1>,
}
fn server_error(error: BrokerError) -> RuntimeProviderBrokerServerErrorV1 {
    match error {
        BrokerError::BindingMismatch | BrokerError::StaleOrRevoked => {
            RuntimeProviderBrokerServerErrorV1::BindingMismatch
        }
        BrokerError::Unavailable => RuntimeProviderBrokerServerErrorV1::EndpointUnavailable,
        BrokerError::Protocol
        | BrokerError::Rejected
        | BrokerError::Conflict
        | BrokerError::Ambiguous => RuntimeProviderBrokerServerErrorV1::Protocol,
    }
}
fn billing_external_error(
    error: sorafs_node::hedging_billing_service::HedgingBillingExternalError,
    mutating: bool,
) -> BrokerError {
    match error {
        sorafs_node::hedging_billing_service::HedgingBillingExternalError::Rejected => {
            BrokerError::Rejected
        }
        sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous
            if mutating =>
        {
            BrokerError::Ambiguous
        }
        sorafs_node::hedging_billing_service::HedgingBillingExternalError::Unavailable
        | sorafs_node::hedging_billing_service::HedgingBillingExternalError::Ambiguous => {
            BrokerError::Unavailable
        }
    }
}
fn qualification_matches(
    binding: &ProviderBindingWireV1,
    revision: u64,
    policy_digest: [u8; 32],
) -> bool {
    binding.revision == Some(revision) && binding.policy_digest == Some(policy_digest)
}
fn consensus_signer_qualification_matches(
    binding: &ProviderBindingWireV1,
    handle: &str,
    qualification: crate::runtime_provider_broker::ConsensusSignerProviderQualificationV1,
) -> bool {
    !qualification.test_marked
        && qualification.revision != 0
        && qualification.policy_digest != [0; 32]
        && handle == binding.handle
        && iroha_config::parameters::is_production_runtime_handle(handle)
        && qualification_matches(binding, qualification.revision, qualification.policy_digest)
}
fn requalify_consensus_threshold_signer_binding(
    state: &BrokerServerStateV1,
    binding: &ProviderBindingWireV1,
) -> Result<bool, BrokerError> {
    if binding.slot == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id() {
        let signer = broker_backend!(state, global_beacon_partial_signer);
        let qualification = signer.qualification().map_err(|error| match error {
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Unavailable => BrokerError::Unavailable,
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected => BrokerError::StaleOrRevoked,
        })?;
        if !consensus_signer_qualification_matches(binding, signer.handle(), qualification) {
            return Err(BrokerError::StaleOrRevoked);
        }
        let qualification_after = signer.qualification().map_err(|error| match error {
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Unavailable => BrokerError::Unavailable,
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected => BrokerError::StaleOrRevoked,
        })?;
        if signer.handle() != binding.handle || qualification_after != qualification {
            return Err(BrokerError::StaleOrRevoked);
        }
        return Ok(true);
    }
    Ok(false)
}
fn qualify_native_transaction_signer_backend(
    network_id: NetworkId,
    binding: &ProviderBindingWireV1,
    backends: &RuntimeProviderBrokerBackendsV1,
) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
    let exact = native_transaction_signer_binding_from_wire(binding)
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    match exact.role() {
        iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome => {
            let provider = server_backend!(backends, proof_outcome_transaction_signer);
            iroha_torii::qualify_sorafs_proof_outcome_transaction_signer_v1(
                network_id,
                exact,
                Arc::clone(provider),
            )
            .map(drop)
            .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        }
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair => {
            let provider = server_backend!(backends, repair_transaction_signer);
            iroha_torii::qualify_sorafs_repair_transaction_signer_v1(
                network_id,
                exact,
                Arc::clone(provider),
            )
            .map(drop)
            .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        }
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Reserve => {
            let provider = server_backend!(backends, reserve_transaction_signer);
            iroha_torii::qualify_sorafs_reserve_transaction_signer_v1(
                network_id,
                exact,
                Arc::clone(provider),
            )
            .map(drop)
            .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        }
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Orderbook => {
            let provider = server_backend!(backends, orderbook_transaction_signer);
            iroha_torii::qualify_sorafs_orderbook_transaction_signer_v1(
                network_id,
                exact,
                Arc::clone(provider),
            )
            .map(drop)
            .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        }
    }
}
fn appeal_finance_signer_backend<'a>(
    backends: &'a RuntimeProviderBrokerBackendsV1,
    handle: &str,
) -> Result<
    &'a Arc<dyn iroha_torii::SoraFsAppealFinanceTransactionSigner>,
    RuntimeProviderBrokerServerErrorV1,
> {
    let mut matching = backends
        .appeal_finance_transaction_signers
        .iter()
        .filter(|signer| signer.handle() == handle);
    let signer = matching
        .next()
        .ok_or(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)?;
    if matching.next().is_some() {
        return Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch);
    }
    Ok(signer)
}
fn qualify_moderation_runtime_backend(
    binding: &ProviderBindingWireV1,
    provider: &dyn sorafs_node::moderation_orchestrator::ModerationRuntimeProviderV1,
) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
    let expected = qualification_from_binding(binding)
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    let expected =
        sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
            expected.revision,
            expected.policy_digest,
        );
    sorafs_node::moderation_orchestrator::qualify_moderation_runtime_provider_v1(
        &binding.handle,
        expected,
        provider,
    )
    .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    let requalification = provider
        .qualification()
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    if provider.handle() != binding.handle || requalification != expected {
        return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
    }
    Ok(())
}
fn qualify_reputation_runtime_backend<P>(
    binding: &ProviderBindingWireV1,
    provider: &P,
) -> Result<(), RuntimeProviderBrokerServerErrorV1>
where
    P: sorafs_node::reputation::runtime::ReputationRuntimeProviderV1 + ?Sized,
{
    let expected = reputation_qualification_from_binding(binding)
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    let qualification = provider
        .qualification()
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    if provider.handle() != binding.handle
        || !iroha_config::parameters::is_production_runtime_handle(provider.handle())
        || qualification != expected
    {
        return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
    }
    let qualification_after = provider
        .qualification()
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    if provider.handle() != binding.handle || qualification_after != qualification {
        return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
    }
    Ok(())
}
fn qualify_billing_runtime_backend<P>(
    binding: &ProviderBindingWireV1,
    provider: &P,
) -> Result<(), RuntimeProviderBrokerServerErrorV1>
where
    P: sorafs_node::hedging_billing_service::HedgingBillingRuntimeProviderV1 + ?Sized,
{
    let expected = qualification_from_binding(binding)
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    let expected =
        sorafs_node::hedging_billing_service::HedgingBillingRuntimeProviderQualificationV1::new(
            expected.revision,
            expected.policy_digest,
        );
    sorafs_node::hedging_billing_service::qualify_hedging_billing_runtime_provider_v1(
        &binding.handle,
        expected,
        provider,
    )
    .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    sorafs_node::hedging_billing_service::revalidate_hedging_billing_runtime_provider_v1(
        &binding.handle,
        expected,
        provider,
    )
    .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)
}
fn make_server_observation(
    network_id: NetworkId,
    binding: &ProviderBindingWireV1,
    backends: &RuntimeProviderBrokerBackendsV1,
) -> Result<ProviderObservationWireV1, RuntimeProviderBrokerServerErrorV1> {
    let mut signer_metadata = None;
    let mut governance_request_ingress_qualification = None;
    let mut moderation_quarantine_active_key_id = None;
    let mut provider_ingest_signer_binding = None;
    let mut provider_ingest_source_provider_ids = Vec::new();
    let mut potr_signer_public_key = Vec::new();
    let mut evidence_viewer_receipt_signer_public_key = None;
    let mut evidence_viewer_archive_id = None;
    let mut evidence_viewer_archive_public_key = None;
    let mut moderation_checkpoint_attestation_public_key = None;
    let mut moderation_panel_notification_archive_binding = None;
    match binding.runtime_slot().map_err(server_error)?.wire_id() {
        slot if slot
            == IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry.wire_id() =>
        {
            let backend = server_backend!(backends, bootle_lantern_issuance);
            let expected_bindings = bootle_lantern_bindings_from_wire(binding)
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let qualification = backend
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let live_bindings = backend
                .bindings()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if backend.handle() != binding.handle
                || !iroha_config::parameters::is_production_runtime_handle(backend.handle())
                || !qualification_matches(
                    binding,
                    qualification.revision,
                    qualification.policy_digest,
                )
                || live_bindings != expected_bindings
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let qualification_after = backend
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let bindings_after = backend
                .bindings()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if backend.handle() != binding.handle
                || qualification_after != qualification
                || bindings_after != live_bindings
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id() => {
            validate_stream_token_backend_metadata(binding, backends)?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id() => {
            let signer = appeal_finance_signer_backend(backends, &binding.handle)?;
            let exact = binding
                .appeal_finance_signer_binding
                .as_ref()
                .ok_or(RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let qualification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let public_key = signer
                .public_key()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if signer.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision,
                    qualification.policy_digest,
                )
                || public_key != exact.public_key
                || iroha_data_model::account::AccountId::new(public_key.clone()) != exact.authority
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let public_key_after = signer
                .public_key()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if signer.handle() != binding.handle
                || requalification != qualification
                || public_key_after != public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint.wire_id() => {
            let checkpoint = server_backend!(backends, appeal_finance_checkpoint);
            let exact = binding
                .appeal_finance_checkpoint_binding
                .as_ref()
                .ok_or(RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let public_key = exact_ed25519_public_key_bytes(&exact.public_key)
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let identity = checkpoint
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity.provider_handle != binding.handle
                || identity.public_key != public_key
                || !qualification_matches(
                    binding,
                    identity.qualification.revision,
                    identity.qualification.policy_digest,
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let identity_after = checkpoint
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity_after != identity {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry.wire_id() => {
            let registry = server_backend!(backends, pop_credential_provider_registry);
            let qualification = registry
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if registry.handle() != binding.handle
                || !iroha_config::parameters::is_production_runtime_handle(registry.handle())
                || !qualification_matches(
                    binding,
                    qualification.revision,
                    qualification.policy_digest,
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let qualification_after = registry
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if registry.handle() != binding.handle || qualification_after != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::PotrGatewaySigner.wire_id() => {
            let signer = server_backend!(backends, potr_gateway_signer);
            let runtime = binding
                .potr_runtime_binding
                .as_ref()
                .ok_or(RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let qualification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let public_key = signer
                .public_key()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if signer.handle() != binding.handle
                || signer.signer_id() != runtime.gateway_signer_id
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
                || public_key != runtime.gateway_public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let public_key_after = signer
                .public_key()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if signer.handle() != binding.handle
                || signer.signer_id() != runtime.gateway_signer_id
                || requalification != qualification
                || public_key_after != public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            potr_signer_public_key = public_key.to_vec();
        }
        slot if slot == IrohaRuntimeProviderSlotV1::PotrProviderSigner.wire_id() => {
            let signer = server_backend!(backends, potr_provider_signer);
            let runtime = binding
                .potr_runtime_binding
                .as_ref()
                .ok_or(RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let qualification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let provider_id = signer
                .provider_id()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let public_key = signer
                .public_key()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if signer.handle() != binding.handle
                || signer.signer_id() != runtime.provider_signer_id
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
                || provider_id != runtime.baseline_admission_policy.provider_id
                || public_key.is_empty()
                || public_key.len() > MAX_POTR_PUBLIC_KEY_BYTES_V1
                || iroha_crypto::PublicKey::from_bytes(iroha_crypto::Algorithm::MlDsa, &public_key)
                    .is_err()
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let provider_id_after = signer
                .provider_id()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let public_key_after = signer
                .public_key()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if signer.handle() != binding.handle
                || signer.signer_id() != runtime.provider_signer_id
                || requalification != qualification
                || provider_id_after != provider_id
                || public_key_after != public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            potr_signer_public_key = public_key;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GatewayAcmeClient.wire_id() => {
            let client = server_backend!(backends, gateway_acme_client);
            let identity = client
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity.test_marked
                || !iroha_config::parameters::is_production_runtime_handle(
                    &identity.provider_handle,
                )
                || identity.provider_handle != binding.handle
                || !qualification_matches(binding, identity.revision, identity.policy_digest)
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let identity_after = client
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity_after != identity {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GatewayComplianceFeedTransport.wire_id() => {
            let transport = server_backend!(backends, gateway_compliance_feed_transport);
            let identity = transport
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity.test_marked
                || !iroha_config::parameters::is_production_runtime_handle(
                    &identity.provider_handle,
                )
                || identity.provider_handle != binding.handle
                || !qualification_matches(binding, identity.revision, identity.policy_digest)
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let identity_after = transport
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity_after != identity {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot
            == IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter.wire_id() =>
        {
            let submitter = server_backend!(backends, reputation_journal_transaction_submitter);
            qualify_reputation_runtime_backend(binding, submitter.as_ref())?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ReputationThresholdSigner.wire_id() => {
            let signer = server_backend!(backends, reputation_threshold_signer);
            qualify_reputation_runtime_backend(binding, signer.as_ref())?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ReputationGovernanceDag.wire_id() => {
            let governance_dag = server_backend!(backends, reputation_governance_dag);
            qualify_reputation_runtime_backend(binding, governance_dag.as_ref())?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint.wire_id() => {
            let checkpoint = server_backend!(backends, reputation_journal_checkpoint);
            qualify_reputation_runtime_backend(binding, checkpoint.as_ref())?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::BillingFinalizedQuery.wire_id() => {
            let query = server_backend!(backends, billing_finalized_query);
            qualify_billing_runtime_backend(binding, query.as_ref())?;
            query
                .check_readiness()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let identity = query
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity.handle != binding.handle || !query.supplies_period_closes() {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let identity_after = query
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity_after != identity {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::BillingJournalVerifier.wire_id() => {
            let verifier = server_backend!(backends, billing_journal_verifier);
            qualify_billing_runtime_backend(binding, verifier.as_ref())?;
            verifier
                .check_readiness()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let identity = verifier
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity.handle != binding.handle {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let identity_after = verifier
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity_after != identity {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::BillingStatementSigner.wire_id() => {
            let signer = server_backend!(backends, billing_statement_signer);
            qualify_billing_runtime_backend(binding, signer.as_ref())?;
            signer
                .check_readiness()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let identity = signer
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity.provider_handle != binding.handle
                || !validate_billing_public_identity_text(
                    &identity.signer_id,
                    sorafs_node::hedging_billing_service::BILLING_SIGNER_ID_MAX_BYTES_V1,
                )
                || iroha_crypto::ed25519_parse_public_key(&identity.public_key).is_err()
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let identity_after = signer
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity_after != identity {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::BillingStatementPublisher.wire_id() => {
            let publisher = server_backend!(backends, billing_statement_publisher);
            qualify_billing_runtime_backend(binding, publisher.as_ref())?;
            publisher
                .check_readiness()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let identity = publisher
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity.provider_handle != binding.handle
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
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let identity_after = publisher
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity_after != identity {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::BillingAcknowledgementAuthority.wire_id() => {
            let authority = server_backend!(backends, billing_acknowledgement_authority);
            qualify_billing_runtime_backend(binding, authority.as_ref())?;
            authority
                .check_readiness()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let identity = authority
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity.provider_handle != binding.handle {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let identity_after = authority
                .identity()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if identity_after != identity {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::BillingEpochWitnessStore.wire_id() => {
            let store = server_backend!(backends, billing_epoch_witness_store);
            qualify_billing_runtime_backend(binding, store.as_ref())?;
            store
                .check_readiness()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive.wire_id() => {
            let archive = server_backend!(backends, por_finalized_replay_archive);
            let expected = por_replay_archive_exact_binding(binding).map_err(server_error)?;
            let observed = archive
                .binding()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if !iroha_config::parameters::is_production_runtime_handle(archive.runtime_handle())
                || archive.runtime_handle() != binding.handle
                || observed != expected
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            archive
                .check_readiness()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let observed_after = archive
                .binding()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if archive.runtime_handle() != binding.handle || observed_after != observed {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider.wire_id() => {
            let provider = server_backend!(backends, privacy_cycle_prf_provider);
            let qualification = provider
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if provider.handle() != binding.handle
                || !iroha_config::parameters::is_production_runtime_handle(provider.handle())
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let qualification_after = provider
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if provider.handle() != binding.handle || qualification_after != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::PrivacyReleaseAnchor.wire_id() => {
            let anchor = server_backend!(backends, privacy_release_anchor);
            let qualification = anchor
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if anchor.handle() != binding.handle
                || !iroha_config::parameters::is_production_runtime_handle(anchor.handle())
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let qualification_after = anchor
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if anchor.handle() != binding.handle || qualification_after != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::TransparencyLeaderLease.wire_id() => {
            let provider = server_backend!(backends, transparency_leader_lease_provider);
            let qualification = provider
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if provider.handle() != binding.handle
                || !iroha_config::parameters::is_production_runtime_handle(provider.handle())
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let qualification_after = provider
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if provider.handle() != binding.handle || qualification_after != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher.wire_id() => {
            let publisher = server_backend!(backends, fenced_privacy_publisher);
            let qualification = publisher
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if publisher.handle() != binding.handle
                || !iroha_config::parameters::is_production_runtime_handle(publisher.handle())
                || !qualification_matches(
                    binding,
                    qualification.revision,
                    qualification.policy_digest,
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let qualification_after = publisher
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if publisher.handle() != binding.handle || qualification_after != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader.wire_id() => {
            let reader = server_backend!(backends, fenced_privacy_head_reader);
            let qualification = reader
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if reader.handle() != binding.handle
                || !iroha_config::parameters::is_production_runtime_handle(reader.handle())
                || !qualification_matches(
                    binding,
                    qualification.revision,
                    qualification.policy_digest,
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let qualification_after = reader
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if reader.handle() != binding.handle || qualification_after != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper.wire_id() => {
            let key_wrapper = server_backend!(backends, moderation_quarantine_key_wrapper);
            let qualification = key_wrapper
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if key_wrapper.provider_handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let active_key_id = key_wrapper.active_key_id().to_owned();
            validate_moderation_quarantine_key_id(&active_key_id)
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let requalification = key_wrapper
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if key_wrapper.provider_handle() != binding.handle
                || requalification != qualification
                || key_wrapper.active_key_id() != active_key_id
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            moderation_quarantine_active_key_id = Some(active_key_id);
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id() => {
            let signer = server_backend!(backends, governance_dag_signer);
            let expected_peer_id = binding
                .governance_dag_publisher_peer_id
                .as_deref()
                .ok_or(RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let expected_public_key = binding
                .governance_dag_publisher_public_key
                .ok_or(RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let qualification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let publisher_peer_id = signer.publisher_peer_id().to_vec();
            let public_key = signer.public_key();
            if signer.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision,
                    qualification.policy_digest,
                )
                || publisher_peer_id.as_slice() != expected_peer_id
                || public_key != expected_public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let qualification_after = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if signer.handle() != binding.handle
                || qualification_after != qualification
                || signer.publisher_peer_id() != publisher_peer_id.as_slice()
                || signer.public_key() != public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            signer_metadata = Some(SignerMetadataWireV1 {
                publisher_peer_id,
                public_key,
            });
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator.wire_id() =>
        {
            let authenticator =
                if slot == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id() {
                    backends.governance_dag_ipfs_authenticator.as_ref()
                } else {
                    backends.governance_dag_head_authenticator.as_ref()
                }
                .ok_or(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch)?;
            let expected_binding =
                governance_request_ingress_binding_from_provider_binding(binding)
                    .map_err(server_error)?;
            let qualification = authenticator
                .ingress_qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if authenticator.handle() != binding.handle
                || !iroha_config::parameters::is_production_runtime_handle(authenticator.handle())
                || !qualification_matches(
                    binding,
                    qualification.provider().revision,
                    qualification.provider().policy_digest,
                )
                || qualification.binding() != expected_binding
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = authenticator
                .ingress_qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if authenticator.handle() != binding.handle || requalification != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            governance_request_ingress_qualification = Some(
                governance_request_ingress_qualification_to_wire(qualification),
            );
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore.wire_id() => {
            let store = server_backend!(backends, governance_dag_checkpoint_store);
            let qualification = store
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if store.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision,
                    qualification.policy_digest,
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ModerationTransactionSigner.wire_id() => {
            let signer = server_backend!(backends, moderation_transaction_signer);
            qualify_moderation_runtime_backend(binding, signer.as_ref())?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id() => {
            let boundary = server_backend!(backends, moderation_settlement_handoff);
            qualify_moderation_runtime_backend(binding, boundary.as_ref())?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id() => {
            let boundary = server_backend!(backends, moderation_publication_handoff);
            qualify_moderation_runtime_backend(binding, boundary.as_ref())?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ModerationPanelNotification.wire_id() => {
            let boundary = server_backend!(backends, moderation_panel_notification);
            qualify_moderation_runtime_backend(binding, boundary.as_ref())?;
        }
        slot if native_transaction_signer_role_for_slot(slot).is_some() => {
            qualify_native_transaction_signer_backend(network_id, binding, backends)?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id() => {
            let exact =
                soracloud_runtime_signer_binding_from_wire(binding).map_err(server_error)?;
            crate::soracloud_runtime_signer::qualify_soracloud_runtime_mutation_signer_v1(
                exact,
                Arc::clone(server_backend!(backends, soracloud_runtime_mutation_signer)),
            )
            .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id() => {
            let source = server_backend!(backends, provider_ingest_authenticated_source);
            let qualification = source
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            source
                .check_readiness()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if source.runtime_handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision,
                    qualification.policy_digest,
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            provider_ingest_source_provider_ids = source.source_provider_ids().to_vec();
        }
        slot if slot
            == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner.wire_id() =>
        {
            let resolver = server_backend!(backends, provider_ingest_signer_resolver);
            let qualification = resolver
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let signer_binding = resolver
                .signer_binding()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            resolver
                .check_readiness()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let expected =
                provider_ingest_expected_signer_binding(binding).map_err(server_error)?;
            let handle_matches = if slot
                == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver.wire_id()
            {
                resolver.runtime_handle() == binding.handle
                    && qualification_matches(
                        binding,
                        qualification.revision,
                        qualification.policy_digest,
                    )
            } else {
                signer_binding.runtime_handle == binding.handle
                    && qualification_matches(
                        binding,
                        signer_binding.qualification.adapter_revision,
                        signer_binding.qualification.signer_policy.policy_digest,
                    )
            };
            if !handle_matches || signer_binding != expected {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            provider_ingest_signer_binding = Some(
                ProviderIngestSignerBindingWireV1::try_from_binding(&signer_binding)
                    .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?,
            );
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore.wire_id() => {
            let store = server_backend!(backends, provider_ingest_checkpoint_store);
            let qualification = store
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if store.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision,
                    qualification.policy_digest,
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ProviderIngestRetentionAuthority.wire_id() => {
            let authority = server_backend!(backends, provider_ingest_retention_authority);
            let qualification = authority
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if authority.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot
            == IrohaRuntimeProviderSlotV1::ReputationFinalizedArchiveRetentionAuthority
                .wire_id() =>
        {
            let authority =
                server_backend!(backends, reputation_finalized_archive_retention_authority);
            let qualification = authority
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if authority.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = authority
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if authority.handle() != binding.handle || requalification != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn.wire_id() => {
            let boundary = server_backend!(backends, evidence_viewer_webauthn);
            let qualification = boundary
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if boundary.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = boundary
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if boundary.handle() != binding.handle || requalification != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority.wire_id() => {
            let boundary = server_backend!(backends, evidence_viewer_grants);
            let qualification = boundary
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if boundary.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = boundary
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if boundary.handle() != binding.handle || requalification != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner.wire_id() => {
            let signer = server_backend!(backends, evidence_viewer_receipt_signer);
            let qualification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let public_key = signer.public_key();
            if signer.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
                || Some(public_key) != binding.evidence_viewer_receipt_signer_public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if signer.handle() != binding.handle
                || requalification != qualification
                || signer.public_key() != public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            evidence_viewer_receipt_signer_public_key = Some(public_key);
        }
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerErasure.wire_id() => {
            let boundary = server_backend!(backends, evidence_viewer_erasure);
            let qualification = boundary
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if boundary.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = boundary
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if boundary.handle() != binding.handle || requalification != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore.wire_id() => {
            let store = server_backend!(backends, evidence_viewer_checkpoint_store);
            let qualification = store
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if store.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = store
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if store.handle() != binding.handle || requalification != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id() => {
            let store = server_backend!(backends, moderation_checkpoint_store);
            qualify_moderation_runtime_backend(binding, store.as_ref())?;
            let public_key = store.attestation_public_key();
            if Some(public_key) != binding.moderation_checkpoint_attestation_public_key
                || iroha_crypto::ed25519_parse_public_key(&public_key).is_err()
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            moderation_checkpoint_attestation_public_key = Some(public_key);
        }
        slot if slot
            == IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id() =>
        {
            let archive = server_backend!(backends, moderation_panel_notification_archive);
            let qualification = archive
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let archive_id = archive.archive_id();
            let public_key = archive.signing_public_key();
            let expected = binding
                .moderation_panel_notification_archive_binding
                .ok_or(RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if archive.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
                || archive_id != expected.archive_id
                || public_key != expected.public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = archive
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if archive.handle() != binding.handle
                || requalification != qualification
                || archive.archive_id() != archive_id
                || archive.signing_public_key() != public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            moderation_panel_notification_archive_binding = Some(expected);
        }
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive.wire_id() => {
            let archive = server_backend!(backends, evidence_viewer_compaction_archive);
            let qualification = archive
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let archive_id = archive.archive_id();
            let public_key = archive.signing_public_key();
            if archive.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
                || Some(archive_id) != binding.evidence_viewer_archive_id
                || Some(public_key) != binding.evidence_viewer_archive_public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = archive
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if archive.handle() != binding.handle
                || requalification != qualification
                || archive.archive_id() != archive_id
                || archive.signing_public_key() != public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            evidence_viewer_archive_id = Some(archive_id);
            evidence_viewer_archive_public_key = Some(public_key);
        }
        slot if slot
            == IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher.wire_id() =>
        {
            let publisher = server_backend!(backends, evidence_viewer_transparency_publisher);
            let qualification = publisher
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            let public_key = publisher.public_key();
            if publisher.handle() != binding.handle
                || !qualification_matches(
                    binding,
                    qualification.revision(),
                    qualification.policy_digest(),
                )
                || Some(public_key) != binding.evidence_viewer_transparency_publisher_public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let requalification = publisher
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if publisher.handle() != binding.handle
                || requalification != qualification
                || publisher.public_key() != public_key
            {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id() => {
            let signer = server_backend!(backends, global_beacon_partial_signer);
            let qualification = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if !consensus_signer_qualification_matches(binding, signer.handle(), qualification) {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
            let qualification_after = signer
                .qualification()
                .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
            if signer.handle() != binding.handle || qualification_after != qualification {
                return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
            }
        }
        _ => return Err(RuntimeProviderBrokerServerErrorV1::UnsupportedRole),
    }
    let metadata_digest = provider_metadata_digest(
        &signer_metadata,
        &governance_request_ingress_qualification,
        &moderation_quarantine_active_key_id,
        &provider_ingest_signer_binding,
        &provider_ingest_source_provider_ids,
        &potr_signer_public_key,
        &evidence_viewer_receipt_signer_public_key,
        &evidence_viewer_archive_id,
        &evidence_viewer_archive_public_key,
        &moderation_checkpoint_attestation_public_key,
        &moderation_panel_notification_archive_binding,
    )
    .map_err(server_error)?;
    let observation = ProviderObservationWireV1 {
        binding: binding.clone(),
        signer_metadata,
        governance_request_ingress_qualification,
        moderation_quarantine_active_key_id,
        provider_ingest_signer_binding,
        provider_ingest_source_provider_ids,
        potr_signer_public_key,
        evidence_viewer_receipt_signer_public_key,
        evidence_viewer_archive_id,
        evidence_viewer_archive_public_key,
        moderation_checkpoint_attestation_public_key,
        moderation_panel_notification_archive_binding,
        metadata_digest,
    };
    validate_observation(binding, &observation).map_err(server_error)?;
    Ok(observation)
}
fn validate_exact_backend_set(
    catalog: &[ProviderBindingWireV1],
    backends: &RuntimeProviderBrokerBackendsV1,
) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
    let requested = |slot: IrohaRuntimeProviderSlotV1| {
        catalog.iter().any(|binding| binding.slot == slot.wire_id())
    };
    let requested_count = |slot: IrohaRuntimeProviderSlotV1| {
        catalog
            .iter()
            .filter(|binding| binding.slot == slot.wire_id())
            .count()
    };
    let wants_resolver =
        requested(IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver);
    let wants_signer = requested(IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner);
    if wants_resolver != wants_signer {
        return Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch);
    }
    let requested_appeal_signers =
        requested_count(IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner);
    let mut injected_appeal_handles = backends
        .appeal_finance_transaction_signers
        .iter()
        .map(|signer| signer.handle())
        .collect::<Vec<_>>();
    injected_appeal_handles.sort_unstable();
    if requested_appeal_signers != injected_appeal_handles.len()
        || injected_appeal_handles
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || catalog
            .iter()
            .filter(|binding| {
                binding.slot == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id()
            })
            .any(|binding| {
                injected_appeal_handles
                    .binary_search(&binding.handle.as_str())
                    .is_err()
            })
    {
        return Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch);
    }
    let wants_potr_gateway = requested(IrohaRuntimeProviderSlotV1::PotrGatewaySigner);
    let wants_potr_provider = requested(IrohaRuntimeProviderSlotV1::PotrProviderSigner);
    if wants_potr_gateway != wants_potr_provider {
        return Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch);
    }
    if let (Some(gateway), Some(provider)) = (
        backends.potr_gateway_signer.as_ref(),
        backends.potr_provider_signer.as_ref(),
    ) && Arc::as_ptr(gateway).cast::<()>() == Arc::as_ptr(provider).cast::<()>()
    {
        return Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch);
    }
    let exact_backend_set =
        requested(IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry)
            == backends.bootle_lantern_issuance.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper)
                == backends.moderation_quarantine_key_wrapper.is_some()
            && requested(IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider)
                == backends.privacy_cycle_prf_provider.is_some()
            && requested(IrohaRuntimeProviderSlotV1::PrivacyReleaseAnchor)
                == backends.privacy_release_anchor.is_some()
            && requested(IrohaRuntimeProviderSlotV1::TransparencyLeaderLease)
                == backends.transparency_leader_lease_provider.is_some()
            && requested(IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher)
                == backends.fenced_privacy_publisher.is_some()
            && requested(IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader)
                == backends.fenced_privacy_head_reader.is_some()
            && requested(IrohaRuntimeProviderSlotV1::GovernanceDagSigner)
                == backends.governance_dag_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator)
                == backends.governance_dag_ipfs_authenticator.is_some()
            && requested(IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator)
                == backends.governance_dag_head_authenticator.is_some()
            && requested(IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore)
                == backends.governance_dag_checkpoint_store.is_some()
            && requested(IrohaRuntimeProviderSlotV1::StreamTokenSigner)
                == backends.stream_token_signer_client.is_some()
            && requested(IrohaRuntimeProviderSlotV1::StreamTokenSigner)
                == backends.stream_token_state_observer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint)
                == backends.appeal_finance_checkpoint.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ProofOutcomeTransactionSigner)
                == backends.proof_outcome_transaction_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::RepairTransactionSigner)
                == backends.repair_transaction_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ReserveTransactionSigner)
                == backends.reserve_transaction_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::OrderbookTransactionSigner)
                == backends.orderbook_transaction_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ModerationTransactionSigner)
                == backends.moderation_transaction_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff)
                == backends.moderation_settlement_handoff.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff)
                == backends.moderation_publication_handoff.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ModerationPanelNotification)
                == backends.moderation_panel_notification.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource)
                == backends.provider_ingest_authenticated_source.is_some()
            && wants_resolver == backends.provider_ingest_signer_resolver.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore)
                == backends.provider_ingest_checkpoint_store.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ProviderIngestRetentionAuthority)
                == backends.provider_ingest_retention_authority.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ReputationFinalizedArchiveRetentionAuthority)
                == backends
                    .reputation_finalized_archive_retention_authority
                    .is_some()
            && requested(IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter)
                == backends.reputation_journal_transaction_submitter.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ReputationThresholdSigner)
                == backends.reputation_threshold_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ReputationGovernanceDag)
                == backends.reputation_governance_dag.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint)
                == backends.reputation_journal_checkpoint.is_some()
            && requested(IrohaRuntimeProviderSlotV1::BillingFinalizedQuery)
                == backends.billing_finalized_query.is_some()
            && requested(IrohaRuntimeProviderSlotV1::BillingJournalVerifier)
                == backends.billing_journal_verifier.is_some()
            && requested(IrohaRuntimeProviderSlotV1::BillingStatementSigner)
                == backends.billing_statement_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::BillingStatementPublisher)
                == backends.billing_statement_publisher.is_some()
            && requested(IrohaRuntimeProviderSlotV1::BillingAcknowledgementAuthority)
                == backends.billing_acknowledgement_authority.is_some()
            && requested(IrohaRuntimeProviderSlotV1::BillingEpochWitnessStore)
                == backends.billing_epoch_witness_store.is_some()
            && requested(IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry)
                == backends.pop_credential_provider_registry.is_some()
            && wants_potr_gateway == backends.potr_gateway_signer.is_some()
            && wants_potr_provider == backends.potr_provider_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::GatewayAcmeClient)
                == backends.gateway_acme_client.is_some()
            && requested(IrohaRuntimeProviderSlotV1::GatewayComplianceFeedTransport)
                == backends.gateway_compliance_feed_transport.is_some()
            && requested(IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive)
                == backends.por_finalized_replay_archive.is_some()
            && requested(IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn)
                == backends.evidence_viewer_webauthn.is_some()
            && requested(IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority)
                == backends.evidence_viewer_grants.is_some()
            && requested(IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner)
                == backends.evidence_viewer_receipt_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::EvidenceViewerErasure)
                == backends.evidence_viewer_erasure.is_some()
            && requested(IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore)
                == backends.evidence_viewer_checkpoint_store.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ModerationCheckpointStore)
                == backends.moderation_checkpoint_store.is_some()
            && requested(IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive)
                == backends.moderation_panel_notification_archive.is_some()
            && requested(IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive)
                == backends.evidence_viewer_compaction_archive.is_some()
            && requested(IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher)
                == backends.evidence_viewer_transparency_publisher.is_some()
            && requested(IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner)
                == backends.soracloud_runtime_mutation_signer.is_some()
            && requested(IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner)
                == backends.global_beacon_partial_signer.is_some();
    if !exact_backend_set {
        return Err(RuntimeProviderBrokerServerErrorV1::BackendSetMismatch);
    }
    Ok(())
}
#[cfg(test)]
fn prepare_server_state(
    bindings: &IrohaRuntimeProviderBindingsV1,
    backends: RuntimeProviderBrokerBackendsV1,
    decode_pool: Arc<DecodeResourcePoolV1>,
) -> Result<BrokerServerStateV1, RuntimeProviderBrokerServerErrorV1> {
    let catalog = bindings
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    validate_exact_backend_set(&catalog, &backends)?;
    let observations = catalog
        .iter()
        .map(|binding| make_server_observation(*bindings.network_id(), binding, &backends))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BrokerServerStateV1 {
        decode_pool,
        chain_id: bindings.chain_id().to_owned(),
        network_id: *bindings.network_id(),
        catalog,
        observations,
        backends,
    })
}
#[derive(Debug)]
enum StartupQualificationErrorV1 {
    Cancelled,
    Failed(RuntimeProviderBrokerServerErrorV1),
}
fn prepare_server_state_for_lifecycle(
    bindings: &IrohaRuntimeProviderBindingsV1,
    backends: RuntimeProviderBrokerBackendsV1,
    lifecycle: &Arc<RuntimeProviderBrokerLifecycleV1>,
    decode_pool: Arc<DecodeResourcePoolV1>,
) -> Result<BrokerServerStateV1, StartupQualificationErrorV1> {
    let catalog = bindings
        .iter()
        .map(ProviderBindingWireV1::try_from_binding)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            StartupQualificationErrorV1::Failed(RuntimeProviderBrokerServerErrorV1::BindingMismatch)
        })?;
    validate_exact_backend_set(&catalog, &backends).map_err(StartupQualificationErrorV1::Failed)?;
    let observations = catalog
        .iter()
        .map(|binding| {
            let Some(_qualification_permit) = lifecycle.try_begin_qualification() else {
                return Err(StartupQualificationErrorV1::Cancelled);
            };
            make_server_observation(*bindings.network_id(), binding, &backends)
                .map_err(StartupQualificationErrorV1::Failed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BrokerServerStateV1 {
        decode_pool,
        chain_id: bindings.chain_id().to_owned(),
        network_id: *bindings.network_id(),
        catalog,
        observations,
        backends,
    })
}
fn requalify_server_state(
    state: &BrokerServerStateV1,
    lifecycle: &Arc<RuntimeProviderBrokerLifecycleV1>,
) -> Result<(), StartupQualificationErrorV1> {
    if lifecycle.shutdown_requested() {
        return Err(StartupQualificationErrorV1::Cancelled);
    }
    validate_exact_backend_set(&state.catalog, &state.backends)
        .map_err(StartupQualificationErrorV1::Failed)?;
    let observations = state
        .catalog
        .iter()
        .map(|binding| {
            let Some(_qualification_permit) = lifecycle.try_begin_qualification() else {
                return Err(StartupQualificationErrorV1::Cancelled);
            };
            make_server_observation(state.network_id, binding, &state.backends)
                .map_err(StartupQualificationErrorV1::Failed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if observations != state.observations {
        return Err(StartupQualificationErrorV1::Failed(
            RuntimeProviderBrokerServerErrorV1::BindingMismatch,
        ));
    }
    Ok(())
}
/// Immutable endpoint identity and admitted-observer operation policy.
#[derive(Clone, Debug)]
pub(super) struct EndpointPolicy {
    path: PathBuf,
    expected_service_uid: u32,
    socket_mode: u32,
    verify_all_ancestors: bool,
    observer_operation_timeout: Duration,
}
impl EndpointPolicy {
    /// Return the same-service-UID production policy at one validated public path.
    pub(super) fn production(
        endpoint_path: &iroha_config::parameters::actual::RuntimeProviderBrokerEndpointPath,
    ) -> Self {
        Self::for_service_uid(
            endpoint_path.as_path().to_path_buf(),
            rustix::process::geteuid().as_raw(),
            true,
        )
    }
    fn for_service_uid(
        path: PathBuf,
        expected_service_uid: u32,
        verify_all_ancestors: bool,
    ) -> Self {
        Self {
            path,
            expected_service_uid,
            socket_mode: STOCK_BROKER_SOCKET_MODE_V1,
            verify_all_ancestors,
            observer_operation_timeout: BROKER_IO_TIMEOUT_V1,
        }
    }
    pub(super) fn from_server_policy(
        config: &iroha_config::parameters::actual::RuntimeProviderBroker,
    ) -> Result<Self, RuntimeProviderBrokerServerErrorV1> {
        if config.observer_operation_timeout.is_zero()
            || config.observer_operation_timeout > BROKER_IO_TIMEOUT_V1
        {
            return Err(RuntimeProviderBrokerServerErrorV1::Protocol);
        }
        let mut policy = Self::production(&config.endpoint_path);
        policy.observer_operation_timeout = config.observer_operation_timeout;
        Ok(policy)
    }
    #[cfg(test)]
    fn for_test(path: PathBuf) -> Self {
        Self::for_service_uid(path, rustix::process::geteuid().as_raw(), false)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}
fn endpoint_identity(policy: &EndpointPolicy) -> Result<SocketIdentity, BrokerError> {
    let metadata = fs::symlink_metadata(&policy.path).map_err(|_| BrokerError::Unavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != policy.expected_service_uid
        || metadata.mode() & 0o7777 != policy.socket_mode
        || metadata.nlink() != 1
    {
        return Err(BrokerError::Unavailable);
    }
    let parent = policy.path.parent().ok_or(BrokerError::Unavailable)?;
    verify_directory(parent, policy.expected_service_uid, false)?;
    if policy.verify_all_ancestors {
        for ancestor in parent.ancestors().skip(1) {
            verify_directory(ancestor, policy.expected_service_uid, true)?;
        }
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}
fn verify_directory(
    path: &Path,
    expected_service_uid: u32,
    allow_root_owner: bool,
) -> Result<(), BrokerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BrokerError::Unavailable)?;
    let owner_is_trusted =
        metadata.uid() == expected_service_uid || (allow_root_owner && metadata.uid() == 0);
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !owner_is_trusted
        || metadata.mode() & 0o022 != 0
    {
        return Err(BrokerError::Unavailable);
    }
    Ok(())
}
fn verify_peer_uid(observed_uid: u32, expected_uid: u32) -> Result<(), BrokerError> {
    if observed_uid != expected_uid {
        return Err(BrokerError::Unavailable);
    }
    Ok(())
}
#[cfg(test)]
fn connect_verified(policy: &EndpointPolicy) -> Result<UnixStream, BrokerError> {
    connect_verified_before(policy, BrokerDeadlineV1::new(BROKER_IO_TIMEOUT_V1)?)
}
fn connect_verified_before(
    policy: &EndpointPolicy,
    deadline: BrokerDeadlineV1,
) -> Result<UnixStream, BrokerError> {
    deadline.remaining()?;
    let before = endpoint_identity(policy)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| BrokerError::Unavailable)?;
    deadline.remaining()?;
    // Callers must enter this synchronous transport from a blocking worker. Connection backlog,
    // peer credentials and the later handshake all consume the original exchange deadline.
    let asynchronous = runtime
        .block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline.expires_at()),
                tokio::net::UnixStream::connect(&policy.path),
            )
            .await
        })
        .map_err(|_| BrokerError::Unavailable)?
        .map_err(|_| BrokerError::Unavailable)?;
    let peer_credentials = asynchronous
        .peer_cred()
        .map_err(|_| BrokerError::Unavailable)?;
    verify_peer_uid(peer_credentials.uid(), policy.expected_service_uid)?;
    let after = endpoint_identity(policy)?;
    if before != after {
        return Err(BrokerError::Unavailable);
    }
    let stream = asynchronous
        .into_std()
        .map_err(|_| BrokerError::Unavailable)?;
    stream
        .set_nonblocking(false)
        .map_err(|_| BrokerError::Unavailable)?;
    let remaining = deadline.remaining()?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| BrokerError::Unavailable)?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|_| BrokerError::Unavailable)?;
    Ok(stream)
}

fn configured_observation<'state>(
    state: &'state BrokerServerStateV1,
    binding: &ProviderBindingWireV1,
) -> Result<&'state ProviderObservationWireV1, BrokerError> {
    state
        .catalog
        .iter()
        .position(|configured| configured == binding)
        .and_then(|index| state.observations.get(index))
        .ok_or(BrokerError::BindingMismatch)
}
fn qualify_server_binding(
    state: &BrokerServerStateV1,
    binding: &ProviderBindingWireV1,
    metadata_digest: [u8; 32],
) -> Result<ProviderObservationWireV1, BrokerError> {
    let configured = configured_observation(state, binding)?;
    if configured.metadata_digest != metadata_digest {
        return Err(BrokerError::BindingMismatch);
    }
    // These two backends expose a typed transient failure. Preserve it so the
    // retained consensus signer proxy can reconnect instead of permanently
    // latching a stale-provider verdict. Startup still uses the exhaustive
    // observation path below and therefore remains fail closed.
    if requalify_consensus_threshold_signer_binding(state, binding)? {
        return Ok(configured.clone());
    }
    let live = make_server_observation(state.network_id, binding, &state.backends)
        .map_err(|_| BrokerError::StaleOrRevoked)?;
    if &live != configured {
        return Err(BrokerError::StaleOrRevoked);
    }
    Ok(live)
}
fn block_on_provider_future<T>(
    future: impl std::future::Future<Output = T>,
) -> Result<T, BrokerError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| BrokerError::Unavailable)?;
    Ok(runtime.block_on(future))
}
fn resolved_provider_signer(
    state: &BrokerServerStateV1,
    context: sorafs_node::ProviderIngestCompletionSignerResolutionContextV1,
) -> Result<Option<Arc<dyn sorafs_node::ProviderIngestCompletionSignerV1>>, BrokerError> {
    let resolver = broker_backend!(state, provider_ingest_signer_resolver);
    block_on_provider_future(resolver.resolve(context))?.map_err(|error| match error {
        sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Unavailable => {
            BrokerError::Unavailable
        }
        sorafs_node::ProviderIngestCompletionSignerResolverErrorV1::Rejected => {
            BrokerError::Rejected
        }
    })
}
fn validate_resolved_provider_signer(
    signer: &dyn sorafs_node::ProviderIngestCompletionSignerV1,
    expected: &sorafs_node::ProviderIngestCompletionSignerBindingV1,
    owner: &iroha_data_model::account::AccountId,
) -> Result<(), BrokerError> {
    let qualification = signer.qualification().map_err(|error| match error {
        sorafs_node::ProviderIngestCompletionSignerErrorV1::Unavailable => BrokerError::Unavailable,
        sorafs_node::ProviderIngestCompletionSignerErrorV1::Rejected => BrokerError::Rejected,
    })?;
    let eligibility = signer.current_eligibility().map_err(|error| match error {
        sorafs_node::ProviderIngestCompletionSignerErrorV1::Unavailable => BrokerError::Unavailable,
        sorafs_node::ProviderIngestCompletionSignerErrorV1::Rejected => BrokerError::Rejected,
    })?;
    if signer.runtime_handle() != expected.runtime_handle
        || signer.authority() != owner
        || qualification != expected.qualification
        || signer.signer_policy() != expected.qualification.signer_policy
        || eligibility != expected.qualification.signer_policy
    {
        return Err(BrokerError::StaleOrRevoked);
    }
    Ok(())
}
fn native_transaction_signer_qualification_error(
    error: iroha_torii::SorafsNativeTransactionSignerQualificationErrorV1,
) -> BrokerError {
    if error == iroha_torii::SorafsNativeTransactionSignerQualificationErrorV1::ProviderUnavailable
    {
        BrokerError::Unavailable
    } else {
        BrokerError::StaleOrRevoked
    }
}
fn soracloud_runtime_signer_qualification_error(
    error: crate::soracloud_runtime_signer::SoracloudRuntimeSignerQualificationErrorV1,
) -> BrokerError {
    use crate::soracloud_runtime_signer::SoracloudRuntimeSignerQualificationErrorV1 as Error;
    match error {
        Error::ProviderUnavailable => BrokerError::Unavailable,
        Error::InvalidProviderHandle
        | Error::InvalidProviderQualification
        | Error::ProviderInactive
        | Error::TestProviderRejected
        | Error::UnsupportedProviderKeyAlgorithm
        | Error::HandleMismatch
        | Error::AuthorityMismatch
        | Error::PublicKeyMismatch
        | Error::ProviderAuthorityKeyMismatch
        | Error::RevisionMismatch
        | Error::PolicyDigestMismatch
        | Error::ProviderDrift => BrokerError::StaleOrRevoked,
    }
}
fn qualified_soracloud_runtime_signer(
    state: &BrokerServerStateV1,
    binding: &ProviderBindingWireV1,
) -> Result<Arc<dyn crate::soracloud_runtime_signer::SoracloudRuntimeMutationSignerV1>, BrokerError>
{
    let exact = soracloud_runtime_signer_binding_from_wire(binding)?;
    crate::soracloud_runtime_signer::qualify_soracloud_runtime_mutation_signer_v1(
        exact,
        Arc::clone(broker_backend!(state, soracloud_runtime_mutation_signer)),
    )
    .map_err(soracloud_runtime_signer_qualification_error)
}
fn map_soracloud_runtime_signing_error(
    error: crate::soracloud_runtime_signer::SoracloudRuntimeSigningErrorV1,
) -> BrokerError {
    use crate::soracloud_runtime_signer::SoracloudRuntimeSigningErrorV1 as Error;
    match error {
        Error::Unavailable => BrokerError::Unavailable,
        Error::Refused | Error::InputAuthorityMismatch | Error::InvalidProvenancePreimage => {
            BrokerError::Rejected
        }
        Error::SubstitutedTransaction | Error::InvalidProvenanceSignature => BrokerError::Ambiguous,
        Error::QualificationChanged => BrokerError::StaleOrRevoked,
    }
}
fn sign_moderation_transaction(
    state: &BrokerServerStateV1,
    payload: &iroha_data_model::transaction::TransactionPayload,
) -> Result<iroha_data_model::transaction::SignedTransaction, BrokerError> {
    let backend = broker_backend!(state, moderation_transaction_signer);
    let transaction = backend.sign(payload.clone()).map_err(|error| match error {
        iroha_torii::sorafs::moderation_runtime::ModerationSigningFailureV1::Unavailable
        | iroha_torii::sorafs::moderation_runtime::ModerationSigningFailureV1::Backpressure => {
            BrokerError::Unavailable
        }
        iroha_torii::sorafs::moderation_runtime::ModerationSigningFailureV1::Refused => {
            BrokerError::Rejected
        }
    })?;
    if transaction.payload() != payload
        || transaction.authority() != payload.authority()
        || transaction.verify_signature().is_err()
    {
        return Err(BrokerError::StaleOrRevoked);
    }
    Ok(transaction)
}
fn sign_native_transaction(
    state: &BrokerServerStateV1,
    binding: &ProviderBindingWireV1,
    payload: iroha_data_model::transaction::TransactionPayload,
) -> Result<iroha_data_model::transaction::SignedTransaction, BrokerError> {
    let exact = native_transaction_signer_binding_from_wire(binding)?;
    if payload.authority() != exact.authority()
        || !iroha_torii::sorafs::native_transaction_signer::sorafs_native_transaction_payload_matches_role_v1(exact.role(), &payload)
    {
        return Err(BrokerError::Rejected);
    }
    ensure_transaction_session_network(&payload, &state.network_id)
        .map_err(|_| BrokerError::Rejected)?;
    match exact.role() {
        iroha_torii::SorafsNativeTransactionSignerRoleV1::ProofOutcome => {
            let signer = iroha_torii::qualify_sorafs_proof_outcome_transaction_signer_v1(
                state.network_id,
                exact,
                Arc::clone(broker_backend!(state, proof_outcome_transaction_signer)),
            )
            .map_err(native_transaction_signer_qualification_error)?;
            signer.sign(payload).map_err(|error| match error {
                iroha_torii::SoraFsProofOutcomeSigningError::Unavailable => {
                    BrokerError::Unavailable
                }
                iroha_torii::SoraFsProofOutcomeSigningError::Refused
                | iroha_torii::SoraFsProofOutcomeSigningError::InputAuthorityMismatch => {
                    BrokerError::Rejected
                }
                iroha_torii::SoraFsProofOutcomeSigningError::SubstitutedTransaction => {
                    BrokerError::Ambiguous
                }
                iroha_torii::SoraFsProofOutcomeSigningError::QualificationChanged => {
                    BrokerError::StaleOrRevoked
                }
            })
        }
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Repair => {
            let signer = iroha_torii::qualify_sorafs_repair_transaction_signer_v1(
                state.network_id,
                exact,
                Arc::clone(broker_backend!(state, repair_transaction_signer)),
            )
            .map_err(native_transaction_signer_qualification_error)?;
            signer.sign(payload).map_err(|error| match error {
                iroha_torii::SoraFsRepairTransactionSigningError::Unavailable => {
                    BrokerError::Unavailable
                }
                iroha_torii::SoraFsRepairTransactionSigningError::Refused
                | iroha_torii::SoraFsRepairTransactionSigningError::InputAuthorityMismatch => {
                    BrokerError::Rejected
                }
                iroha_torii::SoraFsRepairTransactionSigningError::SubstitutedTransaction => {
                    BrokerError::Ambiguous
                }
                iroha_torii::SoraFsRepairTransactionSigningError::QualificationChanged => {
                    BrokerError::StaleOrRevoked
                }
            })
        }
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Reserve => {
            let signer = iroha_torii::qualify_sorafs_reserve_transaction_signer_v1(
                state.network_id,
                exact,
                Arc::clone(broker_backend!(state, reserve_transaction_signer)),
            )
            .map_err(native_transaction_signer_qualification_error)?;
            signer.sign(payload).map_err(|error| match error {
                iroha_torii::SoraFsReserveTransactionSigningError::Unavailable => {
                    BrokerError::Unavailable
                }
                iroha_torii::SoraFsReserveTransactionSigningError::Refused
                | iroha_torii::SoraFsReserveTransactionSigningError::InputAuthorityMismatch => {
                    BrokerError::Rejected
                }
                iroha_torii::SoraFsReserveTransactionSigningError::SubstitutedTransaction => {
                    BrokerError::Ambiguous
                }
                iroha_torii::SoraFsReserveTransactionSigningError::QualificationChanged => {
                    BrokerError::StaleOrRevoked
                }
            })
        }
        iroha_torii::SorafsNativeTransactionSignerRoleV1::Orderbook => {
            let signer = iroha_torii::qualify_sorafs_orderbook_transaction_signer_v1(
                state.network_id,
                exact,
                Arc::clone(broker_backend!(state, orderbook_transaction_signer)),
            )
            .map_err(native_transaction_signer_qualification_error)?;
            signer.sign(payload).map_err(|error| match error {
                iroha_torii::SoraFsOrderbookTransactionSigningError::Unavailable => {
                    BrokerError::Unavailable
                }
                iroha_torii::SoraFsOrderbookTransactionSigningError::Refused
                | iroha_torii::SoraFsOrderbookTransactionSigningError::InputAuthorityMismatch => {
                    BrokerError::Rejected
                }
                iroha_torii::SoraFsOrderbookTransactionSigningError::SubstitutedTransaction => {
                    BrokerError::Ambiguous
                }
                iroha_torii::SoraFsOrderbookTransactionSigningError::QualificationChanged => {
                    BrokerError::StaleOrRevoked
                }
            })
        }
    }
}

/// Stream-token qualification is immutable metadata, without a transient provider call.
fn validate_stream_token_backend_metadata(
    binding: &ProviderBindingWireV1,
    backends: &RuntimeProviderBrokerBackendsV1,
) -> Result<(), RuntimeProviderBrokerServerErrorV1> {
    let signer_backend = binding
        .stream_token_signer_binding
        .as_ref()
        .ok_or(RuntimeProviderBrokerServerErrorV1::BindingMismatch)?;
    let client = server_backend!(backends, stream_token_signer_client);
    let observer = server_backend!(backends, stream_token_state_observer);
    for _ in 0..2 {
        let client_handle = client.handle();
        let observer_handle = observer.handle();
        if signer_backend.validate().is_err()
            || client_handle != signer_backend.custody().runtime_handle
            || observer_handle != signer_backend.observer_handle()
            || client_handle == observer_handle
        {
            return Err(RuntimeProviderBrokerServerErrorV1::BindingMismatch);
        }
    }
    Ok(())
}
fn qualify_stream_token_observer_metadata(
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
) -> Result<(), BrokerError> {
    if request.binding.slot != IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id()
        || request.operation != OPERATION_STREAM_TOKEN_OBSERVE_V1
        || configured_observation(state, &request.binding)?.metadata_digest
            != request.provider_metadata_digest
    {
        return Err(BrokerError::BindingMismatch);
    }
    // This capability's observation has no mutable provider fields. Startup used
    // the same handle checks and computed the configured metadata once. Rechecking
    // those exact handles needs neither a cloned observation nor re-encoding None fields.
    validate_stream_token_backend_metadata(&request.binding, &state.backends)
        .map_err(|_| BrokerError::StaleOrRevoked)
}
