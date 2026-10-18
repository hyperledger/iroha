fn billing_hash_canonical<T: NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], BrokerError> {
    let bytes = encode_canonical(value, MAX_BILLING_RUNTIME_FRAME_BYTES_V1)?;
    let length = u64::try_from(bytes.len()).map_err(|_| BrokerError::Rejected)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&length.to_le_bytes());
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}
fn validate_billing_record_id(record_id: [u8; 32]) -> Result<(), BrokerError> {
    if record_id == [0; 32] {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_billing_public_identity_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn validate_billing_cursor(
    cursor: sorafs_node::hedging_billing_service::HedgingBillingFinalizedCursorV1,
) -> Result<(), BrokerError> {
    if cursor.height == 0 || cursor.block_hash == [0; 32] || cursor.finalized_at_unix == 0 {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_billing_journal_commitment(
    commitment: sorafs_node::hedging_billing_service::HedgingBillingJournalCommitmentV1,
    network_id: iroha_data_model::NetworkId,
) -> Result<(), BrokerError> {
    validate_billing_cursor(commitment.finalized_cursor)?;
    if commitment.version
        != sorafs_node::hedging_billing_service::HEDGING_BILLING_JOURNAL_COMMITMENT_VERSION_V1
        || commitment.network_id != network_id
        || commitment.journal_next_sequence == 0
        || commitment.journal_root == [0; 32]
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_billing_query_position(
    position: BillingQueryPositionWireV1,
    network_id: iroha_data_model::NetworkId,
) -> Result<(), BrokerError> {
    if position.next_sequence == 0 {
        return Err(BrokerError::Rejected);
    }
    if let Some(commitment) = position.journal_commitment {
        validate_billing_journal_commitment(commitment, network_id)?;
        if position.next_sequence > commitment.journal_next_sequence {
            return Err(BrokerError::Rejected);
        }
    }
    Ok(())
}
const fn billing_query_position_from_wire(
    position: BillingQueryPositionWireV1,
) -> sorafs_node::hedging_billing_service::HedgingBillingQueryPositionV1 {
    sorafs_node::hedging_billing_service::HedgingBillingQueryPositionV1 {
        next_sequence: position.next_sequence,
        journal_commitment: position.journal_commitment,
    }
}
const fn billing_query_position_to_wire(
    position: sorafs_node::hedging_billing_service::HedgingBillingQueryPositionV1,
) -> BillingQueryPositionWireV1 {
    BillingQueryPositionWireV1 {
        next_sequence: position.next_sequence,
        journal_commitment: position.journal_commitment,
    }
}
fn validate_billing_page_shape(
    page: &sorafs_node::hedging_billing_service::HedgingBillingFinalizedEventPageV1,
    request: Option<(BillingQueryPositionWireV1, u32)>,
) -> Result<(), BrokerError> {
    validate_billing_journal_commitment(page.journal_commitment, page.network_id)?;
    let expected_next = page
        .start_sequence
        .checked_add(u64::try_from(page.events.len()).map_err(|_| BrokerError::Rejected)?)
        .ok_or(BrokerError::Rejected)?;
    if page.version
        != sorafs_node::hedging_billing_service::HEDGING_BILLING_FINALIZED_PAGE_VERSION_V1
        || page.start_sequence == 0
        || page.next_sequence != expected_next
        || page.next_sequence > page.journal_commitment.journal_next_sequence
        || page.events.len()
            > usize::try_from(
                sorafs_node::hedging_billing_service::HEDGING_BILLING_MAX_EVENTS_PER_PAGE_V1,
            )
            .unwrap_or(usize::MAX)
        || page.append_proof.is_empty()
        || page.append_proof.len()
            > sorafs_node::hedging_billing_service::HEDGING_BILLING_CONSENSUS_PROOF_MAX_BYTES_V1
        || page.inclusion_proof.is_empty()
        || page.inclusion_proof.len()
            > sorafs_node::hedging_billing_service::HEDGING_BILLING_CONSENSUS_PROOF_MAX_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    if let Some((position, max_events)) = request
        && (page.start_sequence != position.next_sequence
            || page.events.len()
                > usize::try_from(max_events).map_err(|_| BrokerError::Rejected)?)
    {
        return Err(BrokerError::Rejected);
    }
    for (offset, event) in page.events.iter().enumerate() {
        let expected_sequence = page
            .start_sequence
            .checked_add(u64::try_from(offset).map_err(|_| BrokerError::Rejected)?)
            .ok_or(BrokerError::Rejected)?;
        if event.sequence != expected_sequence
            || event.block_height == 0
            || event.block_hash == [0; 32]
            || event.block_height > page.journal_commitment.finalized_cursor.height
            || event.source_id.is_empty()
            || event.source_id.len()
                > sorafs_node::hedging_billing_service::BILLING_SOURCE_ID_MAX_BYTES_V1
            || event.source_id.trim() != event.source_id.as_str()
            || event.source_id.chars().any(char::is_control)
            || event.account_id.is_empty()
            || event.account_id.len() > sorafs_manifest::hedging::MAX_BILLING_ACCOUNT_ID_BYTES
            || event.occurred_at_unix == 0
            || event.occurred_at_unix > page.journal_commitment.finalized_cursor.finalized_at_unix
        {
            return Err(BrokerError::Rejected);
        }
    }
    Ok(())
}
fn validate_billing_period_close_shape(
    close: &sorafs_node::hedging_billing_service::HedgingBillingFinalizedPeriodCloseV1,
    expected_period_end_unix: Option<u64>,
) -> Result<(), BrokerError> {
    validate_billing_journal_commitment(close.journal_commitment, close.network_id)?;
    if close.version
        != sorafs_node::hedging_billing_service::HEDGING_BILLING_PERIOD_CLOSE_VERSION_V1
        || close.period_end_unix == 0
        || expected_period_end_unix.is_some_and(|expected| expected != close.period_end_unix)
        || close.billing_policy_digest == [0; 32]
        || close.service_policy_digest == [0; 32]
        || close.feed_trust_policy_digest == [0; 32]
        || close.feed_admitted_at_unix == 0
        || close.authentication_proof.is_empty()
        || close.authentication_proof.len()
            > sorafs_node::hedging_billing_service::HEDGING_BILLING_CONSENSUS_PROOF_MAX_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_billing_signed_statement_shape(
    statement: &sorafs_node::hedging_billing_service::SignedGovernedBillingStatementV1,
) -> Result<[u8; 32], BrokerError> {
    validate_billing_cursor(statement.finalized_cursor)?;
    validate_billing_record_id(statement.governed_statement.statement.statement_id)?;
    if statement.version
        != sorafs_node::hedging_billing_service::SIGNED_GOVERNED_BILLING_STATEMENT_VERSION_V1
        || statement.billing_policy_digest == [0; 32]
        || statement.service_policy_digest == [0; 32]
        || statement.period_close_digest == [0; 32]
        || statement.feed_admitted_at_unix == 0
        || statement.signed_at_unix == 0
        || statement.signer_id.is_empty()
        || statement.signer_id.len()
            > sorafs_node::hedging_billing_service::BILLING_SIGNER_ID_MAX_BYTES_V1
        || statement.signer_id.trim() != statement.signer_id
        || statement.signer_id.chars().any(char::is_control)
        || statement.signature == [0; 64]
    {
        return Err(BrokerError::Rejected);
    }
    let canonical = encode_canonical(
        statement,
        sorafs_node::hedging_billing_service::SIGNED_GOVERNED_BILLING_STATEMENT_MAX_BYTES_V1,
    )?;
    Ok(*blake3::hash(&canonical).as_bytes())
}
fn validate_billing_publish_request(
    publish: &BillingPublishStatementRequestWireV1,
    network_id: iroha_data_model::NetworkId,
) -> Result<(), BrokerError> {
    let statement_id = publish.statement.governed_statement.statement.statement_id;
    let digest = validate_billing_signed_statement_shape(&publish.statement)?;
    if publish.idempotency_key != statement_id
        || publish.statement.network_id != network_id
        || publish.signed_statement_digest != digest
        || publish.signed_statement_digest == [0; 32]
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_billing_acknowledgement_request(
    request: &BillingAcknowledgementRequestWireV1,
    network_id: iroha_data_model::NetworkId,
) -> Result<(), BrokerError> {
    validate_billing_signed_statement_shape(&request.statement)?;
    if request.statement.network_id != network_id {
        return Err(BrokerError::BindingMismatch);
    }
    validate_billing_acknowledgement_shape(
        &request.acknowledgement,
        request.statement.governed_statement.statement.statement_id,
        network_id,
    )
}
fn validate_billing_acknowledgement_shape(
    acknowledgement: &sorafs_node::hedging_billing_service::BillingStatementAcknowledgementV1,
    expected_statement_id: [u8; 32],
    network_id: iroha_data_model::NetworkId,
) -> Result<(), BrokerError> {
    if acknowledgement.version
        != sorafs_node::hedging_billing_service::BILLING_STATEMENT_ACKNOWLEDGEMENT_VERSION_V1
        || acknowledgement.network_id != network_id
        || acknowledgement.statement_id != expected_statement_id
        || acknowledgement.account_digest == [0; 32]
        || acknowledgement.request_binding_digest == [0; 32]
        || acknowledgement.acknowledged_at_unix == 0
        || acknowledgement.authentication_proof.is_empty()
        || acknowledgement.authentication_proof.len()
            > sorafs_node::hedging_billing_service::BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1
        || acknowledgement.acknowledgement_id == [0; 32]
    {
        return Err(BrokerError::Rejected);
    }
    let mut canonical = acknowledgement.clone();
    canonical.acknowledgement_id = [0; 32];
    let expected = billing_hash_canonical(b"sorafs.billing.acknowledgement.v1", &canonical)?;
    if expected != acknowledgement.acknowledgement_id {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_billing_publication_shape(
    publication: &BillingAuthoritativePublicationWireV1,
    requested_statement_id: [u8; 32],
    identity: &BillingStatementPublisherIdentityWireV1,
    network_id: iroha_data_model::NetworkId,
) -> Result<(), BrokerError> {
    let statement_digest = validate_billing_signed_statement_shape(&publication.signed_statement)?;
    let receipt = &publication.receipt;
    if publication
        .signed_statement
        .governed_statement
        .statement
        .statement_id
        != requested_statement_id
        || publication.signed_statement.network_id != network_id
        || receipt.route_id != identity.route_id
        || receipt.publisher_id != identity.publisher_id
    {
        return Err(BrokerError::Rejected);
    }
    validate_billing_publication_receipt_shape(
        receipt,
        requested_statement_id,
        statement_digest,
        publication.signed_statement.signed_at_unix,
    )?;
    let mut canonical = receipt.clone();
    canonical.receipt_digest = [0; 32];
    canonical.signature = [0; 64];
    let expected = billing_hash_canonical(b"sorafs.billing.publication-receipt.v1", &canonical)?;
    if receipt.receipt_digest != expected {
        return Err(BrokerError::Rejected);
    }
    let mut message =
        Vec::with_capacity(b"sorafs.billing.publisher-receipt-signature.v1".len() + 32);
    message.extend_from_slice(b"sorafs.billing.publisher-receipt-signature.v1");
    message.extend_from_slice(&receipt.receipt_digest);
    verify_evidence_viewer_ed25519_signature(identity.public_key, receipt.signature, &message)
}
fn validate_billing_publication_receipt_shape(
    receipt: &sorafs_node::hedging_billing_service::BillingStatementPublicationReceiptV1,
    expected_statement_id: [u8; 32],
    expected_statement_digest: [u8; 32],
    signed_at_unix: u64,
) -> Result<(), BrokerError> {
    if receipt.version
        != sorafs_node::hedging_billing_service::BILLING_STATEMENT_PUBLICATION_RECEIPT_VERSION_V1
        || receipt.statement_id != expected_statement_id
        || receipt.signed_statement_digest != expected_statement_digest
        || !validate_billing_public_identity_text(
            &receipt.route_id,
            sorafs_node::hedging_billing_service::BILLING_PUBLICATION_ROUTE_MAX_BYTES_V1,
        )
        || !validate_billing_public_identity_text(
            &receipt.publisher_id,
            sorafs_node::hedging_billing_service::BILLING_SIGNER_ID_MAX_BYTES_V1,
        )
        || receipt.published_at_unix < signed_at_unix
        || receipt.published_at_unix == u64::MAX
        || receipt.receipt_digest == [0; 32]
        || receipt.signature == [0; 64]
    {
        return Err(BrokerError::Rejected);
    }
    let mut canonical = receipt.clone();
    canonical.receipt_digest = [0; 32];
    canonical.signature = [0; 64];
    let expected = billing_hash_canonical(b"sorafs.billing.publication-receipt.v1", &canonical)?;
    if receipt.receipt_digest != expected {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
define_broker_wire_struct!(owned ProviderIngestSourceMusubiArchiveWireV1 { network_id: iroha_data_model::NetworkId, observed_finalized_cursor: sorafs_node::ProviderIngestFinalizedCursorV1, binding: iroha_data_model::musubi::MusubiReplicationOrderArchiveBindingV1, });
#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "irohad::runtime_provider_broker::protocol::ProviderIngestSourceFetchRequestWireV1"
)]
struct ProviderIngestSourceFetchRequestWireV1 {
    authorization: sorafs_node::FinalizedProviderIngestAuthorizationV1,
    source_provider_ids: Vec<[u8; 32]>,
    musubi_archive: Option<ProviderIngestSourceMusubiArchiveWireV1>,
}
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestCarPlanWireV1"; ProviderIngestCarPlanWireV1 { chunk_profile: ProviderIngestChunkProfileWireV1, payload_digest: [u8; 32], content_length: u64, chunks: Vec<ProviderIngestCarChunkWireV1>, files: Vec<ProviderIngestFilePlanWireV1>, });
define_broker_wire_struct!(copy ProviderIngestChunkProfileWireV1 { min_size: u64, target_size: u64, max_size: u64, break_mask: u64, });
define_broker_wire_struct!(copy ProviderIngestCarChunkWireV1 { offset: u64, length: u32, digest: [u8; 32], });
define_broker_wire_struct!(owned ProviderIngestFilePlanWireV1 { path: Vec<String>, first_chunk: u64, chunk_count: u64, size: u64, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestSourceHeaderWireV1"; ProviderIngestSourceHeaderWireV1 { manifest: Vec<u8>, plan: Vec<u8>, content_length: u64, frame_count: u64, });
define_broker_wire_struct!(owned frame "irohad::runtime_provider_broker::protocol::ProviderIngestSourceChunkWireV1"; ProviderIngestSourceChunkWireV1 { sequence: u64, offset: u64, bytes: Vec<u8>, });
define_broker_wire_struct!(copy frame "irohad::runtime_provider_broker::protocol::ProviderIngestSourceTrailerWireV1"; ProviderIngestSourceTrailerWireV1 { status: u8, content_length: u64, frame_count: u64, payload_digest: [u8; 32], transcript_digest: [u8; 32], provider_metadata_digest: [u8; 32], });
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerError {
    Unavailable,
    Protocol,
    BindingMismatch,
    StaleOrRevoked,
    Rejected,
    Conflict,
    Ambiguous,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecodeResourcePolicyV1 {
    max_sequence_elements: usize,
    max_blob_bytes: usize,
    max_total_elements: usize,
    max_total_allocated_bytes: usize,
    element_headroom: usize,
    allocation_headroom_bytes: usize,
    // Private schema work bound; ordinary operation policies retain one wire pass.
    allocation_wire_passes: usize,
    max_nesting_depth: usize,
    // Process-wide reservation for the audited maximum simultaneously
    // live frame, typed value, and canonical-copy layers.
    max_composed_bytes: usize,
    // Per-call monotonic phase counter. Unlike the live reservation this
    // is not acquired from the memory pool and may exceed the live peak.
    max_cumulative_bytes: usize,
}
impl DecodeResourcePolicyV1 {
    const fn new(
        field_caps: (usize, usize),
        total_caps: (usize, usize),
        headroom: (usize, usize),
        max_nesting_depth: usize,
        resource_caps: (usize, usize),
    ) -> Self {
        Self {
            max_sequence_elements: field_caps.0,
            max_blob_bytes: field_caps.1,
            max_total_elements: total_caps.0,
            max_total_allocated_bytes: total_caps.1,
            element_headroom: headroom.0,
            allocation_headroom_bytes: headroom.1,
            allocation_wire_passes: 1,
            max_nesting_depth,
            max_composed_bytes: resource_caps.0,
            max_cumulative_bytes: resource_caps.1,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecodeResourceBudgetV1 {
    max_sequence_elements: usize,
    max_blob_bytes: usize,
    max_total_elements: usize,
    max_total_allocated_bytes: usize,
    max_nesting_depth: usize,
    composed_charge_bytes: usize,
}
fn decode_resource_budget(
    encoded_len: usize,
    semantic_wire_limit: usize,
    policy: DecodeResourcePolicyV1,
) -> Result<DecodeResourceBudgetV1, BrokerError> {
    if encoded_len == 0
        || semantic_wire_limit == 0
        || encoded_len > semantic_wire_limit
        || encoded_len > policy.max_blob_bytes
        || policy.max_sequence_elements == 0
        || policy.max_blob_bytes == 0
        || policy.max_total_elements == 0
        || policy.max_total_allocated_bytes == 0
        || policy.allocation_wire_passes == 0
        || policy.max_nesting_depth == 0
        || policy.max_composed_bytes == 0
        || policy.max_cumulative_bytes < policy.max_composed_bytes
    {
        return Err(BrokerError::Protocol);
    }
    // Each allowance has its unchanged audited absolute ceiling. The ordinary
    // one-pass policy keeps its previous fixed headroom. Complete beacon graphs
    // additionally bound their actual schema framing/copy work by wire length;
    // the source-derived multiplier never raises the absolute ceiling.
    let max_total_elements = encoded_len
        .checked_add(policy.element_headroom)
        .ok_or(BrokerError::Protocol)?
        .min(policy.max_total_elements);
    let max_total_allocated_bytes = encoded_len
        .checked_mul(policy.allocation_wire_passes)
        .and_then(|bytes| bytes.checked_add(policy.allocation_headroom_bytes))
        .ok_or(BrokerError::Protocol)?
        .min(policy.max_total_allocated_bytes);
    // A canonicality check allocates one exact re-encoding alongside the
    // decoded value. Charge that headroom to the same operation admission.
    let composed_charge_bytes = max_total_allocated_bytes
        .checked_add(encoded_len)
        .ok_or(BrokerError::Protocol)?;
    Ok(DecodeResourceBudgetV1 {
        max_sequence_elements: semantic_wire_limit.min(policy.max_sequence_elements),
        max_blob_bytes: semantic_wire_limit.min(policy.max_blob_bytes),
        max_total_elements,
        max_total_allocated_bytes,
        max_nesting_depth: policy.max_nesting_depth,
        composed_charge_bytes,
    })
}
#[derive(Debug)]
struct DecodeResourcePoolV1 {
    max_bytes: usize,
    allocation: iroha_allocation::AllocationBudget,
}
impl DecodeResourcePoolV1 {
    fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            allocation: iroha_allocation::AllocationBudget::new(max_bytes),
        }
    }
    fn try_acquire(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Result<DecodeResourcePoolPermitV1, BrokerError> {
        if bytes == 0 || bytes > self.max_bytes {
            return Err(BrokerError::Protocol);
        }
        let reservation =
            self.allocation
                .try_reserve_bytes(bytes)
                .map_err(|refusal| match refusal {
                    iroha_allocation::AllocationRefusal::Capacity { .. } => {
                        BrokerError::Unavailable
                    }
                    _ => BrokerError::Protocol,
                })?;
        Ok(DecodeResourcePoolPermitV1 {
            _reservation: reservation,
        })
    }
}
#[derive(Debug)]
struct DecodeResourcePoolPermitV1 {
    _reservation: iroha_allocation::AllocationReservation,
}
#[derive(Debug)]
struct DecodeResourceAdmissionV1 {
    operation: Option<u16>,
    policy: DecodeResourcePolicyV1,
    usage: Mutex<DecodeResourceUsageV1>,
    // The same authenticated request session follows ingress, dispatch and result
    // validation. This owns the original charged graph, never a raw DTO clone.
    // Retire it before releasing the enclosing process-pool permit.
    beacon_session: Mutex<Option<iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1>>,
    pool: Arc<DecodeResourcePoolV1>,
    _permit: DecodeResourcePoolPermitV1,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DecodeResourceUsageV1 {
    consumed_bytes: usize,
}
impl DecodeResourceAdmissionV1 {
    fn acquire(
        operation: Option<u16>,
        policy: DecodeResourcePolicyV1,
    ) -> Result<Arc<Self>, BrokerError> {
        Self::acquire_from(shared_decode_resource_pool(), operation, policy)
    }
    fn acquire_operation(operation: u16) -> Result<Arc<Self>, BrokerError> {
        Self::acquire(Some(operation), operation_decode_policy(operation))
    }
    fn acquire_operation_from(
        pool: Arc<DecodeResourcePoolV1>,
        operation: u16,
    ) -> Result<Arc<Self>, BrokerError> {
        Self::acquire_from(pool, Some(operation), operation_decode_policy(operation))
    }
    fn acquire_from(
        pool: Arc<DecodeResourcePoolV1>,
        operation: Option<u16>,
        policy: DecodeResourcePolicyV1,
    ) -> Result<Arc<Self>, BrokerError> {
        let permit = pool.try_acquire(policy.max_composed_bytes)?;
        Ok(Arc::new(Self {
            operation,
            policy,
            usage: Mutex::new(DecodeResourceUsageV1::default()),
            beacon_session: Mutex::new(None),
            pool,
            _permit: permit,
        }))
    }
    fn reserve_raw_frame(
        &self,
        declared_len: usize,
        semantic_wire_limit: usize,
    ) -> Result<(), BrokerError> {
        if declared_len == 0
            || declared_len > semantic_wire_limit
            || declared_len > self.policy.max_blob_bytes
        {
            return Err(BrokerError::Protocol);
        }
        let mut usage = self.usage.lock().map_err(|_| BrokerError::Protocol)?;
        let next = usage
            .consumed_bytes
            .checked_add(declared_len)
            .ok_or(BrokerError::Protocol)?;
        if next > self.policy.max_cumulative_bytes {
            return Err(BrokerError::Protocol);
        }
        usage.consumed_bytes = next;
        Ok(())
    }
    fn reserve_encoded_copy(
        &self,
        encoded_len: usize,
        semantic_wire_limit: usize,
    ) -> Result<(), BrokerError> {
        if encoded_len > semantic_wire_limit || encoded_len > self.policy.max_blob_bytes {
            return Err(BrokerError::Rejected);
        }
        if encoded_len == 0 {
            return Ok(());
        }
        self.reserve_bytes(encoded_len)
    }
    fn reserve_retained_bytes(
        &self,
        retained_len: usize,
        semantic_wire_limit: usize,
    ) -> Result<(), BrokerError> {
        if retained_len > semantic_wire_limit || retained_len > self.policy.max_blob_bytes {
            return Err(BrokerError::Rejected);
        }
        if retained_len == 0 {
            return Ok(());
        }
        self.reserve_bytes(retained_len)
    }
    fn reserve_bytes(&self, bytes: usize) -> Result<(), BrokerError> {
        let mut usage = self.usage.lock().map_err(|_| BrokerError::Protocol)?;
        let next = usage
            .consumed_bytes
            .checked_add(bytes)
            .ok_or(BrokerError::Protocol)?;
        if next > self.policy.max_cumulative_bytes {
            return Err(BrokerError::Protocol);
        }
        usage.consumed_bytes = next;
        Ok(())
    }
    fn reserve_decode(
        &self,
        encoded_len: usize,
        semantic_wire_limit: usize,
    ) -> Result<DecodeResourceBudgetV1, BrokerError> {
        let budget = decode_resource_budget(encoded_len, semantic_wire_limit, self.policy)?;
        let mut usage = self.usage.lock().map_err(|_| BrokerError::Protocol)?;
        let next = usage
            .consumed_bytes
            .checked_add(budget.composed_charge_bytes)
            .ok_or(BrokerError::Protocol)?;
        if next > self.policy.max_cumulative_bytes {
            return Err(BrokerError::Protocol);
        }
        usage.consumed_bytes = next;
        Ok(budget)
    }
    fn retain_beacon_session(
        &self,
        record: &iroha_data_model::consensus::GlobalThresholdBeaconKeySessionV1,
        binding: &iroha_core::beacon::GlobalThresholdBeaconSessionBindingV1,
    ) -> Result<iroha_core::beacon::ValidatedGlobalThresholdBeaconSessionV1, BrokerError> {
        // Test-only mutant restores the retired per-phase graph reconstruction.
        #[cfg(not(all(test, sumeragi_daemon_mutation = "HC93")))]
        {
            let retained = self
                .beacon_session
                .lock()
                .map_err(|_| BrokerError::Protocol)?;
            if let Some(session) = retained.as_ref() {
                // The external binding is checked on every use. Matching only its
                // identifiers would trust substituted inner transcript/signature bytes.
                session
                    .check_binding(binding)
                    .map_err(|_| BrokerError::Rejected)?;
                if session.record() != record {
                    return Err(BrokerError::Rejected);
                }
                return Ok(session.clone());
            }
        }
        // The existing decoded-frame peak remains completely reserved: its
        // monotonic cumulative counter is not a live allocation owner and cannot
        // donate credits to a graph. Admit the physical graph and verifier buffers
        // additionally from this operation's original finite process pool once.
        // Raw DTO decoding/canonical copies retain their existing audited envelope;
        // no additional raw DTO or canonical bytes are copied into this owner.
        // TODO: replace that conservative decode envelope with actual funded raw
        // decoder/encode backing; retaining the authenticated graph does not do so.
        let verified = iroha_core::beacon::validate_global_threshold_beacon_session_v1(
            record,
            binding,
            &self.pool.allocation,
        )
        .map_err(|error| beacon_session_error(&error))?;
        // Verification and scratch refunds above, and retirement of a losing
        // concurrent reader below, occur outside the session mutex. A physical
        // source release callback can therefore reenter this operation safely.
        let result = {
            let mut retained = self
                .beacon_session
                .lock()
                .map_err(|_| BrokerError::Protocol)?;
            if let Some(session) = retained.as_ref() {
                if session.record() == record {
                    session
                        .check_binding(binding)
                        .map_err(|_| BrokerError::Rejected)?;
                    Ok(session.clone())
                } else {
                    Err(BrokerError::Rejected)
                }
            } else {
                *retained = Some(verified.clone());
                Ok(verified.clone())
            }
        };
        drop(verified);
        result
    }

    fn enter(self: &Arc<Self>) -> DecodeResourceAdmissionScopeV1 {
        CURRENT_DECODE_ADMISSIONS_V1.with(|stack| {
            stack.borrow_mut().push(Arc::clone(self));
        });
        DecodeResourceAdmissionScopeV1 {
            admission: Arc::clone(self),
        }
    }
}
struct DecodeResourceAdmissionScopeV1 {
    admission: Arc<DecodeResourceAdmissionV1>,
}
impl Drop for DecodeResourceAdmissionScopeV1 {
    fn drop(&mut self) {
        CURRENT_DECODE_ADMISSIONS_V1.with(|stack| {
            let popped = stack.borrow_mut().pop();
            debug_assert!(
                popped
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &self.admission))
            );
        });
    }
}
thread_local! {
    static CURRENT_DECODE_ADMISSIONS_V1:
        RefCell<Vec<Arc<DecodeResourceAdmissionV1>>> = const { RefCell::new(Vec::new()) };
}
fn current_decode_resource_admission() -> Option<Arc<DecodeResourceAdmissionV1>> {
    CURRENT_DECODE_ADMISSIONS_V1.with(|stack| stack.borrow().last().cloned())
}
fn shared_decode_resource_pool() -> Arc<DecodeResourcePoolV1> {
    static POOL: OnceLock<Arc<DecodeResourcePoolV1>> = OnceLock::new();
    Arc::clone(
        POOL.get_or_init(|| Arc::new(DecodeResourcePoolV1::new(MAX_BROKER_SHARED_DECODE_BYTES_V1))),
    )
}
fn source_stream_frame_count(content_length: u64) -> Result<u64, BrokerError> {
    if content_length == 0 {
        return Err(BrokerError::Rejected);
    }
    let payload_bytes = u64::try_from(MAX_PROVIDER_INGEST_SOURCE_CHUNK_PAYLOAD_BYTES_V1)
        .map_err(|_| BrokerError::Protocol)?;
    Ok(content_length.div_ceil(payload_bytes))
}
fn validate_source_plan_counts(chunk_count: usize, file_count: usize) -> Result<(), BrokerError> {
    if chunk_count > sorafs_car::CAR_PLAN_MAX_CHUNKS
        || file_count > MAX_PROVIDER_INGEST_SOURCE_PLAN_FILES_V1
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_source_metadata_lengths(
    manifest_bytes: usize,
    plan_bytes: usize,
) -> Result<(), BrokerError> {
    if manifest_bytes == 0
        || manifest_bytes > sorafs_manifest::MAX_MANIFEST_ENCODED_BYTES
        || plan_bytes == 0
        || plan_bytes > MAX_PROVIDER_INGEST_SOURCE_PLAN_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn source_retained_memory_bytes(plan: &sorafs_car::CarBuildPlan) -> Result<usize, BrokerError> {
    let validation = plan
        .validate_for_ingest_with_limit(MAX_PROVIDER_INGEST_SOURCE_PLAN_HEAP_BYTES_V1)
        .map_err(|_| BrokerError::Rejected)?;
    // The CAR validator's allocation-free estimate covers the decoded plan
    // and ingest working set. Add the manifest's fixed public maximum
    // rather than an attacker-controlled multiplier.
    validation
        .estimated_ingest_heap_bytes()
        .checked_add(sorafs_manifest::MAX_MANIFEST_ENCODED_BYTES)
        .ok_or(BrokerError::Protocol)
}
fn acquire_source_retained_memory(
    pool: &Arc<DecodeResourcePoolV1>,
    plan: &sorafs_car::CarBuildPlan,
) -> Result<DecodeResourcePoolPermitV1, BrokerError> {
    pool.try_acquire(source_retained_memory_bytes(plan)?)
}
fn source_plan_to_wire(
    plan: &sorafs_car::CarBuildPlan,
) -> Result<ProviderIngestCarPlanWireV1, BrokerError> {
    plan.validate_for_ingest_with_limit(MAX_PROVIDER_INGEST_SOURCE_PLAN_HEAP_BYTES_V1)
        .map_err(|_| BrokerError::Rejected)?;
    validate_source_plan_counts(plan.chunks.len(), plan.files.len())?;
    let chunks = plan
        .chunks
        .iter()
        .map(|chunk| ProviderIngestCarChunkWireV1 {
            offset: chunk.offset,
            length: chunk.length,
            digest: chunk.digest,
        })
        .collect();
    let files = plan
        .files
        .iter()
        .map(|file| {
            Ok(ProviderIngestFilePlanWireV1 {
                path: file.path.clone(),
                first_chunk: u64::try_from(file.first_chunk).map_err(|_| BrokerError::Rejected)?,
                chunk_count: u64::try_from(file.chunk_count).map_err(|_| BrokerError::Rejected)?,
                size: file.size,
            })
        })
        .collect::<Result<Vec<_>, BrokerError>>()?;
    Ok(ProviderIngestCarPlanWireV1 {
        chunk_profile: ProviderIngestChunkProfileWireV1 {
            min_size: u64::try_from(plan.chunk_profile.min_size)
                .map_err(|_| BrokerError::Rejected)?,
            target_size: u64::try_from(plan.chunk_profile.target_size)
                .map_err(|_| BrokerError::Rejected)?,
            max_size: u64::try_from(plan.chunk_profile.max_size)
                .map_err(|_| BrokerError::Rejected)?,
            break_mask: plan.chunk_profile.break_mask,
        },
        payload_digest: *plan.payload_digest.as_bytes(),
        content_length: plan.content_length,
        chunks,
        files,
    })
}
fn source_plan_from_wire(
    wire: ProviderIngestCarPlanWireV1,
) -> Result<sorafs_car::CarBuildPlan, BrokerError> {
    validate_source_plan_counts(wire.chunks.len(), wire.files.len())?;
    let plan = sorafs_car::CarBuildPlan {
        chunk_profile: sorafs_car::sorafs_chunker::ChunkProfile {
            min_size: usize::try_from(wire.chunk_profile.min_size)
                .map_err(|_| BrokerError::Rejected)?,
            target_size: usize::try_from(wire.chunk_profile.target_size)
                .map_err(|_| BrokerError::Rejected)?,
            max_size: usize::try_from(wire.chunk_profile.max_size)
                .map_err(|_| BrokerError::Rejected)?,
            break_mask: wire.chunk_profile.break_mask,
        },
        payload_digest: blake3::Hash::from_bytes(wire.payload_digest),
        content_length: wire.content_length,
        chunks: wire
            .chunks
            .into_iter()
            .map(|chunk| sorafs_car::CarChunk {
                offset: chunk.offset,
                length: chunk.length,
                digest: chunk.digest,
            })
            .collect(),
        files: wire
            .files
            .into_iter()
            .map(|file| {
                Ok(sorafs_car::FilePlan {
                    path: file.path,
                    first_chunk: usize::try_from(file.first_chunk)
                        .map_err(|_| BrokerError::Rejected)?,
                    chunk_count: usize::try_from(file.chunk_count)
                        .map_err(|_| BrokerError::Rejected)?,
                    size: file.size,
                })
            })
            .collect::<Result<Vec<_>, BrokerError>>()?,
    };
    plan.validate_for_ingest_with_limit(MAX_PROVIDER_INGEST_SOURCE_PLAN_HEAP_BYTES_V1)
        .map_err(|_| BrokerError::Rejected)?;
    Ok(plan)
}
fn encode_source_plan(plan: &sorafs_car::CarBuildPlan) -> Result<Vec<u8>, BrokerError> {
    encode_canonical(
        &source_plan_to_wire(plan)?,
        MAX_PROVIDER_INGEST_SOURCE_PLAN_BYTES_V1,
    )
}
fn decode_source_plan(bytes: &[u8]) -> Result<sorafs_car::CarBuildPlan, BrokerError> {
    if bytes.is_empty() || bytes.len() > MAX_PROVIDER_INGEST_SOURCE_PLAN_BYTES_V1 {
        return Err(BrokerError::Rejected);
    }
    let wire = decode_canonical_with_policy::<ProviderIngestCarPlanWireV1>(
        bytes,
        MAX_PROVIDER_INGEST_SOURCE_PLAN_BYTES_V1,
        SOURCE_PLAN_DECODE_POLICY_V1,
    )
    .map_err(|_| BrokerError::Rejected)?;
    source_plan_from_wire(wire)
}
fn source_request_from_wire(
    fetch: ProviderIngestSourceFetchRequestWireV1,
) -> Result<sorafs_node::ProviderIngestSourceRequestV1, BrokerError> {
    let musubi_archive = match fetch.musubi_archive {
        Some(musubi) => Some(
            sorafs_node::ProviderIngestMusubiArchiveFetchBindingV1::new(
                musubi.network_id,
                fetch.authorization.provider_id(),
                musubi.observed_finalized_cursor,
                musubi.binding,
            )
            .map_err(|_| BrokerError::Rejected)?,
        ),
        None => None,
    };
    sorafs_node::ProviderIngestSourceRequestV1::new(
        fetch.authorization,
        fetch.source_provider_ids,
        musubi_archive,
    )
    .map_err(|_| BrokerError::Rejected)
}
fn source_request_to_wire(
    request: sorafs_node::ProviderIngestSourceRequestV1,
) -> Result<ProviderIngestSourceFetchRequestWireV1, BrokerError> {
    let (authorization, source_provider_ids, musubi_archive) = request.into_parts();
    let musubi_archive = match musubi_archive {
        Some(musubi) => {
            if !musubi.matches_authorization(&authorization) {
                return Err(BrokerError::BindingMismatch);
            }
            Some(ProviderIngestSourceMusubiArchiveWireV1 {
                network_id: *musubi.network_id(),
                observed_finalized_cursor: musubi.observed_finalized_cursor(),
                binding: musubi.binding().clone(),
            })
        }
        None => None,
    };
    let fetch = ProviderIngestSourceFetchRequestWireV1 {
        authorization,
        source_provider_ids,
        musubi_archive,
    };
    source_request_from_wire(fetch.clone())?;
    Ok(fetch)
}
fn validate_source_fetch_request(
    fetch: &ProviderIngestSourceFetchRequestWireV1,
    binding: &ProviderBindingWireV1,
    admitted_provider_ids: Option<&[[u8; 32]]>,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    source_request_from_wire(fetch.clone())?;
    if fetch
        .musubi_archive
        .as_ref()
        .is_some_and(|archive| &archive.network_id != session_network_id)
    {
        return Err(BrokerError::BindingMismatch);
    }
    let limits = required_binding_value!(binding, provider_ingest_source_limits);
    let max_sources =
        usize::try_from(limits.max_source_providers).map_err(|_| BrokerError::Rejected)?;
    if fetch.authorization.content_length() > limits.max_content_bytes
        || fetch.source_provider_ids.len() > max_sources
    {
        return Err(BrokerError::Rejected);
    }
    if let Some(admitted) = admitted_provider_ids
        && (admitted
            .iter()
            .any(|provider_id| *provider_id == fetch.authorization.provider_id())
            || fetch
                .source_provider_ids
                .iter()
                .any(|provider_id| admitted.binary_search(provider_id).is_err()))
    {
        return Err(BrokerError::BindingMismatch);
    }
    source_stream_frame_count(fetch.authorization.content_length())?;
    Ok(())
}
fn validate_source_payload_metadata(
    authorization: &sorafs_node::FinalizedProviderIngestAuthorizationV1,
    manifest: &sorafs_manifest::ManifestV1,
    plan: &sorafs_car::CarBuildPlan,
) -> Result<(), BrokerError> {
    plan.validate().map_err(|_| BrokerError::Rejected)?;
    let digest = manifest.digest().map_err(|_| BrokerError::Rejected)?;
    let profile = format!(
        "{}.{}@{}",
        manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
    );
    if digest.as_bytes() != &authorization.manifest_digest()
        || manifest.root_cid.as_slice() != authorization.manifest_cid()
        || profile != authorization.chunker_handle()
        || manifest.chunk_digest_sha3_256 != authorization.chunk_digest_sha3_256()
        || manifest.por_root != authorization.por_root()
        || manifest.content_length != authorization.content_length()
        || plan.content_length != authorization.content_length()
        || sorafs_car::compute_chunk_plan_digest_sha3(&plan.chunks)
            != authorization.chunk_digest_sha3_256()
        || u32::try_from(plan.chunk_profile.min_size).ok() != Some(manifest.chunking.min_size)
        || u32::try_from(plan.chunk_profile.target_size).ok() != Some(manifest.chunking.target_size)
        || u32::try_from(plan.chunk_profile.max_size).ok() != Some(manifest.chunking.max_size)
        || u32::try_from(plan.chunk_profile.break_mask).ok() != Some(manifest.chunking.break_mask)
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn source_stream_transcript(
    request: &OperationRequestV1,
    response: &OperationResponseV1,
) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVIDER_INGEST_SOURCE_STREAM_DOMAIN_V1);
    hasher.update(&request.request_digest);
    hasher.update(&response.response_digest);
    hasher
}
fn update_source_stream_transcript(
    hasher: &mut blake3::Hasher,
    chunk: &ProviderIngestSourceChunkWireV1,
) {
    hasher.update(PROVIDER_INGEST_SOURCE_CHUNK_DOMAIN_V1);
    hasher.update(&chunk.sequence.to_be_bytes());
    hasher.update(&chunk.offset.to_be_bytes());
    hasher.update(
        &u64::try_from(chunk.bytes.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(&chunk.bytes);
}
fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}
fn encode_canonical<T: NoritoSerialize>(value: &T, limit: usize) -> Result<Vec<u8>, BrokerError> {
    canonical_attempt::encode(value, limit).map_err(|error| error.service_error())
}
fn encode_sensitive_canonical<T: NoritoSerialize>(
    value: &T,
    limit: usize,
) -> Result<ScrubbedBytes, BrokerError> {
    encode_canonical(value, limit).map(ScrubbedBytes::new)
}
fn decode_canonical<T>(bytes: &[u8], limit: usize) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    decode_canonical_with_policy(bytes, limit, CONTROL_DECODE_POLICY_V1)
}
fn decode_nested_canonical<T>(bytes: &[u8], limit: usize) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    decode_canonical_with_policy(bytes, limit, OPAQUE_BLOB_DECODE_POLICY_V1)
}
fn decode_scrubbed_canonical<T>(bytes: &ScrubbedBytes, limit: usize) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let _scope = bytes.enter_decode_admission();
    decode_canonical(bytes, limit)
}
fn reserve_external_canonical_decode(
    encoded_len: usize,
    semantic_wire_limit: usize,
) -> Result<(), BrokerError> {
    // Leave semantic rejection (including empty and oversized records) to
    // the external decoder so this accounting hook does not change its
    // caller-visible error mapping.
    if encoded_len == 0 || encoded_len > semantic_wire_limit {
        return Ok(());
    }
    if let Some(admission) = current_decode_resource_admission() {
        admission.reserve_decode(encoded_len, semantic_wire_limit)?;
    }
    Ok(())
}
fn decode_canonical_with_policy<T>(
    bytes: &[u8],
    limit: usize,
    policy: DecodeResourcePolicyV1,
) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    decode_canonical_with_policy_from(bytes, limit, policy, shared_decode_resource_pool())
}
// Keep standalone defaults and selected connection decodes on the same narrow
// boundary; an enclosing operation already owns its reservation and counters.
fn decode_canonical_with_policy_from<T>(
    bytes: &[u8],
    limit: usize,
    policy: DecodeResourcePolicyV1,
    pool: Arc<DecodeResourcePoolV1>,
) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    if let Some(admission) = current_decode_resource_admission() {
        return decode_canonical_with_admission(bytes, limit, &admission)
            .map_err(|error| error.service_error());
    }
    let admission = DecodeResourceAdmissionV1::acquire_from(pool, None, policy)?;
    admission.reserve_raw_frame(bytes.len(), limit)?;
    let _scope = admission.enter();
    decode_canonical_with_admission(bytes, limit, &admission).map_err(|error| error.service_error())
}
fn decode_canonical_with_admission<T>(
    bytes: &[u8],
    limit: usize,
    admission: &DecodeResourceAdmissionV1,
) -> Result<T, CanonicalAttemptErrorV1>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let budget = admission.reserve_decode(bytes.len(), limit)?;
    let limits = DecodeLimits::new(
        budget.max_sequence_elements,
        budget.max_blob_bytes,
        budget.max_total_elements,
        budget.max_total_allocated_bytes,
        budget.max_nesting_depth,
    );
    norito::decode_canonical_for_admission::<T>(bytes, limits)
        .map_err(CanonicalAttemptErrorV1::Decode)
}
fn encode_frame<T: NoritoSerialize>(
    kind: u8,
    value: &T,
    limit: usize,
) -> Result<ScrubbedBytes, BrokerError> {
    let body = encode_canonical(value, limit)?;
    let frame = BrokerFrameV1 {
        magic: BROKER_MAGIC_V1,
        version: BROKER_VERSION_V1,
        kind,
        body,
    };
    encode_canonical(&frame, limit).map(ScrubbedBytes::new)
}
#[cfg(test)]
fn decode_frame<T>(bytes: &[u8], expected_kind: u8, limit: usize) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    decode_frame_with_policy(bytes, expected_kind, limit, CONTROL_DECODE_POLICY_V1)
}
fn decode_operation_frame<T>(
    bytes: &[u8],
    expected_kind: u8,
    operation: u16,
) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let limit = operation_frame_limit(operation);
    if let Some(admission) = current_decode_resource_admission() {
        if admission.operation != Some(operation) {
            return Err(BrokerError::Protocol);
        }
        return decode_frame_with_admission(bytes, expected_kind, limit, &admission);
    }
    let admission = DecodeResourceAdmissionV1::acquire_operation(operation)?;
    admission.reserve_raw_frame(bytes.len(), limit)?;
    let _scope = admission.enter();
    decode_frame_with_admission(bytes, expected_kind, limit, &admission)
}
fn decode_frame_with_policy<T>(
    bytes: &[u8],
    expected_kind: u8,
    limit: usize,
    policy: DecodeResourcePolicyV1,
) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    decode_frame_with_policy_from(
        bytes,
        expected_kind,
        limit,
        policy,
        shared_decode_resource_pool(),
    )
}
// Preserve an enclosing operation's exact admission; otherwise charge only
// this decode to the process that owns the authenticated connection.
fn decode_frame_with_policy_from<T>(
    bytes: &[u8],
    expected_kind: u8,
    limit: usize,
    policy: DecodeResourcePolicyV1,
    pool: Arc<DecodeResourcePoolV1>,
) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    if let Some(admission) = current_decode_resource_admission() {
        return decode_frame_with_admission(bytes, expected_kind, limit, &admission);
    }
    let admission = DecodeResourceAdmissionV1::acquire_from(pool, None, policy)?;
    admission.reserve_raw_frame(bytes.len(), limit)?;
    let _scope = admission.enter();
    decode_frame_with_admission(bytes, expected_kind, limit, &admission)
}
fn decode_frame_with_admission<T>(
    bytes: &[u8],
    expected_kind: u8,
    limit: usize,
    admission: &DecodeResourceAdmissionV1,
) -> Result<T, BrokerError>
where
    T: NoritoSerialize,
    for<'de> T: NoritoDeserialize<'de>,
{
    let frame = decode_canonical_with_admission::<BrokerFrameV1>(bytes, limit, admission)
        .map_err(|error| error.service_error())?;
    if frame.magic != BROKER_MAGIC_V1
        || frame.version != BROKER_VERSION_V1
        || frame.kind != expected_kind
    {
        return Err(BrokerError::Protocol);
    }
    decode_canonical_with_admission::<T>(&frame.body, limit, admission)
        .map_err(|error| error.service_error())
}
fn write_length_prefixed<W: std::io::Write>(
    writer: &mut W,
    frame: &[u8],
    limit: usize,
) -> Result<(), BrokerError> {
    if frame.is_empty() || frame.len() > limit {
        return Err(BrokerError::Rejected);
    }
    let length = u32::try_from(frame.len()).map_err(|_| BrokerError::Rejected)?;
    writer
        .write_all(&length.to_be_bytes())
        .map_err(|_| BrokerError::Unavailable)?;
    writer
        .write_all(frame)
        .map_err(|_| BrokerError::Unavailable)?;
    writer.flush().map_err(|_| BrokerError::Unavailable)
}
fn read_length_prefixed_inner<R: std::io::Read>(
    reader: &mut R,
    limit: usize,
    inbound_budget: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    decode_admission: Option<&DecodeResourceAdmissionV1>,
) -> Result<ScrubbedBytes, BrokerError> {
    let mut length_bytes = [0_u8; 4];
    reader
        .read_exact(&mut length_bytes)
        .map_err(|_| BrokerError::Unavailable)?;
    let length =
        usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| BrokerError::Protocol)?;
    if length == 0 || length > limit {
        return Err(BrokerError::Protocol);
    }
    if let Some(admission) = decode_admission {
        admission.reserve_raw_frame(length, limit)?;
    }
    let inbound_permit = inbound_budget
        .map(|budget| {
            let permits = u32::try_from(length).map_err(|_| BrokerError::Protocol)?;
            budget
                .try_acquire_many_owned(permits)
                .map_err(|_| BrokerError::Unavailable)
        })
        .transpose()?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(length)
        .map_err(|_| BrokerError::Protocol)?;
    let mut remaining = length;
    let mut chunk = ScrubbedReadChunk(vec![0_u8; 64 * 1024].into_boxed_slice());
    while remaining != 0 {
        let read_len = remaining.min(chunk.len());
        reader
            .read_exact(&mut chunk[..read_len])
            .map_err(|_| BrokerError::Unavailable)?;
        frame.extend_from_slice(&chunk[..read_len]);
        chunk[..read_len].fill(0);
        remaining -= read_len;
    }
    Ok(match inbound_permit {
        Some(permit) => ScrubbedBytes::with_inbound_permit(frame, permit),
        None => ScrubbedBytes::new(frame),
    })
}
fn read_length_prefixed<R: std::io::Read>(
    reader: &mut R,
    limit: usize,
) -> Result<ScrubbedBytes, BrokerError> {
    read_length_prefixed_inner(reader, limit, None, None)
}
fn read_length_prefixed_with_decode_admission<R: std::io::Read>(
    reader: &mut R,
    limit: usize,
    decode_admission: &DecodeResourceAdmissionV1,
) -> Result<ScrubbedBytes, BrokerError> {
    read_length_prefixed_inner(reader, limit, None, Some(decode_admission))
}
fn write_operation_request_frame<W: std::io::Write>(
    writer: &mut W,
    request: &OperationRequestV1,
    frame: &[u8],
) -> Result<(), BrokerError> {
    let limit = operation_frame_limit(request.operation);
    if frame.is_empty() || frame.len() > limit {
        return Err(BrokerError::Rejected);
    }
    writer
        .write_all(&request.binding.slot.to_be_bytes())
        .map_err(|_| BrokerError::Unavailable)?;
    writer
        .write_all(&request.operation.to_be_bytes())
        .map_err(|_| BrokerError::Unavailable)?;
    write_length_prefixed(writer, frame, limit)
}
fn read_operation_request_frame_inner<R: std::io::Read>(
    reader: &mut R,
    inbound_budget: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    decode_pool: Option<Arc<DecodeResourcePoolV1>>,
) -> Result<(u16, u16, ScrubbedBytes, Arc<DecodeResourceAdmissionV1>), BrokerError> {
    let mut discriminator = [0_u8; 4];
    reader
        .read_exact(&mut discriminator)
        .map_err(|_| BrokerError::Unavailable)?;
    let slot = u16::from_be_bytes([discriminator[0], discriminator[1]]);
    let operation = u16::from_be_bytes([discriminator[2], discriminator[3]]);
    if !operation_is_known(operation)
        || (slot == IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id()
            && !matches!(
                operation,
                OPERATION_QUALIFY_V1
                    | OPERATION_STREAM_TOKEN_SIGN_V1
                    | OPERATION_STREAM_TOKEN_RECOVER_V1
                    | OPERATION_STREAM_TOKEN_OBSERVE_V1
                    | OPERATION_STREAM_TOKEN_CHECK_V1
            ))
    {
        // The slot-11 discriminator admits only its four bounded operations. Reject a known
        // bulk operation for another role before reading its length or reserving raw bytes.
        return Err(BrokerError::Protocol);
    }
    let frame = read_length_prefixed_inner(
        reader,
        operation_frame_limit(operation),
        inbound_budget,
        None,
    )?;
    // The process-wide raw semaphore above is acquired from the declared
    // length before allocation and remains attached to `frame`. Only after
    // the complete bounded body arrives do we reserve the substantially
    // larger composed decode budget, so a peer that stalls after the
    // discriminator or length cannot monopolize decode capacity.
    let decode_admission = match decode_pool {
        Some(pool) => DecodeResourceAdmissionV1::acquire_operation_from(pool, operation)?,
        None => DecodeResourceAdmissionV1::acquire_operation(operation)?,
    };
    decode_admission.reserve_raw_frame(frame.len(), operation_frame_limit(operation))?;
    Ok((slot, operation, frame, decode_admission))
}
#[cfg(test)]
fn read_operation_request_frame<R: std::io::Read>(
    reader: &mut R,
) -> Result<(u16, u16, ScrubbedBytes), BrokerError> {
    let (slot, operation, frame, _decode_admission) =
        read_operation_request_frame_inner(reader, None, None)?;
    Ok((slot, operation, frame))
}
fn read_operation_request_frame_with_budget<R: std::io::Read>(
    reader: &mut R,
    inbound_budget: std::sync::Arc<tokio::sync::Semaphore>,
    decode_pool: Arc<DecodeResourcePoolV1>,
) -> Result<(u16, u16, ScrubbedBytes, Arc<DecodeResourceAdmissionV1>), BrokerError> {
    read_operation_request_frame_inner(reader, Some(inbound_budget), Some(decode_pool))
}
fn catalog_digest(
    chain_id: &str,
    network_id: &NetworkId,
    catalog: &[ProviderBindingWireV1],
) -> Result<[u8; 32], BrokerError> {
    let bytes = encode_canonical(&catalog.to_vec(), MAX_HANDSHAKE_FRAME_BYTES_V1)?;
    Ok(digest_parts(
        CATALOG_DIGEST_DOMAIN_V1,
        &[
            &BROKER_MAGIC_V1,
            &BROKER_VERSION_V1.to_be_bytes(),
            chain_id.as_bytes(),
            network_id.as_bytes(),
            &bytes,
        ],
    ))
}
fn client_transcript_digest(fields: &HandshakeTranscriptFieldsV1) -> Result<[u8; 32], BrokerError> {
    let bytes = encode_canonical(fields, MAX_HANDSHAKE_FRAME_BYTES_V1)?;
    Ok(digest_parts(
        CLIENT_TRANSCRIPT_DOMAIN_V1,
        &[&BROKER_MAGIC_V1, &BROKER_VERSION_V1.to_be_bytes(), &bytes],
    ))
}
fn server_transcript_digest(fields: &ServerTranscriptFieldsV1) -> Result<[u8; 32], BrokerError> {
    let bytes = encode_canonical(fields, MAX_HANDSHAKE_FRAME_BYTES_V1)?;
    Ok(digest_parts(
        SERVER_TRANSCRIPT_DOMAIN_V1,
        &[&BROKER_MAGIC_V1, &BROKER_VERSION_V1.to_be_bytes(), &bytes],
    ))
}
#[expect(
    clippy::ref_option,
    clippy::too_many_arguments,
    reason = "arguments mirror the fixed V1 metadata transcript fields"
)]
fn provider_metadata_digest(
    signer_metadata: &Option<SignerMetadataWireV1>,
    governance_request_ingress_qualification: &Option<GovernanceRequestIngressQualificationWireV1>,
    moderation_quarantine_active_key_id: &Option<String>,
    provider_ingest_signer_binding: &Option<ProviderIngestSignerBindingWireV1>,
    provider_ingest_source_provider_ids: &[[u8; 32]],
    potr_signer_public_key: &[u8],
    evidence_viewer_receipt_signer_public_key: &Option<[u8; 32]>,
    evidence_viewer_archive_id: &Option<[u8; 32]>,
    evidence_viewer_archive_public_key: &Option<[u8; 32]>,
    moderation_checkpoint_attestation_public_key: &Option<[u8; 32]>,
    moderation_panel_notification_archive_binding: &Option<
        ModerationPanelNotificationArchiveBindingWireV1,
    >,
) -> Result<[u8; 32], BrokerError> {
    let bytes = encode_canonical(
        &(
            signer_metadata.clone(),
            *governance_request_ingress_qualification,
            moderation_quarantine_active_key_id.clone(),
            provider_ingest_signer_binding.clone(),
            provider_ingest_source_provider_ids.to_vec(),
            potr_signer_public_key.to_vec(),
            *evidence_viewer_receipt_signer_public_key,
            *evidence_viewer_archive_id,
            *evidence_viewer_archive_public_key,
            *moderation_checkpoint_attestation_public_key,
            *moderation_panel_notification_archive_binding,
        ),
        MAX_HANDSHAKE_FRAME_BYTES_V1,
    )?;
    Ok(digest_parts(PROVIDER_METADATA_DOMAIN_V1, &[&bytes]))
}
fn operation_payload_digest(payload: &[u8]) -> [u8; 32] {
    digest_parts(OPERATION_PAYLOAD_DOMAIN_V1, &[payload])
}
fn operation_result_digest(result: &[u8]) -> [u8; 32] {
    digest_parts(OPERATION_RESULT_DOMAIN_V1, &[result])
}
fn operation_request_digest(fields: &OperationRequestFieldsV1) -> Result<[u8; 32], BrokerError> {
    let bytes = encode_canonical(fields, MAX_OPERATION_FRAME_BYTES_V1)?;
    Ok(digest_parts(OPERATION_REQUEST_DOMAIN_V1, &[&bytes]))
}
fn operation_response_digest(
    fields: &OperationResponseFieldsV1,
) -> Result<[u8; 32], CanonicalAttemptErrorV1> {
    let bytes = canonical_attempt::encode(fields, MAX_OPERATION_FRAME_BYTES_V1)?;
    Ok(digest_parts(OPERATION_RESPONSE_DOMAIN_V1, &[&bytes]))
}
fn make_handshake_request(
    chain_id: &str,
    network_id: NetworkId,
    requested_catalog: Vec<ProviderBindingWireV1>,
    client_nonce: [u8; 32],
) -> Result<HandshakeRequestV1, BrokerError> {
    if chain_id.is_empty()
        || chain_id.len() > MAX_CHAIN_ID_BYTES_V1
        || chain_id.as_bytes().contains(&0)
        || client_nonce == [0; 32]
    {
        return Err(BrokerError::BindingMismatch);
    }
    validate_catalog_slot_ids(requested_catalog.iter().map(|binding| binding.slot))?;
    for binding in &requested_catalog {
        validate_wire_binding(binding)?;
        if let Some(signer_backend) = &binding.stream_token_signer_binding {
            signer_backend
                .validate_network(chain_id, network_id.as_bytes())
                .map_err(|_| BrokerError::BindingMismatch)?;
        }
    }
    if requested_catalog
        .windows(2)
        .any(|pair| !compare_wire_bindings(&pair[0], &pair[1]).is_lt())
    {
        return Err(BrokerError::BindingMismatch);
    }
    let catalog_digest = catalog_digest(chain_id, &network_id, &requested_catalog)?;
    let transcript = HandshakeTranscriptFieldsV1 {
        chain_id: chain_id.to_owned(),
        network_id,
        requested_catalog: requested_catalog.clone(),
        client_nonce,
        catalog_digest,
    };
    let client_transcript_digest = client_transcript_digest(&transcript)?;
    Ok(HandshakeRequestV1 {
        chain_id: chain_id.to_owned(),
        network_id,
        requested_catalog,
        client_nonce,
        catalog_digest,
        client_transcript_digest,
    })
}
fn validate_handshake_request(request: &HandshakeRequestV1) -> Result<(), BrokerError> {
    let expected = make_handshake_request(
        &request.chain_id,
        request.network_id,
        request.requested_catalog.clone(),
        request.client_nonce,
    )?;
    if &expected != request {
        return Err(BrokerError::Protocol);
    }
    Ok(())
}
fn make_handshake_response(
    request: &HandshakeRequestV1,
    session_id: [u8; 32],
    observations: Vec<ProviderObservationWireV1>,
) -> Result<HandshakeResponseV1, BrokerError> {
    if session_id == [0; 32] || observations.len() != request.requested_catalog.len() {
        return Err(BrokerError::Protocol);
    }
    for (binding, observation) in request.requested_catalog.iter().zip(&observations) {
        validate_observation(binding, observation)?;
    }
    let transcript = ServerTranscriptFieldsV1 {
        chain_id: request.chain_id.clone(),
        network_id: request.network_id,
        requested_catalog: request.requested_catalog.clone(),
        client_nonce: request.client_nonce,
        catalog_digest: request.catalog_digest,
        client_transcript_digest: request.client_transcript_digest,
        session_id,
        observations: observations.clone(),
    };
    Ok(HandshakeResponseV1 {
        chain_id: request.chain_id.clone(),
        network_id: request.network_id,
        requested_catalog: request.requested_catalog.clone(),
        client_nonce: request.client_nonce,
        catalog_digest: request.catalog_digest,
        client_transcript_digest: request.client_transcript_digest,
        session_id,
        observations,
        server_transcript_digest: server_transcript_digest(&transcript)?,
    })
}
fn validate_observation(
    requested: &ProviderBindingWireV1,
    observed: &ProviderObservationWireV1,
) -> Result<(), BrokerError> {
    if &observed.binding != requested {
        return Err(BrokerError::BindingMismatch);
    }
    if provider_metadata_digest(
        &observed.signer_metadata,
        &observed.governance_request_ingress_qualification,
        &observed.moderation_quarantine_active_key_id,
        &observed.provider_ingest_signer_binding,
        &observed.provider_ingest_source_provider_ids,
        &observed.potr_signer_public_key,
        &observed.evidence_viewer_receipt_signer_public_key,
        &observed.evidence_viewer_archive_id,
        &observed.evidence_viewer_archive_public_key,
        &observed.moderation_checkpoint_attestation_public_key,
        &observed.moderation_panel_notification_archive_binding,
    )? != observed.metadata_digest
    {
        return Err(BrokerError::Protocol);
    }
    let evidence_slot = matches!(
        requested.slot,
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::EvidenceViewerErasure.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive.wire_id()
            || slot
                == IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher.wire_id()
    );
    if !evidence_slot
        && (observed.evidence_viewer_receipt_signer_public_key.is_some()
            || observed.evidence_viewer_archive_id.is_some()
            || observed.evidence_viewer_archive_public_key.is_some())
    {
        return Err(BrokerError::BindingMismatch);
    }
    let governance_request_auth_slot = matches!(
        requested.slot,
        slot if slot == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id()
            || slot
                == IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator.wire_id()
    );
    if governance_request_auth_slot != observed.governance_request_ingress_qualification.is_some() {
        return Err(BrokerError::BindingMismatch);
    }
    let potr_slot = requested.slot == IrohaRuntimeProviderSlotV1::PotrGatewaySigner.wire_id()
        || requested.slot == IrohaRuntimeProviderSlotV1::PotrProviderSigner.wire_id();
    if !potr_slot && !observed.potr_signer_public_key.is_empty() {
        return Err(BrokerError::BindingMismatch);
    }
    match requested.slot {
        slot if slot == IrohaRuntimeProviderSlotV1::StreamTokenSigner.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::PrivacyCyclePrfProvider.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::PrivacyReleaseAnchor.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::TransparencyLeaderLease.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::FencedPrivacyPublisher.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::FencedPrivacyHeadReader.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::PopCredentialProviderRegistry.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::GatewayAcmeClient.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::GatewayComplianceFeedTransport.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::PorFinalizedReplayArchive.wire_id()
            || slot
                == IrohaRuntimeProviderSlotV1::ReputationJournalTransactionSubmitter.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::ReputationThresholdSigner.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::ReputationGovernanceDag.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::ReputationJournalCheckpoint.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::BillingFinalizedQuery.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::BillingJournalVerifier.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::BillingStatementSigner.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::BillingStatementPublisher.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::BillingAcknowledgementAuthority.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::BillingEpochWitnessStore.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::ModerationTransactionSigner.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::ModerationPanelNotification.wire_id()
            || slot
                == IrohaRuntimeProviderSlotV1::BootleLanternIssuanceProviderRegistry.wire_id() =>
        {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
                || !observed.potr_signer_public_key.is_empty()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id() => {
            if observed.signer_metadata.is_some()
                || observed.governance_request_ingress_qualification.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
                || !observed.potr_signer_public_key.is_empty()
                || observed.evidence_viewer_receipt_signer_public_key.is_some()
                || observed.evidence_viewer_archive_id.is_some()
                || observed.evidence_viewer_archive_public_key.is_some()
                || observed
                    .moderation_checkpoint_attestation_public_key
                    .is_some()
                || observed
                    .moderation_panel_notification_archive_binding
                    .is_some()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::PotrGatewaySigner.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::PotrProviderSigner.wire_id() =>
        {
            let runtime = requested
                .potr_runtime_binding
                .as_ref()
                .ok_or(BrokerError::BindingMismatch)?;
            validate_potr_runtime_wire(runtime)?;
            potr_provider_binding_from_wire(requested)?;
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
                || observed.potr_signer_public_key.is_empty()
                || observed.potr_signer_public_key.len() > MAX_POTR_PUBLIC_KEY_BYTES_V1
            {
                return Err(BrokerError::BindingMismatch);
            }
            if slot == IrohaRuntimeProviderSlotV1::PotrGatewaySigner.wire_id() {
                if observed.potr_signer_public_key.as_slice()
                    != runtime.gateway_public_key.as_slice()
                    || iroha_crypto::ed25519_parse_public_key(&runtime.gateway_public_key).is_err()
                {
                    return Err(BrokerError::BindingMismatch);
                }
            } else if iroha_crypto::PublicKey::from_bytes(
                iroha_crypto::Algorithm::MlDsa,
                &observed.potr_signer_public_key,
            )
            .is_err()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ModerationQuarantineKeyWrapper.wire_id() => {
            validate_moderation_quarantine_key_id(
                observed
                    .moderation_quarantine_active_key_id
                    .as_deref()
                    .ok_or(BrokerError::BindingMismatch)?,
            )
            .map_err(|_| BrokerError::BindingMismatch)?;
            if observed.signer_metadata.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GovernanceDagSigner.wire_id() => {
            let metadata = observed
                .signer_metadata
                .as_ref()
                .ok_or(BrokerError::BindingMismatch)?;
            let expected_peer_id = requested
                .governance_dag_publisher_peer_id
                .as_deref()
                .ok_or(BrokerError::BindingMismatch)?;
            let expected_public_key = requested
                .governance_dag_publisher_public_key
                .ok_or(BrokerError::BindingMismatch)?;
            if metadata.publisher_peer_id.is_empty()
                || metadata.publisher_peer_id.len() > GOVERNANCE_DAG_PUBLISHER_PEER_ID_MAX_BYTES_V1
                || !metadata.publisher_peer_id.iter().all(u8::is_ascii_graphic)
                || iroha_crypto::ed25519_parse_public_key(&metadata.public_key).is_err()
                || metadata.publisher_peer_id.as_slice() != expected_peer_id
                || metadata.public_key != expected_public_key
            {
                return Err(BrokerError::BindingMismatch);
            }
            if observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GovernanceDagIpfsAuthenticator.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::GovernanceDagHeadAuthenticator.wire_id() =>
        {
            let expected_binding =
                governance_request_ingress_binding_from_provider_binding(requested)?;
            let qualification = governance_request_ingress_qualification_from_wire(
                observed
                    .governance_request_ingress_qualification
                    .ok_or(BrokerError::BindingMismatch)?,
            )
            .map_err(|_| BrokerError::BindingMismatch)?;
            let expected_revision = requested.revision.ok_or(BrokerError::BindingMismatch)?;
            let expected_policy_digest = requested
                .policy_digest
                .ok_or(BrokerError::BindingMismatch)?;
            if qualification.provider().revision != expected_revision
                || qualification.provider().policy_digest != expected_policy_digest
                || qualification.binding() != expected_binding
                || observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::GovernanceDagCheckpointStore.wire_id() => {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if native_transaction_signer_role_for_slot(slot).is_some()
            || slot == IrohaRuntimeProviderSlotV1::SoracloudRuntimeMutationSigner.wire_id() =>
        {
            if native_transaction_signer_role_for_slot(slot).is_some() {
                native_transaction_signer_binding_from_wire(requested)?;
            } else {
                soracloud_runtime_signer_binding_from_wire(requested)?;
            }
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
                || observed.evidence_viewer_receipt_signer_public_key.is_some()
                || observed.evidence_viewer_archive_id.is_some()
                || observed.evidence_viewer_archive_public_key.is_some()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot
            == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSignerResolver.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::ProviderIngestCompletionSigner.wire_id() =>
        {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding
                    != requested.provider_ingest_signer_binding
                || !observed.provider_ingest_source_provider_ids.is_empty()
            {
                return Err(BrokerError::BindingMismatch);
            }
            observed
                .provider_ingest_signer_binding
                .as_ref()
                .ok_or(BrokerError::BindingMismatch)?
                .to_binding()?;
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ProviderIngestAuthenticatedSource.wire_id() => {
            let limits = requested
                .provider_ingest_source_limits
                .ok_or(BrokerError::BindingMismatch)?;
            let max_sources = usize::try_from(limits.max_source_providers)
                .map_err(|_| BrokerError::BindingMismatch)?;
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || observed.provider_ingest_source_provider_ids.len() < 2
                || observed.provider_ingest_source_provider_ids.len() > max_sources
                || observed
                    .provider_ingest_source_provider_ids
                    .contains(&[0; 32])
                || observed
                    .provider_ingest_source_provider_ids
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ProviderIngestCheckpointStore.wire_id() => {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ProviderIngestRetentionAuthority.wire_id()
            || slot
                == IrohaRuntimeProviderSlotV1::ReputationFinalizedArchiveRetentionAuthority
                    .wire_id() =>
        {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerReceiptSigner.wire_id() => {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
                || observed.evidence_viewer_receipt_signer_public_key
                    != requested.evidence_viewer_receipt_signer_public_key
                || observed.evidence_viewer_archive_id.is_some()
                || observed.evidence_viewer_archive_public_key.is_some()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCompactionArchive.wire_id() => {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
                || observed.evidence_viewer_receipt_signer_public_key.is_some()
                || observed.evidence_viewer_archive_id != requested.evidence_viewer_archive_id
                || observed.evidence_viewer_archive_public_key
                    != requested.evidence_viewer_archive_public_key
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot
            == IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id() =>
        {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
                || observed.evidence_viewer_receipt_signer_public_key.is_some()
                || observed.evidence_viewer_archive_id.is_some()
                || observed.evidence_viewer_archive_public_key.is_some()
                || observed.moderation_panel_notification_archive_binding
                    != requested.moderation_panel_notification_archive_binding
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::EvidenceViewerWebAuthn.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::EvidenceViewerGrantAuthority.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::EvidenceViewerErasure.wire_id()
            || slot == IrohaRuntimeProviderSlotV1::EvidenceViewerCheckpointStore.wire_id()
            || slot
                == IrohaRuntimeProviderSlotV1::EvidenceViewerTransparencyPublisher.wire_id() =>
        {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
                || observed.evidence_viewer_receipt_signer_public_key.is_some()
                || observed.evidence_viewer_archive_id.is_some()
                || observed.evidence_viewer_archive_public_key.is_some()
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        slot if slot == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id() => {
            if observed.signer_metadata.is_some()
                || observed.moderation_quarantine_active_key_id.is_some()
                || observed.provider_ingest_signer_binding.is_some()
                || !observed.provider_ingest_source_provider_ids.is_empty()
                || observed.evidence_viewer_receipt_signer_public_key.is_some()
                || observed.evidence_viewer_archive_id.is_some()
                || observed.evidence_viewer_archive_public_key.is_some()
                || observed.moderation_checkpoint_attestation_public_key
                    != requested.moderation_checkpoint_attestation_public_key
            {
                return Err(BrokerError::BindingMismatch);
            }
        }
        _ => return Err(BrokerError::BindingMismatch),
    }
    Ok(())
}
fn validate_handshake_response(
    request: &HandshakeRequestV1,
    response: &HandshakeResponseV1,
) -> Result<(), BrokerError> {
    let catalog_len_matches = response.observations.len() == request.requested_catalog.len();
    if response.chain_id != request.chain_id
        || response.network_id != request.network_id
        || response.requested_catalog != request.requested_catalog
        || response.client_nonce != request.client_nonce
        || response.catalog_digest != request.catalog_digest
        || response.client_transcript_digest != request.client_transcript_digest
        || response.session_id == [0; 32]
        || !catalog_len_matches
    {
        return Err(BrokerError::BindingMismatch);
    }
    for (requested, observed) in request.requested_catalog.iter().zip(&response.observations) {
        validate_observation(requested, observed)?;
    }
    let transcript = ServerTranscriptFieldsV1 {
        chain_id: response.chain_id.clone(),
        network_id: response.network_id,
        requested_catalog: response.requested_catalog.clone(),
        client_nonce: response.client_nonce,
        catalog_digest: response.catalog_digest,
        client_transcript_digest: response.client_transcript_digest,
        session_id: response.session_id,
        observations: response.observations.clone(),
    };
    if server_transcript_digest(&transcript)? != response.server_transcript_digest {
        return Err(BrokerError::Protocol);
    }
    Ok(())
}
fn make_operation_request(
    session_id: [u8; 32],
    request_id: u64,
    binding: ProviderBindingWireV1,
    provider_metadata_digest: [u8; 32],
    operation: u16,
    payload: Vec<u8>,
) -> Result<OperationRequestV1, BrokerError> {
    make_operation_request_with_scrubbed_payload(
        session_id,
        request_id,
        binding,
        provider_metadata_digest,
        operation,
        ScrubbedBytes::new(payload),
    )
}
fn make_operation_request_with_scrubbed_payload(
    session_id: [u8; 32],
    request_id: u64,
    binding: ProviderBindingWireV1,
    provider_metadata_digest: [u8; 32],
    operation: u16,
    mut payload: ScrubbedBytes,
) -> Result<OperationRequestV1, BrokerError> {
    if session_id == [0; 32] || request_id == 0 || provider_metadata_digest == [0; 32] {
        return Err(BrokerError::Protocol);
    }
    validate_wire_binding(&binding)?;
    let payload_digest = operation_payload_digest(&payload);
    let payload_len = u64::try_from(payload.len()).map_err(|_| BrokerError::Rejected)?;
    let fields = OperationRequestFieldsV1 {
        session_id,
        request_id,
        binding: binding.clone(),
        provider_metadata_digest,
        operation,
        payload_digest,
        payload_len,
    };
    let request_digest = operation_request_digest(&fields)?;
    Ok(OperationRequestV1 {
        session_id,
        request_id,
        binding,
        provider_metadata_digest,
        operation,
        payload_digest,
        payload: payload.take(),
        request_digest,
    })
}
#[cfg(test)]
fn validate_operation_request(request: &OperationRequestV1) -> Result<(), BrokerError> {
    validate_operation_request_with_session(
        request,
        None,
        &crate::runtime_provider_registry::runtime_provider_test_network_id(),
    )
}
fn validate_operation_request_for_session(
    request: &OperationRequestV1,
    session_chain_id: &str,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    validate_operation_request_with_session(request, Some(session_chain_id), session_network_id)
}
fn validate_operation_request_with_session(
    request: &OperationRequestV1,
    session_chain_id: Option<&str>,
    session_network_id: &NetworkId,
) -> Result<(), BrokerError> {
    if request.session_id == [0; 32]
        || request.request_id == 0
        || request.provider_metadata_digest == [0; 32]
        || operation_payload_digest(&request.payload) != request.payload_digest
    {
        return Err(BrokerError::Protocol);
    }
    validate_wire_binding(&request.binding)?;
    if let Some(signer_backend) = &request.binding.stream_token_signer_binding {
        if let Some(chain_id) = session_chain_id {
            signer_backend
                .validate_network(chain_id, session_network_id.as_bytes())
                .map_err(|_| BrokerError::BindingMismatch)?;
        } else if &signer_backend.custody().network_id != session_network_id.as_bytes() {
            return Err(BrokerError::BindingMismatch);
        }
    }
    let payload_len = u64::try_from(request.payload.len()).map_err(|_| BrokerError::Protocol)?;
    let fields = OperationRequestFieldsV1 {
        session_id: request.session_id,
        request_id: request.request_id,
        binding: request.binding.clone(),
        provider_metadata_digest: request.provider_metadata_digest,
        operation: request.operation,
        payload_digest: request.payload_digest,
        payload_len,
    };
    if operation_request_digest(&fields)? != request.request_digest {
        return Err(BrokerError::Protocol);
    }
    validate_operation_payload(request, session_chain_id, session_network_id)?;
    Ok(())
}
fn make_operation_response(
    request: &OperationRequestV1,
    status: u8,
    result: Vec<u8>,
    session_network_id: &NetworkId,
) -> Result<OperationResponseV1, BrokerError> {
    make_operation_response_scrubbed(
        request,
        status,
        ScrubbedBytes::new(result),
        session_network_id,
    )
}
fn make_operation_response_scrubbed(
    request: &OperationRequestV1,
    status: u8,
    result: ScrubbedBytes,
    session_network_id: &NetworkId,
) -> Result<OperationResponseV1, BrokerError> {
    let result_digest = operation_result_digest(&result);
    let fields = OperationResponseFieldsV1 {
        session_id: request.session_id,
        request_id: request.request_id,
        request_digest: request.request_digest,
        observed_binding: request.binding.clone(),
        provider_metadata_digest: request.provider_metadata_digest,
        operation: request.operation,
        payload_digest: request.payload_digest,
        status,
        result_digest,
        result_len: u64::try_from(result.len()).map_err(|_| BrokerError::Protocol)?,
    };
    let response_digest =
        operation_response_digest(&fields).map_err(|error| error.service_error())?;
    let response = operation_response_from_fields(fields, response_digest, result);
    validate_operation_response(request, &response, session_network_id)?;
    Ok(response)
}
/// Move the exact admitted fields and result into the sole response wire owner.
fn operation_response_from_fields(
    fields: OperationResponseFieldsV1,
    response_digest: [u8; 32],
    mut result: ScrubbedBytes,
) -> OperationResponseV1 {
    OperationResponseV1 {
        session_id: fields.session_id,
        request_id: fields.request_id,
        request_digest: fields.request_digest,
        observed_binding: fields.observed_binding,
        provider_metadata_digest: fields.provider_metadata_digest,
        operation: fields.operation,
        payload_digest: fields.payload_digest,
        status: fields.status,
        result_digest: fields.result_digest,
        result: result.take(),
        response_digest,
    }
}
fn validate_signing_payload_len(length: usize) -> Result<(), BrokerError> {
    if length == 0 || length > MAX_SIGNING_PAYLOAD_BYTES_V1 {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_potr_signing_payload(
    payload: &[u8],
    expected_provider_id: [u8; 32],
) -> Result<(), BrokerError> {
    if payload.is_empty() || payload.len() > MAX_POTR_SIGNING_PAYLOAD_BYTES_V1 {
        return Err(BrokerError::Rejected);
    }
    let canonical_receipt = payload
        .strip_prefix(sorafs_manifest::POTR_RECEIPT_SIGNATURE_DOMAIN_V1)
        .filter(|receipt| !receipt.is_empty())
        .ok_or(BrokerError::Rejected)?;
    let receipt = decode_canonical::<sorafs_manifest::PotrReceiptV1>(
        canonical_receipt,
        MAX_POTR_SIGNING_PAYLOAD_BYTES_V1,
    )?;
    if receipt.provider_id != expected_provider_id {
        return Err(BrokerError::BindingMismatch);
    }
    if receipt.gateway_signature.is_some() || receipt.provider_signature.is_some() {
        return Err(BrokerError::Rejected);
    }
    if receipt.validate()
        != Err(sorafs_manifest::PotrReceiptValidationError::MissingGatewaySignature)
    {
        return Err(BrokerError::Rejected);
    }
    if receipt
        .signing_payload_bytes()
        .map_err(|_| BrokerError::Rejected)?
        != payload
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn encode_native_transaction_payload(
    payload: &iroha_data_model::transaction::TransactionPayload,
) -> Result<Vec<u8>, BrokerError> {
    encode_transaction_payload_bounded(payload, MAX_NATIVE_TRANSACTION_PAYLOAD_BYTES_V1)
}
fn encode_transaction_payload_bounded(
    payload: &iroha_data_model::transaction::TransactionPayload,
    max_bytes: usize,
) -> Result<Vec<u8>, BrokerError> {
    let builder = iroha_data_model::transaction::TransactionBuilder::from_payload(payload.clone())
        .map_err(|_| BrokerError::Rejected)?;
    let bytes = builder.encode_payload();
    if max_bytes == 0 || bytes.is_empty() || bytes.len() > max_bytes {
        return Err(BrokerError::Rejected);
    }
    Ok(bytes)
}
fn decode_native_transaction_payload(
    bytes: &[u8],
) -> Result<iroha_data_model::transaction::TransactionPayload, BrokerError> {
    decode_transaction_payload_bounded(bytes, MAX_NATIVE_TRANSACTION_PAYLOAD_BYTES_V1)
}
fn decode_transaction_payload_bounded(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<iroha_data_model::transaction::TransactionPayload, BrokerError> {
    if max_bytes == 0 || bytes.is_empty() || bytes.len() > max_bytes {
        return Err(BrokerError::Rejected);
    }
    let builder = iroha_data_model::transaction::TransactionBuilder::decode_payload(bytes)
        .map_err(|_| BrokerError::Rejected)?;
    builder.into_payload().map_err(|_| BrokerError::Rejected)
}
fn moderation_handoff_kind_for_slot(
    slot: u16,
) -> Option<sorafs_node::moderation_orchestrator::ModerationTerminalHandoffKindV1> {
    if slot == IrohaRuntimeProviderSlotV1::ModerationSettlementHandoff.wire_id() {
        Some(sorafs_node::moderation_orchestrator::ModerationTerminalHandoffKindV1::Settlement)
    } else if slot == IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id() {
        Some(sorafs_node::moderation_orchestrator::ModerationTerminalHandoffKindV1::Publication)
    } else {
        None
    }
}
fn validate_moderation_handoff_request(
    wire: &ModerationDurableHandoffRequestWireV1,
    slot: u16,
    expected_network_id: Option<&NetworkId>,
) -> Result<iroha_torii::sorafs::moderation_runtime::ModerationDurableHandoffRequestV1, BrokerError>
{
    let expected_kind =
        moderation_handoff_kind_for_slot(slot).ok_or(BrokerError::BindingMismatch)?;
    let handoff = &wire.handoff;
    if handoff.kind != expected_kind
        || !handoff.is_bound_to_network(expected_network_id.unwrap_or(&handoff.network_id))
        || handoff.handoff_id == [0; 32]
        || handoff.outcome_digest == [0; 32]
        || handoff.finalized_cursor.block_height == 0
        || handoff.finalized_cursor.block_hash == [0; 32]
        || !iroha_data_model::sorafs::moderation_ledger::is_canonical_moderation_identifier_v1(
            &handoff.case_id,
        )
        || !iroha_data_model::sorafs::moderation_ledger::is_canonical_moderation_identifier_v1(
            &handoff.round_id,
        )
        || wire.canonical_handoff.is_empty()
        || wire.canonical_handoff.len() > MAX_MODERATION_HANDOFF_CANONICAL_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    let canonical = norito::to_bytes(handoff).map_err(|_| BrokerError::Rejected)?;
    if canonical != wire.canonical_handoff {
        return Err(BrokerError::Rejected);
    }
    Ok(
        iroha_torii::sorafs::moderation_runtime::ModerationDurableHandoffRequestV1 {
            handoff: handoff.clone(),
            canonical_handoff: canonical,
        },
    )
}
fn moderation_handoff_request_to_wire(
    request: &iroha_torii::sorafs::moderation_runtime::ModerationDurableHandoffRequestV1,
    slot: u16,
) -> Result<ModerationDurableHandoffRequestWireV1, BrokerError> {
    let wire = ModerationDurableHandoffRequestWireV1 {
        handoff: request.handoff.clone(),
        canonical_handoff: request.canonical_handoff.clone(),
    };
    validate_moderation_handoff_request(&wire, slot, None)?;
    Ok(wire)
}
fn validate_moderation_panel_notification_archive_head_publish_request(
    wire: &ModerationPanelNotificationArchiveHeadPublishRequestWireV1,
    session_network_id: &NetworkId,
) -> Result<
    iroha_torii::sorafs::moderation_runtime::ModerationDurableArchiveHeadPublicationRequestV1,
    BrokerError,
> {
    let publication_slot = IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id();
    if wire.version != MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1
        || wire.slot != publication_slot
        || wire.network_id != *session_network_id
        || wire.head.network_id != wire.network_id
        || wire.canonical_head.is_empty()
        || wire.canonical_head.len() > MAX_MODERATION_HANDOFF_CANONICAL_BYTES_V1
        || wire
            .head
            .verify(
                &wire.head.archive_handle,
                sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
                    wire.head.archive_revision,
                    wire.head.archive_policy_digest,
                ),
                wire.head.archive_id,
                wire.head.archive_public_key,
            )
            .is_err()
    {
        return Err(BrokerError::Rejected);
    }
    let canonical_head = norito::to_bytes(&wire.head).map_err(|_| BrokerError::Rejected)?;
    if canonical_head != wire.canonical_head {
        return Err(BrokerError::Rejected);
    }
    Ok(
        iroha_torii::sorafs::moderation_runtime::ModerationDurableArchiveHeadPublicationRequestV1 {
            head: wire.head.clone(),
            canonical_head,
        },
    )
}
fn validate_moderation_panel_notification_archive_head_at_broker_boundary(
    canonical_head: &[u8],
    network_id: &NetworkId,
    catalog: &[ProviderBindingWireV1],
) -> Result<
    (
        sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveHeadV1,
        sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveBrokerValidationV1,
    ),
    BrokerError,
> {
    let archive_binding = catalog
        .iter()
        .find(|binding| {
            binding.slot == IrohaRuntimeProviderSlotV1::ModerationPanelNotificationArchive.wire_id()
        })
        .ok_or(BrokerError::BindingMismatch)?;
    let archive = archive_binding
        .moderation_panel_notification_archive_binding
        .ok_or(BrokerError::BindingMismatch)?;
    let checkpoint_binding = catalog
        .iter()
        .find(|binding| {
            binding.slot == IrohaRuntimeProviderSlotV1::ModerationCheckpointStore.wire_id()
        })
        .ok_or(BrokerError::BindingMismatch)?;
    let expectation = sorafs_node::moderation_orchestrator::
        ModerationPanelNotificationArchiveBrokerExpectationV1 {
            network_id,
            archive_handle: &archive_binding.handle,
            archive_qualification: sorafs_node::moderation_orchestrator::
                ModerationRuntimeProviderQualificationV1::new(
            archive_binding
                .revision
                .ok_or(BrokerError::BindingMismatch)?,
            archive_binding
                .policy_digest
                .ok_or(BrokerError::BindingMismatch)?,
                ),
            archive_id: archive.archive_id,
            archive_bootstrap_public_key: archive.bootstrap_public_key,
            archive_public_key: archive.public_key,
            checkpoint_handle: &checkpoint_binding.handle,
            checkpoint_qualification: sorafs_node::moderation_orchestrator::
                ModerationRuntimeProviderQualificationV1::new(
                    checkpoint_binding
                        .revision
                        .ok_or(BrokerError::BindingMismatch)?,
                    checkpoint_binding
                        .policy_digest
                        .ok_or(BrokerError::BindingMismatch)?,
                ),
            checkpoint_attestation_public_key: checkpoint_binding
                .moderation_checkpoint_attestation_public_key
                .ok_or(BrokerError::BindingMismatch)?,
            checkpoint_max_bytes: checkpoint_binding
                .moderation_checkpoint_max_bytes
                .ok_or(BrokerError::BindingMismatch)?,
            archive_max_bytes: archive.max_bytes,
            max_records: usize::try_from(archive.max_records)
                .map_err(|_| BrokerError::BindingMismatch)?,
        };
    sorafs_node::moderation_orchestrator::
        validate_moderation_panel_notification_archive_head_for_broker_v1(
            canonical_head,
            &expectation,
        )
        .map_err(|_| BrokerError::Rejected)
}
fn validate_moderation_panel_notification_archive_public_head_readback_at_broker_boundary(
    canonical_head: &[u8],
    network_id: &NetworkId,
) -> Result<
    sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveHeadV1,
    BrokerError,
> {
    if canonical_head.is_empty() || canonical_head.len() > MAX_MODERATION_HANDOFF_CANONICAL_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    let head = decode_canonical::<
        sorafs_node::moderation_orchestrator::ModerationPanelNotificationArchiveHeadV1,
    >(canonical_head, MAX_MODERATION_HANDOFF_CANONICAL_BYTES_V1)?;
    if head.network_id != *network_id
        || norito::to_bytes(&head)
            .map_err(|_| BrokerError::Rejected)?
            .as_slice()
            != canonical_head
        || head
            .verify(
                &head.archive_handle,
                sorafs_node::moderation_orchestrator::ModerationRuntimeProviderQualificationV1::new(
                    head.archive_revision,
                    head.archive_policy_digest,
                ),
                head.archive_id,
                head.archive_public_key,
            )
            .is_err()
    {
        return Err(BrokerError::Rejected);
    }
    Ok(head)
}
fn moderation_panel_notification_archive_head_publish_request_to_wire(
    request: &iroha_torii::sorafs::moderation_runtime::
        ModerationDurableArchiveHeadPublicationRequestV1,
    network_id: &NetworkId,
    catalog: &[ProviderBindingWireV1],
) -> Result<ModerationPanelNotificationArchiveHeadPublishRequestWireV1, BrokerError> {
    let wire = ModerationPanelNotificationArchiveHeadPublishRequestWireV1 {
        version: MODERATION_PANEL_NOTIFICATION_ARCHIVE_BROKER_WIRE_VERSION_V1,
        slot: IrohaRuntimeProviderSlotV1::ModerationPublicationHandoff.wire_id(),
        network_id: *network_id,
        head: request.head.clone(),
        canonical_head: request.canonical_head.clone(),
    };
    validate_moderation_panel_notification_archive_head_publish_request(&wire, network_id)?;
    let (validated_head, _) =
        validate_moderation_panel_notification_archive_head_at_broker_boundary(
            &wire.canonical_head,
            network_id,
            catalog,
        )?;
    if validated_head != wire.head {
        return Err(BrokerError::Rejected);
    }
    Ok(wire)
}
fn validate_moderation_panel_notification_request(
    wire: &ModerationDurablePanelNotificationRequestWireV1,
    expected_network_id: Option<&NetworkId>,
) -> Result<
    iroha_torii::sorafs::moderation_runtime::ModerationDurablePanelNotificationRequestV1,
    BrokerError,
> {
    let notification = &wire.notification;
    if !notification.is_bound_to_network(expected_network_id.unwrap_or(&notification.network_id))
        || notification.notification_id == [0; 32]
        || notification.source_operation_id == [0; 32]
        || notification.scope_digest == [0; 32]
        || notification.finalized_event_cursor.sequence == 0
        || notification.finalized_event_cursor.block_height == 0
        || notification.finalized_event_cursor.block_hash == [0; 32]
        || notification.source_occurred_at_unix_ms == 0
        || wire.lease_expires_at_unix_ms <= notification.source_occurred_at_unix_ms
        || wire.attempt == 0
        || wire.attempt > wire.attempt_limit
        || wire.canonical_notification.is_empty()
        || wire.canonical_notification.len() > MAX_MODERATION_PANEL_NOTIFICATION_CANONICAL_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    let canonical = norito::to_bytes(notification).map_err(|_| BrokerError::Rejected)?;
    if canonical != wire.canonical_notification {
        return Err(BrokerError::Rejected);
    }
    Ok(
        iroha_torii::sorafs::moderation_runtime::ModerationDurablePanelNotificationRequestV1 {
            notification: notification.clone(),
            canonical_notification: canonical,
            lease_expires_at_unix_ms: wire.lease_expires_at_unix_ms,
            attempt: wire.attempt,
            attempt_limit: wire.attempt_limit,
        },
    )
}
fn moderation_panel_notification_request_to_wire(
    request: &iroha_torii::sorafs::moderation_runtime::ModerationDurablePanelNotificationRequestV1,
) -> Result<ModerationDurablePanelNotificationRequestWireV1, BrokerError> {
    let wire = ModerationDurablePanelNotificationRequestWireV1 {
        notification: request.notification.clone(),
        canonical_notification: request.canonical_notification.clone(),
        lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
        attempt: request.attempt,
        attempt_limit: request.attempt_limit,
    };
    validate_moderation_panel_notification_request(&wire, None)?;
    Ok(wire)
}
fn validate_moderation_panel_notification_receipt(
    receipt: ModerationPanelNotificationReceiptWireV1,
    request: &ModerationDurablePanelNotificationRequestWireV1,
) -> Result<
    sorafs_node::moderation_orchestrator::ModerationPanelNotificationDeliveryReceiptV1,
    BrokerError,
> {
    if receipt.notification_id != request.notification.notification_id
        || receipt.receipt_digest == [0; 32]
        || receipt.delivered_at_unix_ms < request.notification.source_occurred_at_unix_ms
        || receipt.delivered_at_unix_ms >= request.lease_expires_at_unix_ms
    {
        return Err(BrokerError::Rejected);
    }
    Ok(
        sorafs_node::moderation_orchestrator::ModerationPanelNotificationDeliveryReceiptV1 {
            notification_id: receipt.notification_id,
            receipt_digest: receipt.receipt_digest,
            delivered_at_unix_ms: receipt.delivered_at_unix_ms,
        },
    )
}
const fn moderation_panel_notification_receipt_to_wire(
    receipt: sorafs_node::moderation_orchestrator::ModerationPanelNotificationDeliveryReceiptV1,
) -> ModerationPanelNotificationReceiptWireV1 {
    ModerationPanelNotificationReceiptWireV1 {
        notification_id: receipt.notification_id,
        receipt_digest: receipt.receipt_digest,
        delivered_at_unix_ms: receipt.delivered_at_unix_ms,
    }
}
fn validate_moderation_quarantine_key_id(key_id: &str) -> Result<(), BrokerError> {
    if key_id.len() > MAX_MODERATION_QUARANTINE_KEY_ID_BYTES_V1
        || iroha_config::parameters::validate_production_runtime_handle(key_id).is_err()
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_moderation_quarantine_context_and_dek(
    context_digest: [u8; 32],
    dek: [u8; 32],
) -> Result<(), BrokerError> {
    if context_digest == [0; 32] || dek == [0; 32] {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_moderation_quarantine_wrapped_dek(wrapped_dek: &[u8]) -> Result<(), BrokerError> {
    if wrapped_dek.is_empty() || wrapped_dek.len() > MAX_MODERATION_QUARANTINE_WRAPPED_DEK_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_gateway_dns_hostname(hostname: &str, allow_wildcard: bool) -> Result<(), BrokerError> {
    if hostname.len() > MAX_GATEWAY_ACME_HOSTNAME_BYTES_V1 {
        return Err(BrokerError::Rejected);
    }
    let hostname = if allow_wildcard {
        hostname.strip_prefix("*.").unwrap_or(hostname)
    } else {
        hostname
    };
    let restricted_suffix = hostname
        .rsplit_once('.')
        .is_some_and(|(_, suffix)| matches!(suffix, "localhost" | "local" | "internal" | "onion"));
    if hostname.is_empty()
        || hostname.len() > MAX_GATEWAY_ACME_HOSTNAME_BYTES_V1
        || !hostname.is_ascii()
        || !hostname.contains('.')
        || hostname.ends_with('.')
        || hostname == "localhost"
        || restricted_suffix
        || hostname.parse::<std::net::IpAddr>().is_ok()
        || hostname.bytes().any(|byte| byte.is_ascii_uppercase())
        || !hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_gateway_https_url(raw: &str) -> Result<reqwest::Url, BrokerError> {
    if raw.is_empty()
        || raw.len() > MAX_GATEWAY_COMPLIANCE_URL_BYTES_V1
        || raw.as_bytes().contains(&0)
        || raw.chars().any(char::is_control)
    {
        return Err(BrokerError::Rejected);
    }
    let parsed = reqwest::Url::parse(raw).map_err(|_| BrokerError::Rejected)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.port().is_some_and(|port| port != 443)
        || parsed.as_str() != raw
    {
        return Err(BrokerError::Rejected);
    }
    let hostname = parsed.host_str().ok_or(BrokerError::Rejected)?;
    validate_gateway_dns_hostname(hostname, false)?;
    Ok(parsed)
}
fn validate_gateway_acme_order(order: &GatewayAcmeOrderRequestWireV1) -> Result<(), BrokerError> {
    if order.hostnames.is_empty()
        || order.hostnames.len() > MAX_GATEWAY_ACME_HOSTNAMES_V1
        || !order.dns01 && !order.tls_alpn_01
    {
        return Err(BrokerError::Rejected);
    }
    for hostname in &order.hostnames {
        validate_gateway_dns_hostname(hostname, true)?;
        if hostname.starts_with("*.") && !order.dns01 {
            return Err(BrokerError::Rejected);
        }
    }
    if let Some(email) = order.account_email.as_deref()
        && (email.is_empty()
            || email.len() > MAX_GATEWAY_ACME_EMAIL_BYTES_V1
            || email.trim() != email
            || email.as_bytes().contains(&0)
            || email.chars().any(char::is_control)
            || !email.contains('@'))
    {
        return Err(BrokerError::Rejected);
    }
    if order.directory_url.len() > MAX_GATEWAY_ACME_URL_BYTES_V1 {
        return Err(BrokerError::Rejected);
    }
    validate_gateway_https_url(&order.directory_url)?;
    if let Some(provider) = order.dns_provider_id.as_deref()
        && (provider.is_empty()
            || provider.len() > MAX_GATEWAY_ACME_DNS_PROVIDER_ID_BYTES_V1
            || provider.trim() != provider
            || provider.as_bytes().contains(&0)
            || provider.chars().any(char::is_control))
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_gateway_acme_outcome(
    outcome: &GatewayAcmeOrderOutcomeWireV1,
) -> Result<(), BrokerError> {
    match outcome.outcome {
        0 => {
            if outcome.certificate_pem.is_empty()
                || outcome.certificate_pem.len() > MAX_GATEWAY_ACME_CERTIFICATE_PEM_BYTES_V1
                || outcome.private_key_pem.is_empty()
                || outcome.private_key_pem.len() > MAX_GATEWAY_ACME_PRIVATE_KEY_PEM_BYTES_V1
                || outcome.ech_config.as_ref().is_some_and(|value| {
                    value.is_empty() || value.len() > MAX_GATEWAY_ACME_ECH_CONFIG_BYTES_V1
                })
                || outcome.not_after.is_none()
                || outcome.retry_after.is_some()
            {
                return Err(BrokerError::Rejected);
            }
            outcome
                .not_after
                .ok_or(BrokerError::Rejected)?
                .to_system_time()?;
        }
        1 | 3 => {
            if !outcome.certificate_pem.is_empty()
                || !outcome.private_key_pem.is_empty()
                || outcome.ech_config.is_some()
                || outcome.not_after.is_some()
                || outcome.retry_after.is_some()
            {
                return Err(BrokerError::Rejected);
            }
        }
        2 => {
            if !outcome.certificate_pem.is_empty()
                || !outcome.private_key_pem.is_empty()
                || outcome.ech_config.is_some()
                || outcome.not_after.is_some()
                || outcome
                    .retry_after
                    .is_some_and(|duration| duration.to_duration().is_err())
            {
                return Err(BrokerError::Rejected);
            }
        }
        _ => return Err(BrokerError::Rejected),
    }
    Ok(())
}
fn gateway_address_is_public(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || a == 0
                || a >= 224
                || a == 100 && (64..=127).contains(&b)
                || a == 192 && b == 0 && c == 0
                || a == 192 && b == 0 && c == 2
                || a == 198 && (b == 18 || b == 19)
                || a == 198 && b == 51 && c == 100
                || a == 203 && b == 0 && c == 113)
        }
        std::net::IpAddr::V6(address) => {
            let segments = address.segments();
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|ipv4| !gateway_address_is_public(std::net::IpAddr::V4(ipv4))))
        }
    }
}
fn gateway_addresses_from_wire(
    addresses: &[IpAddressWireV1],
    require_canonical_order: bool,
) -> Result<Vec<std::net::IpAddr>, BrokerError> {
    if addresses.is_empty() || addresses.len() > MAX_GATEWAY_COMPLIANCE_DNS_ADDRESSES_V1 {
        return Err(BrokerError::Rejected);
    }
    let addresses = addresses
        .iter()
        .map(IpAddressWireV1::to_address)
        .collect::<Result<Vec<_>, _>>()?;
    if addresses
        .iter()
        .any(|address| !gateway_address_is_public(*address))
        || require_canonical_order && addresses.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(BrokerError::Rejected);
    }
    Ok(addresses)
}
fn validate_gateway_compliance_resolve_request(
    request: &GatewayComplianceResolveRequestWireV1,
) -> Result<Duration, BrokerError> {
    validate_gateway_dns_hostname(&request.hostname, false)?;
    let timeout = request.timeout.to_duration()?;
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Err(BrokerError::Rejected);
    }
    Ok(timeout)
}
fn validate_gateway_compliance_fetch_request(
    request: &GatewayComplianceFetchRequestWireV1,
) -> Result<
    (
        reqwest::Url,
        Vec<std::net::IpAddr>,
        Duration,
        Duration,
        usize,
    ),
    BrokerError,
> {
    let url = validate_gateway_https_url(&request.url)?;
    let addresses = gateway_addresses_from_wire(&request.pinned_addresses, true)?;
    let connect_timeout = request.connect_timeout.to_duration()?;
    let total_timeout = request.total_timeout.to_duration()?;
    let max_encoded_bytes =
        usize::try_from(request.max_encoded_bytes).map_err(|_| BrokerError::Rejected)?;
    if connect_timeout.is_zero()
        || connect_timeout > Duration::from_secs(30)
        || total_timeout < connect_timeout
        || total_timeout > Duration::from_secs(120)
        || max_encoded_bytes == 0
        || max_encoded_bytes > MAX_GATEWAY_COMPLIANCE_BODY_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    Ok((
        url,
        addresses,
        connect_timeout,
        total_timeout,
        max_encoded_bytes,
    ))
}
fn gateway_compliance_error_wire(
    error: &iroha_torii::sorafs::gateway::GatewayComplianceError,
) -> (u8, u64, u64) {
    use iroha_torii::sorafs::gateway::GatewayComplianceError as Error;
    match error {
        Error::FetchTimeout => (1, 0, 0),
        Error::DnsRebinding => (2, 0, 0),
        Error::NonPublicAddress => (3, 0, 0),
        Error::UnsafeAddressSet { found, maximum } => (
            4,
            u64::try_from(*found).unwrap_or(u64::MAX),
            u64::try_from(*maximum).unwrap_or(u64::MAX),
        ),
        Error::TrustPinMismatch => (5, 0, 0),
        Error::ResourceLimit { found, maximum, .. } => (
            6,
            u64::try_from(*found).unwrap_or(u64::MAX),
            u64::try_from(*maximum).unwrap_or(u64::MAX),
        ),
        _ => (7, 0, 0),
    }
}
fn gateway_compliance_error_from_wire(
    outcome: u8,
    found: u64,
    maximum: u64,
) -> Result<iroha_torii::sorafs::gateway::GatewayComplianceError, BrokerError> {
    use iroha_torii::sorafs::gateway::GatewayComplianceError as Error;
    let found = usize::try_from(found).map_err(|_| BrokerError::Protocol)?;
    let maximum = usize::try_from(maximum).map_err(|_| BrokerError::Protocol)?;
    match outcome {
        1 if found == 0 && maximum == 0 => Ok(Error::FetchTimeout),
        2 if found == 0 && maximum == 0 => Ok(Error::DnsRebinding),
        3 if found == 0 && maximum == 0 => Ok(Error::NonPublicAddress),
        4 => Ok(Error::UnsafeAddressSet { found, maximum }),
        5 if found == 0 && maximum == 0 => Ok(Error::TrustPinMismatch),
        6 => Ok(Error::ResourceLimit {
            resource: "broker compliance transport",
            found,
            maximum,
        }),
        7 if found == 0 && maximum == 0 => Ok(Error::FeedTransportOperationFailed),
        _ => Err(BrokerError::Protocol),
    }
}
fn validate_gateway_compliance_resolve_outcome(
    outcome: &GatewayComplianceResolveOutcomeWireV1,
) -> Result<(), BrokerError> {
    if outcome.outcome == 0 {
        if outcome.found != 0 || outcome.maximum != 0 {
            return Err(BrokerError::Protocol);
        }
        gateway_addresses_from_wire(&outcome.addresses, false)?;
    } else {
        if !outcome.addresses.is_empty() {
            return Err(BrokerError::Protocol);
        }
        gateway_compliance_error_from_wire(outcome.outcome, outcome.found, outcome.maximum)?;
    }
    Ok(())
}
fn validate_gateway_compliance_fetch_outcome(
    outcome: &GatewayComplianceFetchOutcomeWireV1,
    request: &GatewayComplianceFetchRequestWireV1,
) -> Result<(), BrokerError> {
    let (_, pinned_addresses, _, total_timeout, max_encoded_bytes) =
        validate_gateway_compliance_fetch_request(request)?;
    if outcome.outcome == 0 {
        let connected_address = outcome
            .connected_address
            .as_ref()
            .ok_or(BrokerError::Protocol)?
            .to_address()?;
        let elapsed = outcome
            .elapsed
            .ok_or(BrokerError::Protocol)?
            .to_duration()?;
        if !(100..=599).contains(&outcome.status)
            || outcome.redirect_location.as_ref().is_some_and(|location| {
                location.is_empty()
                    || location.len() > MAX_GATEWAY_COMPLIANCE_URL_BYTES_V1
                    || location.as_bytes().contains(&0)
                    || location.chars().any(char::is_control)
            })
            || !pinned_addresses.contains(&connected_address)
            || !gateway_address_is_public(connected_address)
            || outcome.peer_spki_sha256 == [0; 32]
            || outcome.content_encoding > 2
            || outcome.body.len() > max_encoded_bytes
            || elapsed > total_timeout
            || outcome.found != 0
            || outcome.maximum != 0
        {
            return Err(BrokerError::Protocol);
        }
    } else {
        if outcome.status != 0
            || outcome.redirect_location.is_some()
            || outcome.connected_address.is_some()
            || outcome.peer_spki_sha256 != [0; 32]
            || outcome.content_encoding != 0
            || !outcome.body.is_empty()
            || outcome.elapsed.is_some()
        {
            return Err(BrokerError::Protocol);
        }
        gateway_compliance_error_from_wire(outcome.outcome, outcome.found, outcome.maximum)?;
    }
    Ok(())
}
fn pop_runtime_bindings_from_wire(
    binding: &ProviderBindingWireV1,
) -> Result<iroha_torii::sorafs::pop_api::PopCredentialRuntimeProviderBindingsV1, BrokerError> {
    let exact = required_binding_ref!(binding, pop_credential_runtime_binding);
    iroha_torii::sorafs::pop_api::PopCredentialRuntimeProviderBindingsV1::try_new(
        exact.issuer_policy_digest,
        exact.issuer_id.clone(),
        exact.issuer_signer_handle.clone(),
        exact.issuer_public_key,
        (
            exact.enrollment_recipient_key_id.clone(),
            exact.enrollment_recipient_public_key_digest,
        ),
        (
            exact.wallet_recipient_key_id.clone(),
            exact.wallet_recipient_public_key_digest,
        ),
        exact.wallet_wrapping_key_id.clone(),
    )
    .map_err(|_| BrokerError::BindingMismatch)
}
const fn pop_action_to_wire(action: sorafs_node::pop_credentials::PopCredentialApiActionV1) -> u8 {
    use sorafs_node::pop_credentials::PopCredentialApiActionV1 as Action;
    match action {
        Action::SubmitEnrollment => 1,
        Action::ReadEnrollmentStatus => 2,
        Action::ApproveEnrollment => 3,
        Action::IssueCredential => 4,
        Action::TriggerCredentialIssuance => 5,
        Action::EnqueueRevocation => 6,
        Action::SubmitRegistryOutbox => 7,
        Action::ReconcileRegistry => 8,
        Action::ReadRegistryProjection => 9,
        Action::FetchWalletDelivery => 10,
        Action::AcknowledgeWalletDelivery => 11,
        Action::ImportWalletDelivery => 12,
        Action::SynchronizeWalletWitness => 13,
        Action::ProveMembership => 14,
        Action::VerifyMembership => 15,
    }
}
fn pop_action_from_wire(
    action: u8,
) -> Result<sorafs_node::pop_credentials::PopCredentialApiActionV1, BrokerError> {
    use sorafs_node::pop_credentials::PopCredentialApiActionV1 as Action;
    match action {
        1 => Ok(Action::SubmitEnrollment),
        2 => Ok(Action::ReadEnrollmentStatus),
        3 => Ok(Action::ApproveEnrollment),
        4 => Ok(Action::IssueCredential),
        5 => Ok(Action::TriggerCredentialIssuance),
        6 => Ok(Action::EnqueueRevocation),
        7 => Ok(Action::SubmitRegistryOutbox),
        8 => Ok(Action::ReconcileRegistry),
        9 => Ok(Action::ReadRegistryProjection),
        10 => Ok(Action::FetchWalletDelivery),
        11 => Ok(Action::AcknowledgeWalletDelivery),
        12 => Ok(Action::ImportWalletDelivery),
        13 => Ok(Action::SynchronizeWalletWitness),
        14 => Ok(Action::ProveMembership),
        15 => Ok(Action::VerifyMembership),
        _ => Err(BrokerError::Rejected),
    }
}
fn validate_pop_authenticate_request(
    request: &PopAuthenticateRequestWireV1,
) -> Result<(), BrokerError> {
    if request.opaque_credential.is_empty()
        || request.opaque_credential.len()
            > sorafs_node::pop_credentials::POP_API_AUTHENTICATION_MAX_BYTES_V1
        || request.request_binding == [0; 32]
        || request.now_epoch == 0
    {
        return Err(BrokerError::Rejected);
    }
    pop_action_from_wire(request.action).map(drop)
}
fn validate_pop_principal(
    principal: PopAuthenticatedPrincipalWireV1,
    request: &PopAuthenticateRequestWireV1,
) -> Result<(), BrokerError> {
    if principal.principal_digest == [0; 32] || principal.expires_at_epoch <= request.now_epoch {
        return Err(BrokerError::Rejected);
    }
    if pop_action_from_wire(request.action)?.requires_caller_signed_transaction()
        && !principal.caller_signed_transaction
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_pop_projection(
    projection: &sorafs_node::pop_credentials::PopFinalizedRegistryProjectionV1,
    exact: &PopCredentialRuntimeBindingWireV1,
) -> Result<(), BrokerError> {
    use sorafs_manifest::pop_credentials::{
        PopCommitmentRootV1, PopRevocationListV1, verify_pop_commitment_root_signature_v1,
        verify_pop_revocation_list_signature_v1,
    };
    validate_pop_cursor(projection.cursor)?;
    if projection.version
        != sorafs_node::pop_credentials::POP_FINALIZED_REGISTRY_PROJECTION_VERSION_V1
        || projection.issuer_policy_digest != exact.issuer_policy_digest
        || (projection.cursor.block_height == 1 && projection.previous_block_hash.is_some())
        || (projection.cursor.block_height > 1
            && projection
                .previous_block_hash
                .is_none_or(|digest| digest == [0; 32]))
        || projection.canonical_commitment_root.is_empty()
        || projection.canonical_commitment_root.len()
            > sorafs_node::pop_credentials::POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1
        || projection.canonical_revocation_list.is_empty()
        || projection.canonical_revocation_list.len()
            > sorafs_node::pop_credentials::POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    let collections = [
        projection.committed_operation_digests.as_slice(),
        projection.rejected_operation_digests.as_slice(),
        projection.revoked_issuer_public_keys.as_slice(),
    ];
    if collections.iter().any(|values| {
        values.len() > sorafs_node::pop_credentials::POP_SERVICE_COLLECTION_MAX_V1
            || values.contains(&[0; 32])
            || values.windows(2).any(|pair| pair[0] >= pair[1])
    }) || projection.committed_operation_digests.iter().any(|digest| {
        projection
            .rejected_operation_digests
            .binary_search(digest)
            .is_ok()
    }) {
        return Err(BrokerError::Rejected);
    }
    if projection
        .revoked_issuer_public_keys
        .iter()
        .any(|key| iroha_crypto::ed25519_parse_public_key(key).is_err())
    {
        return Err(BrokerError::Rejected);
    }
    let root = decode_canonical::<PopCommitmentRootV1>(
        &projection.canonical_commitment_root,
        sorafs_node::pop_credentials::POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1,
    )?;
    let revocations = decode_canonical::<PopRevocationListV1>(
        &projection.canonical_revocation_list,
        sorafs_node::pop_credentials::POP_ENCRYPTED_ENROLLMENT_MAX_BYTES_V1,
    )?;
    verify_pop_commitment_root_signature_v1(&root).map_err(|_| BrokerError::Rejected)?;
    verify_pop_revocation_list_signature_v1(&revocations).map_err(|_| BrokerError::Rejected)?;
    if root.issuer_id != exact.issuer_id
        || revocations.issuer_id != exact.issuer_id
        || root.publisher_signature.public_key.as_slice() != exact.issuer_public_key.as_slice()
        || revocations.publisher_signature.public_key.as_slice()
            != exact.issuer_public_key.as_slice()
        || revocations.commitment_root != root.root_digest
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_pop_witness_wire(witness: &PopMembershipWitnessWireV1) -> Result<(), BrokerError> {
    let witness = sorafs_manifest::pop_credentials::PopMembershipWitnessV1 {
        holder_secret: witness.holder_secret,
        credential_path: sorafs_manifest::pop_credentials::PopCredentialMerklePathV1 {
            siblings: witness.credential_siblings.clone(),
            directions: witness.credential_directions.clone(),
        },
        revocation_path: sorafs_manifest::pop_credentials::PopRevocationNonMembershipPathV1 {
            siblings: witness.revocation_siblings.clone(),
        },
    };
    witness.validate().map_err(|_| BrokerError::Rejected)
}
fn validate_pop_draft(
    draft: &PopIssuanceDraftResultWireV1,
    request: PopIssuanceDraftRequestWireV1,
    exact: &PopCredentialRuntimeBindingWireV1,
) -> Result<(), BrokerError> {
    if request.request_id == [0; 32]
        || request.now_epoch == 0
        || draft.request_id != request.request_id
        || draft.credential.version != sorafs_manifest::POP_CREDENTIAL_VERSION_V1
        || draft.commitment_root.version != sorafs_manifest::POP_COMMITMENT_ROOT_VERSION_V1
        || draft.revocation_list.version != sorafs_manifest::POP_REVOCATION_LIST_VERSION_V1
        || draft.credential.issuer_id != exact.issuer_id
        || draft.commitment_root.issuer_id != exact.issuer_id
        || draft.revocation_list.issuer_id != exact.issuer_id
        || draft.credential.issuer_signature.public_key.as_slice()
            != exact.issuer_public_key.as_slice()
        || draft
            .commitment_root
            .publisher_signature
            .public_key
            .as_slice()
            != exact.issuer_public_key.as_slice()
        || draft
            .revocation_list
            .publisher_signature
            .public_key
            .as_slice()
            != exact.issuer_public_key.as_slice()
        || !draft.credential.issuer_signature.signature.is_empty()
        || !draft
            .commitment_root
            .publisher_signature
            .signature
            .is_empty()
        || !draft
            .revocation_list
            .publisher_signature
            .signature
            .is_empty()
        || draft.credential.issued_at_epoch > request.now_epoch
        || draft.credential.expires_at_epoch <= request.now_epoch
        || draft.credential.commitment_root != draft.commitment_root.root_digest
        || draft.credential.commitment_tree_version != draft.commitment_root.tree_version
        || draft.credential.revocation_list_version != draft.revocation_list.list_version
        || draft.revocation_list.commitment_root != draft.commitment_root.root_digest
        || draft.credential.issuer_signature.algorithm
            != sorafs_manifest::pop_credentials::PopSignatureAlgorithmV1::Ed25519
        || draft.commitment_root.publisher_signature.algorithm
            != sorafs_manifest::pop_credentials::PopSignatureAlgorithmV1::Ed25519
        || draft.revocation_list.publisher_signature.algorithm
            != sorafs_manifest::pop_credentials::PopSignatureAlgorithmV1::Ed25519
    {
        return Err(BrokerError::Rejected);
    }
    validate_pop_witness_wire(&draft.witness)
}
fn validate_pop_finalized_time(sample: PopFinalizedTimeResultWireV1) -> Result<(), BrokerError> {
    if sample.finalized_block_height == 0
        || sample.finalized_block_hash == [0; 32]
        || sample.finalized_epoch == 0
        || sample.observed_epoch == 0
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn por_replay_archive_exact_binding(
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::PorFinalizedReplayArchiveBindingV1, BrokerError> {
    let exact = required_binding_value!(binding, por_replay_archive_binding);
    let canonical = sorafs_node::PorFinalizedReplayArchiveBindingV1::try_new(
        exact.archive_id,
        exact.revision,
        exact.policy_digest,
        exact.signing_public_key,
    )
    .map_err(|_| BrokerError::BindingMismatch)?;
    if canonical != exact
        || binding.revision != Some(exact.revision)
        || binding.policy_digest != Some(exact.policy_digest)
    {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(exact)
}
fn por_replay_archive_configured_proof_bounds(
    binding: &ProviderBindingWireV1,
) -> Result<
    (
        PorReplayArchiveProofLimitsWireV1,
        sorafs_node::PorFinalizedReplayArchiveProofBoundsV1,
    ),
    BrokerError,
> {
    let limits = required_binding_value!(binding, por_replay_archive_proof_limits);
    if limits.max_successor_receipts
        > iroha_config::parameters::defaults::sorafs::storage::por_replay_archive::
            MAX_SUCCESSOR_RECEIPTS_LIMIT
        || limits.max_successor_proof_bytes
            > u64::try_from(MAX_POR_REPLAY_ARCHIVE_SUCCESSOR_PROOF_BYTES_V1)
                .map_err(|_| BrokerError::Protocol)?
    {
        return Err(BrokerError::BindingMismatch);
    }
    let bounds = sorafs_node::PorFinalizedReplayArchiveProofBoundsV1::try_new(
        limits.max_successor_receipts,
        limits.max_successor_proof_bytes,
    )
    .map_err(|_| BrokerError::BindingMismatch)?;
    Ok((limits, bounds))
}
fn decode_por_replay_archive_record(
    canonical_record: &[u8],
) -> Result<sorafs_node::PorFinalizedReplayArchiveRecordV1, BrokerError> {
    if canonical_record.is_empty()
        || canonical_record.len() > MAX_POR_REPLAY_ARCHIVE_RECORD_BYTES_V1
    {
        return Err(BrokerError::Rejected);
    }
    let record = decode_canonical::<sorafs_node::PorFinalizedReplayArchiveRecordV1>(
        canonical_record,
        MAX_POR_REPLAY_ARCHIVE_RECORD_BYTES_V1,
    )?;
    record.validate().map_err(|_| BrokerError::Rejected)?;
    Ok(record)
}
fn encode_por_replay_archive_record(
    record: &sorafs_node::PorFinalizedReplayArchiveRecordV1,
) -> Result<Vec<u8>, BrokerError> {
    record.validate().map_err(|_| BrokerError::Rejected)?;
    encode_canonical(record, MAX_POR_REPLAY_ARCHIVE_RECORD_BYTES_V1)
}
fn validate_por_replay_archive_receipt(
    receipt: &sorafs_node::PorFinalizedReplayArchiveReceiptV1,
    exact: sorafs_node::PorFinalizedReplayArchiveBindingV1,
) -> Result<(), BrokerError> {
    receipt.validate().map_err(|_| BrokerError::Rejected)?;
    if receipt.binding() != exact {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn validate_por_replay_archive_append_request(
    request: &PorReplayArchiveAppendRequestWireV1,
) -> Result<sorafs_node::PorFinalizedReplayArchiveRecordV1, BrokerError> {
    if request.expected_previous_head == Some([0; 32]) {
        return Err(BrokerError::Rejected);
    }
    decode_por_replay_archive_record(&request.canonical_record)
}
fn validate_por_replay_archive_lookup_request(
    request: &PorReplayArchiveLookupRequestWireV1,
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::PorFinalizedReplayArchiveProofBoundsV1, BrokerError> {
    let exact = por_replay_archive_exact_binding(binding)?;
    let (configured, _) = por_replay_archive_configured_proof_bounds(binding)?;
    if request.challenge_id == [0; 32]
        || request.max_successor_receipts == 0
        || request.max_successor_receipts > configured.max_successor_receipts
        || request.max_successor_proof_bytes == 0
        || request.max_successor_proof_bytes > configured.max_successor_proof_bytes
    {
        return Err(BrokerError::Rejected);
    }
    validate_por_replay_archive_receipt(&request.expected_checkpoint_head, exact)?;
    sorafs_node::PorFinalizedReplayArchiveProofBoundsV1::try_new(
        request.max_successor_receipts,
        request.max_successor_proof_bytes,
    )
    .map_err(|_| BrokerError::Rejected)
}
fn por_replay_archive_lookup_to_wire(
    lookup: sorafs_node::PorFinalizedReplayArchiveLookupV1,
    request: &PorReplayArchiveLookupRequestWireV1,
    exact: sorafs_node::PorFinalizedReplayArchiveBindingV1,
    bounds: sorafs_node::PorFinalizedReplayArchiveProofBoundsV1,
) -> Result<PorReplayArchiveLookupOutcomeWireV1, BrokerError> {
    match lookup {
        sorafs_node::PorFinalizedReplayArchiveLookupV1::Found(readback) => {
            readback
                .validate_at_checkpoint(exact, request.expected_checkpoint_head, bounds)
                .map_err(|_| BrokerError::Rejected)?;
            if readback.record.challenge_id() != request.challenge_id {
                return Err(BrokerError::Rejected);
            }
            let canonical_record = encode_por_replay_archive_record(&readback.record)?;
            let declared_successor_receipts = u32::try_from(readback.successor_receipts.len())
                .map_err(|_| BrokerError::Rejected)?;
            let canonical_successor_receipts = encode_canonical(
                &readback.successor_receipts,
                MAX_POR_REPLAY_ARCHIVE_SUCCESSOR_PROOF_BYTES_V1,
            )?;
            bounds
                .validate_framed_successor_shape(
                    u64::from(declared_successor_receipts),
                    u64::try_from(canonical_successor_receipts.len())
                        .map_err(|_| BrokerError::Rejected)?,
                )
                .map_err(|_| BrokerError::Rejected)?;
            Ok(PorReplayArchiveLookupOutcomeWireV1 {
                outcome: 1,
                canonical_record,
                receipt: Some(readback.receipt),
                declared_successor_receipts,
                canonical_successor_receipts,
                absence_proof: None,
            })
        }
        sorafs_node::PorFinalizedReplayArchiveLookupV1::Absent(absence_proof) => {
            absence_proof
                .validate_at_checkpoint(
                    exact,
                    request.challenge_id,
                    request.expected_checkpoint_head,
                )
                .map_err(|_| BrokerError::Rejected)?;
            Ok(PorReplayArchiveLookupOutcomeWireV1 {
                outcome: 2,
                canonical_record: Vec::new(),
                receipt: None,
                declared_successor_receipts: 0,
                canonical_successor_receipts: Vec::new(),
                absence_proof: Some(*absence_proof),
            })
        }
    }
}
fn por_replay_archive_lookup_from_wire(
    outcome: &PorReplayArchiveLookupOutcomeWireV1,
    request: &PorReplayArchiveLookupRequestWireV1,
    binding: &ProviderBindingWireV1,
) -> Result<sorafs_node::PorFinalizedReplayArchiveLookupV1, BrokerError> {
    let exact = por_replay_archive_exact_binding(binding)?;
    let bounds = validate_por_replay_archive_lookup_request(request, binding)?;
    match outcome.outcome {
        1 => {
            if outcome.absence_proof.is_some()
                || outcome.receipt.is_none()
                || outcome.canonical_successor_receipts.is_empty()
            {
                return Err(BrokerError::Rejected);
            }
            bounds
                .validate_framed_successor_shape(
                    u64::from(outcome.declared_successor_receipts),
                    u64::try_from(outcome.canonical_successor_receipts.len())
                        .map_err(|_| BrokerError::Rejected)?,
                )
                .map_err(|_| BrokerError::Rejected)?;
            let successor_limit = usize::try_from(request.max_successor_proof_bytes)
                .map_err(|_| BrokerError::Rejected)?;
            let successor_receipts = decode_canonical::<
                Vec<sorafs_node::PorFinalizedReplayArchiveReceiptV1>,
            >(
                &outcome.canonical_successor_receipts, successor_limit
            )?;
            if successor_receipts.len()
                != usize::try_from(outcome.declared_successor_receipts)
                    .map_err(|_| BrokerError::Rejected)?
            {
                return Err(BrokerError::Rejected);
            }
            let readback = sorafs_node::PorFinalizedReplayArchiveReadbackV1 {
                record: decode_por_replay_archive_record(&outcome.canonical_record)?,
                receipt: outcome.receipt.ok_or(BrokerError::Rejected)?,
                successor_receipts,
            };
            if readback.record.challenge_id() != request.challenge_id {
                return Err(BrokerError::Rejected);
            }
            readback
                .validate_at_checkpoint(exact, request.expected_checkpoint_head, bounds)
                .map_err(|_| BrokerError::Rejected)?;
            Ok(sorafs_node::PorFinalizedReplayArchiveLookupV1::Found(
                Box::new(readback),
            ))
        }
        2 => {
            if !outcome.canonical_record.is_empty()
                || outcome.receipt.is_some()
                || outcome.declared_successor_receipts != 0
                || !outcome.canonical_successor_receipts.is_empty()
            {
                return Err(BrokerError::Rejected);
            }
            let absence = outcome.absence_proof.ok_or(BrokerError::Rejected)?;
            absence
                .validate_at_checkpoint(
                    exact,
                    request.challenge_id,
                    request.expected_checkpoint_head,
                )
                .map_err(|_| BrokerError::Rejected)?;
            Ok(sorafs_node::PorFinalizedReplayArchiveLookupV1::Absent(
                Box::new(absence),
            ))
        }
        _ => Err(BrokerError::Rejected),
    }
}
fn reputation_hash_canonical<T: NoritoSerialize>(
    domain: &'static [u8],
    value: &T,
) -> Result<[u8; 32], BrokerError> {
    let canonical = encode_canonical(value, MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1)?;
    let length = u64::try_from(canonical.len()).map_err(|_| BrokerError::Rejected)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&length.to_le_bytes());
    hasher.update(&canonical);
    Ok(*hasher.finalize().as_bytes())
}
fn reputation_publication_idempotency_key(
    domain: &'static [u8],
    sequence: u64,
    material_digest: [u8; 32],
    signed_result_digest: Option<[u8; 32]>,
) -> Result<[u8; 32], BrokerError> {
    if sequence == 0 || material_digest == [0; 32] {
        return Err(BrokerError::Rejected);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&material_digest);
    if let Some(digest) = signed_result_digest {
        if digest == [0; 32] {
            return Err(BrokerError::Rejected);
        }
        hasher.update(&digest);
    }
    Ok(*hasher.finalize().as_bytes())
}
fn reputation_signed_result_digest(
    canonical_signed_result: &[u8],
) -> Result<[u8; 32], BrokerError> {
    if canonical_signed_result.is_empty()
        || canonical_signed_result.len()
            > sorafs_manifest::reputation::signed::MAX_SIGNED_REPUTATION_SNAPSHOT_ENCODED_BYTES
    {
        return Err(BrokerError::Rejected);
    }
    let length = u64::try_from(canonical_signed_result.len()).map_err(|_| BrokerError::Rejected)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sorafs-reputation-signed-material-result-v1");
    hasher.update(&length.to_le_bytes());
    hasher.update(canonical_signed_result);
    Ok(*hasher.finalize().as_bytes())
}
fn validate_reputation_unsigned_material(
    material: &sorafs_node::reputation::ReputationUnsignedSigningMaterialV1,
) -> Result<(), BrokerError> {
    if material.version != sorafs_node::reputation::REPUTATION_UNSIGNED_MATERIAL_VERSION_V1
        || material.network_id.as_bytes()[31] & 1 != 1
        || material.ingest_policy_digest == [0; 32]
        || material.snapshot_trust_policy_digest == [0; 32]
        || material.window_start_height == 0
        || material.window_end_height < material.window_start_height
        || material.target_finalized.height != material.window_end_height
        || material.target_finalized.block_hash == [0; 32]
        || material.target_finalized_at_unix_ms == 0
        || material.source_finality.is_empty()
        || material.snapshot_signing_digest == [0; 32]
    {
        return Err(BrokerError::Rejected);
    }
    if material.source_finality.windows(2).any(|pair| {
        pair[0].source >= pair[1].source
            || pair[0].observed_through != material.target_finalized
            || pair[1].observed_through != material.target_finalized
    }) || material
        .source_finality
        .first()
        .is_some_and(|source| source.observed_through != material.target_finalized)
    {
        return Err(BrokerError::Rejected);
    }
    material
        .scoring_evidence
        .validate()
        .map_err(|_| BrokerError::Rejected)?;
    material
        .scoring_evidence
        .verify_snapshot(&material.snapshot)
        .map_err(|_| BrokerError::Rejected)?;
    let evidence_digest = material
        .scoring_evidence
        .canonical_digest()
        .map_err(|_| BrokerError::Rejected)?;
    if evidence_digest != material.scoring_evidence_digest {
        return Err(BrokerError::Rejected);
    }
    let signing_digest = sorafs_manifest::reputation::signed::snapshot_signing_digest(
        &material.snapshot,
        material.snapshot_trust_policy_digest,
        material.scoring_evidence_digest,
    )
    .map_err(|_| BrokerError::Rejected)?;
    if signing_digest != material.snapshot_signing_digest {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
fn ensure_reputation_session_network(
    network_id: &iroha_data_model::NetworkId,
    session_network_id: &iroha_data_model::NetworkId,
) -> Result<(), BrokerError> {
    if session_network_id != network_id {
        return Err(BrokerError::BindingMismatch);
    }
    Ok(())
}
fn reputation_journal_request_to_wire(
    request: &sorafs_node::reputation::runtime::ReputationJournalTransactionRequestV1,
) -> Result<ReputationJournalTransactionRequestWireV1, BrokerError> {
    request.validate().map_err(|_| BrokerError::Rejected)?;
    let canonical_instruction = encode_canonical(
        &request.instruction,
        MAX_REPUTATION_JOURNAL_INSTRUCTION_BYTES_V1,
    )?;
    Ok(ReputationJournalTransactionRequestWireV1 {
        sequence: request.sequence,
        network_id: request.network_id,
        authority: request.authority.clone(),
        event_id: request.event_id,
        source_id: request.source_id,
        attempt: request.attempt,
        idempotency_key: request.idempotency_key,
        canonical_instruction,
    })
}
fn reputation_journal_request_from_wire(
    wire: ReputationJournalTransactionRequestWireV1,
) -> Result<sorafs_node::reputation::runtime::ReputationJournalTransactionRequestV1, BrokerError> {
    let instruction =
        decode_canonical::<iroha_data_model::isi::sorafs::AppendSorafsPorReputationJournalEntry>(
            &wire.canonical_instruction,
            MAX_REPUTATION_JOURNAL_INSTRUCTION_BYTES_V1,
        )?;
    let request = sorafs_node::reputation::runtime::ReputationJournalTransactionRequestV1 {
        sequence: wire.sequence,
        network_id: wire.network_id,
        authority: wire.authority,
        event_id: wire.event_id,
        source_id: wire.source_id,
        attempt: wire.attempt,
        idempotency_key: wire.idempotency_key,
        instruction,
    };
    request.validate().map_err(|_| BrokerError::Rejected)?;
    Ok(request)
}
fn reputation_journal_submit_result_to_wire(
    outcome: sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitOutcomeV1,
) -> Result<ReputationJournalTransactionSubmitResultWireV1, BrokerError> {
    use sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitOutcomeV1;
    let (outcome, receipt) = match outcome {
        ReputationJournalTransactionSubmitOutcomeV1::Queued { receipt } => (1, receipt),
        ReputationJournalTransactionSubmitOutcomeV1::NotQueued { receipt } => (2, receipt),
        ReputationJournalTransactionSubmitOutcomeV1::Ambiguous { receipt } => (3, receipt),
    };
    if receipt == [0; 32] {
        return Err(BrokerError::Rejected);
    }
    Ok(ReputationJournalTransactionSubmitResultWireV1 { outcome, receipt })
}
fn reputation_journal_submit_result_from_wire(
    wire: ReputationJournalTransactionSubmitResultWireV1,
) -> Result<
    sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitOutcomeV1,
    BrokerError,
> {
    use sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitOutcomeV1;
    if wire.receipt == [0; 32] {
        return Err(BrokerError::Rejected);
    }
    match wire.outcome {
        1 => Ok(ReputationJournalTransactionSubmitOutcomeV1::Queued {
            receipt: wire.receipt,
        }),
        2 => Ok(ReputationJournalTransactionSubmitOutcomeV1::NotQueued {
            receipt: wire.receipt,
        }),
        3 => Ok(ReputationJournalTransactionSubmitOutcomeV1::Ambiguous {
            receipt: wire.receipt,
        }),
        _ => Err(BrokerError::Rejected),
    }
}
fn reputation_threshold_request_to_wire(
    request: &sorafs_node::reputation::runtime::ReputationThresholdSigningRequestV1,
) -> Result<ReputationThresholdSigningRequestWireV1, BrokerError> {
    validate_reputation_unsigned_material(&request.material)?;
    if reputation_hash_canonical(
        b"sorafs-reputation-unsigned-material-delivery-v1",
        &request.material,
    )? != request.material_digest
        || reputation_publication_idempotency_key(
            b"sorafs-reputation-threshold-signing-operation-v1",
            request.sequence,
            request.material_digest,
            None,
        )? != request.idempotency_key
    {
        return Err(BrokerError::Rejected);
    }
    Ok(ReputationThresholdSigningRequestWireV1 {
        sequence: request.sequence,
        material_digest: request.material_digest,
        idempotency_key: request.idempotency_key,
        material: request.material.clone(),
    })
}
fn reputation_threshold_request_from_wire(
    wire: ReputationThresholdSigningRequestWireV1,
) -> Result<sorafs_node::reputation::runtime::ReputationThresholdSigningRequestV1, BrokerError> {
    let request = sorafs_node::reputation::runtime::ReputationThresholdSigningRequestV1 {
        sequence: wire.sequence,
        material_digest: wire.material_digest,
        idempotency_key: wire.idempotency_key,
        material: wire.material,
    };
    reputation_threshold_request_to_wire(&request)?;
    Ok(request)
}
fn validate_reputation_signature(
    request: &sorafs_node::reputation::runtime::ReputationThresholdSigningRequestV1,
    signed: &sorafs_manifest::reputation::signed::SignedReputationSnapshotV1,
) -> Result<Vec<u8>, BrokerError> {
    let canonical = signed
        .canonical_bytes()
        .map_err(|_| BrokerError::Rejected)?;
    if signed.policy_digest != request.material.snapshot_trust_policy_digest
        || signed.snapshot != request.material.snapshot
        || signed.scoring_evidence != request.material.scoring_evidence
        || signed.scoring_evidence_digest != request.material.scoring_evidence_digest
        || signed.signing_digest().map_err(|_| BrokerError::Rejected)?
            != request.material.snapshot_signing_digest
    {
        return Err(BrokerError::Rejected);
    }
    Ok(canonical)
}
fn reputation_governance_request_to_wire(
    request: &sorafs_node::reputation::runtime::ReputationGovernanceDagPublicationRequestV1,
) -> Result<ReputationGovernanceDagPublicationRequestWireV1, BrokerError> {
    reserve_external_canonical_decode(
        request.canonical_signed_result.len(),
        MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
    )?;
    let decoded = sorafs_manifest::reputation::signed::decode_signed_reputation_snapshot(
        &request.canonical_signed_result,
    )
    .map_err(|_| BrokerError::Rejected)?;
    if decoded != request.signed_result
        || reputation_signed_result_digest(&request.canonical_signed_result)?
            != request.signed_result_digest
        || reputation_publication_idempotency_key(
            b"sorafs-reputation-governance-publication-operation-v1",
            request.sequence,
            request.material_digest,
            Some(request.signed_result_digest),
        )? != request.idempotency_key
    {
        return Err(BrokerError::Rejected);
    }
    Ok(ReputationGovernanceDagPublicationRequestWireV1 {
        sequence: request.sequence,
        material_digest: request.material_digest,
        signed_result_digest: request.signed_result_digest,
        idempotency_key: request.idempotency_key,
        canonical_signed_result: request.canonical_signed_result.clone(),
    })
}
fn reputation_governance_request_from_wire(
    wire: ReputationGovernanceDagPublicationRequestWireV1,
) -> Result<
    sorafs_node::reputation::runtime::ReputationGovernanceDagPublicationRequestV1,
    BrokerError,
> {
    reserve_external_canonical_decode(
        wire.canonical_signed_result.len(),
        MAX_REPUTATION_RUNTIME_FRAME_BYTES_V1,
    )?;
    let signed_result = sorafs_manifest::reputation::signed::decode_signed_reputation_snapshot(
        &wire.canonical_signed_result,
    )
    .map_err(|_| BrokerError::Rejected)?;
    let request = sorafs_node::reputation::runtime::ReputationGovernanceDagPublicationRequestV1 {
        sequence: wire.sequence,
        material_digest: wire.material_digest,
        signed_result_digest: wire.signed_result_digest,
        idempotency_key: wire.idempotency_key,
        signed_result,
        canonical_signed_result: wire.canonical_signed_result,
    };
    reputation_governance_request_to_wire(&request)?;
    Ok(request)
}
fn validate_reputation_governance_readback(
    readback: &sorafs_node::reputation::runtime::ReputationGovernanceDagReadbackV1,
    expected_signed_result: &sorafs_manifest::reputation::signed::SignedReputationSnapshotV1,
) -> Result<(), BrokerError> {
    if readback.version
        != sorafs_node::reputation::runtime::REPUTATION_GOVERNANCE_DAG_READBACK_VERSION_V1
        || readback.inclusion_path.is_empty()
        || readback.inclusion_path.len()
            > sorafs_node::reputation::runtime::REPUTATION_GOVERNANCE_DAG_MAX_INCLUSION_BLOCKS_V1
    {
        return Err(BrokerError::Rejected);
    }
    readback
        .head
        .validate()
        .map_err(|_| BrokerError::Rejected)?;
    sorafs_manifest::governance::validate_governance_dag_head_against_chain_v1(
        &readback.head,
        &readback.inclusion_path,
    )
    .map_err(|_| BrokerError::Rejected)?;
    let expected_payload =
        sorafs_manifest::governance::GovernanceLogPayloadV1::SignedReputationSnapshot(
            expected_signed_result.clone(),
        );
    if readback
        .inclusion_path
        .iter()
        .filter(|block| block.node.payload == expected_payload)
        .count()
        != 1
    {
        return Err(BrokerError::Rejected);
    }
    Ok(())
}
