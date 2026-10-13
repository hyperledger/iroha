//! Authoritative read-only finality checks for private Musubi storage coordination.
//!
//! This module deliberately owns no listener, queue submission, `SoraFS` mutation, or service
//! activation. It only derives one current archive record from daemon-owned finalized state and
//! exact Kura history; the stock publication service remains unavailable without deployment
//! injection.
use iroha_core::{
    smartcontracts::isi::musubi::validate_musubi_registry_snapshot_history_v1,
    state::{State, StateQueryView, StateReadOnly, WorldReadOnly, WorldStateSnapshot as _},
};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::SignedBlock,
    isi::musubi::RegisterMusubiArchiveV1,
    musubi::{
        MusubiArchiveLocationV1, MusubiArchiveRecordV1, MusubiArchiveRegistrationProjectionV1,
        MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleAttestationRecordV1,
        MusubiRegistrySnapshotV1, musubi_provider_bundle_attestation_set_digest_v1,
    },
    sorafs::capacity::ProviderId,
    transaction::{Executable, TransactionEntrypoint},
};
use mv::storage::StorageReadOnly as _;
use std::{num::NonZeroUsize, sync::Arc};
/// Exact immutable evidence needed to recover a finalized archive registration.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    norito::derive::Encode,
    norito::derive::Decode,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "irohad::musubi_publication_service::MusubiPublicationFinalizedArchiveRegistrationQueryV1"
)]
pub struct MusubiPublicationFinalizedArchiveRegistrationQueryV1 {
    /// Closed schema version; must equal one.
    pub version: u8,
    /// Exact deployment identity derived from the committed genesis header.
    pub network_id: NetworkId,
    /// Canonical identity of the signed registration transaction.
    pub transaction_hash: [u8; 32],
    /// Finalized registry snapshot at or after archive registration.
    pub snapshot: MusubiRegistrySnapshotV1,
    /// Immutable registration projection supplied by the authenticated publisher operation.
    pub registration: MusubiArchiveRegistrationProjectionV1,
    /// Exact registry policy revision encoded by the native registration instruction.
    pub expected_policy_revision: u64,
}
impl MusubiPublicationFinalizedArchiveRegistrationQueryV1 {
    fn validate(&self) -> Result<(), MusubiPublicationFinalizedArchiveRegistrationReadErrorV1> {
        self.snapshot.validate().map_err(|_| invalid())?;
        self.registration.validate().map_err(|_| invalid())?;
        if self.version != 1
            || self.network_id.as_bytes()[31] & 1 != 1
            || self.transaction_hash.iter().all(|byte| *byte == 0)
            || self.expected_policy_revision == 0
            || self.registration.staging_receipt.payload.binding.network_id != self.network_id
            || self.registration.registered_at_height > self.snapshot.finalized_height
        {
            return Err(invalid());
        }
        Ok(())
    }
}
/// Closed, redacted failure from the daemon-owned finalized reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MusubiPublicationFinalizedArchiveRegistrationReadErrorV1 {
    /// Original local allocation admission has not completed; retry the same read.
    Deferred(iroha_core::execution_attempt::ExecutionDeferred),
    /// The supplied evidence is ahead of this node's coherent finalized view.
    LocallyAhead,
    /// Evidence is malformed, substituted, absent from canonical history, or otherwise invalid.
    Invalid,
}
impl MusubiPublicationFinalizedArchiveRegistrationReadErrorV1 {
    /// Whether retrying after the local finalized view advances may succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::LocallyAhead | Self::Deferred(_))
    }
}
impl core::fmt::Display for MusubiPublicationFinalizedArchiveRegistrationReadErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Deferred(_) => "finalized history read is waiting for local capacity",
            Self::LocallyAhead => {
                "finalized Musubi archive-registration evidence is ahead of local state"
            }
            Self::Invalid => "finalized Musubi archive-registration evidence is invalid",
        })
    }
}
impl std::error::Error for MusubiPublicationFinalizedArchiveRegistrationReadErrorV1 {}
impl From<iroha_core::execution_attempt::ExecutionDeferred>
    for MusubiPublicationFinalizedArchiveRegistrationReadErrorV1
{
    fn from(error: iroha_core::execution_attempt::ExecutionDeferred) -> Self {
        Self::Deferred(error)
    }
}
impl From<iroha_core::execution_attempt::ExecutionAttemptError<iroha_core::kura::Error>>
    for MusubiPublicationFinalizedArchiveRegistrationReadErrorV1
{
    fn from(
        error: iroha_core::execution_attempt::ExecutionAttemptError<iroha_core::kura::Error>,
    ) -> Self {
        match error {
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(error) => {
                Self::Deferred(error)
            }
            iroha_core::execution_attempt::ExecutionAttemptError::Rejected(_) => Self::Invalid,
        }
    }
}
const fn invalid() -> MusubiPublicationFinalizedArchiveRegistrationReadErrorV1 {
    MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Invalid
}
/// Read-only daemon adapter for exact finalized archive registrations.
#[derive(Clone)]
pub struct MusubiPublicationFinalizedArchiveRegistrationReaderV1 {
    network_id: NetworkId,
    state: Arc<State>,
}
impl core::fmt::Debug for MusubiPublicationFinalizedArchiveRegistrationReaderV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MusubiPublicationFinalizedArchiveRegistrationReaderV1")
            .field("network_id", &self.network_id)
            .finish_non_exhaustive()
    }
}
impl MusubiPublicationFinalizedArchiveRegistrationReaderV1 {
    /// Bind a reader to one exact daemon network and finalized-state handle.
    ///
    /// # Errors
    ///
    /// Returns a permanent invalid-evidence error when the explicit network differs from the
    /// state handle's genesis-derived network identity.
    pub fn new(
        network_id: NetworkId,
        state: Arc<State>,
    ) -> Result<Self, MusubiPublicationFinalizedArchiveRegistrationReadErrorV1> {
        if state.network_id_ref() != &network_id {
            return Err(invalid());
        }
        Ok(Self { network_id, state })
    }
    pub(super) fn from_validated_context(network_id: NetworkId, state: Arc<State>) -> Self {
        debug_assert_eq!(state.network_id_ref(), &network_id);
        Self { network_id, state }
    }
    /// Read and independently authenticate one current archive record from finalized history.
    ///
    /// A single Core query view binds the world and canonical block-hash journal. The reader then
    /// validates Core's resolver-revision history, requires native certified history and paired
    /// application attestations for the exact result-bearing registration-height block wire,
    /// authenticates the unique successful native registration transaction, and compares its
    /// immutable projection with the current archive record. No state or storage effect occurs.
    ///
    /// # Errors
    ///
    /// Returns [`MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::LocallyAhead`] only
    /// when the named snapshot height or resolver revision is beyond the captured local view. All
    /// malformed, missing, rejected, substituted, or inconsistent evidence is permanently invalid.
    pub fn read_current_archive(
        &self,
        query: &MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    ) -> Result<MusubiArchiveRecordV1, MusubiPublicationFinalizedArchiveRegistrationReadErrorV1>
    {
        self.read_current_archive_in_view(query, &self.state.query_view())
    }
    pub(super) fn read_current_archive_in_view(
        &self,
        query: &MusubiPublicationFinalizedArchiveRegistrationQueryV1,
        view: &StateQueryView<'_>,
    ) -> Result<MusubiArchiveRecordV1, MusubiPublicationFinalizedArchiveRegistrationReadErrorV1>
    {
        query.validate()?;
        if query.network_id != self.network_id {
            return Err(invalid());
        }
        let local_height = u64::try_from(view.block_hashes().len()).map_err(|_| invalid())?;
        let local_revision = view.world().musubi_resolver_index_revision();
        if query.snapshot.finalized_height > local_height
            || query.snapshot.index_revision > local_revision
        {
            return Err(MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::LocallyAhead);
        }
        validate_musubi_registry_snapshot_history_v1(&query.snapshot, view)
            .map_err(|_| invalid())?;
        let registered_height = usize::try_from(query.registration.registered_at_height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(invalid())?;
        let canonical_hash = view
            .block_hashes()
            .get(registered_height.get() - 1)
            .copied()
            .ok_or(invalid())?;
        let block = view
            .kura()
            .get_block(registered_height, &view.execution_budget())?
            .ok_or(invalid())?;
        if !validate_finalized_block_wire(
            view,
            &query.network_id,
            query.registration.registered_at_height,
            canonical_hash,
            &block,
        )? || !validate_registration_transaction(query, &block)
        {
            return Err(invalid());
        }
        let archive = view
            .world()
            .musubi_archives()
            .get(&query.registration.archive_id)
            .ok_or_else(invalid)?;
        archive.validate().map_err(|_| invalid())?;
        if archive.registration_projection() != query.registration {
            return Err(invalid());
        }
        Ok(archive.clone())
    }
    /// Authenticate the selected readback location against one coherent current State cut.
    ///
    /// The registration block and current tip both require native certified history with full
    /// application-attestation verification. The
    /// location, provider-owner, and immutable signed provider-attestation rows are read from the
    /// same State query view as the archive. A later owner replacement cannot reuse the former
    /// completion attestation.
    /// This relies on State's committed-world ownership; a complete State-root witness remains
    /// a separate release gate.
    pub(super) fn validate_current_readback_target(
        &self,
        query: &MusubiPublicationFinalizedArchiveRegistrationQueryV1,
        location: &MusubiArchiveLocationV1,
        provider: ProviderId,
    ) -> Result<(), MusubiPublicationFinalizedArchiveRegistrationReadErrorV1> {
        let view = self.state.query_view();
        let archive = self.read_current_archive_in_view(query, &view)?;
        let tip_height = u64::try_from(view.block_hashes().len()).map_err(|_| invalid())?;
        if location.finalized_height > tip_height {
            return Err(MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::LocallyAhead);
        }
        let tip_number = NonZeroUsize::new(view.block_hashes().len()).ok_or_else(invalid)?;
        let tip_hash = view
            .block_hashes()
            .get(tip_number.get() - 1)
            .copied()
            .ok_or_else(invalid)?;
        let tip_block = view
            .kura()
            .get_block(tip_number, &view.execution_budget())?
            .ok_or_else(invalid)?;
        let attestation_key = MusubiProviderBundleAttestationKeyV1 {
            archive_id: archive.archive_id,
            replication_order: location.replication_order,
            provider_id: provider,
        };
        if !validate_finalized_block_wire(
            &view,
            &query.network_id,
            tip_height,
            tip_hash,
            &tip_block,
        )? || !complete_location_attestations_match(&archive, location, view.world())
            || !current_readback_target_matches(
                &archive,
                location,
                view.world().musubi_archive_locations().get(&location.key()),
                view.world().provider_owners().get(&provider),
                view.world()
                    .musubi_provider_bundle_attestations()
                    .get(&attestation_key),
            )
        {
            return Err(invalid());
        }
        Ok(())
    }
}
fn complete_location_attestations_match(
    archive: &MusubiArchiveRecordV1,
    location: &MusubiArchiveLocationV1,
    world: &impl WorldReadOnly,
) -> bool {
    let references = location
        .providers
        .iter()
        .map(|provider| {
            let key = MusubiProviderBundleAttestationKeyV1 {
                archive_id: archive.archive_id,
                replication_order: location.replication_order,
                provider_id: *provider,
            };
            let record = world.musubi_provider_bundle_attestations().get(&key)?;
            let binding = &record.attestation.payload.binding;
            (record.validate().is_ok()
                && record.attestation.verify(binding).is_ok()
                && record.registered_at_height >= archive.registered_at_height
                && binding.network_id == archive.staging_receipt.payload.binding.network_id
                && binding.bundle_digest == archive.commitment.bundle_digest
                && binding.descriptor_digest == archive.commitment.descriptor_digest
                && binding.source_tree_digest == archive.commitment.source_tree_digest
                && binding.semantic_release_manifest_digest
                    == archive
                        .staging_receipt
                        .payload
                        .binding
                        .semantic_release_manifest_digest)
                .then(|| record.attestation.reference())
        })
        .collect::<Option<Vec<_>>>();
    references.is_some_and(|references| {
        musubi_provider_bundle_attestation_set_digest_v1(
            archive.archive_id,
            location.replication_order,
            &references,
        )
        .is_ok_and(|digest| digest == location.provider_attestation_set_digest)
    })
}
fn current_readback_target_matches(
    archive: &MusubiArchiveRecordV1,
    expected: &MusubiArchiveLocationV1,
    current: Option<&MusubiArchiveLocationV1>,
    owner: Option<&AccountId>,
    attestation: Option<&MusubiProviderBundleAttestationRecordV1>,
) -> bool {
    let (Some(owner), Some(attestation)) = (owner, attestation) else {
        return false;
    };
    let binding = &attestation.attestation.payload.binding;
    archive
        .location_ids
        .binary_search(&expected.location_id)
        .is_ok()
        && current == Some(expected)
        && attestation.validate().is_ok()
        && attestation.attestation.verify(binding).is_ok()
        && attestation.key.archive_id == archive.archive_id
        && attestation.key.replication_order == expected.replication_order
        && expected
            .providers
            .binary_search(&attestation.key.provider_id)
            .is_ok()
        && attestation.registered_at_height >= archive.registered_at_height
        && binding.network_id == archive.staging_receipt.payload.binding.network_id
        && binding.completed_by == binding.completion_authority.completion_signer
        && binding.completion_authority.provider_owner == *owner
        && binding.archive_id == archive.archive_id
        && binding.bundle_digest == archive.commitment.bundle_digest
        && binding.descriptor_digest == archive.commitment.descriptor_digest
        && binding.source_tree_digest == archive.commitment.source_tree_digest
        && binding.semantic_release_manifest_digest
            == archive
                .staging_receipt
                .payload
                .binding
                .semantic_release_manifest_digest
}
pub(super) fn validate_finalized_block_wire(
    view: &impl StateReadOnly,
    network_id: &NetworkId,
    registered_height: u64,
    canonical_hash: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    block: &SignedBlock,
) -> Result<bool, iroha_core::execution_attempt::ExecutionDeferred> {
    if registered_height < 2
        || view.network_id() != network_id
        || block.header().height().get() != registered_height
        || block.hash() != canonical_hash
    {
        return Ok(false);
    }
    let Some(index) = usize::try_from(registered_height)
        .ok()
        .and_then(|height| height.checked_sub(1))
    else {
        return Ok(false);
    };
    if view.block_hashes().get(index) != Some(&canonical_hash) {
        return Ok(false);
    }
    // This reader verifies native exact-quorum BLS and the paired application
    // attestation against the same immutable State cut. A structural decode or
    // self-declared committee cannot issue this historical execution capability.
    let proof = match iroha_core::sumeragi::finality::build_proof(view, registered_height) {
        Ok(proof) => proof,
        Err(iroha_core::sumeragi::finality::ProofError::Deferred(error)) => return Err(error),
        Err(_) => return Ok(false),
    };
    Ok(proof.block_header == block.header()
        && block
            .encode_wire()
            .is_ok_and(|wire| proof.block_wire == wire))
}
fn validate_registration_transaction(
    query: &MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    block: &SignedBlock,
) -> bool {
    if block.validate_output_merkle_cache().is_err() {
        return false;
    }
    let mut found = false;
    for (input_index, entrypoint) in block.network_entrypoints().enumerate() {
        let transaction = match entrypoint {
            TransactionEntrypoint::External(transaction) => transaction,
            TransactionEntrypoint::SealedReveal(reveal) => {
                if *reveal.signed_transaction().hash().as_ref() == query.transaction_hash {
                    return false;
                }
                continue;
            }
            TransactionEntrypoint::SealedCommitment(_) => {
                continue;
            }
        };
        if *transaction.hash().as_ref() != query.transaction_hash {
            continue;
        }
        let Some((_, output)) = u32::try_from(input_index)
            .ok()
            .and_then(|index| block.network_output_at(index))
        else {
            return false;
        };
        if found
            || output.result.is_err()
            || transaction.verify_signature().is_err()
            || transaction.network_id() != Some(&query.network_id)
            || transaction.authority() != &query.registration.registered_by
        {
            return false;
        }
        found = true;
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return false;
        };
        let [instruction] = instructions.as_ref() else {
            return false;
        };
        let Some(register) = instruction
            .as_any()
            .downcast_ref::<RegisterMusubiArchiveV1>()
        else {
            return false;
        };
        if register.commitment != query.registration.commitment
            || register.staging_receipt != query.registration.staging_receipt
            || register.expected_policy_revision != query.expected_policy_revision
        {
            return false;
        }
    }
    found
}
#[cfg(test)]
pub mod tests {
    use super::*;
    use iroha_core::{
        state::{State, World},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf};
    use iroha_data_model::{
        Registrable as _, ValidationFail,
        account::{Account, AccountId},
        asset::AssetDefinition,
        block::{
            BlockHeader, SignedBlock,
            builder::BlockBuilder,
            execution_output::{
                ExecutionOutputV1, InvocationCompletionV1, NetworkExecutionOutputV1,
                PipelineEventPositionV1, PipelineExecutionOutputV1, PipelineInvocationV1,
                TimeExecutionOutputV1, TimeInvocationV1, TriggerUseV1,
            },
        },
        domain::Domain,
        isi::{InstructionBox, musubi::RegisterMusubiArchiveV1},
        musubi::{
            MUSUBI_REGISTRY_VERSION_V1, MusubiArchiveCommitmentV1, MusubiArchiveLocationIdV1,
            MusubiArchiveLocationStateV1, MusubiContentDigestV1,
            MusubiProviderBundleAttestationSetDigestV1, MusubiProviderBundleVerificationApprovalV1,
            MusubiProviderBundleVerificationAttestationV1,
            MusubiProviderBundleVerificationBindingV1, MusubiProviderBundleVerificationPayloadV1,
            MusubiSeedIngressReceiptApprovalV1, MusubiSeedIngressReceiptBindingV1,
            MusubiSeedIngressReceiptPayloadV1, MusubiSeedIngressReceiptV1,
            MusubiSemanticReleaseDigestV1, MusubiVerificationLockDigestV1,
        },
        sorafs::{
            capacity::ProviderId,
            pin_registry::{
                ChunkerProfileHandle, ManifestDigest, ManifestRootCid,
                ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
                ProviderIngestFinalizedAnchorV1, ReplicationOrderId,
            },
        },
        transaction::{
            DataTriggerSequence, FeePaymentIntent, SignedTransaction, TransactionBuilder,
            TransactionResultInner, error::TransactionRejectionReason,
        },
    };
    use iroha_model_base::chain::ChainId;
    use iroha_primitives::time::TimeSource;
    use std::{num::NonZeroU64, sync::Arc, time::Duration};
    struct RegistrationMaterial {
        network_id: NetworkId,
        publisher_key: KeyPair,
        archive: MusubiArchiveRecordV1,
    }
    pub struct ReaderFixture {
        pub(crate) reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
        pub(crate) state: Arc<State>,
        pub(crate) query: MusubiPublicationFinalizedArchiveRegistrationQueryV1,
        pub(crate) archive: MusubiArchiveRecordV1,
        chain: CertifiedTestChain,
    }
    fn keypair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture seed derives an Ed25519 keypair")
    }
    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([seed | 1; 32]),
        ))
    }
    fn archive_commitment() -> MusubiArchiveCommitmentV1 {
        MusubiArchiveCommitmentV1 {
            root_cid: ManifestRootCid::from_blake3_digest([1; 32]).expect("root CID"),
            chunker: ChunkerProfileHandle {
                profile_id: 1,
                namespace: "sorafs".to_owned(),
                name: "sf1".to_owned(),
                semver: "1.0.0".to_owned(),
                multihash_code: 0x1f,
            },
            chunk_plan_digest: MusubiContentDigestV1::new([2; 32]),
            por_root: MusubiContentDigestV1::new([3; 32]),
            content_length: 1_024,
            car_digest: MusubiContentDigestV1::new([4; 32]),
            car_size: 2_048,
            bundle_digest: MusubiContentDigestV1::new([5; 32]),
            source_tree_digest: MusubiContentDigestV1::new([6; 32]),
            descriptor_digest: MusubiContentDigestV1::new([7; 32]),
            file_count: 2,
            chunk_count: 4,
        }
    }
    fn registration_material() -> RegistrationMaterial {
        registration_material_at(network_id(0x15), 1)
    }
    fn registration_material_at(
        network_id: NetworkId,
        registered_at_height: u64,
    ) -> RegistrationMaterial {
        registration_material_at_with_commitment(
            network_id,
            registered_at_height,
            archive_commitment(),
            MusubiSemanticReleaseDigestV1::new([0x34; 32]),
        )
    }
    fn registration_material_at_with_commitment(
        network_id: NetworkId,
        registered_at_height: u64,
        commitment: MusubiArchiveCommitmentV1,
        semantic_digest: MusubiSemanticReleaseDigestV1,
    ) -> RegistrationMaterial {
        let publisher_key = keypair(0x31);
        let publisher = AccountId::new(publisher_key.public_key().clone());
        let broker_key = keypair(0x32);
        let broker = AccountId::new(broker_key.public_key().clone());
        let binding = MusubiSeedIngressReceiptBindingV1 {
            network_id,
            publisher: publisher.clone(),
            ingress_broker: broker,
            seed_provider: ProviderId::new([0x33; 32]),
            semantic_release_manifest_digest: semantic_digest,
            archive_id: commitment.archive_id(),
            car_body_digest: commitment.car_digest,
            car_body_length: commitment.car_size,
            nonce: [0x35; 32],
        };
        let payload = MusubiSeedIngressReceiptPayloadV1 {
            version: MUSUBI_REGISTRY_VERSION_V1,
            binding,
            issued_at_ms: 500,
            expires_at_ms: 2_000,
        };
        let receipt = MusubiSeedIngressReceiptV1 {
            approvals: vec![MusubiSeedIngressReceiptApprovalV1 {
                public_key: broker_key.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    broker_key.private_key(),
                    payload.signing_hash(),
                )
                .expect("sign staging receipt"),
            }],
            payload,
        };
        let archive = MusubiArchiveRecordV1 {
            archive_id: commitment.archive_id(),
            commitment,
            staging_receipt: receipt,
            registered_by: publisher,
            registered_at_height,
            location_revision: 2,
            location_ids: Vec::new(),
        };
        archive.validate().expect("valid archive fixture");
        RegistrationMaterial {
            network_id,
            publisher_key,
            archive,
        }
    }
    fn registration_instruction(archive: &MusubiArchiveRecordV1) -> RegisterMusubiArchiveV1 {
        RegisterMusubiArchiveV1::new(
            archive.commitment.clone(),
            archive.staging_receipt.clone(),
            1,
        )
    }
    fn signed_transaction(
        network_id: NetworkId,
        key: &KeyPair,
        instructions: Vec<InstructionBox>,
    ) -> SignedTransaction {
        let (_time_handle, time_source) = TimeSource::new_mock(Duration::from_millis(1_000));
        TransactionBuilder::new_with_time_source(
            network_id,
            AccountId::new(key.public_key().clone()),
            &time_source,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(instructions)
        .sign(key.private_key())
    }
    fn successful_registration_transaction(material: &RegistrationMaterial) -> SignedTransaction {
        signed_transaction(
            material.network_id,
            &material.publisher_key,
            vec![registration_instruction(&material.archive).into()],
        )
    }
    fn signed_proposal(transactions: Vec<SignedTransaction>) -> SignedBlock {
        let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 1_001, 0);
        let mut builder = BlockBuilder::new(header);
        for transaction in transactions {
            builder.push_transaction(transaction);
        }
        let block = builder
            .try_build_with_signature(0, keypair(0x41).private_key())
            .unwrap();
        block
            .validate_proposal_commitments()
            .expect("structural proposal commits actual inputs");
        block
    }

    fn network_outputs(
        block: &SignedBlock,
        rejected_index: Option<usize>,
    ) -> Vec<ExecutionOutputV1> {
        block
            .network_entrypoints()
            .enumerate()
            .map(|(index, _)| {
                ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                    input_index: u32::try_from(index).expect("bounded fixture input index"),
                    result: (if rejected_index == Some(index) {
                        TransactionResultInner::Err(TransactionRejectionReason::Validation(
                            ValidationFail::NotPermitted(
                                "rejected registration fixture".to_owned(),
                            ),
                        ))
                    } else {
                        TransactionResultInner::Ok(DataTriggerSequence::default())
                    })
                    .into(),
                    completions: Vec::new(),
                })
            })
            .collect()
    }

    // This helper installs structural negative-test evidence, not execution authority.
    // Positive finalized-reader fixtures below still execute the real registration.
    fn install_fixture_outputs(
        block: &mut SignedBlock,
        outputs: Vec<ExecutionOutputV1>,
        committed_fragments: u64,
    ) -> Result<(), iroha_data_model::block::SetExecutionOutputsError> {
        let header = block.header();
        let signatures = block.signatures().cloned().collect::<Vec<_>>();
        let installed = block.set_execution_outputs(
            outputs,
            committed_fragments,
            if block.has_results() {
                block.fastpq_transcripts().clone()
            } else {
                std::collections::BTreeMap::default()
            },
            block.axt_envelopes().unwrap_or_default().to_vec(),
            block.axt_policy_snapshot().cloned().unwrap_or_default(),
            block
                .axt_transitioned_dataspaces()
                .cloned()
                .unwrap_or_default(),
            &iroha_data_model::parameter::ExecutionOutputPolicyV1::bootstrap().limits(),
        );
        assert_eq!(
            block.header(),
            header,
            "outputs cannot rewrite proposal commitments"
        );
        assert_eq!(block.signatures().cloned().collect::<Vec<_>>(), signatures);
        installed
    }

    fn signed_block_with_results(
        transactions: Vec<SignedTransaction>,
        rejected_index: Option<usize>,
    ) -> SignedBlock {
        let mut block = signed_proposal(transactions);
        let outputs = network_outputs(&block, rejected_index);
        // Every successful fixture input has exactly one structural execution fragment.
        let fragments =
            u64::try_from(outputs.iter().filter(|row| row.result().is_ok()).count()).unwrap();
        install_fixture_outputs(&mut block, outputs, fragments)
            .expect("fixture typed Network outputs match their immutable inputs");
        block
    }

    fn structural_registration_callbacks(
        archive: &MusubiArchiveRecordV1,
    ) -> Vec<ExecutionOutputV1> {
        use iroha_data_model::{
            events::{
                time::{TimeEvent, TimeInterval},
                trigger_completed::TriggerCompletedOutcome,
            },
            transaction::signed::ExecutionStep,
            trigger::DataTriggerStep,
        };
        let callback = |name: &str| {
            let trigger = TriggerUseV1 {
                trigger_id: name.parse().unwrap(),
                registered_at_height: 0,
                action_hash: Hash::new(name.as_bytes()),
            };
            let result = Ok(vec![DataTriggerStep {
                id: trigger.trigger_id.clone(),
                instructions: ExecutionStep(vec![registration_instruction(archive).into()].into()),
            }])
            .into();
            let completions = vec![InvocationCompletionV1 {
                callback_index: 0,
                trigger_id: trigger.trigger_id.clone(),
                outcome: TriggerCompletedOutcome::Success,
            }];
            (trigger, result, completions)
        };
        // Public descriptors only establish distinct structural owners here.
        // Exact executed-wire finality remains mandatory in the production reader.
        let (trigger, result, completions) = callback("registration-pipeline");
        let pipeline = ExecutionOutputV1::Pipeline(PipelineExecutionOutputV1 {
            invocation: PipelineInvocationV1 {
                event: PipelineEventPositionV1::BlockApproved,
                candidate_index: 0,
                trigger,
            },
            result,
            failure_root: None,
            completions,
        });
        let (trigger, result, completions) = callback("registration-time");
        let time = ExecutionOutputV1::Time(TimeExecutionOutputV1 {
            invocation: TimeInvocationV1 {
                schedule_index: 0,
                event: TimeEvent {
                    interval: TimeInterval {
                        since_ms: 0,
                        length_ms: 1,
                    },
                },
                trigger,
            },
            result,
            failure_root: None,
            completions,
        });
        vec![pipeline, time]
    }
    fn seeded_world() -> World {
        let publisher = AccountId::new(keypair(0x31).public_key().clone());
        let account = Account::new(publisher.clone()).build(&publisher);
        let genesis_account = AccountId::new(keypair(0x42).public_key().clone());
        let mut world = World::with(
            [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&genesis_account)],
            [
                account,
                Account::new(genesis_account.clone()).build(&genesis_account),
            ],
            std::iter::empty::<AssetDefinition>(),
        );
        world.provider_owners_mut_for_testing().insert(
            ProviderId::new([0x33; 32]),
            AccountId::new(keypair(0x32).public_key().clone()),
        );
        world
    }
    pub fn reader_fixture() -> ReaderFixture {
        reader_fixture_with_finality(true)
    }
    fn start_reader_chain() -> CertifiedTestChain {
        let mut config = TestChainConfig::new(seeded_world(), 100);
        config.chain_id = ChainId::from("musubi-finality-reader-test");
        config.genesis_key = keypair(0x42);
        CertifiedTestChain::start(config)
            .expect("actual native signed genesis and original execution")
    }
    fn reader_fixture_with_finality(store_finality: bool) -> ReaderFixture {
        reader_fixture_with_finality_using(store_finality, None)
    }
    fn reader_fixture_with_finality_using(
        store_finality: bool,
        seed: Option<&(MusubiArchiveCommitmentV1, MusubiSemanticReleaseDigestV1)>,
    ) -> ReaderFixture {
        let mut chain = start_reader_chain();
        let material = seed.map_or_else(
            || registration_material_at(chain.network_id(), 2),
            |(commitment, semantic)| {
                registration_material_at_with_commitment(
                    chain.network_id(),
                    2,
                    commitment.clone(),
                    *semantic,
                )
            },
        );
        let transaction = successful_registration_transaction(&material);
        let transaction_hash = *transaction.hash().as_ref();
        let state = Arc::clone(chain.state());
        let canonical_block = if store_finality {
            assert_eq!(
                chain.commit(vec![transaction]),
                [true],
                "native registration executes"
            );
            let canonical = chain
                .kura()
                .get_block(
                    NonZeroUsize::new(2).unwrap(),
                    &state.query_view().execution_budget(),
                )
                .unwrap()
                .unwrap();
            let registered = state
                .query_view()
                .world()
                .musubi_archives()
                .get(&material.archive.archive_id)
                .cloned()
                .expect("actual instruction creates archive");
            assert_eq!(
                registered.registration_projection(),
                material.archive.registration_projection()
            );
            assert_eq!(registered.location_revision, 1);
            // Independent mutable-record fixture prestate; this does not change the
            // original transaction, execution outputs, or native historical proof.
            replace_current_archive(&state, *canonical.hash().as_ref(), &material.archive);
            canonical
        } else {
            // Execute the same exact source on a separate genuine native chain, then
            // strip its certificate only for a deliberately invalid local-storage claim.
            let mut source = start_reader_chain();
            assert_eq!(source.network_id(), chain.network_id());
            assert_eq!(source.commit(vec![transaction]), [true]);
            let original = source
                .kura()
                .get_block(
                    NonZeroUsize::new(2).unwrap(),
                    &source.state().query_view().execution_budget(),
                )
                .unwrap()
                .unwrap();
            let uncertified = iroha_data_model::block::SharedSignedBlock::try_new(
                original.as_ref().clone().with_commit_certificate(None),
                &state.query_view().execution_budget(),
            )
            .expect("admit deliberately invalid fixture block");
            chain
                .kura()
                .store_block(uncertified.clone())
                .expect("retain invalid missing-certificate body");
            state
                .block(uncertified.header())
                .commit_empty_block_for_testing()
                .expect("index explicit invalid storage claim without applying registration");
            let view = state.query_view();
            assert!(
                !validate_finalized_block_wire(
                    &view,
                    &material.network_id,
                    2,
                    uncertified.hash(),
                    &uncertified
                )
                .expect("completed finality read"),
                "native source rejects the absent certificate"
            );
            uncertified
        };
        let query = MusubiPublicationFinalizedArchiveRegistrationQueryV1 {
            version: 1,
            network_id: material.network_id,
            transaction_hash,
            snapshot: MusubiRegistrySnapshotV1 {
                finalized_height: material.archive.registered_at_height,
                finalized_block_hash: *canonical_block.hash().as_ref(),
                index_revision: 1,
            },
            registration: material.archive.registration_projection(),
            expected_policy_revision: 1,
        };
        let reader = MusubiPublicationFinalizedArchiveRegistrationReaderV1::new(
            material.network_id,
            Arc::clone(&state),
        )
        .expect("reader binds exact fixture state");
        ReaderFixture {
            reader,
            state,
            query,
            archive: material.archive,
            chain,
        }
    }
    fn replace_current_archive(
        state: &State,
        canonical_hash: [u8; 32],
        archive: &MusubiArchiveRecordV1,
    ) {
        replace_current_archive_with_location(state, canonical_hash, archive, None, None, None);
    }
    fn replace_current_archive_with_location(
        state: &State,
        canonical_hash: [u8; 32],
        archive: &MusubiArchiveRecordV1,
        location: Option<&MusubiArchiveLocationV1>,
        attestation: Option<&MusubiProviderBundleAttestationRecordV1>,
        owner_override: Option<(ProviderId, AccountId)>,
    ) {
        let header = BlockHeader::new(
            NonZeroU64::new(archive.registered_at_height + 1).expect("nonzero fixture height"),
            Some(HashOf::from_untyped_unchecked(Hash::prehashed(
                canonical_hash,
            ))),
            None,
            2_000,
            0,
        );
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        transaction
            .world_mut_for_testing()
            .musubi_archives_mut()
            .insert(archive.archive_id, archive.clone());
        if let Some(location) = location {
            transaction
                .world_mut_for_testing()
                .musubi_archive_locations_mut_for_testing()
                .insert(location.key(), location.clone());
        }
        if let Some(attestation) = attestation {
            transaction
                .world_mut_for_testing()
                .musubi_provider_bundle_attestations_mut_for_testing()
                .insert(attestation.key, attestation.clone());
        }
        if let Some((provider, owner)) = owner_override {
            transaction
                .world_mut_for_testing()
                .provider_owners_mut_for_testing()
                .insert(provider, owner);
        }
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit current archive substitution");
    }
    fn readback_target(
        archive: &MusubiArchiveRecordV1,
    ) -> (
        MusubiArchiveLocationV1,
        MusubiProviderBundleAttestationRecordV1,
    ) {
        let mut location = MusubiArchiveLocationV1 {
            location_id: MusubiArchiveLocationIdV1::new([0x61; 32]),
            archive_id: archive.archive_id,
            pin_manifest: ManifestDigest::new([0x62; 32]),
            replication_order: ReplicationOrderId::new([0x63; 32]),
            providers: vec![archive.staging_receipt.payload.binding.seed_provider],
            provider_attestation_set_digest: MusubiProviderBundleAttestationSetDigestV1::new(
                [0x64; 32],
            ),
            renew_after_epoch: 1,
            expires_at_epoch: 2,
            finalized_height: archive.registered_at_height,
            revision: 1,
            state: MusubiArchiveLocationStateV1::Healthy,
        };
        let provider_key = keypair(0x34);
        let owner = AccountId::new(keypair(0x32).public_key().clone());
        let signer = AccountId::new(provider_key.public_key().clone());
        let binding = MusubiProviderBundleVerificationBindingV1 {
            network_id: archive.staging_receipt.payload.binding.network_id,
            provider_id: location.providers[0],
            completed_by: signer.clone(),
            completion_authority: ProviderIngestCompletionAuthorityV1::new(
                owner,
                signer,
                ProviderIngestCompletionSignerPolicyV1 {
                    policy_id: [0x71; 32],
                    revision: 1,
                    predecessor_digest: None,
                    policy_digest: [0x72; 32],
                },
            ),
            replication_order: location.replication_order,
            assignment_revision: 1,
            completion_epoch: 1,
            finalized_anchor: ProviderIngestFinalizedAnchorV1 {
                height: 1,
                block_hash: [0x73; 32],
            },
            archive_id: archive.archive_id,
            bundle_digest: archive.commitment.bundle_digest,
            descriptor_digest: archive.commitment.descriptor_digest,
            semantic_release_manifest_digest: archive
                .staging_receipt
                .payload
                .binding
                .semantic_release_manifest_digest,
            verification_lock_digest: MusubiVerificationLockDigestV1::new([0x74; 32]),
            source_tree_digest: archive.commitment.source_tree_digest,
        };
        let payload = MusubiProviderBundleVerificationPayloadV1 {
            version: 1,
            binding,
        };
        let attestation = MusubiProviderBundleVerificationAttestationV1 {
            approvals: vec![MusubiProviderBundleVerificationApprovalV1 {
                public_key: provider_key.public_key().clone(),
                signature: SignatureOf::try_from_hash(
                    provider_key.private_key(),
                    payload.signing_hash(),
                )
                .expect("sign provider attestation"),
            }],
            payload,
        };
        location.provider_attestation_set_digest =
            musubi_provider_bundle_attestation_set_digest_v1(
                archive.archive_id,
                location.replication_order,
                &[attestation.reference()],
            )
            .expect("provider-attestation set digest");
        let record = MusubiProviderBundleAttestationRecordV1 {
            key: attestation.key(),
            attestation_digest: attestation.digest(),
            attestation,
            registered_by: archive.registered_by.clone(),
            registered_at_height: archive.registered_at_height,
        };
        record
            .validate()
            .expect("valid signed provider attestation");
        (location, record)
    }
    #[test]
    fn current_readback_target_requires_exact_location_and_registered_provider() {
        let mut archive = registration_material().archive;
        let (location, record) = readback_target(&archive);
        let owner = &record
            .attestation
            .payload
            .binding
            .completion_authority
            .provider_owner;
        assert_ne!(*owner, record.attestation.payload.binding.completed_by);
        archive.location_ids.push(location.location_id);
        assert!(current_readback_target_matches(
            &archive,
            &location,
            Some(&location),
            Some(owner),
            Some(&record),
        ));
        assert!(
            !current_readback_target_matches(
                &archive,
                &location,
                Some(&location),
                Some(&record.attestation.payload.binding.completed_by),
                Some(&record),
            ),
            "completion signer cannot replace the registered provider owner"
        );
        let mut changed = location.clone();
        changed.pin_manifest = ManifestDigest::new([0x65; 32]);
        assert!(!current_readback_target_matches(
            &archive,
            &location,
            Some(&changed),
            Some(owner),
            Some(&record),
        ));
        assert!(!current_readback_target_matches(
            &archive,
            &location,
            None,
            Some(owner),
            Some(&record),
        ));
        assert!(!current_readback_target_matches(
            &archive,
            &location,
            Some(&location),
            None,
            Some(&record),
        ));
        let changed_owner = AccountId::new(keypair(0x35).public_key().clone());
        assert!(!current_readback_target_matches(
            &archive,
            &location,
            Some(&location),
            Some(&changed_owner),
            Some(&record),
        ));
        assert!(!current_readback_target_matches(
            &archive,
            &location,
            Some(&location),
            Some(owner),
            None,
        ));
        archive.location_ids.clear();
        assert!(!current_readback_target_matches(
            &archive,
            &location,
            Some(&location),
            Some(owner),
            Some(&record),
        ));
    }
    #[test]
    fn readback_target_rechecks_current_location_after_mutation_and_reader_restart() {
        let fixture = reader_fixture();
        let (location, record) = readback_target(&fixture.archive);
        let mut archive = fixture.archive.clone();
        archive.location_ids.push(location.location_id);
        replace_current_archive_with_location(
            &fixture.state,
            fixture.query.snapshot.finalized_block_hash,
            &archive,
            Some(&location),
            Some(&record),
            None,
        );
        let provider = location.providers[0];
        fixture
            .reader
            .validate_current_readback_target(&fixture.query, &location, provider)
            .expect("exact current finalized target");

        let mut changed = location.clone();
        changed.pin_manifest = ManifestDigest::new([0x65; 32]);
        replace_current_archive_with_location(
            &fixture.state,
            fixture.query.snapshot.finalized_block_hash,
            &archive,
            Some(&changed),
            Some(&record),
            None,
        );
        assert_eq!(
            fixture
                .reader
                .validate_current_readback_target(&fixture.query, &location, provider),
            Err(invalid()),
        );
        let reopened = MusubiPublicationFinalizedArchiveRegistrationReaderV1::new(
            fixture.query.network_id,
            Arc::clone(&fixture.state),
        )
        .expect("reader restart uses the same authoritative State handle");
        assert_eq!(
            reopened.validate_current_readback_target(&fixture.query, &location, provider),
            Err(invalid()),
        );
        let replacement_owner = AccountId::new(keypair(0x36).public_key().clone());
        replace_current_archive_with_location(
            &fixture.state,
            fixture.query.snapshot.finalized_block_hash,
            &archive,
            Some(&location),
            Some(&record),
            Some((provider, replacement_owner)),
        );
        assert_eq!(
            reopened.validate_current_readback_target(&fixture.query, &location, provider),
            Err(invalid()),
        );
        let mut substituted_attestation = record.clone();
        substituted_attestation
            .attestation
            .payload
            .binding
            .bundle_digest = MusubiContentDigestV1::new([0x75; 32]);
        replace_current_archive_with_location(
            &fixture.state,
            fixture.query.snapshot.finalized_block_hash,
            &archive,
            Some(&location),
            Some(&substituted_attestation),
            Some((
                provider,
                record
                    .attestation
                    .payload
                    .binding
                    .completion_authority
                    .provider_owner
                    .clone(),
            )),
        );
        assert_eq!(
            reopened.validate_current_readback_target(&fixture.query, &location, provider),
            Err(invalid()),
        );
    }
    #[test]
    fn exact_finalized_registration_returns_current_mutable_record() {
        let fixture = reader_fixture();
        let archive = fixture
            .reader
            .read_current_archive(&fixture.query)
            .expect("exact finalized registration reads successfully");
        assert_eq!(archive, fixture.archive);
        assert_eq!(archive.location_revision, 2);
        assert_eq!(archive.location_ids, fixture.archive.location_ids);
    }
    mod storage_authorization_tests {
        include!("finality/storage_authorization_tests.rs");
    }
    #[test]
    fn storage_preflight_never_dispatches_unfinalized_registration() {
        use super::super::storage_coordination::FinalizedRegistrationCheckedStorageBackendV1;
        use iroha_musubi_service::{
            MusubiFinalizedArchiveRegistrationEvidenceV1, MusubiPublicationServiceBackendErrorV1,
            MusubiStorageCoordinationBackendV1, MusubiStorageCoordinationRequestV1,
            MusubiStorageCoordinationResponseV1,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct MutationProbe(Arc<AtomicUsize>);
        impl MusubiStorageCoordinationBackendV1 for MutationProbe {
            fn verify_current_registration(
                &self,
                _request: &MusubiStorageCoordinationRequestV1,
            ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
                Err(MusubiPublicationServiceBackendErrorV1::Retryable)
            }

            fn coordinate_storage(
                &mut self,
                _request: &iroha_musubi_service::VerifiedStorageCoordinationRequestV1<'_>,
            ) -> Result<MusubiStorageCoordinationResponseV1, MusubiPublicationServiceBackendErrorV1>
            {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(MusubiPublicationServiceBackendErrorV1::Retryable)
            }
        }
        fn request(fixture: &ReaderFixture) -> MusubiStorageCoordinationRequestV1 {
            let query = &fixture.query;
            let archive = &fixture.archive;
            MusubiStorageCoordinationRequestV1 {
                version: 1,
                operation_id: [0x81; 32],
                generation: 1,
                prior_location_ids: Vec::new(),
                network_id: query.network_id,
                publisher: archive.registered_by.clone(),
                commitment: archive.commitment.clone(),
                verification_lock_digest: MusubiVerificationLockDigestV1::new([0x74; 32]),
                staging_receipt: archive.staging_receipt.clone(),
                expected_policy_revision: query.expected_policy_revision,
                finalized_registration: MusubiFinalizedArchiveRegistrationEvidenceV1 {
                    version: 1,
                    network_id: query.network_id,
                    transaction_hash: query.transaction_hash,
                    snapshot: query.snapshot,
                    registration: query.registration.clone(),
                },
            }
        }

        let fixture = reader_fixture();
        let calls = Arc::new(AtomicUsize::new(0));
        let checked = FinalizedRegistrationCheckedStorageBackendV1::new(
            fixture.reader.clone(),
            Box::new(MutationProbe(Arc::clone(&calls))),
        );
        let dispatch = |source: &ReaderFixture, request: &MusubiStorageCoordinationRequestV1| {
            storage_authorization_tests::dispatch(
                Box::new(FinalizedRegistrationCheckedStorageBackendV1::new(
                    source.reader.clone(),
                    Box::new(MutationProbe(Arc::clone(&calls))),
                )),
                request,
            )
        };
        let exact = request(&fixture);
        exact.validate().expect("canonical coordination request");
        assert_eq!(checked.verify_current_registration(&exact), Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            dispatch(&fixture, &exact),
            Err(MusubiPublicationServiceBackendErrorV1::Retryable),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let mut wrong_transaction = exact.clone();
        wrong_transaction.finalized_registration.transaction_hash = [0x91; 32];
        assert_eq!(
            checked.verify_current_registration(&wrong_transaction),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        assert_eq!(
            dispatch(&fixture, &wrong_transaction),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        let mut wrong_policy = exact.clone();
        wrong_policy.expected_policy_revision += 1;
        assert_eq!(
            checked.verify_current_registration(&wrong_policy),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        assert_eq!(
            dispatch(&fixture, &wrong_policy),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        let mut foreign_network = exact.clone();
        foreign_network.network_id = network_id(0x67);
        assert_eq!(
            checked.verify_current_registration(&foreign_network),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        assert_eq!(
            dispatch(&fixture, &foreign_network),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        let mut locally_ahead = exact.clone();
        locally_ahead
            .finalized_registration
            .snapshot
            .finalized_height += 1;
        assert_eq!(
            checked.verify_current_registration(&locally_ahead),
            Err(MusubiPublicationServiceBackendErrorV1::Retryable),
        );
        assert_eq!(
            dispatch(&fixture, &locally_ahead),
            Err(MusubiPublicationServiceBackendErrorV1::Retryable),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let uncertified = reader_fixture_with_finality(false);
        let checked_uncertified = FinalizedRegistrationCheckedStorageBackendV1::new(
            uncertified.reader.clone(),
            Box::new(MutationProbe(Arc::clone(&calls))),
        );
        assert_eq!(
            checked_uncertified.verify_current_registration(&request(&uncertified)),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        assert_eq!(
            dispatch(&uncertified, &request(&uncertified)),
            Err(MusubiPublicationServiceBackendErrorV1::Permanent),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn registration_without_verified_native_finality_is_invalid() {
        use iroha_core::query::musubi_pin_outbox::{
            MusubiPinOutboxCheckExpectedV1, begin_musubi_pin_outbox_check_v1,
        };
        use iroha_data_model::musubi::{
            MusubiPinOutboxCheckExpectationV1, MusubiPinOutboxCheckFloorV1,
        };

        let fixture = reader_fixture_with_finality(false);
        assert_eq!(
            fixture
                .reader
                .read_current_archive(&fixture.query)
                .expect_err("an uncertified Kura body must fail closed"),
            invalid()
        );
        let block = fixture
            .chain
            .committed(fixture.query.snapshot.finalized_height);
        let result = begin_musubi_pin_outbox_check_v1(
            Arc::clone(&fixture.state),
            MusubiPinOutboxCheckExpectedV1 {
                chain_id: fixture.state.chain_id_ref().clone(),
                network_id: fixture.query.network_id,
                pin_authority: fixture.archive.registered_by.clone(),
                session_id: [0x81; 32],
                inventory_digest: [0x82; 32],
                floor: MusubiPinOutboxCheckFloorV1 {
                    height: block.height(),
                    block_hash: *block.block_hash().as_ref(),
                    context_id: block.id(),
                },
                expected: MusubiPinOutboxCheckExpectationV1::Absent,
            },
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        );
        assert!(
            result.is_err(),
            "an absent high-water cannot bypass missing tip finality"
        );
    }
    #[test]
    fn missing_duplicate_and_rejected_transactions_are_invalid() {
        let fixture = reader_fixture();
        let mut missing = fixture.query.clone();
        missing.transaction_hash = [0x71; 32];
        let error = fixture
            .reader
            .read_current_archive(&missing)
            .expect_err("missing transaction must fail closed");
        assert_eq!(error, invalid());
        let material = registration_material_at(
            fixture.query.network_id,
            fixture.archive.registered_at_height,
        );
        let transaction = successful_registration_transaction(&material);
        let mut query = fixture.query.clone();
        query.transaction_hash = *transaction.hash().as_ref();
        let mut duplicate = signed_proposal(vec![transaction.clone(), transaction.clone()]);
        let duplicate_before = duplicate
            .canonical_resultless_proposal()
            .expect("valid original proposal");
        let duplicate_outputs = network_outputs(&duplicate, None);
        assert!(install_fixture_outputs(&mut duplicate, duplicate_outputs, 2).is_err());
        assert_eq!(
            duplicate
                .canonical_resultless_proposal()
                .expect("valid original proposal"),
            duplicate_before
        );
        assert!(
            !duplicate.has_results(),
            "duplicate execution calls cannot acquire outputs"
        );
        assert!(!validate_registration_transaction(&query, &duplicate));
        let rejected = signed_block_with_results(vec![transaction], Some(0));
        assert!(!validate_registration_transaction(&query, &rejected));
    }
    #[test]
    fn registration_joins_only_network_success_with_pipeline_and_time_outputs() {
        let material = registration_material();
        let transaction = successful_registration_transaction(&material);
        let mut block = signed_block_with_results(vec![transaction.clone()], None);
        let query = MusubiPublicationFinalizedArchiveRegistrationQueryV1 {
            version: 1,
            network_id: material.network_id,
            transaction_hash: *transaction.hash().as_ref(),
            snapshot: MusubiRegistrySnapshotV1 {
                finalized_height: 1,
                finalized_block_hash: *block.hash().as_ref(),
                index_revision: 1,
            },
            registration: material.archive.registration_projection(),
            expected_policy_revision: 1,
        };
        let mut outputs = block.execution_outputs().to_vec();
        outputs.extend(structural_registration_callbacks(&material.archive));
        install_fixture_outputs(&mut block, outputs, 3).unwrap();
        assert_eq!(block.network_entrypoint_count(), 1);
        assert_eq!(block.execution_outputs().len(), 3);
        assert!(block.network_output_at(1).is_none());
        assert!(validate_registration_transaction(&query, &block));

        let mut rejected = signed_block_with_results(vec![transaction], Some(0));
        let mut outputs = rejected.execution_outputs().to_vec();
        outputs.extend(structural_registration_callbacks(&material.archive));
        install_fixture_outputs(&mut rejected, outputs, 2).unwrap();
        assert!(
            !validate_registration_transaction(&query, &rejected),
            "successful internal registration traces cannot replace rejected Network execution"
        );

        let mut missing = signed_block_with_results(
            vec![signed_transaction(
                material.network_id,
                &material.publisher_key,
                Vec::new(),
            )],
            None,
        );
        let mut outputs = missing.execution_outputs().to_vec();
        outputs.extend(structural_registration_callbacks(&material.archive));
        install_fixture_outputs(&mut missing, outputs, 3).unwrap();
        assert!(
            !validate_registration_transaction(&query, &missing),
            "internal registration traces cannot supply a missing signed Network registration"
        );

        let before = block.encode_wire().unwrap();
        assert!(
            install_fixture_outputs(
                &mut block,
                structural_registration_callbacks(&material.archive),
                2,
            )
            .is_err(),
            "internal outputs cannot replace the required Network owner"
        );
        assert_eq!(block.encode_wire().unwrap(), before);
    }
    #[test]
    fn multi_instruction_registration_is_invalid() {
        let fixture = reader_fixture();
        let material = registration_material_at(
            fixture.query.network_id,
            fixture.archive.registered_at_height,
        );
        let register = registration_instruction(&material.archive);
        let transaction = signed_transaction(
            material.network_id,
            &material.publisher_key,
            vec![register.clone().into(), register.into()],
        );
        let mut query = fixture.query;
        query.transaction_hash = *transaction.hash().as_ref();
        let block = signed_block_with_results(vec![transaction], None);
        assert!(!validate_registration_transaction(&query, &block));
    }
    #[test]
    fn wrong_authority_registration_is_invalid() {
        let fixture = reader_fixture();
        let material = registration_material_at(
            fixture.query.network_id,
            fixture.archive.registered_at_height,
        );
        let transaction = signed_transaction(
            material.network_id,
            &keypair(0x51),
            vec![registration_instruction(&material.archive).into()],
        );
        let mut query = fixture.query;
        query.transaction_hash = *transaction.hash().as_ref();
        let block = signed_block_with_results(vec![transaction], None);
        assert!(!validate_registration_transaction(&query, &block));
    }
    #[test]
    fn wrong_network_registration_is_invalid() {
        let fixture = reader_fixture();
        let material = registration_material_at(
            fixture.query.network_id,
            fixture.archive.registered_at_height,
        );
        let transaction = signed_transaction(
            network_id(0x25),
            &material.publisher_key,
            vec![registration_instruction(&material.archive).into()],
        );
        let mut query = fixture.query;
        query.transaction_hash = *transaction.hash().as_ref();
        let block = signed_block_with_results(vec![transaction], None);
        assert!(!validate_registration_transaction(&query, &block));
    }
    #[test]
    fn snapshot_and_finalized_wire_substitution_are_invalid() {
        let fixture = reader_fixture();
        let mut substituted_snapshot = fixture.query.clone();
        substituted_snapshot.snapshot.finalized_block_hash = [0x61; 32];
        assert_eq!(
            fixture
                .reader
                .read_current_archive(&substituted_snapshot)
                .expect_err("snapshot substitution must fail closed"),
            invalid()
        );
        let view = fixture.state.query_view();
        let height = fixture.archive.registered_at_height;
        let block = view
            .kura()
            .get_block(
                NonZeroUsize::new(usize::try_from(height).unwrap())
                    .expect("nonzero fixture height"),
                &view.execution_budget(),
            )
            .expect("completed fixture read")
            .expect("fixture Kura block");
        let canonical_hash = block.hash();
        assert!(
            validate_finalized_block_wire(
                &view,
                &fixture.query.network_id,
                height,
                canonical_hash,
                &block
            )
            .expect("completed finality read")
        );
        let mut added = block.as_ref().clone();
        let mut outputs = added.execution_outputs().to_vec();
        outputs.extend(structural_registration_callbacks(&fixture.archive));
        let fragments = u64::try_from(added.execution_outputs().len() + 2).unwrap();
        install_fixture_outputs(&mut added, outputs, fragments).unwrap();
        assert_eq!(added.hash(), canonical_hash);
        assert!(
            !validate_finalized_block_wire(
                &view,
                &fixture.query.network_id,
                height,
                canonical_hash,
                &added
            )
            .expect("completed finality read"),
            "additional internal outputs cannot inherit original native finality"
        );
        let mut substituted = block.as_ref().clone();
        let mut outputs = substituted.execution_outputs().to_vec();
        let ExecutionOutputV1::Network(output) = &mut outputs[0] else {
            panic!("registration fixture owns Network output zero");
        };
        assert_eq!(output.input_index, 0);
        output.result = TransactionResultInner::Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted("substituted Kura result".to_owned()),
        ))
        .into();
        output.completions.clear();
        install_fixture_outputs(&mut substituted, outputs, 0)
            .expect("replace the result while retaining the consensus header hash");
        assert_eq!(substituted.hash(), canonical_hash);
        assert!(
            !validate_finalized_block_wire(
                &view,
                &fixture.query.network_id,
                height,
                canonical_hash,
                &substituted
            )
            .expect("completed finality read")
        );
    }
    #[test]
    fn current_registration_projection_substitution_is_invalid() {
        let fixture = reader_fixture();
        let mut substituted = fixture.archive.clone();
        substituted.staging_receipt.payload.binding.nonce = [0x62; 32];
        substituted
            .validate()
            .expect("substituted record remains structural");
        replace_current_archive(
            &fixture.state,
            fixture.query.snapshot.finalized_block_hash,
            &substituted,
        );
        assert_eq!(
            fixture
                .reader
                .read_current_archive(&fixture.query)
                .expect_err("current immutable projection substitution must fail closed"),
            invalid()
        );
    }
    #[test]
    fn finalized_seed_capability_reads_exact_car_once_per_bounded_lease() {
        use super::super::{
            MusubiPublicationFinalizedSeedReadErrorV1,
            shared_seed_staging::SharedSeedStagingBackendV1,
        };
        use iroha_musubi_service::{
            MusubiSeedIngressBackendV1, MusubiSeedStagingBackendV1, MusubiSeedStagingErrorV1,
            seed_test_support::fixture,
        };

        let (seed_binding, commitment, plan, car) = fixture();
        let fixture = reader_fixture_with_finality_using(
            true,
            Some(&(commitment, seed_binding.semantic_release_manifest_digest)),
        );
        let binding = &fixture.archive.staging_receipt.payload.binding;
        let workspace = tempfile::tempdir().expect("seed fixture workspace");
        let directory =
            iroha_fs::PrivateDirectory::open_or_create(workspace.path().join("private"))
                .expect("native private seed fixture root");
        let seed_root = directory.path().to_owned();
        let seed = MusubiSeedStagingBackendV1::initialize(
            &seed_root,
            binding.seed_provider,
            2,
            128 * 1024 * 1024,
        )
        .expect("seed owner");
        let (mut ingress, capability) =
            SharedSeedStagingBackendV1::share(seed, fixture.reader.clone());
        ingress
            .stage_exact_car(
                [0x61; 32],
                binding,
                &fixture.archive.commitment,
                &plan,
                &car,
            )
            .expect("shared ingress stages exact finalized CAR");
        ingress
            .verify_staged_car(
                [0x61; 32],
                binding,
                &fixture.archive.commitment,
                &plan,
                &car,
            )
            .expect("shared ingress re-reads exact staged CAR");
        assert_eq!(capability.provider_id(), binding.seed_provider);
        let mut wrong_transaction = fixture.query.clone();
        wrong_transaction.transaction_hash = [0xaa; 32];
        assert_eq!(
            capability
                .read_finalized_seed(&wrong_transaction)
                .unwrap_err(),
            MusubiPublicationFinalizedSeedReadErrorV1::Finality(
                MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Invalid
            ),
        );
        let budget = fixture.state.ivm_execution_budget();
        let held = budget
            .try_reserve_bytes(budget.limit_bytes().saturating_sub(budget.reserved_bytes()))
            .unwrap();
        let error = capability.read_finalized_seed(&fixture.query).unwrap_err();
        let MusubiPublicationFinalizedSeedReadErrorV1::Finality(
            MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Deferred(ref original),
        ) = error
        else {
            panic!("original native seed-read refusal was lost: {error:?}")
        };
        assert!(original.allocation_refusal().is_some());
        drop(held);
        let lease = capability
            .read_finalized_seed(&fixture.query)
            .expect("exact finalized registration opens exact staged bytes");
        assert_eq!(lease.plan(), &plan);
        assert_eq!(lease.car(), car.as_slice());
        assert_eq!(
            capability.read_finalized_seed(&fixture.query).unwrap_err(),
            MusubiPublicationFinalizedSeedReadErrorV1::Custody(MusubiSeedStagingErrorV1::Capacity),
        );
        drop(lease);
        let replay = capability
            .read_finalized_seed(&fixture.query)
            .expect("released reservation permits exact re-read");
        assert_eq!(replay.car(), car.as_slice());
        drop(replay);
        let mut substituted = fixture.archive.clone();
        substituted.staging_receipt.payload.binding.nonce = [0x62; 32];
        substituted
            .validate()
            .expect("substituted record remains structural");
        replace_current_archive(
            &fixture.state,
            fixture.query.snapshot.finalized_block_hash,
            &substituted,
        );
        assert_eq!(
            capability.read_finalized_seed(&fixture.query).unwrap_err(),
            MusubiPublicationFinalizedSeedReadErrorV1::Finality(
                MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Invalid
            ),
            "a completed seed lease must not authorize a substituted current registration",
        );
        drop(ingress);
        drop(capability);
        MusubiSeedStagingBackendV1::open(&seed_root, binding.seed_provider, 2, 128 * 1024 * 1024)
            .expect("last owner releases exclusive seed lease");
    }
    #[test]
    fn invalid_evidence_is_permanent_while_future_finality_is_retryable() {
        let fixture = reader_fixture();
        let wrong_reader_error = MusubiPublicationFinalizedArchiveRegistrationReaderV1::new(
            network_id(0x25),
            Arc::clone(&fixture.state),
        )
        .expect_err("reader must reject a state handle from another exact network");
        assert_eq!(wrong_reader_error, invalid());
        assert!(!wrong_reader_error.is_retryable());
        let mut height_ahead = fixture.query.clone();
        height_ahead.snapshot.finalized_height = fixture.query.snapshot.finalized_height + 1;
        height_ahead.snapshot.finalized_block_hash = [0x63; 32];
        let height_error = fixture
            .reader
            .read_current_archive(&height_ahead)
            .expect_err("future finalized height is locally ahead");
        assert_eq!(
            height_error,
            MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::LocallyAhead
        );
        assert!(height_error.is_retryable());
        let mut revision_ahead = fixture.query.clone();
        revision_ahead.snapshot.index_revision = 2;
        let revision_error = fixture
            .reader
            .read_current_archive(&revision_ahead)
            .expect_err("future resolver revision is locally ahead");
        assert_eq!(
            revision_error,
            MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::LocallyAhead
        );
        assert!(revision_error.is_retryable());
        let mut substituted = fixture.query;
        substituted.snapshot.finalized_block_hash = [0x64; 32];
        let invalid_error = fixture
            .reader
            .read_current_archive(&substituted)
            .expect_err("same-height fork evidence is invalid");
        assert_eq!(invalid_error, invalid());
        assert!(!invalid_error.is_retryable());
    }

    #[test]
    fn finalized_archive_capacity_refusal_retains_original_owner_and_retries_exact_read() {
        let fixture = reader_fixture();
        let view = fixture.state.query_view();
        let budget = view.execution_budget();
        let held = budget
            .try_reserve_bytes(budget.limit_bytes().saturating_sub(budget.reserved_bytes()))
            .expect("hold remaining original State allocation capacity");
        let error = fixture
            .reader
            .read_current_archive_in_view(&fixture.query, &view)
            .expect_err("unfinished native finality read cannot become invalid evidence");
        assert!(error.is_retryable());
        let MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Deferred(ref local) = error
        else {
            panic!("original resource refusal was lost: {error:?}");
        };
        assert!(
            local.allocation_refusal().is_some(),
            "retain original pool release source"
        );
        let pin = super::super::pin_registration::MusubiPublicationFinalizedPinRegistrationReadErrorV1::from(local.clone());
        assert!(
            matches!(pin, super::super::pin_registration::MusubiPublicationFinalizedPinRegistrationReadErrorV1::Deferred(ref retained) if retained == local)
        );
        drop(held);
        assert_eq!(
            fixture
                .reader
                .read_current_archive_in_view(&fixture.query, &view)
                .unwrap(),
            fixture.archive,
            "retry authenticates exactly the same original registration"
        );
    }
}
