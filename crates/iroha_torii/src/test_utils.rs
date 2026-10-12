//! Test helpers for explicit execution and authenticated native history fixtures.

use iroha_config::parameters::defaults::zk::fastpq;
use iroha_core::{
    queue::Queue,
    state::{State, StateReadOnly, WorldReadOnly},
    sumeragi::certified_chain::CommittedBlock,
    sumeragi::{
        payload,
        test_chain::{CertifiedTestChain, Signers},
    },
    tx::AcceptedTransaction,
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::block::SignedBlock;
use iroha_data_model::{
    NetworkId, Registrable,
    account::AccountId,
    block::BlockHeader,
    content::ContentAuthMode,
    isi::smart_contract_code::{
        CommitContractDeployment, FinalizeSmartContractCodeUpload, RegisterSmartContractCode,
        SMART_CONTRACT_CODE_CHUNK_BYTES, UploadSmartContractCodeChunk,
    },
    jurisdiction::JdgSignatureScheme,
    permission,
    prelude::{
        Account, Domain, ExposedPrivateKey, Grant, InstructionBox, Register, TransactionBuilder,
    },
    smart_contract::{CONTRACT_DEPLOY_NONCE_METADATA_KEY, ContractAddress},
    sorafs::pricing::PricingScheduleRecord,
};
use iroha_executor_data_model::permission::smart_contract::{
    CanInvokeContractEntrypoint, CanUseContractPermission,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use nonzero_ext::nonzero;
use std::{
    borrow::Cow,
    collections::BTreeMap,
    num::NonZeroU64,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::Arc,
    time::Duration,
};
/// Attach a complete structural output collection for transport/projection tests.
/// Each successful fixture row represents one declared fragment. This helper
/// does not execute State or authenticate economic results or finality.
#[cfg(test)]
pub(crate) fn attach_fixture_execution_outputs(
    block: &mut SignedBlock,
    rows: Vec<iroha_data_model::block::execution_output::ExecutionOutputV1>,
) {
    let fragments = u64::try_from(rows.iter().filter(|row| row.result().is_ok()).count()).unwrap();
    block
        .set_execution_outputs(
            rows,
            fragments,
            Default::default(),
            vec![],
            Default::default(),
            Default::default(),
            &iroha_data_model::block::output_budget::ExecutionOutputLimits {
                max_outputs: 1024,
                max_output_bytes: 1024 * 1024,
                max_total_output_bytes: 2 * 1024 * 1024,
                max_executed_wire_bytes: 4 * 1024 * 1024,
            },
        )
        .unwrap();
}
/// Exact genesis-lineage identity used by [`mk_minimal_root_cfg`].
#[must_use]
pub fn signed_query_network_id() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"Torii test genesis trust anchor",
    )))
}
fn checked_random_keypair(context: &str) -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_random()
        .unwrap_or_else(|err| panic!("{context}: checked random key generation failed: {err}"))
}
/// Parameters for invoking a contract within Torii integration tests.
pub struct ContractCallOptions<'a> {
    /// Explicit entry point function to call on the contract.
    pub entrypoint: &'a str,
    /// Serialized JSON payload passed to the contract call.
    pub payload: Option<&'a norito::json::Value>,
    /// Upper bound on gas consumption for the call.
    pub gas_limit: u64,
}
/// Parameters for invoking a read-only contract view within Torii integration tests.
pub struct ContractViewOptions<'a> {
    /// Explicit entry point function to execute.
    pub entrypoint: &'a str,
    /// Serialized JSON payload passed to the contract view.
    pub payload: Option<&'a norito::json::Value>,
    /// Upper bound on gas consumption for the local view execution.
    pub gas_limit: u64,
}
/// Execute the current pending inputs through their original native chain, then remove
/// precisely the entrypoints whose global application completed.
///
/// The snapshot remains retained until genuine native certification and publication finish.
///
/// # Panics
/// Panics if fixture work cannot assemble, execute, or publish successfully.
pub fn apply_queued_in_one_block(chain: &mut CertifiedTestChain, queue: &Arc<Queue>) -> usize {
    let limit = core::num::NonZeroUsize::new(1024).expect("nonzero");
    let accepted = queue
        .bounded_pending_snapshot_for_testing(&chain.state().view(), limit)
        .expect("healthy native queue snapshot");
    if accepted.is_empty() {
        return 0;
    }
    let count = accepted.len();
    let hashes = accepted
        .iter()
        .map(AcceptedTransaction::hash_as_entrypoint)
        .collect::<Vec<_>>();
    let committed = commit_native_accepted_inputs(chain, accepted);
    for (_, _, result) in crate::canonical_history::signed_calls(committed.block())
        .expect("complete native output ownership")
    {
        assert!(
            result.is_ok(),
            "native fixture transaction rejected: {result:?}"
        );
    }
    assert_eq!(queue.remove_committed_hashes_for_testing(hashes), count);
    count
}

/// Assemble and execute exact input envelopes through the original native chain.
/// The returned output and certificate come from production execution.
///
/// # Panics
/// Panics if no original parent or successor schedule exists, or execution refuses the proposal.
pub fn commit_native_accepted_inputs(
    chain: &mut CertifiedTestChain,
    accepted: Vec<AcceptedTransaction<'static>>,
) -> CommittedBlock {
    let view = chain.state().view();
    let parent = view
        .latest_block()
        .expect("funded canonical history read")
        .expect("original applied genesis");
    let schedule = view
        .world()
        .consensus_schedule()
        .ready(chain.height() + 1)
        .expect("authenticated successor schedule");
    let proposal = payload::assemble(
        chain.state(),
        payload::Assembly {
            parent: &parent,
            view: 0,
            cadence: Duration::from_millis(schedule.params.block_time_ms),
        },
        &accepted,
    )
    .expect("assemble original pending inputs");
    drop(view);
    finalize_committed_block(chain, proposal)
}

/// Execute, certify, persist and apply an original proposal owned by this native chain.
/// This accepts no caller-supplied outputs or finality evidence.
///
/// # Panics
/// Panics if original native execution or certification refuses the proposal.
pub fn finalize_committed_block(
    chain: &mut CertifiedTestChain,
    proposal: SignedBlock,
) -> CommittedBlock {
    chain.commit_proposal(proposal, Signers::Quorum, Default::default())
}
/// Build a minimal self-describing contract artifact containing a single HALT.
pub fn minimal_ivm_program(abi_version: u8) -> Vec<u8> {
    let meta = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1_000,
        abi_version,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: Vec::new(),
        callables: Vec::new(),
        seiyaku_name: "TestContract".to_owned(),
        compiler_fingerprint: "torii-test-utils".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: "main".to_owned(),
            kind: iroha_data_model::smart_contract::manifest::EntryPointKind::View,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    };
    let mut out = meta.encode();
    out.extend_from_slice(&interface.encode_section());
    out.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
    out
}
/// Compute the hex-encoded contract code hash for a `.to` program.
///
/// This matches Torii's domain-separated full-artifact deployment hashing.
pub fn contract_code_hash_hex(code_bytes: &[u8]) -> String {
    ivm::ProgramMetadata::parse(code_bytes).expect("parse contract artifact");
    let h = ivm::contract_code_hash(&code_bytes);
    hex::encode(<[u8; 32]>::from(h))
}
/// Guard that overrides Torii's data directory with a temporary path for test isolation
/// and clears it on drop. The underlying directory is removed when the guard is dropped.
#[must_use]
pub struct TestDataDirGuard {
    _temp_dir: tempfile::TempDir,
    canonical_path: PathBuf,
    _override_guard: crate::data_dir::OverrideGuard,
}
impl TestDataDirGuard {
    /// Create a new temporary data directory and activate the override.
    pub fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("temp data dir");
        let canonical_path = temp_dir
            .path()
            .canonicalize()
            .expect("canonicalize temp data dir");
        let override_guard = crate::data_dir::OverrideGuard::new(&canonical_path);
        Self {
            _temp_dir: temp_dir,
            canonical_path,
            _override_guard: override_guard,
        }
    }
    /// Access the filesystem path backing this guard.
    pub fn path(&self) -> &Path {
        &self.canonical_path
    }
}
impl Default for TestDataDirGuard {
    fn default() -> Self {
        Self::new()
    }
}
/// Small container for random authority credentials used in tests.
pub struct AuthorityCreds {
    /// Generated account id for the authority
    pub account: AccountId,
    /// Private key corresponding to the generated account id
    pub private_key: ExposedPrivateKey,
}
/// Generate a random authority with matching private key (domain `wonderland`).
pub fn random_authority() -> AuthorityCreds {
    let kp = checked_random_keypair("random authority fixture");
    let account = AccountId::of(kp.public_key().clone());
    let private_key = ExposedPrivateKey(kp.private_key().clone());
    AuthorityCreds {
        account,
        private_key,
    }
}
/// Build a minimal world that contains the given authority account in `wonderland`.
pub fn world_with_authority(authority: &AccountId) -> iroha_core::state::World {
    let domain_id: iroha_model_base::domain::DomainId =
        DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(authority);
    let account = Account::new(authority.clone()).build(authority);
    iroha_core::state::World::with([domain], [account], [])
}
/// Build and enqueue a locally signed atomic contract deployment transaction.
///
/// This deliberately exercises the native deployment instructions instead of recreating the retired
/// server-side signing endpoint in test routers. The authenticated chain identity is read from the
/// same [`State`] snapshot used to derive the contract address and enqueue the transaction.
pub fn enqueue_locally_signed_contract_deployment(
    state: &Arc<State>,
    queue: &Arc<Queue>,
    authority: &AccountId,
    private_key: &ExposedPrivateKey,
    artifact: &[u8],
) -> (ContractAddress, String, String) {
    enqueue_locally_signed_contract_deployment_with_subject_permissions(
        state,
        queue,
        authority,
        private_key,
        artifact,
        std::iter::empty(),
    )
}
/// Build and enqueue a local deployment with exact permissions for its
/// non-signable contract-subject account.
pub fn enqueue_locally_signed_contract_deployment_with_subject_permissions(
    state: &Arc<State>,
    queue: &Arc<Queue>,
    authority: &AccountId,
    private_key: &ExposedPrivateKey,
    artifact: &[u8],
    subject_permissions: impl IntoIterator<Item = permission::Permission>,
) -> (ContractAddress, String, String) {
    enqueue_locally_signed_contract_deployment_with_permissions(
        state,
        queue,
        authority,
        private_key,
        artifact,
        subject_permissions,
        std::iter::empty(),
    )
}
/// Deploy a fixture and grant explicitly named instance permissions to its caller.
///
/// Caller grants follow deployment in the same signed transaction and bind this exact
/// contract address. Subject permissions separately authorize emitted ledger operations.
pub fn enqueue_locally_signed_contract_deployment_with_permissions(
    state: &Arc<State>,
    queue: &Arc<Queue>,
    authority: &AccountId,
    private_key: &ExposedPrivateKey,
    artifact: &[u8],
    subject_permissions: impl IntoIterator<Item = permission::Permission>,
    caller_permissions: impl IntoIterator<Item = Name>,
) -> (ContractAddress, String, String) {
    let verified = ivm::verify_contract_artifact(artifact).expect("verify contract artifact");
    let key_pair =
        KeyPair::from_private_key(private_key.0.clone()).expect("derive local deployment key pair");
    assert_eq!(
        key_pair.public_key(),
        authority.expect_single_signatory(),
        "local deployment key must match authority"
    );
    let hajimari_entrypoint = verified
        .manifest
        .entrypoints
        .as_ref()
        .and_then(|entrypoints| {
            entrypoints.iter().find(|entrypoint| {
                entrypoint.kind
                    == iroha_data_model::smart_contract::manifest::EntryPointKind::Hajimari
            })
        })
        .map(|entrypoint| entrypoint.name.clone());
    let state_view = state.view();
    let transaction_limits = &state_view.world.parameters().transaction;
    let max_frame_bytes = usize::try_from(transaction_limits.ivm_bytecode_size.get())
        .expect("configured fixture manifest frame bound fits usize");
    let max_elements = usize::try_from(transaction_limits.max_instructions.get())
        .expect("configured fixture element bound fits usize");
    // Fund the canonical frame and signer clone before encoding. This original
    // fixture owner remains live through local transaction construction and enqueue.
    let scratch_bytes = max_frame_bytes
        .checked_mul(8)
        .expect("finite fixture signing scratch fits usize");
    let pool_bytes = scratch_bytes
        .checked_add(norito::core::DecodeBudgetContext::allocation_layout().size())
        .expect("fixture scratch and counter backing fit usize");
    let signing_pool = iroha_allocation::AllocationBudget::new(pool_bytes);
    let _signing_scratch = signing_pool
        .try_reserve_bytes(scratch_bytes)
        .expect("fund original fixture signing scratch");
    let signing_context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(
            max_elements,
            max_frame_bytes,
            max_elements,
            scratch_bytes,
            256,
        ),
        &signing_pool,
    )
    .expect("fund original fixture signing counter");
    let manifest = verified
        .manifest
        .try_signed(&signing_context, max_frame_bytes, &key_pair)
        .expect("sign bounded contract manifest locally");
    let nonce_key = Name::from_str(CONTRACT_DEPLOY_NONCE_METADATA_KEY)
        .expect("contract deployment nonce metadata key");
    let deploy_nonce = state_view
        .world
        .account(authority)
        .expect("deployment authority exists")
        .metadata()
        .get(&nonce_key)
        .map(|value| {
            value
                .clone()
                .try_into_any_norito::<u64>()
                .expect("canonical contract deployment nonce")
        })
        .unwrap_or(0);
    let network_id = *state_view.network_id();
    drop(state_view);
    let contract_alias = iroha_data_model::smart_contract::ContractAlias::from_components(
        &format!("fixture{deploy_nonce}"),
        None,
        "universal",
    )
    .expect("construct contract alias");
    let contract_address =
        ContractAddress::derive(&network_id, authority, deploy_nonce, DataSpaceId::UNIVERSAL)
            .expect("derive contract address");
    let total_size = u64::try_from(artifact.len()).expect("artifact size fits u64");
    let chunk_count = u32::try_from(artifact.len().div_ceil(SMART_CONTRACT_CODE_CHUNK_BYTES))
        .expect("contract upload chunk count fits u32");
    assert_ne!(chunk_count, 0, "contract artifact must not be empty");
    let subject_permissions = subject_permissions.into_iter().collect::<Vec<_>>();
    let mut instructions = Vec::with_capacity(
        usize::try_from(chunk_count).expect("chunk count fits usize")
            + 5
            + subject_permissions.len(),
    );
    for (index, chunk) in artifact.chunks(SMART_CONTRACT_CODE_CHUNK_BYTES).enumerate() {
        instructions.push(InstructionBox::from(UploadSmartContractCodeChunk {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                verified.code_hash,
            ),
            total_size,
            chunk_index: u32::try_from(index).expect("chunk index fits u32"),
            chunk_count,
            chunk: chunk.to_vec(),
        }));
    }
    instructions.push(InstructionBox::from(FinalizeSmartContractCodeUpload {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            verified.code_hash,
        ),
        total_size,
        chunk_count,
    }));
    instructions.push(InstructionBox::from({
        let scoped_manifest = manifest;
        RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }));
    instructions.push(InstructionBox::from(Register::account(Account::new(
        contract_address.subject_id(),
    ))));
    instructions.push(InstructionBox::from(CommitContractDeployment {
        expected_deploy_nonce: deploy_nonce,
        contract_address: contract_address.clone(),
        code_hash: verified.code_hash,
        contract_alias,
        lease_expiry_ms: None,
        expected_previous_contract_address: None,
    }));
    for permission in subject_permissions {
        instructions.push(InstructionBox::from(Grant::account_permission(
            permission,
            contract_address.subject_id(),
        )));
    }
    for permission in caller_permissions {
        instructions.push(InstructionBox::from(Grant::account_permission(
            CanUseContractPermission {
                contract: contract_address.clone(),
                permission,
            },
            authority.clone(),
        )));
    }
    if let Some(entrypoint) = hajimari_entrypoint {
        let permission: permission::Permission = CanInvokeContractEntrypoint {
            contract: contract_address.clone(),
            entrypoint,
        }
        .into();
        instructions.push(InstructionBox::from(Grant::account_permission(
            permission,
            authority.clone(),
        )));
    }
    let transaction = TransactionBuilder::new(
        network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .sign(key_pair.private_key());
    queue
        .push(
            AcceptedTransaction::new_unchecked(Cow::Owned(transaction)),
            state.view(),
        )
        .expect("enqueue locally signed contract deployment");
    (
        contract_address,
        hex::encode(verified.code_hash.as_ref()),
        hex::encode(verified.abi_hash.as_ref()),
    )
}
/// Build an unsigned public contract-call prepare request.
/// Signing keys stay with the caller; detached submission signs the exact returned payload.
pub fn contract_call_request_json(
    account: &AccountId,
    contract_address: &str,
    options: ContractCallOptions<'_>,
) -> String {
    let mut entries = vec![
        crate::json_entry("authority", account.clone()),
        crate::json_entry("contract_address", contract_address),
    ];
    entries.push(crate::json_entry("entrypoint", options.entrypoint));
    if let Some(value) = options.payload {
        entries.push(crate::json_entry("payload", value.clone()));
    }
    entries.push(crate::json_entry(
        "fee_payment",
        iroha_data_model::transaction::FeePaymentIntent::authority(
            Vec::new(),
            NonZeroU64::new(options.gas_limit),
        ),
    ));
    let value = crate::json_object(entries);
    norito::json::to_json(&value).expect("serialize contract call request")
}
/// Build JSON string for contract view request body.
pub fn contract_view_request_json(
    account: &AccountId,
    contract_address: &str,
    options: ContractViewOptions<'_>,
) -> String {
    let mut entries = vec![
        crate::json_entry("authority", account.clone()),
        crate::json_entry("contract_address", contract_address),
    ];
    entries.push(crate::json_entry("entrypoint", options.entrypoint));
    if let Some(value) = options.payload {
        entries.push(crate::json_entry("payload", value.clone()));
    }
    entries.push(crate::json_entry("gas_limit", options.gas_limit));
    let value = crate::json_object(entries);
    norito::json::to_json(&value).expect("serialize contract view request")
}
/// Build a minimal actual configuration root suitable for constructing Kiso and Torii in tests.
///
/// The configuration mirrors the helpers used across integration tests and sets required
/// fields for `Genesis`, `Torii`, and `Sumeragi` to current structures. Durable paths initialized
/// by the minimal Torii router are rooted under the active test data directory so construction
/// cannot write to the process current directory.
pub fn mk_minimal_root_cfg() -> iroha_config::parameters::actual::Root {
    use iroha_config::{
        base::WithOrigin,
        parameters::{actual as A, defaults},
    };
    use iroha_crypto::{
        soranet::handshake::{
            DEFAULT_CLIENT_CAPABILITIES, DEFAULT_DESCRIPTOR_COMMIT, DEFAULT_RELAY_CAPABILITIES,
        },
        streaming::StreamingKeyMaterial,
    };
    use iroha_data_model::peer::Peer;
    use iroha_logger::Level;
    use iroha_primitives::addr::socket_addr;
    let torii_data_dir = crate::data_dir::base_dir();
    let mut da_ingest = A::DaIngest::default();
    da_ingest.replay_cache_store_dir = torii_data_dir.join("da_replay");
    da_ingest.manifest_store_dir = torii_data_dir.join("da_manifests");
    let mut sorafs_storage = A::SorafsStorage::default();
    sorafs_storage.data_dir = torii_data_dir.join("sorafs");
    let mut sorafs_por = A::SorafsPor::default();
    let sorafs_por_state_dir = sorafs_storage.data_dir.join("por");
    sorafs_por.state_dir = sorafs_por_state_dir.clone();
    sorafs_por.drand.state_path =
        sorafs_por_state_dir.join(defaults::sorafs::por::DRAND_STATE_FILE);
    sorafs_por.vrf_state_path = sorafs_por_state_dir.join(defaults::sorafs::por::VRF_STATE_FILE);
    A::Root {
        sccp: A::SccpNode::default(),
        common: A::Common {
            chain: ChainId::from("test-chain"),
            key_pair: checked_random_keypair("minimal root node key fixture"),
            soranet_transport_key_pair: KeyPair::try_from_seed(
                b"iroha:torii:test-utils:soranet-transport:v1".to_vec(),
                Algorithm::Ed25519,
            )
            .expect("minimal root SoraNet transport key fixture"),
            peer: Peer::new(
                socket_addr!(127.0.0.1:0),
                checked_random_keypair("minimal root peer public key fixture")
                    .public_key()
                    .clone(),
            ),
            trusted_peers: WithOrigin::inline(A::TrustedPeers {
                myself: Peer::new(
                    socket_addr!(127.0.0.1:0),
                    checked_random_keypair("minimal root trusted peer fixture")
                        .public_key()
                        .clone(),
                ),
                others: iroha_primitives::unique_vec::UniqueVec::new(),
                pops: std::collections::BTreeMap::new(),
            }),
            chain_discriminant: WithOrigin::inline(defaults::common::chain_discriminant()),
        },
        runtime_provider_broker: A::RuntimeProviderBroker {
                observer_operation_timeout: defaults::runtime_provider_broker::OBSERVER_OPERATION_TIMEOUT,
                credential_max_memory_bytes: iroha_config::parameters::defaults::runtime_provider_broker::CREDENTIAL_MAX_MEMORY_BYTES,
            endpoint_path: A::RuntimeProviderBrokerEndpointPath::try_new(
                defaults::runtime_provider_broker::endpoint_path(),
            )
            .expect("default runtime-provider broker endpoint is valid"),
        },
        network: A::Network {
            address: WithOrigin::inline(socket_addr!(127.0.0.1:0)),
            public_address: WithOrigin::inline(socket_addr!(127.0.0.1:0)),
            relay_mode: A::RelayMode::Disabled,
            relay_hub_addresses: Vec::new(),
            relay_ttl: defaults::network::RELAY_TTL,
            soranet_handshake: A::SoranetHandshake {
                descriptor_commit: WithOrigin::inline(DEFAULT_DESCRIPTOR_COMMIT.to_vec()),
                client_capabilities: WithOrigin::inline(DEFAULT_CLIENT_CAPABILITIES.to_vec()),
                relay_capabilities: WithOrigin::inline(DEFAULT_RELAY_CAPABILITIES.to_vec()),
                trust_gossip: defaults::network::TRUST_GOSSIP,
                kem_id: 1,
                sig_id: 1,
                resume_hash: None,
                pow: A::SoranetPow::default(),
            },
            soranet_privacy: A::SoranetPrivacy::default(),
            soranet_vpn: A::SoranetVpn::default(),
            lane_profile: A::LaneProfile::parse_label(
                &defaults::network::lane_profile::default_label(),
            )
            .expect("default network lane profile must be canonical"),
            require_sm_handshake_match: true,
            require_sm_openssl_preview_match: true,
            idle_timeout: core::time::Duration::from_secs(5),
            preauth_timeout: defaults::network::PREAUTH_TIMEOUT,
            preauth_max_connections_per_ip:
                defaults::network::PREAUTH_MAX_CONNECTIONS_PER_IP,
            reply_writer_flush_timeout: defaults::network::REPLY_WRITER_FLUSH_TIMEOUT,
            connect_startup_delay: defaults::network::CONNECT_STARTUP_DELAY,
            dial_timeout: defaults::network::DIAL_TIMEOUT,
            deferred_send_ttl: core::time::Duration::from_millis(
                defaults::network::DEFERRED_SEND_TTL_MS,
            ),
            deferred_send_max_per_peer: defaults::network::DEFERRED_SEND_MAX_PER_PEER,
            deferred_send_max_bytes_per_peer:
                defaults::network::DEFERRED_SEND_MAX_BYTES_PER_PEER,
            deferred_send_max_bytes_total: iroha_config::parameters::defaults::network::DEFERRED_SEND_MAX_BYTES_TOTAL,
            peer_gossip_period: defaults::network::PEER_GOSSIP_PERIOD,
            peer_gossip_max_period: defaults::network::PEER_GOSSIP_PERIOD,
            trust_gossip: defaults::network::TRUST_GOSSIP,
            trust_decay_half_life: defaults::network::TRUST_DECAY_HALF_LIFE,
            trust_penalty_bad_gossip: defaults::network::TRUST_PENALTY_BAD_GOSSIP,
            trust_penalty_unknown_peer: defaults::network::TRUST_PENALTY_UNKNOWN_PEER,
            trust_min_score: defaults::network::TRUST_MIN_SCORE,
            dns_refresh_interval: None,
            dns_refresh_ttl: None,
            p2p_proxy: None,
            p2p_proxy_required: false,
            p2p_no_proxy: Vec::new(),
            outbound_dial_allow_cidrs: Vec::new(),
            outbound_dial_deny_cidrs: Vec::new(),
            outbound_dial_allow_dns_suffixes: Vec::new(),
            outbound_dial_deny_dns_suffixes: Vec::new(),
            p2p_proxy_tls_verify: true,
            p2p_proxy_tls_pinned_cert_der_base64: None,
            quic_enabled: false,
            quic_datagrams_enabled: defaults::network::QUIC_DATAGRAMS_ENABLED,
            quic_datagram_max_payload_bytes: defaults::network::QUIC_DATAGRAM_MAX_PAYLOAD_BYTES
                .get(),
            quic_datagram_receive_buffer_bytes:
                defaults::network::QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES.get(),
            quic_datagram_send_buffer_bytes: defaults::network::QUIC_DATAGRAM_SEND_BUFFER_BYTES
                .get(),
            p2p_queue_cap_high: nonzero!(128usize),
            p2p_queue_cap_low: nonzero!(512usize),
            p2p_post_queue_cap: nonzero!(128usize),
            p2p_outbound_frame_queue_max_high_bytes:
                defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES,
            p2p_outbound_frame_queue_max_low_bytes:
                defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES,
            p2p_outbound_frame_queue_max_high_frames:
                defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_FRAMES,
            p2p_outbound_frame_queue_max_low_frames:
                defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_FRAMES,
            p2p_subscriber_queue_cap: defaults::network::P2P_SUBSCRIBER_QUEUE_CAP,
            consensus_ingress_rate_per_sec: defaults::network::CONSENSUS_INGRESS_RATE_PER_SEC,
            consensus_ingress_burst: defaults::network::CONSENSUS_INGRESS_BURST,
            consensus_ingress_bytes_per_sec: defaults::network::CONSENSUS_INGRESS_BYTES_PER_SEC,
            consensus_ingress_bytes_burst: defaults::network::CONSENSUS_INGRESS_BYTES_BURST,
            consensus_ingress_critical_rate_per_sec:
                defaults::network::CONSENSUS_INGRESS_CRITICAL_RATE_PER_SEC,
            consensus_ingress_critical_burst: defaults::network::CONSENSUS_INGRESS_CRITICAL_BURST,
            consensus_ingress_critical_bytes_per_sec:
                defaults::network::CONSENSUS_INGRESS_CRITICAL_BYTES_PER_SEC,
            consensus_ingress_critical_bytes_burst:
                defaults::network::CONSENSUS_INGRESS_CRITICAL_BYTES_BURST,
            consensus_ingress_penalty_threshold:
                defaults::network::CONSENSUS_INGRESS_PENALTY_THRESHOLD,
            consensus_ingress_penalty_window: Duration::from_millis(
                defaults::network::CONSENSUS_INGRESS_PENALTY_WINDOW_MS,
            ),
            consensus_ingress_penalty_cooldown: Duration::from_millis(
                defaults::network::CONSENSUS_INGRESS_PENALTY_COOLDOWN_MS,
            ),
            happy_eyeballs_stagger: core::time::Duration::from_millis(100),
            addr_ipv6_first: false,
            max_incoming: None,
            max_total_connections: None,
            accept_rate_per_ip_per_sec: None,
            accept_burst_per_ip: None,
            max_accept_buckets: defaults::network::MAX_ACCEPT_BUCKETS,
            accept_bucket_idle: defaults::network::ACCEPT_BUCKET_IDLE,
            accept_prefix_v4_bits: defaults::network::ACCEPT_PREFIX_V4_BITS,
            accept_prefix_v6_bits: defaults::network::ACCEPT_PREFIX_V6_BITS,
            accept_rate_per_prefix_per_sec: None,
            accept_burst_per_prefix: None,
            low_priority_rate_per_sec: None,
            low_priority_burst: None,
            low_priority_bytes_per_sec: None,
            low_priority_bytes_burst: None,
            allowlist_only: false,
            allow_keys: Vec::new(),
            deny_keys: Vec::new(),
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            disconnect_on_post_overflow: false,
            // The encrypted cap must cover every plaintext topic plus nonce/tag bytes.
            max_frame_bytes: 512 * 1024 + defaults::network::DEFAULT_AEAD_FRAME_OVERHEAD_BYTES,
            tcp_nodelay: true,
            tcp_keepalive: None,
            max_frame_bytes_consensus: 128 * 1024,
            max_frame_bytes_control: 128 * 1024,
            max_frame_bytes_block_sync: 512 * 1024,
            max_frame_bytes_tx_gossip: 128 * 1024,
            max_frame_bytes_peer_gossip: 64 * 1024,
            max_frame_bytes_health: 32 * 1024,
            max_frame_bytes_connect: iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONNECT.get(),
            max_frame_bytes_other: 128 * 1024,
            quic_max_idle_timeout: None,
        },
        genesis: A::Genesis {
            public_key: checked_random_keypair("minimal root genesis public key fixture")
                .public_key()
                .clone(),
            file: None,
            manifest_json: None,
            expected_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"Torii test genesis trust anchor",
            )),
        },
        torii: A::Torii {
            address: WithOrigin::inline(socket_addr!(127.0.0.1:0)),
            max_content_len: (1_048_576u64).into(),
            data_dir: torii_data_dir,
            receipt_signer: None,
            transport: A::ToriiTransport::default(),
            mcp: A::ToriiMcp::default(),
            cors: A::ToriiCors::default(),
            ram_lfe: None,
            faucet: None,
            tx_history: None,
            recipient_lookup: Default::default(),
            kagemusha_enrollment: None,
            public_dataspace_upstreams: Vec::new(),
            webhooks_enabled: defaults::torii::WEBHOOKS_ENABLED,
            zk_attachments_enabled: defaults::torii::ZK_ATTACHMENTS_ENABLED,
            events_buffer_capacity: defaults::torii::events_buffer_capacity(),
            ws_message_timeout: Duration::from_millis(defaults::torii::WS_MESSAGE_TIMEOUT_MS),
            query_rate_per_authority_per_sec: None,
            query_burst_per_authority: None,
            query_max_inflight: defaults::torii::QUERY_MAX_INFLIGHT,
            query_heavy_max_inflight: defaults::torii::QUERY_HEAVY_MAX_INFLIGHT,
            query_fanout_max_working_set_bytes:
                defaults::torii::QUERY_FANOUT_MAX_WORKING_SET_BYTES,
            sccp_history_cache_max_bytes: defaults::torii::SCCP_HISTORY_CACHE_MAX_BYTES,
            query_fanout_max_retained_bytes:
                defaults::torii::QUERY_FANOUT_MAX_RETAINED_BYTES,
            query_queue_timeout: Duration::from_millis(defaults::torii::QUERY_QUEUE_TIMEOUT_MS),
            tx_rate_per_authority_per_sec: None,
            tx_burst_per_authority: None,
            deploy_rate_per_origin_per_sec: None,
            deploy_burst_per_origin: None,
            soracloud_public_rate_per_ip_per_sec:
                iroha_config::parameters::defaults::torii::SORACLOUD_PUBLIC_RATE_PER_IP_PER_SEC
                    .and_then(std::num::NonZeroU32::new),
            soracloud_public_burst_per_ip:
                iroha_config::parameters::defaults::torii::SORACLOUD_PUBLIC_BURST_PER_IP
                    .and_then(std::num::NonZeroU32::new),
            soracloud_public_max_inflight:
                iroha_config::parameters::defaults::torii::SORACLOUD_PUBLIC_MAX_INFLIGHT,
            soracloud_public_max_response_bytes:
                iroha_config::parameters::defaults::torii::SORACLOUD_PUBLIC_MAX_RESPONSE_BYTES,
            soracloud_mutation_rate_per_account_origin_per_sec:
                iroha_config::parameters::defaults::torii::SORACLOUD_MUTATION_RATE_PER_ACCOUNT_ORIGIN_PER_SEC
                    .and_then(std::num::NonZeroU32::new),
            soracloud_mutation_burst_per_account_origin:
                iroha_config::parameters::defaults::torii::SORACLOUD_MUTATION_BURST_PER_ACCOUNT_ORIGIN
                    .and_then(std::num::NonZeroU32::new),
            soracloud_mutation_max_inflight:
                iroha_config::parameters::defaults::torii::SORACLOUD_MUTATION_MAX_INFLIGHT,
            soracloud_mutation_max_body_bytes:
                iroha_config::parameters::defaults::torii::SORACLOUD_MUTATION_MAX_BODY_BYTES,
            proof_api: iroha_config::parameters::actual::ProofApi {
                rate_per_minute: defaults::torii::PROOF_RATE_PER_MIN
                    .and_then(std::num::NonZeroU32::new),
                burst: defaults::torii::PROOF_BURST.and_then(std::num::NonZeroU32::new),
                max_body_bytes: defaults::torii::PROOF_MAX_BODY_BYTES,
                body_max_inflight: defaults::torii::PROOF_BODY_MAX_INFLIGHT,
                body_read_timeout: std::time::Duration::from_millis(
                    defaults::torii::PROOF_BODY_READ_TIMEOUT_MS,
                ),
                egress_bytes_per_sec: defaults::torii::PROOF_EGRESS_BYTES_PER_SEC
                    .and_then(std::num::NonZeroU64::new),
                egress_burst_bytes: defaults::torii::PROOF_EGRESS_BURST_BYTES
                    .and_then(std::num::NonZeroU64::new),
                max_list_limit: std::num::NonZeroU32::new(
                    defaults::torii::PROOF_MAX_LIST_LIMIT.max(1),
                )
                .expect("proof page limit must be non-zero"),
                request_timeout: std::time::Duration::from_millis(
                    defaults::torii::PROOF_REQUEST_TIMEOUT_MS,
                ),
                cache_max_age: std::time::Duration::from_secs(
                    defaults::torii::PROOF_CACHE_MAX_AGE_SECS,
                ),
                retry_after: std::time::Duration::from_secs(
                    defaults::torii::PROOF_RETRY_AFTER_SECS,
                ),
            },
            require_api_token: false,
            api_tokens: Vec::new().into(),
            api_fee_asset_id: None,
            api_fee_amount: None,
            api_fee_receiver: None,
            api_rate_limit_bypass_cidrs: Vec::new(),
            internal_api_trusted_cidrs:
                iroha_config::parameters::defaults::torii::internal_api_trusted_cidrs(),
            peer_telemetry_urls: Vec::new(),
            peer_geo: A::ToriiPeerGeo::default(),
            soranet_privacy_ingest: A::SoranetPrivacyIngest::default(),
            privacy_bootle_lantern_issuer: None,
            debug_match_filters: false,
            operator_auth: A::ToriiOperatorAuth::default(),
            operator_signatures: A::ToriiOperatorSignatures::default(),
            preauth_max_connections: None,
            preauth_max_connections_per_ip: None,
            preauth_rate_per_ip_per_sec: None,
            preauth_burst_per_ip: None,
            preauth_temp_ban: None,
            preauth_ban_capacity: defaults::torii::PREAUTH_BAN_CAPACITY,
            preauth_allow_cidrs: Vec::new(),
            preauth_scheme_limits: Vec::new(),
            api_high_load_tx_threshold: None,
            api_high_load_stream_threshold: None,
            api_high_load_subscription_threshold: None,
            app_api: iroha_config::parameters::actual::AppApi {
                default_list_limit: std::num::NonZeroU32::new(
                    defaults::torii::APP_API_DEFAULT_LIST_LIMIT.max(1),
                )
                .expect("default list limit must be non-zero"),
                max_list_limit: std::num::NonZeroU32::new(
                    defaults::torii::APP_API_MAX_LIST_LIMIT.max(1),
                )
                .expect("max list limit must be non-zero"),
                max_fetch_size: std::num::NonZeroU32::new(
                    defaults::torii::APP_API_MAX_FETCH_SIZE.max(1),
                )
                .expect("max fetch size must be non-zero"),
                rate_limit_cost_per_page: std::num::NonZeroU32::new(
                    defaults::torii::APP_API_RATE_LIMIT_COST_PER_PAGE.max(1),
                )
                .expect("rate limit cost must be non-zero"),
                request_signature_max_clock_skew: std::time::Duration::from_secs(
                    defaults::torii::app_auth::MAX_CLOCK_SKEW_SECS,
                ),
                request_signature_nonce_ttl: std::time::Duration::from_secs(
                    defaults::torii::app_auth::NONCE_TTL_SECS,
                ),
                request_signature_replay_cache_capacity: std::num::NonZeroUsize::new(
                    defaults::torii::app_auth::REPLAY_CACHE_CAPACITY.max(1),
                )
                .expect("request signature replay cache must be non-zero"),
            },
            app_api_routed_read_body_read_timeout: Duration::from_millis(
                defaults::torii::APP_API_ROUTED_READ_BODY_READ_TIMEOUT_MS,
            ),
            attachments_ttl_secs: 7 * 24 * 60 * 60,
            attachments_max_bytes: 4 * 1024 * 1024,
            attachments_per_tenant_max_count: defaults::torii::ATTACHMENTS_PER_TENANT_MAX_COUNT,
            attachments_per_tenant_max_bytes: defaults::torii::ATTACHMENTS_PER_TENANT_MAX_BYTES,
            attachments_global_max_count: defaults::torii::ATTACHMENTS_GLOBAL_MAX_COUNT,
            attachments_global_max_bytes: defaults::torii::ATTACHMENTS_GLOBAL_MAX_BYTES,
            attachments_allowed_mime_types: defaults::torii::attachments_allowed_mime_types(),
            attachments_max_expanded_bytes: defaults::torii::ATTACHMENTS_MAX_EXPANDED_BYTES,
            attachments_max_archive_depth: defaults::torii::ATTACHMENTS_MAX_ARCHIVE_DEPTH,
            attachments_sanitizer_mode:
                iroha_config::parameters::actual::AttachmentSanitizerMode::Subprocess,
            attachments_sanitize_timeout_ms: defaults::torii::ATTACHMENTS_SANITIZE_TIMEOUT_MS,
            webhook: iroha_config::parameters::actual::Webhook {
                queue_capacity: defaults::torii::webhook_queue_capacity(),
                max_attempts: defaults::torii::webhook_max_attempts(),
                backoff_initial: std::time::Duration::from_millis(
                    defaults::torii::WEBHOOK_BACKOFF_INITIAL_MS,
                ),
                backoff_max: std::time::Duration::from_millis(
                    defaults::torii::WEBHOOK_BACKOFF_MAX_MS,
                ),
                connect_timeout: std::time::Duration::from_millis(
                    defaults::torii::WEBHOOK_CONNECT_TIMEOUT_MS,
                ),
                write_timeout: std::time::Duration::from_millis(
                    defaults::torii::WEBHOOK_WRITE_TIMEOUT_MS,
                ),
                read_timeout: std::time::Duration::from_millis(
                    defaults::torii::WEBHOOK_READ_TIMEOUT_MS,
                ),
            },
            webhook_security: A::WebhookSecurity::default(),
            push: iroha_config::parameters::actual::Push::default(),
            zk_prover_enabled: false,
            zk_prover_scan_period_secs: 30,
            zk_prover_reports_ttl_secs: 7 * 24 * 60 * 60,
            zk_prover_reports_max_count:
                iroha_config::parameters::defaults::torii::ZK_PROVER_REPORTS_MAX_COUNT,
            zk_prover_reports_max_bytes:
                iroha_config::parameters::defaults::torii::ZK_PROVER_REPORTS_MAX_BYTES,
            zk_prover_max_inflight: defaults::torii::ZK_PROVER_MAX_INFLIGHT,
            zk_prover_max_scan_bytes: defaults::torii::ZK_PROVER_MAX_SCAN_BYTES,
            zk_prover_max_scan_millis: defaults::torii::ZK_PROVER_MAX_SCAN_MILLIS,
            zk_prover_keys_dir: defaults::torii::zk_prover_keys_dir(),
            zk_prover_allowed_backends: defaults::torii::zk_prover_allowed_backends(),
            zk_prover_allowed_circuits: defaults::torii::zk_prover_allowed_circuits(),
            ivm_tooling_max_inflight: defaults::torii::IVM_TOOLING_MAX_INFLIGHT,
            ivm_tooling_timeout_ms: defaults::torii::IVM_TOOLING_TIMEOUT_MS,
            transaction_ingress: A::TransactionIngress::default(),
            da_ingest,
            connect: A::Connect {
                enabled: false,
                ws_max_sessions: defaults::connect::WS_MAX_SESSIONS,
                ws_per_ip_max_sessions: defaults::connect::WS_PER_IP_MAX_SESSIONS,
                ws_rate_per_ip_per_min: defaults::connect::WS_RATE_PER_IP_PER_MIN,
                session_ttl: defaults::connect::SESSION_TTL,
                frame_max_bytes: defaults::connect::FRAME_MAX_BYTES,
                session_buffer_max_bytes: defaults::connect::SESSION_BUFFER_MAX_BYTES,
                ping_interval: defaults::connect::PING_INTERVAL,
                ping_miss_tolerance: defaults::connect::PING_MISS_TOLERANCE,
                ping_min_interval: defaults::connect::PING_MIN_INTERVAL,
                dedupe_ttl: defaults::connect::DEDUPE_TTL,
                dedupe_cap: defaults::connect::DEDUPE_CAP,
                relay_enabled: defaults::connect::RELAY_ENABLED,
                relay_strategy: A::ConnectRelayStrategy::Broadcast,
                p2p_ttl_hops: defaults::connect::P2P_TTL_HOPS,
            },
            iso_bridge: A::IsoBridge {
                enabled: false,
                max_body_bytes: defaults::torii::ISO_BRIDGE_MAX_BODY_BYTES,
                dedupe_ttl_secs: defaults::torii::ISO_BRIDGE_DEDUPE_TTL_SECS,
                default_profile: defaults::torii::ISO_BRIDGE_DEFAULT_PROFILE.to_owned(),
                profiles: Vec::new(),
                store_dir: None,
                store_retention_secs: defaults::torii::ISO_BRIDGE_STORE_RETENTION_SECS,
                store_max_records: defaults::torii::ISO_BRIDGE_STORE_MAX_RECORDS,
                audit_export_dir: None,
                embedded_signature_policy: None,
                signer: None,
                participants: Vec::new(),
                audit_admin_keys: Vec::new(),
                account_aliases: Vec::new(),
                currency_assets: Vec::new(),
                reference_data: Default::default(),
            },
            sorafs_discovery: Default::default(),
            sorafs_storage,
            sorafs_repair: Default::default(),
            sorafs_gc: Default::default(),
            sorafs_quota: Default::default(),
            sorafs_alias_cache: Default::default(),
            sorafs_gateway: A::SorafsGateway {
                enforce_capabilities: false,
                enforce_admission: false,
                require_manifest_envelope: false,
                ..Default::default()
            },
            sorafs_por,
            sorafs_appeal_finance_settlement: Default::default(),
            account_onboarding: None,
        },
        soracloud_runtime: A::SoracloudRuntime::default(),
        musubi_publication: A::MusubiPublication::default(),
        kura: A::Kura { init_mode: iroha_config::kura::InitMode::Strict, store_dir: WithOrigin::inline(std::env::temp_dir()),
            max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: nonzero!(10usize),
            debug_output_new_blocks: false,
            fsync_mode: defaults::kura::FSYNC_MODE,
            fsync_interval: defaults::kura::FSYNC_INTERVAL,

            native_context_archive_max_bytes: iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity: iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes: iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes: iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
        },
        sumeragi: A::Sumeragi::default(),
        block_sync: A::BlockSync {
            gossip_period: core::time::Duration::from_millis(200),
            gossip_max_period: core::time::Duration::from_millis(200),
            gossip_size: nonzero!(32u32),
        },
        transaction_gossiper: A::TransactionGossiper {
            gossip_period: core::time::Duration::from_millis(200),
            gossip_size: nonzero!(32u32),
            gossip_resend_ticks: defaults::network::TRANSACTION_GOSSIP_RESEND_TICKS,
            dataspace: Default::default(),
        },
        live_query_store: A::LiveQueryStore::default(),
        logger: A::Logger {
            level: Level::INFO,
            filter: None,
            format: iroha_config::logger::Format::default(),
            terminal_colors: false,
        },
        queue: A::Queue::default(),
        nexus: A::Nexus::default(),
        snapshot: iroha_config::parameters::user::Snapshot {
            mode: iroha_config::snapshot::Mode::Disabled,
            create_every_ms: iroha_config::base::util::DurationMs(core::time::Duration::from_secs(
                60,
            )),
            store_dir: WithOrigin::inline(std::env::temp_dir()),
            merkle_chunk_size_bytes: defaults::snapshot::MERKLE_CHUNK_SIZE_BYTES,
            max_payload_bytes: defaults::snapshot::MAX_PAYLOAD_BYTES,
            max_read_buffer_bytes: defaults::snapshot::MAX_READ_BUFFER_BYTES,
            resources: Default::default(),
            verification_public_key: None,
            signing_private_key: None,
        },
        telemetry_profile: A::TelemetryProfile::Disabled,
        telemetry: None,
        telemetry_integrity: A::TelemetryIntegrity::default(),
        dev_telemetry: iroha_config::parameters::user::DevTelemetry {
            out_file: None,
            panic_on_duplicate_metrics: defaults::telemetry::PANIC_ON_DUPLICATE_METRICS,
        },
        pipeline: A::Pipeline {
            dynamic_prepass: false,
            access_set_cache_enabled: defaults::pipeline::ACCESS_SET_CACHE_ENABLED,
            parallel_overlay: false,
            workers: defaults::pipeline::WORKERS,
            stateless_cache_cap: defaults::pipeline::STATELESS_CACHE_CAP,
            parallel_apply: true,
            ready_queue_heap: defaults::pipeline::READY_QUEUE_HEAP,
            gpu_key_bucket: defaults::pipeline::GPU_KEY_BUCKET,
            debug_trace_scheduler_inputs: defaults::pipeline::DEBUG_TRACE_SCHEDULER_INPUTS,
            debug_trace_tx_eval: defaults::pipeline::DEBUG_TRACE_TX_EVAL,
            signature_batch_max_ed25519: defaults::pipeline::SIGNATURE_BATCH_MAX_ED25519,
            signature_batch_max_secp256k1: defaults::pipeline::SIGNATURE_BATCH_MAX_SECP256K1,
            signature_batch_max_pqc: defaults::pipeline::SIGNATURE_BATCH_MAX_PQC,
            signature_batch_max_bls: defaults::pipeline::SIGNATURE_BATCH_MAX_BLS,
            cache_size: defaults::pipeline::CACHE_SIZE,
            ivm_cache_max_decoded_ops: defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
            ivm_cache_max_bytes: defaults::pipeline::IVM_CACHE_MAX_BYTES,
            ivm_execution_max_bytes: defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ivm_prover_threads: defaults::pipeline::IVM_PROVER_THREADS,
            overlay_max_instructions: defaults::pipeline::OVERLAY_MAX_INSTRUCTIONS,
            overlay_max_bytes: defaults::pipeline::OVERLAY_MAX_BYTES,
            overlay_chunk_instructions: defaults::pipeline::OVERLAY_CHUNK_INSTRUCTIONS,
            gas: A::Gas {
                tech_account_id: defaults::pipeline::GAS_TECH_ACCOUNT_ID.to_string(),
                accepted_assets: Vec::new(),
                units_per_gas: Vec::new(),
            },
            ivm_max_cycles_upper_bound: defaults::pipeline::IVM_MAX_CYCLES_UPPER_BOUND,
            ivm_max_decoded_instructions: defaults::pipeline::IVM_MAX_DECODED_INSTRUCTIONS,
            ivm_max_decoded_bytes: defaults::pipeline::IVM_MAX_DECODED_BYTES,
            quarantine_max_txs_per_block: defaults::pipeline::QUARANTINE_MAX_TXS_PER_BLOCK,
            quarantine_tx_max_cycles: defaults::pipeline::QUARANTINE_TX_MAX_CYCLES,
            query_default_cursor_mode: A::QueryCursorMode::Ephemeral,
            query_max_fetch_size: defaults::pipeline::QUERY_MAX_FETCH_SIZE,
            query_stored_min_gas_units: 0,
            amx_per_dataspace_budget_ms: defaults::pipeline::AMX_PER_DATASPACE_BUDGET_MS,
            amx_group_budget_ms: defaults::pipeline::AMX_GROUP_BUDGET_MS,
            amx_per_instruction_ns: defaults::pipeline::AMX_PER_INSTRUCTION_NS,
            amx_per_memory_access_ns: defaults::pipeline::AMX_PER_MEMORY_ACCESS_NS,
            amx_per_syscall_ns: defaults::pipeline::AMX_PER_SYSCALL_NS,
        },
        tiered_state: A::TieredState {
            enabled: defaults::tiered_state::ENABLED,
            hot_retained_keys: defaults::tiered_state::HOT_RETAINED_KEYS,
            hot_retained_bytes: defaults::tiered_state::HOT_RETAINED_BYTES,
            hot_retained_grace_snapshots: defaults::tiered_state::HOT_RETAINED_GRACE_SNAPSHOTS,
            cold_store_root: None,
            da_store_root: None,
            max_snapshots: defaults::tiered_state::MAX_SNAPSHOTS,
            max_cold_bytes: defaults::tiered_state::MAX_COLD_BYTES,
        },
        compute: A::Compute {
            enabled: defaults::compute::ENABLED,
            namespaces: defaults::compute::default_namespaces()
                .into_iter()
                .collect(),
            default_ttl_slots: defaults::compute::default_ttl_slots(),
            max_ttl_slots: defaults::compute::max_ttl_slots(),
            max_request_bytes: defaults::compute::MAX_REQUEST_BYTES,
            max_response_bytes: defaults::compute::MAX_RESPONSE_BYTES,
            max_gas_per_call: defaults::compute::max_gas_per_call(),
            resource_profiles: defaults::compute::resource_profiles(),
            default_resource_profile: defaults::compute::default_resource_profile(),
            price_families: defaults::compute::price_families(),
            default_price_family: defaults::compute::default_price_family(),
            auth_policy: defaults::compute::default_auth_policy(),
            sandbox: defaults::compute::sandbox_rules(),
            economics: A::ComputeEconomics {
                max_cu_per_call: defaults::compute::max_cu_per_call(),
                max_amplification_ratio: defaults::compute::max_amplification_ratio(),
                fee_split: defaults::compute::fee_split(),
                sponsor_policy: defaults::compute::sponsor_policy(),
                price_bounds: defaults::compute::price_bounds(),
                price_risk_classes: defaults::compute::price_risk_classes(),
                price_family_baseline: defaults::compute::price_families(),
                price_amplifiers: defaults::compute::price_amplifiers(),
            },
            slo: A::ComputeSlo {
                max_inflight_per_route: defaults::compute::max_inflight_per_route(),
                queue_depth_per_route: defaults::compute::queue_depth_per_route(),
                max_requests_per_second: defaults::compute::max_requests_per_second(),
                target_p50_latency_ms: defaults::compute::target_p50_latency_ms(),
                target_p95_latency_ms: defaults::compute::target_p95_latency_ms(),
                target_p99_latency_ms: defaults::compute::target_p99_latency_ms(),
            },
        },
        content: A::Content {
            max_bundle_bytes: defaults::content::MAX_BUNDLE_BYTES,
            max_files: defaults::content::MAX_FILES,
            max_path_len: defaults::content::MAX_PATH_LEN,
            max_retention_blocks: defaults::content::MAX_RETENTION_BLOCKS,
            chunk_size_bytes: defaults::content::CHUNK_SIZE_BYTES,
            publish_allow_accounts: Vec::new(),
            limits: A::ContentLimits {
                max_requests_per_second: nonzero!(defaults::content::MAX_REQUESTS_PER_SECOND),
                request_burst: nonzero!(defaults::content::REQUEST_BURST),
                max_egress_bytes_per_second: NonZeroU64::new(
                    defaults::content::MAX_EGRESS_BYTES_PER_SECOND as u64,
                )
                .expect("default egress limit"),
                egress_burst_bytes: NonZeroU64::new(defaults::content::EGRESS_BURST_BYTES)
                    .expect("default egress burst"),
            },
            default_cache_max_age_secs: defaults::content::DEFAULT_CACHE_MAX_AGE_SECS,
            max_cache_max_age_secs: defaults::content::MAX_CACHE_MAX_AGE_SECS,
            immutable_bundles: defaults::content::IMMUTABLE_BUNDLES,
            default_auth_mode: ContentAuthMode::Public,
            slo: A::ContentSlo {
                target_p50_latency_ms: nonzero!(defaults::content::TARGET_P50_LATENCY_MS),
                target_p99_latency_ms: nonzero!(defaults::content::TARGET_P99_LATENCY_MS),
                target_availability_bps: nonzero!(defaults::content::TARGET_AVAILABILITY_BPS),
            },
            pow: A::ContentPow {
                difficulty_bits: defaults::content::POW_DIFFICULTY_BITS,
                header_name: defaults::content::default_pow_header(),
            },
            stripe_layout: defaults::content::default_stripe_layout(),
        },
        oracle: A::Oracle {
            history_depth: defaults::oracle::history_depth(),
            economics: A::OracleEconomics {
                reward_asset: defaults::oracle::reward_asset(),
                reward_pool: defaults::oracle::reward_pool(),
                reward_amount: defaults::oracle::reward_amount(),
                slash_asset: defaults::oracle::slash_asset(),
                slash_receiver: defaults::oracle::slash_receiver(),
                slash_outlier_amount: defaults::oracle::slash_outlier_amount(),
                slash_error_amount: defaults::oracle::slash_error_amount(),
                slash_no_show_amount: defaults::oracle::slash_no_show_amount(),
                dispute_bond_asset: defaults::oracle::dispute_bond_asset(),
                dispute_bond_amount: defaults::oracle::dispute_bond_amount(),
                dispute_reward_amount: defaults::oracle::dispute_reward_amount(),
                frivolous_slash_amount: defaults::oracle::frivolous_slash_amount(),
            },
            governance: A::OracleGovernance {
                intake_sla_blocks: defaults::oracle::intake_sla_blocks(),
                rules_sla_blocks: defaults::oracle::rules_sla_blocks(),
                cop_sla_blocks: defaults::oracle::cop_sla_blocks(),
                technical_sla_blocks: defaults::oracle::technical_sla_blocks(),
                policy_jury_sla_blocks: defaults::oracle::policy_jury_sla_blocks(),
                enact_sla_blocks: defaults::oracle::enact_sla_blocks(),
                intake_min_votes: defaults::oracle::intake_min_votes(),
                rules_min_votes: defaults::oracle::rules_min_votes(),
                cop_min_votes: A::OracleChangeThresholds {
                    low: defaults::oracle::cop_low_votes(),
                    medium: defaults::oracle::cop_medium_votes(),
                    high: defaults::oracle::cop_high_votes(),
                },
                technical_min_votes: defaults::oracle::technical_min_votes(),
                policy_jury_min_votes: A::OracleChangeThresholds {
                    low: defaults::oracle::policy_jury_low_votes(),
                    medium: defaults::oracle::policy_jury_medium_votes(),
                    high: defaults::oracle::policy_jury_high_votes(),
                },
            },
            twitter_binding: A::OracleTwitterBinding {
                feed_id: defaults::oracle::twitter_binding_feed_id(),
                pepper_id: defaults::oracle::twitter_binding_pepper_id(),
                max_ttl_ms: defaults::oracle::twitter_binding_max_ttl_ms(),
                min_ttl_ms: defaults::oracle::twitter_binding_min_ttl_ms(),
                min_update_spacing_ms: defaults::oracle::twitter_binding_min_update_spacing_ms(),
            },
        },
        fraud_monitoring: iroha_config::parameters::actual::FraudMonitoring::new(
            defaults::fraud_monitoring::ENABLED,
            Vec::new(),
            defaults::fraud_monitoring::CONNECT_TIMEOUT,
            defaults::fraud_monitoring::REQUEST_TIMEOUT,
            defaults::fraud_monitoring::MISSING_ASSESSMENT_GRACE_SECS,
            None,
            Vec::new(),
        ),
        zk: A::Zk {
            pipa_r: iroha_config::parameters::actual::PipaR::default(),
            trace: iroha_config::parameters::actual::DiagnosticTrace::default(),
        ipa_commitment: iroha_config::parameters::actual::IpaCommitment::default(),
            max_verify_batch: iroha_config::parameters::defaults::zk::MAX_VERIFY_BATCH,
            fastpq: A::Fastpq {
                execution_mode: A::FastpqExecutionMode::Cpu,
                poseidon_mode: A::FastpqPoseidonMode::Cpu,
                proof_sidecar_queue_cap: fastpq::PROOF_SIDECAR_QUEUE_CAP,
                proof_sidecar_max_bytes: fastpq::PROOF_SIDECAR_MAX_BYTES,
                proof_sidecar_max_retries: fastpq::PROOF_SIDECAR_MAX_RETRIES,
                device_class: None,
                chip_family: None,
                gpu_kind: None,
                metal_queue_fanout: None,
                metal_queue_column_threshold: None,
                metal_max_in_flight: fastpq::METAL_MAX_IN_FLIGHT,
                metal_threadgroup_width: fastpq::METAL_THREADGROUP_WIDTH,
                metal_trace: fastpq::METAL_TRACE,
                metal_debug_enum: fastpq::METAL_DEBUG_ENUM,
            },
            stark: A::Stark::default(),
            sccp: A::Sccp::default(),
            ballot_history_cap: defaults::zk::vote::BALLOT_HISTORY_CAP,
            preverify_max_bytes: defaults::zk::preverify::MAX_BYTES,
            preverify_budget_bytes: defaults::zk::preverify::BUDGET_BYTES,
            proof_history_cap: defaults::zk::proof::RECORD_HISTORY_CAP,
            proof_retention_grace_blocks: defaults::zk::proof::RETENTION_GRACE_BLOCKS,
            proof_prune_batch: defaults::zk::proof::PRUNE_BATCH_SIZE,
            bridge_proof_max_range_len: defaults::zk::proof::BRIDGE_MAX_RANGE_LEN,
            bridge_proof_max_past_age_blocks: defaults::zk::proof::BRIDGE_MAX_PAST_AGE_BLOCKS,
            bridge_proof_max_future_drift_blocks:
                defaults::zk::proof::BRIDGE_MAX_FUTURE_DRIFT_BLOCKS,
            poseidon_params_id: defaults::confidential::POSEIDON_PARAMS_ID,
            pedersen_params_id: defaults::confidential::PEDERSEN_PARAMS_ID,
            kaigi_authorization_vk: None,
            kaigi_usage_vk: None,
            max_proof_size_bytes: defaults::confidential::MAX_PROOF_SIZE_BYTES,
            max_nullifiers_per_tx: defaults::confidential::MAX_NULLIFIERS_PER_TX,
            max_commitments_per_tx: defaults::confidential::MAX_COMMITMENTS_PER_TX,
            max_confidential_ops_per_block: defaults::confidential::MAX_CONFIDENTIAL_OPS_PER_BLOCK,
            verify_timeout: defaults::confidential::VERIFY_TIMEOUT,
            max_anchor_age_blocks: defaults::confidential::MAX_ANCHOR_AGE_BLOCKS,
            max_proof_bytes_block: defaults::confidential::MAX_PROOF_BYTES_BLOCK,
            max_verify_calls_per_tx: defaults::confidential::MAX_VERIFY_CALLS_PER_TX,
            max_verify_calls_per_block: defaults::confidential::MAX_VERIFY_CALLS_PER_BLOCK,
            max_public_inputs: defaults::confidential::MAX_PUBLIC_INPUTS,
            reorg_depth_bound: defaults::confidential::REORG_DEPTH_BOUND,
            policy_transition_delay_blocks: defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS,
            policy_transition_window_blocks:
                defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS,
            policy_transition_max_per_height:
                defaults::confidential::POLICY_TRANSITION_MAX_PER_HEIGHT,
            tree_roots_history_len: defaults::confidential::TREE_ROOTS_HISTORY_LEN,
            tree_frontier_checkpoint_interval:
                defaults::confidential::TREE_FRONTIER_CHECKPOINT_INTERVAL,
            registry_max_vk_entries: defaults::confidential::REGISTRY_MAX_VK_ENTRIES,
            registry_max_params_entries: defaults::confidential::REGISTRY_MAX_PARAMS_ENTRIES,
            registry_max_delta_per_block: defaults::confidential::REGISTRY_MAX_DELTA_PER_BLOCK,
            gas: A::ConfidentialGas {
                proof_base: defaults::confidential::gas::PROOF_BASE,
                per_public_input: defaults::confidential::gas::PER_PUBLIC_INPUT,
                per_proof_byte: defaults::confidential::gas::PER_PROOF_BYTE,
                per_nullifier: defaults::confidential::gas::PER_NULLIFIER,
                per_commitment: defaults::confidential::gas::PER_COMMITMENT,
            },
        },
        gov: A::Governance {
            vk_ballot: None,
            vk_tally: None,
            voting_asset_id: defaults::governance::voting_asset_id()
                .parse()
                .expect("valid default governance asset id"),
            citizenship_asset_id: defaults::governance::citizenship_asset_id()
                .parse()
                .expect("valid default citizenship asset id"),
            citizenship_bond_amount: defaults::governance::CITIZENSHIP_BOND_AMOUNT.into(),
            citizenship_escrow_account: defaults::governance::citizenship_escrow_account_id(),
            min_bond_amount: 150_u64.into(),
            bond_escrow_account: defaults::governance::bond_escrow_account_id(),
            slash_receiver_account: defaults::governance::slash_receiver_account_id(),
            slash_double_vote_bps: 0,
            slash_invalid_proof_bps: 0,
            slash_ineligible_proof_bps: 0,
            sorafs_pin_policy: A::SorafsPinPolicyConstraints::default(),
            sorafs_pin_fee_asset_id: defaults::governance::sorafs_pin_fee::asset_id()
                .parse()
                .expect("valid default SoraFS pin fee asset id"),
            sorafs_pin_fee_treasury_account:
                AccountId::parse_encoded(&defaults::governance::sorafs_pin_fee::treasury_account())
                    .expect("valid default SoraFS pin fee treasury account"),
            alias_teu_minimum: defaults::governance::alias_teu_minimum(),
            alias_frontier_telemetry: defaults::governance::alias_frontier_telemetry(),
            debug_trace_pipeline: defaults::governance::DEBUG_TRACE_PIPELINE,
            jdg_signature_schemes: defaults::governance::jdg_signature_schemes()
                .into_iter()
                .map(|scheme| {
                    scheme
                        .parse::<JdgSignatureScheme>()
                        .expect("valid default JDG signature scheme")
                })
                .collect(),
            runtime_upgrade_provenance: A::RuntimeUpgradeProvenancePolicy::default(),
            sorafs_pricing: PricingScheduleRecord::launch_default(),
            sorafs_penalty: A::SorafsPenaltyPolicy::default(),
            sorafs_telemetry: A::SorafsTelemetryPolicy::default(),
            sorafs_provider_owners: BTreeMap::new(),
            conviction_step_blocks: 10,
            max_conviction: 4,
            min_enactment_delay: 0,
            window_span: 10,
            max_active_referenda: defaults::governance::MAX_ACTIVE_REFERENDA,
            max_lock_owners_per_referendum:
                defaults::governance::MAX_LOCK_OWNERS_PER_REFERENDUM,
            plain_voting_enabled: false,
            approval_threshold_q_num: 1,
            approval_threshold_q_den: 2,
            min_turnout: 0,
            parliament_alternate_size: defaults::governance::PARLIAMENT_ALTERNATE_SIZE,
            parliament_sortition_pulse_delay_blocks:
                defaults::governance::PARLIAMENT_SORTITION_PULSE_DELAY_BLOCKS,
            parliament_invitation_phase_blocks:
                defaults::governance::PARLIAMENT_INVITATION_PHASE_BLOCKS,
            parliament_public_finding_phase_blocks:
                defaults::governance::PARLIAMENT_PUBLIC_FINDING_PHASE_BLOCKS,
            parliament_timed_ovn: A::ParliamentTimedOvn::default(),
            parliament_tle_key_lifecycle: A::ParliamentTleKeyLifecycle::default(),
            parliament_tle_partial_release_signer_provider_handle: None,
            parliament_tle_partial_release_signer_provider_revision: None,
            parliament_tle_partial_release_signer_provider_policy_digest: None,
            rules_committee_size: defaults::governance::PARLIAMENT_RULES_COMMITTEE_SIZE,
            agenda_council_size: defaults::governance::PARLIAMENT_AGENDA_COUNCIL_SIZE,
            interest_panel_size: defaults::governance::PARLIAMENT_INTEREST_PANEL_SIZE,
            review_panel_size: defaults::governance::PARLIAMENT_REVIEW_PANEL_SIZE,
            coordination_council_size:
                defaults::governance::PARLIAMENT_COORDINATION_COUNCIL_SIZE,
            policy_jury_size: defaults::governance::PARLIAMENT_POLICY_JURY_SIZE,
            confirmation_jury_size: defaults::governance::PARLIAMENT_CONFIRMATION_JURY_SIZE,
            oversight_committee_size: defaults::governance::PARLIAMENT_OVERSIGHT_COMMITTEE_SIZE,
            mpc_committee_size: defaults::governance::PARLIAMENT_MPC_COMMITTEE_SIZE,
            fma_committee_size: defaults::governance::PARLIAMENT_FMA_COMMITTEE_SIZE,
            viral_incentives: A::ViralIncentives::default(),
        },
        norito: A::Norito {
            allow_gpu_compression: defaults::norito::ALLOW_GPU_COMPRESSION,
            max_archive_len: defaults::norito::MAX_ARCHIVE_LEN,
        },
        nts: A::Nts {
            sample_interval: defaults::time::NTS_SAMPLE_INTERVAL,
            sample_cap_per_round: defaults::time::NTS_SAMPLE_CAP_PER_ROUND,
            max_rtt_ms: defaults::time::NTS_MAX_RTT_MS,
            trim_percent: defaults::time::NTS_TRIM_PERCENT,
            per_peer_buffer: defaults::time::NTS_PER_PEER_BUFFER,
            smoothing_enabled: defaults::time::NTS_SMOOTHING_ENABLED,
            smoothing_alpha: defaults::time::NTS_SMOOTHING_ALPHA,
            max_adjust_ms_per_min: defaults::time::NTS_MAX_ADJUST_MS_PER_MIN,
            min_samples: defaults::time::NTS_MIN_SAMPLES,
            max_offset_ms: defaults::time::NTS_MAX_OFFSET_MS,
            max_confidence_ms: defaults::time::NTS_MAX_CONFIDENCE_MS,
            enforcement_mode: A::NtsEnforcementMode::Warn,
        },
        accel: A::Acceleration {
            resource_limits: iroha_config::parameters::defaults::accel::RESOURCE_LIMITS,
            enable_simd: false,
            enable_cuda: false,
            enable_metal: false,
            max_gpus: None,
            merkle_min_leaves_gpu: 1_000_000,
            merkle_min_leaves_metal: None,
            merkle_min_leaves_cuda: None,
            prefer_cpu_sha2_max_leaves_aarch64: None,
            prefer_cpu_sha2_max_leaves_x86: None,
        },
        ivm: A::Ivm::default(),
        concurrency: A::Concurrency {
            scheduler_min_threads: 0,
            scheduler_max_threads: 0,
            rayon_global_threads: 0,
            tokio_stack_bytes: defaults::concurrency::TOKIO_STACK_BYTES,
            scheduler_stack_bytes: defaults::concurrency::SCHEDULER_STACK_BYTES,
            prover_stack_bytes: defaults::concurrency::PROVER_STACK_BYTES,
            sumeragi_stack_bytes: defaults::concurrency::SUMERAGI_STACK_BYTES,
        },
        confidential: A::Confidential {
            enabled: defaults::confidential::ENABLED,
            assume_valid: defaults::confidential::ASSUME_VALID,
            verifier_backend: defaults::confidential::VERIFIER_BACKEND.to_string(),
            verify_timeout: defaults::confidential::VERIFY_TIMEOUT,
        },
        crypto: A::Crypto::default(),
        settlement: A::Settlement::default(),
        streaming: A::Streaming {
            key_material: StreamingKeyMaterial::new(checked_random_keypair(
                "minimal root streaming key fixture",
            ))
            .expect("streaming key material"),
            session_store_dir: PathBuf::from(defaults::streaming::SESSION_STORE_DIR),
            feature_bits: defaults::streaming::FEATURE_BITS,
            sync: A::StreamingSync::from_defaults(),
            codec: A::StreamingCodec {
                cabac_mode: A::CabacMode::Disabled,
                trellis_block_sizes: defaults::streaming::codec::trellis_blocks(),
                rans_tables_path: defaults::streaming::codec::rans_tables_path(),
                entropy_mode: norito::streaming::EntropyMode::RansBundled,
                bundle_width: defaults::streaming::codec::bundle_width(),
                bundle_accel: A::BundleAcceleration::None,
            },
        },
        data_dir: None,
        lifecycle: A::Lifecycle::default(),
    }
}
#[cfg(test)]
mod tests {
    use super::checked_random_keypair;
    use super::{
        TestDataDirGuard, apply_queued_in_one_block, contract_code_hash_hex, minimal_ivm_program,
    };
    use iroha_core::{
        queue::Queue,
        state::{StateReadOnly, World},
        tx::AcceptedTransaction,
    };

    use iroha_data_model::{
        Level, Registrable,
        account::{Account, AccountId},
        isi::Log,
        transaction::TransactionBuilder,
    };
    use iroha_model_base::chain::ChainId;

    use std::{borrow::Cow, sync::Arc};
    #[test]
    fn minimal_root_cfg_keeps_durable_torii_paths_in_the_test_data_dir() {
        let data_dir = TestDataDirGuard::new();
        let cfg = super::mk_minimal_root_cfg();
        let sorafs_dir = data_dir.path().join("sorafs");
        let por_dir = sorafs_dir.join("por");

        assert_eq!(cfg.torii.data_dir, data_dir.path());
        assert_eq!(
            cfg.torii.da_ingest.replay_cache_store_dir,
            data_dir.path().join("da_replay")
        );
        assert_eq!(
            cfg.torii.da_ingest.manifest_store_dir,
            data_dir.path().join("da_manifests")
        );
        assert_eq!(cfg.torii.sorafs_storage.data_dir, sorafs_dir);
        assert_eq!(cfg.torii.sorafs_por.state_dir, por_dir);
        assert_eq!(
            cfg.torii.sorafs_por.drand.state_path,
            por_dir.join(iroha_config::parameters::defaults::sorafs::por::DRAND_STATE_FILE)
        );
        assert_eq!(
            cfg.torii.sorafs_por.vrf_state_path,
            por_dir.join(iroha_config::parameters::defaults::sorafs::por::VRF_STATE_FILE)
        );
    }
    #[test]
    fn contract_code_hash_hex_matches_domain_separated_full_artifact_hash() {
        let code = minimal_ivm_program(1);
        let expected = hex::encode(<[u8; 32]>::from(ivm::contract_code_hash(&code)));
        assert_eq!(contract_code_hash_hex(&code), expected);
    }
    #[test]
    fn shared_random_fixture_helpers_emit_default_keys() {
        let creds = super::random_authority();
        assert_eq!(
            creds.account.expect_single_signatory().algorithm(),
            iroha_crypto::Algorithm::default()
        );
        let cfg = super::mk_minimal_root_cfg();
        assert_eq!(
            cfg.common.key_pair.algorithm(),
            iroha_crypto::Algorithm::default()
        );
        assert_eq!(
            cfg.genesis.public_key.algorithm(),
            iroha_crypto::Algorithm::default()
        );
    }
    #[test]
    fn apply_queued_in_one_block_preserves_native_chain_and_indexes() {
        let keypair = checked_random_keypair("queued transaction signer fixture");
        let authority = AccountId::new(keypair.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let chain_id: ChainId = "chain".parse().expect("chain id");
        let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(world, 1);
        config.chain_id = chain_id.clone();
        let mut chain =
            iroha_core::sumeragi::test_chain::CertifiedTestChain::start(config).unwrap();
        let state = Arc::clone(chain.state());
        let network_id = *state.network_id_ref();
        assert_eq!(&state.chain_id, &chain_id);
        let events: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
        let queue = Arc::new(Queue::from_config(
            iroha_config::parameters::actual::Queue::default(),
            events,
        ));
        let tx = TransactionBuilder::new(
            network_id,
            authority.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "queued transaction fixture".to_owned(),
        )])
        .sign(keypair.private_key());
        let first_entrypoint_hash = tx.hash_as_entrypoint();
        let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
        queue.push(accepted, state.view()).expect("queue push");
        let applied = apply_queued_in_one_block(&mut chain, &queue);
        assert_eq!(applied, 1);
        let view = state.view();
        assert_eq!(view.height(), 2);
        let first_block = view
            .latest_block()
            .expect("funded canonical history read")
            .expect("committed test block remains readable from Kura");
        let first_block_hash = first_block.hash();
        assert_eq!(first_block.header().height().get(), 2);
        assert_eq!(
            view.kura().get_block_height_by_hash(first_block_hash),
            core::num::NonZeroUsize::new(2)
        );
        assert_eq!(
            view.kura()
                .get_block_heights_by_entrypoint_hash(first_entrypoint_hash)
                .expect("transaction index is complete"),
            [core::num::NonZeroUsize::new(2).expect("nonzero")]
                .into_iter()
                .collect()
        );
        drop(view);
        let second_tx = TransactionBuilder::new(
            network_id,
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "second queued transaction fixture".to_owned(),
        )])
        .sign(keypair.private_key());
        let second_entrypoint_hash = second_tx.hash_as_entrypoint();
        queue
            .push(
                AcceptedTransaction::new_unchecked(Cow::Owned(second_tx)),
                state.view(),
            )
            .expect("second queue push");
        assert_eq!(apply_queued_in_one_block(&mut chain, &queue), 1);
        let view = state.view();
        assert_eq!(view.height(), 3);
        let second_block = view
            .latest_block()
            .expect("funded canonical history read")
            .expect("second committed test block remains readable from Kura");
        assert_eq!(second_block.header().height().get(), 3);
        assert_eq!(
            second_block.header().prev_block_hash(),
            Some(first_block_hash),
            "the native test chain must preserve canonical parent linkage"
        );
        assert_eq!(
            view.kura().get_block_height_by_hash(second_block.hash()),
            core::num::NonZeroUsize::new(3)
        );
        assert_eq!(
            view.kura()
                .get_block_heights_by_entrypoint_hash(second_entrypoint_hash)
                .expect("transaction index is complete"),
            [core::num::NonZeroUsize::new(3).expect("nonzero")]
                .into_iter()
                .collect()
        );
        assert_eq!(
            view.kura()
                .get_block_heights_by_entrypoint_hash(first_entrypoint_hash)
                .expect("transaction index remains complete"),
            [core::num::NonZeroUsize::new(2).expect("nonzero")]
                .into_iter()
                .collect(),
            "storing the successor must preserve the first transaction index"
        );
    }
}

#[cfg(test)]
/// Test-only wire twin of the private core committee record.
///
/// The explicit frame identity keeps its Norito header identical to the record
/// decoded by `State`; field order and types intentionally mirror that record.
#[derive(norito::Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii::test_utils::AutoscaleLaneCommitteeFixtureV1",
    frame = "iroha_core::state::AutoscaleLaneCommitteeV1"
)]
pub(crate) struct AutoscaleLaneCommitteeFixtureV1 {
    version: u8,
    validator_set_hash_version: u16,
    validator_set_hash: HashOf<Vec<iroha_model_base::peer::PeerId>>,
    validator_set: Vec<iroha_model_base::peer::PeerId>,
    validator_pops: Vec<Vec<u8>>,
    validator_count: u32,
    min_quorum: u32,
}

#[cfg(test)]
/// Attach a canonical, PoP-valid immutable committee to an autoscale fixture.
pub(crate) fn pin_autoscale_lane_committee_for_test(
    lane: &mut iroha_data_model::nexus::LaneConfig,
    keypairs: &[KeyPair],
) -> Vec<iroha_model_base::peer::PeerId> {
    let mut members = keypairs
        .iter()
        .map(|keypair| {
            let peer_id = iroha_model_base::peer::PeerId::new(keypair.public_key().clone());
            let pop = iroha_crypto::bls_normal_pop_prove(keypair.private_key())
                .expect("autoscale fixture committee PoP");
            (peer_id, pop)
        })
        .collect::<Vec<_>>();
    members.sort_by(|left, right| left.0.cmp(&right.0));
    members.dedup_by(|left, right| left.0 == right.0);
    assert_eq!(
        members.len(),
        keypairs.len(),
        "autoscale fixture committee keys must be unique"
    );
    let (validator_set, validator_pops): (Vec<_>, Vec<_>) = members.into_iter().unzip();
    let committee = AutoscaleLaneCommitteeFixtureV1 {
        version: 1,
        validator_set_hash_version: iroha_data_model::consensus::VALIDATOR_SET_HASH_VERSION_V1,
        validator_set_hash: HashOf::new(&validator_set),
        validator_count: u32::try_from(validator_set.len())
            .expect("autoscale fixture committee length fits u32"),
        min_quorum: u32::try_from(iroha_sumeragi::types::quorum(validator_set.len()))
            .expect("autoscale fixture committee quorum fits u32"),
        validator_set: validator_set.clone(),
        validator_pops,
    };
    let encoded = norito::to_bytes(&committee).expect("encode autoscale fixture committee");
    lane.metadata.insert(
        iroha_data_model::nexus::AUTOSCALE_META_COMMITTEE.to_owned(),
        hex::encode(encoded),
    );
    validator_set
}

/// Explicit root authority for routing-only fixtures; this never supplies native finality.
#[cfg(test)]
pub(crate) fn bind_fixture_root(
    world: &mut iroha_core::state::World,
    scope: iroha_data_model::block::consensus::SumeragiRootScope,
) {
    use iroha_data_model::parameter::{
        Parameter,
        custom::CustomParameter,
        system::{
            ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
            consensus_metadata,
        },
    };
    use std::num::NonZeroU64;
    let mut context =
        iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended();
    context.root_scope = scope;
    let metadata = ConsensusHandshakeMetadata {
        mode: SumeragiConsensusMode::Permissioned,
        block_cadence_ms: NonZeroU64::new(1_000).unwrap(),
        wire_protocol_version: u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION),
        consensus_fingerprint: ConsensusFingerprint::new([0xC7; 32]),
        sumeragi_context: context,
    };
    metadata.validate().unwrap();
    let mut block = world.block();
    block
        .parameters
        .set_parameter(Parameter::Custom(CustomParameter::new(
            consensus_metadata::handshake_meta_id(),
            iroha_primitives::json::Json::new(metadata),
        )))
        .expect("install the routing fixture root authority");
    block.commit();
}

/// Configure the original future-created autoscale lane for shared authority refusals.
#[cfg(all(test, any(feature = "app_api", feature = "connect")))]
pub(crate) fn configure_future_created_autoscale_route_for_test(
    app: &mut crate::SharedAppState,
) -> (iroha_model_base::topology::LaneId, DataSpaceId) {
    use iroha_model_base::topology::LaneId;
    use std::num::NonZeroU32;
    let future_lane = LaneId::new(1);
    let future_dataspace = DataSpaceId::UNIVERSAL;
    let mut lane = iroha_data_model::nexus::LaneConfig {
        id: future_lane,
        dataspace_id: future_dataspace,
        alias: "elastic-lane-1".to_owned(),
        visibility: iroha_data_model::nexus::LaneVisibility::Public,
        ..iroha_data_model::nexus::LaneConfig::default()
    };
    lane.metadata.insert(
        iroha_data_model::nexus::AUTOSCALE_META_MANAGED.to_owned(),
        "true".to_owned(),
    );
    lane.metadata.insert(
        iroha_data_model::nexus::AUTOSCALE_META_CREATED_HEIGHT.to_owned(),
        "7".to_owned(),
    );
    assert!(
        lane.is_autoscale_managed_elastic(),
        "fixture must be a valid-looking autoscale elastic lane"
    );
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(2).expect("nonzero lane count"),
        vec![iroha_data_model::nexus::LaneConfig::default(), lane],
    )
    .expect("future-created lane catalog");
    let mut nexus = iroha_config::parameters::actual::Nexus {
        lane_catalog,
        ..iroha_config::parameters::actual::Nexus::default()
    };
    nexus.autoscale.enabled = true;
    nexus.autoscale.min_lane_id = NonZeroU32::new(1).expect("nonzero min lanes");
    nexus.autoscale.max_lane_id_exclusive = NonZeroU32::new(3).expect("nonzero max lanes");
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    let app_state = Arc::get_mut(app).expect("unique app state");
    let state = Arc::get_mut(&mut app_state.state).expect("unique state");
    // This is an isolated malformed read model, never executed or restored authority.
    state.install_synthetic_routing_snapshot_for_testing(nexus);
    state.update_latest_block_header_cache_for_tests(BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero authority height"),
        None,
        None,
        0,
        0,
    ));
    assert!(
        !state.is_lane_active_for_authority(future_lane),
        "future-created autoscale fixture must be inactive before creation height"
    );
    (future_lane, future_dataspace)
}
