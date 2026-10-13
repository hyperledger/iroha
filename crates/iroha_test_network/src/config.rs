//! Sample configuration builders
#[path = "genesis_policy.rs"]
mod genesis_policy;
use crate::init_instruction_registry;
use color_eyre::{Report, eyre::eyre};
pub(crate) use genesis_policy::{discover_generated_policy_hashes, execute_generated_genesis};
use iroha_config::base::toml::WriteExt;
use iroha_config::parameters::actual::{
    Crypto as ActualCrypto, Nexus as ActualNexus, Pipeline as ActualPipeline, Root as ActualRoot,
    Zk as ActualZk,
};
use iroha_core::{
    block::ValidBlock,
    compliance::LaneComplianceEngine,
    governance::manifest::LaneManifestRegistry,
    query::store::LiveQueryStore,
    state::{State, World, derive_committee_key_id},
    sumeragi::network_topology::Topology as CoreTopology,
};
use iroha_crypto::{Hash, KeyPair, SignatureOf};
use iroha_data_model::{
    Registrable as _,
    account::{Account, AccountId},
    asset::{AssetDefinitionId, definition::AssetDefinition, id::AssetId},
    block::consensus::{ConsensusMode as WireConsensusMode, SumeragiGenesisContextParameters},
    consensus::{ConsensusKeyRecord, ConsensusKeyStatus},
    da::commitment::DaProofPolicyBundle,
    domain::Domain,
    hijiri::HijiriParametersV1,
    isi::{
        Grant, InstructionBox, Mint, Revoke, SetParameter, consensus_keys::RegisterConsensusKey,
        register::Register,
    },
    parameter::{
        Parameter,
        custom::CustomParameter,
        system::{
            ConsensusHandshakeMetadata, SumeragiConsensusMode, confidential_metadata,
            consensus_metadata,
        },
    },
    permission::Permission,
    prelude::Transfer,
    transaction::Executable,
};
use iroha_executor_data_model::permission::{
    account::CanRegisterAccount,
    asset::{CanMintAssetWithDefinition, CanTransferAssetWithDefinition},
    domain::CanUnregisterDomain,
    executor::CanUpgradeExecutor,
    governance::{CanManageConsensusKeys, CanManageParliament},
    parameter::{CanSetHijiriParameters, CanSetParameters},
    peer::CanManagePeers,
    query::CanReadAllLedgerData,
    role::CanManageRoles,
    trigger::CanRegisterTrigger,
};
use iroha_genesis::{
    GenesisBlock, GenesisBuilder, GenesisTopologyEntry, ManifestCrypto, RawGenesisTransaction,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_primitives::{json::Json, numeric::NumericSpec, time::TimeSource, unique_vec::UniqueVec};
use iroha_test_samples::{
    ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR, CARPENTER_ID, CARPENTER_KEYPAIR,
    SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
};
#[cfg(test)]
use norito::json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use toml::Table;
#[cfg(test)]
thread_local! {
    static GENESIS_PREEXECUTION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn genesis_preexecution_count() -> usize {
    GENESIS_PREEXECUTION_COUNT.with(std::cell::Cell::get)
}

/// Exact policy commitments derived by isolated genesis pre-execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StagedGenesisPolicyHashes {
    /// Nexus/AMX execution context committed by the signed genesis carrier.
    pub nexus_amx: Hash,
    /// Complete process-local execution policy committed by the signed genesis carrier.
    pub execution_policy: Hash,
}
pub fn chain_id() -> ChainId {
    ChainId::from("00000000-0000-0000-0000-000000000000")
}
/// Build post-topology genesis instructions that install Committee keys for participant peers.
///
/// The fixture genesis authority receives key-management permission only while
/// these records are registered. Each peer must have an authenticated BLS PoP
/// in the genesis topology entries.
pub fn genesis_participant_committee_key_instructions(
    topology_entries: &[GenesisTopologyEntry],
    participant_peers: &[PeerId],
) -> Vec<InstructionBox> {
    if participant_peers.is_empty() {
        return Vec::new();
    }
    let genesis_authority = AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
    let mut instructions = Vec::with_capacity(participant_peers.len() + 2);
    instructions
        .push(Grant::account_permission(CanManageConsensusKeys, genesis_authority.clone()).into());
    for peer in participant_peers {
        let entry = topology_entries
            .iter()
            .find(|entry| entry.peer == *peer)
            .expect("participant peer has a genesis topology entry");
        let pop = entry
            .pop_bytes()
            .expect("valid participant peer proof-of-possession")
            .expect("participant peer proof-of-possession is present");
        let id = derive_committee_key_id(peer.public_key());
        instructions.push(
            RegisterConsensusKey {
                id: id.clone(),
                record: ConsensusKeyRecord {
                    id,
                    public_key: peer.public_key().clone(),
                    pop: Some(pop),
                    activation_height: 1,
                    expiry_height: None,
                    replaces: None,
                    status: ConsensusKeyStatus::Active,
                },
            }
            .into(),
        );
    }
    instructions.push(Revoke::account_permission(CanManageConsensusKeys, genesis_authority).into());
    instructions
}
#[cfg(test)]
fn sanitize_strings(value: &mut Value) {
    match value {
        Value::String(s) => {
            if s.chars().any(char::is_whitespace) {
                *s = s.split_whitespace().collect::<Vec<_>>().join("_");
            }
        }
        Value::Array(arr) => arr.iter_mut().for_each(sanitize_strings),
        Value::Object(map) => map.values_mut().for_each(sanitize_strings),
        _ => {}
    }
}
fn sanitize_account_id(id: &AccountId) -> AccountId {
    let raw = id.to_string();
    if !raw.chars().any(char::is_whitespace) {
        // Avoid reparsing I105 addresses unless we actually sanitize.
        return id.clone();
    }
    let sanitized = sanitize_account_id_str(&raw);
    AccountId::parse_encoded(&sanitized).expect("sanitized AccountId should parse")
}
fn sanitize_account_id_str(s: &str) -> String {
    if s.chars().any(char::is_whitespace) {
        s.split_whitespace().collect::<Vec<_>>().join("_")
    } else {
        s.to_string()
    }
}
pub fn base_iroha_config() -> Table {
    Table::new()
        .write("chain", chain_id().to_string())
        .write(
            ["genesis", "public_key"],
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().to_string(),
        )
        // Enable extended telemetry in test networks so `/metrics` snapshots are available.
        .write("telemetry_profile", "extended")
        // There is no need in persistence in tests.
        .write(["snapshot", "mode"], "disabled")
        .write(["kura", "store_dir"], "./storage")
        // Each temporary peer owns a bounded budget on the shared development
        // filesystem. Production auto-sizing reserves 20% of the whole device,
        // which is inappropriate for several small test peers sharing a host.
        .write(
            ["nexus", "storage", "local_budget_bytes"],
            1_073_741_824_i64,
        )
        // Default to broadcasting blocks to the entire test topology so small networks
        // do not stall waiting for block sync retries when some peers miss a gossip hop.
        .write(["network", "block_gossip_size"], 256)
        .write(["confidential", "enabled"], true)
        .write(["logger", "level"], "INFO")
        .write(["logger", "format"], "pretty")
}
#[must_use]
pub(crate) fn manifest_crypto_from_actual(crypto: &ActualCrypto) -> ManifestCrypto {
    ManifestCrypto {
        sm_openssl_preview: crypto.enable_sm_openssl_preview,
        sm_intrinsics: crypto.sm_intrinsics.as_str().to_owned(),
        default_hash: crypto.default_hash.clone(),
        allowed_signing: crypto.allowed_signing.clone(),
        sm2_distid_default: crypto.sm2_distid_default.clone(),
        allowed_curve_ids: crypto.allowed_curve_ids.clone(),
    }
}
pub fn genesis(
    extra_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
) -> GenesisBlock {
    genesis_with_keypair(
        extra_transactions,
        topology,
        topology_entries,
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
    )
}
/// Build the default genesis using a custom signing key pair.
pub fn genesis_with_keypair(
    extra_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
    genesis_key_pair: KeyPair,
) -> GenesisBlock {
    // Always construct a deterministic, minimal built-in genesis tailored for tests.
    // This avoids treating `defaults/genesis.template.json` as a runtime manifest and keeps the
    // first transaction shape predictable (e.g., single Upgrade when a sample
    // executor is available).
    init_instruction_registry();
    build_minimal_genesis(
        extra_transactions,
        topology,
        topology_entries,
        genesis_key_pair,
    )
}

/// Build and sign the default genesis with post-topology instructions without
/// pre-executing its transactions.
///
/// This is the internal half of the custom-`NetworkBuilder` path. The builder
/// must pre-execute the returned block under its fully merged runtime
/// configuration before any peer starts; direct node startup must never use
/// this block as prepared genesis.
pub(crate) fn genesis_unexecuted_with_keypair_and_post_topology(
    extra_transactions: Vec<Vec<InstructionBox>>,
    post_topology_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
    genesis_key_pair: KeyPair,
) -> GenesisBlock {
    init_instruction_registry();
    build_minimal_genesis_unexecuted_with_post_topology(
        extra_transactions,
        post_topology_transactions,
        topology,
        topology_entries,
        genesis_key_pair,
        chain_id(),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(iroha_core::state::default_genesis_confidential_policy_hash()),
    )
    .0
}

#[cfg(test)]
pub(crate) fn genesis_with_keypair_and_post_topology_with_policies(
    extra_transactions: Vec<Vec<InstructionBox>>,
    post_topology_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
    genesis_key_pair: KeyPair,
    chain_id: ChainId,
    genesis_crypto: Option<ManifestCrypto>,
    da_proof_policies: Option<DaProofPolicyBundle>,
    _nexus_config: Option<ActualNexus>,
    zk_config: Option<ActualZk>,
    consensus_handshake_meta: Option<Parameter>,
    consensus_mode_override: Option<SumeragiConsensusMode>,
    confidential_policy_hash: Option<[u8; 32]>,
) -> GenesisBlock {
    genesis_with_keypair_and_post_topology_with_policies_and_staged_hash(
        extra_transactions,
        post_topology_transactions,
        topology,
        topology_entries,
        genesis_key_pair,
        chain_id,
        genesis_crypto,
        da_proof_policies,
        None,
        _nexus_config,
        zk_config,
        None,
        consensus_handshake_meta,
        consensus_mode_override,
        confidential_policy_hash,
    )
    .0
}
pub(crate) fn genesis_with_keypair_and_post_topology_with_policies_and_staged_hash(
    extra_transactions: Vec<Vec<InstructionBox>>,
    post_topology_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
    genesis_key_pair: KeyPair,
    chain_id: ChainId,
    genesis_crypto: Option<ManifestCrypto>,
    da_proof_policies: Option<DaProofPolicyBundle>,
    pipeline_config: Option<ActualPipeline>,
    nexus_config: Option<ActualNexus>,
    zk_config: Option<ActualZk>,
    runtime_config: Option<ActualRoot>,
    consensus_handshake_meta: Option<Parameter>,
    consensus_mode_override: Option<SumeragiConsensusMode>,
    confidential_policy_hash: Option<[u8; 32]>,
) -> (
    GenesisBlock,
    StagedGenesisPolicyHashes,
    RawGenesisTransaction,
) {
    init_instruction_registry();
    build_minimal_genesis_with_post_topology_and_staged_hash(
        extra_transactions,
        post_topology_transactions,
        topology,
        topology_entries,
        genesis_key_pair,
        chain_id,
        genesis_crypto,
        da_proof_policies,
        pipeline_config,
        nexus_config,
        zk_config,
        runtime_config,
        consensus_handshake_meta,
        consensus_mode_override,
        confidential_policy_hash,
    )
}
fn strip_handshake_metadata_transactions(transactions: &mut [Vec<InstructionBox>]) {
    for instruction_batch in transactions {
        instruction_batch.retain(|instruction| {
            !instruction
                .as_any()
                .downcast_ref::<SetParameter>()
                .is_some_and(|set_param| {
                    matches!(
                        set_param.inner(),
                        Parameter::Custom(custom)
                            if custom.id() == &consensus_metadata::handshake_meta_id()
                    )
                })
        });
    }
}
fn decode_consensus_handshake_metadata(
    parameter: &Parameter,
) -> Result<ConsensusHandshakeMetadata, Report> {
    let Parameter::Custom(custom) = parameter else {
        return Err(eyre!(
            "consensus handshake metadata must be encoded as a custom parameter"
        ));
    };
    if custom.id() != &consensus_metadata::handshake_meta_id() {
        return Err(eyre!(
            "consensus handshake metadata has unexpected parameter id `{}`",
            custom.id()
        ));
    }
    let metadata: ConsensusHandshakeMetadata = norito::json::from_str(custom.payload().get())
        .map_err(|error| eyre!("failed to decode consensus handshake metadata: {error}"))?;
    metadata
        .validate()
        .map_err(|error| eyre!("invalid consensus handshake metadata: {error}"))?;
    Ok(metadata)
}

fn signed_genesis_consensus_mode(block: &GenesisBlock) -> Result<WireConsensusMode, Report> {
    let mut metadata_entries = Vec::new();
    for transaction in block.0.external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(eyre!(
                "signed genesis consensus metadata must be carried by instruction batches"
            ));
        };
        for set_parameter in instructions
            .iter()
            .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        {
            if matches!(
                set_parameter.inner(),
                Parameter::Custom(custom)
                    if custom.id() == &consensus_metadata::handshake_meta_id()
            ) {
                metadata_entries.push(decode_consensus_handshake_metadata(set_parameter.inner())?);
            }
        }
    }
    let [metadata] = metadata_entries.as_slice() else {
        return Err(eyre!(
            "signed genesis requires exactly one consensus handshake metadata entry, found {}",
            metadata_entries.len()
        ));
    };
    Ok(match metadata.mode {
        SumeragiConsensusMode::Permissioned => WireConsensusMode::Permissioned,
        SumeragiConsensusMode::Npos => WireConsensusMode::Npos,
    })
}
fn build_minimal_genesis(
    extra_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
    genesis_key_pair: KeyPair,
) -> GenesisBlock {
    build_minimal_genesis_with_post_topology(
        extra_transactions,
        Vec::new(),
        topology,
        topology_entries,
        genesis_key_pair,
        chain_id(),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(iroha_core::state::default_genesis_confidential_policy_hash()),
    )
}
fn build_minimal_genesis_with_post_topology(
    extra_transactions: Vec<Vec<InstructionBox>>,
    post_topology_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
    genesis_key_pair: KeyPair,
    chain_id: ChainId,
    genesis_crypto: Option<ManifestCrypto>,
    da_proof_policies: Option<DaProofPolicyBundle>,
    nexus_config: Option<ActualNexus>,
    zk_config: Option<ActualZk>,
    consensus_handshake_meta: Option<Parameter>,
    consensus_mode_override: Option<SumeragiConsensusMode>,
    confidential_policy_hash: Option<[u8; 32]>,
) -> GenesisBlock {
    build_minimal_genesis_with_post_topology_and_staged_hash(
        extra_transactions,
        post_topology_transactions,
        topology,
        topology_entries,
        genesis_key_pair,
        chain_id,
        genesis_crypto,
        da_proof_policies,
        None,
        nexus_config,
        zk_config,
        None,
        consensus_handshake_meta,
        consensus_mode_override,
        confidential_policy_hash,
    )
    .0
}
fn build_minimal_genesis_with_post_topology_and_staged_hash(
    extra_transactions: Vec<Vec<InstructionBox>>,
    post_topology_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
    genesis_key_pair: KeyPair,
    chain_id: ChainId,
    genesis_crypto: Option<ManifestCrypto>,
    da_proof_policies: Option<DaProofPolicyBundle>,
    pipeline_config: Option<ActualPipeline>,
    nexus_config: Option<ActualNexus>,
    zk_config: Option<ActualZk>,
    runtime_config: Option<ActualRoot>,
    consensus_handshake_meta: Option<Parameter>,
    consensus_mode_override: Option<SumeragiConsensusMode>,
    confidential_policy_hash: Option<[u8; 32]>,
) -> (
    GenesisBlock,
    StagedGenesisPolicyHashes,
    RawGenesisTransaction,
) {
    // Permission JSON is materialized here, before native pre-execution begins.
    // A supplied runtime configuration owns its address profile on every calling thread.
    let _profile = runtime_config.as_ref().map(|config| {
        iroha_data_model::account::address::ChainDiscriminantGuard::enter(
            *config.common.chain_discriminant.value(),
        )
    });
    let mut extra_transactions = extra_transactions;
    let mut post_topology_transactions = post_topology_transactions;
    strip_handshake_metadata_transactions(&mut extra_transactions);
    strip_handshake_metadata_transactions(&mut post_topology_transactions);
    let bind_generated_policy = consensus_handshake_meta.is_none();
    let (block, genesis_account, topology_vec, genesis_key_pair, raw_genesis) =
        build_minimal_genesis_unexecuted_with_post_topology(
            extra_transactions,
            post_topology_transactions,
            topology,
            topology_entries,
            genesis_key_pair,
            chain_id,
            genesis_crypto,
            da_proof_policies,
            nexus_config.clone(),
            zk_config.clone(),
            consensus_handshake_meta,
            consensus_mode_override,
            confidential_policy_hash,
        );
    genesis_policy::execute_generated_genesis(
        block,
        raw_genesis,
        &genesis_key_pair,
        bind_generated_policy,
        |proposal| {
            preexecute_genesis_with_runtime_config(
                proposal,
                &genesis_account,
                &topology_vec,
                &genesis_key_pair,
                pipeline_config.as_ref(),
                nexus_config.as_ref(),
                zk_config.as_ref(),
                runtime_config.as_ref(),
            )
        },
    )
    .expect("minimal genesis must pre-execute without synthetic results")
}
#[cfg(test)]
fn build_minimal_genesis_unexecuted(
    extra_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
    genesis_key_pair: KeyPair,
) -> (GenesisBlock, AccountId, Vec<PeerId>, KeyPair) {
    let (block, account, peers, key_pair, _) = build_minimal_genesis_unexecuted_with_post_topology(
        extra_transactions,
        Vec::new(),
        topology,
        topology_entries,
        genesis_key_pair,
        chain_id(),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(iroha_core::state::default_genesis_confidential_policy_hash()),
    );
    (block, account, peers, key_pair)
}
fn build_minimal_genesis_unexecuted_with_post_topology(
    extra_transactions: Vec<Vec<InstructionBox>>,
    post_topology_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
    genesis_key_pair: KeyPair,
    chain_id: ChainId,
    genesis_crypto: Option<ManifestCrypto>,
    da_proof_policies: Option<DaProofPolicyBundle>,
    nexus_config: Option<ActualNexus>,
    _zk_config: Option<ActualZk>,
    consensus_handshake_meta: Option<Parameter>,
    consensus_mode_override: Option<SumeragiConsensusMode>,
    confidential_policy_hash: Option<[u8; 32]>,
) -> (
    GenesisBlock,
    AccountId,
    Vec<PeerId>,
    KeyPair,
    RawGenesisTransaction,
) {
    fn append_external_genesis_transaction(
        mut builder: GenesisBuilder,
        instructions: Vec<InstructionBox>,
        vk_registry_instructions: &mut Vec<InstructionBox>,
    ) -> GenesisBuilder {
        if instructions.is_empty() {
            return builder;
        }

        vk_registry_instructions.extend(instructions.iter().cloned());
        let mut transaction_instructions = Vec::with_capacity(instructions.len());
        for instruction in instructions {
            if let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>() {
                builder = builder.append_parameter(set_parameter.inner().clone());
            } else {
                transaction_instructions.push(instruction);
            }
        }
        if transaction_instructions.is_empty() {
            return builder;
        }

        builder = builder.next_transaction();
        for instruction in transaction_instructions {
            builder = builder.append_instruction(instruction);
        }
        builder
    }

    fn try_default_executor_path() -> Option<PathBuf> {
        if std::env::var("IROHA_TEST_PREBUILD_DEFAULT_EXECUTOR")
            .ok()
            .as_deref()
            != Some("1")
        {
            return None;
        }
        let sample = iroha_test_samples::sample_ivm_path("default_executor");
        match std::fs::metadata(&sample) {
            Ok(meta) if meta.len() > 0 => Some(sample),
            _ => None,
        }
    }
    fn default_ivm_dir() -> PathBuf {
        iroha_test_samples::sample_ivm_path("default_executor")
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    }
    let da_proof_policies = da_proof_policies.or_else(|| {
        nexus_config
            .as_ref()
            .map(|nexus| iroha_core::da::active_proof_policy_bundle_at_height(nexus, 1))
    });
    let chain = chain_id.clone();
    let genesis_account = AccountId::new(genesis_key_pair.public_key().clone());
    let genesis_id = sanitize_account_id(&genesis_account);
    let alice_id = sanitize_account_id(&ALICE_ID);
    let bob_id = sanitize_account_id(&BOB_ID);
    let carpenter_id = sanitize_account_id(&CARPENTER_ID);
    let ivm_dir = default_ivm_dir();
    let mut builder = if let Some(executor_path) = try_default_executor_path() {
        GenesisBuilder::new(chain.clone(), executor_path, ivm_dir.clone())
    } else {
        GenesisBuilder::new_without_executor(chain.clone(), ivm_dir.clone())
    };
    let consensus_handshake_metadata = consensus_handshake_meta
        .as_ref()
        .map(decode_consensus_handshake_metadata)
        .transpose()
        .expect("test-network consensus handshake metadata must be canonical");
    if let (Some(metadata), Some(mode_override)) = (
        consensus_handshake_metadata.as_ref(),
        consensus_mode_override,
    ) {
        assert_eq!(
            metadata.mode, mode_override,
            "consensus mode override must agree with signed handshake metadata"
        );
    }
    let consensus_mode = consensus_handshake_metadata.as_ref().map_or_else(
        || consensus_mode_override.unwrap_or(SumeragiConsensusMode::Permissioned),
        |metadata| metadata.mode,
    );
    let (block_cadence_ms, sumeragi_context) = consensus_handshake_metadata.map_or_else(
        || (None, SumeragiGenesisContextParameters::recommended()),
        |metadata| (Some(metadata.block_cadence_ms), metadata.sumeragi_context),
    );
    builder = builder.with_sumeragi_context_parameters(sumeragi_context);
    if let Some(block_cadence_ms) = block_cadence_ms {
        builder = builder.with_block_cadence_ms(block_cadence_ms);
    }
    if let Some(crypto) = genesis_crypto {
        builder = builder.with_crypto(crypto);
    }
    if let Some(policies) = &da_proof_policies {
        builder = builder.with_da_proof_policies(policies.clone());
    }
    let wonderland_name: Name = "wonderland".parse().expect("wonderland domain");
    let rose_name: Name = "rose".parse().expect("rose asset name");
    let camomile_name: Name = "camomile".parse().expect("camomile asset name");
    let garden_name: Name = "garden_of_live_flowers"
        .parse()
        .expect("garden_of_live_flowers domain");
    let cabbage_name: Name = "cabbage".parse().expect("cabbage asset name");
    let test_domain_name: Name = "domain".parse().expect("test domain");
    let and_domain_name: Name = "and".parse().expect("and domain");
    let xor_name: Name = "xor".parse().expect("xor asset name");
    let may_name: Name = "MAY".parse().expect("MAY asset name");
    let alice_metadata = Metadata::default();
    let universal_dataspace: Name = "universal".parse().expect("universal dataspace");
    let wonderland_domain =
        DomainId::try_new(&wonderland_name, &universal_dataspace).expect("wonderland domain id");
    let garden_domain =
        DomainId::try_new(&garden_name, &universal_dataspace).expect("garden domain id");
    let test_domain_id =
        DomainId::try_new(&test_domain_name, &universal_dataspace).expect("test domain id");
    let and_domain_id =
        DomainId::try_new(&and_domain_name, &universal_dataspace).expect("and domain id");
    builder = builder
        .domain(wonderland_domain.clone())
        .account_with_metadata(ALICE_KEYPAIR.public_key().clone(), alice_metadata)
        .account(BOB_KEYPAIR.public_key().clone())
        .asset(rose_name, NumericSpec::default())
        .asset(camomile_name, NumericSpec::default())
        .finish_domain()
        .domain(garden_domain.clone())
        .account(CARPENTER_KEYPAIR.public_key().clone())
        .asset(cabbage_name, NumericSpec::default())
        .finish_domain()
        .domain(test_domain_id.clone())
        .asset(xor_name, NumericSpec::default())
        .finish_domain()
        .domain(and_domain_id.clone())
        .asset(may_name, NumericSpec::default())
        .finish_domain();
    let wonderland_domain =
        DomainId::parse_fully_qualified("wonderland.universal").expect("wonderland domain id");
    let garden_domain = DomainId::parse_fully_qualified("garden_of_live_flowers.universal")
        .expect("garden_of_live_flowers domain id");
    let rose_definition_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            wonderland_domain.clone(),
            "rose".parse().unwrap(),
        );
    let camomile_definition_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            wonderland_domain.clone(),
            "camomile".parse().unwrap(),
        );
    let cabbage_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        garden_domain.clone(),
        "cabbage".parse().unwrap(),
    );
    let rose_asset_id = AssetId::new(rose_definition_id.clone(), alice_id.clone());
    let cabbage_asset_id = AssetId::new(cabbage_definition_id.clone(), alice_id.clone());
    builder = builder.append_instruction(Transfer::domain(
        genesis_id.clone(),
        wonderland_domain.clone(),
        alice_id.clone(),
    ));
    builder = builder.append_instruction(Mint::asset_quantity(13u32, rose_asset_id));
    builder = builder.append_instruction(Mint::asset_quantity(44u32, cabbage_asset_id));
    // Author one global bootstrap phase for the fixture permission grants and
    // SoraCloud asset definitions/balances. They share the genesis authority and
    // universal routing; grants add no balance work to the existing mint phase.
    // Caller-owned batches and the proof-bearing topology stay separate below.
    builder = builder.next_transaction();
    let xor_asset_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            test_domain_id.clone(),
            "xor".parse().unwrap(),
        );
    let may_and_def: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            and_domain_id.clone(),
            "MAY".parse().unwrap(),
        );
    let grant_instructions = [
        InstructionBox::from(Grant::account_permission(
            CanRegisterAccount {
                domain: test_domain_id.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanRegisterAccount {
                domain: wonderland_domain.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanRegisterAccount {
                domain: garden_domain.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanRegisterAccount {
                domain: and_domain_id.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanMintAssetWithDefinition {
                asset_definition: xor_asset_def.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanTransferAssetWithDefinition {
                asset_definition: xor_asset_def.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanMintAssetWithDefinition {
                asset_definition: rose_definition_id.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanMintAssetWithDefinition {
                asset_definition: camomile_definition_id.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanMintAssetWithDefinition {
                asset_definition: cabbage_definition_id.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanMintAssetWithDefinition {
                asset_definition: may_and_def,
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(CanManagePeers, alice_id.clone())),
        InstructionBox::from(Grant::account_permission(CanManageRoles, alice_id.clone())),
        InstructionBox::from(Grant::account_permission(
            CanUnregisterDomain {
                domain: wonderland_domain.clone(),
            },
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanUpgradeExecutor,
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanSetParameters,
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanSetHijiriParameters,
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanReadAllLedgerData,
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanSetParameters,
            genesis_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanSetHijiriParameters,
            genesis_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            Permission::new("CanManageSoracloud".into(), Json::new(())),
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanManageParliament,
            alice_id.clone(),
        )),
        InstructionBox::from(Grant::account_permission(
            CanRegisterTrigger {
                authority: alice_id.clone(),
            },
            alice_id.clone(),
        )),
    ];
    for grant in grant_instructions {
        builder = builder.append_instruction(grant);
    }
    let agent_wallet_asset_definition =
        AssetDefinitionId::parse_address_literal("61CtjvNd9T3THAR65GsMVHr82Bjc")
            .expect("soracloud agent wallet asset definition id");
    let hf_shared_lease_asset_definition =
        AssetDefinitionId::parse_address_literal("5PeSrQmLNwwKtruJvDZrbrm9RuMw")
            .expect("soracloud HF shared lease asset definition id");
    // Topology entries only carry the peer BLS identity. Runtime accounts for validator
    // processes are seeded later from the peer streaming identities in `NetworkBuilder`.
    let soracloud_bootstrap_accounts =
        BTreeSet::from([alice_id.clone(), bob_id.clone(), carpenter_id.clone()]);
    builder = builder.append_instruction(Register::asset_definition(AssetDefinition::numeric(
        agent_wallet_asset_definition.clone(),
        "soracloud_agent_wallet".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )));
    builder = builder.append_instruction(Register::asset_definition(AssetDefinition::numeric(
        hf_shared_lease_asset_definition.clone(),
        "soracloud_hf_lease".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )));
    for account_id in soracloud_bootstrap_accounts {
        builder = builder.append_instruction(Mint::asset_quantity(
            500_000_u32,
            AssetId::new(agent_wallet_asset_definition.clone(), account_id.clone()),
        ));
        builder = builder.append_instruction(Mint::asset_quantity(
            500_000_u32,
            AssetId::new(hf_shared_lease_asset_definition.clone(), account_id),
        ));
    }
    let mut vk_registry_instructions = Vec::new();
    for tx_instr in extra_transactions {
        builder =
            append_external_genesis_transaction(builder, tx_instr, &mut vk_registry_instructions);
    }
    let topology_vec: Vec<PeerId> = topology.iter().cloned().collect();
    if !topology_vec.is_empty() {
        let mut pop_map: BTreeMap<iroha_crypto::PublicKey, Vec<u8>> = topology_entries
            .iter()
            .map(|entry| {
                let pop = entry
                    .pop_bytes()
                    .unwrap_or_else(|err| {
                        panic!(
                            "invalid pop_hex for topology peer {}: {err}",
                            entry.peer.public_key()
                        )
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "missing pop_hex for topology peer {}",
                            entry.peer.public_key()
                        )
                    });
                (entry.peer.public_key().clone(), pop)
            })
            .collect();
        // Keep the proof-bearing topology in the raw manifest until signing. The
        // signer validates the exact validator set and its proofs of possession
        // before lowering the entries into `RegisterPeerWithPop` instructions.
        let mut manifest_topology = Vec::with_capacity(topology_vec.len());
        for peer_id in &topology_vec {
            let pop_bytes = pop_map
                .remove(peer_id.public_key())
                .unwrap_or_else(|| panic!("missing BLS PoP for peer {}", peer_id.public_key()));
            manifest_topology.push(GenesisTopologyEntry::new(peer_id.clone(), pop_bytes));
        }
        if let Some((dangling_pk, _)) = pop_map.into_iter().next() {
            panic!("topology entry present for peer {dangling_pk} that is absent from topology");
        }
        builder = builder.next_transaction().set_topology(manifest_topology);
    }
    for tx_instr in post_topology_transactions {
        builder =
            append_external_genesis_transaction(builder, tx_instr, &mut vk_registry_instructions);
    }
    let vk_set_hash = iroha_genesis::compute_genesis_vk_set_hash(vk_registry_instructions.iter())
        .expect("compute genesis verifying key set hash");
    let vk_set_hash_field = vk_set_hash.map_or(norito::json::Value::Null, |hash| {
        norito::json::Value::String(format_hash_hex(hash))
    });
    let mut confidential_root = norito::json::Map::new();
    confidential_root.insert("vk_set_hash".to_owned(), vk_set_hash_field);
    let conf_param = Parameter::Custom(CustomParameter::new(
        confidential_metadata::registry_root_id(),
        Json::new(norito::json::Value::Object(confidential_root)),
    ));
    builder = builder.append_parameter(Parameter::Custom(
        HijiriParametersV1::first_release_genesis().into_custom_parameter(),
    ));
    builder = builder.append_parameter(conf_param);
    let raw_genesis = builder
        .build_raw()
        .expect("build canonical test-network genesis manifest")
        .with_consensus_mode(consensus_mode)
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
    let block = raw_genesis
        .clone()
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
            &genesis_key_pair,
            da_proof_policies,
            confidential_policy_hash,
        )
        .expect("build minimal genesis");
    (
        block,
        genesis_account,
        topology_vec,
        genesis_key_pair,
        raw_genesis,
    )
}
fn format_hash_hex(hash: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(66);
    encoded.push_str("0x");
    for byte in hash {
        write!(&mut encoded, "{byte:02x}").expect("write to String");
    }
    encoded
}
#[cfg(test)]
pub(crate) fn ensure_genesis_results(
    block: &mut GenesisBlock,
    genesis_account: &AccountId,
    topology: &[PeerId],
    genesis_key_pair: &KeyPair,
    nexus_config: Option<&ActualNexus>,
    zk_config: Option<&ActualZk>,
) {
    ensure_genesis_results_with_runtime_config(
        block,
        genesis_account,
        topology,
        genesis_key_pair,
        None,
        nexus_config,
        zk_config,
        None,
    );
}
pub(crate) fn ensure_genesis_results_with_runtime_config(
    block: &mut GenesisBlock,
    genesis_account: &AccountId,
    topology: &[PeerId],
    genesis_key_pair: &KeyPair,
    pipeline_config: Option<&ActualPipeline>,
    nexus_config: Option<&ActualNexus>,
    zk_config: Option<&ActualZk>,
    runtime_config: Option<&ActualRoot>,
) {
    let has_results = block.0.has_results();
    let results_are_canonical = genesis_results_are_canonical(&block.0);
    assert!(
        !has_results || results_are_canonical,
        "provided genesis execution results must be complete and canonical"
    );
    let signature_is_canonical = genesis_signature_is_canonical(&block.0, genesis_key_pair);
    if results_are_canonical && signature_is_canonical {
        return;
    }
    // Preserve already computed execution results while restoring the canonical genesis signature.
    if has_results {
        block.0 = resign_genesis(&block.0, genesis_key_pair);
        return;
    }
    // A builder-owned proposal mutation invalidates both its execution outputs
    // and signature. Sign those exact new proposal bytes before strict Core
    // validation; publish the replacement only after execution succeeds.
    let signed_proposal = GenesisBlock(resign_genesis(&block.0, genesis_key_pair));
    let (executed, _) = preexecute_genesis_with_runtime_config(
        &signed_proposal,
        genesis_account,
        topology,
        genesis_key_pair,
        pipeline_config,
        nexus_config,
        zk_config,
        runtime_config,
    )
    .unwrap_or_else(|error| panic!("genesis pre-execution must succeed: {error:#}"));
    block.0 = executed;
}
fn genesis_results_are_canonical(block: &iroha_data_model::block::SignedBlock) -> bool {
    if !block.has_results()
        || block.validate_output_merkle_cache().is_err()
        || block
            .output_results()
            .any(|result| result.as_ref().is_err())
    {
        return false;
    }
    // Complete typed validation checks every exact Network source plus internal
    // Pipeline/Time ownership. Internal invocations have no separate input leaf.
    let Ok(minimum_committed_fragments) = u64::try_from(block.execution_outputs().len()) else {
        return false;
    };
    block
        .committed_fragment_count()
        .is_some_and(|actual| actual >= minimum_committed_fragments)
}

fn genesis_signature_is_canonical(
    block: &iroha_data_model::block::SignedBlock,
    genesis_key_pair: &KeyPair,
) -> bool {
    let mut signatures = block.signatures();
    let Some(signature) = signatures.next() else {
        return false;
    };
    if signatures.next().is_some() {
        return false;
    }
    signature
        .signature()
        .verify_hash(genesis_key_pair.public_key(), block.hash())
        .is_ok()
}
#[cfg(test)]
fn populate_genesis_results(
    block: &GenesisBlock,
    genesis_account: &AccountId,
    topology: &[PeerId],
    genesis_key_pair: &KeyPair,
    nexus_config: Option<&ActualNexus>,
    zk_config: Option<&ActualZk>,
) -> Result<iroha_data_model::block::SignedBlock, Report> {
    preexecute_genesis_with_runtime_config(
        block,
        genesis_account,
        topology,
        genesis_key_pair,
        None,
        nexus_config,
        zk_config,
        None,
    )
    .map(|(block, _)| block)
}
pub(crate) fn staged_genesis_policy_hashes(
    block: &GenesisBlock,
    genesis_account: &AccountId,
    topology: &[PeerId],
    genesis_key_pair: &KeyPair,
    pipeline_config: Option<&ActualPipeline>,
    nexus_config: Option<&ActualNexus>,
    zk_config: Option<&ActualZk>,
    runtime_config: Option<&ActualRoot>,
) -> Result<StagedGenesisPolicyHashes, Report> {
    preexecute_genesis_with_runtime_config(
        block,
        genesis_account,
        topology,
        genesis_key_pair,
        pipeline_config,
        nexus_config,
        zk_config,
        runtime_config,
    )
    .map(|(_, hashes)| hashes)
}
/// Pre-execute with the supplied runtime address profile. Configuration-free test helpers
/// use the caller's native address scope for both instruction construction and execution.
///
/// Execution stays on the caller's thread. The scoped profile is restored on return
/// or unwinding; the native state owner supports an ordinary thread stack.
pub(crate) fn preexecute_genesis_with_runtime_config(
    block: &GenesisBlock,
    genesis_account: &AccountId,
    topology: &[PeerId],
    genesis_key_pair: &KeyPair,
    pipeline_config: Option<&ActualPipeline>,
    nexus_config: Option<&ActualNexus>,
    zk_config: Option<&ActualZk>,
    runtime_config: Option<&ActualRoot>,
) -> Result<
    (
        iroha_data_model::block::SignedBlock,
        StagedGenesisPolicyHashes,
    ),
    Report,
> {
    if topology.is_empty() {
        return Err(eyre!("genesis topology is empty"));
    }
    #[cfg(test)]
    GENESIS_PREEXECUTION_COUNT.with(|count| count.set(count.get() + 1));
    // Parsing ActualRoot scopes only that parse. Cached blocks and independent staging
    // can reach this execution boundary later, from a different thread and profile; without
    // a runtime profile the caller's address scope applies.
    let discriminant = runtime_config.map_or_else(
        iroha_data_model::account::address::chain_discriminant,
        |config| *config.common.chain_discriminant.value(),
    );
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant);
    preexecute_genesis_on_current_thread(
        block,
        genesis_account,
        topology,
        genesis_key_pair,
        pipeline_config,
        nexus_config,
        zk_config,
        runtime_config,
    )
}

fn preexecute_genesis_on_current_thread(
    block: &GenesisBlock,
    genesis_account: &AccountId,
    topology: &[PeerId],
    genesis_key_pair: &KeyPair,
    pipeline_config: Option<&ActualPipeline>,
    nexus_config: Option<&ActualNexus>,
    zk_config: Option<&ActualZk>,
    runtime_config: Option<&ActualRoot>,
) -> Result<
    (
        iroha_data_model::block::SignedBlock,
        StagedGenesisPolicyHashes,
    ),
    Report,
> {
    let effective_nexus = runtime_config.map(|config| &config.nexus).or(nexus_config);
    let nexus = resolve_preexec_nexus_config(effective_nexus, block.0.da_proof_policies())?;
    let query_handle = LiveQueryStore::start_test();
    let effective_genesis_account = block
        .0
        .external_transactions()
        .next()
        .map(|tx| tx.authority().clone())
        .unwrap_or_else(|| genesis_account.clone());
    let genesis_domain =
        Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&effective_genesis_account);
    let genesis_account_entry =
        Account::new(effective_genesis_account.clone()).build(&effective_genesis_account);
    let mut world = World::with([genesis_domain], [genesis_account_entry], []);
    iroha_core::sns::seed_genesis_alias_bootstrap(&mut world, &block.0, &nexus.dataspace_catalog)?;
    let mut state = State::new_with_pre_genesis_nexus_for_testing(world, nexus, query_handle);
    if let Some(pipeline_config) = runtime_config
        .map(|config| &config.pipeline)
        .or(pipeline_config)
    {
        // As on a node: the configuration supplies local pipeline resources and
        // the fee policy; execution limits are the committed policy of the
        // genesis under validation.
        state
            .install_node_pipeline(pipeline_config.clone())
            .map_err(Report::from)?;
    }
    if let Some(config) = runtime_config {
        state.set_crypto(config.crypto.clone());
        state.set_oracle(config.oracle.clone());
        state.set_fraud_monitoring(config.fraud_monitoring.clone());
        state.set_gov(config.gov.clone());
        state.content = config.content.clone();
        state.set_settlement(config.settlement);
    }
    if let Some(zk_config) = runtime_config.map(|config| &config.zk).or(zk_config) {
        // As on a node: the configuration supplies local ZK resources only; validity
        // values are the committed policy of the genesis under validation.
        state
            .install_node_zk(zk_config.clone())
            .map_err(Report::from)?;
    }
    install_preexec_lane_manifests(&state, runtime_config)?;
    let core_topology = CoreTopology::new(topology.to_vec());
    let time_source = TimeSource::new_system();
    let consensus_mode = signed_genesis_consensus_mode(block)?;
    let root_scope = iroha_genesis::signed_genesis_consensus_metadata(&block.0)?
        .sumeragi_context
        .root_scope;
    let validation = ValidBlock::validate_signed_genesis(
        block.0.clone(),
        &core_topology,
        &effective_genesis_account,
        &time_source,
        &state,
        consensus_mode,
        root_scope,
    )
    .unpack(|_| {});
    let (valid_block, state_block) = match validation {
        Ok(validated) => validated,
        Err((rejected_block, err)) => {
            let first_tx_error = rejected_block
                .has_results()
                .then(|| {
                    rejected_block
                        .execution_outputs()
                        .iter()
                        .enumerate()
                        .find_map(|(index, output)| {
                            use iroha_data_model::block::execution_output::ExecutionOutputV1;
                            let error = output.result().as_ref().err()?;
                            let source = match output {
                                ExecutionOutputV1::Network(row) => {
                                    format!("tx#{}", row.input_index)
                                }
                                ExecutionOutputV1::Pipeline(_) => {
                                    format!("pipeline output#{index}")
                                }
                                ExecutionOutputV1::Time(_) => format!("time output#{index}"),
                            };
                            Some(format!("{source}: {error}; details: {error:?}"))
                        })
                })
                .flatten();
            let mut report = Report::new(err);
            if let Some(first_tx_error) = first_tx_error {
                report = report.wrap_err(format!(
                    "genesis pre-execution produced rejected transaction result ({first_tx_error})"
                ));
            } else if rejected_block.has_results() {
                report = report.wrap_err(
                    "genesis pre-execution produced invalid results without a concrete transaction \
                     rejection reason"
                        .to_owned(),
                );
            } else {
                report = report.wrap_err(
                    "genesis pre-execution failed before transaction results were recorded"
                        .to_owned(),
                );
            }
            return Err(report);
        }
    };
    let staged_hashes = StagedGenesisPolicyHashes {
        nexus_amx: iroha_core::sumeragi::staged_genesis_nexus_amx_context_hash(&state_block),
        execution_policy: iroha_core::sumeragi::staged_genesis_execution_policy_hash(&state_block)
            .map_err(Report::from)?,
    };
    drop(state_block);
    let signed_block: iroha_data_model::block::SignedBlock = valid_block.into();
    Ok((
        resign_genesis(&signed_block, genesis_key_pair),
        staged_hashes,
    ))
}
fn resolve_preexec_nexus_config(
    nexus_config: Option<&ActualNexus>,
    block_policies: Option<&DaProofPolicyBundle>,
) -> Result<ActualNexus, Report> {
    let has_authoritative_nexus = nexus_config.is_some();
    let mut nexus = nexus_config.cloned().unwrap_or_default();
    if let Some(policies) = block_policies
        && !policies.policies().is_empty()
        && !has_authoritative_nexus
    {
        let mut lanes = Vec::with_capacity(policies.policies().len());
        let mut dataspace_ids = BTreeSet::new();
        let mut max_lane = 0u32;
        for policy in policies.policies() {
            max_lane = max_lane.max(policy.lane_id.as_u32());
            dataspace_ids.insert(policy.dataspace_id);
            lanes.push(iroha_data_model::nexus::LaneConfig {
                id: policy.lane_id,
                dataspace_id: policy.dataspace_id,
                alias: policy.alias.clone(),
                proof_scheme: policy.proof_scheme,
                ..iroha_data_model::nexus::LaneConfig::default()
            });
        }
        let lane_count = std::num::NonZeroU32::new(max_lane.saturating_add(1))
            .ok_or_else(|| eyre!("proof policies must include at least one lane"))?;
        let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(lane_count, lanes)
            .map_err(|err| Report::new(err).wrap_err("build lane catalog from proof policies"))?;
        let mut dataspace_entries = nexus.dataspace_catalog.entries().to_vec();
        let mut existing_ids: BTreeSet<_> =
            dataspace_entries.iter().map(|entry| entry.id).collect();
        let mut existing_aliases: BTreeSet<_> = dataspace_entries
            .iter()
            .map(|entry| entry.alias.clone())
            .collect();
        for dataspace_id in dataspace_ids {
            if existing_ids.insert(dataspace_id) {
                let base_alias = format!("policy-ds-{}", u64::from(dataspace_id));
                let mut alias = base_alias.clone();
                let mut idx = 1u32;
                while existing_aliases.contains(&alias) {
                    alias = format!("{base_alias}-{idx}");
                    idx = idx.saturating_add(1);
                }
                existing_aliases.insert(alias.clone());
                dataspace_entries.push(iroha_data_model::nexus::DataSpaceMetadata {
                    id: dataspace_id,
                    alias,
                    description: None,
                    fault_tolerance: 1,
                });
            }
        }
        let dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(dataspace_entries)
            .map_err(|err| {
            Report::new(err).wrap_err("build dataspace catalog from proof policies")
        })?;
        nexus.lane_catalog = lane_catalog;
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        nexus.dataspace_catalog = dataspace_catalog;
    }
    if !has_authoritative_nexus {
        // Direct fixture calls have no resolved runtime config. Keep their
        // account literals unambiguous, but never rewrite an authoritative Nexus
        // snapshot because the signed Nexus/AMX context commitment must match peer startup.
        let gas_account = ALICE_ID.to_string();
        nexus.staking.stake_escrow_account_id = gas_account.clone();
        nexus.staking.slash_sink_account_id = gas_account;
    }
    Ok(nexus)
}
fn install_preexec_lane_manifests(
    state: &State,
    runtime_config: Option<&ActualRoot>,
) -> Result<(), Report> {
    let nexus = state.nexus_snapshot();
    let lane_compliance = match runtime_config {
        Some(config) if config.nexus.compliance.enabled => {
            let policy_dir = config.nexus.compliance.policy_dir.as_ref().ok_or_else(|| {
                eyre!("lane compliance is enabled but no policy_dir is configured")
            })?;
            let engine = LaneComplianceEngine::from_directory(
                policy_dir,
                config.nexus.compliance.audit_only,
            )
            .map_err(|error| {
                eyre!("load lane compliance policies for genesis pre-execution: {error}")
            })?;
            engine
                .validate_active_catalog(&nexus.lane_catalog)
                .map_err(|error| {
                    eyre!("validate lane compliance policies for genesis pre-execution: {error}")
                })?;
            Some(Arc::new(engine))
        }
        _ => None,
    };
    let lane_manifests =
        LaneManifestRegistry::from_config(&nexus.lane_catalog, &nexus.governance, &nexus.registry);
    lane_manifests
        .validate_active_coverage_for_catalog(&nexus.lane_catalog)
        .map_err(|error| {
            eyre!("validate lane manifest registry for genesis pre-execution: {error}")
        })?;
    state
        .install_materialized_lane_manifests_for_catalog(
            &Arc::new(lane_manifests),
            &nexus.lane_catalog,
            &nexus.governance,
        )
        .map_err(|error| eyre!("install genesis lane manifest authority: {error}"))?;
    state.install_lane_compliance_engine(lane_compliance);
    Ok(())
}
fn resign_genesis(
    template: &iroha_data_model::block::SignedBlock,
    genesis_key_pair: &KeyPair,
) -> iroha_data_model::block::SignedBlock {
    // Preserve the complete proposal or executed object, including internal
    // outputs, source context, AXT/FASTPQ data and fragment accounting. Signing never rebuilds
    // results or restores outputs invalidated by a proposal change.
    let mut signed = template.clone();
    let signature = iroha_data_model::block::BlockSignature::new(
        0,
        SignatureOf::try_from_hash(genesis_key_pair.private_key(), signed.hash())
            .expect("sign exact genesis proposal header"),
    );
    signed
        .replace_signatures(
            iroha_data_model::block::BlockSignatures::try_from_iter([signature])
                .expect("at most 31 block signatures"),
        )
        .expect("replace genesis with its one canonical signature");
    signed
}

#[cfg(test)]
#[path = "genesis_stack_tests.rs"]
mod genesis_stack_tests;

#[cfg(test)]
#[path = "genesis_fixture_policy.rs"]
mod genesis_fixture_policy;

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::state::StateReadOnly;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        asset::AssetDefinition,
        domain::Domain,
        isi::{GrantBox, RevokeBox},
    };
    use norito::codec::Decode;

    // Genesis uses the same exact four-validator committee and authenticated PoPs
    // as a real minimum-size test network; individual tests may own one key.
    fn genesis_committee_with_key(
        first: &KeyPair,
    ) -> (UniqueVec<PeerId>, Vec<GenesisTopologyEntry>) {
        let mut keys = vec![first.clone()];
        keys.extend((0xC1..=0xC3).map(|seed| {
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic test-network validator")
        }));
        let mut entries = keys
            .into_iter()
            .map(|key| {
                GenesisTopologyEntry::new(
                    PeerId::new(key.public_key().clone()),
                    iroha_crypto::bls_normal_pop_prove(key.private_key())
                        .expect("validator BLS PoP"),
                )
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.peer.cmp(&right.peer));
        let topology = entries
            .iter()
            .map(|entry| entry.peer.clone())
            .collect::<UniqueVec<_>>();
        assert_eq!(topology.len(), 4, "fixture validators must be distinct");
        (topology, entries)
    }
    fn genesis_committee() -> (UniqueVec<PeerId>, Vec<GenesisTopologyEntry>) {
        let first = KeyPair::try_from_seed(vec![0xC0; 32], Algorithm::BlsNormal)
            .expect("deterministic first test-network validator");
        genesis_committee_with_key(&first)
    }
    #[test]
    fn participant_committee_key_instructions_bind_pop_and_restore_permission() {
        init_instruction_registry();
        let (_, entries) = genesis_committee();
        assert!(genesis_participant_committee_key_instructions(&entries, &[]).is_empty());
        let peer = entries[0].peer.clone();
        let instructions =
            genesis_participant_committee_key_instructions(&entries, &[peer.clone()]);
        assert_eq!(instructions.len(), 3);
        let authority = AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
        let expected_permission = Permission::from(CanManageConsensusKeys);
        let Some(GrantBox::Permission(grant)) = instructions[0].as_any().downcast_ref::<GrantBox>()
        else {
            panic!("first instruction must grant consensus-key management");
        };
        assert_eq!(grant.destination(), &authority);
        assert_eq!(grant.object(), &expected_permission);
        let register = instructions[1]
            .as_any()
            .downcast_ref::<RegisterConsensusKey>()
            .expect("second instruction registers the Committee key");
        let id = derive_committee_key_id(peer.public_key());
        assert_eq!(register.id, id);
        assert_eq!(register.record.id, id);
        assert_eq!(register.record.public_key, peer.public_key().clone());
        assert_eq!(
            register.record.pop,
            entries[0].pop_bytes().expect("fixture PoP")
        );
        assert_eq!(register.record.activation_height, 1);
        assert_eq!(register.record.expiry_height, None);
        assert_eq!(register.record.replaces, None);
        assert_eq!(register.record.status, ConsensusKeyStatus::Active);
        let Some(RevokeBox::Permission(revoke)) =
            instructions[2].as_any().downcast_ref::<RevokeBox>()
        else {
            panic!("last instruction must revoke consensus-key management");
        };
        assert_eq!(revoke.destination(), &authority);
        assert_eq!(revoke.object(), &expected_permission);
    }
    // Adversarial wire fixture only: production cannot mutate the fragment count
    // independently of its one complete execution-output owner.
    #[derive(norito::NoritoSchema, norito::codec::Decode, norito::codec::Encode)]
    #[norito_schema(name = "iroha_test_network::config::tests::MutableGenesisWire")]
    struct MutableGenesisWire {
        signatures: iroha_data_model::block::BlockSignatures,
        payload: iroha_data_model::block::BlockPayload,
        result: Option<iroha_data_model::block::BlockResult>,
        commit_certificate: Option<iroha_data_model::block::CommitCertificate>,
    }
    fn set_fixture_fragment_count(block: &mut iroha_data_model::block::SignedBlock, count: u64) {
        use norito::codec::{DecodeAll, Encode};
        let bytes = block.encode();
        let mut wire = MutableGenesisWire::decode_all(&mut bytes.as_slice())
            .expect("decode complete genesis mutation fixture");
        wire.result
            .as_mut()
            .expect("fixture is executed")
            .committed_fragment_count = count;
        *block = iroha_data_model::block::SignedBlock::decode_all(&mut wire.encode().as_slice())
            .expect("fragment mutation remains structurally decodable");
    }
    #[test]
    fn base_config_enables_confidential_verification() {
        let table = super::base_iroha_config();
        let confidential = table
            .get("confidential")
            .and_then(|value| value.as_table())
            .expect("confidential section present");
        assert_eq!(
            confidential
                .get("enabled")
                .and_then(|value| value.as_bool()),
            Some(true),
            "`confidential.enabled` must be true for validator peers"
        );
    }
    #[test]
    fn base_config_enables_extended_telemetry() {
        let table = super::base_iroha_config();
        assert_eq!(
            table
                .get("telemetry_profile")
                .and_then(|value| value.as_str()),
            Some("extended"),
            "test networks should expose expensive telemetry metrics"
        );
    }
    #[test]
    fn base_config_applies_bounded_storage_caps() {
        for sora_enabled in [false, true] {
            let mut base = base_iroha_config();
            if sora_enabled {
                let lanes = (0_i64..3)
                    .map(|index| {
                        toml::Value::Table(
                            Table::new()
                                .write("index", index)
                                .write("alias", format!("storage-budget-{index}"))
                                .write("dataspace", "universal")
                                .write("visibility", "public"),
                        )
                    })
                    .collect::<Vec<_>>();
                base = base
                    .write(["nexus", "lane_count"], 3_i64)
                    .write(["nexus", "lane_catalog"], toml::Value::Array(lanes));
            }
            let layers = vec![base];
            assert_eq!(crate::config_requires_sora_profile(&layers), sora_enabled);
            let (_peer_directory, _peer, merged) =
                crate::sora_profile_runtime_config_fixture(&layers);
            let actual = crate::parse_actual_config_for_genesis_result(merged, &layers)
                .expect("test network storage config must parse");
            assert!(!actual.torii.sorafs_storage.enabled);
            assert_eq!(
                actual
                    .nexus
                    .storage
                    .local_budget_bytes
                    .map(|bytes| bytes.get()),
                Some(1_073_741_824)
            );
            assert_eq!(
                actual
                    .nexus
                    .storage
                    .effective_local_budget_bytes
                    .map(|bytes| bytes.get()),
                Some(1_073_741_824)
            );
            assert_eq!(actual.kura.max_disk_usage_bytes.get(), 375_809_640);
            assert_eq!(actual.tiered_state.max_cold_bytes.get(), 214_748_364);
            assert_eq!(
                actual.torii.sorafs_storage.max_capacity_bytes.get(),
                483_183_820
            );
            assert_eq!(
                actual.nexus.storage.budget_enforce_interval_blocks,
                iroha_config::parameters::defaults::nexus::storage::BUDGET_ENFORCE_INTERVAL_BLOCKS
            );
        }
    }
    #[test]
    fn base_config_preserves_caller_storage_budget_and_smaller_component_cap() {
        let layers = vec![
            base_iroha_config(),
            Table::new()
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    2_147_483_648_i64,
                )
                .write(["kura", "max_disk_usage_bytes"], 4_096_i64),
        ];
        let (_peer_directory, _peer, merged) = crate::sora_profile_runtime_config_fixture(&layers);
        let actual = crate::parse_actual_config_for_genesis_result(merged, &layers)
            .expect("caller storage overrides must parse");
        assert_eq!(
            actual
                .nexus
                .storage
                .local_budget_bytes
                .map(|bytes| bytes.get()),
            Some(2_147_483_648)
        );
        assert_eq!(
            actual
                .nexus
                .storage
                .effective_local_budget_bytes
                .map(|bytes| bytes.get()),
            Some(2_147_483_648)
        );
        assert_eq!(actual.kura.max_disk_usage_bytes.get(), 4_096);
        assert_eq!(actual.tiered_state.max_cold_bytes.get(), 429_496_729);
        assert_eq!(
            actual.torii.sorafs_storage.max_capacity_bytes.get(),
            966_367_641
        );
    }
    #[test]
    fn builds_signed_genesis_block() {
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let block = genesis(Vec::new(), topology, entries);
        assert!(block.0.signatures().next().is_some());
        assert!(
            block.0.has_results(),
            "genesis block must carry execution results"
        );
        assert!(
            block
                .0
                .output_results()
                .all(|result| result.as_ref().is_ok()),
            "genesis transactions should execute successfully"
        );
    }
    #[test]
    fn minimal_genesis_seeds_neutral_first_release_hijiri_parameters() {
        init_instruction_registry();
        let (topology, entries) = genesis_committee();
        let (block, _, _, _) = build_minimal_genesis_unexecuted(
            Vec::new(),
            topology,
            entries,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
        );
        let mut hijiri_parameters = Vec::new();
        for transaction in block.0.external_transactions() {
            let Executable::Instructions(instructions) = transaction.instructions() else {
                continue;
            };
            for instruction in instructions {
                let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>()
                else {
                    continue;
                };
                let Parameter::Custom(custom) = set_parameter.inner() else {
                    continue;
                };
                if custom.id() != &HijiriParametersV1::parameter_id() {
                    continue;
                }
                hijiri_parameters.push(
                    HijiriParametersV1::from_custom_parameter(custom)
                        .expect("decode test-network genesis Hijiri parameters")
                        .expect("test-network genesis must preserve the reserved Hijiri identity"),
                );
            }
        }
        assert_eq!(
            hijiri_parameters,
            vec![HijiriParametersV1::first_release_genesis()],
            "test-network genesis must seed exactly one neutral first-release Hijiri snapshot"
        );
    }
    #[test]
    fn parameter_only_addition_does_not_create_empty_genesis_transaction() {
        init_instruction_registry();
        let (topology, entries) = genesis_committee();
        let parameter = Parameter::Block(
            iroha_data_model::parameter::system::BlockParameter::MaxTransactions(
                std::num::NonZeroU64::new(17).expect("non-zero test transaction limit"),
            ),
        );
        let (baseline, _, _, _) = build_minimal_genesis_unexecuted(
            Vec::new(),
            topology.clone(),
            entries.clone(),
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
        );
        let (with_parameter, _, _, _) = build_minimal_genesis_unexecuted(
            vec![vec![InstructionBox::from(SetParameter::new(
                parameter.clone(),
            ))]],
            topology,
            entries,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
        );

        assert_eq!(
            with_parameter.0.external_transactions().count(),
            baseline.0.external_transactions().count(),
            "routing a parameter into the authoritative snapshot must not leave an empty transaction"
        );
        assert!(with_parameter.0.external_transactions().any(|transaction| {
            let Executable::Instructions(instructions) = transaction.instructions() else {
                return false;
            };
            instructions.iter().any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<SetParameter>()
                    .is_some_and(|set_parameter| set_parameter.inner() == &parameter)
            })
        }));
    }
    #[test]
    fn generated_global_bootstrap_keeps_grants_before_exact_soracloud_balances() {
        init_instruction_registry();
        let (topology, entries) = genesis_committee();
        let (_, _, _, _, raw) = build_minimal_genesis_unexecuted_with_post_topology(
            Vec::new(),
            Vec::new(),
            topology,
            entries,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            super::chain_id(),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(iroha_core::state::default_genesis_confidential_policy_hash()),
        );
        let grant_phases = raw
            .transactions()
            .iter()
            .enumerate()
            .filter(|(_, transaction)| {
                transaction
                    .instructions()
                    .iter()
                    .any(|instruction| instruction.as_any().is::<GrantBox>())
            })
            .collect::<Vec<_>>();
        assert_eq!(grant_phases.len(), 1, "built-in grants have one owner");
        let (phase_index, phase) = grant_phases[0];
        assert!(phase_index > 0, "initial registration stays separate");
        assert!(phase.topology().is_empty(), "topology has its own owner");
        let grant_count = phase
            .instructions()
            .iter()
            .take_while(|instruction| instruction.as_any().is::<GrantBox>())
            .count();
        assert_eq!(grant_count, 22, "all built-in grants precede balances");
        let agent_wallet: AssetDefinitionId = "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().unwrap();
        let shared_lease: AssetDefinitionId = "5PeSrQmLNwwKtruJvDZrbrm9RuMw".parse().unwrap();
        let mut expected = vec![
            InstructionBox::from(Register::asset_definition(AssetDefinition::numeric(
                agent_wallet.clone(),
                "soracloud_agent_wallet".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ))),
            InstructionBox::from(Register::asset_definition(AssetDefinition::numeric(
                shared_lease.clone(),
                "soracloud_hf_lease".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ))),
        ];
        for account in BTreeSet::from([
            sanitize_account_id(&ALICE_ID),
            sanitize_account_id(&BOB_ID),
            sanitize_account_id(&CARPENTER_ID),
        ]) {
            expected.push(
                Mint::asset_quantity(
                    500_000_u32,
                    AssetId::new(agent_wallet.clone(), account.clone()),
                )
                .into(),
            );
            expected.push(
                Mint::asset_quantity(500_000_u32, AssetId::new(shared_lease.clone(), account))
                    .into(),
            );
        }
        assert_eq!(&phase.instructions()[grant_count..], expected);
        assert!(
            raw.transactions()[phase_index - 1]
                .instructions()
                .iter()
                .any(|instruction| instruction
                    .as_any()
                    .is::<iroha_data_model::isi::TransferBox>())
        );
    }
    #[test]
    fn generated_global_bootstrap_preserves_caller_batches_at_exact_input_limit() {
        use iroha_data_model::{Level, isi::Log};

        init_instruction_registry();
        let extra = (0..3)
            .map(|index| {
                vec![InstructionBox::from(Log::new(
                    Level::INFO,
                    format!("before-{index}"),
                ))]
            })
            .collect::<Vec<_>>();
        let post = (0..2)
            .map(|index| {
                vec![
                    InstructionBox::from(Log::new(Level::INFO, format!("after-{index}-first"))),
                    InstructionBox::from(Log::new(Level::INFO, format!("after-{index}-second"))),
                ]
            })
            .collect::<Vec<_>>();
        let (topology, entries) = genesis_committee();
        let (block, _, _, _, raw) = build_minimal_genesis_unexecuted_with_post_topology(
            extra.clone(),
            post.clone(),
            topology,
            entries.clone(),
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            super::chain_id(),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(iroha_core::state::default_genesis_confidential_policy_hash()),
        );
        assert_eq!(
            block.0.external_transactions().count(),
            iroha_data_model::parameter::FastpqSourcePolicyV1::BOOTSTRAP_NETWORK_INPUTS as usize,
            "the authored draft uses exactly the fixed eleven network inputs"
        );
        let topology_index = raw
            .transactions()
            .iter()
            .position(|tx| !tx.topology().is_empty())
            .unwrap();
        assert_eq!(raw.transactions()[topology_index].topology(), entries);
        assert!(raw.transactions()[topology_index].instructions().is_empty());
        for (transaction, original) in raw.transactions()
            [topology_index - extra.len()..topology_index]
            .iter()
            .zip(&extra)
        {
            assert_eq!(transaction.instructions(), original);
            assert!(transaction.topology().is_empty());
        }
        for (transaction, original) in raw.transactions()
            [topology_index + 1..topology_index + 1 + post.len()]
            .iter()
            .zip(&post)
        {
            assert_eq!(transaction.instructions(), original);
            assert!(transaction.topology().is_empty());
        }
        for original in extra.iter().chain(&post) {
            assert_eq!(block.0.external_transactions().filter(|transaction| {
                matches!(transaction.instructions(), Executable::Instructions(batch) if batch.as_ref() == original.as_slice())
            }).count(), 1, "each caller batch enters the signed block exactly once");
        }
    }
    #[test]
    fn generated_global_bootstrap_refuses_caller_overflow_without_repacking() {
        use iroha_data_model::{Level, isi::Log};

        init_instruction_registry();
        let extra = (0..6)
            .map(|index| {
                vec![InstructionBox::from(Log::new(
                    Level::INFO,
                    format!("caller-{index}"),
                ))]
            })
            .collect::<Vec<_>>();
        let original = extra.clone();
        let (topology, entries) = genesis_committee();
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            build_minimal_genesis_unexecuted_with_post_topology(
                extra.clone(),
                Vec::new(),
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
                super::chain_id(),
                None,
                None,
                None,
                None,
                None,
                None,
                Some(iroha_core::state::default_genesis_confidential_policy_hash()),
            )
        }))
        .expect_err("the generator must refuse a twelfth caller-authored input");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(message.contains("12 network inputs"), "{message}");
        assert!(message.contains("FASTPQ bootstrap limit 11"), "{message}");
        assert_eq!(
            extra, original,
            "refusal leaves the authored batches intact"
        );
    }
    #[test]
    fn genesis_allows_wonderland_assets_from_genesis_authority() {
        use iroha_core::block::check_genesis_block;
        use iroha_data_model::{asset::AssetDefinition, isi::Register};
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let asset_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "genesis_extra".parse().unwrap(),
        );
        let instructions = vec![InstructionBox::from(Register::asset_definition(
            AssetDefinition::numeric(
                asset_definition_id,
                "Genesis Extra".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ),
        ))];
        let block = genesis(vec![instructions], topology, entries);
        let genesis_account = AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
        check_genesis_block(&block.0, &genesis_account)
            .expect("genesis authority should be permitted to seed wonderland assets");
    }
    #[test]
    fn ensure_genesis_results_populates_when_preexecution_succeeds() {
        init_instruction_registry();
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let (mut block, genesis_account, topology_vec, genesis_key_pair, _) =
            super::genesis_fixture_policy::policy_bound_proposal(
                Vec::new(),
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            );
        assert!(
            block.0.is_resultless_proposal(),
            "freshly built genesis must be an explicitly resultless proposal"
        );
        super::ensure_genesis_results(
            &mut block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        );
        assert!(
            block.0.has_results(),
            "ensure_genesis_results must attach execution results"
        );
        assert!(
            block
                .0
                .output_results()
                .all(|result| result.as_ref().is_ok()),
            "pre-executed genesis should yield successful outcomes"
        );
    }
    #[test]
    fn resign_executed_genesis_preserves_committed_fragment_count() {
        init_instruction_registry();
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let (mut block, genesis_account, topology_vec, genesis_key_pair, _) =
            super::genesis_fixture_policy::policy_bound_proposal(
                Vec::new(),
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            );
        super::ensure_genesis_results(
            &mut block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        );
        let minimum_count =
            u64::try_from(block.0.output_results().count()).expect("genesis result count fits u64");
        let preserved_count = block
            .0
            .committed_fragment_count()
            .expect("executed genesis carries its committed fragment count");
        assert!(
            preserved_count >= minimum_count,
            "execution-derived committed count must cover every result row"
        );
        let executed_before_resigning = block.0.clone();
        let wrong_key = KeyPair::try_from_seed(vec![0xB5; 32], Algorithm::Ed25519)
            .expect("deterministic unrelated genesis signer");
        let wrong_signature = iroha_data_model::block::BlockSignature::new(
            0,
            SignatureOf::try_from_hash(wrong_key.private_key(), block.0.hash()).unwrap(),
        );
        block
            .0
            .replace_signatures(
                iroha_data_model::block::BlockSignatures::try_from_iter([wrong_signature])
                    .expect("at most 31 block signatures"),
            )
            .unwrap();
        assert!(!super::genesis_signature_is_canonical(
            &block.0,
            &genesis_key_pair
        ));
        assert!(super::genesis_results_are_canonical(&block.0));
        let rebuilt = super::resign_genesis(&block.0, &genesis_key_pair);
        assert_eq!(
            rebuilt, executed_before_resigning,
            "re-signing must preserve every complete output field"
        );
        assert_eq!(
            rebuilt.committed_fragment_count(),
            Some(preserved_count),
            "re-signing genesis must preserve the execution-derived committed fragment count"
        );
        assert!(
            super::genesis_signature_is_canonical(&rebuilt, &genesis_key_pair),
            "the canonical signature is restored without rebuilding complete outputs"
        );
        let mut extra_internal_fragments = rebuilt;
        let augmented_count = preserved_count
            .checked_add(1)
            .expect("genesis fixture committed count has room for an internal fragment");
        set_fixture_fragment_count(&mut extra_internal_fragments, augmented_count);
        assert!(
            super::genesis_results_are_canonical(&extra_internal_fragments),
            "deterministic internal fragments may increase the committed count beyond the result count"
        );
    }
    #[test]
    #[should_panic(expected = "provided genesis execution results must be complete and canonical")]
    fn ensure_genesis_results_rejects_noncanonical_fragment_count() {
        init_instruction_registry();
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let (mut block, genesis_account, topology_vec, genesis_key_pair, _) =
            super::genesis_fixture_policy::policy_bound_proposal(
                Vec::new(),
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            );
        super::ensure_genesis_results(
            &mut block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        );
        let expected_count =
            u64::try_from(block.0.output_results().len()).expect("genesis result count fits u64");
        assert_ne!(
            expected_count, 0,
            "fixture must execute at least one entrypoint"
        );
        set_fixture_fragment_count(&mut block.0, 0);
        super::ensure_genesis_results(
            &mut block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        );
    }
    #[test]
    fn ensure_genesis_results_reexecutes_after_proposal_mutation() {
        init_instruction_registry();
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let (mut block, genesis_account, topology_vec, genesis_key_pair, manifest) =
            super::genesis_fixture_policy::policy_bound_proposal(
                Vec::new(),
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            );
        super::ensure_genesis_results(
            &mut block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        );
        assert!(
            block.0.has_results(),
            "precondition: genesis has execution results"
        );
        let mut changed_policies = block
            .0
            .da_proof_policies()
            .expect("genesis carries the active DA policies")
            .policies()
            .to_vec();
        changed_policies[0].alias = "reexecuted-default".to_owned();
        let changed_policies = DaProofPolicyBundle::new(changed_policies);
        assert_ne!(
            block.0.da_proof_policies(),
            Some(&changed_policies),
            "fixture must change the proposal while retaining valid DA policy"
        );
        block
            .0
            .set_da_proof_policies(Some(changed_policies.clone()));
        assert!(
            !block.0.has_results(),
            "proposal mutation must invalidate prior complete execution outputs"
        );
        let stale_signature = block
            .0
            .signatures()
            .next()
            .expect("genesis signature present")
            .signature()
            .verify_hash(genesis_key_pair.public_key(), block.0.hash())
            .is_err();
        assert!(
            stale_signature,
            "mutating header should stale existing signature"
        );
        let error = super::populate_genesis_results(
            &block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        )
        .expect_err("strict preexecution must reject the stale proposal signature");
        assert!(
            format!("{error:#}").contains("must be signed with genesis private key"),
            "the strict verifier must reject the stale signature before execution: {error:#}"
        );
        // A new DA alias changes the actual staged policy. A refreshed signature
        // alone must still reject the old policy commitment. Only this fixture's
        // explicit construction stage may bind and sign its new manifest.
        let signed_mutation = GenesisBlock(super::resign_genesis(&block.0, &genesis_key_pair));
        let policy_error = super::populate_genesis_results(
            &signed_mutation,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        )
        .expect_err("signed DA mutation must not silently rewrite policy authority");
        assert!(matches!(
            policy_error
                .downcast_ref::<Box<iroha_core::block::BlockValidationError>>()
                .map(Box::as_ref),
            Some(iroha_core::block::BlockValidationError::GenesisPolicyMismatch { .. })
        ));
        (block, _) = super::genesis_fixture_policy::bind_proposal(
            signed_mutation,
            manifest,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
        )
        .expect("explicitly bind the mutated fixture's new DA policy");
        super::ensure_genesis_results(
            &mut block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        );
        assert!(
            super::genesis_results_are_canonical(&block.0),
            "changed proposal must be executed again with complete typed outputs"
        );
        assert_eq!(
            block.0.da_proof_policies(),
            Some(&changed_policies),
            "reexecution must retain the exact changed proposal metadata"
        );
        let signatures: Vec<_> = block.0.signatures().collect();
        assert_eq!(
            signatures.len(),
            1,
            "genesis should keep a single canonical signature"
        );
        assert!(
            signatures[0]
                .signature()
                .verify_hash(genesis_key_pair.public_key(), block.0.hash())
                .is_ok(),
            "genesis signature must be refreshed after metadata mutation"
        );
    }
    #[test]
    fn populate_genesis_results_executes_without_fallback() {
        init_instruction_registry();
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let (block, genesis_account, topology_vec, genesis_key_pair, _) =
            super::genesis_fixture_policy::policy_bound_proposal(
                Vec::new(),
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            );
        let executed = super::populate_genesis_results(
            &block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        )
        .expect("genesis pre-execution should succeed");
        assert!(
            executed
                .output_results()
                .all(|result| result.as_ref().is_ok()),
            "pre-executed genesis should not carry errors for valid proof-bearing peers"
        );
    }
    #[test]
    fn preexecuted_genesis_ignores_validity_values_of_the_supplied_configuration() {
        // The supplied ZK and pipeline settings are a node's own: only their
        // local resources reach the staged State. A divergent validity value
        // (proof size limit, verification gas, overlay limit, query fetch size)
        // changes neither the executed genesis nor the policy hashes it binds.
        init_instruction_registry();
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let (block, genesis_account, topology_vec, genesis_key_pair, _) =
            super::genesis_fixture_policy::policy_bound_proposal(
                Vec::new(),
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            );
        let default_zk = iroha_core::state::default_zk_config();
        let default_pipeline = iroha_config::parameters::actual::Pipeline::default();
        let mut divergent_zk = default_zk.clone();
        divergent_zk.max_proof_size_bytes = 1;
        divergent_zk.max_verify_calls_per_block = 1;
        divergent_zk.gas.proof_base = 1;
        divergent_zk.gas.per_proof_byte = 1_000;
        divergent_zk.pipa_r.max_proof_bytes = 1;
        // A local resource, which a node may set.
        divergent_zk.trace.worker_threads = 1;
        let mut divergent_pipeline = default_pipeline.clone();
        divergent_pipeline.overlay_max_instructions = 1;
        divergent_pipeline.query_max_fetch_size = 1;
        divergent_pipeline.ivm_max_cycles_upper_bound =
            core::num::NonZeroU64::new(7).expect("nonzero cycle bound");
        // A local resource, which a node may set.
        divergent_pipeline.stateless_cache_cap = 3;
        let preexecute = |pipeline: &iroha_config::parameters::actual::Pipeline,
                          zk: &iroha_config::parameters::actual::Zk| {
            super::preexecute_genesis_on_current_thread(
                &block,
                &genesis_account,
                &topology_vec,
                &genesis_key_pair,
                Some(pipeline),
                None,
                Some(zk),
                None,
            )
            .expect("genesis pre-execution should succeed")
        };
        let (default_block, default_hashes) = preexecute(&default_pipeline, &default_zk);
        let (divergent_block, divergent_hashes) = preexecute(&divergent_pipeline, &divergent_zk);
        assert_eq!(
            divergent_hashes, default_hashes,
            "the policy hashes of a staged genesis are not a function of node validity settings"
        );
        assert_eq!(
            divergent_block
                .encode_wire()
                .expect("executed genesis encodes"),
            default_block
                .encode_wire()
                .expect("executed genesis encodes"),
            "the executed genesis is identical under divergent node validity settings"
        );
        assert!(
            divergent_block
                .output_results()
                .all(|result| result.as_ref().is_ok())
        );
        // The same settings installed the way the function installs them: the
        // validity values are the protocol default, the local resources are kept.
        let mut state = iroha_core::state::State::new_for_testing(
            iroha_core::state::World::default(),
            iroha_core::kura::Kura::blank_kura_for_testing(),
            iroha_core::query::store::LiveQueryStore::start_test(),
        );
        state
            .install_node_pipeline(divergent_pipeline.clone())
            .expect("node pipeline resources install");
        state
            .install_node_zk(divergent_zk.clone())
            .expect("node ZK resources install");
        let view = state.view();
        assert_eq!(
            view.zk.max_proof_size_bytes,
            default_zk.max_proof_size_bytes
        );
        assert_eq!(view.zk.gas.proof_base, default_zk.gas.proof_base);
        assert_eq!(
            view.zk.pipa_r.max_proof_bytes,
            default_zk.pipa_r.max_proof_bytes
        );
        assert_eq!(view.zk.trace.worker_threads, 1);
        assert_eq!(
            view.pipeline.overlay_max_instructions,
            default_pipeline.overlay_max_instructions
        );
        assert_eq!(
            view.pipeline.query_max_fetch_size,
            default_pipeline.query_max_fetch_size
        );
        assert_eq!(view.pipeline.stateless_cache_cap, 3);
    }
    #[test]
    fn populate_genesis_results_accepts_block_proof_policies() {
        use iroha_data_model::nexus::{LaneCatalog, LaneConfig};
        use iroha_model_base::topology::LaneId;
        use std::num::NonZeroU32;
        init_instruction_registry();
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let lane_count = NonZeroU32::new(2).expect("non-zero lane count");
        let lane0 = LaneConfig {
            id: LaneId::from_lane_index(0, lane_count).expect("lane 0 id"),
            alias: "alpha".to_string(),
            ..LaneConfig::default()
        };
        let lane1 = LaneConfig {
            id: LaneId::from_lane_index(1, lane_count).expect("lane 1 id"),
            alias: "beta".to_string(),
            ..LaneConfig::default()
        };
        let catalog =
            LaneCatalog::new(lane_count, vec![lane0, lane1]).expect("lane catalog should validate");
        let nexus = ActualNexus {
            lane_catalog: catalog.clone(),
            lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&catalog),
            ..Default::default()
        };
        let policies = iroha_core::da::proof_policy_bundle(&nexus.lane_config);
        let (block, genesis_account, topology_vec, genesis_key_pair, manifest) =
            super::build_minimal_genesis_unexecuted_with_post_topology(
                Vec::new(),
                Vec::new(),
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
                super::chain_id(),
                None,
                Some(policies),
                None,
                None,
                None,
                None,
                Some(iroha_core::state::default_genesis_confidential_policy_hash()),
            );
        let (block, _) = super::genesis_fixture_policy::bind_proposal(
            block,
            manifest,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
        )
        .expect("construct a policy-bound resultless fixture under its intended configuration");
        let executed = super::populate_genesis_results(
            &block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            None,
            None,
        )
        .expect("genesis pre-execution should accept proof-policy-derived catalogs");
        assert!(
            executed
                .output_results()
                .all(|result| result.as_ref().is_ok()),
            "pre-executed genesis should succeed with custom lane config"
        );
    }
    #[test]
    fn populate_genesis_results_uses_supplied_nexus_config_for_custom_staking_genesis() {
        use iroha_core::block::{BlockValidationError, InvalidGenesisError};
        use iroha_data_model::{
            ValidationFail,
            isi::{
                error::InstructionExecutionError,
                staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
            },
            parameter::system::SumeragiNposParameters,
            transaction::error::TransactionRejectionReason,
        };
        use iroha_model_base::topology::LaneId;
        use std::num::NonZeroU32;

        init_instruction_registry();
        let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
            iroha_config::parameters::defaults::common::chain_discriminant(),
        );
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let npos = SumeragiNposParameters {
            max_validators: 4,
            ..Default::default()
        };
        let stake_asset_id = npos.xor_asset_definition_id.clone();
        let stake_amount = npos.min_self_bond.clone();
        let escrow_account = AccountId::new(
            KeyPair::from_seed(
                b"custom-genesis-staking-escrow".to_vec(),
                Algorithm::Ed25519,
            )
            .public_key()
            .clone(),
        );
        let nexus = ActualNexus {
            staking: iroha_config::parameters::actual::NexusStaking {
                stake_asset_id: stake_asset_id.to_string(),
                stake_escrow_account_id: escrow_account.to_string(),
                slash_sink_account_id: escrow_account.to_string(),
                min_validator_stake: stake_amount.clone(),
                max_validators: NonZeroU32::new(4).unwrap(),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut resources = vec![
            Register::account(Account::new(escrow_account.clone())).into(),
            Register::asset_definition(AssetDefinition::new(
                stake_asset_id.clone(),
                "XOR".to_owned(),
                NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ))
            .into(),
        ];
        let mut registrations = Vec::new();
        for (index, peer) in topology.iter().enumerate() {
            let validator = AccountId::new(
                KeyPair::from_seed(
                    format!("custom-genesis-staking-validator-{index}").into_bytes(),
                    Algorithm::Ed25519,
                )
                .public_key()
                .clone(),
            );
            resources.push(Register::account(Account::new(validator.clone())).into());
            resources.push(
                Mint::asset_quantity(
                    stake_amount.clone(),
                    AssetId::new(stake_asset_id.clone(), validator.clone()),
                )
                .into(),
            );
            // Global staking uses the validator-role keys installed by the signed topology.
            registrations.push(
                RegisterPublicLaneValidator::new(
                    LaneId::SINGLE,
                    validator.clone(),
                    peer.clone(),
                    validator.clone(),
                    stake_amount.clone(),
                    Metadata::default(),
                    iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                        AssetId::new(stake_asset_id.clone(), validator.clone()),
                        AssetId::new(stake_asset_id.clone(), escrow_account.clone()),
                        stake_amount.clone(),
                    ),
                )
                .into(),
            );
            registrations.push(ActivatePublicLaneValidator::new(LaneId::SINGLE, validator).into());
        }
        let (block, genesis_account, topology_vec, genesis_key_pair, manifest) =
            super::build_minimal_genesis_unexecuted_with_post_topology(
                vec![vec![
                    SetParameter::new(Parameter::Custom(npos.into_custom_parameter())).into(),
                ]],
                vec![resources, registrations],
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
                super::chain_id(),
                None,
                None,
                Some(nexus.clone()),
                None,
                None,
                Some(SumeragiConsensusMode::Npos),
                Some(iroha_core::state::default_genesis_confidential_policy_hash()),
            );
        let expected_rejection_index = block
            .0
            .external_transactions()
            .position(|transaction| {
                let Executable::Instructions(instructions) = transaction.instructions() else {
                    return false;
                };
                instructions
                    .iter()
                    .any(|instruction| instruction.as_any().is::<RegisterPublicLaneValidator>())
            })
            .expect("the signed inputs contain the staking registration source");
        let (block, _) = super::genesis_fixture_policy::bind_proposal(
            block,
            manifest,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            Some(&nexus),
        )
        .expect("construct a policy-bound resultless fixture under its intended configuration");
        assert_eq!(topology_vec.len(), 4);
        assert_eq!(
            super::signed_genesis_consensus_mode(&block).unwrap(),
            WireConsensusMode::Npos
        );
        let original_wire = block.0.encode_wire().unwrap();
        let mut wrong_asset_config = nexus.clone();
        wrong_asset_config.staking.stake_asset_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        )
        .to_string();
        for (config, expected_cause) in [
            (
                None,
                "staking monetary plan does not match its exact current transfer and custody state",
            ),
            (
                Some(&wrong_asset_config),
                "configured staking or reward asset differs from the committed network XOR identity",
            ),
        ] {
            let report = super::populate_genesis_results(
                &block,
                &genesis_account,
                &topology_vec,
                &genesis_key_pair,
                config,
                None,
            )
            .expect_err("signed staking custody requires its supplied Nexus configuration");
            let error = report
                .downcast_ref::<Box<BlockValidationError>>()
                .expect("retain the native validation error");
            let BlockValidationError::InvalidGenesis(InvalidGenesisError::RejectedOutput(
                rejection,
            )) = error.as_ref()
            else {
                panic!("expected an actual staking instruction rejection: {report:#}");
            };
            assert_eq!(rejection.output_index, expected_rejection_index);
            assert!(
                matches!(
                    rejection.reason.as_ref(),
                    TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                        InstructionExecutionError::InvariantViolation(cause)
                    )) if cause.as_ref() == expected_cause
                ),
                "unexpected staking rejection: {report:#}"
            );
            assert!(!block.0.has_results(), "failed outputs remain unpublished");
            assert_eq!(block.0.encode_wire().unwrap(), original_wire);
        }
        let executed = super::populate_genesis_results(
            &block,
            &genesis_account,
            &topology_vec,
            &genesis_key_pair,
            Some(&nexus),
            None,
        )
        .expect("custom staking genesis should succeed with the resolved nexus config");
        assert!(
            executed
                .output_results()
                .all(|result| result.as_ref().is_ok()),
            "pre-executed custom staking genesis should succeed when the builder threads the resolved nexus config"
        );
        assert!(super::genesis_results_are_canonical(&executed));
        assert!(super::genesis_signature_is_canonical(
            &executed,
            &genesis_key_pair
        ));
        assert_eq!(executed.hash(), block.0.hash());
        assert_eq!(block.0.encode_wire().unwrap(), original_wire);
    }
    #[test]
    fn populate_genesis_results_leases_genesis_account_labels() {
        use iroha_data_model::{
            account::rekey::{AccountAlias, AccountAliasDomain},
            isi::{InstructionBox, Register},
        };
        use iroha_model_base::topology::DataSpaceId;
        init_instruction_registry();
        let genesis_key_pair = SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone();
        let ivm_domain: DomainId = DomainId::try_new("ivm", "universal").expect("ivm domain");
        let gas_label: Name = "gas".parse().expect("gas label");
        let gas_account = Account::new(AccountId::new(KeyPair::random().public_key().clone()))
            .with_label(Some(AccountAlias::new(
                gas_label,
                Some(AccountAliasDomain::new(ivm_domain.name().clone())),
                DataSpaceId::UNIVERSAL,
            )));
        let extra_transactions = vec![vec![
            InstructionBox::from(Register::domain(Domain::new(ivm_domain))),
            InstructionBox::from(Register::account(gas_account)),
        ]];
        let bls = KeyPair::random_with_algorithm(iroha_crypto::Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let (block, genesis_account, topology, genesis_key_pair, _) =
            super::genesis_fixture_policy::policy_bound_proposal(
                extra_transactions,
                topology,
                entries,
                genesis_key_pair,
            );
        assert_eq!(
            super::signed_genesis_consensus_mode(&block)
                .expect("canonical minimal genesis must contain exactly one handshake entry"),
            WireConsensusMode::Permissioned
        );
        let executed = super::populate_genesis_results(
            &block,
            &genesis_account,
            &topology,
            &genesis_key_pair,
            None,
            None,
        )
        .expect("genesis pre-execution should lease aliases used by labeled genesis accounts");
        assert!(
            executed
                .output_results()
                .all(|result| result.as_ref().is_ok()),
            "labeled genesis accounts should not fail SNS lease checks"
        );
    }
    #[test]
    fn preexec_overrides_recompute_lane_config_from_policies() {
        use iroha_data_model::da::commitment::{DaProofPolicy, DaProofPolicyBundle, DaProofScheme};
        use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
        use std::num::NonZeroU32;
        let genesis_account = AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
        let genesis_account_entry = Account {
            id: genesis_account,
            metadata: Metadata::default(),
            label: None,
            uaid: None,
            opaque_ids: Vec::new(),
        };
        let query_handle = LiveQueryStore::start_test();
        let world = World::with(
            Vec::<iroha_data_model::domain::Domain>::new(),
            vec![genesis_account_entry],
            Vec::<iroha_data_model::asset::AssetDefinition>::new(),
        );
        let lane_count = NonZeroU32::new(2).expect("non-zero lane count");
        let policy0 = DaProofPolicy {
            lane_id: LaneId::from_lane_index(0, lane_count).expect("lane 0 id"),
            dataspace_id: DataSpaceId::UNIVERSAL,
            alias: "alpha".to_string(),
            proof_scheme: DaProofScheme::MerkleSha256,
        };
        let policy1 = DaProofPolicy {
            lane_id: LaneId::from_lane_index(1, lane_count).expect("lane 1 id"),
            dataspace_id: DataSpaceId::new(7),
            alias: "beta".to_string(),
            proof_scheme: DaProofScheme::MerkleSha256,
        };
        let bundle = DaProofPolicyBundle::new(vec![policy0, policy1]);
        let nexus = super::resolve_preexec_nexus_config(None, Some(&bundle))
            .expect("preexec should resolve proof policy overrides");
        let state = State::new_with_pre_genesis_nexus_for_testing(world, nexus, query_handle);
        super::install_preexec_lane_manifests(&state, None)
            .expect("preexec should install proof-policy-derived lane manifests");
        let view = state.view();
        let nexus = view.nexus();
        let expected =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
        assert_eq!(
            nexus.lane_config.entries().len(),
            expected.entries().len(),
            "lane config must match updated lane catalog"
        );
        for (actual, expected) in nexus
            .lane_config
            .entries()
            .iter()
            .zip(expected.entries().iter())
        {
            assert_eq!(actual.lane_id, expected.lane_id);
            assert_eq!(actual.dataspace_id, expected.dataspace_id);
            assert_eq!(actual.proof_scheme, expected.proof_scheme);
            assert_eq!(actual.alias, expected.alias);
        }
        let manifests = state.lane_manifests.read();
        for lane in nexus.lane_catalog.lanes() {
            assert!(
                manifests.status(lane.id).is_some(),
                "pre-execution manifest registry must be derived from lane {}",
                lane.id.as_u32()
            );
        }
    }
    #[test]
    #[should_panic(expected = "genesis pre-execution must succeed")]
    fn ensure_genesis_results_fails_closed_when_preexecution_fails() {
        init_instruction_registry();
        let (topology, entries) = genesis_committee();
        let (mut block, genesis_account, _, genesis_key_pair) =
            super::build_minimal_genesis_unexecuted(
                Vec::new(),
                topology,
                entries,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            );
        assert!(
            block.0.is_resultless_proposal(),
            "freshly built genesis must be an explicitly resultless proposal"
        );
        super::ensure_genesis_results(
            &mut block,
            &genesis_account,
            &[],
            &genesis_key_pair,
            None,
            None,
        );
    }
    #[test]
    fn genesis_registers_peers_with_pop() {
        use iroha_data_model::{isi::RegisterBox, transaction::Executable};
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let expected = topology.iter().cloned().collect::<BTreeSet<_>>();
        let block = genesis(Vec::new(), topology, entries);
        let mut registered = BTreeSet::new();
        for tx in block.0.external_transactions() {
            match tx.instructions() {
                Executable::Instructions(isi) => {
                    for instr in isi {
                        if let Some(RegisterBox::Peer(register)) =
                            instr.as_any().downcast_ref::<RegisterBox>()
                        {
                            iroha_crypto::bls_normal_pop_verify(
                                register.peer.public_key(),
                                &register.pop,
                            )
                            .expect("registered committee member has its own valid PoP");
                            assert!(
                                registered.insert(register.peer.clone()),
                                "no duplicate registration"
                            );
                        }
                    }
                }
                Executable::ContractCall(_) => {}
                Executable::Ivm(_) => {}
                Executable::IvmProved(_) => {}
                Executable::Batch(_) => {}
            }
        }
        assert_eq!(
            registered, expected,
            "every committee member must be registered exactly once with its authenticated PoP"
        );
    }
    #[test]
    fn genesis_with_crypto_override_embeds_manifest_metadata() {
        use iroha_data_model::{
            isi::SetParameter,
            parameter::{Parameter, system::crypto_metadata},
            transaction::Executable,
        };
        fn embedded_manifest_crypto(block: &GenesisBlock) -> ManifestCrypto {
            for tx in block.0.external_transactions() {
                let Executable::Instructions(instrs) = tx.instructions() else {
                    continue;
                };
                for instr in instrs {
                    let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>() else {
                        continue;
                    };
                    let Parameter::Custom(custom) = set_param.inner() else {
                        continue;
                    };
                    if custom.id() == &crypto_metadata::manifest_meta_id() {
                        return custom
                            .payload()
                            .try_into_any()
                            .expect("decode embedded crypto manifest");
                    }
                }
            }
            panic!("crypto manifest metadata parameter not found in genesis");
        }
        let allowed_signing = vec![
            Algorithm::Ed25519,
            Algorithm::Secp256k1,
            Algorithm::BlsNormal,
        ];
        let expected =
            super::manifest_crypto_from_actual(&iroha_config::parameters::actual::Crypto {
                allowed_curve_ids:
                    iroha_config::parameters::defaults::crypto::derive_curve_ids_from_algorithms(
                        &allowed_signing,
                    ),
                allowed_signing,
                ..Default::default()
            });
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let block = super::genesis_with_keypair_and_post_topology_with_policies(
            Vec::new(),
            Vec::new(),
            topology,
            entries,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            super::chain_id(),
            Some(expected.clone()),
            None,
            None,
            None,
            None,
            None,
            Some(iroha_core::state::default_genesis_confidential_policy_hash()),
        );
        assert_eq!(embedded_manifest_crypto(&block), expected);
    }
    #[test]
    fn minimal_genesis_contains_fixture_accounts() {
        use iroha_data_model::{Identifiable, isi::RegisterBox, transaction::Executable};
        init_instruction_registry();
        fn assert_registers_fixture_accounts(
            topology: iroha_primitives::unique_vec::UniqueVec<PeerId>,
            pops: Vec<GenesisTopologyEntry>,
        ) {
            let (block, _, _, _) = build_minimal_genesis_unexecuted(
                Vec::new(),
                topology,
                pops,
                SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            );
            let mut saw_alice = false;
            let mut saw_carpenter = false;
            for tx in block.0.external_transactions() {
                if let Executable::Instructions(instrs) = tx.instructions() {
                    for instr in instrs {
                        if let Some(RegisterBox::Account(isi)) =
                            instr.as_any().downcast_ref::<RegisterBox>()
                            && isi.object().id() == &*ALICE_ID
                        {
                            saw_alice = true;
                            continue;
                        }
                        if let Some(RegisterBox::Account(isi)) =
                            instr.as_any().downcast_ref::<RegisterBox>()
                            && isi.object().id().expect_single_signatory()
                                == CARPENTER_KEYPAIR.public_key()
                        {
                            saw_carpenter = true;
                            continue;
                        }
                    }
                }
            }
            assert!(saw_alice, "minimal genesis should register ALICE_ID");
            assert!(
                saw_carpenter,
                "minimal genesis should register a fixture account in garden_of_live_flowers"
            );
        }
        let (topology, entries) = genesis_committee();
        assert_registers_fixture_accounts(topology, entries);
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        assert_registers_fixture_accounts(topology, entries);
    }
    #[test]
    fn genesis_grants_alice_bootstrap_management_permissions() {
        use iroha_data_model::{isi::GrantBox, transaction::Executable};
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let block = genesis(Vec::new(), topology, entries);
        let alice_id = sanitize_account_id(&ALICE_ID);
        let genesis_id = sanitize_account_id(&AccountId::new(
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone(),
        ));
        let mut saw_soracloud_permission = false;
        let mut saw_parliament_permission = false;
        let mut saw_read_all_permission = false;
        let mut saw_alice_hijiri_permission = false;
        let mut saw_genesis_hijiri_permission = false;
        for tx in block.0.external_transactions() {
            let Executable::Instructions(instrs) = tx.instructions() else {
                continue;
            };
            for instr in instrs {
                let Some(GrantBox::Permission(grant)) = instr.as_any().downcast_ref::<GrantBox>()
                else {
                    continue;
                };
                if grant.destination == alice_id && grant.object.name() == "CanManageSoracloud" {
                    saw_soracloud_permission = true;
                }
                if grant.destination == alice_id && grant.object.name() == "CanManageParliament" {
                    saw_parliament_permission = true;
                }
                if grant.destination == alice_id && grant.object.name() == "CanReadAllLedgerData" {
                    saw_read_all_permission = true;
                }
                if grant.object.name() == "CanSetHijiriParameters" {
                    saw_alice_hijiri_permission |= grant.destination == alice_id;
                    saw_genesis_hijiri_permission |= grant.destination == genesis_id;
                }
            }
            if saw_soracloud_permission
                && saw_parliament_permission
                && saw_read_all_permission
                && saw_alice_hijiri_permission
                && saw_genesis_hijiri_permission
            {
                break;
            }
        }
        assert!(
            saw_soracloud_permission,
            "default test-network genesis should grant ALICE_ID CanManageSoracloud"
        );
        assert!(
            saw_parliament_permission,
            "default test-network genesis should grant ALICE_ID CanManageParliament"
        );
        assert!(
            saw_read_all_permission,
            "default test-network genesis should grant ALICE_ID CanReadAllLedgerData"
        );
        assert!(
            saw_alice_hijiri_permission,
            "default test-network genesis should grant ALICE_ID CanSetHijiriParameters"
        );
        assert!(
            saw_genesis_hijiri_permission,
            "default test-network genesis should grant the genesis authority CanSetHijiriParameters"
        );
    }
    #[test]
    fn sanitize_strings_removes_whitespace() {
        let mut v = norito::json!({"name": "foo bar"});
        super::sanitize_strings(&mut v);
        assert_eq!(v["name"], norito::json!("foo_bar"));
    }
    #[test]
    fn sanitize_account_id_strips_whitespace() {
        let raw = "foo bar@baz qux";
        let sanitized = super::sanitize_account_id_str(raw);
        assert_eq!(sanitized, "foo_bar@baz_qux");
    }
    #[test]
    fn genesis_contains_upgrade_instruction() {
        use iroha_data_model::{isi::Upgrade, transaction::Executable};
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let block = genesis(Vec::new(), topology, entries);
        let first_tx = block.0.external_transactions().next().unwrap();
        let Executable::Instructions(isi) = first_tx.instructions() else {
            panic!("expected instructions in first transaction");
        };
        let sample = iroha_test_samples::sample_ivm_path("default_executor");
        let has_sample = std::fs::metadata(&sample)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        if has_sample {
            assert_eq!(isi.len(), 1);
            assert!(isi[0].as_any().downcast_ref::<Upgrade>().is_some());
        } else {
            // When no sample executor is available, we skip the upgrade in genesis.
            // Ensure we still have some instructions (e.g., domain/account bootstrap).
            assert!(!isi.is_empty());
        }
    }
    #[test]
    fn genesis_includes_confidential_digest() {
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let block = genesis(Vec::new(), topology, entries);
        assert!(
            block.0.header().confidential_features().is_some(),
            "genesis block must advertise confidential feature digest"
        );
    }
    #[test]
    fn genesis_confidential_digest_tracks_registered_verifying_keys() {
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let (topology, entries) = genesis_committee_with_key(&bls);
        let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "offline-test");
        let mut record = iroha_data_model::proof::VerifyingKeyRecord::new(
            1,
            "offline-test",
            iroha_data_model::zk::BackendTag::NativePipaRPasta,
            "pallas",
            [0xAA; 32],
            [0xBB; 32],
        );
        record.status = iroha_data_model::confidential::ConfidentialStatus::Active;
        record.gas_schedule_id = Some("native_pipa_r_default".into());
        let register = InstructionBox::from(
            iroha_data_model::isi::verifying_keys::RegisterVerifyingKey { id: vk_id, record },
        );
        let expected = iroha_genesis::compute_genesis_vk_set_hash([&register])
            .expect("compute verifier set hash")
            .expect("active verifier registry hash");
        let (block, _, _, _, _) = super::build_minimal_genesis_unexecuted_with_post_topology(
            Vec::new(),
            vec![vec![register]],
            topology,
            entries,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            super::chain_id(),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(iroha_core::state::default_genesis_confidential_policy_hash()),
        );
        let declared_hash = block
            .0
            .external_transactions()
            .find_map(|tx| {
                use iroha_data_model::{isi::SetParameter, transaction::Executable};
                let Executable::Instructions(instrs) = tx.instructions() else {
                    return None;
                };
                instrs.iter().find_map(|instr| {
                    let set_parameter = instr.as_any().downcast_ref::<SetParameter>()?;
                    let Parameter::Custom(custom) = set_parameter.inner() else {
                        return None;
                    };
                    if custom.id() != &confidential_metadata::registry_root_id() {
                        return None;
                    }
                    let value: norito::json::Value = custom
                        .payload()
                        .try_into_any_norito()
                        .expect("decode confidential registry root");
                    let Some(norito::json::Value::String(hash)) = value.get("vk_set_hash") else {
                        return None;
                    };
                    Some(hash.clone())
                })
            })
            .expect("confidential registry root parameter");
        assert_eq!(declared_hash, format_hash_hex(expected));
    }
    #[test]
    fn genesis_topology_entry_norito_roundtrip() {
        let bls = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
        let pop =
            iroha_crypto::bls_normal_pop_prove(bls.private_key()).expect("BLS PoP generation");
        let peer_id = PeerId::new(bls.public_key().clone());
        let entry = GenesisTopologyEntry::new(peer_id.clone(), pop.clone());
        let encoded = norito::codec::encode_adaptive(&entry);
        let decoded = GenesisTopologyEntry::decode(&mut encoded.as_slice())
            .expect("decode GenesisTopologyEntry");
        assert_eq!(decoded.peer, peer_id);
        assert_eq!(decoded.pop_hex, entry.pop_hex);
    }
}
