//! Explicit authority declarations for every actual WorldData field.

pub(in crate::state) mod musubi_availability_policy;
pub(in crate::state) mod musubi_universal_policy;

use super::{Canonical, DerivationCheck, Field, Role, Schema, V1_LAYOUT, schema};
use crate::state::*;

classified_owner!(WorldData, check_world_fields, WORLD_FIELDS, readers = WorldReadReleases, {
    parameters: Cell<Parameters> => ("world.parameters",
        Role::Canonical(Canonical::Cell(schema::<Parameters>())));
    consensus_schedule: Cell<crate::sumeragi::schedule::RetainedConsensusSchedule> => ("world.consensus_schedule",
        Role::Canonical(Canonical::Cell(schema::<crate::sumeragi::schedule::ConsensusSchedule>())));
    state_accumulator: Cell<crate::state::world_projection::WorldStateAccumulator> => ("world.state_accumulator",
        Role::Derived { sources: &["state.world"], check: DerivationCheck::Commitment("state::world_projection::WorldStateAccumulator::capture") });
    peers: Cell<Peers> => ("world.peers",
        Role::Canonical(Canonical::Cell(schema::<Peers>())));
    domains: Storage<DomainId, Domain> => ("world.domains",
        Role::Canonical(Canonical::Table { key: schema::<DomainId>(), value: schema::<Domain>() }));
    domains_by_owner: Storage<AccountId, BTreeSet<DomainId>> => ("world.domains_by_owner",
        Role::Derived { sources: &["world.domains"], check: DerivationCheck::Rebuild("World::rebuild_domain_owner_index; state::authority_registry::domain_ownership::CheckedDomainOwnership::capture") });
    kaigi_relay_registry: Storage<AccountId, DomainId> => ("world.kaigi_relay_registry",
        Role::Derived { sources: &["world.domains", "world.accounts"], check: DerivationCheck::Rebuild("isi::kaigi::rebuild_kaigi_relay_registry; validate_rebuilt_kaigi_relay_registry") });
    kaigi_account_dependencies: Storage<AccountId, BTreeSet<(u8, DomainId, Name)>> => ("world.kaigi_account_dependencies",
        Role::Derived { sources: &["world.domains", "world.accounts", "state.block_hashes"], check: DerivationCheck::Rebuild("isi::kaigi::rebuild_kaigi_account_dependencies_at; validate_rebuilt_kaigi_account_dependencies_at") });
    accounts: Storage<AccountId, AccountValue> => ("world.accounts",
        Role::Canonical(Canonical::Table { key: schema::<AccountId>(), value: schema::<AccountValue>() }));
    uaid_accounts: Storage<UniversalAccountId, AccountId> => ("world.uaid_accounts",
        Role::Derived { sources: &["world.accounts"], check: DerivationCheck::Rebuild("state::account_identity_restore::rebuild; state::authority_registry::account_identity_ownership::CheckedAccountIdentities::capture") });
    account_aliases: Storage<AccountAlias, AccountId> => ("world.account_aliases",
        Role::Canonical(Canonical::Table { key: schema::<AccountAlias>(), value: schema::<AccountId>() }));
    account_aliases_by_account: Storage<AccountId, BTreeSet<AccountAlias>> => ("world.account_aliases_by_account",
        Role::Derived { sources: &["world.account_aliases", "world.accounts"], check: DerivationCheck::Rebuild("World::rebuild_account_alias_index; state::authority_registry::account_alias_ownership::CheckedAccountAliases::capture") });
    account_scope_directory: Storage<AccountId, AccountScopeDirectoryEntry> => ("world.account_scope_directory",
        Role::Derived { sources: &["world.accounts", "world.account_aliases", "world.uaid_dataspaces"], check: DerivationCheck::Rebuild("state::account_scope_restore::rebuild") });
    account_scope_accounts: Storage<(DataSpaceId, AccountAliasDomain), BTreeSet<AccountId>> => ("world.account_scope_accounts",
        Role::Derived { sources: &["world.account_scope_directory"], check: DerivationCheck::Rebuild("state::account_scope_restore::rebuild_accounts_index") });
    opaque_uaids: Storage<OpaqueAccountId, UniversalAccountId> => ("world.opaque_uaids",
        Role::Derived { sources: &["world.accounts"], check: DerivationCheck::Rebuild("state::account_identity_restore::rebuild; state::authority_registry::account_identity_ownership::CheckedAccountIdentities::capture") });
    ram_lfe_program_policies: Storage<RamLfeProgramId, RamLfeProgramPolicy> => ("world.ram_lfe_program_policies",
        Role::Canonical(Canonical::Table { key: schema::<RamLfeProgramId>(), value: schema::<RamLfeProgramPolicy>() }));
    identifier_policies: Storage<IdentifierPolicyId, IdentifierPolicy> => ("world.identifier_policies",
        Role::Canonical(Canonical::Table { key: schema::<IdentifierPolicyId>(), value: schema::<IdentifierPolicy>() }));
    fee_sponsor_programs: Storage<FeeSponsorProgramId, FeeSponsorProgram> => ("world.fee_sponsor_programs",
        Role::Canonical(Canonical::Table { key: schema::<FeeSponsorProgramId>(), value: schema::<FeeSponsorProgram>() }));
    fee_sponsor_program_revisions: Storage<FeeSponsorProgramRevisionKey, FeeSponsorProgramRevision> => ("world.fee_sponsor_program_revisions",
        Role::Canonical(Canonical::Table { key: schema::<FeeSponsorProgramRevisionKey>(), value: schema::<FeeSponsorProgramRevision>() }));
    fee_sponsor_enrollments: Storage<FeeSponsorEnrollmentKey, FeeSponsorEnrollment> => ("world.fee_sponsor_enrollments",
        Role::Canonical(Canonical::Table { key: schema::<FeeSponsorEnrollmentKey>(), value: schema::<FeeSponsorEnrollment>() }));
    fee_sponsor_vaults: Storage<FeeSponsorVaultKey, FeeSponsorVault> => ("world.fee_sponsor_vaults",
        Role::Canonical(Canonical::Table { key: schema::<FeeSponsorVaultKey>(), value: schema::<FeeSponsorVault>() }));
    fee_sponsor_budget_counters: Storage<FeeSponsorBudgetCounterKey, FeeSponsorBudgetCounter> => ("world.fee_sponsor_budget_counters",
        Role::Canonical(Canonical::Table { key: schema::<FeeSponsorBudgetCounterKey>(), value: schema::<FeeSponsorBudgetCounter>() }));
    identifier_claims: Storage<OpaqueAccountId, IdentifierClaimRecord> => ("world.identifier_claims",
        Role::Canonical(Canonical::Table { key: schema::<OpaqueAccountId>(), value: schema::<IdentifierClaimRecord>() }));
    account_rekey_records: Storage<AccountAlias, AccountRekeyRecord> => ("world.account_rekey_records",
        Role::Canonical(Canonical::Table { key: schema::<AccountAlias>(), value: schema::<AccountRekeyRecord>() }));
    account_rekey_records_by_account: Storage<AccountId, BTreeSet<AccountAlias>> => ("world.account_rekey_records_by_account",
        Role::Derived { sources: &["world.account_rekey_records", "world.accounts", "world.account_aliases"], check: DerivationCheck::Rebuild("World::rebuild_account_rekey_records; CheckedAccountRekeys::capture checks both native images") });
    account_recovery_policies: Storage<AccountAlias, AccountRecoveryPolicy> => ("world.account_recovery_policies",
        Role::Canonical(Canonical::Table { key: schema::<AccountAlias>(), value: schema::<AccountRecoveryPolicy>() }));
    account_recovery_requests: Storage<AccountAlias, AccountRecoveryRequest> => ("world.account_recovery_requests",
        Role::Canonical(Canonical::Table { key: schema::<AccountAlias>(), value: schema::<AccountRecoveryRequest>() }));
    asset_definitions: Storage<AssetDefinitionId, AssetDefinition> => ("world.asset_definitions",
        Role::Canonical(Canonical::Table { key: schema::<AssetDefinitionId>(), value: schema::<AssetDefinition>() }));
    asset_definition_aliases: Storage<AssetDefinitionAlias, AssetDefinitionId> => ("world.asset_definition_aliases",
        Role::Derived { sources: &["world.asset_definition_alias_bindings", "world.asset_definitions"], check: DerivationCheck::Rebuild("state::alias_index_restore::assets") });
    asset_definition_alias_bindings: Storage<AssetDefinitionId, AssetDefinitionAliasBindingRecord> => ("world.asset_definition_alias_bindings",
        Role::Canonical(Canonical::Table { key: schema::<AssetDefinitionId>(), value: schema::<AssetDefinitionAliasBindingRecord>() }));
    contract_aliases: Storage<ContractAlias, ContractAddress> => ("world.contract_aliases",
        Role::Derived { sources: &["world.contract_alias_bindings"], check: DerivationCheck::Rebuild("state::alias_index_restore::contracts; state::authority_registry::grouped_ownership::CheckedContractAliases::capture") });
    contract_alias_bindings: Storage<ContractAddress, ContractAliasBindingRecord> => ("world.contract_alias_bindings",
        Role::Canonical(Canonical::Table { key: schema::<ContractAddress>(), value: schema::<ContractAliasBindingRecord>() }));
    asset_definition_domains: Storage<AssetDefinitionId, DomainId> => ("world.asset_definition_domains",
        Role::Derived { sources: &["world.asset_definitions", "world.domains"], check: DerivationCheck::Rebuild("state::asset_index_restore::assets; state::authority_registry::grouped_ownership::CheckedAssetDefinitions::capture") });
    domain_asset_definitions: Storage<DomainId, BTreeSet<AssetDefinitionId>> => ("world.domain_asset_definitions",
        Role::Derived { sources: &["world.asset_definitions", "world.domains"], check: DerivationCheck::Rebuild("state::asset_index_restore::assets; state::authority_registry::grouped_ownership::CheckedAssetDefinitions::capture") });
    asset_definitions_by_owner: Storage<AccountId, BTreeSet<AssetDefinitionId>> => ("world.asset_definitions_by_owner",
        Role::Derived { sources: &["world.asset_definitions", "world.domains"], check: DerivationCheck::Rebuild("state::asset_index_restore::assets; state::authority_registry::grouped_ownership::CheckedAssetDefinitions::capture") });
    asset_definition_holders: Storage<AssetDefinitionId, BTreeSet<AccountId>> => ("world.asset_definition_holders",
        Role::Derived { sources: &["world.assets", "world.asset_definitions"], check: DerivationCheck::Rebuild("state::asset_index_restore::assets; state::authority_registry::grouped_ownership::CheckedAssets::capture") });
    asset_definition_assets: Storage<AssetDefinitionId, BTreeSet<AssetId>> => ("world.asset_definition_assets",
        Role::Derived { sources: &["world.assets", "world.asset_definitions"], check: DerivationCheck::Rebuild("state::asset_index_restore::assets; state::authority_registry::grouped_ownership::CheckedAssets::capture") });
    assets_by_account: Storage<AccountId, BTreeSet<AssetId>> => ("world.assets_by_account",
        Role::Derived { sources: &["world.assets", "world.asset_definitions"], check: DerivationCheck::Rebuild("state::asset_index_restore::assets; state::authority_registry::grouped_ownership::CheckedAssets::capture") });
    assets_by_domain: Storage<DomainId, BTreeSet<AssetId>> => ("world.assets_by_domain",
        Role::Derived { sources: &["world.assets", "world.asset_definitions"], check: DerivationCheck::Rebuild("state::asset_index_restore::assets; state::authority_registry::grouped_ownership::CheckedAssets::capture") });
    asset_definition_nonzero_holders: Storage<AssetDefinitionId, BTreeSet<AccountId>> => ("world.asset_definition_nonzero_holders",
        Role::Derived { sources: &["world.assets", "world.asset_definitions"], check: DerivationCheck::Rebuild("state::asset_index_restore::assets; state::authority_registry::grouped_ownership::CheckedAssets::capture") });
    assets: Storage<AssetId, AssetValue> => ("world.assets",
        Role::Canonical(Canonical::Table { key: schema::<AssetId>(), value: schema::<AssetValue>() }));
    asset_metadata: Storage<AssetId, Metadata> => ("world.asset_metadata",
        Role::Canonical(Canonical::Table { key: schema::<AssetId>(), value: schema::<Metadata>() }));
    nfts: Storage<NftId, NftValue> => ("world.nfts",
        Role::Canonical(Canonical::Table { key: schema::<NftId>(), value: schema::<NftValue>() }));
    nfts_by_owner: Storage<AccountId, BTreeSet<NftId>> => ("world.nfts_by_owner",
        Role::Derived { sources: &["world.nfts"], check: DerivationCheck::Rebuild("World::rebuild_nft_owner_index; state::authority_registry::grouped_ownership::CheckedNfts::capture") });
    nfts_by_domain: Storage<DomainId, BTreeSet<NftId>> => ("world.nfts_by_domain",
        Role::Derived { sources: &["world.nfts"], check: DerivationCheck::Rebuild("World::rebuild_nft_owner_index; state::authority_registry::grouped_ownership::CheckedNfts::capture") });
    rwas: Storage<RwaId, RwaValue> => ("world.rwas",
        Role::Canonical(Canonical::Table { key: schema::<RwaId>(), value: schema::<RwaValue>() }));
    rwas_by_owner: Storage<AccountId, BTreeSet<RwaId>> => ("world.rwas_by_owner",
        Role::Derived { sources: &["world.rwas"], check: DerivationCheck::Rebuild("World::rebuild_rwa_indexes; state::authority_registry::grouped_ownership::CheckedRwas::capture") });
    rwas_by_status: Storage<Option<Name>, BTreeSet<RwaId>> => ("world.rwas_by_status",
        Role::Derived { sources: &["world.rwas"], check: DerivationCheck::Rebuild("World::rebuild_rwa_indexes; state::authority_registry::grouped_ownership::CheckedRwas::capture") });
    rwas_by_frozen: Storage<bool, BTreeSet<RwaId>> => ("world.rwas_by_frozen",
        Role::Derived { sources: &["world.rwas"], check: DerivationCheck::Rebuild("World::rebuild_rwa_indexes; state::authority_registry::grouped_ownership::CheckedRwas::capture") });
    roles: Storage<RoleId, iroha_data_model::role::Role> => ("world.roles",
        Role::Canonical(Canonical::Table { key: schema::<RoleId>(), value: schema::<iroha_data_model::role::Role>() }));
    account_permissions: Storage<AccountId, Permissions> => ("world.account_permissions",
        Role::Canonical(Canonical::Table { key: schema::<AccountId>(), value: schema::<Permissions>() }));
    account_roles: Storage<RoleIdWithOwner, ()> => ("world.account_roles",
        Role::Canonical(Canonical::Table { key: schema::<RoleIdWithOwner>(), value: schema::<()>() }));
    oracle_feeds: Storage<iroha_data_model::oracle::FeedId, iroha_data_model::oracle::FeedConfig> => ("world.oracle_feeds",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::oracle::FeedId>(), value: schema::<iroha_data_model::oracle::FeedConfig>() }));
    oracle_observations: Storage<crate::oracle::ObservationWindowKey, crate::oracle::ObservationWindow> => ("world.oracle_observations",
        Role::Canonical(Canonical::Table { key: schema::<crate::oracle::ObservationWindowKey>(), value: schema::<crate::oracle::ObservationWindow>() }));
    oracle_history: Storage< iroha_data_model::oracle::FeedId, Vec<iroha_data_model::events::data::oracle::FeedEventRecord>, > => ("world.oracle_history",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::oracle::FeedId>(), value: schema::<Vec<iroha_data_model::events::data::oracle::FeedEventRecord>>() }));
    oracle_provider_stats: Storage<OracleProviderKey, OracleProviderStats> => ("world.oracle_provider_stats",
        Role::Canonical(Canonical::Table { key: schema::<OracleProviderKey>(), value: schema::<OracleProviderStats>() }));
    oracle_disputes: Storage<OracleDisputeId, OracleDispute> => ("world.oracle_disputes",
        Role::Canonical(Canonical::Table { key: schema::<OracleDisputeId>(), value: schema::<OracleDispute>() }));
    oracle_changes: Storage< iroha_data_model::oracle::OracleChangeId, iroha_data_model::oracle::OracleChangeProposal, > => ("world.oracle_changes",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::oracle::OracleChangeId>(), value: schema::<iroha_data_model::oracle::OracleChangeProposal>() }));
    defi_oracle_attestations: Storage<DefiOracleAttestationKey, Vec<DefiOracleAttestation>> => ("world.defi_oracle_attestations",
        Role::Canonical(Canonical::Table { key: schema::<DefiOracleAttestationKey>(), value: schema::<Vec<DefiOracleAttestation>>() }));
    twitter_bindings: Storage<Hash, TwitterBindingRecord> => ("world.twitter_bindings",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<TwitterBindingRecord>() }));
    // Query results preserve append order, which shared block timestamps cannot reconstruct.
    twitter_bindings_by_uaid: Storage<UniversalAccountId, Vec<Hash>> => ("world.twitter_bindings_by_uaid",
        Role::Canonical(Canonical::Table { key: schema::<UniversalAccountId>(), value: schema::<Vec<Hash>>() }));
    viral_reward_budget: Cell<ViralRewardBudget> => ("world.viral_reward_budget",
        Role::Canonical(Canonical::Cell(schema::<ViralRewardBudget>())));
    viral_campaign_budget: Cell<ViralCampaignBudget> => ("world.viral_campaign_budget",
        Role::Canonical(Canonical::Cell(schema::<ViralCampaignBudget>())));
    viral_daily_counters: Storage<UniversalAccountId, ViralDailyCounter> => ("world.viral_daily_counters",
        Role::Canonical(Canonical::Table { key: schema::<UniversalAccountId>(), value: schema::<ViralDailyCounter>() }));
    viral_binding_claims: Storage<Hash, u32> => ("world.viral_binding_claims",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<u32>() }));
    viral_escrows: Storage<Hash, ViralEscrowRecord> => ("world.viral_escrows",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<ViralEscrowRecord>() }));
    viral_bonus_paid: Storage<Hash, bool> => ("world.viral_bonus_paid",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<bool>() }));
    asset_escrows: Storage<EscrowId, AssetEscrowRecord> => ("world.asset_escrows",
        Role::Canonical(Canonical::Table { key: schema::<EscrowId>(), value: schema::<AssetEscrowRecord>() }));
    asset_escrows_by_seller: Storage<AccountId, BTreeSet<EscrowId>> => ("world.asset_escrows_by_seller",
        Role::Derived { sources: &["world.asset_escrows"], check: DerivationCheck::Rebuild("World::rebuild_escrow_indexes; state::authority_registry::grouped_ownership::CheckedEscrows::capture") });
    asset_escrows_by_buyer: Storage<AccountId, BTreeSet<EscrowId>> => ("world.asset_escrows_by_buyer",
        Role::Derived { sources: &["world.asset_escrows"], check: DerivationCheck::Rebuild("World::rebuild_escrow_indexes; state::authority_registry::grouped_ownership::CheckedEscrows::capture") });
    asset_escrows_by_status: Storage<AssetEscrowStatus, BTreeSet<EscrowId>> => ("world.asset_escrows_by_status",
        Role::Derived { sources: &["world.asset_escrows"], check: DerivationCheck::Rebuild("World::rebuild_escrow_indexes; state::authority_registry::grouped_ownership::CheckedEscrows::capture") });
    execution_proof_profiles: Storage<Hash, ExecutionProofProfileV1> => ("world.execution_proof_profiles",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<ExecutionProofProfileV1>() }));
    execution_proof_verifications: Storage<Hash, ExecutionProofVerificationV1> => ("world.execution_proof_verifications",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<ExecutionProofVerificationV1>() }));
    game_sessions: Storage<Hash, GameSessionRecordV1> => ("world.game_sessions",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<GameSessionRecordV1>() }));
    nft_sale_offers: Storage<Hash, NftSaleRecordV1> => ("world.nft_sale_offers",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<NftSaleRecordV1>() }));
    nft_custody_records: Storage<AccountId, NftCustodyRecordV1> => ("world.nft_custody_records",
        Role::Canonical(Canonical::Table { key: schema::<AccountId>(), value: schema::<NftCustodyRecordV1>() }));
    nft_custody_by_nft: Storage<NftId, AccountId> => ("world.nft_custody_by_nft",
        Role::Derived { sources: &["world.nft_custody_records", "world.nft_sale_offers", "world.nfts"], check: DerivationCheck::Rebuild("World::rebuild_nft_custody_indexes") });
    nft_custody_owner_refs: Storage<AccountId, u32> => ("world.nft_custody_owner_refs",
        Role::Derived { sources: &["world.nft_custody_records", "world.nft_sale_offers", "world.nfts"], check: DerivationCheck::Rebuild("World::rebuild_nft_custody_indexes") });
    nft_custody_domain_refs: Storage<DomainId, u32> => ("world.nft_custody_domain_refs",
        Role::Derived { sources: &["world.nft_custody_records", "world.nft_sale_offers", "world.nfts"], check: DerivationCheck::Rebuild("World::rebuild_nft_custody_indexes") });
    game_custody_by_account: Storage<AccountId, Hash> => ("world.game_custody_by_account",
        Role::Derived { sources: &["world.game_sessions"], check: DerivationCheck::Rebuild("World::rebuild_game_session_indexes") });
    game_account_references: Storage<AccountId, u32> => ("world.game_account_references",
        Role::Derived { sources: &["world.game_sessions"], check: DerivationCheck::Rebuild("World::rebuild_game_session_indexes") });
    game_asset_references: Storage<AssetDefinitionId, u32> => ("world.game_asset_references",
        Role::Derived { sources: &["world.game_sessions"], check: DerivationCheck::Rebuild("World::rebuild_game_session_indexes") });
    vpn_leases: Storage<[u8; 32], VpnLeaseRecordV1> => ("world.vpn_leases",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<VpnLeaseRecordV1>() }));
    vpn_active_lease_by_account: Storage<AccountId, [u8; 32]> => ("world.vpn_active_lease_by_account",
        Role::Derived { sources: &["world.vpn_leases"], check: DerivationCheck::Rebuild("World::rebuild_vpn_lease_indexes") });
    vpn_active_lease_by_address_slot: Storage<VpnAddressSlotV1, [u8; 32]> => ("world.vpn_active_lease_by_address_slot",
        Role::Derived { sources: &["world.vpn_leases"], check: DerivationCheck::Rebuild("World::rebuild_vpn_lease_indexes") });
    vpn_settled_leases_by_account: Storage<AccountId, BTreeSet<(u64, [u8; 32])>> => ("world.vpn_settled_leases_by_account",
        Role::Derived { sources: &["world.vpn_leases"], check: DerivationCheck::Rebuild("World::rebuild_vpn_lease_indexes") });
    uaid_dataspaces: Storage<UniversalAccountId, UaidDataspaceBindings> => ("world.uaid_dataspaces",
        Role::Derived { sources: &["world.space_directory_manifests"], check: DerivationCheck::Rebuild("state::uaid_dataspace_restore::rebuild") });
    space_directory_manifests: Storage<UniversalAccountId, SpaceDirectoryManifestSet> => ("world.space_directory_manifests",
        Role::Canonical(Canonical::Table { key: schema::<UniversalAccountId>(), value: schema::<SpaceDirectoryManifestSet>() }));
    axt_policies: Storage<DataSpaceId, AxtPolicyEntry> => ("world.axt_policies",
        Role::Derived { sources: &["world.space_directory_manifests", "world.axt_handle_counters", "runtime.lanes", "runtime.lane_incarnation_lineage", "state.nexus", "state.block_hashes"], check: DerivationCheck::Rebuild("World::rebuild_axt_policies_from_space_directory; exact authenticated slot and lane policy") });
    axt_handle_counters: Storage<DataSpaceId, AxtHandleCounterRecord> => ("world.axt_handle_counters",
        Role::Canonical(Canonical::Table { key: schema::<DataSpaceId>(), value: schema::<AxtHandleCounterRecord>() }));
    axt_asset_incarnations: Storage<AssetDefinitionId, AxtAssetIncarnationV1> => ("world.axt_asset_incarnations",
        Role::Canonical(Canonical::Table { key: schema::<AssetDefinitionId>(), value: schema::<AxtAssetIncarnationV1>() }));
    axt_replay_ledger: Storage<AxtHandleReplayKey, AxtReplayRecord> => ("world.axt_replay_ledger",
        Role::Canonical(Canonical::Table { key: schema::<AxtHandleReplayKey>(), value: schema::<AxtReplayRecord>() }));
    axt_spend_nonce_ledger: Storage<AxtAnchoredSpendReplayKeyV1, u64> => ("world.axt_spend_nonce_ledger",
        Role::Canonical(Canonical::Table { key: schema::<AxtAnchoredSpendReplayKeyV1>(), value: schema::<u64>() }));
    axt_source_transfer_replay_ledger: Storage<AxtSourceTransferReplayKeyV1, AxtSourceTransferReplayRecordV1> => ("world.axt_source_transfer_replay_ledger",
        Role::Canonical(Canonical::Table { key: schema::<AxtSourceTransferReplayKeyV1>(), value: schema::<AxtSourceTransferReplayRecordV1>() }));
    axt_handle_budget_ledger: Storage<AxtHandleBudgetKey, AxtHandleBudgetRecord> => ("world.axt_handle_budget_ledger",
        Role::Canonical(Canonical::Table { key: schema::<AxtHandleBudgetKey>(), value: schema::<AxtHandleBudgetRecord>() }));
    tx_sequences: Storage<AccountId, u64> => ("world.tx_sequences",
        Role::Canonical(Canonical::Table { key: schema::<AccountId>(), value: schema::<u64>() }));
    triggers: TriggerSet => ("world.triggers",
        Role::Canonical(Canonical::Owner(crate::smartcontracts::isi::triggers::set::AUTHORITY_FIELDS)));
    executor: Cell<Executor> => ("world.executor",
        Role::Canonical(Canonical::Cell(Schema::Semantic { identity: "iroha:state:executor-semantic:v1", encoder: "crate::executor::executor_norito::net_state_hash; excludes LoadedExecutor runtime pool", layout: V1_LAYOUT })));
    executor_data_model: Cell<ExecutorDataModel> => ("world.executor_data_model",
        Role::Canonical(Canonical::Cell(schema::<ExecutorDataModel>())));
    verifying_keys: Storage< iroha_data_model::proof::VerifyingKeyId, iroha_data_model::proof::VerifyingKeyRecord, > => ("world.verifying_keys",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::proof::VerifyingKeyId>(), value: schema::<iroha_data_model::proof::VerifyingKeyRecord>() }));
    verifying_keys_by_circuit: Storage<(String, u32), iroha_data_model::proof::VerifyingKeyId> => ("world.verifying_keys_by_circuit",
        Role::Derived { sources: &["world.verifying_keys"], check: DerivationCheck::Rebuild("state::verifying_key_index_validation::validate; CheckedVerifyingKeys::capture and fail-closed restore check both original images, independent of status and activation") });
    consensus_keys: Storage< iroha_data_model::consensus::ConsensusKeyId, iroha_data_model::consensus::ConsensusKeyRecord, > => ("world.consensus_keys",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::consensus::ConsensusKeyId>(), value: schema::<iroha_data_model::consensus::ConsensusKeyRecord>() }));
    // Registration order is retained and consumed by public-key lookup; records do not carry it.
    consensus_keys_by_pk: Storage<String, Vec<iroha_data_model::consensus::ConsensusKeyId>> => ("world.consensus_keys_by_pk",
        Role::Canonical(Canonical::Table { key: schema::<String>(), value: schema::<Vec<iroha_data_model::consensus::ConsensusKeyId>>() }));
    domain_committees: Storage<String, DomainCommittee> => ("world.domain_committees",
        Role::Canonical(Canonical::Table { key: schema::<String>(), value: schema::<DomainCommittee>() }));
    domain_endorsement_policies: Storage<DomainId, DomainEndorsementPolicy> => ("world.domain_endorsement_policies",
        Role::Canonical(Canonical::Table { key: schema::<DomainId>(), value: schema::<DomainEndorsementPolicy>() }));
    domain_endorsements: Storage<HashOf<DomainEndorsement>, DomainEndorsementRecord> => ("world.domain_endorsements",
        Role::Canonical(Canonical::Table { key: schema::<HashOf<DomainEndorsement>>(), value: schema::<DomainEndorsementRecord>() }));
    // Endorsement query order is append order; accepted height does not retain intra-block order.
    domain_endorsements_by_domain: Storage<DomainId, Vec<HashOf<DomainEndorsement>>> => ("world.domain_endorsements_by_domain",
        Role::Canonical(Canonical::Table { key: schema::<DomainId>(), value: schema::<Vec<HashOf<DomainEndorsement>>>() }));
    pedersen_params: Storage< iroha_data_model::confidential::ConfidentialParamsId, iroha_data_model::confidential::PedersenParams, > => ("world.pedersen_params",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::confidential::ConfidentialParamsId>(), value: schema::<iroha_data_model::confidential::PedersenParams>() }));
    poseidon_params: Storage< iroha_data_model::confidential::ConfidentialParamsId, iroha_data_model::confidential::PoseidonParams, > => ("world.poseidon_params",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::confidential::ConfidentialParamsId>(), value: schema::<iroha_data_model::confidential::PoseidonParams>() }));
    runtime_upgrades: Storage< iroha_data_model::runtime::RuntimeUpgradeId, iroha_data_model::runtime::RuntimeUpgradeRecord, > => ("world.runtime_upgrades",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::runtime::RuntimeUpgradeId>(), value: schema::<iroha_data_model::runtime::RuntimeUpgradeRecord>() }));
    privacy_consensus_policy: Cell<iroha_data_model::privacy::PrivacyConsensusPolicyV1> => ("world.privacy_consensus_policy",
        Role::Canonical(Canonical::Cell(schema::<iroha_data_model::privacy::PrivacyConsensusPolicyV1>())));
    privacy_exact12_qualification: Cell<Option<iroha_data_model::privacy::PrivacyExact12QualificationRecordV1>> => ("world.privacy_exact12_qualification",
        Role::Canonical(Canonical::Cell(schema::<Option<iroha_data_model::privacy::PrivacyExact12QualificationRecordV1>>())));
    privacy_activations: Storage< crate::privacy_state::PrivacyActivationKeyV1, iroha_data_model::privacy::PrivacyProtocolActivationRecordV1, > => ("world.privacy_activations",
        Role::Canonical(Canonical::Table { key: schema::<crate::privacy_state::PrivacyActivationKeyV1>(), value: schema::<iroha_data_model::privacy::PrivacyProtocolActivationRecordV1>() }));
    private_settlement_governance: Storage<PrivateSettlementPoolKeyV1, PrivateSettlementPoolGovernanceProjectionV1> => ("world.private_settlement_governance",
        Role::Canonical(Canonical::Table { key: schema::<PrivateSettlementPoolKeyV1>(), value: schema::<PrivateSettlementPoolGovernanceProjectionV1>() }));
    private_settlement_pools: Storage<PrivateSettlementPoolKeyV1, PrivateSettlementPoolStateV1> => ("world.private_settlement_pools",
        Role::Canonical(Canonical::Table { key: schema::<PrivateSettlementPoolKeyV1>(), value: schema::<PrivateSettlementPoolStateV1>() }));
    private_settlement_roots: Storage<PrivateSettlementRootKeyV1, PrivateSettlementRootProvenanceV1> => ("world.private_settlement_roots",
        Role::Canonical(Canonical::Table { key: schema::<PrivateSettlementRootKeyV1>(), value: schema::<PrivateSettlementRootProvenanceV1>() }));
    private_settlement_nullifiers: Storage<PrivateSettlementNullifierKeyV1, PrivateSettlementFinalizationReferenceV1> => ("world.private_settlement_nullifiers",
        Role::Canonical(Canonical::Table { key: schema::<PrivateSettlementNullifierKeyV1>(), value: schema::<PrivateSettlementFinalizationReferenceV1>() }));
    private_settlement_outputs: Storage<PrivateSettlementOutputKeyV1, PrivateSettlementOutputRecordV1> => ("world.private_settlement_outputs",
        Role::Canonical(Canonical::Table { key: schema::<PrivateSettlementOutputKeyV1>(), value: schema::<PrivateSettlementOutputRecordV1>() }));
    private_settlement_recipient_index: Storage< iroha_data_model::privacy::PrivacyRecipientIdV1, PrivateSettlementFinalizationReferenceV1, > => ("world.private_settlement_recipient_index",
        Role::Derived { sources: &["world.private_settlement_outputs"], check: DerivationCheck::Rebuild("private_settlement::global_state::rebuild_private_settlement_recipient_index_v1; deserialize_world current and predecessor rebuild") });
    private_settlement_staged_locks: Storage<PrivateSettlementStagedLockKeyV1, PrivateSettlementStagedLockRecordV1> => ("world.private_settlement_staged_locks",
        Role::Canonical(Canonical::Table { key: schema::<PrivateSettlementStagedLockKeyV1>(), value: schema::<PrivateSettlementStagedLockRecordV1>() }));
    private_settlement_receipts: Storage<Hash, iroha_data_model::nexus::PrivateSettlementReceiptV1> => ("world.private_settlement_receipts",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<iroha_data_model::nexus::PrivateSettlementReceiptV1>() }));
    private_settlement_aborts: Storage<Hash, iroha_data_model::nexus::PrivateSettlementAbortReceiptV1> => ("world.private_settlement_aborts",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<iroha_data_model::nexus::PrivateSettlementAbortReceiptV1>() }));
    privacy_pgc_accounts: Storage< crate::privacy_state::PrivacyPgcAccountKeyV1, crate::privacy_state::PrivacyPgcAccountStateV1, > => ("world.privacy_pgc_accounts",
        Role::Canonical(Canonical::Table { key: schema::<crate::privacy_state::PrivacyPgcAccountKeyV1>(), value: schema::<crate::privacy_state::PrivacyPgcAccountStateV1>() }));
    privacy_pgc_pool_invariants: Storage< crate::privacy_state::PrivacyPgcPoolInvariantKeyV1, crate::privacy_state::PrivacyPgcPoolInvariantV1, > => ("world.privacy_pgc_pool_invariants",
        Role::Canonical(Canonical::Table { key: schema::<crate::privacy_state::PrivacyPgcPoolInvariantKeyV1>(), value: schema::<crate::privacy_state::PrivacyPgcPoolInvariantV1>() }));
    privacy_nullifiers: Storage< crate::privacy_state::PrivacyNullifierKeyV1, crate::privacy_state::PrivacyStateItemRecordV1, > => ("world.privacy_nullifiers",
        Role::Canonical(Canonical::Table { key: schema::<crate::privacy_state::PrivacyNullifierKeyV1>(), value: schema::<crate::privacy_state::PrivacyStateItemRecordV1>() }));
    privacy_commitments: Storage< crate::privacy_state::PrivacyCommitmentKeyV1, crate::privacy_state::PrivacyStateItemRecordV1, > => ("world.privacy_commitments",
        Role::Canonical(Canonical::Table { key: schema::<crate::privacy_state::PrivacyCommitmentKeyV1>(), value: schema::<crate::privacy_state::PrivacyStateItemRecordV1>() }));
    privacy_roots: Storage< crate::privacy_state::PrivacyRootKeyV1, crate::privacy_state::PrivacyRootProvenanceV1, > => ("world.privacy_roots",
        Role::Canonical(Canonical::Table { key: schema::<crate::privacy_state::PrivacyRootKeyV1>(), value: schema::<crate::privacy_state::PrivacyRootProvenanceV1>() }));
    privacy_root_heads: Storage< crate::privacy_state::PrivacyRootHeadKeyV1, crate::privacy_state::PrivacyRootHeadRecordV1, > => ("world.privacy_root_heads",
        Role::Canonical(Canonical::Table { key: schema::<crate::privacy_state::PrivacyRootHeadKeyV1>(), value: schema::<crate::privacy_state::PrivacyRootHeadRecordV1>() }));
    proofs: Storage<iroha_data_model::proof::ProofId, iroha_data_model::proof::ProofRecord> => ("world.proofs",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::proof::ProofId>(), value: schema::<iroha_data_model::proof::ProofRecord>() }));
    proofs_by_status: Storage<iroha_data_model::proof::ProofStatus, BTreeSet<iroha_data_model::proof::ProofId>> => ("world.proofs_by_status",
        Role::Derived { sources: &["world.proofs"], check: DerivationCheck::Rebuild("World::rebuild_proof_status_index; state::authority_registry::grouped_ownership::CheckedProofRecords::capture") });
    proof_tags: Storage<iroha_data_model::proof::ProofId, Vec<[u8; 4]>> => ("world.proof_tags",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::proof::ProofId>(), value: schema::<Vec<[u8; 4]>>() }));
    proofs_by_tag: Storage<[u8; 4], Vec<iroha_data_model::proof::ProofId>> => ("world.proofs_by_tag",
        Role::Derived { sources: &["world.proof_tags"], check: DerivationCheck::Rebuild("state::deserialize::proof_tag_index::validate_proof_tag_index compares exact current and predecessor cuts without temporary index allocation") });
    merge_hint_roots: Cell<Vec<Hash>> => ("world.merge_hint_roots",
        Role::Canonical(Canonical::Cell(schema::<Vec<Hash>>())));
    merge_global_state_root: Cell<Option<Hash>> => ("world.merge_global_state_root",
        Role::Canonical(Canonical::Cell(schema::<Option<Hash>>())));
    consensus_evidence: Storage<Hash, EvidenceRecord> => ("world.consensus_evidence",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<EvidenceRecord>() }));
    contract_manifests: Storage<iroha_data_model::smart_contract::ContractArtifactId, iroha_data_model::smart_contract::manifest::ContractManifest> => ("world.contract_manifests",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::smart_contract::ContractArtifactId>(), value: schema::<iroha_data_model::smart_contract::manifest::ContractManifest>() }));
    contract_code: Storage<iroha_data_model::smart_contract::ContractArtifactId, Vec<u8>> => ("world.contract_code",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::smart_contract::ContractArtifactId>(), value: schema::<Vec<u8>>() }));
    contract_code_uploads: Storage<SmartContractCodeUploadKey, SmartContractCodeUploadDescriptor> => ("world.contract_code_uploads",
        Role::Canonical(Canonical::Table { key: schema::<SmartContractCodeUploadKey>(), value: schema::<SmartContractCodeUploadDescriptor>() }));
    contract_code_upload_chunks: Storage<SmartContractCodeUploadChunkKey, Vec<u8>> => ("world.contract_code_upload_chunks",
        Role::Canonical(Canonical::Table { key: schema::<SmartContractCodeUploadChunkKey>(), value: schema::<Vec<u8>>() }));
    contract_instances: Storage<iroha_data_model::smart_contract::ContractAddress, iroha_crypto::Hash> => ("world.contract_instances",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::smart_contract::ContractAddress>(), value: schema::<iroha_crypto::Hash>() }));
    contract_subject_bindings: Storage< iroha_data_model::smart_contract::ContractAddress, crate::smartcontracts::code::ContractSubjectBinding, > => ("world.contract_subject_bindings",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::smart_contract::ContractAddress>(), value: schema::<crate::smartcontracts::code::ContractSubjectBinding>() }));
    contract_subject_addresses: Storage<AccountId, iroha_data_model::smart_contract::ContractAddress> => ("world.contract_subject_addresses",
        Role::Derived { sources: &["world.contract_subject_bindings", "world.accounts", "world.contract_instances"], check: DerivationCheck::Rebuild("state::contract_subject_restore::rebuild; state::authority_registry::grouped_ownership::CheckedContractSubjects::capture checks both original images") });
    smart_contract_state: Storage<StatePath, Vec<u8>> => ("world.smart_contract_state",
        Role::Canonical(Canonical::Table { key: schema::<StatePath>(), value: schema::<Vec<u8>>() }));
    musubi_namespace_bindings: Storage<MusubiNamespaceV1, MusubiNamespaceBindingV1> => ("world.musubi_namespace_bindings",
        Role::Canonical(Canonical::Table { key: schema::<MusubiNamespaceV1>(), value: schema::<MusubiNamespaceBindingV1>() }));
    musubi_domain_ownership_generations: Storage<DomainId, u64> => ("world.musubi_domain_ownership_generations",
        Role::Canonical(Canonical::Table { key: schema::<DomainId>(), value: schema::<u64>() }));
    musubi_packages: Storage<MusubiPackageIdV1, MusubiPackageRecordV1> => ("world.musubi_packages",
        Role::Canonical(Canonical::Table { key: schema::<MusubiPackageIdV1>(), value: schema::<MusubiPackageRecordV1>() }));
    musubi_package_metadata: Storage<MusubiPackageIdV1, MusubiPackageMetadataRecordV1> => ("world.musubi_package_metadata",
        Role::Canonical(Canonical::Table { key: schema::<MusubiPackageIdV1>(), value: schema::<MusubiPackageMetadataRecordV1>() }));
    musubi_package_members: Storage<MusubiPackageMemberKeyV1, MusubiPackageMemberV1> => ("world.musubi_package_members",
        Role::Canonical(Canonical::Table { key: schema::<MusubiPackageMemberKeyV1>(), value: schema::<MusubiPackageMemberV1>() }));
    musubi_package_invitations: Storage<MusubiInviteIdV1, MusubiMaintainerInvitationV1> => ("world.musubi_package_invitations",
        Role::Canonical(Canonical::Table { key: schema::<MusubiInviteIdV1>(), value: schema::<MusubiMaintainerInvitationV1>() }));
    musubi_maintainer_directory: Storage<MusubiMaintainerDirectoryKeyV1, MusubiMaintainerDirectoryEntryV1> => ("world.musubi_maintainer_directory",
        Role::Derived { sources: &["world.musubi_package_members", "world.musubi_package_invitations"], check: DerivationCheck::Rebuild("state::deserialize::musubi_derived::validate_musubi_derived_cuts checks exact current and predecessor directory equivalence") });
    musubi_releases: Storage<MusubiReleaseIdV1, MusubiReleaseRecordV1> => ("world.musubi_releases",
        Role::Canonical(Canonical::Table { key: schema::<MusubiReleaseIdV1>(), value: schema::<MusubiReleaseRecordV1>() }));
    musubi_archives: Storage<ArchiveId, MusubiArchiveRecordV1> => ("world.musubi_archives",
        Role::Canonical(Canonical::Table { key: schema::<ArchiveId>(), value: schema::<MusubiArchiveRecordV1>() }));
    musubi_pin_outbox_high_waters: Storage<AccountId, MusubiPinOutboxHighWaterV1> => ("world.musubi_pin_outbox_high_waters",
        Role::Canonical(Canonical::Table { key: schema::<AccountId>(), value: schema::<MusubiPinOutboxHighWaterV1>() }));
    musubi_provider_bundle_attestations: Storage<MusubiProviderBundleAttestationKeyV1, MusubiProviderBundleAttestationRecordV1> => ("world.musubi_provider_bundle_attestations",
        Role::Canonical(Canonical::Table { key: schema::<MusubiProviderBundleAttestationKeyV1>(), value: schema::<MusubiProviderBundleAttestationRecordV1>() }));
    musubi_archive_locations: Storage<MusubiArchiveLocationKeyV1, MusubiArchiveLocationV1> => ("world.musubi_archive_locations",
        Role::Canonical(Canonical::Table { key: schema::<MusubiArchiveLocationKeyV1>(), value: schema::<MusubiArchiveLocationV1>() }));
    musubi_locations_by_pin: Storage<ManifestDigest, MusubiPinLocationReferenceV1> => ("world.musubi_locations_by_pin",
        Role::Derived { sources: &["world.musubi_archive_locations"], check: DerivationCheck::Rebuild("state::deserialize_world::validate_musubi_location_reverse_indices") });
    musubi_locations_by_replication_order: Storage<ReplicationOrderId, MusubiReplicationOrderLocationReferenceV1> => ("world.musubi_locations_by_replication_order",
        Role::Derived { sources: &["world.musubi_archive_locations"], check: DerivationCheck::Rebuild("state::deserialize_world::validate_musubi_location_reverse_indices") });
    musubi_locations_by_provider: Storage<MusubiProviderLocationKeyV1, ()> => ("world.musubi_locations_by_provider",
        Role::Derived { sources: &["world.musubi_archive_locations"], check: DerivationCheck::Rebuild("state::deserialize_world::validate_musubi_location_reverse_indices") });
    musubi_archive_availability: Storage<ArchiveId, MusubiArchiveAvailabilityV1> => ("world.musubi_archive_availability",
        Role::Canonical(Canonical::Table { key: schema::<ArchiveId>(), value: Schema::Semantic { identity: "iroha:state:musubi-availability-authority:v1", encoder: "state::authority_registry::world::musubi_availability_policy::MusubiAvailabilityAuthorityV1::from_record; state::deserialize_world::validate_musubi_live_projections checks current and predecessor cuts", layout: V1_LAYOUT } }));
    musubi_archive_reverse_references: Storage<ArchiveId, MusubiArchiveReverseReferencesV1> => ("world.musubi_archive_reverse_references",
        Role::Derived { sources: &["world.musubi_archives", "world.musubi_releases"], check: DerivationCheck::Rebuild("state::deserialize::musubi_derived::validate_musubi_derived_cuts checks exact current and predecessor reverse references") });
    musubi_resolver_index: Storage<MusubiReleaseIdV1, MusubiResolverReleaseRowV1> => ("world.musubi_resolver_index",
        Role::Canonical(Canonical::Table { key: schema::<MusubiReleaseIdV1>(), value: Schema::Semantic { identity: "iroha:state:musubi-resolver-authority:v1", encoder: "state::authority_registry::world::musubi_universal_policy::MusubiResolverAuthorityV1::from_record; state::deserialize::musubi_universal::validate_musubi_universal_projection_cuts verifies exact current/predecessor sources; state::world_commit::PreparedWorldCommit::prepare_overlay checks candidate before publication", layout: V1_LAYOUT } }));
    musubi_resolver_index_checkpoints: Storage<MusubiResolverIndexRevisionV1, MusubiRegistrySnapshotV1> => ("world.musubi_resolver_index_checkpoints",
        Role::Canonical(Canonical::Table { key: schema::<MusubiResolverIndexRevisionV1>(), value: schema::<MusubiRegistrySnapshotV1>() }));
    musubi_public_directory: Storage<MusubiPackageSelectorV1, MusubiOrderedPackageEntryV1> => ("world.musubi_public_directory",
        Role::Canonical(Canonical::Table { key: schema::<MusubiPackageSelectorV1>(), value: Schema::Semantic { identity: "iroha:state:musubi-directory-authority:v1", encoder: "state::authority_registry::world::musubi_universal_policy::MusubiDirectoryAuthorityV1::from_record; state::deserialize::musubi_universal::validate_musubi_universal_projection_cuts verifies exact current/predecessor sources; state::world_commit::PreparedWorldCommit::prepare_overlay checks candidate before publication", layout: V1_LAYOUT } }));
    musubi_aliases: Storage<MusubiAliasNameV1, MusubiAliasRecordV1> => ("world.musubi_aliases",
        Role::Canonical(Canonical::Table { key: schema::<MusubiAliasNameV1>(), value: schema::<MusubiAliasRecordV1>() }));
    musubi_alias_history: Storage<MusubiAliasHistoryKeyV1, MusubiAliasHistoryEntryV1> => ("world.musubi_alias_history",
        Role::Canonical(Canonical::Table { key: schema::<MusubiAliasHistoryKeyV1>(), value: schema::<MusubiAliasHistoryEntryV1>() }));
    musubi_governance_decisions: Storage<[u8; 32], MusubiGovernanceDecisionConsumptionV1> => ("world.musubi_governance_decisions",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<MusubiGovernanceDecisionConsumptionV1>() }));
    musubi_registry_policy: Cell<MusubiRegistryPolicyV1> => ("world.musubi_registry_policy",
        Role::Canonical(Canonical::Cell(schema::<MusubiRegistryPolicyV1>())));
    musubi_resolver_index_revision: Cell<MusubiResolverIndexRevisionV1> => ("world.musubi_resolver_index_revision",
        Role::Canonical(Canonical::Cell(schema::<MusubiResolverIndexRevisionV1>())));
    musubi_replication_shortfall_releases: Cell<u64, iroha_allocation::AllocationCharge> => ("world.musubi_replication_shortfall_releases",
        Role::Derived { sources: &["world.musubi_releases", "world.musubi_archive_availability"], check: DerivationCheck::Rebuild("state::deserialize::musubi_derived::validate_musubi_derived_cuts checks exact current and predecessor shortfall count") });
    soracloud_sequence_watermark: Cell<u64> => ("world.soracloud_sequence_watermark",
        Role::Canonical(Canonical::Cell(schema::<u64>())));
    soracloud_service_revisions: Storage<(String, String), SoraDeploymentBundleV1> => ("world.soracloud_service_revisions",
        Role::Canonical(Canonical::Table { key: schema::<(String, String)>(), value: schema::<SoraDeploymentBundleV1>() }));
    soracloud_service_deployments: Storage<Name, SoraServiceDeploymentStateV1> => ("world.soracloud_service_deployments",
        Role::Canonical(Canonical::Table { key: schema::<Name>(), value: schema::<SoraServiceDeploymentStateV1>() }));
    soracloud_app_infra_states: Storage<Name, SoraAppInfraStateV1> => ("world.soracloud_app_infra_states",
        Role::Canonical(Canonical::Table { key: schema::<Name>(), value: schema::<SoraAppInfraStateV1>() }));
    soracloud_service_runtime: Storage<Name, SoraServiceRuntimeStateV1> => ("world.soracloud_service_runtime",
        Role::Canonical(Canonical::Table { key: schema::<Name>(), value: schema::<SoraServiceRuntimeStateV1>() }));
    soracloud_inrou_replica_runtime: Storage<(String, String, String), SoraInrouReplicaRuntimeStateV1> => ("world.soracloud_inrou_replica_runtime",
        Role::Canonical(Canonical::Table { key: schema::<(String, String, String)>(), value: schema::<SoraInrouReplicaRuntimeStateV1>() }));
    soracloud_service_audit_events: Storage<u64, SoraServiceAuditEventV1> => ("world.soracloud_service_audit_events",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<SoraServiceAuditEventV1>() }));
    soracloud_app_infra_audit_events: Storage<u64, SoraAppInfraAuditEventV1> => ("world.soracloud_app_infra_audit_events",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<SoraAppInfraAuditEventV1>() }));
    soracloud_service_state_entries: Storage<(String, String, String), SoraServiceStateEntryV1> => ("world.soracloud_service_state_entries",
        Role::Canonical(Canonical::Table { key: schema::<(String, String, String)>(), value: schema::<SoraServiceStateEntryV1>() }));
    soracloud_decryption_request_records: Storage<(String, String), SoraDecryptionRequestRecordV1> => ("world.soracloud_decryption_request_records",
        Role::Canonical(Canonical::Table { key: schema::<(String, String)>(), value: schema::<SoraDecryptionRequestRecordV1>() }));
    soracloud_agent_apartments: Storage<String, SoraAgentApartmentRecordV1> => ("world.soracloud_agent_apartments",
        Role::Canonical(Canonical::Table { key: schema::<String>(), value: schema::<SoraAgentApartmentRecordV1>() }));
    soracloud_agent_apartment_audit_events: Storage<u64, SoraAgentApartmentAuditEventV1> => ("world.soracloud_agent_apartment_audit_events",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<SoraAgentApartmentAuditEventV1>() }));
    soracloud_training_jobs: Storage<(String, String), SoraTrainingJobRecordV1> => ("world.soracloud_training_jobs",
        Role::Canonical(Canonical::Table { key: schema::<(String, String)>(), value: schema::<SoraTrainingJobRecordV1>() }));
    soracloud_training_job_audit_events: Storage<u64, SoraTrainingJobAuditEventV1> => ("world.soracloud_training_job_audit_events",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<SoraTrainingJobAuditEventV1>() }));
    soracloud_model_registries: Storage<(String, String), SoraModelRegistryV1> => ("world.soracloud_model_registries",
        Role::Canonical(Canonical::Table { key: schema::<(String, String)>(), value: schema::<SoraModelRegistryV1>() }));
    soracloud_model_weight_versions: Storage<(String, String, String), SoraModelWeightVersionRecordV1> => ("world.soracloud_model_weight_versions",
        Role::Canonical(Canonical::Table { key: schema::<(String, String, String)>(), value: schema::<SoraModelWeightVersionRecordV1>() }));
    soracloud_model_weight_audit_events: Storage<u64, SoraModelWeightAuditEventV1> => ("world.soracloud_model_weight_audit_events",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<SoraModelWeightAuditEventV1>() }));
    soracloud_model_artifacts: Storage<(String, String), SoraModelArtifactRecordV1> => ("world.soracloud_model_artifacts",
        Role::Canonical(Canonical::Table { key: schema::<(String, String)>(), value: schema::<SoraModelArtifactRecordV1>() }));
    soracloud_model_artifact_audit_events: Storage<u64, SoraModelArtifactAuditEventV1> => ("world.soracloud_model_artifact_audit_events",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<SoraModelArtifactAuditEventV1>() }));
    soracloud_uploaded_model_bundles: Storage<(String, String, String), SoraUploadedModelBundleV1> => ("world.soracloud_uploaded_model_bundles",
        Role::Canonical(Canonical::Table { key: schema::<(String, String, String)>(), value: schema::<SoraUploadedModelBundleV1>() }));
    soracloud_inrou_host_capabilities: Storage<AccountId, SoraInrouHostCapabilityRecordV1> => ("world.soracloud_inrou_host_capabilities",
        Role::Canonical(Canonical::Table { key: schema::<AccountId>(), value: schema::<SoraInrouHostCapabilityRecordV1>() }));
    soracloud_hf_sources: Storage<Hash, SoraHfSourceRecordV1> => ("world.soracloud_hf_sources",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<SoraHfSourceRecordV1>() }));
    soracloud_hf_shared_lease_pools: Storage<Hash, SoraHfSharedLeasePoolV1> => ("world.soracloud_hf_shared_lease_pools",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<SoraHfSharedLeasePoolV1>() }));
    soracloud_hf_shared_lease_members: Storage<(String, String), SoraHfSharedLeaseMemberV1> => ("world.soracloud_hf_shared_lease_members",
        Role::Canonical(Canonical::Table { key: schema::<(String, String)>(), value: schema::<SoraHfSharedLeaseMemberV1>() }));
    soracloud_hf_shared_lease_audit_events: Storage<u64, SoraHfSharedLeaseAuditEventV1> => ("world.soracloud_hf_shared_lease_audit_events",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<SoraHfSharedLeaseAuditEventV1>() }));
    soracloud_inrou_service_placements: Storage<(String, String), SoraInrouServicePlacementRecordV1> => ("world.soracloud_inrou_service_placements",
        Role::Canonical(Canonical::Table { key: schema::<(String, String)>(), value: schema::<SoraInrouServicePlacementRecordV1>() }));
    soracloud_mailbox_messages: Storage<Hash, SoraServiceMailboxMessageV1> => ("world.soracloud_mailbox_messages",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<SoraServiceMailboxMessageV1>() }));
    soracloud_runtime_receipts: Storage<Hash, SoraRuntimeReceiptV1> => ("world.soracloud_runtime_receipts",
        Role::Canonical(Canonical::Table { key: schema::<Hash>(), value: schema::<SoraRuntimeReceiptV1>() }));
    capacity_declarations: Storage<ProviderId, CapacityDeclarationRecord> => ("world.capacity_declarations",
        Role::Canonical(Canonical::Table { key: schema::<ProviderId>(), value: schema::<CapacityDeclarationRecord>() }));
    capacity_fee_ledger: Storage<ProviderId, CapacityFeeLedgerEntry> => ("world.capacity_fee_ledger",
        Role::Canonical(Canonical::Table { key: schema::<ProviderId>(), value: schema::<CapacityFeeLedgerEntry>() }));
    capacity_disputes: Storage<CapacityDisputeId, CapacityDisputeRecord> => ("world.capacity_disputes",
        Role::Canonical(Canonical::Table { key: schema::<CapacityDisputeId>(), value: schema::<CapacityDisputeRecord>() }));
    sorafs_pricing: Cell<PricingScheduleRecord> => ("world.sorafs_pricing",
        Role::Canonical(Canonical::Cell(schema::<PricingScheduleRecord>())));
    provider_credit_ledger: Storage<ProviderId, ProviderCreditRecord> => ("world.provider_credit_ledger",
        Role::Canonical(Canonical::Table { key: schema::<ProviderId>(), value: schema::<ProviderCreditRecord>() }));
    provider_owners: Storage<ProviderId, AccountId> => ("world.provider_owners",
        Role::Canonical(Canonical::Table { key: schema::<ProviderId>(), value: schema::<AccountId>() }));
    provider_ingest_completion_authorities: Storage<ProviderId, ProviderIngestCompletionAuthorityV1> => ("world.provider_ingest_completion_authorities",
        Role::Canonical(Canonical::Table { key: schema::<ProviderId>(), value: schema::<ProviderIngestCompletionAuthorityV1>() }));
    da_pin_intents_by_ticket: Storage<StorageTicketId, DaPinIntentWithLocation> => ("world.da_pin_intents_by_ticket",
        Role::Canonical(Canonical::Table { key: schema::<StorageTicketId>(), value: schema::<DaPinIntentWithLocation>() }));
    da_pin_intents_by_alias: Storage<String, StorageTicketId> => ("world.da_pin_intents_by_alias",
        Role::Canonical(Canonical::Table { key: schema::<String>(), value: schema::<StorageTicketId>() }));
    da_pin_intents_by_manifest: Storage<ManifestDigest, StorageTicketId> => ("world.da_pin_intents_by_manifest",
        Role::Derived { sources: &["world.da_pin_intents_by_ticket"], check: DerivationCheck::Rebuild("state::deserialize_world::validate_da_pin_persistence_cut") });
    da_pin_intents_by_lane_epoch: Storage<(LaneId, u64, u64), StorageTicketId> => ("world.da_pin_intents_by_lane_epoch",
        Role::Derived { sources: &["world.da_pin_intents_by_ticket"], check: DerivationCheck::Rebuild("state::deserialize_world::validate_da_pin_persistence_cut") });
    pin_manifests: Storage<ManifestDigest, PinManifestRecord> => ("world.pin_manifests",
        Role::Canonical(Canonical::Table { key: schema::<ManifestDigest>(), value: schema::<PinManifestRecord>() }));
    manifest_aliases: Storage<ManifestAliasId, ManifestAliasRecord> => ("world.manifest_aliases",
        Role::Canonical(Canonical::Table { key: schema::<ManifestAliasId>(), value: schema::<ManifestAliasRecord>() }));
    replication_orders: Storage<ReplicationOrderId, ReplicationOrderRecord> => ("world.replication_orders",
        Role::Canonical(Canonical::Table { key: schema::<ReplicationOrderId>(), value: schema::<ReplicationOrderRecord>() }));
    content_bundles: Storage<ContentBundleId, ContentBundleRecord> => ("world.content_bundles",
        Role::Canonical(Canonical::Table { key: schema::<ContentBundleId>(), value: schema::<ContentBundleRecord>() }));
    content_chunks: Storage<[u8; 32], ContentChunk> => ("world.content_chunks",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<ContentChunk>() }));
    soradns_directory_records: Storage<DirectoryId, ResolverDirectoryRecordV1> => ("world.soradns_directory_records",
        Role::Canonical(Canonical::Table { key: schema::<DirectoryId>(), value: schema::<ResolverDirectoryRecordV1>() }));
    soradns_directory_pending: Storage<DirectoryId, PendingDirectoryDraftV1> => ("world.soradns_directory_pending",
        Role::Canonical(Canonical::Table { key: schema::<DirectoryId>(), value: schema::<PendingDirectoryDraftV1>() }));
    soradns_directory_latest: Cell<Option<DirectoryId>> => ("world.soradns_directory_latest",
        Role::Canonical(Canonical::Cell(schema::<Option<DirectoryId>>())));
    soradns_directory_history: Storage<u64, DirectoryId> => ("world.soradns_directory_history",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<DirectoryId>() }));
    soradns_directory_prev_of: Storage<DirectoryId, DirectoryId> => ("world.soradns_directory_prev_of",
        Role::Canonical(Canonical::Table { key: schema::<DirectoryId>(), value: schema::<DirectoryId>() }));
    soradns_directory_revocations: Storage<ResolverId, ResolverRevocationRecordV1> => ("world.soradns_directory_revocations",
        Role::Canonical(Canonical::Table { key: schema::<ResolverId>(), value: schema::<ResolverRevocationRecordV1>() }));
    soradns_release_signers: Storage<PublicKey, ()> => ("world.soradns_release_signers",
        Role::Canonical(Canonical::Table { key: schema::<PublicKey>(), value: schema::<()>() }));
    soradns_rotation_policy: Cell<DirectoryRotationPolicyV1> => ("world.soradns_rotation_policy",
        Role::Canonical(Canonical::Cell(schema::<DirectoryRotationPolicyV1>())));
    soradns_last_publish_ms: Cell<Option<u64>> => ("world.soradns_last_publish_ms",
        Role::Canonical(Canonical::Cell(schema::<Option<u64>>())));
    soradns_history_len: Cell<u64> => ("world.soradns_history_len",
        Role::Canonical(Canonical::Cell(schema::<u64>())));
    repo_agreements: Storage<RepoAgreementId, RepoAgreement> => ("world.repo_agreements",
        Role::Canonical(Canonical::Table { key: schema::<RepoAgreementId>(), value: schema::<RepoAgreement>() }));
    repo_agreements_by_initiator: Storage<AccountId, BTreeSet<RepoAgreementId>> => ("world.repo_agreements_by_initiator",
        Role::Derived { sources: &["world.repo_agreements"], check: DerivationCheck::Rebuild("World::rebuild_repo_agreement_indexes; state::authority_registry::grouped_ownership::CheckedRepoAgreements::capture") });
    repo_agreements_by_counterparty: Storage<AccountId, BTreeSet<RepoAgreementId>> => ("world.repo_agreements_by_counterparty",
        Role::Derived { sources: &["world.repo_agreements"], check: DerivationCheck::Rebuild("World::rebuild_repo_agreement_indexes; state::authority_registry::grouped_ownership::CheckedRepoAgreements::capture") });
    repo_agreements_by_custodian: Storage<AccountId, BTreeSet<RepoAgreementId>> => ("world.repo_agreements_by_custodian",
        Role::Derived { sources: &["world.repo_agreements"], check: DerivationCheck::Rebuild("World::rebuild_repo_agreement_indexes; state::authority_registry::grouped_ownership::CheckedRepoAgreements::capture") });
    settlement_receipts: Storage<SettlementId, SettlementReceipt> => ("world.settlement_receipts",
        Role::Canonical(Canonical::Table { key: schema::<SettlementId>(), value: schema::<SettlementReceipt>() }));
    kagemusha_mint_credit_operations: OperationIndex => ("world.kagemusha_mint_credit_operations",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<[u8; 32]>() }));
    kagemusha_issuance_operations: OperationIndex => ("world.kagemusha_issuance_operations",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<[u8; 32]>() }));
    kagemusha_redemption_id_operations: OperationIndex => ("world.kagemusha_redemption_id_operations",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<[u8; 32]>() }));
    kagemusha_terminal_nullifier_operations: OperationIndex => ("world.kagemusha_terminal_nullifier_operations",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<[u8; 32]>() }));
    public_lane_validators: Storage<(LaneId, AccountId), PublicLaneValidatorRecord> => ("world.public_lane_validators",
        Role::Canonical(Canonical::Table { key: schema::<(LaneId, AccountId)>(), value: schema::<PublicLaneValidatorRecord>() }));
    public_lane_stake_shares: Storage<(LaneId, AccountId, AccountId), PublicLaneStakeShare> => ("world.public_lane_stake_shares",
        Role::Canonical(Canonical::Table { key: schema::<(LaneId, AccountId, AccountId)>(), value: schema::<PublicLaneStakeShare>() }));
    public_lane_rewards: Storage<(LaneId, u64), PublicLaneRewardRecord> => ("world.public_lane_rewards",
        Role::Canonical(Canonical::Table { key: schema::<(LaneId, u64)>(), value: schema::<PublicLaneRewardRecord>() }));
    public_lane_reward_claims: Storage<(LaneId, AccountId), PublicLaneRewardClaimStateV1> => ("world.public_lane_reward_claims",
        Role::Canonical(Canonical::Table { key: schema::<(LaneId, AccountId)>(), value: schema::<PublicLaneRewardClaimStateV1>() }));
    public_lane_reward_accruals: Storage<(LaneId, AccountId, AssetId), Quantity> => ("world.public_lane_reward_accruals",
        Role::Canonical(Canonical::Table { key: schema::<(LaneId, AccountId, AssetId)>(), value: schema::<Quantity>() }));
    public_lane_reward_reserves: Storage<AssetId, Quantity> => ("world.public_lane_reward_reserves",
        Role::Derived { sources: &["world.public_lane_rewards", "world.public_lane_reward_claims", "world.public_lane_reward_accruals", "world.assets"], check: DerivationCheck::Rebuild("state::reward_reserves::validate_public_lane_reward_reserves reconstructs exact unpaid entitlements and validates retained custody backing at both cuts") });
    public_lane_stake_custody: Storage<(LaneId, AccountId), (AssetId, Quantity)> => ("world.public_lane_stake_custody",
        Role::Canonical(Canonical::Table { key: schema::<(LaneId, AccountId)>(), value: schema::<(AssetId, Quantity)>() }));
    public_lane_stake_reserves: Storage<AssetId, Quantity> => ("world.public_lane_stake_reserves",
        Role::Derived { sources: &["world.public_lane_stake_custody", "world.public_lane_stake_shares", "world.public_lane_validators", "world.assets"], check: DerivationCheck::Rebuild("state::stake_reserves::validate_public_lane_stake_reserves reconstructs exact pinned custody aggregate and checks bonded/pending shares and asset backing at both cuts") });
    zk_assets: Storage<AssetDefinitionId, ZkAssetState> => ("world.zk_assets",
        Role::Canonical(Canonical::Table { key: schema::<AssetDefinitionId>(), value: schema::<ZkAssetState>() }));
    confidential_policy_transition_index: Storage<(u64, AssetDefinitionId), ()> => ("world.confidential_policy_transition_index",
        Role::Derived { sources: &["world.asset_definitions"], check: DerivationCheck::Rebuild("World::rebuild_confidential_policy_transition_index; CheckedAssetDefinitions::capture checks both native images") });
    confidential_policy_transition_counts: Storage<u64, u32> => ("world.confidential_policy_transition_counts",
        Role::Derived { sources: &["world.asset_definitions"], check: DerivationCheck::Rebuild("World::rebuild_confidential_policy_transition_index; CheckedAssetDefinitions::capture checks both native images") });
    elections: Storage<String, ElectionState> => ("world.elections",
        Role::Canonical(Canonical::Table { key: schema::<String>(), value: schema::<ElectionState>() }));
    citizens: Storage<AccountId, CitizenshipRecord> => ("world.citizens",
        Role::Canonical(Canonical::Table { key: schema::<AccountId>(), value: schema::<CitizenshipRecord>() }));
    ministry_agenda_proposals: Storage<String, iroha_data_model::ministry::AgendaProposalRecordV1> => ("world.ministry_agenda_proposals",
        Role::Canonical(Canonical::Table { key: schema::<String>(), value: schema::<iroha_data_model::ministry::AgendaProposalRecordV1>() }));
    governance_proposals: Storage<[u8; 32], GovernanceProposalRecord> => ("world.governance_proposals",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<GovernanceProposalRecord>() }));
    governance_referenda: Storage<String, GovernanceReferendumRecord> => ("world.governance_referenda",
        Role::Canonical(Canonical::Table { key: schema::<String>(), value: schema::<GovernanceReferendumRecord>() }));
    governance_locks: Storage<String, GovernanceLocksForReferendum> => ("world.governance_locks",
        Role::Canonical(Canonical::Table { key: schema::<String>(), value: schema::<GovernanceLocksForReferendum>() }));
    governance_lock_expiry_index: Storage<u64, BTreeSet<(String, iroha_data_model::account::AccountId)>> => ("world.governance_lock_expiry_index",
        Role::Derived { sources: &["world.governance_locks", "world.governance_referenda"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes") });
    validation_fee_proposal_index: Storage<(u64, [u8; 32]), ()> => ("world.validation_fee_proposal_index",
        Role::Derived { sources: &["world.governance_proposals"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; CheckedValidationFeeProposals::capture checks both native images") });
    governance_slashes: Storage<String, GovernanceSlashLedger> => ("world.governance_slashes",
        Role::Canonical(Canonical::Table { key: schema::<String>(), value: schema::<GovernanceSlashLedger>() }));
    governance_last_unlock_sweep_height: Cell<u64> => ("world.governance_last_unlock_sweep_height",
        Role::Canonical(Canonical::Cell(schema::<u64>())));
    governance_unlock_stats: Cell<GovernanceUnlockStatsSnapshot> => ("world.governance_unlock_stats",
        Role::Canonical(Canonical::Cell(schema::<GovernanceUnlockStatsSnapshot>())));
    parliament_attempts: Storage<iroha_data_model::governance::types::GovernanceAttemptId, ParliamentAttemptStateV1> => ("world.parliament_attempts",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::governance::types::GovernanceAttemptId>(), value: schema::<ParliamentAttemptStateV1>() }));
    parliament_attempt_counts: Cell<ParliamentAttemptCountsV1> => ("world.parliament_attempt_counts",
        Role::Derived { sources: &["world.parliament_attempts", "world.global_beacon_pulses"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; parliament_derived_read_indexes_v1") });
    parliament_member_reference_counts: Storage<AccountId, ParliamentMemberReferenceCountsV1> => ("world.parliament_member_reference_counts",
        Role::Derived { sources: &["world.parliament_attempts", "world.global_beacon_pulses"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; parliament_derived_read_indexes_v1") });
    parliament_timed_ovn_resource_reservations: Storage<BallotAttemptId, ParliamentTimedOvnResourceReservationV1> => ("world.parliament_timed_ovn_resource_reservations",
        Role::Derived { sources: &["world.parliament_attempts", "world.global_beacon_pulses"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; parliament_derived_read_indexes_v1") });
    parliament_timed_ovn_casting_candidates: Storage<BallotAttemptId, ParliamentTimedOvnCastingCandidateV1> => ("world.parliament_timed_ovn_casting_candidates",
        Role::Derived { sources: &["world.parliament_attempts", "world.global_beacon_pulses"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; parliament_derived_read_indexes_v1") });
    parliament_required_beacon_pulse_slots: Storage<(BeaconSessionId, u64), BTreeSet<GovernanceAttemptId>> => ("world.parliament_required_beacon_pulse_slots",
        Role::Derived { sources: &["world.parliament_attempts", "world.global_beacon_pulses"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; parliament_derived_read_indexes_v1") });
    parliament_certified_enactments: Storage<u64, BTreeSet<GovernanceAttemptId>> => ("world.parliament_certified_enactments",
        Role::Derived { sources: &["world.parliament_attempts", "world.global_beacon_pulses"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; parliament_derived_read_indexes_v1") });
    parliament_unavailable_beacon_pulse_slots: Storage<(BeaconSessionId, u64), BTreeSet<GovernanceAttemptId>> => ("world.parliament_unavailable_beacon_pulse_slots",
        Role::Derived { sources: &["world.parliament_attempts", "world.global_beacon_pulses"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; parliament_derived_read_indexes_v1") });
    parliament_tle_key_session_retention_deadlines: Storage<TleKeySessionId, ParliamentTleKeySessionRetentionIndexV1> => ("world.parliament_tle_key_session_retention_deadlines",
        Role::Derived { sources: &["world.parliament_attempts", "world.global_beacon_pulses"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; parliament_derived_read_indexes_v1") });
    tle_key_session_selection_intervals: Storage<u64, (u64, TleKeySessionId)> => ("world.tle_key_session_selection_intervals",
        Role::Derived { sources: &["world.tle_key_session_lifecycles", "world.tle_active_key_session"], check: DerivationCheck::Rebuild("World::rebuild_governance_read_indexes; tle_key_session_selection_intervals_v1") });
    tle_key_sessions: Storage<TleKeySessionId, TleKeySessionPublicStateV1> => ("world.tle_key_sessions",
        Role::Canonical(Canonical::Table { key: schema::<TleKeySessionId>(), value: schema::<TleKeySessionPublicStateV1>() }));
    tle_key_session_rosters: Storage<TleKeySessionId, Vec<PeerId>> => ("world.tle_key_session_rosters",
        Role::Canonical(Canonical::Table { key: schema::<TleKeySessionId>(), value: schema::<Vec<PeerId>>() }));
    tle_key_session_lifecycles: Storage<TleKeySessionId, TleKeySessionLifecycleV1> => ("world.tle_key_session_lifecycles",
        Role::Canonical(Canonical::Table { key: schema::<TleKeySessionId>(), value: schema::<TleKeySessionLifecycleV1>() }));
    tle_active_key_session: Storage<u64, TleKeySessionId> => ("world.tle_active_key_session",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<TleKeySessionId>() }));
    timed_ovn_evidence: Storage<BallotAttemptId, TimedOvnLifecycleStateV1> => ("world.timed_ovn_evidence",
        Role::Canonical(Canonical::Table { key: schema::<BallotAttemptId>(), value: schema::<TimedOvnLifecycleStateV1>() }));
    validator_candidate_keys: Storage<[u8; 32], iroha_data_model::nexus::ValidatorCandidateKeysV1> => ("world.validator_candidate_keys",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<iroha_data_model::nexus::ValidatorCandidateKeysV1>() }));
    validator_committee_transitions: Storage<u64, iroha_data_model::nexus::ValidatorCommitteeTransitionV1> => ("world.validator_committee_transitions",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<iroha_data_model::nexus::ValidatorCommitteeTransitionV1>() }));
    global_beacon_dkg: Storage<[u8; 32], GlobalThresholdBeaconDkgSnapshotV1> => ("world.global_beacon_dkg",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<GlobalThresholdBeaconDkgSnapshotV1>() }));
    global_beacon_key_sessions: Storage<[u8; 32], RetainedFinalizedGlobalThresholdBeaconSessionV1> => ("world.global_beacon_key_sessions",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<RetainedFinalizedGlobalThresholdBeaconSessionV1>() }));
    global_beacon_active_session: Storage<u64, [u8; 32]> => ("world.global_beacon_active_session",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<[u8; 32]>() }));
    global_beacon_latest_pulse: Storage<u64, GlobalThresholdBeaconPulseLinkV1> => ("world.global_beacon_latest_pulse",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<GlobalThresholdBeaconPulseLinkV1>() }));
    global_beacon_pulses: Storage<[u8; 32], iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1> => ("world.global_beacon_pulses",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1>() }));
    global_beacon_pulse_slots: Storage<(BeaconSessionId, u64), [u8; 32]> => ("world.global_beacon_pulse_slots",
        Role::Derived { sources: &["world.global_beacon_pulses"], check: DerivationCheck::Rebuild("World::rebuild_global_beacon_pulse_slots") });
    external_event_buf: Cell<Vec<EventBox>> => ("world.external_event_buf",
        Role::Local("Process delivery buffer; authoritative invocation effects and completions belong to execution output carriers"));
    sumeragi_lanes: Cell<iroha_data_model::sumeragi_lanes::SumeragiLaneState> => ("world.sumeragi_lanes",
        Role::Canonical(Canonical::Cell(schema::<iroha_data_model::sumeragi_lanes::SumeragiLaneState>())));
    sumeragi_amx: Cell<iroha_data_model::sumeragi_amx::SumeragiAmxState> => ("world.sumeragi_amx",
        Role::Canonical(Canonical::Cell(schema::<iroha_data_model::sumeragi_amx::SumeragiAmxState>())));
    sumeragi_amx_participant: Cell<crate::sumeragi::amx::RetainedNativeAmx, iroha_allocation::AllocationCharge> => ("world.sumeragi_amx_participant",
        Role::Canonical(Canonical::Cell(schema::<crate::sumeragi::amx::RetainedNativeAmx>())));
    private_dataspaces: Cell<iroha_data_model::private_dataspace::PrivateDataspaceRegistry> => ("world.private_dataspaces",
        Role::Canonical(Canonical::Cell(schema::<iroha_data_model::private_dataspace::PrivateDataspaceRegistry>())));
    sccp_parameters: Cell<Option<iroha_data_model::sccp::params::SccpParametersV1>> => ("world.sccp_parameters",
        Role::Canonical(Canonical::Cell(schema::<Option<iroha_data_model::sccp::params::SccpParametersV1>>())));
    sccp_reset_nonce: Cell<Option<[u8; 32]>> => ("world.sccp_reset_nonce",
        Role::Canonical(Canonical::Cell(schema::<Option<[u8; 32]>>())));
    sccp_bridge_keys: Storage<PeerId, iroha_data_model::sccp::keys::SccpBridgeKeyStateV1> => ("world.sccp_bridge_keys",
        Role::Canonical(Canonical::Table { key: schema::<PeerId>(), value: schema::<iroha_data_model::sccp::keys::SccpBridgeKeyStateV1>() }));
    sccp_bridge_key_owners: Storage<[u8; 20], PeerId> => ("world.sccp_bridge_key_owners",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 20]>(), value: schema::<PeerId>() }));
    sccp_rosters: Storage<u64, iroha_data_model::sccp::roster::SccpBridgeRosterV1> => ("world.sccp_rosters",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<iroha_data_model::sccp::roster::SccpBridgeRosterV1>() }));
    sccp_roster_current: Cell<u64> => ("world.sccp_roster_current",
        Role::Canonical(Canonical::Cell(schema::<u64>())));
    sccp_heartbeat_marker: Cell<Option<u64>> => ("world.sccp_heartbeat_marker",
        Role::Canonical(Canonical::Cell(schema::<Option<u64>>())));
    sccp_block_leaves: Storage<(u64, u32), iroha_data_model::sccp::control::SccpLeafRefV1> => ("world.sccp_block_leaves",
        Role::Canonical(Canonical::Table { key: schema::<(u64, u32)>(), value: schema::<iroha_data_model::sccp::control::SccpLeafRefV1>() }));
    sccp_block_commitments: Storage<u64, iroha_data_model::sccp::attestation::SccpBlockCommitmentV1> => ("world.sccp_block_commitments",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<iroha_data_model::sccp::attestation::SccpBlockCommitmentV1>() }));
    sccp_history: Cell<iroha_data_model::sccp::attestation::SccpHistoryStateV1> => ("world.sccp_history",
        Role::Canonical(Canonical::Cell(schema::<iroha_data_model::sccp::attestation::SccpHistoryStateV1>())));
    sccp_history_leaves: Storage<u64, (u64, [u8; 32])> => ("world.sccp_history_leaves",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<(u64, [u8; 32])>() }));
    sccp_attestation_subjects: Storage<u64, iroha_data_model::sccp::attestation::SccpAttestationSubjectV1> => ("world.sccp_attestation_subjects",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<iroha_data_model::sccp::attestation::SccpAttestationSubjectV1>() }));
    sccp_attestation_status: Storage<u64, iroha_data_model::sccp::attestation::SccpAttestationStatusV1> => ("world.sccp_attestation_status",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<iroha_data_model::sccp::attestation::SccpAttestationStatusV1>() }));
    sccp_attestation_signatures: Storage<(u64, u8), [u8; 65]> => ("world.sccp_attestation_signatures",
        Role::Canonical(Canonical::Table { key: schema::<(u64, u8)>(), value: schema::<[u8; 65]>() }));
    sccp_attestation_faults: Storage<([u8; 20], u64), iroha_data_model::sccp::keys::SccpAttestationFaultRecordV1> => ("world.sccp_attestation_faults",
        Role::Canonical(Canonical::Table { key: schema::<([u8; 20], u64)>(), value: schema::<iroha_data_model::sccp::keys::SccpAttestationFaultRecordV1>() }));
    sccp_member_last_signed: Storage<[u8; 20], u64> => ("world.sccp_member_last_signed",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 20]>(), value: schema::<u64>() }));
    sccp_handoff_stalled: Storage<u64, u64> => ("world.sccp_handoff_stalled",
        Role::Canonical(Canonical::Table { key: schema::<u64>(), value: schema::<u64>() }));
    sccp_prune_cursor: Cell<iroha_data_model::sccp::keys_index::SccpPruneCursorV1> => ("world.sccp_prune_cursor",
        Role::Canonical(Canonical::Cell(schema::<iroha_data_model::sccp::keys_index::SccpPruneCursorV1>())));
    sccp_outbound_messages: Storage<[u8; 32], iroha_data_model::sccp::outbound::SccpOutboundMessageRecordV1> => ("world.sccp_outbound_messages",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<iroha_data_model::sccp::outbound::SccpOutboundMessageRecordV1>() }));
    sccp_outbound_by_nonce: Storage<(iroha_data_model::bridge::SccpNetworkV1, u32, u64), [u8; 32]> => ("world.sccp_outbound_by_nonce",
        Role::Canonical(Canonical::Table { key: schema::<(iroha_data_model::bridge::SccpNetworkV1, u32, u64)>(), value: schema::<[u8; 32]>() }));
    sccp_control_messages: Storage< (iroha_data_model::bridge::SccpNetworkV1, u32, u64), iroha_data_model::sccp::control::SccpControlRecordV1, > => ("world.sccp_control_messages",
        Role::Canonical(Canonical::Table { key: schema::<(iroha_data_model::bridge::SccpNetworkV1, u32, u64)>(), value: schema::<iroha_data_model::sccp::control::SccpControlRecordV1>() }));
    sccp_routes: Storage< iroha_data_model::bridge::SccpNetworkV1, iroha_data_model::sccp::registry::SccpRouteV1, > => ("world.sccp_routes",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::bridge::SccpNetworkV1>(), value: schema::<iroha_data_model::sccp::registry::SccpRouteV1>() }));
    sccp_destination_words: Storage<[u8; 32], (iroha_data_model::bridge::SccpNetworkV1, u32)> => ("world.sccp_destination_words",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<(iroha_data_model::bridge::SccpNetworkV1, u32)>() }));
    sccp_governance_revisions: Storage<iroha_data_model::sccp::governance::SccpGovernanceSubjectV1, u64> => ("world.sccp_governance_revisions",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::sccp::governance::SccpGovernanceSubjectV1>(), value: schema::<u64>() }));
    sccp_inbound_messages: Storage<[u8; 32], iroha_data_model::sccp::inbound::SccpInboundRecordV1> => ("world.sccp_inbound_messages",
        Role::Canonical(Canonical::Table { key: schema::<[u8; 32]>(), value: schema::<iroha_data_model::sccp::inbound::SccpInboundRecordV1>() }));
    sccp_pending_counts: Storage<(iroha_data_model::bridge::SccpNetworkV1, u32), (u64, u64)> => ("world.sccp_pending_counts",
        Role::Canonical(Canonical::Table { key: schema::<(iroha_data_model::bridge::SccpNetworkV1, u32)>(), value: schema::<(u64, u64)>() }));
    sccp_light_clients: Storage< iroha_data_model::bridge::SccpNetworkV1, iroha_data_model::sccp::light_client::SccpLightClientV1, > => ("world.sccp_light_clients",
        Role::Canonical(Canonical::Table { key: schema::<iroha_data_model::bridge::SccpNetworkV1>(), value: schema::<iroha_data_model::sccp::light_client::SccpLightClientV1>() }));
    sccp_light_client_sets: Storage< (iroha_data_model::bridge::SccpNetworkV1, u64), iroha_data_model::sccp::light_client::SccpLcConsensusSetV1, > => ("world.sccp_light_client_sets",
        Role::Canonical(Canonical::Table { key: schema::<(iroha_data_model::bridge::SccpNetworkV1, u64)>(), value: schema::<iroha_data_model::sccp::light_client::SccpLcConsensusSetV1>() }));
    sccp_light_client_checkpoints: Storage< (iroha_data_model::bridge::SccpNetworkV1, u64), iroha_data_model::sccp::light_client::SccpLcCheckpointV1, > => ("world.sccp_light_client_checkpoints",
        Role::Canonical(Canonical::Table { key: schema::<(iroha_data_model::bridge::SccpNetworkV1, u64)>(), value: schema::<iroha_data_model::sccp::light_client::SccpLcCheckpointV1>() }));
    sccp_light_client_stride_index: Storage<(iroha_data_model::bridge::SccpNetworkV1, u64), u64> => ("world.sccp_light_client_stride_index",
        Role::Canonical(Canonical::Table { key: schema::<(iroha_data_model::bridge::SccpNetworkV1, u64)>(), value: schema::<u64>() }));
});
