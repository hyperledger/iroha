//! Workload generation utilities for Izanami, covering diverse ISI mixes and trigger flavours.
use color_eyre::{Result, eyre::eyre};
use iroha_config::parameters::defaults as config_defaults;
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::AccountId,
    account::NewAccount,
    account::rekey::{AccountAlias, AccountAliasDomain},
    events::{
        EventFilterBox,
        execute_trigger::ExecuteTriggerEventFilter,
        pipeline::{PipelineEventFilterBox, TransactionEventFilter},
        prelude::{AccountEventFilter, AccountEventSet, DataEventFilter, TimeEventFilter},
        time::{ExecutionTime, Schedule},
    },
    isi::{
        RemoveAssetKeyValue, SetAssetKeyValue,
        settlement::{
            DvpIsi, SettlementId, SettlementInstructionBox, SettlementLeg, SettlementPlan,
        },
        sorafs::{
            ApprovePinManifest, IssueReplicationOrder, RegisterPinManifest,
            SetProviderIngestCompletionAuthority,
        },
        space_directory::{
            ExpireSpaceDirectoryManifest, PublishSpaceDirectoryManifest,
            RevokeSpaceDirectoryManifest,
        },
        staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
    },
    nexus::{
        Allowance, AllowanceWindow, AssetPermissionManifest, CapabilityScope, ManifestEffect,
        ManifestEntry, ManifestVersion, UniversalAccountId,
    },
    parameter::system::SumeragiNposParameters,
    prelude::*,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ChunkerProfileHandle, ManifestDigest, ProviderIngestCompletionAuthorityV1,
            ProviderIngestCompletionSignerPolicyV1, ReplicationOrderId,
        },
    },
    trigger::{
        Trigger,
        action::{Action, Repeats},
    },
};
use iroha_executor_data_model::permission::{
    account::{CanModifyAccountMetadata, CanRegisterAccount},
    asset::{CanMintAssetWithDefinition, CanModifyAssetMetadataWithDefinition},
    asset_definition::CanModifyAssetDefinitionMetadata,
    domain::CanModifyDomainMetadata,
    nexus::CanPublishSpaceDirectoryManifest,
    nft::CanRegisterNft,
    role::CanManageRoles,
    sorafs::CanIssueSorafsReplicationOrder,
    trigger::CanRegisterTrigger,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use norito::{
    codec::Encode as NoritoEncode,
    json::{Map as JsonMap, Value as JsonValue},
};
use rand::{Rng, RngCore, rngs::StdRng, seq::IndexedRandom};
use sorafs_manifest::{
    DagCodecId, MANIFEST_DAG_CODEC, ManifestBuilder,
    capacity::{
        REPLICATION_ORDER_VERSION_V1, ReplicationAssignmentV1, ReplicationOrderSlaV1,
        ReplicationOrderV1,
    },
    chunker_registry,
};
#[cfg(test)]
use std::sync::Mutex as StdMutex;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
/// Base seed used for deterministic peer identity derivation in Izanami networks.
pub const IZANAMI_BASE_SEED: &str = "izanami-chaos";
use crate::config::WorkloadProfile;
use crate::smart_contracts;
use tokio::sync::Mutex;
#[cfg(test)]
fn quantity_to_u64_exact(quantity: &Quantity) -> Option<u64> {
    if quantity.scale() != 0 {
        return None;
    }
    quantity
        .as_numeric()
        .try_mantissa_u128()
        .and_then(|value| u64::try_from(value).ok())
}
/// Record describing an account and its signing material.
#[derive(Clone, Debug)]
pub struct AccountRecord {
    pub id: AccountId,
    pub key_pair: KeyPair,
    pub uaid: Option<UniversalAccountId>,
}
/// Transaction plan produced by the workload generator.
#[derive(Clone, Debug)]
pub struct TransactionPlan {
    pub label: &'static str,
    pub instructions: Vec<InstructionBox>,
    pub signer: AccountRecord,
    pub expect_success: bool,
    pub(crate) state_updates: Vec<PlanUpdate>,
}
#[derive(Clone, Debug)]
pub(crate) enum PlanUpdate {
    TrackAccount(AccountRecord),
    RegisterTrigger(TriggerId),
    RegisterCallTrigger(TriggerId),
    TrackRepeatableTrigger(TriggerId),
    TrackAssetInstance(AssetId),
    MintTriggerRepetitions { trigger_id: TriggerId, amount: u32 },
    BurnTriggerRepetitions { trigger_id: TriggerId, amount: u32 },
    ReleaseTriggerRepetitionsReservation { trigger_id: TriggerId, amount: u32 },
    SetTriggerMetadata { trigger_id: TriggerId, key: Name },
    ClearTriggerMetadata(TriggerId),
}
impl PlanUpdate {
    fn apply(&self, state: &mut ChaosState, succeeded: bool) {
        match self {
            PlanUpdate::TrackAccount(record) if succeeded => {
                state.track_account(record.clone());
            }
            PlanUpdate::RegisterTrigger(trigger_id) if succeeded => {
                if !state.registered_triggers.contains(trigger_id) {
                    state.registered_triggers.push(trigger_id.clone());
                }
            }
            PlanUpdate::RegisterCallTrigger(trigger_id) if succeeded => {
                if !state.call_triggers.contains(trigger_id) {
                    state.call_triggers.push(trigger_id.clone());
                }
            }
            PlanUpdate::TrackRepeatableTrigger(trigger_id) if succeeded => {
                state.track_repeatable_trigger(trigger_id.clone());
            }
            PlanUpdate::TrackAssetInstance(asset_id) if succeeded => {
                state.asset_instances.insert(asset_id.clone());
            }
            PlanUpdate::BurnTriggerRepetitions { trigger_id, amount } if succeeded => {
                state.release_trigger_repetitions_reservation(trigger_id, *amount);
            }
            PlanUpdate::MintTriggerRepetitions { trigger_id, amount } if succeeded => {
                let _ = (trigger_id, amount);
            }
            PlanUpdate::ReleaseTriggerRepetitionsReservation { trigger_id, amount }
                if !succeeded =>
            {
                state.release_trigger_repetitions_reservation(trigger_id, *amount);
            }
            PlanUpdate::SetTriggerMetadata { trigger_id, key } if succeeded => {
                state
                    .trigger_metadata
                    .entry(trigger_id.clone())
                    .or_default()
                    .insert(key.clone());
            }
            PlanUpdate::ClearTriggerMetadata(trigger_id) if succeeded => {
                state.trigger_metadata.remove(trigger_id);
            }
            _ => {}
        }
    }
}
impl TransactionPlan {
    fn apply_updates(&self, state: &mut ChaosState, succeeded: bool) {
        for update in &self.state_updates {
            update.apply(state, succeeded);
        }
    }
    pub fn burn_trigger_repetitions(&self) -> Option<(TriggerId, u32)> {
        self.instructions.iter().find_map(|instruction| {
            let burn = instruction.as_any().downcast_ref::<BurnBox>()?;
            match burn {
                BurnBox::TriggerRepetitions(burn) => Some((burn.destination.clone(), burn.object)),
                BurnBox::Asset(_) => None,
            }
        })
    }
    pub fn mint_trigger_repetitions(&self) -> Option<(TriggerId, u32)> {
        self.instructions.iter().find_map(|instruction| {
            let mint = instruction.as_any().downcast_ref::<MintBox>()?;
            match mint {
                MintBox::TriggerRepetitions(mint) => Some((mint.destination.clone(), mint.object)),
                MintBox::Asset(_) => None,
            }
        })
    }
}
fn json_pair<K, V>(key: K, value: V) -> JsonValue
where
    K: Into<String>,
    V: Into<JsonValue>,
{
    let mut map = JsonMap::new();
    map.insert(key.into(), value.into());
    JsonValue::Object(map)
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
fn nexus_fee_seed_amount() -> Quantity {
    1_000_000_u64.into()
}
fn account_from_record(record: &AccountRecord, _domain: &DomainId) -> NewAccount {
    let builder = Account::new(record.id.clone());
    if let Some(uaid) = record.uaid {
        builder.with_uaid(Some(uaid))
    } else {
        builder
    }
}
pub(crate) fn peer_keypair(index: usize) -> Result<KeyPair> {
    let seed = format!("{IZANAMI_BASE_SEED}-peer-{index}");
    let mut seed_bytes = seed.into_bytes();
    seed_bytes.extend_from_slice(b":bls");
    KeyPair::try_from_seed(seed_bytes, Algorithm::BlsNormal)
        .map_err(|err| eyre!("failed to derive Izanami peer {index} BLS key pair: {err}"))
}
fn nexus_gas_keypair() -> Result<KeyPair> {
    KeyPair::try_from_seed(b"izanami::nexus::gas-account".to_vec(), Algorithm::Ed25519)
        .map_err(|err| eyre!("failed to derive Izanami Nexus gas account key pair: {err}"))
}
/// Deterministic gas/sink account used by Izanami Nexus profiles.
pub(crate) fn nexus_gas_account_id() -> Result<AccountId> {
    Ok(AccountId::new(nexus_gas_keypair()?.public_key().clone()))
}
/// Prepared chaos state with pre-built genesis instructions.
#[derive(Debug)]
pub struct PreparedChaos {
    pub state: ChaosState,
    pub genesis: Vec<Vec<InstructionBox>>,
    pub recipes: Vec<RecipeKind>,
    /// Provider-owner bindings that the local network must load before genesis.
    pub sorafs_provider_owners: BTreeMap<String, String>,
}
/// Build post-topology NPoS bootstrap instructions using an explicit minimum self-bond.
pub fn npos_post_topology_instructions(
    peer_count: usize,
    bootstrap_public_lanes: &[LaneId],
    min_self_bond: &Quantity,
    stake_asset_id: &AssetDefinitionId,
    escrow_account_id: &AccountId,
) -> Result<Vec<InstructionBox>> {
    let effective_peers = peer_count.max(1);
    let mut instructions = Vec::new();
    for index in 0..effective_peers {
        let key_pair = peer_keypair(index)?;
        let validator_id = AccountId::new(key_pair.public_key().clone());
        for &lane_id in bootstrap_public_lanes {
            instructions.push(InstructionBox::from(RegisterPublicLaneValidator {
                lane_id,
                validator: validator_id.clone(),
                peer_id: PeerId::from(validator_id.expect_single_signatory().clone()),
                stake_account: validator_id.clone(),
                initial_stake: min_self_bond.clone(),
                metadata: Metadata::default(),
                monetary_plan:
                    iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                        AssetId::new(stake_asset_id.clone(), validator_id.clone()),
                        AssetId::new(stake_asset_id.clone(), escrow_account_id.clone()),
                        min_self_bond.clone(),
                    ),
            }));
            instructions.push(InstructionBox::from(ActivatePublicLaneValidator {
                lane_id,
                validator: validator_id.clone(),
            }));
        }
    }
    Ok(instructions)
}
/// Create the baseline chaos state and its associated genesis block.
pub fn prepare_state(
    account_count: usize,
    peer_count: Option<usize>,
    nexus: Option<&crate::config::NexusProfile>,
    workload_profile: WorkloadProfile,
    allow_contract_deploy_in_stable: bool,
) -> Result<PreparedChaos> {
    const MIN_WORKLOAD_USER_ACCOUNTS: usize = 64;
    let effective_accounts = account_count.max(MIN_WORKLOAD_USER_ACCOUNTS);
    let base_domain =
        DomainId::try_new("chaosnet", "universal").map_err(|_| eyre!("invalid base domain"))?;
    let treasury_key = KeyPair::try_random()
        .map_err(|err| eyre!("failed to generate Izanami treasury key pair: {err}"))?;
    let treasury_id = AccountId::new(treasury_key.public_key().clone());
    let treasury = AccountRecord {
        id: treasury_id,
        key_pair: treasury_key,
        uaid: None,
    };
    let mut users = Vec::with_capacity(effective_accounts);
    for _ in 0..effective_accounts {
        let key = KeyPair::try_random()
            .map_err(|err| eyre!("failed to generate Izanami user account key pair: {err}"))?;
        let account_id = AccountId::new(key.public_key().clone());
        users.push(AccountRecord {
            id: account_id,
            key_pair: key,
            uaid: None,
        });
    }
    let asset_quantity_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        base_domain.clone(),
        "chaos_coin"
            .parse()
            .map_err(|_| eyre!("failed to parse numeric asset name"))?,
    );
    let asset_nft_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        base_domain.clone(),
        "chaos_collectible"
            .parse()
            .map_err(|_| eyre!("failed to parse nft asset name"))?,
    );
    let dataspaces: Vec<DataSpaceId> = nexus
        .map(|profile| {
            let ids: Vec<DataSpaceId> = profile
                .dataspace_catalog
                .entries()
                .iter()
                .map(|entry| entry.id)
                .collect();
            if ids.is_empty() {
                vec![DataSpaceId::UNIVERSAL]
            } else {
                ids
            }
        })
        .unwrap_or_else(|| vec![DataSpaceId::UNIVERSAL]);
    let bootstrap_public_lanes: Vec<LaneId> = nexus
        .map(|profile| profile.bootstrap_public_lanes.clone())
        .unwrap_or_default();
    let sorafs_replication = if nexus.is_some() {
        let descriptor = chunker_registry::default_descriptor();
        let manifest_root_cid = sorafs_manifest::canonical_manifest_root_cid(
            *Hash::new(b"izanami-sorafs-content-root").as_ref(),
        );
        let manifest = ManifestBuilder::new()
            .root_cid(manifest_root_cid.clone())
            .dag_codec(DagCodecId(MANIFEST_DAG_CODEC))
            .chunking_from_registry(descriptor.id)
            .chunk_digest_sha3_256(*Hash::new(b"izanami-sorafs-chunk-digest").as_ref())
            .por_root(*Hash::new(b"izanami-sorafs-por-root").as_ref())
            .content_length(1_073_741_824)
            .car_digest(*Hash::new(b"izanami-sorafs-car-archive").as_ref())
            .car_size(1_073_742_080)
            .pin_policy(sorafs_manifest::PinPolicy {
                min_replicas: 1,
                storage_class: sorafs_manifest::StorageClass::Warm,
                retention_epoch: u64::MAX,
            })
            .build()
            .map_err(|err| eyre!("failed to build Izanami SoraFS manifest: {err}"))?;
        let manifest_digest = ManifestDigest::from_manifest(&manifest)
            .map_err(|err| eyre!("failed to digest Izanami SoraFS manifest: {err}"))?;
        let manifest_payload = manifest
            .encode()
            .map_err(|err| eyre!("failed to encode Izanami SoraFS manifest: {err}"))?;
        let chunker = ChunkerProfileHandle {
            profile_id: descriptor.id.0,
            namespace: descriptor.namespace.to_string(),
            name: descriptor.name.to_string(),
            semver: descriptor.semver.to_string(),
            multihash_code: descriptor.multihash_code,
        };
        let provider_id = ProviderId::new(*Hash::new(b"izanami-sorafs-provider").as_ref());
        Some(SorafsReplicationSeed {
            manifest_digest,
            manifest_root_cid,
            manifest_payload,
            chunker,
            provider_id,
        })
    } else {
        None
    };
    let mut sorafs_provider_owners = BTreeMap::new();
    if let Some(replication) = sorafs_replication.as_ref() {
        sorafs_provider_owners.insert(
            replication.provider_id.to_string(),
            treasury
                .id
                .canonical_i105()
                .map_err(|error| eyre!("failed to encode Izanami SoraFS owner: {error}"))?,
        );
    }
    let effective_peers = peer_count.unwrap_or(account_count.max(1)).max(1);
    let mut nexus_genesis = Vec::new();
    let mut nexus_staking = None;
    if nexus.is_some() {
        let nexus_domain = DomainId::try_new("nexus", "universal")
            .map_err(|_| eyre!("failed to parse nexus domain id"))?;
        let ivm_domain = DomainId::try_new("ivm", "universal")
            .map_err(|_| eyre!("failed to parse ivm domain id"))?;
        let universal_domain = DomainId::try_new("universal", "universal")
            .map_err(|_| eyre!("failed to parse universal domain id"))?;
        let gas_account_id = nexus_gas_account_id()?;
        let gas_label: Name = "gas"
            .parse()
            .map_err(|_| eyre!("failed to parse gas account label"))?;
        let gas_account = Account::new(gas_account_id.clone()).with_label(Some(AccountAlias::new(
            gas_label,
            Some(AccountAliasDomain::new(ivm_domain.name().clone())),
            DataSpaceId::UNIVERSAL,
        )));
        let stake_asset = nexus
            .map(|profile| profile.stake_asset_id.clone())
            .unwrap_or_else(|| {
                config_defaults::nexus::staking::stake_asset_id()
                    .parse()
                    .expect("default nexus stake asset id should parse")
            });
        let fee_asset = nexus
            .map(|profile| profile.fee_asset_id.clone())
            .unwrap_or_else(|| {
                config_defaults::nexus::fees::fee_asset_id()
                    .parse()
                    .expect("default nexus fee asset id should parse")
            });
        let stake_amount = SumeragiNposParameters::default().min_self_bond().clone();
        let bootstrap_lane_count = u64::try_from(bootstrap_public_lanes.len()).unwrap_or(u64::MAX);
        let total_bootstrap_stake = stake_amount
            .try_mul_decimal(&bootstrap_lane_count.into())
            .expect("bootstrap validator stake must remain representable");
        nexus_genesis.push(InstructionBox::from(Register::domain(Domain::new(
            nexus_domain.clone(),
        ))));
        nexus_genesis.push(InstructionBox::from(Register::domain(Domain::new(
            ivm_domain.clone(),
        ))));
        nexus_genesis.push(InstructionBox::from(Register::domain(Domain::new(
            universal_domain,
        ))));
        nexus_genesis.push(InstructionBox::from(Register::account(gas_account)));
        nexus_genesis.push(InstructionBox::from(Register::asset_definition(
            AssetDefinition::numeric(
                stake_asset.clone(),
                "Nexus Stake".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            ),
        )));
        if fee_asset != stake_asset {
            nexus_genesis.push(InstructionBox::from(Register::asset_definition(
                AssetDefinition::numeric(
                    fee_asset.clone(),
                    "Nexus Fee".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                ),
            )));
        }
        let mut validator_accounts = Vec::new();
        for index in 0..effective_peers {
            let key_pair = peer_keypair(index)?;
            let account_id = AccountId::new(key_pair.public_key().clone());
            validator_accounts.push(AccountRecord {
                id: account_id.clone(),
                key_pair,
                uaid: None,
            });
            nexus_genesis.push(InstructionBox::from(Register::account(Account::new(
                account_id.clone(),
            ))));
        }
        for validator in &validator_accounts {
            if !total_bootstrap_stake.is_zero() {
                nexus_genesis.push(InstructionBox::from(Mint::asset_quantity(
                    total_bootstrap_stake.clone(),
                    AssetId::new(stake_asset.clone(), validator.id.clone()),
                )));
            }
        }
        nexus_genesis.push(InstructionBox::from(Grant::account_permission(
            CanMintAssetWithDefinition {
                asset_definition: stake_asset.clone(),
            },
            treasury.id.clone(),
        )));
        if fee_asset != stake_asset {
            nexus_genesis.push(InstructionBox::from(Grant::account_permission(
                CanMintAssetWithDefinition {
                    asset_definition: fee_asset.clone(),
                },
                treasury.id.clone(),
            )));
        }
        nexus_staking = Some(NexusStakingSetup {
            #[cfg(test)]
            stake_asset,
            fee_asset,
            #[cfg(test)]
            fee_sink: gas_account_id.clone(),
            #[cfg(test)]
            stake_escrow: gas_account_id.clone(),
            #[cfg(test)]
            slash_sink: gas_account_id,
            validator_accounts,
        });
    }
    let mut genesis_tx = Vec::new();
    genesis_tx.push(InstructionBox::from(Register::domain(Domain::new(
        base_domain.clone(),
    ))));
    genesis_tx.push(InstructionBox::from(Register::asset_definition(
        AssetDefinition::numeric(
            asset_quantity_id.clone(),
            "Numeric Asset".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ),
    )));
    genesis_tx.push(InstructionBox::from(Register::asset_definition(
        AssetDefinition::numeric(
            asset_nft_id.clone(),
            "NFT Asset".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .mintable_once(),
    )));
    genesis_tx.push(InstructionBox::from(Register::account(
        account_from_record(&treasury, &base_domain),
    )));
    for account in &users {
        genesis_tx.push(InstructionBox::from(Register::account(
            account_from_record(account, &base_domain),
        )));
    }
    genesis_tx.extend(nexus_genesis);
    if let Some(setup) = nexus_staking.as_ref() {
        let fee_float = nexus_fee_seed_amount();
        genesis_tx.push(InstructionBox::from(Mint::asset_quantity(
            fee_float.clone(),
            AssetId::new(setup.fee_asset.clone(), treasury.id.clone()),
        )));
        for account in &users {
            genesis_tx.push(InstructionBox::from(Mint::asset_quantity(
                fee_float.clone(),
                AssetId::new(setup.fee_asset.clone(), account.id.clone()),
            )));
        }
        for validator in &setup.validator_accounts {
            genesis_tx.push(InstructionBox::from(Mint::asset_quantity(
                fee_float.clone(),
                AssetId::new(setup.fee_asset.clone(), validator.id.clone()),
            )));
        }
    }
    genesis_tx.push(InstructionBox::from(Grant::account_permission(
        CanModifyDomainMetadata {
            domain: base_domain.clone(),
        },
        treasury.id.clone(),
    )));
    genesis_tx.push(InstructionBox::from(Grant::account_permission(
        CanRegisterAccount {
            domain: base_domain.clone(),
        },
        treasury.id.clone(),
    )));
    genesis_tx.push(InstructionBox::from(Grant::account_permission(
        CanMintAssetWithDefinition {
            asset_definition: asset_quantity_id.clone(),
        },
        treasury.id.clone(),
    )));
    genesis_tx.push(InstructionBox::from(Grant::account_permission(
        CanRegisterNft {
            domain: base_domain.clone(),
        },
        treasury.id.clone(),
    )));
    genesis_tx.push(InstructionBox::from(Grant::account_permission(
        CanModifyAssetDefinitionMetadata {
            asset_definition: asset_quantity_id.clone(),
        },
        treasury.id.clone(),
    )));
    genesis_tx.push(InstructionBox::from(Grant::account_permission(
        CanModifyAssetDefinitionMetadata {
            asset_definition: asset_nft_id.clone(),
        },
        treasury.id.clone(),
    )));
    genesis_tx.push(InstructionBox::from(Grant::account_permission(
        CanModifyAssetMetadataWithDefinition {
            asset_definition: asset_quantity_id.clone(),
        },
        treasury.id.clone(),
    )));
    genesis_tx.push(InstructionBox::from(Grant::account_permission(
        CanManageRoles,
        treasury.id.clone(),
    )));
    genesis_tx.push(InstructionBox::from(Grant::account_permission(
        CanRegisterTrigger {
            authority: treasury.id.clone(),
        },
        treasury.id.clone(),
    )));
    let dataspace_grant_txs: Vec<Vec<InstructionBox>> = dataspaces
        .iter()
        .map(|dataspace| {
            vec![InstructionBox::from(Grant::account_permission(
                CanPublishSpaceDirectoryManifest {
                    dataspace: *dataspace,
                },
                treasury.id.clone(),
            ))]
        })
        .collect();
    if sorafs_replication.is_some() {
        genesis_tx.push(InstructionBox::from(Grant::account_permission(
            CanIssueSorafsReplicationOrder,
            treasury.id.clone(),
        )));
    }
    let initial_float: Quantity = 1_000_000_000_u64.into();
    let initial_user_balance: Quantity = 1_000_000_000_u64.into();
    let treasury_asset_id = AssetId::new(asset_quantity_id.clone(), treasury.id.clone());
    genesis_tx.push(InstructionBox::from(Mint::asset_quantity(
        initial_float,
        treasury_asset_id.clone(),
    )));
    for account in &users {
        genesis_tx.push(InstructionBox::from(Mint::asset_quantity(
            initial_user_balance.clone(),
            AssetId::new(asset_quantity_id.clone(), account.id.clone()),
        )));
    }
    let mut state = ChaosState::new(
        base_domain.clone(),
        treasury,
        users,
        asset_quantity_id,
        asset_nft_id,
        dataspaces,
        sorafs_replication,
        nexus_staking,
        matches!(workload_profile, WorkloadProfile::Stable),
    );
    state.asset_instances.insert(treasury_asset_id);
    let mut recipes = match workload_profile {
        WorkloadProfile::Stable => {
            let mut recipes = BASE_RECIPES_STABLE.to_vec();
            if allow_contract_deploy_in_stable {
                recipes.extend([
                    RecipeKind::DeployIvmContract,
                    RecipeKind::DeployKotodamaContract,
                ]);
            }
            recipes
        }
        WorkloadProfile::Chaos => BASE_RECIPES_CHAOS.to_vec(),
    };
    if nexus.is_some() {
        let extra = match workload_profile {
            WorkloadProfile::Stable => NEXUS_RECIPES_STABLE,
            WorkloadProfile::Chaos => NEXUS_RECIPES_CHAOS,
        };
        recipes.extend_from_slice(extra);
    }
    let mut genesis = vec![genesis_tx];
    genesis.extend(dataspace_grant_txs);
    Ok(PreparedChaos {
        state,
        genesis,
        recipes,
        sorafs_provider_owners,
    })
}
/// Workload engine that produces stochastic transaction plans.
#[derive(Debug)]
pub struct WorkloadEngine {
    state: Mutex<ChaosState>,
    recipes: Vec<RecipeKind>,
    plan_sequence: AtomicU64,
    #[cfg(test)]
    recipe_override: StdMutex<Option<RecipeKind>>,
}
impl WorkloadEngine {
    pub fn new(state: ChaosState, recipes: Vec<RecipeKind>) -> Self {
        Self {
            state: Mutex::new(state),
            recipes,
            plan_sequence: AtomicU64::new(0),
            #[cfg(test)]
            recipe_override: StdMutex::new(None),
        }
    }
    pub async fn next_plan(&self, rng: &mut StdRng) -> Result<TransactionPlan> {
        self.next_ordered_plan(rng).await.map(|(_, plan)| plan)
    }
    pub async fn next_ordered_plan(&self, rng: &mut StdRng) -> Result<(u64, TransactionPlan)> {
        #[cfg(test)]
        if let Some(kind) = {
            let guard = self
                .recipe_override
                .lock()
                .expect("override mutex poisoned");
            *guard
        } {
            let mut guard = self.state.lock().await;
            let plan = guard.produce_plan(kind, rng)?;
            let order = self.plan_sequence.fetch_add(1, Ordering::Relaxed);
            return Ok((order, plan));
        }
        let kind = *self
            .recipes
            .choose(rng)
            .ok_or_else(|| eyre!("no recipes configured"))?;
        let mut guard = self.state.lock().await;
        let plan = guard.produce_plan(kind, rng)?;
        let order = self.plan_sequence.fetch_add(1, Ordering::Relaxed);
        Ok((order, plan))
    }
    pub async fn record_result(&self, plan: &TransactionPlan, succeeded: bool) {
        if plan.state_updates.is_empty() {
            return;
        }
        let mut guard = self.state.lock().await;
        plan.apply_updates(&mut guard, succeeded);
    }
    pub async fn sync_trigger_repetitions(&self, trigger_id: &TriggerId, repeats: Option<u32>) {
        let mut guard = self.state.lock().await;
        guard.sync_repeatable_trigger_repetitions(trigger_id.clone(), repeats);
    }
    pub async fn mark_trigger_unknown(&self, trigger_id: &TriggerId) {
        let mut guard = self.state.lock().await;
        guard
            .repeatable_trigger_state
            .insert(trigger_id.clone(), RepeatableTriggerState::Unknown);
    }
    #[cfg(test)]
    fn set_recipe_override(&self, recipe: Option<RecipeKind>) {
        *self
            .recipe_override
            .lock()
            .expect("override mutex poisoned") = recipe;
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum RecipeKind {
    DuplicateDomain,
    RegisterAccount,
    DuplicateAccount,
    RegisterUaidAccount,
    RegisterAssetDefinition,
    UnregisterAssetDefinition,
    MintAsset,
    TransferAsset,
    BurnAsset,
    SetAccountKeyValue,
    RemoveAccountKeyValue,
    SetDomainKeyValue,
    RemoveDomainKeyValue,
    SetAssetDefinitionKeyValue,
    RemoveAssetDefinitionKeyValue,
    SetAssetInstanceKeyValue,
    RemoveAssetInstanceKeyValue,
    RegisterNft,
    TransferNft,
    RegisterRole,
    GrantRole,
    RevokeRole,
    RegisterTimeTrigger,
    RegisterDataTrigger,
    RegisterPipelineTrigger,
    SetTriggerKeyValue,
    RemoveTriggerKeyValue,
    MintTriggerRepetitions,
    BurnTriggerRepetitions,
    ExecuteTrigger,
    ExecuteMissingTrigger,
    DeployIvmContract,
    DeployKotodamaContract,
    PublishSpaceDirectoryManifest,
    RevokeSpaceDirectoryManifest,
    ExpireSpaceDirectoryManifest,
    DvpSettlement,
    IssueReplicationOrder,
}
// Stable runs default to the preallocated hot path only. Contract deployment remains an
// explicit opt-in escape hatch for targeted smoke coverage.
const BASE_RECIPES_STABLE: &[RecipeKind] = &[RecipeKind::TransferAsset];
const BASE_RECIPES_CHAOS: &[RecipeKind] = &[
    RecipeKind::RegisterAssetDefinition,
    RecipeKind::RegisterAccount,
    RecipeKind::RegisterUaidAccount,
    RecipeKind::RegisterNft,
    RecipeKind::MintAsset,
    RecipeKind::TransferAsset,
    RecipeKind::TransferNft,
    RecipeKind::BurnAsset,
    RecipeKind::SetAccountKeyValue,
    RecipeKind::RemoveAccountKeyValue,
    RecipeKind::SetDomainKeyValue,
    RecipeKind::RemoveDomainKeyValue,
    RecipeKind::SetAssetDefinitionKeyValue,
    RecipeKind::RemoveAssetDefinitionKeyValue,
    RecipeKind::SetAssetInstanceKeyValue,
    RecipeKind::RemoveAssetInstanceKeyValue,
    RecipeKind::RegisterRole,
    RecipeKind::GrantRole,
    RecipeKind::RevokeRole,
    RecipeKind::RegisterTimeTrigger,
    RecipeKind::RegisterDataTrigger,
    RecipeKind::RegisterPipelineTrigger,
    RecipeKind::SetTriggerKeyValue,
    RecipeKind::RemoveTriggerKeyValue,
    RecipeKind::MintTriggerRepetitions,
    RecipeKind::BurnTriggerRepetitions,
    RecipeKind::ExecuteTrigger,
    RecipeKind::ExecuteMissingTrigger,
    RecipeKind::DuplicateDomain,
    RecipeKind::DuplicateAccount,
    RecipeKind::UnregisterAssetDefinition,
    RecipeKind::DeployIvmContract,
    RecipeKind::DeployKotodamaContract,
    RecipeKind::PublishSpaceDirectoryManifest,
    RecipeKind::RevokeSpaceDirectoryManifest,
    RecipeKind::ExpireSpaceDirectoryManifest,
];
const NEXUS_RECIPES_STABLE: &[RecipeKind] = &[];
// Replication completion requires a fresh committed anchor and the exact
// chain-authoritative owner, assignment revision, and signer-policy tuple.
// TODO: Add live Nexus staking recipes after the workload can authenticate the
// current height, validator tenure, stake custody, and reward authority.
const NEXUS_RECIPES_CHAOS: &[RecipeKind] =
    &[RecipeKind::DvpSettlement, RecipeKind::IssueReplicationOrder];
/// Genesis staking wiring retained for workload funding.
///
/// Only `fee_asset` and `validator_accounts` drive the current workload; the custody accounts and
/// stake asset are asserted by tests until the staking recipes above are implemented.
#[derive(Debug, Clone)]
struct NexusStakingSetup {
    #[cfg(test)]
    stake_asset: AssetDefinitionId,
    fee_asset: AssetDefinitionId,
    #[cfg(test)]
    fee_sink: AccountId,
    #[cfg(test)]
    stake_escrow: AccountId,
    #[cfg(test)]
    slash_sink: AccountId,
    validator_accounts: Vec<AccountRecord>,
}
#[derive(Debug, Clone)]
pub struct ChaosState {
    base_domain: DomainId,
    treasury: AccountRecord,
    users: Vec<AccountRecord>,
    uaid_accounts: HashMap<UniversalAccountId, AccountRecord>,
    asset_quantity: AssetDefinitionId,
    dataspaces: Vec<DataSpaceId>,
    created_domains: HashSet<DomainId>,
    registered_roles: Vec<RoleId>,
    role_memberships: HashMap<RoleId, HashSet<AccountId>>,
    registered_triggers: Vec<TriggerId>,
    call_triggers: Vec<TriggerId>,
    asset_definitions: HashSet<AssetDefinitionId>,
    asset_definitions_unclaimed: HashSet<AssetDefinitionId>,
    asset_instances: HashSet<AssetId>,
    nft_holdings: HashMap<NftId, AccountId>,
    account_metadata: HashMap<AccountId, HashSet<Name>>,
    domain_metadata: HashMap<DomainId, HashSet<Name>>,
    asset_definition_metadata: HashMap<AssetDefinitionId, HashSet<Name>>,
    asset_metadata: HashMap<AssetId, HashSet<Name>>,
    trigger_metadata: HashMap<TriggerId, HashSet<Name>>,
    repeatable_trigger_state: HashMap<TriggerId, RepeatableTriggerState>,
    pending_trigger_repetitions: HashMap<TriggerId, u32>,
    space_directory_manifests: HashMap<UniversalAccountId, HashSet<DataSpaceId>>,
    pending_replication_orders: Vec<ReplicationOrderId>,
    sorafs_replication: Option<SorafsReplicationSeed>,
    sorafs_replication_ready: bool,
    nexus_staking: Option<NexusStakingSetup>,
    low_contention_transfers: bool,
    counters: ChaosCounters,
}
#[derive(Clone, Debug)]
struct SorafsReplicationSeed {
    manifest_digest: ManifestDigest,
    manifest_root_cid: Vec<u8>,
    manifest_payload: Vec<u8>,
    chunker: ChunkerProfileHandle,
    provider_id: ProviderId,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RepeatableTriggerState {
    Unknown,
    Known { repetitions: u32 },
    Missing,
}
#[derive(Debug, Default, Clone)]
struct ChaosCounters {
    account: u64,
    uaid: u64,
    transfer: u64,
    trigger: u64,
    role: u64,
    asset_definition: u64,
    nft: u64,
    metadata: u64,
    invalid: u64,
    settlement: u64,
    replication: u64,
}
impl ChaosState {
    pub fn base_domain(&self) -> &DomainId {
        &self.base_domain
    }
    #[allow(clippy::too_many_arguments)]
    fn new(
        base_domain: DomainId,
        treasury: AccountRecord,
        users: Vec<AccountRecord>,
        asset_quantity: AssetDefinitionId,
        asset_nft: AssetDefinitionId,
        dataspaces: Vec<DataSpaceId>,
        sorafs_replication: Option<SorafsReplicationSeed>,
        nexus_staking: Option<NexusStakingSetup>,
        low_contention_transfers: bool,
    ) -> Self {
        let mut asset_definitions = HashSet::new();
        asset_definitions.insert(asset_quantity.clone());
        asset_definitions.insert(asset_nft);
        let mut uaid_accounts = HashMap::new();
        if let Some(uaid) = treasury.uaid {
            uaid_accounts.insert(uaid, treasury.clone());
        }
        for account in &users {
            if let Some(uaid) = account.uaid {
                uaid_accounts.insert(uaid, account.clone());
            }
        }
        Self {
            base_domain,
            treasury,
            users,
            uaid_accounts,
            asset_quantity,
            dataspaces,
            created_domains: HashSet::new(),
            registered_roles: Vec::new(),
            role_memberships: HashMap::new(),
            registered_triggers: Vec::new(),
            call_triggers: Vec::new(),
            asset_definitions,
            asset_definitions_unclaimed: HashSet::new(),
            asset_instances: HashSet::new(),
            nft_holdings: HashMap::new(),
            account_metadata: HashMap::new(),
            domain_metadata: HashMap::new(),
            asset_definition_metadata: HashMap::new(),
            asset_metadata: HashMap::new(),
            trigger_metadata: HashMap::new(),
            repeatable_trigger_state: HashMap::new(),
            pending_trigger_repetitions: HashMap::new(),
            space_directory_manifests: HashMap::new(),
            pending_replication_orders: Vec::new(),
            sorafs_replication,
            sorafs_replication_ready: false,
            nexus_staking,
            low_contention_transfers,
            counters: ChaosCounters::default(),
        }
    }
    fn track_account(&mut self, record: AccountRecord) {
        if !self.users.iter().any(|existing| existing.id == record.id) {
            self.users.push(record.clone());
        }
        if let Some(uaid) = record.uaid {
            self.uaid_accounts.insert(uaid, record.clone());
        }
    }
    fn maybe_prefund_nexus_fee_asset(&self, account_id: &AccountId) -> Vec<InstructionBox> {
        self.nexus_staking
            .as_ref()
            .map(|setup| {
                vec![InstructionBox::from(Mint::asset_quantity(
                    nexus_fee_seed_amount(),
                    AssetId::new(setup.fee_asset.clone(), account_id.clone()),
                ))]
            })
            .unwrap_or_default()
    }
    fn allocate_uaid_record(&mut self) -> Result<AccountRecord> {
        let _ = self.bump_account();
        let key = KeyPair::try_random()
            .map_err(|err| eyre!("failed to generate Izanami UAID account key pair: {err}"))?;
        let uaid = self.next_uaid();
        let account_id = AccountId::new(key.public_key().clone());
        Ok(AccountRecord {
            id: account_id,
            key_pair: key,
            uaid: Some(uaid),
        })
    }
    fn next_uaid(&mut self) -> UniversalAccountId {
        let suffix = self.bump_uaid();
        let seed = format!("izanami-uaid-{suffix}");
        UniversalAccountId::from_hash(Hash::new(seed.as_bytes()))
    }
    fn pick_uaid_without_manifest(
        &self,
        dataspace: DataSpaceId,
        rng: &mut StdRng,
    ) -> Option<UniversalAccountId> {
        let eligible: Vec<_> = self
            .uaid_accounts
            .keys()
            .filter(|uaid| {
                !self
                    .space_directory_manifests
                    .get(*uaid)
                    .is_some_and(|spaces| spaces.contains(&dataspace))
            })
            .cloned()
            .collect();
        eligible.choose(rng).cloned()
    }
    fn pick_manifest_for_dataspace(
        &self,
        dataspace: DataSpaceId,
        rng: &mut StdRng,
    ) -> Option<UniversalAccountId> {
        let candidates: Vec<_> = self
            .space_directory_manifests
            .iter()
            .filter(|(_, spaces)| spaces.contains(&dataspace))
            .map(|(uaid, _)| *uaid)
            .collect();
        candidates.choose(rng).copied()
    }
    fn random_dataspace(&self, rng: &mut StdRng) -> DataSpaceId {
        *self
            .dataspaces
            .choose(rng)
            .unwrap_or(&DataSpaceId::UNIVERSAL)
    }
    fn mark_manifest_removed(&mut self, uaid: UniversalAccountId, dataspace: DataSpaceId) {
        if let Some(spaces) = self.space_directory_manifests.get_mut(&uaid) {
            spaces.remove(&dataspace);
            if spaces.is_empty() {
                self.space_directory_manifests.remove(&uaid);
            }
        }
    }
    fn produce_plan(&mut self, kind: RecipeKind, rng: &mut StdRng) -> Result<TransactionPlan> {
        match kind {
            RecipeKind::DuplicateDomain => Ok(self.plan_duplicate_domain()),
            RecipeKind::RegisterAccount => self.plan_register_account(),
            RecipeKind::DuplicateAccount => self.plan_duplicate_account(rng),
            RecipeKind::RegisterUaidAccount => self.plan_register_uaid_account(),
            RecipeKind::RegisterAssetDefinition => self.plan_register_asset_definition(),
            RecipeKind::UnregisterAssetDefinition => Ok(self.plan_unregister_asset_definition(rng)),
            RecipeKind::RegisterNft => self.plan_register_nft(rng),
            RecipeKind::TransferNft => self.plan_transfer_nft(rng),
            RecipeKind::MintAsset => self.plan_mint_asset(rng),
            RecipeKind::TransferAsset => self.plan_transfer_asset(rng),
            RecipeKind::BurnAsset => Ok(self.plan_burn_asset(rng)),
            RecipeKind::SetAccountKeyValue => self.plan_set_key(rng),
            RecipeKind::RemoveAccountKeyValue => self.plan_remove_key(rng),
            RecipeKind::SetDomainKeyValue => self.plan_set_domain_key(),
            RecipeKind::RemoveDomainKeyValue => self.plan_remove_domain_key(),
            RecipeKind::SetAssetDefinitionKeyValue => self.plan_set_asset_definition_key(rng),
            RecipeKind::RemoveAssetDefinitionKeyValue => self.plan_remove_asset_definition_key(rng),
            RecipeKind::SetAssetInstanceKeyValue => self.plan_set_asset_metadata(rng),
            RecipeKind::RemoveAssetInstanceKeyValue => self.plan_remove_asset_metadata(rng),
            RecipeKind::RegisterRole => self.plan_register_role(),
            RecipeKind::GrantRole => self.plan_grant_role(rng),
            RecipeKind::RevokeRole => self.plan_revoke_role(rng),
            RecipeKind::RegisterTimeTrigger => self.plan_time_trigger(rng),
            RecipeKind::RegisterDataTrigger => self.plan_data_trigger(rng),
            RecipeKind::RegisterPipelineTrigger => self.plan_pipeline_trigger(rng),
            RecipeKind::SetTriggerKeyValue => self.plan_set_trigger_key(rng),
            RecipeKind::RemoveTriggerKeyValue => self.plan_remove_trigger_key(rng),
            RecipeKind::MintTriggerRepetitions => self.plan_mint_trigger_repetitions(rng),
            RecipeKind::BurnTriggerRepetitions => self.plan_burn_trigger_repetitions(rng),
            RecipeKind::ExecuteTrigger => self.plan_execute_trigger(rng),
            RecipeKind::ExecuteMissingTrigger => self.plan_execute_missing_trigger(),
            RecipeKind::DeployIvmContract => self.plan_deploy_ivm(rng),
            RecipeKind::DeployKotodamaContract => self.plan_deploy_kotodama(rng),
            RecipeKind::PublishSpaceDirectoryManifest => self.plan_publish_space_manifest(rng),
            RecipeKind::RevokeSpaceDirectoryManifest => self.plan_revoke_space_manifest(rng),
            RecipeKind::ExpireSpaceDirectoryManifest => self.plan_expire_space_manifest(rng),
            RecipeKind::DvpSettlement => self.plan_dvp_settlement(rng),
            RecipeKind::IssueReplicationOrder => self.plan_issue_replication_order(rng),
        }
    }
    /// Expose plan generation to sibling test modules without widening production visibility.
    #[cfg(test)]
    pub(crate) fn produce_plan_for_test(
        &mut self,
        kind: RecipeKind,
        rng: &mut StdRng,
    ) -> Result<TransactionPlan> {
        self.produce_plan(kind, rng)
    }
    #[cfg(test)]
    fn plan_register_domain(&mut self, _rng: &mut StdRng) -> Result<TransactionPlan> {
        Err(eyre!(
            "runtime domain registration requires an active SNS domain-name lease; Izanami does not synthesize leases"
        ))
    }
    fn plan_duplicate_domain(&mut self) -> TransactionPlan {
        let target = self
            .created_domains
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| self.base_domain.clone());
        TransactionPlan {
            state_updates: Vec::new(),
            label: "duplicate_domain",
            instructions: vec![InstructionBox::from(Register::domain(Domain::new(target)))],
            signer: self.treasury.clone(),
            expect_success: false,
        }
    }
    fn plan_register_account(&mut self) -> Result<TransactionPlan> {
        let _suffix = self.bump_account();
        let key = KeyPair::try_random()
            .map_err(|err| eyre!("failed to generate Izanami account key pair: {err}"))?;
        let account_id = AccountId::new(key.public_key().clone());
        let record = AccountRecord {
            id: account_id.clone(),
            key_pair: key,
            uaid: None,
        };
        let mut instructions = vec![InstructionBox::from(Register::account(Account::new(
            account_id.clone(),
        )))];
        instructions.extend(self.maybe_prefund_nexus_fee_asset(&record.id));
        Ok(TransactionPlan {
            state_updates: vec![PlanUpdate::TrackAccount(record)],
            label: "register_account",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_duplicate_account(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let candidate = self.random_user(rng)?.clone();
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "duplicate_account",
            instructions: vec![InstructionBox::from(Register::account(Account::new(
                candidate.id.clone(),
            )))],
            signer: self.treasury.clone(),
            expect_success: false,
        })
    }
    fn plan_register_uaid_account(&mut self) -> Result<TransactionPlan> {
        let record = self.allocate_uaid_record()?;
        let account = account_from_record(&record, &self.base_domain);
        let mut instructions = vec![InstructionBox::from(Register::account(account))];
        instructions.extend(self.maybe_prefund_nexus_fee_asset(&record.id));
        Ok(TransactionPlan {
            state_updates: vec![PlanUpdate::TrackAccount(record)],
            label: "register_uaid_account",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_mint_asset(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let beneficiary = self.random_user(rng)?.clone();
        let amount: Quantity = rng.random_range(1_u32..=100_u32).into();
        let asset_id = AssetId::new(self.asset_quantity.clone(), beneficiary.id.clone());
        Ok(TransactionPlan {
            state_updates: vec![PlanUpdate::TrackAssetInstance(asset_id.clone())],
            label: "mint_asset",
            instructions: vec![InstructionBox::from(Mint::asset_quantity(amount, asset_id))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_transfer_asset(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let (sender, receiver) = if self.low_contention_transfers && self.users.len() >= 2 {
            let pair_count = self.users.len() / 2;
            let idx = usize::try_from(self.counters.transfer).unwrap_or(usize::MAX) % pair_count;
            self.counters.transfer = self.counters.transfer.saturating_add(1);
            (
                self.users[idx].clone(),
                self.users[pair_count + idx].clone(),
            )
        } else {
            let sender = if self.users.is_empty() {
                self.treasury.clone()
            } else {
                let idx = usize::try_from(self.counters.transfer).unwrap_or(usize::MAX)
                    % self.users.len();
                self.counters.transfer = self.counters.transfer.saturating_add(1);
                self.users[idx].clone()
            };
            let receiver = self.random_user_except(rng, &sender.id)?;
            (sender, receiver)
        };
        let amount: Quantity = rng.random_range(1_u32..=50_u32).into();
        let source_asset = AssetId::new(self.asset_quantity.clone(), sender.id.clone());
        let instructions = vec![InstructionBox::from(Transfer::asset_quantity(
            source_asset,
            amount,
            receiver.id.clone(),
        ))];
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "transfer_asset",
            instructions,
            signer: sender,
            expect_success: true,
        })
    }
    fn plan_burn_asset(&mut self, rng: &mut StdRng) -> TransactionPlan {
        let amount: Quantity = rng.random_range(1_u32..=20_u32).into();
        let treasury_asset = AssetId::new(self.asset_quantity.clone(), self.treasury.id.clone());
        let instructions = vec![
            InstructionBox::from(Mint::asset_quantity(amount.clone(), treasury_asset.clone())),
            InstructionBox::from(Burn::asset_quantity(amount, treasury_asset)),
        ];
        TransactionPlan {
            state_updates: Vec::new(),
            label: "burn_asset",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        }
    }
    fn plan_set_key(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let target = self.random_user(rng)?.clone();
        let key: Name = format!("flag_{}", rng.random_range(0_u32..=999_u32))
            .parse()
            .map_err(|_| eyre!("failed to build metadata key"))?;
        let value = json_pair("chaos", true);
        self.account_metadata
            .entry(target.id.clone())
            .or_default()
            .insert(key.clone());
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "set_account_kv",
            instructions: vec![InstructionBox::from(SetKeyValue::account(
                target.id.clone(),
                key,
                value,
            ))],
            signer: target,
            expect_success: true,
        })
    }
    fn plan_remove_key(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let target = self.random_user(rng)?.clone();
        if let Some(keys) = self.account_metadata.get_mut(&target.id) {
            if let Some(existing) = keys.iter().next().cloned() {
                keys.remove(&existing);
            }
            if keys.is_empty() {
                self.account_metadata.remove(&target.id);
            }
        }
        let key: Name = format!("ephemeral_{}", self.bump_metadata())
            .parse()
            .map_err(|_| eyre!("failed to parse key name"))?;
        let instructions = vec![
            InstructionBox::from(SetKeyValue::account(
                target.id.clone(),
                key.clone(),
                json_pair("temp", self.bump_invalid()),
            )),
            InstructionBox::from(RemoveKeyValue::account(target.id.clone(), key)),
        ];
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "remove_account_kv",
            instructions,
            signer: target,
            expect_success: true,
        })
    }
    fn plan_register_asset_definition(&mut self) -> Result<TransactionPlan> {
        let suffix = self.bump_asset_definition();
        let definition_name: Name = format!("chaos_asset_{suffix}")
            .parse()
            .map_err(|_| eyre!("failed to parse asset definition name"))?;
        let definition_id: AssetDefinitionId =
            AssetDefinitionId::derive_from_components(self.base_domain.clone(), definition_name);
        let asset_definition = AssetDefinition::numeric(
            definition_id.clone(),
            format!("chaos_asset_{suffix}"),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        );
        self.asset_definitions.insert(definition_id.clone());
        self.asset_definitions_unclaimed
            .insert(definition_id.clone());
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "register_asset_definition",
            instructions: vec![InstructionBox::from(Register::asset_definition(
                asset_definition,
            ))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_unregister_asset_definition(&mut self, _rng: &mut StdRng) -> TransactionPlan {
        if let Some(candidate) = self.asset_definitions_unclaimed.iter().next().cloned() {
            self.asset_definitions_unclaimed.remove(&candidate);
            self.asset_definitions.remove(&candidate);
            self.asset_definition_metadata.remove(&candidate);
            return TransactionPlan {
                state_updates: Vec::new(),
                label: "unregister_asset_definition",
                instructions: vec![InstructionBox::from(Unregister::asset_definition(
                    candidate,
                ))],
                signer: self.treasury.clone(),
                expect_success: true,
            };
        }
        let fallback_name: Name = format!("ghost_asset_{}", self.bump_invalid())
            .parse()
            .expect("ghost asset definition name should parse");
        let fallback: AssetDefinitionId =
            AssetDefinitionId::derive_from_components(self.base_domain.clone(), fallback_name);
        TransactionPlan {
            state_updates: Vec::new(),
            label: "unregister_asset_definition",
            instructions: vec![InstructionBox::from(Unregister::asset_definition(fallback))],
            signer: self.treasury.clone(),
            expect_success: false,
        }
    }
    fn plan_set_domain_key(&mut self) -> Result<TransactionPlan> {
        let key: Name = format!("domain_flag_{}", self.bump_metadata())
            .parse()
            .map_err(|_| eyre!("failed to parse domain metadata key"))?;
        let domain = self.base_domain.clone();
        self.domain_metadata
            .entry(domain.clone())
            .or_default()
            .insert(key.clone());
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "set_domain_kv",
            instructions: vec![InstructionBox::from(SetKeyValue::domain(
                domain,
                key,
                json_pair("domain", "chaos"),
            ))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_remove_domain_key(&mut self) -> Result<TransactionPlan> {
        let domain = self.base_domain.clone();
        if let Some(keys) = self.domain_metadata.get_mut(&domain) {
            if let Some(existing) = keys.iter().next().cloned() {
                keys.remove(&existing);
            }
            if keys.is_empty() {
                self.domain_metadata.remove(&domain);
            }
        }
        let key: Name = format!("domain_flag_{}", self.bump_metadata())
            .parse()
            .map_err(|_| eyre!("failed to parse fallback domain key"))?;
        let instructions = vec![
            InstructionBox::from(SetKeyValue::domain(
                domain.clone(),
                key.clone(),
                json_pair("ephemeral", true),
            )),
            InstructionBox::from(RemoveKeyValue::domain(domain, key)),
        ];
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "remove_domain_kv",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_set_asset_definition_key(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let definition = self.random_asset_definition(rng)?;
        let key: Name = format!("asset_def_flag_{}", self.bump_metadata())
            .parse()
            .map_err(|_| eyre!("failed to parse asset definition metadata key"))?;
        self.asset_definition_metadata
            .entry(definition.clone())
            .or_default()
            .insert(key.clone());
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "set_asset_definition_kv",
            instructions: vec![InstructionBox::from(SetKeyValue::asset_definition(
                definition,
                key,
                json_pair("definition", "chaos"),
            ))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_remove_asset_definition_key(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let definition = self.random_asset_definition(rng)?;
        if let Some(keys) = self.asset_definition_metadata.get_mut(&definition) {
            if let Some(existing) = keys.iter().next().cloned() {
                keys.remove(&existing);
            }
            if keys.is_empty() {
                self.asset_definition_metadata.remove(&definition);
            }
        }
        let key: Name = format!("asset_def_flag_{}", self.bump_metadata())
            .parse()
            .map_err(|_| eyre!("failed to parse fallback asset definition key"))?;
        let instructions = vec![
            InstructionBox::from(SetKeyValue::asset_definition(
                definition.clone(),
                key.clone(),
                json_pair("ephemeral", true),
            )),
            InstructionBox::from(RemoveKeyValue::asset_definition(definition, key)),
        ];
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "remove_asset_definition_kv",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_set_asset_metadata(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let asset = self.random_asset_instance(rng).unwrap_or_else(|_| {
            AssetId::new(self.asset_quantity.clone(), self.treasury.id.clone())
        });
        let key: Name = format!("asset_flag_{}", self.bump_metadata())
            .parse()
            .map_err(|_| eyre!("failed to parse asset metadata key"))?;
        self.asset_metadata
            .entry(asset.clone())
            .or_default()
            .insert(key.clone());
        let amount: Quantity = 1_u32.into();
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "set_asset_kv",
            instructions: vec![
                InstructionBox::from(Mint::asset_quantity(amount, asset.clone())),
                InstructionBox::from(SetAssetKeyValue::new(
                    asset,
                    key,
                    json_pair("asset", "chaos"),
                )),
            ],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_remove_asset_metadata(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let asset = self.random_asset_instance(rng).unwrap_or_else(|_| {
            AssetId::new(self.asset_quantity.clone(), self.treasury.id.clone())
        });
        if let Some(keys) = self.asset_metadata.get_mut(&asset) {
            if let Some(existing) = keys.iter().next().cloned() {
                keys.remove(&existing);
            }
            if keys.is_empty() {
                self.asset_metadata.remove(&asset);
            }
        }
        let key: Name = format!("asset_flag_{}", self.bump_metadata())
            .parse()
            .map_err(|_| eyre!("failed to parse fallback asset key"))?;
        let amount: Quantity = 1_u32.into();
        let instructions = vec![
            InstructionBox::from(Mint::asset_quantity(amount, asset.clone())),
            InstructionBox::from(SetAssetKeyValue::new(
                asset.clone(),
                key.clone(),
                json_pair("ephemeral", true),
            )),
            InstructionBox::from(RemoveAssetKeyValue::new(asset, key)),
        ];
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "remove_asset_kv",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_register_nft(&mut self, _rng: &mut StdRng) -> Result<TransactionPlan> {
        let suffix = self.bump_nft();
        let domain_id = self.base_domain.to_string();
        let nft_id: NftId = format!("chaos_nft_{suffix}${domain_id}")
            .parse()
            .map_err(|_| eyre!("failed to parse nft id"))?;
        let nft = Nft::new(nft_id.clone(), Metadata::default());
        self.nft_holdings
            .insert(nft_id.clone(), self.treasury.id.clone());
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "register_nft",
            instructions: vec![InstructionBox::from(Register::nft(nft))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_transfer_nft(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let suffix = self.bump_nft();
        let domain_id = self.base_domain.to_string();
        let nft_id: NftId = format!("chaos_nft_{suffix}${domain_id}")
            .parse()
            .map_err(|_| eyre!("failed to parse nft id"))?;
        let receiver = self.random_user_except(rng, &self.treasury.id)?;
        let nft = Nft::new(nft_id.clone(), Metadata::default());
        let instructions = vec![
            InstructionBox::from(Register::nft(nft)),
            InstructionBox::from(Transfer::nft(
                self.treasury.id.clone(),
                nft_id.clone(),
                receiver.id.clone(),
            )),
        ];
        self.nft_holdings.insert(nft_id, receiver.id.clone());
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "transfer_nft",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_set_trigger_key(&mut self, _rng: &mut StdRng) -> Result<TransactionPlan> {
        let mut instructions = Vec::new();
        let trigger_id: TriggerId = format!("metadata_trigger_{}", self.bump_trigger())
            .parse()
            .map_err(|_| eyre!("failed to parse metadata trigger id"))?;
        let log_instruction = Log::new(Level::INFO, "trigger metadata bootstrap".to_string());
        let action = Action::new(
            vec![InstructionBox::from(log_instruction)],
            Repeats::Indefinitely,
            self.treasury.id.clone(),
            EventFilterBox::ExecuteTrigger(
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            ),
        )?;
        instructions.push(InstructionBox::from(Register::trigger(Trigger::new(
            trigger_id.clone(),
            action,
        ))));
        let key: Name = format!("trigger_flag_{}", self.bump_metadata())
            .parse()
            .map_err(|_| eyre!("failed to parse trigger metadata key"))?;
        instructions.push(InstructionBox::from(SetKeyValue::trigger(
            trigger_id.clone(),
            key.clone(),
            json_pair("trigger", "chaos"),
        )));
        let state_updates = vec![
            PlanUpdate::RegisterTrigger(trigger_id.clone()),
            PlanUpdate::SetTriggerMetadata {
                trigger_id: trigger_id.clone(),
                key,
            },
        ];
        Ok(TransactionPlan {
            state_updates,
            label: "set_trigger_kv",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_remove_trigger_key(&mut self, _rng: &mut StdRng) -> Result<TransactionPlan> {
        let mut instructions = Vec::new();
        let trigger_id: TriggerId = format!("metadata_trigger_{}", self.bump_trigger())
            .parse()
            .map_err(|_| eyre!("failed to parse metadata trigger id"))?;
        let log_instruction = Log::new(Level::INFO, "trigger metadata bootstrap".to_string());
        let action = Action::new(
            vec![InstructionBox::from(log_instruction)],
            Repeats::Indefinitely,
            self.treasury.id.clone(),
            EventFilterBox::ExecuteTrigger(
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            ),
        )?;
        instructions.push(InstructionBox::from(Register::trigger(Trigger::new(
            trigger_id.clone(),
            action,
        ))));
        let key: Name = format!("trigger_flag_{}", self.bump_metadata())
            .parse()
            .map_err(|_| eyre!("failed to parse fallback trigger key"))?;
        instructions.push(InstructionBox::from(SetKeyValue::trigger(
            trigger_id.clone(),
            key.clone(),
            json_pair("ephemeral", true),
        )));
        instructions.push(InstructionBox::from(RemoveKeyValue::trigger(
            trigger_id.clone(),
            key,
        )));
        let state_updates = vec![
            PlanUpdate::RegisterTrigger(trigger_id.clone()),
            PlanUpdate::ClearTriggerMetadata(trigger_id.clone()),
        ];
        Ok(TransactionPlan {
            state_updates,
            label: "remove_trigger_kv",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_mint_trigger_repetitions(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let mut instructions = Vec::new();
        let trigger_id = if let Some(existing) = self.random_repeatable_trigger(rng) {
            existing
        } else {
            let trigger_id: TriggerId = format!("repeat_trigger_{}", self.bump_trigger())
                .parse()
                .map_err(|_| eyre!("failed to parse repeat trigger id"))?;
            let action = Action::new(
                vec![InstructionBox::from(Log::new(
                    Level::INFO,
                    "repetition bootstrap".to_string(),
                ))],
                Repeats::Exactly(1),
                self.treasury.id.clone(),
                EventFilterBox::ExecuteTrigger(
                    ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
                ),
            )?;
            instructions.push(InstructionBox::from(Register::trigger(Trigger::new(
                trigger_id.clone(),
                action,
            ))));
            let updates = vec![PlanUpdate::TrackRepeatableTrigger(trigger_id.clone())];
            return Ok(TransactionPlan {
                state_updates: updates,
                label: "mint_trigger_repetitions",
                instructions,
                signer: self.treasury.clone(),
                expect_success: true,
            });
        };
        let amount = rng.random_range(1_u32..=3_u32);
        instructions.push(InstructionBox::from(Mint::trigger_repetitions(
            amount,
            trigger_id.clone(),
        )));
        let state_updates = vec![PlanUpdate::MintTriggerRepetitions { trigger_id, amount }];
        Ok(TransactionPlan {
            state_updates,
            label: "mint_trigger_repetitions",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_burn_trigger_repetitions(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let mut instructions = Vec::new();
        let trigger_id = if let Some(existing) = self.random_repeatable_trigger(rng) {
            existing
        } else {
            return self.plan_mint_trigger_repetitions(rng);
        };
        let tracked = self
            .repeatable_trigger_repetitions(&trigger_id)
            .unwrap_or_default();
        let pending = self.pending_trigger_repetitions(&trigger_id);
        let available = tracked.saturating_sub(pending);
        if available <= 1 {
            return self.plan_mint_trigger_repetitions(rng);
        }
        let burn_amount = rng.random_range(1..=available.saturating_sub(1));
        self.reserve_trigger_repetitions(&trigger_id, burn_amount);
        instructions.push(InstructionBox::from(Burn::trigger_repetitions(
            burn_amount,
            trigger_id.clone(),
        )));
        let state_updates = vec![
            PlanUpdate::BurnTriggerRepetitions {
                trigger_id: trigger_id.clone(),
                amount: burn_amount,
            },
            PlanUpdate::ReleaseTriggerRepetitionsReservation {
                trigger_id,
                amount: burn_amount,
            },
        ];
        Ok(TransactionPlan {
            state_updates,
            label: "burn_trigger_repetitions",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_register_role(&mut self) -> Result<TransactionPlan> {
        let role_id: RoleId = format!("CHAOS_ROLE_{}", self.bump_role())
            .parse()
            .map_err(|_| eyre!("failed to parse role id"))?;
        let permission = CanModifyAccountMetadata {
            account: self.treasury.id.clone(),
        };
        let role = Role::new(role_id.clone(), self.treasury.id.clone()).add_permission(permission);
        self.registered_roles.push(role_id.clone());
        self.role_memberships
            .entry(role_id.clone())
            .or_default()
            .insert(self.treasury.id.clone());
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "register_role",
            instructions: vec![InstructionBox::from(Register::role(role))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_grant_role(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        if self.registered_roles.is_empty() {
            return self.plan_register_role();
        }
        let role = self
            .registered_roles
            .choose(rng)
            .expect("role list not empty")
            .clone();
        let assigned_accounts: HashSet<AccountId> = self
            .role_memberships
            .get(&role)
            .cloned()
            .unwrap_or_default();
        let available_accounts: Vec<&AccountRecord> = self
            .users
            .iter()
            .chain(std::iter::once(&self.treasury))
            .filter(|record| !assigned_accounts.contains(&record.id))
            .collect();
        if let Some(account) = available_accounts.choose(rng).copied() {
            let account_id = account.id.clone();
            self.role_memberships
                .entry(role.clone())
                .or_default()
                .insert(account_id.clone());
            return Ok(TransactionPlan {
                state_updates: Vec::new(),
                label: "grant_role",
                instructions: vec![InstructionBox::from(Grant::account_role(role, account_id))],
                signer: self.treasury.clone(),
                expect_success: true,
            });
        }
        let assigned_vec: Vec<AccountId> = assigned_accounts.into_iter().collect();
        let fallback_account = if let Some(candidate) = assigned_vec.choose(rng) {
            candidate.clone()
        } else {
            self.random_user(rng)?.id.clone()
        };
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "grant_role",
            instructions: vec![InstructionBox::from(Grant::account_role(
                role,
                fallback_account,
            ))],
            signer: self.treasury.clone(),
            expect_success: false,
        })
    }
    fn plan_revoke_role(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        if self.registered_roles.is_empty() {
            return self.plan_register_role();
        }
        let role = self
            .registered_roles
            .choose(rng)
            .expect("role list not empty")
            .clone();
        let existing_members: Vec<AccountId> = self
            .role_memberships
            .get(&role)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();
        if let Some(account_id) = existing_members
            .iter()
            .filter(|member| *member != &self.treasury.id)
            .cloned()
            .collect::<Vec<_>>()
            .choose(rng)
            .cloned()
        {
            let remove_role_entry = self.role_memberships.get_mut(&role).is_some_and(|members| {
                members.remove(&account_id);
                members.is_empty()
            });
            if remove_role_entry {
                self.role_memberships.remove(&role);
            }
            return Ok(TransactionPlan {
                state_updates: Vec::new(),
                label: "revoke_role",
                instructions: vec![InstructionBox::from(Revoke::account_role(role, account_id))],
                signer: self.treasury.clone(),
                expect_success: true,
            });
        }
        let account = self.random_user_except(rng, &self.treasury.id)?;
        let instructions = vec![
            InstructionBox::from(Grant::account_role(role.clone(), account.id.clone())),
            InstructionBox::from(Revoke::account_role(role.clone(), account.id.clone())),
        ];
        let remove_role_entry = self.role_memberships.get_mut(&role).is_some_and(|members| {
            members.remove(&account.id);
            members.is_empty()
        });
        if remove_role_entry {
            self.role_memberships.remove(&role);
        }
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "revoke_role",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_time_trigger(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let trigger_id: TriggerId = format!("time_trigger_{}", self.bump_trigger())
            .parse()
            .map_err(|_| eyre!("failed to parse trigger id"))?;
        let beneficiary = self.random_user(rng)?.clone();
        let amount: Quantity = rng.random_range(1_u32..=5_u32).into();
        let mint = Mint::asset_quantity(
            amount,
            AssetId::new(self.asset_quantity.clone(), beneficiary.id.clone()),
        );
        let schedule = Schedule::starting_at(Duration::from_millis(500))
            .with_period(Duration::from_millis(1_500));
        let action = Action::new(
            vec![InstructionBox::from(mint)],
            Repeats::Exactly(1),
            self.treasury.id.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(schedule)),
        )?;
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "register_time_trigger",
            instructions: vec![InstructionBox::from(Register::trigger(Trigger::new(
                trigger_id, action,
            )))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_data_trigger(&mut self, _rng: &mut StdRng) -> Result<TransactionPlan> {
        let trigger_id: TriggerId = format!("data_trigger_{}", self.bump_trigger())
            .parse()
            .map_err(|_| eyre!("failed to parse data trigger id"))?;
        let amount: Quantity = 1_u32.into();
        let mint = Mint::asset_quantity(
            amount,
            AssetId::new(self.asset_quantity.clone(), self.treasury.id.clone()),
        );
        let filter = AccountEventFilter::new().for_events(AccountEventSet::Created);
        let action = Action::new(
            vec![InstructionBox::from(mint)],
            Repeats::Indefinitely,
            self.treasury.id.clone(),
            DataEventFilter::Account(filter),
        )?;
        let state_updates = vec![PlanUpdate::RegisterTrigger(trigger_id.clone())];
        Ok(TransactionPlan {
            state_updates,
            label: "register_data_trigger",
            instructions: vec![InstructionBox::from(Register::trigger(Trigger::new(
                trigger_id, action,
            )))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_pipeline_trigger(&mut self, _rng: &mut StdRng) -> Result<TransactionPlan> {
        let trigger_id: TriggerId = format!("pipeline_trigger_{}", self.bump_trigger())
            .parse()
            .map_err(|_| eyre!("failed to parse pipeline trigger id"))?;
        let log_instruction = Log::new(Level::INFO, "pipeline chaos".to_string());
        let action = Action::new(
            vec![InstructionBox::from(log_instruction)],
            Repeats::Indefinitely,
            self.treasury.id.clone(),
            EventFilterBox::Pipeline(PipelineEventFilterBox::Transaction(
                TransactionEventFilter::new(),
            )),
        )?;
        let state_updates = vec![PlanUpdate::RegisterTrigger(trigger_id.clone())];
        Ok(TransactionPlan {
            state_updates,
            label: "register_pipeline_trigger",
            instructions: vec![InstructionBox::from(Register::trigger(Trigger::new(
                trigger_id, action,
            )))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_execute_trigger(&mut self, _rng: &mut StdRng) -> Result<TransactionPlan> {
        let trigger_id: TriggerId = format!("call_trigger_{}", self.bump_trigger())
            .parse()
            .map_err(|_| eyre!("failed to parse call trigger id"))?;
        let log_instruction = Log::new(Level::INFO, "call trigger".to_string());
        let action = Action::new(
            vec![InstructionBox::from(log_instruction)],
            Repeats::Indefinitely,
            self.treasury.id.clone(),
            EventFilterBox::ExecuteTrigger(
                ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
            ),
        )?;
        let trigger = Trigger::new(trigger_id.clone(), action);
        let state_updates = vec![
            PlanUpdate::RegisterTrigger(trigger_id.clone()),
            PlanUpdate::RegisterCallTrigger(trigger_id.clone()),
        ];
        Ok(TransactionPlan {
            state_updates,
            label: "execute_trigger",
            instructions: vec![
                InstructionBox::from(Register::trigger(trigger)),
                InstructionBox::from(ExecuteTrigger::new(trigger_id)),
            ],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_execute_missing_trigger(&mut self) -> Result<TransactionPlan> {
        let trigger_id: TriggerId = format!("ghost_trigger_{}", self.bump_invalid())
            .parse()
            .map_err(|_| eyre!("failed to parse ghost trigger id"))?;
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "execute_missing_trigger",
            instructions: vec![InstructionBox::from(ExecuteTrigger::new(trigger_id))],
            signer: self.treasury.clone(),
            expect_success: false,
        })
    }
    fn plan_deploy_ivm(&mut self, _rng: &mut StdRng) -> Result<TransactionPlan> {
        let trigger_id: TriggerId = format!("ivm_trigger_{}", self.bump_trigger())
            .parse()
            .map_err(|_| eyre!("failed to parse ivm trigger id"))?;
        let bytecode = smart_contracts::ivm_trigger_program()?;
        let action = Action::new(
            bytecode,
            Repeats::Exactly(1),
            self.treasury.id.clone(),
            TimeEventFilter::new(ExecutionTime::PreCommit),
        )?;
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "deploy_ivm_contract",
            instructions: vec![InstructionBox::from(Register::trigger(Trigger::new(
                trigger_id, action,
            )))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_deploy_kotodama(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let trigger_id: TriggerId = format!("kotodama_trigger_{}", self.bump_trigger())
            .parse()
            .map_err(|_| eyre!("failed to parse kotodama trigger id"))?;
        let program_name = [
            "asset_ops",
            "domain_ops",
            "mint_rose_trigger",
            "tuple_return_demo",
        ]
        .choose(rng)
        .copied()
        .unwrap_or("asset_ops");
        let bytecode = smart_contracts::kotodama_program(program_name)?;
        let action = Action::new(
            bytecode,
            Repeats::Indefinitely,
            self.treasury.id.clone(),
            DataEventFilter::Any,
        )?;
        let state_updates = vec![PlanUpdate::RegisterTrigger(trigger_id.clone())];
        Ok(TransactionPlan {
            state_updates,
            label: "deploy_kotodama_contract",
            instructions: vec![InstructionBox::from(Register::trigger(Trigger::new(
                trigger_id, action,
            )))],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_publish_space_manifest(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let dataspace = self.random_dataspace(rng);
        let mut instructions = Vec::new();
        let mut state_updates = Vec::new();
        let uaid = if let Some(uaid) = self.pick_uaid_without_manifest(dataspace, rng) {
            self.uaid_accounts
                .get(&uaid)
                .ok_or_else(|| eyre!("UAID record missing from registry"))?;
            uaid
        } else {
            let record = self.allocate_uaid_record()?;
            let account = account_from_record(&record, &self.base_domain);
            instructions.push(InstructionBox::from(Register::account(account)));
            instructions.extend(self.maybe_prefund_nexus_fee_asset(&record.id));
            state_updates.push(PlanUpdate::TrackAccount(record.clone()));
            let uaid = record
                .uaid
                .expect("allocated UAID record should carry uaid");
            uaid
        };
        let manifest = AssetPermissionManifest {
            version: ManifestVersion::V1,
            uaid,
            dataspace,
            issued_ms: now_ms(),
            activation_epoch: self.bump_metadata(),
            expiry_epoch: None,
            entries: vec![ManifestEntry {
                scope: CapabilityScope {
                    dataspace: Some(dataspace),
                    program: None,
                    method: None,
                    asset: None,
                    role: None,
                },
                effect: ManifestEffect::Allow(Allowance {
                    max_amount: None,
                    window: AllowanceWindow::PerSlot,
                }),
                notes: Some("chaos allowance".to_string()),
            }],
        };
        instructions.push(InstructionBox::from(PublishSpaceDirectoryManifest {
            manifest,
        }));
        self.space_directory_manifests
            .entry(uaid)
            .or_default()
            .insert(dataspace);
        Ok(TransactionPlan {
            state_updates,
            label: "publish_space_directory_manifest",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_revoke_space_manifest(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let dataspace = self.random_dataspace(rng);
        let Some(uaid) = self.pick_manifest_for_dataspace(dataspace, rng) else {
            let missing = UniversalAccountId::from_hash(Hash::new(b"izanami-missing-manifest"));
            return Ok(TransactionPlan {
                state_updates: Vec::new(),
                label: "revoke_space_directory_manifest",
                instructions: vec![InstructionBox::from(RevokeSpaceDirectoryManifest {
                    uaid: missing,
                    dataspace,
                    revoked_epoch: self.bump_invalid(),
                    reason: Some("revocation should fail for missing manifest".to_string()),
                })],
                signer: self.treasury.clone(),
                expect_success: false,
            });
        };
        self.mark_manifest_removed(uaid, dataspace);
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "revoke_space_directory_manifest",
            instructions: vec![InstructionBox::from(RevokeSpaceDirectoryManifest {
                uaid,
                dataspace,
                revoked_epoch: self.bump_metadata(),
                reason: Some("chaos revocation".to_string()),
            })],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_expire_space_manifest(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let dataspace = self.random_dataspace(rng);
        let Some(uaid) = self.pick_manifest_for_dataspace(dataspace, rng) else {
            let missing = UniversalAccountId::from_hash(Hash::new(b"izanami-missing-expiry"));
            return Ok(TransactionPlan {
                state_updates: Vec::new(),
                label: "expire_space_directory_manifest",
                instructions: vec![InstructionBox::from(ExpireSpaceDirectoryManifest {
                    uaid: missing,
                    dataspace,
                    expired_epoch: self.bump_invalid(),
                })],
                signer: self.treasury.clone(),
                expect_success: false,
            });
        };
        self.mark_manifest_removed(uaid, dataspace);
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "expire_space_directory_manifest",
            instructions: vec![InstructionBox::from(ExpireSpaceDirectoryManifest {
                uaid,
                dataspace,
                expired_epoch: self.bump_metadata(),
            })],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_dvp_settlement(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        let seller = self.treasury.clone();
        let buyer = self.random_user_except(rng, &seller.id)?;
        let settlement_id = SettlementId::new(
            seller.id.clone(),
            format!("settlement_{}", self.bump_settlement())
                .parse()
                .map_err(|_| eyre!("failed to parse settlement reference"))?,
        );
        let delivery_quantity = Quantity::from(rng.random_range(1_u32..=25_u32));
        let payment_quantity = Quantity::from(rng.random_range(1_u32..=25_u32));
        let delivery_asset = AssetId::new(self.asset_quantity.clone(), seller.id.clone());
        let payment_asset = AssetId::new(self.asset_quantity.clone(), buyer.id.clone());
        let delivery_mint = InstructionBox::from(Mint::asset_quantity(
            delivery_quantity.clone(),
            delivery_asset.clone(),
        ));
        let payment_mint = InstructionBox::from(Mint::asset_quantity(
            payment_quantity.clone(),
            payment_asset.clone(),
        ));
        let delivery_leg = SettlementLeg::new(
            self.asset_quantity.clone(),
            delivery_quantity,
            seller.id.clone(),
            buyer.id.clone(),
        );
        let payment_leg = SettlementLeg::new(
            self.asset_quantity.clone(),
            payment_quantity,
            buyer.id.clone(),
            seller.id.clone(),
        );
        let dvp = SettlementInstructionBox::from(DvpIsi::new(
            settlement_id,
            delivery_leg,
            payment_leg,
            SettlementPlan::default(),
        ));
        Ok(TransactionPlan {
            state_updates: vec![
                PlanUpdate::TrackAssetInstance(delivery_asset.clone()),
                PlanUpdate::TrackAssetInstance(payment_asset.clone()),
            ],
            label: "dvp_settlement",
            instructions: vec![delivery_mint, payment_mint, InstructionBox::from(dvp)],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_seed_replication(&mut self) -> Result<TransactionPlan> {
        let (manifest_digest, manifest_payload, provider_id) = {
            let Some(replication) = self.sorafs_replication.as_ref() else {
                return Err(eyre!("SoraFS replication seed not initialized"));
            };
            (
                replication.manifest_digest,
                replication.manifest_payload.clone(),
                replication.provider_id,
            )
        };
        let _manifest_epoch = self.bump_replication();
        let council_digest = *Hash::new(b"izanami-sorafs-council-digest").as_ref();
        let completion_authority = ProviderIngestCompletionAuthorityV1::new(
            self.treasury.id.clone(),
            self.treasury.id.clone(),
            ProviderIngestCompletionSignerPolicyV1 {
                policy_id: *Hash::new(b"izanami-sorafs-completion-policy").as_ref(),
                revision: 1,
                predecessor_digest: None,
                policy_digest: *Hash::new(self.treasury.id.to_string().as_bytes()).as_ref(),
            },
        );
        let instructions = vec![
            InstructionBox::from(RegisterPinManifest::new(manifest_payload, None, None)),
            InstructionBox::from(ApprovePinManifest {
                digest: manifest_digest,
                council_envelope: None,
                council_envelope_digest: Some(council_digest),
            }),
            InstructionBox::from(SetProviderIngestCompletionAuthority::new(
                provider_id,
                None,
                completion_authority,
            )),
        ];
        self.sorafs_replication_ready = true;
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "seed_replication_manifest",
            instructions,
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn plan_issue_replication_order(&mut self, rng: &mut StdRng) -> Result<TransactionPlan> {
        if !self.sorafs_replication_ready {
            return self.plan_seed_replication();
        }
        let (manifest_digest, manifest_root_cid, chunker, provider_id) = {
            let Some(replication) = self.sorafs_replication.as_ref() else {
                return Err(eyre!("SoraFS replication seed not initialized"));
            };
            (
                replication.manifest_digest,
                replication.manifest_root_cid.clone(),
                replication.chunker.clone(),
                replication.provider_id,
            )
        };
        let mut order_id_bytes = [0u8; 32];
        rng.fill_bytes(&mut order_id_bytes);
        // The high bit of byte zero is reserved for registry-derived automatic orders.
        order_id_bytes[0] &= 0x7f;
        if order_id_bytes.iter().all(|byte| *byte == 0) {
            order_id_bytes[0] = 1;
        }
        let issued_epoch = self.bump_replication();
        let deadline_epoch = issued_epoch
            .checked_add(60)
            .ok_or_else(|| eyre!("replication-order deadline overflow"))?;
        let order = ReplicationOrderV1 {
            version: REPLICATION_ORDER_VERSION_V1,
            order_id: order_id_bytes,
            manifest_cid: manifest_root_cid,
            manifest_digest: *manifest_digest.as_bytes(),
            chunking_profile: chunker.to_handle(),
            target_replicas: 1,
            assignments: vec![ReplicationAssignmentV1 {
                provider_id: *provider_id.as_bytes(),
                slice_gib: 1,
                lane: None,
            }],
            issued_at: issued_epoch,
            deadline_at: deadline_epoch,
            sla: ReplicationOrderSlaV1 {
                ingest_deadline_secs: 60,
                min_availability_percent_milli: 100_000,
                min_por_success_percent_milli: 100_000,
            },
            metadata: Vec::new(),
        };
        let payload = order.encode();
        let order_id = ReplicationOrderId::new(order_id_bytes);
        self.pending_replication_orders.push(order_id);
        Ok(TransactionPlan {
            state_updates: Vec::new(),
            label: "issue_replication_order",
            instructions: vec![InstructionBox::from(IssueReplicationOrder {
                order_id,
                order_payload: payload,
                issued_epoch,
                deadline_epoch,
                musubi_archive: None,
            })],
            signer: self.treasury.clone(),
            expect_success: true,
        })
    }
    fn random_user(&self, rng: &mut StdRng) -> Result<&AccountRecord> {
        self.users
            .choose(rng)
            .or(Some(&self.treasury))
            .ok_or_else(|| eyre!("no accounts available"))
    }
    fn random_user_except(&self, rng: &mut StdRng, excluded: &AccountId) -> Result<AccountRecord> {
        let candidate_count = self.users.len().saturating_add(1);
        if candidate_count <= 1 {
            return Err(eyre!("no alternative accounts available"));
        }
        for _ in 0..8 {
            let idx = rng.random_range(0..candidate_count);
            let candidate = if idx < self.users.len() {
                &self.users[idx]
            } else {
                &self.treasury
            };
            if &candidate.id != excluded {
                return Ok(candidate.clone());
            }
        }
        self.users
            .iter()
            .chain(std::iter::once(&self.treasury))
            .find(|record| &record.id != excluded)
            .cloned()
            .ok_or_else(|| eyre!("no alternative accounts available"))
    }
    fn random_asset_definition(&self, rng: &mut StdRng) -> Result<AssetDefinitionId> {
        let definitions: Vec<_> = self.asset_definitions.iter().cloned().collect();
        definitions
            .choose(rng)
            .cloned()
            .ok_or_else(|| eyre!("no asset definitions available"))
    }
    fn random_asset_instance(&self, rng: &mut StdRng) -> Result<AssetId> {
        let assets: Vec<_> = self.asset_instances.iter().cloned().collect();
        assets
            .choose(rng)
            .cloned()
            .ok_or_else(|| eyre!("no asset instances available"))
    }
    fn random_repeatable_trigger(&self, rng: &mut StdRng) -> Option<TriggerId> {
        self.repeatable_trigger_state
            .iter()
            .filter_map(|(trigger_id, state)| match state {
                RepeatableTriggerState::Known { repetitions } => {
                    (*repetitions > 0).then_some(trigger_id.clone())
                }
                RepeatableTriggerState::Unknown | RepeatableTriggerState::Missing => None,
            })
            .collect::<Vec<_>>()
            .choose(rng)
            .cloned()
    }
    fn track_repeatable_trigger(&mut self, trigger_id: TriggerId) {
        self.repeatable_trigger_state
            .insert(trigger_id, RepeatableTriggerState::Known { repetitions: 1 });
    }
    fn repeatable_trigger_repetitions(&self, trigger_id: &TriggerId) -> Option<u32> {
        match self.repeatable_trigger_state.get(trigger_id) {
            Some(RepeatableTriggerState::Known { repetitions }) => {
                (*repetitions > 0).then_some(*repetitions)
            }
            Some(RepeatableTriggerState::Unknown)
            | Some(RepeatableTriggerState::Missing)
            | None => None,
        }
    }
    fn sync_repeatable_trigger_repetitions(&mut self, trigger_id: TriggerId, repeats: Option<u32>) {
        let state = match repeats {
            Some(repetitions) if repetitions > 0 => RepeatableTriggerState::Known { repetitions },
            _ => RepeatableTriggerState::Missing,
        };
        self.repeatable_trigger_state.insert(trigger_id, state);
    }
    fn pending_trigger_repetitions(&self, trigger_id: &TriggerId) -> u32 {
        self.pending_trigger_repetitions
            .get(trigger_id)
            .copied()
            .unwrap_or(0)
    }
    fn reserve_trigger_repetitions(&mut self, trigger_id: &TriggerId, amount: u32) {
        if amount == 0 {
            return;
        }
        let entry = self
            .pending_trigger_repetitions
            .entry(trigger_id.clone())
            .or_insert(0);
        *entry = entry.saturating_add(amount);
    }
    fn release_trigger_repetitions_reservation(&mut self, trigger_id: &TriggerId, amount: u32) {
        if amount == 0 {
            return;
        }
        let Some(entry) = self.pending_trigger_repetitions.get_mut(trigger_id) else {
            return;
        };
        *entry = entry.saturating_sub(amount);
        if *entry == 0 {
            self.pending_trigger_repetitions.remove(trigger_id);
        }
    }
    fn bump_account(&mut self) -> u64 {
        let value = self.counters.account;
        self.counters.account += 1;
        value
    }
    fn bump_uaid(&mut self) -> u64 {
        let value = self.counters.uaid;
        self.counters.uaid += 1;
        value
    }
    fn bump_trigger(&mut self) -> u64 {
        let value = self.counters.trigger;
        self.counters.trigger += 1;
        value
    }
    fn bump_role(&mut self) -> u64 {
        let value = self.counters.role;
        self.counters.role += 1;
        value
    }
    fn bump_asset_definition(&mut self) -> u64 {
        let value = self.counters.asset_definition;
        self.counters.asset_definition += 1;
        value
    }
    fn bump_nft(&mut self) -> u64 {
        let value = self.counters.nft;
        self.counters.nft += 1;
        value
    }
    fn bump_metadata(&mut self) -> u64 {
        let value = self.counters.metadata;
        self.counters.metadata += 1;
        value
    }
    fn bump_invalid(&mut self) -> u64 {
        let value = self.counters.invalid;
        self.counters.invalid += 1;
        value
    }
    fn bump_settlement(&mut self) -> u64 {
        let value = self.counters.settlement;
        self.counters.settlement += 1;
        value
    }
    fn bump_replication(&mut self) -> u64 {
        let value = self.counters.replication;
        self.counters.replication += 1;
        value
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NexusProfile, WorkloadProfile};
    use iroha_data_model::isi::{
        MintBox, RegisterBox, RemoveKeyValueBox, SetKeyValueBox, UnregisterBox,
    };
    use norito::codec::Decode;
    use rand::SeedableRng;
    use tokio::runtime::Builder;
    fn minted_asset_destination(plan: &TransactionPlan) -> AssetId {
        plan.instructions
            .iter()
            .find_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<MintBox>()
                    .and_then(|mint| match mint {
                        MintBox::Asset(asset) => Some(asset.destination.clone()),
                        _ => None,
                    })
            })
            .expect("plan should include an asset mint destination")
    }
    fn minted_asset_destinations(plan: &[InstructionBox]) -> Vec<AssetId> {
        plan.iter()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<MintBox>()
                    .and_then(|mint| match mint {
                        MintBox::Asset(asset) => Some(asset.destination.clone()),
                        _ => None,
                    })
            })
            .collect()
    }
    #[test]
    fn json_pair_builds_object() {
        let value = json_pair("answer", 42u64);
        let mut expected = JsonMap::new();
        expected.insert("answer".to_string(), JsonValue::from(42u64));
        assert_eq!(value, JsonValue::Object(expected));
    }
    #[test]
    fn prepare_state_builds_genesis() {
        let prepared =
            prepare_state(4, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        assert!(!prepared.genesis.is_empty());
        assert!(!prepared.genesis[0].is_empty());
        assert!(prepared.state.users.len() >= 3);
        let expected: DomainId = DomainId::parse_fully_qualified("chaosnet.universal").unwrap();
        assert_eq!(prepared.state.base_domain(), &expected);
    }
    #[test]
    fn random_user_except_never_returns_excluded_account() {
        let prepared =
            prepare_state(128, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let excluded = prepared.state.users[0].id.clone();
        let mut rng = StdRng::seed_from_u64(17);
        for _ in 0..256 {
            let selected = prepared
                .state
                .random_user_except(&mut rng, &excluded)
                .expect("alternative account should exist");
            assert_ne!(selected.id, excluded);
        }
    }
    #[test]
    fn prepare_state_grants_treasury_mint_permission() {
        let prepared =
            prepare_state(4, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let base_asset = prepared.state.asset_quantity.clone();
        let treasury_id = prepared.state.treasury.id.clone();
        let has_grant = prepared.genesis.iter().flatten().any(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<GrantBox>()
                .is_some_and(|grant| match grant {
                    GrantBox::Permission(permission_grant) => {
                        permission_grant.object
                            == CanMintAssetWithDefinition {
                                asset_definition: base_asset.clone(),
                            }
                            .into()
                            && permission_grant.destination == treasury_id
                    }
                    _ => false,
                })
        });
        assert!(
            has_grant,
            "treasury should be able to mint assets for the base definition"
        );
    }
    #[test]
    fn nexus_staking_genesis_registers_fee_sink_and_validators() {
        let profile = NexusProfile::sora_defaults().expect("profile");
        let PreparedChaos { state, genesis, .. } =
            prepare_state(2, None, Some(&profile), WorkloadProfile::Stable, false)
                .expect("state prepared");
        let setup = state
            .nexus_staking
            .as_ref()
            .expect("nexus staking setup should be present");
        assert!(
            !setup.validator_accounts.is_empty(),
            "validator accounts should be provisioned"
        );
        assert_eq!(
            setup.fee_sink,
            nexus_gas_account_id().expect("nexus gas account"),
            "nexus staking setup should use deterministic Izanami gas account"
        );
        assert_eq!(
            setup.stake_escrow, setup.fee_sink,
            "stake escrow should follow the deterministic gas account"
        );
        assert_eq!(
            setup.slash_sink, setup.fee_sink,
            "slash sink should follow the deterministic gas account"
        );
        let expected_label = AccountAlias::new(
            "gas".parse().expect("gas label"),
            Some(AccountAliasDomain::new(
                "ivm".parse::<Name>().expect("ivm domain"),
            )),
            DataSpaceId::UNIVERSAL,
        );
        let mut found_fee_sink = false;
        for instruction in genesis.iter().flatten() {
            let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() else {
                continue;
            };
            if let RegisterBox::Account(account) = register {
                if account.object.label() == Some(&expected_label) {
                    found_fee_sink = true;
                    break;
                }
            }
        }
        assert!(found_fee_sink, "fee sink account should be registered");
        let post_topology = npos_post_topology_instructions(
            setup.validator_accounts.len(),
            profile.bootstrap_public_lanes.as_slice(),
            SumeragiNposParameters::default().min_self_bond(),
            &setup.stake_asset,
            &setup.stake_escrow,
        )
        .expect("post topology instructions");
        let mut registered_validators = HashSet::new();
        let mut activated_validators = HashSet::new();
        for instruction in &post_topology {
            if let Some(register) = instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
            {
                registered_validators.insert((register.lane_id, register.validator.clone()));
            }
            if let Some(activate) = instruction
                .as_any()
                .downcast_ref::<ActivatePublicLaneValidator>()
            {
                activated_validators.insert((activate.lane_id, activate.validator.clone()));
            }
        }
        for validator in &setup.validator_accounts {
            let registered = genesis.iter().flatten().any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .is_some_and(|register| match register {
                        RegisterBox::Account(account) => account.object.id == validator.id,
                        _ => false,
                    })
            });
            assert!(
                registered,
                "validator account {} should be registered in genesis",
                validator.id
            );
            for &lane_id in &profile.bootstrap_public_lanes {
                assert!(
                    registered_validators.contains(&(lane_id, validator.id.clone())),
                    "validator {} should be registered for staking on lane {} in genesis",
                    validator.id,
                    lane_id
                );
                assert!(
                    activated_validators.contains(&(lane_id, validator.id.clone())),
                    "validator {} should be activated on lane {} in genesis",
                    validator.id,
                    lane_id
                );
            }
        }
    }
    #[test]
    fn npos_post_topology_instructions_use_requested_min_self_bond() {
        let min_self_bond = Quantity::from(2_048_u64);
        let bootstrap_public_lanes = [LaneId::new(0), LaneId::new(1)];
        let profile = NexusProfile::sora_defaults().expect("explicit fixture staking profile");
        let escrow = nexus_gas_account_id().expect("configured fixture escrow");
        let instructions = npos_post_topology_instructions(
            4,
            &bootstrap_public_lanes,
            &min_self_bond,
            &profile.stake_asset_id,
            &escrow,
        )
        .expect("post topology instructions");
        let mut register_count = 0usize;
        let mut activate_count = 0usize;
        let mut registered_pairs = HashSet::new();
        let mut activated_pairs = HashSet::new();
        for instruction in &instructions {
            if let Some(register) = instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
            {
                register_count = register_count.saturating_add(1);
                registered_pairs.insert((register.lane_id, register.validator.clone()));
                assert_eq!(
                    register.initial_stake, min_self_bond,
                    "post-topology validator registrations must use configured min self-bond"
                );
                assert_eq!(
                    register.monetary_plan,
                    iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                        AssetId::new(
                            profile.stake_asset_id.clone(),
                            register.stake_account.clone()
                        ),
                        AssetId::new(profile.stake_asset_id.clone(), escrow.clone()),
                        min_self_bond.clone(),
                    ),
                    "genesis must authorize the exact configured stake custody"
                );
            }
            if instruction
                .as_any()
                .downcast_ref::<ActivatePublicLaneValidator>()
                .is_some()
            {
                activate_count = activate_count.saturating_add(1);
            }
            if let Some(activate) = instruction
                .as_any()
                .downcast_ref::<ActivatePublicLaneValidator>()
            {
                activated_pairs.insert((activate.lane_id, activate.validator.clone()));
            }
        }
        assert_eq!(
            register_count,
            4 * bootstrap_public_lanes.len(),
            "expected one validator registration per peer and bootstrap lane"
        );
        assert_eq!(
            activate_count,
            4 * bootstrap_public_lanes.len(),
            "expected one validator activation per peer and bootstrap lane"
        );
        for index in 0..4 {
            let validator = AccountId::new(
                peer_keypair(index)
                    .expect("validator peer key pair")
                    .public_key()
                    .clone(),
            );
            for &lane_id in &bootstrap_public_lanes {
                assert!(
                    registered_pairs.contains(&(lane_id, validator.clone())),
                    "validator {} should be registered on lane {}",
                    validator,
                    lane_id
                );
                assert!(
                    activated_pairs.contains(&(lane_id, validator.clone())),
                    "validator {} should be activated on lane {}",
                    validator,
                    lane_id
                );
            }
        }
    }
    #[test]
    fn nexus_prepare_state_prefunds_validator_stake_for_all_bootstrap_lanes() {
        let profile = NexusProfile::sora_defaults().expect("profile");
        let PreparedChaos { state, genesis, .. } =
            prepare_state(3, None, Some(&profile), WorkloadProfile::Stable, false)
                .expect("state prepared");
        let setup = state.nexus_staking.as_ref().expect("staking setup");
        let expected_stake =
            quantity_to_u64_exact(SumeragiNposParameters::default().min_self_bond())
                .expect("default self-bond must fit Izanami workload accounting")
                .checked_mul(
                    u64::try_from(profile.bootstrap_public_lanes.len()).unwrap_or(u64::MAX),
                )
                .expect("bootstrap stake total must fit Izanami workload accounting");
        let expected_validator_total = expected_stake
            .checked_add(if setup.fee_asset == setup.stake_asset {
                quantity_to_u64_exact(&nexus_fee_seed_amount())
                    .expect("fee seed must fit Izanami workload accounting")
            } else {
                0
            })
            .expect("validator genesis funding must fit Izanami workload accounting");
        let minted_stake_accounts = genesis
            .iter()
            .flatten()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<MintBox>()
                    .and_then(|mint| match mint {
                        MintBox::Asset(asset)
                            if asset.destination.definition() == &setup.stake_asset =>
                        {
                            Some((
                                asset.destination.account().clone(),
                                quantity_to_u64_exact(&asset.object)
                                    .expect("stake mint should remain integer-valued"),
                            ))
                        }
                        _ => None,
                    })
            })
            .fold(
                HashMap::<AccountId, u64>::new(),
                |mut totals, (account, amount)| {
                    let total = totals.entry(account).or_default();
                    *total = total
                        .checked_add(amount)
                        .expect("validator genesis mint total must fit u64");
                    totals
                },
            );
        for validator in &setup.validator_accounts {
            assert_eq!(
                minted_stake_accounts.get(&validator.id).copied(),
                Some(expected_validator_total),
                "validator {} should be prefunded for every bootstrap lane",
                validator.id
            );
        }
    }
    #[test]
    fn nexus_profile_injects_only_supported_runtime_recipes() {
        let profile = NexusProfile::sora_defaults().expect("profile");
        let PreparedChaos { recipes, .. } =
            prepare_state(3, None, Some(&profile), WorkloadProfile::Chaos, false)
                .expect("state prepared");
        assert!(
            recipes
                .iter()
                .any(|kind| matches!(kind, RecipeKind::DvpSettlement))
        );
        assert!(
            recipes
                .iter()
                .any(|kind| matches!(kind, RecipeKind::IssueReplicationOrder))
        );
        assert_eq!(NEXUS_RECIPES_CHAOS.len(), 2);
        assert_eq!(
            recipes.len(),
            BASE_RECIPES_CHAOS.len() + NEXUS_RECIPES_CHAOS.len()
        );
    }
    #[test]
    fn stable_recipes_skip_contract_deploys_by_default() {
        let PreparedChaos { recipes, .. } =
            prepare_state(2, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        assert!(
            !recipes
                .iter()
                .any(|kind| matches!(kind, RecipeKind::DeployIvmContract)),
            "stable recipes should skip IVM contract deployment by default"
        );
        assert!(
            !recipes
                .iter()
                .any(|kind| matches!(kind, RecipeKind::DeployKotodamaContract)),
            "stable recipes should skip Kotodama contract deployment by default"
        );
    }
    #[test]
    fn stable_recipes_allow_contract_deploys_when_enabled() {
        let PreparedChaos { recipes, .. } =
            prepare_state(2, None, None, WorkloadProfile::Stable, true).expect("state prepared");
        assert!(
            recipes
                .iter()
                .any(|kind| matches!(kind, RecipeKind::DeployIvmContract)),
            "stable recipes should include IVM contract deployment when enabled"
        );
        assert!(
            recipes
                .iter()
                .any(|kind| matches!(kind, RecipeKind::DeployKotodamaContract)),
            "stable recipes should include Kotodama contract deployment when enabled"
        );
    }
    #[test]
    fn stable_recipes_are_preseeded_transfer_only() {
        assert_eq!(BASE_RECIPES_STABLE.len(), 1);
        assert!(matches!(BASE_RECIPES_STABLE[0], RecipeKind::TransferAsset));
    }
    #[test]
    fn chaos_recipes_include_stateful_paths() {
        assert!(
            BASE_RECIPES_CHAOS
                .iter()
                .any(|kind| matches!(kind, RecipeKind::SetAssetInstanceKeyValue))
        );
        assert!(
            BASE_RECIPES_CHAOS
                .iter()
                .any(|kind| matches!(kind, RecipeKind::RemoveAssetInstanceKeyValue))
        );
        assert!(
            BASE_RECIPES_CHAOS
                .iter()
                .any(|kind| matches!(kind, RecipeKind::MintTriggerRepetitions))
        );
        assert!(
            BASE_RECIPES_CHAOS
                .iter()
                .any(|kind| matches!(kind, RecipeKind::BurnTriggerRepetitions))
        );
        assert!(
            BASE_RECIPES_CHAOS
                .iter()
                .any(|kind| matches!(kind, RecipeKind::DeployIvmContract))
        );
        assert!(
            BASE_RECIPES_CHAOS
                .iter()
                .any(|kind| matches!(kind, RecipeKind::DeployKotodamaContract))
        );
    }
    #[test]
    fn register_domain_plan_is_disabled_under_sns_domain_model() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let err = state
            .plan_register_domain(&mut StdRng::seed_from_u64(7))
            .expect_err("runtime domain registration should require an external SNS lease");
        assert!(
            err.to_string().contains("SNS domain-name lease"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn produce_plan_for_all_recipes() {
        let PreparedChaos {
            mut state, recipes, ..
        } = prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(7);
        for kind in recipes {
            let plan = state.produce_plan(kind, &mut rng).expect("plan builds");
            assert!(
                !plan.instructions.is_empty(),
                "{kind:?} produced empty plan"
            );
        }
    }
    #[test]
    fn workload_engine_grant_role_never_duplicates_memberships() {
        let PreparedChaos { state, recipes, .. } =
            prepare_state(4, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let engine = WorkloadEngine::new(state, recipes);
        let mut rng = StdRng::seed_from_u64(17);
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime builds");
        runtime.block_on(async {
            let mut guard = engine.state.lock().await;
            let _ = guard.plan_register_role().expect("role prepared");
        });
        engine.set_recipe_override(Some(RecipeKind::GrantRole));
        let membership_count = |engine: &WorkloadEngine| -> usize {
            runtime.block_on(async {
                let guard = engine.state.lock().await;
                guard.role_memberships.values().map(HashSet::len).sum()
            })
        };
        let available_accounts = runtime.block_on(async {
            let guard = engine.state.lock().await;
            let total_accounts = guard.users.len() + 1;
            total_accounts.saturating_sub(guard.role_memberships.values().map(HashSet::len).sum())
        });
        for _ in 0..available_accounts {
            let before = membership_count(&engine);
            let plan = runtime
                .block_on(engine.next_plan(&mut rng))
                .expect("plan builds");
            assert_eq!(plan.label, "grant_role");
            assert!(plan.expect_success, "grant should succeed for new accounts");
            let after = membership_count(&engine);
            assert_eq!(after, before + 1, "grant must add a new membership");
        }
        let before = membership_count(&engine);
        let plan = runtime
            .block_on(engine.next_plan(&mut rng))
            .expect("plan builds");
        assert_eq!(plan.label, "grant_role");
        assert!(
            !plan.expect_success,
            "grant should downgrade once all accounts have the role"
        );
        let after = membership_count(&engine);
        assert_eq!(after, before, "failing grant must not change memberships");
    }
    #[test]
    fn publish_manifest_tracks_dataspaces() {
        let profile = NexusProfile::sora_defaults().expect("profile");
        let PreparedChaos { mut state, .. } =
            prepare_state(2, None, Some(&profile), WorkloadProfile::Stable, false)
                .expect("state prepared");
        let mut rng = StdRng::seed_from_u64(99);
        let plan = state
            .plan_publish_space_manifest(&mut rng)
            .expect("manifest plan builds");
        assert_eq!(plan.label, "publish_space_directory_manifest");
        assert!(
            state
                .space_directory_manifests
                .values()
                .any(|spaces| !spaces.is_empty()),
            "dataspace tracking should record published manifests"
        );
    }
    #[test]
    fn replication_orders_are_tracked() {
        let profile = NexusProfile::sora_defaults().expect("profile");
        let PreparedChaos { mut state, .. } =
            prepare_state(2, None, Some(&profile), WorkloadProfile::Stable, false)
                .expect("state prepared");
        let mut rng = StdRng::seed_from_u64(45);
        let plan = state
            .plan_issue_replication_order(&mut rng)
            .expect("replication plan builds");
        assert_eq!(plan.label, "seed_replication_manifest");
        let authority = plan
            .instructions
            .iter()
            .find_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<SetProviderIngestCompletionAuthority>()
            })
            .expect("replication seed installs the exact completion authority");
        assert_eq!(authority.next.provider_owner, state.treasury.id);
        assert!(authority.next.signer_policy.is_valid());
        assert!(
            state.pending_replication_orders.is_empty(),
            "replication orders should not be tracked before issuance"
        );
        let plan = state
            .plan_issue_replication_order(&mut rng)
            .expect("replication plan builds");
        assert_eq!(plan.label, "issue_replication_order");
        assert!(
            !state.pending_replication_orders.is_empty(),
            "pending replication orders should be tracked"
        );
    }
    #[test]
    fn replication_order_payload_references_seeded_manifest() {
        let profile = NexusProfile::sora_defaults().expect("profile");
        let PreparedChaos {
            mut state,
            sorafs_provider_owners,
            ..
        } = prepare_state(2, None, Some(&profile), WorkloadProfile::Stable, false)
            .expect("state prepared");
        let replication = state.sorafs_replication.as_ref().expect("replication seed");
        assert_eq!(
            sorafs_provider_owners.get(&replication.provider_id.to_string()),
            Some(
                &state
                    .treasury
                    .id
                    .canonical_i105()
                    .expect("canonical treasury owner")
            ),
            "Izanami must seed provider ownership through pre-genesis configuration"
        );
        let mut rng = StdRng::seed_from_u64(52);
        let seed = state
            .plan_issue_replication_order(&mut rng)
            .expect("replication seed builds");
        assert_eq!(seed.label, "seed_replication_manifest");
        let plan = state
            .plan_issue_replication_order(&mut rng)
            .expect("replication plan builds");
        assert_eq!(plan.label, "issue_replication_order");
        let instruction = plan
            .instructions
            .first()
            .expect("replication order instruction");
        let issue = instruction
            .as_any()
            .downcast_ref::<IssueReplicationOrder>()
            .expect("issue replication order");
        let decoded = ReplicationOrderV1::decode(&mut issue.order_payload.as_slice())
            .expect("decode payload");
        assert!(!issue.order_id.is_auto());
        assert_eq!(decoded.order_id, *issue.order_id.as_bytes());
        assert_eq!(decoded.issued_at, issue.issued_epoch);
        assert_eq!(decoded.deadline_at, issue.deadline_epoch);
        let seed = state.sorafs_replication.as_ref().expect("replication seed");
        assert_eq!(decoded.manifest_digest, *seed.manifest_digest.as_bytes());
        assert_eq!(decoded.chunking_profile, seed.chunker.to_handle());
        let assignment = decoded.assignments.first().expect("assignment");
        assert_eq!(assignment.provider_id, *seed.provider_id.as_bytes());
    }
    #[test]
    fn dvp_settlement_plan_builds() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(77);
        let plan = state
            .plan_dvp_settlement(&mut rng)
            .expect("dvp plan builds");
        assert_eq!(plan.label, "dvp_settlement");
        assert!(plan.expect_success);
        let settlement = plan
            .instructions
            .iter()
            .find_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<SettlementInstructionBox>()
            })
            .expect("settlement instruction");
        match settlement {
            SettlementInstructionBox::Dvp(isi) => {
                assert_eq!(isi.delivery_leg.from, plan.signer.id);
            }
            SettlementInstructionBox::Atomic(_)
            | SettlementInstructionBox::Pvp(_)
            | SettlementInstructionBox::SetFxCorridorPolicy(_)
            | SettlementInstructionBox::FundFxCorridorEscrow(_)
            | SettlementInstructionBox::RefundFxCorridorEscrow(_)
            | SettlementInstructionBox::SettleFxCorridor(_) => {
                panic!("expected DvP settlement instruction");
            }
        }
    }
    #[test]
    fn asset_definition_register_and_unregister_moves_tracking() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(11);
        let before = state.asset_definitions_unclaimed.len();
        let register_plan = state
            .plan_register_asset_definition()
            .expect("register definition");
        assert_eq!(register_plan.label, "register_asset_definition");
        assert_eq!(
            state.asset_definitions_unclaimed.len(),
            before + 1,
            "new definition should be tracked as unclaimed"
        );
        let unregister_plan = state.plan_unregister_asset_definition(&mut rng);
        assert!(
            unregister_plan.expect_success,
            "recent definition should be removable"
        );
        assert!(
            state.asset_definitions_unclaimed.len() <= before,
            "unclaimed pool should shrink after removal"
        );
    }
    #[test]
    fn unregister_asset_definition_fallback_uses_missing_definition() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        assert!(state.asset_definitions_unclaimed.is_empty());
        let before = state.asset_definitions.clone();
        let mut rng = StdRng::seed_from_u64(19);
        let plan = state.plan_unregister_asset_definition(&mut rng);
        assert_eq!(plan.label, "unregister_asset_definition");
        assert!(!plan.expect_success, "fallback should expect failure");
        assert_eq!(
            state.asset_definitions, before,
            "fallback should not mutate tracked definitions"
        );
        let target = plan
            .instructions
            .iter()
            .find_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<UnregisterBox>()
                    .and_then(|unregister| match unregister {
                        UnregisterBox::AssetDefinition(inner) => Some(inner.object.clone()),
                        _ => None,
                    })
            })
            .expect("unregister asset definition instruction");
        assert!(
            !before.contains(&target),
            "fallback should use a missing asset definition id"
        );
    }
    #[test]
    fn nft_registration_and_transfer_updates_owner() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(29);
        let register_plan = state.plan_register_nft(&mut rng).expect("register nft");
        assert_eq!(register_plan.label, "register_nft");
        assert_eq!(state.nft_holdings.len(), 1, "nft holding should be tracked");
        let before_ids: HashSet<NftId> = state.nft_holdings.keys().cloned().collect();
        let transfer_plan = state.plan_transfer_nft(&mut rng).expect("transfer nft");
        assert_eq!(transfer_plan.label, "transfer_nft");
        let after_ids: HashSet<NftId> = state.nft_holdings.keys().cloned().collect();
        assert_eq!(
            after_ids.len(),
            before_ids.len() + 1,
            "transfer should register a new nft entry"
        );
        let new_id = after_ids
            .difference(&before_ids)
            .next()
            .expect("new nft id should be recorded");
        let new_owner = state
            .nft_holdings
            .get(new_id)
            .expect("new owner should be tracked");
        assert_ne!(
            new_owner, &state.treasury.id,
            "transfer should move newly minted nft away from treasury"
        );
    }
    #[test]
    fn trigger_repetition_mint_and_burn_balance() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(93);
        let register_plan = state
            .plan_mint_trigger_repetitions(&mut rng)
            .expect("register repeatable trigger");
        assert_eq!(register_plan.label, "mint_trigger_repetitions");
        register_plan.apply_updates(&mut state, true);
        let trigger_id = state
            .repeatable_trigger_state
            .keys()
            .next()
            .cloned()
            .expect("repeatable trigger should be tracked");
        state.sync_repeatable_trigger_repetitions(trigger_id.clone(), Some(3));
        let minted = state
            .repeatable_trigger_repetitions(&trigger_id)
            .expect("trigger should stay reusable after reconciliation");
        assert_eq!(
            minted, 3,
            "reconciliation should capture the exact on-chain count"
        );
        let burn_plan = state
            .plan_burn_trigger_repetitions(&mut rng)
            .expect("burn repetitions");
        assert_eq!(burn_plan.label, "burn_trigger_repetitions");
        burn_plan.apply_updates(&mut state, true);
        assert_eq!(
            state.repeatable_trigger_repetitions(&trigger_id),
            Some(3),
            "successful burn should wait for exact post-submit reconciliation"
        );
        state.sync_repeatable_trigger_repetitions(trigger_id.clone(), Some(2));
        assert_eq!(
            state.repeatable_trigger_repetitions(&trigger_id),
            Some(2),
            "post-submit reconciliation should apply the exact on-chain burn result"
        );
    }
    #[test]
    fn mint_trigger_repetitions_registers_repeatable_trigger() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(111);
        let pipeline = state
            .plan_pipeline_trigger(&mut rng)
            .expect("pipeline trigger");
        assert_eq!(pipeline.label, "register_pipeline_trigger");
        assert!(state.repeatable_trigger_state.is_empty());
        let plan = state
            .plan_mint_trigger_repetitions(&mut rng)
            .expect("mint plan");
        let trigger = plan
            .instructions
            .iter()
            .find_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .and_then(|register| match register {
                        RegisterBox::Trigger(registration) => Some(&registration.object),
                        _ => None,
                    })
            })
            .expect("repeatable trigger registration");
        assert!(matches!(trigger.action().repeats(), Repeats::Exactly(_)));
        assert!(matches!(
            trigger.action().filter(),
            EventFilterBox::ExecuteTrigger(_)
        ));
        plan.apply_updates(&mut state, true);
        assert!(
            matches!(
                state.repeatable_trigger_state.get(trigger.id()),
                Some(RepeatableTriggerState::Known { repetitions: 1 })
            ),
            "successful trigger registration should start with one known repetition"
        );
    }
    #[test]
    fn mint_trigger_repetitions_plan_exposes_target() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(222);
        let register_plan = state
            .plan_mint_trigger_repetitions(&mut rng)
            .expect("register repeatable trigger");
        register_plan.apply_updates(&mut state, true);
        let mint_plan = state
            .plan_mint_trigger_repetitions(&mut rng)
            .expect("mint repetitions");
        let (trigger_id, amount) = mint_plan
            .mint_trigger_repetitions()
            .expect("mint plan should contain trigger repetitions");
        assert!(
            matches!(
                state.repeatable_trigger_state.get(&trigger_id),
                Some(RepeatableTriggerState::Known { repetitions: 1 })
            ),
            "mint plan should target a tracked trigger"
        );
        assert!(amount > 0, "mint amount should be positive");
    }
    #[test]
    fn failed_asset_plan_does_not_poison_asset_metadata_target() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(223);
        let stale_plan = state.plan_mint_asset(&mut rng).expect("mint asset plan");
        let stale_asset = minted_asset_destination(&stale_plan);
        assert!(
            !state.asset_instances.contains(&stale_asset),
            "planning alone must not track unconfirmed asset instances"
        );
        let metadata_plan = state
            .plan_set_asset_metadata(&mut rng)
            .expect("asset metadata plan");
        let metadata_asset = minted_asset_destination(&metadata_plan);
        let treasury_asset = AssetId::new(state.asset_quantity.clone(), state.treasury.id.clone());
        assert_eq!(
            metadata_asset, treasury_asset,
            "asset metadata should fall back to the known genesis asset after a failed mint"
        );
        assert_ne!(
            metadata_asset, stale_asset,
            "asset metadata should not target an asset that never committed"
        );
    }
    #[test]
    fn transfer_asset_plan_uses_preseeded_balances() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(224);
        let plan = state.plan_transfer_asset(&mut rng).expect("transfer asset");
        assert!(plan.state_updates.is_empty());
        assert_eq!(plan.instructions.len(), 1);
        assert!(
            plan.instructions[0]
                .as_any()
                .downcast_ref::<TransferBox>()
                .is_some(),
            "stable transfer path should submit only the transfer instruction"
        );
        let transfer = plan.instructions[0]
            .as_any()
            .downcast_ref::<TransferBox>()
            .expect("transfer instruction");
        let TransferBox::Asset(transfer) = transfer else {
            panic!("stable transfer should move a numeric asset");
        };
        assert_eq!(
            transfer.source.account(),
            &plan.signer.id,
            "stable transfer signer should own the source asset"
        );
        assert_ne!(
            plan.signer.id, state.treasury.id,
            "stable transfer load should distribute authority across prefunded users"
        );
        assert!(
            plan.instructions
                .iter()
                .all(|instruction| instruction.as_any().downcast_ref::<MintBox>().is_none()),
            "stable transfer path should not mint during the measured hot path"
        );
    }
    #[test]
    fn stable_transfer_plan_uses_disjoint_sender_receiver_halves() {
        let PreparedChaos { mut state, .. } =
            prepare_state(8, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(225);
        let pair_count = state.users.len() / 2;
        let first = state.plan_transfer_asset(&mut rng).expect("first transfer");
        let second = state
            .plan_transfer_asset(&mut rng)
            .expect("second transfer");
        let first_transfer = first.instructions[0]
            .as_any()
            .downcast_ref::<TransferBox>()
            .expect("transfer instruction");
        let second_transfer = second.instructions[0]
            .as_any()
            .downcast_ref::<TransferBox>()
            .expect("transfer instruction");
        let TransferBox::Asset(first_transfer) = first_transfer else {
            panic!("stable transfer should move a numeric asset");
        };
        let TransferBox::Asset(second_transfer) = second_transfer else {
            panic!("stable transfer should move a numeric asset");
        };
        assert_eq!(first.signer.id, state.users[0].id);
        assert_eq!(first_transfer.destination, state.users[pair_count].id);
        assert_eq!(second.signer.id, state.users[1].id);
        assert_eq!(second_transfer.destination, state.users[pair_count + 1].id);
        assert_ne!(first.signer.id, first_transfer.destination);
        assert_ne!(second.signer.id, second_transfer.destination);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ordered_plan_sequence_preserves_stable_transfer_pair_order() {
        let PreparedChaos { state, recipes, .. } =
            prepare_state(8, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let pair_count = state.users.len() / 2;
        let first_sender = state.users[0].id.clone();
        let first_receiver = state.users[pair_count].id.clone();
        let second_sender = state.users[1].id.clone();
        let second_receiver = state.users[pair_count + 1].id.clone();
        let engine = WorkloadEngine::new(state, recipes);
        engine.set_recipe_override(Some(RecipeKind::TransferAsset));
        let mut rng = StdRng::seed_from_u64(226);
        let (first_order, first) = engine
            .next_ordered_plan(&mut rng)
            .await
            .expect("first ordered transfer");
        let (second_order, second) = engine
            .next_ordered_plan(&mut rng)
            .await
            .expect("second ordered transfer");
        let first_transfer = first.instructions[0]
            .as_any()
            .downcast_ref::<TransferBox>()
            .expect("transfer instruction");
        let second_transfer = second.instructions[0]
            .as_any()
            .downcast_ref::<TransferBox>()
            .expect("transfer instruction");
        let TransferBox::Asset(first_transfer) = first_transfer else {
            panic!("stable transfer should move a numeric asset");
        };
        let TransferBox::Asset(second_transfer) = second_transfer else {
            panic!("stable transfer should move a numeric asset");
        };
        assert_eq!((first_order, second_order), (0, 1));
        assert_eq!(first.signer.id, first_sender);
        assert_eq!(first_transfer.destination, first_receiver);
        assert_eq!(second.signer.id, second_sender);
        assert_eq!(second_transfer.destination, second_receiver);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn workload_record_result_applies_updates_on_success() {
        let PreparedChaos {
            state,
            genesis: _,
            recipes,
            sorafs_provider_owners: _,
        } = prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let engine = WorkloadEngine::new(state, recipes);
        engine.set_recipe_override(Some(RecipeKind::SetTriggerKeyValue));
        let mut rng = StdRng::seed_from_u64(211);
        let plan = engine.next_plan(&mut rng).await.expect("plan built");
        {
            let guard = engine.state.lock().await;
            assert!(
                guard.registered_triggers.is_empty(),
                "plans should not mutate trigger state before success"
            );
        }
        engine.record_result(&plan, false).await;
        {
            let guard = engine.state.lock().await;
            assert!(
                guard.registered_triggers.is_empty(),
                "failed submissions should not update trigger state"
            );
        }
        engine.record_result(&plan, true).await;
        {
            let guard = engine.state.lock().await;
            assert_eq!(
                guard.registered_triggers.len(),
                1,
                "successful submissions should apply trigger updates"
            );
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn workload_record_result_tracks_assets_only_on_success() {
        let PreparedChaos {
            state,
            genesis: _,
            recipes,
            sorafs_provider_owners: _,
        } = prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let engine = WorkloadEngine::new(state, recipes);
        engine.set_recipe_override(Some(RecipeKind::MintAsset));
        let mut rng = StdRng::seed_from_u64(224);
        let plan = engine.next_plan(&mut rng).await.expect("mint plan");
        let asset_id = minted_asset_destination(&plan);
        {
            let guard = engine.state.lock().await;
            assert!(
                !guard.asset_instances.contains(&asset_id),
                "plans should not pre-track minted assets before confirmation"
            );
        }
        engine.record_result(&plan, false).await;
        {
            let guard = engine.state.lock().await;
            assert!(
                !guard.asset_instances.contains(&asset_id),
                "failed submissions should not leave stale asset tracking behind"
            );
        }
        engine.record_result(&plan, true).await;
        {
            let guard = engine.state.lock().await;
            assert!(
                guard.asset_instances.contains(&asset_id),
                "successful submissions should publish the asset into workload tracking"
            );
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn workload_record_result_releases_trigger_reservation_on_failure() {
        let PreparedChaos {
            mut state,
            genesis: _,
            recipes,
            sorafs_provider_owners: _,
        } = prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let trigger_id: TriggerId = "repeatable_trigger_failure"
            .parse()
            .expect("valid trigger id");
        state.repeatable_trigger_state.insert(
            trigger_id.clone(),
            RepeatableTriggerState::Known { repetitions: 2 },
        );
        let engine = WorkloadEngine::new(state, recipes);
        engine.set_recipe_override(Some(RecipeKind::BurnTriggerRepetitions));
        let mut rng = StdRng::seed_from_u64(412);
        let plan = engine.next_plan(&mut rng).await.expect("burn plan");
        {
            let guard = engine.state.lock().await;
            assert!(
                guard.pending_trigger_repetitions.contains_key(&trigger_id),
                "burn plan should reserve repetitions"
            );
        }
        engine.record_result(&plan, false).await;
        {
            let guard = engine.state.lock().await;
            assert_eq!(
                guard
                    .pending_trigger_repetitions
                    .get(&trigger_id)
                    .copied()
                    .unwrap_or(0),
                0,
                "failed submissions should release trigger reservations"
            );
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn workload_record_result_releases_pending_on_failure() {
        let PreparedChaos {
            mut state,
            genesis: _,
            recipes,
            sorafs_provider_owners: _,
        } = prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let trigger_id: TriggerId = "repeatable_trigger_pending_failure"
            .parse()
            .expect("valid trigger id");
        state
            .pending_trigger_repetitions
            .insert(trigger_id.clone(), 2);
        let plan = TransactionPlan {
            label: "release_pending_trigger_repetitions",
            instructions: Vec::new(),
            signer: state.treasury.clone(),
            expect_success: false,
            state_updates: vec![PlanUpdate::ReleaseTriggerRepetitionsReservation {
                trigger_id: trigger_id.clone(),
                amount: 2,
            }],
        };
        let engine = WorkloadEngine::new(state, recipes);
        engine.record_result(&plan, false).await;
        let guard = engine.state.lock().await;
        assert!(
            guard
                .pending_trigger_repetitions
                .get(&trigger_id)
                .copied()
                .unwrap_or(0)
                == 0,
            "failed submissions should release pending burn reservations"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn workload_sync_trigger_repetitions_updates_tracking() {
        let PreparedChaos {
            state,
            genesis: _,
            recipes,
            sorafs_provider_owners: _,
        } = prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let engine = WorkloadEngine::new(state, recipes);
        let trigger_id: TriggerId = "repeatable_trigger_sync".parse().expect("valid trigger id");
        engine.sync_trigger_repetitions(&trigger_id, Some(3)).await;
        {
            let guard = engine.state.lock().await;
            assert!(
                matches!(
                    guard.repeatable_trigger_state.get(&trigger_id),
                    Some(RepeatableTriggerState::Known { repetitions: 3 })
                ),
                "sync should store the exact known repetition count"
            );
        }
        engine.sync_trigger_repetitions(&trigger_id, None).await;
        let guard = engine.state.lock().await;
        assert!(
            matches!(
                guard.repeatable_trigger_state.get(&trigger_id),
                Some(RepeatableTriggerState::Missing)
            ),
            "sync removal should mark the trigger missing instead of forgetting it"
        );
    }
    #[test]
    fn repeatable_trigger_tracking_dedupes_ids() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let trigger_id: TriggerId = "repeatable_trigger_dedupe"
            .parse()
            .expect("valid trigger id");
        state.track_repeatable_trigger(trigger_id.clone());
        state.track_repeatable_trigger(trigger_id);
        assert_eq!(
            state.repeatable_trigger_state.len(),
            1,
            "repeatable trigger tracking should not duplicate ids"
        );
    }
    #[test]
    fn trigger_planner_excludes_missing_and_unknown() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(141);
        let missing_id: TriggerId = "repeatable_trigger_missing"
            .parse()
            .expect("valid trigger id");
        let unknown_id: TriggerId = "repeatable_trigger_unknown"
            .parse()
            .expect("valid trigger id");
        let known_id: TriggerId = "repeatable_trigger_known"
            .parse()
            .expect("valid trigger id");
        state
            .repeatable_trigger_state
            .insert(missing_id, RepeatableTriggerState::Missing);
        state
            .repeatable_trigger_state
            .insert(unknown_id, RepeatableTriggerState::Unknown);
        state.repeatable_trigger_state.insert(
            known_id.clone(),
            RepeatableTriggerState::Known { repetitions: 2 },
        );
        let burn = state
            .plan_burn_trigger_repetitions(&mut rng)
            .expect("burn plan");
        assert_eq!(burn.label, "burn_trigger_repetitions");
        assert!(
            burn.burn_trigger_repetitions()
                .is_some_and(|(trigger_id, _)| trigger_id == known_id),
            "planner must only target triggers with known positive repetitions"
        );
    }
    #[test]
    fn burn_trigger_repetitions_keeps_trigger_state_until_reconciled() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let trigger_id: TriggerId = "repeatable_trigger_keep".parse().expect("valid trigger id");
        state.repeatable_trigger_state.insert(
            trigger_id.clone(),
            RepeatableTriggerState::Known { repetitions: 2 },
        );
        let mut rng = StdRng::seed_from_u64(212);
        let burn = state
            .plan_burn_trigger_repetitions(&mut rng)
            .expect("burn plan");
        assert_eq!(burn.label, "burn_trigger_repetitions");
        burn.apply_updates(&mut state, true);
        assert!(
            matches!(
                state.repeatable_trigger_state.get(&trigger_id),
                Some(RepeatableTriggerState::Known { repetitions: 2 })
            ),
            "successful burns should keep the prior count until post-submit reconciliation"
        );
        state.sync_repeatable_trigger_repetitions(trigger_id.clone(), Some(1));
        assert!(
            matches!(
                state.repeatable_trigger_state.get(&trigger_id),
                Some(RepeatableTriggerState::Known { repetitions: 1 })
            ),
            "exact reconciliation should update the known remaining count"
        );
    }
    #[test]
    fn burn_trigger_repetitions_releases_pending_on_failure() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let trigger_id: TriggerId = "repeatable_trigger_pending"
            .parse()
            .expect("valid trigger id");
        state.repeatable_trigger_state.insert(
            trigger_id.clone(),
            RepeatableTriggerState::Known { repetitions: 2 },
        );
        let mut rng = StdRng::seed_from_u64(212);
        let burn = state
            .plan_burn_trigger_repetitions(&mut rng)
            .expect("burn plan");
        let reserved = state
            .pending_trigger_repetitions
            .get(&trigger_id)
            .copied()
            .unwrap_or(0);
        assert!(reserved > 0, "burn plan should reserve repetitions");
        burn.apply_updates(&mut state, false);
        assert_eq!(
            state
                .pending_trigger_repetitions
                .get(&trigger_id)
                .copied()
                .unwrap_or(0),
            0,
            "failed burn should release pending reservation"
        );
        assert_eq!(
            state.repeatable_trigger_state.get(&trigger_id),
            Some(&RepeatableTriggerState::Known { repetitions: 2 }),
            "failed burn should keep the trigger in its last known good state"
        );
    }
    #[test]
    fn trigger_metadata_plans_do_not_track_repeatable_triggers() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(151);
        let set_plan = state
            .plan_set_trigger_key(&mut rng)
            .expect("set trigger metadata");
        assert_eq!(set_plan.label, "set_trigger_kv");
        set_plan.apply_updates(&mut state, true);
        let trigger = set_plan
            .instructions
            .iter()
            .find_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .and_then(|register| match register {
                        RegisterBox::Trigger(registration) => Some(&registration.object),
                        _ => None,
                    })
            })
            .expect("metadata trigger registration");
        assert!(matches!(
            trigger.action().filter(),
            EventFilterBox::ExecuteTrigger(_)
        ));
        assert!(matches!(trigger.action().repeats(), Repeats::Indefinitely));
        assert!(
            state.registered_triggers.contains(trigger.id()),
            "metadata trigger should be tracked as durable"
        );
        assert!(
            state.repeatable_trigger_state.is_empty(),
            "metadata trigger should not be tracked as repeatable"
        );
        let remove_plan = state
            .plan_remove_trigger_key(&mut rng)
            .expect("remove trigger metadata");
        assert_eq!(remove_plan.label, "remove_trigger_kv");
        remove_plan.apply_updates(&mut state, true);
        assert!(
            state.repeatable_trigger_state.is_empty(),
            "metadata trigger should not be tracked as repeatable"
        );
    }
    #[test]
    fn time_trigger_is_not_repeatable() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(161);
        let plan = state.plan_time_trigger(&mut rng).expect("time trigger");
        assert_eq!(plan.label, "register_time_trigger");
        assert!(
            state.repeatable_trigger_state.is_empty(),
            "time triggers should not be used for repetition mint/burn"
        );
    }
    #[test]
    fn deploy_ivm_trigger_is_not_repeatable() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(171);
        let plan = state.plan_deploy_ivm(&mut rng).expect("ivm trigger");
        assert_eq!(plan.label, "deploy_ivm_contract");
        assert!(
            state.repeatable_trigger_state.is_empty(),
            "IVM triggers should not be used for repetition mint/burn"
        );
    }
    #[test]
    fn execute_trigger_registers_and_executes_call_trigger() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(103);
        let plan = state
            .plan_execute_trigger(&mut rng)
            .expect("execute trigger");
        assert_eq!(plan.label, "execute_trigger");
        plan.apply_updates(&mut state, true);
        let registered = plan
            .instructions
            .iter()
            .find_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .and_then(|register| match register {
                        RegisterBox::Trigger(registration) => Some(registration.object.clone()),
                        _ => None,
                    })
            })
            .expect("call trigger registration");
        let execute = plan
            .instructions
            .iter()
            .find_map(|instruction| instruction.as_any().downcast_ref::<ExecuteTrigger>())
            .expect("execute trigger instruction");
        assert_eq!(execute.trigger, *registered.id());
        assert!(
            state.call_triggers.contains(registered.id()),
            "call trigger should be tracked"
        );
    }
    #[test]
    fn asset_metadata_set_and_remove_trackers() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(55);
        let tracked_before: usize = state.asset_metadata.values().map(HashSet::len).sum();
        let set_plan = state
            .plan_set_asset_metadata(&mut rng)
            .expect("set asset metadata");
        assert_eq!(set_plan.label, "set_asset_kv");
        let tracked_after_set: usize = state.asset_metadata.values().map(HashSet::len).sum();
        assert!(
            tracked_after_set >= tracked_before,
            "setting metadata should not reduce tracked keys"
        );
        let remove_plan = state
            .plan_remove_asset_metadata(&mut rng)
            .expect("remove asset metadata");
        assert_eq!(remove_plan.label, "remove_asset_kv");
        let tracked_after_remove: usize = state.asset_metadata.values().map(HashSet::len).sum();
        assert!(
            tracked_after_remove <= tracked_after_set,
            "removal should not grow metadata tracking"
        );
    }
    #[test]
    fn account_metadata_plans_use_account_signer() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let mut rng = StdRng::seed_from_u64(101);
        let set_plan = state.plan_set_key(&mut rng).expect("set key plan");
        let set_target = set_plan
            .instructions
            .iter()
            .find_map(
                |instr| match instr.as_any().downcast_ref::<SetKeyValueBox>() {
                    Some(SetKeyValueBox::Account(set)) => Some(set.object.clone()),
                    _ => None,
                },
            )
            .expect("set key instruction should target an account");
        assert_eq!(
            set_plan.signer.id, set_target,
            "set key plan should be signed by the account owner"
        );
        let remove_plan = state.plan_remove_key(&mut rng).expect("remove key plan");
        let remove_target = remove_plan
            .instructions
            .iter()
            .find_map(
                |instr| match instr.as_any().downcast_ref::<RemoveKeyValueBox>() {
                    Some(RemoveKeyValueBox::Account(remove)) => Some(remove.object.clone()),
                    _ => None,
                },
            )
            .expect("remove key instruction should target an account");
        assert_eq!(
            remove_plan.signer.id, remove_target,
            "remove key plan should be signed by the account owner"
        );
    }
    #[test]
    fn account_metadata_set_and_remove_trackers() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        assert!(state.account_metadata.is_empty());
        let mut rng = StdRng::seed_from_u64(205);
        let set_plan = state.plan_set_key(&mut rng).expect("set key plan");
        assert_eq!(set_plan.label, "set_account_kv");
        let tracked_after_set: usize = state.account_metadata.values().map(HashSet::len).sum();
        assert!(tracked_after_set > 0, "set key should be tracked");
        let remove_plan = state.plan_remove_key(&mut rng).expect("remove key plan");
        assert_eq!(remove_plan.label, "remove_account_kv");
        let tracked_after_remove: usize = state.account_metadata.values().map(HashSet::len).sum();
        assert!(
            tracked_after_remove <= tracked_after_set,
            "removal should not increase tracked keys"
        );
    }
    #[test]
    fn register_uaid_account_tracks_mapping() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let before = state.uaid_accounts.len();
        let plan = state
            .plan_register_uaid_account()
            .expect("register UAID account plan");
        assert_eq!(plan.label, "register_uaid_account");
        assert_eq!(
            state.uaid_accounts.len(),
            before,
            "planning alone must not publish the new UAID account"
        );
        plan.apply_updates(&mut state, false);
        assert_eq!(
            state.uaid_accounts.len(),
            before,
            "failed account registration must not mutate the UAID registry"
        );
        plan.apply_updates(&mut state, true);
        assert!(
            state
                .uaid_accounts
                .values()
                .any(|record| record.uaid.is_some()),
            "UAID registry should record the new account"
        );
    }
    #[test]
    fn register_account_tracks_only_on_success() {
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, None, WorkloadProfile::Stable, false).expect("state prepared");
        let before = state.users.len();
        let plan = state
            .plan_register_account()
            .expect("register account plan");
        assert_eq!(plan.label, "register_account");
        assert_eq!(
            state.users.len(),
            before,
            "planning alone must not publish the new account"
        );
        plan.apply_updates(&mut state, false);
        assert_eq!(
            state.users.len(),
            before,
            "failed account registration must not mutate tracked users"
        );
        plan.apply_updates(&mut state, true);
        assert_eq!(
            state.users.len(),
            before + 1,
            "successful account registration should publish the signer account"
        );
    }
    #[test]
    fn nexus_genesis_prefunds_fee_asset_for_signers() {
        let profile = NexusProfile::sora_defaults().expect("profile");
        let PreparedChaos { state, genesis, .. } =
            prepare_state(3, None, Some(&profile), WorkloadProfile::Stable, false)
                .expect("state prepared");
        let setup = state
            .nexus_staking
            .as_ref()
            .expect("nexus staking setup should be present");
        let fee_asset = setup.fee_asset.clone();
        let minted_fee_accounts: HashSet<AccountId> = genesis
            .iter()
            .flatten()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<MintBox>()
                    .and_then(|mint| match mint {
                        MintBox::Asset(asset) if asset.destination.definition() == &fee_asset => {
                            Some(asset.destination.account().clone())
                        }
                        _ => None,
                    })
            })
            .collect();
        assert!(
            minted_fee_accounts.contains(&state.treasury.id),
            "treasury should start with fee asset balance under nexus"
        );
        for user in &state.users {
            assert!(
                minted_fee_accounts.contains(&user.id),
                "every seeded workload user should start with fee asset balance"
            );
        }
        for validator in &setup.validator_accounts {
            assert!(
                minted_fee_accounts.contains(&validator.id),
                "every validator signer should start with fee asset balance"
            );
        }
    }
    #[test]
    fn nexus_prepare_state_registers_fee_asset_definition() {
        let profile = NexusProfile::sora_defaults().expect("profile");
        let PreparedChaos { genesis, .. } =
            prepare_state(3, None, Some(&profile), WorkloadProfile::Stable, false)
                .expect("state prepared");
        let fee_registration_count = genesis
            .iter()
            .flatten()
            .filter(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .is_some_and(|register| match register {
                        RegisterBox::AssetDefinition(definition) => {
                            definition.object.id == profile.fee_asset_id
                        }
                        _ => false,
                    })
            })
            .count();
        assert_eq!(
            fee_registration_count, 1,
            "prepare_state should register the fee asset definition before minting it"
        );
    }
    #[test]
    fn nexus_account_registration_prefunds_fee_asset_and_tracks_on_success() {
        let profile = NexusProfile::sora_defaults().expect("profile");
        let PreparedChaos { mut state, .. } =
            prepare_state(3, None, Some(&profile), WorkloadProfile::Stable, false)
                .expect("state prepared");
        let before = state.users.len();
        let plan = state
            .plan_register_account()
            .expect("register account plan");
        let registered_account = plan
            .instructions
            .iter()
            .find_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .and_then(|register| match register {
                        RegisterBox::Account(account) => Some(account.object.id().clone()),
                        _ => None,
                    })
            })
            .expect("plan should register an account");
        let fee_asset = state
            .nexus_staking
            .as_ref()
            .expect("nexus staking setup should exist")
            .fee_asset
            .clone();
        assert!(
            minted_asset_destinations(&plan.instructions)
                .iter()
                .any(|asset| {
                    asset.definition() == &fee_asset && asset.account() == &registered_account
                }),
            "nexus account registration should prefund the new signer with fee asset"
        );
        assert_eq!(
            state.users.len(),
            before,
            "planning alone must not publish the new account"
        );
        plan.apply_updates(&mut state, true);
        assert!(
            state
                .users
                .iter()
                .any(|record| record.id == registered_account),
            "successful account registration should publish the new signer"
        );
    }
    include!("instructions_tail_tests.rs");
}
