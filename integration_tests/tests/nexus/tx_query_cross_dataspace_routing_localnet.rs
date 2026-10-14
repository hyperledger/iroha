//! Focused wrong-dataspace Torii ingress regression for transaction and query routing.
use super::localnet_npos::npos_override_transactions;
use eyre::{Result, WrapErr, ensure, eyre};
use integration_tests::sandbox;
use iroha::query::QueryError;
use iroha::{
    blocking::Client,
    crypto::Hash,
    data_model::{
        Level, NetworkId,
        account::{Account, AccountId},
        asset::{AssetDefinition, AssetDefinitionId, AssetId},
        block::BlockHeader,
        da::commitment::DaProofPolicyBundle,
        domain::Domain,
        isi::{
            InstructionBox, Log, Mint, Register,
            consensus_keys::RegisterConsensusKey,
            space_directory::PublishSpaceDirectoryManifest,
            staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
        },
        nexus::{
            Allowance, AllowanceWindow, AssetPermissionManifest, CapabilityScope, LaneCatalog,
            LaneConfig as ModelLaneConfig, LaneVisibility, ManifestEffect, ManifestEntry,
            ManifestVersion, UniversalAccountId,
        },
        prelude::{FindAssetById, Identifiable, Quantity},
        sumeragi::SumeragiStatus,
        transaction::{SignedTransaction, TransactionSubmissionReceipt},
    },
};
use iroha_config::parameters::actual::LaneConfig as ActualLaneConfig;
use iroha_core::{da::proof_policy_bundle, state::derive_committee_key_id};
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::{
    ValidationFail,
    query::error::{FindError, QueryExecutionFail},
};
use iroha_genesis::GenesisTopologyEntry;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::numeric::NumericSpec;
use iroha_test_network::{
    NetworkBuilder, genesis_participant_committee_key_instructions,
    unexecuted_genesis_factory_with_post_topology,
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR};
use iroha_torii::{
    HEADER_ACCOUNT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP_MS, Method, Uri,
    canonical_network_request_signature_message, signature_header_value,
};
use norito::{decode_from_bytes, json::Value as JsonValue};
use reqwest::StatusCode as HttpStatusCode;
use std::{
    collections::BTreeSet,
    num::NonZeroU32,
    thread,
    time::{Duration, Instant},
};
use tokio::time::sleep;
use toml::{Table, Value as TomlValue};
const NEXUS_ALIAS: &str = "universal";
const DS1_ALIAS: &str = "ds1";
const DS2_ALIAS: &str = "ds2";
const NEXUS_ID_U64: u64 = 0;
const DS1_ID_U64: u64 = 1;
const DS2_ID_U64: u64 = 2;
const DS1_MANIFEST_HASH: &str = "0100000000000000000000000000000000000000000000000000000000000000";
const DS2_MANIFEST_HASH: &str = "0200000000000000000000000000000000000000000000000000000000000000";
const NEXUS_LANE_INDEX: u32 = 0;
const DS1_LANE_INDEX: u32 = 1;
const DS2_LANE_INDEX: u32 = 2;
const VALIDATORS_PER_LANE: usize = 4;
const LANE_VALIDATOR_COUNT: usize = VALIDATORS_PER_LANE * 3;
// Keep the global permissioned committee at exact revision-4 geometry while
// assigning only the first twelve peers to the three disjoint lane committees.
const TOTAL_PEERS: usize = 13;
const VALIDATOR_STAKE: u64 = 2_000;
const NEXUS_FEE_SEED_AMOUNT: u32 = 1_000_000;
const STATUS_WAIT_TIMEOUT: Duration = Duration::from_secs(45);
const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(200);
const ALICE_WRONG_INGRESS_INDEX: usize = VALIDATORS_PER_LANE * 2;
const BOB_WRONG_INGRESS_INDEX: usize = VALIDATORS_PER_LANE;
fn stake_asset_definition_id() -> AssetDefinitionId {
    nexus_fee_asset_definition_id()
}
fn stake_asset_id_literal() -> String {
    stake_asset_definition_id().to_string()
}
fn nexus_fee_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("universal", "universal").expect("fee asset domain"),
        "xor".parse().expect("fee asset name"),
    )
}
fn routing_probe_gas_account_id() -> AccountId {
    ALICE_ID.clone()
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ExpectedLaneValidatorBinding {
    validator: String,
    peer_id: String,
}
#[derive(Debug)]
struct RoutedJsonResponse {
    status: HttpStatusCode,
    body: JsonValue,
    body_text: String,
    routed_by: Option<String>,
    route_lane_id: Option<String>,
    route_dataspace_id: Option<String>,
}
#[derive(Debug)]
struct RoutedTransactionSubmitResponse {
    status: HttpStatusCode,
    receipt: Option<TransactionSubmissionReceipt>,
    body_text: String,
    routed_by: Option<String>,
    route_lane_id: Option<String>,
    route_dataspace_id: Option<String>,
}
fn validator_authority_account_for_peer(index: usize) -> AccountId {
    let keypair = KeyPair::try_from_seed(validator_authority_seed(index), Algorithm::Ed25519)
        .expect("fixture tx/query routing validator authority key");
    AccountId::new(keypair.public_key().clone())
}
fn validator_authority_seed(index: usize) -> Vec<u8> {
    let mut seed = vec![0_u8; 32];
    seed[0] = 0xC1;
    seed[1..9].copy_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
    seed
}
fn expected_lane_binding_for_peer(index: usize, peer_id: &PeerId) -> ExpectedLaneValidatorBinding {
    ExpectedLaneValidatorBinding {
        validator: validator_authority_account_for_peer(index).to_string(),
        peer_id: peer_id.to_string(),
    }
}
fn localnet_builder() -> NetworkBuilder {
    let gas_account_str = routing_probe_gas_account_id()
        .canonical_i105()
        .expect("canonical I105 gas account literal");
    NetworkBuilder::new()
        .with_peers(TOTAL_PEERS)
        .without_npos_genesis_bootstrap()
        .with_genesis_block(|topology, topology_entries| {
            let post_topology = npos_multilane_genesis_post_topology_transactions(
                topology.as_ref(),
                &topology_entries,
            );
            let mut genesis = unexecuted_genesis_factory_with_post_topology(
                npos_override_transactions(VALIDATORS_PER_LANE),
                post_topology,
                topology,
                topology_entries,
            );
            genesis
                .0
                .set_da_proof_policies(Some(multilane_da_proof_policy_bundle()));
            genesis
        })
        .with_config_layer(move |layer| {
            let mut lane_nexus = Table::new();
            lane_nexus.insert("index".into(), TomlValue::Integer(0));
            lane_nexus.insert("alias".into(), TomlValue::String("lane-nexus".to_owned()));
            lane_nexus.insert(
                "dataspace".into(),
                TomlValue::String(NEXUS_ALIAS.to_owned()),
            );
            lane_nexus.insert("visibility".into(), TomlValue::String("public".to_owned()));
            lane_nexus.insert("metadata".into(), TomlValue::Table(Table::new()));
            let mut lane_ds1 = Table::new();
            lane_ds1.insert("index".into(), TomlValue::Integer(1));
            lane_ds1.insert("alias".into(), TomlValue::String("lane-ds1".to_owned()));
            lane_ds1.insert("dataspace".into(), TomlValue::String(DS1_ALIAS.to_owned()));
            lane_ds1.insert(
                "visibility".into(),
                TomlValue::String("restricted".to_owned()),
            );
            lane_ds1.insert("metadata".into(), TomlValue::Table(Table::new()));
            let mut lane_ds2 = Table::new();
            lane_ds2.insert("index".into(), TomlValue::Integer(2));
            lane_ds2.insert("alias".into(), TomlValue::String("lane-ds2".to_owned()));
            lane_ds2.insert("dataspace".into(), TomlValue::String(DS2_ALIAS.to_owned()));
            lane_ds2.insert(
                "visibility".into(),
                TomlValue::String("restricted".to_owned()),
            );
            lane_ds2.insert("metadata".into(), TomlValue::Table(Table::new()));
            let mut ds_nexus = Table::new();
            ds_nexus.insert("alias".into(), TomlValue::String(NEXUS_ALIAS.to_owned()));
            ds_nexus.insert("id".into(), TomlValue::Integer(NEXUS_ID_U64 as i64));
            ds_nexus.insert(
                "description".into(),
                TomlValue::String("main nexus dataspace".to_owned()),
            );
            ds_nexus.insert("fault_tolerance".into(), TomlValue::Integer(1));
            let mut ds1 = Table::new();
            ds1.insert("alias".into(), TomlValue::String(DS1_ALIAS.to_owned()));
            ds1.insert("id".into(), TomlValue::Integer(DS1_ID_U64 as i64));
            ds1.insert(
                "manifest_hash".into(),
                TomlValue::String(DS1_MANIFEST_HASH.to_owned()),
            );
            ds1.insert(
                "description".into(),
                TomlValue::String("private dataspace one".to_owned()),
            );
            ds1.insert("fault_tolerance".into(), TomlValue::Integer(1));
            let mut ds2 = Table::new();
            ds2.insert("alias".into(), TomlValue::String(DS2_ALIAS.to_owned()));
            ds2.insert("id".into(), TomlValue::Integer(DS2_ID_U64 as i64));
            ds2.insert(
                "manifest_hash".into(),
                TomlValue::String(DS2_MANIFEST_HASH.to_owned()),
            );
            ds2.insert(
                "description".into(),
                TomlValue::String("private dataspace two".to_owned()),
            );
            ds2.insert("fault_tolerance".into(), TomlValue::Integer(1));
            let mut matcher_alice = Table::new();
            matcher_alice.insert("account".into(), TomlValue::String(ALICE_ID.to_string()));
            let mut rule_alice = Table::new();
            rule_alice.insert("lane".into(), TomlValue::Integer(1));
            rule_alice.insert("dataspace".into(), TomlValue::String(DS1_ALIAS.to_owned()));
            rule_alice.insert("matcher".into(), TomlValue::Table(matcher_alice));
            let mut matcher_bob = Table::new();
            matcher_bob.insert("account".into(), TomlValue::String(BOB_ID.to_string()));
            let mut rule_bob = Table::new();
            rule_bob.insert("lane".into(), TomlValue::Integer(2));
            rule_bob.insert("dataspace".into(), TomlValue::String(DS2_ALIAS.to_owned()));
            rule_bob.insert("matcher".into(), TomlValue::Table(matcher_bob));
            let mut policy = Table::new();
            policy.insert("default_lane".into(), TomlValue::Integer(0));
            policy.insert(
                "default_dataspace".into(),
                TomlValue::String(NEXUS_ALIAS.to_owned()),
            );
            policy.insert(
                "rules".into(),
                TomlValue::Array(vec![
                    TomlValue::Table(rule_alice),
                    TomlValue::Table(rule_bob),
                ]),
            );
            layer
                .write(["nexus", "lane_count"], 3_i64)
                .write(["norito", "allow_gpu_compression"], false)
                .write(
                    ["nexus", "lane_catalog"],
                    TomlValue::Array(vec![
                        TomlValue::Table(lane_nexus),
                        TomlValue::Table(lane_ds1),
                        TomlValue::Table(lane_ds2),
                    ]),
                )
                .write(
                    ["nexus", "dataspace_catalog"],
                    TomlValue::Array(vec![
                        TomlValue::Table(ds_nexus),
                        TomlValue::Table(ds1),
                        TomlValue::Table(ds2),
                    ]),
                )
                .write(["nexus", "routing_policy"], TomlValue::Table(policy))
                .write(
                    ["nexus", "staking", "restricted_validator_mode"],
                    "stake_elected",
                )
                .write(
                    ["nexus", "staking", "public_validator_mode"],
                    "stake_elected",
                )
                .write(
                    ["nexus", "staking", "stake_asset_id"],
                    stake_asset_id_literal(),
                )
                .write(
                    ["nexus", "staking", "stake_escrow_account_id"],
                    gas_account_str.clone(),
                )
                .write(
                    ["nexus", "staking", "slash_sink_account_id"],
                    gas_account_str.clone(),
                )
                .write(
                    ["nexus", "staking", "max_validators"],
                    VALIDATORS_PER_LANE as i64,
                );
        })
}
fn multilane_da_proof_policy_bundle() -> DaProofPolicyBundle {
    let lane_count = NonZeroU32::new(3).expect("lane count");
    let lanes = vec![
        ModelLaneConfig {
            id: LaneId::new(NEXUS_LANE_INDEX),
            dataspace_id: DataSpaceId::new(NEXUS_ID_U64),
            alias: "lane-nexus".to_owned(),
            visibility: LaneVisibility::Public,
            ..ModelLaneConfig::default()
        },
        ModelLaneConfig {
            id: LaneId::new(DS1_LANE_INDEX),
            dataspace_id: DataSpaceId::new(DS1_ID_U64),
            alias: "lane-ds1".to_owned(),
            visibility: LaneVisibility::Restricted,
            ..ModelLaneConfig::default()
        },
        ModelLaneConfig {
            id: LaneId::new(DS2_LANE_INDEX),
            dataspace_id: DataSpaceId::new(DS2_ID_U64),
            alias: "lane-ds2".to_owned(),
            visibility: LaneVisibility::Restricted,
            ..ModelLaneConfig::default()
        },
    ];
    let catalog = LaneCatalog::new(lane_count, lanes).expect("lane catalog");
    let lane_config = ActualLaneConfig::from_catalog(&catalog);
    proof_policy_bundle(&lane_config)
}
fn npos_multilane_genesis_post_topology_transactions(
    topology: &[PeerId],
    topology_entries: &[GenesisTopologyEntry],
) -> Vec<Vec<InstructionBox>> {
    assert_eq!(
        topology.len(),
        TOTAL_PEERS,
        "expected {TOTAL_PEERS} peers in genesis topology, got {}",
        topology.len()
    );
    let nexus_domain: DomainId = DomainId::try_new("nexus", "universal").expect("nexus domain");
    let universal_domain: DomainId =
        DomainId::try_new("universal", "universal").expect("universal domain");
    let ds1_domain: DomainId = DomainId::try_new("ds1", "universal").expect("ds1 domain");
    let ds2_domain: DomainId = DomainId::try_new("ds2", "universal").expect("ds2 domain");
    let stake_asset_id = stake_asset_definition_id();
    let fee_asset_id = nexus_fee_asset_definition_id();
    let ds1_asset_def = AssetDefinitionId::derive_from_components(
        DomainId::try_new("nexus", "universal").expect("asset definition domain"),
        "ds1coin".parse().expect("asset definition name"),
    );
    let ds2_asset_def = AssetDefinitionId::derive_from_components(
        DomainId::try_new("nexus", "universal").expect("asset definition domain"),
        "ds2coin".parse().expect("asset definition name"),
    );
    let mut bootstrap_tx = vec![
        Register::domain(Domain::new(nexus_domain.clone())).into(),
        Register::domain(Domain::new(universal_domain)).into(),
        Register::domain(Domain::new(ds1_domain)).into(),
        Register::domain(Domain::new(ds2_domain)).into(),
        Register::asset_definition({
            let __asset_definition_id = stake_asset_id.clone();
            AssetDefinition::new(
                __asset_definition_id.clone(),
                "XOR".to_owned(),
                NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .into(),
        Register::asset_definition({
            let __asset_definition_id = ds1_asset_def.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "ds1coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .into(),
        Register::asset_definition({
            let __asset_definition_id = ds2_asset_def.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "ds2coin".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        })
        .into(),
        Mint::asset_quantity(
            100_u32,
            AssetId::new(ds1_asset_def.clone(), ALICE_ID.clone()),
        )
        .into(),
        Mint::asset_quantity(
            NEXUS_FEE_SEED_AMOUNT,
            AssetId::new(fee_asset_id.clone(), ALICE_ID.clone()),
        )
        .into(),
        Mint::asset_quantity(
            NEXUS_FEE_SEED_AMOUNT,
            AssetId::new(fee_asset_id.clone(), BOB_ID.clone()),
        )
        .into(),
        Mint::asset_quantity(200_u32, AssetId::new(ds2_asset_def.clone(), BOB_ID.clone())).into(),
    ];
    bootstrap_tx.extend(genesis_participant_committee_key_instructions(
        topology_entries,
        &topology[VALIDATORS_PER_LANE..LANE_VALIDATOR_COUNT],
    ));
    for (index, peer) in topology.iter().take(LANE_VALIDATOR_COUNT).enumerate() {
        let lane_index = if index < VALIDATORS_PER_LANE {
            NEXUS_LANE_INDEX
        } else if index < VALIDATORS_PER_LANE * 2 {
            DS1_LANE_INDEX
        } else {
            DS2_LANE_INDEX
        };
        let lane_id = LaneId::new(lane_index);
        let validator_id = validator_authority_account_for_peer(index);
        bootstrap_tx.push(Register::account(Account::new(validator_id.clone())).into());
        bootstrap_tx.push(
            Mint::asset_quantity(
                VALIDATOR_STAKE,
                AssetId::new(stake_asset_id.clone(), validator_id.clone()),
            )
            .into(),
        );
        bootstrap_tx.push(
            Mint::asset_quantity(
                NEXUS_FEE_SEED_AMOUNT,
                AssetId::new(fee_asset_id.clone(), validator_id.clone()),
            )
            .into(),
        );
        bootstrap_tx.push(
            RegisterPublicLaneValidator::new(
                lane_id,
                validator_id.clone(),
                peer.clone(),
                validator_id.clone(),
                Quantity::from(VALIDATOR_STAKE),
                Metadata::default(),
                iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                    AssetId::new(stake_asset_id.clone(), validator_id.clone()),
                    AssetId::new(stake_asset_id.clone(), routing_probe_gas_account_id()),
                    Quantity::from(VALIDATOR_STAKE),
                ),
            )
            .into(),
        );
        bootstrap_tx.push(ActivatePublicLaneValidator::new(lane_id, validator_id).into());
    }
    vec![bootstrap_tx]
}
fn lane_validator_snapshot(
    snapshot: &JsonValue,
    context: &str,
) -> Result<(usize, BTreeSet<ExpectedLaneValidatorBinding>)> {
    let root = snapshot
        .as_object()
        .ok_or_else(|| eyre!("{context}: lane validator response is not an object"))?;
    let total = root
        .get("total")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| eyre!("{context}: lane validator response is missing total"))?;
    let items = root
        .get("items")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("{context}: lane validator response is missing items"))?;
    let mut active = BTreeSet::new();
    for item in items {
        let entry = item
            .as_object()
            .ok_or_else(|| eyre!("{context}: validator entry is not an object"))?;
        let validator = entry
            .get("validator")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| eyre!("{context}: validator entry missing validator literal"))?;
        let peer_id = entry
            .get("peer_id")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| eyre!("{context}: validator entry missing peer_id literal"))?;
        let status_type = entry
            .get("status")
            .and_then(JsonValue::as_object)
            .and_then(|status| status.get("type"))
            .and_then(JsonValue::as_str)
            .ok_or_else(|| eyre!("{context}: validator entry missing status.type"))?;
        if status_type == "Active" {
            active.insert(ExpectedLaneValidatorBinding {
                validator: validator.to_owned(),
                peer_id: peer_id.to_owned(),
            });
        }
    }
    Ok((usize::try_from(total).unwrap_or(usize::MAX), active))
}
fn wait_for_active_lane_validators(
    client: &Client,
    lane_id: LaneId,
    expected_active: &BTreeSet<ExpectedLaneValidatorBinding>,
    context: &str,
) -> Result<()> {
    let started = Instant::now();
    let mut last_total = 0usize;
    let mut last_active = BTreeSet::new();
    while started.elapsed() <= STATUS_WAIT_TIMEOUT {
        let snapshot = client
            .client()
            .get_public_lane_validators(lane_id)
            .map_err(|err| eyre!(err))?;
        let (total, active) = lane_validator_snapshot(&snapshot, context)?;
        last_total = total;
        last_active = active.clone();
        if total == expected_active.len() && active == *expected_active {
            return Ok(());
        }
        thread::sleep(STATUS_POLL_INTERVAL);
    }
    Err(eyre!(
        "{context}: timed out waiting for active validators on lane {lane_id}; expected total {} active {:?}, observed total {} active {:?}",
        expected_active.len(),
        expected_active,
        last_total,
        last_active
    ))
}
fn wait_for_height(client: &Client, target_height: u64, context: &str) -> Result<SumeragiStatus> {
    let started = Instant::now();
    let mut last_height = 0;
    let mut last_error: Option<String> = None;
    while started.elapsed() <= STATUS_WAIT_TIMEOUT {
        match client.client().get_sumeragi_status() {
            Ok(status) => {
                last_height = status.committed_height;
                if status.committed_height >= target_height {
                    return Ok(status);
                }
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
        thread::sleep(STATUS_POLL_INTERVAL);
    }
    let suffix = last_error
        .map(|err| format!("; last status query error: {err}"))
        .unwrap_or_default();
    Err(eyre!(
        "{context}: timed out waiting for block height >= {target_height}; last observed {last_height}{suffix}"
    ))
}
fn asset_balance(client: &Client, asset_id: &AssetId) -> Result<Quantity> {
    match client
        .client()
        .query_single(FindAssetById::new(asset_id.clone()))
    {
        Ok(asset) if asset.id() == asset_id => Ok(asset.value().clone()),
        Ok(_) => Err(eyre!("exact asset query returned a different asset")),
        Err(QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(
            FindError::Asset(missing),
        )))) if missing.as_ref() == asset_id => Ok(Quantity::zero()),
        Err(error) => Err(eyre!(error)),
    }
}
fn routed_header_string(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}
fn routed_response_context(
    status: HttpStatusCode,
    headers: &reqwest::header::HeaderMap,
    path_segments: &[String],
    query_pairs: &[(String, String)],
) -> String {
    let path = if path_segments.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", path_segments.join("/"))
    };
    let query = if query_pairs.is_empty() {
        String::new()
    } else {
        let encoded = query_pairs
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        format!("?{encoded}")
    };
    format!(
        "status={status}, path={path}{query}, routed_by={:?}, route_lane_id={:?}, route_dataspace_id={:?}",
        routed_header_string(headers, "x-iroha-routed-by"),
        routed_header_string(headers, "x-iroha-route-lane-id"),
        routed_header_string(headers, "x-iroha-route-dataspace-id"),
    )
}
fn routed_json_empty_body_is_transient(status: HttpStatusCode, body: &[u8]) -> bool {
    body.is_empty()
        && matches!(
            status,
            HttpStatusCode::REQUEST_TIMEOUT
                | HttpStatusCode::BAD_GATEWAY
                | HttpStatusCode::SERVICE_UNAVAILABLE
                | HttpStatusCode::GATEWAY_TIMEOUT
        )
}
fn routed_json_response_is_transient(response: &RoutedJsonResponse) -> bool {
    response.body.is_null()
        && routed_json_empty_body_is_transient(response.status, response.body_text.as_bytes())
}
fn routed_submit_response_is_transient(response: &RoutedTransactionSubmitResponse) -> bool {
    if routed_json_empty_body_is_transient(response.status, response.body_text.as_bytes()) {
        return true;
    }
    if response.status == HttpStatusCode::NOT_FOUND && response.body_text.is_empty() {
        return true;
    }
    matches!(
        response.status,
        HttpStatusCode::NOT_FOUND | HttpStatusCode::SERVICE_UNAVAILABLE
    ) && response.body_text.contains("route_unavailable")
}
fn add_client_headers(
    client: &Client,
    mut request: reqwest::RequestBuilder,
    include_content_type: bool,
    include_account_header: bool,
) -> reqwest::RequestBuilder {
    for (name, value) in client.client().headers() {
        if !include_content_type && name.eq_ignore_ascii_case("content-type") {
            continue;
        }
        if !include_account_header && name.eq_ignore_ascii_case("x-iroha-account") {
            continue;
        }
        request = request.header(name, value);
    }
    request
}
fn encode_versioned_signed_transaction(transaction: &SignedTransaction) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1);
    bytes.push(1);
    bytes.extend(norito::codec::encode_adaptive(transaction));
    bytes
}
fn routed_http_client() -> reqwest::Client {
    integration_tests::http::client_with_timeout(iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT)
}
async fn torii_json_get(
    client: &Client,
    path_segments: &[String],
    query_pairs: &[(String, String)],
) -> Result<RoutedJsonResponse> {
    let mut url = client.client().endpoint().clone();
    let torii_url_literal = url.to_string();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| eyre!("torii URL `{torii_url_literal}` cannot accept path segments"))?;
        segments.pop_if_empty();
        for segment in path_segments {
            segments.push(segment);
        }
    }
    if !query_pairs.is_empty() {
        let mut query = url.query_pairs_mut();
        for (key, value) in query_pairs {
            query.append_pair(key, value);
        }
    }
    let request = routed_http_client()
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    let response = add_client_headers(client, request, true, true)
        .send()
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?;
    let body_text = String::from_utf8_lossy(&body).into_owned();
    let response_context = routed_response_context(status, &headers, path_segments, query_pairs);
    let json_body = if routed_json_empty_body_is_transient(status, &body) {
        JsonValue::Null
    } else {
        norito::json::from_slice(&body)
            .wrap_err_with(|| format!("decode JSON body ({response_context}): {body_text}"))?
    };
    Ok(RoutedJsonResponse {
        status,
        body: json_body,
        body_text,
        routed_by: routed_header_string(&headers, "x-iroha-routed-by"),
        route_lane_id: routed_header_string(&headers, "x-iroha-route-lane-id"),
        route_dataspace_id: routed_header_string(&headers, "x-iroha-route-dataspace-id"),
    })
}
async fn torii_json_get_as_account(
    client: &Client,
    account: &AccountId,
    path_segments: &[String],
    query_pairs: &[(String, String)],
) -> Result<RoutedJsonResponse> {
    let mut url = client.client().endpoint().clone();
    let torii_url_literal = url.to_string();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| eyre!("torii URL `{torii_url_literal}` cannot accept path segments"))?;
        segments.pop_if_empty();
        for segment in path_segments {
            segments.push(segment);
        }
    }
    if !query_pairs.is_empty() {
        let mut query = url.query_pairs_mut();
        for (key, value) in query_pairs {
            query.append_pair(key, value);
        }
    }
    let uri: Uri = url
        .as_str()
        .parse()
        .wrap_err("parse canonical app-api URI")?;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .wrap_err("derive canonical auth timestamp")?
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let nonce = format!("nexus-app-api-{timestamp_ms}-{}", Hash::new(url.as_str()));
    let message = canonical_network_request_signature_message(
        client.client().network_id(),
        &Method::GET,
        &uri,
        &[],
        timestamp_ms,
        &nonce,
    )
    .wrap_err("construct canonical app-api request")?;
    let signature = Signature::try_new(client.client().key_pair().private_key(), &message)
        .wrap_err("sign canonical app-api request")?;
    let response = routed_http_client()
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(HEADER_ACCOUNT, account.to_canonical_hex()?)
        .header(HEADER_SIGNATURE, signature_header_value(&signature)?)
        .header(HEADER_TIMESTAMP_MS, timestamp_ms.to_string())
        .header(HEADER_NONCE, nonce)
        .send()
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?;
    let body_text = String::from_utf8_lossy(&body).into_owned();
    let response_context = routed_response_context(status, &headers, path_segments, query_pairs);
    let json_body = if routed_json_empty_body_is_transient(status, &body) {
        JsonValue::Null
    } else {
        norito::json::from_slice(&body)
            .wrap_err_with(|| format!("decode JSON body ({response_context}): {body_text}"))?
    };
    Ok(RoutedJsonResponse {
        status,
        body: json_body,
        body_text,
        routed_by: routed_header_string(&headers, "x-iroha-routed-by"),
        route_lane_id: routed_header_string(&headers, "x-iroha-route-lane-id"),
        route_dataspace_id: routed_header_string(&headers, "x-iroha-route-dataspace-id"),
    })
}
async fn wait_for_torii_json_get(
    client: &Client,
    path_segments: &[String],
    query_pairs: &[(String, String)],
    context: &str,
) -> Result<RoutedJsonResponse> {
    let started = Instant::now();
    let mut last_error: Option<String> = None;
    while started.elapsed() <= STATUS_WAIT_TIMEOUT {
        match torii_json_get(client, path_segments, query_pairs).await {
            Ok(response) if !routed_json_response_is_transient(&response) => return Ok(response),
            Ok(response) => {
                last_error = Some(format!(
                    "transient routed JSON response status {} body `{}`",
                    response.status, response.body_text
                ));
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
        sleep(STATUS_POLL_INTERVAL).await;
    }
    let suffix = last_error
        .map(|err| format!("; last routed JSON error: {err}"))
        .unwrap_or_default();
    Err(eyre!(
        "{context}: timed out waiting for routed JSON response{suffix}"
    ))
}
async fn wait_for_torii_json_get_as_account(
    client: &Client,
    account: &AccountId,
    path_segments: &[String],
    query_pairs: &[(String, String)],
    context: &str,
) -> Result<RoutedJsonResponse> {
    let started = Instant::now();
    let mut last_error: Option<String> = None;
    while started.elapsed() <= STATUS_WAIT_TIMEOUT {
        match torii_json_get_as_account(client, account, path_segments, query_pairs).await {
            Ok(response) if !routed_json_response_is_transient(&response) => return Ok(response),
            Ok(response) => {
                last_error = Some(format!(
                    "transient routed JSON response status {} body `{}`",
                    response.status, response.body_text
                ));
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
        sleep(STATUS_POLL_INTERVAL).await;
    }
    let suffix = last_error
        .map(|err| format!("; last routed JSON error: {err}"))
        .unwrap_or_default();
    Err(eyre!(
        "{context}: timed out waiting for routed JSON response{suffix}"
    ))
}
async fn submit_transaction_raw(
    client: &Client,
    transaction: &SignedTransaction,
) -> Result<RoutedTransactionSubmitResponse> {
    let request = routed_http_client()
        .post(
            client
                .client()
                .endpoint()
                .join("v1/pipeline/transactions")
                .wrap_err("compose /v1/pipeline/transactions URL")?,
        )
        .header(reqwest::header::CONTENT_TYPE, "application/x-norito")
        .body(encode_versioned_signed_transaction(transaction));
    let response = add_client_headers(client, request, false, true)
        .send()
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?;
    let body_text = String::from_utf8_lossy(&body).into_owned();
    let receipt = if status == HttpStatusCode::ACCEPTED {
        Some(decode_from_bytes::<TransactionSubmissionReceipt>(&body)?)
    } else {
        None
    };
    Ok(RoutedTransactionSubmitResponse {
        status,
        receipt,
        body_text,
        routed_by: routed_header_string(&headers, "x-iroha-routed-by"),
        route_lane_id: routed_header_string(&headers, "x-iroha-route-lane-id"),
        route_dataspace_id: routed_header_string(&headers, "x-iroha-route-dataspace-id"),
    })
}
async fn submit_transaction_and_expect_route(
    submitter: &Client,
    _confirmation_client: &Client,
    transaction: &SignedTransaction,
    expected_lane_id: LaneId,
    expected_dataspace_id: DataSpaceId,
    context: &str,
) -> Result<TransactionSubmissionReceipt> {
    let started = Instant::now();
    let response = loop {
        let response = submit_transaction_raw(submitter, transaction).await?;
        if response.status == HttpStatusCode::ACCEPTED
            || !routed_submit_response_is_transient(&response)
            || started.elapsed() >= STATUS_WAIT_TIMEOUT
        {
            break response;
        }
        sleep(STATUS_POLL_INTERVAL).await;
    };
    ensure!(
        response.status == HttpStatusCode::ACCEPTED,
        "{context}: expected 202 Accepted, observed {} body `{}`",
        response.status,
        response.body_text
    );
    ensure!(
        response.routed_by.as_deref() == Some("proxy"),
        "{context}: expected proxy routing, observed {:?}",
        response.routed_by
    );
    ensure!(
        response.route_lane_id.as_deref() == Some(expected_lane_id.as_u32().to_string().as_str()),
        "{context}: expected routed lane {}, observed {:?}",
        expected_lane_id.as_u32(),
        response.route_lane_id
    );
    ensure!(
        response.route_dataspace_id.as_deref()
            == Some(expected_dataspace_id.as_u64().to_string().as_str()),
        "{context}: expected routed dataspace {}, observed {:?}",
        expected_dataspace_id.as_u64(),
        response.route_dataspace_id
    );
    let receipt = response
        .receipt
        .ok_or_else(|| eyre!("{context}: missing transaction submission receipt"))?;
    Ok(receipt)
}
fn expect_proxy_route_headers(
    response: &RoutedJsonResponse,
    expected_lane_id: LaneId,
    expected_dataspace_id: DataSpaceId,
    context: &str,
) -> Result<()> {
    ensure!(
        response.routed_by.as_deref() == Some("proxy"),
        "{context}: expected proxied read, observed {:?}",
        response.routed_by
    );
    ensure!(
        response.route_lane_id.as_deref() == Some(expected_lane_id.as_u32().to_string().as_str()),
        "{context}: expected routed lane {}, observed {:?}",
        expected_lane_id.as_u32(),
        response.route_lane_id
    );
    ensure!(
        response.route_dataspace_id.as_deref()
            == Some(expected_dataspace_id.as_u64().to_string().as_str()),
        "{context}: expected routed dataspace {}, observed {:?}",
        expected_dataspace_id.as_u64(),
        response.route_dataspace_id
    );
    Ok(())
}
fn expect_proxy_fanout_headers(response: &RoutedJsonResponse, context: &str) -> Result<()> {
    ensure!(
        response.routed_by.as_deref() == Some("proxy"),
        "{context}: expected proxied fanout read, observed {:?}",
        response.routed_by
    );
    ensure!(
        response.route_lane_id.is_none(),
        "{context}: fanout response should not expose singular route lane {:?}",
        response.route_lane_id
    );
    ensure!(
        response.route_dataspace_id.is_none(),
        "{context}: fanout response should not expose singular route dataspace {:?}",
        response.route_dataspace_id
    );
    Ok(())
}
fn permission_response_contains(
    body: &JsonValue,
    permission_name: &str,
    payload_matches: impl Fn(&JsonValue) -> bool,
    context: &str,
) -> Result<bool> {
    let items = body
        .get("items")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("{context}: permission response missing items array"))?;
    Ok(items.iter().any(|item| {
        item.get("name").and_then(JsonValue::as_str) == Some(permission_name)
            && item.get("payload").is_some_and(&payload_matches)
    }))
}
fn manifest_response_contains_status(
    body: &JsonValue,
    dataspace_id: DataSpaceId,
    expected_status: &str,
    context: &str,
) -> Result<bool> {
    let manifests = body
        .get("manifests")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("{context}: manifest response missing manifests array"))?;
    Ok(manifests.iter().any(|record| {
        record.get("dataspace_id").and_then(JsonValue::as_u64) == Some(dataspace_id.as_u64())
            && record.get("status").and_then(JsonValue::as_str) == Some(expected_status)
    }))
}
fn manifest_response_contains_dataspace(
    body: &JsonValue,
    dataspace_id: DataSpaceId,
    context: &str,
) -> Result<bool> {
    let manifests = body
        .get("manifests")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("{context}: manifest response missing manifests array"))?;
    Ok(manifests.iter().any(|record| {
        record.get("dataspace_id").and_then(JsonValue::as_u64) == Some(dataspace_id.as_u64())
    }))
}
async fn wait_for_manifest_api_absence(
    client: &Client,
    uaid_literal: &str,
    dataspace_id: DataSpaceId,
    expected_lane_id: LaneId,
    context: &str,
) -> Result<()> {
    let started = Instant::now();
    let mut last_body = String::new();
    let mut last_error: Option<String> = None;
    while started.elapsed() <= STATUS_WAIT_TIMEOUT {
        match torii_json_get(
            client,
            &[
                "v1".to_owned(),
                "space-directory".to_owned(),
                "uaids".to_owned(),
                uaid_literal.to_owned(),
                "manifests".to_owned(),
            ],
            &[("dataspace".to_owned(), dataspace_id.as_u64().to_string())],
        )
        .await
        {
            Ok(response) => {
                last_body = response.body_text.clone();
                match response.status {
                    HttpStatusCode::OK => {
                        expect_proxy_route_headers(
                            &response,
                            expected_lane_id,
                            dataspace_id,
                            context,
                        )?;
                        if !manifest_response_contains_dataspace(
                            &response.body,
                            dataspace_id,
                            context,
                        )? {
                            return Ok(());
                        }
                        last_error = None;
                    }
                    HttpStatusCode::NOT_FOUND => {
                        if let Some(lane_id) = response.route_lane_id.as_deref() {
                            ensure!(
                                lane_id == expected_lane_id.as_u32().to_string(),
                                "{context}: manifests absence reported unexpected lane {lane_id}"
                            );
                        }
                        if let Some(observed_dataspace_id) = response.route_dataspace_id.as_deref()
                        {
                            ensure!(
                                observed_dataspace_id == dataspace_id.as_u64().to_string(),
                                "{context}: manifests absence reported unexpected dataspace {observed_dataspace_id}"
                            );
                        }
                        return Ok(());
                    }
                    _ => {
                        last_error = Some(format!(
                            "unexpected status {} body `{}`",
                            response.status, response.body_text
                        ));
                    }
                }
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
        tokio::time::sleep(STATUS_POLL_INTERVAL).await;
    }
    let suffix = last_error
        .map(|err| format!("; last manifests API error: {err}"))
        .unwrap_or_default();
    Err(eyre!(
        "{context}: timed out waiting for manifest absence on UAID {uaid_literal}; last body `{last_body}`{suffix}"
    ))
}
fn account_assets_response_contains(
    body: &JsonValue,
    asset_definition_id: &AssetDefinitionId,
    context: &str,
) -> Result<bool> {
    let expected = asset_definition_id.to_string();
    let items = body
        .get("items")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| eyre!("{context}: account assets response missing items array"))?;
    Ok(items
        .iter()
        .any(|item| item.get("asset").and_then(JsonValue::as_str) == Some(expected.as_str())))
}
#[test]
fn tx_query_cross_dataspace_routing_genesis_preexecution_smoke() {
    let _guard = sandbox::serial_guard();
    let _network = localnet_builder().build();
}
#[test]
fn wrong_dataspace_ingress_routes_transactions_and_queries_across_permission_models() -> Result<()>
{
    let context = stringify!(
        wrong_dataspace_ingress_routes_transactions_and_queries_across_permission_models
    );
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(localnet_builder(), context)?
    else {
        return Ok(());
    };
    let alice = network.client();
    let bob = network
        .peer()
        .client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone());
    let peers = network.peers();
    ensure!(
        peers.len() == TOTAL_PEERS,
        "expected {TOTAL_PEERS} peers for cross-dataspace topology, got {}",
        peers.len()
    );
    let expected_nexus_validators: BTreeSet<_> = peers
        .iter()
        .enumerate()
        .take(VALIDATORS_PER_LANE)
        .map(|(index, peer)| expected_lane_binding_for_peer(index, &peer.id()))
        .collect();
    let expected_ds1_validators: BTreeSet<_> = peers
        .iter()
        .enumerate()
        .skip(VALIDATORS_PER_LANE)
        .take(VALIDATORS_PER_LANE)
        .map(|(index, peer)| expected_lane_binding_for_peer(index, &peer.id()))
        .collect();
    let expected_ds2_validators: BTreeSet<_> = peers
        .iter()
        .enumerate()
        .skip(VALIDATORS_PER_LANE * 2)
        .take(VALIDATORS_PER_LANE)
        .map(|(index, peer)| expected_lane_binding_for_peer(index, &peer.id()))
        .collect();
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(NEXUS_LANE_INDEX),
        &expected_nexus_validators,
        "nexus lane validator activation",
    )?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS1_LANE_INDEX),
        &expected_ds1_validators,
        "ds1 lane validator activation",
    )?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS2_LANE_INDEX),
        &expected_ds2_validators,
        "ds2 lane validator activation",
    )?;
    let lane_sync_height = alice
        .client()
        .get_sumeragi_status()
        .map_err(|err| eyre!(err))?
        .committed_height;
    wait_for_height(
        &bob,
        lane_sync_height,
        "lane validator activation propagation on bob",
    )?;
    ensure!(
        (VALIDATORS_PER_LANE * 2..LANE_VALIDATOR_COUNT).contains(&ALICE_WRONG_INGRESS_INDEX),
        "alice wrong-dataspace ingress index must point into the ds2 lane"
    );
    ensure!(
        (VALIDATORS_PER_LANE..VALIDATORS_PER_LANE * 2).contains(&BOB_WRONG_INGRESS_INDEX),
        "bob wrong-dataspace ingress index must point into the ds1 lane"
    );
    let alice_via_ds2 =
        peers[ALICE_WRONG_INGRESS_INDEX].client_for(&ALICE_ID, ALICE_KEYPAIR.private_key().clone());
    let alice_on_ds1 =
        peers[BOB_WRONG_INGRESS_INDEX].client_for(&ALICE_ID, ALICE_KEYPAIR.private_key().clone());
    let alice_on_ds2 =
        peers[ALICE_WRONG_INGRESS_INDEX].client_for(&ALICE_ID, ALICE_KEYPAIR.private_key().clone());
    let bob_via_ds1 =
        peers[BOB_WRONG_INGRESS_INDEX].client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone());
    let bob_on_ds2 =
        peers[ALICE_WRONG_INGRESS_INDEX].client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone());
    wait_for_height(
        &alice_via_ds2,
        lane_sync_height,
        "lane validator activation propagation on alice ds2 ingress",
    )?;
    wait_for_height(
        &alice_on_ds1,
        lane_sync_height,
        "lane validator activation propagation on alice ds1 authoritative client",
    )?;
    wait_for_height(
        &alice_on_ds2,
        lane_sync_height,
        "lane validator activation propagation on alice ds2 authoritative client",
    )?;
    wait_for_height(
        &bob_via_ds1,
        lane_sync_height,
        "lane validator activation propagation on bob ds1 ingress",
    )?;
    wait_for_height(
        &bob_on_ds2,
        lane_sync_height,
        "lane validator activation propagation on bob ds2 authoritative client",
    )?;
    let ds1_lane_id = LaneId::new(DS1_LANE_INDEX);
    let ds2_lane_id = LaneId::new(DS2_LANE_INDEX);
    let ds1_dataspace_id = DataSpaceId::new(DS1_ID_U64);
    let ds2_dataspace_id = DataSpaceId::new(DS2_ID_U64);
    let ds1_asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("nexus", "universal").expect("asset definition domain"),
        "ds1coin".parse().expect("asset definition name"),
    );
    let ds2_asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("nexus", "universal").expect("asset definition domain"),
        "ds2coin".parse().expect("asset definition name"),
    );
    let alice_ds1_asset = AssetId::new(ds1_asset_definition_id.clone(), ALICE_ID.clone());
    let bob_ds2_asset = AssetId::new(ds2_asset_definition_id.clone(), BOB_ID.clone());
    rt.block_on(async {
        let alice_probe = {
            let account = alice_via_ds2.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    [InstructionBox::from(Log::new(
                        Level::INFO,
                        "wrong ingress route probe ds1".to_owned(),
                    ))],
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build integration-test transaction");
        submit_transaction_and_expect_route(
            &alice_via_ds2,
            &alice_on_ds1,
            &alice_probe,
            ds1_lane_id,
            ds1_dataspace_id,
            "alice tx via ds2 should route to ds1",
        )
        .await?;
        let bob_probe = {
            let account = bob_via_ds1.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    [InstructionBox::from(Log::new(
                        Level::INFO,
                        "wrong ingress route probe ds2".to_owned(),
                    ))],
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build integration-test transaction");
        submit_transaction_and_expect_route(
            &bob_via_ds1,
            &bob_on_ds2,
            &bob_probe,
            ds2_lane_id,
            ds2_dataspace_id,
            "bob tx via ds1 should route to ds2",
        )
        .await?;
        Ok::<(), eyre::Report>(())
    })?;
    ensure!(
        asset_balance(&alice_via_ds2, &alice_ds1_asset)? == Quantity::from(100_u32),
        "alice signed query through ds2 ingress did not route to ds1"
    );
    ensure!(
        asset_balance(&bob_via_ds1, &bob_ds2_asset)? == Quantity::from(200_u32),
        "bob signed query through ds1 ingress did not route to ds2"
    );
    let alice_account = rt.block_on(wait_for_torii_json_get(
        &alice_via_ds2,
        &["v1".to_owned(), "accounts".to_owned(), ALICE_ID.to_string()],
        &[],
        "alice account GET through ds2 ingress",
    ))?;
    ensure!(
        alice_account.status == HttpStatusCode::OK,
        "alice account GET through ds2 ingress failed with {} body `{}`",
        alice_account.status,
        alice_account.body_text
    );
    expect_proxy_fanout_headers(
        &alice_account,
        "alice account GET through ds2 ingress should fan out globally",
    )?;
    ensure!(
        alice_account
            .body
            .get("account_id")
            .and_then(JsonValue::as_str)
            == Some(ALICE_ID.to_string().as_str()),
        "alice account GET through ds2 ingress did not return alice's canonical account id"
    );
    let alice_assets = rt.block_on(wait_for_torii_json_get_as_account(
        &alice_via_ds2,
        &ALICE_ID,
        &[
            "v1".to_owned(),
            "accounts".to_owned(),
            ALICE_ID.to_string(),
            "assets".to_owned(),
        ],
        &[],
        "alice assets query through ds2 ingress",
    ))?;
    ensure!(
        alice_assets.status == HttpStatusCode::OK,
        "alice assets query through ds2 ingress failed with {} body `{}`",
        alice_assets.status,
        alice_assets.body_text
    );
    expect_proxy_fanout_headers(&alice_assets, "alice assets query through ds2 ingress")?;
    ensure!(
        account_assets_response_contains(
            &alice_assets.body,
            &ds1_asset_definition_id,
            "alice assets query",
        )?,
        "alice assets query through ds2 ingress did not include ds1 asset definition"
    );
    let bob_assets = rt.block_on(wait_for_torii_json_get_as_account(
        &bob_via_ds1,
        &BOB_ID,
        &[
            "v1".to_owned(),
            "accounts".to_owned(),
            BOB_ID.to_string(),
            "assets".to_owned(),
        ],
        &[],
        "bob assets query through ds1 ingress",
    ))?;
    ensure!(
        bob_assets.status == HttpStatusCode::OK,
        "bob assets query through ds1 ingress failed with {} body `{}`",
        bob_assets.status,
        bob_assets.body_text
    );
    expect_proxy_fanout_headers(&bob_assets, "bob assets query through ds1 ingress")?;
    ensure!(
        account_assets_response_contains(
            &bob_assets.body,
            &ds2_asset_definition_id,
            "bob assets query",
        )?,
        "bob assets query through ds1 ingress did not include ds2 asset definition"
    );
    let alice_assets_hidden_from_bob = rt.block_on(wait_for_torii_json_get_as_account(
        &bob_via_ds1,
        &BOB_ID,
        &[
            "v1".to_owned(),
            "accounts".to_owned(),
            ALICE_ID.to_string(),
            "assets".to_owned(),
        ],
        &[],
        "alice assets query as bob through ds1 ingress",
    ))?;
    ensure!(
        alice_assets_hidden_from_bob.status == HttpStatusCode::OK,
        "alice assets query as bob through ds1 ingress failed with {} body `{}`",
        alice_assets_hidden_from_bob.status,
        alice_assets_hidden_from_bob.body_text
    );
    expect_proxy_fanout_headers(
        &alice_assets_hidden_from_bob,
        "alice assets query as bob through ds1 ingress",
    )?;
    let manifest_uaid =
        UniversalAccountId::from_hash(Hash::new(b"wrong-ingress-ds2-manifest-routing"));
    let manifest_uaid_literal = manifest_uaid.to_string();
    let ds2_manifest = AssetPermissionManifest {
        version: ManifestVersion::V1,
        uaid: manifest_uaid,
        dataspace: ds2_dataspace_id,
        issued_ms: 1,
        activation_epoch: 1,
        expiry_epoch: None,
        entries: vec![ManifestEntry {
            scope: CapabilityScope {
                dataspace: Some(ds2_dataspace_id),
                program: None,
                method: None,
                asset: None,
                role: None,
            },
            effect: ManifestEffect::Allow(Allowance {
                max_amount: Some(Quantity::from(1_u32)),
                window: AllowanceWindow::PerDay,
            }),
            notes: Some("wrong ingress manifest routing regression".to_owned()),
        }],
    };
    let manifests_before = rt.block_on(wait_for_torii_json_get(
        &bob_via_ds1,
        &[
            "v1".to_owned(),
            "space-directory".to_owned(),
            "uaids".to_owned(),
            manifest_uaid_literal.clone(),
            "manifests".to_owned(),
        ],
        &[(
            "dataspace".to_owned(),
            ds2_dataspace_id.as_u64().to_string(),
        )],
        "initial manifests read through ds1 ingress",
    ))?;
    ensure!(
        manifests_before.status == HttpStatusCode::OK,
        "initial manifests read through ds1 ingress failed with {} body `{}`",
        manifests_before.status,
        manifests_before.body_text
    );
    expect_proxy_route_headers(
        &manifests_before,
        ds2_lane_id,
        ds2_dataspace_id,
        "initial ds2 manifest read through ds1 ingress",
    )?;
    ensure!(
        !manifest_response_contains_status(
            &manifests_before.body,
            ds2_dataspace_id,
            "Active",
            "initial ds2 manifest read",
        )?,
        "manifest should not exist before publish"
    );
    let bob_manifest_permissions_api_before = rt.block_on(wait_for_torii_json_get_as_account(
        &bob_via_ds1,
        &BOB_ID,
        &[
            "v1".to_owned(),
            "accounts".to_owned(),
            BOB_ID.to_string(),
            "permissions".to_owned(),
        ],
        &[],
        "bob manifest permissions query through ds1 ingress",
    ))?;
    ensure!(
        bob_manifest_permissions_api_before.status == HttpStatusCode::OK,
        "bob manifest permissions query through ds1 ingress failed with {} body `{}`",
        bob_manifest_permissions_api_before.status,
        bob_manifest_permissions_api_before.body_text
    );
    expect_proxy_fanout_headers(
        &bob_manifest_permissions_api_before,
        "bob manifest permissions query before grant",
    )?;
    ensure!(
        !permission_response_contains(
            &bob_manifest_permissions_api_before.body,
            "CanPublishSpaceDirectoryManifest",
            |payload| {
                payload.get("dataspace").and_then(JsonValue::as_u64)
                    == Some(ds2_dataspace_id.as_u64())
            },
            "bob manifest permissions app api before grant",
        )?,
        "bob should not expose ds2 manifest publish permission before grant"
    );
    let unauthorized_publish_tx = {
        let account = bob_via_ds1.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [InstructionBox::from(PublishSpaceDirectoryManifest {
                    manifest: ds2_manifest.clone(),
                })],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    rt.block_on(submit_transaction_and_expect_route(
        &bob_via_ds1,
        &bob_on_ds2,
        &unauthorized_publish_tx,
        ds2_lane_id,
        ds2_dataspace_id,
        "bob unauthorized manifest publish via ds1 ingress should reject on ds2",
    ))?;
    rt.block_on(wait_for_manifest_api_absence(
        &bob_via_ds1,
        &manifest_uaid_literal,
        ds2_dataspace_id,
        ds2_lane_id,
        "manifest must remain absent after unauthorized publish through wrong ingress",
    ))?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::{
        ALICE_ID, ALICE_KEYPAIR, AccountId, Algorithm, AssetDefinitionId, BlockHeader, DS1_ID_U64,
        DS1_LANE_INDEX, DS1_MANIFEST_HASH, DS2_ID_U64, DS2_LANE_INDEX, DS2_MANIFEST_HASH, DomainId,
        ExpectedLaneValidatorBinding, Hash, KeyPair, LANE_VALIDATOR_COUNT, Level, Log, NEXUS_ALIAS,
        NEXUS_ID_U64, NEXUS_LANE_INDEX, NetworkId, RegisterConsensusKey,
        RegisterPublicLaneValidator, RoutedJsonResponse, RoutedTransactionSubmitResponse,
        SignedTransaction, TOTAL_PEERS, VALIDATORS_PER_LANE, account_assets_response_contains,
        derive_committee_key_id, encode_versioned_signed_transaction, expect_proxy_fanout_headers,
        expect_proxy_route_headers, expected_lane_binding_for_peer, lane_validator_snapshot,
        manifest_response_contains_dataspace, manifest_response_contains_status,
        multilane_da_proof_policy_bundle, nexus_fee_asset_definition_id,
        npos_multilane_genesis_post_topology_transactions, permission_response_contains,
        routed_header_string, routed_json_empty_body_is_transient,
        routed_json_response_is_transient, routed_response_context, routing_probe_gas_account_id,
        stake_asset_definition_id, stake_asset_id_literal, validator_authority_account_for_peer,
        validator_authority_seed,
    };
    use iroha::data_model::{
        da::commitment::{DaProofPolicyBundle, DaProofScheme},
        transaction::TransactionBuilder,
    };
    use iroha_model_base::peer::PeerId;
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use norito::{core::DecodeFromSlice, json::Value as JsonValue};
    use reqwest::{
        StatusCode as HttpStatusCode,
        header::{HeaderMap, HeaderValue},
    };
    use std::panic;
    fn routed_json_response(
        status: HttpStatusCode,
        body: JsonValue,
        body_text: &str,
    ) -> RoutedJsonResponse {
        RoutedJsonResponse {
            status,
            body,
            body_text: body_text.to_owned(),
            routed_by: None,
            route_lane_id: None,
            route_dataspace_id: None,
        }
    }
    fn routed_json_response_with_route(
        routed_by: Option<&str>,
        route_lane_id: Option<&str>,
        route_dataspace_id: Option<&str>,
    ) -> RoutedJsonResponse {
        RoutedJsonResponse {
            status: HttpStatusCode::OK,
            body: JsonValue::Null,
            body_text: String::new(),
            routed_by: routed_by.map(ToOwned::to_owned),
            route_lane_id: route_lane_id.map(ToOwned::to_owned),
            route_dataspace_id: route_dataspace_id.map(ToOwned::to_owned),
        }
    }
    fn ds2_asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("nexus", "universal").expect("asset domain"),
            "ds2coin".parse().expect("asset name"),
        )
    }
    fn deterministic_genesis_topology(
        peer_count: usize,
    ) -> (Vec<PeerId>, Vec<iroha_genesis::GenesisTopologyEntry>) {
        let entries = (0..peer_count)
            .map(|index| {
                let mut seed = vec![0_u8; 32];
                seed[0] = 0xE2;
                seed[1..9].copy_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
                let key_pair = KeyPair::try_from_seed(seed, Algorithm::BlsNormal)
                    .expect("fixture tx/query routing genesis peer key");
                iroha_genesis::GenesisTopologyEntry::new(
                    PeerId::new(key_pair.public_key().clone()),
                    iroha_crypto::bls_normal_pop_prove(key_pair.private_key())
                        .expect("fixture tx/query routing genesis peer PoP"),
                )
            })
            .collect::<Vec<_>>();
        let topology = entries.iter().map(|entry| entry.peer.clone()).collect();
        (topology, entries)
    }
    fn decode_manifest_hash_fixture(raw: &str) -> [u8; 32] {
        assert_eq!(raw.len(), 64);
        let mut hash = [0_u8; 32];
        for (idx, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk).expect("hex pair");
            hash[idx] = u8::from_str_radix(pair, 16).expect("manifest hash hex");
        }
        hash
    }
    #[test]
    fn dataspace_fixture_manifest_hashes_derive_config_ids() {
        let ds1_hash = decode_manifest_hash_fixture(DS1_MANIFEST_HASH);
        let ds2_hash = decode_manifest_hash_fixture(DS2_MANIFEST_HASH);
        assert_eq!(NEXUS_ALIAS, "universal");
        assert_eq!(NEXUS_ID_U64, DataSpaceId::UNIVERSAL.as_u64());
        assert_eq!(DataSpaceId::from_hash(&ds1_hash).as_u64(), DS1_ID_U64);
        assert_eq!(DataSpaceId::from_hash(&ds2_hash).as_u64(), DS2_ID_U64);
        assert_ne!(DataSpaceId::from_hash(&ds1_hash), DataSpaceId::UNIVERSAL);
        assert_ne!(DataSpaceId::from_hash(&ds2_hash), DataSpaceId::UNIVERSAL);
    }
    #[test]
    fn fixture_asset_helpers_use_one_real_network_xor() {
        let stake_definition_id = stake_asset_definition_id();
        let fee_definition_id = nexus_fee_asset_definition_id();
        assert_eq!(stake_asset_id_literal(), stake_definition_id.to_string());
        assert_eq!(stake_definition_id, fee_definition_id);
        assert_eq!(
            stake_definition_id.to_string(),
            "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
        );
    }
    #[test]
    fn multilane_da_policy_bundle_matches_wrong_ingress_topology() {
        let bundle = multilane_da_proof_policy_bundle();
        let expected_hash = DaProofPolicyBundle::new(bundle.policies().to_vec()).policy_hash();
        assert_eq!(bundle.version(), DaProofPolicyBundle::VERSION_V1);
        assert_eq!(bundle.policy_hash(), expected_hash);
        assert_eq!(bundle.policies().len(), 3);
        assert_eq!(bundle.policies()[0].lane_id.as_u32(), NEXUS_LANE_INDEX);
        assert_eq!(bundle.policies()[0].dataspace_id.as_u64(), NEXUS_ID_U64);
        assert_eq!(bundle.policies()[0].alias, "lane-nexus");
        assert_eq!(
            bundle.policies()[0].proof_scheme,
            DaProofScheme::MerkleSha256
        );
        assert_eq!(bundle.policies()[1].lane_id.as_u32(), DS1_LANE_INDEX);
        assert_eq!(bundle.policies()[1].dataspace_id.as_u64(), DS1_ID_U64);
        assert_eq!(bundle.policies()[1].alias, "lane-ds1");
        assert_eq!(bundle.policies()[2].lane_id.as_u32(), DS2_LANE_INDEX);
        assert_eq!(bundle.policies()[2].dataspace_id.as_u64(), DS2_ID_U64);
        assert_eq!(bundle.policies()[2].alias, "lane-ds2");
    }
    #[test]
    fn multilane_da_policy_bundle_hash_changes_when_policy_order_changes() {
        let bundle = multilane_da_proof_policy_bundle();
        let mut reversed_policies = bundle.policies().to_vec();
        reversed_policies.reverse();
        let reversed_hash = DaProofPolicyBundle::new(reversed_policies).policy_hash();
        assert_eq!(bundle, multilane_da_proof_policy_bundle());
        assert_ne!(bundle.policy_hash(), reversed_hash);
    }
    #[test]
    fn genesis_post_topology_builder_requires_full_wrong_ingress_roster() {
        let (topology, entries) = deterministic_genesis_topology(TOTAL_PEERS);
        let transactions = npos_multilane_genesis_post_topology_transactions(&topology, &entries);
        assert_eq!(transactions.len(), 1);
        assert_eq!(
            transactions[0].len(),
            11 + LANE_VALIDATOR_COUNT * 5 + (LANE_VALIDATOR_COUNT - VALIDATORS_PER_LANE + 2)
        );
        let committee_registrations = transactions[0]
            .iter()
            .filter_map(|instruction| instruction.as_any().downcast_ref::<RegisterConsensusKey>())
            .collect::<Vec<_>>();
        assert_eq!(
            committee_registrations.len(),
            LANE_VALIDATOR_COUNT - VALIDATORS_PER_LANE
        );
        for (registration, peer) in committee_registrations
            .iter()
            .zip(&topology[VALIDATORS_PER_LANE..LANE_VALIDATOR_COUNT])
        {
            assert_eq!(registration.id, derive_committee_key_id(peer.public_key()));
        }
        let lane_registrations = transactions[0]
            .iter()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterPublicLaneValidator>()
            })
            .collect::<Vec<_>>();
        assert_eq!(lane_registrations.len(), LANE_VALIDATOR_COUNT);
        for registration in &lane_registrations {
            assert_eq!(
                registration.monetary_plan.network_scope,
                iroha_data_model::nexus::PublicLaneMonetaryScopeV1::Genesis
            );
            assert_eq!(registration.monetary_plan.valid_until_height, 1);
            assert_eq!(
                registration.monetary_plan.source_asset,
                iroha_data_model::asset::AssetId::new(
                    stake_asset_definition_id(),
                    registration.validator.clone()
                )
            );
            assert_eq!(
                registration.monetary_plan.destination_asset,
                iroha_data_model::asset::AssetId::new(
                    stake_asset_definition_id(),
                    routing_probe_gas_account_id()
                )
            );
            assert_eq!(
                registration.monetary_plan.amount,
                registration.initial_stake
            );
            assert_eq!(
                registration.monetary_plan.precondition,
                iroha_data_model::nexus::PublicLaneMonetaryPreconditionV1::Registration(
                    iroha_data_model::nexus::PublicLaneMonetaryRegistrationV1 {
                        activation_height: 1
                    }
                )
            );
        }

        assert!(
            lane_registrations
                .iter()
                .all(|register| register.peer_id != topology[LANE_VALIDATOR_COUNT]),
            "the thirteenth global voter must not become a fifth lane validator"
        );
        assert_eq!(
            expected_lane_binding_for_peer(0, &topology[0]).peer_id,
            topology[0].to_string()
        );
        let (short_topology, short_entries) = deterministic_genesis_topology(TOTAL_PEERS - 1);
        let result = panic::catch_unwind(|| {
            npos_multilane_genesis_post_topology_transactions(&short_topology, &short_entries)
        });
        assert!(result.is_err());
    }
    #[test]
    fn genesis_post_topology_builder_is_stable_for_same_wrong_ingress_roster() {
        let (topology, entries) = deterministic_genesis_topology(TOTAL_PEERS);
        let first = npos_multilane_genesis_post_topology_transactions(&topology, &entries);
        let second = npos_multilane_genesis_post_topology_transactions(&topology, &entries);
        assert_eq!(format!("{first:?}"), format!("{second:?}"));
    }
    #[test]
    fn routing_probe_gas_account_uses_alice_subject() {
        let gas_account = routing_probe_gas_account_id();
        assert_eq!(gas_account, ALICE_ID.clone());
        assert_eq!(
            gas_account.canonical_i105().expect("gas account i105"),
            ALICE_ID.canonical_i105().expect("alice i105")
        );
    }
    #[test]
    fn versioned_signed_transaction_encoder_prefixes_v1_and_roundtrips_payload() {
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"cross-dataspace-route-encoder-genesis",
            )),
        );
        let transaction = TransactionBuilder::new(
            network_id,
            ALICE_ID.clone(),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "wrong ingress route envelope".to_owned(),
        )])
        .sign(ALICE_KEYPAIR.private_key());
        let adaptive_payload = norito::codec::encode_adaptive(&transaction);
        let encoded = encode_versioned_signed_transaction(&transaction);
        let (decoded, decoded_len) = SignedTransaction::decode_from_slice(&encoded[1..])
            .expect("adaptive signed transaction should decode from raw slice");
        assert_eq!(encoded.first(), Some(&1));
        assert_eq!(encoded.len(), adaptive_payload.len() + 1);
        assert_eq!(&encoded[1..], adaptive_payload.as_slice());
        assert_eq!(decoded_len, adaptive_payload.len());
        assert_eq!(decoded, transaction);
    }
    #[test]
    fn expected_lane_binding_for_peer_is_deterministic() {
        let mut seed = vec![0_u8; 32];
        seed[0] = 0x5A;
        let peer_key_pair = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
            .expect("fixture tx/query routing binding peer key");
        let peer_id = PeerId::new(peer_key_pair.public_key().clone());
        let expected_validator_key =
            KeyPair::try_from_seed(validator_authority_seed(5), Algorithm::Ed25519)
                .expect("fixture tx/query routing validator authority key");
        let binding = expected_lane_binding_for_peer(5, &peer_id);
        assert_eq!(binding.peer_id, peer_id.to_string());
        assert_eq!(
            binding.validator,
            validator_authority_account_for_peer(5).to_string()
        );
        assert_eq!(
            validator_authority_account_for_peer(5),
            AccountId::new(expected_validator_key.public_key().clone())
        );
        assert_eq!(
            validator_authority_account_for_peer(5),
            validator_authority_account_for_peer(5)
        );
        assert_ne!(
            validator_authority_account_for_peer(5),
            validator_authority_account_for_peer(6)
        );
    }
    #[test]
    fn lane_validator_snapshot_filters_active_bindings_and_preserves_total() {
        let body = norito::json!({
            "total": 2,
            "items": [
                {
                    "validator": "validator-a",
                    "peer_id": "peer-a",
                    "status": { "type": "Active" },
                },
                {
                    "validator": "validator-b",
                    "peer_id": "peer-b",
                    "status": { "type": "Pending" },
                },
            ],
        });
        let (total, active) =
            lane_validator_snapshot(&body, "lane validators").expect("lane snapshot should parse");
        assert_eq!(total, 2);
        assert_eq!(active.len(), 1);
        assert!(active.contains(&ExpectedLaneValidatorBinding {
            validator: "validator-a".to_owned(),
            peer_id: "peer-a".to_owned(),
        }));
    }
    #[test]
    fn lane_validator_snapshot_rejects_malformed_payloads() {
        for (body, expected) in [
            (JsonValue::Null, "lane validator response is not an object"),
            (
                norito::json!({ "items": [] }),
                "lane validator response is missing total",
            ),
            (
                norito::json!({ "total": 1 }),
                "lane validator response is missing items",
            ),
            (
                norito::json!({
                    "total": 1,
                    "items": [{ "validator": "validator-a", "peer_id": "peer-a" }],
                }),
                "validator entry missing status.type",
            ),
            (
                norito::json!({
                    "total": 1,
                    "items": [{ "validator": "validator-a", "status": { "type": "Active" } }],
                }),
                "validator entry missing peer_id literal",
            ),
            (
                norito::json!({
                    "total": 1,
                    "items": [7],
                }),
                "validator entry is not an object",
            ),
        ] {
            let err = lane_validator_snapshot(&body, "lane validators")
                .expect_err("malformed lane snapshot should fail");
            assert!(
                err.to_string().contains(expected),
                "expected `{expected}` in `{err}`"
            );
        }
    }
    #[test]
    fn routed_response_context_includes_path_query_and_route_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iroha-routed-by", HeaderValue::from_static("proxy"));
        headers.insert("x-iroha-route-lane-id", HeaderValue::from_static("2"));
        headers.insert("x-iroha-route-dataspace-id", HeaderValue::from_static("7"));
        let path_segments = vec!["v1".to_owned(), "transactions".to_owned()];
        let query_pairs = vec![
            ("account".to_owned(), "alice".to_owned()),
            ("dataspace".to_owned(), "2".to_owned()),
        ];
        let context = routed_response_context(
            HttpStatusCode::ACCEPTED,
            &headers,
            &path_segments,
            &query_pairs,
        );
        assert_eq!(
            routed_header_string(&headers, "x-iroha-routed-by"),
            Some("proxy".to_owned())
        );
        assert!(context.contains("status=202 Accepted"));
        assert!(context.contains("path=/v1/transactions?account=alice&dataspace=2"));
        assert!(context.contains(r#"routed_by=Some("proxy")"#));
        assert!(context.contains(r#"route_lane_id=Some("2")"#));
        assert!(context.contains(r#"route_dataspace_id=Some("7")"#));
    }
    #[test]
    fn routed_response_context_formats_root_path_without_query_or_headers() {
        let context = routed_response_context(HttpStatusCode::OK, &HeaderMap::new(), &[], &[]);
        assert!(context.contains("status=200 OK"));
        assert!(context.contains("path=/"));
        assert!(context.contains("routed_by=None"));
        assert!(context.contains("route_lane_id=None"));
        assert!(context.contains("route_dataspace_id=None"));
    }
    #[test]
    fn routed_response_context_formats_root_path_with_query() {
        let context = routed_response_context(
            HttpStatusCode::BAD_GATEWAY,
            &HeaderMap::new(),
            &[],
            &[("dataspace".to_owned(), DS2_ID_U64.to_string())],
        );
        assert!(context.contains("status=502 Bad Gateway"));
        assert!(context.contains("path=/?dataspace=2"));
    }
    #[test]
    fn routed_header_string_ignores_non_utf8_header_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-iroha-route-lane-id",
            HeaderValue::from_bytes(&[0xFF]).expect("binary header value"),
        );
        assert_eq!(
            routed_header_string(&headers, "x-iroha-route-lane-id"),
            None
        );
    }
    #[test]
    fn expect_proxy_route_headers_accepts_exact_lane_dataspace() {
        let response = routed_json_response_with_route(
            Some("proxy"),
            Some(&DS1_LANE_INDEX.to_string()),
            Some(&DS1_ID_U64.to_string()),
        );
        expect_proxy_route_headers(
            &response,
            LaneId::new(DS1_LANE_INDEX),
            DataSpaceId::new(DS1_ID_U64),
            "ds1 routed response",
        )
        .expect("matching route headers should pass");
        let wrong_dataspace = routed_json_response_with_route(
            Some("proxy"),
            Some(&DS1_LANE_INDEX.to_string()),
            Some(&DS2_ID_U64.to_string()),
        );
        let err = expect_proxy_route_headers(
            &wrong_dataspace,
            LaneId::new(DS1_LANE_INDEX),
            DataSpaceId::new(DS1_ID_U64),
            "ds1 routed response",
        )
        .expect_err("wrong dataspace header should fail");
        assert!(err.to_string().contains("expected routed dataspace 1"));
    }
    #[test]
    fn expect_proxy_route_headers_rejects_missing_proxy_and_wrong_lane() {
        let local_response = routed_json_response_with_route(
            Some("local"),
            Some(&DS1_LANE_INDEX.to_string()),
            Some(&DS1_ID_U64.to_string()),
        );
        let err = expect_proxy_route_headers(
            &local_response,
            LaneId::new(DS1_LANE_INDEX),
            DataSpaceId::new(DS1_ID_U64),
            "local response",
        )
        .expect_err("local response should not satisfy proxy route headers");
        assert!(err.to_string().contains("expected proxied read"));
        let wrong_lane = routed_json_response_with_route(
            Some("proxy"),
            Some(&(DS1_LANE_INDEX + 1).to_string()),
            Some(&DS1_ID_U64.to_string()),
        );
        let err = expect_proxy_route_headers(
            &wrong_lane,
            LaneId::new(DS1_LANE_INDEX),
            DataSpaceId::new(DS1_ID_U64),
            "wrong lane response",
        )
        .expect_err("wrong lane header should fail");
        assert!(err.to_string().contains("expected routed lane 1"));
    }
    #[test]
    fn expect_proxy_route_headers_rejects_missing_lane_or_dataspace() {
        let missing_lane =
            routed_json_response_with_route(Some("proxy"), None, Some(&DS1_ID_U64.to_string()));
        let err = expect_proxy_route_headers(
            &missing_lane,
            LaneId::new(DS1_LANE_INDEX),
            DataSpaceId::new(DS1_ID_U64),
            "missing lane response",
        )
        .expect_err("missing lane header should fail");
        assert!(err.to_string().contains("expected routed lane 1"));
        let missing_dataspace =
            routed_json_response_with_route(Some("proxy"), Some(&DS1_LANE_INDEX.to_string()), None);
        let err = expect_proxy_route_headers(
            &missing_dataspace,
            LaneId::new(DS1_LANE_INDEX),
            DataSpaceId::new(DS1_ID_U64),
            "missing dataspace response",
        )
        .expect_err("missing dataspace header should fail");
        assert!(err.to_string().contains("expected routed dataspace 1"));
    }
    #[test]
    fn expect_proxy_fanout_headers_requires_proxy_without_singular_route() {
        let response = routed_json_response_with_route(Some("proxy"), None, None);
        expect_proxy_fanout_headers(&response, "fanout permissions")
            .expect("fanout response without singular route should pass");
        let local_response = routed_json_response_with_route(Some("local"), None, None);
        let err = expect_proxy_fanout_headers(&local_response, "fanout permissions")
            .expect_err("local fanout response should fail for proxy-only helper");
        assert!(err.to_string().contains("expected proxied fanout read"));
        let missing_route_source = routed_json_response_with_route(None, None, None);
        let err = expect_proxy_fanout_headers(&missing_route_source, "fanout permissions")
            .expect_err("missing fanout route source should fail");
        assert!(err.to_string().contains("expected proxied fanout read"));
        let singular_route =
            routed_json_response_with_route(Some("proxy"), Some(&DS1_LANE_INDEX.to_string()), None);
        let err = expect_proxy_fanout_headers(&singular_route, "fanout permissions")
            .expect_err("fanout response with singular route should fail");
        assert!(
            err.to_string()
                .contains("fanout response should not expose singular route lane")
        );
        let singular_dataspace =
            routed_json_response_with_route(Some("proxy"), None, Some(&DS2_ID_U64.to_string()));
        let err = expect_proxy_fanout_headers(&singular_dataspace, "fanout permissions")
            .expect_err("fanout response with singular dataspace should fail");
        assert!(
            err.to_string()
                .contains("fanout response should not expose singular route dataspace")
        );
    }
    #[test]
    fn permission_response_contains_matches_name_and_dataspace_payload() {
        let body = norito::json!({
            "items": [
                {
                    "name": "CanPublishSpaceDirectoryManifest",
                    "payload": { "dataspace": DS2_ID_U64 },
                },
                {
                    "name": "OtherPermission",
                    "payload": { "dataspace": DS1_ID_U64 },
                },
            ],
        });
        assert!(
            permission_response_contains(
                &body,
                "CanPublishSpaceDirectoryManifest",
                |payload| payload.get("dataspace").and_then(JsonValue::as_u64) == Some(DS2_ID_U64),
                "permission response",
            )
            .expect("permission response should decode")
        );
        assert!(
            !permission_response_contains(
                &body,
                "CanPublishSpaceDirectoryManifest",
                |payload| payload.get("dataspace").and_then(JsonValue::as_u64) == Some(DS1_ID_U64),
                "permission response",
            )
            .expect("permission response should decode")
        );
        let err = permission_response_contains(
            &norito::json!({}),
            "CanPublishSpaceDirectoryManifest",
            |_| true,
            "permission response",
        )
        .expect_err("missing permission items should fail");
        assert!(
            err.to_string()
                .contains("permission response missing items array")
        );
    }
    #[test]
    fn permission_response_contains_ignores_wrong_names_and_missing_payloads() {
        let body = norito::json!({
            "items": [
                { "name": "CanPublishSpaceDirectoryManifest" },
                { "name": "OtherPermission", "payload": { "dataspace": DS2_ID_U64 } },
                { "name": DS2_ID_U64, "payload": { "dataspace": DS2_ID_U64 } },
            ],
        });
        assert!(
            !permission_response_contains(
                &body,
                "CanPublishSpaceDirectoryManifest",
                |payload| payload.get("dataspace").and_then(JsonValue::as_u64) == Some(DS2_ID_U64),
                "permission response",
            )
            .expect("permission response should decode")
        );
    }
    #[test]
    fn response_helpers_reject_non_array_collections() {
        let asset_definition_id = ds2_asset_definition_id();
        let permission_err = permission_response_contains(
            &norito::json!({ "items": {} }),
            "CanPublishSpaceDirectoryManifest",
            |_| true,
            "permission response",
        )
        .expect_err("non-array permissions should fail");
        assert!(
            permission_err
                .to_string()
                .contains("permission response missing items array")
        );
        let manifest_err = manifest_response_contains_status(
            &norito::json!({ "manifests": {} }),
            DataSpaceId::new(DS2_ID_U64),
            "Active",
            "manifest response",
        )
        .expect_err("non-array manifests should fail");
        assert!(
            manifest_err
                .to_string()
                .contains("manifest response missing manifests array")
        );
        let assets_err = account_assets_response_contains(
            &norito::json!({ "items": {} }),
            &asset_definition_id,
            "account assets",
        )
        .expect_err("non-array assets should fail");
        assert!(
            assets_err
                .to_string()
                .contains("account assets response missing items array")
        );
    }
    #[test]
    fn manifest_response_helpers_match_dataspace_and_status() {
        let body = norito::json!({
            "manifests": [
                { "dataspace_id": DS1_ID_U64, "status": "Pending" },
                { "dataspace_id": DS2_ID_U64, "status": "Active" },
            ],
        });
        assert!(
            manifest_response_contains_status(
                &body,
                DataSpaceId::new(DS2_ID_U64),
                "Active",
                "manifest response",
            )
            .expect("manifest response should decode")
        );
        assert!(
            !manifest_response_contains_status(
                &body,
                DataSpaceId::new(DS1_ID_U64),
                "Active",
                "manifest response",
            )
            .expect("manifest response should decode")
        );
        assert!(
            manifest_response_contains_dataspace(
                &body,
                DataSpaceId::new(DS1_ID_U64),
                "manifest response",
            )
            .expect("manifest response should decode")
        );
        let err = manifest_response_contains_dataspace(
            &norito::json!({}),
            DataSpaceId::new(DS1_ID_U64),
            "manifest response",
        )
        .expect_err("missing manifest array should fail");
        assert!(
            err.to_string()
                .contains("manifest response missing manifests array")
        );
    }
    #[test]
    fn manifest_response_contains_status_requires_manifest_array() {
        let err = manifest_response_contains_status(
            &norito::json!({ "items": [] }),
            DataSpaceId::new(DS2_ID_U64),
            "Active",
            "manifest response",
        )
        .expect_err("missing manifest array should fail");
        assert!(
            err.to_string()
                .contains("manifest response missing manifests array")
        );
    }
    #[test]
    fn manifest_response_contains_dataspace_ignores_missing_or_non_numeric_ids() {
        let body = norito::json!({
            "manifests": [
                { "dataspace_id": "2", "status": "Active" },
                { "status": "Active" },
            ],
        });
        assert!(
            !manifest_response_contains_dataspace(
                &body,
                DataSpaceId::new(DS2_ID_U64),
                "manifest response",
            )
            .expect("manifest response should decode")
        );
    }
    #[test]
    fn manifest_response_contains_status_ignores_missing_or_non_string_statuses() {
        let body = norito::json!({
            "manifests": [
                { "dataspace_id": DS2_ID_U64, "status": true },
                { "dataspace_id": DS2_ID_U64 },
                { "dataspace_id": DS1_ID_U64, "status": "Active" },
            ],
        });
        assert!(
            !manifest_response_contains_status(
                &body,
                DataSpaceId::new(DS2_ID_U64),
                "Active",
                "manifest response",
            )
            .expect("manifest response should decode")
        );
    }
    #[test]
    fn account_assets_response_contains_matches_asset_definition_literal() {
        let asset_definition_id = ds2_asset_definition_id();
        let asset_literal = asset_definition_id.to_string();
        let other_asset_literal = AssetDefinitionId::derive_from_components(
            DomainId::try_new("nexus", "universal").expect("asset domain"),
            "othercoin".parse().expect("asset name"),
        )
        .to_string();
        let body = norito::json!({
            "items": [
                { "asset": asset_literal },
            ],
        });
        let other_body = norito::json!({
            "items": [
                { "asset": other_asset_literal },
            ],
        });
        assert!(
            account_assets_response_contains(&body, &asset_definition_id, "account assets")
                .expect("account assets response should decode")
        );
        assert!(
            !account_assets_response_contains(&other_body, &asset_definition_id, "account assets")
                .expect("account assets response should decode")
        );
        let err =
            account_assets_response_contains(&norito::json!({}), &asset_definition_id, "assets")
                .expect_err("missing account assets items should fail");
        assert!(
            err.to_string()
                .contains("account assets response missing items array")
        );
    }
    #[test]
    fn account_assets_response_contains_ignores_non_string_assets() {
        let asset_definition_id = ds2_asset_definition_id();
        let asset_literal = asset_definition_id.to_string();
        let body = norito::json!({
            "items": [
                { "asset": DS2_ID_U64 },
                { "not_asset": asset_literal },
            ],
        });
        assert!(
            !account_assets_response_contains(&body, &asset_definition_id, "account assets")
                .expect("account assets response should decode")
        );
    }
    #[test]
    fn account_assets_response_contains_requires_exact_asset_literal() {
        let asset_definition_id = ds2_asset_definition_id();
        let asset_literal = format!("{}#dataspace:{}", asset_definition_id, DS2_ID_U64);
        let body = norito::json!({
            "items": [
                { "asset": asset_literal },
            ],
        });
        assert!(
            !account_assets_response_contains(&body, &asset_definition_id, "account assets")
                .expect("account assets response should decode")
        );
    }
    #[test]
    fn routed_json_empty_body_is_transient_for_empty_timeout_statuses() {
        assert!(routed_json_empty_body_is_transient(
            HttpStatusCode::REQUEST_TIMEOUT,
            b""
        ));
        assert!(routed_json_empty_body_is_transient(
            HttpStatusCode::BAD_GATEWAY,
            b""
        ));
        assert!(routed_json_empty_body_is_transient(
            HttpStatusCode::SERVICE_UNAVAILABLE,
            b""
        ));
        assert!(routed_json_empty_body_is_transient(
            HttpStatusCode::GATEWAY_TIMEOUT,
            b""
        ));
    }
    #[test]
    fn routed_json_empty_body_is_not_transient_for_non_empty_or_success_statuses() {
        assert!(!routed_json_empty_body_is_transient(
            HttpStatusCode::REQUEST_TIMEOUT,
            br#"{"error":"timeout"}"#
        ));
        assert!(!routed_json_empty_body_is_transient(
            HttpStatusCode::OK,
            b""
        ));
    }
    #[test]
    fn routed_json_response_is_transient_only_for_empty_retryable_routed_failures() {
        let response = routed_json_response(HttpStatusCode::BAD_GATEWAY, JsonValue::Null, "");
        assert!(routed_json_response_is_transient(&response));
    }
    #[test]
    fn routed_json_response_is_not_transient_after_json_body_decodes() {
        let body_text = r#"{"error":"route_unavailable"}"#;
        let response = routed_json_response(
            HttpStatusCode::SERVICE_UNAVAILABLE,
            norito::json::from_str(body_text).expect("decode test JSON"),
            body_text,
        );
        assert!(!routed_json_response_is_transient(&response));
    }
    #[test]
    fn routed_json_response_is_not_transient_for_non_retryable_empty_statuses() {
        let response = routed_json_response(HttpStatusCode::NOT_FOUND, JsonValue::Null, "");
        assert!(!routed_json_response_is_transient(&response));
    }
    #[test]
    fn routed_json_response_is_not_transient_when_null_body_text_is_non_empty() {
        let response =
            routed_json_response(HttpStatusCode::GATEWAY_TIMEOUT, JsonValue::Null, "timeout");
        assert!(!routed_json_response_is_transient(&response));
    }
    #[test]
    fn routed_submit_response_is_transient_for_route_unavailable() {
        let response = RoutedTransactionSubmitResponse {
            status: HttpStatusCode::NOT_FOUND,
            receipt: None,
            body_text: r#"{"error":"route_unavailable"}"#.to_owned(),
            routed_by: Some("proxy".to_owned()),
            route_lane_id: None,
            route_dataspace_id: None,
        };
        assert!(super::routed_submit_response_is_transient(&response));
    }
    #[test]
    fn routed_submit_response_is_not_transient_for_other_not_found() {
        let response = RoutedTransactionSubmitResponse {
            status: HttpStatusCode::NOT_FOUND,
            receipt: None,
            body_text: r#"{"error":"missing"}"#.to_owned(),
            routed_by: Some("proxy".to_owned()),
            route_lane_id: None,
            route_dataspace_id: None,
        };
        assert!(!super::routed_submit_response_is_transient(&response));
    }
    #[test]
    fn routed_submit_response_is_transient_for_empty_proxy_not_found() {
        let response = RoutedTransactionSubmitResponse {
            status: HttpStatusCode::NOT_FOUND,
            receipt: None,
            body_text: String::new(),
            routed_by: Some("proxy".to_owned()),
            route_lane_id: Some(DS2_LANE_INDEX.to_string()),
            route_dataspace_id: Some(DS2_ID_U64.to_string()),
        };
        assert!(super::routed_submit_response_is_transient(&response));
    }
    #[test]
    fn routed_submit_response_is_transient_for_unmarked_empty_not_found() {
        let response = RoutedTransactionSubmitResponse {
            status: HttpStatusCode::NOT_FOUND,
            receipt: None,
            body_text: String::new(),
            routed_by: None,
            route_lane_id: None,
            route_dataspace_id: None,
        };
        assert!(super::routed_submit_response_is_transient(&response));
    }
}
