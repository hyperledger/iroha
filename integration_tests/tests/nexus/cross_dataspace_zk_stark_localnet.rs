#![cfg(feature = "zk-stark")]
//! Cross-dataspace STARK verification tests that validate proof outcomes while
//! ensuring proof payload details are not exposed to other dataspaces.
use super::localnet_npos::npos_override_transactions;
use base64::Engine as _;
use eyre::{Result, ensure, eyre};
use futures_util::StreamExt;
use integration_tests::sandbox;
use iroha::{
    client::Client,
    crypto::HashOf,
    data_model::{
        Level,
        account::{Account, AccountId},
        asset::{AssetDefinition, AssetDefinitionId, AssetId},
        da::commitment::DaProofPolicyBundle,
        domain::Domain,
        events::{
            EventBox,
            pipeline::{PipelineEventBox, TransactionEventFilter, TransactionStatus},
        },
        isi::{
            ActivatePublicLaneValidator, Grant, InstructionBox, Log, Mint, Register,
            RegisterPublicLaneValidator, consensus_keys::RegisterConsensusKey, zk::VerifyProof,
        },
        nexus::{LaneCatalog, LaneConfig as ModelLaneConfig, LaneVisibility},
        permission::Permission,
        prelude::Quantity,
        proof::{
            ProofAttachment, ProofId, ProofRecord, ProofStatus, VerifyingKeyBox, VerifyingKeyId,
            VerifyingKeyRecord,
        },
        query::proof::prelude::FindProofRecordById,
        transaction::TransactionEntrypoint,
        zk::{BackendTag, OpenVerifyEnvelope, StarkFriOpenProofV1},
    },
    query::QueryError,
};
use iroha_config::parameters::actual::LaneConfig as ActualLaneConfig;
use iroha_core::{da::proof_policy_bundle, state::derive_committee_key_id};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    prelude::QueryBuilderExt,
    query::{
        CommittedTxFilters,
        dsl::CompoundPredicate,
        parameters::{FetchSize, Pagination},
        transaction::prelude::FindTransactions,
    },
};
use iroha_genesis::GenesisTopologyEntry;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::{json::Json, numeric::NumericSpec};
use iroha_test_network::{
    NetworkBuilder, genesis_participant_committee_key_instructions, read_on_dedicated_thread,
    unexecuted_genesis_factory_with_post_topology,
};
use iroha_test_samples::{ALICE_ID, BOB_ID, BOB_KEYPAIR, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
use reqwest::{Client as HttpClient, StatusCode};
use std::{collections::BTreeSet, num::NonZeroU64, time::Duration};
use tokio::time::{sleep, timeout};
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
const TOTAL_PEERS: usize = 4;
const VALIDATOR_STAKE_PER_LANE: u64 = 2_000;
const NEXUS_FEE_SEED_AMOUNT: u32 = 1_000_000;
const STATUS_WAIT_TIMEOUT: Duration = Duration::from_secs(45);
const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(200);
const ROUTE_PROBE_SSE_HANDSHAKE_DELAY: Duration = Duration::from_millis(100);
const PROOF_FETCH_HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const STARK_BACKEND: &str = "stark/fri/poseidon-x7-goldilocks-6x64-v1-v1";
const CIRCUIT_ID_VALID: &str =
    "stark/fri/poseidon-x7-goldilocks-6x64-v1-v1:cross-dataspace-verifyproof-v1";
const CIRCUIT_ID_MISMATCH: &str =
    "stark/fri/poseidon-x7-goldilocks-6x64-v1-v1:cross-dataspace-verifyproof-v2";
const SCHEMA_VALID: &[u8] = b"nexus:cross-dataspace:verifyproof:schema:v1";
const SCHEMA_MISMATCH: &[u8] = b"nexus:cross-dataspace:verifyproof:schema:v2";
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ExpectedLaneValidatorBinding {
    validator: String,
    peer_id: String,
}
fn validator_authority_account_for_peer(index: usize) -> AccountId {
    let keypair = KeyPair::try_from_seed(validator_authority_seed(index), Algorithm::Ed25519)
        .expect("fixture cross-dataspace STARK validator authority key");
    AccountId::new(keypair.public_key().clone())
}
fn validator_authority_seed(index: usize) -> Vec<u8> {
    let mut seed = vec![0_u8; 32];
    seed[0] = 0xD3;
    seed[1..9].copy_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
    seed
}
#[test]
fn validator_authority_account_uses_checked_seed_derivation() {
    let expected = KeyPair::try_from_seed(validator_authority_seed(2), Algorithm::Ed25519)
        .expect("fixture cross-dataspace STARK validator authority key");
    assert_eq!(
        validator_authority_account_for_peer(2),
        AccountId::new(expected.public_key().clone())
    );
}
fn expected_lane_binding_for_peer(index: usize, peer_id: &PeerId) -> ExpectedLaneValidatorBinding {
    ExpectedLaneValidatorBinding {
        validator: validator_authority_account_for_peer(index).to_string(),
        peer_id: peer_id.to_string(),
    }
}
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
enum RouteProbeOutcome {
    Approved,
    Rejected(String),
}
enum CommittedTxOutcome {
    Applied,
    Rejected(String),
}
fn render_rejection_reason(
    reason: &iroha::data_model::transaction::error::TransactionRejectionReason,
) -> String {
    let display = reason.to_string();
    let debug = format!("{reason:?}");
    if display == debug {
        display
    } else {
        format!("{display}; details: {debug}")
    }
}
fn query_committed_tx_outcome(
    client: &Client,
    entry_hash: &HashOf<TransactionEntrypoint>,
) -> core::result::Result<Option<CommittedTxOutcome>, QueryError> {
    let one = NonZeroU64::new(1).expect("nonzero");
    let filters = CommittedTxFilters {
        entry_eq: Some(entry_hash.clone()),
        ..Default::default()
    };
    client
        .query(FindTransactions::new())
        .filter(CompoundPredicate::from_filters(filters))
        .with_pagination(Pagination::new(Some(one), 0))
        .with_fetch_size(FetchSize::new(Some(one)))
        .execute_all()
        .map(|snapshot| {
            snapshot.first().map(|tx| match &tx.result().0 {
                Ok(_) => CommittedTxOutcome::Applied,
                Err(reason) => CommittedTxOutcome::Rejected(render_rejection_reason(reason)),
            })
        })
}
async fn wait_for_committed_success(
    client: &Client,
    entry_hash: HashOf<TransactionEntrypoint>,
    context: &str,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + STATUS_WAIT_TIMEOUT;
    let mut last_error: Option<String> = None;
    loop {
        let mut polling_builder = client.to_builder();
        polling_builder.torii_request_timeout = polling_builder
            .torii_request_timeout
            .min(PROOF_FETCH_HTTP_TIMEOUT);
        let polling_client = polling_builder.build()?;
        let polling_entry_hash = entry_hash.clone();
        match read_on_dedicated_thread(move || {
            Ok(query_committed_tx_outcome(
                &polling_client,
                &polling_entry_hash,
            )?)
        })
        .await
        {
            Ok(Some(CommittedTxOutcome::Applied)) => return Ok(()),
            Ok(Some(CommittedTxOutcome::Rejected(reason))) => {
                return Err(eyre!(
                    "{context}: transaction {entry_hash} rejected unexpectedly: {reason}"
                ));
            }
            Ok(None) => {}
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        sleep(STATUS_POLL_INTERVAL).await;
    }
    let suffix = last_error
        .map(|err| format!("; last tx history query error: {err}"))
        .unwrap_or_default();
    Err(eyre!(
        "{context}: timed out waiting for committed transaction outcome for transaction {entry_hash}{suffix}"
    ))
}
fn has_test_network_feature(feature: &str) -> bool {
    std::env::var("TEST_NETWORK_IROHAD_FEATURES")
        .ok()
        .map(|value| {
            value
                .split([',', ' ', '\t', '\n'])
                .any(|item| item.trim() == feature)
        })
        .unwrap_or(false)
}
fn require_test_network_feature(feature: &str, test_name: &str) -> Result<()> {
    ensure!(
        has_test_network_feature(feature),
        "{test_name}: TEST_NETWORK_IROHAD_FEATURES must include `{feature}` to execute the runtime path"
    );
    Ok(())
}
fn localnet_builder() -> NetworkBuilder {
    let gas_account_str = ALICE_ID.to_string();
    NetworkBuilder::new()
        .with_peers(TOTAL_PEERS)
        .without_npos_genesis_bootstrap()
        .with_genesis_block(|topology, topology_entries| {
            let post_topology = npos_multilane_genesis_post_topology_transactions(
                topology.as_ref(),
                &topology_entries,
            );
            let mut genesis = unexecuted_genesis_factory_with_post_topology(
                npos_override_transactions(TOTAL_PEERS),
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
                .write(["nexus", "staking", "max_validators"], TOTAL_PEERS as i64);
        })
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
    let universal_domain: DomainId =
        DomainId::try_new("universal", "universal").expect("universal domain");
    let ds1_domain: DomainId = DomainId::try_new("ds1", "universal").expect("ds1 domain");
    let ds2_domain: DomainId = DomainId::try_new("ds2", "universal").expect("ds2 domain");
    let stake_asset_id = stake_asset_definition_id();
    let fee_asset_id = nexus_fee_asset_definition_id();
    let mut bootstrap_tx = vec![
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
    ];
    let mut validator_tx = Vec::new();
    bootstrap_tx.extend(genesis_participant_committee_key_instructions(
        topology_entries,
        topology,
    ));
    let lanes = [NEXUS_LANE_INDEX, DS1_LANE_INDEX, DS2_LANE_INDEX];
    let mint_amount =
        VALIDATOR_STAKE_PER_LANE.saturating_mul(u64::try_from(lanes.len()).unwrap_or(u64::MAX));
    for (index, peer) in topology.iter().enumerate() {
        let validator_id = validator_authority_account_for_peer(index);
        bootstrap_tx.push(Register::account(Account::new(validator_id.clone())).into());
        bootstrap_tx.push(
            Mint::asset_quantity(
                mint_amount,
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
        for lane_index in lanes {
            let lane_id = LaneId::new(lane_index);
            validator_tx.push(
                RegisterPublicLaneValidator::new(
                    lane_id,
                    validator_id.clone(),
                    peer.clone(),
                    validator_id.clone(),
                    Quantity::from(VALIDATOR_STAKE_PER_LANE),
                    Metadata::default(),
                    iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                        AssetId::new(stake_asset_id.clone(), validator_id.clone()),
                        AssetId::new(stake_asset_id.clone(), ALICE_ID.clone()),
                        Quantity::from(VALIDATOR_STAKE_PER_LANE),
                    ),
                )
                .into(),
            );
            validator_tx
                .push(ActivatePublicLaneValidator::new(lane_id, validator_id.clone()).into());
        }
    }
    vec![bootstrap_tx, validator_tx]
}
fn multilane_da_proof_policy_bundle() -> DaProofPolicyBundle {
    let lane_count = std::num::NonZeroU32::new(3).expect("lane count");
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
#[test]
fn cross_dataspace_zk_stark_localnet_genesis_preexecution_smoke() {
    let _guard = sandbox::serial_guard();
    let _network = localnet_builder().build();
}
fn expected_lane_validators(
    network: &sandbox::SerializedNetwork,
) -> BTreeSet<ExpectedLaneValidatorBinding> {
    network
        .peers()
        .iter()
        .enumerate()
        .map(|(index, peer)| expected_lane_binding_for_peer(index, &peer.id()))
        .collect()
}
fn lane_validator_snapshot(
    snapshot: &norito::json::Value,
    context: &str,
) -> Result<(usize, BTreeSet<ExpectedLaneValidatorBinding>)> {
    let root = snapshot
        .as_object()
        .ok_or_else(|| eyre!("{context}: lane validator response is not an object"))?;
    let total = root
        .get("total")
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre!("{context}: lane validator response is missing total"))?;
    let items = root
        .get("items")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre!("{context}: lane validator response is missing items"))?;
    let mut active = BTreeSet::new();
    for item in items {
        let entry = item
            .as_object()
            .ok_or_else(|| eyre!("{context}: validator entry is not an object"))?;
        let validator = entry
            .get("validator")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre!("{context}: validator entry missing validator literal"))?;
        let peer_id = entry
            .get("peer_id")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre!("{context}: validator entry missing peer_id literal"))?;
        let status_type = entry
            .get("status")
            .and_then(norito::json::Value::as_object)
            .and_then(|status| status.get("type"))
            .and_then(norito::json::Value::as_str)
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
async fn wait_for_active_lane_validators(
    client: &Client,
    lane_id: LaneId,
    expected_active: &BTreeSet<ExpectedLaneValidatorBinding>,
    context: &str,
) -> Result<()> {
    let started = tokio::time::Instant::now();
    let mut last_total = 0usize;
    let mut last_active = BTreeSet::new();
    while started.elapsed() <= STATUS_WAIT_TIMEOUT {
        let polling_client = client.clone();
        let snapshot =
            read_on_dedicated_thread(move || polling_client.get_public_lane_validators(lane_id))
                .await
                .map_err(|err| eyre!(err))?;
        let (total, active) = lane_validator_snapshot(&snapshot, context)?;
        last_total = total;
        last_active = active.clone();
        if total == expected_active.len() && active == *expected_active {
            return Ok(());
        }
        sleep(STATUS_POLL_INTERVAL).await;
    }
    Err(eyre!(
        "{context}: timed out waiting for active validators on lane {lane_id}; expected total {} active {:?}, observed total {} active {:?}",
        expected_active.len(),
        expected_active,
        last_total,
        last_active
    ))
}
async fn wait_for_route_probe_approval(
    submitter: &Client,
    instruction: InstructionBox,
    expected_lane_id: LaneId,
    expected_dataspace_id: DataSpaceId,
    context: &str,
) -> Result<HashOf<TransactionEntrypoint>> {
    let account = submitter.account_client()?;
    let transaction = {
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [instruction],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    let hash = transaction.hash();
    let entry_hash = transaction.hash_as_entrypoint();
    let mut events = timeout(
        STATUS_WAIT_TIMEOUT,
        account
            .events()
            .subscribe([TransactionEventFilter::default().for_hash(hash)]),
    )
    .await
    .map_err(|_| eyre!("{context}: timed out opening transaction event stream"))??;
    sleep(ROUTE_PROBE_SSE_HANDSHAKE_DELAY).await;
    account
        .submit_transaction(&transaction)
        .await
        .map_err(|err| eyre!("{context}: failed to submit route probe transaction: {err}"))?;
    let outcome = timeout(STATUS_WAIT_TIMEOUT, async {
        let mut saw_queued = false;
        loop {
            let Some(next) = events.next().await else {
                return Err(eyre!("{context}: transaction event stream closed"));
            };
            let EventBox::Pipeline(PipelineEventBox::Transaction(event)) = next? else {
                continue;
            };
            match event.status() {
                TransactionStatus::Queued => {
                    ensure!(
                        event.lane_id() == expected_lane_id,
                        "{context}: expected queued lane {}, observed {}",
                        expected_lane_id.as_u32(),
                        event.lane_id().as_u32()
                    );
                    ensure!(
                        event.dataspace_id() == expected_dataspace_id,
                        "{context}: expected queued dataspace {}, observed {}",
                        expected_dataspace_id.as_u64(),
                        event.dataspace_id().as_u64()
                    );
                    saw_queued = true;
                }
                TransactionStatus::Approved => {
                    if !saw_queued {
                        ensure!(
                            event.lane_id() == expected_lane_id,
                            "{context}: expected approved lane {}, observed {}",
                            expected_lane_id.as_u32(),
                            event.lane_id().as_u32()
                        );
                        ensure!(
                            event.dataspace_id() == expected_dataspace_id,
                            "{context}: expected approved dataspace {}, observed {}",
                            expected_dataspace_id.as_u64(),
                            event.dataspace_id().as_u64()
                        );
                    }
                    return Ok(RouteProbeOutcome::Approved);
                }
                TransactionStatus::Rejected(reason) => {
                    if !saw_queued {
                        ensure!(
                            event.lane_id() == expected_lane_id,
                            "{context}: expected rejected lane {}, observed {}",
                            expected_lane_id.as_u32(),
                            event.lane_id().as_u32()
                        );
                        ensure!(
                            event.dataspace_id() == expected_dataspace_id,
                            "{context}: expected rejected dataspace {}, observed {}",
                            expected_dataspace_id.as_u64(),
                            event.dataspace_id().as_u64()
                        );
                    }
                    return Ok(RouteProbeOutcome::Rejected(format!(
                        "{reason}; debug={reason:?}"
                    )));
                }
                TransactionStatus::Expired => {
                    return Err(eyre!("{context}: route probe transaction expired"));
                }
            }
        }
    })
    .await
    .map_err(|_| eyre!("{context}: timed out waiting for route probe status"))??;
    events.close().await?;
    match outcome {
        RouteProbeOutcome::Approved => Ok(entry_hash),
        RouteProbeOutcome::Rejected(reason) => Err(eyre!(
            "{context}: route probe transaction rejected: {reason}"
        )),
    }
}
async fn wait_for_route_probe_rejection(
    submitter: &Client,
    instruction: InstructionBox,
    expected_lane_id: LaneId,
    expected_dataspace_id: DataSpaceId,
    context: &str,
) -> Result<String> {
    let account = submitter.account_client()?;
    let transaction = {
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [instruction],
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    let hash = transaction.hash();
    let mut events = timeout(
        STATUS_WAIT_TIMEOUT,
        account
            .events()
            .subscribe([TransactionEventFilter::default().for_hash(hash)]),
    )
    .await
    .map_err(|_| eyre!("{context}: timed out opening transaction event stream"))??;
    sleep(ROUTE_PROBE_SSE_HANDSHAKE_DELAY).await;
    account
        .submit_transaction(&transaction)
        .await
        .map_err(|err| eyre!("{context}: failed to submit route probe transaction: {err}"))?;
    let outcome = timeout(STATUS_WAIT_TIMEOUT, async {
        let mut saw_queued = false;
        loop {
            let Some(next) = events.next().await else {
                return Err(eyre!("{context}: transaction event stream closed"));
            };
            let EventBox::Pipeline(PipelineEventBox::Transaction(event)) = next? else {
                continue;
            };
            match event.status() {
                TransactionStatus::Queued => {
                    ensure!(
                        event.lane_id() == expected_lane_id,
                        "{context}: expected queued lane {}, observed {}",
                        expected_lane_id.as_u32(),
                        event.lane_id().as_u32()
                    );
                    ensure!(
                        event.dataspace_id() == expected_dataspace_id,
                        "{context}: expected queued dataspace {}, observed {}",
                        expected_dataspace_id.as_u64(),
                        event.dataspace_id().as_u64()
                    );
                    saw_queued = true;
                }
                TransactionStatus::Approved => {
                    if !saw_queued {
                        ensure!(
                            event.lane_id() == expected_lane_id,
                            "{context}: expected approved lane {}, observed {}",
                            expected_lane_id.as_u32(),
                            event.lane_id().as_u32()
                        );
                        ensure!(
                            event.dataspace_id() == expected_dataspace_id,
                            "{context}: expected approved dataspace {}, observed {}",
                            expected_dataspace_id.as_u64(),
                            event.dataspace_id().as_u64()
                        );
                    }
                    return Ok(RouteProbeOutcome::Approved);
                }
                TransactionStatus::Rejected(reason) => {
                    if !saw_queued {
                        ensure!(
                            event.lane_id() == expected_lane_id,
                            "{context}: expected rejected lane {}, observed {}",
                            expected_lane_id.as_u32(),
                            event.lane_id().as_u32()
                        );
                        ensure!(
                            event.dataspace_id() == expected_dataspace_id,
                            "{context}: expected rejected dataspace {}, observed {}",
                            expected_dataspace_id.as_u64(),
                            event.dataspace_id().as_u64()
                        );
                    }
                    return Ok(RouteProbeOutcome::Rejected(format!(
                        "{reason}; debug={reason:?}"
                    )));
                }
                TransactionStatus::Expired => {
                    return Err(eyre!("{context}: route probe transaction expired"));
                }
            }
        }
    })
    .await
    .map_err(|_| eyre!("{context}: timed out waiting for route probe status"))??;
    events.close().await?;
    match outcome {
        RouteProbeOutcome::Approved => Err(eyre!(
            "{context}: route probe transaction was approved unexpectedly"
        )),
        RouteProbeOutcome::Rejected(reason) => Ok(reason),
    }
}
fn sample_stark_vk_box(circuit_id: &str, n_log2: u8) -> VerifyingKeyBox {
    let vk_payload = iroha_core_zk::stark::StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: circuit_id.to_owned(),
        n_log2,
        blowup_log2: iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    };
    let bytes = norito::to_bytes(&vk_payload).expect("encode stark vk payload");
    VerifyingKeyBox::new(STARK_BACKEND.to_owned(), bytes)
}
async fn register_stark_vk(
    client: &Client,
    vk_id: VerifyingKeyId,
    vk_box: VerifyingKeyBox,
    circuit_id: &str,
    schema: &[u8],
) -> Result<()> {
    let mut record = VerifyingKeyRecord::new(
        1,
        circuit_id,
        BackendTag::Stark,
        "goldilocks",
        Hash::new(schema).into(),
        iroha_core_zk::hash_vk(&vk_box),
    );
    record.status = iroha_data_model::confidential::ConfidentialStatus::Active;
    record.gas_schedule_id = Some("sched_cross_ds".to_owned());
    record.vk_len = vk_box.bytes.len() as u32;
    record.max_proof_bytes = 8 * 1024 * 1024;
    record.key = Some(vk_box);
    let entry_hash = wait_for_route_probe_approval(
        client,
        InstructionBox::from(
            iroha_data_model::isi::verifying_keys::RegisterVerifyingKey { id: vk_id, record },
        ),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "register stark verifying key via ds1",
    )
    .await?;
    wait_for_committed_success(
        client,
        entry_hash,
        "commit stark verifying key registration via ds1",
    )
    .await?;
    Ok(())
}
fn build_stark_attachment(
    vk_ref: VerifyingKeyId,
    vk_box: &VerifyingKeyBox,
    circuit_id: &str,
    schema: &[u8],
) -> Result<ProofAttachment> {
    let proof = iroha_core_zk::prove_stark_fri_open_verify_envelope(
        STARK_BACKEND,
        circuit_id,
        vk_box,
        schema,
        vec![vec![[0x11_u8; 32]], vec![[0x22_u8; 32]]],
    )
    .map_err(|err| eyre!(err))?;
    Ok(ProofAttachment::new_ref(
        STARK_BACKEND.to_owned(),
        proof,
        vk_ref,
    ))
}
fn proof_id_for_attachment(attachment: &ProofAttachment) -> ProofId {
    ProofId {
        backend: attachment.backend.clone(),
        proof_hash: iroha_core_zk::hash_proof(&attachment.proof),
    }
}
async fn grant_manage_verifying_keys_permission(client: &Client) -> Result<()> {
    let manage_vk = Permission::new("CanManageVerifyingKeys".to_string(), Json::new(()));
    let entry_hash = wait_for_route_probe_approval(
        client,
        InstructionBox::from(Grant::account_permission(manage_vk, ALICE_ID.clone())),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "grant manage verifying keys via ds1",
    )
    .await?;
    wait_for_committed_success(
        client,
        entry_hash,
        "commit manage verifying keys grant via ds1",
    )
    .await?;
    Ok(())
}
fn proof_marker(proof_bytes: &[u8]) -> Vec<u8> {
    if proof_bytes.is_empty() {
        return Vec::new();
    }
    let width = proof_bytes.len().min(16);
    let start = (proof_bytes.len().saturating_sub(width)) / 2;
    proof_bytes[start..start + width].to_vec()
}
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
fn assert_payload_redacted(payload: &[u8], marker: &[u8], context: &str) -> Result<()> {
    ensure!(
        !marker.is_empty(),
        "{context}: proof marker is empty; cannot validate redaction"
    );
    ensure!(
        !contains_subsequence(payload, marker),
        "{context}: payload leaked binary proof marker {}",
        hex::encode(marker)
    );
    let marker_hex = hex::encode(marker);
    ensure!(
        !contains_subsequence(payload, marker_hex.as_bytes()),
        "{context}: payload leaked hex proof marker {marker_hex}"
    );
    let marker_base64 = base64::engine::general_purpose::STANDARD.encode(marker);
    ensure!(
        !contains_subsequence(payload, marker_base64.as_bytes()),
        "{context}: payload leaked base64 proof marker {marker_base64}"
    );
    Ok(())
}
fn parse_hex32(input: &str) -> Option<[u8; 32]> {
    let hex = input.strip_prefix("0x").unwrap_or(input);
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_char(*bytes.get(2 * i)?)?;
        let lo = hex_char(*bytes.get(2 * i + 1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}
fn tamper_stark_attachment_inner_envelope(attachment: &ProofAttachment) -> Result<ProofAttachment> {
    let mut tampered = attachment.clone();
    let mut open_verify: OpenVerifyEnvelope = norito::decode_from_bytes(&tampered.proof.bytes)?;
    ensure!(
        open_verify.backend == BackendTag::Stark,
        "tamper helper expected STARK backend envelope"
    );
    let mut open: StarkFriOpenProofV1 = norito::decode_from_bytes(&open_verify.proof_bytes)?;
    ensure!(
        !open.envelope_bytes.is_empty(),
        "tamper helper cannot mutate empty STARK inner envelope"
    );
    let pivot = open.envelope_bytes.len() / 2;
    open.envelope_bytes[pivot] ^= 0x01;
    open_verify.proof_bytes = norito::to_bytes(&open)?;
    tampered.proof.bytes = norito::to_bytes(&open_verify)?;
    Ok(tampered)
}
fn hex_char(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}
fn parse_proof_id_from_json(value: &norito::json::Value) -> Option<ProofId> {
    match value {
        norito::json::Value::String(s) => s.parse::<ProofId>().ok(),
        norito::json::Value::Object(map) => {
            let backend = map.get("backend")?.as_str()?;
            let proof_hash = map
                .get("proof_hash")
                .and_then(|v| match v {
                    norito::json::Value::String(s) => parse_hex32(s),
                    norito::json::Value::Array(arr) if arr.len() == 32 => {
                        let mut out = [0u8; 32];
                        for (i, item) in arr.iter().enumerate() {
                            let n = u8::try_from(item.as_u64()?).ok()?;
                            out[i] = n;
                        }
                        Some(out)
                    }
                    _ => None,
                })
                .unwrap_or([0; 32]);
            Some(ProofId {
                backend: backend.into(),
                proof_hash,
            })
        }
        _ => None,
    }
}
fn parse_proof_status_from_json(value: &norito::json::Value) -> Option<ProofStatus> {
    match value.as_str()? {
        "Submitted" => Some(ProofStatus::Submitted),
        "Verified" => Some(ProofStatus::Verified),
        "Rejected" => Some(ProofStatus::Rejected),
        _ => None,
    }
}
fn decode_proof_record_payload(payload: &[u8]) -> Result<ProofRecord> {
    if payload.len() >= norito::core::Header::SIZE && payload.starts_with(&norito::core::MAGIC) {
        let rec: ProofRecord = norito::decode_from_bytes(payload)?;
        return Ok(rec);
    }
    let value: norito::json::Value = norito::json::from_slice(payload)?;
    if let Ok(record) = norito::json::from_value::<ProofRecord>(value.clone()) {
        return Ok(record);
    }
    let id = value
        .get("id")
        .and_then(parse_proof_id_from_json)
        .ok_or_else(|| eyre!("proof response missing id"))?;
    let status = value
        .get("status")
        .and_then(parse_proof_status_from_json)
        .ok_or_else(|| eyre!("proof response missing status"))?;
    Ok(ProofRecord {
        id,
        vk_ref: None,
        vk_commitment: None,
        status,
        verified_at_height: None,
        bridge: None,
    })
}
async fn fetch_proof_record_payload(
    observer: &Client,
    proof_id: &ProofId,
) -> Result<Option<(ProofRecord, Vec<u8>)>> {
    let mut url = observer.endpoint().clone();
    {
        let mut segments = url
            .path_segments_mut()
            .expect("torii_url must be a base URL");
        segments.clear();
        let proof_id_string = proof_id.to_string();
        segments.extend(["v1", "proofs", proof_id_string.as_str()]);
    }
    let response = HttpClient::builder()
        .timeout(PROOF_FETCH_HTTP_TIMEOUT)
        .build()?
        .get(url)
        .header("Accept", "application/x-norito, application/json")
        .send()
        .await?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response.error_for_status()?;
    let payload = response.bytes().await?.to_vec();
    let record = decode_proof_record_payload(&payload)?;
    Ok(Some((record, payload)))
}
fn query_proof_record_via_signed_query(
    observer: &Client,
    proof_id: &ProofId,
) -> Result<ProofRecord> {
    let mut builder = observer.to_builder();
    builder.torii_request_timeout = builder.torii_request_timeout.min(PROOF_FETCH_HTTP_TIMEOUT);
    let client = builder.build()?;
    let record = client.query_single(FindProofRecordById {
        id: proof_id.clone(),
    })?;
    ensure!(
        &record.id == proof_id,
        "exact proof query returned a different proof"
    );
    Ok(record)
}
async fn wait_for_proof_record_status(
    observer: &Client,
    proof_id: &ProofId,
    expected_status: ProofStatus,
    context: &str,
) -> Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + STATUS_WAIT_TIMEOUT;
    let mut last_status = None;
    let mut last_error = None;
    loop {
        match fetch_proof_record_payload(observer, proof_id).await {
            Ok(Some((record, payload))) => {
                if record.status == expected_status {
                    return Ok(payload);
                }
                last_status = Some(record.status);
            }
            Ok(None) => {
                last_error = Some("proof record not found yet".to_owned());
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let status_suffix = last_status
                .map(|status| format!("; last observed status: {status:?}"))
                .unwrap_or_default();
            let error_suffix = last_error
                .map(|err| format!("; last error: {err}"))
                .unwrap_or_default();
            let query_observer = observer.clone();
            let query_proof_id = proof_id.clone();
            let signed_query_suffix = match read_on_dedicated_thread(move || {
                query_proof_record_via_signed_query(&query_observer, &query_proof_id)
            })
            .await
            {
                Ok(record) => format!(
                    "; signed query observed status {:?} for {}",
                    record.status, record.id
                ),
                Err(err) => format!("; signed query error: {err}"),
            };
            return Err(eyre!(
                "{context}: timed out waiting for proof status {expected_status:?}{status_suffix}{error_suffix}{signed_query_suffix}"
            ));
        }
        sleep(STATUS_POLL_INTERVAL).await;
    }
}
async fn wait_for_absent_proof_record(
    observer: &Client,
    proof_id: &ProofId,
    context: &str,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + STATUS_WAIT_TIMEOUT;
    let mut saw_not_found = false;
    let mut last_error = None;
    loop {
        match fetch_proof_record_payload(observer, proof_id).await {
            Ok(None) => {
                saw_not_found = true;
            }
            Ok(Some((record, _payload))) => {
                return Err(eyre!(
                    "{context}: expected proof record to stay absent, observed status {:?}",
                    record.status
                ));
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            if saw_not_found {
                return Ok(());
            }
            let error_suffix = last_error
                .map(|err| format!("; last error: {err}"))
                .unwrap_or_default();
            return Err(eyre!(
                "{context}: timed out waiting for proof record to remain absent{error_suffix}"
            ));
        }
        sleep(STATUS_POLL_INTERVAL).await;
    }
}
#[tokio::test]
#[ignore = "native STARK/FRI V1 proving fails closed until AIR openings are implemented"]
async fn stark_cross_dataspace_verifyproof_validity_without_payload_leak() -> Result<()> {
    require_test_network_feature(
        "zk-stark",
        stringify!(stark_cross_dataspace_verifyproof_validity_without_payload_leak),
    )?;
    let Some(network) = sandbox::start_network_async_or_skip(
        localnet_builder(),
        stringify!(stark_cross_dataspace_verifyproof_validity_without_payload_leak),
    )
    .await?
    else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let alice = network.client().client().clone();
    let bob = network
        .peer()
        .client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone())
        .client()
        .clone();
    let nexus_observer_id = AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
    let nexus_observer = network
        .peer()
        .client_for(
            &nexus_observer_id,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key().clone(),
        )
        .client()
        .clone();
    let expected_validators = expected_lane_validators(&network);
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(NEXUS_LANE_INDEX),
        &expected_validators,
        "nexus lane validator activation",
    )
    .await?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS1_LANE_INDEX),
        &expected_validators,
        "ds1 lane validator activation",
    )
    .await?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS2_LANE_INDEX),
        &expected_validators,
        "ds2 lane validator activation",
    )
    .await?;
    wait_for_route_probe_approval(
        &alice,
        InstructionBox::from(Log::new(Level::INFO, "route probe ds1".to_owned())),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "route probe ds1",
    )
    .await?;
    wait_for_route_probe_approval(
        &bob,
        InstructionBox::from(Log::new(Level::INFO, "route probe ds2".to_owned())),
        LaneId::new(DS2_LANE_INDEX),
        DataSpaceId::new(DS2_ID_U64),
        "route probe ds2",
    )
    .await?;
    grant_manage_verifying_keys_permission(&alice).await?;
    let valid_vk_id = VerifyingKeyId::new(STARK_BACKEND, "cross_ds_stark_verifyproof_ok");
    let valid_vk_box = sample_stark_vk_box(
        CIRCUIT_ID_VALID,
        iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
    );
    register_stark_vk(
        &alice,
        valid_vk_id.clone(),
        valid_vk_box.clone(),
        CIRCUIT_ID_VALID,
        SCHEMA_VALID,
    )
    .await?;
    let attachment =
        build_stark_attachment(valid_vk_id, &valid_vk_box, CIRCUIT_ID_VALID, SCHEMA_VALID)?;
    let marker = proof_marker(&attachment.proof.bytes);
    let verifyproof_entry_hash = wait_for_route_probe_approval(
        &alice,
        InstructionBox::from(VerifyProof::new(attachment.clone())),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "verifyproof submit ds1",
    )
    .await?;
    wait_for_committed_success(
        &alice,
        verifyproof_entry_hash,
        "commit verifyproof submit ds1",
    )
    .await?;
    network.ensure_blocks(2).await?;
    let proof_id = proof_id_for_attachment(&attachment);
    let ds1_submitter_payload = wait_for_proof_record_status(
        &alice,
        &proof_id,
        ProofStatus::Verified,
        "observe verified proof status from ds1 submitter",
    )
    .await?;
    assert_payload_redacted(&ds1_submitter_payload, &marker, "ds1 submitter payload")?;
    let ds2_observer_payload = wait_for_proof_record_status(
        &bob,
        &proof_id,
        ProofStatus::Verified,
        "observe verified proof status from ds2 observer",
    )
    .await?;
    assert_payload_redacted(&ds2_observer_payload, &marker, "ds2 observer payload")?;
    let nexus_observer_payload = wait_for_proof_record_status(
        &nexus_observer,
        &proof_id,
        ProofStatus::Verified,
        "observe verified proof status from nexus observer",
    )
    .await?;
    assert_payload_redacted(&nexus_observer_payload, &marker, "nexus observer payload")?;
    Ok(())
}
#[tokio::test]
#[ignore = "native STARK/FRI V1 proving fails closed until AIR openings are implemented"]
async fn stark_cross_dataspace_verifyproof_validity_ds2_submission_without_payload_leak()
-> Result<()> {
    require_test_network_feature(
        "zk-stark",
        stringify!(stark_cross_dataspace_verifyproof_validity_ds2_submission_without_payload_leak),
    )?;
    let Some(network) = sandbox::start_network_async_or_skip(
        localnet_builder(),
        stringify!(stark_cross_dataspace_verifyproof_validity_ds2_submission_without_payload_leak),
    )
    .await?
    else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let alice = network.client().client().clone();
    let bob = network
        .peer()
        .client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone())
        .client()
        .clone();
    let nexus_observer_id = AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
    let nexus_observer = network
        .peer()
        .client_for(
            &nexus_observer_id,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key().clone(),
        )
        .client()
        .clone();
    let expected_validators = expected_lane_validators(&network);
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(NEXUS_LANE_INDEX),
        &expected_validators,
        "nexus lane validator activation",
    )
    .await?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS1_LANE_INDEX),
        &expected_validators,
        "ds1 lane validator activation",
    )
    .await?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS2_LANE_INDEX),
        &expected_validators,
        "ds2 lane validator activation",
    )
    .await?;
    wait_for_route_probe_approval(
        &alice,
        InstructionBox::from(Log::new(Level::INFO, "route probe ds1".to_owned())),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "route probe ds1",
    )
    .await?;
    wait_for_route_probe_approval(
        &bob,
        InstructionBox::from(Log::new(Level::INFO, "route probe ds2".to_owned())),
        LaneId::new(DS2_LANE_INDEX),
        DataSpaceId::new(DS2_ID_U64),
        "route probe ds2",
    )
    .await?;
    grant_manage_verifying_keys_permission(&alice).await?;
    let valid_vk_id = VerifyingKeyId::new(STARK_BACKEND, "cross_ds_stark_verifyproof_ok");
    let valid_vk_box = sample_stark_vk_box(
        CIRCUIT_ID_VALID,
        iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
    );
    register_stark_vk(
        &alice,
        valid_vk_id.clone(),
        valid_vk_box.clone(),
        CIRCUIT_ID_VALID,
        SCHEMA_VALID,
    )
    .await?;
    let attachment =
        build_stark_attachment(valid_vk_id, &valid_vk_box, CIRCUIT_ID_VALID, SCHEMA_VALID)?;
    let marker = proof_marker(&attachment.proof.bytes);
    let verifyproof_entry_hash = wait_for_route_probe_approval(
        &bob,
        InstructionBox::from(VerifyProof::new(attachment.clone())),
        LaneId::new(DS2_LANE_INDEX),
        DataSpaceId::new(DS2_ID_U64),
        "verifyproof submit ds2",
    )
    .await?;
    wait_for_committed_success(
        &bob,
        verifyproof_entry_hash,
        "commit verifyproof submit ds2",
    )
    .await?;
    network.ensure_blocks(2).await?;
    let proof_id = proof_id_for_attachment(&attachment);
    let ds2_submitter_payload = wait_for_proof_record_status(
        &bob,
        &proof_id,
        ProofStatus::Verified,
        "observe verified proof status from ds2 submitter",
    )
    .await?;
    assert_payload_redacted(&ds2_submitter_payload, &marker, "ds2 submitter payload")?;
    let ds1_observer_payload = wait_for_proof_record_status(
        &alice,
        &proof_id,
        ProofStatus::Verified,
        "observe verified proof status from ds1 observer",
    )
    .await?;
    assert_payload_redacted(&ds1_observer_payload, &marker, "ds1 observer payload")?;
    let nexus_observer_payload = wait_for_proof_record_status(
        &nexus_observer,
        &proof_id,
        ProofStatus::Verified,
        "observe verified proof status from nexus observer",
    )
    .await?;
    assert_payload_redacted(&nexus_observer_payload, &marker, "nexus observer payload")?;
    Ok(())
}
#[tokio::test]
#[ignore = "native STARK/FRI V1 proving fails closed until AIR openings are implemented"]
async fn stark_cross_dataspace_verifyproof_rejection_without_payload_leak() -> Result<()> {
    require_test_network_feature(
        "zk-stark",
        stringify!(stark_cross_dataspace_verifyproof_rejection_without_payload_leak),
    )?;
    let Some(network) = sandbox::start_network_async_or_skip(
        localnet_builder(),
        stringify!(stark_cross_dataspace_verifyproof_rejection_without_payload_leak),
    )
    .await?
    else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let alice = network.client().client().clone();
    let bob = network
        .peer()
        .client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone())
        .client()
        .clone();
    let nexus_observer_id = AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
    let nexus_observer = network
        .peer()
        .client_for(
            &nexus_observer_id,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key().clone(),
        )
        .client()
        .clone();
    let expected_validators = expected_lane_validators(&network);
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(NEXUS_LANE_INDEX),
        &expected_validators,
        "nexus lane validator activation",
    )
    .await?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS1_LANE_INDEX),
        &expected_validators,
        "ds1 lane validator activation",
    )
    .await?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS2_LANE_INDEX),
        &expected_validators,
        "ds2 lane validator activation",
    )
    .await?;
    wait_for_route_probe_approval(
        &alice,
        InstructionBox::from(Log::new(Level::INFO, "route probe ds1".to_owned())),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "route probe ds1",
    )
    .await?;
    wait_for_route_probe_approval(
        &bob,
        InstructionBox::from(Log::new(Level::INFO, "route probe ds2".to_owned())),
        LaneId::new(DS2_LANE_INDEX),
        DataSpaceId::new(DS2_ID_U64),
        "route probe ds2",
    )
    .await?;
    grant_manage_verifying_keys_permission(&alice).await?;
    let valid_vk_id = VerifyingKeyId::new(STARK_BACKEND, "cross_ds_stark_verifyproof_ok");
    let valid_vk_box = sample_stark_vk_box(
        CIRCUIT_ID_VALID,
        iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
    );
    register_stark_vk(
        &alice,
        valid_vk_id.clone(),
        valid_vk_box.clone(),
        CIRCUIT_ID_VALID,
        SCHEMA_VALID,
    )
    .await?;
    let mismatch_vk_id = VerifyingKeyId::new(STARK_BACKEND, "cross_ds_stark_verifyproof_bad");
    let mismatch_vk_box = sample_stark_vk_box(
        CIRCUIT_ID_MISMATCH,
        iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_N_LOG2 + 1,
    );
    register_stark_vk(
        &alice,
        mismatch_vk_id.clone(),
        mismatch_vk_box,
        CIRCUIT_ID_MISMATCH,
        SCHEMA_MISMATCH,
    )
    .await?;
    let valid_attachment =
        build_stark_attachment(valid_vk_id, &valid_vk_box, CIRCUIT_ID_VALID, SCHEMA_VALID)?;
    let mismatched_attachment = ProofAttachment::new_ref(
        STARK_BACKEND.to_owned(),
        valid_attachment.proof.clone(),
        mismatch_vk_id,
    );
    let _rejection_reason = wait_for_route_probe_rejection(
        &alice,
        InstructionBox::from(VerifyProof::new(mismatched_attachment.clone())),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "verifyproof submit ds1 mismatched vk",
    )
    .await?;
    let proof_id = proof_id_for_attachment(&mismatched_attachment);
    wait_for_absent_proof_record(
        &bob,
        &proof_id,
        "observe absent proof record from ds2 observer",
    )
    .await?;
    wait_for_absent_proof_record(
        &nexus_observer,
        &proof_id,
        "observe absent proof record from nexus observer",
    )
    .await?;
    let mut malformed_attachment = valid_attachment.clone();
    malformed_attachment.proof.bytes.clear();
    let _malformed_rejection_reason = wait_for_route_probe_rejection(
        &alice,
        InstructionBox::from(VerifyProof::new(malformed_attachment.clone())),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "verifyproof submit ds1 malformed proof",
    )
    .await?;
    let malformed_proof_id = proof_id_for_attachment(&malformed_attachment);
    wait_for_absent_proof_record(
        &bob,
        &malformed_proof_id,
        "observe absent malformed proof record from ds2 observer",
    )
    .await?;
    wait_for_absent_proof_record(
        &nexus_observer,
        &malformed_proof_id,
        "observe absent malformed proof record from nexus observer",
    )
    .await?;
    Ok(())
}
#[tokio::test]
#[ignore = "native STARK/FRI V1 proving fails closed until AIR openings are implemented"]
async fn stark_cross_dataspace_verifyproof_tampered_payload_rejected_without_payload_leak()
-> Result<()> {
    require_test_network_feature(
        "zk-stark",
        stringify!(
            stark_cross_dataspace_verifyproof_tampered_payload_rejected_without_payload_leak
        ),
    )?;
    let Some(network) = sandbox::start_network_async_or_skip(
        localnet_builder(),
        stringify!(
            stark_cross_dataspace_verifyproof_tampered_payload_rejected_without_payload_leak
        ),
    )
    .await?
    else {
        return Ok(());
    };
    network.ensure_blocks(1).await?;
    let alice = network.client().client().clone();
    let bob = network
        .peer()
        .client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone())
        .client()
        .clone();
    let nexus_observer_id = AccountId::new(SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
    let nexus_observer = network
        .peer()
        .client_for(
            &nexus_observer_id,
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.private_key().clone(),
        )
        .client()
        .clone();
    let expected_validators = expected_lane_validators(&network);
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(NEXUS_LANE_INDEX),
        &expected_validators,
        "nexus lane validator activation",
    )
    .await?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS1_LANE_INDEX),
        &expected_validators,
        "ds1 lane validator activation",
    )
    .await?;
    wait_for_active_lane_validators(
        &alice,
        LaneId::new(DS2_LANE_INDEX),
        &expected_validators,
        "ds2 lane validator activation",
    )
    .await?;
    wait_for_route_probe_approval(
        &alice,
        InstructionBox::from(Log::new(Level::INFO, "route probe ds1".to_owned())),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "route probe ds1",
    )
    .await?;
    wait_for_route_probe_approval(
        &bob,
        InstructionBox::from(Log::new(Level::INFO, "route probe ds2".to_owned())),
        LaneId::new(DS2_LANE_INDEX),
        DataSpaceId::new(DS2_ID_U64),
        "route probe ds2",
    )
    .await?;
    grant_manage_verifying_keys_permission(&alice).await?;
    let valid_vk_id = VerifyingKeyId::new(STARK_BACKEND, "cross_ds_stark_verifyproof_ok");
    let valid_vk_box = sample_stark_vk_box(
        CIRCUIT_ID_VALID,
        iroha_core_zk::stark::STARK_FRI_CONSENSUS_MIN_N_LOG2,
    );
    register_stark_vk(
        &alice,
        valid_vk_id.clone(),
        valid_vk_box.clone(),
        CIRCUIT_ID_VALID,
        SCHEMA_VALID,
    )
    .await?;
    let valid_attachment =
        build_stark_attachment(valid_vk_id, &valid_vk_box, CIRCUIT_ID_VALID, SCHEMA_VALID)?;
    let tampered_attachment = tamper_stark_attachment_inner_envelope(&valid_attachment)?;
    let marker = proof_marker(&tampered_attachment.proof.bytes);
    let verifyproof_entry_hash = wait_for_route_probe_approval(
        &alice,
        InstructionBox::from(VerifyProof::new(tampered_attachment.clone())),
        LaneId::new(DS1_LANE_INDEX),
        DataSpaceId::new(DS1_ID_U64),
        "verifyproof submit ds1 tampered payload",
    )
    .await?;
    wait_for_committed_success(
        &alice,
        verifyproof_entry_hash,
        "commit verifyproof submit ds1 tampered payload",
    )
    .await?;
    network.ensure_blocks(2).await?;
    let proof_id = proof_id_for_attachment(&tampered_attachment);
    let ds1_submitter_payload = wait_for_proof_record_status(
        &alice,
        &proof_id,
        ProofStatus::Rejected,
        "observe rejected proof status from ds1 submitter",
    )
    .await?;
    assert_payload_redacted(&ds1_submitter_payload, &marker, "ds1 submitter payload")?;
    let ds2_observer_payload = wait_for_proof_record_status(
        &bob,
        &proof_id,
        ProofStatus::Rejected,
        "observe rejected proof status from ds2 observer",
    )
    .await?;
    assert_payload_redacted(&ds2_observer_payload, &marker, "ds2 observer payload")?;
    let nexus_observer_payload = wait_for_proof_record_status(
        &nexus_observer,
        &proof_id,
        ProofStatus::Rejected,
        "observe rejected proof status from nexus observer",
    )
    .await?;
    assert_payload_redacted(&nexus_observer_payload, &marker, "nexus observer payload")?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::{
        DS1_ID_U64, DS1_MANIFEST_HASH, DS2_ID_U64, DS2_MANIFEST_HASH, NEXUS_ALIAS, NEXUS_ID_U64,
        ProofId, STARK_BACKEND, decode_proof_record_payload, parse_proof_status_from_json,
    };
    use iroha::data_model::proof::{ProofRecord, ProofStatus};
    use iroha_model_base::topology::DataSpaceId;
    fn sample_proof_id() -> ProofId {
        ProofId {
            backend: STARK_BACKEND.into(),
            proof_hash: [0xAB; 32],
        }
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
    fn decode_proof_record_payload_accepts_minimal_json_object_shape() {
        let payload = format!(
            r#"{{
                "id": {{
                    "backend": "{backend}",
                    "proof_hash": "{proof_hash}"
                }},
                "status": "Rejected"
            }}"#,
            backend = STARK_BACKEND,
            proof_hash = hex::encode([0xAB; 32]),
        );
        let record = decode_proof_record_payload(payload.as_bytes()).expect("decode JSON payload");
        assert_eq!(record.id, sample_proof_id());
        assert_eq!(record.status, ProofStatus::Rejected);
    }
    #[test]
    fn decode_proof_record_payload_accepts_norito_record_payload() {
        let record = ProofRecord {
            id: sample_proof_id(),
            vk_ref: None,
            vk_commitment: None,
            status: ProofStatus::Verified,
            verified_at_height: None,
            bridge: None,
        };
        let payload = norito::to_bytes(&record).expect("encode norito proof record");
        let decoded = decode_proof_record_payload(&payload).expect("decode norito payload");
        assert_eq!(decoded.id, record.id);
        assert_eq!(decoded.status, ProofStatus::Verified);
    }
    #[test]
    fn parse_proof_status_from_json_rejects_unknown_status_strings() {
        let value =
            norito::json::from_str::<norito::json::Value>(r#""PendingApproval""#).expect("json");
        assert!(parse_proof_status_from_json(&value).is_none());
    }
}

#[test]
fn genesis_staking_plans_bind_funded_validators_to_configured_custody() {
    iroha_test_network::init_instruction_registry();
    let entries = (0..4)
        .map(|index| {
            let key = iroha_crypto::KeyPair::try_from_seed(
                vec![index + 1; 32],
                iroha_crypto::Algorithm::BlsNormal,
            )
            .expect("deterministic genesis staking validator");
            GenesisTopologyEntry::new(
                PeerId::new(key.public_key().clone()),
                iroha_crypto::bls_normal_pop_prove(key.private_key())
                    .expect("deterministic genesis staking validator PoP"),
            )
        })
        .collect::<Vec<_>>();
    let topology = entries
        .iter()
        .map(|entry| entry.peer.clone())
        .collect::<Vec<_>>();
    let transactions = npos_multilane_genesis_post_topology_transactions(&topology, &entries);
    let committee_registrations = transactions
        .iter()
        .flatten()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<RegisterConsensusKey>())
        .collect::<Vec<_>>();
    assert_eq!(committee_registrations.len(), TOTAL_PEERS);
    for (registration, peer) in committee_registrations.iter().zip(&topology) {
        assert_eq!(registration.id, derive_committee_key_id(peer.public_key()));
    }
    let registrations = transactions
        .iter()
        .flatten()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
        })
        .collect::<Vec<_>>();
    assert_eq!(registrations.len(), 12);
    for registration in registrations {
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
            iroha_data_model::asset::AssetId::new(stake_asset_definition_id(), ALICE_ID.clone())
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
}
