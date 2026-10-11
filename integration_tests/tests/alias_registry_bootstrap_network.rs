//! Genuine four-validator NPoS alias bootstrap and retained-Kura replay.
//!
//! This isolated network uses the native SNS policy, signed planner and paid
//! leases. Ordinary transaction fees are zero from genesis to isolate lease
//! accounting; this is not production-fee qualification. Paid alias routing
//! uses the universal registry from genesis, before any private catalog entry.
//! No unchecked blocks, fabricated certificates, injected WSV or storage reset
//! may substitute for the original persisted history and Strict daemon replay.
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fs,
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use eyre::{Result, WrapErr as _, ensure, eyre};
use futures_util::future::try_join_all;

use integration_tests::sandbox;
use iroha::{blocking::Client, sns::SnsNamespacePath};
use iroha_config::{
    base::WithOrigin,
    kura::FsyncMode,
    parameters::{
        actual::{Kura as KuraConfig, LaneConfig as ActualLaneConfig},
        defaults,
    },
};
use iroha_core::{
    kura::{BlockIndex, BlockStore, Kura},
    state::{AllocationBudget, derive_committee_key_id},
    sumeragi::{
        availability_schedule::AvailabilitySchedule,
        certified_chain::CertifiedPrefix,
        crypto::BlsCrypto,
        lanes::{
            self, AnchorView, LaneBatch, LaneChainView, evidence::verify_lane_entry,
            store::LaneFrameRead,
        },
    },
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    Level,
    alias_setup::{
        ALIAS_LEASE_YEAR_MS, AliasDataSpaceIntentV1, AliasDataspaceBootstrapGrantV1,
        AliasDomainIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1, AliasPlanDispositionV1,
        AliasQuoteGuardV1, AliasSetupPlanRequestV1, ResolvedDomainV1,
    },
    asset::AssetDefinitionId,
    block::{SignedBlock, decode_framed_signed_block},
    isi::{
        Grant,
        alias_setup::EnsureAlias,
        consensus_keys::RegisterConsensusKey,
        staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
    },
    nexus::{
        LaneCatalog, LaneConfig as ModelLaneConfig, LaneLifecycleParameterV1, LaneLifecyclePlan,
        LaneLifecycleStatusV1, LaneVisibility, PublicLaneMonetaryPreconditionV1,
        PublicLaneMonetaryScopeV1, PublicLanePreparationOperationV1,
        PublicLanePreparationRequestV1, PublicLanePrepareRegistrationV1, PublicLanePreparedPlanV1,
    },
    parameter::{
        Parameters,
        system::{ConsensusMode, SumeragiNposParameters, SumeragiParameters},
    },
    prelude::*,
    sns::{NameRecordV1, NameSelectorV1, NameStatus, SuffixPolicyV1},
    sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLanePolicy,
        SumeragiLaneRecord, SumeragiLaneRoute, SumeragiLaneState,
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionEntrypoint},
};
use iroha_executor_data_model::permission::peer::CanManagePeers;
use iroha_genesis::{GenesisBlock, GenesisTopologyEntry};
use iroha_model_base::chain::ChainId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_primitives::json::Json;
use iroha_sumeragi::types::{Hash32, HeightConfig};
use iroha_test_network::{
    NetworkBuilder, NetworkPeer, ReleasePrebuiltBinary,
    genesis_participant_committee_key_instructions, init_instruction_registry,
    resolve_release_prebuilt_binary, unexecuted_genesis_factory_with_post_topology,
};
use iroha_test_samples::{BOB_ID, BOB_KEYPAIR};
use tokio::time::{Instant, sleep, timeout};
use toml::{Table, Value as TomlValue};

const BPNG_ID: u64 = 8_648_377_547_929_788_715;
// Fixture-only lane identifier. It is deliberately sparse and must never be
// cited as evidence that lane 8 is operator-allocated on public Taira.
const BPNG_FIXTURE_LANE: LaneId = LaneId::new(8);
const VALIDATOR_COUNT: usize = 4;
const BPNG_MIN_QUORUM: u32 = 3;
const FIXTURE_EPOCH_LENGTH_BLOCKS: u64 = 8;
const NETWORK_SEED: &str =
    "integration-tests-alias-registry-bootstrap-retained-bpng-lane-fixture-only";
const TAIRA_XOR_ASSET_DEFINITION_ID: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";
const READ_TIMEOUT: Duration = Duration::from_secs(180);
const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(300);
const SUBMISSION_TASK_TIMEOUT: Duration = Duration::from_secs(360);
const NETWORK_TIMEOUT: Duration = Duration::from_secs(360);
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);
const ADVANCE_TIMEOUT: Duration = Duration::from_secs(900);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const TRANSACTION_TTL: Duration = Duration::from_secs(600);
const MAX_RETAINED_HEIGHT: u64 = 128;
const MAX_EVIDENCE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RELEASE_IDENTITY_BYTES: u64 = 32 * 1024;
const MAX_RELEASE_TOOL_OUTPUT_BYTES: usize = 64 * 1024;

fn validator_keypair(index: usize) -> KeyPair {
    KeyPair::try_from_seed(
        format!("{NETWORK_SEED}-peer-{index}").into_bytes(),
        Algorithm::Ed25519,
    )
    .expect("derive deterministic retained-BPNG-lane validator signer")
}

fn staking_custody_account() -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(
            format!("{NETWORK_SEED}-staking-custody").into_bytes(),
            Algorithm::Ed25519,
        )
        .expect("derive fixture custody identity")
        .public_key()
        .clone(),
    )
}

fn stake_asset_definition_id() -> AssetDefinitionId {
    let definition: AssetDefinitionId = defaults::nexus::staking::stake_asset_id()
        .parse()
        .expect("canonical network XOR asset");
    assert_eq!(
        definition,
        defaults::nexus::fees::fee_asset_id()
            .parse()
            .expect("canonical Nexus fee XOR asset"),
        "genesis staking and fees must use one real XOR definition"
    );
    assert_eq!(definition.to_string(), TAIRA_XOR_ASSET_DEFINITION_ID);
    definition
}

#[test]
fn retained_bpng_staking_uses_the_real_network_xor() {
    assert_eq!(
        stake_asset_definition_id(),
        SumeragiNposParameters::default().xor_asset_definition_id
    );
}

fn custom_genesis_post_topology(
    topology: &[PeerId],
    topology_entries: &[GenesisTopologyEntry],
) -> Vec<Vec<InstructionBox>> {
    assert_eq!(
        topology.len(),
        VALIDATOR_COUNT,
        "custom genesis requires exactly four BLS validator peers"
    );
    assert_eq!(
        topology_entries.len(),
        topology.len(),
        "every BPNG peer needs a proof-of-possession entry"
    );
    let stake_asset_id = stake_asset_definition_id();
    let stake = SumeragiNposParameters::default().min_self_bond().clone();
    let two_stakes = stake
        .checked_add(&stake)
        .expect("two validator self-stakes must be representable");
    let mut bootstrap: Vec<InstructionBox> = vec![
        Register::account(Account::new(staking_custody_account())).into(),
        Register::domain(Domain::new(
            DomainId::try_new("universal", "universal").expect("XOR domain"),
        ))
        .into(),
        Register::asset_definition(AssetDefinition::new(
            stake_asset_id.clone(),
            "XOR".to_owned(),
            iroha_primitives::numeric::NumericSpec::fractional(9),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ];
    let mut default_lane_validators: Vec<InstructionBox> = Vec::with_capacity(VALIDATOR_COUNT * 2);
    bootstrap.extend(genesis_participant_committee_key_instructions(
        topology_entries,
        topology,
    ));
    for (index, peer_id) in topology.iter().enumerate() {
        let validator = AccountId::new(validator_keypair(index).public_key().clone());
        bootstrap.push(Register::account(Account::new(validator.clone())).into());
        bootstrap.push(
            Mint::asset_quantity(
                two_stakes.clone(),
                AssetId::new(stake_asset_id.clone(), validator.clone()),
            )
            .into(),
        );
        bootstrap.push(Grant::account_permission(CanManagePeers, validator.clone()).into());
        default_lane_validators.push(
            RegisterPublicLaneValidator::new(
                LaneId::SINGLE,
                validator.clone(),
                peer_id.clone(),
                validator.clone(),
                stake.clone(),
                Metadata::default(),
                iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                    AssetId::new(stake_asset_id.clone(), validator.clone()),
                    AssetId::new(stake_asset_id.clone(), staking_custody_account()),
                    stake.clone(),
                ),
            )
            .into(),
        );
        default_lane_validators
            .push(ActivatePublicLaneValidator::new(LaneId::SINGLE, validator).into());
    }
    for instruction in &default_lane_validators {
        if let Some(registration) = instruction
            .as_any()
            .downcast_ref::<RegisterPublicLaneValidator>()
        {
            assert_eq!(
                registration.monetary_plan,
                iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                    AssetId::new(
                        stake_asset_definition_id(),
                        registration.stake_account.clone()
                    ),
                    AssetId::new(stake_asset_definition_id(), staking_custody_account()),
                    registration.initial_stake.clone(),
                ),
                "fixture registration must agree with its explicitly authored staking config"
            );
        }
    }
    vec![bootstrap, default_lane_validators]
}

fn bounded_client(client: Client) -> Client {
    integration_tests::sync::rebind_blocking_client(&client, |client| {
        client.transaction_status_timeout = SUBMISSION_TIMEOUT;
        client.transaction_ttl = Some(TRANSACTION_TTL);
        client.torii_request_timeout = Duration::from_secs(20);
    })
}

async fn read<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    timeout(
        READ_TIMEOUT,
        iroha_test_network::read_on_dedicated_thread(operation),
    )
    .await
    .wrap_err("bounded fixture read timed out")?
    .wrap_err("fixture read task failed")
}

async fn height(client: &Client) -> Result<u64> {
    Ok(client.client().status().get().await?.blocks)
}

async fn lane_lifecycle_status(client: &Client) -> Result<LaneLifecycleStatusV1> {
    let client = client.clone();
    read(move || client.client().get_lane_lifecycle_status()).await
}

async fn common_retained_prefix(clients: &[Client]) -> Result<u64> {
    let mut common = u64::MAX;
    for client in clients {
        common = common.min(height(client).await?);
    }
    ensure!(
        (1..=MAX_RETAINED_HEIGHT).contains(&common),
        "common four-peer retained prefix is missing or exceeds the fixture bound"
    );
    Ok(common)
}

async fn observe_catalog_expansion(
    client: &Client,
    bpng_configured: bool,
) -> Result<LaneLifecycleStatusV1> {
    let lane_client = client.clone();
    let lanes = read(move || {
        let status = lane_client.client().get_lane_lifecycle_status()?;
        ensure!(
            status.validate()? == LaneCatalog::default(),
            "dataspace-only expansion changed the original lane catalog"
        );
        Ok(status)
    })
    .await?;
    // This namespace parses through the daemon's actual static catalog before
    // looking in SNS state. A paid dataspace lease alone cannot satisfy it.
    // Status telemetry instead projects lane-backed dataspaces, so it cannot
    // prove this deliberately lane-free catalog addition.
    let url = client
        .client()
        .endpoint()
        .join("v1/sns/names/account-alias/catalog-probe@mibank.bpng")?;
    let mut response = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(url)
        .send()
        .await?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len().saturating_add(chunk.len()) <= 4096,
            "catalog probe response exceeded its fixed budget"
        );
        body.extend_from_slice(&chunk);
    }
    let (expected_status, expected_body) = if bpng_configured {
        (404, "registration `catalog-probe@mibank.bpng` not found")
    } else {
        (400, "unknown dataspace alias in account alias")
    };
    ensure!(
        status == expected_status && body == expected_body.as_bytes(),
        "live BPNG catalog probe did not match the expected configured state: configured={bpng_configured}, status={status}"
    );
    Ok(lanes)
}

async fn submit(client: &Client, transaction: SignedTransaction) -> Result<SignedTransaction> {
    timeout(
        SUBMISSION_TASK_TIMEOUT,
        client
            .account_client()
            .submit_transaction_and_wait(&transaction),
    )
    .await
    .wrap_err("native transaction did not reach terminal status in time")?
    .wrap_err("native submission failed")?;
    Ok(transaction)
}

fn bpng_fixture_lane() -> ModelLaneConfig {
    ModelLaneConfig {
        id: BPNG_FIXTURE_LANE,
        dataspace_id: DataSpaceId::new(BPNG_ID),
        alias: "bpng-fixture-only-lane-8".to_owned(),
        description: Some(
            "integration fixture only; not a public-Taira lane allocation".to_owned(),
        ),
        visibility: LaneVisibility::Public,
        ..ModelLaneConfig::default()
    }
}

fn dataspace_only_restart_layer(grant: &AliasDataspaceBootstrapGrantV1) -> Table {
    let universal = Table::from_iter([
        (
            "alias".to_owned(),
            TomlValue::String("universal".to_owned()),
        ),
        ("id".to_owned(), TomlValue::Integer(0)),
        ("fault_tolerance".to_owned(), TomlValue::Integer(1)),
    ]);
    let bpng = Table::from_iter([
        ("alias".to_owned(), TomlValue::String("bpng".to_owned())),
        (
            "manifest_hash".to_owned(),
            TomlValue::String(hex::encode(grant.name_hash)),
        ),
        (
            "id".to_owned(),
            TomlValue::Integer(i64::try_from(BPNG_ID).expect("BPNG id fits i64")),
        ),
        ("fault_tolerance".to_owned(), TomlValue::Integer(1)),
    ]);
    let nexus = Table::from_iter([(
        "dataspace_catalog".to_owned(),
        TomlValue::Array(vec![TomlValue::Table(universal), TomlValue::Table(bpng)]),
    )]);
    debug_assert!(
        nexus.len() == 1 && nexus.contains_key("dataspace_catalog"),
        "restart layer must add only the static BPNG dataspace"
    );
    Table::from_iter([("nexus".to_owned(), TomlValue::Table(nexus))])
}

fn assert_bpng_lifecycle_status(
    status: &LaneLifecycleStatusV1,
    expected_original: &LaneLifecycleStatusV1,
) -> Result<Hash> {
    let original_catalog = expected_original.validate()?;
    ensure!(
        original_catalog == LaneCatalog::default(),
        "fixture must begin from the single universal lane"
    );
    let expected_catalog = original_catalog.apply_lifecycle(&LaneLifecyclePlan {
        additions: vec![bpng_fixture_lane()],
        retire: Vec::new(),
    })?;
    ensure!(
        status.validate()? == expected_catalog,
        "signed lifecycle did not add exactly fixture-only lane 8"
    );
    let original_incarnation = expected_original
        .incarnations
        .iter()
        .find(|entry| entry.lane_id == LaneId::SINGLE)
        .ok_or_else(|| eyre!("original universal incarnation missing"))?;
    let retained_original = status
        .incarnations
        .iter()
        .find(|entry| entry.lane_id == LaneId::SINGLE)
        .ok_or_else(|| eyre!("post-lifecycle universal incarnation missing"))?;
    ensure!(
        original_incarnation == retained_original,
        "adding BPNG changed the universal lane incarnation"
    );
    let bpng = status
        .incarnations
        .iter()
        .find(|entry| entry.lane_id == BPNG_FIXTURE_LANE)
        .ok_or_else(|| eyre!("fixture-only BPNG lane incarnation missing"))?;
    ensure!(
        status.incarnations.len() == 2 && bpng.incarnation.as_ref().iter().any(|byte| *byte != 0),
        "lifecycle must advertise exactly two unique non-zero lane incarnations"
    );
    Ok(bpng.incarnation)
}

#[derive(Debug)]
struct ValidatorLifecycleSnapshot {
    total: u64,
    registered: BTreeSet<(AccountId, PeerId)>,
    pending: BTreeMap<(AccountId, PeerId), u64>,
    active: BTreeSet<(AccountId, PeerId)>,
}

fn validator_bindings(
    snapshot: &norito::json::Value,
    expected_stake: &Quantity,
) -> Result<ValidatorLifecycleSnapshot> {
    let root = snapshot
        .as_object()
        .ok_or_else(|| eyre!("lane validator response is not an object"))?;
    let total = root
        .get("total")
        .and_then(norito::json::Value::as_u64)
        .ok_or_else(|| eyre!("lane validator response omitted total"))?;
    let items = root
        .get("items")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre!("lane validator response omitted items"))?;
    let mut registered = BTreeSet::new();
    let mut pending = BTreeMap::new();
    let mut active = BTreeSet::new();
    let expected_stake = expected_stake.to_string();
    for item in items {
        let item = item
            .as_object()
            .ok_or_else(|| eyre!("lane validator item is not an object"))?;
        ensure!(
            item.get("lane_id").and_then(norito::json::Value::as_u64)
                == Some(u64::from(BPNG_FIXTURE_LANE))
                && item
                    .get("authority_source")
                    .and_then(norito::json::Value::as_str)
                    == Some("staking")
                && item
                    .get("deactivation_height")
                    .is_some_and(norito::json::Value::is_null),
            "BPNG validator record route, authority source or open tenure changed"
        );
        let activation_height = item
            .get("activation_height")
            .and_then(norito::json::Value::as_u64)
            .ok_or_else(|| eyre!("lane validator item omitted activation_height"))?;
        ensure!(
            activation_height > 0,
            "BPNG validator activation boundary must be non-zero"
        );
        let status = item
            .get("status")
            .and_then(norito::json::Value::as_object)
            .ok_or_else(|| eyre!("lane validator item omitted status"))?;
        let status_type = status
            .get("type")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre!("lane validator item omitted status.type"))?;
        let validator = AccountId::parse_encoded(
            item.get("validator")
                .and_then(norito::json::Value::as_str)
                .ok_or_else(|| eyre!("lane validator item omitted validator"))?,
        )?;
        let peer = item
            .get("peer_id")
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre!("lane validator item omitted peer_id"))?
            .parse()?;
        let stake_account = AccountId::parse_encoded(
            item.get("stake_account")
                .and_then(norito::json::Value::as_str)
                .ok_or_else(|| eyre!("lane validator item omitted stake_account"))?,
        )?;
        ensure!(
            stake_account == validator
                && item
                    .get("total_stake")
                    .and_then(norito::json::Value::as_str)
                    == Some(expected_stake.as_str())
                && item.get("self_stake").and_then(norito::json::Value::as_str)
                    == Some(expected_stake.as_str()),
            "BPNG validator record does not retain its exact validator-owned minimum stake"
        );
        let binding = (validator, peer);
        ensure!(
            registered.insert(binding.clone()),
            "BPNG validator response contains a duplicate validator/peer binding"
        );
        match status_type {
            "PendingActivation" => {
                ensure!(
                    status.len() == 2
                        && status
                            .get("activates_at_height")
                            .and_then(norito::json::Value::as_u64)
                            == Some(activation_height),
                    "BPNG pending status does not bind its exact activation boundary"
                );
                pending.insert(binding, activation_height);
            }
            "Active" => {
                ensure!(
                    status.len() == 1,
                    "BPNG active status contains unexpected lifecycle fields"
                );
                active.insert(binding);
            }
            other => return Err(eyre!("unexpected BPNG validator lifecycle status {other}")),
        }
    }
    ensure!(
        usize::try_from(total)? == items.len(),
        "lane validator total does not match exact returned records"
    );
    ensure!(
        usize::try_from(total)? == registered.len()
            && pending.len().saturating_add(active.len()) == registered.len(),
        "lane validator response does not classify every exact unique binding"
    );
    Ok(ValidatorLifecycleSnapshot {
        total,
        registered,
        pending,
        active,
    })
}

async fn wait_for_exact_bpng_pending_registrations(
    client: &Client,
    expected: &BTreeSet<(AccountId, PeerId)>,
    expected_stake: &Quantity,
) -> Result<u64> {
    ensure!(
        expected.len() == VALIDATOR_COUNT,
        "pending BPNG qualification requires exactly four expected validator bindings"
    );
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        let query_client = client.clone();
        let expected_stake = expected_stake.clone();
        let observed = read(move || {
            let snapshot = query_client
                .client()
                .get_public_lane_validators(BPNG_FIXTURE_LANE)?;
            validator_bindings(&snapshot, &expected_stake)
        })
        .await;
        if let Ok(snapshot) = &observed
            && snapshot.total == u64::try_from(expected.len())?
            && snapshot.registered == *expected
            && snapshot.pending.len() == expected.len()
            && snapshot.active.is_empty()
        {
            let boundaries = snapshot.pending.values().copied().collect::<BTreeSet<_>>();
            ensure!(
                boundaries.len() == 1,
                "four BPNG pending registrations must share one exact election boundary: {boundaries:?}"
            );
            return boundaries
                .first()
                .copied()
                .ok_or_else(|| eyre!("BPNG pending activation boundary is missing"));
        }
        ensure!(
            Instant::now() < deadline,
            "exact BPNG pending registrations did not converge: {observed:?}"
        );
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_exact_bpng_validators(
    clients: &[Client],
    expected: &BTreeSet<(AccountId, PeerId)>,
    expected_stake: &Quantity,
) -> Result<()> {
    ensure!(
        clients.len() == VALIDATOR_COUNT && expected.len() == VALIDATOR_COUNT,
        "active BPNG qualification requires exactly four peers and validator bindings"
    );
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        let mut matched = true;
        let mut last = Vec::new();
        for client in clients {
            let client = client.clone();
            let expected_stake = expected_stake.clone();
            match read(move || {
                let snapshot = client
                    .client()
                    .get_public_lane_validators(BPNG_FIXTURE_LANE)?;
                validator_bindings(&snapshot, &expected_stake)
            })
            .await
            {
                Ok(snapshot) => {
                    matched &= snapshot.total == u64::try_from(expected.len())?
                        && snapshot.active == *expected
                        && snapshot.registered == *expected
                        && snapshot.pending.is_empty();
                    last.push(snapshot);
                }
                Err(error) => {
                    matched = false;
                    if Instant::now() >= deadline {
                        return Err(error).wrap_err("BPNG validator status did not converge");
                    }
                }
            }
        }
        if matched {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "exact BPNG validator bindings did not converge: {last:?}"
        );
        sleep(POLL_INTERVAL).await;
    }
}

fn transaction(client: &Client, instruction: impl Into<InstructionBox>) -> SignedTransaction {
    {
        let account = client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                [instruction.into()],
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction")
}

#[derive(Debug, PartialEq, Eq)]
struct ReleaseSourceIdentity {
    head_commit: String,
    head_tree: String,
    source_manifest_sha256: String,
    cargo_lock_sha256: String,
}

fn required_exact_env(name: &str) -> Result<String> {
    let value = std::env::var(name).wrap_err_with(|| format!("missing required {name}"))?;
    ensure!(
        !value.is_empty() && value.trim() == value,
        "{name} must be one non-empty canonical value"
    );
    Ok(value)
}

fn required_canonical_path(name: &str, directory: bool) -> Result<PathBuf> {
    let path = PathBuf::from(required_exact_env(name)?);
    ensure!(path.is_absolute(), "{name} must be absolute");
    let canonical = path
        .canonicalize()
        .wrap_err_with(|| format!("{name} is unavailable: {}", path.display()))?;
    ensure!(canonical == path, "{name} must already be canonical");
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        !metadata.file_type().is_symlink()
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        "{name} must be a real {}",
        if directory {
            "directory"
        } else {
            "regular file"
        }
    );
    Ok(path)
}

fn bounded_tool_output(mut command: Command, label: &str) -> Result<Vec<u8>> {
    command.stdin(Stdio::null());
    let output = command
        .output()
        .wrap_err_with(|| format!("failed to execute {label}"))?;
    ensure!(output.status.success(), "{label} failed");
    ensure!(
        output.stdout.len() <= MAX_RELEASE_TOOL_OUTPUT_BYTES
            && output.stderr.len() <= MAX_RELEASE_TOOL_OUTPUT_BYTES,
        "{label} exceeded its fixed output budget"
    );
    Ok(output.stdout)
}

fn parse_release_source_identity(bytes: &[u8]) -> Result<ReleaseSourceIdentity> {
    ensure!(
        !bytes.is_empty() && u64::try_from(bytes.len())? <= MAX_RELEASE_IDENTITY_BYTES,
        "release source identity is empty or oversized"
    );
    let value: norito::json::Value = norito::json::from_slice(bytes)?;
    let object = value
        .as_object()
        .ok_or_else(|| eyre!("release source identity must be a JSON object"))?;
    let expected_fields = BTreeSet::from([
        "schema_version",
        "head_commit",
        "head_tree",
        "index_tree",
        "workspace_source_manifest_sha256",
        "cargo_lock_sha256",
    ]);
    ensure!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected_fields,
        "release source identity has an open or incomplete field set"
    );
    ensure!(
        object
            .get("schema_version")
            .and_then(norito::json::Value::as_u64)
            == Some(1),
        "release source identity schema must be exactly 1"
    );
    let string = |field: &str| -> Result<String> {
        Ok(object
            .get(field)
            .and_then(norito::json::Value::as_str)
            .ok_or_else(|| eyre!("release source identity omitted {field}"))?
            .to_owned())
    };
    let identity = ReleaseSourceIdentity {
        head_commit: string("head_commit")?,
        head_tree: string("head_tree")?,
        source_manifest_sha256: string("workspace_source_manifest_sha256")?,
        cargo_lock_sha256: string("cargo_lock_sha256")?,
    };
    ensure!(
        string("index_tree")? == identity.head_tree,
        "release source index tree is not exact HEAD"
    );
    for (value, label) in [
        (
            &identity.source_manifest_sha256,
            "workspace source manifest",
        ),
        (&identity.cargo_lock_sha256, "Cargo.lock"),
    ] {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "release {label} digest is not lowercase SHA-256"
        );
    }
    Ok(identity)
}

fn read_release_identity(path: &Path) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.len() > 0
            && before.len() <= MAX_RELEASE_IDENTITY_BYTES,
        "sealed release identity must be one bounded regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            before.mode() & 0o7777 == 0o400 && before.nlink() == 1,
            "sealed release identity must have exact mode 0400 and one link"
        );
    }
    let bytes = fs::read(path)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        before.len() == u64::try_from(bytes.len())?
            && before.modified()? == after.modified()?
            && before.len() == after.len(),
        "sealed release identity changed while it was read"
    );
    Ok(bytes)
}

fn verify_clean_release_source(repo_root: &Path) -> Result<ReleaseSourceIdentity> {
    ensure!(
        required_exact_env("IROHA_RELEASE_SEALED_WORKTREE")? == "1",
        "native BPNG qualification requires the sealed production release worktree"
    );
    let invocation_root = required_canonical_path("IROHA_RELEASE_INVOCATION_ROOT", true)?;
    let sealed_root = required_canonical_path("IROHA_RELEASE_SEALED_ROOT", true)?;
    ensure!(
        sealed_root == repo_root && invocation_root.join("source") == sealed_root,
        "compiled BPNG scenario escaped the exact sealed release source root"
    );
    let identity_path = required_canonical_path("IROHA_RELEASE_EXPECTED_IDENTITY_PATH", false)?;
    ensure!(
        identity_path == invocation_root.join("sealed-identity.json"),
        "release identity escaped its fixed invocation path"
    );
    let python = required_canonical_path("IROHA_RELEASE_PYTHON_BIN", false)?;
    let git = required_canonical_path("IROHA_RELEASE_GIT_BIN", false)?;
    let path = required_exact_env("PATH")?;
    let path_entries = std::env::split_paths(&path).collect::<Vec<_>>();
    ensure!(
        path_entries.len() == 1
            && path_entries[0].join("git").canonicalize()? == git
            && path_entries[0].join("python3").canonicalize()? == python,
        "release PATH must resolve only the pinned Git and Python runtime"
    );

    let mut seal = Command::new(&python);
    seal.args(["-I", "-S"])
        .arg(repo_root.join("scripts/seal_workspace_source.py"))
        .arg("--verify")
        .arg("--root")
        .arg(repo_root)
        .arg("--no-writable-paths")
        .current_dir(repo_root);
    ensure!(
        bounded_tool_output(seal, "sealed workspace verifier")?.is_empty(),
        "sealed workspace verifier emitted unexpected output"
    );

    let mut capture = Command::new(&python);
    capture
        .args(["-I", "-S"])
        .arg(repo_root.join("scripts/compute_workspace_source_manifest.py"))
        .arg("--root")
        .arg(repo_root)
        .arg("--release-identity-json")
        .current_dir(repo_root);
    let observed = parse_release_source_identity(&bounded_tool_output(
        capture,
        "clean release source identity capture",
    )?)?;
    let retained = parse_release_source_identity(&read_release_identity(&identity_path)?)?;
    ensure!(
        observed == retained,
        "sealed identity does not reproduce from the exact clean HEAD/test source tree"
    );
    ensure!(
        observed.head_commit == required_exact_env("IROHA_RELEASE_HEAD_COMMIT")?
            && observed.head_tree == required_exact_env("IROHA_RELEASE_HEAD_TREE")?
            && observed.source_manifest_sha256
                == required_exact_env("IROHA_RELEASE_SOURCE_MANIFEST_SHA256")?
            && observed.cargo_lock_sha256 == required_exact_env("IROHA_RELEASE_CARGO_LOCK_SHA256")?,
        "release identity exports disagree with clean HEAD/tree/Cargo.lock/source manifest"
    );
    Ok(observed)
}

fn required_prebuilt_binaries() -> Result<()> {
    ensure!(
        std::env::var("IROHA_TEST_SKIP_BUILD").as_deref() == Ok("1"),
        "native BPNG qualification is lookup-only and must not launch child Cargo builds"
    );
    ensure!(
        required_exact_env("IROHA_TEST_BUILD_PROFILE")? == "release"
            && required_exact_env("PROFILE")? == "release",
        "native BPNG qualification requires the exact release build profile"
    );
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()?;
    let source_identity = verify_clean_release_source(&repo_root)?;
    let manifest_source = required_exact_env("IROHA_RELEASE_SOURCE_MANIFEST_SHA256")?;
    ensure!(
        source_identity.source_manifest_sha256 == manifest_source,
        "prebuilt bundle source anchor differs from the clean qualification source"
    );
    for (name, kind) in [
        ("TEST_NETWORK_BIN_IROHAD", ReleasePrebuiltBinary::Irohad),
        ("TEST_NETWORK_BIN_IROHA", ReleasePrebuiltBinary::Iroha),
        ("KAGAMI_BIN", ReleasePrebuiltBinary::Kagami),
    ] {
        let path = PathBuf::from(required_exact_env(name)?);
        ensure!(
            path.is_absolute(),
            "{name} must be an absolute manifest-bound path"
        );
        let resolved = resolve_release_prebuilt_binary(kind)?
            .ok_or_else(|| eyre!("source-bound release prebuilt contract is not active"))?;
        ensure!(
            path == resolved,
            "{name} is not the exact canonical SHA-256/size/mode/profile/target/toolchain-bound release binary"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LeaseExpectation {
    namespace: SnsNamespacePath,
    literal: String,
    policy: SuffixPolicyV1,
    amount: Quantity,
}

async fn acquire(
    payer: &Client,
    intent: AliasIntentV1,
    namespace: SnsNamespacePath,
    literal: &str,
) -> Result<(SignedTransaction, LeaseExpectation)> {
    let planning_client = payer.clone();
    let literal = literal.to_owned();
    let (signed, expectation) = read(move || {
        let policy = planning_client
            .client()
            .sns()
            .get_policy(namespace.suffix_id())?;
        ensure!(
            policy.fund_splitter_account != *BOB_ID,
            "fixture payer must differ from native lease collector"
        );
        let payment_asset = AssetDefinitionId::parse_address_literal(&policy.payment_asset_id)?;
        let valid_until_ms =
            u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?
                .checked_add(u64::try_from(TRANSACTION_TTL.as_millis())?)
                .ok_or_else(|| eyre!("lease deadline overflow"))?;
        let request = AliasSetupPlanRequestV1::new(vec![EnsureAlias::new(
            intent,
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: policy.policy_version,
                expected_payment_asset: payment_asset,
                max_amount: Quantity::from(100_u32),
                valid_until_ms,
            },
        )]);
        let plan = planning_client.plan_alias_setup(&request)?;
        ensure!(
            plan.body.blockers.is_empty() && plan.body.resources.len() == 1,
            "native planner did not produce one executable resource"
        );
        let resource = &plan.body.resources[0];
        ensure!(
            resource.disposition == AliasPlanDispositionV1::Create,
            "lease must be a first native acquisition, not repair/no-op"
        );
        let quote = resource
            .quote
            .as_ref()
            .ok_or_else(|| eyre!("native create plan omitted its paid quote"))?;
        ensure!(
            !quote.exact_amount.is_zero(),
            "SNS acquisition must charge a real lease payment"
        );
        let instructions = planning_client
            .client()
            .verify_alias_setup_plan_for_request(&request, &plan)?;
        ensure!(
            instructions.len() == 1,
            "one native EnsureAlias instruction expected"
        );
        let signed = {
            let account = planning_client.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    instructions,
                    FeePaymentIntent::authority(Vec::new(), None),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build integration-test transaction");
        Ok((
            signed,
            LeaseExpectation {
                namespace,
                literal,
                policy,
                amount: quote.exact_amount.clone(),
            },
        ))
    })
    .await?;
    Ok((submit(payer, signed).await?, expectation))
}

fn balances(client: &Client, leases: &[LeaseExpectation]) -> Result<BTreeMap<AssetId, Quantity>> {
    let mut selected = BTreeMap::new();
    for lease in leases {
        let definition = AssetDefinitionId::parse_address_literal(&lease.policy.payment_asset_id)?;
        for owner in [BOB_ID.clone(), lease.policy.fund_splitter_account.clone()] {
            selected.insert(AssetId::of(definition.clone(), owner), Quantity::zero());
        }
    }
    for asset in client.client().query(FindAssets::new()).execute_all()? {
        if let Some(amount) = selected.get_mut(asset.id()) {
            *amount = asset.value().clone();
        }
    }
    Ok(selected)
}

fn assert_paid_once(
    before: &BTreeMap<AssetId, Quantity>,
    after: &BTreeMap<AssetId, Quantity>,
    leases: &[LeaseExpectation],
) -> Result<()> {
    let mut expected = before.clone();
    for lease in leases {
        let asset = AssetDefinitionId::parse_address_literal(&lease.policy.payment_asset_id)?;
        let payer = expected
            .get_mut(&AssetId::of(asset.clone(), BOB_ID.clone()))
            .ok_or_else(|| eyre!("missing baseline payer balance"))?;
        *payer = payer.checked_sub(&lease.amount)?;
        let collector = expected
            .get_mut(&AssetId::of(
                asset,
                lease.policy.fund_splitter_account.clone(),
            ))
            .ok_or_else(|| eyre!("missing baseline collector balance"))?;
        *collector = collector.checked_add(&lease.amount)?;
    }
    ensure!(
        &expected == after,
        "native lease payer/collector balances differ from exact once-only quoted charges"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LedgerSnapshot {
    parameters: Vec<u8>,
    leases: Vec<NameRecordV1>,
    domains: BTreeMap<DomainId, Vec<u8>>,
    balances: BTreeMap<AssetId, Quantity>,
}

fn ledger_snapshot(
    client: &Client,
    expectations: &[LeaseExpectation],
    grant: &AliasDataspaceBootstrapGrantV1,
    transactions: &[SignedTransaction],
) -> Result<LedgerSnapshot> {
    let parameters: Parameters = client.client().query_single(FindParameters::new())?;
    let custom = parameters
        .custom()
        .get(&grant.parameter_id()?)
        .ok_or_else(|| eyre!("owner bootstrap grant missing"))?;
    ensure!(
        AliasDataspaceBootstrapGrantV1::from_custom_parameter(custom)?.as_ref() == Some(grant),
        "owner bootstrap grant changed"
    );
    let mut leases = Vec::new();
    for expected in expectations {
        ensure!(
            client
                .client()
                .sns()
                .get_policy(expected.namespace.suffix_id())?
                == expected.policy,
            "native suffix policy drifted"
        );
        let record = client
            .client()
            .sns()
            .get_name(expected.namespace, &expected.literal)?;
        let selector = NameSelectorV1::new(expected.namespace.suffix_id(), &expected.literal)?;
        ensure!(
            record.selector == selector && record.name_hash == selector.name_hash(),
            "native lease selector/hash mismatch"
        );
        ensure!(
            record.owner == *BOB_ID
                && record.ownership_generation == 1
                && record.status == NameStatus::Active,
            "lease owner/generation/status mismatch"
        );
        ensure!(
            record.expires_at_ms.checked_sub(record.registered_at_ms) == Some(ALIAS_LEASE_YEAR_MS),
            "lease term is not exactly one year"
        );
        ensure!(
            record.grace_expires_at_ms.checked_sub(record.expires_at_ms)
                == Some(u64::from(expected.policy.grace_period_days) * 86_400_000),
            "lease grace term mismatch"
        );
        ensure!(
            record
                .redemption_expires_at_ms
                .checked_sub(record.grace_expires_at_ms)
                == Some(u64::from(expected.policy.redemption_period_days) * 86_400_000),
            "lease redemption term mismatch"
        );
        leases.push(record);
    }
    let mut domains = BTreeMap::new();
    for domain in client.client().query(FindDomains::new()).execute_all()? {
        if [
            DomainId::try_new("history", "universal")?,
            DomainId::try_new("mibank", "bpng")?,
        ]
        .contains(domain.id())
        {
            ensure!(
                domain.owned_by() == &*BOB_ID,
                "native domain owner mismatch"
            );
            domains.insert(domain.id().clone(), domain.encode());
        }
    }
    ensure!(domains.len() == 2, "both native domains must be present");
    let committed = client
        .client()
        .query(FindTransactions::new())
        .execute_all()?;
    for transaction in transactions {
        let matching = committed
            .iter()
            .filter(|record| record.entrypoint_hash() == &transaction.hash_as_entrypoint())
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "exact signed transaction must appear once in committed query history"
        );
        ensure!(
            matching[0].entrypoint() == &TransactionEntrypoint::External(transaction.clone())
                && matching[0].result().0.is_ok(),
            "committed transaction bytes/result mismatch"
        );
    }
    Ok(LedgerSnapshot {
        parameters: parameters.encode(),
        leases,
        domains,
        balances: balances(client, expectations)?,
    })
}

async fn wait_for_snapshot(
    client: &Client,
    expectations: &[LeaseExpectation],
    grant: &AliasDataspaceBootstrapGrantV1,
    transactions: &[SignedTransaction],
    expected: Option<&LedgerSnapshot>,
) -> Result<LedgerSnapshot> {
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        let client = client.clone();
        let expectations = expectations.to_vec();
        let grant = grant.clone();
        let transactions = transactions.to_vec();
        let observed =
            read(move || ledger_snapshot(&client, &expectations, &grant, &transactions)).await;
        match observed {
            Ok(snapshot) if expected.is_none_or(|expected| expected == &snapshot) => {
                return Ok(snapshot);
            }
            outcome => {
                ensure!(
                    Instant::now() < deadline,
                    "exact ledger state failed to converge: {outcome:?}"
                );
                sleep(POLL_INTERVAL).await;
            }
        }
    }
}

fn assert_bpng_record(
    record: &SumeragiLaneRecord,
    incarnation: [u8; 32],
    expected_validators: &[PeerId],
) -> Result<()> {
    ensure!(
        record.lane == BPNG_FIXTURE_LANE
            && record.dataspace == DataSpaceId::new(BPNG_ID)
            && record.incarnation == incarnation
            && record.closing.is_none(),
        "native BPNG route/incarnation changed"
    );
    ensure!(
        record
            .committee
            .iter()
            .map(|member| member.peer.clone())
            .collect::<Vec<_>>()
            == expected_validators
            && record.committee.len() == VALIDATOR_COUNT,
        "native BPNG committee differs from the four signed validators"
    );
    Ok(())
}

async fn wait_for_bpng_frontier(
    clients: &[Client],
    incarnation: [u8; 32],
    expected_validators: &[PeerId],
    transaction: &SignedTransaction,
) -> Result<SumeragiLaneRecord> {
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        let mut observations = Vec::new();
        for client in clients {
            let client = client.clone();
            let transaction = transaction.clone();
            let observed = read(move || {
                let statuses = client.client().get_sumeragi_lanes()?;
                let status = statuses
                    .into_iter()
                    .find(|status| status.record.lane == BPNG_FIXTURE_LANE)
                    .ok_or_else(|| eyre!("native BPNG lane is absent"))?;
                ensure!(
                    status
                        .instance
                        .as_ref()
                        .is_some_and(|instance| instance.halted.is_none()),
                    "native BPNG instance is unavailable or halted"
                );
                let mut blocks = client.client().query(FindBlocks::new()).execute_all()?;
                blocks.sort_by_key(|block| block.header().height().get());
                let history = RetainedHistory {
                    blocks: blocks
                        .iter()
                        .map(SignedBlock::encode_wire)
                        .collect::<Result<_, _>>()?,
                };
                let (_, expected) = bpng_transaction_ownership(
                    &history,
                    &transaction,
                    incarnation,
                    &status
                        .record
                        .committee
                        .iter()
                        .map(|member| member.peer.clone())
                        .collect::<Vec<_>>(),
                )?;
                ensure!(
                    status.record == expected,
                    "live native frontier differs from the transaction's exact global merge"
                );
                Ok(status.record)
            })
            .await;
            match observed {
                Ok(record) => {
                    assert_bpng_record(&record, incarnation, expected_validators)?;
                    observations.push(record);
                }
                Err(_) => break,
            }
        }
        if observations.len() == clients.len()
            && observations.windows(2).all(|pair| pair[0] == pair[1])
        {
            return observations
                .into_iter()
                .next()
                .ok_or_else(|| eyre!("no native lane observations"));
        }
        ensure!(
            Instant::now() < deadline,
            "native BPNG frontier did not converge on all four peers"
        );
        sleep(POLL_INTERVAL).await;
    }
}

async fn assert_bpng_metadata(
    client: &Client,
    predecessor_key: &Name,
    predecessor_value: &Json,
    successor: Option<(&Name, &Json)>,
) -> Result<()> {
    let client = client.clone();
    let domain = read(move || {
        Ok(client
            .client()
            .query_single(FindDomainById::new(DomainId::try_new("mibank", "bpng")?))?)
    })
    .await?;
    ensure!(
        domain.metadata().get(predecessor_key) == Some(predecessor_value),
        "pre-restart BPNG state is absent"
    );
    if let Some((key, value)) = successor {
        ensure!(
            domain.metadata().get(key) == Some(value),
            "post-restart BPNG successor state is absent"
        );
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct RetainedHistory {
    blocks: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
struct StoppedEvidence {
    retained: RetainedHistory,
    certified_bpng_lane: CertifiedBpngLaneEvidence,
}

#[derive(Debug, PartialEq, Eq)]
struct CertifiedBpngLaneEvidence {
    artifacts: Vec<Vec<u8>>,
    statements: Vec<(Hash32, Hash32)>,
}
impl CertifiedBpngLaneEvidence {
    fn absent() -> Self {
        Self {
            artifacts: Vec::new(),
            statements: Vec::new(),
        }
    }
    fn assert_exact_prefix_of(&self, successor: &Self) -> Result<()> {
        ensure!(
            successor.artifacts.starts_with(&self.artifacts),
            "strict replay changed the exact retained native lane frame prefix"
        );
        Ok(())
    }
}

// Certificates are verified independently above. Different exact quorum subsets can certify
// identical executed bytes, so cross-peer equality compares their authenticated statements.
fn same_authenticated_prefix(left: &StoppedEvidence, right: &StoppedEvidence) -> Result<bool> {
    if left.retained.blocks.len() != right.retained.blocks.len()
        || left.certified_bpng_lane.artifacts.len() != right.certified_bpng_lane.artifacts.len()
    {
        return Ok(false);
    }
    for (left, right) in left.retained.blocks.iter().zip(&right.retained.blocks) {
        let left = decode_framed_signed_block(left)?
            .with_commit_certificate(None)
            .encode_wire()?;
        let right = decode_framed_signed_block(right)?
            .with_commit_certificate(None)
            .encode_wire()?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(left.certified_bpng_lane.statements == right.certified_bpng_lane.statements)
}

fn assert_same_authenticated_prefix(peers: &[StoppedEvidence]) -> Result<()> {
    for pair in peers.windows(2) {
        ensure!(
            same_authenticated_prefix(&pair[0], &pair[1])?,
            "validators retained different certified execution statements"
        );
    }
    Ok(())
}

// Independently replay this fixture's one signed fixed-lane policy and certified merge ranges.
// The resulting complete state is checked against each global execution result's native proof.
fn native_lane_states(history: &RetainedHistory) -> Result<Vec<SumeragiLaneState>> {
    let mut state = SumeragiLaneState::default();
    let genesis = decode_framed_signed_block(
        history
            .blocks
            .first()
            .ok_or_else(|| eyre!("missing genesis"))?,
    )?;
    let network = NetworkId::from_genesis_hash(genesis.hash());
    let mut states = Vec::new();
    for wire in &history.blocks {
        let block = decode_framed_signed_block(wire)?;
        let height = block.header().height().get();
        if let Some(section) = block.lane_merge() {
            for merge in &section.merges {
                let record = state
                    .lane_mut(merge.lane)
                    .ok_or_else(|| eyre!("merge before signed lane policy"))?;
                ensure!(
                    merge.incarnation == record.incarnation
                        && merge.from == record.merged.height + 1
                        && merge.to >= merge.from,
                    "native merge skipped or changed a lane incarnation"
                );
                record.merged = SumeragiLaneFrontier {
                    height: merge.to,
                    block_hash: merge.tip_hash,
                    result: merge.tip_result,
                };
                record.merged_at = height;
                record.rescued = 0;
            }
        }
        for tx in block.external_transactions() {
            let Executable::Instructions(instructions) = tx.instructions() else {
                continue;
            };
            for instruction in instructions {
                let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
                    continue;
                };
                let Parameter::Custom(custom) = set.inner() else {
                    continue;
                };
                let Some(policy) = SumeragiLanePolicy::from_custom_parameter(custom) else {
                    continue;
                };
                let policy = policy.map_err(|error| eyre!(error))?;
                ensure!(
                    state.lanes.is_empty() && policy.fixed.len() == 1 && policy.autoscale.is_none(),
                    "fixture requires one first signed fixed-lane policy"
                );
                let fixed = &policy.fixed[0];
                let mut record = SumeragiLaneRecord {
                    da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
                    lane: fixed.lane,
                    dataspace: fixed.dataspace,
                    incarnation: lanes::step::incarnation(
                        &network,
                        fixed.lane,
                        fixed.dataspace,
                        height,
                        state.incarnations,
                    ),
                    params: policy.lane_params,
                    committee: fixed.committee.clone(),
                    created_at: height,
                    active_from: height + 2,
                    closing: None,
                    anchor_freshness: policy.anchor_freshness,
                    merged: SumeragiLaneFrontier::default(),
                    merged_at: height + 2,
                    rescued: 0,
                };
                record.merged.block_hash = lanes::lane_genesis_hash(&network, &record).0;
                record.merged.result = lanes::lane_genesis_result(&record).0;
                state.incarnations += 1;
                state.upsert(record);
            }
        }
        states.push(state.clone());
    }
    Ok(states)
}

impl AnchorView for RetainedHistory {
    fn applied_hash(&self, height: u64) -> Option<HashOf<BlockHeader>> {
        let index = usize::try_from(height).ok()?.checked_sub(1)?;
        Some(
            decode_framed_signed_block(self.blocks.get(index)?)
                .ok()?
                .hash(),
        )
    }
    fn creation_time_ms(
        &self,
        height: u64,
    ) -> Result<Option<u64>, iroha_core::execution_attempt::ExecutionAttemptError<std::io::Error>>
    {
        let Some(index) = usize::try_from(height)
            .ok()
            .and_then(|height| height.checked_sub(1))
        else {
            return Ok(None);
        };
        let Some(wire) = self.blocks.get(index) else {
            return Ok(None);
        };
        let block = decode_framed_signed_block(wire)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let timestamp = u64::try_from(block.header().creation_time().as_millis())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        Ok(Some(timestamp))
    }
}

#[test]
fn retained_anchor_time_distinguishes_absent_frames_from_invalid_retained_bytes() {
    let empty = RetainedHistory { blocks: Vec::new() };
    assert_eq!(empty.creation_time_ms(0).unwrap(), None);
    assert_eq!(empty.creation_time_ms(1).unwrap(), None);
    let malformed = RetainedHistory {
        blocks: vec![vec![0xff]],
    };
    let error = malformed
        .creation_time_ms(1)
        .expect_err("invalid retained bytes are not an absent anchor");
    assert!(
        matches!(error, iroha_core::execution_attempt::ExecutionAttemptError::Rejected(error)
        if error.kind() == std::io::ErrorKind::InvalidData)
    );
    let key = KeyPair::try_from_seed(vec![0x46; 32], Algorithm::Ed25519).unwrap();
    let block = iroha_data_model::block::builder::BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(1).unwrap(),
        None,
        None,
        7,
        0,
    ))
    .build_with_signature(0, key.private_key());
    let retained = RetainedHistory {
        blocks: vec![block.encode_wire().unwrap()],
    };
    assert_eq!(retained.creation_time_ms(1).unwrap(), Some(7));
    assert_eq!(retained.creation_time_ms(2).unwrap(), None);
}

// This schedule is derived only from the independently verified global execution history.
// The inspected lane frame supplies neither its committee nor its availability parameters.
struct RetainedLaneSchedule {
    instance: Hash32,
    config: HeightConfig,
    merged_height: u64,
}

impl AvailabilitySchedule for RetainedLaneSchedule {
    fn instance(&self) -> Hash32 {
        self.instance
    }

    fn height_config(
        &self,
        height: u64,
    ) -> Result<
        Option<HeightConfig>,
        iroha_core::execution_attempt::ExecutionAttemptError<std::io::Error>,
    > {
        Ok((height > 0 && height <= self.merged_height).then(|| self.config.clone()))
    }
}

fn inspect_certified_bpng_lane_evidence(
    store_root: &Path,
    network_id: NetworkId,
    chain_id: &ChainId,
    retained: &RetainedHistory,
    expected_incarnation: Option<[u8; 32]>,
    expected_validators: &[PeerId],
    original_voters: &BTreeMap<PeerId, Vec<u8>>,
) -> Result<CertifiedBpngLaneEvidence> {
    let states = native_lane_states(retained)?;
    let Some(record) = states
        .last()
        .and_then(|state| state.lane(BPNG_FIXTURE_LANE))
    else {
        ensure!(
            expected_incarnation.is_none(),
            "signed native BPNG lane is absent"
        );
        return Ok(CertifiedBpngLaneEvidence::absent());
    };
    let incarnation =
        expected_incarnation.ok_or_else(|| eyre!("native lane exists before signed policy"))?;
    assert_bpng_record(record, incarnation, expected_validators)?;
    for member in &record.committee {
        ensure!(
            original_voters.get(&member.peer) == Some(&member.pop),
            "native lane credentials differ from signed genesis"
        );
    }
    let crypto = Arc::new(BlsCrypto::new());
    crypto
        .admit_committee(
            record
                .committee
                .iter()
                .map(|member| (member.peer.public_key(), member.pop.as_slice())),
        )
        .map_err(|(index, error)| eyre!("invalid original lane member {index}: {error}"))?;
    let instance = lanes::lane_instance(&*crypto, &network_id, chain_id.as_str(), record);
    let schedule: Arc<dyn AvailabilitySchedule> = Arc::new(RetainedLaneSchedule {
        instance,
        config: lanes::lane_height_config(record)?,
        merged_height: record.merged.height,
    });
    let budget = AllocationBudget::new(usize::try_from(MAX_EVIDENCE_BYTES)?);
    let directory = store_root.join("lanes").join(hex::encode(instance.0));
    let mut predecessor = SumeragiLaneFrontier {
        height: 0,
        block_hash: lanes::lane_genesis_hash(&network_id, record).0,
        result: lanes::lane_genesis_result(record).0,
    };
    let mut history = LaneChainView::default();
    let mut artifacts = Vec::new();
    let mut statements = Vec::new();
    let mut total = 0_u64;
    ensure!(
        record.merged.height <= MAX_RETAINED_HEIGHT,
        "native lane history exceeds fixture bound"
    );
    for height in 1..=record.merged.height {
        let path = directory.join(format!("{height:020}.frame"));
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= MAX_EVIDENCE_BYTES,
            "native lane frame is not a bounded regular file"
        );
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| eyre!("native lane evidence size overflow"))?;
        ensure!(
            total <= MAX_EVIDENCE_BYTES,
            "native lane evidence exceeds fixture budget"
        );
        let bytes = fs::read(&path)?;
        let (body, certificate) = LaneFrameRead::open(
            &path,
            height,
            crypto.clone(),
            budget.clone(),
            Arc::clone(&schedule),
        )?
        .poll()?;
        ensure!(
            certificate.signers.count_ones() == BPNG_MIN_QUORUM as usize,
            "native lane frame lacks exact three-of-four quorum"
        );
        let result = verify_lane_entry(
            record,
            &network_id,
            chain_id.as_str(),
            retained,
            &history,
            &predecessor,
            &body,
            &certificate,
        )?;
        let batch = LaneBatch::from_payload(body.payload().as_slice())?;
        ensure!(
            batch.transactions.len() == 1,
            "BPNG fixture must certify exactly its one original transaction"
        );
        let carrier = retained
            .blocks
            .iter()
            .map(|wire| decode_framed_signed_block(wire))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|block| {
                block.lane_merge().is_some_and(|section| {
                    section.merges.iter().any(|merge| {
                        merge.lane == record.lane
                            && merge.incarnation == record.incarnation
                            && merge.from == height
                            && merge.to == height
                    })
                })
            })
            .ok_or_else(|| eyre!("native certified lane frame has no exact global merge"))?;
        let section = carrier.lane_merge().expect("matched lane merge");
        let merge = section
            .merges
            .iter()
            .find(|merge| merge.lane == record.lane)
            .expect("matched lane");
        ensure!(
            merge.tip_hash == certificate.block_hash.0
                && merge.tip_result == certificate.result.0
                && section.merged_count == 1,
            "global native merge does not bind its exact certified frame"
        );
        let signed = &batch.transactions[0];
        let (_, execution_record) =
            bpng_transaction_ownership(retained, signed, incarnation, expected_validators)?;
        ensure!(
            execution_record.merged.height == height,
            "native lane transaction executed under another frame"
        );
        history.previous_anchor = result.anchor_height;
        for hash in result.tx_hashes {
            history.recent.insert(hash, result.anchor_height);
        }
        predecessor = SumeragiLaneFrontier {
            height,
            block_hash: certificate.block_hash.0,
            result: certificate.result.0,
        };
        ensure!(
            fs::read(&path)? == bytes,
            "native lane frame changed during read-only inspection"
        );
        artifacts.push(bytes);
        statements.push((certificate.block_hash, certificate.result));
    }
    ensure!(
        predecessor == record.merged,
        "native lane retained tip differs from global certified frontier"
    );
    Ok(CertifiedBpngLaneEvidence {
        artifacts,
        statements,
    })
}

fn inspection_fingerprint(blocks_dir: &Path) -> Result<BTreeMap<PathBuf, (u64, Hash)>> {
    let paths = ["blocks.data", "blocks.index", "blocks.hashes"]
        .map(PathBuf::from)
        .to_vec();
    let mut fingerprint = BTreeMap::new();
    let mut total = 0_u64;
    for relative in paths {
        let path = blocks_dir.join(&relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && relative.components().count() == 2 =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        ensure!(
            metadata.is_file(),
            "inspection evidence must be a regular file"
        );
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| eyre!("inspection size overflow"))?;
        ensure!(
            total <= MAX_EVIDENCE_BYTES,
            "inspection evidence exceeds fixture budget"
        );
        fingerprint.insert(relative, (metadata.len(), Hash::new(fs::read(path)?)));
    }
    Ok(fingerprint)
}

fn read_retained_prefix(blocks_dir: &Path, prefix: u64) -> Result<RetainedHistory> {
    ensure!(
        (1..=MAX_RETAINED_HEIGHT).contains(&prefix),
        "retained prefix exceeds fixture bound"
    );
    let mut store = BlockStore::open_read_only(blocks_dir)?;
    let mut blocks = Vec::new();
    let mut total = 0_u64;
    for height in 1..=prefix {
        let mut index = [BlockIndex::default()];
        store.read_block_indices(height - 1, &mut index)?;
        ensure!(
            index[0].length > 0 && index[0].length <= MAX_EVIDENCE_BYTES,
            "missing/oversized retained block body at {height}"
        );
        total = total
            .checked_add(index[0].length)
            .ok_or_else(|| eyre!("evidence size overflow"))?;
        ensure!(
            total <= MAX_EVIDENCE_BYTES,
            "retained evidence exceeds fixture budget"
        );
        let wire = store.block_bytes(index[0].start, index[0].length)?.to_vec();
        ensure!(
            decode_framed_signed_block(&wire)?.header().height().get() == height,
            "stored block height mismatch"
        );
        blocks.push(wire);
    }
    Ok(RetainedHistory { blocks })
}

fn authenticate_retained_history(
    retained: &RetainedHistory,
    genesis: &GenesisBlock,
    chain_id: &ChainId,
    original_voters: &BTreeMap<PeerId, Vec<u8>>,
) -> Result<()> {
    ensure!(
        retained.blocks.len() >= 2,
        "genesis execution needs its real certified successor"
    );
    let network = NetworkId::from_genesis_hash(genesis.0.hash());
    let stored_genesis = decode_framed_signed_block(&retained.blocks[0])?;
    ensure!(
        stored_genesis
            .canonical_resultless_proposal()?
            .encode_wire()?
            == genesis.0.canonical_resultless_proposal()?.encode_wire()?,
        "original signed genesis changed"
    );
    let states = native_lane_states(retained)?;
    // One bounded offline verification owns the shared controls for its retained prefix.
    let budget = AllocationBudget::new(usize::try_from(MAX_EVIDENCE_BYTES)?);
    let stored_genesis =
        iroha_data_model::block::SharedSignedBlock::try_new(stored_genesis, &budget)
            .map_err(|(_, error)| error)?;
    let mut verifier = CertifiedPrefix::new(chain_id, network, stored_genesis)?;
    for (index, wire) in retained.blocks.iter().enumerate().skip(1) {
        let block = decode_framed_signed_block(wire)?;
        let block = iroha_data_model::block::SharedSignedBlock::try_new(block, &budget)
            .map_err(|(_, error)| error)?;
        let (certified, anchored_genesis) = verifier.push(block.clone())?.into_parts();
        let committed = certified.committed();
        let context = &committed.commitment().schedule.current;
        ensure!(
            context.network_id == network
                && context.mode == ConsensusMode::Npos
                && context.committee.len() == VALIDATOR_COUNT,
            "native finality network/mode/committee changed"
        );
        for member in &context.committee {
            ensure!(
                original_voters.get(&member.validator) == Some(&member.proof_of_possession),
                "native finality voter/PoP differs from signed genesis"
            );
        }
        ensure!(
            certified
                .commit_qc()
                .is_some_and(|qc| qc.signers.count_ones() == BPNG_MIN_QUORUM as usize),
            "native CommitQC must carry exactly three of four equal votes"
        );
        let executed_wire = block
            .as_ref()
            .clone()
            .with_commit_certificate(None)
            .encode_wire()?;
        let execution = &committed.commitment().execution;
        ensure!(
            execution.executed_block_wire_len == u64::try_from(executed_wire.len())?
                && execution.executed_block_wire_hash == Hash::new(&executed_wire),
            "native result does not bind exact executed bytes"
        );
        ensure!(
            committed
                .commitment()
                .native_lanes
                .matches_state(network, committed.height(), &states[index])
                .map_err(|error| eyre!(error))?,
            "signed native lane policy/merge replay differs from its authenticated result"
        );
        if let Some(anchor) = anchored_genesis {
            ensure!(
                index == 1
                    && anchor
                        .committed()
                        .commitment()
                        .native_lanes
                        .matches_state(network, 1, &states[0])
                        .map_err(|error| eyre!(error))?,
                "successor does not authenticate original genesis lane state"
            );
        }
    }
    Ok(())
}

fn inspect_stopped_peer(
    peer: &NetworkPeer,
    prefix: Option<u64>,
    genesis: &GenesisBlock,
    chain_id: &ChainId,
    original_voters: &BTreeMap<PeerId, Vec<u8>>,
    expected_bpng_incarnation: Option<[u8; 32]>,
    expected_bpng_validators: &[PeerId],
) -> Result<StoppedEvidence> {
    let catalog = LaneCatalog::default();
    let lanes = ActualLaneConfig::from_catalog(&catalog);
    let blocks_dir = Kura::canonical_storage_path(&peer.kura_store_dir());
    let indexed_count = BlockStore::open_read_only(&blocks_dir)?.read_index_count()?;
    ensure!(
        (1..=MAX_RETAINED_HEIGHT).contains(&indexed_count),
        "missing/oversized stopped Kura history"
    );
    // Physical journal length may contain an unpublished suffix. Preserve it
    // without treating it as committed.
    let fingerprint = inspection_fingerprint(&blocks_dir)?;
    // Inspection ONLY. Fast opens existing journals without repair or writes;
    // its existing store-root lock is O_RDWR/create(false), never initialized.
    // The actual daemon always replays in Strict with snapshots disabled.
    let config = KuraConfig {
        init_mode: iroha_config::kura::InitMode::Fast,
        store_dir: WithOrigin::inline(peer.kura_store_dir()),
        max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
        blocks_in_memory: NonZeroUsize::new(2).expect("nonzero"),
        history_checkpoint_cache_capacity: defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        debug_output_new_blocks: false,
        fsync_mode: FsyncMode::Batched,
        fsync_interval: defaults::kura::FSYNC_INTERVAL,

        native_context_archive_max_bytes: defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        block_hash_history_bytes:
            iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes:
            iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
        membership_storage: defaults::kura::MEMBERSHIP_STORAGE_POLICY,
        fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
    };
    let (kura, _) = Kura::new_with_configured_lane_catalog(&config, &lanes, &catalog)?;
    let durable_count = u64::try_from(kura.exact_durable_blocks_count()?)?;
    ensure!(
        durable_count > 0 && durable_count <= indexed_count,
        "stopped store has no authenticated durable prefix"
    );
    let prefix = prefix.unwrap_or(durable_count);
    ensure!(
        prefix <= durable_count,
        "restart lost retained carrier heights"
    );
    let retained = read_retained_prefix(&blocks_dir, prefix)?;
    authenticate_retained_history(&retained, genesis, chain_id, original_voters)?;
    let certified_bpng_lane = inspect_certified_bpng_lane_evidence(
        &peer.kura_store_dir(),
        NetworkId::from_genesis_hash(genesis.0.hash()),
        chain_id,
        &retained,
        expected_bpng_incarnation,
        expected_bpng_validators,
        original_voters,
    )?;
    drop(kura); // Release every inspector handle before Strict daemon startup.
    ensure!(
        inspection_fingerprint(&blocks_dir)? == fingerprint
            && read_retained_prefix(&blocks_dir, prefix)? == retained,
        "inspection changed retained or unpublished journal/sidecar bytes"
    );
    Ok(StoppedEvidence {
        retained,
        certified_bpng_lane,
    })
}

fn execution_height(history: &RetainedHistory, transaction: &SignedTransaction) -> Result<u64> {
    let expected = TransactionEntrypoint::External(transaction.clone());
    let mut found = None;
    for wire in &history.blocks {
        let block = decode_framed_signed_block(wire)?;
        for (input_index, entrypoint) in block.network_entrypoints().enumerate() {
            if entrypoint == &expected {
                let (_, output) = block
                    .network_output_at(u32::try_from(input_index)?)
                    .ok_or_else(|| eyre!("retained transaction omitted its Network output"))?;
                ensure!(
                    found.is_none() && output.result.0.is_ok(),
                    "signed transaction must have one successful retained execution"
                );
                let context = block
                    .execution_context()
                    .ok_or_else(|| eyre!("committed execution plan missing"))?;
                let routes = context
                    .external
                    .iter()
                    .filter(|route| route.entrypoint_hash == transaction.hash_as_entrypoint())
                    .collect::<Vec<_>>();
                ensure!(
                    routes.len() == 1,
                    "exact entrypoint execution route missing/duplicated"
                );
                let route = routes[0];
                ensure!(
                    route.lane_id == LaneId::SINGLE && route.dataspace_id == DataSpaceId::UNIVERSAL,
                    "alias/control escaped original universal lane"
                );
                ensure!(
                    route.routing_plan_legs.len() == 1
                        && route.routing_plan_legs[0].lane_id == LaneId::SINGLE
                        && route.routing_plan_legs[0].dataspace_id == DataSpaceId::UNIVERSAL,
                    "full retained routing plan changed scope"
                );
                found = Some(block.header().height().get());
            }
        }
    }
    found.ok_or_else(|| eyre!("signed native transaction missing from persisted execution history"))
}

fn bpng_transaction_ownership(
    history: &RetainedHistory,
    transaction: &SignedTransaction,
    incarnation: [u8; 32],
    expected_validators: &[PeerId],
) -> Result<(u64, SumeragiLaneRecord)> {
    let expected = TransactionEntrypoint::External(transaction.clone());
    let states = native_lane_states(history)?;
    let mut found = None;
    for (height_index, wire) in history.blocks.iter().enumerate() {
        let block = decode_framed_signed_block(wire)?;
        for (input_index, entrypoint) in block.network_entrypoints().enumerate() {
            if entrypoint != &expected {
                continue;
            }
            ensure!(
                found.is_none()
                    && block
                        .network_output_at(u32::try_from(input_index)?)
                        .is_some_and(|(_, output)| output.result.0.is_ok()),
                "BPNG transaction must execute successfully exactly once"
            );
            let context = block
                .execution_context()
                .ok_or_else(|| eyre!("BPNG execution context missing"))?;
            let routes = context
                .external
                .iter()
                .filter(|route| route.entrypoint_hash == transaction.hash_as_entrypoint())
                .collect::<Vec<_>>();
            ensure!(
                routes.len() == 1
                    && routes[0].lane_id == BPNG_FIXTURE_LANE
                    && routes[0].dataspace_id == DataSpaceId::new(BPNG_ID)
                    && routes[0].routing_plan_legs.len() == 1
                    && routes[0].routing_plan_legs[0].lane_id == BPNG_FIXTURE_LANE
                    && routes[0].routing_plan_legs[0].dataspace_id == DataSpaceId::new(BPNG_ID),
                "BPNG transaction lost its exact singleton route"
            );
            let section = block
                .lane_merge()
                .ok_or_else(|| eyre!("BPNG transaction was not carried by a native lane merge"))?;
            ensure!(
                section.merges.len() == 1
                    && section.merged_count == 1
                    && section.merges[0].lane == BPNG_FIXTURE_LANE
                    && section.merges[0].from == section.merges[0].to
                    && input_index + 1 == block.network_entrypoints().count(),
                "BPNG transaction must be the exact singleton suffix of one certified native lane block"
            );
            let record = states[height_index]
                .lane(BPNG_FIXTURE_LANE)
                .ok_or_else(|| eyre!("native lane state missing"))?;
            assert_bpng_record(record, incarnation, expected_validators)?;
            ensure!(
                record.merged_at == block.header().height().get(),
                "native merged frontier points at another global carrier"
            );
            found = Some((record.merged_at, record.clone()));
        }
    }
    found.ok_or_else(|| eyre!("BPNG signed transaction missing from native retained history"))
}

async fn stop_all(peers: &[NetworkPeer]) -> Result<()> {
    try_join_all(peers.iter().map(|peer| async move {
        ensure!(
            timeout(NETWORK_TIMEOUT, peer.shutdown_if_started()).await?,
            "expected running original peer"
        );
        Ok::<_, eyre::Report>(())
    }))
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bpng_native_bootstrap_survives_four_peer_retained_kura_catalog_expansion() -> Result<()> {
    required_prebuilt_binaries()?;
    init_instruction_registry();
    let mut npos = SumeragiNposParameters::default();
    npos.xor_asset_definition_id = stake_asset_definition_id();
    npos.max_validators = u32::try_from(VALIDATOR_COUNT)?;
    // Keep the genuine next-election boundary inside this bounded integration
    // history; validator promotion still waits for the signed epoch boundary.
    // These are fixture horizons, not public-Taira operating recommendations.
    npos.epoch_length_blocks =
        NonZeroU64::new(FIXTURE_EPOCH_LENGTH_BLOCKS).expect("non-zero fixture epoch");
    npos.finality_margin_blocks = 2;
    npos.evidence_horizon_blocks = 16;
    npos.slashing_delay_blocks = 8;
    npos.validate()
        .map_err(|error| eyre!("invalid four-validator NPoS fixture parameters: {error}"))?;
    let builder = NetworkBuilder::new()
        .with_peers(VALIDATOR_COUNT)
        .with_base_seed(NETWORK_SEED)
        .with_auto_populated_trusted_peers()
        .with_npos_consensus()
        .without_npos_genesis_bootstrap()
        .with_genesis_block(|topology, topology_entries| {
            unexecuted_genesis_factory_with_post_topology(
                Vec::new(),
                custom_genesis_post_topology(topology.as_ref(), &topology_entries),
                topology,
                topology_entries,
            )
        })
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )))
        .with_block_cadence(Duration::from_secs(1))
        .with_config_layer(|layer| {
            // Fees are fixed in the original network and retained on restart.
            // Keep one fluent borrow of the configuration writer.
            layer
                .write(
                    ["nexus", "fees", "fee_asset_id"],
                    stake_asset_definition_id().to_string(),
                )
                .write(
                    ["nexus", "staking", "stake_asset_id"],
                    stake_asset_definition_id().to_string(),
                )
                .write(
                    ["nexus", "staking", "stake_escrow_account_id"],
                    staking_custody_account().to_string(),
                )
                .write(
                    ["nexus", "staking", "slash_sink_account_id"],
                    staking_custody_account().to_string(),
                )
                .write(["snapshot", "mode"], "disabled")
                .write(["kura", "init_mode"], "strict")
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1_073_741_824_i64,
                )
                .write(["nexus", "fees", "base_fee"], "0")
                .write(["nexus", "fees", "per_byte_fee"], "0")
                .write(["nexus", "fees", "per_instruction_fee"], "0")
                .write(["nexus", "fees", "per_gas_unit_fee"], "0");
        });
    let network = timeout(
        NETWORK_TIMEOUT,
        sandbox::start_network_async_or_skip(
            builder,
            stringify!(
                bpng_native_bootstrap_survives_four_peer_retained_kura_catalog_expansion
            ),
        ),
    )
    .await??
    .ok_or_else(|| {
        eyre!(
            "this retained-Kura qualification requires a real four-peer network; skipping is forbidden"
        )
    })?;
    ensure!(
        network.peers().len() == VALIDATOR_COUNT,
        "exactly four original validators required"
    );
    let genesis = network.genesis();
    let original_voters = network
        .peers()
        .iter()
        .map(|peer| {
            let key = peer
                .bls_public_key()
                .ok_or_else(|| eyre!("missing original BLS voter key"))?;
            ensure!(
                key.algorithm() == Algorithm::BlsNormal
                    && PeerId::new(key.clone()) == peer.network_peer_id(),
                "original BLS voter identity mismatch"
            );
            Ok((
                peer.network_peer_id(),
                peer.bls_pop()
                    .ok_or_else(|| eyre!("missing original PoP"))?
                    .to_vec(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        original_voters.len() == VALIDATOR_COUNT
            && iroha_core::sumeragi::schedule::genesis_validators(&genesis)? == original_voters,
        "signed genesis must contain exactly the original four voters"
    );
    let expected_validator_peers = original_voters.keys().cloned().collect::<Vec<_>>();
    let validator_keypairs = (0..VALIDATOR_COUNT)
        .map(validator_keypair)
        .collect::<Vec<_>>();
    let expected_validator_bindings = network
        .peers()
        .iter()
        .zip(&validator_keypairs)
        .map(|(peer, keypair)| {
            ensure!(
                peer.streaming_public_key() == keypair.public_key(),
                "deterministic validator signer differs from NetworkBuilder identity"
            );
            Ok((
                AccountId::new(keypair.public_key().clone()),
                peer.network_peer_id(),
            ))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        expected_validator_bindings.len() == VALIDATOR_COUNT,
        "validator signer/peer bindings must be unique"
    );
    let clients = network
        .peers()
        .iter()
        .map(|peer| bounded_client(peer.client()))
        .collect::<Vec<_>>();
    let validator_clients = network
        .peers()
        .iter()
        .zip(&validator_keypairs)
        .map(|(peer, keypair)| {
            bounded_client(peer.client_for(
                &AccountId::new(keypair.public_key().clone()),
                keypair.private_key().clone(),
            ))
        })
        .collect::<Vec<_>>();
    let authority = &clients[0];
    let payer =
        bounded_client(network.peers()[0].client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone()));
    let grant = AliasDataspaceBootstrapGrantV1::try_new("bpng", BOB_ID.clone())?;
    ensure!(
        grant.dataspace.dataspace_id.as_u64() == BPNG_ID,
        "canonical BPNG identity must never be DPN 10"
    );
    let read_client = authority.clone();
    let baseline_leases = read(move || {
        [SnsNamespacePath::Domain, SnsNamespacePath::Dataspace]
            .into_iter()
            .map(|namespace| {
                Ok(LeaseExpectation {
                    namespace,
                    literal: String::new(),
                    policy: read_client
                        .client()
                        .sns()
                        .get_policy(namespace.suffix_id())?,
                    amount: Quantity::zero(),
                })
            })
            .collect::<Result<Vec<_>>>()
    })
    .await?;
    let read_client = authority.clone();
    let baseline_terms = baseline_leases.clone();
    let baseline_balances = read(move || balances(&read_client, &baseline_terms)).await?;
    let domain_intent = |domain: &str, dataspace: &str, id| -> Result<_> {
        Ok(AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(DomainId::try_new(domain, dataspace)?, id),
            owner: BOB_ID.clone(),
        }))
    };
    let (historical, historical_lease) = acquire(
        &payer,
        domain_intent("history", "universal", DataSpaceId::UNIVERSAL)?,
        SnsNamespacePath::Domain,
        "history.universal",
    )
    .await?;
    let granted = submit(
        authority,
        transaction(
            authority,
            SetParameter::new(Parameter::Custom(grant.clone().into_custom_parameter()?)),
        ),
    )
    .await?;
    let (dataspace, dataspace_lease) = acquire(
        &payer,
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: grant.dataspace.clone(),
            owner: BOB_ID.clone(),
        }),
        SnsNamespacePath::Dataspace,
        "bpng",
    )
    .await?;
    let (domain, domain_lease) = acquire(
        &payer,
        domain_intent("mibank", "bpng", grant.dataspace.dataspace_id)?,
        SnsNamespacePath::Domain,
        "mibank.bpng",
    )
    .await?;
    let leases = vec![historical_lease, dataspace_lease, domain_lease];
    let mut transactions = vec![historical, granted, dataspace, domain];
    let expected = wait_for_snapshot(authority, &leases, &grant, &transactions, None).await?;
    assert_paid_once(&baseline_balances, &expected.balances, &leases)?;
    let mut original_lanes = Vec::new();
    for client in &clients {
        wait_for_snapshot(client, &leases, &grant, &transactions, Some(&expected)).await?;
        original_lanes.push(observe_catalog_expansion(client, false).await?);
    }
    let initial_prefix = common_retained_prefix(&clients).await?;
    stop_all(network.peers()).await?;
    let initial_evidence = network
        .peers()
        .iter()
        .map(|peer| {
            inspect_stopped_peer(
                peer,
                Some(initial_prefix),
                &genesis,
                &network.chain_id(),
                &original_voters,
                None,
                &expected_validator_peers,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    assert_same_authenticated_prefix(&initial_evidence)?;
    for evidence in &initial_evidence {
        let history = &evidence.retained;
        ensure!(
            execution_height(history, &transactions[0])?
                < execution_height(history, &transactions[1])?,
            "the first paid universal alias must precede the owner bootstrap grant"
        );
        ensure!(
            execution_height(history, &transactions[1])?
                < execution_height(history, &transactions[2])?,
            "owner grant must precede first paid dataspace lease"
        );
        ensure!(
            execution_height(history, &transactions[2])?
                < execution_height(history, &transactions[3])?,
            "paid dataspace lease must precede its domain lease"
        );
        ensure!(
            evidence.certified_bpng_lane == CertifiedBpngLaneEvidence::absent(),
            "fixture-only BPNG lane must not exist before its signed lifecycle"
        );
    }
    // Preserve every original layer, including fees, lane authority and signed
    // genesis. The one new layer adds only the canonical BPNG catalog identity.
    let mut layers: Vec<Cow<'static, Table>> = network
        .config_layers()
        .map(|layer| Cow::Owned(layer.into_owned()))
        .collect::<Vec<_>>();
    layers.push(Cow::Owned(dataspace_only_restart_layer(&grant)));
    try_join_all(network.peers().iter().map(|peer| async {
        timeout(NETWORK_TIMEOUT, peer.start_checked(layers.iter(), None)).await??;
        Ok::<_, eyre::Report>(())
    }))
    .await?;
    for ((client, retained), original_lanes) in
        clients.iter().zip(&initial_evidence).zip(&original_lanes)
    {
        wait_for_snapshot(client, &leases, &grant, &transactions, Some(&expected)).await?;
        ensure!(
            &observe_catalog_expansion(client, true).await? == original_lanes,
            "dataspace-only restart changed a lane or its incarnation commitment"
        );
        ensure!(
            height(client).await? >= u64::try_from(retained.retained.blocks.len())?,
            "restart did not recover original retained tip"
        );
    }

    let original_lifecycle = lane_lifecycle_status(authority).await?;
    ensure!(
        original_lifecycle.validate()? == LaneCatalog::default(),
        "dataspace-only restart must not create a lane"
    );
    let lifecycle_plan = LaneLifecyclePlan {
        additions: vec![bpng_fixture_lane()],
        retire: Vec::new(),
    };
    let lifecycle_parameter = LaneLifecycleParameterV1::new(
        &original_lifecycle.validate()?,
        &original_lifecycle.incarnations,
        lifecycle_plan,
    )?;
    let lifecycle = submit(
        authority,
        transaction(
            authority,
            SetParameter::new(Parameter::Custom(
                lifecycle_parameter.into_custom_parameter(),
            )),
        ),
    )
    .await?;
    transactions.push(lifecycle);
    let lifecycle_deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    let lifecycle_status = loop {
        let status = lane_lifecycle_status(authority).await?;
        if let Ok(incarnation) = assert_bpng_lifecycle_status(&status, &original_lifecycle) {
            break (status, incarnation);
        }
        ensure!(
            Instant::now() < lifecycle_deadline,
            "signed fixture-only BPNG lifecycle did not converge"
        );
        sleep(POLL_INTERVAL).await;
    };
    let physical_bpng_incarnation = lifecycle_status.1;
    for client in &clients {
        let status = lane_lifecycle_status(client).await?;
        ensure!(
            status == lifecycle_status.0
                && assert_bpng_lifecycle_status(&status, &original_lifecycle)?
                    == physical_bpng_incarnation,
            "signed fixture-only BPNG lifecycle did not converge exactly"
        );
    }

    let stake = SumeragiNposParameters::default().min_self_bond().clone();
    let registration_alignment_deadline = Instant::now() + ADVANCE_TIMEOUT;
    let mut registration_alignment_tick = 0_u32;
    while height(authority).await? % FIXTURE_EPOCH_LENGTH_BLOCKS != 0 {
        ensure!(
            Instant::now() < registration_alignment_deadline && registration_alignment_tick < 16,
            "could not align BPNG registrations to one exact election epoch"
        );
        submit(
            authority,
            transaction(
                authority,
                Log::new(
                    Level::INFO,
                    format!("bpng-fixture-registration-alignment-{registration_alignment_tick}"),
                ),
            ),
        )
        .await?;
        registration_alignment_tick = registration_alignment_tick.saturating_add(1);
    }
    let registration_height = height(authority).await?;
    ensure!(
        registration_height % FIXTURE_EPOCH_LENGTH_BLOCKS == 0,
        "registration alignment moved before signing exact staking consent"
    );
    let parameters_client = authority.clone();
    let parameters: Parameters =
        read(move || Ok(parameters_client.client().query_single(FindParameters)?)).await?;
    let schedule = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .ok_or_else(|| eyre!("BPNG registration requires the committed NPoS schedule"))?;
    ensure!(
        schedule.epoch_length_blocks.get() == FIXTURE_EPOCH_LENGTH_BLOCKS,
        "BPNG registration schedule differs from the aligned fixture epoch"
    );
    let epoch_end = registration_height
        .checked_add(schedule.epoch_length_blocks.get())
        .ok_or_else(|| eyre!("registration epoch end overflowed"))?;
    let valid_until_height = epoch_end
        .checked_sub(1)
        .ok_or_else(|| eyre!("registration validity height underflowed"))?;
    let mut planned_activation_height = None;
    let mut self_registrations = Vec::with_capacity(VALIDATOR_COUNT);
    for ((validator_client, peer), keypair) in validator_clients
        .iter()
        .zip(network.peers())
        .zip(&validator_keypairs)
    {
        let validator = AccountId::new(keypair.public_key().clone());
        let request = PublicLanePreparationRequestV1 {
            lane_id: BPNG_FIXTURE_LANE,
            valid_for_blocks: FIXTURE_EPOCH_LENGTH_BLOCKS,
            operation: PublicLanePreparationOperationV1::Registration(
                PublicLanePrepareRegistrationV1 {
                    validator: validator.clone(),
                    peer_id: peer.network_peer_id(),
                    amount: stake.clone(),
                    candidate: false,
                },
            ),
        };
        let prepared = validator_client
            .client()
            .nexus()
            .prepare_public_lane_plan(&request)
            .await?;
        ensure!(
            prepared.xor_asset_definition_id == stake_asset_definition_id(),
            "prepared BPNG self-bond must use the signed network XOR"
        );
        let PublicLanePreparedPlanV1::Monetary(monetary_plan) = prepared.plan else {
            return Err(eyre!(
                "BPNG registration did not prepare an exact monetary plan"
            ));
        };
        let PublicLaneMonetaryPreconditionV1::Registration(registration) =
            &monetary_plan.precondition
        else {
            return Err(eyre!(
                "BPNG registration preparation returned a different staking operation"
            ));
        };
        ensure!(
            registration.activation_height > epoch_end,
            "BPNG activation must follow the frozen election epoch"
        );
        if let Some(previous_height) = planned_activation_height {
            ensure!(
                previous_height == registration.activation_height,
                "BPNG preparation returned different activation heights for one validator batch"
            );
        } else {
            planned_activation_height = Some(registration.activation_height);
        }
        ensure!(
            monetary_plan.network_scope == PublicLaneMonetaryScopeV1::Network(network.network_id())
                && monetary_plan.valid_until_height >= valid_until_height
                && monetary_plan.source_asset
                    == AssetId::new(stake_asset_definition_id(), validator.clone())
                && monetary_plan.destination_asset
                    == AssetId::new(stake_asset_definition_id(), staking_custody_account())
                && monetary_plan.amount == stake,
            "prepared BPNG monetary consent differs from the expected registration"
        );
        let signed = transaction(
            validator_client,
            RegisterPublicLaneValidator::new(
                BPNG_FIXTURE_LANE,
                validator.clone(),
                peer.network_peer_id(),
                validator.clone(),
                stake.clone(),
                Metadata::default(),
                monetary_plan,
            ),
        );
        ensure!(
            signed.authority() == &validator && signed.verify_signature().is_ok(),
            "BPNG validator registration must be signed by its exact validator account"
        );
        self_registrations.push((validator_client, signed));
    }
    let planned_activation_height = planned_activation_height
        .ok_or_else(|| eyre!("BPNG fixture prepared no validator registrations"))?;
    ensure!(
        height(authority).await? < valid_until_height,
        "exact registration consent expired before submission"
    );
    // Admit the independently signed accounts together so real certified global blocks
    // can execute all four registrations before the one consented election freezes.
    let self_registrations = try_join_all(
        self_registrations
            .into_iter()
            .map(|(client, signed)| submit(client, signed)),
    )
    .await?;
    transactions.extend(self_registrations);
    let activation_boundary =
        wait_for_exact_bpng_pending_registrations(authority, &expected_validator_bindings, &stake)
            .await?;
    ensure!(
        activation_boundary == planned_activation_height,
        "retained pending validators differ from the exact signed activation tenure"
    );
    let deadline = Instant::now() + ADVANCE_TIMEOUT;
    let mut activation_tick = 0_u32;
    while height(authority).await? < activation_boundary {
        ensure!(
            Instant::now() < deadline && activation_tick < 64,
            "BPNG validator activation boundary did not arrive"
        );
        submit(
            authority,
            transaction(
                authority,
                Log::new(
                    Level::INFO,
                    format!("bpng-fixture-validator-activation-{activation_tick}"),
                ),
            ),
        )
        .await?;
        activation_tick = activation_tick.saturating_add(1);
    }
    ensure!(
        wait_for_exact_bpng_pending_registrations(authority, &expected_validator_bindings, &stake,)
            .await?
            == activation_boundary,
        "BPNG pending set or its exact boundary changed before the governed sweep"
    );
    let sweep_validator = AccountId::new(validator_keypairs[0].public_key().clone());
    let sweep_reader = validator_clients[0].clone();
    let sweep_authority = sweep_validator.clone();
    let sweep_permissions = read(move || {
        sweep_reader
            .client()
            .query(FindPermissionsByAccountId::new(sweep_authority))
            .execute_all()
            .map_err(Into::into)
    })
    .await?;
    ensure!(
        sweep_permissions
            .iter()
            .any(|permission| permission == &Permission::from(CanManagePeers)),
        "BPNG activation sweep authority lacks its signed-genesis CanManagePeers grant"
    );
    // ActivatePublicLaneValidator begins with the canonical lifecycle finalizer.
    // One authorised transaction at the shared boundary therefore sweeps all
    // four eligible PendingActivation records before idempotently observing
    // its named target as Active. This is governed batch promotion evidence,
    // not evidence for four independent per-validator promotions.
    let activation_sweep = transaction(
        &validator_clients[0],
        ActivatePublicLaneValidator::new(BPNG_FIXTURE_LANE, sweep_validator.clone()),
    );
    ensure!(
        activation_sweep.authority() == &sweep_validator
            && activation_sweep.verify_signature().is_ok(),
        "BPNG activation sweep must be signed by the exact authorised manager"
    );
    transactions.push(submit(&validator_clients[0], activation_sweep).await?);
    wait_for_exact_bpng_validators(&clients, &expected_validator_bindings, &stake).await?;

    // Physical catalog ownership and native lane consensus are distinct signed state.
    // Install the one native lane only after its four funded validators are active.
    let native_policy = SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: MAX_RETAINED_HEIGHT,
        max_merge_blocks: 16,
        stall_window: MAX_RETAINED_HEIGHT * 2,
        lane_params: SumeragiParameters::default(),
        fixed: vec![SumeragiFixedLane {
            lane: BPNG_FIXTURE_LANE,
            dataspace: DataSpaceId::new(BPNG_ID),
            committee: expected_validator_peers
                .iter()
                .map(|peer| SumeragiLaneMember {
                    peer: peer.clone(),
                    pop: original_voters
                        .get(peer)
                        .expect("signed original voter")
                        .clone(),
                })
                .collect(),
        }],
        routes: vec![SumeragiLaneRoute {
            lane: BPNG_FIXTURE_LANE,
            account: Some(BOB_ID.to_string()),
            instruction: None,
        }],
        autoscale: None,
    };
    transactions.push(
        submit(
            authority,
            transaction(
                authority,
                SetParameter::new(Parameter::Custom(native_policy.into_custom_parameter())),
            ),
        )
        .await?,
    );
    let native_lane_deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    let native_record = loop {
        let reader = authority.clone();
        let statuses = read(move || reader.client().get_sumeragi_lanes()).await?;
        if let Some(status) = statuses
            .into_iter()
            .find(|status| status.record.lane == BPNG_FIXTURE_LANE)
        {
            break status.record;
        }
        ensure!(
            Instant::now() < native_lane_deadline,
            "signed native lane policy did not apply"
        );
        sleep(POLL_INTERVAL).await;
    };
    let bpng_incarnation = native_record.incarnation;
    while height(authority).await? < native_record.active_from {
        ensure!(
            Instant::now() < native_lane_deadline,
            "native lane activation did not advance"
        );
        transactions.push(
            submit(
                authority,
                transaction(
                    authority,
                    Log::new(Level::INFO, "activate native BPNG lane".to_owned()),
                ),
            )
            .await?,
        );
    }

    let predecessor_key: Name = "retained_bpng_predecessor".parse()?;
    let predecessor_value = Json::new("committed-before-strict-restart");
    let predecessor = submit(
        &payer,
        transaction(
            &payer,
            SetKeyValue::domain(
                DomainId::try_new("mibank", "bpng")?,
                predecessor_key.clone(),
                predecessor_value.clone(),
            ),
        ),
    )
    .await?;
    let predecessor_frontier = wait_for_bpng_frontier(
        &clients,
        bpng_incarnation,
        &expected_validator_peers,
        &predecessor,
    )
    .await?;
    transactions.push(predecessor.clone());
    for client in &clients {
        assert_bpng_metadata(client, &predecessor_key, &predecessor_value, None).await?;
    }
    let before_second_restart =
        wait_for_snapshot(authority, &leases, &grant, &transactions, None).await?;
    assert_paid_once(&baseline_balances, &before_second_restart.balances, &leases)?;
    let pre_restart_prefix = common_retained_prefix(&clients).await?;
    ensure!(
        pre_restart_prefix > initial_prefix,
        "BPNG predecessor did not extend the original retained prefix"
    );
    stop_all(network.peers()).await?;

    let pre_restart_evidence = network
        .peers()
        .iter()
        .map(|peer| {
            inspect_stopped_peer(
                peer,
                Some(pre_restart_prefix),
                &genesis,
                &network.chain_id(),
                &original_voters,
                Some(bpng_incarnation),
                &expected_validator_peers,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    for ((evidence, initial), peer_index) in
        pre_restart_evidence.iter().zip(&initial_evidence).zip(0..)
    {
        ensure!(
            evidence
                .retained
                .blocks
                .starts_with(&initial.retained.blocks),
            "first strict replay changed an original certified carrier on peer {peer_index}"
        );
        let (_, ownership) = bpng_transaction_ownership(
            &evidence.retained,
            &predecessor,
            bpng_incarnation,
            &expected_validator_peers,
        )?;
        ensure!(
            ownership == predecessor_frontier,
            "live and stopped-Kura BPNG predecessor ownership differ"
        );
    }
    assert_same_authenticated_prefix(&pre_restart_evidence)?;

    // Restart two deliberately reuses the same dataspace-only operator layer.
    // Lane 8 must come exclusively from the signed lifecycle replay.
    try_join_all(network.peers().iter().map(|peer| async {
        timeout(NETWORK_TIMEOUT, peer.start_checked(layers.iter(), None)).await??;
        Ok::<_, eyre::Report>(())
    }))
    .await?;
    for (client, retained) in clients.iter().zip(&pre_restart_evidence) {
        wait_for_snapshot(
            client,
            &leases,
            &grant,
            &transactions,
            Some(&before_second_restart),
        )
        .await?;
        let status = lane_lifecycle_status(client).await?;
        ensure!(
            status == lifecycle_status.0
                && assert_bpng_lifecycle_status(&status, &original_lifecycle)?
                    == physical_bpng_incarnation,
            "strict restart did not replay exact signed BPNG lifecycle/incarnation"
        );
        ensure!(
            height(client).await? >= u64::try_from(retained.retained.blocks.len())?,
            "strict restart did not recover the BPNG predecessor carrier"
        );
        assert_bpng_metadata(client, &predecessor_key, &predecessor_value, None).await?;
    }
    wait_for_exact_bpng_validators(&clients, &expected_validator_bindings, &stake).await?;
    ensure!(
        wait_for_bpng_frontier(
            &clients,
            bpng_incarnation,
            &expected_validator_peers,
            &predecessor,
        )
        .await?
            == predecessor_frontier,
        "strict restart did not recover exact BPNG predecessor ownership"
    );

    let successor_key: Name = "retained_bpng_successor".parse()?;
    let successor_value = Json::new("committed-after-strict-restart");
    let successor = submit(
        &payer,
        transaction(
            &payer,
            SetKeyValue::domain(
                DomainId::try_new("mibank", "bpng")?,
                successor_key.clone(),
                successor_value.clone(),
            ),
        ),
    )
    .await?;
    let successor_frontier = wait_for_bpng_frontier(
        &clients,
        bpng_incarnation,
        &expected_validator_peers,
        &successor,
    )
    .await?;
    ensure!(
        successor_frontier.incarnation == predecessor_frontier.incarnation
            && successor_frontier.merged.height
                == predecessor_frontier.merged.height.saturating_add(1),
        "post-restart BPNG successor did not extend the retained predecessor/incarnation"
    );
    transactions.push(successor.clone());
    for client in &clients {
        assert_bpng_metadata(
            client,
            &predecessor_key,
            &predecessor_value,
            Some((&successor_key, &successor_value)),
        )
        .await?;
    }
    let after_successor =
        wait_for_snapshot(authority, &leases, &grant, &transactions, None).await?;
    assert_paid_once(&baseline_balances, &after_successor.balances, &leases)?;
    let after_restart_prefix = common_retained_prefix(&clients).await?;
    ensure!(
        after_restart_prefix > pre_restart_prefix,
        "BPNG successor did not extend the pre-restart retained prefix"
    );
    stop_all(network.peers()).await?;

    let after_restart_evidence = network
        .peers()
        .iter()
        .map(|peer| {
            inspect_stopped_peer(
                peer,
                Some(after_restart_prefix),
                &genesis,
                &network.chain_id(),
                &original_voters,
                Some(bpng_incarnation),
                &expected_validator_peers,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    for ((after, before), peer_index) in after_restart_evidence
        .iter()
        .zip(&pre_restart_evidence)
        .zip(0..)
    {
        ensure!(
            after.retained.blocks.starts_with(&before.retained.blocks),
            "second strict replay changed retained certified carriers on peer {peer_index}"
        );
        before
            .certified_bpng_lane
            .assert_exact_prefix_of(&after.certified_bpng_lane)?;
        ensure!(
            after.certified_bpng_lane.artifacts.len()
                == before.certified_bpng_lane.artifacts.len().saturating_add(1),
            "post-restart successor must append exactly one certified BPNG lane block"
        );
        let (predecessor_height, retained_predecessor) = bpng_transaction_ownership(
            &after.retained,
            &predecessor,
            bpng_incarnation,
            &expected_validator_peers,
        )?;
        let (successor_height, retained_successor) = bpng_transaction_ownership(
            &after.retained,
            &successor,
            bpng_incarnation,
            &expected_validator_peers,
        )?;
        ensure!(
            retained_predecessor == predecessor_frontier
                && retained_successor == successor_frontier
                && successor_height > predecessor_height,
            "stopped Kura does not retain the exact BPNG predecessor/successor chain"
        );
    }
    assert_same_authenticated_prefix(&after_restart_evidence)?;
    Ok(())
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
    let transactions = custom_genesis_post_topology(&topology, &entries);
    let committee_registrations = transactions
        .iter()
        .flatten()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<RegisterConsensusKey>())
        .collect::<Vec<_>>();
    assert_eq!(committee_registrations.len(), VALIDATOR_COUNT);
    for (registration, peer) in committee_registrations.iter().zip(&topology) {
        assert_eq!(registration.id, derive_committee_key_id(peer.public_key()));
        assert_eq!(registration.record.public_key, peer.public_key().clone());
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
    assert_eq!(registrations.len(), 4);
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
            iroha_data_model::asset::AssetId::new(
                stake_asset_definition_id(),
                staking_custody_account()
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
}
