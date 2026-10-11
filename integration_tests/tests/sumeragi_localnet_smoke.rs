#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Bounded-latency localnet smoke and throughput tests for permissioned and `NPoS` Sumeragi.
use blake3::Hasher as Blake3Hasher;
use eyre::{Result, WrapErr, bail, ensure, eyre};
use futures_util::{
    StreamExt, TryStreamExt,
    future::{join_all, try_join_all},
    stream::{self, FuturesUnordered},
};
use integration_tests::sandbox;
use iroha::{
    crypto::{Algorithm, HashOf, KeyPair},
    data_model::{
        Level,
        account::{Account, AccountId, OpaqueAccountId},
        asset::{AssetDefinition, AssetDefinitionId, AssetId},
        block::{Header, consensus::SumeragiDiagnosticsStatus},
        domain::Domain,
        events::time::{ExecutionTime, TimeEventFilter},
        identifier::{
            IdentifierNormalization, IdentifierPolicyId, IdentifierResolutionReceipt,
            IdentifierResolutionReceiptPayload,
        },
        isi::{InstructionBox, Log, Mint, Register, SetKeyValue, SetParameter, Transfer},
        nexus::UniversalAccountId,
        parameter::{BlockParameter, Parameter, system::SumeragiNposParameters},
        prelude::{Action, FindAssetById, Quantity, Repeats},
        query::block::prelude::FindBlocks,
        ram_lfe::{
            RamLfeExecutionReceiptPayload, RamLfeOutputOpening, RamLfeOutputOpeningPayload,
            RamLfeProgramId, RamLfeReceiptAttestation,
        },
        trigger::Trigger,
    },
};
use iroha_crypto::{
    Hash, RamLfeBackend, RamLfeVerificationMode, Signature, SignatureOf,
    identifier_hashes_from_output_hash, ram_lfe_output_hash,
};
use iroha_data_model::{HasMetadata, prelude::QueryBuilderExt};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use iroha_test_network::{
    Network, NetworkBuilder, init_instruction_registry, read_on_dedicated_thread,
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, BOB_ID, BOB_KEYPAIR};
use nonzero_ext::nonzero;
use norito::json::{Map, Value};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use reqwest::Client as HttpClient;
use std::{
    cmp::Ordering,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::tempdir;
use tokio::{sync::Mutex, task, time::sleep};
use toml::{Table, Value as TomlValue};
#[path = "sumeragi_localnet_smoke/idle_chain.rs"]
mod idle_chain;
#[path = "../../crates/iroha_test_network/tests/support/multiroute.rs"]
mod multiroute;
use multiroute::{ROUTE_VALIDATOR_FEE_SEED_AMOUNT, route_fee_asset_definition_id};
static LOCALNET_SMOKE_GUARD: OnceLock<Mutex<()>> = OnceLock::new();
const SMOKE_PIPELINE_TIME: Duration = Duration::from_secs(2);
const STATUS_POLL_TIMEOUT: Duration = Duration::from_secs(15);
const STATUS_LOG_INTERVAL: Duration = Duration::from_secs(2);
const SOAK_BLOCK_CADENCE_MS: u64 = 100;
const SOAK_STATUS_POLL_TIMEOUT: Duration = Duration::from_secs(20);
const SOAK_TARGET_BLOCKS: u64 = 2_000;
const SOAK_SUBMIT_BATCH: u64 = 200;
const SOAK_QUEUE_SOFT_LIMIT: u64 = 2_000;
const SOAK_QUEUE_PROGRESS_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const SOAK_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const SOAK_PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(5);
const SOAK_STALL_THRESHOLD: Duration = Duration::from_secs(90);
const SOAK_CLIENT_TTL: Duration = Duration::from_secs(2 * 60 * 60);
const THROUGHPUT_PIPELINE_TIME: Duration = Duration::from_secs(2);
const THROUGHPUT_BLOCK_CADENCE_MS: u64 = 1_000;
const THROUGHPUT_COMMIT_SLO_BASE_MS: u64 = 1_000;
const THROUGHPUT_BLOCK_MAX_TXS: u64 = 10_000;
const THROUGHPUT_LANE_TEU_FLOOR: i64 = 1;
const THROUGHPUT_LANE_TEU_CAPACITY: i64 = 1_000_000_000;
const THROUGHPUT_SUBMIT_BATCH: u64 = 512;
const THROUGHPUT_SUBMIT_PARALLELISM: u64 = 128;
const THROUGHPUT_QUEUE_SOFT_LIMIT: u64 = 20_000;
const THROUGHPUT_STALL_THRESHOLD: Duration = Duration::from_secs(60);
const THROUGHPUT_COMMIT_TIME_MAX_MULTIPLIER: u64 = 2;
const THROUGHPUT_CLIENT_TTL: Duration = Duration::from_secs(2 * 60 * 60);
const THROUGHPUT_WARMUP_BLOCKS: u64 = 10;
const THROUGHPUT_STEADY_BLOCKS: u64 = 30;
const THROUGHPUT_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
const THROUGHPUT_PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(10);
const THROUGHPUT_METRICS_TIMEOUT: Duration = Duration::from_secs(5);
const THROUGHPUT_PAYLOAD_BYTES: usize = 512;
const THROUGHPUT_RNG_SEED: u64 = 0x0049_524f_4841;
const THROUGHPUT_SLO_P95_MS: u64 = 1_500;
const THROUGHPUT_SLO_P99_MS: u64 = 2_000;
const THROUGHPUT_SLO_VIEW_CHANGE_RATE_MAX: f64 = 0.1;
const THROUGHPUT_SLO_QUEUE_SAT_FRAC_MAX: f64 = 0.2;
const THROUGHPUT_NPOS_SLO_P95_MS: u64 = 2_000;
const THROUGHPUT_NPOS_SLO_P99_MS: u64 = 3_000;
const THROUGHPUT_NPOS_SLO_VIEW_CHANGE_RATE_MAX: f64 = 0.2;
const THROUGHPUT_NPOS_SLO_QUEUE_SAT_FRAC_MAX: f64 = 0.3;
const THROUGHPUT_QUEUE_PROGRESS_TIMEOUT_ENV: &str = "IROHA_THROUGHPUT_QUEUE_PROGRESS_TIMEOUT_SECS";
const REALISTIC_30TPS_PEERS: usize = 4;
const REALISTIC_30TPS_DURATION_SECS: u64 = 7_200;
// Default to the transaction-capacity floor; env can raise this for stricter
// block-cadence checks.
const REALISTIC_30TPS_TARGET_BLOCKS: u64 = 0;
const REALISTIC_30TPS_TARGET_TPS: u64 = 30;
const REALISTIC_30TPS_BLOCK_CADENCE_MS: u64 = 400;
const REALISTIC_30TPS_BLOCK_MAX_TXS: u64 = 128;
const REALISTIC_30TPS_SUBMIT_PARALLELISM: usize = 64;
const REALISTIC_30TPS_QUEUE_SOFT_LIMIT: u64 = 3_000;
const REALISTIC_30TPS_ROTATING_FAULT_QUEUE_SOFT_LIMIT: u64 = 64_000;
const REALISTIC_30TPS_STALL_THRESHOLD: Duration = Duration::from_secs(20);
const REALISTIC_30TPS_STALL_SECS_ENV: &str = "IROHA_REALISTIC_30TPS_STALL_SECS";
const REALISTIC_30TPS_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
const REALISTIC_30TPS_PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(10);
const REALISTIC_30TPS_STATUS_RECOVERY_POLL_TIMEOUT: Duration = Duration::from_secs(2);
const REALISTIC_30TPS_OUTAGE_ROTATE_SECS: u64 = 60;
const REALISTIC_30TPS_OUTAGE_ROTATE_SECS_ENV: &str = "IROHA_REALISTIC_30TPS_OUTAGE_ROTATE_SECS";
const REALISTIC_30TPS_OUTAGE_RECOVERY_SECS: u64 = 900;
const REALISTIC_30TPS_OUTAGE_RECOVERY_SECS_ENV: &str = "IROHA_REALISTIC_30TPS_OUTAGE_RECOVERY_SECS";
const REALISTIC_30TPS_RECOVERY_BOUND_SECS_ENV: &str = "IROHA_REALISTIC_30TPS_RECOVERY_BOUND_SECS";
const REALISTIC_30TPS_STRICT_ROTATION_CONVERGENCE_ENV: &str =
    "IROHA_REALISTIC_30TPS_STRICT_ROTATION_CONVERGENCE";
const REALISTIC_30TPS_CONVERGENCE_BOUND_SECS_ENV: &str =
    "IROHA_REALISTIC_30TPS_CONVERGENCE_BOUND_SECS";
const REALISTIC_30TPS_CONVERGENCE_BOUND_SECS: u64 = 120;
const REALISTIC_30TPS_ROTATING_FAULT_TOLERATED_PEERS: usize = 1;
const REALISTIC_30TPS_ROTATING_FAULT_BLOCK_MAX_TXS: u64 = 512;
const REALISTIC_30TPS_ROTATING_FAULT_SNAPSHOT_MODE: &str = "read_write";
const REALISTIC_30TPS_ROTATING_FAULT_SNAPSHOT_CREATE_EVERY_MS: u64 = 30_000;
const REALISTIC_30TPS_SNAPSHOT_DATA_FILE: &str = "snapshot.data";
const REALISTIC_30TPS_SNAPSHOT_DIGEST_FILE: &str = "snapshot.sha256";
const REALISTIC_30TPS_SNAPSHOT_SIGNATURE_FILE: &str = "snapshot.sig";
const REALISTIC_30TPS_SNAPSHOT_MERKLE_FILE: &str = "snapshot.merkle.json";
const REALISTIC_30TPS_ROTATING_FAULT_MAX_HEALTHY_BLOCK_LAG: u64 = 1;
const REALISTIC_30TPS_ROTATING_FAULT_MAX_HEALTHY_APPROVED_LAG: u64 =
    REALISTIC_30TPS_ROTATING_FAULT_BLOCK_MAX_TXS;
const REALISTIC_30TPS_MAX_AVG_SECS_PER_BLOCK_ENV: &str =
    "IROHA_REALISTIC_30TPS_MAX_AVG_SECS_PER_BLOCK";
const REALISTIC_30TPS_MAX_AVG_SECS_PER_BLOCK: f64 = 3.0;
const REALISTIC_30TPS_ROTATING_FAULT_MAX_AVG_SECS_PER_BLOCK: f64 = 18.0;
const REALISTIC_30TPS_RESTART_GRACE: Duration = Duration::from_secs(2);
const REALISTIC_30TPS_TRANSFER_ACCOUNTS: usize = 640;
const REALISTIC_30TPS_TRANSFER_MAX_AMOUNT: u64 = 5;
const REALISTIC_30TPS_NPOS_FEE_FUNDING_CHUNK: usize = 128;
const REALISTIC_30TPS_RAM_LFE_EMAIL_POLICY_ID: &str = "email#realistic";
const REALISTIC_30TPS_RAM_LFE_EMAIL_PROGRAM_ID: &str = "email_realistic";
const FAIL_ON_SANDBOX_SKIP_ENV: &str = "IROHA_FAIL_ON_SANDBOX_SKIP";
// Grouped localnet runs can take longer to publish authoritative Nexus bindings
// than the earlier exact-test-only timeout budget.
const ROUTE_BINDING_TIMEOUT: Duration = Duration::from_secs(120);
const ROUTE_BINDING_POLL: Duration = Duration::from_millis(200);
#[allow(unsafe_code)]
fn set_env_var(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    // Safety: tests serialize env mutation with LOCALNET_SMOKE_GUARD.
    unsafe {
        std::env::set_var(key, value);
    }
}
#[allow(unsafe_code)]
fn remove_env_var(key: &str) {
    // Safety: tests serialize env mutation with LOCALNET_SMOKE_GUARD.
    unsafe {
        std::env::remove_var(key);
    }
}
fn env_or_default(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
fn env_or_default_usize(key: &str, default: usize) -> usize {
    let default_u64 = u64::try_from(default).unwrap_or(u64::MAX);
    let value = env_or_default(key, default_u64);
    usize::try_from(value).unwrap_or(usize::MAX)
}
fn env_or_default_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .unwrap_or(default)
}
fn realistic_max_avg_secs_per_block(rotating_fault: bool) -> f64 {
    let default = if rotating_fault {
        REALISTIC_30TPS_ROTATING_FAULT_MAX_AVG_SECS_PER_BLOCK
    } else {
        REALISTIC_30TPS_MAX_AVG_SECS_PER_BLOCK
    };
    env_or_default_f64(REALISTIC_30TPS_MAX_AVG_SECS_PER_BLOCK_ENV, default)
}
fn realistic_default_block_max_txs(rotating_fault: bool) -> u64 {
    if rotating_fault {
        REALISTIC_30TPS_ROTATING_FAULT_BLOCK_MAX_TXS
    } else {
        REALISTIC_30TPS_BLOCK_MAX_TXS
    }
}
fn realistic_default_queue_soft_limit(rotating_fault: bool) -> u64 {
    if rotating_fault {
        REALISTIC_30TPS_ROTATING_FAULT_QUEUE_SOFT_LIMIT
    } else {
        REALISTIC_30TPS_QUEUE_SOFT_LIMIT
    }
}
fn realistic_30tps_snapshot_settings(rotating_fault: bool) -> (&'static str, u64) {
    if rotating_fault {
        (
            REALISTIC_30TPS_ROTATING_FAULT_SNAPSHOT_MODE,
            REALISTIC_30TPS_ROTATING_FAULT_SNAPSHOT_CREATE_EVERY_MS,
        )
    } else {
        ("disabled", 0)
    }
}
async fn submit_route_probe_with_retry(
    client: &iroha::blocking::Client,
    message: &str,
    timeout: Duration,
    context: &str,
) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        let client = client.clone();
        let message = message.to_owned();
        match read_on_dedicated_thread(move || {
            client
                .submit::<InstructionBox>(Log::new(Level::INFO, message).into(), route_probe_fee())
        })
        .await
        {
            Ok(_) => return Ok(true),
            Err(err)
                if Instant::now() < deadline && err.to_string().contains("route_unavailable") =>
            {
                sleep(ROUTE_BINDING_POLL).await;
            }
            Err(err) if err.to_string().contains("route_unavailable") => return Ok(false),
            Err(err) => return Err(err).wrap_err(context.to_owned()),
        }
    }
}
fn route_probe_fee() -> iroha_data_model::transaction::FeePaymentIntent {
    use iroha_data_model::transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent};
    FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            route_fee_asset_definition_id(),
            Quantity::from(10_000_u32),
        )],
        None,
    )
}
#[test]
fn route_probe_fee_is_bounded_by_the_funded_canonical_asset() {
    let intent = route_probe_fee();
    intent.validate().unwrap();
    let [limit] = intent.charge_limits() else {
        panic!("one Nexus fee limit");
    };
    assert_eq!(
        limit.kind(),
        iroha_data_model::transaction::FeeChargeKind::Nexus
    );
    assert_eq!(
        limit.asset_definition_id(),
        &route_fee_asset_definition_id()
    );
    assert_eq!(limit.max_amount(), &Quantity::from(10_000_u32));
    assert!(10_000 < ROUTE_VALIDATOR_FEE_SEED_AMOUNT);
}
fn checked_localnet_smoke_keypair(seed: Vec<u8>, algorithm: Algorithm) -> KeyPair {
    KeyPair::try_from_seed(seed, algorithm).expect("derive localnet smoke fixture key")
}
fn queue_progress_timeout() -> Duration {
    let default_secs = SOAK_QUEUE_PROGRESS_TIMEOUT.as_secs();
    let secs = env_or_default(THROUGHPUT_QUEUE_PROGRESS_TIMEOUT_ENV, default_secs);
    Duration::from_secs(secs)
}
fn fail_on_sandbox_skip() -> bool {
    let Ok(raw) = std::env::var(FAIL_ON_SANDBOX_SKIP_ENV) else {
        return false;
    };
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
#[allow(clippy::too_many_arguments)]
async fn submit_logs(
    start_idx: u64,
    tx_count: u64,
    network: &Network,
    submit_clients: &[iroha::blocking::Client],
    submit_batch: u64,
    submit_parallelism: usize,
    queue_soft_limit: u64,
    payload_bytes: usize,
    rng_seed: u64,
) -> Result<Duration> {
    let submit_clients = std::sync::Arc::new(submit_clients.to_vec());
    ensure!(
        !submit_clients.is_empty(),
        "submit_logs requires at least one client"
    );
    let client_count = u64::try_from(submit_clients.len()).unwrap_or(1);
    let submit_start = Instant::now();
    let mut submitted = 0_u64;
    while submitted < tx_count {
        let remaining = tx_count.saturating_sub(submitted);
        let batch_count = remaining.min(submit_batch);
        let batch_start = start_idx.saturating_add(submitted);
        stream::iter(batch_start..batch_start.saturating_add(batch_count))
            .map(|idx| {
                let submit_clients = std::sync::Arc::clone(&submit_clients);
                async move {
                    if let Ok(delay) = std::env::var("IROHA_THROUGHPUT_DELAY_MS") {
                        if let Ok(ms) = delay.parse::<u64>() {
                            tokio::time::sleep(Duration::from_millis(ms)).await;
                        }
                    }
                    let payload = throughput_payload(idx, payload_bytes, rng_seed);
                    let client_idx = usize::try_from(idx % client_count).unwrap_or_default();
                    let client = submit_clients[client_idx].clone();
                    let handle = read_on_dedicated_thread(move || {
                        client
                            .submit::<InstructionBox>(
                                Log::new(Level::INFO, payload).into(),
                                iroha::data_model::transaction::FeePaymentIntent::authority(
                                    Vec::new(),
                                    None,
                                ),
                            )
                            .wrap_err_with(|| format!("failed to submit log instruction {idx}"))
                    });
                    handle.await.wrap_err("submit worker failed")
                }
            })
            .buffer_unordered(submit_parallelism)
            .try_for_each(|_| async { Ok(()) })
            .await?;
        submitted = submitted.saturating_add(batch_count);
        wait_for_queue_depth(network, queue_soft_limit, SOAK_STATUS_POLL_TIMEOUT).await?;
    }
    Ok(submit_start.elapsed())
}
#[derive(Clone)]
struct TransferLoadAccount {
    id: AccountId,
    key_pair: KeyPair,
}
#[derive(Clone)]
struct TransferSubmitAccount {
    id: AccountId,
    clients: Vec<iroha::blocking::Client>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Realistic30TpsLoadKind {
    Transfer,
}
impl Realistic30TpsLoadKind {
    fn from_env() -> Result<Self> {
        let Some(raw) = std::env::var("IROHA_REALISTIC_30TPS_LOAD_KIND")
            .ok()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
        else {
            return Ok(Self::Transfer);
        };
        match raw.as_str() {
            "transfer" | "transfers" => Ok(Self::Transfer),
            "ram-lfe-email" | "ram_lfe_email" | "ram-lfe-emails" | "ram_lfe_emails" | "email"
            | "emails" => bail!(
                "ram_lfe_encryption_unavailable: encrypted RAM-LFE loads require a secure replacement profile"
            ),
            _ => bail!("unsupported IROHA_REALISTIC_30TPS_LOAD_KIND={raw}; expected transfer"),
        }
    }
    const fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
        }
    }
}
#[derive(Clone)]
struct DiagnosticIdentifierAccount {
    id: AccountId,
    uaid: UniversalAccountId,
}
#[derive(Clone)]
struct DiagnosticIdentifierContext {
    policy_id: IdentifierPolicyId,
    program_id: RamLfeProgramId,
    program_id_bytes: Vec<u8>,
    program_digest: Hash,
    parameter_digest: Hash,
    evaluation_key_digest: Hash,
    backend: RamLfeBackend,
    verification_mode: RamLfeVerificationMode,
}
fn realistic_transfer_domain_id() -> DomainId {
    DomainId::try_new("realistic", "universal").expect("realistic transfer domain")
}
fn realistic_transfer_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        realistic_transfer_domain_id(),
        "transfer_coin".parse().expect("transfer asset name"),
    )
}
fn realistic_transfer_accounts(account_count: usize, rng_seed: u64) -> Vec<TransferLoadAccount> {
    (0..account_count)
        .map(|index| {
            let key_pair = checked_localnet_smoke_keypair(
                format!("integration_tests::realistic-transfer::{rng_seed}::{index}").into_bytes(),
                Algorithm::Ed25519,
            );
            let id = AccountId::new(key_pair.public_key().clone());
            TransferLoadAccount { id, key_pair }
        })
        .collect()
}
fn realistic_npos_fee_funding_instruction_chunks(
    accounts: &[TransferLoadAccount],
) -> Vec<Vec<InstructionBox>> {
    let fee_asset_definition_id = route_fee_asset_definition_id();
    accounts
        .chunks(REALISTIC_30TPS_NPOS_FEE_FUNDING_CHUNK)
        .map(|chunk| {
            chunk
                .iter()
                .map(|account| {
                    Mint::asset_quantity(
                        ROUTE_VALIDATOR_FEE_SEED_AMOUNT,
                        AssetId::new(fee_asset_definition_id.clone(), account.id.clone()),
                    )
                    .into()
                })
                .collect()
        })
        .collect()
}
async fn fund_realistic_npos_transfer_fee_accounts(
    network: &Network,
    accounts: &[TransferLoadAccount],
) -> Result<()> {
    if accounts.is_empty() {
        return Ok(());
    }
    let before_statuses = collect_statuses(network, STATUS_POLL_TIMEOUT)
        .await
        .wrap_err("failed to collect baseline status before NPoS fee funding")?;
    let baseline_approved = before_statuses
        .iter()
        .map(|status| status.txs_approved)
        .min()
        .unwrap_or_default();
    let instruction_chunks = realistic_npos_fee_funding_instruction_chunks(accounts);
    let target_approved = baseline_approved.saturating_add(
        u64::try_from(instruction_chunks.len()).expect("funding chunk count fits u64"),
    );
    let client = network.client();
    read_on_dedicated_thread(move || -> Result<()> {
        for (chunk_index, instructions) in instruction_chunks.into_iter().enumerate() {
            client
                .submit_all(
                    instructions,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .wrap_err_with(|| {
                    format!(
                        "failed to fund NPoS fee assets for transfer account chunk {chunk_index}"
                    )
                })?;
        }
        Ok(())
    })
    .await
    .wrap_err("NPoS fee funding worker failed")?;
    wait_for_min_txs_approved(network, target_approved, Duration::from_secs(60)).await?;
    Ok(())
}
fn realistic_ram_lfe_email_policy_id() -> IdentifierPolicyId {
    REALISTIC_30TPS_RAM_LFE_EMAIL_POLICY_ID
        .parse()
        .expect("realistic RAM-LFE email policy id")
}
fn realistic_ram_lfe_email_program_id() -> RamLfeProgramId {
    REALISTIC_30TPS_RAM_LFE_EMAIL_PROGRAM_ID
        .parse()
        .expect("realistic RAM-LFE email program id")
}

fn diagnostic_identifier_accounts(
    account_count: usize,
    rng_seed: u64,
) -> Vec<DiagnosticIdentifierAccount> {
    (0..account_count)
        .map(|index| {
            let key_pair = checked_localnet_smoke_keypair(
                format!("integration_tests::realistic-ram-lfe-email::{rng_seed}::{index}")
                    .into_bytes(),
                Algorithm::Ed25519,
            );
            let id = AccountId::new(key_pair.public_key().clone());
            let uaid = UniversalAccountId::from_hash(Hash::new(
                format!("integration_tests::realistic-ram-lfe-email-uaid::{rng_seed}::{index}")
                    .as_bytes(),
            ));
            DiagnosticIdentifierAccount { id, uaid }
        })
        .collect()
}
fn realistic_transfer_route(
    index: u64,
    account_count: usize,
    max_amount: u64,
    rng_seed: u64,
) -> (usize, usize, u64) {
    debug_assert!(account_count >= 2);
    let mut rng = ChaCha8Rng::seed_from_u64(
        rng_seed ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5452_414e_5346_4552,
    );
    let source = usize::try_from(rng.next_u64() % account_count as u64).unwrap_or_default();
    let mut destination = usize::try_from(rng.next_u64() % account_count.saturating_sub(1) as u64)
        .unwrap_or_default();
    if destination >= source {
        destination = destination.saturating_add(1);
    }
    let amount = 1 + rng.next_u64() % max_amount.max(1);
    (source, destination, amount)
}
fn expected_realistic_transfer_balances(
    account_count: usize,
    tx_count: u64,
    initial_balance: u64,
    max_amount: u64,
    rng_seed: u64,
) -> Vec<u64> {
    let mut balances = vec![i128::from(initial_balance); account_count];
    for index in 0..tx_count {
        let (source, destination, amount) =
            realistic_transfer_route(index, account_count, max_amount, rng_seed);
        let amount = i128::from(amount);
        balances[source] -= amount;
        balances[destination] += amount;
    }
    balances
        .into_iter()
        .map(|balance| u64::try_from(balance).expect("transfer load balance should stay positive"))
        .collect()
}
fn realistic_ram_lfe_email_account_index(index: u64, account_count: usize, rng_seed: u64) -> usize {
    debug_assert!(account_count > 0);
    let mut rng = ChaCha8Rng::seed_from_u64(
        rng_seed ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x454d_4149_4c5f_4c46,
    );
    usize::try_from(rng.next_u64() % account_count as u64).unwrap_or_default()
}
fn realistic_ram_lfe_email_address(index: u64, rng_seed: u64) -> String {
    const DOMAINS: [&str; 8] = [
        "retail.example",
        "payments.example",
        "wallet.example",
        "merchant.example",
        "support.example",
        "identity.example",
        "ops.example",
        "settlement.example",
    ];
    let mut rng = ChaCha8Rng::seed_from_u64(
        rng_seed ^ index.wrapping_mul(0xA076_1D64_78BD_642F) ^ 0x454d_4149_4c5f_4944,
    );
    let domain =
        DOMAINS[usize::try_from(rng.next_u64() % DOMAINS.len() as u64).unwrap_or_default()];
    format!(
        "notice.{:08x}.{:08x}+{:08}@{domain}",
        (index >> 32) as u32,
        index as u32,
        rng.next_u64() as u32,
    )
}
fn diagnostic_identifier_receipt(
    context: &DiagnosticIdentifierContext,
    resolver: &KeyPair,
    account_id: &AccountId,
    uaid: UniversalAccountId,
    index: u64,
    rng_seed: u64,
) -> IdentifierResolutionReceipt {
    let normalized_email = IdentifierNormalization::EmailAddress
        .normalize(&realistic_ram_lfe_email_address(index, rng_seed))
        .expect("generated email address should normalize");
    let opened_output_hash = ram_lfe_output_hash(normalized_email.as_bytes());
    let (opaque_id, receipt_hash) =
        identifier_hashes_from_output_hash(&context.program_id_bytes, &opened_output_hash);
    let input_ciphertext_hash =
        Hash::new(format!("{normalized_email}:encrypted-input:{index}").as_bytes());
    let output_ciphertext_hash =
        Hash::new(format!("{normalized_email}:encrypted-output:{index}").as_bytes());
    let execution = RamLfeExecutionReceiptPayload {
        program_id: context.program_id.clone(),
        program_digest: context.program_digest,
        backend: context.backend,
        verification_mode: context.verification_mode,
        input_ciphertext_hash,
        output_ciphertext_hash,
        parameter_digest: context.parameter_digest,
        evaluation_key_digest: context.evaluation_key_digest,
        output_hash: output_ciphertext_hash,
        associated_data_hash: Hash::new(&context.program_id_bytes),
        executed_at_ms: 0,
        expires_at_ms: None,
    };
    let opening_payload = RamLfeOutputOpeningPayload {
        program_id: context.program_id.clone(),
        input_ciphertext_hash,
        output_ciphertext_hash,
        parameter_digest: context.parameter_digest,
        evaluation_key_digest: context.evaluation_key_digest,
        opened_output_hash,
        opened_at_ms: 0,
        expires_at_ms: None,
    };
    let opening = RamLfeOutputOpening {
        signature: SignatureOf::try_new(resolver.private_key(), &opening_payload)
            .expect("sign RAM-LFE output opening fixture")
            .into(),
        payload: opening_payload,
    };
    let payload = IdentifierResolutionReceiptPayload {
        // Explicit DATA identity: this diagnostic fixture is never submitted.
        network_id: iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                b"localnet-identifier-diagnostic-network",
            )),
        ),
        policy_id: context.policy_id.clone(),
        execution,
        opening,
        opaque_id: OpaqueAccountId::from(opaque_id),
        receipt_hash,
        uaid,
        account_id: account_id.clone(),
    };
    let signature: Signature = SignatureOf::try_new(resolver.private_key(), &payload)
        .expect("sign RAM-LFE identifier receipt fixture")
        .into();
    IdentifierResolutionReceipt {
        payload,
        attestation: RamLfeReceiptAttestation::Signed(signature),
        phone_retail_canonicality: None,
    }
}
fn diagnostic_identifier_route_counts(
    account_count: usize,
    tx_count: u64,
    rng_seed: u64,
) -> Vec<usize> {
    let mut counts = vec![0_usize; account_count];
    for index in 0..tx_count {
        let account_index = realistic_ram_lfe_email_account_index(index, account_count, rng_seed);
        counts[account_index] = counts[account_index].saturating_add(1);
    }
    counts
}
fn realistic_load_metadata(index: u64) -> Metadata {
    let mut metadata = Metadata::default();
    metadata.insert(
        Name::from_str("tx_sequence").expect("tx_sequence metadata key"),
        index,
    );
    metadata
}
fn realistic_submit_error_is_retryable_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("connection refused")
        || message.contains("connection reset")
        || message.contains("connection closed")
        || message.contains("tcp connect")
}
fn realistic_submit_error_is_already_known_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("already_enqueued")
        || message.contains("already enqueued")
        || message.contains("already present in the queue")
        || message.contains("already_committed")
        || message.contains("already committed")
        || message.contains("already in blockchain")
        || message.contains("already in the blockchain")
}
fn realistic_submit_accept_quorum(client_count: usize, tolerated_faults: usize) -> usize {
    tolerated_faults.saturating_add(1).min(client_count).max(1)
}
fn submit_prepared_to_accept_quorum(
    clients: &[iroha::blocking::Client],
    payload: &iroha::client::PreparedTransactionPayload,
    required_accepts: usize,
) -> Result<()> {
    ensure!(
        !clients.is_empty(),
        "prepared transaction broadcast requires at least one client"
    );
    let required_accepts = required_accepts.clamp(1, clients.len());
    let mut accepts = 0_usize;
    let mut errors = Vec::new();
    for client in clients {
        match client.submit_prepared_transaction_payload(payload) {
            Ok(_) => accepts = accepts.saturating_add(1),
            Err(err) => {
                let error_message = format!("{err:?}");
                if realistic_submit_error_is_already_known_message(&error_message) {
                    accepts = accepts.saturating_add(1);
                } else {
                    errors.push(error_message);
                }
            }
        }
        if accepts >= required_accepts {
            return Ok(());
        }
    }
    bail!(
        "prepared transaction {:?} accepted by {accepts}/{required_accepts} required Torii endpoints; errors={errors:?}",
        payload.hash()
    )
}
#[allow(clippy::too_many_arguments)]
async fn submit_transfers_paced(
    tx_count: u64,
    target_tps: u64,
    submit_accounts: Vec<TransferSubmitAccount>,
    asset_definition_id: AssetDefinitionId,
    transfer_max_amount: u64,
    rng_seed: u64,
    submit_parallelism: usize,
    submit_accept_quorum: usize,
    submitted_counter: Arc<AtomicU64>,
) -> Result<Duration> {
    ensure!(
        submit_accounts.len() >= 2,
        "submit_transfers_paced requires at least two funded accounts"
    );
    let submit_accounts = Arc::new(submit_accounts);
    let account_count = submit_accounts.len();
    let submit_parallelism = submit_parallelism.max(1);
    let nanos_per_tx = 1_000_000_000_u64 / target_tps.max(1);
    let submit_start = Instant::now();
    let mut pending: FuturesUnordered<task::JoinHandle<Result<()>>> = FuturesUnordered::new();
    for index in 0..tx_count {
        let target_elapsed = Duration::from_nanos(nanos_per_tx.saturating_mul(index));
        if let Some(target_instant) = submit_start.checked_add(target_elapsed) {
            let now = Instant::now();
            if target_instant > now {
                sleep(target_instant.duration_since(now)).await;
            }
        }
        let (source, destination, amount) =
            realistic_transfer_route(index, account_count, transfer_max_amount, rng_seed);
        let source_account = submit_accounts[source].clone();
        let destination_id = submit_accounts[destination].id.clone();
        let asset_definition_id = asset_definition_id.clone();
        let submitted_counter = Arc::clone(&submitted_counter);
        pending.push(task::spawn(async move {
            read_on_dedicated_thread(move || {
            ensure!(
                !source_account.clients.is_empty(),
                "transfer submit account has no clients"
            );
            let source_asset_id =
                AssetId::new(asset_definition_id.clone(), source_account.id.clone());
            let instruction: InstructionBox = Transfer::asset_quantity(
                source_asset_id,
                amount,
                destination_id.clone(),
            )
            .into();
            let transaction ={
    let account = source_account.clients[0]
                .account_client();
    account
        .prepare_transaction(iroha::client::AccountTransactionDraft::new([instruction], iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None), realistic_load_metadata(index)))
        .and_then(|payload| account.sign_transaction(payload))
}.expect("build integration-test transaction");
            let payload =
                iroha::client::PreparedTransactionPayload::from_transaction(&transaction);
            submit_prepared_to_accept_quorum(
                &source_account.clients,
                &payload,
                submit_accept_quorum,
            )
            .wrap_err_with(|| {
                format!(
                    "failed to submit paced transfer instruction {index} from account index {source} to {destination}"
                )
            })?;
            submitted_counter.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(())
            }).await
        }));
        if pending.len() >= submit_parallelism {
            let result = pending
                .next()
                .await
                .ok_or_else(|| eyre!("paced transfer worker set unexpectedly empty"))?;
            result.wrap_err("paced transfer task join failed")??;
        }
    }
    while let Some(result) = pending.next().await {
        result.wrap_err("paced transfer task join failed")??;
    }
    Ok(submit_start.elapsed())
}
fn verify_realistic_transfer_balances(
    client: &iroha::blocking::Client,
    asset_definition_id: &AssetDefinitionId,
    accounts: &[TransferLoadAccount],
    tx_count: u64,
    initial_balance: u64,
    max_amount: u64,
    rng_seed: u64,
) -> Result<()> {
    let expected = expected_realistic_transfer_balances(
        accounts.len(),
        tx_count,
        initial_balance,
        max_amount,
        rng_seed,
    );
    for (account, expected_balance) in accounts.iter().zip(expected) {
        let asset = client
            .client()
            .query_single(FindAssetById::new(AssetId::new(
                asset_definition_id.clone(),
                account.id.clone(),
            )))?;
        ensure!(
            *asset.value() == Quantity::from(expected_balance),
            "unexpected final transfer balance for {}: expected {}, got {:?}",
            account.id,
            expected_balance,
            asset.value()
        );
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running 4-peer localnet regression (30 TPS for 2 hours)"]
#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
async fn permissioned_localnet_realistic_30tps_2h() -> Result<()> {
    run_realistic_30tps_localnet(
        Realistic30TpsConsensusMode::Permissioned,
        stringify!(permissioned_localnet_realistic_30tps_2h),
        None,
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running 4-peer localnet regression (30 TPS for 2 hours, NPoS)"]
#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
async fn npos_localnet_realistic_30tps_2h() -> Result<()> {
    run_realistic_30tps_localnet(
        Realistic30TpsConsensusMode::Npos,
        stringify!(npos_localnet_realistic_30tps_2h),
        None,
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running 4-peer NPoS localnet regression (30 TPS for 2 hours, rotating validator outage)"]
#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
async fn npos_localnet_realistic_30tps_2h_rotating_validator_outage() -> Result<()> {
    run_realistic_30tps_localnet(
        Realistic30TpsConsensusMode::Npos,
        stringify!(npos_localnet_realistic_30tps_2h_rotating_validator_outage),
        Some(Realistic30TpsRotatingFaultConfig::from_env()?),
    )
    .await
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Realistic30TpsConsensusMode {
    Permissioned,
    Npos,
}
impl Realistic30TpsConsensusMode {
    fn select_in_genesis(self, builder: NetworkBuilder) -> NetworkBuilder {
        match self {
            Self::Permissioned => builder.with_permissioned_consensus(),
            Self::Npos => builder.with_npos_consensus(),
        }
    }
    fn is_npos(self) -> bool {
        matches!(self, Self::Npos)
    }
}
#[derive(Clone, Debug)]
struct ConfigLayer(Table);
impl AsRef<Table> for ConfigLayer {
    fn as_ref(&self) -> &Table {
        &self.0
    }
}
fn realistic_30tps_peer_index_at(peer_count: usize, window_index: usize) -> Option<usize> {
    (peer_count > 0).then_some(window_index % peer_count)
}
fn realistic_30tps_recovery_bound_from_env() -> Result<Option<Duration>> {
    match std::env::var(REALISTIC_30TPS_RECOVERY_BOUND_SECS_ENV) {
        Ok(raw) => {
            let seconds = raw.trim().parse::<u64>().map_err(|err| {
                eyre!("failed to parse {REALISTIC_30TPS_RECOVERY_BOUND_SECS_ENV}={raw:?}: {err}")
            })?;
            ensure!(
                seconds > 0,
                "{REALISTIC_30TPS_RECOVERY_BOUND_SECS_ENV} must be positive when set"
            );
            Ok(Some(Duration::from_secs(seconds)))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(eyre!(
            "failed to read {REALISTIC_30TPS_RECOVERY_BOUND_SECS_ENV}: {err}"
        )),
    }
}
fn env_bool(key: &str) -> Result<bool> {
    match std::env::var(key) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(eyre!(
                "{key} must be one of 1/0, true/false, yes/no, or on/off when set"
            )),
        },
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(err) => Err(eyre!("failed to read {key}: {err}")),
    }
}
fn realistic_30tps_convergence_total_bound_from_env(
    recovery_bound: Option<Duration>,
) -> Result<Option<Duration>> {
    match std::env::var(REALISTIC_30TPS_CONVERGENCE_BOUND_SECS_ENV) {
        Ok(raw) => {
            let seconds = raw.trim().parse::<u64>().map_err(|err| {
                eyre!("failed to parse {REALISTIC_30TPS_CONVERGENCE_BOUND_SECS_ENV}={raw:?}: {err}")
            })?;
            ensure!(
                seconds > 0,
                "{REALISTIC_30TPS_CONVERGENCE_BOUND_SECS_ENV} must be positive when set"
            );
            Ok(Some(Duration::from_secs(seconds)))
        }
        Err(std::env::VarError::NotPresent) => Ok(recovery_bound),
        Err(err) => Err(eyre!(
            "failed to read {REALISTIC_30TPS_CONVERGENCE_BOUND_SECS_ENV}: {err}"
        )),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Realistic30TpsRotatingFaultConfig {
    rotate_interval: Duration,
    recovery_timeout: Duration,
    recovery_bound: Option<Duration>,
    strict_rotation_convergence: bool,
    convergence_total_bound: Option<Duration>,
}
impl Realistic30TpsRotatingFaultConfig {
    fn from_env() -> Result<Self> {
        let recovery_bound = realistic_30tps_recovery_bound_from_env()?;
        let strict_rotation_convergence =
            env_bool(REALISTIC_30TPS_STRICT_ROTATION_CONVERGENCE_ENV)?;
        Ok(Self {
            rotate_interval: Duration::from_secs(
                env_or_default(
                    REALISTIC_30TPS_OUTAGE_ROTATE_SECS_ENV,
                    REALISTIC_30TPS_OUTAGE_ROTATE_SECS,
                )
                .max(1),
            ),
            recovery_timeout: Duration::from_secs(
                env_or_default(
                    REALISTIC_30TPS_OUTAGE_RECOVERY_SECS_ENV,
                    REALISTIC_30TPS_OUTAGE_RECOVERY_SECS,
                )
                .max(1),
            ),
            recovery_bound,
            strict_rotation_convergence,
            convergence_total_bound: realistic_30tps_convergence_total_bound_from_env(
                recovery_bound,
            )?,
        })
    }
    fn recovery_wait_timeout(&self) -> Duration {
        self.recovery_bound.unwrap_or(self.recovery_timeout)
    }
    fn requires_bounded_convergence(&self) -> bool {
        self.strict_rotation_convergence
    }
    fn convergence_progress_timeout(&self) -> Duration {
        Duration::from_secs(REALISTIC_30TPS_CONVERGENCE_BOUND_SECS)
    }
    fn convergence_total_bound(&self) -> Option<Duration> {
        self.convergence_total_bound
    }
}
fn realistic_30tps_stall_threshold(
    rotating_fault: Option<&Realistic30TpsRotatingFaultConfig>,
) -> Duration {
    if let Ok(raw) = std::env::var(REALISTIC_30TPS_STALL_SECS_ENV)
        && let Ok(secs) = raw.parse::<u64>()
        && secs > 0
    {
        return Duration::from_secs(secs);
    }
    if let Some(config) = rotating_fault {
        return REALISTIC_30TPS_STALL_THRESHOLD.max(config.rotate_interval.saturating_mul(2));
    }
    REALISTIC_30TPS_STALL_THRESHOLD
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Realistic30TpsFaultWindow {
    peer_index: usize,
    mnemonic: String,
    fault: &'static str,
    started_ms: u64,
    ended_ms: Option<u64>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Realistic30TpsSnapshotObservation {
    store_dir: String,
    data_bytes: Option<u64>,
    digest_bytes: Option<u64>,
    signature_bytes: Option<u64>,
    merkle_bytes: Option<u64>,
    data_modified_ms: Option<u64>,
    errors: Vec<String>,
}
impl Realistic30TpsSnapshotObservation {
    fn data_present(&self) -> bool {
        self.data_bytes.is_some()
    }
    fn bundle_complete(&self) -> bool {
        self.data_bytes.is_some()
            && self.digest_bytes.is_some()
            && self.signature_bytes.is_some()
            && self.merkle_bytes.is_some()
    }
}
#[derive(Clone, Debug)]
struct Realistic30TpsStatusRecoverySample {
    peer_index: usize,
    mnemonic: String,
    context: String,
    restart_started_ms: u64,
    status_wait_started_ms: u64,
    ended_ms: u64,
    bound_ms: u64,
    recovered: bool,
    poll_attempts: u64,
    last_error: Option<String>,
    snapshot_before_shutdown: Realistic30TpsSnapshotObservation,
    snapshot_after_shutdown: Realistic30TpsSnapshotObservation,
    snapshot_after_status: Realistic30TpsSnapshotObservation,
}
impl Realistic30TpsStatusRecoverySample {
    fn total_duration_ms(&self) -> u64 {
        self.ended_ms.saturating_sub(self.restart_started_ms)
    }
    fn status_wait_ms(&self) -> u64 {
        self.ended_ms.saturating_sub(self.status_wait_started_ms)
    }
    fn recovered_within_bound(&self) -> bool {
        self.recovered && self.status_wait_ms() <= self.bound_ms
    }
}
fn realistic_30tps_peer_snapshot_observation(
    peer: &iroha_test_network::NetworkPeer,
) -> Realistic30TpsSnapshotObservation {
    let store_dir = peer.kura_store_dir().join("snapshot");
    let (data_bytes, data_modified_ms, mut errors) =
        realistic_30tps_snapshot_file_metadata(&store_dir.join(REALISTIC_30TPS_SNAPSHOT_DATA_FILE));
    let (digest_bytes, _, digest_errors) = realistic_30tps_snapshot_file_metadata(
        &store_dir.join(REALISTIC_30TPS_SNAPSHOT_DIGEST_FILE),
    );
    let (signature_bytes, _, signature_errors) = realistic_30tps_snapshot_file_metadata(
        &store_dir.join(REALISTIC_30TPS_SNAPSHOT_SIGNATURE_FILE),
    );
    let (merkle_bytes, _, merkle_errors) = realistic_30tps_snapshot_file_metadata(
        &store_dir.join(REALISTIC_30TPS_SNAPSHOT_MERKLE_FILE),
    );
    errors.extend(digest_errors);
    errors.extend(signature_errors);
    errors.extend(merkle_errors);
    Realistic30TpsSnapshotObservation {
        store_dir: store_dir.to_string_lossy().to_string(),
        data_bytes,
        digest_bytes,
        signature_bytes,
        merkle_bytes,
        data_modified_ms,
        errors,
    }
}
fn realistic_30tps_snapshot_file_metadata(path: &Path) -> (Option<u64>, Option<u64>, Vec<String>) {
    match fs::metadata(path) {
        Ok(metadata) => {
            let modified_ms = metadata.modified().ok().and_then(system_time_ms);
            (Some(metadata.len()), modified_ms, Vec::new())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (None, None, Vec::new()),
        Err(err) => (
            None,
            None,
            vec![format!("{}: {err}", path.to_string_lossy())],
        ),
    }
}
fn system_time_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Realistic30TpsCatchUpTarget {
    blocks_non_empty: u64,
    txs_approved: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Realistic30TpsConvergenceSpan {
    min_blocks_non_empty: u64,
    max_blocks_non_empty: u64,
    min_txs_approved: u64,
    max_txs_approved: u64,
}
impl Realistic30TpsConvergenceSpan {
    fn block_gap(self) -> u64 {
        self.max_blocks_non_empty
            .saturating_sub(self.min_blocks_non_empty)
    }
    fn approved_gap(self) -> u64 {
        self.max_txs_approved.saturating_sub(self.min_txs_approved)
    }
}
#[derive(Clone, Debug)]
struct Realistic30TpsCatchUpSample {
    timestamp_ms: u64,
    recovering_peer_index: usize,
    target: Realistic30TpsCatchUpTarget,
    recovering_status: Option<StatusSnapshot>,
    healthy_statuses: Vec<StatusSnapshot>,
    healthy_status_error: Option<String>,
    recovering_no_progress_ms: u64,
}
#[derive(Clone, Debug)]
struct Realistic30TpsConvergenceWindow {
    healed_peer_index: usize,
    healed_fault: &'static str,
    started_ms: u64,
    ended_ms: u64,
    start_span: Option<Realistic30TpsConvergenceSpan>,
    end_span: Realistic30TpsConvergenceSpan,
}
#[derive(Debug)]
struct Realistic30TpsRotatingFaultController {
    config: Realistic30TpsRotatingFaultConfig,
    base_layers: Vec<ConfigLayer>,
    final_target_approved: u64,
    current_peer: Option<usize>,
    next_peer: usize,
    next_rotation_at: Option<Instant>,
    fault_windows: Vec<Realistic30TpsFaultWindow>,
    status_recovery_samples: Vec<Realistic30TpsStatusRecoverySample>,
    catch_up_samples: Vec<Realistic30TpsCatchUpSample>,
    convergence_windows: Vec<Realistic30TpsConvergenceWindow>,
}
impl Realistic30TpsRotatingFaultController {
    fn new(
        network: &Network,
        config: Realistic30TpsRotatingFaultConfig,
        final_target_approved: u64,
    ) -> Self {
        Self {
            config,
            base_layers: network
                .config_layers()
                .map(|layer| ConfigLayer(layer.into_owned()))
                .collect(),
            final_target_approved,
            current_peer: None,
            next_peer: 0,
            next_rotation_at: None,
            fault_windows: Vec::new(),
            status_recovery_samples: Vec::new(),
            catch_up_samples: Vec::new(),
            convergence_windows: Vec::new(),
        }
    }
    async fn start(&mut self, network: &Network) -> Result<()> {
        ensure!(
            network.peers().len() >= REALISTIC_30TPS_PEERS,
            "rotating validator-outage 30 TPS soak requires at least {REALISTIC_30TPS_PEERS} peers"
        );
        self.take_peer_offline(network, 0, "initial rotating validator outage")
            .await?;
        self.next_peer = 1 % network.peers().len();
        self.next_rotation_at = Instant::now().checked_add(self.config.rotate_interval);
        Ok(())
    }
    async fn rotate_if_due(&mut self, network: &Network) -> Result<bool> {
        let Some(next_rotation_at) = self.next_rotation_at else {
            return Ok(false);
        };
        if Instant::now() < next_rotation_at {
            return Ok(false);
        }
        self.rotate(network).await?;
        Ok(true)
    }
    async fn rotate(&mut self, network: &Network) -> Result<()> {
        if let Some(current_peer) = self.current_peer {
            self.heal_peer(
                network,
                current_peer,
                "heal rotating validator outage",
                true,
            )
            .await?;
        }
        let next_peer = self.next_peer % network.peers().len();
        self.take_peer_offline(network, next_peer, "rotate validator outage")
            .await?;
        self.next_peer = (next_peer + 1) % network.peers().len();
        self.next_rotation_at = Instant::now().checked_add(self.config.rotate_interval);
        Ok(())
    }
    async fn stop_and_heal(&mut self, network: &Network) -> Result<()> {
        self.next_rotation_at = None;
        if let Some(current_peer) = self.current_peer {
            let current_fault = self.current_fault_for_peer(current_peer);
            self.heal_peer(
                network,
                current_peer,
                "heal final rotating validator outage",
                false,
            )
            .await?;
            if self.config.requires_bounded_convergence() {
                let convergence_window = wait_for_realistic_all_peer_convergence(
                    network,
                    current_peer,
                    current_fault,
                    self.config.convergence_progress_timeout(),
                    self.config.convergence_total_bound(),
                )
                .await
                .wrap_err_with(|| {
                    format!("heal final rotating validator outage: peer {current_peer} bounded convergence")
                })?;
                self.convergence_windows.push(convergence_window);
            }
        }
        ensure!(
            realistic_fault_windows_have_no_overlap(&self.fault_windows),
            "rotating validator-outage windows overlapped: {:?}",
            self.fault_windows
        );
        if self.config.requires_bounded_convergence() {
            ensure!(
                realistic_strict_fault_windows_start_after_convergence(
                    &self.fault_windows,
                    &self.convergence_windows
                ),
                "strict rotating validator-outage windows started before healed peers converged: windows={:?}, convergence={:?}",
                self.fault_windows,
                self.convergence_windows
            );
        }
        Ok(())
    }
    fn fault_windows(&self) -> &[Realistic30TpsFaultWindow] {
        &self.fault_windows
    }
    fn drain_status_recovery_samples(&mut self) -> Vec<Realistic30TpsStatusRecoverySample> {
        self.status_recovery_samples.drain(..).collect()
    }
    fn drain_catch_up_samples(&mut self) -> Vec<Realistic30TpsCatchUpSample> {
        self.catch_up_samples.drain(..).collect()
    }
    fn convergence_windows(&self) -> &[Realistic30TpsConvergenceWindow] {
        &self.convergence_windows
    }
    fn current_fault_for_peer(&self, peer_index: usize) -> &'static str {
        self.fault_windows
            .iter()
            .rev()
            .find(|window| window.peer_index == peer_index && window.ended_ms.is_none())
            .map_or("unknown", |window| window.fault)
    }
    async fn take_peer_offline(
        &mut self,
        network: &Network,
        peer_index: usize,
        context: &str,
    ) -> Result<()> {
        let peer = network
            .peers()
            .get(peer_index)
            .ok_or_else(|| eyre!("validator index {peer_index} missing"))?;
        ensure!(
            peer.shutdown_if_started().await,
            "{context}: validator {peer_index} ({}) was not running",
            peer.mnemonic()
        );
        ensure!(
            !peer.is_running(),
            "{context}: validator {peer_index} ({}) remained running after shutdown",
            peer.mnemonic()
        );
        self.fault_windows.push(Realistic30TpsFaultWindow {
            peer_index,
            mnemonic: peer.mnemonic().to_owned(),
            fault: "process-outage",
            started_ms: unix_timestamp_ms(),
            ended_ms: None,
        });
        self.current_peer = Some(peer_index);
        Ok(())
    }
    async fn heal_peer(
        &mut self,
        network: &Network,
        peer_index: usize,
        context: &str,
        require_post_heal_progress: bool,
    ) -> Result<()> {
        let catch_up_target = realistic_30tps_catch_up_target(network, peer_index).await?;
        restart_realistic_30tps_peer(
            network,
            peer_index,
            &self.base_layers,
            true,
            self.config.recovery_wait_timeout(),
            context,
            Some(&mut self.status_recovery_samples),
        )
        .await?;
        wait_for_realistic_peer_catch_up(
            network,
            peer_index,
            catch_up_target,
            self.config.recovery_wait_timeout(),
            Some(&mut self.catch_up_samples),
        )
        .await
        .wrap_err_with(|| format!("{context}: peer {peer_index} catch-up after healing"))?;
        if require_post_heal_progress {
            let healed_fault = self.current_fault_for_peer(peer_index);
            wait_for_realistic_post_heal_consensus_progress(
                network,
                peer_index,
                self.config.recovery_wait_timeout(),
                self.final_target_approved,
            )
            .await
            .wrap_err_with(|| {
                format!("{context}: peer {peer_index} post-heal consensus progress")
            })?;
            if self.config.requires_bounded_convergence() {
                let convergence_window = wait_for_realistic_all_peer_convergence(
                    network,
                    peer_index,
                    healed_fault,
                    self.config.convergence_progress_timeout(),
                    self.config.convergence_total_bound(),
                )
                .await
                .wrap_err_with(|| {
                    format!("{context}: peer {peer_index} post-heal all-peer convergence")
                })?;
                self.convergence_windows.push(convergence_window);
            }
        }
        if let Some(window) = self
            .fault_windows
            .iter_mut()
            .rev()
            .find(|window| window.peer_index == peer_index && window.ended_ms.is_none())
        {
            window.ended_ms = Some(unix_timestamp_ms());
        }
        self.current_peer = None;
        Ok(())
    }
}
fn sync_realistic_fault_artifacts(
    controller: &mut Realistic30TpsRotatingFaultController,
    artifacts: &mut ThroughputArtifacts,
) {
    artifacts
        .status_recovery_samples
        .extend(controller.drain_status_recovery_samples());
    artifacts
        .catch_up_samples
        .extend(controller.drain_catch_up_samples());
    let synced_convergence_windows = artifacts.convergence_windows.len();
    if synced_convergence_windows < controller.convergence_windows().len() {
        artifacts.convergence_windows.extend(
            controller.convergence_windows()[synced_convergence_windows..]
                .iter()
                .cloned(),
        );
    }
    artifacts.fault_windows = controller.fault_windows().to_vec();
}
async fn restart_realistic_30tps_peer(
    network: &Network,
    peer_index: usize,
    layers: &[ConfigLayer],
    wait_for_status: bool,
    status_timeout: Duration,
    context: &str,
    mut status_samples: Option<&mut Vec<Realistic30TpsStatusRecoverySample>>,
) -> Result<()> {
    let peer = network
        .peers()
        .get(peer_index)
        .ok_or_else(|| eyre!("peer index {peer_index} missing during {context}"))?;
    let mnemonic = peer.mnemonic().to_owned();
    eprintln!("realistic localnet {context}: restarting peer {peer_index} ({mnemonic})");
    let restart_started_ms = unix_timestamp_ms();
    let snapshot_before_shutdown = realistic_30tps_peer_snapshot_observation(peer);
    let _ = peer.shutdown_if_started().await;
    let snapshot_after_shutdown = realistic_30tps_peer_snapshot_observation(peer);
    peer.start(layers.iter().cloned(), None)
        .await
        .wrap_err_with(|| format!("{context}: restart peer {peer_index} ({mnemonic})"))?;
    sleep(REALISTIC_30TPS_RESTART_GRACE).await;
    if !peer.is_running() {
        let last_error = "peer exited during restart grace".to_string();
        if let Some(status_samples) = status_samples.as_mut() {
            status_samples.push(Realistic30TpsStatusRecoverySample {
                peer_index,
                mnemonic: mnemonic.clone(),
                context: context.to_string(),
                restart_started_ms,
                status_wait_started_ms: unix_timestamp_ms(),
                ended_ms: unix_timestamp_ms(),
                bound_ms: duration_millis_u64(status_timeout),
                recovered: false,
                poll_attempts: 0,
                last_error: Some(last_error.clone()),
                snapshot_before_shutdown,
                snapshot_after_shutdown,
                snapshot_after_status: realistic_30tps_peer_snapshot_observation(peer),
            });
        }
        return Err(eyre!(
            "{context}: peer {peer_index} ({mnemonic}) {last_error}"
        ));
    }
    if wait_for_status {
        let sample = wait_for_realistic_peer_status(
            peer_index,
            peer,
            context,
            restart_started_ms,
            status_timeout,
            snapshot_before_shutdown,
            snapshot_after_shutdown,
        )
        .await;
        let recovered = sample.recovered;
        let status_wait_ms = sample.status_wait_ms();
        let last_error = sample.last_error.clone();
        if let Some(status_samples) = status_samples.as_mut() {
            status_samples.push(sample);
        }
        ensure!(
            recovered,
            "{context}: peer {peer_index} ({mnemonic}) status did not recover within {:?}: {}",
            status_timeout,
            last_error.unwrap_or_else(|| "status endpoint unavailable".to_string())
        );
        eprintln!(
            "realistic localnet {context}: peer {peer_index} ({mnemonic}) status recovered in {status_wait_ms}ms"
        );
    }
    Ok(())
}
async fn wait_for_realistic_peer_status(
    peer_index: usize,
    peer: &iroha_test_network::NetworkPeer,
    context: &str,
    restart_started_ms: u64,
    timeout: Duration,
    snapshot_before_shutdown: Realistic30TpsSnapshotObservation,
    snapshot_after_shutdown: Realistic30TpsSnapshotObservation,
) -> Realistic30TpsStatusRecoverySample {
    let status_wait_started_ms = unix_timestamp_ms();
    let deadline = Instant::now() + timeout;
    let bound_ms = duration_millis_u64(timeout);
    let mut poll_attempts = 0_u64;
    let mut last_error = None;
    let mut last_log = Instant::now()
        .checked_sub(STATUS_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    let make_sample =
        |ended_ms: u64, recovered: bool, poll_attempts: u64, last_error: Option<String>| {
            Realistic30TpsStatusRecoverySample {
                peer_index,
                mnemonic: peer.mnemonic().to_owned(),
                context: context.to_string(),
                restart_started_ms,
                status_wait_started_ms,
                ended_ms,
                bound_ms,
                recovered,
                poll_attempts,
                last_error,
                snapshot_before_shutdown: snapshot_before_shutdown.clone(),
                snapshot_after_shutdown: snapshot_after_shutdown.clone(),
                snapshot_after_status: realistic_30tps_peer_snapshot_observation(peer),
            }
        };
    loop {
        if !peer.is_running() {
            last_error = Some(format!(
                "{context}: peer {} exited before status recovery",
                peer.mnemonic()
            ));
            return make_sample(unix_timestamp_ms(), false, poll_attempts, last_error);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if last_error.is_none() {
                last_error = Some(format!("status did not recover within {timeout:?}"));
            }
            return make_sample(unix_timestamp_ms(), false, poll_attempts, last_error);
        }
        let poll_timeout = std::cmp::min(remaining, REALISTIC_30TPS_STATUS_RECOVERY_POLL_TIMEOUT);
        poll_attempts = poll_attempts.saturating_add(1);
        match tokio::time::timeout(poll_timeout, peer.status()).await {
            Ok(Ok(_)) => {
                return make_sample(unix_timestamp_ms(), true, poll_attempts, last_error);
            }
            Ok(Err(err)) => {
                last_error = Some(format!("{err:?}"));
                if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "waiting for restarted peer {} status recovery: {err:?}",
                        peer.mnemonic()
                    );
                    last_log = Instant::now();
                }
            }
            Err(_) => {
                last_error = Some(format!("status poll timed out after {poll_timeout:?}"));
                if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "waiting for restarted peer {} status recovery timed out",
                        peer.mnemonic()
                    );
                    last_log = Instant::now();
                }
            }
        }
        if Instant::now() >= deadline {
            if last_error.is_none() {
                last_error = Some(format!("status did not recover within {timeout:?}"));
            }
            return make_sample(unix_timestamp_ms(), false, poll_attempts, last_error);
        }
        let sleep_for = std::cmp::min(
            Duration::from_millis(200),
            deadline.saturating_duration_since(Instant::now()),
        );
        if !sleep_for.is_zero() {
            sleep(sleep_for).await;
        }
    }
}
async fn realistic_30tps_catch_up_target(
    network: &Network,
    recovering_peer_index: usize,
) -> Result<Realistic30TpsCatchUpTarget> {
    let statuses = try_join_all(
        network
            .peers()
            .iter()
            .enumerate()
            .filter(|(peer_index, _)| *peer_index != recovering_peer_index)
            .map(|(peer_index, peer)| async move {
                tokio::time::timeout(STATUS_POLL_TIMEOUT, peer.status())
                    .await
                    .map_err(|_| {
                        eyre!(
                            "status request timed out while computing recovery target for peer {peer_index}"
                        )
                    })?
                    .wrap_err_with(|| {
                        format!(
                            "status request failed while computing recovery target for peer {peer_index}"
                        )
                    })
            }),
    )
    .await?;
    realistic_30tps_catch_up_target_from_statuses(&statuses)
}
fn realistic_30tps_catch_up_target_from_statuses(
    statuses: &[iroha_torii_shared::status::Status],
) -> Result<Realistic30TpsCatchUpTarget> {
    ensure!(
        !statuses.is_empty(),
        "cannot compute recovery target without any healthy peer status"
    );
    Ok(Realistic30TpsCatchUpTarget {
        blocks_non_empty: statuses
            .iter()
            .map(|status| status.blocks_non_empty)
            .max()
            .unwrap_or_default(),
        txs_approved: statuses
            .iter()
            .map(|status| status.txs_approved)
            .max()
            .unwrap_or_default(),
    })
}
fn realistic_30tps_strict_progress_target_from_statuses(
    statuses: &[iroha_torii_shared::status::Status],
) -> Result<Realistic30TpsCatchUpTarget> {
    ensure!(
        !statuses.is_empty(),
        "cannot compute strict progress target without any peer status"
    );
    Ok(Realistic30TpsCatchUpTarget {
        blocks_non_empty: statuses
            .iter()
            .map(|status| status.blocks_non_empty)
            .min()
            .unwrap_or_default(),
        txs_approved: statuses
            .iter()
            .map(|status| status.txs_approved)
            .min()
            .unwrap_or_default(),
    })
}
fn realistic_30tps_statuses_exceed_strict_progress_target(
    statuses: &[iroha_torii_shared::status::Status],
    target: Realistic30TpsCatchUpTarget,
) -> bool {
    realistic_30tps_strict_progress_target_from_statuses(statuses).is_ok_and(|current| {
        current.blocks_non_empty > target.blocks_non_empty
            || current.txs_approved > target.txs_approved
    })
}
fn realistic_30tps_statuses_satisfy_post_heal_progress(
    statuses: &[iroha_torii_shared::status::Status],
    target: Realistic30TpsCatchUpTarget,
    final_target_approved: u64,
) -> bool {
    realistic_30tps_strict_progress_target_from_statuses(statuses).is_ok_and(|current| {
        current.blocks_non_empty > target.blocks_non_empty
            || current.txs_approved > target.txs_approved
            || current.txs_approved >= final_target_approved
    })
}
fn realistic_30tps_convergence_span_from_statuses(
    statuses: &[iroha_torii_shared::status::Status],
) -> Result<Realistic30TpsConvergenceSpan> {
    ensure!(
        !statuses.is_empty(),
        "cannot compute all-peer convergence without any peer status"
    );
    Ok(Realistic30TpsConvergenceSpan {
        min_blocks_non_empty: statuses
            .iter()
            .map(|status| status.blocks_non_empty)
            .min()
            .unwrap_or_default(),
        max_blocks_non_empty: statuses
            .iter()
            .map(|status| status.blocks_non_empty)
            .max()
            .unwrap_or_default(),
        min_txs_approved: statuses
            .iter()
            .map(|status| status.txs_approved)
            .min()
            .unwrap_or_default(),
        max_txs_approved: statuses
            .iter()
            .map(|status| status.txs_approved)
            .max()
            .unwrap_or_default(),
    })
}
fn realistic_30tps_statuses_are_converged(
    statuses: &[iroha_torii_shared::status::Status],
) -> Result<bool> {
    let span = realistic_30tps_convergence_span_from_statuses(statuses)?;
    Ok(span
        .max_blocks_non_empty
        .saturating_sub(span.min_blocks_non_empty)
        <= REALISTIC_30TPS_ROTATING_FAULT_MAX_HEALTHY_BLOCK_LAG
        && span.max_txs_approved.saturating_sub(span.min_txs_approved)
            <= REALISTIC_30TPS_ROTATING_FAULT_MAX_HEALTHY_APPROVED_LAG)
}
fn realistic_30tps_convergence_progress_since(
    current: Realistic30TpsConvergenceSpan,
    last_seen: Realistic30TpsConvergenceSpan,
) -> Option<Realistic30TpsConvergenceSpan> {
    let current_block_lag = current
        .max_blocks_non_empty
        .saturating_sub(current.min_blocks_non_empty);
    let last_block_lag = last_seen
        .max_blocks_non_empty
        .saturating_sub(last_seen.min_blocks_non_empty);
    let current_approved_lag = current
        .max_txs_approved
        .saturating_sub(current.min_txs_approved);
    let last_approved_lag = last_seen
        .max_txs_approved
        .saturating_sub(last_seen.min_txs_approved);
    (current.min_blocks_non_empty > last_seen.min_blocks_non_empty
        || current.min_txs_approved > last_seen.min_txs_approved
        || current_block_lag < last_block_lag
        || current_approved_lag < last_approved_lag)
        .then_some(current)
}
fn realistic_30tps_catch_up_progress_since(
    status: &iroha_torii_shared::status::Status,
    last_seen: Realistic30TpsCatchUpTarget,
) -> Option<Realistic30TpsCatchUpTarget> {
    let current = Realistic30TpsCatchUpTarget {
        blocks_non_empty: status.blocks_non_empty,
        txs_approved: status.txs_approved,
    };
    (current.blocks_non_empty > last_seen.blocks_non_empty
        || current.txs_approved > last_seen.txs_approved)
        .then_some(current)
}
async fn realistic_30tps_healthy_status_snapshots(
    network: &Network,
    recovering_peer_index: usize,
    status_timeout: Duration,
) -> Result<Vec<StatusSnapshot>> {
    let statuses = try_join_all(
        network
            .peers()
            .iter()
            .enumerate()
            .filter(|(peer_index, _)| *peer_index != recovering_peer_index)
            .map(|(peer_index, peer)| async move {
                tokio::time::timeout(status_timeout, peer.status())
                    .await
                    .map_err(|_| {
                        eyre!("healthy peer {peer_index} status timed out during catch-up sample")
                    })?
                    .wrap_err_with(|| {
                        format!("healthy peer {peer_index} status failed during catch-up sample")
                    })
            }),
    )
    .await?;
    Ok(statuses.iter().map(StatusSnapshot::from_status).collect())
}
async fn realistic_30tps_catch_up_sample(
    network: &Network,
    recovering_peer_index: usize,
    target: Realistic30TpsCatchUpTarget,
    recovering_status: Option<StatusSnapshot>,
    recovering_no_progress: Duration,
) -> Realistic30TpsCatchUpSample {
    let (healthy_statuses, healthy_status_error) = match realistic_30tps_healthy_status_snapshots(
        network,
        recovering_peer_index,
        STATUS_POLL_TIMEOUT,
    )
    .await
    {
        Ok(statuses) => (statuses, None),
        Err(err) => (Vec::new(), Some(format!("{err:?}"))),
    };
    Realistic30TpsCatchUpSample {
        timestamp_ms: unix_timestamp_ms(),
        recovering_peer_index,
        target,
        recovering_status,
        healthy_statuses,
        healthy_status_error,
        recovering_no_progress_ms: u64::try_from(recovering_no_progress.as_millis())
            .unwrap_or(u64::MAX),
    }
}
async fn wait_for_realistic_peer_catch_up(
    network: &Network,
    peer_index: usize,
    target: Realistic30TpsCatchUpTarget,
    no_progress_timeout: Duration,
    mut catch_up_samples: Option<&mut Vec<Realistic30TpsCatchUpSample>>,
) -> Result<()> {
    let peer = network
        .peers()
        .get(peer_index)
        .ok_or_else(|| eyre!("peer index {peer_index} missing during catch-up wait"))?;
    let mut last_seen = Realistic30TpsCatchUpTarget::default();
    let mut last_progress = Instant::now();
    let mut last_log = Instant::now()
        .checked_sub(STATUS_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        if !peer.is_running() {
            return Err(eyre!(
                "peer {} exited before catch-up to {:?}",
                peer.mnemonic(),
                target
            ));
        }
        let mut recovering_status = None;
        if let Ok(Ok(status)) = tokio::time::timeout(STATUS_POLL_TIMEOUT, peer.status()).await {
            if status.blocks_non_empty >= target.blocks_non_empty
                && status.txs_approved >= target.txs_approved
            {
                return Ok(());
            }
            if let Some(current) = realistic_30tps_catch_up_progress_since(&status, last_seen) {
                last_seen = current;
                last_progress = Instant::now();
            }
            recovering_status = Some(StatusSnapshot::from_status(&status));
            if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                let sample = realistic_30tps_catch_up_sample(
                    network,
                    peer_index,
                    target,
                    recovering_status.clone(),
                    last_progress.elapsed(),
                )
                .await;
                let healthy_summary =
                    ThroughputStatusSummary::from_statuses(&sample.healthy_statuses);
                if let Some(samples) = catch_up_samples.as_mut() {
                    samples.push(sample);
                }
                eprintln!(
                    "waiting for restarted peer {} catch-up: current_non_empty={}, target_non_empty={}, current_approved={}, target_approved={}, healthy_min_non_empty={}, healthy_max_non_empty={}, healthy_min_approved={}, healthy_max_approved={}, no_progress_for={:?}",
                    peer.mnemonic(),
                    status.blocks_non_empty,
                    target.blocks_non_empty,
                    status.txs_approved,
                    target.txs_approved,
                    healthy_summary.min_blocks_non_empty,
                    healthy_summary.max_blocks_non_empty,
                    healthy_summary.min_txs_approved,
                    healthy_summary.max_txs_approved,
                    last_progress.elapsed()
                );
                last_log = Instant::now();
            }
        } else if last_log.elapsed() >= STATUS_LOG_INTERVAL {
            let sample = realistic_30tps_catch_up_sample(
                network,
                peer_index,
                target,
                recovering_status,
                last_progress.elapsed(),
            )
            .await;
            let healthy_summary = ThroughputStatusSummary::from_statuses(&sample.healthy_statuses);
            let healthy_status_error = sample.healthy_status_error.clone();
            if let Some(samples) = catch_up_samples.as_mut() {
                samples.push(sample);
            }
            eprintln!(
                "waiting for restarted peer {} catch-up status sample: healthy_min_non_empty={}, healthy_max_non_empty={}, healthy_min_approved={}, healthy_max_approved={}, healthy_status_error={:?}",
                peer.mnemonic(),
                healthy_summary.min_blocks_non_empty,
                healthy_summary.max_blocks_non_empty,
                healthy_summary.min_txs_approved,
                healthy_summary.max_txs_approved,
                healthy_status_error
            );
            last_log = Instant::now();
        }
        if last_progress.elapsed() >= no_progress_timeout {
            return Err(eyre!(
                "peer {} did not make catch-up progress toward {:?} for {:?}: last_seen={:?}",
                peer.mnemonic(),
                target,
                no_progress_timeout,
                last_seen
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn wait_for_realistic_all_peer_convergence(
    network: &Network,
    peer_index: usize,
    healed_fault: &'static str,
    no_progress_timeout: Duration,
    total_timeout: Option<Duration>,
) -> Result<Realistic30TpsConvergenceWindow> {
    let peer = network
        .peers()
        .get(peer_index)
        .ok_or_else(|| eyre!("peer index {peer_index} missing during all-peer convergence wait"))?;
    let started_at = Instant::now();
    let started_ms = unix_timestamp_ms();
    let mut start_span: Option<Realistic30TpsConvergenceSpan> = None;
    let mut last_seen: Option<Realistic30TpsConvergenceSpan> = None;
    let mut last_progress = Instant::now();
    let mut last_log = Instant::now()
        .checked_sub(STATUS_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        for (running_peer_index, running_peer) in network.peers().iter().enumerate() {
            if !running_peer.is_running() {
                return Err(eyre!(
                    "peer {} exited before all-peer convergence after healing peer {}",
                    running_peer_index,
                    peer.mnemonic()
                ));
            }
        }
        match collect_statuses(network, STATUS_POLL_TIMEOUT).await {
            Ok(statuses) => {
                let span = realistic_30tps_convergence_span_from_statuses(&statuses)?;
                if start_span.is_none() {
                    start_span = Some(span);
                }
                if realistic_30tps_statuses_are_converged(&statuses)? {
                    eprintln!(
                        "healed peer {} all-peer convergence: min_non_empty={}, max_non_empty={}, min_approved={}, max_approved={}",
                        peer.mnemonic(),
                        span.min_blocks_non_empty,
                        span.max_blocks_non_empty,
                        span.min_txs_approved,
                        span.max_txs_approved
                    );
                    return Ok(Realistic30TpsConvergenceWindow {
                        healed_peer_index: peer_index,
                        healed_fault,
                        started_ms,
                        ended_ms: unix_timestamp_ms(),
                        start_span,
                        end_span: span,
                    });
                }
                match last_seen {
                    Some(previous) => {
                        if let Some(current) =
                            realistic_30tps_convergence_progress_since(span, previous)
                        {
                            last_seen = Some(current);
                            last_progress = Instant::now();
                        }
                    }
                    None => {
                        last_seen = Some(span);
                        last_progress = Instant::now();
                    }
                }
                if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "waiting for healed peer {} all-peer convergence: min_non_empty={}, max_non_empty={}, min_approved={}, max_approved={}, max_block_lag={}, max_approved_lag={}, no_progress_for={:?}",
                        peer.mnemonic(),
                        span.min_blocks_non_empty,
                        span.max_blocks_non_empty,
                        span.min_txs_approved,
                        span.max_txs_approved,
                        REALISTIC_30TPS_ROTATING_FAULT_MAX_HEALTHY_BLOCK_LAG,
                        REALISTIC_30TPS_ROTATING_FAULT_MAX_HEALTHY_APPROVED_LAG,
                        last_progress.elapsed()
                    );
                    last_log = Instant::now();
                }
            }
            Err(err) => {
                if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "waiting for healed peer {} all-peer convergence status sample: {err:?}",
                        peer.mnemonic()
                    );
                    last_log = Instant::now();
                }
            }
        }
        if last_progress.elapsed() >= no_progress_timeout {
            return Err(eyre!(
                "peers did not make all-peer convergence progress for {:?} after healing peer {}: last_seen={:?}",
                no_progress_timeout,
                peer.mnemonic(),
                last_seen
            ));
        }
        if let Some(total_timeout) = total_timeout
            && started_at.elapsed() >= total_timeout
        {
            return Err(eyre!(
                "peers did not converge within {:?} after healing peer {}: last_seen={:?}",
                total_timeout,
                peer.mnemonic(),
                last_seen
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn wait_for_realistic_post_heal_consensus_progress(
    network: &Network,
    peer_index: usize,
    timeout: Duration,
    final_target_approved: u64,
) -> Result<()> {
    let peer = network
        .peers()
        .get(peer_index)
        .ok_or_else(|| eyre!("peer index {peer_index} missing during post-heal progress wait"))?;
    let baseline_statuses = collect_statuses(network, STATUS_POLL_TIMEOUT)
        .await
        .wrap_err_with(|| {
            format!(
                "failed to collect all peer statuses before post-heal progress wait for peer {}",
                peer.mnemonic()
            )
        })?;
    let target = realistic_30tps_strict_progress_target_from_statuses(&baseline_statuses)?;
    let deadline = Instant::now() + timeout;
    let mut last_log = Instant::now()
        .checked_sub(STATUS_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        for (running_peer_index, running_peer) in network.peers().iter().enumerate() {
            if !running_peer.is_running() {
                return Err(eyre!(
                    "peer {} exited before post-heal consensus progress for peer {}",
                    running_peer_index,
                    peer.mnemonic()
                ));
            }
        }
        match collect_statuses(network, STATUS_POLL_TIMEOUT).await {
            Ok(statuses) => {
                let current = realistic_30tps_strict_progress_target_from_statuses(&statuses)?;
                if realistic_30tps_statuses_satisfy_post_heal_progress(
                    &statuses,
                    target,
                    final_target_approved,
                ) {
                    eprintln!(
                        "healed peer {} post-heal consensus progress: baseline_non_empty={}, current_min_non_empty={}, baseline_approved={}, current_min_approved={}",
                        peer.mnemonic(),
                        target.blocks_non_empty,
                        current.blocks_non_empty,
                        target.txs_approved,
                        current.txs_approved
                    );
                    return Ok(());
                }
                if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "waiting for healed peer {} post-heal consensus progress: current_min_non_empty={}, target_min_non_empty_gt={}, current_min_approved={}, target_min_approved_gt={}",
                        peer.mnemonic(),
                        current.blocks_non_empty,
                        target.blocks_non_empty,
                        current.txs_approved,
                        target.txs_approved
                    );
                    last_log = Instant::now();
                }
            }
            Err(err) => {
                if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "waiting for healed peer {} post-heal all-peer status sample: {err:?}",
                        peer.mnemonic()
                    );
                    last_log = Instant::now();
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "peer {} did not reach post-heal consensus progress from {:?} within {:?}",
                peer.mnemonic(),
                target,
                timeout
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}
fn realistic_fault_windows_have_no_overlap(windows: &[Realistic30TpsFaultWindow]) -> bool {
    let mut sorted: Vec<_> = windows.iter().collect();
    sorted.sort_by_key(|window| window.started_ms);
    let mut last_end = 0_u64;
    for window in sorted {
        if window.started_ms < last_end {
            return false;
        }
        last_end = window.ended_ms.unwrap_or(u64::MAX);
    }
    true
}
fn realistic_strict_fault_windows_start_after_convergence(
    windows: &[Realistic30TpsFaultWindow],
    convergence_windows: &[Realistic30TpsConvergenceWindow],
) -> bool {
    if windows.len() <= 1 {
        return true;
    }
    windows.windows(2).all(|pair| {
        let previous = &pair[0];
        let next = &pair[1];
        convergence_windows
            .iter()
            .find(|window| {
                window.healed_peer_index == previous.peer_index
                    && window.healed_fault == previous.fault
                    && window.started_ms >= previous.started_ms
            })
            .is_some_and(|convergence| next.started_ms >= convergence.ended_ms)
    })
}
fn unix_timestamp_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}
async fn run_realistic_30tps_localnet(
    consensus_mode: Realistic30TpsConsensusMode,
    test_name: &'static str,
    rotating_fault: Option<Realistic30TpsRotatingFaultConfig>,
) -> Result<()> {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let load_kind = Realistic30TpsLoadKind::from_env()?;
    init_instruction_registry();
    let duration_secs = env_or_default(
        "IROHA_REALISTIC_30TPS_DURATION_SECS",
        REALISTIC_30TPS_DURATION_SECS,
    );
    let target_tps = env_or_default(
        "IROHA_REALISTIC_30TPS_TARGET_TPS",
        REALISTIC_30TPS_TARGET_TPS,
    );
    let configured_target_blocks = env_or_default(
        "IROHA_REALISTIC_30TPS_TARGET_BLOCKS",
        REALISTIC_30TPS_TARGET_BLOCKS,
    );
    let block_cadence_ms = env_or_default(
        "IROHA_REALISTIC_30TPS_BLOCK_CADENCE_MS",
        REALISTIC_30TPS_BLOCK_CADENCE_MS,
    )
    .max(1);
    let stall_threshold = realistic_30tps_stall_threshold(rotating_fault.as_ref());
    let max_avg_secs_per_block = realistic_max_avg_secs_per_block(rotating_fault.is_some());
    let submit_parallelism = env_or_default_usize(
        "IROHA_REALISTIC_30TPS_PARALLELISM",
        REALISTIC_30TPS_SUBMIT_PARALLELISM,
    )
    .max(1);
    let queue_soft_limit = env_or_default(
        "IROHA_REALISTIC_30TPS_QUEUE_SOFT_LIMIT",
        realistic_default_queue_soft_limit(rotating_fault.is_some()),
    );
    let configured_transfer_accounts = env_or_default_usize(
        "IROHA_REALISTIC_30TPS_TRANSFER_ACCOUNTS",
        REALISTIC_30TPS_TRANSFER_ACCOUNTS,
    );
    let transfer_accounts = configured_transfer_accounts.max(2);
    let transfer_max_amount = env_or_default(
        "IROHA_REALISTIC_30TPS_TRANSFER_MAX_AMOUNT",
        REALISTIC_30TPS_TRANSFER_MAX_AMOUNT,
    )
    .max(1);
    let block_max_txs = env_or_default(
        "IROHA_REALISTIC_30TPS_BLOCK_MAX_TXS",
        realistic_default_block_max_txs(rotating_fault.is_some()),
    );
    let rng_seed = env_or_default("IROHA_REALISTIC_30TPS_RNG_SEED", THROUGHPUT_RNG_SEED);
    let total_txs = duration_secs.saturating_mul(target_tps);
    let minimum_initial_balance = total_txs
        .saturating_mul(transfer_max_amount)
        .saturating_add(1);
    let transfer_initial_balance = env_or_default(
        "IROHA_REALISTIC_30TPS_TRANSFER_INITIAL_BALANCE",
        minimum_initial_balance,
    )
    .max(minimum_initial_balance);
    ensure!(
        total_txs > 0 && block_max_txs > 0,
        "realistic 30 TPS run requires a positive duration and TPS"
    );
    let target_blocks = realistic_target_blocks(configured_target_blocks, total_txs, block_max_txs);
    let rotating_fault_snapshots_enabled = rotating_fault.is_some();
    let (snapshot_mode, snapshot_create_every_ms) =
        realistic_30tps_snapshot_settings(rotating_fault_snapshots_enabled);
    let snapshot_create_every_config_ms = if rotating_fault_snapshots_enabled {
        snapshot_create_every_ms
    } else {
        600_000
    };
    let transfer_asset_definition_id = realistic_transfer_asset_definition_id();
    let transfer_load_accounts = realistic_transfer_accounts(transfer_accounts, rng_seed);
    let previous_ttl = std::env::var_os("IROHA_TEST_CLIENT_TTL_MS");
    let client_ttl = Duration::from_secs(duration_secs.saturating_add(120));
    set_env_var(
        "IROHA_TEST_CLIENT_TTL_MS",
        client_ttl.as_millis().to_string(),
    );
    let builder = NetworkBuilder::new()
        .with_peers(REALISTIC_30TPS_PEERS)
        .with_auto_populated_trusted_peers()
        .with_real_genesis_keypair()
        .with_block_cadence(Duration::from_millis(block_cadence_ms))
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(
                std::num::NonZeroU64::new(block_max_txs).expect("checked non-zero"),
            ),
        )));
    let mut builder = consensus_mode
        .select_in_genesis(builder)
        .with_config_layer(|layer| {
            let logger_level =
                std::env::var("IROHA_REALISTIC_30TPS_LOG_LEVEL").unwrap_or_else(|_| "WARN".into());
            layer
                .write(["logger", "level"], logger_level)
                .write(["network", "transaction_gossip_period_ms"], 20_i64)
                .write(["network", "transaction_gossip_size"], 64_i64)
                .write(["network", "max_frame_bytes_tx_gossip"], 65_536_i64)
                .write(["network", "transaction_gossip_public_target_cap"], 8_i64)
                .write(
                    ["network", "transaction_gossip_restricted_target_cap"],
                    8_i64,
                )
                .write(["network", "p2p_post_queue_cap"], 8192_i64)
                .write(["network", "p2p_queue_cap_high"], 16384_i64)
                .write(["network", "p2p_queue_cap_low"], 65536_i64)
                .write(["network", "disconnect_on_post_overflow"], false)
                .write(["nexus", "fusion", "floor_teu"], THROUGHPUT_LANE_TEU_FLOOR)
                .write(
                    ["nexus", "fusion", "exit_teu"],
                    THROUGHPUT_LANE_TEU_CAPACITY,
                )
                .write(
                    ["torii", "preauth_allow_cidrs"],
                    TomlValue::Array(vec![
                        TomlValue::String("127.0.0.0/8".into()),
                        TomlValue::String("::1/128".into()),
                    ]),
                )
                .write(
                    ["torii", "api_rate_limit_bypass_cidrs"],
                    TomlValue::Array(vec![
                        TomlValue::String("127.0.0.0/8".into()),
                        TomlValue::String("::1/128".into()),
                    ]),
                )
                .write(["torii", "preauth_rate_per_ip_per_sec"], 1_000_000_i64)
                .write(["torii", "preauth_burst_per_ip"], 2_000_000_i64)
                .write(["torii", "query_rate_per_authority_per_sec"], 0_i64)
                .write(["torii", "query_burst_per_authority"], 0_i64)
                .write(["torii", "tx_rate_per_authority_per_sec"], 0_i64)
                .write(["torii", "tx_burst_per_authority"], 0_i64)
                .write(["torii", "api_high_load_tx_threshold"], 262_144_i64)
                .write(["snapshot", "mode"], snapshot_mode)
                .write(
                    ["snapshot", "create_every_ms"],
                    i64::try_from(snapshot_create_every_config_ms)
                        .expect("snapshot create interval fits i64"),
                );
        });
    if consensus_mode.is_npos() {
        let mut npos = SumeragiNposParameters::default();
        npos.max_validators = 4;
        npos.epoch_length_blocks = std::num::NonZeroU64::new(3_600).unwrap();
        builder = builder.with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )));
    }
    {
        builder = builder
            .with_genesis_instruction(Register::domain(
                Domain::new(realistic_transfer_domain_id()),
            ))
            .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
                transfer_asset_definition_id.clone(),
                "Realistic Transfer Coin",
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )));
        for account in &transfer_load_accounts {
            builder = builder
                .with_genesis_instruction(Register::account(Account::new(account.id.clone())))
                .with_genesis_instruction(Mint::asset_quantity(
                    transfer_initial_balance,
                    AssetId::new(transfer_asset_definition_id.clone(), account.id.clone()),
                ));
        }
    }
    let result: Result<()> = async {
        let Some(network) = sandbox::start_network_async_or_skip(builder, test_name).await?
        else {
            return Ok(());
        };
        let network_dir = network.env_dir().to_path_buf();
        let http = HttpClient::builder()
            .tls_built_in_root_certs(false)
            .build()
            .wrap_err("build local HTTP client for realistic throughput soak")?;
        let mut artifacts = ThroughputArtifacts::default();
        let run_result: Result<()> = async {
            wait_for_status_responses(&network, Duration::from_secs(30)).await?;
            if consensus_mode.is_npos() {
                fund_realistic_npos_transfer_fee_accounts(&network, &transfer_load_accounts)
                    .await
                    .wrap_err("failed to fund realistic NPoS transfer fee accounts")?;
            }
            let baseline_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
            let baseline_non_empty = baseline_statuses
                .iter()
                .map(|status| status.blocks_non_empty)
                .min()
                .unwrap_or_default();
            let baseline_approved = baseline_statuses
                .iter()
                .map(|status| status.txs_approved)
                .min()
                .unwrap_or_default();
            let target_non_empty = baseline_non_empty.saturating_add(target_blocks);
            let target_approved = baseline_approved.saturating_add(total_txs);
            artifacts.recipe = Some(ThroughputArtifactRecipe {
                peers: network.peers().len() as u64,
                block_cadence_ms,
                block_max_txs,
                warmup_blocks: 0,
                steady_blocks: target_blocks,
                total_blocks: target_blocks,
                warmup_txs: 0,
                steady_txs: total_txs,
                total_txs,
                submit_batch: target_tps,
                submit_parallelism: submit_parallelism as u64,
                queue_soft_limit,
                payload_bytes: 0,
                load_kind: load_kind.as_str().to_owned(),
                transfer_accounts: transfer_accounts as u64,
                transfer_initial_balance,
                transfer_max_amount,
                rng_seed,
                snapshot_mode: snapshot_mode.to_owned(),
                snapshot_create_every_ms,
            });
            let mut fault_controller = if let Some(config) = rotating_fault {
                let mut controller = Realistic30TpsRotatingFaultController::new(
                    &network,
                    config,
                    target_approved,
                );
                controller
                    .start(&network)
                    .await
                    .wrap_err("failed to start rotating validator-outage controller")?;
                artifacts.fault_windows = controller.fault_windows().to_vec();
                Some(controller)
            } else {
                None
            };
            let submitted_counter = Arc::new(AtomicU64::new(0));
            let submitted_for_task = Arc::clone(&submitted_counter);
            let submit_accept_quorum = realistic_submit_accept_quorum(
                network.peers().len(),
                if fault_controller.is_some() {
                    REALISTIC_30TPS_ROTATING_FAULT_TOLERATED_PEERS
                } else {
                    0
                },
            );
            let submit_handle = {
                let submit_accounts: Vec<_> = transfer_load_accounts
                    .iter()
                    .enumerate()
                    .map(|(index, account)| {
                        let peer_count = network.peers().len();
                        TransferSubmitAccount {
                            id: account.id.clone(),
                            clients: (0..peer_count)
                                .map(|offset| {
                                    let peer = &network.peers()[(index + offset) % peer_count];
                                    peer.client_for(
                                        &account.id,
                                        account.key_pair.private_key().clone(),
                                    )
                                })
                                .collect(),
                        }
                    })
                    .collect();
                tokio::spawn(submit_transfers_paced(
                    total_txs,
                    target_tps,
                    submit_accounts,
                    transfer_asset_definition_id.clone(),
                    transfer_max_amount,
                    rng_seed,
                    submit_parallelism,
                    submit_accept_quorum,
                    submitted_for_task,
                ))
            };
            eprintln!(
                "realistic localnet recipe: peers={}, target_tps={}, duration_secs={}, total_txs={}, target_non_empty_delta={}, signed_block_cadence_ms={}, block_max_txs={}, load_kind={}, transfer_accounts={}, transfer_initial_balance={}, transfer_max_amount={}, submit_parallelism={}, submit_accept_quorum={}, queue_soft_limit={}, snapshot_mode={}, snapshot_create_every_ms={}, stall_threshold={:?}, max_avg_secs_per_block={max_avg_secs_per_block:.3}, baseline_non_empty={}, baseline_approved={}",
                network.peers().len(),
                target_tps,
                duration_secs,
                total_txs,
                target_blocks,
                block_cadence_ms,
                block_max_txs,
                load_kind.as_str(),
                transfer_accounts,
                transfer_initial_balance,
                transfer_max_amount,
                submit_parallelism,
                submit_accept_quorum,
                queue_soft_limit,
                snapshot_mode,
                snapshot_create_every_ms,
                stall_threshold,
                baseline_non_empty,
                baseline_approved,
            );
            if let Some(controller) = fault_controller.as_ref() {
                eprintln!(
                    "realistic localnet rotating validator-outage recipe: rotate_interval={:?}, recovery_bound={:?}, strict_rotation_convergence={}, convergence_total_bound={:?}, initial_fault_windows={:?}",
                    controller.config.rotate_interval,
                    controller.config.recovery_bound,
                    controller.config.strict_rotation_convergence,
                    controller.config.convergence_total_bound,
                    controller.fault_windows()
                );
            }
            artifacts.samples.clear();
            let mut last_progress = Instant::now();
            let mut last_min_non_empty = baseline_non_empty;
            let mut last_min_approved = baseline_approved;
            let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
            let mut last_log = Instant::now()
                .checked_sub(REALISTIC_30TPS_PROGRESS_LOG_INTERVAL)
                .unwrap_or_else(Instant::now);
            let run_start = Instant::now();
            let tolerated_progress_lagging = usize::from(fault_controller.is_some());
            loop {
                if let Some(controller) = fault_controller.as_mut() {
                    match controller.rotate_if_due(&network).await {
                        Ok(_) => {
                            sync_realistic_fault_artifacts(controller, &mut artifacts);
                        }
                        Err(err) => {
                            sync_realistic_fault_artifacts(controller, &mut artifacts);
                            submit_handle.abort();
                            let _ = submit_handle.await;
                            if let Err(heal_err) = controller.stop_and_heal(&network).await {
                                eprintln!(
                                    "failed to heal rotating validator outage after load rotation error: {heal_err:?}"
                                );
                            }
                            sync_realistic_fault_artifacts(controller, &mut artifacts);
                            return Err(err.wrap_err(
                                "rotating validator-outage controller failed during load",
                            ));
                        }
                    };
                    sync_realistic_fault_artifacts(controller, &mut artifacts);
                }
                match collect_realistic_statuses(
                    &network,
                    STATUS_POLL_TIMEOUT,
                    fault_controller.is_some(),
                )
                .await
                {
                    Ok(statuses) => {
                        let status_snapshots: Vec<StatusSnapshot> =
                            statuses.iter().map(StatusSnapshot::from_status).collect();
                        let progress_summary =
                            ThroughputStatusSummary::from_statuses_tolerating_lagging(
                                &status_snapshots,
                                tolerated_progress_lagging,
                            );
                        let min_non_empty = progress_summary.min_blocks_non_empty;
                        let max_non_empty = progress_summary.max_blocks_non_empty;
                        let min_approved = progress_summary.min_txs_approved;
                        let max_queue = progress_summary.max_queue_size;
                        if min_non_empty > last_min_non_empty || min_approved > last_min_approved {
                            last_min_non_empty = min_non_empty;
                            last_min_approved = min_approved;
                            last_progress = Instant::now();
                        }
                        let sumeragi_snapshots = match collect_sumeragi_statuses(
                            &network,
                            STATUS_POLL_TIMEOUT,
                        )
                        .await
                        {
                            Ok(sumeragi) => sumeragi
                                .iter()
                                .map(SumeragiStatusSnapshot::from_status)
                                .collect(),
                            Err(err) => {
                                eprintln!("sumeragi status sample failed: {err:?}");
                                Vec::new()
                            }
                        };
                        let timestamp_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis();
                        artifacts.samples.push(ThroughputSample {
                            phase: Some("load".to_owned()),
                            timestamp_ms: u64::try_from(timestamp_ms).unwrap_or(u64::MAX),
                            statuses: status_snapshots.clone(),
                            sumeragi: sumeragi_snapshots,
                        });
                        last_snapshot = status_snapshots;
                        if last_log.elapsed() >= REALISTIC_30TPS_PROGRESS_LOG_INTERVAL {
                            eprintln!(
                                "realistic localnet progress elapsed={:?} submitted={} target_non_empty={} min_non_empty={} max_non_empty={} min_approved={} target_approved={} max_queue={}: {:?}",
                                run_start.elapsed(),
                                submitted_counter.load(AtomicOrdering::Relaxed),
                                target_non_empty,
                                min_non_empty,
                                max_non_empty,
                                min_approved,
                                target_approved,
                                max_queue,
                                last_snapshot,
                            );
                            last_log = Instant::now();
                        }
                    }
                    Err(err) => {
                        if last_log.elapsed() >= REALISTIC_30TPS_PROGRESS_LOG_INTERVAL {
                            eprintln!("realistic localnet status poll failed: {err:?}");
                            last_log = Instant::now();
                        }
                    }
                }
                if submit_handle.is_finished() {
                    break;
                }
                if last_progress.elapsed() >= stall_threshold {
                    submit_handle.abort();
                    let _ = submit_handle.await;
                    if let Some(controller) = fault_controller.as_mut() {
                        if let Err(err) = controller.stop_and_heal(&network).await {
                            eprintln!(
                                "failed to heal rotating validator outage after load stall: {err:?}"
                            );
                        }
                        sync_realistic_fault_artifacts(controller, &mut artifacts);
                    }
                    let elapsed = run_start.elapsed();
                    let submitted = submitted_counter.load(AtomicOrdering::Relaxed);
                    let produced_blocks = last_min_non_empty.saturating_sub(baseline_non_empty);
                    let status_summary =
                        ThroughputStatusSummary::from_statuses_tolerating_lagging(
                            &last_snapshot,
                            tolerated_progress_lagging,
                        );
                    artifacts.realistic = Some(realistic_artifact_summary(
                        baseline_non_empty,
                        baseline_approved,
                        target_non_empty,
                        target_approved,
                        submitted,
                        elapsed,
                        elapsed,
                        elapsed,
                        status_summary.clone(),
                        status_summary,
                        produced_blocks,
                        produced_blocks,
                        &artifacts.samples,
                    ));
                    return Err(eyre!(
                        "realistic localnet stalled for {:?}: elapsed={:?}, submitted={}, last_min_non_empty={}, last_min_approved={}, last_snapshot={last_snapshot:?}",
                        stall_threshold,
                        run_start.elapsed(),
                        submitted_counter.load(AtomicOrdering::Relaxed),
                        last_min_non_empty,
                        last_min_approved,
                    ));
                }
                sleep(REALISTIC_30TPS_SAMPLE_INTERVAL).await;
            }
            let submit_elapsed = submit_handle
                .await
                .wrap_err("paced submit task join failed")??;
            let load_end_elapsed = run_start.elapsed();
            let load_end_statuses =
                collect_realistic_statuses(&network, STATUS_POLL_TIMEOUT, fault_controller.is_some())
                    .await?;
            let load_end_snapshots: Vec<StatusSnapshot> = load_end_statuses
                .iter()
                .map(StatusSnapshot::from_status)
                .collect();
            let load_end_summary = ThroughputStatusSummary::from_statuses_tolerating_lagging(
                &load_end_snapshots,
                tolerated_progress_lagging,
            );
            let load_end_min_non_empty = load_end_summary.min_blocks_non_empty;
            let load_end_produced_blocks =
                load_end_min_non_empty.saturating_sub(baseline_non_empty);
            let max_load_queue_size = max_queue_size_for_phase(&artifacts.samples, "load");
            let mut after_statuses = load_end_statuses;
            let mut drain_last_progress = Instant::now();
            let mut drain_progress_summary = load_end_summary.clone();
            let mut drain_last_min_approved = drain_progress_summary.min_txs_approved;
            let mut drain_last_max_queue = drain_progress_summary.max_queue_size;
            while drain_last_min_approved < target_approved {
                if let Some(controller) = fault_controller.as_mut() {
                    match controller.rotate_if_due(&network).await {
                        Ok(_) => {
                            sync_realistic_fault_artifacts(controller, &mut artifacts);
                        }
                        Err(err) => {
                            sync_realistic_fault_artifacts(controller, &mut artifacts);
                            if let Err(heal_err) = controller.stop_and_heal(&network).await {
                                eprintln!(
                                    "failed to heal rotating validator outage after drain rotation error: {heal_err:?}"
                                );
                            }
                            sync_realistic_fault_artifacts(controller, &mut artifacts);
                            return Err(err.wrap_err(
                                "rotating validator-outage controller failed during drain",
                            ));
                        }
                    };
                    sync_realistic_fault_artifacts(controller, &mut artifacts);
                }
                sleep(REALISTIC_30TPS_SAMPLE_INTERVAL).await;
                after_statuses = collect_realistic_statuses(
                    &network,
                    STATUS_POLL_TIMEOUT,
                    fault_controller.is_some(),
                )
                .await?;
                let status_snapshots: Vec<StatusSnapshot> =
                    after_statuses.iter().map(StatusSnapshot::from_status).collect();
                drain_progress_summary =
                    ThroughputStatusSummary::from_statuses_tolerating_lagging(
                        &status_snapshots,
                        tolerated_progress_lagging,
                    );
                let sumeragi_snapshots = match collect_sumeragi_statuses(
                    &network,
                    STATUS_POLL_TIMEOUT,
                )
                .await
                {
                    Ok(sumeragi) => sumeragi
                        .iter()
                        .map(SumeragiStatusSnapshot::from_status)
                        .collect(),
                    Err(err) => {
                        eprintln!("sumeragi status drain sample failed: {err:?}");
                        Vec::new()
                    }
                };
                let timestamp_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                artifacts.samples.push(ThroughputSample {
                    phase: Some("drain".to_owned()),
                    timestamp_ms: u64::try_from(timestamp_ms).unwrap_or(u64::MAX),
                    statuses: status_snapshots.clone(),
                    sumeragi: sumeragi_snapshots,
                });
                let min_approved = drain_progress_summary.min_txs_approved;
                let max_queue = drain_progress_summary.max_queue_size;
                if min_approved > drain_last_min_approved || max_queue < drain_last_max_queue {
                    drain_last_min_approved = min_approved;
                    drain_last_max_queue = max_queue;
                    drain_last_progress = Instant::now();
                }
                if drain_last_progress.elapsed() >= stall_threshold {
                    let final_summary =
                        ThroughputStatusSummary::from_statuses_tolerating_lagging(
                            &status_snapshots,
                            tolerated_progress_lagging,
                        );
                    let produced_blocks = final_summary
                        .min_blocks_non_empty
                        .saturating_sub(baseline_non_empty);
                    artifacts.realistic = Some(realistic_artifact_summary(
                        baseline_non_empty,
                        baseline_approved,
                        target_non_empty,
                        target_approved,
                        submitted_counter.load(AtomicOrdering::Relaxed),
                        submit_elapsed,
                        load_end_elapsed,
                        run_start.elapsed(),
                        load_end_summary.clone(),
                        final_summary,
                        load_end_produced_blocks,
                        produced_blocks,
                        &artifacts.samples,
                    ));
                    if let Some(controller) = fault_controller.as_mut() {
                        if let Err(err) = controller.stop_and_heal(&network).await {
                            eprintln!(
                                "failed to heal rotating validator outage after drain stall: {err:?}"
                            );
                        }
                        sync_realistic_fault_artifacts(controller, &mut artifacts);
                    }
                    return Err(eyre!(
                        "realistic localnet stalled while draining after load for {:?}: load_elapsed={:?}, submitted={}, min_approved={}, target_approved={}, max_queue={}, last_statuses={after_statuses:?}",
                        stall_threshold,
                        load_end_elapsed,
                        submitted_counter.load(AtomicOrdering::Relaxed),
                        drain_last_min_approved,
                        target_approved,
                        drain_last_max_queue,
                    ));
                }
            }
            if let Some(controller) = fault_controller.as_mut() {
                controller
                    .stop_and_heal(&network)
                    .await
                    .wrap_err("failed to heal final rotating validator outage")?;
                sync_realistic_fault_artifacts(controller, &mut artifacts);
                wait_for_min_txs_approved(&network, target_approved, Duration::from_secs(60))
                    .await
                    .wrap_err("healed network did not preserve approved transaction convergence")?;
                after_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
            }
            let min_non_empty = after_statuses
                .iter()
                .map(|status| status.blocks_non_empty)
                .min()
                .unwrap_or_default();
            let min_approved = after_statuses
                .iter()
                .map(|status| status.txs_approved)
                .min()
                .unwrap_or_default();
            let max_rejected = after_statuses
                .iter()
                .map(|status| status.txs_rejected)
                .max()
                .unwrap_or_default();
            let produced_blocks = min_non_empty.saturating_sub(baseline_non_empty);
            let load_avg_secs_per_block =
                seconds_per_block(load_end_elapsed, load_end_produced_blocks);
            let avg_secs_per_block = seconds_per_block(run_start.elapsed(), produced_blocks);
            if let Ok(after_metrics) =
                collect_metrics_snapshots(&network, &http, THROUGHPUT_METRICS_TIMEOUT).await
            {
                artifacts.after_metrics = after_metrics;
            }
            let final_snapshots: Vec<StatusSnapshot> =
                after_statuses.iter().map(StatusSnapshot::from_status).collect();
            let final_summary = ThroughputStatusSummary::from_statuses(&final_snapshots);
            let total_elapsed = run_start.elapsed();
            let submitted = submitted_counter.load(AtomicOrdering::Relaxed);
            artifacts.realistic = Some(realistic_artifact_summary(
                baseline_non_empty,
                baseline_approved,
                target_non_empty,
                target_approved,
                submitted,
                submit_elapsed,
                load_end_elapsed,
                total_elapsed,
                load_end_summary.clone(),
                final_summary.clone(),
                load_end_produced_blocks,
                produced_blocks,
                &artifacts.samples,
            ));
            eprintln!(
                "realistic localnet summary: load_elapsed={:?}, elapsed={:?}, submit_elapsed={:?}, submitted={}, load_end_produced_blocks={}, produced_blocks={}, min_non_empty={}, target_non_empty={}, final_min_non_empty={}, min_approved={}, target_approved={}, max_rejected={}, load_avg_secs_per_block={load_avg_secs_per_block:.3}, avg_secs_per_block={avg_secs_per_block:.3}",
                load_end_elapsed,
                run_start.elapsed(),
                submit_elapsed,
                submitted_counter.load(AtomicOrdering::Relaxed),
                load_end_produced_blocks,
                produced_blocks,
                load_end_min_non_empty,
                target_non_empty,
                min_non_empty,
                min_approved,
                target_approved,
                max_rejected,
            );
            ensure!(
                load_end_produced_blocks >= target_blocks,
                "realistic 30 TPS load did not keep up with submitted TPS: produced {load_end_produced_blocks} non-empty blocks during load, target {target_blocks}, block_max_txs={block_max_txs}, load_elapsed={load_end_elapsed:?}"
            );
            ensure!(
                max_load_queue_size <= queue_soft_limit,
                "realistic 30 TPS queue exceeded soft limit during load: max_queue_size={max_load_queue_size}, queue_soft_limit={queue_soft_limit}, load_committed_tps={:.3}, submitted_tps={:.3}",
                rate_per_second(
                    load_end_summary
                        .min_txs_approved
                        .saturating_sub(baseline_approved),
                    load_end_elapsed,
                ),
                rate_per_second(submitted, submit_elapsed),
            );
            ensure!(
                min_non_empty >= target_non_empty,
                "expected at least {target_blocks} final non-empty blocks for {duration_secs}s at {target_tps} TPS; produced {produced_blocks} (baseline={baseline_non_empty}, load_end_min_non_empty={load_end_min_non_empty}, final_min_non_empty={min_non_empty})"
            );
            ensure!(
                load_avg_secs_per_block <= max_avg_secs_per_block,
                "average block interval during load exceeded {max_avg_secs_per_block:.3}s: load_avg_secs_per_block={load_avg_secs_per_block:.3}, load_end_produced_blocks={load_end_produced_blocks}, load_elapsed={load_end_elapsed:?}"
            );
            ensure!(
                min_approved >= target_approved,
                "not all submitted transactions were approved: min_approved={min_approved}, target_approved={target_approved}, submitted={}",
                submitted_counter.load(AtomicOrdering::Relaxed)
            );
            ensure!(
                max_rejected == 0,
                "transactions were rejected during realistic localnet run: max_rejected={max_rejected}"
            );
            {
                    verify_realistic_transfer_balances(
                        &network.client(),
                        &transfer_asset_definition_id,
                        &transfer_load_accounts,
                        total_txs,
                        transfer_initial_balance,
                        transfer_max_amount,
                        rng_seed,
                    )
                    .wrap_err("realistic transfer balances did not match submitted random graph")?;
                }
            Ok(())
        }
        .await;
        if let Err(err) = &run_result {
            artifacts.error = Some(err.to_string());
        }
        if let Some(artifact_root) = std::env::var_os("IROHA_THROUGHPUT_ARTIFACT_DIR") {
            let root = PathBuf::from(artifact_root);
            let peer_logs: Vec<PeerLogInfo> = network
                .peers()
                .iter()
                .enumerate()
                .map(|(index, peer)| PeerLogInfo {
                    index: index as u64,
                    mnemonic: peer.mnemonic().to_string(),
                    stdout_log: peer
                        .latest_stdout_log_path()
                        .map(|path| path.to_string_lossy().to_string()),
                    stderr_log: peer
                        .latest_stderr_log_path()
                        .map(|path| path.to_string_lossy().to_string()),
                })
                .collect();
            if let Err(err) =
                write_throughput_artifacts(&root, &network_dir, &peer_logs, &artifacts)
            {
                eprintln!("throughput artifact write failed: {err:?}");
            }
        }
        network.shutdown().await;
        run_result
    }
    .await;
    if let Some(previous_ttl) = previous_ttl {
        set_env_var("IROHA_TEST_CLIENT_TTL_MS", previous_ttl);
    } else {
        remove_env_var("IROHA_TEST_CLIENT_TTL_MS");
    }
    if sandbox::handle_result(result, test_name)?.is_none() {
        return Ok(());
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permissioned_localnet_produces_blocks_within_bound() -> Result<()> {
    idle_chain::run_permissioned_progress().await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permissioned_idle_chain_advances_only_for_external_or_internal_work() -> Result<()> {
    idle_chain::run().await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sumeragi_status_json_endpoint_decodes_to_wire_end_to_end() -> Result<()> {
    init_instruction_registry();
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let builder = multiroute::network_builder();
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(sumeragi_status_json_endpoint_decodes_to_wire_end_to_end),
    )
    .await?
    else {
        ensure!(
            !fail_on_sandbox_skip(),
            "sandbox denied localnet startup and {} is enabled",
            FAIL_ON_SANDBOX_SKIP_ENV
        );
        return Ok(());
    };
    let result: Result<()> = async {
        wait_for_status_responses(&network, Duration::from_secs(30)).await?;
        let bootstrap_key = multiroute::universal_route_key_pair();
        let bootstrap_account = AccountId::new(bootstrap_key.public_key().clone());
        // Genesis-created lanes activate after G applies H3. Funded universal
        // work crosses that boundary before either private account route is used.
        for height in 2..=3 {
            let client = network.peers()[0]
                .client_for(&bootstrap_account, bootstrap_key.private_key().clone());
            read_on_dedicated_thread(move || {
                client.submit::<InstructionBox>(
                    Log::new(
                        Level::INFO,
                        format!("status endpoint bootstrap tick {height}"),
                    )
                    .into(),
                    route_probe_fee(),
                )
            })
            .await?;
        }
        let warmup_statuses =
            wait_for_height_quorum_with_bounded_lag(&network, 3, Duration::from_secs(45)).await?;
        let peer = network
            .peers()
            .first()
            .cloned()
            .ok_or_else(|| eyre!("network started without peers"))?;
        let before_height = quorum_low_watermark_height(
            &warmup_statuses,
            tolerated_lagging_peers(network.peers().len()),
        );
        let alice_client = peer.client_for(&ALICE_ID, ALICE_KEYPAIR.private_key().clone());
        let bob_client = peer.client_for(&BOB_ID, BOB_KEYPAIR.private_key().clone());
        let alice_probe_submitted = submit_route_probe_with_retry(
            &alice_client,
            "cross-lane route probe alice",
            ROUTE_BINDING_TIMEOUT,
            "submit cross-lane route probe from alice",
        )
        .await?;
        let bob_probe_submitted = submit_route_probe_with_retry(
            &bob_client,
            "cross-lane route probe bob",
            ROUTE_BINDING_TIMEOUT,
            "submit cross-lane route probe from bob",
        )
        .await?;
        ensure!(
            alice_probe_submitted && bob_probe_submitted,
            "both signed native account routes must execute successfully"
        );
        wait_for_height_quorum_with_bounded_lag(
            &network,
            before_height.saturating_add(1),
            Duration::from_secs(45),
        )
        .await?;
        let status_client = peer.client();
        let payload =
            read_on_dedicated_thread(move || status_client.client().get_sumeragi_status_json())
                .await
                .wrap_err("fetch and decode operator-signed Sumeragi status JSON payload")?;
        let status: iroha_data_model::sumeragi::SumeragiStatus =
            norito::json::from_value(payload).wrap_err("decode the current native status DTO")?;
        ensure!(
            status.protocol_version == iroha_data_model::sumeragi::PROTOCOL_VERSION,
            "status must report the first-release native protocol"
        );
        ensure!(
            status.committed_height >= 2,
            "status lost the observed committed height"
        );
        ensure!(
            status.applied_height <= status.committed_height,
            "status reports application beyond native commitment"
        );
        ensure!(
            status.instance != [0; 32],
            "native status has an empty instance identity"
        );
        network.shutdown().await;
        Ok(())
    }
    .await;
    if sandbox::handle_result(
        result,
        stringify!(sumeragi_status_json_endpoint_decodes_to_wire_end_to_end),
    )?
    .is_none()
    {
        ensure!(
            !fail_on_sandbox_skip(),
            "sandboxed skip surfaced in result handling and {} is enabled",
            FAIL_ON_SANDBOX_SKIP_ENV
        );
        return Ok(());
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn permissioned_localnet_reaches_100_blocks() -> Result<()> {
    init_instruction_registry();
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let previous_ttl = std::env::var_os("IROHA_TEST_CLIENT_TTL_MS");
    set_env_var(
        "IROHA_TEST_CLIENT_TTL_MS",
        SOAK_CLIENT_TTL.as_millis().to_string(),
    );
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_real_genesis_keypair()
        .with_block_cadence(SMOKE_PIPELINE_TIME)
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(1_u64)),
        )))
        .with_permissioned_consensus()
        .with_config_layer(|layer| {
            layer
                .write(["network", "transaction_gossip_period_ms"], 200_i64)
                .write(["network", "transaction_gossip_public_target_cap"], 3_i64)
                .write(
                    ["network", "transaction_gossip_restricted_target_cap"],
                    3_i64,
                )
                .write(["network", "p2p_post_queue_cap"], 8192_i64)
                .write(["network", "p2p_queue_cap_high"], 16384_i64)
                .write(["network", "p2p_queue_cap_low"], 65536_i64)
                .write(["network", "disconnect_on_post_overflow"], false);
        });
    let result: Result<()> = async {
        let Some(network) = sandbox::start_network_async_or_skip(
            builder,
            stringify!(permissioned_localnet_reaches_100_blocks),
        )
        .await?
        else {
            return Ok(());
        };
        wait_for_status_responses(&network, Duration::from_secs(30)).await?;
        let baseline_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
        let baseline_height = baseline_statuses
            .iter()
            .map(|status| status.blocks)
            .min()
            .unwrap_or_default();
        let warmup_height = baseline_height.saturating_add(1);
        for peer in network.peers() {
            let message = format!("localnet warmup block {}", peer.mnemonic());
            peer.client()
                .submit::<InstructionBox>(Log::new(Level::INFO, message).into(), iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None))
                .wrap_err_with(|| {
                    format!("failed to submit warmup log instruction to {}", peer.mnemonic())
                })?;
        }
        wait_for_converged_height(&network, warmup_height, Duration::from_secs(45)).await?;
        let warmup_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
        let baseline_height = warmup_statuses
            .iter()
            .map(|status| status.blocks)
            .min()
            .unwrap_or_default();
        let target_blocks = if cfg!(debug_assertions) { 30_u64 } else { 100_u64 };
        let target_height = baseline_height.saturating_add(target_blocks);
        let peers = network.peers();
        ensure!(!peers.is_empty(), "network must have at least one peer");
        let peer_count = peers.len();
        let sequence_key = Name::from_str("tx_sequence").expect("tx_sequence metadata key");
        let debug_multiplier = if cfg!(debug_assertions) { 3 } else { 1 };
        let timeout = scale_duration(
            scale_duration(network.block_cadence(), target_blocks.saturating_mul(3))
                .saturating_add(Duration::from_secs(30)),
            debug_multiplier,
        );
        let per_block_timeout = scale_duration(
            scale_duration(network.block_cadence(), 8).saturating_add(Duration::from_secs(4)),
            debug_multiplier,
        );
        let start = Instant::now();
        let mut next_height = baseline_height;
        for idx in 0..target_blocks {
            let peer = &peers[usize::try_from(idx).unwrap_or(0) % peer_count];
            let message = format!("localnet block {idx} via {}", peer.mnemonic());
            let mut metadata = Metadata::default();
            metadata.insert(sequence_key.clone(), idx.saturating_add(1));
            peer.client()
                .submit_with_metadata::<InstructionBox>(
                    Log::new(Level::INFO, message).into(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                    metadata,
                )
                .wrap_err_with(|| {
                    format!(
                        "failed to submit log instruction {idx} to {}",
                        peer.mnemonic()
                    )
                })?;
            next_height = next_height.saturating_add(1);
            let remaining = timeout.saturating_sub(start.elapsed());
            let block_timeout = if remaining < per_block_timeout {
                remaining
            } else {
                per_block_timeout
            };
            let deadline = Instant::now() + block_timeout;
            let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
            let mut last_log = Instant::now()
                .checked_sub(STATUS_LOG_INTERVAL)
                .unwrap_or_else(Instant::now);
            loop {
                match collect_statuses(&network, STATUS_POLL_TIMEOUT).await {
                    Ok(statuses) => {
                        let snapshot: Vec<StatusSnapshot> =
                            statuses.iter().map(StatusSnapshot::from_status).collect();
                        if snapshot != last_snapshot || last_log.elapsed() >= STATUS_LOG_INTERVAL {
                            eprintln!(
                                "localnet status snapshot (target_height={next_height}): {snapshot:?}"
                            );
                            last_log = Instant::now();
                        }
                        last_snapshot = snapshot;
                        let max_height = statuses
                            .iter()
                            .map(|status| status.blocks)
                            .max()
                            .unwrap_or_default();
                        if max_height >= next_height {
                            break;
                        }
                        if Instant::now() >= deadline {
                            return Err(eyre!(
                                "height failed to reach {next_height} within {:?}: last_snapshot={last_snapshot:?}",
                                block_timeout
                            ));
                        }
                    }
                    Err(err) => {
                        if Instant::now() >= deadline {
                            return Err(eyre!(
                                "height failed to reach {next_height} within {:?}: last_snapshot={last_snapshot:?}, last_error={err:?}",
                                block_timeout
                            ));
                        }
                    }
                }
                sleep(Duration::from_millis(200)).await;
            }
        }
        let remaining = timeout.saturating_sub(start.elapsed());
        let catch_up_timeout = per_block_timeout.min(remaining);
        if catch_up_timeout > Duration::ZERO {
            let deadline = Instant::now() + catch_up_timeout;
            let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
            let mut last_log = Instant::now()
                .checked_sub(STATUS_LOG_INTERVAL)
                .unwrap_or_else(Instant::now);
            loop {
                match collect_statuses(&network, STATUS_POLL_TIMEOUT).await {
                    Ok(statuses) => {
                        let snapshot: Vec<StatusSnapshot> =
                            statuses.iter().map(StatusSnapshot::from_status).collect();
                        if snapshot != last_snapshot || last_log.elapsed() >= STATUS_LOG_INTERVAL {
                            eprintln!(
                                "localnet catch-up snapshot (target_height={target_height}): {snapshot:?}"
                            );
                            last_log = Instant::now();
                        }
                        last_snapshot = snapshot;
                        if statuses
                            .iter()
                            .all(|status| status.blocks >= target_height)
                        {
                            break;
                        }
                        if Instant::now() >= deadline {
                            return Err(eyre!(
                                "peers failed to catch up to {target_height} within {:?}: last_snapshot={last_snapshot:?}",
                                catch_up_timeout
                            ));
                        }
                    }
                    Err(err) => {
                        if Instant::now() >= deadline {
                            return Err(eyre!(
                                "peers failed to catch up to {target_height} within {:?}: last_snapshot={last_snapshot:?}, last_error={err:?}",
                                catch_up_timeout
                            ));
                        }
                    }
                }
                sleep(Duration::from_millis(200)).await;
            }
        }
        let elapsed = start.elapsed();
        ensure!(
            elapsed <= timeout,
            "block production exceeded bound: elapsed={:?}",
            elapsed
        );
        let after_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
        ensure!(
            after_statuses
                .iter()
                .all(|status| status.blocks >= target_height),
            "not all peers reached target height {target_height}: {after_statuses:?}"
        );
        network.shutdown().await;
        Ok(())
    }
    .await;
    if let Some(previous_ttl) = previous_ttl {
        set_env_var("IROHA_TEST_CLIENT_TTL_MS", previous_ttl);
    } else {
        remove_env_var("IROHA_TEST_CLIENT_TTL_MS");
    }
    if sandbox::handle_result(result, stringify!(permissioned_localnet_reaches_100_blocks))?
        .is_none()
    {
        return Ok(());
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running localnet soak (thousands of blocks/tx)"]
#[allow(clippy::too_many_lines)]
async fn permissioned_localnet_soak_thousands() -> Result<()> {
    init_instruction_registry();
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let soak_block_cadence_ms =
        env_or_default("IROHA_SOAK_BLOCK_CADENCE_MS", SOAK_BLOCK_CADENCE_MS);
    let soak_max_secs_per_block = env_or_default_f64("IROHA_SOAK_MAX_SEC_PER_BLOCK", 1.0);
    let previous_ttl = std::env::var_os("IROHA_TEST_CLIENT_TTL_MS");
    // Extend TTL so early transactions do not expire during the soak run.
    set_env_var(
        "IROHA_TEST_CLIENT_TTL_MS",
        SOAK_CLIENT_TTL.as_millis().to_string(),
    );
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_real_genesis_keypair()
        .with_block_cadence(Duration::from_millis(soak_block_cadence_ms))
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(1_u64)),
        )))
        .with_permissioned_consensus()
        .with_config_layer(|layer| {
            layer
                .write(["logger", "level"], "WARN")
                .write(["telemetry_profile"], "full")
                .write(["network", "transaction_gossip_period_ms"], 20_i64)
                .write(["network", "transaction_gossip_public_target_cap"], 8_i64)
                .write(
                    ["network", "transaction_gossip_restricted_target_cap"],
                    8_i64,
                )
                .write(["network", "p2p_post_queue_cap"], 8192_i64)
                .write(["network", "p2p_queue_cap_high"], 16384_i64)
                .write(["network", "p2p_queue_cap_low"], 65536_i64)
                .write(["network", "disconnect_on_post_overflow"], false);
        });
    let result: Result<()> = async {
        let Some(network) = sandbox::start_network_async_or_skip(
            builder,
            stringify!(permissioned_localnet_soak_thousands),
        )
        .await?
        else {
            return Ok(());
        };
        eprintln!("localnet soak signed block cadence: {soak_block_cadence_ms} ms");
        wait_for_status_responses(&network, Duration::from_secs(30)).await?;
        let baseline_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
        let baseline_non_empty = baseline_statuses
            .iter()
            .map(|status| status.blocks_non_empty)
            .min()
            .unwrap_or_default();
        let soak_start = Instant::now();
        // Allow shorter local runs via IROHA_SOAK_TARGET_BLOCKS while keeping the default.
        let target_blocks = env_or_default("IROHA_SOAK_TARGET_BLOCKS", SOAK_TARGET_BLOCKS);
        let submit_batch = env_or_default("IROHA_SOAK_SUBMIT_BATCH", SOAK_SUBMIT_BATCH);
        let queue_soft_limit =
            env_or_default("IROHA_SOAK_QUEUE_SOFT_LIMIT", SOAK_QUEUE_SOFT_LIMIT);
        let target_height = baseline_non_empty.saturating_add(target_blocks);
        let submit_peer = network
            .peers()
            .first()
            .cloned()
            .ok_or_else(|| eyre!("network must have at least one peer"))?;
        let client = submit_peer.client();
        for idx in 0..target_blocks {
            client
                .submit::<InstructionBox>(
                    Log::new(Level::INFO, format!("localnet soak {idx}")).into(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .wrap_err_with(|| format!("failed to submit log instruction {idx}"))?;
            if (idx + 1) % submit_batch == 0 {
                wait_for_queue_depth(&network, queue_soft_limit, SOAK_STATUS_POLL_TIMEOUT).await?;
            }
        }
        let mut last_progress = Instant::now();
        let mut last_min_non_empty = baseline_non_empty;
        let mut last_log = Instant::now()
            .checked_sub(SOAK_PROGRESS_LOG_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
        loop {
            if let Ok(statuses) = collect_statuses(&network, SOAK_STATUS_POLL_TIMEOUT).await {
                let min_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .min()
                    .unwrap_or_default();
                let max_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .max()
                    .unwrap_or_default();
                if min_non_empty > last_min_non_empty {
                    last_min_non_empty = min_non_empty;
                    last_progress = Instant::now();
                }
                last_snapshot = statuses
                    .iter()
                    .map(StatusSnapshot::from_status)
                    .collect();
                if last_log.elapsed() >= SOAK_PROGRESS_LOG_INTERVAL {
                    eprintln!(
                        "localnet soak progress (target_non_empty={target_height}, min_non_empty={min_non_empty}, max_non_empty={max_non_empty}): {last_snapshot:?}"
                    );
                    last_log = Instant::now();
                }
                if statuses
                    .iter()
                    .all(|status| status.blocks_non_empty >= target_height)
                {
                    break;
                }
            }
            if last_progress.elapsed() >= SOAK_STALL_THRESHOLD {
                return Err(eyre!(
                    "localnet soak stalled for {:?} (min_non_empty={last_min_non_empty}, target_non_empty={target_height}): last_snapshot={last_snapshot:?}",
                    SOAK_STALL_THRESHOLD,
                ));
            }
            sleep(SOAK_STATUS_POLL_INTERVAL).await;
        }
        let after_statuses = collect_statuses(&network, SOAK_STATUS_POLL_TIMEOUT).await?;
        ensure!(
            after_statuses
                .iter()
                .all(|status| status.blocks_non_empty >= target_height),
            "not all peers reached target non-empty height {target_height}: {after_statuses:?}"
        );
        let elapsed = soak_start.elapsed();
        let secs_per_block = if target_blocks == 0 {
            0.0
        } else {
            elapsed.as_secs_f64() / target_blocks as f64
        };
        eprintln!(
            "localnet soak summary: target_blocks={}, elapsed={:?}, secs_per_block={:.3}",
            target_blocks, elapsed, secs_per_block
        );
        ensure!(
            secs_per_block <= soak_max_secs_per_block,
            "localnet soak too slow: secs_per_block={secs_per_block:.3}, target<={soak_max_secs_per_block:.3}"
        );
        network.shutdown().await;
        Ok(())
    }
    .await;
    if let Some(previous_ttl) = previous_ttl {
        set_env_var("IROHA_TEST_CLIENT_TTL_MS", previous_ttl);
    } else {
        remove_env_var("IROHA_TEST_CLIENT_TTL_MS");
    }
    if sandbox::handle_result(result, stringify!(permissioned_localnet_soak_thousands))?.is_none() {
        return Ok(());
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running 7-peer localnet throughput regression (10k tps target)"]
#[allow(clippy::too_many_lines)]
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
async fn permissioned_localnet_throughput_10k_tps() -> Result<()> {
    init_instruction_registry();
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let previous_ttl = std::env::var_os("IROHA_TEST_CLIENT_TTL_MS");
    set_env_var(
        "IROHA_TEST_CLIENT_TTL_MS",
        THROUGHPUT_CLIENT_TTL.as_millis().to_string(),
    );
    let builder = NetworkBuilder::new()
        .with_peers(7)
        .with_auto_populated_trusted_peers()
        .with_real_genesis_keypair()
        .with_block_cadence(THROUGHPUT_PIPELINE_TIME)
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(THROUGHPUT_BLOCK_MAX_TXS)),
        )))
        .with_permissioned_consensus()
        .with_config_layer(|layer| {
            let _ = layer
                .write(["network", "transaction_gossip_period_ms"], 200_i64)
                .write(["network", "transaction_gossip_public_target_cap"], 3_i64)
                .write(
                    ["network", "transaction_gossip_restricted_target_cap"],
                    3_i64,
                )
                .write(["network", "p2p_post_queue_cap"], 8192_i64)
                .write(["network", "p2p_queue_cap_high"], 16384_i64)
                .write(["network", "p2p_queue_cap_low"], 65536_i64)
                .write(["network", "disconnect_on_post_overflow"], false)
                // Keep the generated-load run focused on consensus/network stability. The
                // default Nexus lane TEU cap is sized for live economic scheduling, not
                // synthetic 10k-log blocks.
                .write(["nexus", "fusion", "floor_teu"], THROUGHPUT_LANE_TEU_FLOOR)
                .write(
                    ["nexus", "fusion", "exit_teu"],
                    THROUGHPUT_LANE_TEU_CAPACITY,
                )
                // Lift Torii limits for sustained local throughput runs.
                .write(
                    ["torii", "preauth_allow_cidrs"],
                    TomlValue::Array(vec![
                        TomlValue::String("127.0.0.0/8".into()),
                        TomlValue::String("::1/128".into()),
                    ]),
                )
                .write(
                    ["torii", "api_rate_limit_bypass_cidrs"],
                    TomlValue::Array(vec![
                        TomlValue::String("127.0.0.0/8".into()),
                        TomlValue::String("::1/128".into()),
                    ]),
                )
                .write(["torii", "preauth_rate_per_ip_per_sec"], 1_000_000_i64)
                .write(["torii", "preauth_burst_per_ip"], 2_000_000_i64)
                .write(["torii", "query_rate_per_authority_per_sec"], 0_i64)
                .write(["torii", "query_burst_per_authority"], 0_i64)
                .write(["torii", "tx_rate_per_authority_per_sec"], 0_i64)
                .write(["torii", "tx_burst_per_authority"], 0_i64)
                .write(["torii", "api_high_load_tx_threshold"], 262_144_i64);
        });
    let result: Result<()> = async {
        let Some(network) = sandbox::start_network_async_or_skip(
            builder,
            stringify!(permissioned_localnet_throughput_10k_tps),
        )
        .await?
        else {
            return Ok(());
        };
        let network_dir = network.env_dir().to_path_buf();
        let http = HttpClient::new();
        let mut artifacts = ThroughputArtifacts::default();
        let run_result: Result<()> = async {
        wait_for_status_responses(&network, Duration::from_secs(30)).await?;
        let baseline_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
        let baseline_non_empty = baseline_statuses
            .iter()
            .map(|status| status.blocks_non_empty)
            .min()
            .unwrap_or_default();
        let baseline_approved = baseline_statuses
            .iter()
            .map(|status| status.txs_approved)
            .min()
            .unwrap_or_default();
        let total_blocks_default = THROUGHPUT_WARMUP_BLOCKS.saturating_add(THROUGHPUT_STEADY_BLOCKS);
        let total_blocks =
            env_or_default("IROHA_THROUGHPUT_TARGET_BLOCKS", total_blocks_default).max(1);
        let warmup_blocks = env_or_default(
            "IROHA_THROUGHPUT_WARMUP_BLOCKS",
            THROUGHPUT_WARMUP_BLOCKS,
        )
        .min(total_blocks.saturating_sub(1).max(1));
        let steady_blocks_default = total_blocks.saturating_sub(warmup_blocks).max(1);
        let steady_blocks = env_or_default(
            "IROHA_THROUGHPUT_STEADY_BLOCKS",
            steady_blocks_default,
        )
        .max(1);
        let total_blocks = warmup_blocks.saturating_add(steady_blocks);
        let submit_batch =
            env_or_default("IROHA_THROUGHPUT_SUBMIT_BATCH", THROUGHPUT_SUBMIT_BATCH).max(1);
        let submit_parallelism =
            env_or_default("IROHA_THROUGHPUT_PARALLELISM", THROUGHPUT_SUBMIT_PARALLELISM)
                .max(1)
                .min(submit_batch);
        let submit_parallelism = usize::try_from(submit_parallelism)
            .wrap_err("submit parallelism exceeds host limits")?;
        let queue_soft_limit = env_or_default(
            "IROHA_THROUGHPUT_QUEUE_SOFT_LIMIT",
            THROUGHPUT_QUEUE_SOFT_LIMIT,
        );
        let payload_bytes = env_or_default_usize(
            "IROHA_THROUGHPUT_PAYLOAD_BYTES",
            THROUGHPUT_PAYLOAD_BYTES,
        )
        .max(32);
        let rng_seed = env_or_default("IROHA_THROUGHPUT_RNG_SEED", THROUGHPUT_RNG_SEED);
        let warmup_target_height = baseline_non_empty.saturating_add(warmup_blocks);
        let steady_target_height = warmup_target_height.saturating_add(steady_blocks);
        let warmup_txs = warmup_blocks.saturating_mul(THROUGHPUT_BLOCK_MAX_TXS);
        let steady_txs = steady_blocks.saturating_mul(THROUGHPUT_BLOCK_MAX_TXS);
        let total_txs = warmup_txs.saturating_add(steady_txs);
        artifacts.recipe = Some(ThroughputArtifactRecipe {
            peers: network.peers().len() as u64,
            block_cadence_ms: THROUGHPUT_BLOCK_CADENCE_MS,
            block_max_txs: THROUGHPUT_BLOCK_MAX_TXS,
            warmup_blocks,
            steady_blocks,
            total_blocks,
            warmup_txs,
            steady_txs,
            total_txs,
            submit_batch,
            submit_parallelism: submit_parallelism as u64,
            queue_soft_limit,
            payload_bytes: payload_bytes as u64,
            load_kind: "log".to_owned(),
            transfer_accounts: 0,
            transfer_initial_balance: 0,
            transfer_max_amount: 0,

            rng_seed,
            snapshot_mode: "disabled".to_owned(),
            snapshot_create_every_ms: 0,
        });
        let slo_p95_ms = env_or_default("IROHA_THROUGHPUT_SLO_P95_MS", THROUGHPUT_SLO_P95_MS);
        let slo_p99_ms = env_or_default("IROHA_THROUGHPUT_SLO_P99_MS", THROUGHPUT_SLO_P99_MS);
        let slo_view_change_rate = env_or_default_f64(
            "IROHA_THROUGHPUT_SLO_VIEW_CHANGE_RATE",
            THROUGHPUT_SLO_VIEW_CHANGE_RATE_MAX,
        );
        let slo_queue_saturation = env_or_default_f64(
            "IROHA_THROUGHPUT_SLO_QUEUE_SAT_FRAC",
            THROUGHPUT_SLO_QUEUE_SAT_FRAC_MAX,
        );
        artifacts.slo = Some(ThroughputArtifactSlo {
            commit_p95_ms: slo_p95_ms,
            commit_p99_ms: slo_p99_ms,
            view_change_rate_max: slo_view_change_rate,
            queue_saturation_max: slo_queue_saturation,
        });
        let submit_clients: Vec<_> =
            network.peers().iter().map(|peer| peer.client()).collect();
        ensure!(
            !submit_clients.is_empty(),
            "network must have at least one peer"
        );
        eprintln!(
            "localnet throughput recipe: peers={}, signed_block_cadence_ms={}, block_max_txs={}, warmup_blocks={}, steady_blocks={}, total_blocks={}, payload_bytes={}, submit_batch={}, submit_parallelism={}, queue_soft_limit={}, rng_seed={}, baseline_non_empty={}, baseline_approved={}",
            network.peers().len(),
            THROUGHPUT_BLOCK_CADENCE_MS,
            THROUGHPUT_BLOCK_MAX_TXS,
            warmup_blocks,
            steady_blocks,
            total_blocks,
            payload_bytes,
            submit_batch,
            submit_parallelism,
            queue_soft_limit,
            rng_seed,
            baseline_non_empty,
            baseline_approved,
        );
        let warmup_submit_elapsed = submit_logs(
            0,
            warmup_txs,
            &network,
            &submit_clients,
            submit_batch,
            submit_parallelism,
            queue_soft_limit,
            payload_bytes,
            rng_seed,
        )
        .await?;
        let mut last_progress = Instant::now();
        let mut last_min_non_empty = baseline_non_empty;
        let mut last_log = Instant::now()
            .checked_sub(THROUGHPUT_PROGRESS_LOG_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
        loop {
            if let Ok(statuses) = collect_statuses(&network, SOAK_STATUS_POLL_TIMEOUT).await {
                let min_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .min()
                    .unwrap_or_default();
                let max_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .max()
                    .unwrap_or_default();
                if min_non_empty > last_min_non_empty {
                    last_min_non_empty = min_non_empty;
                    last_progress = Instant::now();
                }
                last_snapshot = statuses
                    .iter()
                    .map(StatusSnapshot::from_status)
                    .collect();
                if last_log.elapsed() >= THROUGHPUT_PROGRESS_LOG_INTERVAL {
                    eprintln!(
                        "localnet throughput warmup progress (target_non_empty={warmup_target_height}, min_non_empty={min_non_empty}, max_non_empty={max_non_empty}): {last_snapshot:?}"
                    );
                    last_log = Instant::now();
                }
                if statuses
                    .iter()
                    .all(|status| status.blocks_non_empty >= warmup_target_height)
                {
                    break;
                }
            }
            if last_progress.elapsed() >= THROUGHPUT_STALL_THRESHOLD {
                return Err(eyre!(
                    "localnet throughput warmup stalled for {:?} (min_non_empty={last_min_non_empty}, target_non_empty={warmup_target_height}): last_snapshot={last_snapshot:?}",
                    THROUGHPUT_STALL_THRESHOLD
                ));
            }
            sleep(SOAK_STATUS_POLL_INTERVAL).await;
        }
        let warmup_metrics =
            collect_metrics_snapshots(&network, &http, THROUGHPUT_METRICS_TIMEOUT).await?;
        let steady_start_statuses = collect_statuses(&network, SOAK_STATUS_POLL_TIMEOUT).await?;
        let steady_start_approved = steady_start_statuses
            .iter()
            .map(|status| status.txs_approved)
            .min()
            .unwrap_or(baseline_approved);
        let steady_start = Instant::now();
        let steady_submit_elapsed = submit_logs(
            warmup_txs,
            steady_txs,
            &network,
            &submit_clients,
            submit_batch,
            submit_parallelism,
            queue_soft_limit,
            payload_bytes,
            rng_seed,
        )
        .await?;
        let mut samples: Vec<ThroughputSample> = Vec::new();
        let mut last_progress = Instant::now();
        let mut last_min_non_empty = warmup_target_height;
        let mut last_log = Instant::now()
            .checked_sub(THROUGHPUT_PROGRESS_LOG_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
        loop {
            if let Ok(statuses) = collect_statuses(&network, SOAK_STATUS_POLL_TIMEOUT).await {
                let sumeragi_statuses =
                    collect_sumeragi_statuses(&network, SOAK_STATUS_POLL_TIMEOUT).await?;
                let min_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .min()
                    .unwrap_or_default();
                let max_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .max()
                    .unwrap_or_default();
                if min_non_empty > last_min_non_empty {
                    last_min_non_empty = min_non_empty;
                    last_progress = Instant::now();
                }
                let status_snapshots: Vec<StatusSnapshot> = statuses
                    .iter()
                    .map(StatusSnapshot::from_status)
                    .collect();
                let sumeragi_snapshots: Vec<SumeragiStatusSnapshot> = sumeragi_statuses
                    .iter()
                    .map(SumeragiStatusSnapshot::from_status)
                    .collect();
                let timestamp_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                samples.push(ThroughputSample {
                    phase: None,
                    timestamp_ms: u64::try_from(timestamp_ms).unwrap_or(u64::MAX),
                    statuses: status_snapshots.clone(),
                    sumeragi: sumeragi_snapshots,
                });
                last_snapshot = status_snapshots;
                if last_log.elapsed() >= THROUGHPUT_PROGRESS_LOG_INTERVAL {
                    eprintln!(
                        "localnet throughput steady progress (target_non_empty={steady_target_height}, min_non_empty={min_non_empty}, max_non_empty={max_non_empty}): {last_snapshot:?}"
                    );
                    last_log = Instant::now();
                }
                if statuses
                    .iter()
                    .all(|status| status.blocks_non_empty >= steady_target_height)
                {
                    break;
                }
            }
            if last_progress.elapsed() >= THROUGHPUT_STALL_THRESHOLD {
                return Err(eyre!(
                    "localnet throughput stalled for {:?} (min_non_empty={last_min_non_empty}, target_non_empty={steady_target_height}): last_snapshot={last_snapshot:?}",
                    THROUGHPUT_STALL_THRESHOLD
                ));
            }
            sleep(THROUGHPUT_SAMPLE_INTERVAL).await;
        }
        let steady_elapsed = steady_start.elapsed();
        let after_statuses = collect_statuses(&network, SOAK_STATUS_POLL_TIMEOUT).await?;
        let after_metrics =
            collect_metrics_snapshots(&network, &http, THROUGHPUT_METRICS_TIMEOUT).await?;
        ensure!(
            after_statuses
                .iter()
                .all(|status| status.blocks_non_empty >= steady_target_height),
            "not all peers reached target non-empty height {steady_target_height}: {after_statuses:?}"
        );
        let max_commit_time_ms = after_statuses
            .iter()
            .map(|status| status.commit_time_ms)
            .max()
            .unwrap_or_default();
        let max_commit_time_allowed = THROUGHPUT_COMMIT_SLO_BASE_MS
            .saturating_mul(THROUGHPUT_COMMIT_TIME_MAX_MULTIPLIER);
        let mut min_commit_time_ms = u64::MAX;
        let mut sum_commit_time_ms = 0_u128;
        for status in &after_statuses {
            let value = status.commit_time_ms;
            min_commit_time_ms = min_commit_time_ms.min(value);
            sum_commit_time_ms = sum_commit_time_ms.saturating_add(u128::from(value));
        }
        let avg_commit_time_ms = if after_statuses.is_empty() {
            0_u64
        } else {
            (sum_commit_time_ms / u128::from(after_statuses.len() as u64)) as u64
        };
        let min_commit_time_ms = if min_commit_time_ms == u64::MAX {
            0_u64
        } else {
            min_commit_time_ms
        };
        let (commit_p95_ms, commit_p99_ms, commit_hist_count) =
            commit_time_quantiles(&warmup_metrics, &after_metrics);
        let commit_p95_ms = commit_p95_ms.unwrap_or_default();
        let commit_p99_ms = commit_p99_ms.unwrap_or_default();
        let committed_approved = after_statuses
            .iter()
            .map(|status| status.txs_approved)
            .min()
            .unwrap_or(steady_start_approved)
            .saturating_sub(steady_start_approved);
        let committed_tps = if steady_elapsed.as_secs_f64() > 0.0 {
            committed_approved as f64 / steady_elapsed.as_secs_f64()
        } else {
            0.0
        };
        let submitted_tps = if steady_submit_elapsed.as_secs_f64() > 0.0 {
            steady_txs as f64 / steady_submit_elapsed.as_secs_f64()
        } else {
            0.0
        };
        let (view_change_avg, view_change_max) = rate_summary(
            steady_start_statuses
                .iter()
                .map(|status| u64::from(status.view_changes))
                .collect::<Vec<u64>>()
                .as_slice(),
            after_statuses
                .iter()
                .map(|status| u64::from(status.view_changes))
                .collect::<Vec<u64>>()
                .as_slice(),
            steady_elapsed,
        );
        let mut saturated_samples = 0_u64;
        let mut total_samples = 0_u64;
        let mut max_queue_depth = 0_u64;
        for sample in &samples {
            for status in &sample.sumeragi {
                total_samples = total_samples.saturating_add(1);
                if status.tx_queue_saturated {
                    saturated_samples = saturated_samples.saturating_add(1);
                }
                max_queue_depth = max_queue_depth.max(status.tx_queue_depth);
            }
        }
        let queue_saturated_frac = if total_samples > 0 {
            saturated_samples as f64 / total_samples as f64
        } else {
            0.0
        };
        let metrics = ThroughputArtifactMetrics {
            submitted_tps,
            committed_tps,
            commit_p95_ms,
            commit_p99_ms,
            commit_hist_count,
            commit_time_ms_min: min_commit_time_ms,
            commit_time_ms_avg: avg_commit_time_ms,
            commit_time_ms_max: max_commit_time_ms,
            view_change_rate_avg: view_change_avg,
            view_change_rate_max: view_change_max,
            queue_saturated_frac,
            max_queue_depth,
            steady_elapsed_ms: steady_elapsed.as_millis() as u64,
            warmup_submit_elapsed_ms: warmup_submit_elapsed.as_millis() as u64,
            steady_submit_elapsed_ms: steady_submit_elapsed.as_millis() as u64,
        };
        artifacts.metrics = Some(metrics);
        artifacts.samples = samples;
        artifacts.warmup_metrics = warmup_metrics;
        artifacts.after_metrics = after_metrics;
        eprintln!(
            "localnet throughput metrics: peers={}, warmup_blocks={}, steady_blocks={}, warmup_txs={}, steady_txs={}, submit_batch={}, submit_parallelism={}, queue_soft_limit={}, payload_bytes={}, warmup_submit_elapsed={:?}, steady_submit_elapsed={:?}, steady_elapsed={:?}, submitted_tps={:.2}, committed_tps={:.2}, commit_hist_count={}, commit_time_ms(min/avg/max/p95/p99)={}/{}/{}/{}/{}, view_change_rate(avg/max)={:.4}/{:.4}, queue_saturated_frac={:.2}, max_queue_depth={}",
            network.peers().len(),
            warmup_blocks,
            steady_blocks,
            warmup_txs,
            steady_txs,
            submit_batch,
            submit_parallelism,
            queue_soft_limit,
            payload_bytes,
            warmup_submit_elapsed,
            steady_submit_elapsed,
            steady_elapsed,
            submitted_tps,
            committed_tps,
            commit_hist_count,
            min_commit_time_ms,
            avg_commit_time_ms,
            max_commit_time_ms,
            commit_p95_ms,
            commit_p99_ms,
            view_change_avg,
            view_change_max,
            queue_saturated_frac,
            max_queue_depth,
        );
        ensure!(
            max_commit_time_ms <= max_commit_time_allowed,
            "commit time exceeded target: max_commit_time_ms={max_commit_time_ms}, allowed={max_commit_time_allowed}",
        );
        if commit_hist_count > 0 {
            ensure!(
                commit_p95_ms <= slo_p95_ms,
                "p95 commit time exceeded SLO: p95_ms={commit_p95_ms}, slo_p95_ms={slo_p95_ms}",
            );
            ensure!(
                commit_p99_ms <= slo_p99_ms,
                "p99 commit time exceeded SLO: p99_ms={commit_p99_ms}, slo_p99_ms={slo_p99_ms}",
            );
        }
        if slo_view_change_rate > 0.0 {
            ensure!(
                view_change_max <= slo_view_change_rate,
                "view change rate exceeded SLO: max_rate={view_change_max:.4}, slo_rate={slo_view_change_rate:.4}",
            );
        }
        if slo_queue_saturation > 0.0 {
            ensure!(
                queue_saturated_frac <= slo_queue_saturation,
                "queue saturation exceeded SLO: fraction={queue_saturated_frac:.2}, slo={slo_queue_saturation:.2}",
            );
        }
        Ok(())
    }
    .await;
        if let Err(err) = &run_result {
            artifacts.error = Some(err.to_string());
        }
        if let Some(artifact_root) = std::env::var_os("IROHA_THROUGHPUT_ARTIFACT_DIR") {
            let root = PathBuf::from(artifact_root);
            let peer_logs: Vec<PeerLogInfo> = network
                .peers()
                .iter()
                .enumerate()
                .map(|(index, peer)| PeerLogInfo {
                    index: index as u64,
                    mnemonic: peer.mnemonic().to_string(),
                    stdout_log: peer
                        .latest_stdout_log_path()
                        .map(|path| path.to_string_lossy().to_string()),
                    stderr_log: peer
                        .latest_stderr_log_path()
                        .map(|path| path.to_string_lossy().to_string()),
                })
                .collect();
            if let Err(err) =
                write_throughput_artifacts(&root, &network_dir, &peer_logs, &artifacts)
            {
                eprintln!("throughput artifact write failed: {err:?}");
            }
        }
        network.shutdown().await;
        run_result
    }
    .await;
    if let Some(previous_ttl) = previous_ttl {
        set_env_var("IROHA_TEST_CLIENT_TTL_MS", previous_ttl);
    } else {
        remove_env_var("IROHA_TEST_CLIENT_TTL_MS");
    }
    if sandbox::handle_result(result, stringify!(permissioned_localnet_throughput_10k_tps))?
        .is_none()
    {
        return Ok(());
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running 7-peer localnet throughput regression (10k tps target, NPoS)"]
#[allow(clippy::too_many_lines)]
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
async fn npos_localnet_throughput_10k_tps() -> Result<()> {
    init_instruction_registry();
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let previous_ttl = std::env::var_os("IROHA_TEST_CLIENT_TTL_MS");
    set_env_var(
        "IROHA_TEST_CLIENT_TTL_MS",
        THROUGHPUT_CLIENT_TTL.as_millis().to_string(),
    );
    let npos_params = SumeragiNposParameters::default();
    let builder = NetworkBuilder::new()
        .with_peers(7)
        .with_auto_populated_trusted_peers()
        .with_real_genesis_keypair()
        .with_block_cadence(THROUGHPUT_PIPELINE_TIME)
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(THROUGHPUT_BLOCK_MAX_TXS)),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos_params.into_custom_parameter(),
        )))
        .with_npos_consensus()
        .with_config_layer(|layer| {
            layer
                .write(["network", "transaction_gossip_period_ms"], 200_i64)
                .write(["network", "transaction_gossip_public_target_cap"], 3_i64)
                .write(
                    ["network", "transaction_gossip_restricted_target_cap"],
                    3_i64,
                )
                .write(["network", "p2p_post_queue_cap"], 8192_i64)
                .write(["network", "p2p_queue_cap_high"], 16384_i64)
                .write(["network", "p2p_queue_cap_low"], 65536_i64)
                .write(["network", "disconnect_on_post_overflow"], false)
                // Keep the generated-load run focused on consensus/network stability. The
                // default Nexus lane TEU cap is sized for live economic scheduling, not
                // synthetic 10k-log blocks.
                .write(["nexus", "fusion", "floor_teu"], THROUGHPUT_LANE_TEU_FLOOR)
                .write(
                    ["nexus", "fusion", "exit_teu"],
                    THROUGHPUT_LANE_TEU_CAPACITY,
                )
                // Lift Torii limits for sustained local throughput runs.
                .write(
                    ["torii", "preauth_allow_cidrs"],
                    TomlValue::Array(vec![
                        TomlValue::String("127.0.0.0/8".into()),
                        TomlValue::String("::1/128".into()),
                    ]),
                )
                .write(
                    ["torii", "api_rate_limit_bypass_cidrs"],
                    TomlValue::Array(vec![
                        TomlValue::String("127.0.0.0/8".into()),
                        TomlValue::String("::1/128".into()),
                    ]),
                )
                .write(["torii", "preauth_rate_per_ip_per_sec"], 1_000_000_i64)
                .write(["torii", "preauth_burst_per_ip"], 2_000_000_i64)
                .write(["torii", "query_rate_per_authority_per_sec"], 0_i64)
                .write(["torii", "query_burst_per_authority"], 0_i64)
                .write(["torii", "tx_rate_per_authority_per_sec"], 0_i64)
                .write(["torii", "tx_burst_per_authority"], 0_i64)
                .write(["torii", "api_high_load_tx_threshold"], 262_144_i64);
        });
    let result: Result<()> = async {
        let Some(network) = sandbox::start_network_async_or_skip(
            builder,
            stringify!(npos_localnet_throughput_10k_tps),
        )
        .await?
        else {
            return Ok(());
        };
        let network_dir = network.env_dir().to_path_buf();
        let http = HttpClient::new();
        let mut artifacts = ThroughputArtifacts::default();
        let run_result: Result<()> = async {
        wait_for_status_responses(&network, Duration::from_secs(30)).await?;
        let baseline_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
        let baseline_non_empty = baseline_statuses
            .iter()
            .map(|status| status.blocks_non_empty)
            .min()
            .unwrap_or_default();
        let baseline_approved = baseline_statuses
            .iter()
            .map(|status| status.txs_approved)
            .min()
            .unwrap_or_default();
        let total_blocks_default =
            THROUGHPUT_WARMUP_BLOCKS.saturating_add(THROUGHPUT_STEADY_BLOCKS);
        let total_blocks =
            env_or_default("IROHA_THROUGHPUT_TARGET_BLOCKS", total_blocks_default).max(1);
        let warmup_blocks = env_or_default(
            "IROHA_THROUGHPUT_WARMUP_BLOCKS",
            THROUGHPUT_WARMUP_BLOCKS,
        )
        .min(total_blocks.saturating_sub(1).max(1));
        let steady_blocks_default = total_blocks.saturating_sub(warmup_blocks).max(1);
        let steady_blocks = env_or_default("IROHA_THROUGHPUT_STEADY_BLOCKS", steady_blocks_default)
            .max(1);
        let total_blocks = warmup_blocks.saturating_add(steady_blocks);
        let submit_batch =
            env_or_default("IROHA_THROUGHPUT_SUBMIT_BATCH", THROUGHPUT_SUBMIT_BATCH).max(1);
        let submit_parallelism =
            env_or_default("IROHA_THROUGHPUT_PARALLELISM", THROUGHPUT_SUBMIT_PARALLELISM)
                .max(1)
                .min(submit_batch);
        let submit_parallelism = usize::try_from(submit_parallelism)
            .wrap_err("submit parallelism exceeds host limits")?;
        let queue_soft_limit = env_or_default(
            "IROHA_THROUGHPUT_QUEUE_SOFT_LIMIT",
            THROUGHPUT_QUEUE_SOFT_LIMIT,
        );
        let payload_bytes = env_or_default_usize(
            "IROHA_THROUGHPUT_PAYLOAD_BYTES",
            THROUGHPUT_PAYLOAD_BYTES,
        )
        .max(32);
        let rng_seed = env_or_default("IROHA_THROUGHPUT_RNG_SEED", THROUGHPUT_RNG_SEED);
        let warmup_target_height = baseline_non_empty.saturating_add(warmup_blocks);
        let steady_target_height = warmup_target_height.saturating_add(steady_blocks);
        let warmup_txs = warmup_blocks.saturating_mul(THROUGHPUT_BLOCK_MAX_TXS);
        let steady_txs = steady_blocks.saturating_mul(THROUGHPUT_BLOCK_MAX_TXS);
        let total_txs = warmup_txs.saturating_add(steady_txs);
        artifacts.recipe = Some(ThroughputArtifactRecipe {
            peers: network.peers().len() as u64,
            block_cadence_ms: THROUGHPUT_BLOCK_CADENCE_MS,
            block_max_txs: THROUGHPUT_BLOCK_MAX_TXS,
            warmup_blocks,
            steady_blocks,
            total_blocks,
            warmup_txs,
            steady_txs,
            total_txs,
            submit_batch,
            submit_parallelism: submit_parallelism as u64,
            queue_soft_limit,
            payload_bytes: payload_bytes as u64,
            load_kind: "log".to_owned(),
            transfer_accounts: 0,
            transfer_initial_balance: 0,
            transfer_max_amount: 0,

            rng_seed,
            snapshot_mode: "disabled".to_owned(),
            snapshot_create_every_ms: 0,
        });
        let slo_p95_ms =
            env_or_default("IROHA_THROUGHPUT_SLO_P95_MS", THROUGHPUT_NPOS_SLO_P95_MS);
        let slo_p99_ms =
            env_or_default("IROHA_THROUGHPUT_SLO_P99_MS", THROUGHPUT_NPOS_SLO_P99_MS);
        let slo_view_change_rate = env_or_default_f64(
            "IROHA_THROUGHPUT_SLO_VIEW_CHANGE_RATE",
            THROUGHPUT_NPOS_SLO_VIEW_CHANGE_RATE_MAX,
        );
        let slo_queue_saturation = env_or_default_f64(
            "IROHA_THROUGHPUT_SLO_QUEUE_SAT_FRAC",
            THROUGHPUT_NPOS_SLO_QUEUE_SAT_FRAC_MAX,
        );
        artifacts.slo = Some(ThroughputArtifactSlo {
            commit_p95_ms: slo_p95_ms,
            commit_p99_ms: slo_p99_ms,
            view_change_rate_max: slo_view_change_rate,
            queue_saturation_max: slo_queue_saturation,
        });
        let submit_clients: Vec<_> =
            network.peers().iter().map(|peer| peer.client()).collect();
        ensure!(
            !submit_clients.is_empty(),
            "network must have at least one peer"
        );
        eprintln!(
            "localnet throughput recipe: peers={}, signed_block_cadence_ms={}, block_max_txs={}, warmup_blocks={}, steady_blocks={}, total_blocks={}, payload_bytes={}, submit_batch={}, submit_parallelism={}, queue_soft_limit={}, rng_seed={}, baseline_non_empty={}, baseline_approved={}",
            network.peers().len(),
            THROUGHPUT_BLOCK_CADENCE_MS,
            THROUGHPUT_BLOCK_MAX_TXS,
            warmup_blocks,
            steady_blocks,
            total_blocks,
            payload_bytes,
            submit_batch,
            submit_parallelism,
            queue_soft_limit,
            rng_seed,
            baseline_non_empty,
            baseline_approved,
        );
        let warmup_submit_elapsed = submit_logs(
            0,
            warmup_txs,
            &network,
            &submit_clients,
            submit_batch,
            submit_parallelism,
            queue_soft_limit,
            payload_bytes,
            rng_seed,
        )
        .await?;
        let mut last_progress = Instant::now();
        let mut last_min_non_empty = baseline_non_empty;
        let mut last_log = Instant::now()
            .checked_sub(THROUGHPUT_PROGRESS_LOG_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
        loop {
            if let Ok(statuses) = collect_statuses(&network, SOAK_STATUS_POLL_TIMEOUT).await {
                let min_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .min()
                    .unwrap_or_default();
                let max_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .max()
                    .unwrap_or_default();
                last_snapshot = statuses
                    .iter()
                    .map(StatusSnapshot::from_status)
                    .collect();
                if min_non_empty >= warmup_target_height {
                    break;
                }
                if min_non_empty > last_min_non_empty {
                    last_min_non_empty = min_non_empty;
                    last_progress = Instant::now();
                }
                if last_log.elapsed() >= THROUGHPUT_PROGRESS_LOG_INTERVAL {
                    last_log = Instant::now();
                    eprintln!(
                        "localnet throughput warmup progress (target_non_empty={warmup_target_height}, min_non_empty={min_non_empty}, max_non_empty={max_non_empty}): {last_snapshot:?}"
                    );
                }
            }
            if last_progress.elapsed() >= THROUGHPUT_STALL_THRESHOLD {
                bail!(
                    "localnet throughput warmup stalled for {:?} (min_non_empty={last_min_non_empty}, target_non_empty={warmup_target_height}): last_snapshot={last_snapshot:?}",
                    THROUGHPUT_STALL_THRESHOLD
                );
            }
            sleep(THROUGHPUT_SAMPLE_INTERVAL).await;
        }
        let warmup_metrics =
            collect_metrics_snapshots(&network, &http, THROUGHPUT_METRICS_TIMEOUT).await?;
        let steady_start_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
        let steady_submit_elapsed = submit_logs(
            warmup_txs,
            steady_txs,
            &network,
            &submit_clients,
            submit_batch,
            submit_parallelism,
            queue_soft_limit,
            payload_bytes,
            rng_seed,
        )
        .await?;
        let steady_start = Instant::now();
        let mut samples: Vec<ThroughputSample> = Vec::new();
        let mut last_progress = Instant::now();
        let mut last_min_non_empty = warmup_target_height;
        let mut last_log = Instant::now()
            .checked_sub(THROUGHPUT_PROGRESS_LOG_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
        loop {
            if let Ok(statuses) = collect_statuses(&network, SOAK_STATUS_POLL_TIMEOUT).await {
                let min_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .min()
                    .unwrap_or_default();
                let max_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .max()
                    .unwrap_or_default();
                last_snapshot = statuses
                    .iter()
                    .map(StatusSnapshot::from_status)
                    .collect();
                if min_non_empty >= steady_target_height {
                    break;
                }
                if min_non_empty > last_min_non_empty {
                    last_min_non_empty = min_non_empty;
                    last_progress = Instant::now();
                }
                if last_log.elapsed() >= THROUGHPUT_PROGRESS_LOG_INTERVAL {
                    last_log = Instant::now();
                    eprintln!(
                        "localnet throughput steady progress (target_non_empty={steady_target_height}, min_non_empty={min_non_empty}, max_non_empty={max_non_empty}): {last_snapshot:?}"
                    );
                }
            }
            if last_progress.elapsed() >= THROUGHPUT_STALL_THRESHOLD {
                bail!(
                    "localnet throughput stalled for {:?} (min_non_empty={last_min_non_empty}, target_non_empty={steady_target_height}): last_snapshot={last_snapshot:?}",
                    THROUGHPUT_STALL_THRESHOLD
                );
            }
            let statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
            let sumeragi = collect_sumeragi_statuses(&network, STATUS_POLL_TIMEOUT).await?;
            let status_snapshots: Vec<StatusSnapshot> =
                statuses.iter().map(StatusSnapshot::from_status).collect();
            let sumeragi_snapshots: Vec<SumeragiStatusSnapshot> = sumeragi
                .iter()
                .map(SumeragiStatusSnapshot::from_status)
                .collect();
            let timestamp_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            samples.push(ThroughputSample {
                phase: None,
                timestamp_ms: u64::try_from(timestamp_ms).unwrap_or(u64::MAX),
                statuses: status_snapshots,
                sumeragi: sumeragi_snapshots,
            });
            sleep(THROUGHPUT_SAMPLE_INTERVAL).await;
        }
        let steady_elapsed = steady_start.elapsed();
        let after_statuses = collect_statuses(&network, STATUS_POLL_TIMEOUT).await?;
        let after_metrics =
            collect_metrics_snapshots(&network, &http, THROUGHPUT_METRICS_TIMEOUT).await?;
        let max_commit_time_ms = after_statuses
            .iter()
            .map(|status| status.commit_time_ms)
            .max()
            .unwrap_or_default();
        let max_commit_time_allowed = THROUGHPUT_COMMIT_SLO_BASE_MS
            .saturating_mul(THROUGHPUT_COMMIT_TIME_MAX_MULTIPLIER);
        let mut min_commit_time_ms = u64::MAX;
        let mut sum_commit_time_ms = 0_u128;
        for status in &after_statuses {
            let value = status.commit_time_ms;
            min_commit_time_ms = min_commit_time_ms.min(value);
            sum_commit_time_ms = sum_commit_time_ms.saturating_add(u128::from(value));
        }
        let avg_commit_time_ms = if after_statuses.is_empty() {
            0_u64
        } else {
            (sum_commit_time_ms / u128::from(after_statuses.len() as u64)) as u64
        };
        let min_commit_time_ms = if min_commit_time_ms == u64::MAX {
            0_u64
        } else {
            min_commit_time_ms
        };
        let (commit_p95_ms, commit_p99_ms, commit_hist_count) =
            commit_time_quantiles(&warmup_metrics, &after_metrics);
        let commit_p95_ms = commit_p95_ms.unwrap_or_default();
        let commit_p99_ms = commit_p99_ms.unwrap_or_default();
        let steady_approved = after_statuses
            .iter()
            .map(|status| status.txs_approved)
            .min()
            .unwrap_or_default()
            .saturating_sub(
                steady_start_statuses
                    .iter()
                    .map(|status| status.txs_approved)
                    .min()
                    .unwrap_or_default(),
            );
        let committed_approved = steady_approved.saturating_sub(baseline_approved);
        let committed_tps = if steady_elapsed.as_secs_f64() > 0.0 {
            committed_approved as f64 / steady_elapsed.as_secs_f64()
        } else {
            0.0
        };
        let submitted_tps = if steady_submit_elapsed.as_secs_f64() > 0.0 {
            steady_txs as f64 / steady_submit_elapsed.as_secs_f64()
        } else {
            0.0
        };
        let (view_change_avg, view_change_max) = rate_summary(
            steady_start_statuses
                .iter()
                .map(|status| u64::from(status.view_changes))
                .collect::<Vec<u64>>()
                .as_slice(),
            after_statuses
                .iter()
                .map(|status| u64::from(status.view_changes))
                .collect::<Vec<u64>>()
                .as_slice(),
            steady_elapsed,
        );
        let mut saturated_samples = 0_u64;
        let mut total_samples = 0_u64;
        let mut max_queue_depth = 0_u64;
        for sample in &samples {
            for status in &sample.sumeragi {
                total_samples = total_samples.saturating_add(1);
                if status.tx_queue_saturated {
                    saturated_samples = saturated_samples.saturating_add(1);
                }
                max_queue_depth = max_queue_depth.max(status.tx_queue_depth);
            }
        }
        let queue_saturated_frac = if total_samples > 0 {
            saturated_samples as f64 / total_samples as f64
        } else {
            0.0
        };
        let metrics = ThroughputArtifactMetrics {
            submitted_tps,
            committed_tps,
            commit_p95_ms,
            commit_p99_ms,
            commit_hist_count,
            commit_time_ms_min: min_commit_time_ms,
            commit_time_ms_avg: avg_commit_time_ms,
            commit_time_ms_max: max_commit_time_ms,
            view_change_rate_avg: view_change_avg,
            view_change_rate_max: view_change_max,
            queue_saturated_frac,
            max_queue_depth,
            steady_elapsed_ms: steady_elapsed.as_millis() as u64,
            warmup_submit_elapsed_ms: warmup_submit_elapsed.as_millis() as u64,
            steady_submit_elapsed_ms: steady_submit_elapsed.as_millis() as u64,
        };
        artifacts.metrics = Some(metrics);
        artifacts.samples = samples;
        artifacts.warmup_metrics = warmup_metrics;
        artifacts.after_metrics = after_metrics;
        eprintln!(
            "localnet throughput metrics: peers={}, warmup_blocks={}, steady_blocks={}, warmup_txs={}, steady_txs={}, submit_batch={}, submit_parallelism={}, queue_soft_limit={}, payload_bytes={}, warmup_submit_elapsed={:?}, steady_submit_elapsed={:?}, steady_elapsed={:?}, submitted_tps={:.2}, committed_tps={:.2}, commit_hist_count={}, commit_time_ms(min/avg/max/p95/p99)={}/{}/{}/{}/{}, view_change_rate(avg/max)={:.4}/{:.4}, queue_saturated_frac={:.2}, max_queue_depth={}",
            network.peers().len(),
            warmup_blocks,
            steady_blocks,
            warmup_txs,
            steady_txs,
            submit_batch,
            submit_parallelism,
            queue_soft_limit,
            payload_bytes,
            warmup_submit_elapsed,
            steady_submit_elapsed,
            steady_elapsed,
            submitted_tps,
            committed_tps,
            commit_hist_count,
            min_commit_time_ms,
            avg_commit_time_ms,
            max_commit_time_ms,
            commit_p95_ms,
            commit_p99_ms,
            view_change_avg,
            view_change_max,
            queue_saturated_frac,
            max_queue_depth,
        );
        ensure!(
            max_commit_time_ms <= max_commit_time_allowed,
            "commit time exceeded target: max_commit_time_ms={max_commit_time_ms}, allowed={max_commit_time_allowed}",
        );
        if commit_hist_count > 0 {
            ensure!(
                commit_p95_ms <= slo_p95_ms,
                "p95 commit time exceeded SLO: p95_ms={commit_p95_ms}, slo_p95_ms={slo_p95_ms}",
            );
            ensure!(
                commit_p99_ms <= slo_p99_ms,
                "p99 commit time exceeded SLO: p99_ms={commit_p99_ms}, slo_p99_ms={slo_p99_ms}",
            );
        }
        if slo_view_change_rate > 0.0 {
            ensure!(
                view_change_max <= slo_view_change_rate,
                "view change rate exceeded SLO: max_rate={view_change_max:.4}, slo_rate={slo_view_change_rate:.4}",
            );
        }
        if slo_queue_saturation > 0.0 {
            ensure!(
                queue_saturated_frac <= slo_queue_saturation,
                "queue saturation exceeded SLO: fraction={queue_saturated_frac:.2}, slo={slo_queue_saturation:.2}",
            );
        }
        Ok(())
    }
    .await;
        if let Err(err) = &run_result {
            artifacts.error = Some(err.to_string());
        }
        if let Some(artifact_root) = std::env::var_os("IROHA_THROUGHPUT_ARTIFACT_DIR") {
            let root = PathBuf::from(artifact_root);
            let peer_logs: Vec<PeerLogInfo> = network
                .peers()
                .iter()
                .enumerate()
                .map(|(index, peer)| PeerLogInfo {
                    index: index as u64,
                    mnemonic: peer.mnemonic().to_string(),
                    stdout_log: peer
                        .latest_stdout_log_path()
                        .map(|path| path.to_string_lossy().to_string()),
                    stderr_log: peer
                        .latest_stderr_log_path()
                        .map(|path| path.to_string_lossy().to_string()),
                })
                .collect();
            if let Err(err) =
                write_throughput_artifacts(&root, &network_dir, &peer_logs, &artifacts)
            {
                eprintln!("throughput artifact write failed: {err:?}");
            }
        }
        network.shutdown().await;
        run_result
    }
    .await;
    if let Some(previous_ttl) = previous_ttl {
        set_env_var("IROHA_TEST_CLIENT_TTL_MS", previous_ttl);
    } else {
        remove_env_var("IROHA_TEST_CLIENT_TTL_MS");
    }
    if sandbox::handle_result(result, stringify!(npos_localnet_throughput_10k_tps))?.is_none() {
        return Ok(());
    }
    Ok(())
}
async fn collect_statuses(
    network: &Network,
    status_timeout: Duration,
) -> Result<Vec<iroha_torii_shared::status::Status>> {
    try_join_all(network.peers().iter().map(|peer| async move {
        tokio::time::timeout(status_timeout, peer.status())
            .await
            .map_or_else(
                |_| {
                    eprintln!(
                        "status request timed out for peer {} after {:?} (best_effort={:?}, last_known_peers={:?}, stdout={:?})",
                        peer.mnemonic(),
                        status_timeout,
                        peer.best_effort_block_height(),
                        peer.last_known_peers(),
                        peer.latest_stdout_log_path()
                    );
                    Err(eyre!(
                        "status request timed out after {:?} for peer {}",
                        status_timeout,
                        peer.mnemonic()
                    ))
                },
                |result| {
                    result
                        .map_err(|err| {
                            eprintln!(
                                "status request failed for peer {}: {err:?} (best_effort={:?}, last_known_peers={:?}, stdout={:?})",
                                peer.mnemonic(),
                                peer.best_effort_block_height(),
                                peer.last_known_peers(),
                                peer.latest_stdout_log_path()
                            );
                            err
                        })
                        .wrap_err_with(|| format!("status request failed for peer {}", peer.mnemonic()))
                },
            )
    }))
    .await
}
async fn collect_realistic_statuses(
    network: &Network,
    status_timeout: Duration,
    tolerate_one_fault: bool,
) -> Result<Vec<iroha_torii_shared::status::Status>> {
    if tolerate_one_fault {
        collect_statuses_allowing_missing(network, status_timeout, 1).await
    } else {
        collect_statuses(network, status_timeout).await
    }
}
async fn collect_statuses_allowing_missing(
    network: &Network,
    status_timeout: Duration,
    max_missing: usize,
) -> Result<Vec<iroha_torii_shared::status::Status>> {
    let results = join_all(network.peers().iter().map(|peer| async move {
        tokio::time::timeout(status_timeout, peer.status())
            .await
            .map_or_else(
                |_| {
                    Err(eyre!(
                        "status request timed out after {:?} for peer {}",
                        status_timeout,
                        peer.mnemonic()
                    ))
                },
                |result| {
                    result.wrap_err_with(|| {
                        format!("status request failed for peer {}", peer.mnemonic())
                    })
                },
            )
            .map_err(|err| {
                eprintln!(
                    "tolerating realistic localnet status failure for peer {}: {err:?} (best_effort={:?}, stdout={:?})",
                    peer.mnemonic(),
                    peer.best_effort_block_height(),
                    peer.latest_stdout_log_path()
                );
                err
            })
    }))
    .await;
    let mut statuses = Vec::with_capacity(results.len());
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(status) => statuses.push(status),
            Err(err) => failures.push(err.to_string()),
        }
    }
    ensure!(
        !statuses.is_empty(),
        "all peer status requests failed while tolerating at most {max_missing} missing peers: {failures:?}"
    );
    ensure!(
        failures.len() <= max_missing,
        "too many peer status requests failed while tolerating at most {max_missing} missing peers: {failures:?}"
    );
    Ok(statuses)
}
async fn collect_sumeragi_statuses(
    network: &Network,
    status_timeout: Duration,
) -> Result<Vec<SumeragiDiagnosticsStatus>> {
    try_join_all(network.peers().iter().map(|peer| async move {
        let client = peer.client();
        let operator_key = client
            .client()
            .operator_key_pair()
            .cloned()
            .ok_or_else(|| eyre!("test-network client is missing its operator key"))?;
        let operator = client.client().operator_client(operator_key)?;
        if let Ok(response) = tokio::time::timeout(
            status_timeout, operator.consensus().diagnostics(),
        ).await {
            response
                .map_err(|err| {
                    eprintln!(
                        "sumeragi status request failed for peer {}: {err:?} (best_effort={:?}, stdout={:?})",
                        peer.mnemonic(),
                        peer.best_effort_block_height(),
                        peer.latest_stdout_log_path()
                    );
                    err
                })
                .wrap_err_with(|| format!("sumeragi status request failed for peer {}", peer.mnemonic()))
        } else {
            eprintln!(
                "sumeragi status request timed out for peer {} after {:?} (best_effort={:?}, stdout={:?})",
                peer.mnemonic(),
                status_timeout,
                peer.best_effort_block_height(),
                peer.latest_stdout_log_path()
            );
            Err(eyre!(
                "sumeragi status request timed out after {:?} for peer {}",
                status_timeout,
                peer.mnemonic()
            ))
        }
    }))
    .await
}
async fn collect_metrics_snapshots(
    network: &Network,
    http: &HttpClient,
    timeout: Duration,
) -> Result<Vec<PeerMetricsSnapshot>> {
    try_join_all(network.peers().iter().map(|peer| async move {
        let url = metrics_url(&peer.torii_url());
        let response = http
            .get(url.clone())
            .timeout(timeout)
            .send()
            .await
            .wrap_err_with(|| format!("metrics request failed for peer {}", peer.mnemonic()))?;
        let response = response.error_for_status().wrap_err_with(|| {
            format!(
                "metrics request returned error for peer {}",
                peer.mnemonic()
            )
        })?;
        let payload = response
            .text()
            .await
            .wrap_err_with(|| format!("metrics body decode failed for peer {}", peer.mnemonic()))?;
        let commit_time_hist = parse_prom_histogram(&payload, "commit_time_ms");
        Ok(PeerMetricsSnapshot {
            peer: peer.mnemonic().to_string(),
            payload,
            commit_time_hist,
        })
    }))
    .await
}
async fn wait_for_status_responses(network: &Network, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_log = Instant::now()
        .checked_sub(STATUS_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        match collect_statuses(network, STATUS_POLL_TIMEOUT).await {
            Ok(_) => return Ok(()),
            Err(err) => {
                if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "waiting for status responses (timeout={timeout:?}): last_error={err:?}"
                    );
                    last_log = Instant::now();
                }
                if Instant::now() >= deadline {
                    return Err(eyre!(
                        "status responses did not converge within {:?}; last_error={err:?}",
                        timeout,
                    ));
                }
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn wait_for_min_txs_approved(
    network: &Network,
    target_approved: u64,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_min_approved = 0;
    let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
    let mut last_log = Instant::now()
        .checked_sub(STATUS_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        match collect_statuses(network, STATUS_POLL_TIMEOUT).await {
            Ok(statuses) => {
                let min_approved = statuses
                    .iter()
                    .map(|status| status.txs_approved)
                    .min()
                    .unwrap_or_default();
                let snapshot: Vec<StatusSnapshot> =
                    statuses.iter().map(StatusSnapshot::from_status).collect();
                if min_approved > last_min_approved
                    || snapshot != last_snapshot
                    || last_log.elapsed() >= STATUS_LOG_INTERVAL
                {
                    eprintln!(
                        "waiting for approved transactions: min_approved={min_approved}, target_approved={target_approved}, snapshot={snapshot:?}"
                    );
                    last_min_approved = min_approved;
                    last_snapshot = snapshot;
                    last_log = Instant::now();
                }
                if min_approved >= target_approved {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(eyre!(
                        "approved transactions did not reach {target_approved} within {:?}: min_approved={min_approved}, last_snapshot={last_snapshot:?}",
                        timeout
                    ));
                }
            }
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(eyre!(
                        "approved transaction status did not converge within {:?}: target_approved={target_approved}, last_snapshot={last_snapshot:?}, last_error={err:?}",
                        timeout
                    ));
                }
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn wait_for_queue_depth(
    network: &Network,
    max_queue: u64,
    status_timeout: Duration,
) -> Result<()> {
    let progress_timeout = queue_progress_timeout();
    let mut last_progress = Instant::now();
    let mut last_queue: Option<u64> = None;
    let mut last_blocks_non_empty: Option<u64> = None;
    let mut last_log = Instant::now()
        .checked_sub(STATUS_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        match collect_statuses(network, status_timeout).await {
            Ok(statuses) => {
                let submitter_queue = statuses
                    .iter()
                    .map(|status| status.queue_size)
                    .max()
                    .unwrap_or_default();
                let min_non_empty = statuses
                    .iter()
                    .map(|status| status.blocks_non_empty)
                    .min()
                    .unwrap_or_default();
                if submitter_queue <= max_queue {
                    return Ok(());
                }
                let progressed = last_queue.is_some_and(|prev| submitter_queue < prev)
                    || last_blocks_non_empty.is_some_and(|prev| min_non_empty > prev);
                if progressed {
                    last_progress = Instant::now();
                }
                last_queue = Some(submitter_queue);
                last_blocks_non_empty = Some(min_non_empty);
                if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "waiting for submit queue to drain (queue_size={submitter_queue}, limit={max_queue}, min_non_empty={min_non_empty})"
                    );
                    last_log = Instant::now();
                }
            }
            Err(err) => {
                if last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!("waiting for submit queue to drain: status poll failed: {err:?}");
                    last_log = Instant::now();
                }
            }
        }
        if last_progress.elapsed() >= progress_timeout {
            return Err(eyre!(
                "submit queue did not drain below {max_queue} within {:?}",
                progress_timeout
            ));
        }
        sleep(SOAK_STATUS_POLL_INTERVAL).await;
    }
}
#[tokio::test]
async fn env_or_default_reads_positive_values() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let key = "IROHA_ENV_OR_DEFAULT_TEST";
    set_env_var(key, "42");
    assert_eq!(env_or_default(key, 7), 42);
    remove_env_var(key);
}
#[tokio::test]
async fn env_or_default_ignores_invalid_or_zero() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let key = "IROHA_ENV_OR_DEFAULT_TEST";
    set_env_var(key, "0");
    assert_eq!(env_or_default(key, 7), 7);
    set_env_var(key, "nope");
    assert_eq!(env_or_default(key, 7), 7);
    remove_env_var(key);
}
#[tokio::test]
async fn env_or_default_usize_reads_positive_values() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let key = "IROHA_ENV_OR_DEFAULT_USIZE_TEST";
    set_env_var(key, "64");
    assert_eq!(env_or_default_usize(key, 8), 64);
    remove_env_var(key);
}
#[tokio::test]
async fn env_or_default_f64_reads_values() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    let key = "IROHA_ENV_OR_DEFAULT_F64_TEST";
    set_env_var(key, "1.25");
    assert!((env_or_default_f64(key, 0.5) - 1.25).abs() < f64::EPSILON);
    set_env_var(key, "-1.0");
    assert!((env_or_default_f64(key, 0.5) - 0.5).abs() < f64::EPSILON);
    remove_env_var(key);
}
#[tokio::test]
async fn realistic_max_avg_secs_per_block_is_fault_aware_and_overridable() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    remove_env_var(REALISTIC_30TPS_MAX_AVG_SECS_PER_BLOCK_ENV);
    assert!(
        (realistic_max_avg_secs_per_block(false) - REALISTIC_30TPS_MAX_AVG_SECS_PER_BLOCK).abs()
            < f64::EPSILON
    );
    assert!(
        (realistic_max_avg_secs_per_block(true)
            - REALISTIC_30TPS_ROTATING_FAULT_MAX_AVG_SECS_PER_BLOCK)
            .abs()
            < f64::EPSILON
    );
    set_env_var(REALISTIC_30TPS_MAX_AVG_SECS_PER_BLOCK_ENV, "2.5");
    assert!((realistic_max_avg_secs_per_block(false) - 2.5).abs() < f64::EPSILON);
    assert!((realistic_max_avg_secs_per_block(true) - 2.5).abs() < f64::EPSILON);
    remove_env_var(REALISTIC_30TPS_MAX_AVG_SECS_PER_BLOCK_ENV);
}
#[tokio::test]
async fn queue_progress_timeout_reads_override() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    set_env_var(THROUGHPUT_QUEUE_PROGRESS_TIMEOUT_ENV, "12");
    assert_eq!(queue_progress_timeout(), Duration::from_secs(12));
    set_env_var(THROUGHPUT_QUEUE_PROGRESS_TIMEOUT_ENV, "0");
    assert_eq!(queue_progress_timeout(), SOAK_QUEUE_PROGRESS_TIMEOUT);
    remove_env_var(THROUGHPUT_QUEUE_PROGRESS_TIMEOUT_ENV);
}
#[tokio::test]
async fn fail_on_sandbox_skip_parses_truthy_values() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    set_env_var(FAIL_ON_SANDBOX_SKIP_ENV, "1");
    assert!(fail_on_sandbox_skip());
    set_env_var(FAIL_ON_SANDBOX_SKIP_ENV, "true");
    assert!(fail_on_sandbox_skip());
    set_env_var(FAIL_ON_SANDBOX_SKIP_ENV, "yes");
    assert!(fail_on_sandbox_skip());
    remove_env_var(FAIL_ON_SANDBOX_SKIP_ENV);
}
#[tokio::test]
async fn fail_on_sandbox_skip_defaults_to_false() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    remove_env_var(FAIL_ON_SANDBOX_SKIP_ENV);
    assert!(!fail_on_sandbox_skip());
    set_env_var(FAIL_ON_SANDBOX_SKIP_ENV, "0");
    assert!(!fail_on_sandbox_skip());
    set_env_var(FAIL_ON_SANDBOX_SKIP_ENV, "off");
    assert!(!fail_on_sandbox_skip());
    remove_env_var(FAIL_ON_SANDBOX_SKIP_ENV);
}
#[tokio::test]
async fn realistic_30tps_load_kind_rejects_encryption_and_defaults_to_transfer() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    remove_env_var("IROHA_REALISTIC_30TPS_LOAD_KIND");
    assert_eq!(
        Realistic30TpsLoadKind::from_env().expect("default load kind"),
        Realistic30TpsLoadKind::Transfer
    );
    for value in ["transfer", "transfers"] {
        set_env_var("IROHA_REALISTIC_30TPS_LOAD_KIND", value);
        assert_eq!(
            Realistic30TpsLoadKind::from_env().expect("transfer load"),
            Realistic30TpsLoadKind::Transfer
        );
    }
    for value in [
        "ram-lfe-email",
        "ram_lfe_email",
        "ram-lfe-emails",
        "ram_lfe_emails",
        "email",
        "emails",
    ] {
        set_env_var("IROHA_REALISTIC_30TPS_LOAD_KIND", value);
        assert!(
            Realistic30TpsLoadKind::from_env()
                .expect_err("encrypted load unavailable")
                .to_string()
                .starts_with("ram_lfe_encryption_unavailable:")
        );
    }
    set_env_var("IROHA_REALISTIC_30TPS_LOAD_KIND", "unsupported");
    assert!(Realistic30TpsLoadKind::from_env().is_err());
    remove_env_var("IROHA_REALISTIC_30TPS_LOAD_KIND");
}
#[tokio::test]
async fn realistic_30tps_rotating_fault_config_reads_rotate_interval_override() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    remove_env_var(REALISTIC_30TPS_RECOVERY_BOUND_SECS_ENV);
    remove_env_var(REALISTIC_30TPS_STRICT_ROTATION_CONVERGENCE_ENV);
    remove_env_var(REALISTIC_30TPS_CONVERGENCE_BOUND_SECS_ENV);
    set_env_var(REALISTIC_30TPS_OUTAGE_ROTATE_SECS_ENV, "7");
    assert_eq!(
        Realistic30TpsRotatingFaultConfig::from_env()
            .expect("rotating fault config")
            .rotate_interval,
        Duration::from_secs(7)
    );
    set_env_var(REALISTIC_30TPS_OUTAGE_ROTATE_SECS_ENV, "0");
    assert_eq!(
        Realistic30TpsRotatingFaultConfig::from_env()
            .expect("rotating fault config")
            .rotate_interval,
        Duration::from_secs(REALISTIC_30TPS_OUTAGE_ROTATE_SECS)
    );
    set_env_var(REALISTIC_30TPS_OUTAGE_RECOVERY_SECS_ENV, "240");
    assert_eq!(
        Realistic30TpsRotatingFaultConfig::from_env()
            .expect("rotating fault config")
            .recovery_timeout,
        Duration::from_secs(240)
    );
    set_env_var(REALISTIC_30TPS_OUTAGE_RECOVERY_SECS_ENV, "0");
    assert_eq!(
        Realistic30TpsRotatingFaultConfig::from_env()
            .expect("rotating fault config")
            .recovery_timeout,
        Duration::from_secs(REALISTIC_30TPS_OUTAGE_RECOVERY_SECS)
    );
    assert_eq!(
        Realistic30TpsRotatingFaultConfig::from_env()
            .expect("rotating fault config")
            .recovery_bound,
        None
    );
    assert!(
        !Realistic30TpsRotatingFaultConfig::from_env()
            .expect("rotating fault config")
            .requires_bounded_convergence()
    );
    set_env_var(REALISTIC_30TPS_RECOVERY_BOUND_SECS_ENV, "120");
    let config = Realistic30TpsRotatingFaultConfig::from_env().expect("rotating fault config");
    assert_eq!(config.recovery_bound, Some(Duration::from_secs(120)));
    assert_eq!(
        config.convergence_total_bound,
        Some(Duration::from_secs(120))
    );
    assert!(!config.requires_bounded_convergence());
    set_env_var(REALISTIC_30TPS_STRICT_ROTATION_CONVERGENCE_ENV, "true");
    let config = Realistic30TpsRotatingFaultConfig::from_env().expect("rotating fault config");
    assert!(config.strict_rotation_convergence);
    assert!(config.requires_bounded_convergence());
    assert_eq!(
        config.convergence_progress_timeout(),
        Duration::from_secs(REALISTIC_30TPS_CONVERGENCE_BOUND_SECS)
    );
    assert_eq!(
        config.convergence_total_bound(),
        Some(Duration::from_secs(120))
    );
    set_env_var(REALISTIC_30TPS_CONVERGENCE_BOUND_SECS_ENV, "30");
    assert_eq!(
        Realistic30TpsRotatingFaultConfig::from_env()
            .expect("rotating fault config")
            .convergence_total_bound(),
        Some(Duration::from_secs(30))
    );
    set_env_var(REALISTIC_30TPS_STRICT_ROTATION_CONVERGENCE_ENV, "maybe");
    assert!(Realistic30TpsRotatingFaultConfig::from_env().is_err());
    remove_env_var(REALISTIC_30TPS_OUTAGE_ROTATE_SECS_ENV);
    remove_env_var(REALISTIC_30TPS_OUTAGE_RECOVERY_SECS_ENV);
    remove_env_var(REALISTIC_30TPS_RECOVERY_BOUND_SECS_ENV);
    remove_env_var(REALISTIC_30TPS_STRICT_ROTATION_CONVERGENCE_ENV);
    remove_env_var(REALISTIC_30TPS_CONVERGENCE_BOUND_SECS_ENV);
}
#[tokio::test]
async fn realistic_30tps_rotating_fault_stall_threshold_covers_fault_windows() {
    let _guard = LOCALNET_SMOKE_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await;
    remove_env_var(REALISTIC_30TPS_STALL_SECS_ENV);
    let config = Realistic30TpsRotatingFaultConfig {
        rotate_interval: Duration::from_secs(60),
        recovery_timeout: Duration::from_secs(REALISTIC_30TPS_OUTAGE_RECOVERY_SECS),
        recovery_bound: None,
        strict_rotation_convergence: false,
        convergence_total_bound: None,
    };
    assert_eq!(
        realistic_30tps_stall_threshold(None),
        REALISTIC_30TPS_STALL_THRESHOLD
    );
    assert_eq!(
        realistic_30tps_stall_threshold(Some(&config)),
        Duration::from_secs(120)
    );
    set_env_var(REALISTIC_30TPS_STALL_SECS_ENV, "45");
    assert_eq!(
        realistic_30tps_stall_threshold(Some(&config)),
        Duration::from_secs(45)
    );
    set_env_var(REALISTIC_30TPS_STALL_SECS_ENV, "0");
    assert_eq!(
        realistic_30tps_stall_threshold(Some(&config)),
        Duration::from_secs(120)
    );
    remove_env_var(REALISTIC_30TPS_STALL_SECS_ENV);
}
#[test]
fn realistic_30tps_outage_rotation_cycles_peers_without_overlap() -> Result<()> {
    let windows = (0..6)
        .map(|idx| {
            Ok(Realistic30TpsFaultWindow {
                peer_index: realistic_30tps_peer_index_at(REALISTIC_30TPS_PEERS, idx)
                    .expect("peer sequence"),
                mnemonic: format!("peer{idx}"),
                fault: "process-outage",
                started_ms: u64::try_from(idx)? * 60_000,
                ended_ms: Some(u64::try_from(idx + 1)? * 60_000),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(
        windows
            .iter()
            .map(|window| window.peer_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 0, 1]
    );
    assert_eq!(
        windows
            .iter()
            .map(|window| window.fault)
            .collect::<Vec<_>>(),
        vec!["process-outage"; 6]
    );
    assert!(realistic_fault_windows_have_no_overlap(&windows));
    Ok(())
}
#[test]
fn realistic_default_block_max_txs_uses_larger_rotating_fault_batches() {
    assert_eq!(
        realistic_default_block_max_txs(false),
        REALISTIC_30TPS_BLOCK_MAX_TXS
    );
    assert_eq!(
        realistic_default_block_max_txs(true),
        REALISTIC_30TPS_ROTATING_FAULT_BLOCK_MAX_TXS
    );
    assert!(
        realistic_default_block_max_txs(true) > realistic_default_block_max_txs(false),
        "rotating fault soak needs enough per-block capacity to absorb one faulty validator"
    );
    assert_eq!(realistic_default_block_max_txs(true), 512);
}
#[test]
fn realistic_default_queue_soft_limit_is_fault_aware() {
    assert_eq!(
        realistic_default_queue_soft_limit(false),
        REALISTIC_30TPS_QUEUE_SOFT_LIMIT
    );
    assert_eq!(
        realistic_default_queue_soft_limit(true),
        REALISTIC_30TPS_ROTATING_FAULT_QUEUE_SOFT_LIMIT
    );
    assert!(
        realistic_default_queue_soft_limit(true) > realistic_default_queue_soft_limit(false),
        "rotating fault soak allows restart bursts without accepting unbounded backlog"
    );
}
#[test]
fn realistic_30tps_snapshot_settings_enable_read_write_for_rotating_faults() {
    assert_eq!(realistic_30tps_snapshot_settings(false), ("disabled", 0));
    assert_eq!(
        realistic_30tps_snapshot_settings(true),
        (
            REALISTIC_30TPS_ROTATING_FAULT_SNAPSHOT_MODE,
            REALISTIC_30TPS_ROTATING_FAULT_SNAPSHOT_CREATE_EVERY_MS
        )
    );
}
#[test]
fn realistic_30tps_catch_up_target_uses_leading_statuses() -> Result<()> {
    let target = realistic_30tps_catch_up_target_from_statuses(&[
        iroha_torii_shared::status::Status {
            blocks_non_empty: 7,
            txs_approved: 11,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 9,
            txs_approved: 10,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 8,
            txs_approved: 13,
            ..Default::default()
        },
    ])?;
    assert_eq!(
        target,
        Realistic30TpsCatchUpTarget {
            blocks_non_empty: 9,
            txs_approved: 13,
        }
    );
    assert!(realistic_30tps_catch_up_target_from_statuses(&[]).is_err());
    Ok(())
}
#[test]
fn realistic_30tps_catch_up_progress_tracks_block_or_transaction_advances() {
    let last_seen = Realistic30TpsCatchUpTarget {
        blocks_non_empty: 10,
        txs_approved: 100,
    };
    assert_eq!(
        realistic_30tps_catch_up_progress_since(
            &iroha_torii_shared::status::Status {
                blocks_non_empty: 10,
                txs_approved: 100,
                ..Default::default()
            },
            last_seen
        ),
        None
    );
    assert_eq!(
        realistic_30tps_catch_up_progress_since(
            &iroha_torii_shared::status::Status {
                blocks_non_empty: 11,
                txs_approved: 100,
                ..Default::default()
            },
            last_seen
        ),
        Some(Realistic30TpsCatchUpTarget {
            blocks_non_empty: 11,
            txs_approved: 100,
        })
    );
    assert_eq!(
        realistic_30tps_catch_up_progress_since(
            &iroha_torii_shared::status::Status {
                blocks_non_empty: 10,
                txs_approved: 101,
                ..Default::default()
            },
            last_seen
        ),
        Some(Realistic30TpsCatchUpTarget {
            blocks_non_empty: 10,
            txs_approved: 101,
        })
    );
    assert_eq!(
        realistic_30tps_catch_up_progress_since(
            &iroha_torii_shared::status::Status {
                blocks_non_empty: 12,
                txs_approved: 130,
                ..Default::default()
            },
            last_seen
        ),
        Some(Realistic30TpsCatchUpTarget {
            blocks_non_empty: 12,
            txs_approved: 130,
        })
    );
}
#[test]
fn realistic_30tps_strict_progress_target_uses_lagging_statuses() -> Result<()> {
    let target = realistic_30tps_strict_progress_target_from_statuses(&[
        iroha_torii_shared::status::Status {
            blocks_non_empty: 7,
            txs_approved: 11,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 9,
            txs_approved: 10,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 8,
            txs_approved: 13,
            ..Default::default()
        },
    ])?;
    assert_eq!(
        target,
        Realistic30TpsCatchUpTarget {
            blocks_non_empty: 7,
            txs_approved: 10,
        }
    );
    assert!(realistic_30tps_strict_progress_target_from_statuses(&[]).is_err());
    Ok(())
}
#[test]
fn realistic_30tps_strict_progress_requires_all_peers_to_advance() {
    let target = Realistic30TpsCatchUpTarget {
        blocks_non_empty: 10,
        txs_approved: 100,
    };
    let one_peer_still_at_baseline = [
        iroha_torii_shared::status::Status {
            blocks_non_empty: 10,
            txs_approved: 100,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 11,
            txs_approved: 120,
            ..Default::default()
        },
    ];
    assert!(!realistic_30tps_statuses_exceed_strict_progress_target(
        &one_peer_still_at_baseline,
        target
    ));
    let all_peers_approved_more = [
        iroha_torii_shared::status::Status {
            blocks_non_empty: 10,
            txs_approved: 101,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 11,
            txs_approved: 120,
            ..Default::default()
        },
    ];
    assert!(realistic_30tps_statuses_exceed_strict_progress_target(
        &all_peers_approved_more,
        target
    ));
    let all_peers_have_more_non_empty_blocks = [
        iroha_torii_shared::status::Status {
            blocks_non_empty: 11,
            txs_approved: 100,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 12,
            txs_approved: 100,
            ..Default::default()
        },
    ];
    assert!(realistic_30tps_statuses_exceed_strict_progress_target(
        &all_peers_have_more_non_empty_blocks,
        target
    ));
    assert!(!realistic_30tps_statuses_exceed_strict_progress_target(
        &[],
        target
    ));
}
#[test]
fn realistic_30tps_post_heal_progress_accepts_completed_target() {
    let target = Realistic30TpsCatchUpTarget {
        blocks_non_empty: 1379,
        txs_approved: 216_016,
    };
    let all_peers_at_final_target = [
        iroha_torii_shared::status::Status {
            blocks_non_empty: 1379,
            txs_approved: 216_016,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 1379,
            txs_approved: 216_016,
            ..Default::default()
        },
    ];
    assert!(!realistic_30tps_statuses_exceed_strict_progress_target(
        &all_peers_at_final_target,
        target
    ));
    assert!(realistic_30tps_statuses_satisfy_post_heal_progress(
        &all_peers_at_final_target,
        target,
        216_016
    ));
    let one_peer_before_final_target = [
        iroha_torii_shared::status::Status {
            blocks_non_empty: 1379,
            txs_approved: 216_016,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 1379,
            txs_approved: 216_015,
            ..Default::default()
        },
    ];
    assert!(!realistic_30tps_statuses_satisfy_post_heal_progress(
        &one_peer_before_final_target,
        target,
        216_016
    ));
}
#[test]
fn realistic_30tps_all_peer_convergence_rejects_deep_lag() -> Result<()> {
    let converged = [
        iroha_torii_shared::status::Status {
            blocks_non_empty: 42,
            txs_approved: 10_000,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 43,
            txs_approved: 10_300,
            ..Default::default()
        },
    ];
    assert!(realistic_30tps_statuses_are_converged(&converged)?);
    let lagging = [
        iroha_torii_shared::status::Status {
            blocks_non_empty: 42,
            txs_approved: 10_000,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks_non_empty: 47,
            txs_approved: 13_000,
            ..Default::default()
        },
    ];
    assert!(!realistic_30tps_statuses_are_converged(&lagging)?);
    assert!(realistic_30tps_statuses_are_converged(&[]).is_err());
    Ok(())
}
#[test]
fn realistic_30tps_convergence_progress_tracks_lagging_peer_catch_up() {
    let last_seen = Realistic30TpsConvergenceSpan {
        min_blocks_non_empty: 1_111,
        max_blocks_non_empty: 1_196,
        min_txs_approved: 163_597,
        max_txs_approved: 180_156,
    };
    let leading_peer_only_advanced = Realistic30TpsConvergenceSpan {
        min_blocks_non_empty: 1_111,
        max_blocks_non_empty: 1_197,
        min_txs_approved: 163_597,
        max_txs_approved: 180_668,
    };
    assert_eq!(
        realistic_30tps_convergence_progress_since(leading_peer_only_advanced, last_seen),
        None
    );
    let lagging_peer_advanced = Realistic30TpsConvergenceSpan {
        min_blocks_non_empty: 1_112,
        max_blocks_non_empty: 1_197,
        min_txs_approved: 163_700,
        max_txs_approved: 180_668,
    };
    assert_eq!(
        realistic_30tps_convergence_progress_since(lagging_peer_advanced, last_seen),
        Some(lagging_peer_advanced)
    );
    let block_gap_narrowed = Realistic30TpsConvergenceSpan {
        min_blocks_non_empty: 1_111,
        max_blocks_non_empty: 1_195,
        min_txs_approved: 163_597,
        max_txs_approved: 180_156,
    };
    assert_eq!(
        realistic_30tps_convergence_progress_since(block_gap_narrowed, last_seen),
        Some(block_gap_narrowed)
    );
    let approved_gap_narrowed = Realistic30TpsConvergenceSpan {
        min_blocks_non_empty: 1_111,
        max_blocks_non_empty: 1_196,
        min_txs_approved: 163_597,
        max_txs_approved: 179_900,
    };
    assert_eq!(
        realistic_30tps_convergence_progress_since(approved_gap_narrowed, last_seen),
        Some(approved_gap_narrowed)
    );
}
#[test]
fn realistic_fault_windows_detect_overlap() {
    let first = Realistic30TpsFaultWindow {
        peer_index: 0,
        mnemonic: "peer0".to_string(),
        fault: "conflicting-ready",
        started_ms: 10,
        ended_ms: Some(20),
    };
    let second = Realistic30TpsFaultWindow {
        peer_index: 1,
        mnemonic: "peer1".to_string(),
        fault: "duplicate-inits",
        started_ms: 20,
        ended_ms: Some(30),
    };
    assert!(realistic_fault_windows_have_no_overlap(&[
        second.clone(),
        first.clone(),
    ]));
    let overlapping = Realistic30TpsFaultWindow {
        started_ms: 19,
        ..second
    };
    assert!(!realistic_fault_windows_have_no_overlap(&[
        first,
        overlapping,
    ]));
}
#[test]
fn realistic_strict_fault_windows_require_convergence_before_next_fault() {
    let first = Realistic30TpsFaultWindow {
        peer_index: 0,
        mnemonic: "peer0".to_string(),
        fault: "conflicting-ready",
        started_ms: 10,
        ended_ms: Some(40),
    };
    let second = Realistic30TpsFaultWindow {
        peer_index: 1,
        mnemonic: "peer1".to_string(),
        fault: "duplicate-inits",
        started_ms: 75,
        ended_ms: Some(100),
    };
    let convergence = Realistic30TpsConvergenceWindow {
        healed_peer_index: 0,
        healed_fault: "conflicting-ready",
        started_ms: 40,
        ended_ms: 70,
        start_span: Some(Realistic30TpsConvergenceSpan {
            min_blocks_non_empty: 10,
            max_blocks_non_empty: 14,
            min_txs_approved: 1_000,
            max_txs_approved: 1_600,
        }),
        end_span: Realistic30TpsConvergenceSpan {
            min_blocks_non_empty: 14,
            max_blocks_non_empty: 15,
            min_txs_approved: 1_600,
            max_txs_approved: 1_700,
        },
    };
    assert!(realistic_strict_fault_windows_start_after_convergence(
        &[first.clone(), second.clone()],
        std::slice::from_ref(&convergence)
    ));
    let early_second = Realistic30TpsFaultWindow {
        started_ms: 69,
        ..second
    };
    assert!(!realistic_strict_fault_windows_start_after_convergence(
        &[first, early_second],
        &[convergence]
    ));
}
#[test]
fn realistic_status_recovery_summary_distinguishes_startup_bound_from_convergence() {
    let within = Realistic30TpsStatusRecoverySample {
        peer_index: 0,
        mnemonic: "peer0".to_string(),
        context: "heal rotating validator outage".to_string(),
        restart_started_ms: 10,
        status_wait_started_ms: 12,
        ended_ms: 72,
        bound_ms: 120,
        recovered: true,
        poll_attempts: 3,
        last_error: None,
        snapshot_before_shutdown: Realistic30TpsSnapshotObservation::default(),
        snapshot_after_shutdown: Realistic30TpsSnapshotObservation::default(),
        snapshot_after_status: Realistic30TpsSnapshotObservation::default(),
    };
    let outside = Realistic30TpsStatusRecoverySample {
        status_wait_started_ms: 100,
        ended_ms: 230,
        last_error: Some("connection refused".to_string()),
        ..within.clone()
    };
    assert_eq!(within.total_duration_ms(), 62);
    assert_eq!(within.status_wait_ms(), 60);
    assert!(within.recovered_within_bound());
    assert!(!outside.recovered_within_bound());
    let Value::Object(summary) = status_recovery_summary_value(&[within, outside]) else {
        panic!("expected status recovery summary object");
    };
    assert_eq!(summary.get("recoveries"), Some(&Value::from(2_u64)));
    assert_eq!(summary.get("failures"), Some(&Value::from(0_u64)));
    assert_eq!(summary.get("outside_bound"), Some(&Value::from(1_u64)));
    assert_eq!(
        summary.get("all_recovered_within_bound"),
        Some(&Value::from(false))
    );
}
#[test]
fn realistic_load_metadata_stamps_unique_sequence() {
    let sequence_key = Name::from_str("tx_sequence").expect("tx_sequence metadata key");
    let first = realistic_load_metadata(7);
    let second = realistic_load_metadata(8);
    assert_eq!(
        first.get(&sequence_key).map(ToString::to_string).as_deref(),
        Some("7")
    );
    assert_eq!(
        second
            .get(&sequence_key)
            .map(ToString::to_string)
            .as_deref(),
        Some("8")
    );
    assert_ne!(first, second);
}
#[test]
fn realistic_submit_retry_filter_only_matches_local_transport_errors() {
    assert!(realistic_submit_error_is_retryable_message(
        "Failed to send http GET request to http://127.0.0.1:40097/v1/node/capabilities: tcp connect error: Connection refused"
    ));
    assert!(realistic_submit_error_is_retryable_message(
        "connection reset by peer while reading /v1/node/capabilities"
    ));
    assert!(!realistic_submit_error_is_retryable_message(
        "transaction rejected: insufficient balance"
    ));
    assert!(!realistic_submit_error_is_retryable_message(
        "validation failed after transaction reached Torii"
    ));
}
#[test]
fn realistic_submit_already_known_filter_counts_queue_conflicts_as_accepts() {
    assert!(realistic_submit_error_is_already_known_message(
        "Unexpected transaction response: 409 Conflict already_enqueued"
    ));
    assert!(realistic_submit_error_is_already_known_message(
        "transaction already present in the queue"
    ));
    assert!(realistic_submit_error_is_already_known_message(
        "transaction already committed to the blockchain"
    ));
    assert!(!realistic_submit_error_is_already_known_message(
        "transaction rejected: insufficient balance"
    ));
}
#[test]
fn realistic_submit_accept_quorum_requires_one_more_than_tolerated_faults() {
    assert_eq!(realistic_submit_accept_quorum(4, 0), 1);
    assert_eq!(realistic_submit_accept_quorum(4, 1), 2);
    assert_eq!(realistic_submit_accept_quorum(4, 2), 3);
    assert_eq!(realistic_submit_accept_quorum(1, 1), 1);
}
#[test]
fn realistic_npos_fee_funding_instruction_chunks_target_fee_asset() {
    let accounts = realistic_transfer_accounts(3, 7);
    let chunks = realistic_npos_fee_funding_instruction_chunks(&accounts);
    let fee_asset_definition_id = route_fee_asset_definition_id();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].len(), accounts.len());
    for (instruction, account) in chunks[0].iter().zip(&accounts) {
        let Some(iroha::data_model::isi::MintBox::Asset(mint)) = instruction
            .as_any()
            .downcast_ref::<iroha::data_model::isi::MintBox>(
        ) else {
            panic!("expected asset mint instruction");
        };
        assert_eq!(
            mint.destination(),
            &AssetId::new(fee_asset_definition_id.clone(), account.id.clone())
        );
        assert_eq!(
            mint.object(),
            &Quantity::from(ROUTE_VALIDATOR_FEE_SEED_AMOUNT)
        );
    }
}
#[test]
fn diagnostic_identifier_receipt_preserves_signature_and_account_bindings() {
    let resolver = checked_localnet_smoke_keypair(
        b"integration_tests::realistic-ram-lfe-email-receipt-test".to_vec(),
        Algorithm::Ed25519,
    );
    // Synthetic metadata exercises typed signature bindings only; it is never
    // registered, submitted, or presented as successful encrypted execution.
    let program_id = realistic_ram_lfe_email_program_id();
    let context = DiagnosticIdentifierContext {
        policy_id: realistic_ram_lfe_email_policy_id(),
        program_id_bytes: norito::to_bytes(&program_id).expect("encode program id"),
        program_id,
        program_digest: Hash::new(b"diagnostic program"),
        parameter_digest: Hash::new(b"diagnostic parameters"),
        evaluation_key_digest: Hash::new(b"diagnostic evaluation key"),
        backend: RamLfeBackend::BfvProgrammedV1,
        verification_mode: RamLfeVerificationMode::Signed,
    };
    let account = diagnostic_identifier_accounts(1, 9).pop().expect("account");
    let receipt =
        diagnostic_identifier_receipt(&context, &resolver, &account.id, account.uaid, 7, 9);
    assert_ne!(
        receipt.payload.opening.payload.opened_output_hash,
        receipt.payload.execution.output_ciphertext_hash
    );
    receipt
        .verify(resolver.public_key())
        .expect("receipt signature should verify");
    assert_eq!(receipt.payload.policy_id, context.policy_id);
    assert_eq!(receipt.payload.account_id, account.id);
    assert_eq!(receipt.payload.uaid, account.uaid);
    assert!(receipt.phone_retail_canonicality.is_none());
    assert_eq!(
        receipt.payload.execution.associated_data_hash,
        Hash::new(&context.program_id_bytes)
    );
}
#[test]
fn localnet_smoke_fixture_keypairs_use_checked_seed_derivation() {
    let seed = b"integration_tests::sumeragi_localnet_smoke::checked-fixture".to_vec();
    let key_pair = checked_localnet_smoke_keypair(seed.clone(), Algorithm::Ed25519);
    let expected = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
        .expect("derive expected localnet smoke fixture key");
    assert_eq!(key_pair.public_key(), expected.public_key());
    assert!(
        KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
        "checked localnet smoke fixtures must reject invalid Ed25519 seed material"
    );
}
#[test]
fn realistic_ram_lfe_email_claim_counts_are_deterministic() {
    let first = diagnostic_identifier_route_counts(4, 25, 123);
    let second = diagnostic_identifier_route_counts(4, 25, 123);
    assert_eq!(first, second);
    assert_eq!(first.iter().sum::<usize>(), 25);
    assert_ne!(first, diagnostic_identifier_route_counts(4, 25, 124));
}
#[test]
fn write_throughput_artifacts_writes_error_summary() {
    let dir = tempdir().expect("tempdir");
    let artifact_root = dir.path().join("artifacts");
    let network_dir = dir.path().join("network");
    let artifacts = ThroughputArtifacts {
        error: Some("boom".to_string()),
        samples: vec![ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 7,
            statuses: Vec::new(),
            sumeragi: Vec::new(),
        }],
        ..ThroughputArtifacts::default()
    };
    let peer_logs = vec![PeerLogInfo {
        index: 0,
        mnemonic: "peer0".to_string(),
        stdout_log: None,
        stderr_log: None,
    }];
    let run_dir = write_throughput_artifacts(&artifact_root, &network_dir, &peer_logs, &artifacts)
        .expect("write artifacts");
    let summary_path = run_dir.join("summary.json");
    let summary_json = fs::read_to_string(&summary_path).expect("read summary");
    let Value::Object(map) =
        norito::json::from_json::<Value>(&summary_json).expect("parse summary")
    else {
        panic!("expected summary object");
    };
    assert_eq!(map.get("error"), Some(&Value::String("boom".to_string())));
    let samples_json =
        fs::read_to_string(run_dir.join("status_samples.json")).expect("read samples");
    let Value::Array(samples) =
        norito::json::from_json::<Value>(&samples_json).expect("parse samples")
    else {
        panic!("expected samples array");
    };
    let Some(Value::Object(sample)) = samples.first() else {
        panic!("expected first sample object");
    };
    assert_eq!(
        sample.get("phase"),
        Some(&Value::String("load".to_string()))
    );
}
#[test]
fn throughput_status_summary_uses_min_and_max_peer_values() {
    let statuses = vec![
        StatusSnapshot {
            blocks: 10,
            blocks_non_empty: 9,
            queue_size: 4,
            txs_approved: 90,
            txs_rejected: 0,
            view_changes: 0,
        },
        StatusSnapshot {
            blocks: 12,
            blocks_non_empty: 11,
            queue_size: 7,
            txs_approved: 100,
            txs_rejected: 2,
            view_changes: 0,
        },
    ];
    let summary = ThroughputStatusSummary::from_statuses(&statuses);
    assert_eq!(summary.min_blocks, 10);
    assert_eq!(summary.max_blocks, 12);
    assert_eq!(summary.min_blocks_non_empty, 9);
    assert_eq!(summary.max_blocks_non_empty, 11);
    assert_eq!(summary.min_txs_approved, 90);
    assert_eq!(summary.max_txs_rejected, 2);
    assert_eq!(summary.max_queue_size, 7);
}
#[test]
fn throughput_status_summary_can_ignore_one_lagging_peer_for_progress() {
    let statuses = vec![
        StatusSnapshot {
            blocks: 201,
            blocks_non_empty: 201,
            queue_size: 1_847,
            txs_approved: 48_193,
            ..StatusSnapshot::default()
        },
        StatusSnapshot {
            blocks: 208,
            blocks_non_empty: 208,
            queue_size: 517,
            txs_approved: 51_777,
            ..StatusSnapshot::default()
        },
        StatusSnapshot {
            blocks: 208,
            blocks_non_empty: 208,
            queue_size: 525,
            txs_approved: 51_777,
            txs_rejected: 1,
            ..StatusSnapshot::default()
        },
    ];
    let summary = ThroughputStatusSummary::from_statuses_tolerating_lagging(&statuses, 1);
    assert_eq!(summary.min_blocks, 208);
    assert_eq!(summary.min_blocks_non_empty, 208);
    assert_eq!(summary.min_txs_approved, 51_777);
    assert_eq!(summary.max_blocks_non_empty, 208);
    assert_eq!(summary.max_txs_rejected, 1);
    assert_eq!(summary.max_queue_size, 1_847);
}
#[test]
fn throughput_status_summary_uses_strict_min_without_lag_tolerance() {
    let statuses = vec![
        StatusSnapshot {
            blocks_non_empty: 7,
            txs_approved: 70,
            ..StatusSnapshot::default()
        },
        StatusSnapshot {
            blocks_non_empty: 9,
            txs_approved: 90,
            ..StatusSnapshot::default()
        },
    ];
    let summary = ThroughputStatusSummary::from_statuses_tolerating_lagging(&statuses, 0);
    assert_eq!(summary.min_blocks_non_empty, 7);
    assert_eq!(summary.min_txs_approved, 70);
}
#[test]
fn height_quorum_with_bounded_lag_accepts_one_block_tail_lag() {
    let statuses = [
        iroha_torii_shared::status::Status {
            blocks: 2,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 3,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 3,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 3,
            ..Default::default()
        },
    ];
    assert!(height_quorum_with_bounded_lag(&statuses, 3, 3));
}
#[test]
fn height_quorum_with_bounded_lag_accepts_tolerated_tail_lag() {
    let statuses = [
        iroha_torii_shared::status::Status {
            blocks: 1,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 3,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 4,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 4,
            ..Default::default()
        },
    ];
    assert!(height_quorum_with_bounded_lag(&statuses, 3, 3));
}
#[test]
fn height_quorum_with_bounded_lag_rejects_missing_quorum_or_split_quorum() {
    let missing_quorum = [
        iroha_torii_shared::status::Status {
            blocks: 2,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 2,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 3,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 3,
            ..Default::default()
        },
    ];
    assert!(!height_quorum_with_bounded_lag(&missing_quorum, 3, 3));
    let split_quorum = [
        iroha_torii_shared::status::Status {
            blocks: 1,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 3,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 3,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 5,
            ..Default::default()
        },
    ];
    assert!(!height_quorum_with_bounded_lag(&split_quorum, 3, 3));
    assert!(!height_quorum_with_bounded_lag(&[], 3, 3));
}
#[test]
fn quorum_low_watermark_height_ignores_tolerated_tail_lag() {
    let statuses = [
        iroha_torii_shared::status::Status {
            blocks: 1,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 2,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 2,
            ..Default::default()
        },
        iroha_torii_shared::status::Status {
            blocks: 2,
            ..Default::default()
        },
    ];
    assert_eq!(quorum_low_watermark_height(&statuses, 1), 2);
    assert_eq!(quorum_low_watermark_height(&statuses, 0), 1);
    assert_eq!(quorum_low_watermark_height(&[], 1), 0);
}
#[test]
fn realistic_artifact_summary_counts_load_samples_and_keeps_zero_block_rates_finite() {
    let load_end = ThroughputStatusSummary {
        min_txs_approved: 10,
        ..ThroughputStatusSummary::default()
    };
    let final_status = ThroughputStatusSummary {
        min_txs_approved: 25,
        ..ThroughputStatusSummary::default()
    };
    let samples = vec![
        ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 1,
            statuses: Vec::new(),
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("drain".to_string()),
            timestamp_ms: 2,
            statuses: Vec::new(),
            sumeragi: Vec::new(),
        },
    ];
    let summary = realistic_artifact_summary(
        0,
        10,
        5,
        30,
        15,
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(8),
        load_end,
        final_status,
        0,
        0,
        &samples,
    );
    assert_eq!(summary.load_sample_count, 1);
    assert_eq!(summary.drain_elapsed_ms, 3_000);
    assert_eq!(summary.load_avg_secs_per_block, 0.0);
    assert_eq!(summary.avg_secs_per_block, 0.0);
    assert!(summary.final_committed_tps.is_finite());
}
#[test]
fn realistic_target_blocks_cover_load_capacity() {
    assert_eq!(realistic_target_blocks(0, 216_000, 512), 422);
    assert_eq!(realistic_target_blocks(0, 36_000, 100), 360);
    assert_eq!(realistic_target_blocks(600, 36_000, 100), 600);
    assert_eq!(realistic_target_blocks(0, 36_001, 50), 721);
    assert_eq!(realistic_target_blocks(600, 36_000, 0), 600);
}
#[test]
fn realistic_target_blocks_handle_extreme_counters() {
    assert_eq!(realistic_target_blocks(0, u64::MAX, 1), u64::MAX);
    assert_eq!(realistic_target_blocks(0, u64::MAX, 2), 1u64 << 63);
    assert_eq!(realistic_target_blocks(u64::MAX, 1, 1), u64::MAX);
    assert_eq!(realistic_target_blocks(u64::MAX - 1, 1, 0), u64::MAX - 1);
}
#[test]
fn realistic_target_blocks_zero_transactions_never_inflates_default() {
    assert_eq!(realistic_target_blocks(0, 0, 100), 0);
    assert_eq!(realistic_target_blocks(7, 0, 100), 7);
    assert_eq!(realistic_target_blocks(7, 0, 0), 7);
}
#[test]
fn realistic_target_blocks_rounds_up_partial_capacity() {
    assert_eq!(realistic_target_blocks(0, 1, 100), 1);
    assert_eq!(realistic_target_blocks(0, 100, 100), 1);
    assert_eq!(realistic_target_blocks(0, 101, 100), 2);
    assert_eq!(realistic_target_blocks(1, 101, 100), 2);
}
#[test]
fn realistic_target_blocks_handles_near_max_capacity_without_overflow() {
    assert_eq!(realistic_target_blocks(0, u64::MAX, u64::MAX), 1);
    assert_eq!(realistic_target_blocks(0, u64::MAX - 1, u64::MAX), 1);
    assert_eq!(
        realistic_target_blocks(0, u64::MAX - 1, (u64::MAX / 2) + 1),
        2
    );
}
#[test]
fn max_queue_size_for_phase_filters_samples() {
    let samples = vec![
        ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 1,
            statuses: vec![StatusSnapshot {
                queue_size: 7,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("drain".to_string()),
            timestamp_ms: 2,
            statuses: vec![StatusSnapshot {
                queue_size: 99,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 3,
            statuses: vec![StatusSnapshot {
                queue_size: 11,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
    ];
    assert_eq!(max_queue_size_for_phase(&samples, "load"), 11);
    assert_eq!(max_queue_size_for_phase(&samples, "drain"), 99);
    assert_eq!(max_queue_size_for_phase(&samples, "missing"), 0);
}
#[test]
fn max_queue_size_for_phase_ignores_adversarial_non_matching_samples() {
    let samples = vec![
        ThroughputSample {
            phase: None,
            timestamp_ms: 1,
            statuses: vec![StatusSnapshot {
                queue_size: u64::MAX,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("Load".to_string()),
            timestamp_ms: 2,
            statuses: vec![StatusSnapshot {
                queue_size: u64::MAX - 1,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 3,
            statuses: Vec::new(),
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 4,
            statuses: vec![
                StatusSnapshot {
                    queue_size: 13,
                    ..StatusSnapshot::default()
                },
                StatusSnapshot {
                    queue_size: 21,
                    ..StatusSnapshot::default()
                },
            ],
            sumeragi: Vec::new(),
        },
    ];
    assert_eq!(max_queue_size_for_phase(&samples, "load"), 21);
    assert_eq!(max_queue_size_for_phase(&samples, "Load"), u64::MAX - 1);
    assert_eq!(max_queue_size_for_phase(&samples, ""), 0);
}
#[test]
fn max_queue_size_for_phase_counts_all_matching_statuses_without_summing() {
    let samples = vec![
        ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 1,
            statuses: vec![
                StatusSnapshot {
                    queue_size: u64::MAX - 10,
                    ..StatusSnapshot::default()
                },
                StatusSnapshot {
                    queue_size: 9,
                    ..StatusSnapshot::default()
                },
            ],
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("drain".to_string()),
            timestamp_ms: 2,
            statuses: vec![StatusSnapshot {
                queue_size: u64::MAX,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 3,
            statuses: vec![StatusSnapshot {
                queue_size: u64::MAX - 1,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
    ];
    assert_eq!(max_queue_size_for_phase(&samples, "load"), u64::MAX - 1);
    assert_eq!(max_queue_size_for_phase(&samples, "drain"), u64::MAX);
}
#[test]
fn max_queue_size_for_phase_requires_exact_phase_match() {
    let samples = vec![
        ThroughputSample {
            phase: Some("load ".to_string()),
            timestamp_ms: 1,
            statuses: vec![StatusSnapshot {
                queue_size: u64::MAX,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("load\n".to_string()),
            timestamp_ms: 2,
            statuses: vec![StatusSnapshot {
                queue_size: u64::MAX - 1,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("load\0".to_string()),
            timestamp_ms: 3,
            statuses: vec![StatusSnapshot {
                queue_size: u64::MAX - 2,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
        ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 4,
            statuses: vec![StatusSnapshot {
                queue_size: 5,
                ..StatusSnapshot::default()
            }],
            sumeragi: Vec::new(),
        },
    ];
    assert_eq!(max_queue_size_for_phase(&samples, "load"), 5);
    assert_eq!(max_queue_size_for_phase(&samples, "load "), u64::MAX);
}
#[test]
fn write_throughput_artifacts_writes_realistic_summary_and_sample_phases() {
    let dir = tempdir().expect("tempdir");
    let artifact_root = dir.path().join("artifacts");
    let network_dir = dir.path().join("network");
    let status = StatusSnapshot {
        blocks: 5,
        blocks_non_empty: 4,
        queue_size: 3,
        txs_approved: 120,
        txs_rejected: 0,
        view_changes: 1,
    };
    let summary = ThroughputStatusSummary::from_statuses(std::slice::from_ref(&status));
    let recovering_status = StatusSnapshot {
        blocks: 4,
        blocks_non_empty: 3,
        queue_size: 0,
        txs_approved: 80,
        txs_rejected: 0,
        view_changes: 2,
    };
    let healthy_status = StatusSnapshot {
        blocks: 6,
        blocks_non_empty: 5,
        queue_size: 0,
        txs_approved: 150,
        txs_rejected: 0,
        view_changes: 1,
    };
    let artifacts = ThroughputArtifacts {
        realistic: Some(ThroughputArtifactRealistic {
            baseline_non_empty: 1,
            baseline_approved: 8,
            target_non_empty: 4,
            target_approved: 98,
            submitted: 90,
            load_sample_count: 1,
            load_elapsed_ms: 3_000,
            submit_elapsed_ms: 3_000,
            drain_elapsed_ms: 1_000,
            total_elapsed_ms: 4_000,
            load_end: summary.clone(),
            final_status: summary,
            load_end_produced_blocks: 3,
            produced_blocks: 3,
            load_submitted_tps: 30.0,
            load_committed_tps: 28.0,
            final_committed_tps: 22.5,
            load_avg_secs_per_block: 1.0,
            avg_secs_per_block: 1.333,
        }),
        samples: vec![ThroughputSample {
            phase: Some("load".to_string()),
            timestamp_ms: 42,
            statuses: vec![status.clone()],
            sumeragi: Vec::new(),
        }],
        fault_windows: vec![Realistic30TpsFaultWindow {
            peer_index: 2,
            mnemonic: "peer2".to_string(),
            fault: "conflicting-ready",
            started_ms: 100,
            ended_ms: Some(160),
        }],
        status_recovery_samples: vec![Realistic30TpsStatusRecoverySample {
            peer_index: 2,
            mnemonic: "peer2".to_string(),
            context: "heal rotating validator outage".to_string(),
            restart_started_ms: 170,
            status_wait_started_ms: 172,
            ended_ms: 210,
            bound_ms: 120_000,
            recovered: true,
            poll_attempts: 4,
            last_error: Some("connection refused".to_string()),
            snapshot_before_shutdown: Realistic30TpsSnapshotObservation::default(),
            snapshot_after_shutdown: Realistic30TpsSnapshotObservation {
                store_dir: "peer2/storage/snapshot".to_string(),
                data_bytes: Some(4096),
                digest_bytes: Some(64),
                signature_bytes: Some(128),
                merkle_bytes: Some(256),
                data_modified_ms: Some(180),
                errors: Vec::new(),
            },
            snapshot_after_status: Realistic30TpsSnapshotObservation {
                store_dir: "peer2/storage/snapshot".to_string(),
                data_bytes: Some(4096),
                digest_bytes: Some(64),
                signature_bytes: Some(128),
                merkle_bytes: Some(256),
                data_modified_ms: Some(180),
                errors: Vec::new(),
            },
        }],
        catch_up_samples: vec![Realistic30TpsCatchUpSample {
            timestamp_ms: 200,
            recovering_peer_index: 2,
            target: Realistic30TpsCatchUpTarget {
                blocks_non_empty: 4,
                txs_approved: 98,
            },
            recovering_status: Some(recovering_status),
            healthy_statuses: vec![status, healthy_status],
            healthy_status_error: None,
            recovering_no_progress_ms: 12_000,
        }],
        convergence_windows: vec![Realistic30TpsConvergenceWindow {
            healed_peer_index: 2,
            healed_fault: "conflicting-ready",
            started_ms: 170,
            ended_ms: 230,
            start_span: Some(Realistic30TpsConvergenceSpan {
                min_blocks_non_empty: 4,
                max_blocks_non_empty: 7,
                min_txs_approved: 98,
                max_txs_approved: 150,
            }),
            end_span: Realistic30TpsConvergenceSpan {
                min_blocks_non_empty: 8,
                max_blocks_non_empty: 9,
                min_txs_approved: 180,
                max_txs_approved: 200,
            },
        }],
        ..ThroughputArtifacts::default()
    };
    let peer_logs = vec![PeerLogInfo {
        index: 0,
        mnemonic: "peer0".to_string(),
        stdout_log: None,
        stderr_log: None,
    }];
    let run_dir = write_throughput_artifacts(&artifact_root, &network_dir, &peer_logs, &artifacts)
        .expect("write artifacts");
    let summary_json = fs::read_to_string(run_dir.join("summary.json")).expect("read summary");
    let Value::Object(summary_map) =
        norito::json::from_json::<Value>(&summary_json).expect("parse summary")
    else {
        panic!("expected summary object");
    };
    let Some(Value::Object(realistic)) = summary_map.get("realistic") else {
        panic!("expected realistic summary");
    };
    assert_eq!(realistic.get("submitted"), Some(&Value::from(90_u64)));
    assert_eq!(
        realistic.get("load_end_produced_blocks"),
        Some(&Value::from(3_u64))
    );
    let Some(Value::Array(fault_windows)) = summary_map.get("fault_windows") else {
        panic!("expected fault windows");
    };
    let Some(Value::Object(first_fault)) = fault_windows.first() else {
        panic!("expected first fault window");
    };
    assert_eq!(first_fault.get("peer_index"), Some(&Value::from(2_u64)));
    assert_eq!(first_fault.get("duration_ms"), Some(&Value::from(60_u64)));
    let Some(Value::Array(status_recoveries)) = summary_map.get("status_recovery_samples") else {
        panic!("expected status recovery samples");
    };
    let Some(Value::Object(first_status_recovery)) = status_recoveries.first() else {
        panic!("expected first status recovery sample");
    };
    assert_eq!(
        first_status_recovery.get("status_wait_ms"),
        Some(&Value::from(38_u64))
    );
    assert_eq!(
        first_status_recovery.get("recovered_within_bound"),
        Some(&Value::from(true))
    );
    let Some(Value::Object(snapshot_after_shutdown)) =
        first_status_recovery.get("snapshot_after_shutdown")
    else {
        panic!("expected snapshot observation");
    };
    assert_eq!(
        snapshot_after_shutdown.get("bundle_complete"),
        Some(&Value::from(true))
    );
    let Some(Value::Object(status_recovery_summary)) = summary_map.get("status_recovery_summary")
    else {
        panic!("expected status recovery summary");
    };
    assert_eq!(
        status_recovery_summary.get("max_status_wait_ms"),
        Some(&Value::from(38_u64))
    );
    assert_eq!(
        status_recovery_summary.get("outside_bound"),
        Some(&Value::from(0_u64))
    );
    assert_eq!(
        status_recovery_summary.get("complete_bundle_after_shutdown"),
        Some(&Value::from(1_u64))
    );
    assert_eq!(
        status_recovery_summary.get("all_complete_bundle_after_shutdown"),
        Some(&Value::from(true))
    );
    let Some(Value::Array(catch_up_samples)) = summary_map.get("catch_up_samples") else {
        panic!("expected catch-up samples");
    };
    let Some(Value::Object(first_catch_up)) = catch_up_samples.first() else {
        panic!("expected first catch-up sample");
    };
    assert_eq!(
        first_catch_up.get("recovering_peer_index"),
        Some(&Value::from(2_u64))
    );
    assert_eq!(
        first_catch_up.get("recovering_no_progress_ms"),
        Some(&Value::from(12_000_u64))
    );
    let Some(Value::Object(target)) = first_catch_up.get("target") else {
        panic!("expected catch-up target");
    };
    assert_eq!(target.get("blocks_non_empty"), Some(&Value::from(4_u64)));
    assert_eq!(target.get("txs_approved"), Some(&Value::from(98_u64)));
    let Some(Value::Object(recovering_status)) = first_catch_up.get("recovering_status") else {
        panic!("expected recovering status");
    };
    assert_eq!(
        recovering_status.get("blocks_non_empty"),
        Some(&Value::from(3_u64))
    );
    let Some(Value::Array(healthy_statuses)) = first_catch_up.get("healthy_statuses") else {
        panic!("expected healthy statuses");
    };
    assert_eq!(healthy_statuses.len(), 2);
    let Some(Value::Object(healthy_summary)) = first_catch_up.get("healthy_summary") else {
        panic!("expected healthy summary");
    };
    assert_eq!(
        healthy_summary.get("min_txs_approved"),
        Some(&Value::from(120_u64))
    );
    assert_eq!(
        healthy_summary.get("max_txs_approved"),
        Some(&Value::from(150_u64))
    );
    let Some(Value::Array(convergence_windows)) = summary_map.get("strict_convergence_windows")
    else {
        panic!("expected strict convergence windows");
    };
    let Some(Value::Object(first_convergence)) = convergence_windows.first() else {
        panic!("expected first convergence window");
    };
    assert_eq!(
        first_convergence.get("healed_peer_index"),
        Some(&Value::from(2_u64))
    );
    assert_eq!(
        first_convergence.get("duration_ms"),
        Some(&Value::from(60_u64))
    );
    let Some(Value::Object(strict_summary)) = summary_map.get("strict_convergence_summary") else {
        panic!("expected strict convergence summary");
    };
    assert_eq!(
        strict_summary.get("post_heal_lag_windows"),
        Some(&Value::from(1_u64))
    );
    assert_eq!(
        strict_summary.get("max_start_block_gap"),
        Some(&Value::from(3_u64))
    );
    let samples_json =
        fs::read_to_string(run_dir.join("status_samples.json")).expect("read samples");
    let Value::Array(samples) =
        norito::json::from_json::<Value>(&samples_json).expect("parse samples")
    else {
        panic!("expected samples array");
    };
    let Some(Value::Object(sample)) = samples.first() else {
        panic!("expected first sample object");
    };
    assert_eq!(
        sample.get("phase"),
        Some(&Value::String("load".to_string()))
    );
    let Some(Value::Array(statuses)) = sample.get("status") else {
        panic!("expected status array");
    };
    let Some(Value::Object(status)) = statuses.first() else {
        panic!("expected status object");
    };
    assert_eq!(status.get("blocks_non_empty"), Some(&Value::from(4_u64)));
}
#[test]
fn throughput_payload_is_deterministic() {
    let payload = throughput_payload(7, 64, 123);
    let payload_repeat = throughput_payload(7, 64, 123);
    assert_eq!(payload, payload_repeat);
    assert_eq!(payload.len(), 64);
    assert!(payload.contains("localnet throughput 7"));
    let different = throughput_payload(8, 64, 123);
    assert_ne!(payload, different);
}
#[test]
fn metrics_url_handles_variants() {
    assert_eq!(
        metrics_url("http://127.0.0.1:8080"),
        "http://127.0.0.1:8080/metrics"
    );
    assert_eq!(
        metrics_url("http://127.0.0.1:8080/"),
        "http://127.0.0.1:8080/metrics"
    );
    assert_eq!(
        metrics_url("http://127.0.0.1:8080/metrics"),
        "http://127.0.0.1:8080/metrics"
    );
}
#[test]
fn parse_prom_histogram_extracts_quantiles() {
    let payload = r#"
# HELP commit_time_ms Average block commit time on this peer
# TYPE commit_time_ms histogram
commit_time_ms_bucket{le="5"} 1
commit_time_ms_bucket{le="10"} 3
commit_time_ms_bucket{le="+Inf"} 4
commit_time_ms_sum 27
commit_time_ms_count 4
"#;
    let hist = parse_prom_histogram(payload, "commit_time_ms");
    assert_eq!(hist.count, 4);
    assert_eq!(hist.buckets.len(), 3);
    let p50 = hist.quantile(0.5).expect("p50");
    assert!((p50 - 7.5).abs() < 0.25);
}
#[test]
fn aggregate_histograms_sums_counts() {
    let h1 = HistogramSnapshot {
        buckets: vec![(1.0, 2), (2.0, 3)],
        sum: 5.0,
        count: 3,
    };
    let h2 = HistogramSnapshot {
        buckets: vec![(1.0, 1), (2.0, 2)],
        sum: 4.0,
        count: 2,
    };
    let merged = aggregate_histograms([&h1, &h2]);
    assert_eq!(merged.count, 5);
    assert!((merged.sum - 9.0).abs() < f64::EPSILON);
    assert_eq!(merged.buckets.len(), 2);
}
#[test]
fn commit_time_quantiles_use_delta_histogram() {
    let warmup = PeerMetricsSnapshot {
        peer: "peer0".to_string(),
        payload: String::new(),
        commit_time_hist: HistogramSnapshot {
            buckets: vec![(5.0, 1), (10.0, 2), (f64::INFINITY, 2)],
            sum: 15.0,
            count: 2,
        },
    };
    let steady = PeerMetricsSnapshot {
        peer: "peer0".to_string(),
        payload: String::new(),
        commit_time_hist: HistogramSnapshot {
            buckets: vec![(5.0, 1), (10.0, 4), (f64::INFINITY, 4)],
            sum: 35.0,
            count: 4,
        },
    };
    let (p95, p99, count) = commit_time_quantiles(&[warmup], &[steady]);
    assert_eq!(count, 2);
    assert_eq!(p95, Some(10));
    assert_eq!(p99, Some(10));
}
#[test]
fn rate_summary_reports_avg_and_max() {
    let (avg, max) = rate_summary(&[0, 10], &[10, 40], Duration::from_secs(10));
    assert!((avg - 2.0).abs() < f64::EPSILON);
    assert!((max - 3.0).abs() < f64::EPSILON);
}
#[test]
fn config_fingerprint_changes_on_update() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join("config.base.toml");
    fs::write(&config_path, "a = 1").expect("write config");
    let first = config_fingerprint(dir.path())
        .expect("fingerprint")
        .expect("fingerprint value");
    fs::write(&config_path, "a = 2").expect("write config");
    let second = config_fingerprint(dir.path())
        .expect("fingerprint")
        .expect("fingerprint value");
    assert_ne!(first, second);
}
#[test]
fn status_snapshot_value_contains_only_general_telemetry() {
    let snapshot = StatusSnapshot {
        blocks: 1,
        blocks_non_empty: 1,
        queue_size: 2,
        txs_approved: 3,
        txs_rejected: 4,
        view_changes: 5,
    };
    let value = status_snapshot_value(&snapshot);
    let Value::Object(map) = value else {
        panic!("expected object");
    };
    assert_eq!(map.get("blocks"), Some(&Value::from(1)));
    assert!(!map.contains_key("leader_index"));
    assert!(!map.contains_key("highest_qc_height"));
    assert!(!map.contains_key("tx_queue_saturated"));
}
#[test]
fn sumeragi_snapshot_value_maps_fields() {
    let snapshot = SumeragiStatusSnapshot {
        tx_queue_depth: 3,
        tx_queue_capacity: 4,
        tx_queue_retained_bytes: 5,
        tx_queue_max_retained_bytes: 6,
        tx_queue_saturated: true,
        tx_queue_saturated_by_count: false,
        tx_queue_saturated_by_bytes: true,
        tx_queue_saturated_by_age: true,
        tx_queue_oldest_queued_age_ms: 7,
    };
    let value = sumeragi_snapshot_value(&snapshot);
    let Value::Object(map) = value else {
        panic!("expected object");
    };
    assert!(map.get("commit_qc_height").is_none());
    assert_eq!(map.get("tx_queue_retained_bytes"), Some(&Value::from(5)));
    assert_eq!(
        map.get("tx_queue_saturated_by_bytes"),
        Some(&Value::from(true))
    );
    assert_eq!(
        map.get("tx_queue_oldest_queued_age_ms"),
        Some(&Value::from(7))
    );
    assert_eq!(map.get("tx_queue_saturated"), Some(&Value::from(true)));
}
async fn wait_for_converged_height(
    network: &Network,
    target_height: u64,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
    let mut last_log = Instant::now()
        .checked_sub(STATUS_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        match collect_statuses(network, STATUS_POLL_TIMEOUT).await {
            Ok(statuses) => {
                let snapshot: Vec<StatusSnapshot> =
                    statuses.iter().map(StatusSnapshot::from_status).collect();
                if snapshot != last_snapshot || last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "localnet status snapshot (target_height={target_height}): {snapshot:?}"
                    );
                    last_log = Instant::now();
                }
                last_snapshot = snapshot;
                if statuses.iter().all(|status| status.blocks >= target_height) {
                    let first_height = statuses.first().map(|s| s.blocks);
                    if statuses
                        .iter()
                        .all(|status| Some(status.blocks) == first_height)
                    {
                        return Ok(());
                    }
                }
                if Instant::now() >= deadline {
                    return Err(eyre!(
                        "heights failed to converge to {target_height} within {:?}: last_snapshot={last_snapshot:?}",
                        timeout
                    ));
                }
            }
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(eyre!(
                        "heights failed to converge to {target_height} within {:?}: last_snapshot={last_snapshot:?}, last_error={err:?}",
                        timeout
                    ));
                }
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn wait_for_height_quorum_with_bounded_lag(
    network: &Network,
    target_height: u64,
    timeout: Duration,
) -> Result<Vec<iroha_torii_shared::status::Status>> {
    let deadline = Instant::now() + timeout;
    let peer_count = network.peers().len();
    let quorum = iroha_sumeragi::types::quorum(peer_count).max(1);
    let tolerated_lagging = tolerated_lagging_peers(peer_count);
    let mut last_snapshot: Vec<StatusSnapshot> = Vec::new();
    let mut last_log = Instant::now()
        .checked_sub(STATUS_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        match collect_statuses(network, STATUS_POLL_TIMEOUT).await {
            Ok(statuses) => {
                let snapshot: Vec<StatusSnapshot> =
                    statuses.iter().map(StatusSnapshot::from_status).collect();
                if snapshot != last_snapshot || last_log.elapsed() >= STATUS_LOG_INTERVAL {
                    eprintln!(
                        "localnet status quorum snapshot (target_height={target_height}, quorum={quorum}, tolerated_lagging={tolerated_lagging}): {snapshot:?}"
                    );
                    last_log = Instant::now();
                }
                last_snapshot = snapshot;
                if height_quorum_with_bounded_lag(&statuses, target_height, quorum) {
                    return Ok(statuses);
                }
                if Instant::now() >= deadline {
                    return Err(eyre!(
                        "height quorum failed to reach {target_height} within {:?}: quorum={quorum}, tolerated_lagging={tolerated_lagging}, last_snapshot={last_snapshot:?}",
                        timeout
                    ));
                }
            }
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(eyre!(
                        "height quorum failed to reach {target_height} within {:?}: quorum={quorum}, tolerated_lagging={tolerated_lagging}, last_snapshot={last_snapshot:?}, last_error={err:?}",
                        timeout
                    ));
                }
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
}
fn height_quorum_with_bounded_lag(
    statuses: &[iroha_torii_shared::status::Status],
    target_height: u64,
    quorum: usize,
) -> bool {
    if statuses.is_empty() {
        return false;
    }
    if statuses
        .iter()
        .filter(|status| status.blocks >= target_height)
        .count()
        < quorum
    {
        return false;
    }
    let Some((_min_height, max_height)) = status_height_span(statuses) else {
        return false;
    };
    if max_height < target_height {
        return false;
    }
    let tolerated_lagging = statuses.len().saturating_sub(quorum);
    let low_watermark = quorum_low_watermark_height(statuses, tolerated_lagging);
    max_height.saturating_sub(low_watermark) <= 1
}
fn status_height_span(statuses: &[iroha_torii_shared::status::Status]) -> Option<(u64, u64)> {
    let min_height = statuses.iter().map(|status| status.blocks).min()?;
    let max_height = statuses.iter().map(|status| status.blocks).max()?;
    Some((min_height, max_height))
}
fn tolerated_lagging_peers(peer_count: usize) -> usize {
    peer_count.saturating_sub(iroha_sumeragi::types::quorum(peer_count).max(1))
}
fn quorum_low_watermark_height(
    statuses: &[iroha_torii_shared::status::Status],
    tolerated_lagging: usize,
) -> u64 {
    let mut heights: Vec<_> = statuses.iter().map(|status| status.blocks).collect();
    if heights.is_empty() {
        return 0;
    }
    heights.sort_unstable();
    heights[tolerated_lagging.min(heights.len().saturating_sub(1))]
}
fn scale_duration(duration: Duration, factor: u64) -> Duration {
    let total_ms = duration.as_millis().saturating_mul(u128::from(factor));
    Duration::from_millis(u64::try_from(total_ms).unwrap_or(u64::MAX))
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
struct StatusSnapshot {
    blocks: u64,
    blocks_non_empty: u64,
    queue_size: u64,
    txs_approved: u64,
    txs_rejected: u64,
    view_changes: u32,
}
impl StatusSnapshot {
    fn from_status(status: &iroha_torii_shared::status::Status) -> Self {
        Self {
            blocks: status.blocks,
            blocks_non_empty: status.blocks_non_empty,
            queue_size: status.queue_size,
            txs_approved: status.txs_approved,
            txs_rejected: status.txs_rejected,
            view_changes: status.view_changes,
        }
    }
}
#[derive(Debug)]
struct ThroughputSample {
    phase: Option<String>,
    timestamp_ms: u64,
    statuses: Vec<StatusSnapshot>,
    sumeragi: Vec<SumeragiStatusSnapshot>,
}
#[derive(Clone, Debug, Default)]
struct ThroughputStatusSummary {
    min_blocks: u64,
    max_blocks: u64,
    min_blocks_non_empty: u64,
    max_blocks_non_empty: u64,
    min_txs_approved: u64,
    max_txs_approved: u64,
    max_txs_rejected: u64,
    max_queue_size: u64,
}
impl ThroughputStatusSummary {
    fn from_statuses(statuses: &[StatusSnapshot]) -> Self {
        if statuses.is_empty() {
            return Self::default();
        }
        Self {
            min_blocks: statuses
                .iter()
                .map(|status| status.blocks)
                .min()
                .unwrap_or_default(),
            max_blocks: statuses
                .iter()
                .map(|status| status.blocks)
                .max()
                .unwrap_or_default(),
            min_blocks_non_empty: statuses
                .iter()
                .map(|status| status.blocks_non_empty)
                .min()
                .unwrap_or_default(),
            max_blocks_non_empty: statuses
                .iter()
                .map(|status| status.blocks_non_empty)
                .max()
                .unwrap_or_default(),
            min_txs_approved: statuses
                .iter()
                .map(|status| status.txs_approved)
                .min()
                .unwrap_or_default(),
            max_txs_approved: statuses
                .iter()
                .map(|status| status.txs_approved)
                .max()
                .unwrap_or_default(),
            max_txs_rejected: statuses
                .iter()
                .map(|status| status.txs_rejected)
                .max()
                .unwrap_or_default(),
            max_queue_size: statuses
                .iter()
                .map(|status| status.queue_size)
                .max()
                .unwrap_or_default(),
        }
    }
    fn from_statuses_tolerating_lagging(
        statuses: &[StatusSnapshot],
        tolerated_lagging: usize,
    ) -> Self {
        if statuses.is_empty() || tolerated_lagging == 0 {
            return Self::from_statuses(statuses);
        }
        fn low_watermark_after_lagging<I>(values: I, tolerated_lagging: usize) -> u64
        where
            I: IntoIterator<Item = u64>,
        {
            let mut values: Vec<_> = values.into_iter().collect();
            if values.is_empty() {
                return 0;
            }
            values.sort_unstable();
            values[tolerated_lagging.min(values.len().saturating_sub(1))]
        }
        let mut summary = Self::from_statuses(statuses);
        summary.min_blocks = low_watermark_after_lagging(
            statuses.iter().map(|status| status.blocks),
            tolerated_lagging,
        );
        summary.min_blocks_non_empty = low_watermark_after_lagging(
            statuses.iter().map(|status| status.blocks_non_empty),
            tolerated_lagging,
        );
        summary.min_txs_approved = low_watermark_after_lagging(
            statuses.iter().map(|status| status.txs_approved),
            tolerated_lagging,
        );
        summary
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SumeragiStatusSnapshot {
    tx_queue_depth: u64,
    tx_queue_capacity: u64,
    tx_queue_retained_bytes: u64,
    tx_queue_max_retained_bytes: u64,
    tx_queue_saturated: bool,
    tx_queue_saturated_by_count: bool,
    tx_queue_saturated_by_bytes: bool,
    tx_queue_saturated_by_age: bool,
    tx_queue_oldest_queued_age_ms: u64,
}
impl SumeragiStatusSnapshot {
    fn from_status(status: &SumeragiDiagnosticsStatus) -> Self {
        Self {
            tx_queue_depth: status.tx_queue_depth,
            tx_queue_capacity: status.tx_queue_capacity,
            tx_queue_retained_bytes: status.tx_queue_retained_bytes,
            tx_queue_max_retained_bytes: status.tx_queue_max_retained_bytes,
            tx_queue_saturated: status.tx_queue_saturated,
            tx_queue_saturated_by_count: status.tx_queue_saturated_by_count,
            tx_queue_saturated_by_bytes: status.tx_queue_saturated_by_bytes,
            tx_queue_saturated_by_age: status.tx_queue_saturated_by_age,
            tx_queue_oldest_queued_age_ms: status.tx_queue_oldest_queued_age_ms,
        }
    }
}
fn status_snapshot_value(snapshot: &StatusSnapshot) -> Value {
    let mut map = Map::new();
    map.insert("blocks".to_string(), Value::from(snapshot.blocks));
    map.insert(
        "blocks_non_empty".to_string(),
        Value::from(snapshot.blocks_non_empty),
    );
    map.insert("queue_size".to_string(), Value::from(snapshot.queue_size));
    map.insert(
        "txs_approved".to_string(),
        Value::from(snapshot.txs_approved),
    );
    map.insert(
        "txs_rejected".to_string(),
        Value::from(snapshot.txs_rejected),
    );
    map.insert(
        "view_changes".to_string(),
        Value::from(u64::from(snapshot.view_changes)),
    );
    Value::Object(map)
}
fn throughput_status_summary_value(summary: &ThroughputStatusSummary) -> Value {
    let mut map = Map::new();
    map.insert("min_blocks".to_string(), Value::from(summary.min_blocks));
    map.insert("max_blocks".to_string(), Value::from(summary.max_blocks));
    map.insert(
        "min_blocks_non_empty".to_string(),
        Value::from(summary.min_blocks_non_empty),
    );
    map.insert(
        "max_blocks_non_empty".to_string(),
        Value::from(summary.max_blocks_non_empty),
    );
    map.insert(
        "min_txs_approved".to_string(),
        Value::from(summary.min_txs_approved),
    );
    map.insert(
        "max_txs_approved".to_string(),
        Value::from(summary.max_txs_approved),
    );
    map.insert(
        "max_txs_rejected".to_string(),
        Value::from(summary.max_txs_rejected),
    );
    map.insert(
        "max_queue_size".to_string(),
        Value::from(summary.max_queue_size),
    );
    Value::Object(map)
}
fn catch_up_target_value(target: Realistic30TpsCatchUpTarget) -> Value {
    let mut map = Map::new();
    map.insert(
        "blocks_non_empty".to_string(),
        Value::from(target.blocks_non_empty),
    );
    map.insert("txs_approved".to_string(), Value::from(target.txs_approved));
    Value::Object(map)
}
fn convergence_span_value(span: Realistic30TpsConvergenceSpan) -> Value {
    let mut map = Map::new();
    map.insert(
        "min_blocks_non_empty".to_string(),
        Value::from(span.min_blocks_non_empty),
    );
    map.insert(
        "max_blocks_non_empty".to_string(),
        Value::from(span.max_blocks_non_empty),
    );
    map.insert(
        "min_txs_approved".to_string(),
        Value::from(span.min_txs_approved),
    );
    map.insert(
        "max_txs_approved".to_string(),
        Value::from(span.max_txs_approved),
    );
    map.insert("block_gap".to_string(), Value::from(span.block_gap()));
    map.insert("approved_gap".to_string(), Value::from(span.approved_gap()));
    Value::Object(map)
}
fn convergence_window_value(window: &Realistic30TpsConvergenceWindow) -> Value {
    let mut map = Map::new();
    map.insert(
        "healed_peer_index".to_string(),
        Value::from(u64::try_from(window.healed_peer_index).unwrap_or(u64::MAX)),
    );
    map.insert(
        "healed_fault".to_string(),
        Value::String(window.healed_fault.to_owned()),
    );
    map.insert("started_ms".to_string(), Value::from(window.started_ms));
    map.insert("ended_ms".to_string(), Value::from(window.ended_ms));
    map.insert(
        "duration_ms".to_string(),
        Value::from(window.ended_ms.saturating_sub(window.started_ms)),
    );
    map.insert(
        "start_span".to_string(),
        window
            .start_span
            .map_or(Value::Null, convergence_span_value),
    );
    map.insert(
        "end_span".to_string(),
        convergence_span_value(window.end_span),
    );
    Value::Object(map)
}
fn catch_up_sample_value(sample: &Realistic30TpsCatchUpSample) -> Value {
    let mut map = Map::new();
    map.insert("timestamp_ms".to_string(), Value::from(sample.timestamp_ms));
    map.insert(
        "recovering_peer_index".to_string(),
        Value::from(u64::try_from(sample.recovering_peer_index).unwrap_or(u64::MAX)),
    );
    map.insert("target".to_string(), catch_up_target_value(sample.target));
    map.insert(
        "recovering_status".to_string(),
        sample
            .recovering_status
            .as_ref()
            .map_or(Value::Null, status_snapshot_value),
    );
    map.insert(
        "healthy_statuses".to_string(),
        Value::Array(
            sample
                .healthy_statuses
                .iter()
                .map(status_snapshot_value)
                .collect(),
        ),
    );
    map.insert(
        "healthy_summary".to_string(),
        throughput_status_summary_value(&ThroughputStatusSummary::from_statuses(
            &sample.healthy_statuses,
        )),
    );
    map.insert(
        "healthy_status_error".to_string(),
        sample
            .healthy_status_error
            .as_ref()
            .map_or(Value::Null, |error| Value::String(error.clone())),
    );
    map.insert(
        "recovering_no_progress_ms".to_string(),
        Value::from(sample.recovering_no_progress_ms),
    );
    Value::Object(map)
}
fn snapshot_observation_value(snapshot: &Realistic30TpsSnapshotObservation) -> Value {
    let mut map = Map::new();
    map.insert(
        "store_dir".to_string(),
        Value::String(snapshot.store_dir.clone()),
    );
    map.insert(
        "data_present".to_string(),
        Value::from(snapshot.data_present()),
    );
    map.insert(
        "bundle_complete".to_string(),
        Value::from(snapshot.bundle_complete()),
    );
    map.insert(
        "data_bytes".to_string(),
        snapshot.data_bytes.map_or(Value::Null, Value::from),
    );
    map.insert(
        "digest_bytes".to_string(),
        snapshot.digest_bytes.map_or(Value::Null, Value::from),
    );
    map.insert(
        "signature_bytes".to_string(),
        snapshot.signature_bytes.map_or(Value::Null, Value::from),
    );
    map.insert(
        "merkle_bytes".to_string(),
        snapshot.merkle_bytes.map_or(Value::Null, Value::from),
    );
    map.insert(
        "data_modified_ms".to_string(),
        snapshot.data_modified_ms.map_or(Value::Null, Value::from),
    );
    map.insert(
        "errors".to_string(),
        Value::Array(snapshot.errors.iter().cloned().map(Value::String).collect()),
    );
    Value::Object(map)
}
fn status_recovery_sample_value(sample: &Realistic30TpsStatusRecoverySample) -> Value {
    let mut map = Map::new();
    map.insert(
        "peer_index".to_string(),
        Value::from(u64::try_from(sample.peer_index).unwrap_or(u64::MAX)),
    );
    map.insert(
        "mnemonic".to_string(),
        Value::String(sample.mnemonic.clone()),
    );
    map.insert("context".to_string(), Value::String(sample.context.clone()));
    map.insert(
        "restart_started_ms".to_string(),
        Value::from(sample.restart_started_ms),
    );
    map.insert(
        "status_wait_started_ms".to_string(),
        Value::from(sample.status_wait_started_ms),
    );
    map.insert("ended_ms".to_string(), Value::from(sample.ended_ms));
    map.insert(
        "total_duration_ms".to_string(),
        Value::from(sample.total_duration_ms()),
    );
    map.insert(
        "status_wait_ms".to_string(),
        Value::from(sample.status_wait_ms()),
    );
    map.insert("bound_ms".to_string(), Value::from(sample.bound_ms));
    map.insert("recovered".to_string(), Value::from(sample.recovered));
    map.insert(
        "recovered_within_bound".to_string(),
        Value::from(sample.recovered_within_bound()),
    );
    map.insert(
        "poll_attempts".to_string(),
        Value::from(sample.poll_attempts),
    );
    map.insert(
        "last_error".to_string(),
        sample
            .last_error
            .as_ref()
            .map_or(Value::Null, |error| Value::String(error.clone())),
    );
    map.insert(
        "snapshot_before_shutdown".to_string(),
        snapshot_observation_value(&sample.snapshot_before_shutdown),
    );
    map.insert(
        "snapshot_after_shutdown".to_string(),
        snapshot_observation_value(&sample.snapshot_after_shutdown),
    );
    map.insert(
        "snapshot_after_status".to_string(),
        snapshot_observation_value(&sample.snapshot_after_status),
    );
    Value::Object(map)
}
fn fault_window_value(window: &Realistic30TpsFaultWindow) -> Value {
    let mut map = Map::new();
    map.insert(
        "peer_index".to_string(),
        Value::from(u64::try_from(window.peer_index).unwrap_or(u64::MAX)),
    );
    map.insert(
        "mnemonic".to_string(),
        Value::String(window.mnemonic.clone()),
    );
    map.insert("fault".to_string(), Value::String(window.fault.to_owned()));
    map.insert("started_ms".to_string(), Value::from(window.started_ms));
    map.insert(
        "ended_ms".to_string(),
        window.ended_ms.map_or(Value::Null, Value::from),
    );
    map.insert(
        "duration_ms".to_string(),
        window.ended_ms.map_or(Value::Null, |ended_ms| {
            Value::from(ended_ms.saturating_sub(window.started_ms))
        }),
    );
    Value::Object(map)
}
fn convergence_summary_value(
    windows: &[Realistic30TpsFaultWindow],
    convergence_windows: &[Realistic30TpsConvergenceWindow],
) -> Value {
    let mut map = Map::new();
    let strict_fault_starts_after_convergence =
        realistic_strict_fault_windows_start_after_convergence(windows, convergence_windows);
    let post_heal_lag_windows = convergence_windows
        .iter()
        .filter(|window| {
            window
                .start_span
                .is_some_and(|span| span.block_gap() > 0 || span.approved_gap() > 0)
        })
        .count();
    let max_start_block_gap = convergence_windows
        .iter()
        .filter_map(|window| {
            window
                .start_span
                .map(Realistic30TpsConvergenceSpan::block_gap)
        })
        .max()
        .unwrap_or_default();
    let max_start_approved_gap = convergence_windows
        .iter()
        .filter_map(|window| {
            window
                .start_span
                .map(Realistic30TpsConvergenceSpan::approved_gap)
        })
        .max()
        .unwrap_or_default();
    let max_end_block_gap = convergence_windows
        .iter()
        .map(|window| window.end_span.block_gap())
        .max()
        .unwrap_or_default();
    let max_end_approved_gap = convergence_windows
        .iter()
        .map(|window| window.end_span.approved_gap())
        .max()
        .unwrap_or_default();
    let max_wait_ms = convergence_windows
        .iter()
        .map(|window| window.ended_ms.saturating_sub(window.started_ms))
        .max()
        .unwrap_or_default();
    map.insert(
        "strict_fault_starts_after_convergence".to_string(),
        Value::from(strict_fault_starts_after_convergence),
    );
    map.insert(
        "convergence_windows".to_string(),
        Value::from(u64::try_from(convergence_windows.len()).unwrap_or(u64::MAX)),
    );
    map.insert(
        "post_heal_lag_windows".to_string(),
        Value::from(u64::try_from(post_heal_lag_windows).unwrap_or(u64::MAX)),
    );
    map.insert(
        "max_start_block_gap".to_string(),
        Value::from(max_start_block_gap),
    );
    map.insert(
        "max_start_approved_gap".to_string(),
        Value::from(max_start_approved_gap),
    );
    map.insert(
        "max_end_block_gap".to_string(),
        Value::from(max_end_block_gap),
    );
    map.insert(
        "max_end_approved_gap".to_string(),
        Value::from(max_end_approved_gap),
    );
    map.insert("max_wait_ms".to_string(), Value::from(max_wait_ms));
    Value::Object(map)
}
fn status_recovery_summary_value(samples: &[Realistic30TpsStatusRecoverySample]) -> Value {
    let mut map = Map::new();
    let recoveries = samples.len();
    let failures = samples.iter().filter(|sample| !sample.recovered).count();
    let outside_bound = samples
        .iter()
        .filter(|sample| !sample.recovered_within_bound())
        .count();
    let data_present_after_shutdown = samples
        .iter()
        .filter(|sample| sample.snapshot_after_shutdown.data_present())
        .count();
    let complete_bundle_after_shutdown = samples
        .iter()
        .filter(|sample| sample.snapshot_after_shutdown.bundle_complete())
        .count();
    let complete_bundle_after_status = samples
        .iter()
        .filter(|sample| sample.snapshot_after_status.bundle_complete())
        .count();
    let max_total_duration_ms = samples
        .iter()
        .map(Realistic30TpsStatusRecoverySample::total_duration_ms)
        .max()
        .unwrap_or_default();
    let max_status_wait_ms = samples
        .iter()
        .map(Realistic30TpsStatusRecoverySample::status_wait_ms)
        .max()
        .unwrap_or_default();
    let max_bound_ms = samples
        .iter()
        .map(|sample| sample.bound_ms)
        .max()
        .unwrap_or_default();
    map.insert(
        "recoveries".to_string(),
        Value::from(u64::try_from(recoveries).unwrap_or(u64::MAX)),
    );
    map.insert(
        "failures".to_string(),
        Value::from(u64::try_from(failures).unwrap_or(u64::MAX)),
    );
    map.insert(
        "outside_bound".to_string(),
        Value::from(u64::try_from(outside_bound).unwrap_or(u64::MAX)),
    );
    map.insert(
        "data_present_after_shutdown".to_string(),
        Value::from(u64::try_from(data_present_after_shutdown).unwrap_or(u64::MAX)),
    );
    map.insert(
        "complete_bundle_after_shutdown".to_string(),
        Value::from(u64::try_from(complete_bundle_after_shutdown).unwrap_or(u64::MAX)),
    );
    map.insert(
        "complete_bundle_after_status".to_string(),
        Value::from(u64::try_from(complete_bundle_after_status).unwrap_or(u64::MAX)),
    );
    map.insert("all_recovered".to_string(), Value::from(failures == 0));
    map.insert(
        "all_recovered_within_bound".to_string(),
        Value::from(outside_bound == 0),
    );
    map.insert(
        "all_complete_bundle_after_shutdown".to_string(),
        Value::from(complete_bundle_after_shutdown == recoveries),
    );
    map.insert(
        "all_complete_bundle_after_status".to_string(),
        Value::from(complete_bundle_after_status == recoveries),
    );
    map.insert(
        "max_total_duration_ms".to_string(),
        Value::from(max_total_duration_ms),
    );
    map.insert(
        "max_status_wait_ms".to_string(),
        Value::from(max_status_wait_ms),
    );
    map.insert("max_bound_ms".to_string(), Value::from(max_bound_ms));
    Value::Object(map)
}
fn sumeragi_snapshot_value(snapshot: &SumeragiStatusSnapshot) -> Value {
    let mut map = Map::new();
    map.insert(
        "tx_queue_depth".to_string(),
        Value::from(snapshot.tx_queue_depth),
    );
    map.insert(
        "tx_queue_capacity".to_string(),
        Value::from(snapshot.tx_queue_capacity),
    );
    map.insert(
        "tx_queue_retained_bytes".to_string(),
        Value::from(snapshot.tx_queue_retained_bytes),
    );
    map.insert(
        "tx_queue_max_retained_bytes".to_string(),
        Value::from(snapshot.tx_queue_max_retained_bytes),
    );
    map.insert(
        "tx_queue_saturated".to_string(),
        Value::from(snapshot.tx_queue_saturated),
    );
    map.insert(
        "tx_queue_saturated_by_count".to_string(),
        Value::from(snapshot.tx_queue_saturated_by_count),
    );
    map.insert(
        "tx_queue_saturated_by_bytes".to_string(),
        Value::from(snapshot.tx_queue_saturated_by_bytes),
    );
    map.insert(
        "tx_queue_saturated_by_age".to_string(),
        Value::from(snapshot.tx_queue_saturated_by_age),
    );
    map.insert(
        "tx_queue_oldest_queued_age_ms".to_string(),
        Value::from(snapshot.tx_queue_oldest_queued_age_ms),
    );
    Value::Object(map)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct PeerLogInfo {
    index: u64,
    mnemonic: String,
    stdout_log: Option<String>,
    stderr_log: Option<String>,
}
#[derive(Clone, Debug)]
struct ThroughputArtifactRecipe {
    peers: u64,
    block_cadence_ms: u64,
    block_max_txs: u64,
    warmup_blocks: u64,
    steady_blocks: u64,
    total_blocks: u64,
    warmup_txs: u64,
    steady_txs: u64,
    total_txs: u64,
    submit_batch: u64,
    submit_parallelism: u64,
    queue_soft_limit: u64,
    payload_bytes: u64,
    load_kind: String,
    transfer_accounts: u64,
    transfer_initial_balance: u64,
    transfer_max_amount: u64,

    rng_seed: u64,
    snapshot_mode: String,
    snapshot_create_every_ms: u64,
}
#[derive(Clone, Debug)]
struct ThroughputArtifactSlo {
    commit_p95_ms: u64,
    commit_p99_ms: u64,
    view_change_rate_max: f64,
    queue_saturation_max: f64,
}
#[derive(Clone, Debug)]
struct ThroughputArtifactMetrics {
    submitted_tps: f64,
    committed_tps: f64,
    commit_p95_ms: u64,
    commit_p99_ms: u64,
    commit_hist_count: u64,
    commit_time_ms_min: u64,
    commit_time_ms_avg: u64,
    commit_time_ms_max: u64,
    view_change_rate_avg: f64,
    view_change_rate_max: f64,
    queue_saturated_frac: f64,
    max_queue_depth: u64,
    steady_elapsed_ms: u64,
    warmup_submit_elapsed_ms: u64,
    steady_submit_elapsed_ms: u64,
}
#[derive(Clone, Debug)]
struct ThroughputArtifactRealistic {
    baseline_non_empty: u64,
    baseline_approved: u64,
    target_non_empty: u64,
    target_approved: u64,
    submitted: u64,
    load_sample_count: u64,
    load_elapsed_ms: u64,
    submit_elapsed_ms: u64,
    drain_elapsed_ms: u64,
    total_elapsed_ms: u64,
    load_end: ThroughputStatusSummary,
    final_status: ThroughputStatusSummary,
    load_end_produced_blocks: u64,
    produced_blocks: u64,
    load_submitted_tps: f64,
    load_committed_tps: f64,
    final_committed_tps: f64,
    load_avg_secs_per_block: f64,
    avg_secs_per_block: f64,
}
#[derive(Debug, Default)]
struct ThroughputArtifacts {
    recipe: Option<ThroughputArtifactRecipe>,
    slo: Option<ThroughputArtifactSlo>,
    metrics: Option<ThroughputArtifactMetrics>,
    realistic: Option<ThroughputArtifactRealistic>,
    warmup_metrics: Vec<PeerMetricsSnapshot>,
    after_metrics: Vec<PeerMetricsSnapshot>,
    samples: Vec<ThroughputSample>,
    fault_windows: Vec<Realistic30TpsFaultWindow>,
    status_recovery_samples: Vec<Realistic30TpsStatusRecoverySample>,
    catch_up_samples: Vec<Realistic30TpsCatchUpSample>,
    convergence_windows: Vec<Realistic30TpsConvergenceWindow>,
    error: Option<String>,
}
fn write_throughput_artifacts(
    artifact_root: &Path,
    network_dir: &Path,
    peer_logs: &[PeerLogInfo],
    artifacts: &ThroughputArtifacts,
) -> Result<PathBuf> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let run_dir = artifact_root.join(format!(
        "throughput-{}",
        u64::try_from(timestamp_ms).unwrap_or(u64::MAX)
    ));
    fs::create_dir_all(&run_dir).wrap_err("create throughput artifact dir")?;
    let metrics_dir = run_dir.join("metrics");
    fs::create_dir_all(&metrics_dir).wrap_err("create metrics dir")?;
    let logs_dir = run_dir.join("logs");
    fs::create_dir_all(&logs_dir).wrap_err("create logs dir")?;
    for snapshot in &artifacts.warmup_metrics {
        let path = metrics_dir.join(format!("{}-warmup.prom", snapshot.peer));
        fs::write(&path, &snapshot.payload)
            .wrap_err_with(|| format!("write warmup metrics {}", path.display()))?;
    }
    for snapshot in &artifacts.after_metrics {
        let path = metrics_dir.join(format!("{}-steady.prom", snapshot.peer));
        fs::write(&path, &snapshot.payload)
            .wrap_err_with(|| format!("write steady metrics {}", path.display()))?;
    }
    let status_samples_value = Value::Array(
        artifacts
            .samples
            .iter()
            .map(|sample| {
                let mut map = Map::new();
                if let Some(phase) = sample.phase.as_ref() {
                    map.insert("phase".to_string(), Value::String(phase.clone()));
                }
                map.insert("timestamp_ms".to_string(), Value::from(sample.timestamp_ms));
                map.insert(
                    "status".to_string(),
                    Value::Array(sample.statuses.iter().map(status_snapshot_value).collect()),
                );
                map.insert(
                    "sumeragi".to_string(),
                    Value::Array(
                        sample
                            .sumeragi
                            .iter()
                            .map(sumeragi_snapshot_value)
                            .collect(),
                    ),
                );
                Value::Object(map)
            })
            .collect(),
    );
    let status_path = run_dir.join("status_samples.json");
    let status_json = norito::json::to_json_pretty(&status_samples_value)
        .map_err(|err| eyre!(err.to_string()))?;
    fs::write(&status_path, status_json)
        .wrap_err_with(|| format!("write {}", status_path.display()))?;
    let config_fingerprint = config_fingerprint(network_dir)?;
    let mut summary = Map::new();
    summary.insert(
        "run_id".to_string(),
        Value::String(
            run_dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        ),
    );
    summary.insert(
        "timestamp_ms".to_string(),
        Value::from(u64::try_from(timestamp_ms).unwrap_or(u64::MAX)),
    );
    summary.insert(
        "network_dir".to_string(),
        Value::String(network_dir.to_string_lossy().to_string()),
    );
    summary.insert(
        "config_fingerprint".to_string(),
        config_fingerprint.map_or(Value::Null, Value::String),
    );
    if let Some(error) = artifacts.error.as_ref() {
        summary.insert("error".to_string(), Value::String(error.clone()));
    }
    if !artifacts.fault_windows.is_empty() {
        summary.insert(
            "fault_windows".to_string(),
            Value::Array(
                artifacts
                    .fault_windows
                    .iter()
                    .map(fault_window_value)
                    .collect(),
            ),
        );
    }
    if !artifacts.status_recovery_samples.is_empty() {
        summary.insert(
            "status_recovery_samples".to_string(),
            Value::Array(
                artifacts
                    .status_recovery_samples
                    .iter()
                    .map(status_recovery_sample_value)
                    .collect(),
            ),
        );
        summary.insert(
            "status_recovery_summary".to_string(),
            status_recovery_summary_value(&artifacts.status_recovery_samples),
        );
    }
    if !artifacts.catch_up_samples.is_empty() {
        summary.insert(
            "catch_up_samples".to_string(),
            Value::Array(
                artifacts
                    .catch_up_samples
                    .iter()
                    .map(catch_up_sample_value)
                    .collect(),
            ),
        );
    }
    if !artifacts.convergence_windows.is_empty() {
        summary.insert(
            "strict_convergence_windows".to_string(),
            Value::Array(
                artifacts
                    .convergence_windows
                    .iter()
                    .map(convergence_window_value)
                    .collect(),
            ),
        );
        summary.insert(
            "strict_convergence_summary".to_string(),
            convergence_summary_value(&artifacts.fault_windows, &artifacts.convergence_windows),
        );
    }
    if let Some(recipe) = artifacts.recipe.as_ref() {
        let mut recipe_map = Map::new();
        recipe_map.insert("peers".to_string(), Value::from(recipe.peers));
        recipe_map.insert(
            "signed_block_cadence_ms".to_string(),
            Value::from(recipe.block_cadence_ms),
        );
        recipe_map.insert(
            "block_max_txs".to_string(),
            Value::from(recipe.block_max_txs),
        );
        recipe_map.insert(
            "warmup_blocks".to_string(),
            Value::from(recipe.warmup_blocks),
        );
        recipe_map.insert(
            "steady_blocks".to_string(),
            Value::from(recipe.steady_blocks),
        );
        recipe_map.insert("total_blocks".to_string(), Value::from(recipe.total_blocks));
        recipe_map.insert("warmup_txs".to_string(), Value::from(recipe.warmup_txs));
        recipe_map.insert("steady_txs".to_string(), Value::from(recipe.steady_txs));
        recipe_map.insert("total_txs".to_string(), Value::from(recipe.total_txs));
        recipe_map.insert("submit_batch".to_string(), Value::from(recipe.submit_batch));
        recipe_map.insert(
            "submit_parallelism".to_string(),
            Value::from(recipe.submit_parallelism),
        );
        recipe_map.insert(
            "queue_soft_limit".to_string(),
            Value::from(recipe.queue_soft_limit),
        );
        recipe_map.insert(
            "payload_bytes".to_string(),
            Value::from(recipe.payload_bytes),
        );
        recipe_map.insert(
            "load_kind".to_string(),
            Value::from(recipe.load_kind.clone()),
        );
        recipe_map.insert(
            "transfer_accounts".to_string(),
            Value::from(recipe.transfer_accounts),
        );
        recipe_map.insert(
            "transfer_initial_balance".to_string(),
            Value::from(recipe.transfer_initial_balance),
        );
        recipe_map.insert(
            "transfer_max_amount".to_string(),
            Value::from(recipe.transfer_max_amount),
        );
        recipe_map.insert("rng_seed".to_string(), Value::from(recipe.rng_seed));
        recipe_map.insert(
            "snapshot_mode".to_string(),
            Value::from(recipe.snapshot_mode.clone()),
        );
        recipe_map.insert(
            "snapshot_create_every_ms".to_string(),
            Value::from(recipe.snapshot_create_every_ms),
        );
        summary.insert("recipe".to_string(), Value::Object(recipe_map));
    }
    if let Some(slo) = artifacts.slo.as_ref() {
        let mut slo_map = Map::new();
        slo_map.insert("commit_p95_ms".to_string(), Value::from(slo.commit_p95_ms));
        slo_map.insert("commit_p99_ms".to_string(), Value::from(slo.commit_p99_ms));
        slo_map.insert(
            "view_change_rate_max".to_string(),
            Value::from(slo.view_change_rate_max),
        );
        slo_map.insert(
            "queue_saturation_max".to_string(),
            Value::from(slo.queue_saturation_max),
        );
        summary.insert("slo".to_string(), Value::Object(slo_map));
    }
    if let Some(metrics) = artifacts.metrics.as_ref() {
        let mut metrics_map = Map::new();
        metrics_map.insert(
            "submitted_tps".to_string(),
            Value::from(metrics.submitted_tps),
        );
        metrics_map.insert(
            "committed_tps".to_string(),
            Value::from(metrics.committed_tps),
        );
        metrics_map.insert(
            "commit_p95_ms".to_string(),
            Value::from(metrics.commit_p95_ms),
        );
        metrics_map.insert(
            "commit_p99_ms".to_string(),
            Value::from(metrics.commit_p99_ms),
        );
        metrics_map.insert(
            "commit_hist_count".to_string(),
            Value::from(metrics.commit_hist_count),
        );
        metrics_map.insert(
            "commit_time_ms_min".to_string(),
            Value::from(metrics.commit_time_ms_min),
        );
        metrics_map.insert(
            "commit_time_ms_avg".to_string(),
            Value::from(metrics.commit_time_ms_avg),
        );
        metrics_map.insert(
            "commit_time_ms_max".to_string(),
            Value::from(metrics.commit_time_ms_max),
        );
        metrics_map.insert(
            "view_change_rate_avg".to_string(),
            Value::from(metrics.view_change_rate_avg),
        );
        metrics_map.insert(
            "view_change_rate_max".to_string(),
            Value::from(metrics.view_change_rate_max),
        );
        metrics_map.insert(
            "queue_saturated_frac".to_string(),
            Value::from(metrics.queue_saturated_frac),
        );
        metrics_map.insert(
            "max_queue_depth".to_string(),
            Value::from(metrics.max_queue_depth),
        );
        metrics_map.insert(
            "steady_elapsed_ms".to_string(),
            Value::from(metrics.steady_elapsed_ms),
        );
        metrics_map.insert(
            "warmup_submit_elapsed_ms".to_string(),
            Value::from(metrics.warmup_submit_elapsed_ms),
        );
        metrics_map.insert(
            "steady_submit_elapsed_ms".to_string(),
            Value::from(metrics.steady_submit_elapsed_ms),
        );
        summary.insert("metrics".to_string(), Value::Object(metrics_map));
    }
    if let Some(realistic) = artifacts.realistic.as_ref() {
        let mut realistic_map = Map::new();
        realistic_map.insert(
            "baseline_non_empty".to_string(),
            Value::from(realistic.baseline_non_empty),
        );
        realistic_map.insert(
            "baseline_approved".to_string(),
            Value::from(realistic.baseline_approved),
        );
        realistic_map.insert(
            "target_non_empty".to_string(),
            Value::from(realistic.target_non_empty),
        );
        realistic_map.insert(
            "target_approved".to_string(),
            Value::from(realistic.target_approved),
        );
        realistic_map.insert("submitted".to_string(), Value::from(realistic.submitted));
        realistic_map.insert(
            "load_sample_count".to_string(),
            Value::from(realistic.load_sample_count),
        );
        realistic_map.insert(
            "load_elapsed_ms".to_string(),
            Value::from(realistic.load_elapsed_ms),
        );
        realistic_map.insert(
            "submit_elapsed_ms".to_string(),
            Value::from(realistic.submit_elapsed_ms),
        );
        realistic_map.insert(
            "drain_elapsed_ms".to_string(),
            Value::from(realistic.drain_elapsed_ms),
        );
        realistic_map.insert(
            "total_elapsed_ms".to_string(),
            Value::from(realistic.total_elapsed_ms),
        );
        realistic_map.insert(
            "load_end".to_string(),
            throughput_status_summary_value(&realistic.load_end),
        );
        realistic_map.insert(
            "final".to_string(),
            throughput_status_summary_value(&realistic.final_status),
        );
        realistic_map.insert(
            "load_end_produced_blocks".to_string(),
            Value::from(realistic.load_end_produced_blocks),
        );
        realistic_map.insert(
            "produced_blocks".to_string(),
            Value::from(realistic.produced_blocks),
        );
        realistic_map.insert(
            "load_submitted_tps".to_string(),
            Value::from(realistic.load_submitted_tps),
        );
        realistic_map.insert(
            "load_committed_tps".to_string(),
            Value::from(realistic.load_committed_tps),
        );
        realistic_map.insert(
            "final_committed_tps".to_string(),
            Value::from(realistic.final_committed_tps),
        );
        realistic_map.insert(
            "load_avg_secs_per_block".to_string(),
            Value::from(realistic.load_avg_secs_per_block),
        );
        realistic_map.insert(
            "avg_secs_per_block".to_string(),
            Value::from(realistic.avg_secs_per_block),
        );
        summary.insert("realistic".to_string(), Value::Object(realistic_map));
    }
    let peer_logs_value: Vec<Value> = peer_logs
        .iter()
        .map(|peer| {
            let mut map = Map::new();
            let copied_stdout = copy_peer_log_into_artifacts(&logs_dir, peer, "stdout");
            let copied_stderr = copy_peer_log_into_artifacts(&logs_dir, peer, "stderr");
            map.insert("index".to_string(), Value::from(peer.index));
            map.insert("mnemonic".to_string(), Value::String(peer.mnemonic.clone()));
            map.insert(
                "stdout_log".to_string(),
                copied_stdout.map_or(Value::Null, Value::String),
            );
            map.insert(
                "stderr_log".to_string(),
                copied_stderr.map_or(Value::Null, Value::String),
            );
            map.insert(
                "stdout_log_original".to_string(),
                peer.stdout_log
                    .as_ref()
                    .map_or(Value::Null, |path| Value::String(path.clone())),
            );
            map.insert(
                "stderr_log_original".to_string(),
                peer.stderr_log
                    .as_ref()
                    .map_or(Value::Null, |path| Value::String(path.clone())),
            );
            Value::Object(map)
        })
        .collect();
    summary.insert("peer_logs".to_string(), Value::Array(peer_logs_value));
    summary.insert(
        "status_samples_path".to_string(),
        Value::String(status_path.to_string_lossy().to_string()),
    );
    summary.insert(
        "metrics_dir".to_string(),
        Value::String(metrics_dir.to_string_lossy().to_string()),
    );
    let summary_value = Value::Object(summary);
    let summary_path = run_dir.join("summary.json");
    let summary_json =
        norito::json::to_json_pretty(&summary_value).map_err(|err| eyre!(err.to_string()))?;
    fs::write(&summary_path, summary_json)
        .wrap_err_with(|| format!("write {}", summary_path.display()))?;
    Ok(run_dir)
}
fn copy_peer_log_into_artifacts(
    logs_dir: &Path,
    peer: &PeerLogInfo,
    stream: &'static str,
) -> Option<String> {
    let source = match stream {
        "stdout" => peer.stdout_log.as_ref(),
        "stderr" => peer.stderr_log.as_ref(),
        _ => None,
    }?;
    let source_path = Path::new(source);
    if !source_path.is_file() {
        return Some(source.clone());
    }
    let file_name = peer_log_artifact_file_name(peer.index, &peer.mnemonic, stream);
    let dest = logs_dir.join(file_name);
    if let Err(err) = fs::copy(source_path, &dest) {
        eprintln!(
            "failed to copy peer {stream} log for {} from {} to {}: {err:?}",
            peer.mnemonic,
            source_path.display(),
            dest.display()
        );
        return Some(source.clone());
    }
    Some(dest.to_string_lossy().to_string())
}
fn peer_log_artifact_file_name(index: u64, mnemonic: &str, stream: &str) -> String {
    let mut sanitized: String = mnemonic
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        sanitized.push_str("peer");
    }
    format!("{index}-{sanitized}-{stream}.log")
}
#[derive(Clone, Debug, Default)]
struct HistogramSnapshot {
    buckets: Vec<(f64, u64)>,
    sum: f64,
    count: u64,
}
impl HistogramSnapshot {
    #[allow(clippy::float_cmp)]
    fn saturating_sub(&self, baseline: &Self) -> Self {
        let buckets = self
            .buckets
            .iter()
            .map(|(le, count)| {
                let base = baseline
                    .buckets
                    .iter()
                    .find_map(|(base_le, base_count)| (*base_le == *le).then_some(*base_count))
                    .unwrap_or(0);
                (*le, count.saturating_sub(base))
            })
            .collect();
        let sum = (self.sum - baseline.sum).max(0.0);
        let count = self.count.saturating_sub(baseline.count);
        Self {
            buckets,
            sum,
            count,
        }
    }
    #[allow(clippy::cast_precision_loss)]
    fn quantile(&self, quantile: f64) -> Option<f64> {
        if !(0.0..=1.0).contains(&quantile) || self.count == 0 {
            return None;
        }
        let mut buckets = self.buckets.clone();
        buckets.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
        let target = (quantile * self.count as f64).ceil();
        let mut prev_count = 0_u64;
        let mut prev_le = 0.0;
        for (le, count) in buckets {
            if (count as f64) >= target {
                if le.is_infinite() {
                    return Some(prev_le);
                }
                let bucket_count = count.saturating_sub(prev_count);
                if bucket_count == 0 {
                    return Some(le);
                }
                let ratio = (target - prev_count as f64) / bucket_count as f64;
                return Some((le - prev_le).mul_add(ratio, prev_le));
            }
            prev_count = count;
            prev_le = le;
        }
        Some(prev_le)
    }
}
#[derive(Clone, Debug)]
struct PeerMetricsSnapshot {
    peer: String,
    payload: String,
    commit_time_hist: HistogramSnapshot,
}
#[allow(clippy::float_cmp, single_use_lifetimes)]
fn aggregate_histograms<'a>(
    histograms: impl IntoIterator<Item = &'a HistogramSnapshot>,
) -> HistogramSnapshot {
    let mut buckets: Vec<(f64, u64)> = Vec::new();
    let mut sum = 0.0;
    let mut count = 0_u64;
    for hist in histograms {
        sum += hist.sum;
        count = count.saturating_add(hist.count);
        for (le, bucket_count) in &hist.buckets {
            if let Some(entry) = buckets.iter_mut().find(|(bound, _)| *bound == *le) {
                entry.1 = entry.1.saturating_add(*bucket_count);
            } else {
                buckets.push((*le, *bucket_count));
            }
        }
    }
    buckets.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
    HistogramSnapshot {
        buckets,
        sum,
        count,
    }
}
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_cmp
)]
fn parse_prom_histogram(payload: &str, metric: &str) -> HistogramSnapshot {
    let mut buckets: Vec<(f64, u64)> = Vec::new();
    let mut sum = 0.0;
    let mut count = 0_u64;
    let bucket_prefix = format!("{metric}_bucket");
    let sum_prefix = format!("{metric}_sum");
    let count_prefix = format!("{metric}_count");
    for line in payload.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let name = match parts.next() {
            Some(name) => name,
            None => continue,
        };
        let value_raw = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        if name.starts_with(&bucket_prefix) {
            let le = name.find("le=\"").and_then(|pos| {
                let rest = &name[pos + 4..];
                rest.find('"').and_then(|end| {
                    let value = &rest[..end];
                    if value == "+Inf" {
                        Some(f64::INFINITY)
                    } else {
                        value.parse::<f64>().ok()
                    }
                })
            });
            let le = match le {
                Some(value) => value,
                None => continue,
            };
            let value = value_raw
                .parse::<u64>()
                .ok()
                .or_else(|| value_raw.parse::<f64>().ok().map(|v| v.round() as u64));
            if let Some(value) = value {
                if let Some(entry) = buckets.iter_mut().find(|(bound, _)| *bound == le) {
                    entry.1 = value;
                } else {
                    buckets.push((le, value));
                }
            }
        } else if name.starts_with(&sum_prefix) {
            if let Ok(value) = value_raw.parse::<f64>() {
                sum = value;
            }
        } else if name.starts_with(&count_prefix) {
            if let Ok(value) = value_raw.parse::<f64>() {
                count = value.round() as u64;
            } else if let Ok(value) = value_raw.parse::<u64>() {
                count = value;
            }
        }
    }
    buckets.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
    HistogramSnapshot {
        buckets,
        sum,
        count,
    }
}
fn metrics_url(torii_url: &str) -> String {
    if torii_url.ends_with("/metrics") {
        torii_url.to_string()
    } else if torii_url.ends_with('/') {
        format!("{torii_url}metrics")
    } else {
        format!("{torii_url}/metrics")
    }
}
fn throughput_payload(index: u64, payload_bytes: usize, seed: u64) -> String {
    let prefix = format!("localnet throughput {index} ");
    let mut payload = String::with_capacity(payload_bytes.max(prefix.len()));
    payload.push_str(&prefix);
    if payload.len() < payload_bytes {
        let mut rng = ChaCha8Rng::seed_from_u64(seed ^ index);
        let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let remaining = payload_bytes - payload.len();
        for _ in 0..remaining {
            let idx = (rng.next_u32() as usize) % alphabet.len();
            payload.push(alphabet[idx] as char);
        }
    }
    if payload.len() > payload_bytes {
        payload.truncate(payload_bytes);
    }
    payload
}
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn commit_time_quantiles(
    warmup: &[PeerMetricsSnapshot],
    steady: &[PeerMetricsSnapshot],
) -> (Option<u64>, Option<u64>, u64) {
    if warmup.is_empty() && steady.is_empty() {
        return (None, None, 0);
    }
    let warmup_hist = aggregate_histograms(warmup.iter().map(|s| &s.commit_time_hist));
    let steady_hist = aggregate_histograms(steady.iter().map(|s| &s.commit_time_hist));
    let delta = steady_hist.saturating_sub(&warmup_hist);
    let p95 = delta.quantile(0.95).map(|v| v.round() as u64);
    let p99 = delta.quantile(0.99).map(|v| v.round() as u64);
    (p95, p99, delta.count)
}
#[allow(clippy::cast_precision_loss)]
fn rate_summary(start: &[u64], end: &[u64], elapsed: Duration) -> (f64, f64) {
    let count = start.len().min(end.len());
    let secs = elapsed.as_secs_f64();
    if count == 0 || secs <= 0.0 {
        return (0.0, 0.0);
    }
    let mut sum = 0.0;
    let mut max_rate = 0.0;
    for (start, end) in start.iter().zip(end.iter()).take(count) {
        let delta = end.saturating_sub(*start) as f64 / secs;
        sum += delta;
        if delta > max_rate {
            max_rate = delta;
        }
    }
    (sum / count as f64, max_rate)
}
fn rate_per_second(count: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    count as f64 / secs
}
fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
fn seconds_per_block(elapsed: Duration, blocks: u64) -> f64 {
    if blocks == 0 {
        return 0.0;
    }
    elapsed.as_secs_f64() / blocks as f64
}
fn realistic_target_blocks(
    configured_target_blocks: u64,
    total_txs: u64,
    block_max_txs: u64,
) -> u64 {
    if block_max_txs == 0 {
        return configured_target_blocks;
    }
    configured_target_blocks.max(total_txs.div_ceil(block_max_txs))
}
fn max_queue_size_for_phase(samples: &[ThroughputSample], phase: &str) -> u64 {
    samples
        .iter()
        .filter(|sample| sample.phase.as_deref() == Some(phase))
        .flat_map(|sample| sample.statuses.iter().map(|status| status.queue_size))
        .max()
        .unwrap_or_default()
}
#[allow(clippy::too_many_arguments)]
fn realistic_artifact_summary(
    baseline_non_empty: u64,
    baseline_approved: u64,
    target_non_empty: u64,
    target_approved: u64,
    submitted: u64,
    submit_elapsed: Duration,
    load_elapsed: Duration,
    total_elapsed: Duration,
    load_end: ThroughputStatusSummary,
    final_status: ThroughputStatusSummary,
    load_end_produced_blocks: u64,
    produced_blocks: u64,
    samples: &[ThroughputSample],
) -> ThroughputArtifactRealistic {
    let drain_elapsed = total_elapsed.saturating_sub(load_elapsed);
    let load_committed = load_end.min_txs_approved.saturating_sub(baseline_approved);
    let final_committed = final_status
        .min_txs_approved
        .saturating_sub(baseline_approved);
    ThroughputArtifactRealistic {
        baseline_non_empty,
        baseline_approved,
        target_non_empty,
        target_approved,
        submitted,
        load_sample_count: samples
            .iter()
            .filter(|sample| sample.phase.as_deref() == Some("load"))
            .count() as u64,
        load_elapsed_ms: duration_millis_u64(load_elapsed),
        submit_elapsed_ms: duration_millis_u64(submit_elapsed),
        drain_elapsed_ms: duration_millis_u64(drain_elapsed),
        total_elapsed_ms: duration_millis_u64(total_elapsed),
        load_end,
        final_status,
        load_end_produced_blocks,
        produced_blocks,
        load_submitted_tps: rate_per_second(submitted, submit_elapsed),
        load_committed_tps: rate_per_second(load_committed, load_elapsed),
        final_committed_tps: rate_per_second(final_committed, total_elapsed),
        load_avg_secs_per_block: seconds_per_block(load_elapsed, load_end_produced_blocks),
        avg_secs_per_block: seconds_per_block(total_elapsed, produced_blocks),
    }
}
include!("sumeragi_localnet_smoke/config_paths.rs");
