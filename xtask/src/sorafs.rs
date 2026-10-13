//! SoraFS fixture generation, gateway operations and developer command support.
use crate::{JsonTarget, write_json_output};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use blake3::hash as blake3_hash;
use eyre::{WrapErr, eyre};
use integration_tests::sorafs_gateway_conformance::HarnessContext;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{
    Algorithm, BlsNormal, Hash, KeyGenOption, KeyPair, PrivateKey, PublicKey, Signature,
};
use iroha_data_model::{
    account::AccountAddress,
    isi::sorafs::{
        ApprovePinManifest, BindManifestAlias, CompleteReplicationOrder, IssueReplicationOrder,
        RegisterPinManifest, SetProviderIngestCompletionAuthority,
    },
    prelude::*,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ChunkerProfileHandle, ManifestAliasBinding, ManifestAliasId, ManifestAliasRecord,
            ManifestDigest, ManifestRootCid, PinManifestRecord, PinStatus,
            ProviderIngestCompletionAuthorityV1, ProviderIngestCompletionSignerPolicyV1,
            ProviderIngestFinalizedAnchorV1, ReplicationOrderId, ReplicationOrderRecord,
            ReplicationOrderStatus, StorageClass,
        },
        reserve::{ReserveDuration, ReservePolicyV1, ReserveQuote, ReserveTier},
    },
};
use iroha_model_base::domain::DomainId;
use iroha_primitives::json::Json as IrohaJson;
use iroha_torii::sorafs::gateway::AcmeConfig;
use mv::storage::StorageReadOnly;
use norito::{
    decode_from_bytes,
    derive::JsonSerialize,
    json::{self, Map, Number, Value, to_string_pretty},
    to_bytes,
};
use reqwest::{
    Url,
    blocking::Client,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use sha2::{Digest, Sha256};
use sorafs_car::chunker_registry::{self, ChunkerProfileDescriptor};
use sorafs_chunker::fixtures::{FixtureProfile, to_hex};
use sorafs_manifest::{
    AdmissionRecord, AdvertEndpoint, AliasBindingV1, AvailabilityTier, CapabilityTlv,
    CapabilityType, CouncilSignature, DagCodecId, EndpointAdmissionV1, EndpointAttestationKind,
    EndpointAttestationV1, EndpointKind, GatewayAuthorizationRecord, GatewayAuthorizationVerifier,
    MANIFEST_DAG_CODEC, ManifestBuilder, PathDiversityPolicy, ProviderAdmissionCouncilPolicy,
    ProviderAdmissionEnvelopeV1, ProviderAdmissionProposalV1, ProviderAdvertBodyV1,
    ProviderAdvertV1, ProviderCapabilityRangeV1, ProviderVrfPublicKeyV1, QosHints,
    REPLICATION_ORDER_VERSION_V1, RendezvousTopic, ReplicationAssignmentV1, ReplicationOrderSlaV1,
    ReplicationOrderV1, SignatureAlgorithm, StakePointer, StreamBudgetV1, TransportHintV1,
    TransportProtocol,
    alias_cache::{
        AliasCachePolicy, AliasProofEvaluation, AliasProofState,
        decode_alias_proof_untrusted_signers,
    },
    compute_advert_body_digest, compute_envelope_authorization_digest, compute_envelope_digest,
    compute_proposal_digest,
    deal::{MICRO_XOR_PER_XOR, XorQuantity},
    pin_registry::{AliasProofBundleV1, alias_merkle_root, alias_proof_signature_digest},
    verify_advert_against_record,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    convert::{TryFrom, TryInto},
    error::Error,
    fs,
    io::{self, Write},
    num::NonZeroU64,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
#[derive(Clone, Debug)]
pub struct ReserveMatrixOptions {
    pub capacities_gib: Vec<u64>,
    pub storage_classes: Vec<StorageClass>,
    pub tiers: Vec<ReserveTier>,
    pub durations: Vec<ReserveDuration>,
    pub reserve_balance: XorQuantity,
    pub policy_json: Option<PathBuf>,
    pub policy_norito: Option<PathBuf>,
    pub label: Option<String>,
}
pub fn parse_storage_class_label(input: &str) -> eyre::Result<StorageClass> {
    match input.trim().to_ascii_lowercase().as_str() {
        "hot" => Ok(StorageClass::Hot),
        "warm" => Ok(StorageClass::Warm),
        "cold" => Ok(StorageClass::Cold),
        other => Err(eyre!(
            "unknown storage class `{other}` (expected hot|warm|cold)"
        )),
    }
}
pub fn parse_reserve_tier_label(input: &str) -> eyre::Result<ReserveTier> {
    match input.trim().to_ascii_lowercase().as_str() {
        "tier-a" | "a" => Ok(ReserveTier::TierA),
        "tier-b" | "b" => Ok(ReserveTier::TierB),
        "tier-c" | "c" => Ok(ReserveTier::TierC),
        other => Err(eyre!(
            "unknown reserve tier `{other}` (expected tier-a|tier-b|tier-c)"
        )),
    }
}
pub fn parse_reserve_duration_label(input: &str) -> eyre::Result<ReserveDuration> {
    match input.trim().to_ascii_lowercase().as_str() {
        "monthly" => Ok(ReserveDuration::Monthly),
        "quarterly" => Ok(ReserveDuration::Quarterly),
        "annual" | "yearly" => Ok(ReserveDuration::Annual),
        other => Err(eyre!(
            "unknown reserve duration `{other}` (expected monthly|quarterly|annual)"
        )),
    }
}
pub fn parse_xor_amount_decimal(input: &str) -> eyre::Result<XorQuantity> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(eyre!("reserve balance must not be empty"));
    }
    if trimmed.starts_with('-') {
        return Err(eyre!("reserve balance must be non-negative"));
    }
    let mut parts = trimmed.split('.');
    let whole_part = parts.next().unwrap_or("");
    let fractional_part = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err(eyre!(
            "reserve balance may contain at most one decimal separator"
        ));
    }
    if whole_part.is_empty() && fractional_part.is_empty() {
        return Err(eyre!("reserve balance must contain digits"));
    }
    if !whole_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(eyre!("reserve balance contains invalid characters"));
    }
    if !fractional_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(eyre!("reserve balance fractional part is invalid"));
    }
    if fractional_part.len() > 6 {
        return Err(eyre!(
            "reserve balance supports up to six fractional digits (micro XOR precision)"
        ));
    }
    let whole_value = if whole_part.is_empty() {
        0
    } else {
        whole_part
            .parse::<u128>()
            .wrap_err("failed to parse whole-number component")?
    };
    let mut fractional_value = 0u128;
    let mut digits = 0;
    for ch in fractional_part.chars() {
        digits += 1;
        fractional_value = fractional_value * 10 + u128::from(ch as u8 - b'0');
    }
    if digits > 0 {
        for _ in digits..6 {
            fractional_value *= 10;
        }
    }
    let base = whole_value
        .checked_mul(MICRO_XOR_PER_XOR)
        .ok_or_else(|| eyre!("reserve balance exceeds supported range"))?;
    let total = base
        .checked_add(fractional_value)
        .ok_or_else(|| eyre!("reserve balance exceeds supported range"))?;
    Ok(XorQuantity::try_from_micro(total).expect("legacy micro-XOR value is representable"))
}
const fn storage_class_label(class: StorageClass) -> &'static str {
    match class {
        StorageClass::Hot => "hot",
        StorageClass::Warm => "warm",
        StorageClass::Cold => "cold",
    }
}
const fn reserve_tier_label(tier: ReserveTier) -> &'static str {
    match tier {
        ReserveTier::TierA => "tier-a",
        ReserveTier::TierB => "tier-b",
        ReserveTier::TierC => "tier-c",
    }
}
const fn reserve_duration_label(duration: ReserveDuration) -> &'static str {
    match duration {
        ReserveDuration::Monthly => "monthly",
        ReserveDuration::Quarterly => "quarterly",
        ReserveDuration::Annual => "annual",
    }
}
pub fn reserve_matrix_report(options: ReserveMatrixOptions) -> Result<json::Value, Box<dyn Error>> {
    if options.capacities_gib.is_empty() {
        return Err(eyre!("reserve matrix requires at least one --capacity").into());
    }
    if options.storage_classes.is_empty() {
        return Err(eyre!("reserve matrix requires at least one --storage-class").into());
    }
    if options.tiers.is_empty() {
        return Err(eyre!("reserve matrix requires at least one --tier").into());
    }
    if options.durations.is_empty() {
        return Err(eyre!("reserve matrix requires at least one --duration").into());
    }
    let (policy, policy_source) = load_reserve_policy_from_paths(
        options.policy_json.as_deref(),
        options.policy_norito.as_deref(),
    )?;
    let policy_bytes =
        to_bytes(&policy).map_err(|err| eyre!("failed to encode reserve policy: {err}"))?;
    let policy_sha256 = hex::encode(Sha256::digest(&policy_bytes));
    let reserve_balance_micro = u64::try_from(
        options
            .reserve_balance
            .try_to_micro()
            .expect("XOR quantity has exact legacy micro representation"),
    )
    .map_err(|_| eyre!("reserve balance exceeds supported range"))?;
    let mut matrix_entries = Vec::new();
    for &storage_class in &options.storage_classes {
        for &tier in &options.tiers {
            for &duration in &options.durations {
                for &capacity in &options.capacities_gib {
                    let quote = policy
                        .quote(
                            storage_class,
                            capacity,
                            duration,
                            tier,
                            options.reserve_balance.clone(),
                        )
                        .map_err(|err| {
                            eyre!(
                                "failed to compute reserve quote for storage_class={:?} tier={:?} duration={:?} capacity_gib={}: {err}",
                                storage_class,
                                tier,
                                duration,
                                capacity
                            )
                        })?;
                    let entry = build_matrix_entry_value(
                        storage_class,
                        tier,
                        duration,
                        capacity,
                        &options.reserve_balance,
                        &quote,
                    )?;
                    matrix_entries.push(entry);
                }
            }
        }
    }
    let mut payload = json::Map::new();
    payload.insert(
        "capacities_gib".into(),
        json::Value::Array(
            options
                .capacities_gib
                .iter()
                .map(|c| json::Value::from(*c))
                .collect(),
        ),
    );
    payload.insert(
        "storage_classes".into(),
        json::Value::Array(
            options
                .storage_classes
                .iter()
                .map(|class| json::Value::from(storage_class_label(*class)))
                .collect(),
        ),
    );
    payload.insert(
        "tiers".into(),
        json::Value::Array(
            options
                .tiers
                .iter()
                .map(|tier| json::Value::from(reserve_tier_label(*tier)))
                .collect(),
        ),
    );
    payload.insert(
        "durations".into(),
        json::Value::Array(
            options
                .durations
                .iter()
                .map(|duration| json::Value::from(reserve_duration_label(*duration)))
                .collect(),
        ),
    );
    payload.insert(
        "reserve_balance_micro_xor".into(),
        json::Value::from(reserve_balance_micro),
    );
    payload.insert(
        "policy_json".into(),
        options
            .policy_json
            .as_ref()
            .map(|p| json::Value::from(p.display().to_string()))
            .unwrap_or(json::Value::Null),
    );
    payload.insert(
        "policy_norito".into(),
        options
            .policy_norito
            .as_ref()
            .map(|p| json::Value::from(p.display().to_string()))
            .unwrap_or(json::Value::Null),
    );
    payload.insert(
        "label".into(),
        options
            .label
            .map(json::Value::from)
            .unwrap_or(json::Value::Null),
    );
    payload.insert(
        "policy_version".into(),
        json::Value::from(u64::from(policy.version)),
    );
    payload.insert("policy_sha256".into(), json::Value::from(policy_sha256));
    payload.insert("policy_source".into(), json::Value::from(policy_source));
    payload.insert(
        "matrix_entry_count".into(),
        json::Value::from(matrix_entries.len() as u64),
    );
    payload.insert("matrix".into(), json::Value::Array(matrix_entries));
    Ok(json::Value::Object(payload))
}
fn load_reserve_policy_from_paths(
    json_path: Option<&Path>,
    norito_path: Option<&Path>,
) -> Result<(ReservePolicyV1, String), Box<dyn Error>> {
    match (json_path, norito_path) {
        (Some(_), Some(_)) => {
            Err(eyre!("only one of --policy-json or --policy-norito may be supplied").into())
        }
        (Some(path), None) => {
            let contents = fs::read_to_string(path).map_err(|err| {
                eyre!(
                    "failed to read reserve policy JSON `{}`: {err}",
                    path.display()
                )
            })?;
            let policy: ReservePolicyV1 = json::from_str(&contents).map_err(|err| {
                eyre!(
                    "failed to parse reserve policy JSON `{}`: {err}",
                    path.display()
                )
            })?;
            Ok((policy, format!("policy JSON `{}`", path.display())))
        }
        (None, Some(path)) => {
            let bytes = fs::read(path).map_err(|err| {
                eyre!(
                    "failed to read reserve policy Norito `{}`: {err}",
                    path.display()
                )
            })?;
            let policy = decode_from_bytes::<ReservePolicyV1>(&bytes).map_err(|err| {
                eyre!(
                    "failed to decode reserve policy Norito `{}`: {err}",
                    path.display()
                )
            })?;
            Ok((policy, format!("policy Norito `{}`", path.display())))
        }
        (None, None) => Ok((
            ReservePolicyV1::default(),
            "embedded default policy".to_string(),
        )),
    }
}
fn build_matrix_entry_value(
    storage_class: StorageClass,
    tier: ReserveTier,
    duration: ReserveDuration,
    capacity_gib: u64,
    reserve_balance: &XorQuantity,
    quote: &ReserveQuote,
) -> Result<json::Value, Box<dyn Error>> {
    let inputs_value =
        matrix_inputs_value(storage_class, tier, duration, capacity_gib, reserve_balance)?;
    let quote_value = json::to_value(quote)
        .map_err(|err| eyre!("failed to serialize reserve quote JSON: {err}"))?;
    let projection = quote.ledger_projection().map_err(|err| {
        eyre!(
            "failed to project reserve quote for storage_class={:?} tier={:?} duration={:?} capacity_gib={}: {err}",
            storage_class,
            tier,
            duration,
            capacity_gib
        )
    })?;
    let projection_value = json::to_value(&projection)
        .map_err(|err| eyre!("failed to serialize reserve ledger projection: {err}"))?;
    let mut entry = json::Map::new();
    entry.insert(
        "storage_class".into(),
        json::Value::from(storage_class_label(storage_class)),
    );
    entry.insert("tier".into(), json::Value::from(reserve_tier_label(tier)));
    entry.insert(
        "duration".into(),
        json::Value::from(reserve_duration_label(duration)),
    );
    entry.insert("capacity_gib".into(), json::Value::from(capacity_gib));
    entry.insert("inputs".into(), inputs_value);
    entry.insert("quote".into(), quote_value);
    entry.insert("ledger_projection".into(), projection_value);
    Ok(json::Value::Object(entry))
}
fn matrix_inputs_value(
    storage_class: StorageClass,
    tier: ReserveTier,
    duration: ReserveDuration,
    capacity_gib: u64,
    reserve_balance: &XorQuantity,
) -> Result<json::Value, Box<dyn Error>> {
    let mut inputs = json::Map::new();
    inputs.insert(
        "storage_class".into(),
        json::Value::from(storage_class_label(storage_class)),
    );
    inputs.insert("tier".into(), json::Value::from(reserve_tier_label(tier)));
    inputs.insert(
        "duration".into(),
        json::Value::from(reserve_duration_label(duration)),
    );
    inputs.insert("capacity_gib".into(), json::Value::from(capacity_gib));
    let reserve_value = json::to_value(reserve_balance)
        .map_err(|err| eyre!("failed to serialize reserve balance: {err}"))?;
    inputs.insert("reserve_balance".into(), reserve_value);
    Ok(json::Value::Object(inputs))
}
/// Multi-provider rollout evidence and qualification commands.
pub mod adoption;
mod gateway_fixture;
const DEFAULT_PROFILE_HANDLE: &str = "sorafs.sf1@1.0.0";
#[derive(Clone)]
pub struct FetchFixtureOptions {
    pub signatures_source: FetchSource,
    pub manifest_source: Option<FetchSource>,
    pub output_dir: PathBuf,
    pub profile_handle: String,
    pub allow_unsigned: bool,
}
#[derive(Clone)]
pub enum FetchSource {
    File(PathBuf),
    Url(Url),
}
#[derive(Clone)]
pub struct GatewayAttestOptions {
    pub output_dir: PathBuf,
    pub signing_key_path: PathBuf,
    pub signer_account: String,
    pub gateway_target: Option<String>,
}
#[derive(Clone)]
pub struct GatewayProbeOptions {
    pub request: Option<GatewayProbeRequest>,
    pub headers_path: Option<PathBuf>,
    pub gar_path: PathBuf,
    pub gar_keys: Vec<(String, Vec<u8>)>,
    pub cache_max_age: Option<u64>,
    pub cache_swr: Option<u64>,
    pub now_override: Option<u64>,
    pub host_override: Option<String>,
    pub require_tls_state: bool,
    pub report_target: Option<JsonTarget>,
    pub summary_path: Option<PathBuf>,
    pub drill: Option<DrillLogConfig>,
    pub pagerduty: Option<PagerDutyConfig>,
}
#[derive(Clone)]
pub struct DrillLogConfig {
    pub log_path: PathBuf,
    pub scenario: String,
    pub ic: Option<String>,
    pub scribe: Option<String>,
    pub notes: Option<String>,
    pub link: Option<String>,
}
#[derive(Clone)]
pub struct PagerDutyConfig {
    pub payload_path: PathBuf,
    pub routing_key: String,
    pub severity: String,
    pub source: String,
    pub component: Option<String>,
    pub group: Option<String>,
    pub class_name: Option<String>,
    pub dedup_key: Option<String>,
    pub links: Vec<PagerDutyLink>,
    pub endpoint_url: Option<Url>,
}
#[derive(Clone)]
pub struct PagerDutyLink {
    pub text: String,
    pub href: String,
}
#[derive(Clone)]
pub struct GatewayProbeRequest {
    pub url: String,
    pub method: String,
    pub timeout_secs: Option<u64>,
    pub extra_headers: Vec<(String, String)>,
}
#[derive(Debug)]
pub enum GatewayCliCommand {
    TlsRenew(GatewayTlsRenewOptions),
    TlsRevoke(GatewayTlsRevokeOptions),
    KeyRotate(GatewayKeyRotateOptions),
    RoutePlan(Box<GatewayRoutePlanOptions>),
}
#[derive(Debug, Clone)]
pub struct GatewayTlsRenewOptions {
    pub hostnames: Vec<String>,
    pub account_email: Option<String>,
    pub directory_url: String,
    pub dns_provider_id: Option<String>,
    pub output_dir: PathBuf,
    pub force: bool,
}
#[derive(Debug, Clone)]
pub struct GatewayTlsRevokeOptions {
    pub bundle_dir: PathBuf,
    pub archive_dir: Option<PathBuf>,
    pub reason: Option<String>,
    pub force: bool,
}
#[derive(Debug, Clone)]
pub struct GatewayKeyRotateOptions {
    pub kind: String,
    pub output_path: PathBuf,
    pub public_out: Option<PathBuf>,
    pub force: bool,
}
#[derive(Debug, Clone)]
pub struct GatewayRoutePlanOptions {
    pub manifest_json: PathBuf,
    pub output_path: PathBuf,
    pub headers_out: Option<PathBuf>,
    pub alias: Option<String>,
    pub hostname: Option<String>,
    pub route_label: Option<String>,
    pub proof_status: Option<String>,
    pub release_tag: Option<String>,
    pub cutover_window: Option<String>,
    pub rollback_manifest: Option<PathBuf>,
    pub rollback_headers_out: Option<PathBuf>,
    pub rollback_route_label: Option<String>,
    pub rollback_release_tag: Option<String>,
    pub include_csp: bool,
    pub include_permissions: bool,
    pub include_hsts: bool,
    pub now: OffsetDateTime,
}
#[derive(Debug, JsonSerialize)]
struct GatewayRoutePlan {
    version: u32,
    generated_at: String,
    manifest_json: String,
    alias: Option<String>,
    hostname: Option<String>,
    release_tag: Option<String>,
    cutover_window: Option<String>,
    content_cid: String,
    route_binding: String,
    headers: BTreeMap<String, String>,
    headers_template: String,
    headers_path: Option<String>,
    rollback: Option<GatewayRouteRollback>,
}
#[derive(Debug, JsonSerialize)]
struct GatewayRouteRollback {
    manifest_json: String,
    release_tag: Option<String>,
    content_cid: String,
    route_binding: String,
    headers_template: String,
    headers_path: Option<String>,
}
#[derive(Debug)]
struct RouteBindingContext {
    manifest_json: PathBuf,
    alias: Option<String>,
    hostname: Option<String>,
    route_label: Option<String>,
    proof_status: Option<String>,
    include_csp: bool,
    include_permissions: bool,
    include_hsts: bool,
    generated_at: OffsetDateTime,
}
struct RouteBindingOutput {
    content_cid: String,
    route_binding: String,
    headers: BTreeMap<String, String>,
    headers_template: String,
}
#[derive(Debug)]
pub struct GatewayTlsRenewOutcome {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub ech_config_path: PathBuf,
    pub fingerprint_hex: String,
    pub expiry_rfc3339: String,
    pub hostnames: Vec<String>,
}
pub struct GatewayTlsRevokeOutcome {
    pub archive_dir: PathBuf,
    pub archived_files: Vec<PathBuf>,
    pub timestamp_epoch: u64,
    pub reason: Option<String>,
}
pub struct GatewayKeyRotateOutcome {
    pub private_key_path: PathBuf,
    pub public_key_hex: String,
    pub public_key_prefixed: String,
    pub public_out_path: Option<PathBuf>,
}
pub fn parse_gateway_cli<I>(args: I) -> Result<GatewayCliCommand, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut iter = args.into_iter();
    let Some(subcommand) = iter.next() else {
        gateway_cli_usage();
        return Err("sorafs-gateway requires a subcommand (tls|key|route)".into());
    };
    match subcommand.as_str() {
        "tls" => {
            let remaining: Vec<String> = iter.collect();
            parse_gateway_tls_cli(remaining)
        }
        "route" => {
            let remaining: Vec<String> = iter.collect();
            parse_gateway_route_cli(remaining)
        }
        "key" => {
            let remaining: Vec<String> = iter.collect();
            parse_gateway_key_cli(remaining)
        }
        "-h" | "--help" => {
            gateway_cli_usage();
            Err("sorafs-gateway usage displayed".into())
        }
        other => {
            gateway_cli_usage();
            Err(format!("unknown sorafs-gateway subcommand `{other}`").into())
        }
    }
}
pub fn run_gateway_cli(command: GatewayCliCommand) -> Result<(), Box<dyn Error>> {
    match command {
        GatewayCliCommand::TlsRenew(options) => {
            let outcome = gateway_tls_renew(options)?;
            println!("generated TLS bundle:");
            println!("  hosts        : {}", outcome.hostnames.join(", "));
            println!("  fingerprint  : {}", outcome.fingerprint_hex);
            println!("  not_after    : {}", outcome.expiry_rfc3339);
            println!("  certificate  : {}", outcome.certificate_path.display());
            println!("  private key  : {}", outcome.private_key_path.display());
            println!("  ech config   : {}", outcome.ech_config_path.display());
        }
        GatewayCliCommand::TlsRevoke(options) => {
            let outcome = gateway_tls_revoke(options)?;
            println!("archived TLS bundle:");
            println!("  archive dir : {}", outcome.archive_dir.display());
            println!("  timestamp   : {}", outcome.timestamp_epoch);
            if let Some(reason) = outcome.reason.as_deref() {
                println!("  reason      : {reason}");
            }
            for path in &outcome.archived_files {
                println!("  archived    : {}", path.display());
            }
        }
        GatewayCliCommand::KeyRotate(options) => {
            let outcome = gateway_key_rotate(options)?;
            println!("generated token-signing key:");
            println!("  private key : {}", outcome.private_key_path.display());
            println!("  public hex  : {}", outcome.public_key_hex);
            println!("  public mh   : {}", outcome.public_key_prefixed);
            if let Some(path) = outcome.public_out_path {
                println!("  public file : {}", path.display());
            }
        }
        GatewayCliCommand::RoutePlan(options) => {
            run_gateway_route_plan(*options)?;
        }
    }
    Ok(())
}
fn parse_gateway_tls_cli<I>(args: I) -> Result<GatewayCliCommand, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut iter = args.into_iter();
    let Some(action) = iter.next() else {
        gateway_cli_usage();
        return Err("sorafs-gateway tls requires an action (renew|revoke)".into());
    };
    match action.as_str() {
        "renew" => {
            let mut hostnames = Vec::new();
            let mut host_files = Vec::new();
            let mut account_email = None;
            let mut directory_url = None;
            let mut dns_provider_id = None;
            let mut output_dir: Option<PathBuf> = None;
            let mut force = false;
            let mut pending = iter.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--host" => {
                        let Some(value) = pending.next() else {
                            return Err("--host requires a value".into());
                        };
                        let normalized = normalize_tls_host(&value)
                            .map_err(|err| format!("invalid --host value: {err}"))?;
                        hostnames.push(normalized);
                    }
                    "--hosts-from" => {
                        let Some(value) = pending.next() else {
                            return Err("--hosts-from requires a JSON path".into());
                        };
                        host_files.push(crate::normalize_path(Path::new(&value))?);
                    }
                    "--out" | "--output" => {
                        let Some(value) = pending.next() else {
                            return Err("--out requires a directory path".into());
                        };
                        output_dir = Some(crate::normalize_path(Path::new(&value))?);
                    }
                    "--account-email" => {
                        let Some(value) = pending.next() else {
                            return Err("--account-email requires an address".into());
                        };
                        account_email = Some(value);
                    }
                    "--directory-url" => {
                        let Some(value) = pending.next() else {
                            return Err("--directory-url requires a value".into());
                        };
                        directory_url = Some(value);
                    }
                    "--dns-provider-id" => {
                        let Some(value) = pending.next() else {
                            return Err("--dns-provider-id requires a value".into());
                        };
                        dns_provider_id = Some(value);
                    }
                    "--force" => force = true,
                    "-h" | "--help" => {
                        gateway_cli_usage();
                        return Err("sorafs-gateway tls renew usage displayed".into());
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for sorafs-gateway tls renew: {flag}").into()
                        );
                    }
                }
            }
            for path in host_files {
                let additional = load_tls_hosts_from_file(&path)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                if additional.is_empty() {
                    return Err(format!(
                        "host fixture `{}` did not contain any entries",
                        path.display()
                    )
                    .into());
                }
                println!(
                    "[sorafs-gateway tls renew] loaded {} host(s) from {}",
                    additional.len(),
                    path.display()
                );
                hostnames.extend(additional);
            }
            dedup_tls_hosts(&mut hostnames);
            if hostnames.is_empty() {
                return Err(
                    "sorafs-gateway tls renew requires at least one --host or --hosts-from entry"
                        .into(),
                );
            }
            let output_dir = output_dir
                .ok_or_else(|| "sorafs-gateway tls renew requires --out <dir>".to_string())?;
            let directory_url =
                directory_url.unwrap_or_else(|| AcmeConfig::default().directory_url);
            Ok(GatewayCliCommand::TlsRenew(GatewayTlsRenewOptions {
                hostnames,
                account_email,
                directory_url,
                dns_provider_id,
                output_dir,
                force,
            }))
        }
        "revoke" => {
            let mut bundle_dir: Option<PathBuf> = None;
            let mut archive_dir: Option<PathBuf> = None;
            let mut reason: Option<String> = None;
            let mut force = false;
            let mut pending = iter.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--out" | "--bundle" | "--bundle-dir" => {
                        let Some(value) = pending.next() else {
                            return Err("--out requires a directory path".into());
                        };
                        bundle_dir = Some(crate::normalize_path(Path::new(&value))?);
                    }
                    "--archive-dir" => {
                        let Some(value) = pending.next() else {
                            return Err("--archive-dir requires a directory path".into());
                        };
                        archive_dir = Some(crate::normalize_path(Path::new(&value))?);
                    }
                    "--reason" => {
                        let Some(value) = pending.next() else {
                            return Err("--reason requires a value".into());
                        };
                        reason = Some(value);
                    }
                    "--force" => force = true,
                    "-h" | "--help" => {
                        gateway_cli_usage();
                        return Err("sorafs-gateway tls revoke usage displayed".into());
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for sorafs-gateway tls revoke: {flag}").into(),
                        );
                    }
                }
            }
            let bundle_dir = bundle_dir
                .ok_or_else(|| "sorafs-gateway tls revoke requires --out <dir>".to_string())?;
            Ok(GatewayCliCommand::TlsRevoke(GatewayTlsRevokeOptions {
                bundle_dir,
                archive_dir,
                reason,
                force,
            }))
        }
        "-h" | "--help" => {
            gateway_cli_usage();
            Err("sorafs-gateway tls usage displayed".into())
        }
        other => {
            gateway_cli_usage();
            Err(format!("unknown sorafs-gateway tls action `{other}`").into())
        }
    }
}
fn parse_gateway_route_cli<I>(args: I) -> Result<GatewayCliCommand, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut iter = args.into_iter();
    let Some(action) = iter.next() else {
        gateway_cli_usage();
        return Err("sorafs-gateway route requires an action (plan)".into());
    };
    match action.as_str() {
        "plan" => {
            let mut manifest_json: Option<PathBuf> = None;
            let mut output_path: Option<PathBuf> = None;
            let mut headers_out: Option<PathBuf> = None;
            let mut alias: Option<String> = None;
            let mut hostname: Option<String> = None;
            let mut route_label: Option<String> = None;
            let mut proof_status: Option<String> = None;
            let mut release_tag: Option<String> = None;
            let mut cutover_window: Option<String> = None;
            let mut rollback_manifest: Option<PathBuf> = None;
            let mut rollback_headers_out: Option<PathBuf> = None;
            let mut rollback_route_label: Option<String> = None;
            let mut rollback_release_tag: Option<String> = None;
            let mut include_csp = true;
            let mut include_permissions = true;
            let mut include_hsts = true;
            for arg in iter {
                if let Some(rest) = arg.strip_prefix("--manifest-json=") {
                    manifest_json = Some(PathBuf::from(rest));
                } else if let Some(rest) = arg.strip_prefix("--out=") {
                    output_path = Some(PathBuf::from(rest));
                } else if let Some(rest) = arg.strip_prefix("--headers-out=") {
                    headers_out = Some(PathBuf::from(rest));
                } else if let Some(rest) = arg.strip_prefix("--alias=") {
                    alias = Some(rest.to_string());
                } else if let Some(rest) = arg.strip_prefix("--hostname=") {
                    hostname = Some(rest.to_string());
                } else if let Some(rest) = arg.strip_prefix("--route-label=") {
                    route_label = Some(rest.to_string());
                } else if let Some(rest) = arg.strip_prefix("--proof-status=") {
                    proof_status = Some(rest.to_string());
                } else if let Some(rest) = arg.strip_prefix("--release-tag=") {
                    release_tag = Some(rest.to_string());
                } else if let Some(rest) = arg.strip_prefix("--cutover-window=") {
                    cutover_window = Some(rest.to_string());
                } else if let Some(rest) = arg.strip_prefix("--rollback-manifest-json=") {
                    rollback_manifest = Some(PathBuf::from(rest));
                } else if let Some(rest) = arg.strip_prefix("--rollback-route-label=") {
                    rollback_route_label = Some(rest.to_string());
                } else if let Some(rest) = arg.strip_prefix("--rollback-release-tag=") {
                    rollback_release_tag = Some(rest.to_string());
                } else if let Some(rest) = arg.strip_prefix("--rollback-headers-out=") {
                    rollback_headers_out = Some(PathBuf::from(rest));
                } else if arg == "--no-csp" {
                    include_csp = false;
                } else if arg == "--no-permissions-policy" {
                    include_permissions = false;
                } else if arg == "--no-hsts" {
                    include_hsts = false;
                } else if arg == "-h" || arg == "--help" {
                    gateway_cli_usage();
                    return Err("sorafs-gateway route plan usage displayed".into());
                } else {
                    return Err(format!("unknown flag for sorafs-gateway route plan: {arg}").into());
                }
            }
            let manifest_json = manifest_json.ok_or_else(|| {
                "--manifest-json=<path> is required for sorafs-gateway route plan".to_string()
            })?;
            let hostname = hostname.ok_or_else(|| {
                "--hostname=<host> is required for sorafs-gateway route plan".to_string()
            })?;
            let output_path = output_path
                .unwrap_or_else(|| PathBuf::from("artifacts/sorafs_gateway/route_plan.json"));
            let resolved_headers_out = headers_out.or_else(|| {
                output_path
                    .parent()
                    .map(|parent| parent.join("gateway.route.headers.txt"))
            });
            let resolved_rollback_headers = rollback_headers_out.or_else(|| {
                output_path
                    .parent()
                    .map(|parent| parent.join("gateway.route.rollback.headers.txt"))
            });
            Ok(GatewayCliCommand::RoutePlan(Box::new(
                GatewayRoutePlanOptions {
                    manifest_json,
                    output_path,
                    headers_out: resolved_headers_out,
                    alias,
                    hostname: Some(hostname),
                    route_label,
                    proof_status,
                    release_tag,
                    cutover_window,
                    rollback_manifest,
                    rollback_headers_out: resolved_rollback_headers,
                    rollback_route_label,
                    rollback_release_tag,
                    include_csp,
                    include_permissions,
                    include_hsts,
                    now: OffsetDateTime::now_utc(),
                },
            )))
        }
        other => {
            gateway_cli_usage();
            Err(format!("unknown sorafs-gateway route action `{other}`").into())
        }
    }
}
fn run_gateway_route_plan(options: GatewayRoutePlanOptions) -> Result<(), Box<dyn Error>> {
    let binding_context = RouteBindingContext {
        manifest_json: options.manifest_json.clone(),
        alias: options.alias.clone(),
        hostname: options.hostname.clone(),
        route_label: options.route_label.clone(),
        proof_status: options.proof_status.clone(),
        include_csp: options.include_csp,
        include_permissions: options.include_permissions,
        include_hsts: options.include_hsts,
        generated_at: options.now,
    };
    let primary_binding = build_route_binding(&binding_context)?;
    write_optional_output(&options.headers_out, &primary_binding.headers_template)?;
    let rollback = if let Some(rollback_manifest) = options.rollback_manifest.clone() {
        let rollback_context = RouteBindingContext {
            manifest_json: rollback_manifest.clone(),
            alias: options.alias.clone(),
            hostname: options.hostname.clone(),
            route_label: options
                .rollback_route_label
                .clone()
                .or(options.route_label.clone()),
            proof_status: options.proof_status.clone(),
            include_csp: options.include_csp,
            include_permissions: options.include_permissions,
            include_hsts: options.include_hsts,
            generated_at: options.now,
        };
        let binding = build_route_binding(&rollback_context)?;
        write_optional_output(&options.rollback_headers_out, &binding.headers_template)?;
        Some(GatewayRouteRollback {
            manifest_json: rollback_manifest.display().to_string(),
            release_tag: options.rollback_release_tag.clone(),
            content_cid: binding.content_cid,
            route_binding: binding.route_binding,
            headers_template: binding.headers_template,
            headers_path: options
                .rollback_headers_out
                .as_ref()
                .map(|path| path.display().to_string()),
        })
    } else {
        None
    };
    if let Some(parent) = options.output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let generated_at = options
        .now
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format timestamp: {err}"))?;
    let plan = GatewayRoutePlan {
        version: 1,
        generated_at,
        manifest_json: options.manifest_json.display().to_string(),
        alias: options.alias,
        hostname: options.hostname,
        release_tag: options.release_tag,
        cutover_window: options.cutover_window,
        content_cid: primary_binding.content_cid,
        route_binding: primary_binding.route_binding,
        headers: primary_binding.headers,
        headers_template: primary_binding.headers_template,
        headers_path: options
            .headers_out
            .as_ref()
            .map(|path| path.display().to_string()),
        rollback,
    };
    let payload = json::to_string_pretty(&plan)?;
    fs::write(&options.output_path, format!("{payload}\n"))
        .map_err(|err| format!("failed to write {}: {err}", options.output_path.display()))?;
    println!("wrote {}", options.output_path.display());
    Ok(())
}
const ROUTE_HEADER_ORDER: &[&str] = &[
    "Sora-Name",
    "Sora-Content-CID",
    "Sora-Proof",
    "Sora-Proof-Status",
    "Sora-Route-Binding",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Permissions-Policy",
];
const DEFAULT_ROUTE_CSP: &str = "default-src 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'";
const DEFAULT_ROUTE_PERMISSIONS: &str = "accelerometer=(), ambient-light-sensor=(), autoplay=(), camera=(), clipboard-read=(self), clipboard-write=(self), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), speaker-selection=(), usb=(), xr-spatial-tracking=()";
const DEFAULT_ROUTE_HSTS_MAX_AGE: u32 = 63_072_000;
fn build_route_binding(
    context: &RouteBindingContext,
) -> Result<RouteBindingOutput, Box<dyn Error>> {
    let manifest_bytes = fs::read(&context.manifest_json).map_err(|err| {
        format!(
            "failed to read manifest JSON from `{}`: {err}",
            context.manifest_json.display()
        )
    })?;
    let manifest: Value = json::from_slice(&manifest_bytes).map_err(|err| {
        format!(
            "failed to parse manifest JSON from `{}`: {err}",
            context.manifest_json.display()
        )
    })?;
    let root_bytes = manifest_root_bytes(&manifest)?;
    if root_bytes.is_empty() {
        return Err("manifest root CID payload was empty".into());
    }
    let content_cid = format!("b{}", encode_base32_lower(&root_bytes));
    let mut headers = BTreeMap::new();
    headers.insert("Sora-Content-CID".into(), content_cid.clone());
    if let Some(alias) = context.alias.as_deref() {
        headers.insert("Sora-Name".into(), alias.to_string());
        let proof_payload = norito::json!({
            "alias": alias,
            "manifest": content_cid,
        });
        let proof_bytes = json::to_vec(&proof_payload)
            .map_err(|err| format!("failed to encode proof payload: {err}"))?;
        headers.insert("Sora-Proof".into(), BASE64_STD.encode(proof_bytes));
        let status = context
            .proof_status
            .clone()
            .unwrap_or_else(|| "ok".to_string());
        headers.insert("Sora-Proof-Status".into(), status);
    }
    let hostname = context.hostname.as_ref().ok_or_else(|| {
        "hostname must be supplied for sorafs-gateway route plan (--hostname)".to_string()
    })?;
    let generated_at = context
        .generated_at
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format timestamp: {err}"))?;
    let mut binding_parts = vec![
        format!("host={hostname}"),
        format!("cid={content_cid}"),
        format!("generated_at={generated_at}"),
    ];
    if let Some(label) = context.route_label.as_deref() {
        binding_parts.push(format!("label={label}"));
    }
    let route_binding = binding_parts.join(";");
    headers.insert("Sora-Route-Binding".into(), route_binding.clone());
    if context.include_csp {
        headers.insert("Content-Security-Policy".into(), DEFAULT_ROUTE_CSP.into());
    }
    if context.include_hsts {
        headers.insert(
            "Strict-Transport-Security".into(),
            format!(
                "max-age={}; includeSubDomains; preload",
                DEFAULT_ROUTE_HSTS_MAX_AGE
            ),
        );
    }
    if context.include_permissions {
        headers.insert(
            "Permissions-Policy".into(),
            DEFAULT_ROUTE_PERMISSIONS.into(),
        );
    }
    let headers_template = format_headers_template(&headers);
    Ok(RouteBindingOutput {
        content_cid,
        route_binding,
        headers,
        headers_template,
    })
}
fn manifest_root_bytes(manifest: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Some(array) = manifest.get("root_cid").and_then(|value| value.as_array()) {
        let mut bytes = Vec::with_capacity(array.len());
        for value in array {
            let number = value.as_i64().ok_or_else(|| {
                format!("root_cid entries must be integers, found {value:?} instead")
            })?;
            if !(0..=255).contains(&number) {
                return Err(format!(
                    "root_cid entries must be between 0 and 255 inclusive (found {number})"
                )
                .into());
            }
            bytes.push(number as u8);
        }
        return Ok(bytes);
    }
    if let Some(array) = manifest
        .get("root_cids_hex")
        .and_then(|value| value.as_array())
    {
        for value in array {
            if let Some(decoded) = value
                .as_str()
                .and_then(|hex_str| hex::decode(hex_str.trim()).ok())
                .filter(|decoded| !decoded.is_empty())
            {
                return Ok(decoded);
            }
        }
    }
    if let Some(hex_value) = manifest
        .get("root_cid_hex")
        .and_then(|value| value.as_str())
    {
        return hex::decode(hex_value.trim())
            .map_err(|err| format!("failed to decode root_cid_hex value: {err}").into());
    }
    Err("manifest JSON is missing `root_cid`, `root_cids_hex`, or `root_cid_hex` fields".into())
}
fn encode_base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    if bytes.is_empty() {
        return String::new();
    }
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut output = String::new();
    for &byte in bytes {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            let index = ((acc >> (bits - 5)) & 0x1F) as usize;
            output.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((acc << (5 - bits)) & 0x1F) as usize;
        output.push(ALPHABET[index] as char);
    }
    output
}
fn format_headers_template(headers: &BTreeMap<String, String>) -> String {
    let mut lines = Vec::new();
    for &key in ROUTE_HEADER_ORDER {
        if let Some(value) = headers.get(key) {
            lines.push(format!("{key}: {value}"));
        }
    }
    for (key, value) in headers {
        if ROUTE_HEADER_ORDER.contains(&key.as_str()) {
            continue;
        }
        lines.push(format!("{key}: {value}"));
    }
    let mut rendered = lines.join("\n");
    rendered.push('\n');
    rendered
}
fn write_optional_output(path: &Option<PathBuf>, contents: &str) -> Result<(), Box<dyn Error>> {
    if let Some(path) = path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    }
    Ok(())
}
fn parse_gateway_key_cli<I>(args: I) -> Result<GatewayCliCommand, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut iter = args.into_iter();
    let Some(action) = iter.next() else {
        gateway_cli_usage();
        return Err("sorafs-gateway key requires an action (rotate)".into());
    };
    match action.as_str() {
        "rotate" => {
            let mut kind: Option<String> = None;
            let mut output_path: Option<PathBuf> = None;
            let mut public_out: Option<PathBuf> = None;
            let mut force = false;
            let mut pending = iter.peekable();
            while let Some(arg) = pending.next() {
                match arg.as_str() {
                    "--kind" => {
                        let Some(value) = pending.next() else {
                            return Err("--kind requires a value".into());
                        };
                        kind = Some(value);
                    }
                    "--out" | "--output" => {
                        let Some(value) = pending.next() else {
                            return Err("--out requires a path".into());
                        };
                        output_path = Some(crate::normalize_path(Path::new(&value))?);
                    }
                    "--public-out" => {
                        let Some(value) = pending.next() else {
                            return Err("--public-out requires a path".into());
                        };
                        public_out = Some(crate::normalize_path(Path::new(&value))?);
                    }
                    "--force" => force = true,
                    "-h" | "--help" => {
                        gateway_cli_usage();
                        return Err("sorafs-gateway key rotate usage displayed".into());
                    }
                    flag => {
                        return Err(
                            format!("unknown flag for sorafs-gateway key rotate: {flag}").into(),
                        );
                    }
                }
            }
            let kind = kind.unwrap_or_else(|| "token-signing".to_string());
            let output_path = output_path
                .ok_or_else(|| "sorafs-gateway key rotate requires --out <path>".to_string())?;
            Ok(GatewayCliCommand::KeyRotate(GatewayKeyRotateOptions {
                kind,
                output_path,
                public_out,
                force,
            }))
        }
        "-h" | "--help" => {
            gateway_cli_usage();
            Err("sorafs-gateway key usage displayed".into())
        }
        other => {
            gateway_cli_usage();
            Err(format!("unknown sorafs-gateway key action `{other}`").into())
        }
    }
}
pub fn gateway_tls_renew(
    options: GatewayTlsRenewOptions,
) -> Result<GatewayTlsRenewOutcome, Box<dyn Error>> {
    if options.hostnames.is_empty() {
        return Err("sorafs-gateway tls renew requires at least one hostname".into());
    }
    if options
        .account_email
        .as_deref()
        .is_some_and(|email| email.trim().is_empty())
    {
        return Err("sorafs-gateway tls renew account email cannot be empty".into());
    }
    let directory_url = Url::parse(&options.directory_url)
        .map_err(|error| format!("invalid ACME directory URL: {error}"))?;
    if !matches!(directory_url.scheme(), "http" | "https") {
        return Err("ACME directory URL must use http or https".into());
    }
    if options
        .dns_provider_id
        .as_deref()
        .is_some_and(|provider| provider.trim().is_empty())
    {
        return Err("sorafs-gateway tls renew DNS provider id cannot be empty".into());
    }
    if options.output_dir.as_os_str().is_empty() {
        return Err("sorafs-gateway tls renew output directory cannot be empty".into());
    }
    if options.output_dir.exists() && !options.force {
        return Err(format!(
            "TLS output directory {} already exists; use --force to replace it",
            options.output_dir.display()
        )
        .into());
    }
    Err(
        "sorafs-gateway tls renew has no built-in ACME backend; enable Torii ACME only with a runtime-injected provider client"
            .into(),
    )
}
pub fn gateway_tls_revoke(
    options: GatewayTlsRevokeOptions,
) -> Result<GatewayTlsRevokeOutcome, Box<dyn Error>> {
    if !options.bundle_dir.exists() {
        return Err(format!(
            "bundle directory {} does not exist",
            options.bundle_dir.display()
        )
        .into());
    }
    let archive_dir = options
        .archive_dir
        .clone()
        .unwrap_or_else(|| options.bundle_dir.join("revoked"));
    fs::create_dir_all(&archive_dir)?;
    let timestamp_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock before UNIX epoch")?
        .as_secs();
    let suffix = format!(".revoked.{timestamp_epoch}");
    let mut archived_files = Vec::new();
    for name in ["fullchain.pem", "privkey.pem"] {
        let source = options.bundle_dir.join(name);
        if !source.exists() {
            if options.force {
                continue;
            }
            return Err(format!(
                "missing {} in {}; use --force to skip",
                name,
                options.bundle_dir.display()
            )
            .into());
        }
        let target = archive_dir.join(format!("{name}{suffix}"));
        if target.exists() && !options.force {
            return Err(format!(
                "archive target {} already exists; use --force to overwrite",
                target.display()
            )
            .into());
        }
        fs::rename(&source, &target)?;
        archived_files.push(target);
    }
    let ech_source = options.bundle_dir.join("ech.json");
    if ech_source.exists() {
        let target = archive_dir.join(format!("ech.json{suffix}"));
        if target.exists() && !options.force {
            return Err(format!(
                "archive target {} already exists; use --force to overwrite",
                target.display()
            )
            .into());
        }
        fs::rename(&ech_source, &target)?;
        archived_files.push(target);
    }
    let mut audit = Map::new();
    audit.insert(
        "timestamp_epoch".into(),
        Value::Number(timestamp_epoch.into()),
    );
    if let Some(reason) = options.reason.clone() {
        audit.insert("reason".into(), Value::String(reason.clone()));
    }
    let files_value = archived_files
        .iter()
        .map(|path| Value::String(path.display().to_string()))
        .collect::<Vec<_>>();
    audit.insert("archived_files".into(), Value::Array(files_value));
    let audit_json = to_string_pretty(&Value::Object(audit))
        .map_err(|err| format!("failed to encode revocation audit: {err}"))?;
    let audit_path = archive_dir.join(format!("revocation-{timestamp_epoch}.json"));
    write_file_with_mode(&audit_path, audit_json.as_bytes(), true, 0o600)?;
    archived_files.push(audit_path.clone());
    Ok(GatewayTlsRevokeOutcome {
        archive_dir,
        archived_files,
        timestamp_epoch,
        reason: options.reason,
    })
}
pub fn gateway_key_rotate(
    options: GatewayKeyRotateOptions,
) -> Result<GatewayKeyRotateOutcome, Box<dyn Error>> {
    if options.kind.as_str() != "token-signing" {
        return Err(format!(
            "unsupported key kind `{}` (expected token-signing)",
            options.kind
        )
        .into());
    }
    if let Some(parent) = options.output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let keypair = KeyPair::random_with_algorithm(Algorithm::Ed25519);
    let (algorithm, private_bytes) = keypair.private_key().to_bytes();
    if algorithm != Algorithm::Ed25519 {
        return Err("unexpected algorithm for generated private key".into());
    }
    let private_hex = hex::encode(private_bytes);
    let private_contents = format!("{private_hex}\n");
    write_file_with_mode(
        &options.output_path,
        private_contents.as_bytes(),
        options.force,
        0o600,
    )?;
    let public = keypair.public_key();
    let public_bytes =
        checked_ed25519_public_key_bytes(public, "generated token-signing public key")?;
    let public_key_hex = hex::encode(public_bytes);
    let public_key_prefixed = public.try_to_prefixed_string().map_err(|err| {
        format!("generated token-signing public key cannot be formatted as multihash: {err}")
    })?;
    let mut public_out_path = None;
    if let Some(path) = options.public_out.as_ref() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut payload = Map::new();
        payload.insert("algorithm".into(), Value::String("ed25519".into()));
        payload.insert("key_hex".into(), Value::String(public_key_hex.clone()));
        payload.insert(
            "key_multihash".into(),
            Value::String(public_key_prefixed.clone()),
        );
        let json = to_string_pretty(&Value::Object(payload))
            .map_err(|err| format!("failed to encode public key JSON: {err}"))?;
        write_file_with_mode(path, json.as_bytes(), options.force, 0o640)?;
        public_out_path = Some(path.clone());
    }
    Ok(GatewayKeyRotateOutcome {
        private_key_path: options.output_path,
        public_key_hex,
        public_key_prefixed,
        public_out_path,
    })
}
fn gateway_cli_usage() {
    eprintln!("sorafs-gateway CLI usage:");
    eprintln!(
        "  cargo xtask sorafs-gateway tls renew --host <hostname>... [--hosts-from <san.json> ...] --out <dir> [--account-email <email>] [--directory-url <url>] [--dns-provider-id <id>] [--force]"
    );
    eprintln!(
        "  cargo xtask sorafs-gateway tls revoke --out <dir> [--archive-dir <dir>] [--reason <text>] [--force]"
    );
    eprintln!(
        "  cargo xtask sorafs-gateway key rotate --kind token-signing --out <path> [--public-out <path>] [--force]"
    );
    eprintln!(
        "  cargo xtask sorafs-gateway route plan --manifest-json <path> --hostname <host> [--alias <namespace:name>] [--route-label <label>] [--out <path>] [--headers-out <path>] [--rollback-manifest-json <path>] [--rollback-route-label <label>]"
    );
}
fn normalize_tls_host(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("hostname must not be empty".to_string());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(format!("hostname `{trimmed}` must not contain whitespace"));
    }
    if trimmed.contains('/') {
        return Err(format!(
            "hostname `{trimmed}` must not include protocol/path separators"
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}
fn load_tls_hosts_from_file(path: &Path) -> Result<Vec<String>, String> {
    let data = fs::read(path)
        .map_err(|err| format!("failed to read host fixture `{}`: {err}", path.display()))?;
    let value: Value = json::from_slice(&data)
        .map_err(|err| format!("failed to parse host fixture `{}`: {err}", path.display()))?;
    let hosts = if let Some(array) = value.as_array() {
        parse_host_array(path, array)?
    } else if let Some(object) = value.as_object() {
        if let Some(array) = object.get("san_hosts").and_then(Value::as_array) {
            parse_host_array(path, array)?
        } else if let Some(array) = object.get("hosts").and_then(Value::as_array) {
            parse_host_array(path, array)?
        } else {
            return Err(format!(
                "host fixture `{}` must contain a `san_hosts` array",
                path.display()
            ));
        }
    } else {
        return Err(format!(
            "host fixture `{}` must be a JSON array or object with `san_hosts`",
            path.display()
        ));
    };
    Ok(hosts)
}
fn parse_host_array(path: &Path, array: &[Value]) -> Result<Vec<String>, String> {
    let mut hosts = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, entry) in array.iter().enumerate() {
        let Some(raw) = entry.as_str() else {
            return Err(format!(
                "host fixture `{}` entry #{index} is not a string",
                path.display()
            ));
        };
        let normalized = normalize_tls_host(raw).map_err(|err| {
            format!(
                "host fixture `{}` entry #{index} is invalid: {err}",
                path.display()
            )
        })?;
        if seen.insert(normalized.clone()) {
            hosts.push(normalized);
        }
    }
    Ok(hosts)
}
fn dedup_tls_hosts(hosts: &mut Vec<String>) {
    let mut seen = HashSet::new();
    hosts.retain(|host| seen.insert(host.clone()));
}
fn write_file_with_mode(
    path: &Path,
    contents: &[u8],
    overwrite: bool,
    mode: u32,
) -> Result<(), Box<dyn Error>> {
    if path.exists() && !overwrite {
        return Err(format!(
            "{} already exists; pass --force to overwrite",
            path.display()
        )
        .into());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(())
}
pub fn default_gateway_fixture_dir() -> PathBuf {
    self::gateway_fixture::default_output_dir()
}
pub fn write_gateway_fixtures(output: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = self::gateway_fixture::write_bundle(output)?;
    println!(
        "wrote SoraFS gateway fixtures {} to {} (fixtures_digest={})",
        metadata.version,
        output.display(),
        metadata.fixtures_digest_blake3_hex
    );
    println!(
        "  manifest_blake3={}\n  payload_blake3={}\n  car_blake3={}",
        metadata.manifest_blake3_hex, metadata.payload_blake3_hex, metadata.car_blake3_hex
    );
    Ok(())
}
pub fn verify_gateway_fixtures(target: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = self::gateway_fixture::verify_bundle(target)?;
    println!(
        "verified SoraFS gateway fixtures {} at {} (fixtures_digest={})",
        metadata.version,
        target.display(),
        metadata.fixtures_digest_blake3_hex
    );
    println!(
        "  manifest_blake3={}\n  payload_blake3={}\n  car_blake3={}",
        metadata.manifest_blake3_hex, metadata.payload_blake3_hex, metadata.car_blake3_hex
    );
    Ok(())
}
impl FetchSource {
    pub fn parse(raw: &str) -> Result<Self, Box<dyn Error>> {
        if raw.starts_with("http://") || raw.starts_with("https://") {
            let url = Url::parse(raw).map_err(|err| format!("invalid URL {raw}: {err}"))?;
            return Ok(Self::Url(url));
        }
        if raw.starts_with("file://") {
            let url = Url::parse(raw).map_err(|err| format!("invalid file URL {raw}: {err}"))?;
            let path = url
                .to_file_path()
                .map_err(|_| format!("file URL {raw} could not be converted to a path"))?;
            return Ok(Self::File(path));
        }
        let path = Path::new(raw);
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            crate::workspace_root().join(path)
        };
        Ok(Self::File(resolved))
    }
    fn resolve_relative(&self, value: &str) -> Result<Self, Box<dyn Error>> {
        if value.starts_with("http://")
            || value.starts_with("https://")
            || value.starts_with("file://")
        {
            return Self::parse(value);
        }
        match self {
            Self::Url(base) => {
                let joined = base.join(value).map_err(|err| {
                    format!("failed to resolve {value} relative to {base}: {err}")
                })?;
                Ok(Self::Url(joined))
            }
            Self::File(path) => {
                let parent = path.parent().ok_or_else(|| {
                    "signatures path has no parent directory; cannot resolve manifest location"
                        .to_owned()
                })?;
                let candidate = Path::new(value);
                let resolved = if candidate.is_absolute() {
                    candidate.to_path_buf()
                } else {
                    parent.join(candidate)
                };
                Ok(Self::File(resolved))
            }
        }
    }
    fn fetch_bytes(&self, client: &Client) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            Self::Url(url) => {
                let response = client
                    .get(url.clone())
                    .send()
                    .map_err(|err| format!("failed to GET {url}: {err}"))?;
                if !response.status().is_success() {
                    return Err(format!("request to {url} returned {}", response.status()).into());
                }
                let bytes = response
                    .bytes()
                    .map_err(|err| format!("failed to read response body from {url}: {err}"))?;
                Ok(bytes.to_vec())
            }
            Self::File(path) => Ok(fs::read(path)
                .map_err(|err| format!("failed to read {}: {err}", path.display()))?),
        }
    }
    fn describe(&self) -> String {
        match self {
            Self::Url(url) => url.as_str().to_owned(),
            Self::File(path) => path.display().to_string(),
        }
    }
}
pub fn fetch_fixture(options: FetchFixtureOptions) -> Result<(), Box<dyn Error>> {
    let FetchFixtureOptions {
        signatures_source,
        manifest_source,
        output_dir,
        profile_handle,
        allow_unsigned,
    } = options;
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| format!("failed to construct HTTP client: {err}"))?;
    let profile_handle = if profile_handle.is_empty() {
        DEFAULT_PROFILE_HANDLE.to_owned()
    } else {
        profile_handle
    };
    let vectors = FixtureProfile::SF1_V1.generate_vectors();
    let expected_chunk_digest = vectors.sha3_digest_hex();
    let signatures_bytes = signatures_source.fetch_bytes(&client).map_err(|err| {
        format!(
            "failed to fetch manifest signatures from {}: {err}",
            signatures_source.describe()
        )
    })?;
    let signatures_value: Value = json::from_slice(&signatures_bytes)
        .map_err(|err| format!("failed to parse manifest signatures JSON: {err}"))?;
    ensure_profile_matches(&signatures_value, &profile_handle)?;
    ensure_aliases(&signatures_value, &profile_handle)?;
    let chunk_digest_from_signatures =
        extract_string(&signatures_value, "chunk_digest_sha3_256")?.to_ascii_lowercase();
    if chunk_digest_from_signatures != expected_chunk_digest {
        return Err(format!(
            "chunk digest mismatch: manifest_signatures.json reports {chunk_digest_from_signatures} \
             but the canonical fixture expects {expected_chunk_digest}"
        )
        .into());
    }
    let manifest_name = extract_string(&signatures_value, "manifest")?;
    let manifest_digest_expected =
        extract_string(&signatures_value, "manifest_blake3")?.to_ascii_lowercase();
    let manifest_source = match manifest_source {
        Some(source) => source,
        None => signatures_source
            .resolve_relative(manifest_name)
            .map_err(|err| format!("failed to resolve manifest path {manifest_name}: {err}"))?,
    };
    let manifest_bytes = manifest_source.fetch_bytes(&client).map_err(|err| {
        format!(
            "failed to fetch manifest from {}: {err}",
            manifest_source.describe()
        )
    })?;
    let manifest_digest_actual = blake3_hash(&manifest_bytes);
    let manifest_digest_actual_hex = to_hex(manifest_digest_actual.as_bytes());
    if manifest_digest_actual_hex != manifest_digest_expected {
        return Err(format!(
            "manifest digest mismatch: signatures expect {manifest_digest_expected} \
             but fetched manifest hashes to {manifest_digest_actual_hex}"
        )
        .into());
    }
    let manifest_value: Value = json::from_slice(&manifest_bytes)
        .map_err(|err| format!("failed to parse manifest JSON: {err}"))?;
    ensure_profile_matches(&manifest_value, &profile_handle)?;
    ensure_aliases(&manifest_value, &profile_handle)?;
    let manifest_chunk_digest =
        extract_string(&manifest_value, "chunk_digest_sha3_256")?.to_ascii_lowercase();
    if manifest_chunk_digest != expected_chunk_digest {
        return Err(format!(
            "manifest chunk digest mismatch: manifest reports {manifest_chunk_digest} \
             but canonical fixture expects {expected_chunk_digest}"
        )
        .into());
    }
    let signature_count = verify_manifest_signatures(
        &signatures_value,
        manifest_digest_actual.as_bytes(),
        allow_unsigned,
    )?;
    fs::create_dir_all(&output_dir)?;
    fs::write(
        output_dir.join("manifest_signatures.json"),
        &signatures_bytes,
    )?;
    fs::write(output_dir.join("manifest_blake3.json"), &manifest_bytes)?;
    println!(
        "Fetched SoraFS chunker manifest to {} (signatures: {}, digest: {})",
        output_dir.display(),
        signature_count,
        manifest_digest_actual_hex
    );
    Ok(())
}
pub fn generate_gateway_attestation(options: GatewayAttestOptions) -> Result<(), Box<dyn Error>> {
    let GatewayAttestOptions {
        output_dir,
        signing_key_path,
        signer_account,
        gateway_target,
    } = options;
    fs::create_dir_all(&output_dir)
        .map_err(|err| format!("failed to create {}: {err}", output_dir.display()))?;
    let mut context = HarnessContext::new();
    if let Some(target) = gateway_target {
        context = context.with_gateway_target(target);
    }
    let suite = integration_tests::sorafs_gateway_conformance::run_suite(&context);
    if !suite.all_passed() {
        return Err("gateway conformance suite failed; refusing to issue attestation".into());
    }
    let key_text = fs::read_to_string(&signing_key_path).map_err(|err| {
        format!(
            "failed to read signing key {}: {err}",
            signing_key_path.display()
        )
    })?;
    let private_key_hex = key_text.trim();
    if private_key_hex.is_empty() {
        return Err("signing key file is empty".into());
    }
    let private_key =
        iroha_crypto::PrivateKey::from_hex(iroha_crypto::Algorithm::Ed25519, private_key_hex)
            .map_err(|err| {
                format!(
                    "failed to parse signing key {}: {err}",
                    signing_key_path.display()
                )
            })?;
    let key_pair =
        KeyPair::from_private_key(private_key).map_err(|err| format!("invalid key pair: {err}"))?;
    let signer_literal = signer_account.trim();
    let signer = AccountAddress::parse_encoded(
        signer_literal,
        Some(iroha_data_model::account::address::chain_discriminant()),
    )
    .map_err(|err| format!("invalid signer account `{}`: {err}", signer_literal))?;
    let bundle = integration_tests::sorafs_gateway_conformance::generate_attestation(
        &suite,
        &key_pair,
        &signer,
        SystemTime::now(),
    )
    .map_err(|err| format!("failed to generate attestation: {err}"))?;
    let report_path = output_dir.join("sorafs_gateway_report.json");
    fs::write(&report_path, bundle.report_json)
        .map_err(|err| format!("failed to write report {}: {err}", report_path.display()))?;
    let envelope_path = output_dir.join("sorafs_gateway_attestation.to");
    fs::write(&envelope_path, bundle.envelope_bytes).map_err(|err| {
        format!(
            "failed to write attestation envelope {}: {err}",
            envelope_path.display()
        )
    })?;
    let summary_path = output_dir.join("sorafs_gateway_attestation.txt");
    fs::write(&summary_path, bundle.summary_text).map_err(|err| {
        format!(
            "failed to write attestation summary {}: {err}",
            summary_path.display()
        )
    })?;
    println!(
        "Wrote SoraFS gateway conformance attestation:\n  report: {}\n  envelope: {}\n  summary: {}",
        report_path.display(),
        envelope_path.display(),
        summary_path.display()
    );
    Ok(())
}
/// Verify a SoraFS gateway conformance attestation envelope and print metadata.
pub fn verify_gateway_attestation(envelope_path: &Path) -> Result<(), Box<dyn Error>> {
    let envelope_bytes = fs::read(envelope_path).map_err(|err| {
        format!(
            "failed to read attestation envelope {}: {err}",
            envelope_path.display()
        )
    })?;
    let verified =
        integration_tests::sorafs_gateway_conformance::verify_attestation_envelope(&envelope_bytes)
            .map_err(|err| format!("failed to verify SoraFS gateway attestation: {err}"))?;
    println!(
        "Verified SoraFS gateway conformance attestation:\n  envelope: {}\n  profile: {}\n  scenarios: {}\n  digest: {}\n  signer: {}\n  algorithm: {}\n  public_key: {}\n  signed_at_unix: {}",
        envelope_path.display(),
        verified.profile_version,
        verified.scenario_count,
        verified.payload_hash_hex,
        verified.signer_account,
        verified.algorithm.as_static_str(),
        verified.public_key_hex,
        verified.signed_at_unix
    );
    Ok(())
}
const DEFAULT_CACHE_MAX_AGE: u64 = 600;
const DEFAULT_CACHE_STALE_WHILE_REVALIDATE: u64 = 120;
const DEFAULT_CACHE_HARD_EXPIRY: u64 = 900;
const DEFAULT_CACHE_NEGATIVE_TTL: u64 = 60;
const DEFAULT_CACHE_REVOCATION_TTL: u64 = 300;
const DEFAULT_CACHE_ROTATION_MAX_AGE: u64 = 21_600;
const DEFAULT_SUCCESSOR_GRACE: u64 = 300;
const DEFAULT_GOVERNANCE_GRACE: u64 = 0;
const DRILL_LOG_HEADER: &str = r#"---
title: SoraFS Chaos Drill Log
summary: Registry of executed chaos drills and incident rehearsals.
---

| Date | Scenario | Status | Incident Commander | Scribe | Start (UTC) | End (UTC) | Notes | Follow-up / Incident Link |
|------|----------|--------|--------------------|--------|-------------|-----------|-------|---------------------------|
"#;
struct ProbeRunSummary<'a> {
    started_at: OffsetDateTime,
    ended_at: OffsetDateTime,
    success: bool,
    source_description: String,
    target_url: Option<String>,
    target_host: Option<String>,
    gar_path: PathBuf,
    findings: &'a [ProbeFinding],
}
impl<'a> ProbeRunSummary<'a> {
    fn failure_count(&self) -> usize {
        self.findings.iter().filter(|finding| !finding.ok).count()
    }
    fn target_label(&self) -> String {
        self.target_url
            .clone()
            .or_else(|| self.target_host.clone())
            .unwrap_or_else(|| self.source_description.clone())
    }
}
pub fn run_gateway_probe(options: GatewayProbeOptions) -> Result<(), Box<dyn Error>> {
    let report_target = options.report_target.clone();
    let log_to_stderr = matches!(report_target.as_ref(), Some(JsonTarget::Stdout));
    let started_at = OffsetDateTime::now_utc();
    let now_secs = options.now_override.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX_EPOCH")
            .as_secs()
    });
    let gar_record = load_and_verify_gar(&options, now_secs)?;
    let response = if let Some(request) = &options.request {
        probe_headers_via_http(request)?
    } else {
        let path = options
            .headers_path
            .as_ref()
            .expect("headers_path required when no request is present");
        probe_headers_from_file(path)?
    };
    let mut findings = Vec::new();
    let status_ok = (200..=299).contains(&response.status);
    record_finding(
        &mut findings,
        status_ok,
        "HTTP status",
        format!("{} {}", response.status, response.source.describe()),
    );
    let host = resolve_probe_host(&options, &response)?;
    let host_matches = gar_record.matches_host(&host);
    record_finding(
        &mut findings,
        host_matches,
        "GAR host pattern",
        if host_matches {
            format!("host `{host}` authorised by GAR")
        } else {
            format!("host `{host}` missing from GAR host_patterns")
        },
    );
    let cache_control = expect_header(&response.headers, "Cache-Control", &mut findings);
    let sora_name = expect_header(&response.headers, "Sora-Name", &mut findings);
    let sora_content_cid = expect_header(&response.headers, "Sora-Content-CID", &mut findings);
    let sora_proof_header = expect_header(&response.headers, "Sora-Proof", &mut findings);
    let sora_proof_status = expect_header(&response.headers, "Sora-Proof-Status", &mut findings);
    if options.require_tls_state {
        match read_header(&response.headers, "X-Sora-TLS-State") {
            Ok(Some(value)) => {
                let detail = if value.contains("expiry=") {
                    format!("X-Sora-TLS-State `{value}`")
                } else {
                    format!("header `{value}` missing expiry= annotation")
                };
                record_finding(
                    &mut findings,
                    value.contains("expiry="),
                    "X-Sora-TLS-State",
                    detail,
                );
            }
            Ok(None) => {
                record_finding(
                    &mut findings,
                    false,
                    "X-Sora-TLS-State",
                    "header missing from response",
                );
            }
            Err(err) => {
                record_finding(&mut findings, false, "X-Sora-TLS-State", err);
            }
        }
    }
    if let Some(template) = gar_record.csp_template() {
        match read_header(&response.headers, "Content-Security-Policy") {
            Ok(Some(value)) => {
                let matches = value.trim() == template.trim();
                record_finding(
                    &mut findings,
                    matches,
                    "Content-Security-Policy",
                    if matches {
                        "CSP matches GAR template".to_string()
                    } else {
                        format!("expected `{template}`, observed `{value}`")
                    },
                );
            }
            Ok(None) => {
                record_finding(
                    &mut findings,
                    false,
                    "Content-Security-Policy",
                    "header missing but GAR requires it",
                );
            }
            Err(err) => record_finding(&mut findings, false, "Content-Security-Policy", err),
        }
    }
    if let Some(template) = gar_record.hsts_template() {
        match read_header(&response.headers, "Strict-Transport-Security") {
            Ok(Some(value)) => {
                let matches = value.trim() == template.trim();
                record_finding(
                    &mut findings,
                    matches,
                    "Strict-Transport-Security",
                    if matches {
                        "HSTS matches GAR template".to_string()
                    } else {
                        format!("expected `{template}`, observed `{value}`")
                    },
                );
            }
            Ok(None) => {
                record_finding(
                    &mut findings,
                    false,
                    "Strict-Transport-Security",
                    "header missing but GAR requires it",
                );
            }
            Err(err) => record_finding(&mut findings, false, "Strict-Transport-Security", err),
        }
    }
    if let Some(header) = cache_control {
        let directives = parse_cache_directives(&header);
        let expected_max_age = options.cache_max_age.unwrap_or(DEFAULT_CACHE_MAX_AGE);
        let expected_swr = options
            .cache_swr
            .unwrap_or(DEFAULT_CACHE_STALE_WHILE_REVALIDATE);
        let parsed_max_age = directives
            .get("max-age")
            .and_then(|value| value.parse::<u64>().ok());
        let parsed_swr = directives
            .get("stale-while-revalidate")
            .and_then(|value| value.parse::<u64>().ok());
        let ttl_ok = parsed_max_age == Some(expected_max_age) && parsed_swr == Some(expected_swr);
        let detail = format!(
            "Cache-Control max-age={:?} (expected {expected_max_age}), stale-while-revalidate={:?} (expected {expected_swr})",
            parsed_max_age, parsed_swr
        );
        record_finding(&mut findings, ttl_ok, "Cache-Control policy", detail);
    }
    let mut proof_bundle: Option<AliasProofBundleV1> = None;
    if let Some(proof_b64) = sora_proof_header {
        match BASE64_STD.decode(proof_b64.as_bytes()) {
            Ok(bytes) => match decode_alias_proof_untrusted_signers(&bytes) {
                Ok(bundle) => {
                    proof_bundle = Some(bundle);
                }
                Err(err) => record_finding(
                    &mut findings,
                    false,
                    "Sora-Proof decode",
                    format!("invalid alias proof bundle: {err}"),
                ),
            },
            Err(err) => {
                record_finding(
                    &mut findings,
                    false,
                    "Sora-Proof decode",
                    format!("base64 error: {err}"),
                );
            }
        }
    }
    if let (Some(alias), Some(bundle)) = (sora_name.as_ref(), proof_bundle.as_ref()) {
        let matches = alias == &bundle.binding.alias;
        record_finding(
            &mut findings,
            matches,
            "Sora-Name vs alias proof",
            if matches {
                format!("alias `{alias}` matches proof bundle")
            } else {
                format!(
                    "Sora-Name `{alias}` disagrees with proof bundle alias `{}`",
                    bundle.binding.alias
                )
            },
        );
    }
    if let Some(bundle) = proof_bundle.as_ref() {
        match alias_manifest_id(bundle) {
            Ok(proof_cid) => {
                if let Some(content_cid) = sora_content_cid.as_ref() {
                    let matches = proof_cid == *content_cid;
                    record_finding(
                        &mut findings,
                        matches,
                        "Alias proof manifest",
                        if matches {
                            format!("alias proof manifest `{proof_cid}` matches Sora-Content-CID")
                        } else {
                            format!(
                                "alias proof manifest `{proof_cid}` differs from Sora-Content-CID `{content_cid}`"
                            )
                        },
                    );
                }
            }
            Err(err) => record_finding(&mut findings, false, "Alias proof manifest", err),
        }
    }
    if let Some(content_cid) = sora_content_cid.as_ref() {
        let gar_cid = gar_record.manifest_cid().trim();
        let matches = content_cid.trim() == gar_cid;
        record_finding(
            &mut findings,
            matches,
            "GAR manifest CID",
            if matches {
                format!("Sora-Content-CID `{gar_cid}` matches GAR manifest")
            } else {
                format!("Sora-Content-CID `{content_cid}` differs from GAR manifest `{gar_cid}`")
            },
        );
    }
    if let (Some(bundle), Some(status_value)) = (proof_bundle.as_ref(), sora_proof_status.as_ref())
    {
        let policy = default_alias_policy();
        let evaluation = policy.evaluate(bundle, now_secs);
        let matches = proof_status_matches(&evaluation, status_value);
        let detail = format!(
            "status `{status_value}` vs evaluation `{}` (age {}s{})",
            evaluation.status_label(),
            evaluation.age.as_secs(),
            if evaluation.rotation_due {
                ", rotation due"
            } else {
                ""
            }
        );
        record_finding(&mut findings, matches, "Sora-Proof-Status", detail);
    }
    if log_to_stderr {
        eprintln!(
            "SoraFS gateway probe summary ({})",
            response.source.describe()
        );
    } else {
        println!(
            "SoraFS gateway probe summary ({})",
            response.source.describe()
        );
    }
    let mut has_failures = false;
    for finding in &findings {
        if finding.ok {
            if log_to_stderr {
                eprintln!("[ok] {} — {}", finding.name, finding.detail);
            } else {
                println!("[ok] {} — {}", finding.name, finding.detail);
            }
        } else {
            has_failures = true;
            if log_to_stderr {
                eprintln!("[fail] {} — {}", finding.name, finding.detail);
            } else {
                println!("[fail] {} — {}", finding.name, finding.detail);
            }
        }
    }
    if let Some(target) = report_target {
        let gar_info = GatewayProbeGarInfo::from_record(&options.gar_path, &gar_record);
        let report = build_probe_report_value(now_secs, &response, &host, &gar_info, &findings);
        write_json_output(&report, target)?;
    }
    let ended_at = OffsetDateTime::now_utc();
    let summary = ProbeRunSummary {
        started_at,
        ended_at,
        success: !has_failures,
        source_description: response.source.describe(),
        target_url: response.source.url().map(str::to_string),
        target_host: response.source.host().map(str::to_string),
        gar_path: options.gar_path.clone(),
        findings: &findings,
    };
    if let Some(path) = &options.summary_path {
        write_probe_summary(path, &summary)?;
    }
    if let Some(drill) = &options.drill {
        append_drill_log_entry(drill, &summary)?;
    }
    if has_failures {
        if let Some(config) = &options.pagerduty {
            emit_pagerduty_event(config, &summary)?;
        }
        return Err("one or more gateway probe checks failed".into());
    }
    if log_to_stderr {
        eprintln!("All SoraFS gateway probe checks passed.");
    } else {
        println!("All SoraFS gateway probe checks passed.");
    }
    Ok(())
}
fn load_and_verify_gar(
    options: &GatewayProbeOptions,
    now_secs: u64,
) -> Result<GatewayAuthorizationRecord, Box<dyn Error>> {
    let verifier = build_gar_verifier(&options.gar_keys)?;
    let raw = fs::read_to_string(&options.gar_path)
        .map_err(|err| format!("failed to read GAR {}: {err}", options.gar_path.display()))?;
    let jws = raw.trim();
    if jws.is_empty() {
        return Err(format!("GAR file {} was empty", options.gar_path.display()).into());
    }
    verifier
        .verify_at(jws, now_secs)
        .map_err(|err| format!("failed to verify GAR {}: {err}", options.gar_path.display()).into())
}
fn build_gar_verifier(
    entries: &[(String, Vec<u8>)],
) -> Result<GatewayAuthorizationVerifier, Box<dyn Error>> {
    let mut verifier = GatewayAuthorizationVerifier::default();
    for (kid, bytes) in entries {
        let public_key = PublicKey::from_bytes(Algorithm::Ed25519, bytes)
            .map_err(|err| format!("invalid GAR public key `{kid}`: {err}"))?;
        verifier.insert(kid.clone(), public_key);
    }
    Ok(verifier)
}
fn probe_headers_via_http(request: &GatewayProbeRequest) -> Result<ProbeResponse, Box<dyn Error>> {
    let method = request.method.trim().to_ascii_uppercase();
    let url = Url::parse(&request.url)
        .map_err(|err| format!("invalid gateway URL `{}`: {err}", request.url))?;
    let host = url.host_str().map(|h| h.to_ascii_lowercase());
    let mut builder = Client::builder().redirect(reqwest::redirect::Policy::none());
    if let Some(timeout) = request.timeout_secs {
        builder = builder.timeout(Duration::from_secs(timeout));
    }
    let client = builder.build()?;
    let mut req = match method.as_str() {
        "GET" => client.get(url.clone()),
        "HEAD" => client.head(url.clone()),
        other => {
            return Err(format!("unsupported HTTP method `{other}`").into());
        }
    };
    for (name, value) in &request.extra_headers {
        let header_name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|err| format!("invalid header name `{name}`: {err}"))?;
        let header_value = HeaderValue::from_str(value.trim())
            .map_err(|err| format!("invalid value for header `{name}`: {err}"))?;
        req = req.header(header_name, header_value);
    }
    let response = req.send()?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    Ok(ProbeResponse {
        status,
        headers,
        source: ProbeSource::Http {
            url: request.url.clone(),
            host,
        },
    })
}
fn probe_headers_from_file(path: &Path) -> Result<ProbeResponse, Box<dyn Error>> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read header file {}: {err}", path.display()))?;
    let mut lines = raw.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| format!("header file {} is empty", path.display()))?;
    let status = parse_status_line(status_line)?;
    let mut headers = HeaderMap::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("HTTP/") {
            // Ignore intermediate responses in case the dump captured redirects.
            continue;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(format!("invalid header line `{trimmed}` in {}", path.display()).into());
        };
        let header_name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|err| format!("invalid header name `{name}` in {}: {err}", path.display()))?;
        let header_value = HeaderValue::from_str(value.trim()).map_err(|err| {
            format!(
                "invalid header value for `{name}` in {}: {err}",
                path.display()
            )
        })?;
        headers.append(header_name, header_value);
    }
    Ok(ProbeResponse {
        status,
        headers,
        source: ProbeSource::File {
            path: path.to_path_buf(),
        },
    })
}
fn parse_status_line(line: &str) -> Result<u16, Box<dyn Error>> {
    let mut parts = line.split_whitespace();
    let _http = parts
        .next()
        .ok_or("invalid status line (missing HTTP version)")?;
    let status = parts
        .next()
        .ok_or("invalid status line (missing status code)")?;
    status
        .parse::<u16>()
        .map_err(|err| format!("invalid status code `{status}`: {err}").into())
}
fn resolve_probe_host(
    options: &GatewayProbeOptions,
    response: &ProbeResponse,
) -> Result<String, Box<dyn Error>> {
    if let Some(host) = &options.host_override {
        return Ok(host.trim().to_ascii_lowercase());
    }
    if let Some(host) = response.source.host() {
        return Ok(host.to_ascii_lowercase());
    }
    Err("host is unknown; provide --host when parsing captured headers".into())
}
fn expect_header(
    headers: &HeaderMap,
    name: &str,
    findings: &mut Vec<ProbeFinding>,
) -> Option<String> {
    match read_header(headers, name) {
        Ok(Some(value)) => Some(value),
        Ok(None) => {
            record_finding(findings, false, format!("{name} header"), "header missing");
            None
        }
        Err(err) => {
            record_finding(findings, false, format!("{name} header"), err);
            None
        }
    }
}
fn read_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, String> {
    match headers.get(name) {
        Some(value) => value
            .to_str()
            .map(|text| Some(text.trim().to_string()))
            .map_err(|err| format!("header `{name}` is not valid UTF-8: {err}")),
        None => Ok(None),
    }
}
fn parse_cache_directives(value: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for directive in value.split(',') {
        let trimmed = directive.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((key, val)) = trimmed.split_once('=') {
            map.insert(
                key.trim().to_ascii_lowercase(),
                val.trim().trim_matches('"').to_string(),
            );
        } else {
            map.insert(trimmed.to_ascii_lowercase(), String::new());
        }
    }
    map
}
fn findings_to_json(findings: &[ProbeFinding]) -> Vec<Value> {
    findings
        .iter()
        .map(|finding| {
            let mut map = Map::new();
            map.insert("ok".to_string(), Value::Bool(finding.ok));
            map.insert("name".to_string(), Value::String(finding.name.clone()));
            map.insert("detail".to_string(), Value::String(finding.detail.clone()));
            Value::Object(map)
        })
        .collect()
}
fn write_probe_summary(path: &Path, summary: &ProbeRunSummary) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create summary directory {}: {err}",
                parent.display()
            )
        })?;
    }
    let started = summary
        .started_at
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format summary start timestamp: {err}"))?;
    let ended = summary
        .ended_at
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format summary end timestamp: {err}"))?;
    let duration = (summary.ended_at - summary.started_at).whole_seconds();
    let mut root = Map::new();
    root.insert("started_at".into(), Value::String(started));
    root.insert("ended_at".into(), Value::String(ended));
    root.insert(
        "duration_seconds".into(),
        Value::Number(Number::from(duration)),
    );
    root.insert("success".into(), Value::Bool(summary.success));
    root.insert(
        "source".into(),
        Value::String(summary.source_description.clone()),
    );
    match &summary.target_url {
        Some(url) => {
            root.insert("target_url".into(), Value::String(url.clone()));
        }
        None => {
            root.insert("target_url".into(), Value::Null);
        }
    }
    match &summary.target_host {
        Some(host) => {
            root.insert("target_host".into(), Value::String(host.clone()));
        }
        None => {
            root.insert("target_host".into(), Value::Null);
        }
    }
    root.insert(
        "gar_path".into(),
        Value::String(summary.gar_path.display().to_string()),
    );
    root.insert(
        "failure_count".into(),
        Value::Number(Number::from(summary.failure_count() as u64)),
    );
    root.insert(
        "findings".into(),
        Value::Array(findings_to_json(summary.findings)),
    );
    let encoded = to_string_pretty(&Value::Object(root))
        .map_err(|err| format!("failed to encode summary JSON: {err}"))?;
    fs::write(path, encoded)
        .map_err(|err| format!("failed to write summary JSON {}: {err}", path.display()))?;
    Ok(())
}
fn append_drill_log_entry(
    config: &DrillLogConfig,
    summary: &ProbeRunSummary,
) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = config.log_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create drill log directory {}: {err}",
                parent.display()
            )
        })?;
    }
    let needs_header = !config.log_path.exists()
        || fs::metadata(&config.log_path)
            .map(|meta| meta.len() == 0)
            .unwrap_or(true);
    if needs_header {
        fs::write(&config.log_path, DRILL_LOG_HEADER).map_err(|err| {
            format!(
                "failed to initialise drill log {}: {err}",
                config.log_path.display()
            )
        })?;
    }
    let date = summary.started_at.date().to_string();
    let start = format!(
        "{:02}:{:02}Z",
        summary.started_at.hour(),
        summary.started_at.minute()
    );
    let end = format!(
        "{:02}:{:02}Z",
        summary.ended_at.hour(),
        summary.ended_at.minute()
    );
    let status = if summary.success { "pass" } else { "fail" };
    let scenario = sanitise_table_field(&config.scenario);
    let ic = config
        .ic
        .as_deref()
        .map(sanitise_table_field)
        .unwrap_or_else(|| "-".to_string());
    let scribe = config
        .scribe
        .as_deref()
        .map(sanitise_table_field)
        .unwrap_or_else(|| "-".to_string());
    let notes = config
        .notes
        .as_deref()
        .map(sanitise_table_field)
        .unwrap_or_else(|| "-".to_string());
    let link = config
        .link
        .as_deref()
        .map(sanitise_table_field)
        .unwrap_or_else(|| "-".to_string());
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&config.log_path)
        .map_err(|err| {
            format!(
                "failed to open drill log {}: {err}",
                config.log_path.display()
            )
        })?;
    writeln!(
        file,
        "| {date} | {scenario} | {status} | {ic} | {scribe} | {start} | {end} | {notes} | {link} |"
    )
    .map_err(|err| format!("failed to append drill log row: {err}"))?;
    Ok(())
}
fn sanitise_table_field(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed
            .replace('|', "&#124;")
            .replace('\n', "<br>")
            .replace('\r', "")
    }
}
fn emit_pagerduty_event(
    config: &PagerDutyConfig,
    summary: &ProbeRunSummary,
) -> Result<(), Box<dyn Error>> {
    let payload_value = pagerduty_payload_value(config, summary)?;
    let payload_text = to_string_pretty(&payload_value)
        .map_err(|err| format!("failed to encode PagerDuty payload: {err}"))?;
    if let Some(parent) = config.payload_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create PagerDuty payload directory {}: {err}",
                parent.display()
            )
        })?;
    }
    fs::write(&config.payload_path, payload_text.as_bytes()).map_err(|err| {
        format!(
            "failed to write PagerDuty payload {}: {err}",
            config.payload_path.display()
        )
    })?;
    if let Some(endpoint) = &config.endpoint_url {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|err| format!("failed to build PagerDuty client: {err}"))?;
        let response = client
            .post(endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload_text)
            .send()
            .map_err(|err| format!("failed to send PagerDuty request: {err}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "PagerDuty endpoint {} returned {}",
                endpoint,
                response.status()
            )
            .into());
        }
    }
    Ok(())
}
fn pagerduty_payload_value(
    config: &PagerDutyConfig,
    summary: &ProbeRunSummary,
) -> Result<Value, Box<dyn Error>> {
    let timestamp = summary
        .ended_at
        .format(&Rfc3339)
        .map_err(|err| format!("failed to format PagerDuty timestamp: {err}"))?;
    let mut custom_details = Map::new();
    if let Some(url) = &summary.target_url {
        custom_details.insert("target_url".into(), Value::String(url.clone()));
    }
    if let Some(host) = &summary.target_host {
        custom_details.insert("target_host".into(), Value::String(host.clone()));
    }
    custom_details.insert(
        "gar_path".into(),
        Value::String(summary.gar_path.display().to_string()),
    );
    let duration = (summary.ended_at - summary.started_at).whole_seconds();
    custom_details.insert(
        "duration_seconds".into(),
        Value::Number(Number::from(duration)),
    );
    custom_details.insert(
        "failure_count".into(),
        Value::Number(Number::from(summary.failure_count() as u64)),
    );
    custom_details.insert(
        "findings".into(),
        Value::Array(findings_to_json(summary.findings)),
    );
    let mut payload = Map::new();
    payload.insert(
        "summary".into(),
        Value::String(format!(
            "{} probe checks failed ({})",
            summary.failure_count(),
            summary.target_label()
        )),
    );
    payload.insert("severity".into(), Value::String(config.severity.clone()));
    payload.insert("source".into(), Value::String(config.source.clone()));
    if let Some(component) = &config.component {
        payload.insert("component".into(), Value::String(component.clone()));
    }
    if let Some(group) = &config.group {
        payload.insert("group".into(), Value::String(group.clone()));
    }
    if let Some(class_name) = &config.class_name {
        payload.insert("class".into(), Value::String(class_name.clone()));
    }
    payload.insert("timestamp".into(), Value::String(timestamp));
    payload.insert("custom_details".into(), Value::Object(custom_details));
    let mut event = Map::new();
    event.insert(
        "routing_key".into(),
        Value::String(config.routing_key.clone()),
    );
    event.insert("event_action".into(), Value::String("trigger".into()));
    if let Some(dedup) = &config.dedup_key {
        event.insert("dedup_key".into(), Value::String(dedup.clone()));
    }
    if !config.links.is_empty() {
        let mut link_values = Vec::with_capacity(config.links.len());
        for link in &config.links {
            let mut entry = Map::new();
            entry.insert("href".into(), Value::String(link.href.clone()));
            entry.insert("text".into(), Value::String(link.text.clone()));
            link_values.push(Value::Object(entry));
        }
        event.insert("links".into(), Value::Array(link_values));
    }
    event.insert("payload".into(), Value::Object(payload));
    Ok(Value::Object(event))
}
fn default_alias_policy() -> AliasCachePolicy {
    AliasCachePolicy::new(
        Duration::from_secs(DEFAULT_CACHE_MAX_AGE),
        Duration::from_secs(DEFAULT_CACHE_STALE_WHILE_REVALIDATE),
        Duration::from_secs(DEFAULT_CACHE_HARD_EXPIRY),
        Duration::from_secs(DEFAULT_CACHE_NEGATIVE_TTL),
        Duration::from_secs(DEFAULT_CACHE_REVOCATION_TTL),
        Duration::from_secs(DEFAULT_CACHE_ROTATION_MAX_AGE),
        Duration::from_secs(DEFAULT_SUCCESSOR_GRACE),
        Duration::from_secs(DEFAULT_GOVERNANCE_GRACE),
    )
}
fn proof_status_matches(evaluation: &AliasProofEvaluation, header: &str) -> bool {
    let normalized = header.trim().to_ascii_lowercase();
    match evaluation.state {
        AliasProofState::Fresh => {
            let acceptable: &[&str] = if evaluation.rotation_due {
                &["fresh-rotate", "fresh"][..]
            } else {
                &["fresh"][..]
            };
            acceptable.contains(&normalized.as_str())
        }
        AliasProofState::RefreshWindow => {
            let mut acceptable = vec!["refresh", "refresh-successor", "refresh-governance"];
            if evaluation.rotation_due {
                acceptable.push("refresh-rotate");
            }
            acceptable.contains(&normalized.as_str())
        }
        AliasProofState::Expired => normalized == "expired",
        AliasProofState::HardExpired => normalized == "hard-expired",
    }
}
fn alias_manifest_id(bundle: &AliasProofBundleV1) -> Result<String, String> {
    String::from_utf8(bundle.binding.manifest_cid.clone())
        .map(|text| text.trim().to_string())
        .map_err(|_| "manifest CID in alias proof is not valid UTF-8".to_string())
}
fn record_finding(
    findings: &mut Vec<ProbeFinding>,
    ok: bool,
    name: impl Into<String>,
    detail: impl Into<String>,
) {
    findings.push(ProbeFinding {
        ok,
        name: name.into(),
        detail: detail.into(),
    });
}
struct ProbeFinding {
    ok: bool,
    name: String,
    detail: String,
}
struct ProbeResponse {
    status: u16,
    headers: HeaderMap,
    source: ProbeSource,
}
enum ProbeSource {
    Http { url: String, host: Option<String> },
    File { path: PathBuf },
}
impl ProbeSource {
    fn describe(&self) -> String {
        match self {
            Self::Http { url, .. } => format!("HTTP probe via {url}"),
            Self::File { path } => format!("captured headers from {}", path.display()),
        }
    }
    fn host(&self) -> Option<&str> {
        match self {
            Self::Http { host, .. } => host.as_deref(),
            Self::File { .. } => None,
        }
    }
    fn url(&self) -> Option<&str> {
        match self {
            Self::Http { url, .. } => Some(url.as_str()),
            Self::File { .. } => None,
        }
    }
}
struct GatewayProbeGarInfo {
    path: String,
    name: String,
    record_version: u16,
    manifest_cid: String,
    valid_from_epoch: u64,
    valid_until_epoch: Option<u64>,
    host_patterns: Vec<String>,
}
impl GatewayProbeGarInfo {
    fn from_record(path: &Path, record: &GatewayAuthorizationRecord) -> Self {
        Self {
            path: path.display().to_string(),
            name: record.name().to_string(),
            record_version: record.record_version(),
            manifest_cid: record.manifest_cid().trim().to_string(),
            valid_from_epoch: record.valid_from_epoch(),
            valid_until_epoch: record.valid_until_epoch(),
            host_patterns: record
                .host_patterns()
                .iter()
                .map(|pattern| pattern.pattern().to_string())
                .collect(),
        }
    }
}
fn build_probe_report_value(
    timestamp: u64,
    response: &ProbeResponse,
    host: &str,
    gar_info: &GatewayProbeGarInfo,
    findings: &[ProbeFinding],
) -> Value {
    let failure_count = findings.iter().filter(|finding| !finding.ok).count() as u64;
    let mut root = Map::new();
    root.insert("ok".into(), Value::Bool(failure_count == 0));
    root.insert(
        "failure_count".into(),
        Value::Number(Number::from(failure_count)),
    );
    root.insert("timestamp".into(), Value::Number(Number::from(timestamp)));
    root.insert(
        "status".into(),
        Value::Number(Number::from(u64::from(response.status))),
    );
    root.insert("host".into(), Value::String(host.to_string()));
    root.insert("source".into(), probe_source_json(&response.source));
    root.insert("gar".into(), gar_info_to_json(gar_info));
    root.insert("findings".into(), Value::Array(findings_to_json(findings)));
    if failure_count > 0 {
        root.insert(
            "failures".into(),
            Value::Array(
                findings
                    .iter()
                    .filter(|finding| !finding.ok)
                    .map(|finding| Value::String(finding.name.clone()))
                    .collect(),
            ),
        );
    }
    Value::Object(root)
}
fn gar_info_to_json(gar_info: &GatewayProbeGarInfo) -> Value {
    let mut map = Map::new();
    map.insert("path".into(), Value::String(gar_info.path.clone()));
    map.insert("name".into(), Value::String(gar_info.name.clone()));
    map.insert(
        "record_version".into(),
        Value::Number(Number::from(u64::from(gar_info.record_version))),
    );
    map.insert(
        "manifest_cid".into(),
        Value::String(gar_info.manifest_cid.clone()),
    );
    map.insert(
        "valid_from".into(),
        Value::Number(Number::from(gar_info.valid_from_epoch)),
    );
    match gar_info.valid_until_epoch {
        Some(value) => {
            map.insert("valid_until".into(), Value::Number(Number::from(value)));
        }
        None => {
            map.insert("valid_until".into(), Value::Null);
        }
    }
    map.insert(
        "host_patterns".into(),
        Value::Array(
            gar_info
                .host_patterns
                .iter()
                .map(|pattern| Value::String(pattern.clone()))
                .collect(),
        ),
    );
    Value::Object(map)
}
fn probe_source_json(source: &ProbeSource) -> Value {
    match source {
        ProbeSource::Http { url, host } => {
            let mut map = Map::new();
            map.insert("type".into(), Value::String("http".to_string()));
            map.insert("url".into(), Value::String(url.clone()));
            if let Some(host) = host {
                map.insert("host".into(), Value::String(host.clone()));
            }
            Value::Object(map)
        }
        ProbeSource::File { path } => {
            let mut map = Map::new();
            map.insert("type".into(), Value::String("headers-file".to_string()));
            map.insert("path".into(), Value::String(path.display().to_string()));
            Value::Object(map)
        }
    }
}
fn ensure_profile_matches(root: &Value, expected: &str) -> Result<(), Box<dyn Error>> {
    let profile = extract_string(root, "profile")?;
    if profile != expected {
        return Err(format!("expected profile {expected} but found {profile}").into());
    }
    Ok(())
}
fn ensure_aliases(root: &Value, canonical: &str) -> Result<(), Box<dyn Error>> {
    let aliases = root
        .get("profile_aliases")
        .and_then(Value::as_array)
        .ok_or_else(|| "profile_aliases array missing".to_owned())?;
    let mut seen = HashSet::with_capacity(aliases.len());
    for entry in aliases {
        if let Some(text) = entry.as_str() {
            seen.insert(text.to_owned());
        }
    }
    if !seen.contains(canonical) {
        return Err(format!("profile_aliases missing canonical handle {canonical}").into());
    }
    Ok(())
}
fn verify_manifest_signatures(
    root: &Value,
    manifest_digest: &[u8],
    allow_unsigned: bool,
) -> Result<usize, Box<dyn Error>> {
    let entries = root
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| "manifest signatures missing signatures array".to_owned())?;
    if entries.is_empty() {
        if allow_unsigned {
            eprintln!(
                "warning: manifest signatures array empty; continuing due to --allow-unsigned"
            );
            return Ok(0);
        }
        return Err("manifest signatures array empty".into());
    }
    for entry in entries {
        let map = entry
            .as_object()
            .ok_or_else(|| "signature entry must be an object".to_owned())?;
        let algorithm = map
            .get("algorithm")
            .and_then(Value::as_str)
            .ok_or_else(|| "signature entry missing algorithm".to_owned())?;
        if algorithm != "ed25519" {
            return Err(format!("unsupported signature algorithm {algorithm}").into());
        }
        let signer_hex = map
            .get("signer")
            .and_then(Value::as_str)
            .ok_or_else(|| "signature entry missing signer".to_owned())?;
        let signature_hex = map
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| "signature entry missing signature".to_owned())?;
        let signer_bytes = decode_hex(signer_hex)?;
        let signature_bytes = decode_hex(signature_hex)?;
        let public_key = PublicKey::from_bytes(Algorithm::Ed25519, &signer_bytes)
            .map_err(|err| format!("invalid signer public key: {err}"))?;
        let public_key_hex = public_key.to_string();
        if let Some(multihash) = map.get("signer_multihash").and_then(Value::as_str)
            && multihash != public_key_hex
        {
            return Err("signer_multihash does not match encoded public key".into());
        }
        let signature = iroha_crypto::ed25519_parse_signature(&signature_bytes)
            .map_err(|err| format!("invalid signature material: {err}"))?;
        signature
            .verify(&public_key, manifest_digest)
            .map_err(|err| format!("signature verification failed: {err}"))?;
    }
    Ok(entries.len())
}
fn extract_string<'a>(root: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    root.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} field missing or not a string").into())
}
fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    hex::decode(input.trim())
        .map_err(|err| format!("failed to decode hex value {input}: {err}").into())
}
fn checked_ed25519_public_key_bytes<'a>(
    public_key: &'a PublicKey,
    context: &str,
) -> Result<&'a [u8], Box<dyn Error>> {
    let (algorithm, public_bytes) = public_key
        .try_to_bytes()
        .map_err(|err| format!("{context} is malformed: {err}"))?;
    if algorithm != Algorithm::Ed25519 {
        return Err(format!(
            "{context} must be Ed25519, got {}",
            algorithm.as_static_str()
        )
        .into());
    }
    if public_bytes.len() != 32 {
        return Err(format!(
            "{context} must be a 32-byte Ed25519 public key, got {} bytes",
            public_bytes.len()
        )
        .into());
    }
    Ok(public_bytes)
}
fn checked_ed25519_public_key_array(
    public_key: &PublicKey,
    context: &str,
) -> Result<[u8; 32], Box<dyn Error>> {
    let public_bytes = checked_ed25519_public_key_bytes(public_key, context)?;
    public_bytes.try_into().map_err(|_| {
        format!(
            "{context} must be a 32-byte Ed25519 public key, got {} bytes",
            public_bytes.len()
        )
        .into()
    })
}
// Synthetic fixture identity only; production admissions use an explicit genesis hash.
const PROVIDER_ADMISSION_FIXTURE_NETWORK_ID: [u8; 32] = [0xA1; 32];
const PROVIDER_ADMISSION_FIXTURE_COUNCIL_SEEDS: [&str; 2] = [
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
];
fn provider_admission_fixture_council_keypairs() -> Result<Vec<KeyPair>, Box<dyn Error>> {
    PROVIDER_ADMISSION_FIXTURE_COUNCIL_SEEDS
        .iter()
        .map(|seed| {
            let bytes = decode_hex_array::<32>(seed)?;
            KeyPair::try_from_seed(bytes.to_vec(), Algorithm::Ed25519).map_err(|err| {
                format!("failed to derive council admission fixture key: {err}").into()
            })
        })
        .collect()
}
fn provider_admission_fixture_council_policy(
    keypairs: &[KeyPair],
) -> Result<ProviderAdmissionCouncilPolicy, Box<dyn Error>> {
    let trusted_signers = keypairs
        .iter()
        .map(|keypair| checked_ed25519_public_key_array(keypair.public_key(), "council public key"))
        .collect::<Result<Vec<_>, _>>()?;
    ProviderAdmissionCouncilPolicy::new(trusted_signers, keypairs.len())
        .map_err(|err| format!("invalid council admission fixture policy: {err}").into())
}
pub fn write_admission_fixtures(target_dir: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(target_dir)?;
    let descriptor = chunker_registry::lookup_by_handle("sorafs.sf1@1.0.0")
        .ok_or("chunker profile sorafs.sf1@1.0.0 is not registered in the chunker registry")?;
    let canonical_handle = format!(
        "{}.{}@{}",
        descriptor.namespace, descriptor.name, descriptor.semver
    );
    let profile_aliases = canonical_profile_aliases(descriptor);
    let provider_seed =
        decode_hex_array::<32>("505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f")?;
    let provider_pair = KeyPair::try_from_seed(provider_seed.to_vec(), Algorithm::Ed25519)
        .map_err(|err| format!("failed to derive provider admission fixture key: {err}"))?;
    let provider_public =
        checked_ed25519_public_key_array(provider_pair.public_key(), "provider public key")?;
    let provider_public_vec = provider_public.to_vec();
    let (vrf_public, vrf_private) =
        BlsNormal::try_keypair(KeyGenOption::UseSeed(provider_seed.to_vec()))
            .map_err(|err| format!("failed to derive provider VRF fixture key: {err}"))?;
    let vrf_pair: KeyPair = (vrf_public, vrf_private).into();
    let provider_vrf_key = ProviderVrfPublicKeyV1::BlsNormal(
        vrf_pair
            .public_key()
            .to_bytes()
            .1
            .try_into()
            .map_err(|_| "Normal BLS public key must be 48 bytes")?,
    );
    let provider_id =
        decode_hex_array::<32>("11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff")?;
    let stake_pool_id =
        decode_hex_array::<32>("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")?;
    let range_capability = ProviderCapabilityRangeV1 {
        max_chunk_span: 32,
        min_granularity: 8,
        supports_sparse_offsets: true,
        requires_alignment: false,
        supports_merkle_proof: true,
    }
    .to_bytes()
    .expect("encode range capability");
    let capabilities = vec![
        CapabilityTlv {
            cap_type: CapabilityType::ToriiGateway,
            payload: Vec::new(),
        },
        CapabilityTlv {
            cap_type: CapabilityType::QuicNoise,
            payload: Vec::new(),
        },
        CapabilityTlv {
            cap_type: CapabilityType::ChunkRangeFetch,
            payload: range_capability,
        },
    ];
    let torii_endpoint = AdvertEndpoint {
        kind: EndpointKind::Torii,
        host_pattern: "storage.alpha.svc".to_owned(),
        metadata: Vec::new(),
    };
    let torii_attestation = EndpointAttestationV1 {
        version: sorafs_manifest::ENDPOINT_ATTESTATION_VERSION_V1,
        kind: EndpointAttestationKind::Tls,
        attested_at: 1_700_592_000,
        expires_at: 1_703_198_400,
        leaf_certificate: decode_hex_vec("3081deadbeef")?,
        intermediate_certificates: vec![decode_hex_vec("aa55cc33")?],
        alpn_ids: vec!["h2".to_owned()],
        report: decode_hex_vec("9091")?,
    };
    let quic_endpoint = AdvertEndpoint {
        kind: EndpointKind::Quic,
        host_pattern: "quic.alpha.svc".to_owned(),
        metadata: Vec::new(),
    };
    let quic_attestation = EndpointAttestationV1 {
        version: sorafs_manifest::ENDPOINT_ATTESTATION_VERSION_V1,
        kind: EndpointAttestationKind::Quic,
        attested_at: 1_700_595_600,
        expires_at: 1_703_202_000,
        leaf_certificate: decode_hex_vec("3045feedface")?,
        intermediate_certificates: Vec::new(),
        alpn_ids: vec!["h3".to_owned()],
        report: decode_hex_vec("a1b2c3")?,
    };
    let endpoints = vec![
        EndpointAdmissionV1 {
            endpoint: torii_endpoint.clone(),
            attestation: torii_attestation,
        },
        EndpointAdmissionV1 {
            endpoint: quic_endpoint.clone(),
            attestation: quic_attestation,
        },
    ];
    let stake_pointer = StakePointer {
        pool_id: stake_pool_id,
        stake_amount: XorQuantity::try_from_micro(7_500).expect("fixture stake is representable"),
    };
    let proposal = ProviderAdmissionProposalV1 {
        version: sorafs_manifest::PROVIDER_ADMISSION_PROPOSAL_VERSION_V1,
        provider_id,
        profile_id: canonical_handle.clone(),
        profile_aliases: Some(profile_aliases.clone()),
        stake: stake_pointer.clone(),
        capabilities: capabilities.clone(),
        endpoints: endpoints.clone(),
        advert_key: provider_public,
        por_vrf_key: provider_vrf_key,
        jurisdiction_code: "JP".to_owned(),
        contact_uri: Some("https://alpha.example/ops".to_owned()),
        stream_budget: Some(StreamBudgetV1 {
            max_in_flight: 10,
            max_bytes_per_sec: 12_000_000,
            burst_bytes: Some(6_000_000),
        }),
        transport_hints: Some(vec![
            TransportHintV1 {
                protocol: TransportProtocol::ToriiHttpRange,
                priority: 0,
            },
            TransportHintV1 {
                protocol: TransportProtocol::QuicStream,
                priority: 1,
            },
        ]),
    };
    proposal
        .validate()
        .map_err(|err| format!("proposal validation failed: {err}"))?;
    let proposal_bytes = to_bytes(&proposal)?;
    let proposal_digest = compute_proposal_digest(&proposal)?;
    let advert_body = ProviderAdvertBodyV1 {
        provider_id,
        profile_id: canonical_handle.clone(),
        profile_aliases: Some(profile_aliases.clone()),
        stake: stake_pointer,
        qos: QosHints {
            availability: AvailabilityTier::Hot,
            max_retrieval_latency_ms: 1_200,
            max_concurrent_streams: 32,
        },
        capabilities: capabilities.clone(),
        endpoints: vec![torii_endpoint, quic_endpoint],
        rendezvous_topics: vec![
            RendezvousTopic {
                topic: "sorafs.sf1.primary".to_owned(),
                region: "global".to_owned(),
            },
            RendezvousTopic {
                topic: "sorafs.sf1.apac".to_owned(),
                region: "JP".to_owned(),
            },
        ],
        path_policy: PathDiversityPolicy {
            min_guard_weight: 10,
            max_same_asn_per_path: 1,
            max_same_pool_per_path: 1,
        },
        notes: Some("Fixture provider for CI verification".to_owned()),
        stream_budget: proposal.stream_budget,
        transport_hints: proposal.transport_hints.clone(),
    };
    advert_body
        .validate()
        .map_err(|err| format!("advert body validation failed: {err}"))?;
    let advert_body_bytes = to_bytes(&advert_body)?;
    let issued_at = 1_700_592_000;
    let expires_at = issued_at + 3_600;
    let mut advert = ProviderAdvertV1 {
        version: sorafs_manifest::PROVIDER_ADVERT_VERSION_V1,
        network_id: PROVIDER_ADMISSION_FIXTURE_NETWORK_ID,
        issued_at,
        expires_at,
        body: advert_body.clone(),
        signature: sorafs_manifest::AdvertSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: provider_public_vec.clone(),
            signature: vec![0; 64],
        },
        signature_strict: true,
        allow_unknown_capabilities: false,
    };
    let advert_signature_payload = advert.signature_payload_bytes()?;
    advert.signature.signature = Signature::try_new(
        provider_pair.private_key(),
        advert_signature_payload.as_slice(),
    )
    .map_err(|err| format!("failed to sign provider advert fixture: {err}"))?
    .payload()
    .to_vec();
    advert
        .validate_with_body(issued_at)
        .map_err(|err| format!("advert validation failed: {err}"))?;
    advert
        .verify_signature()
        .map_err(|err| format!("advert signature validation failed: {err}"))?;
    let advert_bytes = to_bytes(&advert)?;
    let advert_body_digest = compute_advert_body_digest(&advert_body)?;
    let council_keypairs = provider_admission_fixture_council_keypairs()?;
    let council_policy = provider_admission_fixture_council_policy(&council_keypairs)?;
    let retention_epoch = issued_at + 86_400 * 90;
    let mut envelope = ProviderAdmissionEnvelopeV1 {
        version: sorafs_manifest::PROVIDER_ADMISSION_ENVELOPE_VERSION_V1,
        network_id: PROVIDER_ADMISSION_FIXTURE_NETWORK_ID,
        policy_id: [0xC1; 32],
        policy_revision: 1,
        policy_digest: [0xD1; 32],
        admission_revision: 1,
        expected_current_event_digest: None,
        proposal: proposal.clone(),
        proposal_digest,
        advert_body: advert_body.clone(),
        advert_body_digest,
        issued_at,
        retention_epoch,
        council_signatures: Vec::new(),
        notes: Some("Fixture council approval for provider alpha".to_owned()),
    };
    let authorization_digest = compute_envelope_authorization_digest(&envelope)?;
    let mut council_signatures = council_keypairs
        .iter()
        .map(|council_pair| {
            let signer =
                checked_ed25519_public_key_array(council_pair.public_key(), "council public key")?;
            let signature =
                Signature::try_new(council_pair.private_key(), authorization_digest.as_slice())
                    .map_err(|err| format!("failed to sign council admission fixture: {err}"))?;
            Ok(CouncilSignature {
                signer,
                signature: signature.payload().to_vec(),
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    council_signatures.sort_unstable_by_key(|signature| signature.signer);
    envelope.council_signatures = council_signatures.clone();
    let record = AdmissionRecord::new(envelope.clone(), &council_policy)
        .map_err(|err| format!("envelope validation failed: {err}"))?;
    verify_advert_against_record(&advert, &record)
        .map_err(|err| format!("fixture advert mismatched envelope: {err}"))?;
    let envelope_bytes = to_bytes(&envelope)?;
    let envelope_digest = compute_envelope_digest(&envelope)?;
    write_binary(
        target_dir.join("provider_alpha_proposal.to"),
        &proposal_bytes,
    )?;
    write_binary(
        target_dir.join("provider_alpha_advert_body.to"),
        &advert_body_bytes,
    )?;
    write_binary(target_dir.join("provider_alpha_advert.to"), &advert_bytes)?;
    write_binary(
        target_dir.join("provider_alpha_envelope.to"),
        &envelope_bytes,
    )?;
    write_json_file(
        target_dir.join("provider_alpha_proposal.json"),
        build_proposal_summary(
            &proposal,
            &proposal_bytes,
            &proposal_digest,
            &profile_aliases,
        ),
    )?;
    write_json_file(
        target_dir.join("provider_alpha_advert_body.json"),
        build_advert_body_summary(&advert_body, &capabilities),
    )?;
    write_json_file(
        target_dir.join("provider_alpha_advert.json"),
        build_advert_summary(&advert, &advert_bytes, &advert_body_digest),
    )?;
    write_json_file(
        target_dir.join("provider_alpha_envelope.json"),
        build_envelope_summary(
            &envelope,
            &council_signatures,
            &proposal_digest,
            &advert_body_digest,
            &envelope_digest,
        ),
    )?;
    write_json_file(
        target_dir.join("provider_alpha_metadata.json"),
        build_metadata_summary(
            &proposal_digest,
            &advert_body_digest,
            record.envelope_digest(),
            &council_signatures,
        ),
    )?;
    write_readme(target_dir)?;
    Ok(())
}
fn canonical_profile_aliases(descriptor: &ChunkerProfileDescriptor) -> Vec<String> {
    let canonical_handle = format!(
        "{}.{}@{}",
        descriptor.namespace, descriptor.name, descriptor.semver
    );
    let mut aliases = Vec::with_capacity(descriptor.aliases.len() + 1);
    aliases.push(canonical_handle.clone());
    aliases.extend(descriptor.aliases.iter().map(|alias| alias.to_string()));
    let mut seen = HashSet::new();
    aliases.retain(|alias| seen.insert(alias.clone()));
    aliases
}
fn build_proposal_summary(
    proposal: &ProviderAdmissionProposalV1,
    proposal_bytes: &[u8],
    proposal_digest: &[u8; 32],
    aliases: &[String],
) -> Map {
    let mut map = Map::new();
    map.insert("version".into(), Value::from(proposal.version as u64));
    map.insert(
        "provider_id_hex".into(),
        Value::from(hex_lower(proposal.provider_id)),
    );
    map.insert(
        "profile_id".into(),
        Value::from(proposal.profile_id.clone()),
    );
    map.insert(
        "profile_aliases".into(),
        Value::Array(
            aliases
                .iter()
                .map(|alias| Value::from(alias.clone()))
                .collect(),
        ),
    );
    map.insert(
        "stake_pool_id_hex".into(),
        Value::from(hex_lower(proposal.stake.pool_id)),
    );
    map.insert(
        "stake_amount".into(),
        Value::from(proposal.stake.stake_amount.to_string()),
    );
    map.insert(
        "jurisdiction_code".into(),
        Value::from(proposal.jurisdiction_code.clone()),
    );
    if let Some(contact) = &proposal.contact_uri {
        map.insert("contact_uri".into(), Value::from(contact.clone()));
    }
    map.insert(
        "endpoint_count".into(),
        Value::from(proposal.endpoints.len() as u64),
    );
    map.insert(
        "stream_budget".into(),
        match proposal.stream_budget.as_ref() {
            Some(budget) => stream_budget_to_value(budget),
            None => Value::Null,
        },
    );
    map.insert(
        "transport_hints".into(),
        match proposal.transport_hints.as_ref() {
            Some(hints) => transport_hints_to_value(hints),
            None => Value::Null,
        },
    );
    map.insert(
        "capability_types".into(),
        Value::Array(
            proposal
                .capabilities
                .iter()
                .map(|cap| Value::from(capability_label(cap.cap_type)))
                .collect(),
        ),
    );
    map.insert(
        "proposal_len".into(),
        Value::from(proposal_bytes.len() as u64),
    );
    map.insert(
        "proposal_digest_hex".into(),
        Value::from(hex_lower(proposal_digest)),
    );
    map
}
fn build_advert_body_summary(
    advert_body: &ProviderAdvertBodyV1,
    capabilities: &[CapabilityTlv],
) -> Map {
    let mut map = Map::new();
    map.insert(
        "provider_id_hex".into(),
        Value::from(hex_lower(advert_body.provider_id)),
    );
    map.insert(
        "profile_id".into(),
        Value::from(advert_body.profile_id.clone()),
    );
    map.insert(
        "profile_aliases".into(),
        Value::Array(
            advert_body
                .profile_aliases
                .as_ref()
                .map(|aliases| {
                    aliases
                        .iter()
                        .map(|alias| Value::from(alias.clone()))
                        .collect()
                })
                .unwrap_or_default(),
        ),
    );
    map.insert(
        "stake_pool_id_hex".into(),
        Value::from(hex_lower(advert_body.stake.pool_id)),
    );
    map.insert(
        "stake_amount".into(),
        Value::from(advert_body.stake.stake_amount.to_string()),
    );
    map.insert(
        "availability".into(),
        Value::from(match advert_body.qos.availability {
            AvailabilityTier::Hot => "hot",
            AvailabilityTier::Warm => "warm",
            AvailabilityTier::Cold => "cold",
        }),
    );
    map.insert(
        "max_retrieval_latency_ms".into(),
        Value::from(advert_body.qos.max_retrieval_latency_ms as u64),
    );
    map.insert(
        "max_concurrent_streams".into(),
        Value::from(advert_body.qos.max_concurrent_streams as u64),
    );
    map.insert(
        "capability_types".into(),
        Value::Array(
            capabilities
                .iter()
                .map(|cap| Value::from(capability_label(cap.cap_type)))
                .collect(),
        ),
    );
    map.insert(
        "endpoint_count".into(),
        Value::from(advert_body.endpoints.len() as u64),
    );
    map.insert(
        "stream_budget".into(),
        match advert_body.stream_budget.as_ref() {
            Some(budget) => stream_budget_to_value(budget),
            None => Value::Null,
        },
    );
    map.insert(
        "transport_hints".into(),
        match advert_body.transport_hints.as_ref() {
            Some(hints) => transport_hints_to_value(hints),
            None => Value::Null,
        },
    );
    map.insert(
        "rendezvous_topics".into(),
        Value::Array(
            advert_body
                .rendezvous_topics
                .iter()
                .map(|topic| {
                    let mut entry = Map::new();
                    entry.insert("topic".into(), Value::from(topic.topic.clone()));
                    entry.insert("region".into(), Value::from(topic.region.clone()));
                    Value::Object(entry)
                })
                .collect(),
        ),
    );
    map
}
fn build_advert_summary(
    advert: &ProviderAdvertV1,
    advert_bytes: &[u8],
    advert_body_digest: &[u8; 32],
) -> Map {
    let mut map = Map::new();
    map.insert("version".into(), Value::from(advert.version as u64));
    map.insert("issued_at".into(), Value::from(advert.issued_at));
    map.insert("expires_at".into(), Value::from(advert.expires_at));
    map.insert(
        "signature_alg".into(),
        Value::from(match advert.signature.algorithm {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::MultiSig => "multi_sig",
        }),
    );
    map.insert(
        "public_key_hex".into(),
        Value::from(hex_lower(&advert.signature.public_key)),
    );
    map.insert(
        "signature_hex".into(),
        Value::from(hex_lower(&advert.signature.signature)),
    );
    map.insert("advert_len".into(), Value::from(advert_bytes.len() as u64));
    map.insert(
        "advert_body_digest_hex".into(),
        Value::from(hex_lower(advert_body_digest)),
    );
    map.insert(
        "stream_budget".into(),
        match advert.body.stream_budget.as_ref() {
            Some(budget) => stream_budget_to_value(budget),
            None => Value::Null,
        },
    );
    map.insert(
        "transport_hints".into(),
        match advert.body.transport_hints.as_ref() {
            Some(hints) => transport_hints_to_value(hints),
            None => Value::Null,
        },
    );
    map
}
fn build_envelope_summary(
    envelope: &ProviderAdmissionEnvelopeV1,
    signatures: &[CouncilSignature],
    proposal_digest: &[u8; 32],
    advert_body_digest: &[u8; 32],
    envelope_digest: &[u8; 32],
) -> Map {
    let mut map = Map::new();
    map.insert("version".into(), Value::from(envelope.version as u64));
    map.insert(
        "network_id_hex".into(),
        Value::from(hex_lower(envelope.network_id)),
    );
    map.insert(
        "policy_id_hex".into(),
        Value::from(hex_lower(envelope.policy_id)),
    );
    map.insert(
        "policy_revision".into(),
        Value::from(envelope.policy_revision),
    );
    map.insert(
        "policy_digest_hex".into(),
        Value::from(hex_lower(envelope.policy_digest)),
    );
    map.insert(
        "admission_revision".into(),
        Value::from(envelope.admission_revision),
    );
    map.insert("issued_at".into(), Value::from(envelope.issued_at));
    map.insert(
        "retention_epoch".into(),
        Value::from(envelope.retention_epoch),
    );
    map.insert(
        "proposal_digest_hex".into(),
        Value::from(hex_lower(proposal_digest)),
    );
    map.insert(
        "advert_body_digest_hex".into(),
        Value::from(hex_lower(advert_body_digest)),
    );
    map.insert(
        "envelope_digest_hex".into(),
        Value::from(hex_lower(envelope_digest)),
    );
    map.insert(
        "council_signature_count".into(),
        Value::from(signatures.len() as u64),
    );
    map.insert(
        "council_signers".into(),
        Value::Array(
            signatures
                .iter()
                .map(|sig| Value::from(hex_lower(sig.signer)))
                .collect(),
        ),
    );
    if let Some(notes) = &envelope.notes {
        map.insert("notes".into(), Value::from(notes.clone()));
    }
    map
}
fn build_metadata_summary(
    proposal_digest: &[u8; 32],
    advert_body_digest: &[u8; 32],
    envelope_digest: &[u8; 32],
    signatures: &[CouncilSignature],
) -> Map {
    let mut map = Map::new();
    map.insert(
        "proposal_digest_hex".into(),
        Value::from(hex_lower(proposal_digest)),
    );
    map.insert(
        "advert_body_digest_hex".into(),
        Value::from(hex_lower(advert_body_digest)),
    );
    map.insert(
        "envelope_digest_hex".into(),
        Value::from(hex_lower(envelope_digest)),
    );
    map.insert(
        "council_signatures".into(),
        Value::Array(
            signatures
                .iter()
                .map(|sig| {
                    let mut entry = Map::new();
                    entry.insert("signer".into(), Value::from(hex_lower(sig.signer)));
                    entry.insert(
                        "signature_hex".into(),
                        Value::from(hex_lower(&sig.signature)),
                    );
                    Value::Object(entry)
                })
                .collect(),
        ),
    );
    map
}
fn write_binary(path: PathBuf, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}
fn write_json_file(path: PathBuf, map: Map) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut text = to_string_pretty(&Value::Object(map))?;
    text.push('\n');
    fs::write(path, text)?;
    Ok(())
}
fn write_readme(target_dir: &Path) -> Result<(), Box<dyn Error>> {
    let readme_path = target_dir.join("README.md");
    let mut content = String::from(
        "# SoraFS Provider Admission Fixtures\n\n\
These fixtures capture the deterministic admission bundle used across CLI and Torii tests.\n\n\
- `provider_alpha_proposal.to` — Norito-encoded `ProviderAdmissionProposalV1`\n\
- `provider_alpha_advert_body.to` — Norito-encoded `ProviderAdvertBodyV1`\n\
- `provider_alpha_advert.to` — Signed `ProviderAdvertV1` payload\n\
- `provider_alpha_envelope.to` — Governance envelope binding the proposal, advert, and council signatures\n\
- `provider_alpha_metadata.json` — Digest and signer summary for quick verification\n\n\
Regenerate the fixtures with:\n\n```\n\
cargo xtask sorafs-admission-fixtures\n\
```\n\n\
The generator keeps the canonical chunker aliases, advert capabilities, and council signatures\n\
stable so CI can detect drift or accidental edits.\n",
    );
    content.push('\n');
    fs::write(readme_path, content)?;
    Ok(())
}
fn decode_hex_array<const N: usize>(input: &str) -> Result<[u8; N], Box<dyn Error>> {
    let bytes = hex::decode(input).map_err(|err| format!("invalid hex `{input}`: {err}"))?;
    if bytes.len() != N {
        return Err(format!(
            "expected {N} bytes from hex `{input}`, found {}",
            bytes.len()
        )
        .into());
    }
    let mut array = [0u8; N];
    array.copy_from_slice(&bytes);
    Ok(array)
}
fn decode_hex_vec(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    hex::decode(input).map_err(|err| format!("invalid hex `{input}`: {err}").into())
}
fn hex_lower<T: AsRef<[u8]>>(bytes: T) -> String {
    hex::encode(bytes)
}
fn stream_budget_to_value(budget: &StreamBudgetV1) -> Value {
    let mut map = Map::new();
    map.insert(
        "max_in_flight".into(),
        Value::from(budget.max_in_flight as u64),
    );
    map.insert(
        "max_bytes_per_sec".into(),
        Value::from(budget.max_bytes_per_sec),
    );
    map.insert(
        "burst_bytes".into(),
        match budget.burst_bytes {
            Some(burst) => Value::from(burst),
            None => Value::Null,
        },
    );
    Value::Object(map)
}
fn transport_hints_to_value(hints: &[TransportHintV1]) -> Value {
    Value::Array(
        hints
            .iter()
            .map(|hint| {
                let mut map = Map::new();
                map.insert(
                    "protocol".into(),
                    Value::from(transport_protocol_label(hint.protocol)),
                );
                map.insert("priority".into(), Value::from(hint.priority as u64));
                Value::Object(map)
            })
            .collect(),
    )
}
fn transport_protocol_label(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::ToriiHttpRange => "torii_http_range",
        TransportProtocol::QuicStream => "quic_stream",
        TransportProtocol::SoraNetRelay => "soranet_relay",
        TransportProtocol::VendorReserved => "vendor_reserved",
    }
}
fn capability_label(cap: CapabilityType) -> &'static str {
    match cap {
        CapabilityType::ToriiGateway => "torii_gateway",
        CapabilityType::QuicNoise => "quic_noise",
        CapabilityType::SoraNetHybridPq => "soranet_pq",
        CapabilityType::ChunkRangeFetch => "chunk_range_fetch",
        CapabilityType::PotrMlDsa => "potr_mldsa",
        CapabilityType::RegisteredAccountRead => "registered_account_read",
        CapabilityType::VendorReserved => "vendor_reserved",
    }
}
pub fn write_pin_registry_fixture(output: PathBuf) -> Result<(), Box<dyn Error>> {
    let providers = [
        ProviderId::new([0x51; 32]),
        ProviderId::new([0x52; 32]),
        ProviderId::new([0x53; 32]),
    ];
    let state = pin_fixture_make_state(&providers);
    pin_fixture_commit_completion_anchor(&state)?;
    let mut block = state.block(pin_fixture_block_header(2));
    let mut tx = block.transaction();
    pin_fixture_bootstrap(&mut tx, &providers)?;
    let (digest, manifest_root_cid, manifest_payload) = pin_fixture_default_manifest()?;
    let council_keys = pin_fixture_council_keypair();
    pin_fixture_register_and_approve(&mut tx, digest, manifest_payload, &council_keys)?;
    let alias_binding =
        pin_fixture_alias_binding_for(&manifest_root_cid, "sora", "docs", 12, 36, &council_keys)?;
    BindManifestAlias {
        digest,
        binding: alias_binding.clone(),
        bound_epoch: 12,
        expiry_epoch: 36,
    }
    .execute(&pin_fixture_alice(), &mut tx)
    .map_err(|err| format!("failed to bind alias: {err}"))?;
    let order_id = ReplicationOrderId::new([0x44; 32]);
    let order_struct =
        pin_fixture_replication_order(order_id, digest, &manifest_root_cid, &providers, 3);
    let order_payload = norito::to_bytes(&order_struct)?;
    IssueReplicationOrder {
        order_id,
        order_payload,
        issued_epoch: 20,
        deadline_epoch: 28,
        musubi_archive: None,
    }
    .execute(&pin_fixture_alice(), &mut tx)
    .map_err(|err| format!("failed to issue replication order: {err}"))?;
    for provider_id in providers {
        CompleteReplicationOrder {
            order_id,
            provider_id,
            completion_epoch: 25,
            expected_authority: pin_fixture_completion_authority(),
            expected_assignment_revision: 1,
            finalized_anchor: pin_fixture_completion_anchor(),
        }
        .execute(&pin_fixture_alice(), &mut tx)
        .map_err(|err| format!("failed to complete provider replication assignment: {err}"))?;
    }
    tx.apply();
    block
        .commit()
        .map_err(|err| format!("failed to commit block: {err}"))?;
    let view = state.view();
    let world = view.world();
    let manifest = world
        .pin_manifests()
        .get(&digest)
        .cloned()
        .ok_or("manifest missing after execution")?;
    let alias_id = ManifestAliasId::from(&alias_binding);
    let alias_record = world
        .manifest_aliases()
        .get(&alias_id)
        .cloned()
        .ok_or("alias missing after execution")?;
    let order_record = world
        .replication_orders()
        .get(&order_id)
        .cloned()
        .ok_or("replication order missing after execution")?;
    let snapshot = pin_fixture_snapshot_json(&manifest, &alias_record, &order_record)?;
    let pretty = to_string_pretty(&snapshot)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, format!("{pretty}\n"))?;
    println!("wrote {}", output.display());
    Ok(())
}
fn pin_fixture_make_state(providers: &[ProviderId]) -> State {
    let kura = Kura::blank_kura_for_testing();
    let live = LiveQueryStore::start_test();
    let alice = pin_fixture_alice();
    let domain_id = DomainId::try_new("default", "universal").expect("explicit fixture domain");
    let world = World::with(
        [Domain::new(domain_id).build(&alice)],
        [Account::new(alice.clone()).build(&alice)],
        std::iter::empty::<AssetDefinition>(),
    );
    let mut state = State::new_for_testing(world, kura, live);
    let mut governance = state.gov.clone();
    governance
        .sorafs_provider_owners
        .extend(providers.iter().map(|provider| (*provider, alice.clone())));
    state.set_gov(governance);
    state
}
fn pin_fixture_block_header(height: u64) -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(height).expect("non-zero height"),
        None,
        None,
        0,
        0,
    )
}
fn pin_fixture_completion_anchor_header() -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero height"),
        None,
        None,
        42,
        0,
    )
}
fn pin_fixture_completion_anchor() -> ProviderIngestFinalizedAnchorV1 {
    ProviderIngestFinalizedAnchorV1 {
        height: 1,
        block_hash: *iroha_crypto::HashOf::new(&pin_fixture_completion_anchor_header()).as_ref(),
    }
}
fn pin_fixture_commit_completion_anchor(state: &State) -> Result<(), Box<dyn Error>> {
    let mut block = state.block(pin_fixture_completion_anchor_header());
    block.block_hashes.push_for_tests(iroha_crypto::HashOf::new(
        &pin_fixture_completion_anchor_header(),
    ));
    block.commit()?;
    Ok(())
}
fn pin_fixture_completion_authority() -> ProviderIngestCompletionAuthorityV1 {
    ProviderIngestCompletionAuthorityV1::new(
        pin_fixture_alice(),
        pin_fixture_alice(),
        ProviderIngestCompletionSignerPolicyV1 {
            policy_id: [0xA1; 32],
            revision: 1,
            predecessor_digest: None,
            policy_digest: [0xA2; 32],
        },
    )
}
fn pin_fixture_bootstrap(
    tx: &mut iroha_core::state::StateTransaction<'_, '_>,
    providers: &[ProviderId],
) -> Result<(), Box<dyn Error>> {
    tx.tx_call_hash = Some(Hash::prehashed([0x91; Hash::LENGTH]));
    let alice = pin_fixture_alice();
    for name in [
        "CanBindSorafsAlias",
        "CanIssueSorafsReplicationOrder",
        "CanCompleteSorafsReplicationOrder",
    ] {
        tx.world
            .add_account_permission(&alice, Permission::new(name.to_owned(), IrohaJson::new(())));
    }
    pin_fixture_seed_public_pin_fee_assets(tx)?;
    for provider_id in providers {
        SetProviderIngestCompletionAuthority::new(
            *provider_id,
            None,
            pin_fixture_completion_authority(),
        )
        .execute(&alice, tx)?;
    }
    Ok(())
}
fn pin_fixture_seed_public_pin_fee_assets(
    tx: &mut iroha_core::state::StateTransaction<'_, '_>,
) -> Result<(), Box<dyn Error>> {
    let fee_asset_id = tx.gov.sorafs_pin_fee_asset_id.clone();
    let treasury = tx.gov.sorafs_pin_fee_treasury_account.clone();
    if tx.world().account(&treasury).is_err() {
        Register::account(NewAccount::new(treasury)).execute(&pin_fixture_alice(), tx)?;
    }
    if tx.world().asset_definitions().get(&fee_asset_id).is_none() {
        Register::asset_definition(AssetDefinition::numeric(
            fee_asset_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&pin_fixture_alice(), tx)?;
    }
    Mint::asset_quantity(
        10_000_000_000_000_u128,
        AssetId::new(fee_asset_id, pin_fixture_alice()),
    )
    .execute(&pin_fixture_alice(), tx)?;
    Ok(())
}
fn pin_fixture_register_and_approve(
    tx: &mut iroha_core::state::StateTransaction<'_, '_>,
    digest: ManifestDigest,
    manifest_payload: Vec<u8>,
    council_keys: &KeyPair,
) -> Result<(), Box<dyn Error>> {
    RegisterPinManifest::new(manifest_payload, None, None)
        .execute(&pin_fixture_alice(), tx)
        .map_err(|err| format!("failed to register manifest: {err}"))?;
    let stored = tx
        .world()
        .pin_manifests()
        .get(&digest)
        .cloned()
        .ok_or("manifest missing after registration")?;
    let envelope = pin_fixture_build_envelope(&stored, council_keys)?;
    ApprovePinManifest {
        digest,
        council_envelope: Some(envelope),
        council_envelope_digest: None,
    }
    .execute(&pin_fixture_alice(), tx)
    .map_err(|err| format!("failed to approve manifest: {err}"))?;
    Ok(())
}
fn pin_fixture_default_manifest()
-> Result<(ManifestDigest, ManifestRootCid, Vec<u8>), Box<dyn Error>> {
    let descriptor = sorafs_manifest::chunker_registry::default_descriptor();
    let manifest = ManifestBuilder::new()
        .root_cid(sorafs_manifest::canonical_manifest_root_cid([0xA5; 32]))
        .dag_codec(DagCodecId(MANIFEST_DAG_CODEC))
        .chunking_from_registry(descriptor.id)
        .chunk_digest_sha3_256(pin_fixture_default_chunk_digest())
        .por_root(pin_fixture_default_por_root())
        .content_length(pin_fixture_default_content_length())
        .car_digest([0xB6; 32])
        .car_size(1_048_832)
        .pin_policy(sorafs_manifest::PinPolicy {
            min_replicas: 3,
            storage_class: sorafs_manifest::StorageClass::Hot,
            retention_epoch: 42,
        })
        .build()?;
    let digest = ManifestDigest::from_manifest(&manifest)?;
    let root_cid = ManifestRootCid::try_from_slice(&manifest.root_cid)?;
    let payload = manifest.encode()?;
    Ok((digest, root_cid, payload))
}
fn pin_fixture_default_chunk_digest() -> [u8; 32] {
    [0xCD; 32]
}
fn pin_fixture_default_por_root() -> [u8; 32] {
    [0xCE; 32]
}
fn pin_fixture_default_content_length() -> u64 {
    1_048_576
}
fn pin_fixture_default_chunker() -> ChunkerProfileHandle {
    let descriptor = sorafs_manifest::chunker_registry::default_descriptor();
    ChunkerProfileHandle {
        profile_id: descriptor.id.0,
        namespace: descriptor.namespace.to_owned(),
        name: descriptor.name.to_owned(),
        semver: descriptor.semver.to_owned(),
        multihash_code: descriptor.multihash_code,
    }
}
#[cfg(test)]
fn pin_fixture_default_policy() -> iroha_data_model::sorafs::pin_registry::PinPolicy {
    iroha_data_model::sorafs::pin_registry::PinPolicy {
        min_replicas: 3,
        storage_class: iroha_data_model::sorafs::pin_registry::StorageClass::Hot,
        retention_epoch: 42,
    }
}
fn pin_fixture_replication_order(
    order_id: ReplicationOrderId,
    manifest: ManifestDigest,
    manifest_root_cid: &ManifestRootCid,
    providers: &[ProviderId],
    target_replicas: u16,
) -> ReplicationOrderV1 {
    let assignments = providers
        .iter()
        .map(|provider| ReplicationAssignmentV1 {
            provider_id: *provider.as_bytes(),
            slice_gib: 512,
            lane: None,
        })
        .collect();
    ReplicationOrderV1 {
        version: REPLICATION_ORDER_VERSION_V1,
        order_id: *order_id.as_bytes(),
        manifest_cid: manifest_root_cid.as_bytes().to_vec(),
        manifest_digest: *manifest.as_bytes(),
        chunking_profile: format!(
            "{}.{}@{}",
            pin_fixture_default_chunker().namespace,
            pin_fixture_default_chunker().name,
            pin_fixture_default_chunker().semver
        ),
        target_replicas,
        assignments,
        issued_at: 1_700_000_000,
        deadline_at: 1_700_086_400,
        sla: ReplicationOrderSlaV1 {
            ingest_deadline_secs: 86_400,
            min_availability_percent_milli: 99_500,
            min_por_success_percent_milli: 98_000,
        },
        metadata: Vec::new(),
    }
}
fn pin_fixture_alias_binding_for(
    manifest_root_cid: &ManifestRootCid,
    namespace: &str,
    name: &str,
    bound_at: u64,
    expiry_epoch: u64,
    council_keys: &KeyPair,
) -> Result<ManifestAliasBinding, Box<dyn Error>> {
    let binding_payload = AliasBindingV1 {
        alias: format!("{namespace}/{name}"),
        manifest_cid: manifest_root_cid.as_bytes().to_vec(),
        bound_at,
        expiry_epoch,
    };
    let merkle_path: Vec<[u8; 32]> = Vec::new();
    let registry_root =
        alias_merkle_root(&binding_payload, &merkle_path).map_err(|err| format!("{err}"))?;
    let generated_at_unix = 1_700_000_000;
    let expires_at_unix = generated_at_unix + 86_400;
    let mut bundle = AliasProofBundleV1 {
        binding: binding_payload,
        registry_root,
        registry_height: bound_at,
        generated_at_unix,
        expires_at_unix,
        merkle_path,
        council_signatures: Vec::new(),
    };
    let digest = alias_proof_signature_digest(&bundle);
    let signature = Signature::try_new(council_keys.private_key(), digest.as_ref())
        .map_err(|err| format!("failed to sign alias proof fixture: {err}"))?;
    let signer =
        checked_ed25519_public_key_array(council_keys.public_key(), "alias council public key")?;
    bundle.council_signatures.push(CouncilSignature {
        signer,
        signature: signature.payload().to_vec(),
    });
    let proof = to_bytes(&bundle)?;
    Ok(ManifestAliasBinding {
        name: name.to_owned(),
        namespace: namespace.to_owned(),
        proof,
    })
}
fn pin_fixture_council_keypair() -> KeyPair {
    let secret_bytes = [0x11; 32];
    let private =
        PrivateKey::from_bytes(Algorithm::Ed25519, &secret_bytes).expect("private key from bytes");
    KeyPair::from_private_key(private).expect("derive keypair")
}
fn pin_fixture_build_envelope(
    record: &PinManifestRecord,
    keypair: &KeyPair,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut sig_entry = json::Map::new();
    let signature = Signature::try_new(keypair.private_key(), record.digest.as_bytes())
        .map_err(|err| format!("failed to sign pin manifest fixture envelope: {err}"))?;
    let public_bytes_hex = hex::encode(checked_ed25519_public_key_bytes(
        keypair.public_key(),
        "pin fixture signer public key",
    )?);
    sig_entry.insert("algorithm".into(), Value::from("ed25519"));
    sig_entry.insert("signer".into(), Value::from(public_bytes_hex));
    sig_entry.insert(
        "signature".into(),
        Value::from(hex::encode(signature.payload())),
    );
    sig_entry.insert(
        "signer_multihash".into(),
        Value::from(keypair.public_key().to_string()),
    );
    let mut envelope = json::Map::new();
    envelope.insert(
        "chunk_digest_sha3_256".into(),
        Value::from(hex::encode(record.chunk_digest_sha3_256)),
    );
    envelope.insert(
        "manifest_blake3".into(),
        Value::from(hex::encode(record.digest.as_bytes())),
    );
    envelope.insert("profile".into(), Value::from(record.chunker.to_handle()));
    envelope.insert(
        "signatures".into(),
        Value::Array(vec![Value::Object(sig_entry)]),
    );
    let mut serialized = json::to_vec_pretty(&Value::Object(envelope))?;
    serialized.push(b'\n');
    Ok(serialized)
}
fn pin_fixture_snapshot_json(
    manifest: &PinManifestRecord,
    alias: &ManifestAliasRecord,
    order: &ReplicationOrderRecord,
) -> Result<Value, Box<dyn Error>> {
    let manifest_obj = pin_fixture_manifest_snapshot(manifest)?;
    let alias_obj = pin_fixture_alias_snapshot(alias)?;
    let order_obj = pin_fixture_order_snapshot(order)?;
    let mut root = json::Map::new();
    root.insert(
        "manifests".into(),
        Value::Array(vec![Value::Object(manifest_obj)]),
    );
    root.insert(
        "aliases".into(),
        Value::Array(vec![Value::Object(alias_obj)]),
    );
    root.insert(
        "replication_orders".into(),
        Value::Array(vec![Value::Object(order_obj)]),
    );
    Ok(Value::Object(root))
}
fn pin_fixture_manifest_snapshot(
    manifest: &PinManifestRecord,
) -> Result<json::Map, Box<dyn Error>> {
    let mut manifest_obj = json::Map::new();
    manifest_obj.insert(
        "digest_hex".into(),
        Value::String(hex::encode(manifest.digest.as_bytes())),
    );
    let (status_label, status_epoch) = match manifest.status {
        PinStatus::Pending => ("pending", None),
        PinStatus::Approved(epoch) => ("approved", Some(epoch)),
        PinStatus::Retired(epoch) => ("retired", Some(epoch)),
    };
    manifest_obj.insert("status".into(), Value::String(status_label.into()));
    manifest_obj.insert(
        "status_epoch".into(),
        status_epoch.map_or(Value::Null, Value::from),
    );
    manifest_obj.insert(
        "chunk_digest_sha3_256_hex".into(),
        Value::String(hex::encode(manifest.chunk_digest_sha3_256)),
    );
    manifest_obj.insert(
        "chunker_handle".into(),
        Value::String(manifest.chunker.to_handle()),
    );
    let mut policy_obj = json::Map::new();
    policy_obj.insert(
        "min_replicas".into(),
        Value::from(manifest.policy.min_replicas),
    );
    policy_obj.insert(
        "storage_class".into(),
        Value::String(
            match manifest.policy.storage_class {
                StorageClass::Hot => "hot",
                StorageClass::Warm => "warm",
                StorageClass::Cold => "cold",
            }
            .into(),
        ),
    );
    policy_obj.insert(
        "retention_epoch".into(),
        Value::from(manifest.policy.retention_epoch),
    );
    manifest_obj.insert("policy".into(), Value::Object(policy_obj));
    manifest_obj.insert(
        "submitted_by".into(),
        Value::String(manifest.submitted_by.to_string()),
    );
    manifest_obj.insert(
        "submitted_epoch".into(),
        Value::from(manifest.submitted_epoch),
    );
    manifest_obj.insert(
        "alias_label".into(),
        manifest.alias.as_ref().map_or(Value::Null, |binding| {
            Value::String(format!("{}/{}", binding.namespace, binding.name))
        }),
    );
    manifest_obj.insert(
        "council_envelope_digest_hex".into(),
        manifest
            .council_envelope_digest
            .map_or(Value::Null, |digest| Value::String(hex::encode(digest))),
    );
    Ok(manifest_obj)
}
fn pin_fixture_alias_snapshot(alias: &ManifestAliasRecord) -> Result<json::Map, Box<dyn Error>> {
    let mut alias_obj = json::Map::new();
    alias_obj.insert(
        "alias_label".into(),
        Value::String(alias.alias_id().as_label()),
    );
    alias_obj.insert(
        "namespace".into(),
        Value::String(alias.binding.namespace.clone()),
    );
    alias_obj.insert("name".into(), Value::String(alias.binding.name.clone()));
    alias_obj.insert(
        "manifest_digest_hex".into(),
        Value::String(hex::encode(alias.manifest.as_bytes())),
    );
    alias_obj.insert("bound_by".into(), Value::String(alias.bound_by.to_string()));
    alias_obj.insert("bound_epoch".into(), Value::from(alias.bound_epoch));
    alias_obj.insert("expiry_epoch".into(), Value::from(alias.expiry_epoch));
    alias_obj.insert(
        "proof_b64".into(),
        Value::String(BASE64_STD.encode(&alias.binding.proof)),
    );
    Ok(alias_obj)
}
fn pin_fixture_order_snapshot(order: &ReplicationOrderRecord) -> Result<json::Map, Box<dyn Error>> {
    let order_payload: ReplicationOrderV1 =
        norito::decode_from_bytes(&order.canonical_order).map_err(|err| format!("{err}"))?;
    let mut order_obj = json::Map::new();
    order_obj.insert(
        "order_id_hex".into(),
        Value::String(hex::encode(order.order_id.as_bytes())),
    );
    order_obj.insert(
        "manifest_digest_hex".into(),
        Value::String(hex::encode(order.manifest_digest.as_bytes())),
    );
    order_obj.insert(
        "issued_by".into(),
        Value::String(order.issued_by.to_string()),
    );
    order_obj.insert("issued_epoch".into(), Value::from(order.issued_epoch));
    order_obj.insert("deadline_epoch".into(), Value::from(order.deadline_epoch));
    order_obj.insert(
        "assignment_revision".into(),
        Value::from(order.assignment_revision),
    );
    let (status_label, status_epoch) = match order.status {
        ReplicationOrderStatus::Pending => ("pending", None),
        ReplicationOrderStatus::Completed(epoch) => ("completed", Some(epoch)),
        ReplicationOrderStatus::Expired(epoch) => ("expired", Some(epoch)),
        ReplicationOrderStatus::Cancelled(epoch) => ("cancelled", Some(epoch)),
    };
    order_obj.insert("status".into(), Value::String(status_label.into()));
    order_obj.insert(
        "status_epoch".into(),
        status_epoch.map_or(Value::Null, Value::from),
    );
    let provider_completions = order
        .provider_completions
        .iter()
        .map(|completion| {
            let mut map = json::Map::new();
            map.insert(
                "provider_id_hex".into(),
                Value::String(hex::encode(completion.provider_id.as_bytes())),
            );
            map.insert(
                "completed_by".into(),
                Value::String(completion.completed_by.to_string()),
            );
            map.insert(
                "completion_epoch".into(),
                Value::from(completion.completion_epoch),
            );
            map.insert(
                "assignment_revision".into(),
                Value::from(completion.assignment_revision),
            );
            map.insert(
                "expected_owner".into(),
                Value::String(completion.completion_authority.provider_owner.to_string()),
            );
            map.insert(
                "signer_policy_id_hex".into(),
                Value::String(hex::encode(
                    completion.completion_authority.signer_policy.policy_id,
                )),
            );
            map.insert(
                "signer_policy_revision".into(),
                Value::from(completion.completion_authority.signer_policy.revision),
            );
            map.insert(
                "signer_policy_predecessor_digest_hex".into(),
                completion
                    .completion_authority
                    .signer_policy
                    .predecessor_digest
                    .map_or(Value::Null, |digest| Value::String(hex::encode(digest))),
            );
            map.insert(
                "signer_policy_digest_hex".into(),
                Value::String(hex::encode(
                    completion.completion_authority.signer_policy.policy_digest,
                )),
            );
            map.insert(
                "finalized_height".into(),
                Value::from(completion.finalized_anchor.height),
            );
            map.insert(
                "finalized_block_hash_hex".into(),
                Value::String(hex::encode(completion.finalized_anchor.block_hash)),
            );
            Value::Object(map)
        })
        .collect();
    order_obj.insert(
        "provider_completions".into(),
        Value::Array(provider_completions),
    );
    order_obj.insert(
        "target_replicas".into(),
        Value::from(order_payload.target_replicas as u64),
    );
    order_obj.insert(
        "canonical_order_b64".into(),
        Value::String(BASE64_STD.encode(&order.canonical_order)),
    );
    order_obj.insert(
        "sla_ingest_deadline_secs".into(),
        Value::from(order_payload.sla.ingest_deadline_secs),
    );
    order_obj.insert(
        "sla_min_availability_percent_milli".into(),
        Value::from(order_payload.sla.min_availability_percent_milli as u64),
    );
    order_obj.insert(
        "sla_min_por_success_percent_milli".into(),
        Value::from(order_payload.sla.min_por_success_percent_milli as u64),
    );
    let assignments = order_payload
        .assignments
        .iter()
        .map(|assignment| {
            let mut map = json::Map::new();
            map.insert(
                "provider_id_hex".into(),
                Value::String(hex::encode(assignment.provider_id)),
            );
            map.insert("slice_gib".into(), Value::from(assignment.slice_gib));
            Value::Object(map)
        })
        .collect();
    order_obj.insert("assignments".into(), Value::Array(assignments));
    Ok(order_obj)
}
fn pin_fixture_alice() -> AccountId {
    let public_key: PublicKey =
        "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
            .parse()
            .expect("valid public key");
    AccountId::new(public_key)
}

#[cfg(test)]
mod gateway_rollout_tests;
#[cfg(test)]
mod reserve_matrix_tests;
#[cfg(test)]
mod tests;
