//! `SoraFS` helper commands for interacting with Torii REST endpoints.
use super::{
    da::{normalize_ticket_hex, persist_manifest_bundle},
    da_common::DaManifestFetcher,
};
mod hedging_billing_response;
/// Local artifact compilation and archive packaging.
pub mod toolkit;
use crate::{CliOutputFormat, Run, RunContext, cli_output::print_with_optional_text};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use eyre::{Result, WrapErr, eyre};
use hex::{decode, decode_to_slice, encode};
use iroha::{
    client::{
        AccountTransactionDraft, Client, SORAFS_MODERATION_TRANSACTION_TTL, SorafsAliasListFilter,
        SorafsAppealFinanceReadbackFilter, SorafsBillingAcknowledgementProof,
        SorafsBillingStatementListFilter, SorafsHedgingProjectionFilter,
        SorafsModerationBallotEventsFilter, SorafsModerationBallotsFilter,
        SorafsModerationModelRegistryFilter, SorafsModerationQuarantineFilter,
        SorafsModerationQuarantineObjectStoreRequest, SorafsModerationQuarantineReleaseRequest,
        SorafsModerationQuarantineReviewRequest, SorafsModerationScreeningResultRequest,
        SorafsModerationScreeningResultsFilter, SorafsPinAlias, SorafsPinFinalizedAnchor,
        SorafsPinListFilter, SorafsPinRegisterArgs, SorafsRepairFinalizedAnchor,
        SorafsRepairTasksFilter, SorafsReplicationListFilter, SorafsReplicationStatus,
        SorafsTokenOverrides, SorafsTransparencyReadbackFilter,
    },
    http::{Response, StatusCode},
};
use iroha_config::parameters::defaults;
use iroha_crypto::{
    HashOf, HybridSuite,
    soranet::{
        blinding::canonical_cache_key,
        directory::{
            GuardDirectorySnapshotV2, compute_snapshot_digest, read_guard_directory_snapshot_file,
        },
        token::{AdmissionToken, MintError as AdmissionTokenMintError, compute_issuer_fingerprint},
    },
};
use iroha_data_model::sorafs::pin_registry::PinStatusKindV1;
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    isi::{
        InstructionBox, Transfer,
        sorafs::{
            ApplySorafsRepairTaskAction, FinalizeSorafsModerationCase, SorafsRepairClaimV1,
            SorafsRepairCompleteV1, SorafsRepairEscalateV1, SorafsRepairFailV1,
            SorafsRepairRenewV1, SorafsRepairTaskActionV1, SubmitSorafsModerationCommit,
            SubmitSorafsModerationReveal,
        },
    },
    sorafs::{
        gar::{GarEnforcementActionV1, GarEnforcementReceiptV1},
        moderation::{
            AdversarialCorpusManifestV1, ModerationReproManifestV1, SoraFsModerationBallotCommitV1,
            SoraFsModerationBallotRevealV1,
        },
        pin_registry::StorageClass,
        reserve::{
            ReserveDuration, ReserveLedgerProjection, ReserveLifecycleProjection,
            ReserveLifecycleStage, ReservePolicyV1, ReserveQuote, ReserveTier,
        },
    },
    soranet::{
        RelayId,
        incentives::{
            RelayBondLedgerEntryV1, RelayBondPolicyV1, RelayComplianceStatusV1,
            RelayEpochMetricsV1, RelayRewardInstructionV1,
        },
    },
    transaction::{FeePaymentIntent, SignedTransaction},
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::numeric::{Numeric, Quantity};
use iroha_service_model::soranet::{AnonymityPolicy, TransportPolicy, WriteModeHint};
use iroha_storage_client::client::{
    SorafsGatewayFetchOptions, SorafsGatewayScoreboardOptions, StorageClient,
};
use iroha_torii_shared::configuration::SoranetHandshakeSummary;
use iroha_torii_shared::sorafs_hedging_billing_api::BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1 as SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1;
use norito::json::{Map, Number, Value};
use norito::{NoritoSerialize, decode_from_bytes};
use rand::{
    CryptoRng, RngCore, SeedableRng,
    rand_core::{TryCryptoRng, TryRngCore},
    rngs::{OsRng, StdRng},
};
use reqwest::blocking::Client as BlockingHttpClient;
use sorafs_car::{
    CarBuildPlan, CarChunk, FilePlan,
    fetch_plan::{chunk_fetch_plan_from_json, parse_digest_hex},
};
use sorafs_chunker::ChunkProfile;
use sorafs_manifest::chunker_registry;
use sorafs_manifest::deal::XorQuantity;
use sorafs_manifest::repair::{
    REPAIR_SLASH_PROPOSAL_VERSION_V1, RepairSlashProposalV1, RepairTicketId,
};
use sorafs_manifest::{
    ManifestV1, StorageClass as ManifestStorageClass,
    hosts::{DirectCarLocator, HostMappingInput, HostMappingSummary},
    hybrid_envelope::{HYBRID_PAYLOAD_ENVELOPE_VERSION_V1, HybridPayloadEnvelopeV1},
    manifest_capabilities::{
        ChunkProfileSummary, ManifestCapabilitySummary, detect_manifest_capabilities,
    },
    provider_admission::ProviderAdmissionEnvelopeV1,
    provider_advert::{CapabilityType, ProviderCapabilityRangeV1},
};
use sorafs_orchestrator::{
    PolicyOverride,
    incentives::{RelayRewardEngine, RewardConfig},
    prelude::{
        BrowserExtensionManifest, GUARD_CACHE_MAX_BYTES_V1, GatewayFetchConfig,
        GatewayProviderInput, GuardCacheKey, GuardRetention, GuardSelector, GuardSet,
        PayoutServiceError, RelayDirectory, RewardLedgerError,
    },
    treasury::{
        AdjustmentKind, AdjustmentRequest, DisputeId, DisputeResolution, DisputeStatus,
        EarningsDashboard, EarningsRow, LedgerAmountArithmeticError, LedgerAmountSource,
        LedgerReconciliationReport, LedgerTransferMismatch, LedgerTransferRecord, MismatchReason,
        PayoutInput, QuantityToNanosError, RelayPayoutService, ResolutionKind, RewardDispute,
        RewardLedgerSnapshot, TransferKind,
    },
};
use soranet_incentives::{RelayEarningsAccumulator, RelayPayoutLedger};
use soranet_pq::MlDsaSuite;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::TryFrom,
    fmt::{self, Write as _},
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use time::{Duration as TimeDelta, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::runtime::Runtime;
use zeroize::{Zeroize as _, Zeroizing};

macro_rules! impl_run_with_client_methods {
    ($args:ty, $($method:path),+ $(,)?) => {
        impl Run for $args {
            fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
                self.run_with(context, $($method),+)
            }
        }
    };
}

macro_rules! impl_run_for_subcommand {
    ($(#[$attribute:meta])* $command:ident => $($variant:ident),+ $(,)?) => {
        impl Run for $command {
            $(#[$attribute])*
            fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
                match self {
                    $(Self::$variant(args) => args.run(context)),+
                }
            }
        }
    };
}

macro_rules! impl_json_limit_run_with {
    ($args:ident => $filter:ident) => {
        impl $args {
            fn run_with<C, F>(&self, context: &mut C, request: F) -> Result<()>
            where
                C: RunContext,
                F: FnOnce(&Client, $filter) -> Result<Response<Vec<u8>>>,
            {
                let filter = $filter { limit: self.limit };
                let client = context.client_from_config()?;
                let response = request(&client, filter)?;
                render_json_response(context, response)
            }
        }
    };
}

macro_rules! impl_appeal_finance_submit_run_with {
    ($args:ident => $label:literal, $status:expr) => {
        impl $args {
            fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
            where
                C: RunContext,
                F: FnOnce(&Client, &[u8]) -> Result<Response<Vec<u8>>>,
            {
                run_appeal_finance_json_submit(context, &self.input, $label, submit, $status)
            }
        }
    };
}

macro_rules! impl_json_payload_run_with {
    ($args:ident.$field:ident => $label:literal, $render:path) => {
        impl $args {
            fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
            where
                C: RunContext,
                F: FnOnce(&Client, &[u8]) -> Result<Response<Vec<u8>>>,
            {
                let payload = load_sorafs_json_payload(&self.$field, $label)?;
                let client = context.client_from_config()?;
                let response = submit(&client, &payload)?;
                $render(context, response)
            }
        }
    };
}

macro_rules! impl_moderation_operator_derived_response {
    ($name:ident => $builder:path, $output:ident, $error:literal) => {
        fn $name(
            &self,
            quarantine_id_hex: &str,
            limit: Option<u32>,
        ) -> ModerationOperatorHttpResponse {
            let body = match self.operator_panel_body(quarantine_id_hex, limit) {
                Ok(body) => body,
                Err(response) => return response,
            };
            match moderation_operator_payload_free_panel_json(&body)
                .and_then(|panel| $builder(quarantine_id_hex, &panel))
            {
                Ok($output) => moderation_operator_json_response(StatusCode::OK, &$output),
                Err(err) => moderation_operator_json_error(
                    StatusCode::BAD_GATEWAY,
                    format!($error, err = err),
                ),
            }
        }
    };
}

#[cfg(test)]
macro_rules! assert_eq_compact {
    ($left:expr => $right:expr $(; $($arg:tt)*)?) => {
        assert_eq!($left, $right $(, $($arg)*)?)
    };
}
#[cfg(test)]
macro_rules! assert_compact {
    ($condition:expr $(; $($arg:tt)*)?) => {
        assert!($condition $(, $($arg)*)?)
    };
}

#[cfg(test)]
macro_rules! json_response_fixture {
    ($status:expr, $body:expr $(,)?) => {
        Ok(Response::builder()
            .status($status)
            .header("Content-Type", "application/json")
            .body(norito::json::to_vec($body)?)
            .unwrap())
    };
    ($status:expr, $body:expr, $message:expr) => {
        Ok(Response::builder()
            .status($status)
            .header("Content-Type", "application/json")
            .body(norito::json::to_vec($body)?)
            .expect($message))
    };
}

#[cfg(test)]
macro_rules! test_items {
    ($($item:item)*) => {
        $(#[test] $item)*
    };
}

#[cfg(test)]
const ML_KEM_768_PUBLIC_LEN: usize = 1184;
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default)]
enum MlDsaSuiteArg {
    #[default]
    #[value(name = "mldsa44")]
    MlDsa44,
    #[value(name = "mldsa65")]
    MlDsa65,
    #[value(name = "mldsa87")]
    MlDsa87,
}
impl MlDsaSuiteArg {
    fn as_suite(self) -> MlDsaSuite {
        match self {
            Self::MlDsa44 => MlDsaSuite::MlDsa44,
            Self::MlDsa65 => MlDsaSuite::MlDsa65,
            Self::MlDsa87 => MlDsaSuite::MlDsa87,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }
}
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum StorageClassArg {
    #[value(name = "hot")]
    Hot,
    #[value(name = "warm")]
    Warm,
    #[value(name = "cold")]
    Cold,
}
impl StorageClassArg {
    fn to_storage_class(self) -> StorageClass {
        match self {
            Self::Hot => StorageClass::Hot,
            Self::Warm => StorageClass::Warm,
            Self::Cold => StorageClass::Cold,
        }
    }
}
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ReserveTierArg {
    #[value(name = "tier-a")]
    TierA,
    #[value(name = "tier-b")]
    TierB,
    #[value(name = "tier-c")]
    TierC,
}
impl ReserveTierArg {
    fn to_policy_tier(self) -> ReserveTier {
        match self {
            Self::TierA => ReserveTier::TierA,
            Self::TierB => ReserveTier::TierB,
            Self::TierC => ReserveTier::TierC,
        }
    }
}
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ReserveDurationArg {
    #[value(name = "monthly")]
    Monthly,
    #[value(name = "quarterly")]
    Quarterly,
    #[value(name = "annual")]
    Annual,
}
impl ReserveDurationArg {
    fn to_policy_duration(self) -> ReserveDuration {
        match self {
            Self::Monthly => ReserveDuration::Monthly,
            Self::Quarterly => ReserveDuration::Quarterly,
            Self::Annual => ReserveDuration::Annual,
        }
    }
}
#[cfg(test)]
mod capture_path_tests {
    use super::{default_orchestrator_capture_dir, scoreboard_capture_paths};
    use std::path::PathBuf;
    #[test]
    fn defaults_use_artifacts_directory() {
        let capture = scoreboard_capture_paths(None, None);
        let expected_dir = default_orchestrator_capture_dir();
        assert_eq!(capture.scoreboard, expected_dir.join("scoreboard.json"));
        assert_eq_compact! { capture.summary.as_ref() => Some(&expected_dir.join("summary.json")) };
    }
    #[test]
    fn scoreboard_override_preserves_parent_for_summary() {
        let base = PathBuf::from("/tmp/custom");
        let capture = scoreboard_capture_paths(Some(base.join("sb.json")), None);
        assert_eq!(capture.scoreboard, base.join("sb.json"));
        assert_eq!(capture.summary.as_ref(), Some(&base.join("summary.json")));
    }
    #[test]
    fn summary_override_wins() {
        let summary = PathBuf::from("/tmp/out.json");
        let capture = scoreboard_capture_paths(None, Some(summary.clone()));
        assert_eq!(capture.summary.as_ref(), Some(&summary));
    }
}
#[cfg(test)]
mod provider_count_tests {
    use super::{ProviderCounts, insert_provider_counts};
    use norito::json::Value;
    #[test]
    fn provider_counts_include_gateway_only_runs() {
        let mut summary = norito::json::Map::new();
        insert_provider_counts(&mut summary, ProviderCounts::new(0, 3));
        assert_eq_compact! { summary.get("provider_count").and_then(Value::as_u64) => Some(0) };
        assert_eq_compact! { summary.get("gateway_provider_count").and_then(Value::as_u64) => Some(3) };
        assert_eq_compact! { summary.get("provider_mix").and_then(Value::as_str) => Some("gateway-only") };
    }
    #[test]
    fn provider_counts_report_mixed_classifications() {
        let mut summary = norito::json::Map::new();
        insert_provider_counts(&mut summary, ProviderCounts::new(2, 2));
        assert_eq_compact! { summary.get("provider_mix").and_then(Value::as_str) => Some("mixed") };
    }
}
#[cfg(test)]
mod transport_policy_summary_tests {
    use super::{TransportPolicy, insert_transport_policy};
    use norito::json::Value;
    #[test]
    fn summary_records_transport_policy_overrides() {
        let mut summary = norito::json::Map::new();
        insert_transport_policy(
            &mut summary,
            Some(TransportPolicy::SoranetPreferred),
            Some(TransportPolicy::DirectOnly),
        );
        assert_eq_compact! { summary.get("transport_policy").and_then(Value::as_str) => Some("direct-only") };
        assert_eq_compact! { summary.get("transport_policy_override").and_then(Value::as_bool) => Some(true) };
        assert_eq_compact! { summary.get("transport_policy_override_label").and_then(Value::as_str) => Some("direct-only") };
    }
    #[test]
    fn summary_defaults_transport_policy_without_override() {
        let mut summary = norito::json::Map::new();
        insert_transport_policy(&mut summary, None, None);
        assert_eq_compact! { summary.get("transport_policy").and_then(Value::as_str) => Some("soranet-first") };
        assert_eq_compact! { summary.get("transport_policy_override").and_then(Value::as_bool) => Some(false) };
        assert_compact! { summary.get("transport_policy_override_label").is_none_or(Value::is_null) };
    }
}
#[cfg(test)]
mod telemetry_summary_tests {
    use super::{insert_summary_telemetry_region, insert_summary_telemetry_source};
    use norito::json::Value;
    #[test]
    fn summary_records_telemetry_label() {
        let mut summary = norito::json::Map::new();
        insert_summary_telemetry_source(&mut summary, Some("otel::prod"));
        assert_eq_compact! { summary.get("telemetry_source").and_then(Value::as_str) => Some("otel::prod") };
    }
    #[test]
    fn summary_omits_telemetry_label_when_missing() {
        let mut summary = norito::json::Map::new();
        insert_summary_telemetry_source(&mut summary, None);
        assert!(!summary.contains_key("telemetry_source"));
    }
    #[test]
    fn summary_records_telemetry_region() {
        let mut summary = norito::json::Map::new();
        insert_summary_telemetry_region(&mut summary, Some("iad-prod"));
        assert_eq_compact! { summary.get("telemetry_region").and_then(Value::as_str) => Some("iad-prod") };
    }
    #[test]
    fn summary_omits_telemetry_region_when_missing() {
        let mut summary = norito::json::Map::new();
        insert_summary_telemetry_region(&mut summary, None);
        assert!(!summary.contains_key("telemetry_region"));
    }
}
impl fmt::Display for MlDsaSuiteArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default)]
enum TokenOutputFormat {
    #[default]
    #[value(name = "base64")]
    Base64,
    #[value(name = "hex")]
    Hex,
    #[value(name = "binary")]
    Binary,
}
impl TokenOutputFormat {
    fn describe(self) -> &'static str {
        match self {
            Self::Base64 => "base64url",
            Self::Hex => "hex",
            Self::Binary => "binary",
        }
    }
}
#[derive(clap::Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Interact with the pin registry.
    #[command(subcommand)]
    Pin(PinCommand),
    /// List alias bindings.
    #[command(subcommand)]
    Alias(AliasCommand),
    /// List replication orders.
    #[command(subcommand)]
    Replication(ReplicationCommand),
    /// Storage token helpers.
    #[command(subcommand)]
    Storage(StorageCommand),
    /// Gateway policy and configuration helpers.
    #[command(subcommand)]
    Gateway(GatewayCommand),
    /// Offline helpers for relay payouts, disputes, and dashboards.
    #[command(subcommand)]
    Incentives(IncentivesCommand),
    /// Observe the Torii `SoraNet` handshake configuration or manage admission tokens.
    #[command(subcommand)]
    Handshake(HandshakeCommand),
    /// Local tooling for packaging manifests and payloads.
    #[command(subcommand)]
    Toolkit(toolkit::Command),
    /// Guard directory helpers (fetch/verify snapshots).
    #[command(subcommand)]
    GuardDirectory(GuardDirectoryCommand),
    /// Reserve + rent policy helpers.
    #[command(subcommand)]
    Reserve(ReserveCommand),
    /// Appeal pricing and finance handoff helpers.
    #[command(subcommand)]
    Appeals(AppealsCommand),
    /// GAR policy evidence helpers.
    #[command(subcommand)]
    Gar(GarCommand),
    /// Transparency ledger readback and source-entry ingest helpers.
    #[command(subcommand)]
    Transparency(TransparencyCommand),
    /// Moderation queue and quarantine workflow helpers.
    #[command(subcommand)]
    Moderation(ModerationCommand),
    /// Repair queue helpers (list, claim, close, escalate).
    #[command(subcommand)]
    Repair(RepairCommand),
    /// Authenticated billing statement and reconciliation reads.
    #[command(subcommand)]
    Billing(BillingCommand),
    /// Authenticated finalized hedging projection reads.
    #[command(subcommand)]
    Hedging(HedgingCommand),
    /// GC inspection helpers (no manual deletions).
    #[command(subcommand)]
    Gc(GcCommand),
    /// Orchestrate multi-provider chunk fetches via gateways.
    Fetch(FetchArgs),
}
#[derive(clap::Subcommand, Debug)]
pub enum ReserveCommand {
    /// Quote reserve requirements and effective rent for a given tier/capacity.
    Quote(ReserveQuoteArgs),
    /// Convert a reserve quote into rent/reserve transfer instructions.
    Ledger(ReserveLedgerArgs),
    /// Project reserve lifecycle stage and automatic credit draw state.
    Lifecycle(ReserveLifecycleArgs),
}
impl_run_for_subcommand!(ReserveCommand => Quote, Ledger, Lifecycle);
const SORAFS_HEDGING_BILLING_MAX_PAGE_ITEMS_V1: u16 = 100;
fn required_nonzero_lower_hex32(value: &str, flag: &str) -> Result<String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(eyre!(
            "{flag} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    if value.bytes().all(|byte| byte == b'0') {
        return Err(eyre!("{flag} must be non-zero"));
    }
    Ok(value.to_owned())
}
fn required_hedging_billing_page_limit(limit: u16) -> Result<u16> {
    if !(1..=SORAFS_HEDGING_BILLING_MAX_PAGE_ITEMS_V1).contains(&limit) {
        return Err(eyre!(
            "--limit must be within 1..={SORAFS_HEDGING_BILLING_MAX_PAGE_ITEMS_V1}"
        ));
    }
    Ok(limit)
}
/// Authenticated SoraFS billing statement and reconciliation commands.
#[derive(clap::Subcommand, Debug)]
pub enum BillingCommand {
    /// Fetch the supervised billing projector status and current anchor.
    Status(BillingStatusArgs),
    /// List owner-isolated published statements from an exact checkpoint.
    Statements(BillingStatementsArgs),
    /// Fetch one exact published statement as canonical Norito.
    Statement(BillingStatementArgs),
    /// Submit an externally authenticated owner acknowledgement.
    Acknowledge(BillingAcknowledgeArgs),
    /// Fetch payload-free delivery reconciliation status.
    Reconciliation(BillingReconciliationArgs),
}
impl_run_for_subcommand!(BillingCommand => Status, Statements, Statement, Acknowledge, Reconciliation);
/// Fetch supervised billing projector status.
#[derive(clap::Args, Debug, Default)]
pub struct BillingStatusArgs {}
impl_run_with_client_methods!(BillingStatusArgs, Client::get_sorafs_billing_status);
impl BillingStatusArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client) -> Result<Response<Vec<u8>>>,
    {
        let client = context.client_from_config()?;
        render_json_response(context, get(&client)?)
    }
}
/// List owner-isolated published billing statements.
#[derive(clap::Args, Debug)]
pub struct BillingStatementsArgs {
    /// Exact non-zero lowercase checkpoint fingerprint from billing status.
    #[arg(long = "expected-checkpoint-fingerprint", value_name = "HEX")]
    expected_checkpoint_fingerprint: String,
    /// Optional exclusive non-zero lowercase statement identifier.
    #[arg(long = "after-statement-id", value_name = "HEX")]
    after_statement_id: Option<String>,
    /// Required page size in the inclusive range 1 through 100.
    #[arg(long, value_name = "COUNT")]
    limit: u16,
}
impl_run_with_client_methods!(BillingStatementsArgs, Client::get_sorafs_billing_statements);
impl BillingStatementsArgs {
    fn run_with<C, F>(&self, context: &mut C, list: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, SorafsBillingStatementListFilter<'_>) -> Result<Response<Vec<u8>>>,
    {
        let checkpoint = required_nonzero_lower_hex32(
            &self.expected_checkpoint_fingerprint,
            "--expected-checkpoint-fingerprint",
        )?;
        let after_statement_id = self
            .after_statement_id
            .as_deref()
            .map(|value| required_nonzero_lower_hex32(value, "--after-statement-id"))
            .transpose()?;
        let limit = required_hedging_billing_page_limit(self.limit)?;
        let filter = SorafsBillingStatementListFilter {
            expected_checkpoint_fingerprint_hex: &checkpoint,
            after_statement_id_hex: after_statement_id.as_deref(),
            limit,
        };
        let client = context.client_from_config()?;
        hedging_billing_response::render(context, list(&client, filter)?, &checkpoint)
    }
}
/// Fetch one published billing statement.
#[derive(clap::Args, Debug)]
pub struct BillingStatementArgs {
    /// Exact non-zero lowercase statement identifier.
    #[arg(long = "statement-id", value_name = "HEX")]
    statement_id: String,
    /// Exact non-zero lowercase checkpoint fingerprint from billing status.
    #[arg(long = "expected-checkpoint-fingerprint", value_name = "HEX")]
    expected_checkpoint_fingerprint: String,
    /// Destination for the canonical Norito statement bytes.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}
impl_run_with_client_methods!(BillingStatementArgs, Client::get_sorafs_billing_statement);
impl BillingStatementArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str, &str) -> Result<Response<Vec<u8>>>,
    {
        let statement_id = required_nonzero_lower_hex32(&self.statement_id, "--statement-id")?;
        let checkpoint = required_nonzero_lower_hex32(
            &self.expected_checkpoint_fingerprint,
            "--expected-checkpoint-fingerprint",
        )?;
        let client = context.client_from_config()?;
        let response = get(&client, &statement_id, &checkpoint)?;
        write_billing_statement_response(
            context,
            response,
            &self.output,
            &statement_id,
            &checkpoint,
        )
    }
}
fn write_billing_statement_response<C: RunContext>(
    context: &mut C,
    response: Response<Vec<u8>>,
    output: &Path,
    statement_id: &str,
    checkpoint: &str,
) -> Result<()> {
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(str::to_owned);
    let body = response.into_body();
    if status != StatusCode::OK {
        return Err(make_http_error(status, &body));
    }
    if content_type.as_deref() != Some("application/x-norito") {
        return Err(eyre!(
            "billing statement response for `{statement_id}` must use application/x-norito"
        ));
    }
    if body.is_empty() {
        return Err(eyre!(
            "billing statement response for `{statement_id}` was empty"
        ));
    }
    let mut output_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .wrap_err_with(|| {
            format!(
                "failed to create canonical billing statement `{}` without replacing an existing path",
                output.display()
            )
        })?;
    let output_metadata = output_file.metadata().wrap_err_with(|| {
        format!(
            "failed to inspect newly created canonical billing statement `{}`",
            output.display()
        )
    })?;
    if !output_metadata.is_file() {
        return Err(eyre!(
            "canonical billing statement output `{}` must be a regular file",
            output.display()
        ));
    }
    output_file.write_all(&body).wrap_err_with(|| {
        format!(
            "failed to write canonical billing statement `{}`",
            output.display()
        )
    })?;
    output_file.flush().wrap_err_with(|| {
        format!(
            "failed to flush canonical billing statement `{}`",
            output.display()
        )
    })?;
    context.print_data(&norito::json!({
        "statement_id": statement_id,
        "expected_checkpoint_fingerprint": checkpoint,
        "output": (output.display().to_string()),
        "bytes_written": (u64::try_from(body.len()).unwrap_or(u64::MAX)),
        "content_type": "application/x-norito"
    }))
}
/// Submit one owner acknowledgement for a published billing statement.
#[derive(clap::Args, Debug)]
pub struct BillingAcknowledgeArgs {
    /// Exact non-zero lowercase statement identifier.
    #[arg(long = "statement-id", value_name = "HEX")]
    statement_id: String,
    /// Exact non-zero lowercase checkpoint fingerprint from billing status.
    #[arg(long = "expected-checkpoint-fingerprint", value_name = "HEX")]
    expected_checkpoint_fingerprint: String,
    /// Non-zero lowercase 32-byte idempotency nonce authenticated by the external proof.
    #[arg(long = "request-nonce", value_name = "HEX")]
    request_nonce: String,
    /// Binary external-authority authentication proof, bounded to 64 KiB.
    #[arg(long = "authentication-proof", value_name = "PATH")]
    authentication_proof: PathBuf,
}
impl_run_with_client_methods!(
    BillingAcknowledgeArgs,
    Client::post_sorafs_billing_statement_acknowledgement,
);
impl BillingAcknowledgeArgs {
    fn run_with<C, F>(&self, context: &mut C, acknowledge: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(
            &Client,
            &str,
            &str,
            &SorafsBillingAcknowledgementProof,
        ) -> Result<Response<Vec<u8>>>,
    {
        let statement_id = required_nonzero_lower_hex32(&self.statement_id, "--statement-id")?;
        let checkpoint = required_nonzero_lower_hex32(
            &self.expected_checkpoint_fingerprint,
            "--expected-checkpoint-fingerprint",
        )?;
        let authentication_proof = read_billing_acknowledgement_proof(&self.authentication_proof)?;
        let proof = SorafsBillingAcknowledgementProof::try_from_hex(
            &self.request_nonce,
            authentication_proof,
        )?;
        let client = context.client_from_config()?;
        render_json_response(
            context,
            acknowledge(&client, &statement_id, &checkpoint, &proof)?,
        )
    }
}
#[cfg(unix)]
type BillingProofFileIdentity = (u64, u64);
#[cfg(windows)]
type BillingProofFileIdentity = (Option<u32>, Option<u64>);
#[cfg(not(any(unix, windows)))]
type BillingProofFileIdentity = ();
#[cfg(unix)]
fn billing_proof_file_identity(metadata: &fs::Metadata) -> BillingProofFileIdentity {
    use std::os::unix::fs::MetadataExt as _;
    (metadata.dev(), metadata.ino())
}
#[cfg(windows)]
fn billing_proof_file_identity(metadata: &fs::Metadata) -> BillingProofFileIdentity {
    use std::os::windows::fs::MetadataExt as _;
    (metadata.volume_serial_number(), metadata.file_index())
}
#[cfg(not(any(unix, windows)))]
fn billing_proof_file_identity(_metadata: &fs::Metadata) -> BillingProofFileIdentity {}
#[cfg(unix)]
const fn billing_proof_file_identity_available(_identity: BillingProofFileIdentity) -> bool {
    true
}
#[cfg(windows)]
const fn billing_proof_file_identity_available(identity: BillingProofFileIdentity) -> bool {
    identity.0.is_some() && identity.1.is_some()
}
#[cfg(not(any(unix, windows)))]
const fn billing_proof_file_identity_available(_identity: BillingProofFileIdentity) -> bool {
    false
}
fn billing_proof_file_is_single_link(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        metadata.nlink() == 1
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        metadata.number_of_links() == Some(1)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        false
    }
}
#[cfg(windows)]
fn billing_proof_file_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}
#[cfg(not(windows))]
fn billing_proof_file_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}
fn billing_proof_file_is_indirect(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink() || billing_proof_file_is_reparse_point(metadata)
}
#[cfg(unix)]
fn billing_proof_metadata_unchanged(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    billing_proof_file_identity(left) == billing_proof_file_identity(right)
        && left.nlink() == 1
        && right.nlink() == 1
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(windows)]
fn billing_proof_metadata_unchanged(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    billing_proof_file_identity_available(billing_proof_file_identity(left))
        && billing_proof_file_identity(left) == billing_proof_file_identity(right)
        && left.number_of_links() == Some(1)
        && right.number_of_links() == Some(1)
        && left.file_size() == right.file_size()
        && left.last_write_time() == right.last_write_time()
        && left.creation_time() == right.creation_time()
}
#[cfg(not(any(unix, windows)))]
fn billing_proof_metadata_unchanged(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}
#[cfg(unix)]
fn open_direct_billing_acknowledgement_proof(path: &Path) -> Result<fs::File> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .wrap_err_with(|| {
        format!(
            "failed to securely open billing acknowledgement proof `{}`",
            path.display()
        )
    })?;
    Ok(fs::File::from(descriptor))
}
#[cfg(windows)]
fn open_direct_billing_acknowledgement_proof(path: &Path) -> Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path).wrap_err_with(|| {
        format!(
            "failed to securely open billing acknowledgement proof `{}`",
            path.display()
        )
    })
}
#[cfg(not(any(unix, windows)))]
fn open_direct_billing_acknowledgement_proof(path: &Path) -> Result<fs::File> {
    Err(eyre!(
        "billing acknowledgement proof `{}` cannot be opened because this platform does not expose a stable direct-file identity",
        path.display()
    ))
}
fn read_billing_acknowledgement_proof(path: &Path) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path).wrap_err_with(|| {
        format!(
            "failed to inspect billing acknowledgement proof `{}`",
            path.display()
        )
    })?;
    if billing_proof_file_is_indirect(&path_metadata)
        || !path_metadata.file_type().is_file()
        || !billing_proof_file_identity_available(billing_proof_file_identity(&path_metadata))
        || !billing_proof_file_is_single_link(&path_metadata)
    {
        return Err(eyre!(
            "billing acknowledgement proof `{}` must be a regular non-symlink file with a stable single-link identity",
            path.display()
        ));
    }
    if path_metadata.len() == 0
        || path_metadata.len() > SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1 as u64
    {
        return Err(eyre!(
            "billing acknowledgement proof `{}` must contain between 1 and {SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1} bytes",
            path.display()
        ));
    }
    let expected_len = usize::try_from(path_metadata.len()).map_err(|_| {
        eyre!(
            "billing acknowledgement proof `{}` length is not representable on this host",
            path.display()
        )
    })?;
    let mut file = open_direct_billing_acknowledgement_proof(path)?;
    let opened_metadata = file.metadata().wrap_err_with(|| {
        format!(
            "failed to inspect opened billing acknowledgement proof `{}`",
            path.display()
        )
    })?;
    if billing_proof_file_is_indirect(&opened_metadata)
        || !opened_metadata.is_file()
        || !billing_proof_metadata_unchanged(&path_metadata, &opened_metadata)
    {
        return Err(eyre!(
            "billing acknowledgement proof `{}` changed between inspection and open",
            path.display()
        ));
    }
    let bytes = read_billing_acknowledgement_proof_exact(path, &mut file, expected_len)?;
    let after_file_metadata = file.metadata().wrap_err_with(|| {
        format!(
            "failed to re-inspect opened billing acknowledgement proof `{}`",
            path.display()
        )
    })?;
    let after_path_metadata = fs::symlink_metadata(path).wrap_err_with(|| {
        format!(
            "failed to re-inspect billing acknowledgement proof `{}`",
            path.display()
        )
    })?;
    if billing_proof_file_is_indirect(&after_file_metadata)
        || !after_file_metadata.is_file()
        || billing_proof_file_is_indirect(&after_path_metadata)
        || !after_path_metadata.file_type().is_file()
        || !billing_proof_metadata_unchanged(&opened_metadata, &after_file_metadata)
        || !billing_proof_metadata_unchanged(&opened_metadata, &after_path_metadata)
        || after_file_metadata.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(eyre!(
            "billing acknowledgement proof `{}` changed while it was read",
            path.display()
        ));
    }
    Ok(bytes)
}
fn read_billing_acknowledgement_proof_exact(
    path: &Path,
    reader: &mut impl Read,
    expected_len: usize,
) -> Result<Vec<u8>> {
    let mut bytes = vec![0_u8; expected_len];
    if let Err(error) = reader.read_exact(&mut bytes) {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return Err(eyre!(
                "billing acknowledgement proof `{}` changed length while it was read",
                path.display()
            ));
        }
        return Err(error).wrap_err_with(|| {
            format!(
                "failed to read billing acknowledgement proof `{}`",
                path.display()
            )
        });
    }
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing).wrap_err_with(|| {
        format!(
            "failed to finish reading billing acknowledgement proof `{}`",
            path.display()
        )
    })? != 0
    {
        return Err(eyre!(
            "billing acknowledgement proof `{}` changed length while it was read",
            path.display()
        ));
    }
    Ok(bytes)
}
/// Fetch payload-free billing reconciliation status.
#[derive(clap::Args, Debug, Default)]
pub struct BillingReconciliationArgs {}
impl_run_with_client_methods!(
    BillingReconciliationArgs,
    Client::get_sorafs_billing_reconciliation,
);
impl BillingReconciliationArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client) -> Result<Response<Vec<u8>>>,
    {
        let client = context.client_from_config()?;
        render_json_response(context, get(&client)?)
    }
}
/// Read-only finalized SoraFS hedging projections.
#[derive(clap::Subcommand, Debug)]
pub enum HedgingCommand {
    /// List finalized XOR exposure, including below-threshold periods.
    Exposure(HedgingProjectionArgs),
    /// List deterministic governed hedge intents without executing them.
    Intents(HedgingProjectionArgs),
}
impl Run for HedgingCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Exposure(args) => args.run_with(context, Client::get_sorafs_hedging_exposure),
            Self::Intents(args) => args.run_with(context, Client::get_sorafs_hedging_intents),
        }
    }
}
/// Exact-checkpoint pagination arguments shared by hedging projections.
#[derive(clap::Args, Debug)]
pub struct HedgingProjectionArgs {
    /// Exact non-zero lowercase checkpoint fingerprint from billing status.
    #[arg(long = "expected-checkpoint-fingerprint", value_name = "HEX")]
    expected_checkpoint_fingerprint: String,
    /// Optional exclusive non-zero lowercase opaque cursor.
    #[arg(long, value_name = "HEX")]
    after: Option<String>,
    /// Required page size in the inclusive range 1 through 100.
    #[arg(long, value_name = "COUNT")]
    limit: u16,
}
impl HedgingProjectionArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, SorafsHedgingProjectionFilter<'_>) -> Result<Response<Vec<u8>>>,
    {
        let checkpoint = required_nonzero_lower_hex32(
            &self.expected_checkpoint_fingerprint,
            "--expected-checkpoint-fingerprint",
        )?;
        let after = self
            .after
            .as_deref()
            .map(|value| required_nonzero_lower_hex32(value, "--after"))
            .transpose()?;
        let limit = required_hedging_billing_page_limit(self.limit)?;
        let filter = SorafsHedgingProjectionFilter {
            expected_checkpoint_fingerprint_hex: &checkpoint,
            after_hex: after.as_deref(),
            limit,
        };
        let client = context.client_from_config()?;
        hedging_billing_response::render(context, get(&client, filter)?, &checkpoint)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum AppealsCommand {
    /// Appeal pricing helpers.
    #[command(subcommand)]
    Pricing(AppealsPricingCommand),
    /// Appeal finance helpers.
    #[command(subcommand)]
    Finance(AppealsFinanceCommand),
}
impl_run_for_subcommand!(AppealsCommand => Pricing, Finance);
#[derive(clap::Subcommand, Debug)]
pub enum AppealsPricingCommand {
    /// Print the active local appeal pricing config.
    Config(AppealsPricingConfigArgs),
    /// Print appeal pricing status and supported classes.
    Status(AppealsPricingStatusArgs),
    /// Quote a deposit from a Torii pricing quote JSON payload.
    Quote(AppealsPricingQuoteArgs),
}
impl_run_for_subcommand!(AppealsPricingCommand => Config, Status, Quote);
#[derive(clap::Args, Debug)]
pub struct AppealsPricingConfigArgs;
impl Run for AppealsPricingConfigArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = context.client_from_config()?;
        render_json_response(context, client.get_sorafs_appeal_pricing_config()?)
    }
}
#[derive(clap::Args, Debug)]
pub struct AppealsPricingStatusArgs;
impl Run for AppealsPricingStatusArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = context.client_from_config()?;
        render_json_response(context, client.get_sorafs_appeal_pricing_status()?)
    }
}
#[derive(clap::Args, Debug)]
pub struct AppealsPricingQuoteArgs {
    /// JSON quote request payload path.
    #[arg(long = "input", value_name = "PATH")]
    input: PathBuf,
}
impl_run_with_client_methods!(
    AppealsPricingQuoteArgs,
    Client::post_sorafs_appeal_pricing_quote_json,
);
impl_json_payload_run_with!(AppealsPricingQuoteArgs.input => "appeal pricing quote", render_json_response);
#[derive(clap::Subcommand, Debug)]
pub enum AppealsFinanceCommand {
    /// Runtime asset-lock deposit helpers.
    #[command(subcommand)]
    Deposits(AppealsFinanceDepositsCommand),
    /// List published appeal finance reports.
    Reports(AppealsFinanceReportsArgs),
    /// List published weekly appeal finance rollups.
    WeeklyRollups(AppealsFinanceWeeklyRollupsArgs),
    /// List published appeal finance settlement receipts.
    SettlementReceipts(AppealsFinanceSettlementReceiptsArgs),
}
impl_run_for_subcommand!(AppealsFinanceCommand => Deposits, Reports, WeeklyRollups, SettlementReceipts);
#[derive(clap::Subcommand, Debug)]
pub enum AppealsFinanceDepositsCommand {
    /// Build a runtime asset-lock deposit transaction request.
    Create(AppealsFinanceDepositCreateArgs),
    /// Confirm a runtime asset-lock deposit after ledger submission.
    Confirm(AppealsFinanceDepositConfirmArgs),
    /// Fetch one visible appeal deposit status.
    Get(AppealsFinanceDepositGetArgs),
    /// Settle a confirmed deposit locally.
    Settle(AppealsFinanceDepositSettleArgs),
    /// Reconcile a confirmed deposit against runtime ledger state.
    Reconcile(AppealsFinanceDepositReconcileArgs),
    /// Submit the next settlement transaction step.
    SubmitSettlement(AppealsFinanceDepositSubmitSettlementArgs),
}
impl_run_for_subcommand!(AppealsFinanceDepositsCommand => Create, Confirm, Get, Settle, Reconcile, SubmitSettlement);
#[derive(clap::Args, Debug)]
pub struct AppealsFinanceDepositCreateArgs {
    /// JSON deposit request payload path.
    #[arg(long = "input", value_name = "PATH")]
    input: PathBuf,
}
impl_run_with_client_methods!(
    AppealsFinanceDepositCreateArgs,
    Client::post_sorafs_appeal_finance_deposit_json,
);
impl_appeal_finance_submit_run_with!(AppealsFinanceDepositCreateArgs => "appeal finance deposit", StatusCode::OK);
#[derive(clap::Args, Debug)]
pub struct AppealsFinanceDepositConfirmArgs {
    /// JSON deposit confirmation payload path.
    #[arg(long = "input", value_name = "PATH")]
    input: PathBuf,
}
impl_run_with_client_methods!(
    AppealsFinanceDepositConfirmArgs,
    Client::post_sorafs_appeal_finance_deposit_confirm_json,
);
impl_appeal_finance_submit_run_with!(AppealsFinanceDepositConfirmArgs => "appeal finance deposit confirmation", StatusCode::OK);
#[derive(clap::Args, Debug)]
pub struct AppealsFinanceDepositGetArgs {
    /// Hex-encoded asset-lock escrow id.
    #[arg(long = "escrow-id", value_name = "HEX")]
    escrow_id: String,
}
impl_run_with_client_methods!(
    AppealsFinanceDepositGetArgs,
    Client::get_sorafs_appeal_finance_deposit,
);
impl AppealsFinanceDepositGetArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str) -> Result<Response<Vec<u8>>>,
    {
        let escrow_id = required_trimmed_text(&self.escrow_id, "--escrow-id")?;
        let client = context.client_from_config()?;
        let response = get(&client, &escrow_id)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct AppealsFinanceDepositSettleArgs {
    /// JSON deposit settlement payload path.
    #[arg(long = "input", value_name = "PATH")]
    input: PathBuf,
}
impl_run_with_client_methods!(
    AppealsFinanceDepositSettleArgs,
    Client::post_sorafs_appeal_finance_deposit_settle_json,
);
impl_appeal_finance_submit_run_with!(AppealsFinanceDepositSettleArgs => "appeal finance deposit settlement", StatusCode::OK);
#[derive(clap::Args, Debug)]
pub struct AppealsFinanceDepositReconcileArgs {
    /// JSON deposit settlement reconciliation payload path.
    #[arg(long = "input", value_name = "PATH")]
    input: PathBuf,
}
impl_run_with_client_methods!(
    AppealsFinanceDepositReconcileArgs,
    Client::post_sorafs_appeal_finance_deposit_reconcile_json,
);
impl_appeal_finance_submit_run_with!(AppealsFinanceDepositReconcileArgs => "appeal finance deposit settlement reconciliation", StatusCode::OK);
#[derive(clap::Args, Debug)]
pub struct AppealsFinanceDepositSubmitSettlementArgs {
    /// JSON deposit settlement submission payload path.
    #[arg(long = "input", value_name = "PATH")]
    input: PathBuf,
}
impl_run_with_client_methods!(
    AppealsFinanceDepositSubmitSettlementArgs,
    Client::post_sorafs_appeal_finance_deposit_submit_settlement_json,
);
impl_appeal_finance_submit_run_with!(AppealsFinanceDepositSubmitSettlementArgs => "appeal finance deposit settlement submission", StatusCode::ACCEPTED);
#[derive(clap::Args, Debug)]
pub struct AppealsFinanceReportsArgs {
    /// Maximum number of report entries to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    AppealsFinanceReportsArgs,
    Client::get_sorafs_appeal_finance_reports
);
impl_json_limit_run_with!(AppealsFinanceReportsArgs => SorafsAppealFinanceReadbackFilter);
#[derive(clap::Args, Debug)]
pub struct AppealsFinanceWeeklyRollupsArgs {
    /// Maximum number of rollup entries to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    AppealsFinanceWeeklyRollupsArgs,
    Client::get_sorafs_appeal_finance_weekly_rollups,
);
impl_json_limit_run_with!(AppealsFinanceWeeklyRollupsArgs => SorafsAppealFinanceReadbackFilter);
#[derive(clap::Args, Debug)]
pub struct AppealsFinanceSettlementReceiptsArgs {
    /// Maximum number of settlement receipt entries to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    AppealsFinanceSettlementReceiptsArgs,
    Client::get_sorafs_appeal_finance_settlement_receipts,
);
impl_json_limit_run_with!(AppealsFinanceSettlementReceiptsArgs => SorafsAppealFinanceReadbackFilter);
fn run_appeal_finance_json_submit<C, F>(
    context: &mut C,
    input: &Path,
    payload_label: &str,
    submit: F,
    accepted_status: StatusCode,
) -> Result<()>
where
    C: RunContext,
    F: FnOnce(&Client, &[u8]) -> Result<Response<Vec<u8>>>,
{
    let payload = load_sorafs_json_payload(input, payload_label)?;
    let client = context.client_from_config()?;
    let response = submit(&client, &payload)?;
    match accepted_status {
        StatusCode::ACCEPTED => render_json_response_ok_or_accepted(context, response),
        StatusCode::OK => render_json_response(context, response),
        status => Err(eyre!(
            "unsupported SoraFS appeal finance success status {status}"
        )),
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum GarCommand {
    /// Render a GAR enforcement receipt artefact (JSON + optional Norito bytes).
    Receipt(GarReceiptArgs),
}
impl_run_for_subcommand!(GarCommand => Receipt);
#[derive(clap::Subcommand, Debug)]
pub enum TransparencyCommand {
    /// Inspect published transparency cycles and entry proofs.
    #[command(subcommand)]
    Cycles(TransparencyCyclesCommand),
    /// Fetch the explorer-ready transparency snapshot.
    Explorer(TransparencyExplorerArgs),
    /// Probe deployed transparency explorer routes and emit payload-free rollout evidence.
    ExplorerCanary(TransparencyExplorerCanaryArgs),
    /// Probe deployed transparency publication readback and emit payload-free evidence.
    PublicationCanary(TransparencyPublicationCanaryArgs),
    /// List published proof-token issuance summaries.
    Tokens(TransparencyTokensArgs),
    /// Submit proof-token issuance feed payloads and rollout canaries.
    #[command(subcommand)]
    TokenIssuance(TransparencyTokenIssuanceCommand),
    /// Submit privacy aggregate source events and trigger configured due publication.
    #[command(subcommand)]
    PrivacyAggregate(TransparencyPrivacyAggregateCommand),
}
impl_run_for_subcommand!(TransparencyCommand => Cycles, Explorer, ExplorerCanary, PublicationCanary, Tokens, TokenIssuance, PrivacyAggregate);
#[derive(clap::Subcommand, Debug)]
pub enum TransparencyCyclesCommand {
    /// List locally published transparency cycle summaries.
    List(TransparencyCyclesListArgs),
    /// Fetch and verify one published transparency cycle.
    Get(TransparencyCyclesGetArgs),
    /// Fetch and verify one published transparency entry proof.
    Entry(TransparencyCyclesEntryArgs),
}
impl_run_for_subcommand!(TransparencyCyclesCommand => List, Get, Entry);
#[derive(clap::Args, Debug)]
pub struct TransparencyCyclesListArgs {
    /// Maximum number of cycle summaries to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    TransparencyCyclesListArgs,
    Client::get_sorafs_transparency_cycles,
);
impl_json_limit_run_with!(TransparencyCyclesListArgs => SorafsTransparencyReadbackFilter);
#[derive(clap::Args, Debug)]
pub struct TransparencyCyclesGetArgs {
    /// 16-byte cycle id encoded as hexadecimal.
    #[arg(long = "cycle-id", value_name = "HEX")]
    cycle_id: String,
    /// Maximum number of publication proofs to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    TransparencyCyclesGetArgs,
    Client::get_sorafs_transparency_cycle,
);
impl TransparencyCyclesGetArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str, SorafsTransparencyReadbackFilter) -> Result<Response<Vec<u8>>>,
    {
        let cycle_id = normalize_hex_16_lower(&self.cycle_id, "--cycle-id")?;
        let filter = SorafsTransparencyReadbackFilter { limit: self.limit };
        let client = context.client_from_config()?;
        let response = get(&client, &cycle_id, filter)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct TransparencyCyclesEntryArgs {
    /// 16-byte cycle id encoded as hexadecimal.
    #[arg(long = "cycle-id", value_name = "HEX")]
    cycle_id: String,
    /// 16-byte entry id encoded as hexadecimal.
    #[arg(long = "entry-id", value_name = "HEX")]
    entry_id: String,
}
impl_run_with_client_methods!(
    TransparencyCyclesEntryArgs,
    Client::get_sorafs_transparency_cycle_entry,
);
impl TransparencyCyclesEntryArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str, &str) -> Result<Response<Vec<u8>>>,
    {
        let cycle_id = normalize_hex_16_lower(&self.cycle_id, "--cycle-id")?;
        let entry_id = normalize_hex_16_lower(&self.entry_id, "--entry-id")?;
        let client = context.client_from_config()?;
        let response = get(&client, &cycle_id, &entry_id)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct TransparencyExplorerArgs {
    /// Maximum number of cycle summaries and token issuance entries per array.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    TransparencyExplorerArgs,
    Client::get_sorafs_transparency_explorer,
);
impl_json_limit_run_with!(TransparencyExplorerArgs => SorafsTransparencyReadbackFilter);
#[derive(clap::Args, Debug)]
pub struct TransparencyExplorerCanaryArgs {
    /// Base URL of the deployed Torii or public explorer gateway.
    #[arg(long = "torii-url", value_name = "URL")]
    torii_url: Option<String>,
    /// Maximum number of cycle and proof-token summaries to request.
    #[arg(long)]
    limit: Option<u32>,
    /// HTTP timeout in seconds.
    #[arg(long = "timeout-secs", default_value_t = 30)]
    timeout_secs: u64,
    /// Optional path where the canary evidence JSON will be written.
    #[arg(long = "out", value_name = "PATH")]
    out: Option<PathBuf>,
}
impl Run for TransparencyExplorerCanaryArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let timeout = Duration::from_secs(self.timeout_secs.max(1));
        let client = BlockingHttpClient::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .user_agent("sorafs-cli transparency-explorer-canary")
            .build()
            .wrap_err("failed to construct SoraFS transparency explorer canary HTTP client")?;
        self.run_with_fetch(context, |url| {
            transparency_explorer_canary_http_get(&client, url)
        })
    }
}
impl TransparencyExplorerCanaryArgs {
    fn run_with_fetch<C, F>(&self, context: &mut C, mut fetch: F) -> Result<()>
    where
        C: RunContext,
        F: FnMut(&str) -> Result<TransparencyExplorerCanaryHttpResponse>,
    {
        let torii_url = match self.torii_url.as_deref() {
            Some(url) => required_trimmed_text(url, "--torii-url")?,
            None => context.config().torii_api_url.as_str().trim().to_owned(),
        };
        if torii_url.is_empty() {
            return Err(eyre!("configured Torii API URL must not be empty"));
        }
        let evidence =
            transparency_explorer_canary_evidence_json(&torii_url, self.limit, &mut fetch)?;
        if let Some(path) = &self.out {
            ensure_parent_dir(path)?;
            let bytes = norito::json::to_vec_pretty(&evidence)
                .wrap_err("failed to serialize SoraFS transparency explorer canary evidence")?;
            fs::write(path, bytes).wrap_err_with(|| {
                format!(
                    "failed to write SoraFS transparency explorer canary evidence to `{}`",
                    path.display()
                )
            })?;
        }
        context.print_data(&evidence)
    }
}
#[derive(clap::Args, Debug)]
pub struct TransparencyPublicationCanaryArgs {
    /// Base URL of the deployed Torii or public transparency gateway.
    #[arg(long = "torii-url", value_name = "URL")]
    torii_url: Option<String>,
    /// Published cycle id to verify through the cycle detail route.
    #[arg(long = "cycle-id", value_name = "HEX")]
    cycle_ids: Vec<String>,
    /// Maximum number of cycle summaries or publication proofs to request.
    #[arg(long)]
    limit: Option<u32>,
    /// HTTP timeout in seconds.
    #[arg(long = "timeout-secs", default_value_t = 30)]
    timeout_secs: u64,
    /// Optional path where the canary evidence JSON will be written.
    #[arg(long = "out", value_name = "PATH")]
    out: Option<PathBuf>,
}
impl Run for TransparencyPublicationCanaryArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let timeout = Duration::from_secs(self.timeout_secs.max(1));
        let client = BlockingHttpClient::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .user_agent("sorafs-cli transparency-publication-canary")
            .build()
            .wrap_err("failed to construct SoraFS transparency publication canary HTTP client")?;
        self.run_with_fetch(context, |url| {
            transparency_publication_canary_http_get(&client, url)
        })
    }
}
impl TransparencyPublicationCanaryArgs {
    fn run_with_fetch<C, F>(&self, context: &mut C, mut fetch: F) -> Result<()>
    where
        C: RunContext,
        F: FnMut(&str) -> Result<TransparencyExplorerCanaryHttpResponse>,
    {
        let torii_url = match self.torii_url.as_deref() {
            Some(url) => required_trimmed_text(url, "--torii-url")?,
            None => context.config().torii_api_url.as_str().trim().to_owned(),
        };
        if torii_url.is_empty() {
            return Err(eyre!("configured Torii API URL must not be empty"));
        }
        let cycle_ids = self
            .cycle_ids
            .iter()
            .map(|cycle_id| normalize_hex_16_lower(cycle_id, "--cycle-id"))
            .collect::<Result<Vec<_>>>()?;
        let evidence = transparency_publication_canary_evidence_json(
            &torii_url, &cycle_ids, self.limit, &mut fetch,
        )?;
        if let Some(path) = &self.out {
            write_json_artifact(path, &evidence, "transparency publication canary evidence")?;
        }
        context.print_data(&evidence)
    }
}
#[derive(clap::Args, Debug)]
pub struct TransparencyTokensArgs {
    /// Maximum number of proof-token issuance entries to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    TransparencyTokensArgs,
    Client::get_sorafs_transparency_token_issuances,
);
impl_json_limit_run_with!(TransparencyTokensArgs => SorafsTransparencyReadbackFilter);
#[derive(clap::Subcommand, Debug)]
pub enum TransparencyTokenIssuanceCommand {
    /// Submit one proof-token issuance JSON payload.
    Submit(TransparencyTokenIssuanceSubmitArgs),
    /// Probe deployed proof-token issuance producer feed routes.
    Canary(TransparencyTokenIssuanceCanaryArgs),
}
impl_run_for_subcommand!(TransparencyTokenIssuanceCommand => Submit, Canary);
#[derive(clap::Args, Debug)]
pub struct TransparencyTokenIssuanceSubmitArgs {
    /// JSON proof-token issuance payload path.
    #[arg(long = "payload", value_name = "PATH")]
    payload: PathBuf,
}
impl_run_with_client_methods!(
    TransparencyTokenIssuanceSubmitArgs,
    Client::post_sorafs_transparency_token_issuance_json,
);
impl_json_payload_run_with!(TransparencyTokenIssuanceSubmitArgs.payload => "transparency proof-token issuance", render_json_response_ok_or_accepted);
#[derive(clap::Args, Debug)]
pub struct TransparencyTokenIssuanceCanaryArgs {
    /// Proof-token issuance JSON payload path to submit.
    #[arg(long = "issuance", value_name = "PATH")]
    issuances: Vec<PathBuf>,
    /// Optional path where payload-free canary evidence JSON is written.
    #[arg(long = "out", value_name = "PATH")]
    out: Option<PathBuf>,
}
impl_run_with_client_methods!(
    TransparencyTokenIssuanceCanaryArgs,
    Client::post_sorafs_transparency_token_issuance_json,
);
impl TransparencyTokenIssuanceCanaryArgs {
    fn run_with<C, F>(&self, context: &mut C, mut submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnMut(&Client, &[u8]) -> Result<Response<Vec<u8>>>,
    {
        if self.issuances.is_empty() {
            return Err(eyre!("at least one --issuance payload is required"));
        }
        let client = context.client_from_config()?;
        let mut probes = Vec::new();
        for path in &self.issuances {
            let payload =
                load_sorafs_json_payload(path, "transparency proof-token issuance canary")?;
            let response = submit(&client, &payload)?;
            probes.push(transparency_token_issuance_canary_probe_json(
                path, &payload, response,
            ));
        }
        let passed_count = probes
            .iter()
            .filter(|probe| {
                probe
                    .get("response_success")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .count();
        let mut evidence = Map::new();
        evidence.insert(
            "schema".into(),
            Value::from("sorafs.transparency.proof_token_issuance.canary.v1"),
        );
        evidence.insert("source".into(), Value::from("iroha_cli"));
        evidence.insert(
            "status".into(),
            Value::from(if passed_count == probes.len() {
                "passed"
            } else {
                "failed"
            }),
        );
        evidence.insert(
            "probe_count".into(),
            Value::from(u64::try_from(probes.len()).unwrap_or(u64::MAX)),
        );
        evidence.insert(
            "passed_probe_count".into(),
            Value::from(u64::try_from(passed_count).unwrap_or(u64::MAX)),
        );
        evidence.insert(
            "issuance_probe_count".into(),
            Value::from(u64::try_from(self.issuances.len()).unwrap_or(u64::MAX)),
        );
        evidence.insert("payload_bytes_included".into(), Value::Bool(false));
        evidence.insert("proof_token_frames_included".into(), Value::Bool(false));
        evidence.insert("private_digest_keys_included".into(), Value::Bool(false));
        evidence.insert("response_bodies_included".into(), Value::Bool(false));
        evidence.insert("probes".into(), Value::Array(probes));
        let evidence = Value::Object(evidence);
        if let Some(path) = &self.out {
            write_json_artifact(
                path,
                &evidence,
                "transparency proof-token issuance canary evidence",
            )?;
        }
        context.print_data(&evidence)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum TransparencyPrivacyAggregateCommand {
    /// Submit one privacy aggregate source-event JSON payload.
    SourceEvent(TransparencyPrivacyAggregateSourceEventArgs),
    /// Trigger configured due privacy aggregate publication.
    PublishDue(TransparencyPrivacyAggregatePublishDueArgs),
    /// Probe deployed privacy aggregate producer/scheduler routes.
    Canary(TransparencyPrivacyAggregateCanaryArgs),
}
impl_run_for_subcommand!(TransparencyPrivacyAggregateCommand => SourceEvent, PublishDue, Canary);
#[derive(clap::Args, Debug)]
pub struct TransparencyPrivacyAggregateSourceEventArgs {
    /// JSON payload path.
    #[arg(long = "payload", value_name = "PATH")]
    payload: PathBuf,
}
impl_run_with_client_methods!(
    TransparencyPrivacyAggregateSourceEventArgs,
    Client::post_sorafs_transparency_privacy_aggregate_source_event_json,
);
impl_json_payload_run_with!(TransparencyPrivacyAggregateSourceEventArgs.payload => "transparency privacy aggregate source-event", render_json_response_ok_or_accepted);
#[derive(clap::Args, Debug)]
pub struct TransparencyPrivacyAggregatePublishDueArgs {
    /// JSON payload path.
    #[arg(long = "payload", value_name = "PATH")]
    payload: PathBuf,
}
impl_run_with_client_methods!(
    TransparencyPrivacyAggregatePublishDueArgs,
    Client::post_sorafs_transparency_privacy_aggregate_publish_due_json,
);
impl_json_payload_run_with!(TransparencyPrivacyAggregatePublishDueArgs.payload => "transparency privacy aggregate publish-due", render_json_response);
#[derive(clap::Args, Debug)]
pub struct TransparencyPrivacyAggregateCanaryArgs {
    /// Privacy aggregate source-event JSON payload path to submit.
    #[arg(long = "source-event", value_name = "PATH")]
    source_events: Vec<PathBuf>,
    /// Privacy aggregate publish-due JSON payload path to submit.
    #[arg(long = "publish-due", value_name = "PATH")]
    publish_due: Vec<PathBuf>,
    /// Optional path where payload-free canary evidence JSON is written.
    #[arg(long = "out", value_name = "PATH")]
    out: Option<PathBuf>,
}
impl_run_with_client_methods!(
    TransparencyPrivacyAggregateCanaryArgs,
    Client::post_sorafs_transparency_privacy_aggregate_source_event_json,
    Client::post_sorafs_transparency_privacy_aggregate_publish_due_json,
);
impl TransparencyPrivacyAggregateCanaryArgs {
    fn run_with<C, FSource, FPublish>(
        &self,
        context: &mut C,
        mut submit_source_event: FSource,
        mut submit_publish_due: FPublish,
    ) -> Result<()>
    where
        C: RunContext,
        FSource: FnMut(&Client, &[u8]) -> Result<Response<Vec<u8>>>,
        FPublish: FnMut(&Client, &[u8]) -> Result<Response<Vec<u8>>>,
    {
        if self.source_events.is_empty() && self.publish_due.is_empty() {
            return Err(eyre!(
                "at least one --source-event or --publish-due payload is required"
            ));
        }
        let client = context.client_from_config()?;
        let mut probes = Vec::new();
        for path in &self.source_events {
            let payload = load_sorafs_json_payload(
                path,
                "transparency privacy aggregate canary source-event",
            )?;
            let response = submit_source_event(&client, &payload)?;
            probes.push(transparency_privacy_aggregate_canary_probe_json(
                "source_event",
                path,
                &payload,
                response,
            ));
        }
        for path in &self.publish_due {
            let payload = load_sorafs_json_payload(
                path,
                "transparency privacy aggregate canary publish-due",
            )?;
            let response = submit_publish_due(&client, &payload)?;
            probes.push(transparency_privacy_aggregate_canary_probe_json(
                "publish_due",
                path,
                &payload,
                response,
            ));
        }
        let passed_count = probes
            .iter()
            .filter(|probe| {
                probe
                    .get("response_success")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .count();
        let mut evidence = Map::new();
        evidence.insert(
            "schema".into(),
            Value::from("sorafs.transparency.privacy_aggregate.canary.v1"),
        );
        evidence.insert("source".into(), Value::from("iroha_cli"));
        evidence.insert(
            "status".into(),
            Value::from(if passed_count == probes.len() {
                "passed"
            } else {
                "failed"
            }),
        );
        evidence.insert(
            "probe_count".into(),
            Value::from(u64::try_from(probes.len()).unwrap_or(u64::MAX)),
        );
        evidence.insert(
            "passed_probe_count".into(),
            Value::from(u64::try_from(passed_count).unwrap_or(u64::MAX)),
        );
        evidence.insert(
            "source_event_probe_count".into(),
            Value::from(u64::try_from(self.source_events.len()).unwrap_or(u64::MAX)),
        );
        evidence.insert(
            "publish_due_probe_count".into(),
            Value::from(u64::try_from(self.publish_due.len()).unwrap_or(u64::MAX)),
        );
        evidence.insert("payload_bytes_included".into(), Value::Bool(false));
        evidence.insert("raw_metric_values_included".into(), Value::Bool(false));
        evidence.insert("private_payloads_included".into(), Value::Bool(false));
        evidence.insert("probes".into(), Value::Array(probes));
        let evidence = Value::Object(evidence);
        if let Some(path) = &self.out {
            write_json_artifact(
                path,
                &evidence,
                "transparency privacy aggregate canary evidence",
            )?;
        }
        context.print_data(&evidence)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ModerationCommand {
    /// Inspect finalized moderation cases and submit native ledger actions.
    #[command(subcommand)]
    Ballots(ModerationBallotsCommand),
    /// Admit and inspect local moderation model registry records.
    #[command(subcommand)]
    Registry(ModerationRegistryCommand),
    /// Submit and inspect deterministic local moderation screening results.
    #[command(subcommand)]
    Screening(ModerationScreeningCommand),
    /// Inspect and advance local moderation quarantine records.
    #[command(subcommand)]
    Quarantine(ModerationQuarantineCommand),
}
impl_run_for_subcommand!(ModerationCommand => Ballots, Registry, Screening, Quarantine);
#[derive(clap::Subcommand, Debug)]
pub enum ModerationBallotsCommand {
    /// List finalized chain-authoritative moderation case projections.
    List(ModerationBallotsListArgs),
    /// Get one finalized chain-authoritative moderation case projection.
    Get(ModerationBallotsGetArgs),
    /// Get the payload-free no-show plan for one closed moderation ballot.
    #[command(name = "no-show-plan")]
    NoShowPlan(ModerationBallotsNoShowPlanArgs),
    /// List typed committed moderation events.
    Events(ModerationBallotsEventsArgs),
    /// Submit a juror commit as an exact caller-signed native transaction.
    Commit(ModerationBallotsCommitArgs),
    /// Submit a juror reveal as an exact caller-signed native transaction.
    Reveal(ModerationBallotsRevealArgs),
    /// Submit governed native moderation finalization.
    Tally(ModerationBallotsTallyArgs),
    /// Execute pending commit/reveal/tally actions from a coordination status.
    Execute(ModerationBallotsExecuteArgs),
    /// Generate supervised commit/reveal executor deployment artifacts.
    ExecutorBundle(ModerationBallotsExecutorBundleArgs),
    /// Verify a deployed commit/reveal executor bundle and captured run summary.
    ExecutorCanary(ModerationBallotsExecutorCanaryArgs),
}
impl_run_for_subcommand!(ModerationBallotsCommand => List, Get, NoShowPlan, Events, Commit, Reveal, Tally, Execute, ExecutorBundle, ExecutorCanary);
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsListArgs {
    /// Maximum number of ballots, commits, and reveals to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    ModerationBallotsListArgs,
    Client::get_sorafs_moderation_ballots,
);
impl_json_limit_run_with!(ModerationBallotsListArgs => SorafsModerationBallotsFilter);
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsGetArgs {
    /// Moderation or appeal case identifier.
    #[arg(long = "case-id", value_name = "TEXT")]
    case_id: String,
    /// Moderation ballot round identifier.
    #[arg(long = "round-id", value_name = "TEXT")]
    round_id: String,
    /// Maximum number of commits and reveals to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    ModerationBallotsGetArgs,
    Client::get_sorafs_moderation_ballot,
);
impl ModerationBallotsGetArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str, &str, SorafsModerationBallotsFilter) -> Result<Response<Vec<u8>>>,
    {
        let case_id = required_trimmed_text(&self.case_id, "--case-id")?;
        let round_id = required_trimmed_text(&self.round_id, "--round-id")?;
        let filter = SorafsModerationBallotsFilter { limit: self.limit };
        let client = context.client_from_config()?;
        let response = get(&client, &case_id, &round_id, filter)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsNoShowPlanArgs {
    /// Moderation or appeal case identifier.
    #[arg(long = "case-id", value_name = "TEXT")]
    case_id: String,
    /// Moderation ballot round identifier.
    #[arg(long = "round-id", value_name = "TEXT")]
    round_id: String,
}
impl_run_with_client_methods!(
    ModerationBallotsNoShowPlanArgs,
    Client::get_sorafs_moderation_ballot_no_show_plan,
);
impl ModerationBallotsNoShowPlanArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str, &str) -> Result<Response<Vec<u8>>>,
    {
        let case_id = required_trimmed_text(&self.case_id, "--case-id")?;
        let round_id = required_trimmed_text(&self.round_id, "--round-id")?;
        let client = context.client_from_config()?;
        let response = get(&client, &case_id, &round_id)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsEventsArgs {
    /// Optional event sequence to resume from.
    #[arg(long)]
    since: Option<u64>,
    /// Maximum number of events to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    ModerationBallotsEventsArgs,
    Client::get_sorafs_moderation_ballot_events,
);
impl ModerationBallotsEventsArgs {
    fn run_with<C, F>(&self, context: &mut C, list: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, SorafsModerationBallotEventsFilter) -> Result<Response<Vec<u8>>>,
    {
        let filter = SorafsModerationBallotEventsFilter {
            since: self.since,
            limit: self.limit,
        };
        let client = context.client_from_config()?;
        let response = list(&client, filter)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsCommitArgs {
    /// Commit payload path.
    #[arg(long = "payload", value_name = "PATH")]
    payload: PathBuf,
    /// Input format: json or norito.
    #[arg(long = "format", default_value = "json")]
    format: String,
}
impl_run_with_client_methods!(
    ModerationBallotsCommitArgs,
    Client::post_sorafs_moderation_ballot_commit,
);
impl ModerationBallotsCommitArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
    {
        let commit = load_moderation_ballot_commit_payload(&self.payload, self.format.as_str())?;
        let client = context.client_from_config()?;
        let transaction = build_moderation_commit_transaction(&client, &commit)?;
        let hash = submit(&client, &transaction)?;
        render_moderation_transaction_hash(context, &hash)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsRevealArgs {
    /// Reveal payload path.
    #[arg(long = "payload", value_name = "PATH")]
    payload: PathBuf,
    /// Input format: json or norito.
    #[arg(long = "format", default_value = "json")]
    format: String,
}
impl_run_with_client_methods!(
    ModerationBallotsRevealArgs,
    Client::post_sorafs_moderation_ballot_reveal,
);
impl ModerationBallotsRevealArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
    {
        let reveal = load_moderation_ballot_reveal_payload(&self.payload, self.format.as_str())?;
        let client = context.client_from_config()?;
        let transaction = build_moderation_reveal_transaction(&client, &reveal)?;
        let hash = submit(&client, &transaction)?;
        render_moderation_transaction_hash(context, &hash)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsTallyArgs {
    /// Moderation or appeal case identifier.
    #[arg(long = "case-id", value_name = "TEXT")]
    case_id: String,
    /// Moderation ballot round identifier.
    #[arg(long = "round-id", value_name = "TEXT")]
    round_id: String,
}
impl_run_with_client_methods!(
    ModerationBallotsTallyArgs,
    Client::post_sorafs_moderation_ballot_tally,
);
impl ModerationBallotsTallyArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
    {
        let case_id = required_trimmed_text(&self.case_id, "--case-id")?;
        let round_id = required_trimmed_text(&self.round_id, "--round-id")?;
        let client = context.client_from_config()?;
        let transaction = build_moderation_finalization_transaction(&client, case_id, round_id)?;
        let hash = submit(&client, &transaction)?;
        render_moderation_transaction_hash(context, &hash)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsExecuteArgs {
    /// Payload-free commit/reveal status JSON from the operator workflow service.
    #[arg(long = "status", value_name = "PATH")]
    status: PathBuf,
    /// Commit payload path to submit if the status says the juror is pending.
    #[arg(long = "commit-payload", value_name = "PATH")]
    commit_payloads: Vec<PathBuf>,
    /// Reveal payload path to submit if the status says the juror is pending.
    #[arg(long = "reveal-payload", value_name = "PATH")]
    reveal_payloads: Vec<PathBuf>,
    /// Commit input format: json or norito.
    #[arg(long = "commit-format", default_value = "json")]
    commit_format: String,
    /// Reveal input format: json or norito.
    #[arg(long = "reveal-format", default_value = "json")]
    reveal_format: String,
    /// Submit tally requests for ballots already marked ready in the status.
    #[arg(long = "submit-tally")]
    submit_tally: bool,
}
impl_run_with_client_methods!(
    ModerationBallotsExecuteArgs,
    Client::post_sorafs_moderation_ballot_commit,
    Client::post_sorafs_moderation_ballot_reveal,
    Client::post_sorafs_moderation_ballot_tally,
);
impl ModerationBallotsExecuteArgs {
    fn run_with<C, FCommit, FReveal, FTally>(
        &self,
        context: &mut C,
        mut submit_commit: FCommit,
        mut submit_reveal: FReveal,
        mut submit_tally: FTally,
    ) -> Result<()>
    where
        C: RunContext,
        FCommit: FnMut(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
        FReveal: FnMut(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
        FTally: FnMut(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
    {
        if self.commit_payloads.is_empty() && self.reveal_payloads.is_empty() && !self.submit_tally
        {
            return Err(eyre!(
                "at least one --commit-payload, --reveal-payload, or --submit-tally is required"
            ));
        }
        let status = load_moderation_commit_reveal_status_payload(&self.status)?;
        let coordination = moderation_commit_reveal_coordination_from_status(&status)?;
        let client = context.client_from_config()?;
        let mut actions = Vec::new();
        for path in &self.commit_payloads {
            let commit = load_moderation_ballot_commit_payload(path, self.commit_format.as_str())?;
            let key = ModerationBallotExecutionKey::from_commit(&commit);
            if !coordination.pending_commits.contains(&key) {
                return Err(eyre!(
                    "commit payload for juror `{}` ballot `{}/{}` is not pending in --status",
                    key.juror_id,
                    key.case_id,
                    key.round_id
                ));
            }
            let transaction = build_moderation_commit_transaction(&client, &commit)?;
            let hash = submit_commit(&client, &transaction)?;
            actions.push(moderation_ballot_execution_action_json(
                "commit",
                &key.case_id,
                &key.round_id,
                Some(&key.juror_id),
                &hash,
            )?);
        }
        for path in &self.reveal_payloads {
            let reveal = load_moderation_ballot_reveal_payload(path, self.reveal_format.as_str())?;
            let key = ModerationBallotExecutionKey::from_reveal(&reveal);
            if !coordination.pending_reveals.contains(&key) {
                return Err(eyre!(
                    "reveal payload for juror `{}` ballot `{}/{}` is not pending in --status",
                    key.juror_id,
                    key.case_id,
                    key.round_id
                ));
            }
            let transaction = build_moderation_reveal_transaction(&client, &reveal)?;
            let hash = submit_reveal(&client, &transaction)?;
            actions.push(moderation_ballot_execution_action_json(
                "reveal",
                &key.case_id,
                &key.round_id,
                Some(&key.juror_id),
                &hash,
            )?);
        }
        if self.submit_tally {
            for (case_id, round_id) in &coordination.tally_ready {
                let transaction =
                    build_moderation_finalization_transaction(&client, case_id, round_id)?;
                let hash = submit_tally(&client, &transaction)?;
                actions.push(moderation_ballot_execution_action_json(
                    "tally", case_id, round_id, None, &hash,
                )?);
            }
        }
        let mut output = Map::new();
        output.insert(
            "schema".into(),
            Value::from("sorafs.moderation.ballots.execution.v1"),
        );
        output.insert("source".into(), Value::from("commit-reveal-status"));
        output.insert("status".into(), Value::from("executed"));
        output.insert("action_count".into(), Value::from(actions.len() as u64));
        output.insert(
            "commit_action_count".into(),
            Value::from(self.commit_payloads.len() as u64),
        );
        output.insert(
            "reveal_action_count".into(),
            Value::from(self.reveal_payloads.len() as u64),
        );
        output.insert(
            "tally_action_count".into(),
            Value::from(if self.submit_tally {
                coordination.tally_ready.len() as u64
            } else {
                0
            }),
        );
        output.insert("payload_bytes_included".into(), Value::Bool(false));
        output.insert("private_payloads_included".into(), Value::Bool(false));
        output.insert("actions".into(), Value::Array(actions));
        context.print_data(&Value::Object(output))
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsExecutorBundleArgs {
    /// Runtime path to the payload-free commit/reveal status JSON.
    #[arg(long = "status", value_name = "PATH")]
    status: PathBuf,
    /// Directory to write deployment artifacts into.
    #[arg(long = "bundle-out", value_name = "DIR")]
    bundle_out: PathBuf,
    /// Runtime commit payload path to submit if the status says the juror is pending.
    #[arg(long = "commit-payload", value_name = "PATH")]
    commit_payloads: Vec<PathBuf>,
    /// Runtime reveal payload path to submit if the status says the juror is pending.
    #[arg(long = "reveal-payload", value_name = "PATH")]
    reveal_payloads: Vec<PathBuf>,
    /// Commit input format: json or norito.
    #[arg(long = "commit-format", default_value = "json")]
    commit_format: String,
    /// Reveal input format: json or norito.
    #[arg(long = "reveal-format", default_value = "json")]
    reveal_format: String,
    /// Submit tally requests for ballots already marked ready in the status.
    #[arg(long = "submit-tally")]
    submit_tally: bool,
    /// Iroha CLI binary path used by the generated runner.
    #[arg(long = "iroha-bin", default_value = "iroha", value_name = "PATH")]
    iroha_bin: String,
    /// Service label used for generated systemd and launchd artifacts.
    #[arg(
        long = "service-name",
        default_value = "org.sora.sorafs.ballots-executor"
    )]
    service_name: String,
    /// Service user for the generated systemd unit.
    #[arg(long = "service-user", default_value = "sorafs-moderation")]
    service_user: String,
    /// Service group for the generated systemd unit.
    #[arg(long = "service-group", default_value = "sorafs-moderation")]
    service_group: String,
    /// Scheduler interval for the generated systemd timer and launchd job.
    #[arg(long = "interval-secs", default_value_t = 60)]
    interval_secs: u64,
}
impl Run for ModerationBallotsExecutorBundleArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        self.run_with(context)
    }
}
impl ModerationBallotsExecutorBundleArgs {
    fn run_with<C: RunContext>(&self, context: &mut C) -> Result<()> {
        let summary = write_moderation_ballots_executor_bundle(self)?;
        context.print_data(&summary)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationBallotsExecutorCanaryArgs {
    /// Executor bundle directory produced by `executor-bundle`.
    #[arg(long = "bundle", value_name = "DIR")]
    bundle: PathBuf,
    /// Optional payload-free `ballots execute` summary captured from a deployed job run.
    #[arg(long = "execution-summary", value_name = "PATH")]
    execution_summary: Option<PathBuf>,
    /// Optional path to write canary evidence JSON.
    #[arg(long = "out", value_name = "PATH")]
    out: Option<PathBuf>,
}
impl Run for ModerationBallotsExecutorCanaryArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        self.run_with(context)
    }
}
impl ModerationBallotsExecutorCanaryArgs {
    fn run_with<C: RunContext>(&self, context: &mut C) -> Result<()> {
        let evidence = moderation_ballots_executor_canary_evidence(self)?;
        if let Some(path) = &self.out {
            write_json_artifact(
                path,
                &evidence,
                "moderation ballots executor canary evidence",
            )?;
        }
        context.print_data(&evidence)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ModerationRegistryCommand {
    /// List local moderation model registry records.
    List(ModerationRegistryListArgs),
    /// Admit a governance-signed reproducibility manifest.
    SubmitRepro(ModerationRegistrySubmitReproArgs),
    /// Admit an adversarial corpus manifest.
    SubmitCorpus(ModerationRegistrySubmitCorpusArgs),
}
impl_run_for_subcommand!(ModerationRegistryCommand => List, SubmitRepro, SubmitCorpus);
#[derive(clap::Args, Debug)]
pub struct ModerationRegistryListArgs {
    /// Maximum number of records to return from each registry section.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    ModerationRegistryListArgs,
    Client::get_sorafs_moderation_model_registry,
);
impl_json_limit_run_with!(ModerationRegistryListArgs => SorafsModerationModelRegistryFilter);
#[derive(clap::Args, Debug)]
pub struct ModerationRegistrySubmitReproArgs {
    /// Reproducibility manifest path.
    #[arg(long = "manifest", value_name = "PATH")]
    manifest: PathBuf,
    /// Input format: json or norito.
    #[arg(long = "format", default_value = "json")]
    format: String,
}
impl_run_with_client_methods!(
    ModerationRegistrySubmitReproArgs,
    Client::post_sorafs_moderation_model_registry_repro_manifest,
);
impl ModerationRegistrySubmitReproArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &[u8]) -> Result<Response<Vec<u8>>>,
    {
        let manifest_bytes =
            load_moderation_registry_repro_manifest_bytes(&self.manifest, self.format.as_str())?;
        let client = context.client_from_config()?;
        let response = submit(&client, &manifest_bytes)?;
        render_json_response_ok_or_accepted(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationRegistrySubmitCorpusArgs {
    /// Adversarial corpus manifest path.
    #[arg(long = "manifest", value_name = "PATH")]
    manifest: PathBuf,
    /// Input format: json or norito.
    #[arg(long = "format", default_value = "json")]
    format: String,
}
impl_run_with_client_methods!(
    ModerationRegistrySubmitCorpusArgs,
    Client::post_sorafs_moderation_model_registry_corpus,
);
impl ModerationRegistrySubmitCorpusArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &[u8]) -> Result<Response<Vec<u8>>>,
    {
        let manifest_bytes =
            load_moderation_registry_corpus_manifest_bytes(&self.manifest, self.format.as_str())?;
        let client = context.client_from_config()?;
        let response = submit(&client, &manifest_bytes)?;
        render_json_response_ok_or_accepted(context, response)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ModerationScreeningCommand {
    /// List local moderation screening records.
    List(ModerationScreeningListArgs),
    /// Submit one deterministic local screening result JSON file.
    Submit(ModerationScreeningSubmitArgs),
}
impl_run_for_subcommand!(ModerationScreeningCommand => List, Submit);
#[derive(clap::Args, Debug)]
pub struct ModerationScreeningListArgs {
    /// Maximum number of screening records to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    ModerationScreeningListArgs,
    Client::get_sorafs_moderation_screening_results,
);
impl_json_limit_run_with!(ModerationScreeningListArgs => SorafsModerationScreeningResultsFilter);
#[derive(clap::Args, Debug)]
pub struct ModerationScreeningSubmitArgs {
    /// JSON request containing canonical signed-result or committee authority.
    #[arg(long = "input", value_name = "PATH")]
    input: PathBuf,
}
impl_run_with_client_methods!(
    ModerationScreeningSubmitArgs,
    Client::post_sorafs_moderation_screening_result,
);
impl ModerationScreeningSubmitArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(
            &Client,
            &SorafsModerationScreeningResultRequest<'_>,
        ) -> Result<Response<Vec<u8>>>,
    {
        let payload = load_moderation_screening_submit_payload(&self.input)?;
        let request = payload.as_request();
        let client = context.client_from_config()?;
        let response = submit(&client, &request)?;
        render_json_response_ok_or_accepted(context, response)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModerationScreeningSubmitPayload {
    idempotency_key_hex: String,
    evidence_kind: String,
    authority_b64: String,
    committee_member_results_b64: Vec<String>,
}
impl ModerationScreeningSubmitPayload {
    fn as_request(&self) -> SorafsModerationScreeningResultRequest<'_> {
        SorafsModerationScreeningResultRequest {
            idempotency_key_hex: self.idempotency_key_hex.as_str(),
            evidence_kind: self.evidence_kind.as_str(),
            authority_b64: self.authority_b64.as_str(),
            committee_member_results_b64: self.committee_member_results_b64.as_slice(),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ModerationQuarantineCommand {
    /// List local moderation quarantine records.
    List(ModerationQuarantineListArgs),
    /// Store or read local encrypted quarantine payload objects.
    #[command(subcommand)]
    Object(ModerationQuarantineObjectCommand),
    /// Deliver payload-free juror notification manifests.
    #[command(subcommand)]
    Notifications(ModerationQuarantineNotificationsCommand),
    /// Mark a local moderation quarantine record reviewed.
    Review(ModerationQuarantineReviewArgs),
    /// Release a reviewed local moderation quarantine record.
    Release(ModerationQuarantineReleaseArgs),
    /// Build a reviewed quarantine appeal finance handoff.
    AppealHandoff(ModerationQuarantineAppealHandoffArgs),
    /// Read one role-gated local quarantine operator-panel workflow view.
    OperatorPanel(ModerationQuarantineOperatorPanelArgs),
    /// Build a payload-free bridge automation plan from the operator-panel view.
    BridgePlan(ModerationQuarantineBridgePlanArgs),
    /// Run a local payload-free operator-panel workflow service.
    OperatorServe(ModerationQuarantineOperatorServeArgs),
    /// Probe a deployed operator workflow service and emit payload-free evidence.
    OperatorCanary(ModerationQuarantineOperatorCanaryArgs),
}
impl_run_for_subcommand!(ModerationQuarantineCommand => List, Object, Notifications, Review, Release, AppealHandoff, OperatorPanel, BridgePlan, OperatorServe, OperatorCanary);
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineListArgs {
    /// Maximum number of quarantine records to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    ModerationQuarantineListArgs,
    Client::get_sorafs_moderation_quarantine,
);
impl_json_limit_run_with!(ModerationQuarantineListArgs => SorafsModerationQuarantineFilter);
#[derive(clap::Subcommand, Debug)]
pub enum ModerationQuarantineObjectCommand {
    /// Seal payload bytes into the local encrypted quarantine object store.
    Store(ModerationQuarantineObjectStoreArgs),
    /// Read and verify one local encrypted quarantine object.
    Read(ModerationQuarantineObjectReadArgs),
}
impl_run_for_subcommand!(ModerationQuarantineObjectCommand => Store, Read);
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineObjectStoreArgs {
    /// 16-byte local quarantine id encoded as hexadecimal.
    #[arg(long = "quarantine-id", value_name = "HEX")]
    quarantine_id: String,
    /// Path to the quarantined payload bytes to seal.
    #[arg(long = "payload-file", value_name = "PATH")]
    payload_file: PathBuf,
    /// Capture timestamp (RFC3339 or `@unix_seconds`; defaults to local now).
    #[arg(long = "captured-at", value_name = "RFC3339|@UNIX")]
    captured_at: Option<String>,
    /// Optional content type label recorded with the object.
    #[arg(long = "content-type", value_name = "TEXT")]
    content_type: Option<String>,
    /// Optional object-store notes recorded with the object.
    #[arg(long = "notes", value_name = "TEXT")]
    notes: Option<String>,
}
impl_run_with_client_methods!(
    ModerationQuarantineObjectStoreArgs,
    Client::post_sorafs_moderation_quarantine_object,
);
impl ModerationQuarantineObjectStoreArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(
            &Client,
            &str,
            &SorafsModerationQuarantineObjectStoreRequest<'_>,
        ) -> Result<Response<Vec<u8>>>,
    {
        let quarantine_id = normalize_hex_digest::<16>(&self.quarantine_id, "--quarantine-id")?;
        let payload = fs::read(&self.payload_file).wrap_err_with(|| {
            format!(
                "failed to read quarantine payload file `{}`",
                self.payload_file.display()
            )
        })?;
        if payload.is_empty() {
            return Err(eyre!(
                "--payload-file `{}` must not be empty",
                self.payload_file.display()
            ));
        }
        let captured_at_unix = parse_timestamp_or_now(self.captured_at.as_deref(), "captured-at")?;
        let content_type = optional_trimmed_text(self.content_type.as_deref(), "--content-type")?;
        let notes = optional_trimmed_text(self.notes.as_deref(), "--notes")?;
        let request = SorafsModerationQuarantineObjectStoreRequest {
            payload: &payload,
            captured_at_unix: Some(captured_at_unix),
            content_type: content_type.as_deref(),
            notes: notes.as_deref(),
        };
        let client = context.client_from_config()?;
        let response = submit(&client, &quarantine_id, &request)?;
        render_json_response_ok_or_accepted(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineObjectReadArgs {
    /// 16-byte local quarantine id encoded as hexadecimal.
    #[arg(long = "quarantine-id", value_name = "HEX")]
    quarantine_id: String,
}
impl_run_with_client_methods!(
    ModerationQuarantineObjectReadArgs,
    Client::get_sorafs_moderation_quarantine_object,
);
impl ModerationQuarantineObjectReadArgs {
    fn run_with<C, F>(&self, context: &mut C, read: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str) -> Result<Response<Vec<u8>>>,
    {
        let quarantine_id = normalize_hex_digest::<16>(&self.quarantine_id, "--quarantine-id")?;
        let client = context.client_from_config()?;
        let response = read(&client, &quarantine_id)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ModerationQuarantineNotificationsCommand {
    /// Deliver one payload-free juror notification manifest.
    Deliver(ModerationQuarantineNotificationsDeliverArgs),
    /// Probe a deployed juror notification transport and emit payload-free evidence.
    Canary(ModerationQuarantineNotificationsCanaryArgs),
}
impl_run_for_subcommand!(ModerationQuarantineNotificationsCommand => Deliver, Canary);
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineNotificationsDeliverArgs {
    /// Payload-free juror notification manifest JSON.
    #[arg(long = "manifest", value_name = "PATH")]
    manifest: PathBuf,
    /// Directory where canonical notification JSON files are written.
    #[arg(long = "out-dir", value_name = "DIR")]
    out_dir: Option<PathBuf>,
    /// Optional webhook endpoint that receives each notification JSON.
    #[arg(long = "webhook-url", value_name = "URL")]
    webhook_url: Option<String>,
    /// Webhook request timeout in seconds.
    #[arg(long = "timeout-secs", default_value_t = 10)]
    timeout_secs: u64,
}
impl Run for ModerationQuarantineNotificationsDeliverArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let timeout = Duration::from_secs(self.timeout_secs.max(1));
        let http_client = BlockingHttpClient::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .user_agent("iroha-cli sorafs-moderation-notifications")
            .build()
            .wrap_err("failed to build SoraFS moderation notification HTTP client")?;
        self.run_with(context, |url, body| {
            post_moderation_juror_notification_webhook(&http_client, url, body)
        })
    }
}
impl ModerationQuarantineNotificationsDeliverArgs {
    fn run_with<C, F>(&self, context: &mut C, mut post_webhook: F) -> Result<()>
    where
        C: RunContext,
        F: FnMut(&str, &[u8]) -> Result<Response<Vec<u8>>>,
    {
        if self.out_dir.is_none() && self.webhook_url.is_none() {
            return Err(eyre!(
                "at least one of --out-dir or --webhook-url is required"
            ));
        }
        let webhook_url = self
            .webhook_url
            .as_deref()
            .map(|url| required_trimmed_text(url, "--webhook-url"))
            .transpose()?;
        let manifest = load_moderation_juror_notifications_manifest(&self.manifest)?;
        let notifications = moderation_juror_notification_entries(&manifest)?;
        if notifications.is_empty() {
            return Err(eyre!(
                "juror notification manifest `{}` does not contain notifications to deliver",
                self.manifest.display()
            ));
        }
        if let Some(out_dir) = &self.out_dir {
            fs::create_dir_all(out_dir).wrap_err_with(|| {
                format!(
                    "failed to create juror notification outbox `{}`",
                    out_dir.display()
                )
            })?;
        }
        let mut deliveries = Vec::with_capacity(notifications.len());
        for notification in notifications {
            let canonical = norito::json::to_vec(notification.value)
                .wrap_err("failed to encode juror notification JSON")?;
            let mut outbox_path = Value::Null;
            if let Some(out_dir) = &self.out_dir {
                let path = out_dir.join(format!(
                    "{}.json",
                    safe_moderation_notification_filename(notification.delivery_id)
                ));
                fs::write(&path, &canonical).wrap_err_with(|| {
                    format!(
                        "failed to write juror notification outbox file `{}`",
                        path.display()
                    )
                })?;
                outbox_path = Value::from(path.to_string_lossy().into_owned());
            }
            let mut webhook_status = Value::Null;
            let mut webhook_response_bytes = Value::Null;
            let mut webhook_response_body_blake3 = Value::Null;
            if let Some(url) = webhook_url.as_deref() {
                let response = post_webhook(url, &canonical)?;
                let status = response.status();
                let body = response.into_body();
                if !status.is_success() {
                    return Err(make_http_error(status, &body));
                }
                webhook_status = Value::from(u64::from(status.as_u16()));
                webhook_response_bytes = Value::from(u64::try_from(body.len()).unwrap_or(u64::MAX));
                webhook_response_body_blake3 = Value::from(encode(blake3::hash(&body).as_bytes()));
            }
            deliveries.push(moderation_juror_notification_delivery_result_json(
                notification,
                canonical.len(),
                &canonical,
                outbox_path,
                webhook_status,
                webhook_response_bytes,
                webhook_response_body_blake3,
            ));
        }
        let mut output = Map::new();
        output.insert(
            "schema".into(),
            Value::from("sorafs.moderation.juror_notifications.delivery.v1"),
        );
        output.insert("source".into(), Value::from("juror-notifications"));
        output.insert("status".into(), Value::from("delivered"));
        output.insert(
            "manifest_path".into(),
            Value::from(self.manifest.to_string_lossy().into_owned()),
        );
        output.insert(
            "out_dir".into(),
            self.out_dir.as_ref().map_or(Value::Null, |path| {
                Value::from(path.to_string_lossy().into_owned())
            }),
        );
        output.insert(
            "webhook_url".into(),
            webhook_url.as_deref().map_or(Value::Null, Value::from),
        );
        output.insert(
            "delivery_count".into(),
            Value::from(deliveries.len() as u64),
        );
        output.insert("payload_bytes_included".into(), Value::Bool(false));
        output.insert("private_payloads_included".into(), Value::Bool(false));
        output.insert("deliveries".into(), Value::Array(deliveries));
        context.print_data(&Value::Object(output))
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineNotificationsCanaryArgs {
    /// Payload-free juror notification manifest JSON used as the canary probe.
    #[arg(long = "manifest", value_name = "PATH")]
    manifest: PathBuf,
    /// Deployed webhook endpoint to probe.
    #[arg(long = "webhook-url", value_name = "URL")]
    webhook_url: String,
    /// Optional path where payload-free canary evidence JSON is written.
    #[arg(long = "out", value_name = "PATH")]
    out: Option<PathBuf>,
    /// Webhook request timeout in seconds.
    #[arg(long = "timeout-secs", default_value_t = 10)]
    timeout_secs: u64,
}
impl Run for ModerationQuarantineNotificationsCanaryArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let timeout = Duration::from_secs(self.timeout_secs.max(1));
        let http_client = BlockingHttpClient::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .user_agent("iroha-cli sorafs-moderation-notification-canary")
            .build()
            .wrap_err("failed to build SoraFS moderation notification canary HTTP client")?;
        self.run_with(context, |url, body| {
            post_moderation_juror_notification_webhook(&http_client, url, body)
        })
    }
}
impl ModerationQuarantineNotificationsCanaryArgs {
    fn run_with<C, F>(&self, context: &mut C, mut post_webhook: F) -> Result<()>
    where
        C: RunContext,
        F: FnMut(&str, &[u8]) -> Result<Response<Vec<u8>>>,
    {
        let webhook_url = required_trimmed_text(&self.webhook_url, "--webhook-url")?;
        let manifest = load_moderation_juror_notifications_manifest(&self.manifest)?;
        let notifications = moderation_juror_notification_entries(&manifest)?;
        if notifications.is_empty() {
            return Err(eyre!(
                "juror notification canary manifest `{}` does not contain notifications to probe",
                self.manifest.display()
            ));
        }
        let mut probes = Vec::with_capacity(notifications.len());
        for notification in notifications {
            let canonical = norito::json::to_vec(notification.value)
                .wrap_err("failed to encode juror notification canary JSON")?;
            let response = post_webhook(&webhook_url, &canonical)?;
            probes.push(moderation_juror_notification_canary_probe_json(
                notification,
                &canonical,
                response,
            )?);
        }
        let status = if probes.iter().all(moderation_canary_probe_ok) {
            "passed"
        } else {
            "failed"
        };
        let mut evidence = Map::new();
        evidence.insert(
            "schema".into(),
            Value::from("sorafs.moderation.juror_notifications.transport_canary.v1"),
        );
        evidence.insert("source".into(), Value::from("juror-notifications"));
        evidence.insert("status".into(), Value::from(status));
        evidence.insert(
            "manifest_path".into(),
            Value::from(self.manifest.to_string_lossy().into_owned()),
        );
        evidence.insert(
            "manifest_body_blake3_hex".into(),
            Value::from(encode(
                blake3::hash(
                    &norito::json::to_vec(&manifest)
                        .wrap_err("failed to encode juror notification canary manifest")?,
                )
                .as_bytes(),
            )),
        );
        evidence.insert("webhook_url".into(), Value::from(webhook_url));
        evidence.insert("probe_count".into(), Value::from(probes.len() as u64));
        evidence.insert(
            "accepted_count".into(),
            Value::from(
                probes
                    .iter()
                    .filter(|probe| moderation_canary_probe_ok(probe))
                    .count() as u64,
            ),
        );
        evidence.insert("payload_bytes_included".into(), Value::Bool(false));
        evidence.insert("private_payloads_included".into(), Value::Bool(false));
        evidence.insert("probes".into(), Value::Array(probes));
        let evidence = Value::Object(evidence);
        if let Some(path) = &self.out {
            write_json_artifact(path, &evidence, "juror notification canary evidence")?;
        }
        context.print_data(&evidence)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineReviewArgs {
    /// 16-byte local quarantine id encoded as hexadecimal.
    #[arg(long = "quarantine-id", value_name = "HEX")]
    quarantine_id: String,
    /// Operator identity recorded in the checkpoint (defaults to the CLI account).
    #[arg(long = "reviewed-by", value_name = "TEXT")]
    reviewed_by: Option<String>,
    /// Review timestamp (RFC3339 or `@unix_seconds`; defaults to local now).
    #[arg(long = "reviewed-at", value_name = "RFC3339|@UNIX")]
    reviewed_at: Option<String>,
    /// Optional review notes recorded with the transition.
    #[arg(long = "notes", value_name = "TEXT")]
    notes: Option<String>,
}
impl_run_with_client_methods!(
    ModerationQuarantineReviewArgs,
    Client::post_sorafs_moderation_quarantine_review,
);
impl ModerationQuarantineReviewArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(
            &Client,
            &str,
            &SorafsModerationQuarantineReviewRequest<'_>,
        ) -> Result<Response<Vec<u8>>>,
    {
        let quarantine_id = normalize_hex_digest::<16>(&self.quarantine_id, "--quarantine-id")?;
        let reviewed_by =
            moderation_actor_or_default(context, self.reviewed_by.as_deref(), "--reviewed-by")?;
        let notes = optional_trimmed_text(self.notes.as_deref(), "--notes")?;
        let reviewed_at_unix = parse_timestamp_or_now(self.reviewed_at.as_deref(), "reviewed-at")?;
        let request = SorafsModerationQuarantineReviewRequest {
            reviewed_by: reviewed_by.as_str(),
            reviewed_at_unix: Some(reviewed_at_unix),
            notes: notes.as_deref(),
        };
        let client = context.client_from_config()?;
        let response = submit(&client, &quarantine_id, &request)?;
        render_json_response_ok_or_accepted(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineReleaseArgs {
    /// 16-byte local quarantine id encoded as hexadecimal.
    #[arg(long = "quarantine-id", value_name = "HEX")]
    quarantine_id: String,
    /// Release authority recorded in the checkpoint (defaults to the CLI account).
    #[arg(long = "release-authority", value_name = "TEXT")]
    release_authority: Option<String>,
    /// Release timestamp (RFC3339 or `@unix_seconds`; defaults to local now).
    #[arg(long = "released-at", value_name = "RFC3339|@UNIX")]
    released_at: Option<String>,
    /// Optional release notes recorded with the transition.
    #[arg(long = "notes", value_name = "TEXT")]
    notes: Option<String>,
}
impl_run_with_client_methods!(
    ModerationQuarantineReleaseArgs,
    Client::post_sorafs_moderation_quarantine_release,
);
impl ModerationQuarantineReleaseArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(
            &Client,
            &str,
            &SorafsModerationQuarantineReleaseRequest<'_>,
        ) -> Result<Response<Vec<u8>>>,
    {
        let quarantine_id = normalize_hex_digest::<16>(&self.quarantine_id, "--quarantine-id")?;
        let release_authority = moderation_actor_or_default(
            context,
            self.release_authority.as_deref(),
            "--release-authority",
        )?;
        let notes = optional_trimmed_text(self.notes.as_deref(), "--notes")?;
        let released_at_unix = parse_timestamp_or_now(self.released_at.as_deref(), "released-at")?;
        let request = SorafsModerationQuarantineReleaseRequest {
            release_authority: release_authority.as_str(),
            released_at_unix: Some(released_at_unix),
            notes: notes.as_deref(),
        };
        let client = context.client_from_config()?;
        let response = submit(&client, &quarantine_id, &request)?;
        render_json_response_ok_or_accepted(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineAppealHandoffArgs {
    /// 16-byte local quarantine id encoded as hexadecimal.
    #[arg(long = "quarantine-id", value_name = "HEX")]
    quarantine_id: String,
    /// JSON appeal handoff request payload path.
    #[arg(long = "input", value_name = "PATH")]
    input: PathBuf,
}
impl_run_with_client_methods!(
    ModerationQuarantineAppealHandoffArgs,
    Client::post_sorafs_moderation_quarantine_appeal_handoff_json,
);
impl ModerationQuarantineAppealHandoffArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str, &[u8]) -> Result<Response<Vec<u8>>>,
    {
        let quarantine_id = normalize_hex_digest::<16>(&self.quarantine_id, "--quarantine-id")?;
        let payload =
            load_sorafs_json_payload(&self.input, "moderation quarantine appeal handoff")?;
        let client = context.client_from_config()?;
        let response = submit(&client, &quarantine_id, &payload)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineOperatorPanelArgs {
    /// 16-byte local quarantine id encoded as hexadecimal.
    #[arg(long = "quarantine-id", value_name = "HEX")]
    quarantine_id: String,
    /// Maximum number of matching ballots to return.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    ModerationQuarantineOperatorPanelArgs,
    Client::get_sorafs_moderation_quarantine_operator_panel,
);
impl ModerationQuarantineOperatorPanelArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str, SorafsModerationQuarantineFilter) -> Result<Response<Vec<u8>>>,
    {
        let quarantine_id = normalize_hex_digest::<16>(&self.quarantine_id, "--quarantine-id")?;
        let filter = SorafsModerationQuarantineFilter { limit: self.limit };
        let client = context.client_from_config()?;
        let response = get(&client, &quarantine_id, filter)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineBridgePlanArgs {
    /// 16-byte local quarantine id encoded as hexadecimal.
    #[arg(long = "quarantine-id", value_name = "HEX")]
    quarantine_id: String,
    /// Maximum number of matching ballots to inspect.
    #[arg(long)]
    limit: Option<u32>,
}
impl_run_with_client_methods!(
    ModerationQuarantineBridgePlanArgs,
    Client::get_sorafs_moderation_quarantine_operator_panel,
);
const MODERATION_OPERATOR_SERVICE_DEFAULT_LISTEN: &str = "127.0.0.1:9201";
const MODERATION_OPERATOR_SERVICE_DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const MODERATION_OPERATOR_CSRF_HEADER: &str = "X-SoraFS-Operator-CSRF";
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineOperatorServeArgs {
    /// Local host:port for the operator workflow service.
    #[arg(long, default_value = MODERATION_OPERATOR_SERVICE_DEFAULT_LISTEN)]
    listen: String,
    /// Default ballot limit for operator-panel and bridge-plan reads.
    #[arg(long)]
    limit: Option<u32>,
    /// Maximum accepted HTTP request body bytes.
    #[arg(long, default_value_t = MODERATION_OPERATOR_SERVICE_DEFAULT_MAX_BODY_BYTES)]
    max_body_bytes: usize,
}
#[derive(clap::Args, Debug)]
pub struct ModerationQuarantineOperatorCanaryArgs {
    /// Base URL of the deployed operator workflow service.
    #[arg(long = "operator-url", value_name = "URL")]
    operator_url: String,
    /// 16-byte local quarantine id encoded as hexadecimal.
    #[arg(long = "quarantine-id", value_name = "HEX")]
    quarantine_id: String,
    /// Maximum number of matching ballots to request from readback routes.
    #[arg(long)]
    limit: Option<u32>,
    /// HTTP timeout in seconds.
    #[arg(long = "timeout-secs", default_value_t = 30)]
    timeout_secs: u64,
    /// Optional path where the canary evidence JSON will be written.
    #[arg(long = "out", value_name = "PATH")]
    out: Option<PathBuf>,
}
impl Run for ModerationQuarantineOperatorServeArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = context.client_from_config()?;
        let service = self.service(
            Arc::new(client),
            context.config().torii_api_url.as_str().to_string(),
            context.config().account.to_string(),
        )?;
        let listener = TcpListener::bind(&service.listen).wrap_err_with(|| {
            format!(
                "failed to bind SoraFS moderation operator service to `{}`",
                service.listen
            )
        })?;
        context.print_data(&service.status_json())?;
        let service = Arc::new(service);
        for stream in listener.incoming() {
            let service = Arc::clone(&service);
            match stream {
                Ok(stream) => {
                    thread::spawn(move || {
                        if let Err(err) = moderation_operator_handle_stream(stream, &service) {
                            eprintln!("SoraFS moderation operator service request failed: {err}");
                        }
                    });
                }
                Err(err) => {
                    return Err(eyre!(
                        "failed to accept SoraFS moderation operator service connection: {err}"
                    ));
                }
            }
        }
        Ok(())
    }
}
impl Run for ModerationQuarantineOperatorCanaryArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let timeout = Duration::from_secs(self.timeout_secs.max(1));
        let client = BlockingHttpClient::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .user_agent("sorafs-cli moderation-operator-canary")
            .build()
            .wrap_err("failed to construct SoraFS moderation operator canary HTTP client")?;
        self.run_with_fetch(context, |url| {
            moderation_operator_canary_http_get(&client, url)
        })
    }
}
impl ModerationQuarantineOperatorCanaryArgs {
    fn run_with_fetch<C, F>(&self, context: &mut C, mut fetch: F) -> Result<()>
    where
        C: RunContext,
        F: FnMut(&str) -> Result<ModerationOperatorCanaryHttpResponse>,
    {
        let operator_url = required_trimmed_text(&self.operator_url, "--operator-url")?;
        let quarantine_id = normalize_hex_digest::<16>(&self.quarantine_id, "--quarantine-id")?;
        let evidence = moderation_operator_canary_evidence_json(
            &operator_url,
            &quarantine_id,
            self.limit,
            &mut fetch,
        )?;
        if let Some(path) = &self.out {
            ensure_parent_dir(path)?;
            let bytes = norito::json::to_vec_pretty(&evidence)
                .wrap_err("failed to serialize SoraFS moderation operator canary evidence")?;
            fs::write(path, bytes).wrap_err_with(|| {
                format!(
                    "failed to write SoraFS moderation operator canary evidence to `{}`",
                    path.display()
                )
            })?;
        }
        context.print_data(&evidence)
    }
}
impl ModerationQuarantineOperatorServeArgs {
    fn service(
        &self,
        workflow_source: Arc<dyn ModerationOperatorWorkflowSource>,
        upstream: String,
        default_actor: String,
    ) -> Result<ModerationOperatorService> {
        if self.listen.trim().is_empty() {
            return Err(eyre!("--listen must not be empty"));
        }
        if self.max_body_bytes == 0 {
            return Err(eyre!("--max-body-bytes must be greater than zero"));
        }
        let csrf_token = generate_moderation_operator_csrf_token()?;
        Ok(ModerationOperatorService {
            listen: self.listen.trim().to_string(),
            default_limit: self.limit,
            max_body_bytes: self.max_body_bytes,
            upstream,
            default_actor,
            csrf_token,
            workflow_source,
        })
    }
}
impl ModerationQuarantineBridgePlanArgs {
    fn run_with<C, F>(&self, context: &mut C, get: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str, SorafsModerationQuarantineFilter) -> Result<Response<Vec<u8>>>,
    {
        let quarantine_id = normalize_hex_digest::<16>(&self.quarantine_id, "--quarantine-id")?;
        let filter = SorafsModerationQuarantineFilter { limit: self.limit };
        let client = context.client_from_config()?;
        let response = get(&client, &quarantine_id, filter)?;
        render_moderation_quarantine_bridge_plan_response(context, response, &quarantine_id)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum RepairCommand {
    /// List finalized chain-authoritative repair tasks.
    List(RepairListArgs),
    /// Claim a queued repair task with a native ledger action.
    Claim(RepairClaimArgs),
    /// Renew the current repair lease with a native ledger action.
    Renew(RepairRenewArgs),
    /// Commit a successful terminal repair outcome.
    Complete(RepairCompleteArgs),
    /// Commit an unsuccessful terminal repair outcome.
    Fail(RepairFailArgs),
    /// Atomically escalate a repair task into a terminal slash proposal.
    Escalate(RepairEscalateArgs),
}
impl_run_for_subcommand!(RepairCommand => List, Claim, Renew, Complete, Fail, Escalate);
#[derive(clap::Args, Debug)]
pub struct RepairListArgs {
    /// Fetch one canonical repair ticket instead of a page.
    #[arg(long = "ticket-id", value_name = "ID")]
    ticket_id: Option<String>,
    /// Bounded task page size (1 through 500).
    #[arg(long, value_name = "COUNT")]
    limit: Option<u32>,
    /// Optional finalized block height; requires `--expected-finalized-block-hash`.
    #[arg(long = "expected-finalized-height", value_name = "HEIGHT")]
    expected_finalized_height: Option<u64>,
    /// Optional finalized block hash; requires `--expected-finalized-height`.
    #[arg(long = "expected-finalized-block-hash", value_name = "HEX")]
    expected_finalized_block_hash: Option<String>,
    /// Optional exclusive immutable task-id cursor.
    #[arg(long = "after-task-id", value_name = "HEX")]
    after_task_id: Option<String>,
}
impl_run_with_client_methods!(
    RepairListArgs,
    Client::get_sorafs_repair_tasks,
    Client::get_sorafs_repair_task,
);
impl RepairListArgs {
    fn run_with<C, F, G>(&self, context: &mut C, list: F, get: G) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SorafsRepairTasksFilter<'_>) -> Result<Response<Vec<u8>>>,
        G: FnOnce(&Client, &str, &SorafsRepairFinalizedAnchor<'_>) -> Result<Response<Vec<u8>>>,
    {
        if self.limit.is_some_and(|limit| !(1..=500).contains(&limit)) {
            return Err(eyre!("--limit must be within 1..=500"));
        }
        if self.expected_finalized_height.is_some() != self.expected_finalized_block_hash.is_some()
        {
            return Err(eyre!(
                "--expected-finalized-height and --expected-finalized-block-hash must be supplied together"
            ));
        }
        if self.expected_finalized_height == Some(0) {
            return Err(eyre!("--expected-finalized-height must be non-zero"));
        }
        let finalized_block_hash = self
            .expected_finalized_block_hash
            .as_deref()
            .map(|hex| normalize_hex_digest::<32>(hex, "--expected-finalized-block-hash"))
            .transpose()?;
        let after_task_id = self
            .after_task_id
            .as_deref()
            .map(|hex| normalize_hex_digest::<32>(hex, "--after-task-id"))
            .transpose()?;
        let finalized = SorafsRepairFinalizedAnchor {
            expected_finalized_height: self.expected_finalized_height,
            expected_finalized_block_hash_hex: finalized_block_hash.as_deref(),
        };
        let client = context.client_from_config()?;
        let response = match self.ticket_id.as_deref() {
            Some(ticket_id) => {
                if self.limit.is_some() || after_task_id.is_some() {
                    return Err(eyre!(
                        "--limit and --after-task-id cannot be combined with --ticket-id"
                    ));
                }
                let ticket_id = parse_repair_ticket_id(ticket_id, "--ticket-id")?;
                get(&client, &ticket_id.0, &finalized)?
            }
            None => {
                let filter = SorafsRepairTasksFilter {
                    finalized,
                    limit: self.limit,
                    after_task_id_hex: after_task_id.as_deref(),
                };
                list(&client, &filter)?
            }
        };
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct RepairClaimArgs {
    /// Repair ticket identifier (e.g., `REP-401`).
    #[arg(long = "ticket-id", value_name = "ID")]
    ticket_id: String,
    /// Exact task revision observed before claiming.
    #[arg(long = "expected-revision", value_name = "REVISION")]
    expected_revision: u64,
    /// Requested lease duration measured from the committing block time.
    #[arg(long = "lease-duration-ms", default_value_t = 60_000)]
    lease_duration_ms: u64,
    /// Optional idempotency key (auto-generated when omitted).
    #[arg(long = "idempotency-key", value_name = "KEY")]
    idempotency_key: Option<String>,
}
impl_run_with_client_methods!(RepairClaimArgs, Client::post_sorafs_repair_claim);
impl RepairClaimArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
    {
        ensure_optional_non_empty(self.idempotency_key.as_deref(), "idempotency-key")?;
        let ticket_id = parse_repair_ticket_id(&self.ticket_id, "--ticket-id")?;
        validate_repair_revision(self.expected_revision, "--expected-revision")?;
        if self.lease_duration_ms == 0 {
            return Err(eyre!("--lease-duration-ms must be non-zero"));
        }
        let idempotency_key = match self.idempotency_key.clone() {
            Some(idempotency_key) => idempotency_key,
            None => generate_nonce_hex(12)?,
        };
        let action = SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
            lease_duration_ms: self.lease_duration_ms,
            idempotency_key,
        });
        let client = context.client_from_config()?;
        let transaction =
            build_repair_action_transaction(&client, &ticket_id, self.expected_revision, action)?;
        let hash = submit(&client, &transaction)?;
        render_repair_transaction_hash(context, &hash)
    }
}
#[derive(clap::Args, Debug)]
pub struct RepairRenewArgs {
    /// Repair ticket identifier (e.g., `REP-401`).
    #[arg(long = "ticket-id", value_name = "ID")]
    ticket_id: String,
    /// Exact task revision observed before renewing.
    #[arg(long = "expected-revision", value_name = "REVISION")]
    expected_revision: u64,
    /// Exact current lease generation.
    #[arg(long = "lease-generation", value_name = "GENERATION")]
    lease_generation: u64,
    /// Requested lease duration measured from the committing block time.
    #[arg(long = "lease-duration-ms", default_value_t = 60_000)]
    lease_duration_ms: u64,
    /// Optional idempotency key (auto-generated when omitted).
    #[arg(long = "idempotency-key", value_name = "KEY")]
    idempotency_key: Option<String>,
}
impl_run_with_client_methods!(RepairRenewArgs, Client::post_sorafs_repair_heartbeat);
impl RepairRenewArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
    {
        ensure_optional_non_empty(self.idempotency_key.as_deref(), "idempotency-key")?;
        let ticket_id = parse_repair_ticket_id(&self.ticket_id, "--ticket-id")?;
        validate_repair_revision(self.expected_revision, "--expected-revision")?;
        validate_repair_revision(self.lease_generation, "--lease-generation")?;
        if self.lease_duration_ms == 0 {
            return Err(eyre!("--lease-duration-ms must be non-zero"));
        }
        let idempotency_key = match self.idempotency_key.clone() {
            Some(idempotency_key) => idempotency_key,
            None => generate_nonce_hex(12)?,
        };
        let action = SorafsRepairTaskActionV1::Renew(SorafsRepairRenewV1 {
            lease_generation: self.lease_generation,
            lease_duration_ms: self.lease_duration_ms,
            idempotency_key,
        });
        let client = context.client_from_config()?;
        let transaction =
            build_repair_action_transaction(&client, &ticket_id, self.expected_revision, action)?;
        let hash = submit(&client, &transaction)?;
        render_repair_transaction_hash(context, &hash)
    }
}
#[derive(clap::Args, Debug)]
pub struct RepairCompleteArgs {
    /// Repair ticket identifier (e.g., `REP-401`).
    #[arg(long = "ticket-id", value_name = "ID")]
    ticket_id: String,
    /// Exact task revision observed before completion.
    #[arg(long = "expected-revision", value_name = "REVISION")]
    expected_revision: u64,
    /// Exact current lease generation.
    #[arg(long = "lease-generation", value_name = "GENERATION")]
    lease_generation: u64,
    /// Digest of external completion evidence.
    #[arg(long = "evidence-digest", value_name = "HEX")]
    evidence_digest: String,
    /// Optional idempotency key (auto-generated when omitted).
    #[arg(long = "idempotency-key", value_name = "KEY")]
    idempotency_key: Option<String>,
}
impl_run_with_client_methods!(RepairCompleteArgs, Client::post_sorafs_repair_complete);
impl RepairCompleteArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
    {
        ensure_optional_non_empty(self.idempotency_key.as_deref(), "idempotency-key")?;
        let ticket_id = parse_repair_ticket_id(&self.ticket_id, "--ticket-id")?;
        validate_repair_revision(self.expected_revision, "--expected-revision")?;
        validate_repair_revision(self.lease_generation, "--lease-generation")?;
        let evidence_digest = parse_hex_array::<32>(&self.evidence_digest, "--evidence-digest")?;
        let idempotency_key = match self.idempotency_key.clone() {
            Some(idempotency_key) => idempotency_key,
            None => generate_nonce_hex(12)?,
        };
        let action = SorafsRepairTaskActionV1::Complete(SorafsRepairCompleteV1 {
            lease_generation: self.lease_generation,
            evidence_digest,
            idempotency_key,
        });
        let client = context.client_from_config()?;
        let transaction =
            build_repair_action_transaction(&client, &ticket_id, self.expected_revision, action)?;
        let hash = submit(&client, &transaction)?;
        render_repair_transaction_hash(context, &hash)
    }
}
#[derive(clap::Args, Debug)]
pub struct RepairFailArgs {
    /// Repair ticket identifier (e.g., `REP-401`).
    #[arg(long = "ticket-id", value_name = "ID")]
    ticket_id: String,
    /// Exact task revision observed before failure.
    #[arg(long = "expected-revision", value_name = "REVISION")]
    expected_revision: u64,
    /// Exact current lease generation.
    #[arg(long = "lease-generation", value_name = "GENERATION")]
    lease_generation: u64,
    /// Digest of the external failure reason or evidence.
    #[arg(long = "failure-digest", value_name = "HEX")]
    failure_digest: String,
    /// Optional idempotency key (auto-generated when omitted).
    #[arg(long = "idempotency-key", value_name = "KEY")]
    idempotency_key: Option<String>,
}
impl_run_with_client_methods!(RepairFailArgs, Client::post_sorafs_repair_fail);
impl RepairFailArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
    {
        ensure_optional_non_empty(self.idempotency_key.as_deref(), "idempotency-key")?;
        let ticket_id = parse_repair_ticket_id(&self.ticket_id, "--ticket-id")?;
        validate_repair_revision(self.expected_revision, "--expected-revision")?;
        validate_repair_revision(self.lease_generation, "--lease-generation")?;
        let failure_digest = parse_hex_array::<32>(&self.failure_digest, "--failure-digest")?;
        let idempotency_key = match self.idempotency_key.clone() {
            Some(idempotency_key) => idempotency_key,
            None => generate_nonce_hex(12)?,
        };
        let action = SorafsRepairTaskActionV1::Fail(SorafsRepairFailV1 {
            lease_generation: self.lease_generation,
            failure_digest,
            idempotency_key,
        });
        let client = context.client_from_config()?;
        let transaction =
            build_repair_action_transaction(&client, &ticket_id, self.expected_revision, action)?;
        let hash = submit(&client, &transaction)?;
        render_repair_transaction_hash(context, &hash)
    }
}
#[derive(clap::Args, Debug)]
pub struct RepairEscalateArgs {
    /// Repair ticket identifier (e.g., `REP-401`).
    #[arg(long = "ticket-id", value_name = "ID")]
    ticket_id: String,
    /// Exact task revision observed before escalation.
    #[arg(long = "expected-revision", value_name = "REVISION")]
    expected_revision: u64,
    /// Exact current lease generation.
    #[arg(long = "lease-generation", value_name = "GENERATION")]
    lease_generation: u64,
    /// Manifest digest bound to the ticket (hex-encoded).
    #[arg(long = "manifest-digest", value_name = "HEX")]
    manifest_digest: String,
    /// Provider identifier owning the ticket (hex-encoded).
    #[arg(long = "provider-id", value_name = "HEX")]
    provider_id: String,
    /// Proposed exact XOR-denominated penalty.
    #[arg(long = "penalty", value_name = "QUANTITY")]
    penalty: String,
    /// Escalation rationale for governance review.
    #[arg(long = "rationale", value_name = "TEXT")]
    rationale: String,
    /// Optional auditor account (defaults to the CLI account).
    #[arg(long = "auditor", value_name = "ACCOUNT_ID")]
    auditor: Option<String>,
    /// Optional timestamp for the proposal (RFC3339 or `@unix_seconds`).
    #[arg(long = "submitted-at", value_name = "RFC3339|@UNIX")]
    submitted_at: Option<String>,
    /// Optional idempotency key (auto-generated when omitted).
    #[arg(long = "idempotency-key", value_name = "KEY")]
    idempotency_key: Option<String>,
}
impl_run_with_client_methods!(RepairEscalateArgs, Client::post_sorafs_repair_slash);
impl RepairEscalateArgs {
    fn run_with<C, F>(&self, context: &mut C, submit: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SignedTransaction) -> Result<HashOf<SignedTransaction>>,
    {
        ensure_optional_non_empty(self.idempotency_key.as_deref(), "idempotency-key")?;
        if self.rationale.trim().is_empty() {
            return Err(eyre!("--rationale must not be empty"));
        }
        let ticket_id = parse_repair_ticket_id(&self.ticket_id, "--ticket-id")?;
        validate_repair_revision(self.expected_revision, "--expected-revision")?;
        validate_repair_revision(self.lease_generation, "--lease-generation")?;
        let manifest_digest = parse_hex_array::<32>(&self.manifest_digest, "--manifest-digest")?;
        let provider_id = parse_hex_array::<32>(&self.provider_id, "--provider-id")?;
        let auditor_account = match self.auditor.as_deref() {
            Some(raw) => parse_account_id_str(context, raw, "--auditor")?.to_string(),
            None => context.config().account.to_string(),
        };
        let submitted_at_unix =
            parse_timestamp_or_now(self.submitted_at.as_deref(), "submitted-at")?;
        let proposed_penalty = parse_xor_quantity_labeled(&self.penalty, "--penalty")?;
        let proposal = RepairSlashProposalV1 {
            version: REPAIR_SLASH_PROPOSAL_VERSION_V1,
            ticket_id: ticket_id.clone(),
            provider_id,
            manifest_digest,
            auditor_account,
            proposed_penalty,
            submitted_at_unix,
            rationale: self.rationale.clone(),
            // Approval summaries embedded by the proposal submitter are not an
            // authority source. Governance decisions derive only from
            // authenticated records committed to the native repair ledger.
            approval: None,
        };
        proposal
            .validate()
            .map_err(|err| eyre!("invalid repair slash proposal payload: {err}"))?;
        let idempotency_key = match self.idempotency_key.clone() {
            Some(idempotency_key) => idempotency_key,
            None => generate_nonce_hex(12)?,
        };
        let action = SorafsRepairTaskActionV1::Escalate(SorafsRepairEscalateV1 {
            lease_generation: self.lease_generation,
            slash_proposal_payload: norito::to_bytes(&proposal)
                .wrap_err("failed to encode canonical repair slash proposal")?,
            idempotency_key,
        });
        let client = context.client_from_config()?;
        let transaction =
            build_repair_action_transaction(&client, &ticket_id, self.expected_revision, action)?;
        let hash = submit(&client, &transaction)?;
        render_repair_transaction_hash(context, &hash)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum GcCommand {
    /// Inspect retained manifests and retention deadlines.
    Inspect(GcInspectArgs),
    /// Report which manifests would be evicted by GC (dry-run only).
    DryRun(GcDryRunArgs),
}
impl_run_for_subcommand!(GcCommand => Inspect, DryRun);
#[derive(clap::Args, Debug)]
pub struct GcInspectArgs {
    /// Root directory for SoraFS storage data (defaults to the node config default).
    #[arg(long = "data-dir", value_name = "PATH")]
    data_dir: Option<PathBuf>,
    /// Override the reference timestamp (RFC3339 or `@unix_seconds`).
    #[arg(long = "now", value_name = "RFC3339|@UNIX")]
    now: Option<String>,
    /// Override the retention grace window in seconds.
    #[arg(long = "grace-secs", value_name = "SECONDS")]
    grace_secs: Option<u64>,
}
impl Run for GcInspectArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let report = build_gc_report(
            "inspect",
            self.data_dir.as_deref(),
            self.now.as_deref(),
            self.grace_secs,
            false,
        )?;
        context.print_data(&report)
    }
}
#[derive(clap::Args, Debug)]
pub struct GcDryRunArgs {
    /// Root directory for SoraFS storage data (defaults to the node config default).
    #[arg(long = "data-dir", value_name = "PATH")]
    data_dir: Option<PathBuf>,
    /// Override the reference timestamp (RFC3339 or `@unix_seconds`).
    #[arg(long = "now", value_name = "RFC3339|@UNIX")]
    now: Option<String>,
    /// Override the retention grace window in seconds.
    #[arg(long = "grace-secs", value_name = "SECONDS")]
    grace_secs: Option<u64>,
}
impl Run for GcDryRunArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let report = build_gc_report(
            "dry_run",
            self.data_dir.as_deref(),
            self.now.as_deref(),
            self.grace_secs,
            true,
        )?;
        context.print_data(&report)
    }
}
#[derive(Debug)]
struct GcManifestEntry {
    manifest_id: String,
    manifest_digest_hex: String,
    storage_class: ManifestStorageClass,
    retention_epoch: u64,
    retention_sources: Vec<String>,
    payload_bytes: u64,
    car_bytes: u64,
}
#[derive(Debug, norito::json::JsonSerialize)]
struct GcReportOutput {
    mode: String,
    data_dir: String,
    now_unix: u64,
    grace_secs: u64,
    total_manifests: usize,
    total_payload_bytes: u64,
    total_car_bytes: u64,
    expired_count: usize,
    expired_payload_bytes: u64,
    expired_car_bytes: u64,
    entries: Vec<GcReportEntry>,
}
#[derive(Debug, norito::json::JsonSerialize)]
struct GcReportEntry {
    manifest_id: String,
    manifest_digest_hex: String,
    storage_class: String,
    retention_epoch: u64,
    retention_sources: Vec<String>,
    expires_at_unix: Option<u64>,
    expired: bool,
    payload_bytes: u64,
    car_bytes: u64,
}
const SORAFS_MANIFEST_DIR: &str = "manifests";
const SORAFS_MANIFEST_FILE: &str = "manifest.to";
fn build_gc_report(
    mode: &str,
    data_dir: Option<&Path>,
    now: Option<&str>,
    grace_secs: Option<u64>,
    only_expired: bool,
) -> Result<GcReportOutput> {
    let data_dir = data_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(defaults::sorafs::storage::data_dir);
    let now_unix = parse_timestamp_or_now(now, "now")?;
    let grace_secs = grace_secs.unwrap_or(defaults::sorafs::gc::RETENTION_GRACE_SECS);
    let mut entries = load_gc_manifest_entries(&data_dir)?;
    entries.sort_by(|left, right| left.manifest_id.cmp(&right.manifest_id));
    let total_manifests = entries.len();
    let mut report_entries = Vec::with_capacity(entries.len());
    let mut total_payload_bytes = 0_u64;
    let mut total_car_bytes = 0_u64;
    let mut expired_count = 0_usize;
    let mut expired_payload_bytes = 0_u64;
    let mut expired_car_bytes = 0_u64;
    for entry in entries {
        total_payload_bytes = total_payload_bytes.saturating_add(entry.payload_bytes);
        total_car_bytes = total_car_bytes.saturating_add(entry.car_bytes);
        let expires_at_unix = retention_deadline(entry.retention_epoch, grace_secs);
        let expired = expires_at_unix.is_some_and(|deadline| now_unix >= deadline);
        if expired {
            expired_count += 1;
            expired_payload_bytes = expired_payload_bytes.saturating_add(entry.payload_bytes);
            expired_car_bytes = expired_car_bytes.saturating_add(entry.car_bytes);
        }
        if only_expired && !expired {
            continue;
        }
        report_entries.push(GcReportEntry {
            manifest_id: entry.manifest_id,
            manifest_digest_hex: entry.manifest_digest_hex,
            storage_class: manifest_storage_class_label(entry.storage_class).to_string(),
            retention_epoch: entry.retention_epoch,
            retention_sources: entry.retention_sources,
            expires_at_unix,
            expired,
            payload_bytes: entry.payload_bytes,
            car_bytes: entry.car_bytes,
        });
    }
    Ok(GcReportOutput {
        mode: mode.to_string(),
        data_dir: data_dir.display().to_string(),
        now_unix,
        grace_secs,
        total_manifests,
        total_payload_bytes,
        total_car_bytes,
        expired_count,
        expired_payload_bytes,
        expired_car_bytes,
        entries: report_entries,
    })
}
fn load_gc_manifest_entries(data_dir: &Path) -> Result<Vec<GcManifestEntry>> {
    let manifests_dir = data_dir.join(SORAFS_MANIFEST_DIR);
    if !manifests_dir.exists() {
        return Err(eyre!(
            "SoraFS manifests directory `{}` does not exist",
            manifests_dir.display()
        ));
    }
    let mut entries = Vec::new();
    for dir_entry in fs::read_dir(&manifests_dir)
        .wrap_err_with(|| format!("failed to read `{}`", manifests_dir.display()))?
    {
        let dir_entry = dir_entry?;
        let file_type = dir_entry.file_type()?;
        if !file_type.is_dir() {
            continue;
        }
        let manifest_id = dir_entry.file_name().to_string_lossy().to_string();
        let manifest_path = dir_entry.path().join(SORAFS_MANIFEST_FILE);
        let manifest_bytes = fs::read(&manifest_path)
            .wrap_err_with(|| format!("failed to read manifest `{}`", manifest_path.display()))?;
        let manifest: ManifestV1 = norito::decode_from_bytes(&manifest_bytes)
            .wrap_err_with(|| format!("failed to decode `{}`", manifest_path.display()))?;
        let digest = manifest
            .digest()
            .wrap_err_with(|| format!("failed to hash `{}`", manifest_path.display()))?;
        let retention_source = sorafs_manifest::retention::RetentionSourceV1::from_manifest(
            &manifest,
        )
        .wrap_err_with(|| {
            format!(
                "failed to parse retention metadata for `{}`",
                manifest_path.display()
            )
        })?;
        let retention_sources = retention_source
            .sources
            .iter()
            .map(|source| source.to_string())
            .collect::<Vec<_>>();
        entries.push(GcManifestEntry {
            manifest_id,
            manifest_digest_hex: encode(digest.as_bytes()),
            storage_class: manifest.pin_policy.storage_class,
            retention_epoch: retention_source.effective_epoch(),
            retention_sources,
            payload_bytes: manifest.content_length,
            car_bytes: manifest.car_size,
        });
    }
    Ok(entries)
}
fn retention_deadline(retention_epoch: u64, grace_secs: u64) -> Option<u64> {
    if retention_epoch == 0 {
        return None;
    }
    Some(retention_epoch.saturating_add(grace_secs))
}
const fn manifest_storage_class_label(class: ManifestStorageClass) -> &'static str {
    match class {
        ManifestStorageClass::Hot => "hot",
        ManifestStorageClass::Warm => "warm",
        ManifestStorageClass::Cold => "cold",
    }
}
#[derive(clap::Args, Debug)]
pub struct ReserveQuoteArgs {
    /// Storage class targeted by the commitment (hot, warm, cold).
    #[arg(long = "storage-class", value_enum)]
    storage_class: StorageClassArg,
    /// Provider tier (tier-a, tier-b, tier-c).
    #[arg(long = "tier", value_enum)]
    tier: ReserveTierArg,
    /// Commitment duration (`monthly`, `quarterly`, `annual`).
    #[arg(long = "duration", value_enum, default_value = "monthly")]
    duration: ReserveDurationArg,
    /// Logical GiB covered by the quote.
    #[arg(long = "gib", value_name = "GIB")]
    pub capacity_gib: u64,
    /// Canonical XOR reserve balance applied while computing effective rent (up to 9 fractional digits).
    #[arg(long = "reserve-balance", value_name = "XOR", default_value = "0")]
    pub reserve_balance: String,
    /// Optional path to a JSON-encoded reserve policy (`ReservePolicyV1`).
    #[arg(long = "policy-json", value_name = "PATH")]
    pub policy_json: Option<PathBuf>,
    /// Optional path to a Norito-encoded reserve policy (`ReservePolicyV1`).
    #[arg(long = "policy-norito", value_name = "PATH")]
    pub policy_norito: Option<PathBuf>,
    /// Optional path for persisting the rendered quote JSON.
    #[arg(long = "quote-out", value_name = "PATH")]
    pub quote_out: Option<PathBuf>,
}
impl ReserveQuoteArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let storage_class = self.storage_class.to_storage_class();
        let tier = self.tier.to_policy_tier();
        let duration = self.duration.to_policy_duration();
        let reserve_balance = parse_xor_quantity(&self.reserve_balance)?;
        let (policy, source_label) = load_reserve_policy_from_paths(
            self.policy_json.as_deref(),
            self.policy_norito.as_deref(),
        )?;
        let quote = policy
            .quote(
                storage_class,
                self.capacity_gib,
                duration,
                tier,
                reserve_balance.clone(),
            )
            .wrap_err("failed to compute reserve quote")?;
        let value = build_reserve_quote_value(
            &policy,
            storage_class,
            tier,
            duration,
            self.capacity_gib,
            &reserve_balance,
            &quote,
            &source_label,
        )?;
        if let Some(path) = self.quote_out.as_deref() {
            write_reserve_quote_artifact(path, &value)?;
        }
        context.print_data(&value)
    }
}
#[derive(clap::Args, Debug)]
pub struct ReserveLedgerArgs {
    /// Path to the reserve quote JSON (output of `sorafs reserve quote`).
    #[arg(long = "quote", value_name = "PATH")]
    pub quote_path: PathBuf,
    /// Provider account paying the rent and reserve top-ups.
    #[arg(long = "provider-account", value_name = "ACCOUNT_ID")]
    pub provider_account: String,
    /// Treasury account receiving the rent payment.
    #[arg(long = "treasury-account", value_name = "ACCOUNT_ID")]
    pub treasury_account: String,
    /// Reserve escrow account receiving the reserve top-up.
    #[arg(long = "reserve-account", value_name = "ACCOUNT_ID")]
    pub reserve_account: String,
    /// Asset definition identifier used for transfers (canonical unprefixed Base58 address).
    #[arg(long = "asset-definition", value_name = "AID")]
    pub asset_definition: String,
}
impl ReserveLedgerArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let quote_contents = fs::read_to_string(&self.quote_path).wrap_err_with(|| {
            format!(
                "failed to read reserve quote `{}`",
                self.quote_path.display()
            )
        })?;
        let quote_value: Value =
            norito::json::from_str(&quote_contents).wrap_err("failed to parse reserve quote")?;
        let projection = extract_ledger_projection(&quote_value)?;
        let provider = crate::resolve_account_id(context, &self.provider_account)
            .wrap_err("failed to resolve --provider-account")?;
        let treasury = crate::resolve_account_id(context, &self.treasury_account)
            .wrap_err("failed to resolve --treasury-account")?;
        let reserve = crate::resolve_account_id(context, &self.reserve_account)
            .wrap_err("failed to resolve --reserve-account")?;
        let asset_definition = AssetDefinitionId::parse_address_literal(&self.asset_definition)
            .wrap_err("failed to parse --asset-definition")?;
        let plan = build_reserve_ledger_plan(
            &self.quote_path,
            projection,
            &provider,
            &treasury,
            &reserve,
            &asset_definition,
        )?;
        context.print_data(&plan)
    }
}
#[derive(clap::Args, Debug)]
pub struct ReserveLifecycleArgs {
    /// Path to the reserve quote JSON (output of `sorafs reserve quote`).
    #[arg(long = "quote", value_name = "PATH")]
    pub quote_path: PathBuf,
    /// Days since rent became due.
    #[arg(long = "days-past-due", value_name = "DAYS", default_value_t = 0)]
    pub days_past_due: u16,
    /// Grace window before delinquency.
    #[arg(long = "grace-days", value_name = "DAYS", default_value_t = 7)]
    pub grace_period_days: u16,
    /// Default threshold after the due date.
    #[arg(long = "default-after-days", value_name = "DAYS", default_value_t = 30)]
    pub default_after_days: u16,
}
impl ReserveLifecycleArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let quote_contents = fs::read_to_string(&self.quote_path).wrap_err_with(|| {
            format!(
                "failed to read reserve quote `{}`",
                self.quote_path.display()
            )
        })?;
        let quote_value: Value =
            norito::json::from_str(&quote_contents).wrap_err("failed to parse reserve quote")?;
        let quote = extract_reserve_quote(&quote_value)?;
        let lifecycle = quote
            .lifecycle_projection(
                self.days_past_due,
                self.grace_period_days,
                self.default_after_days,
            )
            .wrap_err("failed to compute reserve lifecycle projection")?;
        let value = build_reserve_lifecycle_value(&self.quote_path, &lifecycle)?;
        context.print_data(&value)
    }
}
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum GarActionArg {
    #[value(name = "purge-static-zone")]
    PurgeStaticZone,
    #[value(name = "cache-bypass")]
    CacheBypass,
    #[value(name = "ttl-override")]
    TtlOverride,
    #[value(name = "rate-limit-override")]
    RateLimitOverride,
    #[value(name = "geo-fence")]
    GeoFence,
    #[value(name = "legal-hold")]
    LegalHold,
    #[value(name = "moderation")]
    Moderation,
    #[value(name = "audit-notice")]
    AuditNotice,
    #[value(name = "custom")]
    Custom,
}
impl GarActionArg {
    fn to_enforcement_action(self, custom_slug: Option<&str>) -> Result<GarEnforcementActionV1> {
        Ok(match self {
            Self::PurgeStaticZone => GarEnforcementActionV1::PurgeStaticZone,
            Self::CacheBypass => GarEnforcementActionV1::CacheBypass,
            Self::TtlOverride => GarEnforcementActionV1::TtlOverride,
            Self::RateLimitOverride => GarEnforcementActionV1::RateLimitOverride,
            Self::GeoFence => GarEnforcementActionV1::GeoFence,
            Self::LegalHold => GarEnforcementActionV1::LegalHold,
            Self::Moderation => GarEnforcementActionV1::Moderation,
            Self::AuditNotice => GarEnforcementActionV1::AuditNotice,
            Self::Custom => {
                let slug = custom_slug.ok_or_else(|| {
                    eyre!("--custom-action-slug must be supplied when --action=custom is used")
                })?;
                GarEnforcementActionV1::Custom(slug.to_string())
            }
        })
    }
}
#[derive(clap::Args, Debug)]
pub struct GarReceiptArgs {
    /// Registered GAR name (`SoraDNS` label, e.g., `docs.sora`).
    #[arg(long = "gar-name", value_name = "LABEL")]
    gar_name: String,
    /// Canonical host affected by the enforcement action.
    #[arg(long = "canonical-host", value_name = "HOST")]
    canonical_host: String,
    /// Enforcement action recorded in the receipt.
    #[arg(long = "action", value_enum, default_value = "audit-notice")]
    action: GarActionArg,
    /// Slug recorded when `--action custom` is selected.
    #[arg(long = "custom-action-slug", value_name = "SLUG")]
    custom_action_slug: Option<String>,
    /// Optional receipt identifier (32 hex chars / 16 bytes). Defaults to a random ULID-like value.
    #[arg(long = "receipt-id", value_name = "HEX16")]
    receipt_id_hex: Option<String>,
    /// Override the triggered timestamp (RFC3339 or `@unix_seconds`). Defaults to `now`.
    #[arg(long = "triggered-at", value_name = "RFC3339|@UNIX")]
    triggered_at: Option<String>,
    /// Optional expiry timestamp (RFC3339 or `@unix_seconds`).
    #[arg(long = "expires-at", value_name = "RFC3339|@UNIX")]
    expires_at: Option<String>,
    /// Policy version label recorded in the receipt.
    #[arg(long = "policy-version", value_name = "STRING")]
    policy_version: Option<String>,
    /// Policy digest (64 hex chars / 32 bytes) referenced by the receipt.
    #[arg(long = "policy-digest", value_name = "HEX32")]
    policy_digest_hex: Option<String>,
    /// Operator account that executed the action.
    #[arg(long = "operator", value_name = "ACCOUNT_ID")]
    operator: String,
    /// Human-readable reason for the enforcement action.
    #[arg(long = "reason", value_name = "TEXT")]
    reason: String,
    /// Optional notes captured for auditors.
    #[arg(long = "notes", value_name = "TEXT")]
    notes: Option<String>,
    /// Evidence URIs (repeatable) recorded with the receipt.
    #[arg(long = "evidence-uri", value_name = "URI")]
    evidence_uri: Vec<String>,
    /// Machine-readable labels (repeatable) applied to the receipt.
    #[arg(long = "label", value_name = "TAG")]
    labels: Vec<String>,
    /// Path for persisting the JSON artefact (pretty-printed).
    #[arg(long = "json-out", value_name = "PATH")]
    json_out: Option<PathBuf>,
    /// Path for persisting the Norito-encoded receipt (`.to` bytes).
    #[arg(long = "norito-out", value_name = "PATH")]
    norito_out: Option<PathBuf>,
}
impl GarReceiptArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let receipt_id = parse_receipt_id(self.receipt_id_hex.as_deref())?;
        let triggered_at = parse_timestamp_or_now(self.triggered_at.as_deref(), "triggered-at")?;
        let expires_at = parse_optional_timestamp(self.expires_at.as_deref(), "expires-at")?;
        let policy_digest =
            parse_optional_hex_array::<32>(self.policy_digest_hex.as_deref(), "--policy-digest")?;
        let operator = crate::resolve_account_id(context, &self.operator)
            .wrap_err("failed to resolve --operator")?;
        let action = self
            .action
            .to_enforcement_action(self.custom_action_slug.as_deref())?;
        let receipt = GarEnforcementReceiptV1 {
            receipt_id,
            gar_name: self.gar_name,
            canonical_host: self.canonical_host,
            action,
            triggered_at_unix: triggered_at,
            expires_at_unix: expires_at,
            policy_version: self.policy_version,
            policy_digest,
            operator,
            reason: self.reason,
            notes: self.notes,
            evidence_uris: self.evidence_uri,
            labels: self.labels,
        };
        if let Some(path) = self.norito_out.as_deref() {
            let bytes = norito::to_bytes(&receipt).wrap_err("failed to encode receipt (Norito)")?;
            fs::write(path, bytes)
                .wrap_err_with(|| format!("failed to write Norito receipt `{}`", path.display()))?;
        }
        let json_value =
            norito::json::to_value(&receipt).wrap_err("failed to encode receipt JSON")?;
        if let Some(path) = self.json_out.as_deref() {
            let pretty = norito::json::to_string_pretty(&json_value)
                .wrap_err("failed to render receipt JSON")?;
            fs::write(path, pretty)
                .wrap_err_with(|| format!("failed to write receipt JSON `{}`", path.display()))?;
        }
        context.print_data(&json_value)
    }
}
fn parse_receipt_id(receipt_id_hex: Option<&str>) -> Result<[u8; 16]> {
    parse_receipt_id_with_rng(receipt_id_hex, &mut OsRng)
}
fn parse_receipt_id_with_rng<R: TryCryptoRng>(
    receipt_id_hex: Option<&str>,
    rng: &mut R,
) -> Result<[u8; 16]> {
    if let Some(hex) = receipt_id_hex {
        return parse_hex_array::<16>(hex, "--receipt-id");
    }
    let mut bytes = [0u8; 16];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|error| eyre!("SoraFS receipt-id OS RNG failed: {error}"))?;
    Ok(bytes)
}
fn parse_optional_hex_array<const N: usize>(
    value: Option<&str>,
    field: &str,
) -> Result<Option<[u8; N]>> {
    value
        .map(|hex| parse_hex_array::<N>(hex, field))
        .transpose()
}
fn parse_timestamp_value(input: &str, field: &str) -> Result<u64> {
    if let Some(rest) = input.strip_prefix('@') {
        let value = rest
            .parse::<u64>()
            .wrap_err_with(|| format!("invalid unix timestamp for {field}"))?;
        return Ok(value);
    }
    let dt = OffsetDateTime::parse(input, &Rfc3339)
        .wrap_err_with(|| format!("failed to parse {field} (expected RFC3339 or @unix format)"))?;
    dt.unix_timestamp()
        .try_into()
        .wrap_err("timestamp is negative")
}
fn parse_timestamp_or_now(value: Option<&str>, field: &str) -> Result<u64> {
    value.map_or_else(
        || {
            let now = OffsetDateTime::now_utc();
            now.unix_timestamp()
                .try_into()
                .wrap_err("current timestamp overflowed i64")
        },
        |input| parse_timestamp_value(input, field),
    )
}
fn parse_optional_timestamp(value: Option<&str>, field: &str) -> Result<Option<u64>> {
    value
        .map(|input| parse_timestamp_value(input, field))
        .transpose()
}
#[cfg(test)]
mod gar_receipt_cli_tests {
    use super::*;
    #[test]
    fn parse_timestamp_accepts_rfc3339() {
        let ts = parse_timestamp_value("2026-05-10T10:15:00Z", "triggered-at")
            .expect("timestamp parsed");
        assert_eq!(ts, 1_778_408_100);
    }
    #[test]
    fn parse_timestamp_accepts_unix_prefix() {
        let ts = parse_timestamp_value("@1778408100", "triggered-at").expect("timestamp parsed");
        assert_eq!(ts, 1_778_408_100);
    }
    #[test]
    fn custom_action_requires_slug() {
        let err = GarActionArg::Custom
            .to_enforcement_action(None)
            .expect_err("missing slug should fail");
        assert!(err.to_string().contains("--custom-action-slug"));
    }
}
#[derive(clap::Args, Debug)]
pub struct FetchArgs {
    /// Path to the Norito-encoded manifest (`.norito`) describing the payload layout.
    #[arg(long, value_name = "PATH", required_unless_present = "storage_ticket")]
    pub manifest: Option<PathBuf>,
    /// Path to a canonical payload-bound `sorafs.chunk_fetch_plan.v1` JSON envelope.
    #[arg(long, value_name = "PATH", required_unless_present = "storage_ticket")]
    pub plan: Option<PathBuf>,
    /// Hex-encoded manifest hash used as the manifest identifier on gateways.
    #[arg(
        long = "manifest-id",
        value_name = "HEX",
        required_unless_present = "storage_ticket"
    )]
    pub manifest_id: Option<String>,
    /// Gateway provider descriptor (`name=... , provider-id=... , base-url=... , stream-token=...`).
    #[arg(long = "gateway-provider", value_name = "SPEC", required = true)]
    pub gateway_provider: Vec<String>,
    /// Storage ticket identifier to fetch manifest + chunk plan automatically from Torii.
    #[arg(long = "storage-ticket", value_name = "HEX")]
    pub storage_ticket: Option<String>,
    /// Optional Torii base URL used with `--storage-ticket` (must end with `/`).
    #[arg(long = "torii-url", value_name = "URL", requires = "storage_ticket")]
    pub torii_url: Option<String>,
    /// Directory for storing manifest/chunk-plan artefacts fetched via `--storage-ticket`.
    #[arg(
        long = "manifest-cache-dir",
        value_name = "PATH",
        requires = "storage_ticket"
    )]
    pub manifest_cache_dir: Option<PathBuf>,
    /// Optional client identifier forwarded to the gateway for auditing.
    #[arg(long = "client-id", value_name = "STRING")]
    pub client_id: Option<String>,
    /// Optional path to a Norito-encoded manifest envelope to satisfy gateway policy checks.
    #[arg(long = "manifest-envelope", value_name = "PATH")]
    pub manifest_envelope: Option<PathBuf>,
    /// Override the expected manifest CID (defaults to the manifest digest).
    #[arg(long = "manifest-cid", value_name = "HEX")]
    pub manifest_cid: Option<String>,
    /// Canonical blinded CID (base64url, no padding) forwarded via `SoraNet` headers.
    #[arg(long = "blinded-cid", value_name = "BASE64", requires = "salt_epoch")]
    pub blinded_cid: Option<String>,
    /// Salt epoch corresponding to the blinded CID headers.
    #[arg(long = "salt-epoch", value_name = "EPOCH")]
    pub salt_epoch: Option<u32>,
    /// Hex-encoded 32-byte salt used to derive the canonical blinded CID (computes `--blinded-cid`).
    #[arg(long = "salt-hex", value_name = "HEX", requires = "salt_epoch")]
    pub salt_hex: Option<String>,
    /// Override the chunker handle advertised to gateways.
    #[arg(long = "chunker-handle", value_name = "STRING")]
    pub chunker_handle: Option<String>,
    /// Limit the number of providers participating in the session.
    #[arg(long = "max-peers", value_name = "COUNT")]
    pub max_peers: Option<usize>,
    /// Maximum retry attempts per chunk (0 disables the cap).
    #[arg(long = "retry-budget", value_name = "COUNT")]
    pub retry_budget: Option<usize>,
    /// Override the default `soranet-first` transport policy (`soranet-first`, `soranet-strict`, or
    /// `direct-only`). Supply `direct-only` only when staging a downgrade or rehearsing the
    /// compliance drills captured in `roadmap.md`.
    #[arg(long = "transport-policy", value_name = "POLICY")]
    pub transport_policy: Option<String>,
    /// Override the anonymity policy with an exact V1 label (`anon-guard-pq`,
    /// `anon-majority-pq`, or `anon-strict-pq`).
    #[arg(long = "anonymity-policy", value_name = "POLICY")]
    pub anonymity_policy: Option<String>,
    /// Hint that tightens PQ expectations for write paths (`read-only` or `upload-pq-only`).
    #[arg(long = "write-mode", value_name = "MODE")]
    pub write_mode: Option<String>,
    /// Force the orchestrator to stay on a specific transport stage (`soranet-first`, `soranet-strict`, or `direct-only`).
    #[arg(long = "transport-policy-override", value_name = "POLICY")]
    pub transport_policy_override: Option<String>,
    /// Force the orchestrator to stay on an exact V1 anonymity policy.
    #[arg(long = "anonymity-policy-override", value_name = "POLICY")]
    pub anonymity_policy_override: Option<String>,
    /// Path to the persisted guard cache (Norito-encoded guard set).
    #[arg(
        long = "guard-cache",
        value_name = "PATH",
        requires_all = ["guard_cache_key_file", "guard_directory"]
    )]
    pub guard_cache: Option<PathBuf>,
    /// Owner-private file containing the exact 32 raw bytes used to authenticate the guard cache.
    #[arg(
        long = "guard-cache-key-file",
        value_name = "PATH",
        requires = "guard_cache"
    )]
    pub guard_cache_key_file: Option<PathBuf>,
    /// Path to a Norito guard directory snapshot used to refresh guard selections.
    #[arg(long = "guard-directory", value_name = "PATH")]
    pub guard_directory: Option<PathBuf>,
    /// Trusted domain-separated BLAKE3 digest of the exact guard directory bytes.
    #[arg(
        long = "guard-directory-digest",
        value_name = "HEX",
        requires = "guard_directory"
    )]
    pub guard_directory_digest: Option<String>,
    /// Target number of entry guards to pin (defaults to 3 when the guard directory is provided).
    #[arg(long = "guard-target", value_name = "COUNT")]
    pub guard_target: Option<usize>,
    /// Guard retention window in days (defaults to 30 when the guard directory is provided).
    #[arg(long = "guard-retention-days", value_name = "DAYS")]
    pub guard_retention_days: Option<u64>,
    /// Write the assembled payload to a file.
    #[arg(long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Override the summary JSON path (defaults to `artifacts/sorafs_orchestrator/latest/summary.json`).
    #[arg(long = "json-out", value_name = "PATH")]
    pub json_out: Option<PathBuf>,
    /// Override the scoreboard JSON path (defaults to `artifacts/sorafs_orchestrator/latest/scoreboard.json`).
    #[arg(long = "scoreboard-out", value_name = "PATH")]
    pub scoreboard_out: Option<PathBuf>,
    /// Override the Unix timestamp used when evaluating provider adverts.
    #[arg(long = "scoreboard-now", value_name = "UNIX_SECS")]
    pub scoreboard_now: Option<u64>,
    /// Label describing the telemetry stream captured alongside the scoreboard (persisted in metadata).
    #[arg(long = "telemetry-source-label", value_name = "LABEL")]
    pub telemetry_source_label: Option<String>,
    /// Optional telemetry region label persisted in both the scoreboard metadata and summary JSON.
    #[arg(long = "telemetry-region", value_name = "LABEL")]
    pub telemetry_region: Option<String>,
}
#[derive(Debug)]
struct ManifestInputs {
    manifest_path: PathBuf,
    plan_path: PathBuf,
    manifest_id: String,
}
#[derive(Debug)]
struct DownloadedManifest {
    manifest_path: PathBuf,
    plan_path: PathBuf,
    manifest_id: String,
}
#[derive(Debug, Clone)]
struct ScoreboardCapturePaths {
    scoreboard: PathBuf,
    summary: Option<PathBuf>,
}
fn default_orchestrator_capture_dir() -> PathBuf {
    PathBuf::from("artifacts")
        .join("sorafs_orchestrator")
        .join("latest")
}
fn scoreboard_capture_paths(
    scoreboard_override: Option<PathBuf>,
    summary_override: Option<PathBuf>,
) -> ScoreboardCapturePaths {
    let scoreboard = scoreboard_override
        .unwrap_or_else(|| default_orchestrator_capture_dir().join("scoreboard.json"));
    let summary = summary_override.or_else(|| {
        scoreboard
            .parent()
            .map(|parent| parent.join("summary.json"))
    });
    ScoreboardCapturePaths {
        scoreboard,
        summary,
    }
}
fn insert_provider_counts(summary: &mut norito::json::Map, counts: ProviderCounts) {
    summary.insert(
        "provider_count".into(),
        norito::json::Value::from(counts.direct_u64()),
    );
    summary.insert(
        "gateway_provider_count".into(),
        norito::json::Value::from(counts.gateway_u64()),
    );
    summary.insert(
        "provider_mix".into(),
        norito::json::Value::from(counts.mix_label()),
    );
}
fn insert_transport_policy(
    summary: &mut norito::json::Map,
    transport_policy: Option<TransportPolicy>,
    transport_policy_override: Option<TransportPolicy>,
) {
    let (label, override_flag, override_label) =
        transport_policy_labels(transport_policy, transport_policy_override);
    summary.insert("transport_policy".into(), norito::json::Value::from(label));
    summary.insert(
        "transport_policy_override".into(),
        norito::json::Value::from(override_flag),
    );
    summary.insert(
        "transport_policy_override_label".into(),
        override_label.map_or(norito::json::Value::Null, norito::json::Value::from),
    );
}
fn insert_summary_telemetry_source(summary: &mut norito::json::Map, label: Option<&str>) {
    if let Some(value) = label {
        summary.insert("telemetry_source".into(), norito::json::Value::from(value));
    }
}
fn insert_summary_telemetry_region(summary: &mut norito::json::Map, label: Option<&str>) {
    if let Some(value) = label {
        summary.insert("telemetry_region".into(), norito::json::Value::from(value));
    }
}
fn public_local_proxy_manifest_value(manifest: &BrowserExtensionManifest) -> norito::json::Value {
    let mut public_manifest = manifest.clone();
    public_manifest.client_capability_hex = None;
    let mut value = norito::json::to_value(&public_manifest)
        .expect("local proxy manifest should serialise to JSON");
    if let norito::json::Value::Object(fields) = &mut value {
        fields.remove("client_capability_hex");
    }
    value
}
impl Run for FetchArgs {
    #[allow(clippy::too_many_lines)]
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if let Some(peers) = self.max_peers
            && peers == 0
        {
            return Err(eyre!("--max-peers must be at least 1 when provided"));
        }
        if self.guard_target.is_some() && self.guard_directory.is_none() {
            return Err(eyre!("--guard-target requires --guard-directory"));
        }
        if self.guard_retention_days.is_some() && self.guard_directory.is_none() {
            return Err(eyre!("--guard-retention-days requires --guard-directory"));
        }
        if self.guard_directory.is_some() && self.guard_directory_digest.is_none() {
            return Err(eyre!(
                "--guard-directory requires --guard-directory-digest from an independent trusted source"
            ));
        }
        if self.guard_cache.is_some() != self.guard_cache_key_file.is_some() {
            return Err(eyre!(
                "--guard-cache and --guard-cache-key-file must be supplied together"
            ));
        }
        if self.guard_cache.is_some() && self.guard_directory.is_none() {
            return Err(eyre!(
                "--guard-cache requires --guard-directory and its independently trusted --guard-directory-digest; cached guard state is not a freshness trust anchor"
            ));
        }
        let guard_cache_key = self
            .guard_cache_key_file
            .as_deref()
            .map(load_guard_cache_key_file)
            .transpose()?;
        let manifest_inputs = resolve_manifest_inputs(context, &self)?;
        let ManifestInputs {
            manifest_path,
            plan_path,
            manifest_id,
        } = manifest_inputs;
        let manifest_bytes = fs::read(&manifest_path).wrap_err_with(|| {
            format!("failed to read manifest from `{}`", manifest_path.display())
        })?;
        let manifest: ManifestV1 =
            norito::decode_from_bytes(&manifest_bytes).wrap_err("failed to decode manifest")?;
        let manifest_digest = manifest
            .digest()
            .wrap_err("failed to compute manifest digest")?;
        let cid_hex_override = if let Some(cid) = &self.manifest_cid {
            validate_hex_digest(cid, "--manifest-cid")?
        } else {
            hex::encode(manifest_digest.as_bytes())
        };
        let plan_bytes = fs::read(&plan_path).wrap_err_with(|| {
            format!("failed to read chunk plan from `{}`", plan_path.display())
        })?;
        let plan_value: norito::json::Value =
            norito::json::from_slice(&plan_bytes).wrap_err("failed to parse chunk plan JSON")?;
        let parsed_plan = chunk_fetch_plan_from_json(&plan_value)
            .map_err(|err| eyre!("failed to parse canonical chunk fetch plan: {err}"))?;
        let plan_payload_digest = parsed_plan.payload_digest;
        let mut chunk_specs = parsed_plan.chunk_fetch_specs;
        if chunk_specs.is_empty() {
            return Err(eyre!("chunk fetch plan contained no entries"));
        }
        chunk_specs.sort_by_key(|spec| spec.chunk_index);
        for (idx, spec) in chunk_specs.iter().enumerate() {
            if spec.chunk_index != idx {
                return Err(eyre!(
                    "chunk fetch plan missing chunk index {idx} (found {})",
                    spec.chunk_index
                ));
            }
        }
        let content_length = chunk_specs
            .iter()
            .map(|spec| spec.offset + u64::from(spec.length))
            .max()
            .expect("non-empty chunk specs");
        let manifest_id_bytes = parse_digest_hex(&manifest_id)
            .map_err(|_| eyre!("--manifest-id must be a 64-character hex-encoded BLAKE3 digest"))?;
        if manifest_id_bytes != *manifest_digest.as_bytes() {
            return Err(eyre!(
                "--manifest-id must match the manifest hash (expected {})",
                hex::encode(manifest_digest.as_bytes())
            ));
        }
        let manifest_id_hex = hex::encode(manifest_id_bytes);
        let payload_digest_hex = hex::encode(plan_payload_digest);
        let payload_digest = blake3::Hash::from_bytes(plan_payload_digest);
        let transport_policy =
            parse_transport_policy_flag(self.transport_policy.as_ref(), "--transport-policy")?;
        let anonymity_policy =
            parse_anonymity_policy_flag(self.anonymity_policy.as_ref(), "--anonymity-policy")?;
        let write_mode = parse_write_mode_flag(self.write_mode.as_ref(), "--write-mode")?;
        let transport_policy_override = parse_transport_policy_flag(
            self.transport_policy_override.as_ref(),
            "--transport-policy-override",
        )?;
        let anonymity_policy_override = parse_anonymity_policy_flag(
            self.anonymity_policy_override.as_ref(),
            "--anonymity-policy-override",
        )?;
        let policy_override =
            PolicyOverride::new(transport_policy_override, anonymity_policy_override);
        let chunk_profile = chunker_registry::lookup(manifest.chunking.profile_id).map_or_else(
            || ChunkProfile {
                min_size: manifest.chunking.min_size as usize,
                target_size: manifest.chunking.target_size as usize,
                max_size: manifest.chunking.max_size as usize,
                break_mask: u64::from(manifest.chunking.break_mask),
            },
            |descriptor| descriptor.profile,
        );
        let chunks: Vec<CarChunk> = chunk_specs
            .iter()
            .map(|spec| CarChunk {
                offset: spec.offset,
                length: spec.length,
                digest: spec.digest,
            })
            .collect();
        let plan = CarBuildPlan {
            chunk_profile,
            payload_digest,
            content_length,
            chunks,
            files: vec![FilePlan {
                path: Vec::new(),
                first_chunk: 0,
                chunk_count: chunk_specs.len(),
                size: content_length,
            }],
        };
        let chunker_handle = self.chunker_handle.unwrap_or_else(|| {
            format!(
                "{}.{}@{}",
                manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
            )
        });
        let salt_epoch_cli = self.salt_epoch;
        let mut blinded_cid_b64 = self
            .blinded_cid
            .as_ref()
            .map(|value| value.trim().to_string());
        if let Some(value) = blinded_cid_b64.as_ref()
            && value.is_empty()
        {
            return Err(eyre!("--blinded-cid must not be empty"));
        }
        if blinded_cid_b64.is_none()
            && let Some(salt_hex) = self.salt_hex.as_ref()
        {
            let trimmed = salt_hex.trim();
            let decoded =
                hex::decode(trimmed).map_err(|err| eyre!("invalid --salt-hex value: {err}"))?;
            if decoded.len() != 32 {
                return Err(eyre!("--salt-hex must decode to 32 bytes"));
            }
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&decoded);
            let blinded = canonical_cache_key(&salt, manifest.root_cid.as_slice());
            blinded_cid_b64 = Some(URL_SAFE_NO_PAD.encode(blinded.as_bytes()));
        }
        let salt_epoch = match (blinded_cid_b64.as_ref(), salt_epoch_cli) {
            (Some(_), Some(epoch)) => Some(epoch),
            (Some(_), None) => {
                return Err(eyre!(
                    "--salt-epoch must be supplied when providing --blinded-cid or --salt-hex"
                ));
            }
            (None, Some(_)) => {
                return Err(eyre!(
                    "--salt-epoch requires --blinded-cid or --salt-hex to compute the header"
                ));
            }
            (None, None) => None,
        };
        let manifest_envelope_b64 = match self.manifest_envelope.as_ref() {
            Some(path) => Some(load_manifest_envelope(path)?),
            None => None,
        };
        let guard_cache_path = self.guard_cache.clone();
        let mut guard_set = if let Some(path) = guard_cache_path.as_ref() {
            load_guard_set(path, guard_cache_key.as_ref())
                .wrap_err_with(|| format!("failed to load guard cache from `{}`", path.display()))?
        } else {
            None
        };
        let mut guard_updated = false;
        let relay_directory = if let Some(directory_path) = self.guard_directory.as_ref() {
            let expected_digest = self
                .guard_directory_digest
                .as_deref()
                .expect("checked guard directory digest above");
            let now_unix = OffsetDateTime::now_utc().unix_timestamp();
            let directory = load_guard_directory(directory_path, expected_digest, now_unix)
                .wrap_err_with(|| {
                    format!(
                        "failed to parse guard directory from `{}`",
                        directory_path.display()
                    )
                })?;
            let target = self.guard_target.unwrap_or(3);
            if target == 0 {
                return Err(eyre!("--guard-target must be at least 1 when provided"));
            }
            let retention_days = self.guard_retention_days.unwrap_or(30);
            if retention_days == 0 {
                return Err(eyre!(
                    "--guard-retention-days must be at least 1 when provided"
                ));
            }
            let retention_secs = retention_days.saturating_mul(24 * 60 * 60);
            let retention = GuardRetention::new(
                NonZeroU64::new(retention_secs)
                    .ok_or_else(|| eyre!("guard retention window must be at least one second"))?,
            );
            let selector = GuardSelector::new(
                NonZeroUsize::new(target)
                    .ok_or_else(|| eyre!("guard target must be at least 1 when provided"))?,
            )
            .with_retention(retention);
            let now_unix = u64::try_from(now_unix).unwrap_or(0);
            let policy = anonymity_policy.unwrap_or(AnonymityPolicy::GuardPq);
            let selected = selector
                .select(&directory, guard_set.as_ref(), now_unix, policy)
                .wrap_err("guard directory is not active at the selection timestamp")?;
            guard_set = Some(selected);
            guard_updated = true;
            Some(directory)
        } else {
            None
        };
        let mut provider_inputs = Vec::with_capacity(self.gateway_provider.len());
        let mut provider_aliases = Vec::with_capacity(self.gateway_provider.len());
        let mut provider_label_by_id = HashMap::with_capacity(self.gateway_provider.len());
        for spec in &self.gateway_provider {
            let parsed = GatewayProviderInput::parse_spec(spec, "--gateway-provider")
                .map_err(|err| eyre!(err))?;
            provider_label_by_id.insert(parsed.provider_id_hex.clone(), parsed.name.clone());
            provider_aliases.push(parsed.name.clone());
            provider_inputs.push(parsed);
        }
        let gateway_config = GatewayFetchConfig {
            manifest_id_hex: manifest_id_hex.clone(),
            chunker_handle,
            manifest_envelope_b64: manifest_envelope_b64.clone(),
            client_id: self.client_id.clone(),
            expected_manifest_cid_hex: Some(cid_hex_override.clone()),
            blinded_cid_b64,
            salt_epoch,
            expected_cache_version: None,
        };
        let telemetry_source_label = self
            .telemetry_source_label
            .as_ref()
            .map(|label| {
                let trimmed = label.trim();
                if trimmed.is_empty() {
                    Err(eyre!(
                        "--telemetry-source-label must not be empty when provided"
                    ))
                } else {
                    Ok(trimmed.to_string())
                }
            })
            .transpose()?;
        let telemetry_region_label = self
            .telemetry_region
            .as_ref()
            .map(|label| {
                let trimmed = label.trim();
                if trimmed.is_empty() {
                    Err(eyre!("--telemetry-region must not be empty when provided"))
                } else {
                    Ok(trimmed.to_string())
                }
            })
            .transpose()?;
        let gateway_provider_count = provider_inputs.len();
        let capture_paths =
            scoreboard_capture_paths(self.scoreboard_out.clone(), self.json_out.clone());
        let write_mode_hint = write_mode.unwrap_or(WriteModeHint::ReadOnly);
        let mut scoreboard_options = SorafsGatewayScoreboardOptions::default();
        if let Some(parent) = capture_paths
            .scoreboard
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).wrap_err_with(|| {
                format!(
                    "failed to create scoreboard directory `{}`",
                    parent.display()
                )
            })?;
        }
        scoreboard_options.persist_path = Some(capture_paths.scoreboard.clone());
        if let Some(now) = self.scoreboard_now {
            scoreboard_options.now_unix_secs = Some(now);
        }
        let provider_counts = ProviderCounts::new(0, gateway_provider_count);
        let metadata = cli_scoreboard_metadata(&ScoreboardMetadataInput {
            version: crate::build_metadata().version(),
            provider_counts,
            max_peers: self.max_peers,
            retry_budget: self.retry_budget,
            manifest_envelope_present: manifest_envelope_b64.is_some(),
            gateway_manifest_id: Some(manifest_id_hex.clone()),
            gateway_manifest_cid: Some(cid_hex_override.clone()),
            transport_policy,
            transport_policy_override,
            anonymity_policy,
            anonymity_policy_override,
            write_mode: write_mode_hint,
            scoreboard_now: self.scoreboard_now,
            telemetry_source: telemetry_source_label.clone(),
            telemetry_region: telemetry_region_label.clone(),
        });
        scoreboard_options.metadata = Some(metadata);
        scoreboard_options
            .telemetry_source_label
            .clone_from(&telemetry_source_label);
        let scoreboard_options = Some(scoreboard_options);
        let fetch_options = SorafsGatewayFetchOptions {
            retry_budget: self.retry_budget,
            max_peers: self.max_peers,
            telemetry_region: telemetry_region_label.clone(),
            transport_policy,
            anonymity_policy,
            guard_set: guard_set.clone(),
            relay_directory,
            write_mode_hint: Some(write_mode_hint),
            policy_override,
            scoreboard: scoreboard_options,
            expected_cache_version: gateway_config.expected_cache_version.clone(),
        };
        let client = context.client_from_config()?;
        let runtime = Runtime::new().wrap_err("failed to create Tokio runtime")?;
        let session = runtime
            .block_on(StorageClient::new(&client).sorafs_fetch_via_gateway(
                &plan,
                gateway_config,
                provider_inputs,
                fetch_options,
            ))
            .map_err(|err| eyre!("SoraFS fetch failed: {err}"))?;
        let outcome = &session.outcome;
        let policy_report = &session.policy_report;
        let assembled = outcome.assemble_payload();
        let computed_digest = blake3::hash(&assembled);
        if computed_digest.as_bytes() != payload_digest.as_bytes() {
            return Err(eyre!(
                "assembled payload digest {} did not match expected payload digest {}",
                hex::encode(computed_digest.as_bytes()),
                payload_digest_hex
            ));
        }
        if guard_updated
            && let (Some(path), Some(guard_state)) = (guard_cache_path.as_ref(), guard_set.as_ref())
        {
            persist_guard_set(path, guard_state, guard_cache_key.as_ref()).wrap_err_with(|| {
                format!("failed to persist guard cache to `{}`", path.display())
            })?;
        }
        let policy = policy_report.policy;
        let soranet_selected = policy_report.selected_soranet_total as u64;
        let pq_selected = policy_report.selected_pq as u64;
        let classical_selected = policy_report.selected_classical() as u64;
        let pq_ratio = policy_report.pq_ratio();
        if let Some(path) = &self.output {
            fs::write(path, &assembled)
                .wrap_err_with(|| format!("failed to write payload to `{}`", path.display()))?;
        }
        let provider_reports_json: Vec<norito::json::Value> = outcome
            .provider_reports
            .iter()
            .map(|report| {
                let provider_id = report.provider.id().as_str();
                let alias = provider_label_by_id
                    .get(&provider_id.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_else(|| provider_id.to_string());
                let mut map = norito::json::Map::new();
                map.insert("provider_id".into(), norito::json::Value::from(provider_id));
                map.insert("alias".into(), norito::json::Value::from(alias));
                map.insert(
                    "successes".into(),
                    norito::json::Value::from(report.successes as u64),
                );
                map.insert(
                    "failures".into(),
                    norito::json::Value::from(report.failures as u64),
                );
                map.insert(
                    "disabled".into(),
                    norito::json::Value::from(report.disabled),
                );
                norito::json::Value::Object(map)
            })
            .collect();
        let chunk_receipts_json: Vec<norito::json::Value> = outcome
            .chunk_receipts
            .iter()
            .map(|receipt| {
                let provider_id_lower = receipt.provider.as_str().to_ascii_lowercase();
                let alias = provider_label_by_id
                    .get(&provider_id_lower)
                    .cloned()
                    .unwrap_or_else(|| receipt.provider.as_str().to_string());
                let mut map = norito::json::Map::new();
                map.insert(
                    "chunk_index".into(),
                    norito::json::Value::from(receipt.chunk_index as u64),
                );
                map.insert(
                    "provider_id".into(),
                    norito::json::Value::from(receipt.provider.as_str()),
                );
                map.insert("alias".into(), norito::json::Value::from(alias));
                map.insert(
                    "attempts".into(),
                    norito::json::Value::from(receipt.attempts as u64),
                );
                map.insert(
                    "latency_ms".into(),
                    norito::json::Value::from(receipt.latency_ms),
                );
                map.insert(
                    "bytes".into(),
                    norito::json::Value::from(u64::from(receipt.bytes)),
                );
                norito::json::Value::Object(map)
            })
            .collect();
        let mut summary = norito::json::Map::new();
        summary.insert(
            "manifest_id".into(),
            norito::json::Value::from(manifest_id_hex),
        );
        summary.insert(
            "manifest_cid".into(),
            norito::json::Value::from(cid_hex_override),
        );
        summary.insert(
            "chunk_count".into(),
            norito::json::Value::from(outcome.chunks.len() as u64),
        );
        summary.insert(
            "fetched_bytes".into(),
            norito::json::Value::from(assembled.len() as u64),
        );
        insert_provider_counts(&mut summary, provider_counts);
        insert_transport_policy(&mut summary, transport_policy, transport_policy_override);
        summary.insert(
            "gateway_manifest_provided".into(),
            norito::json::Value::from(manifest_envelope_b64.is_some()),
        );
        summary.insert(
            "guard_cache_tagged".into(),
            norito::json::Value::from(guard_cache_key.is_some()),
        );
        summary.insert(
            "providers".into(),
            norito::json::Value::Array(
                provider_aliases
                    .iter()
                    .cloned()
                    .map(norito::json::Value::from)
                    .collect(),
            ),
        );
        summary.insert(
            "provider_reports".into(),
            norito::json::Value::Array(provider_reports_json),
        );
        summary.insert(
            "chunk_receipts".into(),
            norito::json::Value::Array(chunk_receipts_json),
        );
        if let Some(manifest) = &session.local_proxy_manifest {
            summary.insert(
                "local_proxy_manifest".into(),
                public_local_proxy_manifest_value(manifest),
            );
        }
        if let Some(budget) = self.retry_budget {
            summary.insert(
                "retry_budget".into(),
                norito::json::Value::from(budget as u64),
            );
        }
        if let Some(peers) = self.max_peers {
            summary.insert("max_peers".into(), norito::json::Value::from(peers as u64));
        }
        if let Some(client_id) = &self.client_id {
            summary.insert(
                "client_id".into(),
                norito::json::Value::from(client_id.clone()),
            );
        }
        insert_summary_telemetry_source(&mut summary, telemetry_source_label.as_deref());
        insert_summary_telemetry_region(&mut summary, telemetry_region_label.as_deref());
        summary.insert(
            "anonymity_policy".into(),
            norito::json::Value::from(anonymity_policy_label(policy).to_string()),
        );
        summary.insert(
            "anonymity_status".into(),
            norito::json::Value::from(policy_report.status_label()),
        );
        summary.insert(
            "anonymity_reason".into(),
            norito::json::Value::from(policy_report.reason_label()),
        );
        summary.insert(
            "anonymity_soranet_selected".into(),
            norito::json::Value::from(soranet_selected),
        );
        summary.insert(
            "anonymity_pq_selected".into(),
            norito::json::Value::from(pq_selected),
        );
        summary.insert(
            "anonymity_classical_selected".into(),
            norito::json::Value::from(classical_selected),
        );
        summary.insert(
            "anonymity_classical_ratio".into(),
            norito::json::Value::from(policy_report.classical_ratio()),
        );
        summary.insert(
            "anonymity_pq_ratio".into(),
            norito::json::Value::from(pq_ratio),
        );
        summary.insert(
            "anonymity_candidate_ratio".into(),
            norito::json::Value::from(policy_report.candidate_ratio()),
        );
        summary.insert(
            "anonymity_deficit_ratio".into(),
            norito::json::Value::from(policy_report.deficit_ratio()),
        );
        summary.insert(
            "anonymity_supply_delta".into(),
            norito::json::Value::from(policy_report.supply_delta_ratio()),
        );
        summary.insert(
            "anonymity_brownout".into(),
            norito::json::Value::from(policy_report.is_brownout()),
        );
        summary.insert(
            "anonymity_brownout_effective".into(),
            norito::json::Value::from(policy_report.should_flag_brownout()),
        );
        summary.insert(
            "anonymity_uses_classical".into(),
            norito::json::Value::from(policy_report.uses_classical()),
        );
        let summary_value = norito::json::Value::Object(summary);
        if let Some(path) = capture_paths.summary.as_ref() {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                fs::create_dir_all(parent).wrap_err_with(|| {
                    format!("failed to create summary directory `{}`", parent.display())
                })?;
            }
            let rendered = norito::json::to_string_pretty(&summary_value)?;
            fs::write(path, rendered.as_bytes())
                .wrap_err_with(|| format!("failed to write summary to `{}`", path.display()))?;
        }
        context.print_data(&summary_value)
    }
}
fn option_usize_to_json_value(value: Option<usize>) -> Value {
    value
        .and_then(|val| u64::try_from(val).ok())
        .map_or(Value::Null, Value::from)
}
fn transport_policy_labels(
    requested: Option<TransportPolicy>,
    override_policy: Option<TransportPolicy>,
) -> (&'static str, bool, Option<&'static str>) {
    let override_flag = override_policy.is_some();
    let override_label = override_policy.map(TransportPolicy::label);
    let effective = override_policy.unwrap_or_else(|| requested.unwrap_or_default());
    (effective.label(), override_flag, override_label)
}
fn anonymity_policy_labels(
    requested: Option<AnonymityPolicy>,
    override_policy: Option<AnonymityPolicy>,
) -> (&'static str, bool, Option<&'static str>) {
    let override_flag = override_policy.is_some();
    let override_label = override_policy.map(AnonymityPolicy::label);
    let effective = override_policy.unwrap_or_else(|| requested.unwrap_or_default());
    (effective.label(), override_flag, override_label)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderCounts {
    direct: usize,
    gateway: usize,
}
impl ProviderCounts {
    const fn new(direct: usize, gateway: usize) -> Self {
        Self { direct, gateway }
    }
    fn direct_u64(self) -> u64 {
        u64::try_from(self.direct).unwrap_or(u64::MAX)
    }
    fn gateway_u64(self) -> u64 {
        u64::try_from(self.gateway).unwrap_or(u64::MAX)
    }
    fn mix_label(self) -> &'static str {
        match (self.direct > 0, self.gateway > 0) {
            (true, true) => "mixed",
            (true, false) => "direct-only",
            (false, true) => "gateway-only",
            (false, false) => "none",
        }
    }
}
#[derive(Clone)]
struct ScoreboardMetadataInput {
    version: &'static str,
    provider_counts: ProviderCounts,
    max_peers: Option<usize>,
    retry_budget: Option<usize>,
    manifest_envelope_present: bool,
    gateway_manifest_id: Option<String>,
    gateway_manifest_cid: Option<String>,
    transport_policy: Option<TransportPolicy>,
    transport_policy_override: Option<TransportPolicy>,
    anonymity_policy: Option<AnonymityPolicy>,
    anonymity_policy_override: Option<AnonymityPolicy>,
    write_mode: WriteModeHint,
    scoreboard_now: Option<u64>,
    telemetry_source: Option<String>,
    telemetry_region: Option<String>,
}
fn cli_scoreboard_metadata(input: &ScoreboardMetadataInput) -> Value {
    let mut metadata = Map::new();
    metadata.insert("version".into(), Value::from(input.version));
    metadata.insert("use_scoreboard".into(), Value::from(true));
    metadata.insert("allow_implicit_metadata".into(), Value::from(false));
    metadata.insert(
        "provider_count".into(),
        Value::from(input.provider_counts.direct_u64()),
    );
    metadata.insert(
        "gateway_provider_count".into(),
        Value::from(input.provider_counts.gateway_u64()),
    );
    metadata.insert(
        "provider_mix".into(),
        Value::from(input.provider_counts.mix_label()),
    );
    metadata.insert("max_parallel".into(), Value::Null);
    metadata.insert(
        "max_peers".into(),
        option_usize_to_json_value(input.max_peers),
    );
    metadata.insert(
        "retry_budget".into(),
        option_usize_to_json_value(input.retry_budget),
    );
    metadata.insert("provider_failure_threshold".into(), Value::Null);
    metadata.insert(
        "assume_now".into(),
        input.scoreboard_now.map_or(Value::Null, Value::from),
    );
    metadata.insert(
        "telemetry_source".into(),
        input
            .telemetry_source
            .as_ref()
            .map_or(Value::Null, |label| Value::from(label.as_str())),
    );
    metadata.insert(
        "telemetry_region".into(),
        input
            .telemetry_region
            .as_ref()
            .map_or(Value::Null, |label| Value::from(label.as_str())),
    );
    metadata.insert(
        "gateway_manifest_id".into(),
        input
            .gateway_manifest_id
            .as_deref()
            .map_or(Value::Null, Value::from),
    );
    metadata.insert(
        "gateway_manifest_cid".into(),
        input
            .gateway_manifest_cid
            .as_deref()
            .map_or(Value::Null, Value::from),
    );
    metadata.insert(
        "gateway_manifest_provided".into(),
        Value::from(input.manifest_envelope_present),
    );
    let (transport_label, transport_override_flag, transport_override_label) =
        transport_policy_labels(input.transport_policy, input.transport_policy_override);
    metadata.insert("transport_policy".into(), Value::from(transport_label));
    metadata.insert(
        "transport_policy_override".into(),
        Value::from(transport_override_flag),
    );
    metadata.insert(
        "transport_policy_override_label".into(),
        transport_override_label.map_or(Value::Null, Value::from),
    );
    let (anonymity_label, anonymity_override_flag, anonymity_override_label) =
        anonymity_policy_labels(input.anonymity_policy, input.anonymity_policy_override);
    metadata.insert("anonymity_policy".into(), Value::from(anonymity_label));
    metadata.insert(
        "anonymity_policy_override".into(),
        Value::from(anonymity_override_flag),
    );
    metadata.insert(
        "anonymity_policy_override_label".into(),
        anonymity_override_label.map_or(Value::Null, Value::from),
    );
    let write_mode_label = input.write_mode.label().replace('_', "-");
    metadata.insert("write_mode".into(), Value::from(write_mode_label));
    metadata.insert(
        "write_mode_enforces_pq".into(),
        Value::from(input.write_mode.enforces_pq_only()),
    );
    Value::Object(metadata)
}
fn load_guard_cache_key_file(path: &Path) -> Result<GuardCacheKey> {
    let bytes = read_owner_private_handshake_file(
        path,
        GuardCacheKey::LENGTH,
        Some(GuardCacheKey::LENGTH),
        "guard cache authentication key",
    )?;
    let mut key_bytes = [0_u8; GuardCacheKey::LENGTH];
    key_bytes.copy_from_slice(bytes.as_slice());
    let key = GuardCacheKey::from_bytes(key_bytes);
    key_bytes.zeroize();
    key.map_err(|error| {
        eyre!(
            "invalid guard cache authentication key file `{}`: {error}",
            path.display()
        )
    })
}
fn load_guard_set(path: &Path, key: Option<&GuardCacheKey>) -> Result<Option<GuardSet>> {
    let key = key.ok_or_else(|| eyre!("guard cache authentication key is required"))?;
    let named_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .wrap_err_with(|| format!("failed to inspect guard cache `{}`", path.display()));
        }
    };
    if named_metadata.file_type().is_symlink() {
        return Err(eyre!(
            "guard cache `{}` must be a direct owner-private file",
            path.display()
        ));
    }
    let direct_path = canonical_guard_cache_path(path, false)?;
    let bytes = read_owner_private_handshake_file(
        &direct_path,
        GUARD_CACHE_MAX_BYTES_V1,
        None,
        "guard cache",
    )?;
    let guard_set = GuardSet::decode_authenticated(&bytes, key).map_err(|err| {
        eyre!(
            "failed to decode guard cache from `{}`: {err}",
            path.display()
        )
    })?;
    Ok(Some(guard_set))
}
fn persist_guard_set(path: &Path, guard_set: &GuardSet, key: Option<&GuardCacheKey>) -> Result<()> {
    let key = key.ok_or_else(|| eyre!("guard cache authentication key is required"))?;
    let payload = guard_set
        .encode_authenticated(key)
        .map_err(|err| eyre!("failed to encode guard cache: {err}"))?;
    if payload.is_empty() || payload.len() > GUARD_CACHE_MAX_BYTES_V1 {
        return Err(eyre!(
            "encoded guard cache must contain between 1 and {GUARD_CACHE_MAX_BYTES_V1} bytes"
        ));
    }
    persist_owner_private_guard_cache(path, &payload)
}
#[cfg(unix)]
fn canonical_guard_cache_path(path: &Path, create_parent: bool) -> Result<PathBuf> {
    let file_name = match path.components().next_back() {
        Some(std::path::Component::Normal(file_name)) => file_name,
        _ => {
            return Err(eyre!(
                "guard cache path `{}` must name a regular file",
                path.display()
            ));
        }
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if create_parent {
        fs::create_dir_all(parent).wrap_err_with(|| {
            format!(
                "failed to create guard cache directory `{}`",
                parent.display()
            )
        })?;
    }
    let canonical_parent = fs::canonicalize(parent).wrap_err_with(|| {
        format!(
            "failed to canonicalize guard cache directory `{}`",
            parent.display()
        )
    })?;
    validate_guard_cache_parent_chain(&canonical_parent)?;
    Ok(canonical_parent.join(file_name))
}
#[cfg(not(unix))]
fn canonical_guard_cache_path(path: &Path, _create_parent: bool) -> Result<PathBuf> {
    Err(eyre!(
        "guard cache `{}` is unsupported because this platform does not expose the required owner/mode/link custody checks",
        path.display()
    ))
}
#[cfg(unix)]
fn validate_guard_cache_parent_chain(parent: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let effective_uid = rustix::process::geteuid().as_raw();
    let mut ancestors = parent
        .ancestors()
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    ancestors.reverse();
    let mut metadata = Vec::with_capacity(ancestors.len());
    for ancestor in &ancestors {
        let observed = fs::symlink_metadata(ancestor).wrap_err_with(|| {
            format!(
                "failed to inspect guard cache directory ancestor `{}`",
                ancestor.display()
            )
        })?;
        if observed.file_type().is_symlink() || !observed.is_dir() {
            return Err(eyre!(
                "guard cache directory ancestor `{}` must be a direct directory",
                ancestor.display()
            ));
        }
        if observed.uid() != 0 && observed.uid() != effective_uid {
            return Err(eyre!(
                "guard cache directory ancestor `{}` must be owned by root or effective UID {effective_uid}",
                ancestor.display()
            ));
        }
        metadata.push(observed);
    }
    for (index, observed) in metadata.iter().enumerate() {
        if observed.mode() & 0o022 == 0 {
            continue;
        }
        let protected_sticky_boundary = observed.uid() == 0
            && observed.mode() & 0o1000 != 0
            && metadata
                .get(index + 1)
                .is_some_and(|child| child.uid() == effective_uid && child.mode() & 0o022 == 0);
        if !protected_sticky_boundary {
            return Err(eyre!(
                "guard cache directory ancestor `{}` is writable by another principal",
                ancestors[index].display()
            ));
        }
    }
    let parent_metadata = metadata
        .last()
        .ok_or_else(|| eyre!("guard cache path has no parent directory metadata"))?;
    if parent_metadata.uid() != effective_uid || parent_metadata.mode() & 0o022 != 0 {
        return Err(eyre!(
            "guard cache directory `{}` must be owned by effective UID {effective_uid} and not be group/world writable",
            parent.display()
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn validate_guard_cache_destination(metadata: &fs::Metadata, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(eyre!(
            "guard cache `{}` must be an owner-private regular non-symlink file with exactly one link",
            path.display()
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn same_guard_cache_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.nlink() == 1
        && right.nlink() == 1
        && left.len() == right.len()
}
#[cfg(unix)]
fn persist_owner_private_guard_cache(path: &Path, payload: &[u8]) -> Result<()> {
    let direct_path = canonical_guard_cache_path(path, true)?;
    match fs::symlink_metadata(&direct_path) {
        Ok(metadata) => validate_guard_cache_destination(&metadata, &direct_path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).wrap_err_with(|| {
                format!(
                    "failed to inspect existing guard cache `{}`",
                    direct_path.display()
                )
            });
        }
    }

    let parent = direct_path
        .parent()
        .ok_or_else(|| eyre!("guard cache path has no parent directory"))?;
    let mut nonce = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|error| eyre!("failed to generate guard cache staging name: {error}"))?;
    let staging_path = parent.join(format!(".guard-cache-{}.tmp", hex::encode(nonce)));
    nonce.zeroize();
    let descriptor = rustix::fs::open(
        &staging_path,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .wrap_err_with(|| {
        format!(
            "failed to create owner-private guard cache staging file `{}`",
            staging_path.display()
        )
    })?;
    let mut staging = fs::File::from(descriptor);
    let write_result = (|| -> Result<()> {
        rustix::fs::fchmod(&staging, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
            .wrap_err_with(|| {
                format!(
                    "failed to enforce owner-private guard cache staging permissions `{}`",
                    staging_path.display()
                )
            })?;
        let created_metadata = staging.metadata().wrap_err_with(|| {
            format!(
                "failed to inspect guard cache staging file `{}`",
                staging_path.display()
            )
        })?;
        validate_guard_cache_destination(&created_metadata, &staging_path)?;
        staging.write_all(payload).wrap_err_with(|| {
            format!(
                "failed to write guard cache staging file `{}`",
                staging_path.display()
            )
        })?;
        staging.sync_all().wrap_err_with(|| {
            format!(
                "failed to sync guard cache staging file `{}`",
                staging_path.display()
            )
        })?;
        let staged_metadata = staging.metadata().wrap_err_with(|| {
            format!(
                "failed to re-inspect guard cache staging file `{}`",
                staging_path.display()
            )
        })?;
        validate_guard_cache_destination(&staged_metadata, &staging_path)?;
        if staged_metadata.len() != u64::try_from(payload.len()).unwrap_or(u64::MAX) {
            return Err(eyre!(
                "guard cache staging file `{}` changed while it was written",
                staging_path.display()
            ));
        }
        fs::rename(&staging_path, &direct_path).wrap_err_with(|| {
            format!(
                "failed to atomically replace guard cache `{}`",
                direct_path.display()
            )
        })?;
        let published_metadata = fs::symlink_metadata(&direct_path).wrap_err_with(|| {
            format!(
                "failed to inspect published guard cache `{}`",
                direct_path.display()
            )
        })?;
        validate_guard_cache_destination(&published_metadata, &direct_path)?;
        if !same_guard_cache_file_identity(&staged_metadata, &published_metadata) {
            return Err(eyre!(
                "published guard cache `{}` does not match the staged file",
                direct_path.display()
            ));
        }
        Ok(())
    })();
    if write_result.is_err() {
        drop(staging);
        let _ = fs::remove_file(&staging_path);
    }
    write_result
}
#[cfg(not(unix))]
fn persist_owner_private_guard_cache(path: &Path, _payload: &[u8]) -> Result<()> {
    Err(eyre!(
        "guard cache `{}` is unsupported because this platform does not expose the required owner/mode/link custody checks",
        path.display()
    ))
}
fn load_guard_directory(
    path: &Path,
    expected_snapshot_digest_hex: &str,
    at_unix: i64,
) -> Result<RelayDirectory> {
    let bytes = read_guard_directory_snapshot_file(path)
        .wrap_err_with(|| format!("failed to read guard directory from `{}`", path.display()))?;
    let expected_digest = parse_snapshot_digest_hex(expected_snapshot_digest_hex)?;
    RelayDirectory::from_guard_directory_bytes_at(&bytes, expected_digest, at_unix).map_err(|err| {
        eyre!(
            "failed to authenticate guard directory from `{}`: {err} (expected pinned SRCv2 Norito snapshot)",
            path.display(),
        )
    })
}
#[derive(Debug, Clone, norito::json::JsonSerialize)]
struct GuardDirectorySummary {
    version: u8,
    snapshot_digest_hex: String,
    authentication: &'static str,
    directory_hash_hex: Option<String>,
    published_at_unix: Option<i64>,
    valid_after_unix: Option<i64>,
    valid_until_unix: Option<i64>,
    issuer_count: usize,
    relay_count: usize,
    entry_guards: usize,
    entry_guards_pq: usize,
    entry_guard_pq_ratio: f64,
    exit_relays: usize,
    pq_handshake_relays: usize,
    snapshot_size_bytes: usize,
}
impl GuardDirectorySummary {
    fn from_components(
        snapshot: &GuardDirectorySnapshotV2,
        directory: &RelayDirectory,
        snapshot_size_bytes: usize,
        snapshot_digest_hex: String,
        authenticated: bool,
    ) -> Self {
        let mut entry_guards = 0usize;
        let mut pq_entry_guards = 0usize;
        let mut exit_relays = 0usize;
        let mut pq_handshake_relays = 0usize;
        for descriptor in directory.entries() {
            if descriptor.is_entry_guard() {
                entry_guards += 1;
                if descriptor.is_pq_capable() {
                    pq_entry_guards += 1;
                }
            }
            if descriptor.roles.exit() {
                exit_relays += 1;
            }
            if descriptor.is_pq_capable() {
                pq_handshake_relays += 1;
            }
        }
        #[allow(clippy::cast_precision_loss)]
        let pq_ratio = if entry_guards == 0 {
            0.0
        } else {
            pq_entry_guards as f64 / entry_guards as f64
        };
        Self {
            version: snapshot.version,
            snapshot_digest_hex,
            authentication: if authenticated {
                "authenticated"
            } else {
                "structural_inspection_only"
            },
            directory_hash_hex: directory.directory_hash().map(hex::encode),
            published_at_unix: directory.published_at(),
            valid_after_unix: directory.valid_after(),
            valid_until_unix: directory.valid_until(),
            issuer_count: snapshot.issuers.len(),
            relay_count: directory.entries().len(),
            entry_guards,
            entry_guards_pq: pq_entry_guards,
            entry_guard_pq_ratio: pq_ratio,
            exit_relays,
            pq_handshake_relays,
            snapshot_size_bytes,
        }
    }
}
fn inspect_guard_directory_bytes(bytes: &[u8]) -> Result<GuardDirectorySummary> {
    let snapshot = GuardDirectorySnapshotV2::inspect_bytes(bytes)
        .wrap_err("failed to decode guard directory snapshot")?;
    let directory = RelayDirectory::inspect_guard_directory_bytes(bytes)
        .wrap_err("guard directory structural inspection failed")?;
    Ok(GuardDirectorySummary::from_components(
        &snapshot,
        &directory,
        bytes.len(),
        hex::encode(compute_snapshot_digest(bytes)),
        false,
    ))
}
fn authenticate_guard_directory_bytes(
    bytes: &[u8],
    expected_snapshot_digest_hex: &str,
    at_unix: i64,
) -> Result<GuardDirectorySummary> {
    let expected_digest = parse_snapshot_digest_hex(expected_snapshot_digest_hex)?;
    let snapshot = GuardDirectorySnapshotV2::authenticate_bytes_at(bytes, expected_digest, at_unix)
        .wrap_err("failed to authenticate guard directory snapshot")?;
    let directory = RelayDirectory::from_guard_directory_bytes_at(bytes, expected_digest, at_unix)
        .wrap_err("guard directory authentication failed")?;
    Ok(GuardDirectorySummary::from_components(
        &snapshot,
        &directory,
        bytes.len(),
        hex::encode(expected_digest),
        true,
    ))
}
fn parse_snapshot_digest_hex(value: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim();
    if trimmed.len() != 64 {
        return Err(eyre!(
            "snapshot digest must contain 64 hex characters (got length {})",
            trimmed.len()
        ));
    }
    if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(eyre!(
            "snapshot digest `{trimmed}` must only contain hexadecimal characters"
        ));
    }
    let decoded = hex::decode(trimmed).wrap_err("failed to decode snapshot digest")?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&decoded);
    Ok(digest)
}
fn write_guard_directory_snapshot(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        return Err(eyre!(
            "refusing to overwrite existing guard directory snapshot `{}` (pass --overwrite to replace)",
            path.display()
        ));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).wrap_err_with(|| {
            format!(
                "failed to create parent directory `{}` for guard directory snapshot",
                parent.display()
            )
        })?;
    }
    fs::write(path, bytes).wrap_err_with(|| {
        format!(
            "failed to write guard directory snapshot to `{}`",
            path.display()
        )
    })
}
fn parse_transport_policy_flag(
    value: Option<&String>,
    flag: &'static str,
) -> Result<Option<TransportPolicy>> {
    if let Some(raw) = value {
        if raw.is_empty() {
            return Err(eyre!("{flag} must not be empty"));
        }
        TransportPolicy::parse(raw)
            .ok_or_else(|| {
                eyre!("{flag} must be one of `soranet-first`, `soranet-strict`, or `direct-only`")
            })
            .map(Some)
    } else {
        Ok(None)
    }
}
fn parse_anonymity_policy_flag(
    value: Option<&String>,
    flag: &'static str,
) -> Result<Option<AnonymityPolicy>> {
    if let Some(raw) = value {
        if raw.is_empty() {
            return Err(eyre!("{flag} must not be empty"));
        }
        AnonymityPolicy::parse(raw)
            .ok_or_else(|| {
                eyre!(
                    "{flag} must be one of `anon-guard-pq`, `anon-majority-pq`, or \
                     `anon-strict-pq`"
                )
            })
            .map(Some)
    } else {
        Ok(None)
    }
}
fn parse_write_mode_flag(
    value: Option<&String>,
    flag: &'static str,
) -> Result<Option<WriteModeHint>> {
    if let Some(raw) = value {
        if raw.is_empty() {
            return Err(eyre!("{flag} must not be empty"));
        }
        WriteModeHint::parse(raw)
            .ok_or_else(|| eyre!("{flag} must be one of `read-only` or `upload-pq-only`"))
            .map(Some)
    } else {
        Ok(None)
    }
}
fn validate_hex_digest(value: &str, flag: &str) -> Result<String> {
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(eyre!("{flag} must be 64 hex characters"));
    }
    Ok(value.to_ascii_lowercase())
}
fn anonymity_policy_label(policy: AnonymityPolicy) -> &'static str {
    match policy {
        AnonymityPolicy::GuardPq => "anon-guard-pq",
        AnonymityPolicy::MajorityPq => "anon-majority-pq",
        AnonymityPolicy::StrictPq => "anon-strict-pq",
    }
}
impl_run_for_subcommand!(#[allow(clippy::too_many_lines)] Command => Pin, Alias, Replication, Storage, Gateway, Incentives, Handshake, Toolkit, GuardDirectory, Reserve, Appeals, Gar, Transparency, Moderation, Repair, Billing, Hedging, Gc, Fetch);
#[derive(clap::Subcommand, Debug)]
pub enum IncentivesCommand {
    /// Compute a relay reward instruction from metrics and bond state.
    Compute(IncentivesComputeArgs),
    /// Open a dispute against an existing reward instruction.
    OpenDispute(IncentivesOpenDisputeArgs),
    /// Summarise reward instructions into an earnings dashboard.
    Dashboard(IncentivesDashboardArgs),
    /// Manage the persistent treasury payout state and disputes.
    #[command(subcommand)]
    Service(IncentivesServiceCommand),
}
impl_run_for_subcommand!(IncentivesCommand => Compute, OpenDispute, Dashboard, Service);
#[derive(clap::Args, Debug)]
pub struct IncentivesComputeArgs {
    /// Path to the reward configuration JSON.
    #[arg(long = "config", value_name = "PATH")]
    pub config: PathBuf,
    /// Norito-encoded relay metrics (`RelayEpochMetricsV1`).
    #[arg(long = "metrics", value_name = "PATH")]
    pub metrics: PathBuf,
    /// Norito-encoded bond ledger entry (`RelayBondLedgerEntryV1`).
    #[arg(long = "bond", value_name = "PATH")]
    pub bond: PathBuf,
    /// Account ID that will receive the payout.
    #[arg(long = "beneficiary", value_name = "ACCOUNT_ID")]
    pub beneficiary: String,
    /// Optional path where the Norito-encoded reward instruction will be written.
    #[arg(long = "norito-out", value_name = "PATH")]
    pub norito_out: Option<PathBuf>,
    /// Emit pretty-printed JSON.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesComputeArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let config = read_reward_config(&self.config)?;
        let engine = RelayRewardEngine::new(config)
            .map_err(|err| eyre!("invalid reward configuration: {err}"))?;
        let metrics = read_metrics_file(&self.metrics)?;
        let bond = read_bond_entry(&self.bond)?;
        let beneficiary = parse_account_id_str(context, &self.beneficiary, "--beneficiary")?;
        let instruction = engine.compute_reward(&metrics, &bond, beneficiary, Metadata::default());
        if let Some(path) = &self.norito_out {
            write_norito_payload(path, &instruction)?;
        }
        let json_bytes = if self.pretty {
            norito::json::to_vec_pretty(&instruction)?
        } else {
            norito::json::to_vec(&instruction)?
        };
        let output = String::from_utf8(json_bytes)
            .map_err(|err| eyre!("instruction JSON is not valid UTF-8: {err}"))?;
        context.println(output)
    }
}
#[derive(clap::Args, Debug)]
pub struct IncentivesOpenDisputeArgs {
    /// Norito-encoded reward instruction (`RelayRewardInstructionV1`).
    #[arg(long = "instruction", value_name = "PATH")]
    pub instruction: PathBuf,
    /// Account ID submitting the dispute.
    #[arg(long = "submitted-by", value_name = "ACCOUNT_ID")]
    pub submitted_by: String,
    /// Requested adjustment quantity.
    #[arg(long = "requested-amount", value_name = "QUANTITY")]
    pub requested_amount: String,
    /// Reason provided by the operator.
    #[arg(long = "reason", value_name = "TEXT")]
    pub reason: String,
    /// Optional UNIX timestamp when the dispute is filed.
    #[arg(long = "submitted-at", value_name = "SECONDS")]
    pub submitted_at: Option<u64>,
    /// Optional path where the Norito-encoded dispute will be written.
    #[arg(long = "norito-out", value_name = "PATH")]
    pub norito_out: Option<PathBuf>,
    /// Emit pretty-printed JSON.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesOpenDisputeArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let instruction = read_reward_instruction(&self.instruction)?;
        let submitted_by = parse_account_id_str(context, &self.submitted_by, "--submitted-by")?;
        let requested_amount = parse_quantity_str(&self.requested_amount, "--requested-amount")?;
        let submitted_at = self.submitted_at.unwrap_or_else(unix_now);
        let dispute = RelayPayoutLedger::open_dispute(
            instruction,
            requested_amount,
            submitted_by,
            submitted_at,
            self.reason,
        );
        if let Some(path) = &self.norito_out {
            write_norito_payload(path, &dispute)?;
        }
        if context.output_format() == crate::CliOutputFormat::Json {
            return context.print_data(&dispute);
        }
        let json_bytes = if self.pretty {
            norito::json::to_vec_pretty(&dispute)?
        } else {
            norito::json::to_vec(&dispute)?
        };
        let output = String::from_utf8(json_bytes)
            .map_err(|err| eyre!("dispute JSON is not valid UTF-8: {err}"))?;
        context.println_data(output)
    }
}
#[derive(clap::Args, Debug)]
pub struct IncentivesDashboardArgs {
    /// Reward instruction payloads to include in the dashboard.
    #[arg(
        long = "instruction",
        value_name = "PATH",
        required = true,
        num_args = 1..
    )]
    pub instructions: Vec<PathBuf>,
}
impl Run for IncentivesDashboardArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let mut accumulator = RelayEarningsAccumulator::default();
        for path in &self.instructions {
            let instruction = read_reward_instruction(path)?;
            accumulator.record(&instruction)?;
        }
        let mut rows: Vec<_> = accumulator
            .entries()
            .iter()
            .map(|(relay_id, entry)| IncentivesDashboardRow {
                relay: hex::encode(relay_id),
                payout_count: entry.payout_count,
                payout_amount: entry.payout_amount.clone(),
            })
            .collect();
        rows.sort_by(|a, b| a.relay.cmp(&b.relay));
        let total_payout = rows.iter().try_fold(Quantity::zero(), |acc, row| {
            acc.checked_add(&row.payout_amount)
        })?;
        let summary = IncentivesDashboardSummary {
            total_relays: rows.len(),
            total_payout,
            rows,
        };
        context.print_data(&summary)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum IncentivesServiceCommand {
    /// Initialise a new payout ledger state file.
    Init(IncentivesServiceInitArgs),
    /// Evaluate metrics, record the payout, and persist the updated state.
    Process(IncentivesServiceProcessArgs),
    /// Record an externally prepared reward instruction into the state.
    Record(IncentivesServiceRecordArgs),
    /// Manage payout disputes recorded in the state.
    #[command(subcommand)]
    Dispute(IncentivesServiceDisputeCommand),
    /// Render an earnings dashboard sourced from the persisted ledger.
    Dashboard(IncentivesServiceDashboardArgs),
    /// Audit bond/payout governance readiness for relay incentives.
    Audit(IncentivesServiceAuditArgs),
    /// Run a shadow simulation across relay metrics and summarise fairness.
    ShadowRun(IncentivesServiceShadowRunArgs),
    /// Reconcile recorded payouts against XOR ledger exports.
    Reconcile(IncentivesServiceReconcileArgs),
    /// Run the treasury daemon against a metrics spool.
    Daemon(IncentivesServiceDaemonArgs),
}
impl_run_for_subcommand!(IncentivesServiceCommand => Init, Process, Record, Dispute, Dashboard, Audit, ShadowRun, Reconcile, Daemon);
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceInitArgs {
    /// Path where the incentives state JSON will be stored.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Reward configuration JSON consumed by the payout engine.
    #[arg(long = "config", value_name = "PATH")]
    pub config: PathBuf,
    /// Treasury account debited when materialising payouts.
    #[arg(long = "treasury-account", value_name = "ACCOUNT_ID")]
    pub treasury_account: String,
    /// Overwrite an existing state file if it already exists.
    #[arg(long = "force", default_value_t = false)]
    pub force: bool,
}
impl Run for IncentivesServiceInitArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if self.state.exists() && !self.force {
            return Err(eyre!(
                "state file `{}` already exists (pass --force to overwrite)",
                self.state.display()
            ));
        }
        let config = read_reward_config(&self.config)?;
        if config.budget_approval_id.is_none() {
            return Err(eyre!(
                "reward_config.budget_approval_id is required for incentives"
            ));
        }
        let treasury_account =
            parse_account_id_str(context, &self.treasury_account, "--treasury-account")?;
        let state = IncentivesState::new(&config, treasury_account);
        save_incentives_state(&self.state, &state)?;
        context.println(format_args!(
            "initialised incentives state at `{}`",
            self.state.display()
        ))
    }
}
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceProcessArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Norito-encoded relay metrics (`RelayEpochMetricsV1`).
    #[arg(long = "metrics", value_name = "PATH", num_args = 1..)]
    pub metrics: Vec<PathBuf>,
    /// Norito-encoded bond ledger entry (`RelayBondLedgerEntryV1`).
    #[arg(long = "bond", value_name = "PATH", num_args = 1..)]
    pub bond: Vec<PathBuf>,
    /// Beneficiary account that receives the payout.
    #[arg(long = "beneficiary", value_name = "ACCOUNT_ID", num_args = 1..)]
    pub beneficiary: Vec<String>,
    /// Write the Norito-encoded reward instruction to this path.
    #[arg(long = "instruction-out", value_name = "PATH")]
    pub instruction_out: Option<PathBuf>,
    /// Write the Norito-encoded transfer instruction to this path.
    #[arg(long = "transfer-out", value_name = "PATH")]
    pub transfer_out: Option<PathBuf>,
    /// Submit the resulting transfer to Torii after recording the payout.
    #[arg(long = "submit-transfer", default_value_t = false)]
    pub submit_transfer: bool,
    /// Emit pretty JSON instead of a compact payload.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesServiceProcessArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if self.metrics.is_empty() {
            return Err(eyre!("at least one --metrics file must be provided"));
        }
        let (mut state, mut service) = load_state_service(&self.state)?;
        let budget_approval_id =
            require_budget_approval_id(state.reward_config.budget_approval_id.as_ref())?;
        let metrics: Vec<_> = self
            .metrics
            .iter()
            .map(|path| read_metrics_file(path.as_path()))
            .collect::<Result<_, _>>()?;
        let metrics_count = metrics.len();
        let bonds: Vec<_> = if self.bond.is_empty() {
            return Err(eyre!("at least one --bond file must be provided"));
        } else if self.bond.len() == 1 {
            let entry = read_bond_entry(&self.bond[0])?;
            vec![entry; metrics_count]
        } else if self.bond.len() == metrics_count {
            self.bond
                .iter()
                .map(|path| read_bond_entry(path.as_path()))
                .collect::<Result<_, _>>()?
        } else {
            return Err(eyre!(
                "number of --bond entries ({}) must be 1 or match the number of --metrics entries ({})",
                self.bond.len(),
                metrics_count
            ));
        };
        let beneficiaries: Vec<_> = if self.beneficiary.is_empty() {
            return Err(eyre!("at least one --beneficiary value must be provided"));
        } else if self.beneficiary.len() == 1 {
            let account = parse_account_id_str(context, &self.beneficiary[0], "--beneficiary")?;
            vec![account; metrics_count]
        } else if self.beneficiary.len() == metrics_count {
            self.beneficiary
                .iter()
                .map(|value| parse_account_id_str(context, value, "--beneficiary"))
                .collect::<Result<_, _>>()?
        } else {
            return Err(eyre!(
                "number of --beneficiary values ({}) must be 1 or match the number of --metrics entries ({})",
                self.beneficiary.len(),
                metrics_count
            ));
        };
        if metrics_count > 1 && (self.instruction_out.is_some() || self.transfer_out.is_some()) {
            return Err(eyre!(
                "`--instruction-out` and `--transfer-out` are only supported when processing a single metrics entry"
            ));
        }
        let inputs: Vec<_> = metrics
            .iter()
            .zip(bonds.iter())
            .zip(beneficiaries.iter())
            .map(|((metrics, bond), beneficiary)| PayoutInput {
                metrics,
                bond_entry: bond,
                beneficiary: beneficiary.clone(),
                metadata: Metadata::default(),
            })
            .collect();
        let outcomes = service
            .process_batch(inputs)
            .map_err(|err| eyre!("failed to process epoch: {err}"))?;
        if metrics_count == 1 {
            if let Some(path) = &self.instruction_out {
                write_norito_payload(path, &outcomes[0].instruction)?;
            }
            if let Some(path) = &self.transfer_out {
                write_norito_payload(path, &outcomes[0].transfer)?;
            }
        }
        let mut transfers_to_submit = Vec::new();
        let mut summaries = Vec::new();
        for outcome in &outcomes {
            ensure_instruction_budget_approval(&outcome.instruction, &budget_approval_id)?;
            if self.submit_transfer && !outcome.instruction.is_zero_amount() {
                transfers_to_submit.push(outcome.transfer.clone());
            }
            store_payout_instruction(&mut state, &outcome.instruction);
            let snapshot = ServiceLedgerSnapshot::from_snapshot(&outcome.ledger_snapshot);
            summaries.push(ServicePayoutSummary::new(&outcome.instruction, snapshot));
        }
        save_incentives_state(&self.state, &state)?;
        if self.submit_transfer && !transfers_to_submit.is_empty() {
            context
                .finish(transfers_to_submit)
                .wrap_err("failed to submit payout transfer")?;
        }
        if summaries.len() == 1 {
            output_summary(context, &summaries[0], self.pretty)
        } else {
            output_summary(context, &summaries, self.pretty)
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceRecordArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Norito-encoded reward instruction to record.
    #[arg(long = "instruction", value_name = "PATH")]
    pub instruction: PathBuf,
    /// Write the Norito-encoded transfer instruction to this path if non-zero.
    #[arg(long = "transfer-out", value_name = "PATH")]
    pub transfer_out: Option<PathBuf>,
    /// Submit the transfer to Torii after recording the payout.
    #[arg(long = "submit-transfer", default_value_t = false)]
    pub submit_transfer: bool,
    /// Emit pretty JSON instead of a compact payload.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesServiceRecordArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let instruction = read_reward_instruction(&self.instruction)?;
        let (mut state, mut service) = load_state_service(&self.state)?;
        let budget_approval_id =
            require_budget_approval_id(state.reward_config.budget_approval_id.as_ref())?;
        ensure_instruction_budget_approval(&instruction, &budget_approval_id)?;
        let transfer_instruction = service.payout_ledger().to_transfer(&instruction);
        if self.submit_transfer
            && !instruction.is_zero_amount()
            && let Some(transfer) = transfer_instruction.as_ref()
        {
            context
                .finish(vec![transfer.clone()])
                .wrap_err("failed to submit payout transfer")?;
        }
        service
            .record_reward(instruction.clone())
            .map_err(|err| eyre!("failed to record reward instruction: {err}"))?;
        if let (Some(path), Some(transfer)) = (&self.transfer_out, transfer_instruction.clone()) {
            write_norito_payload(path, &transfer)?;
        }
        let dashboard = service
            .earnings_dashboard()
            .map_err(|err| eyre!("failed to build earnings dashboard: {err}"))?;
        let ledger = dashboard
            .rows
            .iter()
            .find(|row| row.relay_id == instruction.relay_id)
            .map(ServiceLedgerSnapshot::from_row)
            .ok_or_else(|| eyre!("recorded relay not present in earnings dashboard"))?;
        store_payout_instruction(&mut state, &instruction);
        save_incentives_state(&self.state, &state)?;
        let summary = ServicePayoutSummary::new(&instruction, ledger);
        output_summary(context, &summary, self.pretty)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum IncentivesServiceDisputeCommand {
    /// File a new dispute against a recorded payout.
    File(IncentivesServiceDisputeFileArgs),
    /// Resolve a dispute with the supplied outcome.
    Resolve(IncentivesServiceDisputeResolveArgs),
    /// Reject a dispute without altering the ledger.
    Reject(IncentivesServiceDisputeRejectArgs),
}
impl_run_for_subcommand!(IncentivesServiceDisputeCommand => File, Resolve, Reject);
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceDisputeFileArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Hex-encoded relay identifier (32 bytes, 64 hex chars).
    #[arg(long = "relay-id", value_name = "HEX")]
    pub relay_id: String,
    /// Epoch number associated with the disputed payout.
    #[arg(long = "epoch", value_name = "EPOCH")]
    pub epoch: u32,
    /// Account ID submitting the dispute.
    #[arg(long = "submitted-by", value_name = "ACCOUNT_ID")]
    pub submitted_by: String,
    /// Requested payout quantity.
    #[arg(long = "requested-amount", value_name = "QUANTITY")]
    pub requested_amount: String,
    /// Free-form reason describing the dispute.
    #[arg(long = "reason", value_name = "TEXT")]
    pub reason: String,
    /// Optional UNIX timestamp indicating when the dispute was filed (defaults to now).
    #[arg(long = "filed-at", value_name = "SECONDS")]
    pub filed_at: Option<u64>,
    /// Credit adjustment requested by the operator.
    #[arg(
        long = "adjust-credit",
        value_name = "QUANTITY",
        conflicts_with = "adjust_debit"
    )]
    pub adjust_credit: Option<String>,
    /// Debit adjustment requested by the operator.
    #[arg(
        long = "adjust-debit",
        value_name = "QUANTITY",
        conflicts_with = "adjust_credit"
    )]
    pub adjust_debit: Option<String>,
    /// Write the Norito-encoded dispute payload to this path.
    #[arg(long = "norito-out", value_name = "PATH")]
    pub norito_out: Option<PathBuf>,
    /// Emit pretty JSON instead of a compact payload.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesServiceDisputeFileArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let (mut state, mut service) = load_state_service(&self.state)?;
        let relay_id = relay_id_from_hex(&self.relay_id)?;
        let submitted_by = parse_account_id_str(context, &self.submitted_by, "--submitted-by")?;
        let requested_amount = parse_quantity_str(&self.requested_amount, "--requested-amount")?;
        let requested_adjustment =
            parse_adjustment_flags(self.adjust_credit.as_ref(), self.adjust_debit.as_ref())?;
        let filed_at = self.filed_at.unwrap_or_else(unix_now);
        let dispute = service
            .file_dispute(
                relay_id,
                self.epoch,
                submitted_by,
                requested_amount,
                self.reason,
                filed_at,
                requested_adjustment,
            )
            .map_err(|err| eyre!("failed to file dispute: {err}"))?;
        if let Some(path) = &self.norito_out {
            write_norito_payload(path, dispute.norito_record())?;
        }
        upsert_dispute_record(&mut state, &dispute);
        save_incentives_state(&self.state, &state)?;
        let record = StoredDisputeRecord::from(&dispute);
        output_summary(context, &record, self.pretty)
    }
}
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum IncentivesDisputeResolutionKind {
    #[clap(name = "no-change")]
    NoChange,
    #[clap(name = "credit")]
    Credit,
    #[clap(name = "debit")]
    Debit,
}
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceDisputeResolveArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Dispute identifier to resolve.
    #[arg(long = "dispute-id", value_name = "ID")]
    pub dispute_id: DisputeId,
    /// Resolution kind (`no-change`, `credit`, or `debit`).
    #[arg(long = "resolution", value_enum)]
    pub resolution: IncentivesDisputeResolutionKind,
    /// Amount applied when resolving with `credit` or `debit`.
    #[arg(long = "amount", value_name = "QUANTITY")]
    pub amount: Option<String>,
    /// Resolution notes recorded in the dispute metadata.
    #[arg(long = "notes", value_name = "TEXT")]
    pub notes: String,
    /// Optional UNIX timestamp when the dispute was resolved (defaults to now).
    #[arg(long = "resolved-at", value_name = "SECONDS")]
    pub resolved_at: Option<u64>,
    /// Write the Norito-encoded transfer instruction generated by the resolution (if any).
    #[arg(long = "transfer-out", value_name = "PATH")]
    pub transfer_out: Option<PathBuf>,
    /// Emit pretty JSON instead of a compact payload.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesServiceDisputeResolveArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let (mut state, mut service) = load_state_service(&self.state)?;
        let resolved_at = self.resolved_at.unwrap_or_else(unix_now);
        let resolution = match self.resolution {
            IncentivesDisputeResolutionKind::NoChange => {
                if self.amount.is_some() {
                    return Err(eyre!("--amount is not valid for no-change resolutions"));
                }
                DisputeResolution::NoChange {
                    notes: self.notes.clone(),
                }
            }
            IncentivesDisputeResolutionKind::Credit => {
                let amount = self
                    .amount
                    .as_ref()
                    .ok_or_else(|| eyre!("--amount is required for credit resolutions"))?;
                DisputeResolution::Credit {
                    amount: parse_quantity_str(amount, "--amount")?,
                    notes: self.notes.clone(),
                }
            }
            IncentivesDisputeResolutionKind::Debit => {
                let amount = self
                    .amount
                    .as_ref()
                    .ok_or_else(|| eyre!("--amount is required for debit resolutions"))?;
                DisputeResolution::Debit {
                    amount: parse_quantity_str(amount, "--amount")?,
                    notes: self.notes.clone(),
                }
            }
        };
        let outcome = service
            .resolve_dispute(self.dispute_id, resolution, resolved_at)
            .map_err(|err| eyre!("failed to resolve dispute: {err}"))?;
        if let (Some(path), Some(transfer)) = (&self.transfer_out, outcome.transfer.as_ref()) {
            write_norito_payload(path, transfer)?;
        }
        upsert_dispute_record(&mut state, &outcome.dispute);
        save_incentives_state(&self.state, &state)?;
        let record = StoredDisputeRecord::from(&outcome.dispute);
        output_summary(context, &record, self.pretty)
    }
}
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceDisputeRejectArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Dispute identifier to reject.
    #[arg(long = "dispute-id", value_name = "ID")]
    pub dispute_id: DisputeId,
    /// Rejection notes captured in the dispute metadata.
    #[arg(long = "notes", value_name = "TEXT")]
    pub notes: String,
    /// Optional UNIX timestamp when the dispute was rejected (defaults to now).
    #[arg(long = "rejected-at", value_name = "SECONDS")]
    pub rejected_at: Option<u64>,
    /// Emit pretty JSON instead of a compact payload.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesServiceDisputeRejectArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let (mut state, mut service) = load_state_service(&self.state)?;
        let rejected_at = self.rejected_at.unwrap_or_else(unix_now);
        let dispute = service
            .reject_dispute(self.dispute_id, rejected_at, self.notes.clone())
            .map_err(|err| eyre!("failed to reject dispute: {err}"))?;
        upsert_dispute_record(&mut state, &dispute);
        save_incentives_state(&self.state, &state)?;
        let record = StoredDisputeRecord::from(&dispute);
        output_summary(context, &record, self.pretty)
    }
}
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceDashboardArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
}
impl Run for IncentivesServiceDashboardArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let (_state, service) = load_state_service(&self.state)?;
        let dashboard = service
            .earnings_dashboard()
            .map_err(|err| eyre!("failed to build earnings dashboard: {err}"))?;
        let summary = ServiceDashboardSummary::new(&dashboard);
        context.print_data(&summary)
    }
}
#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq, Hash)]
pub enum IncentiveAuditScope {
    Bond,
    Budget,
    All,
}
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceAuditArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Daemon configuration describing relay beneficiaries and bond sources.
    #[arg(long = "config", value_name = "PATH")]
    pub config: PathBuf,
    /// Audit scopes to evaluate (repeat to combine); defaults to bond checks.
    #[arg(
        long = "scope",
        value_enum,
        default_values_t = vec![IncentiveAuditScope::Bond],
        action = clap::ArgAction::Append
    )]
    pub scopes: Vec<IncentiveAuditScope>,
    /// Emit pretty JSON instead of a compact payload.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesServiceAuditArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let state = load_incentives_state(&self.state)?;
        let config = load_daemon_config(&self.config, &|literal| {
            crate::resolve_account_id(context, literal)
        })?;
        let (audit_bond_enabled, audit_budget_enabled) = audit_scope_flags(&self.scopes);
        let mut summary = IncentivesAuditSummary::default();
        if audit_bond_enabled {
            let bond_summary = audit_bonds(&config, &state.reward_config)?;
            summary.bond = Some(bond_summary);
        }
        if audit_budget_enabled {
            let budget_summary = audit_budget(&state)?;
            summary.budget = Some(budget_summary);
        }
        let failures = summary.failure_count();
        output_summary(context, &summary, self.pretty)?;
        if failures > 0 {
            return Err(eyre!("incentives audit found {failures} issue(s)"));
        }
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceShadowRunArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Shadow simulation configuration mapping relays to beneficiaries and bonds.
    #[arg(long = "config", value_name = "PATH")]
    pub config: PathBuf,
    /// Directory containing Norito-encoded relay metrics snapshots (`relay-<id>-epoch-<n>.to`).
    #[arg(long = "metrics-dir", value_name = "PATH")]
    pub metrics_dir: PathBuf,
    /// Optional path to write the shadow simulation report JSON.
    #[arg(long = "report-out", value_name = "PATH")]
    pub report_out: Option<PathBuf>,
    /// Emit pretty JSON instead of a compact payload.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesServiceShadowRunArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let state = load_incentives_state(&self.state)?;
        let mut state_for_run = state.clone();
        let expected_budget =
            require_budget_approval_id(state.reward_config.budget_approval_id.as_ref())?;
        let mut service = build_clean_payout_service(&state_for_run)?;
        let config = load_daemon_config(&self.config, &|literal| {
            crate::resolve_account_id(context, literal)
        })?;
        let iteration_summary = process_daemon_iteration(
            &mut state_for_run,
            &mut service,
            &config,
            &self.metrics_dir,
            None,
            None,
            None,
            Some(&expected_budget),
        )?;
        if iteration_summary.missing_budget_approval > 0
            || iteration_summary.mismatched_budget_approval > 0
        {
            return Err(eyre!(
                "shadow run found {} payout(s) missing or mismatching budget_approval_id",
                iteration_summary
                    .missing_budget_approval
                    .saturating_add(iteration_summary.mismatched_budget_approval)
            ));
        }
        let report = build_shadow_run_summary(&iteration_summary);
        if let Some(path) = &self.report_out {
            let bytes = norito::json::to_vec_pretty(&report)
                .wrap_err("failed to serialise shadow run report")?;
            fs::write(path, &bytes).wrap_err_with(|| {
                format!("failed to write shadow run report to `{}`", path.display())
            })?;
        }
        output_summary(context, &report, self.pretty)
    }
}
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceReconcileArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Norito-encoded XOR ledger export to reconcile against.
    #[arg(long = "ledger-export", value_name = "PATH")]
    pub ledger_export: PathBuf,
    /// Emit pretty JSON instead of a compact payload.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesServiceReconcileArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let (_, service) = load_state_service(&self.state)?;
        let export = read_ledger_export(&self.ledger_export)?;
        let report = service.reconcile_ledger(&export.transfers);
        let summary = ReconciliationReportSummary::from_report(&report);
        output_summary(context, &summary, self.pretty)
    }
}
#[derive(clap::Args, Debug)]
pub struct IncentivesServiceDaemonArgs {
    /// Path to the persisted incentives state JSON.
    #[arg(long = "state", value_name = "PATH")]
    pub state: PathBuf,
    /// Daemon configuration describing relay beneficiaries and bond sources.
    #[arg(long = "config", value_name = "PATH")]
    pub config: PathBuf,
    /// Directory containing Norito-encoded relay metrics snapshots.
    #[arg(long = "metrics-dir", value_name = "PATH")]
    pub metrics_dir: PathBuf,
    /// Directory where reward instructions will be written.
    #[arg(long = "instruction-out-dir", value_name = "PATH")]
    pub instruction_out_dir: Option<PathBuf>,
    /// Directory where transfer instructions will be written.
    #[arg(long = "transfer-out-dir", value_name = "PATH")]
    pub transfer_out_dir: Option<PathBuf>,
    /// Directory where processed metrics snapshots will be archived.
    #[arg(long = "archive-dir", value_name = "PATH")]
    pub archive_dir: Option<PathBuf>,
    /// Poll interval (seconds) when running continuously.
    #[arg(long = "poll-interval", value_name = "SECONDS", default_value_t = 30)]
    pub poll_interval: u64,
    /// Process the spool once and exit (do not watch for changes).
    #[arg(long = "once", default_value_t = false)]
    pub once: bool,
    /// Emit JSON summaries instead of plain-text logs.
    ///
    /// Ignored when `--output-format json` is used.
    #[arg(long = "pretty", default_value_t = false)]
    pub pretty: bool,
}
impl Run for IncentivesServiceDaemonArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let config = load_daemon_config(&self.config, &|literal| {
            crate::resolve_account_id(context, literal)
        })?;
        if let Some(dir) = &self.instruction_out_dir {
            fs::create_dir_all(dir).wrap_err_with(|| {
                format!(
                    "failed to create instruction output directory `{}`",
                    dir.display()
                )
            })?;
        }
        if let Some(dir) = &self.transfer_out_dir {
            fs::create_dir_all(dir).wrap_err_with(|| {
                format!(
                    "failed to create transfer output directory `{}`",
                    dir.display()
                )
            })?;
        }
        if let Some(dir) = &self.archive_dir {
            fs::create_dir_all(dir).wrap_err_with(|| {
                format!("failed to create archive directory `{}`", dir.display())
            })?;
        }
        let poll_interval = self.poll_interval.max(1);
        let (mut state, mut service) = load_state_service(&self.state)?;
        let expected_budget =
            require_budget_approval_id(state.reward_config.budget_approval_id.as_ref())?;
        loop {
            let summary = process_daemon_iteration(
                &mut state,
                &mut service,
                &config,
                &self.metrics_dir,
                self.instruction_out_dir.as_deref(),
                self.transfer_out_dir.as_deref(),
                self.archive_dir.as_deref(),
                Some(&expected_budget),
            )?;
            if !summary.processed.is_empty() {
                save_incentives_state(&self.state, &state)?;
            }
            log_daemon_summary(context, &summary, self.pretty)?;
            if summary.missing_budget_approval > 0 || summary.mismatched_budget_approval > 0 {
                return Err(eyre!(
                    "daemon detected {} payout(s) missing or mismatching budget_approval_id",
                    summary
                        .missing_budget_approval
                        .saturating_add(summary.mismatched_budget_approval)
                ));
            }
            if self.once {
                break;
            }
            thread::sleep(Duration::from_secs(poll_interval));
        }
        Ok(())
    }
}
fn resolve_manifest_inputs<C: RunContext>(
    context: &mut C,
    args: &FetchArgs,
) -> Result<ManifestInputs> {
    let downloaded = maybe_download_manifest(context, args)?;
    merge_manifest_inputs(
        args.manifest.as_ref(),
        args.plan.as_ref(),
        args.manifest_id.as_ref(),
        downloaded.as_ref(),
    )
}
fn maybe_download_manifest<C: RunContext>(
    context: &mut C,
    args: &FetchArgs,
) -> Result<Option<DownloadedManifest>> {
    let needs_fetch = args.storage_ticket.is_some()
        && (args.manifest.is_none() || args.plan.is_none() || args.manifest_id.is_none());
    if !needs_fetch {
        return Ok(None);
    }
    let ticket = args
        .storage_ticket
        .as_ref()
        .expect("storage ticket present when fetch is required");
    let normalized_ticket = normalize_ticket_hex(ticket)?;
    let fetcher = DaManifestFetcher::new(context.config(), args.torii_url.as_deref())?;
    let bundle = fetcher.fetch(&normalized_ticket)?;
    let persisted = persist_manifest_bundle(
        context,
        &bundle,
        args.manifest_cache_dir.clone(),
        &normalized_ticket,
    )?;
    Ok(Some(DownloadedManifest {
        manifest_path: persisted.manifest_raw,
        plan_path: persisted.chunk_plan,
        manifest_id: bundle.manifest_hash_hex,
    }))
}
fn merge_manifest_inputs(
    manifest: Option<&PathBuf>,
    plan: Option<&PathBuf>,
    manifest_id: Option<&String>,
    fallback: Option<&DownloadedManifest>,
) -> Result<ManifestInputs> {
    let manifest_path = match manifest {
        Some(path) => path.clone(),
        None => fallback.map(|dl| dl.manifest_path.clone()).ok_or_else(|| {
            eyre!("--manifest is required unless `--storage-ticket` provides one")
        })?,
    };
    let plan_path = match plan {
        Some(path) => path.clone(),
        None => fallback
            .map(|dl| dl.plan_path.clone())
            .ok_or_else(|| eyre!("--plan is required unless `--storage-ticket` provides one"))?,
    };
    let manifest_id = match manifest_id {
        Some(id) => id.clone(),
        None => fallback.map(|dl| dl.manifest_id.clone()).ok_or_else(|| {
            eyre!("--manifest-id is required unless `--storage-ticket` provides one")
        })?,
    };
    Ok(ManifestInputs {
        manifest_path,
        plan_path,
        manifest_id,
    })
}
fn validate_manifest_envelope(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(eyre!("manifest envelope must not be empty"));
    }
    let envelope: HybridPayloadEnvelopeV1 =
        decode_from_bytes(bytes).wrap_err("failed to decode manifest envelope")?;
    if envelope.version != HYBRID_PAYLOAD_ENVELOPE_VERSION_V1 {
        return Err(eyre!(
            "manifest envelope version {} is not supported (expected {})",
            envelope.version,
            HYBRID_PAYLOAD_ENVELOPE_VERSION_V1
        ));
    }
    let suite = HybridSuite::from_str(&envelope.suite).map_err(|()| {
        eyre!(
            "unsupported hybrid suite `{}` in manifest envelope",
            envelope.suite
        )
    })?;
    if suite != HybridSuite::X25519MlKem768ChaCha20Poly1305 {
        return Err(eyre!(
            "manifest envelope must use the X25519+ML-KEM-768 suite"
        ));
    }
    if envelope.kem.ephemeral_public.is_empty()
        || envelope.kem.kyber_ciphertext.is_empty()
        || envelope.ciphertext.is_empty()
    {
        return Err(eyre!(
            "manifest envelope is missing required KEM or ciphertext fields"
        ));
    }
    Ok(())
}
fn load_manifest_envelope(path: &Path) -> Result<String> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read manifest envelope from `{}`", path.display()))?;
    validate_manifest_envelope(&bytes)?;
    Ok(STANDARD.encode(bytes))
}
#[cfg(test)]
mod fetch_args_manifest_tests {
    use super::{DownloadedManifest, merge_manifest_inputs};
    use std::path::PathBuf;
    #[test]
    fn merge_inputs_prefers_explicit_values() {
        let manifest = PathBuf::from("/tmp/manifest_explicit.to");
        let plan = PathBuf::from("/tmp/plan_explicit.json");
        let manifest_id = "11".repeat(32);
        let fallback = DownloadedManifest {
            manifest_path: PathBuf::from("/tmp/fallback_manifest.to"),
            plan_path: PathBuf::from("/tmp/fallback_plan.json"),
            manifest_id: "22".repeat(32),
        };
        let inputs = merge_manifest_inputs(
            Some(&manifest),
            Some(&plan),
            Some(&manifest_id),
            Some(&fallback),
        )
        .expect("inputs");
        assert_eq!(inputs.manifest_path, manifest);
        assert_eq!(inputs.plan_path, plan);
        assert_eq!(inputs.manifest_id, manifest_id);
    }
    #[test]
    fn merge_inputs_uses_fallback_when_missing() {
        let manifest_id = "aa".repeat(32);
        let fallback = DownloadedManifest {
            manifest_path: PathBuf::from("/tmp/fetched_manifest.to"),
            plan_path: PathBuf::from("/tmp/fetched_plan.json"),
            manifest_id: manifest_id.clone(),
        };
        let inputs =
            merge_manifest_inputs(None, None, None, Some(&fallback)).expect("resolved inputs");
        assert_eq!(inputs.manifest_path, fallback.manifest_path);
        assert_eq!(inputs.plan_path, fallback.plan_path);
        assert_eq!(inputs.manifest_id, manifest_id);
    }
    #[test]
    fn merge_inputs_errors_without_source() {
        let err = merge_manifest_inputs(None, None, None, None).expect_err("expected failure");
        assert_compact! { err.to_string().contains("`--storage-ticket` provides one"); "error message should mention storage ticket fallback" };
    }
}
#[cfg(test)]
mod manifest_envelope_tests {
    use super::{HybridSuite, load_manifest_envelope};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use iroha_crypto::HybridKeyPair;
    use norito::to_bytes;
    use rand::{SeedableRng, rngs::StdRng};
    use sorafs_manifest::hybrid_envelope::{
        HYBRID_PAYLOAD_ENVELOPE_VERSION_V1, HybridKemBundleV1, HybridPayloadEnvelopeV1,
        encrypt_payload,
    };
    use std::io::Write;
    use tempfile::NamedTempFile;
    #[test]
    fn load_manifest_envelope_rejects_empty_files() {
        let file = NamedTempFile::new().expect("temp file");
        let err = load_manifest_envelope(file.path()).expect_err("empty envelope must fail");
        assert_compact! { err.to_string().contains("must not be empty"); "error should mention empty envelope" };
    }
    #[test]
    fn load_manifest_envelope_encodes_valid_envelope() {
        let mut rng = StdRng::seed_from_u64(7);
        let key_pair = HybridKeyPair::generate(&mut rng).expect("generated hybrid keypair");
        let envelope = encrypt_payload(
            b"manifest payload",
            b"sorafs:manifest:test",
            key_pair.public(),
            &mut rng,
        )
        .expect("envelope encrypts");
        let mut file = NamedTempFile::new().expect("temp file");
        let encoded_bytes = to_bytes(&envelope).expect("encode envelope");
        file.write_all(&encoded_bytes).expect("write envelope");
        let encoded = load_manifest_envelope(file.path()).expect("manifest envelope should load");
        let expected = STANDARD.encode(encoded_bytes);
        assert_eq!(encoded, expected);
    }
    #[test]
    fn load_manifest_envelope_rejects_invalid_contents() {
        let mut file = NamedTempFile::new().expect("temp file");
        let envelope = HybridPayloadEnvelopeV1 {
            version: HYBRID_PAYLOAD_ENVELOPE_VERSION_V1,
            suite: HybridSuite::X25519MlKem768ChaCha20Poly1305.to_string(),
            kem: HybridKemBundleV1 {
                ephemeral_public: Vec::new(),
                kyber_ciphertext: Vec::new(),
            },
            nonce: [0u8; 12],
            ciphertext: Vec::new(),
        };
        let encoded = to_bytes(&envelope).expect("encode envelope");
        file.write_all(&encoded).expect("write envelope");
        let err =
            load_manifest_envelope(file.path()).expect_err("invalid manifest envelope must fail");
        assert_compact! { err.to_string().contains("manifest envelope is missing required KEM or ciphertext fields"); "error should call out missing fields" };
    }
}
#[cfg(test)]
mod cli_scoreboard_metadata_tests {
    use super::*;
    use norito::json::Value;
    #[test]
    fn cli_scoreboard_metadata_records_policy_overrides() {
        let value = cli_scoreboard_metadata(&ScoreboardMetadataInput {
            version: "executable-version",
            provider_counts: ProviderCounts::new(2, 2),
            max_peers: Some(3),
            retry_budget: Some(5),
            manifest_envelope_present: true,
            gateway_manifest_id: Some("deadbeef".to_string()),
            gateway_manifest_cid: Some("c0ffee".to_string()),
            transport_policy: Some(TransportPolicy::SoranetPreferred),
            transport_policy_override: Some(TransportPolicy::DirectOnly),
            anonymity_policy: Some(AnonymityPolicy::GuardPq),
            anonymity_policy_override: Some(AnonymityPolicy::StrictPq),
            write_mode: WriteModeHint::ReadOnly,
            scoreboard_now: None,
            telemetry_source: None,
            telemetry_region: None,
        });
        let object = value.as_object().expect("metadata should be a JSON object");
        assert_eq!(
            object.get("version").and_then(Value::as_str),
            Some("executable-version")
        );
        assert_eq_compact! { object.get("transport_policy").and_then(Value::as_str).expect("transport_policy string") => "direct-only" };
        assert_eq_compact! { object.get("transport_policy_override").and_then(Value::as_bool) => Some(true) };
        assert_eq_compact! { object.get("transport_policy_override_label").and_then(Value::as_str) => Some("direct-only") };
        assert_eq_compact! { object.get("anonymity_policy").and_then(Value::as_str).expect("anonymity label") => "anon-strict-pq" };
        assert_eq_compact! { object.get("anonymity_policy_override").and_then(Value::as_bool) => Some(true) };
        assert_eq_compact! { object.get("anonymity_policy_override_label").and_then(Value::as_str) => Some("anon-strict-pq") };
        assert_eq_compact! { object.get("gateway_manifest_id").and_then(Value::as_str) => Some("deadbeef") };
        assert_eq_compact! { object.get("gateway_manifest_cid").and_then(Value::as_str) => Some("c0ffee") };
    }
    #[test]
    fn cli_scoreboard_metadata_includes_timestamp_and_telemetry_label() {
        let value = cli_scoreboard_metadata(&ScoreboardMetadataInput {
            version: "executable-version",
            provider_counts: ProviderCounts::new(1, 0),
            max_peers: None,
            retry_budget: None,
            manifest_envelope_present: false,
            gateway_manifest_id: None,
            gateway_manifest_cid: None,
            transport_policy: None,
            transport_policy_override: None,
            anonymity_policy: None,
            anonymity_policy_override: None,
            write_mode: WriteModeHint::ReadOnly,
            scoreboard_now: Some(1_700_000_000),
            telemetry_source: Some("otel::prod".to_string()),
            telemetry_region: Some("iad-prod".to_string()),
        });
        let object = value.as_object().expect("metadata should be a JSON object");
        assert_eq_compact! { object.get("assume_now").and_then(Value::as_u64) => Some(1_700_000_000) };
        assert_eq_compact! { object.get("telemetry_source").and_then(Value::as_str) => Some("otel::prod") };
        assert_eq_compact! { object.get("telemetry_region").and_then(Value::as_str) => Some("iad-prod") };
    }
    #[test]
    fn cli_scoreboard_metadata_defaults_to_soranet_first_transport() {
        let value = cli_scoreboard_metadata(&ScoreboardMetadataInput {
            version: "executable-version",
            provider_counts: ProviderCounts::new(0, 2),
            max_peers: None,
            retry_budget: None,
            manifest_envelope_present: false,
            gateway_manifest_id: None,
            gateway_manifest_cid: None,
            transport_policy: None,
            transport_policy_override: None,
            anonymity_policy: None,
            anonymity_policy_override: None,
            write_mode: WriteModeHint::ReadOnly,
            scoreboard_now: None,
            telemetry_source: None,
            telemetry_region: None,
        });
        let object = value.as_object().expect("metadata should be a JSON object");
        assert_eq_compact! { object.get("transport_policy").and_then(Value::as_str).expect("transport_policy string") => "soranet-first" };
        assert_eq_compact! { object.get("transport_policy_override").and_then(Value::as_bool) => Some(false) };
        assert_eq_compact! { object.get("provider_count").and_then(Value::as_u64) => Some(0) };
        assert_eq_compact! { object.get("gateway_provider_count").and_then(Value::as_u64) => Some(2) };
    }
    #[test]
    fn cli_scoreboard_metadata_distinguishes_gateway_providers() {
        let value = cli_scoreboard_metadata(&ScoreboardMetadataInput {
            version: "executable-version",
            provider_counts: ProviderCounts::new(5, 7),
            max_peers: Some(4),
            retry_budget: Some(6),
            manifest_envelope_present: true,
            gateway_manifest_id: Some("abc123".to_string()),
            gateway_manifest_cid: Some("def456".to_string()),
            transport_policy: Some(TransportPolicy::SoranetPreferred),
            transport_policy_override: None,
            anonymity_policy: Some(AnonymityPolicy::MajorityPq),
            anonymity_policy_override: None,
            write_mode: WriteModeHint::ReadOnly,
            scoreboard_now: Some(123),
            telemetry_source: Some("ci".to_string()),
            telemetry_region: None,
        });
        let object = value.as_object().expect("metadata should be a JSON object");
        assert_eq_compact! { object.get("provider_count").and_then(Value::as_u64) => Some(5) };
        assert_eq_compact! { object.get("gateway_provider_count").and_then(Value::as_u64) => Some(7) };
        assert_eq_compact! { object.get("transport_policy").and_then(Value::as_str) => Some("soranet-first") };
        assert_eq_compact! { object.get("anonymity_policy").and_then(Value::as_str) => Some("anon-majority-pq") };
    }
    #[test]
    fn cli_scoreboard_metadata_sets_provider_mix() {
        let value = cli_scoreboard_metadata(&ScoreboardMetadataInput {
            version: "executable-version",
            provider_counts: ProviderCounts::new(0, 1),
            max_peers: None,
            retry_budget: None,
            manifest_envelope_present: false,
            gateway_manifest_id: None,
            gateway_manifest_cid: None,
            transport_policy: None,
            transport_policy_override: None,
            anonymity_policy: None,
            anonymity_policy_override: None,
            write_mode: WriteModeHint::ReadOnly,
            scoreboard_now: None,
            telemetry_source: None,
            telemetry_region: None,
        });
        let object = value.as_object().expect("metadata object");
        assert_eq_compact! { object.get("provider_mix").and_then(Value::as_str) => Some("gateway-only") };
    }
}
#[derive(Debug, norito::json::JsonSerialize)]
struct IncentivesDashboardRow {
    relay: String,
    payout_count: u64,
    payout_amount: Quantity,
}
#[derive(Debug, norito::json::JsonSerialize)]
struct IncentivesDashboardSummary {
    total_relays: usize,
    total_payout: Quantity,
    rows: Vec<IncentivesDashboardRow>,
}
#[derive(Debug, norito::json::JsonSerialize)]
struct DaemonProcessedPayoutSummary {
    relay_id_hex: String,
    epoch: u32,
    payout_amount: Quantity,
    budget_approval_id: Option<String>,
    metrics: PayoutMetricsSnapshot,
    instruction_path: Option<String>,
    transfer_path: Option<String>,
    metrics_archived_to: Option<String>,
}
#[derive(Debug, Default, norito::json::JsonSerialize)]
struct DaemonIterationSummary {
    processed: Vec<DaemonProcessedPayoutSummary>,
    skipped_missing_config: usize,
    skipped_missing_bond: usize,
    skipped_duplicate: usize,
    missing_budget_approval: usize,
    mismatched_budget_approval: usize,
    expected_budget_approval: Option<String>,
    errors: Vec<String>,
}
#[derive(Debug, Default, norito::json::JsonSerialize)]
struct IncentivesAuditSummary {
    bond: Option<BondAuditSummary>,
    budget: Option<BudgetAuditSummary>,
}
impl IncentivesAuditSummary {
    fn failure_count(&self) -> usize {
        let bond = self
            .bond
            .as_ref()
            .map_or(0, BondAuditSummary::failure_count);
        let budget = self
            .budget
            .as_ref()
            .map_or(0, BudgetAuditSummary::failure_count);
        bond.saturating_add(budget)
    }
}
#[derive(Debug, Default, norito::json::JsonSerialize)]
struct BondAuditSummary {
    total_relays: usize,
    exit_relays: usize,
    satisfied: usize,
    missing_bond: usize,
    insufficient_bond: usize,
    asset_mismatch: usize,
    policy_minimum_exit_bond: String,
    policy_bond_asset_id: String,
    errors: Vec<String>,
}
impl BondAuditSummary {
    fn failure_count(&self) -> usize {
        self.missing_bond
            .saturating_add(self.insufficient_bond)
            .saturating_add(self.asset_mismatch)
            .saturating_add(self.errors.len())
    }
}
#[derive(Debug, Default, norito::json::JsonSerialize)]
struct BudgetAuditSummary {
    configured_budget_approval_id: Option<String>,
    total_payouts: usize,
    payouts_without_budget: usize,
    mismatched_budget_approval: usize,
}
impl BudgetAuditSummary {
    fn failure_count(&self) -> usize {
        let missing_config: usize = usize::from(self.configured_budget_approval_id.is_none());
        missing_config
            .saturating_add(self.payouts_without_budget)
            .saturating_add(self.mismatched_budget_approval)
    }
}
#[derive(Debug)]
struct MetricsCandidate {
    relay_id: RelayId,
    relay_hex: String,
    epoch: u32,
    path: PathBuf,
    file_name: String,
}
#[derive(Debug, Clone, norito::json::JsonSerialize)]
struct PayoutMetricsSnapshot {
    availability_per_mille: u16,
    bandwidth_per_mille: u16,
    compliance_per_mille: u16,
    compliance_status: String,
    score_per_mille: u16,
    exit_bonus_applied: bool,
}
#[derive(Debug, Clone)]
struct DaemonConfig {
    relays: HashMap<RelayId, DaemonRelayEntry>,
}
impl DaemonConfig {
    fn entry(&self, relay_id: &RelayId) -> Option<&DaemonRelayEntry> {
        self.relays.get(relay_id)
    }
}
#[derive(Debug, Clone)]
struct DaemonRelayEntry {
    relay_hex: String,
    beneficiary: AccountId,
    bond_path: PathBuf,
}
#[derive(Debug, norito::json::JsonDeserialize)]
struct DaemonConfigFile {
    relays: Vec<DaemonRelayConfigFile>,
}
#[derive(Debug, norito::json::JsonDeserialize)]
struct DaemonRelayConfigFile {
    relay_id: String,
    beneficiary: String,
    bond_path: String,
}
fn read_reward_config(path: &Path) -> Result<RewardConfig> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read reward config from `{}`", path.display()))?;
    let state: RewardConfigState =
        norito::json::from_slice(&bytes).wrap_err("failed to parse reward configuration JSON")?;
    RewardConfig::try_from(state)
}
fn read_metrics_file(path: &Path) -> Result<RelayEpochMetricsV1> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read metrics from `{}`", path.display()))?;
    norito::decode_from_bytes(&bytes).wrap_err("failed to decode RelayEpochMetricsV1 payload")
}
fn read_bond_entry(path: &Path) -> Result<RelayBondLedgerEntryV1> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read bond entry from `{}`", path.display()))?;
    norito::decode_from_bytes(&bytes).wrap_err("failed to decode RelayBondLedgerEntryV1 payload")
}
fn read_reward_instruction(path: &Path) -> Result<RelayRewardInstructionV1> {
    let bytes = fs::read(path).wrap_err_with(|| {
        format!(
            "failed to read reward instruction from `{}`",
            path.display()
        )
    })?;
    norito::decode_from_bytes(&bytes).wrap_err("failed to decode RelayRewardInstructionV1 payload")
}
fn read_ledger_export(path: &Path) -> Result<LedgerExportFile> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read ledger export from `{}`", path.display()))?;
    let export: LedgerExportFile = norito::decode_from_bytes(&bytes)
        .map_err(|err| {
            if matches!(err, norito::Error::SchemaMismatch) {
                const SCHEMA_OFFSET: usize = 4 + 1 + 1;
                const SCHEMA_LEN: usize = 16;
                let expected = norito::schema::identity::frame_hash::<LedgerExportFile>();
                let actual = bytes
                    .get(SCHEMA_OFFSET..SCHEMA_OFFSET + SCHEMA_LEN)
                    .map(|slice| {
                        let mut buf = [0_u8; SCHEMA_LEN];
                        buf.copy_from_slice(slice);
                        buf
                    })
                    .map_or_else(|| "<missing>".to_string(), hex::encode);
                eyre!(
                    "schema mismatch (expected {}, got {actual})",
                    hex::encode(expected)
                )
            } else {
                eyre!(err)
            }
        })
        .wrap_err("failed to decode ledger export payload")?;
    export.ensure_current()?;
    Ok(export)
}
fn write_norito_payload<T>(path: &Path, value: &T) -> Result<()>
where
    T: NoritoSerialize,
{
    let bytes = norito::to_bytes(value).wrap_err("failed to encode Norito payload")?;
    fs::write(path, bytes)
        .wrap_err_with(|| format!("failed to write Norito payload to `{}`", path.display()))
}
fn load_daemon_config(
    path: &Path,
    resolve: &dyn Fn(&str) -> Result<AccountId>,
) -> Result<DaemonConfig> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read daemon config from `{}`", path.display()))?;
    let file: DaemonConfigFile =
        norito::json::from_slice(&bytes).wrap_err("failed to parse daemon config JSON")?;
    let base_dir = path
        .parent()
        .map_or_else(|| Path::new(".").to_path_buf(), Path::to_path_buf);
    let mut relays = HashMap::new();
    for entry in file.relays {
        let normalised = validate_hex_digest(&entry.relay_id, "daemon_config.relays[].relay_id")
            .map_err(|err| eyre!("invalid relay_id `{}`: {err}", entry.relay_id))?;
        let mut relay_id = [0_u8; 32];
        decode_to_slice(&normalised, &mut relay_id)
            .map_err(|err| eyre!("failed to decode relay_id `{}`: {err}", entry.relay_id))?;
        let beneficiary = resolve(entry.beneficiary.trim()).map_err(|err| {
            eyre!(
                "invalid beneficiary `{}` for relay {}: {err}",
                entry.beneficiary,
                normalised
            )
        })?;
        let bond_path = resolve_relative_path(&base_dir, entry.bond_path.trim());
        let relay_entry = DaemonRelayEntry {
            relay_hex: normalised.clone(),
            beneficiary,
            bond_path,
        };
        if relays.insert(relay_id, relay_entry).is_some() {
            return Err(eyre!(
                "duplicate daemon config entry for relay {}",
                normalised
            ));
        }
    }
    Ok(DaemonConfig { relays })
}
fn audit_scope_flags(scopes: &[IncentiveAuditScope]) -> (bool, bool) {
    let mut bond = false;
    let mut budget = false;
    if scopes.is_empty() {
        return (true, false);
    }
    for scope in scopes {
        match scope {
            IncentiveAuditScope::Bond => bond = true,
            IncentiveAuditScope::Budget => budget = true,
            IncentiveAuditScope::All => {
                bond = true;
                budget = true;
            }
        }
    }
    if !bond && !budget {
        bond = true;
    }
    (bond, budget)
}
fn audit_bonds(
    config: &DaemonConfig,
    reward_config: &RewardConfigState,
) -> Result<BondAuditSummary> {
    let policy = RelayBondPolicyV1::try_from(reward_config.policy.clone())
        .map_err(|err| eyre!("invalid reward policy in state: {err}"))?;
    let mut summary = BondAuditSummary {
        total_relays: config.relays.len(),
        policy_minimum_exit_bond: reward_config.policy.minimum_exit_bond.clone(),
        policy_bond_asset_id: reward_config.policy.bond_asset_id.clone(),
        ..BondAuditSummary::default()
    };
    for entry in config.relays.values() {
        let bond_entry = match read_bond_entry(&entry.bond_path) {
            Ok(entry) => entry,
            Err(err) => {
                summary.missing_bond = summary.missing_bond.saturating_add(1);
                summary.errors.push(format!(
                    "relay {} bond missing or unreadable at `{}`: {err}",
                    entry.relay_hex,
                    entry.bond_path.display()
                ));
                continue;
            }
        };
        if bond_entry.exit_capable {
            summary.exit_relays = summary.exit_relays.saturating_add(1);
        }
        if bond_entry.meets_exit_minimum(&policy) {
            summary.satisfied = summary.satisfied.saturating_add(1);
            continue;
        }
        if bond_entry.bond_asset_id != policy.bond_asset_id {
            summary.asset_mismatch = summary.asset_mismatch.saturating_add(1);
            summary.errors.push(format!(
                "relay {} bond uses asset {} (expected {})",
                entry.relay_hex, bond_entry.bond_asset_id, policy.bond_asset_id
            ));
            continue;
        }
        summary.insufficient_bond = summary.insufficient_bond.saturating_add(1);
        summary.errors.push(format!(
            "relay {} bonded {} below minimum {}",
            entry.relay_hex, bond_entry.bonded_amount, policy.minimum_exit_bond
        ));
    }
    Ok(summary)
}
#[allow(clippy::unnecessary_wraps)]
fn audit_budget(state: &IncentivesState) -> Result<BudgetAuditSummary> {
    let mut summary = BudgetAuditSummary {
        configured_budget_approval_id: state.reward_config.budget_approval_id.clone(),
        total_payouts: state.payouts.len(),
        ..BudgetAuditSummary::default()
    };
    let expected_budget =
        match require_budget_approval_id(state.reward_config.budget_approval_id.as_ref()) {
            Ok(id) => id,
            Err(_) => return Ok(summary),
        };
    for payout in &state.payouts {
        match payout.budget_approval_id {
            Some(value) if value == expected_budget => {}
            Some(_) => {
                summary.mismatched_budget_approval =
                    summary.mismatched_budget_approval.saturating_add(1);
            }
            None => {
                summary.payouts_without_budget = summary.payouts_without_budget.saturating_add(1);
            }
        }
    }
    Ok(summary)
}
fn resolve_relative_path(base: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn process_daemon_iteration(
    state: &mut IncentivesState,
    service: &mut RelayPayoutService,
    config: &DaemonConfig,
    metrics_dir: &Path,
    instruction_out_dir: Option<&Path>,
    transfer_out_dir: Option<&Path>,
    archive_dir: Option<&Path>,
    expected_budget: Option<&[u8; 32]>,
) -> Result<DaemonIterationSummary> {
    let mut summary = DaemonIterationSummary {
        expected_budget_approval: expected_budget.map(hex::encode),
        ..DaemonIterationSummary::default()
    };
    let entries = match fs::read_dir(metrics_dir) {
        Ok(entries) => entries,
        Err(err) => {
            return Err(err).wrap_err_with(|| {
                format!(
                    "failed to read metrics directory `{}`",
                    metrics_dir.display()
                )
            });
        }
    };
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                summary
                    .errors
                    .push(format!("failed to read metrics directory entry: {err}"));
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default();
        if !extension.eq_ignore_ascii_case("to") {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .to_string();
        let stem = stem.trim();
        if !stem.starts_with("relay-") {
            summary.errors.push(format!(
                "metrics file `{file_name}` does not start with `relay-`; skipping"
            ));
            continue;
        }
        let relay_split = if let Some(split) = stem[6..].split_once("-epoch-") {
            split
        } else {
            summary.errors.push(format!(
                "metrics file `{file_name}` is missing `-epoch-` segment; skipping"
            ));
            continue;
        };
        let relay_hex_raw = relay_split.0;
        let epoch_segment = relay_split.1;
        let epoch_str = epoch_segment
            .split(['-', '.'])
            .next()
            .unwrap_or(epoch_segment);
        let epoch = match epoch_str.parse::<u32>() {
            Ok(epoch) => epoch,
            Err(err) => {
                summary.errors.push(format!(
                    "metrics file `{file_name}` contains invalid epoch `{epoch_str}`: {err}"
                ));
                continue;
            }
        };
        let normalised = match validate_hex_digest(relay_hex_raw, "metrics relay id") {
            Ok(hex) => hex,
            Err(err) => {
                summary.errors.push(format!(
                    "metrics file `{file_name}` has invalid relay id `{relay_hex_raw}`: {err}"
                ));
                continue;
            }
        };
        let mut relay_id = [0_u8; 32];
        if let Err(err) = decode_to_slice(&normalised, &mut relay_id) {
            summary.errors.push(format!(
                "metrics file `{file_name}` has undecodable relay id `{relay_hex_raw}`: {err}"
            ));
            continue;
        }
        candidates.push(MetricsCandidate {
            relay_id,
            relay_hex: normalised,
            epoch,
            path,
            file_name,
        });
    }
    candidates.sort_by(|left, right| {
        left.epoch
            .cmp(&right.epoch)
            .then_with(|| left.relay_hex.cmp(&right.relay_hex))
    });
    for candidate in candidates {
        let Some(relay_entry) = config.entry(&candidate.relay_id) else {
            summary.skipped_missing_config = summary.skipped_missing_config.saturating_add(1);
            summary.errors.push(format!(
                "no daemon config entry found for relay {} (metrics `{}`).",
                candidate.relay_hex, candidate.file_name
            ));
            continue;
        };
        let bond_entry = match read_bond_entry(&relay_entry.bond_path) {
            Ok(entry) => entry,
            Err(err) => {
                summary.skipped_missing_bond = summary.skipped_missing_bond.saturating_add(1);
                summary.errors.push(format!(
                    "failed to load bond entry for relay {} from `{}`: {err}",
                    relay_entry.relay_hex,
                    relay_entry.bond_path.display()
                ));
                continue;
            }
        };
        let metrics = match read_metrics_file(&candidate.path) {
            Ok(metrics) => metrics,
            Err(err) => {
                summary.errors.push(format!(
                    "failed to decode metrics snapshot `{}`: {err}",
                    candidate.file_name
                ));
                continue;
            }
        };
        if metrics.relay_id != candidate.relay_id {
            summary.errors.push(format!(
                "metrics snapshot `{}` relay id mismatch (expected {}, found {})",
                candidate.file_name,
                candidate.relay_hex,
                hex::encode(metrics.relay_id)
            ));
            continue;
        }
        if metrics.epoch != candidate.epoch {
            summary.errors.push(format!(
                "metrics snapshot `{}` epoch mismatch (expected {}, found {})",
                candidate.file_name, candidate.epoch, metrics.epoch
            ));
            continue;
        }
        let outcome = match service.process_epoch(
            &metrics,
            &bond_entry,
            relay_entry.beneficiary.clone(),
            Metadata::default(),
        ) {
            Ok(outcome) => outcome,
            Err(PayoutServiceError::Ledger(RewardLedgerError::DuplicateEpoch { .. })) => {
                summary.skipped_duplicate = summary.skipped_duplicate.saturating_add(1);
                continue;
            }
            Err(err) => {
                summary.errors.push(format!(
                    "failed to process metrics `{}`: {err}",
                    candidate.file_name
                ));
                continue;
            }
        };
        if let Some(expected) = expected_budget {
            if let Err(err) = ensure_instruction_budget_approval(&outcome.instruction, expected) {
                if outcome.instruction.budget_approval_id.is_some() {
                    summary.mismatched_budget_approval =
                        summary.mismatched_budget_approval.saturating_add(1);
                } else {
                    summary.missing_budget_approval =
                        summary.missing_budget_approval.saturating_add(1);
                }
                summary.errors.push(err.to_string());
            }
        } else if outcome.instruction.budget_approval_id.is_none() {
            summary.missing_budget_approval = summary.missing_budget_approval.saturating_add(1);
        }
        store_payout_instruction(state, &outcome.instruction);
        let metrics_snapshot = extract_payout_metrics(&outcome.instruction, &metrics);
        let budget_approval_id = outcome.instruction.budget_approval_id.map(hex::encode);
        let instruction_path = if let Some(dir) = instruction_out_dir {
            let file_name = format!(
                "relay-{}-epoch-{}.reward.to",
                relay_entry.relay_hex, candidate.epoch
            );
            let path = dir.join(&file_name);
            match write_norito_payload(&path, &outcome.instruction) {
                Ok(()) => Some(path.to_string_lossy().into_owned()),
                Err(err) => {
                    summary.errors.push(format!(
                        "failed to write reward instruction `{}`: {err}",
                        path.display()
                    ));
                    None
                }
            }
        } else {
            None
        };
        let transfer_path = if let Some(dir) = transfer_out_dir {
            if outcome.instruction.is_zero_amount() {
                None
            } else {
                let file_name = format!(
                    "relay-{}-epoch-{}.transfer.to",
                    relay_entry.relay_hex, candidate.epoch
                );
                let path = dir.join(&file_name);
                match write_norito_payload(&path, &outcome.transfer) {
                    Ok(()) => Some(path.to_string_lossy().into_owned()),
                    Err(err) => {
                        summary.errors.push(format!(
                            "failed to write transfer instruction `{}`: {err}",
                            path.display()
                        ));
                        None
                    }
                }
            }
        } else {
            None
        };
        let metrics_archived_to = if let Some(dir) = archive_dir {
            match archive_metrics_snapshot(&candidate.path, dir, &candidate.file_name) {
                Ok(archived_path) => Some(archived_path.to_string_lossy().into_owned()),
                Err(err) => {
                    summary.errors.push(err.to_string());
                    None
                }
            }
        } else {
            None
        };
        summary.processed.push(DaemonProcessedPayoutSummary {
            relay_id_hex: relay_entry.relay_hex.clone(),
            epoch: candidate.epoch,
            payout_amount: outcome.instruction.payout_amount,
            budget_approval_id,
            metrics: metrics_snapshot,
            instruction_path,
            transfer_path,
            metrics_archived_to,
        });
    }
    if summary.missing_budget_approval > 0 && summary.expected_budget_approval.is_some() {
        summary.errors.push(format!(
            "{} payout(s) missing budget_approval_id; set reward_config.budget_approval_id to the signed Parliament hash",
            summary.missing_budget_approval
        ));
    }
    Ok(summary)
}
fn archive_metrics_snapshot(path: &Path, archive_dir: &Path, file_name: &str) -> Result<PathBuf> {
    let mut attempt = 0_u32;
    loop {
        let candidate = if attempt == 0 {
            archive_dir.join(file_name)
        } else {
            archive_dir.join(format!("{file_name}.{attempt}"))
        };
        match fs::rename(path, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.saturating_add(1);
            }
            Err(err) => {
                return Err(err).wrap_err_with(|| {
                    format!(
                        "failed to archive metrics snapshot `{}` to `{}`",
                        path.display(),
                        candidate.display()
                    )
                });
            }
        }
    }
}
fn log_daemon_summary<C: RunContext>(
    context: &mut C,
    summary: &DaemonIterationSummary,
    pretty: bool,
) -> Result<()> {
    match context.output_format() {
        CliOutputFormat::Json => {
            context.print_data(summary)?;
        }
        CliOutputFormat::Text => {
            if pretty {
                context.print_data(summary)?;
            } else {
                let _ = context.println(format_args!(
                    "Processed {} payout(s); skipped {} missing config, {} missing bond, {} duplicate.",
                    summary.processed.len(),
                    summary.skipped_missing_config,
                    summary.skipped_missing_bond,
                    summary.skipped_duplicate
                ));
                if summary.missing_budget_approval > 0 {
                    let _ = context.println(format_args!(
                        "  missing budget approval id on {} payout(s)",
                        summary.missing_budget_approval
                    ));
                }
                if summary.mismatched_budget_approval > 0 {
                    let _ = context.println(format_args!(
                        "  mismatched budget approval id on {} payout(s)",
                        summary.mismatched_budget_approval
                    ));
                }
                if let Some(expected) = &summary.expected_budget_approval {
                    let _ =
                        context.println(format_args!("  expected budget approval id: {expected}"));
                }
                for payout in &summary.processed {
                    let _ = context.println(format_args!(
                        "  relay {} epoch {} payout {}",
                        payout.relay_id_hex, payout.epoch, payout.payout_amount
                    ));
                    if let Some(budget) = &payout.budget_approval_id {
                        let _ = context.println(format_args!("    budget approval: {budget}"));
                    } else {
                        let _ = context.println("    budget approval: <missing>");
                    }
                    if let Some(path) = &payout.instruction_path {
                        let _ = context.println(format_args!("    instruction: {path}"));
                    }
                    if let Some(path) = &payout.transfer_path {
                        let _ = context.println(format_args!("    transfer: {path}"));
                    }
                    if let Some(path) = &payout.metrics_archived_to {
                        let _ = context.println(format_args!("    archived metrics: {path}"));
                    }
                }
                if !summary.errors.is_empty() {
                    let _ = context.println(format_args!(
                        "Encountered {} error(s):",
                        summary.errors.len()
                    ));
                    for err in &summary.errors {
                        let _ = context.println(format_args!("  - {err}"));
                    }
                }
            }
        }
    }
    if summary.expected_budget_approval.is_some() && summary.missing_budget_approval > 0 {
        return Err(eyre!(
            "budget_approval_id missing for {} payout(s); configure reward_config.budget_approval_id before running payouts",
            summary.missing_budget_approval
        ));
    }
    Ok(())
}
#[derive(
    Debug,
    Clone,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::json::JsonSerialize,
    norito::json::JsonDeserialize,
)]
struct RewardConfigState {
    policy: RewardPolicyState,
    base_reward: String,
    uptime_weight_per_mille: u16,
    bandwidth_weight_per_mille: u16,
    compliance_penalty_basis_points: u16,
    bandwidth_target_bytes: u128,
    budget_approval_id: Option<String>,
    metrics_log_path: Option<String>,
}
#[derive(
    Debug,
    Clone,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::json::JsonSerialize,
    norito::json::JsonDeserialize,
)]
struct RewardPolicyState {
    minimum_exit_bond: String,
    bond_asset_id: String,
    uptime_floor_per_mille: u16,
    slash_penalty_basis_points: u16,
    activation_grace_epochs: u16,
}
impl From<&RewardConfig> for RewardConfigState {
    fn from(config: &RewardConfig) -> Self {
        Self {
            policy: RewardPolicyState::from(&config.policy),
            base_reward: config.base_reward.to_string(),
            uptime_weight_per_mille: config.uptime_weight_per_mille,
            bandwidth_weight_per_mille: config.bandwidth_weight_per_mille,
            compliance_penalty_basis_points: config.compliance_penalty_basis_points,
            bandwidth_target_bytes: config.bandwidth_target_bytes,
            budget_approval_id: config.budget_approval_id.map(hex::encode),
            metrics_log_path: config
                .metrics_log_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
        }
    }
}
impl TryFrom<RewardConfigState> for RewardConfig {
    type Error = eyre::Report;
    fn try_from(value: RewardConfigState) -> Result<Self> {
        let RewardConfigState {
            policy: policy_state,
            base_reward,
            uptime_weight_per_mille,
            bandwidth_weight_per_mille,
            compliance_penalty_basis_points,
            bandwidth_target_bytes,
            budget_approval_id,
            metrics_log_path,
        } = value;
        let policy = RelayBondPolicyV1::try_from(policy_state)?;
        let base_reward =
            Quantity::from_str(&base_reward).map_err(|err| eyre!("invalid base_reward: {err}"))?;
        let budget_approval_id = match budget_approval_id {
            Some(hex_value) => {
                let normalised =
                    validate_hex_digest(&hex_value, "reward_config.budget_approval_id")?;
                let mut digest = [0_u8; 32];
                decode_to_slice(normalised, &mut digest)
                    .map_err(|err| eyre!("invalid budget_approval_id hex: {err}"))?;
                Some(digest)
            }
            None => None,
        };
        let metrics_log_path = metrics_log_path.map(PathBuf::from);
        Ok(Self {
            policy,
            base_reward,
            uptime_weight_per_mille,
            bandwidth_weight_per_mille,
            compliance_penalty_basis_points,
            bandwidth_target_bytes,
            budget_approval_id,
            metrics_log_path,
        })
    }
}
impl From<&RelayBondPolicyV1> for RewardPolicyState {
    fn from(policy: &RelayBondPolicyV1) -> Self {
        Self {
            minimum_exit_bond: policy.minimum_exit_bond.to_string(),
            bond_asset_id: policy.bond_asset_id.to_string(),
            uptime_floor_per_mille: policy.uptime_floor_per_mille,
            slash_penalty_basis_points: policy.slash_penalty_basis_points,
            activation_grace_epochs: policy.activation_grace_epochs,
        }
    }
}
impl TryFrom<RewardPolicyState> for RelayBondPolicyV1 {
    type Error = eyre::Report;
    fn try_from(value: RewardPolicyState) -> Result<Self> {
        let minimum_exit_bond = Quantity::from_str(&value.minimum_exit_bond)
            .map_err(|err| eyre!("invalid minimum_exit_bond: {err}"))?;
        let bond_asset_id = AssetDefinitionId::parse_address_literal(&value.bond_asset_id)
            .map_err(|err| eyre!("invalid bond_asset_id: {err}"))?;
        Ok(Self {
            minimum_exit_bond,
            bond_asset_id,
            uptime_floor_per_mille: value.uptime_floor_per_mille,
            slash_penalty_basis_points: value.slash_penalty_basis_points,
            activation_grace_epochs: value.activation_grace_epochs,
        })
    }
}
fn require_budget_approval_id(budget_hex: Option<&String>) -> Result<[u8; 32]> {
    let budget_hex = budget_hex
        .map(String::as_str)
        .ok_or_else(|| eyre!("reward_config.budget_approval_id is required for incentives"))?;
    let normalised = validate_hex_digest(budget_hex, "reward_config.budget_approval_id")?;
    let mut digest = [0_u8; 32];
    decode_to_slice(normalised, &mut digest)
        .map_err(|err| eyre!("invalid budget_approval_id hex: {err}"))?;
    Ok(digest)
}
#[derive(Debug, Clone, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
struct IncentivesState {
    version: u16,
    reward_config: RewardConfigState,
    treasury_account: AccountId,
    payouts: Vec<RelayRewardInstructionV1>,
    disputes: Vec<StoredDisputeRecord>,
}
#[derive(
    Debug,
    Clone,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::json::JsonSerialize,
    norito::json::JsonDeserialize,
)]
#[norito(decode_from_slice)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha::commands::sorafs::LedgerExportFile")]
struct LedgerExportFile {
    version: u16,
    transfers: Vec<LedgerTransferRecord>,
}
impl LedgerExportFile {
    const VERSION: u16 = 1;
    fn ensure_current(&self) -> Result<()> {
        if self.version != Self::VERSION {
            return Err(eyre!(
                "unsupported ledger export version {} (expected {})",
                self.version,
                Self::VERSION
            ));
        }
        Ok(())
    }
}
impl IncentivesState {
    const VERSION: u16 = 1;
    fn new(reward_config: &RewardConfig, treasury_account: AccountId) -> Self {
        Self {
            version: Self::VERSION,
            reward_config: RewardConfigState::from(reward_config),
            treasury_account,
            payouts: Vec::new(),
            disputes: Vec::new(),
        }
    }
    fn ensure_current(&self) -> Result<()> {
        if self.version != Self::VERSION {
            return Err(eyre!(
                "unsupported incentives state version {} (expected {})",
                self.version,
                Self::VERSION
            ));
        }
        Ok(())
    }
}
#[derive(
    Debug,
    Clone,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::json::JsonSerialize,
    norito::json::JsonDeserialize,
)]
#[norito(decode_from_slice)]
struct StoredDisputeRecord {
    id: DisputeId,
    relay_id_hex: String,
    epoch: u32,
    submitted_by: AccountId,
    requested_amount: Quantity,
    filed_at_unix: u64,
    reason: String,
    requested_adjustment: Option<StoredAdjustmentRequest>,
    status: StoredDisputeStatus,
}
#[derive(
    Debug,
    Clone,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::json::JsonSerialize,
    norito::json::JsonDeserialize,
)]
#[norito(decode_from_slice)]
struct StoredAdjustmentRequest {
    kind: StoredAdjustmentKind,
    amount: Quantity,
}
impl StoredAdjustmentRequest {
    fn to_adjustment_request(&self) -> AdjustmentRequest {
        AdjustmentRequest {
            kind: self.kind.into(),
            amount: self.amount.clone(),
        }
    }
}
impl From<&AdjustmentRequest> for StoredAdjustmentRequest {
    fn from(request: &AdjustmentRequest) -> Self {
        Self {
            kind: request.kind.into(),
            amount: request.amount.clone(),
        }
    }
}
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::json::JsonSerialize,
    norito::json::JsonDeserialize,
)]
#[norito(tag = "kind", content = "details")]
#[norito(decode_from_slice)]
enum StoredAdjustmentKind {
    Credit,
    Debit,
}
impl From<AdjustmentKind> for StoredAdjustmentKind {
    fn from(kind: AdjustmentKind) -> Self {
        match kind {
            AdjustmentKind::Credit => Self::Credit,
            AdjustmentKind::Debit => Self::Debit,
        }
    }
}
impl From<StoredAdjustmentKind> for AdjustmentKind {
    fn from(kind: StoredAdjustmentKind) -> Self {
        match kind {
            StoredAdjustmentKind::Credit => AdjustmentKind::Credit,
            StoredAdjustmentKind::Debit => AdjustmentKind::Debit,
        }
    }
}
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::json::JsonSerialize,
    norito::json::JsonDeserialize,
)]
#[norito(tag = "kind", content = "details")]
#[norito(decode_from_slice)]
enum StoredResolutionKind {
    NoChange,
    Credit,
    Debit,
}
impl From<ResolutionKind> for StoredResolutionKind {
    fn from(kind: ResolutionKind) -> Self {
        match kind {
            ResolutionKind::NoChange => Self::NoChange,
            ResolutionKind::Credit => Self::Credit,
            ResolutionKind::Debit => Self::Debit,
        }
    }
}
#[derive(
    Debug,
    Clone,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
    norito::json::JsonSerialize,
    norito::json::JsonDeserialize,
)]
#[norito(tag = "status", content = "details")]
#[norito(decode_from_slice)]
enum StoredDisputeStatus {
    Open,
    Rejected {
        rejected_at_unix: u64,
        notes: String,
    },
    Resolved {
        resolved_at_unix: u64,
        kind: StoredResolutionKind,
        amount: Option<Quantity>,
        notes: String,
    },
}
impl From<&DisputeStatus> for StoredDisputeStatus {
    fn from(status: &DisputeStatus) -> Self {
        match status {
            DisputeStatus::Open => Self::Open,
            DisputeStatus::Rejected {
                rejected_at_unix,
                notes,
            } => Self::Rejected {
                rejected_at_unix: *rejected_at_unix,
                notes: notes.clone(),
            },
            DisputeStatus::Resolved {
                resolved_at_unix,
                outcome,
            } => Self::Resolved {
                resolved_at_unix: *resolved_at_unix,
                kind: outcome.kind.into(),
                amount: outcome.amount.clone(),
                notes: outcome.notes.clone(),
            },
        }
    }
}
impl From<&RewardDispute> for StoredDisputeRecord {
    fn from(dispute: &RewardDispute) -> Self {
        let norito_record = dispute.norito_record();
        Self {
            id: dispute.id,
            relay_id_hex: relay_id_to_hex(dispute.relay_id),
            epoch: dispute.epoch,
            submitted_by: norito_record.submitted_by.clone(),
            requested_amount: norito_record.requested_amount.clone(),
            filed_at_unix: dispute.filed_at_unix,
            reason: dispute.reason.clone(),
            requested_adjustment: dispute
                .requested_adjustment
                .as_ref()
                .map(StoredAdjustmentRequest::from),
            status: StoredDisputeStatus::from(&dispute.status),
        }
    }
}
impl StoredDisputeRecord {
    fn apply_to_service(&self, service: &mut RelayPayoutService) -> Result<()> {
        let relay_id = relay_id_from_hex(&self.relay_id_hex)
            .wrap_err_with(|| format!("invalid relay id for dispute {}", self.id))?;
        let requested_adjustment = self
            .requested_adjustment
            .as_ref()
            .map(StoredAdjustmentRequest::to_adjustment_request);
        let dispute = service
            .file_dispute(
                relay_id,
                self.epoch,
                self.submitted_by.clone(),
                self.requested_amount.clone(),
                self.reason.clone(),
                self.filed_at_unix,
                requested_adjustment,
            )
            .wrap_err_with(|| format!("failed to replay dispute {}", self.id))?;
        if dispute.id != self.id {
            return Err(eyre!(
                "dispute id mismatch when replaying state: expected {}, got {}",
                self.id,
                dispute.id
            ));
        }
        match &self.status {
            StoredDisputeStatus::Open => Ok(()),
            StoredDisputeStatus::Rejected {
                rejected_at_unix,
                notes,
            } => service
                .reject_dispute(self.id, *rejected_at_unix, notes.clone())
                .map(|_| ())
                .wrap_err_with(|| format!("failed to replay rejection for dispute {}", self.id)),
            StoredDisputeStatus::Resolved {
                resolved_at_unix,
                kind,
                amount,
                notes,
            } => {
                let resolution = stored_resolution_to_resolution(*kind, amount.clone(), notes)
                    .wrap_err_with(|| format!("invalid resolution for dispute {}", self.id))?;
                service
                    .resolve_dispute(self.id, resolution, *resolved_at_unix)
                    .map(|_| ())
                    .wrap_err_with(|| {
                        format!("failed to replay resolution for dispute {}", self.id)
                    })
            }
        }
    }
}
fn stored_resolution_to_resolution(
    kind: StoredResolutionKind,
    amount: Option<Quantity>,
    notes: &str,
) -> Result<DisputeResolution> {
    Ok(match kind {
        StoredResolutionKind::NoChange => DisputeResolution::NoChange {
            notes: notes.to_owned(),
        },
        StoredResolutionKind::Credit => DisputeResolution::Credit {
            amount: amount.ok_or_else(|| eyre!("credit resolution requires an amount"))?,
            notes: notes.to_owned(),
        },
        StoredResolutionKind::Debit => DisputeResolution::Debit {
            amount: amount.ok_or_else(|| eyre!("debit resolution requires an amount"))?,
            notes: notes.to_owned(),
        },
    })
}
fn parse_incentives_state_snapshot(bytes: &[u8]) -> Result<IncentivesState> {
    norito::json::from_slice(bytes).wrap_err("failed to parse incentives state JSON")
}
fn load_incentives_state(path: &Path) -> Result<IncentivesState> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read incentives state from `{}`", path.display()))?;
    let state = parse_incentives_state_snapshot(&bytes)?;
    state.ensure_current()?;
    Ok(state)
}
fn save_incentives_state(path: &Path, state: &IncentivesState) -> Result<()> {
    let bytes =
        norito::json::to_vec_pretty(state).wrap_err("failed to render incentives state JSON")?;
    fs::write(path, bytes)
        .wrap_err_with(|| format!("failed to write incentives state to `{}`", path.display()))
}
fn build_clean_payout_service(state: &IncentivesState) -> Result<RelayPayoutService> {
    let config = RewardConfig::try_from(state.reward_config.clone())
        .map_err(|err| eyre!("invalid reward configuration in state: {err}"))?;
    let engine = RelayRewardEngine::new(config)
        .map_err(|err| eyre!("invalid reward configuration in state: {err}"))?;
    Ok(RelayPayoutService::new(
        engine,
        RelayPayoutLedger::new(state.treasury_account.clone()),
    ))
}
fn build_payout_service(state: &IncentivesState) -> Result<RelayPayoutService> {
    state.ensure_current()?;
    let mut service = build_clean_payout_service(state)?;
    for instruction in &state.payouts {
        service
            .record_reward(instruction.clone())
            .wrap_err_with(|| {
                format!(
                    "failed to replay reward instruction for relay {} epoch {}",
                    hex::encode(instruction.relay_id),
                    instruction.epoch
                )
            })?;
    }
    let mut disputes = state.disputes.clone();
    disputes.sort_by_key(|d| d.id);
    for dispute in disputes {
        dispute.apply_to_service(&mut service)?;
    }
    Ok(service)
}
fn store_payout_instruction(state: &mut IncentivesState, instruction: &RelayRewardInstructionV1) {
    state.payouts.push(instruction.clone());
}
fn upsert_dispute_record(state: &mut IncentivesState, dispute: &RewardDispute) {
    let record = StoredDisputeRecord::from(dispute);
    if let Some(existing) = state
        .disputes
        .iter_mut()
        .find(|entry| entry.id == record.id)
    {
        *existing = record;
    } else {
        state.disputes.push(record);
        state.disputes.sort_by_key(|entry| entry.id);
    }
}
fn relay_id_to_hex(relay_id: RelayId) -> String {
    hex::encode(relay_id)
}
fn saturating_u16(value: u64) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}
#[allow(clippy::cast_precision_loss)]
fn u64_to_f64(value: u64) -> f64 {
    value as f64
}
#[allow(clippy::cast_precision_loss)]
fn u128_to_f64(value: u128) -> f64 {
    value as f64
}
#[allow(clippy::cast_precision_loss)]
fn usize_to_f64(value: usize) -> f64 {
    value as f64
}
fn transfer_kind_label(kind: TransferKind) -> &'static str {
    match kind {
        TransferKind::Payout => "payout",
        TransferKind::Credit => "credit",
        TransferKind::Debit => "debit",
    }
}
fn mismatch_reason_label(reason: MismatchReason) -> &'static str {
    match reason {
        MismatchReason::Amount => "amount",
        MismatchReason::SourceAsset => "source_asset",
        MismatchReason::Destination => "destination",
    }
}
fn ledger_amount_source_label(source: LedgerAmountSource) -> &'static str {
    match source {
        LedgerAmountSource::Expected => "expected",
        LedgerAmountSource::Exported => "exported",
    }
}
fn quantity_to_nanos_error_label(error: QuantityToNanosError) -> &'static str {
    match error {
        QuantityToNanosError::TooWideMantissa => "too_wide_mantissa",
        QuantityToNanosError::ScaleOverflow => "scale_overflow",
        QuantityToNanosError::InexactNanos => "inexact_nanos",
        QuantityToNanosError::NanosOverflow => "nanos_overflow",
        QuantityToNanosError::TotalOverflow => "total_overflow",
    }
}
fn quantity_to_nanos_checked(amount: &Quantity) -> Result<u128, QuantityToNanosError> {
    let scale = amount.scale();
    let mantissa = amount
        .as_numeric()
        .try_mantissa_u128()
        .ok_or(QuantityToNanosError::TooWideMantissa)?;
    if scale >= 9 {
        let divisor = 10u128
            .checked_pow(scale.saturating_sub(9))
            .ok_or(QuantityToNanosError::ScaleOverflow)?;
        if mantissa % divisor != 0 {
            return Err(QuantityToNanosError::InexactNanos);
        }
        Ok(mantissa / divisor)
    } else {
        let multiplier = 10u128
            .checked_pow(9 - scale)
            .ok_or(QuantityToNanosError::ScaleOverflow)?;
        mantissa
            .checked_mul(multiplier)
            .ok_or(QuantityToNanosError::NanosOverflow)
    }
}
fn metadata_get_u64(metadata: &Metadata, key: &str) -> Option<u64> {
    let name = Name::from_str(key).ok()?;
    metadata.get(&name)?.try_into_any::<u64>().ok()
}
fn metadata_get_bool(metadata: &Metadata, key: &str) -> Option<bool> {
    let name = Name::from_str(key).ok()?;
    metadata.get(&name)?.try_into_any::<bool>().ok()
}
fn extract_payout_metrics(
    instruction: &RelayRewardInstructionV1,
    metrics: &RelayEpochMetricsV1,
) -> PayoutMetricsSnapshot {
    let availability_raw = metadata_get_u64(&instruction.metadata, "availability_per_mille")
        .unwrap_or_else(|| u64::from(metrics.uptime_ratio_per_mille()));
    let bandwidth_raw = metadata_get_u64(&instruction.metadata, "bandwidth_per_mille").unwrap_or(0);
    let compliance_raw = metadata_get_u64(&instruction.metadata, "compliance_per_mille").unwrap_or(
        match metrics.compliance {
            RelayComplianceStatusV1::Clean => 1_000,
            RelayComplianceStatusV1::Warning => 900,
            RelayComplianceStatusV1::Suspended => 0,
        },
    );
    let exit_bonus_applied =
        metadata_get_bool(&instruction.metadata, "exit_bonus_applied").unwrap_or(false);
    let score_per_mille = instruction.reward_score.try_into().unwrap_or(u16::MAX);
    let compliance_status = match metrics.compliance {
        RelayComplianceStatusV1::Clean => "clean",
        RelayComplianceStatusV1::Warning => "warning",
        RelayComplianceStatusV1::Suspended => "suspended",
    }
    .to_string();
    PayoutMetricsSnapshot {
        availability_per_mille: saturating_u16(availability_raw),
        bandwidth_per_mille: saturating_u16(bandwidth_raw),
        compliance_per_mille: saturating_u16(compliance_raw),
        compliance_status,
        score_per_mille,
        exit_bonus_applied,
    }
}
fn relay_id_from_hex(value: &str) -> Result<RelayId> {
    if value.len() != 64 {
        return Err(eyre!("relay id must be 64 hex characters"));
    }
    let mut bytes = [0_u8; 32];
    decode_to_slice(value, &mut bytes)
        .map_err(|err| eyre!("failed to decode relay id hex: {err}"))?;
    Ok(bytes)
}
fn ensure_instruction_budget_approval(
    instruction: &RelayRewardInstructionV1,
    expected_budget: &[u8; 32],
) -> Result<()> {
    match instruction.budget_approval_id {
        Some(value) if value == *expected_budget => Ok(()),
        Some(value) => Err(eyre!(
            "reward instruction for relay {} epoch {} carries unexpected budget_approval_id {} (expected {})",
            hex::encode(instruction.relay_id),
            instruction.epoch,
            hex::encode(value),
            hex::encode(expected_budget)
        )),
        None => Err(eyre!(
            "reward instruction for relay {} epoch {} missing budget_approval_id",
            hex::encode(instruction.relay_id),
            instruction.epoch
        )),
    }
}
fn load_state_service(path: &Path) -> Result<(IncentivesState, RelayPayoutService)> {
    let state = load_incentives_state(path)?;
    let service = build_payout_service(&state)?;
    Ok((state, service))
}
fn parse_adjustment_flags(
    credit: Option<&String>,
    debit: Option<&String>,
) -> Result<Option<AdjustmentRequest>> {
    if let Some(value) = credit {
        let amount = parse_quantity_str(value, "--adjust-credit")?;
        return Ok(Some(AdjustmentRequest {
            kind: AdjustmentKind::Credit,
            amount,
        }));
    }
    if let Some(value) = debit {
        let amount = parse_quantity_str(value, "--adjust-debit")?;
        return Ok(Some(AdjustmentRequest {
            kind: AdjustmentKind::Debit,
            amount,
        }));
    }
    Ok(None)
}
fn output_summary<C, T>(context: &mut C, summary: &T, pretty: bool) -> Result<()>
where
    C: RunContext,
    T: norito::json::JsonSerialize,
{
    match context.output_format() {
        CliOutputFormat::Json => context.print_data(summary),
        CliOutputFormat::Text => {
            if pretty {
                context.print_data(summary)
            } else {
                let bytes = norito::json::to_vec(summary)
                    .map_err(|err| eyre!("failed to serialise summary: {err}"))?;
                let output = String::from_utf8(bytes)
                    .map_err(|err| eyre!("summary JSON is not valid UTF-8: {err}"))?;
                context.println(output)
            }
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ServicePayoutSummary {
    relay_id_hex: String,
    epoch: u32,
    payout_amount: Quantity,
    reward_score: u64,
    ledger: ServiceLedgerSnapshot,
}
impl ServicePayoutSummary {
    fn new(instruction: &RelayRewardInstructionV1, ledger: ServiceLedgerSnapshot) -> Self {
        Self {
            relay_id_hex: relay_id_to_hex(instruction.relay_id),
            epoch: instruction.epoch,
            payout_amount: instruction.payout_amount.clone(),
            reward_score: instruction.reward_score,
            ledger,
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ServiceLedgerSnapshot {
    total_paid: Quantity,
    total_rebated: Quantity,
    total_withheld: Quantity,
    net_paid: Numeric,
    epochs_recorded: usize,
    last_epoch: Option<u32>,
    last_reward_score: Option<u64>,
    open_disputes: usize,
}
impl ServiceLedgerSnapshot {
    fn from_snapshot(snapshot: &RewardLedgerSnapshot) -> Self {
        Self {
            total_paid: snapshot.total_paid.clone(),
            total_rebated: snapshot.total_rebated.clone(),
            total_withheld: snapshot.total_withheld.clone(),
            net_paid: snapshot.net_paid.clone(),
            epochs_recorded: snapshot.epochs_recorded,
            last_epoch: snapshot.last_epoch,
            last_reward_score: snapshot.last_reward_score,
            open_disputes: 0,
        }
    }
    fn from_row(row: &EarningsRow) -> Self {
        Self {
            total_paid: row.total_paid.clone(),
            total_rebated: row.total_rebated.clone(),
            total_withheld: row.total_withheld.clone(),
            net_paid: row.net_paid.clone(),
            epochs_recorded: row.epochs_recorded,
            last_epoch: row.last_epoch,
            last_reward_score: row.last_reward_score,
            open_disputes: row.open_disputes,
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ServiceDashboardSummary {
    total_relays: usize,
    total_open_disputes: usize,
    rows: Vec<ServiceDashboardRow>,
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ReconciliationTransferSummary {
    relay_id: String,
    epoch: u32,
    kind: String,
    dispute_id: Option<DisputeId>,
    amount: String,
    amount_nanos: Option<u128>,
    amount_conversion_error: Option<String>,
    source_asset: String,
    destination: String,
}
impl ReconciliationTransferSummary {
    fn from_record(record: &LedgerTransferRecord) -> Self {
        let (amount_nanos, amount_conversion_error) =
            match quantity_to_nanos_checked(&record.amount) {
                Ok(nanos) => (Some(nanos), None),
                Err(error) => (None, Some(quantity_to_nanos_error_label(error).to_string())),
            };
        Self {
            relay_id: relay_id_to_hex(record.relay_id),
            epoch: record.epoch,
            kind: transfer_kind_label(record.kind).to_string(),
            dispute_id: record.dispute_id,
            amount: record.amount.to_string(),
            amount_nanos,
            amount_conversion_error,
            source_asset: record.source_asset.to_string(),
            destination: record.destination.to_string(),
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ReconciliationMismatchSummary {
    expected: ReconciliationTransferSummary,
    actual: ReconciliationTransferSummary,
    reasons: Vec<String>,
}
impl ReconciliationMismatchSummary {
    fn from_mismatch(mismatch: &LedgerTransferMismatch) -> Self {
        let reasons = mismatch
            .reasons
            .iter()
            .map(|reason| mismatch_reason_label(*reason))
            .map(str::to_string)
            .collect();
        Self {
            expected: ReconciliationTransferSummary::from_record(&mismatch.expected),
            actual: ReconciliationTransferSummary::from_record(&mismatch.actual),
            reasons,
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ReconciliationAmountArithmeticSummary {
    source: String,
    record: ReconciliationTransferSummary,
}
impl ReconciliationAmountArithmeticSummary {
    fn from_error(error: &LedgerAmountArithmeticError) -> Self {
        Self {
            source: ledger_amount_source_label(error.source).to_string(),
            record: ReconciliationTransferSummary::from_record(&error.record),
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ReconciliationReportSummary {
    clean: bool,
    matched_transfers: usize,
    total_expected_transfers: usize,
    expected_amount: String,
    exported_amount: String,
    missing_transfers: Vec<ReconciliationTransferSummary>,
    unexpected_transfers: Vec<ReconciliationTransferSummary>,
    mismatched_transfers: Vec<ReconciliationMismatchSummary>,
    amount_arithmetic_errors: Vec<ReconciliationAmountArithmeticSummary>,
}
impl ReconciliationReportSummary {
    fn from_report(report: &LedgerReconciliationReport) -> Self {
        let missing_transfers = report
            .missing_transfers
            .iter()
            .map(|entry| ReconciliationTransferSummary::from_record(&entry.record))
            .collect();
        let unexpected_transfers = report
            .unexpected_transfers
            .iter()
            .map(ReconciliationTransferSummary::from_record)
            .collect();
        let mismatched_transfers = report
            .mismatched_transfers
            .iter()
            .map(ReconciliationMismatchSummary::from_mismatch)
            .collect();
        let amount_arithmetic_errors = report
            .amount_arithmetic_errors
            .iter()
            .map(ReconciliationAmountArithmeticSummary::from_error)
            .collect();
        Self {
            clean: report.is_clean(),
            matched_transfers: report.matched_transfers,
            total_expected_transfers: report.total_expected_transfers,
            expected_amount: report.expected_amount.to_string(),
            exported_amount: report.exported_amount.to_string(),
            missing_transfers,
            unexpected_transfers,
            mismatched_transfers,
            amount_arithmetic_errors,
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ShadowRunRelaySummary {
    relay_id_hex: String,
    epochs: usize,
    payout_nanos: u128,
    amount_conversion_errors: usize,
    average_payout_nanos: f64,
    average_score_per_mille: f64,
    average_availability_per_mille: f64,
    average_bandwidth_per_mille: f64,
    warning_epochs: usize,
    suspended_epochs: usize,
    zero_score_epochs: usize,
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ShadowRunAmountConversionError {
    relay_id_hex: String,
    epoch: u32,
    amount: String,
    reason: String,
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ShadowRunSummary {
    processed_payouts: usize,
    total_relays: usize,
    total_payout_nanos: u128,
    payout_amount_conversion_errors: Vec<ShadowRunAmountConversionError>,
    gini_coefficient: f64,
    top_relay_share: f64,
    zero_score_epochs: usize,
    warning_epochs: usize,
    suspended_epochs: usize,
    average_availability_per_mille: f64,
    average_bandwidth_per_mille: f64,
    skipped_missing_config: usize,
    skipped_missing_bond: usize,
    skipped_duplicate: usize,
    missing_budget_approval: usize,
    mismatched_budget_approval: usize,
    expected_budget_approval: Option<String>,
    errors: Vec<String>,
    relays: Vec<ShadowRunRelaySummary>,
}
#[allow(clippy::too_many_lines)]
fn build_shadow_run_summary(summary: &DaemonIterationSummary) -> ShadowRunSummary {
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct RelayAccumulator {
        epochs: usize,
        payout_nanos: u128,
        total_score: u64,
        total_availability: u64,
        total_bandwidth: u64,
        warning_epochs: usize,
        suspended_epochs: usize,
        zero_score_epochs: usize,
        amount_conversion_errors: usize,
    }
    let mut accumulators: BTreeMap<&str, RelayAccumulator> = BTreeMap::new();
    let mut payout_amount_conversion_errors = Vec::new();
    let mut payout_totals: Vec<u128> = Vec::new();
    let mut sum_availability = 0_u64;
    let mut sum_bandwidth = 0_u64;
    let mut total_epochs = 0_usize;
    let mut warning_epochs_total = 0_usize;
    let mut suspended_epochs_total = 0_usize;
    let mut zero_score_epochs_total = 0_usize;
    let mut max_relay_payout = 0_u128;
    for payout in &summary.processed {
        let relay_entry = accumulators.entry(&payout.relay_id_hex).or_default();
        let payout_nanos = match quantity_to_nanos_checked(&payout.payout_amount) {
            Ok(nanos) => nanos,
            Err(error) => {
                relay_entry.amount_conversion_errors =
                    relay_entry.amount_conversion_errors.saturating_add(1);
                payout_amount_conversion_errors.push(ShadowRunAmountConversionError {
                    relay_id_hex: payout.relay_id_hex.clone(),
                    epoch: payout.epoch,
                    amount: payout.payout_amount.to_string(),
                    reason: quantity_to_nanos_error_label(error).to_string(),
                });
                0
            }
        };
        relay_entry.epochs = relay_entry.epochs.saturating_add(1);
        relay_entry.payout_nanos = relay_entry.payout_nanos.saturating_add(payout_nanos);
        relay_entry.total_score = relay_entry
            .total_score
            .saturating_add(u64::from(payout.metrics.score_per_mille));
        relay_entry.total_availability = relay_entry
            .total_availability
            .saturating_add(u64::from(payout.metrics.availability_per_mille));
        relay_entry.total_bandwidth = relay_entry
            .total_bandwidth
            .saturating_add(u64::from(payout.metrics.bandwidth_per_mille));
        match payout.metrics.compliance_status.as_str() {
            "warning" => {
                relay_entry.warning_epochs = relay_entry.warning_epochs.saturating_add(1);
                warning_epochs_total = warning_epochs_total.saturating_add(1);
            }
            "suspended" => {
                relay_entry.suspended_epochs = relay_entry.suspended_epochs.saturating_add(1);
                suspended_epochs_total = suspended_epochs_total.saturating_add(1);
            }
            _ => {}
        }
        if payout.metrics.score_per_mille == 0 {
            relay_entry.zero_score_epochs = relay_entry.zero_score_epochs.saturating_add(1);
            zero_score_epochs_total = zero_score_epochs_total.saturating_add(1);
        }
        sum_availability =
            sum_availability.saturating_add(u64::from(payout.metrics.availability_per_mille));
        sum_bandwidth = sum_bandwidth.saturating_add(u64::from(payout.metrics.bandwidth_per_mille));
        total_epochs = total_epochs.saturating_add(1);
        payout_totals.push(payout_nanos);
    }
    let total_payout_nanos: u128 = accumulators.values().map(|acc| acc.payout_nanos).sum();
    for acc in accumulators.values() {
        if acc.payout_nanos > max_relay_payout {
            max_relay_payout = acc.payout_nanos;
        }
    }
    let mut relay_summaries: Vec<ShadowRunRelaySummary> = accumulators
        .into_iter()
        .map(|(relay_id_hex, acc)| {
            let epochs = acc.epochs.max(1); // avoid division by zero
            let epochs_f64 = usize_to_f64(epochs);
            ShadowRunRelaySummary {
                relay_id_hex: relay_id_hex.to_string(),
                epochs,
                payout_nanos: acc.payout_nanos,
                amount_conversion_errors: acc.amount_conversion_errors,
                average_payout_nanos: u128_to_f64(acc.payout_nanos) / epochs_f64,
                average_score_per_mille: u64_to_f64(acc.total_score) / epochs_f64,
                average_availability_per_mille: u64_to_f64(acc.total_availability) / epochs_f64,
                average_bandwidth_per_mille: u64_to_f64(acc.total_bandwidth) / epochs_f64,
                warning_epochs: acc.warning_epochs,
                suspended_epochs: acc.suspended_epochs,
                zero_score_epochs: acc.zero_score_epochs,
            }
        })
        .collect();
    relay_summaries.sort_by(|left, right| {
        right
            .payout_nanos
            .cmp(&left.payout_nanos)
            .then_with(|| left.relay_id_hex.cmp(&right.relay_id_hex))
    });
    let gini_coefficient = compute_gini(&payout_totals);
    let top_share = if total_payout_nanos == 0 {
        0.0
    } else {
        u128_to_f64(max_relay_payout) / u128_to_f64(total_payout_nanos)
    };
    let average_availability = if total_epochs == 0 {
        0.0
    } else {
        u64_to_f64(sum_availability) / usize_to_f64(total_epochs)
    };
    let average_bandwidth = if total_epochs == 0 {
        0.0
    } else {
        u64_to_f64(sum_bandwidth) / usize_to_f64(total_epochs)
    };
    ShadowRunSummary {
        processed_payouts: total_epochs,
        total_relays: relay_summaries.len(),
        total_payout_nanos,
        payout_amount_conversion_errors,
        gini_coefficient,
        top_relay_share: top_share,
        zero_score_epochs: zero_score_epochs_total,
        warning_epochs: warning_epochs_total,
        suspended_epochs: suspended_epochs_total,
        average_availability_per_mille: average_availability,
        average_bandwidth_per_mille: average_bandwidth,
        skipped_missing_config: summary.skipped_missing_config,
        skipped_missing_bond: summary.skipped_missing_bond,
        skipped_duplicate: summary.skipped_duplicate,
        missing_budget_approval: summary.missing_budget_approval,
        mismatched_budget_approval: summary.mismatched_budget_approval,
        expected_budget_approval: summary.expected_budget_approval.clone(),
        errors: summary.errors.clone(),
        relays: relay_summaries,
    }
}
fn compute_gini(values: &[u128]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<f64> = values.iter().map(|value| u128_to_f64(*value)).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let sum: f64 = sorted.iter().sum();
    if sum == 0.0 {
        return 0.0;
    }
    let n = usize_to_f64(sorted.len());
    let mut cumulative = 0.0;
    for (index, value) in sorted.iter().enumerate() {
        cumulative += (usize_to_f64(index) + 1.0) * value;
    }
    (2.0 * cumulative / (n * sum)) - (n + 1.0) / n
}
impl ServiceDashboardSummary {
    fn new(dashboard: &EarningsDashboard) -> Self {
        let rows = dashboard
            .rows
            .iter()
            .map(ServiceDashboardRow::from_row)
            .collect();
        Self {
            total_relays: dashboard.total_relays,
            total_open_disputes: dashboard.total_open_disputes,
            rows,
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize)]
struct ServiceDashboardRow {
    relay_id_hex: String,
    total_paid: Quantity,
    total_rebated: Quantity,
    total_withheld: Quantity,
    net_paid: Numeric,
    epochs_recorded: usize,
    last_epoch: Option<u32>,
    last_reward_score: Option<u64>,
    open_disputes: usize,
}
impl ServiceDashboardRow {
    fn from_row(row: &EarningsRow) -> Self {
        Self {
            relay_id_hex: relay_id_to_hex(row.relay_id),
            total_paid: row.total_paid.clone(),
            total_rebated: row.total_rebated.clone(),
            total_withheld: row.total_withheld.clone(),
            net_paid: row.net_paid.clone(),
            epochs_recorded: row.epochs_recorded,
            last_epoch: row.last_epoch,
            last_reward_score: row.last_reward_score,
            open_disputes: row.open_disputes,
        }
    }
}
fn parse_account_id_str<C: RunContext>(context: &C, value: &str, flag: &str) -> Result<AccountId> {
    let trimmed = value.trim();
    crate::resolve_account_id(context, trimmed)
        .wrap_err_with(|| format!("{flag} must be a valid account identifier"))
}
fn moderation_actor_or_default<C: RunContext>(
    context: &C,
    value: Option<&str>,
    flag: &str,
) -> Result<String> {
    match value {
        Some(raw) => required_trimmed_text(raw, flag),
        None => Ok(context.config().account.to_string()),
    }
}
fn required_trimmed_text(value: &str, flag: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(eyre!("{flag} must not be empty"));
    }
    Ok(trimmed.to_owned())
}
fn optional_trimmed_text(value: Option<&str>, flag: &str) -> Result<Option<String>> {
    value
        .map(|text| required_trimmed_text(text, flag))
        .transpose()
}
fn required_path_string(path: &Path, flag: &str) -> Result<String> {
    required_trimmed_text(&path.display().to_string(), flag)
}
fn required_path_strings(paths: &[PathBuf], flag: &str) -> Result<Vec<String>> {
    paths
        .iter()
        .map(|path| required_path_string(path, flag))
        .collect()
}
fn shell_single_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn systemd_quote(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}
fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}
const MODERATION_NATIVE_ACTION_INPUT_MAX_BYTES_V1: usize = 2 * 1024 * 1024;
const MODERATION_COORDINATION_STATUS_MAX_BYTES_V1: usize = 4 * 1024 * 1024;
fn load_moderation_ballot_commit_payload(
    path: &Path,
    format: &str,
) -> Result<SoraFsModerationBallotCommitV1> {
    let format = normalize_moderation_ballot_payload_format(format)?;
    let bytes = read_moderation_ballot_payload_file(path)?;
    let commit: SoraFsModerationBallotCommitV1 = match format {
        "json" => norito::json::from_slice(&bytes).wrap_err_with(|| {
            format!(
                "failed to parse moderation ballot commit JSON `{}`",
                path.display()
            )
        })?,
        "norito" => decode_from_bytes(&bytes).wrap_err_with(|| {
            format!(
                "failed to decode moderation ballot commit Norito `{}`",
                path.display()
            )
        })?,
        _ => unreachable!("format normalized"),
    };
    commit
        .validate()
        .wrap_err("moderation ballot commit validation failed")?;
    Ok(commit)
}
fn load_moderation_ballot_reveal_payload(
    path: &Path,
    format: &str,
) -> Result<SoraFsModerationBallotRevealV1> {
    let format = normalize_moderation_ballot_payload_format(format)?;
    let bytes = read_moderation_ballot_payload_file(path)?;
    let reveal: SoraFsModerationBallotRevealV1 = match format {
        "json" => norito::json::from_slice(&bytes).wrap_err_with(|| {
            format!(
                "failed to parse moderation ballot reveal JSON `{}`",
                path.display()
            )
        })?,
        "norito" => decode_from_bytes(&bytes).wrap_err_with(|| {
            format!(
                "failed to decode moderation ballot reveal Norito `{}`",
                path.display()
            )
        })?,
        _ => unreachable!("format normalized"),
    };
    reveal
        .validate()
        .wrap_err("moderation ballot reveal validation failed")?;
    Ok(reveal)
}
fn read_moderation_ballot_payload_file(path: &Path) -> Result<Vec<u8>> {
    read_bounded_moderation_file(
        path,
        "moderation ballot payload",
        MODERATION_NATIVE_ACTION_INPUT_MAX_BYTES_V1,
    )
}
fn load_moderation_commit_reveal_status_payload(path: &Path) -> Result<Value> {
    let bytes = read_bounded_moderation_file(
        path,
        "moderation commit/reveal status",
        MODERATION_COORDINATION_STATUS_MAX_BYTES_V1,
    )?;
    let status: Value = norito::json::from_slice(&bytes).wrap_err_with(|| {
        format!(
            "failed to parse moderation commit/reveal status JSON `{}`",
            path.display()
        )
    })?;
    ensure_moderation_bridge_plan_has_no_payload(&status)?;
    Ok(status)
}
fn read_bounded_moderation_file(path: &Path, label: &str, maximum: usize) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .wrap_err_with(|| format!("failed to inspect {label} `{}`", path.display()))?;
    if metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(eyre!(
            "{label} `{}` must contain between 1 and {maximum} bytes",
            path.display(),
        ));
    }
    let bytes =
        fs::read(path).wrap_err_with(|| format!("failed to read {label} `{}`", path.display()))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(eyre!(
            "{label} `{}` must contain between 1 and {maximum} bytes",
            path.display(),
        ));
    }
    Ok(bytes)
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ModerationBallotExecutionKey {
    case_id: String,
    round_id: String,
    juror_id: String,
}
impl ModerationBallotExecutionKey {
    fn from_commit(commit: &SoraFsModerationBallotCommitV1) -> Self {
        Self {
            case_id: commit.context.case_id.clone(),
            round_id: commit.round_id.clone(),
            juror_id: commit.juror_id.clone(),
        }
    }
    fn from_reveal(reveal: &SoraFsModerationBallotRevealV1) -> Self {
        Self {
            case_id: reveal.context.case_id.clone(),
            round_id: reveal.round_id.clone(),
            juror_id: reveal.juror_id.clone(),
        }
    }
    fn new(case_id: &str, round_id: &str, juror_id: &str) -> Result<Self> {
        Ok(Self {
            case_id: required_trimmed_text(case_id, "case_id")?,
            round_id: required_trimmed_text(round_id, "round_id")?,
            juror_id: required_trimmed_text(juror_id, "juror_id")?,
        })
    }
}
#[derive(Debug, Default)]
struct ModerationCommitRevealCoordination {
    pending_commits: BTreeSet<ModerationBallotExecutionKey>,
    pending_reveals: BTreeSet<ModerationBallotExecutionKey>,
    tally_ready: BTreeSet<(String, String)>,
}
fn moderation_commit_reveal_coordination_from_status(
    status: &Value,
) -> Result<ModerationCommitRevealCoordination> {
    let root = value_object(status, "commit/reveal execution status")?;
    let schema = required_string_field(root, "schema", "commit/reveal execution status")?;
    if schema != "sorafs.moderation.quarantine.commit_reveal_status.v1" {
        return Err(eyre!(
            "commit/reveal execution status schema `{schema}` is not supported"
        ));
    }
    let ballots = root
        .get("ballots")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut coordination = ModerationCommitRevealCoordination::default();
    for ballot in ballots {
        let ballot_obj = value_object(ballot, "commit/reveal execution ballot")?;
        let case_id =
            required_string_field(ballot_obj, "case_id", "commit/reveal execution ballot")?;
        let round_id =
            required_string_field(ballot_obj, "round_id", "commit/reveal execution ballot")?;
        for juror_id in moderation_commit_reveal_juror_list(ballot_obj, "missing_commit_jurors")? {
            coordination
                .pending_commits
                .insert(ModerationBallotExecutionKey::new(
                    case_id, round_id, juror_id,
                )?);
        }
        for juror_id in moderation_commit_reveal_juror_list(ballot_obj, "missing_reveal_jurors")? {
            coordination
                .pending_reveals
                .insert(ModerationBallotExecutionKey::new(
                    case_id, round_id, juror_id,
                )?);
        }
        if ballot_obj
            .get("ready_to_tally")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            coordination.tally_ready.insert((
                required_trimmed_text(case_id, "case_id")?,
                required_trimmed_text(round_id, "round_id")?,
            ));
        }
    }
    Ok(coordination)
}
fn moderation_commit_reveal_juror_list<'a>(
    ballot_obj: &'a Map,
    field: &str,
) -> Result<Vec<&'a str>> {
    let Some(values) = ballot_obj.get(field) else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .ok_or_else(|| eyre!("commit/reveal execution ballot `{field}` must be an array"))?;
    values
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                eyre!("commit/reveal execution ballot `{field}` entries must be strings")
            })
        })
        .collect()
}
fn build_moderation_transaction(
    client: &Client,
    instruction: impl Into<InstructionBox>,
) -> Result<SignedTransaction> {
    let account = client.account_client()?;
    let payload = account.prepare_transaction(
        AccountTransactionDraft::new(
            [instruction.into()],
            FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        )
        .with_time_to_live(SORAFS_MODERATION_TRANSACTION_TTL),
    )?;
    Ok(account.sign_transaction(payload)?)
}

fn build_moderation_commit_transaction(
    client: &Client,
    commit: &SoraFsModerationBallotCommitV1,
) -> Result<SignedTransaction> {
    commit
        .validate()
        .wrap_err("moderation ballot commit validation failed")?;
    if commit.committed_at_unix_ms != 0 {
        return Err(eyre!(
            "moderation commit committed_at_unix_ms must be zero; the ledger records the accepted timestamp"
        ));
    }
    if commit.juror_id != client.account().to_string() {
        return Err(eyre!(
            "moderation commit juror_id must equal the configured transaction authority"
        ));
    }
    let payload = norito::to_bytes(commit).wrap_err("encode canonical moderation commit")?;
    build_moderation_transaction(client, SubmitSorafsModerationCommit::new(payload))
        .wrap_err("build caller-signed native moderation commit transaction")
}
fn build_moderation_reveal_transaction(
    client: &Client,
    reveal: &SoraFsModerationBallotRevealV1,
) -> Result<SignedTransaction> {
    reveal
        .validate()
        .wrap_err("moderation ballot reveal validation failed")?;
    if reveal.revealed_at_unix_ms != 0 {
        return Err(eyre!(
            "moderation reveal revealed_at_unix_ms must be zero; the ledger records the accepted timestamp"
        ));
    }
    if reveal.juror_id != client.account().to_string() {
        return Err(eyre!(
            "moderation reveal juror_id must equal the configured transaction authority"
        ));
    }
    let payload = norito::to_bytes(reveal).wrap_err("encode canonical moderation reveal")?;
    build_moderation_transaction(client, SubmitSorafsModerationReveal::new(payload))
        .wrap_err("build caller-signed native moderation reveal transaction")
}
fn build_moderation_finalization_transaction(
    client: &Client,
    case_id: impl Into<String>,
    round_id: impl Into<String>,
) -> Result<SignedTransaction> {
    build_moderation_transaction(
        client,
        FinalizeSorafsModerationCase::new(case_id.into(), round_id.into()),
    )
    .wrap_err("build governed native moderation finalization transaction")
}
fn render_moderation_transaction_hash<C: RunContext>(
    context: &mut C,
    hash: &HashOf<SignedTransaction>,
) -> Result<()> {
    context.print_data(&norito::json!({
        "transaction_hash_hex": (encode(hash.as_ref()))
    }))
}
fn moderation_ballot_execution_action_json(
    action: &str,
    case_id: &str,
    round_id: &str,
    juror_id: Option<&str>,
    hash: &HashOf<SignedTransaction>,
) -> Result<Value> {
    let mut fields = Map::new();
    fields.insert("action".into(), Value::from(action.to_string()));
    fields.insert("case_id".into(), Value::from(case_id.to_string()));
    fields.insert("round_id".into(), Value::from(round_id.to_string()));
    fields.insert(
        "juror_id".into(),
        juror_id.map_or(Value::Null, |value| Value::from(value.to_string())),
    );
    fields.insert(
        "transaction_hash_hex".into(),
        Value::from(encode(hash.as_ref())),
    );
    fields.insert("payload_bytes_included".into(), Value::Bool(false));
    fields.insert("private_payloads_included".into(), Value::Bool(false));
    Ok(Value::Object(fields))
}
fn write_moderation_ballots_executor_bundle(
    args: &ModerationBallotsExecutorBundleArgs,
) -> Result<Value> {
    if args.commit_payloads.is_empty() && args.reveal_payloads.is_empty() && !args.submit_tally {
        return Err(eyre!(
            "at least one --commit-payload, --reveal-payload, or --submit-tally is required"
        ));
    }
    if args.interval_secs == 0 {
        return Err(eyre!("--interval-secs must be greater than zero"));
    }
    let status_path = required_path_string(&args.status, "--status")?;
    let commit_format = normalize_moderation_ballot_payload_format(&args.commit_format)?;
    let reveal_format = normalize_moderation_ballot_payload_format(&args.reveal_format)?;
    let iroha_bin = required_trimmed_text(&args.iroha_bin, "--iroha-bin")?;
    let service_name = required_trimmed_text(&args.service_name, "--service-name")?;
    if service_name.contains('/') || service_name.contains('\\') {
        return Err(eyre!("--service-name must not contain path separators"));
    }
    let service_user = required_trimmed_text(&args.service_user, "--service-user")?;
    let service_group = required_trimmed_text(&args.service_group, "--service-group")?;
    let commit_payloads = required_path_strings(&args.commit_payloads, "--commit-payload")?;
    let reveal_payloads = required_path_strings(&args.reveal_payloads, "--reveal-payload")?;
    fs::create_dir_all(&args.bundle_out).wrap_err_with(|| {
        format!(
            "failed to create moderation ballots executor bundle directory `{}`",
            args.bundle_out.display()
        )
    })?;
    let bundle_dir = args
        .bundle_out
        .canonicalize()
        .unwrap_or_else(|_| args.bundle_out.clone());
    let env_path = bundle_dir.join("executor.env");
    let run_path = bundle_dir.join("run.sh");
    let systemd_unit_name = format!("{service_name}.service");
    let systemd_timer_name = format!("{service_name}.timer");
    let launchd_plist_name = format!("{service_name}.plist");
    let metadata_path = bundle_dir.join("bundle.json");
    let readme_path = bundle_dir.join("README.md");
    let env = moderation_ballots_executor_bundle_env(
        &iroha_bin,
        &status_path,
        commit_format,
        reveal_format,
    );
    write_text_artifact(&env_path, &env, "moderation ballots executor environment")?;
    let run_script = moderation_ballots_executor_bundle_run_script(
        &commit_payloads,
        &reveal_payloads,
        args.submit_tally,
    );
    write_text_artifact(
        &run_path,
        &run_script,
        "moderation ballots executor run script",
    )?;
    set_executable_if_supported(&run_path)?;
    let systemd_unit = moderation_ballots_executor_bundle_systemd_unit(
        &service_name,
        &service_user,
        &service_group,
        &bundle_dir,
        &run_path,
        &env_path,
    );
    write_text_artifact(
        &bundle_dir.join(&systemd_unit_name),
        &systemd_unit,
        "moderation ballots executor systemd unit",
    )?;
    let systemd_timer =
        moderation_ballots_executor_bundle_systemd_timer(&service_name, args.interval_secs);
    write_text_artifact(
        &bundle_dir.join(&systemd_timer_name),
        &systemd_timer,
        "moderation ballots executor systemd timer",
    )?;
    let launchd = moderation_ballots_executor_bundle_launchd_plist(
        &service_name,
        &bundle_dir,
        &run_path,
        args.interval_secs,
    );
    write_text_artifact(
        &bundle_dir.join(&launchd_plist_name),
        &launchd,
        "moderation ballots executor launchd plist",
    )?;
    let readme = moderation_ballots_executor_bundle_readme(
        &status_path,
        commit_payloads.len(),
        reveal_payloads.len(),
        args.submit_tally,
        args.interval_secs,
        &systemd_unit_name,
        &systemd_timer_name,
        &launchd_plist_name,
    );
    write_text_artifact(
        &readme_path,
        &readme,
        "moderation ballots executor bundle README",
    )?;
    let files = vec![
        "executor.env",
        "run.sh",
        systemd_unit_name.as_str(),
        systemd_timer_name.as_str(),
        launchd_plist_name.as_str(),
        "bundle.json",
        "README.md",
    ];
    let summary = moderation_ballots_executor_bundle_summary_json(
        &bundle_dir,
        &status_path,
        commit_format,
        reveal_format,
        commit_payloads.len(),
        reveal_payloads.len(),
        args.submit_tally,
        args.interval_secs,
        &iroha_bin,
        &service_name,
        &service_user,
        &service_group,
        &systemd_unit_name,
        &systemd_timer_name,
        &launchd_plist_name,
        &files,
    );
    write_json_artifact(
        &metadata_path,
        &summary,
        "moderation ballots executor bundle metadata",
    )?;
    Ok(summary)
}
fn moderation_ballots_executor_bundle_env(
    iroha_bin: &str,
    status_path: &str,
    commit_format: &str,
    reveal_format: &str,
) -> String {
    format!(
        "IROHA_BIN={}\nSORAFS_BALLOTS_EXECUTOR_STATUS_PATH={}\nSORAFS_BALLOTS_EXECUTOR_COMMIT_FORMAT={}\nSORAFS_BALLOTS_EXECUTOR_REVEAL_FORMAT={}\n",
        shell_single_quote(iroha_bin),
        shell_single_quote(status_path),
        shell_single_quote(commit_format),
        shell_single_quote(reveal_format)
    )
}
fn moderation_ballots_executor_bundle_run_script(
    commit_payloads: &[String],
    reveal_payloads: &[String],
    submit_tally: bool,
) -> String {
    let mut command_args = vec![
        "  --status=\"$SORAFS_BALLOTS_EXECUTOR_STATUS_PATH\"".to_string(),
        "  --commit-format=\"$SORAFS_BALLOTS_EXECUTOR_COMMIT_FORMAT\"".to_string(),
        "  --reveal-format=\"$SORAFS_BALLOTS_EXECUTOR_REVEAL_FORMAT\"".to_string(),
    ];
    command_args.extend(
        commit_payloads
            .iter()
            .map(|path| format!("  --commit-payload={}", shell_single_quote(path))),
    );
    command_args.extend(
        reveal_payloads
            .iter()
            .map(|path| format!("  --reveal-payload={}", shell_single_quote(path))),
    );
    if submit_tally {
        command_args.push("  --submit-tally".to_string());
    }
    format!(
        "#!/usr/bin/env sh\nset -eu\nSCRIPT_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\nif [ -f \"$SCRIPT_DIR/executor.env\" ]; then\n  . \"$SCRIPT_DIR/executor.env\"\nfi\n: \"${{IROHA_BIN:=iroha}}\"\n: \"${{SORAFS_BALLOTS_EXECUTOR_STATUS_PATH:?set SORAFS_BALLOTS_EXECUTOR_STATUS_PATH in executor.env}}\"\n: \"${{SORAFS_BALLOTS_EXECUTOR_COMMIT_FORMAT:=json}}\"\n: \"${{SORAFS_BALLOTS_EXECUTOR_REVEAL_FORMAT:=json}}\"\nexec \"$IROHA_BIN\" sorafs moderation ballots execute \\\n{}\n",
        command_args.join(" \\\n")
    )
}
fn moderation_ballots_executor_bundle_systemd_unit(
    service_name: &str,
    service_user: &str,
    service_group: &str,
    bundle_dir: &Path,
    run_path: &Path,
    env_path: &Path,
) -> String {
    format!(
        "[Unit]\nDescription=SoraFS moderation ballot executor ({})\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nUser={}\nGroup={}\nWorkingDirectory={}\nEnvironmentFile={}\nExecStart={}\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=full\n\n[Install]\nWantedBy=multi-user.target\n",
        service_name,
        service_user,
        service_group,
        systemd_quote(&bundle_dir.display().to_string()),
        systemd_quote(&env_path.display().to_string()),
        systemd_quote(&run_path.display().to_string())
    )
}
fn moderation_ballots_executor_bundle_systemd_timer(
    service_name: &str,
    interval_secs: u64,
) -> String {
    format!(
        "[Unit]\nDescription=Schedule SoraFS moderation ballot executor ({})\n\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec={}s\nAccuracySec=5s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        service_name, interval_secs
    )
}
fn moderation_ballots_executor_bundle_launchd_plist(
    service_name: &str,
    bundle_dir: &Path,
    run_path: &Path,
    interval_secs: u64,
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n  </array>\n  <key>WorkingDirectory</key>\n  <string>{}</string>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>StartInterval</key>\n  <integer>{}</integer>\n  <key>StandardOutPath</key>\n  <string>{}</string>\n  <key>StandardErrorPath</key>\n  <string>{}</string>\n</dict>\n</plist>\n",
        xml_escape(service_name),
        xml_escape(&run_path.display().to_string()),
        xml_escape(&bundle_dir.display().to_string()),
        interval_secs,
        xml_escape(&bundle_dir.join("executor.out.log").display().to_string()),
        xml_escape(&bundle_dir.join("executor.err.log").display().to_string())
    )
}
fn moderation_ballots_executor_bundle_readme(
    status_path: &str,
    commit_payload_count: usize,
    reveal_payload_count: usize,
    submit_tally: bool,
    interval_secs: u64,
    systemd_unit_name: &str,
    systemd_timer_name: &str,
    launchd_plist_name: &str,
) -> String {
    format!(
        "# SoraFS Moderation Ballot Executor Bundle\n\nThis bundle runs `iroha sorafs moderation ballots execute` as a scheduled local job. It does not copy private commit or reveal payload files; keep those files in an operator-controlled location and update `run.sh` only if their runtime paths change.\n\n- Status path: `{}`\n- Commit payload paths referenced: `{}`\n- Reveal payload paths referenced: `{}`\n- Submit tally requests: `{}`\n- Interval seconds: `{}`\n\nRun directly:\n\n```sh\n./run.sh\n```\n\nInstall with systemd:\n\n```sh\nsudo cp {} {} /etc/systemd/system/\nsudo systemctl daemon-reload\nsudo systemctl enable --now {}\n```\n\nInstall with launchd:\n\n```sh\ncp {} ~/Library/LaunchAgents/\nlaunchctl load ~/Library/LaunchAgents/{}\n```\n\nReplace `IROHA_BIN` in `executor.env` with the absolute path to the audited `iroha` binary on the target host before installing.\n",
        status_path,
        commit_payload_count,
        reveal_payload_count,
        submit_tally,
        interval_secs,
        systemd_unit_name,
        systemd_timer_name,
        systemd_timer_name,
        launchd_plist_name,
        launchd_plist_name
    )
}
#[allow(clippy::too_many_arguments)]
fn moderation_ballots_executor_bundle_summary_json(
    bundle_dir: &Path,
    status_path: &str,
    commit_format: &str,
    reveal_format: &str,
    commit_payload_count: usize,
    reveal_payload_count: usize,
    submit_tally: bool,
    interval_secs: u64,
    iroha_bin: &str,
    service_name: &str,
    service_user: &str,
    service_group: &str,
    systemd_unit_name: &str,
    systemd_timer_name: &str,
    launchd_plist_name: &str,
    files: &[&str],
) -> Value {
    let mut summary = Map::new();
    summary.insert(
        "schema".into(),
        Value::from("sorafs.moderation.ballots.executor_bundle.v1"),
    );
    summary.insert("source".into(), Value::from("iroha_cli"));
    summary.insert(
        "bundle_dir".into(),
        Value::from(bundle_dir.display().to_string()),
    );
    summary.insert("status_path".into(), Value::from(status_path.to_string()));
    summary.insert(
        "commit_format".into(),
        Value::from(commit_format.to_string()),
    );
    summary.insert(
        "reveal_format".into(),
        Value::from(reveal_format.to_string()),
    );
    summary.insert(
        "commit_payload_count".into(),
        Value::from(u64::try_from(commit_payload_count).unwrap_or(u64::MAX)),
    );
    summary.insert(
        "reveal_payload_count".into(),
        Value::from(u64::try_from(reveal_payload_count).unwrap_or(u64::MAX)),
    );
    summary.insert("submit_tally".into(), Value::Bool(submit_tally));
    summary.insert("interval_secs".into(), Value::from(interval_secs));
    summary.insert("iroha_bin".into(), Value::from(iroha_bin.to_string()));
    summary.insert("service_name".into(), Value::from(service_name.to_string()));
    summary.insert("service_user".into(), Value::from(service_user.to_string()));
    summary.insert(
        "service_group".into(),
        Value::from(service_group.to_string()),
    );
    summary.insert(
        "systemd_unit".into(),
        Value::from(systemd_unit_name.to_string()),
    );
    summary.insert(
        "systemd_timer".into(),
        Value::from(systemd_timer_name.to_string()),
    );
    summary.insert(
        "launchd_plist".into(),
        Value::from(launchd_plist_name.to_string()),
    );
    summary.insert(
        "files".into(),
        Value::Array(
            files
                .iter()
                .map(|file| Value::from((*file).to_string()))
                .collect(),
        ),
    );
    summary.insert("payload_bytes_included".into(), Value::Bool(false));
    summary.insert("private_payloads_included".into(), Value::Bool(false));
    summary.insert("private_payload_files_copied".into(), Value::Bool(false));
    Value::Object(summary)
}
fn moderation_ballots_executor_canary_evidence(
    args: &ModerationBallotsExecutorCanaryArgs,
) -> Result<Value> {
    let bundle_dir = args
        .bundle
        .canonicalize()
        .unwrap_or_else(|_| args.bundle.clone());
    let metadata_path = bundle_dir.join("bundle.json");
    let (metadata, metadata_bytes) = read_json_artifact(
        &metadata_path,
        "moderation ballots executor bundle metadata",
    )?;
    ensure_moderation_bridge_plan_has_no_payload(&metadata)?;
    let metadata_fields = value_object(&metadata, "moderation ballots executor bundle metadata")?;
    let schema = required_string_field(
        metadata_fields,
        "schema",
        "moderation ballots executor bundle metadata",
    )?;
    if schema != "sorafs.moderation.ballots.executor_bundle.v1" {
        return Err(eyre!(
            "moderation ballots executor bundle metadata schema `{schema}` is not supported"
        ));
    }
    require_json_bool_false(
        metadata_fields,
        "payload_bytes_included",
        "moderation ballots executor bundle metadata",
    )?;
    require_json_bool_false(
        metadata_fields,
        "private_payloads_included",
        "moderation ballots executor bundle metadata",
    )?;
    require_json_bool_false(
        metadata_fields,
        "private_payload_files_copied",
        "moderation ballots executor bundle metadata",
    )?;
    let service_name = required_nonblank_string_field(
        metadata_fields,
        "service_name",
        "moderation ballots executor bundle metadata",
    )?;
    let interval_secs = metadata_fields
        .get("interval_secs")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let systemd_unit = required_nonblank_string_field(
        metadata_fields,
        "systemd_unit",
        "moderation ballots executor bundle metadata",
    )?;
    let systemd_timer = required_nonblank_string_field(
        metadata_fields,
        "systemd_timer",
        "moderation ballots executor bundle metadata",
    )?;
    let launchd_plist = required_nonblank_string_field(
        metadata_fields,
        "launchd_plist",
        "moderation ballots executor bundle metadata",
    )?;
    let artifact_specs = [
        ("executor.env", "env"),
        ("run.sh", "run_script"),
        (systemd_unit, "systemd_unit"),
        (systemd_timer, "systemd_timer"),
        (launchd_plist, "launchd_plist"),
        ("README.md", "readme"),
        ("bundle.json", "metadata"),
    ];
    let mut artifacts = Vec::new();
    let mut passed_artifact_count = 0_u64;
    for (name, kind) in artifact_specs {
        let probe = moderation_ballots_executor_canary_artifact(&bundle_dir, name, kind)?;
        if probe
            .get("passed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            passed_artifact_count = passed_artifact_count.saturating_add(1);
        }
        artifacts.push(probe);
    }
    let execution_summary = args
        .execution_summary
        .as_deref()
        .map(moderation_ballots_executor_canary_execution_summary)
        .transpose()?;
    let execution_summary_passed = execution_summary
        .as_ref()
        .and_then(|summary| summary.get("passed"))
        .and_then(Value::as_bool)
        .unwrap_or(args.execution_summary.is_none());
    let artifact_count = u64::try_from(artifacts.len()).unwrap_or(u64::MAX);
    let artifacts_passed = passed_artifact_count == artifact_count;
    let status = if artifacts_passed && execution_summary_passed {
        "passed"
    } else {
        "failed"
    };
    let mut evidence = Map::new();
    evidence.insert(
        "schema".into(),
        Value::from("sorafs.moderation.ballots.executor_canary.v1"),
    );
    evidence.insert("source".into(), Value::from("executor-bundle"));
    evidence.insert("status".into(), Value::from(status));
    evidence.insert(
        "bundle_dir".into(),
        Value::from(bundle_dir.display().to_string()),
    );
    evidence.insert(
        "bundle_metadata_bytes".into(),
        Value::from(u64::try_from(metadata_bytes.len()).unwrap_or(u64::MAX)),
    );
    evidence.insert(
        "bundle_metadata_blake3".into(),
        Value::from(encode(blake3::hash(&metadata_bytes).as_bytes())),
    );
    evidence.insert("service_name".into(), Value::from(service_name.to_string()));
    evidence.insert("interval_secs".into(), Value::from(interval_secs));
    evidence.insert("artifact_count".into(), Value::from(artifact_count));
    evidence.insert(
        "passed_artifact_count".into(),
        Value::from(passed_artifact_count),
    );
    evidence.insert(
        "execution_summary_present".into(),
        Value::Bool(args.execution_summary.is_some()),
    );
    evidence.insert(
        "execution_summary".into(),
        execution_summary.unwrap_or(Value::Null),
    );
    evidence.insert("payload_bytes_included".into(), Value::Bool(false));
    evidence.insert("private_payloads_included".into(), Value::Bool(false));
    evidence.insert("private_payload_files_copied".into(), Value::Bool(false));
    evidence.insert("artifacts".into(), Value::Array(artifacts));
    Ok(Value::Object(evidence))
}
fn moderation_ballots_executor_canary_artifact(
    bundle_dir: &Path,
    name: &str,
    kind: &str,
) -> Result<Value> {
    let path = bundle_dir.join(name);
    let mut fields = Map::new();
    fields.insert("name".into(), Value::from(name.to_string()));
    fields.insert("kind".into(), Value::from(kind.to_string()));
    fields.insert("path".into(), Value::from(path.display().to_string()));
    fields.insert("payload_bytes_included".into(), Value::Bool(false));
    fields.insert("private_payloads_included".into(), Value::Bool(false));
    if !path.exists() {
        fields.insert("exists".into(), Value::Bool(false));
        fields.insert("passed".into(), Value::Bool(false));
        fields.insert("checks".into(), Value::Array(Vec::new()));
        return Ok(Value::Object(fields));
    }
    let bytes = fs::read(&path).wrap_err_with(|| {
        format!(
            "failed to read executor canary artifact `{}`",
            path.display()
        )
    })?;
    let body = String::from_utf8_lossy(&bytes);
    if body.contains("payload_b64") {
        return Err(eyre!(
            "executor canary artifact `{}` unexpectedly contains `payload_b64`",
            path.display()
        ));
    }
    let checks = moderation_ballots_executor_artifact_checks(kind, &body, &path)?;
    let passed = checks.iter().all(|check| {
        check
            .get("passed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    });
    fields.insert("exists".into(), Value::Bool(true));
    fields.insert(
        "bytes".into(),
        Value::from(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
    );
    fields.insert(
        "body_blake3".into(),
        Value::from(encode(blake3::hash(&bytes).as_bytes())),
    );
    fields.insert("passed".into(), Value::Bool(passed));
    fields.insert("checks".into(), Value::Array(checks));
    Ok(Value::Object(fields))
}
fn moderation_ballots_executor_artifact_checks(
    kind: &str,
    body: &str,
    path: &Path,
) -> Result<Vec<Value>> {
    let mut checks = Vec::new();
    match kind {
        "env" => {
            checks.push(check_json(
                "status_path_env",
                body.contains("SORAFS_BALLOTS_EXECUTOR_STATUS_PATH="),
            ));
            checks.push(check_json(
                "commit_format_env",
                body.contains("SORAFS_BALLOTS_EXECUTOR_COMMIT_FORMAT="),
            ));
            checks.push(check_json(
                "reveal_format_env",
                body.contains("SORAFS_BALLOTS_EXECUTOR_REVEAL_FORMAT="),
            ));
        }
        "run_script" => {
            checks.push(check_json(
                "executes_ballots_execute",
                body.contains("sorafs moderation ballots execute"),
            ));
            checks.push(check_json(
                "uses_status_env",
                body.contains("--status=\"$SORAFS_BALLOTS_EXECUTOR_STATUS_PATH\""),
            ));
            checks.push(check_json("executable", file_is_executable(path)));
        }
        "systemd_unit" => {
            checks.push(check_json("oneshot", body.contains("Type=oneshot")));
            checks.push(check_json("exec_start", body.contains("ExecStart=")));
            checks.push(check_json(
                "no_new_privileges",
                body.contains("NoNewPrivileges=true"),
            ));
        }
        "systemd_timer" => {
            checks.push(check_json(
                "active_interval",
                body.contains("OnUnitActiveSec="),
            ));
            checks.push(check_json("persistent", body.contains("Persistent=true")));
        }
        "launchd_plist" => {
            checks.push(check_json("start_interval", body.contains("StartInterval")));
            checks.push(check_json("run_at_load", body.contains("RunAtLoad")));
        }
        "readme" => {
            checks.push(check_json(
                "documents_private_payload_posture",
                body.contains("does not copy private commit or reveal payload files"),
            ));
        }
        "metadata" => {
            checks.push(check_json(
                "metadata_schema",
                body.contains("sorafs.moderation.ballots.executor_bundle.v1"),
            ));
            checks.push(check_json(
                "metadata_payload_free",
                body.contains("\"payload_bytes_included\": false"),
            ));
        }
        _ => checks.push(check_json("known_artifact_kind", false)),
    }
    Ok(checks)
}
fn moderation_ballots_executor_canary_execution_summary(path: &Path) -> Result<Value> {
    let (summary, bytes) =
        read_json_artifact(path, "moderation ballots executor execution summary")?;
    ensure_moderation_bridge_plan_has_no_payload(&summary)?;
    let fields = value_object(&summary, "moderation ballots executor execution summary")?;
    let schema = required_string_field(
        fields,
        "schema",
        "moderation ballots executor execution summary",
    )?;
    if schema != "sorafs.moderation.ballots.execution.v1" {
        return Err(eyre!(
            "moderation ballots executor execution summary schema `{schema}` is not supported"
        ));
    }
    require_json_bool_false(
        fields,
        "payload_bytes_included",
        "moderation ballots executor execution summary",
    )?;
    require_json_bool_false(
        fields,
        "private_payloads_included",
        "moderation ballots executor execution summary",
    )?;
    let actions = fields
        .get("actions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for action in actions {
        let action_fields = value_object(action, "moderation ballots executor action summary")?;
        let transaction_hash_hex = required_string_field(
            action_fields,
            "transaction_hash_hex",
            "moderation ballots executor action summary",
        )?;
        let canonical_transaction_hash = normalize_hex_digest::<32>(
            transaction_hash_hex,
            "moderation ballots executor action transaction_hash_hex",
        )?;
        if transaction_hash_hex != canonical_transaction_hash {
            return Err(eyre!(
                "moderation ballots executor action transaction_hash_hex must be canonical lowercase hex"
            ));
        }
        for stale_field in ["response_status", "response_bytes", "response_body_blake3"] {
            if action_fields.contains_key(stale_field) {
                return Err(eyre!(
                    "moderation ballots executor action must not contain legacy `{stale_field}`"
                ));
            }
        }
        require_json_bool_false(
            action_fields,
            "payload_bytes_included",
            "moderation ballots executor action summary",
        )?;
        require_json_bool_false(
            action_fields,
            "private_payloads_included",
            "moderation ballots executor action summary",
        )?;
    }
    let mut evidence = Map::new();
    evidence.insert("passed".into(), Value::Bool(true));
    evidence.insert("path".into(), Value::from(path.display().to_string()));
    evidence.insert(
        "bytes".into(),
        Value::from(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
    );
    evidence.insert(
        "body_blake3".into(),
        Value::from(encode(blake3::hash(&bytes).as_bytes())),
    );
    evidence.insert(
        "action_count".into(),
        fields.get("action_count").cloned().unwrap_or(Value::Null),
    );
    evidence.insert(
        "commit_action_count".into(),
        fields
            .get("commit_action_count")
            .cloned()
            .unwrap_or(Value::Null),
    );
    evidence.insert(
        "reveal_action_count".into(),
        fields
            .get("reveal_action_count")
            .cloned()
            .unwrap_or(Value::Null),
    );
    evidence.insert(
        "tally_action_count".into(),
        fields
            .get("tally_action_count")
            .cloned()
            .unwrap_or(Value::Null),
    );
    evidence.insert("payload_bytes_included".into(), Value::Bool(false));
    evidence.insert("private_payloads_included".into(), Value::Bool(false));
    Ok(Value::Object(evidence))
}
fn check_json(name: &str, passed: bool) -> Value {
    let mut fields = Map::new();
    fields.insert("name".into(), Value::from(name.to_string()));
    fields.insert("passed".into(), Value::Bool(passed));
    Value::Object(fields)
}
fn file_is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}
fn post_moderation_juror_notification_webhook(
    client: &BlockingHttpClient,
    url: &str,
    body: &[u8],
) -> Result<Response<Vec<u8>>> {
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(body.to_vec())
        .send()
        .wrap_err_with(|| format!("failed to deliver juror notification webhook `{url}`"))?;
    let status = StatusCode::from_u16(response.status().as_u16())
        .wrap_err("failed to convert juror notification webhook status")?;
    let body = response
        .bytes()
        .wrap_err("failed to read juror notification webhook response body")?
        .to_vec();
    Ok(Response::builder().status(status).body(body).unwrap())
}
fn load_moderation_juror_notifications_manifest(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).wrap_err_with(|| {
        format!(
            "failed to read juror notification manifest `{}`",
            path.display()
        )
    })?;
    if bytes.is_empty() {
        return Err(eyre!(
            "juror notification manifest `{}` must not be empty",
            path.display()
        ));
    }
    let manifest: Value = norito::json::from_slice(&bytes).wrap_err_with(|| {
        format!(
            "failed to parse juror notification manifest JSON `{}`",
            path.display()
        )
    })?;
    ensure_moderation_bridge_plan_has_no_payload(&manifest)?;
    Ok(manifest)
}
#[derive(Clone, Copy)]
struct ModerationJurorNotificationEntry<'a> {
    value: &'a Value,
    delivery_id: &'a str,
    dedup_key: &'a str,
    action: &'a str,
    case_id: &'a str,
    round_id: &'a str,
    juror_id: &'a str,
}
fn moderation_juror_notification_entries(
    manifest: &Value,
) -> Result<Vec<ModerationJurorNotificationEntry<'_>>> {
    let root = value_object(manifest, "juror notification manifest")?;
    let schema = required_string_field(root, "schema", "juror notification manifest")?;
    if schema != "sorafs.moderation.quarantine.juror_notifications.v1" {
        return Err(eyre!(
            "juror notification manifest schema `{schema}` is not supported"
        ));
    }
    require_json_bool_false(
        root,
        "payload_bytes_included",
        "juror notification manifest",
    )?;
    require_json_bool_false(
        root,
        "private_payloads_included",
        "juror notification manifest",
    )?;
    let notifications = root
        .get("notifications")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("juror notification manifest is missing `notifications` array"))?;
    notifications
        .iter()
        .map(moderation_juror_notification_entry)
        .collect()
}
fn moderation_juror_notification_entry(
    value: &Value,
) -> Result<ModerationJurorNotificationEntry<'_>> {
    let fields = value_object(value, "juror notification entry")?;
    let schema = required_string_field(fields, "schema", "juror notification entry")?;
    if schema != "sorafs.moderation.juror_notification.v1" {
        return Err(eyre!(
            "juror notification entry schema `{schema}` is not supported"
        ));
    }
    require_json_bool_false(fields, "payload_bytes_included", "juror notification entry")?;
    require_json_bool_false(
        fields,
        "private_payload_included",
        "juror notification entry",
    )?;
    Ok(ModerationJurorNotificationEntry {
        value,
        delivery_id: required_nonblank_string_field(
            fields,
            "delivery_id",
            "juror notification entry",
        )?,
        dedup_key: required_nonblank_string_field(fields, "dedup_key", "juror notification entry")?,
        action: required_nonblank_string_field(fields, "action", "juror notification entry")?,
        case_id: required_nonblank_string_field(fields, "case_id", "juror notification entry")?,
        round_id: required_nonblank_string_field(fields, "round_id", "juror notification entry")?,
        juror_id: required_nonblank_string_field(fields, "juror_id", "juror notification entry")?,
    })
}
fn require_json_bool_false(fields: &Map, field: &str, context: &str) -> Result<()> {
    match fields.get(field).and_then(Value::as_bool) {
        Some(false) => Ok(()),
        Some(true) => Err(eyre!("{context} must set `{field}` to false")),
        None => Err(eyre!("{context} is missing boolean `{field}`")),
    }
}
fn required_nonblank_string_field<'a>(
    fields: &'a Map,
    field: &str,
    context: &str,
) -> Result<&'a str> {
    let value = required_string_field(fields, field, context)?;
    if value.trim().is_empty() {
        return Err(eyre!("{context} string `{field}` must not be empty"));
    }
    Ok(value)
}
fn safe_moderation_notification_filename(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}
fn moderation_juror_notification_delivery_result_json(
    notification: ModerationJurorNotificationEntry<'_>,
    notification_bytes: usize,
    canonical: &[u8],
    outbox_path: Value,
    webhook_status: Value,
    webhook_response_bytes: Value,
    webhook_response_body_blake3: Value,
) -> Value {
    let mut fields = Map::new();
    fields.insert(
        "delivery_id".into(),
        Value::from(notification.delivery_id.to_string()),
    );
    fields.insert(
        "dedup_key".into(),
        Value::from(notification.dedup_key.to_string()),
    );
    fields.insert(
        "action".into(),
        Value::from(notification.action.to_string()),
    );
    fields.insert(
        "case_id".into(),
        Value::from(notification.case_id.to_string()),
    );
    fields.insert(
        "round_id".into(),
        Value::from(notification.round_id.to_string()),
    );
    fields.insert(
        "juror_id".into(),
        Value::from(notification.juror_id.to_string()),
    );
    fields.insert(
        "notification_bytes".into(),
        Value::from(u64::try_from(notification_bytes).unwrap_or(u64::MAX)),
    );
    fields.insert(
        "notification_body_blake3".into(),
        Value::from(encode(blake3::hash(canonical).as_bytes())),
    );
    fields.insert("outbox_path".into(), outbox_path);
    fields.insert("webhook_status".into(), webhook_status);
    fields.insert("webhook_response_bytes".into(), webhook_response_bytes);
    fields.insert(
        "webhook_response_body_blake3".into(),
        webhook_response_body_blake3,
    );
    fields.insert("payload_bytes_included".into(), Value::Bool(false));
    fields.insert("private_payloads_included".into(), Value::Bool(false));
    Value::Object(fields)
}
fn moderation_juror_notification_canary_probe_json(
    notification: ModerationJurorNotificationEntry<'_>,
    canonical: &[u8],
    response: Response<Vec<u8>>,
) -> Result<Value> {
    let status = response.status();
    let body = response.into_body();
    let mut fields = Map::new();
    fields.insert(
        "delivery_id".into(),
        Value::from(notification.delivery_id.to_string()),
    );
    fields.insert(
        "dedup_key".into(),
        Value::from(notification.dedup_key.to_string()),
    );
    fields.insert(
        "action".into(),
        Value::from(notification.action.to_string()),
    );
    fields.insert(
        "case_id".into(),
        Value::from(notification.case_id.to_string()),
    );
    fields.insert(
        "round_id".into(),
        Value::from(notification.round_id.to_string()),
    );
    fields.insert(
        "juror_id".into(),
        Value::from(notification.juror_id.to_string()),
    );
    fields.insert(
        "notification_bytes".into(),
        Value::from(u64::try_from(canonical.len()).unwrap_or(u64::MAX)),
    );
    fields.insert(
        "notification_body_blake3".into(),
        Value::from(encode(blake3::hash(canonical).as_bytes())),
    );
    fields.insert(
        "response_status".into(),
        Value::from(u64::from(status.as_u16())),
    );
    fields.insert("response_success".into(), Value::Bool(status.is_success()));
    fields.insert(
        "response_bytes".into(),
        Value::from(u64::try_from(body.len()).unwrap_or(u64::MAX)),
    );
    fields.insert(
        "response_body_blake3".into(),
        Value::from(encode(blake3::hash(&body).as_bytes())),
    );
    fields.insert("payload_bytes_included".into(), Value::Bool(false));
    fields.insert("private_payloads_included".into(), Value::Bool(false));
    Ok(Value::Object(fields))
}
fn moderation_canary_probe_ok(probe: &Value) -> bool {
    probe
        .get("response_success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
fn write_json_artifact(path: &Path, value: &Value, label: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).wrap_err_with(|| {
            format!("failed to create {label} directory `{}`", parent.display())
        })?;
    }
    fs::write(path, norito::json::to_vec_pretty(value)?)
        .wrap_err_with(|| format!("failed to write {label} `{}`", path.display()))
}
fn read_json_artifact(path: &Path, label: &str) -> Result<(Value, Vec<u8>)> {
    let bytes =
        fs::read(path).wrap_err_with(|| format!("failed to read {label} `{}`", path.display()))?;
    if bytes.is_empty() {
        return Err(eyre!("{label} `{}` must not be empty", path.display()));
    }
    let value = norito::json::from_slice(&bytes)
        .wrap_err_with(|| format!("failed to parse {label} JSON `{}`", path.display()))?;
    Ok((value, bytes))
}
fn write_text_artifact(path: &Path, value: &str, label: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).wrap_err_with(|| {
            format!("failed to create {label} directory `{}`", parent.display())
        })?;
    }
    fs::write(path, value).wrap_err_with(|| format!("failed to write {label} `{}`", path.display()))
}
fn set_executable_if_supported(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(path)
            .wrap_err_with(|| format!("failed to stat `{}`", path.display()))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)
            .wrap_err_with(|| format!("failed to chmod `{}`", path.display()))?;
    }
    Ok(())
}
fn transparency_token_issuance_canary_probe_json(
    path: &Path,
    payload: &[u8],
    response: Response<Vec<u8>>,
) -> Value {
    let status = response.status();
    let body = response.into_body();
    let mut fields = Map::new();
    fields.insert(
        "payload_path".into(),
        Value::from(path.display().to_string()),
    );
    fields.insert(
        "request_bytes".into(),
        Value::from(u64::try_from(payload.len()).unwrap_or(u64::MAX)),
    );
    fields.insert(
        "request_body_blake3".into(),
        Value::from(encode(blake3::hash(payload).as_bytes())),
    );
    fields.insert(
        "response_status".into(),
        Value::from(u64::from(status.as_u16())),
    );
    fields.insert("response_success".into(), Value::Bool(status.is_success()));
    fields.insert(
        "response_bytes".into(),
        Value::from(u64::try_from(body.len()).unwrap_or(u64::MAX)),
    );
    fields.insert(
        "response_body_blake3".into(),
        Value::from(encode(blake3::hash(&body).as_bytes())),
    );
    fields.insert("payload_bytes_included".into(), Value::Bool(false));
    fields.insert("proof_token_frame_included".into(), Value::Bool(false));
    fields.insert("private_digest_keys_included".into(), Value::Bool(false));
    fields.insert("response_body_included".into(), Value::Bool(false));
    Value::Object(fields)
}
fn transparency_privacy_aggregate_canary_probe_json(
    action: &str,
    path: &Path,
    payload: &[u8],
    response: Response<Vec<u8>>,
) -> Value {
    let status = response.status();
    let body = response.into_body();
    let mut fields = Map::new();
    fields.insert("action".into(), Value::from(action.to_string()));
    fields.insert(
        "payload_path".into(),
        Value::from(path.display().to_string()),
    );
    fields.insert(
        "request_bytes".into(),
        Value::from(u64::try_from(payload.len()).unwrap_or(u64::MAX)),
    );
    fields.insert(
        "request_body_blake3".into(),
        Value::from(encode(blake3::hash(payload).as_bytes())),
    );
    fields.insert(
        "response_status".into(),
        Value::from(u64::from(status.as_u16())),
    );
    fields.insert("response_success".into(), Value::Bool(status.is_success()));
    fields.insert(
        "response_bytes".into(),
        Value::from(u64::try_from(body.len()).unwrap_or(u64::MAX)),
    );
    fields.insert(
        "response_body_blake3".into(),
        Value::from(encode(blake3::hash(&body).as_bytes())),
    );
    fields.insert("payload_bytes_included".into(), Value::Bool(false));
    fields.insert("raw_metric_values_included".into(), Value::Bool(false));
    fields.insert("private_payloads_included".into(), Value::Bool(false));
    Value::Object(fields)
}
fn load_sorafs_json_payload(path: &Path, label: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read {label} payload `{}`", path.display(),))?;
    if bytes.is_empty() {
        return Err(eyre!(
            "{label} payload `{}` must not be empty",
            path.display()
        ));
    }
    let value: Value = norito::json::from_slice(&bytes)
        .wrap_err_with(|| format!("failed to parse {label} JSON `{}`", path.display()))?;
    norito::json::to_vec(&value).wrap_err_with(|| format!("failed to encode {label} JSON"))
}
fn normalize_moderation_ballot_payload_format(format: &str) -> Result<&'static str> {
    match format.trim().to_ascii_lowercase().as_str() {
        "json" => Ok("json"),
        "norito" => Ok("norito"),
        other => Err(eyre!(
            "--format must be `json` or `norito` for moderation ballot payloads, got `{other}`"
        )),
    }
}
fn load_moderation_registry_repro_manifest_bytes(path: &Path, format: &str) -> Result<Vec<u8>> {
    let format = normalize_moderation_registry_manifest_format(format)?;
    let bytes = read_moderation_registry_manifest_file(path)?;
    let manifest: ModerationReproManifestV1 = match format {
        "json" => norito::json::from_slice(&bytes).wrap_err_with(|| {
            format!(
                "failed to parse reproducibility manifest JSON `{}`",
                path.display()
            )
        })?,
        "norito" => decode_from_bytes(&bytes).wrap_err_with(|| {
            format!(
                "failed to decode reproducibility manifest Norito `{}`",
                path.display()
            )
        })?,
        _ => unreachable!("format normalized"),
    };
    manifest
        .validate()
        .wrap_err("reproducibility manifest validation failed")?;
    norito::to_bytes(&manifest).wrap_err("failed to encode canonical reproducibility manifest")
}
fn load_moderation_registry_corpus_manifest_bytes(path: &Path, format: &str) -> Result<Vec<u8>> {
    let format = normalize_moderation_registry_manifest_format(format)?;
    let bytes = read_moderation_registry_manifest_file(path)?;
    let manifest: AdversarialCorpusManifestV1 = match format {
        "json" => norito::json::from_slice(&bytes).wrap_err_with(|| {
            format!(
                "failed to parse adversarial corpus manifest JSON `{}`",
                path.display()
            )
        })?,
        "norito" => decode_from_bytes(&bytes).wrap_err_with(|| {
            format!(
                "failed to decode adversarial corpus manifest Norito `{}`",
                path.display()
            )
        })?,
        _ => unreachable!("format normalized"),
    };
    manifest
        .validate()
        .wrap_err("adversarial corpus manifest validation failed")?;
    norito::to_bytes(&manifest).wrap_err("failed to encode canonical adversarial corpus manifest")
}
fn read_moderation_registry_manifest_file(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).wrap_err_with(|| {
        format!(
            "failed to read moderation registry manifest `{}`",
            path.display()
        )
    })?;
    if bytes.is_empty() {
        return Err(eyre!(
            "moderation registry manifest `{}` must not be empty",
            path.display()
        ));
    }
    Ok(bytes)
}
fn normalize_moderation_registry_manifest_format(format: &str) -> Result<&'static str> {
    match format.trim().to_ascii_lowercase().as_str() {
        "json" => Ok("json"),
        "norito" => Ok("norito"),
        other => Err(eyre!(
            "--format must be `json` or `norito` for moderation registry manifests, got `{other}`"
        )),
    }
}
fn load_moderation_screening_submit_payload(
    path: &Path,
) -> Result<ModerationScreeningSubmitPayload> {
    const MAX_AUTHENTICATED_SCREENING_JSON_BYTES: u64 = 8 * 1024 * 1024;
    let metadata = fs::symlink_metadata(path).wrap_err_with(|| {
        format!(
            "failed to inspect moderation screening authority JSON `{}`",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(eyre!(
            "moderation screening authority JSON `{}` must be a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_AUTHENTICATED_SCREENING_JSON_BYTES {
        return Err(eyre!(
            "moderation screening authority JSON `{}` must contain 1..={} bytes",
            path.display(),
            MAX_AUTHENTICATED_SCREENING_JSON_BYTES
        ));
    }
    let bytes = fs::read(path).wrap_err_with(|| {
        format!(
            "failed to read moderation screening authority JSON `{}`",
            path.display()
        )
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len() {
        return Err(eyre!(
            "moderation screening authority JSON `{}` changed while it was read",
            path.display()
        ));
    }
    let value: Value = norito::json::from_slice(&bytes).wrap_err_with(|| {
        format!(
            "failed to parse moderation screening authority JSON `{}`",
            path.display()
        )
    })?;
    moderation_screening_submit_payload_from_json(&value)
}
fn moderation_screening_submit_payload_from_json(
    value: &Value,
) -> Result<ModerationScreeningSubmitPayload> {
    let Value::Object(fields) = value else {
        return Err(eyre!("--input must contain a JSON object"));
    };
    let idempotency_key_hex = required_json_hex_digest::<32>(fields, "idempotency_key_hex")?;
    if idempotency_key_hex.bytes().all(|byte| byte == b'0') {
        return Err(eyre!("idempotency_key_hex must not be all zeroes"));
    }
    let evidence_kind = required_json_text(fields, "evidence_kind")?;
    if !matches!(
        evidence_kind.as_str(),
        "signed_result" | "committee_aggregate"
    ) {
        return Err(eyre!(
            "evidence_kind must be `signed_result` or `committee_aggregate`"
        ));
    }
    let authority_b64 = required_json_text(fields, "authority_b64")?;
    let committee_member_results_b64 =
        required_json_string_array(fields, "committee_member_results_b64")?;
    match evidence_kind.as_str() {
        "signed_result" if !committee_member_results_b64.is_empty() => {
            return Err(eyre!(
                "signed_result must not include committee_member_results_b64"
            ));
        }
        "committee_aggregate"
            if committee_member_results_b64.is_empty()
                || committee_member_results_b64.len() > 64 =>
        {
            return Err(eyre!(
                "committee_member_results_b64 must contain 1..=64 signed results"
            ));
        }
        _ => {}
    }
    Ok(ModerationScreeningSubmitPayload {
        idempotency_key_hex,
        evidence_kind,
        authority_b64,
        committee_member_results_b64,
    })
}
fn required_json_string_array(fields: &Map, field: &str) -> Result<Vec<String>> {
    let Some(Value::Array(values)) = fields.get(field) else {
        return if fields.contains_key(field) {
            Err(eyre!("{field} must be a JSON string array"))
        } else {
            Err(eyre!("{field} is required"))
        };
    };
    values
        .iter()
        .enumerate()
        .map(|(index, value)| match value {
            Value::String(value) if !value.is_empty() && value.trim() == value => Ok(value.clone()),
            Value::String(_) => Err(eyre!("{field}[{index}] must be non-empty and unpadded")),
            _ => Err(eyre!("{field}[{index}] must be a JSON string")),
        })
        .collect()
}
fn required_json_text(fields: &Map, field: &str) -> Result<String> {
    match fields.get(field) {
        Some(Value::String(value)) => required_trimmed_text(value, field),
        Some(_) => Err(eyre!("{field} must be a JSON string")),
        None => Err(eyre!("{field} is required")),
    }
}
fn optional_json_text(fields: &Map, field: &str) -> Result<Option<String>> {
    match fields.get(field) {
        Some(Value::String(value)) => optional_trimmed_text(Some(value), field),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(eyre!("{field} must be a JSON string or null")),
    }
}
fn required_json_hex_digest<const N: usize>(fields: &Map, field: &str) -> Result<String> {
    let value = required_json_text(fields, field)?;
    normalize_hex_digest::<N>(&value, field)
}
fn optional_json_u64(fields: &Map, field: &str) -> Result<Option<u64>> {
    match fields.get(field) {
        Some(Value::Null) | None => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| eyre!("{field} must be an unsigned integer or null")),
    }
}
fn parse_repair_ticket_id(value: &str, flag: &str) -> Result<RepairTicketId> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(eyre!("{flag} must not be empty"));
    }
    let ticket_id = RepairTicketId(trimmed.to_string());
    ticket_id
        .validate()
        .map_err(|err| eyre!("{flag} is invalid: {err}"))?;
    Ok(ticket_id)
}
fn validate_repair_revision(value: u64, flag: &str) -> Result<()> {
    if value == 0 {
        return Err(eyre!("{flag} must be non-zero"));
    }
    Ok(())
}
fn build_repair_action_transaction(
    client: &Client,
    ticket_id: &RepairTicketId,
    expected_revision: u64,
    action: SorafsRepairTaskActionV1,
) -> Result<SignedTransaction> {
    let instruction =
        ApplySorafsRepairTaskAction::new(ticket_id.0.clone(), expected_revision, action);
    {
        let account = client.account_client()?;
        account
            .prepare_transaction(AccountTransactionDraft::new(
                [instruction],
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .wrap_err("failed to build caller-signed native SoraFS repair transaction")
}
fn render_repair_transaction_hash<C: RunContext>(
    context: &mut C,
    hash: &HashOf<SignedTransaction>,
) -> Result<()> {
    context.print_data(&norito::json!({
        "transaction_hash_hex": (encode(hash.as_ref()))
    }))
}
fn parse_quantity_str(value: &str, flag: &str) -> Result<Quantity> {
    Quantity::from_str(value)
        .map_err(|err| eyre!("{flag} must be a valid non-negative quantity: {err}"))
}
fn unix_now() -> u64 {
    let seconds = OffsetDateTime::now_utc().unix_timestamp();
    u64::try_from(seconds.max(0)).unwrap_or(0)
}
#[derive(clap::Subcommand, Debug)]
pub enum HandshakeCommand {
    /// Display the current `SoraNet` handshake summary as reported by Torii.
    Show,
    /// Admission token helpers (issuance, fingerprinting, revocation digests).
    #[command(subcommand)]
    Token(HandshakeTokenCommand),
}
impl Run for HandshakeCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            HandshakeCommand::Show => {
                let operator_key_pair = context.operator_key_pair().cloned().ok_or_else(|| {
                    eyre!("handshake configuration read requires --operator-private-key-file")
                })?;
                let operator = iroha::blocking::OperatorClient::from_client(
                    context
                        .client_from_config()?
                        .operator_client(operator_key_pair)?,
                )?;
                let config = operator
                    .configuration()
                    .get()
                    .wrap_err("failed to fetch configuration")?;
                render_handshake_summary(context, &config.network.soranet_handshake)?;
                context.println(format_args!(
                    "require_sm_handshake_match: {}",
                    config.network.require_sm_handshake_match
                ))?;
                context.println(format_args!(
                    "require_sm_openssl_preview_match: {}",
                    config.network.require_sm_openssl_preview_match
                ))?;
                Ok(())
            }
            HandshakeCommand::Token(cmd) => cmd.run(context),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum HandshakeTokenCommand {
    /// Issue an ML-DSA admission token bound to a relay and transcript hash.
    Issue(HandshakeTokenIssueArgs),
    /// Compute the canonical revocation identifier for an admission token.
    Id(HandshakeTokenIdArgs),
    /// Compute the issuer fingerprint from an ML-DSA public key.
    Fingerprint(HandshakeTokenFingerprintArgs),
}
impl_run_for_subcommand!(HandshakeTokenCommand => Issue, Id, Fingerprint);
// Four-byte magic, fixed v1 body, u16 signature length, and the largest
// signature the frame can structurally advertise.
const HANDSHAKE_TOKEN_FILE_MAX_BYTES_V1: usize = 65_671;
const HANDSHAKE_MLDSA_PUBLIC_KEY_MAX_BYTES_V1: usize = 2_592;
#[derive(clap::Args, Debug)]
pub struct HandshakeTokenIssueArgs {
    /// ML-DSA suite used to sign the token (mldsa44, mldsa65, mldsa87).
    #[arg(long = "suite", value_enum, default_value_t = MlDsaSuiteArg::default())]
    suite: MlDsaSuiteArg,
    /// Path to the issuer ML-DSA secret key (raw bytes).
    ///
    /// The file must be owner-private, single-link, and opened without following
    /// symbolic links. Secret key bytes are never accepted directly on argv.
    #[arg(long = "issuer-secret-key", value_name = "PATH")]
    issuer_secret_key: PathBuf,
    /// Path to the issuer ML-DSA public key (raw bytes).
    #[arg(
        long = "issuer-public-key",
        value_name = "PATH",
        conflicts_with = "issuer_public_hex"
    )]
    issuer_public_key: Option<PathBuf>,
    /// Hex-encoded issuer ML-DSA public key.
    #[arg(
        long = "issuer-public-hex",
        value_name = "HEX",
        conflicts_with = "issuer_public_key"
    )]
    issuer_public_hex: Option<String>,
    /// Hex-encoded 32-byte relay identifier bound into the token.
    #[arg(long = "relay-id", value_name = "HEX")]
    relay_id: String,
    /// Hex-encoded 32-byte transcript hash bound into the token.
    #[arg(long = "transcript-hash", value_name = "HEX")]
    transcript_hash: String,
    /// RFC3339 issuance timestamp (defaults to current UTC time).
    #[arg(long = "issued-at", value_name = "RFC3339")]
    issued_at: Option<String>,
    /// RFC3339 expiry timestamp.
    #[arg(
        long = "expires-at",
        value_name = "RFC3339",
        conflicts_with = "ttl_secs"
    )]
    expires_at: Option<String>,
    /// Token lifetime in seconds (defaults to 600s when --expires-at is omitted).
    #[arg(long = "ttl", value_name = "SECONDS", conflicts_with = "expires_at")]
    ttl_secs: Option<u64>,
    /// Token flags (reserved; must be 0 for v1 tokens).
    #[arg(long = "flags", value_parser = clap::value_parser!(u8))]
    flags: Option<u8>,
    /// New path to write the encoded token as an owner-private file.
    ///
    /// Existing paths are never overwritten, and the bearer token is not
    /// printed to standard output.
    #[arg(long = "output", value_name = "PATH")]
    output: PathBuf,
    /// Encoding used when writing the token to --output (base64, hex, binary).
    #[arg(long = "token-encoding", value_enum, default_value_t = TokenOutputFormat::Base64)]
    token_encoding: TokenOutputFormat,
}
struct TokenIssueArtifacts {
    token: AdmissionToken,
    token_bytes: Vec<u8>,
    suite: MlDsaSuiteArg,
    issued_dt: OffsetDateTime,
    expires_dt: OffsetDateTime,
    ttl_secs: u64,
    issuer_fingerprint: [u8; 32],
    relay_id: [u8; 32],
    transcript_hash: [u8; 32],
}
impl TokenIssueArtifacts {
    fn zeroize_encoded_token(&mut self) {
        self.token_bytes.zeroize();
    }
}
impl Drop for TokenIssueArtifacts {
    fn drop(&mut self) {
        self.zeroize_encoded_token();
    }
}
impl HandshakeTokenIssueArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let mut rng = token_issue_rng()?;
        let now = SystemTime::now();
        let artifacts = self.issue_with_rng(context, &mut rng, now)?;
        Self::emit(context, &artifacts, &self.output, self.token_encoding)?;
        Ok(())
    }
    fn issue_with_rng<C, R>(
        &self,
        context: &mut C,
        rng: &mut R,
        default_now: SystemTime,
    ) -> Result<TokenIssueArtifacts>
    where
        C: RunContext,
        R: RngCore + CryptoRng,
    {
        let suite = self.suite;
        let secret_key = read_owner_private_handshake_file(
            &self.issuer_secret_key,
            suite.as_suite().secret_key_len(),
            Some(suite.as_suite().secret_key_len()),
            "--issuer-secret-key",
        )?;
        let public_key = materialise_key_bytes(
            self.issuer_public_key.as_ref(),
            self.issuer_public_hex.as_deref(),
            "--issuer-public-key",
            "--issuer-public-hex",
            suite.as_suite().public_key_len(),
            Some(suite.as_suite().public_key_len()),
        )?;
        let relay_id = parse_hex_array::<32>(&self.relay_id, "--relay-id")?;
        let transcript_hash = parse_hex_array::<32>(&self.transcript_hash, "--transcript-hash")?;
        let issued_dt = match parse_timestamp(self.issued_at.as_deref(), "--issued-at")? {
            Some(explicit) => require_whole_second_token_timestamp(explicit, "--issued-at")?,
            None => canonical_default_token_timestamp(default_now)?,
        };
        let issued_secs = issued_dt.unix_timestamp();
        let expires_dt =
            if let Some(explicit) = parse_timestamp(self.expires_at.as_deref(), "--expires-at")? {
                require_whole_second_token_timestamp(explicit, "--expires-at")?
            } else {
                let ttl = self.ttl_secs.unwrap_or(600);
                if ttl == 0 {
                    return Err(eyre!("--ttl must be greater than zero"));
                }
                issued_dt
                    .checked_add(TimeDelta::seconds(
                        i64::try_from(ttl)
                            .map_err(|_| eyre!("--ttl must fit into a signed 64-bit value"))?,
                    ))
                    .ok_or_else(|| eyre!("computed expiry timestamp overflowed"))?
            };
        let expires_secs = expires_dt.unix_timestamp();
        if expires_secs <= issued_secs {
            return Err(eyre!("token expiry must be greater than the issuance time"));
        }
        let ttl_secs = u64::try_from(expires_secs - issued_secs).map_err(|_| {
            eyre!("token lifetime overflowed when computing expires_at - issued_at")
        })?;
        let issuer_fingerprint = compute_issuer_fingerprint(&public_key);
        let issued_at_instant =
            UNIX_EPOCH
                + Duration::from_secs(u64::try_from(issued_secs).map_err(|_| {
                    eyre!("--issued-at must not be earlier than 1970-01-01T00:00:00Z")
                })?);
        let expires_at_instant = UNIX_EPOCH
            + Duration::from_secs(u64::try_from(expires_secs).map_err(|_| {
                eyre!("--expires-at must not be earlier than 1970-01-01T00:00:00Z")
            })?);
        let flags = self.flags.unwrap_or(0);
        let token = AdmissionToken::mint(
            suite.as_suite(),
            &secret_key,
            issuer_fingerprint,
            relay_id,
            transcript_hash,
            issued_at_instant,
            expires_at_instant,
            flags,
            rng,
        )
        .map_err(|err| map_mint_error(&err, context))?;
        let token_bytes = token.encode();
        Ok(TokenIssueArtifacts {
            token,
            token_bytes,
            suite,
            issued_dt,
            expires_dt,
            ttl_secs,
            issuer_fingerprint,
            relay_id,
            transcript_hash,
        })
    }
    fn emit<C: RunContext>(
        context: &mut C,
        artifacts: &TokenIssueArtifacts,
        output: &Path,
        format: TokenOutputFormat,
    ) -> Result<()> {
        write_token_to_file(output, format, &artifacts.token_bytes)?;
        let token_id = artifacts.token.token_id();
        let token_id_hex = hex::encode(token_id);
        let token_id_b64 = URL_SAFE_NO_PAD.encode(token_id);
        let fingerprint_hex = hex::encode(artifacts.issuer_fingerprint);
        let fingerprint_b64 = URL_SAFE_NO_PAD.encode(artifacts.issuer_fingerprint);
        let relay_id_hex = hex::encode(artifacts.relay_id);
        let transcript_hash_hex = hex::encode(artifacts.transcript_hash);
        let issued_str = artifacts
            .issued_dt
            .format(&Rfc3339)
            .map_err(|err| eyre!("failed to format issued_at: {err}"))?;
        let expires_str = artifacts
            .expires_dt
            .format(&Rfc3339)
            .map_err(|err| eyre!("failed to format expires_at: {err}"))?;
        let mut obj = Map::new();
        obj.insert("suite".into(), Value::from(artifacts.suite.to_string()));
        obj.insert(
            "token_length".into(),
            Value::from(artifacts.token_bytes.len() as u64),
        );
        obj.insert("token_id_hex".into(), Value::from(token_id_hex));
        obj.insert("token_id_base64url".into(), Value::from(token_id_b64));
        obj.insert(
            "issuer_fingerprint_hex".into(),
            Value::from(fingerprint_hex),
        );
        obj.insert(
            "issuer_fingerprint_base64url".into(),
            Value::from(fingerprint_b64),
        );
        obj.insert("relay_id_hex".into(), Value::from(relay_id_hex));
        obj.insert(
            "transcript_hash_hex".into(),
            Value::from(transcript_hash_hex),
        );
        obj.insert(
            "flags".into(),
            Value::from(u64::from(artifacts.token.flags())),
        );
        obj.insert("issued_at".into(), Value::from(issued_str));
        obj.insert("expires_at".into(), Value::from(expires_str));
        obj.insert("ttl_secs".into(), Value::from(artifacts.ttl_secs));
        obj.insert("token_encoding".into(), Value::from(format.describe()));
        obj.insert(
            "output_path".into(),
            Value::from(output.to_string_lossy().into_owned()),
        );
        let text = render_token_issue_text(artifacts, &obj, output, format.describe());
        print_with_optional_text(context, Some(text), &Value::Object(obj))
    }
}
fn require_whole_second_token_timestamp(
    timestamp: OffsetDateTime,
    field: &str,
) -> Result<OffsetDateTime> {
    if timestamp.nanosecond() != 0 {
        return Err(eyre!(
            "{field} must use whole-second precision because admission-token v1 stores seconds"
        ));
    }
    Ok(timestamp)
}
fn canonical_default_token_timestamp(now: SystemTime) -> Result<OffsetDateTime> {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| eyre!("current time is earlier than the Unix epoch"))?
        .as_secs();
    let seconds = i64::try_from(seconds)
        .map_err(|_| eyre!("current time cannot be represented as an RFC3339 timestamp"))?;
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|error| {
        eyre!("current time cannot be represented as an RFC3339 timestamp: {error}")
    })
}
fn token_issue_rng() -> Result<StdRng> {
    token_issue_rng_from_rng(&mut OsRng)
}
fn token_issue_rng_from_rng<R: TryCryptoRng>(rng: &mut R) -> Result<StdRng> {
    StdRng::try_from_rng(rng).map_err(|error| {
        eyre!("failed to seed SoraNet admission-token RNG from OS entropy: {error}")
    })
}
fn render_token_issue_text(
    artifacts: &TokenIssueArtifacts,
    payload: &Map,
    output: &Path,
    encoding_label: &str,
) -> String {
    let token_id_hex = payload
        .get("token_id_hex")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let fingerprint_hex = payload
        .get("issuer_fingerprint_hex")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let relay_id_hex = payload
        .get("relay_id_hex")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let transcript_hash_hex = payload
        .get("transcript_hash_hex")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let issued_at = payload
        .get("issued_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expires_at = payload
        .get("expires_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ttl_secs = payload
        .get("ttl_secs")
        .and_then(Value::as_u64)
        .unwrap_or(artifacts.ttl_secs);
    let mut out = String::new();
    let _ = writeln!(out, "SoraNet admission token issued");
    let _ = writeln!(out, "suite: {}", artifacts.suite);
    let _ = writeln!(out, "token_id_hex: {token_id_hex}");
    let _ = writeln!(out, "issuer_fingerprint_hex: {fingerprint_hex}");
    let _ = writeln!(out, "relay_id_hex: {relay_id_hex}");
    let _ = writeln!(out, "transcript_hash_hex: {transcript_hash_hex}");
    let _ = writeln!(out, "issued_at: {issued_at}");
    let _ = writeln!(out, "expires_at: {expires_at}");
    let _ = writeln!(out, "ttl_secs: {ttl_secs}");
    let _ = writeln!(out, "output: {} ({encoding_label})", output.display());
    out
}
#[derive(clap::Args, Debug)]
pub struct HandshakeTokenIdArgs {
    /// Path to the admission token frame (binary).
    ///
    /// The bearer token must be supplied through an owner-private, single-link
    /// file and is never accepted directly on argv.
    #[arg(long = "token", value_name = "PATH")]
    path: PathBuf,
}
impl HandshakeTokenIdArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let bytes = read_owner_private_handshake_file(
            &self.path,
            HANDSHAKE_TOKEN_FILE_MAX_BYTES_V1,
            None,
            "--token",
        )?;
        let token =
            AdmissionToken::decode(&bytes).map_err(|err| eyre!("failed to decode token: {err}"))?;
        let token_id = token.token_id();
        let token_id_hex = hex::encode(token_id);
        let token_id_b64 = URL_SAFE_NO_PAD.encode(token_id);
        let fingerprint_hex = hex::encode(token.issuer_fingerprint());
        let fingerprint_b64 = URL_SAFE_NO_PAD.encode(token.issuer_fingerprint());
        let issued_dt = OffsetDateTime::from_unix_timestamp(
            i64::try_from(token.issued_at()).map_err(|_| eyre!("issued_at does not fit in i64"))?,
        )
        .map_err(|err| eyre!("invalid issued_at timestamp: {err}"))?;
        let expires_dt = OffsetDateTime::from_unix_timestamp(
            i64::try_from(token.expires_at())
                .map_err(|_| eyre!("expires_at does not fit in i64"))?,
        )
        .map_err(|err| eyre!("invalid expires_at timestamp: {err}"))?;
        let issued_str = issued_dt
            .format(&Rfc3339)
            .map_err(|err| eyre!("failed to format issued_at: {err}"))?;
        let expires_str = expires_dt
            .format(&Rfc3339)
            .map_err(|err| eyre!("failed to format expires_at: {err}"))?;
        let ttl_secs = token.expires_at().saturating_sub(token.issued_at());
        let mut obj = Map::new();
        obj.insert("token_id_hex".into(), Value::from(token_id_hex));
        obj.insert("token_id_base64url".into(), Value::from(token_id_b64));
        obj.insert(
            "issuer_fingerprint_hex".into(),
            Value::from(fingerprint_hex),
        );
        obj.insert(
            "issuer_fingerprint_base64url".into(),
            Value::from(fingerprint_b64),
        );
        obj.insert("flags".into(), Value::from(u64::from(token.flags())));
        obj.insert("issued_at".into(), Value::from(issued_str));
        obj.insert("expires_at".into(), Value::from(expires_str));
        obj.insert("ttl_secs".into(), Value::from(ttl_secs));
        context.print_data(&Value::Object(obj))
    }
}
#[derive(clap::Args, Debug)]
pub struct HandshakeTokenFingerprintArgs {
    /// Path to the ML-DSA public key (raw bytes).
    #[arg(
        long = "public-key",
        value_name = "PATH",
        conflicts_with = "public_key_hex"
    )]
    public_key: Option<PathBuf>,
    /// Hex-encoded ML-DSA public key.
    #[arg(
        long = "public-key-hex",
        value_name = "HEX",
        conflicts_with = "public_key"
    )]
    public_key_hex: Option<String>,
}
impl HandshakeTokenFingerprintArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let public_key = materialise_key_bytes(
            self.public_key.as_ref(),
            self.public_key_hex.as_deref(),
            "--public-key",
            "--public-key-hex",
            HANDSHAKE_MLDSA_PUBLIC_KEY_MAX_BYTES_V1,
            None,
        )?;
        let fingerprint = compute_issuer_fingerprint(&public_key);
        let fingerprint_hex = hex::encode(fingerprint);
        let fingerprint_b64 = URL_SAFE_NO_PAD.encode(fingerprint);
        let mut obj = Map::new();
        obj.insert(
            "public_key_len".into(),
            Value::from(public_key.len() as u64),
        );
        obj.insert(
            "issuer_fingerprint_hex".into(),
            Value::from(fingerprint_hex),
        );
        obj.insert(
            "issuer_fingerprint_base64url".into(),
            Value::from(fingerprint_b64),
        );
        context.print_data(&Value::Object(obj))
    }
}
fn map_mint_error<C: RunContext>(err: &AdmissionTokenMintError, _context: &C) -> eyre::Report {
    eyre!("failed to mint admission token: {err}")
}
fn materialise_key_bytes(
    path: Option<&PathBuf>,
    hex: Option<&str>,
    path_flag: &str,
    hex_flag: &str,
    maximum_bytes: usize,
    exact_bytes: Option<usize>,
) -> Result<Vec<u8>> {
    match (path, hex) {
        (Some(path), None) => {
            read_bounded_direct_handshake_public_file(path, maximum_bytes, exact_bytes, path_flag)
        }
        (None, Some(hex)) => {
            let bytes = decode_hex_string(hex, hex_flag)?;
            validate_handshake_file_length(
                bytes.len(),
                maximum_bytes,
                exact_bytes,
                hex_flag,
                None,
            )?;
            Ok(bytes)
        }
        (Some(_), Some(_)) => Err(eyre!(
            "exactly one of {path_flag} or {hex_flag} must be provided"
        )),
        (None, None) => Err(eyre!("either {path_flag} or {hex_flag} must be provided")),
    }
}
fn validate_handshake_file_length(
    len: usize,
    maximum_bytes: usize,
    exact_bytes: Option<usize>,
    label: &str,
    path: Option<&Path>,
) -> Result<()> {
    let location = path.map_or_else(String::new, |path| format!(" {}", path.display()));
    if len == 0 {
        return Err(eyre!(
            "{label}{location} must contain between 1 and {maximum_bytes} bytes"
        ));
    }
    if let Some(expected) = exact_bytes
        && len != expected
    {
        return Err(eyre!(
            "{label}{location} must contain exactly {expected} bytes, got {len}"
        ));
    }
    if len > maximum_bytes {
        return Err(eyre!(
            "{label}{location} must contain between 1 and {maximum_bytes} bytes"
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn read_bounded_direct_handshake_public_file(
    path: &Path,
    maximum_bytes: usize,
    exact_bytes: Option<usize>,
    label: &str,
) -> Result<Vec<u8>> {
    let named_before = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("failed to inspect {label} {}", path.display()))?;
    if named_before.file_type().is_symlink() || !named_before.is_file() {
        return Err(eyre!(
            "{label} {} must be a regular non-symlink file",
            path.display()
        ));
    }
    let named_len = usize::try_from(named_before.len())
        .map_err(|_| eyre!("{label} length cannot be represented on this host"))?;
    validate_handshake_file_length(named_len, maximum_bytes, exact_bytes, label, Some(path))?;
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .wrap_err_with(|| format!("failed to securely open {label} {}", path.display()))?;
    let mut file = fs::File::from(descriptor);
    let opened = file
        .metadata()
        .wrap_err_with(|| format!("failed to inspect opened {label} {}", path.display()))?;
    if !opened.is_file() || !same_direct_handshake_file(&named_before, &opened) {
        return Err(eyre!(
            "{label} {} changed between inspection and open",
            path.display()
        ));
    }
    let expected_len = usize::try_from(opened.len())
        .map_err(|_| eyre!("{label} length cannot be represented on this host"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_len)
        .map_err(|error| eyre!("failed to reserve {label} buffer: {error}"))?;
    bytes.resize(expected_len, 0);
    file.read_exact(&mut bytes)
        .wrap_err_with(|| format!("failed to read {label} {}", path.display()))?;
    let mut extra = [0u8; 1];
    let grew = file
        .read(&mut extra)
        .wrap_err_with(|| format!("failed to finish reading {label} {}", path.display()))?
        != 0;
    let opened_after = file
        .metadata()
        .wrap_err_with(|| format!("failed to re-inspect opened {label} {}", path.display()))?;
    let named_after = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("failed to re-inspect {label} {}", path.display()))?;
    if grew
        || !same_direct_handshake_file(&opened, &opened_after)
        || !same_direct_handshake_file(&opened, &named_after)
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(eyre!(
            "{label} {} changed while it was read",
            path.display()
        ));
    }
    Ok(bytes)
}
#[cfg(not(unix))]
fn read_bounded_direct_handshake_public_file(
    path: &Path,
    _maximum_bytes: usize,
    _exact_bytes: Option<usize>,
    label: &str,
) -> Result<Vec<u8>> {
    Err(eyre!(
        "{label} {} is unsupported because this platform does not expose a direct no-follow file open",
        path.display()
    ))
}
#[cfg(unix)]
fn same_direct_handshake_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(unix)]
fn read_owner_private_handshake_file(
    path: &Path,
    maximum_bytes: usize,
    exact_bytes: Option<usize>,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let named_before = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("failed to inspect {label} {}", path.display()))?;
    validate_owner_private_handshake_metadata(
        &named_before,
        maximum_bytes,
        exact_bytes,
        label,
        path,
    )?;
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .wrap_err_with(|| format!("failed to securely open {label} {}", path.display()))?;
    let mut file = fs::File::from(descriptor);
    let opened = file
        .metadata()
        .wrap_err_with(|| format!("failed to inspect opened {label} {}", path.display()))?;
    validate_owner_private_handshake_metadata(&opened, maximum_bytes, exact_bytes, label, path)?;
    if !same_owner_private_handshake_file(&named_before, &opened) {
        return Err(eyre!(
            "{label} {} changed between inspection and open",
            path.display()
        ));
    }
    let expected_len = usize::try_from(opened.len())
        .map_err(|_| eyre!("{label} length cannot be represented on this host"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(expected_len)
        .map_err(|error| eyre!("failed to reserve {label} buffer: {error}"))?;
    bytes.resize(expected_len, 0);
    file.read_exact(bytes.as_mut_slice())
        .wrap_err_with(|| format!("failed to read {label} {}", path.display()))?;
    let mut extra = [0u8; 1];
    let grew = file
        .read(&mut extra)
        .wrap_err_with(|| format!("failed to finish reading {label} {}", path.display()))?
        != 0;
    extra.zeroize();
    let opened_after = file
        .metadata()
        .wrap_err_with(|| format!("failed to re-inspect opened {label} {}", path.display()))?;
    let named_after = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("failed to re-inspect {label} {}", path.display()))?;
    if grew
        || !same_owner_private_handshake_file(&opened, &opened_after)
        || !same_owner_private_handshake_file(&opened, &named_after)
        || opened_after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(eyre!(
            "{label} {} changed while it was read",
            path.display()
        ));
    }
    Ok(bytes)
}
#[cfg(unix)]
fn validate_owner_private_handshake_metadata(
    metadata: &fs::Metadata,
    maximum_bytes: usize,
    exact_bytes: Option<usize>,
    label: &str,
    path: &Path,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(eyre!(
            "{label} {} must be an owner-private regular non-symlink file with exactly one link",
            path.display()
        ));
    }
    let len = usize::try_from(metadata.len())
        .map_err(|_| eyre!("{label} length cannot be represented on this host"))?;
    validate_handshake_file_length(len, maximum_bytes, exact_bytes, label, Some(path))
}
#[cfg(unix)]
fn same_owner_private_handshake_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    same_direct_handshake_file(left, right) && left.nlink() == 1 && right.nlink() == 1
}
#[cfg(not(unix))]
fn read_owner_private_handshake_file(
    path: &Path,
    _maximum_bytes: usize,
    _exact_bytes: Option<usize>,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    Err(eyre!(
        "{label} {} is unsupported because this platform does not expose the required owner/mode/link custody checks",
        path.display()
    ))
}
fn write_token_to_file(path: &Path, format: TokenOutputFormat, bytes: &[u8]) -> Result<()> {
    let mut file = create_owner_private_token_output(path)?;
    match format {
        TokenOutputFormat::Base64 => {
            let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
            file.write_all(encoded.as_bytes())?;
            file.write_all(b"\n")?;
        }
        TokenOutputFormat::Hex => {
            let encoded = Zeroizing::new(hex::encode(bytes));
            file.write_all(encoded.as_bytes())?;
            file.write_all(b"\n")?;
        }
        TokenOutputFormat::Binary => {
            file.write_all(bytes)?;
        }
    }
    file.flush()
        .wrap_err_with(|| format!("failed to flush token output {}", path.display()))?;
    file.sync_all()
        .wrap_err_with(|| format!("failed to sync token output {}", path.display()))?;
    Ok(())
}
#[cfg(unix)]
fn create_owner_private_token_output(path: &Path) -> Result<fs::File> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .wrap_err_with(|| {
        format!(
            "failed to create new owner-private token output {}",
            path.display()
        )
    })?;
    let file = fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .wrap_err_with(|| format!("failed to inspect token output {}", path.display()))?;
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(eyre!(
            "token output {} is not an owner-private single-link regular file",
            path.display()
        ));
    }
    Ok(file)
}
#[cfg(not(unix))]
fn create_owner_private_token_output(path: &Path) -> Result<fs::File> {
    Err(eyre!(
        "token output {} is unsupported because this platform does not expose the required owner/mode/link custody checks",
        path.display()
    ))
}
fn decode_hex_string(value: &str, flag: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(eyre!("{flag} must not be empty"));
    }
    if !trimmed.len().is_multiple_of(2) {
        return Err(eyre!(
            "{flag} must contain an even number of hex characters"
        ));
    }
    hex::decode(trimmed).map_err(|err| eyre!("failed to decode {flag}: {err}"))
}
fn parse_hex_array<const N: usize>(value: &str, flag: &str) -> Result<[u8; N]> {
    let trimmed = value.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if without_prefix.len() != N * 2 {
        return Err(eyre!(
            "{flag} must contain exactly {} hex characters",
            N * 2
        ));
    }
    let mut bytes = [0u8; N];
    decode_to_slice(without_prefix, &mut bytes)
        .map_err(|err| eyre!("failed to decode {flag}: {err}"))?;
    Ok(bytes)
}
fn normalize_hex_digest<const N: usize>(value: &str, flag: &str) -> Result<String> {
    let bytes = parse_hex_array::<N>(value, flag)?;
    Ok(encode(bytes))
}
fn parse_alias_label(raw: &str) -> Result<String> {
    let (namespace_raw, name_raw) = raw
        .split_once(':')
        .ok_or_else(|| eyre!("alias `{raw}` must use the `namespace:name` form"))?;
    let namespace = Name::from_str(namespace_raw.trim())
        .map_err(|err| eyre!("invalid alias namespace `{namespace_raw}`: {err}"))?;
    let name = Name::from_str(name_raw.trim())
        .map_err(|err| eyre!("invalid alias name `{name_raw}`: {err}"))?;
    Ok(format!("{namespace}:{name}"))
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
struct RouteBindingContext {
    manifest_json: PathBuf,
    alias: Option<String>,
    hostname: String,
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
fn build_route_binding(context: &RouteBindingContext) -> Result<RouteBindingOutput> {
    let manifest_bytes = fs::read(&context.manifest_json).wrap_err_with(|| {
        format!(
            "failed to read manifest JSON from `{}`",
            context.manifest_json.display()
        )
    })?;
    let manifest: Value = norito::json::from_slice(&manifest_bytes).wrap_err_with(|| {
        format!(
            "failed to parse manifest JSON from `{}`",
            context.manifest_json.display()
        )
    })?;
    let root_bytes = manifest_root_bytes(&manifest)?;
    if root_bytes.is_empty() {
        return Err(eyre!("manifest root CID payload was empty"));
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
        let proof_bytes = norito::json::to_vec(&proof_payload)
            .map_err(|err| eyre!("failed to encode proof payload: {err}"))?;
        headers.insert("Sora-Proof".into(), STANDARD.encode(proof_bytes));
        let status = context
            .proof_status
            .clone()
            .unwrap_or_else(|| "ok".to_string());
        headers.insert("Sora-Proof-Status".into(), status);
    }
    let generated_at = context
        .generated_at
        .format(&Rfc3339)
        .map_err(|err| eyre!("failed to format timestamp: {err}"))?;
    let mut binding_parts = vec![
        format!("host={}", context.hostname),
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
            format!("max-age={DEFAULT_ROUTE_HSTS_MAX_AGE}; includeSubDomains; preload"),
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
fn manifest_root_bytes(manifest: &Value) -> Result<Vec<u8>> {
    if let Some(array) = manifest.get("root_cid").and_then(Value::as_array) {
        let mut bytes = Vec::with_capacity(array.len());
        for value in array {
            let number = value.as_i64().ok_or_else(|| {
                eyre!("root_cid entries must be integers, found {value:?} instead")
            })?;
            if !(0..=255).contains(&number) {
                return Err(eyre!(
                    "root_cid entries must be between 0 and 255 inclusive (found {number})"
                ));
            }
            bytes.push(u8::try_from(number).expect("checked root_cid bounds"));
        }
        return Ok(bytes);
    }
    if let Some(array) = manifest.get("root_cids_hex").and_then(Value::as_array) {
        for value in array {
            if let Some(hex_str) = value.as_str()
                && let Ok(decoded) = decode(hex_str.trim())
                && !decoded.is_empty()
            {
                return Ok(decoded);
            }
        }
    }
    if let Some(hex_value) = manifest.get("root_cid_hex").and_then(Value::as_str) {
        return decode(hex_value.trim())
            .map_err(|err| eyre!("failed to decode root_cid_hex value: {err}"));
    }
    Err(eyre!(
        "manifest JSON is missing `root_cid`, `root_cids_hex`, or `root_cid_hex` fields"
    ))
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
fn headers_to_value(headers: &BTreeMap<String, String>) -> Map {
    let mut map = Map::new();
    for (key, value) in headers {
        map.insert(key.clone(), Value::from(value.clone()));
    }
    map
}
fn write_optional_output(path: Option<&PathBuf>, contents: &str) -> Result<()> {
    if let Some(path) = path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).wrap_err_with(|| {
                format!("failed to create parent directory for `{}`", path.display())
            })?;
        }
        fs::write(path, contents)
            .wrap_err_with(|| format!("failed to write `{}`", path.display()))?;
    }
    Ok(())
}
fn build_cache_invalidation_payload(
    aliases: &[String],
    manifest_digest: &str,
    car_digest: Option<&str>,
    release_tag: Option<&str>,
) -> Value {
    let mut map = Map::new();
    map.insert(
        "aliases".into(),
        Value::Array(aliases.iter().cloned().map(Value::from).collect()),
    );
    map.insert(
        "manifest_digest_hex".into(),
        Value::from(manifest_digest.to_owned()),
    );
    map.insert(
        "car_digest_hex".into(),
        car_digest.map_or(Value::Null, |hex| Value::from(hex.to_owned())),
    );
    map.insert(
        "release_tag".into(),
        release_tag.map_or(Value::Null, |tag| Value::from(tag.to_owned())),
    );
    Value::Object(map)
}
fn render_cache_invalidation_curl(endpoint: &str, auth_env: &str, payload_json: &str) -> String {
    let mut lines = Vec::new();
    lines.push(format!("curl -X POST {endpoint}"));
    lines.push("  -H 'Content-Type: application/json'".to_string());
    if !auth_env.trim().is_empty() {
        lines.push(format!("  -H \"Authorization: Bearer ${auth_env}\""));
    }
    let escaped = shell_escape_single_quotes(payload_json);
    lines.push(format!("  --data '{escaped}'"));
    lines.join(" \\\n")
}
fn shell_escape_single_quotes(input: &str) -> String {
    if input.contains('\'') {
        input.replace('\'', "'\"'\"'")
    } else {
        input.to_owned()
    }
}
fn render_handshake_summary<C: RunContext>(
    context: &mut C,
    summary: &SoranetHandshakeSummary,
) -> Result<()> {
    context.println(format_args!(
        "descriptor_commit_hex: {}",
        summary.descriptor_commit_hex
    ))?;
    context.println(format_args!(
        "client_capabilities_hex: {}",
        summary.client_capabilities_hex
    ))?;
    context.println(format_args!(
        "relay_capabilities_hex: {}",
        summary.relay_capabilities_hex
    ))?;
    context.println(format_args!("kem_id: {}", summary.kem_id))?;
    context.println(format_args!("sig_id: {}", summary.sig_id))?;
    context.println(format_args!(
        "resume_hash_hex: {}",
        summary
            .resume_hash_hex
            .as_deref()
            .unwrap_or("<not configured>")
    ))?;
    context.println(format_args!("pow.difficulty: {}", summary.pow.difficulty))?;
    context.println(format_args!(
        "pow.max_future_skew_secs: {}",
        summary.pow.max_future_skew_secs
    ))?;
    context.println(format_args!(
        "pow.min_ticket_ttl_secs: {}",
        summary.pow.min_ticket_ttl_secs
    ))?;
    context.println(format_args!(
        "pow.ticket_ttl_secs: {}",
        summary.pow.ticket_ttl_secs
    ))?;
    let puzzle = summary.pow.puzzle;
    context.println(format_args!("pow.puzzle.memory_kib: {}", puzzle.memory_kib))?;
    context.println(format_args!("pow.puzzle.time_cost: {}", puzzle.time_cost))?;
    context.println(format_args!("pow.puzzle.lanes: {}", puzzle.lanes))?;
    Ok(())
}
#[derive(clap::Subcommand, Debug)]
pub enum GatewayCommand {
    /// Emit a TOML snippet with gateway configuration defaults.
    TemplateConfig(GatewayTemplateConfigArgs),
    /// Derive canonical/vanity hostnames for a provider.
    GenerateHosts(GatewayGenerateHostsArgs),
    /// Render the headers + route binding plan for a manifest rollout.
    RoutePlan(GatewayRoutePlanArgs),
    /// Generate a cache invalidation payload and curl snippet for GAR/SoraFS gateways.
    CacheInvalidate(GatewayCacheInvalidateArgs),
    /// Direct-mode planning and configuration helpers.
    #[command(subcommand)]
    DirectMode(GatewayDirectModeCommand),
}
impl_run_for_subcommand!(GatewayCommand => TemplateConfig, GenerateHosts, RoutePlan, CacheInvalidate, DirectMode);
#[derive(clap::Subcommand, Debug)]
pub enum GuardDirectoryCommand {
    /// Fetch a guard directory snapshot over HTTPS, verify it, and emit a summary.
    Fetch(GuardDirectoryFetchArgs),
    /// Authenticate a guard directory snapshot stored on disk.
    Verify(GuardDirectoryVerifyArgs),
    /// Inspect snapshot structure without claiming authenticity or freshness.
    Inspect(GuardDirectoryInspectArgs),
}
impl_run_for_subcommand!(GuardDirectoryCommand => Fetch, Verify, Inspect);
#[derive(clap::Args, Debug)]
pub struct GuardDirectoryFetchArgs {
    /// URLs publishing the guard directory snapshot (first success wins).
    #[arg(long = "url", value_name = "URL", required = true)]
    pub url: Vec<String>,
    /// Path where the verified snapshot will be stored (optional).
    #[arg(long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Trusted domain-separated BLAKE3 digest of the exact snapshot bytes.
    #[arg(long = "expected-snapshot-digest", value_name = "HEX")]
    pub expected_snapshot_digest: String,
    /// HTTP timeout in seconds (defaults to 30s).
    #[arg(long = "timeout-secs", value_name = "SECS", default_value = "30")]
    pub timeout_secs: u64,
    /// Allow overwriting an existing file at --output.
    #[arg(long = "overwrite")]
    pub overwrite: bool,
}
impl Run for GuardDirectoryFetchArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if self.url.is_empty() {
            return Err(eyre!(
                "at least one --url must be supplied when fetching guard directory snapshots"
            ));
        }
        let timeout = Duration::from_secs(self.timeout_secs.max(1));
        let client = BlockingHttpClient::builder()
            .timeout(timeout)
            .user_agent("sorafs-cli guard-directory")
            .build()
            .wrap_err("failed to construct HTTP client")?;
        let mut errors = Vec::new();
        let mut snapshot: Option<Vec<u8>> = None;
        for url in &self.url {
            match client.get(url).send() {
                Ok(response) => match response.error_for_status() {
                    Ok(mut success) => {
                        let content_length = success.content_length();
                        match read_guard_directory_http_body_bounded(&mut success, content_length) {
                            Ok(bytes) => {
                                snapshot = Some(bytes);
                                break;
                            }
                            Err(err) => {
                                errors.push(format!("{url}: failed to read body: {err}"));
                            }
                        }
                    }
                    Err(err) => {
                        errors.push(format!("{url}: HTTP error {err}"));
                    }
                },
                Err(err) => {
                    errors.push(format!("{url}: {err}"));
                }
            }
        }
        let bytes = snapshot.ok_or_else(|| {
            eyre!(
                "failed to fetch guard directory from {} url(s): {}",
                self.url.len(),
                errors.join("; ")
            )
        })?;
        let now_unix = OffsetDateTime::now_utc().unix_timestamp();
        let summary =
            authenticate_guard_directory_bytes(&bytes, &self.expected_snapshot_digest, now_unix)?;
        if let Some(path) = &self.output {
            write_guard_directory_snapshot(path, &bytes, self.overwrite)?;
        }
        context.print_data(&summary)
    }
}
fn read_guard_directory_http_body_bounded<R: Read>(
    reader: R,
    content_length: Option<u64>,
) -> io::Result<Vec<u8>> {
    read_guard_directory_http_body_with_limit(
        reader,
        content_length,
        iroha_crypto::soranet::directory::GUARD_DIRECTORY_SNAPSHOT_MAX_BYTES_V1,
    )
}
fn read_guard_directory_http_body_with_limit<R: Read>(
    mut reader: R,
    content_length: Option<u64>,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let max_bytes_u64 = u64::try_from(max_bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "guard directory HTTP body limit cannot be represented as u64",
        )
    })?;
    if content_length.is_some_and(|length| length > max_bytes_u64) {
        return Err(guard_directory_http_body_too_large(max_bytes));
    }
    let capacity = content_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .by_ref()
        .take(max_bytes_u64.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(guard_directory_http_body_too_large(max_bytes));
    }
    Ok(bytes)
}
fn guard_directory_http_body_too_large(max_bytes: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("guard directory HTTP body exceeds the {max_bytes}-byte first-release limit"),
    )
}
#[derive(clap::Args, Debug)]
pub struct GuardDirectoryVerifyArgs {
    /// Path to the guard directory snapshot to verify.
    #[arg(long = "path", value_name = "PATH")]
    pub path: PathBuf,
    /// Trusted domain-separated BLAKE3 digest of the exact snapshot bytes.
    #[arg(long = "expected-snapshot-digest", value_name = "HEX")]
    pub expected_snapshot_digest: String,
}
impl Run for GuardDirectoryVerifyArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let bytes = read_guard_directory_snapshot_file(&self.path).wrap_err_with(|| {
            format!(
                "failed to read guard directory snapshot from `{}`",
                self.path.display()
            )
        })?;
        let now_unix = OffsetDateTime::now_utc().unix_timestamp();
        let summary =
            authenticate_guard_directory_bytes(&bytes, &self.expected_snapshot_digest, now_unix)?;
        context.print_data(&summary)
    }
}
#[derive(clap::Args, Debug)]
pub struct GuardDirectoryInspectArgs {
    /// Path to the guard directory snapshot to inspect.
    #[arg(long = "path", value_name = "PATH")]
    pub path: PathBuf,
}
impl Run for GuardDirectoryInspectArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let bytes = read_guard_directory_snapshot_file(&self.path).wrap_err_with(|| {
            format!(
                "failed to read guard directory snapshot from `{}`",
                self.path.display()
            )
        })?;
        let summary = inspect_guard_directory_bytes(&bytes)?;
        context.print_data(&summary)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum GatewayDirectModeCommand {
    /// Analyse manifest/admission data and emit a direct-mode readiness plan.
    Plan(GatewayDirectModePlanArgs),
    /// Emit a configuration snippet enabling direct-mode overrides from a plan.
    Enable(GatewayDirectModeEnableArgs),
    /// Emit a configuration snippet restoring default gateway security settings.
    Rollback(GatewayDirectModeRollbackArgs),
}
impl_run_for_subcommand!(GatewayDirectModeCommand => Plan, Enable, Rollback);
#[derive(clap::Args, Debug)]
pub struct GatewayDirectModePlanArgs {
    /// Path to the Norito-encoded manifest (`.to`) file to analyse.
    #[arg(long, value_name = "PATH")]
    pub manifest: PathBuf,
    /// Optional provider admission envelope (`.to`) for capability detection.
    #[arg(long = "admission-envelope", value_name = "PATH")]
    pub admission_envelope: Option<PathBuf>,
    /// Override provider identifier (hex) when no admission envelope is supplied.
    #[arg(long = "provider-id", value_name = "HEX")]
    pub provider_id: Option<String>,
    /// Override chain id (defaults to the CLI configuration chain id).
    #[arg(long = "chain-id")]
    pub chain_id: Option<String>,
    /// URL scheme to use for generated direct-CAR endpoints (default: https).
    #[arg(long, default_value = "https")]
    pub scheme: String,
}
impl Run for GatewayDirectModePlanArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let manifest_bytes = fs::read(&self.manifest).wrap_err_with(|| {
            format!("failed to read manifest from `{}`", self.manifest.display())
        })?;
        let manifest: ManifestV1 =
            norito::decode_from_bytes(&manifest_bytes).wrap_err("failed to decode manifest")?;
        let manifest_digest = manifest
            .digest()
            .wrap_err("failed to compute manifest digest")?;
        let manifest_digest_hex = hex::encode(manifest_digest.as_bytes());
        let envelope = if let Some(path) = &self.admission_envelope {
            let bytes = fs::read(path).wrap_err_with(|| {
                format!(
                    "failed to read admission envelope from `{}`",
                    path.display()
                )
            })?;
            let decoded: ProviderAdmissionEnvelopeV1 = norito::decode_from_bytes(&bytes)
                .wrap_err("failed to decode admission envelope")?;
            decoded
                .validate()
                .wrap_err("admission envelope validation failed")?;
            Some(decoded)
        } else {
            None
        };
        let provider_id = if let Some(hex) = self.provider_id {
            parse_hex_array::<32>(&hex, "provider_id")?
        } else if let Some(env) = envelope.as_ref() {
            env.advert_body.provider_id
        } else {
            return Err(eyre!(
                "provider identifier required; pass --provider-id or --admission-envelope"
            ));
        };
        let chain_id = self
            .chain_id
            .unwrap_or_else(|| context.config().chain.as_str().to_owned());
        let host_input = HostMappingInput {
            chain_id: chain_id.as_str(),
            provider_id: &provider_id,
        };
        let host_summary = host_input.to_summary();
        let direct_car = host_input
            .direct_car_locator(&self.scheme, &manifest_digest_hex)
            .wrap_err("invalid URL scheme for direct CAR locator")?;
        let capability_summary = detect_manifest_capabilities(
            Some(&manifest),
            envelope.as_ref().map(|env| &env.advert_body),
        );
        let plan = DirectModePlanOutput::from_components(
            &chain_id,
            provider_id,
            manifest_digest_hex,
            host_summary,
            direct_car,
            capability_summary,
        );
        context.print_data(&plan)
    }
}
#[derive(clap::Args, Debug)]
pub struct GatewayDirectModeEnableArgs {
    /// Path to the JSON output produced by `sorafs gateway direct-mode plan`.
    #[arg(long, value_name = "PATH")]
    pub plan: PathBuf,
}
impl Run for GatewayDirectModeEnableArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let bytes = fs::read(&self.plan)
            .wrap_err_with(|| format!("failed to read plan from `{}`", self.plan.display()))?;
        let plan: DirectModePlanOutput =
            norito::json::from_slice(&bytes).wrap_err("failed to parse plan JSON")?;
        validate_direct_mode_enable_plan(&plan)?;
        context.println(render_direct_mode_enable_snippet(&plan))
    }
}
#[derive(clap::Args, Debug)]
pub struct GatewayDirectModeRollbackArgs;
impl Run for GatewayDirectModeRollbackArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        context.println(render_direct_mode_rollback_snippet())
    }
}
#[derive(Debug, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
struct DirectModePlanOutput {
    provider_id_hex: String,
    chain_id: String,
    manifest_digest_hex: String,
    hosts: DirectModePlanHosts,
    direct_car: DirectModePlanDirectCar,
    capabilities: DirectModePlanCapabilities,
}
impl DirectModePlanOutput {
    fn from_components(
        chain_id: &str,
        provider_id: [u8; 32],
        manifest_digest_hex: String,
        hosts: HostMappingSummary,
        direct_car: DirectCarLocator,
        capabilities: ManifestCapabilitySummary,
    ) -> Self {
        Self {
            provider_id_hex: hex::encode(provider_id),
            chain_id: chain_id.to_owned(),
            manifest_digest_hex,
            hosts: DirectModePlanHosts {
                canonical: hosts.canonical,
                vanity: hosts.vanity,
            },
            direct_car: DirectModePlanDirectCar {
                canonical_url: direct_car.canonical_url,
                vanity_url: direct_car.vanity_url,
            },
            capabilities: DirectModePlanCapabilities::from_summary(capabilities),
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
struct DirectModePlanHosts {
    canonical: String,
    vanity: String,
}
#[derive(Debug, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
struct DirectModePlanDirectCar {
    canonical_url: String,
    vanity_url: String,
}
#[derive(Debug, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
#[allow(clippy::struct_excessive_bools)]
struct DirectModePlanCapabilities {
    requires_manifest_envelope: bool,
    direct_car_supported: bool,
    supports_torii_gateway: bool,
    supports_quic_noise: bool,
    supports_soranet: bool,
    supports_soranet_hybrid_pq: bool,
    supports_chunk_range_fetch: bool,
    advertised_capabilities: Vec<String>,
    range_capability: Option<DirectModePlanRangeCapability>,
    chunk_profile: Option<DirectModePlanChunkProfile>,
    manifest_metadata: Vec<DirectModePlanMetadataEntry>,
}
impl DirectModePlanCapabilities {
    fn from_summary(summary: ManifestCapabilitySummary) -> Self {
        let ManifestCapabilitySummary {
            chunk_profile,
            metadata_pairs,
            requires_manifest_envelope,
            direct_car_supported,
            supports_torii_gateway,
            supports_quic_noise,
            supports_soranet,
            supports_soranet_hybrid_pq,
            supports_chunk_range_fetch,
            range_capability,
            advertised_capabilities,
        } = summary;
        Self {
            requires_manifest_envelope,
            direct_car_supported,
            supports_torii_gateway,
            supports_quic_noise,
            supports_soranet,
            supports_soranet_hybrid_pq,
            supports_chunk_range_fetch,
            advertised_capabilities: advertised_capabilities
                .into_iter()
                .map(capability_type_label)
                .map(str::to_owned)
                .collect(),
            range_capability: range_capability.map(DirectModePlanRangeCapability::from),
            chunk_profile: chunk_profile.map(DirectModePlanChunkProfile::from),
            manifest_metadata: metadata_pairs
                .into_iter()
                .map(|(key, value)| DirectModePlanMetadataEntry { key, value })
                .collect(),
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
struct DirectModePlanChunkProfile {
    profile_id: u32,
    namespace: String,
    name: String,
    semver: String,
    min_size: u32,
    target_size: u32,
    max_size: u32,
    aliases: Vec<String>,
    multihash_code: u64,
}
impl From<ChunkProfileSummary> for DirectModePlanChunkProfile {
    fn from(summary: ChunkProfileSummary) -> Self {
        Self {
            profile_id: summary.profile_id,
            namespace: summary.namespace,
            name: summary.name,
            semver: summary.semver,
            min_size: summary.min_size,
            target_size: summary.target_size,
            max_size: summary.max_size,
            aliases: summary.aliases,
            multihash_code: summary.multihash_code,
        }
    }
}
#[derive(Debug, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
struct DirectModePlanMetadataEntry {
    key: String,
    value: String,
}
#[derive(Debug, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
struct DirectModePlanRangeCapability {
    max_chunk_span: u32,
    min_granularity: u32,
    supports_sparse_offsets: bool,
    requires_alignment: bool,
    supports_merkle_proof: bool,
}
impl From<ProviderCapabilityRangeV1> for DirectModePlanRangeCapability {
    fn from(range: ProviderCapabilityRangeV1) -> Self {
        Self {
            max_chunk_span: range.max_chunk_span,
            min_granularity: range.min_granularity,
            supports_sparse_offsets: range.supports_sparse_offsets,
            requires_alignment: range.requires_alignment,
            supports_merkle_proof: range.supports_merkle_proof,
        }
    }
}
fn capability_type_label(cap: CapabilityType) -> &'static str {
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
fn validate_direct_mode_enable_plan(plan: &DirectModePlanOutput) -> Result<()> {
    let provider_id = parse_hex_array::<32>(&plan.provider_id_hex, "provider_id_hex")?;
    let canonical_provider_id_hex = encode(provider_id);
    if plan.provider_id_hex != canonical_provider_id_hex {
        return Err(eyre!(
            "provider_id_hex must be canonical lowercase hex; expected {canonical_provider_id_hex}"
        ));
    }
    let manifest_digest = parse_hex_array::<32>(&plan.manifest_digest_hex, "manifest_digest_hex")?;
    let canonical_manifest_digest_hex = encode(manifest_digest);
    if plan.manifest_digest_hex != canonical_manifest_digest_hex {
        return Err(eyre!(
            "manifest_digest_hex must be canonical lowercase hex; expected {canonical_manifest_digest_hex}"
        ));
    }
    if plan.chain_id.trim().is_empty() {
        return Err(eyre!("chain_id must not be empty"));
    }
    if !plan.capabilities.requires_manifest_envelope {
        return Err(eyre!(
            "direct-mode enable requires capabilities.requires_manifest_envelope=true; regenerate the manifest with envelope enforcement metadata"
        ));
    }
    if !plan.capabilities.direct_car_supported {
        return Err(eyre!(
            "direct-mode enable requires capabilities.direct_car_supported=true; advertise capability.direct_car=true before emitting config"
        ));
    }
    let host_input = HostMappingInput {
        chain_id: plan.chain_id.as_str(),
        provider_id: &provider_id,
    };
    let expected_hosts = host_input.to_summary();
    if plan.hosts.canonical != expected_hosts.canonical {
        return Err(eyre!(
            "direct-mode plan canonical host mismatch: expected `{}`, got `{}`",
            expected_hosts.canonical,
            plan.hosts.canonical
        ));
    }
    if plan.hosts.vanity != expected_hosts.vanity {
        return Err(eyre!(
            "direct-mode plan vanity host mismatch: expected `{}`, got `{}`",
            expected_hosts.vanity,
            plan.hosts.vanity
        ));
    }
    let expected_direct_car = host_input
        .direct_car_locator("https", &canonical_manifest_digest_hex)
        .wrap_err("failed to derive expected direct-CAR locators")?;
    validate_direct_mode_url(
        &plan.direct_car.canonical_url,
        "direct_car.canonical_url",
        &expected_direct_car.canonical_url,
    )?;
    validate_direct_mode_url(
        &plan.direct_car.vanity_url,
        "direct_car.vanity_url",
        &expected_direct_car.vanity_url,
    )
}
fn validate_direct_mode_url(value: &str, label: &str, expected: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(value)
        .wrap_err_with(|| format!("{label} must be a valid direct-CAR URL"))?;
    if parsed.scheme() != "https" {
        return Err(eyre!("{label} must use https"));
    }
    if parsed.host_str().is_none() {
        return Err(eyre!("{label} must include a host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(eyre!("{label} must not include userinfo"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(eyre!(
            "{label} must not include query or fragment components"
        ));
    }
    if value != expected {
        return Err(eyre!(
            "{label} mismatch: expected `{expected}`, got `{value}`"
        ));
    }
    Ok(())
}
fn escape_toml_basic_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => {
                write!(&mut escaped, "\\u{:04X}", ch as u32)
                    .expect("writing to a String cannot fail");
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}
fn render_direct_mode_enable_snippet(plan: &DirectModePlanOutput) -> String {
    let provider = escape_toml_basic_string(&plan.provider_id_hex);
    let chain = escape_toml_basic_string(&plan.chain_id);
    let canonical = escape_toml_basic_string(&plan.hosts.canonical);
    let vanity = escape_toml_basic_string(&plan.hosts.vanity);
    let direct_canonical = escape_toml_basic_string(&plan.direct_car.canonical_url);
    let direct_vanity = escape_toml_basic_string(&plan.direct_car.vanity_url);
    let digest = escape_toml_basic_string(&plan.manifest_digest_hex);
    format!(
        r#"# Direct-mode configuration snippet (generated; enforcement remains enabled)
[sorafs.gateway]
require_manifest_envelope = true
enforce_admission = true
enforce_capabilities = true

[sorafs.gateway.direct_mode]
provider_id_hex = "{provider}"
chain_id = "{chain}"
canonical_host = "{canonical}"
vanity_host = "{vanity}"
direct_car_canonical = "{direct_canonical}"
direct_car_vanity = "{direct_vanity}"
manifest_digest_hex = "{digest}"
"#,
    )
}
fn render_direct_mode_rollback_snippet() -> &'static str {
    r"# Direct-mode rollback snippet
[sorafs.gateway]
require_manifest_envelope = true
enforce_admission = true
enforce_capabilities = true

# Remove the `sorafs.gateway.direct_mode` table to disable overrides.
"
}
#[derive(clap::Args, Debug)]
pub struct GatewayTemplateConfigArgs {
    /// Hostname to include in the ACME / gateway sample (repeatable).
    #[arg(long = "host", value_name = "HOSTNAME")]
    pub hosts: Vec<String>,
}
#[derive(clap::Args, Debug)]
pub struct GatewayGenerateHostsArgs {
    /// Provider identifier (hex, 32 bytes).
    #[arg(long = "provider-id", value_name = "HEX")]
    pub provider_id: String,
    /// Chain id (network identifier).
    #[arg(long = "chain-id", default_value = "nexus")]
    pub chain_id: String,
}
impl Run for GatewayTemplateConfigArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let hosts = if self.hosts.is_empty() {
            vec!["gateway.example.com".to_owned()]
        } else {
            self.hosts
        };
        let host_list = hosts
            .iter()
            .map(|h| format!("\"{h}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let template = format!(
            r#"# Paste this snippet into your configuration (e.g. config.toml)
[sorafs.gateway]
require_manifest_envelope = true
enforce_admission = true

[sorafs.gateway.rate_limit]
max_requests = 120
window = {{ secs = 60, nanos = 0 }}
ban = {{ secs = 30, nanos = 0 }}

[sorafs.gateway.acme]
enabled = true
account_email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
hostnames = [{hosts}]
dns_provider_id = "cloudflare-prod"
renewal_window = {{ secs = 2592000, nanos = 0 }}
retry_backoff = {{ secs = 1800, nanos = 0 }}
retry_jitter = {{ secs = 300, nanos = 0 }}

[sorafs.gateway.acme.challenges]
dns01 = true
tls_alpn_01 = true
"#,
            hosts = host_list,
        );
        context.println(template)
    }
}
impl Run for GatewayGenerateHostsArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let chain_id = self
            .chain_id
            .parse::<ChainId>()
            .wrap_err("--chain-id must be canonical")?;
        let provider = parse_hex_array::<32>(&self.provider_id, "provider_id")?;
        let summary = HostMappingInput {
            chain_id: chain_id.as_str(),
            provider_id: &provider,
        }
        .to_summary();
        let mut map = norito::json::Map::new();
        map.insert(
            "canonical".to_owned(),
            norito::json::Value::from(summary.canonical),
        );
        map.insert(
            "vanity".to_owned(),
            norito::json::Value::from(summary.vanity),
        );
        context.print_data(&norito::json::Value::Object(map))
    }
}
#[derive(clap::Args, Debug)]
pub struct GatewayRoutePlanArgs {
    /// Manifest JSON path for the route being promoted.
    #[arg(long = "manifest-json", value_name = "PATH")]
    pub manifest_json: PathBuf,
    /// Hostname that serves the manifest after promotion.
    #[arg(long = "hostname", value_name = "HOSTNAME")]
    pub hostname: String,
    /// Optional alias binding (`namespace:name`) to embed in the headers.
    #[arg(long = "alias", value_name = "NAMESPACE:NAME")]
    pub alias: Option<String>,
    /// Optional logical label applied to the rendered `Sora-Route-Binding`.
    #[arg(long = "route-label", value_name = "LABEL")]
    pub route_label: Option<String>,
    /// Optional proof-status string for the generated `Sora-Proof-Status`.
    #[arg(long = "proof-status", value_name = "STATUS")]
    pub proof_status: Option<String>,
    /// Optional release tag stored alongside the plan.
    #[arg(long = "release-tag", value_name = "STRING")]
    pub release_tag: Option<String>,
    /// Optional cutover window (RFC3339 interval or freeform note).
    #[arg(long = "cutover-window", value_name = "WINDOW")]
    pub cutover_window: Option<String>,
    /// Path where the JSON plan will be written.
    #[arg(
        long = "out",
        value_name = "PATH",
        default_value = "artifacts/sorafs_gateway/route_plan.json"
    )]
    pub output_path: PathBuf,
    /// Optional path storing the primary header block.
    #[arg(long = "headers-out", value_name = "PATH")]
    pub headers_out: Option<PathBuf>,
    /// Optional rollback manifest path (renders a secondary header block).
    #[arg(long = "rollback-manifest-json", value_name = "PATH")]
    pub rollback_manifest_json: Option<PathBuf>,
    /// Optional path for the rollback header block.
    #[arg(long = "rollback-headers-out", value_name = "PATH")]
    pub rollback_headers_out: Option<PathBuf>,
    /// Optional label applied to the rollback binding.
    #[arg(long = "rollback-route-label", value_name = "LABEL")]
    pub rollback_route_label: Option<String>,
    /// Optional release tag for the rollback binding metadata.
    #[arg(long = "rollback-release-tag", value_name = "STRING")]
    pub rollback_release_tag: Option<String>,
    /// Skip emitting the default Content-Security-Policy header.
    #[arg(long = "no-csp")]
    pub no_csp: bool,
    /// Skip emitting the default Permissions-Policy header.
    #[arg(long = "no-permissions-policy")]
    pub no_permissions_policy: bool,
    /// Skip emitting the default `Strict-Transport-Security` header.
    #[arg(long = "no-hsts")]
    pub no_hsts: bool,
    /// Override the timestamp embedded in the binding (RFC3339, test hook).
    #[arg(long = "now", value_name = "RFC3339", hide = true)]
    pub now_override: Option<String>,
}
fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}
#[allow(clippy::too_many_lines)]
impl Run for GatewayRoutePlanArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let alias = match self.alias {
            Some(alias) => Some(parse_alias_label(&alias)?),
            None => None,
        };
        let now = parse_timestamp(self.now_override.as_deref(), "--now")?
            .unwrap_or_else(OffsetDateTime::now_utc);
        let generated_at = now
            .format(&Rfc3339)
            .map_err(|err| eyre!("failed to format timestamp: {err}"))?;
        let headers_out = self.headers_out.or_else(|| {
            self.output_path
                .parent()
                .map(|parent| parent.join("gateway.route.headers.txt"))
        });
        let rollback_headers_out = self.rollback_headers_out.or_else(|| {
            self.output_path
                .parent()
                .map(|parent| parent.join("gateway.route.rollback.headers.txt"))
        });
        let include_csp = !self.no_csp;
        let include_permissions = !self.no_permissions_policy;
        let include_hsts = !self.no_hsts;
        let primary_context = RouteBindingContext {
            manifest_json: self.manifest_json.clone(),
            alias: alias.clone(),
            hostname: self.hostname.clone(),
            route_label: self.route_label.clone(),
            proof_status: self.proof_status.clone(),
            include_csp,
            include_permissions,
            include_hsts,
            generated_at: now,
        };
        let primary_binding = build_route_binding(&primary_context)?;
        write_optional_output(headers_out.as_ref(), &primary_binding.headers_template)?;
        let rollback_value = if let Some(rollback_manifest) = self.rollback_manifest_json.as_ref() {
            let rollback_context = RouteBindingContext {
                manifest_json: rollback_manifest.clone(),
                alias: alias.clone(),
                hostname: self.hostname.clone(),
                route_label: self.rollback_route_label.clone(),
                proof_status: self.proof_status.clone(),
                include_csp,
                include_permissions,
                include_hsts,
                generated_at: now,
            };
            let binding = build_route_binding(&rollback_context)?;
            write_optional_output(rollback_headers_out.as_ref(), &binding.headers_template)?;
            let mut map = Map::new();
            map.insert(
                "manifest_json".into(),
                Value::from(rollback_manifest.display().to_string()),
            );
            if let Some(tag) = &self.rollback_release_tag {
                map.insert("release_tag".into(), Value::from(tag.clone()));
            }
            map.insert("content_cid".into(), Value::from(binding.content_cid));
            map.insert("route_binding".into(), Value::from(binding.route_binding));
            map.insert(
                "headers_template".into(),
                Value::from(binding.headers_template),
            );
            if let Some(path) = rollback_headers_out.as_ref() {
                map.insert(
                    "headers_path".into(),
                    Value::from(path.display().to_string()),
                );
            }
            Some(Value::Object(map))
        } else {
            None
        };
        if let Some(parent) = self.output_path.parent() {
            fs::create_dir_all(parent).wrap_err_with(|| {
                format!(
                    "failed to create parent directory for `{}`",
                    self.output_path.display()
                )
            })?;
        }
        let mut plan = Map::new();
        plan.insert("version".into(), Value::from(1u64));
        plan.insert("generated_at".into(), Value::from(generated_at));
        plan.insert(
            "manifest_json".into(),
            Value::from(self.manifest_json.display().to_string()),
        );
        if let Some(alias) = alias.clone() {
            plan.insert("alias".into(), Value::from(alias));
        }
        plan.insert("hostname".into(), Value::from(self.hostname.clone()));
        if let Some(tag) = &self.release_tag {
            plan.insert("release_tag".into(), Value::from(tag.clone()));
        }
        if let Some(window) = &self.cutover_window {
            plan.insert("cutover_window".into(), Value::from(window.clone()));
        }
        plan.insert(
            "content_cid".into(),
            Value::from(primary_binding.content_cid.clone()),
        );
        plan.insert(
            "route_binding".into(),
            Value::from(primary_binding.route_binding.clone()),
        );
        plan.insert(
            "headers_template".into(),
            Value::from(primary_binding.headers_template.clone()),
        );
        if let Some(path) = headers_out.as_ref() {
            plan.insert(
                "headers_path".into(),
                Value::from(path.display().to_string()),
            );
        }
        plan.insert(
            "headers".into(),
            Value::Object(headers_to_value(&primary_binding.headers)),
        );
        if let Some(rollback) = rollback_value {
            plan.insert("rollback".into(), rollback);
        }
        let mut payload = norito::json::to_vec_pretty(&Value::Object(plan))?;
        payload.push(b'\n');
        fs::write(&self.output_path, &payload).wrap_err_with(|| {
            format!(
                "failed to write route plan `{}`",
                self.output_path.display()
            )
        })?;
        context.println(format_args!("wrote {}", self.output_path.display()))?;
        if let Some(path) = headers_out.as_ref() {
            context.println(format_args!("headers written to {}", path.display()))?;
        }
        if self.rollback_manifest_json.is_some()
            && let Some(path) = rollback_headers_out.as_ref()
        {
            context.println(format_args!(
                "rollback headers written to {}",
                path.display()
            ))?;
        }
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct GatewayCacheInvalidateArgs {
    /// Cache invalidation API endpoint (HTTP/S).
    #[arg(long = "endpoint", value_name = "URL")]
    pub endpoint: String,
    /// Alias bindings (`namespace:name`) that should be purged (repeatable).
    #[arg(long = "alias", value_name = "NAMESPACE:NAME", required = true)]
    pub aliases: Vec<String>,
    /// Manifest digest (hex, 32 bytes) associated with the release.
    #[arg(long = "manifest-digest", value_name = "HEX")]
    pub manifest_digest_hex: String,
    /// Optional CAR digest (hex, 32 bytes) to attach to the request.
    #[arg(long = "car-digest", value_name = "HEX")]
    pub car_digest_hex: Option<String>,
    /// Optional release tag metadata included in the payload.
    #[arg(long = "release-tag", value_name = "STRING")]
    pub release_tag: Option<String>,
    /// Environment variable that stores the cache purge bearer token.
    #[arg(
        long = "auth-env",
        value_name = "ENV",
        default_value = "CACHE_PURGE_TOKEN"
    )]
    pub auth_env: String,
    /// Optional path where the JSON payload will be written.
    #[arg(long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,
}
impl Run for GatewayCacheInvalidateArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            return Err(eyre!("--endpoint must point to a cache invalidation API"));
        }
        let alias_literals = self
            .aliases
            .iter()
            .map(|alias| parse_alias_label(alias))
            .collect::<Result<Vec<_>>>()?;
        let manifest_digest =
            normalize_hex_digest::<32>(&self.manifest_digest_hex, "--manifest-digest")?;
        let car_digest = if let Some(hex) = &self.car_digest_hex {
            Some(normalize_hex_digest::<32>(hex, "--car-digest")?)
        } else {
            None
        };
        let payload_value = build_cache_invalidation_payload(
            &alias_literals,
            &manifest_digest,
            car_digest.as_deref(),
            self.release_tag.as_deref(),
        );
        let payload_bytes = norito::json::to_vec_pretty(&payload_value)?;
        let payload_str = String::from_utf8(payload_bytes).map_err(|err| eyre!(err.to_string()))?;
        if let Some(path) = &self.output {
            fs::write(path, payload_str.as_bytes())
                .wrap_err_with(|| format!("failed to write payload to `{}`", path.display()))?;
            context.println(format_args!(
                "wrote cache invalidation payload to {}",
                path.display()
            ))?;
        } else {
            context.println(&payload_str)?;
        }
        let compact_bytes = norito::json::to_vec(&payload_value)?;
        let compact_str = String::from_utf8(compact_bytes).map_err(|err| eyre!(err.to_string()))?;
        let curl = render_cache_invalidation_curl(&self.endpoint, &self.auth_env, &compact_str);
        context.println(curl)?;
        Ok(())
    }
}
#[cfg(test)]
mod gateway_tests {
    use super::tests::{TestContext, assert_sorafs_config_snippet_is_schema_valid};
    use super::*;
    #[test]
    fn template_config_uses_host_override() {
        let args = GatewayTemplateConfigArgs {
            hosts: vec![
                "gateway-a.example.com".to_owned(),
                "gateway-b.example.com".to_owned(),
            ],
        };
        let mut ctx = TestContext::new();
        args.run(&mut ctx).expect("template command runs");
        let rendered = ctx.outputs().join("\n");
        let config = assert_sorafs_config_snippet_is_schema_valid(&rendered);
        assert_eq!(config.gateway.rate_limit.window, Duration::from_secs(60));
        assert_eq!(config.gateway.rate_limit.ban, Some(Duration::from_secs(30)));
        assert_eq_compact! { config.gateway.acme.renewal_window => Duration::from_secs(30 * 24 * 60 * 60) };
        assert_eq_compact! { config.gateway.acme.retry_backoff => Duration::from_secs(30 * 60) };
        assert_eq_compact! { config.gateway.acme.retry_jitter => Duration::from_secs(5 * 60) };
        assert!(rendered.contains("[sorafs.gateway]"));
        assert!(!rendered.contains("[torii.sorafs_gateway]"));
        assert!(rendered.contains("gateway-a.example.com"));
        assert!(rendered.contains("gateway-b.example.com"));
        assert!(!rendered.contains("denylist"));
    }
    #[test]
    fn direct_mode_documentation_fixture_satisfies_config_schema() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/documentation/sorafs_gateway_direct_mode.toml"
        ));
        let config = assert_sorafs_config_snippet_is_schema_valid(fixture);
        assert_eq!(config.gateway.rate_limit.window, Duration::from_secs(60));
        assert_eq_compact! { config.gateway.rate_limit.ban => Some(Duration::from_secs(10 * 60)) };
        assert!(config.gateway.direct_mode.is_some());
    }
    #[test]
    fn generate_hosts_outputs_summary() {
        let args = GatewayGenerateHostsArgs {
            provider_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            chain_id: "nexus".to_owned(),
        };
        let mut ctx = TestContext::new();
        args.run(&mut ctx).expect("generate-hosts runs");
        assert_compact! { !ctx.outputs().is_empty(); "expected at least one daemon output entry" };
        let output = &ctx.outputs()[0];
        assert!(output.contains("canonical"));
        assert!(output.contains("vanity"));
        assert!(output.contains("aaaaaaaa.nexus.sorafs"));
        assert!(output.contains("aaaa.nexus.direct.sorafs"));
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum PinCommand {
    /// List manifests registered in the pin registry.
    List(PinListArgs),
    /// Fetch a single manifest, aliases, and replication orders.
    Show(PinShowArgs),
    /// Register a manifest in the pin registry via Torii.
    Register(PinRegisterArgs),
}
impl_run_for_subcommand!(PinCommand => List, Show, Register);
#[derive(clap::Args, Debug)]
pub struct PinListArgs {
    /// Optional closed lifecycle filter.
    #[arg(long, value_enum)]
    pub status: Option<PinStatusSelector>,
    /// Maximum number of bounded summaries to return (1 through 256).
    #[arg(long)]
    pub limit: Option<u32>,
    /// Maximum canonical encoded page bytes (1024 through 262144).
    #[arg(long)]
    pub max_bytes: Option<u32>,
    /// Exact non-zero lowercase 32-byte exclusive manifest-digest cursor.
    #[arg(long, value_name = "HEX")]
    pub after_digest_hex: Option<String>,
    /// Non-zero finalized block height anchoring this page.
    #[arg(long, requires = "expected_finalized_block_hash_hex")]
    pub expected_finalized_height: Option<u64>,
    /// Canonical lowercase finalized block hash anchoring this page.
    #[arg(long, value_name = "HEX", requires = "expected_finalized_height")]
    pub expected_finalized_block_hash_hex: Option<String>,
}
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum PinStatusSelector {
    /// Manifests awaiting governance approval.
    Pending,
    /// Approved manifests charged for replication.
    Approved,
    /// Retired manifests retained as lifecycle evidence.
    Retired,
}
impl From<PinStatusSelector> for PinStatusKindV1 {
    fn from(value: PinStatusSelector) -> Self {
        match value {
            PinStatusSelector::Pending => Self::Pending,
            PinStatusSelector::Approved => Self::Approved,
            PinStatusSelector::Retired => Self::Retired,
        }
    }
}
impl Run for PinListArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        self.run_with(context, |client, filter| {
            client.get_sorafs_pin_registry(filter)
        })
    }
}
impl PinListArgs {
    fn run_with<C, F>(&self, context: &mut C, fetch: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SorafsPinListFilter<'_>) -> Result<Response<Vec<u8>>>,
    {
        let after_digest_hex = self
            .after_digest_hex
            .as_deref()
            .map(|digest| required_nonzero_lower_hex32(digest, "--after-digest-hex"))
            .transpose()?;
        let client = context.client_from_config()?;
        let filter = SorafsPinListFilter {
            finalized: SorafsPinFinalizedAnchor {
                expected_finalized_height: self.expected_finalized_height,
                expected_finalized_block_hash_hex: self
                    .expected_finalized_block_hash_hex
                    .as_deref(),
            },
            status: self.status.map(Into::into),
            limit: self.limit,
            max_bytes: self.max_bytes,
            after_digest_hex: after_digest_hex.as_deref(),
        };
        let response = fetch(&client, &filter)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Args, Debug)]
pub struct PinShowArgs {
    /// Exact non-zero lowercase 32-byte manifest digest.
    #[arg(long, value_name = "HEX")]
    pub digest: String,
}
impl Run for PinShowArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        self.run_with(context, |client, digest| {
            client.get_sorafs_pin_manifest(digest)
        })
    }
}
impl PinShowArgs {
    fn run_with<C, F>(&self, context: &mut C, fetch: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &str) -> Result<Response<Vec<u8>>>,
    {
        let digest = required_nonzero_lower_hex32(&self.digest, "--digest")?;
        let client = context.client_from_config()?;
        let response = fetch(&client, &digest)?;
        let status = response.status();
        let body = response.into_body();
        match status {
            StatusCode::OK => render_json_body(context, &body),
            StatusCode::NOT_FOUND => context.println(format_args!("manifest `{digest}` not found")),
            status => Err(make_http_error(status, &body)),
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct PinRegisterArgs {
    /// Path to the Norito-encoded manifest (`.to`) file.
    #[arg(long, value_name = "PATH")]
    pub manifest: PathBuf,
    /// Optional alias namespace to bind alongside the manifest.
    #[arg(long)]
    pub alias_namespace: Option<String>,
    /// Optional alias name to bind alongside the manifest.
    #[arg(long)]
    pub alias_name: Option<String>,
    /// Optional path to the alias proof payload (binary).
    #[arg(long, value_name = "PATH")]
    pub alias_proof: Option<PathBuf>,
    /// Optional predecessor manifest digest (hex).
    #[arg(long, value_name = "HEX")]
    pub successor_of: Option<String>,
}
impl Run for PinRegisterArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let manifest_bytes = fs::read(&self.manifest).wrap_err_with(|| {
            format!("failed to read manifest from `{}`", self.manifest.display())
        })?;
        sorafs_manifest::decode_manifest_v1_canonical(&manifest_bytes)
            .wrap_err("failed to decode exact canonical manifest payload")?;
        let alias_inputs = self.load_alias_inputs()?;
        let successor = self
            .successor_of
            .as_ref()
            .map(|hex| parse_hex_array::<32>(hex, "successor_of"))
            .transpose()?;
        let client = iroha::blocking::Client::new(context.config().clone())
            .wrap_err("failed to initialize blocking SoraFS client")?;
        let alias_ref = alias_inputs.as_ref().map(|alias| SorafsPinAlias {
            namespace: alias.namespace.as_str(),
            name: alias.name.as_str(),
            proof: alias.proof.as_slice(),
        });
        let response = client
            .post_sorafs_pin_register(SorafsPinRegisterArgs {
                manifest_payload: &manifest_bytes,
                alias: alias_ref,
                successor_of: successor,
            })
            .wrap_err("failed to register pin manifest")?;
        context.print_data(&response)
    }
}
struct AliasInputs {
    namespace: String,
    name: String,
    proof: Vec<u8>,
}
impl PinRegisterArgs {
    fn load_alias_inputs(&self) -> Result<Option<AliasInputs>> {
        match (&self.alias_namespace, &self.alias_name, &self.alias_proof) {
            (None, None, None) => Ok(None),
            (Some(namespace), Some(name), Some(path)) => {
                let bytes = fs::read(path).wrap_err_with(|| {
                    format!("failed to read alias proof from `{}`", path.display())
                })?;
                if bytes.is_empty() {
                    return Err(eyre!("alias proof file `{}` is empty", path.display()));
                }
                Ok(Some(AliasInputs {
                    namespace: namespace.clone(),
                    name: name.clone(),
                    proof: bytes,
                }))
            }
            _ => Err(eyre!(
                "alias namespace, name, and proof must be provided together"
            )),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum AliasCommand {
    /// List alias bindings exposed via Torii.
    List(AliasListArgs),
}
impl_run_for_subcommand!(AliasCommand => List);
#[derive(clap::Args, Debug)]
pub struct AliasListArgs {
    /// Maximum number of aliases to return.
    #[arg(long)]
    pub limit: Option<u32>,
    /// Offset for pagination.
    #[arg(long)]
    pub offset: Option<u32>,
    /// Restrict aliases to an exact canonical lowercase namespace.
    #[arg(long)]
    pub namespace: Option<String>,
    /// Restrict aliases to an exact non-zero lowercase 32-byte manifest digest.
    #[arg(long, value_name = "HEX")]
    pub manifest_digest: Option<String>,
}
impl_run_with_client_methods!(AliasListArgs, Client::get_sorafs_aliases);
impl AliasListArgs {
    fn run_with<C, F>(&self, context: &mut C, fetch: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SorafsAliasListFilter<'_>) -> Result<Response<Vec<u8>>>,
    {
        let manifest_digest = self
            .manifest_digest
            .as_deref()
            .map(|digest| required_nonzero_lower_hex32(digest, "--manifest-digest"))
            .transpose()?;
        let client = context.client_from_config()?;
        let filter = SorafsAliasListFilter {
            limit: self.limit,
            offset: self.offset,
            namespace: self.namespace.as_deref(),
            manifest_digest: manifest_digest.as_deref(),
        };
        let response = fetch(&client, &filter)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ReplicationCommand {
    /// List replication orders.
    List(ReplicationListArgs),
}
impl_run_for_subcommand!(ReplicationCommand => List);
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ReplicationStatusSelector {
    /// Orders still awaiting their required provider completions.
    Pending,
    /// Orders whose required provider completions are committed.
    Completed,
    /// Orders cancelled when their target pin was retired.
    Cancelled,
    /// Incomplete orders expired after their inclusive deadline.
    Expired,
}
impl From<ReplicationStatusSelector> for SorafsReplicationStatus {
    fn from(value: ReplicationStatusSelector) -> Self {
        match value {
            ReplicationStatusSelector::Pending => Self::Pending,
            ReplicationStatusSelector::Completed => Self::Completed,
            ReplicationStatusSelector::Cancelled => Self::Cancelled,
            ReplicationStatusSelector::Expired => Self::Expired,
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct ReplicationListArgs {
    /// Maximum number of orders to return.
    #[arg(long)]
    pub limit: Option<u32>,
    /// Offset for pagination.
    #[arg(long)]
    pub offset: Option<u32>,
    /// Optional exact lifecycle filter.
    #[arg(long, value_enum)]
    pub status: Option<ReplicationStatusSelector>,
    /// Restrict orders to an exact non-zero lowercase 32-byte manifest digest.
    #[arg(long, value_name = "HEX")]
    pub manifest_digest: Option<String>,
}
impl Run for ReplicationListArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        self.run_with(context, |client, filter| {
            client.get_sorafs_replication_orders(filter)
        })
    }
}
impl ReplicationListArgs {
    fn run_with<C, F>(&self, context: &mut C, fetch: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(&Client, &SorafsReplicationListFilter<'_>) -> Result<Response<Vec<u8>>>,
    {
        let manifest_digest = self
            .manifest_digest
            .as_deref()
            .map(|digest| required_nonzero_lower_hex32(digest, "--manifest-digest"))
            .transpose()?;
        let client = context.client_from_config()?;
        let filter = SorafsReplicationListFilter {
            limit: self.limit,
            offset: self.offset,
            status: self.status.map(Into::into),
            manifest_digest: manifest_digest.as_deref(),
        };
        let response = fetch(&client, &filter)?;
        render_json_response(context, response)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum StorageCommand {
    /// Issue and inspect stream tokens for chunk-range gateways.
    #[command(subcommand)]
    Token(StorageTokenCommand),
}
impl_run_for_subcommand!(StorageCommand => Token);
#[derive(clap::Subcommand, Debug)]
pub enum StorageTokenCommand {
    /// Issue a stream token for a manifest/provider pair.
    Issue(StorageTokenIssueArgs),
}
impl_run_for_subcommand!(StorageTokenCommand => Issue);
#[derive(clap::Args, Debug)]
pub struct StorageTokenIssueArgs {
    /// Hex-encoded manifest identifier stored on the gateway.
    #[arg(long, value_name = "HEX")]
    pub manifest_id: String,
    /// Hex-encoded provider identifier authorised to serve the manifest.
    #[arg(long, value_name = "HEX")]
    pub provider_id: String,
    /// Logical client identifier used for quota accounting.
    #[arg(long, value_name = "STRING")]
    pub client_id: String,
    /// Optional nonce to send in the request headers (auto-generated when omitted).
    #[arg(long, value_name = "STRING")]
    pub nonce: Option<String>,
    /// Override the default TTL expressed in seconds.
    #[arg(long, value_name = "SECONDS")]
    pub ttl_secs: Option<u64>,
    /// Override the maximum concurrent stream count.
    #[arg(long, value_name = "COUNT")]
    pub max_streams: Option<u16>,
    /// Override the sustained throughput limit in bytes per second.
    #[arg(long, value_name = "BYTES")]
    pub rate_limit_bytes: Option<u64>,
    /// Override the allowed number of refresh requests per minute.
    #[arg(long, value_name = "COUNT")]
    pub requests_per_minute: Option<u32>,
}
impl Run for StorageTokenIssueArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        self.run_with(
            context,
            |client, manifest, provider, client_id, nonce, overrides| {
                client.post_sorafs_storage_token(manifest, provider, client_id, nonce, overrides)
            },
        )
    }
}
impl StorageTokenIssueArgs {
    fn run_with<C, F>(&self, context: &mut C, issue: F) -> Result<()>
    where
        C: RunContext,
        F: FnOnce(
            &Client,
            &str,
            &str,
            &str,
            &str,
            &SorafsTokenOverrides,
        ) -> Result<Response<Vec<u8>>>,
    {
        let nonce = match self.nonce.clone() {
            Some(nonce) => nonce,
            None => generate_nonce_hex(12)?,
        };
        let overrides = SorafsTokenOverrides {
            ttl_secs: self.ttl_secs,
            max_streams: self.max_streams,
            rate_limit_bytes: self.rate_limit_bytes,
            requests_per_minute: self.requests_per_minute,
        };
        let client = context.client_from_config()?;
        let response = issue(
            &client,
            &self.manifest_id,
            &self.provider_id,
            &self.client_id,
            &nonce,
            &overrides,
        )?;
        if self.nonce.is_none() && response.status().is_success() {
            context.println(format!("nonce: {nonce}"))?;
        }
        render_json_response(context, response)
    }
}
fn parse_timestamp(raw: Option<&str>, field: &str) -> Result<Option<OffsetDateTime>> {
    let Some(value) = raw else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(eyre!("`{field}` must not be empty when provided"));
    }
    let parsed =
        OffsetDateTime::parse(trimmed, &Rfc3339).wrap_err_with(|| format!("invalid `{field}`"))?;
    Ok(Some(parsed))
}
fn ensure_optional_non_empty(field: Option<&str>, name: &str) -> Result<()> {
    if let Some(value) = field
        && value.trim().is_empty()
    {
        return Err(eyre!("`{name}` must not be empty when provided"));
    }
    Ok(())
}
#[derive(Debug)]
struct ModerationOperatorCanaryHttpResponse {
    status: StatusCode,
    content_type: Option<String>,
    body: Vec<u8>,
}
#[derive(Clone)]
struct ModerationOperatorCanaryRouteSpec {
    name: &'static str,
    path: String,
    expected_schema: Option<&'static str>,
    expect_html_marker: Option<&'static str>,
    include_limit: bool,
}
fn moderation_operator_canary_http_get(
    client: &BlockingHttpClient,
    url: &str,
) -> Result<ModerationOperatorCanaryHttpResponse> {
    let response = client.get(url).send().wrap_err_with(|| {
        format!("failed to GET SoraFS moderation operator canary route `{url}`")
    })?;
    let status = StatusCode::from_u16(response.status().as_u16()).map_err(|err| {
        eyre!("SoraFS moderation operator canary route `{url}` returned unsupported status: {err}")
    })?;
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = response
        .bytes()
        .wrap_err_with(|| {
            format!("failed to read SoraFS moderation operator canary route `{url}` body")
        })?
        .to_vec();
    Ok(ModerationOperatorCanaryHttpResponse {
        status,
        content_type,
        body,
    })
}
#[derive(Debug)]
struct TransparencyExplorerCanaryHttpResponse {
    status: StatusCode,
    content_type: Option<String>,
    body: Vec<u8>,
}
#[derive(Clone)]
struct TransparencyExplorerCanaryRouteSpec {
    name: &'static str,
    path: &'static str,
    expected_schema: Option<&'static str>,
    expect_html_marker: Option<&'static str>,
    include_limit: bool,
}
fn transparency_explorer_canary_http_get(
    client: &BlockingHttpClient,
    url: &str,
) -> Result<TransparencyExplorerCanaryHttpResponse> {
    let response = client.get(url).send().wrap_err_with(|| {
        format!("failed to GET SoraFS transparency explorer canary route `{url}`")
    })?;
    let status = StatusCode::from_u16(response.status().as_u16()).map_err(|err| {
        eyre!(
            "SoraFS transparency explorer canary route `{url}` returned unsupported status: {err}"
        )
    })?;
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = response
        .bytes()
        .wrap_err_with(|| {
            format!("failed to read SoraFS transparency explorer canary route `{url}` body")
        })?
        .to_vec();
    Ok(TransparencyExplorerCanaryHttpResponse {
        status,
        content_type,
        body,
    })
}
fn transparency_publication_canary_http_get(
    client: &BlockingHttpClient,
    url: &str,
) -> Result<TransparencyExplorerCanaryHttpResponse> {
    let response = client.get(url).send().wrap_err_with(|| {
        format!("failed to GET SoraFS transparency publication canary route `{url}`")
    })?;
    let status = StatusCode::from_u16(response.status().as_u16()).map_err(|err| {
        eyre!(
            "SoraFS transparency publication canary route `{url}` returned unsupported status: {err}"
        )
    })?;
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = response
        .bytes()
        .wrap_err_with(|| {
            format!("failed to read SoraFS transparency publication canary route `{url}` body")
        })?
        .to_vec();
    Ok(TransparencyExplorerCanaryHttpResponse {
        status,
        content_type,
        body,
    })
}
fn transparency_explorer_canary_evidence_json<F>(
    torii_url: &str,
    limit: Option<u32>,
    fetch: &mut F,
) -> Result<Value>
where
    F: FnMut(&str) -> Result<TransparencyExplorerCanaryHttpResponse>,
{
    let route_specs = transparency_explorer_canary_route_specs();
    let mut routes = Vec::with_capacity(route_specs.len());
    for spec in &route_specs {
        routes.push(transparency_explorer_canary_probe_route(
            torii_url, spec, limit, fetch,
        )?);
    }
    let mut evidence = Map::new();
    evidence.insert(
        "schema".into(),
        Value::from("sorafs.transparency.explorer_canary.v1"),
    );
    evidence.insert("status".into(), Value::from("passed"));
    evidence.insert("source".into(), Value::from("iroha_cli"));
    evidence.insert("torii_url".into(), Value::from(torii_url.to_string()));
    evidence.insert("limit".into(), limit.map_or(Value::Null, Value::from));
    evidence.insert(
        "generated_at_unix".into(),
        Value::from(current_unix_timestamp()),
    );
    evidence.insert("route_count".into(), Value::from(routes.len() as u64));
    evidence.insert("payload_bytes_included".into(), Value::Bool(false));
    evidence.insert("private_digest_keys_included".into(), Value::Bool(false));
    evidence.insert("routes".into(), Value::Array(routes));
    Ok(Value::Object(evidence))
}
fn transparency_publication_canary_evidence_json<F>(
    torii_url: &str,
    cycle_ids: &[String],
    limit: Option<u32>,
    fetch: &mut F,
) -> Result<Value>
where
    F: FnMut(&str) -> Result<TransparencyExplorerCanaryHttpResponse>,
{
    let mut routes = Vec::with_capacity(1 + cycle_ids.len());
    routes.push(transparency_publication_canary_probe_route(
        torii_url,
        "cycles_list",
        None,
        limit,
        fetch,
    )?);
    for cycle_id in cycle_ids {
        routes.push(transparency_publication_canary_probe_route(
            torii_url,
            "cycle_publication",
            Some(cycle_id),
            limit,
            fetch,
        )?);
    }
    let passed_count = routes
        .iter()
        .filter(|route| {
            route
                .get("passed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    let mut evidence = Map::new();
    evidence.insert(
        "schema".into(),
        Value::from("sorafs.transparency.publication_canary.v1"),
    );
    evidence.insert(
        "status".into(),
        Value::from(if passed_count == routes.len() {
            "passed"
        } else {
            "failed"
        }),
    );
    evidence.insert("source".into(), Value::from("iroha_cli"));
    evidence.insert("torii_url".into(), Value::from(torii_url.to_string()));
    evidence.insert("limit".into(), limit.map_or(Value::Null, Value::from));
    evidence.insert(
        "generated_at_unix".into(),
        Value::from(current_unix_timestamp()),
    );
    evidence.insert("route_count".into(), Value::from(routes.len() as u64));
    evidence.insert(
        "passed_route_count".into(),
        Value::from(passed_count as u64),
    );
    evidence.insert(
        "cycle_detail_probe_count".into(),
        Value::from(cycle_ids.len() as u64),
    );
    evidence.insert("publisher_identity_required".into(), Value::Bool(true));
    evidence.insert("payload_bytes_included".into(), Value::Bool(false));
    evidence.insert("publication_bodies_included".into(), Value::Bool(false));
    evidence.insert("private_payloads_included".into(), Value::Bool(false));
    evidence.insert("routes".into(), Value::Array(routes));
    Ok(Value::Object(evidence))
}
fn transparency_publication_canary_probe_route<F>(
    torii_url: &str,
    route_name: &'static str,
    cycle_id: Option<&str>,
    limit: Option<u32>,
    fetch: &mut F,
) -> Result<Value>
where
    F: FnMut(&str) -> Result<TransparencyExplorerCanaryHttpResponse>,
{
    let url = transparency_publication_canary_route_url(torii_url, cycle_id, limit)?;
    let response = fetch(&url)?;
    let status_success = response.status == StatusCode::OK;
    let body_blake3_hex = blake3::hash(&response.body).to_hex().to_string();
    let body_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
    let mut route = Map::new();
    route.insert("name".into(), Value::from(route_name));
    route.insert("method".into(), Value::from("GET"));
    route.insert(
        "path".into(),
        Value::from(match cycle_id {
            Some(_) => "/v1/sorafs/transparency/cycles/{cycle_id}",
            None => "/v1/sorafs/transparency/cycles",
        }),
    );
    route.insert("url".into(), Value::from(url));
    if let Some(cycle_id) = cycle_id {
        route.insert("cycle_id_hex".into(), Value::from(cycle_id.to_string()));
    }
    route.insert(
        "status_code".into(),
        Value::from(u64::from(response.status.as_u16())),
    );
    route.insert("http_success".into(), Value::Bool(status_success));
    route.insert(
        "content_type".into(),
        response.content_type.map_or(Value::Null, Value::from),
    );
    route.insert("body_blake3_hex".into(), Value::from(body_blake3_hex));
    route.insert("body_bytes".into(), Value::from(body_bytes));
    route.insert("payload_bytes_included".into(), Value::Bool(false));
    route.insert("publication_body_included".into(), Value::Bool(false));
    route.insert("private_payloads_included".into(), Value::Bool(false));
    if !status_success {
        route.insert("passed".into(), Value::Bool(false));
        return Ok(Value::Object(route));
    }
    let value: Value = norito::json::from_slice(&response.body).wrap_err_with(|| {
        format!("failed to decode SoraFS transparency publication canary `{route_name}` JSON")
    })?;
    transparency_explorer_canary_ensure_payload_free(&value)?;
    let expected_schema = if cycle_id.is_some() {
        "sorafs.transparency.cycle_publication.v1"
    } else {
        "sorafs.transparency.cycles.v1"
    };
    let actual_schema = value
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let schema_ok = actual_schema == expected_schema;
    let anchor_metadata_present =
        transparency_publication_canary_anchor_metadata_present(&value, cycle_id.is_some());
    let publisher_identity_present =
        transparency_publication_canary_publisher_identity_present(&value);
    let verification_valid = if cycle_id.is_some() {
        value
            .get("verification")
            .and_then(|verification| verification.get("valid"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
            && value
                .get("verification")
                .and_then(|verification| verification.get("all_proofs_verified"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
    } else {
        true
    };
    let passed =
        schema_ok && anchor_metadata_present && verification_valid && publisher_identity_present;
    route.insert("passed".into(), Value::Bool(passed));
    route.insert("schema".into(), Value::from(actual_schema.to_string()));
    route.insert("schema_ok".into(), Value::Bool(schema_ok));
    route.insert(
        "anchor_metadata_present".into(),
        Value::Bool(anchor_metadata_present),
    );
    route.insert(
        "publisher_identity_present".into(),
        Value::Bool(publisher_identity_present),
    );
    route.insert("verification_valid".into(), Value::Bool(verification_valid));
    if cycle_id.is_none() {
        route.insert(
            "published_cycle_count".into(),
            value
                .get("published_cycle_count")
                .cloned()
                .unwrap_or(Value::Null),
        );
        route.insert(
            "returned_cycle_count".into(),
            value
                .get("returned_cycle_count")
                .cloned()
                .unwrap_or(Value::Null),
        );
        route.insert(
            "truncated".into(),
            value.get("truncated").cloned().unwrap_or(Value::Null),
        );
    } else {
        route.insert(
            "proof_count".into(),
            value.get("proof_count").cloned().unwrap_or(Value::Null),
        );
        route.insert(
            "returned_proof_count".into(),
            value
                .get("returned_proof_count")
                .cloned()
                .unwrap_or(Value::Null),
        );
        route.insert(
            "truncated_proofs".into(),
            value
                .get("truncated_proofs")
                .cloned()
                .unwrap_or(Value::Null),
        );
    }
    Ok(Value::Object(route))
}
fn transparency_explorer_canary_route_specs() -> Vec<TransparencyExplorerCanaryRouteSpec> {
    vec![
        TransparencyExplorerCanaryRouteSpec {
            name: "explorer_snapshot",
            path: "/v1/sorafs/transparency/explorer",
            expected_schema: Some("sorafs.transparency.explorer_snapshot.v1"),
            expect_html_marker: None,
            include_limit: true,
        },
        TransparencyExplorerCanaryRouteSpec {
            name: "browser_ui",
            path: "/v1/sorafs/transparency/explorer/ui",
            expected_schema: None,
            expect_html_marker: Some("SoraFS Transparency Explorer"),
            include_limit: false,
        },
        TransparencyExplorerCanaryRouteSpec {
            name: "proof_token_issuance_index",
            path: "/v1/sorafs/transparency/tokens",
            expected_schema: Some("sorafs.transparency.proof_token_issuances.v1"),
            expect_html_marker: None,
            include_limit: true,
        },
    ]
}
fn transparency_explorer_canary_probe_route<F>(
    torii_url: &str,
    spec: &TransparencyExplorerCanaryRouteSpec,
    limit: Option<u32>,
    fetch: &mut F,
) -> Result<Value>
where
    F: FnMut(&str) -> Result<TransparencyExplorerCanaryHttpResponse>,
{
    let url = transparency_explorer_canary_route_url(torii_url, spec, limit)?;
    let response = fetch(&url)?;
    if response.status != StatusCode::OK {
        return Err(eyre!(
            "SoraFS transparency explorer canary route `{}` returned status {}",
            spec.name,
            response.status
        ));
    }
    let body_blake3_hex = blake3::hash(&response.body).to_hex().to_string();
    let mut schema = None;
    if let Some(expected_schema) = spec.expected_schema {
        let value: Value = norito::json::from_slice(&response.body).wrap_err_with(|| {
            format!(
                "failed to decode SoraFS transparency explorer canary `{}` JSON response",
                spec.name
            )
        })?;
        transparency_explorer_canary_ensure_payload_free(&value)?;
        let fields = value_object(&value, "transparency explorer canary JSON response")?;
        let actual_schema = required_string_field(
            fields,
            "schema",
            "transparency explorer canary JSON response",
        )?;
        if actual_schema != expected_schema {
            return Err(eyre!(
                "SoraFS transparency explorer canary route `{}` returned schema `{actual_schema}` (expected `{expected_schema}`)",
                spec.name
            ));
        }
        schema = Some(actual_schema.to_string());
    }
    if let Some(marker) = spec.expect_html_marker {
        let body = std::str::from_utf8(&response.body).wrap_err_with(|| {
            format!(
                "SoraFS transparency explorer canary `{}` response is not UTF-8",
                spec.name
            )
        })?;
        if !body.contains(marker) {
            return Err(eyre!(
                "SoraFS transparency explorer canary route `{}` response is missing `{marker}`",
                spec.name
            ));
        }
        transparency_explorer_canary_ensure_html_payload_free(body, spec.name)?;
    }
    let mut route = Map::new();
    route.insert("name".into(), Value::from(spec.name));
    route.insert("method".into(), Value::from("GET"));
    route.insert("path".into(), Value::from(spec.path));
    route.insert("url".into(), Value::from(url));
    route.insert(
        "status_code".into(),
        Value::from(u64::from(response.status.as_u16())),
    );
    route.insert(
        "content_type".into(),
        response.content_type.map_or(Value::Null, Value::from),
    );
    route.insert("schema".into(), schema.map_or(Value::Null, Value::from));
    route.insert("body_blake3_hex".into(), Value::from(body_blake3_hex));
    route.insert(
        "body_bytes".into(),
        Value::from(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
    );
    route.insert("payload_bytes_included".into(), Value::Bool(false));
    route.insert("private_digest_keys_included".into(), Value::Bool(false));
    Ok(Value::Object(route))
}
fn transparency_explorer_canary_route_url(
    torii_url: &str,
    spec: &TransparencyExplorerCanaryRouteSpec,
    limit: Option<u32>,
) -> Result<String> {
    let base = format!("{}/", torii_url.trim_end_matches('/'));
    let mut url = reqwest::Url::parse(&base)
        .wrap_err_with(|| format!("failed to parse --torii-url `{torii_url}`"))?
        .join(spec.path.trim_start_matches('/'))
        .wrap_err_with(|| format!("failed to join transparency explorer route `{}`", spec.path))?;
    if spec.include_limit
        && let Some(limit) = limit
    {
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
    }
    Ok(url.to_string())
}
fn transparency_publication_canary_route_url(
    torii_url: &str,
    cycle_id: Option<&str>,
    limit: Option<u32>,
) -> Result<String> {
    let base = format!("{}/", torii_url.trim_end_matches('/'));
    let mut url = reqwest::Url::parse(&base)
        .wrap_err_with(|| format!("failed to parse --torii-url `{torii_url}`"))?
        .join("v1/sorafs/transparency/cycles")
        .wrap_err("failed to join transparency publication cycles route")?;
    if let Some(cycle_id) = cycle_id {
        url.path_segments_mut()
            .map_err(|_| eyre!("failed to append transparency cycle id to --torii-url"))?
            .push(cycle_id);
    }
    if let Some(limit) = limit {
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
    }
    Ok(url.to_string())
}
fn transparency_publication_canary_anchor_metadata_present(
    value: &Value,
    cycle_detail: bool,
) -> bool {
    fn has_string_field(fields: &Map, key: &str) -> bool {
        fields
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty() && !matches!(value, "0" | "0x0"))
    }
    if cycle_detail {
        let Some(fields) = value.as_object() else {
            return false;
        };
        let Some(verification) = fields.get("verification").and_then(Value::as_object) else {
            return false;
        };
        has_string_field(fields, "encoded_blake3")
            && has_string_field(verification, "block_hash_hex")
            && has_string_field(verification, "publication_hash_hex")
            && has_string_field(verification, "entry_root_hex")
    } else {
        let Some(first_cycle) = value
            .get("cycles")
            .and_then(Value::as_array)
            .and_then(|cycles| cycles.first())
            .and_then(Value::as_object)
        else {
            return false;
        };
        has_string_field(first_cycle, "block_hash_hex")
            && has_string_field(first_cycle, "publication_hash_hex")
            && has_string_field(first_cycle, "entry_root_hex")
            && has_string_field(first_cycle, "encoded_blake3")
    }
}
fn transparency_publication_canary_publisher_identity_present(value: &Value) -> bool {
    fn visit(value: &Value) -> bool {
        match value {
            Value::Object(fields) => {
                for key in [
                    "publisher_peer_id",
                    "publisher_peer_id_hex",
                    "publisher_public_key_hex",
                ] {
                    if fields
                        .get(key)
                        .and_then(Value::as_str)
                        .is_some_and(|value| {
                            !value.trim().is_empty() && !matches!(value, "0" | "0x0")
                        })
                    {
                        return true;
                    }
                }
                fields.values().any(visit)
            }
            Value::Array(values) => values.iter().any(visit),
            _ => false,
        }
    }
    visit(value)
}
fn transparency_explorer_canary_ensure_payload_free(value: &Value) -> Result<()> {
    fn visit(path: &str, value: &Value) -> Result<()> {
        match value {
            Value::Object(fields) => {
                for (key, child) in fields {
                    let child_path = if path.is_empty() {
                        key.to_string()
                    } else {
                        format!("{path}.{key}")
                    };
                    if matches!(
                        key.as_str(),
                        "payload_b64"
                            | "payload_bytes"
                            | "payload_body"
                            | "blinded_digest_key"
                            | "digest_key"
                            | "proof_token_digest_key"
                            | "private_digest_key"
                    ) {
                        return Err(eyre!(
                            "transparency explorer canary response included private payload or digest-key material at `{child_path}`"
                        ));
                    }
                    if matches!(
                        key.as_str(),
                        "payload_bytes_included"
                            | "private_payloads_included"
                            | "private_payload_included"
                            | "private_digest_keys_included"
                    ) && child.as_bool() == Some(true)
                    {
                        return Err(eyre!(
                            "transparency explorer canary response advertised private payload or digest-key material at `{child_path}`"
                        ));
                    }
                    visit(&child_path, child)?;
                }
            }
            Value::Array(values) => {
                for (index, child) in values.iter().enumerate() {
                    visit(&format!("{path}[{index}]"), child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit("", value)
}
fn transparency_explorer_canary_ensure_html_payload_free(
    body: &str,
    route_name: &str,
) -> Result<()> {
    for marker in [
        "payload_b64",
        "payload_bytes",
        "blinded_digest_key",
        "digest_key",
        "proof_token_digest_key",
        "private_digest_key",
    ] {
        if body.contains(marker) {
            return Err(eyre!(
                "SoraFS transparency explorer canary route `{route_name}` HTML included private marker `{marker}`"
            ));
        }
    }
    Ok(())
}
fn moderation_operator_canary_evidence_json<F>(
    operator_url: &str,
    quarantine_id_hex: &str,
    limit: Option<u32>,
    fetch: &mut F,
) -> Result<Value>
where
    F: FnMut(&str) -> Result<ModerationOperatorCanaryHttpResponse>,
{
    let route_specs = moderation_operator_canary_route_specs(quarantine_id_hex);
    let mut routes = Vec::with_capacity(route_specs.len());
    for spec in &route_specs {
        routes.push(moderation_operator_canary_probe_route(
            operator_url,
            spec,
            limit,
            fetch,
        )?);
    }
    let mut evidence = Map::new();
    evidence.insert(
        "schema".into(),
        Value::from("sorafs.moderation.quarantine.operator_canary.v1"),
    );
    evidence.insert("status".into(), Value::from("passed"));
    evidence.insert("source".into(), Value::from("iroha_cli"));
    evidence.insert("operator_url".into(), Value::from(operator_url.to_string()));
    evidence.insert(
        "quarantine_id_hex".into(),
        Value::from(quarantine_id_hex.to_string()),
    );
    evidence.insert("limit".into(), limit.map_or(Value::Null, Value::from));
    evidence.insert(
        "generated_at_unix".into(),
        Value::from(current_unix_timestamp()),
    );
    evidence.insert("route_count".into(), Value::from(routes.len() as u64));
    evidence.insert("payload_bytes_included".into(), Value::Bool(false));
    evidence.insert("private_payloads_included".into(), Value::Bool(false));
    evidence.insert("routes".into(), Value::Array(routes));
    Ok(Value::Object(evidence))
}
fn moderation_operator_canary_route_specs(
    quarantine_id_hex: &str,
) -> Vec<ModerationOperatorCanaryRouteSpec> {
    let workflow =
        |suffix: &str| format!("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/{suffix}");
    vec![
        ModerationOperatorCanaryRouteSpec {
            name: "healthz",
            path: "/healthz".to_string(),
            expected_schema: Some("sorafs.moderation.quarantine.operator_service.status.v1"),
            expect_html_marker: None,
            include_limit: false,
        },
        ModerationOperatorCanaryRouteSpec {
            name: "status",
            path: "/v1/sorafs/moderation/operator-panel/status".to_string(),
            expected_schema: Some("sorafs.moderation.quarantine.operator_service.status.v1"),
            expect_html_marker: None,
            include_limit: false,
        },
        ModerationOperatorCanaryRouteSpec {
            name: "browser_ui",
            path: "/v1/sorafs/moderation/operator-panel/ui".to_string(),
            expected_schema: None,
            expect_html_marker: Some("SoraFS Moderation Operator"),
            include_limit: false,
        },
        ModerationOperatorCanaryRouteSpec {
            name: "operator_panel",
            path: workflow("operator-panel"),
            expected_schema: Some("sorafs.moderation.quarantine.operator_panel.v1"),
            expect_html_marker: None,
            include_limit: true,
        },
        ModerationOperatorCanaryRouteSpec {
            name: "bridge_plan",
            path: workflow("bridge-plan"),
            expected_schema: Some("sorafs.moderation.quarantine.bridge_plan.v1"),
            expect_html_marker: None,
            include_limit: true,
        },
        ModerationOperatorCanaryRouteSpec {
            name: "juror_plan",
            path: workflow("juror-plan"),
            expected_schema: Some("sorafs.moderation.quarantine.juror_plan.v1"),
            expect_html_marker: None,
            include_limit: true,
        },
        ModerationOperatorCanaryRouteSpec {
            name: "juror_notifications",
            path: workflow("juror-notifications"),
            expected_schema: Some("sorafs.moderation.quarantine.juror_notifications.v1"),
            expect_html_marker: None,
            include_limit: true,
        },
        ModerationOperatorCanaryRouteSpec {
            name: "commit_reveal_status",
            path: workflow("commit-reveal-status"),
            expected_schema: Some("sorafs.moderation.quarantine.commit_reveal_status.v1"),
            expect_html_marker: None,
            include_limit: true,
        },
    ]
}
fn moderation_operator_canary_probe_route<F>(
    operator_url: &str,
    spec: &ModerationOperatorCanaryRouteSpec,
    limit: Option<u32>,
    fetch: &mut F,
) -> Result<Value>
where
    F: FnMut(&str) -> Result<ModerationOperatorCanaryHttpResponse>,
{
    let url = moderation_operator_canary_route_url(operator_url, spec, limit)?;
    let response = fetch(&url)?;
    if response.status != StatusCode::OK {
        return Err(eyre!(
            "SoraFS moderation operator canary route `{}` returned status {}",
            spec.name,
            response.status
        ));
    }
    let body_blake3_hex = blake3::hash(&response.body).to_hex().to_string();
    let mut schema = None;
    if let Some(expected_schema) = spec.expected_schema {
        let value: Value = norito::json::from_slice(&response.body).wrap_err_with(|| {
            format!(
                "failed to decode SoraFS moderation operator canary `{}` JSON response",
                spec.name
            )
        })?;
        moderation_operator_canary_ensure_payload_free(&value)?;
        let fields = value_object(&value, "operator canary JSON response")?;
        let actual_schema =
            required_string_field(fields, "schema", "operator canary JSON response")?;
        if actual_schema != expected_schema {
            return Err(eyre!(
                "SoraFS moderation operator canary route `{}` returned schema `{actual_schema}` (expected `{expected_schema}`)",
                spec.name
            ));
        }
        schema = Some(actual_schema.to_string());
    }
    if let Some(marker) = spec.expect_html_marker {
        let body = std::str::from_utf8(&response.body).wrap_err_with(|| {
            format!(
                "SoraFS moderation operator canary `{}` response is not UTF-8",
                spec.name
            )
        })?;
        if !body.contains(marker) {
            return Err(eyre!(
                "SoraFS moderation operator canary route `{}` response is missing `{marker}`",
                spec.name
            ));
        }
    }
    let mut route = Map::new();
    route.insert("name".into(), Value::from(spec.name));
    route.insert("method".into(), Value::from("GET"));
    route.insert("path".into(), Value::from(spec.path.clone()));
    route.insert("url".into(), Value::from(url));
    route.insert(
        "status_code".into(),
        Value::from(u64::from(response.status.as_u16())),
    );
    route.insert(
        "content_type".into(),
        response.content_type.map_or(Value::Null, Value::from),
    );
    route.insert("schema".into(), schema.map_or(Value::Null, Value::from));
    route.insert("body_blake3_hex".into(), Value::from(body_blake3_hex));
    route.insert(
        "body_bytes".into(),
        Value::from(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
    );
    route.insert("payload_bytes_included".into(), Value::Bool(false));
    route.insert("private_payloads_included".into(), Value::Bool(false));
    Ok(Value::Object(route))
}
fn moderation_operator_canary_route_url(
    operator_url: &str,
    spec: &ModerationOperatorCanaryRouteSpec,
    limit: Option<u32>,
) -> Result<String> {
    let base = format!("{}/", operator_url.trim_end_matches('/'));
    let mut url = reqwest::Url::parse(&base)
        .wrap_err_with(|| format!("failed to parse --operator-url `{operator_url}`"))?
        .join(spec.path.trim_start_matches('/'))
        .wrap_err_with(|| format!("failed to join operator route `{}`", spec.path))?;
    if spec.include_limit
        && let Some(limit) = limit
    {
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
    }
    Ok(url.to_string())
}
fn moderation_operator_canary_ensure_payload_free(value: &Value) -> Result<()> {
    fn visit(path: &str, value: &Value) -> Result<()> {
        match value {
            Value::Object(fields) => {
                for (key, child) in fields {
                    let child_path = if path.is_empty() {
                        key.to_string()
                    } else {
                        format!("{path}.{key}")
                    };
                    if key == "payload_b64" {
                        return Err(eyre!(
                            "operator canary response unexpectedly included payload bytes at `{child_path}`"
                        ));
                    }
                    if matches!(
                        key.as_str(),
                        "payload_bytes_included"
                            | "private_payloads_included"
                            | "private_payload_included"
                    ) && child.as_bool() == Some(true)
                    {
                        return Err(eyre!(
                            "operator canary response advertised payload bytes at `{child_path}`"
                        ));
                    }
                    visit(&child_path, child)?;
                }
            }
            Value::Array(values) => {
                for (index, child) in values.iter().enumerate() {
                    visit(&format!("{path}[{index}]"), child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit("", value)
}
fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn generate_nonce_hex(bytes: usize) -> Result<String> {
    generate_nonce_hex_with_rng(bytes, &mut OsRng)
}
fn generate_moderation_operator_csrf_token() -> Result<String> {
    let mut token = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut token)
        .map_err(|error| eyre!("SoraFS moderation operator CSRF token OS RNG failed: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(token))
}
fn generate_nonce_hex_with_rng<R: TryCryptoRng>(bytes: usize, rng: &mut R) -> Result<String> {
    let mut data = vec![0u8; bytes];
    rng.try_fill_bytes(&mut data)
        .map_err(|error| eyre!("SoraFS CLI nonce OS RNG failed: {error}"))?;
    Ok(hex::encode(data))
}
fn render_json_response<C: RunContext>(context: &mut C, response: Response<Vec<u8>>) -> Result<()> {
    let status = response.status();
    let body = response.into_body();
    match status {
        StatusCode::OK => render_json_body(context, &body),
        status => Err(make_http_error(status, &body)),
    }
}
fn render_json_response_ok_or_accepted<C: RunContext>(
    context: &mut C,
    response: Response<Vec<u8>>,
) -> Result<()> {
    let status = response.status();
    let body = response.into_body();
    match status {
        StatusCode::OK | StatusCode::ACCEPTED => render_json_body(context, &body),
        status => Err(make_http_error(status, &body)),
    }
}
fn render_json_body<C: RunContext>(context: &mut C, body: &[u8]) -> Result<()> {
    let value: norito::json::Value = norito::json::from_slice(body)?;
    context.print_data(&value)
}
fn render_moderation_quarantine_bridge_plan_response<C: RunContext>(
    context: &mut C,
    response: Response<Vec<u8>>,
    quarantine_id_hex: &str,
) -> Result<()> {
    let status = response.status();
    let body = response.into_body();
    match status {
        StatusCode::OK => {
            let panel: Value = norito::json::from_slice(&body)
                .wrap_err("failed to decode moderation operator-panel JSON")?;
            let plan = moderation_quarantine_bridge_plan_json(quarantine_id_hex, &panel)?;
            context.print_data(&plan)
        }
        status => Err(make_http_error(status, &body)),
    }
}
fn moderation_quarantine_bridge_plan_json(quarantine_id_hex: &str, panel: &Value) -> Result<Value> {
    ensure_moderation_bridge_plan_has_no_payload(panel)?;
    let root = value_object(panel, "operator panel response")?;
    let schema = required_string_field(root, "schema", "operator panel response")?;
    if schema != "sorafs.moderation.quarantine.operator_panel.v1" {
        return Err(eyre!(
            "operator panel response schema `{schema}` is not supported by bridge-plan"
        ));
    }
    let record = root
        .get("record")
        .ok_or_else(|| eyre!("operator panel response is missing `record`"))?;
    let record_obj = value_object(record, "operator panel record")?;
    let record_state = required_string_field(record_obj, "state", "operator panel record")?;
    let object_status = required_string_field(root, "object_status", "operator panel response")?;
    let case_count = root
        .get("case_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let returned_case_count = root
        .get("returned_case_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let next_actions = root
        .get("next_actions")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("operator panel response is missing `next_actions` array"))?;
    let cases = root
        .get("cases")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let case_ref = first_moderation_case_reference(cases);
    let mut actions = Vec::with_capacity(next_actions.len());
    let mut required_count = 0_u64;
    for (index, action) in next_actions.iter().enumerate() {
        let planned =
            moderation_quarantine_bridge_action_json(index, action, quarantine_id_hex, case_ref)?;
        if planned
            .as_object()
            .and_then(|fields| fields.get("required"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            required_count += 1;
        }
        actions.push(planned);
    }
    let mut plan = Map::new();
    plan.insert(
        "schema".into(),
        Value::from("sorafs.moderation.quarantine.bridge_plan.v1"),
    );
    plan.insert("source".into(), Value::from("operator-panel"));
    plan.insert("status".into(), Value::from("planned"));
    plan.insert(
        "quarantine_id_hex".into(),
        Value::from(quarantine_id_hex.to_string()),
    );
    plan.insert("record_state".into(), Value::from(record_state.to_string()));
    plan.insert(
        "object_status".into(),
        Value::from(object_status.to_string()),
    );
    plan.insert("case_count".into(), Value::from(case_count));
    plan.insert(
        "returned_case_count".into(),
        Value::from(returned_case_count),
    );
    plan.insert("action_count".into(), Value::from(actions.len() as u64));
    plan.insert("required_action_count".into(), Value::from(required_count));
    plan.insert("payload_bytes_included".into(), Value::Bool(false));
    plan.insert("actions".into(), Value::Array(actions));
    Ok(Value::Object(plan))
}
fn moderation_quarantine_bridge_action_json(
    index: usize,
    action: &Value,
    quarantine_id_hex: &str,
    ballot_ref: Option<(&str, &str)>,
) -> Result<Value> {
    let action_obj = value_object(action, "operator panel next action")?;
    let action_name = required_string_field(action_obj, "action", "operator panel next action")?;
    let route = required_string_field(action_obj, "route", "operator panel next action")?;
    let required = action_obj
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut fields = Map::new();
    fields.insert("order".into(), Value::from((index + 1) as u64));
    fields.insert("action".into(), Value::from(action_name.to_string()));
    fields.insert("required".into(), Value::Bool(required));
    fields.insert("route".into(), Value::from(route.to_string()));
    fields.insert(
        "automation_status".into(),
        Value::from(moderation_quarantine_bridge_action_status(
            action_name,
            required,
        )),
    );
    fields.insert(
        "cli".into(),
        Value::Array(
            moderation_quarantine_bridge_action_cli(action_name, quarantine_id_hex, ballot_ref)
                .into_iter()
                .map(Value::from)
                .collect(),
        ),
    );
    Ok(Value::Object(fields))
}
fn moderation_quarantine_bridge_action_status(action: &str, required: bool) -> &'static str {
    match action {
        "store_object" => "blocked_until_payload_is_sealed",
        "read_object" => {
            if required {
                "required_payload_review"
            } else {
                "available_for_operator_review"
            }
        }
        "review" => "operator_review_required",
        "appeal_handoff" => "ready_for_appeal_finance_handoff",
        "submit_native_appeal_intake" => "ready_for_caller_signed_native_appeal",
        "await_chain_sortition_activation" => "waiting_for_finalized_chain_activation",
        "submit_native_case_actions" => "waiting_for_native_commit_reveal_finalization",
        "release_complete" => "complete",
        _ => "operator_attention_required",
    }
}
fn moderation_quarantine_bridge_action_cli(
    action: &str,
    quarantine_id_hex: &str,
    ballot_ref: Option<(&str, &str)>,
) -> Vec<String> {
    let command = |parts: &[&str]| parts.iter().map(|part| (*part).to_string()).collect();
    match action {
        "store_object" => command(&[
            "iroha",
            "sorafs",
            "moderation",
            "quarantine",
            "object",
            "store",
            "--quarantine-id",
            quarantine_id_hex,
            "--payload-file",
            "<payload>",
        ]),
        "read_object" => command(&[
            "iroha",
            "sorafs",
            "moderation",
            "quarantine",
            "object",
            "read",
            "--quarantine-id",
            quarantine_id_hex,
        ]),
        "review" => command(&[
            "iroha",
            "sorafs",
            "moderation",
            "quarantine",
            "review",
            "--quarantine-id",
            quarantine_id_hex,
        ]),
        "appeal_handoff" => command(&[
            "iroha",
            "sorafs",
            "moderation",
            "quarantine",
            "appeal-handoff",
            "--quarantine-id",
            quarantine_id_hex,
            "--input",
            "<appeal-handoff.json>",
        ]),
        "submit_native_appeal_intake" => command(&[
            "iroha",
            "transaction",
            "submit",
            "--file",
            "<signed-native-moderation-appeal.norito>",
        ]),
        "await_chain_sortition_activation" => command(&[
            "iroha",
            "sorafs",
            "moderation",
            "ballots",
            "events",
            "--limit",
            "25",
        ]),
        "submit_native_case_actions" => {
            if let Some((case_id, round_id)) = ballot_ref {
                command(&[
                    "iroha",
                    "sorafs",
                    "moderation",
                    "ballots",
                    "tally",
                    "--case-id",
                    case_id,
                    "--round-id",
                    round_id,
                ])
            } else {
                command(&[
                    "iroha",
                    "sorafs",
                    "moderation",
                    "ballots",
                    "events",
                    "--limit",
                    "25",
                ])
            }
        }
        "release_complete" => command(&[
            "iroha",
            "sorafs",
            "moderation",
            "quarantine",
            "operator-panel",
            "--quarantine-id",
            quarantine_id_hex,
        ]),
        _ => command(&[
            "iroha",
            "sorafs",
            "moderation",
            "quarantine",
            "operator-panel",
            "--quarantine-id",
            quarantine_id_hex,
        ]),
    }
}
fn moderation_quarantine_juror_plan_json(quarantine_id_hex: &str, panel: &Value) -> Result<Value> {
    ensure_moderation_bridge_plan_has_no_payload(panel)?;
    let root = value_object(panel, "operator panel response")?;
    let schema = required_string_field(root, "schema", "operator panel response")?;
    if schema != "sorafs.moderation.quarantine.operator_panel.v1" {
        return Err(eyre!(
            "operator panel response schema `{schema}` is not supported by juror-plan"
        ));
    }
    let ballot_count = root
        .get("case_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let returned_ballot_count = root
        .get("returned_case_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let truncated_ballots = root
        .get("truncated_cases")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let ballots = root
        .get("cases")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut planned_ballots = Vec::with_capacity(ballots.len());
    let mut notification_count = 0_u64;
    let mut pending_commit_count = 0_u64;
    let mut pending_reveal_count = 0_u64;
    for ballot in ballots {
        let (planned, counts) = moderation_quarantine_juror_plan_ballot_json(ballot)?;
        notification_count = notification_count.saturating_add(counts.notification_count);
        pending_commit_count = pending_commit_count.saturating_add(counts.pending_commit_count);
        pending_reveal_count = pending_reveal_count.saturating_add(counts.pending_reveal_count);
        planned_ballots.push(planned);
    }
    let mut plan = Map::new();
    plan.insert(
        "schema".into(),
        Value::from("sorafs.moderation.quarantine.juror_plan.v1"),
    );
    plan.insert("source".into(), Value::from("operator-panel"));
    plan.insert("status".into(), Value::from("planned"));
    plan.insert(
        "quarantine_id_hex".into(),
        Value::from(quarantine_id_hex.to_string()),
    );
    plan.insert("ballot_count".into(), Value::from(ballot_count));
    plan.insert(
        "returned_ballot_count".into(),
        Value::from(returned_ballot_count),
    );
    plan.insert("truncated_ballots".into(), Value::Bool(truncated_ballots));
    plan.insert("notification_count".into(), Value::from(notification_count));
    plan.insert(
        "pending_commit_count".into(),
        Value::from(pending_commit_count),
    );
    plan.insert(
        "pending_reveal_count".into(),
        Value::from(pending_reveal_count),
    );
    plan.insert("payload_bytes_included".into(), Value::Bool(false));
    plan.insert("ballots".into(), Value::Array(planned_ballots));
    Ok(Value::Object(plan))
}
fn moderation_quarantine_juror_notifications_json(
    quarantine_id_hex: &str,
    panel: &Value,
) -> Result<Value> {
    let plan = moderation_quarantine_juror_plan_json(quarantine_id_hex, panel)?;
    moderation_quarantine_juror_notifications_from_plan(quarantine_id_hex, &plan)
}
fn moderation_quarantine_juror_notifications_from_plan(
    quarantine_id_hex: &str,
    plan: &Value,
) -> Result<Value> {
    let root = value_object(plan, "juror notification plan")?;
    let schema = required_string_field(root, "schema", "juror notification plan")?;
    if schema != "sorafs.moderation.quarantine.juror_plan.v1" {
        return Err(eyre!(
            "juror notification plan schema `{schema}` is not supported by notification delivery"
        ));
    }
    let ballots = root
        .get("ballots")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut notifications = Vec::new();
    let mut planned_juror_count = 0_u64;
    let mut skipped_complete_count = 0_u64;
    let mut pending_commit_count = 0_u64;
    let mut pending_reveal_count = 0_u64;
    for ballot in ballots {
        let ballot_obj = value_object(ballot, "juror notification ballot")?;
        let case_id = required_string_field(ballot_obj, "case_id", "juror notification ballot")?;
        let round_id = required_string_field(ballot_obj, "round_id", "juror notification ballot")?;
        let jurors = ballot_obj
            .get("jurors")
            .and_then(Value::as_array)
            .ok_or_else(|| eyre!("juror notification ballot is missing `jurors` array"))?;
        for juror in jurors {
            planned_juror_count = planned_juror_count.saturating_add(1);
            let juror_obj = value_object(juror, "juror notification entry")?;
            let needs_commit = juror_obj
                .get("needs_commit")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let needs_reveal = juror_obj
                .get("needs_reveal")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !needs_commit && !needs_reveal {
                skipped_complete_count = skipped_complete_count.saturating_add(1);
                continue;
            }
            let notification = moderation_quarantine_juror_notification_delivery_json(
                quarantine_id_hex,
                case_id,
                round_id,
                ballot_obj,
                juror_obj,
                needs_commit,
            )?;
            if needs_commit {
                pending_commit_count = pending_commit_count.saturating_add(1);
            } else if needs_reveal {
                pending_reveal_count = pending_reveal_count.saturating_add(1);
            }
            notifications.push(notification);
        }
    }
    let mut delivery = Map::new();
    delivery.insert(
        "schema".into(),
        Value::from("sorafs.moderation.quarantine.juror_notifications.v1"),
    );
    delivery.insert("source".into(), Value::from("juror-plan"));
    delivery.insert("status".into(), Value::from("ready"));
    delivery.insert(
        "quarantine_id_hex".into(),
        Value::from(quarantine_id_hex.to_string()),
    );
    delivery.insert(
        "planned_juror_count".into(),
        Value::from(planned_juror_count),
    );
    delivery.insert(
        "notification_count".into(),
        Value::from(notifications.len() as u64),
    );
    delivery.insert(
        "skipped_complete_count".into(),
        Value::from(skipped_complete_count),
    );
    delivery.insert(
        "pending_commit_count".into(),
        Value::from(pending_commit_count),
    );
    delivery.insert(
        "pending_reveal_count".into(),
        Value::from(pending_reveal_count),
    );
    delivery.insert("delivery_transport".into(), Value::from("operator-managed"));
    delivery.insert(
        "delivery_semantics".into(),
        Value::from("at-least-once-with-dedup-key"),
    );
    delivery.insert("payload_bytes_included".into(), Value::Bool(false));
    delivery.insert("private_payloads_included".into(), Value::Bool(false));
    delivery.insert("notifications".into(), Value::Array(notifications));
    Ok(Value::Object(delivery))
}
fn moderation_quarantine_commit_reveal_status_json(
    quarantine_id_hex: &str,
    panel: &Value,
) -> Result<Value> {
    let plan = moderation_quarantine_juror_plan_json(quarantine_id_hex, panel)?;
    moderation_quarantine_commit_reveal_status_from_plan(quarantine_id_hex, &plan)
}
fn moderation_quarantine_commit_reveal_status_from_plan(
    quarantine_id_hex: &str,
    plan: &Value,
) -> Result<Value> {
    let root = value_object(plan, "commit/reveal coordination plan")?;
    let schema = required_string_field(root, "schema", "commit/reveal coordination plan")?;
    if schema != "sorafs.moderation.quarantine.juror_plan.v1" {
        return Err(eyre!(
            "juror notification plan schema `{schema}` is not supported by commit/reveal coordination"
        ));
    }
    let ballots = root
        .get("ballots")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut ballot_statuses = Vec::with_capacity(ballots.len());
    let mut pending_commit_count = 0_u64;
    let mut pending_reveal_count = 0_u64;
    let mut commit_quorum_count = 0_u64;
    let mut reveal_quorum_count = 0_u64;
    let mut tally_ready_count = 0_u64;
    let mut tallied_count = 0_u64;
    for ballot in ballots {
        let (status, counts) =
            moderation_quarantine_commit_reveal_ballot_status_json(quarantine_id_hex, ballot)?;
        pending_commit_count = pending_commit_count.saturating_add(counts.pending_commit_count);
        pending_reveal_count = pending_reveal_count.saturating_add(counts.pending_reveal_count);
        if counts.commit_quorum_met {
            commit_quorum_count = commit_quorum_count.saturating_add(1);
        }
        if counts.reveal_quorum_met {
            reveal_quorum_count = reveal_quorum_count.saturating_add(1);
        }
        if counts.ready_to_tally {
            tally_ready_count = tally_ready_count.saturating_add(1);
        }
        if counts.tallied {
            tallied_count = tallied_count.saturating_add(1);
        }
        ballot_statuses.push(status);
    }
    let mut status = Map::new();
    status.insert(
        "schema".into(),
        Value::from("sorafs.moderation.quarantine.commit_reveal_status.v1"),
    );
    status.insert("source".into(), Value::from("juror-plan"));
    status.insert("status".into(), Value::from("coordinated"));
    status.insert(
        "quarantine_id_hex".into(),
        Value::from(quarantine_id_hex.to_string()),
    );
    status.insert(
        "ballot_count".into(),
        Value::from(ballot_statuses.len() as u64),
    );
    status.insert(
        "pending_commit_count".into(),
        Value::from(pending_commit_count),
    );
    status.insert(
        "pending_reveal_count".into(),
        Value::from(pending_reveal_count),
    );
    status.insert(
        "commit_quorum_count".into(),
        Value::from(commit_quorum_count),
    );
    status.insert(
        "reveal_quorum_count".into(),
        Value::from(reveal_quorum_count),
    );
    status.insert("tally_ready_count".into(), Value::from(tally_ready_count));
    status.insert("tallied_count".into(), Value::from(tallied_count));
    status.insert("payload_bytes_included".into(), Value::Bool(false));
    status.insert("private_payloads_included".into(), Value::Bool(false));
    status.insert("ballots".into(), Value::Array(ballot_statuses));
    Ok(Value::Object(status))
}
#[derive(Default)]
struct ModerationCommitRevealStatusCounts {
    pending_commit_count: u64,
    pending_reveal_count: u64,
    commit_quorum_met: bool,
    reveal_quorum_met: bool,
    ready_to_tally: bool,
    tallied: bool,
}
fn moderation_quarantine_commit_reveal_ballot_status_json(
    quarantine_id_hex: &str,
    ballot: &Value,
) -> Result<(Value, ModerationCommitRevealStatusCounts)> {
    let ballot_obj = value_object(ballot, "commit/reveal ballot status")?;
    let case_id = required_string_field(ballot_obj, "case_id", "commit/reveal ballot status")?;
    let round_id = required_string_field(ballot_obj, "round_id", "commit/reveal ballot status")?;
    let quorum = ballot_obj.get("quorum").and_then(Value::as_u64);
    let juror_count = ballot_obj
        .get("juror_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let committed_count = ballot_obj
        .get("committed_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let revealed_count = ballot_obj
        .get("revealed_count")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let tally_status =
        required_string_field(ballot_obj, "tally_status", "commit/reveal ballot status")?;
    let jurors = ballot_obj
        .get("jurors")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("commit/reveal ballot status is missing `jurors` array"))?;
    let mut missing_commit_jurors = Vec::new();
    let mut missing_reveal_jurors = Vec::new();
    for juror in jurors {
        let juror_obj = value_object(juror, "commit/reveal juror status")?;
        let juror_id = required_string_field(juror_obj, "juror_id", "commit/reveal juror status")?;
        if juror_obj
            .get("needs_commit")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            missing_commit_jurors.push(Value::from(juror_id.to_string()));
        }
        if juror_obj
            .get("needs_reveal")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            missing_reveal_jurors.push(Value::from(juror_id.to_string()));
        }
    }
    let quorum_known = quorum.is_some();
    let commit_quorum_met = quorum.is_some_and(|value| committed_count >= value);
    let reveal_quorum_met = quorum.is_some_and(|value| revealed_count >= value);
    let pending_commit_count = missing_commit_jurors.len() as u64;
    let pending_reveal_count = missing_reveal_jurors.len() as u64;
    let tallied = tally_status == "tallied";
    let (next_action, automation_status, ready_to_tally) = if tallied {
        ("complete", "tallied", false)
    } else if !commit_quorum_met {
        ("collect_commits", "awaiting_commit_quorum", false)
    } else if !reveal_quorum_met {
        ("collect_reveals", "awaiting_reveal_quorum", false)
    } else {
        ("submit_tally", "ready_for_tally", true)
    };
    let mut status = Map::new();
    status.insert("case_id".into(), Value::from(case_id.to_string()));
    status.insert("round_id".into(), Value::from(round_id.to_string()));
    status.insert(
        "quarantine_id_hex".into(),
        Value::from(quarantine_id_hex.to_string()),
    );
    status.insert(
        "quorum".into(),
        ballot_obj.get("quorum").cloned().unwrap_or(Value::Null),
    );
    status.insert("quorum_known".into(), Value::Bool(quorum_known));
    status.insert("juror_count".into(), Value::from(juror_count));
    status.insert("committed_count".into(), Value::from(committed_count));
    status.insert("revealed_count".into(), Value::from(revealed_count));
    status.insert("commit_quorum_met".into(), Value::Bool(commit_quorum_met));
    status.insert("reveal_quorum_met".into(), Value::Bool(reveal_quorum_met));
    status.insert(
        "pending_commit_count".into(),
        Value::from(pending_commit_count),
    );
    status.insert(
        "pending_reveal_count".into(),
        Value::from(pending_reveal_count),
    );
    status.insert(
        "missing_commit_jurors".into(),
        Value::Array(missing_commit_jurors),
    );
    status.insert(
        "missing_reveal_jurors".into(),
        Value::Array(missing_reveal_jurors),
    );
    status.insert("tally_status".into(), Value::from(tally_status.to_string()));
    status.insert("next_action".into(), Value::from(next_action));
    status.insert("automation_status".into(), Value::from(automation_status));
    status.insert("ready_to_tally".into(), Value::Bool(ready_to_tally));
    let tally_request = if ready_to_tally {
        let mut request = Map::new();
        request.insert(
            "route".into(),
            Value::from("/v1/sorafs/moderation/ballots/tally"),
        );
        request.insert(
            "instruction".into(),
            Value::from("FinalizeSorafsModerationCase"),
        );
        request.insert(
            "submission".into(),
            Value::from("caller-signed-native-transaction"),
        );
        request.insert(
            "cli".into(),
            Value::Array(
                [
                    "iroha",
                    "sorafs",
                    "moderation",
                    "ballots",
                    "tally",
                    "--case-id",
                    case_id,
                    "--round-id",
                    round_id,
                ]
                .into_iter()
                .map(Value::from)
                .collect(),
            ),
        );
        Value::Object(request)
    } else {
        Value::Null
    };
    status.insert("tally_request".into(), tally_request);
    status.insert("payload_bytes_included".into(), Value::Bool(false));
    status.insert("private_payloads_included".into(), Value::Bool(false));
    Ok((
        Value::Object(status),
        ModerationCommitRevealStatusCounts {
            pending_commit_count,
            pending_reveal_count,
            commit_quorum_met,
            reveal_quorum_met,
            ready_to_tally,
            tallied,
        },
    ))
}
fn moderation_quarantine_juror_notification_delivery_json(
    quarantine_id_hex: &str,
    case_id: &str,
    round_id: &str,
    ballot_obj: &Map,
    juror_obj: &Map,
    needs_commit: bool,
) -> Result<Value> {
    let juror_id = required_string_field(juror_obj, "juror_id", "juror notification entry")?;
    let notification_status =
        required_string_field(juror_obj, "notification_status", "juror notification entry")?;
    let signed_by = required_string_field(juror_obj, "signed_by", "juror notification entry")?;
    let (action, route_key, cli_key, deadline_field, title_action) = if needs_commit {
        (
            "submit_commit",
            "commit",
            "commit_cli",
            "commit_deadline_unix_ms",
            "commit",
        )
    } else {
        (
            "submit_reveal",
            "reveal",
            "reveal_cli",
            "reveal_deadline_unix_ms",
            "reveal",
        )
    };
    let route = juror_obj
        .get("routes")
        .and_then(Value::as_object)
        .and_then(|routes| routes.get(route_key))
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("juror notification entry is missing `{route_key}` route"))?;
    let cli = juror_obj
        .get(cli_key)
        .cloned()
        .ok_or_else(|| eyre!("juror notification entry is missing `{cli_key}`"))?;
    let delivery_id = moderation_juror_notification_delivery_id(
        quarantine_id_hex,
        case_id,
        round_id,
        juror_id,
        action,
    );
    let deadline = ballot_obj
        .get(deadline_field)
        .cloned()
        .unwrap_or(Value::Null);
    let evidence_uri = ballot_obj
        .get("evidence_uri")
        .cloned()
        .unwrap_or(Value::Null);
    let subject = format!("SoraFS moderation {title_action} required for {case_id}/{round_id}");
    let body = format!(
        "Juror {juror_id} must {title_action} moderation ballot {case_id}/{round_id}. Sign as {signed_by} and submit to {route}. Build any private commit/reveal payload locally; this notification intentionally carries no payload bytes."
    );
    let mut notification = Map::new();
    notification.insert(
        "schema".into(),
        Value::from("sorafs.moderation.juror_notification.v1"),
    );
    notification.insert("delivery_id".into(), Value::from(delivery_id.clone()));
    notification.insert(
        "dedup_key".into(),
        Value::from(format!("sorafs-moderation-juror:{delivery_id}")),
    );
    notification.insert("delivery_status".into(), Value::from("ready_for_delivery"));
    notification.insert("delivery_transport".into(), Value::from("operator-managed"));
    notification.insert(
        "quarantine_id_hex".into(),
        Value::from(quarantine_id_hex.to_string()),
    );
    notification.insert("case_id".into(), Value::from(case_id.to_string()));
    notification.insert("round_id".into(), Value::from(round_id.to_string()));
    notification.insert("juror_id".into(), Value::from(juror_id.to_string()));
    notification.insert("signed_by".into(), Value::from(signed_by.to_string()));
    notification.insert("action".into(), Value::from(action));
    notification.insert(
        "notification_status".into(),
        Value::from(notification_status.to_string()),
    );
    notification.insert("route".into(), Value::from(route.to_string()));
    notification.insert("cli".into(), cli);
    notification.insert("subject".into(), Value::from(subject));
    notification.insert("body".into(), Value::from(body));
    notification.insert("deadline_unix_ms".into(), deadline);
    notification.insert("evidence_uri".into(), evidence_uri);
    notification.insert("payload_bytes_included".into(), Value::Bool(false));
    notification.insert("private_payload_included".into(), Value::Bool(false));
    notification.insert("private_payload_source".into(), Value::from("juror-local"));
    Ok(Value::Object(notification))
}
fn moderation_juror_notification_delivery_id(
    quarantine_id_hex: &str,
    case_id: &str,
    round_id: &str,
    juror_id: &str,
    action: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in [
        "sorafs.moderation.juror_notification.v1",
        quarantine_id_hex,
        case_id,
        round_id,
        juror_id,
        action,
    ] {
        hasher.update(part.as_bytes());
        hasher.update(&[0]);
    }
    encode(hasher.finalize().as_bytes())
}
#[derive(Default)]
struct ModerationJurorPlanCounts {
    notification_count: u64,
    pending_commit_count: u64,
    pending_reveal_count: u64,
}
fn moderation_quarantine_juror_plan_ballot_json(
    ballot: &Value,
) -> Result<(Value, ModerationJurorPlanCounts)> {
    let ballot_obj = value_object(ballot, "operator panel finalized case")?;
    let case = ballot_obj
        .get("case")
        .ok_or_else(|| eyre!("operator panel finalized case is missing `case`"))?;
    let case_obj = value_object(case, "operator panel finalized case record")?;
    let spec = case_obj
        .get("spec")
        .ok_or_else(|| eyre!("operator panel finalized case record is missing `spec`"))?;
    let spec_obj = value_object(spec, "operator panel finalized case spec")?;
    let context = spec_obj
        .get("context")
        .ok_or_else(|| eyre!("operator panel finalized case spec is missing `context`"))?;
    let context_obj = value_object(context, "operator panel finalized case context")?;
    let case_id = required_string_field(
        context_obj,
        "case_id",
        "operator panel finalized case context",
    )?;
    let round_id =
        required_string_field(spec_obj, "round_id", "operator panel finalized case spec")?;
    let juror_values = spec_obj
        .get("jurors")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("operator panel finalized case spec is missing `jurors` array"))?;
    let commits = moderation_juror_ids_from_entries(ballot_obj, "commits")?;
    let reveals = moderation_juror_ids_from_entries(ballot_obj, "reveals")?;
    let mut jurors = Vec::with_capacity(juror_values.len());
    let mut counts = ModerationJurorPlanCounts::default();
    for juror in juror_values {
        let juror_id = juror
            .as_str()
            .ok_or_else(|| eyre!("operator panel ballot juror id must be a string"))?;
        let planned = moderation_quarantine_juror_plan_entry_json(
            case_id, round_id, juror_id, &commits, &reveals,
        )?;
        let planned_obj = value_object(&planned, "juror notification plan entry")?;
        if planned_obj
            .get("needs_commit")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            counts.pending_commit_count = counts.pending_commit_count.saturating_add(1);
        }
        if planned_obj
            .get("needs_reveal")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            counts.pending_reveal_count = counts.pending_reveal_count.saturating_add(1);
        }
        counts.notification_count = counts.notification_count.saturating_add(1);
        jurors.push(planned);
    }
    let mut fields = Map::new();
    fields.insert("case_id".into(), Value::from(case_id.to_string()));
    fields.insert("round_id".into(), Value::from(round_id.to_string()));
    fields.insert(
        "evidence_uri".into(),
        context_obj
            .get("evidence_uri")
            .cloned()
            .unwrap_or(Value::Null),
    );
    fields.insert(
        "quorum".into(),
        spec_obj.get("quorum").cloned().unwrap_or(Value::Null),
    );
    fields.insert(
        "announced_at_unix_ms".into(),
        case_obj
            .get("opened_at_unix_ms")
            .cloned()
            .unwrap_or(Value::Null),
    );
    for field in [
        "commit_deadline_unix_ms",
        "challenge_submission_deadline_unix_ms",
        "challenge_resolution_deadline_unix_ms",
        "reveal_deadline_unix_ms",
    ] {
        fields.insert(
            field.into(),
            spec_obj.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    fields.insert("juror_count".into(), Value::from(juror_values.len() as u64));
    fields.insert("committed_count".into(), Value::from(commits.len() as u64));
    fields.insert("revealed_count".into(), Value::from(reveals.len() as u64));
    fields.insert(
        "tally_status".into(),
        Value::from(
            if ballot_obj
                .get("outcome")
                .is_some_and(|tally| !tally.is_null())
            {
                "tallied"
            } else {
                "pending"
            },
        ),
    );
    fields.insert("jurors".into(), Value::Array(jurors));
    Ok((Value::Object(fields), counts))
}
fn moderation_juror_ids_from_entries(ballot_obj: &Map, field: &str) -> Result<BTreeSet<String>> {
    let mut jurors = BTreeSet::new();
    let Some(entries) = ballot_obj.get(field).and_then(Value::as_array) else {
        return Ok(jurors);
    };
    for entry in entries {
        let entry_obj = value_object(entry, field)?;
        let juror_id = required_string_field(entry_obj, "juror", field)?;
        jurors.insert(juror_id.to_string());
    }
    Ok(jurors)
}
fn moderation_quarantine_juror_plan_entry_json(
    case_id: &str,
    round_id: &str,
    juror_id: &str,
    commits: &BTreeSet<String>,
    reveals: &BTreeSet<String>,
) -> Result<Value> {
    let committed = commits.contains(juror_id);
    let revealed = reveals.contains(juror_id);
    let needs_commit = !committed;
    let needs_reveal = committed && !revealed;
    let mut entry = Map::new();
    entry.insert("juror_id".into(), Value::from(juror_id.to_string()));
    entry.insert("case_id".into(), Value::from(case_id.to_string()));
    entry.insert("round_id".into(), Value::from(round_id.to_string()));
    entry.insert(
        "notification_status".into(),
        Value::from(if revealed {
            "complete"
        } else if committed {
            "reveal_required"
        } else {
            "commit_required"
        }),
    );
    entry.insert(
        "commit_status".into(),
        Value::from(if committed { "accepted" } else { "pending" }),
    );
    entry.insert(
        "reveal_status".into(),
        Value::from(if revealed {
            "accepted"
        } else if committed {
            "pending"
        } else {
            "waiting_for_commit"
        }),
    );
    entry.insert("needs_commit".into(), Value::Bool(needs_commit));
    entry.insert("needs_reveal".into(), Value::Bool(needs_reveal));
    entry.insert("signed_by".into(), Value::from(juror_id.to_string()));
    entry.insert(
        "routes".into(),
        norito::json!({
            "commit": "/v1/sorafs/moderation/ballots/commits",
            "reveal": "/v1/sorafs/moderation/ballots/reveals"
        }),
    );
    entry.insert(
        "commit_cli".into(),
        Value::Array(
            [
                "iroha",
                "sorafs",
                "moderation",
                "ballots",
                "commit",
                "--payload",
                "<commit-payload.json>",
            ]
            .into_iter()
            .map(Value::from)
            .collect(),
        ),
    );
    entry.insert(
        "reveal_cli".into(),
        Value::Array(
            [
                "iroha",
                "sorafs",
                "moderation",
                "ballots",
                "reveal",
                "--payload",
                "<reveal-payload.json>",
            ]
            .into_iter()
            .map(Value::from)
            .collect(),
        ),
    );
    Ok(Value::Object(entry))
}
fn first_moderation_case_reference(cases: &[Value]) -> Option<(&str, &str)> {
    for case in cases {
        let case_obj = case.as_object()?.get("case")?.as_object()?;
        let spec = case_obj.get("spec")?.as_object()?;
        let round_id = spec.get("round_id")?.as_str()?;
        let context = spec.get("context")?.as_object()?;
        let case_id = context.get("case_id")?.as_str()?;
        return Some((case_id, round_id));
    }
    None
}
fn ensure_moderation_bridge_plan_has_no_payload(value: &Value) -> Result<()> {
    fn visit(path: &str, value: &Value) -> Result<()> {
        match value {
            Value::Object(fields) => {
                for (key, child) in fields {
                    let child_path = if path.is_empty() {
                        key.to_string()
                    } else {
                        format!("{path}.{key}")
                    };
                    if key == "payload_b64" {
                        return Err(eyre!(
                            "operator panel response unexpectedly included payload bytes at `{child_path}`"
                        ));
                    }
                    visit(&child_path, child)?;
                }
            }
            Value::Array(values) => {
                for (index, child) in values.iter().enumerate() {
                    visit(&format!("{path}[{index}]"), child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit("", value)
}
fn value_object<'a>(value: &'a Value, context: &str) -> Result<&'a Map> {
    value
        .as_object()
        .ok_or_else(|| eyre!("{context} must be a JSON object"))
}
fn required_string_field<'a>(fields: &'a Map, field: &str, context: &str) -> Result<&'a str> {
    fields
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("{context} is missing string `{field}`"))
}
fn make_http_error(status: StatusCode, body: &[u8]) -> eyre::Report {
    let message = String::from_utf8_lossy(body);
    eyre!("request failed with status {status}: {message}")
}
trait ModerationOperatorWorkflowSource: Send + Sync {
    fn get_operator_panel(
        &self,
        quarantine_id_hex: &str,
        filter: SorafsModerationQuarantineFilter,
    ) -> Result<Response<Vec<u8>>>;
    fn post_review(
        &self,
        _quarantine_id_hex: &str,
        _request: &SorafsModerationQuarantineReviewRequest<'_>,
    ) -> Result<Response<Vec<u8>>> {
        Err(eyre!(
            "SoraFS moderation operator service review forwarding is unavailable"
        ))
    }
    fn post_release(
        &self,
        _quarantine_id_hex: &str,
        _request: &SorafsModerationQuarantineReleaseRequest<'_>,
    ) -> Result<Response<Vec<u8>>> {
        Err(eyre!(
            "SoraFS moderation operator service release forwarding is unavailable"
        ))
    }
    fn post_appeal_handoff(
        &self,
        _quarantine_id_hex: &str,
        _payload: &[u8],
    ) -> Result<Response<Vec<u8>>> {
        Err(eyre!(
            "SoraFS moderation operator service appeal-handoff forwarding is unavailable"
        ))
    }
}
impl ModerationOperatorWorkflowSource for Client {
    fn get_operator_panel(
        &self,
        quarantine_id_hex: &str,
        filter: SorafsModerationQuarantineFilter,
    ) -> Result<Response<Vec<u8>>> {
        self.get_sorafs_moderation_quarantine_operator_panel(quarantine_id_hex, filter)
    }
    fn post_review(
        &self,
        quarantine_id_hex: &str,
        request: &SorafsModerationQuarantineReviewRequest<'_>,
    ) -> Result<Response<Vec<u8>>> {
        self.post_sorafs_moderation_quarantine_review(quarantine_id_hex, request)
    }
    fn post_release(
        &self,
        quarantine_id_hex: &str,
        request: &SorafsModerationQuarantineReleaseRequest<'_>,
    ) -> Result<Response<Vec<u8>>> {
        self.post_sorafs_moderation_quarantine_release(quarantine_id_hex, request)
    }
    fn post_appeal_handoff(
        &self,
        quarantine_id_hex: &str,
        payload: &[u8],
    ) -> Result<Response<Vec<u8>>> {
        self.post_sorafs_moderation_quarantine_appeal_handoff_json(quarantine_id_hex, payload)
    }
}
struct ModerationOperatorService {
    listen: String,
    default_limit: Option<u32>,
    max_body_bytes: usize,
    upstream: String,
    default_actor: String,
    csrf_token: String,
    workflow_source: Arc<dyn ModerationOperatorWorkflowSource>,
}
impl ModerationOperatorService {
    const HTML_CONTENT_TYPE: &'static str = "text/html; charset=utf-8";
    const JSON_CONTENT_TYPE: &'static str = "application/json";
    fn status_json(&self) -> Value {
        let mut fields = Map::new();
        fields.insert(
            "schema".into(),
            Value::from("sorafs.moderation.quarantine.operator_service.status.v1"),
        );
        fields.insert("status".into(), Value::from("listening"));
        fields.insert("source".into(), Value::from("iroha_cli"));
        fields.insert("listen".into(), Value::from(self.listen.clone()));
        fields.insert("upstream".into(), Value::from(self.upstream.clone()));
        fields.insert(
            "default_actor".into(),
            Value::from(self.default_actor.clone()),
        );
        fields.insert(
            "default_limit".into(),
            self.default_limit.map_or(Value::Null, Value::from),
        );
        fields.insert(
            "max_body_bytes".into(),
            Value::from(u64::try_from(self.max_body_bytes).unwrap_or(u64::MAX)),
        );
        fields.insert(
            "csrf_header".into(),
            Value::from(MODERATION_OPERATOR_CSRF_HEADER),
        );
        fields.insert("csrf_token".into(), Value::from(self.csrf_token.clone()));
        fields.insert("payload_bytes_included".into(), Value::Bool(false));
        fields.insert(
            "routes".into(),
            Value::Array(vec![
                Value::from("/"),
                Value::from("/healthz"),
                Value::from("/v1/sorafs/moderation/operator-panel/ui"),
                Value::from("/v1/sorafs/moderation/operator-panel/status"),
                Value::from("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/operator-panel"),
                Value::from("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/bridge-plan"),
                Value::from("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/juror-plan"),
                Value::from(
                    "/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/juror-notifications",
                ),
                Value::from(
                    "/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/commit-reveal-status",
                ),
                Value::from("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/review"),
                Value::from("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/release"),
                Value::from("/v1/sorafs/moderation/quarantine/{quarantine_id_hex}/appeal-handoff"),
            ]),
        );
        Value::Object(fields)
    }
    fn handle_request(
        &self,
        request: &ModerationOperatorHttpRequest<'_>,
    ) -> ModerationOperatorHttpResponse {
        let route = match moderation_operator_route(request.path) {
            Ok(route) => route,
            Err(err) => return err.into_response(),
        };
        match route {
            ModerationOperatorRoute::BrowserUi => {
                if let Err(err) = moderation_operator_expect_method(request, "GET", false) {
                    return err.into_response();
                }
                self.browser_ui_response()
            }
            ModerationOperatorRoute::Status => {
                if let Err(err) = moderation_operator_expect_method(request, "GET", false) {
                    return err.into_response();
                }
                moderation_operator_json_response(StatusCode::OK, &self.status_json())
            }
            ModerationOperatorRoute::OperatorPanel { quarantine_id_hex } => {
                if let Err(err) = moderation_operator_expect_method(request, "GET", false) {
                    return err.into_response();
                }
                let limit = match moderation_operator_query_limit(request.query, self.default_limit)
                {
                    Ok(limit) => limit,
                    Err(err) => return err.into_response(),
                };
                self.operator_panel_response(&quarantine_id_hex, limit)
            }
            ModerationOperatorRoute::BridgePlan { quarantine_id_hex } => {
                if let Err(err) = moderation_operator_expect_method(request, "GET", false) {
                    return err.into_response();
                }
                let limit = match moderation_operator_query_limit(request.query, self.default_limit)
                {
                    Ok(limit) => limit,
                    Err(err) => return err.into_response(),
                };
                self.bridge_plan_response(&quarantine_id_hex, limit)
            }
            ModerationOperatorRoute::JurorPlan { quarantine_id_hex } => {
                if let Err(err) = moderation_operator_expect_method(request, "GET", false) {
                    return err.into_response();
                }
                let limit = match moderation_operator_query_limit(request.query, self.default_limit)
                {
                    Ok(limit) => limit,
                    Err(err) => return err.into_response(),
                };
                self.juror_plan_response(&quarantine_id_hex, limit)
            }
            ModerationOperatorRoute::JurorNotifications { quarantine_id_hex } => {
                if let Err(err) = moderation_operator_expect_method(request, "GET", false) {
                    return err.into_response();
                }
                let limit = match moderation_operator_query_limit(request.query, self.default_limit)
                {
                    Ok(limit) => limit,
                    Err(err) => return err.into_response(),
                };
                self.juror_notifications_response(&quarantine_id_hex, limit)
            }
            ModerationOperatorRoute::CommitRevealStatus { quarantine_id_hex } => {
                if let Err(err) = moderation_operator_expect_method(request, "GET", false) {
                    return err.into_response();
                }
                let limit = match moderation_operator_query_limit(request.query, self.default_limit)
                {
                    Ok(limit) => limit,
                    Err(err) => return err.into_response(),
                };
                self.commit_reveal_status_response(&quarantine_id_hex, limit)
            }
            ModerationOperatorRoute::Review { quarantine_id_hex } => {
                if let Err(err) = moderation_operator_expect_method(request, "POST", true)
                    .and_then(|_| moderation_operator_reject_query(request.query))
                    .and_then(|_| self.require_csrf_token(request))
                {
                    return err.into_response();
                }
                self.review_response(&quarantine_id_hex, request.body)
            }
            ModerationOperatorRoute::Release { quarantine_id_hex } => {
                if let Err(err) = moderation_operator_expect_method(request, "POST", true)
                    .and_then(|_| moderation_operator_reject_query(request.query))
                    .and_then(|_| self.require_csrf_token(request))
                {
                    return err.into_response();
                }
                self.release_response(&quarantine_id_hex, request.body)
            }
            ModerationOperatorRoute::AppealHandoff { quarantine_id_hex } => {
                if let Err(err) = moderation_operator_expect_method(request, "POST", true)
                    .and_then(|_| moderation_operator_reject_query(request.query))
                    .and_then(|_| self.require_csrf_token(request))
                {
                    return err.into_response();
                }
                self.appeal_handoff_response(&quarantine_id_hex, request.body)
            }
        }
    }
    fn require_csrf_token(
        &self,
        request: &ModerationOperatorHttpRequest<'_>,
    ) -> Result<(), ModerationOperatorRequestError> {
        let mut values = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(MODERATION_OPERATOR_CSRF_HEADER))
            .map(|(_, value)| *value);
        let Some(value) = values.next() else {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::FORBIDDEN,
                format!(
                    "SoraFS moderation operator service mutation routes require `{MODERATION_OPERATOR_CSRF_HEADER}`"
                ),
            ));
        };
        if values.next().is_some() {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::FORBIDDEN,
                format!(
                    "SoraFS moderation operator service request must include only one `{MODERATION_OPERATOR_CSRF_HEADER}`"
                ),
            ));
        }
        if value != self.csrf_token {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::FORBIDDEN,
                "invalid SoraFS moderation operator service CSRF token",
            ));
        }
        Ok(())
    }
    fn operator_panel_body(
        &self,
        quarantine_id_hex: &str,
        limit: Option<u32>,
    ) -> std::result::Result<Vec<u8>, ModerationOperatorHttpResponse> {
        let response = match self.workflow_source.get_operator_panel(
            quarantine_id_hex,
            SorafsModerationQuarantineFilter { limit },
        ) {
            Ok(response) => response,
            Err(err) => {
                return Err(moderation_operator_json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("failed to fetch operator-panel response from Torii: {err}"),
                ));
            }
        };
        let status = response.status();
        let body = response.into_body();
        if status != StatusCode::OK {
            return Err(moderation_operator_upstream_response(status, body));
        }
        Ok(body)
    }
    fn operator_panel_response(
        &self,
        quarantine_id_hex: &str,
        limit: Option<u32>,
    ) -> ModerationOperatorHttpResponse {
        let body = match self.operator_panel_body(quarantine_id_hex, limit) {
            Ok(body) => body,
            Err(response) => return response,
        };
        match moderation_operator_payload_free_panel_json(&body) {
            Ok(panel) => moderation_operator_json_response(StatusCode::OK, &panel),
            Err(err) => moderation_operator_json_error(
                StatusCode::BAD_GATEWAY,
                format!("unsafe or invalid operator-panel response from Torii: {err}"),
            ),
        }
    }
    impl_moderation_operator_derived_response!(
        bridge_plan_response => moderation_quarantine_bridge_plan_json,
        plan,
        "failed to build payload-free bridge plan: {err}"
    );
    impl_moderation_operator_derived_response!(
        juror_plan_response => moderation_quarantine_juror_plan_json,
        plan,
        "failed to build payload-free juror notification plan: {err}"
    );
    impl_moderation_operator_derived_response!(
        commit_reveal_status_response => moderation_quarantine_commit_reveal_status_json,
        status,
        "failed to build payload-free commit/reveal coordination status: {err}"
    );
    impl_moderation_operator_derived_response!(
        juror_notifications_response => moderation_quarantine_juror_notifications_json,
        notifications,
        "failed to build payload-free juror notification delivery manifest: {err}"
    );
    fn review_response(
        &self,
        quarantine_id_hex: &str,
        body: &[u8],
    ) -> ModerationOperatorHttpResponse {
        let payload = match moderation_operator_review_payload_from_body(body, &self.default_actor)
        {
            Ok(payload) => payload,
            Err(err) => return err.into_response(),
        };
        let request = payload.as_request();
        let response = match self
            .workflow_source
            .post_review(quarantine_id_hex, &request)
        {
            Ok(response) => response,
            Err(err) => {
                return moderation_operator_json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("failed to forward review request to Torii: {err}"),
                );
            }
        };
        moderation_operator_success_json_response(response, "review")
    }
    fn release_response(
        &self,
        quarantine_id_hex: &str,
        body: &[u8],
    ) -> ModerationOperatorHttpResponse {
        let payload = match moderation_operator_release_payload_from_body(body, &self.default_actor)
        {
            Ok(payload) => payload,
            Err(err) => return err.into_response(),
        };
        let request = payload.as_request();
        let response = match self
            .workflow_source
            .post_release(quarantine_id_hex, &request)
        {
            Ok(response) => response,
            Err(err) => {
                return moderation_operator_json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("failed to forward release request to Torii: {err}"),
                );
            }
        };
        moderation_operator_success_json_response(response, "release")
    }
    fn appeal_handoff_response(
        &self,
        quarantine_id_hex: &str,
        body: &[u8],
    ) -> ModerationOperatorHttpResponse {
        let payload =
            match moderation_operator_payload_free_json_body(body, "appeal-handoff request") {
                Ok(payload) => payload,
                Err(err) => return err.into_response(),
            };
        let response = match self
            .workflow_source
            .post_appeal_handoff(quarantine_id_hex, &payload)
        {
            Ok(response) => response,
            Err(err) => {
                return moderation_operator_json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("failed to forward appeal-handoff request to Torii: {err}"),
                );
            }
        };
        moderation_operator_success_json_response(response, "appeal-handoff")
    }
    fn browser_ui_response(&self) -> ModerationOperatorHttpResponse {
        let html = MODERATION_OPERATOR_BROWSER_UI_HTML
            .replace(
                "__SORAFS_OPERATOR_CSRF_HEADER__",
                MODERATION_OPERATOR_CSRF_HEADER,
            )
            .replace("__SORAFS_OPERATOR_CSRF_TOKEN__", &self.csrf_token);
        ModerationOperatorHttpResponse {
            status: StatusCode::OK,
            content_type: Self::HTML_CONTENT_TYPE,
            body: html.into_bytes(),
        }
    }
}
const MODERATION_OPERATOR_BROWSER_UI_HTML: &str =
    include_str!("sorafs/moderation_operator_browser_ui.v1.html");
#[derive(Debug)]
struct ModerationOperatorHttpRequest<'a> {
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    headers: Vec<(&'a str, &'a str)>,
    body: &'a [u8],
}
#[derive(Debug)]
struct ModerationOperatorHttpResponse {
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
}
impl ModerationOperatorHttpResponse {
    fn to_http_bytes(&self) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.status.as_u16(),
            moderation_operator_status_reason(self.status),
            self.content_type,
            self.body.len()
        )
        .into_bytes();
        response.extend_from_slice(&self.body);
        response
    }
}
#[derive(Debug)]
struct ModerationOperatorRequestError {
    status: StatusCode,
    message: String,
}
impl ModerationOperatorRequestError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn into_response(self) -> ModerationOperatorHttpResponse {
        moderation_operator_json_error(self.status, self.message)
    }
}
#[derive(Debug, PartialEq, Eq)]
enum ModerationOperatorRoute {
    BrowserUi,
    Status,
    OperatorPanel { quarantine_id_hex: String },
    BridgePlan { quarantine_id_hex: String },
    JurorPlan { quarantine_id_hex: String },
    JurorNotifications { quarantine_id_hex: String },
    CommitRevealStatus { quarantine_id_hex: String },
    Review { quarantine_id_hex: String },
    Release { quarantine_id_hex: String },
    AppealHandoff { quarantine_id_hex: String },
}
fn moderation_operator_handle_stream(
    mut stream: TcpStream,
    service: &ModerationOperatorService,
) -> Result<()> {
    let response = match moderation_operator_read_http_request(&mut stream, service.max_body_bytes)
    {
        Ok(raw) => match moderation_operator_parse_http_request(&raw, service.max_body_bytes) {
            Ok(request) => service.handle_request(&request),
            Err(err) => err.into_response(),
        },
        Err(err) => err.into_response(),
    };
    stream
        .write_all(&response.to_http_bytes())
        .wrap_err("failed to write SoraFS moderation operator service response")?;
    stream
        .flush()
        .wrap_err("failed to flush SoraFS moderation operator service response")
}
fn moderation_operator_read_http_request(
    stream: &mut TcpStream,
    max_body_bytes: usize,
) -> Result<Vec<u8>, ModerationOperatorRequestError> {
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(header_end) = moderation_operator_find_header_end(&buffer) {
            break header_end;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                "SoraFS moderation operator service request headers are too large",
            ));
        }
        let read = stream.read(&mut chunk).map_err(|err| {
            ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                format!("failed to read SoraFS moderation operator service request: {err}"),
            )
        })?;
        if read == 0 {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                "connection closed before HTTP request headers were complete",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let header_text = moderation_operator_header_text(&buffer, header_end)?;
    let content_length = moderation_operator_content_length(header_text)?;
    if content_length.is_none() && buffer.len() > header_end {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request body requires Content-Length",
        ));
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > max_body_bytes {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "SoraFS moderation operator service request body exceeds {max_body_bytes} bytes"
            ),
        ));
    }
    let request_len = header_end.checked_add(content_length).ok_or_else(|| {
        ModerationOperatorRequestError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SoraFS moderation operator service request length overflowed",
        )
    })?;
    while buffer.len() < request_len {
        let read = stream.read(&mut chunk).map_err(|err| {
            ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                format!("failed to read SoraFS moderation operator service request body: {err}"),
            )
        })?;
        if read == 0 {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                "connection closed before HTTP request body was complete",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    if buffer.len() > request_len {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request has trailing bytes after declared body",
        ));
    }
    buffer.truncate(request_len);
    Ok(buffer)
}
fn moderation_operator_parse_http_request(
    raw: &[u8],
    max_body_bytes: usize,
) -> Result<ModerationOperatorHttpRequest<'_>, ModerationOperatorRequestError> {
    let header_end = moderation_operator_find_header_end(raw).ok_or_else(|| {
        ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request is missing HTTP header terminator",
        )
    })?;
    let header_text = moderation_operator_header_text(raw, header_end)?;
    let mut lines = header_text.lines();
    let request_line = lines.next().ok_or_else(|| {
        ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request line is missing",
        )
    })?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or_else(|| {
        ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request method is missing",
        )
    })?;
    let target = request_parts.next().ok_or_else(|| {
        ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request target is missing",
        )
    })?;
    let version = request_parts.next().ok_or_else(|| {
        ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service HTTP version is missing",
        )
    })?;
    if request_parts.next().is_some() || !version.starts_with("HTTP/") {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request line is malformed",
        ));
    }
    let content_length = moderation_operator_content_length(header_text)?;
    if method == "POST" && content_length.is_none() {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service POST request requires Content-Length",
        ));
    }
    if content_length.is_none() && raw.len() > header_end {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request body requires Content-Length",
        ));
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > max_body_bytes {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "SoraFS moderation operator service request body exceeds {max_body_bytes} bytes"
            ),
        ));
    }
    let body_end = header_end.checked_add(content_length).ok_or_else(|| {
        ModerationOperatorRequestError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SoraFS moderation operator service request length overflowed",
        )
    })?;
    if raw.len() < body_end {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request body is incomplete",
        ));
    }
    if raw.len() > body_end {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request has trailing bytes after declared body",
        ));
    }
    let headers = moderation_operator_headers(header_text);
    let (path, query) = moderation_operator_split_target(target)?;
    Ok(ModerationOperatorHttpRequest {
        method,
        path,
        query,
        headers,
        body: &raw[header_end..body_end],
    })
}
fn moderation_operator_header_text(
    raw: &[u8],
    header_end: usize,
) -> Result<&str, ModerationOperatorRequestError> {
    let header_bytes = raw.get(..header_end.saturating_sub(4)).ok_or_else(|| {
        ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request headers are malformed",
        )
    })?;
    std::str::from_utf8(header_bytes).map_err(|err| {
        ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            format!("SoraFS moderation operator service headers are not UTF-8: {err}"),
        )
    })
}
fn moderation_operator_content_length(
    header_text: &str,
) -> Result<Option<usize>, ModerationOperatorRequestError> {
    let mut content_length = None;
    for line in header_text.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ModerationOperatorRequestError::new(
                    StatusCode::BAD_REQUEST,
                    "SoraFS moderation operator service request has duplicate Content-Length",
                ));
            }
            let parsed = value.trim().parse::<usize>().map_err(|err| {
                ModerationOperatorRequestError::new(
                    StatusCode::BAD_REQUEST,
                    format!("invalid SoraFS moderation operator service Content-Length: {err}"),
                )
            })?;
            content_length = Some(parsed);
        }
    }
    Ok(content_length)
}
fn moderation_operator_headers(header_text: &str) -> Vec<(&str, &str)> {
    header_text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim(), value.trim()))
        })
        .collect()
}
fn moderation_operator_split_target(
    target: &str,
) -> Result<(&str, Option<&str>), ModerationOperatorRequestError> {
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    if !path.starts_with('/') {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service request path must be absolute",
        ));
    }
    Ok((path, query))
}
fn moderation_operator_find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
}
fn moderation_operator_route(
    path: &str,
) -> Result<ModerationOperatorRoute, ModerationOperatorRequestError> {
    if path == "/" || path == "/v1/sorafs/moderation/operator-panel/ui" {
        return Ok(ModerationOperatorRoute::BrowserUi);
    }
    if path == "/healthz" || path == "/v1/sorafs/moderation/operator-panel/status" {
        return Ok(ModerationOperatorRoute::Status);
    }
    const PREFIX: &str = "/v1/sorafs/moderation/quarantine/";
    let Some(remainder) = path.strip_prefix(PREFIX) else {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::NOT_FOUND,
            "unknown SoraFS moderation operator service route",
        ));
    };
    let Some((quarantine_id, suffix)) = remainder.split_once('/') else {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::NOT_FOUND,
            "SoraFS moderation operator service route is missing a workflow endpoint",
        ));
    };
    if suffix.contains('/') {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::NOT_FOUND,
            "unknown SoraFS moderation operator service workflow endpoint",
        ));
    }
    let quarantine_id_hex =
        normalize_hex_digest::<16>(quarantine_id, "quarantine id in request path").map_err(
            |err| ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string()),
        )?;
    match suffix {
        "operator-panel" => Ok(ModerationOperatorRoute::OperatorPanel { quarantine_id_hex }),
        "bridge-plan" => Ok(ModerationOperatorRoute::BridgePlan { quarantine_id_hex }),
        "juror-plan" => Ok(ModerationOperatorRoute::JurorPlan { quarantine_id_hex }),
        "juror-notifications" => {
            Ok(ModerationOperatorRoute::JurorNotifications { quarantine_id_hex })
        }
        "commit-reveal-status" => {
            Ok(ModerationOperatorRoute::CommitRevealStatus { quarantine_id_hex })
        }
        "review" => Ok(ModerationOperatorRoute::Review { quarantine_id_hex }),
        "release" => Ok(ModerationOperatorRoute::Release { quarantine_id_hex }),
        "appeal-handoff" => Ok(ModerationOperatorRoute::AppealHandoff { quarantine_id_hex }),
        _ => Err(ModerationOperatorRequestError::new(
            StatusCode::NOT_FOUND,
            "unknown SoraFS moderation operator service workflow endpoint",
        )),
    }
}
fn moderation_operator_expect_method(
    request: &ModerationOperatorHttpRequest<'_>,
    expected_method: &str,
    body_required: bool,
) -> Result<(), ModerationOperatorRequestError> {
    if request.method != expected_method {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            format!("SoraFS moderation operator service route requires {expected_method}"),
        ));
    }
    if body_required {
        if request.body.is_empty() {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                "SoraFS moderation operator service POST request body must not be empty",
            ));
        }
    } else if !request.body.is_empty() {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service GET requests must not include a body",
        ));
    }
    Ok(())
}
fn moderation_operator_reject_query(
    query: Option<&str>,
) -> Result<(), ModerationOperatorRequestError> {
    if query.is_some_and(|query| !query.is_empty()) {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "SoraFS moderation operator service mutation routes do not accept query parameters",
        ));
    }
    Ok(())
}
fn moderation_operator_query_limit(
    query: Option<&str>,
    default_limit: Option<u32>,
) -> Result<Option<u32>, ModerationOperatorRequestError> {
    let Some(query) = query else {
        return Ok(default_limit);
    };
    let mut limit = default_limit;
    let mut saw_limit = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key != "limit" {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                format!("unsupported SoraFS moderation operator service query parameter `{key}`"),
            ));
        }
        if saw_limit {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                "SoraFS moderation operator service query parameter `limit` was repeated",
            ));
        }
        if value.is_empty() {
            return Err(ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                "SoraFS moderation operator service query parameter `limit` must not be empty",
            ));
        }
        let parsed = value.parse::<u32>().map_err(|err| {
            ModerationOperatorRequestError::new(
                StatusCode::BAD_REQUEST,
                format!("invalid SoraFS moderation operator service `limit`: {err}"),
            )
        })?;
        limit = Some(parsed);
        saw_limit = true;
    }
    Ok(limit)
}
fn moderation_operator_payload_free_panel_json(body: &[u8]) -> Result<Value> {
    let panel: Value =
        norito::json::from_slice(body).wrap_err("failed to decode operator-panel JSON")?;
    ensure_moderation_bridge_plan_has_no_payload(&panel)?;
    Ok(panel)
}
struct ModerationOperatorReviewPayload {
    reviewed_by: String,
    reviewed_at_unix: Option<u64>,
    notes: Option<String>,
}
impl ModerationOperatorReviewPayload {
    fn as_request(&self) -> SorafsModerationQuarantineReviewRequest<'_> {
        SorafsModerationQuarantineReviewRequest {
            reviewed_by: self.reviewed_by.as_str(),
            reviewed_at_unix: self.reviewed_at_unix,
            notes: self.notes.as_deref(),
        }
    }
}
struct ModerationOperatorReleasePayload {
    release_authority: String,
    released_at_unix: Option<u64>,
    notes: Option<String>,
}
impl ModerationOperatorReleasePayload {
    fn as_request(&self) -> SorafsModerationQuarantineReleaseRequest<'_> {
        SorafsModerationQuarantineReleaseRequest {
            release_authority: self.release_authority.as_str(),
            released_at_unix: self.released_at_unix,
            notes: self.notes.as_deref(),
        }
    }
}
fn moderation_operator_review_payload_from_body(
    body: &[u8],
    default_actor: &str,
) -> Result<ModerationOperatorReviewPayload, ModerationOperatorRequestError> {
    let value = moderation_operator_payload_free_json_value(body, "review request")?;
    let fields = value_object(&value, "review request").map_err(|err| {
        ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string())
    })?;
    let reviewed_by = optional_json_text(fields, "reviewed_by")
        .map_err(|err| {
            ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string())
        })?
        .unwrap_or_else(|| default_actor.to_string());
    let reviewed_at_unix = optional_json_u64(fields, "reviewed_at_unix").map_err(|err| {
        ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string())
    })?;
    if reviewed_at_unix == Some(0) {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "reviewed_at_unix must be non-zero",
        ));
    }
    let notes = optional_json_text(fields, "notes").map_err(|err| {
        ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string())
    })?;
    Ok(ModerationOperatorReviewPayload {
        reviewed_by,
        reviewed_at_unix,
        notes,
    })
}
fn moderation_operator_release_payload_from_body(
    body: &[u8],
    default_actor: &str,
) -> Result<ModerationOperatorReleasePayload, ModerationOperatorRequestError> {
    let value = moderation_operator_payload_free_json_value(body, "release request")?;
    let fields = value_object(&value, "release request").map_err(|err| {
        ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string())
    })?;
    let release_authority = optional_json_text(fields, "release_authority")
        .map_err(|err| {
            ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string())
        })?
        .unwrap_or_else(|| default_actor.to_string());
    let released_at_unix = optional_json_u64(fields, "released_at_unix").map_err(|err| {
        ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string())
    })?;
    if released_at_unix == Some(0) {
        return Err(ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            "released_at_unix must be non-zero",
        ));
    }
    let notes = optional_json_text(fields, "notes").map_err(|err| {
        ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string())
    })?;
    Ok(ModerationOperatorReleasePayload {
        release_authority,
        released_at_unix,
        notes,
    })
}
fn moderation_operator_payload_free_json_body(
    body: &[u8],
    label: &str,
) -> Result<Vec<u8>, ModerationOperatorRequestError> {
    let value = moderation_operator_payload_free_json_value(body, label)?;
    norito::json::to_vec(&value).map_err(|err| {
        ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            format!("failed to canonicalize SoraFS moderation operator service {label}: {err}"),
        )
    })
}
fn moderation_operator_payload_free_json_value(
    body: &[u8],
    label: &str,
) -> Result<Value, ModerationOperatorRequestError> {
    let value: Value = norito::json::from_slice(body).map_err(|err| {
        ModerationOperatorRequestError::new(
            StatusCode::BAD_REQUEST,
            format!("failed to parse SoraFS moderation operator service {label} JSON: {err}"),
        )
    })?;
    ensure_moderation_bridge_plan_has_no_payload(&value).map_err(|err| {
        ModerationOperatorRequestError::new(StatusCode::BAD_REQUEST, err.to_string())
    })?;
    Ok(value)
}
fn moderation_operator_success_json_response(
    response: Response<Vec<u8>>,
    operation: &str,
) -> ModerationOperatorHttpResponse {
    let status = response.status();
    let body = response.into_body();
    if !matches!(status, StatusCode::OK | StatusCode::ACCEPTED) {
        return moderation_operator_upstream_response(status, body);
    }
    match moderation_operator_payload_free_json_value(&body, operation) {
        Ok(value) => moderation_operator_json_response(status, &value),
        Err(err) => moderation_operator_json_error(
            StatusCode::BAD_GATEWAY,
            format!(
                "unsafe or invalid {operation} response from Torii: {}",
                err.message
            ),
        ),
    }
}
fn moderation_operator_upstream_response(
    status: StatusCode,
    body: Vec<u8>,
) -> ModerationOperatorHttpResponse {
    if body.is_empty() {
        moderation_operator_json_error(status, format!("Torii returned status {status}"))
    } else {
        ModerationOperatorHttpResponse {
            status,
            content_type: ModerationOperatorService::JSON_CONTENT_TYPE,
            body,
        }
    }
}
fn moderation_operator_json_response(
    status: StatusCode,
    value: &Value,
) -> ModerationOperatorHttpResponse {
    let body = norito::json::to_vec(value).unwrap_or_else(|_| {
        br#"{"schema":"sorafs.moderation.quarantine.operator_service.error.v1","error":"failed to encode SoraFS moderation operator service JSON"}"#.to_vec()
    });
    ModerationOperatorHttpResponse {
        status,
        content_type: ModerationOperatorService::JSON_CONTENT_TYPE,
        body,
    }
}
fn moderation_operator_json_error(
    status: StatusCode,
    message: impl Into<String>,
) -> ModerationOperatorHttpResponse {
    let message = message.into();
    moderation_operator_json_response(
        status,
        &norito::json!({
            "schema": "sorafs.moderation.quarantine.operator_service.error.v1",
            "error": (message)
        }),
    )
}
fn moderation_operator_status_reason(status: StatusCode) -> &'static str {
    match status {
        StatusCode::OK => "OK",
        StatusCode::ACCEPTED => "Accepted",
        StatusCode::BAD_REQUEST => "Bad Request",
        StatusCode::UNAUTHORIZED => "Unauthorized",
        StatusCode::FORBIDDEN => "Forbidden",
        StatusCode::NOT_FOUND => "Not Found",
        StatusCode::METHOD_NOT_ALLOWED => "Method Not Allowed",
        StatusCode::PAYLOAD_TOO_LARGE => "Payload Too Large",
        StatusCode::BAD_GATEWAY => "Bad Gateway",
        StatusCode::INTERNAL_SERVER_ERROR => "Internal Server Error",
        _ => "Status",
    }
}
fn normalize_hex_lower(value: &str, flag: &str, byte_len: usize) -> Result<String> {
    let trimmed = required_trimmed_text(value, flag)?;
    let hex_value = trimmed.strip_prefix("0x").unwrap_or(&trimmed);
    let bytes = decode(hex_value)
        .wrap_err_with(|| format!("{flag} must be a {byte_len}-byte hex string"))?;
    if bytes.len() != byte_len {
        return Err(eyre!("{flag} must be a {byte_len}-byte hex string"));
    }
    Ok(encode(bytes))
}
fn normalize_hex_16_lower(value: &str, flag: &str) -> Result<String> {
    normalize_hex_lower(value, flag, 16)
}
fn parse_xor_quantity(input: &str) -> Result<XorQuantity> {
    parse_xor_quantity_labeled(input, "reserve balance")
}
fn parse_xor_quantity_labeled(input: &str, label: &str) -> Result<XorQuantity> {
    if input.is_empty() {
        return Err(eyre!("{label} must not be empty"));
    }
    let amount = input
        .parse::<XorQuantity>()
        .wrap_err_with(|| format!("failed to parse {label} as a canonical XOR quantity"))?;
    let canonical = amount.to_string();
    if canonical != input {
        return Err(eyre!(
            "{label} must use the canonical XOR decimal `{canonical}`"
        ));
    }
    Ok(amount)
}
fn load_reserve_policy_from_paths(
    json_path: Option<&Path>,
    norito_path: Option<&Path>,
) -> Result<(ReservePolicyV1, String)> {
    match (json_path, norito_path) {
        (Some(_), Some(_)) => Err(eyre!(
            "only one of --policy-json or --policy-norito may be supplied"
        )),
        (Some(path), None) => {
            let contents = fs::read_to_string(path).wrap_err_with(|| {
                format!("failed to read reserve policy JSON `{}`", path.display())
            })?;
            let policy: ReservePolicyV1 = norito::json::from_str(&contents)
                .wrap_err("failed to parse reserve policy JSON")?;
            Ok((policy, format!("policy JSON `{}`", path.display())))
        }
        (None, Some(path)) => {
            let bytes = fs::read(path).wrap_err_with(|| {
                format!("failed to read reserve policy Norito `{}`", path.display())
            })?;
            let policy = decode_from_bytes::<ReservePolicyV1>(&bytes)
                .wrap_err("failed to decode reserve policy Norito bytes")?;
            Ok((policy, format!("policy Norito `{}`", path.display())))
        }
        (None, None) => Ok((
            ReservePolicyV1::default(),
            "embedded default policy".to_string(),
        )),
    }
}
#[allow(clippy::too_many_arguments)]
fn build_reserve_quote_value(
    policy: &ReservePolicyV1,
    storage_class: StorageClass,
    tier: ReserveTier,
    duration: ReserveDuration,
    capacity_gib: u64,
    reserve_balance: &XorQuantity,
    quote: &ReserveQuote,
    policy_source: &str,
) -> Result<Value> {
    let mut root = Map::new();
    root.insert(
        "policy_source".into(),
        Value::from(policy_source.to_string()),
    );
    let mut inputs = Map::new();
    inputs.insert(
        "storage_class".into(),
        Value::from(storage_class_label(storage_class)),
    );
    inputs.insert("tier".into(), Value::from(reserve_tier_label(tier)));
    inputs.insert(
        "duration".into(),
        Value::from(reserve_duration_label(duration)),
    );
    inputs.insert(
        "capacity_gib".into(),
        Value::Number(Number::from(capacity_gib)),
    );
    let reserve_value =
        norito::json::to_value(reserve_balance).wrap_err("serialize reserve balance to JSON")?;
    inputs.insert("reserve_balance".into(), reserve_value);
    root.insert("inputs".into(), Value::Object(inputs));
    let policy_value =
        norito::json::to_value(policy).wrap_err("serialize reserve policy to JSON")?;
    root.insert("policy".into(), policy_value);
    let quote_value = norito::json::to_value(quote).wrap_err("serialize reserve quote to JSON")?;
    root.insert("quote".into(), quote_value);
    let projection = quote
        .ledger_projection()
        .wrap_err("failed to compute reserve ledger projection")?;
    let projection_value = norito::json::to_value(&projection)
        .wrap_err("serialize reserve ledger projection to JSON")?;
    root.insert("ledger_projection".into(), projection_value);
    Ok(Value::Object(root))
}
fn write_reserve_quote_artifact(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).wrap_err_with(|| {
            format!(
                "failed to create reserve quote artifact directory `{}`",
                parent.display()
            )
        })?;
    }
    let rendered =
        norito::json::to_json_pretty(value).wrap_err("failed to render reserve quote artifact")?;
    fs::write(path, rendered).wrap_err_with(|| {
        format!(
            "failed to write reserve quote artifact `{}`",
            path.display()
        )
    })
}
#[derive(Clone)]
struct LedgerProjectionAmounts {
    rent_due: XorQuantity,
    reserve_shortfall: XorQuantity,
    top_up_shortfall: XorQuantity,
}
fn extract_ledger_projection(value: &Value) -> Result<LedgerProjectionAmounts> {
    let root = value
        .as_object()
        .ok_or_else(|| eyre!("reserve quote must be a JSON object"))?;
    let ledger_value = root
        .get("ledger_projection")
        .ok_or_else(|| eyre!("reserve quote missing `ledger_projection` block"))?;
    let projection: ReserveLedgerProjection = norito::json::from_value(ledger_value.clone())
        .wrap_err("failed to parse reserve ledger projection from quote")?;
    Ok(LedgerProjectionAmounts {
        rent_due: projection.rent_due,
        reserve_shortfall: projection.reserve_shortfall,
        top_up_shortfall: projection.top_up_shortfall,
    })
}
fn extract_reserve_quote(value: &Value) -> Result<ReserveQuote> {
    let root = value
        .as_object()
        .ok_or_else(|| eyre!("reserve quote must be a JSON object"))?;
    let quote_value = root
        .get("quote")
        .ok_or_else(|| eyre!("reserve quote missing `quote` block"))?;
    norito::json::from_value(quote_value.clone())
        .wrap_err("failed to parse reserve quote from quote artifact")
}
fn build_reserve_ledger_plan(
    quote_path: &Path,
    projection: LedgerProjectionAmounts,
    provider: &AccountId,
    treasury: &AccountId,
    reserve: &AccountId,
    asset_definition: &AssetDefinitionId,
) -> Result<Value> {
    let mut instructions = Vec::new();
    append_transfer_instruction(
        &mut instructions,
        provider,
        treasury,
        &projection.rent_due,
        asset_definition,
    )?;
    append_transfer_instruction(
        &mut instructions,
        provider,
        reserve,
        &projection.reserve_shortfall,
        asset_definition,
    )?;
    let mut root = Map::new();
    root.insert(
        "quote_path".into(),
        Value::from(quote_path.display().to_string()),
    );
    root.insert("rent_due".into(), xor_quantity_value(&projection.rent_due));
    root.insert(
        "reserve_shortfall".into(),
        xor_quantity_value(&projection.reserve_shortfall),
    );
    root.insert(
        "top_up_shortfall".into(),
        xor_quantity_value(&projection.top_up_shortfall),
    );
    root.insert("instructions".into(), Value::Array(instructions));
    Ok(Value::Object(root))
}
fn build_reserve_lifecycle_value(
    quote_path: &Path,
    lifecycle: &ReserveLifecycleProjection,
) -> Result<Value> {
    let mut root = Map::new();
    root.insert(
        "quote_path".into(),
        Value::from(quote_path.display().to_string()),
    );
    root.insert(
        "stage".into(),
        Value::from(reserve_lifecycle_stage_label(lifecycle.stage)),
    );
    root.insert(
        "days_past_due".into(),
        Value::Number(Number::from(u64::from(lifecycle.days_past_due))),
    );
    root.insert(
        "grace_period_days".into(),
        Value::Number(Number::from(u64::from(lifecycle.grace_period_days))),
    );
    root.insert(
        "default_after_days".into(),
        Value::Number(Number::from(u64::from(lifecycle.default_after_days))),
    );
    root.insert("rent_due".into(), xor_quantity_value(&lifecycle.rent_due));
    root.insert(
        "reserve_shortfall".into(),
        xor_quantity_value(&lifecycle.reserve_shortfall),
    );
    root.insert(
        "top_up_shortfall".into(),
        xor_quantity_value(&lifecycle.top_up_shortfall),
    );
    root.insert(
        "credit_draw".into(),
        xor_quantity_value(&lifecycle.credit_draw),
    );
    let available = lifecycle
        .credit_available_after_draw
        .as_ref()
        .map_or(Value::Null, xor_quantity_value);
    root.insert("credit_available_after_draw".into(), available);
    root.insert(
        "credit_shortfall".into(),
        xor_quantity_value(&lifecycle.credit_shortfall),
    );
    root.insert(
        "accrued_interest".into(),
        xor_quantity_value(&lifecycle.accrued_interest),
    );
    root.insert(
        "total_due_after_credit".into(),
        xor_quantity_value(&lifecycle.total_due_after_credit),
    );
    root.insert(
        "restrict_new_manifests".into(),
        Value::from(lifecycle.restrict_new_manifests),
    );
    root.insert(
        "disable_adverts".into(),
        Value::from(lifecycle.disable_adverts),
    );
    root.insert(
        "requires_governance_notification".into(),
        Value::from(lifecycle.requires_governance_notification),
    );
    root.insert(
        "requires_manual_credit_approval".into(),
        Value::from(lifecycle.requires_manual_credit_approval),
    );
    let projection = norito::json::to_value(lifecycle)
        .wrap_err("failed to serialize reserve lifecycle projection")?;
    root.insert("lifecycle_projection".into(), projection);
    Ok(Value::Object(root))
}
fn append_transfer_instruction(
    instructions: &mut Vec<Value>,
    source_account: &AccountId,
    destination_account: &AccountId,
    amount: &XorQuantity,
    asset_definition: &AssetDefinitionId,
) -> Result<()> {
    if amount.is_zero() {
        return Ok(());
    }
    let asset_id = AssetId::new(asset_definition.clone(), source_account.clone());
    let transfer = InstructionBox::from(Transfer::asset_quantity(
        asset_id,
        amount.as_quantity().clone(),
        destination_account.clone(),
    ));
    let value = norito::json::to_value(&transfer)
        .wrap_err("failed to serialize reserve ledger transfer instruction")?;
    instructions.push(value);
    Ok(())
}
fn xor_quantity_value(amount: &XorQuantity) -> Value {
    Value::String(amount.to_string())
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
const fn reserve_lifecycle_stage_label(stage: ReserveLifecycleStage) -> &'static str {
    match stage {
        ReserveLifecycleStage::Active => "active",
        ReserveLifecycleStage::Warning => "warning",
        ReserveLifecycleStage::Grace => "grace",
        ReserveLifecycleStage::Delinquent => "delinquent",
        ReserveLifecycleStage::Default => "default",
    }
}
#[cfg(test)]
#[path = "sorafs/tests.rs"]
mod tests;
