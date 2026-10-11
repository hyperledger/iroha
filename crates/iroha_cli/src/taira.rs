//! Taira public testnet diagnostics and write canaries.
use crate::{CliOutputFormat, Run, RunContext, quote_and_sign_transaction_with_expiry};
use eyre::{Context, Result, eyre};
use iroha::{
    blocking::Client as BlockingIrohaClient,
    client::{
        AccountFaucetClaimV1, AccountFaucetPolicyV1, AccountFaucetPreparedTransactionV1,
        AccountOnboardingCurrentStateV1, AccountOnboardingPlanReceiptV1,
        AccountOnboardingPlanRequestV1, AccountOnboardingPrepareResponseV1,
        AccountOnboardingPreparedTransactionV1, AccountOnboardingProofRequiredPrepareResponseV1,
        Client as IrohaClient, PreparedOperationBindingV1, PreparedTransactionOutcomeV1,
    },
    config::Config,
    data_model::{
        NetworkId,
        account::{AccountId, address::ChainDiscriminantGuard},
        alias_setup::AccountAliasName,
        asset::AssetDefinitionId,
        isi::{InstructionBox, Log},
        level::Level as LogLevel,
        prelude::{SignedTransaction, TransactionEntrypoint},
        transaction::{Executable, FeePaymentIntent},
    },
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json as IrohaJson;
use iroha_primitives::numeric::Quantity;
use iroha_torii_shared::{FeeQuoteResponse, PipelineTransactionStatusResponse, mcp as mcp_wire};
use iroha_version::codec::DecodeVersioned as _;
use norito::json::{self, JsonDeserialize, JsonSerialize, Map, Value};
use reqwest::blocking::Client as HttpClient;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read as _, Write as _},
    num::NonZeroU64,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;
use zeroize::Zeroizing;
#[path = "taira_doctor_accounts.rs"]
mod doctor_accounts;
#[path = "taira_onboarding.rs"]
mod onboarding;
#[path = "taira_parliament_seating.rs"]
pub(crate) mod parliament_seating;
use iroha_wallet::faucet_pow::{solve_account_faucet_claim, validate_puzzle_identity};
const DEFAULT_PUBLIC_ROOT: &str = "https://taira.sora.org";
const DEFAULT_CHAIN_ID: &str = "fc56984b-2be7-431d-840e-21514d1883f0";
const DEFAULT_CHAIN_DISCRIMINANT: u16 = 369;
/// Canonical first-release Taira fee/faucet asset definition.
pub(crate) const DEFAULT_GAS_ASSET_ID: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";
const CANARY_ALIAS_PREFIX: &str = "tairarolloutcanary";
const DEFAULT_WRITE_TTL_MS: u64 = 120_000;
const DEFAULT_WRITE_STATUS_TIMEOUT_MS: u64 = 120_000;
const PREPARED_ENVELOPE_SCHEMA_V1: &str = "iroha.taira.prepared-mutation-envelope.v1";
const PREPARED_BINDING_SCHEMA_V1: &str = "iroha.taira.public-reset.mutation-binding.v1";
const PREPARED_OPERATION_SCHEMA_V1: &str = "iroha.taira.prepared-transaction.v1";
const PREPARED_ONBOARDING_PROOF_REQUIRED_SCHEMA_V1: &str =
    "iroha.taira.prepared-onboarding-proof-required.v1";
const PREPARED_ENVELOPE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const PREPARED_TRANSACTION_MAX_BYTES: usize = 1024 * 1024;
const PREPARED_TRANSACTION_CLOCK_SKEW_MS: u64 = 30_000;
const READINESS_RESPONSE_MAX_BYTES: u64 = 4 * 1024;
const INROU_CANARY_HEALTH_RESPONSE_MAX_BYTES: u64 = 4 * 1024;
const INROU_PUBLIC_DISCOVERY_RESPONSE_MAX_BYTES: u64 = 64 * 1024;
const INROU_PUBLIC_DISCOVERY_CONTENT_TYPE: &str = "application/json";
const INROU_PUBLIC_DISCOVERY_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const INROU_PUBLIC_DISCOVERY_CONTENT_CID_HEADER: &str = "sora-content-cid";
const INROU_CANARY_SERVICE_PORT_V1: u64 = 8_787;
const WRITE_CANARY_MUTATION_KIND: &str = "write_canary";
const WRITE_CANARY_OPERATION: &str = "final_canary";
const MCP_ACCEPT: &str = "application/json, text/event-stream";
const MCP_CLIENT_NAME: &str = "iroha-taira-doctor";
const MCP_CLIENT_VERSION: &str = "1";
const REQUIRED_MCP_TOOLS: &[&str] = &[
    "iroha.health",
    "iroha.accounts.get",
    "iroha.accounts.assets",
    "iroha.assets.definitions.get",
    "iroha.transactions.submit",
    "iroha.transactions.submit_and_wait",
];
const FULL_MCP_TOOLS: &[&str] = &[
    "iroha.musubi.queries.exact_package",
    "iroha.musubi.queries.exact_release",
    "iroha.musubi.instructions.release_yank_set",
];
#[derive(Clone, Copy)]
enum RouteCheckMethod {
    Get,
    GetReadiness,
    PostEmptyObject,
}
const ROUTE_CHECKS: &[(&str, RouteCheckMethod, &str, &[u16])] = &[
    (
        "readiness",
        RouteCheckMethod::GetReadiness,
        "/readyz",
        &[200],
    ),
    ("status", RouteCheckMethod::Get, "/status", &[200]),
    ("time_now", RouteCheckMethod::Get, "/v1/time/now", &[200]),
    (
        "sumeragi_status",
        RouteCheckMethod::Get,
        "/v1/sumeragi/status",
        &[401],
    ),
    (
        "pipeline_transaction_status",
        RouteCheckMethod::Get,
        "/v1/pipeline/transactions/status",
        &[400],
    ),
    (
        "zk_proofs_count",
        RouteCheckMethod::Get,
        "/v1/zk/proofs/count",
        &[200],
    ),
    (
        "public_lane_validators",
        RouteCheckMethod::Get,
        "/v1/nexus/public-lanes/0/validators",
        &[200],
    ),
    // A missing selector should reach the mounted contract-state route and be
    // rejected as bad input. Treating that as mounted keeps the doctor aligned
    // with the rollout harness instead of requiring a real contract key.
    (
        "contracts_state",
        RouteCheckMethod::Get,
        "/v1/contracts/state",
        &[400],
    ),
    // The V1 directory is POST-only and authenticates before typed body decode.
    // An unsigned malformed object must therefore fail at the mounted canonical
    // account boundary, independently of registry data.
    (
        "musubi_ordered_prefix",
        RouteCheckMethod::PostEmptyObject,
        "/v1/musubi/queries/ordered-prefix",
        &[401],
    ),
    (
        "soracloud_status",
        RouteCheckMethod::Get,
        "/v1/soracloud/status",
        &[401],
    ),
];
/// Taira public testnet helpers.
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Prepare, submit, or recover ordinary account onboarding and faucet transactions.
    #[command(subcommand)]
    Account(onboarding::AccountCommand),
    /// Check Taira read-side health and MCP route posture.
    Doctor(Doctor),
    /// Seat the SORA Parliament in a freshly generated Kagami Taira network: genesis citizens
    /// and the recommended `[gov]` profile (`specs/sccp.md` §4.14.5).
    SeatParliament(parliament_seating::SeatParliament),
    /// Preflight or execute the strictly authorized compiled public reset.
    PublicReset(crate::taira_public_reset::PublicReset),
    /// Reconcile empty stopped Inrou owners under the active routine updater lock.
    StoppedOwnerMaintenance(crate::taira_public_reset::StoppedOwnerMaintenance),
    /// Remove only retired validator configuration under the routine updater owner.
    RetireValidatorConfig(crate::taira_public_reset::RetireValidatorConfig),
    /// Prepare, submit, or recover exactly one authorized public-reset child.
    WriteCanary(WriteCanary),
    /// Generate the canonical deploy-mode Inrou canary workspace from AArch64 guest assets.
    InrouWorkspace(InrouWorkspace),
    /// Build the canonical offline artifact stage that operators preseed into all validators.
    InrouStage(InrouStage),
    /// Register an exact preseeded stage, mutate explicitly, and verify the four-replica Inrou canary.
    InrouCanary(InrouCanary),
    /// Revalidate an exact retained stage and verify its live four-replica service without mutation.
    InrouCheck(InrouCheck),
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Account(cmd) => cmd.run(context),
            Self::Doctor(cmd) => cmd.run(context),
            Self::SeatParliament(cmd) => cmd.run(context),
            Self::PublicReset(_) => eyre::bail!(
                "`taira public-reset` must be dispatched before client configuration is loaded"
            ),
            Self::StoppedOwnerMaintenance(_) => eyre::bail!(
                "`taira stopped-owner-maintenance` must run before client configuration is loaded"
            ),
            Self::RetireValidatorConfig(_) => eyre::bail!(
                "`taira retire-validator-config` must run before client configuration is loaded"
            ),
            Self::WriteCanary(cmd) => cmd.run(context),
            Self::InrouWorkspace(cmd) => cmd.run(context),
            Self::InrouStage(cmd) => cmd.run(context),
            Self::InrouCanary(cmd) => cmd.run(context),
            Self::InrouCheck(cmd) => cmd.run(context),
        }
    }
}
/// Read-only Taira public endpoint diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(super) enum DoctorScope {
    /// Basic admission readiness, account, asset, transaction and consensus connectivity.
    #[default]
    Basic,
    /// Include advanced service readiness and strict network-time health.
    Full,
}
impl DoctorScope {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Full => "full",
        }
    }

    fn includes_route(self, name: &str) -> bool {
        self == Self::Full
            || matches!(
                name,
                "readiness"
                    | "status"
                    | "time_now"
                    | "sumeragi_status"
                    | "pipeline_transaction_status"
                    | "public_lane_validators"
                    | "contracts_state"
            )
    }
}

/// Read-only Taira public endpoint diagnostics.
#[derive(clap::Args, Debug)]
pub struct Doctor {
    /// Public Torii root URL.
    #[arg(long, default_value = DEFAULT_PUBLIC_ROOT)]
    pub public_root: String,
    /// Release surface whose availability is required.
    #[arg(long, value_enum, default_value = "basic")]
    pub(super) scope: DoctorScope,
    /// Emit a stable JSON report.
    #[arg(long)]
    pub json: bool,
    /// Also report every SORA Parliament seating requirement (`specs/sccp.md` §4.14.5) that
    /// signer-free public routes cannot prove, as warnings.
    #[arg(long)]
    pub parliament: bool,
}
impl Run for Doctor {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let mut output = RunContextReportOutput { context };
        self.run_with_output(&mut output)
    }
}
impl Doctor {
    fn run_with_output<O: ReportOutput>(&self, output: &mut O) -> Result<()> {
        let mut report = run_doctor(&self.public_root, self.scope)?;
        if self.parliament {
            doctor_accounts::append_parliament_warnings(&mut report)?;
        }
        render_report_to(output, self.json, &report)?;
        if report_status(&report) == Some("fail") {
            eyre::bail!("Taira doctor found hard failures");
        }
        Ok(())
    }

    /// Run the public read-only diagnostic without loading client configuration
    /// or constructing any signing identity.
    pub(super) fn run_without_client_config<W: std::io::Write>(
        &self,
        output_format: CliOutputFormat,
        write: W,
    ) -> Result<()> {
        let mut output = WriterReportOutput {
            write,
            output_format,
        };
        self.run_with_output(&mut output)
    }
}
/// Native operator custody binding; never sent as public customer authorization.
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct PreparedMutationBindingV1 {
    /// Exact immutable binding schema.
    pub schema: String,
    /// SHA-256 of the admitted reset authorization.
    pub authorization_sha256: String,
    /// Exact authorization nonce.
    pub authorization_nonce: String,
    /// Exact operation kind: `onboarding` or `faucet`.
    pub kind: String,
    /// Canonical reset phase label.
    pub phase: String,
    /// Exact mutation idempotency digest.
    pub idempotency_key: String,
    /// Absolute execution deadline from the admitted authorization.
    pub execution_expires_at_unix_ms: u64,
}
impl PreparedMutationBindingV1 {
    /// Current immutable binding schema.
    pub const SCHEMA: &'static str = "iroha.taira.public-reset.mutation-binding.v1";

    /// Project admitted native custody onto the exact signed public onboarding operation.
    pub(super) fn onboarding_binding(
        &self,
        receipt: &AccountOnboardingPlanReceiptV1,
    ) -> Result<PreparedOperationBindingV1> {
        validate_prepared_binding(self)?;
        if self.kind != "onboarding" {
            eyre::bail!("native reset binding does not authorize onboarding");
        }
        PreparedOperationBindingV1::onboarding(
            receipt,
            self.idempotency_key.clone(),
            self.execution_expires_at_unix_ms
                .min(receipt.body.valid_until_ms),
        )
    }

    /// Project admitted native custody onto the exact solved public faucet claim.
    pub(super) fn faucet_binding(
        &self,
        claim: &AccountFaucetClaimV1,
    ) -> Result<PreparedOperationBindingV1> {
        validate_prepared_binding(self)?;
        if self.kind != "faucet" {
            eyre::bail!("native reset binding does not authorize a faucet claim");
        }
        PreparedOperationBindingV1::faucet(
            claim,
            self.idempotency_key.clone(),
            self.execution_expires_at_unix_ms,
        )
    }
}

#[derive(Clone, Debug, PartialEq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct FinalCanaryPreparedTransactionV1 {
    schema: String,
    binding: PreparedMutationBindingV1,
    operation: String,
    transaction_hash_hex: String,
    signed_transaction_wire_hex: String,
    signed_transaction_wire_sha256: String,
    semantic_hash_hex: String,
    fee_payment: FeePaymentIntent,
    fee_quote: FeeQuoteResponse,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PreparedOnboardingProofRequiredV1 {
    schema: String,
    receipt: AccountOnboardingPlanReceiptV1,
    result: AccountOnboardingProofRequiredPrepareResponseV1,
}

#[derive(Clone, Debug, PartialEq, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "kind",
    content = "envelope",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum PreparedTransactionOperationV1 {
    OnboardingPrepared(AccountOnboardingPreparedTransactionV1),
    OnboardingProofRequired(PreparedOnboardingProofRequiredV1),
    FaucetPrepared(AccountFaucetPreparedTransactionV1),
    FinalCanary(FinalCanaryPreparedTransactionV1),
}

impl PreparedTransactionOperationV1 {
    fn matches_binding(&self, binding: &PreparedMutationBindingV1) -> Result<bool> {
        Ok(match self {
            Self::OnboardingPrepared(operation) => {
                operation.binding == binding.onboarding_binding(&operation.receipt)?
            }
            Self::OnboardingProofRequired(operation) => {
                operation.result.binding == binding.onboarding_binding(&operation.receipt)?
            }
            Self::FaucetPrepared(operation) => {
                operation.binding == binding.faucet_binding(&operation.claim)?
            }
            Self::FinalCanary(operation) => &operation.binding == binding,
        })
    }

    fn binding_metadata(&self) -> Result<(&'static str, String)> {
        let (name, binding) = match self {
            Self::OnboardingPrepared(operation) => (
                "prepared_operation_binding",
                json::to_value(&operation.binding)?,
            ),
            Self::OnboardingProofRequired(operation) => (
                "prepared_operation_binding",
                json::to_value(&operation.result.binding)?,
            ),
            Self::FaucetPrepared(operation) => (
                "prepared_operation_binding",
                json::to_value(&operation.binding)?,
            ),
            Self::FinalCanary(operation) => (
                PREPARED_BINDING_METADATA,
                json::to_value(&operation.binding)?,
            ),
        };
        Ok((name, json::to_json(&binding)?))
    }

    const fn label(&self) -> &'static str {
        match self {
            Self::OnboardingPrepared(_) | Self::OnboardingProofRequired(_) => "onboarding",
            Self::FaucetPrepared(_) => "faucet",
            Self::FinalCanary(_) => WRITE_CANARY_OPERATION,
        }
    }

    fn transaction_hash_hex(&self) -> Option<&str> {
        match self {
            Self::OnboardingPrepared(operation) => Some(&operation.transaction_hash_hex),
            Self::OnboardingProofRequired(_) => None,
            Self::FaucetPrepared(operation) => Some(&operation.transaction_hash_hex),
            Self::FinalCanary(operation) => Some(&operation.transaction_hash_hex),
        }
    }

    fn signed_transaction_wire_hex(&self) -> Option<&str> {
        match self {
            Self::OnboardingPrepared(operation) => Some(&operation.signed_transaction_wire_hex),
            Self::OnboardingProofRequired(_) => None,
            Self::FaucetPrepared(operation) => Some(&operation.signed_transaction_wire_hex),
            Self::FinalCanary(operation) => Some(&operation.signed_transaction_wire_hex),
        }
    }

    fn signed_transaction_wire_sha256(&self) -> Option<&str> {
        match self {
            Self::OnboardingPrepared(operation) => Some(&operation.signed_transaction_wire_sha256),
            Self::OnboardingProofRequired(_) => None,
            Self::FaucetPrepared(operation) => Some(&operation.signed_transaction_wire_sha256),
            Self::FinalCanary(operation) => Some(&operation.signed_transaction_wire_sha256),
        }
    }

    fn semantic_hash_hex(&self) -> &str {
        match self {
            Self::OnboardingPrepared(operation) => &operation.semantic_hash_hex,
            Self::OnboardingProofRequired(operation) => &operation.result.semantic_hash_hex,
            Self::FaucetPrepared(operation) => &operation.semantic_hash_hex,
            Self::FinalCanary(operation) => &operation.semantic_hash_hex,
        }
    }

    fn fee_payment(&self) -> Option<&FeePaymentIntent> {
        match self {
            Self::OnboardingPrepared(operation) => Some(&operation.fee_payment),
            Self::OnboardingProofRequired(_) => None,
            Self::FaucetPrepared(operation) => Some(&operation.fee_payment),
            Self::FinalCanary(operation) => Some(&operation.fee_payment),
        }
    }

    fn fee_quote(&self) -> Option<&FeeQuoteResponse> {
        match self {
            Self::FinalCanary(operation) => Some(&operation.fee_quote),
            Self::OnboardingPrepared(_)
            | Self::OnboardingProofRequired(_)
            | Self::FaucetPrepared(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PreparedMutationEnvelopeV1 {
    schema: String,
    binding: PreparedMutationBindingV1,
    public_root: String,
    chain_id: String,
    network_id: String,
    authority: String,
    operation: PreparedTransactionOperationV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedEnvelopeAction {
    Prepare(u32),
    Submit(u32),
    Recover(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedLifetimeCheck {
    Structural,
    LiveForward,
}

/// One strictly ordered mutation in the Taira write-canary bootstrap.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteCanaryOperation {
    /// Prepare, submit, or recover the sponsored account/alias onboarding transaction.
    Onboarding,
    /// Prepare, submit, or recover the faucet funding transaction.
    Faucet,
    /// Prepare, submit, or recover the final authority-signed log canary transaction.
    FinalCanary,
}

impl WriteCanaryOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::Onboarding => "onboarding",
            Self::Faucet => "faucet",
            Self::FinalCanary => WRITE_CANARY_OPERATION,
        }
    }

    const fn mutation_kind(self) -> &'static str {
        match self {
            Self::Onboarding => "onboarding",
            Self::Faucet => "faucet",
            Self::FinalCanary => WRITE_CANARY_MUTATION_KIND,
        }
    }
}

/// Signed Taira write canary using an exact durable prepared envelope.
#[derive(clap::Args, Debug)]
#[command(group(
    clap::ArgGroup::new("prepared_action")
        .required(true)
        .multiple(false)
        .args([
            "prepare_envelope",
            "submit_prepared_envelope_fd",
            "recover_prepared_envelope_fd",
        ])
))]
pub struct WriteCanary {
    /// Public Torii root URL.
    #[arg(long, default_value = DEFAULT_PUBLIC_ROOT)]
    pub public_root: String,
    /// Independently trusted faucet authority; required for the faucet child.
    #[arg(long, required_if_eq("operation", "faucet"))]
    pub faucet_authority: Option<String>,
    /// Independently trusted exact faucet asset definition; required for the faucet child.
    #[arg(long, required_if_eq("operation", "faucet"))]
    pub faucet_asset_id: Option<String>,
    /// Independently trusted exact faucet transfer amount; required for the faucet child.
    #[arg(long, required_if_eq("operation", "faucet"))]
    pub faucet_amount: Option<String>,
    /// Independently trusted faucet authority for the final canary's predecessor proof.
    #[arg(long)]
    pub predecessor_faucet_authority: Option<String>,
    /// Exact faucet asset definition for the final canary's predecessor proof.
    #[arg(long)]
    pub predecessor_faucet_asset_id: Option<String>,
    /// Exact faucet transfer amount for the final canary's predecessor proof.
    #[arg(long)]
    pub predecessor_faucet_amount: Option<String>,
    /// Owner-only onboarding token; required only while preparing or submitting the envelope.
    #[arg(long, value_name = "PATH", conflicts_with = "onboarding_token_fd")]
    pub onboarding_token_file: Option<PathBuf>,
    /// Inherited read-only owner-private token descriptor for onboarding prepare or submit.
    #[arg(long, value_name = "FD", conflicts_with = "onboarding_token_file", value_parser = clap::value_parser!(u32).range(3..=65535))]
    pub onboarding_token_fd: Option<u32>,
    /// Exact ordered child operation; each invocation handles one transaction only.
    #[arg(long, value_enum)]
    pub operation: WriteCanaryOperation,
    /// Exact admitted public-reset authorization digest.
    #[arg(long, value_parser = validate_sha256_argument)]
    pub authorization_sha256: String,
    /// Exact admitted public-reset authorization nonce.
    #[arg(long, value_parser = validate_authorization_nonce_argument)]
    pub authorization_nonce: String,
    /// Exact write-canary phase (`pre_edge` or `post_edge`).
    #[arg(long, value_parser = validate_write_canary_phase_argument)]
    pub mutation_phase: String,
    /// Exact lowercase SHA-256 idempotency key bound into the canary transaction.
    #[arg(long, value_parser = validate_write_canary_idempotency_key)]
    pub idempotency_key: String,
    /// Exact signed execution expiry; preparation and submission are barred at this instant.
    #[arg(long)]
    pub execution_expires_at_unix_ms: u64,
    /// Quote and sign one exact envelope without performing any ledger mutation.
    #[arg(long, requires = "prepared_output_fd")]
    pub prepare_envelope: bool,
    /// Inherited writable numeric descriptor receiving canonical envelope JSON.
    #[arg(long, value_name = "FD", requires = "prepare_envelope")]
    pub prepared_output_fd: Option<u32>,
    /// Submit only exact bytes read from this inherited numeric envelope descriptor.
    #[arg(long, value_name = "FD")]
    pub submit_prepared_envelope_fd: Option<u32>,
    /// Read-only classify exact bytes read from this inherited numeric envelope descriptor.
    #[arg(long, value_name = "FD")]
    pub recover_prepared_envelope_fd: Option<u32>,
    /// Inherited descriptor for the exact Applied predecessor envelope during preparation.
    #[arg(long, value_name = "FD")]
    pub prerequisite_envelope_fd: Option<u32>,
    /// Read-only confirmation budget in seconds; the caller owns the outer child deadline.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_secs: u64,
    /// Emit a stable JSON receipt.
    #[arg(long)]
    pub json: bool,
}
impl Run for WriteCanary {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let receipt = run_write_canary_exact(context, &self)?;
        render_report(context, self.json, &receipt)?;
        ensure_write_canary_succeeded(&receipt)
    }
}

impl WriteCanary {
    fn faucet_policy(&self) -> Result<AccountFaucetPolicyV1> {
        if self.operation != WriteCanaryOperation::Faucet {
            eyre::bail!("faucet policy is valid only for the exact faucet child");
        }
        parse_write_canary_faucet_policy(
            self.faucet_authority.as_deref(),
            self.faucet_asset_id.as_deref(),
            self.faucet_amount.as_deref(),
            "faucet",
        )
    }

    fn predecessor_faucet_policy(&self) -> Result<AccountFaucetPolicyV1> {
        if self.operation != WriteCanaryOperation::FinalCanary
            || !matches!(self.prepared_action()?, PreparedEnvelopeAction::Prepare(_))
        {
            eyre::bail!("predecessor faucet policy is valid only for final-canary preparation");
        }
        parse_write_canary_faucet_policy(
            self.predecessor_faucet_authority.as_deref(),
            self.predecessor_faucet_asset_id.as_deref(),
            self.predecessor_faucet_amount.as_deref(),
            "predecessor-faucet",
        )
    }

    fn validated_action(&self) -> Result<PreparedEnvelopeAction> {
        let action = self.prepared_action()?;
        self.validate_prerequisite_action(action)?;
        self.validate_onboarding_token_action(action)?;
        if self.operation == WriteCanaryOperation::Faucet {
            PreparedOperationPolicyContext::Current(self).faucet_policy()?;
        } else if self.faucet_authority.is_some()
            || self.faucet_asset_id.is_some()
            || self.faucet_amount.is_some()
        {
            eyre::bail!("faucet policy inputs are valid only for the exact faucet child");
        }
        if self.operation == WriteCanaryOperation::FinalCanary
            && matches!(action, PreparedEnvelopeAction::Prepare(_))
        {
            PreparedOperationPolicyContext::Predecessor(self).faucet_policy()?;
        } else if self.predecessor_faucet_authority.is_some()
            || self.predecessor_faucet_asset_id.is_some()
            || self.predecessor_faucet_amount.is_some()
        {
            eyre::bail!(
                "predecessor faucet policy inputs are valid only for final-canary preparation"
            );
        }
        Ok(action)
    }

    fn prepared_action(&self) -> Result<PreparedEnvelopeAction> {
        match (
            self.prepare_envelope,
            self.submit_prepared_envelope_fd,
            self.recover_prepared_envelope_fd,
        ) {
            (true, None, None) => Ok(PreparedEnvelopeAction::Prepare(
                self.prepared_output_fd
                    .ok_or_else(|| eyre!("--prepare-envelope requires --prepared-output-fd"))?,
            )),
            (false, Some(fd), None) => {
                if self.prepared_output_fd.is_some() {
                    eyre::bail!("--prepared-output-fd is valid only with --prepare-envelope");
                }
                Ok(PreparedEnvelopeAction::Submit(fd))
            }
            (false, None, Some(fd)) => {
                if self.prepared_output_fd.is_some() {
                    eyre::bail!("--prepared-output-fd is valid only with --prepare-envelope");
                }
                Ok(PreparedEnvelopeAction::Recover(fd))
            }
            _ => eyre::bail!(
                "select exactly one of --prepare-envelope, --submit-prepared-envelope-fd, or --recover-prepared-envelope-fd"
            ),
        }
    }

    fn binding(&self) -> Result<PreparedMutationBindingV1> {
        validate_sha256_argument(&self.authorization_sha256).map_err(|error| eyre!(error))?;
        validate_authorization_nonce_argument(&self.authorization_nonce)
            .map_err(|error| eyre!(error))?;
        validate_write_canary_phase_argument(&self.mutation_phase).map_err(|error| eyre!(error))?;
        validate_write_canary_idempotency_key(&self.idempotency_key)
            .map_err(|error| eyre!(error))?;
        let expected_idempotency_key = write_canary_child_idempotency_key(
            &self.authorization_nonce,
            &self.mutation_phase,
            self.operation.mutation_kind(),
        );
        if self.idempotency_key != expected_idempotency_key {
            eyre::bail!(
                "idempotency key does not match the exact authorization nonce, phase, and child kind"
            );
        }
        if self.execution_expires_at_unix_ms == 0 {
            eyre::bail!("execution expiry must be a positive Unix millisecond instant");
        }
        Ok(PreparedMutationBindingV1 {
            schema: PREPARED_BINDING_SCHEMA_V1.to_owned(),
            authorization_sha256: self.authorization_sha256.clone(),
            authorization_nonce: self.authorization_nonce.clone(),
            kind: self.operation.mutation_kind().to_owned(),
            phase: self.mutation_phase.clone(),
            idempotency_key: self.idempotency_key.clone(),
            execution_expires_at_unix_ms: self.execution_expires_at_unix_ms,
        })
    }

    fn validate_prerequisite_action(&self, action: PreparedEnvelopeAction) -> Result<()> {
        match (action, self.operation, self.prerequisite_envelope_fd) {
            (PreparedEnvelopeAction::Prepare(_), WriteCanaryOperation::Onboarding, None)
            | (
                PreparedEnvelopeAction::Prepare(_),
                WriteCanaryOperation::Faucet | WriteCanaryOperation::FinalCanary,
                Some(_),
            )
            | (PreparedEnvelopeAction::Submit(_), _, None)
            | (PreparedEnvelopeAction::Recover(_), _, None) => Ok(()),
            (PreparedEnvelopeAction::Prepare(_), WriteCanaryOperation::Onboarding, Some(_)) => {
                eyre::bail!("onboarding preparation has no predecessor envelope")
            }
            (
                PreparedEnvelopeAction::Prepare(_),
                WriteCanaryOperation::Faucet | WriteCanaryOperation::FinalCanary,
                None,
            ) => eyre::bail!(
                "faucet and final-canary preparation require --prerequisite-envelope-fd"
            ),
            (
                PreparedEnvelopeAction::Submit(_) | PreparedEnvelopeAction::Recover(_),
                _,
                Some(_),
            ) => {
                eyre::bail!(
                    "--prerequisite-envelope-fd is valid only while preparing the next operation"
                )
            }
        }
    }

    fn validate_onboarding_token_action(&self, action: PreparedEnvelopeAction) -> Result<()> {
        let sources = usize::from(self.onboarding_token_file.is_some())
            + usize::from(self.onboarding_token_fd.is_some());
        let required = self.operation == WriteCanaryOperation::Onboarding
            && matches!(
                action,
                PreparedEnvelopeAction::Prepare(_) | PreparedEnvelopeAction::Submit(_)
            );
        if required && sources != 1 {
            eyre::bail!(
                "onboarding prepare/submit requires exactly one of --onboarding-token-file or --onboarding-token-fd"
            );
        }
        if !required && sources != 0 {
            eyre::bail!("onboarding token inputs are valid only for onboarding prepare/submit");
        }
        if self
            .onboarding_token_fd
            .is_some_and(|fd| !(3..=65535).contains(&fd))
        {
            eyre::bail!("--onboarding-token-fd must be in 3..=65535");
        }
        Ok(())
    }

    fn read_onboarding_token(&self) -> Result<Zeroizing<String>> {
        match (
            self.onboarding_token_file.as_deref(),
            self.onboarding_token_fd,
        ) {
            (Some(path), None) => read_onboarding_token_file(path),
            (None, Some(fd)) => read_onboarding_token_fd(fd),
            _ => eyre::bail!("onboarding requires exactly one explicit token input"),
        }
    }
}

pub(super) fn parse_write_canary_faucet_policy(
    authority_raw: Option<&str>,
    asset_raw: Option<&str>,
    amount_raw: Option<&str>,
    flag_prefix: &str,
) -> Result<AccountFaucetPolicyV1> {
    let authority_raw = authority_raw.ok_or_else(|| eyre!("missing --{flag_prefix}-authority"))?;
    let authority = AccountId::parse_encoded(authority_raw)
        .wrap_err_with(|| format!("--{flag_prefix}-authority is not a canonical AccountId"))?;
    if authority.to_string() != authority_raw {
        eyre::bail!("--{flag_prefix}-authority must use its exact canonical representation");
    }
    let asset_raw = asset_raw.ok_or_else(|| eyre!("missing --{flag_prefix}-asset-id"))?;
    let asset_definition_id = AssetDefinitionId::from_str(asset_raw).wrap_err_with(|| {
        format!("--{flag_prefix}-asset-id is not a canonical asset definition")
    })?;
    if asset_definition_id.to_string() != asset_raw {
        eyre::bail!("--{flag_prefix}-asset-id must use its exact canonical representation");
    }
    let amount_raw = amount_raw.ok_or_else(|| eyre!("missing --{flag_prefix}-amount"))?;
    let amount = Quantity::from_str(amount_raw)
        .wrap_err_with(|| format!("--{flag_prefix}-amount is not an exact positive quantity"))?;
    if amount.to_string() != amount_raw {
        eyre::bail!("--{flag_prefix}-amount must use its exact canonical representation");
    }
    AccountFaucetPolicyV1::try_new(authority, asset_definition_id, amount)
        .wrap_err("invalid independently trusted faucet policy")
}

/// Distinguish the operation being executed from the predecessor being authenticated.
#[derive(Clone, Copy)]
enum PreparedOperationPolicyContext<'a> {
    Current(&'a WriteCanary),
    Predecessor(&'a WriteCanary),
}

impl PreparedOperationPolicyContext<'_> {
    fn operation(self) -> Result<WriteCanaryOperation> {
        match self {
            Self::Current(args) => Ok(args.operation),
            Self::Predecessor(args) => {
                if !matches!(args.prepared_action()?, PreparedEnvelopeAction::Prepare(_)) {
                    eyre::bail!(
                        "predecessor policy is valid only while preparing the next operation"
                    );
                }
                match args.operation {
                    WriteCanaryOperation::Onboarding => {
                        eyre::bail!("onboarding has no predecessor")
                    }
                    WriteCanaryOperation::Faucet => Ok(WriteCanaryOperation::Onboarding),
                    WriteCanaryOperation::FinalCanary => Ok(WriteCanaryOperation::Faucet),
                }
            }
        }
    }

    fn faucet_policy(self) -> Result<AccountFaucetPolicyV1> {
        if self.operation()? != WriteCanaryOperation::Faucet {
            eyre::bail!("the authenticated operation is not the faucet");
        }
        match self {
            Self::Current(args) => args.faucet_policy(),
            Self::Predecessor(args) => args.predecessor_faucet_policy(),
        }
    }
}

#[cfg(test)]
/// Exercise the production action and policy validation with actual parent-produced arguments.
pub(crate) fn validate_parent_write_canary_for_test(
    args: &WriteCanary,
) -> Result<(Option<AccountFaucetPolicyV1>, Option<AccountFaucetPolicyV1>)> {
    args.binding()?;
    let action = args.validated_action()?;
    let current = PreparedOperationPolicyContext::Current(args);
    let current_policy = (current.operation()? == WriteCanaryOperation::Faucet)
        .then(|| current.faucet_policy())
        .transpose()?;
    let predecessor_policy = if matches!(action, PreparedEnvelopeAction::Prepare(_))
        && args.operation == WriteCanaryOperation::FinalCanary
    {
        Some(PreparedOperationPolicyContext::Predecessor(args).faucet_policy()?)
    } else {
        None
    };
    Ok((current_policy, predecessor_policy))
}

fn validate_sha256_argument(value: &str) -> Result<String, String> {
    validate_lower_hex_argument(value, "SHA-256", 64)
}

pub(super) fn validate_authorization_nonce_argument(value: &str) -> Result<String, String> {
    if value.len() != 32
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(
            "must be exactly 32 lowercase URL-safe ASCII characters (`a-z`, `0-9`, `-`, `_`)"
                .to_owned(),
        );
    }
    Ok(value.to_owned())
}

fn validate_write_canary_phase_argument(value: &str) -> Result<String, String> {
    let first = value.as_bytes().first().copied();
    let last = value.as_bytes().last().copied();
    if value.is_empty()
        || value.len() > 64
        || first.is_some_and(|byte| matches!(byte, b'-' | b'_'))
        || last.is_some_and(|byte| matches!(byte, b'-' | b'_'))
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err("must be a 1..=64 byte canonical lowercase phase slug".to_owned());
    }
    Ok(value.to_owned())
}

fn validate_lower_hex_argument(value: &str, label: &str, length: usize) -> Result<String, String> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly {length} lowercase hexadecimal characters"
        ));
    }
    Ok(value.to_owned())
}

fn write_canary_child_idempotency_key(
    authorization_nonce: &str,
    phase: &str,
    child_kind: &str,
) -> String {
    let mut digest = Sha256::new();
    for frame in [
        b"iroha:taira:public-reset:child-idempotency:v1\0".as_slice(),
        authorization_nonce.as_bytes(),
        phase.as_bytes(),
        child_kind.as_bytes(),
    ] {
        let length = u64::try_from(frame.len()).expect("idempotency frame length fits u64");
        digest.update(length.to_be_bytes());
        digest.update(frame);
    }
    hex::encode(digest.finalize())
}
/// Canonical deploy-mode Taira Inrou canary workspace generator.
#[derive(clap::Args, Debug)]
pub struct InrouWorkspace {
    /// Direct regular AArch64 kernel image prepared for PortableVM.
    #[arg(long, value_name = "PATH")]
    pub kernel: PathBuf,
    /// Direct regular AArch64 ext4 root filesystem image prepared for PortableVM.
    #[arg(long, value_name = "PATH")]
    pub rootfs: PathBuf,
    /// Direct regular AArch64 initrd image prepared for PortableVM.
    #[arg(long, value_name = "PATH")]
    pub initrd: PathBuf,
    /// Fresh owner-only directory to create with the exact canonical workspace layout.
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,
    /// Emit a stable JSON report.
    #[arg(long)]
    pub json: bool,
}
impl Run for InrouWorkspace {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let receipt = crate::soracloud::create_taira_inrou_canary_workspace(
            &self.kernel,
            &self.rootfs,
            &self.initrd,
            &self.output_dir,
        )?;
        let mut extra = Map::new();
        extra.insert(
            "output_dir".into(),
            Value::String(self.output_dir.display().to_string()),
        );
        extra.insert("workspace".into(), json::to_value(&receipt)?);
        let report = report_value(
            "taira_inrou_workspace",
            "ok",
            "offline",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            extra,
        )?;
        render_report(context, self.json, &report)
    }
}
/// Explicit mutation mode for the Taira Inrou canary.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum InrouCanaryMode {
    /// Register a new canary service.
    Deploy,
    /// Replace an already-deployed canary revision.
    Upgrade,
}
/// Select runtime qualification before cutover or full public qualification after cutover.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum InrouProbeScope {
    /// Probe the admitted local candidate without public discovery.
    Candidate,
    /// Require runtime, routed service, and public discovery evidence.
    Public,
}
impl InrouProbeScope {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Public => "public",
        }
    }

    fn validate_root(self, root: &str) -> Result<()> {
        if self == Self::Candidate {
            let root = Url::parse(&normalize_root_url(root)?)?;
            if root.scheme() != "http"
                || root.host_str() != Some("127.0.0.1")
                || root.port().is_none()
            {
                eyre::bail!("candidate Inrou probes require an explicit HTTP loopback port");
            }
        }
        Ok(())
    }
}
/// Canonical offline Taira Inrou artifact staging.
#[derive(clap::Args, Debug)]
pub struct InrouStage {
    /// Build the exact deploy or upgrade revision; no mutation mode is inferred.
    #[arg(long, value_enum)]
    pub mode: InrouCanaryMode,
    /// Path to the canonical strict-null, unpublished four-replica Inrou source manifest.
    #[arg(long, value_name = "PATH")]
    pub container: PathBuf,
    /// Path to the matching public HttpService manifest.
    #[arg(long, value_name = "PATH")]
    pub service: PathBuf,
    /// Canonical service bundle bytes to preseed.
    #[arg(long, value_name = "PATH")]
    pub bundle_file: PathBuf,
    /// Exact Unix-second SoraFS retention boundary embedded in both staged manifests.
    /// Retain and reuse this value when reproducing the same release stage.
    #[arg(long = "sorafs-retention-epoch", value_name = "UNIX_SECONDS")]
    pub sorafs_retention_epoch: NonZeroU64,
    /// Exact validator account and peer identity eligible for one staged replica.
    /// Supply exactly four `VALIDATOR,PEER` values matching the public-reset inventory.
    #[arg(long = "placement-target", value_name = "VALIDATOR,PEER")]
    pub placement_targets: Vec<String>,
    /// Fresh owner-only directory that will contain exact manifests and payloads.
    #[arg(long, value_name = "PATH")]
    pub stage_dir: PathBuf,
    /// Owner-private directory containing exactly peer0.toml through peer3.toml to bind.
    #[arg(long, value_name = "PATH")]
    pub bind_validator_config_dir: PathBuf,
    /// Emit a stable JSON receipt.
    #[arg(long)]
    pub json: bool,
}
impl Run for InrouStage {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        ensure_canonical_taira_client_identity(context.config())?;
        let _chain_discriminant = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        let placement_targets = self
            .placement_targets
            .iter()
            .map(|target| crate::soracloud::parse_inrou_placement_target_identity(target))
            .collect::<std::result::Result<BTreeSet<_>, _>>()
            .map_err(|error| eyre!("invalid --placement-target: {error}"))?;
        if placement_targets.len() != 4 {
            return Err(eyre!(
                "Taira Inrou staging requires exactly four distinct --placement-target validator/peer identities"
            ));
        }
        let receipt = crate::soracloud::stage_taira_inrou_canary_deployment(
            self.mode,
            &self.container,
            &self.service,
            &self.bundle_file,
            &self.stage_dir,
            &context.config().key_pair,
            self.sorafs_retention_epoch,
            placement_targets,
        )?;
        crate::soracloud::bind_taira_inrou_validator_configs(
            &self.bind_validator_config_dir,
            &receipt,
        )?;
        let mut extra = Map::new();
        extra.insert(
            "stage_dir".into(),
            Value::String(self.stage_dir.display().to_string()),
        );
        extra.insert(
            "validator_config_dir".into(),
            Value::String(self.bind_validator_config_dir.display().to_string()),
        );
        extra.insert("receipt".into(), json::to_value(&receipt)?);
        let report = report_value(
            "taira_inrou_stage",
            "ok",
            "offline",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            extra,
        )?;
        render_report(context, self.json, &report)
    }
}
const PREPARED_INROU_OPERATION_SCHEMA_V1: &str = "iroha.taira.prepared-soracloud-transaction.v1";

/// One strictly ordered transaction in the Taira Inrou deployment canary.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum InrouCanaryOperation {
    /// Register the canonical service-bundle manifest.
    BundlePin,
    /// Register the canonical AArch64 guest-image manifest.
    GuestPin,
    /// Register the canonical public-discovery manifest.
    DiscoveryPin,
    /// Deploy or upgrade the service after all three manifests are Approved.
    ServiceMutation,
}

impl InrouCanaryOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::BundlePin => "bundle_pin",
            Self::GuestPin => "guest_pin",
            Self::DiscoveryPin => "discovery_pin",
            Self::ServiceMutation => "service_mutation",
        }
    }

    const fn mutation_kind(self) -> &'static str {
        match self {
            Self::BundlePin => "inrou_bundle_pin",
            Self::GuestPin => "inrou_guest_pin",
            Self::DiscoveryPin => "inrou_discovery_pin",
            Self::ServiceMutation => "inrou_canary",
        }
    }

    const fn tagged_kind(self) -> &'static str {
        match self {
            Self::BundlePin => "inrou_bundle_pin",
            Self::GuestPin => "inrou_guest_pin",
            Self::DiscoveryPin => "inrou_discovery_pin",
            Self::ServiceMutation => "inrou_canary",
        }
    }

    const fn prepared_operation(self) -> crate::soracloud::TairaInrouCanaryPreparedOperationV1 {
        match self {
            Self::BundlePin => crate::soracloud::TairaInrouCanaryPreparedOperationV1::BundlePin,
            Self::GuestPin => crate::soracloud::TairaInrouCanaryPreparedOperationV1::GuestPin,
            Self::DiscoveryPin => {
                crate::soracloud::TairaInrouCanaryPreparedOperationV1::DiscoveryPin
            }
            Self::ServiceMutation => {
                crate::soracloud::TairaInrouCanaryPreparedOperationV1::ServiceMutation
            }
        }
    }

    const fn predecessor(self) -> (&'static str, &'static str) {
        match self {
            Self::BundlePin => ("write_canary", "final_canary"),
            Self::GuestPin => ("inrou_bundle_pin", "bundle_pin"),
            Self::DiscoveryPin => ("inrou_guest_pin", "guest_pin"),
            Self::ServiceMutation => ("inrou_discovery_pin", "discovery_pin"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PreparedInrouTransactionV1 {
    schema: String,
    binding: crate::soracloud::TairaMutationBindingV1,
    operation: String,
    transaction_hash_hex: String,
    signed_transaction_wire_hex: String,
    signed_transaction_wire_sha256: String,
    fee_payment: FeePaymentIntent,
    fee_quote: FeeQuoteResponse,
}

#[derive(Clone, Debug, PartialEq, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "kind",
    content = "envelope",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum PreparedInrouOperationV1 {
    InrouBundlePin(PreparedInrouTransactionV1),
    InrouGuestPin(PreparedInrouTransactionV1),
    InrouDiscoveryPin(PreparedInrouTransactionV1),
    InrouCanary(PreparedInrouTransactionV1),
}

impl PreparedInrouOperationV1 {
    fn transaction(&self) -> &PreparedInrouTransactionV1 {
        match self {
            Self::InrouBundlePin(value)
            | Self::InrouGuestPin(value)
            | Self::InrouDiscoveryPin(value)
            | Self::InrouCanary(value) => value,
        }
    }

    const fn tagged_kind(&self) -> &'static str {
        match self {
            Self::InrouBundlePin(_) => "inrou_bundle_pin",
            Self::InrouGuestPin(_) => "inrou_guest_pin",
            Self::InrouDiscoveryPin(_) => "inrou_discovery_pin",
            Self::InrouCanary(_) => "inrou_canary",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PreparedInrouStageIdentityV1 {
    service_name: String,
    service_version: String,
    route_host: String,
    route_path_prefix: String,
    healthcheck_path: String,
    stage_mode: String,
    bundle_hash: String,
    bundle_content_cid: String,
    bundle_manifest_digest_hex: String,
    guest_content_cid: String,
    guest_manifest_digest_hex: String,
    discovery_payload_dir: String,
    discovery_document_hash: String,
    discovery_content_cid: String,
    discovery_manifest_digest_hex: String,
    public_discovery_url: String,
    public_discovery_cid_host_url: String,
    deployment_bundle_hash: String,
    container_manifest_hash: String,
    service_manifest_hash: String,
    placement_targets: BTreeSet<iroha::data_model::soracloud::SoraInrouPlacementTargetV1>,
}

impl From<&crate::soracloud::TairaInrouStageIdentity> for PreparedInrouStageIdentityV1 {
    fn from(value: &crate::soracloud::TairaInrouStageIdentity) -> Self {
        Self {
            service_name: value.service_name.clone(),
            service_version: value.service_version.clone(),
            route_host: value.route_host.clone(),
            route_path_prefix: value.route_path_prefix.clone(),
            healthcheck_path: value.healthcheck_path.clone(),
            stage_mode: value.stage_mode.clone(),
            bundle_hash: value.bundle_hash.clone(),
            bundle_content_cid: value.bundle_content_cid.clone(),
            bundle_manifest_digest_hex: value.bundle_manifest_digest_hex.clone(),
            guest_content_cid: value.guest_content_cid.clone(),
            guest_manifest_digest_hex: value.guest_manifest_digest_hex.clone(),
            discovery_payload_dir: value.discovery_payload_dir.clone(),
            discovery_document_hash: value.discovery_document_hash.clone(),
            discovery_content_cid: value.discovery_content_cid.clone(),
            discovery_manifest_digest_hex: value.discovery_manifest_digest_hex.clone(),
            public_discovery_url: value.public_discovery_url.clone(),
            public_discovery_cid_host_url: value.public_discovery_cid_host_url.clone(),
            deployment_bundle_hash: value.deployment_bundle_hash.clone(),
            container_manifest_hash: value.container_manifest_hash.clone(),
            service_manifest_hash: value.service_manifest_hash.clone(),
            placement_targets: value.placement_targets.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PreparedInrouEnvelopeV1 {
    schema: String,
    probe_scope: String,
    binding: crate::soracloud::TairaMutationBindingV1,
    public_root: String,
    chain_id: String,
    network_id: String,
    authority: String,
    stage: PreparedInrouStageIdentityV1,
    operation: PreparedInrouOperationV1,
}

struct ValidatedPreparedInrouV1 {
    envelope: PreparedInrouEnvelopeV1,
    prepared: crate::soracloud::PreparedSoracloudTransactionV1,
    envelope_bytes: Vec<u8>,
    stage: crate::soracloud::TairaInrouStageIdentity,
}

/// Canonical Taira Inrou exact-transaction preparation and recovery.
#[derive(clap::Args, Debug)]
#[command(group(
    clap::ArgGroup::new("prepared_action")
        .required(true)
        .multiple(false)
        .args([
            "prepare_envelope",
            "submit_prepared_envelope_fd",
            "recover_prepared_envelope_fd",
        ])
))]
pub struct InrouCanary {
    /// Candidate runtime qualification or complete public qualification.
    #[arg(long, value_enum, default_value = "public")]
    pub probe_scope: InrouProbeScope,
    /// Public or admitted loopback Torii root used for mutation, status, and route probes.
    #[arg(long, default_value = DEFAULT_PUBLIC_ROOT)]
    pub public_root: String,
    /// Owner-only stage created by `iroha taira inrou-stage` and preseeded into all validators.
    #[arg(long, value_name = "PATH")]
    pub stage_dir: PathBuf,
    /// Submit an explicit deploy or upgrade mutation; conflicts are never retried as another mode.
    #[arg(long, value_enum)]
    pub mode: InrouCanaryMode,
    /// Exact ordered child operation; each invocation handles one transaction only.
    #[arg(long, value_enum)]
    pub operation: InrouCanaryOperation,
    /// Exact admitted public-reset authorization digest.
    #[arg(long, value_parser = validate_sha256_argument)]
    pub authorization_sha256: String,
    /// Exact admitted public-reset authorization nonce.
    #[arg(long, value_parser = validate_authorization_nonce_argument)]
    pub authorization_nonce: String,
    /// Exact mutation phase; Inrou V1 is admitted only in `pre_edge`.
    #[arg(long, value_parser = validate_write_canary_phase_argument)]
    pub mutation_phase: String,
    /// Exact child-kind-derived idempotency key bound into the signed transaction.
    #[arg(long, value_parser = validate_write_canary_idempotency_key)]
    pub idempotency_key: String,
    /// Exact signed execution expiry; preparation and submission are barred at this instant.
    #[arg(long)]
    pub execution_expires_at_unix_ms: u64,
    /// Quote and sign one exact transaction envelope without submitting it.
    #[arg(long, requires = "prepared_output_fd")]
    pub prepare_envelope: bool,
    /// Inherited writable descriptor receiving canonical envelope JSON.
    #[arg(long, value_name = "FD", requires = "prepare_envelope")]
    pub prepared_output_fd: Option<u32>,
    /// Submit only exact bytes read from this inherited descriptor.
    #[arg(long, value_name = "FD")]
    pub submit_prepared_envelope_fd: Option<u32>,
    /// Read-only classify exact bytes read from this inherited descriptor.
    #[arg(long, value_name = "FD")]
    pub recover_prepared_envelope_fd: Option<u32>,
    /// Inherited exact Applied predecessor envelope, required only while preparing.
    #[arg(long, value_name = "FD")]
    pub prerequisite_envelope_fd: Option<u32>,
    /// Maximum convergence time for adverts, placements, runtime health, and all four routes.
    #[arg(long, value_name = "SECS", default_value_t = 180)]
    pub timeout_secs: u64,
    /// Emit a stable redacted JSON receipt.
    #[arg(long)]
    pub json: bool,
}
impl Run for InrouCanary {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let receipt = run_inrou_canary_exact(context, &self)?;
        render_report(context, self.json, &receipt)?;
        if report_status(&receipt) != Some("ok") {
            eyre::bail!("Taira Inrou prepared operation found hard failures");
        }
        Ok(())
    }
}

impl InrouCanary {
    fn prepared_action(&self) -> Result<PreparedEnvelopeAction> {
        match (
            self.prepare_envelope,
            self.submit_prepared_envelope_fd,
            self.recover_prepared_envelope_fd,
        ) {
            (true, None, None) => Ok(PreparedEnvelopeAction::Prepare(
                self.prepared_output_fd
                    .ok_or_else(|| eyre!("--prepare-envelope requires --prepared-output-fd"))?,
            )),
            (false, Some(fd), None) if self.prepared_output_fd.is_none() => {
                Ok(PreparedEnvelopeAction::Submit(fd))
            }
            (false, None, Some(fd)) if self.prepared_output_fd.is_none() => {
                Ok(PreparedEnvelopeAction::Recover(fd))
            }
            _ => eyre::bail!(
                "select exactly one prepared action and use --prepared-output-fd only with --prepare-envelope"
            ),
        }
    }

    fn binding(&self) -> Result<crate::soracloud::TairaMutationBindingV1> {
        validate_sha256_argument(&self.authorization_sha256).map_err(|error| eyre!(error))?;
        validate_authorization_nonce_argument(&self.authorization_nonce)
            .map_err(|error| eyre!(error))?;
        validate_write_canary_phase_argument(&self.mutation_phase).map_err(|error| eyre!(error))?;
        if self.mutation_phase != "pre_edge" {
            eyre::bail!("Taira Inrou prepared operations are admitted only in pre_edge");
        }
        validate_write_canary_idempotency_key(&self.idempotency_key)
            .map_err(|error| eyre!(error))?;
        let expected = write_canary_child_idempotency_key(
            &self.authorization_nonce,
            &self.mutation_phase,
            self.operation.mutation_kind(),
        );
        if self.idempotency_key != expected {
            eyre::bail!(
                "idempotency key does not match the exact authorization nonce, phase, and Inrou child kind"
            );
        }
        if self.execution_expires_at_unix_ms == 0 {
            eyre::bail!("execution expiry must be a positive Unix millisecond instant");
        }
        Ok(crate::soracloud::TairaMutationBindingV1 {
            authorization_sha256: self.authorization_sha256.clone(),
            authorization_nonce: self.authorization_nonce.clone(),
            kind: self.operation.mutation_kind().to_owned(),
            phase: self.mutation_phase.clone(),
            idempotency_key: self.idempotency_key.clone(),
            execution_expires_at_unix_ms: self.execution_expires_at_unix_ms,
        })
    }

    fn validate_prerequisite_action(&self, action: PreparedEnvelopeAction) -> Result<()> {
        match (action, self.prerequisite_envelope_fd) {
            (PreparedEnvelopeAction::Prepare(_), Some(_))
            | (PreparedEnvelopeAction::Submit(_) | PreparedEnvelopeAction::Recover(_), None) => {
                Ok(())
            }
            (PreparedEnvelopeAction::Prepare(_), None) => {
                eyre::bail!("every Inrou child preparation requires --prerequisite-envelope-fd")
            }
            (PreparedEnvelopeAction::Submit(_) | PreparedEnvelopeAction::Recover(_), Some(_)) => {
                eyre::bail!(
                    "--prerequisite-envelope-fd is valid only while preparing the next Inrou child"
                )
            }
        }
    }
}

fn run_inrou_canary_exact<C: RunContext>(context: &mut C, args: &InrouCanary) -> Result<Value> {
    validate_inrou_canary_timeout(args.timeout_secs)?;
    ensure_canonical_taira_client_identity(context.config())?;
    let _chain_discriminant = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
    let public_root = normalize_root_url(&args.public_root)?;
    args.probe_scope.validate_root(&public_root)?;
    let binding = args.binding()?;
    let action = args.prepared_action()?;
    args.validate_prerequisite_action(action)?;
    let expected_fee_payment = context.transaction_fee_payment()?;
    match action {
        PreparedEnvelopeAction::Prepare(output_fd) => {
            require_inrou_binding_current(&binding)?;
            let deadline = prepared_observation_deadline(
                args.timeout_secs,
                Some(binding.execution_expires_at_unix_ms),
            )?;
            preflight_taira_network_identity(&public_root, context.config())?;
            prove_inrou_predecessor_applied(
                context.config(),
                args,
                &public_root,
                &binding,
                &expected_fee_payment,
                deadline,
            )?;
            require_inrou_binding_current(&binding)?;
            let stage = crate::soracloud::load_taira_inrou_stage_identity(
                context.config(),
                &args.stage_dir,
                args.mode,
            )?;
            let prepared = crate::soracloud::prepare_taira_inrou_canary_operation(
                context.config(),
                context.soracloud_http_witness_file(),
                expected_fee_payment.clone(),
                binding.clone(),
                &args.stage_dir,
                &public_root,
                None,
                args.timeout_secs,
                args.mode,
                args.operation.prepared_operation(),
            )?;
            let envelope = make_prepared_inrou_envelope(
                context.config(),
                &public_root,
                args.probe_scope,
                args.operation,
                &stage,
                &expected_fee_payment,
                prepared,
            )?;
            let envelope_bytes = canonical_prepared_inrou_envelope_bytes(&envelope)?;
            write_prepared_envelope(output_fd, &envelope_bytes)?;
            prepared_inrou_report(
                context.config(),
                &public_root,
                args,
                &envelope,
                &envelope_bytes,
                &stage,
                "Prepared",
                None,
                None,
                None,
                deadline,
            )
        }
        PreparedEnvelopeAction::Submit(fd) => {
            let deadline = prepared_observation_deadline(
                args.timeout_secs,
                Some(binding.execution_expires_at_unix_ms),
            )?;
            let validated = load_and_validate_prepared_inrou(
                context.config(),
                args,
                &public_root,
                &binding,
                fd,
                &expected_fee_payment,
                PreparedLifetimeCheck::LiveForward,
            )?;
            let transaction = validated.prepared.decode_and_validate()?;
            let ttl = transaction
                .time_to_live()
                .ok_or_else(|| eyre!("prepared Inrou transaction omits its required TTL"))?;
            let expires_at_ms = u64::try_from(
                transaction
                    .creation_time()
                    .checked_add(ttl)
                    .ok_or_else(|| eyre!("prepared Inrou transaction expiry overflow"))?
                    .as_millis(),
            )?;
            let deadline = deadline.min(prepared_observation_deadline(
                args.timeout_secs,
                Some(expires_at_ms),
            )?);
            let outcome = submit_prepared_inrou_until(
                context.config(),
                &public_root,
                deadline,
                &validated.prepared,
                &binding,
            )?;
            report_prepared_inrou_outcome(
                context.config(),
                &public_root,
                args,
                &validated,
                outcome,
                deadline,
            )
        }
        PreparedEnvelopeAction::Recover(fd) => {
            let deadline = prepared_observation_deadline(args.timeout_secs, None)?;
            let validated = load_and_validate_prepared_inrou(
                context.config(),
                args,
                &public_root,
                &binding,
                fd,
                &expected_fee_payment,
                PreparedLifetimeCheck::Structural,
            )?;
            let outcome = recover_prepared_inrou(
                context.config(),
                &public_root,
                deadline,
                &validated.prepared,
            )?;
            report_prepared_inrou_outcome(
                context.config(),
                &public_root,
                args,
                &validated,
                outcome,
                deadline,
            )
        }
    }
}

fn require_inrou_binding_current(binding: &crate::soracloud::TairaMutationBindingV1) -> Result<()> {
    if current_unix_ms()? >= binding.execution_expires_at_unix_ms {
        eyre::bail!("prepared Inrou mutation execution expiry bars a new forward effect");
    }
    Ok(())
}

fn make_prepared_inrou_envelope(
    config: &Config,
    public_root: &str,
    probe_scope: InrouProbeScope,
    operation: InrouCanaryOperation,
    stage: &crate::soracloud::TairaInrouStageIdentity,
    expected_fee_payment: &FeePaymentIntent,
    prepared: crate::soracloud::PreparedSoracloudTransactionV1,
) -> Result<PreparedInrouEnvelopeV1> {
    let transaction = prepared.decode_and_validate()?;
    if prepared.operation != operation.label()
        || prepared.binding.kind != operation.mutation_kind()
        || transaction.authority() != &config.account
        || transaction.network_id() != Some(&config.network_id)
    {
        eyre::bail!("prepared Inrou transaction differs from its exact CLI identity");
    }
    validate_expected_prepared_fee_payment(expected_fee_payment, transaction.fee_payment_intent())?;
    crate::soracloud::verify_taira_inrou_prepared_transaction_identity_v1(
        &transaction,
        operation.prepared_operation(),
        stage,
        &prepared.binding.idempotency_key,
    )
    .wrap_err("prepared Inrou transaction executable authentication failed")?;
    validate_inrou_transaction_lifetime(
        &transaction,
        &prepared.binding,
        PreparedLifetimeCheck::LiveForward,
    )?;
    let transaction_envelope = PreparedInrouTransactionV1 {
        schema: PREPARED_INROU_OPERATION_SCHEMA_V1.to_owned(),
        binding: prepared.binding.clone(),
        operation: prepared.operation.clone(),
        transaction_hash_hex: prepared.tx_hash_hex,
        signed_transaction_wire_sha256: hex::encode(Sha256::digest(&prepared.wire)),
        signed_transaction_wire_hex: hex::encode(&prepared.wire),
        fee_payment: prepared.fee_payment,
        fee_quote: prepared.fee_quote,
    };
    let tagged = match operation {
        InrouCanaryOperation::BundlePin => {
            PreparedInrouOperationV1::InrouBundlePin(transaction_envelope)
        }
        InrouCanaryOperation::GuestPin => {
            PreparedInrouOperationV1::InrouGuestPin(transaction_envelope)
        }
        InrouCanaryOperation::DiscoveryPin => {
            PreparedInrouOperationV1::InrouDiscoveryPin(transaction_envelope)
        }
        InrouCanaryOperation::ServiceMutation => {
            PreparedInrouOperationV1::InrouCanary(transaction_envelope)
        }
    };
    Ok(PreparedInrouEnvelopeV1 {
        schema: PREPARED_ENVELOPE_SCHEMA_V1.to_owned(),
        probe_scope: probe_scope.label().to_owned(),
        binding: prepared.binding,
        public_root: public_root.to_owned(),
        chain_id: config.chain.to_string(),
        network_id: config.network_id.to_string(),
        authority: config.account.to_string(),
        stage: stage.into(),
        operation: tagged,
    })
}

fn canonical_prepared_inrou_envelope_bytes(envelope: &PreparedInrouEnvelopeV1) -> Result<Vec<u8>> {
    let value = json::to_value(envelope).wrap_err("project canonical prepared Inrou envelope")?;
    let mut bytes = json::to_json(&value)
        .wrap_err("encode canonical prepared Inrou envelope")?
        .into_bytes();
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > PREPARED_ENVELOPE_MAX_BYTES {
        eyre::bail!("prepared Inrou envelope exceeds its V1 byte bound");
    }
    Ok(bytes)
}

fn read_prepared_inrou_envelope(fd: u32) -> Result<(PreparedInrouEnvelopeV1, Vec<u8>)> {
    let path = inherited_fd_path(fd)?;
    let file = File::open(path)
        .wrap_err_with(|| format!("failed to duplicate prepared Inrou input FD {fd}"))?;
    let mut bytes = Vec::new();
    file.take(PREPARED_ENVELOPE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .wrap_err("failed to read prepared Inrou envelope")?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > PREPARED_ENVELOPE_MAX_BYTES
    {
        eyre::bail!("prepared Inrou envelope is empty or exceeds its V1 byte bound");
    }
    let envelope: PreparedInrouEnvelopeV1 =
        json::from_slice(&bytes).wrap_err("prepared Inrou envelope is not canonical V1 JSON")?;
    if canonical_prepared_inrou_envelope_bytes(&envelope)? != bytes {
        eyre::bail!("prepared Inrou envelope bytes are not exact canonical V1 JSON");
    }
    Ok((envelope, bytes))
}

fn load_and_validate_prepared_inrou(
    config: &Config,
    args: &InrouCanary,
    public_root: &str,
    expected_binding: &crate::soracloud::TairaMutationBindingV1,
    fd: u32,
    expected_fee_payment: &FeePaymentIntent,
    lifetime_check: PreparedLifetimeCheck,
) -> Result<ValidatedPreparedInrouV1> {
    let (envelope, envelope_bytes) = read_prepared_inrou_envelope(fd)?;
    let stage =
        crate::soracloud::load_taira_inrou_stage_identity(config, &args.stage_dir, args.mode)?;
    let operation = envelope.operation.transaction();
    if envelope.schema != PREPARED_ENVELOPE_SCHEMA_V1
        || envelope.probe_scope != args.probe_scope.label()
        || &envelope.binding != expected_binding
        || envelope.public_root != public_root
        || envelope.chain_id != config.chain.to_string()
        || envelope.network_id != config.network_id.to_string()
        || envelope.authority != config.account.to_string()
        || envelope.stage != PreparedInrouStageIdentityV1::from(&stage)
        || envelope.operation.tagged_kind() != args.operation.tagged_kind()
        || operation.schema != PREPARED_INROU_OPERATION_SCHEMA_V1
        || operation.binding != envelope.binding
        || operation.operation != args.operation.label()
    {
        eyre::bail!("prepared Inrou envelope does not bind the exact CLI authorization and stage");
    }
    let wire = hex::decode(&operation.signed_transaction_wire_hex)
        .wrap_err("prepared Inrou transaction wire is not hexadecimal")?;
    if wire.is_empty()
        || wire.len() > PREPARED_TRANSACTION_MAX_BYTES
        || hex::encode(&wire) != operation.signed_transaction_wire_hex
        || hex::encode(Sha256::digest(&wire)) != operation.signed_transaction_wire_sha256
    {
        eyre::bail!("prepared Inrou transaction wire is not canonical or bounded");
    }
    let prepared = crate::soracloud::PreparedSoracloudTransactionV1 {
        operation: operation.operation.clone(),
        wire,
        tx_hash_hex: operation.transaction_hash_hex.clone(),
        fee_payment: operation.fee_payment.clone(),
        fee_quote: operation.fee_quote.clone(),
        binding: operation.binding.clone(),
    };
    let transaction = prepared.decode_and_validate()?;
    if transaction.authority() != &config.account
        || transaction.network_id() != Some(&config.network_id)
    {
        eyre::bail!("prepared Inrou transaction has a substituted authority or network");
    }
    validate_expected_prepared_fee_payment(expected_fee_payment, transaction.fee_payment_intent())?;
    crate::soracloud::verify_taira_inrou_prepared_transaction_identity_v1(
        &transaction,
        args.operation.prepared_operation(),
        &stage,
        &prepared.binding.idempotency_key,
    )
    .wrap_err("prepared Inrou transaction executable authentication failed")?;
    validate_inrou_transaction_lifetime(&transaction, &prepared.binding, lifetime_check)?;
    Ok(ValidatedPreparedInrouV1 {
        envelope,
        prepared,
        envelope_bytes,
        stage,
    })
}

fn validate_inrou_transaction_lifetime(
    transaction: &SignedTransaction,
    binding: &crate::soracloud::TairaMutationBindingV1,
    lifetime_check: PreparedLifetimeCheck,
) -> Result<()> {
    let creation_ms = u64::try_from(transaction.creation_time().as_millis())
        .wrap_err("prepared Inrou transaction creation time exceeds u64")?;
    let ttl_ms = u64::try_from(
        transaction
            .time_to_live()
            .ok_or_else(|| eyre!("prepared Inrou transaction omits its required TTL"))?
            .as_millis(),
    )
    .wrap_err("prepared Inrou transaction TTL exceeds u64")?;
    validate_prepared_transaction_time_window(
        creation_ms,
        ttl_ms,
        binding.execution_expires_at_unix_ms,
        "prepared Inrou transaction",
    )?;
    if lifetime_check == PreparedLifetimeCheck::LiveForward {
        validate_live_prepared_transaction_freshness(
            creation_ms,
            ttl_ms,
            current_unix_ms()?,
            "prepared Inrou transaction",
        )?;
    }
    Ok(())
}

fn submit_prepared_inrou_until(
    config: &Config,
    public_root: &str,
    deadline: Instant,
    prepared: &crate::soracloud::PreparedSoracloudTransactionV1,
    binding: &crate::soracloud::TairaMutationBindingV1,
) -> Result<crate::soracloud::PreparedSoracloudRecoveryV1> {
    let mut outcome = recover_prepared_inrou(config, public_root, deadline, prepared)?;
    if matches!(
        outcome,
        crate::soracloud::PreparedSoracloudRecoveryV1::Absent
    ) {
        require_inrou_binding_current(binding)?;
        if Instant::now() >= deadline {
            return Ok(crate::soracloud::PreparedSoracloudRecoveryV1::Pending {
                terminal_kind: "ObservationBudgetExhausted".to_owned(),
            });
        }
        match crate::soracloud::submit_prepared_soracloud_transaction(
            config,
            public_root,
            deadline,
            prepared,
        ) {
            Ok(hash) if hex::encode(hash.as_ref()) == prepared.tx_hash_hex => {}
            Ok(_) => {
                eyre::bail!("submitted Soracloud hash differs from the exact prepared transaction")
            }
            Err(error)
                if observation_transport_unavailable(&error)
                    || error.chain().any(|cause| {
                        cause
                            .downcast_ref::<iroha::client::TransactionDispatchOutcomeUnknownError>()
                            .is_some()
                    }) => {}
            Err(error) => return Err(error),
        }
        // The one submitted envelope is now reconciled read-only, even if dispatch
        // returned an uncertain transport outcome. Never submit a second time.
        outcome = crate::soracloud::PreparedSoracloudRecoveryV1::Pending {
            terminal_kind: "AcceptedNotVisible".to_owned(),
        };
    }
    loop {
        if !matches!(
            &outcome,
            crate::soracloud::PreparedSoracloudRecoveryV1::Absent
                | crate::soracloud::PreparedSoracloudRecoveryV1::Pending { .. }
        ) || Instant::now() >= deadline
        {
            return Ok(outcome);
        }
        std::thread::sleep(
            Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())),
        );
        if Instant::now() >= deadline {
            return Ok(outcome);
        }
        outcome = recover_prepared_inrou(config, public_root, deadline, prepared)?;
    }
}

/// Only transport unavailability may retain a pending observation. Authorization,
/// compatibility, decoding, and proof errors are immediately returned to the caller.
pub(crate) fn observation_transport_unavailable(error: &eyre::Report) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|error| error.is_timeout() || error.is_connect() || error.is_body())
            || cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::BrokenPipe
                )
            })
    })
}

fn recover_prepared_inrou(
    config: &Config,
    public_root: &str,
    deadline: Instant,
    prepared: &crate::soracloud::PreparedSoracloudTransactionV1,
) -> Result<crate::soracloud::PreparedSoracloudRecoveryV1> {
    match crate::soracloud::recover_prepared_soracloud_transaction(
        config,
        public_root,
        deadline,
        prepared,
    ) {
        Err(error) if observation_transport_unavailable(&error) => {
            Ok(crate::soracloud::PreparedSoracloudRecoveryV1::Pending {
                terminal_kind: "ObservationUnavailable".to_owned(),
            })
        }
        result => result,
    }
}

fn report_prepared_inrou_outcome(
    config: &Config,
    public_root: &str,
    args: &InrouCanary,
    validated: &ValidatedPreparedInrouV1,
    outcome: crate::soracloud::PreparedSoracloudRecoveryV1,
    deadline: Instant,
) -> Result<Value> {
    let outcome = qualify_applied_inrou_pin_outcome(config, public_root, args, outcome, deadline)?;
    match outcome {
        crate::soracloud::PreparedSoracloudRecoveryV1::Absent => prepared_inrou_report(
            config,
            public_root,
            args,
            &validated.envelope,
            &validated.envelope_bytes,
            &validated.stage,
            "Pending",
            None,
            Some("Absent".to_owned()),
            None,
            deadline,
        ),
        crate::soracloud::PreparedSoracloudRecoveryV1::Applied {
            block_height,
            evidence_sha256,
        } => prepared_inrou_report(
            config,
            public_root,
            args,
            &validated.envelope,
            &validated.envelope_bytes,
            &validated.stage,
            "Applied",
            Some(block_height),
            Some(evidence_sha256),
            Some(validated),
            deadline,
        ),
        crate::soracloud::PreparedSoracloudRecoveryV1::Pending { terminal_kind } => {
            prepared_inrou_report(
                config,
                public_root,
                args,
                &validated.envelope,
                &validated.envelope_bytes,
                &validated.stage,
                "Pending",
                None,
                Some(terminal_kind),
                None,
                deadline,
            )
        }
        crate::soracloud::PreparedSoracloudRecoveryV1::Rejected { terminal_kind } => {
            prepared_inrou_report(
                config,
                public_root,
                args,
                &validated.envelope,
                &validated.envelope_bytes,
                &validated.stage,
                "Rejected",
                None,
                Some(terminal_kind),
                None,
                deadline,
            )
        }
    }
}

fn qualify_applied_inrou_pin_outcome(
    config: &Config,
    public_root: &str,
    args: &InrouCanary,
    outcome: crate::soracloud::PreparedSoracloudRecoveryV1,
    deadline: Instant,
) -> Result<crate::soracloud::PreparedSoracloudRecoveryV1> {
    if args.operation == InrouCanaryOperation::ServiceMutation
        || !matches!(
            &outcome,
            crate::soracloud::PreparedSoracloudRecoveryV1::Applied { .. }
        )
    {
        return Ok(outcome);
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(crate::soracloud::PreparedSoracloudRecoveryV1::Pending {
            terminal_kind: "PinObservationBudgetExhausted".to_owned(),
        });
    }
    Ok(
        match crate::soracloud::taira_inrou_canary_pin_readiness_v1(
            config,
            &args.stage_dir,
            public_root,
            remaining,
            args.mode,
            args.operation.prepared_operation(),
        ) {
            Ok(crate::soracloud::TairaInrouCanaryPinReadinessV1::Approved(epoch)) if epoch > 0 => {
                outcome
            }
            Ok(crate::soracloud::TairaInrouCanaryPinReadinessV1::Approved(_)) => {
                crate::soracloud::PreparedSoracloudRecoveryV1::Rejected {
                    terminal_kind: "InvalidApprovalEpoch".to_owned(),
                }
            }
            Ok(crate::soracloud::TairaInrouCanaryPinReadinessV1::Pending) => {
                crate::soracloud::PreparedSoracloudRecoveryV1::Pending {
                    terminal_kind: "PinApprovalPending".to_owned(),
                }
            }
            Ok(crate::soracloud::TairaInrouCanaryPinReadinessV1::Missing) => {
                crate::soracloud::PreparedSoracloudRecoveryV1::Pending {
                    terminal_kind: "PinObservationMissing".to_owned(),
                }
            }
            Err(error) if observation_transport_unavailable(&error) => {
                crate::soracloud::PreparedSoracloudRecoveryV1::Pending {
                    terminal_kind: "ObservationUnavailable".to_owned(),
                }
            }
            Err(error) => return Err(error),
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn prepared_inrou_report(
    config: &Config,
    public_root: &str,
    args: &InrouCanary,
    envelope: &PreparedInrouEnvelopeV1,
    envelope_bytes: &[u8],
    stage: &crate::soracloud::TairaInrouStageIdentity,
    outcome: &str,
    applied_block_height: Option<u64>,
    evidence: Option<String>,
    applied: Option<&ValidatedPreparedInrouV1>,
    deadline: Instant,
) -> Result<Value> {
    let mut report = if args.operation == InrouCanaryOperation::ServiceMutation
        && outcome == "Applied"
        && applied.is_some()
    {
        let mut status_config = config.clone();
        status_config.torii_api_url = Url::parse(&format!("{public_root}/"))
            .wrap_err("failed to bind prepared Inrou status client")?;
        status_config.torii_request_timeout = deadline.saturating_duration_since(Instant::now());
        let status_client = IrohaClient::builder(status_config).build()?;
        verify_inrou_check_until(
            public_root,
            &status_client,
            stage,
            deadline,
            args.probe_scope,
        )?
    } else {
        report_value(
            "taira_inrou_canary",
            "ok",
            public_root,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Map::new(),
        )?
    };
    let object = report
        .as_object_mut()
        .ok_or_else(|| eyre!("prepared Inrou report root is not an object"))?;
    object.insert(
        "probe_scope".to_owned(),
        Value::String(args.probe_scope.label().to_owned()),
    );
    object.insert(
        "command".to_owned(),
        Value::String("taira_inrou_canary".to_owned()),
    );
    object.insert(
        "authorization_sha256".to_owned(),
        Value::String(envelope.binding.authorization_sha256.clone()),
    );
    object.insert(
        "authorization_nonce".to_owned(),
        Value::String(envelope.binding.authorization_nonce.clone()),
    );
    object.insert(
        "mutation_kind".to_owned(),
        Value::String(envelope.binding.kind.clone()),
    );
    object.insert(
        "mutation_phase".to_owned(),
        Value::String(envelope.binding.phase.clone()),
    );
    object.insert(
        "idempotency_key".to_owned(),
        Value::String(envelope.binding.idempotency_key.clone()),
    );
    object.insert(
        "operation".to_owned(),
        Value::String(envelope.operation.transaction().operation.clone()),
    );
    object.insert(
        "transaction_hash_hex".to_owned(),
        Value::String(
            envelope
                .operation
                .transaction()
                .transaction_hash_hex
                .clone(),
        ),
    );
    object.insert(
        "prepared_envelope_sha256".to_owned(),
        Value::String(hex::encode(Sha256::digest(envelope_bytes))),
    );
    object.insert(
        "prepared_envelope_size".to_owned(),
        Value::from(u64::try_from(envelope_bytes.len()).expect("bounded envelope")),
    );
    object.insert(
        "recovery_outcome".to_owned(),
        Value::String(outcome.to_owned()),
    );
    object.insert(
        "applied_block_height".to_owned(),
        applied_block_height.map(Value::from).unwrap_or(Value::Null),
    );
    object.insert(
        "evidence".to_owned(),
        evidence.map(Value::String).unwrap_or(Value::Null),
    );
    object.insert(
        "execution_expires_at_unix_ms".to_owned(),
        Value::from(envelope.binding.execution_expires_at_unix_ms),
    );
    object.insert(
        "fee_payment".to_owned(),
        json::to_value(&envelope.operation.transaction().fee_payment)?,
    );
    object.insert(
        "fee_quote".to_owned(),
        json::to_value(&envelope.operation.transaction().fee_quote)?,
    );
    object.insert(
        "mutation_mode".to_owned(),
        Value::String(stage.stage_mode.clone()),
    );
    Ok(report)
}

fn prove_inrou_predecessor_applied(
    config: &Config,
    args: &InrouCanary,
    public_root: &str,
    binding: &crate::soracloud::TairaMutationBindingV1,
    expected_fee_payment: &FeePaymentIntent,
    deadline: Instant,
) -> Result<()> {
    let fd = args
        .prerequisite_envelope_fd
        .ok_or_else(|| eyre!("Inrou preparation is missing its predecessor envelope"))?;
    let path = inherited_fd_path(fd)?;
    let file = File::open(path)
        .wrap_err_with(|| format!("failed to duplicate predecessor envelope FD {fd}"))?;
    let mut bytes = Vec::new();
    file.take(PREPARED_ENVELOPE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > PREPARED_ENVELOPE_MAX_BYTES
    {
        eyre::bail!("Inrou predecessor envelope is empty or oversized");
    }
    let (expected_kind, expected_operation) = args.operation.predecessor();
    let value = decode_exact_inrou_predecessor_v1(&bytes, expected_kind)?;
    let root = value
        .as_object()
        .ok_or_else(|| eyre!("Inrou predecessor envelope root is not an object"))?;
    let predecessor_binding = root
        .get("binding")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("Inrou predecessor envelope omits its binding"))?;
    let binding_string = |name: &str| {
        predecessor_binding
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("Inrou predecessor binding omits `{name}`"))
    };
    let expected_idempotency_key = write_canary_child_idempotency_key(
        &binding.authorization_nonce,
        &binding.phase,
        expected_kind,
    );
    if binding_string("authorization_sha256")? != binding.authorization_sha256
        || binding_string("authorization_nonce")? != binding.authorization_nonce
        || binding_string("kind")? != expected_kind
        || binding_string("phase")? != binding.phase
        || binding_string("idempotency_key")? != expected_idempotency_key
        || predecessor_binding
            .get("execution_expires_at_unix_ms")
            .and_then(Value::as_u64)
            != Some(binding.execution_expires_at_unix_ms)
        || root.get("public_root").and_then(Value::as_str) != Some(public_root)
        || (expected_kind != "write_canary"
            && root.get("probe_scope").and_then(Value::as_str) != Some(args.probe_scope.label()))
        || root.get("chain_id").and_then(Value::as_str) != Some(DEFAULT_CHAIN_ID)
        || root.get("network_id").and_then(Value::as_str)
            != Some(config.network_id.to_string().as_str())
        || root.get("authority").and_then(Value::as_str)
            != Some(config.account.to_string().as_str())
    {
        eyre::bail!("Inrou predecessor differs from the exact authorization and network");
    }
    let tagged = root
        .get("operation")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("Inrou predecessor omits its tagged operation"))?;
    let payload = tagged
        .get("envelope")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("Inrou predecessor omits its transaction envelope"))?;
    let expected_tag = match expected_kind {
        "write_canary" => "final_canary",
        "inrou_bundle_pin" => "inrou_bundle_pin",
        "inrou_guest_pin" => "inrou_guest_pin",
        "inrou_discovery_pin" => "inrou_discovery_pin",
        _ => return Err(eyre!("unsupported Inrou predecessor kind")),
    };
    if tagged.get("kind").and_then(Value::as_str) != Some(expected_tag)
        || payload.get("operation").and_then(Value::as_str) != Some(expected_operation)
        || payload.get("binding") != root.get("binding")
    {
        eyre::bail!("Inrou predecessor operation tag or binding is invalid");
    }
    let wire_hex = payload
        .get("signed_transaction_wire_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("Inrou predecessor omits its transaction wire"))?;
    let wire = hex::decode(wire_hex).wrap_err("Inrou predecessor wire is not hexadecimal")?;
    let transaction = SignedTransaction::decode_all_versioned(&wire)
        .wrap_err("Inrou predecessor is not a versioned SignedTransaction")?;
    transaction
        .verify_signature()
        .wrap_err("Inrou predecessor signature is invalid")?;
    let transaction_hash = hex::encode(transaction.hash().as_ref());
    let transaction_wire_sha256 = hex::encode(Sha256::digest(&wire));
    if wire.is_empty()
        || wire.len() > PREPARED_TRANSACTION_MAX_BYTES
        || hex::encode(&wire) != wire_hex
        || transaction.encode_wire_v1()? != wire
        || payload.get("transaction_hash_hex").and_then(Value::as_str)
            != Some(transaction_hash.as_str())
        || payload
            .get("signed_transaction_wire_sha256")
            .and_then(Value::as_str)
            != Some(transaction_wire_sha256.as_str())
        || transaction.authority() != &config.account
        || transaction.network_id() != Some(&config.network_id)
    {
        eyre::bail!("Inrou predecessor transaction identity is invalid");
    }
    let payload_fee_payment: FeePaymentIntent = json::from_value(
        payload
            .get("fee_payment")
            .cloned()
            .ok_or_else(|| eyre!("Inrou predecessor omits its fee payment"))?,
    )
    .wrap_err("Inrou predecessor fee payment is not exact typed V1 JSON")?;
    if payload.get("fee_payment") != Some(&json::to_value(&payload_fee_payment)?)
        || transaction.fee_payment_intent() != &payload_fee_payment
    {
        eyre::bail!("Inrou predecessor has a substituted fee-payment closure");
    }
    validate_expected_prepared_fee_payment(expected_fee_payment, &payload_fee_payment)?;
    let expected_binding_json = json::to_json(
        root.get("binding")
            .expect("predecessor binding was validated above"),
    )?;
    let binding_name = Name::from_str(PREPARED_BINDING_METADATA)?;
    if transaction
        .metadata()
        .get(&binding_name)
        .map(IrohaJson::get)
        .map(String::as_str)
        != Some(expected_binding_json.as_str())
    {
        eyre::bail!("Inrou predecessor transaction metadata has a substituted binding");
    }
    match expected_kind {
        "write_canary" => {
            let verified = verify_final_canary_prepared_operation_v1(
                &Value::Object(payload.clone()),
                &config.network_id,
                &config.account,
            )
            .wrap_err("Inrou predecessor final-canary executable authentication failed")?;
            if verified.hash() != transaction.hash() || verified.encode_wire_v1()? != wire {
                eyre::bail!("Inrou predecessor final-canary verifier selected different bytes");
            }
        }
        "inrou_bundle_pin" | "inrou_guest_pin" | "inrou_discovery_pin" => {
            let typed: PreparedInrouTransactionV1 =
                json::from_value(Value::Object(payload.clone()))
                    .wrap_err("Inrou predecessor operation is not exact typed V1 JSON")?;
            if json::to_value(&typed)? != Value::Object(payload.clone()) {
                eyre::bail!("Inrou predecessor operation is outside its typed V1 JSON closure");
            }
            let stage = crate::soracloud::load_taira_inrou_stage_identity(
                config,
                &args.stage_dir,
                args.mode,
            )?;
            if root.get("stage")
                != Some(&json::to_value(&PreparedInrouStageIdentityV1::from(
                    &stage,
                ))?)
            {
                eyre::bail!("Inrou predecessor retained-stage identity was substituted");
            }
            let prepared = crate::soracloud::PreparedSoracloudTransactionV1 {
                operation: typed.operation.clone(),
                wire: wire.clone(),
                tx_hash_hex: typed.transaction_hash_hex,
                fee_payment: typed.fee_payment,
                fee_quote: typed.fee_quote,
                binding: typed.binding,
            };
            let verified = prepared
                .decode_and_validate()
                .wrap_err("Inrou predecessor transaction closure is invalid")?;
            let prepared_operation = match expected_kind {
                "inrou_bundle_pin" => {
                    crate::soracloud::TairaInrouCanaryPreparedOperationV1::BundlePin
                }
                "inrou_guest_pin" => {
                    crate::soracloud::TairaInrouCanaryPreparedOperationV1::GuestPin
                }
                "inrou_discovery_pin" => {
                    crate::soracloud::TairaInrouCanaryPreparedOperationV1::DiscoveryPin
                }
                _ => unreachable!("matched exact Inrou predecessor kinds"),
            };
            crate::soracloud::verify_taira_inrou_prepared_transaction_identity_v1(
                &verified,
                prepared_operation,
                &stage,
                &expected_idempotency_key,
            )
            .wrap_err("Inrou predecessor executable authentication failed")?;
            validate_inrou_transaction_lifetime(
                &verified,
                &prepared.binding,
                PreparedLifetimeCheck::Structural,
            )?;
            if verified.hash() != transaction.hash() || verified.encode_wire_v1()? != wire {
                eyre::bail!("Inrou predecessor typed verifier selected different bytes");
            }
        }
        _ => return Err(eyre!("unsupported Inrou predecessor kind")),
    }
    let mut status_config = config.clone();
    status_config.torii_api_url = Url::parse(&format!("{public_root}/"))?;
    await_predecessor_applied(deadline, Duration::from_millis(200), |request_budget| {
        let client = IrohaClient::builder(status_config.clone())
            .build()?
            .with_request_deadline(deadline);
        let Some(status) = client.get_transaction_status_response_global(transaction.hash())?
        else {
            return Ok(false);
        };
        if status.hash != transaction_hash || status.scope != "global" {
            eyre::bail!("Inrou predecessor status differs from its exact identity or scope");
        }
        if prepared_recovery_status_is_final_failure(&status) {
            eyre::bail!("Inrou predecessor is terminally {}", status.status.kind);
        }
        if !matches!(
            status.status.kind.as_str(),
            "Queued" | "Approved" | "Committed" | "Applied" | "Rejected" | "Expired"
        ) {
            eyre::bail!("Inrou predecessor has unsupported status kind");
        }
        if !prepared_recovery_status_is_final_applied(&status) {
            return Ok(false);
        }
        if !status.status.block_height.is_some_and(|height| height > 0) {
            eyre::bail!("Applied Inrou predecessor omits its positive block height");
        }
        match verify_exact_committed_transaction(&client, &transaction, &wire) {
            Ok(()) => {}
            Err(error) if exact_transaction_details_not_found(&error) => return Ok(false),
            Err(error) => return Err(error),
        }
        if expected_kind == "write_canary" {
            return Ok(true);
        }
        let operation = match expected_kind {
            "inrou_bundle_pin" => crate::soracloud::TairaInrouCanaryPreparedOperationV1::BundlePin,
            "inrou_guest_pin" => crate::soracloud::TairaInrouCanaryPreparedOperationV1::GuestPin,
            "inrou_discovery_pin" => {
                crate::soracloud::TairaInrouCanaryPreparedOperationV1::DiscoveryPin
            }
            _ => return Err(eyre!("unsupported Inrou pin predecessor kind")),
        };
        match crate::soracloud::taira_inrou_canary_pin_readiness_v1(
            config,
            &args.stage_dir,
            public_root,
            request_budget.min(deadline.saturating_duration_since(Instant::now())),
            args.mode,
            operation,
        )? {
            crate::soracloud::TairaInrouCanaryPinReadinessV1::Approved(epoch) if epoch > 0 => {
                Ok(true)
            }
            crate::soracloud::TairaInrouCanaryPinReadinessV1::Approved(_) => {
                eyre::bail!("Inrou predecessor pin has an invalid zero approval epoch")
            }
            crate::soracloud::TairaInrouCanaryPinReadinessV1::Pending
            | crate::soracloud::TairaInrouCanaryPinReadinessV1::Missing => Ok(false),
        }
    })
}

fn decode_exact_inrou_predecessor_v1(bytes: &[u8], expected_kind: &str) -> Result<Value> {
    let (value, canonical) = match expected_kind {
        "write_canary" => {
            let envelope: PreparedMutationEnvelopeV1 = json::from_slice(bytes)
                .wrap_err("Inrou predecessor is not an exact prepared-mutation V1 envelope")?;
            if !matches!(
                &envelope.operation,
                PreparedTransactionOperationV1::FinalCanary(_)
            ) {
                eyre::bail!("Inrou predecessor is not the final-canary V1 variant");
            }
            (
                json::to_value(&envelope)?,
                canonical_prepared_envelope_bytes(&envelope)?,
            )
        }
        "inrou_bundle_pin" | "inrou_guest_pin" | "inrou_discovery_pin" => {
            let envelope: PreparedInrouEnvelopeV1 = json::from_slice(bytes)
                .wrap_err("Inrou predecessor is not an exact prepared-Inrou V1 envelope")?;
            let expected_variant = matches!(
                (&envelope.operation, expected_kind),
                (
                    PreparedInrouOperationV1::InrouBundlePin(_),
                    "inrou_bundle_pin"
                ) | (
                    PreparedInrouOperationV1::InrouGuestPin(_),
                    "inrou_guest_pin"
                ) | (
                    PreparedInrouOperationV1::InrouDiscoveryPin(_),
                    "inrou_discovery_pin"
                )
            );
            if !expected_variant {
                eyre::bail!("Inrou predecessor has the wrong prepared-Inrou V1 variant");
            }
            (
                json::to_value(&envelope)?,
                canonical_prepared_inrou_envelope_bytes(&envelope)?,
            )
        }
        _ => return Err(eyre!("unsupported Inrou predecessor kind")),
    };
    if canonical != bytes {
        eyre::bail!("Inrou predecessor envelope is not canonical newline JSON");
    }
    Ok(value)
}

fn verify_exact_committed_transaction(
    client: &IrohaClient,
    expected: &SignedTransaction,
    expected_wire: &[u8],
) -> Result<()> {
    let entrypoint_hash = expected.hash_as_entrypoint();
    let details = client.get_transaction_details(entrypoint_hash)?;
    let committed = &details.transaction;
    let TransactionEntrypoint::External(transaction) = committed.entrypoint() else {
        eyre::bail!("Applied predecessor resolves to a non-external entrypoint");
    };
    if committed.result().is_err()
        || transaction.hash() != expected.hash()
        || transaction.hash_as_entrypoint() != entrypoint_hash
        || transaction.encode_wire_v1()? != expected_wire
    {
        eyre::bail!("committed predecessor differs from its exact prepared transaction");
    }
    Ok(())
}
/// Read-only verification of one retained canonical Taira Inrou stage.
#[derive(clap::Args, Debug)]
pub struct InrouCheck {
    /// Candidate runtime qualification or complete public qualification.
    #[arg(long, value_enum, default_value = "public")]
    pub probe_scope: InrouProbeScope,
    /// Public or admitted loopback Torii root used for network preflight and route reads.
    ///
    /// Signed Soracloud status reads continue to use the Torii URL from the selected client
    /// configuration so validator-specific restart checks cannot collapse onto the public edge.
    #[arg(long, default_value = DEFAULT_PUBLIC_ROOT)]
    pub public_root: String,
    /// Owner-only stage created by `iroha taira inrou-stage` and retained after deployment.
    #[arg(long, value_name = "PATH")]
    pub stage_dir: PathBuf,
    /// Exact revision mode encoded by the retained stage.
    #[arg(long, value_enum)]
    pub mode: InrouCanaryMode,
    /// Maximum convergence time for signed status and all four route identities.
    #[arg(long, value_name = "SECS", default_value_t = 180)]
    pub timeout_secs: u64,
    /// Emit a stable JSON evidence receipt.
    #[arg(long)]
    pub json: bool,
}
impl Run for InrouCheck {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        validate_inrou_canary_timeout(self.timeout_secs)?;
        ensure_canonical_taira_client_identity(context.config())?;
        let _chain_discriminant = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        let stage = crate::soracloud::load_taira_inrou_stage_identity(
            context.config(),
            &self.stage_dir,
            self.mode,
        )?;
        let public_root = normalize_root_url(&self.public_root)?;
        self.probe_scope.validate_root(&public_root)?;
        preflight_taira_network_identity(&public_root, context.config())?;
        let receipt = verify_inrou_check_from_selected_status_origin(
            &public_root,
            context.config(),
            &stage,
            self.timeout_secs,
            self.probe_scope,
        )?;
        render_report(context, self.json, &receipt)?;
        if report_status(&receipt) != Some("ok") {
            eyre::bail!("Taira Inrou read-only check found hard failures");
        }
        Ok(())
    }
}

fn verify_inrou_check_from_selected_status_origin(
    public_root: &str,
    status_config: &Config,
    stage: &crate::soracloud::TairaInrouStageIdentity,
    timeout_secs: u64,
    probe_scope: InrouProbeScope,
) -> Result<Value> {
    let status_client = IrohaClient::builder(status_config.clone()).build()?;
    verify_inrou_check(
        public_root,
        &status_client,
        stage,
        timeout_secs,
        probe_scope,
    )
}
fn ensure_canonical_taira_client_identity(config: &Config) -> Result<()> {
    if config.chain.to_string() != DEFAULT_CHAIN_ID {
        eyre::bail!(
            "Taira Inrou canary requires canonical chain `{DEFAULT_CHAIN_ID}`; configured `{}`",
            config.chain
        );
    }
    if config.account_chain_discriminant != DEFAULT_CHAIN_DISCRIMINANT {
        eyre::bail!(
            "Taira Inrou canary requires chain discriminant {DEFAULT_CHAIN_DISCRIMINANT}; configured {}",
            config.account_chain_discriminant
        );
    }
    Ok(())
}
fn preflight_taira_network_identity(public_root: &str, config: &Config) -> Result<()> {
    let http = http_client()?;
    let puzzle_url = join_url(public_root, "/v1/accounts/faucet/puzzle")?;
    let puzzle = http_json(&http, reqwest::Method::GET, puzzle_url.as_str(), None)?;
    if puzzle.status != 200 {
        eyre::bail!(
            "Taira network-identity preflight returned HTTP {} from {}",
            puzzle.status,
            puzzle_url
        );
    }
    let body = puzzle
        .body
        .as_ref()
        .ok_or_else(|| eyre!("Taira network-identity preflight returned a non-JSON puzzle"))?;
    validate_puzzle_identity(body, &config.network_id, config.account_chain_discriminant)
        .map(|_| ())
}
#[derive(Debug)]
struct HttpJson {
    status: u16,
    body: Option<Value>,
}
#[derive(Debug)]
struct CanarySigner {
    key_pair: KeyPair,
    account_id: AccountId,
}
fn run_doctor(public_root: &str, scope: DoctorScope) -> Result<Value> {
    let public_root = normalize_root_url(public_root)?;
    let http = http_client()?;
    let mut checks = Vec::new();
    let mut warnings = Vec::new();
    let mut failures = Vec::new();
    let empty_object = norito::json!({});
    for (name, method, path, expected_statuses) in ROUTE_CHECKS {
        if !scope.includes_route(name) {
            continue;
        }
        let url = join_url(&public_root, path)?;
        let result = match method {
            RouteCheckMethod::Get => http_json(&http, reqwest::Method::GET, url.as_str(), None)?,
            RouteCheckMethod::GetReadiness => http_readiness(&http, url.as_str())?,
            RouteCheckMethod::PostEmptyObject => http_json(
                &http,
                reqwest::Method::POST,
                url.as_str(),
                Some(&empty_object),
            )?,
        };
        let status_ok = expected_statuses.contains(&result.status);
        let semantic_error = if status_ok {
            match *name {
                "readiness" => (result.body.as_ref().and_then(Value::as_str) != Some("Ready"))
                    .then(|| {
                        "/readyz did not return the exact plain-text Ready response".to_owned()
                    }),
                "status" => validate_public_status(result.body.as_ref()).err(),
                "time_now" => validate_time_snapshot(result.body.as_ref(), scope).err(),
                _ => None,
            }
        } else {
            None
        };
        let readiness_failure = (*name == "readiness" && !status_ok).then(|| {
            format!(
                "/readyz returned HTTP {}; error_code={}; expected 200",
                result.status,
                readiness_error_code(result.body.as_ref())
            )
        });
        let ok = status_ok && semantic_error.is_none();
        push_check(
            &mut checks,
            name,
            result.status,
            ok,
            semantic_error
                .clone()
                .or_else(|| readiness_failure.clone())
                .or_else(|| route_check_detail(expected_statuses)),
        );
        if !status_ok {
            failures.push(readiness_failure.unwrap_or_else(|| {
                format!(
                    "{name} returned HTTP {}; expected {}",
                    result.status,
                    expected_statuses
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(" or ")
                )
            }));
        } else if let Some(error) = semantic_error {
            failures.push(error);
        }
        if *name == "status" && ok {
            collect_status_warnings(result.body.as_ref(), &mut warnings);
        }
        if *name == "time_now" && ok && scope == DoctorScope::Basic {
            collect_time_warnings(result.body.as_ref(), &mut warnings);
        }
    }
    doctor_accounts::append_checks(&public_root, &mut checks, &mut failures)?;
    let mcp_url = join_url(&public_root, "/v1/mcp")?;
    let mcp_get = http_json(&http, reqwest::Method::GET, mcp_url.as_str(), None)?;
    let mcp_get_ok = mcp_get.status == 405;
    push_check(&mut checks, "mcp_get", mcp_get.status, mcp_get_ok, None);
    if !mcp_get_ok {
        failures.push(format!(
            "mcp_get returned HTTP {}; expected 405 for the POST-only MCP transport",
            mcp_get.status
        ));
    }
    let discovery = http_mcp_json(
        &http,
        mcp_url.as_str(),
        1,
        "server/discover",
        norito::json!({}),
    )?;
    let discovery_error = (discovery.status == 200)
        .then(|| validate_mcp_discovery_response(discovery.body.as_ref()).err())
        .flatten();
    let discovery_ok = discovery.status == 200 && discovery_error.is_none();
    push_check(
        &mut checks,
        "mcp_discovery",
        discovery.status,
        discovery_ok,
        discovery_error.clone(),
    );
    if !discovery_ok {
        failures.push(
            discovery_error.unwrap_or_else(|| {
                format!("MCP server/discover returned HTTP {}", discovery.status)
            }),
        );
    }
    let (tools_status, parsed_tool_names) = read_mcp_tool_catalog(&http, mcp_url.as_str())?;
    let tools_error = parsed_tool_names.as_ref().err().cloned();
    let tools_ok = tools_status == 200 && tools_error.is_none();
    push_check(
        &mut checks,
        "mcp_tools_list",
        tools_status,
        tools_ok,
        tools_error.clone(),
    );
    if !tools_ok {
        failures.push(
            tools_error.unwrap_or_else(|| format!("mcp_tools_list returned HTTP {tools_status}")),
        );
    } else {
        let tool_names = parsed_tool_names.expect("successful MCP tool parsing has one result");
        let missing: Vec<String> = REQUIRED_MCP_TOOLS
            .iter()
            .chain(FULL_MCP_TOOLS.iter().filter(|_| scope == DoctorScope::Full))
            .copied()
            .filter(|name| !tool_names.iter().any(|present| present == name))
            .map(str::to_owned)
            .collect();
        if missing.is_empty() {
            push_check(
                &mut checks,
                "mcp_required_tools",
                200,
                true,
                Some("all required curated tools are present".to_owned()),
            );
        } else {
            if !missing.is_empty() {
                failures.push(format!("MCP tools/list missing: {}", missing.join(", ")));
            }
            push_check(
                &mut checks,
                "mcp_required_tools",
                200,
                false,
                Some(format!("missing=[{}]", missing.join(", "))),
            );
        }
    }
    let status = if failures.is_empty() { "ok" } else { "fail" };
    let mut extra = Map::new();
    extra.insert("scope".into(), Value::from(scope.as_str()));
    report_value(
        "taira_doctor",
        status,
        &public_root,
        checks,
        warnings,
        failures,
        extra,
    )
}

/// The public-reset verifier consumes the producer's scoped check contract.
pub(super) fn doctor_expected_checks(
    scope: DoctorScope,
) -> Vec<(&'static str, u64, Option<String>)> {
    let mut checks = ROUTE_CHECKS
        .iter()
        .filter(|(name, _, _, _)| scope.includes_route(name))
        .map(|(name, _, _, statuses)| (*name, u64::from(statuses[0]), route_check_detail(statuses)))
        .collect::<Vec<_>>();
    checks.extend(doctor_accounts::expected());
    checks.extend([
        ("mcp_get", 405, None),
        ("mcp_discovery", 200, None),
        ("mcp_tools_list", 200, None),
        (
            "mcp_required_tools",
            200,
            Some("all required curated tools are present".to_owned()),
        ),
    ]);
    checks
}
#[derive(Clone, Debug)]
struct InrouProbeIdentity {
    service_name: String,
    service_version: String,
    route_host: String,
    route_path_prefix: String,
    healthcheck_path: String,
    stage_mode: String,
    bundle_hash: String,
    discovery_payload_dir: String,
    discovery_document_hash: String,
    discovery_content_cid: String,
    discovery_manifest_digest_hex: String,
    public_discovery_url: String,
    public_discovery_cid_host_url: String,
    deployment_bundle_hash: String,
    container_manifest_hash: String,
    service_manifest_hash: String,
    placement_targets: BTreeSet<iroha::data_model::soracloud::SoraInrouPlacementTargetV1>,
}
impl From<&crate::soracloud::TairaInrouStageIdentity> for InrouProbeIdentity {
    fn from(stage: &crate::soracloud::TairaInrouStageIdentity) -> Self {
        Self {
            service_name: stage.service_name.clone(),
            service_version: stage.service_version.clone(),
            route_host: stage.route_host.clone(),
            route_path_prefix: stage.route_path_prefix.clone(),
            healthcheck_path: stage.healthcheck_path.clone(),
            stage_mode: stage.stage_mode.clone(),
            bundle_hash: stage.bundle_hash.clone(),
            discovery_payload_dir: stage.discovery_payload_dir.clone(),
            discovery_document_hash: stage.discovery_document_hash.clone(),
            discovery_content_cid: stage.discovery_content_cid.clone(),
            discovery_manifest_digest_hex: stage.discovery_manifest_digest_hex.clone(),
            public_discovery_url: stage.public_discovery_url.clone(),
            public_discovery_cid_host_url: stage.public_discovery_cid_host_url.clone(),
            deployment_bundle_hash: stage.deployment_bundle_hash.clone(),
            container_manifest_hash: stage.container_manifest_hash.clone(),
            service_manifest_hash: stage.service_manifest_hash.clone(),
            placement_targets: stage.placement_targets.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize)]
struct InrouPublicDiscoveryDocumentV1 {
    schema_version: u16,
    service_name: String,
    service_version: String,
    execution_plane: String,
    runtime: String,
    route_host: String,
    path_prefix: String,
    base_url: String,
    #[norito(required)]
    healthcheck_path: Option<String>,
    #[norito(required)]
    healthcheck_url: Option<String>,
    service_manifest_hash: Hash,
    container_manifest_hash: Hash,
    deployment_bundle_hash: Hash,
}
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct InrouPublicDiscoveryV1 {
    schema_version: u16,
    service_name: String,
    service_version: String,
    execution_plane: String,
    runtime: String,
    route_host: String,
    path_prefix: String,
    base_url: String,
    #[norito(required)]
    healthcheck_path: Option<String>,
    #[norito(required)]
    healthcheck_url: Option<String>,
    service_manifest_hash: Hash,
    container_manifest_hash: Hash,
    deployment_bundle_hash: Hash,
    document_hash: Hash,
    content_cid: String,
    public_discovery_url: String,
    public_discovery_cid_host_url: String,
    manifest_digest_hex: String,
}
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct InrouPublicDiscoveryResponseV1 {
    schema_version: u16,
    service_name: String,
    current_version: String,
    requested_version: String,
    discovery: InrouPublicDiscoveryV1,
}
struct ExpectedInrouPublicDiscoveryV1 {
    response: InrouPublicDiscoveryResponseV1,
    document_bytes: Vec<u8>,
}
fn parse_exact_inrou_hash(field: &str, value: &str) -> Result<Hash> {
    let hash = Hash::from_str(value)
        .wrap_err_with(|| format!("retained Taira Inrou stage has invalid {field}"))?;
    if hash.to_string() != value {
        eyre::bail!("retained Taira Inrou stage has noncanonical {field}");
    }
    Ok(hash)
}
fn expected_inrou_public_discovery(
    deployment: &InrouProbeIdentity,
) -> Result<ExpectedInrouPublicDiscoveryV1> {
    let mut base_url = Url::parse(&format!("https://{}", deployment.route_host))
        .wrap_err("retained Taira Inrou route host cannot form a discovery base URL")?;
    base_url.set_path(&format!(
        "{}/",
        deployment.route_path_prefix.trim_end_matches('/')
    ));
    let base_url = base_url.to_string();
    let mut healthcheck_url =
        Url::parse(&base_url).wrap_err("retained Taira Inrou discovery base URL is invalid")?;
    healthcheck_url.set_path(&inrou_canary_health_path(
        &deployment.route_path_prefix,
        &deployment.healthcheck_path,
    ));
    let service_manifest_hash =
        parse_exact_inrou_hash("service_manifest_hash", &deployment.service_manifest_hash)?;
    let container_manifest_hash = parse_exact_inrou_hash(
        "container_manifest_hash",
        &deployment.container_manifest_hash,
    )?;
    let deployment_bundle_hash =
        parse_exact_inrou_hash("deployment_bundle_hash", &deployment.deployment_bundle_hash)?;
    let document = InrouPublicDiscoveryDocumentV1 {
        schema_version: 1,
        service_name: deployment.service_name.clone(),
        service_version: deployment.service_version.clone(),
        execution_plane: "HttpService".to_owned(),
        runtime: "Inrou".to_owned(),
        route_host: deployment.route_host.clone(),
        path_prefix: deployment.route_path_prefix.clone(),
        base_url: base_url.clone(),
        healthcheck_path: Some(deployment.healthcheck_path.clone()),
        healthcheck_url: Some(healthcheck_url.to_string()),
        service_manifest_hash,
        container_manifest_hash,
        deployment_bundle_hash,
    };
    let document_bytes = json::to_vec(&document)
        .wrap_err("failed to encode exact retained Taira Inrou discovery document")?;
    if u64::try_from(document_bytes.len()).unwrap_or(u64::MAX)
        > INROU_PUBLIC_DISCOVERY_RESPONSE_MAX_BYTES
    {
        eyre::bail!("retained Taira Inrou discovery document exceeds the V1 byte limit");
    }
    let document_hash = Hash::new(&document_bytes);
    if document_hash.to_string() != deployment.discovery_document_hash {
        eyre::bail!(
            "retained Taira Inrou discovery document hash does not bind its canonical bytes"
        );
    }
    let discovery = InrouPublicDiscoveryV1 {
        schema_version: document.schema_version,
        service_name: document.service_name,
        service_version: document.service_version,
        execution_plane: document.execution_plane,
        runtime: document.runtime,
        route_host: document.route_host,
        path_prefix: document.path_prefix,
        base_url: document.base_url,
        healthcheck_path: document.healthcheck_path,
        healthcheck_url: document.healthcheck_url,
        service_manifest_hash: document.service_manifest_hash,
        container_manifest_hash: document.container_manifest_hash,
        deployment_bundle_hash: document.deployment_bundle_hash,
        document_hash,
        content_cid: deployment.discovery_content_cid.clone(),
        public_discovery_url: deployment.public_discovery_url.clone(),
        public_discovery_cid_host_url: deployment.public_discovery_cid_host_url.clone(),
        manifest_digest_hex: deployment.discovery_manifest_digest_hex.clone(),
    };
    Ok(ExpectedInrouPublicDiscoveryV1 {
        response: InrouPublicDiscoveryResponseV1 {
            schema_version: 1,
            service_name: deployment.service_name.clone(),
            current_version: deployment.service_version.clone(),
            requested_version: deployment.service_version.clone(),
            discovery,
        },
        document_bytes,
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct InrouLocalPlacement {
    peer_id: String,
    validator_account_id: String,
    replica_slot: u16,
    placement_incarnation: String,
}
impl InrouLocalPlacement {
    fn to_json(&self) -> Value {
        norito::json!({
            "peer_id": (self.peer_id.clone()),
            "validator_account_id": (self.validator_account_id.clone()),
            "replica_slot": (self.replica_slot),
            "placement_incarnation": (self.placement_incarnation.clone())
        })
    }
}
fn exact_inrou_local_placement(
    root: &Map,
    deployment: &InrouProbeIdentity,
    authoritative_process_generation: u64,
) -> Result<InrouLocalPlacement, String> {
    let snapshot_value = root
        .get("runtime_manager")
        .and_then(Value::as_object)
        .and_then(|runtime| runtime.get("snapshot"))
        .ok_or_else(|| "runtime manager is missing its exact local snapshot".to_owned())?;
    let snapshot = json::from_value::<iroha_core::soracloud_runtime::SoracloudRuntimeSnapshot>(
        snapshot_value.clone(),
    )
    .map_err(|error| format!("runtime manager snapshot is not exact V1 JSON: {error}"))?;
    if snapshot.schema_version
        != iroha_core::soracloud_runtime::SORACLOUD_RUNTIME_SNAPSHOT_VERSION_V1
    {
        return Err("runtime manager snapshot is not schema version 1".to_owned());
    }
    let local_peer_id = snapshot
        .local_peer_id
        .as_deref()
        .ok_or_else(|| "runtime manager snapshot is missing local_peer_id".to_owned())?;
    let canonical_peer_id = local_peer_id
        .parse::<iroha_model_base::peer::PeerId>()
        .map_err(|error| format!("runtime manager local_peer_id is invalid: {error}"))?;
    if canonical_peer_id.to_string() != local_peer_id {
        return Err("runtime manager local_peer_id is not canonical".to_owned());
    }
    let versions = snapshot
        .services
        .get(&deployment.service_name)
        .ok_or_else(|| "runtime manager snapshot is missing the canary service".to_owned())?;
    if versions.len() != 1 {
        return Err(
            "runtime manager snapshot must contain exactly one revision for the canary service"
                .to_owned(),
        );
    }
    let plan = versions.get(&deployment.service_version).ok_or_else(|| {
        "runtime manager snapshot is missing the retained canary revision".to_owned()
    })?;
    let inrou = plan.inrou.as_ref().ok_or_else(|| {
        "runtime manager is missing the exact AArch64 Inrou canary plan".to_owned()
    })?;
    if plan.service_name != deployment.service_name
        || plan.service_version != deployment.service_version
        || plan.runtime != iroha::data_model::soracloud::SoraContainerRuntimeV1::Inrou
        || plan.execution_plane
            != iroha::data_model::soracloud::SoraServiceExecutionPlaneV1::HttpService
        || plan.role != iroha_core::soracloud_runtime::SoracloudRuntimeRevisionRole::Active
        || plan.traffic_percent != 100
        || plan.bundle_hash != deployment.bundle_hash
        || plan.bundle_path != "/app/server.py"
        || plan.entrypoint != "/app/server.py"
        || !plan.bundle_available_locally
        || plan.process_generation != Some(authoritative_process_generation)
        || plan.desired_replica_count != 4
        || plan.health_status != iroha::data_model::soracloud::SoraServiceHealthStatusV1::Healthy
        || plan.local_replicas.len() != 1
        || plan.rollout_handle.is_some()
        || inrou.selected_guest_isa != iroha::data_model::soracloud::SoraInrouGuestIsaV1::Aarch64
        || inrou.kernel_image_path != "/inrou/aarch64/vmlinux"
        || inrou.rootfs_image_path != "/inrou/aarch64/rootfs.ext4"
        || inrou.initrd_image_path.as_deref() != Some("/inrou/aarch64/initrd.img")
        || inrou.root_volume_name != "root_disk"
    {
        return Err(
            "runtime manager does not expose the exact retained healthy AArch64 Inrou canary revision"
                .to_owned(),
        );
    }
    let replica = &plan.local_replicas[0];
    if plan.local_replica_slots.as_slice() != [replica.replica_slot]
        || !(1..=4).contains(&replica.replica_slot)
        || !replica.host_availability.is_available()
        || replica.health_status != iroha::data_model::soracloud::SoraServiceHealthStatusV1::Healthy
        || replica.peer_id != local_peer_id
        || !replica.pid.is_some_and(|pid| pid > 0)
        || replica.listen_base_url.is_none()
        || replica.last_error.is_some()
    {
        return Err(
            "runtime manager local replica is not the exact healthy placement for this host"
                .to_owned(),
        );
    }
    let validator_account = AccountId::parse_encoded(&replica.validator_account_id)
        .map_err(|error| format!("local placement validator account is invalid: {error}"))?;
    if validator_account.to_string() != replica.validator_account_id {
        return Err("local placement validator account is not canonical".to_owned());
    }
    let replica_peer = replica
        .peer_id
        .parse::<iroha_model_base::peer::PeerId>()
        .map_err(|error| format!("local placement peer ID is invalid: {error}"))?;
    if replica_peer.to_string() != replica.peer_id {
        return Err("local placement peer ID is not canonical".to_owned());
    }
    if validator_account.try_signatory().is_none() {
        return Err("local placement validator account must be single-signatory".to_owned());
    }
    let placement_target = iroha::data_model::soracloud::SoraInrouPlacementTargetV1 {
        validator_account_id: validator_account,
        peer_id: replica.peer_id.clone(),
    };
    if !deployment.placement_targets.contains(&placement_target) {
        return Err(
            "local placement account/peer pair is absent from the retained stage allowlist"
                .to_owned(),
        );
    }
    let placement_incarnation = Hash::from_str(&replica.placement_incarnation)
        .map_err(|error| format!("local placement incarnation is invalid: {error}"))?;
    if placement_incarnation.to_string() != replica.placement_incarnation {
        return Err("local placement incarnation is not canonical".to_owned());
    }
    let mut zero_prehash_sentinel = [0_u8; Hash::LENGTH];
    zero_prehash_sentinel[Hash::LENGTH - 1] = 1;
    if <[u8; Hash::LENGTH]>::from(placement_incarnation) == zero_prehash_sentinel {
        return Err("local placement incarnation must not be the zero prehash sentinel".to_owned());
    }
    Ok(InrouLocalPlacement {
        peer_id: replica.peer_id.clone(),
        validator_account_id: replica.validator_account_id.clone(),
        replica_slot: replica.replica_slot,
        placement_incarnation: replica.placement_incarnation.clone(),
    })
}
fn validate_exact_inrou_canary_status(
    status: &Value,
    deployment: &InrouProbeIdentity,
) -> Result<(u64, u64, InrouLocalPlacement), String> {
    if !crate::soracloud::is_taira_inrou_canary_service_version(&deployment.service_version) {
        return Err("retained Taira Inrou stage has a noncanonical revision identity".to_owned());
    }
    validate_soracloud_status(Some(status))?;
    let root = status
        .as_object()
        .ok_or_else(|| "Soracloud status response is not an object".to_owned())?;
    if root.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("Soracloud status is not canonical schema version 1".to_owned());
    }
    if root
        .get("runtime_manager")
        .and_then(Value::as_object)
        .and_then(|runtime| runtime.get("available"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("runtime manager is unavailable".to_owned());
    }
    let topology = root
        .get("hosted_http_topology")
        .and_then(Value::as_object)
        .ok_or_else(|| "Soracloud status is missing hosted HTTP topology".to_owned())?;
    let active_adverts = topology
        .get("active_capability_adverts")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Soracloud status is missing exact active_capability_adverts".to_owned())?;
    let hosted_replicas = topology
        .get("hosted_replica_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Soracloud status is missing exact hosted_replica_count".to_owned())?;
    let placed_hosts = topology
        .get("placed_host_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Soracloud status is missing exact placed_host_count".to_owned())?;
    let unavailable_replicas = topology
        .get("unavailable_replica_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Soracloud status is missing exact unavailable_replica_count".to_owned())?;
    if active_adverts != 4 || placed_hosts != 4 || hosted_replicas != 4 || unavailable_replicas != 0
    {
        return Err(format!(
            "requires exactly four available Inrou hosts and placements (adverts={active_adverts}, placed_hosts={placed_hosts}, replicas={hosted_replicas}, unavailable_replicas={unavailable_replicas})"
        ));
    }
    let services = root
        .get("control_plane")
        .and_then(Value::as_object)
        .and_then(|control_plane| control_plane.get("services"))
        .and_then(Value::as_array)
        .ok_or_else(|| "Soracloud status is missing control-plane services".to_owned())?;
    let mut matching_services = services.iter().filter(|service| {
        service.get("service_name").and_then(Value::as_str)
            == Some(deployment.service_name.as_str())
    });
    let service = matching_services.next().ok_or_else(|| {
        format!(
            "canary service `{}` is not present in authoritative status",
            deployment.service_name
        )
    })?;
    if matching_services.next().is_some() {
        return Err(format!(
            "canary service `{}` appears more than once in authoritative status",
            deployment.service_name
        ));
    }
    if service.get("current_version").and_then(Value::as_str)
        != Some(deployment.service_version.as_str())
    {
        return Err("authoritative canary version does not match the retained stage".to_owned());
    }
    if service.get("config_entry_count").and_then(Value::as_u64) != Some(2)
        || service
            .get("public_discovery_content_cid")
            .and_then(Value::as_str)
            != Some(deployment.discovery_content_cid.as_str())
        || service.get("public_discovery_url").and_then(Value::as_str)
            != Some(deployment.public_discovery_url.as_str())
        || service
            .get("public_discovery_cid_host_url")
            .and_then(Value::as_str)
            != Some(deployment.public_discovery_cid_host_url.as_str())
    {
        return Err(
            "authoritative canary status does not expose the exact two-config discovery identity"
                .to_owned(),
        );
    }
    let (expected_action, revision_count_is_valid): (&str, fn(u64) -> bool) =
        match deployment.stage_mode.as_str() {
            "deploy" => ("Deploy", |count| count == 1),
            "upgrade" => ("Upgrade", |count| count >= 2),
            other => return Err(format!("unsupported Inrou mutation mode `{other}`")),
        };
    let revision_count = service
        .get("revision_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| "authoritative canary status is missing revision_count".to_owned())?;
    if !revision_count_is_valid(revision_count) {
        return Err(format!(
            "authoritative canary revision count {revision_count} is invalid after {}",
            deployment.stage_mode,
        ));
    }
    if !service.get("active_rollout").is_some_and(Value::is_null) {
        return Err("Taira Inrou canary must report an explicit null active_rollout".to_owned());
    }
    match deployment.stage_mode.as_str() {
        "deploy" => {
            if !service.get("last_rollout").is_some_and(Value::is_null) {
                return Err(
                    "initial Taira Inrou deploy must report an explicit null last_rollout"
                        .to_owned(),
                );
            }
        }
        "upgrade" => {
            let rollout = service
                .get("last_rollout")
                .and_then(Value::as_object)
                .ok_or_else(|| "Taira Inrou upgrade is missing its promoted rollout".to_owned())?;
            let baseline_version = rollout
                .get("baseline_version")
                .and_then(Value::as_str)
                .filter(|version| {
                    crate::soracloud::is_taira_inrou_canary_service_version(version)
                        && *version != deployment.service_version.as_str()
                });
            let promoted = baseline_version.is_some()
                && rollout.get("candidate_version").and_then(Value::as_str)
                    == Some(deployment.service_version.as_str())
                && rollout.get("canary_percent").and_then(Value::as_u64) == Some(100)
                && rollout.get("traffic_percent").and_then(Value::as_u64) == Some(100)
                && rollout
                    .get("stage")
                    .and_then(|stage| tagged_enum_name(stage, "stage"))
                    == Some("Promoted");
            if !promoted {
                return Err(
                    "Taira Inrou upgrade rollout is not an exact promoted immutable revision transition"
                        .to_owned(),
                );
            }
        }
        _ => unreachable!("mutation mode was validated above"),
    }
    let revision = service
        .get("latest_revision")
        .and_then(Value::as_object)
        .ok_or_else(|| "canary service is missing its latest revision".to_owned())?;
    for (field, expected) in [
        (
            "container_manifest_hash",
            deployment.container_manifest_hash.as_str(),
        ),
        (
            "service_manifest_hash",
            deployment.service_manifest_hash.as_str(),
        ),
    ] {
        let actual = revision
            .get(field)
            .and_then(|value| json::from_value::<Hash>(value.clone()).ok())
            .map(|hash| hash.to_string());
        if actual.as_deref() != Some(expected) {
            return Err(format!(
                "authoritative {field} does not match the fully revalidated retained stage"
            ));
        }
    }
    let canonical = revision.get("replicas").and_then(Value::as_u64) == Some(4)
        && revision.get("service_version").and_then(Value::as_str)
            == Some(deployment.service_version.as_str())
        && revision
            .get("action")
            .and_then(|action| tagged_enum_name(action, "action"))
            == Some(expected_action)
        && revision
            .get("runtime")
            .and_then(|runtime| tagged_enum_name(runtime, "runtime"))
            == Some("Inrou")
        && revision
            .get("execution_plane")
            .and_then(|plane| tagged_enum_name(plane, "execution_plane"))
            == Some("HttpService")
        && revision.get("route_host").and_then(Value::as_str)
            == Some(deployment.route_host.as_str())
        && revision.get("route_path_prefix").and_then(Value::as_str)
            == Some(deployment.route_path_prefix.as_str())
        && revision.get("route_service_port").and_then(Value::as_u64)
            == Some(INROU_CANARY_SERVICE_PORT_V1)
        && revision.get("route_visibility").and_then(Value::as_str) == Some("Public")
        && revision.get("route_tls_mode").and_then(Value::as_str) == Some("Required");
    let canonical = canonical
        && revision
            .get("public_discovery_content_cid")
            .and_then(Value::as_str)
            == Some(deployment.discovery_content_cid.as_str())
        && revision.get("public_discovery_url").and_then(Value::as_str)
            == Some(deployment.public_discovery_url.as_str())
        && revision
            .get("public_discovery_cid_host_url")
            .and_then(Value::as_str)
            == Some(deployment.public_discovery_cid_host_url.as_str());
    if !canonical {
        return Err(
            "authoritative canary revision differs from the canonical four-replica Inrou route"
                .to_owned(),
        );
    }
    let authoritative_process_generation = revision
        .get("process_generation")
        .and_then(Value::as_u64)
        .filter(|generation| *generation > 0)
        .ok_or_else(|| {
            "authoritative canary revision has no positive process generation".to_owned()
        })?;
    let local_placement =
        exact_inrou_local_placement(root, deployment, authoritative_process_generation)?;
    Ok((active_adverts, hosted_replicas, local_placement))
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct InrouHealthIdentity {
    replica_slot: u64,
    identity: String,
    response_sha256: String,
    app_data_marker_sha256: String,
    boot_sequence: u64,
    guest_boot_id_sha256: String,
}
fn exact_inrou_health_identity(
    body: &Value,
    deployment: &InrouProbeIdentity,
) -> Option<InrouHealthIdentity> {
    let object = body.as_object()?;
    if object.len() != 9 {
        return None;
    }
    let schema_version = object.get("schema_version").and_then(Value::as_u64)?;
    let service = object.get("service").and_then(Value::as_str)?;
    let service_version = object.get("service_version").and_then(Value::as_str)?;
    let runtime = object.get("runtime").and_then(Value::as_str)?;
    let replica_slot = object.get("replica_slot").and_then(Value::as_u64)?;
    let identity = object.get("identity").and_then(Value::as_str)?;
    let app_data_marker_sha256 = object
        .get("app_data_marker_sha256")
        .and_then(Value::as_str)?;
    let boot_sequence = object.get("boot_sequence").and_then(Value::as_u64)?;
    let guest_boot_id_sha256 = object.get("guest_boot_id_sha256").and_then(Value::as_str)?;
    let expected_identity = format!("{}:replica:{replica_slot}", deployment.service_name);
    if schema_version != 1
        || service != deployment.service_name.as_str()
        || service_version != deployment.service_version.as_str()
        || runtime != "Inrou"
        || !(1..=4).contains(&replica_slot)
        || identity != expected_identity
        || boot_sequence == 0
        || validate_sha256_argument(app_data_marker_sha256).is_err()
        || validate_sha256_argument(guest_boot_id_sha256).is_err()
    {
        return None;
    }
    let encoded = json::to_vec(body).ok()?;
    Some(InrouHealthIdentity {
        replica_slot,
        identity: identity.to_owned(),
        response_sha256: hex::encode(Sha256::digest(encoded)),
        app_data_marker_sha256: app_data_marker_sha256.to_owned(),
        boot_sequence,
        guest_boot_id_sha256: guest_boot_id_sha256.to_owned(),
    })
}
fn retain_exact_inrou_health_identity(
    identities: &mut BTreeMap<u64, InrouHealthIdentity>,
    identity: InrouHealthIdentity,
) -> Result<(), String> {
    if let Some(previous) = identities.get(&identity.replica_slot) {
        if previous != &identity {
            return Err(format!(
                "replica slot {} returned conflicting durable health evidence",
                identity.replica_slot
            ));
        }
        return Ok(());
    }
    identities.insert(identity.replica_slot, identity);
    Ok(())
}
fn inrou_canary_health_path(route_prefix: &str, healthcheck_path: &str) -> String {
    format!(
        "{}/{}",
        route_prefix.trim_end_matches('/'),
        healthcheck_path.trim_start_matches('/')
    )
}
fn inrou_public_discovery_authority_url(
    public_root: &str,
    service_name: &str,
    service_version: Option<&str>,
) -> Result<Url> {
    let mut url = join_url(public_root, "/v1/soracloud/services/")?;
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| eyre!("public root cannot carry encoded discovery identity segments"))?;
    segments.pop_if_empty().push(service_name);
    if let Some(service_version) = service_version {
        segments.push("revisions").push(service_version);
    }
    segments.push("public-discovery");
    drop(segments);
    Ok(url)
}
fn read_bounded_inrou_public_response(
    response: reqwest::blocking::Response,
    context: &str,
) -> Result<(u16, reqwest::header::HeaderMap, Vec<u8>)> {
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|length| length > INROU_PUBLIC_DISCOVERY_RESPONSE_MAX_BYTES)
    {
        eyre::bail!("{context} exceeds the V1 byte limit");
    }
    let headers = response.headers().clone();
    let mut bytes = Vec::new();
    response
        .take(INROU_PUBLIC_DISCOVERY_RESPONSE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .wrap_err_with(|| format!("failed to read {context}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > INROU_PUBLIC_DISCOVERY_RESPONSE_MAX_BYTES {
        eyre::bail!("{context} exceeds the V1 byte limit");
    }
    Ok((status, headers, bytes))
}
fn has_one_exact_inrou_header(
    headers: &reqwest::header::HeaderMap,
    name: &'static str,
    expected: &str,
) -> bool {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected)
        && values.next().is_none()
}
fn inrou_request_budget(deadline: Instant) -> Result<Duration> {
    // One status, one health and four discovery requests share the original clock.
    let budget =
        (deadline.saturating_duration_since(Instant::now()) / 6).min(Duration::from_secs(5));
    if budget.is_zero() {
        eyre::bail!("Taira Inrou verification deadline elapsed");
    }
    Ok(budget)
}
fn fetch_inrou_public_discovery_authority(
    http: &HttpClient,
    url: Url,
    expected: &InrouPublicDiscoveryResponseV1,
    context: &str,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let response = http
        .get(url.clone())
        .timeout(inrou_request_budget(deadline)?)
        .header(reqwest::header::ACCEPT, INROU_PUBLIC_DISCOVERY_CONTENT_TYPE)
        .send()
        .wrap_err_with(|| format!("{context} request failed for {url}"))?;
    let (status, headers, bytes) = read_bounded_inrou_public_response(response, context)?;
    if status != 200 {
        eyre::bail!("{context} returned HTTP {status}; redirects are not accepted");
    }
    if !has_one_exact_inrou_header(
        &headers,
        reqwest::header::CONTENT_TYPE.as_str(),
        INROU_PUBLIC_DISCOVERY_CONTENT_TYPE,
    ) {
        eyre::bail!("{context} did not return exact application/json content type");
    }
    let decoded = json::from_slice::<InrouPublicDiscoveryResponseV1>(&bytes)
        .wrap_err_with(|| format!("{context} is not exact V1 discovery JSON"))?;
    if &decoded != expected {
        eyre::bail!("{context} differs from the fully revalidated retained stage");
    }
    Ok(bytes)
}
fn fetch_exact_inrou_public_discovery_document(
    http: &HttpClient,
    public_root: &str,
    published_url: &str,
    expected_host: &str,
    expected_content_cid: &str,
    expected_document_hash: &Hash,
    expected_bytes: &[u8],
    context: &str,
    deadline: Instant,
) -> Result<()> {
    let published = Url::parse(published_url)
        .wrap_err_with(|| format!("{context} has an invalid published URL"))?;
    if published.scheme() != "https"
        || !published.username().is_empty()
        || published.password().is_some()
        || published.host_str() != Some(expected_host)
        || published.port().is_some()
        || published.query().is_some()
        || published.fragment().is_some()
    {
        eyre::bail!("{context} has a noncanonical published URL identity");
    }
    let mut request_url = join_url(public_root, published.path())?;
    request_url.set_query(None);
    request_url.set_fragment(None);
    let response = http
        .get(request_url.clone())
        .timeout(inrou_request_budget(deadline)?)
        .header(reqwest::header::ACCEPT, INROU_PUBLIC_DISCOVERY_CONTENT_TYPE)
        .header(reqwest::header::HOST, expected_host)
        .send()
        .wrap_err_with(|| format!("{context} request failed for {request_url}"))?;
    let (status, headers, bytes) = read_bounded_inrou_public_response(response, context)?;
    if status != 200 {
        eyre::bail!("{context} returned HTTP {status}; redirects are not accepted");
    }
    let expected_length = expected_bytes.len().to_string();
    let expected_etag = format!("\"{expected_document_hash}\"");
    for (name, expected) in [
        (
            reqwest::header::CONTENT_TYPE.as_str(),
            INROU_PUBLIC_DISCOVERY_CONTENT_TYPE,
        ),
        (
            reqwest::header::CONTENT_LENGTH.as_str(),
            expected_length.as_str(),
        ),
        (
            INROU_PUBLIC_DISCOVERY_CONTENT_CID_HEADER,
            expected_content_cid,
        ),
        (
            reqwest::header::CACHE_CONTROL.as_str(),
            INROU_PUBLIC_DISCOVERY_CACHE_CONTROL,
        ),
        (reqwest::header::ETAG.as_str(), expected_etag.as_str()),
        ("x-content-type-options", "nosniff"),
    ] {
        if !has_one_exact_inrou_header(&headers, name, expected) {
            eyre::bail!("{context} has a missing, duplicate, or substituted `{name}` header");
        }
    }
    if bytes != expected_bytes || Hash::new(&bytes) != *expected_document_hash {
        eyre::bail!("{context} bytes or document hash differ from the retained stage");
    }
    Ok(())
}
fn verify_inrou_public_discovery(
    http: &HttpClient,
    public_root: &str,
    deployment: &InrouProbeIdentity,
    deadline: Instant,
) -> Result<u16> {
    let expected = expected_inrou_public_discovery(deployment)?;
    if deployment.discovery_payload_dir != "payloads/discovery" {
        eyre::bail!("retained Taira Inrou discovery payload directory is not canonical V1");
    }
    let expected_path = format!(
        "/sorafs/cid/{}/index.json",
        deployment.discovery_content_cid
    );
    let path_url = Url::parse(&deployment.public_discovery_url)
        .wrap_err("retained Taira Inrou path-gateway discovery URL is invalid")?;
    if path_url.path() != expected_path {
        eyre::bail!("retained Taira Inrou path-gateway discovery URL has substituted identity");
    }
    let expected_cid_host = format!("{}.sorafs.taira.sora.org", deployment.discovery_content_cid);
    let cid_host_url = Url::parse(&deployment.public_discovery_cid_host_url)
        .wrap_err("retained Taira Inrou CID-host discovery URL is invalid")?;
    if cid_host_url.path() != "/index.json" {
        eyre::bail!("retained Taira Inrou CID-host discovery URL has substituted identity");
    }
    let current_url =
        inrou_public_discovery_authority_url(public_root, &deployment.service_name, None)?;
    let revision_url = inrou_public_discovery_authority_url(
        public_root,
        &deployment.service_name,
        Some(&deployment.service_version),
    )?;
    let current_bytes = fetch_inrou_public_discovery_authority(
        http,
        current_url,
        &expected.response,
        "current Taira Inrou public-discovery authority",
        deadline,
    )?;
    let revision_bytes = fetch_inrou_public_discovery_authority(
        http,
        revision_url,
        &expected.response,
        "revision Taira Inrou public-discovery authority",
        deadline,
    )?;
    if current_bytes != revision_bytes {
        eyre::bail!("current and revision Taira Inrou discovery authority bytes differ");
    }
    fetch_exact_inrou_public_discovery_document(
        http,
        public_root,
        &deployment.public_discovery_url,
        &deployment.route_host,
        &deployment.discovery_content_cid,
        &expected.response.discovery.document_hash,
        &expected.document_bytes,
        "Taira Inrou path-gateway discovery document",
        deadline,
    )?;
    fetch_exact_inrou_public_discovery_document(
        http,
        public_root,
        &deployment.public_discovery_cid_host_url,
        &expected_cid_host,
        &deployment.discovery_content_cid,
        &expected.response.discovery.document_hash,
        &expected.document_bytes,
        "Taira Inrou CID-host discovery document",
        deadline,
    )?;
    Ok(200)
}
struct InrouProbeObservation {
    health_path: String,
    active_host_adverts: u64,
    hosted_replica_count: u64,
    checks: Vec<Value>,
    failures: Vec<String>,
    replica_identities: Value,
    local_placement: Option<InrouLocalPlacement>,
}
fn probe_inrou_service(
    public_root: &str,
    status_client: &IrohaClient,
    deployment: &InrouProbeIdentity,
    deadline: Instant,
    probe_scope: InrouProbeScope,
) -> Result<InrouProbeObservation> {
    probe_scope.validate_root(public_root)?;
    let health_path =
        inrou_canary_health_path(&deployment.route_path_prefix, &deployment.healthcheck_path);
    let health_base = join_url(public_root, &health_path)?;
    // Keep one connection pool for the entire observation. Each dispatch below
    // derives its own timeout from the same absolute deadline.
    let http = HttpClient::builder()
        .no_proxy()
        .user_agent("iroha-taira-inrou-probe/1")
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .wrap_err("failed to build Taira Inrou verification HTTP client")?;
    let mut nonce = 0_u64;
    let mut status_ready = false;
    let mut active_adverts = 0_u64;
    let mut hosted_replicas = 0_u64;
    let mut local_placement = None;
    let mut last_status_code = 0_u16;
    let mut last_status_error = "status not observed".to_owned();
    let mut last_route_code = 0_u16;
    let mut last_route_error = "route not observed".to_owned();
    let mut current_route_ready = false;
    let mut discovery_ready = probe_scope == InrouProbeScope::Candidate;
    let mut last_discovery_code = 0_u16;
    let mut last_discovery_error = "public discovery not observed".to_owned();
    let mut health_identity_conflict = false;
    let mut identities = BTreeMap::<u64, InrouHealthIdentity>::new();
    while Instant::now() < deadline
        && (!status_ready || !current_route_ready || identities.len() < 4 || !discovery_ready)
    {
        let Ok(request_budget) = inrou_request_budget(deadline) else {
            break;
        };
        let mut bounded_status = status_client.to_builder();
        bounded_status.torii_request_timeout = request_budget;
        let bounded_status = bounded_status.build()?.with_request_deadline(deadline);
        status_ready = false;
        current_route_ready = false;
        active_adverts = 0;
        hosted_replicas = 0;
        local_placement = None;
        match account_signed_soracloud_status(&bounded_status) {
            Ok(response) => {
                last_status_code = response.status;
                match response
                    .body
                    .as_ref()
                    .ok_or_else(|| "Soracloud status returned non-JSON".to_owned())
                    .and_then(|status| validate_exact_inrou_canary_status(status, deployment))
                {
                    Ok((adverts, replicas, placement)) if response.status == 200 => {
                        status_ready = true;
                        active_adverts = adverts;
                        hosted_replicas = replicas;
                        local_placement = Some(placement);
                        last_status_error.clear();
                    }
                    Ok(_) => last_status_error = format!("HTTP {}", response.status),
                    Err(error) => last_status_error = error,
                }
            }
            Err(error) => last_status_error = format!("{error:#}"),
        }
        let mut health_url = health_base.clone();
        health_url
            .query_pairs_mut()
            .append_pair("taira_inrou_probe", &nonce.to_string());
        nonce = nonce.saturating_add(1);
        let Ok(request_budget) = inrou_request_budget(deadline) else {
            break;
        };
        let route_response = http
            .get(health_url)
            .timeout(request_budget)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::HOST, deployment.route_host.as_str())
            .send();
        match route_response {
            Ok(response) => {
                last_route_code = response.status().as_u16();
                let response = match decode_inrou_canary_health_response(response) {
                    Ok(response) => response,
                    Err(error) => {
                        last_route_error = format!("{error:#}");
                        if !status_ready || !current_route_ready || identities.len() < 4 {
                            std::thread::sleep(
                                Duration::from_millis(200)
                                    .min(deadline.saturating_duration_since(Instant::now())),
                            );
                        }
                        continue;
                    }
                };
                if response.status != 200 {
                    last_route_error = format!("HTTP {}", response.status);
                    if !status_ready || !current_route_ready || identities.len() < 4 {
                        std::thread::sleep(
                            Duration::from_millis(200)
                                .min(deadline.saturating_duration_since(Instant::now())),
                        );
                    }
                    continue;
                }
                let identity = response
                    .body
                    .as_ref()
                    .and_then(|body| exact_inrou_health_identity(body, deployment));
                if let Some(identity) = identity {
                    if let Err(error) =
                        retain_exact_inrou_health_identity(&mut identities, identity)
                    {
                        health_identity_conflict = true;
                        last_route_error = error;
                    } else {
                        current_route_ready = true;
                        if !health_identity_conflict {
                            last_route_error.clear();
                        }
                    }
                } else {
                    last_route_error =
                        "health response violated the canary identity contract".to_owned();
                }
            }
            Err(error) => last_route_error = format!("{error:#}"),
        }
        if probe_scope == InrouProbeScope::Public
            && status_ready
            && current_route_ready
            && identities.len() == 4
            && !health_identity_conflict
        {
            match verify_inrou_public_discovery(&http, public_root, deployment, deadline) {
                Ok(status) => {
                    discovery_ready = true;
                    last_discovery_code = status;
                    last_discovery_error.clear();
                }
                Err(error) => {
                    discovery_ready = false;
                    last_discovery_error = format!("{error:#}");
                }
            }
        }
        if !status_ready || !current_route_ready || identities.len() < 4 || !discovery_ready {
            std::thread::sleep(
                Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "inrou_authoritative_status",
        last_status_code,
        status_ready,
        Some(if status_ready {
            format!("active_adverts={active_adverts}, hosted_replicas={hosted_replicas}")
        } else {
            last_status_error.clone()
        }),
    );
    let marker_count = identities
        .values()
        .map(|identity| identity.app_data_marker_sha256.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let guest_boot_id_count = identities
        .values()
        .map(|identity| identity.guest_boot_id_sha256.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let routes_ready = current_route_ready
        && last_route_code == 200
        && !health_identity_conflict
        && identities.len() == 4
        && marker_count == 4
        && guest_boot_id_count == 4;
    push_check(
        &mut checks,
        "inrou_public_routes",
        last_route_code,
        routes_ready,
        Some(if routes_ready {
            "observed distinct durable identities and guest boots for replica slots 1, 2, 3, and 4"
                .to_owned()
        } else {
            format!(
                "observed {}/4 replica identities, {marker_count} durable markers, and {guest_boot_id_count} guest boots; {last_route_error}",
                identities.len(),
            )
        }),
    );
    if probe_scope == InrouProbeScope::Public {
        push_check(
            &mut checks,
            "inrou_public_discovery",
            last_discovery_code,
            discovery_ready,
            Some(if discovery_ready {
                "current and revision authority plus public path and CID-host bytes, headers, and hash are exact"
                .to_owned()
            } else {
                last_discovery_error.clone()
            }),
        );
    }
    let mut failures = Vec::new();
    if !status_ready {
        failures.push(format!(
            "authoritative Inrou status did not converge: {last_status_error}"
        ));
    }
    if !routes_ready {
        failures.push(format!(
            "public Inrou route did not prove four distinct durable replicas: {last_route_error}"
        ));
    }
    if !discovery_ready {
        failures.push(format!(
            "public Inrou discovery did not converge: {last_discovery_error}"
        ));
    }
    let replica_identities = Value::Array(
        identities
            .into_iter()
            .map(|(slot, identity)| {
                norito::json!({
                    "replica_slot": (slot),
                    "identity": (identity.identity),
                    "response_sha256": (identity.response_sha256),
                    "app_data_marker_sha256": (identity.app_data_marker_sha256),
                    "boot_sequence": (identity.boot_sequence),
                    "guest_boot_id_sha256": (identity.guest_boot_id_sha256)
                })
            })
            .collect(),
    );
    Ok(InrouProbeObservation {
        health_path,
        active_host_adverts: active_adverts,
        hosted_replica_count: hosted_replicas,
        checks,
        failures,
        replica_identities,
        local_placement,
    })
}
fn verify_inrou_check(
    public_root: &str,
    status_client: &IrohaClient,
    stage: &crate::soracloud::TairaInrouStageIdentity,
    timeout_secs: u64,
    probe_scope: InrouProbeScope,
) -> Result<Value> {
    validate_inrou_canary_timeout(timeout_secs)?;
    verify_inrou_check_until(
        public_root,
        status_client,
        stage,
        prepared_observation_deadline(timeout_secs, None)?,
        probe_scope,
    )
}

fn verify_inrou_check_until(
    public_root: &str,
    status_client: &IrohaClient,
    stage: &crate::soracloud::TairaInrouStageIdentity,
    deadline: Instant,
    probe_scope: InrouProbeScope,
) -> Result<Value> {
    let expected = InrouProbeIdentity::from(stage);
    let observation =
        probe_inrou_service(public_root, status_client, &expected, deadline, probe_scope)?;
    let observed_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock predates the Unix epoch; refusing stale-looking Inrou evidence")?
        .as_millis();
    let observed_at_unix_ms = u64::try_from(observed_at_unix_ms)
        .wrap_err("Inrou evidence timestamp exceeds the V1 u64 range")?;
    let mut extra = Map::new();
    extra.insert(
        "probe_scope".to_owned(),
        Value::String(probe_scope.label().to_owned()),
    );
    extra.insert(
        "service_name".to_owned(),
        Value::from(stage.service_name.clone()),
    );
    extra.insert(
        "service_version".to_owned(),
        Value::from(stage.service_version.clone()),
    );
    extra.insert(
        "route_host".to_owned(),
        Value::from(stage.route_host.clone()),
    );
    extra.insert(
        "route_path".to_owned(),
        Value::from(observation.health_path),
    );
    extra.insert(
        "active_host_adverts".to_owned(),
        Value::from(observation.active_host_adverts),
    );
    extra.insert(
        "hosted_replica_count".to_owned(),
        Value::from(observation.hosted_replica_count),
    );
    extra.insert(
        "local_placement".to_owned(),
        observation
            .local_placement
            .as_ref()
            .map_or(Value::Null, InrouLocalPlacement::to_json),
    );
    extra.insert(
        "bundle_hash".to_owned(),
        Value::from(stage.bundle_hash.clone()),
    );
    extra.insert(
        "bundle_content_cid".to_owned(),
        Value::from(stage.bundle_content_cid.clone()),
    );
    extra.insert(
        "bundle_manifest_digest_hex".to_owned(),
        Value::from(stage.bundle_manifest_digest_hex.clone()),
    );
    extra.insert(
        "guest_content_cid".to_owned(),
        Value::from(stage.guest_content_cid.clone()),
    );
    extra.insert(
        "guest_manifest_digest_hex".to_owned(),
        Value::from(stage.guest_manifest_digest_hex.clone()),
    );
    extra.insert(
        "discovery_payload_dir".to_owned(),
        Value::from(stage.discovery_payload_dir.clone()),
    );
    extra.insert(
        "discovery_document_hash".to_owned(),
        Value::from(stage.discovery_document_hash.clone()),
    );
    extra.insert(
        "discovery_content_cid".to_owned(),
        Value::from(stage.discovery_content_cid.clone()),
    );
    extra.insert(
        "discovery_manifest_digest_hex".to_owned(),
        Value::from(stage.discovery_manifest_digest_hex.clone()),
    );
    extra.insert(
        "public_discovery_url".to_owned(),
        Value::from(stage.public_discovery_url.clone()),
    );
    extra.insert(
        "public_discovery_cid_host_url".to_owned(),
        Value::from(stage.public_discovery_cid_host_url.clone()),
    );
    extra.insert(
        "deployment_bundle_hash".to_owned(),
        Value::from(stage.deployment_bundle_hash.clone()),
    );
    extra.insert(
        "container_manifest_hash".to_owned(),
        Value::from(stage.container_manifest_hash.clone()),
    );
    extra.insert(
        "service_manifest_hash".to_owned(),
        Value::from(stage.service_manifest_hash.clone()),
    );
    extra.insert(
        "observed_at_unix_ms".to_owned(),
        Value::from(observed_at_unix_ms),
    );
    extra.insert(
        "replica_identities".to_owned(),
        observation.replica_identities,
    );
    report_value(
        "taira_inrou_check",
        if observation.failures.is_empty() {
            "ok"
        } else {
            "fail"
        },
        public_root,
        observation.checks,
        Vec::new(),
        observation.failures,
        extra,
    )
}
fn validate_inrou_canary_timeout(timeout_secs: u64) -> Result<()> {
    if timeout_secs == 0 {
        eyre::bail!("--timeout-secs must be greater than zero");
    }
    Ok(())
}

const PREPARED_BINDING_METADATA: &str = "taira_public_reset_binding";
const PREPARED_OPERATION_METADATA: &str = "prepared_operation";
const PREPARED_SEMANTIC_METADATA: &str = "prepared_semantic_hash";

struct ValidatedPreparedOperation {
    envelope: PreparedMutationEnvelopeV1,
    transaction: Option<SignedTransaction>,
    wire: Option<Vec<u8>>,
    envelope_bytes: Vec<u8>,
}

impl ValidatedPreparedOperation {
    fn transaction(&self) -> Result<&SignedTransaction> {
        self.transaction
            .as_ref()
            .ok_or_else(|| eyre!("the prepared operation has no transaction"))
    }

    fn wire(&self) -> Result<&[u8]> {
        self.wire
            .as_deref()
            .ok_or_else(|| eyre!("the prepared operation has no transaction wire"))
    }
}

macro_rules! prepared_write_pending_reasons {
    ($($reason:ident),+ $(,)?) => {
        /// Closed nonterminal reasons shared by the core write producer and host consumer.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum PreparedWritePendingReason {
            $($reason),+
        }

        impl PreparedWritePendingReason {
            pub(super) const ALL: &'static [Self] = &[$(Self::$reason),+];

            pub(super) const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$reason => stringify!($reason)),+
                }
            }

            pub(super) fn parse(value: &str) -> Result<Self> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|reason| reason.as_str() == value)
                    .ok_or_else(|| eyre!("unsupported core write Pending evidence"))
            }
        }
    };
}

prepared_write_pending_reasons! {
    Absent,
    AcceptedNotVisible,
    AppliedEvidencePending,
    ObservationUnavailable,
    OnboardingAliasConflict,
    OnboardingStateAbsent,
    Queued,
    Approved,
    Committed,
    Applied,
    Rejected,
    Expired,
}

#[cfg(test)]
pub(crate) fn core_pending_report_cases_for_test(
    reason: PreparedWritePendingReason,
) -> Result<Vec<(String, Vec<u8>, Value)>> {
    tests::core_report_cases(PreparedRecoveryClassification::Pending { reason })
}

#[cfg(test)]
pub(crate) fn core_rejected_report_cases_for_test(
    evidence: &str,
) -> Result<Vec<(String, Vec<u8>, Value)>> {
    tests::core_report_cases(PreparedRecoveryClassification::Rejected {
        terminal_kind: evidence.to_owned(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PreparedRecoveryClassification {
    Absent,
    Applied {
        block_height: Option<u64>,
        evidence: String,
    },
    Pending {
        reason: PreparedWritePendingReason,
    },
    Rejected {
        terminal_kind: String,
    },
}

fn run_write_canary_exact<C: RunContext>(context: &mut C, args: &WriteCanary) -> Result<Value> {
    ensure_canonical_taira_client_identity(context.config())?;
    let _guard = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
    let public_root = normalize_root_url(&args.public_root)?;
    let binding = args.binding()?;
    let action = args.validated_action()?;
    let expected_fee_payment = context.transaction_fee_payment()?;
    let deadline = prepared_observation_deadline(
        args.timeout_secs,
        (!matches!(action, PreparedEnvelopeAction::Recover(_)))
            .then_some(binding.execution_expires_at_unix_ms),
    )?;
    match action {
        PreparedEnvelopeAction::Prepare(output) => {
            require_forward_binding_current(&binding)?;
            prove_predecessor_applied(
                context.config(),
                args,
                &public_root,
                &binding,
                &expected_fee_payment,
                deadline,
            )?;
            require_forward_binding_current(&binding)?;
            let envelope = prepare_one_write_canary_operation(
                context.config(),
                args,
                &public_root,
                &binding,
                expected_fee_payment.clone(),
                deadline,
            )?;
            remaining_prepared_budget(deadline)?;
            let envelope_bytes = canonical_prepared_envelope_bytes(&envelope)?;
            write_prepared_envelope(output, &envelope_bytes)?;
            let (outcome, evidence) = initial_prepared_report_state(&envelope.operation);
            prepared_operation_report(
                &public_root,
                args,
                &envelope,
                &envelope_bytes,
                outcome,
                None,
                evidence,
            )
        }
        PreparedEnvelopeAction::Submit(fd) => {
            let validated = load_and_validate_prepared_operation(
                context.config(),
                args,
                &public_root,
                fd,
                &expected_fee_payment,
                PreparedLifetimeCheck::LiveForward,
            )?;
            let classification = submit_exact_prepared_operation(
                context.config(),
                args,
                &public_root,
                &validated,
                &expected_fee_payment,
                deadline,
            )?;
            report_prepared_classification(&public_root, args, &validated, classification)
        }
        PreparedEnvelopeAction::Recover(fd) => {
            let validated = load_and_validate_prepared_operation(
                context.config(),
                args,
                &public_root,
                fd,
                &expected_fee_payment,
                PreparedLifetimeCheck::Structural,
            )?;
            let client = IrohaClient::builder(write_canary_config(
                context.config(),
                &public_root,
                &CanarySigner {
                    account_id: context.config().account.clone(),
                    key_pair: context.config().key_pair.clone(),
                },
            )?)
            .build()?
            .with_request_deadline(deadline);
            let classification = match classify_exact_prepared_operation(&client, &validated) {
                Ok(classification) => classification,
                Err(error) if Instant::now() >= deadline && prepared_request_timed_out(&error) => {
                    PreparedRecoveryClassification::Pending {
                        reason: PreparedWritePendingReason::ObservationUnavailable,
                    }
                }
                Err(error) => return Err(error),
            };
            report_prepared_classification(&public_root, args, &validated, classification)
        }
    }
}

fn initial_prepared_report_state(
    operation: &PreparedTransactionOperationV1,
) -> (&'static str, Option<String>) {
    let proof_required_evidence = match operation {
        PreparedTransactionOperationV1::OnboardingProofRequired(proof_required) => {
            Some(proof_required.result.semantic_hash_hex.as_str())
        }
        PreparedTransactionOperationV1::OnboardingPrepared(_)
        | PreparedTransactionOperationV1::FaucetPrepared(_)
        | PreparedTransactionOperationV1::FinalCanary(_) => None,
    };
    initial_prepared_report_state_from_evidence(proof_required_evidence)
}

fn initial_prepared_report_state_from_evidence(
    proof_required_evidence: Option<&str>,
) -> (&'static str, Option<String>) {
    match proof_required_evidence {
        Some(evidence) => ("ProofRequired", Some(evidence.to_owned())),
        None => ("Prepared", None),
    }
}

fn prepare_one_write_canary_operation(
    config: &Config,
    args: &WriteCanary,
    public_root: &str,
    binding: &PreparedMutationBindingV1,
    fee_payment: FeePaymentIntent,
    deadline: Instant,
) -> Result<PreparedMutationEnvelopeV1> {
    match args.operation {
        WriteCanaryOperation::Onboarding => {
            prepare_onboarding_operation(config, args, public_root, binding, &fee_payment, deadline)
        }
        WriteCanaryOperation::Faucet => {
            prepare_faucet_operation(config, args, public_root, binding, &fee_payment, deadline)
        }
        WriteCanaryOperation::FinalCanary => prepare_final_canary_operation(
            config,
            args,
            public_root,
            binding,
            fee_payment,
            deadline,
        ),
    }
}

fn prove_predecessor_applied(
    config: &Config,
    args: &WriteCanary,
    public_root: &str,
    current_binding: &PreparedMutationBindingV1,
    expected_fee_payment: &FeePaymentIntent,
    deadline: Instant,
) -> Result<()> {
    if args.operation == WriteCanaryOperation::Onboarding {
        return Ok(());
    }
    let policy_context = PreparedOperationPolicyContext::Predecessor(args);
    let predecessor = policy_context.operation()?;
    let fd = args
        .prerequisite_envelope_fd
        .ok_or_else(|| eyre!("the next operation requires its exact predecessor envelope"))?;
    let (envelope, envelope_bytes) = read_prepared_envelope(fd)?;
    let mut predecessor_binding = current_binding.clone();
    predecessor_binding.kind = predecessor.mutation_kind().to_owned();
    predecessor_binding.idempotency_key = write_canary_child_idempotency_key(
        &predecessor_binding.authorization_nonce,
        &predecessor_binding.phase,
        predecessor.mutation_kind(),
    );
    let wire = envelope
        .operation
        .signed_transaction_wire_hex()
        .map(|wire| hex::decode(wire).wrap_err("predecessor transaction wire is not hexadecimal"))
        .transpose()?;
    let mut validated = validate_prepared_operation(
        config,
        policy_context,
        &predecessor_binding,
        public_root,
        envelope,
        wire,
        expected_fee_payment,
        PreparedLifetimeCheck::Structural,
    )?;
    validated.envelope_bytes = envelope_bytes;
    let signer = CanarySigner {
        account_id: config.account.clone(),
        key_pair: config.key_pair.clone(),
    };
    let canary_config = write_canary_config(config, public_root, &signer)?;
    let client = IrohaClient::builder(canary_config)
        .build()?
        .with_request_deadline(deadline);
    await_predecessor_applied(deadline, Duration::from_millis(200), |_| {
        match classify_exact_prepared_operation(&client, &validated)? {
            PreparedRecoveryClassification::Applied { .. } => Ok(true),
            PreparedRecoveryClassification::Absent
            | PreparedRecoveryClassification::Pending { .. } => Ok(false),
            PreparedRecoveryClassification::Rejected { terminal_kind } => eyre::bail!(
                "predecessor transaction is terminally rejected (`{terminal_kind}`); refusing to prepare the next operation"
            ),
        }
    })
}

fn prepare_final_canary_operation(
    config: &Config,
    args: &WriteCanary,
    public_root: &str,
    binding: &PreparedMutationBindingV1,
    fee_payment: FeePaymentIntent,
    deadline: Instant,
) -> Result<PreparedMutationEnvelopeV1> {
    let signer = resolve_canary_signer(config)?;
    let canary_config = write_canary_config(config, public_root, &signer)?;
    let client = BlockingIrohaClient::from_client(
        IrohaClient::builder(canary_config.clone())
            .build()?
            .with_request_deadline(deadline),
    )
    .wrap_err("failed to initialize blocking transaction client")?;
    let message = prepared_canary_message(binding)?;
    let semantic_sha256 = prepared_semantic_sha256(binding, WRITE_CANARY_OPERATION, &message)?;
    let mut metadata = Metadata::default();
    insert_string_metadata(&mut metadata, "taira_canary", "write-canary")?;
    insert_string_metadata(
        &mut metadata,
        "taira_write_canary_idempotency_v1",
        &binding.idempotency_key,
    )?;
    let binding_value = json::to_value(binding).wrap_err("serialize prepared mutation binding")?;
    metadata.insert(
        Name::from_str(PREPARED_BINDING_METADATA)?,
        IrohaJson::from_norito_value_ref(&binding_value)
            .wrap_err("encode prepared mutation binding metadata")?,
    );
    insert_string_metadata(
        &mut metadata,
        PREPARED_OPERATION_METADATA,
        WRITE_CANARY_OPERATION,
    )?;
    insert_string_metadata(&mut metadata, PREPARED_SEMANTIC_METADATA, &semantic_sha256)?;
    let instruction = Log::new(LogLevel::INFO, message);
    let executable = Executable::Instructions(vec![InstructionBox::from(instruction)].into());
    let (transaction, fee_quote) = quote_and_sign_transaction_with_expiry(
        &client,
        executable,
        fee_payment.clone(),
        metadata,
        binding.execution_expires_at_unix_ms,
    )
    .wrap_err("failed to quote and sign exact Taira canary transaction")?;
    let wire = transaction
        .encode_wire_v1()
        .map_err(|error| eyre!("failed to encode exact Taira canary transaction: {error}"))?;
    if wire.len() > PREPARED_TRANSACTION_MAX_BYTES {
        eyre::bail!("prepared Taira canary transaction exceeds its V1 byte bound");
    }
    let prepared = iroha::client::PreparedTransactionPayload::from_transaction(&transaction);
    if prepared.as_bytes() != wire {
        eyre::bail!("prepared submission changed exact Taira canary transaction bytes");
    }
    let operation = FinalCanaryPreparedTransactionV1 {
        schema: PREPARED_OPERATION_SCHEMA_V1.to_owned(),
        binding: binding.clone(),
        operation: WRITE_CANARY_OPERATION.to_owned(),
        transaction_hash_hex: hex::encode(transaction.hash().as_ref()),
        signed_transaction_wire_hex: hex::encode(&wire),
        signed_transaction_wire_sha256: hex::encode(Sha256::digest(&wire)),
        semantic_hash_hex: semantic_sha256,
        fee_payment: transaction.fee_payment_intent().clone(),
        fee_quote,
    };
    let envelope = PreparedMutationEnvelopeV1 {
        schema: PREPARED_ENVELOPE_SCHEMA_V1.to_owned(),
        binding: binding.clone(),
        public_root: public_root.to_owned(),
        chain_id: canary_config.chain.to_string(),
        network_id: canary_config.network_id.to_string(),
        authority: canary_config.account.to_string(),
        operation: PreparedTransactionOperationV1::FinalCanary(operation),
    };
    validate_prepared_operation(
        config,
        PreparedOperationPolicyContext::Current(args),
        binding,
        public_root,
        envelope.clone(),
        Some(wire),
        &fee_payment,
        PreparedLifetimeCheck::LiveForward,
    )?;
    Ok(envelope)
}

fn prepared_canary_message(binding: &PreparedMutationBindingV1) -> Result<String> {
    validate_prepared_binding(binding)?;
    Ok(format!(
        "taira-public-reset-write-canary-v1:{}:{}:{}:{}",
        binding.authorization_sha256,
        binding.authorization_nonce,
        binding.phase,
        binding.idempotency_key
    ))
}

fn prepared_semantic_sha256(
    binding: &PreparedMutationBindingV1,
    operation: &str,
    semantic_identity: &str,
) -> Result<String> {
    validate_prepared_binding(binding)?;
    let binding_bytes = json::to_vec(binding).wrap_err("encode prepared mutation binding")?;
    let mut digest = Sha256::new();
    for frame in [
        b"iroha:taira:prepared-operation:semantic:v1\0".as_slice(),
        binding_bytes.as_slice(),
        operation.as_bytes(),
        semantic_identity.as_bytes(),
    ] {
        let length = u64::try_from(frame.len()).expect("frame length fits u64");
        digest.update(length.to_be_bytes());
        digest.update(frame);
    }
    Ok(hex::encode(digest.finalize()))
}

fn require_forward_binding_current(binding: &PreparedMutationBindingV1) -> Result<()> {
    let now = current_unix_ms()?;
    if now >= binding.execution_expires_at_unix_ms {
        eyre::bail!("prepared mutation execution expiry bars a new forward effect");
    }
    Ok(())
}

fn current_unix_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before the Unix epoch")?;
    u64::try_from(elapsed.as_millis()).wrap_err("current Unix milliseconds exceed u64")
}

fn validate_prepared_binding(binding: &PreparedMutationBindingV1) -> Result<()> {
    if binding.schema != PREPARED_BINDING_SCHEMA_V1 {
        eyre::bail!("prepared mutation binding has an unsupported schema");
    }
    validate_sha256_argument(&binding.authorization_sha256).map_err(|error| eyre!(error))?;
    validate_authorization_nonce_argument(&binding.authorization_nonce)
        .map_err(|error| eyre!(error))?;
    validate_write_canary_phase_argument(&binding.phase).map_err(|error| eyre!(error))?;
    validate_write_canary_idempotency_key(&binding.idempotency_key)
        .map_err(|error| eyre!(error))?;
    if binding.execution_expires_at_unix_ms == 0 {
        eyre::bail!("prepared mutation binding has a zero execution expiry");
    }
    if !matches!(
        binding.kind.as_str(),
        "onboarding" | "faucet" | WRITE_CANARY_MUTATION_KIND
    ) {
        eyre::bail!("prepared mutation binding has an unsupported operation kind");
    }
    Ok(())
}

fn canonical_prepared_envelope_bytes(envelope: &PreparedMutationEnvelopeV1) -> Result<Vec<u8>> {
    let value =
        json::to_value(envelope).wrap_err("project canonical prepared mutation envelope")?;
    let mut bytes = json::to_json(&value)
        .wrap_err("encode canonical prepared mutation envelope")?
        .into_bytes();
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > PREPARED_ENVELOPE_MAX_BYTES {
        eyre::bail!("prepared mutation envelope exceeds its V1 byte bound");
    }
    Ok(bytes)
}

#[cfg(test)]
/// Exercise the actual typed write-envelope producer from authenticated host fixtures.
pub(crate) fn typed_write_envelope_bytes_for_test(value: Value) -> Result<Vec<u8>> {
    let envelope: PreparedMutationEnvelopeV1 = json::from_value(value)?;
    canonical_prepared_envelope_bytes(&envelope)
}

fn inherited_fd_path(fd: u32) -> Result<PathBuf> {
    if !(3..=65_535).contains(&fd) {
        eyre::bail!("prepared-envelope descriptor must be an inherited FD in 3..=65535");
    }
    if Path::new("/proc/self/fd").is_dir() {
        return Ok(PathBuf::from(format!("/proc/self/fd/{fd}")));
    }
    if Path::new("/dev/fd").is_dir() {
        return Ok(PathBuf::from(format!("/dev/fd/{fd}")));
    }
    eyre::bail!("this platform does not expose inherited descriptor paths")
}

fn write_prepared_envelope(fd: u32, bytes: &[u8]) -> Result<()> {
    let path = inherited_fd_path(fd)?;
    let mut file = File::options()
        .write(true)
        .open(path)
        .wrap_err_with(|| format!("failed to duplicate prepared-envelope output FD {fd}"))?;
    file.write_all(bytes)
        .wrap_err("failed to write canonical prepared mutation envelope")?;
    file.flush()
        .wrap_err("failed to flush canonical prepared mutation envelope")
}

fn read_prepared_envelope(fd: u32) -> Result<(PreparedMutationEnvelopeV1, Vec<u8>)> {
    let path = inherited_fd_path(fd)?;
    let file = File::open(path)
        .wrap_err_with(|| format!("failed to duplicate prepared-envelope input FD {fd}"))?;
    let mut bytes = Vec::new();
    file.take(PREPARED_ENVELOPE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .wrap_err("failed to read prepared mutation envelope")?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > PREPARED_ENVELOPE_MAX_BYTES
    {
        eyre::bail!("prepared mutation envelope is empty or exceeds its V1 byte bound");
    }
    let envelope: PreparedMutationEnvelopeV1 =
        json::from_slice(&bytes).wrap_err("prepared mutation envelope is not canonical V1 JSON")?;
    let canonical = canonical_prepared_envelope_bytes(&envelope)?;
    if canonical != bytes {
        eyre::bail!("prepared mutation envelope bytes are not exact canonical V1 JSON");
    }
    Ok((envelope, bytes))
}

fn load_and_validate_prepared_operation(
    config: &Config,
    args: &WriteCanary,
    public_root: &str,
    fd: u32,
    expected_fee_payment: &FeePaymentIntent,
    lifetime_check: PreparedLifetimeCheck,
) -> Result<ValidatedPreparedOperation> {
    let (envelope, envelope_bytes) = read_prepared_envelope(fd)?;
    let wire = envelope
        .operation
        .signed_transaction_wire_hex()
        .map(|wire| hex::decode(wire).wrap_err("prepared transaction wire is not hexadecimal"))
        .transpose()?;
    let binding = args.binding()?;
    let mut validated = validate_prepared_operation(
        config,
        PreparedOperationPolicyContext::Current(args),
        &binding,
        public_root,
        envelope,
        wire,
        expected_fee_payment,
        lifetime_check,
    )?;
    validated.envelope_bytes = envelope_bytes;
    Ok(validated)
}

fn validate_prepared_operation(
    config: &Config,
    policy_context: PreparedOperationPolicyContext<'_>,
    expected_binding: &PreparedMutationBindingV1,
    public_root: &str,
    envelope: PreparedMutationEnvelopeV1,
    supplied_wire: Option<Vec<u8>>,
    expected_fee_payment: &FeePaymentIntent,
    lifetime_check: PreparedLifetimeCheck,
) -> Result<ValidatedPreparedOperation> {
    expected_fee_payment
        .validate()
        .map_err(|error| eyre!("invalid requested prepared-operation fee payment: {error}"))?;
    validate_prepared_binding(&envelope.binding)?;
    if envelope.schema != PREPARED_ENVELOPE_SCHEMA_V1
        || &envelope.binding != expected_binding
        || envelope.public_root != public_root
        || envelope.chain_id != DEFAULT_CHAIN_ID
        || envelope.network_id != config.network_id.to_string()
        || envelope.authority != config.account.to_string()
    {
        eyre::bail!("prepared mutation envelope does not bind the exact CLI authorization");
    }
    let expected_operation = policy_context.operation()?;
    let operation = &envelope.operation;
    if !operation.matches_binding(&envelope.binding)?
        || operation.label() != expected_operation.label()
        || !matches!(
            (expected_operation, operation),
            (
                WriteCanaryOperation::Onboarding,
                PreparedTransactionOperationV1::OnboardingPrepared(_)
                    | PreparedTransactionOperationV1::OnboardingProofRequired(_)
            ) | (
                WriteCanaryOperation::Faucet,
                PreparedTransactionOperationV1::FaucetPrepared(_)
            ) | (
                WriteCanaryOperation::FinalCanary,
                PreparedTransactionOperationV1::FinalCanary(_)
            )
        )
    {
        eyre::bail!("prepared operation variant does not match the exact CLI operation");
    }
    let signer = CanarySigner {
        account_id: config.account.clone(),
        key_pair: config.key_pair.clone(),
    };
    let client =
        IrohaClient::builder(write_canary_config(config, public_root, &signer)?).build()?;
    let transaction = match operation {
        PreparedTransactionOperationV1::OnboardingPrepared(prepared) => {
            let expected_alias = canary_alias(signer.key_pair.public_key());
            let expected_request = AccountOnboardingPlanRequestV1::try_new(
                expected_alias.clone(),
                &signer.account_id,
                std::iter::empty(),
            )?;
            if prepared.account_id != config.account.to_string() || prepared.alias != expected_alias
            {
                eyre::bail!(
                    "prepared onboarding target differs from the configured canary identity"
                );
            }
            Some(client.verify_account_onboarding_prepared_transaction(
                &expected_request,
                prepared,
                &prepared.receipt,
                &prepared.binding,
                expected_fee_payment,
            )?)
        }
        PreparedTransactionOperationV1::OnboardingProofRequired(proof_required) => {
            let expected_alias = canary_alias(signer.key_pair.public_key());
            let expected_request = AccountOnboardingPlanRequestV1::try_new(
                expected_alias.clone(),
                &signer.account_id,
                std::iter::empty(),
            )?;
            if proof_required.schema != PREPARED_ONBOARDING_PROOF_REQUIRED_SCHEMA_V1
                || proof_required.result.account_id != config.account.to_string()
                || proof_required.result.alias != expected_alias
                || proof_required.receipt.body.request.account_id != config.account.to_string()
                || proof_required.receipt.body.request.alias != expected_alias
            {
                eyre::bail!(
                    "proof-required onboarding target differs from the configured canary identity"
                );
            }
            client.verify_account_onboarding_proof_required_result(
                &expected_request,
                &proof_required.result,
                &proof_required.receipt,
                &proof_required.result.binding,
            )?;
            None
        }
        PreparedTransactionOperationV1::FaucetPrepared(prepared) => {
            let faucet_policy = policy_context.faucet_policy()?;
            if prepared.account_id != config.account.to_string()
                || prepared.asset_definition_id != faucet_policy.asset_definition_id().to_string()
            {
                eyre::bail!("prepared faucet target differs from the configured canary identity");
            }
            Some(client.verify_account_faucet_prepared_transaction(
                prepared,
                &prepared.claim,
                &prepared.binding,
                expected_fee_payment,
                &faucet_policy,
            )?)
        }
        PreparedTransactionOperationV1::FinalCanary(prepared) => {
            validate_final_canary_envelope(prepared)?;
            let wire = supplied_wire
                .as_deref()
                .ok_or_else(|| eyre!("prepared final canary omits its transaction wire"))?;
            let transaction = SignedTransaction::decode_all_versioned(wire)
                .wrap_err("prepared final canary is not a versioned SignedTransaction")?;
            if transaction.authority() != &config.account {
                eyre::bail!("prepared final canary has a substituted authority");
            }
            prepared
                .fee_quote
                .validate_for_signed_payload(transaction.payload())
                .map_err(|error| {
                    eyre!("prepared final-canary fee quote is semantically invalid: {error}")
                })?;
            Some(transaction)
        }
    };
    if let Some(transaction) = transaction.as_ref() {
        validate_expected_prepared_fee_payment(
            expected_fee_payment,
            transaction.fee_payment_intent(),
        )?;
        let wire = supplied_wire
            .as_deref()
            .ok_or_else(|| eyre!("prepared transaction omits its exact wire"))?;
        validate_prepared_transaction_closure(transaction, operation, wire, &config.network_id)?;
        validate_prepared_transaction_lifetime(transaction, &envelope.binding, lifetime_check)?;
    } else if supplied_wire.is_some() {
        eyre::bail!("proof-required onboarding result must not contain transaction bytes");
    }
    Ok(ValidatedPreparedOperation {
        envelope,
        transaction,
        wire: supplied_wire,
        envelope_bytes: Vec::new(),
    })
}

fn validate_expected_prepared_fee_payment(
    expected: &FeePaymentIntent,
    actual: &FeePaymentIntent,
) -> Result<()> {
    expected
        .validate()
        .map_err(|error| eyre!("invalid requested prepared-operation fee payment: {error}"))?;
    actual
        .validate()
        .map_err(|error| eyre!("invalid signed prepared-operation fee payment: {error}"))?;
    if !expected.has_same_payer_and_gas_bound(actual) {
        eyre::bail!(
            "prepared transaction fee payer, sponsor revision, or gas bound differs from the independent CLI selection"
        );
    }
    Ok(())
}

fn validate_final_canary_envelope(operation: &FinalCanaryPreparedTransactionV1) -> Result<()> {
    if operation.schema != PREPARED_OPERATION_SCHEMA_V1
        || operation.operation != WRITE_CANARY_OPERATION
        || operation.fee_quote.intent != operation.fee_payment
    {
        eyre::bail!("prepared final-canary identity or fee closure is invalid");
    }
    Ok(())
}

fn validate_prepared_transaction_closure(
    transaction: &SignedTransaction,
    operation: &PreparedTransactionOperationV1,
    wire: &[u8],
    expected_network_id: &NetworkId,
) -> Result<()> {
    let transaction_hash_hex = operation
        .transaction_hash_hex()
        .ok_or_else(|| eyre!("prepared operation omits its transaction hash"))?;
    let wire_hex = operation
        .signed_transaction_wire_hex()
        .ok_or_else(|| eyre!("prepared operation omits its transaction wire"))?;
    let wire_sha256 = operation
        .signed_transaction_wire_sha256()
        .ok_or_else(|| eyre!("prepared operation omits its wire digest"))?;
    let fee_payment = operation
        .fee_payment()
        .ok_or_else(|| eyre!("prepared operation omits its fee intent"))?;
    if wire.len() > PREPARED_TRANSACTION_MAX_BYTES
        || wire_hex.len() > PREPARED_TRANSACTION_MAX_BYTES.saturating_mul(2)
        || hex::encode(wire) != wire_hex
        || hex::encode(Sha256::digest(wire)) != wire_sha256
    {
        eyre::bail!("prepared operation exact wire or digest is invalid");
    }
    let canonical = transaction
        .encode_wire_v1()
        .map_err(|error| eyre!("failed to re-encode prepared transaction: {error}"))?;
    if canonical != wire
        || hex::encode(transaction.hash().as_ref()) != transaction_hash_hex
        || transaction.network_id() != Some(expected_network_id)
        || transaction.fee_payment_intent() != fee_payment
    {
        eyre::bail!("prepared operation transaction bytes do not bind its declared identity");
    }
    transaction
        .verify_signature()
        .wrap_err("prepared operation transaction signature is invalid")?;
    let prepared = iroha::client::PreparedTransactionPayload::from_transaction(transaction);
    if prepared.as_bytes() != wire || prepared.hash() != transaction.hash() {
        eyre::bail!("prepared client payload differs from the exact signed transaction");
    }
    let metadata = transaction.metadata();
    if !prepared_operation_binding_matches(metadata, operation)? {
        eyre::bail!("prepared transaction metadata does not bind `{PREPARED_BINDING_METADATA}`");
    }
    for (key, expected) in [
        (PREPARED_OPERATION_METADATA, operation.label()),
        (PREPARED_SEMANTIC_METADATA, operation.semantic_hash_hex()),
    ] {
        let actual = metadata
            .get(&Name::from_str(key)?)
            .and_then(|value| value.try_into_any_norito::<String>().ok());
        if actual.as_deref() != Some(expected) {
            eyre::bail!("prepared transaction metadata does not bind `{key}`");
        }
    }
    match operation {
        PreparedTransactionOperationV1::FinalCanary(operation) => {
            let expected_message = prepared_canary_message(&operation.binding)?;
            let expected_semantic = prepared_semantic_sha256(
                &operation.binding,
                WRITE_CANARY_OPERATION,
                &expected_message,
            )?;
            if operation.semantic_hash_hex != expected_semantic {
                eyre::bail!("prepared final-canary semantic digest is invalid");
            }
            let idempotency_name = Name::from_str("taira_write_canary_idempotency_v1")?;
            let canary_name = Name::from_str("taira_canary")?;
            if metadata
                .get(&idempotency_name)
                .and_then(|value| value.try_into_any_norito::<String>().ok())
                .as_deref()
                != Some(operation.binding.idempotency_key.as_str())
                || metadata
                    .get(&canary_name)
                    .and_then(|value| value.try_into_any_norito::<String>().ok())
                    .as_deref()
                    != Some("write-canary")
            {
                eyre::bail!("prepared final canary omits its exact idempotency metadata");
            }
            let executable_matches = match transaction.instructions() {
                Executable::Instructions(instructions) if instructions.len() == 1 => instructions
                    .first()
                    .and_then(|instruction| instruction.as_any().downcast_ref::<Log>())
                    .is_some_and(|log| log.level == LogLevel::INFO && log.msg == expected_message),
                _ => false,
            };
            if !executable_matches || metadata.iter().len() != 5 {
                eyre::bail!("prepared final-canary instruction or metadata closure is not exact");
            }
        }
        PreparedTransactionOperationV1::OnboardingPrepared(_) => {
            if metadata.iter().len() != 3 {
                eyre::bail!("prepared onboarding metadata closure is not exact");
            }
        }
        PreparedTransactionOperationV1::FaucetPrepared(_) => {
            if !prepared_faucet_metadata_closure_is_exact(metadata) {
                eyre::bail!(
                    "prepared faucet metadata closure or claim marker version is not exact"
                );
            }
        }
        PreparedTransactionOperationV1::OnboardingProofRequired(_) => {
            eyre::bail!("proof-required onboarding result cannot contain a transaction")
        }
    }
    Ok(())
}

fn prepared_faucet_metadata_closure_is_exact(metadata: &Metadata) -> bool {
    use iroha::data_model::transaction::{
        FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY, FAUCET_CLAIM_MARKER_VERSION_V1,
    };
    metadata.iter().len() == 4
        && metadata.get(
            &Name::from_str(FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY)
                .expect("static faucet claim marker metadata key"),
        ) == Some(&IrohaJson::new(FAUCET_CLAIM_MARKER_VERSION_V1))
}

/// Authenticate one exact first-release final-canary operation without network I/O.
///
/// # Errors
/// Returns an error for noncanonical JSON, a substituted binding, wire, signature, network,
/// authority, fee closure, metadata, semantic message, instruction sequence, or lifetime.
pub(crate) fn verify_final_canary_prepared_operation_v1(
    operation_value: &Value,
    expected_network_id: &NetworkId,
    expected_authority: &AccountId,
) -> Result<SignedTransaction> {
    let operation: FinalCanaryPreparedTransactionV1 = json::from_value(operation_value.clone())
        .wrap_err("prepared final canary is not exact typed V1 JSON")?;
    if json::to_value(&operation)? != *operation_value {
        eyre::bail!("prepared final canary is outside its exact typed V1 JSON closure");
    }
    validate_final_canary_envelope(&operation)?;
    if operation.signed_transaction_wire_hex.len()
        > PREPARED_TRANSACTION_MAX_BYTES.saturating_mul(2)
    {
        eyre::bail!("prepared final-canary transaction wire is oversized");
    }
    let wire = hex::decode(&operation.signed_transaction_wire_hex)
        .wrap_err("prepared final-canary transaction wire is not hexadecimal")?;
    let transaction = SignedTransaction::decode_all_versioned(&wire)
        .wrap_err("prepared final canary is not a versioned SignedTransaction")?;
    if transaction.authority() != expected_authority {
        eyre::bail!("prepared final canary has a substituted authority");
    }
    operation
        .fee_quote
        .validate_for_signed_payload(transaction.payload())
        .map_err(|error| {
            eyre!("prepared final-canary fee quote is semantically invalid: {error}")
        })?;
    let binding = operation.binding.clone();
    let tagged = PreparedTransactionOperationV1::FinalCanary(operation);
    validate_prepared_transaction_closure(&transaction, &tagged, &wire, expected_network_id)?;
    validate_prepared_transaction_lifetime(
        &transaction,
        &binding,
        PreparedLifetimeCheck::Structural,
    )?;
    Ok(transaction)
}

fn validate_prepared_transaction_lifetime(
    transaction: &SignedTransaction,
    binding: &PreparedMutationBindingV1,
    lifetime_check: PreparedLifetimeCheck,
) -> Result<()> {
    let creation_ms = u64::try_from(transaction.creation_time().as_millis())
        .wrap_err("prepared transaction creation time exceeds u64")?;
    let ttl_ms = u64::try_from(
        transaction
            .time_to_live()
            .ok_or_else(|| eyre!("prepared transaction omits its required TTL"))?
            .as_millis(),
    )
    .wrap_err("prepared transaction TTL exceeds u64")?;
    validate_prepared_transaction_time_window(
        creation_ms,
        ttl_ms,
        binding.execution_expires_at_unix_ms,
        "prepared transaction",
    )?;
    if lifetime_check == PreparedLifetimeCheck::LiveForward {
        validate_live_prepared_transaction_freshness(
            creation_ms,
            ttl_ms,
            current_unix_ms()?,
            "prepared transaction",
        )?;
    }
    Ok(())
}

fn validate_prepared_transaction_time_window(
    creation_ms: u64,
    ttl_ms: u64,
    execution_expiry_ms: u64,
    label: &str,
) -> Result<u64> {
    let expiry_ms = creation_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| eyre!("{label} lifetime overflows u64"))?;
    if ttl_ms == 0 || expiry_ms > execution_expiry_ms {
        eyre::bail!("{label} lifetime is outside the signed execution window");
    }
    Ok(expiry_ms)
}

fn validate_live_prepared_transaction_freshness(
    creation_ms: u64,
    ttl_ms: u64,
    now_ms: u64,
    label: &str,
) -> Result<()> {
    let expiry_ms = creation_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| eyre!("{label} lifetime overflows u64"))?;
    if creation_ms > now_ms.saturating_add(PREPARED_TRANSACTION_CLOCK_SKEW_MS) {
        eyre::bail!("{label} was created beyond the permitted future clock skew");
    }
    if now_ms >= expiry_ms {
        eyre::bail!("{label} is already expired");
    }
    Ok(())
}

fn classify_exact_prepared_operation(
    client: &IrohaClient,
    validated: &ValidatedPreparedOperation,
) -> Result<PreparedRecoveryClassification> {
    if let PreparedTransactionOperationV1::OnboardingProofRequired(proof_required) =
        &validated.envelope.operation
    {
        let expected_account = AccountId::parse_encoded(&proof_required.result.account_id)
            .wrap_err("prepared proof-required onboarding account is not canonical")?;
        let alias = proof_required
            .result
            .alias
            .parse::<AccountAliasName>()
            .wrap_err("prepared proof-required onboarding alias is not canonical")?;
        let current_state =
            client.prove_account_onboarding_current_state(&expected_account, &alias)?;
        return Ok(classify_proof_required_current_state(
            &proof_required.result.semantic_hash_hex,
            current_state,
        ));
    }
    let expected_hash = validated.transaction()?.hash();
    let Some(status) = client
        .get_transaction_status_response_global(expected_hash)
        .wrap_err("read-only exact prepared-transaction status lookup failed")?
    else {
        return Ok(PreparedRecoveryClassification::Absent);
    };
    if status.hash != hex::encode(expected_hash.as_ref()) || status.scope != "global" {
        eyre::bail!("prepared-transaction status response has a mismatched identity or scope");
    }
    match status.status.kind.as_str() {
        "Applied" if prepared_recovery_status_is_final_applied(&status) => {
            let block_height = status
                .status
                .block_height
                .filter(|height| *height > 0)
                .ok_or_else(|| eyre!("Applied prepared transaction omits its block height"))?;
            let evidence = match verify_exact_committed_prepared_operation(client, validated) {
                Ok(evidence) => evidence.to_string(),
                Err(error) if exact_transaction_details_not_found(&error) => {
                    // Global status may resolve at a peer ahead of this exact local
                    // lookup. Keep polling the same hash until its proof is visible.
                    return Ok(PreparedRecoveryClassification::Pending {
                        reason: PreparedWritePendingReason::AppliedEvidencePending,
                    });
                }
                Err(error) => return Err(error),
            };
            Ok(PreparedRecoveryClassification::Applied {
                block_height: Some(block_height),
                evidence,
            })
        }
        "Rejected" | "Expired" if prepared_recovery_status_is_final_failure(&status) => {
            Ok(PreparedRecoveryClassification::Rejected {
                terminal_kind: status.status.kind,
            })
        }
        "Queued" | "Approved" | "Committed" | "Applied" | "Rejected" | "Expired" => {
            Ok(PreparedRecoveryClassification::Pending {
                reason: PreparedWritePendingReason::parse(&status.status.kind)?,
            })
        }
        other => Err(eyre!(
            "prepared-transaction status response has unsupported kind `{other}`"
        )),
    }
}

/// Only a typed absence from the exact details endpoint permits proof-visibility retry.
pub(crate) fn exact_transaction_details_not_found(error: &eyre::Report) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<iroha::query::QueryError>(),
            Some(iroha::query::QueryError::Validation(
                iroha::data_model::ValidationFail::QueryFailed(
                    iroha::data_model::query::error::QueryExecutionFail::NotFound
                )
            ))
        )
    })
}

fn prepared_observation_deadline(timeout_secs: u64, expires_at: Option<u64>) -> Result<Instant> {
    let mut budget = Duration::from_secs(timeout_secs);
    if let Some(expires_at) = expires_at {
        budget = budget.min(Duration::from_millis(
            expires_at.saturating_sub(current_unix_ms()?),
        ));
    }
    Instant::now()
        .checked_add(budget)
        .ok_or_else(|| eyre!("prepared observation deadline overflow"))
}

fn remaining_prepared_budget(deadline: Instant) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "prepared action exhausted its original deadline",
        )
        .into());
    }
    Ok(remaining)
}

/// A successor observes its retained predecessor under one original deadline.
/// Each observer binds its physical reads to this same absolute deadline.
fn await_predecessor_applied(
    deadline: Instant,
    poll_interval: Duration,
    mut observe: impl FnMut(Duration) -> Result<bool>,
) -> Result<()> {
    if poll_interval.is_zero() {
        eyre::bail!("predecessor poll interval must be positive");
    }
    loop {
        let request_budget = deadline.saturating_duration_since(Instant::now());
        if request_budget.is_zero() {
            eyre::bail!(
                "predecessor has not reached exact Applied proof within the original deadline"
            );
        }
        if observe(request_budget)? {
            return Ok(());
        }
        std::thread::sleep(poll_interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn prepared_recovery_status_is_final_applied(status: &PipelineTransactionStatusResponse) -> bool {
    status.status.kind == "Applied" && status.scope == "global" && status.resolved_from == "state"
}

fn prepared_recovery_status_is_final_failure(status: &PipelineTransactionStatusResponse) -> bool {
    matches!(status.status.kind.as_str(), "Rejected" | "Expired")
        && status.scope == "global"
        && status.resolved_from == "state"
}

fn classify_proof_required_current_state(
    semantic_hash_hex: &str,
    current_state: AccountOnboardingCurrentStateV1,
) -> PreparedRecoveryClassification {
    match current_state {
        AccountOnboardingCurrentStateV1::Applied {
            block_height: _,
            block_hash: _,
        } => {
            PreparedRecoveryClassification::Applied {
                // The durable report is not itself a state proof: every reopen and successor
                // re-runs the atomic observation. Do not mislabel its anchor as a transaction
                // application height or replace the authenticated semantic evidence with it.
                block_height: None,
                evidence: semantic_hash_hex.to_owned(),
            }
        }
        AccountOnboardingCurrentStateV1::AliasConflict { .. } => {
            PreparedRecoveryClassification::Pending {
                reason: PreparedWritePendingReason::OnboardingAliasConflict,
            }
        }
        AccountOnboardingCurrentStateV1::AliasAbsent { .. } => {
            PreparedRecoveryClassification::Pending {
                reason: PreparedWritePendingReason::OnboardingStateAbsent,
            }
        }
    }
}

fn submit_required_after_classification(
    binding: &PreparedMutationBindingV1,
    classification: &PreparedRecoveryClassification,
) -> Result<bool> {
    if matches!(classification, PreparedRecoveryClassification::Absent) {
        require_forward_binding_current(binding)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn verify_exact_committed_prepared_operation(
    client: &IrohaClient,
    validated: &ValidatedPreparedOperation,
) -> Result<Hash> {
    let operation_name = Name::from_str(PREPARED_OPERATION_METADATA)?;
    let expected_transaction = validated.transaction()?;
    let entrypoint_hash = expected_transaction.hash_as_entrypoint();
    let details = client
        .get_transaction_details(entrypoint_hash)
        .wrap_err("read-only exact prepared-transaction proof query failed")?;
    let committed = &details.transaction;
    if committed.result().is_err() {
        eyre::bail!("Applied status resolves to a failed committed transaction");
    }
    let TransactionEntrypoint::External(transaction) = committed.entrypoint() else {
        eyre::bail!("Applied status resolves to a non-external transaction entrypoint");
    };
    let binding_matches =
        prepared_operation_binding_matches(transaction.metadata(), &validated.envelope.operation)?;
    let operation_matches = transaction
        .metadata()
        .get(&operation_name)
        .and_then(|value| value.try_into_any_norito::<String>().ok())
        .as_deref()
        == Some(validated.envelope.operation.label());
    let wire = transaction
        .encode_wire_v1()
        .map_err(|error| eyre!("failed to encode committed prepared transaction: {error}"))?;
    if !binding_matches
        || !operation_matches
        || wire != validated.wire()?
        || transaction.hash() != expected_transaction.hash()
        || transaction.hash_as_entrypoint() != entrypoint_hash
    {
        eyre::bail!("committed proof differs from the exact prepared transaction");
    }
    Ok(entrypoint_hash.into())
}

fn prepared_operation_binding_matches(
    metadata: &Metadata,
    operation: &PreparedTransactionOperationV1,
) -> Result<bool> {
    let (binding_key, expected_binding) = operation.binding_metadata()?;
    Ok(metadata
        .get(&Name::from_str(binding_key)?)
        .map(IrohaJson::get)
        .map(String::as_str)
        == Some(expected_binding.as_str()))
}

fn report_prepared_classification(
    public_root: &str,
    args: &WriteCanary,
    validated: &ValidatedPreparedOperation,
    classification: PreparedRecoveryClassification,
) -> Result<Value> {
    match classification {
        PreparedRecoveryClassification::Absent => prepared_operation_report(
            public_root,
            args,
            &validated.envelope,
            &validated.envelope_bytes,
            "Pending",
            None,
            Some(PreparedWritePendingReason::Absent.as_str().to_owned()),
        ),
        PreparedRecoveryClassification::Applied {
            block_height,
            evidence,
        } => prepared_operation_report(
            public_root,
            args,
            &validated.envelope,
            &validated.envelope_bytes,
            "Applied",
            block_height,
            Some(evidence),
        ),
        PreparedRecoveryClassification::Pending { reason } => prepared_operation_report(
            public_root,
            args,
            &validated.envelope,
            &validated.envelope_bytes,
            "Pending",
            None,
            Some(reason.as_str().to_owned()),
        ),
        PreparedRecoveryClassification::Rejected { terminal_kind } => prepared_operation_report(
            public_root,
            args,
            &validated.envelope,
            &validated.envelope_bytes,
            "Rejected",
            None,
            Some(terminal_kind),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn prepared_operation_report(
    public_root: &str,
    args: &WriteCanary,
    envelope: &PreparedMutationEnvelopeV1,
    envelope_bytes: &[u8],
    outcome: &str,
    applied_block_height: Option<u64>,
    evidence: Option<String>,
) -> Result<Value> {
    let operation = &envelope.operation;
    let mut extra = Map::new();
    extra.insert(
        "authorization_sha256".to_owned(),
        Value::String(envelope.binding.authorization_sha256.clone()),
    );
    extra.insert(
        "authorization_nonce".to_owned(),
        Value::String(envelope.binding.authorization_nonce.clone()),
    );
    extra.insert(
        "mutation_kind".to_owned(),
        Value::String(envelope.binding.kind.clone()),
    );
    extra.insert(
        "mutation_phase".to_owned(),
        Value::String(envelope.binding.phase.clone()),
    );
    extra.insert(
        "idempotency_key".to_owned(),
        Value::String(envelope.binding.idempotency_key.clone()),
    );
    extra.insert(
        "operation".to_owned(),
        Value::String(operation.label().to_owned()),
    );
    extra.insert(
        "transaction_hash_hex".to_owned(),
        operation
            .transaction_hash_hex()
            .map(|hash| Value::String(hash.to_owned()))
            .unwrap_or(Value::Null),
    );
    extra.insert(
        "prepared_envelope_sha256".to_owned(),
        Value::String(hex::encode(Sha256::digest(envelope_bytes))),
    );
    extra.insert(
        "prepared_envelope_size".to_owned(),
        Value::from(u64::try_from(envelope_bytes.len()).expect("bounded envelope size")),
    );
    extra.insert(
        "recovery_outcome".to_owned(),
        Value::String(outcome.to_owned()),
    );
    extra.insert(
        "applied_block_height".to_owned(),
        applied_block_height.map(Value::from).unwrap_or(Value::Null),
    );
    extra.insert(
        "evidence".to_owned(),
        evidence.map(Value::String).unwrap_or(Value::Null),
    );
    extra.insert(
        "execution_expires_at_unix_ms".to_owned(),
        Value::from(envelope.binding.execution_expires_at_unix_ms),
    );
    if args.operation == WriteCanaryOperation::FinalCanary {
        let fee_payment = operation
            .fee_payment()
            .ok_or_else(|| eyre!("final canary report omits its exact fee payment"))?;
        let fee_quote = operation
            .fee_quote()
            .ok_or_else(|| eyre!("final canary report omits its exact fee quote"))?;
        extra.insert(
            "fee_payment".to_owned(),
            json::to_value(fee_payment).wrap_err("serialize exact fee payment")?,
        );
        extra.insert(
            "fee_quote".to_owned(),
            json::to_value(fee_quote).wrap_err("serialize exact fee quote")?,
        );
    }
    report_value(
        "taira_write_canary",
        "ok",
        public_root,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        extra,
    )
}

fn prepare_onboarding_operation(
    config: &Config,
    args: &WriteCanary,
    public_root: &str,
    binding: &PreparedMutationBindingV1,
    fee_payment: &FeePaymentIntent,
    deadline: Instant,
) -> Result<PreparedMutationEnvelopeV1> {
    let token = args.read_onboarding_token()?;
    let signer = resolve_canary_signer(config)?;
    let canary_config = write_canary_config(config, public_root, &signer)?;
    let client = IrohaClient::builder(canary_config.clone())
        .build()?
        .with_request_deadline(deadline);
    let alias = canary_alias(signer.key_pair.public_key());
    let request =
        AccountOnboardingPlanRequestV1::try_new(alias, &signer.account_id, std::iter::empty())?;
    let receipt = client
        .plan_account_onboarding(&request, token.as_str())
        .wrap_err("failed to obtain an authenticated onboarding plan")?;
    let public_binding = binding.onboarding_binding(&receipt)?;
    let operation = match client
        .prepare_account_onboarding_transaction(
            &request,
            &receipt,
            &public_binding,
            fee_payment,
            token.as_str(),
        )
        .wrap_err("failed to prepare exact sponsored onboarding transaction")?
    {
        AccountOnboardingPrepareResponseV1::Prepared(prepared) => {
            PreparedTransactionOperationV1::OnboardingPrepared(*prepared)
        }
        AccountOnboardingPrepareResponseV1::ProofRequired(result) => {
            PreparedTransactionOperationV1::OnboardingProofRequired(
                PreparedOnboardingProofRequiredV1 {
                    schema: PREPARED_ONBOARDING_PROOF_REQUIRED_SCHEMA_V1.to_owned(),
                    receipt,
                    result: *result,
                },
            )
        }
    };
    let wire = operation
        .signed_transaction_wire_hex()
        .map(|wire| hex::decode(wire).wrap_err("prepared onboarding wire is not hexadecimal"))
        .transpose()?;
    let envelope = PreparedMutationEnvelopeV1 {
        schema: PREPARED_ENVELOPE_SCHEMA_V1.to_owned(),
        binding: binding.clone(),
        public_root: public_root.to_owned(),
        chain_id: canary_config.chain.to_string(),
        network_id: canary_config.network_id.to_string(),
        authority: canary_config.account.to_string(),
        operation,
    };
    validate_prepared_operation(
        config,
        PreparedOperationPolicyContext::Current(args),
        binding,
        public_root,
        envelope.clone(),
        wire,
        fee_payment,
        PreparedLifetimeCheck::LiveForward,
    )?;
    Ok(envelope)
}

fn prepare_faucet_operation(
    config: &Config,
    args: &WriteCanary,
    public_root: &str,
    binding: &PreparedMutationBindingV1,
    fee_payment: &FeePaymentIntent,
    deadline: Instant,
) -> Result<PreparedMutationEnvelopeV1> {
    let signer = resolve_canary_signer(config)?;
    let canary_config = write_canary_config(config, public_root, &signer)?;
    let client = IrohaClient::builder(canary_config.clone())
        .build()?
        .with_request_deadline(deadline);
    let faucet_policy = args.faucet_policy()?;
    let claim = solve_account_faucet_claim(
        public_root,
        &signer.account_id,
        &canary_config.network_id,
        canary_config.account_chain_discriminant,
        deadline,
    )?;
    let public_binding = binding.faucet_binding(&claim)?;
    let prepared = client
        .prepare_account_faucet_transaction(&claim, &public_binding, fee_payment, &faucet_policy)
        .wrap_err("failed to prepare exact faucet transaction")?;
    let wire = hex::decode(&prepared.signed_transaction_wire_hex)
        .wrap_err("prepared faucet wire is not hexadecimal")?;
    let envelope = PreparedMutationEnvelopeV1 {
        schema: PREPARED_ENVELOPE_SCHEMA_V1.to_owned(),
        binding: binding.clone(),
        public_root: public_root.to_owned(),
        chain_id: canary_config.chain.to_string(),
        network_id: canary_config.network_id.to_string(),
        authority: canary_config.account.to_string(),
        operation: PreparedTransactionOperationV1::FaucetPrepared(prepared),
    };
    validate_prepared_operation(
        config,
        PreparedOperationPolicyContext::Current(args),
        binding,
        public_root,
        envelope.clone(),
        Some(wire),
        fee_payment,
        PreparedLifetimeCheck::LiveForward,
    )?;
    Ok(envelope)
}

struct PreparedCanaryClient {
    signer: CanarySigner,
    client: IrohaClient,
}

fn prepare_canary_client(config: &Config, public_root: &str) -> Result<PreparedCanaryClient> {
    let signer = resolve_canary_signer(config)?;
    let client =
        IrohaClient::builder(write_canary_config(config, public_root, &signer)?).build()?;
    Ok(PreparedCanaryClient { signer, client })
}

fn submit_exact_prepared_operation(
    config: &Config,
    args: &WriteCanary,
    public_root: &str,
    validated: &ValidatedPreparedOperation,
    expected_fee_payment: &FeePaymentIntent,
    deadline: Instant,
) -> Result<PreparedRecoveryClassification> {
    // Production preparation consumes the caller's original end-to-end budget.
    let prepared_client = prepare_canary_client(config, public_root)?;
    submit_exact_prepared_operation_with_client(
        &prepared_client,
        args,
        validated,
        expected_fee_payment,
        deadline,
    )
}

fn submit_exact_prepared_operation_with_client(
    prepared_client: &PreparedCanaryClient,
    args: &WriteCanary,
    validated: &ValidatedPreparedOperation,
    expected_fee_payment: &FeePaymentIntent,
    deadline: Instant,
) -> Result<PreparedRecoveryClassification> {
    let signer = &prepared_client.signer;
    let client = prepared_client.client.with_request_deadline(deadline);
    let classification = classify_exact_prepared_operation(&client, validated)?;
    if !submit_required_after_classification(&validated.envelope.binding, &classification)? {
        return await_exact_prepared_operation(
            &client,
            validated,
            classification,
            deadline,
            Duration::from_millis(500),
        );
    }
    let submitted = match &validated.envelope.operation {
        PreparedTransactionOperationV1::OnboardingPrepared(prepared) => {
            let token = args.read_onboarding_token()?;
            let request = AccountOnboardingPlanRequestV1::try_new(
                canary_alias(signer.key_pair.public_key()),
                &signer.account_id,
                std::iter::empty(),
            )?;
            client
                .submit_prepared_account_onboarding_transaction(
                    &request,
                    prepared,
                    expected_fee_payment,
                    token.as_str(),
                )
                .map(|submitted| submitted.outcome)
        }
        PreparedTransactionOperationV1::FaucetPrepared(prepared) => {
            let faucet_policy = args.faucet_policy()?;
            client
                .submit_prepared_account_faucet_transaction(
                    prepared,
                    expected_fee_payment,
                    &faucet_policy,
                )
                .map(|submitted| submitted.outcome)
        }
        PreparedTransactionOperationV1::OnboardingProofRequired(_) => {
            eyre::bail!("a proof-required onboarding result must never be submitted")
        }
        PreparedTransactionOperationV1::FinalCanary(_) => {
            let transaction = validated.transaction()?;
            let prepared = iroha::client::PreparedTransactionPayload::from_transaction(transaction);
            if prepared.as_bytes() != validated.wire()? {
                eyre::bail!("raw submit bytes differ from the retained prepared envelope");
            }
            let blocking = BlockingIrohaClient::from_client(client.clone())?;
            blocking
                .submit_prepared_transaction_payload(&prepared)
                .and_then(|submitted| {
                    if submitted != transaction.hash() {
                        eyre::bail!("raw submit returned a different transaction hash");
                    }
                    Ok(PreparedTransactionOutcomeV1::Pending)
                })
        }
    };
    let submitted = match submitted {
        Ok(submitted) => submitted,
        Err(error) => {
            let reconciled = match classify_exact_prepared_operation(&client, validated) {
                Ok(reconciled) => reconciled,
                Err(error) if Instant::now() >= deadline && prepared_request_timed_out(&error) => {
                    return Ok(PreparedRecoveryClassification::Pending {
                        reason: PreparedWritePendingReason::ObservationUnavailable,
                    });
                }
                Err(error) => return Err(error),
            };
            return match reconciled {
                PreparedRecoveryClassification::Absent => Err(hint_submit_error(error))
                    .wrap_err("exact prepared transaction submission failed before observability"),
                reconciled => await_exact_prepared_operation(
                    &client,
                    validated,
                    reconciled,
                    deadline,
                    Duration::from_millis(500),
                ),
            };
        }
    };
    match submitted {
        PreparedTransactionOutcomeV1::Rejected => Ok(PreparedRecoveryClassification::Rejected {
            terminal_kind: "Rejected".to_owned(),
        }),
        PreparedTransactionOutcomeV1::Applied | PreparedTransactionOutcomeV1::Pending => {
            await_exact_prepared_operation(
                &client,
                validated,
                PreparedRecoveryClassification::Pending {
                    reason: PreparedWritePendingReason::AcceptedNotVisible,
                },
                deadline,
                Duration::from_millis(500),
            )
        }
    }
}

fn prepared_request_timed_out(error: &eyre::Report) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout)
            || cause
                .downcast_ref::<iroha::client::CapabilityProbeError>()
                .is_some_and(iroha::client::CapabilityProbeError::is_timeout)
            || cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
    })
}
/// Poll only the already authenticated transaction; submission is never repeated here.
/// Timeouts imposed by the remaining confirmation budget retain the last observation.
fn await_exact_prepared_operation(
    client: &IrohaClient,
    validated: &ValidatedPreparedOperation,
    mut classification: PreparedRecoveryClassification,
    deadline: Instant,
    poll_interval: Duration,
) -> Result<PreparedRecoveryClassification> {
    if poll_interval.is_zero() {
        eyre::bail!("prepared confirmation poll interval must be positive");
    }
    let bounded_client = client.with_request_deadline(deadline);
    loop {
        if matches!(
            classification,
            PreparedRecoveryClassification::Applied { .. }
                | PreparedRecoveryClassification::Rejected { .. }
        ) {
            return Ok(classification);
        }
        if classification == PreparedRecoveryClassification::Absent {
            classification = PreparedRecoveryClassification::Pending {
                reason: PreparedWritePendingReason::AcceptedNotVisible,
            };
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(classification);
        }
        std::thread::sleep(poll_interval.min(remaining));
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(classification);
        }
        let deadline_limits_request =
            client.torii_request_timeout().is_zero() || remaining < client.torii_request_timeout();
        match classify_exact_prepared_operation(&bounded_client, validated) {
            Ok(observed) => classification = observed,
            Err(error)
                if (deadline_limits_request || Instant::now() >= deadline)
                    && prepared_request_timed_out(&error) =>
            {
                // A shrinking deadline can cancel even a healthy read. Keep the
                // last observation and retry only within the original deadline.
            }
            Err(error) => return Err(error),
        }
    }
}

fn write_canary_config(
    config: &Config,
    public_root: &str,
    signer: &CanarySigner,
) -> Result<Config> {
    let mut canary_config = config.clone();
    canary_config.chain = DEFAULT_CHAIN_ID.into();
    canary_config.torii_api_url = Url::parse(&format!("{public_root}/"))
        .wrap_err_with(|| format!("invalid public root `{public_root}`"))?;
    canary_config.account = signer.account_id.clone();
    canary_config.account_chain_discriminant = DEFAULT_CHAIN_DISCRIMINANT;
    canary_config.key_pair = signer.key_pair.clone();
    canary_config.transaction_ttl = Duration::from_millis(DEFAULT_WRITE_TTL_MS);
    canary_config.transaction_status_timeout =
        Duration::from_millis(DEFAULT_WRITE_STATUS_TIMEOUT_MS);
    canary_config.transaction_add_nonce = false;
    Ok(canary_config)
}

trait ReportOutput {
    fn output_format(&self) -> CliOutputFormat;
    fn print_data(&mut self, data: &Value) -> Result<()>;
    fn println_data(&mut self, data: String) -> Result<()>;
}
struct RunContextReportOutput<'a, C: RunContext> {
    context: &'a mut C,
}
impl<C: RunContext> ReportOutput for RunContextReportOutput<'_, C> {
    fn output_format(&self) -> CliOutputFormat {
        self.context.output_format()
    }
    fn print_data(&mut self, data: &Value) -> Result<()> {
        self.context.print_data(data)
    }
    fn println_data(&mut self, data: String) -> Result<()> {
        self.context.println_data(data)
    }
}
struct WriterReportOutput<W> {
    write: W,
    output_format: CliOutputFormat,
}
impl<W: std::io::Write> ReportOutput for WriterReportOutput<W> {
    fn output_format(&self) -> CliOutputFormat {
        self.output_format
    }
    fn print_data(&mut self, data: &Value) -> Result<()> {
        let rendered = json::to_json_pretty(data).wrap_err("failed to render Taira report JSON")?;
        writeln!(self.write, "{rendered}").wrap_err("failed to write Taira report JSON")
    }
    fn println_data(&mut self, data: String) -> Result<()> {
        writeln!(self.write, "{data}").wrap_err("failed to write Taira report text")
    }
}
fn render_report<C: RunContext>(context: &mut C, json: bool, report: &Value) -> Result<()> {
    let mut output = RunContextReportOutput { context };
    render_report_to(&mut output, json, report)
}
fn render_report_to<O: ReportOutput>(output: &mut O, json: bool, report: &Value) -> Result<()> {
    if json || output.output_format() == CliOutputFormat::Json {
        output.print_data(report)
    } else {
        let object = report
            .as_object()
            .ok_or_else(|| eyre!("report must be an object"))?;
        let command = object
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("taira");
        let status = object
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let public_root = object
            .get("public_root")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_PUBLIC_ROOT);
        output.println_data(format!("{command}: {status} ({public_root})"))?;
        if let Some(checks) = object.get("checks").and_then(Value::as_array) {
            for check in checks {
                let name = check.get("name").and_then(Value::as_str).unwrap_or("check");
                let ok = check.get("ok").and_then(Value::as_bool).unwrap_or(false);
                let status_code = check
                    .get("http_status")
                    .and_then(Value::as_u64)
                    .map_or_else(|| "-".to_owned(), |value| value.to_string());
                let detail = check
                    .get("detail")
                    .and_then(Value::as_str)
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default();
                let marker = if ok { "ok" } else { "fail" };
                output.println_data(format!("  {marker} {name} HTTP {status_code}{detail}"))?;
            }
        }
        if let Some(warnings) = object.get("warnings").and_then(Value::as_array) {
            print_receipt_fields(output, object)?;
            for warning in warnings {
                if let Some(warning) = warning.as_str() {
                    output.println_data(format!("  warn {warning}"))?;
                }
            }
        }
        if let Some(failures) = object.get("failures").and_then(Value::as_array) {
            for failure in failures {
                if let Some(failure) = failure.as_str() {
                    output.println_data(format!("  fail {failure}"))?;
                }
            }
        }
        Ok(())
    }
}
fn report_status(report: &Value) -> Option<&str> {
    report
        .as_object()
        .and_then(|object| object.get("status"))
        .and_then(Value::as_str)
}
fn ensure_write_canary_succeeded(report: &Value) -> Result<()> {
    if report_status(report) == Some("ok") {
        return Ok(());
    }
    eyre::bail!("Taira write canary found hard failures")
}
fn print_receipt_fields<O: ReportOutput>(output: &mut O, object: &Map) -> Result<()> {
    const RECEIPT_FIELDS: &[&str] = &[
        "chain",
        "chain_discriminant",
        "account_id",
        "alias",
        "faucet_asset_id",
        "fee_payment",
        "fee_quote",
        "faucet_tx_hash",
        "ping_tx_hash",
        "applied_block_height",
        "terminal_kind",
        "tx_query_verified",
        "config_path",
    ];
    for field in RECEIPT_FIELDS {
        let Some(value) = object
            .get(*field)
            .filter(|value| !matches!(value, Value::Null))
        else {
            continue;
        };
        output.println_data(format!("  {field}: {}", display_json_scalar(value)))?;
    }
    Ok(())
}
fn display_json_scalar(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        _ => compact_json(value),
    }
}
fn report_value(
    command: &str,
    status: &str,
    public_root: &str,
    checks: Vec<Value>,
    warnings: Vec<String>,
    failures: Vec<String>,
    extra: Map,
) -> Result<Value> {
    let mut root = Map::new();
    root.insert("command".into(), Value::String(command.to_owned()));
    root.insert("status".into(), Value::String(status.to_owned()));
    root.insert("public_root".into(), Value::String(public_root.to_owned()));
    root.insert("checks".into(), Value::Array(checks));
    root.insert(
        "warnings".into(),
        Value::Array(warnings.into_iter().map(Value::String).collect()),
    );
    root.insert(
        "failures".into(),
        Value::Array(failures.into_iter().map(Value::String).collect()),
    );
    for (key, value) in extra {
        root.insert(key, value);
    }
    Ok(Value::Object(root))
}
fn push_check(
    checks: &mut Vec<Value>,
    name: &str,
    http_status: u16,
    ok: bool,
    detail: Option<String>,
) {
    let mut object = Map::new();
    object.insert("name".into(), Value::String(name.to_owned()));
    object.insert("http_status".into(), Value::from(u64::from(http_status)));
    object.insert("ok".into(), Value::from(ok));
    if let Some(detail) = detail {
        object.insert("detail".into(), Value::String(detail));
    }
    checks.push(Value::Object(object));
}
fn route_check_detail(expected_statuses: &[u16]) -> Option<String> {
    (expected_statuses.len() == 1 && expected_statuses[0] != 200).then(|| {
        format!(
            "mounted route is expected to return HTTP {} for this preflight shape",
            expected_statuses[0]
        )
    })
}
fn normalize_root_url(raw: &str) -> Result<String> {
    if raw.is_empty() {
        eyre::bail!("public root URL must not be empty");
    }
    if raw != raw.trim() {
        eyre::bail!("public root URL must not contain surrounding whitespace");
    }
    let parsed = Url::parse(raw).wrap_err_with(|| format!("invalid URL `{raw}`"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => eyre::bail!("unsupported URL scheme `{other}`"),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        eyre::bail!("public root URL must not contain credentials");
    }
    if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
        eyre::bail!("public root URL must be an origin without a path, query, or fragment");
    }
    let canonical = parsed.origin().ascii_serialization();
    if raw != canonical {
        eyre::bail!("public root URL must use the canonical origin spelling `{canonical}`");
    }
    Ok(canonical)
}
fn join_url(root: &str, path: &str) -> Result<Url> {
    let root = format!("{}/", root.trim_end_matches('/'));
    let suffix = path.trim_start_matches('/');
    Url::parse(&root)
        .and_then(|url| url.join(suffix))
        .wrap_err_with(|| format!("failed to build URL from `{root}` and `{path}`"))
}
fn validate_onboarding_token(token: &str) -> Result<&str> {
    let bytes = token.as_bytes();
    if !(32..=256).contains(&bytes.len()) || !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        eyre::bail!(
            "account onboarding token must contain 32..256 printable ASCII bytes without spaces or normalization"
        );
    }
    Ok(token)
}
fn read_onboarding_token_fd(fd: u32) -> Result<Zeroizing<String>> {
    let raw =
        crate::client_config::read_inherited_private_file(fd, 256, "account onboarding token")?;
    let token = std::str::from_utf8(&raw)
        .map_err(|_| eyre!("account onboarding token must contain printable ASCII"))?;
    validate_onboarding_token(token)?;
    Ok(Zeroizing::new(token.to_owned()))
}
#[cfg(unix)]
fn validate_onboarding_token_file_metadata(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        eyre::bail!("account onboarding token file must be owned by the current user");
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        eyre::bail!("account onboarding token file must not grant group or other access");
    }
    if mode & 0o400 == 0 {
        eyre::bail!("account onboarding token file must be owner-readable");
    }
    Ok(())
}
#[cfg(not(unix))]
fn validate_onboarding_token_file_metadata(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}
fn read_onboarding_token_file(path: &Path) -> Result<Zeroizing<String>> {
    let before =
        fs::symlink_metadata(path).wrap_err("failed to inspect account onboarding token file")?;
    if before.file_type().is_symlink() || !before.file_type().is_file() {
        eyre::bail!("account onboarding token file must be a regular non-symlink file");
    }
    validate_onboarding_token_file_metadata(&before)?;
    #[cfg(unix)]
    let mut file = {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .wrap_err("failed to securely open account onboarding token file")?;
        fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .wrap_err("failed to open account onboarding token file")?;
    let opened = file
        .metadata()
        .wrap_err("failed to inspect opened account onboarding token file")?;
    if !opened.file_type().is_file() {
        eyre::bail!("account onboarding token file must remain a regular file");
    }
    validate_onboarding_token_file_metadata(&opened)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            eyre::bail!("account onboarding token file changed during secure open");
        }
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(257));
    std::io::Read::by_ref(&mut file)
        .take(257)
        .read_to_end(&mut raw)
        .wrap_err("failed to read account onboarding token file")?;
    if raw.len() > 256 {
        eyre::bail!("account onboarding token file exceeds the maximum credential length");
    }
    let token = std::str::from_utf8(&raw)
        .map_err(|_| eyre!("account onboarding token file must contain printable ASCII"))?;
    validate_onboarding_token(token)?;
    Ok(Zeroizing::new(token.to_owned()))
}
fn http_client() -> Result<HttpClient> {
    HttpClient::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .user_agent("iroha-taira-devex/1")
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .wrap_err("failed to build HTTP client")
}
fn http_json(
    http: &HttpClient,
    method: reqwest::Method,
    url: &str,
    body: Option<&Value>,
) -> Result<HttpJson> {
    let mut request = http
        .request(method, url)
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(body) = body {
        let bytes = json::to_vec(body).map_err(|err| eyre!("encode JSON request body: {err}"))?;
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes);
    }
    let response = request
        .send()
        .wrap_err_with(|| format!("request failed for {url}"))?;
    decode_http_json_response(response)
}
fn http_readiness(http: &HttpClient, url: &str) -> Result<HttpJson> {
    // Successful readiness is plain text; failures use the typed JSON envelope.
    // Bound the response and retain only exact success or a bounded machine code.
    let response = http
        .get(url)
        .header(reqwest::header::ACCEPT, "text/plain, application/json")
        .send()
        .wrap_err_with(|| format!("readiness request failed for {url}"))?;
    let status = response.status().as_u16();
    let plain_text = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim() == "text/plain")
        });
    if response
        .content_length()
        .is_some_and(|length| length > READINESS_RESPONSE_MAX_BYTES)
    {
        return Ok(HttpJson { status, body: None });
    }
    let mut bytes = Vec::new();
    response
        .take(READINESS_RESPONSE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .wrap_err("failed to read bounded Taira readiness response")?;
    let body = if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > READINESS_RESPONSE_MAX_BYTES {
        None
    } else if status == 200 {
        (plain_text && bytes.as_slice() == b"Ready").then(|| Value::from("Ready"))
    } else {
        json::from_slice(&bytes).ok()
    };
    Ok(HttpJson { status, body })
}
fn readiness_error_code(body: Option<&Value>) -> &str {
    body.and_then(|body| body.get("code"))
        .and_then(Value::as_str)
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 64
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
        .unwrap_or("unspecified")
}
fn http_mcp_json(
    http: &HttpClient,
    url: &str,
    request_id: u64,
    method: &str,
    params: Value,
) -> Result<HttpJson> {
    http_mcp_json_with_timeout(
        http,
        url,
        request_id,
        method,
        params,
        Duration::from_secs(30),
    )
}

fn http_mcp_json_with_timeout(
    http: &HttpClient,
    url: &str,
    request_id: u64,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<HttpJson> {
    let mut params = params
        .as_object()
        .cloned()
        .ok_or_else(|| eyre!("MCP `{method}` params must be an object"))?;
    if params.contains_key("_meta") {
        eyre::bail!("MCP `{method}` params must not override request metadata");
    }
    let routing_name = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    }
    .map(|field| {
        params
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| eyre!("MCP `{method}` params require a non-empty `{field}`"))
    })
    .transpose()?;
    let mut meta = Map::new();
    meta.insert(
        mcp_wire::META_PROTOCOL_VERSION.to_owned(),
        Value::String(mcp_wire::MODERN_PROTOCOL_VERSION.to_owned()),
    );
    meta.insert(
        mcp_wire::META_CLIENT_CAPABILITIES.to_owned(),
        Value::Object(Map::new()),
    );
    meta.insert(
        mcp_wire::META_CLIENT_INFO.to_owned(),
        norito::json!({
            "name": MCP_CLIENT_NAME,
            "version": MCP_CLIENT_VERSION
        }),
    );
    params.insert("_meta".to_owned(), Value::Object(meta));
    let payload = norito::json!({
        "jsonrpc": "2.0",
        "id": (request_id),
        "method": (method),
        "params": (Value::Object(params))
    });
    let bytes = json::to_vec(&payload).map_err(|err| eyre!("encode MCP request body: {err}"))?;
    let mut request = http
        .post(url)
        .timeout(timeout)
        .header(reqwest::header::ACCEPT, MCP_ACCEPT)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            mcp_wire::HEADER_PROTOCOL_VERSION,
            mcp_wire::MODERN_PROTOCOL_VERSION,
        )
        .header(mcp_wire::HEADER_METHOD, method);
    if let Some(routing_name) = routing_name.as_deref() {
        request = request.header(
            mcp_wire::HEADER_NAME,
            mcp_wire::encode_mirrored_header_value(routing_name),
        );
    }
    let response = request
        .body(bytes)
        .send()
        .wrap_err_with(|| format!("MCP `{method}` request failed for {url}"))?;
    decode_http_json_response(response)
}
fn account_signed_soracloud_status(client: &IrohaClient) -> Result<HttpJson> {
    let response = client
        .get_soracloud_status_response()
        .wrap_err("canonical account-signed Soracloud status request failed")?;
    let status = response.status().as_u16();
    let text = String::from_utf8(response.body().to_vec())
        .wrap_err("canonical account-signed Soracloud status response is not UTF-8")?;
    let body = if text.trim().is_empty() {
        None
    } else {
        json::from_str::<Value>(&text).ok()
    };
    Ok(HttpJson { status, body })
}
fn decode_http_json_response(response: reqwest::blocking::Response) -> Result<HttpJson> {
    let status = response.status().as_u16();
    let text = response
        .text()
        .wrap_err("failed to read Taira HTTP response body")?;
    let parsed = if text.trim().is_empty() {
        None
    } else {
        json::from_str::<Value>(&text).ok()
    };
    Ok(HttpJson {
        status,
        body: parsed,
    })
}
fn decode_inrou_canary_health_response(response: reqwest::blocking::Response) -> Result<HttpJson> {
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|length| length > INROU_CANARY_HEALTH_RESPONSE_MAX_BYTES)
    {
        eyre::bail!("Taira Inrou health response exceeds the V1 byte limit");
    }
    decode_inrou_canary_health_reader(status, response)
}
fn decode_inrou_canary_health_reader(status: u16, reader: impl std::io::Read) -> Result<HttpJson> {
    let mut bytes = Vec::new();
    reader
        .take(INROU_CANARY_HEALTH_RESPONSE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .wrap_err("failed to read Taira Inrou health response body")?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > INROU_CANARY_HEALTH_RESPONSE_MAX_BYTES {
        eyre::bail!("Taira Inrou health response exceeds the V1 byte limit");
    }
    let text = std::str::from_utf8(&bytes)
        .wrap_err("Taira Inrou health response body is not exact UTF-8")?;
    let body = if text.trim().is_empty() {
        None
    } else {
        json::from_str::<Value>(text).ok()
    };
    Ok(HttpJson { status, body })
}
fn collect_status_warnings(status: Option<&Value>, warnings: &mut Vec<String>) {
    let Some(status) = status else {
        warnings.push("/status returned a non-JSON body".to_owned());
        return;
    };
    if value_path_bool(status, &["sumeragi", "tx_queue_saturated"]).unwrap_or(false) {
        warnings.push("public transaction queue reports saturation".to_owned());
    }
    if let Some(rejected) = value_path_u64(status, &["txs_rejected_recent_5m"])
        && rejected > 0
    {
        warnings.push(format!(
            "recent rejected transactions in /status: {rejected}"
        ));
    }
    if let Some(queue) = value_path_u64(status, &["queue_size"])
        && queue > 0
    {
        warnings.push(format!("public queue has {queue} pending transaction(s)"));
    }
}
fn value_path<'a>(mut value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    for key in path {
        value = value.as_object()?.get(*key)?;
    }
    Some(value)
}
fn value_path_u64(value: &Value, path: &[&str]) -> Option<u64> {
    value_path(value, path).and_then(Value::as_u64)
}
fn value_path_bool(value: &Value, path: &[&str]) -> Option<bool> {
    value_path(value, path).and_then(Value::as_bool)
}
fn validate_public_status(status: Option<&Value>) -> Result<(), String> {
    let status = status
        .and_then(Value::as_object)
        .ok_or_else(|| "/status returned a non-object JSON body".to_owned())?;
    if status.contains_key("tx_queue_saturated") {
        return Err(
            "/status contains retired root `tx_queue_saturated`; expected `sumeragi.tx_queue_saturated`"
                .to_owned(),
        );
    }
    status
        .get("sumeragi")
        .and_then(Value::as_object)
        .and_then(|sumeragi| sumeragi.get("tx_queue_saturated"))
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            "/status field `sumeragi.tx_queue_saturated` must be a boolean".to_owned()
        })?;
    Ok(())
}
fn validate_time_snapshot(snapshot: Option<&Value>, scope: DoctorScope) -> Result<(), String> {
    let snapshot = snapshot
        .and_then(Value::as_object)
        .ok_or_else(|| "/v1/time/now returned a non-object JSON body".to_owned())?;
    let unsigned = |field: &str| {
        snapshot
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("/v1/time/now field `{field}` must be a nonnegative integer"))
    };
    if unsigned("now")? == 0 {
        return Err("/v1/time/now field `now` must be a positive integer".to_owned());
    }
    let samples = unsigned("sample_count")?;
    let peers = unsigned("peer_count")?;
    unsigned("confidence_ms")?;
    snapshot
        .get("offset_ms")
        .and_then(Value::as_i64)
        .ok_or_else(|| "/v1/time/now field `offset_ms` must be an integer".to_owned())?;
    let mode = snapshot.get("enforcement_mode").and_then(Value::as_str);
    if !matches!(mode, Some("warn" | "reject")) {
        return Err("/v1/time/now has an unknown time enforcement mode".to_owned());
    }
    let fallback = snapshot
        .get("fallback")
        .and_then(Value::as_bool)
        .ok_or_else(|| "/v1/time/now field `fallback` must be a boolean".to_owned())?;
    let health = snapshot
        .get("health")
        .and_then(Value::as_object)
        .ok_or_else(|| "/v1/time/now field `health` must be an object".to_owned())?;
    let flag = |field: &str| {
        health
            .get(field)
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("/v1/time/now health field `{field}` must be a boolean"))
    };
    let healthy = flag("healthy")?;
    let min_samples_ok = flag("min_samples_ok")?;
    let offset_ok = flag("offset_ok")?;
    let confidence_ok = flag("confidence_ok")?;
    if healthy != (!fallback && min_samples_ok && offset_ok && confidence_ok)
        || (min_samples_ok && (samples == 0 || peers == 0))
        || samples > peers
    {
        return Err("/v1/time/now has inconsistent sample or health fields".to_owned());
    }
    // Missing synchronization is visible but does not gate the basic testnet.
    // An observed violation of the node's configured clock bounds still does.
    if !offset_ok || !confidence_ok {
        return Err("/v1/time/now exceeds configured offset or confidence bounds".to_owned());
    }
    if scope == DoctorScope::Full {
        if mode != Some("reject") {
            return Err("/v1/time/now is not using fail-closed time enforcement".to_owned());
        }
        if fallback {
            return Err("/v1/time/now is using the local-clock fallback".to_owned());
        }
        if !healthy {
            return Err("/v1/time/now network time is not healthy".to_owned());
        }
    }
    Ok(())
}

fn collect_time_warnings(snapshot: Option<&Value>, warnings: &mut Vec<String>) {
    let Some(snapshot) = snapshot else { return };
    if snapshot.get("enforcement_mode").and_then(Value::as_str) != Some("reject")
        || snapshot.pointer("/health/healthy").and_then(Value::as_bool) != Some(true)
    {
        warnings.push(format!(
            "network time: enforcement_mode={}, fallback={}, sample_count={}, peer_count={}, healthy={}, min_samples_ok={}, offset_ok={}, confidence_ok={}",
            snapshot["enforcement_mode"].as_str().expect("validated mode"),
            snapshot["fallback"].as_bool().expect("validated fallback"),
            snapshot["sample_count"].as_u64().expect("validated sample count"),
            snapshot["peer_count"].as_u64().expect("validated peer count"),
            snapshot["health"]["healthy"].as_bool().expect("validated health"),
            snapshot["health"]["min_samples_ok"].as_bool().expect("validated samples"),
            snapshot["health"]["offset_ok"].as_bool().expect("validated offset"),
            snapshot["health"]["confidence_ok"].as_bool().expect("validated confidence"),
        ));
    }
}

fn tagged_enum_name<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    let object = value.as_object()?;
    if object.len() != 2 || !object.get("value").is_some_and(Value::is_null) {
        return None;
    }
    object.get(field)?.as_str()
}
fn exact_soracloud_status_object<'a>(
    value: &'a Value,
    context: &str,
    fields: &[&str],
) -> Result<&'a Map, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))?;
    if let Some(field) = fields.iter().find(|field| !object.contains_key(**field)) {
        return Err(format!("{context} is missing required field `{field}`"));
    }
    if let Some(field) = object
        .keys()
        .find(|field| !fields.contains(&field.as_str()))
    {
        return Err(format!("{context} contains unknown field `{field}`"));
    }
    Ok(object)
}
fn soracloud_status_field<'a>(
    object: &'a Map,
    field: &str,
    context: &str,
) -> Result<&'a Value, String> {
    object
        .get(field)
        .ok_or_else(|| format!("{context} is missing required field `{field}`"))
}
fn soracloud_status_u64(object: &Map, field: &str, context: &str) -> Result<u64, String> {
    soracloud_status_field(object, field, context)?
        .as_u64()
        .ok_or_else(|| format!("{context}.{field} must be a nonnegative integer"))
}
fn soracloud_status_bool(object: &Map, field: &str, context: &str) -> Result<bool, String> {
    soracloud_status_field(object, field, context)?
        .as_bool()
        .ok_or_else(|| format!("{context}.{field} must be a boolean"))
}
fn soracloud_status_string<'a>(
    object: &'a Map,
    field: &str,
    context: &str,
) -> Result<&'a str, String> {
    soracloud_status_field(object, field, context)?
        .as_str()
        .ok_or_else(|| format!("{context}.{field} must be a string"))
}
fn validate_soracloud_nullable_string(
    object: &Map,
    field: &str,
    context: &str,
) -> Result<(), String> {
    let value = soracloud_status_field(object, field, context)?;
    if value.is_null() || value.is_string() {
        Ok(())
    } else {
        Err(format!("{context}.{field} must be a string or null"))
    }
}
fn validate_soracloud_string_array(object: &Map, field: &str, context: &str) -> Result<(), String> {
    let values = soracloud_status_field(object, field, context)?
        .as_array()
        .ok_or_else(|| format!("{context}.{field} must be an array"))?;
    if values.iter().all(Value::is_string) {
        Ok(())
    } else {
        Err(format!("{context}.{field} must contain only strings"))
    }
}
fn validate_soracloud_tagged_unit<'a>(
    value: &'a Value,
    tag: &str,
    variants: &[&str],
    context: &str,
) -> Result<&'a str, String> {
    let object = exact_soracloud_status_object(value, context, &[tag, "value"])?;
    if !soracloud_status_field(object, "value", context)?.is_null() {
        return Err(format!("{context}.value must be null"));
    }
    let variant = soracloud_status_string(object, tag, context)?;
    if variants.contains(&variant) {
        Ok(variant)
    } else {
        Err(format!("{context}.{tag} has unknown variant `{variant}`"))
    }
}
fn validate_soracloud_hash(value: &Value, context: &str) -> Result<(), String> {
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{context} must be a canonical hash string"))?;
    let hash = json::from_value::<Hash>(value.clone())
        .map_err(|_| format!("{context} must be a canonical hash string"))?;
    let canonical =
        json::to_value(&hash).map_err(|_| format!("{context} must be a canonical hash string"))?;
    if canonical.as_str() != Some(raw) {
        return Err(format!("{context} must use exact canonical hash text"));
    }
    Ok(())
}
fn validate_soracloud_bare_hash(value: &Value, context: &str) -> Result<(), String> {
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{context} must be an exact bare hash string"))?;
    let hash =
        Hash::from_str(raw).map_err(|_| format!("{context} must be an exact bare hash string"))?;
    if hash.to_string() != raw {
        return Err(format!("{context} must use exact bare hash text"));
    }
    Ok(())
}
fn validate_soracloud_nullable_bare_hash(
    object: &Map,
    field: &str,
    context: &str,
) -> Result<(), String> {
    let value = soracloud_status_field(object, field, context)?;
    if value.is_null() {
        Ok(())
    } else {
        validate_soracloud_bare_hash(value, &format!("{context}.{field}"))
    }
}
fn validate_canonical_soracloud_route_host(host: &str, context: &str) -> Result<(), String> {
    if host.is_empty()
        || host.chars().any(char::is_whitespace)
        || host.chars().any(char::is_control)
    {
        return Err(format!(
            "{context} must be an exact nonempty host without whitespace"
        ));
    }
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        if address.to_string() == host {
            return Ok(());
        }
        return Err(format!("{context} must use canonical IP-literal spelling"));
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(format!("{context} must use canonical IPv4 spelling"));
    }
    if !host.is_ascii()
        || host.len() > 253
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(format!(
            "{context} must be a lowercase canonical DNS host or canonical IP literal"
        ));
    }
    Ok(())
}
fn validate_canonical_soracloud_route_prefix(prefix: &str, context: &str) -> Result<(), String> {
    let Some(suffix) = prefix.strip_prefix('/') else {
        return Err(format!(
            "{context} must be an exact canonical absolute route prefix"
        ));
    };
    if prefix.is_empty()
        || prefix.contains('\\')
        || prefix.contains('?')
        || prefix.contains('#')
        || prefix.chars().any(char::is_whitespace)
        || prefix.chars().any(char::is_control)
        || (prefix != "/"
            && (prefix.ends_with('/')
                || suffix
                    .split('/')
                    .any(|component| component.is_empty() || matches!(component, "." | ".."))))
    {
        return Err(format!(
            "{context} must be an exact canonical absolute route prefix"
        ));
    }
    Ok(())
}
fn validate_soracloud_service_health(value: &Value) -> Result<&str, String> {
    const FULL_FIELDS: &[&str] = &[
        "mode",
        "status",
        "message",
        "observed_height",
        "observed_block_hash",
        "state_dir",
        "service_revisions",
        "healthy_service_revisions",
        "hydrating_service_revisions",
        "degraded_service_revisions",
        "unavailable_service_revisions",
        "apartments",
        "running_apartments",
        "expired_apartments",
    ];
    const UNAVAILABLE_FIELDS: &[&str] = &["mode", "status", "message"];
    let context = "/v1/soracloud/status.service_health";
    let unvalidated = value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))?;
    let status = unvalidated
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context}.status must be a string"))?;
    let fields = if unvalidated.len() == UNAVAILABLE_FIELDS.len() {
        UNAVAILABLE_FIELDS
    } else {
        FULL_FIELDS
    };
    let object = exact_soracloud_status_object(value, context, fields)?;
    if soracloud_status_string(object, "mode", context)? != "embedded_runtime_manager" {
        return Err(format!(
            "{context}.mode is not the canonical V1 runtime mode"
        ));
    }
    soracloud_status_string(object, "message", context)?;
    if fields == UNAVAILABLE_FIELDS {
        if status != "unavailable" {
            return Err(format!(
                "{context} compact form is reserved for unavailable runtime"
            ));
        }
        return Ok(status);
    }
    if !["idle", "healthy", "degraded", "unavailable"].contains(&status) {
        return Err(format!("{context}.status has unknown value `{status}`"));
    }
    for field in [
        "observed_height",
        "service_revisions",
        "healthy_service_revisions",
        "hydrating_service_revisions",
        "degraded_service_revisions",
        "unavailable_service_revisions",
        "apartments",
        "running_apartments",
        "expired_apartments",
    ] {
        soracloud_status_u64(object, field, context)?;
    }
    validate_soracloud_nullable_bare_hash(object, "observed_block_hash", context)?;
    soracloud_status_string(object, "state_dir", context)?;
    Ok(status)
}
fn validate_soracloud_routing(value: &Value) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "configured_lane_count",
        "declared_lane_count",
        "active_lane_count",
        "active_lane_ids",
        "autoscale_capacity_lane_count",
        "autoscale_capacity_lane_ids",
        "dataspace_count",
        "routing_rules",
        "default_lane_id",
        "default_dataspace_id",
    ];
    let context = "/v1/soracloud/status.routing";
    let object = exact_soracloud_status_object(value, context, FIELDS)?;
    for field in [
        "configured_lane_count",
        "declared_lane_count",
        "active_lane_count",
        "autoscale_capacity_lane_count",
        "dataspace_count",
        "routing_rules",
        "default_lane_id",
        "default_dataspace_id",
    ] {
        soracloud_status_u64(object, field, context)?;
    }
    for (count_field, ids_field) in [
        ("active_lane_count", "active_lane_ids"),
        (
            "autoscale_capacity_lane_count",
            "autoscale_capacity_lane_ids",
        ),
    ] {
        let ids = soracloud_status_field(object, ids_field, context)?
            .as_array()
            .ok_or_else(|| format!("{context}.{ids_field} must be an array"))?;
        if !ids.iter().all(|value| value.as_u64().is_some()) {
            return Err(format!(
                "{context}.{ids_field} must contain only nonnegative integers"
            ));
        }
        if soracloud_status_u64(object, count_field, context)?
            != u64::try_from(ids.len()).unwrap_or(u64::MAX)
        {
            return Err(format!(
                "{context}.{count_field} does not match {ids_field}"
            ));
        }
    }
    Ok(())
}
fn validate_soracloud_topology(value: &Value) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "active_capability_adverts",
        "placed_host_count",
        "hosted_replica_count",
        "unavailable_replica_count",
    ];
    let context = "/v1/soracloud/status.hosted_http_topology";
    let object = exact_soracloud_status_object(value, context, FIELDS)?;
    for field in FIELDS {
        soracloud_status_u64(object, field, context)?;
    }
    Ok(())
}
fn validate_soracloud_runtime_pressure(value: &Value) -> Result<(), String> {
    const FULL_FIELDS: &[&str] = &[
        "enabled",
        "state_dir",
        "observed_height",
        "service_revisions",
        "apartments",
        "max_load_factor_bps",
        "authoritative_pending_mailbox_messages",
        "bundle_cache_misses",
        "artifact_cache_misses",
    ];
    let context = "/v1/soracloud/status.resource_pressure.runtime";
    let unvalidated = value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))?;
    let enabled = unvalidated
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{context}.enabled must be a boolean"))?;
    if !enabled {
        exact_soracloud_status_object(value, context, &["enabled"])?;
        return Ok(());
    }
    let object = exact_soracloud_status_object(value, context, FULL_FIELDS)?;
    soracloud_status_string(object, "state_dir", context)?;
    for field in &FULL_FIELDS[2..] {
        soracloud_status_u64(object, field, context)?;
    }
    if soracloud_status_u64(object, "max_load_factor_bps", context)? > 10_000 {
        return Err(format!(
            "{context}.max_load_factor_bps exceeds the V1 basis-point domain"
        ));
    }
    Ok(())
}
fn validate_soracloud_resource_pressure(value: &Value) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "queue_active",
        "queue_queued",
        "queue_capacity",
        "queue_saturated",
        "high_load_threshold",
        "high_load",
        "runtime",
    ];
    let context = "/v1/soracloud/status.resource_pressure";
    let object = exact_soracloud_status_object(value, context, FIELDS)?;
    for field in [
        "queue_active",
        "queue_queued",
        "queue_capacity",
        "high_load_threshold",
    ] {
        soracloud_status_u64(object, field, context)?;
    }
    soracloud_status_bool(object, "queue_saturated", context)?;
    soracloud_status_bool(object, "high_load", context)?;
    validate_soracloud_runtime_pressure(soracloud_status_field(object, "runtime", context)?)
}
fn validate_soracloud_failed_admissions(value: &Value) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "available",
        "total",
        "governance_manifest_rejected",
        "sorafs_provider_rejected",
    ];
    let context = "/v1/soracloud/status.failed_admissions";
    let object = exact_soracloud_status_object(value, context, FIELDS)?;
    soracloud_status_bool(object, "available", context)?;
    for field in &FIELDS[1..] {
        soracloud_status_u64(object, field, context)?;
    }
    Ok(())
}
fn validate_soracloud_runtime_snapshot(value: &Value) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "schema_version",
        "observed_height",
        "observed_block_hash",
        "local_peer_id",
        "services",
        "apartments",
    ];
    let context = "/v1/soracloud/status.runtime_manager.snapshot";
    let object = exact_soracloud_status_object(value, context, FIELDS)?;
    if soracloud_status_u64(object, "schema_version", context)? != 1 {
        return Err(format!("{context}.schema_version must equal 1"));
    }
    soracloud_status_u64(object, "observed_height", context)?;
    validate_soracloud_nullable_bare_hash(object, "observed_block_hash", context)?;
    validate_soracloud_nullable_string(object, "local_peer_id", context)?;
    for field in ["services", "apartments"] {
        if !soracloud_status_field(object, field, context)?.is_object() {
            return Err(format!("{context}.{field} must be an object"));
        }
    }
    Ok(())
}
fn validate_soracloud_runtime_manager(value: &Value) -> Result<bool, String> {
    let context = "/v1/soracloud/status.runtime_manager";
    let unvalidated = value
        .as_object()
        .ok_or_else(|| format!("{context} must be an object"))?;
    let available = unvalidated
        .get("available")
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{context}.available must be a boolean"))?;
    if !available {
        exact_soracloud_status_object(value, context, &["available"])?;
        return Ok(false);
    }
    let object =
        exact_soracloud_status_object(value, context, &["available", "state_dir", "snapshot"])?;
    soracloud_status_string(object, "state_dir", context)?;
    validate_soracloud_runtime_snapshot(soracloud_status_field(object, "snapshot", context)?)?;
    Ok(true)
}
fn validate_soracloud_rollout(value: &Value, context: &str) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "rollout_handle",
        "baseline_version",
        "candidate_version",
        "canary_percent",
        "traffic_percent",
        "stage",
        "health_failures",
        "max_health_failures",
        "health_window_secs",
        "created_sequence",
        "updated_sequence",
    ];
    let object = exact_soracloud_status_object(value, context, FIELDS)?;
    let rollout_handle = soracloud_status_string(object, "rollout_handle", context)?;
    let baseline_version = soracloud_status_string(object, "baseline_version", context)?;
    let candidate_version = soracloud_status_string(object, "candidate_version", context)?;
    if rollout_handle.trim().is_empty()
        || baseline_version.trim().is_empty()
        || candidate_version.trim().is_empty()
    {
        return Err(format!(
            "{context} rollout identity fields must be nonempty"
        ));
    }
    if baseline_version == candidate_version {
        return Err(format!(
            "{context}.baseline_version must differ from candidate_version"
        ));
    }
    let canary_percent = soracloud_status_u64(object, "canary_percent", context)?;
    let traffic_percent = soracloud_status_u64(object, "traffic_percent", context)?;
    let health_failures = soracloud_status_u64(object, "health_failures", context)?;
    let max_health_failures = soracloud_status_u64(object, "max_health_failures", context)?;
    let health_window_secs = soracloud_status_u64(object, "health_window_secs", context)?;
    let created_sequence = soracloud_status_u64(object, "created_sequence", context)?;
    let updated_sequence = soracloud_status_u64(object, "updated_sequence", context)?;
    if canary_percent > 100 || traffic_percent > 100 {
        return Err(format!(
            "{context} rollout percentages must be within 0..=100"
        ));
    }
    for (field, value, maximum) in [
        ("health_failures", health_failures, u64::from(u32::MAX)),
        (
            "max_health_failures",
            max_health_failures,
            u64::from(u32::MAX),
        ),
        (
            "health_window_secs",
            health_window_secs,
            u64::from(u32::MAX),
        ),
    ] {
        if value > maximum {
            return Err(format!("{context}.{field} exceeds the V1 u32 domain"));
        }
    }
    if max_health_failures == 0 || health_window_secs == 0 {
        return Err(format!(
            "{context}.max_health_failures and health_window_secs must be positive"
        ));
    }
    if updated_sequence < created_sequence {
        return Err(format!(
            "{context}.updated_sequence must not precede created_sequence"
        ));
    }
    let stage = validate_soracloud_tagged_unit(
        soracloud_status_field(object, "stage", context)?,
        "stage",
        &["Canary", "Promoted", "RolledBack"],
        &format!("{context}.stage"),
    )?;
    let stage_is_valid = match stage {
        "Canary" => {
            (1..100).contains(&canary_percent)
                && (canary_percent..100).contains(&traffic_percent)
                && health_failures < max_health_failures
        }
        "Promoted" => traffic_percent == 100 && health_failures == 0,
        "RolledBack" => traffic_percent == 0 && health_failures >= max_health_failures,
        _ => unreachable!("tagged-unit validator returned an admitted rollout stage"),
    };
    if !stage_is_valid {
        return Err(format!(
            "{context} rollout counters do not match the exact V1 stage"
        ));
    }
    Ok(())
}
fn validate_soracloud_network_policy(value: &Value, context: &str) -> Result<(), String> {
    let object = exact_soracloud_status_object(value, context, &["mode", "value"])?;
    let mode = soracloud_status_string(object, "mode", context)?;
    let payload = soracloud_status_field(object, "value", context)?;
    match mode {
        "Open" | "Isolated" if payload.is_null() => Ok(()),
        "Allowlist" if payload.is_array() => Ok(()),
        "Open" | "Isolated" => Err(format!("{context}.value must be null for `{mode}`")),
        "Allowlist" => Err(format!("{context}.value must be an array for `Allowlist`")),
        _ => Err(format!("{context}.mode has unknown variant `{mode}`")),
    }
}
fn validate_soracloud_revision(value: &Value, context: &str) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "sequence",
        "action",
        "service_version",
        "service_manifest_hash",
        "container_manifest_hash",
        "replicas",
        "execution_plane",
        "route_host",
        "route_path_prefix",
        "route_service_port",
        "route_visibility",
        "route_tls_mode",
        "base_url",
        "healthcheck_url",
        "public_discovery_content_cid",
        "public_discovery_url",
        "public_discovery_cid_host_url",
        "state_binding_count",
        "state_bindings",
        "lease_volumes",
        "allow_model_inference",
        "allow_model_training",
        "runtime",
        "allow_state_writes",
        "network",
        "cpu_millis",
        "memory_bytes",
        "ephemeral_storage_bytes",
        "max_open_files_per_process",
        "max_tasks",
        "start_grace_secs",
        "stop_grace_secs",
        "healthcheck_path",
        "required_config_names",
        "required_secret_names",
        "config_exports",
        "sandbox_profile_hash",
        "process_generation",
        "process_started_sequence",
        "signed_by",
    ];
    let object = exact_soracloud_status_object(value, context, FIELDS)?;
    soracloud_status_u64(object, "sequence", context)?;
    validate_soracloud_tagged_unit(
        soracloud_status_field(object, "action", context)?,
        "action",
        &[
            "Deploy",
            "Upgrade",
            "Rollback",
            "ConfigMutation",
            "SecretMutation",
            "StateMutation",
            "FheJobRun",
            "FhePolicyRegister",
            "FhePolicyRotate",
            "FhePolicyRevoke",
            "DecryptionRequest",
            "CiphertextQuery",
            "Rollout",
            "LeaseReportingEpochRollover",
        ],
        &format!("{context}.action"),
    )?;
    soracloud_status_string(object, "service_version", context)?;
    for field in [
        "service_manifest_hash",
        "container_manifest_hash",
        "sandbox_profile_hash",
    ] {
        validate_soracloud_hash(
            soracloud_status_field(object, field, context)?,
            &format!("{context}.{field}"),
        )?;
    }
    for field in [
        "replicas",
        "state_binding_count",
        "cpu_millis",
        "memory_bytes",
        "ephemeral_storage_bytes",
        "max_open_files_per_process",
        "max_tasks",
        "start_grace_secs",
        "stop_grace_secs",
        "process_generation",
        "process_started_sequence",
    ] {
        soracloud_status_u64(object, field, context)?;
    }
    let execution_plane = validate_soracloud_tagged_unit(
        soracloud_status_field(object, "execution_plane", context)?,
        "execution_plane",
        &["DeterministicService", "HttpService"],
        &format!("{context}.execution_plane"),
    )?;
    let route_host = soracloud_status_field(object, "route_host", context)?;
    let route_host_is_present = !route_host.is_null();
    if route_host_is_present {
        validate_canonical_soracloud_route_host(
            route_host
                .as_str()
                .ok_or_else(|| format!("{context}.route_host must be a string or null"))?,
            &format!("{context}.route_host"),
        )?;
    }
    let route_prefix = soracloud_status_field(object, "route_path_prefix", context)?;
    let route_prefix_is_present = !route_prefix.is_null();
    if route_prefix_is_present {
        validate_canonical_soracloud_route_prefix(
            route_prefix
                .as_str()
                .ok_or_else(|| format!("{context}.route_path_prefix must be a string or null"))?,
            &format!("{context}.route_path_prefix"),
        )?;
    }
    let route_service_port = soracloud_status_field(object, "route_service_port", context)?;
    let route_service_port_is_present = if route_service_port.is_null() {
        false
    } else {
        let port = route_service_port.as_u64().ok_or_else(|| {
            format!("{context}.route_service_port must be a positive V1 u16 or null")
        })?;
        if port == 0 || port > u64::from(u16::MAX) {
            return Err(format!(
                "{context}.route_service_port must be a positive V1 u16 or null"
            ));
        }
        true
    };
    let route_visibility = soracloud_status_field(object, "route_visibility", context)?;
    let route_visibility_is_present = if route_visibility.is_null() {
        false
    } else {
        let visibility = route_visibility.as_str().ok_or_else(|| {
            format!("{context}.route_visibility must be a V1 string variant or null")
        })?;
        if !matches!(visibility, "Public" | "Internal") {
            return Err(format!(
                "{context}.route_visibility has unknown V1 variant `{visibility}`"
            ));
        }
        true
    };
    let route_tls_mode = soracloud_status_field(object, "route_tls_mode", context)?;
    let route_tls_mode_is_present = if route_tls_mode.is_null() {
        false
    } else {
        let tls_mode = route_tls_mode.as_str().ok_or_else(|| {
            format!("{context}.route_tls_mode must be a V1 string variant or null")
        })?;
        if !matches!(tls_mode, "Required" | "Optional" | "Disabled") {
            return Err(format!(
                "{context}.route_tls_mode has unknown V1 variant `{tls_mode}`"
            ));
        }
        true
    };
    let route_fields_present = [
        route_host_is_present,
        route_prefix_is_present,
        route_service_port_is_present,
        route_visibility_is_present,
        route_tls_mode_is_present,
    ];
    if route_fields_present
        .iter()
        .any(|present| *present != route_host_is_present)
    {
        return Err(format!(
            "{context} must project either one complete V1 route or five null route fields"
        ));
    }
    if execution_plane == "HttpService" && !route_host_is_present {
        return Err(format!(
            "{context} HttpService revisions must project one complete V1 route"
        ));
    }
    for field in [
        "base_url",
        "healthcheck_url",
        "public_discovery_content_cid",
        "public_discovery_url",
        "public_discovery_cid_host_url",
        "healthcheck_path",
    ] {
        validate_soracloud_nullable_string(object, field, context)?;
    }
    for field in ["state_bindings", "lease_volumes", "config_exports"] {
        if !soracloud_status_field(object, field, context)?.is_array() {
            return Err(format!("{context}.{field} must be an array"));
        }
    }
    if soracloud_status_u64(object, "state_binding_count", context)?
        != u64::try_from(
            soracloud_status_field(object, "state_bindings", context)?
                .as_array()
                .expect("state_bindings was validated as an array")
                .len(),
        )
        .unwrap_or(u64::MAX)
    {
        return Err(format!(
            "{context}.state_binding_count does not match state_bindings"
        ));
    }
    for field in [
        "allow_model_inference",
        "allow_model_training",
        "allow_state_writes",
    ] {
        soracloud_status_bool(object, field, context)?;
    }
    validate_soracloud_tagged_unit(
        soracloud_status_field(object, "runtime", context)?,
        "runtime",
        &["Ivm", "Inrou"],
        &format!("{context}.runtime"),
    )?;
    validate_soracloud_network_policy(
        soracloud_status_field(object, "network", context)?,
        &format!("{context}.network"),
    )?;
    validate_soracloud_string_array(object, "required_config_names", context)?;
    validate_soracloud_string_array(object, "required_secret_names", context)?;
    soracloud_status_string(object, "signed_by", context)?;
    Ok(())
}
fn validate_soracloud_audit_event(value: &Value, context: &str) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "sequence",
        "action",
        "service_name",
        "from_version",
        "to_version",
        "service_manifest_hash",
        "container_manifest_hash",
        "process_generation",
        "config_generation",
        "secret_generation",
        "config_snapshot_hash",
        "secret_snapshot_hash",
        "binding_name",
        "state_key",
        "config_mutations",
        "secret_mutations",
        "governance_tx_hash",
        "rollout_state",
        "policy_name",
        "policy_snapshot_hash",
        "jurisdiction_tag",
        "consent_evidence_hash",
        "break_glass",
        "break_glass_reason",
        "lease_usage",
        "service_lease_commitment",
        "lease_reporting_epoch_rollover",
        "signed_by",
    ];
    exact_soracloud_status_object(value, context, FIELDS)?;

    // Torii intentionally projects away ledger-only block metadata and the
    // two fixed V1 schema markers. Restore those constants, validate the
    // authoritative data-model event, and project it back before comparing.
    // This keeps the public doctor boundary exactly aligned with every
    // action-specific, break-glass, rollout, and lease-accounting invariant.
    let mut authoritative_value = value.clone();
    let authoritative_object = authoritative_value
        .as_object_mut()
        .expect("the exact-object validator admitted an audit object");
    let signer = authoritative_object
        .remove("signed_by")
        .expect("the exact-object validator required signed_by");
    authoritative_object.insert("schema_version".to_owned(), Value::from(1_u64));
    authoritative_object.insert("block_height".to_owned(), Value::from(1_u64));
    authoritative_object.insert("block_timestamp_ms".to_owned(), Value::from(1_u64));
    authoritative_object.insert("signer".to_owned(), signer);
    if let Some(rollout) = authoritative_object
        .get_mut("rollout_state")
        .and_then(Value::as_object_mut)
    {
        rollout.insert("schema_version".to_owned(), Value::from(1_u64));
    }

    let event = json::from_value::<iroha::data_model::soracloud::SoraServiceAuditEventV1>(
        authoritative_value,
    )
    .map_err(|error| {
        format!("{context} is not exact authoritative audit-event V1 JSON: {error}")
    })?;
    event
        .validate()
        .map_err(|error| format!("{context} violates audit-event V1 invariants: {error}"))?;

    let mut canonical = json::to_value(&event)
        .map_err(|error| format!("{context} could not be canonically encoded: {error}"))?;
    let canonical_object = canonical
        .as_object_mut()
        .expect("an authoritative audit event serializes as an object");
    canonical_object.remove("schema_version");
    canonical_object.remove("block_height");
    canonical_object.remove("block_timestamp_ms");
    let signer = canonical_object
        .remove("signer")
        .expect("an authoritative audit event serializes its signer");
    canonical_object.insert("signed_by".to_owned(), signer);
    if let Some(rollout) = canonical_object
        .get_mut("rollout_state")
        .and_then(Value::as_object_mut)
    {
        rollout.remove("schema_version");
    }
    if &canonical != value {
        return Err(format!(
            "{context} is not exact canonical projected audit-event V1 JSON"
        ));
    }
    Ok(())
}
fn validate_soracloud_service_lease(value: &Value, context: &str) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "authoritative_state",
        "effective_status",
        "remaining_runtime_balance",
    ];
    let object = exact_soracloud_status_object(value, context, FIELDS)?;

    let authoritative_value = soracloud_status_field(object, "authoritative_state", context)?;
    let authoritative = json::from_value::<iroha::data_model::soracloud::SoraServiceLeaseStateV1>(
        authoritative_value.clone(),
    )
    .map_err(|error| {
        format!("{context}.authoritative_state is not exact SoraServiceLeaseStateV1 JSON: {error}")
    })?;
    authoritative.validate().map_err(|error| {
        format!(
            "{context}.authoritative_state violates SoraServiceLeaseStateV1 invariants: {error}"
        )
    })?;
    let canonical_authoritative = json::to_value(&authoritative).map_err(|error| {
        format!("{context}.authoritative_state could not be canonically encoded: {error}")
    })?;
    if &canonical_authoritative != authoritative_value {
        return Err(format!(
            "{context}.authoritative_state is not exact canonical SoraServiceLeaseStateV1 JSON"
        ));
    }

    let effective_value = soracloud_status_field(object, "effective_status", context)?;
    let effective_status =
        json::from_value::<iroha::data_model::soracloud::SoraServiceLeaseStatusV1>(
            effective_value.clone(),
        )
        .map_err(|error| format!("{context}.effective_status is not exact V1 JSON: {error}"))?;
    let canonical_effective = json::to_value(&effective_status).map_err(|error| {
        format!("{context}.effective_status could not be canonically encoded: {error}")
    })?;
    if &canonical_effective != effective_value {
        return Err(format!(
            "{context}.effective_status is not exact canonical V1 JSON"
        ));
    }

    let remaining_value = soracloud_status_field(object, "remaining_runtime_balance", context)?;
    let remaining = json::from_value::<Quantity>(remaining_value.clone()).map_err(|error| {
        format!("{context}.remaining_runtime_balance is not an exact V1 quantity: {error}")
    })?;
    let canonical_remaining = json::to_value(&remaining).map_err(|error| {
        format!("{context}.remaining_runtime_balance could not be canonically encoded: {error}")
    })?;
    if &canonical_remaining != remaining_value {
        return Err(format!(
            "{context}.remaining_runtime_balance is not an exact canonical V1 quantity"
        ));
    }
    Ok(())
}
fn validate_soracloud_service(value: &Value, index: usize) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "service_name",
        "current_version",
        "revision_count",
        "config_generation",
        "secret_generation",
        "config_entry_count",
        "secret_entry_count",
        "service_lease",
        "public_discovery_content_cid",
        "public_discovery_url",
        "public_discovery_cid_host_url",
        "latest_revision",
        "active_rollout",
        "last_rollout",
    ];
    let context = format!("/v1/soracloud/status.control_plane.services[{index}]");
    let object = exact_soracloud_status_object(value, &context, FIELDS)?;
    soracloud_status_string(object, "service_name", &context)?;
    soracloud_status_string(object, "current_version", &context)?;
    for field in [
        "revision_count",
        "config_generation",
        "secret_generation",
        "config_entry_count",
        "secret_entry_count",
    ] {
        soracloud_status_u64(object, field, &context)?;
    }
    let service_lease = soracloud_status_field(object, "service_lease", &context)?;
    if !service_lease.is_null() {
        validate_soracloud_service_lease(service_lease, &format!("{context}.service_lease"))?;
    }
    for field in [
        "public_discovery_content_cid",
        "public_discovery_url",
        "public_discovery_cid_host_url",
    ] {
        validate_soracloud_nullable_string(object, field, &context)?;
    }
    let revision = soracloud_status_field(object, "latest_revision", &context)?;
    if !revision.is_null() {
        validate_soracloud_revision(revision, &format!("{context}.latest_revision"))?;
    }
    for field in ["active_rollout", "last_rollout"] {
        let rollout = soracloud_status_field(object, field, &context)?;
        if !rollout.is_null() {
            validate_soracloud_rollout(rollout, &format!("{context}.{field}"))?;
        }
    }
    Ok(())
}
fn validate_soracloud_control_plane(value: &Value) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "schema_version",
        "service_count",
        "audit_event_count",
        "services",
        "recent_audit_events",
    ];
    let context = "/v1/soracloud/status.control_plane";
    let object = exact_soracloud_status_object(value, context, FIELDS)?;
    if soracloud_status_u64(object, "schema_version", context)? != 1 {
        return Err(format!("{context}.schema_version must equal 1"));
    }
    let services = soracloud_status_field(object, "services", context)?
        .as_array()
        .ok_or_else(|| format!("{context}.services must be an array"))?;
    if soracloud_status_u64(object, "service_count", context)?
        != u64::try_from(services.len()).unwrap_or(u64::MAX)
    {
        return Err(format!("{context}.service_count does not match services"));
    }
    for (index, service) in services.iter().enumerate() {
        validate_soracloud_service(service, index)?;
    }
    let audit_events = soracloud_status_field(object, "recent_audit_events", context)?
        .as_array()
        .ok_or_else(|| format!("{context}.recent_audit_events must be an array"))?;
    if soracloud_status_u64(object, "audit_event_count", context)?
        < u64::try_from(audit_events.len()).unwrap_or(u64::MAX)
    {
        return Err(format!(
            "{context}.audit_event_count is smaller than recent_audit_events"
        ));
    }
    for (index, event) in audit_events.iter().enumerate() {
        validate_soracloud_audit_event(event, &format!("{context}.recent_audit_events[{index}]"))?;
    }
    Ok(())
}
fn validate_soracloud_status(status: Option<&Value>) -> Result<(), String> {
    const ROOT_FIELDS: &[&str] = &[
        "schema_version",
        "service_health",
        "routing",
        "hosted_http_topology",
        "resource_pressure",
        "failed_admissions",
        "runtime_manager",
        "control_plane",
    ];
    let status = status.ok_or_else(|| "/v1/soracloud/status returned no JSON body".to_owned())?;
    let status = exact_soracloud_status_object(status, "/v1/soracloud/status", ROOT_FIELDS)?;
    if soracloud_status_u64(status, "schema_version", "/v1/soracloud/status")? != 1 {
        return Err("/v1/soracloud/status is not canonical schema version 1".to_owned());
    }
    let health_status = validate_soracloud_service_health(soracloud_status_field(
        status,
        "service_health",
        "/v1/soracloud/status",
    )?)?;
    match health_status {
        "healthy" | "idle" => {}
        other => {
            return Err(format!(
                "/v1/soracloud/status runtime health is `{other}`, expected healthy or idle"
            ));
        }
    }
    validate_soracloud_routing(soracloud_status_field(
        status,
        "routing",
        "/v1/soracloud/status",
    )?)?;
    validate_soracloud_topology(soracloud_status_field(
        status,
        "hosted_http_topology",
        "/v1/soracloud/status",
    )?)?;
    validate_soracloud_resource_pressure(soracloud_status_field(
        status,
        "resource_pressure",
        "/v1/soracloud/status",
    )?)?;
    validate_soracloud_failed_admissions(soracloud_status_field(
        status,
        "failed_admissions",
        "/v1/soracloud/status",
    )?)?;
    if !validate_soracloud_runtime_manager(soracloud_status_field(
        status,
        "runtime_manager",
        "/v1/soracloud/status",
    )?)? {
        return Err("/v1/soracloud/status reports no runtime manager".to_owned());
    }
    validate_soracloud_control_plane(soracloud_status_field(
        status,
        "control_plane",
        "/v1/soracloud/status",
    )?)?;
    let topology = status
        .get("hosted_http_topology")
        .and_then(Value::as_object)
        .ok_or_else(|| "/v1/soracloud/status is missing `hosted_http_topology`".to_owned())?;
    let active_adverts = topology
        .get("active_capability_adverts")
        .and_then(Value::as_u64)
        .ok_or_else(|| "/v1/soracloud/status is missing `active_capability_adverts`".to_owned())?;
    if active_adverts < 4 {
        return Err(format!(
            "/v1/soracloud/status reports {active_adverts} active Inrou host advert(s); expected at least 4"
        ));
    }
    let hosted_replicas = topology
        .get("hosted_replica_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| "/v1/soracloud/status is missing `hosted_replica_count`".to_owned())?;
    if hosted_replicas < 4 {
        return Err(format!(
            "/v1/soracloud/status reports {hosted_replicas} hosted Inrou replica placement(s); expected at least 4"
        ));
    }
    let services = status
        .get("control_plane")
        .and_then(Value::as_object)
        .and_then(|control_plane| control_plane.get("services"))
        .and_then(Value::as_array)
        .ok_or_else(|| "/v1/soracloud/status is missing control-plane services".to_owned())?;
    let has_four_replica_public_inrou_route = services.iter().any(|service| {
        let Some(revision) = service
            .as_object()
            .and_then(|service| service.get("latest_revision"))
            .and_then(Value::as_object)
        else {
            return false;
        };
        revision.get("replicas").and_then(Value::as_u64) == Some(4)
            && revision
                .get("runtime")
                .and_then(|runtime| tagged_enum_name(runtime, "runtime"))
                == Some("Inrou")
            && revision
                .get("execution_plane")
                .and_then(|plane| tagged_enum_name(plane, "execution_plane"))
                == Some("HttpService")
            && revision.get("route_host").and_then(Value::as_str).is_some()
            && revision
                .get("route_path_prefix")
                .and_then(Value::as_str)
                .is_some()
    });
    if !has_four_replica_public_inrou_route {
        return Err(
            "/v1/soracloud/status has no canonical four-replica public HttpService/Inrou route"
                .to_owned(),
        );
    }
    Ok(())
}
fn validate_modern_mcp_result<'a>(
    payload: Option<&'a Value>,
    expected_id: u64,
    method: &str,
) -> Result<&'a Map, String> {
    let payload = payload.ok_or_else(|| format!("MCP {method} body is not canonical JSON"))?;
    if payload.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || payload.get("id").and_then(Value::as_u64) != Some(expected_id)
    {
        return Err(format!(
            "MCP {method} response has a substituted JSON-RPC envelope"
        ));
    }
    if let Some(error) = payload.get("error") {
        // Preserve bounded machine diagnostics without copying the upstream
        // free-form message, arbitrary data, or the complete response body.
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .map_or_else(|| "invalid".to_owned(), |code| code.to_string());
        let error_code = error
            .pointer("/data/error_code")
            .and_then(Value::as_str)
            .filter(|code| {
                !code.is_empty()
                    && code.len() <= 64
                    && code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
            .unwrap_or("unspecified");
        return Err(format!(
            "MCP {method} response contains a JSON-RPC error: code={code}, error_code={error_code}"
        ));
    }
    let result = payload
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("MCP {method} response omits its result object"))?;
    if result.get("resultType").and_then(Value::as_str) != Some("complete") {
        return Err(format!("MCP {method} resultType must equal `complete`"));
    }
    if result.get("ttlMs").and_then(Value::as_u64) == Some(0)
        || result.get("ttlMs").and_then(Value::as_u64).is_none()
    {
        return Err(format!("MCP {method} result requires a positive ttlMs"));
    }
    if result.get("cacheScope").and_then(Value::as_str) != Some("private") {
        return Err(format!("MCP {method} cacheScope must equal `private`"));
    }
    let server_info = result
        .get("_meta")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get(mcp_wire::META_SERVER_INFO))
        .and_then(Value::as_object)
        .ok_or_else(|| format!("MCP {method} result omits serverInfo metadata"))?;
    for field in ["name", "version"] {
        if server_info
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(format!(
                "MCP {method} serverInfo requires a non-empty `{field}`"
            ));
        }
    }
    Ok(result)
}

fn validate_mcp_discovery_response(payload: Option<&Value>) -> Result<(), String> {
    let result = validate_modern_mcp_result(payload, 1, "server/discover")?;
    let supported_versions = result
        .get("supportedVersions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "MCP server/discover response omits its supportedVersions array".to_owned()
        })?;
    if supported_versions.len() != 1
        || supported_versions[0].as_str() != Some(mcp_wire::MODERN_PROTOCOL_VERSION)
    {
        return Err(format!(
            "MCP server/discover supportedVersions must contain only protocolVersion `{}`",
            mcp_wire::MODERN_PROTOCOL_VERSION
        ));
    }
    if !result
        .get("capabilities")
        .and_then(Value::as_object)
        .and_then(|capabilities| capabilities.get("tools"))
        .is_some_and(Value::is_object)
    {
        return Err("MCP server/discover response omits tools capabilities".to_owned());
    }
    Ok(())
}

fn read_mcp_tool_catalog(
    http: &HttpClient,
    url: &str,
) -> Result<(u16, Result<Vec<String>, String>)> {
    let mut names = BTreeSet::new();
    let mut cursor = 0_u64;
    let deadline = Instant::now() + Duration::from_secs(30);
    // A bounded walk consumes the actual Torii pagination contract. A missing
    // required tool on an early page is not evidence that the tool is absent.
    for _ in 0..64 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok((200, Err("MCP tools/list exceeded its deadline".to_owned())));
        }
        let params = if cursor == 0 {
            norito::json!({})
        } else {
            norito::json!({ "cursor": (cursor.to_string()) })
        };
        let response = http_mcp_json_with_timeout(http, url, 2, "tools/list", params, remaining)?;
        if response.status != 200 {
            return Ok((response.status, Ok(Vec::new())));
        }
        let page = match mcp_tool_names(response.body.as_ref()) {
            Ok(page) => page,
            Err(error) => return Ok((200, Err(error))),
        };
        for name in page {
            if !names.insert(name) {
                return Ok((
                    200,
                    Err("MCP tools/list repeats a tool across pages".to_owned()),
                ));
            }
        }
        let next = response
            .body
            .as_ref()
            .and_then(|body| body.pointer("/result/nextCursor"));
        let Some(next) = next else {
            return Ok((200, Ok(names.into_iter().collect())));
        };
        let next = next.as_str().and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|number| value == number.to_string())
        });
        let Some(next) = next.filter(|next| *next > cursor && *next == names.len() as u64) else {
            return Ok((
                200,
                Err("MCP tools/list has an invalid or nonprogressing cursor".to_owned()),
            ));
        };
        cursor = next;
    }
    Ok((
        200,
        Err("MCP tools/list exceeds the 64-page doctor bound".to_owned()),
    ))
}

fn mcp_tool_names(payload: Option<&Value>) -> Result<Vec<String>, String> {
    let result = validate_modern_mcp_result(payload, 2, "tools/list")?;
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| "MCP tools/list response omits its exact tools array".to_owned())?;
    let mut names = Vec::with_capacity(tools.len());
    let mut unique = std::collections::BTreeSet::new();
    for (index, tool) in tools.iter().enumerate() {
        let object = tool
            .as_object()
            .ok_or_else(|| format!("MCP tool {index} is not an object"))?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("MCP tool {index} omits a string name"))?;
        if !(name.starts_with("iroha.") || name.starts_with("torii."))
            || name.len() > 128
            || name.ends_with('.')
            || name.contains("..")
            || !name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_')
            })
        {
            return Err(format!(
                "MCP tool {index} has noncanonical Taira name `{name}`"
            ));
        }
        if !unique.insert(name) {
            return Err(format!("MCP tools/list duplicates `{name}`"));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}
fn resolve_canary_signer(config: &Config) -> Result<CanarySigner> {
    let key_pair = config.key_pair.clone();
    let (algorithm, _) = key_pair
        .public_key()
        .try_to_bytes()
        .wrap_err("Taira canary signer public key is malformed")?;
    if algorithm != Algorithm::Ed25519 {
        eyre::bail!("Taira canary signer must use Ed25519");
    }
    let account_id = AccountId::new(key_pair.public_key().clone());
    Ok(CanarySigner {
        account_id,
        key_pair,
    })
}
pub(super) fn canary_alias(public_key: &iroha_crypto::PublicKey) -> String {
    let digest = Sha256::digest(public_key.to_string().as_bytes());
    let suffix = hex::encode(&digest[..8]);
    format!("{CANARY_ALIAS_PREFIX}{suffix}@universal")
}

fn insert_string_metadata(metadata: &mut Metadata, key: &str, value: &str) -> Result<()> {
    metadata.insert(Name::from_str(key)?, IrohaJson::new(value.to_owned()));
    Ok(())
}

fn validate_write_canary_idempotency_key(value: &str) -> Result<String, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("must be exactly 64 lowercase hexadecimal characters".to_owned());
    }
    Ok(value.to_owned())
}

fn hint_submit_error(err: eyre::Report) -> eyre::Report {
    let text = format!("{err:#}");
    if text.contains("fee intent") || text.contains("fee_payment") {
        eyre!(
            "{text}\nTaira requires the exact signature-bound `FeePaymentIntent` returned by `/v1/fees/quote`; re-quote after any payload or sponsor-program revision change."
        )
    } else if text.contains("route_unavailable") || text.contains("ROUTE_UNRESOLVED") {
        eyre!(
            "{text}\nTaira accepted the request at ingress but no authoritative peer accepted the route; treat this as ingress or lane routing first."
        )
    } else if text.contains("Failed to find asset") {
        eyre!(
            "{text}\nThe canary signer appears unfunded for the fee asset; re-run the command so the faucet path can claim starter funds."
        )
    } else {
        err
    }
}
fn compact_json(value: &Value) -> String {
    json::to_json(value).unwrap_or_else(|_| format!("{value:?}"))
}
#[cfg(test)]
mod tests {
    include!("taira_canary_deadline_tests.rs");
    include!("taira_doctor_accounts_tests.rs");
    use super::*;
    use clap::Parser as _;
    use iroha_i18n::{Bundle, Language, Localizer};
    use std::{
        io::Read,
        net::{TcpListener, TcpStream},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
    };
    use tempfile::NamedTempFile;
    const TEST_ONBOARDING_TOKEN: &str = "0123456789abcdef0123456789ABCDEF";

    #[test]
    fn prepared_transaction_lifetime_separates_recovery_from_forward_freshness() {
        validate_prepared_transaction_time_window(1_000, 200, 1_300, "fixture")
            .expect("immutable transaction window fits inside its execution lease");
        validate_live_prepared_transaction_freshness(1_000, 200, 1_100, "fixture")
            .expect("fresh transaction remains eligible for a forward effect");

        for (creation, ttl, expiry) in [
            (1_000, 0, 1_300),
            (1_000, 301, 1_300),
            (u64::MAX, 1, u64::MAX),
        ] {
            let _error =
                validate_prepared_transaction_time_window(creation, ttl, expiry, "fixture")
                    .expect_err("invalid immutable prepared-transaction window must fail closed");
        }

        let _error = validate_live_prepared_transaction_freshness(1_000, 200, 1_200, "fixture")
            .expect_err("an expired transaction must not create a new forward effect");
        let _error = validate_live_prepared_transaction_freshness(
            1_000 + PREPARED_TRANSACTION_CLOCK_SKEW_MS + 1,
            200,
            1_000,
            "fixture",
        )
        .expect_err("a future-dated transaction must not create a new forward effect");

        validate_prepared_transaction_time_window(1_000, 200, 1_300, "fixture")
            .expect("durable recovery keeps accepting an expired but immutable valid window");
    }

    #[test]
    fn prepared_fee_payment_requires_the_independent_cli_selection() {
        let selected = FeePaymentIntent::authority(Vec::new(), None);
        validate_expected_prepared_fee_payment(&selected, &selected)
            .expect("the exact selected payer and gas bound are accepted");

        let substituted_gas = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(1));
        let _error = validate_expected_prepared_fee_payment(&selected, &substituted_gas)
            .expect_err("a substituted gas bound must fail closed");
    }

    #[test]
    fn faucet_child_requires_one_exact_independent_policy() {
        let args = fixture_write_canary_args(WriteCanaryOperation::Faucet);
        let policy = args.faucet_policy().expect("canonical faucet policy");
        assert_eq!(
            policy.asset_definition_id().to_string(),
            DEFAULT_GAS_ASSET_ID
        );
        assert_eq!(policy.amount(), &Quantity::from(25_000_u32));

        let mut missing_authority = fixture_write_canary_args(WriteCanaryOperation::Faucet);
        missing_authority.faucet_authority = None;
        let _error = missing_authority
            .faucet_policy()
            .expect_err("missing faucet authority must fail closed");

        let mut alias_asset = fixture_write_canary_args(WriteCanaryOperation::Faucet);
        alias_asset.faucet_asset_id = Some("xor#universal".to_owned());
        let _error = alias_asset
            .faucet_policy()
            .expect_err("an asset alias must not replace the exact canonical asset definition");

        let mut zero_amount = fixture_write_canary_args(WriteCanaryOperation::Faucet);
        zero_amount.faucet_amount = Some("0".to_owned());
        let _error = zero_amount
            .faucet_policy()
            .expect_err("zero faucet amount must fail closed");
    }

    #[test]
    fn final_canary_predecessor_requires_its_independent_faucet_policy() {
        let mut args = fixture_write_canary_args(WriteCanaryOperation::FinalCanary);
        args.prerequisite_envelope_fd = Some(4);
        args.validated_action().expect("complete final preparation");
        let expected = fixture_write_canary_args(WriteCanaryOperation::Faucet)
            .faucet_policy()
            .expect("independent operator policy");
        let predecessor = PreparedOperationPolicyContext::Predecessor(&args);
        assert_eq!(
            predecessor.operation().unwrap(),
            WriteCanaryOperation::Faucet
        );
        assert_eq!(predecessor.faucet_policy().unwrap(), expected);
        assert!(
            args.faucet_policy().is_err(),
            "current-child faucet guard stays strict"
        );
        assert!(
            PreparedOperationPolicyContext::Current(&args)
                .faucet_policy()
                .is_err()
        );

        for field in ["authority", "asset", "amount"] {
            let mut missing = fixture_write_canary_args(WriteCanaryOperation::FinalCanary);
            missing.prerequisite_envelope_fd = Some(4);
            match field {
                "authority" => missing.predecessor_faucet_authority = None,
                "asset" => missing.predecessor_faucet_asset_id = None,
                "amount" => missing.predecessor_faucet_amount = None,
                _ => unreachable!(),
            }
            assert!(
                missing.validated_action().is_err(),
                "missing predecessor {field}"
            );
            assert!(
                PreparedOperationPolicyContext::Predecessor(&missing)
                    .faucet_policy()
                    .is_err()
            );
        }
        for (asset, amount) in [("xor#universal", "25000"), (DEFAULT_GAS_ASSET_ID, "0")] {
            args.predecessor_faucet_asset_id = Some(asset.to_owned());
            args.predecessor_faucet_amount = Some(amount.to_owned());
            assert!(
                args.validated_action().is_err(),
                "invalid predecessor policy"
            );
        }
    }

    #[test]
    fn write_canary_policy_inputs_are_operation_and_action_scoped() {
        for operation in [
            WriteCanaryOperation::Onboarding,
            WriteCanaryOperation::Faucet,
            WriteCanaryOperation::FinalCanary,
        ] {
            for action in [
                PreparedEnvelopeAction::Prepare(3),
                PreparedEnvelopeAction::Submit(3),
                PreparedEnvelopeAction::Recover(3),
            ] {
                let mut args = fixture_write_canary_args(operation);
                args.prepare_envelope = matches!(action, PreparedEnvelopeAction::Prepare(_));
                args.prepared_output_fd = args.prepare_envelope.then_some(3);
                args.submit_prepared_envelope_fd =
                    matches!(action, PreparedEnvelopeAction::Submit(_)).then_some(3);
                args.recover_prepared_envelope_fd =
                    matches!(action, PreparedEnvelopeAction::Recover(_)).then_some(3);
                args.prerequisite_envelope_fd = (args.prepare_envelope
                    && operation != WriteCanaryOperation::Onboarding)
                    .then_some(4);
                args.onboarding_token_fd = (operation == WriteCanaryOperation::Onboarding
                    && !matches!(action, PreparedEnvelopeAction::Recover(_)))
                .then_some(5);
                let predecessor_required =
                    args.prepare_envelope && operation == WriteCanaryOperation::FinalCanary;
                if !predecessor_required {
                    args.predecessor_faucet_authority = None;
                    args.predecessor_faucet_asset_id = None;
                    args.predecessor_faucet_amount = None;
                }
                assert_eq!(
                    args.validated_action().unwrap(),
                    action,
                    "{operation:?}/{action:?}"
                );
                let predecessor = PreparedOperationPolicyContext::Predecessor(&args);
                if args.prepare_envelope && operation != WriteCanaryOperation::Onboarding {
                    assert_eq!(
                        predecessor.operation().unwrap(),
                        if operation == WriteCanaryOperation::Faucet {
                            WriteCanaryOperation::Onboarding
                        } else {
                            WriteCanaryOperation::Faucet
                        }
                    );
                } else {
                    assert!(
                        predecessor.operation().is_err(),
                        "no predecessor in this action"
                    );
                }
                if operation != WriteCanaryOperation::Faucet {
                    args.faucet_amount = Some("25000".to_owned());
                    assert!(args.validated_action().is_err(), "misplaced current policy");
                    args.faucet_amount = None;
                }
                if !predecessor_required {
                    args.predecessor_faucet_amount = Some("25000".to_owned());
                    assert!(
                        args.validated_action().is_err(),
                        "misplaced predecessor policy"
                    );
                }
            }
        }
    }

    #[derive(clap::Parser, Debug)]
    struct TestTairaCli {
        #[command(subcommand)]
        command: Command,
    }

    #[test]
    fn retired_epoch_maintenance_commands_are_rejected() {
        for retired in ["epoch-maintenance", "epoch-supervisor"] {
            let error = TestTairaCli::try_parse_from(["taira-test", retired])
                .expect_err("retired authority writers must not remain CLI commands");
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        }
    }

    #[test]
    fn write_canary_parser_accepts_only_one_exact_child_action() {
        let nonce = "n".repeat(32);
        let phase = "pre_edge";
        let key = write_canary_child_idempotency_key(&nonce, phase, "onboarding");
        let parsed = TestTairaCli::try_parse_from([
            "taira-test".to_owned(),
            "write-canary".to_owned(),
            "--operation".to_owned(),
            "onboarding".to_owned(),
            "--authorization-sha256".to_owned(),
            "ab".repeat(32),
            "--authorization-nonce".to_owned(),
            nonce,
            "--mutation-phase".to_owned(),
            phase.to_owned(),
            "--idempotency-key".to_owned(),
            key,
            "--execution-expires-at-unix-ms".to_owned(),
            u64::MAX.to_string(),
            "--prepare-envelope".to_owned(),
            "--prepared-output-fd".to_owned(),
            "3".to_owned(),
            "--onboarding-token-file".to_owned(),
            "/private/runtime/token".to_owned(),
        ])
        .expect("one-operation prepared mode must parse");
        let Command::WriteCanary(command) = parsed.command else {
            panic!("expected write-canary command");
        };
        assert_eq!(command.operation, WriteCanaryOperation::Onboarding);
        assert_eq!(
            command.prepared_action().expect("prepared action"),
            PreparedEnvelopeAction::Prepare(3)
        );

        for retired in [
            "--recover-only",
            "--write-config",
            "--alias-prefix",
            "--use-config-signer",
        ] {
            let error = TestTairaCli::try_parse_from(["taira-test", "write-canary", retired])
                .expect_err("retired one-shot flags must fail closed");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
        let error = TestTairaCli::try_parse_from(["taira-test", "write-canary"])
            .expect_err("aggregate operation and implicit action must not parse");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn inrou_canary_parser_accepts_only_one_exact_child_action() {
        let nonce = "n".repeat(32);
        let phase = "pre_edge";
        let key = write_canary_child_idempotency_key(&nonce, phase, "inrou_bundle_pin");
        let parsed = TestTairaCli::try_parse_from([
            "taira-test".to_owned(),
            "inrou-canary".to_owned(),
            "--stage-dir".to_owned(),
            "/private/runtime/inrou-stage".to_owned(),
            "--mode".to_owned(),
            "deploy".to_owned(),
            "--operation".to_owned(),
            "bundle-pin".to_owned(),
            "--authorization-sha256".to_owned(),
            "ab".repeat(32),
            "--authorization-nonce".to_owned(),
            nonce.clone(),
            "--mutation-phase".to_owned(),
            phase.to_owned(),
            "--idempotency-key".to_owned(),
            key,
            "--execution-expires-at-unix-ms".to_owned(),
            u64::MAX.to_string(),
            "--prepare-envelope".to_owned(),
            "--prepared-output-fd".to_owned(),
            "3".to_owned(),
            "--prerequisite-envelope-fd".to_owned(),
            "4".to_owned(),
        ])
        .expect("one-operation Inrou prepare mode must parse");
        let Command::InrouCanary(command) = parsed.command else {
            panic!("expected inrou-canary command");
        };
        assert_eq!(command.operation, InrouCanaryOperation::BundlePin);
        assert_eq!(
            command.prepared_action().expect("prepared action"),
            PreparedEnvelopeAction::Prepare(3)
        );
        command.binding().expect("exact child key must bind");

        let error = TestTairaCli::try_parse_from(["taira-test", "inrou-canary", "--recover-only"])
            .expect_err("retired aggregate recovery flag must fail closed");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn inrou_canary_binding_and_prerequisite_are_child_exact() {
        let nonce = "n".repeat(32);
        let mut args = InrouCanary {
            probe_scope: InrouProbeScope::Public,
            public_root: DEFAULT_PUBLIC_ROOT.to_owned(),
            stage_dir: PathBuf::from("/private/runtime/inrou-stage"),
            mode: InrouCanaryMode::Deploy,
            operation: InrouCanaryOperation::GuestPin,
            authorization_sha256: "ab".repeat(32),
            authorization_nonce: nonce.clone(),
            mutation_phase: "pre_edge".to_owned(),
            idempotency_key: write_canary_child_idempotency_key(
                &nonce,
                "pre_edge",
                "inrou_guest_pin",
            ),
            execution_expires_at_unix_ms: u64::MAX,
            prepare_envelope: true,
            prepared_output_fd: Some(3),
            submit_prepared_envelope_fd: None,
            recover_prepared_envelope_fd: None,
            prerequisite_envelope_fd: Some(4),
            timeout_secs: 1,
            json: true,
        };
        assert!(args.binding().is_ok());
        assert!(
            args.validate_prerequisite_action(PreparedEnvelopeAction::Prepare(3))
                .is_ok()
        );
        args.idempotency_key =
            write_canary_child_idempotency_key(&nonce, "pre_edge", "inrou_bundle_pin");
        assert!(args.binding().is_err());
        args.prerequisite_envelope_fd = None;
        assert!(
            args.validate_prerequisite_action(PreparedEnvelopeAction::Prepare(3))
                .is_err()
        );
        args.prerequisite_envelope_fd = Some(4);
        assert!(
            args.validate_prerequisite_action(PreparedEnvelopeAction::Recover(3))
                .is_err()
        );
    }

    #[test]
    fn write_canary_prerequisite_policy_is_exact() {
        let mut args = fixture_write_canary_args(WriteCanaryOperation::Onboarding);
        assert!(
            args.validate_prerequisite_action(PreparedEnvelopeAction::Prepare(3))
                .is_ok()
        );
        args.prerequisite_envelope_fd = Some(4);
        assert!(
            args.validate_prerequisite_action(PreparedEnvelopeAction::Prepare(3))
                .is_err()
        );
        args.operation = WriteCanaryOperation::Faucet;
        args.idempotency_key = write_canary_child_idempotency_key(
            &args.authorization_nonce,
            &args.mutation_phase,
            args.operation.mutation_kind(),
        );
        assert!(
            args.validate_prerequisite_action(PreparedEnvelopeAction::Prepare(3))
                .is_ok()
        );
        args.prerequisite_envelope_fd = None;
        assert!(
            args.validate_prerequisite_action(PreparedEnvelopeAction::Prepare(3))
                .is_err()
        );
        args.prerequisite_envelope_fd = Some(4);
        assert!(
            args.validate_prerequisite_action(PreparedEnvelopeAction::Recover(3))
                .is_err()
        );
    }

    #[test]
    fn authenticated_no_op_preparation_reports_proof_required() {
        let semantic_evidence = "ab".repeat(32);
        let (outcome, evidence) =
            initial_prepared_report_state_from_evidence(Some(&semantic_evidence));
        assert_eq!(outcome, "ProofRequired");
        assert_eq!(evidence.as_deref(), Some(semantic_evidence.as_str()));
        assert_eq!(
            initial_prepared_report_state_from_evidence(None),
            ("Prepared", None)
        );
    }

    #[test]
    fn proof_required_applied_state_maps_without_transaction_height() {
        let semantic_evidence = "ab".repeat(32);
        let classification = classify_proof_required_current_state(
            &semantic_evidence,
            AccountOnboardingCurrentStateV1::Applied {
                block_height: NonZeroU64::new(41).expect("nonzero fixture height"),
                block_hash: iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                    b"proof-required current-state fixture anchor",
                )),
            },
        );
        let PreparedRecoveryClassification::Applied {
            block_height,
            evidence,
        } = classification
        else {
            panic!("applied proof-required current state must classify as applied");
        };
        assert_eq!(block_height, None);
        assert_eq!(evidence, semantic_evidence);
    }

    #[test]
    fn proof_required_mismatch_states_remain_nonterminal() {
        let block_height = NonZeroU64::new(41).expect("nonzero fixture height");
        let block_hash = iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
            b"proof-required mismatch fixture anchor",
        ));
        for (state, expected_kind) in [
            (
                AccountOnboardingCurrentStateV1::AliasAbsent {
                    block_height,
                    block_hash,
                },
                "OnboardingStateAbsent",
            ),
            (
                AccountOnboardingCurrentStateV1::AliasConflict {
                    block_height,
                    block_hash,
                },
                "OnboardingAliasConflict",
            ),
        ] {
            assert_eq!(
                classify_proof_required_current_state(&"ab".repeat(32), state),
                PreparedRecoveryClassification::Pending {
                    reason: PreparedWritePendingReason::parse(expected_kind).unwrap()
                }
            );
        }
    }

    #[test]
    fn prepared_recovery_accepts_only_global_state_finality() {
        let response = |kind: &str, scope: &str, resolved_from: &str| {
            PipelineTransactionStatusResponse::new(
                format!("{}b", "a".repeat(63)),
                iroha_torii_shared::PipelineTransactionStatus {
                    kind: kind.to_owned(),
                    block_height: Some(7),
                },
                scope.to_owned(),
                resolved_from.to_owned(),
            )
        };
        assert!(prepared_recovery_status_is_final_applied(&response(
            "Applied", "global", "state"
        )));
        for (scope, resolved_from) in [("global", "cache"), ("global", "queue"), ("local", "state")]
        {
            assert!(!prepared_recovery_status_is_final_applied(&response(
                "Applied",
                scope,
                resolved_from
            )));
        }
        for kind in ["Rejected", "Expired"] {
            assert!(prepared_recovery_status_is_final_failure(&response(
                kind, "global", "state"
            )));
            for (scope, resolved_from) in
                [("global", "cache"), ("global", "queue"), ("local", "state")]
            {
                assert!(!prepared_recovery_status_is_final_failure(&response(
                    kind,
                    scope,
                    resolved_from
                )));
            }
        }
    }

    fn queued_onboarding_fixture() -> ValidatedPreparedOperation {
        let _chain = ChainDiscriminantGuard::enter(0x02f1);
        let fixture: Value = json::from_str(include_str!(
            "../../../fixtures/prepared_transactions/prepared_transaction_signature_v1.json"
        ))
        .unwrap();
        let vector = fixture
            .pointer("/vectors")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|value| {
                value.pointer("/name").and_then(Value::as_str) == Some("onboarding_prepared")
            })
            .unwrap();
        let prepared: AccountOnboardingPreparedTransactionV1 =
            json::from_value(vector.pointer("/response").unwrap().clone()).unwrap();
        let transaction = iroha::client::verify_account_onboarding_prepared_transaction_v1(
            json::from_value(vector.pointer("/network_id").unwrap().clone()).unwrap(),
            &prepared.receipt.body.request,
            &prepared,
            &prepared.receipt,
            &prepared.binding,
            &prepared.fee_payment,
        )
        .expect("actual signed onboarding fixture must satisfy SDK closure");
        let wire = hex::decode(&prepared.signed_transaction_wire_hex).unwrap();
        let mut envelope = final_canary_envelope_fixture();
        envelope.operation = PreparedTransactionOperationV1::OnboardingPrepared(prepared);
        let envelope_bytes = json::to_vec(&envelope).unwrap();
        ValidatedPreparedOperation {
            envelope,
            transaction: Some(transaction),
            wire: Some(wire),
            envelope_bytes,
        }
    }

    fn prepared_status_response(
        transaction: &SignedTransaction,
        kind: &str,
        source: &str,
    ) -> MockResponse {
        MockResponse::json(
            200,
            json::to_value(&PipelineTransactionStatusResponse::new(
                hex::encode(transaction.hash().as_ref()),
                iroha_torii_shared::PipelineTransactionStatus {
                    kind: kind.to_owned(),
                    block_height: (kind == "Applied").then_some(2),
                },
                "global".to_owned(),
                source.to_owned(),
            ))
            .unwrap(),
        )
    }

    #[derive(Clone, Copy, Debug)]
    enum PreparedStatusPoll {
        Status(&'static str, &'static str),
        Failure(std::io::ErrorKind),
    }

    #[derive(Debug, thiserror::Error)]
    #[error("scripted prepared status transport failure")]
    struct PreparedStatusTransportError(#[source] std::io::Error);

    #[derive(Debug)]
    struct PreparedStatusTransport {
        transaction: SignedTransaction,
        polls: Vec<PreparedStatusPoll>,
        timeouts: Mutex<Vec<Option<Duration>>>,
    }

    impl iroha::http::HttpTransport for PreparedStatusTransport {
        fn send_blocking(
            &self,
            request: iroha::http::TransportRequest,
        ) -> Result<iroha::http::Response<Vec<u8>>> {
            assert_eq!(request.method, iroha::http::Method::GET);
            assert_eq!(request.url.path(), "/v1/pipeline/transactions/status");
            assert_eq!(
                request.url.query_pairs().into_owned().collect::<Vec<_>>(),
                vec![
                    ("hash".to_owned(), self.transaction.hash().to_string()),
                    ("scope".to_owned(), "global".to_owned()),
                ]
            );
            assert!(request.body.is_empty());
            let mut timeouts = self.timeouts.lock().expect("prepared status timeouts");
            let poll = self.polls[timeouts.len().min(self.polls.len() - 1)];
            timeouts.push(request.timeout);
            drop(timeouts);
            match poll {
                PreparedStatusPoll::Status(kind, source) => {
                    let response = prepared_status_response(&self.transaction, kind, source);
                    Ok(iroha::http::Response::builder()
                        .status(response.status)
                        .header("Content-Type", response.content_type)
                        .body(response.body)
                        .expect("prepared status response"))
                }
                PreparedStatusPoll::Failure(kind) => Err(PreparedStatusTransportError(
                    std::io::Error::new(kind, "scripted prepared status failure"),
                ))
                .wrap_err("prepared status transport failed"),
            }
        }

        fn send(&self, request: iroha::http::TransportRequest) -> iroha::http::TransportFuture<'_> {
            Box::pin(async move { self.send_blocking(request) })
        }
    }

    fn prepared_status_transport_client(
        validated: &ValidatedPreparedOperation,
        request_timeout: Duration,
        polls: &[PreparedStatusPoll],
    ) -> (IrohaClient, Arc<PreparedStatusTransport>) {
        assert!(!polls.is_empty());
        let transport = Arc::new(PreparedStatusTransport {
            transaction: validated.transaction().unwrap().clone(),
            polls: polls.to_vec(),
            timeouts: Mutex::new(Vec::new()),
        });
        let mut config = crate::fallback_config();
        config.torii_api_url = Url::parse("http://127.0.0.1:1").unwrap();
        config.torii_request_timeout = request_timeout;
        let client = IrohaClient::builder(config)
            .http_transport(transport.clone())
            .build()
            .expect("valid Taira fixture context");
        (client, transport)
    }

    #[test]
    fn prepared_server_confirmation_polls_queued_then_verifies_exact_applied_wire() {
        use iroha::data_model::{
            query::CommittedTransaction,
            transaction::{DataTriggerSequence, TransactionResult},
        };
        let validated = queued_onboarding_fixture();
        let transaction = validated.transaction().unwrap().clone();
        let result = TransactionResult::new(Ok(DataTriggerSequence::default()));
        let output = iroha::data_model::block::execution_output::ExecutionOutputV1::Network(
            iroha::data_model::block::execution_output::NetworkExecutionOutputV1 {
                input_index: 0,
                result,
                completions: Vec::new(),
            },
        );
        let committed = CommittedTransaction {
            block_hash: iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"confirmed block")),
            entrypoint_hash: transaction.hash_as_entrypoint(),
            entrypoint_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
            entrypoint: TransactionEntrypoint::External(transaction.clone()),
            output_hash: iroha_crypto::HashOf::new(&output),
            output_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
            output,
        };
        let details = iroha_torii_shared::PipelineTransactionDetailsResponse {
            hash: transaction.hash_as_entrypoint().to_string(),
            transaction: committed,
        };
        let query_bytes = norito::to_bytes(&details).unwrap();
        let polls = AtomicUsize::new(0);
        let server = spawn_mock_http(6, move |request| match path_only(&request.path) {
            "/v1/pipeline/transactions/status" => {
                assert!(request.path.contains("scope=global"));
                if polls.fetch_add(1, Ordering::SeqCst) == 0 {
                    prepared_status_response(&transaction, "Queued", "queue")
                } else {
                    prepared_status_response(&transaction, "Applied", "state")
                }
            }
            "/v1/node/capabilities" => MockResponse::json(
                200,
                norito::json!({
                    "data_model_version": (iroha::data_model::DATA_MODEL_VERSION)
                }),
            ),
            "/v1/pipeline/transactions/details" => {
                assert_eq!(request.header_values("accept"), ["application/x-norito"]);
                assert_eq!(
                    request.header_values("content-type"),
                    ["application/x-norito"]
                );
                MockResponse {
                    status: 200,
                    content_type: "application/x-norito",
                    headers: Vec::new(),
                    body: query_bytes.clone(),
                }
            }
            other => panic!("confirmation must never submit: {other}"),
        });
        let mut config = crate::fallback_config();
        config.torii_api_url = Url::parse(&server.base_url).unwrap();
        let client = IrohaClient::builder(config)
            .build()
            .expect("valid Taira fixture context");
        let outcome = await_exact_prepared_operation(
            &client,
            &validated,
            PreparedRecoveryClassification::Absent,
            Instant::now() + Duration::from_secs(5),
            Duration::from_millis(1),
        )
        .expect("queued submission must wait for its exact committed transaction");
        assert_eq!(
            outcome,
            PreparedRecoveryClassification::Applied {
                block_height: Some(2),
                evidence: validated
                    .transaction()
                    .unwrap()
                    .hash_as_entrypoint()
                    .to_string(),
            }
        );
        verify_exact_committed_transaction(
            &client,
            validated.transaction().unwrap(),
            validated.wire().unwrap(),
        )
        .expect("Inrou predecessor verification uses the same exact details route");
        let mut substituted_wire = validated.wire().unwrap().to_vec();
        substituted_wire[0] ^= 1;
        let _ = verify_exact_committed_transaction(
            &client,
            validated.transaction().unwrap(),
            &substituted_wire,
        )
        .expect_err("an exact details response must not authorize substituted retained bytes");
        let requests = finish_mock(server);
        assert_eq!(requests.len(), 6);
        assert_eq!(
            requests
                .iter()
                .filter(|request| path_only(&request.path) == "/v1/node/capabilities")
                .count(),
            1,
            "deadline-bounded clones must reuse the client's capability cache"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST")
                .count(),
            3
        );
        assert_eq!(
            path_only(&requests.last().unwrap().path),
            "/v1/pipeline/transactions/details"
        );
    }

    #[test]
    fn prepared_predecessor_wait_retries_delayed_exact_proof_with_one_deadline() {
        let validated = queued_onboarding_fixture();
        let transaction = validated.transaction().unwrap().clone();
        let result = iroha::data_model::transaction::TransactionResult::new(Ok(
            iroha::data_model::transaction::DataTriggerSequence::default(),
        ));
        let output = iroha::data_model::block::execution_output::ExecutionOutputV1::Network(
            iroha::data_model::block::execution_output::NetworkExecutionOutputV1 {
                input_index: 0,
                result,
                completions: Vec::new(),
            },
        );
        let details = iroha_torii_shared::PipelineTransactionDetailsResponse {
            hash: transaction.hash_as_entrypoint().to_string(),
            transaction: iroha::data_model::query::CommittedTransaction {
                block_hash: iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                    b"exact proof block",
                )),
                entrypoint_hash: transaction.hash_as_entrypoint(),
                entrypoint_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
                entrypoint: TransactionEntrypoint::External(transaction.clone()),
                output_hash: iroha_crypto::HashOf::new(&output),
                output_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
                output,
            },
        };
        let proof_reads = AtomicUsize::new(0);
        let server = spawn_mock_http(6, move |request| match path_only(&request.path) {
            "/v1/pipeline/transactions/status" => {
                prepared_status_response(&transaction, "Applied", "state")
            }
            "/v1/node/capabilities" => MockResponse::json(
                200,
                norito::json!({
                    "data_model_version": (iroha::data_model::DATA_MODEL_VERSION)
                }),
            ),
            "/v1/pipeline/transactions/details" => {
                if proof_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                    MockResponse {
                        status: 404,
                        content_type: "application/x-norito",
                        headers: Vec::new(),
                        body: norito::to_bytes(&iroha_torii_shared::ErrorEnvelope::new(
                            "transaction_details_not_found",
                            "The exact committed transaction proof is not available.",
                        ))
                        .unwrap(),
                    }
                } else {
                    MockResponse {
                        status: 200,
                        content_type: "application/x-norito",
                        headers: Vec::new(),
                        body: norito::to_bytes(&details).unwrap(),
                    }
                }
            }
            other => panic!("successor confirmation must read only exact proof: {other}"),
        });
        let mut config = crate::fallback_config();
        config.torii_api_url = Url::parse(&server.base_url).unwrap();
        let mut budgets = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        await_predecessor_applied(deadline, Duration::from_millis(1), |budget| {
            budgets.push(budget);
            let mut config = config.clone();
            config.torii_request_timeout = budget;
            let client = IrohaClient::builder(config).build()?;
            Ok(matches!(
                classify_exact_prepared_operation(&client, &validated)?,
                PreparedRecoveryClassification::Applied { .. }
            ))
        })
        .expect("local proof may become visible after globally Applied status");
        assert_eq!(budgets.len(), 2);
        assert!(budgets[1] < budgets[0]);
        assert!(budgets[0] <= Duration::from_secs(5));
        assert_eq!(finish_mock(server).len(), 6);

        let mut observations = 0;
        let _ = await_predecessor_applied(Instant::now(), Duration::from_millis(1), |_| {
            observations += 1;
            Ok(true)
        })
        .expect_err("an expired deadline cannot trigger another network observation");
        assert_eq!(observations, 0);
        let error = await_predecessor_applied(deadline, Duration::from_millis(1), |_| {
            observations += 1;
            Err(eyre!("authenticated exact proof denied"))
        })
        .expect_err("semantic failures must terminate immediately");
        assert_eq!(observations, 1);
        assert!(
            error
                .to_string()
                .contains("authenticated exact proof denied")
        );
    }

    #[test]
    fn prepared_inrou_observation_preserves_auth_and_proof_errors() {
        let denied = eyre::Report::new(iroha::query::QueryError::Validation(
            iroha::data_model::ValidationFail::NotPermitted("private exact transaction".to_owned()),
        ));
        assert!(!observation_transport_unavailable(&denied));
        assert!(!exact_transaction_details_not_found(&denied));
        assert!(!observation_transport_unavailable(&eyre!(
            "malformed committed proof"
        )));
        let truncated_decode = eyre::Report::new(iroha::query::QueryError::Other(
            eyre::Report::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated canonical frame",
            )),
        ));
        assert!(!observation_transport_unavailable(&truncated_decode));
        let absent = eyre::Report::new(iroha::query::QueryError::Validation(
            iroha::data_model::ValidationFail::QueryFailed(
                iroha::data_model::query::error::QueryExecutionFail::NotFound,
            ),
        ));
        assert!(exact_transaction_details_not_found(&absent));
        assert!(!observation_transport_unavailable(&absent));
        let timeout = eyre::Report::new(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "read deadline",
        ));
        assert!(observation_transport_unavailable(&timeout));
        assert!(!exact_transaction_details_not_found(&timeout));
        assert!(prepared_observation_deadline(120, Some(1)).unwrap() <= Instant::now());
    }

    #[test]
    fn prepared_applied_confirmation_waits_for_exact_details_visibility() {
        let validated = queued_onboarding_fixture();
        let transaction = validated.transaction().unwrap().clone();
        let server = spawn_mock_http(3, move |request| match path_only(&request.path) {
            "/v1/pipeline/transactions/status" => {
                prepared_status_response(&transaction, "Applied", "state")
            }
            "/v1/node/capabilities" => MockResponse::json(
                200,
                norito::json!({
                    "data_model_version": (iroha::data_model::DATA_MODEL_VERSION)
                }),
            ),
            "/v1/pipeline/transactions/details" => MockResponse {
                status: 404,
                content_type: "application/x-norito",
                headers: Vec::new(),
                body: norito::to_bytes(&iroha_torii_shared::ErrorEnvelope::new(
                    "transaction_details_not_found",
                    "The exact committed transaction proof is not available.",
                ))
                .unwrap(),
            },
            other => panic!("confirmation must never submit or read global inventory: {other}"),
        });
        let mut config = crate::fallback_config();
        config.torii_api_url = Url::parse(&server.base_url).unwrap();
        let outcome = classify_exact_prepared_operation(
            &IrohaClient::builder(config).build().unwrap(),
            &validated,
        )
        .expect("an advanced peer's global Applied status does not imply local proof visibility");
        assert_eq!(
            outcome,
            PreparedRecoveryClassification::Pending {
                reason: PreparedWritePendingReason::AppliedEvidencePending
            }
        );
        assert_eq!(finish_mock(server).len(), 3);
    }

    #[test]
    fn prepared_applied_confirmation_rejects_unauthorized_or_malformed_exact_details() {
        let denied = norito::to_bytes(&iroha_torii_shared::ErrorEnvelope::new(
            "query_validation_failed",
            "exact transaction is private",
        ))
        .unwrap();
        for (status, body) in [
            (403, denied.clone()),
            (404, denied.clone()),
            (404, b"untyped missing proof".to_vec()),
            (200, denied[..denied.len() - 1].to_vec()),
            (200, b"invalid canonical Norito proof".to_vec()),
        ] {
            let validated = queued_onboarding_fixture();
            let transaction = validated.transaction().unwrap().clone();
            let server = spawn_mock_http(3, move |request| match path_only(&request.path) {
                "/v1/pipeline/transactions/status" => {
                    prepared_status_response(&transaction, "Applied", "state")
                }
                "/v1/node/capabilities" => MockResponse::json(
                    200,
                    norito::json!({
                        "data_model_version": (iroha::data_model::DATA_MODEL_VERSION)
                    }),
                ),
                "/v1/pipeline/transactions/details" => MockResponse {
                    status,
                    content_type: "application/x-norito",
                    headers: Vec::new(),
                    body: body.clone(),
                },
                other => panic!("confirmation must use the exact read route: {other}"),
            });
            let mut config = crate::fallback_config();
            config.torii_api_url = Url::parse(&server.base_url).unwrap();
            let error = classify_exact_prepared_operation(
                &IrohaClient::builder(config).build().unwrap(),
                &validated,
            )
            .expect_err("authorization and malformed proof failures must not become Pending");
            assert!(!observation_transport_unavailable(&error));
            assert!(!exact_transaction_details_not_found(&error));
            assert_eq!(finish_mock(server).len(), 3);
        }
    }

    #[test]
    fn prepared_server_confirmation_preserves_fixed_failure_and_deadline() {
        for kind in ["Rejected", "Expired"] {
            let validated = queued_onboarding_fixture();
            let transaction = validated.transaction().unwrap().clone();
            let server = spawn_mock_http(1, move |_| {
                prepared_status_response(&transaction, kind, "state")
            });
            let mut config = crate::fallback_config();
            config.torii_api_url = Url::parse(&server.base_url).unwrap();
            let client = IrohaClient::builder(config)
                .build()
                .expect("valid Taira fixture context");
            let outcome = await_exact_prepared_operation(
                &client,
                &validated,
                PreparedRecoveryClassification::Absent,
                Instant::now() + Duration::from_secs(5),
                Duration::from_millis(1),
            )
            .unwrap();
            assert_eq!(
                outcome,
                PreparedRecoveryClassification::Rejected {
                    terminal_kind: kind.to_owned(),
                }
            );
            assert_eq!(finish_mock(server).len(), 1);
            let pending = PreparedRecoveryClassification::Pending {
                reason: PreparedWritePendingReason::Queued,
            };
            assert_eq!(
                await_exact_prepared_operation(
                    &client,
                    &validated,
                    pending,
                    Instant::now(),
                    Duration::from_secs(1),
                )
                .unwrap(),
                PreparedRecoveryClassification::Pending {
                    reason: PreparedWritePendingReason::Queued
                },
                "an elapsed deadline must retain the last observation without another request"
            );
        }
        let validated = queued_onboarding_fixture();
        let configured_timeout = Duration::from_secs(5);
        let wait_budget = Duration::from_millis(200);
        let (client, transport) = prepared_status_transport_client(
            &validated,
            configured_timeout,
            &[
                PreparedStatusPoll::Status("Expired", "cache"),
                PreparedStatusPoll::Failure(std::io::ErrorKind::TimedOut),
            ],
        );
        let first = classify_exact_prepared_operation(&client, &validated).unwrap();
        let started = Instant::now();
        let outcome = await_exact_prepared_operation(
            &client,
            &validated,
            first,
            started + wait_budget,
            Duration::from_millis(10),
        )
        .unwrap();
        assert_eq!(
            outcome,
            PreparedRecoveryClassification::Pending {
                reason: PreparedWritePendingReason::Expired
            },
            "cache expiry cannot become a definitive failure at the wait deadline"
        );
        assert!(started.elapsed() >= wait_budget);
        assert!(started.elapsed() < Duration::from_secs(2));
        let timeouts = transport.timeouts.lock().unwrap();
        assert_eq!(timeouts[0], Some(configured_timeout));
        assert!(timeouts.iter().skip(1).all(|timeout| {
            timeout.is_some_and(|timeout| !timeout.is_zero() && timeout <= wait_budget)
        }));
    }

    #[test]
    fn prepared_server_confirmation_retries_deadline_timeout_until_fixed_failure() {
        let validated = queued_onboarding_fixture();
        let wait_budget = Duration::from_secs(5);
        for configured_timeout in [Duration::ZERO, Duration::from_secs(30)] {
            let (client, transport) = prepared_status_transport_client(
                &validated,
                configured_timeout,
                &[
                    PreparedStatusPoll::Failure(std::io::ErrorKind::TimedOut),
                    PreparedStatusPoll::Status("Rejected", "state"),
                ],
            );
            let outcome = await_exact_prepared_operation(
                &client,
                &validated,
                PreparedRecoveryClassification::Pending {
                    reason: PreparedWritePendingReason::Queued,
                },
                Instant::now() + wait_budget,
                Duration::from_millis(1),
            )
            .expect("a deadline-bounded timeout must allow a later definitive observation");
            assert_eq!(
                outcome,
                PreparedRecoveryClassification::Rejected {
                    terminal_kind: "Rejected".to_owned(),
                }
            );
            let timeouts = transport.timeouts.lock().unwrap();
            assert_eq!(timeouts.len(), 2);
            assert!(timeouts.iter().all(|timeout| {
                timeout.is_some_and(|timeout| !timeout.is_zero() && timeout <= wait_budget)
            }));
        }
    }

    #[test]
    fn prepared_server_confirmation_preserves_configured_timeout_errors() {
        let validated = queued_onboarding_fixture();
        let configured_timeout = Duration::from_millis(1);
        let (client, transport) = prepared_status_transport_client(
            &validated,
            configured_timeout,
            &[PreparedStatusPoll::Failure(std::io::ErrorKind::TimedOut)],
        );
        let error = await_exact_prepared_operation(
            &client,
            &validated,
            PreparedRecoveryClassification::Pending {
                reason: PreparedWritePendingReason::Queued,
            },
            Instant::now() + Duration::from_secs(5),
            Duration::from_millis(1),
        )
        .expect_err("a shorter configured timeout must remain a transport failure");
        assert_eq!(
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                .unwrap()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            *transport.timeouts.lock().unwrap(),
            vec![Some(configured_timeout)]
        );
    }

    #[test]
    fn prepared_server_confirmation_preserves_other_transport_errors() {
        let validated = queued_onboarding_fixture();
        let wait_budget = Duration::from_secs(5);
        let (client, transport) = prepared_status_transport_client(
            &validated,
            Duration::from_secs(30),
            &[PreparedStatusPoll::Failure(
                std::io::ErrorKind::ConnectionReset,
            )],
        );
        let error = await_exact_prepared_operation(
            &client,
            &validated,
            PreparedRecoveryClassification::Pending {
                reason: PreparedWritePendingReason::Queued,
            },
            Instant::now() + wait_budget,
            Duration::from_millis(1),
        )
        .expect_err("a non-timeout transport failure must not become a pending observation");
        assert_eq!(
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                .unwrap()
                .kind(),
            std::io::ErrorKind::ConnectionReset
        );
        let timeouts = transport.timeouts.lock().unwrap();
        assert_eq!(timeouts.len(), 1);
        assert!(
            timeouts[0].is_some_and(|timeout| { !timeout.is_zero() && timeout <= wait_budget })
        );
    }

    #[test]
    fn prepared_server_confirmation_rejects_malformed_status_without_resubmission() {
        let validated = queued_onboarding_fixture();
        let server = spawn_mock_http(1, |_| {
            MockResponse::json(
                200,
                norito::json!({
                    "hash": "substituted", "scope": "global", "resolved_from": "state",
                    "status": {"kind": "Applied", "block_height": 2}
                }),
            )
        });
        let mut config = crate::fallback_config();
        config.torii_api_url = Url::parse(&server.base_url).unwrap();
        assert!(
            await_exact_prepared_operation(
                &IrohaClient::builder(config)
                    .build()
                    .expect("valid Taira fixture context"),
                &validated,
                PreparedRecoveryClassification::Absent,
                Instant::now() + Duration::from_secs(5),
                Duration::from_millis(1),
            )
            .is_err()
        );
        assert_eq!(finish_mock(server).len(), 1);
        let server = spawn_mock_http(1, |_| MockResponse::text(503, "unavailable"));
        let mut config = crate::fallback_config();
        config.torii_api_url = Url::parse(&server.base_url).unwrap();
        assert!(
            await_exact_prepared_operation(
                &IrohaClient::builder(config)
                    .build()
                    .expect("valid Taira fixture context"),
                &validated,
                PreparedRecoveryClassification::Pending {
                    reason: PreparedWritePendingReason::Queued
                },
                Instant::now() + Duration::from_secs(5),
                Duration::from_millis(1),
            )
            .is_err()
        );
        let requests = finish_mock(server);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
    }

    #[test]
    fn prepared_envelope_rejects_legacy_zero_or_multi_operation_shapes() {
        for operations in [norito::json!([]), norito::json!([{}, {}])] {
            let retired = norito::json!({
                "schema": PREPARED_ENVELOPE_SCHEMA_V1,
                "binding": {
                    "schema": PREPARED_BINDING_SCHEMA_V1,
                    "authorization_sha256": ("ab".repeat(32)),
                    "authorization_nonce": ("n".repeat(32)),
                    "kind": "onboarding",
                    "phase": "pre_edge",
                    "idempotency_key": ("cd".repeat(32)),
                    "execution_expires_at_unix_ms": (u64::MAX)
                },
                "public_root": DEFAULT_PUBLIC_ROOT,
                "chain_id": DEFAULT_CHAIN_ID,
                "network_id": "retired",
                "authority": "retired",
                "operations": operations
            });
            let bytes = json::to_vec(&retired).expect("encode retired aggregate shape");
            let error = json::from_slice::<PreparedMutationEnvelopeV1>(&bytes)
                .expect_err("zero/multi operation envelopes must fail closed");
            assert!(!error.to_string().is_empty());
        }
    }

    pub(super) fn core_report_cases(
        classification: PreparedRecoveryClassification,
    ) -> Result<Vec<(String, Vec<u8>, Value)>> {
        let _chain = ChainDiscriminantGuard::enter(0x02f1);
        let fixture: Value = json::from_str(include_str!(
            "../../../fixtures/prepared_transactions/prepared_transaction_signature_v1.json"
        ))?;
        let vectors = fixture.get("vectors").and_then(Value::as_array).unwrap();
        let response = |name: &str| {
            vectors
                .iter()
                .find(|vector| vector.get("name").and_then(Value::as_str) == Some(name))
                .unwrap()
                .get("response")
                .unwrap()
                .clone()
        };
        let onboarding: AccountOnboardingPreparedTransactionV1 =
            json::from_value(response("onboarding_prepared"))?;
        let proof = PreparedOnboardingProofRequiredV1 {
            schema: PREPARED_ONBOARDING_PROOF_REQUIRED_SCHEMA_V1.to_owned(),
            receipt: onboarding.receipt.clone(),
            result: json::from_value(response("onboarding_proof_required"))?,
        };
        let faucet = json::from_value(response("faucet_prepared"))?;
        let mut cases = Vec::new();
        for (operation, prepared) in [
            (
                WriteCanaryOperation::Onboarding,
                PreparedTransactionOperationV1::OnboardingPrepared(onboarding),
            ),
            (
                WriteCanaryOperation::Onboarding,
                PreparedTransactionOperationV1::OnboardingProofRequired(proof),
            ),
            (
                WriteCanaryOperation::Faucet,
                PreparedTransactionOperationV1::FaucetPrepared(faucet),
            ),
            (
                WriteCanaryOperation::FinalCanary,
                final_canary_envelope_fixture().operation,
            ),
        ] {
            let args = fixture_write_canary_args(operation);
            let mut envelope = final_canary_envelope_fixture();
            envelope.binding = args.binding()?;
            envelope.operation = prepared;
            if let PreparedTransactionOperationV1::FinalCanary(operation) = &mut envelope.operation
            {
                operation.binding = envelope.binding.clone();
            }
            let envelope_bytes = canonical_prepared_envelope_bytes(&envelope)?;
            let validated = ValidatedPreparedOperation {
                envelope,
                transaction: None,
                wire: None,
                envelope_bytes: envelope_bytes.clone(),
            };
            let report = report_prepared_classification(
                &args.public_root,
                &args,
                &validated,
                classification.clone(),
            )?;
            cases.push((operation.mutation_kind().to_owned(), envelope_bytes, report));
        }
        Ok(cases)
    }

    #[test]
    fn core_pending_reason_codec_is_closed_and_round_trips_every_variant() {
        let mut labels = std::collections::BTreeSet::new();
        for reason in PreparedWritePendingReason::ALL.iter().copied() {
            assert_eq!(
                PreparedWritePendingReason::parse(reason.as_str()).unwrap(),
                reason
            );
            assert!(labels.insert(reason.as_str()));
        }
        assert_eq!(labels.len(), 12);
        for unknown in [
            "",
            "queued",
            "Queued ",
            "ObservationDeadlineReached",
            "SubmissionOutcomeUnknown",
            "Unknown",
            "Rejected\n",
        ] {
            assert!(PreparedWritePendingReason::parse(unknown).is_err());
        }
    }

    fn final_canary_envelope_fixture() -> PreparedMutationEnvelopeV1 {
        let account = AccountId::new(fixture_key_pair(0x45).public_key().clone());
        let fee_payment = FeePaymentIntent::authority(Vec::new(), None);
        let binding = PreparedMutationBindingV1 {
            schema: PREPARED_BINDING_SCHEMA_V1.to_owned(),
            authorization_sha256: "ab".repeat(32),
            authorization_nonce: "n".repeat(32),
            kind: "write_canary".to_owned(),
            phase: "pre_edge".to_owned(),
            idempotency_key: "cd".repeat(32),
            execution_expires_at_unix_ms: u64::MAX,
        };
        let operation = FinalCanaryPreparedTransactionV1 {
            schema: PREPARED_OPERATION_SCHEMA_V1.to_owned(),
            binding: binding.clone(),
            operation: WRITE_CANARY_OPERATION.to_owned(),
            transaction_hash_hex: "ab".repeat(32),
            signed_transaction_wire_hex: "00".to_owned(),
            signed_transaction_wire_sha256: "cd".repeat(32),
            semantic_hash_hex: "ef".repeat(32),
            fee_payment: fee_payment.clone(),
            fee_quote: FeeQuoteResponse {
                intent: fee_payment,
                observation: iroha_torii_shared::FeeQuoteObservation {
                    ledger_time_ms: 1,
                    next_block_height: 1,
                    route_dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                },
                components: Vec::new(),
                capacities: Vec::new(),
                decision: iroha_torii_shared::FeeQuoteDecision::Accepted {
                    debit_source: iroha::data_model::nexus::FeeDebitSource::Account(
                        account.clone(),
                    ),
                    program_revision: None,
                },
            },
        };
        PreparedMutationEnvelopeV1 {
            schema: PREPARED_ENVELOPE_SCHEMA_V1.to_owned(),
            binding,
            public_root: DEFAULT_PUBLIC_ROOT.to_owned(),
            chain_id: DEFAULT_CHAIN_ID.to_owned(),
            network_id: "fixture-network".to_owned(),
            authority: account.to_string(),
            operation: PreparedTransactionOperationV1::FinalCanary(operation),
        }
    }

    #[test]
    fn prepared_final_canary_requires_signed_current_admission() {
        use iroha::data_model::transaction::TransactionBuilder;

        let _chain = ChainDiscriminantGuard::enter(0x02f1);
        let network_id = crate::fallback_config().network_id;
        let key_pair = fixture_key_pair(0x45);
        let envelope = final_canary_envelope_fixture();
        let binding = envelope.binding;
        let message = prepared_canary_message(&binding).unwrap();
        let semantic_hash =
            prepared_semantic_sha256(&binding, WRITE_CANARY_OPERATION, &message).unwrap();
        let binding_value = json::to_value(&binding).unwrap();
        let mut metadata = Metadata::default();
        insert_string_metadata(&mut metadata, "taira_canary", "write-canary").unwrap();
        insert_string_metadata(
            &mut metadata,
            "taira_write_canary_idempotency_v1",
            &binding.idempotency_key,
        )
        .unwrap();
        metadata.insert(
            Name::from_str(PREPARED_BINDING_METADATA).unwrap(),
            IrohaJson::from_norito_value_ref(&binding_value).unwrap(),
        );
        insert_string_metadata(
            &mut metadata,
            PREPARED_OPERATION_METADATA,
            WRITE_CANARY_OPERATION,
        )
        .unwrap();
        insert_string_metadata(&mut metadata, PREPARED_SEMANTIC_METADATA, &semantic_hash).unwrap();

        let PreparedTransactionOperationV1::FinalCanary(mut operation) =
            final_canary_envelope_fixture().operation
        else {
            unreachable!("final canary fixture")
        };
        let transaction = TransactionBuilder::new(
            network_id,
            AccountId::new(key_pair.public_key().clone()),
            operation.fee_payment.clone(),
        )
        .with_executable(Executable::Instructions(
            vec![InstructionBox::from(Log::new(
                LogLevel::INFO,
                message.clone(),
            ))]
            .into(),
        ))
        .with_metadata(metadata.clone())
        .try_sign(key_pair.private_key())
        .unwrap();
        let wire = transaction.encode_wire_v1().unwrap();
        operation.transaction_hash_hex = hex::encode(transaction.hash().as_ref());
        operation.signed_transaction_wire_hex = hex::encode(&wire);
        operation.signed_transaction_wire_sha256 = hex::encode(Sha256::digest(&wire));
        operation.semantic_hash_hex = semantic_hash.clone();
        let value = json::to_value(&operation).unwrap();
        let result =
            verify_final_canary_prepared_operation_v1(&value, &network_id, transaction.authority());
        assert_eq!(result.unwrap(), transaction);
    }

    #[test]
    fn prepared_binding_metadata_matches_objects_before_submission_and_after_commit() {
        let _chain = ChainDiscriminantGuard::enter(0x02f1);
        let fixture: Value = json::from_str(include_str!(
            "../../../fixtures/prepared_transactions/prepared_transaction_signature_v1.json"
        ))
        .expect("public signed preparation fixtures");
        let vectors = fixture
            .pointer("/vectors")
            .and_then(Value::as_array)
            .unwrap();
        let vector = |name: &str| {
            vectors
                .iter()
                .find(|value| value.pointer("/name").and_then(Value::as_str) == Some(name))
                .expect("named signed fixture")
        };
        let onboarding: AccountOnboardingPreparedTransactionV1 = json::from_value(
            vector("onboarding_prepared")
                .pointer("/response")
                .unwrap()
                .clone(),
        )
        .expect("typed onboarding fixture");
        let proof = PreparedOnboardingProofRequiredV1 {
            schema: PREPARED_ONBOARDING_PROOF_REQUIRED_SCHEMA_V1.to_owned(),
            receipt: onboarding.receipt.clone(),
            result: json::from_value(
                vector("onboarding_proof_required")
                    .pointer("/response")
                    .unwrap()
                    .clone(),
            )
            .expect("typed onboarding proof fixture"),
        };
        let faucet = json::from_value(
            vector("faucet_prepared")
                .pointer("/response")
                .unwrap()
                .clone(),
        )
        .expect("typed faucet fixture");
        for operation in [
            PreparedTransactionOperationV1::OnboardingPrepared(onboarding),
            PreparedTransactionOperationV1::OnboardingProofRequired(proof),
            PreparedTransactionOperationV1::FaucetPrepared(faucet),
            final_canary_envelope_fixture().operation,
        ] {
            let value = json::to_value(&operation).expect("typed operation projection");
            let binding = value
                .pointer("/envelope/binding")
                .or_else(|| value.pointer("/envelope/result/binding"))
                .expect("operation binding object");
            let (binding_key, expected) = operation.binding_metadata().unwrap();
            let mut metadata = Metadata::default();
            metadata.insert(
                Name::from_str(binding_key).unwrap(),
                IrohaJson::from_norito_value_ref(binding)
                    .expect("actual binding metadata producer"),
            );
            assert!(prepared_operation_binding_matches(&metadata, &operation).unwrap());
            insert_string_metadata(&mut metadata, binding_key, &expected).unwrap();
            assert!(
                !prepared_operation_binding_matches(&metadata, &operation).unwrap(),
                "a JSON string must not substitute for the bound object"
            );
            let mut substituted = binding.clone();
            substituted
                .as_object_mut()
                .unwrap()
                .insert("execution_expires_at_unix_ms".to_owned(), 1_u64.into());
            metadata.insert(
                Name::from_str(binding_key).unwrap(),
                IrohaJson::from_norito_value_ref(&substituted).unwrap(),
            );
            assert!(
                !prepared_operation_binding_matches(&metadata, &operation).unwrap(),
                "a changed binding field must remain fatal"
            );

            if matches!(
                operation,
                PreparedTransactionOperationV1::OnboardingPrepared(_)
                    | PreparedTransactionOperationV1::FaucetPrepared(_)
            ) {
                let wire = hex::decode(operation.signed_transaction_wire_hex().unwrap()).unwrap();
                let transaction = SignedTransaction::decode_all_versioned(&wire)
                    .expect("actual signed fixture transaction");
                let verified = match &operation {
                    PreparedTransactionOperationV1::OnboardingPrepared(prepared) => {
                        let network = json::from_value(
                            vector("onboarding_prepared")
                                .pointer("/network_id")
                                .unwrap()
                                .clone(),
                        )
                        .unwrap();
                        iroha::client::verify_account_onboarding_prepared_transaction_v1(
                            network,
                            &prepared.receipt.body.request,
                            prepared,
                            &prepared.receipt,
                            &prepared.binding,
                            &prepared.fee_payment,
                        )
                        .expect(
                            "actual SDK onboarding verifier accepts the signed producer fixture",
                        )
                    }
                    PreparedTransactionOperationV1::FaucetPrepared(prepared) => {
                        let network = json::from_value(
                            vector("faucet_prepared")
                                .pointer("/network_id")
                                .unwrap()
                                .clone(),
                        )
                        .unwrap();
                        let policy = AccountFaucetPolicyV1::try_new(
                            AccountId::new(fixture_key_pair(0x61).public_key().clone()),
                            "4rPeAP6jAjiLVZThZYwwPRBuQagt".parse().unwrap(),
                            5_u64.into(),
                        )
                        .expect("independent public fixture faucet policy");
                        iroha::client::verify_account_faucet_prepared_transaction_v1(
                            network,
                            prepared,
                            &prepared.claim,
                            &prepared.binding,
                            &prepared.fee_payment,
                            &policy,
                        )
                        .expect("actual SDK faucet verifier accepts the signed producer fixture")
                    }
                    _ => unreachable!("selected server-prepared transaction variants"),
                };
                assert_eq!(verified.encode_wire_v1().unwrap(), wire);
                validate_prepared_transaction_closure(
                    &transaction,
                    &operation,
                    &wire,
                    transaction.network_id().unwrap(),
                )
                .expect("real pre-submit closure accepts signed object binding");
                assert!(
                    prepared_operation_binding_matches(transaction.metadata(), &operation)
                        .expect("same exact binding check used by committed transaction proof")
                );
                if matches!(operation, PreparedTransactionOperationV1::FaucetPrepared(_)) {
                    use iroha::data_model::transaction::FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY;
                    let marker = Name::from_str(FAUCET_CLAIM_MARKER_VERSION_METADATA_KEY).unwrap();
                    for invalid in [None, Some(IrohaJson::new(2_u64)), Some(IrohaJson::new("1"))] {
                        let mut metadata = transaction.metadata().clone();
                        metadata.remove(&marker);
                        if let Some(value) = invalid {
                            metadata.insert(marker.clone(), value);
                        }
                        assert!(
                            !prepared_faucet_metadata_closure_is_exact(&metadata),
                            "faucet claim marker must exist as the exact numeric V1 value"
                        );
                    }
                    let mut metadata = transaction.metadata().clone();
                    metadata.insert(Name::from_str("unexpected").unwrap(), IrohaJson::new(1_u64));
                    assert!(
                        !prepared_faucet_metadata_closure_is_exact(&metadata),
                        "faucet metadata remains a closed four-field shape"
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn typed_inrou_envelopes_reach_fd_and_exact_predecessor_consumers() {
        use std::{io::Seek as _, os::fd::AsRawFd as _};

        let _chain = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        let canary = final_canary_envelope_fixture();
        let PreparedTransactionOperationV1::FinalCanary(final_operation) = &canary.operation else {
            panic!("final-canary fixture");
        };
        for operation in [
            InrouCanaryOperation::BundlePin,
            InrouCanaryOperation::GuestPin,
            InrouCanaryOperation::DiscoveryPin,
            InrouCanaryOperation::ServiceMutation,
        ] {
            let binding = crate::soracloud::TairaMutationBindingV1 {
                authorization_sha256: canary.binding.authorization_sha256.clone(),
                authorization_nonce: canary.binding.authorization_nonce.clone(),
                kind: operation.mutation_kind().to_owned(),
                phase: canary.binding.phase.clone(),
                idempotency_key: canary.binding.idempotency_key.clone(),
                execution_expires_at_unix_ms: canary.binding.execution_expires_at_unix_ms,
            };
            let transaction = PreparedInrouTransactionV1 {
                schema: PREPARED_INROU_OPERATION_SCHEMA_V1.to_owned(),
                binding: binding.clone(),
                operation: operation.label().to_owned(),
                transaction_hash_hex: final_operation.transaction_hash_hex.clone(),
                signed_transaction_wire_hex: final_operation.signed_transaction_wire_hex.clone(),
                signed_transaction_wire_sha256: final_operation
                    .signed_transaction_wire_sha256
                    .clone(),
                fee_payment: final_operation.fee_payment.clone(),
                fee_quote: final_operation.fee_quote.clone(),
            };
            let tagged = match operation {
                InrouCanaryOperation::BundlePin => {
                    PreparedInrouOperationV1::InrouBundlePin(transaction)
                }
                InrouCanaryOperation::GuestPin => {
                    PreparedInrouOperationV1::InrouGuestPin(transaction)
                }
                InrouCanaryOperation::DiscoveryPin => {
                    PreparedInrouOperationV1::InrouDiscoveryPin(transaction)
                }
                InrouCanaryOperation::ServiceMutation => {
                    PreparedInrouOperationV1::InrouCanary(transaction)
                }
            };
            let envelope = PreparedInrouEnvelopeV1 {
                schema: PREPARED_ENVELOPE_SCHEMA_V1.to_owned(),
                probe_scope: "candidate".to_owned(),
                binding,
                public_root: canary.public_root.clone(),
                chain_id: canary.chain_id.clone(),
                network_id: canary.network_id.clone(),
                authority: canary.authority.clone(),
                stage: (&inrou_canary_stage_identity("deploy", "v1")).into(),
                operation: tagged,
            };
            let produced = canonical_prepared_inrou_envelope_bytes(&envelope)
                .expect("actual typed Inrou producer");
            let mut canonical = json::to_json(&json::to_value(&envelope).unwrap())
                .unwrap()
                .into_bytes();
            canonical.push(b'\n');
            assert_eq!(produced, canonical, "host canonical JSON boundary");
            let mut file = NamedTempFile::new().unwrap();
            file.write_all(&produced).unwrap();
            file.rewind().unwrap();
            let (reopened, bytes) =
                read_prepared_inrou_envelope(u32::try_from(file.as_raw_fd()).unwrap())
                    .expect("actual inherited-FD consumer");
            assert_eq!(reopened, envelope);
            assert_eq!(bytes, produced);
            if operation != InrouCanaryOperation::ServiceMutation {
                let predecessor =
                    decode_exact_inrou_predecessor_v1(&produced, operation.mutation_kind())
                        .expect("actual typed predecessor consumer");
                assert_eq!(predecessor, json::to_value(&envelope).unwrap());
            }
            let mut declaration_order = json::to_json(&envelope).unwrap().into_bytes();
            declaration_order.push(b'\n');
            assert_ne!(
                produced, declaration_order,
                "fixture exercises differing object field orders"
            );
        }
    }

    #[test]
    fn inrou_predecessor_decoder_rejects_unknown_fields_at_every_envelope_layer() {
        let envelope = final_canary_envelope_fixture();
        let exact = canonical_prepared_envelope_bytes(&envelope).expect("canonical predecessor");
        decode_exact_inrou_predecessor_v1(&exact, "write_canary")
            .expect("exact final-canary predecessor");

        for path in [
            &["retired_v0"][..],
            &["binding", "retired_v0"][..],
            &["operation", "retired_v0"][..],
            &["operation", "envelope", "retired_v0"][..],
            &["operation", "envelope", "fee_quote", "retired_v0"][..],
            &[
                "operation",
                "envelope",
                "fee_quote",
                "observation",
                "retired_v0",
            ][..],
        ] {
            let mut unknown = json::to_value(&envelope).expect("encode predecessor fixture");
            let mut object = unknown.as_object_mut().expect("predecessor object");
            for segment in &path[..path.len() - 1] {
                object = object
                    .get_mut(*segment)
                    .and_then(Value::as_object_mut)
                    .expect("nested predecessor object");
            }
            object.insert(
                path[path.len() - 1].to_owned(),
                Value::String("forbidden".to_owned()),
            );
            let mut bytes = json::to_json(&unknown)
                .expect("encode unknown predecessor")
                .into_bytes();
            bytes.push(b'\n');
            assert!(
                decode_exact_inrou_predecessor_v1(&bytes, "write_canary").is_err(),
                "first-release predecessor accepted unknown path {}",
                path.join("."),
            );
        }
    }

    fn test_onboarding_token_file() -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create onboarding token file");
        file.write_all(TEST_ONBOARDING_TOKEN.as_bytes())
            .expect("write onboarding token file");
        file.flush().expect("flush onboarding token file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600))
                .expect("set onboarding token file mode");
        }
        file
    }

    fn fixture_write_canary_args(operation: WriteCanaryOperation) -> WriteCanary {
        let faucet_authority = AccountId::new(
            KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
                .expect("deterministic faucet policy key")
                .public_key()
                .clone(),
        );
        let authorization_nonce = "n".repeat(32);
        let mutation_phase = "pre_edge".to_owned();
        let idempotency_key = write_canary_child_idempotency_key(
            &authorization_nonce,
            &mutation_phase,
            operation.mutation_kind(),
        );
        WriteCanary {
            public_root: DEFAULT_PUBLIC_ROOT.to_owned(),
            faucet_authority: (operation == WriteCanaryOperation::Faucet)
                .then(|| faucet_authority.to_string()),
            faucet_asset_id: (operation == WriteCanaryOperation::Faucet)
                .then(|| DEFAULT_GAS_ASSET_ID.to_owned()),
            faucet_amount: (operation == WriteCanaryOperation::Faucet).then(|| "25000".to_owned()),
            predecessor_faucet_authority: (operation == WriteCanaryOperation::FinalCanary)
                .then(|| faucet_authority.to_string()),
            predecessor_faucet_asset_id: (operation == WriteCanaryOperation::FinalCanary)
                .then(|| DEFAULT_GAS_ASSET_ID.to_owned()),
            predecessor_faucet_amount: (operation == WriteCanaryOperation::FinalCanary)
                .then(|| "25000".to_owned()),
            onboarding_token_file: None,
            onboarding_token_fd: None,
            operation,
            authorization_sha256: "ab".repeat(32),
            authorization_nonce,
            mutation_phase,
            idempotency_key,
            execution_expires_at_unix_ms: u64::MAX,
            prepare_envelope: true,
            prepared_output_fd: Some(3),
            submit_prepared_envelope_fd: None,
            recover_prepared_envelope_fd: None,
            prerequisite_envelope_fd: None,
            timeout_secs: 120,
            json: true,
        }
    }

    #[derive(Clone)]
    struct MockRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    }
    impl std::fmt::Debug for MockRequest {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("MockRequest")
                .field("method", &self.method)
                .field("path", &self.path)
                .field(
                    "header_names",
                    &self
                        .headers
                        .iter()
                        .map(|(name, _)| name)
                        .collect::<Vec<_>>(),
                )
                .field("body", &self.body)
                .finish()
        }
    }
    impl MockRequest {
        fn header_values(&self, name: &str) -> Vec<&str> {
            self.headers
                .iter()
                .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .collect()
        }
    }
    struct MockResponse {
        status: u16,
        content_type: &'static str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    }
    fn fixture_key_pair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair")
    }
    struct TextContext {
        cfg: Config,
        i18n: Localizer,
        lines: Vec<String>,
    }
    impl TextContext {
        fn new() -> Self {
            Self {
                cfg: crate::fallback_config(),
                i18n: Localizer::new(Bundle::Cli, Language::English),
                lines: Vec::new(),
            }
        }
    }
    impl RunContext for TextContext {
        fn config(&self) -> &Config {
            &self.cfg
        }
        fn transaction_metadata(&self) -> Option<&Metadata> {
            None
        }
        fn input_instructions(&self) -> bool {
            false
        }
        fn output_instructions(&self) -> bool {
            false
        }
        fn i18n(&self) -> &Localizer {
            &self.i18n
        }
        fn output_format(&self) -> CliOutputFormat {
            CliOutputFormat::Text
        }
        fn print_data<T>(&mut self, data: &T) -> Result<()>
        where
            T: norito::json::JsonSerialize + ?Sized,
        {
            let _value = norito::json::to_value(data)?;
            Ok(())
        }
        fn println(&mut self, data: impl std::fmt::Display) -> Result<()> {
            self.lines.push(data.to_string());
            Ok(())
        }
    }
    impl MockResponse {
        fn json(status: u16, value: Value) -> Self {
            Self {
                status,
                content_type: "application/json",
                headers: Vec::new(),
                body: json::to_vec(&value).expect("mock JSON response"),
            }
        }
        fn text(status: u16, body: impl Into<String>) -> Self {
            let body: String = body.into();
            Self {
                status,
                content_type: "text/plain",
                headers: Vec::new(),
                body: body.into_bytes(),
            }
        }
    }
    static MOCK_HTTP_FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    struct MockHttpFixturePermit {
        _guard: std::sync::MutexGuard<'static, ()>,
    }
    thread_local! {
        static MOCK_HTTP_FIXTURE_OWNER: std::cell::RefCell<std::rc::Weak<MockHttpFixturePermit>> =
            std::cell::RefCell::new(std::rc::Weak::new());
    }
    fn mock_http_fixture_guard() -> std::rc::Rc<MockHttpFixturePermit> {
        // Independent blocking clients otherwise multiply worker threads and consume the
        // deliberately short wall-clock deadlines under parallel unit execution. A test owns
        // all of its loopback servers together; nested servers share the same permit.
        MOCK_HTTP_FIXTURE_OWNER.with(|owner| {
            if let Some(permit) = owner.borrow().upgrade() {
                return permit;
            }
            let permit = std::rc::Rc::new(MockHttpFixturePermit {
                _guard: MOCK_HTTP_FIXTURE_LOCK
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            });
            *owner.borrow_mut() = std::rc::Rc::downgrade(&permit);
            permit
        })
    }
    struct MockHttpServer {
        _fixture_permit: std::rc::Rc<MockHttpFixturePermit>,
        base_url: String,
        requests: Arc<Mutex<Vec<MockRequest>>>,
        stop: Arc<AtomicBool>,
        handle: thread::JoinHandle<()>,
    }
    fn spawn_mock_http<F>(expected_requests: usize, responder: F) -> MockHttpServer
    where
        F: Fn(&MockRequest) -> MockResponse + Send + Sync + 'static,
    {
        let fixture_permit = mock_http_fixture_guard();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server address");
        listener
            .set_nonblocking(true)
            .expect("set mock server nonblocking");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_requests = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let responder = Arc::new(responder);
        let chain_discriminant = iroha::data_model::account::address::chain_discriminant();
        let handle = thread::spawn(move || {
            // Account JSON uses a thread-scoped network identity. The fixture's
            // HTTP peer must decode and encode in the caller's selected network.
            let _chain = ChainDiscriminantGuard::enter(chain_discriminant);
            let mut accepted = 0_usize;
            while accepted < expected_requests && !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("set accepted mock stream blocking");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("mock stream timeout");
                        let request = match read_mock_request(&mut stream) {
                            Ok(Some(request)) => request,
                            // Deadline-bound clients may cancel before sending a complete
                            // request. Such connections do not consume the request budget.
                            Ok(None) => continue,
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionAborted
                                        | std::io::ErrorKind::TimedOut
                                        | std::io::ErrorKind::WouldBlock
                                ) =>
                            {
                                continue;
                            }
                            Err(error) => panic!("read mock request: {error}"),
                        };
                        let response = responder(&request);
                        server_requests
                            .lock()
                            .expect("requests")
                            .push(request.clone());
                        if let Err(error) = write_mock_response(&mut stream, response) {
                            // Deadline-bound probes may close a connection before the mock
                            // finishes replying. Keep recording requests and serving retries.
                            assert!(
                                matches!(
                                    error.kind(),
                                    std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionAborted
                                ),
                                "write mock response: {error}"
                            );
                        }
                        accepted += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("mock server accept failed: {error}"),
                }
            }
        });
        MockHttpServer {
            _fixture_permit: fixture_permit,
            base_url: format!("http://{addr}"),
            requests,
            stop,
            handle,
        }
    }
    fn read_mock_request(reader: &mut impl Read) -> std::io::Result<Option<MockRequest>> {
        let mut raw = Vec::new();
        let mut buf = [0_u8; 4096];
        let (header_end, body_end) = loop {
            let read = match reader.read(&mut buf) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if read == 0 {
                return Ok(None);
            }
            raw.extend_from_slice(&buf[..read]);
            if let Some(header_end) = find_header_end(&raw) {
                let headers = String::from_utf8_lossy(&raw[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let body_end = header_end + 4 + content_length;
                if raw.len() >= body_end {
                    break (header_end, body_end);
                }
            }
        };
        let headers = String::from_utf8_lossy(&raw[..header_end]);
        let request_line = headers.lines().next().expect("request line");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().expect("method").to_owned();
        let path = parts.next().expect("path").to_owned();
        let parsed_headers = headers
            .lines()
            .skip(1)
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_owned(), value.trim().to_owned()))
            })
            .collect();
        let body = String::from_utf8_lossy(&raw[header_end + 4..body_end]).to_string();
        Ok(Some(MockRequest {
            method,
            path,
            headers: parsed_headers,
            body,
        }))
    }
    fn find_header_end(raw: &[u8]) -> Option<usize> {
        raw.windows(4).position(|window| window == b"\r\n\r\n")
    }
    fn write_mock_response(
        stream: &mut impl std::io::Write,
        response: MockResponse,
    ) -> std::io::Result<()> {
        let reason = match response.status {
            200 => "OK",
            202 => "Accepted",
            307 => "Temporary Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            503 => "Service Unavailable",
            _ => "OK",
        };
        let body = response.body.as_slice();
        // Send the frame together: fragmented header writes trigger Nagle/delayed-ACK
        // latency on loopback and consume the operation deadlines being tested.
        let mut frame = Vec::new();
        write!(
            frame,
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            response.status,
            reason,
            response.content_type,
            body.len()
        )?;
        for (name, value) in response.headers {
            write!(frame, "{name}: {value}\r\n")?;
        }
        write!(frame, "\r\n")?;
        frame.extend_from_slice(body);
        stream.write_all(&frame)
    }
    fn finish_mock(server: MockHttpServer) -> Vec<MockRequest> {
        server.stop.store(true, Ordering::Release);
        server.handle.join().expect("mock server thread");
        Arc::try_unwrap(server.requests)
            .expect("request references")
            .into_inner()
            .expect("requests")
    }

    #[test]
    fn mock_http_fixture_ownership_is_reentrant_and_released_after_last_owner() {
        let first = mock_http_fixture_guard();
        let original = std::rc::Rc::downgrade(&first);
        let second = mock_http_fixture_guard();
        assert!(std::rc::Rc::ptr_eq(&first, &second));
        assert!(
            thread::spawn(|| MOCK_HTTP_FIXTURE_LOCK.try_lock().is_err())
                .join()
                .unwrap()
        );
        drop(first);
        assert!(
            original.upgrade().is_some(),
            "the nested fixture still owns exclusion"
        );
        drop(second);
        assert!(
            original.upgrade().is_none(),
            "the final fixture releases its ownership"
        );
        let next = mock_http_fixture_guard();
        assert!(!std::rc::Weak::ptr_eq(
            &original,
            &std::rc::Rc::downgrade(&next)
        ));
    }
    #[test]
    fn mock_response_preserves_the_exact_frame_in_one_transport_write() {
        #[derive(Default)]
        struct TransportWrites(Vec<Vec<u8>>);
        impl std::io::Write for TransportWrites {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.push(bytes.to_vec());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut transport = TransportWrites::default();
        write_mock_response(
            &mut transport,
            MockResponse {
                status: 202,
                content_type: "application/x-norito",
                headers: vec![("X-Proof", "exact".to_owned())],
                body: vec![0, 0xff, b'\r', b'\n'],
            },
        )
        .expect("complete mock HTTP frame");
        assert_eq!(
            transport.0,
            [b"HTTP/1.1 202 Accepted\r\nContent-Type: application/x-norito\r\nContent-Length: 4\r\nConnection: close\r\nX-Proof: exact\r\n\r\n\0\xff\r\n".to_vec()],
            "the fixture must preserve headers and binary body without delaying fragments"
        );
    }

    #[test]
    fn mock_request_reader_requires_complete_headers_and_body() {
        let raw = b"POST /retry HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
        for end in 0..raw.len() {
            let request = read_mock_request(&mut std::io::Cursor::new(&raw[..end]))
                .expect("read truncated fixture");
            assert!(
                request.is_none(),
                "accepted truncated request at byte {end}"
            );
        }
        let request = read_mock_request(&mut std::io::Cursor::new(raw))
            .expect("read complete fixture")
            .expect("complete request");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/retry");
        assert_eq!(request.header_values("content-length"), ["4"]);
        assert_eq!(request.body, "body");
    }

    #[test]
    fn mock_request_reader_handles_fragmentation_and_interrupted_reads() {
        struct FragmentedReader<'a> {
            remaining: &'a [u8],
            interrupt: bool,
        }
        impl Read for FragmentedReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.interrupt = !self.interrupt;
                if self.interrupt {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.remaining.read(&mut buf[..1])
            }
        }
        let mut reader = FragmentedReader {
            remaining: b"POST /fragmented HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody",
            interrupt: false,
        };
        let request = read_mock_request(&mut reader)
            .expect("retry interrupted reads")
            .expect("reassemble complete request");
        assert_eq!(request.path, "/fragmented");
        assert_eq!(request.body, "body");
    }

    #[test]
    fn mock_http_server_continues_after_incomplete_requests() {
        let server = spawn_mock_http(1, |request| {
            assert_eq!(request.path, "/retry");
            MockResponse::text(200, "ok")
        });
        let address = server.base_url.strip_prefix("http://").unwrap();
        for partial in [
            b"".as_slice(),
            b"GET /cancelled HTTP/1.1\r\nHost: localhost\r\n",
            b"POST /cancelled HTTP/1.1\r\nContent-Length: 4\r\n\r\nab",
        ] {
            let mut cancelled = TcpStream::connect(address).expect("connect cancelled request");
            cancelled.write_all(partial).expect("send partial request");
            cancelled
                .shutdown(std::net::Shutdown::Write)
                .expect("close incomplete request");
            cancelled
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("bound cancelled read");
            let mut response = Vec::new();
            cancelled
                .read_to_end(&mut response)
                .expect("server discards incomplete request");
            assert!(response.is_empty());
        }
        let mut retry = TcpStream::connect(address).expect("connect retry");
        retry
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("bound retry read");
        retry
            .write_all(b"GET /retry HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("send complete retry");
        let mut response = String::new();
        retry
            .read_to_string(&mut response)
            .expect("read retry response");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("\r\n\r\nok"));
        let requests = finish_mock(server);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/retry");
    }

    #[test]
    fn mock_http_server_continues_after_client_disconnect() {
        let (received_tx, received_rx) = std::sync::mpsc::channel();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let closed_rx = Mutex::new(closed_rx);
        let server = spawn_mock_http(2, move |request| {
            if request.path == "/cancelled" {
                received_tx.send(()).expect("notify request received");
                closed_rx
                    .lock()
                    .expect("client closure receiver")
                    .recv_timeout(Duration::from_secs(5))
                    .expect("client closes before the response");
                // Use a large response so the mock observes the client disconnect
                // while writing, even if the initial headers fit in the socket buffer.
                MockResponse::text(200, "x".repeat(4 * 1024 * 1024))
            } else {
                assert_eq!(request.path, "/retry");
                MockResponse::text(200, "ok")
            }
        });
        let address = server.base_url.strip_prefix("http://").unwrap();
        let mut cancelled = TcpStream::connect(address).expect("connect cancelled request");
        cancelled
            .write_all(b"GET /cancelled HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("send cancelled request");
        received_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server received complete request");
        cancelled
            .shutdown(std::net::Shutdown::Both)
            .expect("close client before response");
        drop(cancelled);
        closed_tx.send(()).expect("notify client closed");

        let mut retry = TcpStream::connect(address).expect("connect retry");
        retry
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("bound retry read");
        retry
            .write_all(b"GET /retry HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("send retry");
        let mut response = String::new();
        retry
            .read_to_string(&mut response)
            .expect("read retry response");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("\r\n\r\nok"));
        let requests = finish_mock(server);
        assert_eq!(
            requests
                .iter()
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            ["/cancelled", "/retry"]
        );
    }

    fn path_only(path: &str) -> &str {
        path.split_once('?').map_or(path, |(path, _)| path)
    }
    fn assert_modern_mcp_request(request: &MockRequest, expected_id: u64, method: &str) {
        assert_eq!(request.header_values("accept"), vec![MCP_ACCEPT]);
        assert_eq!(
            request.header_values(mcp_wire::HEADER_PROTOCOL_VERSION),
            vec![mcp_wire::MODERN_PROTOCOL_VERSION]
        );
        assert_eq!(request.header_values(mcp_wire::HEADER_METHOD), vec![method]);
        assert!(request.header_values(mcp_wire::HEADER_NAME).is_empty());
        let payload: Value = json::from_str(&request.body).expect("modern MCP request JSON");
        assert_eq!(payload.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
        assert_eq!(payload.get("id").and_then(Value::as_u64), Some(expected_id));
        assert_eq!(payload.get("method").and_then(Value::as_str), Some(method));
        let params = payload
            .get("params")
            .and_then(Value::as_object)
            .expect("modern MCP params");
        let meta = params
            .get("_meta")
            .and_then(Value::as_object)
            .expect("modern MCP request metadata");
        assert_eq!(
            meta.get(mcp_wire::META_PROTOCOL_VERSION)
                .and_then(Value::as_str),
            Some(mcp_wire::MODERN_PROTOCOL_VERSION)
        );
        assert!(
            meta.get(mcp_wire::META_CLIENT_CAPABILITIES)
                .is_some_and(Value::is_object)
        );
        assert_eq!(
            meta.get(mcp_wire::META_CLIENT_INFO)
                .and_then(|info| info.get("name"))
                .and_then(Value::as_str),
            Some(MCP_CLIENT_NAME)
        );
        assert_eq!(
            meta.get(mcp_wire::META_CLIENT_INFO)
                .and_then(|info| info.get("version"))
                .and_then(Value::as_str),
            Some(MCP_CLIENT_VERSION)
        );
    }
    fn doctor_mock_response(request: &MockRequest, omit_tool: Option<&str>) -> MockResponse {
        match (request.method.as_str(), path_only(&request.path)) {
            ("GET", "/readyz") => MockResponse::text(200, "Ready"),
            ("GET", "/v1/accounts/capabilities") => doctor_account_tests::capability_response(),
            ("GET", "/v1/accounts/faucet/policy") => doctor_account_tests::faucet_response(),
            ("GET", "/status") => MockResponse::json(
                200,
                norito::json!({
                    "txs_rejected_recent_5m": 0,
                    "queue_size": 0,
                    "sumeragi": { "tx_queue_saturated": false }
                }),
            ),
            ("GET", "/v1/time/now") => MockResponse::json(
                200,
                norito::json!({
                    "now": 1_785_168_000_000_u64,
                    "offset_ms": 0,
                    "confidence_ms": 1,
                    "sample_count": 3,
                    "peer_count": 3,
                    "enforcement_mode": "reject",
                    "fallback": false,
                    "health": {
                        "healthy": true,
                        "min_samples_ok": true,
                        "offset_ok": true,
                        "confidence_ok": true
                    }
                }),
            ),
            ("GET", "/v1/sumeragi/status") => MockResponse::json(
                401,
                norito::json!({
                    "code": "canonical_authentication_required",
                    "message": "canonical account request authentication is required"
                }),
            ),
            ("GET", "/v1/contracts/state") => {
                MockResponse::json(400, norito::json!({"error": "missing selector"}))
            }
            ("GET", "/v1/pipeline/transactions/status") => {
                MockResponse::json(400, norito::json!({"error": "missing transaction hash"}))
            }
            ("POST", "/v1/musubi/queries/ordered-prefix") => MockResponse::json(
                401,
                norito::json!({
                    "code": "canonical_authentication_required",
                    "message": "canonical account request authentication is required"
                }),
            ),
            ("GET", "/v1/soracloud/status") => MockResponse::json(
                401,
                norito::json!({
                    "code": "canonical_authentication_required",
                    "message": "canonical account request authentication is required"
                }),
            ),
            ("GET", "/v1/mcp") => MockResponse::text(405, "method not allowed"),
            ("POST", "/v1/mcp") if request.body.contains("server/discover") => {
                assert_modern_mcp_request(request, 1, "server/discover");
                MockResponse::json(
                    200,
                    norito::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "supportedVersions": [
                                (mcp_wire::MODERN_PROTOCOL_VERSION),
                            ],
                            "capabilities": {
                                "tools": { "listChanged": false }
                            },
                            "resultType": "complete",
                            "ttlMs": 30_000,
                            "cacheScope": "private",
                            "_meta": {
                                "io.modelcontextprotocol/serverInfo": {
                                    "name": "iroha-torii-mcp",
                                    "version": "1"
                                }
                            }
                        }
                    }),
                )
            }
            ("POST", "/v1/mcp") if request.body.contains("tools/list") => {
                assert_modern_mcp_request(request, 2, "tools/list");
                let mut tools: Vec<Value> = REQUIRED_MCP_TOOLS
                    .iter()
                    .chain(FULL_MCP_TOOLS)
                    .copied()
                    .filter(|name| Some(*name) != omit_tool)
                    .map(|name| norito::json!({ "name": name, "description": "mock" }))
                    .collect();
                tools.push(norito::json!({ "name": "torii.get_v1_accounts", "description": "projected route" }));
                MockResponse::json(
                    200,
                    norito::json!({
                        "jsonrpc": "2.0",
                        "id": 2,
                        "result": {
                            "tools": tools,
                            "resultType": "complete",
                            "ttlMs": 30_000,
                            "cacheScope": "private",
                            "_meta": {
                                "io.modelcontextprotocol/serverInfo": {
                                    "name": "iroha-torii-mcp",
                                    "version": "1"
                                }
                            }
                        }
                    }),
                )
            }
            ("GET", _) => MockResponse::json(200, norito::json!({"ok": true})),
            _ => MockResponse::text(404, "not found"),
        }
    }
    fn inrou_canary_deployment(mode: &str, version: &str) -> InrouProbeIdentity {
        let validator_key = fixture_key_pair(0x91);
        let bundle_hash = Hash::new(b"taira-test-bundle");
        let deployment_bundle_hash = Hash::new(b"taira-test-deployment-bundle");
        let container_manifest_hash = Hash::new(b"taira-test-container-manifest");
        let service_manifest_hash = Hash::new(b"taira-test-service-manifest");
        let discovery_document = InrouPublicDiscoveryDocumentV1 {
            schema_version: 1,
            service_name: "taira_inrou_canary".to_owned(),
            service_version: version.to_owned(),
            execution_plane: "HttpService".to_owned(),
            runtime: "Inrou".to_owned(),
            route_host: "taira.sora.org".to_owned(),
            path_prefix: "/api/v1/inrou-canary".to_owned(),
            base_url: "https://taira.sora.org/api/v1/inrou-canary/".to_owned(),
            healthcheck_path: Some("/health".to_owned()),
            healthcheck_url: Some("https://taira.sora.org/api/v1/inrou-canary/health".to_owned()),
            service_manifest_hash,
            container_manifest_hash,
            deployment_bundle_hash,
        };
        let discovery_document_hash = Hash::new(
            json::to_vec(&discovery_document).expect("encode exact discovery document fixture"),
        );
        let discovery_content_cid =
            "bafyr6ibugm2danbugm2danbugm2danbugm2danbugm2danbugm2danbugm".to_owned();
        InrouProbeIdentity {
            service_name: "taira_inrou_canary".to_owned(),
            service_version: version.to_owned(),
            route_host: "taira.sora.org".to_owned(),
            route_path_prefix: "/api/v1/inrou-canary".to_owned(),
            healthcheck_path: "/health".to_owned(),
            stage_mode: mode.to_owned(),
            bundle_hash: bundle_hash.to_string(),
            discovery_payload_dir: "payloads/discovery".to_owned(),
            discovery_document_hash: discovery_document_hash.to_string(),
            discovery_content_cid: discovery_content_cid.clone(),
            discovery_manifest_digest_hex: "33".repeat(32),
            public_discovery_url: format!(
                "https://taira.sora.org/sorafs/cid/{discovery_content_cid}/index.json"
            ),
            public_discovery_cid_host_url: format!(
                "https://{discovery_content_cid}.sorafs.taira.sora.org/index.json"
            ),
            deployment_bundle_hash: deployment_bundle_hash.to_string(),
            container_manifest_hash: container_manifest_hash.to_string(),
            service_manifest_hash: service_manifest_hash.to_string(),
            placement_targets: BTreeSet::from([
                iroha::data_model::soracloud::SoraInrouPlacementTargetV1 {
                    validator_account_id: AccountId::new(validator_key.public_key().clone()),
                    peer_id: validator_key.public_key().to_string(),
                },
            ]),
        }
    }
    fn inrou_canary_stage_identity(
        mode: &str,
        version: &str,
    ) -> crate::soracloud::TairaInrouStageIdentity {
        let deployment = inrou_canary_deployment(mode, version);
        let placement_targets = deployment.placement_targets.clone();
        crate::soracloud::TairaInrouStageIdentity {
            service_name: deployment.service_name,
            service_version: deployment.service_version,
            route_host: deployment.route_host,
            route_path_prefix: deployment.route_path_prefix,
            healthcheck_path: deployment.healthcheck_path,
            stage_mode: deployment.stage_mode,
            bundle_hash: deployment.bundle_hash,
            bundle_content_cid: "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge"
                .to_owned(),
            bundle_manifest_digest_hex: "31".repeat(32),
            guest_content_cid: "bafyr6ibsgizdemrsgizdemrsgizdemrsgizdemrsgizdemrsgizdemrsgi"
                .to_owned(),
            guest_manifest_digest_hex: "32".repeat(32),
            discovery_payload_dir: deployment.discovery_payload_dir,
            discovery_document_hash: deployment.discovery_document_hash,
            discovery_content_cid: deployment.discovery_content_cid,
            discovery_manifest_digest_hex: deployment.discovery_manifest_digest_hex,
            public_discovery_url: deployment.public_discovery_url,
            public_discovery_cid_host_url: deployment.public_discovery_cid_host_url,
            deployment_bundle_hash: deployment.deployment_bundle_hash,
            container_manifest_hash: deployment.container_manifest_hash,
            service_manifest_hash: deployment.service_manifest_hash,
            placement_targets,
        }
    }
    fn exact_inrou_discovery_authority(deployment: &InrouProbeIdentity) -> Value {
        json::to_value(
            &expected_inrou_public_discovery(deployment)
                .expect("exact discovery fixture")
                .response,
        )
        .expect("serialize exact discovery authority fixture")
    }
    fn exact_inrou_discovery_document_response(deployment: &InrouProbeIdentity) -> MockResponse {
        let expected =
            expected_inrou_public_discovery(deployment).expect("exact discovery document fixture");
        let etag = format!("\"{}\"", expected.response.discovery.document_hash);
        MockResponse {
            status: 200,
            content_type: INROU_PUBLIC_DISCOVERY_CONTENT_TYPE,
            headers: vec![
                (
                    INROU_PUBLIC_DISCOVERY_CONTENT_CID_HEADER,
                    deployment.discovery_content_cid.clone(),
                ),
                (
                    reqwest::header::CACHE_CONTROL.as_str(),
                    INROU_PUBLIC_DISCOVERY_CACHE_CONTROL.to_owned(),
                ),
                (reqwest::header::ETAG.as_str(), etag),
                ("x-content-type-options", "nosniff".to_owned()),
            ],
            body: expected.document_bytes,
        }
    }

    fn inrou_public_discovery_http_client() -> HttpClient {
        HttpClient::builder()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build exact public-discovery client")
    }
    fn inrou_discovery_mock_response(
        request: &MockRequest,
        deployment: &InrouProbeIdentity,
    ) -> Option<MockResponse> {
        let path = path_only(&request.path);
        let current_path = format!(
            "/v1/soracloud/services/{}/public-discovery",
            deployment.service_name
        );
        let revision_path = format!(
            "/v1/soracloud/services/{}/revisions/{}/public-discovery",
            deployment.service_name, deployment.service_version
        );
        if path == current_path || path == revision_path {
            return Some(MockResponse::json(
                200,
                exact_inrou_discovery_authority(deployment),
            ));
        }
        let path_gateway = format!(
            "/sorafs/cid/{}/index.json",
            deployment.discovery_content_cid
        );
        if path == path_gateway {
            assert_eq!(
                request.header_values("host"),
                vec![deployment.route_host.as_str()]
            );
            return Some(exact_inrou_discovery_document_response(deployment));
        }
        if path == "/index.json" {
            let expected_host =
                format!("{}.sorafs.taira.sora.org", deployment.discovery_content_cid);
            assert_eq!(request.header_values("host"), vec![expected_host.as_str()]);
            return Some(exact_inrou_discovery_document_response(deployment));
        }
        None
    }
    fn inrou_canary_artifact_version(seed: u8) -> String {
        format!("artifact-{}", Hash::new(&[seed; 32]))
    }

    #[test]
    fn inrou_public_discovery_authority_encodes_identity_segments() {
        let current =
            inrou_public_discovery_authority_url("https://taira.sora.org", "service/name", None)
                .expect("encode current discovery identity");
        assert_eq!(
            current.as_str(),
            "https://taira.sora.org/v1/soracloud/services/service%2Fname/public-discovery"
        );

        let revision = inrou_public_discovery_authority_url(
            "https://taira.sora.org",
            "service/name",
            Some("artifact/revision?selected"),
        )
        .expect("encode revision discovery identity");
        assert_eq!(
            revision.as_str(),
            "https://taira.sora.org/v1/soracloud/services/service%2Fname/revisions/artifact%2Frevision%3Fselected/public-discovery"
        );
    }

    #[test]
    fn inrou_public_discovery_rejects_missing_duplicate_or_substituted_etag() {
        let service_version = inrou_canary_artifact_version(0x2A);
        let deployment = inrou_canary_deployment("deploy", &service_version);
        let expected = expected_inrou_public_discovery(&deployment)
            .expect("build exact public-discovery expectation");
        for variant in ["missing", "duplicate", "substituted"] {
            let server_deployment = deployment.clone();
            let server = spawn_mock_http(1, move |_request| {
                let mut response = exact_inrou_discovery_document_response(&server_deployment);
                let etag_index = response
                    .headers
                    .iter()
                    .position(|(name, _)| name.eq_ignore_ascii_case(reqwest::header::ETAG.as_str()))
                    .expect("exact fixture has ETag");
                match variant {
                    "missing" => {
                        response.headers.remove(etag_index);
                    }
                    "duplicate" => {
                        let duplicate = response.headers[etag_index].1.clone();
                        response
                            .headers
                            .push((reqwest::header::ETAG.as_str(), duplicate));
                    }
                    "substituted" => {
                        response.headers[etag_index].1 = format!("\"{}\"", Hash::new(b"other"));
                    }
                    _ => unreachable!("bounded test variant"),
                }
                response
            });
            let error = fetch_exact_inrou_public_discovery_document(
                &inrou_public_discovery_http_client(),
                &server.base_url,
                &deployment.public_discovery_url,
                &deployment.route_host,
                &deployment.discovery_content_cid,
                &expected.response.discovery.document_hash,
                &expected.document_bytes,
                "test Taira Inrou discovery document",
                Instant::now() + Duration::from_secs(12),
            )
            .expect_err("non-exact ETag must fail closed");
            assert!(
                error.to_string().contains("`etag` header"),
                "unexpected {variant} ETag error: {error:#}"
            );
            assert_eq!(finish_mock(server).len(), 1);
        }
    }

    #[test]
    fn inrou_public_discovery_does_not_follow_redirects() {
        let service_version = inrou_canary_artifact_version(0x2B);
        let deployment = inrou_canary_deployment("deploy", &service_version);
        let expected = expected_inrou_public_discovery(&deployment)
            .expect("build exact public-discovery expectation");
        let server = spawn_mock_http(1, |_request| MockResponse {
            status: 307,
            content_type: "text/plain",
            headers: vec![(
                reqwest::header::LOCATION.as_str(),
                "https://attacker.invalid/substituted".to_owned(),
            )],
            body: Vec::new(),
        });
        let error = fetch_exact_inrou_public_discovery_document(
            &inrou_public_discovery_http_client(),
            &server.base_url,
            &deployment.public_discovery_url,
            &deployment.route_host,
            &deployment.discovery_content_cid,
            &expected.response.discovery.document_hash,
            &expected.document_bytes,
            "test Taira Inrou discovery document",
            Instant::now() + Duration::from_secs(12),
        )
        .expect_err("public discovery redirects must fail closed");
        assert!(
            error.to_string().contains("redirects are not accepted"),
            "unexpected redirect error: {error:#}"
        );
        assert_eq!(finish_mock(server).len(), 1);
    }

    #[test]
    fn inrou_public_discovery_expired_deadline_never_dispatches() {
        let _fixture = mock_http_fixture_guard();
        let service_version = inrou_canary_artifact_version(0x2B);
        let deployment = inrou_canary_deployment("deploy", &service_version);
        let expected = expected_inrou_public_discovery(&deployment).unwrap();
        let server = spawn_mock_http(1, |_| panic!("expired discovery must not reach HTTP"));
        let http = inrou_public_discovery_http_client();
        let deadline = Instant::now();
        let authority_url =
            inrou_public_discovery_authority_url(&server.base_url, &deployment.service_name, None)
                .unwrap();
        let error = fetch_inrou_public_discovery_authority(
            &http,
            authority_url,
            &expected.response,
            "expired authority",
            deadline,
        )
        .expect_err("expired authority must fail before dispatch");
        assert!(error.to_string().contains("verification deadline elapsed"));
        let error = fetch_exact_inrou_public_discovery_document(
            &http,
            &server.base_url,
            &deployment.public_discovery_url,
            &deployment.route_host,
            &deployment.discovery_content_cid,
            &expected.response.discovery.document_hash,
            &expected.document_bytes,
            "expired document",
            deadline,
        )
        .expect_err("expired document must fail before dispatch");
        assert!(error.to_string().contains("verification deadline elapsed"));
        assert!(finish_mock(server).is_empty());
    }

    #[test]
    fn inrou_probe_expired_deadline_never_dispatches() {
        let _fixture = mock_http_fixture_guard();
        let _chain = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        let service_version = inrou_canary_artifact_version(0x2B);
        let deployment = inrou_canary_deployment("deploy", &service_version);
        let server = spawn_mock_http(1, |_| panic!("expired probe must not reach HTTP"));
        let mut config = crate::fallback_config();
        config.torii_api_url = Url::parse(&server.base_url).unwrap();
        let status_client = IrohaClient::builder(config).build().unwrap();
        let observation = probe_inrou_service(
            &server.base_url,
            &status_client,
            &deployment,
            Instant::now(),
            InrouProbeScope::Candidate,
        )
        .unwrap();
        assert!(!observation.failures.is_empty());
        assert_eq!(observation.replica_identities.as_array().unwrap().len(), 0);
        assert!(
            observation
                .checks
                .iter()
                .all(|check| check.get("ok").and_then(Value::as_bool) == Some(false))
        );
        assert!(finish_mock(server).is_empty());
    }

    #[test]
    fn retained_stage_discovery_bytes_bind_encoded_deployment_bundle() {
        let _chain_discriminant = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        let temp = tempfile::Builder::new()
            .prefix(".taira-retained-stage-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("create retained-stage fixture directory under a real owner path");
        let kernel = temp.path().join("kernel.source");
        let rootfs = temp.path().join("rootfs.source");
        let initrd = temp.path().join("initrd.source");
        fs::write(&kernel, b"aarch64-kernel").expect("write kernel fixture");
        fs::write(&rootfs, b"aarch64-rootfs").expect("write rootfs fixture");
        fs::write(&initrd, b"aarch64-initrd").expect("write initrd fixture");
        let workspace = temp.path().join("workspace");
        crate::soracloud::create_taira_inrou_canary_workspace(
            &kernel, &rootfs, &initrd, &workspace,
        )
        .expect("create canonical Taira Inrou workspace");

        let placement_targets = (0_u8..4)
            .map(|offset| {
                let key = fixture_key_pair(0x70 + offset);
                iroha::data_model::soracloud::SoraInrouPlacementTargetV1 {
                    validator_account_id: AccountId::new(key.public_key().clone()),
                    peer_id: key.public_key().to_string(),
                }
            })
            .collect::<BTreeSet<_>>();
        let stage_dir = temp.path().join("stage");
        let stage_key = fixture_key_pair(0x74);
        crate::soracloud::stage_taira_inrou_canary_deployment(
            InrouCanaryMode::Deploy,
            &workspace.join("container_manifest.json"),
            &workspace.join("service_manifest.json"),
            &workspace.join("bundle.tgz"),
            &stage_dir,
            &stage_key,
            NonZeroU64::new(2_000_000_000).expect("positive retention epoch"),
            placement_targets,
        )
        .expect("stage canonical Taira Inrou deployment");

        let mut config = crate::fallback_config();
        config.key_pair = stage_key;
        let stage = crate::soracloud::load_taira_inrou_stage_identity(
            &config,
            &stage_dir,
            InrouCanaryMode::Deploy,
        )
        .expect("fully revalidate retained Taira Inrou stage");
        let expected = expected_inrou_public_discovery(&InrouProbeIdentity::from(&stage))
            .expect("derive exact public discovery from retained stage");
        let staged_document = fs::read(stage_dir.join("payloads/discovery/index.json"))
            .expect("read retained discovery document");
        assert_eq!(expected.document_bytes, staged_document);
        assert_eq!(
            expected.response.discovery.document_hash.to_string(),
            stage.discovery_document_hash
        );
        assert_eq!(
            expected
                .response
                .discovery
                .deployment_bundle_hash
                .to_string(),
            stage.deployment_bundle_hash
        );
        assert_ne!(stage.bundle_hash, stage.deployment_bundle_hash);
    }
    fn exact_inrou_health_response(version: &str, replica_slot: u64) -> Value {
        norito::json!({
            "schema_version": 1,
            "service": "taira_inrou_canary",
            "service_version": version,
            "runtime": "Inrou",
            "replica_slot": replica_slot,
            "identity": (format!("taira_inrou_canary:replica:{replica_slot}")),
            "app_data_marker_sha256": (format!("{replica_slot:x}").repeat(64)),
            "boot_sequence": 1,
            "guest_boot_id_sha256": (format!("{:x}", replica_slot + 4).repeat(64))
        })
    }
    fn exact_inrou_runtime_snapshot(
        version: &str,
        process_generation: u64,
        observed_block_hash: &str,
    ) -> Value {
        use iroha::data_model::soracloud::{
            SoraContainerRuntimeV1, SoraInrouGuestIsaV1, SoraInrouReplicaHostAvailabilityV1,
            SoraServiceExecutionPlaneV1, SoraServiceHealthStatusV1,
        };
        use iroha_core::soracloud_runtime::{
            SoracloudRuntimeInrouPlan, SoracloudRuntimeReplicaPlan, SoracloudRuntimeRevisionRole,
            SoracloudRuntimeServicePlan, SoracloudRuntimeSnapshot,
        };
        let validator_key_pair = fixture_key_pair(0x91);
        let peer_id = validator_key_pair.public_key().to_string();
        let validator_account_id =
            AccountId::new(validator_key_pair.public_key().clone()).to_string();
        let plan = SoracloudRuntimeServicePlan {
            service_name: "taira_inrou_canary".to_owned(),
            service_version: version.to_owned(),
            role: SoracloudRuntimeRevisionRole::Active,
            traffic_percent: 100,
            runtime: SoraContainerRuntimeV1::Inrou,
            execution_plane: SoraServiceExecutionPlaneV1::HttpService,
            bundle_hash: Hash::new(b"taira-test-bundle").to_string(),
            bundle_path: "/app/server.py".to_owned(),
            entrypoint: "/app/server.py".to_owned(),
            inrou: Some(SoracloudRuntimeInrouPlan {
                selected_guest_isa: SoraInrouGuestIsaV1::Aarch64,
                kernel_image_path: "/inrou/aarch64/vmlinux".to_owned(),
                rootfs_image_path: "/inrou/aarch64/rootfs.ext4".to_owned(),
                initrd_image_path: Some("/inrou/aarch64/initrd.img".to_owned()),
                root_volume_name: "root_disk".to_owned(),
            }),
            bundle_cache_path: "/runtime/cache/taira-inrou".to_owned(),
            bundle_available_locally: true,
            process_generation: Some(process_generation),
            desired_replica_count: 4,
            local_replica_slots: vec![2],
            local_replicas: vec![SoracloudRuntimeReplicaPlan {
                replica_slot: 2,
                lease_started_height: 1,
                placement_incarnation: Hash::new(b"taira-test-placement").to_string(),
                host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
                validator_account_id,
                peer_id: peer_id.clone(),
                materialization_dir: "/runtime/taira-inrou/replica-0002".to_owned(),
                health_status: SoraServiceHealthStatusV1::Healthy,
                listen_base_url: Some("http://127.0.0.1:18082".to_owned()),
                pid: Some(1234),
                last_error: None,
            }],
            health_status: SoraServiceHealthStatusV1::Healthy,
            load_factor_bps: 0,
            authoritative_pending_mailbox_messages: 0,
            rollout_handle: None,
            config_generation: 0,
            secret_generation: 0,
            quota_class: None,
            service_lease_status: None,
            lease_expires_height: None,
            remaining_runtime_balance: None,
            config_entry_count: 2,
            secret_entry_count: 0,
            config_exports: Vec::new(),
            supports_host_read_config: false,
            supports_host_read_secret_envelope: false,
            materialization_dir: "/runtime/taira-inrou".to_owned(),
            config_materialization_dir: "/runtime/taira-inrou/config".to_owned(),
            effective_env: BTreeMap::new(),
            effective_env_materialization_path: "/runtime/taira-inrou/env.json".to_owned(),
            config_exports_materialization_dir: "/runtime/taira-inrou/exports".to_owned(),
            secret_envelopes_materialization_dir: "/runtime/taira-inrou/secrets".to_owned(),
            lease_volumes: Vec::new(),
            mailboxes: Vec::new(),
            artifacts: Vec::new(),
        };
        json::to_value(&SoracloudRuntimeSnapshot {
            schema_version: 1,
            observed_height: 1,
            observed_block_hash: Some(observed_block_hash.to_owned()),
            local_peer_id: Some(peer_id),
            services: BTreeMap::from([(
                "taira_inrou_canary".to_owned(),
                BTreeMap::from([(version.to_owned(), plan)]),
            )]),
            apartments: BTreeMap::new(),
        })
        .expect("serialize exact local Inrou runtime snapshot")
    }
    fn exact_service_lease_snapshot(service_version: &str) -> Value {
        use iroha::data_model::soracloud::{
            SORA_SERVICE_LEASE_REPORTER_ASSIGNMENT_VERSION_V1, SORA_SERVICE_LEASE_STATE_VERSION_V1,
            SoraInrouGuestIsaV1, SoraInrouReplicaHostAvailabilityV1, SoraInrouReplicaPlacementV1,
            SoraServiceLeaseClockV1, SoraServiceLeaseEgressCheckpointV1,
            SoraServiceLeaseReporterAssignmentV1, SoraServiceLeaseStateV1,
            SoraServiceLeaseStatusV1,
        };

        let validator_key_pair = fixture_key_pair(0x96);
        let validator_account_id = AccountId::new(validator_key_pair.public_key().clone());
        let lease = SoraServiceLeaseStateV1 {
            schema_version: SORA_SERVICE_LEASE_STATE_VERSION_V1,
            economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
            status: SoraServiceLeaseStatusV1::Active,
            quota_class: "taira-open".to_owned(),
            replica_count: std::num::NonZeroU16::new(4).expect("nonzero replica count"),
            deployment_deposit: "1".parse().expect("deployment deposit"),
            prepaid_runtime_balance: "50".parse().expect("prepaid balance"),
            runtime_price_per_block: "0.00025".parse().expect("runtime price"),
            storage_price_per_gib_block: "0.000025".parse().expect("storage price"),
            egress_price_per_mib: "0.000005".parse().expect("egress price"),
            lease_started_height: 1,
            lease_expires_height: 100,
            reporting_epoch: 1,
            settled_egress_bytes: 1_024,
            egress_reporter_checkpoints: vec![SoraServiceLeaseEgressCheckpointV1 {
                reporting_epoch: 1,
                assignment: SoraServiceLeaseReporterAssignmentV1 {
                    schema_version: SORA_SERVICE_LEASE_REPORTER_ASSIGNMENT_VERSION_V1,
                    service_version: service_version.to_owned(),
                    placement: SoraInrouReplicaPlacementV1 {
                        replica_slot: 2,
                        economic_clock: SoraServiceLeaseClockV1::CanonicalBlockHeight,
                        lease_started_height: 1,
                        placement_incarnation: Hash::new(b"taira-status-lease-placement"),
                        host_availability: SoraInrouReplicaHostAvailabilityV1::Available,
                        validator_account_id,
                        peer_id: validator_key_pair.public_key().to_string(),
                        selected_guest_isa: SoraInrouGuestIsaV1::Aarch64,
                    },
                    placement_reconciled_at_ms: 1,
                },
                accounted_egress_bytes: 256,
                last_updated_height: 1,
                finalize_reporter: false,
            }],
            accounted_egress_bytes: 1_280,
            last_status_reason: None,
        };
        lease.validate().expect("exact service lease fixture");
        let remaining_runtime_balance: Quantity =
            "49.99975".parse().expect("remaining runtime balance");
        norito::json!({
            "authoritative_state": (json::to_value(&lease).expect("serialize service lease")),
            "effective_status": (json::to_value(&SoraServiceLeaseStatusV1::Active)
                .expect("serialize effective lease status")),
            "remaining_runtime_balance": (json::to_value(&remaining_runtime_balance)
                .expect("serialize remaining runtime balance"))
        })
    }
    fn exact_inrou_status(version: &str, action: &str, revision_count: u64) -> Value {
        let observed_block_hash = Hash::new(b"taira-test-observed-block").to_string();
        let validator_signer = fixture_key_pair(0x96).public_key().to_string();
        let discovery = inrou_canary_deployment("deploy", version);
        let (audit_from_version, audit_rollout_state) = if action == "Upgrade" {
            let baseline_version = format!("{version}-baseline");
            (
                Value::from(baseline_version.clone()),
                norito::json!({
                    "rollout_handle": (format!(
                        "taira_inrou_canary:rollout:{revision_count}"
                    )),
                    "baseline_version": baseline_version,
                    "candidate_version": version,
                    "canary_percent": 100,
                    "traffic_percent": 100,
                    "stage": {"stage": "Promoted", "value": null},
                    "health_failures": 0,
                    "max_health_failures": 3,
                    "health_window_secs": 30,
                    "created_sequence": revision_count,
                    "updated_sequence": revision_count
                }),
            )
        } else {
            (Value::Null, Value::Null)
        };
        norito::json!({
            "schema_version": 1,
            "service_health": {
                "mode": "embedded_runtime_manager",
                "status": "healthy",
                "message": "embedded runtime manager reports healthy hosted workloads",
                "observed_height": 1,
                "observed_block_hash": (observed_block_hash.clone()),
                "state_dir": "/tmp/taira-inrou-runtime",
                "service_revisions": 1,
                "healthy_service_revisions": 1,
                "hydrating_service_revisions": 0,
                "degraded_service_revisions": 0,
                "unavailable_service_revisions": 0,
                "apartments": 0,
                "running_apartments": 0,
                "expired_apartments": 0
            },
            "routing": {
                "configured_lane_count": 1,
                "declared_lane_count": 1,
                "active_lane_count": 1,
                "active_lane_ids": [0],
                "autoscale_capacity_lane_count": 1,
                "autoscale_capacity_lane_ids": [0],
                "dataspace_count": 1,
                "routing_rules": 0,
                "default_lane_id": 0,
                "default_dataspace_id": 0
            },
            "hosted_http_topology": {
                "active_capability_adverts": 4,
                "placed_host_count": 4,
                "hosted_replica_count": 4,
                "unavailable_replica_count": 0
            },
            "resource_pressure": {
                "queue_active": 0,
                "queue_queued": 0,
                "queue_capacity": 1024,
                "queue_saturated": false,
                "high_load_threshold": 1024,
                "high_load": false,
                "runtime": {
                    "enabled": true,
                    "state_dir": "/tmp/taira-inrou-runtime",
                    "observed_height": 1,
                    "service_revisions": 1,
                    "apartments": 0,
                    "max_load_factor_bps": 0,
                    "authoritative_pending_mailbox_messages": 0,
                    "bundle_cache_misses": 0,
                    "artifact_cache_misses": 0
                }
            },
            "failed_admissions": {
                "available": true,
                "total": 0,
                "governance_manifest_rejected": 0,
                "sorafs_provider_rejected": 0
            },
            "runtime_manager": {
                "available": true,
                "state_dir": "/tmp/taira-inrou-runtime",
                "snapshot": (exact_inrou_runtime_snapshot(
                    version,
                    revision_count,
                    &observed_block_hash,
                ))
            },
            "control_plane": {
                "schema_version": 1,
                "service_count": 1,
                "audit_event_count": 1,
                "services": [{
                    "service_name": "taira_inrou_canary",
                    "current_version": version,
                    "revision_count": revision_count,
                    "config_generation": 0,
                    "secret_generation": 0,
                    "config_entry_count": 2,
                    "secret_entry_count": 0,
                    "service_lease": (exact_service_lease_snapshot(version)),
                    "public_discovery_content_cid": (discovery.discovery_content_cid.clone()),
                    "public_discovery_url": (discovery.public_discovery_url.clone()),
                    "public_discovery_cid_host_url": (discovery.public_discovery_cid_host_url.clone()),
                    "active_rollout": null,
                    "last_rollout": null,
                    "latest_revision": {
                        "sequence": revision_count,
                        "action": { "action": action, "value": null },
                        "service_version": version,
                        "container_manifest_hash": (Hash::new(b"taira-test-container-manifest")),
                        "service_manifest_hash": (Hash::new(b"taira-test-service-manifest")),
                        "replicas": 4,
                        "execution_plane": {
                            "execution_plane": "HttpService",
                            "value": null
                        },
                        "route_host": "taira.sora.org",
                        "route_path_prefix": "/api/v1/inrou-canary",
                        "route_service_port": 8787,
                        "route_visibility": "Public",
                        "route_tls_mode": "Required",
                        "base_url": "https://taira.sora.org/api/v1/inrou-canary/",
                        "healthcheck_url": "https://taira.sora.org/api/v1/inrou-canary/health",
                        "public_discovery_content_cid": (discovery.discovery_content_cid.clone()),
                        "public_discovery_url": (discovery.public_discovery_url.clone()),
                        "public_discovery_cid_host_url": (discovery.public_discovery_cid_host_url.clone()),
                        "state_binding_count": 0,
                        "state_bindings": [],
                        "lease_volumes": [],
                        "allow_model_inference": false,
                        "allow_model_training": false,
                        "runtime": { "runtime": "Inrou", "value": null },
                        "allow_state_writes": false,
                        "network": { "mode": "Open", "value": null },
                        "cpu_millis": 1000,
                        "memory_bytes": 1073741824,
                        "ephemeral_storage_bytes": 1073741824,
                        "max_open_files_per_process": 1024,
                        "max_tasks": 64,
                        "start_grace_secs": 30,
                        "stop_grace_secs": 30,
                        "healthcheck_path": "/health",
                        "required_config_names": [],
                        "required_secret_names": [],
                        "config_exports": [],
                        "sandbox_profile_hash": (Hash::new(b"taira-test-sandbox-profile")),
                        "process_generation": revision_count,
                        "process_started_sequence": revision_count,
                        "signed_by": (validator_signer.clone())
                    }
                }],
                "recent_audit_events": [{
                    "sequence": revision_count,
                    "action": { "action": action, "value": null },
                    "service_name": "taira_inrou_canary",
                    "from_version": audit_from_version,
                    "to_version": version,
                    "service_manifest_hash": (Hash::new(b"taira-test-service-manifest")),
                    "container_manifest_hash": (Hash::new(b"taira-test-container-manifest")),
                    "process_generation": revision_count,
                    "config_generation": 0,
                    "secret_generation": 0,
                    "config_snapshot_hash": (Hash::new(b"taira-test-config-snapshot")),
                    "secret_snapshot_hash": (Hash::new(b"taira-test-secret-snapshot")),
                    "binding_name": null,
                    "state_key": null,
                    "config_mutations": [],
                    "secret_mutations": [],
                    "governance_tx_hash": null,
                    "rollout_state": audit_rollout_state,
                    "policy_name": null,
                    "policy_snapshot_hash": null,
                    "jurisdiction_tag": null,
                    "consent_evidence_hash": null,
                    "break_glass": null,
                    "break_glass_reason": null,
                    "lease_usage": null,
                    "service_lease_commitment": null,
                    "lease_reporting_epoch_rollover": null,
                    "signed_by": validator_signer
                }]
            }
        })
    }
    #[test]
    fn exact_inrou_status_requires_distinct_promoted_upgrade() {
        let deployed_version = inrou_canary_artifact_version(0x11);
        let upgraded_version = inrou_canary_artifact_version(0x22);
        let deploy = inrou_canary_deployment("deploy", &deployed_version);
        let deploy_status = exact_inrou_status(&deployed_version, "Deploy", 1);
        assert!(validate_exact_inrou_canary_status(&deploy_status, &deploy).is_ok());
        let mut missing_schema = deploy_status.clone();
        missing_schema
            .as_object_mut()
            .expect("status fixture is an object")
            .remove("schema_version");
        assert!(validate_exact_inrou_canary_status(&missing_schema, &deploy).is_err());
        for missing_field in [
            "active_capability_adverts",
            "placed_host_count",
            "hosted_replica_count",
            "unavailable_replica_count",
        ] {
            let mut missing = deploy_status.clone();
            missing
                .pointer_mut("/hosted_http_topology")
                .and_then(Value::as_object_mut)
                .expect("status fixture has hosted topology")
                .remove(missing_field);
            assert!(
                validate_exact_inrou_canary_status(&missing, &deploy).is_err(),
                "missing {missing_field} must fail closed"
            );
        }
        let mut duplicate_service = deploy_status.clone();
        let services = duplicate_service
            .pointer_mut("/control_plane/services")
            .and_then(Value::as_array_mut)
            .expect("status fixture has services");
        let duplicate = services[0].clone();
        services.push(duplicate);
        assert!(
            validate_exact_inrou_canary_status(&duplicate_service, &deploy).is_err(),
            "duplicate authoritative service rows must fail closed"
        );
        for missing_field in ["active_rollout", "last_rollout"] {
            let mut missing = deploy_status.clone();
            missing
                .pointer_mut("/control_plane/services/0")
                .and_then(Value::as_object_mut)
                .expect("status fixture has one service")
                .remove(missing_field);
            assert!(
                validate_exact_inrou_canary_status(&missing, &deploy).is_err(),
                "missing {missing_field} must fail closed"
            );
        }
        let mut missing_revision_version = deploy_status.clone();
        missing_revision_version
            .pointer_mut("/control_plane/services/0/latest_revision")
            .and_then(Value::as_object_mut)
            .expect("status fixture has a latest revision")
            .remove("service_version");
        assert!(
            validate_exact_inrou_canary_status(&missing_revision_version, &deploy).is_err(),
            "latest revision must carry its exact service version"
        );
        for hash_field in ["container_manifest_hash", "service_manifest_hash"] {
            let mut mismatched = deploy_status.clone();
            *mismatched
                .pointer_mut(&format!(
                    "/control_plane/services/0/latest_revision/{hash_field}"
                ))
                .expect("status fixture has manifest hashes") = Value::from("foreign-hash");
            assert!(
                validate_exact_inrou_canary_status(&mismatched, &deploy).is_err(),
                "a live {hash_field} mismatch must fail closed"
            );
        }
        for (field, invalid) in [
            ("route_service_port", Value::from(8_788_u64)),
            ("route_visibility", Value::from("Internal")),
            ("route_tls_mode", Value::from("Optional")),
        ] {
            let mut mismatched = deploy_status.clone();
            *mismatched
                .pointer_mut(&format!(
                    "/control_plane/services/0/latest_revision/{field}"
                ))
                .expect("status fixture has the complete route projection") = invalid;
            assert!(
                validate_exact_inrou_canary_status(&mismatched, &deploy).is_err(),
                "the fixed Inrou canary route must reject a mismatched {field}"
            );
        }
        for (path, retired) in [
            ("/control_plane/services/0/latest_revision/action", "Deploy"),
            ("/control_plane/services/0/latest_revision/runtime", "Inrou"),
            (
                "/control_plane/services/0/latest_revision/execution_plane",
                "HttpService",
            ),
        ] {
            let mut bare = deploy_status.clone();
            *bare
                .pointer_mut(path)
                .expect("status fixture has a tagged enum") = Value::from(retired);
            assert!(
                validate_exact_inrou_canary_status(&bare, &deploy).is_err(),
                "bare-string enum at {path} must fail closed"
            );
        }
        let mismatched_deploy = inrou_canary_deployment("deploy", "1.0.0");
        let mismatched_deploy_status = exact_inrou_status("1.0.0", "Deploy", 1);
        assert!(
            validate_exact_inrou_canary_status(&mismatched_deploy_status, &mismatched_deploy)
                .is_err()
        );

        let upgrade = inrou_canary_deployment("upgrade", &upgraded_version);
        let mut upgrade_status = exact_inrou_status(&upgraded_version, "Upgrade", 3);
        upgrade_status
            .pointer_mut("/control_plane/services/0")
            .and_then(Value::as_object_mut)
            .expect("status fixture has one service")
            .insert(
                "last_rollout".to_owned(),
                norito::json!({
                    "rollout_handle": "taira-inrou-upgrade",
                    "baseline_version": (deployed_version.clone()),
                    "candidate_version": (upgraded_version.clone()),
                    "canary_percent": 100,
                    "traffic_percent": 100,
                    "stage": { "stage": "Promoted", "value": null },
                    "health_failures": 0,
                    "max_health_failures": 3,
                    "health_window_secs": 30,
                    "created_sequence": 1,
                    "updated_sequence": 2
                }),
            );
        assert!(validate_exact_inrou_canary_status(&upgrade_status, &upgrade).is_ok());

        let mut bare_stage = upgrade_status.clone();
        *bare_stage
            .pointer_mut("/control_plane/services/0/last_rollout/stage")
            .expect("status fixture has a rollout stage") = Value::from("Promoted");
        assert!(
            validate_exact_inrou_canary_status(&bare_stage, &upgrade).is_err(),
            "bare-string rollout stage must fail closed"
        );

        let mut stale = upgrade_status.clone();
        *stale
            .pointer_mut("/control_plane/services/0/last_rollout/candidate_version")
            .expect("status fixture has a rollout candidate") =
            Value::from(deployed_version.clone());
        assert!(validate_exact_inrou_canary_status(&stale, &upgrade).is_err());
        for field in ["rollout_handle", "updated_sequence"] {
            let mut missing = upgrade_status.clone();
            missing
                .pointer_mut("/control_plane/services/0/last_rollout")
                .and_then(Value::as_object_mut)
                .expect("status fixture has a rollout")
                .remove(field);
            assert!(
                validate_exact_inrou_canary_status(&missing, &upgrade).is_err(),
                "missing rollout field {field} must fail closed"
            );
        }
        let mut extra_rollout = upgrade_status.clone();
        extra_rollout
            .pointer_mut("/control_plane/services/0/last_rollout")
            .and_then(Value::as_object_mut)
            .expect("status fixture has a rollout")
            .insert("retired_v0".to_owned(), Value::from(true));
        assert!(validate_exact_inrou_canary_status(&extra_rollout, &upgrade).is_err());
        let mut extra_host = upgrade_status.clone();
        *extra_host
            .pointer_mut("/hosted_http_topology/active_capability_adverts")
            .expect("status fixture has an advert count") = Value::from(5_u64);
        assert!(validate_exact_inrou_canary_status(&extra_host, &upgrade).is_err());
        for (field, invalid) in [
            ("placed_host_count", 3_u64),
            ("unavailable_replica_count", 1_u64),
        ] {
            let mut unavailable = upgrade_status.clone();
            *unavailable
                .pointer_mut(&format!("/hosted_http_topology/{field}"))
                .expect("status fixture has an exact topology count") = Value::from(invalid);
            assert!(
                validate_exact_inrou_canary_status(&unavailable, &upgrade).is_err(),
                "noncanonical topology count {field}={invalid} must fail closed"
            );
        }
    }
    #[test]
    fn exact_inrou_status_requires_one_canonical_local_placement() {
        let version = inrou_canary_artifact_version(0x31);
        let deployment = inrou_canary_deployment("deploy", &version);
        let status = exact_inrou_status(&version, "Deploy", 1);
        let (_, _, placement) = validate_exact_inrou_canary_status(&status, &deployment)
            .expect("exact status contains one local healthy placement");
        assert_eq!(placement.replica_slot, 2);
        assert_eq!(
            placement.peer_id,
            fixture_key_pair(0x91).public_key().to_string()
        );
        assert_eq!(
            placement.validator_account_id,
            AccountId::new(fixture_key_pair(0x91).public_key().clone()).to_string()
        );
        assert_eq!(
            placement.placement_incarnation,
            Hash::new(b"taira-test-placement").to_string()
        );

        let mut mismatched_peer = status.clone();
        *mismatched_peer
            .pointer_mut("/runtime_manager/snapshot/local_peer_id")
            .expect("snapshot has local peer ID") =
            Value::from(fixture_key_pair(0x92).public_key().to_string());
        assert!(
            validate_exact_inrou_canary_status(&mismatched_peer, &deployment).is_err(),
            "local snapshot identity must match the replica placement"
        );

        let placement_path = format!(
            "/runtime_manager/snapshot/services/taira_inrou_canary/{version}/local_replicas/0"
        );
        let plan_path = format!("/runtime_manager/snapshot/services/taira_inrou_canary/{version}");
        let mut mismatched_validator = status.clone();
        *mismatched_validator
            .pointer_mut(&format!("{placement_path}/validator_account_id"))
            .expect("snapshot has local validator account ID") =
            Value::from(AccountId::new(fixture_key_pair(0x93).public_key().clone()).to_string());
        let error = validate_exact_inrou_canary_status(&mismatched_validator, &deployment)
            .expect_err("an account/peer pair absent from the stage must fail closed");
        assert!(
            error.contains("absent from the retained stage allowlist"),
            "mismatched validator identity reported the wrong error: {error}"
        );

        use iroha::data_model::account::{MultisigMember, MultisigPolicy};
        let multisig_validator = AccountId::new_multisig(
            MultisigPolicy::new(
                2,
                vec![
                    MultisigMember::new(fixture_key_pair(0x94).public_key().clone(), 1)
                        .expect("first multisig validator member"),
                    MultisigMember::new(fixture_key_pair(0x95).public_key().clone(), 1)
                        .expect("second multisig validator member"),
                ],
            )
            .expect("multisig validator fixture policy"),
        );
        let mut multisig_validator_status = status.clone();
        *multisig_validator_status
            .pointer_mut(&format!("{placement_path}/validator_account_id"))
            .expect("snapshot has local validator account ID") =
            Value::from(multisig_validator.to_string());
        let error = validate_exact_inrou_canary_status(&multisig_validator_status, &deployment)
            .expect_err("a multisig validator account must fail closed");
        assert!(
            error.contains("validator account must be single-signatory"),
            "multisig validator identity reported the wrong error: {error}"
        );

        let mut sentinel_incarnation = status.clone();
        let mut zero_prehash_sentinel = [0_u8; Hash::LENGTH];
        zero_prehash_sentinel[Hash::LENGTH - 1] = 1;
        *sentinel_incarnation
            .pointer_mut(&format!("{placement_path}/placement_incarnation"))
            .expect("snapshot has local placement incarnation") =
            Value::from(Hash::prehashed(zero_prehash_sentinel).to_string());
        let error = validate_exact_inrou_canary_status(&sentinel_incarnation, &deployment)
            .expect_err("the zero-prehash placement incarnation sentinel must fail closed");
        assert!(
            error.contains("zero prehash sentinel"),
            "zero-prehash placement incarnation reported the wrong error: {error}"
        );

        let mut duplicate = status.clone();
        let replicas = duplicate
            .pointer_mut(&format!(
                "/runtime_manager/snapshot/services/taira_inrou_canary/{version}/local_replicas"
            ))
            .and_then(Value::as_array_mut)
            .expect("snapshot has local replicas");
        replicas.push(replicas[0].clone());
        assert!(
            validate_exact_inrou_canary_status(&duplicate, &deployment).is_err(),
            "more than one local replica must fail closed"
        );

        for (field, value) in [
            (
                "bundle_hash",
                Value::from(Hash::new(b"substituted bundle").to_string()),
            ),
            ("bundle_available_locally", Value::from(false)),
            ("process_generation", Value::from(2_u64)),
            ("bundle_path", Value::from("/app/substituted.py")),
            ("entrypoint", Value::from("/app/substituted.py")),
        ] {
            let mut substituted = status.clone();
            *substituted
                .pointer_mut(&format!("{plan_path}/{field}"))
                .expect("snapshot plan contains bound field") = value;
            assert!(
                validate_exact_inrou_canary_status(&substituted, &deployment).is_err(),
                "substituted local plan field {field} must fail closed"
            );
        }

        let mut zero_authoritative_generation = status.clone();
        *zero_authoritative_generation
            .pointer_mut("/control_plane/services/0/latest_revision/process_generation")
            .expect("control-plane revision has a process generation") = Value::from(0_u64);
        assert!(
            validate_exact_inrou_canary_status(&zero_authoritative_generation, &deployment)
                .is_err(),
            "zero authoritative process generation must fail closed"
        );

        for (field, value) in [
            (
                "selected_guest_isa",
                json::to_value(&iroha::data_model::soracloud::SoraInrouGuestIsaV1::X8664)
                    .expect("serialize substituted guest ISA"),
            ),
            ("kernel_image_path", Value::from("/inrou/aarch64/other")),
            (
                "rootfs_image_path",
                Value::from("/inrou/aarch64/other.ext4"),
            ),
            ("initrd_image_path", Value::Null),
            ("root_volume_name", Value::from("retired_root")),
        ] {
            let mut substituted = status.clone();
            *substituted
                .pointer_mut(&format!("{plan_path}/inrou/{field}"))
                .expect("snapshot Inrou plan contains bound field") = value;
            assert!(
                validate_exact_inrou_canary_status(&substituted, &deployment).is_err(),
                "substituted AArch64 Inrou plan field {field} must fail closed"
            );
        }

        for (field, value) in [
            ("traffic_percent", Value::from(99_u64)),
            ("inrou", Value::Null),
            ("process_generation", Value::Null),
            ("rollout_handle", Value::from("retired-rollout")),
        ] {
            let mut noncanonical = status.clone();
            *noncanonical
                .pointer_mut(&format!(
                    "/runtime_manager/snapshot/services/taira_inrou_canary/{version}/{field}"
                ))
                .expect("snapshot plan contains tested field") = value;
            assert!(
                validate_exact_inrou_canary_status(&noncanonical, &deployment).is_err(),
                "noncanonical local plan field {field} must fail closed"
            );
        }

        let mut extra_revision = status.clone();
        let revisions = extra_revision
            .pointer_mut("/runtime_manager/snapshot/services/taira_inrou_canary")
            .and_then(Value::as_object_mut)
            .expect("snapshot has canary revisions");
        let plan = revisions
            .get(&version)
            .expect("snapshot has retained revision")
            .clone();
        revisions.insert("retired-revision".to_owned(), plan);
        assert!(
            validate_exact_inrou_canary_status(&extra_revision, &deployment).is_err(),
            "more than one local canary revision must fail closed"
        );

        let mut future_snapshot = status.clone();
        *future_snapshot
            .pointer_mut("/runtime_manager/snapshot/schema_version")
            .expect("runtime snapshot has schema version") = Value::from(2_u64);
        assert!(
            validate_exact_inrou_canary_status(&future_snapshot, &deployment).is_err(),
            "non-V1 runtime snapshots must fail closed"
        );

        let mut unknown_snapshot_field = status;
        unknown_snapshot_field
            .pointer_mut("/runtime_manager/snapshot")
            .and_then(Value::as_object_mut)
            .expect("runtime snapshot object")
            .insert("legacy_placement".to_owned(), Value::Null);
        assert!(
            validate_exact_inrou_canary_status(&unknown_snapshot_field, &deployment).is_err(),
            "unknown runtime snapshot fields must fail closed"
        );
    }
    #[test]
    fn doctor_soracloud_status_accepts_only_nested_service_lease_v1() {
        let canonical = exact_inrou_status(&inrou_canary_artifact_version(0x34), "Deploy", 1);
        validate_soracloud_status(Some(&canonical)).expect("exact nested V1 service lease");

        let service = canonical
            .pointer("/control_plane/services/0")
            .and_then(Value::as_object)
            .expect("status fixture has one service");
        for retired in [
            "quota_class",
            "service_lease_status",
            "lease_expires_height",
            "prepaid_runtime_balance",
            "remaining_runtime_balance",
        ] {
            assert!(
                !service.contains_key(retired),
                "fixture must not expose retired flattened field {retired}"
            );
            let mut flattened = canonical.clone();
            flattened
                .pointer_mut("/control_plane/services/0")
                .and_then(Value::as_object_mut)
                .expect("status fixture has one service")
                .insert(retired.to_owned(), Value::Null);
            let error = validate_soracloud_status(Some(&flattened))
                .expect_err("retired flattened lease field must fail closed");
            assert!(
                error.contains(retired),
                "retired field {retired} reported the wrong error: {error}"
            );
        }

        let mut absent = canonical.clone();
        absent
            .pointer_mut("/control_plane/services/0")
            .and_then(Value::as_object_mut)
            .expect("status fixture has one service")
            .remove("service_lease");
        validate_soracloud_status(Some(&absent))
            .expect_err("required nullable service_lease field must not be omitted");

        let mut no_lease = canonical.clone();
        *no_lease
            .pointer_mut("/control_plane/services/0/service_lease")
            .expect("status fixture has a service lease") = Value::Null;
        validate_soracloud_status(Some(&no_lease))
            .expect("the nested service_lease field is explicitly nullable");

        for field in [
            "authoritative_state",
            "effective_status",
            "remaining_runtime_balance",
        ] {
            let mut missing = canonical.clone();
            missing
                .pointer_mut("/control_plane/services/0/service_lease")
                .and_then(Value::as_object_mut)
                .expect("status fixture has a service lease")
                .remove(field);
            validate_soracloud_status(Some(&missing))
                .expect_err("every nested service lease field is required");
        }

        for (path, replacement) in [
            (
                "/control_plane/services/0/service_lease/authoritative_state/schema_version",
                Value::from(2_u64),
            ),
            (
                "/control_plane/services/0/service_lease/authoritative_state/economic_clock",
                Value::from("CanonicalBlockHeight"),
            ),
            (
                "/control_plane/services/0/service_lease/authoritative_state/lease_expires_height",
                Value::from(1_u64),
            ),
            (
                "/control_plane/services/0/service_lease/authoritative_state/egress_reporter_checkpoints/0/reporting_epoch",
                Value::from(2_u64),
            ),
            (
                "/control_plane/services/0/service_lease/authoritative_state/accounted_egress_bytes",
                Value::from(1_279_u64),
            ),
            (
                "/control_plane/services/0/service_lease/authoritative_state/last_status_reason",
                Value::from(""),
            ),
            (
                "/control_plane/services/0/service_lease/effective_status",
                Value::from("Active"),
            ),
            (
                "/control_plane/services/0/service_lease/remaining_runtime_balance",
                Value::from("01"),
            ),
        ] {
            let mut malformed = canonical.clone();
            *malformed
                .pointer_mut(path)
                .unwrap_or_else(|| panic!("status fixture has nested lease field at {path}")) =
                replacement;
            assert!(
                validate_soracloud_status(Some(&malformed)).is_err(),
                "noncanonical nested lease value at {path} must fail closed"
            );
        }
    }
    #[test]
    fn doctor_soracloud_status_accepts_only_current_audit_event_v1() {
        let version = inrou_canary_artifact_version(0x35);
        let canonical = exact_inrou_status(&version, "Deploy", 1);
        validate_soracloud_status(Some(&canonical)).expect("exact current audit event V1");

        let mut read_only_action = canonical.clone();
        *read_only_action
            .pointer_mut("/control_plane/recent_audit_events/0/action")
            .expect("status fixture has an audit action") =
            norito::json!({"action": "CiphertextQuery", "value": null});
        validate_soracloud_status(Some(&read_only_action))
            .expect_err("read-only CiphertextQuery must never be persisted as an audit event");

        let mut missing_config_delta = canonical.clone();
        *missing_config_delta
            .pointer_mut("/control_plane/recent_audit_events/0/action")
            .expect("status fixture has an audit action") =
            norito::json!({"action": "ConfigMutation", "value": null});
        validate_soracloud_status(Some(&missing_config_delta))
            .expect_err("ConfigMutation must carry exactly one authoritative config delta");

        let mut illegal_break_glass = canonical.clone();
        *illegal_break_glass
            .pointer_mut("/control_plane/recent_audit_events/0/break_glass")
            .expect("status fixture has a break-glass field") = Value::from(true);
        *illegal_break_glass
            .pointer_mut("/control_plane/recent_audit_events/0/break_glass_reason")
            .expect("status fixture has a break-glass reason") = Value::from("emergency");
        validate_soracloud_status(Some(&illegal_break_glass))
            .expect_err("break-glass fields must be null outside decryption requests");

        for retired in ["config_name", "secret_name", "rollout_handle"] {
            let mut stale = canonical.clone();
            stale
                .pointer_mut("/control_plane/recent_audit_events/0")
                .and_then(Value::as_object_mut)
                .expect("status fixture has one audit event")
                .insert(retired.to_owned(), Value::Null);
            let error = validate_soracloud_status(Some(&stale))
                .expect_err("retired audit field must fail closed");
            assert!(
                error.contains(retired),
                "retired audit field {retired} reported the wrong error: {error}"
            );
        }
        for current in [
            "process_generation",
            "config_generation",
            "secret_generation",
            "config_snapshot_hash",
            "secret_snapshot_hash",
            "config_mutations",
            "secret_mutations",
            "rollout_state",
            "lease_usage",
            "service_lease_commitment",
        ] {
            let mut missing = canonical.clone();
            missing
                .pointer_mut("/control_plane/recent_audit_events/0")
                .and_then(Value::as_object_mut)
                .expect("status fixture has one audit event")
                .remove(current);
            let error = validate_soracloud_status(Some(&missing))
                .expect_err("current audit field must be required");
            assert!(
                error.contains(current),
                "missing audit field {current} reported the wrong error: {error}"
            );
        }

        let assignment = canonical
            .pointer("/control_plane/services/0/service_lease/authoritative_state/egress_reporter_checkpoints/0/assignment")
            .expect("status fixture has one reporter assignment")
            .clone();
        let mut lease_usage = canonical.clone();
        let event = lease_usage
            .pointer_mut("/control_plane/recent_audit_events/0")
            .and_then(Value::as_object_mut)
            .expect("status fixture has one audit event");
        event.insert(
            "action".to_owned(),
            norito::json!({"action": "LeaseUsage", "value": null}),
        );
        event.insert("from_version".to_owned(), Value::from(version));
        event.insert(
            "lease_usage".to_owned(),
            norito::json!({
                "schema_version": 1,
                "reporting_epoch": 1,
                "assignment": assignment,
                "replica_accounted_egress_bytes": 256,
                "finalize_reporter": false
            }),
        );
        event.insert(
            "service_lease_commitment".to_owned(),
            json::to_value(&Hash::new(b"taira-test-service-lease"))
                .expect("serialize service lease commitment"),
        );
        validate_soracloud_status(Some(&lease_usage))
            .expect("current LeaseUsage audit payload is accepted");

        let mut wrong_reporter = lease_usage.clone();
        *wrong_reporter
            .pointer_mut("/control_plane/recent_audit_events/0/signed_by")
            .expect("lease usage has a signer") =
            Value::from(fixture_key_pair(0x97).public_key().to_string());
        validate_soracloud_status(Some(&wrong_reporter))
            .expect_err("lease-usage reporter and audit signer must be identical");

        let mut lease_fields_on_deploy = lease_usage.clone();
        *lease_fields_on_deploy
            .pointer_mut("/control_plane/recent_audit_events/0/action")
            .expect("lease usage has an action") =
            norito::json!({"action": "Deploy", "value": null});
        *lease_fields_on_deploy
            .pointer_mut("/control_plane/recent_audit_events/0/from_version")
            .expect("lease usage has a from-version field") = Value::Null;
        validate_soracloud_status(Some(&lease_fields_on_deploy))
            .expect_err("lease usage and commitment must be null for Deploy");

        *lease_usage
            .pointer_mut("/control_plane/recent_audit_events/0/lease_usage/schema_version")
            .expect("lease usage has a schema version") = Value::from(2_u64);
        validate_soracloud_status(Some(&lease_usage))
            .expect_err("non-V1 lease usage must fail closed");

        let mut nullable_baseline =
            exact_inrou_status(&inrou_canary_artifact_version(0x36), "Upgrade", 2);
        nullable_baseline
            .pointer_mut("/control_plane/services/0")
            .and_then(Value::as_object_mut)
            .expect("status fixture has one service")
            .insert(
                "last_rollout".to_owned(),
                norito::json!({
                    "rollout_handle": "taira_inrou_canary:rollout:1",
                    "baseline_version": null,
                    "candidate_version": "candidate",
                    "canary_percent": 100,
                    "traffic_percent": 100,
                    "stage": {"stage": "Promoted", "value": null},
                    "health_failures": 0,
                    "max_health_failures": 3,
                    "health_window_secs": 30,
                    "created_sequence": 1,
                    "updated_sequence": 2
                }),
            );
        validate_soracloud_status(Some(&nullable_baseline))
            .expect_err("retired nullable rollout baseline must fail closed");
    }
    #[test]
    fn tagged_enum_name_requires_exact_tagged_unit_envelope() {
        let canonical = norito::json!({"runtime": "Inrou", "value": null});
        assert_eq!(tagged_enum_name(&canonical, "runtime"), Some("Inrou"));
        for retired in [
            Value::from("Inrou"),
            norito::json!({"runtime": "Inrou"}),
            norito::json!({"runtime": "Inrou", "value": {}}),
            norito::json!({"runtime": "Inrou", "value": null, "legacy": true}),
        ] {
            assert_eq!(
                tagged_enum_name(&retired, "runtime"),
                None,
                "noncanonical tagged enum must fail: {retired:?}"
            );
        }
    }
    #[test]
    fn soracloud_hash_requires_the_canonical_norito_literal() {
        let hash = Hash::new(b"canonical Soracloud status hash");
        let canonical = json::to_value(&hash).expect("serialize canonical Hash literal");
        validate_soracloud_hash(&canonical, "fixture hash")
            .expect("canonical Norito Hash literal is accepted");
        let literal = canonical.as_str().expect("canonical Hash JSON is a string");
        let lowercase_literal = literal.to_ascii_lowercase();
        assert_ne!(
            lowercase_literal, literal,
            "fixture must exercise canonical Hash-literal case"
        );
        for invalid in [
            hash.to_string(),
            lowercase_literal,
            format!(" {literal}"),
            format!("{literal} "),
        ] {
            assert!(
                validate_soracloud_hash(&Value::from(invalid.clone()), "fixture hash").is_err(),
                "noncanonical Soracloud hash text must fail closed: {invalid}"
            );
        }

        let bare = hash.to_string();
        validate_soracloud_bare_hash(&Value::from(bare.clone()), "snapshot hash")
            .expect("runtime snapshot hash uses exact Hash display text");
        for invalid in [
            canonical
                .as_str()
                .expect("canonical Hash JSON string")
                .to_owned(),
            bare.to_ascii_uppercase(),
            format!(" {bare}"),
            format!("{bare} "),
        ] {
            assert!(
                validate_soracloud_bare_hash(&Value::from(invalid.clone()), "snapshot hash")
                    .is_err(),
                "noncanonical bare snapshot hash must fail closed: {invalid}"
            );
        }

        let version = inrou_canary_artifact_version(0x33);
        let status = exact_inrou_status(&version, "Deploy", 1);
        validate_soracloud_status(Some(&status))
            .expect("live-shaped non-null bare observed block hashes are valid");
        for path in [
            "/service_health/observed_block_hash",
            "/runtime_manager/snapshot/observed_block_hash",
        ] {
            let mut typed_literal = status.clone();
            *typed_literal
                .pointer_mut(path)
                .expect("status fixture has an observed block hash") = canonical.clone();
            assert!(
                validate_soracloud_status(Some(&typed_literal)).is_err(),
                "string-projected observed block hash must reject typed literal at {path}"
            );
        }
    }
    #[test]
    fn doctor_soracloud_status_rejects_bare_string_enum_aliases() {
        let canonical = exact_inrou_status(&inrou_canary_artifact_version(0x11), "Deploy", 1);
        validate_soracloud_status(Some(&canonical)).expect("canonical tagged status");
        for (path, retired) in [
            ("/control_plane/services/0/latest_revision/runtime", "Inrou"),
            (
                "/control_plane/services/0/latest_revision/execution_plane",
                "HttpService",
            ),
        ] {
            let mut bare = canonical.clone();
            *bare
                .pointer_mut(path)
                .expect("status fixture has a tagged enum") = Value::from(retired);
            assert!(
                validate_soracloud_status(Some(&bare)).is_err(),
                "doctor must reject bare-string enum alias at {path}"
            );
        }
        for field in [
            "active_capability_adverts",
            "placed_host_count",
            "hosted_replica_count",
            "unavailable_replica_count",
        ] {
            let mut missing = canonical.clone();
            missing
                .pointer_mut("/hosted_http_topology")
                .and_then(Value::as_object_mut)
                .expect("status fixture has hosted HTTP topology")
                .remove(field);
            let error = validate_soracloud_status(Some(&missing))
                .expect_err("doctor must reject a missing authoritative topology count");
            assert!(
                error.contains(field),
                "missing {field} reported the wrong error: {error}"
            );
        }
    }
    #[test]
    fn doctor_soracloud_status_rejects_unknown_and_missing_v1_fields() {
        let canonical = exact_inrou_status(&inrou_canary_artifact_version(0x11), "Deploy", 1);
        let mut extra_root = canonical.clone();
        extra_root
            .as_object_mut()
            .expect("status fixture is an object")
            .insert("retired_v0".to_owned(), Value::from(true));
        assert!(
            validate_soracloud_status(Some(&extra_root))
                .expect_err("unknown root field must fail closed")
                .contains("unknown field `retired_v0`")
        );
        for path in [
            "/service_health",
            "/routing",
            "/hosted_http_topology",
            "/resource_pressure",
            "/resource_pressure/runtime",
            "/failed_admissions",
            "/runtime_manager",
            "/runtime_manager/snapshot",
            "/control_plane",
            "/control_plane/services/0",
            "/control_plane/services/0/service_lease",
            "/control_plane/services/0/service_lease/authoritative_state",
            "/control_plane/services/0/service_lease/authoritative_state/egress_reporter_checkpoints/0",
            "/control_plane/services/0/service_lease/authoritative_state/egress_reporter_checkpoints/0/assignment",
            "/control_plane/services/0/service_lease/authoritative_state/egress_reporter_checkpoints/0/assignment/placement",
            "/control_plane/services/0/latest_revision",
            "/control_plane/recent_audit_events/0",
        ] {
            let mut extra = canonical.clone();
            extra
                .pointer_mut(path)
                .and_then(Value::as_object_mut)
                .unwrap_or_else(|| panic!("status fixture has object at {path}"))
                .insert("retired_v0".to_owned(), Value::from(true));
            let error = validate_soracloud_status(Some(&extra))
                .expect_err("unknown nested field must fail closed");
            assert!(
                error.contains("unknown field `retired_v0`"),
                "unknown field at {path} reported the wrong error: {error}"
            );
        }
        for (path, field) in [
            ("", "routing"),
            ("/service_health", "observed_height"),
            ("/routing", "default_lane_id"),
            ("/hosted_http_topology", "placed_host_count"),
            ("/resource_pressure", "runtime"),
            ("/resource_pressure/runtime", "artifact_cache_misses"),
            ("/failed_admissions", "total"),
            ("/runtime_manager", "snapshot"),
            ("/runtime_manager/snapshot", "services"),
            ("/control_plane", "recent_audit_events"),
            ("/control_plane/services/0", "service_lease"),
            (
                "/control_plane/services/0/service_lease",
                "authoritative_state",
            ),
            (
                "/control_plane/services/0/service_lease/authoritative_state",
                "economic_clock",
            ),
            ("/control_plane/services/0/latest_revision", "network"),
            (
                "/control_plane/recent_audit_events/0",
                "lease_reporting_epoch_rollover",
            ),
        ] {
            let mut missing = canonical.clone();
            let object = if path.is_empty() {
                missing.as_object_mut()
            } else {
                missing.pointer_mut(path).and_then(Value::as_object_mut)
            }
            .unwrap_or_else(|| panic!("status fixture has object at {path}"));
            object.remove(field);
            let error = validate_soracloud_status(Some(&missing))
                .expect_err("missing nested field must fail closed");
            assert!(
                error.contains(field),
                "missing {field} at {path} reported the wrong error: {error}"
            );
        }
    }

    #[test]
    fn doctor_soracloud_status_requires_canonical_observed_block_hashes() {
        let canonical = exact_inrou_status(&inrou_canary_artifact_version(0x11), "Deploy", 1);
        for path in [
            "/service_health/observed_block_hash",
            "/runtime_manager/snapshot/observed_block_hash",
        ] {
            let mut present = canonical.clone();
            *present
                .pointer_mut(path)
                .expect("status fixture has observed block hash") =
                Value::from(Hash::new(path.as_bytes()).to_string());
            validate_soracloud_status(Some(&present))
                .expect("canonical observed block hash is accepted");

            for malformed in ["not-a-hash".to_owned(), "10".repeat(32)] {
                let mut invalid = canonical.clone();
                *invalid
                    .pointer_mut(path)
                    .expect("status fixture has observed block hash") = Value::from(malformed);
                validate_soracloud_status(Some(&invalid))
                    .expect_err("noncanonical observed block hash must fail closed");
            }
        }
    }
    #[test]
    fn doctor_soracloud_status_rejects_noncanonical_route_text() {
        let canonical = exact_inrou_status(&inrou_canary_artifact_version(0x11), "Deploy", 1);
        for (field, retired) in [
            ("route_host", " taira.sora.org"),
            ("route_host", "TAIRA-INROU-CANARY.SORA"),
            ("route_path_prefix", " /api/v1"),
            ("route_path_prefix", "/api/v1/"),
            ("route_path_prefix", "/api//v1"),
        ] {
            let mut status = canonical.clone();
            *status
                .pointer_mut(&format!(
                    "/control_plane/services/0/latest_revision/{field}"
                ))
                .expect("status fixture has a route field") = Value::from(retired);
            assert!(
                validate_soracloud_status(Some(&status)).is_err(),
                "noncanonical {field} value {retired:?} must fail closed"
            );
        }
    }
    #[test]
    fn doctor_soracloud_status_accepts_only_current_route_and_pressure_v1() {
        let version = inrou_canary_artifact_version(0x12);
        let canonical = exact_inrou_status(&version, "Deploy", 1);
        validate_soracloud_status(Some(&canonical))
            .expect("live-shaped current route and runtime pressure are valid");

        let runtime_pressure = canonical
            .pointer("/resource_pressure/runtime")
            .and_then(Value::as_object)
            .expect("status fixture has runtime pressure");
        assert!(
            !runtime_pressure.contains_key("reported_pending_mailbox_messages"),
            "the fixture must not preserve the retired reported mailbox counter"
        );
        let mut retired_pressure = canonical.clone();
        retired_pressure
            .pointer_mut("/resource_pressure/runtime")
            .and_then(Value::as_object_mut)
            .expect("status fixture has runtime pressure")
            .insert(
                "reported_pending_mailbox_messages".to_owned(),
                Value::from(0_u64),
            );
        let error = validate_soracloud_status(Some(&retired_pressure))
            .expect_err("retired runtime pressure fields must fail closed");
        assert!(error.contains("reported_pending_mailbox_messages"));
        let mut impossible_pressure = canonical.clone();
        *impossible_pressure
            .pointer_mut("/resource_pressure/runtime/max_load_factor_bps")
            .expect("status fixture has a load factor") = Value::from(10_001_u64);
        validate_soracloud_status(Some(&impossible_pressure))
            .expect_err("runtime load factor must remain in the V1 basis-point domain");

        for field in ["route_service_port", "route_visibility", "route_tls_mode"] {
            let mut missing = canonical.clone();
            missing
                .pointer_mut("/control_plane/services/0/latest_revision")
                .and_then(Value::as_object_mut)
                .expect("status fixture has a latest revision")
                .remove(field);
            let error = validate_soracloud_status(Some(&missing))
                .expect_err("current route projection fields are required");
            assert!(error.contains(field), "wrong missing-field error: {error}");
        }

        for (field, invalid) in [
            ("route_service_port", Value::from(0_u64)),
            ("route_service_port", Value::from(65_536_u64)),
            ("route_service_port", Value::from("8787")),
            ("route_visibility", Value::from("External")),
            ("route_tls_mode", Value::from("TlsRequired")),
            ("route_tls_mode", Value::Null),
        ] {
            let mut malformed = canonical.clone();
            *malformed
                .pointer_mut(&format!(
                    "/control_plane/services/0/latest_revision/{field}"
                ))
                .expect("status fixture has the complete route projection") = invalid;
            assert!(
                validate_soracloud_status(Some(&malformed)).is_err(),
                "invalid {field} must fail closed"
            );
        }

        let mut no_route = canonical;
        for field in [
            "route_host",
            "route_path_prefix",
            "route_service_port",
            "route_visibility",
            "route_tls_mode",
        ] {
            *no_route
                .pointer_mut(&format!(
                    "/control_plane/services/0/latest_revision/{field}"
                ))
                .expect("status fixture has the complete route projection") = Value::Null;
        }
        validate_soracloud_revision(
            no_route
                .pointer("/control_plane/services/0/latest_revision")
                .expect("status fixture has a latest revision"),
            "fixture revision",
        )
        .expect_err("an HttpService revision cannot project an all-null route");
        *no_route
            .pointer_mut("/control_plane/services/0/latest_revision/execution_plane")
            .expect("status fixture has an execution plane") =
            norito::json!({"execution_plane": "DeterministicService", "value": null});
        validate_soracloud_revision(
            no_route
                .pointer("/control_plane/services/0/latest_revision")
                .expect("status fixture has a latest revision"),
            "fixture revision",
        )
        .expect("a DeterministicService revision may project an explicit all-null route");
    }
    #[test]
    fn native_reset_projection_keeps_operator_authority_out_of_public_binding() {
        let fixture: Value = json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/norito_rpc/alias_setup_v1/alias_setup_v1.json"
        )))
        .expect("public receipt fixture");
        let receipt: AccountOnboardingPlanReceiptV1 =
            json::from_value(fixture["account_onboarding_receipt_vector"]["receipt_json"].clone())
                .expect("typed receipt");
        let native = fixture_write_canary_args(WriteCanaryOperation::Onboarding)
            .binding()
            .expect("native custody");
        let public = native
            .onboarding_binding(&receipt)
            .expect("public projection");
        assert_eq!(public.request_id, native.idempotency_key);
        assert_eq!(
            public.semantic_hash_hex,
            hex::encode(receipt.plan_hash.as_ref())
        );
        assert_eq!(
            public.execution_expires_at_unix_ms,
            native
                .execution_expires_at_unix_ms
                .min(receipt.body.valid_until_ms)
        );
        let value = json::to_value(&public).expect("public JSON");
        let fields = value.as_object().expect("binding object");
        assert_eq!(fields.len(), 5);
        for private_field in [
            "authorization_sha256",
            "authorization_nonce",
            "phase",
            "idempotency_key",
        ] {
            assert!(!fields.contains_key(private_field));
        }
        assert_eq!(native.schema, PREPARED_BINDING_SCHEMA_V1);
        let mut different = native.clone();
        different.idempotency_key = "aa".repeat(32);
        assert_ne!(
            different
                .onboarding_binding(&receipt)
                .expect("other request"),
            public
        );
        different = native.clone();
        different.kind = "faucet".to_owned();
        assert!(different.onboarding_binding(&receipt).is_err());
        let mut changed = receipt;
        changed.body.request.alias.push('x');
        assert!(native.onboarding_binding(&changed).is_err());
    }

    #[test]
    fn native_faucet_projection_changes_with_exact_claim() {
        let native = fixture_write_canary_args(WriteCanaryOperation::Faucet)
            .binding()
            .expect("native faucet custody");
        let account = AccountId::new(fixture_key_pair(0x45).public_key().clone());
        let claim = AccountFaucetClaimV1 {
            account_id: account.to_string(),
            pow_anchor_height: 42,
            pow_nonce_hex: "0001".to_owned(),
        };
        let public = native.faucet_binding(&claim).expect("project claim");
        assert_eq!(public.request_id, native.idempotency_key);
        let mut changed = claim;
        changed.pow_nonce_hex = "0002".to_owned();
        let changed_public = native
            .faucet_binding(&changed)
            .expect("project different claim");
        assert_ne!(public.semantic_hash_hex, changed_public.semantic_hash_hex);
        assert_eq!(public.request_id, changed_public.request_id);
        let mut wrong_kind = native;
        wrong_kind.kind = "onboarding".to_owned();
        assert!(wrong_kind.faucet_binding(&changed).is_err());
    }

    #[test]
    fn write_canary_child_idempotency_keys_are_domain_separated() {
        let nonce = "n".repeat(32);
        let phase = "pre_edge";
        let onboarding = write_canary_child_idempotency_key(&nonce, phase, "onboarding");
        let faucet = write_canary_child_idempotency_key(&nonce, phase, "faucet");
        let final_canary = write_canary_child_idempotency_key(&nonce, phase, "write_canary");
        assert_eq!(onboarding.len(), 64);
        assert_ne!(onboarding, faucet);
        assert_ne!(onboarding, final_canary);
        assert_ne!(faucet, final_canary);

        let mut args = fixture_write_canary_args(WriteCanaryOperation::Onboarding);
        assert!(args.binding().is_ok());
        args.idempotency_key = faucet;
        assert!(args.binding().is_err());
    }

    #[test]
    fn expired_submit_reconciles_known_state_but_bars_absent_effect() {
        let mut binding = fixture_write_canary_args(WriteCanaryOperation::FinalCanary)
            .binding()
            .expect("binding");
        binding.execution_expires_at_unix_ms = 1;
        let applied = PreparedRecoveryClassification::Applied {
            block_height: Some(7),
            evidence: "ab".repeat(32),
        };
        assert!(
            !submit_required_after_classification(&binding, &applied)
                .expect("known state is read-only across expiry")
        );
        let absent = PreparedRecoveryClassification::Absent;
        assert!(submit_required_after_classification(&binding, &absent).is_err());
    }
    #[test]
    fn inrou_canary_rejects_zero_timeout_before_external_work() {
        assert!(validate_inrou_canary_timeout(1).is_ok());
        let error = validate_inrou_canary_timeout(0)
            .expect_err("zero timeout must fail before canary mutation");
        assert!(error.to_string().contains("must be greater than zero"));
    }
    #[test]
    fn inrou_canary_health_response_rejects_oversized_body_before_json_decode() {
        let oversized = vec![
            b' ';
            usize::try_from(INROU_CANARY_HEALTH_RESPONSE_MAX_BYTES)
                .expect("V1 health bound fits usize")
                + 1
        ];
        for status in [200, 503] {
            let error = decode_inrou_canary_health_reader(
                status,
                std::io::Cursor::new(oversized.as_slice()),
            )
            .expect_err("oversized unauthenticated health response must fail closed");
            assert!(
                error.to_string().contains("exceeds the V1 byte limit"),
                "unexpected oversized-response error for HTTP {status}: {error:#}"
            );
        }
    }
    #[test]
    fn inrou_canary_health_response_rejects_oversized_declared_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local health fixture");
        let address = listener.local_addr().expect("local health fixture address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept local health request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("local health request timeout");
            let _request = read_mock_request(&mut stream)
                .expect("read local health request")
                .expect("complete local health request");
            write!(
                stream,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{{}}",
                INROU_CANARY_HEALTH_RESPONSE_MAX_BYTES + 1
            )
            .expect("write oversized declared health response");
        });
        let response = HttpClient::builder()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build local health client")
            .get(format!("http://{address}/health"))
            .send()
            .expect("read local health response headers");
        assert_eq!(response.status().as_u16(), 503);
        let error = decode_inrou_canary_health_response(response)
            .expect_err("oversized declared Content-Length must fail before body decoding");
        assert!(
            error.to_string().contains("exceeds the V1 byte limit"),
            "unexpected declared-length error: {error:#}"
        );
        server.join().expect("local health fixture thread");
    }
    #[test]
    fn inrou_probe_requires_a_current_successful_route_observation() {
        let _fixture = mock_http_fixture_guard();
        let _chain_discriminant = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        let service_version = inrou_canary_artifact_version(0x24);
        let deployment = inrou_canary_deployment("deploy", &service_version);
        let status = exact_inrou_status(&service_version, "Deploy", 1);
        let status_calls = Arc::new(AtomicUsize::new(0));
        let route_calls = Arc::new(AtomicUsize::new(0));
        let server_status_calls = Arc::clone(&status_calls);
        let server_route_calls = Arc::clone(&route_calls);
        let server_version = service_version.clone();
        let server_deployment = deployment.clone();
        let server = spawn_mock_http(16, move |request| match path_only(&request.path) {
            "/v1/soracloud/status" => {
                let call = server_status_calls.fetch_add(1, Ordering::AcqRel);
                MockResponse::json(if call < 4 { 503 } else { 200 }, status.clone())
            }
            "/api/v1/inrou-canary/health" => {
                let call = server_route_calls.fetch_add(1, Ordering::AcqRel);
                if call == 4 {
                    MockResponse::json(503, norito::json!({"error": "transient"}))
                } else {
                    let slot = if call < 4 {
                        u64::try_from(call + 1).expect("bounded slot")
                    } else {
                        1
                    };
                    MockResponse::json(200, exact_inrou_health_response(&server_version, slot))
                }
            }
            path => inrou_discovery_mock_response(request, &server_deployment)
                .unwrap_or_else(|| panic!("unexpected Inrou probe path: {path}")),
        });
        let key_pair = fixture_key_pair(0x42);
        let mut config = crate::fallback_config();
        config.account = AccountId::new(key_pair.public_key().clone());
        config.key_pair = key_pair;
        config.torii_api_url =
            Url::parse(&format!("{}/", server.base_url)).expect("mock Torii URL");
        let client = IrohaClient::builder(config)
            .build()
            .expect("valid Taira fixture context");

        let observation = probe_inrou_service(
            &server.base_url,
            &client,
            &deployment,
            Instant::now() + Duration::from_secs(3),
            InrouProbeScope::Public,
        )
        .expect("probe converges after a final current route success");
        assert!(
            observation.failures.is_empty(),
            "unexpected probe failures: {:?}",
            observation.failures
        );
        let route_check = observation
            .checks
            .iter()
            .find(|check| check.get("name").and_then(Value::as_str) == Some("inrou_public_routes"))
            .expect("route check");
        assert_eq!(
            route_check.get("http_status").and_then(Value::as_u64),
            Some(200)
        );
        assert_eq!(route_check.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(status_calls.load(Ordering::Acquire), 6);
        assert_eq!(route_calls.load(Ordering::Acquire), 6);
        let requests = finish_mock(server);
        assert_eq!(requests.len(), 16);
    }
    #[test]
    fn inrou_check_separates_selected_status_origin_from_public_route_origin() {
        let _chain_discriminant = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        let service_version = inrou_canary_artifact_version(0x25);
        let stage = inrou_canary_stage_identity("deploy", &service_version);
        let status = exact_inrou_status(&service_version, "Deploy", 1);

        let status_server = spawn_mock_http(4, move |request| {
            assert_eq!(request.method, "GET");
            assert_eq!(path_only(&request.path), "/v1/soracloud/status");
            MockResponse::json(200, status.clone())
        });
        let route_index = Arc::new(AtomicUsize::new(0));
        let server_route_index = Arc::clone(&route_index);
        let route_version = service_version.clone();
        let public_deployment = inrou_canary_deployment("deploy", &service_version);
        let server_deployment = public_deployment.clone();
        let public_server = spawn_mock_http(8, move |request| {
            assert_eq!(request.method, "GET");
            if path_only(&request.path) == "/api/v1/inrou-canary/health" {
                let replica_slot =
                    u64::try_from(server_route_index.fetch_add(1, Ordering::AcqRel) + 1)
                        .expect("bounded replica slot");
                MockResponse::json(
                    200,
                    exact_inrou_health_response(&route_version, replica_slot),
                )
            } else {
                inrou_discovery_mock_response(request, &server_deployment)
                    .unwrap_or_else(|| panic!("unexpected public Inrou path: {}", request.path))
            }
        });

        let key_pair = fixture_key_pair(0x43);
        let mut status_config = crate::fallback_config();
        status_config.account = AccountId::new(key_pair.public_key().clone());
        status_config.key_pair = key_pair;
        status_config.torii_api_url = Url::parse(&format!("{}/", status_server.base_url))
            .expect("selected validator Torii URL");
        // This checks origin separation, not latency. Give the twelve local requests
        // and four-replica polling cadence bounded time on a loaded build host.
        let report = verify_inrou_check_from_selected_status_origin(
            &public_server.base_url,
            &status_config,
            &stage,
            30,
            InrouProbeScope::Public,
        )
        .expect("status and route probes use their distinct configured origins");
        crate::taira_public_reset::validate_inrou_checks_for_test(&report, InrouProbeScope::Public)
            .unwrap_or_else(|error| {
                panic!(
                    "active public probe output must satisfy the host receipt contract: \
                     {error:?}; report: {report:?}"
                )
            });
        assert_eq!(report_status(&report), Some("ok"));
        assert_eq!(route_index.load(Ordering::Acquire), 4);

        let status_requests = finish_mock(status_server);
        assert_eq!(status_requests.len(), 4);
        assert!(
            status_requests
                .iter()
                .all(|request| path_only(&request.path) == "/v1/soracloud/status")
        );
        let public_requests = finish_mock(public_server);
        assert_eq!(public_requests.len(), 8);
        assert_eq!(
            public_requests
                .iter()
                .filter(|request| { path_only(&request.path) == "/api/v1/inrou-canary/health" })
                .count(),
            4
        );
    }
    #[test]
    fn candidate_inrou_qualifies_runtime_before_public_discovery_exists() {
        let _fixture = mock_http_fixture_guard();
        let _chain_discriminant = ChainDiscriminantGuard::enter(DEFAULT_CHAIN_DISCRIMINANT);
        for scope in [InrouProbeScope::Candidate, InrouProbeScope::Public] {
            let service_version = inrou_canary_artifact_version(0x26);
            let stage = inrou_canary_stage_identity("deploy", &service_version);
            let status = exact_inrou_status(&service_version, "Deploy", 1);
            let route_index = Arc::new(AtomicUsize::new(0));
            let server_route_index = Arc::clone(&route_index);
            let server = spawn_mock_http(100, move |request| {
                assert_eq!(request.method, "GET");
                match path_only(&request.path) {
                    "/v1/soracloud/status" => {
                        assert!(
                            !request.header_values("x-iroha-signature").is_empty(),
                            "authoritative status must retain account authentication"
                        );
                        MockResponse::json(200, status.clone())
                    }
                    "/api/v1/inrou-canary/health" => {
                        let slot = u64::try_from(
                            server_route_index.fetch_add(1, Ordering::AcqRel) % 4 + 1,
                        )
                        .expect("bounded replica slot");
                        MockResponse::json(200, exact_inrou_health_response(&service_version, slot))
                    }
                    _ => MockResponse::json(404, norito::json!({"error": "edge not installed"})),
                }
            });
            let key_pair = fixture_key_pair(0x44);
            let mut config = crate::fallback_config();
            config.account = AccountId::new(key_pair.public_key().clone());
            config.key_pair = key_pair;
            config.torii_api_url =
                Url::parse(&format!("{}/", server.base_url)).expect("candidate Torii URL");
            let report = verify_inrou_check_from_selected_status_origin(
                &server.base_url,
                &config,
                &stage,
                2,
                scope,
            )
            .expect("probe report");
            assert_eq!(
                report.get("probe_scope").and_then(Value::as_str),
                Some(scope.label())
            );
            assert_eq!(
                report
                    .get("replica_identities")
                    .and_then(Value::as_array)
                    .map(Vec::len),
                Some(4)
            );
            let checks = report
                .get("checks")
                .and_then(Value::as_array)
                .expect("probe checks");
            let expected_checks: &[&str] = match scope {
                InrouProbeScope::Candidate => {
                    &["inrou_authoritative_status", "inrou_public_routes"]
                }
                InrouProbeScope::Public => &[
                    "inrou_authoritative_status",
                    "inrou_public_routes",
                    "inrou_public_discovery",
                ],
            };
            assert_eq!(
                checks
                    .iter()
                    .map(|check| check
                        .get("name")
                        .and_then(Value::as_str)
                        .expect("check name"))
                    .collect::<Vec<_>>(),
                expected_checks
            );
            let accepted =
                crate::taira_public_reset::validate_inrou_checks_for_test(&report, scope);
            let requests = finish_mock(server);
            if scope == InrouProbeScope::Candidate {
                assert_eq!(report_status(&report), Some("ok"));
                accepted.expect("actual candidate producer output satisfies the host contract");
                assert_eq!(requests.len(), 8);
                assert!(requests.iter().all(|request| matches!(
                    path_only(&request.path),
                    "/v1/soracloud/status" | "/api/v1/inrou-canary/health"
                )));
                assert!(
                    crate::taira_public_reset::validate_inrou_checks_for_test(
                        &report,
                        InrouProbeScope::Public
                    )
                    .is_err(),
                    "candidate evidence must never qualify public cutover"
                );
            } else {
                assert_eq!(report_status(&report), Some("fail"));
                assert!(
                    accepted.is_err(),
                    "missing public discovery must block public qualification"
                );
                assert!(requests.iter().any(|request| !matches!(
                    path_only(&request.path),
                    "/v1/soracloud/status" | "/api/v1/inrou-canary/health"
                )));
                assert_eq!(
                    checks
                        .last()
                        .and_then(|check| check.get("ok"))
                        .and_then(Value::as_bool),
                    Some(false)
                );
            }
        }
    }

    #[test]
    fn candidate_inrou_scope_rejects_remote_or_implicit_probe_destinations() {
        InrouProbeScope::Candidate
            .validate_root("http://127.0.0.1:8080")
            .expect("inventory can bind an explicit local Torii port");
        for root in [
            "https://taira.sora.org",
            "http://127.0.0.1",
            "http://localhost:8080",
            "http://192.0.2.1:8080",
            "http://127.0.0.1:8080/redirect",
            "http://127.0.0.1:8080?route=other",
            "http://user@127.0.0.1:8080",
        ] {
            assert!(
                InrouProbeScope::Candidate.validate_root(root).is_err(),
                "candidate root accepted {root}"
            );
        }
        InrouProbeScope::Public
            .validate_root(DEFAULT_PUBLIC_ROOT)
            .expect("public endpoint");
    }

    #[test]
    fn inrou_health_identity_requires_exact_v1_shape_and_version() {
        let service_version = inrou_canary_artifact_version(0x22);
        let deployment = inrou_canary_deployment("upgrade", &service_version);
        let canonical = norito::json!({
            "schema_version": 1,
            "service": "taira_inrou_canary",
            "service_version": (service_version.clone()),
            "runtime": "Inrou",
            "replica_slot": 3,
            "identity": "taira_inrou_canary:replica:3",
            "app_data_marker_sha256": ("ab".repeat(32)),
            "boot_sequence": 7,
            "guest_boot_id_sha256": ("cd".repeat(32))
        });
        let parsed = exact_inrou_health_identity(&canonical, &deployment)
            .expect("exact durable V1 health identity");
        assert_eq!(parsed.replica_slot, 3);
        assert_eq!(parsed.app_data_marker_sha256, "ab".repeat(32));
        assert_eq!(parsed.boot_sequence, 7);
        assert_eq!(parsed.guest_boot_id_sha256, "cd".repeat(32));

        let mut identities = BTreeMap::new();
        retain_exact_inrou_health_identity(&mut identities, parsed.clone())
            .expect("first exact observation");
        retain_exact_inrou_health_identity(&mut identities, parsed.clone())
            .expect("an exact-equal repeated observation");
        let mut conflict = parsed.clone();
        conflict.boot_sequence += 1;
        assert!(
            retain_exact_inrou_health_identity(&mut identities, conflict).is_err(),
            "a changed observation for one slot must fail closed"
        );
        assert_eq!(identities.get(&3), Some(&parsed));

        let mut extra = canonical.clone();
        extra
            .as_object_mut()
            .expect("health fixture is an object")
            .insert("legacy_version".to_owned(), Value::from("retired"));
        assert!(exact_inrou_health_identity(&extra, &deployment).is_none());
        let mut stale = canonical.clone();
        *stale
            .pointer_mut("/service_version")
            .expect("health fixture has a service version") =
            Value::from(inrou_canary_artifact_version(0x11));
        assert!(exact_inrou_health_identity(&stale, &deployment).is_none());
        let mut string_slot = canonical.clone();
        *string_slot
            .pointer_mut("/replica_slot")
            .expect("health fixture has a replica slot") = Value::from("3");
        assert!(exact_inrou_health_identity(&string_slot, &deployment).is_none());

        for (path, invalid) in [
            ("/schema_version", Value::from(2_u64)),
            ("/app_data_marker_sha256", Value::from("AB".repeat(32))),
            ("/boot_sequence", Value::from(0_u64)),
            ("/guest_boot_id_sha256", Value::from("cd".repeat(31))),
        ] {
            let mut malformed = canonical.clone();
            *malformed
                .pointer_mut(path)
                .expect("health fixture contains tested field") = invalid;
            assert!(
                exact_inrou_health_identity(&malformed, &deployment).is_none(),
                "malformed health field {path} must fail closed"
            );
        }
    }
    #[test]
    fn doctor_faucet_policy_checks_both_scopes_without_authentication() {
        let policy: Value =
            json::from_slice(&doctor_account_tests::faucet_response().body).unwrap();
        let disabled = norito::json!({
            "code": "account_faucet_disabled",
            "message": "Account faucet is disabled"
        });
        let mut extended = policy.clone();
        extended
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), Value::Bool(true));
        let mut unsupported_schema = policy.clone();
        unsupported_schema
            .as_object_mut()
            .unwrap()
            .insert("schema_version".to_owned(), Value::from(2_u64));
        let mut zero_amount = policy.clone();
        zero_amount
            .as_object_mut()
            .unwrap()
            .insert("amount".to_owned(), Value::from("0"));
        let cases = [
            ("enabled", 200, Some(policy.clone()), true),
            ("disabled", 503, Some(disabled.clone()), false),
            ("missing", 404, None, false),
            ("unavailable", 502, None, false),
            ("forbidden", 403, None, false),
            ("non-JSON success", 200, None, false),
            ("malformed success", 200, Some(norito::json!({})), false),
            ("unknown field", 200, Some(extended), false),
            ("unsupported schema", 200, Some(unsupported_schema), false),
            ("zero issuance", 200, Some(zero_amount), false),
            (
                "disabled body with success status",
                200,
                Some(disabled),
                false,
            ),
            (
                "enabled body with unavailable status",
                503,
                Some(policy),
                false,
            ),
        ];
        for scope in [DoctorScope::Basic, DoctorScope::Full] {
            for (label, status, body, accepted) in &cases {
                let status = *status;
                let body = body.clone();
                let server = spawn_mock_http(16, move |request| {
                    if path_only(&request.path) == "/v1/accounts/faucet/policy" {
                        match &body {
                            Some(body) => MockResponse::json(status, body.clone()),
                            None => MockResponse::text(status, "not JSON"),
                        }
                    } else {
                        doctor_mock_response(request, None)
                    }
                });
                let report = run_doctor(&server.base_url, scope).expect("doctor report");
                let requests = finish_mock(server);
                assert_eq!(
                    report_status(&report),
                    Some(if *accepted { "ok" } else { "fail" }),
                    "{scope:?}: {label}"
                );
                let faucet_requests = requests
                    .iter()
                    .filter(|request| path_only(&request.path) == "/v1/accounts/faucet/policy")
                    .collect::<Vec<_>>();
                assert_eq!(faucet_requests.len(), 1, "{scope:?}: {label}");
                let request = faucet_requests[0];
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/v1/accounts/faucet/policy");
                assert!(request.body.is_empty());
                for header in [
                    "authorization",
                    "proxy-authorization",
                    "cookie",
                    "x-iroha-account",
                    "x-iroha-signature",
                    "x-iroha-timestamp-ms",
                    "x-iroha-nonce",
                ] {
                    assert!(
                        request.header_values(header).is_empty(),
                        "unexpected {header}"
                    );
                }
                let check = report["checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|check| check["name"].as_str() == Some("account_faucet_policy"))
                    .expect("faucet policy check");
                let observed_status = if status == 200 && !*accepted {
                    0
                } else {
                    status
                };
                assert_eq!(
                    check["http_status"].as_u64(),
                    Some(u64::from(observed_status))
                );
                assert_eq!(check["ok"].as_bool(), Some(*accepted));
                assert_eq!(
                    report["failures"].as_array().unwrap().len(),
                    usize::from(!*accepted)
                );
                assert!(
                    report["warnings"].as_array().unwrap().is_empty(),
                    "{scope:?}: {label}"
                );
            }
            let expected = doctor_expected_checks(scope);
            let (_, status, detail) = expected
                .iter()
                .find(|(name, _, _)| *name == "account_faucet_policy")
                .expect("public reset requires the faucet policy check");
            assert_eq!(*status, 200);
            assert!(detail.is_none());
        }
    }

    #[test]
    fn doctor_mock_healthy_flow_reports_ok() {
        let server = spawn_mock_http(16, |request| doctor_mock_response(request, None));
        let report = run_doctor(&server.base_url, DoctorScope::Full).expect("doctor report");
        let requests = finish_mock(server);
        assert_eq!(report_status(&report), Some("ok"));
        assert!(
            !requests.iter().any(|request| {
                request.method == "POST"
                    && (request.body.contains("\"method\":\"initialize\"")
                        || request.body.contains("notifications/initialized"))
            }),
            "native doctor must not use the retired initialization lifecycle"
        );
        let discovery = requests
            .iter()
            .find(|request| request.method == "POST" && request.body.contains("server/discover"))
            .expect("MCP server/discover request");
        assert_modern_mcp_request(discovery, 1, "server/discover");
        let tools_list = requests
            .iter()
            .find(|request| request.method == "POST" && request.body.contains("tools/list"))
            .expect("MCP tools/list request");
        assert_modern_mcp_request(tools_list, 2, "tools/list");
        assert!(requests.iter().any(|request| {
            request.method == "GET"
                && path_only(&request.path) == "/v1/pipeline/transactions/status"
        }));
        assert!(requests.iter().any(|request| {
            request.method == "GET" && path_only(&request.path) == "/v1/time/now"
        }));
        assert!(
            requests
                .iter()
                .all(|request| !path_only(&request.path).starts_with("/v1/kagemusha/")),
            "the doctor must not probe the retired KAGEMUSHA route family"
        );
        assert!(requests.iter().any(|request| {
            request.method == "POST"
                && path_only(&request.path) == "/v1/musubi/queries/ordered-prefix"
                && request.body == "{}"
        }));
    }

    #[test]
    fn doctor_readiness_requires_exact_plain_text_ready_in_both_scopes() {
        for scope in [DoctorScope::Basic, DoctorScope::Full] {
            for (label, content_type, body, accepted) in [
                (
                    "ready",
                    "text/plain; charset=utf-8",
                    b"Ready".to_vec(),
                    true,
                ),
                ("other text", "text/plain", b"Alive".to_vec(), false),
                (
                    "JSON string",
                    "application/json",
                    b"\"Ready\"".to_vec(),
                    false,
                ),
                (
                    "oversized",
                    "text/plain",
                    vec![b'x'; usize::try_from(READINESS_RESPONSE_MAX_BYTES + 1).unwrap()],
                    false,
                ),
            ] {
                let server = spawn_mock_http(16, move |request| {
                    if path_only(&request.path) == "/readyz" {
                        MockResponse {
                            status: 200,
                            content_type,
                            headers: Vec::new(),
                            body: body.clone(),
                        }
                    } else {
                        doctor_mock_response(request, None)
                    }
                });
                let report = run_doctor(&server.base_url, scope).expect("doctor report");
                let requests = finish_mock(server);
                assert_eq!(
                    report_status(&report),
                    Some(if accepted { "ok" } else { "fail" }),
                    "{scope:?}: {label}"
                );
                let readiness_requests = requests
                    .iter()
                    .filter(|request| path_only(&request.path) == "/readyz")
                    .collect::<Vec<_>>();
                assert_eq!(readiness_requests.len(), 1, "{scope:?}: {label}");
                assert_eq!(readiness_requests[0].method, "GET");
                assert_eq!(
                    readiness_requests[0].header_values("accept"),
                    ["text/plain, application/json"]
                );
                let checks = report["checks"].as_array().unwrap();
                let readiness = checks
                    .iter()
                    .find(|check| check["name"].as_str() == Some("readiness"))
                    .expect("mandatory readiness check");
                assert_eq!(readiness["http_status"].as_u64(), Some(200));
                assert_eq!(readiness["ok"].as_bool(), Some(accepted));
                assert!(checks.iter().all(|check| {
                    check["name"].as_str() == Some("readiness")
                        || check["ok"].as_bool() == Some(true)
                }));
                assert_eq!(
                    report["failures"].as_array().unwrap().len(),
                    usize::from(!accepted)
                );
                assert!(
                    doctor_expected_checks(scope)
                        .iter()
                        .any(|(name, status, detail)| {
                            *name == "readiness" && *status == 200 && detail.is_none()
                        })
                );
            }
        }
    }

    #[test]
    fn doctor_readiness_unavailable_fails_both_scopes_with_only_bounded_error_codes() {
        for scope in [DoctorScope::Basic, DoctorScope::Full] {
            for (code, expected) in [
                (
                    Value::from("consensus_admission_unavailable"),
                    "consensus_admission_unavailable",
                ),
                (Value::from("injected\ncode"), "unspecified"),
                (Value::from("x".repeat(65)), "unspecified"),
                (Value::Bool(false), "unspecified"),
            ] {
                let server = spawn_mock_http(16, move |request| {
                    if path_only(&request.path) == "/readyz" {
                        MockResponse::json(
                            503,
                            norito::json!({
                                "code": (code.clone()),
                                "message": "do-not-forward-server-message",
                                "details": { "private": "do-not-forward-server-data" }
                            }),
                        )
                    } else {
                        doctor_mock_response(request, None)
                    }
                });
                let report = run_doctor(&server.base_url, scope).expect("doctor report");
                finish_mock(server);
                assert_eq!(
                    report_status(&report),
                    Some("fail"),
                    "{scope:?}: {expected}"
                );
                let checks = report["checks"].as_array().unwrap();
                let readiness = checks
                    .iter()
                    .find(|check| check["name"].as_str() == Some("readiness"))
                    .expect("mandatory readiness check");
                assert_eq!(readiness["http_status"].as_u64(), Some(503));
                assert_eq!(readiness["ok"].as_bool(), Some(false));
                let failure =
                    format!("/readyz returned HTTP 503; error_code={expected}; expected 200");
                assert_eq!(readiness["detail"].as_str(), Some(failure.as_str()));
                assert_eq!(
                    report["failures"].as_array().unwrap().as_slice(),
                    &[Value::from(failure)]
                );
                assert!(checks.iter().all(|check| {
                    check["name"].as_str() == Some("readiness")
                        || check["ok"].as_bool() == Some(true)
                }));
                assert!(!json::to_json(&report).unwrap().contains("do-not-forward"));
            }
        }
    }

    #[test]
    fn inrou_status_probe_uses_canonical_account_authentication() {
        let server = spawn_mock_http(1, |request| {
            assert_eq!(request.method, "GET");
            assert_eq!(path_only(&request.path), "/v1/soracloud/status");
            MockResponse::json(200, norito::json!({ "schema_version": 1 }))
        });
        let key_pair = fixture_key_pair(0x41);
        let mut config = crate::fallback_config();
        config.account = AccountId::new(key_pair.public_key().clone());
        config.key_pair = key_pair;
        config.torii_api_url =
            Url::parse(&format!("{}/", server.base_url)).expect("mock Torii URL");
        let client = IrohaClient::builder(config)
            .build()
            .expect("valid Taira fixture context");
        let status = account_signed_soracloud_status(&client).expect("signed status response");
        assert_eq!(status.status, 200);
        assert_eq!(status.body, Some(norito::json!({ "schema_version": 1 })));
        let requests = finish_mock(server);
        let request = requests.first().expect("status request");
        for header in [
            "x-iroha-account",
            "x-iroha-signature",
            "x-iroha-timestamp-ms",
            "x-iroha-nonce",
        ] {
            assert_eq!(
                request.header_values(header).len(),
                1,
                "canonical header {header} must appear exactly once"
            );
        }
        assert_eq!(request.header_values("accept"), vec!["application/json"]);
    }
    #[test]
    fn render_report_text_includes_route_check_detail() {
        let mut checks = Vec::new();
        push_check(
            &mut checks,
            "contracts_state",
            400,
            true,
            route_check_detail(&[400]),
        );
        let report = report_value(
            "taira_doctor",
            "ok",
            DEFAULT_PUBLIC_ROOT,
            checks,
            Vec::new(),
            Vec::new(),
            Map::new(),
        )
        .expect("report");
        let mut context = TextContext::new();
        render_report(&mut context, false, &report).expect("render report");
        let output = context.lines.join("\n");
        assert!(
            output
                .contains("contracts_state HTTP 400 (mounted route is expected to return HTTP 400")
        );
    }
    #[test]
    fn configless_report_writer_emits_json_and_text() {
        let report = report_value(
            "taira_doctor",
            "ok",
            DEFAULT_PUBLIC_ROOT,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Map::new(),
        )
        .expect("report");

        let mut json_output = WriterReportOutput {
            write: Vec::new(),
            output_format: CliOutputFormat::Text,
        };
        render_report_to(&mut json_output, true, &report).expect("render configless JSON report");
        let decoded: Value =
            json::from_slice(&json_output.write).expect("decode configless JSON report");
        assert_eq!(decoded, report);
        assert!(json_output.write.ends_with(b"\n"));

        let mut text_output = WriterReportOutput {
            write: Vec::new(),
            output_format: CliOutputFormat::Text,
        };
        render_report_to(&mut text_output, false, &report).expect("render configless text report");
        assert_eq!(
            String::from_utf8(text_output.write).expect("UTF-8 report"),
            format!("taira_doctor: ok ({DEFAULT_PUBLIC_ROOT})\n")
        );
    }
    #[test]
    fn public_status_requires_canonical_nested_queue_saturation() {
        let canonical = norito::json!({
            "sumeragi": { "tx_queue_saturated": false },
            "txs_rejected_recent_5m": 0,
            "queue_size": 0
        });
        validate_public_status(Some(&canonical)).expect("canonical status");

        let flattened = norito::json!({
            "tx_queue_saturated": false,
            "sumeragi": { "tx_queue_saturated": false }
        });
        assert!(
            validate_public_status(Some(&flattened))
                .expect_err("retired flattened status field must fail")
                .contains("retired root")
        );
        let missing = norito::json!({ "sumeragi": {} });
        assert!(validate_public_status(Some(&missing)).is_err());
        assert!(validate_public_status(None).is_err());

        let mut warnings = Vec::new();
        let saturated = norito::json!({
            "sumeragi": { "tx_queue_saturated": true },
            "txs_rejected_recent_5m": 0,
            "queue_size": 0
        });
        collect_status_warnings(Some(&saturated), &mut warnings);
        assert_eq!(warnings, ["public transaction queue reports saturation"]);
    }
    #[test]
    fn time_snapshot_requires_network_time_and_every_health_axis() {
        let healthy = norito::json!({
            "now": 1_u64, "offset_ms": 0, "confidence_ms": 0_u64,
            "sample_count": 3_u64, "peer_count": 3_u64,
            "enforcement_mode": "reject", "fallback": false,
            "health": {"healthy": true, "min_samples_ok": true,
                "offset_ok": true, "confidence_ok": true}
        });
        for scope in [DoctorScope::Basic, DoctorScope::Full] {
            validate_time_snapshot(Some(&healthy), scope).expect("healthy network time");
            for (path, value) in [
                ("/now", Value::from(0_u64)),
                ("/offset_ms", Value::from("0")),
                ("/confidence_ms", Value::from(-1_i64)),
                ("/sample_count", Value::from(4_u64)),
                ("/peer_count", Value::from("3")),
                ("/enforcement_mode", Value::from("disabled")),
                ("/fallback", Value::from("false")),
                ("/health/healthy", Value::Bool(false)),
                ("/health/min_samples_ok", Value::from("true")),
            ] {
                let mut invalid = healthy.clone();
                *invalid.pointer_mut(path).expect("tested field") = value;
                assert!(
                    validate_time_snapshot(Some(&invalid), scope).is_err(),
                    "{path}"
                );
            }
            for flag in ["offset_ok", "confidence_ok"] {
                let mut invalid = healthy.clone();
                *invalid
                    .pointer_mut("/health/healthy")
                    .expect("health field") = Value::Bool(false);
                *invalid
                    .pointer_mut(&format!("/health/{flag}"))
                    .expect("health bound") = Value::Bool(false);
                assert!(
                    validate_time_snapshot(Some(&invalid), scope)
                        .expect_err("observed clock bound violation")
                        .contains("bounds")
                );
            }
            assert!(validate_time_snapshot(None, scope).is_err());
        }
        let mut unsynchronized = healthy.clone();
        *unsynchronized
            .pointer_mut("/enforcement_mode")
            .expect("snapshot field") = Value::from("warn");
        *unsynchronized
            .pointer_mut("/sample_count")
            .expect("snapshot field") = Value::from(0_u64);
        *unsynchronized
            .pointer_mut("/peer_count")
            .expect("snapshot field") = Value::from(0_u64);
        *unsynchronized
            .pointer_mut("/fallback")
            .expect("snapshot field") = Value::Bool(true);
        *unsynchronized
            .pointer_mut("/health/healthy")
            .expect("health field") = Value::Bool(false);
        *unsynchronized
            .pointer_mut("/health/min_samples_ok")
            .expect("health field") = Value::Bool(false);
        validate_time_snapshot(Some(&unsynchronized), DoctorScope::Basic)
            .expect("basic scope reports synchronization separately");
        assert!(validate_time_snapshot(Some(&unsynchronized), DoctorScope::Full).is_err());
    }

    #[test]
    fn doctor_basic_scope_accepts_unsynchronized_time_and_excludes_advanced_routes() {
        for (args, expected) in [
            (vec!["taira-test", "doctor"], DoctorScope::Basic),
            (
                vec!["taira-test", "doctor", "--scope", "full"],
                DoctorScope::Full,
            ),
        ] {
            let cli = TestTairaCli::try_parse_from(args).expect("doctor scope arguments");
            let Command::Doctor(doctor) = cli.command else {
                panic!("expected doctor command");
            };
            assert_eq!(doctor.scope, expected);
        }
        assert!(
            TestTairaCli::try_parse_from(["taira-test", "doctor", "--scope", "unknown"]).is_err()
        );
        let server = spawn_mock_http(16, |request| {
            let mut response = doctor_mock_response(request, None);
            if path_only(&request.path) == "/v1/time/now" {
                let mut body: Value = json::from_slice(&response.body).unwrap();
                *body
                    .pointer_mut("/enforcement_mode")
                    .expect("snapshot field") = Value::from("warn");
                *body.pointer_mut("/sample_count").expect("snapshot field") = Value::from(0_u64);
                *body.pointer_mut("/peer_count").expect("snapshot field") = Value::from(0_u64);
                *body.pointer_mut("/fallback").expect("snapshot field") = Value::Bool(true);
                *body.pointer_mut("/health/healthy").expect("health field") = Value::Bool(false);
                *body
                    .pointer_mut("/health/min_samples_ok")
                    .expect("health field") = Value::Bool(false);
                response.body = json::to_vec(&body).unwrap();
            }
            response
        });
        let report = run_doctor(&server.base_url, DoctorScope::Basic).expect("basic doctor");
        let requests = finish_mock(server);
        assert_eq!(report_status(&report), Some("ok"));
        assert_eq!(report["scope"].as_str(), Some("basic"));
        let warnings = report["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        let warning = warnings[0].as_str().unwrap();
        assert!(
            warning.contains("enforcement_mode=warn")
                && warning.contains("fallback=true")
                && warning.contains("healthy=false")
                && warning.contains("sample_count=0")
        );
        for (name, _, path, _) in ROUTE_CHECKS {
            if !DoctorScope::Basic.includes_route(name) {
                assert!(
                    !requests
                        .iter()
                        .any(|request| path_only(&request.path) == *path)
                );
            }
        }
        let checks = report["checks"].as_array().unwrap();
        assert!(
            checks
                .iter()
                .any(|check| check["name"].as_str() == Some("mcp_discovery"))
        );
        assert!(
            !checks
                .iter()
                .any(|check| check["name"].as_str() == Some("mcp_initialize"))
        );
        let expected = doctor_expected_checks(DoctorScope::Basic);
        assert_eq!(checks.len(), expected.len());
        for (actual, (name, status, detail)) in checks.iter().zip(expected) {
            assert_eq!(actual["name"].as_str(), Some(name));
            assert_eq!(actual["http_status"].as_u64(), Some(status));
            assert_eq!(
                actual.get("detail").and_then(Value::as_str),
                detail.as_deref()
            );
        }
    }

    #[test]
    fn doctor_tools_list_consumes_pages_and_rejects_invalid_cursors() {
        for invalid_cursor in [false, true] {
            let server = spawn_mock_http(16, move |request| {
                let mut response = doctor_mock_response(request, None);
                if request.method == "POST" && request.body.contains("tools/list") {
                    let request_body: Value = json::from_str(&request.body).unwrap();
                    let mut body: Value = json::from_slice(&response.body).unwrap();
                    let tools = body
                        .pointer_mut("/result/tools")
                        .and_then(Value::as_array_mut)
                        .unwrap();
                    if request_body.pointer("/params/cursor").is_none() {
                        tools.truncate(1);
                        body.pointer_mut("/result")
                            .and_then(Value::as_object_mut)
                            .unwrap()
                            .insert(
                                "nextCursor".into(),
                                Value::from(if invalid_cursor { "0" } else { "1" }),
                            );
                    } else {
                        assert_eq!(request_body["params"]["cursor"].as_str(), Some("1"));
                        tools.remove(0);
                    }
                    response.body = json::to_vec(&body).unwrap();
                }
                response
            });
            let report = run_doctor(&server.base_url, DoctorScope::Basic).expect("paged doctor");
            let requests = finish_mock(server);
            assert_eq!(
                report_status(&report),
                Some(if invalid_cursor { "fail" } else { "ok" })
            );
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request.body.contains("tools/list"))
                    .count(),
                if invalid_cursor { 1 } else { 2 }
            );
        }
    }
    #[test]
    fn write_canary_exit_gate_fails_closed() {
        ensure_write_canary_succeeded(&norito::json!({"status": "ok"}))
            .expect("an explicitly successful canary may exit zero");
        for report in [
            norito::json!({"status": "fail"}),
            norito::json!({"status": "unknown"}),
            norito::json!({}),
        ] {
            let _ = ensure_write_canary_succeeded(&report)
                .expect_err("non-success canary reports must produce a failing process exit");
        }
    }
    #[test]
    fn onboarding_token_validation_is_byte_exact() {
        assert_eq!(
            validate_onboarding_token(TEST_ONBOARDING_TOKEN).expect("valid token"),
            TEST_ONBOARDING_TOKEN
        );
        for malformed in [
            String::new(),
            "T".repeat(31),
            "T".repeat(257),
            format!("{} ", "T".repeat(31)),
            format!("{}é", "T".repeat(31)),
        ] {
            let error = validate_onboarding_token(&malformed)
                .expect_err("malformed onboarding token must fail closed");
            if !malformed.is_empty() {
                assert!(!format!("{error:#}").contains(&malformed));
            }
        }
    }
    #[test]
    #[cfg(unix)]
    fn onboarding_token_fd_is_exact_private_and_offset_independent() {
        use std::{
            io::{Seek as _, SeekFrom},
            os::{fd::AsRawFd as _, unix::fs::PermissionsExt as _},
        };
        let file = test_onboarding_token_file();
        let mut inherited = File::open(file.path()).expect("open read-only token descriptor");
        inherited
            .seek(SeekFrom::Start(7))
            .expect("advance caller offset");
        let fd = u32::try_from(inherited.as_raw_fd()).expect("positive descriptor");
        let mut args = fixture_write_canary_args(WriteCanaryOperation::Onboarding);
        args.onboarding_token_fd = Some(fd);
        args.validate_onboarding_token_action(PreparedEnvelopeAction::Prepare(3))
            .expect("explicit inherited token source");
        assert_eq!(
            args.read_onboarding_token().expect("token").as_str(),
            TEST_ONBOARDING_TOKEN
        );
        assert_eq!(inherited.stream_position().expect("caller offset"), 7);
        let replacement = "Z".repeat(32);
        fs::write(file.path(), &replacement).expect("replace token");
        assert_eq!(
            read_onboarding_token_fd(fd).expect("fresh token").as_str(),
            replacement
        );
        for malformed in [
            "T".repeat(31),
            "T".repeat(257),
            format!("{TEST_ONBOARDING_TOKEN}\n"),
        ] {
            fs::write(file.path(), &malformed).expect("write invalid token");
            let error = read_onboarding_token_fd(fd).expect_err("invalid exact token");
            assert!(!format!("{error:#}").contains(&malformed));
        }
        fs::write(file.path(), TEST_ONBOARDING_TOKEN).expect("restore token");
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o640)).expect("unsafe mode");
        assert!(read_onboarding_token_fd(fd).is_err());
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).expect("private mode");
        let writable_fd = u32::try_from(file.as_raw_fd()).expect("writable descriptor");
        assert!(read_onboarding_token_fd(writable_fd).is_err());
        let directory = tempfile::tempdir().expect("directory");
        let directory_fd = File::open(directory.path()).expect("open directory");
        assert!(
            read_onboarding_token_fd(
                u32::try_from(directory_fd.as_raw_fd()).expect("directory descriptor")
            )
            .is_err()
        );
    }
    #[test]
    fn onboarding_token_sources_are_exact_and_action_scoped() {
        let mut args = fixture_write_canary_args(WriteCanaryOperation::Onboarding);
        assert!(
            args.validate_onboarding_token_action(PreparedEnvelopeAction::Prepare(3))
                .is_err()
        );
        args.onboarding_token_file = Some(PathBuf::from("/private/runtime/onboarding.token"));
        for action in [
            PreparedEnvelopeAction::Prepare(3),
            PreparedEnvelopeAction::Submit(3),
        ] {
            assert!(args.validate_onboarding_token_action(action).is_ok());
        }
        args.onboarding_token_fd = Some(4);
        assert!(
            args.validate_onboarding_token_action(PreparedEnvelopeAction::Prepare(3))
                .is_err()
        );
        assert!(args.read_onboarding_token().is_err());
        args.onboarding_token_file = None;
        assert!(
            args.validate_onboarding_token_action(PreparedEnvelopeAction::Submit(3))
                .is_ok()
        );
        assert!(
            args.validate_onboarding_token_action(PreparedEnvelopeAction::Recover(3))
                .is_err()
        );
        for operation in [
            WriteCanaryOperation::Faucet,
            WriteCanaryOperation::FinalCanary,
        ] {
            args.operation = operation;
            for action in [
                PreparedEnvelopeAction::Prepare(3),
                PreparedEnvelopeAction::Submit(3),
                PreparedEnvelopeAction::Recover(3),
            ] {
                assert!(args.validate_onboarding_token_action(action).is_err());
            }
        }
        args.onboarding_token_fd = None;
        assert!(
            args.validate_onboarding_token_action(PreparedEnvelopeAction::Recover(3))
                .is_ok()
        );
        args.operation = WriteCanaryOperation::Onboarding;
        args.onboarding_token_fd = Some(2);
        assert!(
            args.validate_onboarding_token_action(PreparedEnvelopeAction::Prepare(3))
                .is_err()
        );
    }
    #[test]
    fn onboarding_token_fd_cli_rejects_invalid_and_conflicting_arguments() {
        #[derive(clap::Parser)]
        struct TokenArgs {
            #[command(flatten)]
            write_canary: WriteCanary,
        }
        use clap::Parser as _;
        let base = [
            "token-test",
            "--operation",
            "onboarding",
            "--authorization-sha256",
            "abababababababababababababababababababababababababababababababab",
            "--authorization-nonce",
            "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn",
            "--mutation-phase",
            "pre_edge",
            "--idempotency-key",
            "abababababababababababababababababababababababababababababababab",
            "--execution-expires-at-unix-ms",
            "18446744073709551615",
            "--prepare-envelope",
            "--prepared-output-fd",
            "3",
        ];
        let parse = |extra: &[&str]| {
            TokenArgs::try_parse_from(base.iter().copied().chain(extra.iter().copied()))
        };
        assert_eq!(
            parse(&["--onboarding-token-fd", "4"])
                .expect("numeric token descriptor")
                .write_canary
                .onboarding_token_fd,
            Some(4)
        );
        for invalid in ["2", "65536", "-1", "not-a-descriptor"] {
            assert!(parse(&["--onboarding-token-fd", invalid]).is_err());
        }
        assert!(
            parse(&[
                "--onboarding-token-fd",
                "4",
                "--onboarding-token-file",
                "/private/runtime/onboarding.token"
            ])
            .is_err()
        );
    }
    #[test]
    fn onboarding_token_file_is_exact_owner_only_regular_and_not_cached() {
        let file = test_onboarding_token_file();
        assert_eq!(
            read_onboarding_token_file(file.path())
                .expect("read token")
                .as_str(),
            TEST_ONBOARDING_TOKEN
        );
        let replacement = "Z".repeat(32);
        fs::write(file.path(), &replacement).expect("replace token bytes");
        assert_eq!(
            read_onboarding_token_file(file.path())
                .expect("read replacement token")
                .as_str(),
            replacement
        );
        fs::write(file.path(), format!("{TEST_ONBOARDING_TOKEN}\n")).expect("write newline token");
        let error = read_onboarding_token_file(file.path())
            .expect_err("newline must not be trimmed from token file");
        assert!(format!("{error:#}").contains("printable ASCII"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};
            fs::write(file.path(), TEST_ONBOARDING_TOKEN).expect("restore token");
            fs::set_permissions(file.path(), fs::Permissions::from_mode(0o640))
                .expect("set unsafe permissions");
            let error = read_onboarding_token_file(file.path())
                .expect_err("group-readable token file must fail closed");
            assert!(format!("{error:#}").contains("group or other"));
            fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600))
                .expect("restore safe permissions");
            let directory = tempfile::tempdir().expect("token symlink directory");
            let link = directory.path().join("onboarding.token");
            symlink(file.path(), &link).expect("create token symlink");
            let error =
                read_onboarding_token_file(&link).expect_err("token symlink must fail closed");
            assert!(format!("{error:#}").contains("non-symlink"));
        }
        let directory = tempfile::tempdir().expect("token directory");
        let error = read_onboarding_token_file(directory.path())
            .expect_err("directory token path must fail closed");
        assert!(format!("{error:#}").contains("regular non-symlink"));
    }
    #[test]
    fn doctor_mock_required_tool_missing_reports_failure() {
        let missing_tool = REQUIRED_MCP_TOOLS[0];
        let server = spawn_mock_http(16, move |request| {
            doctor_mock_response(request, Some(missing_tool))
        });
        let report = run_doctor(&server.base_url, DoctorScope::Full).expect("doctor report");
        let _requests = finish_mock(server);
        let failures = report
            .as_object()
            .and_then(|object| object.get("failures"))
            .and_then(Value::as_array)
            .expect("failures");
        assert_eq!(report_status(&report), Some("fail"));
        assert!(
            failures
                .iter()
                .filter_map(Value::as_str)
                .any(|failure| failure.contains(missing_tool))
        );
    }
    #[test]
    fn doctor_rejects_substituted_mcp_protocol_version() {
        let server = spawn_mock_http(16, |request| {
            if request.method == "POST"
                && path_only(&request.path) == "/v1/mcp"
                && request.body.contains("server/discover")
            {
                let mut response = doctor_mock_response(request, None);
                let mut payload: Value =
                    json::from_slice(&response.body).expect("mock discovery JSON");
                *payload
                    .pointer_mut("/result/supportedVersions")
                    .expect("mock supportedVersions") = norito::json!(["2024-11-05"]);
                response.body = json::to_vec(&payload).expect("encode mock discovery JSON");
                response
            } else {
                doctor_mock_response(request, None)
            }
        });
        let report = run_doctor(&server.base_url, DoctorScope::Full).expect("doctor report");
        let _requests = finish_mock(server);
        assert_eq!(report_status(&report), Some("fail"));
        assert!(
            report
                .get("failures")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|failure| failure.contains("protocolVersion"))
        );
    }
    #[test]
    fn doctor_rejects_noncanonical_mcp_discovery_response() {
        for noncanonical_response in ["wrong_status", "legacy_result", "mixed_versions"] {
            let server = spawn_mock_http(16, move |request| {
                if request.method == "POST"
                    && path_only(&request.path) == "/v1/mcp"
                    && request.body.contains("server/discover")
                {
                    assert_modern_mcp_request(request, 1, "server/discover");
                    match noncanonical_response {
                        "wrong_status" => MockResponse::text(202, ""),
                        "legacy_result" => MockResponse::json(
                            200,
                            norito::json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "result": {
                                    "protocolVersion": "2025-06-18",
                                    "capabilities": {}
                                }
                            }),
                        ),
                        "mixed_versions" => MockResponse::json(
                            200,
                            norito::json!({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "result": {
                                    "supportedVersions": [
                                        (mcp_wire::MODERN_PROTOCOL_VERSION),
                                        "2025-06-18"
                                    ],
                                    "capabilities": { "tools": { "listChanged": false } },
                                    "resultType": "complete",
                                    "ttlMs": 30_000,
                                    "cacheScope": "private",
                                    "_meta": {
                                        "io.modelcontextprotocol/serverInfo": {
                                            "name": "iroha-torii-mcp",
                                            "version": "1"
                                        }
                                    }
                                }
                            }),
                        ),
                        _ => unreachable!(),
                    }
                } else {
                    doctor_mock_response(request, None)
                }
            });
            let report = run_doctor(&server.base_url, DoctorScope::Full).expect("doctor report");
            let _requests = finish_mock(server);
            assert_eq!(report_status(&report), Some("fail"));
            assert!(
                report
                    .get("failures")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .any(|failure| failure.contains("server/discover")),
                "unexpected doctor report for {noncanonical_response}: {report:?}"
            );
        }
    }
    #[test]
    fn doctor_rejects_retired_mcp_get_capability_document() {
        let server = spawn_mock_http(16, |request| {
            if request.method == "GET" && path_only(&request.path) == "/v1/mcp" {
                MockResponse::json(
                    200,
                    norito::json!({
                        "protocolVersion": (mcp_wire::MODERN_PROTOCOL_VERSION)
                    }),
                )
            } else {
                doctor_mock_response(request, None)
            }
        });
        let report = run_doctor(&server.base_url, DoctorScope::Full).expect("doctor report");
        let _requests = finish_mock(server);
        assert_eq!(report_status(&report), Some("fail"));
        assert!(
            report
                .get("failures")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|failure| failure.contains("expected 405"))
        );
    }
    #[test]
    fn doctor_reports_bounded_mcp_application_error_codes() {
        let payload = norito::json!({
            "jsonrpc": "2.0", "id": 2,
            "error": {"code": (-32000_i64), "message": "do-not-forward-server-message",
                "data": {"error_code": "response_too_large", "private": "do-not-forward-data"}}
        });
        let error = mcp_tool_names(Some(&payload)).expect_err("MCP application error");
        assert!(error.contains("code=-32000") && error.contains("error_code=response_too_large"));
        assert!(!error.contains("do-not-forward"));
        for value in [
            Value::from("injected\ncode"),
            Value::from("x".repeat(65)),
            Value::Bool(false),
        ] {
            let mut invalid = payload.clone();
            *invalid.pointer_mut("/error/data/error_code").unwrap() = value;
            let error = mcp_tool_names(Some(&invalid)).unwrap_err();
            assert!(error.contains("error_code=unspecified"));
        }
    }

    #[test]
    fn doctor_rejects_unknown_namespaces_or_malformed_mcp_tools() {
        for hostile_tool in [
            norito::json!({"name": "connect.legacy", "description": "retired"}),
            norito::json!({"name": "torii.get-v1-accounts", "description": "malformed"}),
            norito::json!({"description": "missing name"}),
            norito::json!({"name": (REQUIRED_MCP_TOOLS[0]), "description": "duplicate"}),
        ] {
            let server = spawn_mock_http(16, move |request| {
                if request.method == "POST"
                    && path_only(&request.path) == "/v1/mcp"
                    && request.body.contains("tools/list")
                {
                    let mut response = doctor_mock_response(request, None);
                    let mut payload: Value =
                        json::from_slice(&response.body).expect("mock tools/list JSON");
                    payload
                        .pointer_mut("/result/tools")
                        .and_then(Value::as_array_mut)
                        .expect("mock tools array")
                        .push(hostile_tool.clone());
                    response.body = json::to_vec(&payload).expect("encode mock tools/list JSON");
                    response
                } else {
                    doctor_mock_response(request, None)
                }
            });
            let report = run_doctor(&server.base_url, DoctorScope::Full).expect("doctor report");
            let _requests = finish_mock(server);
            assert_eq!(report_status(&report), Some("fail"));
        }
    }
    #[test]
    fn submit_failure_hints_cover_invalid_fee_intent_and_route_unavailable() {
        let invalid_fee = hint_submit_error(eyre!("invalid fee_payment intent"));
        assert!(format!("{invalid_fee:#}").contains("/v1/fees/quote"));
        let route = hint_submit_error(eyre!("route_unavailable"));
        assert!(format!("{route:#}").contains("ingress or lane routing"));
    }
    #[test]
    fn resolve_canary_signer_derives_account() {
        let key_pair = fixture_key_pair(3);
        let mut config = crate::fallback_config();
        config.key_pair = key_pair.clone();
        let signer = resolve_canary_signer(&config).expect("config signer");
        assert_eq!(
            signer.account_id,
            AccountId::new(key_pair.public_key().clone())
        );
    }
    #[test]
    fn canary_alias_is_one_canonical_key_derived_identity() {
        let key_pair = fixture_key_pair(7);
        let alias = canary_alias(key_pair.public_key());
        assert!(alias.starts_with("tairarolloutcanary"));
        assert!(alias.ends_with("@universal"));
        assert!(
            alias
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '@')
        );
        assert_eq!(alias, canary_alias(key_pair.public_key()));
    }
    #[test]
    fn public_root_requires_an_exact_origin() {
        assert_eq!(
            normalize_root_url(DEFAULT_PUBLIC_ROOT).expect("canonical public root"),
            DEFAULT_PUBLIC_ROOT
        );
        assert_eq!(
            normalize_root_url("http://127.0.0.1:18080").expect("canonical local origin"),
            "http://127.0.0.1:18080"
        );
        for invalid in [
            " https://taira.sora.org",
            "https://user@taira.sora.org",
            "https://taira.sora.org/",
            "https://taira.sora.org/path",
            "https://taira.sora.org?debug=1",
            "https://taira.sora.org#fragment",
            "HTTPS://TAIRA.SORA.ORG",
        ] {
            let _ = normalize_root_url(invalid)
                .expect_err("noncanonical public roots must fail closed");
        }
    }
    #[test]
    fn inrou_canary_requires_exact_taira_client_identity_before_publication() {
        let mut config = crate::fallback_config();
        config.chain = DEFAULT_CHAIN_ID.into();
        config.account_chain_discriminant = DEFAULT_CHAIN_DISCRIMINANT;
        ensure_canonical_taira_client_identity(&config).expect("canonical Taira identity");

        config.chain = "iroha3-taira".into();
        let chain_error = ensure_canonical_taira_client_identity(&config)
            .expect_err("retired chain alias must fail before publication");
        assert!(format!("{chain_error:#}").contains("requires canonical chain"));

        config.chain = DEFAULT_CHAIN_ID.into();
        config.account_chain_discriminant = DEFAULT_CHAIN_DISCRIMINANT + 1;
        let discriminant_error = ensure_canonical_taira_client_identity(&config)
            .expect_err("wrong Taira discriminant must fail before publication");
        assert!(format!("{discriminant_error:#}").contains("requires chain discriminant"));
    }
    #[test]
    fn fixture_key_pair_uses_checked_seed_derivation() {
        assert_eq!(fixture_key_pair(11).algorithm(), Algorithm::Ed25519);
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
}
