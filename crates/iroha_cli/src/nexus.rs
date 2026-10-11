//! Nexus helpers for lane governance, public lanes, and private settlement.
mod private_settlement_online_auditor;

use crate::{Run, RunContext};
use eyre::{Result, eyre};
use iroha::client::BorrowedKeyPairIdentityRequestSignerV1;
use iroha::data_model::nexus::{
    AtomicPrivateSettlementV1, PrivateSettlementCommitteeAuthorityV1,
    PrivateSettlementPhaseCertificateV1, PrivateSettlementPrepareBarrierV1,
    PrivateSettlementProvisionalLegMaterialV1, ValidatorCommitteeOperationV1,
};
use iroha_core::private_settlement::{
    PrivateSettlementAuditEvaluationV1, PrivateSettlementAuditPolicyEvaluatorV1,
    SoftwarePrivateSettlementAuditorKeyringCredentialsV1,
};
use iroha_crypto::{Hash, KeyPair};
use iroha_model_base::topology::LaneId;
use iroha_torii_shared::private_settlement_api::{
    PrivateSettlementAuditApprovalRequestV1, PrivateSettlementAuditorCapsuleRequestV1,
    PrivateSettlementBundleSubmitRequestV1, PrivateSettlementLegUploadRequestV1,
};
use norito::json::{Map, Value};
use std::{
    fmt::Write,
    path::{Path, PathBuf},
    str::FromStr as _,
};
use url::Url;

use self::private_settlement_online_auditor::{
    PrivateSettlementAuditorBusinessPolicyV1, coordinate_private_settlement_online_auditor_v1,
    load_private_settlement_audit_policy_v1, load_private_settlement_auditor_business_policy_v1,
    load_private_settlement_auditor_secret_v1, load_private_settlement_committee_authority_v1,
    load_private_settlement_pool_governance_v1,
};
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Show governance manifest status per lane
    LaneReport(LaneReportArgs),
    /// Inspect public-lane validator lifecycle and stake state
    #[command(subcommand)]
    PublicLane(PublicLaneCommand),
    /// Coordinate and inspect atomic private cross-dataspace settlement
    #[command(subcommand)]
    PrivateSettlement(PrivateSettlementCommand),
}
#[derive(clap::Args, Debug, Default)]
pub struct LaneReportArgs {
    /// Print a compact table instead of JSON
    #[arg(long, default_value_t = false)]
    pub summary: bool,
    /// Show only lanes that require a manifest but remain sealed
    #[arg(long, default_value_t = false)]
    pub only_missing: bool,
    /// Exit with non-zero status if any manifest is missing
    #[arg(long, default_value_t = false)]
    pub fail_on_sealed: bool,
}
#[derive(clap::Subcommand, Debug)]
pub enum PublicLaneCommand {
    /// List validators for a public lane with lifecycle hints
    Validators(PublicLaneValidatorsArgs),
    /// List bonded stake and pending unbonds for a public lane
    Stake(PublicLaneStakeArgs),
    /// Observe the current finality source and one target's frozen preparation and custody progress
    CommitteeStatus(PublicLaneCommitteeStatusArgs),
    /// Submit one reviewed credential preparation or seat admission
    CommitteeSubmit(PublicLaneCommitteeSubmitArgs),
}

/// Explicit target for the canonical public committee observation.
#[derive(clap::Args, Debug)]
pub struct PublicLaneCommitteeStatusArgs {
    /// Target scheduling epoch; the server cannot select a different epoch
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub target_epoch: u64,
}

/// Exact owner-authorized preparation operation, never an activation or cancellation.
#[derive(clap::Args, Debug)]
pub struct PublicLaneCommitteeSubmitArgs {
    /// Canonical Norito JSON ValidatorCommitteeOperationV1 reviewed before submission
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,
}

impl Run for PublicLaneCommitteeStatusArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = iroha::blocking::Client::from_client(context.client_from_config()?)?;
        let observation = client
            .nexus()
            .validator_committee(Some(self.target_epoch))?;
        // Retain the original finality attachments and all preparation evidence.
        // Callers must authenticate them before provisioning or authorizing keys.
        context.print_data(&observation)
    }
}

impl Run for PublicLaneCommitteeSubmitArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        use iroha::data_model::{isi::SetParameter, parameter::Parameter};

        // Both operations bind their exact frozen transition. Core reconstructs the
        // network-bound target generation and readiness challenge from that preparation.
        let operation: ValidatorCommitteeOperationV1 =
            crate::staking::load_committee_json(&self.file, "--file")?;
        let instruction = SetParameter::new(Parameter::Custom(operation.into_custom_parameter()));
        context.finish(vec![iroha::data_model::isi::InstructionBox::from(
            instruction,
        )])
    }
}

/// Atomic private-settlement Torii operations.
#[derive(clap::Subcommand, Debug)]
pub enum PrivateSettlementCommand {
    /// Persist provisional material on one validator and request its availability share
    AvailabilityShare(PrivateSettlementAvailabilityShareArgs),
    /// Ask one validator to verify, durably stage, and vote Prepare
    PrepareVote(PrivateSettlementPrepareVoteArgs),
    /// Ask one validator to verify the complete Prepare barrier and vote Commit
    CommitVote(PrivateSettlementCommitVoteArgs),
    /// Persist one exact Prepare or Commit certificate on a validator
    PhaseCertificate(PrivateSettlementPhaseCertificateArgs),
    /// Recover locally durable Prepare and Commit certificates as the sponsor
    PhaseCertificates(PrivateSettlementPhaseCertificatesArgs),
    /// Upload one certified encrypted leg
    LegUpload(PrivateSettlementLegUploadArgs),
    /// Read one authenticated redacted leg status
    LegStatus(PrivateSettlementDigestArgs),
    /// Fetch the restricted proof view as an exact committee identity
    CommitteeProof(PrivateSettlementDigestArgs),
    /// Fetch the encrypted capsule as an exact governed auditor identity
    AuditCapsule(PrivateSettlementAuditCapsuleArgs),
    /// Submit one purpose-separated auditor approval
    AuditApproval(PrivateSettlementAuditApprovalArgs),
    /// Fetch, decrypt, decide, sign, and quorum-submit one auditor approval
    AuditOnline(PrivateSettlementAuditOnlineArgs),
    /// Submit the exact sponsor-signed global finalization carrier
    BundleSubmit(PrivateSettlementJsonFileArgs),
    /// Read the public bundle lifecycle
    BundleStatus(PrivateSettlementBundleIdArgs),
    /// Read the public terminal receipt or pending marker
    BundleReceipt(PrivateSettlementBundleIdArgs),
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementAvailabilityShareArgs {
    /// Exact participant Torii root URL.
    #[arg(long)]
    pub endpoint: Url,
    /// Bounded Norito JSON `PrivateSettlementProvisionalLegMaterialV1` file.
    #[arg(long, value_name = "PATH")]
    pub material: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementPrepareVoteArgs {
    /// Exact participant Torii root URL.
    #[arg(long)]
    pub endpoint: Url,
    /// Bounded Norito JSON `AtomicPrivateSettlementV1` file.
    #[arg(long, value_name = "PATH")]
    pub manifest: PathBuf,
    /// Exact leg payload digest.
    #[arg(long)]
    pub payload_digest: String,
    /// Bounded Norito JSON four-validator authority file.
    #[arg(long, value_name = "PATH")]
    pub authority: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementCommitVoteArgs {
    /// Exact participant Torii root URL.
    #[arg(long)]
    pub endpoint: Url,
    /// Exact leg payload digest.
    #[arg(long)]
    pub payload_digest: String,
    /// Bounded Norito JSON complete Prepare barrier file.
    #[arg(long, value_name = "PATH")]
    pub barrier: PathBuf,
    /// Bounded Norito JSON four-validator authority file.
    #[arg(long, value_name = "PATH")]
    pub authority: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementPhaseCertificateArgs {
    /// Exact participant Torii root URL.
    #[arg(long)]
    pub endpoint: Url,
    /// Bounded Norito JSON `AtomicPrivateSettlementV1` file.
    #[arg(long, value_name = "PATH")]
    pub manifest: PathBuf,
    /// Exact leg payload digest.
    #[arg(long)]
    pub payload_digest: String,
    /// Bounded Norito JSON Prepare or Commit certificate file.
    #[arg(long, value_name = "PATH")]
    pub certificate: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementPhaseCertificatesArgs {
    /// Optional participant Torii root; defaults to the configured Torii URL.
    #[arg(long)]
    pub endpoint: Option<Url>,
    /// Exact leg payload digest.
    #[arg(long)]
    pub payload_digest: String,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementLegUploadArgs {
    /// Optional participant Torii root; defaults to the configured Torii URL.
    #[arg(long)]
    pub endpoint: Option<Url>,
    /// Bounded Norito JSON `PrivateSettlementLegUploadRequestV1` file.
    #[arg(long, value_name = "PATH")]
    pub request: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementDigestArgs {
    /// Exact leg payload digest.
    #[arg(long)]
    pub payload_digest: String,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementAuditCapsuleArgs {
    /// Exact leg payload digest.
    #[arg(long)]
    pub payload_digest: String,
    /// Absolute owner-only current governed auditor-policy file.
    #[arg(long, value_name = "PATH")]
    pub audit_policy: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementAuditApprovalArgs {
    /// Exact leg payload digest.
    #[arg(long)]
    pub payload_digest: String,
    /// Bounded Norito JSON `PrivateSettlementAuditApprovalRequestV1` file.
    #[arg(long, value_name = "PATH")]
    pub request: PathBuf,
}

/// Explicit fail-closed online-auditor decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum PrivateSettlementAuditDecisionV1 {
    /// Approve only after all cryptographic and governance checks pass.
    Approve,
    /// Decrypt and validate, but reject without creating or submitting an approval.
    Reject,
}

struct PrivateSettlementAuditDecisionPolicyV1<'a> {
    decision: PrivateSettlementAuditDecisionV1,
    business_policy: &'a PrivateSettlementAuditorBusinessPolicyV1,
}

impl PrivateSettlementAuditPolicyEvaluatorV1 for PrivateSettlementAuditDecisionPolicyV1<'_> {
    fn approves(&self, context: PrivateSettlementAuditEvaluationV1<'_>) -> bool {
        self.decision == PrivateSettlementAuditDecisionV1::Approve
            && self.business_policy.approves(context)
    }
}

/// End-to-end governed online-auditor operation.
#[derive(clap::Args, Debug)]
pub struct PrivateSettlementAuditOnlineArgs {
    /// Participant committee Torii root; repeat exactly four times.
    #[arg(long = "committee-endpoint", required = true)]
    pub committee_endpoints: Vec<Url>,
    /// Separately governed ordered four-validator committee authority record.
    #[arg(long, value_name = "PATH")]
    pub committee_authority: PathBuf,
    /// Exact leg payload digest.
    #[arg(long)]
    pub payload_digest: String,
    /// Absolute owner-only restricted Norito JSON pool-governance file.
    #[arg(long, value_name = "PATH")]
    pub pool_governance: PathBuf,
    /// Absolute owner-only current governed auditor-policy file.
    #[arg(long, value_name = "PATH")]
    pub audit_policy: PathBuf,
    /// Absolute owner-only Norito JSON hybrid decryption-key file.
    #[arg(long, value_name = "PATH")]
    pub auditor_decryption_key_file: PathBuf,
    /// Retired owner-only hybrid decryption-key file retained for audit; repeat as needed.
    #[arg(long = "auditor-retired-decryption-key-file", value_name = "PATH")]
    pub auditor_retired_decryption_key_files: Vec<PathBuf>,
    /// Absolute owner-only strict Norito JSON business-policy file.
    #[arg(long, value_name = "PATH")]
    pub business_policy: PathBuf,
    /// Explicit local decision in addition to the strict business policy.
    #[arg(long, value_enum)]
    pub decision: PrivateSettlementAuditDecisionV1,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementJsonFileArgs {
    /// Bounded Norito JSON request file.
    #[arg(long, value_name = "PATH")]
    pub request: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct PrivateSettlementBundleIdArgs {
    /// Exact public bundle identifier.
    #[arg(long)]
    pub bundle_id: String,
}
#[derive(clap::Args, Debug)]
pub struct PublicLaneValidatorsArgs {
    /// Public lane identifier (defaults to SINGLE lane)
    #[arg(long, value_name = "LANE", default_value_t = 0)]
    pub lane: u32,
    /// Render a compact table instead of raw JSON
    #[arg(long, default_value_t = false)]
    pub summary: bool,
}
#[derive(clap::Args, Debug)]
pub struct PublicLaneStakeArgs {
    /// Public lane identifier (defaults to SINGLE lane)
    #[arg(long, value_name = "LANE", default_value_t = 0)]
    pub lane: u32,
    /// Filter for a specific validator account (optional)
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub validator: Option<String>,
    /// Render a compact table instead of raw JSON
    #[arg(long, default_value_t = false)]
    pub summary: bool,
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::LaneReport(args) => lane_report(context, &args),
            Command::PublicLane(cmd) => match cmd {
                PublicLaneCommand::Validators(args) => public_lane_validators(context, &args),
                PublicLaneCommand::Stake(args) => public_lane_stake(context, &args),
                PublicLaneCommand::CommitteeStatus(args) => args.run(context),
                PublicLaneCommand::CommitteeSubmit(args) => args.run(context),
            },
            Command::PrivateSettlement(command) => private_settlement(context, command),
        }
    }
}

fn read_private_settlement_json<T>(path: &Path, label: &str) -> Result<T>
where
    T: norito::json::JsonDeserialize,
{
    let json = crate::read_cli_text_file_bounded(path, label)?;
    crate::parse_json(&json).map_err(|error| eyre!("invalid {label}: {error}"))
}

fn private_settlement_digest(literal: &str, label: &str) -> Result<Hash> {
    Hash::from_str(literal).map_err(|_| eyre!("{label} must be an exact bare hash string"))
}

fn private_settlement_operator_key<C: RunContext>(context: &C) -> Result<KeyPair> {
    context.operator_key_pair().cloned().ok_or_else(|| {
        eyre!("this restricted private-settlement operation requires --operator-private-key-file")
    })
}

fn private_settlement<C: RunContext>(
    context: &mut C,
    command: PrivateSettlementCommand,
) -> Result<()> {
    let client = context.client_from_config()?;
    match command {
        PrivateSettlementCommand::AvailabilityShare(args) => {
            let material: PrivateSettlementProvisionalLegMaterialV1 =
                read_private_settlement_json(&args.material, "private-settlement material")?;
            let response = client
                .request_private_settlement_availability_share_v1(&args.endpoint, &material)?;
            context.print_data(&response)
        }
        PrivateSettlementCommand::PrepareVote(args) => {
            let manifest: AtomicPrivateSettlementV1 =
                read_private_settlement_json(&args.manifest, "private-settlement manifest")?;
            let authority: PrivateSettlementCommitteeAuthorityV1 =
                read_private_settlement_json(&args.authority, "private-settlement authority")?;
            let payload_digest = private_settlement_digest(&args.payload_digest, "payload digest")?;
            let response = client.request_private_settlement_prepare_vote_v1(
                &args.endpoint,
                &manifest,
                payload_digest,
                &authority,
            )?;
            context.print_data(&response)
        }
        PrivateSettlementCommand::CommitVote(args) => {
            let barrier: PrivateSettlementPrepareBarrierV1 =
                read_private_settlement_json(&args.barrier, "private-settlement Prepare barrier")?;
            let authority: PrivateSettlementCommitteeAuthorityV1 =
                read_private_settlement_json(&args.authority, "private-settlement authority")?;
            let payload_digest = private_settlement_digest(&args.payload_digest, "payload digest")?;
            let response = client.request_private_settlement_commit_vote_v1(
                &args.endpoint,
                payload_digest,
                &barrier,
                &authority,
            )?;
            context.print_data(&response)
        }
        PrivateSettlementCommand::PhaseCertificate(args) => {
            let manifest: AtomicPrivateSettlementV1 =
                read_private_settlement_json(&args.manifest, "private-settlement manifest")?;
            let certificate: PrivateSettlementPhaseCertificateV1 = read_private_settlement_json(
                &args.certificate,
                "private-settlement phase certificate",
            )?;
            let payload_digest = private_settlement_digest(&args.payload_digest, "payload digest")?;
            let response = client.persist_private_settlement_phase_certificate_v1(
                &args.endpoint,
                &manifest,
                payload_digest,
                &certificate,
            )?;
            context.print_data(&response)
        }
        PrivateSettlementCommand::PhaseCertificates(args) => {
            let payload_digest = private_settlement_digest(&args.payload_digest, "payload digest")?;
            let response = if let Some(endpoint) = args.endpoint {
                client.private_settlement_phase_certificates_from_v1(&endpoint, payload_digest)?
            } else {
                client.private_settlement_phase_certificates_v1(payload_digest)?
            };
            context.print_data(&response)
        }
        PrivateSettlementCommand::LegUpload(args) => {
            let request: PrivateSettlementLegUploadRequestV1 =
                read_private_settlement_json(&args.request, "private-settlement leg upload")?;
            let response = if let Some(endpoint) = args.endpoint {
                client.upload_private_settlement_leg_to_v1(&endpoint, &request)?
            } else {
                client.upload_private_settlement_leg_v1(&request)?
            };
            context.print_data(&response)
        }
        PrivateSettlementCommand::LegStatus(args) => {
            let payload_digest = private_settlement_digest(&args.payload_digest, "payload digest")?;
            context.print_data(&client.private_settlement_leg_status_v1(payload_digest)?)
        }
        PrivateSettlementCommand::CommitteeProof(args) => {
            let role_key = private_settlement_operator_key(context)?;
            let payload_digest = private_settlement_digest(&args.payload_digest, "payload digest")?;
            context.print_data(
                &client.private_settlement_committee_proof_v1(payload_digest, &role_key)?,
            )
        }
        PrivateSettlementCommand::AuditCapsule(args) => {
            let role_key = private_settlement_operator_key(context)?;
            let payload_digest = private_settlement_digest(&args.payload_digest, "payload digest")?;
            let request = PrivateSettlementAuditorCapsuleRequestV1 {
                audit_policy: load_private_settlement_audit_policy_v1(&args.audit_policy)?,
            };
            context.print_data(&client.private_settlement_auditor_capsule_v1(
                payload_digest,
                &request,
                &role_key,
            )?)
        }
        PrivateSettlementCommand::AuditApproval(args) => {
            let role_key = private_settlement_operator_key(context)?;
            let payload_digest = private_settlement_digest(&args.payload_digest, "payload digest")?;
            let request: PrivateSettlementAuditApprovalRequestV1 =
                read_private_settlement_json(&args.request, "private-settlement audit approval")?;
            context.print_data(&client.submit_private_settlement_audit_approval_v1(
                payload_digest,
                &role_key,
                &request,
            )?)
        }
        PrivateSettlementCommand::AuditOnline(args) => {
            let role_key = private_settlement_operator_key(context)?;
            let payload_digest = private_settlement_digest(&args.payload_digest, "payload digest")?;
            let committee_authority =
                load_private_settlement_committee_authority_v1(&args.committee_authority)?;
            let pool_governance =
                load_private_settlement_pool_governance_v1(&args.pool_governance)?;
            let audit_policy = load_private_settlement_audit_policy_v1(&args.audit_policy)?;
            let mut decryption_secrets = Vec::with_capacity(
                1_usize.saturating_add(args.auditor_retired_decryption_key_files.len()),
            );
            decryption_secrets.push(load_private_settlement_auditor_secret_v1(
                &args.auditor_decryption_key_file,
            )?);
            for retired_path in &args.auditor_retired_decryption_key_files {
                decryption_secrets.push(load_private_settlement_auditor_secret_v1(retired_path)?);
            }
            let business_policy =
                load_private_settlement_auditor_business_policy_v1(&args.business_policy)?;
            let credentials = SoftwarePrivateSettlementAuditorKeyringCredentialsV1::new(
                &decryption_secrets,
                &role_key,
            )
            .map_err(|_| eyre!("private-settlement auditor decryption-key keyring is invalid"))?;
            let request_signer = BorrowedKeyPairIdentityRequestSignerV1::new(&role_key);
            let evaluator = PrivateSettlementAuditDecisionPolicyV1 {
                decision: args.decision,
                business_policy: &business_policy,
            };
            let response = coordinate_private_settlement_online_auditor_v1(
                &client,
                &args.committee_endpoints,
                &committee_authority,
                payload_digest,
                &audit_policy,
                &pool_governance,
                &credentials,
                &request_signer,
                &evaluator,
            )?;
            context.print_data(&response)
        }
        PrivateSettlementCommand::BundleSubmit(args) => {
            let request: PrivateSettlementBundleSubmitRequestV1 =
                read_private_settlement_json(&args.request, "private-settlement bundle carrier")?;
            context.print_data(&client.submit_private_settlement_bundle_v1(&request)?)
        }
        PrivateSettlementCommand::BundleStatus(args) => {
            let bundle_id = private_settlement_digest(&args.bundle_id, "bundle id")?;
            context.print_data(&client.private_settlement_bundle_status_v1(bundle_id)?)
        }
        PrivateSettlementCommand::BundleReceipt(args) => {
            let bundle_id = private_settlement_digest(&args.bundle_id, "bundle id")?;
            context.print_data(&client.private_settlement_bundle_receipt_v1(bundle_id)?)
        }
    }
}
fn lane_report<C: RunContext>(context: &mut C, args: &LaneReportArgs) -> Result<()> {
    let client = context.client_from_config()?;
    let operator_key = context
        .operator_key_pair()
        .cloned()
        .ok_or_else(|| eyre::eyre!("consensus diagnostics require --operator-private-key-file"))?;
    let operator =
        iroha::blocking::OperatorClient::from_client(client.operator_client(operator_key)?)?;
    let status = operator.consensus().diagnostics()?;
    let sealed_count = status.lane_governance_sealed_total;
    let sealed_aliases = status.lane_governance_sealed_aliases;
    let lanes = norito::json::to_value(&status.lane_governance)?;
    let filtered_lanes = if args.only_missing {
        filter_lane_entries(lanes, true)
    } else {
        lanes
    };
    if args.summary {
        context.println(format_lane_summary(&filtered_lanes, args.only_missing))?;
    } else {
        let mut map = Map::new();
        map.insert("sealed_total".into(), Value::from(u64::from(sealed_count)));
        map.insert(
            "sealed_aliases".into(),
            Value::Array(sealed_aliases.into_iter().map(Value::from).collect()),
        );
        map.insert("lanes".into(), filtered_lanes);
        context.print_data(&Value::Object(map))?;
    }
    if args.fail_on_sealed && sealed_count > 0 {
        return Err(eyre!(
            "{sealed_count} lane(s) still sealed (governance manifest missing)"
        ));
    }
    Ok(())
}
fn public_lane_validators<C: RunContext>(
    context: &mut C,
    args: &PublicLaneValidatorsArgs,
) -> Result<()> {
    let client = context.client_from_config()?;
    let payload = client.get_public_lane_validators(LaneId::new(args.lane))?;
    if args.summary {
        context.println(format_validator_summary(&payload)?)?;
    } else {
        context.print_data(&payload)?;
    }
    Ok(())
}
fn public_lane_stake<C: RunContext>(context: &mut C, args: &PublicLaneStakeArgs) -> Result<()> {
    let client = context.client_from_config()?;
    let validator = args
        .validator
        .as_deref()
        .map(|literal| crate::resolve_account_id(context, literal))
        .transpose()?
        .map(|account| account.to_string());
    let payload = client.get_public_lane_stake(LaneId::new(args.lane), validator.as_deref())?;
    if args.summary {
        context.println(format_stake_summary(&payload)?)?;
    } else {
        context.print_data(&payload)?;
    }
    Ok(())
}
fn filter_lane_entries(value: Value, only_missing: bool) -> Value {
    if !only_missing {
        return value;
    }
    if let Value::Array(entries) = value {
        let filtered: Vec<_> = entries.into_iter().filter(lane_still_sealed).collect();
        Value::Array(filtered)
    } else {
        value
    }
}
fn lane_still_sealed(entry: &Value) -> bool {
    let Some(map) = entry.as_object() else {
        return false;
    };
    let required = map
        .get("manifest_required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let ready = map
        .get("manifest_ready")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    required && !ready
}
fn format_lane_summary(value: &Value, only_missing: bool) -> String {
    let Some(array) = value.as_array() else {
        return "No lane governance entries returned.".to_string();
    };
    if array.is_empty() {
        return if only_missing {
            "All governance manifests are provisioned.".to_string()
        } else {
            "No lane governance entries returned.".to_string()
        };
    }
    let mut rows = Vec::with_capacity(array.len());
    for entry in array {
        if let Some(map) = entry.as_object() {
            rows.push(build_lane_row(map));
        }
    }
    if rows.is_empty() {
        return if only_missing {
            "All governance manifests are provisioned.".to_string()
        } else {
            "No lane governance entries returned.".to_string()
        };
    }
    let header = format!(
        "{:>4}  {:<16}  {:<16}  {:<7}  {:>6}  {:>10}  {}",
        "ID", "ALIAS", "MODULE", "STATUS", "QUORUM", "VALIDATORS", "DETAIL"
    );
    let mut formatted = String::with_capacity((rows.len() + 1) * header.len());
    formatted.push_str(&header);
    formatted.push('\n');
    for row in rows {
        formatted.push_str(&row);
        formatted.push('\n');
    }
    formatted.trim_end().to_string()
}
fn build_lane_row(entry: &Map) -> String {
    let lane_id = entry
        .get("lane_id")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let alias = entry
        .get("alias")
        .and_then(Value::as_str)
        .map_or_else(|| "-".to_string(), normalize_width);
    let module = entry
        .get("governance")
        .and_then(Value::as_str)
        .map_or_else(|| "-".to_string(), normalize_width);
    let manifest_required = entry
        .get("manifest_required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let manifest_ready = entry
        .get("manifest_ready")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let status = if manifest_required {
        if manifest_ready { "READY" } else { "SEALED" }
    } else {
        "N/A"
    };
    let quorum = entry
        .get("quorum")
        .and_then(Value::as_u64)
        .map_or_else(|| "-".to_string(), |q| q.to_string());
    let validator_count = entry
        .get("validator_ids")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let validators = validator_count.to_string();
    let detail = lane_detail(entry, manifest_required, manifest_ready);
    format!(
        "{lane_id:>4}  {alias:<16}  {module:<16}  {status:<7}  {quorum:>6}  {validators:>10}  {detail}"
    )
}
fn lane_detail(entry: &Map, manifest_required: bool, manifest_ready: bool) -> String {
    if !manifest_required {
        return "governance not configured".to_string();
    }
    if manifest_ready {
        if let Some(path) = entry
            .get("manifest_path")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
        {
            return path.to_string();
        }
        return "manifest loaded".to_string();
    }
    "manifest missing".to_string()
}
fn format_validator_summary(payload: &Value) -> Result<String> {
    let mut entries = lane_items(payload)?;
    if entries.is_empty() {
        return Ok("No validator entries returned.".to_string());
    }
    entries.sort_by(|lhs, rhs| {
        let l_val = lhs.get("validator").and_then(Value::as_str).unwrap_or("");
        let r_val = rhs.get("validator").and_then(Value::as_str).unwrap_or("");
        l_val.cmp(r_val)
    });
    let rows: Vec<_> = entries.into_iter().map(build_validator_row).collect();
    // Heights and status details must remain readable even at the u64 boundary.
    let status_width = rows
        .iter()
        .map(|row| row.status.len())
        .max()
        .unwrap_or(0)
        .max(18);
    let tenure_width = rows
        .iter()
        .map(|row| row.tenure.len())
        .max()
        .unwrap_or(0)
        .max(22);
    let mut output = String::new();
    writeln!(
        &mut output,
        "{:<36}  {:<24}  {:<status_width$}  {:<tenure_width$}  {:<20}",
        "VALIDATOR", "PEER_ID", "STATUS", "TENURE", "STAKE"
    )?;
    for row in rows {
        writeln!(
            &mut output,
            "{:<36}  {:<24}  {:<status_width$}  {:<tenure_width$}  {:<20}",
            truncate_field(&row.validator, 36),
            truncate_field(&row.peer_id, 24),
            row.status,
            row.tenure,
            truncate_field(&row.stake, 20),
        )?;
    }
    Ok(output.trim_end().to_string())
}
fn format_stake_summary(payload: &Value) -> Result<String> {
    let mut entries = lane_items(payload)?;
    if entries.is_empty() {
        return Ok("No stake entries returned.".to_string());
    }
    entries.sort_by(|lhs, rhs| {
        let l_val = lhs.get("validator").and_then(Value::as_str).unwrap_or("");
        let r_val = rhs.get("validator").and_then(Value::as_str).unwrap_or("");
        l_val.cmp(r_val).then_with(|| {
            let l_staker = lhs.get("staker").and_then(Value::as_str).unwrap_or("");
            let r_staker = rhs.get("staker").and_then(Value::as_str).unwrap_or("");
            l_staker.cmp(r_staker)
        })
    });
    let mut output = String::new();
    writeln!(
        &mut output,
        "{:<32}  {:<32}  {:>14}  {:<22}",
        "VALIDATOR", "STAKER", "BONDED", "PENDING_UNBONDS"
    )?;
    for entry in entries {
        let row = build_stake_row(entry);
        writeln!(
            &mut output,
            "{:<32}  {:<32}  {:>14}  {:<22}",
            truncate_field(&row.validator, 32),
            truncate_field(&row.staker, 32),
            row.bonded,
            truncate_field(&row.pending_unbonds, 22),
        )?;
    }
    Ok(output.trim_end().to_string())
}
fn lane_items(payload: &Value) -> Result<Vec<&Map>> {
    let Some(items) = payload.get("items").and_then(Value::as_array) else {
        return Err(eyre!(
            "public lane response missing `items` array; unexpected payload shape"
        ));
    };
    let mut mapped = Vec::with_capacity(items.len());
    for item in items {
        let Some(map) = item.as_object() else {
            return Err(eyre!("public lane item was not an object"));
        };
        mapped.push(map);
    }
    Ok(mapped)
}
struct ValidatorRow {
    validator: String,
    peer_id: String,
    status: String,
    tenure: String,
    stake: String,
}
fn build_validator_row(entry: &Map) -> ValidatorRow {
    let validator = entry
        .get("validator")
        .and_then(Value::as_str)
        .unwrap_or("-")
        .to_string();
    let peer_id = entry
        .get("peer_id")
        .and_then(Value::as_str)
        .unwrap_or("-")
        .to_string();
    let status = validator_status_label(entry.get("status"));
    let tenure = tenure_label(entry);
    let total_stake = entry
        .get("total_stake")
        .map_or_else(|| "-".to_string(), stringify_value);
    let self_stake = entry
        .get("self_stake")
        .map_or_else(|| "-".to_string(), stringify_value);
    let stake = format!("{total_stake} (self {self_stake})");
    ValidatorRow {
        validator,
        peer_id,
        status,
        tenure,
        stake,
    }
}
fn validator_status_label(status: Option<&Value>) -> String {
    let Some(map) = status.and_then(Value::as_object) else {
        return "-".to_string();
    };
    let Some(kind) = map.get("type").and_then(Value::as_str) else {
        return "-".to_string();
    };
    match kind {
        "PendingActivation" => {
            let height = map
                .get("activates_at_height")
                .and_then(Value::as_u64)
                .map_or_else(String::new, |v| format!("height {v}"));
            if height.is_empty() {
                "Pending".to_string()
            } else {
                format!("Pending({height})")
            }
        }
        "Active" => "Active".to_string(),
        "Exiting" => map
            .get("releases_at_ms")
            .and_then(Value::as_u64)
            .map_or_else(|| "Exiting".to_string(), |ts| format!("Exiting({ts})")),
        "Exited" => "Exited".to_string(),
        "Slashed" => map.get("slash_id").and_then(Value::as_str).map_or_else(
            || "Slashed".to_string(),
            |id| format!("Slashed({})", truncate_field(id, 14)),
        ),
        other => truncate_field(other, 18),
    }
}
fn tenure_label(entry: &Map) -> String {
    let activation = entry.get("activation_height").and_then(Value::as_u64);
    let deactivation = entry.get("deactivation_height").and_then(Value::as_u64);
    match (activation, deactivation) {
        (Some(start), Some(end)) => format!("heights [{start}, {end})"),
        (Some(start), None) => format!("height {start}+"),
        _ => "-".to_string(),
    }
}
struct StakeRow {
    validator: String,
    staker: String,
    bonded: String,
    pending_unbonds: String,
}
fn build_stake_row(entry: &Map) -> StakeRow {
    let validator = entry
        .get("validator")
        .and_then(Value::as_str)
        .unwrap_or("-")
        .to_string();
    let staker = entry
        .get("staker")
        .and_then(Value::as_str)
        .unwrap_or("-")
        .to_string();
    let bonded = entry
        .get("bonded")
        .map_or_else(|| "-".to_string(), stringify_value);
    let pending_unbonds = pending_unbond_label(entry);
    StakeRow {
        validator,
        staker,
        bonded,
        pending_unbonds,
    }
}
fn pending_unbond_label(entry: &Map) -> String {
    let Some(pending) = entry.get("pending_unbonds").and_then(Value::as_array) else {
        return "-".to_string();
    };
    if pending.is_empty() {
        return "-".to_string();
    }
    let mut next_release: Option<u64> = None;
    for item in pending {
        if let Some(release_at) = item
            .as_object()
            .and_then(|map| map.get("release_at_ms"))
            .and_then(Value::as_u64)
        {
            next_release = Some(next_release.map_or(release_at, |current| current.min(release_at)));
        }
    }
    next_release.map_or_else(
        || format!("{} pending", pending.len()),
        |ts| format!("{} pending (next @ {ts})", pending.len()),
    )
}
fn stringify_value(value: &Value) -> String {
    if let Some(as_str) = value.as_str() {
        return as_str.to_owned();
    }
    norito::json::to_string(value).unwrap_or_else(|_| "-".to_string())
}
fn truncate_field(value: &str, max_len: usize) -> String {
    value.chars().take(max_len).collect()
}
fn normalize_width(value: &str) -> String {
    const MAX_LEN: usize = 16;
    value.chars().take(MAX_LEN).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    fn fixture_account_i105(seed: u8) -> String {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair");
        iroha::data_model::account::AccountId::new(key_pair.public_key().clone())
            .canonical_i105()
            .expect("canonical I105")
    }
    #[test]
    fn fixture_account_i105_uses_checked_seed_derivation() {
        assert!(!fixture_account_i105(0x10).is_empty());
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }

    #[test]
    fn private_settlement_digest_parser_is_exact() {
        let expected = Hash::prehashed([0x42; Hash::LENGTH]);
        assert_eq!(
            private_settlement_digest(&expected.to_string(), "bundle id")
                .expect("canonical digest"),
            expected
        );
        assert!(private_settlement_digest("not-a-hash", "bundle id").is_err());
    }

    #[test]
    fn private_settlement_cli_exposes_sponsor_phase_recovery() {
        let command = <PrivateSettlementCommand as clap::Subcommand>::augment_subcommands(
            clap::Command::new("private-settlement"),
        );
        let recovery = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "phase-certificates")
            .expect("phase-certificate recovery subcommand");
        let argument_ids = recovery
            .get_arguments()
            .map(|argument| argument.get_id().as_str())
            .collect::<Vec<_>>();
        assert!(argument_ids.contains(&"endpoint"));
        assert!(argument_ids.contains(&"payload_digest"));
    }

    #[test]
    fn private_settlement_cli_exposes_fail_closed_online_auditor_inputs() {
        let command = <PrivateSettlementCommand as clap::Subcommand>::augment_subcommands(
            clap::Command::new("private-settlement"),
        );
        let online = command
            .get_subcommands()
            .find(|subcommand| subcommand.get_name() == "audit-online")
            .expect("online auditor subcommand");
        let argument_ids = online
            .get_arguments()
            .map(|argument| argument.get_id().as_str())
            .collect::<Vec<_>>();
        for required in [
            "committee_endpoints",
            "committee_authority",
            "payload_digest",
            "pool_governance",
            "audit_policy",
            "auditor_decryption_key_file",
            "auditor_retired_decryption_key_files",
            "business_policy",
            "decision",
        ] {
            assert!(argument_ids.contains(&required), "missing {required}");
        }
        let decision = online
            .get_arguments()
            .find(|argument| argument.get_id().as_str() == "decision")
            .expect("explicit decision argument");
        assert!(decision.is_required_set());
        let business_policy = online
            .get_arguments()
            .find(|argument| argument.get_id().as_str() == "business_policy")
            .expect("strict business-policy argument");
        assert!(business_policy.is_required_set());
        let committee_authority = online
            .get_arguments()
            .find(|argument| argument.get_id().as_str() == "committee_authority")
            .expect("governed committee-authority argument");
        assert!(committee_authority.is_required_set());
    }

    #[test]
    fn lane_summary_formats_rows() {
        let entry = Map::from_iter([
            ("lane_id".into(), Value::from(2u64)),
            ("alias".into(), Value::from("governance")),
            ("governance".into(), Value::from("parliament")),
            ("manifest_required".into(), Value::from(true)),
            ("manifest_ready".into(), Value::from(false)),
            ("quorum".into(), Value::from(3u64)),
            (
                "validator_ids".into(),
                Value::Array(vec![
                    Value::from("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"),
                    Value::from("sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"),
                ]),
            ),
            ("manifest_path".into(), Value::Null),
        ]);
        let value = Value::Array(vec![Value::Object(entry)]);
        let table = format_lane_summary(&value, false);
        assert!(table.contains("SEALED"));
        assert!(table.contains("manifest missing"));
    }
    #[test]
    fn lane_summary_handles_empty() {
        let value = Value::Array(Vec::new());
        let table = format_lane_summary(&value, false);
        assert_eq!(table, "No lane governance entries returned.");
        let filtered = format_lane_summary(&value, true);
        assert_eq!(filtered, "All governance manifests are provisioned.");
    }
    #[test]
    fn filter_removes_ready_lanes() {
        let sealed = Map::from_iter([
            ("lane_id".into(), Value::from(1u64)),
            ("alias".into(), Value::from("sealed")),
            ("governance".into(), Value::from("parliament")),
            ("manifest_required".into(), Value::from(true)),
            ("manifest_ready".into(), Value::from(false)),
        ]);
        let ready = Map::from_iter([
            ("lane_id".into(), Value::from(2u64)),
            ("alias".into(), Value::from("ready")),
            ("governance".into(), Value::from("parliament")),
            ("manifest_required".into(), Value::from(true)),
            ("manifest_ready".into(), Value::from(true)),
        ]);
        let filtered = filter_lane_entries(
            Value::Array(vec![Value::Object(sealed), Value::Object(ready)]),
            true,
        );
        match &filtered {
            Value::Array(entries) => {
                assert_eq!(entries.len(), 1);
                let map = entries[0].as_object().expect("object");
                assert_eq!(map.get("alias").and_then(Value::as_str), Some("sealed"));
            }
            _ => panic!("expected array"),
        }
        let summary = format_lane_summary(&filtered, true);
        assert!(summary.contains("sealed"));
        assert!(!summary.contains("ready"));
    }
    #[test]
    fn validator_summary_formats_activation_and_status() {
        let validator = fixture_account_i105(0x11);
        let record = Map::from_iter([
            ("lane_id".into(), Value::from(0u64)),
            ("validator".into(), Value::from(validator.clone())),
            ("stake_account".into(), Value::from(validator.clone())),
            ("total_stake".into(), Value::from("1000")),
            ("self_stake".into(), Value::from("800")),
            (
                "status".into(),
                Value::Object(Map::from_iter([
                    ("type".into(), Value::from("PendingActivation")),
                    ("activates_at_height".into(), Value::from(3601u64)),
                ])),
            ),
            ("activation_height".into(), Value::from(3601u64)),
            ("deactivation_height".into(), Value::from(7201u64)),
        ]);
        let payload = Value::Object(Map::from_iter([
            ("lane_id".into(), Value::from(0u64)),
            ("total".into(), Value::from(1u64)),
            ("items".into(), Value::Array(vec![Value::Object(record)])),
        ]));
        let summary = format_validator_summary(&payload).expect("format summary");
        assert!(summary.contains(&truncate_field(&validator, 36)));
        assert!(summary.contains("Pending(height 3601)"));
        assert!(summary.contains("heights [3601, 7201)"));
        assert!(summary.contains("1000 (self 800)"));
    }
    #[test]
    fn validator_summary_preserves_full_height_boundaries() {
        let activation_height = u64::MAX - 1;
        let deactivation_height = u64::MAX;
        let payload = norito::json!({
            "items": [{
                "status": {"type": "PendingActivation", "activates_at_height": activation_height},
                "activation_height": activation_height,
                "deactivation_height": deactivation_height,
            }],
        });
        let summary = format_validator_summary(&payload).expect("format maximum-height summary");
        assert!(summary.contains(&format!("Pending(height {})", u64::MAX - 1)));
        assert!(summary.contains(&format!("heights [{}, {})", u64::MAX - 1, u64::MAX)));
    }
    #[test]
    fn validator_summary_bounds_unknown_status_width() {
        let status = "x".repeat(1024);
        let payload = norito::json!({"items": [{"status": {"type": status}}]});
        let summary = format_validator_summary(&payload).expect("format unknown status summary");
        assert!(summary.contains(&truncate_field(&status, 18)));
        assert!(summary.lines().all(|line| line.len() < 200));
    }
    #[test]
    fn stake_summary_marks_pending_unbonds() {
        let validator = fixture_account_i105(0x12);
        let staker = fixture_account_i105(0x13);
        let pending = Map::from_iter([
            ("request_id".into(), Value::from("deadbeef")),
            ("amount".into(), Value::from("250")),
            ("release_at_ms".into(), Value::from(10u64)),
        ]);
        let record = Map::from_iter([
            ("lane_id".into(), Value::from(0u64)),
            ("validator".into(), Value::from(validator.clone())),
            ("staker".into(), Value::from(staker.clone())),
            ("bonded".into(), Value::from("750")),
            (
                "pending_unbonds".into(),
                Value::Array(vec![Value::Object(pending)]),
            ),
        ]);
        let payload = Value::Object(Map::from_iter([
            ("lane_id".into(), Value::from(0u64)),
            ("total".into(), Value::from(1u64)),
            ("items".into(), Value::Array(vec![Value::Object(record)])),
        ]));
        let summary = format_stake_summary(&payload).expect("format summary");
        assert!(summary.contains(&truncate_field(&validator, 32)));
        assert!(summary.contains(&truncate_field(&staker, 32)));
        assert!(summary.contains("750"));
        assert!(summary.contains("pending (next @ 10)"));
    }
    #[test]
    fn normalize_width_preserves_short_values() {
        assert_eq!(normalize_width("governance"), "governance");
    }
    #[test]
    fn normalize_width_truncates_unicode_on_char_boundary() {
        let input = "いろはにほへとちりぬるをわかよたれそ";
        let expected = "いろはにほへとちりぬるをわかよた";
        assert_eq!(normalize_width(input), expected);
    }
}
