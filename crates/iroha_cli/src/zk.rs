//! ZK convenience commands for the CLI (experimental/app API).
#![allow(
    clippy::struct_excessive_bools,
    clippy::explicit_iter_loop,
    clippy::option_if_let_else,
    clippy::nonminimal_bool,
    clippy::explicit_into_iter_loop,
    clippy::needless_collect,
    clippy::ignored_unit_patterns,
    clippy::too_many_lines,
    clippy::map_unwrap_or,
    clippy::redundant_closure_for_method_calls,
    clippy::redundant_closure,
    clippy::cast_possible_truncation,
    clippy::uninlined_format_args,
    unused_imports
)]
// Current allowances cover the data-munging helpers used by the ZK CLI.
// They stay until the module is decomposed and the conversion helpers are refactored.
//!
//! Provides thin wrappers over Torii app endpoints for ZK features. These are
//! intended for operator/testing convenience and are not consensus-critical.
use eyre::{Context, Result};
use std::{fs::File, path::Path};
// For base64 Engine trait (decode)
use crate::{Run, RunContext, json_utils};
use base64::Engine as _;
use iroha::data_model::prelude::{Executable, InstructionBox};
use iroha::{
    blocking::Client as BlockingClient,
    client::{Client, ZkProofsFilter},
};
// Proof/attachment tooling shares the first-release CLI's 64 MiB local-input
// corridor. Backend-specific VK inputs use the stricter 8 MiB protocol cap.
// JSON and Norito decoders additionally receive explicit graph/allocation
// limits so a short hostile frame cannot request a much larger heap.
const ZK_CLI_INPUT_MAX_BYTES_V1: usize = super::MAX_CLI_STDIN_BYTES_V1;
const ZK_CLI_JSON_MAX_SEQUENCE_ELEMENTS_V1: usize = 65_536;
const ZK_CLI_JSON_MAX_TOTAL_ELEMENTS_V1: usize = 4 * ZK_CLI_JSON_MAX_SEQUENCE_ELEMENTS_V1;
const ZK_CLI_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 128 * 1024 * 1024;
const ZK_CLI_JSON_MAX_NESTING_DEPTH_V1: usize = norito::json::MAX_JSON_VALUE_NESTING_DEPTH;
const ZK_CLI_JSON_DECODE_LIMITS_V1: norito::DecodeLimits = norito::DecodeLimits::new(
    ZK_CLI_JSON_MAX_SEQUENCE_ELEMENTS_V1,
    ZK_CLI_INPUT_MAX_BYTES_V1,
    ZK_CLI_JSON_MAX_TOTAL_ELEMENTS_V1,
    ZK_CLI_MAX_DECODE_ALLOCATION_BYTES_V1,
    ZK_CLI_JSON_MAX_NESTING_DEPTH_V1,
);
fn read_zk_file_bounded(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).wrap_err_with(|| format!("failed to open {label} {}", path.display()))?;
    let before = file
        .metadata()
        .wrap_err_with(|| format!("failed to inspect {label} {}", path.display()))?;
    if !before.is_file() {
        eyre::bail!("{label} must be a regular file: {}", path.display());
    }
    if before.len() > max_bytes as u64 {
        eyre::bail!(
            "{label} {} exceeds the first-release limit of {} bytes",
            path.display(),
            max_bytes
        );
    }
    let bytes = super::read_cli_input_bounded(&mut file, max_bytes, label)
        .wrap_err_with(|| format!("failed to read {label} {}", path.display()))?;
    let after = file
        .metadata()
        .wrap_err_with(|| format!("failed to reinspect {label} {}", path.display()))?;
    if before.len() != after.len() || after.len() != bytes.len() as u64 {
        eyre::bail!("{label} changed while reading: {}", path.display());
    }
    Ok(bytes)
}
fn decode_zk_json_file<T>(path: &Path, label: &str) -> Result<T>
where
    T: norito::json::JsonDeserialize,
{
    let bytes = read_zk_file_bounded(path, ZK_CLI_INPUT_MAX_BYTES_V1, label)?;
    norito::json::preflight_slice(
        &bytes,
        norito::json::JsonPreflightLimits::from_decode_limits(
            ZK_CLI_INPUT_MAX_BYTES_V1,
            ZK_CLI_JSON_DECODE_LIMITS_V1,
        ),
    )
    .map_err(|error| eyre::eyre!("{label} JSON exceeds its lexical resource bounds: {error}"))?;
    norito::with_decode_limits_scope(ZK_CLI_JSON_DECODE_LIMITS_V1, || {
        norito::json::from_slice(&bytes)
    })
    .map_err(|error| eyre::eyre!("failed to decode {label} JSON: {error}"))
}
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Get recent shielded roots for an asset (JSON). Posts to /v1/zk/roots
    Roots(RootsArgs),
    /// Verify a batch of ZK `OpenVerify` envelopes (Norito vector) via /v1/zk/verify-batch
    VerifyBatch(VerifyBatchArgs),
    /// Manage ZK attachments in the app API
    #[command(subcommand)]
    Attachments(AttachmentsCommand),
    /// Register a ZK-capable asset (Hybrid mode) with policy and VK ids
    RegisterAsset(ZkRegisterAssetArgs),
    /// Verifying-key registry lifecycle (register/update/get)
    #[command(subcommand)]
    Vk(VkCommand),
    /// Inspect proof registry (list/count/get)
    #[command(subcommand)]
    Proofs(ProofCommand),
    /// ZK Vote helpers (tally)
    #[command(subcommand)]
    Vote(VoteCommand),
    /// Validate and encode a typed confidential encrypted memo
    Envelope(EnvelopeArgs),
}
#[derive(clap::Args, Debug)]
pub struct RootsArgs {
    /// Canonical unprefixed Base58 `AssetDefinitionId`
    #[arg(long, value_name = "ASSET_ID")]
    asset_id: String,
    /// Maximum number of roots to return (0 = server cap)
    #[arg(long, default_value_t = 0)]
    max: u32,
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Roots(args) => args.run(context),
            Command::VerifyBatch(args) => args.run(context),
            Command::Attachments(args) => args.run(context),
            Command::RegisterAsset(args) => args.run(context),
            Command::Vk(args) => args.run(context),
            Command::Proofs(args) => args.run(context),
            Command::Vote(args) => args.run(context),
            Command::Envelope(args) => args.run(context),
        }
    }
}
impl Command {
    pub(crate) fn allows_fallback_config(&self) -> bool {
        false
    }
}
impl Run for RootsArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = BlockingClient::from_client(context.client_from_config()?)?;
        let value = client
            .client()
            .get_zk_roots_json(&self.asset_id, self.max)?;
        context.print_data(&value)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct VerifyBatchArgs {
    /// Path to a Norito-encoded Vec<OpenVerifyEnvelope> (mutually exclusive with --json)
    #[arg(long, value_name = "PATH", conflicts_with = "json")]
    norito: Option<std::path::PathBuf>,
    /// Path to a JSON array of base64-encoded Norito `OpenVerifyEnvelope` items (mutually exclusive with --norito)
    #[arg(long, value_name = "PATH", conflicts_with = "norito")]
    json: Option<std::path::PathBuf>,
}
impl Run for VerifyBatchArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = BlockingClient::from_client(context.client_from_config()?)?;
        if let Some(p) = self.norito {
            let body = read_zk_file_bounded(&p, ZK_CLI_INPUT_MAX_BYTES_V1, "ZK verify batch")?;
            let value = client.client().post_zk_verify_batch_norito(&body)?;
            context.print_data(&value)?;
            return Ok(());
        }
        if let Some(p) = self.json {
            let v: norito::json::Value = decode_zk_json_file(&p, "ZK verify batch")?;
            let value = client.client().post_zk_verify_batch_json(&v)?;
            context.print_data(&value)?;
            return Ok(());
        }
        eyre::bail!("provide either --norito <file> or --json <file>");
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ProofCommand {
    /// List proof records maintained by Torii.
    List(ProofListArgs),
    /// Count proof records matching the filters.
    Count(ProofCountArgs),
    /// Fetch a proof record by backend and proof hash (hex).
    Get(ProofGetArgs),
    /// Inspect proof retention configuration and live counters.
    Retention(ProofRetentionArgs),
    /// Submit a pruning transaction to enforce proof retention immediately.
    Prune(ProofPruneArgs),
}
impl Run for ProofCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            ProofCommand::List(args) => args.run(context),
            ProofCommand::Count(args) => args.run(context),
            ProofCommand::Get(args) => args.run(context),
            ProofCommand::Retention(args) => args.run(context),
            ProofCommand::Prune(args) => args.run(context),
        }
    }
}
#[derive(clap::Args, Debug, Clone, Default)]
pub struct ProofFilterArgs {
    /// Filter by backend identifier (e.g., `pipa-r/pasta`).
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
    /// Filter by verification status (`Submitted`, `Verified`, `Rejected`).
    #[arg(long, value_name = "STATUS")]
    status: Option<String>,
    /// Require a ZK1 TLV tag (4 ASCII characters, e.g., `PROF`).
    #[arg(long, value_name = "TAG")]
    has_tag: Option<String>,
    /// Minimum verification height (inclusive).
    #[arg(long, value_name = "HEIGHT")]
    verified_from_height: Option<u64>,
    /// Maximum verification height (inclusive).
    #[arg(long, value_name = "HEIGHT")]
    verified_until_height: Option<u64>,
    /// Limit result size (server caps at 1000).
    #[arg(long, value_name = "LIMIT")]
    limit: Option<u32>,
    /// Offset for server-side pagination.
    #[arg(long, value_name = "OFFSET")]
    offset: Option<u32>,
    /// Sort order (`asc` or `desc`) by verification height.
    #[arg(long, value_name = "ORDER")]
    order: Option<String>,
}
impl ProofFilterArgs {
    fn as_filter(&self) -> Result<ZkProofsFilter<'_>> {
        if let Some(backend) = self.backend.as_deref() {
            ensure_verifier_backend_registry_label_v1(backend, "proof filter backend")?;
        }
        Ok(ZkProofsFilter {
            backend: self.backend.as_deref(),
            status: self.status.as_deref(),
            has_tag: self.has_tag.as_deref(),
            verified_from_height: self.verified_from_height,
            verified_until_height: self.verified_until_height,
            limit: self.limit,
            offset: self.offset,
            order: self.order.as_deref(),
            ids_only: None,
        })
    }
}
#[derive(clap::Args, Debug)]
pub struct ProofListArgs {
    #[command(flatten)]
    filter: ProofFilterArgs,
    /// Return only `{ backend, hash }` identifiers.
    #[arg(long)]
    ids_only: bool,
}
impl Run for ProofListArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let mut filter = self.filter.as_filter()?;
        if self.ids_only {
            filter.ids_only = Some(true);
        }
        let value = client.get_zk_proofs_list_filtered(&filter)?;
        context.print_data(&value)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct ProofCountArgs {
    #[command(flatten)]
    filter: ProofFilterArgs,
}
impl Run for ProofCountArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let filter = self.filter.as_filter()?;
        let count = client.get_zk_proofs_count(&filter)?;
        let value = json_utils::json_object(vec![("count", json_utils::json_value(&count)?)])?;
        context.print_data(&value)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct ProofGetArgs {
    /// Backend identifier (e.g., `pipa-r/pasta`).
    #[arg(long, value_name = "BACKEND")]
    backend: String,
    /// Proof hash (hex, with or without `0x` prefix).
    #[arg(long, value_name = "HASH")]
    hash: String,
}
impl Run for ProofGetArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let backend =
            ensure_verifier_backend_registry_label_v1(&self.backend, "proof get backend")?;
        let hash_hex = parse_hex32_lower(&self.hash, "proof hash")?;
        let value = client.get_zk_proof_json(backend, &hash_hex)?;
        context.print_data(&value)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct ProofRetentionArgs {}
impl Run for ProofRetentionArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let operator_key_pair = context
            .operator_key_pair()
            .cloned()
            .ok_or_else(|| eyre::eyre!("proof retention requires an operator signing key"))?;
        let client = BlockingClient::from_client(context.client_from_config()?)?;
        let operator = client.operator_client(operator_key_pair)?;
        let status = operator.get_proof_retention_status()?;
        context.print_data(&status)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct ProofPruneArgs {
    /// Restrict pruning to a single backend (e.g., `pipa-r/pasta`). Omit to prune all backends.
    #[arg(long, value_name = "BACKEND")]
    backend: Option<String>,
}
impl Run for ProofPruneArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if let Some(backend) = self.backend.as_deref() {
            ensure_verifier_backend_registry_label_v1(backend, "proof prune backend")?;
        }
        let prune: InstructionBox =
            iroha_data_model::isi::zk::PruneProofs::new(self.backend).into();
        context.finish(Executable::Instructions(vec![prune].into()))
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum VoteCommand {
    /// Get election tally (JSON)
    Tally(VoteTallyArgs),
}
impl Run for VoteCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            VoteCommand::Tally(args) => args.run(context),
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct VoteTallyArgs {
    /// Election identifier
    #[arg(
        long,
        value_name = "ELECTION_ID",
        value_parser = crate::gov::parse_governance_selector_v1
    )]
    election_id: String,
}
impl Run for VoteTallyArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let value = client.post_zk_vote_tally_json(&self.election_id)?;
        context.print_data(&value)?;
        Ok(())
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum AttachmentsCommand {
    /// Upload a file as an attachment. Returns JSON metadata.
    Upload(AttachmentUploadArgs),
    /// List stored attachments (JSON array of metadata).
    List(AttachmentListArgs),
    /// Download an attachment by id to a file.
    Get(AttachmentGetArgs),
    /// Delete an attachment by id.
    Delete(AttachmentDeleteArgs),
    /// Cleanup attachments by filters (age/content-type/ids). Deletes individually via API.
    Cleanup(AttachmentCleanupArgs),
}
impl Run for AttachmentsCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            AttachmentsCommand::Upload(args) => args.run(context),
            AttachmentsCommand::List(args) => args.run(context),
            AttachmentsCommand::Get(args) => args.run(context),
            AttachmentsCommand::Delete(args) => args.run(context),
            AttachmentsCommand::Cleanup(args) => args.run(context),
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct AttachmentUploadArgs {
    /// Path to the file to upload
    #[arg(long, value_name = "PATH")]
    file: std::path::PathBuf,
    /// Content-Type to send with the file
    #[arg(long, value_name = "MIME", default_value = "application/octet-stream")]
    content_type: String,
}
impl Run for AttachmentUploadArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let body = read_zk_file_bounded(&self.file, ZK_CLI_INPUT_MAX_BYTES_V1, "ZK attachment")?;
        let value = client.post_zk_attachment(&body, &self.content_type)?;
        context.print_data(&value)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct AttachmentListArgs {}
impl Run for AttachmentListArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let value = client.get_zk_attachments_list()?;
        context.print_data(&value)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct AttachmentGetArgs {
    /// Attachment id (hex)
    #[arg(long, value_name = "ID")]
    id: String,
    /// Output path to write the downloaded bytes
    #[arg(long, value_name = "PATH")]
    out: std::path::PathBuf,
}
impl Run for AttachmentGetArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let (bytes, _ct) = client.get_zk_attachment_raw(&self.id)?;
        std::fs::write(&self.out, &bytes)?;
        context.println(format!(
            "Wrote {} bytes to {}",
            bytes.len(),
            self.out.display()
        ))?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct AttachmentDeleteArgs {
    /// Attachment id (hex)
    #[arg(long, value_name = "ID")]
    id: String,
}
impl Run for AttachmentDeleteArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        client.delete_zk_attachment(&self.id)?;
        context.println("Deleted")?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct AttachmentCleanupArgs {
    /// Proceed without confirmation
    #[arg(long)]
    yes: bool,
    /// Delete all attachments (dangerous). Requires --yes.
    #[arg(long, conflicts_with_all = ["content_type", "older_than_secs", "before_ms", "id"])]
    all: bool,
    /// Filter by content-type substring (e.g., application/x-norito)
    #[arg(long, value_name = "MIME")]
    content_type: Option<String>,
    /// Filter attachments created strictly before this UNIX epoch in milliseconds
    #[arg(long, value_name = "MS", conflicts_with = "older_than_secs")]
    before_ms: Option<u64>,
    /// Filter attachments older than N seconds (relative to now)
    #[arg(long, value_name = "SECS")]
    older_than_secs: Option<u64>,
    /// Filter by specific id(s); may be repeated
    #[arg(long, value_name = "ID")]
    id: Vec<String>,
    /// Maximum number of attachments to delete (applied after filtering)
    #[arg(long, value_name = "N")]
    limit: Option<usize>,
    /// Preview only: list matching ids instead of full metadata
    #[arg(long)]
    ids_only: bool,
    /// Preview only: print a summary table (id, `content_type`, size, `created_ms`)
    #[arg(long)]
    summary: bool,
}
fn now_ms_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn select_attachment_ids(
    list: &norito::json::Value,
    content_type_sub: Option<&str>,
    before_ms: Option<u64>,
    ids: &[String],
    older_than_secs: Option<u64>,
    now_ms: u64,
) -> Vec<(String, String, u64, u64)> {
    let mut out = Vec::new();
    let arr = list.as_array().cloned().unwrap_or_default();
    for v in arr.into_iter() {
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        if !ids.is_empty() && !ids.iter().any(|x| x == &id) {
            continue;
        }
        let ct = v
            .get("content_type")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(sub) = content_type_sub
            && !ct.contains(sub)
        {
            continue;
        }
        let created_ms = v.get("created_ms").and_then(|x| x.as_u64()).unwrap_or(0);
        let size = v.get("size").and_then(|x| x.as_u64()).unwrap_or(0);
        if let Some(ms) = before_ms
            && !(created_ms < ms)
        {
            continue;
        }
        if let Some(secs) = older_than_secs {
            let threshold = now_ms.saturating_sub(secs.saturating_mul(1000));
            if !(created_ms < threshold) {
                continue;
            }
        }
        out.push((id, ct, size, created_ms));
    }
    out
}
impl Run for AttachmentCleanupArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let list = client.get_zk_attachments_list()?;
        let now_ms = now_ms_u64();
        let before_ms = if self.older_than_secs.is_some() {
            None
        } else {
            self.before_ms
        };
        if !(self.all
            || self.content_type.is_some()
            || before_ms.is_some()
            || self.older_than_secs.is_some()
            || !self.id.is_empty())
        {
            eyre::bail!(
                "no filters provided; use --all (with --yes) or one of --content-type/--before-ms/--older-than-secs/--id"
            );
        }
        if self.all && !self.yes {
            eyre::bail!("--all requires --yes confirmation");
        }
        let mut matches = if self.all {
            // select everything
            select_attachment_ids(&list, None, None, &[], None, now_ms)
        } else {
            select_attachment_ids(
                &list,
                self.content_type.as_deref(),
                before_ms,
                &self.id,
                self.older_than_secs,
                now_ms,
            )
        };
        // Sort by created time ascending
        matches.sort_by_key(|(_, _, _, created)| *created);
        if let Some(cap) = self.limit
            && matches.len() > cap
        {
            matches.truncate(cap);
        }
        if !self.yes {
            if self.ids_only {
                let ids = json_utils::json_array(matches.iter().map(|(id, _, _, _)| id.as_str()))?;
                context.print_data(&ids)?;
            } else if self.summary {
                // print concise lines
                for (id, ct, size, created) in &matches {
                    context.println(format!("{id}  {ct}  size={size}  created_ms={created}"))?;
                }
                context.println(format!("{} match(es). Use --yes to delete.", matches.len()))?;
            } else {
                // default: print the full JSON array back
                let arr: Vec<norito::json::Value> = matches
                    .iter()
                    .map(|(id, ct, size, created)| {
                        json_utils::json_object(vec![
                            ("id", json_utils::json_value(id.as_str())?),
                            ("content_type", json_utils::json_value(ct.as_str())?),
                            ("size", json_utils::json_value(size)?),
                            ("created_ms", json_utils::json_value(created)?),
                        ])
                    })
                    .collect::<Result<_, _>>()?;
                let arr_value = json_utils::json_array(arr)?;
                context.print_data(&arr_value)?;
                context.println("Preview only. Use --yes to delete.")?;
            }
            return Ok(());
        }
        // Proceed with deletion
        let mut ok = 0usize;
        let mut failed = 0usize;
        for (id, _ct, _size, _created) in &matches {
            match client.delete_zk_attachment(id) {
                Ok(_) => ok += 1,
                Err(_) => failed += 1,
            }
        }
        context.println(format!("Deleted {} attachment(s), failed {}.", ok, failed))?;
        Ok(())
    }
}
#[cfg(test)]
mod attachments_cleanup_tests {
    use super::select_attachment_ids;
    #[test]
    fn selects_by_ct_and_age() {
        let now_ms = 1_000_000u64;
        let json = r#"[
            {"id":"a","content_type":"application/json","size":1,"created_ms":900000},
            {"id":"b","content_type":"application/x-norito","size":2,"created_ms":800000},
            {"id":"c","content_type":"application/x-norito","size":3,"created_ms":999000}
        ]"#;
        let list = norito::json::from_str(json).expect("parse attachment list");
        // older than 100 seconds => threshold 900_000; norito only
        let v = select_attachment_ids(
            &list,
            Some("application/x-norito"),
            None,
            &[],
            Some(100),
            now_ms,
        );
        let ids: Vec<String> = v.into_iter().map(|t| t.0).collect();
        assert_eq!(ids, vec!["b"]);
    }
}
// ---------------- Confidential envelope helpers ----------------
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum MemoEncoding {
    Base64,
    Hex,
    Json,
}
#[derive(clap::Args, Debug)]
pub struct EnvelopeArgs {
    /// Path to one typed `ConfidentialMemoEnvelopeV1` JSON object.
    #[arg(long, value_name = "PATH")]
    envelope_json: std::path::PathBuf,
    /// Optional output path for Norito bytes.
    #[arg(long, value_name = "PATH")]
    output: Option<std::path::PathBuf>,
    /// Emit exactly one stdout encoding; defaults to base64 when no output file is given.
    #[arg(long, value_enum, value_name = "ENCODING")]
    format: Option<MemoEncoding>,
}
fn read_confidential_memo_envelope_json(
    path: &Path,
) -> eyre::Result<iroha::data_model::confidential::ConfidentialMemoEnvelopeV1> {
    let payload: iroha::data_model::confidential::ConfidentialMemoEnvelopeV1 =
        decode_zk_json_file(path, "confidential memo envelope")?;
    payload
        .validate()
        .map_err(|error| eyre::eyre!("invalid confidential memo envelope: {error}"))?;
    Ok(payload)
}
fn encode_confidential_memo_envelope(
    payload: iroha::data_model::confidential::ConfidentialMemoEnvelopeV1,
) -> eyre::Result<(
    iroha::data_model::confidential::ConfidentialMemoEnvelopeV1,
    Vec<u8>,
)> {
    payload
        .validate()
        .map_err(|error| eyre::eyre!("invalid confidential memo envelope: {error}"))?;
    let bytes = norito::codec::encode_adaptive(&payload);
    Ok((payload, bytes))
}
impl EnvelopeArgs {
    /// Encode an encrypted memo locally without reading client credentials.
    pub(crate) fn run_without_client_config(self, mut output: impl std::io::Write) -> Result<()> {
        if let Some(rendered) = self.execute()? {
            writeln!(output, "{rendered}")?;
        }
        Ok(())
    }

    fn execute(self) -> Result<Option<String>> {
        let payload = read_confidential_memo_envelope_json(&self.envelope_json)?;
        let (payload, bytes) = encode_confidential_memo_envelope(payload)?;
        if let Some(path) = &self.output {
            std::fs::write(path, &bytes)
                .with_context(|| format!("failed to write envelope to {}", path.display()))?;
        }
        if self.output.is_none() || self.format.is_some() {
            Ok(Some(match self.format.unwrap_or(MemoEncoding::Base64) {
                MemoEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(&bytes),
                MemoEncoding::Hex => hex::encode(&bytes),
                MemoEncoding::Json => norito::json::to_json_pretty(&payload)?,
            }))
        } else {
            Ok(None)
        }
    }
}
impl Run for EnvelopeArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if let Some(rendered) = self.execute()? {
            context.println_data(rendered)?;
        }
        Ok(())
    }
}
fn ensure_verifier_backend_registry_label_v1<'a>(backend: &'a str, field: &str) -> Result<&'a str> {
    if backend.is_empty() {
        eyre::bail!("{field} must be non-empty");
    }
    if !iroha_core_zk::is_verifier_backend_registry_label_v1(backend) {
        eyre::bail!("{field} uses unsupported verifier-registry label `{backend}`");
    }
    Ok(backend)
}
fn parse_hex32_lower(value: &str, field: &str) -> Result<String> {
    let bytes = parse_hex32_str(value, field)?;
    Ok(hex::encode(bytes))
}
#[cfg(test)]
mod tests {
    use super::*;

    struct VkSubmissionContext {
        submitted: Option<Executable>,
        reject: bool,
    }
    impl RunContext for VkSubmissionContext {
        fn config(&self) -> &iroha::config::Config {
            panic!("VK command must defer client construction to the shared submission owner")
        }
        fn transaction_metadata(&self) -> Option<&iroha_model_base::metadata::Metadata> {
            panic!("shared submission owns metadata")
        }
        fn input_instructions(&self) -> bool {
            false
        }
        fn output_instructions(&self) -> bool {
            false
        }
        fn i18n(&self) -> &iroha_i18n::Localizer {
            panic!("shared submission owns output")
        }
        fn print_data<T: norito::json::JsonSerialize + ?Sized>(&mut self, _: &T) -> Result<()> {
            panic!("shared submission owns its JSON receipt")
        }
        fn println(&mut self, _: impl std::fmt::Display) -> Result<()> {
            panic!("VK command must not substitute a diagnostic for the receipt")
        }
        fn finish_unconfirmed(&mut self, executable: impl Into<Executable>) -> Result<()> {
            assert!(self.submitted.replace(executable.into()).is_none());
            if self.reject {
                eyre::bail!("canonical submission failed");
            }
            Ok(())
        }
    }

    fn check_vk_submission_dispatch(operation: VkSubmissionOperation) {
        use iroha::data_model::isi::verifying_keys::{RegisterVerifyingKey, UpdateVerifyingKey};
        let mut payload = sample_vk_submission(Some("core"));
        payload.circuit_id = "pipa-r/pasta/kaigi-usage-v1".to_owned();
        let record = build_vk_record(&payload, operation).expect("canonical submission record");
        let directory = tempfile::tempdir().unwrap();
        let json = directory.path().join("vk.json");
        std::fs::write(&json, norito::json::to_vec(&payload).unwrap()).unwrap();
        let id = iroha::data_model::proof::VerifyingKeyId::new(&payload.backend, &payload.name);
        let expected: InstructionBox = match operation {
            VkSubmissionOperation::Register => RegisterVerifyingKey { id, record }.into(),
            VkSubmissionOperation::Update => UpdateVerifyingKey { id, record }.into(),
        };
        for reject in [false, true] {
            let mut context = VkSubmissionContext {
                submitted: None,
                reject,
            };
            let result = match operation {
                VkSubmissionOperation::Register => {
                    VkRegisterArgs { json: json.clone() }.run(&mut context)
                }
                VkSubmissionOperation::Update => {
                    VkUpdateArgs { json: json.clone() }.run(&mut context)
                }
            };
            if reject {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "canonical submission failed"
                );
            } else {
                result.unwrap();
            }
            assert_eq!(
                context.submitted,
                Some(Executable::Instructions(vec![expected.clone()].into()))
            );
        }
    }

    #[test]
    fn vk_submission_register_uses_canonical_receipt_owner() {
        check_vk_submission_dispatch(VkSubmissionOperation::Register);
    }

    #[test]
    fn vk_submission_update_uses_canonical_receipt_owner() {
        check_vk_submission_dispatch(VkSubmissionOperation::Update);
    }

    fn checked_zk_ed25519_key_fixture() -> iroha_crypto::KeyPair {
        iroha_crypto::KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::Ed25519)
            .expect("generate checked ZK fixture key")
    }
    #[test]
    fn zk_fixture_uses_checked_ed25519_key_generation() {
        let key_pair = checked_zk_ed25519_key_fixture();
        let actual = key_pair
            .public_key()
            .try_algorithm()
            .expect("ZK fixture key advertises a valid algorithm");
        assert_eq!(actual, iroha_crypto::Algorithm::Ed25519);
    }
    #[test]
    fn proof_filter_args_reject_unsupported_backend_labels() {
        for backend in [
            " halo2/ipa",
            "halo2/ipa ",
            "\thalo2/ipa",
            "halo2/ipa\n",
            "HALO2/IPA",
            "stark/FRI",
            "halo2/ipa::ivm-replay-binding-v1",
            "halo2//ipa",
            "halo2/ipa:",
            "halo2/ipa.",
            "halo2/ipa/.ivm-replay-binding-v1",
            "halo2/ipa:ivm..execution-v1",
            "halo2/ipa/orchard",
            "halo2/kzg",
            "mock/dev",
            "stark/fri/latest",
            "stark/fri/random-profile",
            "stark/fri/boi-audited",
            "halo2/ipa:release-ready",
            "halo2/ipa:tiny-add",
        ] {
            let args = ProofFilterArgs {
                backend: Some(backend.to_string()),
                ..ProofFilterArgs::default()
            };
            let err = args
                .as_filter()
                .expect_err("unsupported proof filter backend rejected");
            assert!(format!("{err}").contains("unsupported verifier-registry label"));
        }
    }
    #[test]
    fn parse_vk_id_pair_rejects_unsupported_backend_aliases_and_accepts_registry_labels() {
        for literal in [
            " halo2/ipa:vk_transfer",
            "halo2/ipa :vk_transfer",
            "HALO2/IPA:vk_transfer",
            "stark/FRI:vk_transfer",
            "halo2/ipa::ivm-replay-binding-v1:vk_transfer",
            "halo2//ipa:vk_transfer",
            "halo2/ipa.:vk_transfer",
            "halo2/ipa:ivm..execution-v1:vk_transfer",
            "halo2/ipa/orchard:vk_transfer",
            "stark/fri/latest:vk_transfer",
            "stark/fri/random-profile:vk_transfer",
            "stark/fri/boi-audited:vk_transfer",
            "halo2/ipa:release-ready:vk_transfer",
            "halo2/ipa:tiny-add:vk_transfer",
            "halo2/ipa:ivm-replay-binding-v1:vk_ivm",
            "halo2/ipa:ivm-execution-v1:vk_ivm",
            "halo2/pasta/ivm-execution-v1:vk_ivm",
            "halo2/pasta/ivm-replay-binding-v1:vk_ivm",
            "mock/dev:vk_transfer",
            "halo2/ipa:",
            "halo2/ipa:vk:shadow",
        ] {
            assert!(
                parse_vk_id_pair(literal).is_err(),
                "{literal:?} must reject before building a verifying-key id"
            );
        }
        let parsed = parse_vk_id_pair("stark/fri/poseidon-x7-goldilocks-6x64-v1:vk_stark")
            .expect("stark vk id");
        assert_eq!(
            parsed.backend.as_str(),
            "stark/fri/poseidon-x7-goldilocks-6x64-v1"
        );
        assert_eq!(parsed.name.as_str(), "vk_stark");
    }
    #[test]
    fn parse_hex32_lower_canonicalizes_and_rejects_malformed_hashes() {
        assert_eq!(
            parse_hex32_lower(&format!("0x{}", "AA".repeat(32)), "proof hash").expect("hash"),
            "aa".repeat(32)
        );
        for value in [
            String::new(),
            "abc".to_string(),
            "z".repeat(64),
            "a".repeat(63),
            format!("0x0x{}", "aa".repeat(32)),
        ] {
            assert!(
                parse_hex32_lower(&value, "proof hash").is_err(),
                "{value:?} must reject as malformed proof hash"
            );
        }
    }
    #[test]
    fn encode_confidential_memo_envelope_returns_expected_bytes() {
        use iroha::data_model::confidential::{
            CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1, CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1,
            CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1, ConfidentialMemoEnvelopeV1,
            ConfidentialMemoRecipientSlotV1, ConfidentialMemoSuiteV1,
        };
        let payload = ConfidentialMemoEnvelopeV1::new(
            core::array::from_fn(|index| {
                let suite = ConfidentialMemoSuiteV1::MlKem768XChaCha20Poly1305;
                ConfidentialMemoRecipientSlotV1::new(
                    suite,
                    vec![
                        u8::try_from(index).expect("slot index fits u8") + 1;
                        suite.encapsulation_bytes()
                    ],
                    [u8::try_from(index).expect("slot index fits u8") + 17;
                        CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
                    [u8::try_from(index).expect("slot index fits u8") + 33;
                        CONFIDENTIAL_MEMO_WRAPPED_KEY_BYTES_V1],
                )
                .expect("canonical slot")
            }),
            [0xA5; CONFIDENTIAL_MEMO_XCHACHA_NONCE_BYTES_V1],
            vec![0x5A; CONFIDENTIAL_MEMO_XCHACHA_TAG_BYTES_V1],
        )
        .expect("canonical memo envelope");
        let (payload, bytes) = encode_confidential_memo_envelope(payload).expect("encode envelope");
        let decoded: iroha::data_model::confidential::ConfidentialMemoEnvelopeV1 =
            norito::codec::decode_adaptive(&bytes).expect("decode envelope");
        assert_eq!(payload, decoded);
        let json = norito::json::to_json(&payload).expect("encode typed JSON");
        let directory = tempfile::tempdir().expect("memo directory");
        let path = directory.path().join("memo.json");
        std::fs::write(&path, json).expect("write typed JSON");
        assert_eq!(
            read_confidential_memo_envelope_json(&path).expect("read typed JSON"),
            payload
        );
        let output = directory.path().join("memo.bin");
        EnvelopeArgs {
            envelope_json: path,
            output: Some(output.clone()),
            format: None,
        }
        .run(&mut VkSubmissionContext {
            submitted: None,
            reject: false,
        })
        .expect("file-only memo must not access credentials or emit a diagnostic");
        assert_eq!(std::fs::read(output).unwrap(), bytes);
    }
    #[test]
    fn vk_submission_backend_parser_accepts_only_supported_open_verify_engines() {
        use iroha::data_model::zk::BackendTag;
        for (label, expected) in [
            ("pipa-r/pasta", BackendTag::NativePipaRPasta),
            (
                "pipa-r/pasta/kaigi-authorization-v1",
                BackendTag::NativePipaRPasta,
            ),
            ("pipa-r/pasta/kaigi-usage-v1", BackendTag::NativePipaRPasta),
            (
                "stark/fri/poseidon-x7-goldilocks-6x64-v1",
                BackendTag::Stark,
            ),
        ] {
            assert_eq!(
                vk_backend_tag_from_label(label).expect("supported engine"),
                expected,
                "{label} must map to its exact generic engine",
            );
        }
        for label in [
            "halo2/ipa",
            "halo2/pasta/kaigi-authorization-v1",
            "halo2/pasta/kaigi-usage-v1",
            "pipa-r/ipa/pasta/kaigi-usage-v1",
            "halo2/ipa/orchard",
            "groth16/bls12-377",
            "sis-hints-anoncred-pq-v0",
            "sis-with-hints",
            "unknown/privacy/backend",
        ] {
            let _ = vk_backend_tag_from_label(label)
                .expect_err("protocol names and unknown labels must not map to generic engines");
        }
    }
    fn sample_vk_submission(namespace: Option<&str>) -> VkSubmissionJson {
        VkSubmissionJson {
            backend: "pipa-r/pasta".to_owned(),
            name: "vk_namespace_test".to_owned(),
            version: 1,
            circuit_id: "namespace-test-v1".to_owned(),
            public_inputs_schema_hash_hex: "11".repeat(32),
            curve: Some("vesta".to_owned()),
            gas_schedule_id: Some("zk-gas-v1".to_owned()),
            vk_len: Some(32),
            max_proof_bytes: Some(4096),
            metadata_uri_cid: None,
            vk_bytes_cid: None,
            activation_height: None,
            withdraw_height: None,
            commitment_hex: Some("22".repeat(32)),
            vk_bytes: None,
            status: Some(iroha::data_model::confidential::ConfidentialStatus::Active),
            namespace: namespace.map(str::to_owned),
        }
    }
    #[test]
    fn vk_submission_namespace_explicit_and_defaults() {
        let encoded = norito::json::to_value(&sample_vk_submission(Some("example_v1")))
            .expect("serialize VK submission fixture");
        let explicit: VkSubmissionJson =
            norito::json::from_value(encoded.clone()).expect("deserialize explicit namespace");
        assert_eq!(
            build_vk_record(&explicit, VkSubmissionOperation::Register)
                .expect("build explicit namespace record")
                .namespace,
            "example_v1"
        );
        let mut omitted = encoded.clone();
        omitted
            .as_object_mut()
            .expect("VK submission JSON object")
            .remove("namespace");
        let omitted: VkSubmissionJson =
            norito::json::from_value(omitted).expect("deserialize omitted namespace");
        assert_eq!(
            build_vk_record(&omitted, VkSubmissionOperation::Register)
                .expect("build default namespace record")
                .namespace,
            DEFAULT_VK_NAMESPACE
        );
        let mut null = encoded;
        null.as_object_mut()
            .expect("VK submission JSON object")
            .insert("namespace".to_owned(), norito::json::Value::Null);
        let null: VkSubmissionJson =
            norito::json::from_value(null).expect("deserialize null namespace");
        assert_eq!(
            build_vk_record(&null, VkSubmissionOperation::Register)
                .expect("build null-defaulted namespace record")
                .namespace,
            DEFAULT_VK_NAMESPACE
        );
    }
    #[test]
    fn vk_submission_namespace_rejects_blank_or_untrimmed_values() {
        for namespace in ["", " \t ", " example_v1", "example_v1 "] {
            let err = build_vk_record(
                &sample_vk_submission(Some(namespace)),
                VkSubmissionOperation::Register,
            )
            .expect_err("blank or untrimmed namespace must be rejected");
            assert!(
                err.to_string().contains("namespace must not"),
                "unexpected error for {namespace:?}: {err}"
            );
        }
    }
    #[test]
    fn vk_submission_rejects_signing_secrets_and_unknown_fields() {
        let encoded =
            norito::json::to_value(&sample_vk_submission(None)).expect("serialize VK submission");
        for field in ["authority", "private_key", "unexpected"] {
            let mut value = encoded.clone();
            value
                .as_object_mut()
                .expect("VK submission JSON object")
                .insert(
                    field.to_owned(),
                    norito::json::Value::String("retired".to_owned()),
                );
            let error = norito::json::from_value::<VkSubmissionJson>(value)
                .expect_err("strict VK submission schema must reject unknown fields");
            assert!(
                error.to_string().contains(field),
                "unexpected error for {field}: {error}"
            );
        }
    }
    #[test]
    fn vk_submission_rejects_nonportable_names_before_key_preparation() {
        let directory = tempfile::tempdir().expect("VK submission directory");
        let path = directory.path().join("key.json");
        let mut payload = sample_vk_submission(None);
        // Invalid key bytes distinguish early ID rejection from key preparation.
        payload.vk_bytes = Some("not valid base64!".to_owned());
        for name in [
            String::new(),
            " key".to_owned(),
            "quoted\"key".to_owned(),
            "back\\slash".to_owned(),
            "a".repeat(iroha_data_model::proof::VERIFYING_KEY_ID_MAX_FIELD_BYTES + 1),
        ] {
            payload.name = name;
            std::fs::write(
                &path,
                norito::json::to_json(&payload).expect("serialize DTO"),
            )
            .expect("write DTO");
            for operation in [
                VkSubmissionOperation::Register,
                VkSubmissionOperation::Update,
            ] {
                let error = load_vk_submission(&path, operation)
                    .err()
                    .expect("nonportable ID must reject before key decoding");
                assert!(
                    error.to_string().contains("portable registry syntax"),
                    "{error}"
                );
            }
        }
        payload.name = "portable_key".to_owned();
        std::fs::write(
            &path,
            norito::json::to_json(&payload).expect("serialize DTO"),
        )
        .expect("write DTO");
        let error = load_vk_submission(&path, VkSubmissionOperation::Register)
            .err()
            .expect("portable name proceeds to invalid key bytes");
        assert!(error.to_string().contains("base64"), "{error}");
    }
    #[test]
    fn vk_submission_enforces_backend_specific_key_size_limits() {
        use base64::Engine as _;
        for (backend, limit) in [
            (
                iroha_core_zk::ZK_BACKEND_STARK_FRI_V1,
                iroha_core_zk::STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES,
            ),
            (
                "pipa-r/pasta",
                iroha_core_zk::NATIVE_PIPA_R_VERIFYING_KEY_V1_MAX_BYTES,
            ),
        ] {
            // This tests CLI container bounds, not cryptographic key admission.
            let mut inline = sample_vk_submission(None);
            inline.backend = backend.to_owned();
            inline.commitment_hex = None;
            inline.vk_len = Some(u32::try_from(limit).expect("VK limit fits u32"));
            inline.vk_bytes =
                Some(base64::engine::general_purpose::STANDARD.encode(vec![0xA5; limit]));
            assert!(
                build_vk_record(&inline, VkSubmissionOperation::Register).is_ok(),
                "the exact {backend} VK byte limit must be admitted by the CLI builder"
            );
            inline.vk_len = Some(u32::try_from(limit + 1).expect("VK overflow fits u32"));
            inline.vk_bytes =
                Some(base64::engine::general_purpose::STANDARD.encode(vec![0xA5; limit + 1]));
            let error = build_vk_record(&inline, VkSubmissionOperation::Register)
                .expect_err("the first byte over the VK limit must be rejected");
            assert!(error.to_string().contains("backend limit"), "{error}");

            let mut commitment_only = sample_vk_submission(None);
            commitment_only.backend = backend.to_owned();
            commitment_only.vk_len = Some(u32::try_from(limit).expect("VK limit fits u32"));
            assert!(
                build_vk_record(&commitment_only, VkSubmissionOperation::Register).is_ok(),
                "the exact declared {backend} VK limit must be admitted"
            );
            commitment_only.vk_len = Some(u32::try_from(limit + 1).expect("VK overflow fits u32"));
            let error = build_vk_record(&commitment_only, VkSubmissionOperation::Register)
                .expect_err("an oversized declared VK length must be rejected");
            assert!(error.to_string().contains("backend limit"), "{error}");
        }
    }
    #[test]
    fn vk_submission_requires_strict_withdrawal_ordering() {
        for (activation_height, withdraw_height) in [(10, 10), (11, 10)] {
            let mut payload = sample_vk_submission(None);
            payload.activation_height = Some(activation_height);
            payload.withdraw_height = Some(withdraw_height);
            let error = build_vk_record(&payload, VkSubmissionOperation::Register)
                .expect_err("withdrawal must follow activation");
            assert!(
                error.to_string().contains("greater than activation_height"),
                "{error}"
            );
        }
        let mut payload = sample_vk_submission(None);
        payload.activation_height = Some(10);
        payload.withdraw_height = Some(11);
        assert!(build_vk_record(&payload, VkSubmissionOperation::Register).is_ok());
    }
    #[test]
    fn vk_submission_rejects_withdrawn_registration_but_allows_update() {
        use iroha::data_model::confidential::ConfidentialStatus;
        let mut payload = sample_vk_submission(None);
        payload.status = Some(ConfidentialStatus::Withdrawn);
        let error = build_vk_record(&payload, VkSubmissionOperation::Register)
            .expect_err("new withdrawn records must be rejected");
        assert!(
            error.to_string().contains("cannot be registered"),
            "{error}"
        );
        let record = build_vk_record(&payload, VkSubmissionOperation::Update)
            .expect("updates may transition an existing verifier to withdrawn");
        assert_eq!(record.status, ConfidentialStatus::Withdrawn);
    }
    #[test]
    fn typed_memo_json_rejects_invalid_placeholder() {
        let placeholder = iroha::data_model::confidential::ConfidentialMemoEnvelopeV1::default();
        let json = norito::json::to_json(&placeholder).expect("serialize placeholder JSON");
        let directory = tempfile::tempdir().expect("memo directory");
        let path = directory.path().join("invalid.json");
        std::fs::write(&path, json).expect("write placeholder JSON");
        let err = read_confidential_memo_envelope_json(&path)
            .expect_err("invalid confidential memo placeholder must fail");
        assert!(
            format!("{err}").contains("recipient slot 0"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn zk_file_reader_accepts_exact_limit_and_rejects_sparse_overflow() {
        let directory = tempfile::tempdir().expect("create ZK input directory");
        let exact = directory.path().join("exact.bin");
        std::fs::write(&exact, [0xA5; 32]).expect("write exact ZK input");
        assert_eq!(
            read_zk_file_bounded(&exact, 32, "fixture").expect("read exact ZK input"),
            vec![0xA5; 32]
        );
        let oversized = directory.path().join("oversized.bin");
        let file = File::create(&oversized).expect("create sparse ZK input");
        file.set_len(33).expect("extend sparse ZK input");
        let error = read_zk_file_bounded(&oversized, 32, "fixture")
            .expect_err("first over-limit ZK input must fail before reading");
        assert!(error.to_string().contains("first-release limit"));
    }
    #[test]
    fn zk_json_depth_bound_rejects_first_overflow() {
        let directory = tempfile::tempdir().expect("create ZK JSON directory");
        let exact = directory.path().join("exact.json");
        let exact_body = format!(
            "{}0{}",
            "[".repeat(ZK_CLI_JSON_MAX_NESTING_DEPTH_V1 - 1),
            "]".repeat(ZK_CLI_JSON_MAX_NESTING_DEPTH_V1 - 1)
        );
        std::fs::write(&exact, exact_body).expect("write exact-depth JSON");
        let _: norito::json::Value =
            decode_zk_json_file(&exact, "fixture").expect("exact JSON depth is admitted");
        let over = directory.path().join("over.json");
        let over_body = format!(
            "{}0{}",
            "[".repeat(ZK_CLI_JSON_MAX_NESTING_DEPTH_V1),
            "]".repeat(ZK_CLI_JSON_MAX_NESTING_DEPTH_V1)
        );
        std::fs::write(&over, over_body).expect("write over-depth JSON");
        let error = decode_zk_json_file::<norito::json::Value>(&over, "fixture")
            .expect_err("first over-limit JSON depth must fail");
        assert!(error.to_string().contains("lexical resource bounds"));
    }
}
// --------------- Register ZK Asset ---------------
#[derive(clap::Args, Debug)]
pub struct ZkRegisterAssetArgs {
    /// Canonical unprefixed Base58 `AssetDefinitionId`
    #[arg(long, value_name = "ASSET_ID")]
    asset: String,
    /// Verifying key id for unshield proofs (format: `<backend>:<name>`)
    #[arg(long, value_name = "BACKEND:NAME")]
    vk_unshield: Option<String>,
}
fn parse_vk_id_pair(s: &str) -> eyre::Result<iroha::data_model::proof::VerifyingKeyId> {
    use iroha::data_model::proof::VerifyingKeyId;
    let (backend, name) = s
        .rsplit_once(':')
        .ok_or_else(|| eyre::eyre!("expected BACKEND:NAME for verifying key id"))?;
    let backend = ensure_verifier_backend_registry_label_v1(backend, "verifying key backend")?;
    let name = name.trim();
    if name.is_empty() {
        eyre::bail!("verifying key name must be non-empty");
    }
    if name.contains(':') {
        eyre::bail!("verifying key name must not contain ':'");
    }
    Ok(VerifyingKeyId::new(backend, name))
}
impl Run for ZkRegisterAssetArgs {
    fn run<C: RunContext>(self, context: &mut C) -> eyre::Result<()> {
        use iroha::data_model::isi::zk::RegisterZkAsset;
        use iroha::data_model::prelude::{AssetDefinitionId, InstructionBox};
        let asset = AssetDefinitionId::parse_address_literal(&self.asset)?;
        let vk_unshield = match self.vk_unshield {
            Some(s) => Some(parse_vk_id_pair(&s)?),
            None => None,
        };
        let registration = RegisterZkAsset::new(asset, vk_unshield);
        let ib: InstructionBox = registration.into();
        context.finish(vec![ib])
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum VkCommand {
    /// Register a verifying key record with the configured account and key
    Register(VkRegisterArgs),
    /// Update an existing verifying key record (version must increase)
    Update(VkUpdateArgs),
    /// Get a verifying key record by backend and name
    Get(VkGetArgs),
}
impl Run for VkCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            VkCommand::Register(args) => args.run(context),
            VkCommand::Update(args) => args.run(context),
            VkCommand::Get(args) => args.run(context),
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct VkRegisterArgs {
    /// Path to a JSON DTO file for register (backend, name, version, optional `vk_bytes` (base64)
    /// or `commitment_hex`). The configured client account and key sign the transaction. Optional
    /// `namespace` defaults to `core` and must be non-empty without leading or trailing whitespace.
    #[arg(long, value_name = "PATH")]
    json: std::path::PathBuf,
}
#[path = "zk_registry_json.rs"]
mod registry_json;
use registry_json::VkSubmissionJson;

struct PreparedVkSubmission {
    id: iroha::data_model::proof::VerifyingKeyId,
    record: iroha::data_model::proof::VerifyingKeyRecord,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VkSubmissionOperation {
    Register,
    Update,
}
fn parse_hex32_str(value: &str, field: &str) -> Result<[u8; 32]> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).wrap_err_with(|| format!("invalid {field}"))?;
    if bytes.len() != 32 {
        eyre::bail!("{field} must be 32 bytes");
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
fn parse_commitment_hex(value: &str) -> Result<[u8; 32]> {
    parse_hex32_str(value, "commitment_hex")
}
fn vk_backend_tag_from_label(label: &str) -> Result<iroha::data_model::zk::BackendTag> {
    iroha_core_zk::verifier_backend_registry_tag_v1(label)
        .ok_or_else(|| eyre::eyre!("unsupported generic OpenVerify backend `{label}`"))
}
const DEFAULT_VK_NAMESPACE: &str = "core";
fn resolve_vk_namespace(namespace: Option<&str>) -> Result<String> {
    let Some(namespace) = namespace else {
        return Ok(DEFAULT_VK_NAMESPACE.to_owned());
    };
    if namespace.trim().is_empty() {
        eyre::bail!("namespace must not be empty or whitespace-only");
    }
    if namespace.trim() != namespace {
        eyre::bail!("namespace must not contain leading or trailing whitespace");
    }
    Ok(namespace.to_owned())
}
fn build_vk_record(
    payload: &VkSubmissionJson,
    operation: VkSubmissionOperation,
) -> Result<iroha::data_model::proof::VerifyingKeyRecord> {
    use iroha::data_model::{
        confidential::ConfidentialStatus,
        proof::{VerifyingKeyBox, VerifyingKeyRecord},
    };
    use iroha_core_zk::hash_vk;
    let backend =
        ensure_verifier_backend_registry_label_v1(&payload.backend, "verifying key backend")?;
    let backend_tag = vk_backend_tag_from_label(backend)?;
    let max_vk_bytes = match backend_tag {
        iroha::data_model::zk::BackendTag::NativePipaRPasta => {
            iroha_core_zk::NATIVE_PIPA_R_VERIFYING_KEY_V1_MAX_BYTES
        }
        iroha::data_model::zk::BackendTag::Stark => {
            iroha_core_zk::STARK_FRI_VERIFYING_KEY_V1_MAX_BYTES
        }
    };
    let vk_bytes = match payload.vk_bytes.as_deref() {
        Some(value) => {
            if base64::decoded_len_estimate(value.len()) > max_vk_bytes.saturating_add(2) {
                eyre::bail!(
                    "inline verifying-key container exceeds the {max_vk_bytes}-byte backend limit"
                );
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(value.as_bytes())
                .wrap_err("failed to decode vk_bytes base64")?;
            if bytes.len() > max_vk_bytes {
                eyre::bail!(
                    "inline verifying-key container exceeds the {max_vk_bytes}-byte backend limit"
                );
            }
            Some(bytes)
        }
        None => None,
    };
    let mut key_opt = None;
    let commitment;
    let vk_len_value;
    if let Some(bytes) = vk_bytes {
        let vk = VerifyingKeyBox::new(backend.into(), bytes);
        let actual_commitment = hash_vk(&vk);
        if let Some(hex) = payload.commitment_hex.as_deref() {
            let parsed = parse_commitment_hex(hex)?;
            if parsed != actual_commitment {
                eyre::bail!("commitment mismatch with provided vk_bytes");
            }
        }
        commitment = actual_commitment;
        let actual_len = vk.bytes.len() as u32;
        if let Some(explicit_len) = payload.vk_len {
            if explicit_len != actual_len {
                eyre::bail!("vk_len mismatch with provided vk_bytes");
            }
        }
        vk_len_value = actual_len;
        key_opt = Some(vk);
    } else if let Some(hex) = payload.commitment_hex.as_deref() {
        commitment = parse_commitment_hex(hex)?;
        let explicit_len = payload
            .vk_len
            .ok_or_else(|| eyre::eyre!("vk_len required when vk_bytes omitted"))?;
        if explicit_len == 0 {
            eyre::bail!("vk_len must be > 0");
        }
        if usize::try_from(explicit_len).map_or(true, |len| len > max_vk_bytes) {
            eyre::bail!(
                "declared verifying-key length exceeds the {max_vk_bytes}-byte backend limit"
            );
        }
        vk_len_value = explicit_len;
    } else {
        eyre::bail!("provide either vk_bytes or commitment_hex");
    }
    let schema_hash = parse_hex32_str(
        &payload.public_inputs_schema_hash_hex,
        "public_inputs_schema_hash_hex",
    )?;
    if payload
        .gas_schedule_id
        .as_ref()
        .is_some_and(|gas_schedule_id| gas_schedule_id.trim().is_empty())
    {
        eyre::bail!("gas_schedule_id must not be empty");
    }
    if let (Some(activation_height), Some(withdraw_height)) =
        (payload.activation_height, payload.withdraw_height)
    {
        if activation_height >= withdraw_height {
            eyre::bail!("withdraw_height must be greater than activation_height");
        }
    }
    let status = payload.status.unwrap_or(ConfidentialStatus::Active);
    if operation == VkSubmissionOperation::Register && status == ConfidentialStatus::Withdrawn {
        eyre::bail!("a new verifying key cannot be registered as withdrawn");
    }
    let mut record = VerifyingKeyRecord::new_with_owner(
        payload.version,
        payload.circuit_id.clone(),
        None,
        resolve_vk_namespace(payload.namespace.as_deref())?,
        backend_tag,
        payload.curve.clone().unwrap_or_else(|| "unknown".into()),
        schema_hash,
        commitment,
    );
    record.vk_len = vk_len_value;
    record.max_proof_bytes = payload.max_proof_bytes.unwrap_or(0);
    record.status = status;
    record.metadata_uri_cid = payload.metadata_uri_cid.clone();
    record.vk_bytes_cid = payload.vk_bytes_cid.clone();
    record.activation_height = payload.activation_height;
    record.withdraw_height = payload.withdraw_height;
    record.key = key_opt;
    record.gas_schedule_id = payload.gas_schedule_id.clone();
    Ok(record)
}
fn load_vk_submission(
    path: &std::path::Path,
    operation: VkSubmissionOperation,
) -> Result<PreparedVkSubmission> {
    let payload: VkSubmissionJson = decode_zk_json_file(path, "verifying-key submission")?;
    let backend =
        ensure_verifier_backend_registry_label_v1(&payload.backend, "verifying key backend")?;
    let id =
        iroha::data_model::proof::VerifyingKeyId::new(backend.to_string(), payload.name.clone());
    if !id.is_portable_registry_id() {
        eyre::bail!("verifying-key ID must use bounded portable registry syntax");
    }
    let record = build_vk_record(&payload, operation)?;
    Ok(PreparedVkSubmission { id, record })
}
impl Run for VkRegisterArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let prepared = load_vk_submission(&self.json, VkSubmissionOperation::Register)?;
        context.finish_unconfirmed(vec![InstructionBox::from(
            iroha::data_model::isi::verifying_keys::RegisterVerifyingKey {
                id: prepared.id,
                record: prepared.record,
            },
        )])
    }
}
#[derive(clap::Args, Debug)]
pub struct VkUpdateArgs {
    /// Path to a JSON DTO file for update (backend, name, version, optional `vk_bytes` or
    /// `commitment_hex`). The configured client account and key sign the transaction. Optional
    /// `namespace` defaults to `core` and must be non-empty without leading or trailing whitespace.
    #[arg(long, value_name = "PATH")]
    json: std::path::PathBuf,
}
impl Run for VkUpdateArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let prepared = load_vk_submission(&self.json, VkSubmissionOperation::Update)?;
        context.finish_unconfirmed(vec![InstructionBox::from(
            iroha::data_model::isi::verifying_keys::UpdateVerifyingKey {
                id: prepared.id,
                record: prepared.record,
            },
        )])
    }
}
#[derive(clap::Args, Debug)]
pub struct VkGetArgs {
    /// Backend identifier (e.g., "pipa-r/pasta")
    #[arg(long, value_name = "BACKEND")]
    backend: String,
    /// Verifying key name
    #[arg(long, value_name = "NAME")]
    name: String,
}
impl Run for VkGetArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let backend =
            ensure_verifier_backend_registry_label_v1(&self.backend, "verifying key get backend")?;
        let name = self.name.trim();
        if name.is_empty() {
            eyre::bail!("verifying key get name must be non-empty");
        }
        let client: Client = context.client_from_config()?;
        let v = client.get_zk_vk_json(backend, name)?;
        context.print_data(&v)?;
        Ok(())
    }
}
