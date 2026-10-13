//! Space Directory operator helpers.
use crate::{Run, RunContext};
use eyre::{Result, WrapErr, eyre};
use iroha::data_model::{
    isi::{
        InstructionBox,
        space_directory::{
            ExpireSpaceDirectoryManifest, PublishSpaceDirectoryManifest,
            RevokeSpaceDirectoryManifest,
        },
    },
    nexus::AssetPermissionManifest,
};
use iroha::{config::Config, data_model::Decode};
use iroha_data_model::{
    asset::AssetDefinitionId,
    nexus::{
        Allowance, AllowanceWindow, AmxRole, CapabilityScope, DenyDirective, ManifestEffect,
        ManifestEntry, ManifestVersion, SmartContractId, UniversalAccountId,
    },
};
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use norito::json::{self, JsonDeserialize, JsonSerialize, Value as JsonValue};
use reqwest::{
    blocking::Client as BlockingHttpClient,
    header::{ACCEPT, HeaderValue},
};
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;
const SPACE_DIRECTORY_INPUT_MAX_BYTES_V1: usize = super::MAX_CLI_STDIN_BYTES_V1;
const SPACE_DIRECTORY_MAX_SEQUENCE_ELEMENTS_V1: usize = 65_536;
const SPACE_DIRECTORY_MAX_TOTAL_ELEMENTS_V1: usize = 4 * SPACE_DIRECTORY_MAX_SEQUENCE_ELEMENTS_V1;
const SPACE_DIRECTORY_MAX_DECODE_ALLOCATION_BYTES_V1: usize = 128 * 1024 * 1024;
const SPACE_DIRECTORY_MAX_NESTING_DEPTH_V1: usize = 64;
const SPACE_DIRECTORY_JSON_MAX_NESTING_DEPTH_V1: usize = norito::json::MAX_JSON_VALUE_NESTING_DEPTH;
const SPACE_DIRECTORY_ERROR_PREVIEW_BYTES_V1: usize = 4 * 1024;
const SPACE_DIRECTORY_OUTPUT_MAX_BYTES_V1: usize = 2 * SPACE_DIRECTORY_INPUT_MAX_BYTES_V1;
const SPACE_DIRECTORY_BINARY_DECODE_LIMITS_V1: norito::DecodeLimits = norito::DecodeLimits::new(
    SPACE_DIRECTORY_MAX_SEQUENCE_ELEMENTS_V1,
    SPACE_DIRECTORY_INPUT_MAX_BYTES_V1,
    SPACE_DIRECTORY_MAX_TOTAL_ELEMENTS_V1,
    SPACE_DIRECTORY_MAX_DECODE_ALLOCATION_BYTES_V1,
    SPACE_DIRECTORY_MAX_NESTING_DEPTH_V1,
);
const SPACE_DIRECTORY_JSON_DECODE_LIMITS_V1: norito::DecodeLimits = norito::DecodeLimits::new(
    SPACE_DIRECTORY_MAX_SEQUENCE_ELEMENTS_V1,
    SPACE_DIRECTORY_INPUT_MAX_BYTES_V1,
    SPACE_DIRECTORY_MAX_TOTAL_ELEMENTS_V1,
    SPACE_DIRECTORY_MAX_DECODE_ALLOCATION_BYTES_V1,
    SPACE_DIRECTORY_JSON_MAX_NESTING_DEPTH_V1,
);
#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Manage UAID capability manifests.
    #[command(subcommand)]
    Manifest(ManifestCommand),
    /// Inspect UAID bindings surfaced by Torii.
    #[command(subcommand)]
    Bindings(BindingsCommand),
}
#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
pub enum ManifestCommand {
    /// Publish or replace a capability manifest (.to payload).
    Publish(ManifestPublishArgs),
    /// Encode manifest JSON into Norito bytes and record its hash.
    Encode(ManifestEncodeArgs),
    /// Revoke a manifest for a UAID/dataspace pair.
    Revoke(ManifestRevokeArgs),
    /// Expire a manifest that reached its scheduled end-of-life.
    Expire(ManifestExpireArgs),
    /// Produce an audit bundle for an existing capability manifest + dataspace profile.
    AuditBundle(ManifestAuditBundleArgs),
    /// Fetch manifests for a UAID via Torii.
    Fetch(ManifestFetchArgs),
    /// Scaffold manifest/profile templates for a UAID + dataspace pair.
    Scaffold(ManifestScaffoldArgs),
}
#[derive(clap::Args, Debug)]
pub struct ManifestAuditBundleArgs {
    /// Path to the Norito-encoded `AssetPermissionManifest` (.to).
    #[arg(long, value_name = "PATH", conflicts_with = "manifest_json")]
    pub manifest: Option<PathBuf>,
    /// Path to the JSON `AssetPermissionManifest` (encoded on export).
    #[arg(long, value_name = "PATH", conflicts_with = "manifest")]
    pub manifest_json: Option<PathBuf>,
    /// Dataspace profile JSON used to capture governance/audit hooks.
    #[arg(long, value_name = "PATH")]
    pub profile: PathBuf,
    /// Directory where the bundle (manifest/profile/hash/audit metadata) will be written.
    #[arg(long = "out-dir", value_name = "DIR")]
    pub out_dir: PathBuf,
    /// Optional operator note recorded inside the bundle metadata.
    #[arg(long, value_name = "TEXT")]
    pub notes: Option<String>,
}
#[derive(clap::Args, Debug)]
pub struct ManifestPublishArgs {
    /// Path to the Norito-encoded `AssetPermissionManifest` (.to).
    #[arg(long, value_name = "PATH", conflicts_with = "manifest_json")]
    pub manifest: Option<PathBuf>,
    /// Path to the JSON `AssetPermissionManifest` (encoded on submit).
    #[arg(long, value_name = "PATH", conflicts_with = "manifest")]
    pub manifest_json: Option<PathBuf>,
    /// Optional CLI-level reason used when publishing a new manifest (added to metadata).
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Manifest(command) => command.run(context),
            Command::Bindings(command) => command.run(context),
        }
    }
}
impl Run for ManifestCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            ManifestCommand::Publish(args) => args.run(context),
            ManifestCommand::Encode(args) => args.run(context),
            ManifestCommand::Revoke(args) => args.run(context),
            ManifestCommand::Expire(args) => args.run(context),
            ManifestCommand::AuditBundle(args) => args.run(context),
            ManifestCommand::Fetch(args) => args.run(context),
            ManifestCommand::Scaffold(args) => args.run(context),
        }
    }
}
impl Run for ManifestPublishArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let manifest = self.load_manifest()?;
        let mut instruction = PublishSpaceDirectoryManifest { manifest };
        if let Some(reason) = &self.reason {
            apply_manifest_reason_bounded(
                &mut instruction.manifest,
                reason,
                SPACE_DIRECTORY_INPUT_MAX_BYTES_V1,
            )?;
        }
        let isi: InstructionBox = instruction.into();
        context.finish(vec![isi])
    }
}
impl ManifestPublishArgs {
    fn load_manifest(&self) -> Result<AssetPermissionManifest> {
        load_manifest_from_sources(self.manifest.as_deref(), self.manifest_json.as_deref())
    }
}
fn apply_manifest_reason_bounded(
    manifest: &mut AssetPermissionManifest,
    reason: &str,
    max_added_bytes: usize,
) -> Result<()> {
    let missing_notes = manifest
        .entries
        .iter()
        .filter(|entry| entry.notes.is_none())
        .count();
    let added_bytes = missing_notes
        .checked_mul(reason.len())
        .ok_or_else(|| eyre!("manifest reason retention length overflow"))?;
    if added_bytes > max_added_bytes {
        return Err(eyre!(
            "manifest reason expansion exceeds the retained limit of {max_added_bytes} bytes"
        ));
    }
    for entry in &mut manifest.entries {
        if entry.notes.is_none() {
            let mut note = String::new();
            note.try_reserve_exact(reason.len())
                .map_err(|error| eyre!("failed to reserve manifest reason storage: {error}"))?;
            note.push_str(reason);
            entry.notes = Some(note);
        }
    }
    Ok(())
}
#[derive(clap::Args, Debug)]
pub struct ManifestEncodeArgs {
    /// Path to the JSON `AssetPermissionManifest`.
    #[arg(long, value_name = "PATH")]
    pub json: PathBuf,
    /// Target path for the Norito `.to` payload (defaults to `<json>.manifest.to`).
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// Optional file for the manifest hash (defaults to `<out>.hash`).
    #[arg(long, value_name = "PATH")]
    pub hash_out: Option<PathBuf>,
}
impl ManifestEncodeArgs {
    fn resolve_out(&self) -> PathBuf {
        self.out
            .clone()
            .unwrap_or_else(|| self.json.with_extension("manifest.to"))
    }
    fn resolve_hash_out(&self, to_path: &Path) -> PathBuf {
        self.hash_out
            .clone()
            .unwrap_or_else(|| to_path.with_extension("hash"))
    }
}
impl Run for ManifestEncodeArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let json_bytes = read_space_directory_file_bounded(&self.json, "manifest JSON")?;
        let manifest: AssetPermissionManifest =
            decode_space_directory_json(&json_bytes, "manifest JSON")?;
        let encoded = norito::core::to_bytes_bounded(&manifest, SPACE_DIRECTORY_INPUT_MAX_BYTES_V1)
            .map_err(|error| eyre!("failed to encode bounded manifest payload: {error}"))?;
        let out_path = self.resolve_out();
        if let Some(parent) = out_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .wrap_err("failed to create manifest output directory")?;
        }
        std::fs::write(&out_path, &encoded).wrap_err_with(|| {
            format!("failed to write Norito payload to {}", out_path.display())
        })?;
        let hash = iroha_crypto::Hash::new(&encoded);
        let hash_hex = hex::encode(hash.as_ref());
        let hash_path = self.resolve_hash_out(out_path.as_path());
        if let Some(parent) = hash_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).wrap_err("failed to create hash output directory")?;
        }
        std::fs::write(&hash_path, format!("{hash_hex}\n")).wrap_err_with(|| {
            format!("failed to write manifest hash to {}", hash_path.display())
        })?;
        context.println(format!(
            "Wrote Norito payload ({:?} bytes) to {}",
            encoded.len(),
            out_path.display()
        ))?;
        context.println(format!(
            "Manifest hash (BLAKE3-256): {} (written to {})",
            hash_hex,
            hash_path.display()
        ))?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct ManifestRevokeArgs {
    /// UAID whose manifest should be revoked.
    #[arg(long, value_name = "UAID")]
    pub uaid: String,
    /// Dataspace identifier hosting the manifest.
    #[arg(long, value_name = "ID")]
    pub dataspace: u64,
    /// Epoch (inclusive) when the revocation takes effect.
    #[arg(long, value_name = "EPOCH")]
    pub revoked_epoch: u64,
    /// Optional reason recorded with the revocation.
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,
}
impl Run for ManifestRevokeArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let uaid = self
            .uaid
            .parse()
            .wrap_err("failed to parse exact canonical UAID `uaid:<64-lowercase-hex>`")?;
        let dataspace = DataSpaceId::new(self.dataspace);
        let instruction = RevokeSpaceDirectoryManifest {
            uaid,
            dataspace,
            revoked_epoch: self.revoked_epoch,
            reason: self.reason.clone(),
        };
        context.finish(vec![InstructionBox::from(instruction)])
    }
}
#[derive(clap::Args, Debug)]
pub struct ManifestExpireArgs {
    /// UAID whose manifest should be expired.
    #[arg(long, value_name = "UAID")]
    pub uaid: String,
    /// Dataspace identifier hosting the manifest.
    #[arg(long, value_name = "ID")]
    pub dataspace: u64,
    /// Epoch (inclusive) when the expiry occurred.
    #[arg(long, value_name = "EPOCH")]
    pub expired_epoch: u64,
}
impl Run for ManifestExpireArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let uaid = self
            .uaid
            .parse()
            .wrap_err("failed to parse exact canonical UAID `uaid:<64-lowercase-hex>`")?;
        let dataspace = DataSpaceId::new(self.dataspace);
        let instruction = ExpireSpaceDirectoryManifest {
            uaid,
            dataspace,
            expired_epoch: self.expired_epoch,
        };
        context.finish(vec![InstructionBox::from(instruction)])
    }
}
#[derive(clap::Args, Debug)]
pub struct ManifestFetchArgs {
    /// UAID literal whose manifests should be fetched.
    #[arg(long, value_name = "UAID")]
    pub uaid: UniversalAccountId,
    /// Shared collection filter, sort, projection and cursor pagination controls.
    #[command(flatten)]
    pub list: crate::collection_list::ListArgs,
}
impl Run for ManifestFetchArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        crate::collection_list::run_list(
            context,
            iroha::collections::Collection::UaidManifests(self.uaid),
            &self.list,
        )
    }
}
#[derive(clap::Args, Debug)]
pub struct ManifestScaffoldArgs {
    /// Exact canonical universal account identifier (`uaid:<64-lowercase-hex>`, LSB=1).
    #[arg(long = "uaid", value_name = "UAID", required = true)]
    pub uaid: String,
    /// Dataspace identifier the manifest targets.
    #[arg(long = "dataspace", value_name = "ID", required = true)]
    pub dataspace: u64,
    /// Activation epoch recorded in the manifest.
    #[arg(long = "activation-epoch", value_name = "EPOCH", required = true)]
    pub activation_epoch: u64,
    /// Optional expiry epoch recorded in the manifest.
    #[arg(long = "expiry-epoch", value_name = "EPOCH")]
    pub expiry_epoch: Option<u64>,
    /// Override the issued timestamp (milliseconds since UNIX epoch).
    #[arg(long = "issued-ms", value_name = "MS")]
    pub issued_ms: Option<u64>,
    /// Optional notes propagated to scaffolded entries.
    #[arg(long = "notes", value_name = "TEXT")]
    pub notes: Option<String>,
    /// Output path for the manifest JSON (defaults to `artifacts/space_directory/scaffold/<timestamp>/manifest.json`).
    #[arg(long = "manifest-out", value_name = "PATH")]
    pub manifest_out: Option<PathBuf>,
    /// Optional output path for the dataspace profile skeleton (defaults beside the manifest).
    #[arg(long = "profile-out", value_name = "PATH")]
    pub profile_out: Option<PathBuf>,
    /// Optional allow-entry template.
    #[command(flatten)]
    pub allow: ManifestScaffoldAllowArgs,
    /// Optional deny-entry template.
    #[command(flatten)]
    pub deny: ManifestScaffoldDenyArgs,
    /// Dataspace profile scaffolding parameters.
    #[command(flatten)]
    pub profile: ManifestScaffoldProfileArgs,
}
#[derive(clap::Args, Debug, Default)]
pub struct ManifestScaffoldAllowArgs {
    /// Optional dataspace override for the allow entry scope.
    #[arg(long = "allow-dataspace", value_name = "ID", id = "allow_dataspace")]
    pub dataspace: Option<u64>,
    /// Program identifier (`contract.name`) for the allow entry.
    #[arg(long = "allow-program", value_name = "PROGRAM", id = "allow_program")]
    pub program: Option<String>,
    /// Method/entry-point for the allow entry.
    #[arg(long = "allow-method", value_name = "NAME", id = "allow_method")]
    pub method: Option<String>,
    /// Asset identifier (e.g. `61CtjvNd9T3THAR65GsMVHr82Bjc`) for the allow entry.
    #[arg(long = "allow-asset", value_name = "ASSET-ID", id = "allow_asset")]
    pub asset: Option<String>,
    /// AMX role enforced by the allow entry (`initiator` or `participant`).
    #[arg(long = "allow-role", value_name = "ROLE", id = "allow_role")]
    pub role: Option<String>,
    /// Deterministic allowance cap (decimal string).
    #[arg(
        long = "allow-max-amount",
        value_name = "DECIMAL",
        id = "allow_max_amount"
    )]
    pub max_amount: Option<String>,
    /// Allowance window (`per-slot`, `per-minute`, or `per-day`).
    #[arg(long = "allow-window", value_name = "WINDOW", id = "allow_window")]
    pub window: Option<String>,
    /// Optional operator note stored alongside the entry.
    #[arg(long = "allow-notes", value_name = "TEXT", id = "allow_notes")]
    pub notes: Option<String>,
}
#[derive(clap::Args, Debug, Default)]
pub struct ManifestScaffoldDenyArgs {
    /// Optional dataspace override for the deny entry scope.
    #[arg(long = "deny-dataspace", value_name = "ID", id = "deny_dataspace")]
    pub dataspace: Option<u64>,
    /// Program identifier (`contract.name`) for the deny entry.
    #[arg(long = "deny-program", value_name = "PROGRAM", id = "deny_program")]
    pub program: Option<String>,
    /// Method/entry-point for the deny entry.
    #[arg(long = "deny-method", value_name = "NAME", id = "deny_method")]
    pub method: Option<String>,
    /// Asset identifier (e.g. `61CtjvNd9T3THAR65GsMVHr82Bjc`) for the deny entry.
    #[arg(long = "deny-asset", value_name = "ASSET-ID", id = "deny_asset")]
    pub asset: Option<String>,
    /// AMX role enforced by the deny entry.
    #[arg(long = "deny-role", value_name = "ROLE", id = "deny_role")]
    pub role: Option<String>,
    /// Optional reason recorded for the deny directive.
    #[arg(long = "deny-reason", value_name = "TEXT", id = "deny_reason")]
    pub reason: Option<String>,
    /// Optional operator note stored alongside the entry.
    #[arg(long = "deny-notes", value_name = "TEXT", id = "deny_notes")]
    pub notes: Option<String>,
}
#[derive(clap::Args, Debug, Default)]
pub struct ManifestScaffoldProfileArgs {
    /// Dataspace profile identifier (default `profile.<dataspace>.v1`).
    #[arg(long = "profile-id", value_name = "ID", id = "profile_id")]
    pub profile_id: Option<String>,
    /// Epoch recorded in the profile metadata.
    #[arg(
        long = "profile-activation-epoch",
        value_name = "EPOCH",
        id = "profile_activation_epoch"
    )]
    pub activation_epoch: Option<u64>,
    /// Dataspace governance issuer account.
    #[arg(
        long = "profile-governance-issuer",
        value_name = "ACCOUNT_ID",
        id = "profile_governance_issuer"
    )]
    pub governance_issuer: Option<String>,
    /// Governance ticket/evidence label.
    #[arg(
        long = "profile-governance-ticket",
        value_name = "TEXT",
        id = "profile_governance_ticket"
    )]
    pub governance_ticket: Option<String>,
    /// Governance quorum threshold.
    #[arg(
        long = "profile-governance-quorum",
        value_name = "N",
        id = "profile_governance_quorum"
    )]
    pub governance_quorum: Option<u32>,
    /// Validator account identifiers.
    #[arg(
        long = "profile-validator",
        value_name = "ACCOUNT_ID",
        id = "profile_validator"
    )]
    pub validators: Vec<String>,
    /// Validator quorum threshold.
    #[arg(
        long = "profile-validator-quorum",
        value_name = "N",
        id = "profile_validator_quorum"
    )]
    pub validator_quorum: Option<u32>,
    /// Protected namespace entries.
    #[arg(
        long = "profile-protected-namespace",
        value_name = "NAME",
        id = "profile_protected_namespace"
    )]
    pub protected_namespaces: Vec<String>,
    /// DA class label (default `A`).
    #[arg(
        long = "profile-da-class",
        value_name = "TEXT",
        id = "profile_da_class"
    )]
    pub da_class: Option<String>,
    /// DA attester quorum.
    #[arg(long = "profile-da-quorum", value_name = "N", id = "profile_da_quorum")]
    pub da_quorum: Option<u32>,
    /// DA attester identifiers.
    #[arg(
        long = "profile-da-attester",
        value_name = "ACCOUNT_ID",
        id = "profile_da_attester"
    )]
    pub da_attesters: Vec<String>,
    /// DA rotation cadence in epochs.
    #[arg(
        long = "profile-da-rotation-epochs",
        value_name = "EPOCHS",
        id = "profile_da_rotation_epochs"
    )]
    pub da_rotation_epochs: Option<u64>,
    /// Composability group identifier (hex string).
    #[arg(
        long = "profile-composability-group",
        value_name = "HEX",
        id = "profile_composability_group"
    )]
    pub composability_group: Option<String>,
    /// Optional audit log schema hint.
    #[arg(
        long = "profile-audit-log-schema",
        value_name = "TEXT",
        id = "profile_audit_log_schema"
    )]
    pub audit_log_schema: Option<String>,
    /// Optional `PagerDuty` service label.
    #[arg(
        long = "profile-pagerduty-service",
        value_name = "TEXT",
        id = "profile_pagerduty_service"
    )]
    pub pagerduty_service: Option<String>,
}
impl Run for ManifestScaffoldArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let uaid = parse_uaid_literal(&self.uaid)?;
        let dataspace = DataSpaceId::new(self.dataspace);
        let issued_ms = self.issued_ms.unwrap_or(current_unix_time_ms()?);
        let entries = self.build_entries(dataspace)?;
        let manifest = AssetPermissionManifest {
            version: ManifestVersion::V1,
            uaid,
            dataspace,
            issued_ms,
            activation_epoch: self.activation_epoch,
            expiry_epoch: self.expiry_epoch,
            entries,
        };
        let manifest_path = self.resolve_manifest_out(&manifest)?;
        write_json(&manifest_path, &manifest)?;
        context.println(format!(
            "Wrote Space Directory manifest scaffold to {}",
            manifest_path.display()
        ))?;
        if let Some(profile_path) = self.resolve_profile_out(&manifest_path)? {
            let profile_json = self
                .profile
                .build_profile_value(&manifest, self.notes.as_deref());
            write_json(&profile_path, &profile_json)?;
            context.println(format!(
                "Wrote dataspace profile scaffold to {}",
                profile_path.display()
            ))?;
        }
        Ok(())
    }
}
impl ManifestScaffoldArgs {
    fn build_entries(&self, manifest_dataspace: DataSpaceId) -> Result<Vec<ManifestEntry>> {
        let mut entries = Vec::new();
        if let Some(entry) = self
            .allow
            .build_entry(manifest_dataspace, self.notes.as_deref())?
        {
            entries.push(entry);
        }
        if let Some(entry) = self
            .deny
            .build_entry(manifest_dataspace, self.notes.as_deref())?
        {
            entries.push(entry);
        }
        Ok(entries)
    }
    fn resolve_manifest_out(&self, manifest: &AssetPermissionManifest) -> Result<PathBuf> {
        let path = self.manifest_out.as_ref().map_or_else(
            || {
                let dir = default_scaffold_dir().join(format!(
                    "{}_{}",
                    manifest.dataspace.as_u64(),
                    manifest.activation_epoch
                ));
                dir.join("manifest.json")
            },
            PathBuf::clone,
        );
        ensure_parent_dir(&path)?;
        Ok(path)
    }
    fn resolve_profile_out(&self, manifest_path: &Path) -> Result<Option<PathBuf>> {
        let path = self.profile_out.as_ref().map_or_else(
            || {
                manifest_path.parent().map_or_else(
                    || PathBuf::from("profile.json"),
                    |dir| dir.join("profile.json"),
                )
            },
            PathBuf::clone,
        );
        ensure_parent_dir(&path)?;
        Ok(Some(path))
    }
}
impl ManifestScaffoldAllowArgs {
    fn build_entry(
        &self,
        manifest_dataspace: DataSpaceId,
        default_notes: Option<&str>,
    ) -> Result<Option<ManifestEntry>> {
        if self.is_empty() {
            return Ok(None);
        }
        let scope = CapabilityScope {
            dataspace: self.dataspace.map(DataSpaceId::new),
            program: opt_program(self.program.as_deref(), "--allow-program")?,
            method: opt_name(self.method.as_deref(), "--allow-method")?,
            asset: opt_asset(self.asset.as_deref(), "--allow-asset")?,
            role: opt_amx_role(self.role.as_deref(), "--allow-role")?,
        };
        let allowance = Allowance {
            max_amount: match self.max_amount.as_deref() {
                Some(value) => Some(parse_quantity(value, "--allow-max-amount")?),
                None => None,
            },
            window: parse_allowance_window(self.window.as_deref())?,
        };
        let notes = self
            .notes
            .clone()
            .or_else(|| default_notes.map(ToOwned::to_owned));
        Ok(Some(ManifestEntry {
            scope: update_scope_defaults(scope, manifest_dataspace),
            effect: ManifestEffect::Allow(allowance),
            notes,
        }))
    }
    fn is_empty(&self) -> bool {
        self.dataspace.is_none()
            && self.program.is_none()
            && self.method.is_none()
            && self.asset.is_none()
            && self.role.is_none()
            && self.max_amount.is_none()
    }
}
impl ManifestScaffoldDenyArgs {
    fn build_entry(
        &self,
        manifest_dataspace: DataSpaceId,
        default_notes: Option<&str>,
    ) -> Result<Option<ManifestEntry>> {
        if self.is_empty() {
            return Ok(None);
        }
        let scope = CapabilityScope {
            dataspace: self.dataspace.map(DataSpaceId::new),
            program: opt_program(self.program.as_deref(), "--deny-program")?,
            method: opt_name(self.method.as_deref(), "--deny-method")?,
            asset: opt_asset(self.asset.as_deref(), "--deny-asset")?,
            role: opt_amx_role(self.role.as_deref(), "--deny-role")?,
        };
        let notes = self
            .notes
            .clone()
            .or_else(|| default_notes.map(ToOwned::to_owned));
        let effect = ManifestEffect::Deny(DenyDirective {
            reason: self.reason.clone(),
        });
        Ok(Some(ManifestEntry {
            scope: update_scope_defaults(scope, manifest_dataspace),
            effect,
            notes,
        }))
    }
    fn is_empty(&self) -> bool {
        self.dataspace.is_none()
            && self.program.is_none()
            && self.method.is_none()
            && self.asset.is_none()
            && self.role.is_none()
            && self.reason.is_none()
    }
}
impl ManifestScaffoldProfileArgs {
    #[allow(clippy::too_many_lines)]
    fn build_profile_value(
        &self,
        manifest: &AssetPermissionManifest,
        default_notes: Option<&str>,
    ) -> JsonValue {
        let dataspace = manifest.dataspace.as_u64();
        let profile_id = self
            .profile_id
            .clone()
            .unwrap_or_else(|| format!("profile.{dataspace}.v1"));
        let activation_epoch = self.activation_epoch.unwrap_or(manifest.activation_epoch);
        let governance_issuer = self
            .governance_issuer
            .clone()
            .unwrap_or_else(|| "sorauﾛ1PyXﾉspjg6gnvｴ1ﾒﾑLﾈｵBﾄEwtﾃD8Rｸﾇgｦﾎｾﾚｶ7ｴvWUJA5A".to_owned());
        let governance_ticket = self
            .governance_ticket
            .clone()
            .unwrap_or_else(|| "gov-ticket-placeholder".to_owned());
        let governance_quorum = self.governance_quorum.unwrap_or(1);
        let validators = if self.validators.is_empty() {
            vec![
                "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D".to_owned(),
                "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB".to_owned(),
            ]
        } else {
            self.validators.clone()
        };
        let validator_quorum = self
            .validator_quorum
            .unwrap_or_else(|| u32::try_from(validators.len().max(1)).unwrap_or(u32::MAX));
        let protected_namespaces = if self.protected_namespaces.is_empty() {
            vec!["default".to_owned()]
        } else {
            self.protected_namespaces.clone()
        };
        let da_class = self.da_class.clone().unwrap_or_else(|| "A".to_owned());
        let da_quorum = self.da_quorum.unwrap_or(4);
        let da_attesters = if self.da_attesters.is_empty() {
            vec![
                "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6".to_owned(),
                "sorauﾛ1NcﾐuﾛﾀKﾓhﾈgｽXｦDTﾏｴtﾔﾐ8PJPfSﾕPuﾃ884ｳﾇヰ4ﾇJKTL36".to_owned(),
            ]
        } else {
            self.da_attesters.clone()
        };
        let da_rotation_epochs = self.da_rotation_epochs.unwrap_or(96);
        let composability_group = self.composability_group.clone().unwrap_or_else(|| {
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned()
        });
        let audit_log_schema = self
            .audit_log_schema
            .clone()
            .unwrap_or_else(|| "metrics/space_directory_audit.prom".to_owned());
        let pagerduty_service = self
            .pagerduty_service
            .clone()
            .unwrap_or_else(|| "space-directory-oncall".to_owned());
        let mut governance = json::Map::new();
        governance.insert("issuer".into(), JsonValue::from(governance_issuer));
        governance.insert("evidence_ticket".into(), JsonValue::from(governance_ticket));
        governance.insert(
            "quorum".into(),
            JsonValue::from(u64::from(governance_quorum)),
        );
        let mut da_profile = json::Map::new();
        da_profile.insert("class".into(), JsonValue::from(da_class));
        da_profile.insert("quorum".into(), JsonValue::from(u64::from(da_quorum)));
        da_profile.insert(
            "attesters".into(),
            JsonValue::Array(
                da_attesters
                    .into_iter()
                    .map(JsonValue::from)
                    .collect::<Vec<_>>(),
            ),
        );
        da_profile.insert(
            "rotation_epochs".into(),
            JsonValue::from(da_rotation_epochs),
        );
        let mut composability = json::Map::new();
        composability.insert("group_id_hex".into(), JsonValue::from(composability_group));
        composability.insert(
            "activation_epoch".into(),
            JsonValue::from(manifest.activation_epoch),
        );
        composability.insert("whitelist".into(), JsonValue::Array(Vec::new()));
        composability.insert(
            "deny_wins_policy".into(),
            JsonValue::from(default_notes.unwrap_or("update with governance guidance")),
        );
        let mut audit_hooks = json::Map::new();
        audit_hooks.insert(
            "events".into(),
            JsonValue::Array(vec![
                JsonValue::from("SpaceDirectoryEvent.ManifestActivated"),
                JsonValue::from("SpaceDirectoryEvent.ManifestRevoked"),
            ]),
        );
        audit_hooks.insert("log_schema".into(), JsonValue::from(audit_log_schema));
        audit_hooks.insert(
            "pagerduty_service".into(),
            JsonValue::from(pagerduty_service),
        );
        let mut profile = json::Map::new();
        profile.insert("profile_id".into(), JsonValue::from(profile_id));
        profile.insert("dataspace".into(), JsonValue::from(dataspace));
        profile.insert("activation_epoch".into(), JsonValue::from(activation_epoch));
        profile.insert("governance".into(), JsonValue::Object(governance));
        profile.insert(
            "validators".into(),
            JsonValue::Array(validators.into_iter().map(JsonValue::from).collect()),
        );
        profile.insert(
            "validator_quorum".into(),
            JsonValue::from(u64::from(validator_quorum)),
        );
        profile.insert(
            "protected_namespaces".into(),
            JsonValue::Array(
                protected_namespaces
                    .into_iter()
                    .map(JsonValue::from)
                    .collect(),
            ),
        );
        profile.insert("da_profile".into(), JsonValue::Object(da_profile));
        profile.insert(
            "composability_group".into(),
            JsonValue::Object(composability),
        );
        profile.insert("audit_hooks".into(), JsonValue::Object(audit_hooks));
        JsonValue::Object(profile)
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum BindingsCommand {
    /// Fetch UAID dataspace bindings via Torii.
    Fetch(BindingsFetchArgs),
}
impl Run for BindingsCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            BindingsCommand::Fetch(args) => args.run(context),
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct BindingsFetchArgs {
    /// UAID literal whose bindings should be fetched.
    #[arg(long, value_name = "UAID")]
    pub uaid: String,
    /// Optional path where the JSON response will be stored.
    #[arg(long = "json-out", value_name = "PATH")]
    pub json_out: Option<PathBuf>,
}
impl Run for BindingsFetchArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = SpaceDirectoryRestClient::new(context.config())?;
        let payload = client.fetch_bindings(&self)?;
        if let Some(path) = &self.json_out {
            write_json_response(path, &payload)?;
        }
        context.print_data(&payload)
    }
}
impl Run for ManifestAuditBundleArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let manifest =
            load_manifest_from_sources(self.manifest.as_deref(), self.manifest_json.as_deref())?;
        let encoded = norito::core::to_bytes_bounded(&manifest, SPACE_DIRECTORY_INPUT_MAX_BYTES_V1)
            .map_err(|error| eyre!("failed to encode bounded manifest payload: {error}"))?;
        fs::create_dir_all(&self.out_dir).wrap_err_with(|| {
            format!(
                "failed to create audit bundle directory {}",
                self.out_dir.display()
            )
        })?;
        let manifest_json_name = "manifest.json";
        let manifest_to_name = "manifest.to";
        let manifest_hash_name = "manifest.hash";
        let profile_json_name = "profile.json";
        let bundle_name = "audit_bundle.json";
        let manifest_json_path = self.out_dir.join(manifest_json_name);
        let manifest_to_path = self.out_dir.join(manifest_to_name);
        let manifest_hash_path = self.out_dir.join(manifest_hash_name);
        let profile_out_path = self.out_dir.join(profile_json_name);
        let bundle_path = self.out_dir.join(bundle_name);
        let manifest_json_bytes = encode_space_directory_json_bounded(&manifest)
            .wrap_err("failed to serialize manifest JSON for audit bundle")?;
        fs::write(&manifest_json_path, manifest_json_bytes).wrap_err_with(|| {
            format!(
                "failed to write manifest JSON to {}",
                manifest_json_path.display()
            )
        })?;
        fs::write(&manifest_to_path, &encoded).wrap_err_with(|| {
            format!(
                "failed to write manifest Norito payload to {}",
                manifest_to_path.display()
            )
        })?;
        let manifest_hash = iroha_crypto::Hash::new(&encoded);
        let manifest_hash_hex = hex::encode(manifest_hash.as_ref());
        fs::write(&manifest_hash_path, format!("{manifest_hash_hex}\n")).wrap_err_with(|| {
            format!(
                "failed to write manifest hash to {}",
                manifest_hash_path.display()
            )
        })?;
        let profile_bytes = read_space_directory_file_bounded(&self.profile, "dataspace profile")?;
        let profile_json: JsonValue =
            decode_space_directory_json(&profile_bytes, "dataspace profile JSON")?;
        drop(profile_bytes);
        let profile_serialized = encode_space_directory_json_bounded(&profile_json)
            .wrap_err("failed to serialize profile JSON for audit bundle")?;
        fs::write(&profile_out_path, profile_serialized).wrap_err_with(|| {
            format!(
                "failed to write profile JSON to {}",
                profile_out_path.display()
            )
        })?;
        let audit_hooks = extract_audit_hooks(&profile_json)?;
        let generated_at_ms = current_unix_time_ms()?;
        let dataspace_id: u64 = manifest.dataspace.into();
        let bundle = ManifestAuditBundle {
            generated_at_ms,
            uaid: manifest.uaid.to_string(),
            dataspace_id,
            manifest_hash: manifest_hash_hex,
            activation_epoch: manifest.activation_epoch,
            expiry_epoch: manifest.expiry_epoch,
            audit_hooks,
            notes: self.notes.clone(),
            artifacts: BundleArtifacts {
                manifest_json: manifest_json_name.to_owned(),
                manifest_norito: manifest_to_name.to_owned(),
                manifest_hash: manifest_hash_name.to_owned(),
                profile_json: profile_json_name.to_owned(),
            },
            profile: profile_json,
        };
        let bundle_bytes = encode_space_directory_json_bounded(&bundle)
            .wrap_err("failed to serialize audit bundle metadata")?;
        fs::write(&bundle_path, bundle_bytes).wrap_err_with(|| {
            format!("failed to write audit bundle to {}", bundle_path.display())
        })?;
        context.println(format!(
            "Wrote Space Directory audit bundle to {}",
            bundle_path.display()
        ))?;
        Ok(())
    }
}
struct SpaceDirectoryRestClient {
    client: BlockingHttpClient,
    base_url: Url,
    basic_auth: Option<(String, String)>,
}
impl SpaceDirectoryRestClient {
    fn new(config: &Config) -> Result<Self> {
        let client = BlockingHttpClient::builder()
            .user_agent("iroha-cli space-directory")
            .build()
            .wrap_err("failed to construct HTTP client for space-directory queries")?;
        let basic_auth = config.basic_auth.as_ref().map(|auth| {
            (
                auth.web_login.as_str().to_owned(),
                auth.password.expose_secret().to_owned(),
            )
        });
        Ok(Self {
            client,
            base_url: config.torii_api_url.clone(),
            basic_auth,
        })
    }
    fn fetch_bindings(&self, args: &BindingsFetchArgs) -> Result<JsonValue> {
        let url = build_space_directory_url(
            &self.base_url,
            &["v1", "space-directory", "uaids", args.uaid.as_str()],
        )?;
        self.get_json(&url)
    }
    fn get_json(&self, url: &Url) -> Result<JsonValue> {
        let mut request = self
            .client
            .get(url.clone())
            .header(ACCEPT, HeaderValue::from_static("application/json"));
        if let Some((ref login, ref password)) = self.basic_auth {
            request = request.basic_auth(login, Some(password));
        }
        let mut response = request
            .send()
            .wrap_err_with(|| format!("failed to query Torii at {url}"))?;
        let status = response.status();
        let declared_bytes = response.content_length();
        let bytes = read_space_directory_body_bounded(
            &mut response,
            declared_bytes,
            SPACE_DIRECTORY_INPUT_MAX_BYTES_V1,
        )?;
        if !status.is_success() {
            let preview_len = bytes.len().min(SPACE_DIRECTORY_ERROR_PREVIEW_BYTES_V1);
            let preview = String::from_utf8_lossy(&bytes[..preview_len]);
            return Err(eyre!(
                "Torii {url} responded with {}: {}",
                status,
                preview.trim()
            ));
        }
        decode_space_directory_json(&bytes, "Torii response JSON")
    }
}
fn write_json_response(path: &Path, value: &JsonValue) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes = encode_space_directory_json_bounded(value)?;
    fs::write(path, bytes).wrap_err_with(|| format!("failed to write {}", path.display()))
}
fn build_space_directory_url(base: &Url, segments: &[&str]) -> Result<Url> {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|()| eyre!("torii_api_url must include a path segment-ready base"))?;
        path.pop_if_empty();
        path.extend(segments);
    }
    Ok(url)
}
fn load_manifest_from_sources(
    manifest_path: Option<&Path>,
    manifest_json_path: Option<&Path>,
) -> Result<AssetPermissionManifest> {
    match (manifest_path, manifest_json_path) {
        (Some(path), None) => {
            let bytes = read_space_directory_file_bounded(path, "manifest payload")?;
            norito::with_decode_limits_scope(SPACE_DIRECTORY_BINARY_DECODE_LIMITS_V1, || {
                AssetPermissionManifest::decode(&mut &*bytes)
            })
            .wrap_err("manifest is not valid bounded Norito")
        }
        (None, Some(path)) => {
            let bytes = read_space_directory_file_bounded(path, "manifest JSON")?;
            decode_space_directory_json(&bytes, "manifest JSON")
                .wrap_err_with(|| format!("manifest JSON is invalid ({})", path.display()))
        }
        (None, None) => Err(eyre::eyre!(
            "either --manifest (Norito .to) or --manifest-json (raw JSON) must be provided"
        )),
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    }
}
fn read_space_directory_file_bounded(path: &Path, label: &str) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("failed to inspect {label} {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(eyre!(
            "{label} must be a direct regular file: {}",
            path.display()
        ));
    }
    if path_metadata.len() > SPACE_DIRECTORY_INPUT_MAX_BYTES_V1 as u64 {
        return Err(eyre!(
            "{label} {} exceeds the first-release limit of {} bytes",
            path.display(),
            SPACE_DIRECTORY_INPUT_MAX_BYTES_V1
        ));
    }
    let mut file = open_space_directory_input_file(path)
        .wrap_err_with(|| format!("failed to open {label} {}", path.display()))?;
    let before = file
        .metadata()
        .wrap_err_with(|| format!("failed to inspect opened {label} {}", path.display()))?;
    if !before.is_file() || before.len() > SPACE_DIRECTORY_INPUT_MAX_BYTES_V1 as u64 {
        return Err(eyre!(
            "{label} must be a regular file within {} bytes: {}",
            SPACE_DIRECTORY_INPUT_MAX_BYTES_V1,
            path.display()
        ));
    }
    let bytes = super::read_cli_input_bounded(&mut file, SPACE_DIRECTORY_INPUT_MAX_BYTES_V1, label)
        .wrap_err_with(|| format!("failed to read {label} {}", path.display()))?;
    let after = file
        .metadata()
        .wrap_err_with(|| format!("failed to reinspect {label} {}", path.display()))?;
    if before.len() != after.len() || after.len() != bytes.len() as u64 {
        return Err(eyre!("{label} changed while reading: {}", path.display()));
    }
    Ok(bytes)
}
#[cfg(unix)]
fn open_space_directory_input_file(path: &Path) -> std::io::Result<fs::File> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    Ok(fs::File::from(descriptor))
}
#[cfg(windows)]
fn open_space_directory_input_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}
#[cfg(not(any(unix, windows)))]
fn open_space_directory_input_file(path: &Path) -> std::io::Result<fs::File> {
    fs::File::open(path)
}
fn read_space_directory_body_bounded<R: std::io::Read>(
    reader: &mut R,
    declared_bytes: Option<u64>,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if declared_bytes.is_some_and(|length| length > max_bytes as u64) {
        return Err(eyre!(
            "Space Directory response Content-Length exceeds the first-release limit of {max_bytes} bytes"
        ));
    }
    super::read_cli_input_bounded(reader, max_bytes, "Space Directory response body")
}
fn decode_space_directory_json<T>(bytes: &[u8], label: &str) -> Result<T>
where
    T: JsonDeserialize,
{
    if bytes.len() > SPACE_DIRECTORY_INPUT_MAX_BYTES_V1 {
        return Err(eyre!(
            "{label} exceeds the first-release input limit of {} bytes",
            SPACE_DIRECTORY_INPUT_MAX_BYTES_V1
        ));
    }
    json::preflight_slice(
        bytes,
        json::JsonPreflightLimits::from_decode_limits(
            SPACE_DIRECTORY_INPUT_MAX_BYTES_V1,
            SPACE_DIRECTORY_JSON_DECODE_LIMITS_V1,
        ),
    )
    .map_err(|error| eyre!("{label} exceeds its JSON lexical resource bounds: {error}"))?;
    norito::with_decode_limits_scope(SPACE_DIRECTORY_JSON_DECODE_LIMITS_V1, || {
        json::from_slice(bytes)
    })
    .map_err(|_| eyre!("{label} could not be decoded within its resource limits"))
}
fn encode_space_directory_json_bounded<T>(value: &T) -> Result<Vec<u8>>
where
    T: JsonSerialize + ?Sized,
{
    json::to_json_bounded(value, SPACE_DIRECTORY_OUTPUT_MAX_BYTES_V1)
        .map(String::into_bytes)
        .map_err(|error| eyre!("JSON output exceeds its bounded resource corridor: {error}"))
}
fn extract_audit_hooks(profile: &JsonValue) -> Result<Option<AuditHookSummary>> {
    let Some(raw_hooks) = profile.get("audit_hooks") else {
        return Ok(None);
    };
    if raw_hooks.is_null() {
        return Ok(None);
    }
    let hooks: AuditHookSummary =
        norito::with_decode_limits_scope(SPACE_DIRECTORY_JSON_DECODE_LIMITS_V1, || {
            norito::json::from_value(raw_hooks.clone())
        })
        .wrap_err("profile audit_hooks could not be parsed")?;
    eyre::ensure!(
        hooks
            .events
            .iter()
            .any(|event| event == "SpaceDirectoryEvent.ManifestActivated"),
        "profile audit_hooks.events must include SpaceDirectoryEvent.ManifestActivated"
    );
    eyre::ensure!(
        hooks
            .events
            .iter()
            .any(|event| event == "SpaceDirectoryEvent.ManifestRevoked"),
        "profile audit_hooks.events must include SpaceDirectoryEvent.ManifestRevoked"
    );
    Ok(Some(hooks))
}
fn current_unix_time_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock drifted before UNIX_EPOCH")?;
    u64::try_from(duration.as_millis())
        .map_err(|_| eyre!("system clock exceeded u64::MAX milliseconds since UNIX_EPOCH"))
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
fn default_scaffold_dir() -> PathBuf {
    PathBuf::from("artifacts")
        .join("space_directory")
        .join("scaffold")
}
fn write_json<T: JsonSerialize>(path: &Path, value: &T) -> Result<()> {
    ensure_parent_dir(path)?;
    let bytes = encode_space_directory_json_bounded(value)?;
    fs::write(path, bytes).wrap_err_with(|| format!("failed to write {}", path.display()))
}
fn parse_quantity(value: &str, flag: &str) -> Result<Quantity> {
    value
        .parse::<Quantity>()
        .wrap_err_with(|| format!("{flag} must be a non-negative decimal quantity"))
}
fn parse_allowance_window(value: Option<&str>) -> Result<AllowanceWindow> {
    value.map_or(Ok(AllowanceWindow::PerDay), |raw| match raw {
        "per-day" => Ok(AllowanceWindow::PerDay),
        "per-minute" => Ok(AllowanceWindow::PerMinute),
        "per-slot" => Ok(AllowanceWindow::PerSlot),
        _ => Err(eyre!(
            "invalid allowance window `{raw}`; expected exactly `per-day`, `per-minute`, or `per-slot`"
        )),
    })
}
#[cfg(test)]
mod quantity_tests {
    use super::*;

    #[test]
    fn allowance_cap_parser_rejects_negative_quantity() {
        let error = parse_quantity("-1", "--allow-max-amount")
            .expect_err("negative manifest cap must fail");
        assert!(error.to_string().contains("non-negative decimal quantity"));
    }

    #[test]
    fn allowance_window_parser_accepts_only_exact_first_release_spellings() {
        assert_eq!(
            parse_allowance_window(None).expect("omitted window uses the documented default"),
            AllowanceWindow::PerDay
        );
        for (literal, expected) in [
            ("per-day", AllowanceWindow::PerDay),
            ("per-minute", AllowanceWindow::PerMinute),
            ("per-slot", AllowanceWindow::PerSlot),
        ] {
            assert_eq!(
                parse_allowance_window(Some(literal)).expect("canonical allowance window"),
                expected
            );
        }
        for retired in [
            "",
            "perday",
            "perminute",
            "perslot",
            "PerDay",
            " per-day",
            "per-day ",
        ] {
            let _error = parse_allowance_window(Some(retired))
                .expect_err("allowance window aliases and normalized spellings must fail");
        }
    }

    #[test]
    fn amx_role_parser_accepts_only_exact_first_release_spellings() {
        assert_eq!(
            opt_amx_role(Some("initiator"), "--allow-role").expect("canonical initiator role"),
            Some(AmxRole::Initiator)
        );
        assert_eq!(
            opt_amx_role(Some("participant"), "--allow-role").expect("canonical participant role"),
            Some(AmxRole::Participant)
        );
        for retired in ["Initiator", "PARTICIPANT", " initiator", "participant "] {
            let _error = opt_amx_role(Some(retired), "--allow-role")
                .expect_err("AMX role aliases and normalized spellings must fail");
        }
    }
}
fn opt_program(value: Option<&str>, flag: &str) -> Result<Option<SmartContractId>> {
    value
        .map(|raw| {
            raw.parse()
                .wrap_err_with(|| format!("failed to parse {flag}"))
        })
        .transpose()
}
fn opt_name(value: Option<&str>, flag: &str) -> Result<Option<Name>> {
    value
        .map(|raw| {
            raw.parse()
                .wrap_err_with(|| format!("failed to parse {flag}"))
        })
        .transpose()
}
fn opt_asset(value: Option<&str>, flag: &str) -> Result<Option<AssetDefinitionId>> {
    value
        .map(|raw| {
            AssetDefinitionId::parse_address_literal(raw)
                .wrap_err_with(|| format!("failed to parse {flag}"))
        })
        .transpose()
}
fn opt_amx_role(value: Option<&str>, flag: &str) -> Result<Option<AmxRole>> {
    value
        .map(|raw| match raw {
            "initiator" => Ok(AmxRole::Initiator),
            "participant" => Ok(AmxRole::Participant),
            other => Err(eyre!("invalid {} role `{other}`", flag)),
        })
        .transpose()
}
fn update_scope_defaults(
    mut scope: CapabilityScope,
    manifest_dataspace: DataSpaceId,
) -> CapabilityScope {
    if scope.dataspace.is_none() {
        scope.dataspace = Some(manifest_dataspace);
    }
    scope
}
fn parse_uaid_literal(raw: &str) -> Result<UniversalAccountId> {
    UniversalAccountId::from_str(raw)
        .wrap_err("UAID literal must be exact canonical `uaid:<lowercase-hex>`")
}
#[derive(Debug, JsonSerialize)]
struct ManifestAuditBundle {
    generated_at_ms: u64,
    uaid: String,
    dataspace_id: u64,
    manifest_hash: String,
    activation_epoch: u64,
    expiry_epoch: Option<u64>,
    #[norito(skip_serializing_if = "Option::is_none")]
    audit_hooks: Option<AuditHookSummary>,
    #[norito(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    artifacts: BundleArtifacts,
    profile: JsonValue,
}
#[derive(Debug, JsonSerialize)]
struct BundleArtifacts {
    manifest_json: String,
    manifest_norito: String,
    manifest_hash: String,
    profile_json: String,
}
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize)]
struct AuditHookSummary {
    events: Vec<String>,
    #[norito(default)]
    log_schema: Option<String>,
    #[norito(default)]
    pagerduty_service: Option<String>,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::RunContext;
    use eyre::Result;
    use iroha::{
        config::Config,
        crypto::{Algorithm, Hash as CryptoHash, KeyPair},
        data_model::{
            nexus::{
                Allowance, AllowanceWindow, AmxRole, CapabilityScope, ManifestEffect,
                ManifestEntry, ManifestVersion, UniversalAccountId,
            },
            prelude::*,
        },
    };
    use iroha_i18n::{Bundle, Language, Localizer};
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::topology::DataSpaceId;
    use norito::json::JsonSerialize;
    use std::path::Path;
    use tempfile::tempdir;
    use url::Url;
    #[test]
    fn parse_uaid_literal_accepts_only_canonical_form() {
        let uaid = UniversalAccountId::from_hash(CryptoHash::new(b"cli-uaid"));
        let hex = uaid.as_hash().to_string();
        let canonical = format!("uaid:{hex}");
        assert_eq!(
            parse_uaid_literal(&canonical).expect("parse canonical UAID literal"),
            uaid
        );
        for literal in [
            hex.clone(),
            format!("UAID:{}", hex.to_uppercase()),
            format!(" {canonical}"),
            format!("{canonical} "),
        ] {
            assert!(
                parse_uaid_literal(&literal).is_err(),
                "noncanonical UAID must reject: {literal:?}"
            );
        }
    }
    #[test]
    fn manifest_encode_writes_payload_and_hash_with_defaults() {
        let manifest = sample_manifest();
        let dir = tempdir().expect("tmpdir");
        let json_path = dir.path().join("manifest.json");
        write_manifest_json(&json_path, &manifest);
        let mut ctx = TestContext::new();
        ManifestEncodeArgs {
            json: json_path.clone(),
            out: None,
            hash_out: None,
        }
        .run(&mut ctx)
        .expect("encode manifest");
        let to_path = dir.path().join("manifest.manifest.to");
        let hash_path = dir.path().join("manifest.manifest.hash");
        assert!(to_path.exists(), "missing encoded payload");
        assert!(hash_path.exists(), "missing hash payload");
        let encoded = std::fs::read(&to_path).expect("read encoded manifest");
        let decoded: AssetPermissionManifest =
            norito::decode_from_bytes(&encoded).expect("decode Norito manifest");
        assert_eq!(decoded, manifest, "encoded manifest differs");
        assert_eq!(
            encoded,
            norito::to_bytes(&manifest).expect("encode canonical Norito manifest"),
            "encode command must emit canonical Norito bytes"
        );
        let expected_hash = iroha_crypto::Hash::new(&encoded);
        let hash_body = std::fs::read_to_string(&hash_path).expect("read manifest hash file");
        assert_eq!(
            hash_body.trim(),
            hex::encode(expected_hash.as_ref()),
            "hash file did not match encoded payload"
        );
        assert_eq!(
            ctx.lines.len(),
            2,
            "encode command should print two status lines"
        );
        assert!(
            ctx.lines[0].contains("Wrote Norito payload"),
            "missing payload log line"
        );
        assert!(
            ctx.lines[1].contains("Manifest hash"),
            "missing hash log line"
        );
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_scaffold_writes_manifest_and_profile_templates() {
        let dir = tempdir().expect("tmpdir");
        let manifest_path = dir.path().join("fixture").join("manifest.json");
        let profile_path = dir.path().join("fixture").join("profile.json");
        let allow_args = ManifestScaffoldAllowArgs {
            program: Some("cbdc.transfer".to_owned()),
            method: Some("transfer".to_owned()),
            asset: Some(
                AssetDefinitionId::derive_from_components(
                    iroha_model_base::domain::DomainId::try_new("wonderland", "universal")
                        .expect("domain"),
                    "cbdc".parse().expect("name"),
                )
                .to_string(),
            ),
            role: Some("initiator".to_owned()),
            max_amount: Some("500000000".to_owned()),
            window: Some("per-day".to_owned()),
            ..Default::default()
        };
        let deny_args = ManifestScaffoldDenyArgs {
            program: Some("cbdc.kit".to_owned()),
            method: Some("withdraw".to_owned()),
            reason: Some("Withdrawals disabled for dApp".to_owned()),
            ..Default::default()
        };
        let profile_args = ManifestScaffoldProfileArgs {
            profile_id: Some("profile.cbdc.preview".to_owned()),
            governance_issuer: Some(
                "sorauﾛ1PyXﾉspjg6gnvｴ1ﾒﾑLﾈｵBﾄEwtﾃD8Rｸﾇgｦﾎｾﾚｶ7ｴvWUJA5A".to_owned(),
            ),
            governance_ticket: Some("gov-ticket".to_owned()),
            governance_quorum: Some(4),
            validators: vec![
                "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D".to_owned(),
                "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB".to_owned(),
            ],
            validator_quorum: Some(2),
            protected_namespaces: vec!["cbdc".to_owned(), "gov".to_owned()],
            da_class: Some("A".to_owned()),
            da_quorum: Some(8),
            da_attesters: vec![
                "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6".to_owned(),
                "sorauﾛ1NcﾐuﾛﾀKﾓhﾈgｽXｦDTﾏｴtﾔﾐ8PJPfSﾕPuﾃ884ｳﾇヰ4ﾇJKTL36".to_owned(),
            ],
            da_rotation_epochs: Some(96),
            composability_group: Some(
                "3b2a4e8b7047e36de62a1b4a64f48870664f581e06e4b1340f9e963835d02c8b".to_owned(),
            ),
            audit_log_schema: Some("metrics/nexus_space_directory_audit.prom".to_owned()),
            pagerduty_service: Some("Nexus-SpaceDirectory".to_owned()),
            ..Default::default()
        };
        let mut ctx = TestContext::new();
        ManifestScaffoldArgs {
            uaid: sample_manifest().uaid.to_string(),
            dataspace: 11,
            activation_epoch: 4097,
            expiry_epoch: Some(8192),
            issued_ms: Some(1_762_723_200_000),
            notes: Some("scaffold smoke".to_owned()),
            manifest_out: Some(manifest_path.clone()),
            profile_out: Some(profile_path.clone()),
            allow: allow_args,
            deny: deny_args,
            profile: profile_args,
        }
        .run(&mut ctx)
        .expect("scaffold manifest/profile");
        assert!(manifest_path.exists(), "manifest scaffold missing");
        assert!(profile_path.exists(), "profile scaffold missing");
        let manifest_json: JsonValue =
            json::from_slice(&fs::read(&manifest_path).expect("read manifest scaffold"))
                .expect("parse manifest scaffold");
        assert_eq!(
            manifest_json.get("dataspace").and_then(JsonValue::as_u64),
            Some(11),
            "manifest dataspace mismatch"
        );
        assert_eq!(
            manifest_json
                .get("entries")
                .and_then(JsonValue::as_array)
                .map(Vec::len),
            Some(2),
            "manifest scaffold should include two entries"
        );
        let profile_json: JsonValue =
            json::from_slice(&fs::read(&profile_path).expect("read profile scaffold"))
                .expect("parse profile scaffold");
        let events = profile_json
            .get("audit_hooks")
            .and_then(|hooks| hooks.get("events"))
            .and_then(JsonValue::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(
            events
                .iter()
                .any(|value| value.as_str() == Some("SpaceDirectoryEvent.ManifestActivated")),
            "profile scaffold must subscribe to ManifestActivated"
        );
        assert!(
            events
                .iter()
                .any(|value| value.as_str() == Some("SpaceDirectoryEvent.ManifestRevoked")),
            "profile scaffold must subscribe to ManifestRevoked"
        );
        assert!(
            ctx.lines
                .iter()
                .any(|line| line.contains("manifest scaffold")),
            "scaffold command should log manifest path"
        );
    }
    #[test]
    fn manifest_encode_respects_custom_output_paths() {
        let manifest = sample_manifest();
        let dir = tempdir().expect("tmpdir");
        let json_path = dir.path().join("fixtures").join("manifest.json");
        std::fs::create_dir_all(json_path.parent().unwrap()).expect("json dir");
        write_manifest_json(&json_path, &manifest);
        let out_path = dir
            .path()
            .join("artifacts")
            .join("nexus")
            .join("uaid")
            .join("wholesale.to");
        let hash_path = dir
            .path()
            .join("metadata")
            .join("nexus")
            .join("uaid")
            .join("wholesale.hash");
        let mut ctx = TestContext::new();
        ManifestEncodeArgs {
            json: json_path,
            out: Some(out_path.clone()),
            hash_out: Some(hash_path.clone()),
        }
        .run(&mut ctx)
        .expect("encode manifest with overrides");
        assert!(out_path.exists(), "custom output path was not created");
        assert!(hash_path.exists(), "custom hash path was not created");
        let encoded = std::fs::read(&out_path).expect("read encoded manifest");
        let decoded: AssetPermissionManifest =
            norito::decode_from_bytes(&encoded).expect("decode canonical Norito manifest");
        assert_eq!(decoded, manifest, "custom output encoded manifest differs");
        let expected_hash = iroha_crypto::Hash::new(&encoded);
        let hash_body = std::fs::read_to_string(&hash_path).expect("read manifest hash file");
        assert_eq!(
            hash_body.trim(),
            hex::encode(expected_hash.as_ref()),
            "hash file did not match encoded payload"
        );
    }
    fn write_manifest_json(path: &Path, manifest: &AssetPermissionManifest) {
        let json_bytes = norito::json::to_vec(manifest).expect("serialize manifest to JSON");
        std::fs::write(path, json_bytes).expect("write JSON manifest");
    }
    fn sample_manifest() -> AssetPermissionManifest {
        AssetPermissionManifest {
            version: ManifestVersion::V1,
            uaid: UniversalAccountId::from_hash(CryptoHash::new(b"cli-manifest")),
            dataspace: DataSpaceId::new(11),
            issued_ms: 1_736_668_800_000,
            activation_epoch: 4_096,
            expiry_epoch: Some(4_600),
            entries: vec![ManifestEntry {
                scope: CapabilityScope {
                    dataspace: Some(DataSpaceId::new(11)),
                    program: None,
                    method: None,
                    asset: None,
                    role: Some(AmxRole::Initiator),
                },
                effect: ManifestEffect::Allow(Allowance {
                    max_amount: None,
                    window: AllowanceWindow::PerDay,
                }),
                notes: Some("CLI test manifest".to_string()),
            }],
        }
    }
    fn checked_space_directory_key_fixture() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate checked space directory fixture key")
    }
    #[test]
    fn build_space_directory_url_appends_segments() {
        let base = Url::parse("https://example.test/torii/").expect("base url");
        let url = build_space_directory_url(
            &base,
            &["v1", "space-directory", "uaids", "uaid:abc", "manifests"],
        )
        .expect("build url");
        assert_eq!(
            url.as_str(),
            "https://example.test/torii/v1/space-directory/uaids/uaid:abc/manifests"
        );
    }
    #[test]
    fn manifest_fetch_uses_shared_collection_query_flags() {
        #[derive(clap::Parser)]
        struct Args {
            #[command(flatten)]
            fetch: ManifestFetchArgs,
        }
        let uaid = UniversalAccountId::from_hash(CryptoHash::new(b"manifest-list"));
        let args = <Args as clap::Parser>::try_parse_from([
            "fetch",
            "--uaid",
            &uaid.to_string(),
            "--filter",
            "dataspace_id = 11",
            "--cursor",
            "manifest-page",
            "--include-total",
        ])
        .unwrap();
        let query = args.fetch.list.to_query().unwrap();
        assert_eq!(args.fetch.uaid, uaid);
        assert_eq!(query.cursor.as_deref(), Some("manifest-page"));
        assert!(query.include_total);
        for retired in ["--dataspace", "--offset", "--status", "--count-mode"] {
            assert!(
                <Args as clap::Parser>::try_parse_from([
                    "fetch",
                    "--uaid",
                    &uaid.to_string(),
                    retired,
                    "1",
                ])
                .is_err()
            );
        }
    }
    #[test]
    fn manifest_reason_rejects_aggregate_expansion_before_mutation() {
        let mut manifest = sample_manifest();
        manifest.entries[0].notes = None;
        manifest.entries.push(manifest.entries[0].clone());
        let before = manifest.clone();
        let error = apply_manifest_reason_bounded(&mut manifest, "ab", 3)
            .expect_err("aggregate max plus one must fail");
        assert!(error.to_string().contains("retained limit"));
        assert_eq!(manifest, before, "failed admission must not mutate entries");
    }
    #[test]
    fn bounded_file_reader_rejects_sparse_max_plus_one() {
        let dir = tempdir().expect("tmpdir");
        let small = dir.path().join("small.json");
        fs::write(&small, b"{}").expect("write small input");
        assert_eq!(
            read_space_directory_file_bounded(&small, "test input").expect("small input"),
            b"{}"
        );
        let oversized = dir.path().join("oversized.json");
        let file = fs::File::create(&oversized).expect("create sparse input");
        file.set_len(SPACE_DIRECTORY_INPUT_MAX_BYTES_V1 as u64 + 1)
            .expect("size sparse input");
        drop(file);
        let error = read_space_directory_file_bounded(&oversized, "test input")
            .expect_err("max plus one must fail before allocation");
        assert!(error.to_string().contains("first-release limit"));
    }
    #[cfg(unix)]
    #[test]
    fn bounded_file_reader_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("tmpdir");
        let target = dir.path().join("target.json");
        fs::write(&target, b"{}").expect("write target");
        let link = dir.path().join("link.json");
        symlink(&target, &link).expect("create symlink");
        let error = read_space_directory_file_bounded(&link, "test input")
            .expect_err("symlink must fail closed");
        assert!(error.to_string().contains("direct regular file"));
    }
    #[test]
    fn response_reader_preflights_length_and_probes_growth() {
        struct PanicReader;
        impl std::io::Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                panic!("declared oversize must fail before reading")
            }
        }
        let declared = read_space_directory_body_bounded(&mut PanicReader, Some(17), 16)
            .expect_err("declared max plus one must fail");
        assert!(declared.to_string().contains("Content-Length"));
        let mut exact = std::io::Cursor::new([0_u8; 16]);
        assert_eq!(
            read_space_directory_body_bounded(&mut exact, None, 16)
                .expect("exact response")
                .len(),
            16
        );
        let mut oversized = std::io::Cursor::new([0_u8; 17]);
        let error = read_space_directory_body_bounded(&mut oversized, None, 16)
            .expect_err("chunked max plus one must fail");
        assert!(error.to_string().contains("first-release limit"));
    }
    #[test]
    fn json_decoder_accepts_exact_depth_and_rejects_one_more() {
        let exact = format!(
            "{}null{}",
            "[".repeat(SPACE_DIRECTORY_JSON_MAX_NESTING_DEPTH_V1 - 1),
            "]".repeat(SPACE_DIRECTORY_JSON_MAX_NESTING_DEPTH_V1 - 1)
        );
        decode_space_directory_json::<JsonValue>(exact.as_bytes(), "test JSON")
            .expect("exact nesting depth");
        let over = format!("[{exact}]");
        let error = decode_space_directory_json::<JsonValue>(over.as_bytes(), "test JSON")
            .expect_err("max depth plus one must fail");
        assert!(error.to_string().contains("lexical resource bounds"));
    }
    #[test]
    fn write_json_response_creates_parent_directories() {
        let dir = tempdir().expect("tmpdir");
        let path = dir.path().join("nested").join("bindings.json");
        let payload = norito::json!({"uaid": "uaid:test", "dataspaces": []});
        write_json_response(&path, &payload).expect("write json");
        let written = std::fs::read_to_string(&path).expect("read json");
        assert!(
            written.contains("\"dataspaces\""),
            "json output should include the dataspaces array"
        );
    }
    struct TestContext {
        cfg: Config,
        lines: Vec<String>,
        i18n: Localizer,
    }
    impl TestContext {
        fn new() -> Self {
            let key_pair = checked_space_directory_key_fixture();
            let account_id = AccountId::new(key_pair.public_key().clone());
            let cfg = Config {
                chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
                network_id:
                    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                        .parse()
                        .expect("network id"),
                account: account_id,
                account_chain_discriminant:
                    iroha_config::parameters::defaults::common::chain_discriminant(),
                key_pair,
                basic_auth: None,
                api_token: None,
                http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
                torii_api_url: Url::parse("http://127.0.0.1/").unwrap(),
                torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
                transaction_ttl: iroha::config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
                transaction_status_timeout: iroha::config::DEFAULT_TRANSACTION_STATUS_TIMEOUT,
                transaction_add_nonce: iroha::config::DEFAULT_TRANSACTION_NONCE,
                sorafs_alias_cache: crate::config_utils::default_alias_cache_policy(),
                sorafs_anonymity_policy: crate::config_utils::default_anonymity_policy(),
                sorafs_rollout_phase: crate::config_utils::default_rollout_phase(),
            };
            Self {
                cfg,
                lines: Vec::new(),
                i18n: Localizer::new(Bundle::Cli, Language::English),
            }
        }
    }
    #[test]
    fn test_context_uses_checked_ed25519_key_generation() {
        let context = TestContext::new();
        let actual = context
            .cfg
            .key_pair
            .public_key()
            .try_algorithm()
            .expect("space directory fixture key advertises a valid algorithm");
        assert_eq!(actual, Algorithm::Ed25519);
    }
    impl RunContext for TestContext {
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
        fn print_data<T>(&mut self, _data: &T) -> Result<()>
        where
            T: JsonSerialize + ?Sized,
        {
            Ok(())
        }
        fn println(&mut self, data: impl std::fmt::Display) -> Result<()> {
            self.lines.push(data.to_string());
            Ok(())
        }
    }
}
