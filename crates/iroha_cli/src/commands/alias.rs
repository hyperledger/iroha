//! Alias resolution and declarative setup helpers.
//!
//! Setup planning is a canonical-account-signed read. Apply verifies the exact
//! plan frames locally and submits one ordinary transaction; neither command
//! accepts inline tokens or private keys.
use crate::cli_output::print_with_optional_text;
use crate::{Run, RunContext};
use eyre::{Result, WrapErr, eyre};
#[cfg(test)]
use iroha::client::AccountAliasListItemV1;
use iroha::client::{
    AccountAliasIndexResolutionV1, AccountAliasResolutionV1, AccountAliasesByAccountRequestV1,
    AccountAliasesByAccountV1, Client,
};
use iroha::data_model::{
    alias::AliasIndex,
    alias_setup::{
        AccountAliasName, AliasAutoRenewPlanRequestV1, AliasLeaseRenewPlanRequestV1,
        AliasLifecycleOperationV1, AliasLifecycleTransactionPlanV1, AliasSetupPlanRequestV1,
        AliasSetupStatusV1, AliasTransactionPlanV1,
    },
};
#[cfg(test)]
use iroha_i18n::{Bundle, Language, Localizer};
use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Inspect authenticated account-onboarding readiness.
    Doctor(DoctorArgs),
    /// Plan or apply one atomic declarative alias setup transaction.
    #[command(subcommand)]
    Setup(SetupCommand),
    /// Manage explicit alias lease lifecycle operations.
    #[command(subcommand)]
    Lease(LeaseCommand),
    /// Configure deterministic native alias auto-renew.
    #[command(subcommand)]
    AutoRenew(AutoRenewCommand),
    /// Resolve an alias by its canonical name.
    Resolve(ResolveArgs),
    /// Resolve an alias by deterministic index.
    ResolveIndex(ResolveIndexArgs),
    /// List aliases bound to a canonical account id.
    ByAccount(ByAccountArgs),
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Doctor(args) => args.run(context),
            Command::Setup(command) => command.run(context),
            Command::Lease(command) => command.run(context),
            Command::AutoRenew(command) => command.run(context),
            Command::Resolve(args) => args.run(context),
            Command::ResolveIndex(args) => args.run(context),
            Command::ByAccount(args) => args.run(context),
        }
    }
}
/// Explicit alias lease lifecycle commands.
#[derive(clap::Subcommand, Debug)]
pub enum LeaseCommand {
    /// Plan or apply an absolute-expiry lease renewal CAS.
    #[command(subcommand)]
    Renew(LeaseRenewCommand),
}
impl Run for LeaseCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Renew(command) => command.run(context),
        }
    }
}
/// Guarded alias lease renewal workflow.
#[derive(clap::Subcommand, Debug)]
pub enum LeaseRenewCommand {
    /// Plan a renewal against live state without mutating it.
    Plan(LeaseRenewPlanArgs),
    /// Verify, locally sign, and submit one exact renewal plan.
    Apply(LeaseRenewApplyArgs),
}
impl Run for LeaseRenewCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Plan(args) => args.run(context),
            Self::Apply(args) => args.run(context),
        }
    }
}
/// Owner-only alias auto-renew configuration workflow.
#[derive(clap::Subcommand, Debug)]
pub enum AutoRenewCommand {
    /// Plan a configuration CAS against live state without mutating it.
    Plan(AutoRenewPlanArgs),
    /// Verify, locally sign, and submit one exact configuration plan.
    Apply(AutoRenewApplyArgs),
}
impl Run for AutoRenewCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Plan(args) => args.run(context),
            Self::Apply(args) => args.run(context),
        }
    }
}
/// Declarative alias setup workflow.
#[derive(clap::Subcommand, Debug)]
pub enum SetupCommand {
    /// Plan an intent against live state without mutating it.
    Plan(SetupPlanArgs),
    /// Verify, locally sign, and submit one exact plan as a normal transaction.
    Apply(SetupApplyArgs),
}
impl Run for SetupCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Plan(args) => args.run(context),
            Self::Apply(args) => args.run(context),
        }
    }
}
/// Arguments for `iroha app alias setup plan`.
#[derive(clap::Args, Debug)]
pub struct SetupPlanArgs {
    /// Secret-free JSON file containing `AliasSetupPlanRequestV1`.
    #[arg(long, value_name = "PATH")]
    pub intent_file: PathBuf,
    /// Optional path at which to write the verified, secret-free plan JSON.
    #[arg(long, value_name = "PATH")]
    pub plan_file: Option<PathBuf>,
}
impl Run for SetupPlanArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let request: AliasSetupPlanRequestV1 =
            read_secret_free_json_file(&self.intent_file, "alias setup intent")?;
        if request.intents.is_empty() {
            return Err(eyre!(
                "alias setup intent must contain at least one resource"
            ));
        }
        let client = context.client_from_config()?;
        let plan = iroha::blocking::Client::from_client(client)?.plan_alias_setup(&request)?;
        if let Some(path) = &self.plan_file {
            write_secret_free_plan_file(path, &plan)?;
        }
        let text = render_alias_setup_plan_text(&plan, self.plan_file.as_deref());
        print_with_optional_text(context, Some(text), &plan)
    }
}
/// Arguments for `iroha app alias setup apply`.
#[derive(clap::Args, Debug)]
pub struct SetupApplyArgs {
    /// Secret-free JSON plan returned by `setup plan`.
    #[arg(long, value_name = "PATH")]
    pub plan_file: PathBuf,
}
impl Run for SetupApplyArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if context.input_instructions() || context.output_instructions() {
            return Err(eyre!(
                "alias setup apply cannot be combined with global instruction input/output flags"
            ));
        }
        let plan: AliasTransactionPlanV1 =
            read_secret_free_json_file(&self.plan_file, "alias setup plan")?;
        let client = context.client_from_config()?;
        let instructions = client.verify_alias_setup_plan(&plan)?;
        // `finish` constructs exactly one ordinary transaction from this full
        // ordered vector, quotes only its normal transaction fee, signs with the
        // configured client key, and submits through the existing transaction
        // endpoint. The verified plan authority and chain match that same client.
        context.finish(instructions)
    }
}
/// Arguments for `iroha app alias lease renew plan`.
#[derive(clap::Args, Debug)]
pub struct LeaseRenewPlanArgs {
    /// Secret-free JSON file containing `AliasLeaseRenewPlanRequestV1`.
    #[arg(long, value_name = "PATH")]
    pub intent_file: PathBuf,
    /// Optional path at which to write the verified, secret-free plan JSON.
    #[arg(long, value_name = "PATH")]
    pub plan_file: Option<PathBuf>,
}
impl Run for LeaseRenewPlanArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let request: AliasLeaseRenewPlanRequestV1 =
            read_secret_free_json_file(&self.intent_file, "alias lease renewal intent")?;
        let client = context.client_from_config()?;
        let plan = client.plan_alias_lease_renewal(&request)?;
        if let Some(path) = &self.plan_file {
            write_secret_free_plan_file(path, &plan)?;
        }
        let text = render_alias_lifecycle_plan_text(
            "alias lease renewal",
            &plan,
            self.plan_file.as_deref(),
        );
        print_with_optional_text(context, Some(text), &plan)
    }
}
/// Arguments for `iroha app alias lease renew apply`.
#[derive(clap::Args, Debug)]
pub struct LeaseRenewApplyArgs {
    /// Secret-free JSON plan returned by `lease renew plan`.
    #[arg(long, value_name = "PATH")]
    pub plan_file: PathBuf,
}
impl Run for LeaseRenewApplyArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        ensure_standalone_alias_apply(context, "alias lease renew apply")?;
        let plan: AliasLifecycleTransactionPlanV1 =
            read_secret_free_json_file(&self.plan_file, "alias lease renewal plan")?;
        if !matches!(
            &plan.body.operation,
            AliasLifecycleOperationV1::RenewLease(_)
        ) {
            return Err(eyre!(
                "alias lease renew apply requires a RenewAliasLease plan"
            ));
        }
        let instruction = context
            .client_from_config()?
            .verify_alias_lifecycle_plan(&plan)?
            .ok_or_else(|| eyre!("alias lease renewal plan cannot be a no-op"))?;
        context.finish([instruction])
    }
}
/// Arguments for `iroha app alias auto-renew plan`.
#[derive(clap::Args, Debug)]
pub struct AutoRenewPlanArgs {
    /// Secret-free JSON file containing `AliasAutoRenewPlanRequestV1`.
    #[arg(long, value_name = "PATH")]
    pub intent_file: PathBuf,
    /// Optional path at which to write the verified, secret-free plan JSON.
    #[arg(long, value_name = "PATH")]
    pub plan_file: Option<PathBuf>,
}
impl Run for AutoRenewPlanArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let request: AliasAutoRenewPlanRequestV1 =
            read_secret_free_json_file(&self.intent_file, "alias auto-renew intent")?;
        let client = context.client_from_config()?;
        let plan = client.plan_alias_auto_renew(&request)?;
        if let Some(path) = &self.plan_file {
            write_secret_free_plan_file(path, &plan)?;
        }
        let text =
            render_alias_lifecycle_plan_text("alias auto-renew", &plan, self.plan_file.as_deref());
        print_with_optional_text(context, Some(text), &plan)
    }
}
/// Arguments for `iroha app alias auto-renew apply`.
#[derive(clap::Args, Debug)]
pub struct AutoRenewApplyArgs {
    /// Secret-free JSON plan returned by `auto-renew plan`.
    #[arg(long, value_name = "PATH")]
    pub plan_file: PathBuf,
}
impl Run for AutoRenewApplyArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        ensure_standalone_alias_apply(context, "alias auto-renew apply")?;
        let plan: AliasLifecycleTransactionPlanV1 =
            read_secret_free_json_file(&self.plan_file, "alias auto-renew plan")?;
        if !matches!(
            &plan.body.operation,
            AliasLifecycleOperationV1::ConfigureAutoRenew(_)
        ) {
            return Err(eyre!(
                "alias auto-renew apply requires a ConfigureAliasAutoRenew plan"
            ));
        }
        let client = context.client_from_config()?;
        let Some(instruction) = client.verify_alias_lifecycle_plan(&plan)? else {
            let text = render_alias_lifecycle_plan_text("alias auto-renew", &plan, None);
            return print_with_optional_text(context, Some(text), &plan);
        };
        context.finish([instruction])
    }
}
/// Arguments for `iroha app alias doctor`.
#[derive(clap::Args, Debug)]
pub struct DoctorArgs {
    /// File containing the dedicated onboarding API token.
    #[arg(long, value_name = "PATH")]
    pub token_file: PathBuf,
}
impl Run for DoctorArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let token = read_onboarding_token_file(&self.token_file)?;
        let report = context
            .client_from_config()?
            .get_account_onboarding_readiness(&token)?;
        let text = render_alias_doctor_text(&report);
        print_with_optional_text(context, Some(text), &report)?;
        match report.status {
            AliasSetupStatusV1::Blocked => Err(eyre!(
                "alias onboarding readiness is blocked; follow the reported remediation"
            )),
            AliasSetupStatusV1::Pending | AliasSetupStatusV1::Ready => Ok(()),
        }
    }
}
const MAX_ALIAS_SETUP_FILE_BYTES: u64 = 16 * 1024 * 1024;
fn ensure_standalone_alias_apply<C: RunContext>(context: &C, label: &str) -> Result<()> {
    if context.input_instructions() || context.output_instructions() {
        return Err(eyre!(
            "{label} cannot be combined with global instruction input/output flags"
        ));
    }
    Ok(())
}
fn read_secret_free_json_file<T>(path: &Path, label: &str) -> Result<T>
where
    T: norito::json::JsonDeserialize,
{
    let metadata = fs::metadata(path)
        .wrap_err_with(|| format!("failed to inspect {label} file `{}`", path.display()))?;
    if !metadata.is_file() {
        return Err(eyre!("{label} path `{}` is not a file", path.display()));
    }
    if metadata.len() > MAX_ALIAS_SETUP_FILE_BYTES {
        return Err(eyre!(
            "{label} file `{}` exceeds the {} byte limit",
            path.display(),
            MAX_ALIAS_SETUP_FILE_BYTES,
        ));
    }
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read {label} file `{}`", path.display()))?;
    let value: norito::json::Value = norito::json::from_slice(&bytes)
        .wrap_err_with(|| format!("failed to parse {label} JSON `{}`", path.display()))?;
    reject_secret_fields(&value, label)?;
    norito::json::from_value(value)
        .wrap_err_with(|| format!("failed to decode typed {label} `{}`", path.display()))
}
fn reject_secret_fields(value: &norito::json::Value, label: &str) -> Result<()> {
    match value {
        norito::json::Value::Array(values) => {
            for value in values {
                reject_secret_fields(value, label)?;
            }
        }
        norito::json::Value::Object(fields) => {
            for (key, value) in fields {
                let normalized: String = key
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect();
                let forbidden = normalized.contains("privatekey")
                    || normalized == "keypair"
                    || normalized == "token"
                    || normalized.starts_with("rawtoken")
                    || normalized == "tokenfile"
                    || normalized.contains("secret")
                    || normalized.contains("paymentproof")
                    || normalized == "signature"
                    || normalized == "authorization";
                if forbidden {
                    return Err(eyre!(
                        "{label} must be secret-free; forbidden field `{key}` was present"
                    ));
                }
                reject_secret_fields(value, label)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn write_secret_free_plan_file<T>(path: &Path, plan: &T) -> Result<()>
where
    T: norito::json::JsonSerialize,
{
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(eyre!(
            "alias setup plan output `{}` must not be a symbolic link",
            path.display()
        ));
    }
    let mut bytes =
        norito::json::to_vec_pretty(plan).wrap_err("failed to encode alias setup plan JSON")?;
    bytes.push(b'\n');
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .wrap_err_with(|| format!("failed to open alias setup plan `{}`", path.display()))?;
    file.write_all(&bytes)
        .wrap_err_with(|| format!("failed to write alias setup plan `{}`", path.display()))?;
    file.sync_all()
        .wrap_err_with(|| format!("failed to sync alias setup plan `{}`", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .wrap_err_with(|| format!("failed to protect alias setup plan `{}`", path.display()))?;
    }
    Ok(())
}
fn render_alias_setup_plan_text(plan: &AliasTransactionPlanV1, output: Option<&Path>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "alias setup plan verified: {}", plan.plan_hash);
    let _ = writeln!(out, "authority: {}", plan.body.authority);
    let _ = writeln!(out, "network_id: {}", plan.body.network_id);
    let _ = writeln!(out, "resources: {}", plan.body.resources.len());
    let _ = writeln!(out, "instructions: {}", plan.body.instructions.len());
    let _ = writeln!(out, "valid_until_ms: {}", plan.body.valid_until_ms);
    if let Some(path) = output {
        let _ = writeln!(out, "plan_file: {}", path.display());
    }
    out
}
fn render_alias_lifecycle_plan_text(
    label: &str,
    plan: &AliasLifecycleTransactionPlanV1,
    output: Option<&Path>,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{label} plan verified: {}", plan.plan_hash);
    let _ = writeln!(out, "authority: {}", plan.body.authority);
    let _ = writeln!(out, "network_id: {}", plan.body.network_id);
    let _ = writeln!(out, "resource: {}", plan.body.operation.target());
    let disposition = match plan.body.disposition {
        iroha::data_model::alias_setup::AliasLifecyclePlanDispositionV1::NoOp => "no_op",
        iroha::data_model::alias_setup::AliasLifecyclePlanDispositionV1::Apply => "apply",
    };
    let _ = writeln!(out, "disposition: {disposition}");
    let _ = writeln!(
        out,
        "instruction: {}",
        if plan.body.instruction.is_some() {
            "1"
        } else {
            "0"
        }
    );
    let _ = writeln!(out, "valid_until_ms: {}", plan.body.valid_until_ms);
    if let Some(path) = output {
        let _ = writeln!(out, "plan_file: {}", path.display());
    }
    out
}
fn read_onboarding_token_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).wrap_err_with(|| {
        format!(
            "failed to inspect onboarding token file `{}`",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(eyre!(
            "onboarding token path `{}` must be a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() > 64 * 1024 {
        return Err(eyre!(
            "onboarding token file `{}` exceeds the 65536 byte limit",
            path.display()
        ));
    }
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read onboarding token file `{}`", path.display()))?;
    let raw = String::from_utf8(bytes).wrap_err("onboarding token file must contain UTF-8")?;
    let token = raw.trim_end_matches(|character| matches!(character, '\r' | '\n'));
    if token.is_empty() {
        return Err(eyre!("onboarding token file must not be empty"));
    }
    if token.trim() != token || token.chars().any(char::is_control) {
        return Err(eyre!(
            "onboarding token file must contain one token without whitespace or control characters"
        ));
    }
    Ok(token.to_owned())
}
fn render_alias_doctor_text(report: &iroha::data_model::alias_setup::AliasSetupReportV1) -> String {
    let mut out = String::new();
    let status = match report.status {
        AliasSetupStatusV1::Ready => "Ready",
        AliasSetupStatusV1::Pending => "Pending",
        AliasSetupStatusV1::Blocked => "Blocked",
    };
    let _ = writeln!(out, "alias onboarding readiness: {status}");
    for diagnostic in &report.diagnostics {
        let resource = diagnostic.resource.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "{:?} {:?} {} resource={} remediation={}",
            diagnostic.severity,
            diagnostic.phase,
            diagnostic.code,
            resource,
            diagnostic.remediation,
        );
    }
    out
}
#[derive(clap::Args, Debug)]
pub struct ResolveArgs {
    /// Alias name to resolve.
    #[arg(long)]
    pub alias: String,
    /// Print only validation result (skip future network call).
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}
impl Run for ResolveArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        alias_resolve_with(
            context,
            &self.alias,
            self.dry_run,
            Client::resolve_account_alias_authenticated,
        )
    }
}
#[derive(clap::Args, Debug)]
pub struct ResolveIndexArgs {
    /// Alias Merkle index to resolve.
    #[arg(long)]
    pub index: u64,
}
impl Run for ResolveIndexArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        alias_resolve_index_with(
            context,
            self.index,
            Client::resolve_account_alias_index_authenticated,
        )
    }
}
#[derive(clap::Args, Debug)]
pub struct ByAccountArgs {
    /// Canonical I105 account id.
    #[arg(long)]
    pub account_id: String,
    /// Optional dataspace alias filter such as `centralbank`.
    #[arg(long)]
    pub dataspace: Option<String>,
    /// Optional exact domain filter such as `banka`.
    #[arg(long)]
    pub domain: Option<String>,
}
impl Run for ByAccountArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        alias_by_account_with(
            context,
            &self.account_id,
            self.dataspace.as_deref(),
            self.domain.as_deref(),
            Client::list_account_aliases_authenticated,
        )
    }
}
fn alias_resolve_with<C, F>(context: &mut C, alias: &str, dry_run: bool, call: F) -> Result<()>
where
    C: RunContext,
    F: FnOnce(&Client, &AccountAliasName) -> Result<Option<AccountAliasResolutionV1>>,
{
    let alias = alias
        .parse::<AccountAliasName>()
        .map_err(|error| eyre!("invalid account alias: {error}"))?;
    let canonical_alias = alias.to_string();
    if dry_run {
        let output = norito::json!({
            "alias": canonical_alias,
            "dry_run": true,
        });
        let text = "alias resolve dry-run completed".to_string();
        return print_with_optional_text(context, Some(text), &output);
    }
    let client = context.client_from_config()?;
    let dto = call(&client, &alias)?.ok_or_else(|| eyre!("alias `{canonical_alias}` not found"))?;
    let text = render_alias_resolve_text(&dto);
    print_with_optional_text(context, Some(text), &dto)
}
fn alias_resolve_index_with<C, F>(context: &mut C, index: u64, call: F) -> Result<()>
where
    C: RunContext,
    F: FnOnce(&Client, AliasIndex) -> Result<Option<AccountAliasIndexResolutionV1>>,
{
    let index = AliasIndex(index);
    let client = context.client_from_config()?;
    let dto =
        call(&client, index)?.ok_or_else(|| eyre!("account alias index {} not found", index.0))?;
    let text = render_alias_resolve_index_text(&dto);
    print_with_optional_text(context, Some(text), &dto)
}
fn alias_by_account_with<C, F>(
    context: &mut C,
    account_id: &str,
    dataspace: Option<&str>,
    domain: Option<&str>,
    call: F,
) -> Result<()>
where
    C: RunContext,
    F: FnOnce(
        &Client,
        &AccountAliasesByAccountRequestV1,
    ) -> Result<Option<AccountAliasesByAccountV1>>,
{
    let parsed = iroha::data_model::account::AccountId::parse_encoded(account_id)
        .map_err(|error| eyre!("invalid account_id: {error}"))?;
    if parsed.to_string() != account_id {
        return Err(eyre!(
            "account_id must use the canonical domainless I105 representation"
        ));
    }
    let account = parsed;
    let request = AccountAliasesByAccountRequestV1::try_new(&account, dataspace, domain)?;
    let client = context.client_from_config()?;
    let dto = call(&client, &request)?
        .ok_or_else(|| eyre!("no visible aliases found for account `{account_id}`"))?;
    let text = render_alias_by_account_text(&dto);
    print_with_optional_text(context, Some(text), &dto)
}
fn render_alias_resolve_text(dto: &AccountAliasResolutionV1) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "alias `{}` resolved to `{}`",
        dto.alias(),
        dto.account_id()
    );
    if let Some(index) = dto.index() {
        let _ = writeln!(out, "index: {}", index.0);
    }
    if let Some(source) = dto.source() {
        let _ = writeln!(out, "source: {source}");
    }
    out
}
fn render_alias_resolve_index_text(dto: &AccountAliasIndexResolutionV1) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "alias index {} resolved to `{}`",
        dto.index().0,
        dto.alias()
    );
    let _ = writeln!(out, "account_id: {}", dto.account_id());
    if let Some(source) = dto.source() {
        let _ = writeln!(out, "source: {source}");
    }
    out
}
fn render_alias_by_account_text(dto: &AccountAliasesByAccountV1) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "account `{}` has {} matching alias(es)",
        dto.account_id(),
        dto.total()
    );
    for item in dto.items() {
        let _ = writeln!(out, "alias: {}", item.alias());
        let _ = writeln!(out, "dataspace: {}", item.dataspace());
        if let Some(domain) = item.domain() {
            let _ = writeln!(out, "domain: {domain}");
        }
        let _ = writeln!(out, "is_primary: {}", item.is_primary());
    }
    if let Some(source) = dto.source() {
        let _ = writeln!(out, "source: {source}");
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::CliOutputFormat;
    use clap::Parser;
    use iroha::{
        config::{self, Config},
        crypto::{Algorithm, KeyPair},
        data_model::prelude::AccountId,
    };
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::metadata::Metadata;
    use norito::json::JsonSerialize;
    use std::fmt::Display;
    use url::Url;
    #[derive(Parser, Debug)]
    struct Wrapper {
        #[command(subcommand)]
        command: Command,
    }
    const SAMPLE_ACCOUNT_ID: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
    fn checked_alias_key_fixture() -> KeyPair {
        KeyPair::try_random().expect("generate checked alias fixture key")
    }
    #[test]
    fn alias_fixture_uses_checked_default_key_generation() {
        let key_pair = checked_alias_key_fixture();
        let actual = key_pair
            .public_key()
            .try_algorithm()
            .expect("alias fixture key advertises a valid algorithm");
        assert_eq!(actual, Algorithm::default());
    }
    #[test]
    fn parse_by_account_args() {
        let wrapper = Wrapper::parse_from([
            "iroha",
            "by-account",
            "--account-id",
            SAMPLE_ACCOUNT_ID,
            "--dataspace",
            "centralbank",
            "--domain",
            "banka",
        ]);
        match wrapper.command {
            Command::ByAccount(args) => {
                assert_eq!(args.account_id, SAMPLE_ACCOUNT_ID);
                assert_eq!(args.dataspace.as_deref(), Some("centralbank"));
                assert_eq!(args.domain.as_deref(), Some("banka"));
            }
            _ => panic!("unexpected command"),
        }
    }
    #[test]
    fn parse_alias_setup_plan_and_apply_files() {
        let wrapper = Wrapper::parse_from([
            "iroha",
            "setup",
            "plan",
            "--intent-file",
            "intent.json",
            "--plan-file",
            "plan.json",
        ]);
        match wrapper.command {
            Command::Setup(SetupCommand::Plan(args)) => {
                assert_eq!(args.intent_file, PathBuf::from("intent.json"));
                assert_eq!(args.plan_file, Some(PathBuf::from("plan.json")));
            }
            _ => panic!("unexpected command"),
        }
        let wrapper = Wrapper::parse_from(["iroha", "setup", "apply", "--plan-file", "plan.json"]);
        match wrapper.command {
            Command::Setup(SetupCommand::Apply(args)) => {
                assert_eq!(args.plan_file, PathBuf::from("plan.json"));
            }
            _ => panic!("unexpected command"),
        }
    }
    #[test]
    fn parse_alias_lifecycle_and_doctor_files() {
        let wrapper = Wrapper::parse_from([
            "iroha",
            "lease",
            "renew",
            "plan",
            "--intent-file",
            "renew.json",
            "--plan-file",
            "renew-plan.json",
        ]);
        match wrapper.command {
            Command::Lease(LeaseCommand::Renew(LeaseRenewCommand::Plan(args))) => {
                assert_eq!(args.intent_file, PathBuf::from("renew.json"));
                assert_eq!(args.plan_file, Some(PathBuf::from("renew-plan.json")));
            }
            _ => panic!("unexpected command"),
        }
        let wrapper = Wrapper::parse_from([
            "iroha",
            "auto-renew",
            "apply",
            "--plan-file",
            "auto-plan.json",
        ]);
        match wrapper.command {
            Command::AutoRenew(AutoRenewCommand::Apply(args)) => {
                assert_eq!(args.plan_file, PathBuf::from("auto-plan.json"));
            }
            _ => panic!("unexpected command"),
        }
        let wrapper = Wrapper::parse_from(["iroha", "doctor", "--token-file", "onboarding.token"]);
        match wrapper.command {
            Command::Doctor(args) => {
                assert_eq!(args.token_file, PathBuf::from("onboarding.token"));
            }
            _ => panic!("unexpected command"),
        }
    }
    #[test]
    fn alias_setup_commands_do_not_accept_inline_keys_or_tokens() {
        assert!(
            Wrapper::try_parse_from([
                "iroha",
                "setup",
                "plan",
                "--intent-file",
                "intent.json",
                "--private-key",
                "secret",
            ])
            .is_err()
        );
        assert!(
            Wrapper::try_parse_from([
                "iroha",
                "setup",
                "apply",
                "--plan-file",
                "plan.json",
                "--token",
                "secret",
            ])
            .is_err()
        );
        assert!(
            Wrapper::try_parse_from([
                "iroha",
                "lease",
                "renew",
                "plan",
                "--intent-file",
                "renew.json",
                "--private-key",
                "secret",
            ])
            .is_err()
        );
        assert!(
            Wrapper::try_parse_from([
                "iroha",
                "auto-renew",
                "apply",
                "--plan-file",
                "auto.json",
                "--token",
                "secret",
            ])
            .is_err()
        );
        assert!(Wrapper::try_parse_from(["iroha", "doctor", "--token", "secret",]).is_err());
    }
    #[test]
    fn doctor_token_file_accepts_one_line_and_rejects_control_characters() {
        let directory = tempfile::tempdir().expect("temporary token directory");
        let token_path = directory.path().join("onboarding.token");
        fs::write(&token_path, "runtime-only-token\n").expect("write token fixture");
        assert_eq!(
            read_onboarding_token_file(&token_path).expect("read one-line token"),
            "runtime-only-token"
        );
        fs::write(&token_path, "two\nlines\n").expect("write invalid token fixture");
        assert!(read_onboarding_token_file(&token_path).is_err());
    }
    #[test]
    fn alias_setup_file_guard_rejects_secret_fields_but_allows_digests() {
        let error = reject_secret_fields(
            &norito::json!({
                "intent": {
                    "private_key": "must-not-cross-the-file-boundary"
                }
            }),
            "alias setup intent",
        )
        .expect_err("private key field must fail");
        assert!(error.to_string().contains("forbidden field `private_key`"));
        reject_secret_fields(
            &norito::json!({
                "token_hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
            "alias setup intent",
        )
        .expect("digests are not secret token values");
    }
    struct TestContext {
        cfg: Config,
        printed: Vec<String>,
        i18n: Localizer,
        output_format: CliOutputFormat,
    }
    impl TestContext {
        fn new(output_format: CliOutputFormat) -> Self {
            let kp = checked_alias_key_fixture();
            let account = AccountId::new(kp.public_key().clone());
            let cfg = Config {
                chain: ChainId::from("test-chain"),
                network_id:
                    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                        .parse()
                        .expect("network id"),
                account,
                account_chain_discriminant:
                    iroha_config::parameters::defaults::common::chain_discriminant(),
                key_pair: kp,
                basic_auth: None,
                api_token: None,
                torii_api_url: Url::parse("http://localhost/").unwrap(),
                torii_request_timeout: config::DEFAULT_TORII_REQUEST_TIMEOUT,
                transaction_ttl: config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
                transaction_status_timeout: config::DEFAULT_TRANSACTION_STATUS_TIMEOUT,
                transaction_add_nonce: config::DEFAULT_TRANSACTION_NONCE,
                sorafs_alias_cache: crate::config_utils::default_alias_cache_policy(),
                sorafs_anonymity_policy: crate::config_utils::default_anonymity_policy(),
                sorafs_rollout_phase: crate::config_utils::default_rollout_phase(),
            };
            Self {
                cfg,
                printed: Vec::new(),
                i18n: Localizer::new(Bundle::Cli, Language::English),
                output_format,
            }
        }
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
        fn output_format(&self) -> crate::CliOutputFormat {
            self.output_format
        }
        fn print_data<T>(&mut self, data: &T) -> Result<()>
        where
            T: JsonSerialize + ?Sized,
        {
            let bytes = norito::json::to_vec(data)?;
            let out = String::from_utf8(bytes).map_err(|err| eyre!(err.to_string()))?;
            self.printed.push(out);
            Ok(())
        }
        fn println(&mut self, data: impl Display) -> Result<()> {
            self.printed.push(data.to_string());
            Ok(())
        }
    }
    fn sample_account_id() -> AccountId {
        AccountId::parse_encoded(SAMPLE_ACCOUNT_ID).expect("canonical sample account")
    }
    #[test]
    fn resolve_helper_prints_result() {
        let mut ctx = TestContext::new(CliOutputFormat::Json);
        alias_resolve_with(&mut ctx, "alice@centralbank", false, |_, _| {
            Ok(Some(AccountAliasResolutionV1::try_new(
                "alice@centralbank"
                    .parse::<AccountAliasName>()
                    .expect("canonical alias"),
                sample_account_id(),
                Some(AliasIndex(7)),
                Some("iso_bridge".to_owned()),
            )?))
        })
        .expect("helper should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains(SAMPLE_ACCOUNT_ID));
    }
    #[test]
    fn resolve_text_includes_source() {
        let dto = AccountAliasResolutionV1::try_new(
            "alice@centralbank"
                .parse::<AccountAliasName>()
                .expect("canonical alias"),
            sample_account_id(),
            None,
            Some("iso_bridge".to_owned()),
        )
        .expect("valid response");
        let text = render_alias_resolve_text(&dto);
        assert!(text.contains("source: iso_bridge"));
    }
    #[test]
    fn resolve_helper_handles_not_found() {
        let mut ctx = TestContext::new(CliOutputFormat::Json);
        let err = alias_resolve_with(&mut ctx, "alice@centralbank", false, |_, _| Ok(None))
            .expect_err("expected error");
        assert!(
            err.to_string()
                .contains("alias `alice@centralbank` not found")
        );
    }
    #[test]
    fn resolve_index_helper_handles_not_implemented() {
        let mut ctx = TestContext::new(CliOutputFormat::Json);
        let err = alias_resolve_index_with(&mut ctx, 0, |_, _| Err(eyre!("not ready")))
            .expect_err("expected error");
        assert!(err.to_string().contains("not ready"));
    }
    #[test]
    fn resolve_index_helper_prints_result() {
        let mut ctx = TestContext::new(CliOutputFormat::Json);
        alias_resolve_index_with(&mut ctx, 0, |_, _| {
            Ok(Some(AccountAliasIndexResolutionV1::try_new(
                AliasIndex(0),
                "merchant@centralbank"
                    .parse::<AccountAliasName>()
                    .expect("canonical alias"),
                sample_account_id(),
                Some("iso_bridge".to_owned()),
            )?))
        })
        .expect("helper should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("merchant@centralbank"));
    }
    #[test]
    fn resolve_index_text_mentions_account() {
        let dto = AccountAliasIndexResolutionV1::try_new(
            AliasIndex(0),
            "merchant@centralbank"
                .parse::<AccountAliasName>()
                .expect("canonical alias"),
            sample_account_id(),
            None,
        )
        .expect("valid index resolution");
        let text = render_alias_resolve_index_text(&dto);
        assert!(text.contains(&format!("account_id: {SAMPLE_ACCOUNT_ID}")));
    }
    #[test]
    fn alias_by_account_helper_prints_result() {
        let mut ctx = TestContext::new(CliOutputFormat::Json);
        alias_by_account_with(
            &mut ctx,
            SAMPLE_ACCOUNT_ID,
            Some("centralbank"),
            Some("banka"),
            |_, _| {
                Ok(Some(AccountAliasesByAccountV1::try_new(
                    sample_account_id(),
                    vec![AccountAliasListItemV1::try_new(
                        "merchant@banka.centralbank"
                            .parse::<AccountAliasName>()
                            .expect("canonical alias"),
                        true,
                    )?],
                    Some("on_chain".to_owned()),
                )?))
            },
        )
        .expect("helper should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("merchant@banka.centralbank"));
    }
    #[test]
    fn alias_by_account_text_mentions_total() {
        let dto = AccountAliasesByAccountV1::try_new(
            sample_account_id(),
            vec![
                AccountAliasListItemV1::try_new(
                    "merchant@banka.centralbank"
                        .parse::<AccountAliasName>()
                        .expect("canonical alias"),
                    true,
                )
                .expect("valid row"),
            ],
            Some("on_chain".to_owned()),
        )
        .expect("valid response");
        let text = render_alias_by_account_text(&dto);
        assert!(text.contains("has 1 matching alias(es)"));
        assert!(text.contains("merchant@banka.centralbank"));
    }
}
