//! Contracts helpers.
mod local_debug_attempt;
mod local_debug_rendering;
mod manifest_signing;
use crate::{
    Run, RunContext, TransactionWaitArgs, apply_cli_gas_limit_override,
    wait_for_transaction_applied,
};
use base64::Engine as _;
use eyre::{Result, WrapErr as _, eyre};
use iroha::{
    account_address::parse_account_address,
    blocking::Client as BlockingClient,
    client::{Client, ContractCallDraftIntent},
    data_model::{
        isi::contract_alias::SetContractAlias,
        prelude::*,
        transaction::{IvmBytecode, TransactionBuilder},
    },
};
use iroha_core::{
    pipeline::overlay::build_overlay_for_transaction_with_accounts,
    smartcontracts::ivm::{cache::ProgramSummary, host::CoreHost},
};
use iroha_crypto::{KeyPair, PrivateKey};
use iroha_data_model::executor::fault::{IvmFaultPositionV1, IvmFaultV1};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::state_path::StatePath;
use ivm::host::IVMHost;
use local_debug_rendering::{
    build_local_debug_entrypoint, render_durable_state_overlay, render_queued_instructions,
};
use reqwest::StatusCode;
use std::{
    collections::BTreeMap,
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
// Canonical argument preparation checks a conservative predecode gas quote
// covering bounded complete materialization. Keep the default above the strict
// admission floor; representative bounded schemas fit this default.
const DEFAULT_CONTRACT_GAS_LIMIT: u64 = 1_500_000;
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Contract code helpers
    #[command(subcommand)]
    Code(CodeCommand),
    /// Contract alias helpers
    #[command(subcommand)]
    Alias(AliasCommand),
    /// Derive a canonical contract address locally from exact network identity, authority, nonce,
    /// and dataspace
    DeriveAddress(DeriveAddressArgs),
    /// Submit a contract call through Torii (POST /v1/contracts/call)
    Call(CallArgs),
    /// Execute a read-only contract view through Torii (POST /v1/contracts/view)
    View(ViewArgs),
    /// Execute a read-only contract view locally against compiled bytecode and optional fixtures
    DebugView(DebugViewArgs),
    /// Execute a public contract entrypoint locally against compiled bytecode and optional fixtures
    DebugCall(DebugCallArgs),
    /// Contract manifest helpers
    #[command(subcommand)]
    Manifest(ManifestCommand),
    /// Run an offline simulation of IVM bytecode to see the queued ISIs and header metadata
    Simulate(SimulateArgs),
    /// List committed contract activity with shared filter, projection and cursor controls.
    Activity(crate::collection_list::ListArgs),
    /// List committed contract events with shared filter, projection and cursor controls.
    Events(crate::collection_list::ListArgs),
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Code(cmd) => cmd.run(context),
            Command::Alias(cmd) => cmd.run(context),
            Command::DeriveAddress(args) => args.run(context),
            Command::Call(args) => args.run(context),
            Command::View(args) => args.run(context),
            Command::DebugView(args) => args.run(context),
            Command::DebugCall(args) => args.run(context),
            Command::Manifest(cmd) => cmd.run(context),
            Command::Simulate(args) => args.run(context),
            Command::Activity(args) => crate::collection_list::run_list(
                context,
                iroha::collections::Collection::ContractActivity,
                &args,
            ),
            Command::Events(args) => crate::collection_list::run_list(
                context,
                iroha::collections::Collection::ContractEvents,
                &args,
            ),
        }
    }
}
impl Command {
    /// Return whether this contract command is entirely local and may use the
    /// deterministic offline fallback configuration.
    pub(crate) fn allows_fallback_config(&self) -> bool {
        matches!(
            self,
            Self::DeriveAddress(_)
                | Self::DebugView(_)
                | Self::DebugCall(_)
                | Self::Manifest(ManifestCommand::Build(_))
                | Self::Simulate(_)
        )
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum CodeCommand {
    /// Fetch on-chain contract code bytes by code hash and write to a file
    Get(CodeBytesGetArgs),
}
#[derive(clap::Subcommand, Debug)]
pub enum AliasCommand {
    /// Lease or renew an on-chain contract alias for a contract address
    Lease(ContractAliasLeaseArgs),
    /// Release the current on-chain alias binding for a contract address
    Release(ContractAliasReleaseArgs),
    /// Resolve an on-chain contract alias to its current canonical contract address
    Resolve(ContractAliasResolveArgs),
}
impl Run for AliasCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            AliasCommand::Lease(args) => args.run(context),
            AliasCommand::Release(args) => args.run(context),
            AliasCommand::Resolve(args) => args.run(context),
        }
    }
}
impl Run for CodeCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            CodeCommand::Get(args) => args.run(context),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ManifestCommand {
    /// Fetch on-chain contract manifest by code hash and either print or save (if --out is provided)
    Get(ManifestArgs),
    /// Inspect the manifest embedded in compiled bytecode (with optional signing)
    Build(BuildManifestArgs),
}
impl Run for ManifestCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            ManifestCommand::Get(args) => args.run(context),
            ManifestCommand::Build(args) => args.run(context),
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct CodeBytesGetArgs {
    /// Exact artifact dataspace identifier (zero selects the universal dataspace).
    #[arg(long)]
    pub dataspace_id: u64,
    /// Hex-encoded 32-byte code hash (0x optional)
    #[arg(long, value_name = "HEX64")]
    pub code_hash: String,
    /// Output path to write the `.to` bytes
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
}
impl Run for CodeBytesGetArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = BlockingClient::from_client(context.client_from_config()?)?;
        let artifact_id = contract_artifact_id(self.dataspace_id, &self.code_hash)?;
        let bytes = client.client().get_contract_code_bytes(&artifact_id)?;
        std::fs::write(&self.out, &bytes)?;
        context.println(format_args!(
            "Wrote {} bytes to {}",
            bytes.len(),
            self.out.display()
        ))?;
        Ok(())
    }
}
pub(crate) fn contract_artifact_id(
    dataspace_id: u64,
    code_hash: &str,
) -> Result<iroha_data_model::smart_contract::ContractArtifactId> {
    let mut bytes = [0; iroha_crypto::Hash::LENGTH];
    hex::decode_to_slice(
        code_hash.strip_prefix("0x").unwrap_or(code_hash),
        &mut bytes,
    )
    .wrap_err("contract code hash must contain exactly 32 hexadecimal bytes")?;
    let hash = iroha_crypto::Hash::prehashed(bytes);
    if hash.as_ref() != &bytes {
        return Err(eyre!("contract code hash is not canonical"));
    }
    Ok(iroha_data_model::smart_contract::ContractArtifactId::new(
        iroha_model_base::topology::DataSpaceId::new(dataspace_id),
        hash,
    ))
}
#[derive(clap::Args, Debug)]
pub struct ContractAliasLeaseArgs {
    /// Canonical contract address to bind.
    #[arg(long)]
    pub contract_address: String,
    /// Alias literal in `name::domain.dataspace` or `name::dataspace` format.
    #[arg(long)]
    pub contract_alias: String,
    /// Optional lease expiry timestamp in unix milliseconds. Omit for a permanent binding.
    #[arg(long)]
    pub lease_expiry_ms: Option<u64>,
}
impl Run for ContractAliasLeaseArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let contract_address = self
            .contract_address
            .parse()
            .wrap_err("invalid --contract-address")?;
        let contract_alias = self
            .contract_alias
            .parse()
            .wrap_err("invalid --contract-alias")?;
        context.submit(vec![InstructionBox::from(SetContractAlias::bind(
            contract_address,
            contract_alias,
            self.lease_expiry_ms,
        ))])
    }
}
#[derive(clap::Args, Debug)]
pub struct ContractAliasReleaseArgs {
    /// Canonical contract address whose alias binding should be cleared.
    #[arg(long)]
    pub contract_address: String,
}
impl Run for ContractAliasReleaseArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let contract_address = self
            .contract_address
            .parse()
            .wrap_err("invalid --contract-address")?;
        context.submit(vec![InstructionBox::from(SetContractAlias::clear(
            contract_address,
        ))])
    }
}
#[derive(clap::Args, Debug)]
pub struct ContractAliasResolveArgs {
    /// Alias literal in `name::domain.dataspace` or `name::dataspace` format.
    pub contract_alias: String,
}
impl Run for ContractAliasResolveArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let contract_alias: iroha::data_model::smart_contract::ContractAlias = self
            .contract_alias
            .parse()
            .wrap_err("invalid contract alias")?;
        let client: Client = context.client_from_config()?;
        let response = client
            .post_contract_alias_resolve(&contract_alias)
            .wrap_err("failed to call `/v1/contracts/aliases/resolve`")?;
        let status = response.status();
        let body = response.into_body();
        match status {
            StatusCode::OK => {
                let value: norito::json::Value =
                    norito::json::from_slice(&body).wrap_err("decode contract alias response")?;
                context.print_data(&value)
            }
            StatusCode::NOT_FOUND => Err(eyre!("contract alias `{contract_alias}` not found")),
            status => Err(eyre!(
                "contract alias resolve request failed with HTTP {}: {}",
                status,
                std::str::from_utf8(&body).unwrap_or("")
            )),
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct DeriveAddressArgs {
    /// Authority account identifier (canonical I105 account literal)
    #[arg(long)]
    pub authority: String,
    /// Target dataspace alias or numeric dataspace id (defaults to `universal`)
    #[arg(long, default_value = "universal")]
    pub dataspace: String,
    /// Successful deploy nonce consumed for address derivation
    #[arg(long)]
    pub deploy_nonce: u64,
    /// Exact genesis-derived network identity committed into the contract address
    #[arg(long)]
    pub network_id: NetworkId,
    /// Public network profile used to decode the authority account literal
    #[arg(long)]
    pub profile: Option<String>,
    /// Explicit chain discriminant used to decode the authority account literal
    #[arg(long)]
    pub chain_discriminant: Option<u16>,
    /// Optional numeric dataspace id override for non-default dataspaces
    #[arg(long)]
    pub dataspace_id: Option<u64>,
}
impl Run for DeriveAddressArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let (profile_name, chain_discriminant) =
            resolve_network_context(self.profile.as_deref(), self.chain_discriminant)?;
        let authority = parse_account_address(&self.authority, Some(chain_discriminant))
            .map_err(|err| eyre!(err.to_string()))
            .wrap_err("failed to resolve --authority")?
            .to_account_id()
            .map_err(|err| eyre!(err.to_string()))
            .wrap_err("failed to decode --authority")?;
        let dataspace_id = resolve_contract_dataspace_id_hint(&self.dataspace, self.dataspace_id)?;
        let contract_address = iroha::data_model::smart_contract::ContractAddress::derive(
            &self.network_id,
            &authority,
            self.deploy_nonce,
            dataspace_id,
        )
        .map_err(|err| eyre!(err.to_string()))
        .wrap_err("failed to derive contract address")?;
        context.print_data(&norito::json!({
            "authority": (authority),
            "dataspace": (self.dataspace),
            "dataspace_id": (dataspace_id.as_u64()),
            "deploy_nonce": (self.deploy_nonce),
            "network_id": (self.network_id),
            "profile": (profile_name),
            "chain_discriminant": (chain_discriminant),
            "contract_address": (contract_address),
        }))?;
        Ok(())
    }
}
fn resolve_network_context(
    profile: Option<&str>,
    chain_discriminant: Option<u16>,
) -> Result<(Option<String>, u16)> {
    match (
        profile.map(str::trim).filter(|value| !value.is_empty()),
        chain_discriminant,
    ) {
        (Some(profile_name), Some(actual)) => {
            let expected = iroha_torii_shared::network_profile(profile_name).ok_or_else(|| {
                eyre!(
                    "unknown network profile `{profile_name}` (supported: {})",
                    iroha_torii_shared::network_profile_names()
                )
            })?;
            if expected.chain_discriminant != actual {
                eyre::bail!(
                    "network profile mismatch: profile `{}` expects chain_discriminant={}, actual chain_discriminant={}",
                    expected.name,
                    expected.chain_discriminant,
                    actual
                );
            }
            Ok((Some(expected.name.to_owned()), actual))
        }
        (Some(profile_name), None) => {
            let expected = iroha_torii_shared::network_profile(profile_name).ok_or_else(|| {
                eyre!(
                    "unknown network profile `{profile_name}` (supported: {})",
                    iroha_torii_shared::network_profile_names()
                )
            })?;
            Ok((Some(expected.name.to_owned()), expected.chain_discriminant))
        }
        (None, Some(chain_discriminant)) => Ok((None, chain_discriminant)),
        (None, None) => eyre::bail!("provide --profile or --chain-discriminant"),
    }
}
#[derive(clap::Args, Debug, Clone)]
pub struct ContractTargetArgs {
    /// Canonical contract address.
    #[arg(long, conflicts_with = "contract_alias")]
    pub contract_address: Option<String>,
    /// On-chain contract alias (`name::domain.dataspace` or `name::dataspace`).
    #[arg(long, conflicts_with = "contract_address")]
    pub contract_alias: Option<String>,
}
#[derive(clap::Args, Debug, Clone)]
pub struct ContractPayloadArgs {
    /// Inline Norito JSON entrypoint arguments.
    #[arg(long, value_name = "JSON", conflicts_with = "args_file")]
    pub args: Option<String>,
    /// File containing Norito JSON entrypoint arguments.
    #[arg(long, value_name = "PATH", conflicts_with = "args")]
    pub args_file: Option<PathBuf>,
}
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct ContractSubmissionWaitResponse {
    submit: norito::json::Value,
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    trace: Option<norito::json::Value>,
    terminal_kind: String,
    attempts: u64,
    elapsed_ms: u64,
    block_height: Option<u64>,
    scope: String,
    resolved_from: String,
    r#final: iroha_torii_shared::PipelineTransactionStatusResponse,
}
fn contract_submit_only_response(
    submit: norito::json::Value,
    trace: Option<norito::json::Value>,
) -> norito::json::Value {
    if let Some(trace) = trace {
        norito::json!({
            "submit": submit,
            "trace": trace,
            "finalized": false,
        })
    } else {
        norito::json!({
            "submit": submit,
            "finalized": false,
        })
    }
}
fn extract_submitted_transaction_hash(
    value: &norito::json::Value,
) -> Result<HashOf<iroha::data_model::transaction::SignedTransaction>> {
    let tx_hash_hex = value
        .as_object()
        .and_then(|map| map.get("tx_hash_hex"))
        .and_then(norito::json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| eyre!("response missing `tx_hash_hex`"))?;
    tx_hash_hex
        .parse::<HashOf<iroha::data_model::transaction::SignedTransaction>>()
        .map_err(|err| eyre!("invalid `tx_hash_hex`: {err}"))
}
#[derive(clap::Args, Debug)]
pub struct CallArgs {
    /// Authority account identifier. Defaults to the configured client authority.
    #[arg(long)]
    pub authority: Option<String>,
    /// Hex-encoded private key override used to sign and submit the call directly.
    #[arg(long, value_name = "HEX", conflicts_with = "draft_only")]
    pub private_key: Option<String>,
    /// Request the exact unsigned transaction payload instead of direct submission.
    #[arg(long, conflicts_with = "simulate")]
    pub draft_only: bool,
    /// Secret-free JSON file containing the exact invocation and final metadata authorized for
    /// the unsigned draft.
    #[arg(long, value_name = "PATH", conflicts_with = "simulate")]
    pub draft_intent_file: Option<PathBuf>,
    /// Simulate the contract call locally on Torii without submitting a transaction.
    #[arg(long, conflicts_with_all = ["draft_only", "private_key", "wait"])]
    pub simulate: bool,
    /// Run Torii simulation first and include the server-side execution trace in the submit response.
    #[arg(long, conflicts_with = "simulate")]
    pub trace: bool,
    /// Contract entrypoint selector.
    #[arg(long)]
    pub entrypoint: String,
    /// Signature-bound gas limit forwarded to the contract call.
    #[arg(long, default_value_t = DEFAULT_CONTRACT_GAS_LIMIT)]
    pub gas_limit: u64,
    #[command(flatten)]
    pub target: ContractTargetArgs,
    #[command(flatten)]
    pub payload: ContractPayloadArgs,
    #[command(flatten)]
    pub wait: TransactionWaitArgs,
}
impl Run for CallArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = BlockingClient::from_client(context.client_from_config()?)?;
        let authority = resolve_contract_authority(context, self.authority.as_deref())?;
        let private_key = if self.simulate {
            None
        } else {
            resolve_contract_call_private_key(
                context,
                &authority,
                self.private_key.as_deref(),
                self.draft_only,
            )?
        };
        let target = resolve_contract_target(self.target)?;
        let payload = load_contract_payload_value(
            self.payload.args.as_deref(),
            self.payload.args_file.as_deref(),
        )?;
        if self.simulate {
            let value = client.client().post_contract_call_simulate_json(
                &authority,
                target.contract_address.as_ref(),
                target.contract_alias.as_ref(),
                &self.entrypoint,
                payload.as_ref(),
                self.gas_limit,
            )?;
            context.print_data(&value)?;
            return Ok(());
        }
        let trace = if self.trace {
            Some(client.client().post_contract_call_simulate_json(
                &authority,
                target.contract_address.as_ref(),
                target.contract_alias.as_ref(),
                &self.entrypoint,
                payload.as_ref(),
                self.gas_limit,
            )?)
        } else {
            None
        };
        let fee_payment =
            apply_cli_gas_limit_override(context.transaction_fee_payment()?, Some(self.gas_limit))?;
        let draft_intent = self
            .draft_intent_file
            .as_deref()
            .ok_or_else(|| {
                eyre!("contract calls that produce an unsigned payload require --draft-intent-file")
            })
            .and_then(load_contract_call_draft_intent)?;
        let value = client.post_contract_call_json(
            &authority,
            private_key.as_ref(),
            target.contract_address.as_ref(),
            target.contract_alias.as_ref(),
            &self.entrypoint,
            payload.as_ref(),
            None,
            None,
            None,
            &fee_payment,
            &draft_intent,
        )?;
        if self.wait.is_enabled() {
            let tx_hash = extract_submitted_transaction_hash(&value)
                .wrap_err("contract call response missing canonical `tx_hash_hex`")?;
            let status = wait_for_transaction_applied(client.client(), tx_hash, &self.wait)?;
            context.print_data(&ContractSubmissionWaitResponse {
                submit: value,
                trace,
                terminal_kind: status.terminal_kind,
                attempts: status.attempts,
                elapsed_ms: status.elapsed_ms,
                block_height: status.block_height,
                scope: status.scope,
                resolved_from: status.resolved_from,
                r#final: status.r#final,
            })?;
        } else {
            context.print_data(&contract_submit_only_response(value, trace))?;
        }
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct ViewArgs {
    /// Authority account identifier used as the read context. Defaults to the configured client authority.
    #[arg(long)]
    pub authority: Option<String>,
    /// Contract view entrypoint selector.
    #[arg(long)]
    pub entrypoint: String,
    /// Gas limit applied to the local view execution.
    #[arg(long, default_value_t = DEFAULT_CONTRACT_GAS_LIMIT)]
    pub gas_limit: u64,
    #[command(flatten)]
    pub target: ContractTargetArgs,
    #[command(flatten)]
    pub payload: ContractPayloadArgs,
}
impl Run for ViewArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let authority = resolve_contract_authority(context, self.authority.as_deref())?;
        let target = resolve_contract_target(self.target)?;
        let payload = load_contract_payload_value(
            self.payload.args.as_deref(),
            self.payload.args_file.as_deref(),
        )?;
        let value = client.post_contract_view_json(
            &authority,
            target.contract_address.as_ref(),
            target.contract_alias.as_ref(),
            &self.entrypoint,
            payload.as_ref(),
            self.gas_limit,
        )?;
        context.print_data(&value)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct DebugViewArgs {
    /// Authority account identifier used as the local read context. Defaults to the configured client authority.
    #[arg(long)]
    pub authority: Option<String>,
    /// Path to compiled `.to` file (mutually exclusive with --code-b64)
    #[arg(long, conflicts_with = "code_b64")]
    pub code_file: Option<PathBuf>,
    /// Base64-encoded code (mutually exclusive with --code-file)
    #[arg(long, conflicts_with = "code_file")]
    pub code_b64: Option<String>,
    /// Contract view entrypoint selector.
    #[arg(long)]
    pub entrypoint: String,
    /// Gas limit applied to the local view execution.
    #[arg(long, default_value_t = DEFAULT_CONTRACT_GAS_LIMIT)]
    pub gas_limit: u64,
    /// Optional source file used to render snippet context for trapped debug locations.
    #[arg(long, value_name = "PATH", requires = "source_map_file")]
    pub source_file: Option<PathBuf>,
    /// Hash-bound Kotodama source-map sidecar used to resolve trapped debug locations.
    /// Relative source paths in the sidecar are read from the current working directory.
    #[arg(long, value_name = "PATH")]
    pub source_map_file: Option<PathBuf>,
    /// Optional JSON array of canonical account ids available to iterator helpers.
    #[arg(long, value_name = "JSON", conflicts_with = "accounts_file")]
    pub accounts_json: Option<String>,
    /// File containing a JSON array of canonical account ids available to iterator helpers.
    #[arg(long, value_name = "PATH", conflicts_with = "accounts_json")]
    pub accounts_file: Option<PathBuf>,
    /// Optional JSON object mapping durable state keys to encoded values (`0x...` hex or base64).
    #[arg(long, value_name = "JSON", conflicts_with = "durable_state_file")]
    pub durable_state_json: Option<String>,
    /// File containing a JSON object mapping durable state keys to encoded values (`0x...` hex or base64).
    #[arg(long, value_name = "PATH", conflicts_with = "durable_state_json")]
    pub durable_state_file: Option<PathBuf>,
    #[command(flatten)]
    pub payload: ContractPayloadArgs,
}
impl Run for DebugViewArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let authority = resolve_contract_authority(context, self.authority.as_deref())?;
        let report = execute_local_contract_debug_view(context, self, authority)?;
        context.print_data(&report)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct DebugCallArgs {
    /// Authority account identifier used as the local call context. Defaults to the configured client authority.
    #[arg(long)]
    pub authority: Option<String>,
    /// Path to compiled `.to` file (mutually exclusive with --code-b64)
    #[arg(long, conflicts_with = "code_b64")]
    pub code_file: Option<PathBuf>,
    /// Base64-encoded code (mutually exclusive with --code-file)
    #[arg(long, conflicts_with = "code_file")]
    pub code_b64: Option<String>,
    /// Local kotoage, hajimari, or kaizen entrypoint selector.
    #[arg(long)]
    pub entrypoint: String,
    /// Gas limit applied to the local call execution.
    #[arg(long, default_value_t = DEFAULT_CONTRACT_GAS_LIMIT)]
    pub gas_limit: u64,
    /// Optional source file used to render snippet context for trapped debug locations.
    #[arg(long, value_name = "PATH", requires = "source_map_file")]
    pub source_file: Option<PathBuf>,
    /// Hash-bound Kotodama source-map sidecar used to resolve trapped debug locations.
    /// Relative source paths in the sidecar are read from the current working directory.
    #[arg(long, value_name = "PATH")]
    pub source_map_file: Option<PathBuf>,
    /// Optional JSON array of canonical account ids available to iterator helpers.
    #[arg(long, value_name = "JSON", conflicts_with = "accounts_file")]
    pub accounts_json: Option<String>,
    /// File containing a JSON array of canonical account ids available to iterator helpers.
    #[arg(long, value_name = "PATH", conflicts_with = "accounts_json")]
    pub accounts_file: Option<PathBuf>,
    /// Optional JSON object mapping durable state keys to encoded values (`0x...` hex or base64).
    #[arg(long, value_name = "JSON", conflicts_with = "durable_state_file")]
    pub durable_state_json: Option<String>,
    /// File containing a JSON object mapping durable state keys to encoded values (`0x...` hex or base64).
    #[arg(long, value_name = "PATH", conflicts_with = "durable_state_json")]
    pub durable_state_file: Option<PathBuf>,
    #[command(flatten)]
    pub payload: ContractPayloadArgs,
}
impl Run for DebugCallArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let authority = resolve_contract_authority(context, self.authority.as_deref())?;
        let report = execute_local_contract_debug_call(context, self, authority)?;
        context.print_data(&report)?;
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct BuildManifestArgs {
    /// Path to compiled `.to` file (mutually exclusive with --code-b64)
    #[arg(long, conflicts_with = "code_b64")]
    pub code_file: Option<PathBuf>,
    /// Base64-encoded code (mutually exclusive with --code-file)
    #[arg(long, conflicts_with = "code_file")]
    pub code_b64: Option<String>,
    /// Hex-encoded private key for signing the manifest (optional)
    #[arg(long, value_name = "HEX")]
    pub sign_with: Option<String>,
    /// Optional output path; if omitted, prints to stdout
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}
impl Run for BuildManifestArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let code = load_code_bytes(self.code_file.clone(), self.code_b64.clone())?;
        let verified = verify_contract_from_bytes(&code)?;
        let mut signing_owner = self
            .sign_with
            .as_ref()
            .map(|_| manifest_signing::ManifestSigningBudget::new())
            .transpose()?;
        // This guard precedes the manifest and survives JSON/file consumption.
        let mut signer_backing = None;
        let mut manifest = verified.manifest;
        if let Some(hex_key) = self.sign_with {
            let private: PrivateKey = hex_key.parse().wrap_err("invalid --sign-with")?;
            let kp =
                KeyPair::from_private_key(private).wrap_err("derive signing keypair failed")?;
            let owner = signing_owner
                .as_mut()
                .ok_or_else(|| eyre!("manifest signing owner is absent"))?;
            signer_backing = Some(owner.reserve_signer(kp.public_key())?);
            let frame = owner.reserve_frame(&manifest)?;
            manifest = manifest
                .try_signed(owner.context(), frame.remaining_bytes(), &kp)
                .wrap_err("sign contract manifest failed")?;
            drop(frame);
        }
        let rendered = norito::json::to_json_pretty(&manifest)?;
        if let Some(path) = self.out {
            write_manifest_output(&path, rendered.as_bytes())
                .wrap_err_with(|| format!("write manifest to {}", path.display()))?;
            context.println(format_args!("Wrote manifest to {}", path.display()))?;
        } else {
            context.println(rendered)?;
        }
        drop(manifest);
        drop(signer_backing);
        drop(signing_owner);
        Ok(())
    }
}
/// Keep the original frame, signer and counter backing through the manifest's consumption.
/// The artifact already owns the source graph; the callback must consume the signed manifest
/// before this finite signing grant is released.
#[cfg(test)]
fn with_signed_contract_manifest(
    manifest: iroha_data_model::smart_contract::manifest::ContractManifest,
    key_pair: &KeyPair,
    max_frame_bytes: usize,
    consume: impl FnOnce(
        iroha_data_model::smart_contract::manifest::ContractManifest,
        &norito::core::DecodeBudgetContext,
    ) -> Result<()>,
) -> Result<()> {
    use norito::core::DecodeBudgetContext;

    if max_frame_bytes == 0 {
        return Err(eyre!("manifest frame ceiling must be nonzero"));
    }
    let signer_bytes = key_pair.public_key().retained_allocation_layout().size();
    // Admit one signing frame and one verification frame under the same cumulative context.
    let cumulative_bytes = max_frame_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(signer_bytes))
        .ok_or_else(|| eyre!("manifest signing allowance overflow"))?;
    let pool_bytes = cumulative_bytes
        .checked_add(DecodeBudgetContext::allocation_layout().size())
        .ok_or_else(|| eyre!("manifest signing physical allowance overflow"))?;
    let pool = iroha_core::state::AllocationBudget::new(pool_bytes);
    let mut grant = pool.try_reserve_bytes(pool_bytes)?;
    let context = DecodeBudgetContext::from_reservation(
        norito::DecodeLimits::new(
            max_frame_bytes,
            max_frame_bytes,
            max_frame_bytes,
            cumulative_bytes,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ),
        &mut grant,
    )?;
    let _signer_backing = grant.try_partition_bytes(signer_bytes)?;
    let encoded_bytes = context.with(|| {
        let _canonical =
            norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
        norito::core::encoded_frame_len_bounded(&manifest.signature_payload(), max_frame_bytes)
    })?;
    let signing_frame = grant.try_partition_bytes(encoded_bytes)?;
    let signed = manifest
        .try_signed(&context, signing_frame.remaining_bytes(), key_pair)
        .wrap_err("sign contract manifest failed")?;
    // try_signed has freed its temporary frame; the signer remains funded through consumption.
    drop(signing_frame);
    consume(signed, &context)
}
fn write_manifest_output(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "manifest output requires a file name",
        )
    })?;
    iroha_fs::OwnerDirectory::open(parent)?.write_atomic(
        name,
        bytes,
        iroha_fs::PublishMode::Replace,
    )
}
fn load_code_bytes(code_file: Option<PathBuf>, code_b64: Option<String>) -> Result<Vec<u8>> {
    if let Some(path) = code_file {
        let bytes = std::fs::read(&path).wrap_err_with(|| format!("read {}", path.display()))?;
        Ok(bytes)
    } else if let Some(s) = code_b64 {
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .wrap_err("decode base64 code payload")
    } else {
        Err(eyre!("either --code-file or --code-b64 must be provided"))
    }
}
fn resolve_contract_dataspace_id_hint(
    dataspace: &str,
    dataspace_id: Option<u64>,
) -> Result<iroha_model_base::topology::DataSpaceId> {
    if let Some(dataspace_id) = dataspace_id {
        return Ok(iroha_model_base::topology::DataSpaceId::new(dataspace_id));
    }
    let trimmed = dataspace.trim();
    if trimmed.is_empty() {
        return Err(eyre!("--dataspace must not be empty"));
    }
    if let Ok(raw) = trimmed.parse::<u64>() {
        return Ok(iroha_model_base::topology::DataSpaceId::new(raw));
    }
    let raw = match trimmed {
        "universal" => 0,
        "governance" => 1,
        "zk" => 2,
        _ => {
            return Err(eyre!(
                "unknown dataspace alias `{trimmed}`; pass --dataspace-id for non-default dataspaces"
            ));
        }
    };
    Ok(iroha_model_base::topology::DataSpaceId::new(raw))
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedContractTarget {
    contract_address: Option<iroha::data_model::smart_contract::ContractAddress>,
    contract_alias: Option<iroha::data_model::smart_contract::ContractAlias>,
}
fn resolve_contract_target(args: ContractTargetArgs) -> Result<ResolvedContractTarget> {
    match (
        args.contract_address.as_deref(),
        args.contract_alias.as_deref(),
    ) {
        (Some(address), None) => Ok(ResolvedContractTarget {
            contract_address: Some(
                address
                    .parse()
                    .wrap_err("invalid --contract-address canonical literal")?,
            ),
            contract_alias: None,
        }),
        (None, Some(alias)) => Ok(ResolvedContractTarget {
            contract_address: None,
            contract_alias: Some(alias.parse().wrap_err("invalid --contract-alias")?),
        }),
        (None, None) => Err(eyre!(
            "provide exactly one contract target via --contract-address or --contract-alias"
        )),
        _ => Err(eyre!(
            "provide exactly one contract target via --contract-address or --contract-alias"
        )),
    }
}
fn load_contract_call_draft_intent(path: &Path) -> Result<ContractCallDraftIntent> {
    let bytes = fs::read(path).wrap_err_with(|| format!("read {}", path.display()))?;
    norito::json::from_slice(&bytes)
        .wrap_err_with(|| format!("invalid contract-call draft intent in {}", path.display()))
}
fn load_contract_payload_value(
    args: Option<&str>,
    args_file: Option<&std::path::Path>,
) -> Result<Option<norito::json::Value>> {
    match (args, args_file) {
        (Some(raw), None) => norito::json::from_str(raw)
            .map(Some)
            .wrap_err("invalid --args"),
        (None, Some(path)) => {
            let contents = std::fs::read_to_string(path)
                .wrap_err_with(|| format!("read {}", path.display()))?;
            norito::json::from_str(&contents)
                .map(Some)
                .wrap_err_with(|| format!("invalid JSON in {}", path.display()))
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(eyre!("--args and --args-file are mutually exclusive")),
    }
}
fn resolve_contract_authority<C: RunContext>(
    context: &mut C,
    authority: Option<&str>,
) -> Result<AccountId> {
    match authority {
        Some(authority) => {
            crate::resolve_account_id(context, authority).wrap_err("failed to resolve --authority")
        }
        None => Ok(context.config().account.clone()),
    }
}
fn resolve_contract_call_private_key<C: RunContext>(
    context: &C,
    authority: &AccountId,
    private_key_hex: Option<&str>,
    draft_only: bool,
) -> Result<Option<PrivateKey>> {
    if draft_only {
        return Ok(None);
    }
    if let Some(private_key_hex) = private_key_hex {
        return private_key_hex
            .parse()
            .map(Some)
            .wrap_err("invalid --private-key");
    }
    if authority == &context.config().account {
        return Ok(Some(context.config().key_pair.private_key().clone()));
    }
    Err(eyre!(
        "--private-key is required when --authority does not match client.toml authority"
    ))
}
fn verify_contract_from_bytes(bytes: &[u8]) -> Result<ivm::VerifiedContractArtifact> {
    ivm::verify_contract_artifact(bytes).map_err(|err| eyre!(err.to_string()))
}
fn program_summary_from_bytes(bytes: &[u8]) -> Result<ProgramSummary> {
    let summary = ProgramSummary::from_artifact(bytes)
        .map_err(|err| eyre!("failed to prepare IVM program summary: {err}"))?;
    match summary.metadata.abi_version {
        1 => {}
        v => {
            return Err(eyre!(
                "unsupported abi_version {v}; expected 1 for the first release"
            ));
        }
    }
    Ok(summary)
}
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct LocalContractDebugViewResponse {
    ok: bool,
    code_hash_hex: String,
    abi_hash_hex: String,
    entrypoint: LocalContractDebugEntrypoint,
    budget: LocalContractDebugBudget,
    syscall_trace: Vec<LocalContractSyscallTrace>,
    result: Option<norito::json::Value>,
    error: Option<String>,
    fault: Option<IvmFaultV1>,
    vm_diagnostic: Option<LocalContractDebugVmDiagnostic>,
    source_snippet: Option<LocalContractSourceSnippet>,
    queued_instruction_count: usize,
    durable_state_mutation_count: usize,
}
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct LocalContractDebugEntrypoint {
    name: String,
    kind: String,
    pc: u64,
    return_type: Option<String>,
    params: Vec<LocalContractDebugParam>,
}
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct LocalContractDebugParam {
    name: String,
    type_name: String,
}
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct LocalContractDebugBudget {
    gas_limit: u64,
    gas_remaining: u64,
    gas_used: u64,
    cycles: u64,
    max_cycles: u64,
    stack_limit_bytes: u64,
    stack_bytes_used: u64,
    entrypoint_pc: u64,
    final_pc: u64,
}
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct LocalContractDebugVmDiagnostic {
    fault: Option<IvmFaultV1>,
    trap_kind: String,
    message: String,
    pc: u64,
    function: Option<String>,
    source_path: Option<String>,
    line: Option<u32>,
    column: Option<u32>,
    gas_limit: u64,
    gas_remaining: u64,
    gas_used: u64,
    cycles: u64,
    max_cycles: u64,
    stack_limit_bytes: u64,
    stack_bytes_used: u64,
    entrypoint_pc: Option<u64>,
    current_function: Option<String>,
    opcode: Option<u16>,
    syscall: Option<u32>,
    predecoded_loaded: bool,
    predecoded_hit: Option<bool>,
}
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct LocalContractSyscallTrace {
    pc: u64,
    syscall: u32,
    gas_remaining_at_call: u64,
    additional_gas: Option<u64>,
    error: Option<String>,
}
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct LocalContractSourceSnippet {
    path: String,
    line: u32,
    column: u32,
    excerpt: String,
}
#[derive(Clone, Debug, crate::json_macros::JsonSerialize)]
struct LocalContractDebugCallResponse {
    ok: bool,
    code_hash_hex: String,
    abi_hash_hex: String,
    entrypoint: LocalContractDebugEntrypoint,
    budget: LocalContractDebugBudget,
    syscall_trace: Vec<LocalContractSyscallTrace>,
    result: Option<norito::json::Value>,
    error: Option<String>,
    fault: Option<IvmFaultV1>,
    vm_diagnostic: Option<LocalContractDebugVmDiagnostic>,
    source_snippet: Option<LocalContractSourceSnippet>,
    queued_instruction_count: usize,
    queued_instructions: norito::json::Value,
    durable_state_mutation_count: usize,
    durable_state_overlay: norito::json::Value,
}
struct TracingHost<H> {
    inner: H,
    syscall_trace: Vec<LocalContractSyscallTrace>,
}
impl<H> TracingHost<H> {
    fn new(inner: H) -> Self {
        Self {
            inner,
            syscall_trace: Vec::new(),
        }
    }
    fn into_parts(self) -> (H, Vec<LocalContractSyscallTrace>) {
        (self.inner, self.syscall_trace)
    }
}
impl<H> IVMHost for TracingHost<H>
where
    H: IVMHost + 'static,
{
    fn prepared_entrypoint_arguments(&self) -> Option<ivm::PreparedArgumentRecord> {
        self.inner.prepared_entrypoint_arguments()
    }
    fn prepare_syscall(&self, number: u32, vm: &ivm::IVM) -> Result<u64, ivm::VMError> {
        self.inner.prepare_syscall(number, vm)
    }
    fn syscall(&mut self, number: u32, vm: &mut ivm::IVM) -> Result<u64, ivm::VMError> {
        let record = LocalContractSyscallTrace {
            pc: vm.pc(),
            syscall: number,
            gas_remaining_at_call: vm.remaining_gas(),
            additional_gas: None,
            error: None,
        };
        match self.inner.syscall(number, vm) {
            Ok(additional_gas) => {
                let mut record = record;
                record.additional_gas = Some(additional_gas);
                self.syscall_trace.push(record);
                Ok(additional_gas)
            }
            Err(err) => {
                let mut record = record;
                record.error = Some(err.to_string());
                self.syscall_trace.push(record);
                Err(err)
            }
        }
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any
    where
        Self: 'static,
    {
        self
    }
    fn begin_tx(&mut self, declared: &ivm::parallel::StateAccessSet) -> Result<(), ivm::VMError> {
        self.inner.begin_tx(declared)
    }
    fn finish_tx(&mut self) -> Result<ivm::host::AccessLog, ivm::VMError> {
        self.inner.finish_tx()
    }
    fn checkpoint(&self) -> Option<Box<dyn std::any::Any + Send>> {
        self.inner.checkpoint()
    }
    fn restore(&mut self, snapshot: &dyn std::any::Any) -> Result<(), ivm::VMError> {
        self.inner.restore(snapshot)
    }
    fn access_logging_supported(&self) -> bool {
        self.inner.access_logging_supported()
    }
}
fn prepare_local_contract_arguments(
    descriptor: &ivm::EmbeddedEntrypointDescriptor,
    payload: Option<&Json>,
    gas_limit: u64,
) -> Result<Option<ivm::PreparedArgumentRecord>> {
    match (descriptor.argument_schema.as_ref(), payload) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(eyre!(
            "zero-parameter entrypoint `{}` must not receive a payload",
            descriptor.name
        )),
        (Some(_), None) => Err(eyre!(
            "parameterized entrypoint `{}` requires a payload",
            descriptor.name
        )),
        (Some(schema), Some(payload)) => {
            let canonical = ivm_abi::arguments::encode_argument_record_from_json(schema, payload)
                .map_err(|err| {
                eyre!(
                    "payload for entrypoint `{}` does not match its argument schema: {err}",
                    descriptor.name
                )
            })?;
            ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), gas_limit)
                .map(Some)
                .map_err(|err| {
                    eyre!(
                        "failed to prepare arguments for entrypoint `{}`: {err}",
                        descriptor.name
                    )
                })
        }
    }
}
fn execute_local_contract_debug_view<C: RunContext>(
    context: &C,
    args: DebugViewArgs,
    authority: AccountId,
) -> Result<LocalContractDebugViewResponse> {
    let code = load_code_bytes(args.code_file.clone(), args.code_b64.clone())?;
    let verified = verify_contract_from_bytes(&code)?;
    let summary = program_summary_from_bytes(&code)?;
    let executable_len = code
        .len()
        .checked_sub(verified.code_offset)
        .ok_or_else(|| eyre!("contract executable offset exceeds artifact length"))?;
    let executable_len = u64::try_from(executable_len)
        .map_err(|_| eyre!("contract executable length exceeds u64"))?;
    let source_map = load_local_contract_source_map(
        args.source_map_file.as_deref(),
        &verified.code_hash,
        executable_len,
    )?;
    let selector = args.entrypoint;
    let descriptor = resolve_local_view_entrypoint(&verified, &selector)?;
    let entrypoint_pc = resolve_local_contract_entrypoint_pc(&code, descriptor)?;
    let payload = load_contract_payload_value(
        args.payload.args.as_deref(),
        args.payload.args_file.as_deref(),
    )?;
    let payload = normalize_local_contract_payload(descriptor, payload.as_ref())?;
    let arguments = prepare_local_contract_arguments(descriptor, payload.as_ref(), args.gas_limit)?;
    let prepared_arguments = arguments.clone();
    let accounts = load_debug_accounts_fixture(
        &authority,
        args.accounts_json.as_deref(),
        args.accounts_file.as_deref(),
    )?;
    let durable_state = load_debug_durable_state_fixture(
        args.durable_state_json.as_deref(),
        args.durable_state_file.as_deref(),
    )?;
    let mut host = if let Some(arguments) = arguments {
        CoreHost::with_accounts_and_argument_record(
            authority,
            Arc::clone(&accounts),
            Some(arguments),
        )
    } else {
        CoreHost::with_accounts(authority, Arc::clone(&accounts))
    };
    host.set_local_contract_debug_view_execution();
    host.set_chain_id(&context.config().chain);
    host.set_durable_state_snapshot(durable_state);
    let mut tracing_host = TracingHost::new(host);
    let mut vm = ivm::IVM::try_new(args.gas_limit)
        .map_err(|err| eyre!("failed to allocate contract debug view VM: {err}"))?;
    vm.load_program(&code)
        .map_err(|err| eyre!("failed to load contract debug view bytecode: {err}"))?;
    vm.set_gas_limit(args.gas_limit);
    vm.set_register(1, vm.memory.code_len());
    vm.set_program_counter(entrypoint_pc)
        .map_err(|err| eyre!("failed to seek to contract debug entrypoint: {err}"))?;
    let preparation = prepared_arguments
        .as_ref()
        .map_or(Ok(()), |arguments| arguments.precharge_vm(&mut vm));
    let run_result = match preparation {
        Ok(()) => local_debug_attempt::run(&mut vm, &mut tracing_host)?,
        Err(error) => {
            vm.record_boundary_fault(&error, IvmFaultPositionV1::Initialization);
            local_debug_attempt::completed(Err(error))?
        }
    };
    let (mut host, syscall_trace) = tracing_host.into_parts();
    let run_result = local_debug_attempt::completed(run_result.and_then(|()| {
        host.finish_local_contract_result(&vm, &descriptor.name)
            .map(|_| ())
    }))?;
    let queued = host.drain_instructions();
    let durable_state_overlay = host.drain_durable_state_overlay();
    let budget = build_local_debug_budget(&vm, args.gas_limit, entrypoint_pc);
    let fault = run_result
        .as_ref()
        .err()
        .and_then(|error| vm.execution_fault(error, IvmFaultPositionV1::ReturnValidation));
    let mut vm_diagnostic = run_result.as_ref().err().and_then(|error| {
        vm.last_diagnostic()
            .map(|diagnostic| map_local_vm_diagnostic(diagnostic, error, &summary.code_hash))
    });
    if let (Some(diagnostic), Some(source_map)) = (vm_diagnostic.as_mut(), source_map.as_deref()) {
        apply_local_contract_source_map(diagnostic, source_map, &summary.code_hash);
    }
    let source_snippet =
        maybe_render_source_snippet(args.source_file.as_deref(), vm_diagnostic.as_ref());
    let entrypoint = build_local_debug_entrypoint(descriptor, entrypoint_pc);
    if let Err(err) = run_result {
        return Ok(LocalContractDebugViewResponse {
            ok: false,
            code_hash_hex: hex::encode(summary.code_hash.as_ref()),
            abi_hash_hex: hex::encode(summary.abi_hash.as_ref()),
            entrypoint,
            budget,
            syscall_trace,
            result: None,
            error: Some(format!("contract debug view execution failed: {err}")),
            fault,
            vm_diagnostic,
            source_snippet,
            queued_instruction_count: queued.len(),
            durable_state_mutation_count: durable_state_overlay.len(),
        });
    }
    if !queued.is_empty() {
        return Ok(LocalContractDebugViewResponse {
            ok: false,
            code_hash_hex: hex::encode(summary.code_hash.as_ref()),
            abi_hash_hex: hex::encode(summary.abi_hash.as_ref()),
            entrypoint,
            budget,
            syscall_trace,
            result: None,
            error: Some("view entrypoint attempted to emit instructions".to_owned()),
            fault,
            vm_diagnostic,
            source_snippet,
            queued_instruction_count: queued.len(),
            durable_state_mutation_count: durable_state_overlay.len(),
        });
    }
    if !durable_state_overlay.is_empty() {
        return Ok(LocalContractDebugViewResponse {
            ok: false,
            code_hash_hex: hex::encode(summary.code_hash.as_ref()),
            abi_hash_hex: hex::encode(summary.abi_hash.as_ref()),
            entrypoint,
            budget,
            syscall_trace,
            result: None,
            error: Some("view entrypoint attempted to mutate durable state".to_owned()),
            fault,
            vm_diagnostic,
            source_snippet,
            queued_instruction_count: queued.len(),
            durable_state_mutation_count: durable_state_overlay.len(),
        });
    }
    let result = descriptor.return_schema.as_ref().map_or_else(
        || Ok(norito::json::Value::Null),
        |schema| {
            local_debug_attempt::decode_return(
                &vm,
                schema,
                "failed to decode contract debug view return value",
            )
        },
    )?;
    Ok(LocalContractDebugViewResponse {
        ok: true,
        code_hash_hex: hex::encode(summary.code_hash.as_ref()),
        abi_hash_hex: hex::encode(summary.abi_hash.as_ref()),
        entrypoint,
        budget,
        syscall_trace,
        result: Some(result),
        error: None,
        fault,
        vm_diagnostic,
        source_snippet,
        queued_instruction_count: 0,
        durable_state_mutation_count: 0,
    })
}
fn execute_local_contract_debug_call<C: RunContext>(
    context: &C,
    args: DebugCallArgs,
    authority: AccountId,
) -> Result<LocalContractDebugCallResponse> {
    let code = load_code_bytes(args.code_file.clone(), args.code_b64.clone())?;
    let verified = verify_contract_from_bytes(&code)?;
    let summary = program_summary_from_bytes(&code)?;
    let executable_len = code
        .len()
        .checked_sub(verified.code_offset)
        .ok_or_else(|| eyre!("contract executable offset exceeds artifact length"))?;
    let executable_len = u64::try_from(executable_len)
        .map_err(|_| eyre!("contract executable length exceeds u64"))?;
    let source_map = load_local_contract_source_map(
        args.source_map_file.as_deref(),
        &verified.code_hash,
        executable_len,
    )?;
    let selector = args.entrypoint;
    let descriptor = resolve_local_call_entrypoint(&verified, &selector)?;
    let entrypoint_pc = resolve_local_contract_entrypoint_pc(&code, descriptor)?;
    let payload = load_contract_payload_value(
        args.payload.args.as_deref(),
        args.payload.args_file.as_deref(),
    )?;
    let payload = normalize_local_contract_payload(descriptor, payload.as_ref())?;
    let arguments = prepare_local_contract_arguments(descriptor, payload.as_ref(), args.gas_limit)?;
    let prepared_arguments = arguments.clone();
    let accounts = load_debug_accounts_fixture(
        &authority,
        args.accounts_json.as_deref(),
        args.accounts_file.as_deref(),
    )?;
    let durable_state = load_debug_durable_state_fixture(
        args.durable_state_json.as_deref(),
        args.durable_state_file.as_deref(),
    )?;
    let mut host = if let Some(arguments) = arguments {
        CoreHost::with_accounts_and_argument_record(
            authority,
            Arc::clone(&accounts),
            Some(arguments),
        )
    } else {
        CoreHost::with_accounts(authority, Arc::clone(&accounts))
    };
    host.set_local_contract_debug_execution();
    host.set_chain_id(&context.config().chain);
    host.set_durable_state_snapshot(durable_state);
    let mut tracing_host = TracingHost::new(host);
    let mut vm = ivm::IVM::try_new(args.gas_limit)
        .map_err(|err| eyre!("failed to allocate contract debug call VM: {err}"))?;
    vm.load_program(&code)
        .map_err(|err| eyre!("failed to load contract debug call bytecode: {err}"))?;
    vm.set_gas_limit(args.gas_limit);
    vm.set_register(1, vm.memory.code_len());
    vm.set_program_counter(entrypoint_pc)
        .map_err(|err| eyre!("failed to seek to contract debug entrypoint: {err}"))?;
    let preparation = prepared_arguments
        .as_ref()
        .map_or(Ok(()), |arguments| arguments.precharge_vm(&mut vm));
    let run_result = match preparation {
        Ok(()) => local_debug_attempt::run(&mut vm, &mut tracing_host)?,
        Err(error) => {
            vm.record_boundary_fault(&error, IvmFaultPositionV1::Initialization);
            local_debug_attempt::completed(Err(error))?
        }
    };
    let (mut host, syscall_trace) = tracing_host.into_parts();
    let run_result = local_debug_attempt::completed(run_result.and_then(|()| {
        host.finish_local_contract_result(&vm, &descriptor.name)
            .map(|_| ())
    }))?;
    let queued = host.drain_instructions();
    let durable_state_overlay = host.drain_durable_state_overlay();
    let queued_instruction_count = queued.len();
    let durable_state_mutation_count = durable_state_overlay.len();
    let queued_instructions = render_queued_instructions(&queued)?;
    let durable_state_overlay_json = render_durable_state_overlay(&durable_state_overlay)?;
    let budget = build_local_debug_budget(&vm, args.gas_limit, entrypoint_pc);
    let fault = run_result
        .as_ref()
        .err()
        .and_then(|error| vm.execution_fault(error, IvmFaultPositionV1::ReturnValidation));
    let mut vm_diagnostic = run_result.as_ref().err().and_then(|error| {
        vm.last_diagnostic()
            .map(|diagnostic| map_local_vm_diagnostic(diagnostic, error, &summary.code_hash))
    });
    if let (Some(diagnostic), Some(source_map)) = (vm_diagnostic.as_mut(), source_map.as_deref()) {
        apply_local_contract_source_map(diagnostic, source_map, &summary.code_hash);
    }
    let source_snippet =
        maybe_render_source_snippet(args.source_file.as_deref(), vm_diagnostic.as_ref());
    let entrypoint = build_local_debug_entrypoint(descriptor, entrypoint_pc);
    if let Err(err) = run_result {
        return Ok(LocalContractDebugCallResponse {
            ok: false,
            code_hash_hex: hex::encode(summary.code_hash.as_ref()),
            abi_hash_hex: hex::encode(summary.abi_hash.as_ref()),
            entrypoint,
            budget,
            syscall_trace,
            result: None,
            error: Some(format!("contract debug call execution failed: {err}")),
            fault,
            vm_diagnostic,
            source_snippet,
            queued_instruction_count,
            queued_instructions,
            durable_state_mutation_count,
            durable_state_overlay: durable_state_overlay_json,
        });
    }
    let result = descriptor
        .return_schema
        .as_ref()
        .map(|schema| {
            local_debug_attempt::decode_return(
                &vm,
                schema,
                "failed to decode contract debug call return value",
            )
        })
        .transpose()?;
    Ok(LocalContractDebugCallResponse {
        ok: true,
        code_hash_hex: hex::encode(summary.code_hash.as_ref()),
        abi_hash_hex: hex::encode(summary.abi_hash.as_ref()),
        entrypoint,
        budget,
        syscall_trace,
        result,
        error: None,
        fault,
        vm_diagnostic,
        source_snippet,
        queued_instruction_count,
        queued_instructions,
        durable_state_mutation_count,
        durable_state_overlay: durable_state_overlay_json,
    })
}
fn build_local_debug_budget(
    vm: &ivm::IVM,
    gas_limit: u64,
    entrypoint_pc: u64,
) -> LocalContractDebugBudget {
    let stack_top = vm.memory.stack_top();
    let stack_pointer = vm.register(31);
    let stack_bytes_used = if stack_pointer <= stack_top {
        stack_top.saturating_sub(stack_pointer)
    } else {
        0
    };
    LocalContractDebugBudget {
        gas_limit,
        gas_remaining: vm.gas_remaining,
        gas_used: gas_limit.saturating_sub(vm.gas_remaining),
        cycles: vm.get_cycle_count(),
        max_cycles: vm.metadata().max_cycles,
        stack_limit_bytes: vm.memory.stack_limit(),
        stack_bytes_used,
        entrypoint_pc,
        final_pc: vm.pc(),
    }
}
fn map_local_vm_diagnostic(
    diag: ivm::VmExecutionDiagnostic<'_>,
    error: &ivm::VMError,
    source_hash: &iroha_crypto::Hash,
) -> LocalContractDebugVmDiagnostic {
    let source = diag.source.as_ref().filter(|_| {
        diag.fault.is_some_and(|fault| {
            fault.site.code_hash == *source_hash
                && matches!(fault.site.position, IvmFaultPositionV1::Execute { .. })
        })
    });
    LocalContractDebugVmDiagnostic {
        fault: diag.fault,
        trap_kind: format!("{:?}", diag.trap_kind),
        message: error.to_string(),
        pc: diag.pc,
        function: source.and_then(|source| source.function.map(str::to_owned)),
        source_path: source.and_then(|source| source.path.map(str::to_owned)),
        line: source.and_then(|source| source.line),
        column: source.and_then(|source| source.column),
        gas_limit: diag.budget.gas_limit,
        gas_remaining: diag.budget.gas_remaining,
        gas_used: diag.budget.gas_used,
        cycles: diag.budget.cycles,
        max_cycles: diag.budget.max_cycles,
        stack_limit_bytes: diag.budget.stack_limit_bytes,
        stack_bytes_used: diag.budget.stack_bytes_used,
        entrypoint_pc: diag.context.entrypoint_pc,
        current_function: diag.context.current_function.map(str::to_owned),
        opcode: diag.context.opcode,
        syscall: diag.context.syscall,
        predecoded_loaded: diag.context.predecoded_loaded,
        predecoded_hit: diag.context.predecoded_hit,
    }
}
fn load_local_contract_source_map(
    path: Option<&Path>,
    artifact_hash: &iroha_crypto::Hash,
    executable_len: u64,
) -> Result<Option<Vec<ivm::EmbeddedSourceMapEntryV1>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let contents = fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read source-map sidecar {}", path.display()))?;
    let value: norito::json::Value = norito::json::from_str(&contents)
        .wrap_err_with(|| format!("failed to parse source-map sidecar {}", path.display()))?;
    let object = value
        .as_object()
        .ok_or_else(|| eyre!("source-map sidecar must be a JSON object"))?;
    if object
        .get("sidecar_version")
        .and_then(norito::json::Value::as_u64)
        != Some(1)
        || object.get("kind").and_then(norito::json::Value::as_str) != Some("source-map")
    {
        return Err(eyre!(
            "source-map sidecar must declare sidecar_version 1 and kind `source-map`"
        ));
    }
    let expected_hash = artifact_hash.to_string();
    let actual_hash = object
        .get("artifact_hash")
        .and_then(norito::json::Value::as_str)
        .ok_or_else(|| eyre!("source-map sidecar is missing string `artifact_hash`"))?;
    if actual_hash != expected_hash {
        return Err(eyre!(
            "source-map sidecar artifact_hash does not match the debug contract artifact"
        ));
    }
    let entries = object
        .get("entries")
        .and_then(norito::json::Value::as_array)
        .ok_or_else(|| eyre!("source-map sidecar is missing array `entries`"))?;
    let mut decoded = Vec::with_capacity(entries.len());
    let mut previous_end = 0_u64;
    for (index, entry) in entries.iter().enumerate() {
        let entry = entry
            .as_object()
            .ok_or_else(|| eyre!("source-map entry {index} must be a JSON object"))?;
        let string = |name: &str| -> Result<String> {
            entry
                .get(name)
                .and_then(norito::json::Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| eyre!("source-map entry {index} is missing string `{name}`"))
        };
        let unsigned = |name: &str| -> Result<u64> {
            entry
                .get(name)
                .and_then(norito::json::Value::as_u64)
                .ok_or_else(|| eyre!("source-map entry {index} is missing integer `{name}`"))
        };
        let narrow = |name: &str| -> Result<u32> {
            u32::try_from(unsigned(name)?)
                .map_err(|_| eyre!("source-map entry {index} `{name}` exceeds u32"))
        };
        let source_path = match entry.get("source_path") {
            Some(norito::json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or_else(|| {
                        eyre!("source-map entry {index} `source_path` must be a string or null")
                    })?
                    .to_owned(),
            ),
            None => {
                return Err(eyre!("source-map entry {index} is missing `source_path`"));
            }
        };
        let pc_start = unsigned("pc_start")?;
        let pc_end = unsigned("pc_end")?;
        if pc_start >= pc_end || pc_end > executable_len || pc_start < previous_end {
            return Err(eyre!(
                "source-map entry {index} has an invalid or overlapping PC range"
            ));
        }
        let byte_start = narrow("byte_start")?;
        let byte_end = narrow("byte_end")?;
        if byte_start > byte_end {
            return Err(eyre!(
                "source-map entry {index} has an invalid source byte range"
            ));
        }
        let line = narrow("line")?;
        let column = narrow("column")?;
        if line == 0 || column == 0 {
            return Err(eyre!(
                "source-map entry {index} line and column must be one-based"
            ));
        }
        decoded.push(ivm::EmbeddedSourceMapEntryV1 {
            function_name: string("function_name")?,
            pc_start,
            pc_end,
            source: ivm::EmbeddedSourceLocation {
                source_path,
                source_id: narrow("source_id")?,
                byte_start,
                byte_end,
                line,
                column,
            },
        });
        previous_end = pc_end;
    }
    Ok(Some(decoded))
}
fn apply_local_contract_source_map(
    diagnostic: &mut LocalContractDebugVmDiagnostic,
    source_map: &[ivm::EmbeddedSourceMapEntryV1],
    source_hash: &iroha_crypto::Hash,
) {
    let Some(fault) = diagnostic
        .fault
        .filter(|fault| fault.site.code_hash == *source_hash)
    else {
        return;
    };
    let IvmFaultPositionV1::Execute {
        pc_offset: relative_pc,
    } = fault.site.position
    else {
        return;
    };
    let Some(entry) = source_map
        .iter()
        .find(|entry| relative_pc >= entry.pc_start && relative_pc < entry.pc_end)
    else {
        return;
    };
    diagnostic.function = Some(entry.function_name.clone());
    diagnostic.current_function = Some(entry.function_name.clone());
    diagnostic.source_path = entry.source.source_path.clone();
    diagnostic.line = Some(entry.source.line);
    diagnostic.column = Some(entry.source.column);
}
fn maybe_render_source_snippet(
    source_file: Option<&std::path::Path>,
    diagnostic: Option<&LocalContractDebugVmDiagnostic>,
) -> Option<LocalContractSourceSnippet> {
    let diagnostic = diagnostic?;
    let line = diagnostic.line?;
    let column = diagnostic.column.unwrap_or(1);
    let resolved_path = if let Some(source_file) = source_file {
        source_file.to_path_buf()
    } else {
        PathBuf::from(diagnostic.source_path.as_deref()?)
    };
    let contents = std::fs::read_to_string(&resolved_path).ok()?;
    let lines = contents.lines().collect::<Vec<_>>();
    let idx = usize::try_from(line.checked_sub(1)?).ok()?;
    if idx >= lines.len() {
        return None;
    }
    let start = idx.saturating_sub(1);
    let end = idx.saturating_add(2).min(lines.len());
    let mut excerpt = String::new();
    for (offset, text) in lines[start..end].iter().enumerate() {
        let current = start + offset + 1;
        if !excerpt.is_empty() {
            excerpt.push('\n');
        }
        excerpt.push_str(&format!("{current:>4} | {text}"));
    }
    Some(LocalContractSourceSnippet {
        path: resolved_path.display().to_string(),
        line,
        column,
        excerpt,
    })
}
fn load_debug_accounts_fixture(
    authority: &AccountId,
    accounts_json: Option<&str>,
    accounts_file: Option<&std::path::Path>,
) -> Result<Arc<Vec<AccountId>>> {
    let mut accounts = match (accounts_json, accounts_file) {
        (Some(raw), None) => parse_debug_account_list(raw)?,
        (None, Some(path)) => {
            let contents = std::fs::read_to_string(path)
                .wrap_err_with(|| format!("read {}", path.display()))?;
            parse_debug_account_list(&contents)?
        }
        (None, None) => vec![authority.clone()],
        (Some(_), Some(_)) => {
            return Err(eyre!(
                "--accounts-json and --accounts-file are mutually exclusive"
            ));
        }
    };
    if !accounts.iter().any(|candidate| candidate == authority) {
        accounts.push(authority.clone());
    }
    Ok(Arc::new(accounts))
}
fn parse_debug_account_list(raw: &str) -> Result<Vec<AccountId>> {
    let parsed: norito::json::Value =
        norito::json::from_str(raw).wrap_err("invalid account fixture JSON")?;
    let array = parsed
        .as_array()
        .ok_or_else(|| eyre!("account fixture must be a JSON array"))?;
    array
        .iter()
        .map(|value| {
            let literal = value
                .as_str()
                .ok_or_else(|| eyre!("account fixture entries must be strings"))?;
            AccountId::parse_encoded(literal)
                .map_err(|err| eyre!("invalid account fixture literal `{literal}`: {err}"))
        })
        .collect()
}
fn load_debug_durable_state_fixture(
    durable_state_json: Option<&str>,
    durable_state_file: Option<&std::path::Path>,
) -> Result<BTreeMap<StatePath, Vec<u8>>> {
    match (durable_state_json, durable_state_file) {
        (Some(raw), None) => parse_debug_durable_state_fixture(raw),
        (None, Some(path)) => {
            let contents = std::fs::read_to_string(path)
                .wrap_err_with(|| format!("read {}", path.display()))?;
            parse_debug_durable_state_fixture(&contents)
        }
        (None, None) => Ok(BTreeMap::new()),
        (Some(_), Some(_)) => Err(eyre!(
            "--durable-state-json and --durable-state-file are mutually exclusive"
        )),
    }
}
fn parse_debug_durable_state_fixture(raw: &str) -> Result<BTreeMap<StatePath, Vec<u8>>> {
    let parsed: norito::json::Value =
        norito::json::from_str(raw).wrap_err("invalid durable state fixture JSON")?;
    let object = parsed
        .as_object()
        .ok_or_else(|| eyre!("durable state fixture must be a JSON object"))?;
    let mut state = BTreeMap::new();
    for (path, value) in object {
        let path = StatePath::from_str(path)
            .map_err(|err| eyre!("invalid durable state key `{path}`: {err}"))?;
        let encoded = value
            .as_str()
            .ok_or_else(|| eyre!("durable state values must be strings"))?;
        let bytes = decode_debug_fixture_bytes(encoded)?;
        // JSON rejects duplicate keys and StatePath rejects noncanonical spelling.
        state.insert(path, bytes);
    }
    Ok(state)
}
fn decode_debug_fixture_bytes(raw: &str) -> Result<Vec<u8>> {
    if let Some(hex_raw) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        return hex::decode(hex_raw).wrap_err("invalid hex fixture bytes");
    }
    base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .wrap_err("invalid base64 fixture bytes")
}
fn resolve_local_entrypoint<'a>(
    artifact: &'a ivm::VerifiedContractArtifact,
    selector: &str,
    expected_kinds: &[iroha_data_model::smart_contract::manifest::EntryPointKind],
    expected_label: &str,
) -> Result<&'a ivm::EmbeddedEntrypointDescriptor> {
    let descriptor = artifact
        .contract_interface
        .entrypoints
        .iter()
        .find(|candidate| candidate.name == selector)
        .ok_or_else(|| eyre!("unknown contract entrypoint `{selector}`"))?;
    if !expected_kinds.contains(&descriptor.kind) {
        return Err(eyre!(
            "contract entrypoint `{selector}` is not a {expected_label} entrypoint"
        ));
    }
    Ok(descriptor)
}
fn resolve_local_view_entrypoint<'a>(
    artifact: &'a ivm::VerifiedContractArtifact,
    selector: &str,
) -> Result<&'a ivm::EmbeddedEntrypointDescriptor> {
    resolve_local_entrypoint(
        artifact,
        selector,
        &[iroha_data_model::smart_contract::manifest::EntryPointKind::View],
        "read-only view",
    )
}
fn resolve_local_call_entrypoint<'a>(
    artifact: &'a ivm::VerifiedContractArtifact,
    selector: &str,
) -> Result<&'a ivm::EmbeddedEntrypointDescriptor> {
    resolve_local_entrypoint(
        artifact,
        selector,
        &[
            iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage,
            iroha_data_model::smart_contract::manifest::EntryPointKind::Hajimari,
            iroha_data_model::smart_contract::manifest::EntryPointKind::Kaizen,
        ],
        "kotoage or lifecycle",
    )
}
fn resolve_local_contract_entrypoint_pc(
    code_bytes: &[u8],
    descriptor: &ivm::EmbeddedEntrypointDescriptor,
) -> Result<u64> {
    let parsed = ivm::ProgramMetadata::parse(code_bytes)
        .map_err(|err| eyre!("invalid contract artifact: {err}"))?;
    Ok(parsed.prefix_len() as u64 + descriptor.entry_pc)
}
fn normalize_local_contract_payload(
    descriptor: &ivm::EmbeddedEntrypointDescriptor,
    payload: Option<&norito::json::Value>,
) -> Result<Option<iroha_primitives::json::Json>> {
    match (descriptor.argument_schema.as_ref(), payload) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(eyre!(
            "contract payload must be omitted for zero-parameter entrypoints"
        )),
        (Some(_), None) => Err(eyre!(
            "contract payload is required for parameterized entrypoints"
        )),
        (Some(schema), Some(payload)) => {
            let object = payload.as_object().ok_or_else(|| {
                eyre!("contract payload must be a JSON object keyed by parameter name")
            })?;
            for field in &schema.fields {
                if !object.contains_key(&field.name) {
                    return Err(eyre!(
                        "missing contract payload field `{}` for entrypoint `{}`",
                        field.name,
                        descriptor.name
                    ));
                }
            }
            for name in object.keys() {
                if !schema.fields.iter().any(|field| field.name == *name) {
                    return Err(eyre!(
                        "unexpected contract payload field `{name}` for entrypoint `{}`",
                        descriptor.name
                    ));
                }
            }
            for field in &schema.fields {
                let mut field_schema = schema.clone();
                field_schema.fields = vec![field.clone()];
                let mut field_object = norito::json::Map::new();
                let field_value = object.get(&field.name).ok_or_else(|| {
                    eyre!(
                        "missing contract payload field `{}` for entrypoint `{}`",
                        field.name,
                        descriptor.name
                    )
                })?;
                field_object.insert(field.name.clone(), field_value.clone());
                let field_payload =
                    iroha_primitives::json::Json::from(norito::json::Value::Object(field_object));
                ivm_abi::arguments::encode_argument_record_from_json(&field_schema, &field_payload).map_err(
                    |error| {
                        eyre!(
                            "contract payload field `{}` does not match the declared schema: {error}",
                            field.name,
                        )
                    },
                )?;
            }
            let payload = iroha_primitives::json::Json::from(payload.clone());
            ivm_abi::arguments::encode_argument_record_from_json(schema, &payload).map_err(|error| {
                eyre!(
                    "contract payload for entrypoint `{}` does not match its exact argument schema: {error}",
                    descriptor.name
                )
            })?;
            Ok(Some(payload))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, ExposedPrivateKey};
    use iroha_i18n::{Bundle, Language, Localizer};
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    use kotodama_lang::session::{CompileRequest, CompilerSession};
    use url::Url;
    #[test]
    fn contract_artifact_identity_requires_exact_hash_and_keeps_full_dataspace() {
        let hash = iroha_crypto::Hash::new(b"CLI artifact identity");
        let literal = hex::encode(hash.as_ref());
        let artifact = contract_artifact_id(u64::MAX, &literal).unwrap();
        assert_eq!(artifact.dataspace_id.as_u64(), u64::MAX);
        assert_eq!(artifact.code_hash, hash);
        assert_eq!(
            contract_artifact_id(u64::MAX, &format!("0x{literal}")).unwrap(),
            artifact
        );
        assert_ne!(contract_artifact_id(0, &literal).unwrap(), artifact);
        for invalid in ["", "00", "0x0x00", "not-hex"] {
            assert!(contract_artifact_id(1, invalid).is_err());
        }
    }
    #[test]
    fn artifact_read_commands_require_an_explicit_dataspace() {
        use clap::Parser as _;
        let hash = hex::encode(iroha_crypto::Hash::new(b"CLI read").as_ref());
        for command in ["code", "manifest"] {
            let mut args = vec![
                "iroha",
                "contract",
                command,
                "get",
                "--code-hash",
                &hash,
                "--out",
                "artifact",
            ];
            assert!(crate::Args::try_parse_from(&args).is_err());
            args.extend(["--dataspace-id", "18446744073709551615"]);
            crate::Args::try_parse_from(&args).expect("explicit full-width artifact scope");
        }
    }
    #[test]
    fn contract_argument_flags_use_one_canonical_spelling() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct ArgumentParser {
            #[command(flatten)]
            payload: ContractPayloadArgs,
        }
        let inline = ArgumentParser::try_parse_from(["contract", "--args", "{}"]).unwrap();
        assert_eq!(inline.payload.args.as_deref(), Some("{}"));
        let file =
            ArgumentParser::try_parse_from(["contract", "--args-file", "args.json"]).unwrap();
        assert_eq!(
            file.payload.args_file.as_deref(),
            Some(Path::new("args.json"))
        );
        for retired in ["--payload-json", "--payload-file"] {
            let error = ArgumentParser::try_parse_from(["contract", retired, "{}"])
                .err()
                .unwrap();
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
        let error = ArgumentParser::try_parse_from([
            "contract",
            "--args",
            "{}",
            "--args-file",
            "args.json",
        ])
        .err()
        .unwrap();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
    #[test]
    fn package_project_commands_are_owned_by_musubi() {
        use crate::Args;
        use clap::Parser;
        for prefix in [["iroha"].as_slice(), ["iroha", "--machine"].as_slice()] {
            for command in [
                ["contract", "dev", "doctor"].as_slice(),
                ["contract", "dev", "check"].as_slice(),
                ["contract", "dev", "build"].as_slice(),
                ["contract", "dev", "test"].as_slice(),
                ["contract", "dev", "schema"].as_slice(),
                ["contract", "app", "build"].as_slice(),
                ["app", "contracts", "dev", "doctor"].as_slice(),
                ["contracts", "dev", "doctor"].as_slice(),
            ] {
                let args = [prefix, command].concat();
                let error = Args::try_parse_from(&args)
                    .expect_err("Musubi package project commands must not parse in iroha");
                assert_eq!(
                    error.kind(),
                    clap::error::ErrorKind::InvalidSubcommand,
                    "duplicate package project command remains: {args:?}"
                );
            }
        }
        let help = Args::try_parse_from(["iroha", "contract", "view", "--help"])
            .expect_err("low-level view still exposes native help");
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn build_manifest_signing_preserves_verified_payload_and_native_provenance() {
        let key = fixture_key_pair(0xCA);
        let account = AccountId::new(key.public_key().clone());
        let mut ctx = TestContext::new(account);
        let program = minimal_view_contract_program();
        let expected = ivm::verify_contract_artifact(&program)
            .expect("verify source contract")
            .manifest;
        let output = tempfile::tempdir().expect("manifest output directory");
        let path = output.path().join("manifest.json");
        BuildManifestArgs {
            code_file: None,
            code_b64: Some(base64::engine::general_purpose::STANDARD.encode(&program)),
            sign_with: Some(ExposedPrivateKey(key.private_key().clone()).to_string()),
            out: Some(path.clone()),
        }
        .run(&mut ctx)
        .expect("build signed manifest");
        let mut owner = manifest_signing::ManifestSigningBudget::new()
            .expect("fund independent output verification");
        let actual: iroha::data_model::smart_contract::manifest::ContractManifest =
            norito::json::from_slice(&std::fs::read(path).expect("signed manifest output"))
                .expect("decode signed manifest output");
        let provenance = actual.provenance.as_ref().expect("manifest provenance");
        assert_eq!(&provenance.signer, key.public_key());
        let frame = owner
            .reserve_frame(&actual)
            .expect("admit verification frame");
        let payload = actual
            .signature_payload_bytes(owner.context(), frame.remaining_bytes())
            .expect("encode output verification payload");
        let mut expected_owner = manifest_signing::ManifestSigningBudget::new()
            .expect("fund independent source payload verification");
        let expected_frame = expected_owner
            .reserve_frame(&expected)
            .expect("admit source verification frame");
        let expected_payload = expected
            .signature_payload_bytes(expected_owner.context(), expected_frame.remaining_bytes())
            .expect("encode source verification payload");
        assert_eq!(payload, expected_payload);
        provenance
            .signature
            .verify(&provenance.signer, &payload)
            .expect("valid emitted manifest signature");
        drop(payload);
        drop(frame);
        drop(expected_payload);
        drop(expected_frame);
    }

    #[test]
    fn build_unsigned_manifest_keeps_original_artifact_payload() {
        let mut ctx = TestContext::new(fixture_account(0xCB));
        let program = minimal_view_contract_program();
        let expected = ivm::verify_contract_artifact(&program)
            .expect("verify source contract")
            .manifest;
        let output = tempfile::tempdir().expect("manifest output directory");
        let path = output.path().join("manifest.json");
        BuildManifestArgs {
            code_file: None,
            code_b64: Some(base64::engine::general_purpose::STANDARD.encode(&program)),
            sign_with: None,
            out: Some(path.clone()),
        }
        .run(&mut ctx)
        .expect("build unsigned manifest");
        let actual: iroha::data_model::smart_contract::manifest::ContractManifest =
            norito::json::from_slice(&std::fs::read(path).expect("unsigned manifest output"))
                .expect("decode unsigned manifest output");
        assert_eq!(actual, expected);
        assert!(actual.provenance.is_none());
    }

    #[test]
    fn default_contract_gas_limit_covers_strict_argument_admission_floor() {
        assert!(DEFAULT_CONTRACT_GAS_LIMIT > 1_048_752);
    }
    fn fixture_key_pair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair")
    }
    fn fixture_account(seed: u8) -> AccountId {
        AccountId::new(fixture_key_pair(seed).public_key().clone())
    }
    fn encode_int_state_value(value: i64) -> Vec<u8> {
        use ivm::state_value::{
            StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1,
            StateValueSchemaV1, state_value_schema_hash_v1,
        };
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::Int)],
        };
        let schema_bytes = norito::to_bytes(&schema).expect("encode state int schema");
        let envelope = ivm_abi::numeric_tlv::encode_int(
            &iroha_primitives::bigint::BigInt::from_i128(i128::from(value)),
        )
        .expect("encode canonical state int pointer");
        norito::to_bytes(&StateValueRecordV1 {
            schema_hash: state_value_schema_hash_v1(&schema_bytes),
            atoms: vec![StateValueAtomV1::Pointer(envelope)],
        })
        .expect("encode state int record")
    }
    fn minimal_program() -> Vec<u8> {
        let meta = ivm::ProgramMetadata {
            max_cycles: 1,
            ..ivm::ProgramMetadata::default()
        };
        let mut program = meta.encode();
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        program
    }
    fn minimal_view_contract_program() -> Vec<u8> {
        let source = concat!(
            include_str!("contracts/fixtures/minimal_view.ko"),
            "        "
        );
        let compiler = kotodama_lang::compiler::Compiler::new();
        let (program, _manifest) = compiler
            .compile_source_with_manifest(source)
            .expect("compile view contract");
        program
    }
    fn compile_contract_program(source: &str) -> Vec<u8> {
        let compiler = kotodama_lang::compiler::Compiler::new();
        let (program, _manifest) = compiler
            .compile_source_with_manifest(source)
            .expect("compile contract");
        program
    }
    fn embedded_entrypoint(program: &[u8], name: &str) -> ivm::EmbeddedEntrypointDescriptor {
        let parsed = ivm::ProgramMetadata::parse(program).expect("parse contract metadata");
        parsed
            .contract_interface
            .expect("compiled contract interface")
            .entrypoints
            .into_iter()
            .find(|entrypoint| entrypoint.name == name)
            .unwrap_or_else(|| panic!("missing embedded entrypoint `{name}`"))
    }
    fn compile_contract_program_with_source_map(
        source: &str,
        source_path: &str,
    ) -> (Vec<u8>, String) {
        let output = CompilerSession::default()
            .build(CompileRequest {
                source,
                source_name: Some(source_path),
            })
            .expect("compile contract with source path");
        let source_map = output
            .report
            .render_source_map_json()
            .expect("render source-map sidecar");
        (output.artifact, source_map)
    }
    #[test]
    fn extract_submitted_transaction_hash_prefers_top_level_field() {
        let value = norito::json!({
            "tx_hash_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "contracts": [
                {
                    "tx_hash_hex": "2222222222222222222222222222222222222222222222222222222222222222"
                }
            ]
        });
        let hash = extract_submitted_transaction_hash(&value).expect("extract hash");
        assert_eq!(
            hash.to_string(),
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
    }
    #[test]
    fn extract_submitted_transaction_hash_rejects_nested_contract_receipt() {
        let value = norito::json!({
            "contracts": [
                {
                    "tx_hash_hex": "3333333333333333333333333333333333333333333333333333333333333333"
                }
            ]
        });
        let err = extract_submitted_transaction_hash(&value)
            .expect_err("nested contract receipt hash should not be accepted");
        assert!(err.to_string().contains("response missing `tx_hash_hex`"));
    }
    #[test]
    fn resolve_network_context_accepts_public_profile() {
        let (profile, chain_discriminant) =
            resolve_network_context(Some("taira"), None).expect("resolve profile");
        assert_eq!(profile.as_deref(), Some("taira"));
        assert_eq!(
            chain_discriminant,
            iroha_torii_shared::TAIRA_CHAIN_DISCRIMINANT
        );
    }
    #[test]
    fn resolve_network_context_rejects_profile_discriminant_mismatch() {
        let err = resolve_network_context(Some("taira"), Some(753))
            .expect_err("profile mismatch should fail");
        assert!(
            err.to_string()
                .contains("profile `taira` expects chain_discriminant=369")
        );
    }
    #[test]
    fn contract_submit_only_response_marks_unfinalized() {
        let response =
            contract_submit_only_response(norito::json!({ "tx_hash_hex": "deadbeef" }), None);
        assert_eq!(
            response
                .get("finalized")
                .and_then(norito::json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            response
                .get("submit")
                .and_then(|submit| submit.get("tx_hash_hex"))
                .and_then(norito::json::Value::as_str),
            Some("deadbeef")
        );
    }
    #[test]
    fn contract_submit_only_response_keeps_operation_receipt_under_submit() {
        let response = contract_submit_only_response(
            norito::json!({
                "tx_hash_hex": "deadbeef",
                "operation_receipt": {
                    "operation_kind": "contract_call",
                    "status": "submitted",
                    "transport": "torii",
                    "dataspace": "universal",
                    "payload_digest_hex": "payload-digest"
                }
            }),
            None,
        );
        assert!(response.get("operation_receipt").is_none());
        assert!(response.get("tx_hash_hex").is_none());
        assert_eq!(
            response
                .get("submit")
                .and_then(|submit| submit.get("operation_receipt"))
                .and_then(|receipt| receipt.get("operation_kind"))
                .and_then(norito::json::Value::as_str),
            Some("contract_call")
        );
        let submit = response
            .get("submit")
            .and_then(norito::json::Value::as_object)
            .expect("submit object");
        for forbidden_key in [
            "private_key",
            "payload",
            "raw_payload",
            "normalized_payload",
            "transaction_scaffold_b64",
            "signed_transaction_b64",
            "transaction_payload_b64",
            "signing_message_b64",
        ] {
            assert!(
                submit.get(forbidden_key).is_none(),
                "CLI submit response must not expose `{forbidden_key}`"
            );
        }
    }
    #[test]
    fn contract_payload_validation_rejects_adversarial_shapes() {
        let account = fixture_account(0x11).to_string();
        let program = compile_contract_program(concat!(
            include_str!("contracts/fixtures/adversarial_payload.ko"),
            "            "
        ));
        let submit = embedded_entrypoint(&program, "submit");
        let upload = embedded_entrypoint(&program, "upload");
        let ping = embedded_entrypoint(&program, "ping");
        let err =
            normalize_local_contract_payload(&submit, None).expect_err("missing payload fails");
        assert!(
            err.to_string()
                .contains("contract payload is required for parameterized entrypoints"),
            "unexpected error: {err}"
        );
        let err = normalize_local_contract_payload(&submit, Some(&norito::json!([1, 2])))
            .expect_err("array payload fails");
        assert!(
            err.to_string()
                .contains("contract payload must be a JSON object keyed by parameter name"),
            "unexpected error: {err}"
        );
        let missing = norito::json!({ "recipient": (account.clone()) });
        let err = normalize_local_contract_payload(&submit, Some(&missing))
            .expect_err("missing required field fails");
        assert!(
            err.to_string()
                .contains("missing contract payload field `amount`"),
            "unexpected error: {err}"
        );
        let wrong_type = norito::json!({ "amount": 7, "recipient": (account.clone()) });
        let err = normalize_local_contract_payload(&submit, Some(&wrong_type))
            .expect_err("wrong amount type fails");
        assert!(
            err.to_string()
                .contains("contract payload field `amount` does not match the declared schema"),
            "unexpected error: {err}"
        );
        let extra = norito::json!({ "amount": "7", "recipient": (account), "extra": 1 });
        let err = normalize_local_contract_payload(&submit, Some(&extra))
            .expect_err("unexpected field fails");
        assert!(
            err.to_string()
                .contains("unexpected contract payload field `extra`"),
            "unexpected error: {err}"
        );
        let err = normalize_local_contract_payload(&ping, Some(&norito::json!({ "extra": 1 })))
            .expect_err("zero-parameter entrypoint rejects non-empty payload");
        assert!(
            err.to_string().contains("contract payload must be omitted"),
            "unexpected error: {err}"
        );
        let err = normalize_local_contract_payload(&ping, Some(&norito::json!(null)))
            .expect_err("zero-parameter entrypoint rejects null payload");
        assert!(
            err.to_string().contains("contract payload must be omitted"),
            "unexpected error: {err}"
        );
        for (payload, expected_field) in [
            (
                norito::json!({ "owner": "not-an-account", "tag": "safe_tag", "payload": "0x00" }),
                "owner",
            ),
            (
                norito::json!({ "owner": (fixture_account(0x12).to_string()), "tag": "bad tag", "payload": "0x00" }),
                "tag",
            ),
            (
                norito::json!({ "owner": (fixture_account(0x13).to_string()), "tag": "safe_tag", "payload": "0x0" }),
                "payload",
            ),
        ] {
            let err = normalize_local_contract_payload(&upload, Some(&payload))
                .expect_err("invalid typed payload field fails");
            assert!(
                err.to_string().contains(&format!(
                    "contract payload field `{expected_field}` does not match the declared schema"
                )),
                "unexpected error: {err}"
            );
        }
    }
    #[test]
    fn program_summary_reports_hashes() {
        let program = minimal_view_contract_program();
        let expected_code_hash = ivm::contract_code_hash(&program);
        let summary = program_summary_from_bytes(&program).expect("summary");
        assert_eq!(summary.code_hash, expected_code_hash);
        assert_eq!(
            summary.abi_hash,
            iroha_crypto::Hash::prehashed(ivm::syscalls::compute_abi_hash(
                ivm::SyscallPolicy::AbiV1,
            ))
        );
    }
    #[test]
    fn fixture_key_pair_uses_checked_seed_derivation() {
        assert_eq!(fixture_key_pair(1).algorithm(), Algorithm::Ed25519);
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    #[test]
    fn bounded_manifest_signing_verifies_original_and_rejects_changed_content() {
        let key_pair = fixture_key_pair(0x61);
        let manifest = verify_contract_from_bytes(&minimal_view_contract_program())
            .expect("verify source artifact")
            .manifest;
        with_signed_contract_manifest(manifest, &key_pair, 4096, |mut signed, context| {
            let payload = signed.signature_payload_bytes(context, 4096)?;
            let provenance = signed.provenance.as_ref().expect("signed provenance");
            assert_eq!(&provenance.signer, key_pair.public_key());
            provenance.signature.verify(&provenance.signer, &payload)?;
            drop(payload);
            signed.seiyaku_name = Some("changed signed source".to_owned());
            let payload = signed.signature_payload_bytes(context, 4096)?;
            let provenance = signed.provenance.as_ref().unwrap();
            assert!(
                provenance
                    .signature
                    .verify(&provenance.signer, &payload)
                    .is_err()
            );
            assert!(context.consumed_allocated_bytes() > 0);
            Ok(())
        })
        .expect("funded manifest consumption");
    }
    #[test]
    fn bounded_manifest_signing_refuses_invalid_grants_before_consumption() {
        let key_pair = fixture_key_pair(0x62);
        let manifest = verify_contract_from_bytes(&minimal_view_contract_program())
            .expect("verify source artifact")
            .manifest;
        let error = with_signed_contract_manifest(manifest.clone(), &key_pair, 1, |_, _| {
            panic!("an oversized signing frame cannot reach its consumer")
        })
        .expect_err("reject the undersized complete frame ceiling");
        assert!(matches!(
            error.downcast_ref::<norito::Error>(),
            Some(norito::Error::LengthMismatch)
        ));
        for bound in [0, usize::MAX] {
            assert!(
                with_signed_contract_manifest(manifest.clone(), &key_pair, bound, |_, _| {
                    panic!("invalid physical grants cannot reach signing consumption")
                })
                .is_err()
            );
        }
    }
    #[test]
    fn build_manifest_signing_publishes_the_authenticated_artifact_manifest() {
        let key_pair = fixture_key_pair(0x63);
        let mut context = TestContext::new(AccountId::new(key_pair.public_key().clone()));
        let directory = tempfile::tempdir().expect("manifest output directory");
        let path = directory.path().join("manifest.json");
        let program = minimal_view_contract_program();
        BuildManifestArgs {
            code_file: None,
            code_b64: Some(base64::engine::general_purpose::STANDARD.encode(&program)),
            sign_with: Some(ExposedPrivateKey(key_pair.private_key().clone()).to_string()),
            out: Some(path.clone()),
        }
        .run(&mut context)
        .expect("build and publish the bounded signed manifest");
        let bytes = iroha_fs::read_private(&path, 4096).expect("private published manifest");
        let manifest: iroha_data_model::smart_contract::manifest::ContractManifest =
            norito::json::from_slice(&bytes).expect("decode published manifest");
        let verified = verify_contract_from_bytes(&program).expect("verify artifact");
        assert!(manifest.same_signed_content(&verified.manifest));
        assert_eq!(
            &manifest
                .provenance
                .as_ref()
                .expect("published provenance")
                .signer,
            key_pair.public_key()
        );
        with_signed_contract_manifest(verified.manifest, &key_pair, 4096, |_, context| {
            let payload = manifest.signature_payload_bytes(context, 4096)?;
            let provenance = manifest.provenance.as_ref().unwrap();
            provenance.signature.verify(&provenance.signer, &payload)?;
            Ok(())
        })
        .expect("authenticate the published signature with bounded original backing");
    }
    #[test]
    fn simulate_emits_typed_fee_gas_bound_without_legacy_metadata() {
        let key_pair = fixture_key_pair(1);
        let authority = AccountId::new(key_pair.public_key().clone());
        let mut ctx = TestContext::new(authority.clone());
        let authority_literal = authority.to_string();
        let program = minimal_program();
        let code_b64 = base64::engine::general_purpose::STANDARD.encode(&program);
        let private_key = ExposedPrivateKey(key_pair.private_key().clone()).to_string();
        let args = SimulateArgs {
            authority: authority_literal,
            private_key,
            code_file: None,
            code_b64: Some(code_b64),
            gas_limit: 42,
        };
        args.run(&mut ctx).expect("simulate");
        let output = ctx.take_output().expect("output");
        let metadata_keys = output
            .get("metadata_keys")
            .and_then(norito::json::Value::as_array)
            .expect("metadata_keys");
        assert!(
            metadata_keys.is_empty(),
            "simulation must not emit legacy fee metadata: {metadata_keys:?}"
        );
        assert_eq!(
            output
                .get("fee_gas_limit")
                .and_then(norito::json::Value::as_u64),
            Some(42)
        );
    }
    #[test]
    fn simulate_routes_cntr_artifacts_to_contract_specific_commands() {
        let key_pair = fixture_key_pair(2);
        let authority = AccountId::new(key_pair.public_key().clone());
        let mut ctx = TestContext::new(authority.clone());
        let args = SimulateArgs {
            authority: authority.to_string(),
            private_key: ExposedPrivateKey(key_pair.private_key().clone()).to_string(),
            code_file: None,
            code_b64: Some(
                base64::engine::general_purpose::STANDARD.encode(minimal_view_contract_program()),
            ),
            gas_limit: 42,
        };
        let error = args
            .run(&mut ctx)
            .expect_err("CNTR simulation requires contract-aware dispatch");
        assert!(
            error.to_string().contains("contract call --simulate")
                && error.to_string().contains("contract debug-call"),
            "unexpected routing error: {error}"
        );
    }
    #[test]
    fn debug_view_executes_local_view_and_decodes_result() {
        let authority = fixture_account(0x21);
        let mut ctx = TestContext::new(authority);
        let program = minimal_view_contract_program();
        let code_b64 = base64::engine::general_purpose::STANDARD.encode(&program);
        let args = DebugViewArgs {
            authority: None,
            code_file: None,
            code_b64: Some(code_b64),
            entrypoint: "inspect".to_owned(),
            gas_limit: DEFAULT_CONTRACT_GAS_LIMIT,
            source_file: None,
            source_map_file: None,
            accounts_json: None,
            accounts_file: None,
            durable_state_json: None,
            durable_state_file: None,
            payload: ContractPayloadArgs {
                args: None,
                args_file: None,
            },
        };
        args.run(&mut ctx).expect("debug view");
        let output = ctx.take_output().expect("output");
        assert_eq!(
            output.get("ok").and_then(norito::json::Value::as_bool),
            Some(true),
            "unexpected debug-view response: {output:?}"
        );
        assert_eq!(
            output.get("result").and_then(norito::json::Value::as_str),
            Some("7")
        );
        assert_eq!(
            output
                .get("entrypoint")
                .and_then(norito::json::Value::as_object)
                .and_then(|entrypoint| entrypoint.get("name"))
                .and_then(norito::json::Value::as_str),
            Some("inspect")
        );
    }
    #[test]
    fn debug_view_uses_hash_bound_source_map_for_snippets() {
        let authority = fixture_account(0x22);
        let mut ctx = TestContext::new(authority);
        let dir = tempfile::tempdir().expect("tempdir");
        let source_path = dir.path().join("debug_view_with_path.ko");
        let source = concat!(
            include_str!("contracts/fixtures/minimal_view.ko"),
            "        "
        );
        std::fs::write(&source_path, source).expect("write source");
        let (program, source_map) =
            compile_contract_program_with_source_map(source, &source_path.display().to_string());
        let source_map_path = dir.path().join("debug_view.source-map.json");
        std::fs::write(&source_map_path, source_map).expect("write source-map sidecar");
        let code_b64 = base64::engine::general_purpose::STANDARD.encode(&program);
        let args = DebugViewArgs {
            authority: None,
            code_file: None,
            code_b64: Some(code_b64),
            entrypoint: "inspect".to_owned(),
            // The entrypoint wrapper costs two gas; exhaust at the first mapped body opcode.
            gas_limit: 2,
            source_file: None,
            source_map_file: Some(source_map_path),
            accounts_json: None,
            accounts_file: None,
            durable_state_json: None,
            durable_state_file: None,
            payload: ContractPayloadArgs {
                args: None,
                args_file: None,
            },
        };
        args.run(&mut ctx).expect("debug view");
        let output = ctx.take_output().expect("output");
        assert_eq!(
            output.get("ok").and_then(norito::json::Value::as_bool),
            Some(false)
        );
        let diagnostic = output
            .get("vm_diagnostic")
            .and_then(norito::json::Value::as_object)
            .expect("VM diagnostic");
        assert_eq!(
            diagnostic
                .get("function")
                .and_then(norito::json::Value::as_str),
            Some("inspect")
        );
        assert_eq!(
            diagnostic
                .get("current_function")
                .and_then(norito::json::Value::as_str),
            Some("inspect")
        );
        let snippet = output
            .get("source_snippet")
            .and_then(norito::json::Value::as_object)
            .expect("source snippet");
        assert_eq!(
            snippet.get("path").and_then(norito::json::Value::as_str),
            Some(source_path.to_string_lossy().as_ref())
        );
        let excerpt = snippet
            .get("excerpt")
            .and_then(norito::json::Value::as_str)
            .expect("excerpt");
        assert!(
            excerpt.contains("view fn inspect"),
            "unexpected excerpt: {excerpt}"
        );
    }
    #[test]
    fn debug_source_map_rejects_mismatched_artifact_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source_path = dir.path().join("debug_view_mismatch.ko");
        let source = concat!(
            include_str!("contracts/fixtures/minimal_view.ko"),
            "        "
        );
        let (program, source_map) =
            compile_contract_program_with_source_map(source, &source_path.display().to_string());
        let mut source_map: norito::json::Value =
            norito::json::from_str(&source_map).expect("parse source-map sidecar");
        source_map
            .as_object_mut()
            .expect("source-map object")
            .insert(
                "artifact_hash".to_owned(),
                norito::json::Value::from("00".repeat(iroha_crypto::Hash::LENGTH)),
            );
        let source_map_path = dir.path().join("mismatch.source-map.json");
        std::fs::write(
            &source_map_path,
            norito::json::to_json_pretty(&source_map).expect("render tampered sidecar"),
        )
        .expect("write tampered sidecar");
        let parsed = ivm::ProgramMetadata::parse(&program).expect("parse contract metadata");
        let executable_len = u64::try_from(program.len() - parsed.code_offset)
            .expect("fixture executable length fits u64");
        let err = load_local_contract_source_map(
            Some(&source_map_path),
            &ivm::contract_code_hash(&program),
            executable_len,
        )
        .expect_err("mismatched source-map sidecar must fail");
        assert!(
            err.to_string().contains("artifact_hash does not match"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn source_snippet_ignores_out_of_range_source_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source_path = dir.path().join("short.ko");
        std::fs::write(&source_path, "one line\n").expect("write source");
        let diagnostic = LocalContractDebugVmDiagnostic {
            fault: None,
            trap_kind: "OutOfGas".to_owned(),
            message: "fixture".to_owned(),
            pc: 0,
            function: Some("inspect".to_owned()),
            source_path: Some(source_path.display().to_string()),
            line: Some(2),
            column: Some(1),
            gas_limit: 0,
            gas_remaining: 0,
            gas_used: 0,
            cycles: 0,
            max_cycles: 0,
            stack_limit_bytes: 0,
            stack_bytes_used: 0,
            entrypoint_pc: None,
            current_function: Some("inspect".to_owned()),
            opcode: None,
            syscall: None,
            predecoded_loaded: false,
            predecoded_hit: None,
        };
        assert!(
            maybe_render_source_snippet(None, Some(&diagnostic)).is_none(),
            "an invalid sidecar line must not panic or produce an empty snippet"
        );
        let parent_hash = iroha_crypto::Hash::new(b"parent artifact");
        let child_hash = iroha_crypto::Hash::new(b"child artifact");
        let mut diagnostic = diagnostic;
        diagnostic.function = None;
        diagnostic.source_path = None;
        diagnostic.line = None;
        diagnostic.column = None;
        diagnostic.fault = Some(IvmFaultV1 {
            kind: iroha_data_model::executor::fault::IvmFaultKindV1::OutOfGas,
            site: iroha_data_model::executor::fault::IvmFaultSiteV1 {
                code_hash: child_hash,
                selector: iroha_data_model::executor::fault::IvmInvocationSelectorV1::Entrypoint(0),
                position: IvmFaultPositionV1::Execute { pc_offset: 4 },
            },
        });
        let source_map = vec![ivm::EmbeddedSourceMapEntryV1 {
            function_name: "inspect".into(),
            pc_start: 4,
            pc_end: 8,
            source: ivm::EmbeddedSourceLocation {
                source_path: Some("matching.ko".into()),
                source_id: 0,
                byte_start: 0,
                byte_end: 1,
                line: 7,
                column: 2,
            },
        }];
        apply_local_contract_source_map(&mut diagnostic, &source_map, &parent_hash);
        assert!(
            diagnostic.source_path.is_none(),
            "child fault must never use parent sidecar"
        );
        apply_local_contract_source_map(&mut diagnostic, &source_map, &child_hash);
        assert_eq!(
            diagnostic.line,
            Some(7),
            "use authenticated relative PC, not local diagnostic PC"
        );
        diagnostic.line = None;
        diagnostic.fault.as_mut().unwrap().site.position = IvmFaultPositionV1::ReturnValidation;
        apply_local_contract_source_map(&mut diagnostic, &source_map, &child_hash);
        assert!(
            diagnostic.line.is_none(),
            "return validation has no invented instruction coordinate"
        );
    }
    #[test]
    fn debug_view_source_file_override_beats_sidecar_path() {
        let authority = fixture_account(0x23);
        let mut ctx = TestContext::new(authority);
        let dir = tempfile::tempdir().expect("tempdir");
        let embedded_path = dir.path().join("embedded.ko");
        let override_path = dir.path().join("override.ko");
        let source = concat!(
            include_str!("contracts/fixtures/minimal_view.ko"),
            "        "
        );
        std::fs::write(&embedded_path, source).expect("write embedded source");
        std::fs::write(
            &override_path,
            concat!(
                include_str!("contracts/fixtures/override_view.ko"),
                "            "
            ),
        )
        .expect("write override source");
        let (program, source_map) =
            compile_contract_program_with_source_map(source, &embedded_path.display().to_string());
        let source_map_path = dir.path().join("debug_view.source-map.json");
        std::fs::write(&source_map_path, source_map).expect("write source-map sidecar");
        let code_b64 = base64::engine::general_purpose::STANDARD.encode(&program);
        let args = DebugViewArgs {
            authority: None,
            code_file: None,
            code_b64: Some(code_b64),
            entrypoint: "inspect".to_owned(),
            // The entrypoint wrapper costs two gas; exhaust at the first mapped body opcode.
            gas_limit: 2,
            source_file: Some(override_path.clone()),
            source_map_file: Some(source_map_path),
            accounts_json: None,
            accounts_file: None,
            durable_state_json: None,
            durable_state_file: None,
            payload: ContractPayloadArgs {
                args: None,
                args_file: None,
            },
        };
        args.run(&mut ctx).expect("debug view");
        let output = ctx.take_output().expect("output");
        let snippet = output
            .get("source_snippet")
            .and_then(norito::json::Value::as_object)
            .expect("source snippet");
        assert_eq!(
            snippet.get("path").and_then(norito::json::Value::as_str),
            Some(override_path.to_string_lossy().as_ref())
        );
        let excerpt = snippet
            .get("excerpt")
            .and_then(norito::json::Value::as_str)
            .expect("excerpt");
        assert!(
            excerpt.contains("return 99"),
            "unexpected excerpt: {excerpt}"
        );
    }
    #[test]
    fn debug_call_executes_public_entrypoint_and_reports_side_effects() {
        let authority = fixture_account(0x31);
        let mut ctx = TestContext::new(authority);
        let source = concat!(include_str!("contracts/fixtures/debug_call.ko"), "        ");
        let program = compile_contract_program(&source);
        let code_b64 = base64::engine::general_purpose::STANDARD.encode(&program);
        let durable_state_json = format!(
            r#"{{"counter":"0x{}"}}"#,
            hex::encode(encode_int_state_value(41))
        );
        let args = DebugCallArgs {
            authority: None,
            code_file: None,
            code_b64: Some(code_b64),
            entrypoint: "bump".to_owned(),
            gas_limit: DEFAULT_CONTRACT_GAS_LIMIT,
            source_file: None,
            source_map_file: None,
            accounts_json: None,
            accounts_file: None,
            durable_state_json: Some(durable_state_json),
            durable_state_file: None,
            payload: ContractPayloadArgs {
                args: None,
                args_file: None,
            },
        };
        args.run(&mut ctx).expect("debug call");
        let output = ctx.take_output().expect("output");
        assert_eq!(
            output.get("ok").and_then(norito::json::Value::as_bool),
            Some(true),
            "unexpected debug-call response: {output:?}"
        );
        assert_eq!(
            output.get("result").and_then(norito::json::Value::as_str),
            Some("42")
        );
        assert_eq!(
            output
                .get("queued_instruction_count")
                .and_then(norito::json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            output
                .get("durable_state_mutation_count")
                .and_then(norito::json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            output
                .get("queued_instructions")
                .and_then(norito::json::Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        let overlay = output
            .get("durable_state_overlay")
            .and_then(norito::json::Value::as_object)
            .expect("durable overlay");
        assert!(
            overlay.contains_key("counter"),
            "expected durable overlay to contain counter: {overlay:?}"
        );
    }
    #[test]
    fn debug_result_error_keeps_return_value_and_discards_state_and_ledger_effects() {
        let authority = fixture_account(0x35);
        let ctx = TestContext::new(authority.clone());
        let program = compile_contract_program(
            r#"
seiyaku DebugResult { permission Admin;
    state StateMap<int, int> Values;
    kotoage fn run(bool succeed) authorize(Admin) -> Result<int, int> {
        Values[1] = 9;
        ledger::domain::register(domain: DomainId::parse("debugresult.universal"));
        if succeed { return Result::ok(9); }
        return Result::err(7);
    }
}"#,
        );
        let code_b64 = base64::engine::general_purpose::STANDARD.encode(&program);
        for succeed in [false, true] {
            let response = execute_local_contract_debug_call(
                &ctx,
                DebugCallArgs {
                    authority: None,
                    code_file: None,
                    code_b64: Some(code_b64.clone()),
                    entrypoint: "run".to_owned(),
                    gas_limit: DEFAULT_CONTRACT_GAS_LIMIT,
                    source_file: None,
                    source_map_file: None,
                    accounts_json: None,
                    accounts_file: None,
                    durable_state_json: None,
                    durable_state_file: None,
                    payload: ContractPayloadArgs {
                        args: Some(format!("{{\"succeed\":{succeed}}}")),
                        args_file: None,
                    },
                },
                authority.clone(),
            )
            .expect("complete local Result call");
            assert!(
                response.ok,
                "returned Err remains recoverable: {:?}",
                response.error
            );
            assert_eq!(
                response.result,
                Some(if succeed {
                    norito::json!({"ok": "9"})
                } else {
                    norito::json!({"err": "7"})
                })
            );
            assert_eq!(response.queued_instruction_count, usize::from(succeed));
            assert_eq!(response.durable_state_mutation_count, usize::from(succeed));
        }
    }

    #[test]
    fn debug_call_executes_lifecycle_and_persists_state_for_readback() {
        let authority = fixture_account(0x34);
        let ctx = TestContext::new(authority.clone());
        let program = compile_contract_program(
            "seiyaku LifecycleDebug {\n                state int counter;\n                hajimari() { counter = 7; }\n                kaizen() { counter = counter + 1; }\n                view fn value() authorize(anyone) -> int { return counter; }\n            }",
        );
        let code_b64 = base64::engine::general_purpose::STANDARD.encode(&program);
        let mut state = None;
        for (selector, expected) in [("hajimari", 7), ("kaizen", 8)] {
            let response = execute_local_contract_debug_call(
                &ctx,
                DebugCallArgs {
                    authority: None,
                    code_file: None,
                    code_b64: Some(code_b64.clone()),
                    entrypoint: selector.to_owned(),
                    gas_limit: DEFAULT_CONTRACT_GAS_LIMIT,
                    source_file: None,
                    source_map_file: None,
                    accounts_json: None,
                    accounts_file: None,
                    durable_state_json: state,
                    durable_state_file: None,
                    payload: ContractPayloadArgs {
                        args: None,
                        args_file: None,
                    },
                },
                authority.clone(),
            )
            .expect("local lifecycle execution");
            assert!(response.ok, "{selector}: {:?}", response.error);
            assert_eq!(response.result, Some(norito::json::Value::Null));
            assert_eq!(response.durable_state_mutation_count, 1);
            assert_eq!(response.queued_instruction_count, 0);
            assert_eq!(
                response.durable_state_overlay.get("counter"),
                Some(&norito::json::Value::from(format!(
                    "0x{}",
                    hex::encode(encode_int_state_value(expected))
                )))
            );
            state = Some(norito::json::to_json(&response.durable_state_overlay).unwrap());
        }
        let response = execute_local_contract_debug_view(
            &ctx,
            DebugViewArgs {
                authority: None,
                code_file: None,
                code_b64: Some(code_b64),
                entrypoint: "value".to_owned(),
                gas_limit: DEFAULT_CONTRACT_GAS_LIMIT,
                source_file: None,
                source_map_file: None,
                accounts_json: None,
                accounts_file: None,
                durable_state_json: state,
                durable_state_file: None,
                payload: ContractPayloadArgs {
                    args: None,
                    args_file: None,
                },
            },
            authority,
        )
        .expect("read lifecycle state");
        assert!(response.ok, "readback: {:?}", response.error);
        assert_eq!(response.result, Some(norito::json::Value::from("8")));
        assert_eq!(response.durable_state_mutation_count, 0);
    }
    #[test]
    fn debug_call_rejects_view_entrypoints() {
        let authority = fixture_account(0x32);
        let mut ctx = TestContext::new(authority);
        let program = minimal_view_contract_program();
        let code_b64 = base64::engine::general_purpose::STANDARD.encode(&program);
        let args = DebugCallArgs {
            authority: None,
            code_file: None,
            code_b64: Some(code_b64),
            entrypoint: "inspect".to_owned(),
            gas_limit: 50_000,
            source_file: None,
            source_map_file: None,
            accounts_json: None,
            accounts_file: None,
            durable_state_json: None,
            durable_state_file: None,
            payload: ContractPayloadArgs {
                args: None,
                args_file: None,
            },
        };
        let err = args
            .run(&mut ctx)
            .expect_err("view entrypoints must be rejected");
        assert!(
            err.to_string()
                .contains("is not a kotoage or lifecycle entrypoint"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn debug_call_matches_overlay_for_public_by_call_execution() {
        use iroha::data_model::{
            permission::{Permission, Permissions},
            transaction::executable::{ContractArgumentRecord, ContractInvocation},
        };
        use iroha_core::{
            smartcontracts::{Execute as _, code},
            state::World,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        let authority_key_pair = fixture_key_pair(0x33);
        // The chain retains the signed manifest in State. Admit these owners
        // before constructing the chain so State is always destroyed first.
        let mut signing_owner =
            manifest_signing::ManifestSigningBudget::new().expect("fund contract manifest signing");
        let _signer_backing = signing_owner
            .reserve_signer(authority_key_pair.public_key())
            .expect("retain original manifest signer backing");
        let authority = AccountId::new(authority_key_pair.public_key().clone());
        let mut ctx = TestContext::new(authority.clone());
        let fixture_domain =
            Domain::new(DomainId::try_new("fixture", "universal").expect("valid fixture domain"))
                .build(&authority);
        let account = Account::new(authority.clone()).build(&authority);
        let mut world = World::with([fixture_domain], [account], []);
        let mut permissions = Permissions::new();
        assert!(permissions.insert(Permission::new(
            "CanManageSmartContractCode".to_owned(),
            iroha_primitives::json::Json::new(()),
        )));
        world
            .account_permissions_mut_for_testing()
            .insert(authority.clone(), permissions);
        // Live contract lookup authenticates its root scope from committed genesis metadata.
        let mut chain_config = TestChainConfig::new(world, 1_000);
        chain_config.chain_id = ctx.config().chain.clone();
        let chain = CertifiedTestChain::start(chain_config).expect("certified contract test chain");
        ctx.cfg.network_id = chain.network_id();
        let source = concat!(
            include_str!("contracts/fixtures/debug_parity.ko"),
            "        "
        );
        let program = compile_contract_program(source);
        let code_b64 = base64::engine::general_purpose::STANDARD.encode(&program);
        let arguments_json = r#"{"amount":"7"}"#.to_owned();
        let args = DebugCallArgs {
            authority: None,
            code_file: None,
            code_b64: Some(code_b64),
            entrypoint: "bump".to_owned(),
            gas_limit: DEFAULT_CONTRACT_GAS_LIMIT,
            source_file: None,
            source_map_file: None,
            accounts_json: None,
            accounts_file: None,
            durable_state_json: None,
            durable_state_file: None,
            payload: ContractPayloadArgs {
                args: Some(arguments_json.clone()),
                args_file: None,
            },
        };
        ivm::reset_argument_record_decode_count();
        args.run(&mut ctx).expect("debug call");
        #[cfg(debug_assertions)]
        assert_eq!(
            ivm::argument_record_decode_count(),
            1,
            "tracing must retain the prepared arguments without decoding them again"
        );
        let output = ctx.take_output().expect("debug call output");
        assert_eq!(
            output.get("ok").and_then(norito::json::Value::as_bool),
            Some(true),
            "unexpected debug-call response: {output:?}"
        );
        let verified = ivm::verify_contract_artifact(&program).expect("verify contract artifact");
        let code_hash = verified.code_hash;
        let argument_schema = verified
            .contract_interface
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == "bump")
            .and_then(|entrypoint| entrypoint.argument_schema.as_ref())
            .expect("bump argument schema")
            .clone();
        let frame = signing_owner
            .reserve_frame(&verified.manifest)
            .expect("admit canonical contract manifest payload");
        let manifest = verified
            .manifest
            .try_signed(
                signing_owner.context(),
                frame.remaining_bytes(),
                &authority_key_pair,
            )
            .expect("sign contract manifest");
        drop(frame);
        let argument_bytes = ivm_abi::arguments::encode_argument_record_from_json(
            &argument_schema,
            &iroha_primitives::json::Json::from(
                norito::json::from_str::<norito::json::Value>(&arguments_json)
                    .expect("payload json"),
            ),
        )
        .expect("encode contract arguments");
        let arguments = ContractArgumentRecord::try_new(argument_bytes)
            .expect("bounded contract argument record");
        let contract_address = ContractAddress::derive(
            &ctx.config().network_id,
            &authority,
            1,
            DataSpaceId::UNIVERSAL,
        )
        .expect("derive contract address");
        chain.setup_world_at(2_000, |transaction| {
            let registered_hash = code::register_code_bytes(
                &authority,
                DataSpaceId::UNIVERSAL,
                program.clone(),
                transaction,
            )
            .expect("register contract bytecode");
            assert_eq!(registered_hash, code_hash);
            code::register_manifest(&authority, DataSpaceId::UNIVERSAL, manifest, transaction)
                .expect("register contract manifest");
            transaction
                .world
                .bind_inactive_contract_subject_for_testing(
                    contract_address.clone(),
                    authority.clone(),
                );
            code::activate_instance(
                &authority,
                contract_address.clone(),
                1,
                code_hash,
                transaction,
            )
            .expect("activate contract instance");
            Grant::account_permission(
                iroha::executor_data_model::permission::smart_contract::CanUseContractPermission {
                    contract: contract_address.clone(),
                    permission: "Admin".parse().expect("declared contract permission"),
                },
                authority.clone(),
            )
            .execute(&authority, transaction)
            .expect("grant this instance's exact declared permission");
        });
        let state = chain.state();
        let tx = TransactionBuilder::new(
            ctx.config().network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(DEFAULT_CONTRACT_GAS_LIMIT)),
        )
        .with_executable(Executable::ContractCall(ContractInvocation {
            contract_address: contract_address.clone(),
            expected_code_hash: code_hash,
            entrypoint: "bump".to_owned(),
            arguments: Some(arguments),
        }))
        .sign(authority_key_pair.private_key());
        let overlay =
            iroha_core::pipeline::overlay::build_overlay_for_transaction(&tx, &state.view())
                .expect("overlay");
        assert_eq!(
            output
                .get("queued_instruction_count")
                .and_then(norito::json::Value::as_u64),
            Some(overlay.instruction_count() as u64)
        );
        let expected_queue_json =
            norito::json::to_value(&overlay.instructions().collect::<Vec<_>>())
                .expect("serialize queue");
        assert_eq!(
            output.get("queued_instructions"),
            Some(&expected_queue_json)
        );
        assert_eq!(
            output
                .get("durable_state_mutation_count")
                .and_then(norito::json::Value::as_u64),
            Some(overlay.durable_state_overlay().len() as u64)
        );
        let expected_durable_json = render_durable_state_overlay(overlay.durable_state_overlay())
            .expect("serialize durable overlay");
        let expected_durable = expected_durable_json
            .as_object()
            .expect("live durable overlay object");
        let contract_state_digest =
            hex::encode(iroha_crypto::Hash::new(contract_address.to_string().as_bytes()).as_ref());
        let debug_durable = output
            .get("durable_state_overlay")
            .and_then(norito::json::Value::as_object)
            .expect("debug durable overlay object");
        let (logical_key, debug_value) = debug_durable
            .iter()
            .next()
            .expect("one local durable-state mutation");
        assert_eq!(debug_durable.len(), 1);
        let scoped_key = format!("sc/{contract_state_digest}/{logical_key}");
        assert_eq!(
            Some(debug_value),
            expected_durable.get(&scoped_key),
            "local logical state must match the live contract-scoped overlay"
        );
        assert_eq!(
            output.get("result").and_then(norito::json::Value::as_str),
            Some("7")
        );
    }
    #[test]
    fn load_contract_payload_value_accepts_inline_json() {
        let payload = load_contract_payload_value(Some(r#"{"amount":7}"#), None).expect("payload");
        let object = payload
            .as_ref()
            .and_then(norito::json::Value::as_object)
            .expect("payload object");
        assert_eq!(
            object.get("amount").and_then(norito::json::Value::as_i64),
            Some(7)
        );
    }
    #[test]
    fn debug_durable_state_fixture_enforces_canonical_state_path_boundaries() {
        let maximum = "x".repeat(iroha_model_base::state_path::MAX_STATE_PATH_BYTES);
        let fixture = format!(r#"{{"{maximum}":"0x00"}}"#);
        let state = parse_debug_durable_state_fixture(&fixture).expect("maximum StatePath fixture");
        assert_eq!(
            state.keys().next().map(|path| path.as_ref()),
            Some(maximum.as_str())
        );
        let oversized = format!("{maximum}x");
        let fixture = format!(r#"{{"{oversized}":"0x00"}}"#);
        let error = parse_debug_durable_state_fixture(&fixture)
            .expect_err("oversized StatePath fixture must fail");
        assert!(error.to_string().contains("invalid durable state key"));
        let composed = parse_debug_durable_state_fixture(r#"{"root/é":"0x0102"}"#)
            .expect("exact NFC state key");
        assert_eq!(composed.len(), 1);
        let (path, bytes) = composed.iter().next().expect("one exact NFC state key");
        assert_eq!(path.as_ref(), "root/é");
        assert_eq!(bytes.as_slice(), &[0x01, 0x02]);
        for fixture in [
            r#"{"root/e\u0301":"0x01"}"#,
            r#"{"root/e\u0301":"0x01","root/é":"0x02"}"#,
        ] {
            let error = parse_debug_durable_state_fixture(fixture)
                .expect_err("alternate NFC spelling must fail before state insertion");
            assert_eq!(
                error.to_string(),
                "invalid durable state key `root/e\u{301}`: StatePath must already use the exact NFC spelling",
                "unexpected rejection stage for {fixture}"
            );
        }
        for duplicate in [
            r#"{"root/é":"0x01","root/é":"0x02"}"#,
            r#"{"root/é":"0x01","root/\u00e9":"0x02"}"#,
        ] {
            let error = parse_debug_durable_state_fixture(duplicate)
                .expect_err("duplicate decoded JSON state keys must not overwrite");
            assert_eq!(error.to_string(), "invalid durable state fixture JSON");
            assert!(
                matches!(
                    error.downcast_ref::<norito::json::Error>(),
                    Some(norito::json::Error::DuplicateField { field }) if field == "root/é"
                ),
                "the JSON decoder must reject the exact duplicate key: {error:?}"
            );
        }
    }
    #[test]
    fn load_contract_payload_value_accepts_json_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payload.json");
        std::fs::write(&path, r#"{"entrypoint":"mirror_state"}"#).expect("write payload");
        let payload = load_contract_payload_value(None, Some(&path)).expect("payload from file");
        let object = payload
            .as_ref()
            .and_then(norito::json::Value::as_object)
            .expect("payload object");
        assert_eq!(
            object
                .get("entrypoint")
                .and_then(norito::json::Value::as_str),
            Some("mirror_state")
        );
    }
    #[test]
    fn load_contract_payload_value_rejects_invalid_json_and_conflicting_sources() {
        let err = load_contract_payload_value(Some("{"), None)
            .expect_err("malformed inline payload must fail");
        assert!(
            format!("{err:?}").contains("invalid --args"),
            "unexpected error: {err:?}"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("payload.json");
        std::fs::write(&path, "{").expect("write malformed payload");
        let err = load_contract_payload_value(None, Some(&path))
            .expect_err("malformed payload file must fail");
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("invalid JSON in") && rendered.contains("payload.json"),
            "unexpected error: {rendered}"
        );
        let missing_path = dir.path().join("missing.json");
        let err = load_contract_payload_value(None, Some(&missing_path))
            .expect_err("missing payload file must fail");
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("read") && rendered.contains("missing.json"),
            "unexpected error: {rendered}"
        );
        let err = load_contract_payload_value(Some("{}"), Some(&path))
            .expect_err("dual payload sources must fail");
        assert!(
            err.to_string()
                .contains("--args and --args-file are mutually exclusive"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn resolve_contract_target_accepts_contract_address() {
        let authority = fixture_account(0x41);
        let contract_address = iroha::data_model::smart_contract::ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &authority,
            1,
            iroha_model_base::topology::DataSpaceId::new(0),
        )
        .expect("contract address");
        let resolved = resolve_contract_target(ContractTargetArgs {
            contract_address: Some(contract_address.to_string()),
            contract_alias: None,
        })
        .expect("resolved target");
        assert_eq!(resolved.contract_address, Some(contract_address));
        assert!(resolved.contract_alias.is_none());
    }
    #[test]
    fn resolve_contract_target_accepts_contract_alias() {
        let resolved = resolve_contract_target(ContractTargetArgs {
            contract_address: None,
            contract_alias: Some("router::dex.universal".to_owned()),
        })
        .expect("resolved target");
        assert_eq!(
            resolved
                .contract_alias
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("router::dex.universal")
        );
        assert!(resolved.contract_address.is_none());
    }
    #[test]
    fn resolve_contract_target_rejects_missing_target() {
        let err = resolve_contract_target(ContractTargetArgs {
            contract_address: None,
            contract_alias: None,
        })
        .expect_err("missing target should fail");
        assert!(err.to_string().contains(
            "provide exactly one contract target via --contract-address or --contract-alias"
        ));
    }
    #[test]
    fn resolve_contract_dataspace_id_hint_accepts_default_aliases() {
        assert_eq!(
            resolve_contract_dataspace_id_hint("universal", None)
                .expect("universal")
                .as_u64(),
            0
        );
        assert_eq!(
            resolve_contract_dataspace_id_hint("governance", None)
                .expect("governance")
                .as_u64(),
            1
        );
        assert_eq!(
            resolve_contract_dataspace_id_hint("zk", None)
                .expect("zk")
                .as_u64(),
            2
        );
    }
    #[test]
    fn resolve_contract_dataspace_id_hint_requires_override_for_unknown_alias() {
        let err = resolve_contract_dataspace_id_hint("private-ds", None).expect_err("must fail");
        assert!(
            err.to_string()
                .contains("pass --dataspace-id for non-default dataspaces")
        );
    }
    #[test]
    fn resolve_contract_call_private_key_uses_context_key_for_default_authority() {
        let authority = fixture_account(0x51);
        let ctx = TestContext::new(authority.clone());
        let private_key =
            resolve_contract_call_private_key(&ctx, &authority, None, false).expect("key");
        assert_eq!(
            private_key,
            Some(ctx.config().key_pair.private_key().clone())
        );
    }
    #[test]
    fn resolve_contract_call_private_key_rejects_mismatched_authority_without_override() {
        let ctx = TestContext::new(fixture_account(0x52));
        let other_authority = fixture_account(0x53);
        let err = resolve_contract_call_private_key(&ctx, &other_authority, None, false)
            .expect_err("missing override should fail");
        assert!(
            err.to_string()
                .contains("--private-key is required when --authority does not match")
        );
    }
    struct TestContext {
        cfg: iroha::config::Config,
        output: Option<norito::json::Value>,
        i18n: Localizer,
    }
    impl TestContext {
        fn new(account: AccountId) -> Self {
            let key_pair = fixture_key_pair(0xA5);
            let cfg = iroha::config::Config {
                chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
                network_id:
                    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                        .parse()
                        .expect("network id"),
                account,
                account_chain_discriminant:
                    iroha_config::parameters::defaults::common::chain_discriminant(),
                key_pair,
                basic_auth: None,
                api_token: None,
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
                output: None,
                i18n: Localizer::new(Bundle::Cli, Language::English),
            }
        }
        fn take_output(&mut self) -> Option<norito::json::Value> {
            self.output.take()
        }
    }
    impl RunContext for TestContext {
        fn config(&self) -> &iroha::config::Config {
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
        fn print_data<T>(&mut self, data: &T) -> Result<()>
        where
            T: norito::json::JsonSerialize + ?Sized,
        {
            self.output = Some(norito::json::to_value(data)?);
            Ok(())
        }
        fn println(&mut self, _data: impl std::fmt::Display) -> Result<()> {
            Ok(())
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct SimulateArgs {
    /// Authority account identifier for an ABI-bound generic IVM program.
    #[arg(long)]
    pub authority: String,
    /// Hex-encoded private key used to sign the simulated transaction
    #[arg(long, value_name = "HEX")]
    pub private_key: String,
    /// Path to a generic (non-CNTR) compiled `.to` file (mutually exclusive with --code-b64).
    #[arg(long, conflicts_with = "code_b64")]
    pub code_file: Option<PathBuf>,
    /// Base64-encoded generic program (mutually exclusive with --code-file).
    #[arg(long, conflicts_with = "code_file")]
    pub code_b64: Option<String>,
    /// Required executable gas bound in the typed fee payment intent.
    #[arg(long)]
    pub gas_limit: u64,
}
impl Run for SimulateArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let authority = crate::resolve_account_id(context, &self.authority)
            .wrap_err("failed to resolve --authority")?;
        let private_key: PrivateKey = self.private_key.parse().wrap_err("invalid --private-key")?;
        let code = load_code_bytes(self.code_file.clone(), self.code_b64.clone())?;
        let summary = match iroha_core::smartcontracts::ivm::cache::IvmCache::new()
            .summarize_executable(&code)
            .map_err(|err| eyre!("failed to prepare IVM program: {err}"))?
        {
            iroha_core::smartcontracts::ivm::cache::ExecutableProgramSummary::Generic(summary) => {
                summary
            }
            iroha_core::smartcontracts::ivm::cache::ExecutableProgramSummary::Contract(_) => {
                return Err(eyre!(
                    "`contract simulate` accepts only generic IVM programs; use `contract call --simulate` for a live deployed contract or `contract debug-call` for a local CNTR artifact"
                ));
            }
        };
        let gas_limit = NonZeroU64::new(self.gas_limit)
            .ok_or_else(|| eyre!("--gas-limit must be greater than zero"))?;
        let metadata = Metadata::default();
        let tx = TransactionBuilder::new(
            context.config().network_id,
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), Some(gas_limit)),
        )
        .with_metadata(metadata.clone())
        .with_executable(Executable::Ivm(IvmBytecode::from_compiled(code.clone())))
        .try_sign(&private_key)
        .wrap_err("sign simulated contract transaction failed")?;
        let decoded = ivm::ivm_cache::IvmCache::decode_stream(&code[summary.code_offset..])
            .map_err(|err| eyre!("instruction decode failed: {err}"))?;
        let decoded_bytes =
            u64::try_from(code.len().saturating_sub(summary.code_offset)).unwrap_or(u64::MAX);
        let overlay =
            build_overlay_for_transaction_with_accounts(&tx, std::slice::from_ref(&authority))
                .map_err(|err| eyre!("simulation overlay failed: {err}"))?;
        let instruction_ids: Vec<String> =
            overlay.instructions().map(|i| i.id().to_string()).collect();
        let metadata_keys: Vec<String> = metadata
            .iter()
            .map(|(name, _)| name.as_ref().to_string())
            .collect();
        let mut summary_json = norito::json::Map::new();
        summary_json.insert(
            "code_hash_hex".to_string(),
            norito::json::to_value(&hex::encode(summary.code_hash.as_ref()))?,
        );
        summary_json.insert(
            "abi_hash_hex".to_string(),
            norito::json::to_value(&hex::encode(summary.abi_hash.as_ref()))?,
        );
        summary_json.insert(
            "abi_version".to_string(),
            norito::json::to_value(&summary.metadata.abi_version)?,
        );
        summary_json.insert(
            "max_cycles".to_string(),
            norito::json::to_value(&summary.metadata.max_cycles)?,
        );
        summary_json.insert(
            "decoded_instructions".to_string(),
            norito::json::to_value(&decoded.len())?,
        );
        summary_json.insert(
            "decoded_code_bytes".to_string(),
            norito::json::to_value(&decoded_bytes)?,
        );
        summary_json.insert(
            "queued_instruction_count".to_string(),
            norito::json::to_value(&overlay.instruction_count())?,
        );
        summary_json.insert(
            "instruction_ids".to_string(),
            norito::json::to_value(&instruction_ids)?,
        );
        summary_json.insert(
            "metadata_keys".to_string(),
            norito::json::to_value(&metadata_keys)?,
        );
        summary_json.insert(
            "fee_gas_limit".to_string(),
            norito::json::to_value(&gas_limit.get())?,
        );
        let summary_json = norito::json::Value::Object(summary_json);
        context.print_data(&summary_json)?;
        Ok(())
    }
}
// Unified Manifest handling supersedes earlier subcommands
#[derive(clap::Args, Debug)]
pub struct ManifestArgs {
    /// Exact artifact dataspace identifier (zero selects the universal dataspace).
    #[arg(long)]
    pub dataspace_id: u64,
    /// Hex-encoded 32-byte code hash (0x optional)
    #[arg(long, value_name = "HEX64")]
    pub code_hash: String,
    /// Optional output path; if provided, writes JSON manifest to file, otherwise prints to stdout
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}
impl Run for ManifestArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let artifact_id = contract_artifact_id(self.dataspace_id, &self.code_hash)?;
        let v = client.get_contract_manifest_json(&artifact_id)?;
        if let Some(p) = self.out {
            let s = norito::json::to_json_pretty(&v)?;
            std::fs::write(&p, s.as_bytes())?;
            context.println(format_args!("Wrote manifest to {}", p.display()))?;
        } else {
            context.print_data(&v)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod manifest_publication_tests {
    use super::write_manifest_output;

    #[test]
    fn manifest_publication_is_private_atomic_and_replaces_only_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        write_manifest_output(&path, b"first").unwrap();
        assert_eq!(&*iroha_fs::read_private(&path, 32).unwrap(), b"first");
        write_manifest_output(&path, b"second").unwrap();
        assert_eq!(&*iroha_fs::read_private(&path, 32).unwrap(), b"second");
        let non_file = directory.path().join("directory");
        std::fs::create_dir(&non_file).unwrap();
        assert!(write_manifest_output(&non_file, b"rejected").is_err());
        assert!(non_file.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn manifest_publication_rejects_symlink_output() {
        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim.json");
        std::fs::write(&victim, b"unchanged").unwrap();
        let output = directory.path().join("manifest.json");
        std::os::unix::fs::symlink(&victim, &output).unwrap();
        assert!(write_manifest_output(&output, b"rejected").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"unchanged");
    }
}
