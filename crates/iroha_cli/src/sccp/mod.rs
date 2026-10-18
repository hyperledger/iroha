//! `iroha sccp`: SCCP v1 reads, outbound transfers and proofs (`specs/sccp.md` §6, §7.1, §8).
//!
//! Reads come from one Taira peer's public API and are untrusted: proof bundles are verified by
//! the destination (and by the wallet flows) before use. `send` records an outbound transfer
//! from the configured account after checking the route (§7.1 steps 1–2), then finds the
//! committed record by the revision's nonce (the `message_id` depends on the nonce and deadline
//! assigned at execution) and prints it. `status` shows the status union of any message id and
//! `recent` the newest records.
//!
//! `finalize`, `committee-sync` and `deploy` act on every destination: the Solidity deployments
//! (Ethereum and BSC over JSON-RPC, signed with an owner-only secp256k1 key file) and the TON
//! minter (over ADNL liteservers, sent from the user's `v5r1` wallet with an owner-only Ed25519
//! key file). They read the deployment's committee state, verify Taira's bundle or rotation chain
//! locally and submit the destination call. `deploy` additionally requires an independently
//! selected signed genesis, verifier key/hash and manifest, plus `--at-height`, a complete
//! `--world-snapshot` and its independently selected `--world-schema-hash`. Contiguous native
//! certificates authenticate that cut; exact World preimages authenticate the deployment pin.
//! This does not bypass Parliament registration or the separately enforced launch gates.
//!
//! `claim`, `light-client advance` and `light-client bootstrap build` build Ethereum, BSC and TON light-client evidence
//! from the source chain's public RPC (for Ethereum also a beacon light-client API, for TON ADNL
//! liteservers) through the shared
//! `iroha_sccp_rpc::builders::SourceChainBuilder` entry points. `claim` lets the builder pick the
//! proof's anchor from Taira's light client (§4.13.5), verifies the evidence locally against it
//! and submits any `Backfill` advances the anchor needs first. `--self-claim` retains one
//! recipient transaction with optional bare registration and bounded, locally verified
//! catch-up/backfill prerequisites; paid relayers submit backfills separately.
//! `light-client advance` steps a light client that is far behind; run it until it has caught up.
//!
//! Native validator keys follow the consensus key lifecycle; SCCP has no separate bridge keys.

mod administration;
mod deployment;
mod evidence;
mod evm;
mod fast_pause;
mod finalization;
mod flows;
mod governance;
mod light_client;
mod monitor;
mod native_receipt;
mod origin;
mod recipient_claim;
mod reconcile;
mod record;
mod recovery;
mod ton;
mod ton_state;
mod transfers;

use eyre::{Result, WrapErr as _, eyre};
use iroha::{
    blocking::Client as BlockingClient,
    client::sccp::{SccpDirection, SccpFinalityAt, SccpProofHeightV1},
    data_model::{
        bridge::SccpNetworkV1,
        isi::{InstructionBox, sccp::RecordSccpMessage},
        sccp::{
            light_client::{SccpLcCheckpointV1, SccpLcConsensusSetV1, SccpLightClientV1},
            registry::SccpRouteActivationV1,
        },
    },
};
use iroha_primitives::numeric::Numeric;
use iroha_sccp_rpc::builders::{
    AdvanceBudgetV1, BuildError, LightClientReplayV1, SourceChainBuilder, SourceEventRefV1,
    SourceEvidenceV1, TairaLightClientView,
};
use iroha_sccp_wallet::journal::SccpEvidenceItemV1;

use crate::{Run, RunContext};

/// Original anchor lookup selector.
#[derive(clap::Args, Debug)]
pub struct AnchorArgs {
    /// Nonzero committed Taira height; the open chunk needs no witness path.
    pub height: std::num::NonZeroU64,
}

/// `iroha sccp` subcommands.
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Show the Taira identity, SCCP parameters and native finality metadata.
    Info,
    /// List the routes with their revisions, escrows and liabilities.
    Routes,
    /// Inspect held revisions or prove an authenticated forged destination mint.
    #[command(subcommand)]
    Reconcile(reconcile::Command),
    /// Inspect standing pause panels, retained rounds and current eligibility availability.
    #[command(subcommand)]
    FastPause(fast_pause::Command),
    /// Build, submit and inspect original-root forgery evidence.
    #[command(subcommand)]
    Evidence(evidence::Command),
    /// Compare bounded pinned destination observations and build original-root evidence.
    Monitor(monitor::Args),
    /// Record an outbound transfer from the configured account and print its record.
    Send(SendArgs),
    /// Burn destination tokens for a canonical Taira recipient.
    Burn(transfers::BurnArgs),
    /// Retry an admitted inbound settlement.
    Settle(transfers::SettleArgs),
    /// Permanently void an expired or frozen outbound message.
    Void(transfers::VoidArgs),
    /// Prove a destination void or retry its Taira refund.
    Refund(transfers::RefundArgs),
    /// Fund an existing TON recovery operation without replaying the original transfer.
    TonRetry(recovery::Args),
    /// Show the status of one message id (outbound, inbound or unknown).
    Status(MessageArgs),
    /// List the newest outbound or inbound records.
    Recent(RecentArgs),
    /// Fetch the native certificate proof bundle of one outbound message.
    Proof(ProofArgs),
    /// Show a committee generation (the current one by default).
    Committee(CommitteeArgs),
    /// Fetch an original native finality certificate at a height or the durable tip.
    Finality(FinalityArgs),
    /// Fetch the catch-up rotation chain from a generation.
    Rotations(RotationsArgs),
    /// Apply a certified destination control.
    #[command(subcommand)]
    Control(administration::ControlCommand),
    /// Verify a registered deployment against the independently authenticated route.
    #[command(subcommand)]
    Deployment(administration::DeploymentCommand),
    /// Mint a certified outbound message on its EVM or TON destination.
    Finalize(FinalizeArgs),
    /// Advance an EVM or TON committee by at most sixteen generations; rerun after confirmation.
    CommitteeSync(CommitteeSyncArgs),
    /// SCCP proposals to the SORA Parliament.
    #[command(subcommand)]
    Governance(governance::Command),
    /// Deploy an EVM or TON destination pinned to a Taira generation and print its
    /// `RegisterRoute`.
    Deploy(DeployArgs),
    /// Prove an Ethereum or BSC (`transferToTaira`) or TON (`sccp_burn_to_taira`) burn on
    /// Taira and settle it, submitting the `Backfill` advances an aged burn needs first.
    Claim(ClaimArgs),
    /// Advance Taira's Ethereum, BSC or TON light client toward the latest finality, one
    /// bounded step per run.
    #[command(subcommand)]
    LightClient(light_client::Command),
    /// Build the Parliament `ActivateLightClientProfile` action of a profile version compiled
    /// into this release.
    LcProfile(LcProfileArgs),
}

/// Arguments of `iroha sccp claim`.
#[derive(clap::Args, Debug)]
pub struct ClaimArgs {
    /// Durable transfer identity and exact-byte recovery choice.
    #[command(flatten)]
    flow: flows::FlowArgs,
    /// Original authority and complete certified World snapshot for the source route.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// Source network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// Burn transaction: EVM `transferToTaira` tx hash, or TON `<lt>:<hash>` of the minter
    /// transaction that emitted `sccp_transfer_to_taira`.
    #[arg(long)]
    pub tx_hash: String,
    /// Comma-separated source endpoints (EVM) or liteservers (TON); omit for the configured list.
    #[arg(long, default_value = "")]
    pub rpc_url: String,
    /// Comma-separated Beacon API endpoints (Ethereum); omit for the configured list.
    #[arg(long)]
    pub beacon_url: Option<String>,
    /// Submit one recipient-owned exempt bundle, including all proof prerequisites.
    #[arg(long)]
    pub self_claim: bool,
    /// Include bare registration of the configured recipient before its first claim.
    #[arg(long, requires = "self_claim")]
    pub register_self: bool,
    /// Maximum catch-up and backfill instructions in one self-claim; larger catch-up needs a keeper.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub max_advances: u16,
}

/// Arguments of `iroha sccp light-client advance`.
#[derive(clap::Args, Debug)]
pub struct LcAdvanceArgs {
    /// Source network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// Comma-separated source endpoints (EVM) or liteservers (TON); omit for the configured list.
    #[arg(long, default_value = "")]
    pub rpc_url: String,
    /// Comma-separated Beacon API endpoints (Ethereum); omit for the configured list.
    #[arg(long)]
    pub beacon_url: Option<String>,
}

/// Arguments of `iroha sccp light-client bootstrap build`.
#[derive(clap::Args, Debug)]
pub struct LcBootstrapArgs {
    /// Source network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// Comma-separated source endpoints (EVM) or liteservers (TON); omit for the configured list.
    #[arg(long, default_value = "")]
    pub rpc_url: String,
    /// Comma-separated Beacon API endpoints (Ethereum); omit for the configured list.
    #[arg(long)]
    pub beacon_url: Option<String>,
    /// Re-initialize a frozen or aged light client instead of installing a first one.
    #[arg(long)]
    pub reinitialize: bool,
}

/// Arguments of `iroha sccp lc-profile`.
#[derive(clap::Args, Debug)]
pub struct LcProfileArgs {
    /// Source network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// Compiled profile version to activate (default: the newest compiled version).
    #[arg(long)]
    pub version: Option<u32>,
}

/// Arguments of `iroha sccp deploy`.
#[derive(clap::Args, Debug)]
pub struct DeployArgs {
    /// Durable deployment identity and exact original-byte recovery policy.
    #[command(flatten)]
    flow: flows::FlowArgs,
    /// Original authority and complete certified World snapshot for the deployment pin.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// Destination network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// Route revision the deployment serves (the route's next revision).
    #[arg(long)]
    pub revision: u32,
    /// Supply cap in XOR.
    #[arg(long)]
    pub max_supply: String,
    /// Taira committee generation to pin; the current one when absent.
    #[arg(long)]
    pub generation: Option<u64>,
    /// EVM: creation bytecode from `scripts/contract_artifact_corridor.py build` (hex text); it
    /// must match the locked artifact.
    #[arg(long)]
    pub creation_bytecode: Option<std::path::PathBuf>,
    /// TON: the Acton build directory holding `SccpTairaXorMinter.json`,
    /// `SccpTairaXorWallet.json` and `SccpConsumedBucket.json`.
    #[arg(long)]
    pub ton_build_dir: Option<std::path::PathBuf>,
    /// JSON-RPC endpoint (EVM), or comma-separated `<ip>:<port>:<base64 key>` liteservers (TON;
    /// empty for the compiled list).
    #[arg(long, default_value = "")]
    pub rpc_url: String,
    /// Owner-only key file of the deploying account (secp256k1; TON: the Ed25519 seed of the
    /// wallet).
    #[arg(long)]
    pub key_file: std::path::PathBuf,
    /// TON: the raw `0:<hex>` address of the deployed `v5r1` wallet the key file controls. It
    /// funds the minter with `MINTER_FLOOR` at mainnet storage prices plus 25% and initialization headroom.
    #[arg(long)]
    pub ton_wallet: Option<String>,
}

/// Locked `SccpTairaXor` artifacts (`scripts/contract_tooling/artifact-lock.json`).
const ARTIFACT_LOCK: &str = include_str!("../../../../scripts/contract_tooling/artifact-lock.json");

/// The locked keccak-256 of the `SccpTairaXor` creation bytecode (the lock's `evm` target).
fn locked_creation_keccak() -> Result<[u8; 32]> {
    let lock: norito::json::Value =
        norito::json::from_str(ARTIFACT_LOCK).map_err(|error| eyre!("artifact lock: {error}"))?;
    let text = lock
        .get("targets")
        .and_then(|targets| targets.get("evm"))
        .and_then(|evm| evm.get("contracts"))
        .and_then(|contracts| contracts.get("contracts/evm/sccp/SccpTairaXor.sol:SccpTairaXor"))
        .and_then(|contract| contract.get("creation_bytecode_keccak256_hex"))
        .and_then(norito::json::Value::as_str)
        .ok_or_else(|| eyre!("the artifact lock has no SccpTairaXor creation hash"))?;
    parse_word(text)
}

/// Read creation bytecode hex text and check it against the lock.
fn locked_creation_bytecode(path: &std::path::Path) -> Result<Vec<u8>> {
    let text =
        std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
    let text = text.trim();
    let bytecode = hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .wrap_err("creation bytecode is not hex")?;
    if iroha_sccp::v1::hashes::keccak256(&[&bytecode]) != locked_creation_keccak()? {
        return Err(eyre!(
            "the creation bytecode differs from the locked SccpTairaXor artifact"
        ));
    }
    Ok(bytecode)
}

/// Arguments of `iroha sccp finalize`.
#[derive(clap::Args, Debug)]
pub struct FinalizeArgs {
    /// Durable transfer identity and exact-byte recovery choice.
    #[command(flatten)]
    flow: flows::FlowArgs,
    /// Original authority and complete certified World snapshot for the destination route.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// Message id (32-byte hex).
    #[arg(long)]
    pub message_id: String,
    /// JSON-RPC endpoint (EVM), or comma-separated liteservers (TON; empty for the compiled
    /// list).
    #[arg(long, default_value = "")]
    pub rpc_url: String,
    /// Owner-only key file of the account that pays for the call (secp256k1; TON: the Ed25519
    /// seed of the wallet).
    #[arg(long, required_unless_present = "emit", conflicts_with = "emit")]
    pub key_file: Option<std::path::PathBuf>,
    /// Export an unsigned request for an external signer without signing or broadcasting.
    #[arg(long, conflicts_with_all = ["rebroadcast", "retry"])]
    pub emit: bool,
    /// EVM external fee payer address, required for unsigned export.
    #[arg(long, requires = "emit")]
    pub payer: Option<String>,
    /// TON: the raw `0:<hex>` address of the deployed `v5r1` wallet the key file controls.
    #[arg(long)]
    pub ton_wallet: Option<String>,
    /// Proof height: `record`, `latest` or a positive Taira height.
    #[arg(long, default_value = "record")]
    pub at: String,
}

/// Arguments of `iroha sccp committee-sync`.
#[derive(clap::Args, Debug)]
pub struct CommitteeSyncArgs {
    /// Original signed custody and exact-byte recovery policy.
    #[command(flatten)]
    flow: flows::FlowArgs,

    /// Original authority and complete certified World snapshot for the destination route.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// External network of the deployment.
    #[arg(long)]
    pub network: String,
    /// Route revision of the deployment; defaults to the route's live revision.
    #[arg(long)]
    pub revision: Option<u32>,
    /// JSON-RPC endpoint (EVM), or comma-separated liteservers (TON; empty for the compiled
    /// list).
    #[arg(long, default_value = "")]
    pub rpc_url: String,
    /// Owner-only key file of the account that pays for the calls (secp256k1; TON: the Ed25519
    /// seed of the wallet).
    #[arg(long)]
    pub key_file: std::path::PathBuf,
    /// TON: the raw `0:<hex>` address of the deployed `v5r1` wallet the key file controls.
    #[arg(long)]
    pub ton_wallet: Option<String>,
}

/// Arguments of `iroha sccp send`.
#[derive(clap::Args, Debug)]
pub struct SendArgs {
    /// Original signed genesis and complete certified source World cut.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// EVM JSON-RPC endpoint or TON liteserver list for the registered destination.
    #[arg(long, default_value = "")]
    rpc_url: String,
    /// Expected inclusion latency, added to twice the protocol maximum clock-drift bound.
    #[arg(long, default_value_t = 60_000, value_parser = clap::value_parser!(u64).range(1..))]
    inclusion_margin_ms: u64,
    /// Durable transfer identity and exact-byte recovery choice.
    #[command(flatten)]
    flow: flows::FlowArgs,
    /// External target network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// XOR amount, for example `1.5`.
    #[arg(long)]
    pub amount: String,
    /// Recipient on the target: `0x`-hex (EVM, 20 bytes) or `0:<64 hex>` (TON raw address).
    #[arg(long)]
    pub recipient: String,
    /// Route revision to record on; defaults to the route's `Bidirectional` revision.
    #[arg(long)]
    pub revision: Option<u32>,
}

/// Arguments of `iroha sccp recent`.
#[derive(clap::Args, Debug)]
pub struct RecentArgs {
    /// `outbound` (Taira → external) or `inbound` (external → Taira).
    #[arg(long, default_value = "outbound")]
    pub direction: String,
    /// Only this external network.
    #[arg(long)]
    pub network: Option<String>,
    /// `next_before` cursor of the previous page.
    #[arg(long)]
    pub before: Option<String>,
    /// Records per page (at most 50).
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

/// Arguments naming one message.
#[derive(clap::Args, Debug)]
pub struct MessageArgs {
    /// Message id (32-byte hex).
    #[arg(long)]
    pub message_id: String,
}

/// Arguments of `iroha sccp proof`.
#[derive(clap::Args, Debug)]
pub struct ProofArgs {
    /// Message id (32-byte hex).
    #[arg(long)]
    pub message_id: String,
    /// Proof height: `record`, `latest` or a positive Taira height.
    #[arg(long, default_value = "record")]
    pub at: String,
}

/// Arguments of `iroha sccp committee`.
#[derive(clap::Args, Debug)]
pub struct CommitteeArgs {
    /// Positive generation; the current one when absent.
    #[arg(long)]
    pub generation: Option<std::num::NonZeroU64>,
}

/// Arguments of `iroha sccp finality`.
#[derive(clap::Args, Debug)]
pub struct FinalityArgs {
    /// Positive certified height; the durable tip when absent.
    #[arg(long)]
    pub height: Option<std::num::NonZeroU64>,
}

/// Arguments of `iroha sccp rotations`.
#[derive(clap::Args, Debug)]
pub struct RotationsArgs {
    /// Generation the destination currently trusts.
    #[arg(long)]
    pub after_generation: u64,
    /// Steps per page (at most 16).
    #[arg(long, default_value_t = 16)]
    pub limit: usize,
}

/// Parse an external network profile key.
pub fn parse_network(text: &str) -> Result<SccpNetworkV1> {
    SccpNetworkV1::from_profile_key(text)
        .filter(|network| network.is_external())
        .ok_or_else(|| eyre!("`{text}` is not an external SCCP network profile"))
}

/// Parse a 32-byte hex identifier (optional `0x`).
pub fn parse_word(text: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(text.strip_prefix("0x").unwrap_or(text)).wrap_err("identifier is not hex")?;
    <[u8; 32]>::try_from(bytes).map_err(|_| eyre!("identifier must be 32 bytes"))
}

/// Parse a `recent` direction.
pub fn parse_direction(text: &str) -> Result<SccpDirection> {
    match text {
        "outbound" => Ok(SccpDirection::Outbound),
        "inbound" => Ok(SccpDirection::Inbound),
        _ => Err(eyre!("direction must be `outbound` or `inbound`")),
    }
}

/// Parse only the shared current proof-height selector.
pub fn parse_proof_height(text: &str) -> Result<SccpProofHeightV1> {
    text.parse().map_err(|error| eyre!("proof height: {error}"))
}

/// Encode `text` as the target network's recipient bytes (§3.1).
pub fn parse_recipient(network: SccpNetworkV1, text: &str) -> Result<Vec<u8>> {
    let bytes = if network == SccpNetworkV1::TonMainnet {
        let account = text
            .strip_prefix("0:")
            .ok_or_else(|| eyre!("a TON recipient is a raw `0:<64 hex>` address"))?;
        let id = hex::decode(account).wrap_err("TON account id is not hex")?;
        let mut bytes = vec![0_u8; 4];
        bytes.extend(id);
        bytes
    } else {
        hex::decode(text.strip_prefix("0x").unwrap_or(text)).wrap_err("recipient is not hex")?
    };
    let codec = iroha_sccp::v1::network::account_codec(network);
    if !iroha_sccp::v1::payload::is_valid_account(codec, &bytes) {
        return Err(eyre!(
            "recipient is not a valid {} account",
            network.profile_key()
        ));
    }
    Ok(bytes)
}

/// This machine's Unix time in milliseconds.
fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn blocking<C: RunContext>(context: &C) -> Result<BlockingClient> {
    BlockingClient::from_client(context.client_from_config()?)
}

impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Info => {
                let capabilities = blocking(context)?.sccp().capabilities()?;
                context.print_data(&capabilities)
            }
            Self::Routes => {
                let routes = blocking(context)?.sccp().registry()?;
                context.print_data(&routes)
            }
            Self::Reconcile(command) => command.run(context),
            Self::FastPause(command) => command.run(context),
            Self::Evidence(command) => command.run(context),
            Self::Monitor(args) => args.run(context),
            Self::Send(args) => send(context, &args),
            Self::Burn(args) => transfers::burn(context, &args),
            Self::Settle(args) => transfers::settle(context, &args),
            Self::Void(args) => transfers::void(context, &args),
            Self::Refund(args) => transfers::refund(context, args),
            Self::TonRetry(args) => recovery::run(context, &args),
            Self::Status(args) => {
                let status = blocking(context)?
                    .sccp()
                    .message(&parse_word(&args.message_id)?)?;
                context.print_data(&status)
            }
            Self::Recent(args) => {
                let network = args.network.as_deref().map(parse_network).transpose()?;
                let page = blocking(context)?.sccp().recent_messages(
                    parse_direction(&args.direction)?,
                    network,
                    args.before.as_deref(),
                    args.limit,
                )?;
                context.print_data(&page)
            }
            Self::Proof(args) => {
                let bundle = blocking(context)?.sccp().message_proof(
                    &parse_word(&args.message_id)?,
                    parse_proof_height(&args.at)?,
                )?;
                context.print_data(&bundle)
            }
            Self::Committee(args) => {
                let client = blocking(context)?;
                let committee = match args.generation {
                    Some(generation) => client.sccp().committee(generation.get())?,
                    None => client.sccp().current_committee()?,
                };
                context.print_data(&committee)
            }
            Self::Finality(args) => {
                let certificate = blocking(context)?.sccp().finality(
                    args.height
                        .map_or(SccpFinalityAt::Latest, SccpFinalityAt::Height),
                )?;
                context.print_data(&certificate)
            }
            Self::Rotations(args) => {
                let chain = blocking(context)?
                    .sccp()
                    .rotations(args.after_generation, args.limit)?;
                context.print_data(&chain)
            }
            Self::Control(command) => command.run(context),
            Self::Deployment(command) => command.run(context),
            Self::Finalize(args) => finalize(context, &args),
            Self::CommitteeSync(args) => committee_sync(context, &args),
            Self::Governance(command) => command.run(context),
            Self::Deploy(args) => deploy(context, &args),
            Self::Claim(args) => claim(context, &args),
            Self::LightClient(command) => command.run(context),
            Self::LcProfile(args) => {
                let action = lc_profile_action(parse_network(&args.network)?, args.version)?;
                context.print_data(&vec![action])
            }
        }
    }
}

/// The deployment and destination identity of `(network, revision)` from Taira's registry (the
/// live revision when `revision` is `None`).
fn route_deployment(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    network: SccpNetworkV1,
    revision: Option<u32>,
) -> Result<(
    iroha::data_model::sccp::deployment::SccpDeploymentV1,
    iroha_sccp::v1::proof::DestinationV1,
)> {
    let route = client
        .sccp()
        .registry()?
        .into_iter()
        .find(|route| route.network == network)
        .ok_or_else(|| eyre!("Taira has no route to {}", network.profile_key()))?;
    original.verify_route(network, &route)?;
    let record = match revision {
        Some(revision) => route.revisions.get(&revision),
        None => route
            .revisions
            .values()
            .find(|record| record.activation.is_live()),
    }
    .ok_or_else(|| eyre!("the {} route has no such revision", network.profile_key()))?;
    Ok((
        record.deployment,
        iroha_sccp::v1::proof::DestinationV1 {
            network,
            route_revision: record.revision,
            destination_word: record.destination_word,
        },
    ))
}

/// Connect to the EVM deployment of `(network, revision)` through `rpc_url`.
fn evm_destination(
    config: &iroha_sccp_wallet::config::SccpClientConfig,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    network: SccpNetworkV1,
    revision: Option<u32>,
    rpc_url: &str,
) -> Result<evm::EvmDestination> {
    use iroha::data_model::sccp::deployment::SccpDeploymentV1;
    match route_deployment(client, original, network, revision)? {
        (SccpDeploymentV1::Evm(deployment), destination) => evm::EvmDestination::connect(
            config,
            rpc_url,
            network,
            deployment.address,
            destination,
            deployment.runtime_code_hash,
        ),
        (SccpDeploymentV1::Ton(_), _) => {
            Err(eyre!("{} is a TON destination", network.profile_key()))
        }
    }
}

/// Connect to the TON minter of `(network, revision)` through `liteservers` and load the wallet.
fn ton_destination(
    config: &iroha_sccp_wallet::config::SccpClientConfig,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    (network, revision): (SccpNetworkV1, Option<u32>),
    liteservers: &str,
    wallet: Option<&str>,
    key_file: &std::path::Path,
) -> Result<(ton::TonDestination, ton::TonWallet)> {
    use iroha::data_model::sccp::deployment::SccpDeploymentV1;
    let (SccpDeploymentV1::Ton(deployment), destination) =
        route_deployment(client, original, network, revision)?
    else {
        return Err(eyre!("{} is not a TON destination", network.profile_key()));
    };
    let destination =
        ton::TonDestination::connect(config, liteservers, deployment.master_account, destination)?;
    let wallet = ton::TonWallet::load(
        destination.lite(),
        wallet.ok_or_else(|| eyre!("TON destinations need `--ton-wallet 0:<hex>`"))?,
        key_file,
    )?;
    Ok((destination, wallet))
}

fn require_requested_message(requested: &[u8; 32], returned: &[u8; 32]) -> Result<()> {
    eyre::ensure!(
        requested == returned,
        "proof bundle names a different requested message"
    );
    Ok(())
}

/// `iroha sccp finalize`: verify the bundle against the destination and mint.
fn finalize<C: RunContext>(context: &mut C, args: &FinalizeArgs) -> Result<()> {
    finalization::run(context, args)
}

fn deploy<C: RunContext>(context: &mut C, args: &DeployArgs) -> Result<()> {
    deployment::run(context, args)
}

/// The Ethereum evidence builder over `rpc_url` and `beacon_url`.
fn ethereum_builder(
    config: &iroha_sccp_wallet::config::SccpClientConfig,
    profile: iroha_sccp::light_client::profile::EthereumChainProfileV1,
    rpc_url: &str,
    beacon_url: Option<&str>,
) -> Result<iroha_sccp_rpc::builders::ethereum::EthereumBuilder> {
    use iroha_sccp_rpc::{
        BeaconClient, EndpointSet, FailoverPolicy, HttpEndpointKind, HttpTransport,
    };
    let execution = evm::connect_chain_config(config, rpc_url, SccpNetworkV1::EthereumMainnet)?;
    let endpoints = beacon_url
        .filter(|value| !value.trim().is_empty())
        .map_or_else(
            || config.endpoint_set(HttpEndpointKind::EthereumBeacon),
            |urls| {
                EndpointSet::parse(
                    &urls.split(',').map(str::trim).collect::<Vec<_>>(),
                    &config.secret_headers,
                )
            },
        )
        .map_err(|error| eyre!("beacon endpoints: {error}"))?;
    let transport = HttpTransport::new(endpoints, config.http_config(), FailoverPolicy::default())
        .map_err(|error| eyre!("beacon transport: {error}"))?;
    Ok(iroha_sccp_rpc::builders::ethereum::EthereumBuilder::new(
        profile,
        BeaconClient::new(transport),
        execution,
    ))
}

/// The evidence builder of `network`'s source chain over `rpc_url` (for Ethereum also
/// `beacon_url`).
fn source_builder(
    config: &iroha_sccp_wallet::config::SccpClientConfig,
    profiles: &iroha_sccp::light_client::profile::SccpChainProfilesV1,
    network: SccpNetworkV1,
    rpc_url: &str,
    beacon_url: Option<&str>,
) -> Result<Box<dyn SourceChainBuilder>> {
    use iroha_sccp_rpc::builders::{bsc::BscBuilder, ton::TonBuilder};
    let builder: Box<dyn SourceChainBuilder> = match network {
        SccpNetworkV1::EthereumMainnet => Box::new(ethereum_builder(
            config,
            profiles.ethereum,
            rpc_url,
            beacon_url,
        )?),
        SccpNetworkV1::BscMainnet => Box::new(BscBuilder::new(
            profiles.bsc,
            evm::connect_chain_config(config, rpc_url, network)?,
        )),
        SccpNetworkV1::TonMainnet => Box::new(TonBuilder::new(
            profiles.ton,
            ton::connect_config(config, rpc_url)?,
        )),
        SccpNetworkV1::SoraTaira => {
            return Err(eyre!("{} is not a source chain", network.profile_key()));
        }
    };
    Ok(builder)
}

/// Taira's light client of one network as Torii serves it (§6), read once. The checkpoints the
/// builders look up are kept, so the evidence is verified locally against exactly the data it
/// was built from (§7.2 step 5).
struct ToriiLightClient<'a> {
    original: Option<&'a origin::AuthenticatedOrigin>,
    profiles: iroha_sccp::light_client::profile::SccpChainProfilesV1,
    client: &'a BlockingClient,
    network: SccpNetworkV1,
    light_client: SccpLightClientV1,
    sets: Vec<SccpLcConsensusSetV1>,
    checkpoints: std::cell::RefCell<Vec<SccpLcCheckpointV1>>,
}

impl<'a> ToriiLightClient<'a> {
    /// Read the light client of `network` and its stored sets.
    fn read(
        client: &'a BlockingClient,
        network: SccpNetworkV1,
        profiles: &iroha_sccp::light_client::profile::SccpChainProfilesV1,
    ) -> Result<Self> {
        Ok(Self {
            original: None,
            profiles: *profiles,
            client,
            network,
            light_client: client.sccp().light_client(network)?.light_client,
            sets: client.sccp().light_client_sets(network)?,
            checkpoints: std::cell::RefCell::new(Vec::new()),
        })
    }

    fn authenticated(
        client: &'a BlockingClient,
        original: &'a origin::AuthenticatedOrigin,
        network: SccpNetworkV1,
        profiles: &iroha_sccp::light_client::profile::SccpChainProfilesV1,
    ) -> Result<Self> {
        let mut view = Self::read(client, network, profiles)?;
        original.verify_light_client(network, &view.light_client)?;
        for set in &view.sets {
            original.verify_light_client_set(network, set)?;
        }
        view.original = Some(original);
        Ok(view)
    }

    /// A local replay of what was read.
    fn replay(&self) -> LightClientReplayV1 {
        LightClientReplayV1::new(
            &self.profiles,
            self.network,
            self.light_client,
            self.sets.clone(),
            self.checkpoints.borrow().clone(),
        )
    }

    fn retained_trust(&self, now: u64) -> Result<SccpEvidenceItemV1> {
        let original = self
            .original
            .ok_or_else(|| eyre!("source trust was not authenticated to an original cut"))?;
        retain_source_trust(SourceTrust {
            network: self.network,
            original_cut: original.receipt_cut(),
            verification_time_ms: now,
            light_client: self.light_client,
            sets: self.sets.clone(),
            checkpoints: self.checkpoints.borrow().clone(),
        })
    }
}

/// Original authenticated records sufficient to replay a retained source proof and backfills.
#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SourceTrust {
    network: SccpNetworkV1,
    original_cut: norito::json::Value,
    verification_time_ms: u64,
    light_client: SccpLightClientV1,
    sets: Vec<SccpLcConsensusSetV1>,
    checkpoints: Vec<SccpLcCheckpointV1>,
}

fn retain_source_trust(mut trust: SourceTrust) -> Result<SccpEvidenceItemV1> {
    trust
        .checkpoints
        .sort_by_key(|checkpoint| checkpoint.data.source_height);
    trust.checkpoints.dedup();
    let bytes = norito::json::to_json_bounded_boxed(
        &trust,
        usize::try_from(iroha_sccp_wallet::journal::MAX_RECORD_BYTES)?,
    )
    .map_err(|error| eyre!("source trust exceeds durable evidence bound: {error:?}"))?;
    Ok(SccpEvidenceItemV1 {
        label: "source.original_trust".to_owned(),
        bytes: bytes.into_vec(),
    })
}

impl TairaLightClientView for ToriiLightClient<'_> {
    fn light_client(&self) -> std::result::Result<SccpLightClientV1, BuildError> {
        Ok(self.light_client)
    }

    fn sets(&self) -> std::result::Result<Vec<SccpLcConsensusSetV1>, BuildError> {
        Ok(self.sets.clone())
    }

    fn checkpoint_covering(
        &self,
        source_height: u64,
    ) -> std::result::Result<Option<SccpLcCheckpointV1>, BuildError> {
        match self
            .client
            .sccp()
            .light_client_checkpoints(self.network, source_height)
        {
            Ok(cover) => {
                let checkpoint = cover.nearest.checkpoint;
                if let Some(original) = self.original {
                    original
                        .verify_light_client_checkpoint(self.network, &checkpoint)
                        .map_err(|error| {
                            BuildError::Inconsistent(format!("original checkpoint: {error}"))
                        })?;
                }
                self.checkpoints.borrow_mut().push(checkpoint);
                Ok(Some(checkpoint))
            }
            // 404: the head is below the height; 410: no checkpoint above it is retained.
            Err(error) if matches!(error.http_status(), Some(404 | 410)) => Ok(None),
            Err(error) => Err(BuildError::Unavailable(format!(
                "reading Taira's checkpoints: {error}"
            ))),
        }
    }
}

/// Build the evidence of `event` against Taira's light client of `network` with the anchor
/// chosen by the builder (§4.13.5), and verify it locally with the verifier Taira runs before
/// anything is paid for (§7.2 step 5).
fn prove(
    profiles: &iroha_sccp::light_client::profile::SccpChainProfilesV1,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    network: SccpNetworkV1,
    builder: &dyn SourceChainBuilder,
    event: &SourceEventRefV1,
) -> Result<(
    SourceEvidenceV1,
    iroha_sccp::light_client::proof::SccpVerifiedProofV1,
    SccpEvidenceItemV1,
)> {
    let view = ToriiLightClient::authenticated(client, original, network, profiles)?;
    let now = original.source_verification_time_ms(wall_clock_ms());
    let evidence = iroha_sccp_rpc::builders::build_verified(
        builder.source_attempts(),
        || builder.evidence(event, &view, now),
        |evidence| view.replay().verify_evidence(evidence, now).map(|_| ()),
        || builder.rotate_endpoints(),
    )?;
    let verified = view.replay().verify_evidence(&evidence, now)?;
    require_ton_reference(event, &evidence)?;
    Ok((evidence, verified, view.retained_trust(now)?))
}

fn require_ton_reference(event: &SourceEventRefV1, evidence: &SourceEvidenceV1) -> Result<()> {
    if let SourceEventRefV1::Ton {
        minter,
        lt,
        hash,
        message_index,
    } = event
    {
        let iroha_sccp::light_client::proof::SccpSourceProofV1::Ton(proof) =
            iroha_sccp::light_client::proof::SccpSourceProofV1::from_frame(
                evidence.proof.as_bytes(),
            )?
        else {
            return Err(eyre!("TON discovery produced another proof type"));
        };
        eyre::ensure!(
            proof.minter == *minter
                && proof.transaction_lt == *lt
                && proof.message_index == *message_index
                && iroha_sccp::ton_canonical_boc_single_root_hash_v1(&proof.transaction)
                    == Some(*hash),
            "authenticated TON transaction differs from the exact discovered original"
        );
    }
    Ok(())
}

/// `iroha sccp claim` for TON: `--tx-hash <lt>:<hash hex>` names the minter transaction whose
/// external message 0 is the `sccp_transfer_to_taira` event; the proof hangs from the burn's own
/// masterchain block, or from a back link of the newest stored epoch once the burn's epoch is
/// stale.
fn ton_claim(
    config: &iroha_sccp_wallet::config::SccpClientConfig,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    args: &ClaimArgs,
) -> Result<(u32, Vec<u8>, recipient_claim::Evidence)> {
    use iroha::data_model::sccp::deployment::SccpDeploymentV1;
    use iroha_sccp::v1::payload::SccpTransferPayloadV1;
    use iroha_sccp_rpc::builders::ton::TonBuilder;
    let (lt, hash) = args
        .tx_hash
        .split_once(':')
        .ok_or_else(|| eyre!("a TON transaction is `<lt>:<hash hex>`"))?;
    let lt: u64 = lt
        .parse()
        .map_err(|_| eyre!("the transaction lt is not a number"))?;
    let hash = parse_word(hash)?;
    let (SccpDeploymentV1::Ton(deployment), destination) =
        route_deployment(client, original, SccpNetworkV1::TonMainnet, None)?
    else {
        return Err(eyre!("the TON route has no TON deployment"));
    };
    let minter = deployment.master_account;
    let profiles = original.light_client_profiles(client)?;
    let builder = TonBuilder::new(profiles.ton, ton::connect_config(config, &args.rpc_url)?);
    let payload = builder
        .transfer_payload(minter, lt, hash, 0)
        .map_err(|error| eyre!("reading the burn: {error}"))?;
    let decoded = SccpTransferPayloadV1::decode(&payload)
        .map_err(|error| eyre!("the burned payload does not decode: {error}"))?;
    require_claim_route(&decoded, destination)?;
    let revision = decoded.route_revision;
    let event = SourceEventRefV1::Ton {
        minter,
        lt,
        hash,
        message_index: 0,
    };
    let evidence = recipient_claim::prove_claim(
        &profiles,
        client,
        original,
        SccpNetworkV1::TonMainnet,
        &builder,
        (&event, &payload),
        if args.self_claim {
            args.max_advances
        } else {
            0
        },
    )?;
    Ok((revision, payload, evidence))
}

/// `iroha sccp claim` for Ethereum and BSC: the payload comes from the receipt's
/// `SccpTransferToTaira` log.
fn evm_claim(
    config: &iroha_sccp_wallet::config::SccpClientConfig,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    network: SccpNetworkV1,
    args: &ClaimArgs,
) -> Result<(u32, Vec<u8>, recipient_claim::Evidence)> {
    use iroha_sccp::v1::{evm_abi::TransferToTairaLogV1, payload::SccpTransferPayloadV1};
    use iroha_sccp_rpc::builders::ethereum::EthereumEventV1;
    let tx_hash = parse_word(&args.tx_hash)?;
    let receipt = evm::connect_chain_config(config, &args.rpc_url, network)?
        .transaction_receipt(&tx_hash)
        .map_err(|error| eyre!("eth_getTransactionReceipt: {error}"))?
        .ok_or_else(|| eyre!("the transaction is not mined"))?;
    let (log_index, emitter, log) = receipt
        .logs
        .iter()
        .enumerate()
        .find_map(|(index, log)| {
            TransferToTairaLogV1::decode(&log.topics, &log.data)
                .ok()
                .map(|decoded| (index, log.address, decoded))
        })
        .ok_or_else(|| eyre!("the transaction emitted no SccpTransferToTaira log"))?;
    let payload = SccpTransferPayloadV1::decode(&log.payload)
        .map_err(|error| eyre!("the burned payload does not decode: {error}"))?;
    let (iroha::data_model::sccp::deployment::SccpDeploymentV1::Evm(deployment), destination) =
        route_deployment(client, original, network, Some(payload.route_revision))?
    else {
        return Err(eyre!("the selected source route has no EVM deployment"));
    };
    eyre::ensure!(
        emitter == deployment.address,
        "the burn event comes from a different registered deployment"
    );
    require_claim_route(&payload, destination)?;
    let event = SourceEventRefV1::Evm {
        tx_hash,
        event: EthereumEventV1::TransferToTaira {
            log_index: u32::try_from(log_index).map_err(|_| eyre!("log index overflows"))?,
        },
    };
    let profiles = original.light_client_profiles(client)?;
    let builder = source_builder(
        config,
        &profiles,
        network,
        &args.rpc_url,
        args.beacon_url.as_deref(),
    )?;
    let evidence = recipient_claim::prove_claim(
        &profiles,
        client,
        original,
        network,
        builder.as_ref(),
        (&event, &log.payload),
        if args.self_claim {
            args.max_advances
        } else {
            0
        },
    )?;
    Ok((payload.route_revision, log.payload, evidence))
}

fn require_claim_route(
    payload: &iroha_sccp::v1::payload::SccpTransferPayloadV1,
    route: iroha_sccp::v1::proof::DestinationV1,
) -> Result<()> {
    eyre::ensure!(
        payload.source() == Some(route.network)
            && payload.target() == Some(SccpNetworkV1::SoraTaira)
            && payload.route_revision == route.route_revision,
        "the burn payload differs from the authenticated source route"
    );
    Ok(())
}

// Keep the ordered intent array explicit: Norito does not implement six-element JSON tuples.
fn claim_intent(
    network: SccpNetworkV1,
    transaction_hash: &str,
    account: &iroha::data_model::account::AccountId,
    self_claim: bool,
    register_self: bool,
    max_advances: u16,
) -> Result<[u8; 32]> {
    use norito::json::{Value, to_value};
    let fields = Value::Array(vec![
        to_value(&network)?,
        to_value(transaction_hash)?,
        to_value(account)?,
        to_value(&self_claim)?,
        to_value(&register_self)?,
        to_value(&max_advances)?,
    ]);
    Ok(flows::intent(&norito::json::to_vec(&fields)?))
}

/// `iroha sccp claim`: prove a source-chain burn and submit `SubmitSccpInboundMessageV1`,
/// using one recipient bundle with `--self-claim`, or separate paid backfills otherwise.
fn claim<C: RunContext>(context: &mut C, args: &ClaimArgs) -> Result<()> {
    use iroha::data_model::isi::sccp::{AdvanceSccpLightClientV1, SubmitSccpInboundMessageV1};
    use iroha_sccp_wallet::{flow::SccpFlowActionV1 as Action, journal::SccpFlowKindV1};
    let network = parse_network(&args.network)?;
    let default_id = claim_intent(
        network,
        &args.tx_hash,
        &context.config().account,
        args.self_claim,
        args.register_self,
        args.max_advances,
    )?;
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args.origin)?;
    let flow = flows::open(context, SccpFlowKindV1::Inbound, &args.flow, default_id)?;
    if flows::recover_taira(context, &original, &flow, Action::ProveInbound)? {
        return Ok(());
    }
    if flows::recover_advance(context, &original, &flow)? {
        return Ok(());
    }
    let config = context.sccp_config()?;
    let (revision, payload, evidence) = if network == SccpNetworkV1::TonMainnet {
        ton_claim(&config, &client, &original, args)?
    } else {
        evm_claim(&config, &client, &original, network, args)?
    };
    let mut raw_evidence = evidence.trust.clone();
    raw_evidence.push(iroha_sccp_wallet::journal::SccpEvidenceItemV1 {
        label: "source.verified_proof".to_owned(),
        bytes: evidence.source.proof.as_bytes().to_vec(),
    });
    if args.self_claim {
        let parameters = original.parameters(&client.sccp().capabilities()?)?;
        recipient_claim::require_recipient(
            &context.config().account,
            &payload,
            parameters.inbound_self_claim_fee,
        )?;
        let instructions = recipient_claim::instructions(
            &context.config().account,
            args.register_self,
            network,
            revision,
            payload,
            evidence,
        )?;
        flows::taira(
            context,
            &original,
            &flow,
            Action::ProveInbound,
            instructions,
            raw_evidence,
        )?;
        return Ok(());
    }
    for advance in evidence.source.backfills {
        let outcome = flows::taira(
            context,
            &original,
            &flow,
            Action::Advance,
            vec![
                AdvanceSccpLightClientV1 {
                    network,
                    expected_state_hash: None,
                    advance,
                }
                .into(),
            ],
            raw_evidence.clone(),
        )?;
        if !flows::confirmed(outcome.as_ref()) {
            return Ok(());
        }
    }
    flows::taira(
        context,
        &original,
        &flow,
        Action::ProveInbound,
        vec![InstructionBox::from(SubmitSccpInboundMessageV1 {
            network,
            revision,
            payload,
            proof: evidence.source.proof,
        })],
        raw_evidence,
    )?;
    Ok(())
}

/// `iroha sccp light-client advance`: advance Taira's light client of a source chain toward its latest
/// finality, stepped to the light client's per-advance bounds; run it again while the light
/// client is still behind.
fn lc_advance<C: RunContext>(context: &mut C, args: &LcAdvanceArgs) -> Result<()> {
    use iroha::data_model::isi::sccp::AdvanceSccpLightClientV1;
    let configuration = context.sccp_config()?;
    let config = &configuration;
    let network = parse_network(&args.network)?;
    let client = blocking(context)?;
    let profiles = light_client::active_profiles(&client, *context.config().network_id.as_bytes())?;
    let view = ToriiLightClient::read(&client, network, &profiles)?;
    let light_client = view.light_client;
    let budget = AdvanceBudgetV1::for_params(&light_client.params, usize::MAX);
    let builder = source_builder(
        config,
        &profiles,
        network,
        &args.rpc_url,
        args.beacon_url.as_deref(),
    )?;
    let now = wall_clock_ms();
    let advance = iroha_sccp_rpc::builders::build_verified(
        builder.source_attempts(),
        || builder.advance(light_client.head.latest_set_id, budget),
        |advance| view.replay().advance(advance, now).map(|_| ()),
        || builder.rotate_endpoints(),
    )?;
    context.finish(vec![InstructionBox::from(AdvanceSccpLightClientV1 {
        network,
        expected_state_hash: Some(light_client.state_hash),
        advance,
    })])
}

/// `iroha sccp light-client bootstrap build`: print the `InitializeLightClient` action of the latest finalized
/// source block with the default params, for `iroha sccp governance propose --actions`.
fn lc_bootstrap<C: RunContext>(context: &mut C, args: &LcBootstrapArgs) -> Result<()> {
    use iroha::data_model::sccp::{
        governance::{SccpGovernanceActionV1, SccpInitializeLightClientActionV1},
        light_client::{SccpLcInitExpectationV1, SccpLightClientParamsV1},
    };
    let configuration = context.sccp_config()?;
    let config = &configuration;
    let network = parse_network(&args.network)?;
    let client = blocking(context)?;
    let profiles = light_client::active_profiles(&client, *context.config().network_id.as_bytes())?;
    let builder = source_builder(
        config,
        &profiles,
        network,
        &args.rpc_url,
        args.beacon_url.as_deref(),
    )?;
    let params = SccpLightClientParamsV1::defaults_for(network)
        .ok_or_else(|| eyre!("{} has no light-client defaults", network.profile_key()))?;
    let now = wall_clock_ms();
    let bootstrap = iroha_sccp_rpc::builders::build_verified(
        builder.source_attempts(),
        || builder.bootstrap(),
        |bootstrap| {
            iroha_sccp::light_client::verify_bootstrap_with_profiles(
                &profiles, network, &params, bootstrap, now,
            )
            .map(|_| ())
        },
        || builder.rotate_endpoints(),
    )?;
    let action = SccpGovernanceActionV1::InitializeLightClient(SccpInitializeLightClientActionV1 {
        network,
        expected: if args.reinitialize {
            SccpLcInitExpectationV1::Unusable
        } else {
            SccpLcInitExpectationV1::Absent
        },
        params,
        bootstrap,
    });
    context.print_data(&vec![action])
}

/// `iroha sccp lc-profile`: the `ActivateLightClientProfile` action of compiled profile
/// `version` of `network` (the newest compiled version by default), carrying the profile hash
/// this release compiles, for `iroha sccp governance propose --actions` (§4.13.2). Reviewers
/// rebuild it with their own release before the vote.
fn lc_profile_action(
    network: SccpNetworkV1,
    version: Option<u32>,
) -> Result<iroha::data_model::sccp::governance::SccpGovernanceActionV1> {
    use iroha::data_model::sccp::governance::{
        SccpActivateLightClientProfileActionV1, SccpGovernanceActionV1,
    };
    use iroha_sccp::light_client::profile::{GENESIS_PROFILE_VERSION, SccpLcProfileCatalogV1};
    let catalog = SccpLcProfileCatalogV1::compiled();
    let version = version.unwrap_or_else(|| catalog.latest_version(network));
    if version <= GENESIS_PROFILE_VERSION {
        return Err(eyre!(
            "{} light-client profile version {version} is active from genesis; this release \
             compiles no later version to activate",
            network.profile_key()
        ));
    }
    let profile_hash = catalog.profile_hash(network, version).ok_or_else(|| {
        eyre!(
            "this release does not compile {} light-client profile version {version}",
            network.profile_key()
        )
    })?;
    Ok(SccpGovernanceActionV1::ActivateLightClientProfile(
        SccpActivateLightClientProfileActionV1 {
            network,
            version,
            profile_hash,
        },
    ))
}

/// Select one bounded catch-up step; untrusted discovery cannot make an ahead destination regress.
fn sync_target(from: u64, current: u64) -> Result<u64> {
    eyre::ensure!(
        from > 0 && current >= from,
        "discovery is older than the destination committee"
    );
    Ok(current
        .min(from.saturating_add(iroha_sccp::v1::destination::MAX_CERTIFICATES_PER_CALL as u64)))
}

/// `iroha sccp committee-sync`: submit one bounded catch-up step, then re-observe on the next run.
fn committee_sync<C: RunContext>(context: &mut C, args: &CommitteeSyncArgs) -> Result<()> {
    finalization::maintain(context, args)
}

/// `iroha sccp send`: check the route (§7.1 steps 1–2) and record the transfer.
fn send<C: RunContext>(context: &mut C, args: &SendArgs) -> Result<()> {
    record::send(context, args)
}

/// The transfer `send` submitted, as its committed record must show it.
struct SentTransfer {
    sender: iroha::data_model::account::AccountId,
    amount: u128,
    recipient: Vec<u8>,
}

impl SentTransfer {
    /// Whether `record` is this transfer: same sender, amount and recipient.
    fn matches(
        &self,
        record: &iroha::data_model::sccp::outbound::SccpOutboundMessageRecordV1,
    ) -> bool {
        record.sender == self.sender
            && record.amount == self.amount
            && iroha_sccp::v1::payload::SccpTransferPayloadV1::decode(&record.payload)
                .is_ok_and(|payload| payload.recipient.bytes == self.recipient)
    }
}

/// Polls of [`locate_sent`] before giving up (one second apart).
const LOCATE_ATTEMPTS: usize = 10;

/// Find the committed record of `sent` among the nonces of `(network, revision)` from
/// `first_nonce` (the revision's next nonce before submission), lowest nonce first.
fn locate_sent(
    client: &BlockingClient,
    step: &iroha_sccp_wallet::journal::SccpJournalStep,
    network: SccpNetworkV1,
    revision: u32,
    first_nonce: u64,
    sent: &SentTransfer,
) -> Result<iroha_sccp::api::SccpOutboundMessageViewV1> {
    for attempt in 0..LOCATE_ATTEMPTS {
        if let Some(view) =
            record::locate_sent_scan(step, network, revision, first_nonce, sent, |from_nonce| {
                Ok(client.sccp().outbound(
                    network,
                    revision,
                    from_nonce,
                    iroha_sccp::api::MAX_OUTBOUND_PAGE,
                )?)
            })?
        {
            return Ok(view);
        }
        if attempt + 1 < LOCATE_ATTEMPTS {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    Err(eyre!(
        "the transaction committed but no {} revision {revision} record from nonce {first_nonce} \
         matches it; rerun the same flow to resume retained discovery",
        network.profile_key()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_intent_binds_each_ordered_recovery_input() {
        use iroha::data_model::account::AccountId;
        use iroha_crypto::{Algorithm, KeyPair};
        let account = AccountId::new(
            KeyPair::from_seed(vec![21; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let other_account = AccountId::new(
            KeyPair::from_seed(vec![22; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let network = SccpNetworkV1::EthereumMainnet;
        let original = claim_intent(network, "transaction", &account, true, true, 4).unwrap();
        let fields = norito::json!([network, "transaction", account, true, true, 4]);
        assert_eq!(
            original,
            flows::intent(&norito::json::to_vec(&fields).unwrap())
        );
        for changed in [
            claim_intent(
                SccpNetworkV1::BscMainnet,
                "transaction",
                &account,
                true,
                true,
                4,
            ),
            claim_intent(network, "other transaction", &account, true, true, 4),
            claim_intent(network, "transaction", &other_account, true, true, 4),
            claim_intent(network, "transaction", &account, false, true, 4),
            claim_intent(network, "transaction", &account, true, false, 4),
            claim_intent(network, "transaction", &account, true, true, 5),
        ] {
            assert_ne!(original, changed.unwrap());
        }
    }

    #[test]
    fn finalize_refuses_a_different_message_before_destination_work() {
        assert!(require_requested_message(&[1; 32], &[1; 32]).is_ok());
        assert!(require_requested_message(&[1; 32], &[2; 32]).is_err());
    }

    #[test]
    fn claim_requires_an_inbound_payload_for_the_authenticated_route() {
        use iroha_sccp::v1::{payload::SccpTransferPayloadV1, proof::DestinationV1};
        let route = DestinationV1 {
            network: SccpNetworkV1::EthereumMainnet,
            route_revision: 7,
            destination_word: [3; 32],
        };
        let payload = SccpTransferPayloadV1::inbound(
            route.network,
            1,
            route.route_revision,
            10,
            vec![1; 20],
            vec![2; 32],
        )
        .unwrap();
        require_claim_route(&payload, route).unwrap();
        for changed in [
            DestinationV1 {
                network: SccpNetworkV1::BscMainnet,
                ..route
            },
            DestinationV1 {
                route_revision: 8,
                ..route
            },
        ] {
            assert!(require_claim_route(&payload, changed).is_err());
        }
        let outbound = SccpTransferPayloadV1::outbound(
            route.network,
            1,
            route.route_revision,
            1_000,
            10,
            vec![2; 32],
            vec![1; 20],
        )
        .unwrap();
        assert!(require_claim_route(&outbound, route).is_err());
    }

    #[test]
    fn committee_sync_bounds_progress_and_refuses_older_discovery() {
        assert_eq!(sync_target(1, 1).unwrap(), 1);
        assert_eq!(sync_target(1, 7).unwrap(), 7);
        assert_eq!(sync_target(1, 100).unwrap(), 17);
        assert_eq!(sync_target(u64::MAX - 1, u64::MAX).unwrap(), u64::MAX);
        assert!(sync_target(2, 1).is_err());
        assert!(sync_target(0, 1).is_err());
    }

    #[test]
    fn profile_activations_name_only_compiled_later_versions() {
        let error = lc_profile_action(SccpNetworkV1::EthereumMainnet, None)
            .expect_err("this release compiles only version 1");
        assert!(error.to_string().contains("active from genesis"), "{error}");
        let error = lc_profile_action(SccpNetworkV1::TonMainnet, Some(1)).expect_err("genesis");
        assert!(error.to_string().contains("active from genesis"), "{error}");
        let error = lc_profile_action(SccpNetworkV1::BscMainnet, Some(2)).expect_err("unknown");
        assert!(error.to_string().contains("does not compile"), "{error}");
        drop(lc_profile_action(SccpNetworkV1::SoraTaira, Some(2)).expect_err("Taira has none"));
    }

    #[test]
    fn recipients_are_encoded_per_target_codec() {
        let evm = parse_recipient(
            SccpNetworkV1::EthereumMainnet,
            &format!("0x{}", "11".repeat(20)),
        )
        .expect("evm");
        assert_eq!(evm, vec![0x11; 20]);
        assert!(parse_recipient(SccpNetworkV1::EthereumMainnet, &"00".repeat(20)).is_err());
        for network in [SccpNetworkV1::EthereumMainnet, SccpNetworkV1::BscMainnet] {
            assert!(
                parse_recipient(network, &format!("41{}", "22".repeat(20))).is_err(),
                "a 21-byte address of the retired TRON codec is no EVM recipient"
            );
        }
        let ton = parse_recipient(SccpNetworkV1::TonMainnet, &format!("0:{}", "33".repeat(32)))
            .expect("ton");
        assert_eq!(&ton[..4], &[0; 4]);
        assert_eq!(ton.len(), 36);
        assert!(parse_recipient(SccpNetworkV1::TonMainnet, &"33".repeat(32)).is_err());
    }

    #[test]
    fn networks_words_and_current_proof_heights_parse() {
        assert_eq!(
            parse_network("bsc-mainnet").expect("bsc"),
            SccpNetworkV1::BscMainnet
        );
        assert!(parse_network("sora-taira").is_err());
        assert!(
            parse_network("tron-mainnet").is_err(),
            "SCCP v1 has no TRON profile"
        );
        assert_eq!(parse_word(&"ab".repeat(32)).expect("word"), [0xab; 32]);
        assert!(parse_word("ab").is_err());
        assert_eq!(
            parse_proof_height("record").expect("record"),
            SccpProofHeightV1::Record
        );
        assert_eq!(
            parse_proof_height("9").expect("height"),
            SccpProofHeightV1::At(9)
        );
        for invalid in [
            "own",
            "later",
            "0",
            "+1",
            " 1",
            "1 ",
            "18446744073709551616",
        ] {
            assert!(parse_proof_height(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            parse_direction("inbound").expect("inbound"),
            SccpDirection::Inbound
        );
        assert!(parse_direction("both").is_err());
    }

    #[test]
    fn sent_transfers_match_their_committed_record() {
        use iroha::data_model::{
            account::AccountId,
            sccp::outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
        };
        use iroha_sccp::v1::payload::SccpTransferPayloadV1;
        let account = |seed: u8| {
            let key_pair = iroha_crypto::KeyPair::try_from_seed(
                vec![seed; 32],
                iroha_crypto::Algorithm::Ed25519,
            )
            .expect("seed");
            AccountId::new(key_pair.public_key().clone())
        };
        let payload = |recipient: [u8; 20]| {
            SccpTransferPayloadV1::outbound(
                SccpNetworkV1::EthereumMainnet,
                4,
                1,
                9,
                15,
                vec![1; 32],
                recipient.to_vec(),
            )
            .and_then(|payload| payload.encode())
            .expect("payload")
        };
        let record =
            |sender: AccountId, amount: u128, recipient: [u8; 20]| SccpOutboundMessageRecordV1 {
                network: SccpNetworkV1::EthereumMainnet,
                revision: 1,
                nonce: 4,
                height: 3,
                commitment_index: 0,
                deadline_ms: 9,
                sender,
                amount,
                payload: payload(recipient),
                leaf: [0; 32],
                status: SccpOutboundStatusV1::Recorded,
            };
        let sent = SentTransfer {
            sender: account(1),
            amount: 15,
            recipient: vec![0x11; 20],
        };
        assert!(sent.matches(&record(account(1), 15, [0x11; 20])));
        assert!(!sent.matches(&record(account(2), 15, [0x11; 20])));
        assert!(!sent.matches(&record(account(1), 16, [0x11; 20])));
        assert!(!sent.matches(&record(account(1), 15, [0x22; 20])));
    }

    #[test]
    fn source_builders_cover_every_source_chain() {
        let config = iroha_sccp_wallet::config::SccpClientConfig::from_user(
            iroha::config::sccp::SccpClientConfigUser::default(),
            std::path::Path::new("client.toml"),
        )
        .unwrap();
        let network = |network, rpc_url| {
            source_builder(
                &config,
                &iroha_sccp::light_client::profile::GENESIS_PROFILES,
                network,
                rpc_url,
                None,
            )
            .expect("builder")
            .network()
        };
        assert_eq!(
            network(SccpNetworkV1::TonMainnet, ""),
            SccpNetworkV1::TonMainnet
        );
        // Invalid explicit endpoints and non-source networks are refused before RPC.
        assert!(
            source_builder(
                &config,
                &iroha_sccp::light_client::profile::GENESIS_PROFILES,
                SccpNetworkV1::EthereumMainnet,
                "not a URL",
                None
            )
            .is_err()
        );
        assert!(
            source_builder(
                &config,
                &iroha_sccp::light_client::profile::GENESIS_PROFILES,
                SccpNetworkV1::SoraTaira,
                "https://taira.invalid",
                None
            )
            .is_err()
        );
    }

    #[test]
    fn creation_bytecode_must_match_the_locked_artifact() {
        locked_creation_keccak().expect("the lock pins the SccpTairaXor creation hash");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("creation.hex");
        std::fs::write(&path, "0x6080\n").expect("write");
        let error = locked_creation_bytecode(&path).expect_err("not the locked artifact");
        assert!(
            error.to_string().contains("differs from the locked"),
            "{error}"
        );
        std::fs::write(&path, "not hex").expect("write");
        assert!(locked_creation_bytecode(&path).is_err());
        assert!(locked_creation_bytecode(&dir.path().join("missing.hex")).is_err());
    }

    #[test]
    fn sccp_commands_parse() {
        use clap::Parser as _;
        #[derive(clap::Parser, Debug)]
        struct Cli {
            #[command(subcommand)]
            command: Command,
        }
        assert!(
            Cli::try_parse_from([
                "sccp",
                "send",
                "--network",
                "ethereum-mainnet",
                "--amount",
                "1.5",
                "--recipient",
                "0x1111111111111111111111111111111111111111",
            ])
            .is_err(),
            "send requires independent origin and destination observation"
        );
        Cli::try_parse_from(["sccp", "rotations", "--after-generation", "3"]).expect("rotations");
        Cli::try_parse_from(["sccp", "recent", "--direction", "inbound", "--limit", "5"])
            .expect("recent");
        Cli::try_parse_from(["sccp", "proof", "--message-id", "00"]).expect("proof");
        Cli::try_parse_from(["sccp", "finality", "--height", "1"]).expect("finality");
        Cli::try_parse_from(["sccp", "finality"]).expect("latest finality");
        assert!(Cli::try_parse_from(["sccp", "finality", "--height", "0"]).is_err());
        Cli::try_parse_from(["sccp", "committee", "--generation", "1"]).expect("native committee");
        assert!(Cli::try_parse_from(["sccp", "committee", "--generation", "0"]).is_err());
        assert!(matches!(
            Cli::try_parse_from(["sccp", "fast-pause", "status"])
                .unwrap()
                .command,
            Command::FastPause(fast_pause::Command::Status)
        ));
        assert!(matches!(
            Cli::try_parse_from(["sccp", "evidence", "anchor", "1"])
                .unwrap()
                .command,
            Command::Evidence(evidence::Command::Anchor(AnchorArgs { height })) if height.get() == 1
        ));
        assert!(Cli::try_parse_from(["sccp", "evidence", "anchor", "0"]).is_err());
        let public =
            iroha_crypto::KeyPair::from_seed(vec![1; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .to_string();
        let hash = iroha_crypto::Hash::new(b"selected original").to_string();
        for command in [
            "send",
            "finalize",
            "committee-sync",
            "claim",
            "control",
            "deployment",
            "burn",
            "void",
            "refund",
        ] {
            let mut args = vec!["sccp", command];
            match command {
                "control" => args.push("apply"),
                "deployment" => args.push("verify"),
                _ => {}
            }
            args.extend(["--rpc-url", "http://localhost:8545"]);
            if !["claim", "deployment", "send", "refund"].contains(&command) {
                args.extend(["--key-file", "key"]);
            }
            if ["finalize", "void", "refund"].contains(&command) {
                args.extend(["--message-id", "00"]);
            } else {
                args.extend(["--network", "ethereum-mainnet"]);
            }
            if command == "claim" {
                args.extend(["--tx-hash", "00"]);
            }
            if command == "send" {
                args.extend([
                    "--amount",
                    "1.5",
                    "--recipient",
                    "0x1111111111111111111111111111111111111111",
                ]);
            }
            if command == "burn" {
                args.extend(["--amount", "1.5"]);
            }
            if ["control", "deployment", "burn"].contains(&command) {
                args.extend(["--revision", "1"]);
            }
            assert!(
                Cli::try_parse_from(&args).is_err(),
                "independent origin is mandatory for {command}"
            );
            args.extend([
                "--signed-genesis",
                "genesis.nrt",
                "--genesis-manifest",
                "genesis.json",
                "--genesis-public-key",
                &public,
                "--genesis-hash",
                &hash,
                "--at-height",
                "2",
                "--world-snapshot",
                "world.nrt",
                "--world-schema-hash",
                &hash,
            ]);
            Cli::try_parse_from(&args).expect("complete independent origin flags");
            if command == "deployment" {
                args[1] = "control";
                args[2] = "status";
                Cli::try_parse_from(&args).expect("control status is read-only and needs no key");
            }
        }
        Cli::try_parse_from(["sccp", "governance", "show", "00"]).expect("proposal show");
        for retired in ["roster", "roster-sync", "key", "bridge-key", "bridge-keys"] {
            assert!(Cli::try_parse_from(["sccp", retired]).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "sccp",
                "proof",
                "--message-id",
                "00",
                "--attestation",
                "own"
            ])
            .is_err()
        );
    }
}
