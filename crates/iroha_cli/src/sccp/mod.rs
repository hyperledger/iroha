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
//! key file). They read the deployment's native committee state, verify Taira's bundle or rotation chain
//! locally and submit the destination call.
//!
//! `claim`, `lc-advance` and `lc-bootstrap` build Ethereum, BSC and TON light-client evidence
//! from the source chain's public RPC (for Ethereum also a beacon light-client API, for TON ADNL
//! liteservers) through the shared
//! `iroha_sccp_rpc::builders::SourceChainBuilder` entry points. `claim` lets the builder pick the
//! proof's anchor from Taira's light client (§4.13.5), verifies the evidence locally against it
//! and submits any `Backfill` advances the anchor needs first, each in its own transaction.
//! `lc-advance` steps a light client that is far behind; run it until it has caught up.
//!
//! TODO: control apply, deployment verification and governance detail commands.

mod evm;
mod governance;
mod ton;

use eyre::{Result, WrapErr as _, eyre};
use iroha::{
    blocking::Client as BlockingClient,
    client::sccp::{SccpDirection, SccpFinalityAt, SccpProofAt},
    data_model::{
        bridge::SccpNetworkV1,
        isi::{InstructionBox, sccp::RecordSccpMessage},
        sccp::{
            light_client::{
                SccpLcAdvanceBytesV1, SccpLcCheckpointV1, SccpLcConsensusSetV1, SccpLightClientV1,
            },
            registry::SccpRouteActivationV1,
        },
    },
};
use iroha_primitives::numeric::Numeric;
use iroha_sccp_rpc::builders::{
    AdvanceBudgetV1, BuildError, LightClientReplayV1, SourceChainBuilder, SourceEventRefV1,
    SourceEvidenceV1, TairaLightClientView,
};

use crate::{Run, RunContext};

/// `iroha sccp` subcommands.
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Show the Taira identity, SCCP parameters and native finality constants.
    Info,
    /// List the routes with their revisions, escrows and liabilities.
    Routes,
    /// Record an outbound transfer from the configured account and print its record.
    Send(SendArgs),
    /// Show the status of one message id (outbound, inbound or unknown).
    Status(MessageArgs),
    /// List the newest outbound or inbound records.
    Recent(RecentArgs),
    /// Fetch the native certificate proof bundle of one outbound message.
    Proof(ProofArgs),
    /// Show full native generation DATA, including liability (not an authority pin).
    Committee(CommitteeArgs),
    /// Show the native certificate at an explicit height or durable tip.
    Finality(FinalityArgs),
    /// Fetch the catch-up rotation chain from a generation.
    Rotations(RotationsArgs),
    /// Mint a certified outbound message on its EVM or TON destination.
    Finalize(FinalizeArgs),
    /// Rotate an EVM or TON destination's committee forward to Taira's current generation.
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
    LcAdvance(LcAdvanceArgs),
    /// Build the Parliament `InitializeLightClient` action of the latest finalized source block.
    LcBootstrap(LcBootstrapArgs),
    /// Build the Parliament `ActivateLightClientProfile` action of a profile version compiled
    /// into this release.
    LcProfile(LcProfileArgs),
}

/// Explicit local trust input; Torii responses never populate these fields.
#[derive(Debug, Clone, clap::Args)]
pub struct NativeTrustArgs {
    /// Independently verified JSON native pin (network_id, consensus_instance, generation,
    /// committee_root, start_height, until_ms, keys). Never save a Torii response here
    /// without independently authenticating that complete pin and its canonical keys.
    #[arg(long, value_name = "PATH")]
    pub trusted_native_pin: std::path::PathBuf,
    /// Optional independently authenticated native checkpoint to additionally bind network,
    /// original Global scope and consensus instance. It does not authenticate missing pin fields.
    #[arg(long, value_name = "PATH")]
    pub trusted_checkpoint: Option<std::path::PathBuf>,
}

/// Locally selected native authority, separate from transported certificates and routing DATA.
#[derive(Debug, Clone)]
struct NativePin {
    network_id: [u8; 32],
    instance: [u8; 32],
    committee: iroha::data_model::sccp::native::SccpCommitteePinV1,
    keys: Vec<[u8; 48]>,
}

fn bounded_public_file(path: &std::path::Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).wrap_err_with(|| format!("read {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(
        u64::try_from(limit)?
            .checked_add(1)
            .ok_or_else(|| eyre!("file limit overflows"))?,
    )
    .read_to_end(&mut bytes)?;
    eyre::ensure!(
        bytes.len() <= limit,
        "{} exceeds {limit} bytes",
        path.display()
    );
    Ok(bytes)
}

impl NativePin {
    fn parse(bytes: &[u8]) -> Result<Self> {
        eyre::ensure!(bytes.len() <= 16_384, "native pin exceeds 16 KiB");
        let value: norito::json::Value = norito::json::from_slice(bytes)?;
        let object = value
            .as_object()
            .ok_or_else(|| eyre!("native pin must be an object"))?;
        eyre::ensure!(
            object.len() == 7,
            "native pin must contain exactly seven fields"
        );
        let text = |name| {
            value
                .get(name)
                .and_then(norito::json::Value::as_str)
                .ok_or_else(|| eyre!("native pin is missing string {name}"))
        };
        let number = |name| {
            value
                .get(name)
                .and_then(norito::json::Value::as_u64)
                .ok_or_else(|| eyre!("native pin is missing unsigned integer {name}"))
        };
        let keys = value
            .get("keys")
            .and_then(norito::json::Value::as_array)
            .ok_or_else(|| eyre!("native pin is missing ordered keys"))?;
        eyre::ensure!(
            iroha_sccp::v1::committee::is_valid_committee_size(keys.len()),
            "committee must contain exactly 3f+1 keys, 4..=31"
        );
        let keys = keys
            .iter()
            .map(|value| {
                let text = value
                    .as_str()
                    .ok_or_else(|| eyre!("committee key is not hex text"))?;
                let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))?;
                <[u8; 48]>::try_from(bytes)
                    .map_err(|_| eyre!("committee key must contain 48 bytes"))
            })
            .collect::<Result<Vec<_>>>()?;
        let pin = Self {
            network_id: parse_word(text("network_id")?)?,
            instance: parse_word(text("consensus_instance")?)?,
            committee: iroha::data_model::sccp::native::SccpCommitteePinV1 {
                generation: number("generation")?,
                committee_root: parse_word(text("committee_root")?)?,
                start_height: number("start_height")?,
                until_ms: number("until_ms")?,
            },
            keys,
        };
        eyre::ensure!(
            pin.network_id != [0; 32] && pin.instance != [0; 32],
            "native network and instance must be nonzero"
        );
        eyre::ensure!(
            pin.committee.generation != 0
                && pin.committee.start_height != 0
                && pin.committee.until_ms != 0,
            "native pin generation, start and deadline must be nonzero"
        );
        eyre::ensure!(
            iroha_sccp::v1::committee::successor_keys_match(
                &pin.keys,
                &pin.committee.committee_root
            ),
            "native pin root/ordered keys mismatch"
        );
        eyre::ensure!(
            pin.keys
                .iter()
                .all(iroha_crypto::bls::consensus::key_validate),
            "native pin has an invalid BLS key"
        );
        Ok(pin)
    }
    fn load(args: &NativeTrustArgs) -> Result<Self> {
        let pin = Self::parse(&bounded_public_file(&args.trusted_native_pin, 16_384)?)?;
        if let Some(path) = &args.trusted_checkpoint {
            use iroha::data_model::{
                block::consensus::SumeragiRootScope,
                sumeragi_finality::{
                    MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint,
                    SumeragiFinalityVerifier,
                },
            };
            let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&bounded_public_file(
                path,
                MAX_FINALITY_CHECKPOINT_BYTES,
            )?)?;
            eyre::ensure!(
                checkpoint.network_id().as_bytes() == &pin.network_id,
                "checkpoint and native pin network differ"
            );
            let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
                &checkpoint,
                &checkpoint.network_id(),
                checkpoint.chain_id(),
            )?;
            eyre::ensure!(
                verifier.root_scope() == SumeragiRootScope::Global
                    && verifier.instance().0 == pin.instance,
                "checkpoint is not the pinned Global instance"
            );
        }
        Ok(pin)
    }
    fn check_deployment(
        &self,
        network: SccpNetworkV1,
        revision: u32,
        word: [u8; 32],
        cap: u128,
        now: u64,
    ) -> Result<()> {
        let deployment = self.deployment(network, revision, word, cap);
        iroha_sccp::v1::destination::Destination::new(deployment.clone())
            .map_err(|error| eyre!("native deployment configuration: {error}"))?;
        deployment
            .check_init_time(now)
            .map_err(|error| eyre!("initial native pin deadline: {error}"))
    }
    fn deployment(
        &self,
        network: SccpNetworkV1,
        revision: u32,
        word: [u8; 32],
        cap: u128,
    ) -> iroha_sccp::v1::destination::DeploymentV1 {
        use iroha_sccp::v1::destination::{DeploymentV1, DestinationFlavor};
        DeploymentV1 {
            flavor: if network == SccpNetworkV1::TonMainnet {
                DestinationFlavor::Ton
            } else {
                DestinationFlavor::Evm
            },
            taira_network_id: self.network_id,
            consensus_instance: self.instance,
            network,
            destination_word: word,
            route_revision: revision,
            max_wrapped_supply: cap,
            pin_generation: self.committee.generation,
            pin_root: self.committee.committee_root,
            pin_start_height: self.committee.start_height,
            pin_until_ms: self.committee.until_ms,
            pin_keys: Some(self.keys.clone()),
        }
    }
}

/// Select the exact call form; an unavailable checkpoint never selects an inline fallback.
fn proof_source(checkpoint: bool) -> iroha_sccp_wallet::pure::bundle::BundleSourceV1 {
    use iroha_sccp_wallet::pure::bundle::BundleSourceV1;
    if checkpoint {
        BundleSourceV1::Checkpoint
    } else {
        BundleSourceV1::Inline
    }
}

/// Arguments of `iroha sccp claim`.
#[derive(clap::Args, Debug)]
pub struct ClaimArgs {
    /// Source network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// Burn transaction: EVM `transferToTaira` tx hash, or TON `<lt>:<hash>` of the minter
    /// transaction that emitted `sccp_transfer_to_taira`.
    #[arg(long)]
    pub tx_hash: String,
    /// JSON-RPC endpoint (EVM) or liteserver list (TON) of the source chain.
    #[arg(long)]
    pub rpc_url: String,
    /// Beacon API endpoint serving the light-client routes (Ethereum only).
    #[arg(long)]
    pub beacon_url: Option<String>,
}

/// Arguments of `iroha sccp lc-advance`.
#[derive(clap::Args, Debug)]
pub struct LcAdvanceArgs {
    /// Source network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// JSON-RPC endpoint (EVM) or liteserver list (TON) of the source chain.
    #[arg(long)]
    pub rpc_url: String,
    /// Beacon API endpoint serving the light-client routes (Ethereum only).
    #[arg(long)]
    pub beacon_url: Option<String>,
}

/// Arguments of `iroha sccp lc-bootstrap`.
#[derive(clap::Args, Debug)]
pub struct LcBootstrapArgs {
    /// Source network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// JSON-RPC endpoint (EVM) or liteserver list (TON) of the source chain.
    #[arg(long)]
    pub rpc_url: String,
    /// Beacon API endpoint serving the light-client routes (Ethereum only).
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
    /// Destination network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    pub network: String,
    /// Route revision the deployment serves (the route's next revision).
    #[arg(long)]
    pub revision: u32,
    /// Supply cap in XOR.
    #[arg(long)]
    pub max_supply: String,
    /// Independently selected native deployment authority.
    #[command(flatten)]
    pub trust: NativeTrustArgs,
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
    #[arg(long)]
    pub rpc_url: String,
    /// Owner-only key file of the deploying account (secp256k1; TON: the Ed25519 seed of the
    /// wallet).
    #[arg(long)]
    pub key_file: std::path::PathBuf,
    /// TON: the raw `0:<hex>` address of the deployed `v5r1` wallet the key file controls. It
    /// funds the minter with `MINTER_FLOOR` at mainnet storage prices plus 25% (about 12.4 TON).
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

/// Exact compiled init-code template from the release lock; used for address verification.
fn locked_creation_template() -> Result<Vec<u8>> {
    let lock: norito::json::Value = norito::json::from_str(ARTIFACT_LOCK)?;
    let text = lock
        .get("targets")
        .and_then(|v| v.get("evm"))
        .and_then(|v| v.get("contracts"))
        .and_then(|v| v.get("contracts/evm/sccp/SccpTairaXor.sol:SccpTairaXor"))
        .and_then(|v| v.get("creation_bytecode_hex"))
        .and_then(norito::json::Value::as_str)
        .ok_or_else(|| eyre!("release lock has no creation template"))?;
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))?;
    eyre::ensure!(
        iroha_sccp::v1::hashes::keccak256(&[&bytes]) == locked_creation_keccak()?,
        "release creation template hash differs"
    );
    Ok(bytes)
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
    /// Message id (32-byte hex).
    #[arg(long)]
    pub message_id: String,
    /// JSON-RPC endpoint (EVM), or comma-separated liteservers (TON; empty for the compiled
    /// list).
    #[arg(long)]
    pub rpc_url: String,
    /// Owner-only key file of the account that pays for the call (secp256k1; TON: the Ed25519
    /// seed of the wallet).
    #[arg(long)]
    pub key_file: std::path::PathBuf,
    /// TON: the raw `0:<hex>` address of the deployed `v5r1` wallet the key file controls.
    #[arg(long)]
    pub ton_wallet: Option<String>,
    /// Certified height: `record`, `latest` or a positive Taira height.
    #[arg(long, default_value = "record")]
    pub at: String,
    /// Verify an independently observed retained checkpoint rather than an inline certificate.
    #[arg(long)]
    pub checkpoint: bool,
    /// Independently selected native deployment authority.
    #[command(flatten)]
    pub trust: NativeTrustArgs,
    /// TON: independently authenticated local Acton artifacts for minter, wallet and bucket.
    /// These are deployment-code trust inputs, never downloaded or selected by Torii DATA.
    #[arg(long)]
    pub ton_build_dir: Option<std::path::PathBuf>,
}

/// Arguments of `iroha sccp committee-sync`.
#[derive(clap::Args, Debug)]
pub struct CommitteeSyncArgs {
    /// External network of the deployment.
    #[arg(long)]
    pub network: String,
    /// Route revision of the deployment; defaults to the route's live revision.
    #[arg(long)]
    pub revision: Option<u32>,
    /// JSON-RPC endpoint (EVM), or comma-separated liteservers (TON; empty for the compiled
    /// list).
    #[arg(long)]
    pub rpc_url: String,
    /// Owner-only key file of the account that pays for the calls (secp256k1; TON: the Ed25519
    /// seed of the wallet).
    #[arg(long)]
    pub key_file: std::path::PathBuf,
    /// TON: the raw `0:<hex>` address of the deployed `v5r1` wallet the key file controls.
    #[arg(long)]
    pub ton_wallet: Option<String>,
    /// Independently selected native deployment authority.
    #[command(flatten)]
    pub trust: NativeTrustArgs,
    /// TON: independently authenticated local Acton artifacts for minter, wallet and bucket.
    /// These are deployment-code trust inputs, never downloaded or selected by Torii DATA.
    #[arg(long)]
    pub ton_build_dir: Option<std::path::PathBuf>,
}

/// Arguments of `iroha sccp send`.
#[derive(clap::Args, Debug)]
pub struct SendArgs {
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
    /// Certified height: `record`, `latest` or a positive Taira height.
    #[arg(long, default_value = "record")]
    pub at: String,
}

/// Arguments of `iroha sccp committee`.
#[derive(clap::Args, Debug)]
pub struct CommitteeArgs {
    /// Positive native generation; current when absent. This response is untrusted DATA.
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
pub(crate) fn parse_network(text: &str) -> Result<SccpNetworkV1> {
    SccpNetworkV1::from_profile_key(text)
        .filter(|network| network.is_external())
        .ok_or_else(|| eyre!("`{text}` is not an external SCCP network profile"))
}

/// Parse a 32-byte hex identifier (optional `0x`).
pub(crate) fn parse_word(text: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(text.strip_prefix("0x").unwrap_or(text)).wrap_err("identifier is not hex")?;
    <[u8; 32]>::try_from(bytes).map_err(|_| eyre!("identifier must be 32 bytes"))
}

/// Parse a `recent` direction.
pub(crate) fn parse_direction(text: &str) -> Result<SccpDirection> {
    match text {
        "outbound" => Ok(SccpDirection::Outbound),
        "inbound" => Ok(SccpDirection::Inbound),
        _ => Err(eyre!("direction must be `outbound` or `inbound`")),
    }
}

/// Parse the explicit native proof height selector.
pub(crate) fn parse_proof_at(text: &str) -> Result<SccpProofAt> {
    match text {
        "record" => Ok(SccpProofAt::Record),
        "latest" => Ok(SccpProofAt::Latest),
        height => height
            .parse()
            .map(SccpProofAt::Height)
            .map_err(|_| eyre!("at must be `record`, `latest` or a positive height")),
    }
}

/// Encode `text` as the target network's recipient bytes (§3.1).
pub(crate) fn parse_recipient(network: SccpNetworkV1, text: &str) -> Result<Vec<u8>> {
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
    Ok(BlockingClient::from_client(context.client_from_config()?)?)
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
            Self::Send(args) => send(context, args),
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
                let bundle = blocking(context)?
                    .sccp()
                    .message_proof(&parse_word(&args.message_id)?, parse_proof_at(&args.at)?)?;
                context.print_data(&bundle)
            }
            Self::Committee(args) => {
                let client = blocking(context)?;
                let generation = match args.generation {
                    Some(generation) => client.sccp().committee(generation)?,
                    None => client.sccp().current_committee()?,
                };
                context.print_data(&generation)
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
                    .committee_rotations(args.after_generation, args.limit)?;
                context.print_data(&chain)
            }
            Self::Finalize(args) => finalize(context, args),
            Self::CommitteeSync(args) => committee_sync(context, args),
            Self::Governance(command) => command.run(context),
            Self::Deploy(args) => deploy(context, args),
            Self::Claim(args) => claim(context, args),
            Self::LcAdvance(args) => lc_advance(context, args),
            Self::LcBootstrap(args) => lc_bootstrap(context, args),
            Self::LcProfile(args) => {
                let action = lc_profile_action(parse_network(&args.network)?, args.version)?;
                context.print_data(&vec![action])
            }
        }
    }
}

/// Resolve routing DATA, then bind it to the independently supplied initial native pin.
/// The destination reader additionally checks the actual contract's immutable fields.
fn route_deployment(
    client: &BlockingClient,
    network: SccpNetworkV1,
    revision: Option<u32>,
    pin: &NativePin,
) -> Result<(
    iroha::data_model::sccp::deployment::SccpDeploymentV1,
    iroha_sccp::v1::destination::DeploymentV1,
)> {
    let route = client
        .sccp()
        .registry()?
        .into_iter()
        .find(|route| route.network == network)
        .ok_or_else(|| eyre!("Taira has no route to {}", network.profile_key()))?;
    let record = match revision {
        Some(revision) => route.revisions.get(&revision),
        None => route
            .revisions
            .values()
            .find(|record| record.activation.is_live()),
    }
    .ok_or_else(|| eyre!("the route has no selected revision"))?;
    eyre::ensure!(
        record.initial_committee == pin.committee,
        "registry initial committee differs from independently selected pin"
    );
    Ok((
        record.deployment.clone(),
        pin.deployment(
            network,
            record.revision,
            record.destination_word,
            record.max_wrapped_supply,
        ),
    ))
}
fn evm_destination(
    client: &BlockingClient,
    network: SccpNetworkV1,
    revision: Option<u32>,
    rpc_url: &str,
    pin: &NativePin,
) -> Result<evm::EvmDestination> {
    use iroha::data_model::sccp::deployment::SccpDeploymentV1;
    match route_deployment(client, network, revision, pin)? {
        (SccpDeploymentV1::Evm(deployment), destination) => {
            evm::EvmDestination::connect(rpc_url, network, deployment.address, destination)
        }
        _ => Err(eyre!("selected route is not an EVM deployment")),
    }
}
fn ton_destination(
    client: &BlockingClient,
    network: SccpNetworkV1,
    revision: Option<u32>,
    liteservers: &str,
    wallet: Option<&str>,
    key_file: &std::path::Path,
    pin: &NativePin,
    build_dir: Option<&std::path::Path>,
) -> Result<(ton::TonDestination, ton::TonWallet)> {
    use iroha::data_model::sccp::deployment::SccpDeploymentV1;
    let (SccpDeploymentV1::Ton(deployment), destination) =
        route_deployment(client, network, revision, pin)?
    else {
        return Err(eyre!("selected route is not a TON deployment"));
    };
    let build_dir=build_dir.ok_or_else(||eyre!("TON destinations require --ton-build-dir with independently authenticated local artifacts"))?;
    let code_ref = |name| -> Result<iroha::data_model::sccp::deployment::SccpTonCodeRefV1> {
        let cell = ton_code(build_dir, name)?;
        Ok(iroha::data_model::sccp::deployment::SccpTonCodeRefV1 {
            hash: *cell.hash(),
            depth: cell.depth(),
        })
    };
    let minter_code = code_ref("SccpTairaXorMinter")?;
    let wallet_code = code_ref("SccpTairaXorWallet")?;
    let bucket_code = code_ref("SccpConsumedBucket")?;
    validate_ton_address(
        &deployment,
        &destination,
        minter_code,
        wallet_code,
        bucket_code,
    )?;
    let destination = ton::TonDestination::connect(
        liteservers,
        deployment.master_account,
        destination,
        deployment.bucket_code,
    )?;
    let wallet = ton::TonWallet::load(
        destination.lite(),
        wallet.ok_or_else(|| eyre!("TON destinations need --ton-wallet"))?,
        key_file,
    )?;
    Ok((destination, wallet))
}

/// Derive the deployment address from locally selected code and the independent initial pin.
fn validate_ton_address(
    route: &iroha::data_model::sccp::deployment::SccpTonDeploymentV1,
    d: &iroha_sccp::v1::destination::DeploymentV1,
    minter_code: iroha::data_model::sccp::deployment::SccpTonCodeRefV1,
    wallet_code: iroha::data_model::sccp::deployment::SccpTonCodeRefV1,
    bucket_code: iroha::data_model::sccp::deployment::SccpTonCodeRefV1,
) -> Result<()> {
    eyre::ensure!(
        route.minter_code == minter_code
            && route.wallet_code == wallet_code
            && route.bucket_code == bucket_code,
        "registry code references differ from local authenticated artifacts"
    );
    let init = iroha_sccp::v1::ton_cell::TonMinterInitV1 {
        taira_network_id: d.taira_network_id,
        consensus_instance: d.consensus_instance,
        route_revision: d.route_revision,
        max_supply: d.max_wrapped_supply,
        pin_generation: d.pin_generation,
        pin_root: d.pin_root,
        pin_start_height: d.pin_start_height,
        pin_until_ms: d.pin_until_ms,
        pin_keys: d
            .pin_keys
            .clone()
            .ok_or_else(|| eyre!("initial TON pin keys unavailable"))?,
        wallet_code,
        bucket_code,
    };
    let expected = iroha_sccp::v1::ton_cell::minter_account_id(&init, minter_code)?;
    eyre::ensure!(
        route.master_account == expected && d.destination_word == expected,
        "minter is not the exact native StateInit of the selected pin and local artifacts"
    );
    Ok(())
}

/// `iroha sccp finalize`: verify the bundle against the destination and mint.
fn finalize<C: RunContext>(context: &mut C, args: FinalizeArgs) -> Result<()> {
    let pin = NativePin::load(&args.trust)?;
    let client = blocking(context)?;
    let message_id = parse_word(&args.message_id)?;
    let record = client
        .sccp()
        .message(&message_id)?
        .outbound()
        .map(|view| view.record.clone())
        .ok_or_else(|| eyre!("selected id is not an outbound message"))?;
    let bundle = client
        .sccp()
        .message_proof(&message_id, parse_proof_at(&args.at)?)?;
    let source = proof_source(args.checkpoint);
    if record.network == SccpNetworkV1::TonMainnet {
        let (destination, wallet) = ton_destination(
            &client,
            record.network,
            Some(record.revision),
            &args.rpc_url,
            args.ton_wallet.as_deref(),
            &args.key_file,
            &pin,
            args.ton_build_dir.as_deref(),
        )?;
        let hash = destination.finalize(&bundle, &message_id, source, &wallet)?;
        return context.println(hex::encode(hash));
    }
    let destination = evm_destination(
        &client,
        record.network,
        Some(record.revision),
        &args.rpc_url,
        &pin,
    )?;
    let data = destination.finalize_call(&bundle, &message_id, source)?;
    let key = evm::load_key(&args.key_file)?;
    let hash = destination.send(&key, data)?;
    context.println(format!("0x{}", hex::encode(hash)))
}

/// Poll `code_hash` every five seconds for up to five minutes until the deployed code appears.
fn wait_for_code(mut code_hash: impl FnMut() -> Result<[u8; 32]>) -> Result<[u8; 32]> {
    for _ in 0..60 {
        if let Ok(hash) = code_hash() {
            return Ok(hash);
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    Err(eyre!("the deployment was not mined within five minutes"))
}

/// The code cell of Acton artifact `<build_dir>/<name>.json` (`code_boc64`).
fn ton_code(build_dir: &std::path::Path, name: &str) -> Result<iroha_sccp::v1::ton_cell::Cell> {
    use base64::Engine as _;
    let path = build_dir.join(format!("{name}.json"));
    let artifact: norito::json::Value =
        norito::json::from_slice(&bounded_public_file(&path, 4 * 1024 * 1024)?)
            .map_err(|error| eyre!("{}: {error}", path.display()))?;
    let encoded = artifact
        .get("code_boc64")
        .and_then(norito::json::Value::as_str)
        .ok_or_else(|| eyre!("{} has no `code_boc64`", path.display()))?;
    let boc = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| eyre!("{}: code_boc64: {error}", path.display()))?;
    iroha_sccp_wallet::pure::ton::code_cell(&boc)
        .map_err(|error| eyre!("{}: {error}", path.display()))
}

/// `iroha sccp deploy --network ton-mainnet`: deploy the minter pinned to a Taira generation
/// from the user's wallet (with `sccp_init`) and print its `RegisterRoute` action.
fn deploy_ton<C: RunContext>(context: &mut C, args: DeployArgs) -> Result<()> {
    use iroha::data_model::sccp::{
        deployment::{SccpDeploymentV1, SccpTonCodeRefV1, SccpTonDeploymentV1},
        governance::{SccpGovernanceActionV1, SccpRegisterRouteActionV1},
    };
    use iroha_sccp::v1::ton_cell::{TonMinterInitV1, minter_deployment_data, state_init};
    use iroha_sccp_wallet::pure::ton::{
        SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS, init_body, internal_message,
        minter_deploy_value,
    };
    let build_dir = args
        .ton_build_dir
        .as_deref()
        .ok_or_else(|| eyre!("TON deployments need `--ton-build-dir`"))?;
    let minter_code = ton_code(build_dir, "SccpTairaXorMinter")?;
    let wallet_code = ton_code(build_dir, "SccpTairaXorWallet")?;
    let bucket_code = ton_code(build_dir, "SccpConsumedBucket")?;
    let code_ref = |cell: &iroha_sccp::v1::ton_cell::Cell| SccpTonCodeRefV1 {
        hash: *cell.hash(),
        depth: cell.depth(),
    };
    let max_supply: Numeric = args.max_supply.parse().map_err(|_| {
        eyre!(
            "max supply `{}` is not a decimal XOR amount",
            args.max_supply
        )
    })?;
    let max_wrapped_supply = iroha_sccp::v1::amount::taira_units(&max_supply)
        .map_err(|error| eyre!("max supply: {error}"))?;
    let pin = NativePin::load(&args.trust)?;
    let init = TonMinterInitV1 {
        taira_network_id: pin.network_id,
        consensus_instance: pin.instance,
        route_revision: args.revision,
        max_supply: max_wrapped_supply,
        pin_generation: pin.committee.generation,
        pin_root: pin.committee.committee_root,
        pin_start_height: pin.committee.start_height,
        pin_until_ms: pin.committee.until_ms,
        pin_keys: pin.keys.clone(),
        wallet_code: code_ref(&wallet_code),
        bucket_code: code_ref(&bucket_code),
    };
    let data = minter_deployment_data(&init, wallet_code.clone(), bucket_code.clone())
        .map_err(|error| eyre!("minter data: {error}"))?;
    let state = state_init(minter_code.clone(), data.root)
        .map_err(|error| eyre!("minter StateInit: {error}"))?;
    let minter = *state.hash();
    let lite = ton::connect(&args.rpc_url)?;
    pin.check_deployment(
        SccpNetworkV1::TonMainnet,
        args.revision,
        minter,
        max_wrapped_supply,
        ton::block_time_ms(&lite, ton::last_block(&lite)?)?,
    )?;
    let wallet = ton::TonWallet::load(
        &lite,
        args.ton_wallet
            .as_deref()
            .ok_or_else(|| eyre!("TON deployments need `--ton-wallet 0:<hex>`"))?,
        &args.key_file,
    )?;
    // §5.3.5: the deployment funds MINTER_FLOOR plus a margin, so the minter starts above its
    // floor instead of charging the deficit to its first caller.
    let message = internal_message(
        &minter,
        minter_deploy_value(),
        false,
        init_body(0).map_err(|error| eyre!("sccp_init: {error}"))?,
        Some(state),
    )
    .map_err(|error| eyre!("deployment message: {error}"))?;
    let hash = wallet.send(
        &lite,
        &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
    )?;
    context.println(format!(
        "deployment message {}; minter 0:{}",
        hex::encode(hash),
        hex::encode(minter)
    ))?;
    let action = SccpGovernanceActionV1::RegisterRoute(SccpRegisterRouteActionV1 {
        network: SccpNetworkV1::TonMainnet,
        revision: args.revision,
        deployment: SccpDeploymentV1::Ton(SccpTonDeploymentV1 {
            master_account: minter,
            minter_code: code_ref(&minter_code),
            wallet_code: code_ref(&wallet_code),
            bucket_code: code_ref(&bucket_code),
        }),
        max_wrapped_supply,
        initial_committee: pin.committee.clone(),
    });
    context.print_data(&vec![action])
}

/// `iroha sccp deploy`: deploy a pinned EVM or TON destination and print its `RegisterRoute`
/// action.
fn deploy<C: RunContext>(context: &mut C, args: DeployArgs) -> Result<()> {
    use iroha::data_model::sccp::{
        deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
        governance::{SccpGovernanceActionV1, SccpRegisterRouteActionV1},
    };
    let network = parse_network(&args.network)?;
    match network {
        SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet => {}
        SccpNetworkV1::TonMainnet => return deploy_ton(context, args),
        SccpNetworkV1::SoraTaira => {
            return Err(eyre!("{} is not a destination", network.profile_key()));
        }
    }
    let bytecode = locked_creation_bytecode(
        args.creation_bytecode
            .as_deref()
            .ok_or_else(|| eyre!("Solidity deployments need `--creation-bytecode`"))?,
    )?;
    let max_supply: Numeric = args.max_supply.parse().map_err(|_| {
        eyre!(
            "max supply `{}` is not a decimal XOR amount",
            args.max_supply
        )
    })?;
    let max_wrapped_supply = iroha_sccp::v1::amount::taira_units(&max_supply)
        .map_err(|error| eyre!("max supply: {error}"))?;
    let pin = NativePin::load(&args.trust)?;
    let mut init_code = bytecode;
    init_code.extend(evm::constructor_args(
        &pin,
        network,
        args.revision,
        max_wrapped_supply,
    ));
    let address = evm::created_address(&init_code);
    let chain = evm::connect_chain(&args.rpc_url, network)?;
    pin.check_deployment(
        network,
        args.revision,
        iroha_sccp::v1::hashes::word_address(&address),
        max_wrapped_supply,
        evm::now_ms(&chain)?,
    )?;
    let key = evm::load_key(&args.key_file)?;
    let hash = evm::deploy(&chain, network, &key, init_code)?;
    context.println(format!(
        "deployment transaction 0x{}; contract 0x{}",
        hex::encode(hash),
        hex::encode(address)
    ))?;
    let runtime_code_hash = wait_for_code(|| evm::runtime_code_hash(&chain, &address))?;
    let action = SccpGovernanceActionV1::RegisterRoute(SccpRegisterRouteActionV1 {
        network,
        revision: args.revision,
        deployment: SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address,
            runtime_code_hash,
        }),
        max_wrapped_supply,
        initial_committee: pin.committee.clone(),
    });
    context.print_data(&vec![action])
}

/// The Ethereum evidence builder over `rpc_url` and `beacon_url`.
fn ethereum_builder(
    rpc_url: &str,
    beacon_url: Option<&str>,
) -> Result<iroha_sccp_rpc::builders::ethereum::EthereumBuilder> {
    use iroha_sccp_rpc::{BeaconClient, EndpointSet, FailoverPolicy, HttpConfig, HttpTransport};
    let beacon_url = beacon_url.ok_or_else(|| eyre!("Ethereum evidence needs `--beacon-url`"))?;
    let execution = evm::connect_chain(rpc_url, SccpNetworkV1::EthereumMainnet)?;
    let endpoints = EndpointSet::parse(&[beacon_url], &[])
        .map_err(|error| eyre!("beacon endpoint: {error}"))?;
    let transport = HttpTransport::new(endpoints, HttpConfig::default(), FailoverPolicy::default())
        .map_err(|error| eyre!("beacon transport: {error}"))?;
    Ok(iroha_sccp_rpc::builders::ethereum::EthereumBuilder::new(
        BeaconClient::new(transport),
        execution,
    ))
}

/// The evidence builder of `network`'s source chain over `rpc_url` (for Ethereum also
/// `beacon_url`).
fn source_builder(
    network: SccpNetworkV1,
    rpc_url: &str,
    beacon_url: Option<&str>,
) -> Result<Box<dyn SourceChainBuilder>> {
    use iroha_sccp_rpc::builders::{bsc::BscBuilder, ton::TonBuilder};
    let builder: Box<dyn SourceChainBuilder> = match network {
        SccpNetworkV1::EthereumMainnet => Box::new(ethereum_builder(rpc_url, beacon_url)?),
        SccpNetworkV1::BscMainnet => {
            Box::new(BscBuilder::new(evm::connect_chain(rpc_url, network)?))
        }
        SccpNetworkV1::TonMainnet => Box::new(TonBuilder::new(ton::connect(rpc_url)?)),
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
    client: &'a BlockingClient,
    network: SccpNetworkV1,
    light_client: SccpLightClientV1,
    sets: Vec<SccpLcConsensusSetV1>,
    checkpoints: std::cell::RefCell<Vec<SccpLcCheckpointV1>>,
}

impl<'a> ToriiLightClient<'a> {
    /// Read the light client of `network` and its stored sets.
    fn read(client: &'a BlockingClient, network: SccpNetworkV1) -> Result<Self> {
        Ok(Self {
            client,
            network,
            light_client: client.sccp().light_client(network)?.light_client,
            sets: client.sccp().light_client_sets(network)?,
            checkpoints: std::cell::RefCell::new(Vec::new()),
        })
    }

    /// A local replay of what was read.
    fn replay(&self) -> LightClientReplayV1 {
        LightClientReplayV1::new(
            self.network,
            self.light_client,
            self.sets.clone(),
            self.checkpoints.borrow().clone(),
        )
    }
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
    client: &BlockingClient,
    network: SccpNetworkV1,
    builder: &dyn SourceChainBuilder,
    event: &SourceEventRefV1,
) -> Result<SourceEvidenceV1> {
    let view = ToriiLightClient::read(client, network)?;
    let now = wall_clock_ms();
    let evidence = builder
        .evidence(event, &view, now)
        .map_err(|error| eyre!("building the proof: {error}"))?;
    view.replay()
        .verify_evidence(&evidence, now)
        .map_err(|error| {
            eyre!("the built evidence does not verify against Taira's light client: {error}")
        })?;
    Ok(evidence)
}

/// Submit the evidence's `Backfill` advances, each in its own transaction, then finish with
/// `instruction`.
fn submit_evidence<C: RunContext>(
    context: &mut C,
    network: SccpNetworkV1,
    backfills: Vec<SccpLcAdvanceBytesV1>,
    instruction: InstructionBox,
) -> Result<()> {
    use iroha::data_model::isi::sccp::AdvanceSccpLightClientV1;
    for advance in backfills {
        context.submit(vec![InstructionBox::from(AdvanceSccpLightClientV1 {
            network,
            expected_state_hash: None,
            advance,
        })])?;
    }
    context.finish(vec![instruction])
}

/// `iroha sccp claim` for TON: `--tx-hash <lt>:<hash hex>` names the minter transaction whose
/// external message 0 is the `sccp_transfer_to_taira` event; the proof hangs from the burn's own
/// masterchain block, or from a back link of the newest stored epoch once the burn's epoch is
/// stale.
fn ton_claim(
    client: &BlockingClient,
    args: &ClaimArgs,
) -> Result<(u32, Vec<u8>, SourceEvidenceV1)> {
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
    // Routing DATA only locates the burn. The source builder and ledger independently
    // authenticate its proof and registered minter; it is not a destination authority pin.
    let routes = client.sccp().registry()?;
    let route = routes
        .iter()
        .find(|route| route.network == SccpNetworkV1::TonMainnet)
        .ok_or_else(|| eyre!("Taira has no TON route"))?;
    let record = route
        .revisions
        .values()
        .find(|record| record.activation.is_live())
        .ok_or_else(|| eyre!("the TON route has no live revision"))?;
    let SccpDeploymentV1::Ton(deployment) = &record.deployment else {
        return Err(eyre!("the TON route has no TON deployment"));
    };
    let minter = deployment.master_account;
    let builder = TonBuilder::new(ton::connect(&args.rpc_url)?);
    let payload = builder
        .transfer_payload(minter, lt, hash, 0)
        .map_err(|error| eyre!("reading the burn: {error}"))?;
    let revision = SccpTransferPayloadV1::decode(&payload)
        .map_err(|error| eyre!("the burned payload does not decode: {error}"))?
        .route_revision;
    let event = SourceEventRefV1::Ton {
        minter,
        lt,
        hash,
        message_index: 0,
    };
    let evidence = prove(client, SccpNetworkV1::TonMainnet, &builder, &event)?;
    Ok((revision, payload, evidence))
}

/// `iroha sccp claim` for Ethereum and BSC: the payload comes from the receipt's
/// `SccpTransferToTaira` log.
fn evm_claim(
    client: &BlockingClient,
    network: SccpNetworkV1,
    args: &ClaimArgs,
) -> Result<(u32, Vec<u8>, SourceEvidenceV1)> {
    use iroha_sccp::v1::{evm_abi::TransferToTairaLogV1, payload::SccpTransferPayloadV1};
    use iroha_sccp_rpc::builders::ethereum::EthereumEventV1;
    let tx_hash = parse_word(&args.tx_hash)?;
    let receipt = evm::connect_chain(&args.rpc_url, network)?
        .transaction_receipt(&tx_hash)
        .map_err(|error| eyre!("eth_getTransactionReceipt: {error}"))?
        .ok_or_else(|| eyre!("the transaction is not mined"))?;
    let (log_index, log) = receipt
        .logs
        .iter()
        .enumerate()
        .find_map(|(index, log)| {
            TransferToTairaLogV1::decode(&log.topics, &log.data)
                .ok()
                .map(|decoded| (index, decoded))
        })
        .ok_or_else(|| eyre!("the transaction emitted no SccpTransferToTaira log"))?;
    let payload = SccpTransferPayloadV1::decode(&log.payload)
        .map_err(|error| eyre!("the burned payload does not decode: {error}"))?;
    let event = SourceEventRefV1::Evm {
        tx_hash,
        event: EthereumEventV1::TransferToTaira {
            log_index: u32::try_from(log_index).map_err(|_| eyre!("log index overflows"))?,
        },
    };
    let builder = source_builder(network, &args.rpc_url, args.beacon_url.as_deref())?;
    let evidence = prove(client, network, builder.as_ref(), &event)?;
    Ok((payload.route_revision, log.payload, evidence))
}

/// `iroha sccp claim`: prove a source-chain burn and submit `SubmitSccpInboundMessageV1`,
/// preceded by the `Backfill` advances the proof's anchor needs, each in its own transaction.
fn claim<C: RunContext>(context: &mut C, args: ClaimArgs) -> Result<()> {
    use iroha::data_model::isi::sccp::SubmitSccpInboundMessageV1;
    let network = parse_network(&args.network)?;
    let client = blocking(context)?;
    let (revision, payload, evidence) = if network == SccpNetworkV1::TonMainnet {
        ton_claim(&client, &args)?
    } else {
        evm_claim(&client, network, &args)?
    };
    submit_evidence(
        context,
        network,
        evidence.backfills,
        InstructionBox::from(SubmitSccpInboundMessageV1 {
            network,
            revision,
            payload,
            proof: evidence.proof,
        }),
    )
}

/// `iroha sccp lc-advance`: advance Taira's light client of a source chain toward its latest
/// finality, stepped to the light client's per-advance bounds; run it again while the light
/// client is still behind.
fn lc_advance<C: RunContext>(context: &mut C, args: LcAdvanceArgs) -> Result<()> {
    use iroha::data_model::isi::sccp::AdvanceSccpLightClientV1;
    let network = parse_network(&args.network)?;
    let light_client = blocking(context)?
        .sccp()
        .light_clients()?
        .into_iter()
        .find(|light_client| light_client.params.network == network)
        .ok_or_else(|| eyre!("Taira has no {} light client", network.profile_key()))?;
    let budget = AdvanceBudgetV1::for_params(&light_client.params, usize::MAX);
    let advance = source_builder(network, &args.rpc_url, args.beacon_url.as_deref())?
        .advance(light_client.head.latest_set_id, budget)
        .map_err(|error| eyre!("building the advance: {error}"))?;
    context.finish(vec![InstructionBox::from(AdvanceSccpLightClientV1 {
        network,
        expected_state_hash: Some(light_client.state_hash),
        advance,
    })])
}

/// `iroha sccp lc-bootstrap`: print the `InitializeLightClient` action of the latest finalized
/// source block with the default params, for `iroha sccp governance propose --actions`.
fn lc_bootstrap<C: RunContext>(context: &mut C, args: LcBootstrapArgs) -> Result<()> {
    use iroha::data_model::sccp::{
        governance::{SccpGovernanceActionV1, SccpInitializeLightClientActionV1},
        light_client::{SccpLcInitExpectationV1, SccpLightClientParamsV1},
    };
    let network = parse_network(&args.network)?;
    let bootstrap = source_builder(network, &args.rpc_url, args.beacon_url.as_deref())?
        .bootstrap()
        .map_err(|error| eyre!("building the bootstrap: {error}"))?;
    let params = SccpLightClientParamsV1::defaults_for(network)
        .ok_or_else(|| eyre!("{} has no light-client defaults", network.profile_key()))?;
    iroha_sccp::light_client::verify_bootstrap(network, &params, &bootstrap, wall_clock_ms())
        .map_err(|error| eyre!("the built bootstrap does not verify: {error}"))?;
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

/// Submit one bounded certified committee catch-up prefix. Another invocation re-reads state.
fn committee_sync<C: RunContext>(context: &mut C, args: CommitteeSyncArgs) -> Result<()> {
    let pin = NativePin::load(&args.trust)?;
    let client = blocking(context)?;
    let network = parse_network(&args.network)?;
    if network == SccpNetworkV1::TonMainnet {
        let (destination, wallet) = ton_destination(
            &client,
            network,
            args.revision,
            &args.rpc_url,
            args.ton_wallet.as_deref(),
            &args.key_file,
            &pin,
            args.ton_build_dir.as_deref(),
        )?;
        let from = destination.observation()?.committee().generation;
        let steps = client.sccp().committee_rotations(from, 16)?;
        let hashes = destination.checkpoints(&steps, &wallet)?;
        for hash in hashes {
            context.println(hex::encode(hash))?;
        }
        return Ok(());
    }
    let destination = evm_destination(&client, network, args.revision, &args.rpc_url, &pin)?;
    let from = destination.observation(&[])?.committee().generation;
    let steps = client.sccp().committee_rotations(from, 16)?;
    let calls = destination.checkpoint_calls(&steps)?;
    let key = evm::load_key(&args.key_file)?;
    for call in calls {
        context.println(format!("0x{}", hex::encode(destination.send(&key, call)?)))?;
    }
    Ok(())
}

/// Target derived from the offered final rotation is a requested goal, never trusted state.
fn rotation_target(steps: &[iroha_sccp::api::SccpRotationV1], current: u64) -> Result<u64> {
    match steps.last() {
        None => Ok(current),
        Some(step) => {
            iroha_sccp::v1::finality::SccpFinalityHeaderV1::parse(&step.certificate.header)
                .map_err(|error| eyre!("rotation header: {error:?}"))?
                .generation()
                .checked_add(1)
                .ok_or_else(|| eyre!("rotation generation overflow"))
        }
    }
}

/// `iroha sccp send`: check the route (§7.1 steps 1–2) and record the transfer.
fn send<C: RunContext>(context: &mut C, args: SendArgs) -> Result<()> {
    let network = parse_network(&args.network)?;
    let recipient = parse_recipient(network, &args.recipient)?;
    let amount: Numeric = args
        .amount
        .parse()
        .map_err(|_| eyre!("amount `{}` is not a decimal XOR amount", args.amount))?;
    let units = iroha_sccp::v1::amount::taira_units(&amount)
        .map_err(|error| eyre!("amount `{}`: {error}", args.amount))?;
    let client = blocking(context)?;
    let route = client
        .sccp()
        .registry()?
        .into_iter()
        .find(|route| route.network == network)
        .ok_or_else(|| eyre!("Taira has no route to {}", network.profile_key()))?;
    let live = route
        .revisions
        .values()
        .find(|revision| revision.activation == SccpRouteActivationV1::Bidirectional)
        .ok_or_else(|| {
            eyre!(
                "the {} route has no Bidirectional revision",
                network.profile_key()
            )
        })?;
    if args
        .revision
        .is_some_and(|revision| revision != live.revision)
    {
        return Err(eyre!(
            "revision {} is not the Bidirectional revision {}",
            args.revision.unwrap_or_default(),
            live.revision
        ));
    }
    if live.destination_paused {
        return Err(eyre!("the destination is paused by the Parliament"));
    }
    let (revision, first_nonce) = (live.revision, live.next_outbound_nonce);
    let instruction = RecordSccpMessage {
        network,
        expected_revision: revision,
        amount,
        recipient: recipient.clone(),
    };
    context.finish(vec![InstructionBox::from(instruction)])?;
    if context.output_instructions() {
        // The instruction was emitted for an external signer; nothing was recorded yet.
        return Ok(());
    }
    // The nonce (and with it the message id) is assigned at execution: find the committed
    // record among the revision's nonces from the one that was next before submission.
    let sent = SentTransfer {
        sender: context.config().account.clone(),
        amount: units,
        recipient,
    };
    let view = locate_sent(&client, network, revision, first_nonce, &sent)?;
    context.print_data(&view)
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
    network: SccpNetworkV1,
    revision: u32,
    first_nonce: u64,
    sent: &SentTransfer,
) -> Result<iroha_sccp::api::SccpOutboundMessageViewV1> {
    for attempt in 0..LOCATE_ATTEMPTS {
        let mut from_nonce = first_nonce;
        loop {
            let page = client.sccp().outbound(
                network,
                revision,
                from_nonce,
                iroha_sccp::api::MAX_OUTBOUND_PAGE,
            )?;
            if let Some(view) = page.records.iter().find(|view| sent.matches(&view.record)) {
                return Ok(view.clone());
            }
            match page.next_from_nonce {
                Some(next) => from_nonce = next,
                None => break,
            }
        }
        if attempt + 1 < LOCATE_ATTEMPTS {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    Err(eyre!(
        "the transaction committed but no {} revision {revision} record from nonce {first_nonce} \
         matches it; look it up with `iroha sccp recent`",
        network.profile_key()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn native_pin() -> NativePin {
        let keys = KEYS
            .iter()
            .map(|text| hex::decode(text).unwrap().try_into().unwrap())
            .collect::<Vec<[u8; 48]>>();
        NativePin {
            network_id: [7; 32],
            instance: [8; 32],
            committee: iroha::data_model::sccp::native::SccpCommitteePinV1 {
                generation: 2,
                committee_root: iroha_sccp::v1::committee::committee_root(&keys).unwrap(),
                start_height: 10,
                until_ms: 1000,
            },
            keys,
        }
    }
    const KEYS: [&str; 4] = [
        "84c8b13b9e7bcff2dca2393b04e53e29037b5daf06f34758368cbd85b1fb9e4001e085b2dba5d1fb7b109fc4a38c1b14",
        "8b7e70568eec51b46670bf583c05b857c9c5e888d663e0af2606ab6613a600aaab2c0130733722409f77ee67d08bc223",
        "98deef4a5d6468f0725ea03a677415de205c1c90ad01044187029cb9ad00cc7285e9b1d7ebd7ff6b2e3bddc7fe110d90",
        "b2d3a715d3fa2670e31baeecd4210431a8f09f5210e4a2e68c67083e38f7ac6f61134a4a0d9eaecf3bdd465d4533e470",
    ];
    fn pin_json(pin: &NativePin) -> norito::json::Value {
        norito::json::json!({"network_id":hex::encode(pin.network_id),"consensus_instance":hex::encode(pin.instance),
            "generation":pin.committee.generation,"committee_root":hex::encode(pin.committee.committee_root),
            "start_height":pin.committee.start_height,"until_ms":pin.committee.until_ms,
            "keys":pin.keys.iter().map(hex::encode).collect::<Vec<_>>()})
    }
    #[test]
    fn trusted_native_pin_rejects_identity_geometry_and_root_substitutions() {
        let pin = native_pin();
        let original = pin_json(&pin);
        let parse =
            |value: &norito::json::Value| NativePin::parse(&norito::json::to_vec(value).unwrap());
        assert_eq!(parse(&original).unwrap().committee, pin.committee);
        for field in ["network_id", "consensus_instance", "committee_root"] {
            let mut v = original.clone();
            v.as_object_mut()
                .unwrap()
                .insert(field.into(), norito::json::Value::from("00".repeat(32)));
            assert!(parse(&v).is_err());
        }
        for field in ["generation", "start_height", "until_ms"] {
            let mut v = original.clone();
            v.as_object_mut()
                .unwrap()
                .insert(field.into(), norito::json::Value::from(0u64));
            assert!(parse(&v).is_err());
        }
        let mut v = original.clone();
        v.as_object_mut()
            .unwrap()
            .insert("extra".into(), norito::json::Value::from(1u64));
        assert!(parse(&v).is_err());
        let mut v = original.clone();
        v.as_object_mut().unwrap().remove("keys");
        assert!(parse(&v).is_err());
        let mut changed = pin.clone();
        changed.keys.swap(0, 1);
        assert!(parse(&pin_json(&changed)).is_err());
        changed = pin.clone();
        changed.keys[1] = changed.keys[0];
        assert!(parse(&pin_json(&changed)).is_err());
        changed = pin.clone();
        changed.keys.pop();
        assert!(parse(&pin_json(&changed)).is_err());
        assert!(NativePin::parse(&vec![b' '; 16_385]).is_err());
        assert!(
            pin.check_deployment(SccpNetworkV1::EthereumMainnet, 1, [9; 32], 100, 999)
                .is_ok()
        );
        assert!(
            pin.check_deployment(SccpNetworkV1::EthereumMainnet, 0, [9; 32], 100, 999)
                .is_err()
        );
        assert!(
            pin.check_deployment(SccpNetworkV1::EthereumMainnet, 1, [9; 32], 0, 999)
                .is_err()
        );
        assert!(
            pin.check_deployment(SccpNetworkV1::EthereumMainnet, 1, [9; 32], 100, 1000)
                .is_err()
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pin.json");
        std::fs::write(&path, b"12345").unwrap();
        assert_eq!(bounded_public_file(&path, 5).unwrap(), b"12345");
        assert!(bounded_public_file(&path, 4).is_err());
        assert!(bounded_public_file(&dir.path().join("absent"), 10).is_err());
    }

    #[test]
    fn ton_route_address_binds_local_codes_and_initial_native_pin() {
        use iroha::data_model::sccp::deployment::{SccpTonCodeRefV1, SccpTonDeploymentV1};
        let fixture: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../fixtures/sccp/ton_stateinit_v1.json"
        ))
        .unwrap();
        let v = &fixture["vectors"][0];
        let code = |name: &str| SccpTonCodeRefV1 {
            hash: parse_word(fixture["code"][name]["hash"].as_str().unwrap()).unwrap(),
            depth: u16::try_from(fixture["code"][name]["depth"].as_u64().unwrap()).unwrap(),
        };
        let pin=NativePin::parse(&norito::json::to_vec(&norito::json::json!({
            "network_id":v["taira_network_id"].clone(),"consensus_instance":v["consensus_instance"].clone(),
            "generation":v["pin"]["generation"].clone(),"committee_root":v["pin"]["committee_root"].clone(),
            "start_height":v["pin"]["start_height"].clone(),"until_ms":v["pin"]["until_ms"].clone(),"keys":v["keys"].clone()
        })).unwrap()).unwrap();
        let address = parse_word(v["address"]["account_id"].as_str().unwrap()).unwrap();
        let d = pin.deployment(
            SccpNetworkV1::TonMainnet,
            u32::try_from(v["route_revision"].as_u64().unwrap()).unwrap(),
            address,
            v["max_supply"].as_str().unwrap().parse().unwrap(),
        );
        let route = SccpTonDeploymentV1 {
            master_account: address,
            minter_code: code("minter"),
            wallet_code: code("wallet"),
            bucket_code: code("bucket"),
        };
        validate_ton_address(&route, &d, code("minter"), code("wallet"), code("bucket")).unwrap();
        let mut altered = route;
        altered.master_account[0] ^= 1;
        assert!(
            validate_ton_address(&altered, &d, code("minter"), code("wallet"), code("bucket"))
                .is_err()
        );
        altered = route;
        altered.bucket_code.hash[0] ^= 1;
        assert!(
            validate_ton_address(&altered, &d, code("minter"), code("wallet"), code("bucket"))
                .is_err()
        );
        for change in [0, 1, 2, 3] {
            let mut different = d.clone();
            match change {
                0 => different.consensus_instance[0] ^= 1,
                1 => different.pin_until_ms += 1,
                2 => different.pin_keys.as_mut().unwrap().swap(0, 1),
                _ => different.pin_start_height += 1,
            };
            assert!(
                validate_ton_address(
                    &route,
                    &different,
                    code("minter"),
                    code("wallet"),
                    code("bucket")
                )
                .is_err()
            );
        }
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
        lc_profile_action(SccpNetworkV1::SoraTaira, Some(2)).expect_err("Taira has none");
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
    fn networks_words_and_native_heights_parse() {
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
            parse_proof_at("record").expect("record"),
            SccpProofAt::Record
        );
        assert_eq!(
            parse_proof_at("9").expect("height"),
            SccpProofAt::Height(std::num::NonZeroU64::new(9).unwrap())
        );
        assert!(parse_proof_at("later").is_err());
        assert!(parse_proof_at("0").is_err());
        assert!(parse_proof_at("own").is_err());
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
        let network = |network, rpc_url| {
            source_builder(network, rpc_url, None)
                .expect("builder")
                .network()
        };
        assert_eq!(
            network(SccpNetworkV1::TonMainnet, ""),
            SccpNetworkV1::TonMainnet
        );
        // Ethereum evidence needs a beacon endpoint; Taira is not a source chain.
        assert!(
            source_builder(SccpNetworkV1::EthereumMainnet, "https://eth.invalid", None).is_err()
        );
        assert!(source_builder(SccpNetworkV1::SoraTaira, "https://taira.invalid", None).is_err());
    }

    #[test]
    fn creation_bytecode_must_match_the_locked_artifact() {
        locked_creation_keccak().expect("the lock pins the SccpTairaXor creation hash");
        assert!(
            !locked_creation_template()
                .expect("verified template")
                .is_empty()
        );
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
        let parsed = Cli::try_parse_from([
            "sccp",
            "send",
            "--network",
            "ethereum-mainnet",
            "--amount",
            "1.5",
            "--recipient",
            "0x1111111111111111111111111111111111111111",
        ])
        .expect("send");
        assert!(matches!(parsed.command, Command::Send(_)));
        Cli::try_parse_from(["sccp", "rotations", "--after-generation", "3"]).expect("rotations");
        Cli::try_parse_from(["sccp", "recent", "--direction", "inbound", "--limit", "5"])
            .expect("recent");
        Cli::try_parse_from(["sccp", "proof", "--message-id", "00"]).expect("proof");
        Cli::try_parse_from(["sccp", "finality", "--height", "1"]).expect("finality");
        assert!(Cli::try_parse_from(["sccp", "finality", "--height", "0"]).is_err());
        for retired in ["roster", "roster-sync"] {
            assert!(Cli::try_parse_from(["sccp", retired]).is_err());
        }
        Cli::try_parse_from(["sccp", "committee", "--generation", "1"]).expect("native committee");
        assert!(Cli::try_parse_from(["sccp", "committee", "--generation", "0"]).is_err());
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
        assert!(
            Cli::try_parse_from([
                "sccp",
                "deploy",
                "--network",
                "ethereum-mainnet",
                "--revision",
                "1",
                "--max-supply",
                "1",
                "--rpc-url",
                "https://invalid",
                "--key-file",
                "key"
            ])
            .is_err()
        );
    }
}
