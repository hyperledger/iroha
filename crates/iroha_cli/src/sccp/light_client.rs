//! Committed-profile light-client inspection, maintenance and bootstrap review.

use std::{fs::File, io::Read as _, path::PathBuf};

use eyre::{Result, eyre};
use iroha::{
    blocking::Client as BlockingClient,
    data_model::{
        NetworkId,
        bridge::SccpNetworkV1,
        isi::{InstructionBox, sccp::AdvanceSccpLightClientV1},
        sccp::{governance::SccpGovernanceActionV1, light_client::SCCP_LC_BOOTSTRAP_MAX_BYTES_V1},
    },
};
use iroha_sccp::{
    api::SccpLcProfileStatusV1,
    light_client::{
        profile::{
            SCCP_LC_PROFILE_NETWORKS_V1, SccpChainProfilesV1, SccpLcProfileCatalogV1,
            SccpLcProfileRefV1,
        },
        proof::SccpLcSegmentV1,
    },
};
use iroha_sccp_rpc::builders::{
    TairaLightClientView as _, backfill_bytes, ethereum::evm_headers_at,
};

use crate::{Run, RunContext};

/// Native source light-client reads and bounded maintenance.
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Show one light client, or all installed light clients.
    Status(StatusArgs),
    /// Advance toward finalized source state by one bounded step.
    Advance(super::LcAdvanceArgs),
    /// Prove an older EVM header range against an exact retained checkpoint.
    Backfill(BackfillArgs),
    /// Build or independently verify a Parliament initialization action.
    #[command(subcommand)]
    Bootstrap(BootstrapCommand),
}

/// Bootstrap actions remain ordinary Parliament proposal material.
#[derive(clap::Subcommand, Debug)]
pub enum BootstrapCommand {
    /// Build an initialization action from finalized source state.
    Build(super::LcBootstrapArgs),
    /// Verify exactly the initialization actions in a JSON action file.
    Verify(VerifyArgs),
}

/// Optional network selector for status.
#[derive(clap::Args, Debug)]
pub struct StatusArgs {
    /// External source network; omit to list all installed clients.
    #[arg(long)]
    network: Option<String>,
}

/// One bounded range, inclusive of its retained checkpoint.
#[derive(clap::Args, Debug)]
pub struct BackfillArgs {
    /// Ethereum or BSC source network.
    #[arg(long)]
    network: String,
    /// Comma-separated source execution JSON-RPC endpoints; omit for the configured list.
    #[arg(long, default_value = "")]
    rpc_url: String,
    /// First older source height to authenticate.
    #[arg(long)]
    first_height: u64,
    /// Exact retained checkpoint height closing this range.
    #[arg(long)]
    checkpoint_height: u64,
}

/// Review the same action file submitted to governance propose.
#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    /// JSON array containing only `InitializeLightClient` actions.
    #[arg(long)]
    actions: PathBuf,
}

pub(super) fn resolve_profiles(
    rows: &[SccpLcProfileStatusV1],
    policy_hash: [u8; 32],
) -> Result<SccpChainProfilesV1> {
    let catalog = SccpLcProfileCatalogV1::compiled();
    eyre::ensure!(
        rows.len() == SCCP_LC_PROFILE_NETWORKS_V1.len(),
        "capabilities must name exactly three light-client profiles"
    );
    let mut active = catalog.genesis();
    for network in SCCP_LC_PROFILE_NETWORKS_V1 {
        let mut matching = rows.iter().filter(|row| row.network == network);
        let row = matching
            .next()
            .ok_or_else(|| eyre!("missing {} active profile", network.profile_key()))?;
        eyre::ensure!(matching.next().is_none(), "duplicate active profile");
        active = active.with(
            network,
            SccpLcProfileRefV1 {
                version: row.version,
                profile_hash: row.profile_hash,
            },
        );
    }
    eyre::ensure!(
        active.policy_hash() == policy_hash,
        "active profile policy hash differs from capabilities"
    );
    catalog
        .resolve(&active)
        .map_err(|error| eyre!("active profile unavailable: {error}"))
}

/// Resolve the exact committed catalog selection; never substitute a newer local version.
pub(super) fn active_profiles(
    client: &BlockingClient,
    network: [u8; 32],
) -> Result<SccpChainProfilesV1> {
    let capabilities = client.sccp().capabilities()?;
    eyre::ensure!(
        capabilities.network_id == network,
        "capabilities belong to another Taira network"
    );
    resolve_profiles(
        &capabilities.light_client_profiles,
        capabilities.profiles_policy_hash,
    )
}

fn backfill_range(first: u64, checkpoint: u64, maximum: u32) -> Result<Vec<u64>> {
    let count = checkpoint
        .checked_sub(first)
        .and_then(|span| span.checked_add(1))
        .ok_or_else(|| eyre!("invalid backfill range"))?;
    eyre::ensure!(
        first < checkpoint && count <= u64::from(maximum),
        "backfill must contain an older header and fit the committed header bound"
    );
    Ok((first..=checkpoint).collect())
}

fn backfill<C: RunContext>(context: &mut C, args: &BackfillArgs) -> Result<()> {
    let network = super::parse_network(&args.network)?;
    eyre::ensure!(
        matches!(
            network,
            SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet
        ),
        "Backfill is defined only for Ethereum and BSC"
    );
    let client = super::blocking(context)?;
    let profiles = active_profiles(&client, *context.config().network_id.as_bytes())?;
    let view = super::ToriiLightClient::read(&client, network, &profiles)?;
    let checkpoint = view
        .checkpoint_covering(args.checkpoint_height)?
        .ok_or_else(|| eyre!("no retained checkpoint covers the selected range"))?;
    eyre::ensure!(
        checkpoint.data.source_height == args.checkpoint_height,
        "the selected height is not an exact retained checkpoint"
    );
    let hard_bound = match network {
        SccpNetworkV1::EthereumMainnet => {
            iroha_sccp::light_client::profile::ETHEREUM_MAX_BACKFILL_HEADERS
        }
        _ => iroha_sccp::light_client::profile::BSC_MAX_SEGMENT_HEADERS,
    };
    let maximum = view
        .light_client
        .params
        .max_backfill_headers
        .min(u32::try_from(hard_bound).unwrap_or(u32::MAX));
    let heights = backfill_range(args.first_height, args.checkpoint_height, maximum)?;
    let rpc = super::evm::connect_chain_config(&context.sccp_config()?, &args.rpc_url, network)?;
    let now = super::wall_clock_ms();
    let advance = iroha_sccp_rpc::builders::build_verified(
        rpc.transport().endpoints().len(),
        || {
            let headers = evm_headers_at(&rpc, &heights)?;
            let segment = match network {
                SccpNetworkV1::EthereumMainnet => SccpLcSegmentV1::Ethereum(
                    iroha_sccp::light_client::ethereum::EthereumHeaderSegmentV1 { headers },
                ),
                _ => SccpLcSegmentV1::Bsc(iroha_sccp::light_client::bsc::BscHeaderSegmentV1 {
                    headers,
                }),
            };
            backfill_bytes(segment)
        },
        |advance| view.replay().advance(advance, now).map(|_| ()),
        || rpc.transport().rotate_preferred(),
    )?;
    context.finish(vec![InstructionBox::from(AdvanceSccpLightClientV1 {
        network,
        expected_state_hash: Some(view.light_client.state_hash),
        advance,
    })])
}

fn read_actions(path: &std::path::Path) -> Result<Vec<SccpGovernanceActionV1>> {
    // At most the three source bootstraps. JSON encodes every byte as at most four characters.
    let max = SCCP_LC_BOOTSTRAP_MAX_BYTES_V1
        .saturating_mul(12)
        .saturating_add(16_384);
    let mut bytes = Vec::new();
    File::open(path)?
        .take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    eyre::ensure!(
        bytes.len() <= max,
        "bootstrap action file exceeds the bounded review size"
    );
    let actions: Vec<SccpGovernanceActionV1> = norito::json::from_slice(&bytes)?;
    eyre::ensure!(
        !actions.is_empty() && actions.len() <= 3,
        "review between one and three initialization actions"
    );
    Ok(actions)
}

fn verify_actions(
    profiles: &SccpChainProfilesV1,
    actions: &[SccpGovernanceActionV1],
    now: u64,
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for action in actions {
        let SccpGovernanceActionV1::InitializeLightClient(action) = action else {
            return Err(eyre!(
                "bootstrap verify accepts only InitializeLightClient actions"
            ));
        };
        eyre::ensure!(seen.insert(action.network), "duplicate bootstrap network");
        iroha_sccp::light_client::verify_bootstrap_with_profiles(
            profiles,
            action.network,
            &action.params,
            &action.bootstrap,
            now,
        )
        .map_err(|error| {
            eyre!(
                "{} bootstrap rejected: {error}",
                action.network.profile_key()
            )
        })?;
    }
    Ok(())
}

impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Status(args) => {
                let client = super::blocking(context)?;
                match args.network {
                    Some(network) => context.print_data(
                        &client
                            .sccp()
                            .light_client(super::parse_network(&network)?)?,
                    ),
                    None => context.print_data(&client.sccp().light_clients()?),
                }
            }
            Self::Advance(args) => super::lc_advance(context, &args),
            Self::Backfill(args) => backfill(context, &args),
            Self::Bootstrap(BootstrapCommand::Build(args)) => super::lc_bootstrap(context, &args),
            Self::Bootstrap(BootstrapCommand::Verify(args)) => {
                let client = super::blocking(context)?;
                let network: NetworkId = context.config().network_id;
                let profiles = active_profiles(&client, *network.as_bytes())?;
                let actions = read_actions(&args.actions)?;
                verify_actions(&profiles, &actions, super::wall_clock_ms())?;
                context.print_data(&actions)
            }
        }
    }
}

#[cfg(test)]
mod tests;
