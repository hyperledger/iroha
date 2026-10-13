//! Authenticated deployment inspection and destination control submission.

use super::{blocking, origin};
use crate::{Run, RunContext};
use eyre::{Result, ensure, eyre};
use iroha::data_model::{
    bridge::SccpNetworkV1,
    sccp::{deployment::SccpDeploymentV1, registry::SccpRouteRevisionV1},
};

/// Destination control operations.
#[derive(clap::Subcommand, Debug)]
pub enum ControlCommand {
    /// Verify and apply a complete control; defaults to the newest observed control.
    Apply(ControlArgs),
}

/// Destination inspection operations.
#[derive(clap::Subcommand, Debug)]
pub enum DeploymentCommand {
    /// Recompute the registered address and inspect the destination's identity and code.
    Verify(DeploymentArgs),
}

/// Independently authenticated destination selection.
#[derive(clap::Args, Debug)]
pub struct DeploymentArgs {
    /// Original native authority and complete certified World snapshot.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// External network profile.
    #[arg(long)]
    network: String,
    /// Exact registered revision.
    #[arg(long)]
    revision: u32,
    /// EVM JSON-RPC endpoint or TON liteserver list.
    #[arg(long, default_value = "")]
    rpc_url: String,
}

/// Complete control proof and fee payer selection.
#[derive(clap::Args, Debug)]
pub struct ControlArgs {
    /// Original signed custody and exact-byte recovery policy.
    #[command(flatten)]
    flow: super::flows::FlowArgs,

    /// Authenticated destination selection.
    #[command(flatten)]
    destination: DeploymentArgs,
    /// Exact control nonce; defaults to the newest observed committed nonce.
    #[arg(long)]
    nonce: Option<std::num::NonZeroU64>,
    /// Certificate height: record, latest, or an explicit positive height.
    #[arg(long, default_value = "latest")]
    at: String,
    /// Owner-only fee payer key file.
    #[arg(long)]
    key_file: std::path::PathBuf,
    /// TON fee payer's deployed v5r1 wallet, in raw 0:<hex> form.
    #[arg(long)]
    ton_wallet: Option<String>,
}

fn selected_revision(
    client: &iroha::blocking::Client,
    original: &origin::AuthenticatedOrigin,
    network: SccpNetworkV1,
    revision: u32,
) -> Result<SccpRouteRevisionV1> {
    let route = client
        .sccp()
        .registry()?
        .into_iter()
        .find(|route| route.network == network)
        .ok_or_else(|| eyre!("the requested route is absent"))?;
    original.verify_route(network, &route)?;
    route
        .revisions
        .get(&revision)
        .copied()
        .ok_or_else(|| eyre!("the requested revision is absent"))
}

pub(super) fn latest_control_nonce(
    client: &iroha::blocking::Client,
    original: &origin::AuthenticatedOrigin,
    network: SccpNetworkV1,
    revision: u32,
) -> Result<u64> {
    let selected = selected_revision(client, original, network, revision)?;
    let page = client.sccp().controls(network, revision, 0, 1)?;
    ensure!(
        page.network == network && page.revision == revision,
        "controls name another destination"
    );
    ensure!(
        page.next_control_nonce >= selected.next_control_nonce,
        "controls omit a control in the authenticated World cut"
    );
    page.next_control_nonce
        .checked_sub(1)
        .ok_or_else(|| eyre!("invalid next control nonce"))
}

/// An unapplied newer control is a hard refusal before constructing any mint transaction.
pub(super) fn require_latest_control(applied: u64, required: u64) -> Result<()> {
    ensure!(
        applied >= required,
        "destination control {required} must be applied first with `sccp control apply`; confirm it and rerun finalize (currently {applied})"
    );
    Ok(())
}

impl Run for ControlCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let Self::Apply(args) = self;
        let client = blocking(context)?;
        let original = origin::authenticate_origin(context, &client, &args.destination.origin)?;
        let network = super::parse_network(&args.destination.network)?;
        let revision = args.destination.revision;
        let latest = latest_control_nonce(&client, &original, network, revision)?;
        let mut nonce = args.nonce.map_or(latest, std::num::NonZeroU64::get);
        ensure!(nonce != 0 && nonce <= latest, "no such committed control");
        #[derive(norito::derive::JsonSerialize)]
        struct Intent {
            network: SccpNetworkV1,
            revision: u32,
            nonce: u64,
        }
        #[derive(norito::derive::JsonSerialize)]
        struct UserIntent {
            network: SccpNetworkV1,
            revision: u32,
            requested_nonce: Option<u64>,
        }
        let flow = super::flows::open_with_intent(
            context,
            iroha_sccp_wallet::journal::SccpFlowKindV1::ControlApply,
            &args.flow,
            super::flows::intent(&norito::json::to_vec(&Intent {
                network,
                revision,
                nonce,
            })?),
            super::flows::intent(&norito::json::to_vec(&UserIntent {
                network,
                revision,
                requested_nonce: args.nonce.map(std::num::NonZeroU64::get),
            })?),
        )?;
        use iroha_sccp_wallet::flow::SccpFlowActionV1 as Action;
        if let Some(step) = flow.latest(Action::Control)? {
            super::flows::check_flow(&flow, &step)?;
            let evidence = step
                .record()
                .evidence
                .iter()
                .find(|item| item.label == "taira.verified_control")
                .ok_or_else(|| eyre!("retained control has no original target"))?;
            let original: iroha_sccp::api::SccpControlProofBundleV1 =
                norito::json::from_slice(&evidence.bytes)?;
            ensure!(
                original.network == network && original.revision == revision,
                "retained control belongs to another deployment"
            );
            nonce = original.control_nonce;
        }
        if network == SccpNetworkV1::TonMainnet {
            let (destination, wallet) = super::ton_destination(
                &context.sccp_config()?,
                &client,
                &original,
                network,
                Some(revision),
                &args.destination.rpc_url,
                args.ton_wallet.as_deref(),
                &args.key_file,
            )?;
            let bundle = if super::flows::needs_preparation(&flow, Action::Control)? {
                Some(client.sccp().control_proof(
                    network,
                    revision,
                    nonce,
                    super::parse_proof_height(&args.at)?,
                )?)
            } else {
                None
            };
            let items = bundle
                .as_ref()
                .map(|bundle| super::flows::evidence("taira.verified_control", bundle))
                .transpose()?
                .into_iter()
                .collect();
            super::flows::ton(
                context,
                &flow,
                Action::Control,
                destination.lite(),
                items,
                |_| {
                    destination.prepare_control(
                        bundle
                            .as_ref()
                            .ok_or_else(|| eyre!("missing original control"))?,
                        original.network,
                        original.instance,
                        &wallet,
                    )
                },
                |_| {
                    destination.progress_evidence(
                        original.network,
                        original.instance,
                        Some(nonce),
                        None,
                    )
                },
            )?;
        } else {
            let destination = super::evm_destination(
                &context.sccp_config()?,
                &client,
                &original,
                network,
                Some(revision),
                &args.destination.rpc_url,
            )?;
            if super::flows::recover_evm(context, &flow, Action::Control, &destination)? {
                return Ok(());
            }
            let bundle = client.sccp().control_proof(
                network,
                revision,
                nonce,
                super::parse_proof_height(&args.at)?,
            )?;
            let call = destination.control_call(&bundle, original.network, original.instance)?;
            super::flows::evm(
                context,
                &flow,
                Action::Control,
                network,
                &destination,
                &args.key_file,
                call,
                vec![super::flows::evidence("taira.verified_control", &bundle)?],
            )?;
        }
        Ok(())
    }
}

impl Run for DeploymentCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let Self::Verify(args) = self;
        let client = blocking(context)?;
        let original = origin::authenticate_origin(context, &client, &args.origin)?;
        let network = super::parse_network(&args.network)?;
        let revision = selected_revision(&client, &original, network, args.revision)?;
        match revision.deployment {
            SccpDeploymentV1::Evm(deployment) => {
                let constructor = iroha_sccp::v1::evm_abi::ConstructorArgsV1 {
                    taira_network_id: original.network,
                    consensus_instance: original.instance,
                    network,
                    route_revision: revision.revision,
                    max_wrapped_supply: revision.max_wrapped_supply,
                    pin: revision.initial_committee,
                };
                ensure!(
                    constructor.address() == deployment.address,
                    "registered EVM address differs from the locked CREATE2 deployment"
                );
                super::evm_destination(
                    &context.sccp_config()?,
                    &client,
                    &original,
                    network,
                    Some(args.revision),
                    &args.rpc_url,
                )?
                .verify_identity(original.network, original.instance)?;
            }
            SccpDeploymentV1::Ton(deployment) => {
                let generation = client
                    .sccp()
                    .committee(revision.initial_committee.generation)?;
                let keys =
                    original.verify_pin_generation(generation, &revision.initial_committee)?;
                let init = iroha_sccp::v1::ton_cell::TonMinterInitV1 {
                    taira_network_id: original.network,
                    consensus_instance: original.instance,
                    route_revision: revision.revision,
                    max_supply: revision.max_wrapped_supply,
                    pin: revision.initial_committee,
                    keys,
                    wallet_code: deployment.wallet_code,
                    bucket_code: deployment.bucket_code,
                };
                let account =
                    iroha_sccp::v1::ton_cell::minter_account_id(&init, deployment.minter_code)?;
                ensure!(
                    account == deployment.master_account,
                    "registered TON address differs from its canonical StateInit"
                );
                let destination = iroha_sccp::v1::proof::DestinationV1 {
                    network,
                    route_revision: revision.revision,
                    destination_word: revision.destination_word,
                };
                super::ton::TonDestination::connect(
                    &context.sccp_config()?,
                    &args.rpc_url,
                    account,
                    destination,
                )?
                .verify_identity(original.network, original.instance)?;
            }
        }
        context.println("Authenticated route and deterministic deployment address match; destination observation matches the selected native identity.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_requires_newest_control_including_an_unapplied_resume() {
        for (applied, required) in [(0, 1), (2, 3), (0, u64::MAX)] {
            assert!(require_latest_control(applied, required).is_err());
        }
        for (applied, required) in [(0, 0), (3, 3), (4, 3), (u64::MAX, u64::MAX)] {
            require_latest_control(applied, required).unwrap();
        }
    }
}
