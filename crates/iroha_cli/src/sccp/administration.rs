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
    /// Compare the original native control with the destination's applied pause state.
    Status(DeploymentArgs),
}

/// Destination inspection operations.
#[derive(clap::Subcommand, Debug)]
pub enum DeploymentCommand {
    /// Recompute the registered address and inspect the destination's identity and code.
    Verify(super::deployment::VerifyArgs),
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
        let args = match self {
            Self::Status(args) => return control_status(context, args),
            Self::Apply(args) => args,
        };
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
                &original,
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
            if super::flows::recover_evm(context, &original, &flow, Action::Control, &destination)?
            {
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
                &original,
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

#[derive(Debug, PartialEq, Eq, norito::derive::JsonSerialize)]
struct ControlStatus {
    network: SccpNetworkV1,
    revision: u32,
    destination_time_ms: u64,
    native_control_nonce: u64,
    native_parliament_paused: bool,
    native_fast_pause_until_ms: u64,
    destination_control_nonce: u64,
    destination_parliament_paused: bool,
    destination_fast_pause_until_ms: u64,
    destination_paused: bool,
    newest_paused: bool,
    apply_control_required: bool,
    refresh_native_origin_required: bool,
}

fn control_comparison(
    network: SccpNetworkV1,
    revision: u32,
    applied: iroha_sccp_wallet::pure::control::DestinationControlStateV1,
    native: iroha_sccp_wallet::pure::control::TairaControlV1,
    now_ms: u64,
) -> ControlStatus {
    let newest = iroha_sccp_wallet::pure::control::newest_control(&applied, Some(&native), now_ms);
    ControlStatus {
        network,
        revision,
        destination_time_ms: now_ms,
        native_control_nonce: native.control_nonce,
        native_parliament_paused: native.parliament_paused,
        native_fast_pause_until_ms: native.fast_pause_until_ms,
        destination_control_nonce: applied.control_nonce,
        destination_parliament_paused: applied.parliament_paused,
        destination_fast_pause_until_ms: applied.fast_pause_until_ms,
        destination_paused: applied.paused_at(now_ms),
        newest_paused: newest.paused,
        apply_control_required: native.control_nonce > applied.control_nonce,
        refresh_native_origin_required: applied.control_nonce > native.control_nonce,
    }
}

fn control_status(context: &mut impl RunContext, args: DeploymentArgs) -> Result<()> {
    use iroha_sccp_wallet::pure::control::TairaControlV1;
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args.origin)?;
    let network = super::parse_network(&args.network)?;
    let revision = selected_revision(&client, &original, network, args.revision)?;
    let nonce = revision
        .next_control_nonce
        .checked_sub(1)
        .ok_or_else(|| eyre!("original revision has an invalid next control nonce"))?;
    let native = if nonce == 0 {
        ensure!(
            !revision.destination_paused,
            "original route lacks its pause control"
        );
        TairaControlV1 {
            control_nonce: 0,
            parliament_paused: false,
            fast_pause_until_ms: 0,
        }
    } else {
        let page = client
            .sccp()
            .controls(network, args.revision, nonce - 1, 1)?;
        ensure!(
            page.network == network
                && page.revision == args.revision
                && page.controls.len() == 1
                && page.controls[0].control_nonce == nonce,
            "control page omits the original native control"
        );
        let control = &page.controls[0].record;
        original.verify_record_control(network, &revision, nonce, control)?;
        TairaControlV1 {
            control_nonce: nonce,
            parliament_paused: control.parliament_paused,
            fast_pause_until_ms: control.fast_pause_until_ms,
        }
    };
    let (applied, now_ms) = match revision.deployment {
        SccpDeploymentV1::Evm(_) => super::evm_destination(
            &context.sccp_config()?,
            &client,
            &original,
            network,
            Some(args.revision),
            &args.rpc_url,
        )?
        .control_observation(original.network, original.instance)?,
        SccpDeploymentV1::Ton(deployment) => {
            let destination = iroha_sccp::v1::proof::DestinationV1 {
                network,
                route_revision: args.revision,
                destination_word: revision.destination_word,
            };
            super::ton::TonDestination::connect(
                &context.sccp_config()?,
                &args.rpc_url,
                deployment.master_account,
                destination,
            )?
            .control_observation(original.network, original.instance)?
        }
    };
    context.print_data(&control_comparison(
        network,
        args.revision,
        applied,
        native,
        now_ms,
    ))
}

impl Run for DeploymentCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let Self::Verify(args) = self;
        super::deployment::verify(context, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_status_preserves_unapplied_resume_pause_expiry_and_newer_destination() {
        use iroha_sccp_wallet::pure::control::{DestinationControlStateV1, TairaControlV1};
        let applied = DestinationControlStateV1 {
            control_nonce: 4,
            parliament_paused: true,
            fast_pause_until_ms: 1000,
        };
        let native = TairaControlV1 {
            control_nonce: 5,
            parliament_paused: false,
            fast_pause_until_ms: 0,
        };
        let compare = |applied, native, now| {
            control_comparison(SccpNetworkV1::EthereumMainnet, 2, applied, native, now)
        };
        let resume = compare(applied, native, 500);
        assert!(resume.apply_control_required && resume.destination_paused);
        assert!(!resume.newest_paused && !resume.refresh_native_origin_required);
        let json = norito::json::to_value(&resume).unwrap();
        assert_eq!(json["native_control_nonce"].as_u64(), Some(5));
        assert_eq!(json["destination_control_nonce"].as_u64(), Some(4));
        assert_eq!(json["apply_control_required"].as_bool(), Some(true));
        let pause = compare(
            DestinationControlStateV1 {
                parliament_paused: false,
                fast_pause_until_ms: 0,
                ..applied
            },
            TairaControlV1 {
                parliament_paused: true,
                ..native
            },
            500,
        );
        assert!(pause.apply_control_required && pause.newest_paused && !pause.destination_paused);
        let newer = compare(
            DestinationControlStateV1 {
                control_nonce: 6,
                parliament_paused: false,
                ..applied
            },
            native,
            999,
        );
        assert!(newer.refresh_native_origin_required && newer.newest_paused);
        assert!(!newer.apply_control_required);
        let expired = compare(
            DestinationControlStateV1 {
                control_nonce: 6,
                parliament_paused: false,
                ..applied
            },
            native,
            1000,
        );
        assert!(!expired.newest_paused && !expired.destination_paused);
    }

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
