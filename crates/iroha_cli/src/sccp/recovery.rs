//! Paid TON recovery of an existing immutable minter operation, distinct from transfer completion.

use super::*;
use eyre::ensure;
use iroha_sccp_wallet::{
    flow::SccpFlowActionV1 as Action,
    journal::{SccpEvidenceItemV1, SccpFlowKindV1, SccpStepOutcomeKindV1},
    pure::ton::recovery_row,
};

/// Fund one original retained recovery row; this never resends the mint or burn entrypoint.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Original native authority and registry snapshot.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// Original TON route revision.
    #[arg(long)]
    revision: u32,
    /// Immutable operation id from the minter's retained recovery book.
    #[arg(long)]
    operation_id: u64,
    /// TON liteserver list.
    #[arg(long, default_value = "")]
    rpc_url: String,
    /// Runtime-only wallet seed file.
    #[arg(long)]
    key_file: std::path::PathBuf,
    /// Deployed basechain v5r1 fee payer.
    #[arg(long)]
    ton_wallet: String,
    /// Exact original-byte recovery policy.
    #[command(flatten)]
    flow: flows::FlowArgs,
}

pub(super) fn run(context: &mut impl RunContext, args: Args) -> Result<()> {
    ensure!(args.operation_id > 0, "operation id must be nonzero");
    let flow = flows::open(
        context,
        SccpFlowKindV1::TonRecovery,
        &args.flow,
        flows::intent(format!("ton-recovery:{}:{}", args.revision, args.operation_id).as_bytes()),
    )?;
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args.origin)?;
    let (destination, wallet) = ton_destination(
        &context.sccp_config()?,
        &client,
        &original,
        SccpNetworkV1::TonMainnet,
        Some(args.revision),
        &args.rpc_url,
        Some(&args.ton_wallet),
        &args.key_file,
    )?;
    destination.verify_identity(original.network, original.instance)?;
    let previous = flow.latest(Action::RetryRecovery)?;
    let retained = match &previous {
        Some(step) if !flows::retry_allowed(&flow, Action::RetryRecovery, step)? => {
            flows::check_flow(&flow, step)?;
            Some(
                step.record()
                    .evidence
                    .iter()
                    .find(|item| item.label == "ton.recovery.original_row")
                    .ok_or_else(|| eyre!("original retry lacks recovery row custody"))?
                    .bytes
                    .clone(),
            )
        }
        _ => None,
    };
    drop(previous);
    let row = if let Some(bytes) = retained {
        iroha_sccp::v1::ton_cell::cell_from_boc(&bytes)?
    } else {
        let Some(row) = destination.recovery_row(args.operation_id)? else {
            context.println("No recovery row remains; verify the original terminal event to establish the transfer outcome.")?;
            return Ok(());
        };
        row
    };
    let initial = recovery_row(&row)?;
    ensure!(
        initial.phase != 3,
        "queued recovery is advanced by its original predecessor"
    );
    let retained = SccpEvidenceItemV1 {
        label: "ton.recovery.original_row".to_owned(),
        bytes: row.to_boc()?,
    };
    flows::ton_observed(
        context,
        &original,
        &flow,
        Action::RetryRecovery,
        destination.lite(),
        vec![retained],
        |_| destination.prepare_retry(&wallet, args.operation_id),
        |_| {
            let current = destination.recovery_row(args.operation_id)?;
            if let Some(current) = &current {
                let state = recovery_row(current)?;
                ensure!(
                    state.identity == initial.identity,
                    "immutable recovery cause changed"
                );
                if state.stage == initial.stage
                    && state.phase == initial.phase
                    && state.attempt == initial.attempt
                {
                    return Ok(None);
                }
            }
            Ok(Some(vec![SccpEvidenceItemV1 {
                label: if current.is_some() {
                    "ton.recovery.advanced_row"
                } else {
                    "ton.recovery.row_absent"
                }
                .to_owned(),
                bytes: current
                    .as_ref()
                    .map(|cell| cell.to_boc())
                    .transpose()?
                    .unwrap_or_else(|| args.operation_id.to_be_bytes().to_vec()),
            }]))
        },
        SccpStepOutcomeKindV1::Superseded,
    )?;
    context.println("Recovery progress is separate from mint/burn completion; resume the original transfer to verify its terminal source event.")
}
