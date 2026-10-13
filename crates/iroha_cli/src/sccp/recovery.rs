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
    flows::ton_observed(
        context,
        &original,
        &flow,
        Action::RetryRecovery,
        destination.lite(),
        Vec::new(),
        |items| {
            let (row, evidence) = super::ton_state::recovery_snapshot(
                &client,
                &original,
                destination.lite(),
                destination.minter(),
                args.revision,
                args.operation_id,
            )?
            .ok_or_else(|| {
                eyre!(
                    "Recovery account proof is unavailable; the original operation remains unknown."
                )
            })?;
            let (_, bytes) = row.ok_or_else(|| eyre!("No authenticated recovery row remains; verify the original terminal event to establish the transfer outcome."))?;
            let row = iroha_sccp::v1::ton_cell::cell_from_boc(&bytes)?;
            ensure!(
                recovery_row(&row)?.phase != 3,
                "queued recovery is advanced by its original predecessor"
            );
            super::ton_state::recovery_baseline(&evidence)?;
            items.extend(evidence);
            items.push(SccpEvidenceItemV1 {
                label: "ton.recovery.original_row".to_owned(),
                bytes,
            });
            destination.prepare_retry(&wallet, args.operation_id)
        },
        |step| {
            let (initial, baseline) = retry_baseline(step)?;
            super::ton_state::recovery(
                &client,
                &original,
                destination.lite(),
                destination.minter(),
                args.revision,
                args.operation_id,
                &initial,
                &baseline,
            )
        },
        SccpStepOutcomeKindV1::Superseded,
    )?;
    context.println("Recovery progress is separate from mint/burn completion; resume the original transfer to verify its terminal source event.")
}

/// Read custody from the exact locked step selected by the confirmation driver.
pub(super) fn retry_baseline(
    step: &iroha_sccp_wallet::journal::SccpJournalStep,
) -> Result<(
    iroha_sccp_wallet::pure::ton::RecoveryRowV1,
    super::ton_state::RecoveryCut,
)> {
    let items = &step.record().evidence;
    let mut rows = items
        .iter()
        .filter(|item| item.label == "ton.recovery.original_row");
    let row = rows
        .next()
        .ok_or_else(|| eyre!("original retry lacks recovery row custody"))?;
    ensure!(
        rows.next().is_none(),
        "original retry has duplicate recovery row custody"
    );
    let row = iroha_sccp::v1::ton_cell::cell_from_boc(&row.bytes)?;
    Ok((
        recovery_row(&row)?,
        super::ton_state::recovery_baseline(items)?,
    ))
}
