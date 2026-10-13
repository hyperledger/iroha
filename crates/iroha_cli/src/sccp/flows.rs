//! Original signed transfer custody and observation-only recovery for SCCP commands.

use super::*;
use eyre::ensure;
use iroha::client::PreparedTransactionPayload;
use iroha_data_model::transaction::{Executable, SignedTransaction};
use iroha_sccp_wallet::{
    flow::{SccpFlowActionV1, SccpFlowV1, drive_step_with_rebroadcast},
    journal::{
        SccpEvidenceItemV1, SccpFlowIdV1, SccpFlowKindV1, SccpJournalOutcomeV1,
        SccpJournalRecordV1, SccpJournalRoot, SccpJournalStep, SccpStepOutcomeKindV1,
    },
};
use iroha_version::codec::DecodeVersioned as _;
use norito::json::JsonSerialize;

/// Optional explicit id for an independently intended repetition of the same transfer.
#[derive(Debug, Default, clap::Args)]
pub struct FlowArgs {
    /// Stable 32-byte flow id. Reuse it after a crash; choose another only for a new transfer.
    #[arg(long)]
    pub flow_id: Option<String>,
    /// Reconcile first, then rebroadcast only identical retained signed bytes if still unknown.
    #[arg(long)]
    pub rebroadcast: bool,
    /// Prepare a new attempt only after the retained attempt has an authenticated terminal result.
    #[arg(long)]
    pub retry: bool,
}

pub(super) struct Flow {
    journal: SccpFlowV1,
    rebroadcast: bool,
    retry: bool,
    intent: [u8; 32],
}
impl std::ops::Deref for Flow {
    type Target = SccpFlowV1;
    fn deref(&self) -> &Self::Target {
        &self.journal
    }
}

pub(super) fn evidence(
    label: &str,
    value: &(impl JsonSerialize + ?Sized),
) -> Result<SccpEvidenceItemV1> {
    Ok(SccpEvidenceItemV1 {
        label: label.to_owned(),
        bytes: norito::json::to_vec(value)?,
    })
}

pub(super) fn intent(bytes: &[u8]) -> [u8; 32] {
    {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"SCCP_WALLET_INTENT_V1");
        hasher.update(bytes);
        hasher.finalize().into()
    }
}

pub(super) fn open<C: RunContext>(
    context: &mut C,
    kind: SccpFlowKindV1,
    args: &FlowArgs,
    default_id: [u8; 32],
) -> Result<Flow> {
    open_with_intent(context, kind, args, default_id, default_id)
}

/// Bind user intent independently from a newly discovered default operation folder.
pub(super) fn open_with_intent<C: RunContext>(
    context: &mut C,
    kind: SccpFlowKindV1,
    args: &FlowArgs,
    default_id: [u8; 32],
    semantic_intent: [u8; 32],
) -> Result<Flow> {
    let id = args
        .flow_id
        .as_deref()
        .map(parse_word)
        .transpose()?
        .unwrap_or(default_id);
    let root = SccpJournalRoot::open(&context.sccp_config()?.journal_dir)?;
    let flow = SccpFlowIdV1 { kind, id };
    let journal = root.network(&context.config().network_id)?.flow(&flow)?;
    context.println(format!(
        "SCCP flow {} (reuse --flow-id {} to recover)",
        flow.dir_name(),
        hex::encode(id)
    ))?;
    Ok(Flow {
        journal: SccpFlowV1::open(journal, *context.config().network_id.as_bytes())?,
        rebroadcast: args.rebroadcast,
        retry: args.retry,
        intent: semantic_intent,
    })
}

pub(super) fn bind_intent(items: &mut Vec<SccpEvidenceItemV1>, digest: [u8; 32]) {
    items.push(SccpEvidenceItemV1 {
        label: "sccp.intent.sha256".to_owned(),
        bytes: digest.to_vec(),
    });
}

pub(super) fn confirmed(outcome: &Option<SccpJournalOutcomeV1>) -> bool {
    matches!(
        outcome.as_ref().map(|outcome| outcome.outcome),
        Some(SccpStepOutcomeKindV1::Confirmed | SccpStepOutcomeKindV1::Superseded)
    )
}

fn bind_flow(flow: &Flow, items: &mut Vec<SccpEvidenceItemV1>) {
    items.push(SccpEvidenceItemV1 {
        label: "sccp.flow.intent".to_owned(),
        bytes: flow.intent.to_vec(),
    });
}
pub(super) fn check_flow(flow: &Flow, step: &SccpJournalStep) -> Result<()> {
    check_intent(&step.record().evidence, &flow.intent)
}

fn check_intent(items: &[SccpEvidenceItemV1], intent: &[u8; 32]) -> Result<()> {
    ensure!(
        items
            .iter()
            .filter(|item| item.label == "sccp.flow.intent")
            .count()
            == 1
            && items
                .iter()
                .any(|item| item.label == "sccp.flow.intent" && item.bytes.as_slice() == intent),
        "flow id belongs to another original operation; recover with its original arguments"
    );
    Ok(())
}

/// A terminal outcome authorizes another attempt, never a different original intent.
fn check_action_intent(flow: &Flow, action: SccpFlowActionV1) -> Result<()> {
    if let Some(previous) = flow.latest(action)? {
        check_flow(flow, &previous)?;
    }
    Ok(())
}

fn newer_prerequisite(previous: &[SccpEvidenceItemV1], offered: &[SccpEvidenceItemV1]) -> bool {
    let target = |items: &[SccpEvidenceItemV1]| {
        items
            .iter()
            .find(|item| item.label == "sccp.prerequisite.target")
            .and_then(|item| <[u8; 8]>::try_from(item.bytes.as_slice()).ok())
            .map(u64::from_be_bytes)
    };
    matches!((target(previous), target(offered)), (Some(a), Some(b)) if a > 0 && b > a)
}

pub(super) fn retry_allowed(
    flow: &Flow,
    action: SccpFlowActionV1,
    step: &SccpJournalStep,
) -> Result<bool> {
    if !flow.retry {
        return Ok(false);
    }
    let Some(outcome) = step.outcome()? else {
        return Ok(false);
    };
    Ok(outcome.outcome == SccpStepOutcomeKindV1::Failed
        || (action == SccpFlowActionV1::RetryRecovery
            && outcome.outcome == SccpStepOutcomeKindV1::Superseded)
        || (matches!(
            action,
            SccpFlowActionV1::SettleInbound | SccpFlowActionV1::SettleRefund
        ) && outcome.outcome == SccpStepOutcomeKindV1::Confirmed))
}

pub(super) fn needs_preparation(flow: &Flow, action: SccpFlowActionV1) -> Result<bool> {
    match flow.latest(action)? {
        None => Ok(true),
        Some(step) => {
            check_flow(flow, &step)?;
            retry_allowed(flow, action, &step)
        }
    }
}

fn original_transaction(
    context: &impl RunContext,
    record: &SccpJournalRecordV1,
) -> Result<SignedTransaction> {
    ensure!(
        record.chain == SccpNetworkV1::SoraTaira,
        "the pending step belongs to another chain"
    );
    let transaction = SignedTransaction::decode_all_versioned(&record.submission)?;
    transaction.verify_signature()?;
    ensure!(
        transaction.encode_wire_v1()? == record.submission
            && transaction.network_id() == Some(&context.config().network_id)
            && transaction.authority() == &context.config().account,
        "the original signed transaction differs from the configured network or authority"
    );
    Ok(transaction)
}

/// Quote and sign only an unprepared intent. All subsequent invocations use its original bytes.
pub(super) fn taira<C: RunContext>(
    context: &mut C,
    flow: &Flow,
    action: SccpFlowActionV1,
    instructions: Vec<InstructionBox>,
    mut items: Vec<SccpEvidenceItemV1>,
) -> Result<Option<SccpJournalOutcomeV1>> {
    ensure!(
        !context.input_instructions(),
        "SCCP flows reject additional stdin instructions"
    );
    if context.output_instructions() {
        context.finish(instructions)?;
        return Ok(None);
    }
    check_action_intent(flow, action)?;
    let instruction_wire = norito::json::to_vec(&instructions)?;
    let digest = intent(&instruction_wire);
    let previous = flow.find_intent(action, &digest)?;
    let previous = match previous {
        Some(step) if retry_allowed(flow, action, &step)? => None,
        other => other,
    };
    let step = if let Some(step) = previous {
        step
    } else {
        ensure!(
            flow.pending()?.is_none(),
            "recover the original pending flow step before preparing another"
        );
        let client = blocking(context)?;
        let (transaction, quote) = crate::quote_and_sign_transaction(
            &client,
            Executable::from(instructions),
            context.transaction_fee_payment()?,
            context.transaction_metadata().cloned().unwrap_or_default(),
        )?;
        bind_intent(&mut items, digest);
        bind_flow(flow, &mut items);
        items.push(evidence("taira.fee_quote", &quote)?);
        flow.prepare(
            action,
            SccpNetworkV1::SoraTaira,
            transaction.encode_wire_v1()?,
            items,
        )?
    };
    check_flow(flow, &step)?;
    run_taira_step(context, &step, flow.rebroadcast)
}

/// Recover the exact original before fresh proof discovery, eligibility or signing.
/// Returns true whenever the action already has retained custody, even if still unresolved.
pub(super) fn recover_taira(
    context: &mut impl RunContext,
    flow: &Flow,
    action: SccpFlowActionV1,
) -> Result<bool> {
    let Some(step) = flow.latest(action)? else {
        return Ok(false);
    };
    check_flow(flow, &step)?;
    let outcome = run_taira_step(context, &step, flow.rebroadcast)?;
    if outcome.is_some() && retry_allowed(flow, action, &step)? {
        return Ok(false);
    }
    Ok(true)
}

/// Reconcile a retained prerequisite before a fresh proof can select another backfill.
pub(super) fn recover_advance(context: &mut impl RunContext, flow: &Flow) -> Result<bool> {
    let Some(step) = flow.pending()? else {
        return Ok(false);
    };
    if step.record().action != SccpFlowActionV1::Advance {
        return Ok(false);
    }
    check_flow(flow, &step)?;
    let outcome = run_taira_step(context, &step, flow.rebroadcast)?;
    Ok(!confirmed(&outcome) && !retry_allowed(flow, SccpFlowActionV1::Advance, &step)?)
}

/// Retain the final Core message state separately from transaction admission. A confirmed
/// settle instruction may have left a held or frozen claim pending and is not itself release.
pub(super) fn finish_message(
    context: &mut impl RunContext,
    flow: &Flow,
    message_id: &[u8; 32],
) -> Result<bool> {
    check_action_intent(flow, SccpFlowActionV1::ObserveComplete)?;
    let status = blocking(context)?.sccp().message(message_id)?;
    let observed_id = match &status {
        iroha_sccp::api::SccpMessageStatusV1::Inbound(view) => Some(&view.message_id),
        iroha_sccp::api::SccpMessageStatusV1::Outbound(view) => Some(&view.message_id),
        iroha_sccp::api::SccpMessageStatusV1::Unknown => None,
    };
    ensure!(
        observed_id.is_none_or(|id| id == message_id),
        "message status names another id"
    );
    context.print_data(&status)?;
    if !status.is_final() || flow.pending()?.is_some() {
        return Ok(false);
    }
    if flow.phase()? == iroha_sccp_wallet::flow::SccpFlowPhaseV1::Complete {
        return Ok(true);
    }
    let mut items = vec![evidence("taira.final_message_status", &status)?];
    bind_flow(flow, &mut items);
    let step = flow.prepare(
        SccpFlowActionV1::ObserveComplete,
        SccpNetworkV1::SoraTaira,
        Vec::new(),
        items.clone(),
    )?;
    step.complete(&SccpJournalOutcomeV1 {
        outcome: SccpStepOutcomeKindV1::Confirmed,
        transaction: message_id.to_vec(),
        evidence: items,
    })?;
    Ok(true)
}

fn drive_and_wait(
    context: &impl RunContext,
    step: &SccpJournalStep,
    rebroadcast: bool,
    mut observe: impl FnMut(&SccpJournalRecordV1) -> Result<Option<SccpJournalOutcomeV1>>,
    dispatch: impl FnMut(&[u8]) -> Result<()>,
) -> Result<Option<SccpJournalOutcomeV1>> {
    let config = context.sccp_config()?;
    let started = std::time::Instant::now();
    let mut outcome = drive_step_with_rebroadcast(step, rebroadcast, &mut observe, dispatch)?;
    while outcome.is_none() {
        let Some(remaining) = config.confirmation_timeout.checked_sub(started.elapsed()) else {
            break;
        };
        std::thread::sleep(config.poll_interval.min(remaining));
        // The original dispatch marker already exists. Waiting never rebroadcasts, signs,
        // advances a nonce or classifies a missing receipt as a failed transaction.
        outcome = drive_step_with_rebroadcast(step, false, &mut observe, |_| {
            Err(eyre!(
                "a waiting step unexpectedly lost its durable submission marker"
            ))
        })?;
    }
    Ok(outcome)
}

fn run_taira_step(
    context: &mut impl RunContext,
    step: &SccpJournalStep,
    rebroadcast: bool,
) -> Result<Option<SccpJournalOutcomeV1>> {
    let transaction = original_transaction(context, step.record())?;
    let native = context.client_from_config()?;
    let client = BlockingClient::from_client(native.clone())?;
    let outcome = drive_and_wait(
        context,
        step,
        rebroadcast,
        |_| {
            let status = native.get_transaction_status_response_global(transaction.hash())?;
            let Some(status) = status else {
                return Ok(None);
            };
            ensure!(
                status.hash == transaction.hash().to_string() && status.scope == "global",
                "status differs from the original global transaction"
            );
            let kind = match (status.status.kind.as_str(), status.resolved_from.as_str()) {
                ("Applied", "state") => SccpStepOutcomeKindV1::Confirmed,
                ("Rejected" | "Expired", "state") => SccpStepOutcomeKindV1::Failed,
                _ => return Ok(None),
            };
            let mut retained = vec![evidence("taira.transaction_status", &status)?];
            if kind == SccpStepOutcomeKindV1::Confirmed {
                ensure!(
                    status.status.block_height.is_some_and(|height| height > 0),
                    "Applied status lacks a committed height"
                );
                let details = native.get_transaction_details(transaction.hash_as_entrypoint())?;
                crate::transaction_journal::verify_committed(&transaction, &details)?;
                retained.push(evidence("taira.committed_transaction", &details)?);
            }
            Ok(Some(SccpJournalOutcomeV1 {
                outcome: kind,
                transaction: transaction.hash().as_ref().to_vec(),
                evidence: retained,
            }))
        },
        |wire| {
            ensure!(
                wire == transaction.encode_wire_v1()?,
                "dispatch bytes differ from original signed envelope"
            );
            let prepared = PreparedTransactionPayload::from_transaction(&transaction);
            ensure!(
                prepared.as_bytes() == wire,
                "SDK wire differs from the durable original"
            );
            let hash = client.submit_prepared_transaction_payload(&prepared)?;
            ensure!(
                hash == transaction.hash(),
                "submission returned a different transaction hash"
            );
            Ok(())
        },
    )?;
    print_outcome(context, &outcome, transaction.hash().as_ref())?;
    Ok(outcome)
}

pub(super) fn print_outcome(
    context: &mut impl RunContext,
    outcome: &Option<SccpJournalOutcomeV1>,
    hash: &[u8],
) -> Result<()> {
    context.print_data(&norito::json!({
        "transaction": (hex::encode(hash)),
        "state": (match outcome.as_ref().map(|outcome| outcome.outcome) {
            Some(SccpStepOutcomeKindV1::Confirmed) => "confirmed",
            Some(SccpStepOutcomeKindV1::Failed) => "failed",
            Some(SccpStepOutcomeKindV1::Superseded) => "superseded",
            None => "awaiting_reconciliation",
        }),
        "recovery": "reuse the same flow id; --rebroadcast permits only identical original bytes after reconciliation",
    }))
}

/// Retain a verified EVM call before signing/broadcasting and recover its exact receipt.
pub(super) fn evm<C: RunContext>(
    context: &mut C,
    original: &origin::AuthenticatedOrigin,
    flow: &Flow,
    action: SccpFlowActionV1,
    network: SccpNetworkV1,
    destination: &super::evm::EvmDestination,
    key_file: &std::path::Path,
    calldata: Vec<u8>,
    items: Vec<SccpEvidenceItemV1>,
) -> Result<Option<SccpJournalOutcomeV1>> {
    evm_call(
        context,
        original,
        flow,
        action,
        network,
        &destination.transport(),
        key_file,
        calldata,
        items,
    )
}

/// Journal one verified call target, including the fixed deterministic deployment proxy.
pub(super) fn evm_call<C: RunContext>(
    context: &mut C,
    original: &origin::AuthenticatedOrigin,
    flow: &Flow,
    action: SccpFlowActionV1,
    network: SccpNetworkV1,
    destination: &super::evm::EvmTransport<'_>,
    key_file: &std::path::Path,
    calldata: Vec<u8>,
    mut items: Vec<SccpEvidenceItemV1>,
) -> Result<Option<SccpJournalOutcomeV1>> {
    check_action_intent(flow, action)?;
    let digest = intent(&calldata);
    let previous = flow.find_intent(action, &digest)?;
    let previous = match previous {
        Some(step) if retry_allowed(flow, action, &step)? => None,
        other => other,
    };
    let step = if let Some(step) = previous {
        step
    } else {
        ensure!(
            flow.pending()?.is_none(),
            "recover the original pending step before preparing another"
        );
        let key = super::evm::load_key(key_file)?;
        let raw = destination.prepare(&key, calldata.clone())?;
        bind_intent(&mut items, digest);
        bind_flow(flow, &mut items);
        flow.prepare(action, network, raw, items)?
    };
    ensure!(
        step.record().chain == network,
        "the retained call belongs to another network"
    );
    destination.retained_hash(&step.record().submission, &calldata)?;
    run_evm_step(context, original, flow, &step, destination)
}

/// Reconcile retained bytes before requesting a fresh bundle that may now be stale.
pub(super) fn recover_evm(
    context: &mut impl RunContext,
    original: &origin::AuthenticatedOrigin,
    flow: &Flow,
    action: SccpFlowActionV1,
    destination: &super::evm::EvmDestination,
) -> Result<bool> {
    recover_evm_call(context, original, flow, action, &destination.transport())
}

pub(super) fn recover_evm_call(
    context: &mut impl RunContext,
    original: &origin::AuthenticatedOrigin,
    flow: &Flow,
    action: SccpFlowActionV1,
    destination: &super::evm::EvmTransport<'_>,
) -> Result<bool> {
    let Some(step) = flow.latest(action)? else {
        return Ok(false);
    };
    let outcome = run_evm_step(context, original, flow, &step, destination)?;
    if outcome.is_some()
        && (action == SccpFlowActionV1::Checkpoint || retry_allowed(flow, action, &step)?)
    {
        return Ok(false);
    }
    Ok(true)
}

fn run_evm_step(
    context: &mut impl RunContext,
    original: &origin::AuthenticatedOrigin,
    flow: &Flow,
    step: &SccpJournalStep,
    destination: &super::evm::EvmTransport<'_>,
) -> Result<Option<SccpJournalOutcomeV1>> {
    check_flow(flow, step)?;
    let signed = iroha_sccp_wallet::pure::evm::SignedEip1559V1::decode(&step.record().submission)
        .map_err(|error| eyre!("original EVM envelope: {error:?}"))?;
    let hash = destination.retained_hash(&step.record().submission, &signed.transaction.data)?;
    let outcome = drive_and_wait(
        context,
        step,
        flow.rebroadcast,
        |_| {
            let Some((receipt, mut proof_items)) = destination.receipt(&blocking(context)?, original, &step.record().submission)? else {
                return Ok(None);
            };
            ensure!(
                receipt.transaction_hash == hash,
                "receipt differs from the original transaction hash"
            );
            let kind = match receipt.status {
                Some(1) => SccpStepOutcomeKindV1::Confirmed,
                Some(0) => SccpStepOutcomeKindV1::Failed,
                _ => return Err(eyre!("receipt lacks a canonical success status")),
            };
            if kind == SccpStepOutcomeKindV1::Confirmed
                && step.record().action == SccpFlowActionV1::Finalize
            {
                let original = step
                    .record()
                    .evidence
                    .iter()
                    .find(|item| item.label == "taira.verified_message_bundle")
                    .ok_or_else(|| eyre!("original finalize lacks its retained message proof"))?;
                let bundle = norito::json::from_slice(&original.bytes)?;
                proof_items.extend(destination.confirm_finalized(&receipt, &bundle)?);
            }
            let locator = norito::json!({"transaction_hash": (hex::encode(hash)), "block_hash": (hex::encode(receipt.block_hash)), "block_number": (receipt.block_number), "transaction_index": (receipt.transaction_index)});
            Ok(Some(SccpJournalOutcomeV1 {
                outcome: kind,
                transaction: hash.to_vec(),
                evidence: {
                    proof_items.extend([
                    SccpEvidenceItemV1 {
                        label: "evm.receipt.rlp".to_owned(),
                        bytes: iroha_sccp_rpc::builders::ethereum::receipt_rlp(&receipt),
                    },
                    evidence("evm.receipt.locator", &locator)?,
                    ]);
                    proof_items
                },
            }))
        },
        |raw| {
            ensure!(
                destination.broadcast(raw)? == hash,
                "broadcast returned another transaction hash"
            );
            Ok(())
        },
    )?;
    print_outcome(context, &outcome, &hash)?;
    Ok(outcome)
}

/// Prepare one TON wallet envelope only after retaining its verified source evidence.
pub(super) fn ton(
    context: &mut impl RunContext,
    original: &origin::AuthenticatedOrigin,
    flow: &Flow,
    action: SccpFlowActionV1,
    lite: &iroha_sccp_rpc::ton::LiteClient,
    items: Vec<SccpEvidenceItemV1>,
    prepare: impl FnOnce(&mut Vec<SccpEvidenceItemV1>) -> Result<Vec<u8>>,
    observe: impl FnMut(&SccpJournalStep) -> Result<Option<Vec<SccpEvidenceItemV1>>>,
) -> Result<Option<SccpJournalOutcomeV1>> {
    ton_observed(
        context,
        original,
        flow,
        action,
        lite,
        items,
        prepare,
        observe,
        SccpStepOutcomeKindV1::Confirmed,
    )
}

/// Maintenance progress can supersede the need to retry; it does not prove mint/burn completion.
pub(super) fn ton_observed(
    context: &mut impl RunContext,
    original: &origin::AuthenticatedOrigin,
    flow: &Flow,
    action: SccpFlowActionV1,
    lite: &iroha_sccp_rpc::ton::LiteClient,
    items: Vec<SccpEvidenceItemV1>,
    prepare: impl FnOnce(&mut Vec<SccpEvidenceItemV1>) -> Result<Vec<u8>>,
    mut observe: impl FnMut(&SccpJournalStep) -> Result<Option<Vec<SccpEvidenceItemV1>>>,
    kind: SccpStepOutcomeKindV1,
) -> Result<Option<SccpJournalOutcomeV1>> {
    check_action_intent(flow, action)?;
    let previous = flow.latest(action)?;
    let previous = match previous {
        Some(step)
            if (action == SccpFlowActionV1::Checkpoint && step.outcome()?.is_some())
                || (action == SccpFlowActionV1::Control
                    && confirmed(&step.outcome()?)
                    && newer_prerequisite(&step.record().evidence, &items))
                || retry_allowed(flow, action, &step)? =>
        {
            None
        }
        other => other,
    };
    let step = if let Some(step) = previous {
        step
    } else {
        prepare_ton_original(flow, action, items, prepare)?
    };
    check_flow(flow, &step)?;
    ensure!(
        step.record().chain == SccpNetworkV1::TonMainnet,
        "original step is not TON"
    );
    let hash = iroha_sccp::ton_boc_single_root_hash_v1(&step.record().submission)
        .ok_or_else(|| eyre!("original TON envelope is not a single-root BoC"))?;
    let outcome = drive_and_wait(
        context,
        &step,
        flow.rebroadcast,
        |_| {
            retired_ton_outcome(observe(&step)?, kind, hash, || {
                super::ton::wallet_retirement(lite, &step.record().submission)
            })
        },
        |bytes| {
            ensure!(
                super::ton::broadcast(lite, bytes)? == hash,
                "TON original root changed"
            );
            Ok(())
        },
    )?;
    print_outcome(context, &outcome, &hash)?;
    if outcome.is_none() {
        let envelope = iroha_sccp_wallet::pure::ton::wallet_v5_envelope(&step.record().submission)?;
        if u64::from(envelope.valid_until) <= super::wall_clock_ms() / 1000 {
            context.println(format!("Original TON wallet seqno {} has deadline {}; execution remains unknown. Linked source-history discovery is retained. Expiry does not authorize a new sequence number or a second burn.", envelope.seqno, envelope.valid_until))?;
        }
    }
    Ok(outcome)
}

fn prepare_ton_original(
    flow: &Flow,
    action: SccpFlowActionV1,
    mut items: Vec<SccpEvidenceItemV1>,
    prepare: impl FnOnce(&mut Vec<SccpEvidenceItemV1>) -> Result<Vec<u8>>,
) -> Result<SccpJournalStep> {
    ensure!(
        flow.pending()?.is_none(),
        "recover the original pending step first"
    );
    let submission = prepare(&mut items)?;
    bind_flow(flow, &mut items);
    Ok(flow.prepare(action, SccpNetworkV1::TonMainnet, submission, items)?)
}

/// Another relayer's effect cannot free an original envelope that still owns its wallet nonce.
pub(super) fn retired_ton_outcome(
    observed: Option<Vec<SccpEvidenceItemV1>>,
    kind: SccpStepOutcomeKindV1,
    hash: [u8; 32],
    observe_retirement: impl FnOnce() -> Result<super::ton::WalletRetirement>,
) -> Result<Option<SccpJournalOutcomeV1>> {
    let Some(mut evidence) = observed else {
        return Ok(None);
    };
    let retirement = observe_retirement()?;
    if !retirement.retired() {
        return Ok(None);
    }
    evidence.push(self::evidence(
        "ton.original_wallet_retirement",
        &retirement,
    )?);
    Ok(Some(SccpJournalOutcomeV1 {
        outcome: kind,
        transaction: hash.to_vec(),
        evidence,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ton_preparation_retains_burn_preflight_before_any_dispatch_and_recovery() {
        let base =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sccp-continuation");
        std::fs::create_dir_all(&base).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("ton-preflight-")
            .tempdir_in(base)
            .unwrap();
        let network = iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([12; 32])),
        );
        let flow = Flow {
            journal: SccpFlowV1::open(
                SccpJournalRoot::open(&dir.path().join("journal"))
                    .unwrap()
                    .network(&network)
                    .unwrap()
                    .flow(&SccpFlowIdV1 {
                        kind: SccpFlowKindV1::Inbound,
                        id: [11; 32],
                    })
                    .unwrap(),
                *network.as_bytes(),
            )
            .unwrap(),
            rebroadcast: false,
            retry: false,
            intent: [11; 32],
        };
        let preflight = evidence(
            "taira.original_burn_preflight",
            &norito::json!({"generation": 7}),
        )
        .unwrap();
        assert!(
            prepare_ton_original(&flow, SccpFlowActionV1::Burn, Vec::new(), |_| {
                Err(eyre!("stale original light client"))
            })
            .is_err()
        );
        assert!(flow.latest(SccpFlowActionV1::Burn).unwrap().is_none());
        let step = prepare_ton_original(
            &flow,
            SccpFlowActionV1::Burn,
            vec![evidence("verified.burn_intent", &norito::json!({"amount": "15"})).unwrap()],
            |items| {
                items.push(preflight.clone());
                Ok(vec![1, 2, 3])
            },
        )
        .unwrap();
        let original = step.record().clone();
        assert!(original.evidence.contains(&preflight));
        assert!(!step.submission_recorded().unwrap());
        check_flow(&flow, &step).unwrap();
        step.begin_submission().unwrap();
        drop(step);
        assert!(
            prepare_ton_original(&flow, SccpFlowActionV1::Burn, Vec::new(), |_| {
                panic!("recovery cannot refresh preflight or sign replacement bytes")
            })
            .is_err()
        );
        let retained = flow.latest(SccpFlowActionV1::Burn).unwrap().unwrap();
        assert_eq!(retained.record(), &original);
        assert!(!retained.begin_submission().unwrap());
    }
    #[test]
    fn flow_intent_is_domain_separated_and_exact() {
        use sha2::{Digest as _, Sha256};
        assert_ne!(intent(b"a"), Sha256::digest(b"a").as_slice());
        assert_ne!(intent(b"a"), intent(b"a\0"));
        assert_eq!(intent(b"a"), intent(b"a"));
        let item = evidence("source", &norito::json!({"nonce": 3})).unwrap();
        assert_eq!(item.label, "source");
        assert_eq!(
            norito::json::from_slice::<norito::json::Value>(&item.bytes).unwrap()["nonce"].as_u64(),
            Some(3)
        );
        assert!(!confirmed(&None));
    }

    #[test]
    fn original_action_intent_remains_exact_after_terminal_retry() {
        let original = intent(b"original recipient and amount");
        let item = SccpEvidenceItemV1 {
            label: "sccp.flow.intent".to_owned(),
            bytes: original.to_vec(),
        };
        assert!(check_intent(std::slice::from_ref(&item), &original).is_ok());
        assert!(
            check_intent(
                std::slice::from_ref(&item),
                &intent(b"replacement recipient")
            )
            .is_err()
        );
        assert!(check_intent(&[], &original).is_err());
        assert!(check_intent(&[item.clone(), item], &original).is_err());
        let target = |n: u64| SccpEvidenceItemV1 {
            label: "sccp.prerequisite.target".to_owned(),
            bytes: n.to_be_bytes().to_vec(),
        };
        assert!(newer_prerequisite(&[target(1)], &[target(2)]));
        assert!(!newer_prerequisite(&[target(2)], &[target(2)]));
        assert!(!newer_prerequisite(&[target(2)], &[target(1)]));
        assert!(!newer_prerequisite(&[target(0)], &[target(1)]));
        assert!(!newer_prerequisite(&[], &[target(1)]));
    }
}
