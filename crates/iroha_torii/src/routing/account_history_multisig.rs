//! Account-history movements from immutable native multisig execution records.
//!
//! These are display projections from the same committed State view as the
//! enclosing history page. They are not a substitute for client/Core finality
//! verification of the execution transaction and its authenticated State proof.

use std::str::FromStr;

use iroha_core::{
    smartcontracts::isi::multisig::{
        multisig_approval_outcome_state_key, multisig_proposal_terminal_execution_state_key,
    },
    state::WorldReadOnly,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    asset::AssetId,
    events::data::prelude::{AssetBatchTransferLegStatus, AssetBatchTransferOutcome},
    isi::{BurnBox, InstructionBox, MintBox, TransferBox},
};
use iroha_executor_data_model::isi::multisig::{
    MultisigApprovalOutcomeStatusV1, MultisigApprovalOutcomeV1, MultisigProposalId,
    MultisigProposalTerminalExecutionStateV1, MultisigProposalTerminalStatus,
};
use iroha_model_base::state_path::StatePath;
use mv::storage::StorageReadOnly as _;

use super::{
    AccountHistoryIndex, AccountHistoryProjection, AccountHistoryTxBase, HistoryTransaction,
    Result, account_history_movements_from_instruction, account_history_push_directional,
    account_history_tx_base, append_account_history_projection, conversion_error,
    history_capacity_error,
};

/// Additional immutable-record work allowed for one complete history page.
///
/// Share this across every visited transaction, including transactions/rows
/// excluded by the requested account, asset, filter or continuation coordinate.
pub(super) struct MultisigHistoryBudget {
    work_left: u64,
    bytes_left: u64,
}

impl MultisigHistoryBudget {
    /// Use the page's existing raw-row work and transaction-history byte limits.
    pub(super) fn new(work: u64, bytes: u64) -> Self {
        Self {
            work_left: work,
            bytes_left: bytes,
        }
    }

    fn require_work(&self, count: usize) -> Result<()> {
        let count = u64::try_from(count).map_err(|_| history_capacity_error())?;
        if count > self.work_left {
            return Err(history_capacity_error());
        }
        Ok(())
    }

    fn charge_work(&mut self, count: usize) -> Result<()> {
        self.require_work(count)?;
        self.work_left -= count as u64;
        Ok(())
    }

    fn charge_original(&mut self, bytes: &[u8]) -> Result<()> {
        // Match the native multisig execution-proof original bound. Reject
        // before parsing a dynamic InstructionBox graph or copying any bytes.
        const MAX_ORIGINAL_BYTES: usize = 64 * 1024;
        if bytes.len() > MAX_ORIGINAL_BYTES {
            return Err(history_capacity_error());
        }
        let length = u64::try_from(bytes.len()).map_err(|_| history_capacity_error())?;
        self.bytes_left = self
            .bytes_left
            .checked_sub(length)
            .ok_or_else(history_capacity_error)?;
        Ok(())
    }
}

fn decode_original<T>(bytes: &[u8], budget: &mut MultisigHistoryBudget) -> Result<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    budget.charge_original(bytes)?;
    let value: T =
        norito::with_decode_limits_scope(norito::canonical_decode_limits(bytes.len()), || {
            norito::decode_from_bytes(bytes)
        })
        .map_err(|error| {
            conversion_error(format!("invalid native multisig history original: {error}"))
        })?;
    // The native writers use to_bytes. Stream that exact re-encoding over the
    // retained frame instead of allocating a second original-sized buffer.
    norito::verify_exact_frame(&value, bytes).map_err(|error| {
        conversion_error(format!(
            "noncanonical native multisig history original: {error}"
        ))
    })?;
    Ok(value)
}

fn validate_execution(
    key: &StatePath,
    execution: &MultisigProposalTerminalExecutionStateV1,
    entrypoint_hash: [u8; Hash::LENGTH],
    height: u64,
    network_id: &NetworkId,
) -> Result<()> {
    let terminal = &execution.terminal;
    let proposal = &terminal.proposal;
    let actual_hash = HashOf::try_new(&proposal.instructions).map_err(|error| {
        conversion_error(format!("invalid native multisig instruction hash: {error}"))
    })?;
    if execution.terminal_entrypoint_hash != entrypoint_hash
        || execution.terminal_block_height != height
        || execution.entrypoint_account_id != terminal.multisig_account_id
        || proposal.network_id != *network_id
        || proposal.proposal_id != terminal.proposal_id
        || MultisigProposalId::derive(
            network_id,
            &terminal.multisig_account_id,
            &proposal.proposal_nonce,
        ) != terminal.proposal_id
        || terminal.instructions_hash != actual_hash
        || proposal.expires_at_ms < proposal.proposed_at_ms
        || proposal.transaction_ttl_ms.is_some_and(|ttl| {
            proposal.proposed_at_ms.checked_add(ttl.get()) != Some(proposal.expires_at_ms)
        })
        || multisig_proposal_terminal_execution_state_key(
            entrypoint_hash,
            &terminal.multisig_account_id,
            &terminal.proposal_id,
        ) != *key
    {
        return Err(conversion_error(
            "native multisig history execution binding mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_executed_outcome(
    execution: &MultisigProposalTerminalExecutionStateV1,
    outcome: &MultisigApprovalOutcomeV1,
) -> Result<()> {
    let terminal = &execution.terminal;
    if outcome.status != MultisigApprovalOutcomeStatusV1::Executed
        || outcome.entrypoint_account_id != execution.entrypoint_account_id
        || outcome.resolved_multisig_account_id != terminal.multisig_account_id
        || outcome.proposal_id != terminal.proposal_id
        || outcome.instructions_hash != terminal.instructions_hash
        || outcome.entrypoint_hash != execution.terminal_entrypoint_hash
        || outcome.block_height != execution.terminal_block_height
    {
        return Err(conversion_error(
            "native multisig history executed outcome mismatch".into(),
        ));
    }
    Ok(())
}

/// Bound the existing pure movement projector before it allocates its output.
///
/// Never feed it CustomInstruction: a nested proposal is intent, and a nested
/// approval's actual effects are represented by its own immutable execution
/// record in the same entrypoint prefix. This also prevents double projection.
fn direct_movement_bound(instruction: &InstructionBox) -> usize {
    let any = instruction.as_any();
    if any.is::<TransferBox>() {
        return 2;
    }
    if any.is::<MintBox>() || any.is::<BurnBox>() {
        return 1;
    }
    // Both Atomic and Independent batches produce committed receipts. Their
    // effects are projected exactly once at transaction level, never here.
    0
}

fn append_applied_batch_outcomes(
    index: &mut AccountHistoryIndex,
    base: &AccountHistoryTxBase,
    receipts: &[AssetBatchTransferOutcome],
    budget: &mut MultisigHistoryBudget,
) -> Result<()> {
    // Rejected entries still consume work. Receipts are already decoded and
    // byte-charged by the committed transaction carrier read.
    budget.charge_work(receipts.len())?;
    for (receipt_index, receipt) in receipts.iter().enumerate() {
        if receipt.status != AssetBatchTransferLegStatus::Applied {
            continue;
        }
        let from = receipt.asset.account();
        let to = &receipt.destination;
        let count = if from == to { 1 } else { 2 };
        budget.charge_work(count)?;
        let destination_asset = AssetId::new(receipt.asset.definition().clone(), to.clone());
        let mut movements = Vec::with_capacity(count);
        account_history_push_directional(
            &mut movements,
            from,
            to,
            (
                Some(receipt.asset.to_string()),
                Some(destination_asset.to_string()),
            ),
            Some(receipt.asset.definition().to_string()),
            Some(receipt.amount.to_string()),
            "TRANSFER",
        );
        for (leaf_index, movement) in movements.into_iter().enumerate() {
            // Receipt position is global within the actual execution result.
            // leg_index restarts per batch and leg_id may repeat across batches.
            // Never deduplicate matching payloads or infer an occurrence owner.
            let id = format!(
                "{}:batch:{}:{}:{}",
                base.tx_hash, receipt_index, leaf_index, movement.account
            );
            append_account_history_projection(
                index,
                AccountHistoryProjection {
                    id,
                    source: "transaction".to_owned(),
                    history_type: movement.history_type.to_owned(),
                    timestamp_ms: base.timestamp_ms,
                    status: base.status.clone(),
                    result_ok: Some(base.result_ok),
                    direction: movement.direction.to_owned(),
                    account_id: movement.account.to_string(),
                    counterparty_account_id: movement
                        .counterparty
                        .map(|account| account.to_string()),
                    asset_id: movement.asset_id,
                    asset_definition_id: movement.asset_definition_id,
                    amount: movement.amount,
                    tx_hash: Some(base.tx_hash.clone()),
                    block_height: Some(base.block_height),
                    operation_id: None,
                    expires_at_ms: None,
                    finalized_at_ms: None,
                    requesting_fi_id: None,
                },
            );
        }
    }
    Ok(())
}

/// Append actual executed multisig movements after ordinary transaction rows.
///
/// The caller must propagate errors and discard the page, never return a
/// partially projected success. The same State view must supply both history
/// transactions and `world`; one budget must span the entire page.
pub(super) fn append_executed_multisig_history(
    index: &mut AccountHistoryIndex,
    tx: &impl HistoryTransaction,
    height: u64,
    world: &impl WorldReadOnly,
    network_id: &NetworkId,
    budget: &mut MultisigHistoryBudget,
) -> Result<()> {
    if tx.result().as_ref().is_err() {
        return Ok(());
    }
    let entrypoint_hash = *tx.entrypoint_hash().as_ref();
    let prefix = StatePath::from_str(&format!(
        "multisig/proposal-terminal-execution/{}/",
        Hash::prehashed(entrypoint_hash),
    ))
    .map_err(|error| conversion_error(format!("invalid multisig history prefix: {error}")))?;
    let base = account_history_tx_base(tx, height);
    append_applied_batch_outcomes(index, &base, tx.result().batch_transfer_outcomes(), budget)?;
    for (key, bytes) in world.smart_contract_state().range(prefix.clone()..) {
        if !key.as_ref().starts_with(prefix.as_ref()) {
            break;
        }
        budget.charge_work(1)?;
        let execution: MultisigProposalTerminalExecutionStateV1 = decode_original(bytes, budget)?;
        budget.charge_work(execution.terminal.proposal.instructions.len())?;
        validate_execution(key, &execution, entrypoint_hash, height, network_id)?;
        if execution.terminal.status != MultisigProposalTerminalStatus::Finalized {
            continue;
        }
        let terminal = &execution.terminal;
        let outcome_key = multisig_approval_outcome_state_key(
            entrypoint_hash,
            &execution.entrypoint_account_id,
            &terminal.proposal_id,
        );
        let outcome_bytes = world
            .smart_contract_state()
            .get(&outcome_key)
            .ok_or_else(|| {
                conversion_error(
                    "finalized multisig history occurrence has no executed outcome".into(),
                )
            })?;
        budget.charge_work(1)?;
        let outcome: MultisigApprovalOutcomeV1 = decode_original(outcome_bytes, budget)?;
        validate_executed_outcome(&execution, &outcome)?;
        for (instruction_index, instruction) in terminal.proposal.instructions.iter().enumerate() {
            let bound = direct_movement_bound(instruction);
            if bound == 0 {
                continue;
            }
            budget.require_work(bound)?;
            let movements = account_history_movements_from_instruction(instruction);
            if movements.len() > bound {
                return Err(history_capacity_error());
            }
            budget.charge_work(movements.len())?;
            for (leaf_index, movement) in movements.into_iter().enumerate() {
                // Identity is independent of filter/page size and stable after
                // replay/restart. The occurrence distinguishes equal payloads.
                let id = format!(
                    "{}:multisig:{}:{}:{}:{}:{}",
                    base.tx_hash,
                    terminal.multisig_account_id,
                    terminal.proposal_id,
                    instruction_index,
                    leaf_index,
                    movement.account,
                );
                append_account_history_projection(
                    index,
                    AccountHistoryProjection {
                        id,
                        source: "transaction".to_owned(),
                        history_type: movement.history_type.to_owned(),
                        timestamp_ms: base.timestamp_ms,
                        status: base.status.clone(),
                        result_ok: Some(base.result_ok),
                        direction: movement.direction.to_owned(),
                        account_id: movement.account.to_string(),
                        counterparty_account_id: movement
                            .counterparty
                            .map(|account| account.to_string()),
                        asset_id: movement.asset_id,
                        asset_definition_id: movement.asset_definition_id,
                        amount: movement.amount,
                        tx_hash: Some(base.tx_hash.clone()),
                        block_height: Some(base.block_height),
                        operation_id: None,
                        expires_at_ms: None,
                        finalized_at_ms: None,
                        requesting_fi_id: None,
                    },
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        asset::AssetDefinitionId,
        events::data::prelude::{AssetBatchTransferRejection, AssetBatchTransferRejectionCode},
        isi::TransferAssetBatch,
    };
    use iroha_executor_data_model::isi::multisig::{
        MultisigProposalNonce, MultisigProposalTerminalState, MultisigProposalValue,
    };

    fn execution_fixture() -> (StatePath, MultisigProposalTerminalExecutionStateV1) {
        let account = iroha_test_samples::ALICE_ID.clone();
        let network_id = super::super::routing_test_network_id(0x63);
        let proposal_nonce = MultisigProposalNonce::new([0x71; 32]).unwrap();
        let proposal_id = MultisigProposalId::derive(&network_id, &account, &proposal_nonce);
        let instructions = Vec::new();
        let terminal = MultisigProposalTerminalState {
            multisig_account_id: account.clone(),
            proposal_id,
            instructions_hash: HashOf::try_new(&instructions).unwrap(),
            proposal: MultisigProposalValue {
                network_id,
                proposal_nonce,
                proposal_id,
                transaction_ttl_ms: None,
                instructions,
                proposed_at_ms: 100,
                expires_at_ms: 200,
                approvals: Default::default(),
            },
            status: MultisigProposalTerminalStatus::Finalized,
            terminal_at_ms: 150,
        };
        let key =
            multisig_proposal_terminal_execution_state_key([0x33; 32], &account, &proposal_id);
        (
            key,
            MultisigProposalTerminalExecutionStateV1::new(terminal, account, 65, [0x33; 32]),
        )
    }

    #[test]
    fn page_budget_is_shared_and_originals_are_bounded_before_decode() {
        let mut budget = MultisigHistoryBudget::new(3, 4);
        budget.charge_work(1).unwrap();
        budget.charge_work(2).unwrap();
        assert!(budget.charge_work(1).is_err());
        budget.charge_original(&[0; 3]).unwrap();
        assert!(budget.charge_original(&[0; 2]).is_err());
        let mut budget = MultisigHistoryBudget::new(1, u64::MAX);
        assert!(budget.charge_original(&vec![0; 64 * 1024 + 1]).is_err());
    }

    #[test]
    fn originals_reject_invalid_frames_and_roundtrip_exact_native_writes() {
        let (_, execution) = execution_fixture();
        let bytes = norito::to_bytes(&execution).unwrap();
        let mut budget = MultisigHistoryBudget::new(20, 1024 * 1024);
        let decoded: MultisigProposalTerminalExecutionStateV1 =
            decode_original(&bytes, &mut budget).unwrap();
        assert_eq!(decoded.terminal.proposal_id, execution.terminal.proposal_id);
        assert!(
            decode_original::<MultisigProposalTerminalExecutionStateV1>(&[0; 5], &mut budget)
                .is_err()
        );
        let mut suffixed = bytes;
        suffixed.push(0);
        assert!(
            decode_original::<MultisigProposalTerminalExecutionStateV1>(&suffixed, &mut budget)
                .is_err()
        );
    }

    #[test]
    fn execution_is_bound_to_exact_key_network_height_and_occurrence() {
        let (key, execution) = execution_fixture();
        let network = execution.terminal.proposal.network_id.clone();
        validate_execution(&key, &execution, [0x33; 32], 65, &network).unwrap();
        assert!(validate_execution(&key, &execution, [0x34; 32], 65, &network).is_err());
        assert!(validate_execution(&key, &execution, [0x33; 32], 66, &network).is_err());
        let wrong_network = super::super::routing_test_network_id(0x64);
        assert!(validate_execution(&key, &execution, [0x33; 32], 65, &wrong_network).is_err());
        let mut wrong_nonce = execution.clone();
        wrong_nonce.terminal.proposal.proposal_nonce =
            MultisigProposalNonce::new([0x72; 32]).unwrap();
        assert!(validate_execution(&key, &wrong_nonce, [0x33; 32], 65, &network).is_err());
        let wrong_key = StatePath::from_str("multisig/proposal-terminal-execution/wrong").unwrap();
        assert!(validate_execution(&wrong_key, &execution, [0x33; 32], 65, &network).is_err());
    }

    #[test]
    fn finalized_terminal_alone_and_nonexecuting_outcome_cannot_credit() {
        let (_, execution) = execution_fixture();
        let mut outcome = MultisigApprovalOutcomeV1::new(
            execution.entrypoint_account_id.clone(),
            execution.terminal.multisig_account_id.clone(),
            execution.terminal.proposal_id,
            execution.terminal.instructions_hash,
            MultisigApprovalOutcomeStatusV1::Executed,
            65,
            [0x33; 32],
        );
        validate_executed_outcome(&execution, &outcome).unwrap();
        outcome.status = MultisigApprovalOutcomeStatusV1::NotExecuted;
        assert!(validate_executed_outcome(&execution, &outcome).is_err());
        outcome.status = MultisigApprovalOutcomeStatusV1::Executed;
        outcome.block_height = 66;
        assert!(validate_executed_outcome(&execution, &outcome).is_err());
    }

    fn batch_receipt_fixture() -> AssetBatchTransferOutcome {
        let definition = AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("history", "universal").unwrap(),
            "coin".parse().unwrap(),
        );
        AssetBatchTransferOutcome {
            leg_index: 0,
            leg_id: "same-leg-id-in-distinct-batches".into(),
            asset: AssetId::new(definition, iroha_test_samples::ALICE_ID.clone()),
            destination: iroha_test_samples::BOB_ID.clone(),
            amount: 20u32.into(),
            status: AssetBatchTransferLegStatus::Applied,
        }
    }

    fn batch_base() -> AccountHistoryTxBase {
        AccountHistoryTxBase {
            timestamp_ms: Some(150),
            tx_hash: "actual-execution".into(),
            result_ok: true,
            status: "SUCCESS".into(),
            block_height: 65,
        }
    }

    #[test]
    fn batch_receipts_project_only_applied_and_preserve_identical_executions() {
        let applied = batch_receipt_fixture();
        let mut rejected = applied.clone();
        rejected.status = AssetBatchTransferLegStatus::Rejected(AssetBatchTransferRejection {
            code: AssetBatchTransferRejectionCode::InsufficientFunds,
            message: "fixture rejection".into(),
        });
        let mut index = AccountHistoryIndex::default();
        let mut budget = MultisigHistoryBudget::new(7, 0);
        append_applied_batch_outcomes(
            &mut index,
            &batch_base(),
            &[applied.clone(), rejected, applied],
            &mut budget,
        )
        .unwrap();
        assert_eq!(index.items.len(), 4);
        assert!(
            index
                .items
                .iter()
                .all(|row| row.result_ok == Some(true) && row.amount.as_deref() == Some("20"))
        );
        assert_eq!(
            index
                .items
                .iter()
                .filter(|row| row.direction == "incoming")
                .count(),
            2
        );
        assert!(index.items[0].id.contains(":batch:0:0:"));
        assert!(index.items[2].id.contains(":batch:2:0:"));
        assert_ne!(index.items[0].id, index.items[2].id);
        assert_eq!(budget.work_left, 0);
        let receipt = batch_receipt_fixture();
        let destination_asset = AssetId::new(
            receipt.asset.definition().clone(),
            receipt.destination.clone(),
        );
        assert_eq!(
            index.items[1].asset_id.as_deref(),
            Some(destination_asset.to_string().as_str())
        );
        assert_eq!(
            index.items[1].asset_definition_id.as_deref(),
            Some(receipt.asset.definition().to_string().as_str())
        );
        assert_eq!(
            index.items[1].counterparty_account_id.as_deref(),
            Some(receipt.asset.account().to_string().as_str())
        );
    }

    #[test]
    fn receipt_projection_checks_work_before_allocating_movements_and_handles_self() {
        let applied = batch_receipt_fixture();
        let mut index = AccountHistoryIndex::default();
        let mut insufficient = MultisigHistoryBudget::new(2, 0);
        assert!(
            append_applied_batch_outcomes(
                &mut index,
                &batch_base(),
                std::slice::from_ref(&applied),
                &mut insufficient,
            )
            .is_err()
        );
        assert!(index.items.is_empty());
        let mut self_receipt = applied;
        self_receipt.destination = self_receipt.asset.account().clone();
        let mut exact = MultisigHistoryBudget::new(2, 0);
        append_applied_batch_outcomes(&mut index, &batch_base(), &[self_receipt], &mut exact)
            .unwrap();
        assert_eq!(index.items.len(), 1);
        assert_eq!(index.items[0].direction, "self");
    }

    #[test]
    fn both_batch_modes_are_excluded_from_instruction_projection() {
        let atomic: InstructionBox = TransferAssetBatch::new(Vec::new()).into();
        let independent: InstructionBox = TransferAssetBatch::independent(Vec::new()).into();
        assert_eq!(direct_movement_bound(&atomic), 0);
        assert_eq!(direct_movement_bound(&independent), 0);
    }
}
