//! Native journal receipts authenticated by the caller's retained Global decision prefix.

use super::origin::AuthenticatedOrigin;
use eyre::{Result, ensure, eyre};
use iroha::client::Client;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    sumeragi_finality::SumeragiFinalityProof,
    transaction::{SignedTransaction, TransactionEntrypoint},
};
use iroha_sccp_wallet::journal::{SccpEvidenceItemV1, SccpJournalOutcomeV1, SccpStepOutcomeKindV1};
use iroha_torii_shared::{PipelineTransactionDetailsResponse, PipelineTransactionStatusResponse};
use std::num::NonZeroU64;

pub(super) fn observe(
    native: &Client,
    original: &AuthenticatedOrigin,
    transaction: &SignedTransaction,
) -> Result<Option<SccpJournalOutcomeV1>> {
    let Some(status) = native.get_transaction_status_response_global(transaction.hash())? else {
        return Ok(None);
    };
    let Some(height) = candidate_height(original.height(), transaction, &status)? else {
        return Ok(None);
    };
    let proof = native.get_sumeragi_finality_proof(height, SumeragiRootScope::Global)?;
    let details = native.get_transaction_details(transaction.hash_as_entrypoint())?;
    verify_receipt(original, transaction, &status, &proof, &details).map(Some)
}

fn candidate_height(
    original_height: u64,
    transaction: &SignedTransaction,
    status: &PipelineTransactionStatusResponse,
) -> Result<Option<NonZeroU64>> {
    ensure!(
        status.hash == transaction.hash().to_string() && status.scope == "global",
        "status differs from the original global transaction"
    );
    if status.resolved_from != "state"
        || !matches!(status.status.kind.as_str(), "Applied" | "Rejected")
    {
        return Ok(None);
    }
    // An unproven expiry or a response newer than the selected cut cannot retire signed work.
    Ok(status
        .status
        .block_height
        .filter(|height| (2..=original_height).contains(height))
        .and_then(NonZeroU64::new))
}

fn verify_receipt(
    original: &AuthenticatedOrigin,
    transaction: &SignedTransaction,
    status: &PipelineTransactionStatusResponse,
    proof: &SumeragiFinalityProof,
    details: &PipelineTransactionDetailsResponse,
) -> Result<SccpJournalOutcomeV1> {
    let height = candidate_height(original.height(), transaction, status)?
        .ok_or_else(|| eyre!("status supplies no candidate inside the original certified cut"))?;
    ensure!(
        proof.height() == height.get(),
        "finality proof differs from the candidate height"
    );
    let block = original.verify_retained_block(proof)?;
    let network = transaction
        .network_id()
        .ok_or_else(|| eyre!("signed transaction lacks its original network"))?;
    ensure!(
        *network.as_bytes() == original.network,
        "signed transaction belongs to another original network"
    );
    ensure!(
        details.hash == transaction.hash_as_entrypoint().to_string(),
        "committed detail locator differs"
    );
    let TransactionEntrypoint::External(committed) = details.transaction.entrypoint() else {
        return Err(eyre!("committed receipt is not an external transaction"));
    };
    ensure!(
        committed.hash() == transaction.hash()
            && committed.hash_as_entrypoint() == transaction.hash_as_entrypoint()
            && committed.encode_wire_v1()? == transaction.encode_wire_v1()?,
        "committed receipt differs from the exact retained signed envelope"
    );
    block.verify_transaction_execution(network, &details.transaction)?;
    let outcome = SccpJournalOutcomeV1 {
        outcome: if details.transaction.result().is_ok() {
            SccpStepOutcomeKindV1::Confirmed
        } else {
            SccpStepOutcomeKindV1::Failed
        },
        transaction: transaction.hash().as_ref().to_vec(),
        evidence: vec![
            evidence("taira.original_cut", &original.receipt_cut())?,
            evidence("taira.transaction_status", status)?,
            evidence("taira.finality_proof", proof)?,
            evidence("taira.committed_transaction", details)?,
        ],
    };
    // Bound the complete retained evidence before the journal can publish a terminal result.
    iroha_operation_journal::canonical_bytes(&outcome)?;
    Ok(outcome)
}

fn evidence(
    label: &str,
    value: &(impl norito::json::JsonSerialize + ?Sized),
) -> Result<SccpEvidenceItemV1> {
    Ok(SccpEvidenceItemV1 {
        label: label.to_owned(),
        bytes: iroha_operation_journal::canonical_bytes(value)?.into_vec(),
    })
}

#[cfg(test)]
mod tests;
