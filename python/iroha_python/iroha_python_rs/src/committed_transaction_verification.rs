//! Native checkpoint authentication of a Python consumer's exact committed output.

use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    query::CommittedTransaction,
    sumeragi_finality::{
        SumeragiFinalityCheckpoint, SumeragiFinalityProof, VerifiedFinalityPage,
        verify_checkpoint_page,
    },
    transaction::TransactionEntrypoint,
};
use norito::json;
use pyo3::{PyResult, exceptions::PyValueError};

const MAX_FINALITY_CHAIN_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_FINALITY_CHAIN_PROOFS: usize = 4096;
const MAX_CHECKPOINT_BYTES: usize = 68 * 1024 * 1024;

pub(super) fn authenticate_committed_transaction(
    expected: HashOf<TransactionEntrypoint>,
    transaction_response_bytes: &[u8],
    native_finality_proof_chain_json: &str,
    expected_network_id: NetworkId,
    expected_chain: &str,
    trusted_checkpoint: &[u8],
) -> PyResult<(CommittedTransaction, VerifiedFinalityPage)> {
    authenticate_selected_response(
        expected,
        transaction_response_bytes,
        native_finality_proof_chain_json,
        expected_network_id,
        expected_chain,
        trusted_checkpoint,
        super::decode_single_committed_transaction,
    )
}

pub(super) fn authenticate_selected_response(
    expected: HashOf<TransactionEntrypoint>,
    transaction_response_bytes: &[u8],
    native_finality_proof_chain_json: &str,
    expected_network_id: NetworkId,
    expected_chain: &str,
    trusted_checkpoint: &[u8],
    decode_response: impl FnOnce(&[u8]) -> PyResult<CommittedTransaction>,
) -> PyResult<(CommittedTransaction, VerifiedFinalityPage)> {
    if native_finality_proof_chain_json.is_empty()
        || native_finality_proof_chain_json.len() > MAX_FINALITY_CHAIN_JSON_BYTES
    {
        return Err(PyValueError::new_err(
            "native finality proof chain must contain 1..16 MiB",
        ));
    }
    if transaction_response_bytes.is_empty() || transaction_response_bytes.len() > 32 * 1024 * 1024
    {
        return Err(PyValueError::new_err(
            "selective query response must contain 1..32 MiB",
        ));
    }
    if expected_chain.is_empty() || expected_chain.len() > 1024 {
        return Err(PyValueError::new_err(
            "expected chain must contain 1..1024 UTF-8 bytes",
        ));
    }
    if trusted_checkpoint.is_empty() || trusted_checkpoint.len() > MAX_CHECKPOINT_BYTES {
        return Err(PyValueError::new_err(
            "trusted checkpoint must contain 1..68 MiB",
        ));
    }
    let checkpoint =
        SumeragiFinalityCheckpoint::decode_canonical(trusted_checkpoint).map_err(|error| {
            PyValueError::new_err(format!(
                "invalid independently selected checkpoint: {error}"
            ))
        })?;
    if checkpoint.chain_id() != expected_chain {
        return Err(PyValueError::new_err(
            "checkpoint differs from independently selected chain",
        ));
    }
    let proofs: Vec<SumeragiFinalityProof> = json::from_json(native_finality_proof_chain_json)
        .map_err(|error| {
            PyValueError::new_err(format!("invalid native finality proof chain: {error}"))
        })?;
    if proofs.is_empty() || proofs.len() > MAX_FINALITY_CHAIN_PROOFS {
        return Err(PyValueError::new_err(
            "native finality chain must contain 1..4096 proofs",
        ));
    }
    let page = verify_checkpoint_page(
        expected_network_id,
        &checkpoint,
        &proofs,
        MAX_FINALITY_CHAIN_PROOFS,
        MAX_FINALITY_CHAIN_JSON_BYTES,
    )
    .map_err(|error| {
        PyValueError::new_err(format!("native finality authentication failed: {error}"))
    })?;
    let tip = page.tip();
    let committed = decode_response(transaction_response_bytes)?;
    if committed.entrypoint_hash != expected {
        return Err(PyValueError::new_err(
            "committed transaction does not match requested transaction hash",
        ));
    }
    // Rejections remain authentic evidence. Require original full-wire inclusion as
    // well as the selective commitments authenticated by this native capability.
    if !committed.verify_selective_in_authenticated_execution(
        &expected_network_id,
        &tip.header(),
        tip.execution(),
    ) || !committed.verify_inclusion_in_block(tip.block())
    {
        return Err(PyValueError::new_err(
            "committed transaction does not verify against authenticated execution",
        ));
    }
    Ok((committed, page))
}

#[cfg(test)]
#[path = "tests/committed_transaction_verification_tests.rs"]
mod tests;
