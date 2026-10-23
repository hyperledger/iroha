//! Current selective committed-transaction proof for mobile clients.
//!
//! The Torii response is only a candidate. The caller must pin both the native
//! NetworkId, chain label and canonical checkpoint independently of that response.

use std::{ptr, slice};

use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    query::{CommittedTransaction, QueryOutputBatchBox, QueryResponse},
    sumeragi_finality::{
        MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint, SumeragiFinalityProof,
        verify_checkpoint_page,
    },
    transaction::TransactionEntrypoint,
};
use libc::{c_int, c_uchar, c_ulong};
use norito::json;

pub(crate) const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_ROW_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_ORIGINAL_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_CHAIN_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_CHAIN_PROOFS: usize = 4096;
const ERR_COMMITTED_INCLUSION: c_int = -508;

pub(crate) struct VerifiedCommittedTransaction {
    pub row: Vec<u8>,
    pub checkpoint: Vec<u8>,
    pub output_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub block_height: u64,
    pub block_creation_time_ms: u64,
    pub global_root: bool,
    pub result_ok: bool,
}

fn decode_candidate_response(
    response_bytes: &[u8],
) -> Result<Option<CommittedTransaction>, String> {
    let response: QueryResponse = norito::decode_canonical_with_limits(
        response_bytes,
        norito::canonical_decode_limits(response_bytes.len()),
    )
    .map_err(|error| format!("invalid committed transaction query response: {error}"))?;
    let QueryResponse::Iterable(output) = response else {
        return Err("committed transaction response must be iterable".into());
    };
    if output.has_more
        || output.continue_cursor.is_some()
        || output
            .remaining_items
            .is_some_and(|remaining| remaining != 0)
    {
        return Err("committed transaction response must contain exactly one page".into());
    }
    let mut rows = Vec::new();
    let mut committed_batches = 0_usize;
    for batch in output.batch {
        let QueryOutputBatchBox::CommittedTransaction(mut batch) = batch else {
            return Err("committed transaction response has a foreign batch type".into());
        };
        committed_batches += 1;
        rows.append(&mut batch);
    }
    if committed_batches != 1 || rows.len() > 1 {
        return Err("committed transaction response must contain zero or one exact row".into());
    }
    Ok(rows.pop())
}

fn decode_single_response(response_bytes: &[u8]) -> Result<CommittedTransaction, String> {
    decode_candidate_response(response_bytes)?
        .ok_or_else(|| "committed transaction response has no selected row".into())
}

/// Untrusted carrier block hash used only to locate consecutive native finality
/// proofs. It does not confer finality or authorize a transaction result.
pub(crate) fn candidate_block_hash(
    response_bytes: &[u8],
    expected_transaction_hash: HashOf<TransactionEntrypoint>,
) -> Result<Option<[u8; 32]>, String> {
    if response_bytes.is_empty() || response_bytes.len() > MAX_RESPONSE_BYTES {
        return Err("committed transaction response exceeds its bound".into());
    }
    let Some(row) = decode_candidate_response(response_bytes)? else {
        return Ok(None);
    };
    if row.entrypoint_hash != expected_transaction_hash {
        return Err("candidate row does not match requested transaction hash".into());
    }
    Ok(Some(*row.block_hash.as_ref()))
}

/// Decode only the exact untrusted carrier hash from a one-row response. A
/// canonical empty committed-transaction page returns status 1 and zeroed
/// output. This is a routing hint, never an authenticated proof. A caller must
/// verify the native finality chain and selected row with the verifier below before use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_committed_transaction_candidate_block_hash_v1(
    response_ptr: *const c_uchar,
    response_len: c_ulong,
    expected_transaction_hash_ptr: *const c_uchar,
    expected_transaction_hash_len: c_ulong,
    out_block_hash_32: *mut c_uchar,
) -> c_int {
    if !out_block_hash_32.is_null() {
        unsafe { ptr::write_bytes(out_block_hash_32, 0, 32) };
    }
    let result = std::panic::catch_unwind(|| {
        let response_len = usize::try_from(response_len)
            .map_err(|_| "candidate response length exceeds platform size")?;
        if response_ptr.is_null()
            || expected_transaction_hash_ptr.is_null()
            || out_block_hash_32.is_null()
            || response_len == 0
            || response_len > MAX_RESPONSE_BYTES
            || expected_transaction_hash_len != 32
        {
            return Err("invalid candidate block-hash argument".to_owned());
        }
        let transaction_bytes: [u8; 32] = unsafe {
            slice::from_raw_parts(expected_transaction_hash_ptr, 32)
                .try_into()
                .expect("fixed transaction hash length")
        };
        if transaction_bytes[31] & 1 == 0 {
            return Err("unmarked transaction hash".to_owned());
        }
        candidate_block_hash(
            unsafe { slice::from_raw_parts(response_ptr, response_len) },
            HashOf::from_untyped_unchecked(Hash::prehashed(transaction_bytes)),
        )
    });
    let Ok(Ok(candidate)) = result else {
        return ERR_COMMITTED_INCLUSION;
    };
    if let Some(hash) = candidate {
        unsafe { ptr::copy_nonoverlapping(hash.as_ptr(), out_block_hash_32, 32) };
        0
    } else {
        1
    }
}

pub(crate) fn verify_committed_transaction_inclusion(
    response_bytes: &[u8],
    chain_json: &[u8],
    expected_network_id: NetworkId,
    expected_chain: &str,
    trusted_checkpoint: &[u8],
    expected_transaction_hash: HashOf<TransactionEntrypoint>,
) -> Result<VerifiedCommittedTransaction, String> {
    verify_committed_transaction(
        response_bytes,
        chain_json,
        expected_network_id,
        expected_chain,
        trusted_checkpoint,
        expected_transaction_hash,
        None,
    )
}

/// Require the exact independently retained signed wire, including authorization,
/// and certified successful execution. The transaction identity alone excludes
/// signatures and therefore cannot substitute for this original.
pub(crate) fn verify_exact_successful_committed_transaction(
    response_bytes: &[u8],
    chain_json: &[u8],
    expected_network_id: NetworkId,
    expected_chain: &str,
    trusted_checkpoint: &[u8],
    original_signed_transaction: &[u8],
) -> Result<VerifiedCommittedTransaction, String> {
    if original_signed_transaction.is_empty()
        || original_signed_transaction.len() > MAX_ORIGINAL_TRANSACTION_BYTES
    {
        return Err("original signed transaction exceeds its bound".into());
    }
    let original = super::decode_signed_transaction(original_signed_transaction)
        .map_err(|error| format!("invalid canonical original signed transaction: {error}"))?;
    if original.network_id() != Some(&expected_network_id) {
        return Err("original signed transaction differs from the selected network".into());
    }
    let transaction_hash = original
        .try_hash_as_entrypoint()
        .map_err(|error| format!("invalid original transaction identity: {error}"))?;
    verify_committed_transaction(
        response_bytes,
        chain_json,
        expected_network_id,
        expected_chain,
        trusted_checkpoint,
        transaction_hash,
        Some(original_signed_transaction),
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_committed_transaction(
    response_bytes: &[u8],
    chain_json: &[u8],
    expected_network_id: NetworkId,
    expected_chain: &str,
    trusted_checkpoint: &[u8],
    expected_transaction_hash: HashOf<TransactionEntrypoint>,
    original_signed_transaction: Option<&[u8]>,
) -> Result<VerifiedCommittedTransaction, String> {
    if response_bytes.is_empty() || response_bytes.len() > MAX_RESPONSE_BYTES {
        return Err("committed transaction response exceeds its bound".into());
    }
    if chain_json.is_empty() || chain_json.len() > MAX_CHAIN_JSON_BYTES {
        return Err("native finality proof chain exceeds its bound".into());
    }
    if expected_chain.is_empty() || expected_chain.len() > 1024 {
        return Err("expected chain label exceeds its bound".into());
    }
    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(trusted_checkpoint)
        .map_err(|error| format!("invalid independently selected checkpoint: {error}"))?;
    if checkpoint.chain_id() != expected_chain {
        return Err("checkpoint differs from the independently selected chain".into());
    }
    let chain_json =
        std::str::from_utf8(chain_json).map_err(|_| "native finality proof chain is not UTF-8")?;
    let chain: Vec<SumeragiFinalityProof> = json::from_json(chain_json)
        .map_err(|error| format!("invalid native finality proof chain: {error}"))?;
    let page = verify_checkpoint_page(
        expected_network_id,
        &checkpoint,
        &chain,
        MAX_CHAIN_PROOFS,
        MAX_CHAIN_JSON_BYTES,
    )
    .map_err(|error| format!("native finality page failed: {error}"))?;
    let tip = page.tip();
    if original_signed_transaction.is_some()
        && tip.root_scope() != iroha_data_model::block::consensus::SumeragiRootScope::Global
    {
        return Err("exact historical success requires the authenticated Global root".into());
    }
    let committed = decode_single_response(response_bytes)?;
    if committed.entrypoint_hash != expected_transaction_hash {
        return Err("committed row does not match requested transaction hash".into());
    }
    // The native capability authenticates this complete header/wire and R before either
    // selective or full-row inclusion is examined. Rejected execution remains authentic.
    if !committed.verify_selective_in_authenticated_execution(
        &expected_network_id,
        &tip.header(),
        tip.execution(),
    ) || !committed.verify_inclusion_in_block(tip.block())
    {
        return Err("committed row does not verify against authenticated execution".into());
    }
    if let Some(original_wire) = original_signed_transaction {
        let TransactionEntrypoint::External(signed) = &committed.entrypoint else {
            return Err("committed entrypoint is not an external signed transaction".into());
        };
        let committed_wire = signed
            .encode_wire_v1()
            .map_err(|error| format!("invalid committed signed transaction wire: {error}"))?;
        if committed_wire != original_wire {
            return Err("committed signed transaction differs from the retained original".into());
        }
        if committed.result().is_err() {
            return Err("exact retained transaction did not execute successfully".into());
        }
    }
    let row = norito::to_bytes(&committed)
        .map_err(|error| format!("failed to encode canonical committed row: {error}"))?;
    if row.is_empty() || row.len() > MAX_ROW_BYTES {
        return Err("canonical committed row exceeds its bound".into());
    }
    let promoted = page
        .checkpoint()
        .encode_canonical()
        .map_err(|error| error.to_string())?;
    Ok(VerifiedCommittedTransaction {
        row,
        checkpoint: promoted,
        output_hash: *committed.output_hash.as_ref(),
        block_hash: *committed.block_hash.as_ref(),
        block_height: tip.height(),
        block_creation_time_ms: tip.header().creation_time_ms,
        global_root: tip.root_scope() == iroha_data_model::block::consensus::SumeragiRootScope::Global,
        result_ok: committed.result().is_ok(),
    })
}

/// Authenticate one current selective `CommittedTransaction` row against an
/// independently pinned NetworkId, chain, complete checkpoint and exact transaction hash.
/// On success the returned row is bare canonical Norito and must be freed with
/// `connect_norito_free`, as must the promoted canonical checkpoint. Every output is cleared on failure.
/// Output pointer/length slots must be distinct and must not overlap any input.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn connect_norito_verify_committed_transaction_inclusion_v1(
    response_ptr: *const c_uchar,
    response_len: c_ulong,
    chain_json_ptr: *const c_uchar,
    chain_json_len: c_ulong,
    expected_network_id_ptr: *const c_uchar,
    expected_network_id_len: c_ulong,
    expected_chain_ptr: *const c_uchar,
    expected_chain_len: c_ulong,
    trusted_checkpoint_ptr: *const c_uchar,
    trusted_checkpoint_len: c_ulong,
    expected_transaction_hash_ptr: *const c_uchar,
    expected_transaction_hash_len: c_ulong,
    out_row_ptr: *mut *mut c_uchar,
    out_row_len: *mut c_ulong,
    out_output_hash: *mut c_uchar,
    out_block_hash: *mut c_uchar,
    out_block_height: *mut u64,
    out_result_ok: *mut c_uchar,
    out_checkpoint_ptr: *mut *mut c_uchar,
    out_checkpoint_len: *mut c_ulong,
) -> c_int {
    unsafe {
        verify_committed_transaction_ffi(
            response_ptr,
            response_len,
            chain_json_ptr,
            chain_json_len,
            expected_network_id_ptr,
            expected_network_id_len,
            expected_chain_ptr,
            expected_chain_len,
            trusted_checkpoint_ptr,
            trusted_checkpoint_len,
            expected_transaction_hash_ptr,
            expected_transaction_hash_len,
            out_row_ptr,
            out_row_len,
            out_output_hash,
            out_block_hash,
            out_block_height,
            out_result_ok,
            out_checkpoint_ptr,
            out_checkpoint_len,
            false,
        )
    }
}

/// Authenticate successful execution of the exact independently retained canonical
/// versioned SignedTransaction, including its complete authorization proof.
/// Network, chain and checkpoint must be independently selected. Buffer ownership,
/// clearing and non-overlap requirements are identical to the general verifier.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn connect_norito_verify_exact_successful_committed_transaction_v1(
    response_ptr: *const c_uchar,
    response_len: c_ulong,
    chain_json_ptr: *const c_uchar,
    chain_json_len: c_ulong,
    expected_network_id_ptr: *const c_uchar,
    expected_network_id_len: c_ulong,
    expected_chain_ptr: *const c_uchar,
    expected_chain_len: c_ulong,
    trusted_checkpoint_ptr: *const c_uchar,
    trusted_checkpoint_len: c_ulong,
    original_signed_transaction_ptr: *const c_uchar,
    original_signed_transaction_len: c_ulong,
    out_row_ptr: *mut *mut c_uchar,
    out_row_len: *mut c_ulong,
    out_output_hash: *mut c_uchar,
    out_block_hash: *mut c_uchar,
    out_block_height: *mut u64,
    out_result_ok: *mut c_uchar,
    out_checkpoint_ptr: *mut *mut c_uchar,
    out_checkpoint_len: *mut c_ulong,
) -> c_int {
    unsafe {
        verify_committed_transaction_ffi(
            response_ptr,
            response_len,
            chain_json_ptr,
            chain_json_len,
            expected_network_id_ptr,
            expected_network_id_len,
            expected_chain_ptr,
            expected_chain_len,
            trusted_checkpoint_ptr,
            trusted_checkpoint_len,
            original_signed_transaction_ptr,
            original_signed_transaction_len,
            out_row_ptr,
            out_row_len,
            out_output_hash,
            out_block_hash,
            out_block_height,
            out_result_ok,
            out_checkpoint_ptr,
            out_checkpoint_len,
            true,
        )
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn verify_committed_transaction_ffi(
    response_ptr: *const c_uchar,
    response_len: c_ulong,
    chain_json_ptr: *const c_uchar,
    chain_json_len: c_ulong,
    expected_network_id_ptr: *const c_uchar,
    expected_network_id_len: c_ulong,
    expected_chain_ptr: *const c_uchar,
    expected_chain_len: c_ulong,
    trusted_checkpoint_ptr: *const c_uchar,
    trusted_checkpoint_len: c_ulong,
    expected_transaction_hash_ptr: *const c_uchar,
    expected_transaction_hash_len: c_ulong,
    out_row_ptr: *mut *mut c_uchar,
    out_row_len: *mut c_ulong,
    out_output_hash: *mut c_uchar,
    out_block_hash: *mut c_uchar,
    out_block_height: *mut u64,
    out_result_ok: *mut c_uchar,
    out_checkpoint_ptr: *mut *mut c_uchar,
    out_checkpoint_len: *mut c_ulong,
    exact_successful: bool,
) -> c_int {
    super::clear_bridge_output(out_row_ptr, out_row_len);
    super::clear_bridge_output(out_checkpoint_ptr, out_checkpoint_len);
    if !out_output_hash.is_null() {
        unsafe { ptr::write_bytes(out_output_hash, 0, 32) };
    }
    if !out_block_hash.is_null() {
        unsafe { ptr::write_bytes(out_block_hash, 0, 32) };
    }
    if !out_block_height.is_null() {
        unsafe { *out_block_height = 0 };
    }
    if !out_result_ok.is_null() {
        unsafe { *out_result_ok = 0 };
    }
    let result = std::panic::catch_unwind(|| {
        if response_ptr.is_null()
            || chain_json_ptr.is_null()
            || expected_network_id_ptr.is_null()
            || expected_chain_ptr.is_null()
            || trusted_checkpoint_ptr.is_null()
            || out_checkpoint_ptr.is_null()
            || out_checkpoint_len.is_null()
            || expected_transaction_hash_ptr.is_null()
            || out_row_ptr.is_null()
            || out_row_len.is_null()
            || out_output_hash.is_null()
            || out_block_hash.is_null()
            || out_block_height.is_null()
            || out_result_ok.is_null()
        {
            return Err("null committed inclusion argument".to_owned());
        }
        let response_len = usize::try_from(response_len).map_err(|error| error.to_string())?;
        let chain_len = usize::try_from(chain_json_len).map_err(|error| error.to_string())?;
        let label_len = usize::try_from(expected_chain_len).map_err(|error| error.to_string())?;
        let checkpoint_len =
            usize::try_from(trusted_checkpoint_len).map_err(|error| error.to_string())?;
        let transaction_len =
            usize::try_from(expected_transaction_hash_len).map_err(|error| error.to_string())?;
        let valid_transaction_length = if exact_successful {
            transaction_len > 0 && transaction_len <= MAX_ORIGINAL_TRANSACTION_BYTES
        } else {
            transaction_len == 32
        };
        if response_len == 0
            || response_len > MAX_RESPONSE_BYTES
            || chain_len == 0
            || chain_len > MAX_CHAIN_JSON_BYTES
            || expected_network_id_len != 32
            || !valid_transaction_length
            || label_len == 0
            || label_len > 1024
            || checkpoint_len == 0
            || checkpoint_len > MAX_FINALITY_CHECKPOINT_BYTES
        {
            return Err("invalid committed inclusion input length".to_owned());
        }
        let network_bytes: [u8; 32] = unsafe {
            slice::from_raw_parts(expected_network_id_ptr, 32)
                .try_into()
                .expect("fixed network byte count")
        };
        if network_bytes[31] & 1 == 0 {
            return Err("unmarked network hash".to_owned());
        }
        let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::prehashed(network_bytes),
        ));
        let label =
            std::str::from_utf8(unsafe { slice::from_raw_parts(expected_chain_ptr, label_len) })
                .map_err(|error| error.to_string())?;
        let response = unsafe { slice::from_raw_parts(response_ptr, response_len) };
        let chain = unsafe { slice::from_raw_parts(chain_json_ptr, chain_len) };
        let checkpoint = unsafe { slice::from_raw_parts(trusted_checkpoint_ptr, checkpoint_len) };
        let transaction =
            unsafe { slice::from_raw_parts(expected_transaction_hash_ptr, transaction_len) };
        if exact_successful {
            verify_exact_successful_committed_transaction(
                response,
                chain,
                network_id,
                label,
                checkpoint,
                transaction,
            )
        } else {
            let transaction_bytes: [u8; 32] = transaction
                .try_into()
                .expect("checked transaction hash length");
            if transaction_bytes[31] & 1 == 0 {
                return Err("unmarked transaction hash".to_owned());
            }
            verify_committed_transaction_inclusion(
                response,
                chain,
                network_id,
                label,
                checkpoint,
                HashOf::from_untyped_unchecked(Hash::prehashed(transaction_bytes)),
            )
        }
    });
    let Ok(Ok(verified)) = result else {
        return ERR_COMMITTED_INCLUSION;
    };
    if unsafe { super::write_bytes(out_row_ptr, out_row_len, &verified.row) }.is_err() {
        return ERR_COMMITTED_INCLUSION;
    }
    if unsafe { super::write_bytes(out_checkpoint_ptr, out_checkpoint_len, &verified.checkpoint) }
        .is_err()
    {
        super::connect_norito_free(unsafe { *out_row_ptr });
        super::clear_bridge_output(out_row_ptr, out_row_len);
        return ERR_COMMITTED_INCLUSION;
    }
    unsafe {
        ptr::copy_nonoverlapping(verified.output_hash.as_ptr(), out_output_hash, 32);
        ptr::copy_nonoverlapping(verified.block_hash.as_ptr(), out_block_hash, 32);
        *out_block_height = verified.block_height;
        *out_result_ok = u8::from(verified.result_ok);
    }
    0
}

#[cfg(test)]
#[path = "committed_transaction_inclusion/tests.rs"]
mod tests;
