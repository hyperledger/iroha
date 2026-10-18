//! Bounded reconstruction of an ordered transaction trie from opaque raw envelopes.

use std::{collections::BTreeSet, time::Instant};

use iroha_sccp::{
    ethereum_source::{
        EthereumMptRoleV1, EthereumNativeMptProofV1, MAX_MPT_NODE_BYTES, MAX_MPT_PROOF_BYTES,
        mpt_proof, mpt_root, rlp_encode_u64, verify_mpt_inclusion_ref,
    },
    v1::hashes::keccak256,
};
use norito::json::Value;

use crate::{
    evm::{EvmBlock, format_data, parse_data},
    http::{HttpTransport, JSON_RPC_UNSUPPORTED_CODES, RpcError, invalid_response},
    limits::EVM_BLOCK_RESPONSE_BYTES,
};

fn check_deadline(deadline: Instant) -> Result<(), RpcError> {
    if Instant::now() >= deadline {
        return Err(RpcError::BudgetExhausted {
            failures: Vec::new(),
        });
    }
    Ok(())
}

fn raw_method_error(error: RpcError) -> RpcError {
    let unsupported = |error: &RpcError| matches!(error, RpcError::JsonRpc { code, .. } if JSON_RPC_UNSUPPORTED_CODES.contains(code));
    if unsupported(&error)
        || matches!(&error, RpcError::Exhausted { failures }
            if !failures.is_empty() && failures.iter().all(|failure| unsupported(&failure.error)))
    {
        return invalid_response(
            "eth_getRawTransactionByHash is required for an authenticated transaction proof; \
             the configured endpoints do not support this method",
        );
    }
    error
}

pub(crate) fn build(
    transport: &HttpTransport,
    block: &EvmBlock,
    target: u64,
    max_proof_bytes: usize,
) -> Result<EthereumNativeMptProofV1, RpcError> {
    let target_index = usize::try_from(target)
        .map_err(|_| RpcError::InvalidRequest("transaction index exceeds usize".into()))?;
    if target_index >= block.transactions.len() {
        return Err(RpcError::InvalidRequest(
            "transaction target is outside the selected block".into(),
        ));
    }
    if max_proof_bytes == 0 || max_proof_bytes > MAX_MPT_PROOF_BYTES {
        return Err(RpcError::InvalidRequest(
            "transaction proof byte limit is outside the native MPT bounds".into(),
        ));
    }
    let input_limit = transport.config().max_response_bytes;
    // A hash is at least 68 JSON bytes: two quotes, `0x`, and 64 hex digits.
    // Bound caller-constructed blocks too, before allocating keys or requesting raw bytes.
    if block.transactions.len() > EVM_BLOCK_RESPONSE_BYTES.min(input_limit) / 68 {
        return Err(invalid_response(
            "transaction count exceeds the block response bound",
        ));
    }
    let deadline = transport.budget().deadline().ok_or_else(|| {
        RpcError::InvalidRequest("transaction proof requires an active poll deadline".into())
    })?;
    check_deadline(deadline)?;
    if block.header.extra_data.len() > input_limit {
        return Err(invalid_response(
            "transaction block header exceeds the source bound",
        ));
    }
    crate::builders::ethereum::checked_header_rlp(block)
        .map_err(|_| invalid_response("transaction block header does not match its hash"))?;
    let unique: BTreeSet<_> = block.transactions.iter().collect();
    if unique.len() != block.transactions.len() {
        return Err(invalid_response(
            "selected block repeats a transaction hash",
        ));
    }
    let mut entries = Vec::with_capacity(block.transactions.len());
    let mut retained_bytes = 0_usize;
    // Fetch the target first, so an oversized selected envelope cannot cause unrelated work.
    for index in std::iter::once(target_index)
        .chain((0..block.transactions.len()).filter(|index| *index != target_index))
    {
        check_deadline(deadline)?;
        let hash = &block.transactions[index];
        let index_u64 =
            u64::try_from(index).map_err(|_| invalid_response("transaction index overflows"))?;
        let key = rlp_encode_u64(index_u64);
        let remaining = input_limit
            .checked_sub(retained_bytes)
            .and_then(|remaining| remaining.checked_sub(key.len()))
            .ok_or_else(|| invalid_response("raw transactions exceed the retained-input bound"))?;
        let value_limit = if index == target_index {
            remaining.min(max_proof_bytes).min(MAX_MPT_NODE_BYTES)
        } else {
            remaining
        };
        let raw = transport
            .json_rpc_then(
                "eth_getRawTransactionByHash",
                vec![Value::from(format_data(hash))],
                |value| {
                    let text = value.as_str().ok_or_else(|| {
                        invalid_response("eth_getRawTransactionByHash returned no raw envelope")
                    })?;
                    if text.len().saturating_sub(2) / 2 > value_limit {
                        return Err(invalid_response(
                            "raw transaction exceeds its proof or retained-input bound",
                        ));
                    }
                    let raw = parse_data(text).map_err(|_| {
                        invalid_response("eth_getRawTransactionByHash returned malformed hex data")
                    })?;
                    if raw.is_empty() || keccak256(&[&raw]) != *hash {
                        return Err(invalid_response(
                            "raw transaction does not match the selected block's transaction hash",
                        ));
                    }
                    Ok(raw)
                },
            )
            .map_err(raw_method_error)?;
        check_deadline(deadline)?;
        retained_bytes = retained_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(raw.len()))
            .filter(|bytes| *bytes <= input_limit)
            .ok_or_else(|| invalid_response("raw transactions exceed the retained-input bound"))?;
        entries.push((key, raw));
    }
    let root = mpt_root(&entries);
    check_deadline(deadline)?;
    if root != Some(block.header.transactions_root) {
        return Err(invalid_response(
            "raw transactions do not rebuild the block transaction root",
        ));
    }
    let key = rlp_encode_u64(target);
    let proof = mpt_proof(&entries, &key);
    check_deadline(deadline)?;
    let proof =
        proof.ok_or_else(|| invalid_response("selected transaction proof is unavailable"))?;
    if proof.byte_len() > max_proof_bytes {
        return Err(invalid_response("transaction proof exceeds its byte limit"));
    }
    let opened = verify_mpt_inclusion_ref(
        block.header.transactions_root,
        &key,
        &proof,
        EthereumMptRoleV1::Transaction,
    )
    .map_err(|_| invalid_response("transaction proof exceeds native bounds or is noncanonical"))?;
    // The first entry is the selected raw envelope; never substitute a sibling leaf.
    if opened != entries[0].1 {
        return Err(invalid_response(
            "transaction proof opens a different envelope",
        ));
    }
    check_deadline(deadline)?;
    Ok(proof)
}
