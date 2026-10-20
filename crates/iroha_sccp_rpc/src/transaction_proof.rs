//! Bounded reconstruction of an ordered transaction trie from opaque raw envelopes.

use std::{collections::BTreeSet, time::Instant};

use iroha_sccp::{
    ethereum_source::{
        EthereumMptRoleV1, EthereumNativeMptProofV1, MAX_MPT_NODE_BYTES, MAX_MPT_PROOF_BYTES,
        rlp_encode_u64, verify_mpt_inclusion_ref,
    },
    v1::hashes::keccak256,
};

use crate::{
    evm::{EvmBlock, EvmClient},
    http::{JSON_RPC_UNSUPPORTED_CODES, RpcError, invalid_response},
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

pub fn build(
    client: &EvmClient,
    block: &EvmBlock,
    target: u64,
    max_proof_bytes: usize,
) -> Result<EthereumNativeMptProofV1, RpcError> {
    let transport = client.transport();
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
    let mut trie =
        crate::receipt_trie::Trie::new(block.transactions.len(), target, max_proof_bytes)?;
    // Fetch the target first, so an oversized selected envelope cannot cause unrelated work.
    for index in std::iter::once(target_index)
        .chain((0..block.transactions.len()).filter(|index| *index != target_index))
    {
        check_deadline(deadline)?;
        let hash = &block.transactions[index];
        let index_u64 =
            u64::try_from(index).map_err(|_| invalid_response("transaction index overflows"))?;
        let raw = client
            .raw_transaction_bounded(
                hash,
                if index == target_index {
                    max_proof_bytes.min(MAX_MPT_NODE_BYTES)
                } else {
                    input_limit
                },
            )
            .map_err(raw_method_error)?
            .ok_or_else(|| invalid_response("a selected block transaction is absent"))?;
        check_deadline(deadline)?;
        trie.insert(index_u64, &raw)?;
    }
    check_deadline(deadline)?;
    let (root, proof) = trie.finish()?;
    check_deadline(deadline)?;
    if root != block.header.transactions_root {
        return Err(invalid_response(
            "raw transactions do not rebuild the block transaction root",
        ));
    }
    let key = rlp_encode_u64(target);
    let opened = verify_mpt_inclusion_ref(
        block.header.transactions_root,
        &key,
        &proof,
        EthereumMptRoleV1::Transaction,
    )
    .map_err(|_| invalid_response("transaction proof exceeds native bounds or is noncanonical"))?;
    // The selected hash names the exact already-validated raw envelope, not a sibling leaf.
    if keccak256(&[opened]) != block.transactions[target_index] {
        return Err(invalid_response(
            "transaction proof opens a different envelope",
        ));
    }
    check_deadline(deadline)?;
    Ok(proof)
}
