//! Journal receipts bound to original native-certified checkpoints and signed transaction bytes.

use eyre::{Result, ensure, eyre};
use iroha_data_model::sccp::light_client::{SccpLcPointV1, SccpLightClientParamsV1};
use iroha_sccp::{
    ethereum_source::{
        EthereumExecutionHeaderFieldsV1, EthereumMptRoleV1, EthereumNativeMptProofV1,
        MAX_MPT_PROOF_BYTES, decode_account, decode_execution_header, decode_receipt,
        decode_storage_word, rlp_encode_u64, verify_mpt_inclusion_ref,
    },
    v1::hashes::{keccak256, word_u64},
};
use iroha_sccp_rpc::{
    builders::{
        MAX_BACKFILL_SEGMENTS,
        ethereum::{checked_header_rlp, receipt_rlp},
    },
    evm::{BlockId, BlockTag, EvmReceipt},
};
use iroha_sccp_wallet::journal::SccpEvidenceItemV1;

use super::super::{BlockingClient, flows, origin::AuthenticatedOrigin};
use super::EvmTransport;

pub(super) type Observation = (EvmReceipt, Vec<SccpEvidenceItemV1>);

fn item(label: &str, bytes: Vec<u8>) -> SccpEvidenceItemV1 {
    SccpEvidenceItemV1 {
        label: label.into(),
        bytes,
    }
}

fn nodes(label: &str, proof: EthereumNativeMptProofV1) -> Vec<SccpEvidenceItemV1> {
    proof
        .nodes
        .into_iter()
        .enumerate()
        .map(|(index, node)| item(&format!("{label}.{index}"), node))
        .collect()
}

/// Each operation uses the same bounded ancestry reach as the native backfill builder.
fn ancestry_limit(params: &SccpLightClientParamsV1) -> u64 {
    u64::from(params.max_ancestry_headers.min(256))
        + (MAX_BACKFILL_SEGMENTS as u64)
            * u64::from(params.max_backfill_headers.min(256).saturating_sub(1))
}

fn byte_budget(lengths: impl IntoIterator<Item = usize>, limit: usize) -> Result<()> {
    let sum = lengths.into_iter().try_fold(0_usize, usize::checked_add);
    ensure!(
        sum.is_some_and(|sum| sum <= limit),
        "receipt evidence exceeds its byte budget"
    );
    Ok(())
}

/// Authenticate all parent links and both endpoints, without trusting RPC's finalized tag.
fn ancestry(
    headers: &[Vec<u8>],
    event: SccpLcPointV1,
    anchor: SccpLcPointV1,
    limit: u64,
) -> Result<EthereumExecutionHeaderFieldsV1> {
    let distance = anchor
        .source_height
        .checked_sub(event.source_height)
        .ok_or_else(|| eyre!("receipt is above its authenticated anchor"))?;
    ensure!(
        distance <= limit && headers.len() as u64 == distance + 1,
        "receipt ancestry is incomplete or exceeds the native backfill reach"
    );
    let first = decode_execution_header(&headers[0])?;
    ensure!(
        first.number == event.source_height && first.hash == event.block_hash,
        "receipt differs from the first ancestry header"
    );
    let mut previous = first;
    for encoded in &headers[1..] {
        let next = decode_execution_header(encoded)?;
        ensure!(
            previous.number.checked_add(1) == Some(next.number)
                && next.parent_hash == previous.hash,
            "receipt ancestry has a broken parent or height link"
        );
        previous = next;
    }
    ensure!(
        previous.number == anchor.source_height
            && previous.hash == anchor.block_hash
            && previous.timestamp.checked_mul(1000) == Some(anchor.source_time_ms),
        "receipt ancestry does not end at the original authenticated checkpoint"
    );
    Ok(first)
}

/// A receipt's untrusted transaction hash is insufficient: both tries use the same index.
fn inclusion(
    header: &EthereumExecutionHeaderFieldsV1,
    receipt: &EvmReceipt,
    raw: &[u8],
    transaction: &EthereumNativeMptProofV1,
    receipt_proof: &EthereumNativeMptProofV1,
) -> Result<()> {
    ensure!(
        receipt.block_number == header.number
            && receipt.block_hash == header.hash
            && receipt.transaction_hash == keccak256(&[raw]),
        "receipt locator differs from the original transaction or authenticated block"
    );
    let key = rlp_encode_u64(receipt.transaction_index);
    let signed = verify_mpt_inclusion_ref(
        header.transactions_root,
        &key,
        transaction,
        EthereumMptRoleV1::Transaction,
    )?;
    ensure!(
        signed == raw,
        "receipt index does not contain the original signed transaction"
    );
    let opened = verify_mpt_inclusion_ref(
        header.receipts_root,
        &key,
        receipt_proof,
        EthereumMptRoleV1::Receipt,
    )?;
    let decoded = decode_receipt(opened)?;
    ensure!(
        opened == receipt_rlp(receipt) && receipt.status == Some(u8::from(decoded.success)),
        "RPC receipt status or logs differ from the authenticated receipt"
    );
    // Log locator metadata is absent from receipt RLP. The containing receipt is authoritative;
    // contradictory RPC metadata is rejected instead of being retained as apparent evidence.
    ensure!(
        receipt.logs.iter().all(|log| !log.removed
            && log.block_hash.is_none_or(|hash| hash == header.hash)
            && log
                .block_number
                .is_none_or(|height| height == header.number)
            && log
                .transaction_hash
                .is_none_or(|hash| hash == receipt.transaction_hash)
            && log
                .transaction_index
                .is_none_or(|index| index == receipt.transaction_index)),
        "receipt log metadata disagrees with its authenticated container"
    );
    Ok(())
}

pub(super) fn observe(
    destination: &EvmTransport<'_>,
    taira: &BlockingClient,
    original: &AuthenticatedOrigin,
    raw: &[u8],
) -> Result<Option<Observation>> {
    let deadline = destination
        .client
        .transport()
        .budget()
        .deadline()
        .ok_or_else(|| eyre!("receipt recovery requires its original confirmation deadline"))?;
    let taira = taira.with_request_deadline(deadline)?;
    let hash = keccak256(&[raw]);
    let Some(receipt) = destination.client.transaction_receipt(&hash)? else {
        return Ok(None);
    };
    let lc = taira.sccp().light_client(destination.network)?.light_client;
    original.verify_light_client(destination.network, &lc)?;
    ensure!(
        lc.frozen.is_none(),
        "the original destination light client is frozen"
    );
    if receipt.block_number > lc.head.latest_finalized.source_height {
        // Lack of an authenticated decision never retires the retained envelope.
        return Ok(None);
    }
    let mut anchor = lc.head.latest_finalized;
    let mut evidence = vec![
        flows::evidence("taira.authenticated_light_client", &lc)?,
        flows::evidence("taira.original_cut_height", &original.height())?,
    ];
    match taira
        .sccp()
        .light_client_checkpoints(destination.network, receipt.block_number)
    {
        Ok(cover) => {
            let checkpoint = cover.nearest.checkpoint;
            original.verify_light_client_checkpoint(destination.network, &checkpoint)?;
            ensure!(
                checkpoint.data.source_height >= receipt.block_number,
                "the selected checkpoint does not cover the original receipt"
            );
            if checkpoint.data.source_height <= anchor.source_height {
                anchor = SccpLcPointV1 {
                    source_height: checkpoint.data.source_height,
                    block_hash: checkpoint.data.block_hash,
                    source_time_ms: checkpoint.data.source_time_ms,
                };
                evidence.push(flows::evidence(
                    "taira.authenticated_receipt_checkpoint",
                    &checkpoint,
                )?);
            }
        }
        Err(error) if matches!(error.http_status(), Some(404 | 410)) => {}
        Err(error) => return Err(error.into()),
    }
    let limit = ancestry_limit(&lc.params);
    ensure!(
        anchor.source_height - receipt.block_number <= limit,
        "original receipt needs a retained checkpoint within the native backfill reach"
    );
    let block = destination
        .client
        .block_by_number(BlockTag::Number(receipt.block_number))?
        .ok_or_else(|| eyre!("original receipt block is unavailable"))?;
    let mut headers = vec![checked_header_rlp(&block)?];
    let max_bytes = (lc.params.max_proof_bytes as usize).min(MAX_MPT_PROOF_BYTES);
    let mut remaining = max_bytes
        .checked_sub(headers[0].len())
        .ok_or_else(|| eyre!("receipt header exceeds the evidence budget"))?;
    for offset in 1..=anchor.source_height - receipt.block_number {
        let next = destination
            .client
            .block_by_number(BlockTag::Number(receipt.block_number + offset))?
            .ok_or_else(|| eyre!("receipt ancestry block is unavailable"))?;
        let header = checked_header_rlp(&next)?;
        remaining = remaining
            .checked_sub(header.len())
            .ok_or_else(|| eyre!("receipt ancestry exceeds the evidence budget"))?;
        headers.push(header);
    }
    let first = ancestry(
        &headers,
        SccpLcPointV1 {
            source_height: receipt.block_number,
            block_hash: receipt.block_hash,
            source_time_ms: 0,
        },
        anchor,
        limit,
    )?;
    let transaction =
        destination
            .client
            .block_transaction_proof(&block, receipt.transaction_index, max_bytes)?;
    let receipt_proof =
        destination
            .client
            .block_receipt_proof(&block, receipt.transaction_index, max_bytes)?;
    inclusion(&first, &receipt, raw, &transaction, &receipt_proof)?;
    let account = EthereumNativeMptProofV1 {
        nodes: destination
            .client
            .proof(&destination.contract, &[], BlockId::Hash(first.hash))?
            .account_proof,
    };
    byte_budget(
        [
            transaction.byte_len(),
            receipt_proof.byte_len(),
            account.byte_len(),
        ],
        remaining,
    )?;
    account_storage_root(
        first.state_root,
        destination.contract,
        destination.code_hash,
        &account,
    )?;
    evidence.extend(
        headers.into_iter().enumerate().map(|(index, header)| {
            item(&format!("evm.authenticated_receipt_header.{index}"), header)
        }),
    );
    evidence.extend(nodes("evm.original_transaction_proof", transaction));
    evidence.extend(nodes("evm.original_receipt_proof", receipt_proof));
    evidence.extend(nodes("evm.original_call_target_proof", account));
    Ok(Some((receipt, evidence)))
}

/// Solidity storage slot 4 is the locked contract's consumed bitmap mapping.
fn consumed_slot(nonce: u64) -> [u8; 32] {
    keccak256(&[&word_u64(nonce >> 8), &word_u64(4)])
}

/// Authenticate the locked call target for every journaled effect, including maintenance.
fn account_storage_root(
    state_root: [u8; 32],
    contract: [u8; 20],
    code_hash: [u8; 32],
    account_proof: &EthereumNativeMptProofV1,
) -> Result<[u8; 32]> {
    let account = decode_account(verify_mpt_inclusion_ref(
        state_root,
        &keccak256(&[&contract]),
        account_proof,
        EthereumMptRoleV1::Account,
    )?)?;
    ensure!(
        account.code_hash == code_hash,
        "authenticated destination code differs from the registered runtime"
    );
    Ok(account.storage_root)
}

fn consumed_proof(
    state_root: [u8; 32],
    contract: [u8; 20],
    code_hash: [u8; 32],
    nonce: u64,
    account_proof: &EthereumNativeMptProofV1,
    storage_proof: &EthereumNativeMptProofV1,
) -> Result<()> {
    let storage_root = account_storage_root(state_root, contract, code_hash, account_proof)?;
    let bits = decode_storage_word(verify_mpt_inclusion_ref(
        storage_root,
        &keccak256(&[&consumed_slot(nonce)]),
        storage_proof,
        EthereumMptRoleV1::Storage,
    )?)?;
    let bit = (nonce & 255) as usize;
    ensure!(
        bits[31 - bit / 8] & (1 << (bit % 8)) != 0,
        "finalized event lacks its authenticated consumed nonce at the original block"
    );
    Ok(())
}

pub(super) fn consumed(
    destination: &EvmTransport<'_>,
    receipt: &EvmReceipt,
    nonce: u64,
) -> Result<Vec<SccpEvidenceItemV1>> {
    // `receipt` has already passed `observe`; bind this new response to that exact header.
    let block = destination
        .client
        .block_by_number(BlockTag::Number(receipt.block_number))?
        .ok_or_else(|| eyre!("authenticated receipt block is unavailable"))?;
    let encoded = checked_header_rlp(&block)?;
    let header = decode_execution_header(&encoded)?;
    ensure!(
        header.hash == receipt.block_hash && header.number == receipt.block_number,
        "consumed proof substituted another block for the authenticated receipt"
    );
    let proof = destination.client.proof(
        &destination.contract,
        &[consumed_slot(nonce)],
        BlockId::Hash(header.hash),
    )?;
    let account = EthereumNativeMptProofV1 {
        nodes: proof.account_proof,
    };
    let storage = EthereumNativeMptProofV1 {
        nodes: proof
            .storage_proof
            .into_iter()
            .next()
            .ok_or_else(|| eyre!("consumed proof lacks its requested slot"))?
            .proof,
    };
    consumed_proof(
        header.state_root,
        destination.contract,
        destination.code_hash,
        nonce,
        &account,
        &storage,
    )?;
    let mut evidence = nodes("evm.destination_account_proof", account);
    evidence.extend(nodes("evm.consumed_bitmap_proof", storage));
    Ok(evidence)
}

#[cfg(test)]
#[path = "evm_receipt/tests.rs"]
mod tests;
