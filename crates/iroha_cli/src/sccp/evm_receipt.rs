//! Authenticated original EVM transaction outcomes under a native retained checkpoint.

use super::*;
use iroha::data_model::sccp::light_client::{SccpLcCheckpointV1, SccpLightClientV1};
use iroha_sccp::{
    ethereum_source::{
        EthereumExecutionHeaderFieldsV1, EthereumMptRoleV1, EthereumNativeMptProofV1,
        MAX_MPT_PROOF_BYTES, decode_account, decode_execution_header, decode_receipt,
        decode_storage_word, rlp_encode_u64, verify_mpt_inclusion_ref,
    },
    light_client::profile::{
        BSC_MAX_SEGMENT_HEADERS, ETHEREUM_MAX_ANCESTRY_HEADERS, SccpChainProfilesV1,
    },
    v1::hashes::{keccak256, word_u64},
};
use iroha_sccp_rpc::{
    builders::ethereum::{checked_header_rlp, receipt_rlp},
    evm::{EvmAccountProof, EvmReceipt},
};
use iroha_sccp_wallet::journal::SccpEvidenceItemV1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReceiptTarget {
    network: SccpNetworkV1,
    contract: [u8; 20],
    code_hash: [u8; 32],
}

/// Receipt whose original transaction and status share one authenticated block and index.
pub(in crate::sccp) struct VerifiedEvmReceipt {
    receipt: EvmReceipt,
    header: EthereumExecutionHeaderFieldsV1,
    target: ReceiptTarget,
    remaining_proof_bytes: usize,
}

impl std::ops::Deref for VerifiedEvmReceipt {
    type Target = EvmReceipt;

    fn deref(&self) -> &Self::Target {
        &self.receipt
    }
}

impl EvmTransport<'_> {
    /// One whole-observation deadline, preserving any earlier caller-owned budget.
    pub(in crate::sccp) fn receipt_budget(
        &self,
        timeout: std::time::Duration,
    ) -> Result<(
        std::time::Instant,
        Option<iroha_sccp_rpc::endpoints::PollBudgetGuard>,
    )> {
        let budget = self.client.transport().budget();
        if let Some(deadline) = budget.deadline() {
            return Ok((deadline, None));
        }
        ensure!(
            !timeout.is_zero() && std::time::Instant::now().checked_add(timeout).is_some(),
            "receipt observation requires a finite positive deadline"
        );
        let guard = budget.start(timeout);
        let deadline = budget
            .deadline()
            .ok_or_else(|| eyre!("receipt deadline overflowed"))?;
        Ok((deadline, Some(guard)))
    }

    /// Check the same finite deadline after local verification and evidence serialization.
    pub(in crate::sccp) fn require_receipt_deadline(
        &self,
        deadline: std::time::Instant,
    ) -> Result<()> {
        ensure!(
            self.client.transport().budget().deadline() == Some(deadline)
                && std::time::Instant::now() < deadline,
            "original receipt observation deadline elapsed or changed"
        );
        Ok(())
    }

    /// Bind every native authority read to the existing whole-observation deadline.
    fn receipt_authority_client(
        &self,
        client: &iroha::blocking::Client,
    ) -> Result<iroha::blocking::Client> {
        let deadline = self
            .client
            .transport()
            .budget()
            .deadline()
            .ok_or_else(|| eyre!("receipt authority reads require a finite deadline"))?;
        self.require_receipt_deadline(deadline)?;
        client.with_request_deadline(deadline)
    }

    fn receipt_target(&self) -> ReceiptTarget {
        ReceiptTarget {
            network: self.network,
            contract: self.contract,
            code_hash: self.code_hash,
        }
    }

    /// Authenticate the exact retained bytes and receipt before recording success or failure.
    pub(in crate::sccp) fn receipt(
        &self,
        client: &iroha::blocking::Client,
        original: &crate::sccp::origin::AuthenticatedOrigin,
        raw: &[u8],
    ) -> Result<Option<(VerifiedEvmReceipt, Vec<SccpEvidenceItemV1>)>> {
        let signed = iroha_sccp_wallet::pure::evm::SignedEip1559V1::decode(raw)
            .map_err(|error| eyre!("retained EVM transaction: {error:?}"))?;
        let hash = self.retained_hash(raw, &signed.transaction.data)?;
        let Some(receipt) = self.client.transaction_receipt(&hash)? else {
            return Ok(None);
        };
        ensure!(
            receipt.transaction_hash == hash,
            "receipt names another original transaction"
        );

        let client = self.receipt_authority_client(client)?;
        let light_client = client.sccp().light_client(self.network)?.light_client;
        original.verify_light_client(self.network, &light_client)?;
        let (max_headers, max_proof_bytes) = receipt_limits(self.network, &light_client)?;
        let profiles = original.light_client_profiles(&client)?;
        let checkpoint = match client
            .sccp()
            .light_client_checkpoints(self.network, receipt.block_number)
        {
            Ok(cover) => cover.nearest.checkpoint,
            // No authenticated covering checkpoint is an unresolved outcome, not failure.
            Err(error) if matches!(error.http_status(), Some(404 | 410)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        original.verify_light_client_checkpoint(self.network, &checkpoint)?;
        let count = checkpoint
            .data
            .source_height
            .checked_sub(receipt.block_number)
            .and_then(|distance| distance.checked_add(1))
            .ok_or_else(|| eyre!("receipt is newer than its covering checkpoint"))?;
        ensure!(
            count <= max_headers as u64,
            "receipt ancestry exceeds the authenticated bound; retain a nearer checkpoint with light-client backfill"
        );

        let block = self
            .client
            .block_by_number(BlockTag::Number(receipt.block_number))?
            .ok_or_else(|| eyre!("original receipt block is unavailable"))?;
        let mut headers = vec![checked_header_rlp(&block)?];
        let mut header_bytes = headers[0].len();
        for offset in 1..count {
            let number = receipt
                .block_number
                .checked_add(offset)
                .ok_or_else(|| eyre!("receipt ancestry height overflows"))?;
            let descendant = self
                .client
                .block_by_number(BlockTag::Number(number))?
                .ok_or_else(|| eyre!("receipt ancestry block {number} is unavailable"))?;
            let wire = checked_header_rlp(&descendant)?;
            header_bytes = header_bytes
                .checked_add(wire.len())
                .filter(|bytes| *bytes <= max_proof_bytes)
                .ok_or_else(|| eyre!("receipt ancestry exceeds the authenticated proof budget"))?;
            headers.push(wire);
        }
        let header =
            verify_header_chain(self.network, &profiles, &checkpoint, &headers, max_headers)?;
        ensure!(
            header_bytes < max_proof_bytes,
            "receipt ancestry exhausts its proof budget"
        );
        let transaction_proof = self.client.block_transaction_proof(
            &block, receipt.transaction_index, max_proof_bytes - header_bytes,
        ).wrap_err("authenticate original transaction; the endpoint must serve eth_getRawTransactionByHash")?;
        let used = header_bytes
            .checked_add(transaction_proof.byte_len())
            .filter(|bytes| *bytes < max_proof_bytes)
            .ok_or_else(|| {
                eyre!("original transaction proof exhausts the authenticated proof budget")
            })?;
        let receipt_proof = self.client.block_receipt_proof(
            &block,
            receipt.transaction_index,
            max_proof_bytes - used,
        )?;
        ensure!(
            receipt_proof.byte_len() <= max_proof_bytes - used,
            "receipt proof exceeds the authenticated proof budget"
        );
        let mut verified = verify_receipt_inclusion(
            self.receipt_target(),
            raw,
            receipt,
            header,
            &transaction_proof,
            &receipt_proof,
        )?;
        verified.remaining_proof_bytes = max_proof_bytes - used - receipt_proof.byte_len();
        let account_proof = EthereumNativeMptProofV1 {
            nodes: self
                .client
                .proof(&self.contract, &[], BlockId::Hash(verified.block_hash))?
                .account_proof,
        };
        verified.remaining_proof_bytes = verified
            .remaining_proof_bytes
            .checked_sub(account_proof.byte_len())
            .ok_or_else(|| eyre!("call target proof exceeds the authenticated proof budget"))?;
        account_storage_root(
            self.receipt_target(),
            verified.header.state_root,
            &account_proof,
        )?;

        let mut evidence = vec![
            original.receipt_authority_evidence()?,
            crate::sccp::flows::evidence(
                "taira.evm_receipt_profile",
                &norito::json!({
                    "network": (self.network.profile_key()),
                    "profile_hash": (hex::encode(match self.network {
                        SccpNetworkV1::EthereumMainnet => profiles.ethereum.profile_hash(),
                        SccpNetworkV1::BscMainnet => profiles.bsc.profile_hash(),
                        _ => return Err(eyre!("unsupported receipt network")),
                    })),
                }),
            )?,
            crate::sccp::flows::evidence("taira.evm_receipt_light_client", &light_client)?,
            crate::sccp::flows::evidence("taira.evm_receipt_checkpoint", &checkpoint)?,
            proof_evidence("evm.original_transaction.proof", &transaction_proof)?,
            proof_evidence("evm.original_receipt.proof", &receipt_proof)?,
            proof_evidence("evm.original_call_target.proof", &account_proof)?,
        ];
        for (index, bytes) in headers.into_iter().enumerate() {
            evidence.push(SccpEvidenceItemV1 {
                label: format!("evm.receipt.ancestry.{index}.rlp"),
                bytes,
            });
        }
        Ok(Some((verified, evidence)))
    }

    /// Prove the exact mint effect and consumed bit at the authenticated receipt block.
    pub(in crate::sccp) fn confirm_finalized(
        &self,
        receipt: &VerifiedEvmReceipt,
        bundle: &SccpMessageProofBundleV1,
    ) -> Result<Vec<SccpEvidenceItemV1>> {
        let payload = iroha_sccp::v1::payload::SccpTransferPayloadRefV1::decode(&bundle.payload)?;
        let expected = iroha_sccp::v1::evm_abi::FinalizedLogV1 {
            message_id: bundle.message_id,
            nonce: payload.nonce,
            token_amount: payload.amount,
            recipient: payload
                .recipient
                .bytes
                .try_into()
                .map_err(|_| eyre!("original recipient is not EVM"))?,
        };
        ensure!(
            receipt.status == Some(1),
            "a failed receipt cannot confirm a mint"
        );
        require_finalized_log(&receipt.logs, self.contract, expected)?;
        let slot = consumed_slot(expected.nonce);
        let proof =
            self.client
                .proof(&self.contract, &[slot], BlockId::Hash(receipt.block_hash))?;
        verify_consumed_storage(self.receipt_target(), receipt, expected.nonce, &proof)?;
        Ok(vec![
            proof_evidence(
                "evm.finalized.account.proof",
                &EthereumNativeMptProofV1 {
                    nodes: proof.account_proof,
                },
            )?,
            proof_evidence(
                "evm.finalized.consumed.proof",
                &EthereumNativeMptProofV1 {
                    nodes: proof.storage_proof[0].proof.clone(),
                },
            )?,
            crate::sccp::flows::evidence(
                "evm.finalized.consumed.locator",
                &norito::json!({
                    "contract": (hex::encode(self.contract)),
                    "code_hash": (hex::encode(self.code_hash)),
                    "slot": (hex::encode(slot)),
                    "nonce": (expected.nonce),
                    "block_hash": (hex::encode(receipt.block_hash)),
                }),
            )?,
        ])
    }
}

fn proof_evidence(label: &str, proof: &EthereumNativeMptProofV1) -> Result<SccpEvidenceItemV1> {
    Ok(SccpEvidenceItemV1 {
        label: label.to_owned(),
        bytes: norito::to_bytes(proof)?,
    })
}

fn receipt_limits(
    network: SccpNetworkV1,
    light_client: &SccpLightClientV1,
) -> Result<(usize, usize)> {
    ensure!(
        light_client.params.network == network,
        "receipt light client names another network"
    );
    ensure!(
        light_client.frozen.is_none(),
        "receipt light client is frozen"
    );
    light_client.params.validate()?;
    let configured = light_client.params.max_ancestry_headers as usize;
    let headers = match network {
        SccpNetworkV1::EthereumMainnet => configured.min(ETHEREUM_MAX_ANCESTRY_HEADERS) + 1,
        SccpNetworkV1::BscMainnet => configured.min(BSC_MAX_SEGMENT_HEADERS),
        _ => {
            return Err(eyre!(
                "EVM receipts require an Ethereum or BSC light client"
            ));
        }
    };
    Ok((
        headers,
        (light_client.params.max_proof_bytes as usize).min(MAX_MPT_PROOF_BYTES),
    ))
}

fn verify_header_chain(
    network: SccpNetworkV1,
    profiles: &SccpChainProfilesV1,
    checkpoint: &SccpLcCheckpointV1,
    headers: &[Vec<u8>],
    max_headers: usize,
) -> Result<EthereumExecutionHeaderFieldsV1> {
    ensure!(
        !headers.is_empty() && headers.len() <= max_headers,
        "receipt ancestry exceeds its header bound"
    );
    let first = decode_execution_header(&headers[0])?;
    let mut previous = None::<EthereumExecutionHeaderFieldsV1>;
    let mut previous_time = None;
    for wire in headers {
        let header = decode_execution_header(wire)?;
        let time = match network {
            SccpNetworkV1::EthereumMainnet => header
                .timestamp
                .checked_mul(1000)
                .ok_or_else(|| eyre!("receipt header time overflows"))?,
            SccpNetworkV1::BscMainnet => {
                let summary = iroha_sccp::light_client::bsc::header_summary(wire)?;
                ensure!(
                    profiles.bsc.supports_time(summary.time_ms),
                    "receipt header is outside the compiled BSC profile"
                );
                summary.time_ms
            }
            _ => return Err(eyre!("unsupported receipt network")),
        };
        if let Some(parent) = previous {
            ensure!(
                header.parent_hash == parent.hash
                    && parent.number.checked_add(1) == Some(header.number),
                "receipt ancestry is not one contiguous parent-linked chain"
            );
            if network == SccpNetworkV1::BscMainnet {
                ensure!(
                    previous_time.is_some_and(|before| before < time),
                    "BSC receipt ancestry time does not advance"
                );
            }
        }
        previous = Some(header);
        previous_time = Some(time);
    }
    let end = previous.ok_or_else(|| eyre!("receipt ancestry is empty"))?;
    ensure!(
        end.hash == checkpoint.data.block_hash
            && end.number == checkpoint.data.source_height
            && checkpoint
                .data
                .state_root
                .is_none_or(|root| root == end.state_root)
            && end.receipts_root == checkpoint.data.receipts_or_tx_root
            && previous_time == Some(checkpoint.data.source_time_ms),
        "receipt ancestry does not end at the exact authenticated checkpoint"
    );
    Ok(first)
}

fn verify_receipt_inclusion(
    target: ReceiptTarget,
    raw: &[u8],
    receipt: EvmReceipt,
    header: EthereumExecutionHeaderFieldsV1,
    transaction_proof: &EthereumNativeMptProofV1,
    receipt_proof: &EthereumNativeMptProofV1,
) -> Result<VerifiedEvmReceipt> {
    let signed = iroha_sccp_wallet::pure::evm::SignedEip1559V1::decode(raw)
        .map_err(|error| eyre!("retained EVM transaction: {error:?}"))?;
    ensure!(
        signed.transaction.chain_id
            == eip1559_chain_id(target.network).map_err(|error| eyre!("{error:?}"))?
            && signed.transaction.to == Some(target.contract)
            && signed.transaction.value == 0
            && signed.raw() == raw,
        "receipt transaction differs from the original chain or call target"
    );
    ensure!(
        receipt.transaction_hash == signed.hash()
            && receipt.block_hash == header.hash
            && receipt.block_number == header.number,
        "receipt locator differs from authenticated original transaction or block"
    );
    let key = rlp_encode_u64(receipt.transaction_index);
    let transaction = verify_mpt_inclusion_ref(
        header.transactions_root,
        &key,
        transaction_proof,
        EthereumMptRoleV1::Transaction,
    )?;
    ensure!(
        transaction == raw,
        "transaction proof opens different signed bytes at the receipt index"
    );
    let encoded = verify_mpt_inclusion_ref(
        header.receipts_root,
        &key,
        receipt_proof,
        EthereumMptRoleV1::Receipt,
    )?;
    ensure!(
        encoded == receipt_rlp(&receipt),
        "receipt metadata differs from its authenticated receipt bytes"
    );
    let decoded = decode_receipt(encoded)?;
    ensure!(
        decoded.tx_type == 2 && receipt.status == Some(u8::from(decoded.success)),
        "receipt is not the canonical status of the original EIP-1559 transaction"
    );
    // Locator metadata is absent from receipt RLP; reject contradictions with its
    // authenticated container before retaining any terminal journal evidence.
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
    let remaining_proof_bytes = MAX_MPT_PROOF_BYTES
        .checked_sub(transaction_proof.byte_len())
        .and_then(|remaining| remaining.checked_sub(receipt_proof.byte_len()))
        .ok_or_else(|| {
            eyre!("combined original transaction and receipt proof exceeds its bound")
        })?;
    Ok(VerifiedEvmReceipt {
        receipt,
        header,
        target,
        remaining_proof_bytes,
    })
}

fn consumed_slot(nonce: u64) -> [u8; 32] {
    // SCCP v1 §5.2.3 fixes consumedBitmap at Solidity mapping slot 4.
    keccak256(&[&word_u64(nonce >> 8), &word_u64(4)])
}

/// Authenticate the locked runtime for every journaled effect, including maintenance.
fn account_storage_root(
    target: ReceiptTarget,
    state_root: [u8; 32],
    proof: &EthereumNativeMptProofV1,
) -> Result<[u8; 32]> {
    let account = decode_account(verify_mpt_inclusion_ref(
        state_root,
        &keccak256(&[&target.contract]),
        proof,
        EthereumMptRoleV1::Account,
    )?)?;
    ensure!(
        account.code_hash == target.code_hash,
        "authenticated destination code differs from the registered runtime"
    );
    Ok(account.storage_root)
}

fn verify_consumed_storage(
    target: ReceiptTarget,
    receipt: &VerifiedEvmReceipt,
    nonce: u64,
    proof: &EvmAccountProof,
) -> Result<()> {
    ensure!(
        receipt.target == target,
        "receipt belongs to another transport identity"
    );
    let slot = consumed_slot(nonce);
    ensure!(
        proof.address == target.contract
            && proof.storage_proof.len() == 1
            && proof.storage_proof[0].key == slot,
        "consumed proof names another account or slot"
    );
    let proof_bytes = proof
        .account_proof
        .iter()
        .chain(proof.storage_proof[0].proof.iter())
        .try_fold(0usize, |total, node| total.checked_add(node.len()))
        .ok_or_else(|| eyre!("consumed proof size overflows"))?;
    ensure!(
        proof_bytes <= receipt.remaining_proof_bytes,
        "consumed proof exceeds the remaining authenticated proof budget"
    );
    let account_proof = EthereumNativeMptProofV1 {
        nodes: proof.account_proof.clone(),
    };
    let storage_root = account_storage_root(target, receipt.header.state_root, &account_proof)?;
    let storage_proof = EthereumNativeMptProofV1 {
        nodes: proof.storage_proof[0].proof.clone(),
    };
    let word = decode_storage_word(verify_mpt_inclusion_ref(
        storage_root,
        &keccak256(&[&slot]),
        &storage_proof,
        EthereumMptRoleV1::Storage,
    )?)?;
    let bit = (nonce & 255) as usize;
    ensure!(
        word[31 - bit / 8] & (1 << (bit % 8)) != 0,
        "authenticated destination storage has not consumed the original nonce"
    );
    Ok(())
}

#[cfg(test)]
#[path = "evm_receipt/tests.rs"]
mod tests;
