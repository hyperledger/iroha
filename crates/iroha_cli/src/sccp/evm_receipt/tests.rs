//! Transaction, receipt, ancestry and consumed-state forgery regressions.

use super::*;
use iroha_sccp::ethereum_source::{
    mpt_proof, mpt_root, rlp_encode_bytes, rlp_encode_list, rlp_encode_uint_bytes,
};
use iroha_sccp_rpc::evm::EvmLog;
use iroha_sccp_wallet::pure::evm::{Eip1559TransactionV1, EvmSigningKey};

fn signed(nonce: u64) -> Vec<u8> {
    Eip1559TransactionV1 {
        chain_id: 1,
        nonce,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 2,
        gas_limit: 100_000,
        to: Some([8; 20]),
        value: 0,
        data: vec![1, 2, 3],
    }
    .sign(&EvmSigningKey::from_secret([17; 32]).unwrap())
    .unwrap()
    .raw()
}

fn header(
    number: u64,
    parent: [u8; 32],
    state: [u8; 32],
    tx: [u8; 32],
    receipts: [u8; 32],
) -> Vec<u8> {
    rlp_encode_list(&[
        rlp_encode_bytes(&parent),
        rlp_encode_bytes(&[1; 32]),
        rlp_encode_bytes(&[2; 20]),
        rlp_encode_bytes(&state),
        rlp_encode_bytes(&tx),
        rlp_encode_bytes(&receipts),
        rlp_encode_bytes(&[0; 256]),
        rlp_encode_u64(0),
        rlp_encode_u64(number),
        rlp_encode_u64(30_000_000),
        rlp_encode_u64(21_000),
        rlp_encode_u64(100 + number),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[0; 32]),
        rlp_encode_bytes(&[0; 8]),
        rlp_encode_u64(7),
    ])
}

fn receipt(raw: &[u8], status: u8) -> EvmReceipt {
    EvmReceipt {
        tx_type: 2,
        status: Some(status),
        state_root: None,
        cumulative_gas_used: 21_000,
        logs_bloom: [0; 256],
        logs: vec![],
        transaction_hash: keccak256(&[raw]),
        transaction_index: 0,
        block_hash: [0; 32],
        block_number: 10,
        gas_used: 21_000,
        effective_gas_price: None,
        from: None,
        to: None,
        contract_address: None,
        blob_gas_used: None,
        blob_gas_price: None,
    }
}

#[test]
fn original_signed_transaction_and_receipt_share_the_authenticated_index() {
    let raw = signed(7);
    for status in [0, 1] {
        let mut receipt = receipt(&raw, status);
        let key = rlp_encode_u64(0);
        let txs = vec![(key.clone(), raw.clone()), (rlp_encode_u64(1), signed(8))];
        let receipts = vec![(key.clone(), receipt_rlp(&receipt))];
        let header = decode_execution_header(&header(
            10,
            [3; 32],
            [4; 32],
            mpt_root(&txs).unwrap(),
            mpt_root(&receipts).unwrap(),
        ))
        .unwrap();
        receipt.block_hash = header.hash;
        let tp = mpt_proof(&txs, &key).unwrap();
        let rp = mpt_proof(&receipts, &key).unwrap();
        inclusion(&header, &receipt, &raw, &tp, &rp).unwrap();
        // Authentic status=0 is a proven failed attempt, never an inferred timeout.
        let mut forged = receipt.clone();
        forged.status = Some(1 - status);
        assert!(inclusion(&header, &forged, &raw, &tp, &rp).is_err());
        forged.status = None;
        assert!(inclusion(&header, &forged, &raw, &tp, &rp).is_err());
        forged = receipt.clone();
        forged.transaction_index = 1;
        assert!(inclusion(&header, &forged, &raw, &tp, &rp).is_err());
        forged = receipt.clone();
        forged.transaction_hash = keccak256(&[&signed(8)]);
        // A real receipt and a plausible transaction hash still do not prove that transaction.
        assert!(inclusion(&header, &forged, &signed(8), &tp, &rp).is_err());
        forged = receipt.clone();
        forged.block_number += 1;
        assert!(inclusion(&header, &forged, &raw, &tp, &rp).is_err());
        forged = receipt.clone();
        forged.block_hash[0] ^= 1;
        assert!(inclusion(&header, &forged, &raw, &tp, &rp).is_err());
        let mut wrong = tp.clone();
        wrong.nodes[0][0] ^= 1;
        assert!(inclusion(&header, &receipt, &raw, &wrong, &rp).is_err());
        assert!(inclusion(&header, &receipt, &raw, &tp, &tp).is_err());
    }
}

#[test]
fn authenticated_receipt_logs_reject_rpc_metadata_and_payload_substitution() {
    let raw = signed(7);
    let mut receipt = receipt(&raw, 1);
    receipt.logs.push(EvmLog {
        address: [8; 20],
        topics: vec![[9; 32]],
        data: vec![10],
        log_index: Some(0),
        transaction_index: Some(0),
        transaction_hash: Some(receipt.transaction_hash),
        block_hash: None,
        block_number: Some(10),
        removed: false,
    });
    let key = rlp_encode_u64(0);
    let txs = vec![(key.clone(), raw.clone())];
    let receipts = vec![(key.clone(), receipt_rlp(&receipt))];
    let header = decode_execution_header(&header(
        10,
        [3; 32],
        [4; 32],
        mpt_root(&txs).unwrap(),
        mpt_root(&receipts).unwrap(),
    ))
    .unwrap();
    receipt.block_hash = header.hash;
    let tp = mpt_proof(&txs, &key).unwrap();
    let rp = mpt_proof(&receipts, &key).unwrap();
    inclusion(&header, &receipt, &raw, &tp, &rp).unwrap();
    for change in 0..8 {
        let mut forged = receipt.clone();
        let log = &mut forged.logs[0];
        match change {
            0 => log.removed = true,
            1 => log.block_hash = Some([0; 32]),
            2 => log.block_number = Some(11),
            3 => log.transaction_hash = Some([0; 32]),
            4 => log.transaction_index = Some(1),
            5 => log.address[0] ^= 1,
            6 => log.data.push(0),
            _ => log.topics[0][0] ^= 1,
        }
        assert!(
            inclusion(&header, &forged, &raw, &tp, &rp).is_err(),
            "change {change}"
        );
    }
}

#[test]
fn ancestry_requires_the_original_checkpoint_and_every_link() {
    let a = header(10, [3; 32], [4; 32], [5; 32], [6; 32]);
    let ah = decode_execution_header(&a).unwrap();
    let b = header(11, ah.hash, [4; 32], [5; 32], [6; 32]);
    let bh = decode_execution_header(&b).unwrap();
    let point = |h: EthereumExecutionHeaderFieldsV1| SccpLcPointV1 {
        source_height: h.number,
        block_hash: h.hash,
        source_time_ms: h.timestamp * 1000,
    };
    let event = point(ah);
    let anchor = point(bh);
    assert_eq!(
        ancestry(&[a.clone(), b.clone()], event, anchor, 1).unwrap(),
        ah
    );
    ancestry(std::slice::from_ref(&a), event, event, 0).unwrap();
    assert!(ancestry(&[], event, event, 1).is_err());
    assert!(ancestry(std::slice::from_ref(&a), event, anchor, 1).is_err());
    assert!(ancestry(&[a.clone(), b.clone()], event, anchor, 0).is_err());
    assert!(ancestry(&[b.clone(), a.clone()], anchor, event, 1).is_err());
    for change in 0..3 {
        let mut wrong = anchor;
        match change {
            0 => wrong.block_hash[0] ^= 1,
            1 => wrong.source_time_ms += 1,
            _ => wrong.source_height += 1,
        }
        assert!(ancestry(&[a.clone(), b.clone()], event, wrong, 2).is_err());
    }
    let broken = header(11, [8; 32], [4; 32], [5; 32], [6; 32]);
    let broken_anchor = point(decode_execution_header(&broken).unwrap());
    assert!(ancestry(&[a, broken], event, broken_anchor, 1).is_err());
}

#[test]
fn consumed_state_proves_locked_code_account_slot_and_bit() {
    let address = [7; 20];
    let code = [8; 32];
    for nonce in [0, 7, 255, 256, 511, u64::MAX] {
        let bit = (nonce & 255) as usize;
        let mut bits = [0; 32];
        bits[31 - bit / 8] = 1 << (bit % 8);
        let slot_key = keccak256(&[&consumed_slot(nonce)]);
        let slots = vec![(slot_key.to_vec(), rlp_encode_uint_bytes(&bits))];
        let storage = mpt_root(&slots).unwrap();
        let account = rlp_encode_list(&[
            rlp_encode_u64(0),
            rlp_encode_u64(0),
            rlp_encode_bytes(&storage),
            rlp_encode_bytes(&code),
        ]);
        let account_key = keccak256(&[&address]);
        let accounts = vec![(account_key.to_vec(), account)];
        let state = mpt_root(&accounts).unwrap();
        let ap = mpt_proof(&accounts, &account_key).unwrap();
        let sp = mpt_proof(&slots, &slot_key).unwrap();
        assert_eq!(
            account_storage_root(state, address, code, &ap).unwrap(),
            storage
        );
        assert!(account_storage_root(state, address, [9; 32], &ap).is_err());
        assert!(account_storage_root(state, [9; 20], code, &ap).is_err());
        assert!(account_storage_root([9; 32], address, code, &ap).is_err());
        consumed_proof(state, address, code, nonce, &ap, &sp).unwrap();
        assert!(consumed_proof(state, [9; 20], code, nonce, &ap, &sp).is_err());
        assert!(consumed_proof(state, address, [9; 32], nonce, &ap, &sp).is_err());
        assert!(consumed_proof([9; 32], address, code, nonce, &ap, &sp).is_err());
        assert!(consumed_proof(state, address, code, nonce ^ 1, &ap, &sp).is_err());
        assert!(consumed_proof(state, address, code, nonce ^ 256, &ap, &sp).is_err());
        assert!(consumed_proof(state, address, code, nonce, &ap, &ap).is_err());
    }
}

#[test]
fn receipt_evidence_budgets_and_retained_node_order_are_exact() {
    byte_budget([1, 2, 3], 6).unwrap();
    assert!(byte_budget([1, 2, 3], 5).is_err());
    assert!(byte_budget([usize::MAX, 1], usize::MAX).is_err());
    for network in [
        super::super::SccpNetworkV1::EthereumMainnet,
        super::super::SccpNetworkV1::BscMainnet,
    ] {
        let mut params = SccpLightClientParamsV1::defaults_for(network).unwrap();
        assert_eq!(
            ancestry_limit(&params),
            u64::from(params.max_ancestry_headers.min(256)) + 64 * 255
        );
        params.max_backfill_headers = u32::MAX;
        params.max_ancestry_headers = u32::MAX;
        assert_eq!(ancestry_limit(&params), 256 + 64 * 255);
    }
    let evidence = nodes(
        "proof",
        EthereumNativeMptProofV1 {
            nodes: vec![vec![1, 2], vec![3]],
        },
    );
    assert_eq!(
        evidence,
        vec![item("proof.0", vec![1, 2]), item("proof.1", vec![3])]
    );
}
