//! Deterministic opening tests for exact EVM receipt, ancestry and consumed-state custody.

use super::*;
use iroha::data_model::sccp::light_client::{
    SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1, SccpLcFreezeReasonV1,
    SccpLcHeadV1, SccpLcParliamentFreezeV1, SccpLcPointV1, SccpLightClientParamsV1,
    SccpLightClientV1,
};
use iroha_sccp::{
    ethereum_source::{
        EthereumNativeMptProofV1, decode_execution_header, mpt_proof, mpt_root, rlp_encode_bytes,
        rlp_encode_list, rlp_encode_u64, rlp_encode_uint_bytes,
    },
    light_client::profile::GENESIS_PROFILES,
    v1::hashes::keccak256,
};
use iroha_sccp_rpc::evm::{EvmAccountProof, EvmLog, EvmReceipt, EvmStorageProof, U256};
use iroha_sccp_wallet::pure::evm::{Eip1559TransactionV1, EvmSigningKey};

fn target() -> ReceiptTarget {
    ReceiptTarget {
        network: SccpNetworkV1::EthereumMainnet,
        contract: [0x31; 20],
        code_hash: [0x32; 32],
    }
}

fn light_client(network: SccpNetworkV1) -> SccpLightClientV1 {
    SccpLightClientV1 {
        params: SccpLightClientParamsV1::defaults_for(network).unwrap(),
        head: SccpLcHeadV1 {
            latest_set_id: 9,
            latest_finalized: SccpLcPointV1 {
                source_height: 11,
                block_hash: [1; 32],
                source_time_ms: 1_700_000_000_000,
            },
            last_progress_taira_ms: 1_700_000_001_000,
        },
        frozen: None,
        state_hash: [2; 32],
    }
}

#[test]
fn receipt_limits_bind_network_freeze_and_committed_bounds() {
    let mut ethereum = light_client(SccpNetworkV1::EthereumMainnet);
    let defaults = receipt_limits(SccpNetworkV1::EthereumMainnet, &ethereum).unwrap();
    assert_eq!(defaults.0, 257);
    assert_eq!(defaults.1, ethereum.params.max_proof_bytes as usize);
    ethereum.params.max_ancestry_headers = 1;
    ethereum.params.max_proof_bytes = 1024;
    assert_eq!(
        receipt_limits(SccpNetworkV1::EthereumMainnet, &ethereum).unwrap(),
        (2, 1024)
    );
    assert!(receipt_limits(SccpNetworkV1::BscMainnet, &ethereum).is_err());
    let bsc = light_client(SccpNetworkV1::BscMainnet);
    assert_eq!(
        receipt_limits(SccpNetworkV1::BscMainnet, &bsc).unwrap().0,
        256
    );
    ethereum.frozen = Some(SccpLcFreezeReasonV1::Parliament(SccpLcParliamentFreezeV1 {
        proposal_id: [9; 32],
    }));
    assert!(receipt_limits(SccpNetworkV1::EthereumMainnet, &ethereum).is_err());
}

fn header_rlp(
    parent: [u8; 32],
    number: u64,
    time_ms: u64,
    state_root: [u8; 32],
    transactions_root: [u8; 32],
    receipts_root: [u8; 32],
    bsc: bool,
) -> Vec<u8> {
    let mut fields = vec![rlp_encode_bytes(&[]); if bsc { 21 } else { 16 }];
    for (index, value) in [
        (0, parent),
        (3, state_root),
        (4, transactions_root),
        (5, receipts_root),
    ] {
        fields[index] = rlp_encode_bytes(&value);
    }
    fields[8] = rlp_encode_u64(number);
    fields[11] = rlp_encode_u64(time_ms / 1000);
    let mut mix = [0u8; 32];
    mix[24..].copy_from_slice(&(time_ms % 1000).to_be_bytes());
    fields[13] = rlp_encode_bytes(&mix);
    rlp_encode_list(&fields)
}

fn make_checkpoint(header: &[u8], time_ms: u64) -> SccpLcCheckpointV1 {
    let decoded = decode_execution_header(header).unwrap();
    SccpLcCheckpointV1 {
        data: SccpLcCheckpointDataV1 {
            source_height: decoded.number,
            block_hash: decoded.hash,
            state_root: Some(decoded.state_root),
            receipts_or_tx_root: decoded.receipts_root,
            source_time_ms: time_ms,
        },
        recorded_at_taira_ms: time_ms + 1,
        origin: SccpLcCheckpointOriginV1::Advance,
    }
}

#[test]
fn receipt_ancestry_requires_every_link_and_exact_original_checkpoint() {
    let first = header_rlp(
        [1; 32],
        10,
        1_700_000_000_000,
        [2; 32],
        [3; 32],
        [4; 32],
        false,
    );
    let decoded = decode_execution_header(&first).unwrap();
    let next = header_rlp(
        decoded.hash,
        11,
        1_700_000_012_000,
        [5; 32],
        [6; 32],
        [7; 32],
        false,
    );
    let checkpoint = make_checkpoint(&next, 1_700_000_012_000);
    let headers = vec![first.clone(), next.clone()];
    let verify = |anchor: &SccpLcCheckpointV1, chain: &[Vec<u8>], limit| {
        verify_header_chain(
            SccpNetworkV1::EthereumMainnet,
            &GENESIS_PROFILES,
            anchor,
            chain,
            limit,
        )
    };
    assert_eq!(verify(&checkpoint, &headers, 2).unwrap(), decoded);
    let mut parliament = checkpoint;
    parliament.data.state_root = None;
    parliament.origin = SccpLcCheckpointOriginV1::Parliament;
    assert_eq!(verify(&parliament, &headers, 2).unwrap(), decoded);
    assert!(verify(&checkpoint, &headers, 1).is_err());
    assert!(verify(&checkpoint, &[], 2).is_err());
    assert!(verify(&checkpoint, &[next, first], 2).is_err());
    for field in 0..5 {
        let mut changed = checkpoint;
        match field {
            0 => changed.data.source_height += 1,
            1 => changed.data.block_hash[0] ^= 1,
            2 => changed.data.state_root = Some([8; 32]),
            3 => changed.data.receipts_or_tx_root[0] ^= 1,
            _ => changed.data.source_time_ms += 1,
        }
        assert!(verify(&changed, &headers, 2).is_err());
    }
    let bad_parent = header_rlp(
        [0x99; 32],
        11,
        1_700_000_012_000,
        [5; 32],
        [6; 32],
        [7; 32],
        false,
    );
    assert!(
        verify(
            &make_checkpoint(&bad_parent, 1_700_000_012_000),
            &[headers[0].clone(), bad_parent],
            2
        )
        .is_err()
    );
}

#[test]
fn bsc_receipt_ancestry_retains_milliseconds_and_profile_window() {
    let time_ms = GENESIS_PROFILES.bsc.supported_from_ms + 12_345;
    let header = header_rlp([1; 32], 10, time_ms, [2; 32], [3; 32], [4; 32], true);
    let anchor = make_checkpoint(&header, time_ms);
    assert!(
        verify_header_chain(
            SccpNetworkV1::BscMainnet,
            &GENESIS_PROFILES,
            &anchor,
            &[header.clone()],
            1
        )
        .is_ok()
    );
    let mut rounded = anchor;
    rounded.data.source_time_ms = time_ms / 1000 * 1000;
    assert!(
        verify_header_chain(
            SccpNetworkV1::BscMainnet,
            &GENESIS_PROFILES,
            &rounded,
            &[header],
            1
        )
        .is_err()
    );
    let future = GENESIS_PROFILES.bsc.supported_until_ms + 1;
    let unsupported = header_rlp([1; 32], 10, future, [2; 32], [3; 32], [4; 32], true);
    assert!(
        verify_header_chain(
            SccpNetworkV1::BscMainnet,
            &GENESIS_PROFILES,
            &make_checkpoint(&unsupported, future),
            &[unsupported],
            1
        )
        .is_err()
    );
}

fn signed_raw(selected: ReceiptTarget, nonce: u64) -> Vec<u8> {
    Eip1559TransactionV1::contract_call(
        selected.network,
        selected.contract,
        vec![0x12, 0x34],
        nonce,
        1,
        2,
        100_000,
    )
    .unwrap()
    .sign(&EvmSigningKey::from_secret([7; 32]).unwrap())
    .unwrap()
    .raw()
    .to_vec()
}

fn rpc_receipt(hash: [u8; 32], index: u64, success: bool) -> EvmReceipt {
    EvmReceipt {
        tx_type: 2,
        status: Some(u8::from(success)),
        state_root: None,
        cumulative_gas_used: 21_000 * (index + 1),
        logs_bloom: [0; 256],
        logs: vec![],
        transaction_hash: hash,
        transaction_index: index,
        block_hash: [0; 32],
        block_number: 10,
        gas_used: 21_000,
        effective_gas_price: None,
        from: None,
        to: Some(target().contract),
        contract_address: None,
        blob_gas_used: None,
        blob_gas_price: None,
    }
}

struct InclusionFixture {
    raw: Vec<u8>,
    receipt: EvmReceipt,
    header: iroha_sccp::ethereum_source::EthereumExecutionHeaderFieldsV1,
    transactions: EthereumNativeMptProofV1,
    receipts: EthereumNativeMptProofV1,
}

impl InclusionFixture {
    fn new(success: bool, state_root: [u8; 32]) -> Self {
        Self::with_logs(success, state_root, Vec::new())
    }

    fn with_logs(success: bool, state_root: [u8; 32], logs: Vec<EvmLog>) -> Self {
        let raw = signed_raw(target(), 1);
        let transactions = vec![
            (rlp_encode_u64(0), signed_raw(target(), 0)),
            (rlp_encode_u64(1), raw.clone()),
        ];
        let mut receipt = rpc_receipt(keccak256(&[&raw]), 1, success);
        receipt.logs = logs;
        let first_receipt = rpc_receipt(keccak256(&[&transactions[0].1]), 0, true);
        let receipts = vec![
            (
                rlp_encode_u64(0),
                iroha_sccp_rpc::builders::ethereum::receipt_rlp(&first_receipt),
            ),
            (
                rlp_encode_u64(1),
                iroha_sccp_rpc::builders::ethereum::receipt_rlp(&receipt),
            ),
        ];
        let header = decode_execution_header(&header_rlp(
            [1; 32],
            10,
            1_700_000_000_000,
            state_root,
            mpt_root(&transactions).unwrap(),
            mpt_root(&receipts).unwrap(),
            false,
        ))
        .unwrap();
        let mut receipt = receipt;
        receipt.block_hash = header.hash;
        Self {
            raw,
            receipt,
            header,
            transactions: mpt_proof(&transactions, &rlp_encode_u64(1)).unwrap(),
            receipts: mpt_proof(&receipts, &rlp_encode_u64(1)).unwrap(),
        }
    }

    fn verify(&self) -> Result<VerifiedEvmReceipt> {
        verify_receipt_inclusion(
            target(),
            &self.raw,
            self.receipt.clone(),
            self.header,
            &self.transactions,
            &self.receipts,
        )
    }
}

#[test]
fn original_transaction_and_same_index_receipt_prove_success_and_failure() {
    for success in [false, true] {
        let fixture = InclusionFixture::new(success, [0x42; 32]);
        let verified = fixture.verify().unwrap();
        assert_eq!(verified.status, Some(u8::from(success)));
        assert_eq!(verified.transaction_hash, keccak256(&[&fixture.raw]));
        assert_eq!(verified.header, fixture.header);
    }
}

#[test]
fn authenticated_receipt_logs_reject_rpc_metadata_and_payload_substitution() {
    let mut fixture = InclusionFixture::with_logs(
        true,
        [0x42; 32],
        vec![EvmLog {
            address: target().contract,
            topics: vec![[9; 32]],
            data: vec![10],
            log_index: Some(0),
            transaction_index: Some(1),
            transaction_hash: None,
            block_hash: None,
            block_number: Some(10),
            removed: false,
        }],
    );
    fixture.verify().unwrap();
    fixture.receipt.logs[0].block_hash = Some(fixture.header.hash);
    fixture.receipt.logs[0].transaction_hash = Some(fixture.receipt.transaction_hash);
    fixture.verify().unwrap();
    for change in 0..8 {
        let mut forged = fixture.receipt.clone();
        let log = &mut forged.logs[0];
        match change {
            0 => log.removed = true,
            1 => log.block_hash = Some([0; 32]),
            2 => log.block_number = Some(11),
            3 => log.transaction_hash = Some([0; 32]),
            4 => log.transaction_index = Some(0),
            5 => log.address[0] ^= 1,
            6 => log.data.push(0),
            _ => log.topics[0][0] ^= 1,
        }
        assert!(
            verify_receipt_inclusion(
                target(),
                &fixture.raw,
                forged,
                fixture.header,
                &fixture.transactions,
                &fixture.receipts,
            )
            .is_err(),
            "change {change}"
        );
    }
}

#[test]
fn receipt_metadata_cannot_substitute_transaction_or_receipt_openings() {
    let fixture = InclusionFixture::new(true, [0x42; 32]);
    for field in 0..7 {
        let mut receipt = fixture.receipt.clone();
        match field {
            0 => receipt.transaction_hash[0] ^= 1,
            1 => receipt.transaction_index = 0,
            2 => receipt.block_hash[0] ^= 1,
            3 => receipt.block_number += 1,
            4 => receipt.status = Some(0),
            5 => receipt.tx_type = 1,
            _ => receipt.cumulative_gas_used += 1,
        }
        assert!(
            verify_receipt_inclusion(
                target(),
                &fixture.raw,
                receipt,
                fixture.header,
                &fixture.transactions,
                &fixture.receipts
            )
            .is_err()
        );
    }
    let replacement = signed_raw(target(), 2);
    let mut receipt = fixture.receipt.clone();
    receipt.transaction_hash = keccak256(&[&replacement]);
    assert!(
        verify_receipt_inclusion(
            target(),
            &replacement,
            receipt,
            fixture.header,
            &fixture.transactions,
            &fixture.receipts
        )
        .is_err()
    );
    let mut header = fixture.header;
    header.transactions_root[0] ^= 1;
    assert!(
        verify_receipt_inclusion(
            target(),
            &fixture.raw,
            fixture.receipt.clone(),
            header,
            &fixture.transactions,
            &fixture.receipts
        )
        .is_err()
    );
    let mut broken = fixture.receipts.clone();
    broken.nodes[0][0] ^= 1;
    assert!(
        verify_receipt_inclusion(
            target(),
            &fixture.raw,
            fixture.receipt.clone(),
            fixture.header,
            &fixture.transactions,
            &broken
        )
        .is_err()
    );
}

#[test]
fn receipt_opening_refuses_noncanonical_status_and_foreign_call_target() {
    // Both invalid status values project to the same failed-receipt RLP: the
    // opening succeeds, so rejection must also enforce canonical status metadata.
    let fixture = InclusionFixture::new(false, [0x42; 32]);
    for status in [None, Some(2)] {
        let mut receipt = fixture.receipt.clone();
        receipt.status = status;
        assert!(
            verify_receipt_inclusion(
                target(),
                &fixture.raw,
                receipt,
                fixture.header,
                &fixture.transactions,
                &fixture.receipts
            )
            .is_err()
        );
    }
    for changed in [
        ReceiptTarget {
            network: SccpNetworkV1::BscMainnet,
            ..target()
        },
        ReceiptTarget {
            contract: [0x99; 20],
            ..target()
        },
    ] {
        assert!(
            verify_receipt_inclusion(
                changed,
                &fixture.raw,
                fixture.receipt.clone(),
                fixture.header,
                &fixture.transactions,
                &fixture.receipts
            )
            .is_err()
        );
    }
}

fn storage_proof(nonce: u64, set_bit: u64) -> ([u8; 32], EvmAccountProof) {
    let slot = consumed_slot(nonce);
    let key = keccak256(&[&slot]);
    let mut word = [0u8; 32];
    word[31 - (set_bit % 256 / 8) as usize] = 1 << (set_bit % 8);
    let storage = vec![(key.to_vec(), rlp_encode_uint_bytes(&word))];
    let storage_root = mpt_root(&storage).unwrap();
    let account = rlp_encode_list(&[
        rlp_encode_u64(1),
        rlp_encode_u64(0),
        rlp_encode_bytes(&storage_root),
        rlp_encode_bytes(&target().code_hash),
    ]);
    let account_key = keccak256(&[&target().contract]);
    let accounts = vec![(account_key.to_vec(), account)];
    (
        mpt_root(&accounts).unwrap(),
        EvmAccountProof {
            address: target().contract,
            balance: U256::ZERO,
            code_hash: target().code_hash,
            nonce: 1,
            storage_hash: storage_root,
            account_proof: mpt_proof(&accounts, &account_key).unwrap().nodes,
            storage_proof: vec![EvmStorageProof {
                key: slot,
                value: U256::from_be_bytes(word),
                proof: mpt_proof(&storage, &key).unwrap().nodes,
            }],
        },
    )
}

#[test]
fn consumed_storage_opens_exact_bitmap_across_word_boundaries() {
    for nonce in [0, 255, 256, u64::MAX] {
        let (root, proof) = storage_proof(nonce, nonce);
        let receipt = InclusionFixture::new(true, root).verify().unwrap();
        verify_consumed_storage(target(), &receipt, nonce, &proof).unwrap();
    }
    assert_ne!(consumed_slot(255), consumed_slot(256));
    assert_eq!(consumed_slot(0), consumed_slot(255));
}

#[test]
fn call_target_proof_requires_the_locked_runtime_account_and_state() {
    let (root, proof) = storage_proof(7, 7);
    let opening = EthereumNativeMptProofV1 {
        nodes: proof.account_proof,
    };
    assert_eq!(
        account_storage_root(target(), root, &opening).unwrap(),
        proof.storage_hash
    );
    assert!(account_storage_root(target(), [9; 32], &opening).is_err());
    for changed in [
        ReceiptTarget {
            contract: [9; 20],
            ..target()
        },
        ReceiptTarget {
            code_hash: [9; 32],
            ..target()
        },
    ] {
        assert!(account_storage_root(changed, root, &opening).is_err());
    }
}

#[test]
fn consumed_storage_refuses_wrong_bit_target_key_and_root() {
    let nonce = 255;
    let (root, proof) = storage_proof(nonce, nonce);
    let receipt = InclusionFixture::new(true, root).verify().unwrap();
    for field in 0..4 {
        let mut changed = proof.clone();
        match field {
            0 => changed.address[0] ^= 1,
            1 => changed.storage_proof[0].key[0] ^= 1,
            2 => changed.account_proof[0][0] ^= 1,
            _ => changed.storage_proof[0].proof[0][0] ^= 1,
        }
        assert!(verify_consumed_storage(target(), &receipt, nonce, &changed).is_err());
    }
    for changed in [
        ReceiptTarget {
            network: SccpNetworkV1::BscMainnet,
            ..target()
        },
        ReceiptTarget {
            contract: [0x99; 20],
            ..target()
        },
        ReceiptTarget {
            code_hash: [0x99; 32],
            ..target()
        },
    ] {
        assert!(verify_consumed_storage(changed, &receipt, nonce, &proof).is_err());
    }
    let wrong_root = InclusionFixture::new(true, [0x99; 32]).verify().unwrap();
    assert!(verify_consumed_storage(target(), &wrong_root, nonce, &proof).is_err());
    let (wrong_bit_root, wrong_bit_proof) = storage_proof(nonce, 254);
    let wrong_bit_receipt = InclusionFixture::new(true, wrong_bit_root)
        .verify()
        .unwrap();
    assert!(
        verify_consumed_storage(target(), &wrong_bit_receipt, nonce, &wrong_bit_proof).is_err()
    );
    assert!(verify_consumed_storage(target(), &receipt, 256, &proof).is_err());
}

#[test]
fn consumed_storage_keeps_the_combined_authenticated_proof_budget() {
    let nonce = 255;
    let (root, proof) = storage_proof(nonce, nonce);
    let mut receipt = InclusionFixture::new(true, root).verify().unwrap();
    let needed = proof
        .account_proof
        .iter()
        .chain(proof.storage_proof[0].proof.iter())
        .map(Vec::len)
        .sum::<usize>();
    receipt.remaining_proof_bytes = needed;
    verify_consumed_storage(target(), &receipt, nonce, &proof).unwrap();
    receipt.remaining_proof_bytes = needed - 1;
    assert!(verify_consumed_storage(target(), &receipt, nonce, &proof).is_err());
}

#[test]
fn proof_evidence_roundtrips_a_framed_norito_opening() {
    let fixture = InclusionFixture::new(true, [0x42; 32]);
    for (label, proof) in [
        ("evm.original_transaction.proof", &fixture.transactions),
        ("evm.original_receipt.proof", &fixture.receipts),
    ] {
        let evidence = proof_evidence(label, proof).unwrap();
        assert_eq!(evidence.label, label);
        let decoded: EthereumNativeMptProofV1 = norito::decode_from_bytes(&evidence.bytes).unwrap();
        assert_eq!(&decoded, proof);
        assert_eq!(norito::to_bytes(&decoded).unwrap(), evidence.bytes);
        let mut damaged = evidence.bytes.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(norito::decode_from_bytes::<EthereumNativeMptProofV1>(&damaged).is_err());
    }
}

fn budget_client() -> EvmClient {
    EvmClient::new(
        HttpTransport::new(
            EndpointSet::parse(&["http://127.0.0.1:1"], &[]).unwrap(),
            iroha_sccp_rpc::HttpConfig::default(),
            FailoverPolicy::default(),
        )
        .unwrap(),
    )
}

#[test]
fn receipt_budget_preserves_an_existing_owner_and_deadline() {
    use std::time::Duration;
    let client = budget_client();
    let target = target();
    let transport = EvmTransport {
        client: &client,
        network: target.network,
        contract: target.contract,
        code_hash: target.code_hash,
    };
    let budget = client.transport().budget();
    let owner = budget.start(Duration::from_secs(60));
    let original = budget.deadline().unwrap();
    let (deadline, nested_guard) = transport.receipt_budget(Duration::from_secs(120)).unwrap();
    assert_eq!(deadline, original);
    assert!(nested_guard.is_none());
    transport.require_receipt_deadline(deadline).unwrap();
    drop(nested_guard);
    assert_eq!(budget.deadline(), Some(original));
    budget.set_deadline(Some(original + Duration::from_secs(1)));
    assert!(transport.require_receipt_deadline(deadline).is_err());
    drop(owner);
    assert_eq!(budget.deadline(), None);
}

#[test]
fn receipt_budget_owns_only_its_new_deadline_and_refuses_expiry() {
    use std::time::{Duration, Instant};
    let client = budget_client();
    let target = target();
    let transport = EvmTransport {
        client: &client,
        network: target.network,
        contract: target.contract,
        code_hash: target.code_hash,
    };
    let budget = client.transport().budget();
    assert!(transport.receipt_budget(Duration::ZERO).is_err());
    let (deadline, guard) = transport.receipt_budget(Duration::from_secs(60)).unwrap();
    assert!(guard.is_some());
    transport.require_receipt_deadline(deadline).unwrap();
    drop(guard);
    assert_eq!(budget.deadline(), None);
    assert!(transport.require_receipt_deadline(deadline).is_err());
    let expired = Instant::now();
    budget.set_deadline(Some(expired));
    let (retained, no_guard) = transport.receipt_budget(Duration::from_secs(60)).unwrap();
    assert_eq!(retained, expired);
    assert!(no_guard.is_none());
    assert!(transport.require_receipt_deadline(retained).is_err());
}

#[derive(Debug)]
struct ReceiptAuthorityTransport {
    requests: std::sync::Mutex<Vec<iroha::http::TransportRequest>>,
    max_timeout: std::time::Duration,
    stall: bool,
}

impl iroha::http::HttpTransport for ReceiptAuthorityTransport {
    fn send_blocking(
        &self,
        _request: iroha::http::TransportRequest,
    ) -> Result<iroha::http::Response<Vec<u8>>> {
        panic!("receipt authority reads must use the bounded asynchronous dispatch");
    }

    fn send(&self, request: iroha::http::TransportRequest) -> iroha::http::TransportFuture<'_> {
        Box::pin(async move {
            assert!(
                request
                    .timeout
                    .is_some_and(|timeout| timeout <= self.max_timeout),
                "every authority request must inherit the receipt deadline"
            );
            self.requests.lock().unwrap().push(request);
            if self.stall {
                // Deliberately ignore the request's timeout field: the client's
                // absolute async deadline must cancel even an unresponsive transport.
                std::future::pending().await
            } else {
                // No response content is needed to observe dispatch and timeout behavior.
                Ok(iroha::http::Response::builder()
                    .status(404)
                    .body(Vec::new())
                    .unwrap())
            }
        })
    }
}

fn receipt_authority_fixture(
    timeout: std::time::Duration,
    max_timeout: std::time::Duration,
    stall: bool,
) -> (
    iroha::blocking::Client,
    std::sync::Arc<ReceiptAuthorityTransport>,
) {
    let transport = std::sync::Arc::new(ReceiptAuthorityTransport {
        requests: std::sync::Mutex::new(Vec::new()),
        max_timeout,
        stall,
    });
    let mut config = crate::fallback_config();
    config.torii_request_timeout = timeout;
    let client = iroha::client::Client::builder(config)
        .headers(std::collections::HashMap::from([(
            "x-receipt-authority-fixture".to_owned(),
            "retained".to_owned(),
        )]))
        .http_transport(transport.clone())
        .build()
        .unwrap();
    (
        iroha::blocking::Client::from_client(client).unwrap(),
        transport,
    )
}

fn receipt_authority_read(client: &iroha::blocking::Client, index: usize) -> iroha::Result<()> {
    let api = client.sccp();
    match index {
        0 => api.light_client(target().network).map(|_| ()),
        1 => api.capabilities().map(|_| ()),
        2 => api
            .light_client_checkpoints(target().network, 10)
            .map(|_| ()),
        _ => panic!("only the three receipt authority reads are selected"),
    }
}

#[test]
fn receipt_torii_reads_share_deadline_and_authority() {
    use std::time::{Duration, Instant};
    let evm = budget_client();
    let target = target();
    let transport = EvmTransport {
        client: &evm,
        network: target.network,
        contract: target.contract,
        code_hash: target.code_hash,
    };
    let timeout = Duration::from_secs(60);
    let (source, observed) = receipt_authority_fixture(timeout, timeout, false);
    let (deadline, _guard) = transport.receipt_budget(Duration::from_secs(30)).unwrap();
    let bounded = transport.receipt_authority_client(&source).unwrap();
    assert_eq!(
        bounded.account_client().authority(),
        source.account_client().authority()
    );
    assert_eq!(
        bounded.account_client().network_id(),
        source.account_client().network_id()
    );
    let mut prior_remaining = deadline.saturating_duration_since(Instant::now());
    for index in 0..3 {
        let before_read = deadline.saturating_duration_since(Instant::now());
        assert_eq!(
            receipt_authority_read(&bounded, index)
                .unwrap_err()
                .http_status(),
            Some(404)
        );
        let requests = observed.requests.lock().unwrap();
        assert_eq!(requests.len(), index + 1, "authority reads must not retry");
        let request = &requests[index];
        let remaining = request.timeout.unwrap();
        assert!(remaining <= before_read && remaining <= prior_remaining);
        assert!(
            request.headers.iter().any(|(name, value)| {
                name == "x-receipt-authority-fixture" && value == "retained"
            })
        );
        prior_remaining = remaining;
    }
    // Creating the bounded view must not shorten the caller's original context.
    assert_eq!(
        receipt_authority_read(&source, 0)
            .unwrap_err()
            .http_status(),
        Some(404)
    );
    let requests = observed.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[3].timeout, Some(timeout));
    assert_eq!(requests[0].url, requests[3].url);
    assert_eq!(requests[0].headers, requests[3].headers);
    assert_eq!(requests[0].body, requests[3].body);
    assert_eq!(requests[1].url.path(), "/v1/sccp/capabilities");
    assert!(requests[2].url.path().ends_with("/checkpoints"));
    assert_eq!(requests[2].url.query(), Some("covering=10"));
}

#[test]
fn receipt_torii_stalled_reads_are_canceled_without_retry() {
    use std::time::Duration;
    // A zero SDK timeout and a much longer timeout must both retain the same
    // finite receipt bound, independently at each of the three read sites.
    for configured in [Duration::ZERO, Duration::from_secs(2)] {
        for index in 0..3 {
            let evm = budget_client();
            let target = target();
            let transport = EvmTransport {
                client: &evm,
                network: target.network,
                contract: target.contract,
                code_hash: target.code_hash,
            };
            let bound = Duration::from_millis(100);
            let (source, observed) = receipt_authority_fixture(configured, bound, true);
            let (_deadline, _guard) = transport.receipt_budget(bound).unwrap();
            let bounded = transport.receipt_authority_client(&source).unwrap();
            assert!(matches!(
                receipt_authority_read(&bounded, index),
                Err(iroha::Error::Timeout { .. })
            ));
            assert_eq!(
                observed.requests.lock().unwrap().len(),
                1,
                "no retry after expiry"
            );
            assert!(matches!(
                receipt_authority_read(&bounded, index),
                Err(iroha::Error::Timeout { .. })
            ));
            assert_eq!(
                observed.requests.lock().unwrap().len(),
                1,
                "expired reads must not dispatch"
            );
        }
    }
}

#[test]
fn receipt_torii_client_refuses_missing_or_expired_budget() {
    use std::time::{Duration, Instant};
    let evm = budget_client();
    let target = target();
    let transport = EvmTransport {
        client: &evm,
        network: target.network,
        contract: target.contract,
        code_hash: target.code_hash,
    };
    let (source, observed) = receipt_authority_fixture(Duration::ZERO, Duration::ZERO, false);
    assert!(transport.receipt_authority_client(&source).is_err());
    evm.transport().budget().set_deadline(Some(Instant::now()));
    assert!(transport.receipt_authority_client(&source).is_err());
    // A stricter deadline already on the source context cannot be extended.
    let expired = source.with_request_deadline(Instant::now()).unwrap();
    evm.transport().budget().set_deadline(None);
    let (_deadline, _guard) = transport.receipt_budget(Duration::from_secs(30)).unwrap();
    let bounded = transport.receipt_authority_client(&expired).unwrap();
    assert!(matches!(
        receipt_authority_read(&bounded, 0),
        Err(iroha::Error::Timeout { .. })
    ));
    assert!(observed.requests.lock().unwrap().is_empty());
}
