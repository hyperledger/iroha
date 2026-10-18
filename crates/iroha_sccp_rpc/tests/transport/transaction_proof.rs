//! Raw transaction proofs retain exact envelopes and fail closed within finite RPC budgets.

use super::*;
use iroha_sccp::{
    ethereum_source::{
        EthereumMptRoleV1, MAX_MPT_NODE_BYTES, MAX_MPT_PROOF_BYTES, mpt_proof, mpt_root,
        rlp_encode_bytes, rlp_encode_list, rlp_encode_u64, verify_mpt_inclusion_ref,
    },
    v1::hashes::keccak256,
};
use iroha_sccp_rpc::{
    builders::ethereum::header_rlp,
    endpoints::PollBudgetGuard,
    evm::{EvmBlock, EvmHeader, format_data},
    limits::EVM_BLOCK_RESPONSE_BYTES,
};

fn entries(raw: &[Vec<u8>]) -> Vec<(Vec<u8>, Vec<u8>)> {
    raw.iter()
        .enumerate()
        .map(|(index, raw)| (rlp_encode_u64(index as u64), raw.clone()))
        .collect()
}

fn rehash(block: &mut EvmBlock) {
    block.header.hash = keccak256(&[&header_rlp(&block.header)]);
}

fn block(raw: &[Vec<u8>]) -> EvmBlock {
    let mut block = EvmBlock {
        header: EvmHeader {
            hash: [0; 32],
            parent_hash: [1; 32],
            ommers_hash: [2; 32],
            beneficiary: [3; 20],
            state_root: [4; 32],
            transactions_root: mpt_root(&entries(raw)).unwrap(),
            receipts_root: [5; 32],
            logs_bloom: [0; 256],
            difficulty: U256::ZERO,
            number: 1,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1,
            extra_data: vec![],
            mix_hash: [6; 32],
            nonce: [0; 8],
            base_fee_per_gas: Some(U256::ZERO),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        },
        transactions: raw.iter().map(|raw| keccak256(&[raw])).collect(),
        uncles: vec![],
        size: None,
        raw: Value::Null,
    };
    rehash(&mut block);
    block
}

fn raw_reply(raw: &[u8]) -> Reply {
    Reply::rpc_result(&norito::json::to_json(&format_data(raw)).unwrap())
}

fn replies(raw: &[Vec<u8>], target: usize) -> Vec<Reply> {
    std::iter::once(target)
        .chain((0..raw.len()).filter(|index| *index != target))
        .map(|index| raw_reply(&raw[index]))
        .collect()
}

fn proof_client(server: &MockServer, cap: usize) -> (EvmClient, PollBudgetGuard) {
    let set = EndpointSet::parse(&[&server.url()], &[]).unwrap();
    let transport = transport_with(
        set,
        config(Duration::from_secs(5)).with_max_response_bytes(cap),
        1,
    )
    .0;
    let guard = transport.budget().start(Duration::from_secs(5));
    (EvmClient::new(transport), guard)
}

fn mixed_envelopes() -> Vec<Vec<u8>> {
    let to = rlp_encode_bytes(&[7; 20]);
    let input = rlp_encode_bytes(&[8; 40]);
    let legacy = rlp_encode_list(&[
        rlp_encode_u64(0),
        rlp_encode_u64(1),
        rlp_encode_u64(50_000),
        to.clone(),
        rlp_encode_u64(0),
        input.clone(),
        rlp_encode_u64(27),
        rlp_encode_u64(1),
        rlp_encode_u64(2),
    ]);
    let access_list = rlp_encode_list(&[
        rlp_encode_u64(1),
        rlp_encode_u64(1),
        rlp_encode_u64(1),
        rlp_encode_u64(50_000),
        to.clone(),
        rlp_encode_u64(0),
        input.clone(),
        rlp_encode_list(&[]),
        rlp_encode_u64(0),
        rlp_encode_u64(1),
        rlp_encode_u64(2),
    ]);
    let dynamic_fee = rlp_encode_list(&[
        rlp_encode_u64(1),
        rlp_encode_u64(2),
        rlp_encode_u64(1),
        rlp_encode_u64(2),
        rlp_encode_u64(50_000),
        to,
        rlp_encode_u64(0),
        input,
        rlp_encode_list(&[]),
        rlp_encode_u64(0),
        rlp_encode_u64(1),
        rlp_encode_u64(2),
    ]);
    vec![
        legacy,
        [vec![1], access_list].concat(),
        [vec![2], dynamic_fee].concat(),
        vec![0x7f, 0xc0], // An unknown envelope type remains opaque too.
    ]
}

#[test]
fn transaction_proof_opens_exact_mixed_envelopes_at_each_index() {
    let raw = mixed_envelopes();
    let block = block(&raw);
    for target in 0..raw.len() {
        let server = MockServer::start(replies(&raw, target));
        let (client, _guard) = proof_client(&server, HttpConfig::default().max_response_bytes);
        let deadline = client.transport().budget().deadline();
        let proof = client
            .block_transaction_proof(&block, target as u64, 4096)
            .unwrap();
        assert_eq!(
            verify_mpt_inclusion_ref(
                block.header.transactions_root,
                &rlp_encode_u64(target as u64),
                &proof,
                EthereumMptRoleV1::Transaction,
            )
            .unwrap(),
            raw[target],
        );
        assert_eq!(client.transport().budget().deadline(), deadline);
        let expected =
            std::iter::once(target).chain((0..raw.len()).filter(|index| *index != target));
        let requests = server.requests();
        assert_eq!(requests.len(), raw.len());
        for (request, index) in requests.iter().zip(expected) {
            let request = request.json();
            assert_eq!(
                request.get("method").and_then(Value::as_str),
                Some("eth_getRawTransactionByHash")
            );
            assert_eq!(
                request.get("params"),
                Some(&Value::Array(vec![Value::from(format_data(
                    &block.transactions[index]
                ))]))
            );
        }
    }
}

#[test]
fn transaction_proof_supports_short_inline_children() {
    let raw = vec![vec![0xc0], vec![1, 0xc0], vec![2, 0xc0]];
    let block = block(&raw);
    let server = MockServer::start(replies(&raw, 1));
    let (client, _guard) = proof_client(&server, 4096);
    let proof = client.block_transaction_proof(&block, 1, 4096).unwrap();
    assert_eq!(proof.nodes.len(), 1, "short children must remain inline");
    assert_eq!(
        verify_mpt_inclusion_ref(
            block.header.transactions_root,
            &rlp_encode_u64(1),
            &proof,
            EthereumMptRoleV1::Transaction
        )
        .unwrap(),
        raw[1],
    );
}

#[test]
fn transaction_proof_refuses_missing_malformed_empty_and_substituted_envelopes() {
    let raw = mixed_envelopes();
    let block = block(&raw);
    for reply in [
        Reply::rpc_result("null"),
        Reply::rpc_result("\"0x\""),
        Reply::rpc_result("\"0x1\""),
        Reply::rpc_result("\"0xgg\""),
        raw_reply(&raw[0]),
    ] {
        let server = MockServer::start(vec![reply]);
        let (client, _guard) = proof_client(&server, 4096);
        assert!(matches!(
            client.block_transaction_proof(&block, 2, 4096),
            Err(RpcError::InvalidResponse { .. })
        ));
        assert_eq!(server.request_count(), 1);
    }
}

#[test]
fn transaction_proof_refuses_wrong_root_order_and_duplicate_envelopes() {
    let raw = mixed_envelopes();
    for case in 0..4 {
        let mut block = block(&raw);
        let mut served = raw.clone();
        match case {
            0 => block.header.transactions_root = [0x42; 32],
            1 => {
                block.transactions.swap(0, 1);
                served.swap(0, 1);
            }
            2 => {
                block.transactions[1] = block.transactions[0];
                served[1] = served[0].clone();
            }
            _ => {
                served[1] = served[0].clone();
            }
        }
        // The receipt root is unchanged, even when the transaction root/list is wrong.
        assert_eq!(block.header.receipts_root, [5; 32]);
        rehash(&mut block);
        let server = MockServer::start(replies(&served, 0));
        let (client, _guard) = proof_client(&server, 4096);
        assert!(
            matches!(
                client.block_transaction_proof(&block, 0, 4096),
                Err(RpcError::InvalidResponse { .. })
            ),
            "case {case}"
        );
        assert_eq!(
            server.request_count(),
            match case {
                2 => 0,
                3 => 2,
                _ => raw.len(),
            }
        );
    }
}

#[test]
fn transaction_proof_refuses_invalid_header_target_limits_and_count_without_io() {
    let raw = mixed_envelopes();
    for case in 0..7 {
        let mut block = block(&raw);
        let mut target = 0;
        let mut limit = 4096;
        match case {
            0 => block.header.hash[0] ^= 1,
            1 => target = raw.len() as u64,
            2 => limit = 0,
            3 => limit = MAX_MPT_PROOF_BYTES + 1,
            4 => block.transactions = vec![[0; 32]; EVM_BLOCK_RESPONSE_BYTES / 68 + 1],
            5 => block.transactions.clear(),
            _ => target = u64::MAX,
        }
        let server = MockServer::start(vec![]);
        let (client, _guard) = proof_client(&server, HttpConfig::default().max_response_bytes);
        assert!(
            client
                .block_transaction_proof(&block, target, limit)
                .is_err(),
            "case {case}"
        );
        assert_eq!(server.request_count(), 0);
    }
}

#[test]
fn transaction_proof_requires_and_preserves_a_finite_original_deadline() {
    let block = block(&mixed_envelopes());
    let server = MockServer::start(vec![]);
    let client = evm(&server);
    assert!(matches!(
        client.block_transaction_proof(&block, 0, 4096),
        Err(RpcError::InvalidRequest(_))
    ));
    assert_eq!(client.transport().budget().deadline(), None);
    let deadline = Instant::now();
    client.transport().budget().set_deadline(Some(deadline));
    assert!(matches!(
        client.block_transaction_proof(&block, 0, 4096),
        Err(RpcError::BudgetExhausted { .. })
    ));
    assert_eq!(client.transport().budget().deadline(), Some(deadline));
    assert_eq!(server.request_count(), 0);
}

#[test]
fn transaction_proof_stops_on_original_deadline_during_acquisition() {
    let raw = mixed_envelopes();
    let block = block(&raw);
    let server = MockServer::start(vec![Reply::Stall(Duration::from_millis(400))]);
    let client = evm(&server);
    let _guard = client
        .transport()
        .budget()
        .start(Duration::from_millis(150));
    let deadline = client.transport().budget().deadline();
    let error = client.block_transaction_proof(&block, 0, 4096).unwrap_err();
    assert!(
        matches!(error, RpcError::BudgetExhausted { .. })
            || matches!(error.last_failure(), RpcError::Timeout { .. }),
        "{error:?}"
    );
    assert_eq!(client.transport().budget().deadline(), deadline);
    assert_eq!(server.request_count(), 1);
}

#[test]
fn transaction_proof_reports_unsupported_raw_method_without_fallback() {
    let block = block(&mixed_envelopes());
    for code in [-32601, -32004] {
        let server = MockServer::start(vec![Reply::rpc_errors(&format!(
            r#"{{"jsonrpc":"2.0","id":0,"error":{{"code":{code},"message":"unavailable"}}}}"#
        ))]);
        let (client, _guard) = proof_client(&server, 4096);
        let error = client.block_transaction_proof(&block, 0, 4096).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("eth_getRawTransactionByHash is required"),
            "{error:?}"
        );
        assert_eq!(server.request_count(), 1);
        assert_eq!(
            server.requests()[0]
                .json()
                .get("method")
                .and_then(Value::as_str),
            Some("eth_getRawTransactionByHash")
        );
    }
}

#[test]
fn transaction_proof_enforces_exact_proof_bytes_before_returning() {
    let raw = mixed_envelopes();
    let block = block(&raw);
    let exact = mpt_proof(&entries(&raw), &rlp_encode_u64(2))
        .unwrap()
        .byte_len();
    for limit in [exact, exact - 1] {
        let server = MockServer::start(replies(&raw, 2));
        let (client, _guard) = proof_client(&server, 4096);
        let result = client.block_transaction_proof(&block, 2, limit);
        assert_eq!(result.is_ok(), limit == exact);
        assert_eq!(server.request_count(), raw.len());
    }
}

#[test]
fn transaction_proof_fetches_target_first_and_rejects_oversized_target_early() {
    let raw = mixed_envelopes();
    let block = block(&raw);
    let server = MockServer::start(vec![raw_reply(&raw[2])]);
    let (client, _guard) = proof_client(&server, 4096);
    assert!(
        client
            .block_transaction_proof(&block, 2, raw[2].len() - 1)
            .is_err()
    );
    assert_eq!(server.request_count(), 1);
    assert_eq!(
        server.requests()[0].json().get("params"),
        Some(&Value::Array(vec![Value::from(format_data(
            &block.transactions[2]
        ))]))
    );
}

#[test]
fn transaction_proof_enforces_native_per_node_bound() {
    // The raw bytes fit MAX_MPT_NODE_BYTES, but their enclosing trie leaf does not.
    let raw = vec![vec![0x7f; MAX_MPT_NODE_BYTES]];
    let block = block(&raw);
    let server = MockServer::start(replies(&raw, 0));
    let (client, _guard) = proof_client(&server, HttpConfig::default().max_response_bytes);
    let error = client
        .block_transaction_proof(&block, 0, MAX_MPT_PROOF_BYTES)
        .unwrap_err();
    assert!(error.to_string().contains("native bounds"), "{error:?}");
    assert_eq!(server.request_count(), 1);
}

#[test]
fn transaction_proof_streams_past_the_aggregate_response_cap_and_bounds_each_response() {
    let raw: Vec<_> = (0..6).map(|index| vec![index; 100]).collect();
    let block = block(&raw);
    let server = MockServer::start(replies(&raw, 0));
    let (client, _guard) = proof_client(&server, 512);
    assert!(raw.iter().map(Vec::len).sum::<usize>() > 512);
    let proof = client.block_transaction_proof(&block, 0, 4096).unwrap();
    assert_eq!(
        verify_mpt_inclusion_ref(
            block.header.transactions_root,
            &rlp_encode_u64(0),
            &proof,
            EthereumMptRoleV1::Transaction
        )
        .unwrap(),
        raw[0],
    );
    assert_eq!(server.request_count(), 6);

    let server = MockServer::start(vec![raw_reply(&vec![1; 512]).close_delimited()]);
    let (client, _guard) = proof_client(&server, 512);
    let error = client.block_transaction_proof(&block, 0, 4096).unwrap_err();
    assert!(
        matches!(
            error.last_failure(),
            RpcError::ResponseTooLarge { limit: 512, .. }
        ),
        "{error:?}"
    );
    assert_eq!(server.request_count(), 1);
}

fn envelope(nonce: u64, data_bytes: usize) -> Vec<u8> {
    let mut raw = vec![2];
    raw.extend(rlp_encode_list(&[
        rlp_encode_u64(1),
        rlp_encode_u64(nonce),
        rlp_encode_u64(1),
        rlp_encode_u64(2),
        rlp_encode_u64(21_000),
        rlp_encode_bytes(&[3; 20]),
        rlp_encode_u64(0),
        rlp_encode_bytes(&vec![4; data_bytes]),
        rlp_encode_list(&[]),
        rlp_encode_u64(0),
        rlp_encode_bytes(&[5; 32]),
        rlp_encode_bytes(&[6; 32]),
    ]));
    raw
}

#[test]
fn raw_transaction_checks_hash_and_distinguishes_unknown_from_malformed() {
    let raw = envelope(0, 0);
    let hash = keccak256(&[&raw]);
    let server = MockServer::start(vec![raw_reply(&raw), Reply::rpc_result("null")]);
    let client = evm(&server);
    assert_eq!(client.raw_transaction(&hash).unwrap(), Some(raw.clone()));
    assert_eq!(client.raw_transaction(&hash).unwrap(), None);
    for request in server.requests() {
        let value = request.json();
        assert_eq!(
            value.get("method").and_then(Value::as_str),
            Some("eth_getRawTransactionByHash")
        );
        assert_eq!(
            value.get("params"),
            Some(&Value::Array(vec![Value::from(format_data(&hash))]))
        );
    }
    for reply in [raw_reply(&envelope(1, 0)), Reply::rpc_result("\"0x\"")] {
        let server = MockServer::start(vec![reply]);
        assert!(evm(&server).raw_transaction(&hash).is_err());
    }
}

#[test]
fn transaction_trie_acquisition_shares_one_deadline_across_all_requests() {
    let raws: Vec<_> = (0..8).map(|nonce| envelope(nonce, 0)).collect();
    let block = block(&raws);
    let replies = raws
        .iter()
        .enumerate()
        .map(|(index, raw)| Reply::Drip {
            body: format!(
                r#"{{"jsonrpc":"2.0","id":{},"result":"{}"}}"#,
                index + 1,
                format_data(raw)
            )
            .into_bytes(),
            interval: Duration::from_millis(2),
        })
        .collect();
    let server = MockServer::start(replies);
    let set = EndpointSet::parse(&[&server.url()], &[]).unwrap();
    // Each response fits the independent five-second request timeout; the full sequence does
    // not fit one confirmation budget. A per-request reset would incorrectly finish the trie.
    let client = EvmClient::new(transport_with(set, config(Duration::from_secs(5)), 1).0);
    let budget = client.transport().budget().clone();
    let guard = budget.start(Duration::from_millis(1500));
    let deadline = budget.deadline();
    let started = Instant::now();
    let error = client.block_transaction_proof(&block, 0, 4096).unwrap_err();
    assert!(
        matches!(error.last_failure(), RpcError::Timeout { .. }),
        "{error:?}"
    );
    assert!(deadline.is_some_and(|deadline| Instant::now() >= deadline));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(
        (2..raws.len()).contains(&server.request_count()),
        "some valid requests finish, but the whole block must not: {}",
        server.request_count()
    );
    assert_eq!(
        budget.deadline(),
        deadline,
        "no per-transaction deadline renewal"
    );
    drop(guard);
    assert_eq!(budget.deadline(), None);
}

#[test]
fn raw_transaction_stream_enforces_whole_body_ceiling_and_attempt_deadline() {
    let raw = envelope(0, 1024);
    let hash = keccak256(&[&raw]);
    for close_delimited in [false, true] {
        let reply = raw_reply(&raw);
        let server = MockServer::start(vec![if close_delimited {
            reply.close_delimited()
        } else {
            reply
        }]);
        let set = EndpointSet::parse(&[&server.url()], &[]).unwrap();
        let client = EvmClient::new(
            transport_with(
                set,
                config(Duration::from_secs(5)).with_max_response_bytes(1024),
                1,
            )
            .0,
        );
        let error = client.raw_transaction(&hash).unwrap_err();
        assert!(
            matches!(
                error.last_failure(),
                RpcError::ResponseTooLarge { limit: 1024, .. }
            ),
            "{error:?}"
        );
        assert_eq!(server.request_count(), 1);
    }

    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":"{}"}}"#,
        format_data(&raw)
    )
    .into_bytes();
    let server = MockServer::start(vec![Reply::Drip {
        body,
        interval: Duration::from_millis(20),
    }]);
    let set = EndpointSet::parse(&[&server.url()], &[]).unwrap();
    let client = EvmClient::new(transport_with(set, config(Duration::from_millis(500)), 1).0);
    let started = Instant::now();
    let error = client.raw_transaction(&hash).unwrap_err();
    assert!(
        matches!(error.last_failure(), RpcError::Timeout { .. }),
        "{error:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(server.request_count(), 1);
}
