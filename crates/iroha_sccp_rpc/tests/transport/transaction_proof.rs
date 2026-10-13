//! Raw transaction inclusion, bounded streaming and hostile RPC controls.

use super::*;
use iroha_sccp::{
    ethereum_source::{
        EthereumMptRoleV1, mpt_proof, mpt_root, rlp_encode_bytes, rlp_encode_list, rlp_encode_u64,
        verify_mpt_inclusion,
    },
    v1::hashes::keccak256,
};
use iroha_sccp_rpc::evm::{EvmBlock, format_data};

// The RPC boundary preserves envelopes as opaque bytes. Signature and source-header
// authority are independently checked by its caller; this fixture supplies typed RLP.
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

fn raw_reply(raw: &[u8]) -> Reply {
    Reply::rpc_result(&norito::json::to_json(&format_data(raw)).unwrap())
}

fn block(raws: &[Vec<u8>]) -> EvmBlock {
    let mut value = fixture_json("evm/eth_getBlockByNumber_hashes")
        .get("result")
        .unwrap()
        .clone();
    let entries: Vec<_> = raws
        .iter()
        .enumerate()
        .map(|(index, raw)| (rlp_encode_u64(u64::try_from(index).unwrap()), raw.clone()))
        .collect();
    let fields = value.as_object_mut().unwrap();
    fields.insert(
        "transactions".into(),
        Value::Array(
            raws.iter()
                .map(|raw| Value::from(format_data(&keccak256(&[raw]))))
                .collect(),
        ),
    );
    fields.insert(
        "transactionsRoot".into(),
        Value::from(format_data(&mpt_root(&entries).unwrap())),
    );
    let server = MockServer::start(vec![Reply::rpc_result(
        &norito::json::to_json(&value).unwrap(),
    )]);
    evm(&server)
        .block_by_number(BlockTag::Number(0x18d_af08))
        .unwrap()
        .unwrap()
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
fn transaction_proof_matches_independent_root_path_and_original_raw_at_every_index() {
    let raws = vec![envelope(0, 0), envelope(1, 1), envelope(2, 1024)];
    let block = block(&raws);
    let entries: Vec<_> = raws
        .iter()
        .enumerate()
        .map(|(index, raw)| (rlp_encode_u64(u64::try_from(index).unwrap()), raw.clone()))
        .collect();
    for target in 0..raws.len() {
        let target = u64::try_from(target).unwrap();
        let server = MockServer::start(raws.iter().map(|raw| raw_reply(raw)).collect());
        let proof = evm(&server)
            .block_transaction_proof(&block, target, 4096)
            .unwrap();
        let key = rlp_encode_u64(target);
        assert_eq!(Some(proof.clone()), mpt_proof(&entries, &key));
        assert_eq!(
            verify_mpt_inclusion(
                block.header.transactions_root,
                &key,
                &proof,
                EthereumMptRoleV1::Transaction,
            )
            .unwrap(),
            raws[usize::try_from(target).unwrap()]
        );
        assert_eq!(server.request_count(), raws.len());
    }
}

#[test]
fn transaction_proof_refuses_missing_substituted_reordered_and_wrong_root_answers() {
    let raws = vec![envelope(0, 0), envelope(1, 1)];
    let original = block(&raws);
    for case in 0..5 {
        let mut block = original.clone();
        let mut replies: Vec<_> = raws.iter().map(|raw| raw_reply(raw)).collect();
        match case {
            0 => replies[1] = Reply::rpc_result("null"),
            1 => replies[1] = raw_reply(&envelope(2, 1)),
            2 => replies.swap(0, 1),
            3 => {
                // Matching RPC hashes and order are insufficient when the signed root differs.
                block.transactions.swap(0, 1);
                replies.swap(0, 1);
            }
            _ => block.header.transactions_root[0] ^= 1,
        }
        let server = MockServer::start(replies);
        assert!(
            evm(&server)
                .block_transaction_proof(&block, 0, 4096)
                .is_err(),
            "case {case}"
        );
    }
    let server = MockServer::start(vec![]);
    let client = evm(&server);
    assert!(client.block_transaction_proof(&original, 2, 4096).is_err());
    assert_eq!(server.request_count(), 0);
}

#[test]
fn transaction_proof_streams_without_an_aggregate_budget_and_limits_the_selected_path() {
    let raws = vec![envelope(0, 0), envelope(1, 3072), envelope(2, 3072)];
    let block = block(&raws);
    let cap = 8192;
    assert!(raws.iter().map(|raw| raw.len() * 2).sum::<usize>() > cap);
    let server = MockServer::start(raws.iter().map(|raw| raw_reply(raw)).collect());
    let set = EndpointSet::parse(&[&server.url()], &[]).unwrap();
    let client = EvmClient::new(
        transport_with(
            set,
            config(Duration::from_secs(5)).with_max_response_bytes(cap),
            1,
        )
        .0,
    );
    let proof = client.block_transaction_proof(&block, 0, 1024).unwrap();
    assert!(proof.nodes.iter().map(Vec::len).sum::<usize>() < 1024);
    assert_eq!(server.request_count(), 3);

    let server = MockServer::start(vec![raw_reply(&raws[0])]);
    assert!(
        evm(&server)
            .block_transaction_proof(&block, 0, raws[0].len() - 1)
            .is_err()
    );
    assert_eq!(server.request_count(), 1);

    let server = MockServer::start(raws.iter().map(|raw| raw_reply(raw)).collect());
    assert!(
        evm(&server)
            .block_transaction_proof(&block, 0, raws[0].len() + 16)
            .is_err()
    );
    assert_eq!(server.request_count(), 3);
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
