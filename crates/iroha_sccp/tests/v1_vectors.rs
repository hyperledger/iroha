//! Golden current SCCP v1 vectors (`specs/sccp.md` §11).
//!
//! Regenerates `fixtures/sccp/{payload,commitment_tree,history,evm_calldata}_v1.json`
//! and verifies exact committed bytes. The mixed commitment tree uses native 199-byte
//! control leaves with explicit synthetic certificate/effect identities; these are DATA,
//! not evidence of Parliament authorization. Native EVM scenarios use genuine BLS certificates.
//! `control_v1.json` remains owned by `tests/v1_reference_control.rs`.
//!
//! After a reviewed change, run the ignored `regenerate_v1_vectors` test, then read back
//! with `v1_vectors_match_committed_fixtures` and regenerate the Tolk vectors.

mod reference_support;

use std::{fs, path::PathBuf};

use iroha_data_model::{bridge::SccpNetworkV1, prelude::Numeric};
use iroha_sccp::ethereum_signing::address_of_secret;
use iroha_sccp::v1::{
    amount::taira_units,
    constants::{CODEC_CANONICAL_TEXT, CODEC_TAIRA_ACCOUNT, TON_AMOUNT_BOUND},
    control::{ControlLeafV1, TRACK_PARLIAMENT, control_leaf, control_leaf_preimage},
    evm_abi::{
        TransferToTairaCallV1, TransferToTairaLogV1, ViewCallV1, VoidCallV1, VoidedLogV1,
        apply_control_calldata, apply_control_from_checkpoint_calldata,
        finalize_from_checkpoint_calldata, finalize_from_taira_calldata,
        submit_checkpoints_calldata, void_expired_calldata, void_expired_from_checkpoint_calldata,
        void_frozen_calldata,
    },
    hashes::{
        history_leaf, keccak256, message_id, node, payload_hash, to_hex, transfer_leaf,
        word_address,
    },
    history::{HistoryAccumulatorV1, history_path, history_root},
    merkle::{PromoteOddTree, merkle_root},
    network::{
        ALL_NETWORKS, EXTERNAL_NETWORKS, account_codec, domain, identity_word, network_bytes,
        route_id, tag,
    },
    payload::{PayloadAccountV1, SccpTransferPayloadV1},
};
use norito::json::{Map, Value};

/// Fixed Taira `NetworkId` of every vector (the §3.4 example value).
const TAIRA: [u8; 32] = [0x11; 32];
/// Base Taira time of the vectors (ms).
const T0: u64 = 1_800_000_000_000;
/// One day (ms).
const DAY: u64 = 86_400_000;
/// Outbound mint deadline of every Taira → X vector.
const DEADLINE: u64 = T0 + DAY;
/// Generator named in every fixture.
const GENERATOR: &str = "crates/iroha_sccp/tests/v1_vectors.rs";

// ---------------------------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------------------------

fn obj<const N: usize>(entries: [(&str, Value); N]) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        assert!(
            map.insert(key.to_owned(), value).is_none(),
            "duplicate {key}"
        );
    }
    Value::Object(map)
}

fn header(schema: &str, spec: &str) -> Map {
    let mut map = Map::new();
    map.insert("schema".to_owned(), text(schema));
    map.insert("spec".to_owned(), text(spec));
    map.insert("generator".to_owned(), text(GENERATOR));
    map
}

fn with(mut map: Map, entries: Vec<(&str, Value)>) -> Value {
    for (key, value) in entries {
        assert!(
            map.insert(key.to_owned(), value).is_none(),
            "duplicate {key}"
        );
    }
    Value::Object(map)
}

fn hex_string(bytes: &[u8]) -> String {
    format!("0x{}", to_hex(bytes))
}

fn hex(bytes: &[u8]) -> Value {
    Value::String(hex_string(bytes))
}

fn hexes<T: AsRef<[u8]>>(items: &[T]) -> Value {
    Value::Array(items.iter().map(|item| hex(item.as_ref())).collect())
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn num(value: u64) -> Value {
    assert!(value < (1 << 53), "JSON numbers stay exact in JavaScript");
    Value::from(value)
}

fn dec(value: u128) -> Value {
    Value::String(value.to_string())
}

fn error_name(error: impl core::fmt::Debug) -> Value {
    text(&format!("{error:?}"))
}

fn profile(network: SccpNetworkV1) -> Value {
    text(network.profile_key())
}

// ---------------------------------------------------------------------------------------------
// Shared deterministic inputs
// ---------------------------------------------------------------------------------------------

fn fixture_secret(index: u8) -> [u8; 32] {
    keccak256(&[b"SCCP/FIXTURE/KEY/V1", &[index]])
}

fn fixture_address(index: u8) -> [u8; 20] {
    address_of_secret(&fixture_secret(index)).expect("fixture secret is a valid scalar")
}

fn taira_account(seed: u8) -> Vec<u8> {
    let mut bytes = vec![0x02, 0x01, 0x20];
    bytes.extend_from_slice(&keccak256(&[b"SCCP/FIXTURE/TAIRA/V1", &[seed]]));
    bytes
}

fn external_account(network: SccpNetworkV1, seed: u8) -> Vec<u8> {
    let body = keccak256(&[b"SCCP/FIXTURE/EXTERNAL/V1", &[seed]]);
    match network {
        SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet => body[12..].to_vec(),
        SccpNetworkV1::TonMainnet => {
            let mut bytes = vec![0; 4];
            bytes.extend_from_slice(&body);
            bytes
        }
        SccpNetworkV1::SoraTaira => taira_account(seed),
    }
}

/// The destination word of the fixed deployment on `network` (§3.4).
fn destination_word(network: SccpNetworkV1) -> [u8; 32] {
    match network {
        SccpNetworkV1::TonMainnet => [0x44; 32],
        _ => word_address(&[0x22; 20]),
    }
}

/// The ETH outbound payload with `nonce` used by the tree and calldata vectors.
fn eth_outbound(nonce: u64) -> SccpTransferPayloadV1 {
    SccpTransferPayloadV1::outbound(
        SccpNetworkV1::EthereumMainnet,
        nonce,
        1,
        DEADLINE,
        1_000_000_000 + u128::from(nonce),
        taira_account(1),
        external_account(SccpNetworkV1::EthereumMainnet, 2),
    )
    .expect("valid outbound payload")
}

fn eth_transfer_leaf(nonce: u64) -> [u8; 32] {
    let payload = eth_outbound(nonce);
    let id = payload.message_id(&TAIRA).expect("message id");
    transfer_leaf(&id, &destination_word(SccpNetworkV1::EthereumMainnet))
}

// Synthetic native control fields for tree/path tests, not an enacted certificate.
fn tree_control(control_nonce: u64, paused: bool) -> ControlLeafV1 {
    ControlLeafV1 {
        route_revision: 1,
        control_nonce,
        track: TRACK_PARLIAMENT,
        parliament_paused: u8::from(paused),
        fast_pause_until_ms: 0,
        certificate_id: [0x33; 32],
        effect_hash: [0x44; 32],
    }
}

fn eth_control_leaf(control_nonce: u64, paused: bool) -> [u8; 32] {
    control_leaf(
        &TAIRA,
        SccpNetworkV1::EthereumMainnet,
        &destination_word(SccpNetworkV1::EthereumMainnet),
        &tree_control(control_nonce, paused),
    )
    .expect("valid native control leaf")
}

// ---------------------------------------------------------------------------------------------
// payload_v1.json
// ---------------------------------------------------------------------------------------------

fn direction_payload(
    source: SccpNetworkV1,
    target: SccpNetworkV1,
    index: u64,
) -> SccpTransferPayloadV1 {
    let ton = source == SccpNetworkV1::TonMainnet || target == SccpNetworkV1::TonMainnet;
    let amount = if ton {
        TON_AMOUNT_BOUND - 1
    } else {
        1_500_000_000 + u128::from(index)
    };
    if source == SccpNetworkV1::SoraTaira {
        SccpTransferPayloadV1::outbound(
            target,
            7 + index,
            1,
            DEADLINE,
            amount,
            taira_account(u8::try_from(index).expect("small index")),
            external_account(target, u8::try_from(index).expect("small index")),
        )
    } else {
        SccpTransferPayloadV1::inbound(
            source,
            3 + index,
            2,
            amount,
            external_account(source, u8::try_from(index).expect("small index")),
            taira_account(u8::try_from(index).expect("small index")),
        )
    }
    .expect("valid direction payload")
}

/// An account of the removed TRON profile in its retired codec 5 form: `0x41` then 20 bytes.
fn retired_tron_account(seed: u8) -> PayloadAccountV1 {
    let body = keccak256(&[b"SCCP/FIXTURE/EXTERNAL/V1", &[seed]]);
    let mut bytes = vec![0x41];
    bytes.extend_from_slice(&body[12..]);
    PayloadAccountV1::new(5, bytes)
}

fn payload_json(label: &str, payload: &SccpTransferPayloadV1) -> Value {
    let encoded = payload.encode().expect("valid payload");
    assert_eq!(
        SccpTransferPayloadV1::decode(&encoded).as_ref(),
        Ok(payload)
    );
    let lane = payload.lane_bytes(&TAIRA).expect("lane");
    let hash = payload_hash(&encoded);
    let id = message_id(&lane, &hash);
    assert_eq!(payload.message_id(&TAIRA), Ok(id));
    obj([
        ("label", text(label)),
        ("source", profile(payload.source().expect("source"))),
        ("target", profile(payload.target().expect("target"))),
        ("source_domain", num(u64::from(payload.source_domain))),
        ("dest_domain", num(u64::from(payload.dest_domain))),
        ("nonce", num(payload.nonce)),
        ("route_revision", num(u64::from(payload.route_revision))),
        ("deadline_ms", num(payload.deadline_ms)),
        ("amount", dec(payload.amount)),
        ("sender_codec", num(u64::from(payload.sender.codec))),
        ("sender", hex(&payload.sender.bytes)),
        ("recipient_codec", num(u64::from(payload.recipient.codec))),
        ("recipient", hex(&payload.recipient.bytes)),
        ("route_id", text(&payload.route_id)),
        ("payload", hex(&encoded)),
        ("payload_hash", hex(&hash)),
        ("lane_bytes", hex(&lane)),
        ("message_id", hex(&id)),
    ])
}

#[allow(
    clippy::too_many_lines,
    reason = "one generator writes one fixture file"
)]
fn rejected_payloads() -> Vec<Value> {
    let base = direction_payload(SccpNetworkV1::SoraTaira, SccpNetworkV1::EthereumMainnet, 0);
    let valid = base.encode().expect("valid payload");
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let mutate = |f: &dyn Fn(&mut SccpTransferPayloadV1)| {
        let mut payload = base.clone();
        f(&mut payload);
        payload.encode_unvalidated().expect("encodable")
    };
    let patch = |index: usize, value: u8| {
        let mut bytes = valid.clone();
        bytes[index] = value;
        bytes
    };
    cases.push(("empty", Vec::new()));
    cases.push(("truncated", valid[..valid.len() - 1].to_vec()));
    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(("trailing_byte", trailing));
    let mut long = valid.clone();
    long.resize(4097, 0);
    cases.push(("longer_than_4096", long));
    cases.push(("wrong_kind", patch(0, 0x01)));
    cases.push(("wrong_version", patch(1, 0x02)));
    cases.push(("same_domains", patch(9, 0x00)));
    cases.push(("unknown_domain_3", patch(9, 0x03)));
    cases.push(("zero_revision", patch(21, 0x00)));
    cases.push(("asset_home_domain_nonzero", patch(33, 0x01)));
    cases.push(("asset_codec_2", patch(34, 0x02)));
    cases.push(("asset_id_not_xor", patch(39, b's')));
    cases.push(("wrong_sender_codec", patch(56, CODEC_CANONICAL_TEXT)));
    cases.push((
        "both_external",
        mutate(&|payload| payload.source_domain = 2),
    ));
    cases.push((
        "outbound_zero_deadline",
        mutate(&|payload| payload.deadline_ms = 0),
    ));
    cases.push(("zero_amount", mutate(&|payload| payload.amount = 0)));
    cases.push((
        "zero_evm_recipient",
        mutate(&|payload| payload.recipient.bytes = vec![0; 20]),
    ));
    cases.push((
        "evm_recipient_21_bytes",
        mutate(&|payload| payload.recipient.bytes = vec![1; 21]),
    ));
    cases.push((
        "recipient_codec_5_on_eth",
        mutate(&|payload| payload.recipient = retired_tron_account(0)),
    ));
    // The removed TRON profile as it encoded its own lanes: domain 5, codec 5 accounts and the
    // route id `taira_tron_xor`.
    cases.push((
        "retired_tron_domain_5_outbound",
        mutate(&|payload| {
            payload.dest_domain = 5;
            payload.recipient = retired_tron_account(0);
            "taira_tron_xor".clone_into(&mut payload.route_id);
        }),
    ));
    cases.push((
        "unassigned_codec_4",
        mutate(&|payload| payload.recipient.codec = 4),
    ));
    cases.push((
        "empty_taira_sender",
        mutate(&|payload| payload.sender.bytes.clear()),
    ));
    cases.push((
        "taira_sender_1025_bytes",
        mutate(&|payload| payload.sender.bytes = vec![0xab; 1025]),
    ));
    cases.push((
        "route_id_mismatch",
        mutate(&|payload| "taira_bsc_xor".clone_into(&mut payload.route_id)),
    ));
    cases.push((
        "route_id_not_printable",
        mutate(&|payload| "taira eth".clone_into(&mut payload.route_id)),
    ));
    cases.push(("route_id_codec_3", {
        let mut bytes = valid.clone();
        let index = bytes.len() - base.route_id.len() - 3;
        bytes[index] = CODEC_TAIRA_ACCOUNT;
        bytes
    }));
    let inbound = direction_payload(SccpNetworkV1::BscMainnet, SccpNetworkV1::SoraTaira, 0);
    let inbound_mutate = |f: &dyn Fn(&mut SccpTransferPayloadV1)| {
        let mut payload = inbound.clone();
        f(&mut payload);
        payload.encode_unvalidated().expect("encodable")
    };
    cases.push((
        "inbound_nonzero_deadline",
        inbound_mutate(&|payload| payload.deadline_ms = 1),
    ));
    cases.push((
        "inbound_zero_evm_sender",
        inbound_mutate(&|payload| payload.sender.bytes.fill(0)),
    ));
    cases.push((
        "sender_codec_5_on_bsc",
        inbound_mutate(&|payload| payload.sender = retired_tron_account(0)),
    ));
    cases.push((
        "retired_tron_domain_5_inbound",
        inbound_mutate(&|payload| {
            payload.source_domain = 5;
            payload.sender = retired_tron_account(0);
            "taira_tron_xor".clone_into(&mut payload.route_id);
        }),
    ));
    let ton = direction_payload(SccpNetworkV1::SoraTaira, SccpNetworkV1::TonMainnet, 0);
    let ton_mutate = |f: &dyn Fn(&mut SccpTransferPayloadV1)| {
        let mut payload = ton.clone();
        f(&mut payload);
        payload.encode_unvalidated().expect("encodable")
    };
    cases.push((
        "ton_amount_2_pow_96",
        ton_mutate(&|payload| payload.amount = TON_AMOUNT_BOUND),
    ));
    cases.push((
        "ton_workchain_minus_1",
        ton_mutate(&|payload| payload.recipient.bytes[..4].fill(0xff)),
    ));
    cases.push((
        "ton_zero_account",
        ton_mutate(&|payload| payload.recipient.bytes[4..].fill(0)),
    ));
    cases
        .into_iter()
        .map(|(label, bytes)| {
            let error = SccpTransferPayloadV1::decode(&bytes).expect_err(label);
            obj([
                ("label", text(label)),
                ("payload", hex(&bytes)),
                ("error", error_name(error)),
            ])
        })
        .collect()
}

fn payload_fixture() -> Value {
    let networks = ALL_NETWORKS
        .iter()
        .map(|network| {
            obj([
                ("profile", profile(*network)),
                ("tag", num(u64::from(tag(*network)))),
                ("domain", num(u64::from(domain(*network)))),
                ("identity_word", hex(&identity_word(*network, &TAIRA))),
                ("network_bytes", hex(&network_bytes(*network, &TAIRA))),
                ("route_id", route_id(*network).map_or(Value::Null, text)),
                ("account_codec", num(u64::from(account_codec(*network)))),
            ])
        })
        .collect();
    let mut directions = Vec::new();
    for (index, network) in EXTERNAL_NETWORKS.iter().enumerate() {
        let index = index as u64;
        for (source, target) in [
            (SccpNetworkV1::SoraTaira, *network),
            (*network, SccpNetworkV1::SoraTaira),
        ] {
            let label = format!("{}->{}", source.profile_key(), target.profile_key());
            directions.push(payload_json(
                &label,
                &direction_payload(source, target, index),
            ));
        }
    }
    let amount_case = |mantissa: &str, scale: u32, value: Numeric| {
        let outcome = match taira_units(&value) {
            Ok(units) => ("taira_units", dec(units)),
            Err(error) => ("error", error_name(error)),
        };
        obj([
            ("numeric", text(&value.to_string())),
            ("mantissa", text(mantissa)),
            ("scale", num(u64::from(scale))),
            outcome,
        ])
    };
    let numeric = |mantissa: u128, scale: u32| Numeric::try_new(mantissa, scale).expect("numeric");
    let amounts = vec![
        amount_case("1", 0, numeric(1, 0)),
        amount_case("15", 1, numeric(15, 1)),
        amount_case("1", 9, numeric(1, 9)),
        amount_case("123456789", 9, numeric(123_456_789, 9)),
        amount_case("1000", 12, numeric(1_000, 12)),
        amount_case(&u128::MAX.to_string(), 9, numeric(u128::MAX, 9)),
    ];
    let rejected_amounts = vec![
        amount_case("0", 0, numeric(0, 0)),
        amount_case("-1", 0, Numeric::try_new(-1_i128, 0).expect("numeric")),
        amount_case("1", 10, numeric(1, 10)),
        amount_case("123", 11, numeric(123, 11)),
        amount_case(&u128::MAX.to_string(), 0, numeric(u128::MAX, 0)),
    ];
    for case in &amounts {
        assert!(case.get("taira_units").is_some(), "accepted amount");
    }
    for case in &rejected_amounts {
        assert!(case.get("error").is_some(), "rejected amount");
    }
    with(
        header(
            "iroha.sccp.payload.v1",
            "specs/sccp.md §0, §2, §3.1–§3.3 (revision 5)",
        ),
        vec![
            ("taira_network_id", hex(&TAIRA)),
            ("networks", Value::Array(networks)),
            ("directions", Value::Array(directions)),
            ("amounts", Value::Array(amounts)),
            ("rejected_amounts", Value::Array(rejected_amounts)),
            ("ton_amount_bound", dec(TON_AMOUNT_BOUND)),
            ("rejected_payloads", Value::Array(rejected_payloads())),
        ],
    )
}

// ---------------------------------------------------------------------------------------------
// commitment_tree_v1.json
// ---------------------------------------------------------------------------------------------

/// Leaf `i` of the tree vectors: a control leaf every third position, else a transfer leaf.
fn tree_leaf(index: u64) -> [u8; 32] {
    if index % 3 == 2 {
        eth_control_leaf(index + 1, index.is_multiple_of(2))
    } else {
        eth_transfer_leaf(index)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one generator writes one fixture file"
)]
fn commitment_tree_fixture() -> Value {
    let all: Vec<[u8; 32]> = (0..512).map(tree_leaf).collect();
    let trees: Vec<Value> = (1..=17_usize)
        .chain([512])
        .map(|count| {
            let leaves = &all[..count];
            let tree = PromoteOddTree::block(leaves).expect("tree");
            let paths: Vec<Value> = (0..count)
                .map(|index| {
                    let path = tree.path(index).expect("path");
                    assert!(path.len() <= 9);
                    assert_eq!(
                        merkle_root(&leaves[index], index as u64, count as u64, &path),
                        Ok(tree.root())
                    );
                    hexes(&path)
                })
                .collect();
            obj([
                ("count", num(count as u64)),
                ("root", hex(&tree.root())),
                ("paths", Value::Array(paths)),
            ])
        })
        .collect();

    let payload = eth_outbound(0);
    let encoded = payload.encode().expect("payload");
    let id = payload.message_id(&TAIRA).expect("message id");
    let word = destination_word(SccpNetworkV1::EthereumMainnet);
    let transfer = obj([
        ("payload", hex(&encoded)),
        ("message_id", hex(&id)),
        ("destination_word", hex(&word)),
        (
            "preimage",
            hex(&[b"SCCP/LEAF/V1".as_slice(), &id, &word].concat()),
        ),
        ("leaf", hex(&transfer_leaf(&id, &word))),
    ]);
    let control_preimage = control_leaf_preimage(
        &TAIRA,
        SccpNetworkV1::EthereumMainnet,
        &word,
        &tree_control(3, true),
    )
    .expect("control preimage");
    assert_eq!(control_preimage.len(), 199);
    let control = obj([
        ("target", profile(SccpNetworkV1::EthereumMainnet)),
        ("destination_word", hex(&word)),
        ("route_revision", num(1)),
        ("control_nonce", num(3)),
        ("track", num(u64::from(TRACK_PARLIAMENT))),
        ("parliament_paused", num(1)),
        ("fast_pause_until_ms", num(0)),
        ("certificate_id", hex(&tree_control(3, true).certificate_id)),
        ("effect_hash", hex(&tree_control(3, true).effect_hash)),
        ("preimage", hex(&control_preimage)),
        ("leaf", hex(&eth_control_leaf(3, true))),
    ]);
    let internal = obj([
        ("left", hex(&all[0])),
        ("right", hex(&all[1])),
        (
            "preimage",
            hex(&[b"SCCP/NODE/V1".as_slice(), &all[0], &all[1]].concat()),
        ),
        ("node", hex(&node(&all[0], &all[1]))),
    ]);

    // Negatives: every verifier recomputes the leaf from its fields and binds index and count.
    let four = PromoteOddTree::block(&all[..4]).expect("tree");
    let three = PromoteOddTree::block(&all[..3]).expect("tree");
    let five = PromoteOddTree::block(&all[..5]).expect("tree");
    let inner = node(&all[0], &all[1]);
    let inner_path = [node(&all[2], &all[3])];
    let control_path = three.path(2).expect("path");
    let as_transfer = eth_transfer_leaf(2);
    let flipped = eth_control_leaf(3, false);
    let promoted_path = five.path(4).expect("path");
    let mut long_path = four.path(1).expect("path");
    long_path.push([0; 32]);
    let negative = |label: &str,
                    leaf: &[u8; 32],
                    index: u64,
                    count: u64,
                    path: &[[u8; 32]],
                    root: &[u8; 32]| {
        let outcome = merkle_root(leaf, index, count, path);
        assert_ne!(outcome.as_ref().ok(), Some(root), "{label} must not verify");
        obj([
            ("label", text(label)),
            ("leaf", hex(leaf)),
            ("index", num(index)),
            ("count", num(count)),
            ("path", hexes(path)),
            ("expected_root", hex(root)),
            (
                "result",
                match outcome {
                    Ok(computed) => obj([("computed_root", hex(&computed))]),
                    Err(error) => obj([("error", error_name(error))]),
                },
            ),
        ])
    };
    let negatives = vec![
        negative(
            "internal_node_as_leaf",
            &inner,
            0,
            4,
            &inner_path,
            &four.root(),
        ),
        negative(
            "transfer_leaf_at_control_position",
            &as_transfer,
            2,
            3,
            &control_path,
            &three.root(),
        ),
        negative(
            "control_leaf_with_flipped_pause",
            &flipped,
            2,
            3,
            &control_path,
            &three.root(),
        ),
        negative(
            "promoted_leaf_with_larger_count",
            &all[4],
            4,
            6,
            &promoted_path,
            &five.root(),
        ),
        negative("unused_sibling", &all[1], 1, 4, &long_path, &four.root()),
        negative(
            "index_out_of_range",
            &all[0],
            4,
            4,
            &four.path(0).expect("path"),
            &four.root(),
        ),
    ];
    with(
        header(
            "iroha.sccp.commitment-tree.v1",
            "specs/sccp.md §3.3, §3.4 (native control leaf)",
        ),
        vec![
            ("taira_network_id", hex(&TAIRA)),
            (
                "destination",
                obj([
                    ("target", profile(SccpNetworkV1::EthereumMainnet)),
                    ("route_revision", num(1)),
                    ("destination_word", hex(&word)),
                ]),
            ),
            (
                "leaf_rule",
                text(
                    "leaf i is the native control leaf (revision = 1, control_nonce = i + 1, \
                     track = 1, parliament_paused = i even, fast_pause_until_ms = 0, \
                     certificate_id = 0x33 repeated 32 bytes, effect_hash = 0x44 repeated 32 bytes) when \
                     i mod 3 = 2, else the transfer leaf of the ethereum-mainnet outbound payload \
                     with nonce i, amount 1000000000 + i, deadline_ms 1800086400000",
                ),
            ),
            ("leaves", hexes(&all)),
            (
                "examples",
                obj([
                    ("transfer", transfer),
                    ("control", control),
                    ("node", internal),
                ]),
            ),
            ("trees", Value::Array(trees)),
            ("negatives", Value::Array(negatives)),
        ],
    )
}

// ---------------------------------------------------------------------------------------------
// history_v1.json
// ---------------------------------------------------------------------------------------------

fn history_block(index: u32) -> (u64, [u8; 32], u32) {
    let height = 100 + 7 * u64::from(index);
    let root = keccak256(&[b"SCCP/FIXTURE/ROOT/V1", &index.to_be_bytes()]);
    (height, root, 1 + index % 512)
}

fn history_fixture() -> Value {
    let blocks: Vec<(u64, [u8; 32], u32)> = (0..40).map(history_block).collect();
    let leaves: Vec<[u8; 32]> = blocks
        .iter()
        .map(|(height, root, count)| history_leaf(*height, root, *count))
        .collect();
    let leaf_json: Vec<Value> = blocks
        .iter()
        .zip(&leaves)
        .map(|((height, root, count), leaf)| {
            obj([
                ("height", num(*height)),
                ("sccp_root", hex(root)),
                ("message_count", num(u64::from(*count))),
                ("leaf", hex(leaf)),
            ])
        })
        .collect();
    let mut accumulator = HistoryAccumulatorV1::new();
    assert_eq!(accumulator.root(), [0; 32]);
    let sizes: Vec<Value> = (1..=40_usize)
        .map(|size| {
            accumulator.append(&leaves[size - 1]).expect("append");
            let prefix = &leaves[..size];
            let root = history_root(prefix).expect("root");
            assert_eq!(accumulator.root(), root, "peak bagging equals promote-odd");
            let bagged = accumulator
                .peaks()
                .iter()
                .rev()
                .copied()
                .reduce(|acc, peak| node(&peak, &acc))
                .expect("non-empty");
            assert_eq!(bagged, root);
            let paths: Vec<Value> = (0..size)
                .map(|index| {
                    let path = history_path(prefix, index as u64).expect("path");
                    assert!(path.len() <= 32);
                    assert_eq!(
                        merkle_root(&prefix[index], index as u64, size as u64, &path),
                        Ok(root)
                    );
                    hexes(&path)
                })
                .collect();
            obj([
                ("size", num(size as u64)),
                ("root", hex(&root)),
                ("peaks", hexes(accumulator.peaks())),
                ("paths", Value::Array(paths)),
            ])
        })
        .collect();
    with(
        header("iroha.sccp.history.v1", "specs/sccp.md §3.5"),
        vec![
            (
                "leaf_rule",
                text(
                    "history leaf i = history_leaf(height = 100 + 7i, sccp_root = \
                     keccak256(\"SCCP/FIXTURE/ROOT/V1\" ‖ u32 i), message_count = 1 + i mod 512)",
                ),
            ),
            ("empty_root", hex(&[0; 32])),
            ("leaves", Value::Array(leaf_json)),
            ("sizes", Value::Array(sizes)),
        ],
    )
}

// ---------------------------------------------------------------------------------------------
// evm_calldata_v1.json
// ---------------------------------------------------------------------------------------------

/// The coherent scenario behind the calldata vectors.
fn call_json(label: &str, function: &str, calldata: &[u8]) -> Value {
    obj([
        ("label", text(label)),
        ("function", text(function)),
        ("calldata", hex(calldata)),
    ])
}

/// Native certificates are produced by the maintained independent Rust reference support.
/// Every golden call is executed by the destination model before its bytes are recorded.
fn evm_calldata_fixture() -> Value {
    use iroha_sccp::v1::{
        control::ControlLeafV1,
        destination::{CheckpointRefV1, DeploymentV1, DestinationFlavor},
        destination_abi,
        evm_abi::{
            CommitteeViewV1, InitialCommitteeViewV1, PauseStateV1, ViewReturnV1,
            encode_committee_state_return, encode_initial_committee_return,
            encode_pause_state_return,
        },
    };
    use reference_support::{
        insert,
        scenario::{CertificatePool, Scenario, Source, Submission},
        taira_sim::{CertifyOptions, Committee, Rotate, TairaSim},
    };
    use std::{cell::RefCell, rc::Rc};
    let g7 = Committee::new("g7", 0..4);
    let g8 = Committee::new("g8", 4..8);
    let mut sim = TairaSim::new(
        TAIRA,
        [0x77; 32],
        SccpNetworkV1::EthereumMainnet,
        word_address(&[0x22; 20]),
    );
    sim.start(7, g7.clone(), 50, T0, 14 * DAY);
    let recipient = [0x55; 20];
    sim.block(
        50,
        T0 + 50_000,
        vec![sim.transfer(0, 1_000_000_000, DEADLINE, &recipient)],
        None,
        None,
    );
    let ctl = ControlLeafV1 {
        route_revision: 1,
        control_nonce: 1,
        track: 1,
        parliament_paused: 1,
        fast_pause_until_ms: 0,
        certificate_id: [0x61; 32],
        effect_hash: [0x62; 32],
    };
    let b100 = sim.block(
        100,
        T0 + 100_000,
        vec![
            sim.control(&ctl, true),
            sim.transfer(1, 2_000_000_000, DEADLINE, &recipient),
            sim.transfer(2, 2_000_000_000, DEADLINE, &recipient),
        ],
        None,
        None,
    );
    let b150 = sim.block(
        150,
        T0 + 150_000,
        vec![],
        Some(Rotate::Key(g8.clone())),
        None,
    );
    let b200 = sim.block(
        200,
        T0 + 200_000,
        vec![sim.transfer(3, 3_000_000_000, DEADLINE, &recipient)],
        None,
        None,
    );
    let c100 = sim.certify(&b100.x(), &g7, &CertifyOptions::default());
    let c150 = sim.certify(&b150.x(), &g7, &CertifyOptions::default());
    let c200 = sim.certify(&b200.x(), &g8, &CertifyOptions::default());
    let s100 = Submission::new(c100.clone(), "block100", "g7");
    let s150 = Submission::new(c150.clone(), "rotation150", "g7").with_next(&g8);
    let s200 = Submission::new(c200.clone(), "block200", "g8");
    let cert = c100.wire();
    let checkpoint = CheckpointRefV1 { header: b200.x() };
    let direct = sim.message_proof(100, 1, &b100.header);
    let historical = sim.message_proof(100, 2, &b200.header);
    let control = sim.control_proof(100, 0, &b100.header);
    let historical_control = sim.control_proof(100, 0, &b200.header);
    let deployment = DeploymentV1 {
        flavor: DestinationFlavor::Evm,
        taira_network_id: TAIRA,
        consensus_instance: [0x77; 32],
        network: SccpNetworkV1::EthereumMainnet,
        destination_word: word_address(&[0x22; 20]),
        route_revision: 1,
        max_wrapped_supply: 1_000_000_000_000_000_000,
        pin_generation: 7,
        pin_root: g7.root(),
        pin_start_height: 50,
        pin_until_ms: T0 + 14 * DAY,
        pin_keys: None,
    };
    let pool = Rc::new(RefCell::new(CertificatePool::default()));
    let fresh = |name| {
        Scenario::new(
            name,
            "Native ABI golden calldata, derived and verified in Rust",
            deployment.clone(),
            &pool,
            true,
        )
    };
    let mut calls = Vec::new();
    let mut add = |label: &str, function: &str, calldata: Vec<u8>, scenario: Scenario| {
        let mut row = call_json(label, function, &calldata);
        insert(&mut row, "scenario", scenario.as_json());
        calls.push(row);
    };
    let now = T0 + 300_000;
    let mut run = fresh("finalize_direct");
    run.finalize(Source::Inline(&s100), &direct, now, Some("ok"))
        .expect("direct transfer");
    add(
        "finalize_direct",
        "finalizeFromTaira",
        finalize_from_taira_calldata(&cert, &direct),
        run,
    );
    let mut run = fresh("finalize_from_checkpoint");
    run.submit(&[s150.clone(), s200.clone()], now, Some("ok"))
        .expect("rotation and checkpoint");
    run.finalize(
        Source::Checkpoint(&checkpoint.header),
        &historical,
        now,
        Some("ok"),
    )
    .expect("historical transfer");
    add(
        "finalize_from_checkpoint",
        "finalizeFromCheckpoint",
        finalize_from_checkpoint_calldata(&checkpoint, &historical),
        run,
    );
    let mut run = fresh("rotate_one");
    run.submit(std::slice::from_ref(&s150), now, Some("ok"))
        .expect("rotation");
    let after = &run.destination.state().committee;
    assert_eq!(after.root, g8.root());
    assert_eq!(after.generation, 8);
    let committee_view = CommitteeViewV1 {
        root: after.root,
        until_ms: after.until_ms,
        start: after.start,
        high: after.high,
        generation: after.generation,
    };
    let committee_return = encode_committee_state_return(&committee_view);
    assert_eq!(
        ViewCallV1::CommitteeState.decode_return(&committee_return),
        Ok(ViewReturnV1::CommitteeState(committee_view))
    );
    add(
        "rotate_one",
        "submitCheckpoints",
        submit_checkpoints_calldata(&[c150.wire()]),
        run,
    );
    let mut run = fresh("apply_control_direct");
    run.apply_control(Source::Inline(&s100), &control, now, Some("ok"))
        .expect("direct control");
    add(
        "apply_control_direct",
        "applyControl",
        apply_control_calldata(&cert, &control),
        run,
    );
    let mut run = fresh("apply_control_from_checkpoint");
    run.submit(&[s150.clone(), s200.clone()], now, Some("ok"))
        .expect("rotation and checkpoint");
    run.apply_control(
        Source::Checkpoint(&checkpoint.header),
        &historical_control,
        now,
        Some("ok"),
    )
    .expect("historical control");
    add(
        "apply_control_from_checkpoint",
        "applyControlFromCheckpoint",
        apply_control_from_checkpoint_calldata(&checkpoint, &historical_control),
        run,
    );
    let expired = void_expired_calldata(1, &cert, &direct);
    let expired_checkpoint = void_expired_from_checkpoint_calldata(2, &checkpoint, &historical);
    assert_eq!(
        VoidCallV1::decode(&expired),
        Ok(VoidCallV1::Expired {
            nonce: 1,
            from_checkpoint: false
        })
    );
    assert_eq!(
        VoidCallV1::decode(&expired_checkpoint),
        Ok(VoidCallV1::Expired {
            nonce: 2,
            from_checkpoint: true
        })
    );
    let mut run = fresh("void_expired");
    run.void_expired(
        1,
        Source::Inline(&s100),
        &direct,
        DEADLINE + 1000,
        Some("ok"),
    )
    .expect("expired direct");
    add("void_expired", "voidExpired", expired.clone(), run);
    let mut run = fresh("void_expired_from_checkpoint");
    run.submit(&[s150.clone(), s200.clone()], now, Some("ok"))
        .expect("rotation and checkpoint");
    run.void_expired(
        2,
        Source::Checkpoint(&checkpoint.header),
        &historical,
        DEADLINE + 1000,
        Some("ok"),
    )
    .expect("expired historical");
    add(
        "void_expired_from_checkpoint",
        "voidExpiredFromCheckpoint",
        expired_checkpoint.clone(),
        run,
    );
    let frozen = void_frozen_calldata(4, 3);
    assert_eq!(
        VoidCallV1::decode(&frozen),
        Ok(VoidCallV1::Frozen {
            first_nonce: 4,
            count: 3
        })
    );
    let mut run = fresh("void_frozen");
    run.void_frozen(4, 3, T0 + 14 * DAY + 1000, Some("ok"))
        .expect("frozen void");
    add("void_frozen", "voidFrozen", frozen, run);

    let transfer_call = TransferToTairaCallV1 {
        taira_recipient: taira_account(9),
        token_amount: 1_500_000_000,
        expected_nonce: 0,
    };
    let transfer_calldata = transfer_call.calldata();
    assert_eq!(
        TransferToTairaCallV1::decode(&transfer_calldata),
        Ok(transfer_call.clone())
    );
    calls.push(call_json(
        "transfer_to_taira",
        "transferToTaira",
        &transfer_calldata,
    ));
    let initial = InitialCommitteeViewV1 {
        generation: 7,
        root: g7.root(),
        start: 50,
        until_ms: T0 + 14 * DAY,
    };
    let pause = PauseStateV1 {
        parliament_paused: true,
        fast_pause_until_ms: 0,
        control_nonce: 1,
        effective: true,
    };
    let initial_return = encode_initial_committee_return(&initial);
    let pause_return = encode_pause_state_return(&pause);
    assert_eq!(
        ViewCallV1::InitialCommittee.decode_return(&initial_return),
        Ok(ViewReturnV1::InitialCommittee(initial))
    );
    assert_eq!(
        ViewCallV1::PauseState.decode_return(&pause_return),
        Ok(ViewReturnV1::PauseState(pause))
    );
    let views: Vec<Value> = [
        ("committeeState", ViewCallV1::CommitteeState),
        ("checkpointHeader", ViewCallV1::CheckpointHeader(200)),
        ("pauseState", ViewCallV1::PauseState),
        ("consensusInstance", ViewCallV1::ConsensusInstance),
        ("initialCommittee", ViewCallV1::InitialCommittee),
        ("equivocated", ViewCallV1::Equivocated),
        ("maxValidityMs", ViewCallV1::MaxValidityMs),
        ("isConsumed", ViewCallV1::IsConsumed(300)),
        ("transferNonces", ViewCallV1::TransferNonces(recipient)),
        ("tairaNetworkId", ViewCallV1::TairaNetworkId),
        ("routeRevision", ViewCallV1::RouteRevision),
        ("maxWrappedSupply", ViewCallV1::MaxWrappedSupply),
        ("mintingPaused", ViewCallV1::MintingPaused),
        ("controlNonce", ViewCallV1::ControlNonce),
        ("opCount", ViewCallV1::OpCount),
    ]
    .into_iter()
    .map(|(name, call)| call_json(name, name, &call.calldata()))
    .collect();
    let inbound = transfer_call
        .inbound_payload(SccpNetworkV1::EthereumMainnet, 1, &recipient)
        .expect("inbound payload");
    let transfer_log = TransferToTairaLogV1 {
        message_id: inbound.message_id(&TAIRA).expect("id"),
        sender: recipient,
        nonce: 0,
        payload: inbound.encode().expect("payload"),
    };
    assert_eq!(
        transfer_log.verified_payload(&TAIRA, SccpNetworkV1::EthereumMainnet, 1),
        Ok(inbound)
    );
    let expired_log = VoidedLogV1 {
        message_id: SccpTransferPayloadV1::decode(&direct.payload)
            .expect("payload")
            .message_id(&TAIRA)
            .expect("id"),
        nonce: 1,
    };
    let frozen_log = VoidedLogV1 {
        message_id: [0; 32],
        nonce: 4,
    };
    let mut logs = Vec::new();
    let log_json = |label: &str, (topics, data): (Vec<[u8; 32]>, Vec<u8>)| {
        obj([
            ("label", text(label)),
            ("topics", hexes(&topics)),
            ("data", hex(&data)),
        ])
    };
    let (topics, data) = transfer_log.encode();
    assert_eq!(
        TransferToTairaLogV1::decode(&topics, &data),
        Ok(transfer_log.clone())
    );
    logs.push(log_json("transfer_to_taira", (topics, data)));
    for (label, log) in [
        ("voided_expired", expired_log),
        ("voided_frozen", frozen_log),
    ] {
        let (topics, data) = log.encode();
        assert_eq!(VoidedLogV1::decode(&topics, &data), Ok(log));
        logs.push(log_json(label, (topics, data)));
    }
    let selectors = destination_abi::SELECTORS
        .iter()
        .map(|(name, signature, selector)| {
            obj([
                ("function", text(name)),
                ("signature", text(signature)),
                ("selector", hex(selector)),
            ])
        })
        .collect();
    let events = destination_abi::EVENT_TOPICS
        .iter()
        .map(|(_, signature, topic)| obj([("signature", text(signature)), ("topic0", hex(topic))]))
        .collect();
    with(
        header(
            "iroha.sccp.evm-calldata.v1",
            "specs/sccp.md §5.1.3–§5.1.8, §5.2.2 (native BLS)",
        ),
        vec![
            ("certificates", pool.borrow().as_json()),
            (
                "committees",
                obj([("g7", g7.as_json()), ("g8", g8.as_json())]),
            ),
            ("selectors", Value::Array(selectors)),
            ("events", Value::Array(events)),
            ("calls", Value::Array(calls)),
            ("views", Value::Array(views)),
            ("logs", Value::Array(logs)),
            (
                "view_returns",
                obj([
                    ("committee_after_rotation", hex(&committee_return)),
                    ("initial_committee", hex(&initial_return)),
                    ("pause_after_control", hex(&pause_return)),
                ]),
            ),
            (
                "calldata_conformance",
                Value::Array(calldata_conformance(
                    &transfer_call,
                    &expired,
                    &expired_checkpoint,
                )),
            ),
        ],
    )
}

/// A conformance verdict: the call succeeds (contract) or decodes (Rust).
const ACCEPT: &str = "accept";
/// The contract reverts in Solidity's own ABI decoder, with empty revert data.
const EMPTY_REVERT: &str = "empty";
/// The contract's custom error for a non-canonical encoding.
const NON_CANONICAL: &str = "NonCanonicalCalldata";
/// One ABI word.
const WORD: usize = 32;

/// `calldata` with a zero word inserted at argument offset `at` (after the selector).
fn with_gap(calldata: &[u8], at: usize) -> Vec<u8> {
    let mut out = calldata[..4 + at].to_vec();
    out.extend_from_slice(&[0; WORD]);
    out.extend_from_slice(&calldata[4 + at..]);
    out
}

/// The `u64` value of the argument word at `at`.
fn arg_u64(calldata: &[u8], at: usize) -> usize {
    let low = &calldata[4 + at + 24..4 + at + WORD];
    usize::try_from(u64::from_be_bytes(low.try_into().expect("8 bytes"))).expect("usize")
}

/// Adds `delta` to the `u64` argument word at `at`.
fn bump(calldata: &mut [u8], at: usize, delta: u64) {
    let low = 4 + at + 24..4 + at + WORD;
    let value = u64::from_be_bytes(calldata[low.clone()].try_into().expect("8 bytes")) + delta;
    calldata[low].copy_from_slice(&value.to_be_bytes());
}

/// `calldata` with byte `index` of the argument word at `at` set to 1.
fn dirty(calldata: &[u8], at: usize, index: usize) -> Vec<u8> {
    let mut out = calldata.to_vec();
    out[4 + at + index] = 1;
    out
}

fn appended(calldata: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut out = calldata.to_vec();
    out.extend_from_slice(tail);
    out
}

/// Each mutation preserves its own Rust/contract verdict. Solidity deliberately allows
/// noncanonical expired-void offsets/padding/trailing bytes; only the local decoder is strict.
fn void_expired_variants(
    base: &[u8],
    checkpoint: bool,
) -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let source_at = arg_u64(base, WORD);
    let proof_at = arg_u64(base, 2 * WORD);
    let block_at = proof_at + arg_u64(base, proof_at + 3 * WORD);
    let source_fields = if checkpoint { 1 } else { 5 };
    let mut fields = vec![
        ("dirty_nonce_high_bits", 0, 8),
        ("dirty_message_leaf_index", proof_at + WORD, 4),
        ("dirty_block_height", block_at, 8),
        ("dirty_block_message_count", block_at + 2 * WORD, 4),
        ("dirty_history_index", block_at + 3 * WORD, 8),
    ];
    let mut offsets = vec![
        ("source_offset_gap", source_at, vec![WORD, 2 * WORD]),
        ("message_proof_offset_gap", proof_at, vec![2 * WORD]),
        (
            "payload_offset_gap",
            proof_at + arg_u64(base, proof_at),
            vec![proof_at, proof_at + 2 * WORD, proof_at + 3 * WORD],
        ),
        (
            "path_offset_gap",
            proof_at + arg_u64(base, proof_at + 2 * WORD),
            vec![proof_at + 2 * WORD, proof_at + 3 * WORD],
        ),
        ("block_offset_gap", block_at, vec![proof_at + 3 * WORD]),
        (
            "history_path_offset_gap",
            block_at + arg_u64(base, block_at + 4 * WORD),
            vec![block_at + 4 * WORD],
        ),
    ];
    let source_names = [
        "qc_offset_gap",
        "header_offset_gap",
        "signature_offset_gap",
        "committee_offset_gap",
        "signer_ys_offset_gap",
    ];
    let padding_names = [
        "nonzero_qc_padding",
        "nonzero_header_padding",
        "nonzero_signature_padding",
        "nonzero_committee_padding",
        "nonzero_signer_ys_padding",
    ];
    let mut paddings = Vec::new();
    for i in 0..source_fields {
        let at = source_at + arg_u64(base, source_at + i * WORD);
        let mut affected: Vec<_> = (i..source_fields).map(|j| source_at + j * WORD).collect();
        affected.push(2 * WORD);
        offsets.push((
            if checkpoint {
                "checkpoint_header_offset_gap"
            } else {
                source_names[i]
            },
            at,
            affected,
        ));
        let length = arg_u64(base, at);
        if length % WORD != 0 {
            paddings.push((
                if checkpoint {
                    "nonzero_checkpoint_header_padding"
                } else {
                    padding_names[i]
                },
                at,
            ));
        }
    }
    let payload = proof_at + arg_u64(base, proof_at);
    assert_ne!(
        arg_u64(base, payload) % WORD,
        0,
        "payload padding control is meaningful"
    );
    paddings.push(("nonzero_payload_padding", payload));
    let mut variants = vec![
        ("canonical", base.to_vec(), ACCEPT),
        ("trailing_byte", appended(base, &[0]), ACCEPT),
        ("trailing_word", appended(base, &[0; WORD]), ACCEPT),
        ("short_byte", base[..base.len() - 1].to_vec(), EMPTY_REVERT),
        ("offset_high_bits", dirty(base, WORD, 0), EMPTY_REVERT),
    ];
    variants.extend(
        fields
            .drain(..)
            .map(|(label, at, width)| (label, dirty(base, at, WORD - width - 1), EMPTY_REVERT)),
    );
    variants.extend(offsets.into_iter().map(|(label, at, affected)| {
        let mut bytes = with_gap(base, at);
        for offset in affected {
            assert!(offset < at, "offset precedes gap");
            bump(&mut bytes, offset, 32);
        }
        (label, bytes, ACCEPT)
    }));
    variants.extend(paddings.into_iter().map(|(label, at)| {
        let mut bytes = base.to_vec();
        let len = arg_u64(base, at);
        bytes[4 + at + WORD + len] = 1;
        (label, bytes, ACCEPT)
    }));
    variants
}

/// The shared void and burn calldata conformance table (§5.1.7, §5.1.8, §5.2.2): every entry
/// records the Rust decoder's verdict and the destination's outcome in a state where the
/// canonical call succeeds. Transfer/frozen verdicts agree; expired-void canonicality is
/// intentionally stricter locally than Solidity. `contract` is
/// `accept`, a custom error, or `empty` for a revert in Solidity's ABI decoder.
fn calldata_conformance(
    transfer_call: &TransferToTairaCallV1,
    void_expired: &[u8],
    void_expired_checkpoint: &[u8],
) -> Vec<Value> {
    let mut cases: Vec<(&str, String, Vec<u8>, &str)> = Vec::new();
    let mut push = |function: &'static str,
                    variants: Vec<(&'static str, Vec<u8>, &'static str)>| {
        for (label, calldata, contract) in variants {
            cases.push((function, label.to_owned(), calldata, contract));
        }
    };

    push("voidExpired", void_expired_variants(void_expired, false));
    push(
        "voidExpiredFromCheckpoint",
        void_expired_variants(void_expired_checkpoint, true),
    );

    // `voidFrozen` in a frozen state; the accepted ranges are disjoint.
    let frozen = void_frozen_calldata(4, 3);
    push(
        "voidFrozen",
        vec![
            ("canonical", frozen.clone(), ACCEPT),
            ("count_1", void_frozen_calldata(0, 1), ACCEPT),
            ("count_256", void_frozen_calldata(256, 256), ACCEPT),
            (
                "range_ends_at_u64_max",
                void_frozen_calldata(u64::MAX - 255, 256),
                ACCEPT,
            ),
            ("count_0", void_frozen_calldata(8, 0), "BadAmount"),
            ("count_257", void_frozen_calldata(8, 257), "BadAmount"),
            (
                "range_past_u64_max",
                void_frozen_calldata(u64::MAX, 2),
                "BadAmount",
            ),
            ("trailing_byte", appended(&frozen, &[0]), NON_CANONICAL),
            (
                "trailing_word",
                appended(&frozen, &[0; WORD]),
                NON_CANONICAL,
            ),
            (
                "short_byte",
                frozen[..frozen.len() - 1].to_vec(),
                EMPTY_REVERT,
            ),
            (
                "dirty_first_nonce_high_bits",
                dirty(&frozen, 0, 23),
                EMPTY_REVERT,
            ),
            (
                "dirty_count_high_bits",
                dirty(&frozen, WORD, 23),
                EMPTY_REVERT,
            ),
        ],
    );

    // `transferToTaira` by a funded caller whose next nonce is 0.
    let transfer = transfer_call.calldata();
    let recipient_len = transfer_call.taira_recipient.len();
    assert_ne!(recipient_len % WORD, 0, "the recipient has padding");
    // Offset 0x80 over the unchanged body points the length at the recipient bytes; with a zero
    // word inserted first, Solidity's own decoder reads the same arguments.
    let mut offset_0x80 = transfer.clone();
    offset_0x80[4 + 31] = 0x80;
    let mut offset_gap = with_gap(&transfer, 3 * WORD);
    bump(&mut offset_gap, 0, 0x20);
    let mut padding = transfer.clone();
    let last = padding.len() - 1;
    padding[last] = 1;
    let mut empty_recipient = transfer[..4 + 4 * WORD].to_vec();
    empty_recipient[4 + 3 * WORD..].fill(0);
    // The length word claims one byte less; the dropped recipient byte becomes padding.
    let mut length_short = transfer.clone();
    length_short[4 + 4 * WORD - 1] -= 1;
    let mut amount_2_pow_128 = transfer.clone();
    amount_2_pow_128[4 + WORD..4 + 2 * WORD].fill(0);
    amount_2_pow_128[4 + WORD + 15] = 1;
    let with = |edit: TransferToTairaCallV1| edit.calldata();
    push(
        "transferToTaira",
        vec![
            ("canonical", transfer.clone(), ACCEPT),
            ("offset_0x80", offset_0x80, EMPTY_REVERT),
            ("recipient_offset_gap", offset_gap, NON_CANONICAL),
            ("nonzero_padding", padding, NON_CANONICAL),
            (
                "trailing_word",
                appended(&transfer, &[0; WORD]),
                NON_CANONICAL,
            ),
            ("trailing_byte", appended(&transfer, &[0]), NON_CANONICAL),
            (
                "truncated_word",
                transfer[..transfer.len() - WORD].to_vec(),
                EMPTY_REVERT,
            ),
            ("empty_recipient", empty_recipient, NON_CANONICAL),
            ("recipient_length_short_by_one", length_short, NON_CANONICAL),
            (
                "recipient_1025_bytes",
                with(TransferToTairaCallV1 {
                    taira_recipient: vec![0x5a; 1025],
                    ..transfer_call.clone()
                }),
                NON_CANONICAL,
            ),
            (
                "zero_amount",
                with(TransferToTairaCallV1 {
                    token_amount: 0,
                    ..transfer_call.clone()
                }),
                "BadAmount",
            ),
            ("amount_2_pow_128", amount_2_pow_128, "BadAmount"),
            (
                "dirty_nonce_high_bits",
                dirty(&transfer, 2 * WORD, 23),
                EMPTY_REVERT,
            ),
        ],
    );

    cases
        .into_iter()
        .map(|(function, label, calldata, contract)| {
            let outcome = if function == "transferToTaira" {
                TransferToTairaCallV1::decode(&calldata).map(|call| {
                    assert_eq!(&call, transfer_call, "{label}");
                })
            } else {
                VoidCallV1::decode(&calldata).map(|_| ())
            };
            let decoder = match outcome {
                Ok(()) => text(ACCEPT),
                Err(error) => error_name(error),
            };
            if matches!(function, "transferToTaira" | "voidFrozen") {
                assert_eq!(
                    decoder == text(ACCEPT),
                    contract == ACCEPT,
                    "{function} {label}: canonicality verdicts agree"
                );
            } else {
                assert_eq!(
                    decoder == text(ACCEPT),
                    label == "canonical",
                    "{function} {label}: local expired-void decoding is canonical only"
                );
            }
            obj([
                ("function", text(function)),
                ("label", text(&label)),
                ("calldata", hex(&calldata)),
                ("decoder", decoder),
                ("contract", text(contract)),
            ])
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

type Generator = fn() -> Value;

const FIXTURES: [(&str, Generator); 4] = [
    ("payload_v1.json", payload_fixture),
    ("commitment_tree_v1.json", commitment_tree_fixture),
    ("history_v1.json", history_fixture),
    ("evm_calldata_v1.json", evm_calldata_fixture),
];

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/sccp")
        .join(name)
}

fn render(value: &Value) -> String {
    let mut out = norito::json::to_string_pretty(value).expect("render fixture");
    out.push('\n');
    out
}

#[test]
fn v1_vectors_match_committed_fixtures() {
    for (name, generate) in FIXTURES {
        let generated = generate();
        let expected = render(&generated);
        let path = fixture_path(name);
        let actual = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert!(
            actual == expected,
            "{name} differs from the generated vectors; after a reviewed change run \
             `cargo test -p iroha_sccp --test v1_vectors -- --ignored regenerate_v1_vectors`"
        );
        let parsed: Value = norito::json::from_str(&actual).expect("fixture parses");
        assert_eq!(
            parsed, generated,
            "{name} parses back to the generated value"
        );
    }
}

#[test]
#[ignore = "rewrites fixtures/sccp/*_v1.json; run only after a reviewed layout change"]
fn regenerate_v1_vectors() {
    for (name, generate) in FIXTURES {
        let path = fixture_path(name);
        fs::write(&path, render(&generate()))
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    }
}

/// Focused native-EVM parity without rewriting the other, separately owned fixture families.
#[test]
fn evm_calldata_v1_matches_committed_fixture() {
    let value = evm_calldata_fixture();
    let actual = fs::read_to_string(fixture_path("evm_calldata_v1.json")).expect("EVM fixture");
    assert_eq!(actual, render(&value));
    assert_eq!(
        norito::json::from_str::<Value>(&actual).expect("JSON"),
        value
    );
}

/// Regenerate only the native EVM fixture after a reviewed ABI migration.
#[test]
#[ignore = "rewrites only fixtures/sccp/evm_calldata_v1.json"]
fn regenerate_evm_calldata_v1() {
    fs::write(
        fixture_path("evm_calldata_v1.json"),
        render(&evm_calldata_fixture()),
    )
    .expect("write native EVM fixture");
}
