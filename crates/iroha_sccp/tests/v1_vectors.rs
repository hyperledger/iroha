//! Golden SCCP v1 vectors (`specs/sccp.md` §11).
//!
//! Regenerates `fixtures/sccp/{payload,commitment_tree,history,eip712,roster,
//! evm_calldata}_v1.json` from `iroha_sccp::v1` and asserts byte equality with the committed
//! files. Every generator also cross-checks its vectors with the crate's verifiers (paths,
//! signature sets, roster rotation, proof bundles), so a committed vector is always one the Rust
//! implementation accepts or rejects exactly as recorded.
//!
//! `control_v1.json` is a revision-5 reference file: `tests/v1_reference_control.rs` owns it.
//! Of the files written here, `payload_v1.json` follows revision 5 (its sections, §0, §2 and
//! §3.1–§3.3, describe the current profiles, codecs and payload layout); the other five still
//! carry the revision 4 layouts named in their `spec` strings.
//!
//! After a reviewed layout change, rewrite the files with
//! `cargo test -p iroha_sccp --test v1_vectors -- --ignored regenerate_v1_vectors`.

use std::{fs, path::PathBuf};

use iroha_data_model::{bridge::SccpNetworkV1, prelude::Numeric};
use iroha_sccp::v1::{
    amount::taira_units,
    constants::{
        ATTESTATION_TYPE, ATTESTATION_TYPEHASH, BRIDGE_KEY_TYPE, BRIDGE_KEY_TYPEHASH,
        CODEC_CANONICAL_TEXT, CODEC_TAIRA_ACCOUNT, DOMAIN_TYPEHASH, EIP712_DOMAIN_TYPE,
        EVENT_TOPICS, MAX_CLOCK_SKEW_MS, MAX_ROSTER_MEMBERS, MAX_ROSTER_VALIDITY_MS,
        MIN_ROSTER_MEMBERS, NAME_HASH, PREVIOUS_ROSTER_GRACE_MS, SECP256K1_HALF_N, SECP256K1_N,
        SELECTORS, TON_AMOUNT_BOUND, VERSION_HASH,
    },
    eip712::{AttestationFieldsV1, BridgeKeyPopFieldsV1, domain_separator, peer_key_hash},
    evm_abi::{
        AttestedV1, RotationV1, TransferToTairaCallV1, TransferToTairaLogV1, ViewCallV1,
        VoidCallV1, VoidedLogV1, apply_control_calldata, apply_control_historical_calldata,
        encode_roster_state_return, finalize_from_taira_calldata,
        finalize_from_taira_historical_calldata, rotate_rosters_calldata, void_expired_calldata,
        void_expired_historical_calldata, void_frozen_calldata,
    },
    hashes::{
        control_leaf, control_leaf_preimage, history_leaf, keccak256, message_id, node,
        payload_hash, to_hex, transfer_leaf, word_address,
    },
    history::{HistoryAccumulatorV1, history_path, history_root},
    merkle::{PromoteOddTree, merkle_root},
    network::{
        ALL_NETWORKS, EXTERNAL_NETWORKS, account_codec, domain, identity_word, network_bytes,
        route_id, tag,
    },
    payload::{PayloadAccountV1, SccpTransferPayloadV1},
    proof::{
        ControlProofV1, DestinationV1, HistoryBlockV1, HistoryProofV1, MessageProofV1,
        verify_control_direct, verify_control_historical, verify_transfer_direct,
        verify_transfer_historical,
    },
    roster::{RosterStateV1, RosterV1, check_validity_bounds, roster_digest_checked, threshold},
    signature::{
        SignatureSetV1, address_of_secret, check_signature_form, public_key_of, recover_address,
        rfc6979_sign, sign_digest, sign_digest_with,
    },
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

/// A 20-byte pseudo address for rosters larger than the fixed key set.
fn pseudo_address(index: u32) -> [u8; 20] {
    let hash = keccak256(&[b"SCCP/FIXTURE/MEMBER/V1", &index.to_be_bytes()]);
    hash[12..].try_into().expect("20 bytes")
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

fn eth_destination() -> DestinationV1 {
    DestinationV1 {
        network: SccpNetworkV1::EthereumMainnet,
        route_revision: 1,
        destination_word: destination_word(SccpNetworkV1::EthereumMainnet),
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

fn eth_control_leaf(control_nonce: u64, paused: bool) -> [u8; 32] {
    control_leaf(
        &TAIRA,
        SccpNetworkV1::EthereumMainnet,
        &destination_word(SccpNetworkV1::EthereumMainnet),
        1,
        control_nonce,
        paused,
    )
    .expect("valid control leaf")
}

fn roster_json(roster: &RosterV1) -> Value {
    let preimage = roster.preimage(&TAIRA).expect("valid roster");
    obj([
        ("generation", num(roster.generation)),
        ("valid_from_ms", num(roster.valid_from_ms)),
        ("valid_until_ms", num(roster.valid_until_ms)),
        ("n", num(roster.n() as u64)),
        ("threshold", num(roster.threshold() as u64)),
        ("members", hexes(&roster.members)),
        ("packed_members", hex(&roster.packed_members())),
        ("preimage", hex(&preimage)),
        ("digest", hex(&roster.digest(&TAIRA).expect("valid roster"))),
    ])
}

fn attestation_json(attestation: &AttestationFieldsV1) -> Value {
    obj([
        ("height", num(attestation.height)),
        ("epoch", num(attestation.epoch)),
        ("timestamp_ms", num(attestation.timestamp_ms)),
        ("block_hash", hex(&attestation.block_hash)),
        ("sccp_root", hex(&attestation.sccp_root)),
        ("message_count", num(u64::from(attestation.message_count))),
        ("history_root", hex(&attestation.history_root)),
        ("history_size", num(attestation.history_size)),
        ("roster_digest", hex(&attestation.roster_digest)),
        ("next_roster_digest", hex(&attestation.next_roster_digest)),
        ("struct_hash", hex(&attestation.struct_hash())),
        ("digest", hex(&attestation.digest(&TAIRA))),
    ])
}

/// Sign `digest` with the fixed keys `signers` and assemble the set for `roster`.
fn signature_set(roster: &RosterV1, signers: &[u8], digest: &[u8; 32]) -> SignatureSetV1 {
    let entries: Vec<(usize, [u8; 65])> = signers
        .iter()
        .map(|key| {
            let address = fixture_address(*key);
            let index = roster
                .members
                .iter()
                .position(|member| *member == address)
                .expect("signer is a roster member");
            let signature = sign_digest(&fixture_secret(*key), digest).expect("signature");
            (index, signature)
        })
        .collect();
    let set = SignatureSetV1::from_signers(roster.n(), &entries).expect("signature set");
    set.verify_quorum(digest, &roster.members, roster.threshold())
        .expect("quorum verifies");
    set
}

fn signatures_json(set: &SignatureSetV1) -> Value {
    obj([
        ("signer_bitmap", num(u64::from(set.signer_bitmap))),
        ("signatures", hex(&set.signatures)),
    ])
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
    let control_preimage =
        control_leaf_preimage(&TAIRA, SccpNetworkV1::EthereumMainnet, &word, 1, 3, true)
            .expect("control preimage");
    let control = obj([
        ("target", profile(SccpNetworkV1::EthereumMainnet)),
        ("destination_word", hex(&word)),
        ("route_revision", num(1)),
        ("control_nonce", num(3)),
        ("paused", Value::Bool(true)),
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
            "specs/sccp.md §3.3, §3.4 (revision 4)",
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
                    "leaf i is the control leaf (control_nonce = i + 1, paused = i even) when \
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
        header(
            "iroha.sccp.history.v1",
            "specs/sccp.md §3.5, §5.1.3 (revision 4)",
        ),
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
// eip712_v1.json
// ---------------------------------------------------------------------------------------------

fn sample_attestation() -> AttestationFieldsV1 {
    AttestationFieldsV1 {
        height: 100,
        epoch: 0,
        timestamp_ms: T0 + 100_000,
        block_hash: keccak256(&[b"SCCP/FIXTURE/BLOCK/V1", &100_u64.to_be_bytes()]),
        sccp_root: [0xc2; 32],
        message_count: 3,
        history_root: [0xd3; 32],
        history_size: 2,
        roster_digest: [0xe4; 32],
        next_roster_digest: [0; 32],
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one generator writes one fixture file"
)]
fn eip712_fixture() -> Value {
    let separator = domain_separator(&TAIRA);
    assert_eq!(
        separator,
        keccak256(&[&DOMAIN_TYPEHASH, &NAME_HASH, &VERSION_HASH, &TAIRA])
    );
    let attestation = sample_attestation();
    let rotation = AttestationFieldsV1 {
        height: 3_600,
        epoch: 0,
        timestamp_ms: T0 + 3_600_000,
        sccp_root: [0; 32],
        message_count: 0,
        next_roster_digest: [0xf5; 32],
        ..attestation
    };
    for fields in [&attestation, &rotation] {
        fields.check_invariants().expect("attestation invariants");
    }
    let consensus_key: Vec<u8> = (0..48_u8).map(|byte| 0xa0 ^ byte).collect();
    let pop = BridgeKeyPopFieldsV1 {
        peer_key_hash: peer_key_hash(&consensus_key),
        bridge_address: fixture_address(0),
        activation_epoch: 1,
    };
    let pop_digest = pop.digest(&TAIRA);
    let pop_signature = sign_digest(&fixture_secret(0), &pop_digest).expect("pop signature");
    assert_eq!(
        recover_address(&pop_digest, &pop_signature),
        Ok(fixture_address(0))
    );

    let keys: Vec<Value> = (0..4_u8)
        .map(|index| {
            let secret = fixture_secret(index);
            obj([
                ("secret", hex(&secret)),
                (
                    "public_key",
                    hex(&public_key_of(&secret).expect("public key")),
                ),
                ("address", hex(&fixture_address(index))),
            ])
        })
        .collect();
    let digest = attestation.digest(&TAIRA);
    let signatures: Vec<Value> = (0..4_u8)
        .map(|index| {
            let signature = sign_digest(&fixture_secret(index), &digest).expect("signature");
            check_signature_form(&signature).expect("canonical form");
            assert_eq!(
                recover_address(&digest, &signature),
                Ok(fixture_address(index))
            );
            obj([
                ("key", num(u64::from(index))),
                ("digest", hex(&digest)),
                ("signature", hex(&signature)),
                ("v", num(u64::from(signature[64]))),
                ("address", hex(&fixture_address(index))),
            ])
        })
        .collect();

    // Negatives derived from key 0's attestation signature.
    let good = sign_digest(&fixture_secret(0), &digest).expect("signature");
    let mut high_s = good;
    let s: [u8; 32] = good[32..64].try_into().expect("32 bytes");
    high_s[32..64].copy_from_slice(&sub_be(&SECP256K1_N, &s));
    high_s[64] = if good[64] == 27 { 28 } else { 27 };
    let with_v = |v: u8| {
        let mut signature = good;
        signature[64] = v;
        signature
    };
    let with_r = |r: [u8; 32]| {
        let mut signature = good;
        signature[..32].copy_from_slice(&r);
        signature
    };
    let mut zero_s = good;
    zero_s[32..64].fill(0);
    let mut half_n_plus_one = SECP256K1_HALF_N;
    half_n_plus_one[31] += 1;
    let mut s_above_half = good;
    s_above_half[32..64].copy_from_slice(&half_n_plus_one);
    let negatives: Vec<Value> = [
        ("high_s", high_s),
        ("s_half_n_plus_one", s_above_half),
        ("v_0", with_v(0)),
        ("v_1", with_v(1)),
        ("v_29", with_v(29)),
        ("v_30", with_v(30)),
        ("r_zero", with_r([0; 32])),
        ("r_equals_n", with_r(SECP256K1_N)),
        ("s_zero", zero_s),
    ]
    .into_iter()
    .map(|(label, signature)| {
        let error = recover_address(&digest, &signature).expect_err(label);
        obj([
            ("label", text(label)),
            ("digest", hex(&digest)),
            ("signature", hex(&signature)),
            ("error", error_name(error)),
        ])
    })
    .collect();
    let other_digest = rotation.digest(&TAIRA);
    let wrong_signer = obj([
        ("label", text("signature_over_another_digest")),
        ("digest", hex(&other_digest)),
        ("signature", hex(&good)),
        ("expected_address", hex(&fixture_address(0))),
        (
            "recovered_address",
            hex(&recover_address(&other_digest, &good).expect("recovers some key")),
        ),
    ]);

    // The recovery-id re-sign branch, forced deterministically: the first attempt is reported
    // with v = 29 and the retry uses the fixed extra entropy below.
    let entropy = keccak256(&[b"SCCP/FIXTURE/ENTROPY/V1"]);
    let forced = sign_digest_with(
        &fixture_secret(0),
        &digest,
        |secret, digest, extra| {
            let mut signature = rfc6979_sign(secret, digest, extra)?;
            if extra.is_none() {
                signature[64] = 29;
            }
            Ok(signature)
        },
        || Ok(entropy),
    )
    .expect("forced re-sign");
    assert_ne!(forced, good);
    assert_eq!(recover_address(&digest, &forced), Ok(fixture_address(0)));
    let forced_json = obj([
        ("key", num(0)),
        ("digest", hex(&digest)),
        ("deterministic_signature", hex(&good)),
        ("forced_first_attempt_v", num(29)),
        ("extra_entropy", hex(&entropy)),
        ("resigned_signature", hex(&forced)),
    ]);

    with(
        header(
            "iroha.sccp.eip712.v1",
            "specs/sccp.md §0, §3.6, §3.8 (revision 4)",
        ),
        vec![
            ("taira_network_id", hex(&TAIRA)),
            (
                "domain",
                obj([
                    ("type", text(EIP712_DOMAIN_TYPE)),
                    ("typehash", hex(&DOMAIN_TYPEHASH)),
                    ("name_hash", hex(&NAME_HASH)),
                    ("version_hash", hex(&VERSION_HASH)),
                    ("separator", hex(&separator)),
                ]),
            ),
            (
                "attestation",
                with(
                    Map::new(),
                    vec![
                        ("type", text(ATTESTATION_TYPE)),
                        ("typehash", hex(&ATTESTATION_TYPEHASH)),
                        ("fields", attestation_json(&attestation)),
                    ],
                ),
            ),
            ("rotation_attestation", attestation_json(&rotation)),
            (
                "bridge_key_pop",
                obj([
                    ("type", text(BRIDGE_KEY_TYPE)),
                    ("typehash", hex(&BRIDGE_KEY_TYPEHASH)),
                    ("consensus_public_key", hex(&consensus_key)),
                    ("peer_key_hash", hex(&pop.peer_key_hash)),
                    ("bridge_address", hex(&pop.bridge_address)),
                    ("activation_epoch", num(pop.activation_epoch)),
                    ("struct_hash", hex(&pop.struct_hash())),
                    ("digest", hex(&pop_digest)),
                    ("signature", hex(&pop_signature)),
                ]),
            ),
            (
                "curve",
                obj([("n", hex(&SECP256K1_N)), ("half_n", hex(&SECP256K1_HALF_N))]),
            ),
            ("keys", Value::Array(keys)),
            ("signatures", Value::Array(signatures)),
            ("negatives", Value::Array(negatives)),
            ("wrong_signer", wrong_signer),
            ("forced_resign", forced_json),
        ],
    )
}

fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut borrow = 0_i16;
    for index in (0..32).rev() {
        let mut value = i16::from(a[index]) - i16::from(b[index]) - borrow;
        borrow = i16::from(value < 0);
        if value < 0 {
            value += 256;
        }
        out[index] = u8::try_from(value).expect("byte");
    }
    out
}

// ---------------------------------------------------------------------------------------------
// roster_v1.json
// ---------------------------------------------------------------------------------------------

fn roster_with_zero_slots(generation: u64, n: u32, zeros: u32) -> RosterV1 {
    let mut members: Vec<[u8; 20]> = (0..n - zeros)
        .map(|index| pseudo_address(n * 100 + index))
        .collect();
    members.extend((0..zeros).map(|_| [0; 20]));
    members.sort_unstable();
    RosterV1 {
        generation,
        valid_from_ms: T0,
        valid_until_ms: T0 + 14 * DAY,
        members,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one generator writes one fixture file"
)]
fn roster_fixture() -> Value {
    let rosters: Vec<Value> = [
        ("n4_one_zero_slot", roster_with_zero_slots(1, 4, 1)),
        ("n7_two_zero_slots", roster_with_zero_slots(2, 7, 2)),
        ("n31_five_zero_slots", roster_with_zero_slots(3, 31, 5)),
    ]
    .into_iter()
    .map(|(label, roster)| {
        let digest = roster.digest(&TAIRA).expect("valid roster");
        assert_eq!(
            roster_digest_checked(
                &TAIRA,
                roster.generation,
                roster.valid_from_ms,
                roster.valid_until_ms,
                u8::try_from(roster.threshold()).expect("small"),
                &roster.packed_members(),
            ),
            Ok(digest)
        );
        with(
            Map::new(),
            vec![("label", text(label)), ("roster", roster_json(&roster))],
        )
    })
    .collect();
    let thresholds: Vec<Value> = (MIN_ROSTER_MEMBERS..=MAX_ROSTER_MEMBERS)
        .map(|n| obj([("n", num(n as u64)), ("t", num(threshold(n) as u64))]))
        .collect();

    let base = roster_with_zero_slots(4, 5, 1);
    let packed_negative = |label: &str, generation: u64, t: u8, members: Vec<[u8; 20]>| {
        let packed: Vec<u8> = members.iter().flatten().copied().collect();
        let error =
            roster_digest_checked(&TAIRA, generation, T0, T0 + DAY, t, &packed).expect_err(label);
        obj([
            ("label", text(label)),
            ("generation", num(generation)),
            ("valid_from_ms", num(T0)),
            ("valid_until_ms", num(T0 + DAY)),
            ("threshold", num(u64::from(t))),
            ("packed_members", hex(&packed)),
            ("error", error_name(error)),
        ])
    };
    let mut nonzero_first = base.members.clone();
    nonzero_first.rotate_left(1);
    let mut duplicate = base.members.clone();
    duplicate[2] = duplicate[3];
    let mut descending = base.members.clone();
    descending.swap(2, 3);
    let three: Vec<[u8; 20]> = (0..3).map(pseudo_address).collect();
    let mut thirty_two: Vec<[u8; 20]> = (0..32).map(pseudo_address).collect();
    thirty_two.sort_unstable();
    let rejected = vec![
        packed_negative("zero_slot_after_nonzero", 4, 4, nonzero_first),
        packed_negative("duplicate_member", 4, 4, duplicate),
        packed_negative("descending_members", 4, 4, descending),
        packed_negative("n_3", 4, 3, three),
        packed_negative("n_32", 4, 22, thirty_two),
        packed_negative("threshold_too_high", 4, 5, base.members.clone()),
        packed_negative("threshold_too_low", 4, 3, base.members.clone()),
        packed_negative("generation_zero", 0, 4, base.members.clone()),
        {
            let packed = &base.packed_members()[..99];
            let error = roster_digest_checked(&TAIRA, 4, T0, T0 + DAY, 4, packed)
                .expect_err("partial member");
            obj([
                ("label", text("partial_member_bytes")),
                ("generation", num(4)),
                ("valid_from_ms", num(T0)),
                ("valid_until_ms", num(T0 + DAY)),
                ("threshold", num(4)),
                ("packed_members", hex(packed)),
                ("error", error_name(error)),
            ])
        },
    ];

    let now = T0;
    let max = MAX_ROSTER_VALIDITY_MS;
    let skew = MAX_CLOCK_SKEW_MS;
    let validity: Vec<Value> = [
        ("fourteen_days", now, now + 14 * DAY),
        ("empty_window", now, now),
        ("inverted_window", now + 1, now),
        ("from_at_skew_bound", now + skew, now + skew + DAY),
        ("from_past_skew_bound", now + skew + 1, now + skew + DAY),
        ("window_at_max", now - 1, now - 1 + max),
        ("window_past_max", now - 1, now + max),
        ("until_equals_now", now - DAY, now),
        ("until_now_plus_one", now - DAY, now + 1),
        ("until_at_max_ahead", now + 1, now + max),
        ("until_past_max_ahead", now + 2, now + max + 1),
    ]
    .into_iter()
    .map(|(label, from, until)| {
        let outcome = check_validity_bounds(from, until, now);
        obj([
            ("label", text(label)),
            ("now_ms", num(now)),
            ("valid_from_ms", num(from)),
            ("valid_until_ms", num(until)),
            ("valid", Value::Bool(outcome.is_ok())),
            ("error", outcome.err().map_or(Value::Null, error_name)),
        ])
    })
    .collect();

    with(
        header(
            "iroha.sccp.roster.v1",
            "specs/sccp.md §3.7, §5.1.2, §5.1.5 (revision 4)",
        ),
        vec![
            ("taira_network_id", hex(&TAIRA)),
            (
                "constants",
                obj([
                    ("min_members", num(MIN_ROSTER_MEMBERS as u64)),
                    ("max_members", num(MAX_ROSTER_MEMBERS as u64)),
                    ("max_roster_validity_ms", num(MAX_ROSTER_VALIDITY_MS)),
                    ("max_clock_skew_ms", num(MAX_CLOCK_SKEW_MS)),
                    ("previous_roster_grace_ms", num(PREVIOUS_ROSTER_GRACE_MS)),
                ]),
            ),
            ("rosters", Value::Array(rosters)),
            ("thresholds", Value::Array(thresholds)),
            ("rejected", Value::Array(rejected)),
            ("validity", Value::Array(validity)),
        ],
    )
}

// ---------------------------------------------------------------------------------------------
// evm_calldata_v1.json
// ---------------------------------------------------------------------------------------------

/// The coherent scenario behind the calldata vectors.
struct Scenario {
    g7: RosterV1,
    g8: RosterV1,
    a100: AttestationFieldsV1,
    a150: AttestationFieldsV1,
    a200: AttestationFieldsV1,
    s7_a100: SignatureSetV1,
    s7_a150: SignatureSetV1,
    s8_a200: SignatureSetV1,
    block100: PromoteOddTree,
    history: Vec<[u8; 32]>,
    payloads: Vec<SccpTransferPayloadV1>,
}

fn scenario() -> Scenario {
    let mut g7_members = vec![
        [0; 20],
        fixture_address(0),
        fixture_address(1),
        fixture_address(2),
    ];
    g7_members.sort_unstable();
    let g7 = RosterV1 {
        generation: 7,
        valid_from_ms: T0,
        valid_until_ms: T0 + 14 * DAY,
        members: g7_members,
    };
    let mut g8_members: Vec<[u8; 20]> = (0..4).map(fixture_address).collect();
    g8_members.sort_unstable();
    let g8 = RosterV1 {
        generation: 8,
        valid_from_ms: T0 + 150_000,
        valid_until_ms: T0 + 150_000 + 14 * DAY,
        members: g8_members,
    };
    let d7 = g7.digest(&TAIRA).expect("g7");
    let d8 = g8.digest(&TAIRA).expect("g8");

    let payloads: Vec<SccpTransferPayloadV1> = (0..4).map(eth_outbound).collect();
    let block50 = PromoteOddTree::block(&[eth_transfer_leaf(0)]).expect("block 50");
    let block100 = PromoteOddTree::block(&[
        eth_transfer_leaf(1),
        eth_transfer_leaf(2),
        eth_control_leaf(1, true),
    ])
    .expect("block 100");
    let block200 = PromoteOddTree::block(&[eth_transfer_leaf(3)]).expect("block 200");
    let history = vec![
        history_leaf(50, &block50.root(), 1),
        history_leaf(100, &block100.root(), 3),
        history_leaf(200, &block200.root(), 1),
    ];
    let block_hash = |height: u64| keccak256(&[b"SCCP/FIXTURE/BLOCK/V1", &height.to_be_bytes()]);
    let a100 = AttestationFieldsV1 {
        height: 100,
        epoch: 0,
        timestamp_ms: T0 + 100_000,
        block_hash: block_hash(100),
        sccp_root: block100.root(),
        message_count: 3,
        history_root: history_root(&history[..2]).expect("history"),
        history_size: 2,
        roster_digest: d7,
        next_roster_digest: [0; 32],
    };
    let a150 = AttestationFieldsV1 {
        height: 150,
        epoch: 0,
        timestamp_ms: T0 + 150_000,
        block_hash: block_hash(150),
        sccp_root: [0; 32],
        message_count: 0,
        history_root: history_root(&history[..2]).expect("history"),
        history_size: 2,
        roster_digest: d7,
        next_roster_digest: d8,
    };
    let a200 = AttestationFieldsV1 {
        height: 200,
        epoch: 1,
        timestamp_ms: T0 + 200_000,
        block_hash: block_hash(200),
        sccp_root: block200.root(),
        message_count: 1,
        history_root: history_root(&history).expect("history"),
        history_size: 3,
        roster_digest: d8,
        next_roster_digest: [0; 32],
    };
    for attestation in [&a100, &a150, &a200] {
        attestation.check_invariants().expect("invariants");
    }
    let s7_a100 = signature_set(&g7, &[0, 1, 2], &a100.digest(&TAIRA));
    let s7_a150 = signature_set(&g7, &[2, 0, 1], &a150.digest(&TAIRA));
    let s8_a200 = signature_set(&g8, &[1, 2, 3], &a200.digest(&TAIRA));

    // The destination roster light client accepts the rotation.
    let mut state = RosterStateV1::initial(&g7, &TAIRA, T0 + 100_000).expect("initial");
    state
        .rotate(&a150, &g7, &g8, &TAIRA, T0 + 200_000)
        .expect("rotation");
    assert!(state.accepts(&d8, T0 + 300_000));
    assert!(state.accepts(&d7, T0 + 300_000));

    Scenario {
        g7,
        g8,
        a100,
        a150,
        a200,
        s7_a100,
        s7_a150,
        s8_a200,
        block100,
        history,
        payloads,
    }
}

fn call_json(label: &str, function: &str, calldata: &[u8]) -> Value {
    obj([
        ("label", text(label)),
        ("function", text(function)),
        ("calldata", hex(calldata)),
    ])
}

#[allow(
    clippy::too_many_lines,
    reason = "one generator writes one fixture file"
)]
fn evm_calldata_fixture() -> Value {
    let s = scenario();
    let destination = eth_destination();
    let history_proof = HistoryProofV1 {
        block: HistoryBlockV1 {
            height: 100,
            sccp_root: s.block100.root(),
            message_count: 3,
        },
        leaf_index: 1,
        path: history_path(&s.history, 1).expect("history path"),
    };
    let message = |nonce: u64, index: usize| MessageProofV1 {
        payload: s.payloads[usize::try_from(nonce).expect("small")]
            .encode()
            .expect("payload"),
        leaf_index: u32::try_from(index).expect("small"),
        path: s.block100.path(index).expect("path"),
    };
    let proof1 = message(1, 0);
    let proof2 = message(2, 1);
    let control = ControlProofV1 {
        control_nonce: 1,
        paused: true,
        leaf_index: 2,
        path: s.block100.path(2).expect("path"),
    };
    // The bundles verify with the pure destination checks.
    verify_transfer_direct(&s.a100, &proof1, &TAIRA, &destination).expect("direct transfer");
    verify_transfer_historical(&s.a200, &history_proof, &proof2, &TAIRA, &destination)
        .expect("historical transfer");
    verify_control_direct(&s.a100, &control, &TAIRA, &destination).expect("direct control");
    verify_control_historical(&s.a200, &history_proof, &control, &TAIRA, &destination)
        .expect("historical control");

    let g7_attested = AttestedV1 {
        attestation: &s.a100,
        roster: &s.g7,
        signatures: &s.s7_a100,
    };
    let g8_attested = AttestedV1 {
        attestation: &s.a200,
        roster: &s.g8,
        signatures: &s.s8_a200,
    };
    let rotation = RotationV1 {
        attestation: s.a150,
        current: s.g7.clone(),
        signatures: s.s7_a150.clone(),
        next: s.g8.clone(),
    };
    let transfer_call = TransferToTairaCallV1 {
        taira_recipient: taira_account(9),
        token_amount: 1_500_000_000,
        expected_nonce: 0,
    };
    let transfer_calldata = transfer_call.calldata();
    assert_eq!(
        TransferToTairaCallV1::decode(&transfer_calldata).as_ref(),
        Ok(&transfer_call)
    );
    let void_expired = void_expired_calldata(1, g7_attested, &proof1);
    let void_expired_historical =
        void_expired_historical_calldata(2, g8_attested, &history_proof, &proof2);
    let void_frozen = void_frozen_calldata(4, 3);
    assert_eq!(
        VoidCallV1::decode(&void_expired),
        Ok(VoidCallV1::Expired {
            nonce: 1,
            historical: false
        })
    );
    assert_eq!(
        VoidCallV1::decode(&void_expired_historical),
        Ok(VoidCallV1::Expired {
            nonce: 2,
            historical: true
        })
    );
    assert_eq!(
        VoidCallV1::decode(&void_frozen),
        Ok(VoidCallV1::Frozen {
            first_nonce: 4,
            count: 3
        })
    );
    let calls = vec![
        call_json(
            "finalize_direct",
            "finalizeFromTaira",
            &finalize_from_taira_calldata(g7_attested, &proof1),
        ),
        call_json(
            "finalize_historical",
            "finalizeFromTairaHistorical",
            &finalize_from_taira_historical_calldata(g8_attested, &history_proof, &proof2),
        ),
        call_json(
            "rotate_one",
            "rotateRosters",
            &rotate_rosters_calldata(std::slice::from_ref(&rotation)),
        ),
        call_json(
            "apply_control_direct",
            "applyControl",
            &apply_control_calldata(g7_attested, &control),
        ),
        call_json(
            "apply_control_historical",
            "applyControlHistorical",
            &apply_control_historical_calldata(g8_attested, &history_proof, &control),
        ),
        call_json("void_expired", "voidExpired", &void_expired),
        call_json(
            "void_expired_historical",
            "voidExpiredHistorical",
            &void_expired_historical,
        ),
        call_json("void_frozen", "voidFrozen", &void_frozen),
        call_json("transfer_to_taira", "transferToTaira", &transfer_calldata),
    ];

    let views: Vec<Value> = [
        ("rosterState", ViewCallV1::RosterState),
        ("isConsumed", ViewCallV1::IsConsumed(300)),
        ("transferNonces", ViewCallV1::TransferNonces([0x55; 20])),
        ("tairaNetworkId", ViewCallV1::TairaNetworkId),
        ("routeRevision", ViewCallV1::RouteRevision),
        ("maxWrappedSupply", ViewCallV1::MaxWrappedSupply),
        ("mintingPaused", ViewCallV1::MintingPaused),
        ("controlNonce", ViewCallV1::ControlNonce),
        ("domainSeparator", ViewCallV1::DomainSeparator),
        ("initialRosterDigest", ViewCallV1::InitialRosterDigest),
        (
            "initialRosterGeneration",
            ViewCallV1::InitialRosterGeneration,
        ),
        ("opCount", ViewCallV1::OpCount),
        ("maxRosterValidityMs", ViewCallV1::MaxRosterValidityMs),
    ]
    .into_iter()
    .map(|(function, call)| call_json(function, function, &call.calldata()))
    .collect();
    let mut state = RosterStateV1::initial(&s.g7, &TAIRA, T0 + 100_000).expect("initial");
    state
        .rotate(&s.a150, &s.g7, &s.g8, &TAIRA, T0 + 200_000)
        .expect("rotation");
    let roster_state_return = encode_roster_state_return(&state);
    assert_eq!(
        ViewCallV1::RosterState.decode_return(&roster_state_return),
        Ok(iroha_sccp::v1::evm_abi::ViewReturnV1::RosterState(state))
    );

    // Logs: the burn of `transfer_call` by caller 0x55…55, and both void shapes.
    let caller = [0x55; 20];
    let inbound = transfer_call
        .inbound_payload(SccpNetworkV1::EthereumMainnet, 1, &caller)
        .expect("inbound payload");
    let transfer_log = TransferToTairaLogV1 {
        message_id: inbound.message_id(&TAIRA).expect("message id"),
        sender: caller,
        nonce: 0,
        payload: inbound.encode().expect("payload"),
    };
    assert_eq!(
        transfer_log.verified_payload(&TAIRA, SccpNetworkV1::EthereumMainnet, 1),
        Ok(inbound)
    );
    let log_json = |label: &str, topics: Vec<[u8; 32]>, data: Vec<u8>| {
        obj([
            ("label", text(label)),
            ("topics", hexes(&topics)),
            ("data", hex(&data)),
        ])
    };
    let (transfer_topics, transfer_data) = transfer_log.encode();
    let expired_void = VoidedLogV1 {
        message_id: s.payloads[1].message_id(&TAIRA).expect("message id"),
        nonce: 1,
    };
    let frozen_void = VoidedLogV1 {
        message_id: [0; 32],
        nonce: 4,
    };
    let (expired_topics, expired_data) = expired_void.encode();
    let (frozen_topics, frozen_data) = frozen_void.encode();
    let logs = vec![
        log_json("transfer_to_taira", transfer_topics, transfer_data),
        log_json("voided_expired", expired_topics, expired_data),
        log_json("voided_frozen", frozen_topics, frozen_data),
    ];

    let conformance = calldata_conformance(&transfer_call, &void_expired, &void_expired_historical);

    let selectors: Vec<Value> = SELECTORS
        .iter()
        .map(|(name, signature, selector)| {
            obj([
                ("function", text(name)),
                ("signature", text(signature)),
                ("selector", hex(selector)),
            ])
        })
        .collect();
    let events: Vec<Value> = EVENT_TOPICS
        .iter()
        .map(|(signature, topic)| obj([("signature", text(signature)), ("topic0", hex(topic))]))
        .collect();

    let payloads_json: Vec<Value> = s
        .payloads
        .iter()
        .map(|payload| {
            obj([
                ("nonce", num(payload.nonce)),
                ("payload", hex(&payload.encode().expect("payload"))),
                (
                    "message_id",
                    hex(&payload.message_id(&TAIRA).expect("message id")),
                ),
            ])
        })
        .collect();
    let scenario_json = obj([
        ("taira_network_id", hex(&TAIRA)),
        (
            "destination",
            obj([
                ("target", profile(destination.network)),
                ("route_revision", num(u64::from(destination.route_revision))),
                ("destination_word", hex(&destination.destination_word)),
            ]),
        ),
        ("deadline_ms", num(DEADLINE)),
        ("payloads", Value::Array(payloads_json)),
        ("roster_g7", roster_json(&s.g7)),
        ("roster_g8", roster_json(&s.g8)),
        ("attestation_100", attestation_json(&s.a100)),
        ("attestation_150_rotation", attestation_json(&s.a150)),
        ("attestation_200", attestation_json(&s.a200)),
        ("signatures_g7_100", signatures_json(&s.s7_a100)),
        ("signatures_g7_150", signatures_json(&s.s7_a150)),
        ("signatures_g8_200", signatures_json(&s.s8_a200)),
        ("block_100_root", hex(&s.block100.root())),
        ("history_leaves", hexes(&s.history)),
        ("roster_state_after_rotation", hex(&roster_state_return)),
    ]);

    with(
        header(
            "iroha.sccp.evm-calldata.v1",
            "specs/sccp.md §4.12.2, §4.16, §5.1.3–§5.1.8, §5.2.2 (revision 4)",
        ),
        vec![
            ("scenario", scenario_json),
            ("selectors", Value::Array(selectors)),
            ("events", Value::Array(events)),
            ("calls", Value::Array(calls)),
            ("views", Value::Array(views)),
            ("logs", Value::Array(logs)),
            ("calldata_conformance", Value::Array(conformance)),
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

/// The `voidExpired*` variants (`historical` selects `voidExpiredHistorical`, whose head has 15
/// words instead of 14). Besides the length edits, every unsigned integer field gets a word
/// with the lowest bit above its declared width set, every dynamic offset is moved past an
/// inserted zero word (with every enclosing offset moved accordingly, so Solidity's own decoder
/// reads the same arguments) and every `bytes` value gets a nonzero padding byte.
fn void_expired_variants(
    base: &[u8],
    historical: bool,
) -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let head_words = if historical { 15 } else { 14 };
    let head = |from: usize| (from..head_words).map(|word| word * WORD);
    let roster_at = arg_u64(base, 11 * WORD);
    let signatures_at = arg_u64(base, 12 * WORD);
    let proof_head = (head_words - 1) * WORD;
    let proof_at = arg_u64(base, proof_head);
    let members_at = roster_at + arg_u64(base, roster_at + 4 * WORD);
    let signature_bytes_at = signatures_at + arg_u64(base, signatures_at + WORD);
    let payload_at = proof_at + arg_u64(base, proof_at);
    let path_at = proof_at + arg_u64(base, proof_at + 2 * WORD);

    // (label, argument offset of the word, declared width in bytes).
    let mut fields = vec![
        ("dirty_attestation_height", WORD, 8),
        ("dirty_attestation_epoch", 2 * WORD, 8),
        ("dirty_attestation_timestamp_ms", 3 * WORD, 8),
        ("dirty_attestation_message_count", 6 * WORD, 4),
        ("dirty_attestation_history_size", 8 * WORD, 8),
        ("dirty_roster_generation", roster_at, 8),
        ("dirty_roster_valid_from_ms", roster_at + WORD, 8),
        ("dirty_roster_valid_until_ms", roster_at + 2 * WORD, 8),
        ("dirty_roster_threshold", roster_at + 3 * WORD, 1),
        ("dirty_signer_bitmap", signatures_at, 4),
        ("dirty_message_leaf_index", proof_at + WORD, 4),
    ];
    // (label, argument offset where the zero word goes, offsets that move past it).
    let mut gaps: Vec<(&'static str, usize, Vec<usize>)> = vec![
        ("roster_offset_gap", roster_at, head(11).collect()),
        (
            "members_offset_gap",
            members_at,
            std::iter::once(roster_at + 4 * WORD)
                .chain(head(12))
                .collect(),
        ),
        ("signatures_offset_gap", signatures_at, head(12).collect()),
        (
            "signature_bytes_offset_gap",
            signature_bytes_at,
            std::iter::once(signatures_at + WORD)
                .chain(head(13))
                .collect(),
        ),
        ("message_proof_offset_gap", proof_at, vec![proof_head]),
        (
            "payload_offset_gap",
            payload_at,
            vec![proof_at, proof_at + 2 * WORD],
        ),
        ("path_offset_gap", path_at, vec![proof_at + 2 * WORD]),
    ];
    let paddings = [
        ("nonzero_members_padding", members_at),
        ("nonzero_signatures_padding", signature_bytes_at),
        ("nonzero_payload_padding", payload_at),
    ];
    if historical {
        let history_at = arg_u64(base, 13 * WORD);
        fields.extend([
            ("dirty_history_height", history_at, 8),
            ("dirty_history_message_count", history_at + 2 * WORD, 4),
            ("dirty_history_leaf_index", history_at + 3 * WORD, 8),
        ]);
        gaps.extend([
            ("history_offset_gap", history_at, head(13).collect()),
            (
                "history_path_offset_gap",
                history_at + arg_u64(base, history_at + 4 * WORD),
                vec![history_at + 4 * WORD, 14 * WORD],
            ),
        ]);
    }

    let mut variants = vec![
        ("canonical", base.to_vec(), ACCEPT),
        ("trailing_byte", appended(base, &[0]), NON_CANONICAL),
        ("trailing_word", appended(base, &[0; WORD]), NON_CANONICAL),
        ("short_byte", base[..base.len() - 1].to_vec(), NON_CANONICAL),
        ("dirty_nonce_high_bits", dirty(base, 0, 23), EMPTY_REVERT),
        ("offset_high_bits", dirty(base, 11 * WORD, 0), EMPTY_REVERT),
    ];
    variants.extend(
        fields
            .into_iter()
            .map(|(label, at, width)| (label, dirty(base, at, WORD - width - 1), NON_CANONICAL)),
    );
    variants.extend(gaps.into_iter().map(|(label, at, offsets)| {
        let mut calldata = with_gap(base, at);
        for offset in offsets {
            assert!(offset < at, "{label}: only offsets before the gap move");
            bump(&mut calldata, offset, 0x20);
        }
        (label, calldata, NON_CANONICAL)
    }));
    variants.extend(paddings.into_iter().map(|(label, at)| {
        let len = arg_u64(base, at);
        assert_ne!(len % WORD, 0, "{label}: the bytes have padding");
        let mut calldata = base.to_vec();
        calldata[4 + at + WORD + len.div_ceil(WORD) * WORD - 1] = 1;
        (label, calldata, NON_CANONICAL)
    }));
    variants
}

/// The shared void and burn calldata conformance table (§5.1.7, §5.1.8, §5.2.2): every entry
/// records the Rust decoder's verdict and the destination's outcome in a state where the
/// canonical call succeeds, and the two accept exactly the same entries. `contract` is
/// `accept`, a custom error, or `empty` for a revert in Solidity's ABI decoder.
fn calldata_conformance(
    transfer_call: &TransferToTairaCallV1,
    void_expired: &[u8],
    void_expired_historical: &[u8],
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
        "voidExpiredHistorical",
        void_expired_variants(void_expired_historical, true),
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
            assert_eq!(
                decoder == text(ACCEPT),
                contract == ACCEPT,
                "{function} {label}: the decoder and the contract disagree"
            );
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

const FIXTURES: [(&str, Generator); 6] = [
    ("payload_v1.json", payload_fixture),
    ("commitment_tree_v1.json", commitment_tree_fixture),
    ("history_v1.json", history_fixture),
    ("eip712_v1.json", eip712_fixture),
    ("roster_v1.json", roster_fixture),
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
