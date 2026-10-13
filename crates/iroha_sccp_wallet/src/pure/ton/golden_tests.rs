//! Canonical wallet-produced TON BoCs replayed by the independent Tolk contracts.

use super::*;
use crate::pure::{
    bundle::{CertificateUseV1, DestinationContextV1, certificate_wire, verify_message_bundle},
    control::{DestinationControlStateV1, verify_control_bundle},
    rotation::verify_rotation_steps,
    test_support::{Fixture, INSTANCE, NETWORK, NOW, T0},
};
use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::{
    api::{SccpBlockRefV1, SccpMessageProofBundleV1},
    v1::{
        destination::{DestinationFlavor, check_ton_burn_payload},
        finality::checkpoint_id,
        hashes::transfer_leaf,
        history::{history_path, history_root},
        merkle::PromoteOddTree,
        payload::SccpTransferPayloadV1,
    },
};
use norito::{json, json::Value};

const DESTINATION: [u8; 32] = [0x35; 32];
const RECIPIENT: [u8; 32] = [0x33; 32];
const RESPONSE: [u8; 32] = [3; 32];
const DEADLINE: u64 = T0 + 86_400_000;

fn context(f: &Fixture) -> DestinationContextV1<'_> {
    DestinationContextV1 {
        taira_network_id: NETWORK,
        consensus_instance: INSTANCE,
        destination: f.destination,
        flavor: DestinationFlavor::Ton,
        committee_state: f.state,
        ton_keys: Some(&f.keys),
        checkpoints: &f.checkpoints,
        now_ms: NOW,
    }
}

fn message(f: &Fixture, historical: bool) -> SccpMessageProofBundleV1 {
    let mut recipient = vec![0; 4];
    recipient.extend_from_slice(&RECIPIENT);
    let payload = SccpTransferPayloadV1::outbound(
        SccpNetworkV1::TonMainnet,
        1,
        f.destination.route_revision,
        DEADLINE,
        1_000,
        vec![1, 2, 3],
        recipient,
    )
    .unwrap();
    let id = payload.message_id(&NETWORK).unwrap();
    let tree = PromoteOddTree::block(&[[5; 32], transfer_leaf(&id, &DESTINATION)]).unwrap();
    let mut fields = f.fields(if historical { 20 } else { 9 });
    let mut block = SccpBlockRefV1 {
        height: 9,
        sccp_root: tree.root(),
        message_count: 2,
        history_index: 0,
        history_path: vec![],
    };
    if historical {
        let leaves = [
            iroha_sccp::v1::hashes::history_leaf(3, &[3; 32], 1),
            iroha_sccp::v1::hashes::history_leaf(9, &tree.root(), 2),
        ];
        block.history_index = 1;
        block.history_path = history_path(&leaves, 1).unwrap();
        fields.history_size = 2;
        fields.history_root = history_root(&leaves).unwrap();
    } else {
        fields.message_count = 2;
        fields.sccp_root = tree.root();
    }
    SccpMessageProofBundleV1 {
        message_id: id,
        payload: payload.encode().unwrap(),
        deadline_ms: DEADLINE,
        leaf_index: 1,
        path: tree.path(1).unwrap(),
        block,
        certificate: f.certify(fields),
    }
}

fn row(label: &str, kind: &str, cell: Cell) -> Value {
    let boc = cell.to_boc().unwrap();
    assert_eq!(cell_from_boc(&boc).unwrap(), cell, "{label}");
    json!({
        "label": label,
        "kind": kind,
        "boc": (hex::encode(boc)),
        "hash": (hex::encode(cell.hash())),
        "bits": (cell.bit_len() as u64),
        "depth": (cell.depth()),
    })
}

fn fixture() -> Value {
    let mut f = Fixture::new();
    f.destination.network = SccpNetworkV1::TonMainnet;
    f.destination.destination_word = DESTINATION;
    let next = Fixture::with_tag(1);
    let mut rows = vec![
        row("keys", "KeyChunk", key_chunks(&f.keys).unwrap()),
        row("next_keys", "KeyChunk", key_chunks(&next.keys).unwrap()),
        row("init", "SccpInit", init_body(7).unwrap()),
        row(
            "deploy_buckets",
            "SccpDeployBuckets",
            deploy_buckets_body(3, 7, &RESPONSE).unwrap(),
        ),
        row(
            "retry",
            "SccpRetry",
            retry_body(1024, 7, &RESPONSE).unwrap(),
        ),
        row(
            "void_frozen",
            "SccpVoidFrozen",
            void_frozen_body(512, 512, 7, &RESPONSE).unwrap(),
        ),
    ];
    for historical in [false, true] {
        let label = if historical { "historical" } else { "direct" };
        let bundle = message(&f, historical);
        let wire = certificate_wire(&bundle.certificate).unwrap();
        rows.push(row(
            &format!("certificate_{label}"),
            "TairaCert",
            certificate_cell(&wire).unwrap(),
        ));
        rows.push(row(
            &format!("proof_{label}"),
            "MessageProof",
            message_proof_cell(&bundle.message_proof()).unwrap(),
        ));
        f.checkpoints.clear();
        f.checkpoints.insert(
            bundle.certificate.height,
            checkpoint_id(&bundle.certificate.header),
        );
        for (source, usage) in [
            ("inline", CertificateUseV1::Inline),
            ("checkpoint", CertificateUseV1::Checkpoint),
        ] {
            let selected = context(&f);
            let verified =
                verify_message_bundle(&bundle, &selected, BundlePurposeV1::Finalize, usage)
                    .unwrap();
            rows.push(row(
                &format!("finalize_{label}_{source}"),
                if usage == CertificateUseV1::Inline {
                    "SccpFinalize"
                } else {
                    "SccpFinalizeCheckpoint"
                },
                finalize_body(&verified, 7, &RESPONSE).unwrap(),
            ));
            let mut expired = selected;
            expired.now_ms = DEADLINE + 1;
            let verified =
                verify_message_bundle(&bundle, &expired, BundlePurposeV1::VoidExpired, usage)
                    .unwrap();
            rows.push(row(
                &format!("void_{label}_{source}"),
                if usage == CertificateUseV1::Inline {
                    "SccpVoidExpired"
                } else {
                    "SccpVoidExpiredCheckpoint"
                },
                void_expired_body(&verified, 7, &RESPONSE).unwrap(),
            ));
        }
    }
    f.checkpoints.clear();
    let control = f.control();
    let wire = certificate_wire(&control.certificate).unwrap();
    rows.push(row(
        "certificate_control",
        "TairaCert",
        certificate_cell(&wire).unwrap(),
    ));
    rows.push(row(
        "proof_control",
        "ControlProof",
        control_proof_cell(&control.control_proof()).unwrap(),
    ));
    f.checkpoints.insert(
        control.certificate.height,
        checkpoint_id(&control.certificate.header),
    );
    for (source, usage) in [
        ("inline", CertificateUseV1::Inline),
        ("checkpoint", CertificateUseV1::Checkpoint),
    ] {
        let verified = verify_control_bundle(
            &control,
            &context(&f),
            &DestinationControlStateV1::default(),
            usage,
        )
        .unwrap();
        rows.push(row(
            &format!("control_{source}"),
            if usage == CertificateUseV1::Inline {
                "SccpApplyControl"
            } else {
                "SccpApplyControlCheckpoint"
            },
            apply_control_body(&verified, 7, &RESPONSE).unwrap(),
        ));
    }
    f.checkpoints.clear();
    for (label, target) in [
        ("checkpoint_heartbeat", &f),
        ("checkpoint_key_change", &next),
    ] {
        let plan = verify_rotation_steps(&[f.rotation(1, 101, target)], &context(&f), 2).unwrap();
        rows.push(row(
            label,
            "SccpCheckpoint",
            checkpoint_body(&plan.steps()[0], 7, &RESPONSE).unwrap(),
        ));
    }
    for size in [1, 127, 128, 1024] {
        rows.push(row(
            &format!("burn_{size}"),
            "SccpBurnToTaira",
            burn_payload_cell(&vec![0x42; size]).unwrap(),
        ));
    }
    let mut negatives = Vec::new();
    for (label, snake) in [
        ("empty", CellBuilder::new().build()),
        (
            "partial_byte",
            CellBuilder::new().store_bit(true).unwrap().build(),
        ),
        (
            "short_nonterminal",
            CellBuilder::new()
                .store_bytes(&[1])
                .unwrap()
                .store_ref(snake_bytes(&[2]).unwrap())
                .unwrap()
                .build(),
        ),
        (
            "extra_reference",
            CellBuilder::new()
                .store_bytes(&[1])
                .unwrap()
                .store_ref(snake_bytes(&[2]).unwrap())
                .unwrap()
                .store_ref(snake_bytes(&[3]).unwrap())
                .unwrap()
                .build(),
        ),
        ("oversized", snake_bytes(&[0x42; 1025]).unwrap()),
    ] {
        let cell = CellBuilder::new()
            .store_uint(0x5343_4254, 32)
            .unwrap()
            .store_ref(snake)
            .unwrap()
            .build();
        let refusal = format!("{:?}", check_ton_burn_payload(Some(&cell)).unwrap_err());
        let mut value = row(label, "SccpBurnToTaira", cell);
        value
            .as_object_mut()
            .unwrap()
            .insert("expected".to_owned(), Value::String(refusal));
        negatives.push(value);
    }
    json!({
        "schema": "iroha.sccp.ton-boc.v1",
        "generator": "crates/iroha_sccp_wallet/src/pure/ton/golden_tests.rs",
        "context": {
            "network_id": (hex::encode(NETWORK)), "consensus_instance": (hex::encode(INSTANCE)),
            "destination": (hex::encode(DESTINATION)), "recipient": (hex::encode(RECIPIENT)),
            "revision": (f.destination.route_revision), "now_ms": NOW, "deadline_ms": DEADLINE,
            "generation": (f.state.generation), "root": (hex::encode(f.state.root)),
            "start": (f.state.start), "until_ms": (f.state.until_ms),
        },
        "rows": rows, "snake_negatives": negatives,
    })
}

fn rendered_fixture() -> String {
    let mut text = norito::json::to_string_pretty(&fixture()).unwrap();
    text.push('\n');
    text
}

fn fixture_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sccp/ton_boc_v1.json")
}

#[test]
fn ton_boc_vectors_match_wallet_encoders() {
    assert_eq!(
        std::fs::read_to_string(fixture_path()).unwrap(),
        rendered_fixture()
    );
}

#[test]
#[ignore = "regenerates reviewed TON BoCs for independent contract replay"]
fn regenerate_ton_boc_vectors() {
    std::fs::write(fixture_path(), rendered_fixture()).unwrap();
}
