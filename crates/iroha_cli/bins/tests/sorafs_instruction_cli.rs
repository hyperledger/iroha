//! Executable coverage for canonical offline `SoraFS` instruction preparation.
use assert_cmd::cargo::cargo_bin_cmd;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use iroha_data_model::{isi::sorafs::RegisterCapacityDeclaration, prelude::InstructionBox};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use norito::{
    decode_from_bytes,
    json::{self, Value},
    to_bytes,
};
use sorafs_manifest::{
    canonical_manifest_root_cid,
    capacity::{
        CAPACITY_DECLARATION_VERSION_V1, CapacityDeclarationV1, CapacityMetadataEntry,
        ChunkerCommitmentV1, LaneCommitmentV1, REPLICATION_ORDER_VERSION_V1,
        ReplicationAssignmentV1, ReplicationOrderSlaV1, ReplicationOrderV1,
    },
    provider_advert::{CapabilityType, StakePointer},
};
use std::fs;
use tempfile::tempdir;
#[test]
fn tx_stdin_builder_wraps_capacity_declaration_summaries() {
    let temp = tempdir().expect("tempdir");
    let summary_path = temp.path().join("declaration_summary.json");
    let declaration_b64 =
        BASE64_STD.encode(to_bytes(&sample_declaration()).expect("serialize declaration"));
    fs::write(
        &summary_path,
        format!("{{\"declaration_b64\":\"{declaration_b64}\"}}\n"),
    )
    .expect("write declaration summary");
    let payload = run_builder([
        "capacity-declaration".to_owned(),
        format!("--summary={}", summary_path.display()),
    ]);
    let instruction = decode_single_instruction(&payload);
    let declaration = instruction
        .as_any()
        .downcast_ref::<RegisterCapacityDeclaration>()
        .expect("register capacity declaration");
    let decoded: CapacityDeclarationV1 = decode_from_bytes(&declaration.declaration).unwrap();
    assert_eq!(decoded, sample_declaration());
    assert_eq!(decoded.provider_id, [0x11; 32]);
    assert_eq!(decoded.valid_from, 1_700_000_000);
    assert_eq!(decoded.valid_until, 1_700_086_400);
}
#[test]
fn tx_stdin_builder_rejects_redundant_capacity_summary_fields() {
    let temp = tempdir().expect("tempdir");
    let summary_path = temp.path().join("redundant_declaration_summary.json");
    let declaration_b64 = BASE64_STD.encode(to_bytes(&sample_declaration()).unwrap());
    for field in [
        "registered_epoch",
        "valid_from_epoch",
        "valid_until_epoch",
        "provider_id_hex",
        "committed_capacity_gib",
        "metadata",
    ] {
        fs::write(
            &summary_path,
            format!("{{\"declaration_b64\":\"{declaration_b64}\",\"{field}\":580}}\n"),
        )
        .unwrap();
        let stderr = run_builder_failure([
            "capacity-declaration".to_owned(),
            format!("--summary={}", summary_path.display()),
        ]);
        assert!(
            stderr.contains(field) && stderr.contains("must be omitted"),
            "redundant {field} must be rejected: {stderr}"
        );
    }
}
#[test]
fn tx_stdin_builder_wraps_replication_order_summaries() {
    let temp = tempdir().expect("tempdir");
    let summary_path = temp.path().join("order_summary.json");
    let order_b64 =
        BASE64_STD.encode(to_bytes(&sample_replication_order()).expect("serialize order"));
    fs::write(
        &summary_path,
        format!("{{\n  \"replication_order_b64\": \"{order_b64}\"\n}}\n"),
    )
    .expect("write order summary");
    let payload = run_builder([
        "replication-order".to_owned(),
        format!("--summary={}", summary_path.display()),
    ]);
    let instruction = decode_single_instruction(&payload);
    let order = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::sorafs::IssueReplicationOrder>()
        .expect("issue replication order");
    assert_eq!(order.issued_epoch, 1_700_000_000);
    assert_eq!(order.deadline_epoch, 1_700_003_600);
    assert_eq!(order.order_id.as_bytes(), &[0x55; 32]);
    assert_eq!(order.musubi_archive, None);
}
#[test]
fn tx_stdin_builder_binds_replication_order_to_musubi_archive() {
    let temp = tempdir().expect("tempdir");
    let summary_path = temp.path().join("order_summary.json");
    let order_b64 =
        BASE64_STD.encode(to_bytes(&sample_replication_order()).expect("serialize order"));
    fs::write(
        &summary_path,
        format!("{{\n  \"replication_order_b64\": \"{order_b64}\"\n}}\n"),
    )
    .expect("write order summary");
    let payload = run_builder([
        "replication-order".to_owned(),
        format!("--summary={}", summary_path.display()),
        format!("--musubi-archive-id-hex={}", "a5".repeat(32)),
    ]);
    let instruction = decode_single_instruction(&payload);
    let order = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::sorafs::IssueReplicationOrder>()
        .expect("issue replication order");
    assert_eq!(
        order.musubi_archive,
        Some(iroha_data_model::musubi::ArchiveId::new([0xa5; 32]))
    );
}
#[test]
fn tx_stdin_builder_rejects_reserved_automatic_order_id() {
    let temp = tempdir().expect("tempdir");
    let summary_path = temp.path().join("reserved_order_summary.json");
    let mut order = sample_replication_order();
    order.order_id[0] |= 0x80;
    let order_b64 = BASE64_STD.encode(to_bytes(&order).expect("serialize reserved order"));
    fs::write(
        &summary_path,
        format!("{{\n  \"replication_order_b64\": \"{order_b64}\"\n}}\n"),
    )
    .expect("write order summary");
    let stderr = run_builder_failure([
        "replication-order".to_owned(),
        format!("--summary={}", summary_path.display()),
    ]);
    assert!(
        stderr.contains("reserved automatic order id"),
        "generic builder must reject the automatic namespace: {stderr}"
    );
}
#[test]
fn tx_stdin_builder_rejects_redundant_replication_epoch_options() {
    for option in ["--issued-epoch=580", "--deadline-epoch=2580"] {
        let stderr = run_builder_failure([
            "replication-order".to_owned(),
            "--summary=unused.json".to_owned(),
            option.to_owned(),
        ]);
        assert!(
            stderr.contains("unexpected argument")
                && stderr.contains(option.split('=').next().unwrap()),
            "payload timestamps are authoritative and {option} must be rejected: {stderr}"
        );
    }
}
#[test]
fn tx_stdin_builder_rejects_noncanonical_musubi_archive_id_hex() {
    for value in [
        "a5".repeat(31),
        format!("0x{}", "a5".repeat(32)),
        "A5".repeat(32),
        "00".repeat(32),
    ] {
        let stderr = run_builder_failure([
            "replication-order".to_owned(),
            "--summary=unused.json".to_owned(),
            format!("--musubi-archive-id-hex={value}"),
        ]);
        assert!(
            stderr.contains("--musubi-archive-id-hex"),
            "stderr should name rejected Musubi archive id {value}, got: {stderr}"
        );
    }
}
#[test]
fn tx_stdin_builder_emits_completion_instruction() {
    let payload = run_builder([
        "complete-order".to_owned(),
        "--order-id-hex=5555555555555555555555555555555555555555555555555555555555555555"
            .to_owned(),
        "--provider-id-hex=6666666666666666666666666666666666666666666666666666666666666666"
            .to_owned(),
        "--completion-epoch=777".to_owned(),
        format!("--expected-owner={}", *ALICE_ID),
        format!("--expected-completion-signer={}", *BOB_ID),
        "--assignment-revision=3".to_owned(),
        format!("--signer-policy-id-hex={}", "33".repeat(32)),
        "--signer-policy-revision=2".to_owned(),
        format!("--signer-policy-predecessor-digest-hex={}", "44".repeat(32)),
        format!("--signer-policy-digest-hex={}", "55".repeat(32)),
        "--finalized-height=19".to_owned(),
        format!("--finalized-block-hash-hex={}", "66".repeat(32)),
    ]);
    let instruction = decode_single_instruction(&payload);
    let completion = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::sorafs::CompleteReplicationOrder>()
        .expect("complete replication order");
    assert_eq!(completion.completion_epoch, 777);
    assert_eq!(completion.order_id.as_bytes(), &[0x55; 32]);
    assert_eq!(completion.provider_id.as_bytes(), &[0x66; 32]);
    assert_eq!(completion.expected_authority.provider_owner, *ALICE_ID);
    assert_eq!(completion.expected_authority.completion_signer, *BOB_ID);
    let signer_policy = &completion.expected_authority.signer_policy;
    assert_eq!(signer_policy.policy_id, [0x33; 32]);
    assert_eq!(signer_policy.revision, 2);
    assert_eq!(signer_policy.predecessor_digest, Some([0x44; 32]));
    assert_eq!(signer_policy.policy_digest, [0x55; 32]);
    assert_eq!(completion.expected_assignment_revision, 3);
    assert_eq!(completion.finalized_anchor.height, 19);
    assert_eq!(completion.finalized_anchor.block_hash, [0x66; 32]);
}
#[test]
fn tx_stdin_builder_emits_expiration_instruction() {
    let payload = run_builder([
        "expire-order".to_owned(),
        "--order-id-hex=5555555555555555555555555555555555555555555555555555555555555555"
            .to_owned(),
        "--expiration-epoch=778".to_owned(),
    ]);
    let instruction = decode_single_instruction(&payload);
    let expiration = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::sorafs::ExpireReplicationOrder>()
        .expect("expire replication order");
    assert_eq!(expiration.expiration_epoch, 778);
    assert_eq!(expiration.order_id.as_bytes(), &[0x55; 32]);
}
#[test]
fn tx_stdin_builder_rejects_noncanonical_epoch_flags() {
    for (args, expected) in [
        (
            vec![
                "complete-order",
                "--order-id-hex=5555555555555555555555555555555555555555555555555555555555555555",
                "--completion-epoch=0777",
            ],
            "--completion-epoch",
        ),
        (
            vec![
                "expire-order",
                "--order-id-hex=5555555555555555555555555555555555555555555555555555555555555555",
                "--expiration-epoch=0778",
            ],
            "--expiration-epoch",
        ),
    ] {
        let stderr = run_builder_failure(args.into_iter().map(str::to_owned));
        assert!(
            stderr.contains(expected) && stderr.contains("canonical unsigned"),
            "stderr should reject {expected} canonically, got: {stderr}"
        );
    }
}
#[test]
fn tx_stdin_builder_rejects_noncanonical_order_id_hex() {
    for value in [
        "5555",
        "0x5555555555555555555555555555555555555555555555555555555555555555",
        "555555555555555555555555555555555555555555555555555555555555555A",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ] {
        let stderr = run_builder_failure([
            "complete-order".to_owned(),
            format!("--order-id-hex={value}"),
            "--completion-epoch=777".to_owned(),
        ]);
        assert!(
            stderr.contains("--order-id-hex"),
            "stderr should name rejected order_id_hex {value}, got: {stderr}"
        );
    }
}
#[test]
fn tx_stdin_builder_rejects_duplicate_options() {
    for (args, expected) in [
        (
            vec![
                "capacity-declaration",
                "--summary=one.json",
                "--summary=two.json",
            ],
            "--summary",
        ),
        (
            vec![
                "replication-order",
                "--summary=one.json",
                "--summary=two.json",
            ],
            "--summary",
        ),
        (
            vec![
                "complete-order",
                "--order-id-hex=5555555555555555555555555555555555555555555555555555555555555555",
                "--order-id-hex=6666666666666666666666666666666666666666666666666666666666666666",
            ],
            "--order-id-hex",
        ),
    ] {
        let stderr = run_builder_failure(args.into_iter().map(str::to_owned));
        assert!(
            stderr.contains("cannot be used multiple times") && stderr.contains(expected),
            "stderr should reject duplicate {expected}, got: {stderr}"
        );
    }
}
fn instruction_command() -> assert_cmd::Command {
    let mut command = cargo_bin_cmd!("iroha");
    command.args(["app", "sorafs", "toolkit", "instruction"]);
    command
}

fn run_builder(args: impl IntoIterator<Item = String>) -> Value {
    let mut cmd = instruction_command();
    cmd.args(args);
    let output = cmd.assert().success().get_output().stdout.clone();
    json::from_slice(&output).expect("parse tx stdin json")
}
fn run_builder_failure(args: impl IntoIterator<Item = String>) -> String {
    let mut cmd = instruction_command();
    cmd.args(args);
    let assertion = cmd.assert().failure();
    assert!(
        assertion.get_output().stdout.is_empty(),
        "failed preparation must emit no instruction"
    );
    String::from_utf8(assertion.get_output().stderr.clone()).expect("stderr should be utf8")
}
fn decode_single_instruction(payload: &Value) -> InstructionBox {
    let entries = payload.as_array().expect("tx stdin array");
    assert_eq!(entries.len(), 1);
    let encoded = entries[0].as_str().expect("base64 instruction");
    let bytes = BASE64_STD
        .decode(encoded.as_bytes())
        .expect("decode instruction base64");
    decode_from_bytes(&bytes).expect("decode instruction")
}
fn sample_declaration() -> CapacityDeclarationV1 {
    CapacityDeclarationV1 {
        version: CAPACITY_DECLARATION_VERSION_V1,
        provider_id: [0x11; 32],
        stake: StakePointer {
            pool_id: [0x22; 32],
            stake_amount: "1".parse().expect("canonical XOR quantity"),
        },
        committed_capacity_gib: 1,
        chunker_commitments: vec![ChunkerCommitmentV1 {
            profile_id: "sorafs.sf1@1.0.0".to_owned(),
            profile_aliases: None,
            committed_gib: 1,
            capability_refs: vec![CapabilityType::ToriiGateway],
        }],
        lane_commitments: vec![LaneCommitmentV1 {
            lane_id: "global".to_owned(),
            max_gib: 1,
        }],
        pricing: None,
        valid_from: 1_700_000_000,
        valid_until: 1_700_086_400,
        metadata: vec![
            CapacityMetadataEntry {
                key: "sorafs.owner_account_id".to_owned(),
                value: "testuﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV".to_owned(),
            },
            CapacityMetadataEntry {
                key: "sorafs.storage_class".to_owned(),
                value: "hot".to_owned(),
            },
        ],
    }
}
fn sample_replication_order() -> ReplicationOrderV1 {
    ReplicationOrderV1 {
        version: REPLICATION_ORDER_VERSION_V1,
        order_id: [0x55; 32],
        manifest_cid: canonical_manifest_root_cid([0x77; 32]),
        manifest_digest: [0x66; 32],
        chunking_profile: "sorafs.sf1@1.0.0".to_owned(),
        target_replicas: 1,
        assignments: vec![ReplicationAssignmentV1 {
            provider_id: [0x11; 32],
            slice_gib: 1,
            lane: Some("global".to_owned()),
        }],
        issued_at: 1_700_000_000,
        deadline_at: 1_700_003_600,
        sla: ReplicationOrderSlaV1 {
            ingest_deadline_secs: 300,
            min_availability_percent_milli: 99_000,
            min_por_success_percent_milli: 99_000,
        },
        metadata: vec![CapacityMetadataEntry {
            key: "service".to_owned(),
            value: "ton-indexer".to_owned(),
        }],
    }
}

#[test]
fn instruction_output_is_config_free_and_exact_canonical_json() {
    let directory = tempdir().expect("empty working directory");
    let output = instruction_command()
        .current_dir(directory.path())
        .args([
            "expire-order",
            &format!("--order-id-hex={}", "55".repeat(32)),
            "--expiration-epoch=778",
        ])
        .output()
        .expect("run local instruction preparation");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let expected =
        InstructionBox::from(iroha_data_model::isi::sorafs::ExpireReplicationOrder::new(
            iroha_data_model::sorafs::pin_registry::ReplicationOrderId::new([0x55; 32]),
            778,
        ));
    let payload = Value::Array(vec![Value::String(
        BASE64_STD.encode(to_bytes(&expected).expect("canonical instruction")),
    )]);
    let rendered = format!("{}\n", json::to_string(&payload).expect("canonical JSON"));
    assert_eq!(output.stdout, rendered.as_bytes());
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("inspect working directory")
            .count(),
        0
    );
}

#[test]
fn instruction_help_lists_the_exact_operation_options_without_config() {
    let directory = tempdir().expect("empty working directory");
    for (operation, required) in [
        ("capacity-declaration", "--summary"),
        ("replication-order", "--musubi-archive-id-hex"),
        ("complete-order", "--signer-policy-predecessor-digest-hex"),
        ("expire-order", "--expiration-epoch"),
    ] {
        let output = instruction_command()
            .current_dir(directory.path())
            .args([operation, "--help"])
            .output()
            .expect("read operation help");
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let help = String::from_utf8(output.stdout).expect("UTF-8 help");
        assert!(help.contains("iroha app sorafs toolkit instruction"));
        assert!(help.contains(required), "{operation}: {help}");
    }
}

#[test]
fn completion_without_its_authority_context_is_rejected_before_output() {
    let output = instruction_command()
        .args([
            "complete-order",
            &format!("--order-id-hex={}", "55".repeat(32)),
            &format!("--provider-id-hex={}", "66".repeat(32)),
            "--completion-epoch=777",
        ])
        .output()
        .expect("reject incomplete completion");
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required arguments") && stderr.contains("--expected-owner"));
    let error: Value = json::from_slice(&output.stderr).expect("canonical CLI error JSON");
    assert_eq!(error["error"]["kind"].as_str(), Some("input"));
    assert_eq!(error["error"]["exit_code"].as_u64(), Some(4));
}
