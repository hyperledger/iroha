//! Artifact validation, canonical argument and cryptographic regression tests.

pub(super) fn parse_args<T: clap::Args>(args: &[String]) -> Result<T, CliError> {
    let command = T::augment_args(clap::Command::new("artifact"));
    let matches = command
        .try_get_matches_from(std::iter::once("artifact".to_owned()).chain(args.iter().cloned()))
        .map_err(|error| CliError::Config(error.to_string()))?;
    T::from_arg_matches(&matches).map_err(|error| CliError::Config(error.to_string()))
}
fn parse_command(args: impl IntoIterator<Item = String>) -> Result<Command, CliError> {
    let command =
        <Command as clap::Subcommand>::augment_subcommands(clap::Command::new("validate"));
    let matches = command
        .try_get_matches_from(std::iter::once("validate".to_owned()).chain(args))
        .map_err(|error| CliError::Config(error.to_string()))?;
    <Command as clap::FromArgMatches>::from_arg_matches(&matches)
        .map_err(|error| CliError::Config(error.to_string()))
}
use super::*;
fn workspace_fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}
#[test]
fn output_format_parse_accepts_supported_values() {
    assert!(matches!(
        OutputFormat::parse("json"),
        Ok(OutputFormat::Json)
    ));
    assert!(matches!(
        OutputFormat::parse("table"),
        Ok(OutputFormat::Table)
    ));
    assert!(matches!(
        OutputFormat::parse("yaml"),
        Ok(OutputFormat::Yaml)
    ));
}
#[test]
fn output_format_parse_rejects_unknown_values() {
    assert!(matches!(
        OutputFormat::parse("xml"),
        Err(CliError::Config(message)) if message.contains("unsupported --format")
    ));
}
#[test]
fn bounded_cli_reader_accepts_boundary_and_rejects_one_over() {
    let directory = tempfile::tempdir().expect("temporary input directory");
    let path = directory.path().join("provider-advert.to");
    fs::write(&path, vec![0xA5; PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1])
        .expect("write exact-boundary input");
    assert_eq!(
        read_cli_bytes_bounded(&path, PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1)
            .expect("exact input boundary"),
        vec![0xA5; PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1]
    );
    fs::write(
        &path,
        vec![0xA5; PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1 + 1],
    )
    .expect("write one-over input");
    assert!(matches!(
        read_cli_bytes_bounded(&path, PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1),
        Err(CliError::Validation(message)) if message.contains("input ceiling")
    ));
}
#[test]
fn bounded_orderbook_cli_reader_accepts_boundary_and_rejects_one_over() {
    let directory = tempfile::tempdir().expect("temporary input directory");
    let path = directory.path().join("orderbook.to");
    fs::write(&path, vec![0xA5; ORDERBOOK_PAYLOAD_MAX_CANONICAL_BYTES_V1])
        .expect("write exact-boundary orderbook input");
    assert_eq!(
        read_cli_bytes_bounded(&path, ORDERBOOK_PAYLOAD_MAX_CANONICAL_BYTES_V1)
            .expect("exact orderbook input boundary")
            .len(),
        ORDERBOOK_PAYLOAD_MAX_CANONICAL_BYTES_V1
    );
    fs::write(
        &path,
        vec![0xA5; ORDERBOOK_PAYLOAD_MAX_CANONICAL_BYTES_V1 + 1],
    )
    .expect("write one-over orderbook input");
    assert!(matches!(
        read_cli_bytes_bounded(&path, ORDERBOOK_PAYLOAD_MAX_CANONICAL_BYTES_V1),
        Err(CliError::Validation(message)) if message.contains("input ceiling")
    ));
}
#[test]
fn parse_u64_flag_rejects_noncanonical_values() {
    assert_eq!(parse_u64_flag("0", "--now").expect("canonical zero"), 0);
    assert_eq!(
        parse_u64_flag("1700000000", "--generated-at").expect("canonical timestamp"),
        1_700_000_000
    );
    for value in ["", " 1", "1 ", "+1", "-1", "01", "1_000", "0x10"] {
        assert!(matches!(
            parse_u64_flag(value, "--now"),
            Err(CliError::Config(message))
                if message.contains("canonical unsigned decimal")
        ));
    }
}
#[test]
fn advert_args_parse_reads_input_format_and_timestamps() {
    let args = [
        "--input=advert.to".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--now=5".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<AdvertArgs>(&args).expect("parse args");
    assert_eq!(parsed.input, Some(PathBuf::from("advert.to")));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.now, Some(5));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn admission_args_parse_reads_input_format_and_generated_at() {
    let args = [
        "--input=envelope.to".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<AdmissionArgs>(&args).expect("parse args");
    assert_eq!(parsed.input, Some(PathBuf::from("envelope.to")));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn admission_args_parse_rejects_envelope_alias() {
    let args = ["--envelope=envelope.to".to_owned()];
    assert!(matches!(
        parse_args::<AdmissionArgs>(&args),
        Err(CliError::Config(message)) if message.contains("unexpected argument")
    ));
}
#[test]
fn admission_args_parse_reads_renewal_and_revocation_flags() {
    let args = [
        "--input=envelope.to".to_owned(),
        "--renewal=renewal.to".to_owned(),
    ];
    let parsed = parse_args::<AdmissionArgs>(&args).expect("parse renewal args");
    assert_eq!(parsed.input, Some(PathBuf::from("envelope.to")));
    assert_eq!(parsed.renewal, Some(PathBuf::from("renewal.to")));
    assert_eq!(parsed.revocation, None);
    let args = [
        "--input=envelope.to".to_owned(),
        "--revocation=revocation.to".to_owned(),
    ];
    let parsed = parse_args::<AdmissionArgs>(&args).expect("parse revocation args");
    assert_eq!(parsed.input, Some(PathBuf::from("envelope.to")));
    assert_eq!(parsed.renewal, None);
    assert_eq!(parsed.revocation, Some(PathBuf::from("revocation.to")));
}
#[test]
fn admission_args_parse_rejects_renewal_revocation_conflict() {
    let args = [
        "--input=envelope.to".to_owned(),
        "--renewal=renewal.to".to_owned(),
        "--revocation=revocation.to".to_owned(),
    ];
    assert!(matches!(
        parse_args::<AdmissionArgs>(&args),
        Err(CliError::Config(message))
            if message.contains("cannot be used with")
    ));
}
#[test]
fn por_args_parse_reads_inputs_format_and_generated_at() {
    let args = [
        "--challenge=challenge.to".to_owned(),
        "--proof=proof.to".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<PorArgs>(&args).expect("parse args");
    assert_eq!(parsed.challenge, Some(PathBuf::from("challenge.to")));
    assert_eq!(parsed.proof, Some(PathBuf::from("proof.to")));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn pdp_args_parse_reads_inputs_format_and_generated_at() {
    let args = [
        "--commitment=commitment.to".to_owned(),
        "--challenge=challenge.to".to_owned(),
        "--proof=proof.to".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<PdpArgs>(&args).expect("parse args");
    assert_eq!(parsed.commitment, Some(PathBuf::from("commitment.to")));
    assert_eq!(parsed.challenge, Some(PathBuf::from("challenge.to")));
    assert_eq!(parsed.proof, Some(PathBuf::from("proof.to")));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn potr_args_parse_reads_receipt_profile_format_and_generated_at() {
    let args = [
        "--receipt=receipt.to".to_owned(),
        "--profile=archive".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<PotrArgs>(&args).expect("parse args");
    assert_eq!(parsed.receipt, Some(PathBuf::from("receipt.to")));
    assert!(matches!(parsed.profile, Some(ProofStreamTier::Archive)));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn bundle_args_parse_reads_directory_format_and_timestamps() {
    let args = [
        "--bundle=fixtures/sorafs_manifest".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--now=5".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<BundleArgs>(&args).expect("parse args");
    assert_eq!(
        parsed.bundle,
        Some(PathBuf::from("fixtures/sorafs_manifest"))
    );
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.now, Some(5));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn governance_args_parse_reads_node_cid_format_and_generated_at() {
    let cid = format!("hex:{}", "a5".repeat(32));
    let args = [
        "--node=governance.to".to_owned(),
        format!("--cid={cid}"),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<GovernanceArgs>(&args)
        .map(GovernanceArgs::normalize)
        .expect("parse args");
    assert_eq!(parsed.node, Some(PathBuf::from("governance.to")));
    assert_eq!(parsed.cid.as_deref(), Some(cid.as_str()));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn governance_args_parse_rejects_input_alias() {
    assert!(matches!(
        parse_args::<GovernanceArgs>(&["--input=governance.to".to_owned()]),
        Err(CliError::Config(message)) if message.contains("unexpected argument")
    ));
}
#[test]
fn governance_args_parse_reads_head_and_block_chain() {
    let args = [
        "--block=block-0.to".to_owned(),
        "--head=head.to".to_owned(),
        "--block=block-1.to".to_owned(),
        "--format=json".to_owned(),
    ];
    let parsed = parse_args::<GovernanceArgs>(&args)
        .map(GovernanceArgs::normalize)
        .expect("parse args");
    assert_eq!(parsed.node, None);
    assert_eq!(parsed.block, None);
    assert_eq!(parsed.head, Some(PathBuf::from("head.to")));
    assert_eq!(
        parsed.blocks,
        vec![PathBuf::from("block-0.to"), PathBuf::from("block-1.to")]
    );
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
}
#[test]
fn parse_cid_arg_bytes_accepts_exact_prefixed_and_bare_hex_cids() {
    let expected = vec![0x0A; 32];
    let hex_cid = "0a".repeat(32);
    assert_eq!(
        parse_cid_arg_bytes(&format!("hex:{hex_cid}")).expect("parse prefixed hex"),
        expected
    );
    assert_eq!(
        parse_cid_arg_bytes(&hex_cid).expect("parse bare hex"),
        expected
    );
}
#[test]
fn sign_args_parse_reads_advert_signing_flags() {
    let args = [
        "--kind=advert".to_owned(),
        "--payload-kind=order-request".to_owned(),
        "--input=advert.to".to_owned(),
        "--out=signed-advert.to".to_owned(),
        "--key-hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--now=5".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<SignArgs>(&args).expect("parse args");
    assert!(matches!(parsed.kind, Some(SignKind::Advert)));
    assert_eq!(
        parsed.payload_kind,
        Some(OrderbookValidationPayloadKindV1::OrderRequest)
    );
    assert_eq!(parsed.input, Some(PathBuf::from("advert.to")));
    assert_eq!(parsed.out, Some(PathBuf::from("signed-advert.to")));
    assert_eq!(
        parsed.key_hex.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.now, Some(5));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn parse_sign_kind_accepts_only_exact_v1_names() {
    assert_eq!(parse_sign_kind("advert").unwrap(), SignKind::Advert);
    assert_eq!(parse_sign_kind("order").unwrap(), SignKind::Order);
    assert_eq!(parse_sign_kind("orderbook").unwrap(), SignKind::Orderbook);
    assert_eq!(parse_sign_kind("governance").unwrap(), SignKind::Governance);
    for alias in [
        "provider-advert",
        "replication-order",
        "orderbook-payload",
        "governance-log-node",
        "Advert",
        " advert",
    ] {
        assert!(parse_sign_kind(alias).is_err());
    }
}
#[test]
fn parse_orderbook_sign_kind_accepts_only_signable_payloads() {
    assert_eq!(
        parse_orderbook_sign_kind("order-request").unwrap(),
        OrderbookValidationPayloadKindV1::OrderRequest
    );
    assert_eq!(
        parse_orderbook_sign_kind("order-cancel").unwrap(),
        OrderbookValidationPayloadKindV1::OrderCancel
    );
    assert_eq!(
        parse_orderbook_sign_kind("settlement-receipt").unwrap(),
        OrderbookValidationPayloadKindV1::SettlementReceipt
    );
    assert!(matches!(
        parse_orderbook_sign_kind("trade-event"),
        Err(CliError::Config(message)) if message.contains("expected order-request")
    ));
}
#[test]
fn parse_ed25519_seed_hex_accepts_canonical_lowercase_hex() {
    let seed = parse_ed25519_seed_hex(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--key-hex",
    )
    .expect("parse seed");
    assert_eq!(seed, [0xAA; 32]);
}
#[test]
fn parse_ed25519_seed_hex_rejects_wrong_length() {
    assert!(matches!(
        parse_ed25519_seed_hex("abcd", "--key-hex"),
        Err(CliError::Config(message)) if message.contains("lowercase hex")
    ));
}
#[test]
fn parse_ed25519_seed_hex_rejects_noncanonical_text() {
    for value in [
        "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
        " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    ] {
        assert!(matches!(
            parse_ed25519_seed_hex(value, "--key-hex"),
            Err(CliError::Config(message)) if message.contains("lowercase hex")
        ));
    }
}
#[test]
fn parse_ed25519_seed_hex_rejects_all_zero_seed_material() {
    assert!(matches!(
        parse_ed25519_seed_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--key-hex"
        ),
        Err(CliError::Config(message)) if message.contains("must not be all zero")
    ));
}
#[test]
fn read_signing_seed_accepts_key_hex_and_rejects_conflicts() {
    let parsed = SignArgs {
        key_hex: Some(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ),
        ..SignArgs::default()
    };
    assert_eq!(read_signing_seed(&parsed).unwrap(), [0xAA; 32]);
    let conflict = SignArgs {
        key_hex: Some(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ),
        key: Some(PathBuf::from("key.hex")),
        ..SignArgs::default()
    };
    assert!(matches!(
        read_signing_seed(&conflict),
        Err(CliError::Config(message)) if message.contains("either --key-hex or --key")
    ));
}
#[test]
fn sign_provider_advert_replaces_signature_with_verified_ed25519_signature() {
    let fixture = workspace_fixture("fixtures/sorafs_manifest/provider_admission/advert_v1.to");
    let bytes = fs::read(fixture).expect("read advert fixture");
    let mut advert: ProviderAdvertV1 =
        norito::decode_from_bytes(&bytes).expect("decode advert fixture");
    let original_public_key = advert.signature.public_key.clone();
    let seed = [0xA5; 32];
    sign_provider_advert(&mut advert, &seed).expect("sign advert");
    let expected_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    assert_eq!(advert.signature.public_key, expected_key.to_vec());
    assert_ne!(advert.signature.public_key, original_public_key);
    assert!(advert.signature_strict);
    advert.verify_signature().expect("signed advert verifies");
}
#[test]
fn sign_replication_order_returns_verified_ed25519_envelope() {
    let fixture = workspace_fixture("fixtures/sorafs_manifest/replication_order/order_v1.to");
    let bytes = fs::read(fixture).expect("read order fixture");
    let order: ReplicationOrderV1 =
        norito::decode_from_bytes(&bytes).expect("decode order fixture");
    let seed = [0xA7; 32];
    let signed_order = sign_replication_order(order.clone(), &seed).expect("sign order");
    let expected_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    assert_eq!(signed_order.version, SIGNED_REPLICATION_ORDER_VERSION_V1);
    assert_eq!(signed_order.order, order);
    assert_eq!(signed_order.signature.public_key, expected_key.to_vec());
    assert_eq!(
        signed_order.signature.algorithm,
        SignatureAlgorithm::Ed25519
    );
    signed_order
        .verify_signature()
        .expect("signed replication order verifies");
}
#[test]
fn sign_orderbook_payload_bytes_returns_verified_signed_payloads() {
    let seed = [0xB7; 32];
    let expected_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let cases = [
        (
            OrderbookValidationPayloadKindV1::OrderRequest,
            "fixtures/sorafs_manifest/orderbook/order_request_v1.to",
        ),
        (
            OrderbookValidationPayloadKindV1::OrderCancel,
            "fixtures/sorafs_manifest/orderbook/order_cancel_v1.to",
        ),
        (
            OrderbookValidationPayloadKindV1::SettlementReceipt,
            "fixtures/sorafs_manifest/orderbook/settlement_receipt_v1.to",
        ),
    ];
    for (kind, fixture_path) in cases {
        let fixture = workspace_fixture(fixture_path);
        let bytes = fs::read(fixture).expect("read orderbook fixture");
        let signed =
            sign_orderbook_payload_bytes(kind, &bytes, &seed).expect("sign orderbook payload");
        let outcome = validate_orderbook_payload_bytes(kind, &signed, "signed.to".to_owned(), 123);
        assert!(outcome.is_ok(), "{kind:?} failed: {outcome:?}");
        assert_eq!(
            orderbook_payload_public_key(kind, &signed).expect("signed public key"),
            expected_key.to_vec()
        );
    }
}
#[test]
fn sign_governance_log_node_replaces_signature_with_verified_ed25519_signature() {
    let fixture = workspace_fixture("fixtures/sorafs_manifest/governance/node_v1.to");
    let bytes = fs::read(fixture).expect("read governance fixture");
    let mut node: GovernanceLogNodeV1 =
        norito::decode_from_bytes(&bytes).expect("decode governance fixture");
    let original_public_key = node.publisher_signature.public_key.clone();
    let seed = [0xA6; 32];
    sign_governance_log_node(&mut node, &seed).expect("sign governance node");
    let expected_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    assert_eq!(node.publisher_signature.public_key, expected_key.to_vec());
    assert_ne!(node.publisher_signature.public_key, original_public_key);
    node.verify_publisher_signature()
        .expect("signed governance node verifies");
}
#[test]
fn parse_profile_accepts_only_exact_v1_names() {
    assert!(matches!(parse_profile("hot"), Ok(ProofStreamTier::Hot)));
    assert!(matches!(parse_profile("warm"), Ok(ProofStreamTier::Warm)));
    assert!(matches!(
        parse_profile("archive"),
        Ok(ProofStreamTier::Archive)
    ));
    for alias in ["cold", "Archive", " archive"] {
        assert!(parse_profile(alias).is_err());
    }
}
#[test]
fn repair_args_parse_reads_kind_input_format_and_generated_at() {
    let args = [
        "--kind=task".to_owned(),
        "--input=repair-task.to".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<RepairArgs>(&args).expect("parse args");
    assert_eq!(parsed.input, Some(PathBuf::from("repair-task.to")));
    assert!(matches!(
        parsed.kind,
        Some(RepairValidationPayloadKindV1::TaskRecord)
    ));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn repair_args_parse_rejects_payload_flag_aliases() {
    for flag in [
        "--task=payload.to",
        "--evidence=payload.to",
        "--report=payload.to",
        "--slash-proposal=payload.to",
        "--policy=payload.to",
        "--approval=payload.to",
        "--event=payload.to",
        "--audit-event=payload.to",
    ] {
        assert!(matches!(
            parse_args::<RepairArgs>(&[flag.to_owned()]),
            Err(CliError::Config(message)) if message.contains("unexpected argument")
        ));
    }
}
#[test]
fn parse_repair_kind_accepts_only_exact_v1_names() {
    assert!(matches!(
        parse_repair_kind("task"),
        Ok(RepairValidationPayloadKindV1::TaskRecord)
    ));
    assert!(matches!(
        parse_repair_kind("evidence"),
        Ok(RepairValidationPayloadKindV1::Evidence)
    ));
    assert!(matches!(
        parse_repair_kind("report"),
        Ok(RepairValidationPayloadKindV1::Report)
    ));
    assert!(matches!(
        parse_repair_kind("slash-proposal"),
        Ok(RepairValidationPayloadKindV1::SlashProposal)
    ));
    assert!(matches!(
        parse_repair_kind("policy"),
        Ok(RepairValidationPayloadKindV1::EscalationPolicy)
    ));
    assert!(matches!(
        parse_repair_kind("approval"),
        Ok(RepairValidationPayloadKindV1::EscalationApproval)
    ));
    assert!(matches!(
        parse_repair_kind("event"),
        Ok(RepairValidationPayloadKindV1::TaskEvent)
    ));
    assert!(matches!(
        parse_repair_kind("audit-event"),
        Ok(RepairValidationPayloadKindV1::AuditEvent)
    ));
    for alias in [
        "task-record",
        "repair-task",
        "repair-evidence",
        "slash",
        "escalation-policy",
        "repair-audit-event",
        "Task",
        " task",
    ] {
        assert!(parse_repair_kind(alias).is_err());
    }
}
#[test]
fn repair_cli_rejects_retired_envelope_and_worker_aliases() {
    for kind in [
        "signed-auditor",
        "signed-auditor-request",
        "worker",
        "worker-signature",
        "worker-signature-payload",
    ] {
        assert!(
            matches!(parse_repair_kind(kind), Err(CliError::Config(_))),
            "retired repair kind alias {kind} must be rejected"
        );
    }
    for flag in [
        "--signed-auditor-request=retired.to",
        "--signed-auditor=retired.to",
        "--worker-signature=retired.to",
    ] {
        assert!(
            matches!(
                parse_args::<RepairArgs>(&[flag.to_owned()]),
                Err(CliError::Config(message)) if message.contains("unexpected argument")
            ),
            "retired repair payload flag {flag} must be rejected"
        );
    }
}
#[test]
fn pop_cli_reads_regular_canonical_input() {
    let directory = tempfile::tempdir().expect("temporary PoP input directory");
    let input = directory.path().join("enrollment.to");
    let payload = sorafs_manifest::PopEnrollmentRequestV1 {
        version: sorafs_manifest::POP_ENROLLMENT_REQUEST_VERSION_V1,
        request_id: [0x21; 32],
        applicant_id: "fixture-applicant".to_owned(),
        requested_class: sorafs_manifest::PopEligibilityClassV1::General,
        requested_attributes: vec!["residency".to_owned()],
        attestation_digest: [0x22; 32],
        submitted_at_epoch: 100,
        expires_at_epoch: 200,
    };
    let bytes = norito::encode_canonical(&payload).expect("canonical enrollment fixture");
    fs::write(&input, &bytes).expect("write regular PoP input");
    assert_eq!(
        read_cli_bytes_bounded(&input, POP_REFERENCE_PAYLOAD_MAX_BYTES_V1).unwrap(),
        bytes
    );
    assert_eq!(
        run_pop(PopArgs {
            input: Some(input),
            kind: Some(PopValidationPayloadKindV1::EnrollmentRequest),
            format: Some(OutputFormat::Json),
            generated_at: Some(123),
            ..PopArgs::default()
        })
        .expect("bounded regular PoP input validates"),
        ExitCode::SUCCESS
    );
}
#[test]
fn pop_cli_rejects_oversized_input_before_decode() {
    let directory = tempfile::tempdir().expect("temporary PoP input directory");
    let input = directory.path().join("oversized.to");
    fs::File::create(&input)
        .unwrap()
        .set_len(POP_REFERENCE_PAYLOAD_MAX_BYTES_V1 as u64 + 1)
        .unwrap();
    let expected = format!(
        "{} exceeds the {POP_REFERENCE_PAYLOAD_MAX_BYTES_V1}-byte input ceiling",
        input.display()
    );
    assert!(matches!(
        run_pop(PopArgs {
            input: Some(input),
            kind: Some(PopValidationPayloadKindV1::MembershipProof),
            generated_at: Some(123),
            ..PopArgs::default()
        }),
        Err(CliError::Validation(message)) if message == expected
    ));
}
#[cfg(unix)]
#[test]
fn pop_cli_rejects_symbolic_link_input_before_decode() {
    let directory = tempfile::tempdir().expect("temporary PoP input directory");
    let target = directory.path().join("target.to");
    let input = directory.path().join("link.to");
    fs::write(&target, b"not a proof").unwrap();
    std::os::unix::fs::symlink(&target, &input).unwrap();
    let expected = format!("failed to open {}:", input.display());
    assert!(matches!(
        run_pop(PopArgs {
            input: Some(input),
            kind: Some(PopValidationPayloadKindV1::MembershipProof),
            generated_at: Some(123),
            ..PopArgs::default()
        }),
        Err(CliError::Io(message)) if message.starts_with(&expected)
    ));
}
#[test]
fn pop_args_parse_reads_kind_input_format_and_generated_at() {
    let args = [
        "--kind=credential".to_owned(),
        "--input=pop-credential.to".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<PopArgs>(&args).expect("parse args");
    assert_eq!(parsed.input, Some(PathBuf::from("pop-credential.to")));
    assert!(matches!(
        parsed.kind,
        Some(PopValidationPayloadKindV1::Credential)
    ));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn pop_args_parse_rejects_payload_flag_aliases() {
    for flag in [
        "--credential=payload.to",
        "--root=payload.to",
        "--commitment-root=payload.to",
        "--revocations=payload.to",
        "--revocation-list=payload.to",
        "--issued-bundle=payload.to",
        "--issued-credential-bundle=payload.to",
        "--enrollment=payload.to",
        "--enrollment-request=payload.to",
        "--renewal=payload.to",
        "--renewal-request=payload.to",
        "--proof=payload.to",
        "--membership-proof=payload.to",
    ] {
        assert!(matches!(
            parse_args::<PopArgs>(&[flag.to_owned()]),
            Err(CliError::Config(message)) if message.contains("unexpected argument")
        ));
    }
}
#[test]
fn parse_pop_kind_accepts_only_exact_v1_names() {
    assert!(matches!(
        parse_pop_kind("credential"),
        Ok(PopValidationPayloadKindV1::Credential)
    ));
    assert!(matches!(
        parse_pop_kind("commitment-root"),
        Ok(PopValidationPayloadKindV1::CommitmentRoot)
    ));
    assert!(matches!(
        parse_pop_kind("revocation-list"),
        Ok(PopValidationPayloadKindV1::RevocationList)
    ));
    assert!(matches!(
        parse_pop_kind("issued-credential-bundle"),
        Ok(PopValidationPayloadKindV1::IssuedCredentialBundle)
    ));
    assert!(matches!(
        parse_pop_kind("enrollment-request"),
        Ok(PopValidationPayloadKindV1::EnrollmentRequest)
    ));
    assert!(matches!(
        parse_pop_kind("renewal-request"),
        Ok(PopValidationPayloadKindV1::RenewalRequest)
    ));
    assert!(matches!(
        parse_pop_kind("membership-proof"),
        Ok(PopValidationPayloadKindV1::MembershipProof)
    ));
    for alias in [
        "pop-credential",
        "root",
        "pop-root",
        "revocations",
        "issued-bundle",
        "enrollment",
        "renewal",
        "proof",
        "Credential",
        " credential",
    ] {
        assert!(parse_pop_kind(alias).is_err());
    }
}
#[test]
fn hedging_args_parse_reads_kind_input_format_and_generated_at() {
    let args = [
        "--kind=billing-statement".to_owned(),
        "--input=statement.to".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<HedgingArgs>(&args).expect("parse args");
    assert_eq!(parsed.input, Some(PathBuf::from("statement.to")));
    assert!(matches!(
        parsed.kind,
        Some(HedgingValidationPayloadKindV1::BillingStatement)
    ));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn hedging_args_parse_rejects_payload_flag_aliases() {
    for flag in [
        "--feed=payload.to",
        "--price-feed=payload.to",
        "--decision=payload.to",
        "--reference-price=payload.to",
        "--reference-price-decision=payload.to",
        "--line=payload.to",
        "--line-item=payload.to",
        "--billing-line=payload.to",
        "--statement=payload.to",
        "--billing-statement=payload.to",
    ] {
        assert!(matches!(
            parse_args::<HedgingArgs>(&[flag.to_owned()]),
            Err(CliError::Config(message)) if message.contains("unexpected argument")
        ));
    }
    assert!(matches!(
        parse_command(["billing".to_owned()]),
        Err(CliError::Config(message)) if message.contains("unrecognized subcommand")
    ));
}
#[test]
fn parse_hedging_kind_accepts_only_exact_v1_names() {
    assert!(matches!(
        parse_hedging_kind("price-feed"),
        Ok(HedgingValidationPayloadKindV1::PriceFeed)
    ));
    assert!(matches!(
        parse_hedging_kind("reference-price-decision"),
        Ok(HedgingValidationPayloadKindV1::ReferencePriceDecision)
    ));
    assert!(matches!(
        parse_hedging_kind("billing-line-item"),
        Ok(HedgingValidationPayloadKindV1::BillingLineItem)
    ));
    assert!(matches!(
        parse_hedging_kind("billing-statement"),
        Ok(HedgingValidationPayloadKindV1::BillingStatement)
    ));
    for alias in [
        "feed",
        "hedging-price-feed",
        "decision",
        "reference-price",
        "line",
        "line-item",
        "billing-line",
        "statement",
        "Price-Feed",
        " price-feed",
    ] {
        assert!(parse_hedging_kind(alias).is_err());
    }
}
#[test]
fn orderbook_args_parse_reads_kind_input_format_and_generated_at() {
    let args = [
        "--kind=settlement-receipt".to_owned(),
        "--input=receipt.to".to_owned(),
        "--format=json".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<OrderbookArgs>(&args).expect("parse args");
    assert_eq!(parsed.input, Some(PathBuf::from("receipt.to")));
    assert!(matches!(
        parsed.kind,
        Some(OrderbookValidationPayloadKindV1::SettlementReceipt)
    ));
    assert!(matches!(parsed.format, Some(OutputFormat::Json)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn orderbook_args_parse_rejects_payload_flag_aliases() {
    for flag in [
        "--order=payload.to",
        "--order-request=payload.to",
        "--cancel=payload.to",
        "--order-cancel=payload.to",
        "--trade=payload.to",
        "--trade-event=payload.to",
        "--channel=payload.to",
        "--settlement-channel=payload.to",
        "--receipt=payload.to",
        "--settlement-receipt=payload.to",
        "--runtime-snapshot=payload.to",
    ] {
        assert!(matches!(
            parse_args::<OrderbookArgs>(&[flag.to_owned()]),
            Err(CliError::Config(message)) if message.contains("unexpected argument")
        ));
    }
}
#[test]
fn parse_orderbook_kind_accepts_only_exact_v1_names() {
    assert!(matches!(
        parse_orderbook_kind("order-request"),
        Ok(OrderbookValidationPayloadKindV1::OrderRequest)
    ));
    assert!(matches!(
        parse_orderbook_kind("order-cancel"),
        Ok(OrderbookValidationPayloadKindV1::OrderCancel)
    ));
    assert!(matches!(
        parse_orderbook_kind("trade-event"),
        Ok(OrderbookValidationPayloadKindV1::TradeEvent)
    ));
    assert!(matches!(
        parse_orderbook_kind("settlement-channel"),
        Ok(OrderbookValidationPayloadKindV1::SettlementChannel)
    ));
    assert!(matches!(
        parse_orderbook_kind("settlement-receipt"),
        Ok(OrderbookValidationPayloadKindV1::SettlementReceipt)
    ));
    for alias in [
        "order",
        "request",
        "cancel",
        "cancel-request",
        "trade",
        "channel",
        "receipt",
        "runtime-snapshot",
        "Order-Request",
        " order-request",
    ] {
        assert!(parse_orderbook_kind(alias).is_err());
    }
}
#[test]
fn order_args_parse_reads_order_format_and_generated_at() {
    let args = [
        "--order=order.to".to_owned(),
        "--format=yaml".to_owned(),
        "--telemetry-out=out.json".to_owned(),
        "--generated-at=6".to_owned(),
    ];
    let parsed = parse_args::<OrderArgs>(&args)
        .map(OrderArgs::normalize)
        .expect("parse args");
    assert_eq!(parsed.order, Some(PathBuf::from("order.to")));
    assert!(!parsed.signed);
    assert!(matches!(parsed.format, Some(OutputFormat::Yaml)));
    assert_eq!(parsed.telemetry_out, Some(PathBuf::from("out.json")));
    assert_eq!(parsed.generated_at, Some(6));
}
#[test]
fn order_args_parse_rejects_input_alias() {
    let args = ["--input=order.to".to_owned()];
    assert!(matches!(
        parse_args::<OrderArgs>(&args),
        Err(CliError::Config(message)) if message.contains("unexpected argument")
    ));
}
#[test]
fn order_args_parse_reads_signed_order_input() {
    let args = ["--signed-order=signed-order.to".to_owned()];
    let parsed = parse_args::<OrderArgs>(&args)
        .map(OrderArgs::normalize)
        .expect("parse args");
    assert_eq!(parsed.order, Some(PathBuf::from("signed-order.to")));
    assert!(parsed.signed);
}
#[test]
fn order_args_parse_rejects_multiple_inputs() {
    let args = [
        "--order=order.to".to_owned(),
        "--signed-order=signed-order.to".to_owned(),
    ];
    assert!(matches!(
        parse_args::<OrderArgs>(&args),
        Err(CliError::Config(message)) if message.contains("cannot be used with")
    ));
}
#[test]
fn cli_error_exit_code_matches_contract() {
    assert_eq!(CliError::Config("x".to_owned()).exit_code(), 4);
    assert_eq!(CliError::Io("x".to_owned()).exit_code(), 3);
    assert_eq!(CliError::Internal("x".to_owned()).exit_code(), 10);
}
#[test]
fn yaml_string_quotes_control_characters() {
    assert_eq!(yaml_string("a\n\"b\""), "\"a\\n\\\"b\\\"\"");
}

#[test]
fn canonical_toolkit_clap_tree_owns_all_artifact_operations() {
    use clap::Parser as _;
    for operation in [
        "advert",
        "admission",
        "order",
        "orderbook",
        "pdp",
        "pop",
        "hedging",
        "por",
        "potr",
        "repair",
        "bundle",
        "governance",
    ] {
        let parsed = crate::Args::try_parse_from([
            "iroha", "app", "sorafs", "toolkit", "validate", operation,
        ])
        .expect("canonical artifact command");
        let crate::Command::App(crate::app::Command::Sorafs(
            crate::commands::sorafs::Command::Toolkit(command),
        )) = parsed.command
        else {
            panic!("expected local toolkit operation")
        };
        assert!(command.is_artifact_tool());
    }
    for operation in ["sign", "release-manifest", "release-manifest-receipt"] {
        let error =
            crate::Args::try_parse_from(["iroha", "app", "sorafs", "toolkit", operation, "--help"])
                .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    }
    assert!(crate::Args::try_parse_from(["iroha", "app", "sorafs", "toolkit", "advert"]).is_err());
}

#[test]
fn typed_artifact_options_reject_duplicates_and_empty_values() {
    for args in [
        vec!["--input=a", "--input=b"],
        vec!["--input="],
        vec!["--now=01"],
        vec!["--generated-at=+1"],
    ] {
        let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert!(parse_args::<AdvertArgs>(&args).is_err());
    }
    for args in [
        vec!["--manifest=a", "--manifest=b"],
        vec!["--development-local-signing", "--development-local-signing"],
        vec!["--public-key-fingerprint="],
    ] {
        let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert!(parse_args::<ReleaseManifestArgs>(&args).is_err());
    }
    let parsed = parse_args::<GovernanceArgs>(&["--block=first".into(), "--block=second".into()])
        .unwrap()
        .normalize();
    assert_eq!(parsed.block, Some(PathBuf::from("first")));
    assert_eq!(parsed.blocks, [PathBuf::from("second")]);
}
