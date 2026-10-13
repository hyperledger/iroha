include!("../../sorafs_nonce_rng_tests.rs");
test_items! {
    fn persisted_guard_cache_requires_a_key_and_enforces_the_file_bound() {
        let temporary = TempDir::new().expect("temporary directory");
        let cache = temporary.path().join("guards.norito");
        let missing_key = load_guard_set(&cache, None)
            .expect_err("configured cache without a key must fail closed");
        assert!(missing_key.to_string().contains("authentication key is required"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::write(&cache, vec![0_u8; GUARD_CACHE_MAX_BYTES_V1 + 1])
                .expect("write oversized guard cache");
            fs::set_permissions(&cache, fs::Permissions::from_mode(0o600))
                .expect("make oversized cache owner-private");
            let key =
                GuardCacheKey::from_bytes([0x6D; 32]).expect("non-zero guard cache key");
            let oversized = load_guard_set(&cache, Some(&key))
                .expect_err("oversized guard cache must fail before decode");
            assert!(oversized.to_string().contains("must contain between 1 and"));
        }

        let unsigned_write = persist_guard_set(&cache, &GuardSet::new(Vec::new()), None)
            .expect_err("unsigned guard cache persistence must be unavailable");
        assert!(
            unsigned_write
                .to_string()
                .contains("authentication key is required")
        );
    }

    fn guard_cache_cli_requires_a_current_directory() {
        use clap::Parser as _;

        #[allow(dead_code)]
        #[derive(clap::Parser, Debug)]
        struct Parser {
            #[command(flatten)]
            fetch: FetchArgs,
        }

        let error = Parser::try_parse_from([
            "sorafs-fetch-test",
            "--manifest",
            "manifest.to",
            "--plan",
            "plan.json",
            "--manifest-id",
            "00",
            "--gateway-provider",
            "name=relay",
            "--guard-cache",
            "guards.norito",
            "--guard-cache-key-file",
            "guard-cache.key",
        ])
        .expect_err("a persisted guard cache without a current directory must be rejected");
        assert!(error.to_string().contains("--guard-directory"));

        let raw_key = "11".repeat(32);
        let raw_error = Parser::try_parse_from([
            "sorafs-fetch-test",
            "--manifest",
            "manifest.to",
            "--plan",
            "plan.json",
            "--manifest-id",
            "00",
            "--gateway-provider",
            "name=relay",
            "--guard-cache-key",
            raw_key.as_str(),
        ])
        .expect_err("raw guard-cache key material must not be accepted on argv");
        assert!(raw_error.to_string().contains("--guard-cache-key"));
    }

    #[cfg(unix)]
    fn guard_cache_key_file_is_exact_raw_and_owner_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TempDir::new().expect("temporary directory");
        let key_path = temporary.path().join("guard-cache.key");
        fs::write(&key_path, [0x6D; GuardCacheKey::LENGTH]).expect("write raw key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("make raw key owner-private");
        let loaded = load_guard_cache_key_file(&key_path).expect("load raw key");
        let guards = GuardSet::new(Vec::new());
        let encoded = guards
            .encode_authenticated(&loaded)
            .expect("authenticate cache with loaded key");
        let expected = GuardCacheKey::from_bytes([0x6D; GuardCacheKey::LENGTH])
            .expect("fixture key");
        GuardSet::decode_authenticated(&encoded, &expected)
            .expect("loaded key must contain the exact raw bytes");

        fs::write(&key_path, "6d".repeat(GuardCacheKey::LENGTH))
            .expect("replace with argv-style hex text");
        assert!(load_guard_cache_key_file(&key_path).is_err());
        fs::write(&key_path, [0x6D; GuardCacheKey::LENGTH]).expect("restore raw key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))
            .expect("make key permissive");
        assert!(load_guard_cache_key_file(&key_path).is_err());
    }

    fn ordinary_proxy_manifest_summary_never_serialises_the_client_capability() {
        let secret = "11".repeat(32);
        let manifest_json = format!(
            r#"{{"version":2,"authority":"127.0.0.1:9443","certificate_pem":"test","client_capability_hex":"{secret}"}}"#
        );
        let manifest: BrowserExtensionManifest = norito::json::from_str(&manifest_json)
            .expect("decode proxy manifest with bootstrap capability");
        let public = public_local_proxy_manifest_value(&manifest);
        let rendered = norito::json::to_json_pretty(&public)
            .expect("render public local-proxy manifest summary");
        assert!(!rendered.contains(&secret));
        assert!(!rendered.contains("client_capability_hex"));
    }

    #[cfg(unix)]
    fn authenticated_guard_cache_is_owner_private_and_atomically_replaceable() {
        use std::os::unix::fs::MetadataExt as _;

        let temporary = TempDir::new().expect("temporary directory");
        let cache = temporary.path().join("guards.norito");
        let key = GuardCacheKey::from_bytes([0x6D; 32]).expect("non-zero guard cache key");
        let guards = GuardSet::new(Vec::new());

        persist_guard_set(&cache, &guards, Some(&key)).expect("persist authenticated cache");
        persist_guard_set(&cache, &guards, Some(&key))
            .expect("atomically replace authenticated cache");
        let metadata = fs::symlink_metadata(&cache).expect("inspect persisted cache");
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o077, 0);
        assert_eq!(metadata.nlink(), 1);
        let loaded = load_guard_set(&cache, Some(&key))
            .expect("load authenticated cache")
            .expect("cache exists");
        assert!(loaded.guards().is_empty());
        let names = fs::read_dir(temporary.path())
            .expect("list cache directory")
            .map(|entry| entry.expect("directory entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [std::ffi::OsString::from("guards.norito")]);
    }

    #[cfg(unix)]
    fn guard_cache_rejects_symlink_hardlink_and_permissive_custody() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let temporary = TempDir::new().expect("temporary directory");
        let key = GuardCacheKey::from_bytes([0x6D; 32]).expect("non-zero guard cache key");
        let guards = GuardSet::new(Vec::new());
        let target = temporary.path().join("target.norito");
        fs::write(&target, b"unchanged").expect("write symlink target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .expect("make target owner-private");
        let link = temporary.path().join("link.norito");
        symlink(&target, &link).expect("create cache symlink");
        let error = persist_guard_set(&link, &guards, Some(&key))
            .expect_err("cache symlink must fail closed");
        assert!(error.to_string().contains("owner-private"));
        assert_eq!(fs::read(&target).expect("read target"), b"unchanged");
        let error = load_guard_set(&link, Some(&key))
            .expect_err("cache symlink load must fail closed");
        assert!(error.to_string().contains("direct owner-private"));

        let hardlink = temporary.path().join("hardlink.norito");
        fs::hard_link(&target, &hardlink).expect("create cache hardlink");
        let error = load_guard_set(&target, Some(&key))
            .expect_err("multiply linked cache must fail closed");
        assert!(error.to_string().contains("exactly one link"));

        fs::remove_file(&hardlink).expect("remove hardlink");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))
            .expect("make target permissive");
        let error = persist_guard_set(&target, &guards, Some(&key))
            .expect_err("permissive cache must fail closed");
        assert!(error.to_string().contains("owner-private"));
    }

    #[cfg(unix)]
    fn guard_cache_rejects_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TempDir::new().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o777))
            .expect("make cache parent permissive");
        let cache = temporary.path().join("guards.norito");
        let key = GuardCacheKey::from_bytes([0x6D; 32]).expect("non-zero guard cache key");
        let error = persist_guard_set(&cache, &GuardSet::new(Vec::new()), Some(&key))
            .expect_err("writable cache parent must fail closed");
        assert!(error.to_string().contains("writable by another principal"));
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("restore cache parent custody");
    }

    fn hedging_billing_subcommands_parse_all_read_and_ack_routes() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Parser {
            #[command(subcommand)]
            command: Command,
        }
        let checkpoint = "11".repeat(32);
        let statement_id = "22".repeat(32);
        let request_nonce = "33".repeat(32);
        let commands = [
            vec![
                "sorafs-test".to_owned(),
                "billing".to_owned(),
                "status".to_owned(),
            ],
            vec![
                "sorafs-test".to_owned(),
                "billing".to_owned(),
                "statements".to_owned(),
                "--expected-checkpoint-fingerprint".to_owned(),
                checkpoint.clone(),
                "--limit".to_owned(),
                "10".to_owned(),
            ],
            vec![
                "sorafs-test".to_owned(),
                "billing".to_owned(),
                "statement".to_owned(),
                "--statement-id".to_owned(),
                statement_id.clone(),
                "--expected-checkpoint-fingerprint".to_owned(),
                checkpoint.clone(),
                "--output".to_owned(),
                "statement.norito".to_owned(),
            ],
            vec![
                "sorafs-test".to_owned(),
                "billing".to_owned(),
                "acknowledge".to_owned(),
                "--statement-id".to_owned(),
                statement_id,
                "--expected-checkpoint-fingerprint".to_owned(),
                checkpoint.clone(),
                "--request-nonce".to_owned(),
                request_nonce,
                "--authentication-proof".to_owned(),
                "proof.bin".to_owned(),
            ],
            vec![
                "sorafs-test".to_owned(),
                "billing".to_owned(),
                "reconciliation".to_owned(),
            ],
            vec![
                "sorafs-test".to_owned(),
                "hedging".to_owned(),
                "exposure".to_owned(),
                "--expected-checkpoint-fingerprint".to_owned(),
                checkpoint.clone(),
                "--limit".to_owned(),
                "10".to_owned(),
            ],
            vec![
                "sorafs-test".to_owned(),
                "hedging".to_owned(),
                "intents".to_owned(),
                "--expected-checkpoint-fingerprint".to_owned(),
                checkpoint,
                "--limit".to_owned(),
                "10".to_owned(),
            ],
        ];
        for command in commands {
            let parsed = Parser::try_parse_from(command).expect("hedging/billing command parses");
            let _ = parsed.command;
        }
    }
    fn billing_statements_cli_builds_exact_checkpoint_filter() {
        let checkpoint = "11".repeat(32);
        let after_statement_id = "22".repeat(32);
        let args = BillingStatementsArgs {
            expected_checkpoint_fingerprint: checkpoint.clone(),
            after_statement_id: Some(after_statement_id.clone()),
            limit: 25,
        };
        let mut context = TestContext::new();
        args.run_with(&mut context, |_client, filter| {
            assert_eq_compact! { filter.expected_checkpoint_fingerprint_hex => checkpoint.as_str() };
            assert_eq_compact! { filter.after_statement_id_hex => Some(after_statement_id.as_str()) };
            assert_eq!(filter.limit, 25);
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "anchor": {"checkpoint_fingerprint": (checkpoint.to_ascii_uppercase())},
                }), "billing statement page response")
        })
        .expect("billing statement list succeeds");
        assert_eq!(context.printed.len(), 1);
        assert!(context.printed[0].contains("\"anchor\""));
    }
    fn hedging_projection_cli_builds_read_only_exact_checkpoint_filter() {
        let checkpoint = "33".repeat(32);
        let after = "44".repeat(32);
        let args = HedgingProjectionArgs {
            expected_checkpoint_fingerprint: checkpoint.clone(),
            after: Some(after.clone()),
            limit: 100,
        };
        let mut context = TestContext::new();
        args.run_with(&mut context, |_client, filter| {
            assert_eq_compact! { filter.expected_checkpoint_fingerprint_hex => checkpoint.as_str() };
            assert_eq!(filter.after_hex, Some(after.as_str()));
            assert_eq!(filter.limit, 100);
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "anchor": {"checkpoint_fingerprint": (checkpoint.to_ascii_uppercase())},
                    "automatic_execution_enabled": false,
                }), "hedging projection response")
        })
        .expect("hedging projection read succeeds");
        assert_eq!(context.printed.len(), 1);
        let output: Value =
            norito::json::from_str(&context.printed[0]).expect("projection output JSON");
        assert_eq_compact! { output.get("automatic_execution_enabled").and_then(Value::as_bool) => Some(false); "projection output must preserve the disabled execution claim" };
    }
    }
include!("../hedging_billing_response_tests.rs");
#[test]
fn billing_acknowledgement_cli_reads_bounded_binary_proof() {
    let checkpoint = "55".repeat(32);
    let statement_id = "66".repeat(32);
    let request_nonce = "77".repeat(32);
    let mut proof_file = NamedTempFile::new().expect("proof file");
    proof_file
        .write_all(&[0xA5; 48])
        .expect("write authentication proof");
    let args = BillingAcknowledgeArgs {
        statement_id: statement_id.clone(),
        expected_checkpoint_fingerprint: checkpoint.clone(),
        request_nonce: request_nonce.clone(),
        authentication_proof: proof_file.path().to_path_buf(),
    };
    let expected = SorafsBillingAcknowledgementProof::try_from_hex(&request_nonce, vec![0xA5; 48])
        .expect("expected proof");
    let mut context = TestContext::new();
    args.run_with(
        &mut context,
        |_client, actual_statement_id, actual_checkpoint, proof| {
            assert_eq!(actual_statement_id, statement_id);
            assert_eq!(actual_checkpoint, checkpoint);
            assert_eq!(proof, &expected);
            assert_compact! { format!("{proof:?}").contains("[REDACTED]"); "proof debug output must not expose authentication bytes" };
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "acknowledged": true
                }), "billing acknowledgement response")
        },
    )
    .expect("billing acknowledgement succeeds");
    assert_eq!(context.printed.len(), 1);
    let output: Value =
        norito::json::from_str(&context.printed[0]).expect("acknowledgement output JSON");
    assert_eq_compact! { output.get("acknowledged").and_then(Value::as_bool) => Some(true) };
}
#[test]
fn hedging_billing_cli_rejects_non_regular_and_oversized_proofs() {
    let proof_dir = TempDir::new().expect("proof directory");
    let error = read_billing_acknowledgement_proof(proof_dir.path())
        .expect_err("directory proof must fail closed");
    assert!(error.to_string().contains("regular non-symlink file"));
    let oversized = proof_dir.path().join("oversized-proof.bin");
    fs::write(
        &oversized,
        vec![0xA5; SORAFS_BILLING_ACKNOWLEDGEMENT_PROOF_MAX_BYTES_V1 + 1],
    )
    .expect("write oversized proof");
    let error = read_billing_acknowledgement_proof(&oversized)
        .expect_err("oversized proof must fail closed");
    assert!(error.to_string().contains("must contain between 1 and"));
}
#[cfg(any(unix, windows))]
#[test]
fn hedging_billing_cli_rejects_multiply_linked_proof() {
    let proof_dir = TempDir::new().expect("proof directory");
    let target = proof_dir.path().join("proof-target.bin");
    let alias = proof_dir.path().join("proof-alias.bin");
    fs::write(&target, [0xA5; 32]).expect("write proof target");
    fs::hard_link(&target, &alias).expect("create proof hard link");
    let error = read_billing_acknowledgement_proof(&target)
        .expect_err("multiply linked proof must fail closed");
    assert!(error.to_string().contains("stable single-link identity"));
}
#[cfg(unix)]
#[test]
fn hedging_billing_cli_rejects_symlink_proof() {
    use std::os::unix::fs::symlink;
    let proof_dir = TempDir::new().expect("proof directory");
    let target = proof_dir.path().join("proof-target.bin");
    let link = proof_dir.path().join("proof-link.bin");
    fs::write(&target, [0xA5; 32]).expect("write proof target");
    symlink(&target, &link).expect("create proof symlink");
    let error =
        read_billing_acknowledgement_proof(&link).expect_err("symlink proof must fail closed");
    assert!(error.to_string().contains("regular non-symlink file"));
}
test_items! {
fn billing_proof_reader_retains_windows_direct_identity_guards() {
    let source = include_str!("../../sorafs.rs");
    for required_guard in [
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "metadata.volume_serial_number()",
        "metadata.file_index()",
        "left.file_size() == right.file_size()",
        "left.last_write_time() == right.last_write_time()",
        "left.creation_time() == right.creation_time()",
        "billing_proof_metadata_unchanged(&path_metadata, &opened_metadata)",
        "billing_proof_metadata_unchanged(&opened_metadata, &after_file_metadata)",
        "billing_proof_metadata_unchanged(&opened_metadata, &after_path_metadata)",
        "this platform does not expose a stable direct-file identity",
    ] {
        assert_compact! { source.contains(required_guard); "billing proof reader lost required direct-file guard `{required_guard}`" };
    }
}
fn hedging_billing_proof_exact_read_detects_length_drift() {
    let path = Path::new("drifting-proof.bin");
    let mut truncated = std::io::Cursor::new(vec![0xA5; 3]);
    let error = read_billing_acknowledgement_proof_exact(path, &mut truncated, 4)
        .expect_err("truncated proof must fail closed");
    assert!(error.to_string().contains("changed length"));
    let mut extended = std::io::Cursor::new(vec![0xA5; 5]);
    let error = read_billing_acknowledgement_proof_exact(path, &mut extended, 4)
        .expect_err("extended proof must fail closed");
    assert!(error.to_string().contains("changed length"));
}
fn billing_statement_cli_writes_exact_norito_response() {
    let checkpoint = "88".repeat(32);
    let statement_id = "99".repeat(32);
    let output_dir = TempDir::new().expect("statement output directory");
    let output = output_dir.path().join("statement.norito");
    let args = BillingStatementArgs {
        statement_id: statement_id.clone(),
        expected_checkpoint_fingerprint: checkpoint.clone(),
        output: output.clone(),
    };
    let expected_bytes = vec![0x4E, 0x52, 0x54, 0x31];
    let mut context = TestContext::new();
    args.run_with(&mut context, |_client, actual_id, actual_checkpoint| {
        assert_eq!(actual_id, statement_id);
        assert_eq!(actual_checkpoint, checkpoint);
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/x-norito")
            .body(expected_bytes.clone())
            .expect("published statement response"))
    })
    .expect("published statement write succeeds");
    assert_eq_compact! { fs::read(output).expect("read written statement") => expected_bytes };
    assert_eq!(context.printed.len(), 1);
    let summary: Value =
        norito::json::from_str(&context.printed[0]).expect("statement summary JSON");
    assert_eq_compact! { summary.get("bytes_written").and_then(Value::as_u64) => Some(4) };
}
fn billing_statement_cli_refuses_to_clobber_existing_file() {
    let output_dir = TempDir::new().expect("statement output directory");
    let output = output_dir.path().join("statement.norito");
    let original = b"existing-statement".to_vec();
    fs::write(&output, &original).expect("write existing statement");
    let args = BillingStatementArgs {
        statement_id: "99".repeat(32),
        expected_checkpoint_fingerprint: "88".repeat(32),
        output: output.clone(),
    };
    let mut context = TestContext::new();
    let error = args
        .run_with(&mut context, |_client, _statement_id, _checkpoint| {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/x-norito")
                .body(vec![0x4E, 0x52, 0x54, 0x31])
                .expect("published statement response"))
        })
        .expect_err("existing output must fail closed");
    assert!(error.to_string().contains("without replacing"));
    assert_eq_compact! { fs::read(&output).expect("read preserved statement") => original };
    assert!(context.printed.is_empty());
}
}
#[cfg(unix)]
#[test]
fn billing_statement_cli_refuses_to_follow_output_symlink() {
    use std::os::unix::fs::symlink;
    let output_dir = TempDir::new().expect("statement output directory");
    let target = output_dir.path().join("target.norito");
    let output = output_dir.path().join("statement.norito");
    let original = b"target-statement".to_vec();
    fs::write(&target, &original).expect("write statement target");
    symlink(&target, &output).expect("create output symlink");
    let args = BillingStatementArgs {
        statement_id: "99".repeat(32),
        expected_checkpoint_fingerprint: "88".repeat(32),
        output: output.clone(),
    };
    let mut context = TestContext::new();
    let error = args
        .run_with(&mut context, |_client, _statement_id, _checkpoint| {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/x-norito")
                .body(vec![0x4E, 0x52, 0x54, 0x31])
                .expect("published statement response"))
        })
        .expect_err("symlink output must fail closed");
    assert!(error.to_string().contains("without replacing"));
    assert_eq_compact! { fs::read(&target).expect("read preserved target statement") => original };
    assert_compact! { fs::symlink_metadata(&output).expect("inspect preserved output symlink").file_type().is_symlink() };
    assert!(context.printed.is_empty());
}
test_items! {
fn billing_statement_cli_rejects_substituted_media_type() {
    let output_dir = TempDir::new().expect("statement output directory");
    let output = output_dir.path().join("statement.norito");
    let args = BillingStatementArgs {
        statement_id: "99".repeat(32),
        expected_checkpoint_fingerprint: "88".repeat(32),
        output: output.clone(),
    };
    let mut context = TestContext::new();
    let error = args
        .run_with(&mut context, |_client, _statement_id, _checkpoint| {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(br#"{"substituted":true}"#.to_vec())
                .expect("substituted statement response"))
        })
        .expect_err("non-Norito response must fail closed");
    assert!(error.to_string().contains("application/x-norito"));
    assert_compact! { !output.exists(); "substituted response must not be persisted" };
    assert!(context.printed.is_empty());
}
fn hedging_billing_cli_rejects_aliases_and_invalid_bounds_before_http() {
    let mut context = TestContext::new();
    let uppercase = "AA".repeat(32);
    let list = BillingStatementsArgs {
        expected_checkpoint_fingerprint: uppercase,
        after_statement_id: None,
        limit: 1,
    };
    let error = list
        .run_with(&mut context, |_client, _filter| {
            unreachable!("invalid checkpoint must fail before HTTP")
        })
        .expect_err("uppercase checkpoint rejected");
    assert!(error.to_string().contains("lowercase hexadecimal"));
    let projection = HedgingProjectionArgs {
        expected_checkpoint_fingerprint: "11".repeat(32),
        after: None,
        limit: SORAFS_HEDGING_BILLING_MAX_PAGE_ITEMS_V1 + 1,
    };
    let error = projection
        .run_with(&mut context, |_client, _filter| {
            unreachable!("invalid limit must fail before HTTP")
        })
        .expect_err("out-of-range limit rejected");
    assert!(error.to_string().contains("--limit"));
    let zero_nonce = SorafsBillingAcknowledgementProof::try_from_hex(&"00".repeat(32), vec![1])
        .expect_err("zero nonce rejected");
    assert!(zero_nonce.to_string().contains("request nonce"));
    assert!(context.printed.is_empty());
}
fn token_issue_rng_reports_os_seed_failure() {
    let mut rng = FailingSorafsCliNonceRng;
    let error = token_issue_rng_from_rng(&mut rng)
        .expect_err("token RNG seeding should fail when entropy fails");
    let message = format!("{error:?}");
    assert!(message.contains("failed to seed SoraNet admission-token RNG"));
    assert!(message.contains("failing SoraFS CLI nonce RNG"));
}
fn parse_xor_quantity_accepts_canonical_sub_micro_and_wide_inputs() {
    for canonical in [
        "12.3456",
        "0.000000001",
        "340282366920938463463374607431768211456.000000001",
    ] {
        let amount = parse_xor_quantity(canonical).expect("canonical quantity parses");
        assert_eq!(amount.to_string(), canonical);
    }
}
fn parse_xor_quantity_rejects_noncanonical_negative_and_over_scale_inputs() {
    for invalid in [
        "",
        " 1",
        "1 ",
        "+1",
        "01",
        "1.0",
        ".5",
        "1.",
        "-1",
        "0.0000000001",
    ] {
        assert_compact! { parse_xor_quantity(invalid).is_err(); "invalid XOR quantity must be rejected: {invalid:?}" };
    }
}
fn reserve_quote_builder_renders_inputs() {
    let policy = ReservePolicyV1::default();
    let quote = policy
        .quote(
            super::StorageClass::Hot,
            4,
            ReserveDuration::Monthly,
            ReserveTier::TierA,
            XorQuantity::zero(),
        )
        .expect("quote");
    let value = build_reserve_quote_value(
        &policy,
        super::StorageClass::Hot,
        ReserveTier::TierA,
        ReserveDuration::Monthly,
        4,
        &XorQuantity::zero(),
        &quote,
        "test policy",
    )
    .expect("build");
    let root = value
        .as_object()
        .expect("quote payload should be a JSON object");
    assert_eq_compact! { root.get("policy_source").and_then(Value::as_str) => Some("test policy") };
    let inputs = root
        .get("inputs")
        .and_then(Value::as_object)
        .expect("inputs object");
    assert_eq_compact! { inputs.get("storage_class").and_then(Value::as_str) => Some("hot") };
    assert_eq!(inputs.get("capacity_gib").and_then(Value::as_u64), Some(4));
    let quote_value = root.get("quote").expect("quote field exists");
    assert_compact! { quote_value.get("monthly_rent").is_some(); "quote field should carry rent breakdown: {quote_value:?}" };
    let ledger_projection = root
        .get("ledger_projection")
        .and_then(Value::as_object)
        .expect("ledger projection should be serialized");
    assert_compact! { ledger_projection.contains_key("rent_due"); "ledger projection exposes rent_due amount: {ledger_projection:?}" };
}
fn reserve_ledger_projection_rejects_non_string_and_noncanonical_quantities() {
    let policy = ReservePolicyV1::default();
    let reserve_balance = XorQuantity::zero();
    let quote = policy
        .quote(
            super::StorageClass::Hot,
            4,
            ReserveDuration::Monthly,
            ReserveTier::TierA,
            reserve_balance.clone(),
        )
        .expect("quote");
    let valid = build_reserve_quote_value(
        &policy,
        super::StorageClass::Hot,
        ReserveTier::TierA,
        ReserveDuration::Monthly,
        4,
        &reserve_balance,
        &quote,
        "test policy",
    )
    .expect("quote artifact");
    for invalid in [
        Value::Number(Number::from(1_u64)),
        Value::String("+1".into()),
        Value::String("01".into()),
        Value::String("1.0".into()),
        Value::String("-1".into()),
        Value::String("0.0000000001".into()),
    ] {
        let mut artifact = valid.clone();
        artifact
            .as_object_mut()
            .expect("quote object")
            .get_mut("ledger_projection")
            .expect("ledger projection")
            .as_object_mut()
            .expect("ledger object")
            .insert("rent_due".into(), invalid.clone());
        assert_compact! { extract_ledger_projection(&artifact).is_err(); "invalid exact quantity must be rejected: {invalid:?}" };
    }
}
fn reserve_ledger_plan_preserves_sub_micro_and_wide_quantities() {
    let sub_micro: XorQuantity = "0.000000001".parse().expect("sub-micro quantity");
    let wide: XorQuantity = "340282366920938463463374607431768211456.000000001"
        .parse()
        .expect("wide quantity");
    let projection = LedgerProjectionAmounts {
        rent_due: sub_micro.clone(),
        reserve_shortfall: wide.clone(),
        top_up_shortfall: XorQuantity::zero(),
    };
    let provider = sample_account_id("reserve-ledger-provider");
    let treasury = sample_account_id("reserve-ledger-treasury");
    let reserve = sample_account_id("reserve-ledger-escrow");
    let plan = build_reserve_ledger_plan(
        Path::new("quote.json"),
        projection,
        &provider,
        &treasury,
        &reserve,
        &xor_asset_id(),
    )
    .expect("exact reserve ledger plan");
    let root = plan.as_object().expect("ledger plan object");
    assert_eq_compact! { root.get("rent_due").and_then(Value::as_str) => Some(sub_micro.to_string().as_str()) };
    assert_eq_compact! { root.get("reserve_shortfall").and_then(Value::as_str) => Some(wide.to_string().as_str()) };
    assert!(!root.contains_key("rent_due_micro_xor"));
    assert_eq_compact! { root.get("instructions").and_then(Value::as_array).map(Vec::len) => Some(2) };
    let rendered = norito::json::to_json(&plan).expect("ledger plan JSON");
    assert!(rendered.contains(&sub_micro.to_string()));
    assert!(rendered.contains(&wide.to_string()));
}
fn reserve_lifecycle_builder_renders_stage_and_credit_fields() {
    let policy = ReservePolicyV1::default();
    let quote = policy
        .quote(
            super::StorageClass::Hot,
            10,
            ReserveDuration::Monthly,
            ReserveTier::TierA,
            XorQuantity::zero(),
        )
        .expect("quote");
    let lifecycle = quote
        .lifecycle_projection(3, 7, 30)
        .expect("lifecycle projection");
    let value = build_reserve_lifecycle_value(Path::new("quote.json"), &lifecycle)
        .expect("build lifecycle JSON");
    let root = value
        .as_object()
        .expect("lifecycle payload should be a JSON object");
    assert_eq!(root.get("stage").and_then(Value::as_str), Some("grace"));
    assert_eq!(root.get("credit_draw").and_then(Value::as_str), Some("120"));
    assert_eq_compact! { root.get("disable_adverts").and_then(Value::as_bool) => Some(false) };
    assert_compact! { root.get("lifecycle_projection").is_some(); "full projection should be embedded" };
}
}
fn sample_guard_directory_signing_key() -> SigningKey {
    let mut rng = StdRng::seed_from_u64(0x5EED);
    let mut ed_seed = [0u8; 32];
    rng.fill_bytes(&mut ed_seed);
    SigningKey::from_bytes(&ed_seed)
}
fn sample_guard_directory_snapshot_bytes() -> Vec<u8> {
    let signing_key = sample_guard_directory_signing_key();
    let ed_public = Ed25519VerifyingKey::from(&signing_key).to_bytes();
    let mldsa_keys = generate_mldsa_keypair(MlDsaSuite::MlDsa65)
        .expect("ML-DSA keypair generation should succeed");
    let mldsa_public = mldsa_keys.public_key().to_vec();
    let fingerprint = compute_issuer_fingerprint(&ed_public, &mldsa_public)
        .expect("sample issuer fingerprint should compute");
    let directory_hash = [0xAB; 32];
    let certificate = RelayCertificateV2 {
        relay_id: ed_public,
        identity_ed25519: ed_public,
        identity_mldsa65: vec![0x44; 1952],
        descriptor_commit: [0x22; 32],
        roles: RelayRolesV2 {
            entry: true,
            middle: false,
            exit: false,
        },
        guard_weight: 12,
        bandwidth_bytes_per_sec: 1_500_000,
        reputation_weight: 80,
        endpoints: vec![RelayEndpointV2 {
            quic_multiaddr: "/dns/pq.guard/udp/443/quic".to_string(),
            tls_server_name: "pq.guard".to_string(),
            tls_spki_sha256: [0xA5; 32],
            priority: 0,
            tags: vec![EndpointTag::NoritoStream.as_label().to_string()],
        }],
        capability_flags: RelayCapabilityFlagsV1::new(
            CapabilityToggle::Enabled,
            CapabilityToggle::Disabled,
            CapabilityToggle::Enabled,
            CapabilityToggle::Disabled,
        ),
        handshake_suites: vec![
            HandshakeSuite::Nk3PqForwardSecure,
            HandshakeSuite::Nk2Hybrid,
        ],
        published_at: 1_734_000_000,
        valid_after: 1_734_000_000,
        valid_until: 1_734_086_400,
        directory_hash,
        issuer_fingerprint: fingerprint,
    };
    let published_at = certificate.published_at;
    let valid_after = certificate.valid_after;
    let valid_until = certificate.valid_until;
    let bundle = certificate
        .issue(&signing_key, mldsa_keys.secret_key())
        .expect("issue certificate");
    let snapshot = GuardDirectorySnapshotV2 {
        version: 2,
        directory_hash,
        published_at_unix: published_at,
        valid_after_unix: valid_after,
        valid_until_unix: valid_until,
        issuers: vec![GuardDirectoryIssuerV1 {
            fingerprint,
            ed25519_public: ed_public,
            mldsa65_public: mldsa_public,
        }],
        relays: vec![GuardDirectoryRelayEntryV2 {
            certificate: bundle
                .try_to_cbor()
                .expect("sample relay bundle should encode"),
        }],
    };
    to_bytes(&snapshot).expect("encode snapshot")
}
pub(super) struct TestContext {
    cfg: Config,
    printed: Vec<String>,
    i18n: Localizer,
    output_format: CliOutputFormat,
}
impl TestContext {
    pub(super) fn new() -> Self {
        Self::with_output_format(CliOutputFormat::Json)
    }
    pub(super) fn with_output_format(output_format: CliOutputFormat) -> Self {
        let kp = checked_sorafs_ed25519_key_fixture();
        let account = AccountId::new(kp.public_key().clone());
        let cfg = Config {
            chain: ChainId::from("test-chain"),
            network_id: iroha::data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                    b"iroha-cli-sorafs-test-genesis",
                )),
            ),
            account,
            account_chain_discriminant:
                iroha_config::parameters::defaults::common::chain_discriminant(),
            key_pair: kp,
            basic_auth: None,
            api_token: None,
            http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
            torii_api_url: Url::parse("http://localhost/").unwrap(),
            torii_request_timeout: config::DEFAULT_TORII_REQUEST_TIMEOUT,
            transaction_ttl: config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
            transaction_status_timeout: config::DEFAULT_TRANSACTION_STATUS_TIMEOUT,
            transaction_add_nonce: config::DEFAULT_TRANSACTION_NONCE,
            sorafs_alias_cache: crate::config_utils::default_alias_cache_policy(),
            sorafs_anonymity_policy: crate::config_utils::default_anonymity_policy(),
            sorafs_rollout_phase: crate::config_utils::default_rollout_phase(),
        };
        Self {
            cfg,
            printed: Vec::new(),
            i18n: Localizer::new(Bundle::Cli, Language::English),
            output_format,
        }
    }
    pub(super) fn outputs(&self) -> &[String] {
        &self.printed
    }
}
#[test]
fn handshake_configuration_read_requires_explicit_operator_authority() {
    let mut context = TestContext::new();
    let error = HandshakeCommand::Show
        .run(&mut context)
        .expect_err("configuration reads require an operator key");
    assert!(format!("{error:#}").contains("--operator-private-key-file"));
    assert!(context.outputs().is_empty());
}
fn checked_sorafs_ed25519_key_fixture() -> KeyPair {
    KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked SoraFS fixture key")
}
#[test]
fn sorafs_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_sorafs_ed25519_key_fixture();
    let actual = key_pair
        .public_key()
        .try_algorithm()
        .expect("SoraFS fixture key advertises a valid algorithm");
    assert_eq!(actual, Algorithm::Ed25519);
}
struct OutputModeContext {
    config: Config,
    output_format: CliOutputFormat,
    printed: Vec<String>,
    i18n: Localizer,
}
impl OutputModeContext {
    fn new(output_format: CliOutputFormat) -> Self {
        Self {
            config: crate::fallback_config(),
            output_format,
            printed: Vec::new(),
            i18n: Localizer::new(Bundle::Cli, Language::English),
        }
    }
}
impl RunContext for OutputModeContext {
    fn config(&self) -> &Config {
        &self.config
    }
    fn transaction_metadata(&self) -> Option<&Metadata> {
        None
    }
    fn input_instructions(&self) -> bool {
        false
    }
    fn output_instructions(&self) -> bool {
        false
    }
    fn i18n(&self) -> &Localizer {
        &self.i18n
    }
    fn output_format(&self) -> CliOutputFormat {
        self.output_format
    }
    fn print_data<T>(&mut self, _data: &T) -> Result<()>
    where
        T: JsonSerialize + ?Sized,
    {
        self.printed.push("json".to_string());
        Ok(())
    }
    fn println(&mut self, _data: impl Display) -> Result<()> {
        self.printed.push("text".to_string());
        Ok(())
    }
}
test_items! {
fn output_summary_prefers_json_in_json_mode() {
    let mut ctx = OutputModeContext::new(CliOutputFormat::Json);
    let summary = DaemonIterationSummary::default();
    output_summary(&mut ctx, &summary, false).expect("summary output");
    assert_eq!(ctx.printed, vec!["json"]);
}
fn output_summary_uses_text_in_text_mode() {
    let mut ctx = OutputModeContext::new(CliOutputFormat::Text);
    let summary = DaemonIterationSummary::default();
    output_summary(&mut ctx, &summary, false).expect("summary output");
    assert_eq!(ctx.printed, vec!["text"]);
}
fn log_daemon_summary_emits_json_in_json_mode() {
    let mut ctx = OutputModeContext::new(CliOutputFormat::Json);
    let summary = DaemonIterationSummary::default();
    log_daemon_summary(&mut ctx, &summary, false).expect("daemon summary");
    assert_eq!(ctx.printed, vec!["json"]);
}
}
fn sample_reward_config_json() -> norito::json::Value {
    let mut policy = norito::json::Map::new();
    policy.insert(
        "minimum_exit_bond".to_string(),
        norito::json::Value::String("1000".to_string()),
    );
    policy.insert(
        "bond_asset_id".to_string(),
        norito::json::Value::String(xor_asset_id().to_string()),
    );
    policy.insert(
        "uptime_floor_per_mille".to_string(),
        norito::json::Value::Number(900u64.into()),
    );
    policy.insert(
        "slash_penalty_basis_points".to_string(),
        norito::json::Value::Number(250u64.into()),
    );
    policy.insert(
        "activation_grace_epochs".to_string(),
        norito::json::Value::Number(0u64.into()),
    );
    let mut root = norito::json::Map::new();
    root.insert("policy".to_string(), norito::json::Value::Object(policy));
    root.insert(
        "base_reward".to_string(),
        norito::json::Value::String("100".to_string()),
    );
    root.insert(
        "uptime_weight_per_mille".to_string(),
        norito::json::Value::Number(500u64.into()),
    );
    root.insert(
        "bandwidth_weight_per_mille".to_string(),
        norito::json::Value::Number(500u64.into()),
    );
    root.insert(
        "compliance_penalty_basis_points".to_string(),
        norito::json::Value::Number(0u64.into()),
    );
    root.insert(
        "bandwidth_target_bytes".to_string(),
        norito::json::Value::Number(1_000u64.into()),
    );
    root.insert(
        "budget_approval_id".to_string(),
        norito::json::Value::String(sample_budget_id_hex()),
    );
    root.insert("metrics_log_path".to_string(), norito::json::Value::Null);
    norito::json::Value::Object(root)
}
fn sample_bond_entry(amount: u32) -> RelayBondLedgerEntryV1 {
    RelayBondLedgerEntryV1 {
        relay_id: [0xAB; 32],
        bonded_amount: Quantity::from(amount),
        bond_asset_id: xor_asset_id(),
        bonded_since_unix: 1,
        exit_capable: true,
    }
}
fn sample_metrics() -> RelayEpochMetricsV1 {
    RelayEpochMetricsV1 {
        relay_id: [0xAB; 32],
        epoch: 7,
        uptime_seconds: 3_600,
        scheduled_uptime_seconds: 3_600,
        verified_bandwidth_bytes: 1_000,
        compliance: RelayComplianceStatusV1::Clean,
        reward_score: 0,
        confidence_floor_per_mille: 1_000,
        measurement_ids: Vec::new(),
        metadata: Metadata::default(),
    }
}
fn sample_reward_instruction() -> RelayRewardInstructionV1 {
    RelayRewardInstructionV1 {
        relay_id: [0xCD; 32],
        epoch: 9,
        beneficiary: sample_account_id("relay-beneficiary"),
        payout_asset_id: xor_asset_id(),
        payout_amount: Quantity::from(42_u32),
        reward_score: 750,
        budget_approval_id: Some(sample_budget_id()),
        metadata: Metadata::default(),
    }
}
include!("../incentives_ledger_tests.rs");
test_items! {
#[cfg(unix)]
fn handshake_token_issue_generates_verifiable_token() {
    let mut ctx = TestContext::new();
    let keypair = generate_mldsa_keypair(MlDsaSuite::MlDsa44).expect("keypair");
    let mut secret_file = NamedTempFile::new().expect("secret file");
    secret_file
        .write_all(keypair.secret_key())
        .expect("write secret key");
    let public_hex = hex::encode(keypair.public_key());
    let output_dir = TempDir::new().expect("token output directory");
    let output_path = output_dir.path().join("admission.token");
    let args = HandshakeTokenIssueArgs {
        suite: MlDsaSuiteArg::MlDsa44,
        issuer_secret_key: secret_file.path().to_path_buf(),
        issuer_public_key: None,
        issuer_public_hex: Some(public_hex.clone()),
        relay_id: "11".repeat(32),
        transcript_hash: "22".repeat(32),
        issued_at: Some("2026-01-01T00:00:00Z".to_string()),
        expires_at: None,
        ttl_secs: Some(900),
        flags: Some(0),
        output: output_path.clone(),
        token_encoding: TokenOutputFormat::Base64,
    };
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let default_now = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let mut artifacts = args
        .issue_with_rng(&mut ctx, &mut rng, default_now)
        .expect("issue token");
    let replay_limits = TokenStoreLimits::new(4, Duration::from_secs(1_800))
        .expect("fixture replay limits");
    let replay_store: Arc<Mutex<dyn TokenStore + Send>> = Arc::new(Mutex::new(
        InMemoryTokenStore::new(replay_limits).expect("fixture replay store"),
    ));
    let verifier = AdmissionTokenVerifier::try_new(
        MlDsaSuite::MlDsa44,
        keypair.public_key().to_vec(),
        Duration::from_secs(900),
        Duration::from_secs(5),
        replay_store,
    )
    .expect("generated verifier key must match ML-DSA-44");
    let verify_now = SystemTime::UNIX_EPOCH
        + Duration::from_secs(artifacts.token.issued_at().saturating_add(1));
    verifier
        .verify(
            &artifacts.token,
            &artifacts.relay_id,
            &artifacts.transcript_hash,
            verify_now,
        )
        .expect("token should verify");
    HandshakeTokenIssueArgs::emit(
        &mut ctx,
        &artifacts,
        &output_path,
        TokenOutputFormat::Base64,
    )
    .expect("emit output");
    let output = ctx.outputs().last().expect("json output present");
    let json: Value = norito::json::from_str(output).expect("valid json");
    assert_eq!(json["flags"], Value::from(0u64));
    assert_eq_compact! { json["token_id_hex"] => Value::from(hex::encode(artifacts.token.token_id())) };
    assert!(json.get("token_base64url").is_none());
    assert!(json.get("token_hex").is_none());
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        fs::metadata(&output_path).expect("token metadata").mode() & 0o077,
        0
    );
    let error = HandshakeTokenIssueArgs::emit(
        &mut ctx,
        &artifacts,
        &output_path,
        TokenOutputFormat::Base64,
    )
    .expect_err("existing bearer output must not be overwritten");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("failed to create new owner-private token output"),
        "unexpected overwrite error: {rendered}"
    );
    artifacts.zeroize_encoded_token();
    assert!(artifacts.token_bytes.is_empty());
}
#[cfg(unix)]
fn handshake_token_issue_rejects_explicit_subsecond_timestamps() {
    let mut ctx = TestContext::new();
    let keypair = generate_mldsa_keypair(MlDsaSuite::MlDsa44).expect("keypair");
    let mut secret_file = NamedTempFile::new().expect("secret file");
    secret_file
        .write_all(keypair.secret_key())
        .expect("write secret key");
    let output_dir = TempDir::new().expect("token output directory");
    let mut args = HandshakeTokenIssueArgs {
        suite: MlDsaSuiteArg::MlDsa44,
        issuer_secret_key: secret_file.path().to_path_buf(),
        issuer_public_key: None,
        issuer_public_hex: Some(hex::encode(keypair.public_key())),
        relay_id: "11".repeat(32),
        transcript_hash: "22".repeat(32),
        issued_at: Some("2026-01-01T00:00:00.123Z".to_string()),
        expires_at: None,
        ttl_secs: Some(900),
        flags: Some(0),
        output: output_dir.path().join("admission.token"),
        token_encoding: TokenOutputFormat::Binary,
    };
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let error = match args.issue_with_rng(&mut ctx, &mut rng, UNIX_EPOCH) {
        Ok(_) => panic!("fractional explicit issuance time must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("--issued-at must use whole-second"));

    args.issued_at = Some("2026-01-01T00:00:00Z".to_string());
    args.expires_at = Some("2026-01-01T00:15:00.123Z".to_string());
    args.ttl_secs = None;
    let error = match args.issue_with_rng(&mut ctx, &mut rng, UNIX_EPOCH) {
        Ok(_) => panic!("fractional explicit expiry time must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("--expires-at must use whole-second"));
}
#[cfg(unix)]
fn handshake_token_issue_floors_only_default_wall_clock_time() {
    let mut ctx = TestContext::new();
    let keypair = generate_mldsa_keypair(MlDsaSuite::MlDsa44).expect("keypair");
    let mut secret_file = NamedTempFile::new().expect("secret file");
    secret_file
        .write_all(keypair.secret_key())
        .expect("write secret key");
    let output_dir = TempDir::new().expect("token output directory");
    let args = HandshakeTokenIssueArgs {
        suite: MlDsaSuiteArg::MlDsa44,
        issuer_secret_key: secret_file.path().to_path_buf(),
        issuer_public_key: None,
        issuer_public_hex: Some(hex::encode(keypair.public_key())),
        relay_id: "33".repeat(32),
        transcript_hash: "44".repeat(32),
        issued_at: None,
        expires_at: None,
        ttl_secs: Some(600),
        flags: None,
        output: output_dir.path().join("admission.token"),
        token_encoding: TokenOutputFormat::Binary,
    };
    let default_seconds = 1_800_000_000;
    let default_now = UNIX_EPOCH
        + Duration::from_secs(default_seconds)
        + Duration::from_nanos(987_654_321);
    let mut rng = StdRng::seed_from_u64(0xabad_1dea);
    let artifacts = args
        .issue_with_rng(&mut ctx, &mut rng, default_now)
        .expect("default wall clock is canonicalized");
    assert_eq!(artifacts.issued_dt.nanosecond(), 0);
    assert_eq!(artifacts.expires_dt.nanosecond(), 0);
    assert_eq!(artifacts.token.issued_at(), default_seconds);
    assert_eq!(artifacts.token.expires_at(), default_seconds + 600);
    assert_eq!(artifacts.issued_dt.unix_timestamp(), default_seconds as i64);
}
#[cfg(unix)]
fn handshake_token_id_reports_expected_digest() {
    let mut ctx = TestContext::new();
    let keypair = generate_mldsa_keypair(MlDsaSuite::MlDsa44).expect("keypair");
    let mut secret_file = NamedTempFile::new().expect("secret file");
    secret_file
        .write_all(keypair.secret_key())
        .expect("write secret key");
    let public_hex = hex::encode(keypair.public_key());
    let output_dir = TempDir::new().expect("token output directory");
    let args = HandshakeTokenIssueArgs {
        suite: MlDsaSuiteArg::MlDsa44,
        issuer_secret_key: secret_file.path().to_path_buf(),
        issuer_public_key: None,
        issuer_public_hex: Some(public_hex),
        relay_id: "33".repeat(32),
        transcript_hash: "44".repeat(32),
        issued_at: Some("2026-02-01T00:00:00Z".to_string()),
        expires_at: None,
        ttl_secs: Some(600),
        flags: None,
        output: output_dir.path().join("unused.token"),
        token_encoding: TokenOutputFormat::Base64,
    };
    let mut rng = StdRng::seed_from_u64(0xabad_1dea);
    let artifacts = args
        .issue_with_rng(
            &mut ctx,
            &mut rng,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        )
        .expect("issue token");
    let token_path = output_dir.path().join("admission.token");
    write_token_to_file(
        &token_path,
        TokenOutputFormat::Binary,
        &artifacts.token_bytes,
    )
    .expect("write private token file");
    let id_args = HandshakeTokenIdArgs { path: token_path };
    id_args.run(&mut ctx).expect("compute id");
    let output = ctx.outputs().last().expect("json output");
    let json: Value = norito::json::from_str(output).expect("valid json");
    assert_eq_compact! { json["token_id_hex"] => Value::from(hex::encode(artifacts.token.token_id())) };
}
fn handshake_token_fingerprint_matches_helper() {
    let mut ctx = TestContext::new();
    let keypair = generate_mldsa_keypair(MlDsaSuite::MlDsa65).expect("keypair");
    let public_hex = hex::encode(keypair.public_key());
    let expected = token::compute_issuer_fingerprint(keypair.public_key());
    let args = HandshakeTokenFingerprintArgs {
        public_key: None,
        public_key_hex: Some(public_hex),
    };
    args.run(&mut ctx).expect("fingerprint");
    let output = ctx.outputs().last().expect("json output");
    let json: Value = norito::json::from_str(output).expect("valid json");
    assert_eq_compact! { json["issuer_fingerprint_hex"] => Value::from(hex::encode(expected)) };
}
fn handshake_token_cli_rejects_secret_and_bearer_argv_inputs() {
    use clap::Parser as _;
    #[derive(clap::Parser, Debug)]
    struct Parser {
        #[command(subcommand)]
        command: HandshakeTokenCommand,
    }
    let relay_id = "11".repeat(32);
    let transcript_hash = "22".repeat(32);
    let issue_error = Parser::try_parse_from([
        "token-test",
        "issue",
        "--issuer-secret-hex",
        "00",
        "--issuer-public-hex",
        "00",
        "--relay-id",
        &relay_id,
        "--transcript-hash",
        &transcript_hash,
        "--output",
        "token.bin",
    ])
    .expect_err("inline issuer secret must be unknown");
    assert_eq!(issue_error.kind(), clap::error::ErrorKind::UnknownArgument);
    let id_error = Parser::try_parse_from(["token-test", "id", "--token-hex", "00"])
        .expect_err("inline bearer token must be unknown");
    assert_eq!(id_error.kind(), clap::error::ErrorKind::UnknownArgument);
}
#[cfg(unix)]
fn handshake_token_private_reader_rejects_public_links_and_oversize() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let directory = TempDir::new().expect("private input directory");
    let secret = directory.path().join("secret.key");
    fs::write(&secret, [0xA5; 32]).expect("write secret");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))
        .expect("set private mode");
    assert_eq!(
        read_owner_private_handshake_file(&secret, 32, Some(32), "secret")
            .expect("private secret")
            .as_slice(),
        [0xA5; 32]
    );
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o640))
        .expect("set public mode");
    assert!(
        read_owner_private_handshake_file(&secret, 32, Some(32), "secret")
            .expect_err("group-readable secret must fail")
            .to_string()
            .contains("owner-private")
    );
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))
        .expect("restore private mode");
    let hard_link = directory.path().join("secret-copy.key");
    fs::hard_link(&secret, &hard_link).expect("create hard link");
    assert!(
        read_owner_private_handshake_file(&secret, 32, Some(32), "secret")
            .expect_err("multiply linked secret must fail")
            .to_string()
            .contains("exactly one link")
    );
    let direct = directory.path().join("direct.key");
    fs::write(&direct, [0xB6; 32]).expect("write direct target");
    fs::set_permissions(&direct, fs::Permissions::from_mode(0o600))
        .expect("set target mode");
    let symbolic = directory.path().join("secret-link.key");
    symlink(&direct, &symbolic).expect("create symbolic link");
    assert!(
        read_owner_private_handshake_file(&symbolic, 32, Some(32), "secret")
            .expect_err("symbolic link must fail")
            .to_string()
            .contains("non-symlink")
    );
    let oversized = directory.path().join("oversized.token");
    let file = fs::File::create(&oversized).expect("create oversized token");
    file.set_len((HANDSHAKE_TOKEN_FILE_MAX_BYTES_V1 + 1) as u64)
        .expect("size oversized token");
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))
        .expect("set oversized mode");
    assert!(
        read_owner_private_handshake_file(
            &oversized,
            HANDSHAKE_TOKEN_FILE_MAX_BYTES_V1,
            None,
            "token",
        )
        .expect_err("oversized token must fail")
        .to_string()
        .contains("must contain between")
    );
    let public_key = directory.path().join("issuer.pub");
    fs::write(&public_key, [0xC7; 32]).expect("write public key");
    assert_eq!(
        materialise_key_bytes(
            Some(&public_key),
            None,
            "--issuer-public-key",
            "--issuer-public-hex",
            32,
            Some(32),
        )
        .expect("exact public key"),
        [0xC7; 32]
    );
    fs::write(&public_key, [0xC7; 33]).expect("grow public key");
    assert!(
        materialise_key_bytes(
            Some(&public_key),
            None,
            "--issuer-public-key",
            "--issuer-public-hex",
            32,
            Some(32),
        )
        .expect_err("oversized public key must fail")
        .to_string()
        .contains("exactly 32 bytes")
    );
}
}
impl RunContext for TestContext {
    fn config(&self) -> &Config {
        &self.cfg
    }
    fn transaction_metadata(&self) -> Option<&Metadata> {
        None
    }
    fn input_instructions(&self) -> bool {
        false
    }
    fn output_instructions(&self) -> bool {
        false
    }
    fn i18n(&self) -> &Localizer {
        &self.i18n
    }
    fn output_format(&self) -> CliOutputFormat {
        self.output_format
    }
    fn print_data<T>(&mut self, data: &T) -> Result<()>
    where
        T: JsonSerialize + ?Sized,
    {
        let bytes = norito::json::to_vec(data)?;
        let out = String::from_utf8(bytes).map_err(|err| eyre!(err.to_string()))?;
        self.printed.push(out);
        Ok(())
    }
    fn println(&mut self, data: impl Display) -> Result<()> {
        self.printed.push(data.to_string());
        Ok(())
    }
}
test_items! {
fn gateway_provider_spec_parses_expected_keys() {
    let id_hex = "11".repeat(32);
    let key_hex = "22".repeat(32);
    let spec = format!(
        "name=alpha, provider-id={id_hex}, gateway-key={key_hex}, base-url=https://example.com, stream-token=YWJj"
    );
    let parsed =
        GatewayProviderInput::parse_spec(&spec, "--gateway-provider").expect("parse spec");
    assert_eq!(parsed.name, "alpha");
    assert_eq!(parsed.provider_id_hex, id_hex);
    assert_eq!(parsed.gateway_public_key_hex, key_hex);
    assert_eq!(parsed.base_url, "https://example.com");
    assert_eq!(parsed.stream_token_b64, "YWJj");
}
fn gateway_provider_spec_rejects_missing_fields() {
    let err = GatewayProviderInput::parse_spec(
        "name=alpha, base-url=https://example.com",
        "--gateway-provider",
    )
    .expect_err("missing provider-id should fail");
    assert_compact! { err.to_string().contains("provider-id"); "unexpected error: {err}" };
}
fn validate_hex_digest_enforces_format() {
    let valid = validate_hex_digest(&"ab".repeat(32), "--flag").expect("valid digest");
    assert_eq!(valid, "ab".repeat(32));
    let err = validate_hex_digest("zz", "--flag").expect_err("invalid digest");
    assert!(err.to_string().contains("--flag"));
}
fn parse_transport_policy_flag_accepts_valid_value() {
    let value = "soranet-strict".to_string();
    let parsed = parse_transport_policy_flag(Some(&value), "--transport-policy-override")
        .expect("parse transport policy");
    assert_eq!(parsed, Some(TransportPolicy::SoranetStrict));
}
fn parse_transport_policy_flag_rejects_noncanonical_inputs() {
    for rejected in [
        "",
        " ",
        " soranet-first",
        "soranet-first ",
        "SORANET-FIRST",
        "soranet_first",
        "soranet_strict",
        "direct_only",
        "soranet-only",
        "soranet_only",
    ] {
        let rejected_value = rejected.to_owned();
        assert_compact! { parse_transport_policy_flag(Some(&rejected_value), "--transport-policy").is_err(); "noncanonical transport label `{rejected}` must fail" };
    }
}
fn parse_anonymity_policy_flag_accepts_canonical_value() {
    let value = "anon-majority-pq".to_string();
    let parsed = parse_anonymity_policy_flag(Some(&value), "--anonymity-policy-override")
        .expect("parse anonymity policy");
    assert_eq!(parsed, Some(AnonymityPolicy::MajorityPq));
}
fn parse_anonymity_policy_flag_rejects_noncanonical_inputs() {
    for rejected in [
        "",
        " ",
        " anon-guard-pq",
        "anon-guard-pq ",
        "ANON-GUARD-PQ",
        "anon_guard_pq",
        "anon_majority_pq",
        "anon_strict_pq",
        "stage-a",
        "stage_a",
        "stagea",
        "stage-b",
        "stage_b",
        "stageb",
        "stage-c",
        "stage_c",
        "stagec",
        "anon-unknown",
    ] {
        let rejected_value = rejected.to_owned();
        assert_compact! { parse_anonymity_policy_flag(Some(&rejected_value), "--anonymity-policy").is_err(); "noncanonical anonymity label `{rejected}` must fail" };
    }
}
fn parse_write_mode_flag_accepts_only_exact_v1_labels() {
    for (label, expected) in [
        ("read-only", WriteModeHint::ReadOnly),
        ("upload-pq-only", WriteModeHint::UploadPqOnly),
    ] {
        let label_value = label.to_owned();
        assert_eq_compact! { parse_write_mode_flag(Some(&label_value), "--write-mode").expect("canonical write mode") => Some(expected) };
    }
    for rejected in [
        "",
        " ",
        " read-only",
        "read-only ",
        "READ-ONLY",
        "read_only",
        "upload_pq_only",
    ] {
        let rejected_value = rejected.to_owned();
        assert_compact! { parse_write_mode_flag(Some(&rejected_value), "--write-mode").is_err(); "noncanonical write-mode label `{rejected}` must fail" };
    }
}
fn anonymity_policy_label_matches_expected_values() {
    assert_eq_compact! { anonymity_policy_label(AnonymityPolicy::GuardPq) => "anon-guard-pq" };
    assert_eq_compact! { anonymity_policy_label(AnonymityPolicy::MajorityPq) => "anon-majority-pq" };
    assert_eq_compact! { anonymity_policy_label(AnonymityPolicy::StrictPq) => "anon-strict-pq" };
}
fn load_guard_directory_json_rejected() {
    let (_directory, mut file) = guard_directory_snapshot_file();
    let id_primary = "01".repeat(32);
    let id_secondary = "02".repeat(32);
    let pq_hex = "aa".repeat(ML_KEM_768_PUBLIC_LEN);
    let json = format!(
        r#"{{
  "relays": [
    {{
      "relay_id_hex": "{id_primary}",
      "guard_weight": 10,
      "roles": {{ "entry": true, "middle": false, "exit": false }},
      "endpoints": [{{ "url": "soranet://pq.guard", "priority": 0 }}],
      "ml_kem_public_hex": "{pq_hex}"
    }},
    {{
      "relay_id_hex": "{id_secondary}",
      "guard_weight": 5,
      "roles": {{ "entry": true, "middle": false, "exit": false }},
      "endpoints": [{{ "url": "soranet://classical.guard", "priority": 0 }}]
    }}
  ]
}}
"#
    );
    write!(file, "{json}").expect("write guard directory");
    let json_bytes = fs::read(file.path()).expect("read fixture");
    let digest = hex::encode(compute_snapshot_digest(&json_bytes));
    let err = load_guard_directory(file.path(), &digest, 1_734_000_000)
        .expect_err("json format must be rejected");
    let msg = err.to_string();
    assert_compact! { msg.contains("failed to authenticate guard directory"); "unexpected error message: {msg}" };
    assert_compact! { msg.contains("SRCv2"); "error should mention the canonical SRCv2 Norito format: {msg}" };
}
fn load_guard_directory_decodes_srcv2_bundle() {
    let bytes = sample_guard_directory_snapshot_bytes();
    let (_directory, mut file) = guard_directory_snapshot_file();
    file.write_all(&bytes).expect("write snapshot");
    let digest = hex::encode(compute_snapshot_digest(&bytes));
    let directory =
        load_guard_directory(file.path(), &digest, 1_734_000_000).expect("load directory");
    let entries = directory.entries();
    assert_eq!(entries.len(), 1);
    let descriptor = &entries[0];
    let expected_relay_id =
        Ed25519VerifyingKey::from(&sample_guard_directory_signing_key()).to_bytes();
    assert_eq!(descriptor.relay_id, expected_relay_id);
    assert!(descriptor.is_pq_capable());
    assert!(descriptor.certificate().is_some());
    assert_eq_compact! { descriptor.certificate_validity() => directory.valid_after().zip(directory.valid_until()) };
    assert_eq!(directory.valid_after(), Some(1_734_000_000));
    assert_eq!(directory.valid_until(), Some(1_734_086_400));
}
}
include!("../../sorafs_guard_directory_tests.rs");
test_items! {
    fn authenticated_directory_accepts_matching_snapshot_digest() {
        let bytes = sample_guard_directory_snapshot_bytes();
        let expected = hex::encode(compute_snapshot_digest(&bytes));
        let summary = authenticate_guard_directory_bytes(&bytes, &expected, 1_734_000_000)
            .expect("digest and time should authenticate");
        assert_eq!(summary.authentication, "authenticated");
    }
    fn authenticated_directory_rejects_mismatch_and_expiry() {
        let bytes = sample_guard_directory_snapshot_bytes();
        let mismatch = authenticate_guard_directory_bytes(&bytes, &"00".repeat(32), 1_734_000_000);
        assert!(mismatch.is_err(), "snapshot digest mismatch should fail");
        let expected = hex::encode(compute_snapshot_digest(&bytes));
        let expired = authenticate_guard_directory_bytes(&bytes, &expected, 1_734_086_400);
        assert!(expired.is_err(), "expired snapshot should fail");
    }
    fn write_guard_directory_snapshot_honours_overwrite_flag() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().expect("temp dir");
        let path = temp_dir.path().join("snapshot.norito");
        let bytes = sample_guard_directory_snapshot_bytes();
        write_guard_directory_snapshot(&path, &bytes, false).expect("first write should succeed");
        let second = write_guard_directory_snapshot(&path, &bytes, false);
        assert!(second.is_err(), "expected overwrite protection");
        write_guard_directory_snapshot(&path, &bytes, true).expect("overwrite when allowed");
    }
    fn pin_list_with_prints_payload() {
        let block_hash = "11".repeat(32);
        let after_digest = "22".repeat(32);
        let args = PinListArgs {
            status: Some(PinStatusSelector::Approved),
            limit: Some(5),
            max_bytes: Some(4096),
            after_digest_hex: Some(after_digest.clone()),
            expected_finalized_height: Some(7),
            expected_finalized_block_hash_hex: Some(block_hash.clone()),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, filter| {
            assert_eq!(filter.status, Some(PinStatusKindV1::Approved));
            assert_eq!(filter.limit, Some(5));
            assert_eq!(filter.max_bytes, Some(4096));
            assert_eq!(filter.after_digest_hex, Some(after_digest.as_str()));
            assert_eq!(filter.finalized.expected_finalized_height, Some(7));
            assert_eq_compact! { filter.finalized.expected_finalized_block_hash_hex => Some(block_hash.as_str()) };
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "manifests": [ { "digest": "aa" } ]
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"manifests\""));
    }
    fn pin_list_with_propagates_error_status() {
        let args = PinListArgs {
            status: None,
            limit: None,
            max_bytes: None,
            after_digest_hex: None,
            expected_finalized_height: None,
            expected_finalized_block_hash_hex: None,
        };
        let mut ctx = TestContext::new();
        let result = args.run_with(&mut ctx, |_client, _| {
json_response_fixture!(StatusCode::BAD_REQUEST,
                    &norito::json!({ "error": "bad request" }),
                )
        });
        assert!(result.is_err());
        assert!(ctx.printed.is_empty());
    }
    fn pin_show_with_handles_not_found() {
        let digest = "33".repeat(32);
        let args = PinShowArgs {
            digest: digest.clone(),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, actual_digest| {
            assert_eq!(actual_digest, digest.as_str());
json_response_fixture!(StatusCode::NOT_FOUND,
                    &norito::json!({ "error": "missing" }),
                )
        })
        .expect("run should succeed for 404");
        assert_eq_compact! { ctx.printed => vec![format!("manifest `{digest}` not found")] };
    }
    fn alias_list_with_prints_payload() {
        let manifest_digest = "44".repeat(32);
        let args = AliasListArgs {
            limit: Some(3),
            offset: Some(0),
            namespace: Some("docs".to_string()),
            manifest_digest: Some(manifest_digest.clone()),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, filter| {
            assert_eq!(filter.limit, Some(3));
            assert_eq!(filter.namespace, Some("docs"));
            assert_eq!(filter.manifest_digest, Some(manifest_digest.as_str()));
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "aliases": [
                        { "alias": "docs/latest", "digest": manifest_digest }
                    ]
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"aliases\""));
    }
    fn replication_list_with_prints_payload() {
        let args = ReplicationListArgs {
            limit: Some(2),
            offset: None,
            status: Some(ReplicationStatusSelector::Completed),
            manifest_digest: None,
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, filter| {
            assert_eq!(filter.status, Some(SorafsReplicationStatus::Completed));
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "orders": [
                        { "id": "order1", "status": "completed" }
                    ]
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"orders\""));
    }
    fn replication_status_cli_is_closed_and_includes_cancelled() {
        use clap::Parser as _;
        #[derive(clap::Parser, Debug)]
        struct Parser {
            #[command(flatten)]
            args: ReplicationListArgs,
        }
        let parsed = Parser::try_parse_from(["sorafs-test", "--status", "cancelled"])
            .expect("cancelled must be part of the first-release status set");
        assert!(matches!(
            parsed.args.status,
            Some(ReplicationStatusSelector::Cancelled)
        ));
        let error = Parser::try_parse_from(["sorafs-test", "--status", "Completed"])
            .expect_err("status parsing must remain exact and case-sensitive");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }
    fn pin_and_inventory_cli_reject_noncanonical_digests_before_fetch() {
        let mut ctx = TestContext::new();
        let pin_result = PinShowArgs {
            digest: "deadbeef".to_owned(),
        }
        .run_with(&mut ctx, |_client, _digest| {
            panic!("invalid pin digest must fail before fetch")
        });
        assert!(
            pin_result
                .expect_err("short pin digest must fail")
                .to_string()
                .contains("64 lowercase")
        );

        let alias_result = AliasListArgs {
            limit: None,
            offset: None,
            namespace: None,
            manifest_digest: Some("AA".repeat(32)),
        }
        .run_with(&mut ctx, |_client, _filter| {
            panic!("invalid alias digest must fail before fetch")
        });
        assert!(
            alias_result
                .expect_err("uppercase alias digest must fail")
                .to_string()
                .contains("64 lowercase")
        );

        let replication_result = ReplicationListArgs {
            limit: None,
            offset: None,
            status: Some(ReplicationStatusSelector::Pending),
            manifest_digest: Some("00".repeat(32)),
        }
        .run_with(&mut ctx, |_client, _filter| {
            panic!("invalid replication digest must fail before fetch")
        });
        assert!(
            replication_result
                .expect_err("zero replication digest must fail")
                .to_string()
                .contains("non-zero")
        );

        let pin_list_result = PinListArgs {
            status: None,
            limit: None,
            max_bytes: None,
            after_digest_hex: Some("abc123".to_owned()),
            expected_finalized_height: None,
            expected_finalized_block_hash_hex: None,
        }
        .run_with(&mut ctx, |_client, _filter| {
            panic!("invalid pin-list cursor must fail before fetch")
        });
        assert!(
            pin_list_result
                .expect_err("short pin-list cursor must fail")
                .to_string()
                .contains("64 lowercase")
        );
    }
    fn transparency_cycles_list_prints_payload() {
        let args = TransparencyCyclesListArgs { limit: Some(8) };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, filter| {
            assert_eq!(filter.limit, Some(8));
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "cycles": [
                        { "cycle_id_hex": "aa" }
                    ]
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"cycles\""));
    }
    fn transparency_cycles_get_normalizes_cycle_id() {
        let args = TransparencyCyclesGetArgs {
            cycle_id: format!(" 0x{} ", "AA".repeat(16)),
            limit: Some(3),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, cycle_id, filter| {
            assert_eq!(cycle_id, "aa".repeat(16));
            assert_eq!(filter.limit, Some(3));
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "cycle_id_hex": "aa"
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"cycle_id_hex\""));
    }
    fn transparency_cycles_entry_normalizes_identifiers() {
        let args = TransparencyCyclesEntryArgs {
            cycle_id: format!(" 0x{} ", "AB".repeat(16)),
            entry_id: format!(" 0x{} ", "CD".repeat(16)),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, cycle_id, entry_id| {
            assert_eq!(cycle_id, "ab".repeat(16));
            assert_eq!(entry_id, "cd".repeat(16));
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "entry_id_hex": "bb"
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"entry_id_hex\""));
    }
    fn transparency_explorer_prints_payload() {
        let args = TransparencyExplorerArgs { limit: Some(5) };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, filter| {
            assert_eq!(filter.limit, Some(5));
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "schema": "sorafs.transparency.explorer_snapshot.v1"
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("explorer_snapshot"));
    }
    }
fn transparency_explorer_canary_fixture_json(
    value: Value,
) -> Result<TransparencyExplorerCanaryHttpResponse> {
    Ok(TransparencyExplorerCanaryHttpResponse {
        status: StatusCode::OK,
        content_type: Some("application/json".to_string()),
        body: norito::json::to_vec(&value)?,
    })
}
fn transparency_explorer_canary_fixture_response(
    url: &str,
    include_private_key: bool,
) -> Result<TransparencyExplorerCanaryHttpResponse> {
    let parsed = Url::parse(url).expect("canary URL should parse");
    let path = parsed.path();
    if path.ends_with("/v1/sorafs/transparency/explorer") {
        assert_eq_compact! { parsed.query_pairs().find(|(key, _)| key == "limit").map(|(_, value)| value.into_owned()) => Some("6".to_string()) };
        let value = if include_private_key {
            norito::json!({
                "schema": "sorafs.transparency.explorer_snapshot.v1",
                "payload_bytes_included": false,
                "private_digest_keys_included": false,
                "proof_token_issuances": [
                    { "proof_token_digest_key": "must-not-ship" }
                ]
            })
        } else {
            norito::json!({
                "schema": "sorafs.transparency.explorer_snapshot.v1",
                "payload_bytes_included": false,
                "private_digest_keys_included": false,
                "cycles": [],
                "proof_token_issuances": []
            })
        };
        return transparency_explorer_canary_fixture_json(value);
    }
    if path.ends_with("/v1/sorafs/transparency/explorer/ui") {
        return Ok(TransparencyExplorerCanaryHttpResponse {
            status: StatusCode::OK,
            content_type: Some("text/html; charset=utf-8".to_string()),
            body: b"<main><h1>SoraFS Transparency Explorer</h1></main>".to_vec(),
        });
    }
    if path.ends_with("/v1/sorafs/transparency/tokens") {
        assert_eq_compact! { parsed.query_pairs().find(|(key, _)| key == "limit").map(|(_, value)| value.into_owned()) => Some("6".to_string()) };
        return transparency_explorer_canary_fixture_json(norito::json!({
            "schema": "sorafs.transparency.proof_token_issuances.v1",
            "payload_bytes_included": false,
            "private_digest_keys_included": false,
            "entries": []
        }));
    }
    panic!("unexpected transparency explorer canary route: {url}");
}
#[test]
fn transparency_explorer_canary_builds_payload_free_evidence() {
    let out_dir = TempDir::new().expect("canary evidence dir");
    let out = out_dir.path().join("nested/evidence.json");
    let args = TransparencyExplorerCanaryArgs {
        torii_url: Some(" https://torii.test/root ".to_string()),
        limit: Some(6),
        timeout_secs: 1,
        out: Some(out.clone()),
    };
    let mut ctx = TestContext::new();
    let mut requested = Vec::new();
    args.run_with_fetch(&mut ctx, |url| {
        requested.push(url.to_string());
        transparency_explorer_canary_fixture_response(url, false)
    })
    .expect("transparency explorer canary should render evidence");
    assert_eq!(requested.len(), 3);
    assert_eq!(ctx.printed.len(), 1);
    assert!(!ctx.printed[0].contains("proof_token_digest_key"));
    let value: Value = norito::json::from_str(&ctx.printed[0]).expect("canary evidence JSON");
    let schema = value["schema"].as_str();
    assert_eq!(schema, Some("sorafs.transparency.explorer_canary.v1"));
    assert_eq!(value["status"].as_str(), Some("passed"));
    assert_eq!(value["limit"].as_u64(), Some(6));
    assert_eq!(value["route_count"].as_u64(), Some(3));
    assert_eq!(value["payload_bytes_included"].as_bool(), Some(false));
    assert_eq!(value["private_digest_keys_included"].as_bool(), Some(false));
    let routes = value["routes"].as_array().expect("canary routes");
    for name in ["browser_ui", "proof_token_issuance_index"] {
        let found = routes
            .iter()
            .any(|route| route["name"].as_str() == Some(name));
        assert!(found);
    }
    let explorer = routes
        .iter()
        .find(|route| route["name"].as_str() == Some("explorer_snapshot"))
        .expect("explorer route evidence");
    let explorer_url = explorer["url"].as_str().expect("explorer URL");
    assert!(explorer_url.contains("/root/v1/sorafs/transparency/explorer"));
    assert!(explorer_url.contains("limit=6"));
    let bytes = fs::read(out).expect("written canary evidence");
    let written: Value = norito::json::from_slice(&bytes).expect("written evidence JSON");
    assert_eq!(written["schema"], value["schema"]);
}
#[test]
fn transparency_explorer_canary_rejects_private_digest_keys() {
    let args = TransparencyExplorerCanaryArgs {
        torii_url: Some("https://torii.test/root".to_string()),
        limit: Some(6),
        timeout_secs: 1,
        out: None,
    };
    let mut ctx = TestContext::new();
    let err = args
        .run_with_fetch(&mut ctx, |url| {
            transparency_explorer_canary_fixture_response(url, true)
        })
        .expect_err("transparency explorer canary must reject private digest keys");
    assert!(err.to_string().contains("digest-key"));
    assert!(ctx.printed.is_empty());
}
fn transparency_publication_canary_fixture_response(
    url: &str,
    include_publisher_identity: bool,
    status: StatusCode,
) -> Result<TransparencyExplorerCanaryHttpResponse> {
    if status != StatusCode::OK {
        return Ok(TransparencyExplorerCanaryHttpResponse {
            status,
            content_type: Some("application/json".to_string()),
            body: br#"{"error":"publication route unavailable must not leak"}"#.to_vec(),
        });
    }
    let parsed = Url::parse(url).expect("publication canary URL should parse");
    assert_eq_compact! { parsed.query_pairs().find(|(key, _)| key == "limit").map(|(_, value)| value.into_owned()) => Some("3".to_string()) };
    let path = parsed.path();
    let cycle_id = "11".repeat(16);
    let publisher_labels = if include_publisher_identity {
        norito::json!({
            "publisher_peer_id": "peer-a",
            "publisher_public_key_hex": ("a1".repeat(32)),
        })
    } else {
        norito::json!({})
    };
    if path.ends_with("/v1/sorafs/transparency/cycles") {
        return transparency_explorer_canary_fixture_json(norito::json!({
            "schema": "sorafs.transparency.cycles.v1",
            "published_cycle_count": 1_u64,
            "returned_cycle_count": 1_u64,
            "limit": 3_u64,
            "truncated": false,
            "cycles": [
                {
                    "cycle_id_hex": cycle_id,
                    "block_hash_hex": ("b2".repeat(32)),
                    "publication_hash_hex": ("c3".repeat(32)),
                    "entry_root_hex": ("d4".repeat(32)),
                    "encoded_blake3": ("e5".repeat(32)),
                    "source_entry": {
                        "labels": publisher_labels
                    }
                }
            ]
        }));
    }
    if path.ends_with(&format!("/v1/sorafs/transparency/cycles/{cycle_id}")) {
        return transparency_explorer_canary_fixture_json(norito::json!({
            "schema": "sorafs.transparency.cycle_publication.v1",
            "cycle_id_hex": cycle_id,
            "encoded_blake3": ("e5".repeat(32)),
            "proof_count": 2_u64,
            "returned_proof_count": 1_u64,
            "limit": 3_u64,
            "truncated_proofs": true,
            "entry": {
                "labels": publisher_labels
            },
            "verification": {
                "valid": true,
                "all_proofs_verified": true,
                "block_hash_hex": ("b2".repeat(32)),
                "publication_hash_hex": ("c3".repeat(32)),
                "entry_root_hex": ("d4".repeat(32)),
                "proof_count": 2_u64
            },
            "publication": {
                "proofs": [
                    { "public_subject": "manifest-must-not-leak" }
                ]
            }
        }));
    }
    panic!("unexpected transparency publication canary route: {url}");
}
test_items! {
    fn transparency_publication_canary_builds_payload_free_evidence() {
        let out_dir = TempDir::new().expect("publication canary evidence dir");
        let out = out_dir.path().join("nested/evidence.json");
        let cycle_id = "11".repeat(16);
        let args = TransparencyPublicationCanaryArgs {
            torii_url: Some(" https://torii.test/root ".to_string()),
            cycle_ids: vec![cycle_id],
            limit: Some(3),
            timeout_secs: 1,
            out: Some(out.clone()),
        };
        let mut ctx = TestContext::new();
        let mut requested = Vec::new();
        args.run_with_fetch(&mut ctx, |url| {
            requested.push(url.to_string());
            transparency_publication_canary_fixture_response(url, true, StatusCode::OK)
        })
        .expect("publication canary should render evidence");
        assert_eq!(requested.len(), 2);
        assert_eq!(ctx.printed.len(), 1);
        assert!(!ctx.printed[0].contains("manifest-must-not-leak"));
        let value: Value =
            norito::json::from_str(&ctx.printed[0]).expect("publication canary evidence JSON");
        let schema = value["schema"].as_str();
        assert_eq!(schema, Some("sorafs.transparency.publication_canary.v1"));
        assert_eq!(value["status"].as_str(), Some("passed"));
        assert_eq!(value["route_count"].as_u64(), Some(2));
        assert_eq!(value["passed_route_count"].as_u64(), Some(2));
        assert_eq!(value["cycle_detail_probe_count"].as_u64(), Some(1));
        assert_eq!(value["publication_bodies_included"].as_bool(), Some(false));
        let routes = value["routes"]
            .as_array()
            .expect("publication canary routes");
        for field in ["anchor_metadata_present", "publisher_identity_present"] {
            let all_present = routes
                .iter()
                .all(|route| route[field].as_bool() == Some(true));
            assert!(all_present);
        }
        let bytes = fs::read(out).expect("written publication canary evidence");
        let written: Value = norito::json::from_slice(&bytes).expect("written evidence JSON");
        assert_eq!(written["schema"], value["schema"]);
    }
    fn transparency_publication_canary_rejects_malformed_cycle_id_before_fetch() {
        let args = TransparencyPublicationCanaryArgs {
            torii_url: Some("https://torii.test/root".to_string()),
            cycle_ids: vec!["not-a-cycle-id".to_string()],
            limit: Some(3),
            timeout_secs: 1,
            out: None,
        };
        let mut ctx = TestContext::new();
        let err = args
            .run_with_fetch(&mut ctx, |_url| {
                panic!("malformed cycle id must fail before HTTP fetch")
            })
            .expect_err("malformed cycle id must be rejected");
        assert_compact! { err.to_string().contains("--cycle-id must be a 16-byte hex string") };
        assert!(ctx.printed.is_empty());
    }
    fn transparency_publication_canary_fails_missing_publisher_identity() {
        let args = TransparencyPublicationCanaryArgs {
            torii_url: Some("https://torii.test/root".to_string()),
            cycle_ids: Vec::new(),
            limit: Some(3),
            timeout_secs: 1,
            out: None,
        };
        let mut ctx = TestContext::new();
        args.run_with_fetch(&mut ctx, |url| {
            transparency_publication_canary_fixture_response(url, false, StatusCode::OK)
        })
        .expect("publication canary should emit failed evidence");
        let value: Value =
            norito::json::from_str(&ctx.printed[0]).expect("publication canary evidence JSON");
        assert_eq!(value.get("status").and_then(Value::as_str), Some("failed"));
        assert_eq!(value["passed_route_count"].as_u64(), Some(0));
        let routes = value["routes"].as_array().expect("routes");
        assert_compact! { routes.iter().all(|route| route["publisher_identity_present"].as_bool() == Some(false)) };
    }
    fn transparency_publication_canary_records_http_failure_without_body() {
        let args = TransparencyPublicationCanaryArgs {
            torii_url: Some("https://torii.test/root".to_string()),
            cycle_ids: Vec::new(),
            limit: Some(3),
            timeout_secs: 1,
            out: None,
        };
        let mut ctx = TestContext::new();
        args.run_with_fetch(&mut ctx, |url| {
            transparency_publication_canary_fixture_response(url, true, StatusCode::BAD_GATEWAY)
        })
        .expect("HTTP failure should still emit canary evidence");
        assert_eq!(ctx.printed.len(), 1);
        assert!(!ctx.printed[0].contains("publication route unavailable"));
        let value: Value =
            norito::json::from_str(&ctx.printed[0]).expect("publication canary evidence JSON");
        assert_eq!(value.get("status").and_then(Value::as_str), Some("failed"));
        assert_eq!(value["passed_route_count"].as_u64(), Some(0));
    }
    fn transparency_tokens_prints_payload() {
        let args = TransparencyTokensArgs { limit: Some(7) };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, filter| {
            assert_eq!(filter.limit, Some(7));
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "entries": [
                        { "payload_kind": "proof_token_issuance" }
                    ]
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"proof_token_issuance\""));
    }
    fn transparency_token_issuance_submit_reads_json_payload() {
        let file = write_json_file(&norito::json!({
            "token_b64": "proof-token-frame",
            "signer_key_hex": ("a1".repeat(32)),
            "evidence_digest_hex": ("b2".repeat(32)),
            "policy_digest_hex": ("c3".repeat(32)),
            "metadata": [
                { "key": "producer", "value": "gateway-a" }
            ]
        }));
        let args = TransparencyTokenIssuanceSubmitArgs {
            payload: file.path().to_path_buf(),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, payload| {
            let value: Value = norito::json::from_slice(payload).expect("payload is json");
            assert_eq_compact! { value.get("token_b64").and_then(Value::as_str) => Some("proof-token-frame") };
            assert_eq_compact! { value.get("signer_key_hex").and_then(Value::as_str) => Some("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1") };
json_response_fixture!(StatusCode::ACCEPTED, &norito::json!({
                    "schema": "sorafs.transparency.proof_token_issuance.ingest.v1"
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("proof_token_issuance"));
    }
    fn transparency_token_issuance_canary_writes_payload_free_evidence() {
        let issuance_file = write_json_file(&norito::json!({
            "token_b64": "proof-token-frame-must-not-leak",
            "signer_key_hex": ("a1".repeat(32)),
            "evidence_digest_hex": ("b2".repeat(32)),
            "policy_digest_hex": ("c3".repeat(32)),
            "metadata": [
                { "key": "producer", "value": "gateway-a" }
            ]
        }));
        let out_dir = TempDir::new().expect("proof-token issuance canary evidence dir");
        let out = out_dir.path().join("nested/evidence.json");
        let args = TransparencyTokenIssuanceCanaryArgs {
            issuances: vec![issuance_file.path().to_path_buf()],
            out: Some(out.clone()),
        };
        let mut ctx = TestContext::new();
        let mut submitted = 0_usize;
        args.run_with(&mut ctx, |_client, payload| {
            submitted += 1;
            let value: Value = norito::json::from_slice(payload).expect("issuance payload JSON");
            assert_eq_compact! { value.get("token_b64").and_then(Value::as_str) => Some("proof-token-frame-must-not-leak") };
json_response_fixture!(StatusCode::ACCEPTED, &norito::json!({
                    "schema": "sorafs.transparency.proof_token_issuance.ingest.v1",
                    "token_id_hex": "token-id-must-not-leak"
                }))
        })
        .expect("proof-token issuance canary should succeed");
        assert_eq!(submitted, 1);
        assert!(out.exists(), "canary evidence should be written");
        assert_eq!(ctx.printed.len(), 1);
        let evidence: Value =
            norito::json::from_str(&ctx.printed[0]).expect("canary evidence JSON");
        assert_eq_compact! { evidence.get("schema").and_then(Value::as_str) => Some("sorafs.transparency.proof_token_issuance.canary.v1") };
        assert_eq_compact! { evidence.get("status").and_then(Value::as_str) => Some("passed") };
        assert_eq!(evidence.get("probe_count").and_then(Value::as_u64), Some(1));
        assert_eq_compact! { evidence.get("passed_probe_count").and_then(Value::as_u64) => Some(1) };
        assert_eq_compact! { evidence.get("issuance_probe_count").and_then(Value::as_u64) => Some(1) };
        assert_eq_compact! { evidence.get("payload_bytes_included").and_then(Value::as_bool) => Some(false) };
        assert_eq_compact! { evidence.get("proof_token_frames_included").and_then(Value::as_bool) => Some(false) };
        assert_eq_compact! { evidence.get("response_bodies_included").and_then(Value::as_bool) => Some(false) };
        assert_compact! { !ctx.printed[0].contains("proof-token-frame-must-not-leak"); "canary evidence must not include proof-token frames" };
        assert_compact! { !ctx.printed[0].contains("token-id-must-not-leak"); "canary evidence must not archive response bodies" };
    }
    fn transparency_token_issuance_canary_records_failed_probe_without_body() {
        let issuance_file = write_json_file(&norito::json!({
            "token_b64": "proof-token-frame-must-not-leak",
            "signer_key_hex": ("a1".repeat(32)),
            "evidence_digest_hex": ("b2".repeat(32)),
            "policy_digest_hex": ("c3".repeat(32)),
        }));
        let args = TransparencyTokenIssuanceCanaryArgs {
            issuances: vec![issuance_file.path().to_path_buf()],
            out: None,
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, _payload| {
json_response_fixture!(StatusCode::BAD_GATEWAY, &norito::json!({
                    "error": "proof-token producer unavailable"
                }))
        })
        .expect("failed probe should still emit canary evidence");
        assert_eq!(ctx.printed.len(), 1);
        let evidence: Value =
            norito::json::from_str(&ctx.printed[0]).expect("canary evidence JSON");
        assert_eq_compact! { evidence.get("status").and_then(Value::as_str) => Some("failed") };
        assert_eq_compact! { evidence.get("passed_probe_count").and_then(Value::as_u64) => Some(0) };
        assert_compact! { !ctx.printed[0].contains("proof-token producer unavailable"); "canary evidence must not archive response bodies" };
    }
    fn transparency_token_issuance_canary_rejects_empty_payload_list() {
        let args = TransparencyTokenIssuanceCanaryArgs {
            issuances: Vec::new(),
            out: None,
        };
        let mut ctx = TestContext::new();
        let err = args
            .run_with(&mut ctx, |_client, _| unreachable!("submit must not run"))
            .expect_err("missing issuance payloads must be rejected");
        assert!(err.to_string().contains("at least one --issuance"));
        assert!(ctx.printed.is_empty());
    }
    fn transparency_privacy_aggregate_source_event_reads_json_payload() {
        let mut file = NamedTempFile::new().expect("privacy aggregate source-event file");
        file.write_all(
            &norito::json::to_vec(&norito::json!({
                "event_id": "privacy-event-1",
                "occurred_at_unix": 1_800_000_500_u64,
                "population_label": "moderation.global",
                "metrics": [
                    { "key": "quarantined", "value": 3_u64 }
                ],
                "policy_digest_hex": ("a1".repeat(32)),
            }))
            .expect("serialize privacy aggregate source-event JSON"),
        )
        .expect("write privacy aggregate source-event JSON");
        let args = TransparencyPrivacyAggregateSourceEventArgs {
            payload: file.path().to_path_buf(),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, payload| {
            let value: Value = norito::json::from_slice(payload).expect("payload is json");
            assert_eq_compact! { value.get("event_id").and_then(Value::as_str) => Some("privacy-event-1") };
            assert_eq_compact! { value.get("population_label").and_then(Value::as_str) => Some("moderation.global") };
json_response_fixture!(StatusCode::ACCEPTED,
                    &norito::json!({ "status": "accepted" }),
                )
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"accepted\""));
    }
    fn transparency_privacy_aggregate_publish_due_reads_json_payload() {
        let mut file = NamedTempFile::new().expect("privacy aggregate publish-due file");
        file.write_all(
            &norito::json::to_vec(&norito::json!({
                "now_unix": 1_800_000_800_u64,
                "previous_block_hash_hex": ("d4".repeat(32)),
            }))
            .expect("serialize privacy aggregate publish-due JSON"),
        )
        .expect("write privacy aggregate publish-due JSON");
        let args = TransparencyPrivacyAggregatePublishDueArgs {
            payload: file.path().to_path_buf(),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, payload| {
            let value: Value = norito::json::from_slice(payload).expect("payload is json");
            assert_eq_compact! { value.get("previous_block_hash_hex").and_then(Value::as_str) => Some("d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4") };
            assert!(value.get("cycle_prf_output_hex").is_none());
json_response_fixture!(StatusCode::OK,
                    &norito::json!({ "status": "published" }),
                )
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"published\""));
    }
    fn transparency_privacy_aggregate_commands_reject_empty_payloads() {
        let file = NamedTempFile::new().expect("empty privacy aggregate file");
        let mut ctx = TestContext::new();
        let source_args = TransparencyPrivacyAggregateSourceEventArgs {
            payload: file.path().to_path_buf(),
        };
        let err = source_args
            .run_with(&mut ctx, |_client, _| unreachable!("submit must not run"))
            .expect_err("empty source-event payload must be rejected");
        assert!(err.to_string().contains("source-event payload"));
        let publish_args = TransparencyPrivacyAggregatePublishDueArgs {
            payload: file.path().to_path_buf(),
        };
        let err = publish_args
            .run_with(&mut ctx, |_client, _| unreachable!("submit must not run"))
            .expect_err("empty publish-due payload must be rejected");
        assert!(err.to_string().contains("publish-due payload"));
        assert!(ctx.printed.is_empty());
    }
    fn transparency_privacy_aggregate_canary_writes_payload_free_evidence() {
        let source_file = write_json_file(&norito::json!({
            "event_id": "privacy-event-1",
            "occurred_at_unix": 1_800_000_500_u64,
            "population_label": "moderation.global",
            "subject_digest_hex": ("b2".repeat(32)),
            "metrics": [
                { "key": "quarantined", "value": 3_u64, "unit": "count" }
            ],
            "policy_digest_hex": ("a1".repeat(32)),
        }));
        let publish_file = write_json_file(&norito::json!({
            "now_unix": 1_800_000_800_u64,
            "previous_block_hash_hex": ("d4".repeat(32)),
        }));
        let out_dir = TempDir::new().expect("privacy aggregate canary evidence dir");
        let out = out_dir.path().join("nested/evidence.json");
        let args = TransparencyPrivacyAggregateCanaryArgs {
            source_events: vec![source_file.path().to_path_buf()],
            publish_due: vec![publish_file.path().to_path_buf()],
            out: Some(out.clone()),
        };
        let mut ctx = TestContext::new();
        let mut submitted_source = 0_usize;
        let mut submitted_publish = 0_usize;
        args.run_with(
            &mut ctx,
            |_client, payload| {
                submitted_source += 1;
                let value: Value = norito::json::from_slice(payload).expect("source payload JSON");
                assert_eq_compact! { value.get("event_id").and_then(Value::as_str) => Some("privacy-event-1") };
json_response_fixture!(StatusCode::ACCEPTED, &norito::json!({
                        "status": "accepted",
                        "event_id": "privacy-event-1"
                    }))
            },
            |_client, payload| {
                submitted_publish += 1;
                let value: Value = norito::json::from_slice(payload).expect("publish payload JSON");
                assert_eq_compact! { value.get("previous_block_hash_hex").and_then(Value::as_str) => Some("d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4") };
                assert!(value.get("cycle_prf_output_hex").is_none());
json_response_fixture!(StatusCode::OK, &norito::json!({
                        "status": "published",
                        "cycle_id_hex": "aa"
                    }))
            },
        )
        .expect("privacy aggregate canary should succeed");
        assert_eq!(submitted_source, 1);
        assert_eq!(submitted_publish, 1);
        assert!(out.exists(), "canary evidence should be written");
        assert_eq!(ctx.printed.len(), 1);
        let evidence: Value =
            norito::json::from_str(&ctx.printed[0]).expect("canary evidence JSON");
        assert_eq_compact! { evidence.get("schema").and_then(Value::as_str) => Some("sorafs.transparency.privacy_aggregate.canary.v1") };
        assert_eq_compact! { evidence.get("status").and_then(Value::as_str) => Some("passed") };
        assert_eq!(evidence.get("probe_count").and_then(Value::as_u64), Some(2));
        assert_eq_compact! { evidence.get("passed_probe_count").and_then(Value::as_u64) => Some(2) };
        assert_eq_compact! { evidence.get("payload_bytes_included").and_then(Value::as_bool) => Some(false) };
        assert_eq_compact! { evidence.get("raw_metric_values_included").and_then(Value::as_bool) => Some(false) };
        assert_compact! { !ctx.printed[0].contains("\"metrics\""); "canary evidence must not include raw metric arrays" };
        assert_compact! { !ctx.printed[0].contains("\"quarantined\""); "canary evidence must not include raw metric names" };
    }
    fn transparency_privacy_aggregate_canary_records_failed_probe_without_body() {
        let publish_file = write_json_file(&norito::json!({
            "now_unix": 1_800_000_800_u64,
            "aggregate_id_prefix": "moderation",
            "privacy_mode": "suppression",
            "suppression_threshold": 4_u64,
        }));
        let args = TransparencyPrivacyAggregateCanaryArgs {
            source_events: Vec::new(),
            publish_due: vec![publish_file.path().to_path_buf()],
            out: None,
        };
        let mut ctx = TestContext::new();
        args.run_with(
            &mut ctx,
            |_client, _payload| unreachable!("source-event submit must not run"),
            |_client, _payload| {
json_response_fixture!(StatusCode::BAD_GATEWAY, &norito::json!({
                        "error": "scheduler unavailable"
                    }))
            },
        )
        .expect("failed probe should still emit canary evidence");
        assert_eq!(ctx.printed.len(), 1);
        let evidence: Value =
            norito::json::from_str(&ctx.printed[0]).expect("canary evidence JSON");
        assert_eq_compact! { evidence.get("status").and_then(Value::as_str) => Some("failed") };
        assert_eq_compact! { evidence.get("passed_probe_count").and_then(Value::as_u64) => Some(0) };
        assert_compact! { !ctx.printed[0].contains("scheduler unavailable"); "canary evidence must not archive response bodies" };
    }
    }
fn write_json_file(value: &Value) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("json file");
    file.write_all(&norito::json::to_vec(value).expect("serialize json"))
        .expect("write json file");
    file
}
test_items! {
    fn appeals_pricing_quote_reads_json_payload() {
        let file = write_json_file(&norito::json!({
            "class": "content",
            "backlog": 4_u64,
            "evidence_size_mb": 12_u64,
            "urgency": "normal"
        }));
        let args = AppealsPricingQuoteArgs {
            input: file.path().to_path_buf(),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, payload| {
            let value: Value = norito::json::from_slice(payload).expect("payload is json");
            assert_eq!(value.get("class").and_then(Value::as_str), Some("content"));
json_response_fixture!(StatusCode::OK,
                    &norito::json!({ "deposit_xor": "123" }),
                )
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("\"123\""));
    }
    fn appeals_finance_deposit_create_reads_json_payload() {
        let file = write_json_file(&norito::json!({
            "case_id": "case-401",
            "payer_account": "payer",
            "destination_account": "treasury",
            "asset_definition_id": "xor#wonderland",
            "deposit_xor": "100",
            "idempotency_key": "case-401-round-7"
        }));
        let args = AppealsFinanceDepositCreateArgs {
            input: file.path().to_path_buf(),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, payload| {
            let value: Value = norito::json::from_slice(payload).expect("payload is json");
            assert_eq_compact! { value.get("case_id").and_then(Value::as_str) => Some("case-401") };
json_response_fixture!(StatusCode::OK,
                    &norito::json!({ "status": "deposit_instruction" }),
                )
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("deposit_instruction"));
    }
    fn appeals_finance_deposit_get_trims_escrow_id() {
        let args = AppealsFinanceDepositGetArgs {
            escrow_id: " 0xAAAA ".to_string(),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, escrow_id| {
            assert_eq!(escrow_id, "0xAAAA");
json_response_fixture!(StatusCode::OK,
                    &norito::json!({ "escrow_id_hex": "aa" }),
                )
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("escrow_id_hex"));
    }
    fn appeals_finance_deposit_submit_settlement_accepts_accepted_status() {
        let file = write_json_file(&norito::json!({
            "deposit_confirmation": {
                "escrow_id_hex": ("11".repeat(32)),
                "case_id": "case-401",
                "payer_account": "payer",
                "destination_account": "treasury",
                "asset_definition_id": "xor#wonderland",
                "deposit_xor": "100",
                "idempotency_key": "case-401-round-7"
            },
            "outcome": "uphold"
        }));
        let args = AppealsFinanceDepositSubmitSettlementArgs {
            input: file.path().to_path_buf(),
        };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, payload| {
            let value: Value = norito::json::from_slice(payload).expect("payload is json");
            assert_eq!(value.get("outcome").and_then(Value::as_str), Some("uphold"));
json_response_fixture!(StatusCode::ACCEPTED,
                    &norito::json!({ "status": "queued" }),
                )
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("queued"));
    }
    fn appeals_finance_reports_list_prints_payload() {
        let args = AppealsFinanceReportsArgs { limit: Some(5) };
        let mut ctx = TestContext::new();
        args.run_with(&mut ctx, |_client, filter| {
            assert_eq!(filter.limit, Some(5));
json_response_fixture!(StatusCode::OK, &norito::json!({
                    "entries": [
                        { "payload_kind": "appeal_finance_report" }
                    ]
                }))
        })
        .expect("run should succeed");
        assert_eq!(ctx.printed.len(), 1);
        assert!(ctx.printed[0].contains("appeal_finance_report"));
    }
    fn appeals_finance_deposit_create_rejects_empty_payload() {
        let file = NamedTempFile::new().expect("empty payload");
        let args = AppealsFinanceDepositCreateArgs {
            input: file.path().to_path_buf(),
        };
        let mut ctx = TestContext::new();
        let err = args
            .run_with(&mut ctx, |_client, _| unreachable!("submit must not run"))
            .expect_err("empty payload must be rejected");
        assert!(err.to_string().contains("appeal finance deposit payload"));
        assert!(ctx.printed.is_empty());
    }
    }
fn signed_moderation_repro_manifest_fixture() -> ModerationReproManifestV1 {
    use iroha_data_model::sorafs::moderation::{
        MODERATION_REPRO_MANIFEST_VERSION_V1, ModerationModelFingerprintV1, ModerationReproBodyV1,
        ModerationReproSignatureV1, ModerationSeedMaterialV1, ModerationThresholdsV1,
    };
    let mut body = ModerationReproBodyV1 {
        schema_version: MODERATION_REPRO_MANIFEST_VERSION_V1,
        manifest_id: [0xA1; 16],
        manifest_digest: [0xB2; 32],
        runner_hash: [0xC3; 32],
        runtime_version: "sorafs-ai-runner cli-test".to_string(),
        issued_at_unix: 1_800_000_000,
        seed_material: ModerationSeedMaterialV1 {
            domain_tag: "sfm4a:cli-test".to_string(),
            seed_version: 1,
            run_nonce: [0xD4; 32],
        },
        thresholds: ModerationThresholdsV1 {
            quarantine: 6_000,
            escalate: 8_500,
        },
        models: vec![ModerationModelFingerprintV1 {
            model_id: [0x11; 16],
            artifact_path: "models/model-11.norito".to_string(),
            artifact_bytes: 1,
            artifact_digest: [0x22; 32],
            weights_digest: [0x33; 32],
            engine: iroha_data_model::sorafs::moderation::ModerationModelEngineV1::DeterministicLinearV1,
            feature_profile: iroha_data_model::sorafs::moderation::ModerationFeatureProfileV1::ByteHistogramAndBigramV1,
            calibration_knot_count: 2,
            max_input_bytes: 1024,
            max_operations: 3073,
            working_memory_bytes: 4096,
            weight: Some(10_000),
        }],
        notes: Some("cli registry fixture".to_string()),
    };
    body.refresh_manifest_digest()
        .expect("refresh moderation fixture digest");
    let keypair = KeyPair::try_from_seed(vec![0xE5; 32], Algorithm::Ed25519)
        .expect("derive moderation fixture keypair");
    let signature = iroha_crypto::SignatureOf::try_new(keypair.private_key(), &body)
        .expect("sign moderation fixture body");
    ModerationReproManifestV1 {
        body,
        signatures: vec![ModerationReproSignatureV1 {
            role: "council".to_string(),
            public_key: keypair.public_key().clone(),
            signature,
        }],
    }
}
fn adversarial_corpus_manifest_fixture() -> AdversarialCorpusManifestV1 {
    use iroha_data_model::sorafs::moderation::{
        ADVERSARIAL_CORPUS_VERSION_V1, AdversarialPerceptualFamilyV1,
        AdversarialPerceptualVariantV1,
    };
    AdversarialCorpusManifestV1 {
        schema_version: ADVERSARIAL_CORPUS_VERSION_V1,
        issued_at_unix: 1_800_000_100,
        cohort_label: Some("cli-registry-fixture".to_string()),
        families: vec![AdversarialPerceptualFamilyV1 {
            family_id: [0x44; 16],
            description: "jpeg jitter corpus".to_string(),
            variants: vec![AdversarialPerceptualVariantV1 {
                variant_id: [0x55; 16],
                attack_vector: "jpeg_jitter".to_string(),
                reference_cid_b64: None,
                perceptual_hash: Some([0x66; 32]),
                hamming_radius: 8,
                embedding_digest: None,
                notes: Some("cli registry variant".to_string()),
            }],
        }],
    }
}
fn moderation_ballot_reveal_fixture() -> SoraFsModerationBallotRevealV1 {
    use iroha_data_model::sorafs::moderation::{
        SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1, SORAFS_MODERATION_BALLOT_REVEAL_VERSION_V1,
        SoraFsModerationBallotContextV1, SoraFsModerationVoteChoice,
    };
    SoraFsModerationBallotRevealV1 {
        version: SORAFS_MODERATION_BALLOT_REVEAL_VERSION_V1,
        context: SoraFsModerationBallotContextV1 {
            version: SORAFS_MODERATION_BALLOT_CONTEXT_VERSION_V1,
            case_id: "case-401".to_string(),
            evidence_bundle_digest: [0xA1; 32],
            appeal_finance_config_version: "appeal-fee-v1".to_string(),
            panel_roster_hash: [0xB2; 32],
            policy_reference: "moderation-policy-v1".to_string(),
            evidence_uri: Some("dag://evidence/case-401".to_string()),
        },
        round_id: "round-7".to_string(),
        juror_id: "juror-1@moderation".to_string(),
        choice: SoraFsModerationVoteChoice::Overturn,
        nonce: vec![0xC3; 32],
        revealed_at_unix_ms: 0,
    }
}
fn moderation_ballot_reveal_fixture_for_juror(juror_id: &str) -> SoraFsModerationBallotRevealV1 {
    let mut reveal = moderation_ballot_reveal_fixture();
    reveal.juror_id = juror_id.to_string();
    reveal
}
fn moderation_ballot_commit_fixture_for_juror(juror_id: &str) -> SoraFsModerationBallotCommitV1 {
    use iroha_data_model::sorafs::moderation::SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1;
    let reveal = moderation_ballot_reveal_fixture_for_juror(juror_id);
    SoraFsModerationBallotCommitV1 {
        version: SORAFS_MODERATION_BALLOT_COMMIT_VERSION_V1,
        context: reveal.context.clone(),
        round_id: reveal.round_id.clone(),
        juror_id: reveal.juror_id.clone(),
        commitment_blake2b_256: reveal.compute_commitment(),
        committed_at_unix_ms: 0,
    }
}
fn moderation_commit_from_transaction(
    transaction: &SignedTransaction,
) -> SoraFsModerationBallotCommitV1 {
    let iroha_data_model::transaction::Executable::Instructions(instructions) =
        transaction.instructions()
    else {
        panic!("moderation commit transaction must contain instructions");
    };
    assert_eq!(instructions.len(), 1);
    let instruction = instructions[0]
        .as_any()
        .downcast_ref::<SubmitSorafsModerationCommit>()
        .expect("native moderation commit instruction");
    decode_from_bytes(instruction.commit_payload()).expect("decode embedded moderation commit")
}
fn moderation_reveal_from_transaction(
    transaction: &SignedTransaction,
) -> SoraFsModerationBallotRevealV1 {
    let iroha_data_model::transaction::Executable::Instructions(instructions) =
        transaction.instructions()
    else {
        panic!("moderation reveal transaction must contain instructions");
    };
    assert_eq!(instructions.len(), 1);
    let instruction = instructions[0]
        .as_any()
        .downcast_ref::<SubmitSorafsModerationReveal>()
        .expect("native moderation reveal instruction");
    decode_from_bytes(instruction.reveal_payload()).expect("decode embedded moderation reveal")
}
fn moderation_finalization_from_transaction(
    transaction: &SignedTransaction,
) -> &FinalizeSorafsModerationCase {
    let iroha_data_model::transaction::Executable::Instructions(instructions) =
        transaction.instructions()
    else {
        panic!("moderation finalization transaction must contain instructions");
    };
    assert_eq!(instructions.len(), 1);
    instructions[0]
        .as_any()
        .downcast_ref::<FinalizeSorafsModerationCase>()
        .expect("native moderation finalization instruction")
}
fn write_commit_reveal_status_file(
    missing_commit_jurors: &[&str],
    missing_reveal_jurors: &[&str],
    ready_to_tally: bool,
) -> NamedTempFile {
    let status = norito::json!({
        "schema": "sorafs.moderation.quarantine.commit_reveal_status.v1",
        "status": "coordinated",
        "payload_bytes_included": false,
        "private_payloads_included": false,
        "ballots": [{
            "case_id": "case-401",
            "round_id": "round-7",
            "missing_commit_jurors": (
                missing_commit_jurors
                    .iter()
                    .copied()
                    .map(Value::from)
                    .collect::<Vec<_>>()
            ),
            "missing_reveal_jurors": (
                missing_reveal_jurors
                    .iter()
                    .copied()
                    .map(Value::from)
                    .collect::<Vec<_>>()
            ),
            "ready_to_tally": (ready_to_tally)
        }]
    });
    write_json_file(&status)
}
fn juror_notifications_manifest_fixture(private_payload_included: bool) -> Value {
    norito::json!({
        "schema": "sorafs.moderation.quarantine.juror_notifications.v1",
        "source": "juror-plan",
        "status": "ready",
        "quarantine_id_hex": "abababababababababababababababab",
        "planned_juror_count": 1_u64,
        "notification_count": 1_u64,
        "skipped_complete_count": 0_u64,
        "pending_commit_count": 1_u64,
        "pending_reveal_count": 0_u64,
        "delivery_transport": "operator-managed",
        "delivery_semantics": "at-least-once-with-dedup-key",
        "payload_bytes_included": false,
        "private_payloads_included": false,
        "notifications": [{
            "schema": "sorafs.moderation.juror_notification.v1",
            "delivery_id": "notify-1",
            "dedup_key": "sorafs-moderation-juror:notify-1",
            "delivery_status": "ready_for_delivery",
            "delivery_transport": "operator-managed",
            "quarantine_id_hex": "abababababababababababababababab",
            "case_id": "case-401",
            "round_id": "round-7",
            "juror_id": "juror-1@moderation",
            "signed_by": "juror-1@moderation",
            "action": "submit_commit",
            "notification_status": "commit_required",
            "route": "/v1/sorafs/moderation/ballots/commits",
            "cli": ["iroha", "sorafs", "moderation", "ballots", "commit"],
            "subject": "SoraFS moderation commit required",
            "body": "Build the private commit payload locally.",
            "deadline_unix_ms": 1_800_000_200_000_u64,
            "evidence_uri": "dag://evidence/case-401",
            "payload_bytes_included": false,
            "private_payload_included": (private_payload_included),
            "private_payload_source": "juror-local"
        }]
    })
}
