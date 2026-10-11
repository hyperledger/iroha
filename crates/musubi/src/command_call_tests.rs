//! Public call grammar and caller-owned artifact/schema binding.
use super::*;
use iroha_primitives::json::Json;
fn fixture() -> (Vec<u8>, ContractAddress) {
    let artifact = kotodama_lang::compiler::Compiler::new().compile_source(
        "seiyaku Example { permission Update;  kotoage fn write(int value) authorize(Update) {} kotoage fn ping() authorize(Update) {} view fn read() authorize(anyone) -> int { return 1; } }",
    ).expect("compile current artifact");
    let key = iroha::crypto::KeyPair::random();
    let authority = iroha_data_model::account::AccountId::new(key.public_key().clone());
    let network = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
        .parse()
        .unwrap();
    let address = ContractAddress::derive(
        &network,
        &authority,
        1,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    (artifact, address)
}
#[test]
fn mutable_call_encodes_local_schema_and_omits_zero_argument_payload() {
    let (artifact, address) = fixture();
    let value = norito::json!({"value": "7"});
    let (intent, payload) =
        trusted_call_intent(&artifact, address.clone(), "write", value.clone()).unwrap();
    assert_eq!(payload, Some(value.clone()));
    assert_eq!(intent.invocation.contract_address, address);
    assert_eq!(
        intent.invocation.expected_code_hash,
        ivm::verify_contract_artifact(&artifact).unwrap().code_hash
    );
    assert!(intent.invocation.arguments.is_some());
    assert_eq!(
        intent
            .metadata
            .get(&"contract_payload".parse::<Name>().unwrap())
            .unwrap(),
        &Json::from_norito_value_ref(&value).unwrap()
    );
    let (_, other) =
        trusted_call_intent(&artifact, address.clone(), "ping", norito::json!({})).unwrap();
    assert!(other.is_none());
    assert!(
        trusted_call_intent(
            &artifact,
            address.clone(),
            "write",
            norito::json!({"wrong": "7"})
        )
        .is_err()
    );
    assert!(trusted_call_intent(&artifact, address.clone(), "ping", value).is_err());
    assert!(trusted_call_intent(&artifact, address.clone(), "read", norito::json!({})).is_err());
    let mut changed = artifact;
    changed[0] ^= 1;
    assert!(
        trusted_call_intent(&changed, address, "write", norito::json!({"value": "7"})).is_err()
    );
}
#[test]
fn mutable_call_cli_requires_new_intent_or_exact_resume() {
    assert!(
        Cli::try_parse_from([
            "musubi",
            "call",
            "--entrypoint",
            "write",
            "--args",
            "{\"value\":\"7\"}"
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["musubi", "call", "--resume", "/private/call"]).is_ok());
    assert!(Cli::try_parse_from(["musubi", "call", "--cancel", "/private/call"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "musubi",
            "call",
            "--resume",
            "/private/call",
            "--cancel",
            "/private/call"
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["musubi", "call"]).is_err());
    assert!(
        Cli::try_parse_from([
            "musubi",
            "call",
            "--resume",
            "/private/call",
            "--entrypoint",
            "other"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "musubi",
            "call",
            "--entrypoint",
            "write",
            "--gas-limit",
            "0"
        ])
        .is_err()
    );
}

fn continuation_network(config: Option<PathBuf>) -> network::SelectedNetwork {
    network::SelectedNetwork {
        name: "other-taira".to_owned(),
        config,
        config_image: None,
        chain_discriminant: 369,
        network_id: None,
        fee_payment: None,
        contracts: BTreeMap::new(),
    }
}

#[test]
fn mutable_call_continuation_retains_quoted_project_network_and_selected_client() {
    let manifest = Path::new("/projects/coffee club/Musubi.toml");
    let journal = Path::new("/projects/coffee club/target/call/exact-journal");
    let network = continuation_network(Some(PathBuf::from("/runtime/owner's wallet/client.toml")));
    assert_eq!(
        deploy::contract_resume_command("call", manifest, &network, journal),
        r#"musubi --manifest-path '/projects/coffee club/Musubi.toml' call --network other-taira --config '/runtime/owner'"'"'s wallet/client.toml' --resume '/projects/coffee club/target/call/exact-journal'"#
    );
    let parsed = Cli::try_parse_from([
        "musubi",
        "--manifest-path",
        manifest.to_str().expect("manifest"),
        "call",
        "--network",
        &network.name,
        "--config",
        network
            .config
            .as_ref()
            .expect("client")
            .to_str()
            .expect("path"),
        "--resume",
        journal.to_str().expect("journal"),
    ])
    .expect("continuation uses exact call resume grammar");
    assert_eq!(parsed.manifest_path.as_deref(), Some(manifest));
    let Command::Call(args) = parsed.command else {
        panic!("call continuation");
    };
    assert_eq!(args.network.as_deref(), Some("other-taira"));
    assert_eq!(args.config, network.config);
    assert_eq!(args.resume.as_deref(), Some(journal));
}

#[test]
fn mutable_call_continuation_without_client_override_keeps_network_selection() {
    let manifest = Path::new("/projects/coffee club/Musubi.toml");
    let journal = Path::new("/projects/coffee club/target/call/exact-journal");
    let network = continuation_network(None);
    assert_eq!(
        deploy::contract_resume_command("call", manifest, &network, journal),
        "musubi --manifest-path '/projects/coffee club/Musubi.toml' call --network other-taira --resume '/projects/coffee club/target/call/exact-journal'"
    );
    let parsed = Cli::try_parse_from([
        "musubi",
        "--manifest-path",
        manifest.to_str().expect("manifest"),
        "call",
        "--network",
        &network.name,
        "--resume",
        journal.to_str().expect("journal"),
    ])
    .expect("configured-network continuation remains valid");
    let Command::Call(args) = parsed.command else {
        panic!("call continuation");
    };
    assert_eq!(args.network.as_deref(), Some("other-taira"));
    assert!(args.config.is_none());
    assert_eq!(args.resume.as_deref(), Some(journal));
}

fn parsed_call(arguments: &[&str]) -> CallArgs {
    let parsed = Cli::try_parse_from(["musubi", "call"].iter().chain(arguments))
        .expect("call grammar accepts the fixture");
    let Command::Call(args) = parsed.command else {
        panic!("call command");
    };
    args
}

fn human_failure(diagnostic: Diagnostic) -> String {
    CommandOutput::failure("call", diagnostic)
        .render(OutputFormat::Human)
        .expect("render call failure")
        .stderr()
        .to_owned()
}

#[test]
fn mutable_call_requires_one_canonical_entrypoint_selector() {
    let args = parsed_call(&["--entrypoint", "write"]);
    assert_eq!(requested_entrypoint(&args).expect("canonical"), "write");
    for selector in ["", " write", "write\t"] {
        let diagnostic = requested_entrypoint(&parsed_call(&["--entrypoint", selector]))
            .expect_err("non-canonical selector");
        assert_eq!(diagnostic.code(), ErrorCode::Usage);
        assert!(human_failure(diagnostic).contains("non-empty canonical selector"));
    }
    let diagnostic = requested_entrypoint(&parsed_call(&["--resume", "/private/call"]))
        .expect_err("a new call names its entrypoint");
    assert_eq!(diagnostic.code(), ErrorCode::Usage);
    assert!(human_failure(diagnostic).contains("call requires --entrypoint"));
}

#[test]
fn mutable_call_builds_online_with_only_the_caller_lock_policy() {
    let args = parsed_call(&[
        "--package",
        "demo/coffee-club",
        "--network",
        "other-taira",
        "--config",
        "/runtime/client.toml",
        "--locked",
        "--entrypoint",
        "write",
    ]);
    let build = call_build_args(&args);
    assert!(build.mode.locked);
    assert!(!build.mode.offline);
    assert!(!build.mode.frozen);
    assert_eq!(
        build.registry.config.as_deref(),
        Some(Path::new("/runtime/client.toml"))
    );
    assert_eq!(build.network.as_deref(), Some("other-taira"));
    assert_eq!(build.chain_discriminant, None);
    assert!(!build.selection.workspace);
    assert_eq!(
        build.selection.packages,
        vec![
            "demo/coffee-club"
                .parse::<MusubiPackageSelectorV1>()
                .expect("package")
        ]
    );
    assert!(build.selection.exclude.is_empty());
    let unlocked = call_build_args(&parsed_call(&["--entrypoint", "write"]));
    assert!(!unlocked.mode.locked);
    assert!(unlocked.registry.config.is_none());
    assert!(unlocked.network.is_none());
}

#[test]
fn mutable_call_binds_the_configured_fee_payer_to_its_gas_limit() {
    use iroha::crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        nexus::FeeSponsorProgramId,
        transaction::{FeeChargeKind, FeeChargeLimit},
    };
    let _profile = ChainDiscriminantGuard::enter(369);
    let gas_limit = NonZeroU64::new(1_500_000).expect("gas limit");
    let mut network = continuation_network(None);
    let missing = gas_limited_fee_payment(&network, gas_limit).expect_err("explicit payer");
    assert_eq!(missing.code(), ErrorCode::Usage);
    let limits = vec![FeeChargeLimit {
        kind: FeeChargeKind::Nexus,
        asset_definition_id: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().expect("asset"),
        max_amount: "2".parse().expect("fee"),
    }];
    network.fee_payment = Some(FeePaymentIntent::authority(limits.clone(), None));
    assert_eq!(
        gas_limited_fee_payment(&network, gas_limit).expect("authority payer"),
        FeePaymentIntent::authority(limits.clone(), Some(gas_limit))
    );
    let key = KeyPair::try_from_seed(vec![3; 32], Algorithm::Ed25519).expect("test key");
    let sponsor = FeeSponsorProgramId::new(
        AccountId::new(key.public_key().clone()),
        "coffee-fees".parse().expect("program name"),
    );
    network.fee_payment = Some(FeePaymentIntent::sponsor(
        sponsor.clone(),
        7,
        limits.clone(),
        NonZeroU64::new(9),
    ));
    assert_eq!(
        gas_limited_fee_payment(&network, gas_limit).expect("sponsor payer"),
        FeePaymentIntent::sponsor(sponsor, 7, limits, Some(gas_limit))
    );
}

#[test]
fn mutable_call_failure_keeps_the_redacted_cause_chain() {
    let diagnostic = call_diagnostic(
        &eyre::eyre!("route_unavailable; private_key=secret-value").wrap_err("call failed"),
    );
    assert_eq!(diagnostic.code(), ErrorCode::Network);
    let rendered = human_failure(diagnostic);
    assert!(rendered.contains("call failed"), "{rendered}");
    assert!(rendered.contains("route_unavailable"), "{rendered}");
    assert!(!rendered.contains("secret-value"), "{rendered}");
}

#[test]
fn gas_limit_follows_the_simulation_before_anything_is_signed() {
    let executed = CallSimulation::Executed { gas_used: 100_000 };
    let (limit, note) = choose_gas_limit(None, &executed).expect("simulated budget");
    assert_eq!(limit, 160_000);
    assert!(
        note.contains("Simulated gas: 100000; gas limit: 160000"),
        "{note}"
    );
    assert_eq!(
        choose_gas_limit(Some(200_000), &executed)
            .expect("requested budget")
            .0,
        200_000
    );
    let too_small = choose_gas_limit(Some(99_999), &executed).expect_err("below simulation");
    assert_eq!(too_small.code(), ErrorCode::Usage);
    assert!(human_failure(too_small).contains("pass at least 160000"));
    let rejected = choose_gas_limit(
        None,
        &CallSimulation::Rejected {
            message: "contract rejected: ZeroStep".to_owned(),
            gas_used: 12,
        },
    )
    .expect_err("rejected simulation stops the call");
    let rendered = human_failure(rejected);
    assert!(
        rendered.contains("nothing was signed or submitted"),
        "{rendered}"
    );
    assert!(rendered.contains("ZeroStep"), "{rendered}");
    let (limit, note) =
        choose_gas_limit(None, &CallSimulation::RequiresSelfGrant).expect("unsimulated default");
    assert_eq!(
        limit,
        iroha_contract_deploy::call::UNSIMULATED_CALL_GAS_LIMIT
    );
    assert!(note.contains("pass --gas-limit"), "{note}");
    assert_eq!(
        choose_gas_limit(Some(42), &CallSimulation::RequiresSelfGrant)
            .expect("requested")
            .0,
        42
    );
    assert!(parsed_call(&["--entrypoint", "write"]).gas_limit.is_none());
    assert!(
        Cli::try_parse_from([
            "musubi",
            "call",
            "--entrypoint",
            "write",
            "--gas-limit",
            "10000001"
        ])
        .is_err()
    );
}

#[test]
fn receipts_report_the_settled_gas_and_fee() {
    let mut evidence = iroha_contract_deploy::AppliedEvidence {
        hash: "hash".to_owned(),
        terminal_kind: "Applied".to_owned(),
        block_height: 3,
        scope: "global".to_owned(),
        resolved_from: "state".to_owned(),
        charge: None,
    };
    assert_eq!(
        charge_line("Call", &evidence),
        "Call: gas and fee not reported by the node\n"
    );
    evidence.charge = Some(iroha_contract_deploy::AppliedCharge {
        gas_used: 4_321,
        fee_asset: "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse().expect("asset"),
        fee_amount: "3".parse().expect("fee"),
    });
    assert_eq!(
        charge_line("Call", &evidence),
        "Call: gas used 4321; fee 3 6TEAJqbb8oEPmLncoNiMRbLEK6tw\n"
    );
}

#[test]
fn call_view_and_activation_share_args_and_args_file() {
    let dir = tempfile::tempdir().expect("argument directory");
    let file = dir.path().join("arguments.json");
    fs::write(&file, "{\"step\":\"2\"}").expect("argument file");
    assert_eq!(
        argument_source(Some("{}"), Some(&file)).expect("file arguments"),
        "{\"step\":\"2\"}"
    );
    assert_eq!(
        argument_source(Some("{\"step\":\"1\"}"), None).expect("inline arguments"),
        "{\"step\":\"1\"}"
    );
    assert_eq!(argument_source(None, None).expect("no arguments"), "{}");
    fs::write(&file, [0xff_u8, 0xfe]).expect("non-UTF-8 file");
    assert_eq!(
        argument_source(None, Some(&file))
            .expect_err("arguments are UTF-8 JSON")
            .code(),
        ErrorCode::Usage
    );
    fs::write(&file, vec![b' '; 64 * 1024 + 1]).expect("oversized file");
    assert!(argument_source(None, Some(&file)).is_err());
    let path = file.to_str().expect("UTF-8 path");
    let parse = |arguments: &[&str]| Cli::try_parse_from(arguments.iter());
    assert_eq!(
        parsed_call(&["--entrypoint", "write", "--args-file", path])
            .args_file
            .as_deref(),
        Some(file.as_path())
    );
    for refused in [
        &[
            "musubi",
            "call",
            "--entrypoint",
            "write",
            "--args",
            "{}",
            "--args-file",
            path,
        ][..],
        &[
            "musubi",
            "view",
            "--contract",
            "c",
            "--entrypoint",
            "read",
            "--args",
            "{}",
            "--args-file",
            path,
        ],
        &["musubi", "deploy", "--args-file", path],
        &[
            "musubi",
            "deploy",
            "--activate",
            "--args",
            "{}",
            "--args-file",
            path,
        ],
    ] {
        assert!(parse(refused).is_err(), "{refused:?}");
    }
    for accepted in [
        &[
            "musubi",
            "view",
            "--contract",
            "c",
            "--entrypoint",
            "read",
            "--args-file",
            path,
        ][..],
        &["musubi", "deploy", "--activate", "--args-file", path],
    ] {
        assert!(parse(accepted).is_ok(), "{accepted:?}");
    }
}
