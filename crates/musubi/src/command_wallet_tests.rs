//! Wallet CLI selection, private custody integration and honest transaction lifecycle output.

use super::*;
use clap::CommandFactory as _;
use iroha::crypto::{Hash, HashOf};
use iroha_wallet::operations::OperationStatus;
use tempfile::TempDir;

fn network() -> WalletNetwork {
    WalletNetwork::new(
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"Musubi wallet test genesis",
        ))),
        TAIRA_CHAIN_ID.into(),
        "https://taira.sora.org".parse().unwrap(),
        369,
    )
    .unwrap()
}

#[test]
fn wallet_cli_exposes_setup_and_exact_transaction_actions() {
    Cli::command().debug_assert();
    for args in [
        vec!["wallet", "create"],
        vec!["wallet", "show"],
        vec!["wallet", "list"],
        vec!["wallet", "balance"],
        vec!["wallet", "fund"],
        vec!["wallet", "namespace", "developer.universal"],
        vec!["wallet", "namespace", "--resume", "/runtime/journal"],
        vec!["wallet", "fund", "--prepare"],
        vec!["wallet", "fund", "--submit", "/runtime/journal"],
        vec!["wallet", "fund", "--resume", "/runtime/journal"],
        vec!["wallet", "send", "--submit", "/runtime/journal"],
        vec!["wallet", "send", "--resume", "/runtime/journal"],
        vec!["wallet", "import", "--config", "/runtime/client.toml"],
        vec!["network", "configure", "taira", "--wallet", "default"],
    ] {
        let argv = std::iter::once("musubi").chain(args.iter().copied());
        assert!(Cli::try_parse_from(argv).is_ok(), "{args:?}");
    }
    for args in [
        vec!["wallet", "send"],
        vec!["wallet", "import"],
        vec![
            "wallet",
            "fund",
            "--prepare",
            "--submit",
            "/runtime/journal",
        ],
        vec![
            "wallet",
            "fund",
            "--submit",
            "/runtime/journal",
            "--resume",
            "/runtime/journal",
        ],
        vec![
            "wallet",
            "send",
            "--resume",
            "/runtime/journal",
            "--fee-program",
            "program",
        ],
        vec![
            "wallet",
            "import",
            "--config",
            "/runtime/client.toml",
            "--network",
            "taira",
        ],
        vec![
            "network",
            "configure",
            "taira",
            "--config",
            "/runtime/client.toml",
            "--wallet",
            "default",
        ],
    ] {
        let argv = std::iter::once("musubi").chain(args.iter().copied());
        assert!(Cli::try_parse_from(argv).is_err(), "{args:?}");
    }
}

#[test]
fn local_wallet_show_and_list_need_no_project_or_live_node() {
    let root = TempDir::new().unwrap();
    let store = WalletStore::open(&root.path().join("wallets"), None).unwrap();
    let info = store.create("alice", &network()).unwrap();
    for command in ["show", "list"] {
        let result = invoke([
            OsString::from("musubi"),
            "wallet".into(),
            "--wallet-dir".into(),
            store.root().as_os_str().into(),
            "--wallet".into(),
            "alice".into(),
            command.into(),
        ]);
        let output = result.output.render(OutputFormat::Human).unwrap();
        assert_eq!(output.exit_code(), 0, "{}", output.stderr());
        assert!(output.stdout().contains(&info.account_id));
        if command == "show" {
            assert!(output.stdout().contains(&info.public_key));
            assert!(output.stdout().contains("Address profile: 369"));
        }
        assert!(!output.stdout().contains("private_key"));
    }
    let selected = open_store(None, Some(store.root())).unwrap();
    assert_eq!(selected.show("alice").unwrap(), info);
    assert!(
        open_store(Some(Path::new("Musubi.toml")), Some(store.root())).is_ok(),
        "a relative explicit manifest with empty textual parent resolves against cwd"
    );
}

#[test]
fn wallet_setup_discovers_without_account_and_missing_policy_never_prepares_a_claim() {
    use std::{
        io::{Read as _, Write as _},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let capabilities = norito::json!({
        "schema_version": 1,
        "network_id": (network().network_id),
        "network_prefix": 369,
        "allowed_signing": ["ed25519"],
        "default_signing": "ed25519",
    });
    let body = norito::json::to_vec(&capabilities).unwrap();
    let server = thread::spawn(move || {
        for (route, status, body) in [
            ("/v1/accounts/capabilities", "200 OK", body),
            ("/v1/accounts/faucet/policy", "404 Not Found", Vec::new()),
        ] {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("wallet discovery request did not arrive: {error}"),
                }
            };
            // BSD-derived platforms (including macOS) let the accepted stream inherit the
            // listener's non-blocking mode; the read timeout below only applies to blocking reads.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let mut buffer = [0; 1024];
                let length = stream.read(&mut buffer).unwrap();
                assert!(length > 0 && request.len() < 8192);
                request.extend_from_slice(&buffer[..length]);
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.starts_with(&format!("get {route} http/1.1\r\n")));
            assert!(!request.contains("authorization:"));
            assert!(!request.contains("x-iroha-signature:"));
            write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    let temporary = TempDir::new().unwrap();
    let directory = temporary.path().join("wallets");
    let create = invoke([
        OsString::from("musubi"),
        "wallet".into(),
        "--wallet-dir".into(),
        directory.as_os_str().into(),
        "create".into(),
        "--torii-url".into(),
        endpoint.into(),
    ])
    .output
    .render(OutputFormat::Human)
    .unwrap();
    assert_eq!(create.exit_code(), 0, "{}", create.stderr());
    assert!(create.stdout().contains("Created default"));
    let fund = invoke([
        OsString::from("musubi"),
        "wallet".into(),
        "--wallet-dir".into(),
        directory.as_os_str().into(),
        "fund".into(),
    ])
    .output
    .render(OutputFormat::Human)
    .unwrap();
    assert_ne!(fund.exit_code(), 0);
    assert!(fund.stderr().contains("HTTP 404"));
    assert!(
        fund.stderr()
            .contains("Deploy the current wallet funding API")
    );
    assert!(!fund.stderr().contains("--submit"));
    assert!(!directory.join("default/operations").exists());
    server.join().unwrap();
}

#[test]
fn network_binding_uses_wallet_and_defaults_to_fee_payment() {
    let temp = TempDir::new().unwrap();
    let package = temp.path().join("project");
    let scaffold = invoke([
        OsString::from("musubi"),
        "new".into(),
        package.as_os_str().into(),
        "--namespace".into(),
        "demo".into(),
    ]);
    assert_eq!(
        scaffold
            .output
            .render(OutputFormat::Human)
            .unwrap()
            .exit_code(),
        0
    );
    let store = WalletStore::open(&temp.path().join("wallets"), Some(&package)).unwrap();
    store.create("alice", &network()).unwrap();
    let result = invoke([
        OsString::from("musubi"),
        "--manifest-path".into(),
        package.join("Musubi.toml").as_os_str().into(),
        "network".into(),
        "configure".into(),
        "taira".into(),
        "--wallet-dir".into(),
        store.root().as_os_str().into(),
        "--wallet".into(),
        "alice".into(),
    ]);
    let output = result.output.render(OutputFormat::Human).unwrap();
    assert_eq!(output.exit_code(), 0, "{}", output.stderr());
    assert!(output.stdout().contains("Fee payer: authority"));
    let text = fs::read_to_string(package.join("Musubi.networks.toml")).unwrap();
    assert!(text.contains("payer = \"authority\""));
    assert!(!text.contains("private_key"));
    let selected = network::select_network(
        &package,
        None,
        None,
        None,
        network::NetworkPurpose::Deployment,
    )
    .unwrap();
    assert_eq!(
        selected.load_client().unwrap().account,
        store.load_config("alice").unwrap().account
    );
}

#[test]
fn prepared_operation_has_submit_and_pending_retains_exact_recovery_evidence() {
    let make = |status| OperationReport {
        status,
        data: norito::json!({
            "transaction_hash": "exact-retained-hash",
            "fee_payment": (FeePaymentIntent::authority(Vec::new(), None)),
        }),
    };
    let journal = Path::new("/runtime/wallets/alice/operations/send-123");
    let prepared = operation_output(
        make(OperationStatus::Prepared),
        journal,
        true,
        "send",
        "alice",
        Path::new("/runtime/wallets"),
    )
    .unwrap();
    assert!(prepared.message.contains("--submit"));
    assert!(prepared.message.contains("--wallet-dir /runtime/wallets"));
    assert!(prepared.message.contains("Maximum fees:"));
    for status in [
        OperationStatus::Absent,
        OperationStatus::Pending,
        OperationStatus::Rejected,
        OperationStatus::Expired,
        OperationStatus::AliasConflict,
    ] {
        let error = operation_output(
            make(status),
            journal,
            false,
            "send",
            "alice",
            Path::new("/runtime/wallets"),
        )
        .err()
        .expect("unresolved operation must fail");
        let failure = CommandOutput::failure("wallet", error)
            .render(OutputFormat::Human)
            .unwrap();
        assert_ne!(failure.exit_code(), 0);
        if matches!(status, OperationStatus::Absent | OperationStatus::Pending) {
            assert!(failure.stderr().contains("--resume"));
        } else {
            assert!(!failure.stderr().contains("--resume"));
            assert!(failure.stderr().contains("prepare a new operation"));
            assert!(failure.stderr().contains("keep this journal as evidence"));
        }
        assert!(failure.stderr().contains("exact-retained-hash"));
    }
    assert!(
        operation_output(
            make(OperationStatus::Applied),
            journal,
            false,
            "send",
            "alice",
            Path::new("/runtime/wallets")
        )
        .is_ok()
    );
}

#[test]
fn wallet_fee_default_is_authority_and_partial_sponsorship_rejects() {
    assert_eq!(
        WalletFeeArgs::default().intent().unwrap(),
        FeePaymentIntent::authority(Vec::new(), None)
    );
    assert!(
        WalletFeeArgs {
            fee_program: None,
            fee_program_revision: Some(1)
        }
        .intent()
        .is_err()
    );
    assert!(
        WalletFeeArgs {
            fee_program: Some("not-a-program".into()),
            fee_program_revision: None
        }
        .intent()
        .is_err()
    );
}

#[test]
fn incompatible_custom_network_arguments_fail_before_contacting_a_node() {
    assert!(
        discover_network(&WalletNetworkArgs {
            network: Some("custom".into()),
            ..WalletNetworkArgs::default()
        })
        .is_err()
    );
    assert!(
        discover_network(&WalletNetworkArgs {
            chain_id: Some("wrong-taira-chain".into()),
            ..WalletNetworkArgs::default()
        })
        .is_err()
    );
}

#[test]
fn public_wallet_next_steps_keep_store_and_network_context() {
    let temp = TempDir::new().unwrap();
    let store = WalletStore::open(&temp.path().join("custom wallets"), None).unwrap();
    let info = store.create("alice", &network()).unwrap();
    let created = wallet_info_output(&info, "Created", store.root()).unwrap();
    assert!(created.message.contains("--wallet-dir"));
    assert!(created.message.contains("--wallet alice fund"));
    let mut custom = info;
    custom.network.chain_id = "custom".to_owned();
    for profile in [369, 42] {
        custom.network.chain_discriminant = profile;
        let output = wallet_info_output(&custom, "Created", store.root()).unwrap();
        assert!(output.message.ends_with("balance"));
    }
}

#[test]
fn fee_review_and_post_prepare_error_are_readable_and_recoverable() {
    use iroha_data_model::transaction::{FeeChargeKind, FeeChargeLimit};
    let intent = FeePaymentIntent::authority(
        vec![FeeChargeLimit {
            kind: FeeChargeKind::Nexus,
            asset_definition_id: XOR_ASSET_DEFINITION.parse().unwrap(),
            max_amount: "0.02".parse().unwrap(),
        }],
        None,
    );
    let review = render_fees(&norito::json::to_value(&intent).unwrap());
    assert!(review.contains("Fee payer: transaction authority"));
    assert!(review.contains("0.02 XOR"));
    assert!(!review.contains('{'));
    for action in ["submit", "resume"] {
        let error = retained_operation_error(
            "observation unavailable",
            Path::new("/runtime/journal"),
            "send",
            action,
            "alice",
            Path::new("/runtime/wallets"),
        );
        let output = CommandOutput::failure("wallet", error)
            .render(OutputFormat::Human)
            .unwrap();
        assert!(
            output
                .stderr()
                .contains(&format!("--{action} /runtime/journal"))
        );
        assert!(output.stderr().contains("--wallet-dir /runtime/wallets"));
        assert!(output.stderr().contains("without another dispatch"));
        if action == "resume" {
            assert!(!output.stderr().contains("--submit"));
        }
    }
}

#[test]
fn execution_deadline_is_readable_for_transfer_and_funding_reports() {
    assert_eq!(
        render_deadline(121_500, 1_000),
        "Execution deadline: in 121 seconds"
    );
    assert_eq!(render_deadline(1_000, 1_000), "Execution deadline: elapsed");
    for key in ["deadline_ms", "expires_at_unix_ms"] {
        let mut data = norito::json::Map::new();
        data.insert(key.to_owned(), Value::from(u64::MAX));
        let report = OperationReport {
            status: OperationStatus::Prepared,
            data: Value::Object(data),
        };
        assert!(
            render_operation(&report, Path::new("/runtime/journal"))
                .contains("Execution deadline: in ")
        );
    }
}
