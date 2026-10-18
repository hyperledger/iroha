//! Explicit pre-submit retention by the already-exported native software A owner.
//! This is an artifact-dependent component fixture, never a phone observation.
use super::*;
use iroha_version::codec::DecodeVersioned as _;

fn prepared_wire(row: &norito::json::Value, wire: &[u8], setup_sha: &str, target_sha: &str) {
    assert_eq!(
        row.as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [
            "schema",
            "setup_sha256",
            "registration_sha256",
            "funding_command_sha256",
            "target_sha256",
            "transaction_hash_hex",
            "signed_transaction"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        row["schema"].as_str(),
        Some("iroha.kagemusha.network-activation-prepared.v1")
    );
    assert_eq!(row["setup_sha256"].as_str(), Some(setup_sha));
    assert_eq!(row["target_sha256"].as_str(), Some(target_sha));
    for field in [
        "setup_sha256",
        "registration_sha256",
        "funding_command_sha256",
        "target_sha256",
        "transaction_hash_hex",
    ] {
        assert_ne!(fixed::<32>(&row[field]), [0; 32]);
    }
    let original = &row["signed_transaction"];
    assert_eq!(
        original
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        ["name", "bytes", "sha256"].into_iter().collect()
    );
    assert_eq!(
        original["name"].as_str(),
        Some("funding/activate-signed.wire")
    );
    assert_eq!(original["bytes"].as_u64(), Some(wire.len() as u64));
    assert_eq!(original["sha256"].as_str(), Some(sha(wire).as_str()));
    let transaction =
        iroha_data_model::transaction::SignedTransaction::decode_all_versioned(wire).unwrap();
    assert_eq!(transaction.encode_wire_v1().unwrap(), wire);
    assert_eq!(
        transaction.hash().as_ref(),
        &fixed::<32>(&row["transaction_hash_hex"])
    );
}

#[test]
#[ignore = "requires exact exported software A custody, genuine source admission and network activation-prepared original before H4; never physical-device evidence"]
fn retain_actual_a_activation_before_network_submission() {
    let clock_origin = std::time::Instant::now();
    let output = fresh_output("KAGEMUSHA_NATIVE_ACTIVATION_RETENTION_OUTPUT");
    let sources = Sources::requalify(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let fixture = sources.fixture(&setup, 0);
    let (target_path, target_bytes, target) =
        selected_json("KAGEMUSHA_NATIVE_LOAD_TARGET", TARGET_MAX);
    let public = target_path.parent().unwrap();
    let frames = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let instruction: KagemushaWalletLedgerV1 =
        decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &fixture, &frames, &instruction);
    let bootstrap = target_original(
        public,
        &target,
        "bootstrap.norito",
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    );
    let activation = target_original(
        public,
        &target,
        "activation.norito",
        KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1,
    );
    let (prepared_path, prepared_bytes, prepared) =
        selected_json("KAGEMUSHA_NATIVE_ACTIVATION_PREPARED", TARGET_MAX);
    // The fixed relative role is never taken from untrusted path text.
    let wire = pinned(
        &prepared_path
            .parent()
            .unwrap()
            .join("funding/activate-signed.wire"),
        ORIGINAL_MAX,
        prepared["signed_transaction"]["sha256"].as_str().unwrap(),
    );
    prepared_wire(
        &prepared,
        &wire,
        &setup.manifest_sha256,
        &sha(&target_bytes),
    );
    let invocation = std::env::var("KAGEMUSHA_NATIVE_ACTIVATION_INVOCATION").unwrap();
    assert!(
        invocation.len() == 36
            && invocation.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
    );
    let credential = KagemushaWalletCredentialV1::decode_canonical(
        &frames[0],
        &fixture.config.scheme.scheme_id(),
    )
    .unwrap();
    let device = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential);
    let mut wallet = sources.open(&device, &fixture, &frames);
    let sign_calls = device.platform.with(|state| state.sign_calls);
    assert_eq!(complete(wallet.bootstrap().unwrap()), bootstrap);
    assert_eq!(wallet.activation().unwrap(), activation);
    assert_eq!(
        (
            wallet.snapshot().unwrap().sequence,
            wallet.snapshot().unwrap().owned_balance
        ),
        (0, 0)
    );
    let progress = wallet.retain_activation_attempt(&wire).unwrap();
    let returned_ticks = u64::try_from(clock_origin.elapsed().as_nanos()).unwrap();
    assert_eq!(progress, state::ActivationFinalityProgressV1::NotStarted);
    assert!(returned_ticks > 0);
    assert_eq!(
        device.platform.with(|state| state.sign_calls),
        sign_calls,
        "retention must not recreate Bootstrap or sign"
    );
    drop(wallet);
    // Reopen the same durable owner and independently observe retention before publishing.
    let mut wallet = sources.open(&device, &fixture, &frames);
    assert_eq!(
        wallet.activation_finality_progress(&wire).unwrap(),
        state::ActivationFinalityProgressV1::NotStarted
    );
    assert_eq!(wallet.activation().unwrap(), activation);
    assert_eq!(device.platform.with(|state| state.sign_calls), sign_calls);
    let receipt = norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.wallet-activation-retained.v1", "action":"retain-activation",
        "signedWireSHA256":(sha(&wire)), "signedWireBytes":(wire.len().to_string()), "nativeResult":"not_started",
        "nativeReturnedTicks":(returned_ticks.to_string()), "invocation":invocation, "sequence":"0"
    })).unwrap();
    let directory = PrivateDirectory::open_exact(&output).unwrap();
    directory
        .write_atomic("signed-activation.wire", &wire, PublishMode::CreateNew)
        .unwrap();
    directory
        .write_atomic(
            "activation-prepared.json",
            &prepared_bytes,
            PublishMode::CreateNew,
        )
        .unwrap();
    directory
        .write_atomic("activation-retained.json", &receipt, PublishMode::CreateNew)
        .unwrap();
    directory.write_atomic("component-scope.json", &norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.native-software-activation-retention.v1", "source_pins":(source_pins()),
        "prepared_sha256":(sha(&prepared_bytes)), "target_sha256":(sha(&target_bytes)), "retention_sha256":(sha(&receipt)),
        "new_payment_signatures":0, "physical_device_qualified":false,
        "clock_origin":"component entry monotonic Instant; ticks are elapsed nanoseconds",
        "scope":"Actual pre-submit Native retention and same-owner reopen using already-exported software A custody; no network submission, new key, payment signature or phone observation."
    })).unwrap(), PublishMode::CreateNew).unwrap();
}

#[test]
fn prepared_original_requires_exact_full_wire_and_target_chain() {
    use iroha_data_model::transaction::{FeePaymentIntent, TransactionBuilder};
    let keys = iroha_crypto::KeyPair::from_seed(vec![41; 32], iroha_crypto::Algorithm::Ed25519);
    let account = iroha_data_model::account::AccountId::new(keys.public_key().clone());
    let network = iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"prepared test"),
    ));
    let transaction = TransactionBuilder::new(
        network,
        account,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "prepared".into(),
    )])
    .sign(keys.private_key());
    let wire = transaction.encode_wire_v1().unwrap();
    let row = norito::json!({"schema":"iroha.kagemusha.network-activation-prepared.v1", "setup_sha256":(sha(b"setup")),
        "registration_sha256":(sha(b"registration")), "funding_command_sha256":(sha(b"command")), "target_sha256":(sha(b"target")),
        "transaction_hash_hex":(hex::encode(transaction.hash().as_ref())),
        "signed_transaction":{"name":"funding/activate-signed.wire", "bytes":(wire.len()), "sha256":(sha(&wire))}});
    prepared_wire(&row, &wire, &sha(b"setup"), &sha(b"target"));
    for (name, value) in [
        ("target_sha256", sha(b"foreign")),
        ("setup_sha256", sha(b"foreign")),
        ("transaction_hash_hex", sha(b"foreign")),
    ] {
        let mut changed = row.clone();
        changed
            .as_object_mut()
            .unwrap()
            .insert(name.into(), value.into());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepared_wire(
                &changed,
                &wire,
                &sha(b"setup"),
                &sha(b"target")
            )))
            .is_err()
        );
    }
    let mut changed = row.clone();
    changed
        .as_object_mut()
        .unwrap()
        .insert("retained".into(), true.into());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepared_wire(
            &changed,
            &wire,
            &sha(b"setup"),
            &sha(b"target")
        )))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepared_wire(
            &row,
            &norito::encode_canonical(&transaction).unwrap(),
            &sha(b"setup"),
            &sha(b"target")
        )))
        .is_err()
    );
}
