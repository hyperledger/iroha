//! Fresh all-control-permitted enrollment and genuine Bootstrap target; no finalized Load.
use super::*;

#[test]
#[ignore = "requires the genuine complete52 source grant; exports a target, never a finalized receipt"]
fn export_actual_controls_load_target_with_separate_native_custody() {
    let output = fresh_output("KAGEMUSHA_NATIVE_CONTROLS_TARGET_OUTPUT");
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = permitted(sources.fixture(&setup, 0));
    let device = HostDevice::create(&output.join("wallet-a"), CONTROL_A_SEED);
    let frames = enrollment::enroll(&device, &f);
    let mut wallet = sources.open(&device, &f, &frames);
    let bootstrap = complete(wallet.bootstrap().unwrap());
    assert_eq!(complete(wallet.bootstrap().unwrap()), bootstrap);
    let activation = wallet.activation().unwrap();
    assert_eq!(wallet.activation().unwrap(), activation);
    fold(&mut wallet);
    let snapshot = wallet.snapshot().unwrap();
    assert_eq!((snapshot.sequence, snapshot.owned_balance), (0, 0));
    let instruction = KagemushaWalletLedgerV1::new(
        snapshot.scheme_id,
        KagemushaWalletLedgerActionV1::IssueLoad {
            wallet: snapshot.wallet_id,
            asset: f.asset.asset_digest(),
            ordinal: 0,
            request_id: LOAD_ID,
            amount: LOAD_AMOUNT,
            charge: None,
        },
    );
    let public = output.join("public-target");
    private_dir(&public);
    let mut records = Vec::new();
    for (name, bytes) in FRAME_NAMES.into_iter().zip(&frames).chain([
        ("bootstrap.norito", &bootstrap),
        ("activation.norito", &activation),
        (
            "issue-load.norito",
            &norito::encode_canonical(&instruction).unwrap(),
        ),
    ]) {
        publish(&public.join(name), bytes);
        records
            .push(norito::json!({ "name": name, "bytes": (bytes.len()), "sha256": (sha(bytes)) }));
    }
    drop(wallet);
    device.save_simulator();
    let manifest = norito::json!({
        "schema": TARGET_SCHEMA,
        "variant": "offline-controls-all-masks",
        "scope": "Actual native A with real host storage and proofs; simulated payment hardware and engineering issuer. Target DATA is not a finalized receipt or settlement verdict.",
        "source_pins": (source_pins()),
        "sealed_originals": (source_reuse::locator(&sources.originals)),
        "executed_ledger_setup_sha256": (setup.manifest_sha256),
        "native_source_sha256": (env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "native_binary_sha256": (executable_hash()),
        "native_chain_id": (sources.genesis.chain_id()),
        "native_instance": (hex::encode(sources.genesis.instance().0)),
        "native_initial_epoch_sha256": (sha(&norito::encode_canonical(sources.genesis.initial_epoch()).unwrap())),
        "scheme_id": (hex::encode(snapshot.scheme_id)),
        "manifest_digest": (hex::encode(sources.qualified.installation().1)),
        "wallet_id": (hex::encode(snapshot.wallet_id)),
        "asset_digest": (hex::encode(f.asset.asset_digest())),
        "payer_account_digest": (hex::encode(kagemusha_wallet_account_digest_v1(&f.account).unwrap())),
        "request_id": (hex::encode(LOAD_ID)),
        "ordinal": "0", "amount": "100", "online_charge": "0",
        "charge_quote": (hex::encode([0_u8; 32])),
        "files": records,
    });
    let bytes = norito::json::to_vec(&manifest).unwrap();
    assert!(bytes.len() <= TARGET_MAX);
    publish(&public.join("target.json"), &bytes);
    eprintln!(
        "NATIVE_LOAD_TARGET path={} sha256={} finalized_receipt=false",
        public.join("target.json").display(),
        sha(&bytes)
    );
}
