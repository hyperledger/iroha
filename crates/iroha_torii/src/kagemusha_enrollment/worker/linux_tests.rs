//! Linux descriptor launch and durable worker recovery with signed synthetic evidence.
//!
//! This exercises the production private Python worker, not Apple device or provider
//! qualification. It retains all attempt files, including on failure, under target/qualification.

use super::*;
use iroha_core_zk::kagemusha_wallet_enrollment_v1::{
    PlatformEvidenceV1, PreKeyDispatchV1, RequestBodyV1, RequestV1,
    issuer_worker::{ActionV1, OutcomeV1},
};
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::{account::AccountId, kagemusha::*};
use std::{
    ffi::OsStr,
    fs,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn selected_executable(name: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os(name).expect("explicit Linux test executable required"));
    assert!(path.is_absolute());
    assert_eq!(
        path.canonicalize().unwrap(),
        path,
        "executable path must be canonical"
    );
    path
}

fn run_python(python: &Path, script: &Path, arguments: &[&OsStr]) -> Vec<u8> {
    let output = Command::new(python)
        .args(["-I", "-S", "-B"])
        .arg(script)
        .args(arguments)
        .env_clear()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture/setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn pin(path: &Path) -> [u8; 32] {
    Sha256::digest(fs::read(path).unwrap()).into()
}

fn dispatch(
    provider: &KagemushaEnrollmentProvider,
    account: AccountId,
    asset: KagemushaWalletAssetScopeV1,
) -> PreKeyDispatchV1 {
    PreKeyDispatchV1 {
        version: 1,
        request_id: [21; 32],
        platform: KagemushaEnrollmentPermitPlatformV1::Apple,
        purpose: KagemushaEnrollmentPermitPurposeV1::Fresh,
        client_nonce: [22; 32],
        native_dispatch_nonce: [23; 32],
        manifest_digest: provider.manifest_digest,
        release_digest: provider.release_digest,
        service_origin_digest: provider.service_origin_digest,
        fi_digest: [24; 32],
        actor_digest: [25; 32],
        scheme: provider.scheme,
        app: provider.app.clone(),
        policy: provider.enrollment.for_asset(&asset).unwrap(),
        enrollment_certificate: provider.certificate,
        account,
        asset,
        previous_permit: None,
    }
}

#[test]
#[ignore = "explicit Linux runtime and real private-worker process; synthetic evidence only"]
fn real_descriptor_worker_retains_exact_evidence_after_lost_reply_and_restart() {
    let python = selected_executable("IROHA_KAGEMUSHA_LINUX_TEST_PYTHON");
    let openssl = selected_executable("IROHA_KAGEMUSHA_LINUX_TEST_OPENSSL");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap();
    let package = repo.join("python/iroha_app_attestation");
    let helper = package.join("tests/linux_worker_fixture.py");
    let output_root = repo.join("target/qualification/enrollment-service/linux-worker-tests");
    fs::create_dir_all(&output_root).unwrap();
    let directory = tempfile::tempdir_in(output_root).unwrap().keep();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["pki", "store", "issuer-originals"] {
        let path = directory.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    println!(
        "Linux synthetic worker evidence retained at {}",
        directory.display()
    );
    let fixture = |action: &str, extras: &[&OsStr]| {
        let mut args = vec![
            OsStr::new(action),
            OsStr::new("--directory"),
            directory.as_os_str(),
            OsStr::new("--openssl"),
            openssl.as_os_str(),
        ];
        args.extend_from_slice(extras);
        run_python(&python, &helper, &args)
    };
    fixture("initialize", &[]);
    let archive = directory.join("wallet-e1.pyz");
    let archive_inventory = directory.join("archive-inventory.json");
    run_python(
        &python,
        &package.join("tools/build_wallet_e1_verifier_zipapp.py"),
        &[
            OsStr::new("--package"),
            package.as_os_str(),
            OsStr::new("--output"),
            archive.as_os_str(),
            OsStr::new("--inventory"),
            archive_inventory.as_os_str(),
        ],
    );
    let root = directory.join("pki/root.der");
    let mut provider =
        super::super::test_fixture::provider(directory.join("unused-enrollment-signer"));
    provider.enrollment.platform = KagemushaWalletEnrollmentPlatformV1::Apple {
        attestation_root_sha256: pin(&root),
    };
    provider.worker.python_executable = python.clone();
    provider.worker.python_sha256 = pin(&python);
    provider.worker.verifier_archive = archive.clone();
    provider.worker.verifier_sha256 = pin(&archive);
    provider.worker.openssl_executable = openssl.clone();
    provider.worker.openssl_sha256 = pin(&openssl);
    provider.worker.attestation_root = Some(root);
    provider.worker.store_directory = directory.join("store");
    let asset = super::super::test_fixture::asset(31, 0);
    let account_key = KeyPair::from_seed(vec![43; 32], Algorithm::Ed25519);
    let selected = dispatch(
        &provider,
        AccountId::new(account_key.public_key().clone()),
        asset.clone(),
    );
    selected.validate().unwrap();
    let challenge = KagemushaWalletEnrollmentChallengeV1 {
        version: 1,
        scheme_id: provider.scheme.scheme_id(),
        asset_digest: asset.asset_digest(),
        account_digest: kagemusha_wallet_account_digest_v1(&selected.account).unwrap(),
        app_policy: selected.policy.app_policy,
        enrollment_policy: selected.policy.policy_digest().unwrap(),
        issuer_nonce: [26; 32],
    };
    let created = now_ms();
    let originals = PrivateDirectory::open(&directory.join("issuer-originals")).unwrap();
    let retain = |name: &str, bytes: &[u8]| {
        originals
            .write_atomic(name, bytes, iroha_fs::PublishMode::CreateNew)
            .unwrap();
    };
    retain("dispatch", &norito::encode_canonical(&selected).unwrap());
    retain("challenge", &norito::encode_canonical(&challenge).unwrap());
    retain("created", &created.to_le_bytes());
    let mut owner = PrivateVerifier::open(&provider).unwrap();
    assert!(
        PrivateVerifier::open(&provider).is_err(),
        "exclusive generation custody"
    );
    let configuration = owner.configuration(&provider, &asset).unwrap();
    let journal = configuration.journal([27; 32]).unwrap();
    let incarnation = journal
        .journal_response(&owner.exchange(&provider, &configuration, &journal).unwrap())
        .unwrap();
    assert!(owner.process.is_some(), "real Process::spawn must have run");
    retain("incarnation", &incarnation);
    let preparation = configuration
        .preparation(&selected, challenge, created)
        .unwrap();
    retain("preparation", preparation.original());
    let prepare = preparation.packet(incarnation, [28; 32]).unwrap();
    prepare
        .prepared_response(&owner.exchange(&provider, &configuration, &prepare).unwrap())
        .unwrap();
    drop(owner); // Join the real child and release the retained generation before reopening.
    let prepared: norito::json::Value =
        norito::json::from_slice(&fixture("snapshot", &[])).unwrap();
    assert_eq!(prepared["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(
        prepared["attempts"][0]["preparation"].as_str().unwrap(),
        hex::encode(preparation.original())
    );
    for name in [
        "request_sha256",
        "original",
        "first_dispatch",
        "outcome",
        "result",
    ] {
        assert_eq!(prepared["attempts"][0][name], norito::json::Value::Null);
    }
    assert!(prepared["keys"].as_array().unwrap().is_empty());
    let payment = super::super::test_fixture::public(
        &p256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap(),
    );
    let challenge_hex = hex::encode(challenge.challenge_digest());
    let binding_hex = hex::encode(kagemusha_wallet_enrollment_key_binding_v1(
        &challenge.challenge_digest(),
        &payment,
    ));
    let KagemushaWalletAppIdentityV1::Apple { app_id } = &provider.app.identity else {
        panic!("Apple fixture")
    };
    fixture(
        "evidence",
        &[
            OsStr::new("--challenge"),
            OsStr::new(&challenge_hex),
            OsStr::new("--binding"),
            OsStr::new(&binding_hex),
            OsStr::new("--app-id"),
            OsStr::new(app_id),
        ],
    );
    let key_id: [u8; 32] = fs::read(directory.join("pki/key-id.bin"))
        .unwrap()
        .try_into()
        .unwrap();
    let evidence = PlatformEvidenceV1::Apple {
        key_id,
        attestation: fs::read(directory.join("pki/attestation.bin")).unwrap(),
        key_binding_assertion: fs::read(directory.join("pki/assertion.bin")).unwrap(),
    };
    let body = RequestBodyV1 {
        version: 1,
        challenge,
        marker: KagemushaWalletMarkerV1::enrollment(&challenge, payment).unwrap(),
        app: selected.app.clone(),
        policy: selected.policy.clone(),
        account: selected.account.clone(),
        asset: asset.clone(),
        evidence: norito::encode_canonical(&evidence).unwrap(),
    };
    let account_signature = Signature::try_new(
        account_key.private_key(),
        &body.account_challenge().unwrap(),
    )
    .unwrap()
    .payload()
    .try_into()
    .unwrap();
    let request = RequestV1 {
        body,
        account_signature,
    };
    retain("request", &request.encode().unwrap());
    let verification_time = now_ms(); // After certificate creation; no replaced or future clock.
    retain("verification-time", &verification_time.to_le_bytes());
    let request = configuration
        .request(request, &preparation, verification_time)
        .unwrap();
    retain("worker-request", request.original());
    let mut owner = PrivateVerifier::open(&provider).unwrap();
    assert_eq!(
        owner.configuration(&provider, &asset).unwrap().original(),
        configuration.original()
    );
    let complete_time = now_ms();
    let complete = request
        .packet(ActionV1::Complete, incarnation, [29; 32], complete_time)
        .unwrap();
    // The caller loses the completed reply before decoding or retaining it. This is the
    // post-commit/pre-issuer-retention loss boundary, not a claimed kernel pipe fault.
    drop(
        owner
            .exchange(&provider, &configuration, &complete)
            .unwrap(),
    );
    drop(owner);
    let committed: norito::json::Value =
        norito::json::from_slice(&fixture("snapshot", &[])).unwrap();
    let row = &committed["attempts"][0];
    assert_eq!(row["outcome"].as_str(), Some("evidence"));
    assert_eq!(
        row["original"].as_str().unwrap(),
        hex::encode(request.original())
    );
    assert_eq!(
        row["request_sha256"].as_str().unwrap(),
        hex::encode(Sha256::digest(request.original()))
    );
    assert_eq!(
        row["account_signature"].as_str().unwrap(),
        hex::encode(account_signature)
    );
    assert_eq!(
        row["first_dispatch"].as_str().unwrap(),
        hex::encode(complete_time.to_le_bytes())
    );
    assert_eq!(committed["keys"].as_array().unwrap().len(), 1);
    assert_eq!(committed["keys"][0]["counter"].as_u64(), Some(1));
    assert_eq!(committed["consumed"].as_array().unwrap().len(), 1);
    let result = hex::decode(row["result"].as_str().unwrap()).unwrap();
    drop(request);
    drop(preparation);
    // Reconstruct the selected preparation and E5 from durable originals rather than
    // recapturing keys, evidence or their first retained timestamps.
    let selected: PreKeyDispatchV1 = norito::decode_canonical_with_limits(
        &fs::read(directory.join("issuer-originals/dispatch")).unwrap(),
        norito::canonical_decode_limits(16_384),
    )
    .unwrap();
    let challenge: KagemushaWalletEnrollmentChallengeV1 = norito::decode_canonical_with_limits(
        &fs::read(directory.join("issuer-originals/challenge")).unwrap(),
        norito::canonical_decode_limits(4096),
    )
    .unwrap();
    let created = u64::from_le_bytes(
        fs::read(directory.join("issuer-originals/created"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let verification_time = u64::from_le_bytes(
        fs::read(directory.join("issuer-originals/verification-time"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let incarnation: [u8; 32] = fs::read(directory.join("issuer-originals/incarnation"))
        .unwrap()
        .try_into()
        .unwrap();
    let preparation = configuration
        .preparation(&selected, challenge, created)
        .unwrap();
    assert_eq!(
        preparation.original(),
        fs::read(directory.join("issuer-originals/preparation")).unwrap()
    );
    let restored =
        RequestV1::decode(&fs::read(directory.join("issuer-originals/request")).unwrap()).unwrap();
    let restored = configuration
        .request(restored, &preparation, verification_time)
        .unwrap();
    assert_eq!(
        restored.original(),
        fs::read(directory.join("issuer-originals/worker-request")).unwrap()
    );
    let mut owner = PrivateVerifier::open(&provider).unwrap();
    assert_eq!(
        owner.configuration(&provider, &asset).unwrap().original(),
        configuration.original()
    );
    let journal = configuration.journal([30; 32]).unwrap();
    assert_eq!(
        journal
            .journal_response(&owner.exchange(&provider, &configuration, &journal).unwrap())
            .unwrap(),
        incarnation
    );
    for (index, action) in [ActionV1::Recover, ActionV1::Complete, ActionV1::Inspect]
        .into_iter()
        .enumerate()
    {
        let exchange = restored
            .packet(
                action,
                incarnation,
                [40 + u8::try_from(index).unwrap(); 32],
                now_ms(),
            )
            .unwrap();
        let reply = owner
            .exchange(&provider, &configuration, &exchange)
            .unwrap();
        let OutcomeV1::Evidence(verified) = restored.response(&exchange, &reply).unwrap() else {
            panic!("retained evidence required")
        };
        assert_eq!(
            verified.original_result, result,
            "exact committed original, not a re-encoding"
        );
        assert_eq!(verified.apple_counter, Some((key_id, 1)));
        assert_eq!(verified.evidence.time_ms, complete_time);
        let foreign = restored
            .packet(
                action,
                incarnation,
                [60 + u8::try_from(index).unwrap(); 32],
                now_ms(),
            )
            .unwrap();
        assert!(
            restored.response(&foreign, &reply).is_err(),
            "foreign exchange must not authenticate"
        );
    }
    drop(owner);
    let after: norito::json::Value = norito::json::from_slice(&fixture("snapshot", &[])).unwrap();
    assert_eq!(
        after, committed,
        "recovery cannot consume the Apple counter or rewrite the claim/result"
    );
    // Evidence remains an intermediate worker result: this test does not sign/issue E6.
}
