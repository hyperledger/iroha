//! Artifact-dependent native exchange over real host custody and explicit simulated hardware.
//!
//! The producer and consumer reopen the SAME persisted A incarnation. The private software
//! key fixture is never part of the public Load target. No grant, proof or ledger result is
//! synthesized: the genuine pipeline tests remain ignored until independently pinned artifacts
//! are available. The Load producer and settlement continuation have separate retained owners.

use super::*;
use crate::{
    kagemusha_wallet_artifacts_v1::{
        InstallationV1, InstalledVerifierPackV1,
        producer_inventory::{
            DirectoryOriginalsV1, PROVING_KEY_MAX_BYTES_V1, QualifiedWalletSourcesV1,
            open_pinned_engineering_wallet_sources,
        },
    },
    kagemusha_wallet_state_v1::{
        self as state, Completion, FoldStatus, NativeWalletCoordinatorV1, NativeWalletRuntimeV1,
        OperationActionV1, OperationRequestV1,
    },
};
use iroha_data_model::{
    isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1, KagemushaWalletLoadReceiptV1,
        load_finality::KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
    },
    sumeragi_finality::SumeragiFinalityVerifier,
};
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::keys::pk::{CosetCachePolicy, artifact::ReadConfig};
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};

#[path = "native_exchange/archive.rs"]
mod archive;
#[path = "native_exchange/load.rs"]
mod load;
#[path = "native_exchange/load_seam.rs"]
mod load_seam;
#[path = "native_exchange/network_settlement.rs"]
mod network_settlement;
#[path = "native_exchange/proof_negative.rs"]
mod proof_negative;
#[path = "native_exchange/settlement.rs"]
mod settlement;
#[path = "native_exchange/setup.rs"]
mod setup;
use setup::LedgerSetup;

const TARGET_SCHEMA: &str = "iroha.kagemusha.native-load-target.v1";
const TARGET_MAX: usize = 16 << 10;
const LOAD_ID: [u8; 32] = [201; 32];
const LOAD_AMOUNT: u128 = 100;
const FRAME_NAMES: [&str; 4] = [
    "credential.norito",
    "certificates.norito",
    "account.norito",
    "asset.norito",
];
type Wallet =
    NativeWalletCoordinatorV1<KagemushaWalletStdFsV1, FakePlatformV1, DirectoryOriginalsV1>;
type HostEnrollment = EnrollmentOwnerV1<KagemushaWalletStdFsV1, FakePlatformV1>;

struct Sources {
    installed: Arc<InstalledVerifierPackV1>,
    qualified: Arc<QualifiedWalletSourcesV1>,
    genesis: Arc<SumeragiFinalityVerifier>,
    originals: PathBuf,
}
impl Sources {
    fn admit(output: &Path) -> Self {
        let (installed, qualified, genesis, originals) =
            open_pinned_engineering_wallet_sources(output);
        let path = originals.root().unwrap().to_path_buf();
        drop(originals);
        Self {
            installed,
            qualified,
            genesis: Arc::new(genesis),
            originals: path,
        }
    }
    fn fixture(&self, setup: &LedgerSetup, index: usize) -> Fixture {
        let mut f = fixture();
        f.config.scheme = *self.installed.verifier().scheme();
        assert_eq!(
            f.config.scheme.scheme_root_key,
            public_key(&signing_key(17))
        );
        let (scheme_id, manifest_digest) = self.qualified.installation();
        f.config.installation = InstallationV1 {
            scheme_id,
            manifest_digest,
        };
        f.config.app.scheme_id = scheme_id;
        f.config.policy.scheme_id = scheme_id;
        f.config.policy.app_policy = f.config.app.policy_digest().unwrap();
        f.config.enrollment_certificate = enrollment_certificate(&f.config.scheme);
        f.challenge.scheme_id = scheme_id;
        f.challenge.app_policy = f.config.app.policy_digest().unwrap();
        f.challenge.enrollment_policy = f.config.policy.policy_digest().unwrap();
        setup::bind_identity(
            &mut f,
            setup.accounts[index].clone(),
            setup.asset.clone(),
            [41, 42, 43][index],
        );
        f
    }
    fn open(&self, device: &HostDevice, f: &Fixture, frames: &[Vec<u8>; 4]) -> Wallet {
        let provider = device.provider(f.config.scheme.scheme_id());
        let originals =
            DirectoryOriginalsV1::open_existing(&self.originals, PROVING_KEY_MAX_BYTES_V1).unwrap();
        let runtime = NativeWalletRuntimeV1::new(
            provider,
            Arc::clone(&self.installed),
            Arc::clone(&self.qualified),
            Arc::clone(&self.genesis),
            originals,
            ReadConfig {
                maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
                maximum_rows: 1 << 16,
                coset_cache: CosetCachePolicy::OnDemand,
                msm_budget: MemoryBudget::DEFAULT,
            },
            MemoryBudget::DEFAULT,
        );
        let pending = runtime
            .begin(&frames[0], &frames[1], &frames[2], &frames[3])
            .unwrap();
        let challenge = pending.challenge().to_vec();
        // An ordinary refusal retains the exact pending source/challenge and cannot admit.
        let refusal = pending
            .finish(&[0; 64])
            .err()
            .expect("wrong account signature refused");
        let (runtime, _) = refusal.into_parts();
        let mut changed = frames[2].clone();
        changed.push(0);
        let refusal = runtime
            .begin(&frames[0], &frames[1], &changed, &frames[3])
            .err()
            .expect("changed pending originals refused");
        let (runtime, _) = refusal.into_parts();
        let pending = runtime
            .begin(&frames[0], &frames[1], &frames[2], &frames[3])
            .unwrap();
        assert_eq!(pending.challenge(), challenge);
        pending.finish(&sign(f, &challenge)).unwrap()
    }
}

struct HostDevice {
    root: PathBuf,
    platform: FakePlatformV1,
}
impl HostDevice {
    fn create(root: &Path, seed: u8) -> Self {
        private_dir(root);
        private_dir(&root.join("custody"));
        Self {
            root: root.to_path_buf(),
            platform: FakePlatformV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, seed),
        }
    }
    fn provider(
        &self,
        scheme: [u8; 32],
    ) -> KagemushaWalletProviderV1<KagemushaWalletStdFsV1, FakePlatformV1> {
        KagemushaWalletProviderV1::open(
            KagemushaWalletStdFsV1::open(self.root.join("custody")).unwrap(),
            self.platform.clone(),
            scheme,
            test_options(),
        )
        .unwrap()
    }
    fn enroll(&self, f: &Fixture) -> [Vec<u8>; 4] {
        let mut owner: HostEnrollment =
            EnrollmentOwnerV1::new(self.provider(f.config.scheme.scheme_id()), f.config.clone())
                .unwrap_or_else(|(_, error)| panic!("{error}"));
        let dispatch = PreKeyDispatchV1::decode(
            &owner
                .begin(
                    &[11; 32],
                    &norito::encode_canonical(&f.account).unwrap(),
                    &norito::encode_canonical(&f.asset).unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        let challenge = owner
            .accept_permit(&permit(f, &dispatch).encode_canonical().unwrap())
            .unwrap();
        assert!(matches!(
            owner.authorize(&sign(f, &challenge)).unwrap(),
            EnrollmentProgressV1::Evidence { .. }
        ));
        let RequestPreparationV1::AccountChallenge(challenge) =
            owner.prepare_request(&f.evidence).unwrap()
        else {
            panic!("fresh E5 challenge")
        };
        let request =
            RequestV1::decode(&owner.retain_request(&sign(f, &challenge)).unwrap()).unwrap();
        owner
            .accept_credential(&issuer_result(f, &request).encode().unwrap())
            .unwrap();
        let frames = owner.open_originals().unwrap();
        drop(owner);
        frames
    }
    fn save_simulator(&self) {
        // Test-only software hardware custody, in a separate private original. Production
        // platforms cannot export keys; no cryptographic fixture key is public target DATA.
        let keys: Vec<([u8; 32], [u8; 32])> = self.platform.with(|state| {
            state
                .keys
                .iter()
                .map(|(slot, key)| (slot.0, key.to_bytes().into()))
                .collect()
        });
        assert_eq!(keys.len(), 1);
        publish(
            &self.root.join("simulator-key.norito"),
            &norito::encode_canonical(&keys).unwrap(),
        );
    }
    fn restore(root: &Path, credential: &KagemushaWalletCredentialV1) -> Self {
        let keys: Vec<([u8; 32], [u8; 32])> =
            decode(&iroha_fs::read_private(root.join("simulator-key.norito"), 1024).unwrap());
        assert_eq!(keys.len(), 1);
        let platform = FakePlatformV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 0);
        platform.with(|state| {
            for (slot, key) in keys {
                let key = p256::ecdsa::SigningKey::from_slice(&key).unwrap();
                assert_eq!(public_key(&key), credential.body.payment_key);
                state.keys.insert(KagemushaWalletSlotIdV1(slot), key);
            }
        });
        Self {
            root: root.to_path_buf(),
            platform,
        }
    }
}

fn qualification_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/qualification")
        .canonicalize()
        .unwrap()
}
fn selected_path(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} required")));
    assert!(path.is_absolute());
    assert!(
        path.parent()
            .unwrap()
            .canonicalize()
            .unwrap()
            .starts_with(qualification_root())
    );
    path
}
fn fresh_output(name: &str) -> PathBuf {
    let path = selected_path(name);
    private_dir(&path);
    path
}
fn private_dir(path: &Path) {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .expect("fresh private output, never overwrite");
}
fn publish(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
fn decode<T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>>(bytes: &[u8]) -> T {
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .unwrap()
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read_pin(path: &Path, maximum: usize, expected: &str) -> Vec<u8> {
    let bytes = iroha_fs::read_regular(path, maximum).unwrap().to_vec();
    assert_eq!(sha(&bytes), expected, "independently selected original pin");
    bytes
}
fn env_pin(name: &str) -> String {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("{name} required"));
    assert_eq!(hex::decode(&value).unwrap().len(), 32);
    value
}
fn complete(result: Completion) -> Vec<u8> {
    let Completion::Complete(bytes) = result else {
        panic!("not a durable completion: {result:?}")
    };
    bytes
}
fn action(id: u8, action: OperationActionV1) -> OperationRequestV1 {
    OperationRequestV1 {
        request_id: [id; 32],
        action,
    }
}
fn fold(wallet: &mut Wallet) {
    wallet.scheduler().set_activity(true, false);
    // Fixed operation schedules are bounded; a broken scheduler must fail, not spin forever.
    for _ in 0..1024 {
        let result = wallet.fold_once().unwrap();
        eprintln!("NATIVE_EXCHANGE_FOLD {result:?}");
        if result == FoldStatus::CaughtUp {
            let snapshot = wallet.snapshot().unwrap();
            assert_eq!(snapshot.fold_backlog, 0);
            assert_eq!(snapshot.folded_balance, Some(snapshot.owned_balance));
            return;
        }
        assert_ne!(result, FoldStatus::Idle);
    }
    panic!("bounded native fold schedule did not complete");
}

const SOURCE_PINS: [&str; 7] = [
    "KAGEMUSHA_SIGNED_GENESIS_FIXTURE_SHA256",
    "KAGEMUSHA_WALLET_CATALOG_PRODUCER_SHA256",
    "KAGEMUSHA_WALLET_CATALOG_SOURCE_SHA256",
    "KAGEMUSHA_WALLET_CATALOG_INVENTORY_SHA256",
    "KAGEMUSHA_WALLET_CATALOG_PACK_SHA256",
    "KAGEMUSHA_WALLET_SCHEME_ID",
    "KAGEMUSHA_WALLET_MANIFEST_DIGEST",
];
fn source_pins() -> norito::json::Value {
    norito::json::to_value(
        &SOURCE_PINS
            .into_iter()
            .map(|name| (name, env_pin(name)))
            .collect::<std::collections::BTreeMap<_, _>>(),
    )
    .unwrap()
}
fn executable_hash() -> String {
    use std::io::Read as _;
    let mut file = fs::File::open(std::env::current_exe().unwrap()).unwrap();
    let mut hash = Sha256::new();
    let mut bytes = [0_u8; 65536];
    loop {
        let length = file.read(&mut bytes).unwrap();
        if length == 0 {
            break;
        }
        hash.update(&bytes[..length]);
    }
    hex::encode(hash.finalize())
}

#[test]
#[ignore = "requires the genuine complete52 source grant; exports a target, never a finalized receipt"]
fn export_actual_a_load_target_with_retained_native_custody() {
    let output = fresh_output("KAGEMUSHA_NATIVE_LOAD_TARGET_OUTPUT");
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let device = HostDevice::create(&output.join("wallet-a"), 83);
    let frames = device.enroll(&f);
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
        "scope": "Actual native A with real host storage and proofs; simulated payment hardware and engineering issuer. Target DATA is not a finalized receipt or settlement verdict.",
        "source_pins": (source_pins()),
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

fn target_original(
    directory: &Path,
    manifest: &norito::json::Value,
    name: &str,
    maximum: usize,
) -> Vec<u8> {
    let rows = manifest["files"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .filter(|row| row["name"].as_str() == Some(name))
            .count(),
        1
    );
    let row = rows
        .iter()
        .find(|row| row["name"].as_str() == Some(name))
        .unwrap();
    let bytes = read_pin(
        &directory.join(name),
        maximum,
        row["sha256"].as_str().unwrap(),
    );
    assert_eq!(bytes.len() as u64, row["bytes"].as_u64().unwrap());
    bytes
}
fn require_target(
    manifest: &norito::json::Value,
    sources: &Sources,
    setup: &LedgerSetup,
    f: &Fixture,
    frames: &[Vec<u8>; 4],
    instruction: &KagemushaWalletLedgerV1,
) {
    assert_eq!(manifest["schema"].as_str(), Some(TARGET_SCHEMA));
    assert_eq!(manifest["source_pins"], source_pins());
    assert_eq!(
        manifest["executed_ledger_setup_sha256"].as_str(),
        Some(setup.manifest_sha256.as_str())
    );
    assert_eq!(
        manifest["native_chain_id"].as_str(),
        Some(sources.genesis.chain_id())
    );
    assert_eq!(
        manifest["native_instance"].as_str(),
        Some(hex::encode(sources.genesis.instance().0).as_str())
    );
    assert_eq!(
        manifest["native_initial_epoch_sha256"].as_str(),
        Some(sha(&norito::encode_canonical(sources.genesis.initial_epoch()).unwrap()).as_str())
    );
    assert_eq!(manifest["files"].as_array().unwrap().len(), 7);
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &f.config.scheme.scheme_id())
            .unwrap();
    let account: AccountId = decode(&frames[2]);
    let asset: KagemushaWalletAssetScopeV1 = decode(&frames[3]);
    assert_eq!(account, f.account);
    assert_eq!(asset, f.asset);
    assert_eq!(
        instruction,
        &KagemushaWalletLedgerV1::new(
            f.config.scheme.scheme_id(),
            KagemushaWalletLedgerActionV1::IssueLoad {
                wallet: credential.body.wallet_id,
                asset: asset.asset_digest(),
                ordinal: 0,
                request_id: LOAD_ID,
                amount: LOAD_AMOUNT,
                charge: None,
            }
        )
    );
    for (name, value) in [
        ("scheme_id", f.config.scheme.scheme_id()),
        ("manifest_digest", sources.qualified.installation().1),
        ("wallet_id", credential.body.wallet_id),
        ("asset_digest", asset.asset_digest()),
        (
            "payer_account_digest",
            kagemusha_wallet_account_digest_v1(&account).unwrap(),
        ),
        ("request_id", LOAD_ID),
        ("charge_quote", [0; 32]),
    ] {
        assert_eq!(manifest[name].as_str(), Some(hex::encode(value).as_str()));
    }
    for (name, expected) in [("ordinal", "0"), ("amount", "100"), ("online_charge", "0")] {
        assert_eq!(manifest[name].as_str(), Some(expected));
    }
}

fn receive(payment: &[u8], payer: &[Vec<u8>; 4], id: u8) -> OperationRequestV1 {
    action(
        id,
        OperationActionV1::Receive {
            payment: payment.to_vec(),
            payer_credential: payer[0].clone(),
            certificates: payer[1].clone(),
        },
    )
}
fn credited(original: &[u8]) -> Vec<u8> {
    let package: KagemushaWalletPackageV1 = decode(original);
    norito::encode_canonical(&KagemushaWalletCreditedV1::from_receive(package).unwrap()).unwrap()
}
fn require_payment_bound(bytes: &[u8], scheme: &[u8; 32]) {
    let payment: KagemushaWalletPaymentV1 = decode(bytes);
    let envelope = KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Payment { payment });
    let frame = envelope.to_canonical_bytes().unwrap();
    assert!(frame.len() <= KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletEnvelopeV1::decode_canonical(&frame, scheme).unwrap(),
        envelope
    );
}

#[test]
#[ignore = "requires exported SAME A custody, genuine full52 grant and an independently pinned finalized Load for its exact target"]
fn actual_native_a_to_b_to_c_then_unload_with_restart_and_replay() {
    let output = fresh_output("KAGEMUSHA_NATIVE_EXCHANGE_OUTPUT");
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    let public = path.parent().unwrap();
    let frames_a = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let instruction: KagemushaWalletLedgerV1 =
        decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames_a, &instruction);
    let bootstrap_a = target_original(
        public,
        &target,
        "bootstrap.norito",
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    );
    let activation_a = target_original(
        public,
        &target,
        "activation.norito",
        KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1,
    );
    let credential_a =
        KagemushaWalletCredentialV1::decode_canonical(&frames_a[0], &f.config.scheme.scheme_id())
            .unwrap();
    let device_a = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential_a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    let count = device_a.platform.with(|state| state.sign_calls);
    assert_eq!(complete(a.bootstrap().unwrap()), bootstrap_a);
    assert_eq!(a.activation().unwrap(), activation_a);
    assert_eq!(
        device_a.platform.with(|state| state.sign_calls),
        count,
        "no recreated Bootstrap or activation"
    );
    assert_eq!(
        (
            a.snapshot().unwrap().sequence,
            a.snapshot().unwrap().owned_balance
        ),
        (0, 0)
    );

    let receipt_bytes = read_pin(
        &selected_path("KAGEMUSHA_NATIVE_LOAD_RECEIPT"),
        KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256"),
    );
    let finality_bytes = read_pin(
        &selected_path("KAGEMUSHA_NATIVE_LOAD_FINALITY"),
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_FINALITY_SHA256"),
    );
    let receipt = KagemushaWalletLoadReceiptV1::decode_canonical(&receipt_bytes).unwrap();
    assert_eq!(receipt.scheme_id, f.config.scheme.scheme_id());
    assert_eq!(
        (
            receipt.wallet_id,
            receipt.asset_digest,
            receipt.payer_account_digest
        ),
        (
            credential_a.body.wallet_id,
            f.asset.asset_digest(),
            kagemusha_wallet_account_digest_v1(&f.account).unwrap()
        )
    );
    assert_eq!(
        (
            receipt.request_id,
            receipt.ordinal,
            receipt.amount,
            receipt.online_charge,
            receipt.charge_quote
        ),
        (LOAD_ID, 0, LOAD_AMOUNT, 0, [0; 32])
    );
    let evidence = KagemushaWalletLoadFinalityV1::decode_canonical(&finality_bytes).unwrap();
    assert_eq!(evidence.receipt_digest, receipt.receipt_digest().unwrap());
    let load = action(
        202,
        OperationActionV1::Load {
            receipt: receipt_bytes,
            finality: finality_bytes,
        },
    );
    let (mut a, device_a, loaded) =
        load_seam::exercise(a, device_a, &sources, &f, &frames_a, &credential_a, &load);
    assert_eq!(complete(a.execute(load.clone()).unwrap()), loaded);
    assert_eq!(a.snapshot().unwrap().owned_balance, 100);
    let mut duplicate = load.clone();
    duplicate.request_id = [203; 32];
    assert!(
        a.execute(duplicate).is_err(),
        "the same receipt cannot credit twice"
    );
    fold(&mut a);

    let f_b = sources.fixture(&setup, 1);
    let f_c = sources.fixture(&setup, 2);
    let device_b = HostDevice::create(&output.join("wallet-b"), 89);
    let frames_b = device_b.enroll(&f_b);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    complete(b.bootstrap().unwrap());
    fold(&mut b);
    let device_c = HostDevice::create(&output.join("wallet-c"), 97);
    let frames_c = device_c.enroll(&f_c);
    let mut c = sources.open(&device_c, &f_c, &frames_c);
    complete(c.bootstrap().unwrap());
    fold(&mut c);
    assert_ne!(
        a.snapshot().unwrap().wallet_id,
        b.snapshot().unwrap().wallet_id
    );
    assert_ne!(
        b.snapshot().unwrap().wallet_id,
        c.snapshot().unwrap().wallet_id
    );

    let offer_ab = a.offer([210; 32], 100).unwrap();
    let request_ab = b.request([211; 32], &offer_ab, None).unwrap();
    let send_ab = action(
        212,
        OperationActionV1::Send {
            request: request_ab,
        },
    );
    device_a
        .platform
        .with(|state| state.sign_fault_at = Some(state.sign_calls));
    assert_eq!(
        a.execute(send_ab.clone()).unwrap(),
        Completion::Pending,
        "post-Advance receipt-signing outage must never report a rejected debit"
    );
    drop(a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    let payment_ab = complete(a.execute(send_ab.clone()).unwrap());
    require_payment_bound(&payment_ab, &f.config.scheme.scheme_id());
    assert_eq!(
        a.snapshot().unwrap().owned_balance,
        0,
        "Send debit is already irreversible before delivery"
    );
    let signs = device_a.platform.with(|state| state.sign_calls);
    drop(a); // lost delivery response / process restart after durable Send
    let mut a = sources.open(&device_a, &f, &frames_a);
    assert_eq!(complete(a.execute(send_ab.clone()).unwrap()), payment_ab);
    assert_eq!(device_a.platform.with(|state| state.sign_calls), signs);
    assert_eq!(a.snapshot().unwrap().owned_balance, 0);
    let before_invalid = b.snapshot().unwrap();
    let mut forged: KagemushaWalletPaymentV1 = decode(&payment_ab);
    forged.send.step_proof.bytes[0] ^= 1;
    assert!(
        b.execute(receive(
            &norito::encode_canonical(&forged).unwrap(),
            &frames_a,
            209
        ))
        .is_err()
    );
    assert_eq!(
        b.snapshot().unwrap(),
        before_invalid,
        "invalid incoming proof cannot credit"
    );
    let receive_ab = receive(&payment_ab, &frames_a, 213);
    let received_ab = complete(b.execute(receive_ab.clone()).unwrap());
    assert_eq!(
        complete(b.execute(receive_ab.clone()).unwrap()),
        received_ab
    );
    let before_duplicate = b.snapshot().unwrap();
    let mut duplicate = receive_ab.clone();
    duplicate.request_id = [214; 32];
    assert!(
        b.execute(duplicate).is_err(),
        "a fresh intent cannot insert a consumed credit twice"
    );
    assert_eq!(
        b.snapshot().unwrap(),
        before_duplicate,
        "duplicate credit changes no monetary state"
    );
    assert_eq!(before_duplicate.owned_balance, 100);
    assert!(before_duplicate.fold_backlog > 0);
    assert_eq!(before_duplicate.folded_balance, None);
    let offer_bc = b.offer([220; 32], 100).unwrap();
    let request_bc = c.request([221; 32], &offer_bc, None).unwrap();
    let send_bc = action(
        222,
        OperationActionV1::Send {
            request: request_bc,
        },
    );
    assert!(matches!(
        b.execute(send_bc.clone()),
        Err(state::Error::FoldRequired)
    ));
    b.scheduler().set_activity(true, false);
    let first = b.fold_once().unwrap();
    let FoldStatus::Checkpoint { sequence, ordinal } = first else {
        panic!("real Receive starts with a durable sub-proof: {first:?}")
    };
    drop(b); // actual checkpoint files and selected manifest survive owner reconstruction
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    b.scheduler().set_activity(true, false);
    match b.fold_once().unwrap() {
        FoldStatus::Checkpoint {
            sequence: next,
            ordinal: second,
        } => {
            assert_eq!(next, sequence);
            assert!(second > ordinal);
        }
        FoldStatus::Folded(next) => assert_eq!(next, sequence),
        other => panic!("checkpoint restart did not advance: {other:?}"),
    }
    fold(&mut b);
    // Genuine storage unavailability must not become absence or a new monetary operation.
    let before = b.snapshot().unwrap();
    device_b
        .platform
        .with(|s| s.storage = Err(KagemushaWalletUnavailableV1::Locked));
    assert!(b.execute(send_bc.clone()).is_err());
    device_b.platform.with(|s| s.storage = Ok(()));
    assert_eq!(b.snapshot().unwrap(), before);
    let payment_bc = complete(b.execute(send_bc.clone()).unwrap());
    require_payment_bound(&payment_bc, &f.config.scheme.scheme_id());
    assert_eq!(complete(b.execute(send_bc).unwrap()), payment_bc);
    let receive_bc = receive(&payment_bc, &frames_b, 223);
    let received_bc = complete(c.execute(receive_bc.clone()).unwrap());
    let signed = device_c.platform.with(|state| state.sign_calls);
    drop(c);
    let mut c = sources.open(&device_c, &f_c, &frames_c);
    assert_eq!(complete(c.execute(receive_bc).unwrap()), received_bc);
    assert_eq!(device_c.platform.with(|state| state.sign_calls), signed);
    fold(&mut c);
    assert_eq!(
        a.snapshot().unwrap().owned_balance
            + b.snapshot().unwrap().owned_balance
            + c.snapshot().unwrap().owned_balance,
        LOAD_AMOUNT
    );
    assert_eq!(
        (
            a.snapshot().unwrap().known_burned_total,
            b.snapshot().unwrap().known_burned_total,
            c.snapshot().unwrap().known_burned_total
        ),
        (0, 0, 0)
    );

    // Exercise both installed Archive sources. A receives the original Receive
    // acknowledgement; B receives C's actual folded CreditStatus. Neither form
    // is considered covered merely because the local Archive sigma completed.
    let credited_ab = credited(&received_ab);
    let bc: KagemushaWalletPaymentV1 = decode(&payment_bc);
    let status_bc = c
        .credit_status(&bc.request.credit_id(), &bc.payment_digest().unwrap())
        .unwrap();
    assert_eq!(
        status_bc.lineage.public.wallet_id,
        c.snapshot().unwrap().wallet_id
    );
    let credited_bc =
        norito::encode_canonical(&KagemushaWalletCreditedV1::from_status(status_bc).unwrap())
            .unwrap();
    let (reopened_a, archived_ab) =
        archive::exercise(a, &device_a, &sources, &f, &frames_a, &credited_ab);
    a = reopened_a;
    let (reopened_b, archived_bc) =
        archive::exercise(b, &device_b, &sources, &f_b, &frames_b, &credited_bc);
    b = reopened_b;
    // B has an incoming credit, so its public status also exposes the final
    // pending-outgoing root after folding the independently verified C evidence.
    let ab: KagemushaWalletPaymentV1 = decode(&payment_ab);
    let b_status = b
        .credit_status(&ab.request.credit_id(), &ab.payment_digest().unwrap())
        .unwrap();
    assert_eq!(
        b_status.lineage.public.pending_outgoing_root,
        kagemusha_wallet_empty_map_root_v1(),
        "ArchiveStatus removes B's only pending outgoing credit"
    );
    let unload = action(
        230,
        OperationActionV1::Unload {
            amount: LOAD_AMOUNT,
            charge: None,
        },
    );
    let unload_id = unload.request_id;
    let unloaded = complete(c.execute(unload.clone()).unwrap());
    assert_eq!(complete(c.execute(unload).unwrap()), unloaded);
    let claim_original = c.unload_claim_bytes(&unload_id, None).unwrap();
    drop(c);
    let mut c = sources.open(&device_c, &f_c, &frames_c);
    assert_eq!(
        c.unload_claim_bytes(&unload_id, None).unwrap(),
        claim_original
    );
    let claim = KagemushaWalletUnloadClaimV1::decode_canonical(
        &claim_original,
        &f.config.scheme.scheme_id(),
    )
    .unwrap();
    assert_eq!(norito::encode_canonical(&claim.package).unwrap(), unloaded);
    assert_eq!(claim.account, f_c.account);
    assert_ne!(claim.account, f.account);
    assert_ne!(claim.account, f_b.account);
    let payout = claim.verify(&f.config.scheme).unwrap();
    sources
        .installed
        .verifier()
        .verify_package_proofs(&claim.package, None, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(
        (payout.amount, payout.account_payout, payout.online_charge),
        (100, 100, 0)
    );
    assert_eq!(
        a.snapshot().unwrap().owned_balance
            + b.snapshot().unwrap().owned_balance
            + c.snapshot().unwrap().owned_balance
            + payout.account_payout,
        LOAD_AMOUNT
    );
    assert!(
        c.execute(action(
            231,
            OperationActionV1::Unload {
                amount: 100,
                charge: None
            }
        ))
        .is_err()
    );
    // Adversarial DATA uses the existing simulated C payment key outside the provider.
    // It never replaces the genuine released claim or performs another monetary operation.
    let c_before_negative = c.snapshot().unwrap();
    let c_sign_calls = device_c.platform.with(|state| state.sign_calls);
    let bad_sigma_claim = proof_negative::claim(&sources, &device_c, &claim);
    assert_eq!(c.snapshot().unwrap(), c_before_negative);
    assert_eq!(
        device_c.platform.with(|state| state.sign_calls),
        c_sign_calls
    );
    assert_eq!(
        c.unload_claim_bytes(&unload_id, None).unwrap(),
        claim_original
    );
    let bad_sigma_original = norito::json!({
        "name": "c-unload-bad-sigma-claim.norito",
        "bytes": (bad_sigma_claim.len()), "sha256": (sha(&bad_sigma_claim)),
        "mutation": "sigma_ipa_f_plus_one", "model_verified": true,
        "native_proof_rejected": true, "adversarial_fixture_signatures": 1
    });
    publish(
        &output.join("c-unload-bad-sigma-claim.norito"),
        &bad_sigma_claim,
    );
    let archive_originals = [
        ("a-credited-receive.norito", credited_ab),
        ("b-credited-status.norito", credited_bc),
        ("a-archive-receive.norito", archived_ab),
        ("b-archive-status.norito", archived_bc),
    ]
    .into_iter()
    .map(|(name, bytes)| {
        assert!(bytes.len() <= KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1);
        publish(&output.join(name), &bytes);
        norito::json!({"name": name, "bytes": (bytes.len()), "sha256": (sha(&bytes))})
    })
    .collect::<Vec<_>>();
    for (name, bytes) in [
        ("a-b-payment.norito", payment_ab),
        ("b-c-payment.norito", payment_bc),
        ("b-receive.norito", received_ab),
        ("c-receive.norito", received_bc),
        ("c-unload-claim.norito", claim.to_canonical_bytes().unwrap()),
    ] {
        publish(&output.join(name), &bytes);
    }
    // Keep exactly C's existing test-only private platform key for the separate actual-ledger
    // settlement consumer. Public continuation originals grant no new custody or authority.
    device_c.save_simulator();
    let c_open_originals = FRAME_NAMES
        .into_iter()
        .zip(&frames_c)
        .map(|(name, bytes)| {
            publish(&device_c.root.join(name), bytes);
            norito::json!({ "name": name, "bytes": (bytes.len()), "sha256": (sha(bytes)) })
        })
        .collect::<Vec<_>>();
    let result = norito::json!({ "schema": "iroha.kagemusha.native-abc-result.v1",
        "source_pins": (source_pins()), "binary_sha256": (executable_hash()),
        "target_sha256": (sha(&target_bytes)), "native_unload_payout": "100",
        "executed_ledger_setup_sha256": (setup.manifest_sha256),
        "a_account_digest": (hex::encode(kagemusha_wallet_account_digest_v1(&f.account).unwrap())),
        "b_account_digest": (hex::encode(kagemusha_wallet_account_digest_v1(&f_b.account).unwrap())),
        "c_account_digest": (hex::encode(kagemusha_wallet_account_digest_v1(&f_c.account).unwrap())),
        "c_open_originals": c_open_originals,
        "c_wallet_id": (hex::encode(claim.credential.body.wallet_id)),
        "c_unload_request_id": (hex::encode(unload_id)),
        "c_unload_claim_sha256": (sha(&claim_original)),
        "c_unload_bad_sigma_claim": bad_sigma_original,
        "archive_receive_folded": true, "archive_status_folded": true,
        "archive_exact_replay_after_restart": true, "archive_originals": archive_originals,
        "ledger_settlement_executed": false, "physical_device_qualified": false,
        "scope": "Real installed proof source, finalized receipt proof, native host custody, exact replay and local folds; simulated hardware. Exported Unload claim still requires actual ledger execution and replay qualification." });
    publish(
        &output.join("result.json"),
        &norito::json::to_vec(&result).unwrap(),
    );
}

#[test]
fn host_enrollment_retains_exact_originals_and_existing_simulated_key_across_restart() {
    // This exercises ONLY host custody and enrollment fixture restoration. No source grant
    // or wallet proof is constructed, and this test cannot establish exchange qualification.
    let directory = tempfile::tempdir().unwrap();
    let f = fixture();
    let device = HostDevice::create(&directory.path().join("device"), 103);
    let frames = device.enroll(&f);
    for (name, bytes) in FRAME_NAMES.into_iter().zip(&frames) {
        publish(&device.root.join(name), bytes);
        assert_eq!(
            read_pin(&device.root.join(name), 32768, &sha(bytes)),
            *bytes
        );
    }
    device.save_simulator();
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &f.config.scheme.scheme_id())
            .unwrap();
    let recovered = HostDevice::restore(&device.root, &credential);
    let provider = recovered.provider(f.config.scheme.scheme_id());
    let slots = provider.slots().unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(
        recovered.platform.key_of(&slots[0]),
        Some(credential.body.payment_key)
    );
    recovered.platform.with(|state| {
        assert_eq!(
            state.generate_calls, 0,
            "restore must not generate another payment key"
        );
        assert_eq!(state.sign_calls, 0);
    });
    drop(provider);
    assert!(iroha_fs::read_private(device.root.join("simulator-key.norito"), 1).is_err());
    for name in FRAME_NAMES {
        assert_eq!(
            iroha_fs::read_private(device.root.join(name), 32768)
                .unwrap()
                .as_slice(),
            frames[FRAME_NAMES.iter().position(|other| *other == name).unwrap()]
        );
    }
}
