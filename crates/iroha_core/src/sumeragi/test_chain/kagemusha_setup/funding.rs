//! Artifact-dependent real ledger funding; no injected registration, activation or Result.
use super::*;
use crate::kagemusha_wallet_v1::CommittedLoadReceipts;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
    InstallationV1, InstalledVerifierPackV1, VERIFIER_PACK_MAX_BYTES_V1, VerifierPackV1,
};
use iroha_data_model::{
    asset::AssetBalanceScope,
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1},
    kagemusha::*,
    sumeragi_finality::VerifiedSumeragiBlock,
};
use std::{io::Read as _, num::NonZeroU16, path::PathBuf, time::Instant};

fn pin(name: &str) -> [u8; 32] {
    let bytes: [u8; 32] = hex::decode(std::env::var(name).expect("independent SHA-256 pin"))
        .unwrap()
        .try_into()
        .unwrap();
    assert_ne!(bytes, [0; 32]);
    bytes
}
fn read(path: &Path, cap: usize, expected: [u8; 32]) -> Vec<u8> {
    let before = fs::symlink_metadata(path).unwrap();
    assert!(before.file_type().is_file() && before.len() > 0 && before.len() <= cap as u64);
    let file = File::open(path).unwrap();
    assert_eq!(file.metadata().unwrap().len(), before.len());
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len() as u64, before.len());
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), expected);
    bytes
}
fn selected(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).expect("explicit original path"))
}
fn canonical<T>(bytes: &[u8]) -> T
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .unwrap()
}
fn original(root: &Path, manifest: &norito::json::Value, name: &str, cap: usize) -> Vec<u8> {
    let rows = manifest["files"].as_array().unwrap();
    let selected = rows
        .iter()
        .filter(|row| row["name"].as_str() == Some(name))
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 1);
    let row = selected[0];
    let hash = hex::decode(row["sha256"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let bytes = read(&root.join(name), cap, hash);
    assert_eq!(row["bytes"].as_u64().unwrap(), bytes.len() as u64);
    bytes
}

struct Inputs {
    scheme: KagemushaWalletSchemeV1,
    manifest: [u8; 32],
    pack: Vec<u8>,
    activation: Vec<u8>,
    load: KagemushaWalletLedgerV1,
    target_sha256: [u8; 32],
}
fn inputs(setup: &ExecutedKagemushaSetup) -> Inputs {
    let path = selected("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_sha256 = pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256");
    let bytes = read(&path, 16 << 10, target_sha256);
    let target: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(
        target["schema"].as_str(),
        Some("iroha.kagemusha.native-load-target.v1")
    );
    assert_eq!(target["files"].as_array().unwrap().len(), 7);
    assert_eq!(target["native_chain_id"].as_str(), Some(CHAIN));
    assert_eq!(
        target["native_instance"].as_str().unwrap(),
        hex::encode(setup.chain.instance().0)
    );
    assert_eq!(
        target["native_initial_epoch_sha256"].as_str().unwrap(),
        hex::encode(Sha256::digest(
            norito::encode_canonical(native(setup).initial_epoch()).unwrap()
        ))
    );
    let root = path.parent().unwrap();
    let account: AccountId = canonical(&original(root, &target, "account.norito", 4_096));
    let asset: KagemushaWalletAssetScopeV1 =
        canonical(&original(root, &target, "asset.norito", 4_096));
    assert_eq!(account, setup.account);
    assert_eq!(asset, setup.asset);
    let scheme_id = hex::decode(target["scheme_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let manifest = hex::decode(target["manifest_digest"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let pack = read(
        &selected("KAGEMUSHA_NATIVE_VERIFIER_PACK"),
        VERIFIER_PACK_MAX_BYTES_V1,
        pin("KAGEMUSHA_NATIVE_VERIFIER_PACK_SHA256"),
    );
    let admitted = InstalledVerifierPackV1::load(
        &pack,
        InstallationV1 {
            scheme_id,
            manifest_digest: manifest,
        },
    )
    .unwrap();
    let scheme = *admitted.verifier().scheme();
    assert_eq!(&scheme.network_id, setup.chain.network_id().as_bytes());
    assert_eq!(
        VerifierPackV1::decode_canonical(&pack).unwrap().scheme,
        scheme.to_canonical_bytes().unwrap()
    );
    let activation = original(
        root,
        &target,
        "activation.norito",
        KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1,
    );
    let typed = KagemushaWalletActivationV1::decode_canonical(&activation, &scheme_id).unwrap();
    assert_eq!(
        typed.credential.body.account_digest,
        kagemusha_wallet_account_digest_v1(&account).unwrap()
    );
    assert_eq!(typed.asset, asset);
    assert_eq!(
        typed.credential.to_canonical_bytes().unwrap(),
        original(
            root,
            &target,
            "credential.norito",
            KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1
        )
    );
    assert_eq!(
        norito::encode_canonical(&typed.certificates).unwrap(),
        original(root, &target, "certificates.norito", 32_768)
    );
    assert_eq!(
        norito::encode_canonical(&typed.bootstrap).unwrap(),
        original(
            root,
            &target,
            "bootstrap.norito",
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
        )
    );
    let load: KagemushaWalletLedgerV1 =
        canonical(&original(root, &target, "issue-load.norito", 4_096));
    assert_eq!(
        load,
        KagemushaWalletLedgerV1::new(
            scheme_id,
            Action::IssueLoad {
                wallet: typed.credential.body.wallet_id,
                asset: asset.asset_digest(),
                ordinal: 0,
                request_id: [201; 32],
                amount: 100,
                charge: None,
            }
        )
    );
    Inputs {
        scheme,
        manifest,
        pack,
        activation,
        load,
        target_sha256,
    }
}

fn balance(setup: &ExecutedKagemushaSetup, account: &AccountId) -> Quantity {
    setup
        .chain
        .state()
        .view()
        .world()
        .assets()
        .get(&AssetId::of(setup.asset.asset.clone(), account.clone()))
        .map_or_else(Quantity::zero, |value| value.as_ref().clone())
}
fn fund(setup: &mut ExecutedKagemushaSetup, input: &Inputs) {
    let scheme = input.scheme.scheme_id();
    let register = KagemushaWalletLedgerV1::new(
        scheme,
        Action::Register {
            scheme: input.scheme.to_canonical_bytes().unwrap(),
            asset: norito::encode_canonical(&setup.asset).unwrap(),
            reserve: setup.reserve.clone(),
            balance_scope: AssetBalanceScope::Global,
        },
    );
    let install = KagemushaWalletLedgerV1::new(
        scheme,
        Action::InstallVerifierPack {
            asset: setup.asset.asset_digest(),
            manifest_digest: input.manifest,
            pack: input.pack.clone(),
        },
    );
    let transaction = setup
        .chain
        .sign(&key(95), [register.into(), install.into()], 2_999);
    assert_eq!(setup.chain.commit_at(3_000, vec![transaction]), [true]);
    let activate = KagemushaWalletLedgerV1::new(scheme, Action::Activate(input.activation.clone()));
    let transaction = setup.chain.sign(&key(41), [activate.into()], 3_999);
    assert_eq!(setup.chain.commit_at(4_000, vec![transaction]), [true]);
    let transaction = setup
        .chain
        .sign(&key(41), [input.load.clone().into()], 4_999);
    assert_eq!(setup.chain.commit_at(5_000, vec![transaction]), [true]);
    assert_eq!(
        balance(setup, &setup.account),
        Quantity::from_canonical_numeric(Numeric::new(900, SCALE)).unwrap()
    );
    assert_eq!(
        balance(setup, &setup.reserve),
        Quantity::from_canonical_numeric(Numeric::new(100, SCALE)).unwrap()
    );
    for recipient in &setup.recipients {
        assert_eq!(balance(setup, recipient), Quantity::zero());
    }
}

fn block_capture(block: &VerifiedSumeragiBlock) -> norito::json::Value {
    let certificate = block.block().commit_certificate().unwrap();
    let qc: iroha_sumeragi::message::Qc = canonical(certificate.commit_qc());
    let schedule = &block.commitment().schedule;
    // This test has one fixed short permissioned history. Never silently erase a boundary.
    assert!(schedule.boundary.is_none());
    let public_keys: Vec<_> = schedule
        .current
        .committee
        .iter()
        .map(|member| {
            let (algorithm, bytes) = member.validator.public_key().try_to_bytes().unwrap();
            assert_eq!(algorithm, Algorithm::BlsNormal);
            hex::encode(bytes)
        })
        .collect();
    let pops: Vec<_> = schedule
        .current
        .committee
        .iter()
        .map(|member| hex::encode(&member.proof_of_possession))
        .collect();
    norito::json!({
        "height": (block.height()),
        "result_preimage_hex": (hex::encode(block.commitment().preimage().unwrap())),
        "result_hash_hex": (hex::encode(block.result().0)),
        "commit_vote_preimage_hex": (hex::encode(qc.preimage())),
        "qc_bitmap_hex": (hex::encode(qc.signers.as_bytes())),
        "qc_aggregate_signature_hex": (hex::encode(qc.agg_sig.0)),
        "committee_public_keys_hex": public_keys,
        "committee_proofs_of_possession_hex": pops,
        "authenticated_schedule": {
            "current": { "context_id_hex": (hex::encode(schedule.current.context_id().unwrap())) },
            "boundary": (norito::json::Value::Null),
        },
    })
}

fn capture(setup: &ExecutedKagemushaSetup, input: &Inputs, output: &Path) {
    assert!(!output.exists(), "fresh exclusive capture directory");
    let mut directory = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        directory.mode(0o700);
    }
    directory.create(output).unwrap();
    let mut originals = Vec::new();
    let mut blocks = Vec::new();
    let mut verifier = native(setup);
    // The funded receipt is at H5; the later rejection checks are not part of its proof.
    assert!(setup.chain.height() >= 5);
    for height in 1..=5 {
        let proof =
            crate::sumeragi::finality::build_proof(&setup.chain.state().view(), height).unwrap();
        let verified = verifier.verify(&proof).unwrap();
        assert_eq!(verified.result(), setup.chain.committed(height).result());
        originals.push(publish(
            output,
            &format!("block-{height}.wire"),
            &proof.block_wire,
        ));
        originals.push(publish(
            output,
            &format!("native-proof-{height}.norito"),
            &norito::encode_canonical(&proof).unwrap(),
        ));
        if height > 1 {
            blocks.push(block_capture(&verified));
        }
    }
    let mut cursor = crate::sumeragi::finality::NativeFinalityCursorV1::new();
    let budget = iroha_allocation::AllocationBudget::new(2 << 30);
    let view = setup.chain.state().view();
    let at = cursor
        .advance_to_height(
            &view,
            NonZeroU64::new(5).unwrap(),
            &budget,
            Instant::now() + Duration::from_secs(60),
            NonZeroU16::new(64).unwrap(),
        )
        .unwrap()
        .unwrap();
    let source =
        CommittedLoadReceipts::new(&view, 2_000_000, norito::canonical_decode_limits(2_000_000))
            .unwrap();
    let Action::IssueLoad {
        wallet, request_id, ..
    } = &input.load.action
    else {
        panic!("selected Load")
    };
    let evidence = source
        .event_evidence_for(
            &at,
            &setup.account,
            &input.scheme.scheme_id(),
            wallet,
            request_id,
        )
        .unwrap();
    let receipt = evidence.verified().receipt();
    assert_eq!(
        (receipt.ordinal, receipt.amount, receipt.block_height),
        (0, 100, 5)
    );
    let receipt_frame = norito::encode_canonical(receipt).unwrap();
    originals.push(publish(output, "receipt.norito", &receipt_frame));
    let path = evidence.path().proof().unwrap();
    let mut siblings = [[0_u8; 32]; 32];
    assert!(path.audit_path().len() <= siblings.len());
    for (original, output) in path.audit_path().iter().zip(&mut siblings) {
        if let Some(hash) = original {
            *output = *hash.as_ref();
        }
    }
    let commitment = evidence.path().commitment();
    let mut capture = source_capture(setup);
    let object = capture.as_object_mut().unwrap();
    object.insert("scope".into(), "Actual registered reserve/install/Bootstrap/IssueLoad execution and complete ordered certified history; fixture signs committee votes, simulated wallet hardware.".into());
    object.insert("blocks".into(), norito::json::to_value(&blocks).unwrap());
    object.insert(
        "load".into(),
        norito::json!({
            "result_preimage_hex": (hex::encode(at.block().commitment().preimage().unwrap())),
            "receipt_frame_hex": (hex::encode(&receipt_frame)),
            "receipt_transcript_hex": (hex::encode(receipt.transcript().unwrap())),
            "receipt_digest_hex": (hex::encode(receipt.receipt_digest().unwrap())),
            "event_commitment_root_hex": (hex::encode(commitment.root().as_ref())),
            "event_commitment_count": (commitment.leaf_count().get()),
            "event_index": (path.leaf_index()),
            "event_siblings_hex": (siblings.iter().map(hex::encode).collect::<Vec<_>>()),
        }),
    );
    object.insert(
        "native_target_sha256".into(),
        hex::encode(input.target_sha256).into(),
    );
    object.insert(
        "originals".into(),
        norito::json::to_value(&originals).unwrap(),
    );
    publish(
        output,
        "capture.json",
        norito::json::to_json(&capture).unwrap().as_bytes(),
    );
    File::open(output).unwrap().sync_all().unwrap();
    File::open(output.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

#[test]
fn capture_reader_rejects_changed_original_and_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("original");
    fs::write(&path, b"exact").unwrap();
    let pin = Sha256::digest(b"exact").into();
    assert_eq!(read(&path, 5, pin), b"exact");
    assert!(std::panic::catch_unwind(|| read(&path, 4, pin)).is_err());
    fs::write(&path, b"alter").unwrap();
    assert!(std::panic::catch_unwind(|| read(&path, 5, pin)).is_err());
    #[cfg(unix)]
    {
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            std::panic::catch_unwind(|| read(&link, 5, Sha256::digest(b"alter").into())).is_err()
        );
    }
}

#[test]
#[ignore = "requires same canonical genesis complete catalog and real native A target; executes funding and exports exact native history"]
fn execute_actual_a_registration_activation_and_load() {
    let mut setup = start();
    let input = inputs(&setup);
    fund(&mut setup, &input);
    let before = (
        balance(&setup, &setup.account),
        balance(&setup, &setup.reserve),
    );
    let retry = setup
        .chain
        .sign(&key(41), [input.load.clone().into()], 5_999);
    assert_eq!(setup.chain.commit_at(6_000, vec![retry]), [false]);
    assert_eq!(
        (
            balance(&setup, &setup.account),
            balance(&setup, &setup.reserve)
        ),
        before
    );
    // Publish completion only after the exact retry has failed without another debit.
    capture(&setup, &input, &selected("KAGEMUSHA_EXECUTED_LOAD_OUTPUT"));
}

mod settlement;
