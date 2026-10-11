//! CLI selection, immutable lazy input and native genesis checks; no monetary acceptance claim.
use super::*;
use clap::Parser as _;
use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;
use std::{fs, io::Write as _, path::Path};

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: super::super::Command,
}

fn args(input: &Path) -> RegistrationPackageArgs {
    RegistrationPackageArgs {
        input_dir: input.to_owned(),
        genesis_sha256: [1; 32],
        scheme_sha256: [2; 32],
        chain_id: "registration-cli-test".into(),
        asset_digest: [3; 32],
        instruction_index: 0,
        proof_count: 3,
        output_parent: input.to_owned(),
        output_name: "new-package".into(),
    }
}
fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    root
}
fn put(directory: &PrivateDirectory, name: &str, bytes: &[u8]) {
    let mut file = directory
        .create_retained_private(name, bytes.len())
        .unwrap();
    file.write_all(bytes).unwrap();
    file.seal_read_only().unwrap();
}

#[test]
fn required_independent_pins_and_explicit_selection_parse() {
    let genesis = "12".repeat(32);
    let scheme = "23".repeat(32);
    let asset = "34".repeat(32);
    let words = [
        "iroha-offline",
        "registration-package",
        "--input-dir",
        "/private/inputs",
        "--genesis-sha256",
        &genesis,
        "--scheme-sha256",
        &scheme,
        "--chain-id",
        "chain",
        "--asset-digest",
        &asset,
        "--instruction-index",
        "4",
        "--proof-count",
        "99",
        "--output-parent",
        "/private/output",
        "--output-name",
        "token",
    ];
    let command = Cli::try_parse_from(words).unwrap().command;
    assert!(command.allows_fallback_config());
    command.preflight_before_operator_key_load().unwrap();
    let super::super::Command::RegistrationPackage(parsed) = command else {
        panic!("wrong command")
    };
    assert_eq!(parsed.proof_count, 99);
    assert_eq!(parsed.instruction_index, 4);
    assert_eq!(parsed.genesis_sha256, [0x12; 32]);
    for flag in [
        "--genesis-sha256",
        "--scheme-sha256",
        "--asset-digest",
        "--proof-count",
        "--instruction-index",
    ] {
        let index = words.iter().position(|word| *word == flag).unwrap();
        let reduced: Vec<_> = words
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index && *i != index + 1)
            .map(|(_, word)| *word)
            .collect();
        assert!(Cli::try_parse_from(reduced).is_err(), "{flag}");
    }
}

#[test]
fn digest_refuses_ambiguous_zero_and_malformed_identity() {
    assert_eq!(digest(&"1a".repeat(32)).unwrap(), [0x1a; 32]);
    for invalid in [
        "0".repeat(64),
        "A".repeat(64),
        "ff".repeat(31),
        "ff".repeat(33),
        "gg".repeat(32),
    ] {
        assert!(digest(&invalid).is_err());
    }
}

#[test]
fn preflight_refuses_nonfresh_names_and_incomplete_history() {
    let mut value = args(Path::new("/unused"));
    value.preflight().unwrap();
    for name in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
        value.output_name = name.into();
        assert!(value.preflight().is_err());
    }
    value.output_name = "token".into();
    for count in [0, 1] {
        value.proof_count = count;
        assert!(value.preflight().is_err());
    }
    value.proof_count = 2;
    value.chain_id.clear();
    assert!(value.preflight().is_err());
    value.chain_id = "chain\nlabel".into();
    assert!(value.preflight().is_err());
}

#[test]
fn immutable_pinned_input_refuses_hash_bound_and_replacement() {
    let root = private_root();
    let directory = PrivateDirectory::open_exact(root.path().canonicalize().unwrap()).unwrap();
    put(&directory, "original", b"exact body");
    let hash = Sha256::digest(b"exact body").into();
    assert_eq!(
        pinned_original(&directory, "original", 10, hash).unwrap(),
        b"exact body"
    );
    assert!(pinned_original(&directory, "original", 10, [7; 32]).is_err());
    assert!(pinned_original(&directory, "original", 9, hash).is_err());
    let mut reader = OriginalReader::open(&directory, "original", 10).unwrap();
    fs::rename(
        directory.path().join("original"),
        directory.path().join("old"),
    )
    .unwrap();
    put(&directory, "original", b"exact body");
    assert!(reader.read(&mut [0; 10]).is_err());
}

#[test]
fn proof_iterator_opens_only_requested_ordinal_in_each_direction() {
    let root = private_root();
    let directory = PrivateDirectory::open_exact(root.path().canonicalize().unwrap()).unwrap();
    put(&directory, "proof-00000000000000000001.norito", b"first");
    put(&directory, "proof-00000000000000000003.norito", b"last");
    let mut readers = proof_readers(&directory, 3);
    assert_eq!(readers.len(), 3);
    let mut last = String::new();
    readers
        .next_back()
        .unwrap()
        .unwrap()
        .read_to_string(&mut last)
        .unwrap();
    assert_eq!(last, "last");
    let mut first = String::new();
    readers
        .next()
        .unwrap()
        .unwrap()
        .read_to_string(&mut first)
        .unwrap();
    assert_eq!(first, "first");
    assert_eq!(
        readers.next().unwrap().err().unwrap().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(readers.len(), 0);
}

#[test]
fn pinned_native_genesis_checks_signature_chain_and_canonical_frame() {
    let mut native = NativeFinalityFixture::start("registration-cli-test");
    let bytes = norito::encode_canonical(native.genesis_proof()).unwrap();
    let mut verifier = genesis_verifier(&bytes, native.chain_id()).unwrap();
    verifier.verify(native.genesis_proof()).unwrap();
    // The pinned genesis fixes the network; the separately selected chain label fixes
    // the consensus instance. Its first non-genesis certificate binds that instance.
    let mut foreign = genesis_verifier(&bytes, "foreign chain").unwrap();
    assert_ne!(foreign.instance(), verifier.instance());
    foreign.verify(native.genesis_proof()).unwrap();
    let second = native.block_with_submitted_work(native.next_header());
    let second = native.certify(second);
    verifier.verify(&second).unwrap();
    assert!(foreign.verify(&second).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(genesis_verifier(&trailing, native.chain_id()).is_err());
    let mut changed = native.genesis_proof().clone();
    changed.block_wire[0] ^= 1;
    assert!(
        genesis_verifier(
            &norito::encode_canonical(&changed).unwrap(),
            native.chain_id()
        )
        .is_err()
    );
}

#[test]
fn failed_pin_never_creates_output_and_report_is_machine_readable() {
    let root = private_root();
    let directory = PrivateDirectory::open_exact(root.path().canonicalize().unwrap()).unwrap();
    put(
        &directory,
        "proof-00000000000000000001.norito",
        b"unauthenticated input",
    );
    let value = args(directory.path());
    assert!(value.package().is_err());
    assert!(!directory.path().join("new-package").exists());
    let report = RegistrationPackageReport {
        schema: "iroha.offline.registration-package.v1",
        source_path: "/private/token/registration-source.norito".into(),
        source_sha256: "12".repeat(32),
        asset_digest: "23".repeat(32),
        scheme_id: "34".repeat(32),
        block_hash: "45".repeat(32),
        transaction_hash: "56".repeat(32),
        registered_height: 37,
        proof_count: 37,
    };
    let json = norito::json::to_value(&report).unwrap();
    assert_eq!(json["registered_height"].as_u64(), Some(37));
    assert_eq!(
        json["schema"].as_str(),
        Some("iroha.offline.registration-package.v1")
    );
    assert!(json.get("private_key").is_none());
}

#[test]
fn successful_package_reopens_and_altered_commit_never_publishes_a_locator() {
    use iroha_core_zk::kagemusha_wallet_registration_v1::{
        RegistrationSourceV1, verify_registration_source_v1,
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        asset::{AssetBalanceScope, AssetDefinitionId},
        block::{BlockSignatures, builder::BlockBuilder},
        isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
        kagemusha::{
            KagemushaDevicePublicKeyV1, KagemushaWalletAssetScopeV1,
            kagemusha_wallet_provider_contract_v1,
        },
        query::CommittedTransaction,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    let root = private_root();
    let directory = PrivateDirectory::open_exact(root.path().canonicalize().unwrap()).unwrap();
    let mut native = NativeFinalityFixture::start("registration-cli-test");
    let genesis_bytes = norito::encode_canonical(native.genesis_proof()).unwrap();
    let second = native.block_with_submitted_work(native.next_header());
    let second = native.certify(second);
    // Public P-256 generator. The test signs only the native transaction/certificates;
    // these supplied successful output rows are synthetic, not actual ledger execution.
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *native.network_id().as_bytes(),
        scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            &hex::decode("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
                .unwrap(),
        )
        .unwrap(),
        relation_id: [9; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let scheme_bytes = scheme.to_canonical_bytes().unwrap();
    let asset = KagemushaWalletAssetScopeV1 {
        version: 1,
        asset: AssetDefinitionId::from_uuid_bytes([
            0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
            0xcd, 0x2f,
        ])
        .unwrap(),
        asset_incarnation: *Hash::new(b"CLI registered incarnation").as_ref(),
        scale: 0,
    };
    let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let reserve = AccountId::new(key.public_key().clone());
    let instruction = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Register {
            scheme: scheme_bytes.clone(),
            asset: norito::encode_canonical(&asset).unwrap(),
            reserve: reserve.clone(),
            balance_scope: AssetBalanceScope::Global,
        },
    );
    let header = native.next_header();
    let mut transaction = TransactionBuilder::new(
        native.network_id(),
        reserve,
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(std::time::Duration::from_millis(
        header.creation_time_ms - 1,
    ));
    let transaction = transaction
        .with_instructions([instruction])
        .sign(key.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(transaction);
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, vec![Ok(vec![])]);
    let third = native.certify(block);
    let verified = native.verifier().verify_retained_decision(&third).unwrap();
    let block = verified.block();
    let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
    let (output_index, _) = block.network_output_at(0).unwrap();
    let output = block.execution_outputs()[output_index as usize].clone();
    let mut committed = CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(0).unwrap(),
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(output_index).unwrap(),
        output,
    };
    put(&directory, "scheme.norito", &scheme_bytes);
    put(
        &directory,
        "committed.norito",
        &norito::encode_canonical(&committed).unwrap(),
    );
    for (index, bytes) in [
        genesis_bytes.clone(),
        norito::encode_canonical(&second).unwrap(),
        norito::encode_canonical(&third).unwrap(),
    ]
    .iter()
    .enumerate()
    {
        put(
            &directory,
            &format!("proof-{:020}.norito", index + 1),
            bytes,
        );
    }
    let mut value = args(directory.path());
    value.genesis_sha256 = Sha256::digest(&genesis_bytes).into();
    value.scheme_sha256 = Sha256::digest(&scheme_bytes).into();
    value.asset_digest = asset.asset_digest();
    let report = value.package().unwrap();
    let source_bytes = fs::read(&report.source_path).unwrap();
    let source = RegistrationSourceV1::decode_canonical(&source_bytes).unwrap();
    let genesis = genesis_verifier(&genesis_bytes, native.chain_id()).unwrap();
    let registration = verify_registration_source_v1(&source, &genesis, &scheme, || false).unwrap();
    assert_eq!(registration.asset(), &asset);
    assert_eq!(registration.height(), 3);
    assert_eq!(
        report.source_sha256,
        hex::encode(Sha256::digest(&source_bytes))
    );
    assert_eq!(
        report.transaction_hash,
        hex::encode(registration.transaction_hash())
    );
    assert!(
        value.package().is_err(),
        "an existing output cannot be overwritten"
    );
    assert_eq!(fs::read(&report.source_path).unwrap(), source_bytes);

    committed.block_hash = native.genesis().hash();
    fs::rename(
        directory.path().join("committed.norito"),
        directory.path().join("retained-committed.norito"),
    )
    .unwrap();
    put(
        &directory,
        "committed.norito",
        &norito::encode_canonical(&committed).unwrap(),
    );
    value.output_name = "bad-commit".into();
    assert!(value.package().is_err());
    assert!(
        !directory
            .path()
            .join("bad-commit/registration-source.norito")
            .exists()
    );
}
