//! Exact actual-StateExecutor Register capture for the genuine compact differential.
//! Fixture validators sign real exact-quorum certificates; no deployed-node authority is claimed.
use super::*;
use iroha_core_zk::kagemusha_wallet_registration_v1::{
    REGISTRATION_PROOF_MAX_BYTES_V1, REGISTRATION_SOURCE_MAX_BYTES_V1, RegistrationSelectionV1,
    publish_registration_source_v1,
};
use iroha_data_model::{
    kagemusha::KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1, transaction::TransactionEntrypoint,
};
use iroha_fs::PrivateDirectory;
use std::io::{Cursor, Write as _};

const SCHEMA: &str = "iroha.kagemusha.executed-terminal-registration.v1";
const MANIFEST_MAX: usize = 16 * 1024;

fn pin(name: &str) -> [u8; 32] {
    let encoded = std::env::var(name).expect("independently captured exact SHA-256 pin");
    let value: [u8; 32] = hex::decode(&encoded).unwrap().try_into().unwrap();
    assert_eq!(hex::encode(value), encoded);
    assert_ne!(value, [0; 32]);
    value
}

fn require_pins(
    setup: &ExecutedKagemushaSetup,
    original: &[u8],
    expected_scheme_sha: [u8; 32],
    expected_scheme_id: [u8; 32],
    expected_genesis_sha: [u8; 32],
) -> KagemushaWalletSchemeV1 {
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(original)),
        expected_scheme_sha
    );
    let selected =
        KagemushaWalletSchemeV1::decode_canonical(original, &expected_scheme_id).unwrap();
    assert_eq!(selected.to_canonical_bytes().unwrap(), original);
    assert_eq!(selected.network_id, *setup.chain.network_id().as_bytes());
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(setup.chain.genesis().encode_wire().unwrap())),
        expected_genesis_sha,
        "execution must reproduce the independently selected canonical genesis"
    );
    selected
}

fn put(
    directory: &PrivateDirectory,
    name: &str,
    bytes: &[u8],
    maximum: usize,
) -> norito::json::Value {
    assert!(!bytes.is_empty() && bytes.len() <= maximum);
    let mut file = directory.create_retained_private(name, maximum).unwrap();
    file.write_all(bytes).unwrap();
    file.seal_read_only().unwrap();
    norito::json!({"name": name, "sha256": (hex::encode(Sha256::digest(bytes))), "bytes": (bytes.len())})
}

fn successor(executed: &mut ExecutedRegistration) -> SumeragiFinalityProof {
    assert_eq!(executed.setup.chain.height(), 5);
    // commit_at inserts actual signed Log work. This never creates an empty block.
    executed.setup.chain.commit_at(6_000, Vec::new());
    let proof =
        crate::sumeragi::finality::build_proof(&executed.setup.chain.state().view(), 6).unwrap();
    let mut verifier = native(&executed.setup);
    for original in &executed.proofs {
        verifier.verify(original).unwrap();
    }
    assert_eq!(verifier.verify(&proof).unwrap().height(), 6);
    assert!(
        executed
            .setup
            .chain
            .committed(6)
            .block()
            .output_results()
            .all(|result| result.is_ok())
    );
    proof
}

fn export(executed: &ExecutedRegistration, following: &SumeragiFinalityProof, output: &Path) {
    let parent = PrivateDirectory::open_exact(output.parent().unwrap()).unwrap();
    let directory = parent.create_child(output.file_name().unwrap()).unwrap();
    let setup = &executed.setup;
    let genesis = native(setup);
    assert_eq!(following.height(), 6);
    let scheme_bytes = executed.scheme.to_canonical_bytes().unwrap();
    let committed_bytes = norito::encode_canonical(&executed.committed).unwrap();
    let terminal = setup.chain.committed(5);
    let mut originals = vec![
        put(
            &directory,
            "scheme.norito",
            &scheme_bytes,
            KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
        ),
        put(
            &directory,
            "asset.norito",
            &norito::encode_canonical(&setup.asset).unwrap(),
            4096,
        ),
        put(
            &directory,
            "signed-genesis.wire",
            &setup.chain.genesis().encode_wire().unwrap(),
            REGISTRATION_PROOF_MAX_BYTES_V1,
        ),
        put(
            &directory,
            "committed.norito",
            &committed_bytes,
            REGISTRATION_PROOF_MAX_BYTES_V1,
        ),
        put(
            &directory,
            "terminal-block.wire",
            &terminal.block().encode_wire().unwrap(),
            REGISTRATION_PROOF_MAX_BYTES_V1,
        ),
    ];
    for proof in &executed.proofs {
        originals.push(put(
            &directory,
            &format!("proof-{}.norito", proof.height()),
            &norito::encode_canonical(proof).unwrap(),
            REGISTRATION_PROOF_MAX_BYTES_V1,
        ));
    }
    let frames = executed
        .proofs
        .iter()
        .map(|proof| norito::encode_canonical(proof).unwrap())
        .collect::<Vec<_>>();
    let (locator, registration) = publish_registration_source_v1(
        &directory,
        "native-registration",
        RegistrationSelectionV1 {
            genesis: &genesis,
            scheme: &executed.scheme,
            asset_digest: setup.asset.asset_digest(),
            instruction_index: 0,
        },
        Cursor::new(&committed_bytes),
        frames.iter().map(|frame| Ok(Cursor::new(frame))),
        || false,
    )
    .unwrap();
    assert_eq!(registration.height(), 5);
    assert_eq!(registration.asset(), &setup.asset);
    assert_eq!(registration.scheme(), &executed.scheme);
    assert_eq!(registration.reserve(), &setup.reserve);
    let TransactionEntrypoint::External(signed) = &executed.committed.entrypoint else {
        panic!("external Register");
    };
    assert_eq!(registration.transaction_hash(), *signed.hash().as_ref());
    originals.push(put(
        &directory,
        "native-registration.norito",
        &locator.encode_canonical().unwrap(),
        REGISTRATION_SOURCE_MAX_BYTES_V1,
    ));
    originals.push(put(
        &directory,
        "successor-proof.norito",
        &norito::encode_canonical(following).unwrap(),
        REGISTRATION_PROOF_MAX_BYTES_V1,
    ));
    assert_eq!(originals.len(), 12);
    let manifest = norito::json!({
        "schema": SCHEMA,
        "chain_id": CHAIN,
        "network_hex": (hex::encode(setup.chain.network_id().as_bytes())),
        "instance_hex": (hex::encode(genesis.instance().0)),
        "scheme_id_hex": (hex::encode(executed.scheme.scheme_id())),
        "asset_digest_hex": (hex::encode(setup.asset.asset_digest())),
        "registration_height": 5, "following_height": 6, "instruction_index": 0,
        "failed_registration_heights": (vec![3, 4]),
        "transaction_hash_hex": (hex::encode(registration.transaction_hash())),
        "block_hash_hex": (hex::encode(registration.block_hash())),
        "scope": "Actual StateExecutor refusals at H3/H4, successful Register at H5, signed Log at H6; ordinary native finality verified. Four-seat fixture signs exact three-vote certificates. No recursive proof, Load event, wallet grant, deployment or device qualification.",
        "originals": originals,
    });
    put(
        &directory,
        "capture.json",
        &norito::json::to_vec(&manifest).unwrap(),
        MANIFEST_MAX,
    );
    directory.sync().unwrap();
    parent.sync().unwrap();
}

#[test]
fn executed_registration_capture_is_exact_private_and_refuses_pin_substitution_or_overwrite() {
    let setup = start();
    let selected = scheme(&setup);
    let original = selected.to_canonical_bytes().unwrap();
    let scheme_sha: [u8; 32] = Sha256::digest(&original).into();
    let genesis_sha: [u8; 32] = Sha256::digest(setup.chain.genesis().encode_wire().unwrap()).into();
    assert_eq!(
        require_pins(
            &setup,
            &original,
            scheme_sha,
            selected.scheme_id(),
            genesis_sha
        ),
        selected
    );
    for change in 0..3 {
        let mut bad_scheme_sha = scheme_sha;
        let mut bad_scheme_id = selected.scheme_id();
        let mut bad_genesis_sha = genesis_sha;
        match change {
            0 => bad_scheme_sha[0] ^= 1,
            1 => bad_scheme_id[0] ^= 1,
            _ => bad_genesis_sha[0] ^= 1,
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                require_pins(
                    &setup,
                    &original,
                    bad_scheme_sha,
                    bad_scheme_id,
                    bad_genesis_sha,
                )
            }))
            .is_err()
        );
    }
    let mut executed = execute_registration(setup, selected);
    let following = successor(&mut executed);
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/qualification");
    fs::create_dir_all(&scratch).unwrap();
    let temp = tempfile::tempdir_in(scratch).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let output = temp.path().canonicalize().unwrap().join("registration");
    export(&executed, &following, &output);
    let original_manifest =
        iroha_fs::read_private(output.join("capture.json"), MANIFEST_MAX).unwrap();
    let manifest: norito::json::Value = norito::json::from_slice(&original_manifest).unwrap();
    assert_eq!(manifest["schema"].as_str(), Some(SCHEMA));
    assert_eq!(manifest["registration_height"].as_u64(), Some(5));
    assert_eq!(manifest["following_height"].as_u64(), Some(6));
    assert_eq!(manifest["originals"].as_array().unwrap().len(), 12);
    for row in manifest["originals"].as_array().unwrap() {
        let data = iroha_fs::read_private(
            output.join(row["name"].as_str().unwrap()),
            REGISTRATION_PROOF_MAX_BYTES_V1,
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&*data)),
            row["sha256"].as_str().unwrap()
        );
        assert_eq!(data.len() as u64, row["bytes"].as_u64().unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(output.join(row["name"].as_str().unwrap()))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }
    }
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| export(
            &executed, &following, &output
        )))
        .is_err()
    );
    assert_eq!(
        &*iroha_fs::read_private(output.join("capture.json"), MANIFEST_MAX).unwrap(),
        &*original_manifest
    );
}

#[test]
#[ignore = "exports actual terminal Register under externally pinned scheme and canonical genesis for genuine compact proving"]
fn export_executed_terminal_registration_for_compact_differential() {
    let original = iroha_fs::read_private(
        std::env::var_os("KAGEMUSHA_REGISTER_SCHEME_ORIGINAL")
            .expect("exact signed-installation scheme original"),
        KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
    )
    .unwrap();
    let setup = start();
    let selected = require_pins(
        &setup,
        &original,
        pin("KAGEMUSHA_REGISTER_SCHEME_SHA256"),
        pin("KAGEMUSHA_WALLET_SCHEME_ID"),
        pin("KAGEMUSHA_REGISTER_GENESIS_SHA256"),
    );
    let mut executed = execute_registration(setup, selected);
    let following = successor(&mut executed);
    let output =
        std::env::var_os("KAGEMUSHA_REGISTER_CAPTURE_OUTPUT").expect("fresh private output child");
    export(&executed, &following, Path::new(&output));
}
