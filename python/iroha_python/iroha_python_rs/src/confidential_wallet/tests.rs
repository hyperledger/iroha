//! Native Python wallet ownership, bounded parsing and real proof controls.

use super::*;
use iroha_core_zk::confidential_v2 as note;
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{NetworkId, block::BlockHeader};

fn context() -> (PyNetworkId, String) {
    (
        PyNetworkId {
            inner: NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
                Hash::new(b"python-confidential-wallet-test"),
            )),
        },
        AssetDefinitionId::from_uuid_bytes([
            1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16,
        ])
        .expect("asset")
        .to_string(),
    )
}

fn input_dict(py: Python<'_>, amount: u128) -> Bound<'_, PyDict> {
    let dict = PyDict::new(py);
    dict.set_item("amount", amount).expect("amount");
    dict.set_item("rho", PyBytes::new(py, &[7; 32]))
        .expect("rho");
    dict.set_item(
        "diversifier",
        PyBytes::new(py, &note::default_confidential_diversifier_v2()),
    )
    .expect("diversifier");
    dict.set_item("leaf_index", 0).expect("index");
    dict
}

fn assert_code(py: Python<'_>, error: PyErr, expected: &str) {
    assert!(error.is_instance_of::<ConfidentialWalletError>(py));
    let args: (String, String) = error
        .value(py)
        .getattr("args")
        .expect("args")
        .extract()
        .expect("typed args");
    assert_eq!(args.0, expected);
}

#[test]
fn confidential_python_private_derivation_matches_core_and_rejects_partial_hex() {
    Python::initialize();
    Python::attach(|py| {
        let seed = PyBytes::new(py, &[3; 32]);
        let hex = PyString::new(py, &"03".repeat(32));
        assert_eq!(
            &*secret_bytes(seed.as_any(), 32).expect("bytes"),
            &*secret_bytes(hex.as_any(), 32).expect("hex")
        );
        assert!(secret_bytes(seed.as_any(), 31).is_err());
        assert!(secret_word(PyString::new(py, "03030303xz").as_any()).is_err());
        assert!(secret_word(PyString::new(py, "030").as_any()).is_err());
        assert!(
            super::super::parse_confidential_amount_py(PyBool::new(py, true).as_any(), "amount")
                .is_err()
        );
        assert!(
            super::super::parse_confidential_amount_py(PyString::new(py, "7").as_any(), "amount")
                .is_err()
        );
        let expected_diversifier = note::derive_confidential_diversifier_v2(&[3; 32]);
        assert_eq!(
            super::super::default_confidential_diversifier_v2_py(py)
                .bind(py)
                .as_bytes(),
            &note::default_confidential_diversifier_v2(),
        );
        let diversifier = super::super::derive_confidential_diversifier_v2_py(py, seed.as_any())
            .expect("derive diversifier");
        assert_eq!(diversifier.bind(py).as_bytes(), &expected_diversifier);
        let expected_owner =
            note::derive_confidential_owner_tag_v2_with_diversifier(&[3; 32], expected_diversifier)
                .expect("owner");
        let owner = super::super::derive_confidential_owner_tag_v2_py(
            py,
            hex.as_any(),
            diversifier.bind(py).as_any(),
        )
        .expect("derive owner");
        assert_eq!(owner.bind(py).as_bytes(), &expected_owner);
        let (_, asset) = context();
        let amount = 7_u128.into_pyobject(py).expect("amount").into_any();
        let actual = super::super::derive_confidential_note_v2_py(
            py,
            asset.clone(),
            &amount,
            seed.as_any(),
            owner.bind(py).as_any(),
        )
        .expect("derive note");
        assert_eq!(
            actual.bind(py).as_bytes(),
            &note::derive_confidential_note_v2(&asset, 7, [3; 32], expected_owner).expect("note")
        );
        assert!(
            super::super::derive_confidential_owner_tag_v2_py(
                py,
                seed.as_any(),
                PyBytes::new(py, &[4; 31]).as_any()
            )
            .is_err()
        );
    });
}

#[test]
fn confidential_python_wallet_closure_preserves_active_owner_and_redacts_context() {
    Python::initialize();
    Python::attach(|py| {
        let (network, asset) = context();
        let key = PyBytes::new(py, &[3; 32]);
        let wallet = PyConfidentialProver::new(&network, &asset, key.as_any()).expect("wallet");
        assert_eq!(
            wallet.__repr__(),
            "ConfidentialProver(private_context=[REDACTED])"
        );
        let running = wallet.acquire().expect("running owner");
        let weak = Arc::downgrade(&running);
        wallet.close().expect("close");
        wallet.close().expect("idempotent close");
        assert_code(py, wallet.acquire().expect_err("closed"), "closed");
        assert!(weak.upgrade().is_some());
        drop(running);
        assert!(
            weak.upgrade().is_none(),
            "the last job releases the clearing Core owner"
        );
        assert_eq!(
            key.as_bytes(),
            &[3; 32],
            "caller Python bytes are not modified"
        );
        assert_code(
            py,
            PyConfidentialProver::new(&network, &asset, PyBytes::new(py, &[0; 32]).as_any())
                .err()
                .expect("zero key"),
            "invalid_spend_key",
        );
        assert_code(
            py,
            PyConfidentialProver::new(&network, "not-an-asset", key.as_any())
                .err()
                .expect("bad asset"),
            "invalid_input",
        );
    });
}

#[test]
fn confidential_python_wallet_parses_bounds_and_fails_before_tree_or_key_work() {
    Python::initialize();
    Python::attach(|py| {
        let (network, asset) = context();
        let wallet =
            PyConfidentialProver::new(&network, &asset, PyBytes::new(py, &[3; 32]).as_any())
                .expect("wallet");
        let empty = PyList::empty(py);
        let invalid_tree = PyBytes::new(py, &[0]);
        let amount = 1_u128.into_pyobject(py).expect("amount").into_any();
        assert_code(
            py,
            wallet
                .prove_unshield(
                    py,
                    invalid_tree.as_any(),
                    empty.as_any(),
                    &amount,
                    None,
                    None,
                    None,
                )
                .expect_err("empty"),
            "input_count",
        );
        let inputs = PyList::new(
            py,
            [input_dict(py, 1), input_dict(py, 1), input_dict(py, 1)],
        )
        .expect("list");
        assert_code(
            py,
            wallet
                .prove_unshield(
                    py,
                    invalid_tree.as_any(),
                    inputs.as_any(),
                    &amount,
                    None,
                    None,
                    None,
                )
                .expect_err("too many"),
            "invalid_input",
        );
        let partial = input_dict(py, 1);
        partial.del_item("diversifier").expect("partial input");
        assert_code(
            py,
            input(partial.as_any()).expect_err("partial secret parse"),
            "invalid_input",
        );
        let malformed = input_dict(py, 1);
        malformed.set_item("amount", true).expect("bool");
        assert_code(
            py,
            input(malformed.as_any()).expect_err("boolean amount"),
            "invalid_input",
        );
        assert_code(
            py,
            word(PyBytes::new(py, &[2; 31]).as_any()).expect_err("word width"),
            "invalid_input",
        );
        let change = PyDict::new(py);
        change.set_item("amount", 1).expect("change amount");
        assert_code(
            py,
            super::change(change.as_any()).expect_err("missing change nonce"),
            "invalid_input",
        );
        change
            .set_item("rho", PyBytes::new(py, &[7; 32]))
            .expect("rho");
        assert_eq!(super::change(change.as_any()).expect("change").amount, 1);
        let output = PyDict::new(py);
        output.set_item("amount", 1).expect("amount");
        output
            .set_item("rho", PyBytes::new(py, &[8; 32]))
            .expect("rho");
        output
            .set_item("owner_tag", PyBytes::new(py, &[9; 32]))
            .expect("owner");
        assert_eq!(
            super::output(output.as_any()).expect("output").owner_tag,
            [9; 32]
        );
        let leaves = PyTuple::new(py, [PyBytes::new(py, &[4; 32])]).expect("leaves");
        let root = PyBytes::new(py, &[5; 32]);
        let tree = Tree::parse(root.as_any(), Some(leaves.as_any()), None).expect("tree");
        assert!(
            matches!(tree.borrowed(), ConfidentialTree::Commitments { leaves, .. } if leaves.len() == 1)
        );
        assert_code(
            py,
            Tree::parse(root.as_any(), Some(leaves.as_any()), Some(empty.as_any()))
                .err()
                .expect("ambiguous tree"),
            "invalid_input",
        );
        let zero_inputs = PyList::new(py, [input_dict(py, 0)]).expect("inputs");
        let outputs = PyList::new(py, [output]).expect("outputs");
        assert_code(
            py,
            wallet
                .prove_transfer(
                    py,
                    root.as_any(),
                    zero_inputs.as_any(),
                    outputs.as_any(),
                    Some(leaves.as_any()),
                    None,
                )
                .expect_err("invalid amount before key work"),
            "invalid_transfer_amounts",
        );
    });
}

#[test]
fn confidential_python_wallet_full_redemption_produces_self_verified_material() {
    Python::initialize();
    Python::attach(|py| {
        let (network, asset) = context();
        let key = [3; 32];
        let wallet = PyConfidentialProver::new(&network, &asset, PyBytes::new(py, &key).as_any())
            .expect("wallet");
        let owner = note::derive_confidential_owner_tag_v2_with_diversifier(
            &key,
            note::default_confidential_diversifier_v2(),
        )
        .expect("owner");
        let commitment =
            note::derive_confidential_note_v2(&asset, 7, [7; 32], owner).expect("commitment");
        let merkle = note::compute_confidential_merkle_path_v2(&[commitment], 0).expect("path");
        let root = merkle.root;
        // Exercise the same list-of-integer directions emitted by the public
        // native derivation helper; PyO3 converts a raw Vec<u8> to Python bytes.
        let path = super::super::confidential_merkle_path_v2_py_dict(py, 0, commitment, merkle)
            .expect("public path shape");
        let paths = PyList::new(py, [path]).expect("paths");
        let inputs = PyList::new(py, [input_dict(py, 7)]).expect("inputs");
        let amount = 7_u128.into_pyobject(py).expect("amount").into_any();
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiting = std::thread::spawn(move || {
            Python::attach(|_| sender.send(()).expect("GIL progress"));
        });
        let result = wallet
            .prove_unshield(
                py,
                PyBytes::new(py, &root).as_any(),
                inputs.as_any(),
                &amount,
                None,
                None,
                Some(paths.as_any()),
            )
            .expect("real proof");
        receiver
            .try_recv()
            .expect("another Python thread acquired the GIL during native proving");
        waiting.join().expect("GIL worker");
        let result = result.bind(py);
        assert_eq!(
            member(result, "relation")
                .expect("relation")
                .extract::<String>()
                .expect("string"),
            "full_redemption"
        );
        assert_eq!(
            member(result, "nullifiers")
                .expect("nullifiers")
                .len()
                .expect("len"),
            1
        );
        assert_eq!(
            member(result, "output_commitments")
                .expect("outputs")
                .len()
                .expect("len"),
            0
        );
        assert!(
            !member(result, "proof")
                .expect("proof")
                .cast::<PyBytes>()
                .expect("bytes")
                .as_bytes()
                .is_empty()
        );
        wallet.close().expect("close");
    });
}
