//! Closed handshake inputs and exact versioned transaction custody controls.
use super::*;

fn command(phase: &str, selected: &str) -> norito::json::Value {
    let mut value = norito::json!({"schema":"iroha.kagemusha.real-network-command.v1",
        "phase":phase, "setup_sha256":(hash(b"setup")), "previous_sha256":(hash(b"previous"))});
    value.as_object_mut().unwrap().insert(
        selected.into(),
        norito::json!({"path":"/private/original", "sha256":(hash(b"original"))}),
    );
    value
}

#[test]
fn activation_commands_require_closed_phase_and_exact_selected_original() {
    for (phase, selected) in [("funding", "target"), ("activation-retained", "retention")] {
        let original = command(phase, selected);
        require_command(&original, phase).unwrap();
        let mut unknown = original.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("retained".into(), true.into());
        assert!(require_command(&unknown, phase).is_err());
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(selected);
        assert!(require_command(&missing, phase).is_err());
        let mut foreign = original.clone();
        foreign
            .as_object_mut()
            .unwrap()
            .insert("phase".into(), "activation".into());
        assert!(require_command(&foreign, phase).is_err());
        for reference in [
            norito::json!({"path":"relative", "sha256":(hash(b"original"))}),
            norito::json!({"path":"/private/original", "sha256":("00".repeat(32))}),
            norito::json!({"path":"/private/original", "sha256":(hash(b"original")), "confirmed":true}),
        ] {
            let mut changed = original.clone();
            changed
                .as_object_mut()
                .unwrap()
                .insert(selected.into(), reference);
            assert!(require_command(&changed, phase).is_err());
        }
    }
    assert!(require_command(&command("funding", "target"), "other").is_err());
}

const ENTRYPOINT: [u8; 32] = [0x0f; 32];

fn retention(wire: &[u8]) -> norito::json::Value {
    norito::json!({"schema":"iroha.kagemusha.wallet-activation-retained.v1",
        "action":"retain-activation", "signedWireSHA256":(hash(wire)), "signedWireBytes":(wire.len().to_string()),
        "nativeResult":"awaiting", "entrypointHex":("0f".repeat(32)), "nativeReturnedTicks":"123",
        "invocation":"60ae6b58-627c-4c41-88a6-13637881079e", "sequence":"0"})
}

#[test]
fn retention_requires_initial_native_result_and_exact_wire() {
    let wire = b"exact signed transaction";
    let original = retention(wire);
    require_retention(&original, wire, &ENTRYPOINT).unwrap();
    let mut apple = original.clone();
    apple.as_object_mut().unwrap().insert(
        "invocation".into(),
        "60AE6B58-627C-4C41-88A6-13637881079E".into(),
    );
    require_retention(&apple, wire, &ENTRYPOINT).unwrap();
    assert!(require_retention(&original, b"foreign signed transaction", &ENTRYPOINT).is_err());
    assert!(require_retention(&original, wire, &[0x0e; 32]).is_err());
    for (name, value) in [
        ("schema", "iroha.kagemusha.activation-export.v1"),
        ("action", "activation-status"),
        ("nativeResult", "not_started"),
        ("nativeResult", "confirmed"),
        ("nativeResult", "rejected"),
        ("nativeResult", "verifying"),
        ("entrypointHex", &"00".repeat(32)),
        ("entrypointHex", &"0F".repeat(32)),
        ("entrypointHex", &"0f".repeat(31)),
        ("signedWireSHA256", &hash(b"foreign")),
        ("signedWireBytes", "0"),
        ("signedWireBytes", "024"),
        ("nativeReturnedTicks", "0"),
        ("nativeReturnedTicks", "+1"),
        ("sequence", "10000"),
        ("sequence", "00"),
        ("invocation", "60ZE6B58-627C-4C41-88A6-13637881079E"),
        ("invocation", "foreign"),
    ] {
        let mut changed = original.clone();
        changed
            .as_object_mut()
            .unwrap()
            .insert(name.into(), value.into());
        assert!(
            require_retention(&changed, wire, &ENTRYPOINT).is_err(),
            "{name}={value}"
        );
    }
    for name in original.as_object().unwrap().keys() {
        let mut changed = original.clone();
        changed.as_object_mut().unwrap().remove(name);
        assert!(
            require_retention(&changed, wire, &ENTRYPOINT).is_err(),
            "missing {name}"
        );
    }
    let mut changed = original.clone();
    changed
        .as_object_mut()
        .unwrap()
        .insert("retained".into(), true.into());
    assert!(require_retention(&changed, wire, &ENTRYPOINT).is_err());
    changed = original;
    changed
        .as_object_mut()
        .unwrap()
        .insert("sequence".into(), 0.into());
    assert!(require_retention(&changed, wire, &ENTRYPOINT).is_err());
}

#[test]
fn prepared_receipt_binds_complete_versioned_signed_wire_and_predecessors() {
    use iroha_data_model::transaction::{FeePaymentIntent, TransactionBuilder};
    let keys = iroha_crypto::KeyPair::from_seed(vec![41; 32], iroha_crypto::Algorithm::Ed25519);
    let authority = iroha_data_model::account::AccountId::new(keys.public_key().clone());
    let network = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"retention test genesis",
        )),
    );
    let transaction = TransactionBuilder::new(
        network,
        authority,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "retained wire".into(),
    )])
    .sign(keys.private_key());
    let (wire, receipt) = prepared(
        &hash(b"setup"),
        b"registration",
        b"command",
        b"target",
        &transaction,
    )
    .unwrap();
    assert_eq!(wire, transaction.encode_wire_v1().unwrap());
    assert_ne!(wire, norito::encode_canonical(&transaction).unwrap());
    let value: norito::json::Value = norito::json::from_slice(&receipt).unwrap();
    closed(
        &value,
        &[
            "schema",
            "setup_sha256",
            "registration_sha256",
            "funding_command_sha256",
            "target_sha256",
            "transaction_hash_hex",
            "signed_transaction",
        ],
    )
    .unwrap();
    closed(&value["signed_transaction"], &["name", "bytes", "sha256"]).unwrap();
    assert_eq!(
        value["signed_transaction"]["name"].as_str(),
        Some("funding/activate-signed.wire")
    );
    assert_eq!(
        value["signed_transaction"]["bytes"].as_u64(),
        Some(wire.len() as u64)
    );
    assert_eq!(
        value["signed_transaction"]["sha256"].as_str(),
        Some(hash(&wire).as_str())
    );
    assert_eq!(
        value["transaction_hash_hex"].as_str(),
        Some(hex::encode(transaction.hash().as_ref()).as_str())
    );
    for (field, original) in [
        ("registration_sha256", b"registration".as_slice()),
        ("funding_command_sha256", b"command"),
        ("target_sha256", b"target"),
    ] {
        assert_eq!(value[field].as_str(), Some(hash(original).as_str()));
    }
}
