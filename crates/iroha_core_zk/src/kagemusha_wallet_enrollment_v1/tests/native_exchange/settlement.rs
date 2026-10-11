//! Artifact-dependent return of actual ledger settlement to the same retained native C owner.
use super::*;
use crate::kagemusha_wallet_state_v1::{
    LEDGER_PROOF_MAX_BYTES_V1, LedgerProgressV1, UnloadFinalityProgressV1,
};
use iroha_data_model::sumeragi_finality::{MAX_FINALITY_BLOCK_BYTES, SumeragiFinalityProof};

fn original(directory: &Path, rows: &[norito::json::Value], name: &str, maximum: usize) -> Vec<u8> {
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

fn digest(value: &norito::json::Value) -> [u8; 32] {
    let bytes = hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_ne!(bytes, [0; 32]);
    bytes
}

// A test receipt projection of the public native result, not a new protocol encoding.
fn confirmation_bytes(value: LedgerProgressV1) -> Vec<u8> {
    norito::encode_canonical(&(value.height, value.block_hash)).unwrap()
}

#[test]
#[ignore = "requires same retained C custody plus actual StateExecutor settlement originals from the genuine A→B→C campaign"]
fn actual_c_confirms_executed_unload_after_process_restart() {
    let output = fresh_output("KAGEMUSHA_NATIVE_SETTLEMENT_CONFIRMATION_OUTPUT");
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 2);
    let exchange_path = selected_path("KAGEMUSHA_NATIVE_EXCHANGE_RESULT");
    let exchange_bytes = read_pin(
        &exchange_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_EXCHANGE_RESULT_SHA256"),
    );
    let exchange: norito::json::Value = norito::json::from_slice(&exchange_bytes).unwrap();
    assert_eq!(
        exchange["schema"].as_str(),
        Some("iroha.kagemusha.native-abc-result.v1")
    );
    assert_eq!(exchange["source_pins"], source_pins());
    assert_eq!(
        exchange["executed_ledger_setup_sha256"].as_str(),
        Some(setup.manifest_sha256.as_str())
    );
    assert_eq!(
        exchange["target_sha256"].as_str(),
        Some(env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256").as_str())
    );
    assert_eq!(
        exchange["c_account_digest"].as_str(),
        Some(hex::encode(kagemusha_wallet_account_digest_v1(&f.account).unwrap()).as_str())
    );
    let device_root = exchange_path.parent().unwrap().join("wallet-c");
    let rows = exchange["c_open_originals"].as_array().unwrap();
    assert_eq!(rows.len(), FRAME_NAMES.len());
    let frames = FRAME_NAMES.map(|name| original(&device_root, rows, name, 32768));
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &f.config.scheme.scheme_id())
            .unwrap();
    assert_eq!(credential.body.wallet_id, digest(&exchange["c_wallet_id"]));
    assert_eq!(decode::<AccountId>(&frames[2]), f.account);
    assert_eq!(decode::<KagemushaWalletAssetScopeV1>(&frames[3]), f.asset);
    let device = HostDevice::restore(&device_root, &credential);
    let mut c = sources.open(&device, &f, &frames);
    let before = c.snapshot().unwrap();
    assert_eq!(before.owned_balance, 0);
    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(signatures, 0, "reopening cannot sign a new payment receipt");

    let settlement_path = selected_path("KAGEMUSHA_EXECUTED_UNLOAD_SETTLEMENT");
    let settlement_bytes = read_pin(
        &settlement_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_EXECUTED_UNLOAD_SETTLEMENT_SHA256"),
    );
    let settlement: norito::json::Value = norito::json::from_slice(&settlement_bytes).unwrap();
    assert_eq!(
        settlement["schema"].as_str(),
        Some("iroha.kagemusha.executed-unload-settlement.v1")
    );
    assert_eq!(
        settlement["network_hex"].as_str(),
        Some(hex::encode(f.config.scheme.network_id).as_str())
    );
    assert_eq!(settlement["target_sha256"], exchange["target_sha256"]);
    assert_eq!(
        settlement["receipt_sha256"].as_str(),
        Some(env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256").as_str())
    );
    assert_eq!(
        settlement["claim_sha256"],
        exchange["c_unload_claim_sha256"]
    );
    assert_eq!(settlement["settlement_height"].as_u64(), Some(6));
    let rows = settlement["originals"].as_array().unwrap();
    assert_eq!(rows.len(), 13);
    let root = settlement_path.parent().unwrap();
    let claim = original(
        root,
        rows,
        "unload-claim.norito",
        KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
    );
    assert_eq!(
        sha(&claim),
        exchange["c_unload_claim_sha256"].as_str().unwrap()
    );
    assert_eq!(
        c.unload_claim_bytes(&digest(&exchange["c_unload_request_id"]), None)
            .unwrap(),
        claim
    );
    let transaction = digest(&settlement["settlement_transaction_hash_hex"]);
    let expected = LedgerProgressV1 {
        height: 6,
        block_hash: digest(&settlement["settlement_block_hash_hex"]),
    };
    let expected_bytes = confirmation_bytes(expected);
    let block = original(root, rows, "unload-block.norito", MAX_FINALITY_BLOCK_BYTES);
    let signed = original(
        root,
        rows,
        "unload-signed-transaction.norito",
        MAX_FINALITY_BLOCK_BYTES,
    );
    let signed: iroha_data_model::transaction::SignedTransaction = decode(&signed);
    assert_eq!(*signed.hash().as_ref(), transaction);
    assert_eq!(signed.authority(), &f.account);
    let instruction = original(
        root,
        rows,
        "unload-instruction.norito",
        state::LEDGER_INSTRUCTION_MAX_BYTES_V1,
    );
    assert_eq!(
        decode::<KagemushaWalletLedgerV1>(&instruction),
        KagemushaWalletLedgerV1::new(
            f.config.scheme.scheme_id(),
            KagemushaWalletLedgerActionV1::Unload(claim.clone())
        )
    );

    assert_eq!(
        c.unload_finality_progress(transaction, &claim).unwrap(),
        UnloadFinalityProgressV1::NotStarted
    );
    assert!(c.confirm_ledger_unload(transaction, &claim).is_err());
    let mut independent = (*sources.genesis).clone();
    for height in 1..=9 {
        let bytes = original(
            root,
            rows,
            &format!("native-proof-{height}.norito"),
            LEDGER_PROOF_MAX_BYTES_V1,
        );
        let proof: SumeragiFinalityProof = decode(&bytes);
        let verified = independent.verify(&proof).unwrap();
        assert_eq!(proof.height(), height);
        if height == 6 {
            assert_eq!(proof.block_wire, block);
            assert_eq!(*verified.block().hash().as_ref(), expected.block_hash);
        }
        let progress = c
            .ingest_unload_finality(transaction, &claim, &bytes)
            .unwrap();
        assert_eq!(progress.height, height);
        assert_eq!(
            c.ingest_unload_finality(transaction, &claim, &bytes)
                .unwrap(),
            progress
        );
        if height < 6 {
            assert_eq!(
                c.unload_finality_progress(transaction, &claim).unwrap(),
                UnloadFinalityProgressV1::Verifying(progress)
            );
            assert!(c.confirm_ledger_unload(transaction, &claim).is_err());
        } else {
            assert_eq!(
                c.unload_finality_progress(transaction, &claim).unwrap(),
                UnloadFinalityProgressV1::Confirmed(expected)
            );
            assert_eq!(
                confirmation_bytes(c.confirm_ledger_unload(transaction, &claim).unwrap()),
                expected_bytes
            );
        }
        if [5, 6, 9].contains(&height) {
            drop(c);
            c = sources.open(&device, &f, &frames);
            if height >= 6 {
                assert_eq!(
                    confirmation_bytes(c.confirm_ledger_unload(transaction, &claim).unwrap()),
                    expected_bytes
                );
            } else {
                assert_eq!(
                    c.unload_finality_progress(transaction, &claim).unwrap(),
                    UnloadFinalityProgressV1::Verifying(progress)
                );
            }
        }
        assert_eq!(c.snapshot().unwrap(), before);
        assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    }
    let mut wrong_transaction = transaction;
    wrong_transaction[0] ^= 1;
    assert!(c.confirm_ledger_unload(wrong_transaction, &claim).is_err());
    let mut changed =
        KagemushaWalletUnloadClaimV1::decode_canonical(&claim, &f.config.scheme.scheme_id())
            .unwrap();
    changed.account = setup.accounts[0].clone();
    assert!(
        c.confirm_ledger_unload(transaction, &norito::encode_canonical(&changed).unwrap())
            .is_err()
    );
    assert_eq!(
        confirmation_bytes(c.confirm_ledger_unload(transaction, &claim).unwrap()),
        expected_bytes
    );
    assert_eq!(c.snapshot().unwrap(), before);
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    publish(&output.join("confirmation.norito"), &expected_bytes);
    let result = norito::json!({
        "schema": "iroha.kagemusha.native-settlement-confirmation.v1",
        "source_pins": (source_pins()), "binary_sha256": (executable_hash()),
        "exchange_sha256": (sha(&exchange_bytes)), "settlement_sha256": (sha(&settlement_bytes)),
        "executed_ledger_setup_sha256": (setup.manifest_sha256),
        "claim_sha256": (sha(&claim)), "transaction_hash_hex": (hex::encode(transaction)),
        "confirmation_sha256": (sha(&expected_bytes)), "confirmation_height": 6,
        "last_native_cursor_height": 9, "new_payment_signatures": 0,
        "scope": "Same retained C incarnation reopened in a separate process with private software hardware fixture; actual StateExecutor settlement evidence, native durable confirmation and reopen/overshoot refusal. No fresh wallet, disk power-loss, physical platform or P2P-network qualification."
    });
    publish(
        &output.join("result.json"),
        &norito::json::to_vec(&result).unwrap(),
    );
}
