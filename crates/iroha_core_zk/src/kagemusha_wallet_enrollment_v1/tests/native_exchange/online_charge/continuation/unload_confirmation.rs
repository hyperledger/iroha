//! Confirm the historical charged Unload after the same wallet absorbed its later Load.
//!
//! The existing eight stages retain their original assertions. This ninth continuation
//! consumes their pinned results, never reenrolls or repeats a monetary operation, and
//! preserves the exact Unload original after recording certified successful inclusion.
//! TODO: Compile and execute with matching captured harnesses after the next source batch.

use super::*;

#[test]
#[ignore = "requires successful charged-Load absorption, SAME seed111 custody and exact H8 charged-Unload finality through H12"]
fn actual_same_a_confirms_charged_unload_after_absorption_and_restart() {
    let output = fresh_output("KAGEMUSHA_NATIVE_CHARGED_UNLOAD_CONFIRMATION_OUTPUT");
    let sources = Sources::requalify(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let scheme = &f.config.scheme;
    let producer_path = selected_path("KAGEMUSHA_NATIVE_CHARGE_RESULT");
    let producer_bytes = read_pin(
        &producer_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_CHARGE_RESULT_SHA256"),
    );
    let producer: norito::json::Value = norito::json::from_slice(&producer_bytes).unwrap();
    assert_eq!(
        producer["schema"].as_str(),
        Some("iroha.kagemusha.native-online-charge-result.v1")
    );
    assert_eq!(producer["variant"].as_str(), Some("online-charges"));
    assert_eq!(producer["source_pins"], source_pins());
    assert_eq!(
        producer["executed_ledger_setup_sha256"].as_str(),
        Some(setup.manifest_sha256.as_str())
    );
    assert_eq!(digest(&producer["scheme_id"]), scheme.scheme_id());
    assert_eq!(
        digest(&producer["manifest_digest"]),
        sources.qualified.installation().1
    );
    inventory(
        &producer,
        &[
            "regulatory-certificate.norito",
            "load-quote.norito",
            "stale-load-quote.norito",
            "exhausting-load-quote.norito",
            "unload-quote.norito",
            "stale-unload-quote.norito",
            "unload-claim.norito",
        ]
        .map(str::to_owned),
    );
    let claim_bytes = original(
        producer_path.parent().unwrap(),
        &producer,
        "unload-claim.norito",
        KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1,
    );
    let claim =
        KagemushaWalletUnloadClaimV1::decode_canonical(&claim_bytes, &scheme.scheme_id()).unwrap();
    let paid = claim.verify(scheme).unwrap();
    assert_eq!(
        (paid.amount, paid.account_payout, paid.online_charge),
        (100, 95, 5)
    );
    assert_eq!(claim.account, setup.accounts[0]);
    assert_eq!(claim.charge.beneficiary(), Some(&setup.accounts[2]));
    assert_eq!(claim.package.statement.next_load, 1);
    sources
        .installed
        .verifier()
        .verify_package_proofs(&claim.package, MemoryBudget::DEFAULT)
        .unwrap();

    let capture_path = selected_path("KAGEMUSHA_EXECUTED_CHARGE_CONTINUATION");
    let capture_bytes = read_pin(
        &capture_path,
        32 << 10,
        &env_pin("KAGEMUSHA_EXECUTED_CHARGE_CONTINUATION_SHA256"),
    );
    let capture: norito::json::Value = norito::json::from_slice(&capture_bytes).unwrap();
    let (load_height, unload_height, through) = evidence_inventory(&capture);
    assert_eq!((load_height, unload_height, through), (7, 8, 12));
    assert_eq!(
        capture["producer_sha256"].as_str(),
        Some(sha(&producer_bytes).as_str())
    );
    for field in ["target_sha256", "scheme_id", "manifest_digest"] {
        assert_eq!(capture[field], producer[field]);
    }
    assert_eq!(
        capture["initial_receipt_sha256"],
        producer["receipt_sha256"]
    );
    let capture_root = capture_path.parent().unwrap();
    let payout_bytes = original(capture_root, &capture, "unload-payout.norito", 4096);
    let payout: KagemushaWalletPayoutRecordV1 = decode(&payout_bytes);
    let transaction = digest(&capture["unload_transaction_hash"]);
    assert_ne!(transaction, digest(&capture["load_transaction_hash"]));
    assert_eq!(
        payout.key,
        KagemushaWalletPayoutKeyV1::Unload(paid.nullifier)
    );
    assert_eq!(
        (payout.source, payout.amount, payout.transaction),
        (paid.package, 100, transaction)
    );

    let absorption_path = selected_path("KAGEMUSHA_NATIVE_CHARGED_LOAD_RESULT");
    let absorption_bytes = read_pin(
        &absorption_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_CHARGED_LOAD_RESULT_SHA256"),
    );
    let absorption: norito::json::Value = norito::json::from_slice(&absorption_bytes).unwrap();
    assert_eq!(
        absorption["schema"].as_str(),
        Some("iroha.kagemusha.native-charged-load-absorption.v1")
    );
    assert_eq!(absorption["origin"].as_str(), Some("core"));
    assert_eq!(absorption["source_pins"], source_pins());
    assert_eq!(
        absorption["native_binary_sha256"].as_str(),
        Some(executable_hash().as_str())
    );
    assert_eq!(
        absorption["producer_sha256"].as_str(),
        Some(sha(&producer_bytes).as_str())
    );
    assert_eq!(
        absorption["execution_sha256"].as_str(),
        Some(sha(&capture_bytes).as_str())
    );
    assert_eq!(absorption["target_sha256"], producer["target_sha256"]);
    assert_eq!(
        (
            absorption["load_height"].as_u64(),
            absorption["unload_height"].as_u64(),
            absorption["last_certified_height"].as_u64()
        ),
        (Some(7), Some(8), Some(12))
    );
    assert_eq!(
        absorption["native_balance_atomic_units"].as_str(),
        Some("100")
    );
    assert_eq!(absorption["native_next_load"].as_str(), Some("2"));
    assert_eq!(absorption["new_payment_signatures"].as_u64(), Some(1));
    assert_eq!(
        absorption["original_pending_unload_retained"].as_bool(),
        Some(true)
    );
    assert_eq!(
        absorption["exact_retry_after_restart"].as_bool(),
        Some(true)
    );
    assert_eq!(
        absorption["ledger_balances_atomic_units"],
        norito::json!(["892", "0", "8", "100"])
    );
    let originals = norito::json!({"originals":(absorption["complete_online_originals"].clone())});
    inventory(
        &originals,
        &[
            "charged-load-receipt.norito",
            "charged-load-finality.norito",
            "charged-load-package.norito",
        ]
        .map(str::to_owned),
    );
    let loaded_bytes = original(
        absorption_path.parent().unwrap(),
        &originals,
        "charged-load-package.norito",
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    );
    let loaded =
        KagemushaWalletPackageV1::decode_canonical(&loaded_bytes, &scheme.scheme_id()).unwrap();
    assert_eq!(loaded.statement.next_load, 2);
    assert_eq!(loaded.statement.sequence, 3);
    assert!(matches!(
        loaded.statement.effect,
        KagemushaWalletEffectV1::Load {
            load_ordinal: 1,
            amount: 100,
            online_charge: 3,
            ..
        }
    ));
    sources
        .installed
        .verifier()
        .verify_package_proofs(&loaded, MemoryBudget::DEFAULT)
        .unwrap();

    let target_path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &target_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    assert_eq!(target["variant"].as_str(), Some("online-charges"));
    assert_eq!(
        producer["target_sha256"].as_str(),
        Some(sha(&target_bytes).as_str())
    );
    assert_eq!(
        producer["receipt_sha256"].as_str(),
        Some(env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256").as_str())
    );
    let public = target_path.parent().unwrap();
    let frames = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let initial_command: KagemushaWalletLedgerV1 =
        decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames, &initial_command);
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &scheme.scheme_id()).unwrap();
    assert_eq!(
        credential.body.payment_key,
        public_key(&signing_key(CHARGE_KEY_SEED))
    );
    assert_eq!(credential, claim.credential);
    assert_eq!(
        credential.body.wallet_id,
        digest(&producer["payer_wallet_id"])
    );
    assert_eq!(
        credential.credential_digest(),
        digest(&producer["payer_credential_digest"])
    );
    loaded.verify(&credential).unwrap();
    let beneficiary = norito::encode_canonical(&setup.accounts[2]).unwrap();
    let unload_request = digest(&producer["unload_request_id"]);
    assert_eq!(unload_request, [241; 32]);

    let device = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential);
    let mut a = sources.open(&device, &f, &frames);
    let before = a.snapshot().unwrap();
    let epoch = a.epoch_progress().unwrap();
    let general_cursor = a.ledger_progress().unwrap();
    assert_eq!(before.head, digest(&absorption["payer_head"]));
    assert_eq!(before.head, loaded.statement.successor.value);
    assert_eq!(before.sequence, 3);
    assert_eq!(
        before.sequence.to_string(),
        absorption["payer_sequence"].as_str().unwrap()
    );
    assert_eq!(before.credential_digest, credential.credential_digest());
    assert_eq!(
        (
            before.owned_balance,
            before.known_burned_total,
            before.folded_balance
        ),
        (100, 0, Some(100))
    );
    assert_eq!(epoch.epoch, absorption["finality_epoch"].as_u64().unwrap());
    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(
        signatures, 0,
        "reopening and confirmation cannot payment-sign"
    );
    assert_eq!(
        a.unload_claim_bytes(&unload_request, Some(&beneficiary))
            .unwrap(),
        claim_bytes
    );
    let instruction = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        KagemushaWalletLedgerActionV1::Unload(claim_bytes.clone()),
    );
    assert_eq!(
        a.ledger_instruction(2, &claim_bytes).unwrap(),
        norito::encode_canonical(&instruction).unwrap()
    );
    // The test, not Native, verifies the recorded prefix to locate the certified block.
    let mut independent = (*sources.genesis).clone();
    let mut certified = None;
    for height in 1..=through {
        let bytes = original(
            capture_root,
            &capture,
            &format!("native-proof-{height}.norito"),
            LEDGER_PROOF_MAX_BYTES_V1,
        );
        let proof: SumeragiFinalityProof = decode(&bytes);
        assert_eq!(proof.height(), height);
        assert_eq!(proof.committee.len(), 4);
        let verified = independent.verify(&proof).unwrap();
        if height > 1 {
            let qc: iroha_sumeragi::message::Qc =
                decode(verified.block().commit_certificate().unwrap().commit_qc());
            assert_eq!(qc.signers.count_ones(), 3);
        }
        if height == unload_height {
            require_success(&verified, transaction, &setup.accounts[1], &instruction);
            certified = Some(verified);
        }
    }
    let certified = certified.unwrap();
    let signed = certified
        .block()
        .external_transactions()
        .next()
        .unwrap()
        .clone();
    let wire = signed.encode_wire_v1().unwrap();
    let awaiting = state::LedgerAttemptOutcomeV1::Awaiting {
        entrypoint: transaction,
    };
    assert_eq!(
        a.unload_attempt_outcome(&claim_bytes, &wire).unwrap(),
        awaiting
    );
    let finality = ledger_finality_original(&certified, &signed);
    for limits in [
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
    ] {
        let refusal = norito::with_decode_limits_scope(limits, || {
            a.ingest_unload_finality(&claim_bytes, &wire, &finality)
        });
        assert!(
            matches!(refusal, Err(state::Error::DecodeResource(ref cause)) if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit)
        );
        assert_eq!(
            a.unload_attempt_outcome(&claim_bytes, &wire).unwrap(),
            awaiting
        );
        assert_eq!(a.snapshot().unwrap(), before);
        assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    }
    let state::LedgerAttemptIngestV1::Outcome(state::LedgerAttemptOutcomeV1::Confirmed(expected)) =
        a.ingest_unload_finality(&claim_bytes, &wire, &finality)
            .unwrap()
    else {
        panic!("the charged Unload confirms from one direct original");
    };
    assert_eq!(expected.height, 8);
    assert_eq!(expected.commit_hash, certified.core_hash().0);
    let confirmed = state::LedgerAttemptOutcomeV1::Confirmed(expected);
    // Exact retries are idempotent; altered claims are refused; neither replays the
    // monetary Unload or Load.
    for _ in 0..2 {
        for mode in 0..4 {
            let mut changed = claim.clone();
            match mode {
                0 => changed.account = setup.accounts[1].clone(),
                1 => {
                    let KagemushaWalletEffectV1::Unload {
                        ref mut online_charge,
                        ..
                    } = changed.package.statement.effect
                    else {
                        unreachable!()
                    };
                    *online_charge += 1;
                }
                2 => {
                    let KagemushaWalletUnloadChargeV1::Quoted { ref mut quote, .. } =
                        changed.charge
                    else {
                        unreachable!()
                    };
                    quote.body.online_charge += 1;
                }
                _ => {
                    let KagemushaWalletUnloadChargeV1::Quoted {
                        ref mut beneficiary,
                        ..
                    } = changed.charge
                    else {
                        unreachable!()
                    };
                    *beneficiary = setup.accounts[1].clone();
                }
            }
            let changed = norito::encode_canonical(&changed).unwrap();
            assert_ne!(changed, claim_bytes);
            assert!(a.unload_attempt_outcome(&changed, &wire).is_err());
            assert!(
                a.ingest_unload_finality(&changed, &wire, &finality)
                    .is_err()
            );
            assert_eq!(
                a.unload_attempt_outcome(&claim_bytes, &wire).unwrap(),
                confirmed
            );
            assert_eq!(a.snapshot().unwrap(), before);
            assert_eq!(
                a.unload_claim_bytes(&unload_request, Some(&beneficiary))
                    .unwrap(),
                claim_bytes
            );
            assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
        }
        assert_eq!(
            a.ingest_unload_finality(&claim_bytes, &wire, &finality)
                .unwrap(),
            state::LedgerAttemptIngestV1::Outcome(confirmed)
        );
        drop(a);
        a = sources.open(&device, &f, &frames);
        assert_eq!(
            a.unload_attempt_outcome(&claim_bytes, &wire).unwrap(),
            confirmed
        );
        assert_eq!(a.snapshot().unwrap(), before);
        assert_eq!(a.epoch_progress().unwrap(), epoch);
        assert_eq!(a.ledger_progress().unwrap(), general_cursor);
        assert_eq!(
            a.unload_claim_bytes(&unload_request, Some(&beneficiary))
                .unwrap(),
            claim_bytes
        );
        assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    }
    let confirmation_bytes =
        norito::encode_canonical(&(expected.height, expected.commit_hash)).unwrap();
    publish(&output.join("confirmation.norito"), &confirmation_bytes);
    publish(&output.join("result.json"), &norito::json::to_vec(&norito::json!({
        "schema":"iroha.kagemusha.native-charged-unload-confirmation.v1","origin":"core",
        "source_pins":(source_pins()),"native_binary_sha256":(executable_hash()),
        "producer_sha256":(sha(&producer_bytes)),"execution_sha256":(sha(&capture_bytes)),"absorption_sha256":(sha(&absorption_bytes)),
        "target_sha256":(sha(&target_bytes)),"executed_ledger_setup_sha256":(setup.manifest_sha256),
        "claim_sha256":(sha(&claim_bytes)),"payout_sha256":(sha(&payout_bytes)),"transaction_hash":(hex::encode(transaction)),
        "confirmation_height":(expected.height),"confirmation_commit_hash":(hex::encode(expected.commit_hash)),"confirmation_sha256":(sha(&confirmation_bytes)),
        "native_finality_originals":1,"payer_head":(hex::encode(before.head)),"payer_sequence":(before.sequence.to_string()),
        "native_balance_atomic_units":"100","native_next_load":"2","gross_unload":"100","account_payout":"95","online_unload_charge":"5",
        "original_unload_retained":true,"exact_retry_after_restart":true,"new_payment_signatures":0,
        "scope":"Same retained seed111 A confirms exact successful charged-Unload H8 inclusion from its actual Core chain after absorbing the later net100 Load. One direct finality original of H8 confirms it without changing the monetary head, balance, epoch, general ledger cursor or signature count. Altered claim/account/charge/quote/beneficiary are refused; exact retries are idempotent and the historical Unload original remains recoverable. Test-signed committee and simulated hardware: no four live peers, physical durability or release qualification. The payout row is producer evidence; acknowledgement authority is the authenticated successful transaction inclusion, not a separately authenticated World-row proof."
    })).unwrap());
}
