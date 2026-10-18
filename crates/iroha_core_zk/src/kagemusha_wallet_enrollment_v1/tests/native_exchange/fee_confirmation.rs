//! Genuine certified fee payout acknowledgement returned to the same retained native A.
//!
//! Component and network exporters use the same evidence shape; their origin labels are
//! diagnostic DATA. Only the selected native finality verifier and authenticated complete
//! World row grant acknowledgement. No acknowledgement grants a second payout or balance.
//! TODO: Compile and execute on the current candidate after the dedicated fee journey.

use super::*;
use crate::kagemusha_wallet_state_v1::{
    FinalizedPayoutEvidence, LEDGER_PROOF_MAX_BYTES_V1, RetainedFeeClaim,
};
use iroha_data_model::sumeragi_finality::{
    MAX_WORLD_STATE_SNAPSHOT_BYTES_V1, SumeragiFinalityProof, WorldStateSnapshotV1,
};
use std::collections::BTreeSet;

fn digest(value: &norito::json::Value) -> [u8; 32] {
    let text = value.as_str().unwrap();
    let bytes: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
    assert_ne!(bytes, [0; 32]);
    assert_eq!(hex::encode(bytes), text);
    bytes
}

fn inventory(value: &norito::json::Value, field: &str, expected: &[String]) {
    let rows = value[field].as_array().unwrap();
    assert_eq!(rows.len(), expected.len());
    let names = rows
        .iter()
        .map(|row| {
            assert!(row["bytes"].as_u64().is_some_and(|bytes| bytes > 0));
            digest(&row["sha256"]);
            row["name"].as_str().unwrap().to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(names, expected.iter().cloned().collect::<BTreeSet<_>>());
}

fn evidence_inventory(value: &norito::json::Value) -> (u64, u64) {
    assert_eq!(
        value["schema"].as_str(),
        Some("iroha.kagemusha.fee-payout-evidence.v1")
    );
    assert!(matches!(value["origin"].as_str(), Some("core" | "network")));
    let paid = value["payout_height"].as_u64().unwrap();
    let through = value["last_certified_height"].as_u64().unwrap();
    assert!((6..=64).contains(&paid) && (paid..=64).contains(&through));
    assert_eq!(value["world_height"].as_u64(), Some(through));
    let expected = ["fee-payout.norito", "world-snapshot.norito"]
        .into_iter()
        .map(str::to_owned)
        .chain((1..=through).map(|height| format!("native-proof-{height}.norito")))
        .collect::<Vec<_>>();
    inventory(value, "originals", &expected);
    (paid, through)
}

fn original(
    root: &Path,
    value: &norito::json::Value,
    field: &str,
    name: &str,
    maximum: usize,
) -> Vec<u8> {
    target_original(
        root,
        &norito::json!({"files":(value[field].clone())}),
        name,
        maximum,
    )
}

#[test]
fn fee_evidence_inventory_rejects_missing_duplicate_foreign_roles_and_heights() {
    let rows = ["fee-payout.norito", "world-snapshot.norito"]
        .into_iter()
        .map(str::to_owned)
        .chain((1..=11).map(|height| format!("native-proof-{height}.norito")))
        .map(|name| norito::json!({"name":name,"bytes":1,"sha256":(hex::encode([7;32]))}))
        .collect::<Vec<_>>();
    let valid = norito::json!({"schema":"iroha.kagemusha.fee-payout-evidence.v1","origin":"core","payout_height":9,"world_height":11,"last_certified_height":11,"originals":rows});
    assert_eq!(evidence_inventory(&valid), (9, 11));
    for mode in 0..7 {
        let mut changed = valid.clone();
        if mode < 3 {
            let rows = changed
                .as_object_mut()
                .unwrap()
                .get_mut("originals")
                .unwrap()
                .as_array_mut()
                .unwrap();
            match mode {
                0 => {
                    rows.pop();
                }
                1 => {
                    rows[1] = rows[0].clone();
                }
                _ => {
                    rows[0]
                        .as_object_mut()
                        .unwrap()
                        .insert("name".into(), "../foreign.norito".into());
                }
            }
        } else {
            let (name, value) = match mode {
                3 => ("world_height", 10.into()),
                4 => ("last_certified_height", 65.into()),
                5 => ("payout_height", 12.into()),
                _ => ("origin", "unverified".into()),
            };
            changed.as_object_mut().unwrap().insert(name.into(), value);
        }
        assert!(std::panic::catch_unwind(|| evidence_inventory(&changed)).is_err());
    }
    assert!(std::panic::catch_unwind(|| digest(&norito::json!("07"))).is_err());
    assert!(std::panic::catch_unwind(|| digest(&norito::json!(hex::encode([0; 32])))).is_err());
}

#[test]
#[ignore = "requires dedicated completed fee journey, SAME A/B custody, and genuine Core or four-validator certified fee payout evidence"]
fn actual_a_acknowledges_certified_fee_payout_with_restart_and_exact_retry() {
    let output = fresh_output("KAGEMUSHA_NATIVE_FEE_CONFIRMATION_OUTPUT");
    let sources = Sources::requalify(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let scheme = &f.config.scheme;
    let producer_path = selected_path("KAGEMUSHA_NATIVE_FEE_RESULT");
    let producer_bytes = read_pin(
        &producer_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_FEE_RESULT_SHA256"),
    );
    let producer: norito::json::Value = norito::json::from_slice(&producer_bytes).unwrap();
    assert_eq!(
        producer["schema"].as_str(),
        Some("iroha.kagemusha.native-fee-result.v1")
    );
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
    assert_eq!(
        producer["target_sha256"].as_str(),
        Some(env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256").as_str())
    );
    assert_eq!(
        producer["receipt_sha256"].as_str(),
        Some(env_pin("KAGEMUSHA_NATIVE_LOAD_RECEIPT_SHA256").as_str())
    );
    inventory(
        &producer,
        "originals",
        &[
            "request.norito".into(),
            "payment.norito".into(),
            "fee-claim.norito".into(),
        ],
    );
    let producer_root = producer_path.parent().unwrap();
    let request_bytes = original(
        producer_root,
        &producer,
        "originals",
        "request.norito",
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    );
    let payment_bytes = original(
        producer_root,
        &producer,
        "originals",
        "payment.norito",
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    );
    let claim_bytes = original(
        producer_root,
        &producer,
        "originals",
        "fee-claim.norito",
        KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1,
    );
    let request: KagemushaWalletRequestV1 = decode(&request_bytes);
    let payment =
        KagemushaWalletPaymentV1::decode_canonical(&payment_bytes, &scheme.scheme_id()).unwrap();
    let claim =
        KagemushaWalletFeeClaimV1::decode_canonical(&claim_bytes, &scheme.scheme_id()).unwrap();
    assert_eq!(claim.payment, payment);
    assert_eq!(claim.beneficiary, setup.accounts[2]);
    assert_eq!((request.body.amount, request.body.fee), (97, 3));
    let target_path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &target_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    assert_eq!(target["variant"].as_str(), Some("fee97-plus3"));
    let public = target_path.parent().unwrap();
    let frames = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let load: KagemushaWalletLedgerV1 =
        decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames, &load);
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &scheme.scheme_id()).unwrap();
    assert_eq!(credential.body.payment_key, public_key(&signing_key(101)));
    assert_eq!(
        credential.body.wallet_id,
        digest(&producer["payer_wallet_id"])
    );
    assert_eq!(
        credential.credential_digest(),
        digest(&producer["payer_credential_digest"])
    );
    let certificates: KagemushaWalletCertificateSetV1 = decode(&frames[1]);
    let digests = payment
        .verify(scheme, &credential, &certificates, &request)
        .unwrap();
    let verified_claim = claim
        .verify(scheme, &request, &credential, &certificates)
        .unwrap();
    assert_eq!(verified_claim.payment, digests.payment);
    sources
        .installed
        .verifier()
        .verify_package_proofs(&payment.send, MemoryBudget::DEFAULT)
        .unwrap();
    let retained = RetainedFeeClaim {
        payment: payment_bytes,
        request: request_bytes,
    };
    assert_eq!(
        retained
            .ledger_claim_bytes(
                &scheme.scheme_id(),
                &norito::encode_canonical(&setup.accounts[2]).unwrap()
            )
            .unwrap(),
        claim_bytes
    );
    let device = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential);
    let mut a = sources.open(&device, &f, &frames);
    let before = a.snapshot().unwrap();
    assert_eq!(before.head, digest(&producer["a_final_head"]));
    assert_eq!(
        before.sequence.to_string(),
        producer["a_final_sequence"].as_str().unwrap()
    );
    assert_eq!(
        (
            before.owned_balance,
            before.known_burned_total,
            before.folded_balance
        ),
        (0, 0, Some(0))
    );
    assert_eq!(
        a.epoch_progress().unwrap().epoch,
        producer["finality_epoch"].as_u64().unwrap()
    );
    assert_eq!(
        a.fee_claim(digests.credit_id).unwrap(),
        Some(retained.clone())
    );
    assert_eq!(
        a.request_fee_selection().unwrap(),
        (f.asset.asset_digest(), [0; 32])
    );
    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(signatures, 0, "confirmation reopening must never sign");

    let f_b = sources.fixture(&setup, 1);
    inventory(
        &producer,
        "b_open_originals",
        &FRAME_NAMES.map(str::to_owned),
    );
    let b_root = producer_root.join("wallet-b");
    let b_frames =
        FRAME_NAMES.map(|name| original(&b_root, &producer, "b_open_originals", name, 32768));
    let b_credential =
        KagemushaWalletCredentialV1::decode_canonical(&b_frames[0], &scheme.scheme_id()).unwrap();
    assert_eq!(b_credential, request.receiver_credential);
    assert_eq!(decode::<AccountId>(&b_frames[2]), setup.accounts[1]);
    assert_eq!(decode::<KagemushaWalletAssetScopeV1>(&b_frames[3]), f.asset);
    let b_device = HostDevice::restore(&b_root, &b_credential);
    let mut b = sources.open(&b_device, &f_b, &b_frames);
    let b_before = b.snapshot().unwrap();
    assert_eq!(
        (
            b_before.owned_balance,
            b_before.known_burned_total,
            b_before.folded_balance
        ),
        (97, 0, Some(97))
    );
    assert_eq!(b.fee_claim(digests.credit_id).unwrap(), None);

    let evidence_path = selected_path("KAGEMUSHA_FEE_PAYOUT_EVIDENCE");
    let evidence_bytes = read_pin(
        &evidence_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_FEE_PAYOUT_EVIDENCE_SHA256"),
    );
    let evidence_manifest: norito::json::Value = norito::json::from_slice(&evidence_bytes).unwrap();
    let (paid_height, through) = evidence_inventory(&evidence_manifest);
    assert_eq!(
        evidence_manifest["producer_sha256"].as_str(),
        Some(sha(&producer_bytes).as_str())
    );
    for field in [
        "target_sha256",
        "receipt_sha256",
        "scheme_id",
        "manifest_digest",
    ] {
        assert_eq!(evidence_manifest[field], producer[field]);
    }
    let root = evidence_path.parent().unwrap();
    let payout_bytes = original(
        root,
        &evidence_manifest,
        "originals",
        "fee-payout.norito",
        4096,
    );
    let payout: KagemushaWalletPayoutRecordV1 = decode(&payout_bytes);
    assert_eq!(
        payout.key,
        KagemushaWalletPayoutKeyV1::Fee(digests.credit_id)
    );
    assert_eq!((payout.source, payout.amount), (digests.payment, 3));
    let world_bytes = original(
        root,
        &evidence_manifest,
        "originals",
        "world-snapshot.norito",
        MAX_WORLD_STATE_SNAPSHOT_BYTES_V1,
    );
    let snapshot = WorldStateSnapshotV1::decode_bounded_canonical(&world_bytes).unwrap();
    let mut verifier = (*sources.genesis).clone();
    let mut terminal = None;
    let mut previous = None;
    for height in 1..=through {
        let bytes = original(
            root,
            &evidence_manifest,
            "originals",
            &format!("native-proof-{height}.norito"),
            LEDGER_PROOF_MAX_BYTES_V1,
        );
        let proof: SumeragiFinalityProof = decode(&bytes);
        assert_eq!(proof.height(), height);
        let verified = verifier.verify(&proof).unwrap();
        if height == paid_height {
            let (index, _) = verified
                .block()
                .external_transactions()
                .enumerate()
                .find(|(_, tx)| tx.hash().as_ref() == &payout.transaction)
                .expect("exact paid transaction in certified payout block");
            assert!(verified.block().output_error(index).is_none());
        }
        if height + 1 == through {
            previous = Some(verified.clone());
        }
        if height == through {
            terminal = Some(verified);
        }
    }
    let terminal = terminal.unwrap();
    let previous = previous.unwrap();
    let world = snapshot.authenticate(&terminal).unwrap();
    assert_eq!(
        digest(&evidence_manifest["world_block_hash"]),
        *terminal.block().hash().as_ref()
    );
    assert_eq!(
        digest(&evidence_manifest["world_context_id"]),
        *world.context_id().as_ref()
    );
    assert_eq!(
        digest(&evidence_manifest["world_root"]),
        *world.world_root().as_ref()
    );
    assert_eq!(
        digest(&evidence_manifest["world_schema_hash"]),
        *world.schema_hash().as_ref()
    );
    let evidence = FinalizedPayoutEvidence {
        block: &terminal,
        world: &world,
        payout,
    };
    assert!(matches!(
        b.acknowledge_fee_payout(digests.credit_id, &evidence),
        Err(state::Error::Invalid("unknown fee claim"))
    ));
    assert_eq!(b.snapshot().unwrap(), b_before);
    assert_eq!(b_device.platform.with(|state| state.sign_calls), 0);

    // Test refusals both before acknowledgement and after persisted cleanup/reopening.
    for acknowledged in [false, true] {
        let expected = if acknowledged {
            None
        } else {
            Some(retained.clone())
        };
        let mut wrong_credit = digests.credit_id;
        wrong_credit[0] ^= 1;
        assert!(matches!(
            a.acknowledge_fee_payout(wrong_credit, &evidence),
            Err(state::Error::Invalid("unknown fee claim"))
        ));
        let wrong_cut = FinalizedPayoutEvidence {
            block: &previous,
            world: &world,
            payout,
        };
        assert!(matches!(
            a.acknowledge_fee_payout(digests.credit_id, &wrong_cut),
            Err(state::Error::Invalid("finalized fee payout binding"))
        ));
        for mode in 0..4 {
            let mut changed = payout;
            let reason = match mode {
                0 => {
                    changed.source[0] ^= 1;
                    "finalized fee payout binding"
                }
                1 => {
                    changed.amount += 1;
                    "finalized fee payout binding"
                }
                2 => {
                    changed.key = KagemushaWalletPayoutKeyV1::Fee(wrong_credit);
                    "finalized fee payout binding"
                }
                _ => {
                    changed.transaction[0] ^= 1;
                    "finalized fee payout row"
                }
            };
            let invalid = FinalizedPayoutEvidence {
                block: &terminal,
                world: &world,
                payout: changed,
            };
            assert!(
                matches!(a.acknowledge_fee_payout(digests.credit_id, &invalid), Err(state::Error::Invalid(actual)) if actual == reason)
            );
            assert_eq!(a.fee_claim(digests.credit_id).unwrap(), expected);
            assert_eq!(a.snapshot().unwrap(), before);
            assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
        }
        a.acknowledge_fee_payout(digests.credit_id, &evidence)
            .unwrap();
        assert_eq!(a.fee_claim(digests.credit_id).unwrap(), None);
        a.acknowledge_fee_payout(digests.credit_id, &evidence)
            .unwrap();
        assert_eq!(a.snapshot().unwrap(), before);
        assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
        drop(a);
        a = sources.open(&device, &f, &frames);
        assert_eq!(a.snapshot().unwrap(), before);
        assert_eq!(a.fee_claim(digests.credit_id).unwrap(), None);
        assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    }
    assert_eq!(b.snapshot().unwrap(), b_before);
    assert_eq!(
        before.owned_balance + b_before.owned_balance + payout.amount,
        LOAD_AMOUNT
    );
    let result = norito::json!({
        "schema":"iroha.kagemusha.native-fee-confirmation.v1", "evidence_origin":(evidence_manifest["origin"].clone()),
        "producer_sha256":(sha(&producer_bytes)), "evidence_sha256":(sha(&evidence_bytes)),
        "source_pins":(source_pins()), "native_binary_sha256":(executable_hash()),
        "target_sha256":(sha(&target_bytes)), "claim_sha256":(sha(&claim_bytes)),
        "payout_sha256":(sha(&payout_bytes)), "world_snapshot_sha256":(sha(&world_bytes)),
        "world_height":through, "world_context_id":(evidence_manifest["world_context_id"].clone()),
        "payer_head":(hex::encode(before.head)), "payer_sequence":(before.sequence.to_string()),
        "payer_balance_atomic_units":"0", "receiver_balance_atomic_units":"97", "paid_fee_atomic_units":"3",
        "retained_fee_claim_after_acknowledgement":false, "exact_retry_after_restart":true, "new_payment_signatures":0,
        "scope":"Same retained software A accepts the exact authenticated certified fee payout row, durably records acknowledgement, and removes pending fee originals. Wrong owner, credit, payment, amount, transaction and block/world bindings are refused. Acknowledgement remains bound to the historical Request despite the current zero-fee policy. Component or network origin is preserved as diagnostic evidence provenance; physical hardware, power-loss and enabled offline controls are not qualified. Native balance is unchanged; ledger conservation was asserted by the ordinary executed payout producer.",
    });
    publish(
        &output.join("result.json"),
        &norito::json::to_vec(&result).unwrap(),
    );
}
