//! Synthetic checkpoint-receipt refusals; no wallet proof or recovery is executed here.

use super::*;

fn sample_snapshot() -> state::Snapshot {
    state::Snapshot {
        scheme_id: [1; 32],
        wallet_id: [2; 32],
        head: [3; 32],
        credential_digest: [4; 32],
        sequence: 3,
        lifecycle: KagemushaWalletLifecycleV1::Active,
        balance: 0,
        core_burned_total: 0,
        known_burned_total: 0,
        owned_balance: 0,
        folded_balance: None,
        fold_backlog: 2,
        verified_fold: Some(state::SnapshotFold {
            sequence: 1,
            head: [5; 32],
            credential_digest: [4; 32],
            burned_total: 0,
        }),
    }
}

fn receipt_fixture(ordinal: u32) -> (norito::json::Value, norito::json::Value) {
    let snapshot = snapshot_record(&sample_snapshot());
    let mut selection = norito::json!({
        "schema": "iroha.kagemusha.retained-send-checkpoint-selection.v1",
        "snapshot_before": snapshot, "cursor_before": (cursor_record((2, ordinal))),
        "maximum_fold_calls": 1, "new_monetary_operations": 0, "retained_fee": 0,
    });
    for (index, field) in [
        "previous_continuation_sha256",
        "selected_send_continuation_sha256",
        "message_originals_manifest_sha256",
        "target_sha256",
        "payment_sha256",
        "archive_sha256",
        "consumer_binary_sha256",
        "consumer_source_sha256",
    ]
    .into_iter()
    .enumerate()
    {
        selection
            .as_object_mut()
            .unwrap()
            .insert(field.into(), sha(&[u8::try_from(index).unwrap()]).into());
    }
    let receipt = norito::json!({
        "schema": "iroha.kagemusha.retained-send-checkpoint-receipt.v1",
        "selection_sha256": (sha(&norito::json::to_vec(&selection).unwrap())),
        "outcome": (outcome_record(&Ok(FoldStatus::Checkpoint { sequence: 2, ordinal }))),
        "fold_calls": 1, "new_keys": 0, "new_signatures": 0, "new_monetary_operations": 0,
        "snapshot_after": snapshot, "snapshot_after_reopen": snapshot,
        "completed_payment_after_reopen_sha256": (selection["payment_sha256"].clone()),
        "archive_after_reopen_sha256": (selection["archive_sha256"].clone()),
        "cursor_after_reopen": (cursor_record((2, ordinal + 1))),
    });
    (selection, receipt)
}

#[test]
fn current_checkpoint_receipt_requires_observed_checkpoint_and_rejects_failures() {
    for ordinal in [1, 3, 17] {
        let (selection, receipt) = receipt_fixture(ordinal);
        let bytes = norito::json::to_vec(&selection).unwrap();
        assert_eq!(require_receipt(&receipt, &bytes), (2, ordinal + 1));
        for result in [
            Err(state::Error::Proof(
                "prepared capsule differs from native derivation",
            )),
            Ok(FoldStatus::Idle),
            Ok(FoldStatus::CaughtUp),
            Ok(FoldStatus::Folded(2)),
            Ok(FoldStatus::Checkpoint {
                sequence: 3,
                ordinal,
            }),
            Ok(FoldStatus::Checkpoint {
                sequence: 2,
                ordinal: ordinal + 1,
            }),
        ] {
            let outcome = outcome_record(&result);
            if result.is_err() {
                assert_eq!(outcome["kind"].as_str(), Some("error"));
                assert!(
                    outcome["description"]
                        .as_str()
                        .unwrap()
                        .contains("prepared capsule")
                );
            }
            let mut changed = receipt.clone();
            changed
                .as_object_mut()
                .unwrap()
                .insert("outcome".into(), outcome);
            assert!(std::panic::catch_unwind(|| require_receipt(&changed, &bytes)).is_err());
        }
    }
}

#[test]
fn current_checkpoint_receipt_binds_reopened_originals_state_and_one_call() {
    let (selection, receipt) = receipt_fixture(3);
    let bytes = norito::json::to_vec(&selection).unwrap();
    for (field, value) in [
        ("selection_sha256", norito::json!(hex::encode([9; 32]))),
        ("fold_calls", norito::json!(2)),
        ("new_keys", norito::json!(1)),
        ("new_signatures", norito::json!(1)),
        ("new_monetary_operations", norito::json!(1)),
        (
            "completed_payment_after_reopen_sha256",
            norito::json!(hex::encode([9; 32])),
        ),
        (
            "archive_after_reopen_sha256",
            norito::json!(hex::encode([9; 32])),
        ),
        ("snapshot_after", norito::json!({"head":"changed"})),
        ("snapshot_after_reopen", norito::json!({"sequence":"4"})),
        ("cursor_after_reopen", cursor_record((2, 3))),
        (
            "schema",
            norito::json!("iroha.kagemusha.retained-send-fold-diagnostic-result.v1"),
        ),
    ] {
        let mut changed = receipt.clone();
        changed.as_object_mut().unwrap().insert(field.into(), value);
        assert!(
            std::panic::catch_unwind(|| require_receipt(&changed, &bytes)).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        (
            "schema",
            norito::json!("iroha.kagemusha.retained-send-fold-diagnostic.v1"),
        ),
        ("maximum_fold_calls", norito::json!(2)),
        ("new_monetary_operations", norito::json!(1)),
        ("retained_fee", norito::json!(1)),
        ("archive_sha256", norito::json!("not-a-digest")),
        ("target_sha256", norito::json!(hex::encode([0; 32]))),
        (
            "cursor_before",
            norito::json!({"sequence":"02","ordinal":3}),
        ),
        ("cursor_before", cursor_record((2, 0))),
    ] {
        let mut changed = selection.clone();
        changed.as_object_mut().unwrap().insert(field.into(), value);
        let bytes = norito::json::to_vec(&changed).unwrap();
        let mut changed_receipt = receipt.clone();
        changed_receipt
            .as_object_mut()
            .unwrap()
            .insert("selection_sha256".into(), sha(&bytes).into());
        assert!(
            std::panic::catch_unwind(|| require_receipt(&changed_receipt, &bytes)).is_err(),
            "{field}"
        );
    }
}

#[test]
fn current_checkpoint_snapshot_preserves_every_native_identity_and_balance_field() {
    let original = sample_snapshot();
    let expected = snapshot_record(&original);
    for field in 0..17 {
        let mut changed = original;
        match field {
            0 => changed.scheme_id[0] ^= 1,
            1 => changed.wallet_id[0] ^= 1,
            2 => changed.head[0] ^= 1,
            3 => changed.credential_digest[0] ^= 1,
            4 => changed.sequence += 1,
            5 => changed.lifecycle = KagemushaWalletLifecycleV1::Retiring,
            6 => changed.balance += 1,
            7 => changed.core_burned_total += 1,
            8 => changed.known_burned_total += 1,
            9 => changed.owned_balance += 1,
            10 => changed.folded_balance = Some(0),
            11 => changed.fold_backlog += 1,
            12 => changed.verified_fold = None,
            13 => changed.verified_fold.as_mut().unwrap().sequence += 1,
            14 => changed.verified_fold.as_mut().unwrap().head[0] ^= 1,
            15 => changed.verified_fold.as_mut().unwrap().credential_digest[0] ^= 1,
            _ => changed.verified_fold.as_mut().unwrap().burned_total += 1,
        }
        assert_ne!(
            snapshot_record(&changed),
            expected,
            "snapshot field {field}"
        );
    }
}
