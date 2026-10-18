//! One current retained Send checkpoint, with structured observation and exact reopen checks.
//!
//! Receipts describe an executed attempt; they never authorize skipping native restoration.
//! A failed or non-checkpoint outcome is retained and cannot admit archive continuation.

use super::*;

#[path = "checkpoint/tests.rs"]
mod tests;

pub(super) fn snapshot_record(snapshot: &state::Snapshot) -> norito::json::Value {
    norito::json!({
        "scheme_id": (hex::encode(snapshot.scheme_id)),
        "wallet_id": (hex::encode(snapshot.wallet_id)),
        "head": (hex::encode(snapshot.head)),
        "credential_digest": (hex::encode(snapshot.credential_digest)),
        "sequence": (snapshot.sequence.to_string()),
        "lifecycle": (snapshot.lifecycle.tag()),
        "balance": (snapshot.balance.to_string()),
        "core_burned_total": (snapshot.core_burned_total.to_string()),
        "known_burned_total": (snapshot.known_burned_total.to_string()),
        "owned_balance": (snapshot.owned_balance.to_string()),
        "folded_balance": (snapshot.folded_balance.map(|value| value.to_string())),
        "fold_backlog": (snapshot.fold_backlog.to_string()),
        "verified_fold": (snapshot.verified_fold.map(|fold| norito::json!({
            "sequence": (fold.sequence.to_string()), "head": (hex::encode(fold.head)),
            "credential_digest": (hex::encode(fold.credential_digest)),
            "burned_total": (fold.burned_total.to_string()),
        }))),
    })
}

fn cursor_record((sequence, ordinal): (u128, u32)) -> norito::json::Value {
    norito::json!({"sequence": (sequence.to_string()), "ordinal": ordinal})
}

fn outcome_record(result: &Result<FoldStatus, state::Error>) -> norito::json::Value {
    match result {
        Ok(FoldStatus::Checkpoint { sequence, ordinal }) => norito::json!({
            "kind": "checkpoint", "sequence": (sequence.to_string()), "ordinal": ordinal,
        }),
        Ok(FoldStatus::Folded(sequence)) => norito::json!({
            "kind": "folded", "sequence": (sequence.to_string()),
        }),
        Ok(FoldStatus::Idle) => norito::json!({"kind": "idle"}),
        Ok(FoldStatus::CaughtUp) => norito::json!({"kind": "caught_up"}),
        Err(error) => norito::json!({"kind": "error", "description": (format!("{error:?}"))}),
    }
}

pub(super) fn require_receipt(
    receipt: &norito::json::Value,
    selection_bytes: &[u8],
) -> (u128, u32) {
    let selection: norito::json::Value = norito::json::from_slice(selection_bytes).unwrap();
    assert_eq!(
        selection["schema"].as_str(),
        Some("iroha.kagemusha.retained-send-checkpoint-selection.v1")
    );
    assert_eq!(
        receipt["schema"].as_str(),
        Some("iroha.kagemusha.retained-send-checkpoint-receipt.v1")
    );
    assert_eq!(
        receipt["selection_sha256"].as_str(),
        Some(sha(selection_bytes).as_str())
    );
    for field in [
        "previous_continuation_sha256",
        "selected_send_continuation_sha256",
        "message_originals_manifest_sha256",
        "target_sha256",
        "payment_sha256",
        "archive_sha256",
        "consumer_binary_sha256",
        "consumer_source_sha256",
    ] {
        let text = selection[field].as_str().unwrap();
        let digest: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
        assert_ne!(digest, [0; 32]);
        assert_eq!(hex::encode(digest), text);
    }
    assert_eq!(selection["maximum_fold_calls"].as_u64(), Some(1));
    assert_eq!(selection["new_monetary_operations"].as_u64(), Some(0));
    assert_eq!(selection["retained_fee"].as_u64(), Some(0));
    assert_eq!(receipt["fold_calls"].as_u64(), Some(1));
    for field in ["new_keys", "new_signatures", "new_monetary_operations"] {
        assert_eq!(receipt[field].as_u64(), Some(0));
    }
    assert_eq!(receipt["snapshot_after"], selection["snapshot_before"]);
    assert_eq!(
        receipt["snapshot_after_reopen"],
        selection["snapshot_before"]
    );
    assert_eq!(
        receipt["completed_payment_after_reopen_sha256"],
        selection["payment_sha256"]
    );
    assert_eq!(
        receipt["archive_after_reopen_sha256"],
        selection["archive_sha256"]
    );
    let sequence_text = selection["cursor_before"]["sequence"].as_str().unwrap();
    let sequence: u128 = sequence_text.parse().unwrap();
    assert_eq!(sequence.to_string(), sequence_text);
    assert_eq!(sequence, 2, "the existing A Send follows its folded Load");
    let ordinal: u32 = selection["cursor_before"]["ordinal"]
        .as_u64()
        .unwrap()
        .try_into()
        .unwrap();
    assert!(ordinal > 0, "an existing Send checkpoint is required");
    assert_eq!(receipt["outcome"]["kind"].as_str(), Some("checkpoint"));
    assert_eq!(receipt["outcome"]["sequence"].as_str(), Some(sequence_text));
    assert_eq!(
        receipt["outcome"]["ordinal"].as_u64(),
        Some(u64::from(ordinal))
    );
    let next = (sequence, ordinal.checked_add(1).unwrap());
    assert_eq!(receipt["cursor_after_reopen"], cursor_record(next));
    next
}

#[test]
#[ignore = "requires current admitted artifacts and exact A Archive/Send custody; attempts one existing Send checkpoint, never a monetary operation"]
fn retain_current_send_checkpoint_once_without_monetary_replay() {
    let (census_manifest, census_originals) = message_census::read_pinned_originals();
    let output = fresh_output("KAGEMUSHA_NATIVE_SEND_CHECKPOINT_OUTPUT");
    let previous_path = selected_path("KAGEMUSHA_NATIVE_COMPLETED_SEND_CONTINUATION");
    let previous_bytes = read_pin(
        &previous_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_COMPLETED_SEND_CONTINUATION_SHA256"),
    );
    let previous: norito::json::Value = norito::json::from_slice(&previous_bytes).unwrap();
    assert_eq!(
        previous["schema"].as_str(),
        Some("iroha.kagemusha.completed-send-continuation.v1")
    );
    assert_eq!(
        previous["status_before_continue"].as_str(),
        Some("Complete")
    );
    let prior_path = selected_path("KAGEMUSHA_NATIVE_SEND_CONTINUATION");
    let prior_bytes = read_pin(
        &prior_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_SEND_CONTINUATION_SHA256"),
    );
    let prior: norito::json::Value = norito::json::from_slice(&prior_bytes).unwrap();
    assert_eq!(
        prior["schema"].as_str(),
        Some("iroha.kagemusha.selected-send-continuation.v1")
    );
    assert_eq!(
        previous["previous_continuation_sha256"].as_str(),
        Some(sha(&prior_bytes).as_str())
    );
    message_census::require_selected_send_session(
        &census_originals[4],
        &census_originals[5],
        &prior,
    );
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let fixture = sources.fixture(&setup, 0);
    let target_path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &target_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    assert_eq!(
        prior["target_sha256"].as_str(),
        Some(sha(&target_bytes).as_str())
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    let public = target_path.parent().unwrap();
    let frames = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let instruction = decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &fixture, &frames, &instruction);
    let credential = KagemushaWalletCredentialV1::decode_canonical(
        &frames[0],
        &fixture.config.scheme.scheme_id(),
    )
    .unwrap();
    let device = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential);
    device.platform.with(|state| state.sign_fault_at = Some(0));
    let mut wallet = sources.open(&device, &fixture, &frames);
    let payment = completed(&mut wallet, 212);
    assert_eq!(
        previous["payment_sha256"].as_str(),
        Some(sha(&payment).as_str())
    );
    assert_eq!(payment, census_originals[0]);
    let decoded: KagemushaWalletPaymentV1 = decode(&payment);
    assert_eq!(decoded.signed_request().unwrap().body.fee, 0);
    let request: KagemushaWalletRequestV1 = decode(&census_originals[5]);
    let credited_original = &census_originals[2];
    let credited: KagemushaWalletCreditedV1 = decode(credited_original);
    credited
        .verify_for(&fixture.config.scheme, &request, &decoded)
        .unwrap();
    let before = wallet.snapshot().unwrap();
    assert_eq!(
        (
            before.sequence,
            before.owned_balance,
            before.known_burned_total,
            before.fold_backlog
        ),
        (3, 0, 0, 2)
    );
    assert_eq!(before.verified_fold.unwrap().sequence, 1);
    assert_eq!(before.folded_balance, None);
    let archive = retained_archive(
        &mut wallet,
        &sources,
        &fixture,
        &frames,
        credited_original,
        decoded.signed_request().unwrap().credit_id(),
    );
    let cursor_before = wallet.fold_checkpoint_cursor_for_test().unwrap();
    assert_eq!(cursor_before.0, 2);
    assert!(
        cursor_before.1 > 0,
        "only an existing current Send checkpoint may be attempted"
    );
    let selection = norito::json!({
        "schema": "iroha.kagemusha.retained-send-checkpoint-selection.v1",
        "previous_continuation_sha256": (sha(&previous_bytes)),
        "selected_send_continuation_sha256": (sha(&prior_bytes)),
        "message_originals_manifest_sha256": (sha(&census_manifest)),
        "target_sha256": (sha(&target_bytes)), "payment_sha256": (sha(&payment)),
        "archive_sha256": (sha(&archive)), "retained_fee": 0,
        "source_pins": (source_pins()), "consumer_binary_sha256": (executable_hash()),
        "consumer_source_sha256": (env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "snapshot_before": (snapshot_record(&before)), "cursor_before": (cursor_record(cursor_before)),
        "maximum_fold_calls": 1, "new_monetary_operations": 0,
    });
    let selection_bytes = norito::json::to_vec(&selection).unwrap();
    publish(&output.join("selection.json"), &selection_bytes);
    publish(&output.join("retained-payment.norito"), &payment);
    publish(&output.join("retained-archive.norito"), &archive);
    wallet.scheduler().set_activity(true, false);
    let result = wallet.fold_once();
    // Retain any failure before snapshot/reopen assertions, with no historical error whitelist.
    let outcome = outcome_record(&result);
    publish(
        &output.join("fold-outcome.json"),
        &norito::json::to_vec(&outcome).unwrap(),
    );
    let after = wallet.snapshot().unwrap();
    assert_eq!(completed(&mut wallet, 212), payment);
    drop(wallet);
    let mut reopened = sources.open(&device, &fixture, &frames);
    let after_reopen = reopened.snapshot().unwrap();
    let reopened_payment = completed(&mut reopened, 212);
    let reopened_archive = retained_archive(
        &mut reopened,
        &sources,
        &fixture,
        &frames,
        credited_original,
        decoded.signed_request().unwrap().credit_id(),
    );
    let cursor_after = reopened.fold_checkpoint_cursor_for_test().unwrap();
    let (keys, signatures) = device
        .platform
        .with(|state| (state.generate_calls, state.sign_calls));
    let receipt = norito::json!({
        "schema": "iroha.kagemusha.retained-send-checkpoint-receipt.v1",
        "selection_sha256": (sha(&selection_bytes)), "outcome": outcome, "fold_calls": 1,
        "snapshot_after": (snapshot_record(&after)), "snapshot_after_reopen": (snapshot_record(&after_reopen)),
        "completed_payment_after_reopen_sha256": (sha(&reopened_payment)),
        "archive_after_reopen_sha256": (sha(&reopened_archive)),
        "cursor_after_reopen": (cursor_record(cursor_after)),
        "new_keys": keys, "new_signatures": signatures, "new_monetary_operations": 0,
        "scope": "One observed native checkpoint attempt using existing Send and Archive originals, reopened current custody and disabled payment signing. Failure remains failure; no monetary operation replay, historical capture admission, network or release qualification.",
    });
    publish(
        &output.join("receipt.json"),
        &norito::json::to_vec(&receipt).unwrap(),
    );
    assert_eq!(after, before);
    assert_eq!(after_reopen, before);
    assert_eq!(reopened_payment, payment);
    assert_eq!(reopened_archive, archive);
    assert_eq!((keys, signatures), (0, 0));
    assert_eq!(require_receipt(&receipt, &selection_bytes), cursor_after);
}
