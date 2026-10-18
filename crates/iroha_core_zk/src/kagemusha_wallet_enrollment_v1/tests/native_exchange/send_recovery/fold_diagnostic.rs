//! One bounded fold of retained A custody; no monetary operation is replayed.

use super::*;

#[test]
#[ignore = "requires the exact retained A Send/Archive head; attempts at most one existing fold checkpoint without executing a monetary operation"]
fn diagnose_retained_a_send_fold_once_without_monetary_replay() {
    let output = fresh_output("KAGEMUSHA_NATIVE_FOLD_DIAGNOSTIC_OUTPUT");
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
    let prior_path = selected_path("KAGEMUSHA_NATIVE_PREVIOUS_FOLD_RESULT");
    let prior_bytes = read_pin(
        &prior_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_PREVIOUS_FOLD_RESULT_SHA256"),
    );
    let prior: norito::json::Value = norito::json::from_slice(&prior_bytes).unwrap();
    assert_eq!(
        prior["schema"].as_str(),
        Some("iroha.kagemusha.retained-send-fold-diagnostic-result.v1")
    );
    assert_eq!(prior["fold_succeeded"].as_bool(), Some(false));
    assert_eq!(
        prior["fold_outcome"].as_str(),
        Some("Err(Proof(\"prepared capsule differs from native derivation\"))")
    );
    assert_eq!(prior["snapshot_unchanged"].as_bool(), Some(true));
    assert_eq!(
        prior["exact_completed_payment_after_reopen"].as_bool(),
        Some(true)
    );
    for field in ["new_keys", "new_signatures", "new_monetary_operations"] {
        assert_eq!(prior[field].as_u64(), Some(0));
    }
    let prior_selection_bytes = read_pin(
        &prior_path.parent().unwrap().join("selection.json"),
        TARGET_MAX,
        prior["selection_sha256"].as_str().unwrap(),
    );
    let prior_selection: norito::json::Value =
        norito::json::from_slice(&prior_selection_bytes).unwrap();
    assert_eq!(
        prior_selection["schema"].as_str(),
        Some("iroha.kagemusha.retained-send-fold-diagnostic.v1")
    );
    assert_eq!(
        prior_selection["previous_continuation_sha256"].as_str(),
        Some(sha(&previous_bytes).as_str())
    );
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    let public = path.parent().unwrap();
    let frames = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let instruction = decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames, &instruction);
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &f.config.scheme.scheme_id())
            .unwrap();
    let device = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential);
    // Any accidental signing must fail. The selected fold only uses retained originals.
    device.platform.with(|state| state.sign_fault_at = Some(0));
    let mut wallet = sources.open(&device, &f, &frames);
    let state::RequestStatusV1::Outcome(Completion::Complete(payment)) =
        wallet.retry_request(&[212; 32]).unwrap()
    else {
        panic!("retained Send212 must already be complete; never resume or execute it");
    };
    assert_eq!(
        previous["payment_sha256"].as_str(),
        Some(sha(&payment).as_str())
    );
    let decoded: KagemushaWalletPaymentV1 = decode(&payment);
    assert_eq!(
        decoded.signed_request().unwrap().body.fee,
        0,
        "retained zero-fee Send"
    );
    let before = wallet.snapshot().unwrap();
    assert_eq!(
        prior_selection["target_sha256"].as_str(),
        Some(sha(&target_bytes).as_str())
    );
    assert_eq!(
        prior_selection["payment_sha256"].as_str(),
        Some(sha(&payment).as_str())
    );
    assert_eq!(
        prior_selection["snapshot_before"].as_str(),
        Some(format!("{before:?}").as_str()),
        "the exact previously unchanged retained snapshot is required before one new fold"
    );
    assert_eq!(before.sequence, 3, "existing ArchiveReceive head required");
    assert_eq!(before.owned_balance, 0);
    assert_eq!(before.known_burned_total, 0);
    assert_eq!(before.fold_backlog, 2);
    assert_eq!(before.verified_fold.unwrap().sequence, 1);
    assert_eq!(before.folded_balance, None);
    assert_eq!(
        wallet.fold_checkpoint_cursor_for_test().unwrap(),
        (2, 6),
        "only the exact retained Send A2 checkpoint may be attempted"
    );
    let selection = norito::json!({
        "schema": "iroha.kagemusha.retained-send-fold-diagnostic.v1",
        "previous_continuation_sha256": (sha(&previous_bytes)),
        "target_sha256": (sha(&target_bytes)),
        "payment_sha256": (sha(&payment)),
        "retained_fee": (decoded.signed_request().unwrap().body.fee),
        "consumer_binary_sha256": (executable_hash()),
        "consumer_source_sha256": (env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "snapshot_before": (format!("{before:?}")),
        "previous_failed_result_sha256": (sha(&prior_bytes)),
        "maximum_fold_calls": 1,
        "new_monetary_operations": 0
    });
    publish(
        &output.join("selection.json"),
        &norito::json::to_vec(&selection).unwrap(),
    );
    wallet.scheduler().set_activity(true, false);
    let result = wallet.fold_once();
    let after = wallet.snapshot().unwrap();
    assert_eq!(
        after, before,
        "one sub-proof cannot alter the monetary head"
    );
    assert_eq!(
        wallet.retry_request(&[212; 32]).unwrap(),
        state::RequestStatusV1::Outcome(Completion::Complete(payment.clone()))
    );
    drop(wallet);
    let mut reopened = sources.open(&device, &f, &frames);
    assert_eq!(reopened.snapshot().unwrap(), before);
    assert_eq!(
        reopened.retry_request(&[212; 32]).unwrap(),
        state::RequestStatusV1::Outcome(Completion::Complete(payment))
    );
    assert_eq!(
        device
            .platform
            .with(|state| (state.generate_calls, state.sign_calls)),
        (0, 0)
    );
    let record = norito::json!({
        "schema": "iroha.kagemusha.retained-send-fold-diagnostic-result.v1",
        "selection_sha256": (sha(&norito::json::to_vec(&selection).unwrap())),
        "fold_outcome": (format!("{result:?}")),
        "fold_succeeded": (result.is_ok()),
        "snapshot_unchanged": true,
        "exact_completed_payment_after_reopen": true,
        "new_signatures": 0, "new_keys": 0, "new_monetary_operations": 0
    });
    publish(
        &output.join("result.json"),
        &norito::json::to_vec(&record).unwrap(),
    );
    eprintln!(
        "NATIVE_RETAINED_SEND_FOLD_DIAGNOSTIC outcome={result:?} snapshot_unchanged=true exact_reopen=true new_signatures=0 new_monetary_operations=0"
    );
    assert_eq!(
        result.expect("retained Send fold remains blocked; preserve the exact custody"),
        FoldStatus::Checkpoint {
            sequence: 2,
            ordinal: 6
        }
    );
}
