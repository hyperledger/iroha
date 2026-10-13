//! Resume the exact retained Archive head after the independently checked Send checkpoint.

use super::*;

fn completed(wallet: &mut Wallet, id: u8) -> Vec<u8> {
    let state::RequestStatusV1::Outcome(Completion::Complete(bytes)) =
        wallet.retry_request(&[id; 32]).unwrap()
    else {
        panic!("required retained request{id} is not complete; never execute it again");
    };
    bytes
}

#[test]
#[ignore = "requires retained A Archive, both completed transfers/Receive folds and successful one-checkpoint repair; never repeats Load, enrollment, Send or Receive"]
fn continue_retained_archives_then_unload_without_repeating_transfers() {
    let output = fresh_output("KAGEMUSHA_NATIVE_ARCHIVE_RECOVERY_OUTPUT");
    let checkpoint_path = selected_path("KAGEMUSHA_NATIVE_SEND_FOLD_DIAGNOSTIC_RESULT");
    let checkpoint_bytes = read_pin(
        &checkpoint_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_SEND_FOLD_DIAGNOSTIC_RESULT_SHA256"),
    );
    let checkpoint: norito::json::Value = norito::json::from_slice(&checkpoint_bytes).unwrap();
    assert_eq!(
        checkpoint["schema"].as_str(),
        Some("iroha.kagemusha.retained-send-fold-diagnostic-result.v1")
    );
    assert_eq!(checkpoint["fold_succeeded"].as_bool(), Some(true));
    assert_eq!(
        checkpoint["fold_outcome"].as_str(),
        Some("Ok(Checkpoint { sequence: 2, ordinal: 6 })")
    );
    let checkpoint_selection_path = checkpoint_path.parent().unwrap().join("selection.json");
    let checkpoint_selection_bytes = read_pin(
        &checkpoint_selection_path,
        TARGET_MAX,
        checkpoint["selection_sha256"].as_str().unwrap(),
    );
    let checkpoint_selection: norito::json::Value =
        norito::json::from_slice(&checkpoint_selection_bytes).unwrap();
    assert_eq!(
        checkpoint_selection["schema"].as_str(),
        Some("iroha.kagemusha.retained-send-fold-diagnostic.v1")
    );
    assert_eq!(checkpoint_selection["maximum_fold_calls"].as_u64(), Some(1));
    assert_eq!(
        checkpoint_selection["new_monetary_operations"].as_u64(),
        Some(0)
    );
    assert_eq!(checkpoint_selection["retained_fee"].as_u64(), Some(0));
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
        checkpoint_selection["previous_continuation_sha256"].as_str(),
        Some(sha(&previous_bytes).as_str())
    );
    let prior_path = selected_path("KAGEMUSHA_NATIVE_SEND_CONTINUATION");
    let prior_bytes = read_pin(
        &prior_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_SEND_CONTINUATION_SHA256"),
    );
    assert_eq!(
        previous["previous_continuation_sha256"].as_str(),
        Some(sha(&prior_bytes).as_str())
    );
    let prior: norito::json::Value = norito::json::from_slice(&prior_bytes).unwrap();
    assert_eq!(
        prior["schema"].as_str(),
        Some("iroha.kagemusha.selected-send-continuation.v1")
    );
    let custody = selected_path("KAGEMUSHA_NATIVE_RETAINED_EXCHANGE");
    assert_eq!(prior["prior_custody_root"].as_str(), custody.to_str());
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
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
    assert_eq!(
        checkpoint_selection["target_sha256"].as_str(),
        Some(sha(&target_bytes).as_str())
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    let public = target_path.parent().unwrap();
    let frames_a = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let instruction = decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames_a, &instruction);
    let credential_a =
        KagemushaWalletCredentialV1::decode_canonical(&frames_a[0], &f.config.scheme.scheme_id())
            .unwrap();
    let device_a = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential_a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    let f_b = sources.fixture(&setup, 1);
    let f_c = sources.fixture(&setup, 2);
    let (device_b, frames_b) = restore_recorded(&custody.join("wallet-b"), &f_b);
    let (device_c, frames_c) = restore_recorded(&custody.join("wallet-c"), &f_c);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    let mut c = sources.open(&device_c, &f_c, &frames_c);
    // All transfers are already complete. Refuse any changed or unexpected recovery seam.
    let before_a = a.snapshot().unwrap();
    let before_b = b.snapshot().unwrap();
    let before_c = c.snapshot().unwrap();
    assert_eq!(
        (
            before_a.sequence,
            before_a.owned_balance,
            before_a.fold_backlog
        ),
        (3, 0, 2)
    );
    assert_eq!(before_a.verified_fold.unwrap().sequence, 1);
    assert_eq!(a.fold_checkpoint_cursor_for_test().unwrap(), (2, 7));
    assert_eq!(
        (
            before_b.sequence,
            before_b.owned_balance,
            before_b.fold_backlog
        ),
        (2, 0, 1)
    );
    assert_eq!(before_b.verified_fold.unwrap().sequence, 1);
    assert_eq!(
        (
            before_c.sequence,
            before_c.owned_balance,
            before_c.folded_balance
        ),
        (1, 100, Some(100))
    );
    assert_eq!(
        (
            before_a.known_burned_total,
            before_b.known_burned_total,
            before_c.known_burned_total
        ),
        (0, 0, 0)
    );
    assert_eq!(
        c.retry_request(&[230; 32]).unwrap(),
        state::RequestStatusV1::Unknown
    );
    let payment_ab = completed(&mut a, 212);
    assert_eq!(
        previous["payment_sha256"].as_str(),
        Some(sha(&payment_ab).as_str())
    );
    assert_eq!(
        checkpoint_selection["payment_sha256"].as_str(),
        Some(sha(&payment_ab).as_str())
    );
    let received_ab = completed(&mut b, 213);
    let payment_bc = completed(&mut b, 222);
    let received_bc = completed(&mut c, 223);
    for device in [&device_a, &device_b, &device_c] {
        device.platform.with(|state| state.sign_fault_at = Some(0));
    }
    require_payment_bound(&payment_ab, &f.config.scheme.scheme_id());
    require_payment_bound(&payment_bc, &f.config.scheme.scheme_id());
    let payment: KagemushaWalletPaymentV1 = decode(&payment_ab);
    let credit_ab = payment.request.credit_id();
    let received: KagemushaWalletPackageV1 = decode(&received_ab);
    assert!(matches!(received.statement.effect,
        KagemushaWalletEffectV1::Receive { credit_id, payer_wallet_id, amount }
        if credit_id == credit_ab && payer_wallet_id == before_a.wallet_id && amount == LOAD_AMOUNT));
    let credited_ab = credited(&received_ab);
    // This must be the previously committed Archive package. Hardware signing is disabled,
    // and its sequence/head must equal the existing snapshot before any fold is attempted.
    let archived_ab = complete(a.accept_credited(&credited_ab).unwrap());
    let package: KagemushaWalletPackageV1 = decode(&archived_ab);
    package.verify(&credential_a).unwrap();
    assert!(matches!(package.statement.effect,
        KagemushaWalletEffectV1::ArchiveSent { credit_id, .. } if credit_id == credit_ab));
    sources
        .installed
        .verifier()
        .verify_package_proofs(&package, None, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(package.statement.sequence, before_a.sequence);
    assert_eq!(package.statement.successor.value, before_a.head);
    assert_eq!(a.snapshot().unwrap(), before_a);
    let selection = norito::json!({
        "schema": "iroha.kagemusha.retained-archive-continuation.v1",
        "checkpoint_result_sha256": (sha(&checkpoint_bytes)),
        "completed_send_continuation_sha256": (sha(&previous_bytes)),
        "consumer_binary_sha256": (executable_hash()),
        "consumer_source_sha256": (env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "target_sha256": (sha(&target_bytes)),
        "retained_payment_ab_sha256": (sha(&payment_ab)),
        "retained_payment_bc_sha256": (sha(&payment_bc)),
        "retained_receive_ab_sha256": (sha(&received_ab)),
        "retained_receive_bc_sha256": (sha(&received_bc)),
        "retained_archive_ab_sha256": (sha(&archived_ab)),
        "new_transfers": 0, "new_loads": 0, "new_enrollments": 0
    });
    publish(
        &output.join("continuation.json"),
        &norito::json::to_vec(&selection).unwrap(),
    );
    // Persist public outcome originals before the remaining work, preserving exact retries.
    for (name, bytes) in [
        ("retained-payment-ab.norito", &payment_ab),
        ("retained-payment-bc.norito", &payment_bc),
        ("retained-receive-ab.norito", &received_ab),
        ("retained-receive-bc.norito", &received_bc),
        ("retained-archive-ab.norito", &archived_ab),
    ] {
        publish(&output.join(name), bytes);
    }
    fold(&mut a);
    let folded = a.snapshot().unwrap();
    assert_eq!(folded.sequence, before_a.sequence);
    assert_eq!(folded.head, before_a.head);
    assert_eq!(folded.owned_balance, 0);
    assert_eq!(folded.known_burned_total, 0);
    assert_eq!(folded.verified_fold.unwrap().sequence, 3);
    assert_eq!(folded.fold_backlog, 0);
    assert_eq!(folded.folded_balance, Some(0));
    drop(a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    assert_eq!(a.snapshot().unwrap(), folded);
    assert_eq!(
        complete(a.accept_credited(&credited_ab).unwrap()),
        archived_ab
    );
    assert_eq!(a.snapshot().unwrap(), folded);
    for device in [&device_a, &device_b, &device_c] {
        assert_eq!(
            device
                .platform
                .with(|state| (state.generate_calls, state.sign_calls)),
            (0, 0)
        );
    }
    eprintln!(
        "NATIVE_EXCHANGE_ARCHIVE branch=ArchiveReceive exact_replay_after_restart=true current_head_folded=true monetary_value_unchanged=true retained_archive_only=true"
    );
    assert_eq!(b.snapshot().unwrap(), before_b);
    assert_eq!(c.snapshot().unwrap(), before_c);
    // Only the remaining original B Archive and C Unload are now allowed to sign.
    device_b.platform.with(|state| state.sign_fault_at = None);
    device_c.platform.with(|state| state.sign_fault_at = None);
    let bc: KagemushaWalletPaymentV1 = decode(&payment_bc);
    let status_bc = c
        .credit_status(&bc.request.credit_id(), &bc.payment_digest().unwrap())
        .unwrap();
    assert_eq!(status_bc.lineage.public.wallet_id, before_c.wallet_id);
    let credited_bc =
        norito::encode_canonical(&KagemushaWalletCreditedV1::from_status(status_bc).unwrap())
            .unwrap();
    let (b, archived_bc) = archive::exercise(b, &device_b, &sources, &f_b, &frames_b, &credited_bc);
    finish_unload(
        output,
        sources,
        setup,
        target_bytes,
        [
            Participant {
                wallet: a,
                device: device_a,
                fixture: f,
                frames: frames_a,
            },
            Participant {
                wallet: b,
                device: device_b,
                fixture: f_b,
                frames: frames_b,
            },
            Participant {
                wallet: c,
                device: device_c,
                fixture: f_c,
                frames: frames_c,
            },
        ],
        ExchangeOriginals {
            payment_ab,
            payment_bc,
            received_ab,
            received_bc,
            credited_ab,
            credited_bc,
            archived_ab,
            archived_bc,
        },
    );
}
