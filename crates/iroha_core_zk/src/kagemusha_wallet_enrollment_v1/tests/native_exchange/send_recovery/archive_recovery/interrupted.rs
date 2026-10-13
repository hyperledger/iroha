//! Resume only B's committed Archive after an interrupted retained-custody campaign.

use super::*;

fn prior_original(root: &Path, manifest: &norito::json::Value, name: &str, field: &str) -> Vec<u8> {
    read_pin(
        &root.join(name),
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
        manifest[field].as_str().unwrap(),
    )
}

/// Recover an already committed Archive, never permit a fresh sequence or signature.
fn retained_archive(
    wallet: &mut Wallet,
    sources: &Sources,
    fixture: &Fixture,
    frames: &[Vec<u8>; 4],
    evidence: &[u8],
    credit_id: [u8; 32],
) -> Vec<u8> {
    let before = wallet.snapshot().unwrap();
    let original = complete(wallet.accept_credited(evidence).unwrap());
    let package: KagemushaWalletPackageV1 = decode(&original);
    let credential = KagemushaWalletCredentialV1::decode_canonical(
        &frames[0],
        &fixture.config.scheme.scheme_id(),
    )
    .unwrap();
    package.verify(&credential).unwrap();
    assert!(matches!(package.statement.effect,
        KagemushaWalletEffectV1::ArchiveSent { credit_id: actual, .. }
        if actual == credit_id));
    sources
        .installed
        .verifier()
        .verify_package_proofs(&package, None, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(package.statement.sequence, before.sequence);
    assert_eq!(package.statement.successor.value, before.head);
    assert_eq!(wallet.snapshot().unwrap(), before);
    original
}

#[test]
#[ignore = "requires exact retained A Archive fully folded and B Archive checkpoint7; never repeats completed transfers or Archive commits"]
fn continue_retained_b_archive_then_unload_without_repeating_transfers() {
    let output = fresh_output("KAGEMUSHA_NATIVE_ARCHIVE_RESTART_OUTPUT");
    let prior_path = selected_path("KAGEMUSHA_NATIVE_INTERRUPTED_ARCHIVE_CONTINUATION");
    let prior_bytes = read_pin(
        &prior_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_INTERRUPTED_ARCHIVE_CONTINUATION_SHA256"),
    );
    let prior: norito::json::Value = norito::json::from_slice(&prior_bytes).unwrap();
    assert_eq!(
        prior["schema"].as_str(),
        Some("iroha.kagemusha.retained-archive-continuation.v1")
    );
    for field in ["new_enrollments", "new_loads", "new_transfers"] {
        assert_eq!(prior[field].as_u64(), Some(0));
    }
    let previous_path = selected_path("KAGEMUSHA_NATIVE_SEND_CONTINUATION");
    let previous_bytes = read_pin(
        &previous_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_SEND_CONTINUATION_SHA256"),
    );
    let previous: norito::json::Value = norito::json::from_slice(&previous_bytes).unwrap();
    assert_eq!(
        previous["schema"].as_str(),
        Some("iroha.kagemusha.selected-send-continuation.v1")
    );
    let completed_path = selected_path("KAGEMUSHA_NATIVE_COMPLETED_SEND_CONTINUATION");
    let completed_bytes = read_pin(
        &completed_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_COMPLETED_SEND_CONTINUATION_SHA256"),
    );
    assert_eq!(
        prior["completed_send_continuation_sha256"].as_str(),
        Some(sha(&completed_bytes).as_str())
    );
    let completed_manifest: norito::json::Value =
        norito::json::from_slice(&completed_bytes).unwrap();
    assert_eq!(
        completed_manifest["schema"].as_str(),
        Some("iroha.kagemusha.completed-send-continuation.v1")
    );
    assert_eq!(
        completed_manifest["previous_continuation_sha256"].as_str(),
        Some(sha(&previous_bytes).as_str())
    );
    let custody = selected_path("KAGEMUSHA_NATIVE_RETAINED_EXCHANGE");
    assert_eq!(previous["prior_custody_root"].as_str(), custody.to_str());
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let f_b = sources.fixture(&setup, 1);
    let f_c = sources.fixture(&setup, 2);
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
    assert_eq!(previous["target_sha256"], prior["target_sha256"]);
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    let public = target_path.parent().unwrap();
    let frames_a = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let instruction = decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames_a, &instruction);
    let credential_a =
        KagemushaWalletCredentialV1::decode_canonical(&frames_a[0], &f.config.scheme.scheme_id())
            .unwrap();
    let device_a = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential_a);
    let (device_b, frames_b) = restore_recorded(&custody.join("wallet-b"), &f_b);
    let (device_c, frames_c) = restore_recorded(&custody.join("wallet-c"), &f_c);
    for device in [&device_a, &device_b, &device_c] {
        device.platform.with(|state| {
            assert_eq!((state.generate_calls, state.sign_calls), (0, 0));
            state.sign_fault_at = Some(0);
        });
    }
    let mut a = sources.open(&device_a, &f, &frames_a);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    let mut c = sources.open(&device_c, &f_c, &frames_c);
    let before_a = a.snapshot().unwrap();
    let before_b = b.snapshot().unwrap();
    let before_c = c.snapshot().unwrap();
    assert_eq!(
        (
            before_a.sequence,
            before_a.owned_balance,
            before_a.fold_backlog,
            before_a.verified_fold.unwrap().sequence,
            before_a.folded_balance
        ),
        (3, 0, 0, 3, Some(0))
    );
    assert_eq!(
        (
            before_b.sequence,
            before_b.owned_balance,
            before_b.fold_backlog,
            before_b.verified_fold.unwrap().sequence,
            before_b.folded_balance
        ),
        (3, 0, 1, 2, None)
    );
    assert_eq!(
        b.fold_checkpoint_cursor_for_test().unwrap(),
        (3, 8),
        "only B's exact retained Archive checkpoint8 may be resumed"
    );
    assert_eq!(
        (
            before_c.sequence,
            before_c.owned_balance,
            before_c.fold_backlog,
            before_c.verified_fold.unwrap().sequence,
            before_c.folded_balance
        ),
        (1, 100, 0, 1, Some(100))
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

    let root = prior_path.parent().unwrap();
    let payment_ab = prior_original(
        root,
        &prior,
        "retained-payment-ab.norito",
        "retained_payment_ab_sha256",
    );
    let payment_bc = prior_original(
        root,
        &prior,
        "retained-payment-bc.norito",
        "retained_payment_bc_sha256",
    );
    let received_ab = prior_original(
        root,
        &prior,
        "retained-receive-ab.norito",
        "retained_receive_ab_sha256",
    );
    let received_bc = prior_original(
        root,
        &prior,
        "retained-receive-bc.norito",
        "retained_receive_bc_sha256",
    );
    let archived_ab = prior_original(
        root,
        &prior,
        "retained-archive-ab.norito",
        "retained_archive_ab_sha256",
    );
    assert_eq!(completed(&mut a, 212), payment_ab);
    assert_eq!(completed(&mut b, 213), received_ab);
    assert_eq!(completed(&mut b, 222), payment_bc);
    assert_eq!(completed(&mut c, 223), received_bc);
    require_payment_bound(&payment_ab, &f.config.scheme.scheme_id());
    require_payment_bound(&payment_bc, &f.config.scheme.scheme_id());
    let ab: KagemushaWalletPaymentV1 = decode(&payment_ab);
    let bc: KagemushaWalletPaymentV1 = decode(&payment_bc);
    let credited_ab = credited(&received_ab);
    assert_eq!(
        retained_archive(
            &mut a,
            &sources,
            &f,
            &frames_a,
            &credited_ab,
            ab.request.credit_id()
        ),
        archived_ab
    );
    // C's unchanged folded head reconstructs the same authenticated public status.
    let status_bc = c
        .credit_status(&bc.request.credit_id(), &bc.payment_digest().unwrap())
        .unwrap();
    assert_eq!(status_bc.lineage.public.wallet_id, before_c.wallet_id);
    let credited_bc =
        norito::encode_canonical(&KagemushaWalletCreditedV1::from_status(status_bc).unwrap())
            .unwrap();
    let archived_bc = retained_archive(
        &mut b,
        &sources,
        &f_b,
        &frames_b,
        &credited_bc,
        bc.request.credit_id(),
    );
    assert_eq!(a.snapshot().unwrap(), before_a);
    assert_eq!(b.snapshot().unwrap(), before_b);
    assert_eq!(c.snapshot().unwrap(), before_c);
    for device in [&device_a, &device_b, &device_c] {
        assert_eq!(
            device
                .platform
                .with(|state| (state.generate_calls, state.sign_calls)),
            (0, 0)
        );
    }
    let selection = norito::json!({
        "schema": "iroha.kagemusha.interrupted-archive-continuation.v1",
        "previous_continuation_sha256": (sha(&prior_bytes)),
        "target_sha256": (sha(&target_bytes)),
        "consumer_binary_sha256": (executable_hash()),
        "consumer_source_sha256": (env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "retained_payment_ab_sha256": (sha(&payment_ab)),
        "retained_payment_bc_sha256": (sha(&payment_bc)),
        "retained_archive_ab_sha256": (sha(&archived_ab)),
        "retained_archive_bc_sha256": (sha(&archived_bc)),
        "a_snapshot_before": (format!("{before_a:?}")),
        "b_snapshot_before": (format!("{before_b:?}")),
        "c_snapshot_before": (format!("{before_c:?}")),
        "new_transfers": 0, "new_loads": 0, "new_enrollments": 0,
        "new_archive_commits": 0, "b_resume_sequence": 3, "b_resume_ordinal": 8
    });
    publish(
        &output.join("continuation.json"),
        &norito::json::to_vec(&selection).unwrap(),
    );
    // Preserve exact already committed outputs before resuming the remaining proofs.
    for (name, bytes) in [
        ("retained-payment-ab.norito", &payment_ab),
        ("retained-payment-bc.norito", &payment_bc),
        ("retained-receive-ab.norito", &received_ab),
        ("retained-receive-bc.norito", &received_bc),
        ("retained-archive-ab.norito", &archived_ab),
        ("retained-archive-bc.norito", &archived_bc),
        ("retained-credited-bc.norito", &credited_bc),
    ] {
        publish(&output.join(name), bytes);
    }
    fold(&mut b);
    let folded = b.snapshot().unwrap();
    assert_eq!(
        (
            folded.sequence,
            folded.head,
            folded.owned_balance,
            folded.known_burned_total
        ),
        (
            before_b.sequence,
            before_b.head,
            before_b.owned_balance,
            before_b.known_burned_total
        )
    );
    assert_eq!(
        (
            folded.verified_fold.unwrap().sequence,
            folded.fold_backlog,
            folded.folded_balance
        ),
        (3, 0, Some(0))
    );
    drop(b);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    assert_eq!(b.snapshot().unwrap(), folded);
    assert_eq!(
        retained_archive(
            &mut b,
            &sources,
            &f_b,
            &frames_b,
            &credited_bc,
            bc.request.credit_id()
        ),
        archived_bc
    );
    assert_eq!(a.snapshot().unwrap(), before_a);
    assert_eq!(c.snapshot().unwrap(), before_c);
    for device in [&device_a, &device_b, &device_c] {
        assert_eq!(
            device
                .platform
                .with(|state| (state.generate_calls, state.sign_calls)),
            (0, 0)
        );
    }
    eprintln!(
        "NATIVE_EXCHANGE_ARCHIVE branch=ArchiveStatus exact_replay_after_restart=true current_head_folded=true monetary_value_unchanged=true retained_archive_only=true new_payment_signatures=0"
    );
    // Only the first remaining C Unload may sign; neither archived payer is enabled.
    device_c.platform.with(|state| state.sign_fault_at = None);
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
