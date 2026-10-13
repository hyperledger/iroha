//! Explicit engineering continuation of an already selected Send, never another Load.
//! The interrupted fixture predated early simulator-key retention for B/C. Only its
//! deterministic test keys may be restored, after binding each to existing native custody.

use super::*;
use crate::kagemusha_wallet_advance_v1::PreKeyRecordV1;

fn restore_fixture_originals(root: &Path, f: &Fixture, seed: u8) -> (HostDevice, [Vec<u8>; 4]) {
    assert!(root.is_dir());
    for name in FRAME_NAMES.into_iter().chain(["simulator-key.norito"]) {
        assert!(
            !root.join(name).exists(),
            "never replace retained originals"
        );
    }
    let device = HostDevice {
        root: root.to_path_buf(),
        platform: FakePlatformV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 0),
    };
    let provider = device.provider(f.config.scheme.scheme_id());
    let slots = provider.slots().unwrap();
    assert_eq!(slots.len(), 1, "exact existing enrolled slot required");
    let slot = slots[0];
    let original = provider
        .credential(&slot, 0)
        .unwrap()
        .expect("retained credential");
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&original, &f.config.scheme.scheme_id())
            .unwrap();
    let key = signing_key(seed);
    assert_eq!(
        public_key(&key),
        credential.body.payment_key,
        "existing fixture identity"
    );
    // These must already exist. begin() below may only reopen the retained E6 selection.
    for record in [
        PreKeyRecordV1::Client,
        PreKeyRecordV1::Accepted,
        PreKeyRecordV1::Slot,
    ] {
        assert!(provider.prekey_read(&[11; 32], record).unwrap().is_some());
    }
    device.platform.with(|state| {
        state.keys.insert(slot, key);
    });
    let mut owner = HostEnrollment::new(provider, f.config.clone())
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    let dispatch = PreKeyDispatchV1::decode(
        &owner
            .begin(
                &[11; 32],
                &norito::encode_canonical(&f.account).unwrap(),
                &norito::encode_canonical(&f.asset).unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(dispatch.purpose, KagemushaEnrollmentPermitPurposeV1::Resume);
    assert!(dispatch.previous_permit.is_some());
    let retained = owner
        .retained_result()
        .unwrap()
        .expect("existing signed E6 original");
    let frames = owner.open_originals().unwrap();
    assert_eq!(owner.retained_result().unwrap(), Some(retained));
    assert_eq!(frames[0], original);
    assert_eq!(decode::<AccountId>(&frames[2]), f.account);
    assert_eq!(decode::<KagemushaWalletAssetScopeV1>(&frames[3]), f.asset);
    drop(owner);
    device.platform.with(|state| {
        assert_eq!(state.generate_calls, 0, "no enrollment or key generation");
        assert_eq!(state.sign_calls, 0, "no new hardware signature");
    });
    device.save_simulator();
    retain_frames(&device, &frames);
    (device, frames)
}

#[test]
fn deterministic_fixture_restoration_requires_existing_identity_and_e6_originals() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture();
    let device = HostDevice::create(&dir.path().join("existing"), 89);
    let frames = device.enroll(&f);
    let root = device.root.clone();
    drop(device);
    assert!(std::panic::catch_unwind(|| restore_fixture_originals(&root, &f, 97)).is_err());
    assert!(!root.join("simulator-key.norito").exists());
    let (restored, retained) = restore_fixture_originals(&root, &f, 89);
    assert_eq!(retained, frames);
    assert!(std::panic::catch_unwind(|| restore_fixture_originals(&root, &f, 89)).is_err());
    assert_eq!(restored.platform.with(|state| state.generate_calls), 0);
    assert_eq!(restored.platform.with(|state| state.sign_calls), 0);
}

#[test]
#[ignore = "requires exact retained A selected Send and original B/C engineering custody; never repeats Load, Bootstrap or Send preparation"]
fn resume_selected_a_send_then_b_to_c_unload_with_restart_and_replay() {
    let output = fresh_output("KAGEMUSHA_NATIVE_EXCHANGE_OUTPUT");
    let prior = selected_path("KAGEMUSHA_NATIVE_PENDING_EXCHANGE");
    assert!(prior.is_dir());
    assert!(
        !prior.join("result.json").exists(),
        "only interrupted exchange"
    );
    let producer_path = selected_path("KAGEMUSHA_NATIVE_PENDING_SEND_PRODUCER");
    let producer = read_pin(
        &producer_path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_PENDING_SEND_PRODUCER_SHA256"),
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
    let frames_a = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let instruction = decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames_a, &instruction);
    let credential_a =
        KagemushaWalletCredentialV1::decode_canonical(&frames_a[0], &f.config.scheme.scheme_id())
            .unwrap();
    let device_a = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential_a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    assert_eq!(
        a.retry_request(&[212; 32]).unwrap(),
        state::RequestStatusV1::Outcome(Completion::Pending)
    );
    let f_b = sources.fixture(&setup, 1);
    let f_c = sources.fixture(&setup, 2);
    let (device_b, frames_b) = restore_fixture_originals(&prior.join("wallet-b"), &f_b, 89);
    let (device_c, frames_c) = restore_fixture_originals(&prior.join("wallet-c"), &f_c, 97);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    let mut c = sources.open(&device_c, &f_c, &frames_c);
    for wallet in [&mut b, &mut c] {
        let before = wallet.snapshot().unwrap();
        assert_eq!(
            (before.sequence, before.owned_balance, before.folded_balance),
            (0, 0, Some(0))
        );
    }
    // Exact retained sessions must remain readable even while A's Send is Pending.
    // A signature outage makes accidental replacement setup fail before any new signature.
    device_a
        .platform
        .with(|state| state.sign_fault_at = Some(0));
    device_b
        .platform
        .with(|state| state.sign_fault_at = Some(0));
    let offer = a.offer([210; 32], LOAD_AMOUNT).unwrap();
    let request = b.request([211; 32], &offer, None).unwrap();
    assert_eq!(device_a.platform.with(|state| state.sign_calls), 0);
    assert_eq!(device_b.platform.with(|state| state.sign_calls), 0);
    device_a.platform.with(|state| state.sign_fault_at = None);
    device_b.platform.with(|state| state.sign_fault_at = None);
    let send = action(
        212,
        OperationActionV1::Send {
            request: request.clone(),
        },
    );
    assert_eq!(a.execute(send.clone()).unwrap(), Completion::Pending);
    assert_eq!(device_a.platform.with(|state| state.sign_calls), 0);
    let evidence = norito::json!({
        "schema": "iroha.kagemusha.selected-send-continuation.v1",
        "prior_custody_root": (prior.to_str().unwrap()),
        "prior_consumer_selection_sha256": (sha(&producer)),
        "consumer_binary_sha256": (executable_hash()),
        "consumer_source_sha256": (env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "target_sha256": (sha(&target_bytes)),
        "retained_offer_sha256": (sha(&offer)), "retained_request_sha256": (sha(&request)),
        "request_id": (hex::encode([212; 32])), "status_before_resume": "Pending",
        "new_enrollments": 0, "new_loads": 0, "new_setup_signatures": 0,
        "fixture_key_recovery": "Exact deterministic engineering keys, bound to native retained slot, credential and signed E6 originals; not a production key recovery capability"
    });
    publish(
        &output.join("selected-send-continuation.json"),
        &norito::json::to_vec(&evidence).unwrap(),
    );
    let payment = complete(a.resume().unwrap().expect("existing selected Send"));
    let decoded: KagemushaWalletPaymentV1 = decode(&payment);
    require_payment_request(&decoded, &request);
    assert_eq!(complete(a.execute(send.clone()).unwrap()), payment);
    assert_eq!(a.resume().unwrap(), None);
    eprintln!(
        "NATIVE_SELECTED_SEND_RESUMED request_id=212 exact_retained_request=true no_new_load=true"
    );
    finish_exchange(
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
        send,
        payment,
    );
}

fn require_payment_request(payment: &KagemushaWalletPaymentV1, original: &[u8]) {
    let request: KagemushaWalletRequestV1 = decode(original);
    assert_eq!(
        payment.request,
        request.signed(),
        "exact receiver-signed Request body and signature"
    );
    assert_eq!(payment.request.request_digest(), request.request_digest());
}

#[test]
fn payment_request_binding_uses_signed_projection_and_rejects_changes() {
    // Canonical codec/signature vectors only; this does not qualify native monetary proofs.
    let vectors: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let rows = vectors["objects"].as_array().unwrap();
    let payment: KagemushaWalletPaymentV1 = decode(
        &hex::decode(
            rows.iter()
                .find(|row| row["type"].as_str() == Some("KagemushaWalletPaymentV1"))
                .unwrap()["canonical_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    );
    let capsule: KagemushaWalletRecoveryCapsuleV1 = decode(
        &hex::decode(
            rows.iter()
                .find(|row| row["type"].as_str() == Some("KagemushaWalletRecoveryCapsuleV1"))
                .unwrap()["canonical_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    );
    let original = &capsule
        .retained_inputs
        .iter()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request)
        .unwrap()
        .bytes;
    assert_ne!(
        norito::encode_canonical(&payment.request).unwrap(),
        *original,
        "Payment carries the signed projection, not the full Request frame"
    );
    require_payment_request(&payment, original);
    let mut changed = payment.clone();
    changed.request.body.amount += 1;
    assert!(std::panic::catch_unwind(|| require_payment_request(&changed, original)).is_err());
    changed = payment;
    changed.request.signature = KagemushaDeviceSignatureV1::from_raw_bytes(&[1; 64]).unwrap();
    assert!(std::panic::catch_unwind(|| require_payment_request(&changed, original)).is_err());
}

fn restore_recorded(root: &Path, f: &Fixture) -> (HostDevice, [Vec<u8>; 4]) {
    let frames = FRAME_NAMES.map(|name| {
        iroha_fs::read_private(root.join(name), 32768)
            .unwrap()
            .to_vec()
    });
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &f.config.scheme.scheme_id())
            .unwrap();
    assert_eq!(decode::<AccountId>(&frames[2]), f.account);
    assert_eq!(decode::<KagemushaWalletAssetScopeV1>(&frames[3]), f.asset);
    let device = HostDevice::restore(root, &credential);
    assert_eq!(
        device
            .platform
            .with(|state| (state.generate_calls, state.sign_calls)),
        (0, 0)
    );
    (device, frames)
}

#[test]
#[ignore = "requires exact COMPLETED A Send and retained A/B/C originals; reads completion without another Advance, Load or enrollment"]
fn continue_completed_a_send_then_b_to_c_unload_with_restart_and_replay() {
    let output = fresh_output("KAGEMUSHA_NATIVE_EXCHANGE_OUTPUT");
    let prior = selected_path("KAGEMUSHA_NATIVE_RETAINED_EXCHANGE");
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
    assert_eq!(previous["prior_custody_root"].as_str(), prior.to_str());
    let sources = Sources::admit(&output.join("source-admission"));
    let setup = LedgerSetup::read(&sources);
    let f = sources.fixture(&setup, 0);
    let path = selected_path("KAGEMUSHA_NATIVE_LOAD_TARGET");
    let target_bytes = read_pin(
        &path,
        TARGET_MAX,
        &env_pin("KAGEMUSHA_NATIVE_LOAD_TARGET_SHA256"),
    );
    assert_eq!(
        previous["target_sha256"].as_str(),
        Some(sha(&target_bytes).as_str())
    );
    let target: norito::json::Value = norito::json::from_slice(&target_bytes).unwrap();
    let public = path.parent().unwrap();
    let frames_a = FRAME_NAMES.map(|name| target_original(public, &target, name, 32768));
    let instruction = decode(&target_original(public, &target, "issue-load.norito", 4096));
    require_target(&target, &sources, &setup, &f, &frames_a, &instruction);
    let credential_a =
        KagemushaWalletCredentialV1::decode_canonical(&frames_a[0], &f.config.scheme.scheme_id())
            .unwrap();
    let device_a = HostDevice::restore(&public.parent().unwrap().join("wallet-a"), &credential_a);
    let mut a = sources.open(&device_a, &f, &frames_a);
    let state::RequestStatusV1::Outcome(Completion::Complete(payment)) =
        a.retry_request(&[212; 32]).unwrap()
    else {
        panic!("exact retained Send must already be durably complete; no resume or new Advance");
    };
    let before_a = a.snapshot().unwrap();
    assert_eq!(before_a.owned_balance, 0);
    let f_b = sources.fixture(&setup, 1);
    let f_c = sources.fixture(&setup, 2);
    let (device_b, frames_b) = restore_recorded(&prior.join("wallet-b"), &f_b);
    let (device_c, frames_c) = restore_recorded(&prior.join("wallet-c"), &f_c);
    let mut b = sources.open(&device_b, &f_b, &frames_b);
    let mut c = sources.open(&device_c, &f_c, &frames_c);
    for wallet in [&mut b, &mut c] {
        let before = wallet.snapshot().unwrap();
        assert_eq!(
            (before.sequence, before.owned_balance, before.folded_balance),
            (0, 0, Some(0))
        );
    }
    device_a
        .platform
        .with(|state| state.sign_fault_at = Some(0));
    device_b
        .platform
        .with(|state| state.sign_fault_at = Some(0));
    let offer = a.offer([210; 32], LOAD_AMOUNT).unwrap();
    let request = b.request([211; 32], &offer, None).unwrap();
    assert_eq!(
        previous["retained_offer_sha256"].as_str(),
        Some(sha(&offer).as_str())
    );
    assert_eq!(
        previous["retained_request_sha256"].as_str(),
        Some(sha(&request).as_str())
    );
    let send = action(
        212,
        OperationActionV1::Send {
            request: request.clone(),
        },
    );
    require_payment_request(&decode(&payment), &request);
    assert_eq!(complete(a.execute(send.clone()).unwrap()), payment);
    assert_eq!(a.snapshot().unwrap(), before_a);
    for device in [&device_a, &device_b, &device_c] {
        assert_eq!(
            device
                .platform
                .with(|state| (state.generate_calls, state.sign_calls)),
            (0, 0)
        );
    }
    device_a.platform.with(|state| state.sign_fault_at = None);
    device_b.platform.with(|state| state.sign_fault_at = None);
    let record = norito::json!({
        "schema": "iroha.kagemusha.completed-send-continuation.v1",
        "previous_continuation_sha256": (sha(&previous_bytes)),
        "consumer_binary_sha256": (executable_hash()),
        "consumer_source_sha256": (env_pin("KAGEMUSHA_NATIVE_SOURCE_SHA256")),
        "payment_sha256": (sha(&payment)), "request_sha256": (sha(&request)),
        "status_before_continue": "Complete", "new_recovery_signatures": 0,
        "new_loads": 0, "new_enrollments": 0, "resumed_advance": false
    });
    publish(
        &output.join("completed-send-continuation.json"),
        &norito::json::to_vec(&record).unwrap(),
    );
    publish(&output.join("retained-a-b-payment.norito"), &payment);
    eprintln!(
        "NATIVE_COMPLETED_SEND_REOPENED request_id=212 exact_payment=true new_payment_signatures=0 no_advance=true"
    );
    finish_exchange(
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
        send,
        payment,
    );
}

#[path = "send_recovery/fold_diagnostic.rs"]
mod fold_diagnostic;

#[path = "send_recovery/archive_recovery.rs"]
mod archive_recovery;
