//! Explicit engineering continuation of an already selected Send, never another Load.
//! Every participant must retain its exact current key, public frames and signed E6;
//! missing custody is refused without reconstructing keys or enrollment originals.

use super::*;

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
    assert_eq!(
        derived(|| a.execute(send.clone()).unwrap()),
        (Completion::Pending, 0),
        "a selected Send is never derived again"
    );
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
        "retained_custody_recovery": "Exact existing engineering key, public frames, native slot, credential, pre-key selection and signed E5/E6 originals; durable adoption preserves bytes and missing originals are refused without reconstruction"
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
        SendOriginals { offer, payment },
    );
}

fn require_payment_request(payment: &KagemushaWalletPaymentV1, original: &[u8]) {
    let request: KagemushaWalletRequestV1 = decode(original);
    assert_eq!(
        payment.signed_request().unwrap(),
        request.signed(),
        "exact receiver-signed Request body and signature"
    );
    assert_eq!(
        payment.signed_request().unwrap().request_digest(),
        request.request_digest()
    );
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
        .body()
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
    if let KagemushaWalletEffectV1::Send { amount, .. } = &mut changed.send.statement.effect {
        *amount += 1;
    }
    assert!(std::panic::catch_unwind(|| require_payment_request(&changed, original)).is_err());
    changed = payment;
    changed.request.signature = KagemushaDeviceSignatureV1::from_raw_bytes(&[1; 64]).unwrap();
    assert!(std::panic::catch_unwind(|| require_payment_request(&changed, original)).is_err());
}

fn restore_recorded(root: &Path, f: &Fixture) -> (HostDevice, [Vec<u8>; 4]) {
    use crate::kagemusha_wallet_advance_v1::{PreKeyRecordV1, kagemusha_wallet_provider_digest_v1};

    assert!(root.is_dir());
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
    let mut provider = device.provider(f.config.scheme.scheme_id());
    let slots = provider.slots().unwrap();
    assert_eq!(slots.len(), 1, "exact existing enrolled slot required");
    let slot = slots[0];
    assert_eq!(
        provider.credential(&slot, 0).unwrap().as_ref(),
        Some(&frames[0]),
        "recorded credential must equal existing native custody"
    );
    device.platform.with(|state| {
        assert_eq!(state.keys.len(), 1);
        assert!(
            state.keys.contains_key(&slot),
            "recorded key must use retained slot"
        );
    });
    // begin() and the retained-owner reads durably adopt existing originals.
    // Require every selected original first so a loss cannot create fresh state.
    let prekeys = [
        PreKeyRecordV1::Client,
        PreKeyRecordV1::Accepted,
        PreKeyRecordV1::Slot,
        PreKeyRecordV1::Phase,
    ]
    .map(|record| {
        (
            record,
            provider
                .prekey_read(&[11; 32], record)
                .unwrap()
                .expect("existing pre-key selection original"),
        )
    });
    let enrollment = provider
        .enrollment_record(&slot)
        .unwrap()
        .expect("existing signed E5 original");
    let result_key =
        kagemusha_wallet_provider_digest_v1("enrollment-issuer-result", &enrollment.request);
    let result = provider
        .with_archive(&slot, |archive| {
            archive.read_record(&result_key, RESULT_MAX_BYTES)
        })
        .unwrap()
        .expect("existing signed E6 original");
    let mut owner = HostEnrollment::new(provider, f.config.clone())
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    let dispatch =
        PreKeyDispatchV1::decode(&owner.begin(&[11; 32], &frames[2], &frames[3]).unwrap()).unwrap();
    assert_eq!(dispatch.purpose, KagemushaEnrollmentPermitPurposeV1::Resume);
    assert!(dispatch.previous_permit.is_some());
    let retained = owner
        .retained_result()
        .unwrap()
        .expect("existing signed E6 original");
    assert_eq!(retained.as_slice(), result.as_slice());
    assert_eq!(owner.open_originals().unwrap(), frames);
    assert_eq!(owner.retained_result().unwrap(), Some(retained));
    let provider = owner.test_provider();
    for (record, original) in prekeys {
        assert_eq!(
            provider.prekey_read(&[11; 32], record).unwrap(),
            Some(original)
        );
    }
    assert_eq!(provider.enrollment_record(&slot).unwrap(), Some(enrollment));
    assert_eq!(
        provider
            .with_archive(&slot, |archive| archive
                .read_record(&result_key, RESULT_MAX_BYTES))
            .unwrap(),
        Some(result)
    );
    drop(owner);
    device.platform.with(|state| {
        assert_eq!(state.generate_calls, 0, "no enrollment or key generation");
        assert_eq!(state.sign_calls, 0, "no new hardware signature");
    });
    (device, frames)
}

fn recorded_fixture(root: &Path, f: &Fixture, seed: u8) -> [Vec<u8>; 4] {
    let device = HostDevice::create(root, seed);
    let frames = device.enroll(f);
    device.save_simulator();
    retain_frames(&device, &frames);
    frames
}

#[test]
fn current_recorded_b_and_c_reopen_exact_originals_without_regeneration() {
    let directory = tempfile::tempdir().unwrap();
    let f = fixture();
    for (name, seed) in [("wallet-b", 89), ("wallet-c", 97)] {
        let root = directory.path().join(name);
        let frames = recorded_fixture(&root, &f, seed);
        let originals = FRAME_NAMES
            .into_iter()
            .chain(["simulator-key.norito"])
            .map(|name| (name, fs::read(root.join(name)).unwrap()))
            .collect::<Vec<_>>();
        for _ in 0..2 {
            let (device, retained) = restore_recorded(&root, &f);
            assert_eq!(retained, frames);
            assert_eq!(
                device
                    .platform
                    .with(|state| (state.generate_calls, state.sign_calls)),
                (0, 0)
            );
            for (name, bytes) in &originals {
                assert_eq!(fs::read(root.join(name)).unwrap(), *bytes);
            }
        }
    }
}

#[test]
fn recorded_recovery_refuses_each_missing_original_without_recreating_it() {
    let directory = tempfile::tempdir().unwrap();
    let f = fixture();
    let root = directory.path().join("wallet-b");
    let frames = recorded_fixture(&root, &f, 89);
    for name in FRAME_NAMES.into_iter().chain(["simulator-key.norito"]) {
        let path = root.join(name);
        let held = root.join("held-original");
        fs::rename(&path, &held).unwrap();
        assert!(
            std::panic::catch_unwind(|| restore_recorded(&root, &f)).is_err(),
            "missing {name}"
        );
        assert!(!path.exists(), "lost {name} must not be reconstructed");
        fs::rename(&held, &path).unwrap();
    }
    assert_eq!(restore_recorded(&root, &f).1, frames);
}

#[test]
fn recorded_recovery_refuses_foreign_key_slot_frames_and_native_identity() {
    let directory = tempfile::tempdir().unwrap();
    let f = fixture();
    let root = directory.path().join("wallet-b");
    let frames = recorded_fixture(&root, &f, 89);
    let foreign = directory.path().join("wallet-c");
    recorded_fixture(&foreign, &f, 97);
    let key_path = root.join("simulator-key.norito");
    let key_original = fs::read(&key_path).unwrap();
    for name in ["simulator-key.norito", "credential.norito"] {
        let path = root.join(name);
        let original = fs::read(&path).unwrap();
        let changed = fs::read(foreign.join(name)).unwrap();
        fs::write(&path, &changed).unwrap();
        assert!(std::panic::catch_unwind(|| restore_recorded(&root, &f)).is_err());
        assert_eq!(fs::read(&path).unwrap(), changed);
        fs::write(&path, original).unwrap();
    }
    let mut key: Vec<([u8; 32], [u8; 32])> = decode(&key_original);
    key[0].0[0] ^= 1;
    fs::write(&key_path, norito::encode_canonical(&key).unwrap()).unwrap();
    assert!(std::panic::catch_unwind(|| restore_recorded(&root, &f)).is_err());
    fs::write(&key_path, &key_original).unwrap();
    for (name, changed) in [
        ("certificates.norito", vec![0]),
        (
            "account.norito",
            norito::encode_canonical(&AccountId::new(
                KeyPair::from_seed(vec![77; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            ))
            .unwrap(),
        ),
        ("asset.norito", {
            let mut asset = f.asset.clone();
            asset.scale += 1;
            norito::encode_canonical(&asset).unwrap()
        }),
    ] {
        let path = root.join(name);
        let original = fs::read(&path).unwrap();
        fs::write(&path, &changed).unwrap();
        assert!(
            std::panic::catch_unwind(|| restore_recorded(&root, &f)).is_err(),
            "foreign {name}"
        );
        assert_eq!(fs::read(&path).unwrap(), changed);
        fs::write(&path, original).unwrap();
    }
    // A mutually matching foreign key and public credential still cannot adopt
    // another participant's already-selected native slot and enrollment result.
    for name in FRAME_NAMES.into_iter().chain(["simulator-key.norito"]) {
        fs::write(root.join(name), fs::read(foreign.join(name)).unwrap()).unwrap();
    }
    assert!(std::panic::catch_unwind(|| restore_recorded(&root, &f)).is_err());
    for (name, original) in FRAME_NAMES.into_iter().zip(&frames) {
        fs::write(root.join(name), original).unwrap();
    }
    fs::write(key_path, key_original).unwrap();
    assert_eq!(restore_recorded(&root, &f).1, frames);
}

#[test]
fn recorded_recovery_refuses_lost_prekey_or_e5_before_enrollment_adoption() {
    let directory = tempfile::tempdir().unwrap();
    let f = fixture();
    let root = directory.path().join("wallet-b");
    let frames = recorded_fixture(&root, &f, 89);
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &f.config.scheme.scheme_id())
            .unwrap();
    let device = HostDevice::restore(&root, &credential);
    let provider = device.provider(f.config.scheme.scheme_id());
    let slot = provider.slots().unwrap()[0];
    drop(provider);
    let custody = root.join("custody");
    let mut paths = ["client", "accepted", "slot", "phase"]
        .map(|role| custody.join(format!("prekey-{}-{role}.norito", hex::encode([11; 32]))))
        .to_vec();
    paths.push(
        custody
            .join("slots")
            .join(hex::encode(slot.0))
            .join("enrollment.norito"),
    );
    let originals = paths
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect::<Vec<_>>();
    for missing in &paths {
        let held = root.join("held-enrollment-original");
        fs::rename(missing, &held).unwrap();
        assert!(std::panic::catch_unwind(|| restore_recorded(&root, &f)).is_err());
        assert!(
            !missing.exists(),
            "missing enrollment original must remain absent"
        );
        for (path, original) in paths.iter().zip(&originals) {
            if path != missing {
                assert_eq!(fs::read(path).unwrap(), *original);
            }
        }
        fs::rename(&held, missing).unwrap();
    }
    assert_eq!(restore_recorded(&root, &f).1, frames);
}

#[test]
fn recorded_recovery_refuses_lost_e6_without_reconstructing_enrollment() {
    use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1;

    let directory = tempfile::tempdir().unwrap();
    let f = fixture();
    let root = directory.path().join("wallet-b");
    let frames = recorded_fixture(&root, &f, 89);
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &f.config.scheme.scheme_id())
            .unwrap();
    let device = HostDevice::restore(&root, &credential);
    let mut provider = device.provider(f.config.scheme.scheme_id());
    let slot = provider.slots().unwrap()[0];
    let request = provider.enrollment_record(&slot).unwrap().unwrap().request;
    let key = kagemusha_wallet_provider_digest_v1("enrollment-issuer-result", &request);
    provider
        .with_archive(&slot, |archive| archive.remove_record(&key))
        .unwrap();
    drop(provider);
    assert!(std::panic::catch_unwind(|| restore_recorded(&root, &f)).is_err());
    let mut provider = device.provider(f.config.scheme.scheme_id());
    assert!(
        provider
            .with_archive(&slot, |archive| archive.read_record(&key, RESULT_MAX_BYTES))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        provider.credential(&slot, 0).unwrap(),
        Some(frames[0].clone())
    );
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
        SendOriginals { offer, payment },
    );
}

#[path = "send_recovery/archive_recovery.rs"]
mod archive_recovery;
