//! Selected charged operations survive full host-owner reconstruction with exact originals.
//!
//! Genuine installed proofs and current pinned ledger inputs are supplied by the two parent
//! scenarios. Only signer availability is simulated; this is not physical power-loss testing.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletMarkerRecordV1, KagemushaWalletSlotStatusV1,
};
use state::RequestStatusV1;

fn require_load_originals(
    retained: &[KagemushaWalletRetainedInputV1],
    receipt: &[u8],
    finality: &[u8],
) {
    for (role, original) in [
        (KagemushaWalletRetainedInputRoleV1::LoadReceipt, receipt),
        (KagemushaWalletRetainedInputRoleV1::LoadFinality, finality),
    ] {
        let selected = retained
            .iter()
            .filter(|input| input.role == role)
            .collect::<Vec<_>>();
        assert_eq!(
            selected.len(),
            1,
            "one exact retained Load original per role"
        );
        assert_eq!(selected[0].bytes, original);
    }
}

fn persisted_key(device: &HostDevice) -> Vec<u8> {
    let keys: Vec<([u8; 32], [u8; 32])> = device.platform.with(|state| {
        state
            .keys
            .iter()
            .map(|(slot, key)| (slot.0, key.to_bytes().into()))
            .collect()
    });
    assert_eq!(keys.len(), 1);
    let retained = iroha_fs::read_private(device.root.join("simulator-key.norito"), 1024).unwrap();
    assert_eq!(
        retained.as_slice(),
        norito::encode_canonical(&keys).unwrap()
    );
    retained.to_vec()
}

fn selected(
    device: &HostDevice,
    scheme: [u8; 32],
) -> (
    KagemushaWalletMarkerRecordV1,
    KagemushaWalletRecoveryCapsuleV1,
) {
    let mut provider = device.provider(scheme);
    let slots = provider.slots().unwrap();
    assert_eq!(slots.len(), 1);
    let KagemushaWalletSlotStatusV1::Pending(marker) = provider.status(&slots[0]).unwrap() else {
        panic!("charged operation must remain durably Selected and unsigned");
    };
    let capsule = provider
        .current_capsule(&slots[0])
        .unwrap()
        .expect("selected capsule original");
    assert_eq!(
        marker.head().unwrap(),
        (
            capsule.body().statement.sequence,
            capsule.body().operation_id,
            capsule.custody_digest()
        )
    );
    (marker, capsule)
}

fn require_pending(
    wallet: &mut Wallet,
    device: &HostDevice,
    request: &OperationRequestV1,
    conflicts: &[OperationRequestV1],
) {
    let signs = device.platform.with(|state| state.sign_calls);
    assert_eq!(
        wallet.retry_request(&request.request_id).unwrap(),
        RequestStatusV1::Outcome(Completion::Pending)
    );
    assert_eq!(
        derived(|| wallet.execute(request.clone()).unwrap()),
        (Completion::Pending, 0)
    );
    for conflicting in conflicts {
        assert!(matches!(
            wallet.execute(conflicting.clone()),
            Err(state::Error::OperationConflict)
        ));
    }
    assert!(matches!(wallet.snapshot(), Err(state::Error::Pending)));
    if matches!(request.action, OperationActionV1::Unload { .. }) {
        assert!(matches!(
            wallet.unload_claim_bytes(&request.request_id, None),
            Err(state::Error::Pending)
        ));
    }
    assert_eq!(device.platform.with(|state| state.sign_calls), signs);
    assert_eq!(device.platform.with(|state| state.generate_calls), 0);
}

fn require_released(
    wallet: &mut Wallet,
    marker: &KagemushaWalletMarkerRecordV1,
    capsule: &KagemushaWalletRecoveryCapsuleV1,
    request: &OperationRequestV1,
    output: &[u8],
) {
    let steps = wallet.released_steps().unwrap();
    let released = steps.last().unwrap();
    assert_eq!(
        released.frozen.capsule.as_canonical_bytes(),
        capsule.as_canonical_bytes()
    );
    assert_eq!(
        Some(released.retained.selected_generation),
        marker.selected_generation()
    );
    assert_eq!(released.retained.record.output, output);
    assert_eq!(capsule.body().kind, request.kind());
    if let OperationActionV1::Load { receipt, finality } = &request.action {
        require_load_originals(&capsule.body().retained_inputs, receipt, finality);
    }
    // Unload quote/certificate originals belong to durable payout custody, not Lambda
    // inputs. The parent scenario verifies their exact reconstructed claim after resume.
    let package =
        KagemushaWalletPackageV1::decode_canonical(output, &capsule.body().scheme_id).unwrap();
    assert_eq!(package.statement, capsule.body().statement);
    assert_eq!(package.receipt.operation_id, capsule.body().operation_id);
    assert_eq!(
        package.receipt.capsule_commitment,
        capsule.receipt_commitment()
    );
}

pub(super) fn exercise(
    mut wallet: Wallet,
    device: HostDevice,
    sources: &Sources,
    fixture: &Fixture,
    frames: &[Vec<u8>; 4],
    request: &OperationRequestV1,
    conflicts: &[OperationRequestV1],
) -> (Wallet, HostDevice, Vec<u8>, norito::json::Value) {
    assert!(!conflicts.is_empty());
    request.validate(&fixture.config.scheme).unwrap();
    for conflicting in conflicts {
        assert_eq!(request.request_id, conflicting.request_id);
        assert_eq!(request.kind(), conflicting.kind());
        assert_ne!(request, conflicting);
        conflicting.validate(&fixture.config.scheme).unwrap();
    }
    match &request.action {
        OperationActionV1::Load { receipt, .. } => {
            assert!(
                KagemushaWalletLoadReceiptV1::decode_canonical(receipt)
                    .unwrap()
                    .online_charge
                    > 0
            );
        }
        OperationActionV1::Unload {
            charge: Some(charge),
            ..
        } => {
            assert!(
                KagemushaWalletChargeQuoteV1::decode_canonical(
                    &charge.quote,
                    &fixture.config.scheme.scheme_id()
                )
                .unwrap()
                .body
                .online_charge
                    > 0
            );
        }
        _ => panic!("charged Load or Unload required"),
    }
    let scheme = fixture.config.scheme.scheme_id();
    let credential = KagemushaWalletCredentialV1::decode_canonical(&frames[0], &scheme).unwrap();
    let before = wallet.snapshot().unwrap();
    let epoch = wallet.epoch_progress().unwrap();
    let ledger = wallet.ledger_progress().unwrap();
    let key = persisted_key(&device);
    let root = device.root.clone();
    let signs = device.platform.with(|state| state.sign_calls);
    assert_eq!(device.platform.with(|state| state.generate_calls), 0);
    device.platform.with(|state| state.sign_unavailable = true);
    let (pending, derivations) = derived(|| wallet.execute(request.clone()).unwrap());
    assert_eq!(pending, Completion::Pending);
    assert_eq!(
        derivations, 2,
        "fresh plan and independent commit derivation"
    );
    let failed_attempts = device.platform.with(|state| state.sign_calls) - signs;
    assert_eq!(
        failed_attempts, 1,
        "failed signer attempt is counted, not a signature"
    );
    require_pending(&mut wallet, &device, request, conflicts);
    drop(wallet);
    let (marker, capsule) = selected(&device, scheme);
    assert_eq!(capsule.body().kind, request.kind());
    assert_eq!(capsule.body().statement.sequence, before.sequence + 1);
    if let OperationActionV1::Load { receipt, finality } = &request.action {
        require_load_originals(&capsule.body().retained_inputs, receipt, finality);
    }
    assert_eq!(persisted_key(&device), key);
    drop(device);

    let device = HostDevice::restore(&root, &credential);
    device.platform.with(|state| state.sign_unavailable = true);
    let (reopened_marker, reopened_capsule) = selected(&device, scheme);
    assert_eq!(reopened_marker, marker);
    assert_eq!(
        reopened_capsule.as_canonical_bytes(),
        capsule.as_canonical_bytes()
    );
    let mut wallet = sources.open(&device, fixture, frames);
    require_pending(&mut wallet, &device, request, conflicts);
    assert_eq!(device.platform.with(|state| state.sign_calls), 0);
    // Check that Pending retries and conflicts did not select a different marker/capsule.
    drop(wallet);
    let (unchanged_marker, unchanged_capsule) = selected(&device, scheme);
    assert_eq!(unchanged_marker, marker);
    assert_eq!(
        unchanged_capsule.as_canonical_bytes(),
        capsule.as_canonical_bytes()
    );
    let mut wallet = sources.open(&device, fixture, frames);
    device.platform.with(|state| state.sign_unavailable = false);
    let (completed, resume_derivations) = derived(|| {
        wallet
            .resume()
            .unwrap()
            .expect("existing charged Selected operation")
    });
    let output = complete(completed);
    assert_eq!(
        resume_derivations, 0,
        "resume uses the selected proof and capsule"
    );
    let successful_signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(successful_signatures, 1);
    assert_eq!(device.platform.with(|state| state.generate_calls), 0);
    require_released(&mut wallet, &marker, &capsule, request, &output);
    let after = wallet.snapshot().unwrap();
    assert_eq!(after.sequence, before.sequence + 1);
    assert_eq!(after.head, capsule.body().statement.successor.value);
    assert_eq!(wallet.epoch_progress().unwrap(), epoch);
    assert_eq!(wallet.ledger_progress().unwrap(), ledger);
    assert_eq!(
        derived(|| complete(wallet.execute(request.clone()).unwrap())),
        (output.clone(), 0)
    );
    assert_eq!(
        wallet.retry_request(&request.request_id).unwrap(),
        RequestStatusV1::Outcome(Completion::Complete(output.clone()))
    );
    for conflicting in conflicts {
        assert!(matches!(
            wallet.execute(conflicting.clone()),
            Err(state::Error::OperationConflict)
        ));
    }
    assert_eq!(wallet.snapshot().unwrap(), after);
    assert_eq!(
        device.platform.with(|state| state.sign_calls),
        successful_signatures
    );
    assert_eq!(persisted_key(&device), key);
    drop(wallet);
    drop(device);

    let device = HostDevice::restore(&root, &credential);
    device.platform.with(|state| state.sign_unavailable = true);
    let mut wallet = sources.open(&device, fixture, frames);
    assert_eq!(wallet.snapshot().unwrap(), after);
    assert!(wallet.resume().unwrap().is_none());
    require_released(&mut wallet, &marker, &capsule, request, &output);
    assert_eq!(
        derived(|| complete(wallet.execute(request.clone()).unwrap())),
        (output.clone(), 0)
    );
    assert_eq!(
        wallet.retry_request(&request.request_id).unwrap(),
        RequestStatusV1::Outcome(Completion::Complete(output.clone()))
    );
    for conflicting in conflicts {
        assert!(matches!(
            wallet.execute(conflicting.clone()),
            Err(state::Error::OperationConflict)
        ));
    }
    assert_eq!(wallet.snapshot().unwrap(), after);
    assert_eq!(wallet.epoch_progress().unwrap(), epoch);
    assert_eq!(wallet.ledger_progress().unwrap(), ledger);
    let replay_attempts = device.platform.with(|state| state.sign_calls);
    assert_eq!(
        replay_attempts, 0,
        "completed retry with unavailable signer returns original bytes"
    );
    assert_eq!(device.platform.with(|state| state.generate_calls), 0);
    assert_eq!(persisted_key(&device), key);
    let evidence = norito::json!({
        "schema":"iroha.kagemusha.charged-selected-restart.v1",
        "request_id":(hex::encode(request.request_id)), "request_sha256":(sha(&norito::encode_canonical(request).unwrap())),
        "selected_marker_sha256":(sha(marker.file_bytes())), "selected_generation":(marker.selected_generation().unwrap().to_string()),
        "selected_capsule_sha256":(sha(capsule.as_canonical_bytes())), "capsule_commitment":(hex::encode(capsule.receipt_commitment())),
        "operation_id":(hex::encode(capsule.body().operation_id)), "completion_sha256":(sha(&output)),
        "sequence_before":(before.sequence.to_string()), "sequence_after":(after.sequence.to_string()),
        "head_before":(hex::encode(before.head)), "head_after":(hex::encode(after.head)),
        "failed_signing_attempts":failed_attempts, "successful_signatures":successful_signatures,
        "completed_replay_signing_attempts":replay_attempts, "fresh_derivations":derivations, "resume_derivations":resume_derivations,
        "conflicting_originals_refused":(conflicts.len()), "full_owner_restarts":2, "selected_originals_unchanged":true, "exact_completed_replay":true,
        "scope":"Existing charged operation only; actual native selected custody and host-owner reconstruction, simulated signer availability. No new enrollment or additional monetary operation; no physical crash or release qualification."
    });
    (wallet, device, output, evidence)
}

#[test]
fn load_original_check_requires_both_unique_exact_roles() {
    use KagemushaWalletRetainedInputRoleV1 as Role;
    // Structural DATA only: genuine canonical finality and proof authority remain in exercise.
    let valid = vec![
        KagemushaWalletRetainedInputV1 {
            role: Role::LoadReceipt,
            bytes: vec![1],
        },
        KagemushaWalletRetainedInputV1 {
            role: Role::LoadFinality,
            bytes: vec![2],
        },
    ];
    require_load_originals(&valid, &[1], &[2]);
    for role in 0..2 {
        let mut absent = valid.clone();
        absent.remove(role);
        assert!(std::panic::catch_unwind(|| require_load_originals(&absent, &[1], &[2])).is_err());
        let mut duplicate = valid.clone();
        duplicate.push(valid[role].clone());
        assert!(
            std::panic::catch_unwind(|| require_load_originals(&duplicate, &[1], &[2])).is_err()
        );
        let mut changed = valid.clone();
        changed[role].bytes.push(9);
        assert!(std::panic::catch_unwind(|| require_load_originals(&changed, &[1], &[2])).is_err());
        let mut foreign = valid.clone();
        foreign[role].role = Role::ChargeQuote;
        assert!(std::panic::catch_unwind(|| require_load_originals(&foreign, &[1], &[2])).is_err());
    }
}

#[test]
fn restart_key_requires_exact_existing_original_without_rewriting() {
    let directory = tempfile::tempdir().unwrap();
    let f = fixture();
    let root = directory.path().join("wallet");
    let device = HostDevice::create(&root, CHARGE_KEY_SEED);
    device.enroll(&f);
    device.save_simulator();
    let path = root.join("simulator-key.norito");
    let original = fs::read(&path).unwrap();
    assert_eq!(persisted_key(&device), original);
    fs::write(&path, [0]).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| persisted_key(&device))).is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), [0]);
    fs::write(&path, &original).unwrap();
    let held = root.join("held-original");
    fs::rename(&path, &held).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| persisted_key(&device))).is_err()
    );
    assert!(!path.exists());
    fs::rename(&held, &path).unwrap();
    assert_eq!(persisted_key(&device), original);
}
