//! Genuine Load admission, Selected custody, and exact restart/replay within the ABC test.
//!
//! This uses the installed native proof owner and independently pinned finalized receipt.
//! Only the hardware availability fault is simulated. A Selected resume authenticates its
//! existing capsule custody; it does not reverify finality or create another monetary proof.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletMarkerRecordV1, KagemushaWalletSlotStatusV1,
};
use state::RequestStatusV1;

fn load_action(
    receipt: &KagemushaWalletLoadReceiptV1,
    finality: &KagemushaWalletLoadFinalityV1,
) -> OperationActionV1 {
    let receipt_bytes = receipt.to_canonical_bytes().unwrap();
    let finality_bytes = finality.to_canonical_bytes().unwrap();
    assert_eq!(
        KagemushaWalletLoadReceiptV1::decode_canonical(&receipt_bytes).unwrap(),
        *receipt
    );
    assert_eq!(
        KagemushaWalletLoadFinalityV1::decode_canonical(&finality_bytes).unwrap(),
        *finality
    );
    OperationActionV1::Load {
        receipt: receipt_bytes,
        finality: finality_bytes,
    }
}

fn forged_loads(request: &OperationRequestV1) -> [OperationActionV1; 3] {
    let OperationActionV1::Load { receipt, finality } = &request.action else {
        panic!("Load seam requires the actual retained Load request")
    };
    let receipt = KagemushaWalletLoadReceiptV1::decode_canonical(receipt).unwrap();
    let evidence = KagemushaWalletLoadFinalityV1::decode_canonical(finality).unwrap();

    let mut changed_receipt = receipt;
    changed_receipt.amount = changed_receipt.amount.checked_add(1).unwrap();
    let mut rebound = evidence.clone();
    // Keep the advertised digest consistent: only the signed result's actual event can
    // reject the changed amount. This is not a malformed-frame/digest-mismatch test.
    rebound.receipt_digest = changed_receipt.receipt_digest().unwrap();
    let changed_receipt = load_action(&changed_receipt, &rebound);

    let mut forged_qc = evidence.clone();
    let mut qc: iroha_sumeragi::message::Qc = decode(&forged_qc.certificate.commit_qc);
    qc.agg_sig.0[0] ^= 1;
    forged_qc.certificate.commit_qc = norito::encode_canonical(&qc).unwrap();
    assert_eq!(
        decode::<iroha_sumeragi::message::Qc>(&forged_qc.certificate.commit_qc),
        qc
    );

    let mut forged_event = evidence;
    forged_event.event_proof = iroha_crypto::MerkleProof::from_audit_path(
        forged_event.event_proof.leaf_index() ^ 1,
        forged_event.event_proof.audit_path().to_vec(),
    );
    [
        changed_receipt,
        load_action(&receipt, &forged_qc),
        load_action(&receipt, &forged_event),
    ]
}

fn pending_marker(device: &HostDevice, scheme: [u8; 32]) -> KagemushaWalletMarkerRecordV1 {
    let mut provider = device.provider(scheme);
    let slots = provider.slots().unwrap();
    assert_eq!(slots.len(), 1);
    let KagemushaWalletSlotStatusV1::Pending(marker) = provider.status(&slots[0]).unwrap() else {
        panic!("valid Load must be durably Selected before restart")
    };
    marker
}

fn require_persisted_simulator(device: &HostDevice) {
    // The Load-target producer already durably published this exact private simulator key.
    // Do not overwrite it or carry the old in-memory platform into the restarted owner.
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
}

fn require_released_originals(
    wallet: &mut Wallet,
    selected: &KagemushaWalletMarkerRecordV1,
    request: &OperationRequestV1,
    loaded: &[u8],
) {
    let steps = wallet.released_steps().unwrap();
    let released = steps.last().unwrap();
    let capsule = &released.frozen.capsule;
    let (sequence, operation, digest) = selected.head().unwrap();
    assert_eq!(capsule.kind, KagemushaWalletOperationKindV1::Load);
    assert_eq!(capsule.statement.sequence, sequence);
    assert_eq!(capsule.operation_id, operation);
    assert_eq!(capsule.capsule_digest().unwrap(), digest);
    assert_eq!(
        Some(released.retained.selected_generation),
        selected.selected_generation()
    );
    assert_eq!(released.retained.record.output, loaded);
    let OperationActionV1::Load { receipt, finality } = &request.action else {
        panic!("Load request")
    };
    for (role, original) in [
        (KagemushaWalletRetainedInputRoleV1::LoadReceipt, receipt),
        (KagemushaWalletRetainedInputRoleV1::LoadFinality, finality),
    ] {
        let retained: Vec<_> = capsule
            .retained_inputs
            .iter()
            .filter(|input| input.role == role)
            .collect();
        assert_eq!(retained.len(), 1);
        assert_eq!(&retained[0].bytes, original);
    }
}

fn reject_forged(
    wallet: &mut Wallet,
    device: &HostDevice,
    request: &OperationRequestV1,
) -> [OperationRequestV1; 3] {
    let before = wallet.snapshot().unwrap();
    let signs = device.platform.with(|state| state.sign_calls);
    let forged = forged_loads(request);
    let changed_requests = forged.clone().map(|action| OperationRequestV1 {
        action,
        ..request.clone()
    });
    for ((id, label), forged) in [(204, "receipt"), (205, "QC"), (206, "event")]
        .into_iter()
        .zip(forged)
    {
        assert!(
            matches!(
                wallet.execute(action(id, forged)),
                Err(state::Error::Proof(_))
            ),
            "canonical forged {label} must fail the real native proof gate"
        );
        assert_eq!(device.platform.with(|state| state.sign_calls), signs);
        assert_eq!(
            wallet.snapshot().unwrap(),
            before,
            "rejected Load cannot credit or change the head"
        );
    }

    changed_requests
}

pub(super) fn exercise(
    mut wallet: Wallet,
    device: HostDevice,
    sources: &Sources,
    f: &Fixture,
    frames: &[Vec<u8>; 4],
    credential: &KagemushaWalletCredentialV1,
    request: &OperationRequestV1,
) -> (Wallet, HostDevice, Vec<u8>) {
    let before = wallet.snapshot().unwrap();
    let changed_requests = reject_forged(&mut wallet, &device, request);
    let signs = device.platform.with(|state| state.sign_calls);

    device.platform.with(|state| state.sign_unavailable = true);
    assert_eq!(
        wallet.execute(request.clone()).unwrap(),
        Completion::Pending
    );
    assert_eq!(device.platform.with(|state| state.sign_calls), signs + 1);
    assert_eq!(
        wallet.retry_request(&request.request_id).unwrap(),
        RequestStatusV1::Outcome(Completion::Pending)
    );
    assert!(matches!(wallet.snapshot(), Err(state::Error::Pending)));
    for changed_request in &changed_requests {
        assert!(matches!(
            wallet.execute(changed_request.clone()),
            Err(state::Error::OperationConflict)
        ));
    }
    assert_eq!(device.platform.with(|state| state.sign_calls), signs + 1);
    drop(wallet);
    let selected = pending_marker(&device, f.config.scheme.scheme_id());
    require_persisted_simulator(&device);
    let root = device.root.clone();
    drop(device);

    let device = HostDevice::restore(&root, credential);
    device.platform.with(|state| state.sign_unavailable = true);
    assert_eq!(
        pending_marker(&device, f.config.scheme.scheme_id()),
        selected
    );
    let mut wallet = sources.open(&device, f, frames);
    assert_eq!(
        wallet.retry_request(&request.request_id).unwrap(),
        RequestStatusV1::Outcome(Completion::Pending)
    );
    assert!(matches!(wallet.snapshot(), Err(state::Error::Pending)));
    for changed_request in &changed_requests {
        assert!(matches!(
            wallet.execute(changed_request.clone()),
            Err(state::Error::OperationConflict)
        ));
    }
    assert_eq!(
        device.platform.with(|state| state.sign_calls),
        0,
        "reopen and conflicting request cannot sign"
    );

    device.platform.with(|state| state.sign_unavailable = false);
    let loaded = complete(wallet.resume().unwrap().expect("existing Selected Load"));
    assert_eq!(device.platform.with(|state| state.sign_calls), 1);
    require_released_originals(&mut wallet, &selected, request, &loaded);
    let after = wallet.snapshot().unwrap();
    assert_eq!(after.sequence, before.sequence + 1);
    assert_eq!(after.owned_balance, before.owned_balance + LOAD_AMOUNT);
    assert_eq!(complete(wallet.execute(request.clone()).unwrap()), loaded);
    assert_eq!(
        wallet.retry_request(&request.request_id).unwrap(),
        RequestStatusV1::Outcome(Completion::Complete(loaded.clone()))
    );
    for changed_request in &changed_requests {
        assert!(matches!(
            wallet.execute(changed_request.clone()),
            Err(state::Error::OperationConflict)
        ));
    }
    assert_eq!(wallet.snapshot().unwrap(), after);
    assert_eq!(
        device.platform.with(|state| state.sign_calls),
        1,
        "completed retries return the retained randomized signature"
    );
    // Reopen the completed owner from the actual retained private simulator key. A
    // completion retry must not depend on the earlier process or an available signer.
    require_persisted_simulator(&device);
    drop(wallet);
    drop(device);
    let device = HostDevice::restore(&root, credential);
    device.platform.with(|state| state.sign_unavailable = true);
    let mut wallet = sources.open(&device, f, frames);
    assert_eq!(wallet.snapshot().unwrap(), after);
    assert!(wallet.resume().unwrap().is_none());
    require_released_originals(&mut wallet, &selected, request, &loaded);
    assert_eq!(complete(wallet.execute(request.clone()).unwrap()), loaded);
    assert_eq!(
        wallet.retry_request(&request.request_id).unwrap(),
        RequestStatusV1::Outcome(Completion::Complete(loaded.clone()))
    );
    for changed_request in &changed_requests {
        assert!(matches!(
            wallet.execute(changed_request.clone()),
            Err(state::Error::OperationConflict)
        ));
    }
    assert_eq!(wallet.snapshot().unwrap(), after);
    assert_eq!(
        device.platform.with(|state| state.sign_calls),
        0,
        "completed replay after restart needs no new signature"
    );
    // The surrounding A → B → C exchange continues with its ordinary signer available.
    device.platform.with(|state| state.sign_unavailable = false);
    (wallet, device, loaded)
}
