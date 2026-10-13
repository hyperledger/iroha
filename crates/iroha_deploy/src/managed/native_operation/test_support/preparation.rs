//! Actual wallet-produced prefix fault controls, never parallel preparation records or authority.

use super::UnavailablePeers;
use crate::managed::{PreparedLocalnet, Result};
use iroha_fs::PrivateDirectory;
use iroha_wallet::operations::{
    NativePreparationPhase, OperationStatus, VerifiedNativePreparation,
};
use std::path::Path;

const MAX_BYTES: usize = 4 * 1024 * 1024;

/// Replay the real durable prefix before operation publication; the canonical producer alone
/// finishes its retained payload. These controls precede every native commit and any dispatch.
pub(in crate::managed) fn payload_retained(
    prepared: &PreparedLocalnet,
    path: &Path,
    mut inspect: impl FnMut() -> VerifiedNativePreparation,
    mut observe_or_advance: impl FnMut(bool) -> Result<OperationStatus>,
    mut finish: impl FnMut(),
) {
    assert_phase(&inspect(), NativePreparationPhase::Signed);
    let directory = PrivateDirectory::open_exact(path).unwrap();
    let request = directory.read("preparation.json", MAX_BYTES).unwrap();
    let payload = directory.read("payload.json", MAX_BYTES).unwrap();
    let signed = directory.read("operation.json", MAX_BYTES).unwrap();
    assert!(!path.join("submission.json").exists());
    assert!(!path.join("applied.json").exists());
    // Test-only fault: all remaining bytes were published by the genuine wallet producer.
    // They are exactly the prefix present before that producer commits operation.json.
    std::fs::remove_file(path.join("operation.json")).unwrap();
    let inventory = directory.entries(8).unwrap();
    let mut peers = UnavailablePeers::start(prepared);
    assert_phase(&inspect(), NativePreparationPhase::PayloadRetained);
    for _ in 0..2 {
        assert_eq!(observe_or_advance(false).unwrap(), OperationStatus::Absent);
        assert_eq!(directory.entries(8).unwrap(), inventory);
        assert_eq!(
            directory.read("preparation.json", MAX_BYTES).unwrap(),
            request
        );
        assert_eq!(directory.read("payload.json", MAX_BYTES).unwrap(), payload);
        assert!(peers.requests.lock().unwrap().is_empty());
    }
    assert!(
        observe_or_advance(true).is_err(),
        "missing fresh native prerequisite must refuse explicit advance"
    );
    assert_phase(&inspect(), NativePreparationPhase::PayloadRetained);
    assert!(!path.join("operation.json").exists());
    assert!(
        peers
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.method == "GET")
    );
    peers.requests.lock().unwrap().clear();
    // This existing native fixture has already authenticated the unchanged prerequisite.
    // Finish directly through the same wallet owner; this does not claim coordinator HTTP success.
    finish();
    assert_phase(&inspect(), NativePreparationPhase::Signed);
    assert_eq!(
        directory.read("preparation.json", MAX_BYTES).unwrap(),
        request
    );
    assert_eq!(directory.read("payload.json", MAX_BYTES).unwrap(), payload);
    assert_eq!(directory.read("operation.json", MAX_BYTES).unwrap(), signed);
    assert!(!path.join("submission.json").exists());
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

fn assert_phase(preparation: &VerifiedNativePreparation, phase: NativePreparationPhase) {
    assert_eq!(preparation.phase(), phase);
    assert_eq!(
        preparation.unprepared_status(),
        match phase {
            NativePreparationPhase::RequestOnly | NativePreparationPhase::PayloadRetained => {
                Some(OperationStatus::Absent)
            }
            NativePreparationPhase::Missing
            | NativePreparationPhase::Signed
            | NativePreparationPhase::Retired => None,
        }
    );
    assert_eq!(
        preparation.signed_transaction().is_some(),
        phase == NativePreparationPhase::Signed
    );
}
