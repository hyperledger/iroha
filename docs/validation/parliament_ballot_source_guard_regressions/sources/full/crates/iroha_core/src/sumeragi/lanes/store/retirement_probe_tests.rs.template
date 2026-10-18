//! Nonblocking conservative retirement probes for the actual ready store mutexes.

use super::tests::open;
use super::*;
use crate::sumeragi::lanes::record::tests::fixture;

#[test]
fn retirement_pending_work_probe_retains_each_held_mutex_without_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let (_body, _qc, source, budget, crypto) = fixture(1025);
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    assert!(!store.retains_pending_work());
    let state = store.state.lock();
    assert!(
        store.retains_pending_work(),
        "an actual held state mutex conservatively retains custody"
    );
    drop(state);
    assert!(!store.retains_pending_work());
    let batch = store.batch_read.lock();
    assert!(
        store.retains_pending_work(),
        "an actual held batch mutex conservatively retains custody"
    );
    drop(batch);
    assert!(!store.retains_pending_work());
}
