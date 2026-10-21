//! Observe selected fold calls through the unchanged bridge return/fence boundary.
use super::*;
use std::cell::Cell;

#[derive(Clone, Copy)]
struct Capture {
    log: usize,
    record: Option<u64>,
}
thread_local! {
    static CAPTURE: Cell<Option<Capture>> = const { Cell::new(None) };
}
pub(super) fn capture(inner: &Inner, id: u64) {
    let _ = CAPTURE.try_with(|cell| {
        if let Some(mut selected) = cell.get()
            && selected.log == std::ptr::from_ref(inner) as usize
        {
            selected.record = Some(id);
            cell.set(Some(selected));
        }
    });
}

/// Holds only the observation log while a selected bridge fold returns; never an Owner.
pub(crate) struct FoldBridgeTurnV1 {
    inner: Arc<Inner>,
    turn: Option<state::NativeWorkTurnV1>,
    previous: Option<Capture>,
}
impl FoldBridgeTurnV1 {
    /// An invalid/closed handle still follows the unchanged original dispatch failure.
    pub(crate) fn begin(handle: u64) -> Option<Self> {
        let owner = owner(handle).ok()?;
        Some(Self::of(&owner.background))
    }
    pub(super) fn of(background: &Background) -> Self {
        let inner = Arc::clone(&background.inner);
        let previous = CAPTURE
            .try_with(|cell| {
                cell.replace(Some(Capture {
                    log: Arc::as_ptr(&inner) as usize,
                    record: None,
                }))
            })
            .unwrap_or(None);
        Self {
            inner,
            previous,
            turn: Some(state::NativeWorkTurnV1::start(
                state::NativeWorkKindV1::Fold,
            )),
        }
    }
    /// Called only after the original bridge run/output returned. No-selected-work attempts
    /// are omitted; absence is not evidence of zero waiting or cancellation effort.
    pub(crate) fn finish(mut self, returned: bool) {
        let selected = CAPTURE.try_with(Cell::get).unwrap_or(None);
        if let Some(selected) = selected
            && selected.log == Arc::as_ptr(&self.inner) as usize
            && let Some(id) = selected.record
            && let Some(turn) = self.turn.take()
        {
            let mut record = turn.finish(returned);
            record.fold_record_id = Some(id);
            self.inner.lock().fold.record_native_work(record);
        }
    }
}
impl Drop for FoldBridgeTurnV1 {
    fn drop(&mut self) {
        let _ = CAPTURE.try_with(|cell| cell.set(self.previous));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use state::FoldObserverV1;
    fn core_record() -> state::FoldSubProofV1 {
        state::FoldSubProofV1 {
            started_native_micros: 0,
            ended_native_micros: 0,
            sequence: 1,
            operation: None,
            stage: None,
            ordinal: 0,
            outcome: state::FoldOutcomeV1::Folded,
            phases: [std::time::Duration::ZERO; state::FoldPhaseV1::COUNT],
            verification: Default::default(),
            work: Default::default(),
            peak_rss_bytes: None,
            ingests: 0,
        }
    }
    #[test]
    fn bridge_record_is_after_final_fence_and_failure_does_not_rewrite_core_outcome() {
        let background = Background::default();
        for failed in [false, true] {
            let scope = FoldBridgeTurnV1::of(&background);
            let expected_id = background.inner.lock().fold.counts().sub_proofs + 1;
            let previous_work = background.inner.lock().fold.native_work_count();
            let result = run_with_fence(
                || {
                    background.inner.sub_proof(core_record());
                    // Another caller can append a core record before this call releases.
                    let other = Arc::clone(&background.inner);
                    std::thread::spawn(move || other.sub_proof(core_record()))
                        .join()
                        .unwrap();
                    Ok(())
                },
                || {
                    assert_eq!(
                        background.inner.lock().fold.native_work_count(),
                        previous_work
                    );
                    if failed {
                        Err(std::io::Error::other("test fence"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.is_ok(), !failed);
            scope.finish(result.is_ok());
            let control = background.inner.lock();
            let work = control.fold.native_work().back().unwrap();
            assert_eq!(work.kind, state::NativeWorkKindV1::Fold);
            assert_eq!(work.fold_record_id, Some(expected_id));
            assert_eq!(work.returned, !failed);
            assert!(
                control
                    .fold
                    .records()
                    .iter()
                    .all(|record| record.outcome == state::FoldOutcomeV1::Folded)
            );
        }
    }
    #[test]
    fn no_selected_subproof_produces_no_bridge_record() {
        let background = Background::default();
        FoldBridgeTurnV1::of(&background).finish(true);
        assert_eq!(background.inner.lock().fold.native_work_count(), 0);
        assert!(CAPTURE.with(Cell::get).is_none());
    }
}
