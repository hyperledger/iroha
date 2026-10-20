//! Nested bridge waits on the calling thread; no scheduling decisions read these values.
use std::{
    cell::Cell,
    marker::PhantomData,
    rc::Rc,
    time::{Duration, Instant},
};

/// Existing bridge admission boundaries.
#[derive(Clone, Copy, Debug)]
pub enum NativeBridgePhaseV1 {
    /// Payment priority admission, including cancellation and joining accepted proof work.
    SchedulerWait,
    /// Acquiring the exclusive wallet mutex.
    WalletLockWait,
    /// Existing custody-operations admission after that mutex is acquired.
    CustodyAdmission,
}

/// Nested elapsed times, not additional work to add to the enclosing interval.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeBridgeMetricsV1 {
    /// Priority admission, cancellation and join.
    pub scheduler_wait: Duration,
    /// Exclusive owner lock wait.
    pub wallet_lock_wait: Duration,
    /// Existing custody gate execution.
    pub custody_admission: Duration,
}
impl NativeBridgeMetricsV1 {
    pub(super) fn current() -> Self {
        METRICS.try_with(Cell::get).unwrap_or_default()
    }
    pub(super) fn since(self, before: Self) -> Self {
        Self {
            scheduler_wait: self.scheduler_wait.saturating_sub(before.scheduler_wait),
            wallet_lock_wait: self
                .wallet_lock_wait
                .saturating_sub(before.wallet_lock_wait),
            custody_admission: self
                .custody_admission
                .saturating_sub(before.custody_admission),
        }
    }
}
thread_local! {
    static METRICS: Cell<NativeBridgeMetricsV1> = const { Cell::new(NativeBridgeMetricsV1 {
        scheduler_wait: Duration::ZERO, wallet_lock_wait: Duration::ZERO,
        custody_admission: Duration::ZERO,
    }) };
}
/// Thread-confined scope that records on return or unwind without changing the operation.
#[must_use]
pub struct NativeBridgeTimerV1 {
    phase: NativeBridgePhaseV1,
    started: Instant,
    _thread: PhantomData<Rc<()>>,
}
impl NativeBridgeTimerV1 {
    /// Begin one existing bridge wait or admission scope.
    pub fn start(phase: NativeBridgePhaseV1) -> Self {
        Self {
            phase,
            started: Instant::now(),
            _thread: PhantomData,
        }
    }
}
impl Drop for NativeBridgeTimerV1 {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        let _ = METRICS.try_with(|cell| {
            let mut value = cell.get();
            let total = match self.phase {
                NativeBridgePhaseV1::SchedulerWait => &mut value.scheduler_wait,
                NativeBridgePhaseV1::WalletLockWait => &mut value.wallet_lock_wait,
                NativeBridgePhaseV1::CustodyAdmission => &mut value.custody_admission,
            };
            *total = total.saturating_add(elapsed);
            cell.set(value);
        });
    }
}
