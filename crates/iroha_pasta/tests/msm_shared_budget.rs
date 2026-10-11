//! Process-wide scratch admission in an isolated test process. Saturating the
//! cap here cannot starve unrelated unit tests that deliberately reserve bytes.

use std::sync::{Barrier, mpsc};

use iroha_pasta::msm::{PROCESS_MSM_SCRATCH_BYTES, ScratchReservation, SharedMemoryBudget};

#[test]
fn independent_budgets_share_the_process_ceiling() {
    const WORKERS: usize = 12;
    const RESERVATION: usize = 8 << 20;
    let release = Barrier::new(WORKERS + 1);
    let (send, receive) = mpsc::channel();
    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            let send = send.clone();
            let release = &release;
            scope.spawn(move || {
                let budget = SharedMemoryBudget::new(PROCESS_MSM_SCRATCH_BYTES);
                let reservation = budget.try_reserve(RESERVATION);
                send.send(reservation.as_ref().map_or(0, ScratchReservation::bytes))
                    .unwrap();
                // All successful reservations stay live until checked.
                release.wait();
                drop(reservation);
                assert_eq!(budget.in_use_bytes(), 0);
            });
        }
        let admitted: usize = (0..WORKERS).map(|_| receive.recv().unwrap()).sum();
        let process_used = SharedMemoryBudget::process_default().in_use_bytes();
        let refused_extra = SharedMemoryBudget::new(1).try_reserve(1).is_none();
        release.wait();
        assert_eq!(admitted, PROCESS_MSM_SCRATCH_BYTES);
        assert_eq!(process_used, PROCESS_MSM_SCRATCH_BYTES);
        assert!(
            refused_extra,
            "a fresh caller budget bypassed the process cap"
        );
    });
    let process = SharedMemoryBudget::process_default();
    assert_eq!(process.in_use_bytes(), 0);
    assert_eq!(process.peak_bytes(), PROCESS_MSM_SCRATCH_BYTES);
    let reservation = process.try_reserve(PROCESS_MSM_SCRATCH_BYTES).unwrap();
    assert_eq!(reservation.bytes(), PROCESS_MSM_SCRATCH_BYTES);
}
