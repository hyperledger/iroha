//! Scheduler-only lifetime, ordering and codec controls; these grant no protocol authority.

use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

#[test]
fn independent_workers_join_before_ordered_results_and_partial_failure() {
    for fail in [false, true] {
        let (entered, starts) = mpsc::channel();
        let gates: [_; 3] = std::array::from_fn(|_| mpsc::channel());
        let [a, b, c] = gates;
        let receivers = [Mutex::new(a.1), Mutex::new(b.1), Mutex::new(c.1)];
        let exited = AtomicUsize::new(0);
        thread::scope(|scope| {
            let controller = scope.spawn(move || {
                for _ in 0..3 {
                    starts.recv_timeout(Duration::from_secs(10)).unwrap();
                }
                // A serial implementation cannot reach these releases. Out-of-order worker
                // completion must still produce provider order, including an earlier error.
                c.0.send(()).unwrap();
                b.0.send(()).unwrap();
                a.0.send(()).unwrap();
            });
            let result = run(
                [0, 1, 2],
                true,
                |slot| {
                    entered.send(slot).unwrap();
                    receivers[slot]
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap();
                    exited.fetch_add(1, Ordering::SeqCst);
                    if fail && slot == 0 {
                        Err("member refused")
                    } else {
                        Ok(slot)
                    }
                },
                || "worker failed",
            );
            assert_eq!(exited.load(Ordering::SeqCst), 3);
            assert_eq!(
                result,
                if fail {
                    Err("member refused")
                } else {
                    Ok([0, 1, 2])
                }
            );
            controller.join().unwrap();
        });
    }
}

#[test]
fn panicked_worker_does_not_leave_other_workers_owned_by_caller() {
    let finished = AtomicUsize::new(0);
    let result = run(
        [0, 1, 2],
        true,
        |slot| {
            if slot == 0 {
                panic!("scheduler-only injected panic");
            }
            finished.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>(slot)
        },
        || "worker failed",
    );
    assert_eq!(result, Err("worker failed"));
    assert_eq!(finished.load(Ordering::SeqCst), 2);
}

#[test]
fn recovery_and_active_norito_keep_caller_thread_and_short_circuit() {
    let caller = thread::current().id();
    for active in [false, true] {
        let calls = Mutex::new(Vec::new());
        let check = || {
            let result = run(
                [0, 1, 2],
                active,
                |slot| {
                    assert_eq!(thread::current().id(), caller);
                    assert_eq!(norito::core::decode_limits_active(), active);
                    calls.lock().unwrap().push(slot);
                    if slot == 1 { Err("stop") } else { Ok(slot) }
                },
                || "worker failed",
            );
            assert_eq!(result, Err("stop"));
        };
        if active {
            let limits = norito::DecodeLimits::new(1024, 1024, 1024, 0, 8);
            norito::core::DecodeBudgetContext::new(limits).with(check);
        } else {
            check();
        }
        assert_eq!(*calls.lock().unwrap(), [0, 1]);
    }
}
