//! Existing engine continuation keeps the original round custody and read-only recovery.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Continuing {
    calls: AtomicUsize,
    reads: AtomicUsize,
    wrong_context: AtomicBool,
    enabled: bool,
}
impl Continuing {
    fn status(&self, context: RoundContext<'_>) -> RoundStatusReport {
        RoundStatusReport {
            round_id: context.round_id,
            context_digest: if self.wrong_context.load(Ordering::SeqCst) {
                fixture_digest("foreign")
            } else {
                context.descriptor.intent_digest
            },
            participants: Vec::new(),
        }
    }
}
impl WorkflowDriver for Continuing {
    fn identity(&self) -> DriverIdentityV1 {
        driver_identity()
    }
    fn supports_round_continuation(&self) -> bool {
        self.enabled
    }
    fn start_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, Result<RoundReport, StepFailure>> {
        Box::pin(async move { Ok(RoundReport::Waiting(self.status(context))) })
    }
    fn recover_round<'a>(
        &'a self,
        context: RoundContext<'a>,
    ) -> WorkflowFuture<'a, Result<RoundRecovery, StepFailure>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(RoundRecovery::Found(RoundReport::Waiting(
                self.status(context),
            )))
        })
    }
    fn continue_round<'a>(
        &'a self,
        context: RoundContext<'a>,
        observed: RoundStatusReport,
    ) -> WorkflowFuture<'a, Result<RoundReport, StepFailure>> {
        Box::pin(async move {
            assert!(
                self.reads.load(Ordering::SeqCst) > 0,
                "unknown original round must recover before more effects"
            );
            let round = context.journal.steps[0].round.as_ref().unwrap();
            assert_eq!(round.round_id, Some(observed.round_id));
            assert_eq!(round.state, crate::workflow::RoundStateV1::RoundWaiting);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(RoundReport::Completed {
                status: observed,
                transcript: b"public-certificate-checkpoint".to_vec(),
                custody_handles: Vec::new(),
            })
        })
    }
}
fn driver(enabled: bool) -> Continuing {
    Continuing {
        calls: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        wrong_context: AtomicBool::new(false),
        enabled,
    }
}
fn round_plan() -> WorkflowPlanV1 {
    plan(vec![StepDescriptorV1::offchain_round(
        "phase",
        fixture_digest("round"),
        true,
        0,
        0,
    )])
}

#[test]
fn waiting_round_continues_only_after_bound_recovery_during_explicit_run() {
    let world = world();
    let storage = Arc::new(MemoryWorkflowStorage::new());
    let handle = engine(&world, storage).workflow(round_plan()).unwrap();
    let driver = driver(true);
    let error = run_until_interrupted(&world, handle.run(&driver, &options()))
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, WorkflowErrorCode::RoundPending);
    assert_eq!(driver.calls.load(Ordering::SeqCst), 0);
    let _ = run_until_interrupted(&world, handle.recover(Some(&driver), &options())).unwrap();
    assert_eq!(
        driver.calls.load(Ordering::SeqCst),
        0,
        "Recover cannot certify or promote"
    );
    driver.wrong_context.store(true, Ordering::SeqCst);
    let error = run_until_interrupted(&world, handle.run(&driver, &options()))
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, WorkflowErrorCode::BindingMismatch);
    assert_eq!(
        driver.calls.load(Ordering::SeqCst),
        0,
        "substituted recovery cannot authorize continuation"
    );
    driver.wrong_context.store(false, Ordering::SeqCst);
    let complete = run_until_interrupted(&world, handle.run(&driver, &options()))
        .unwrap()
        .unwrap();
    assert_eq!(complete.status, WorkflowStatusV1::Completed);
    assert_eq!(driver.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn cancelling_and_default_drivers_never_continue_waiting_round_effects() {
    for enabled in [false, true] {
        let world = world();
        let handle = engine(&world, Arc::new(MemoryWorkflowStorage::new()))
            .workflow(round_plan())
            .unwrap();
        let driver = driver(enabled);
        let _ = run_until_interrupted(&world, handle.run(&driver, &options())).unwrap();
        if enabled {
            handle.cancel().unwrap();
        }
        let before = handle.progress().unwrap().unwrap().sequence;
        let _ = run_until_interrupted(&world, handle.run(&driver, &options())).unwrap();
        assert_eq!(
            driver.calls.load(Ordering::SeqCst),
            0,
            "only explicit opt-in Run on an active round may continue"
        );
        if !enabled {
            assert_eq!(
                handle.progress().unwrap().unwrap().sequence,
                before,
                "default waiting must not rewrite the journal"
            );
        }
    }
}
