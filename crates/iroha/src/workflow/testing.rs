//! Deterministic doubles for workflow tests: a fake clock, a fake account and a scripted ledger.
//!
//! One [`FakeWorkflowWorld`] plays all three roles and records every external
//! effect in order, so a test can assert the exact sequence of signs,
//! dispatches, committed-outcome reads and sleeps. Nothing here touches a
//! network or the wall clock, and no secret is involved: fake signed bytes are
//! the text `signed:<label>`.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use iroha_crypto::Hash;

use super::{
    contract::WorkflowErrorCode,
    engine::{
        CommittedOutcome, DispatchOutcome, SignedStepTransaction, StepFailure, WorkflowAccount,
        WorkflowClock, WorkflowFuture, WorkflowLedger,
    },
    journal::{Digest32, TransactionIdentityV1, WorkflowBindingV1},
};

/// Prefix of every fake unsigned payload.
pub const FAKE_PAYLOAD_PREFIX: &[u8] = b"payload:";
/// Prefix of every fake signed transaction.
pub const FAKE_SIGNED_PREFIX: &[u8] = b"signed:";

/// The Iroha hash of a text, used to derive fixture digests from labels.
#[must_use]
pub fn fixture_digest(text: &str) -> Digest32 {
    *Hash::new(text.as_bytes()).as_ref()
}

/// Scripted behaviour of one signing call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeSign {
    /// Sign and report the true identity.
    Ok,
    /// Fail with a typed code.
    Fail(WorkflowErrorCode),
    /// Sign, but report an identity the bytes do not hash to.
    WrongIdentity,
    /// The process stops inside this call.
    Interrupt,
}

/// Scripted behaviour of one dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeDispatch {
    /// Return this classification.
    Outcome(DispatchOutcome),
    /// The process stops inside this call.
    Interrupt,
}

/// Scripted behaviour of one committed-outcome read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeStatus {
    /// Return this outcome.
    Outcome(CommittedOutcome),
    /// The process stops inside this call.
    Interrupt,
}

/// Called with every effect right after it joins the trace, from inside the external call.
pub type EffectHook = Arc<dyn Fn(&str) + Send + Sync>;

/// Holder that keeps [`FakeWorkflowWorld`] printable.
#[derive(Default)]
struct HookSlot(Mutex<Option<EffectHook>>);

impl core::fmt::Debug for HookSlot {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HookSlot")
    }
}

/// Fake clock, fake account and scripted ledger with one ordered effect trace.
#[derive(Debug)]
pub struct FakeWorkflowWorld {
    binding: WorkflowBindingV1,
    now_ms: AtomicU64,
    interrupted: AtomicBool,
    effect_hook: HookSlot,
    trace: Mutex<Vec<String>>,
    labels: Mutex<HashMap<Digest32, String>>,
    signs: Mutex<VecDeque<FakeSign>>,
    dispatches: Mutex<VecDeque<FakeDispatch>>,
    statuses: Mutex<VecDeque<FakeStatus>>,
}

impl FakeWorkflowWorld {
    /// Create a world bound to `binding` whose clock starts at one million milliseconds.
    #[must_use]
    pub fn new(binding: WorkflowBindingV1) -> Self {
        Self {
            binding,
            now_ms: AtomicU64::new(1_000_000),
            interrupted: AtomicBool::new(false),
            effect_hook: HookSlot::default(),
            trace: Mutex::new(Vec::new()),
            labels: Mutex::new(HashMap::new()),
            signs: Mutex::new(VecDeque::new()),
            dispatches: Mutex::new(VecDeque::new()),
            statuses: Mutex::new(VecDeque::new()),
        }
    }

    /// The unsigned payload a fixture driver returns for `label`.
    #[must_use]
    pub fn payload(label: &str) -> Vec<u8> {
        [FAKE_PAYLOAD_PREFIX, label.as_bytes()].concat()
    }

    /// Replace the scripts of the next call.
    pub fn script(
        &self,
        signs: Vec<FakeSign>,
        dispatches: Vec<FakeDispatch>,
        statuses: Vec<FakeStatus>,
    ) {
        *self.signs.lock().expect("signs") = signs.into();
        *self.dispatches.lock().expect("dispatches") = dispatches.into();
        *self.statuses.lock().expect("statuses") = statuses.into();
    }

    /// Number of scripted entries no call consumed.
    #[must_use]
    pub fn unconsumed(&self) -> usize {
        self.signs.lock().expect("signs").len()
            + self.dispatches.lock().expect("dispatches").len()
            + self.statuses.lock().expect("statuses").len()
    }

    /// Append one effect to the ordered trace, then tell the effect hook.
    ///
    /// Every external call records its effect when it starts, so the hook runs
    /// while that call is in flight: another actor can act between the moment the
    /// engine entered the call and the moment the call returns.
    pub fn push_effect(&self, effect: impl Into<String>) {
        let effect = effect.into();
        self.trace.lock().expect("trace").push(effect.clone());
        // The hook is called without any lock held: it may append effects itself.
        let hook = self.effect_hook.0.lock().expect("effect hook").clone();
        if let Some(hook) = hook {
            hook(&effect);
        }
    }

    /// Install or remove the hook that observes every effect from inside its call.
    pub fn set_effect_hook(&self, hook: Option<EffectHook>) {
        *self.effect_hook.0.lock().expect("effect hook") = hook;
    }

    /// Take the ordered effect trace recorded so far.
    #[must_use]
    pub fn take_trace(&self) -> Vec<String> {
        std::mem::take(&mut *self.trace.lock().expect("trace"))
    }

    /// Mark the process as stopped and never return.
    pub async fn interrupt<T>(&self) -> T {
        self.interrupted.store(true, Ordering::SeqCst);
        std::future::pending().await
    }

    /// Read and clear the interruption mark.
    pub fn take_interrupted(&self) -> bool {
        self.interrupted.swap(false, Ordering::SeqCst)
    }

    fn label_of(&self, identity: &TransactionIdentityV1) -> String {
        self.labels
            .lock()
            .expect("labels")
            .get(&identity.signed_transaction_hash)
            .cloned()
            .unwrap_or_else(|| "unknown-identity".to_owned())
    }

    fn identity_of(signed_transaction: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        if !signed_transaction.starts_with(FAKE_SIGNED_PREFIX)
            || signed_transaction.len() == FAKE_SIGNED_PREFIX.len()
        {
            return Err(StepFailure::new(
                WorkflowErrorCode::NonCanonicalEncoding,
                "not a fake signed transaction",
            ));
        }
        Ok(TransactionIdentityV1 {
            signed_transaction_hash: *Hash::new(signed_transaction).as_ref(),
            entrypoint_hash: *Hash::new_from_chunks(&[b"entrypoint:", signed_transaction]).as_ref(),
        })
    }
}

impl WorkflowClock for FakeWorkflowWorld {
    fn now_unix_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    fn sleep(&self, duration: Duration) -> WorkflowFuture<'_, ()> {
        let milliseconds = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        self.now_ms.fetch_add(milliseconds, Ordering::SeqCst);
        self.push_effect(format!("sleep:{milliseconds}"));
        Box::pin(async {})
    }
}

impl WorkflowAccount for FakeWorkflowWorld {
    fn binding(&self) -> WorkflowBindingV1 {
        self.binding.clone()
    }

    fn sign<'a>(
        &'a self,
        unsigned_payload: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
        Box::pin(async move {
            let Some(label) = unsigned_payload
                .strip_prefix(FAKE_PAYLOAD_PREFIX)
                .and_then(|label| core::str::from_utf8(label).ok())
            else {
                return Err(StepFailure::new(
                    WorkflowErrorCode::NonCanonicalEncoding,
                    "not a fake unsigned payload",
                ));
            };
            self.push_effect(format!("sign:{label}"));
            let step = self
                .signs
                .lock()
                .expect("signs")
                .pop_front()
                .unwrap_or_else(|| panic!("unscripted sign of {label}"));
            let signed_transaction = [FAKE_SIGNED_PREFIX, label.as_bytes()].concat();
            let mut identity = Self::identity_of(&signed_transaction)?;
            match step {
                FakeSign::Ok => {}
                FakeSign::Fail(code) => {
                    return Err(StepFailure::new(code, "scripted sign failure"));
                }
                FakeSign::WrongIdentity => identity.signed_transaction_hash[0] ^= 0xFF,
                FakeSign::Interrupt => return self.interrupt().await,
            }
            self.labels
                .lock()
                .expect("labels")
                .insert(identity.signed_transaction_hash, label.to_owned());
            Ok(SignedStepTransaction {
                signed_transaction,
                identity,
            })
        })
    }

    fn identify(&self, signed_transaction: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        Self::identity_of(signed_transaction)
    }
}

impl WorkflowLedger for FakeWorkflowWorld {
    fn dispatch<'a>(
        &'a self,
        signed_transaction: &'a [u8],
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        Box::pin(async move {
            let label = self.label_of(identity);
            assert_eq!(
                Self::identity_of(signed_transaction).ok().as_ref(),
                Some(identity),
                "dispatched bytes must hash to the dispatched identity"
            );
            self.push_effect(format!("dispatch:{label}"));
            let step = self
                .dispatches
                .lock()
                .expect("dispatches")
                .pop_front()
                .unwrap_or_else(|| panic!("unscripted dispatch of {label}"));
            match step {
                FakeDispatch::Outcome(outcome) => outcome,
                FakeDispatch::Interrupt => self.interrupt().await,
            }
        })
    }

    fn committed_outcome<'a>(
        &'a self,
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        Box::pin(async move {
            let label = self.label_of(identity);
            self.push_effect(format!("status:{label}"));
            let step = self
                .statuses
                .lock()
                .expect("statuses")
                .pop_front()
                .unwrap_or_else(|| panic!("unscripted status read of {label}"));
            match step {
                FakeStatus::Outcome(outcome) => outcome,
                FakeStatus::Interrupt => self.interrupt().await,
            }
        })
    }
}

/// Poll `future` to completion, or return `None` when the world was interrupted.
///
/// An interruption models a process that stops inside an external call: the
/// future is dropped at that await point and nothing after it runs.
///
/// # Panics
/// Panics when the future suspends without an interruption; the fake world never does.
pub fn run_until_interrupted<T>(
    world: &FakeWorkflowWorld,
    future: impl Future<Output = T>,
) -> Option<T> {
    let mut future = std::pin::pin!(future);
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => {
            assert!(
                world.take_interrupted(),
                "the fake world suspends only on a scripted interruption"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn world() -> FakeWorkflowWorld {
        FakeWorkflowWorld::new(WorkflowBindingV1 {
            network: "net".to_owned(),
            authority: "alice".to_owned(),
        })
    }

    #[test]
    fn fake_world_signs_dispatches_and_reads_in_scripted_order() {
        let world = world();
        world.script(
            vec![FakeSign::Ok],
            vec![FakeDispatch::Outcome(DispatchOutcome::Accepted)],
            vec![FakeStatus::Outcome(CommittedOutcome::ExactAbsence)],
        );
        assert_eq!(world.unconsumed(), 3);
        let payload = FakeWorkflowWorld::payload("0#1");
        let signed = run_until_interrupted(&world, world.sign(&payload))
            .expect("not interrupted")
            .expect("signed");
        assert_eq!(signed.signed_transaction, b"signed:0#1");
        assert_eq!(
            world.identify(&signed.signed_transaction),
            Ok(signed.identity)
        );
        assert_eq!(
            run_until_interrupted(
                &world,
                world.dispatch(&signed.signed_transaction, &signed.identity)
            ),
            Some(DispatchOutcome::Accepted)
        );
        assert_eq!(
            run_until_interrupted(&world, world.committed_outcome(&signed.identity)),
            Some(CommittedOutcome::ExactAbsence)
        );
        run_until_interrupted(&world, world.sleep(Duration::from_millis(250)));
        assert_eq!(world.now_unix_ms(), 1_000_250);
        world.push_effect("extra");
        assert_eq!(
            world.take_trace(),
            [
                "sign:0#1",
                "dispatch:0#1",
                "status:0#1",
                "sleep:250",
                "extra"
            ]
        );
        assert_eq!(format!("{:?}", world.effect_hook), "HookSlot");
        assert_eq!(world.unconsumed(), 0);
        assert_eq!(world.binding().authority, "alice");
        assert_ne!(fixture_digest("a"), fixture_digest("b"));
    }

    #[test]
    fn the_effect_hook_runs_inside_the_external_call_and_may_append_effects() {
        let world = Arc::new(world());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let hook: EffectHook = {
            let seen = Arc::clone(&seen);
            let world = Arc::downgrade(&world);
            Arc::new(move |effect: &str| {
                seen.lock().expect("seen").push(effect.to_owned());
                // Another actor acts while the dispatch is in flight.
                if effect.starts_with("dispatch:") {
                    world
                        .upgrade()
                        .expect("world")
                        .push_effect("concurrent:act");
                }
            })
        };
        world.set_effect_hook(Some(hook));
        world.script(
            vec![FakeSign::Ok],
            vec![FakeDispatch::Outcome(DispatchOutcome::Accepted)],
            Vec::new(),
        );
        let payload = FakeWorkflowWorld::payload("0#1");
        let signed = run_until_interrupted(&world, world.sign(&payload))
            .expect("not interrupted")
            .expect("signed");
        run_until_interrupted(
            &world,
            world.dispatch(&signed.signed_transaction, &signed.identity),
        )
        .expect("not interrupted");
        // The other actor's effect is recorded after the dispatch started.
        assert_eq!(
            world.take_trace(),
            ["sign:0#1", "dispatch:0#1", "concurrent:act"]
        );
        assert_eq!(
            *seen.lock().expect("seen"),
            ["sign:0#1", "dispatch:0#1", "concurrent:act"]
        );
        world.set_effect_hook(None);
        world.push_effect("quiet");
        assert_eq!(seen.lock().expect("seen").len(), 3);
    }

    #[test]
    fn fake_world_reports_scripted_failures_and_interruptions() {
        let world = world();
        world.script(
            vec![
                FakeSign::Fail(WorkflowErrorCode::AuthorizationDenied),
                FakeSign::WrongIdentity,
                FakeSign::Interrupt,
            ],
            vec![FakeDispatch::Interrupt],
            vec![FakeStatus::Interrupt],
        );
        let payload = FakeWorkflowWorld::payload("1#1");
        assert_eq!(
            run_until_interrupted(&world, world.sign(&payload))
                .expect("not interrupted")
                .expect_err("scripted failure")
                .code,
            WorkflowErrorCode::AuthorizationDenied
        );
        let wrong = run_until_interrupted(&world, world.sign(&payload))
            .expect("not interrupted")
            .expect("signed");
        assert_ne!(
            world.identify(&wrong.signed_transaction),
            Ok(wrong.identity)
        );
        assert!(run_until_interrupted(&world, world.sign(&payload)).is_none());
        assert!(!world.take_interrupted(), "the mark is cleared once read");

        let identity = world.identify(b"signed:1#1").expect("identity");
        assert!(run_until_interrupted(&world, world.dispatch(b"signed:1#1", &identity)).is_none());
        assert!(run_until_interrupted(&world, world.committed_outcome(&identity)).is_none());
        assert_eq!(
            world
                .identify(b"not-signed")
                .expect_err("foreign bytes")
                .code,
            WorkflowErrorCode::NonCanonicalEncoding
        );
        assert_eq!(
            run_until_interrupted(&world, world.sign(b"not-a-payload"))
                .expect("not interrupted")
                .expect_err("foreign payload")
                .code,
            WorkflowErrorCode::NonCanonicalEncoding
        );
    }
}
