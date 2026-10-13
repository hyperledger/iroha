//! Observe real producer custody and temporarily occupy only its original State pool.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal, AllocationReservation};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::signer_operation::stream_token::native) enum Point {
    Body,
    Encoded,
}
#[derive(Debug, PartialEq, Eq)]
struct Identity {
    request: usize,
    request_bytes: Vec<u8>,
    deadline: Instant,
    check_pointer: usize,
    check_bytes: Vec<u8>,
    reply: Option<(usize, Vec<u8>, [u8; 64])>,
}
impl Identity {
    fn of(attempt: &CompletedObservation<'_>) -> Self {
        Self {
            request: std::ptr::from_ref(attempt.request) as usize,
            request_bytes: attempt.request.encode_canonical().unwrap(),
            deadline: attempt.deadline,
            check_pointer: attempt.check.canonical_external().as_ptr() as usize,
            check_bytes: attempt.check.canonical_external().to_vec(),
            reply: match attempt.stage.as_ref().unwrap() {
                Stage::Encoded { signed, reply } => {
                    let bytes = reply.completed_observation().unwrap();
                    Some((bytes.as_ptr() as usize, bytes.to_vec(), signed.signature))
                }
                _ => None,
            },
        }
    }
}
#[derive(Default)]
pub(in crate::signer_operation::stream_token::native) struct Audit {
    pub(in crate::signer_operation::stream_token::native) refusals: usize,
    pub(in crate::signer_operation::stream_token::native) signatures: usize,
    pub(in crate::signer_operation::stream_token::native) reply: Option<(usize, Vec<u8>)>,
    pub(in crate::signer_operation::stream_token::native) check_bytes: Vec<u8>,
    pub(in crate::signer_operation::stream_token::native) deadline: Option<Instant>,
}
struct Probe {
    point: Option<Point>,
    original: AllocationBudget,
    held: Option<AllocationReservation>,
    identity: Option<Identity>,
    audit: Audit,
}
thread_local! { static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) }; }

pub(in crate::signer_operation::stream_token::native) fn measure<T>(
    original: AllocationBudget,
    point: Option<Point>,
    action: impl FnOnce() -> T,
) -> (T, Audit) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            PROBE.with_borrow_mut(|slot| *slot = None);
        }
    }

    PROBE.with_borrow_mut(|slot| {
        assert!(slot.is_none(), "one native observation probe");
        *slot = Some(Probe {
            point,
            original,
            held: None,
            identity: None,
            audit: Audit::default(),
        });
    });
    let reset = Reset;
    let result = action();
    let probe = PROBE.with_borrow_mut(|slot| slot.take().unwrap());
    assert!(
        probe.held.is_none(),
        "the actual refusal must retire the test pressure owner"
    );
    drop(reset);
    (result, probe.audit)
}

pub(super) fn before_advance(attempt: &CompletedObservation<'_>) {
    PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return;
        };
        let point = match attempt.stage.as_ref().unwrap() {
            Stage::Body => Point::Body,
            Stage::Encoded { .. } => Point::Encoded,
            _ => return,
        };
        if Some(point) != probe.point {
            return;
        }
        let identity = Identity::of(attempt);
        if let Some(original) = &probe.identity {
            assert_eq!(
                &identity, original,
                "same original Check, request, signature, reply and deadline"
            );
            return;
        }
        let budget = attempt.observer.source.state.ivm_execution_budget();
        assert!(budget.same_pool(&probe.original));
        probe.audit.deadline = Some(identity.deadline);
        probe.audit.check_bytes = identity.check_bytes.clone();
        probe.audit.reply = identity
            .reply
            .as_ref()
            .map(|(pointer, bytes, _)| (*pointer, bytes.clone()));
        probe.identity = Some(identity);
        probe.held = Some(
            budget
                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                .unwrap(),
        );
        assert!(probe.held.as_ref().unwrap().belongs_to(&probe.original));
    });
}
pub(super) fn refused(attempt: &CompletedObservation<'_>, error: &AttemptError) {
    PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return;
        };
        assert_eq!(Some(&Identity::of(attempt)), probe.identity.as_ref());
        let AttemptError::Native(ExecutionAttemptError::Deferred(original)) = error else {
            panic!("actual original native floor read must refuse locally");
        };
        assert!(matches!(
            original.allocation_refusal(),
            Some(AllocationRefusal::Capacity { .. })
        ));
        assert!(
            attempt
                .observer
                .source
                .state
                .ivm_execution_budget()
                .same_pool(&probe.original)
        );
        probe.audit.refusals += 1;
        assert_eq!(probe.audit.refusals, 1);
        drop(probe.held.take());
    });
}
pub(super) fn signed_observation() {
    PROBE.with_borrow_mut(|slot| {
        if let Some(probe) = slot {
            probe.audit.signatures += 1;
        }
    });
}
