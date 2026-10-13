//! Move-only register logger scopes and before-effects event batch credit.
//!
//! TLS retains only inline counters and strong handles to the original logger.
//! Outermost admission leaves the TLS borrow before reserving through that
//! logger; nested work partitions already admitted credit. Callback masks and
//! repeated installation of the same logger move its quota, never duplicate it.
//! A different VM suspends the original invocation with its quota intact.

use super::{RegEvent, SharedRegLog};
use crate::VMError;
use std::{cell::RefCell, marker::PhantomData, rc::Rc};

#[derive(Default)]
enum Quota {
    #[default]
    Idle,
    Preparing(u64),
    Ready {
        id: u64,
        remaining: usize,
    },
}

struct State {
    log: Option<SharedRegLog>,
    logging_enabled: bool,
    quota: Quota,
}

#[derive(Default)]
struct Local {
    state: Option<State>,
    next_batch: u64,
}

thread_local! {
    static LOGGER: RefCell<Local> = const {
        RefCell::new(Local { state: None, next_batch: 0 })
    };
}

fn same_log(left: Option<&SharedRegLog>, right: Option<&SharedRegLog>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => SharedRegLog::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

/// Restore invocation identity and its unique event quota on the same thread.
pub(crate) struct RegLoggerGuard {
    previous: Option<State>,
    transfer_quota: bool,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl RegLoggerGuard {
    /// Select a new invocation or explicitly untraced invocation. Reinstalling
    /// the same logger retains its existing quota rather than making new credit.
    pub(crate) fn install(log: Option<SharedRegLog>) -> Self {
        let logging_enabled = log.is_some();
        let (previous, transfer_quota) = LOGGER.with(|slot| {
            let mut local = slot.borrow_mut();
            let mut previous = local.state.take();
            let transfer = previous
                .as_ref()
                .is_some_and(|state| same_log(state.log.as_ref(), log.as_ref()));
            let quota = if transfer {
                std::mem::take(&mut previous.as_mut().expect("original scope").quota)
            } else {
                Quota::Idle
            };
            local.state = Some(State {
                log,
                logging_enabled,
                quota,
            });
            (previous, transfer)
        });
        Self {
            previous,
            transfer_quota,
            _not_send_or_sync: PhantomData,
        }
    }

    /// Suppress event emission without losing fixed invocation trace policy,
    /// original logger identity, active batch identity or unused quota.
    pub(crate) fn mask() -> Self {
        let previous = LOGGER.with(|slot| {
            let mut local = slot.borrow_mut();
            let mut previous = local.state.take();
            local.state = previous.as_mut().map(|state| State {
                log: state.log.clone(),
                logging_enabled: false,
                quota: std::mem::take(&mut state.quota),
            });
            previous
        });
        let transfer_quota = previous.is_some();
        Self {
            previous,
            transfer_quota,
            _not_send_or_sync: PhantomData,
        }
    }
}

impl Drop for RegLoggerGuard {
    fn drop(&mut self) {
        let mut previous = self.previous.take();
        let (retired, valid) = LOGGER.with(|slot| {
            let mut local = slot.borrow_mut();
            let mut retired = local.state.take();
            let valid = if self.transfer_quota {
                match (&mut previous, &mut retired) {
                    (Some(previous), Some(retired))
                        if same_log(previous.log.as_ref(), retired.log.as_ref()) =>
                    {
                        previous.quota = std::mem::take(&mut retired.quota);
                        true
                    }
                    _ => false,
                }
            } else {
                true
            };
            local.state = previous;
            (retired, valid)
        });
        // A final original logger can notify callbacks; no TLS borrow survives.
        drop(retired);
        assert!(
            valid,
            "register logger scopes must retire in their original order"
        );
    }
}

/// Invocation trace policy remains fixed even while callbacks are masked.
pub(crate) fn scoped_reg_logger_enabled() -> Option<bool> {
    LOGGER.with(|slot| {
        slot.borrow()
            .state
            .as_ref()
            .map(|state| state.log.is_some())
    })
}

/// Borrow the original invocation identity irrespective of a callback mask.
pub(crate) fn scoped_reg_logger() -> Option<SharedRegLog> {
    LOGGER.with(|slot| {
        slot.borrow()
            .state
            .as_ref()
            .and_then(|state| state.log.clone())
    })
}

/// Obtain the original logger only if the current scope may emit an event.
pub(crate) fn event_reg_logger() -> Option<SharedRegLog> {
    LOGGER.with(|slot| {
        slot.borrow()
            .state
            .as_ref()
            .and_then(|state| state.logging_enabled.then(|| state.log.clone()).flatten())
    })
}

enum Parent {
    Outer,
    Nested { id: u64, remaining: usize },
}

struct ActiveBatch {
    log: SharedRegLog,
    id: u64,
    limit: usize,
    parent: Parent,
}

/// Keep the whole root, instruction or syscall subtree's admitted rows alive.
///
/// The instruction owner must outlive its delayed `native_finish_step` reads.
/// Nested guards spend only their parent's remaining credit; unused child rows
/// return to that same parent. Physical backing remains owned by the logger.
#[must_use = "retain the batch through every register observation in its subtree"]
pub(crate) struct RegEventBatch {
    active: Option<ActiveBatch>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl RegEventBatch {
    /// Admit an allocation-free public row bound before the first semantic effect.
    /// Allocation refusal is possible only at an outer boundary. Reentrant
    /// preparation and a child exceeding its parent are rejected before entry.
    pub(crate) fn begin(rows: usize) -> Result<Self, VMError> {
        let active = LOGGER.with(|slot| {
            let mut local = slot.borrow_mut();
            let Some(state) = local.state.as_ref().filter(|state| state.logging_enabled) else {
                return Ok(None);
            };
            let Some(log) = state.log.clone() else {
                return Ok(None);
            };
            match state.quota {
                Quota::Preparing(_) => return Err(VMError::HostUnavailable),
                Quota::Ready { remaining, .. } if rows > remaining => {
                    return Err(VMError::HostUnavailable);
                }
                _ => {}
            }
            let id = local
                .next_batch
                .checked_add(1)
                .ok_or(VMError::HostUnavailable)?;
            local.next_batch = id;
            let state = local.state.as_mut().expect("original enabled scope");
            let parent = match std::mem::take(&mut state.quota) {
                Quota::Idle => {
                    state.quota = Quota::Preparing(id);
                    Parent::Outer
                }
                Quota::Ready {
                    id: parent,
                    remaining,
                } => {
                    state.quota = Quota::Ready {
                        id,
                        remaining: rows,
                    };
                    Parent::Nested {
                        id: parent,
                        remaining: remaining - rows,
                    }
                }
                Quota::Preparing(_) => unreachable!("preparation refused before mutation"),
            };
            Ok(Some(ActiveBatch {
                log,
                id,
                limit: rows,
                parent,
            }))
        })?;
        let batch = Self {
            active,
            _not_send_or_sync: PhantomData,
        };
        if let Some(active) = &batch.active
            && matches!(active.parent, Parent::Outer)
        {
            // SharedRegLog enters the original refund scope,
            // acquire lock, prepare rows, drop lock, then drain callbacks. The
            // Preparing marker remains visible throughout those callbacks.
            active.log.prepare_events(rows)?;
            let valid = LOGGER.with(|slot| {
                let mut local = slot.borrow_mut();
                let Some(state) = &mut local.state else {
                    return false;
                };
                if same_log(state.log.as_ref(), Some(&active.log))
                    && matches!(state.quota, Quota::Preparing(id) if id == active.id)
                {
                    state.quota = Quota::Ready {
                        id: active.id,
                        remaining: rows,
                    };
                    true
                } else {
                    false
                }
            });
            assert!(
                valid,
                "row admission must restore the same original TLS invocation"
            );
        }
        Ok(batch)
    }
}

impl Drop for RegEventBatch {
    fn drop(&mut self) {
        let Some(active) = self.active.take() else {
            return;
        };
        let valid = LOGGER.with(|slot| {
            let mut local = slot.borrow_mut();
            let Some(state) = &mut local.state else {
                return false;
            };
            if !same_log(state.log.as_ref(), Some(&active.log)) {
                return false;
            }
            let remaining = match state.quota {
                Quota::Ready { id, remaining } if id == active.id && remaining <= active.limit => {
                    remaining
                }
                Quota::Preparing(id)
                    if id == active.id && matches!(active.parent, Parent::Outer) =>
                {
                    active.limit
                }
                _ => return false,
            };
            state.quota = match &active.parent {
                Parent::Outer => Quota::Idle,
                Parent::Nested {
                    id,
                    remaining: parent,
                } => Quota::Ready {
                    id: *id,
                    remaining: parent
                        .checked_add(remaining)
                        .expect("partitioned original row credit"),
                },
            };
            true
        });
        // Restore counters before the final retained handle can notify anyone.
        drop(active);
        assert!(
            valid,
            "register batches must retire within their original invocation"
        );
    }
}

/// Emit exactly one event from a previously admitted batch. The event builder
/// runs only for an enabled logger, after releasing TLS and before the logger
/// mutex. Fixed register Merkle paths require no fallible allocation here.
pub(crate) fn record_register_event(build: impl FnOnce() -> RegEvent) {
    let log = LOGGER.with(|slot| {
        let mut local = slot.borrow_mut();
        let state = local.state.as_mut().filter(|state| state.logging_enabled)?;
        let log = state.log.as_ref()?;
        let Quota::Ready { remaining, .. } = &mut state.quota else {
            panic!("register events require a before-effects batch");
        };
        *remaining = remaining
            .checked_sub(1)
            .expect("register event exceeds its admitted subtree");
        Some(log.clone())
    });
    if let Some(log) = log {
        let event = build();
        log.record_reserved(event);
    }
}

#[cfg(test)]
mod tests;
