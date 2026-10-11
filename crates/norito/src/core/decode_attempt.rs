//! Original decode-budget provenance at a synchronous canonical admission boundary.

use super::{ActiveDecodeBudgetLayer, CounterOwner, DecodeResourceError, Error, budget_scope};
use std::cell::RefCell;

// The counter context can be reused or sent to another thread. Mint an
// allocation-free process identity for every observer boundary, independently
// of that context's counters and prepared-workspace attempt number. Exhaustion
// never wraps: a later boundary cannot establish resource provenance.
static LAST_BOUNDARY: super::AtomicU64 = super::AtomicU64::new(0);

fn next_boundary(sequence: &super::AtomicU64) -> Option<u64> {
    if cfg!(all(test, sumeragi_norito_mutation = "NC3")) {
        return Some(
            sequence
                .fetch_add(1, super::Ordering::Relaxed)
                .wrapping_add(1),
        );
    }
    sequence
        .fetch_update(
            super::Ordering::Relaxed,
            super::Ordering::Relaxed,
            |current| current.checked_add(1),
        )
        .ok()
        .map(|previous| previous + 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BoundaryIdentity {
    root: u64,
    boundary: u64,
}

impl BoundaryIdentity {
    fn contains(self, origin: Self) -> bool {
        if cfg!(all(test, sumeragi_norito_mutation = "NC2")) {
            return true;
        }
        self.root == origin.root && self.boundary <= origin.boundary
    }
}

#[derive(Clone, Debug)]
struct BudgetFamily {
    counters: CounterOwner,
    attempt: u64,
}
impl BudgetFamily {
    fn same(&self, other: &Self) -> bool {
        self.attempt == other.attempt && self.counters.ptr_eq(&other.counters)
    }
}

#[derive(Clone)]
struct Observer {
    boundary: usize,
    protocol_start: usize,
    family: Option<BudgetFamily>,
    identity: Option<BoundaryIdentity>,
}

thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
}

struct Scope {
    previous: Option<Observer>,
}

impl Scope {
    fn enter() -> Self {
        let boundary = budget_scope::with_active(|layers| layers.len());
        let previous = OBSERVER.with(|slot| {
            let previous = slot.borrow_mut().take();
            let identity = next_boundary(&LAST_BOUNDARY).and_then(|boundary| {
                let root = match previous.as_ref() {
                    Some(parent) => parent.identity?.root,
                    None => boundary,
                };
                Some(BoundaryIdentity { root, boundary })
            });
            *slot.borrow_mut() = Some(Observer {
                boundary,
                protocol_start: previous
                    .as_ref()
                    .map_or(boundary, |value| value.protocol_start),
                family: previous.as_ref().and_then(|value| value.family.clone()),
                identity,
            });
            previous
        });
        Self { previous }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        OBSERVER.with(|slot| {
            let current = slot.borrow_mut().take();
            if let Some(previous) = self.previous.as_mut()
                && previous.family.is_none()
            {
                previous.family = current.and_then(|value| value.family);
            }
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

/// Error origin established by one completed canonical decode attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeAttemptErrorKind {
    /// An actual native allocation failed; no allocation-pool release owner exists here.
    Allocator,
    /// The original attempt's enclosing admission budget refused the operation.
    EnclosingLimit,
    /// Invalid bytes, a protocol limit, or an error without current-attempt provenance.
    Invalid,
}

/// A canonical decoder error with its original non-wire resource classification.
#[derive(Debug)]
pub struct DecodeAttemptError {
    error: Error,
    kind: DecodeAttemptErrorKind,
}

impl DecodeAttemptError {
    /// Return the origin established before the decoder's observer scope unwound.
    #[must_use]
    pub const fn kind(&self) -> DecodeAttemptErrorKind {
        self.kind
    }

    /// Return the original error, retaining any opaque scope provenance for an outer attempt.
    #[must_use]
    pub fn into_error(self) -> Error {
        self.error
    }
}

impl std::fmt::Display for DecodeAttemptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for DecodeAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Exact resource refusal emitted by a budget layer during canonical admission.
///
/// Construction is private to the budget owner. Reconstructing [`Error`] from
/// [`DecodeResourceError`] does not reconstruct this original scope identity.
#[derive(Clone, Debug)]
pub struct ScopedDecodeResourceError {
    resource: DecodeResourceError,
    family: BudgetFamily,
    layer: usize,
    protocol_start: usize,
    identity: BoundaryIdentity,
}

impl PartialEq for ScopedDecodeResourceError {
    fn eq(&self, other: &Self) -> bool {
        self.resource == other.resource
            && self.family.same(&other.family)
            && self.layer == other.layer
            && self.protocol_start == other.protocol_start
            && self.identity == other.identity
    }
}

impl Eq for ScopedDecodeResourceError {}

impl ScopedDecodeResourceError {
    pub(super) const fn resource(&self) -> DecodeResourceError {
        self.resource
    }

    pub(super) fn matches_enclosing_scope(&self) -> bool {
        self.layer < self.protocol_start
            && OBSERVER.with(|slot| {
                slot.borrow().as_ref().is_some_and(|observer| {
                    observer
                        .identity
                        .is_some_and(|identity| identity.contains(self.identity))
                        && observer
                            .family
                            .as_ref()
                            .is_some_and(|family| family.same(&self.family))
                        && self.layer < observer.boundary
                })
            })
    }
}

impl std::fmt::Display for ScopedDecodeResourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.resource, formatter)
    }
}

impl std::error::Error for ScopedDecodeResourceError {}

pub(super) fn note_fresh_budget(counters: &CounterOwner) {
    OBSERVER.with(|slot| {
        if let Some(observer) = slot.borrow_mut().as_mut()
            && observer.family.is_none()
        {
            observer.family = Some(BudgetFamily {
                counters: counters.clone(),
                attempt: counters.attempt.load(super::Ordering::Relaxed),
            });
        }
    });
}

pub(super) fn layers_in_order<'a>(
    layers: budget_scope::BudgetLayers<'a>,
) -> impl Iterator<Item = (usize, &'a ActiveDecodeBudgetLayer)> {
    let split = OBSERVER.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(0, |observer| observer.protocol_start.min(layers.len()))
    });
    layers
        .iter()
        .enumerate()
        .skip(split)
        .chain(layers.iter().enumerate().take(split))
}

pub(super) fn budget_error(layer: usize, counters: &CounterOwner, error: Error) -> Error {
    let Some(resource) = error.decode_resource_error() else {
        return error;
    };
    OBSERVER.with(|slot| {
        let mut observer = slot.borrow_mut();
        let Some(observer) = observer.as_mut() else {
            return error;
        };
        let Some(identity) = observer.identity else {
            return error;
        };
        // A direct JSON parser/writer may use only an already-active caller
        // context. Its real budget check supplies the original owner here;
        // an injected or reconstructed error cannot initialize this family.
        if cfg!(all(test, sumeragi_norito_mutation = "NC1")) && observer.family.is_none() {
            return error;
        }
        let family = observer.family.get_or_insert_with(|| BudgetFamily {
            counters: counters.clone(),
            attempt: counters.attempt.load(super::Ordering::Relaxed),
        });
        Error::ScopedDecodeResource(ScopedDecodeResourceError {
            resource,
            family: family.clone(),
            layer,
            protocol_start: observer.protocol_start,
            identity,
        })
    })
}

/// Run a synchronous decoder and its canonical authentication under one admission observer.
///
/// Protocol-owned decode limits belong inside `decode`; caller-owned limits enclose this
/// call. The original decoder resource identity is captured before those scopes unwind.
/// This does not invent an allocation-pool wake source or classify reconstructed errors.
/// Direct parsers and checked writers preserve the same enclosing provenance as framed
/// decoders. If the process exhausts its non-repeating observer identities, subsequent
/// budget-layer errors fail classification closed as [`DecodeAttemptErrorKind::Invalid`].
pub fn classify_decode_attempt<T>(
    decode: impl FnOnce() -> Result<T, Error>,
) -> Result<T, DecodeAttemptError> {
    observe(|| decode().map_err(capture))
}

pub(super) fn observe<R>(body: impl FnOnce() -> R) -> R {
    let _scope = Scope::enter();
    body()
}

pub(super) fn capture(error: Error) -> DecodeAttemptError {
    let kind = match &error {
        Error::AllocationFailed { .. } => DecodeAttemptErrorKind::Allocator,
        Error::ScopedDecodeResource(origin) => OBSERVER.with(|slot| {
            let observer = slot.borrow();
            let observer = observer
                .as_ref()
                .expect("original observer remains in scope");
            if observer
                .identity
                .is_some_and(|identity| identity.contains(origin.identity))
                && observer
                    .family
                    .as_ref()
                    .is_some_and(|family| family.same(&origin.family))
                && origin.layer < observer.boundary
                && origin.layer < origin.protocol_start
            {
                DecodeAttemptErrorKind::EnclosingLimit
            } else {
                DecodeAttemptErrorKind::Invalid
            }
        }),
        _ => DecodeAttemptErrorKind::Invalid,
    };
    DecodeAttemptError { error, kind }
}

#[cfg(test)]
mod tests;
