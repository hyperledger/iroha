//! Process-local identity of one installed native prover instance (D6a).
//!
//! A fold owner may keep a session's verified preparation between fold calls
//! and resume it later. Such state is bound to the exact prover instance that
//! prepared it. The identity is an allocation, never a value: it is not
//! serialized, hashed, compared by content, exported over FFI or built from
//! bytes or flags, and two instances with identical installed artifacts are
//! still different instances.
//!
//! A bound value keeps its owner's allocation alive, so no later instance can
//! reuse that address while the value exists. Route, wallet and durable-input
//! binding belong to the retention owner's key; this module only guarantees
//! that a resumed session runs on the prover whose `prepare` verified it.

use std::sync::Arc;

/// Zero-sized marker; only the address of its allocation is meaningful.
struct ProverIdentityV1;

/// The identity owned by exactly one native prover instance.
///
/// `Clone` deliberately allocates a fresh identity: a cloned prover is another
/// instance, so state retained from one never resumes on the other.
pub(super) struct ProverInstanceV1(Arc<ProverIdentityV1>);

/// A value released only to the prover instance that bound it.
///
/// Deliberately not `Clone`: one retained state resumes at most once, and the
/// session it resumes into remains the only continuation of the original one.
pub(super) struct BoundV1<T> {
    identity: Arc<ProverIdentityV1>,
    value: T,
}

impl ProverInstanceV1 {
    /// Allocate the identity of a newly constructed prover instance.
    pub(super) fn fresh() -> Self {
        Self(Arc::new(ProverIdentityV1))
    }

    /// Bind `value` to this instance. Nothing is copied or verified here.
    pub(super) fn bind<T>(&self, value: T) -> BoundV1<T> {
        BoundV1 {
            identity: Arc::clone(&self.0),
            value,
        }
    }

    /// Release a bound value only to the instance that bound it.
    ///
    /// # Errors
    /// The value was bound by another instance, including a clone of this one
    /// or an instance built from identical artifacts. The bound value is
    /// returned unchanged so the caller decides to drop it.
    pub(super) fn admit<T>(&self, bound: BoundV1<T>) -> Result<T, BoundV1<T>> {
        if Arc::ptr_eq(&self.0, &bound.identity) {
            Ok(bound.value)
        } else {
            Err(bound)
        }
    }
}

impl Clone for ProverInstanceV1 {
    fn clone(&self) -> Self {
        Self::fresh()
    }
}

#[cfg(test)]
mod tests;
