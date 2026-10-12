//! Native history production under the request's original complete memory owner.
//!
//! A byte counter is not an allocation permit. This module joins the existing query-pool
//! reservation to one cumulative native codec context and one original cold-frame pool. Every
//! clone shares those same owners. Synchronous scopes restore thread state before returning;
//! no native allocation scope survives an await or moves to an unrelated request.

use std::cell::RefCell;
#[cfg(test)]
use std::sync::Arc;

use iroha_allocation::{AllocationBudget, ChargedShared};
use norito::{DecodeLimits, core::DecodeBudgetContext};

use crate::{Error, QueryAdmissionPermit, QueryFanoutMemoryEnvelope, QueryFanoutMemoryReservation};

fn capacity() -> Error {
    crate::native_projection_response::capacity()
}

/// The producer phases are created only by the original query-pool acquisition.
pub(crate) struct ProducerBudget {
    envelope: QueryFanoutMemoryEnvelope,
    pool_generation: u64,
    cold_frames: AllocationBudget,
    /// Physical response-wrapper layouts occupy the remaining encoder corridor. They grant
    /// neither decoder credit nor source admission, and all clones keep this original pool.
    response_metadata: AllocationBudget,
    allocations: DecodeBudgetContext,
}

impl ProducerBudget {
    pub(crate) fn response_metadata(&self) -> &AllocationBudget {
        &self.response_metadata
    }
    /// Derive corridors from an already admitted envelope, never a configured or response cap.
    pub(crate) fn from_admitted(
        envelope: QueryFanoutMemoryEnvelope,
        pool_generation: u64,
    ) -> Result<ChargedShared<Self>, Error> {
        // History retains one raw source, cumulative native block/result graphs, compact selected
        // rows and cursor scratch, then the exact response. Request representations and their
        // decode phase stay outside this corridor. Counting allocations cumulatively is stricter
        // than live-byte accounting: freeing a traversed ancestor does not reset this allowance.
        // Both inline and evicted cold frames charge this same cumulative counter before
        // their physical frame-pool allocation. Do not count that sub-pool a second time.
        // Keep the independently retained request bytes and input decode phase, native
        // wrapper/control corridor, and existing fixed allowance outside this grant.
        // Their sum plus this cumulative grant is exactly the actual admitted W, even
        // for signed fanout envelopes whose phase is larger than prebody admission.
        // A prebody owner has not measured Q/E yet: request_bytes == 0 reserves
        // the original seven signed plus one verified representation, rather than
        // asserting no request retention. The shared prebody denominator already
        // admits precisely this floor. Measured envelopes retain their exact bytes.
        let retained_request = if envelope.request_bytes == 0 {
            envelope
                .request_decode_allocated_bytes
                .checked_mul(
                    crate::QUERY_FANOUT_SIGNED_REQUEST_REPRESENTATIONS
                        + crate::QUERY_FANOUT_VERIFIED_REQUEST_REPRESENTATIONS,
                )
                .ok_or_else(capacity)?
        } else {
            envelope.request_bytes
        };
        let allocated = envelope
            .working_set_bytes
            .checked_sub(retained_request)
            .and_then(|bytes| bytes.checked_sub(envelope.request_decode_allocated_bytes))
            .and_then(|bytes| bytes.checked_sub(envelope.candidate_encoded_bytes))
            .and_then(|bytes| bytes.checked_sub(crate::query_fanout_fixed_overhead_bytes()?))
            .filter(|bytes| *bytes >= envelope.final_body_bytes)
            .ok_or_else(capacity)?;
        let response_metadata = AllocationBudget::new(envelope.candidate_encoded_bytes);
        let allocations = DecodeBudgetContext::try_new_owned(
            DecodeLimits::new(
                envelope.decode_allocated_bytes,
                envelope.route_body_bytes,
                allocated,
                allocated,
                norito::core::MAX_VALUE_NESTING_DEPTH,
            ),
            &response_metadata,
        )
        .map_err(|_| capacity())?;
        let mut reservation = response_metadata
            .try_reserve(ChargedShared::<Self>::allocation_layout())
            .map_err(|_| capacity())?;
        let budget = Self {
            envelope,
            pool_generation,
            cold_frames: AllocationBudget::new(envelope.route_body_bytes),
            response_metadata,
            allocations,
        };
        ChargedShared::from_reservation(budget, &mut reservation).map_err(|_| capacity())
    }
}

/// Closed capability retaining both actual admission and its unchanged producer corridors.
#[derive(Clone)]
pub(crate) struct HistoryProducerOwner {
    // Reclaim all native producer controls before the last query lease releases credit.
    budget: ChargedShared<ProducerBudget>,
    reservation: QueryFanoutMemoryReservation,
}

thread_local! {
    static PHYSICAL_HISTORY_OWNER: RefCell<Option<HistoryProducerOwner>> = const {
        RefCell::new(None)
    };
}

impl HistoryProducerOwner {
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        let working = 48 * 1024 * 1024;
        let pool = crate::ByteWeightedMemoryPool::new(working).unwrap();
        let reservation = QueryFanoutMemoryReservation::from_admitted_fanout(
            pool.try_acquire_parts([working as u64]).unwrap(),
            QueryFanoutMemoryEnvelope::for_body_admission(working).unwrap(),
            pool.generation(),
        )
        .unwrap();
        Self::from_reservation(&reservation).unwrap()
    }
    /// Capture the admitted producer before moving the request into a physical worker.
    pub(crate) fn from_admission(admission: &QueryAdmissionPermit) -> Result<Self, Error> {
        Self::from_reservation(admission._fanout_memory.as_ref().ok_or_else(capacity)?)
    }

    /// Response-only tokens and a different admission generation cannot grant production.
    pub(crate) fn from_reservation(
        reservation: &QueryFanoutMemoryReservation,
    ) -> Result<Self, Error> {
        let admitted = reservation.admission.ok_or_else(capacity)?;
        let budget = reservation.producer.as_ref().ok_or_else(capacity)?;
        if budget.envelope != admitted.envelope
            || budget.pool_generation != admitted.pool_generation
        {
            return Err(capacity());
        }
        Ok(Self {
            reservation: reservation.clone(),
            budget: budget.clone(),
        })
    }

    /// Borrow only the retained physical or asynchronous request capability.
    /// Asynchronous lookup supplies data; it never installs a native thread scope.
    pub(crate) fn current() -> Result<Self, Error> {
        Self::current_if_admitted()?.ok_or_else(capacity)
    }

    /// Distinguish an explicitly standalone engine from a present but invalid admission.
    /// A failed query owner must never select a standalone serialization path.
    pub(crate) fn current_if_admitted() -> Result<Option<Self>, Error> {
        if let Some(owner) = PHYSICAL_HISTORY_OWNER.with(|current| current.borrow().clone()) {
            return Ok(Some(owner));
        }
        #[cfg(feature = "app_api")]
        if let Ok(owner) =
            crate::COLLECTION_READ_MEMORY_RESERVATION.try_with(Self::from_reservation)
        {
            return owner.map(Some);
        }
        if let Ok(owner) = crate::APP_ROUTED_READ_HTTP_ADMISSION
            .try_with(|admission| Self::from_reservation(&admission.reservation))
        {
            return owner.map(Some);
        }
        Ok(None)
    }

    /// Retain one cumulative context across all synchronous source and projection phases.
    pub(crate) fn scope<R>(&self, work: impl FnOnce() -> R) -> R {
        struct Restore(Option<HistoryProducerOwner>);
        impl Drop for Restore {
            fn drop(&mut self) {
                PHYSICAL_HISTORY_OWNER.with(|current| {
                    *current.borrow_mut() = self.0.take();
                });
            }
        }
        let _restore = Restore(
            PHYSICAL_HISTORY_OWNER.with(|current| current.borrow_mut().replace(self.clone())),
        );
        self.budget.allocations.with(work)
    }

    /// Exact native backing pool used by cold canonical frame and shared shell allocation.
    pub(crate) fn cold_frames(&self) -> &AllocationBudget {
        &self.budget.cold_frames
    }

    /// Share the same physical and cumulative owners with Core's canonical cold reader.
    pub(crate) fn canonical_history_budget(&self) -> iroha_core::state::CanonicalHistoryReadBudget {
        iroha_core::state::CanonicalHistoryReadBudget::new(
            self.budget.cold_frames.clone(),
            self.budget.allocations.clone(),
        )
    }

    pub(crate) fn response_metadata(&self) -> &AllocationBudget {
        &self.budget.response_metadata
    }

    /// Borrow the original cumulative codec owner for synchronous authorization reads.
    pub(crate) fn allocation_context(&self) -> &DecodeBudgetContext {
        &self.budget.allocations
    }

    /// Reuse matching physical admission or acquire one actual transient authorization owner.
    /// A present invalid or foreign-generation token is a refusal, never a standalone grant.
    pub(crate) fn authentication_read(app: &crate::SharedAppState) -> Result<Self, Error> {
        if let Some(owner) = Self::current_if_admitted()? {
            if owner.budget.pool_generation != app.query_fanout_inflight.generation()
                || owner.budget.envelope.working_set_bytes != app.query_fanout_working_set_bytes
            {
                return Err(capacity());
            }
            return Ok(owner);
        }
        let reservation =
            crate::try_acquire_new_query_fanout_memory(app).map_err(|_| capacity())?;
        Self::from_reservation(&reservation)
    }

    /// Compact row and cursor backing may not borrow the decoded-graph corridor.
    pub(crate) fn retained_bytes(&self) -> usize {
        self.budget.envelope.accumulator_retained_bytes
    }

    /// The final body remains inside the existing response corridor.
    pub(crate) fn response_bytes(&self) -> usize {
        self.budget.envelope.final_body_bytes
    }

    /// Preserve the same real permit until the last response byte is dropped.
    pub(crate) fn response(&self, response: axum::response::Response) -> axum::response::Response {
        crate::hold_query_fanout_memory_in_response_body(response, self.reservation.clone())
    }

    /// Admit exact native collection backing before allocation, without geometric overgrowth.
    pub(crate) fn selected<T>(&self, count: usize) -> Result<Vec<T>, Error> {
        let bytes = std::alloc::Layout::array::<T>(count)
            .map_err(|_| capacity())?
            .size();
        if bytes > self.retained_bytes() {
            return Err(capacity());
        }
        self.scope(|| norito::core::reserve_decode_allocation(bytes))
            .map_err(|_| capacity())?;
        crate::torii_routed_read_exact_vec(count, "history selected records", bytes)
            .map_err(|_| capacity())
    }

    /// Encode a borrowed projection under the unchanged cumulative owner.
    pub(crate) fn json<T: norito::json::JsonSerialize + ?Sized>(
        &self,
        payload: &T,
    ) -> Result<axum::response::Response, Error> {
        self.json_with_limit(payload, self.response_bytes())
    }

    /// Keep a stricter selected-source phase without replacing the actual query owner.
    pub(crate) fn json_with_limit<T: norito::json::JsonSerialize + ?Sized>(
        &self,
        payload: &T,
        limit: usize,
    ) -> Result<axum::response::Response, Error> {
        let encoded = self
            .scope(|| {
                norito::json::to_json_bounded_boxed(payload, limit.min(self.response_bytes()))
            })
            .map_err(|_| capacity())?;
        let bytes = crate::response_memory_custody::owned(encoded, self).map_err(|_| capacity())?;
        crate::response_memory_custody::json(bytes, self).map_err(|_| capacity())
    }

    /// Stream one single-line canonical JSON event into exact native response backing.
    /// The returned data owns this same complete query reservation through its last slice.
    pub(crate) fn sse_data<T: norito::json::JsonSerialize + ?Sized>(
        &self,
        payload: &T,
    ) -> Result<axum::body::Bytes, Error> {
        struct Event<'a, T: ?Sized>(&'a T);
        impl<T: norito::json::JsonSerialize + ?Sized> norito::json::FastJsonWrite for Event<'_, T> {
            fn write_json(&self, out: &mut String) {
                norito::json::write_json_unbounded(self, out);
            }
            fn write_json_to(
                &self,
                out: &mut dyn norito::json::JsonWriteSink,
            ) -> Result<(), norito::json::BoundedJsonError> {
                out.push_str("data: ")?;
                self.0.json_serialize_to(out)?;
                out.push_str("\n\n")
            }
        }
        let encoded = self
            .scope(|| norito::json::to_json_bounded_boxed(&Event(payload), self.response_bytes()))
            .map_err(|_| capacity())?;
        crate::response_memory_custody::owned(encoded, self).map_err(|_| capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(bytes: usize) -> HistoryProducerOwner {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let envelope = QueryFanoutMemoryEnvelope::for_body_admission(bytes).unwrap();
        let reservation = QueryFanoutMemoryReservation::from_admitted_fanout(
            semaphore.try_acquire_owned().unwrap(),
            envelope,
            7,
        )
        .unwrap();
        HistoryProducerOwner::from_reservation(&reservation).unwrap()
    }

    #[test]
    fn native_history_counters_are_cumulative_across_physical_scopes() {
        let owner = owner(48 * 1024 * 1024);
        let amount = owner.response_bytes();
        owner
            .scope(|| norito::core::reserve_decode_allocation(amount))
            .unwrap();
        let first = owner.budget.allocations.consumed_allocated_bytes();
        owner
            .clone()
            .scope(|| norito::core::reserve_decode_allocation(amount))
            .unwrap();
        assert_eq!(
            owner.budget.allocations.consumed_allocated_bytes(),
            first + amount as u64
        );
        let mut refused = false;
        for _ in 0..16 {
            if owner
                .scope(|| norito::core::reserve_decode_allocation(amount))
                .is_err()
            {
                refused = true;
                break;
            }
        }
        assert!(
            refused,
            "separate cold reads must not reset allocation credit"
        );
        assert!(
            HistoryProducerOwner::current().is_err(),
            "physical scope must be restored"
        );
    }

    #[test]
    fn native_history_refuses_response_only_and_foreign_generation_tokens() {
        let permit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        assert!(
            HistoryProducerOwner::from_reservation(&QueryFanoutMemoryReservation::new(permit))
                .is_err()
        );
        let mut original = owner(48 * 1024 * 1024).reservation;
        original.admission.as_mut().unwrap().pool_generation += 1;
        assert!(HistoryProducerOwner::from_reservation(&original).is_err());
    }

    #[test]
    fn native_history_scope_restores_after_panic_and_isolates_requests() {
        let first = owner(48 * 1024 * 1024);
        let second = owner(48 * 1024 * 1024);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            first.scope(|| {
                norito::core::reserve_decode_allocation(1024).unwrap();
                panic!("physical worker interrupted");
            })
        }));
        assert!(HistoryProducerOwner::current().is_err());
        assert_eq!(second.budget.allocations.consumed_allocated_bytes(), 0);
        assert_eq!(first.budget.allocations.consumed_allocated_bytes(), 1024);
    }

    #[test]
    fn native_history_unknown_prebody_request_retains_all_original_request_phases() {
        let owner = owner(48_000_000);
        let envelope = owner.budget.envelope;
        let retained_request = envelope.request_decode_allocated_bytes
            * (crate::QUERY_FANOUT_SIGNED_REQUEST_REPRESENTATIONS
                + crate::QUERY_FANOUT_VERIFIED_REQUEST_REPRESENTATIONS);
        let grant = envelope.working_set_bytes
            - crate::query_fanout_fixed_overhead_bytes().unwrap()
            - retained_request
            - envelope.request_decode_allocated_bytes
            - envelope.candidate_encoded_bytes;
        owner
            .scope(|| norito::core::reserve_decode_allocation(grant))
            .unwrap();
        assert!(
            owner
                .scope(|| norito::core::reserve_decode_allocation(1))
                .is_err()
        );
        assert_eq!(
            owner.budget.allocations.consumed_allocated_bytes(),
            grant as u64
        );
        assert_eq!(
            retained_request
                + envelope.request_decode_allocated_bytes
                + envelope.candidate_encoded_bytes
                + grant
                + crate::query_fanout_fixed_overhead_bytes().unwrap(),
            envelope.working_set_bytes
        );
    }

    #[tokio::test]
    async fn detached_history_worker_installs_the_real_owner_and_retains_returned_sse_bytes() {
        let working = 48_000_000;
        let pool = crate::ByteWeightedMemoryPool::new(working).unwrap();
        let reservation = QueryFanoutMemoryReservation::from_admitted_fanout(
            pool.try_acquire_parts([working as u64]).unwrap(),
            QueryFanoutMemoryEnvelope::for_body_admission(working).unwrap(),
            pool.generation(),
        )
        .unwrap();
        let query = Arc::new(tokio::sync::Semaphore::new(1));
        let admission = QueryAdmissionPermit {
            _query: query.try_acquire_owned().unwrap(),
            _heavy: None,
            _body: None,
            _fanout_memory: Some(reservation),
        };
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let (finished, output) = tokio::sync::oneshot::channel();
        let request = tokio::spawn(crate::routing::run_admitted_blocking(
            admission,
            "owned history test worker failed",
            move || {
                let owner = HistoryProducerOwner::current()?;
                started.send(()).unwrap();
                held.recv().unwrap();
                let bytes = owner.sse_data(&17_u64)?;
                finished.send(bytes).unwrap();
                Ok(())
            },
        ));
        entered.await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(pool.try_acquire_parts([working as u64]).is_none());
        release.send(()).unwrap();
        let bytes = output.await.unwrap();
        assert_eq!(bytes.as_ref(), b"data: 17\n\n");
        let clone = bytes.clone();
        drop(bytes);
        assert!(pool.try_acquire_parts([working as u64]).is_none());
        drop(clone);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if pool.try_acquire_parts([working as u64]).is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("physical worker must release the original complete owner");
        assert!(HistoryProducerOwner::current().is_err());
    }
}
