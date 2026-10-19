//! Retained destination copy of the actual native parent acquisition's QC input.
//!
//! This shares its existing paid block control without copying the decoded graph.
//! The certificate input's nested allocation remains a separate funding obligation.
//! Native receipt, authority and proposal verification precedes preparation and every lend.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    block::SharedSignedBlock,
    consensus::{NposParentServiceCommitQc, PreparedParentServiceCommitQc},
};

#[derive(Default)]
pub(super) struct ParentServiceCopyPreparation {
    original: Option<SharedSignedBlock>,
    pending: Option<PreparedParentServiceCommitQc>,
    complete: Option<NposParentServiceCommitQc>,
}
impl ParentServiceCopyPreparation {
    fn check(
        &self,
        parent: &SharedSignedBlock,
        pool: &AllocationBudget,
    ) -> Result<(), ParentServiceError> {
        if !parent.belongs_to(pool)
            || !self.original.as_ref().is_some_and(|original| {
                original.belongs_to(pool) && SharedSignedBlock::ptr_eq(original, parent)
            })
        {
            return Err(parent_source_failure(
                "producer copy replaced its original native parent or pool",
            ));
        }
        Ok(())
    }
    pub(super) fn prepare(
        &mut self,
        parent: &SharedSignedBlock,
        pool: &AllocationBudget,
    ) -> Result<(), ParentServiceError> {
        if self.original.is_none() {
            if !parent.belongs_to(pool) {
                return Err(parent_source_failure(
                    "producer parent has a foreign original pool",
                ));
            }
            self.original = Some(parent.clone());
        }
        self.check(parent, pool)?;
        if self.complete.is_some() {
            return Ok(());
        }
        if self.pending.is_none() {
            let bytes = parent
                .commit_certificate()
                .ok_or_else(|| parent_source_failure("producer parent has no certificate"))?
                .commit_qc()
                .len();
            query_scratch_admission(bytes).map_err(ParentServiceError::Deferred)?;
            // Installing this infallibly inspected continuation records successful logical
            // admission. Later physical retries reuse it without charging the copy again.
            self.pending = Some(
                PreparedParentServiceCommitQc::from_parent(parent, pool).map_err(custody_error)?,
            );
        }
        #[cfg(test)]
        admission_probe(
            pool,
            self.pending
                .as_ref()
                .expect("original copy continuation")
                .allocation_layouts()
                .map_err(|original| ParentServiceError::Deferred(original.into()))?,
        );
        let result = self
            .pending
            .as_mut()
            .expect("original copy continuation")
            .prepare_parent(parent, pool);
        #[cfg(all(test, sumeragi_core_mutation = "HC464"))]
        if result.is_err() {
            self.pending = None;
        }
        result.map_err(custody_error)?;
        let pending = self.pending.take().expect("complete original copy");
        match pending.finish_parent(parent, pool) {
            Ok(value) => self.complete = Some(value),
            Err((pending, error)) => {
                self.pending = Some(pending);
                return Err(custody_error(error));
            }
        }
        Ok(())
    }
    pub(super) fn get(
        &self,
        parent: &SharedSignedBlock,
        pool: &AllocationBudget,
    ) -> Result<NposParentServiceCommitQc, ParentServiceError> {
        self.check(parent, pool)?;
        self.complete
            .as_ref()
            .filter(|value| value.admitted_to(pool))
            .cloned()
            .ok_or_else(|| parent_source_failure("producer copy is incomplete"))
    }
}

fn custody_error(
    error: iroha_data_model::consensus::ParentServiceCustodyError,
) -> ParentServiceError {
    // The existing field-5 transport preserves the same concrete capacity, allocator,
    // canonical and source causes. This is classification only, not another decoder.
    match crate::execution_attempt::prepared_signature_block_attempt_error(
        iroha_data_model::block::PreparedSignatureBlockError::ParentService(error),
        |reason| reason,
    ) {
        ExecutionAttemptError::Deferred(original) => ParentServiceError::Deferred(original),
        ExecutionAttemptError::Rejected(reason) => parent_source_failure(reason),
    }
}

#[cfg(test)]
thread_local! {
    static ADMISSION_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce(&AllocationBudget, [std::alloc::Layout; 2])>>> = const { std::cell::RefCell::new(None) };
}
/// One observer at the actual copy admission; no refusal is synthesized.
#[cfg(test)]
pub(crate) struct ParentServiceCopyAdmissionProbe;
#[cfg(test)]
impl Drop for ParentServiceCopyAdmissionProbe {
    fn drop(&mut self) {
        ADMISSION_PROBE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
/// Observe original demand so controls may occupy genuine original-pool credit.
#[cfg(test)]
pub(crate) fn observe_parent_service_copy_admission(
    observer: impl FnOnce(&AllocationBudget, [std::alloc::Layout; 2]) + 'static,
) -> ParentServiceCopyAdmissionProbe {
    ADMISSION_PROBE.with(|slot| {
        assert!(slot.borrow().is_none(), "one producer copy observer");
        *slot.borrow_mut() = Some(Box::new(observer));
    });
    ParentServiceCopyAdmissionProbe
}
#[cfg(test)]
fn admission_probe(pool: &AllocationBudget, layouts: [std::alloc::Layout; 2]) {
    let observer = ADMISSION_PROBE.with(|slot| slot.borrow_mut().take());
    if let Some(observer) = observer {
        observer(pool, layouts);
    }
}
#[cfg(test)]
mod tests;
