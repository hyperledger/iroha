//! Retained semantic parent-service QC over the already admitted immutable byte owner.
//!
//! This source-bound owner grants no signature, quorum or State authority. Those checks
//! remain with the original native parent relation after complete canonical preparation.
//! The adjacent signer owner retains the authenticated participation output separately.
//! The adjacent producer copy owner funds new bytes; native-body nested decoding and
//! the enclosing evidence graph remain separate funding obligations.
use super::*;
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedShared};
use iroha_sumeragi::qc_custody::{NativeQc, PreparedQc, QcCustodyError, QcFieldError};
use norito::core::{PreparedDecodeError, PreparedDecodeScopeError, SequenceSpan};

/// One proposal's retained original semantic QC, reusable only for the same source and pool.
#[derive(Default)]
pub(crate) struct ParentServiceQcPreparation {
    original: Option<(
        HashOf<IrohaHeader>,
        ChargedShared<ChargedBuffer<u8>>,
        AllocationBudget,
    )>,
    pending: Option<PreparedQc<'static>>,
    complete: Option<NativeQc<'static>>,
}
impl ParentServiceQcPreparation {
    fn require_original(
        &self,
        proposal: &SignedBlock,
        pool: &AllocationBudget,
    ) -> Result<&ChargedShared<ChargedBuffer<u8>>, ParentServiceError> {
        let offered = proposal
            .npos_consensus_effects()
            .and_then(|effects| effects.parent_service_commit_qc.as_ref())
            .and_then(|offered| offered.admitted_source())
            .ok_or_else(|| {
                parent_source_failure("parent-service QC has no admitted original source")
            })?;
        let (hash, original, budget) = self
            .original
            .as_ref()
            .ok_or_else(|| parent_source_failure("parent-service QC preparation is absent"))?;
        if *hash != proposal.hash()
            || !ChargedShared::ptr_eq(original, offered)
            || !pool.same_pool(budget)
            || !offered.belongs_to(pool)
            || !ChargedBuffer::belongs_to(offered, pool)
        {
            return Err(parent_source_failure(
                "parent-service QC replaced its original proposal, source or pool",
            ));
        }
        Ok(original)
    }
    /// Retain the exact source before paid decoder admission and resume its original fields.
    pub(crate) fn prepare(
        &mut self,
        proposal: &SignedBlock,
        pool: &AllocationBudget,
    ) -> Result<(), ParentServiceError> {
        if self.original.is_none() {
            let offered = proposal
                .npos_consensus_effects()
                .and_then(|effects| effects.parent_service_commit_qc.as_ref())
                .and_then(|offered| offered.admitted_source())
                .filter(|source| source.belongs_to(pool) && ChargedBuffer::belongs_to(source, pool))
                .ok_or_else(|| {
                    parent_source_failure("parent-service QC has no admitted original source")
                })?;
            self.original = Some((proposal.hash(), offered.clone(), pool.clone()));
        }
        let source = self.require_original(proposal, pool)?.clone();
        if self.complete.is_some() {
            return Ok(());
        }
        let span = SequenceSpan {
            start: 0,
            end: source.as_slice().len(),
        };
        if self.pending.is_none() {
            self.pending =
                Some(PreparedQc::new_shared(source.clone(), span, pool).map_err(custody_error)?);
        }
        #[cfg(test)]
        admission_probe(&source, pool);
        let prepared = self
            .pending
            .as_mut()
            .expect("original semantic QC decoder")
            .prepare_shared(
                &source,
                span,
                norito::canonical_decode_limits(source.as_slice().len()),
            );
        #[cfg(all(test, sumeragi_core_mutation = "HC462"))]
        if prepared.is_err() {
            self.pending = None;
            self.original = None;
        }
        prepared.map_err(custody_error)?;
        let pending = self
            .pending
            .take()
            .expect("completed original semantic QC decoder");
        match pending.finish() {
            Ok(complete) => self.complete = Some(complete),
            Err((pending, error)) => {
                self.pending = Some(pending);
                return Err(custody_error(error));
            }
        }
        Ok(())
    }
    /// Borrow complete canonical fields only after the same original source is rechecked.
    pub(crate) fn get(
        &self,
        proposal: &SignedBlock,
        pool: &AllocationBudget,
    ) -> Result<&Qc, ParentServiceError> {
        self.require_original(proposal, pool)?;
        self.complete
            .as_ref()
            .filter(|qc| qc.belongs_to(pool))
            .map(NativeQc::get)
            .ok_or_else(|| {
                parent_source_failure("parent-service semantic QC preparation is incomplete")
            })
    }
    #[cfg(test)]
    pub(super) fn retained_pointers(&self) -> (usize, usize) {
        (
            self.original
                .as_ref()
                .map_or(0, |(_, source, _)| source.as_slice().as_ptr().addr()),
            self.complete
                .as_ref()
                .map_or(0, |qc| qc.get().signers.as_bytes().as_ptr().addr()),
        )
    }
}

/// Preserve actual source/pool/decoder refusal before any diagnostic formatting.
fn custody_error(error: QcCustodyError) -> ParentServiceError {
    use iroha_allocation::{
        AllocatorRefusal, ChargedBufferError, ChargedBufferFromChargeError, PrepaidSharedError,
    };
    if cfg!(all(test, sumeragi_core_mutation = "HC463")) {
        return ParentServiceError::Deferred(
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into(),
        );
    }
    match error {
        QcCustodyError::Admission(original)
        | QcCustodyError::Decode(PreparedDecodeError::Destination(QcFieldError::Bitmap(
            ChargedBufferError::Admission(original),
        ))) => ParentServiceError::Deferred(original.into()),
        QcCustodyError::Decode(PreparedDecodeError::Codec(original)) => {
            parent_proof_decode_failure(original)
        }
        QcCustodyError::Decode(PreparedDecodeError::Destination(QcFieldError::Bitmap(
            original @ ChargedBufferError::Allocator { .. },
        ))) => ParentServiceError::Deferred(
            AllocatorRefusal::try_from(original)
                .expect("matched original allocator refusal")
                .into(),
        ),
        QcCustodyError::Decode(PreparedDecodeError::Scope(
            PreparedDecodeScopeError::Allocation(original @ PrepaidSharedError::Allocator { .. }),
        )) => ParentServiceError::Deferred(
            AllocatorRefusal::try_from(original)
                .expect("matched original allocator refusal")
                .into(),
        ),
        QcCustodyError::LedgerBacking(
            original @ ChargedBufferFromChargeError::Allocator { .. },
        )
        | QcCustodyError::Decode(PreparedDecodeError::Destination(QcFieldError::BitmapBacking(
            original @ ChargedBufferFromChargeError::Allocator { .. },
        ))) => ParentServiceError::Deferred(
            AllocatorRefusal::try_from(original)
                .expect("matched original allocator refusal")
                .into(),
        ),
        QcCustodyError::ControlBacking(
            original @ iroha_allocation::SharedFromChargeError::Allocator { .. },
        ) => ParentServiceError::Deferred(
            AllocatorRefusal::try_from(original)
                .expect("matched original shared allocator refusal")
                .into(),
        ),
        QcCustodyError::Structural(original) => ParentServiceError::Invalid(original.to_string()),
        invariant => parent_source_failure(invariant),
    }
}

/// Initial component-fixture admission through the existing complete model decoder.
/// Production proposals arrive through the retained signed-RS16 worker owner instead.
#[cfg(any(test, feature = "iroha-core-tests", feature = "bench"))]
pub(crate) fn admit_parent_service_fixture(
    proposal: &mut SignedBlock,
    pool: &AllocationBudget,
) -> Result<(), ParentServiceError> {
    use iroha_data_model::block::PreparedSignedBlockSignaturesDecode;
    if proposal
        .npos_consensus_effects()
        .and_then(|effects| effects.parent_service_commit_qc.as_ref())
        .is_some_and(|source| source.admitted_to(pool))
    {
        return Ok(());
    }
    let wire = proposal
        .encode_wire()
        .map_err(|error| ParentServiceError::Invalid(error.to_string()))?;
    let mut source = ChargedBuffer::new(wire.len(), pool).map_err(|error| match error {
        iroha_allocation::ChargedBufferError::Admission(original) => {
            ParentServiceError::Deferred(original.into())
        }
        original @ iroha_allocation::ChargedBufferError::Allocator { .. } => {
            ParentServiceError::Deferred(
                iroha_allocation::AllocatorRefusal::try_from(original)
                    .expect("original fixture allocation refusal")
                    .into(),
            )
        }
    })?;
    for byte in wire {
        source.push_reserved(byte);
    }
    let classify = |error| match crate::execution_attempt::prepared_signature_block_attempt_error(
        error,
        |reason| reason,
    ) {
        ExecutionAttemptError::Deferred(original) => ParentServiceError::Deferred(original),
        ExecutionAttemptError::Rejected(reason) => parent_source_failure(reason),
    };
    let mut prepared = PreparedSignedBlockSignaturesDecode::new(pool).map_err(classify)?;
    let decoded = prepared
        .decode(
            &source,
            SequenceSpan {
                start: 0,
                end: source.as_slice().len(),
            },
            norito::canonical_decode_limits(source.as_slice().len()),
        )
        .map_err(classify)?;
    *proposal = decoded;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static ADMISSION_PROBE: std::cell::RefCell<Option<Box<dyn FnOnce(&ChargedShared<ChargedBuffer<u8>>, &AllocationBudget)>>> = const { std::cell::RefCell::new(None) };
}
/// Observe the actual paid-control/bitmap admission boundary without supplying a refusal.
#[cfg(test)]
pub(crate) struct ParentServiceQcAdmissionProbe;
#[cfg(test)]
impl Drop for ParentServiceQcAdmissionProbe {
    fn drop(&mut self) {
        ADMISSION_PROBE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
/// Register one read-only observer; a test may occupy real credit in the original pool.
#[cfg(test)]
pub(crate) fn observe_parent_service_qc_admission(
    observer: impl FnOnce(&ChargedShared<ChargedBuffer<u8>>, &AllocationBudget) + 'static,
) -> ParentServiceQcAdmissionProbe {
    ADMISSION_PROBE.with(|slot| {
        assert!(slot.borrow().is_none(), "one original semantic QC observer");
        *slot.borrow_mut() = Some(Box::new(observer));
    });
    ParentServiceQcAdmissionProbe
}
#[cfg(test)]
fn admission_probe(source: &ChargedShared<ChargedBuffer<u8>>, pool: &AllocationBudget) {
    let observer = ADMISSION_PROBE.with(|slot| slot.borrow_mut().take());
    if let Some(observer) = observer {
        observer(source, pool);
    }
}

#[cfg(test)]
mod tests;
