//! Allocation-free local storage attempts retaining original capacity release owners.

use crate::execution_attempt::{ExecutionAttemptError as Attempt, ExecutionDeferred};
use iroha_allocation::ChargedBufferError;
use iroha_primitives::erasure::rs16::compact::CodecAllocationError;
use iroha_sumeragi::{availability::RestorationError, message::ByteAdmissionError};
use std::io;

pub(super) fn byte(error: ByteAdmissionError) -> Attempt<io::Error> {
    match error {
        ByteAdmissionError::Buffer(error) => buffer(error),
        ByteAdmissionError::ControlAdmission(refusal) => Attempt::Deferred(refusal.into()),
        ByteAdmissionError::ControlAllocation(_) => allocator(),
        error => io::Error::new(io::ErrorKind::InvalidData, error).into(),
    }
}
pub(super) fn buffer(error: ChargedBufferError) -> Attempt<io::Error> {
    match error {
        ChargedBufferError::Admission(refusal) => Attempt::Deferred(refusal.into()),
        ChargedBufferError::Allocator { .. } => allocator(),
    }
}
fn allocator() -> Attempt<io::Error> {
    Attempt::Deferred(ivm::error::ExecutionDeferral::AllocationUnavailable.into())
}
pub(super) fn restoration(error: RestorationError) -> Attempt<io::Error> {
    match error {
        RestorationError::Bytes(error) => byte(error),
        RestorationError::Codec(CodecAllocationError::Admission(refusal)) => {
            Attempt::Deferred(refusal.into())
        }
        RestorationError::Codec(CodecAllocationError::Allocation(_)) => allocator(),
        error => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("availability restoration: {error:?}"),
        )
        .into(),
    }
}
pub(super) fn take_deferred(error: Attempt<io::Error>) -> Result<ExecutionDeferred, io::Error> {
    match error {
        Attempt::Deferred(owner) => Ok(owner),
        Attempt::Rejected(error) => Err(error),
    }
}

/// Project progress only after the original source-bearing job has retained this refusal.
pub(super) fn retained_io(
    error: Attempt<io::Error>,
    owner: &mut Option<ExecutionDeferred>,
) -> io::Error {
    match error {
        Attempt::Deferred(reason) => {
            *owner = Some(reason);
            io::ErrorKind::WouldBlock.into()
        }
        Attempt::Rejected(error) => {
            *owner = None;
            error
        }
    }
}

#[cfg(test)]
mod tests {
    //! Actual original-pool refusals survive every storage adapter and allocation-free projection.
    use super::*;
    use iroha_allocation::AllocationBudget;

    #[test]
    fn original_pool_refusal_survives_byte_restoration_and_retained_io() {
        let budget = AllocationBudget::new(1);
        let held = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let errors = [
            byte(ByteAdmissionError::Buffer(ChargedBufferError::Admission(
                refusal.clone(),
            ))),
            byte(ByteAdmissionError::ControlAdmission(refusal.clone())),
            restoration(RestorationError::Codec(CodecAllocationError::Admission(
                refusal.clone(),
            ))),
        ];
        let mut retained = None;
        for error in errors {
            let projected = retained_io(error, &mut retained);
            assert_eq!(projected.kind(), io::ErrorKind::WouldBlock);
            assert!(projected.get_ref().is_none());
            assert_eq!(
                retained.as_ref().unwrap().allocation_refusal(),
                Some(&refusal)
            );
            assert_eq!(budget.reserved_bytes(), 1);
        }
        drop(held);
        let retry = budget.try_reserve_bytes(1).unwrap();
        assert_eq!(budget.reserved_bytes(), 1);
        drop(retry);
        assert_eq!(budget.reserved_bytes(), 0);
        let completed = retained_io(
            io::Error::from(io::ErrorKind::InvalidData).into(),
            &mut retained,
        );
        assert_eq!(completed.kind(), io::ErrorKind::InvalidData);
        assert!(retained.is_none());
    }

    #[test]
    fn terminal_byte_identity_and_physical_refusal_remain_distinct() {
        let error = byte(ByteAdmissionError::ForeignBudget);
        assert!(matches!(error, Attempt::Rejected(_)));
        let Attempt::Deferred(owner) = allocator() else {
            panic!("physical refusal")
        };
        assert_eq!(
            owner.reason(),
            ivm::error::ExecutionDeferral::AllocationUnavailable
        );
        assert!(owner.allocation_refusal().is_none());
    }
}
