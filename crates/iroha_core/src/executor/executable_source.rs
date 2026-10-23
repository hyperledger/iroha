//! Borrowed dispatch view of the original signed executable.
//!
//! Every body retains its source owner. The view grants no invocation custody,
//! admission, proof acceptance or permission; those have separate typed owners.

use iroha_data_model::{
    isi::InstructionBox,
    transaction::{
        Executable, ExecutableBatchItem,
        executable::{ContractInvocation, IvmBytecode},
    },
};

/// Dispatch input retaining the original signed objects in every execution mode.
pub(super) enum Body<'source> {
    /// Direct native instructions.
    Instructions(&'source [InstructionBox]),
    /// The previously verified replay remains a separate owner.
    IvmProved,
    /// One contract invocation.
    ContractCall(&'source ContractInvocation),
    /// Ordered native and contract items.
    Batch(&'source [ExecutableBatchItem]),
    /// Raw IVM code.
    Ivm(&'source IvmBytecode),
}

impl<'source> Body<'source> {
    /// Retain references to the actual signed executable without cloning it.
    pub(super) fn original(executable: &'source Executable) -> Self {
        match executable {
            Executable::Instructions(instructions) => Self::Instructions(instructions.as_ref()),
            Executable::IvmProved(_) => Self::IvmProved,
            Executable::ContractCall(call) => Self::ContractCall(call),
            Executable::Batch(items) => Self::Batch(items.as_ref()),
            Executable::Ivm(bytes) => Self::Ivm(bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{Level, isi::Log};

    fn instruction() -> InstructionBox {
        Log::new(Level::INFO, "original source".into()).into()
    }

    #[test]
    fn original_body_and_items_preserve_actual_instruction_address() {
        let executable = Executable::Instructions(vec![instruction()].into());
        let Executable::Instructions(original) = &executable else {
            unreachable!()
        };
        let Body::Instructions(items) = Body::original(&executable) else {
            unreachable!()
        };
        let mut items = items.iter();
        let Some(item) = items.next() else {
            panic!("original instruction disappeared")
        };
        assert!(std::ptr::eq(item, &original[0]));
        assert!(items.next().is_none());
    }

    #[test]
    fn owned_body_storage_is_borrowed_without_copying_items() {
        let executable = Executable::Instructions(vec![instruction()].into());
        let Body::Instructions(items) = Body::original(&executable) else {
            unreachable!()
        };
        let mut items = items.iter();
        assert!(items.next().is_some());
        assert!(items.next().is_none());
        let Executable::Instructions(original) = &executable else {
            unreachable!()
        };
        let Body::Instructions(borrowed) = Body::original(&executable) else {
            unreachable!()
        };
        assert!(std::ptr::eq(borrowed.as_ptr(), original.as_ptr()));
    }

    #[test]
    fn original_batch_split_preserves_actual_instruction_address() {
        let executable =
            Executable::Batch(vec![ExecutableBatchItem::Instruction(instruction())].into());
        let Executable::Batch(original) = &executable else {
            unreachable!()
        };
        let ExecutableBatchItem::Instruction(expected) = &original[0] else {
            unreachable!()
        };
        let Body::Batch(items) = Body::original(&executable) else {
            unreachable!()
        };
        let ExecutableBatchItem::Instruction(actual) = items.first().unwrap() else {
            panic!("original batch instruction disappeared")
        };
        assert!(std::ptr::eq(actual, expected));
    }

    #[test]
    fn owned_batch_storage_is_borrowed_without_copying_items() {
        let executable =
            Executable::Batch(vec![ExecutableBatchItem::Instruction(instruction())].into());
        let Body::Batch(items) = Body::original(&executable) else {
            unreachable!()
        };
        assert!(matches!(
            items.first().unwrap(),
            ExecutableBatchItem::Instruction(_)
        ));
        let Executable::Batch(original) = &executable else {
            unreachable!()
        };
        assert!(std::ptr::eq(items.as_ptr(), original.as_ptr()));
    }
}
