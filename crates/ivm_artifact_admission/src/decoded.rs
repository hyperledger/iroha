//! Temporary instruction storage owned by its original admission pool.

use super::{ContractArtifactError, MAX_CONTRACT_IMAGE_BYTES, VMError};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};

/// One fixed-width decoded instruction in the executable stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedOp {
    /// Byte offset within the executable instruction stream.
    pub pc: u64,
    /// Exact little-endian instruction word.
    pub inst: u32,
}

pub enum Instructions {
    Diagnostic(Vec<DecodedOp>),
    Funded(ChargedBuffer<DecodedOp>),
}

impl std::ops::Deref for Instructions {
    type Target = [DecodedOp];
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Diagnostic(values) => values,
            Self::Funded(values) => values.as_slice(),
        }
    }
}

pub fn instructions(
    code: &[u8],
    budget: Option<&AllocationBudget>,
) -> Result<Instructions, ContractArtifactError> {
    let Some(budget) = budget else {
        return super::decode_instruction_stream(code).map(Instructions::Diagnostic);
    };
    if code.len() as u64 > MAX_CONTRACT_IMAGE_BYTES || !code.len().is_multiple_of(4) {
        return Err(ContractArtifactError::invalid(
            "instruction decode failed for executable stream: decode error",
        ));
    }
    let mut decoded = ChargedBuffer::new(code.len() / 4, budget).map_err(|error| {
        let error = match error {
            ChargedBufferError::Admission(error) => VMError::AllocationDeferred(error),
            ChargedBufferError::Allocator { .. } => {
                VMError::ExecutionDeferred(ivm_abi::error::ExecutionDeferral::AllocationUnavailable)
            }
        };
        ContractArtifactError::preparation("instruction admission", error)
    })?;
    for (index, bytes) in code.chunks_exact(4).enumerate() {
        decoded.push_reserved(DecodedOp {
            pc: (index as u64) * 4,
            inst: u32::from_le_bytes(bytes.try_into().expect("four-byte instruction")),
        });
    }
    Ok(Instructions::Funded(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_allocation::AllocationRefusal;

    #[test]
    fn funded_decode_refuses_the_original_pool_and_retries_exact_backing() {
        let code = [0x11_u32, 0x2233]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let bytes = 2 * std::mem::size_of::<DecodedOp>();
        let budget = AllocationBudget::new(0);
        let error = instructions(&code, Some(&budget)).err().unwrap();
        assert!(
            matches!(error.try_into_local_vm_error(), Ok(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes: 0 }
        )) if requested_bytes == bytes)
        );
        assert_eq!(budget.peak_reserved_bytes(), 0);
        budget.set_limit_bytes(bytes);
        let occupied = budget.try_reserve_bytes(bytes).unwrap();
        let error = instructions(&code, Some(&budget)).err().unwrap();
        assert!(matches!(
            error.into_vm_error(),
            VMError::AllocationDeferred(AllocationRefusal::Capacity { .. })
        ));
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(occupied);
        let decoded = instructions(&code, Some(&budget)).unwrap();
        let diagnostic = instructions(&code, None).unwrap();
        assert_eq!(&*decoded, &*diagnostic);
        assert_eq!(budget.reserved_bytes(), bytes);
        budget.set_limit_bytes(0);
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(decoded);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn malformed_words_refuse_before_funding_and_empty_streams_need_no_credit() {
        let budget = AllocationBudget::new(0);
        for length in [1, 2, 3, 5, 6, 7] {
            let code = vec![0; length];
            let error = instructions(&code, Some(&budget)).err().unwrap();
            assert_eq!(
                error.to_string(),
                instructions(&code, None).err().unwrap().to_string()
            );
            assert!(!error.is_local_deferral());
            assert_eq!(budget.peak_reserved_bytes(), 0);
        }
        assert!(instructions(&[], Some(&budget)).unwrap().is_empty());
        assert_eq!(budget.peak_reserved_bytes(), 0);
    }
}
