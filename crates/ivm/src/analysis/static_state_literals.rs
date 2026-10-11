//! Borrowed pointer material for optional static-state key construction.
//!
//! Pointer envelopes and opaque Norito payloads stay in the original artifact.
//! One prepaid index borrows canonical Name/StatePath text; temporary NFC
//! allocations are admitted separately before validation and released afterward.

use iroha_model_base::{name::Name, state_path::StatePath};

use super::authenticated_literal_tlv_bytes;
use iroha_allocation::AllocationBudget;
mod text_index;
use crate::{
    PreparedContract, VMError,
    ivm::DecodedLiteral,
    pointer_abi::{PointerType, validate_tlv_bytes},
};
use text_index::TextIndex;

pub(super) trait LiteralSource {
    fn name(&self, index: usize) -> Option<&str>;
    fn path(&self, index: usize) -> Option<&str>;
    fn envelope(&self, index: usize) -> Option<&[u8]>;
    fn payload(&self, index: usize) -> Option<&[u8]>;
}

pub(super) struct PreparedLiterals<'a> {
    contract: &'a PreparedContract,
    text: TextIndex<'a>,
}
impl<'a> PreparedLiterals<'a> {
    pub(super) fn new(
        contract: &'a PreparedContract,
        budget: &AllocationBudget,
    ) -> Result<Self, VMError> {
        Ok(Self {
            contract,
            text: TextIndex::new(contract, budget)?,
        })
    }
}
impl LiteralSource for PreparedLiterals<'_> {
    fn name(&self, index: usize) -> Option<&str> {
        self.text.name(index)
    }
    fn path(&self, index: usize) -> Option<&str> {
        self.text.path(index)
    }
    fn envelope(&self, index: usize) -> Option<&[u8]> {
        let DecodedLiteral::Pointer(pointer) =
            self.contract.literal_table().entries().get(index)?
        else {
            return None;
        };
        authenticated_literal_tlv_bytes(self.contract, *pointer)
    }
    fn payload(&self, index: usize) -> Option<&[u8]> {
        let tlv = validate_tlv_bytes(self.envelope(index)?).ok()?;
        (tlv.type_id == PointerType::NoritoBytes).then_some(tlv.payload)
    }
}

#[cfg(test)]
pub(super) struct TestLiterals<'a> {
    pub(super) names: &'a [Option<&'a str>],
    pub(super) paths: &'a [Option<&'a str>],
    pub(super) envelopes: &'a [Option<&'a [u8]>],
    pub(super) payloads: &'a [Option<&'a [u8]>],
}
#[cfg(test)]
impl LiteralSource for TestLiterals<'_> {
    fn name(&self, index: usize) -> Option<&str> {
        self.names.get(index).copied().flatten()
    }
    fn path(&self, index: usize) -> Option<&str> {
        self.paths.get(index).copied().flatten()
    }
    fn envelope(&self, index: usize) -> Option<&[u8]> {
        self.envelopes.get(index).copied().flatten()
    }
    fn payload(&self, index: usize) -> Option<&[u8]> {
        self.payloads.get(index).copied().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_literal_views_keep_original_envelope_and_payload_addresses() {
        let bytes = kotodama_lang::compiler::Compiler::new().compile_source(
            "seiyaku BorrowedStateLiterals { permission CanWrite;  state StateMap<int, int> Values; kotoage fn write_one() authorize(CanWrite) { Values[1] = 10; } }",
        ).unwrap();
        let contract = crate::prepare_contract(std::sync::Arc::from(bytes.as_slice())).unwrap();
        let budget = AllocationBudget::new(1024 * 1024);
        let literals = PreparedLiterals::new(&contract, &budget).unwrap();
        let mut pointers = 0;
        let mut payloads = 0;
        let mut names = 0;
        for (index, literal) in contract.literal_table().entries().iter().enumerate() {
            match literal {
                DecodedLiteral::I64(_) => {
                    assert!(literals.envelope(index).is_none());
                    assert!(literals.payload(index).is_none());
                }
                DecodedLiteral::Pointer(pointer) => {
                    pointers += 1;
                    let envelope = literals.envelope(index).unwrap();
                    let original =
                        &contract.artifact()[contract.header_len() + *pointer as usize..];
                    assert_eq!(envelope.as_ptr(), original.as_ptr());
                    let tlv = validate_tlv_bytes(envelope).unwrap();
                    if tlv.type_id == PointerType::NoritoBytes {
                        payloads += 1;
                        let payload = literals.payload(index).unwrap();
                        assert_eq!(payload.as_ptr(), tlv.payload.as_ptr());
                        assert_eq!(payload, tlv.payload);
                    } else {
                        assert!(literals.payload(index).is_none());
                    }
                    if tlv.type_id == PointerType::Name {
                        names += 1;
                        let original: Name = norito::decode_canonical(tlv.payload).unwrap();
                        assert_eq!(literals.name(index), Some(original.as_ref()));
                    }
                }
            }
        }
        assert!(pointers > 0 && payloads > 0 && names > 0);
        assert!(literals.envelope(usize::MAX).is_none());
        assert!(literals.payload(usize::MAX).is_none());
        assert!(literals.name(usize::MAX).is_none());
        assert!(literals.path(usize::MAX).is_none());
    }
}
