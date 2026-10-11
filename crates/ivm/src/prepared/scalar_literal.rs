//! Borrow public scalar bits from the original admitted literal owner.

use super::PreparedContract;
use crate::ivm::DecodedLiteral;

impl PreparedContract {
    /// Return the exact public bits of one admitted `LDI64` literal.
    ///
    /// The canonical instruction carries a 16-bit literal index. Missing
    /// indexes and pointer-ABI literals return `None`; scalar bits never confer
    /// pointer provenance. This lookup neither allocates nor decodes or copies
    /// the literal table. Its original storage remains owned by this prepared
    /// contract, including after cache eviction or a resource-budget shrink.
    #[must_use]
    pub fn scalar_literal(&self, index: u16) -> Option<u64> {
        match self.inner.literal_table.entries().get(usize::from(index))? {
            DecodedLiteral::I64(bits) => Some(*bits),
            DecodedLiteral::Pointer(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{LITERAL_SECTION_MAGIC, LiteralKindV1, encode_literal_descriptor};
    use crate::{encoding::wide as enc, instruction::wide};
    use iroha_allocation::AllocationBudget;

    const VALUES: [u64; 5] = [0, 1, i64::MAX as u64, i64::MIN as u64, u64::MAX];

    fn artifact() -> Vec<u8> {
        let source = kotodama_lang::compiler::Compiler::new()
            .compile_source("seiyaku ScalarLiterals { view fn main() authorize(anyone) {} }")
            .unwrap();
        let original = crate::prepare_contract(source.into()).unwrap();
        let mut interface = original.contract_interface().clone();
        assert_eq!(interface.callables.len(), 1);
        assert_eq!(interface.entrypoints.len(), 1);
        interface.callables[0].entry_pc = 0;
        interface.callables[0].frame_bytes = 0;
        interface.entrypoints[0].entry_pc = 0;
        let mut pointer = (crate::pointer_abi::PointerType::Blob as u16)
            .to_be_bytes()
            .to_vec();
        pointer.push(1);
        pointer.extend(0_u32.to_be_bytes());
        pointer.extend(iroha_crypto::Hash::new([]).as_ref());
        let count = 1 + VALUES.len();
        let data_offset = 16 + count * 8;
        let data_bytes = pointer.len() + VALUES.len() * 8;
        let mut bytes = original.metadata().encode();
        bytes.extend(interface.encode_section());
        let padding =
            (4 - (bytes.len() - original.header_len() + data_offset + data_bytes) % 4) % 4;
        bytes.extend(LITERAL_SECTION_MAGIC);
        bytes.extend((count as u32).to_le_bytes());
        bytes.extend((padding as u32).to_le_bytes());
        bytes.extend((data_bytes as u32).to_le_bytes());
        bytes.extend(
            encode_literal_descriptor(LiteralKindV1::PointerTlv, data_offset as u64)
                .unwrap()
                .to_le_bytes(),
        );
        for index in 0..VALUES.len() {
            bytes.extend(
                encode_literal_descriptor(
                    LiteralKindV1::I64,
                    (data_offset + pointer.len() + index * 8) as u64,
                )
                .unwrap()
                .to_le_bytes(),
            );
        }
        bytes.extend(pointer);
        bytes.extend(VALUES.into_iter().flat_map(u64::to_le_bytes));
        bytes.resize(bytes.len() + padding, 0);
        // Pair this table with code naming its actual descriptor indexes and
        // kinds. The compiler's former body belongs to its former table and
        // cannot be retained after replacing that table.
        bytes.extend(enc::encode_literal(wide::memory::LDLIT, 7, 0).to_le_bytes());
        for index in 0..VALUES.len() {
            bytes.extend(
                enc::encode_literal(wide::memory::LDI64, 16 + index as u8, index as u16 + 1)
                    .to_le_bytes(),
            );
        }
        for word in [
            enc::encode_store(wide::memory::STORE64, 12, 0, 0),
            enc::encode_ri(wide::arithmetic::ADDI, 10, 12, 0),
            enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 1),
            enc::encode_rr(wide::control::JALR, 0, 1, 0),
        ] {
            bytes.extend(word.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn scalar_lookup_preserves_full_bits_and_rejects_pointer_or_missing_entries() {
        let prepared = crate::prepare_contract(artifact().into()).unwrap();
        assert_eq!(prepared.scalar_literal(0), None);
        for (index, value) in VALUES.into_iter().enumerate() {
            assert_eq!(prepared.scalar_literal(index as u16 + 1), Some(value));
        }
        assert_eq!(prepared.scalar_literal(VALUES.len() as u16 + 1), None);
        assert_eq!(prepared.scalar_literal(u16::MAX), None);
    }

    #[test]
    fn lookup_retains_the_original_literal_owner_after_shrink_and_final_borrow() {
        let budget = AllocationBudget::new(16 * 1024 * 1024);
        let original = crate::prepare_contract_with_memory_budget(&artifact(), &budget).unwrap();
        let borrower = original.clone();
        assert!(PreparedContract::ptr_eq(&original, &borrower));
        let charged = budget.reserved_bytes();
        let peak = budget.peak_reserved_bytes();
        assert!(charged > 0);
        budget.set_limit_bytes(0);
        drop(original);
        for (index, value) in VALUES.into_iter().enumerate() {
            assert_eq!(borrower.scalar_literal(index as u16 + 1), Some(value));
        }
        assert_eq!(borrower.scalar_literal(0), None);
        assert_eq!(budget.reserved_bytes(), charged);
        assert_eq!(budget.peak_reserved_bytes(), peak);
        drop(borrower);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
