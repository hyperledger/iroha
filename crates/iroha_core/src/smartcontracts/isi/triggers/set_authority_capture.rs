//! Original malformed-contract custody controls for the production checked reader.

use super::*;
use crate::state::authority_registry::leaf::{LeafError, LeafLimits};

#[cfg(test)]
mod custody_tests {
    use super::*;

    #[test]
    fn malformed_contract_source_is_not_a_codec_failure_or_a_partial_table() {
        let set = Set::default();
        let blob = IvmBytecode::from_compiled(vec![1, 2, 3]);
        let key = HashOf::new(&blob);
        let mut block = set.block();
        block.contracts.insert(
            key,
            IvmBytecodeEntry {
                original_contract: blob,
                code_hash: Hash::new(b"incorrect derived contract hash"),
                count: NonZeroU64::MIN,
            },
        );
        block.commit();
        let pool = iroha_allocation::AllocationBudget::new(64 * 1024);
        let limits = LeafLimits {
            max_tables: 1,
            max_rows: 1,
            max_payload_bytes: 1024,
            max_ordered_table_bytes: 4096,
            max_streamed_value_bytes: 4096,
        };
        let result = CheckedContracts::capture(&set, contract_source_work(limits), &pool)
            .map_err(LeafError::from)
            .and_then(|mut checked| {
                let outcome = checked.encode(limits);
                let current = checked.matches_current();
                drop(checked);
                assert!(current.expect("original contract source identity"));
                outcome
            });
        assert!(
            matches!(result, Err(LeafError::SourceValidation(ref message))
            if message == "trigger contract code hash does not match its original bytecode")
        );
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(pool.peak_reserved_bytes(), 0);
    }
}
