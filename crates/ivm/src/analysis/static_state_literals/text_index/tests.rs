//! Original text/index custody, combined scratch admission and syntax parity.

use super::*;
use iroha_allocation::AllocationRefusal;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

#[test]
fn combined_index_and_nfc_admission_precedes_all_backings_and_retries() {
    let long = format!("q{}", "\u{301}".repeat(4096));
    let rejected = "e\u{301}";
    let values = [
        Text::Name("Map"),
        Text::Path(&long),
        Text::Name(rejected),
        Text::Absent,
    ];
    let index_bytes = values.len() * std::mem::size_of::<Text<'_>>();
    let scratch_bytes = values
        .iter()
        .copied()
        .map(Text::scratch_bytes)
        .max()
        .unwrap();
    assert!(scratch_bytes > index_bytes);
    let demand = index_bytes + scratch_bytes;
    let budget = AllocationBudget::new(0);
    for limit in [0, demand - 1] {
        budget.set_limit_bytes(limit);
        assert!(matches!(
            TextIndex::from_candidates(values.into_iter(), &budget),
            Err(VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit { requested_bytes, .. }))
                if requested_bytes == demand
        ));
        assert_eq!(
            budget.peak_reserved_bytes(),
            0,
            "no partially admitted index"
        );
    }
    budget.set_limit_bytes(demand);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    assert!(matches!(
        TextIndex::from_candidates(values.into_iter(), &budget),
        Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
            if requested_bytes == demand
    ));
    assert_eq!(budget.reserved_bytes(), 1);
    drop(occupied);
    let index = TextIndex::from_candidates(values.into_iter(), &budget).unwrap();
    assert_eq!(index.name(0), Some("Map"));
    assert_eq!(index.path(1), Some(long.as_str()));
    assert_eq!(index.path(1).unwrap().as_ptr(), long.as_ptr());
    assert!(index.name(2).is_none(), "noncanonical NFC remains absent");
    assert!(index.path(3).is_none() && index.path(usize::MAX).is_none());
    assert_eq!(budget.peak_reserved_bytes(), demand);
    assert_eq!(
        budget.reserved_bytes(),
        index_bytes,
        "only physical text indexes remain"
    );
    budget.set_limit_bytes(0);
    assert_eq!(index.path(1), Some(long.as_str()));
    assert_eq!(budget.reserved_bytes(), index_bytes);
    drop(index);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn actual_prepared_literal_index_borrows_only_original_canonical_payloads() {
    let artifact = kotodama_lang::compiler::Compiler::new().compile_source(
        "seiyaku BorrowedText { permission CanWrite;  state StateMap<int, int> Values; kotoage fn write_one() authorize(CanWrite) { Values[1] = 10; } }",
    ).unwrap();
    let contract = crate::prepare_contract(Arc::from(artifact.as_slice())).unwrap();
    let count = contract.literal_table().entries().len();
    let bytes = count * std::mem::size_of::<Text<'_>>();
    let budget = AllocationBudget::new(bytes);
    let index = TextIndex::new(&contract, &budget).unwrap();
    let mut names = 0;
    for (position, literal) in contract.literal_table().entries().iter().enumerate() {
        match candidate(&contract, literal) {
            Text::Name(original) => {
                names += 1;
                let actual = index.name(position).unwrap();
                assert_eq!(actual.as_ptr(), original.as_ptr());
                assert_eq!(actual, original);
                let DecodedLiteral::Pointer(pointer) = literal else {
                    unreachable!()
                };
                let envelope = authenticated_literal_tlv_bytes(&contract, *pointer).unwrap();
                let tlv = validate_tlv_bytes(envelope).unwrap();
                let old: Name = norito::decode_canonical(tlv.payload).unwrap();
                assert_eq!(actual, old.as_ref());
            }
            Text::Path(original) => {
                assert_eq!(index.path(position).unwrap().as_ptr(), original.as_ptr());
            }
            Text::Absent => {
                assert!(index.name(position).is_none() && index.path(position).is_none());
            }
        }
    }
    assert!(names > 0);
    assert_eq!(budget.reserved_bytes(), bytes);
    drop(index);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(contract.artifact(), artifact);
}

#[test]
fn syntax_and_nfc_rejection_match_owned_models_without_retaining_replacements() {
    let long = "a".repeat(iroha_model_base::name::MAX_NAME_BYTES + 1);
    let cases = [
        "",
        "Name",
        "é",
        "e\u{301}",
        "bad@name",
        "bad path",
        "a\u{202e}b",
        long.as_str(),
    ];
    let budget = AllocationBudget::new(1024 * 1024);
    for raw in cases {
        let expected_name = raw.parse::<Name>().ok();
        let expected_path = raw.parse::<StatePath>().ok();
        let values = [Text::Name(raw), Text::Path(raw)];
        let index = TextIndex::from_candidates(values.into_iter(), &budget).unwrap();
        assert_eq!(index.name(0), expected_name.as_ref().map(AsRef::as_ref));
        assert_eq!(index.path(1), expected_path.as_ref().map(AsRef::as_ref));
        if let Some(text) = index.name(0).or_else(|| index.path(1)) {
            assert_eq!(text.as_ptr(), raw.as_ptr());
        }
        assert_eq!(budget.reserved_bytes(), 2 * std::mem::size_of::<Text<'_>>());
        drop(index);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn empty_zero_retention_and_unwind_reclaim_the_original_index_owner() {
    let _limits = crate::ivm_cache::CacheLimitsGuard::new(crate::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    let budget = AllocationBudget::new(0);
    let empty = TextIndex::from_candidates([].into_iter(), &budget).unwrap();
    assert!(empty.entries.as_slice().is_empty());
    assert_eq!(budget.reserved_bytes(), 0);
    drop(empty);
    let bytes = std::mem::size_of::<Text<'_>>();
    budget.set_limit_bytes(bytes + 7);
    let original = budget.try_reserve_bytes(7).unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _index = TextIndex::from_candidates([Text::Name("Map")].into_iter(), &budget).unwrap();
        assert_eq!(budget.reserved_bytes(), bytes + 7);
        budget.set_limit_bytes(0);
        panic!("optional analysis unwound");
    }));
    assert!(result.is_err());
    assert_eq!(budget.reserved_bytes(), 7);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}
