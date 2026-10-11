//! Real prepared-program refusal and retry across optional dataflow traversal.

use super::*;
use iroha_allocation::AllocationRefusal;

fn prepared() -> PreparedContract {
    let bytes = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            "seiyaku FundedState { permission CanWrite;  state StateMap<int, int> Values; kotoage fn write_one() authorize(CanWrite) { Values[1] = 10; } }",
        )
        .unwrap();
    crate::prepare_contract(std::sync::Arc::from(bytes.as_slice())).unwrap()
}

#[test]
fn real_analyzer_preserves_original_refusal_then_returns_identical_exact_keys() {
    let contract = prepared();
    let original = contract.artifact().as_ptr();
    let budget = AllocationBudget::new(0);
    let limits =
        norito::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
    let (refused, refused_decode) = norito::core::with_decode_limits_measured(limits, || {
        analyze(&contract, Some("write_one"), &budget)
    });
    assert!(matches!(refused,
        Err(VMError::AllocationDeferred(AllocationRefusal::ExceedsLimit {
            requested_bytes, limit_bytes: 0,
        })) if requested_bytes > 0));
    assert_eq!(
        refused_decode.total_allocated_bytes(),
        0,
        "original-pool admission must precede actual literal decoding"
    );
    assert_eq!(budget.peak_reserved_bytes(), 0);
    budget.set_limit_bytes(64 * 1024 * 1024);
    let (accepted, accepted_decode) = norito::core::with_decode_limits_measured(limits, || {
        analyze(&contract, Some("write_one"), &budget)
    });
    let first = accepted.unwrap().unwrap();
    assert_eq!(
        accepted_decode.total_allocated_bytes(),
        0,
        "real literal analysis now borrows canonical text without owned decoding"
    );
    assert!(first.complete && first.has_state_writes);
    assert_eq!(first.write_keys.len(), 1);
    assert!(
        first
            .write_keys
            .iter()
            .all(|key| key.starts_with("state:Values/"))
    );
    let output_charge = budget.reserved_bytes();
    assert!(
        output_charge > 0,
        "published keys retain their original pool charge"
    );
    let demand = budget.peak_reserved_bytes();
    assert!(
        demand > output_charge,
        "facts/FIFO/key scratch ended before publication"
    );
    let borrower = first.clone();
    let expected: Vec<_> = first.write_keys.iter().map(str::to_owned).collect();
    assert_eq!(
        budget.reserved_bytes(),
        output_charge,
        "clone shares original output"
    );
    drop(first);
    budget.set_limit_bytes(0);
    assert_eq!(budget.reserved_bytes(), output_charge);
    drop(borrower);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(demand);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    assert!(matches!(analyze(&contract, Some("write_one"), &budget),
        Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
        if requested_bytes == output_charge));
    assert_eq!(budget.reserved_bytes(), 1);
    drop(occupied);
    let second = analyze(&contract, Some("write_one"), &budget)
        .unwrap()
        .unwrap();
    assert!(second.complete && second.has_state_writes && !second.has_state_reads);
    assert_eq!(
        second.write_keys.iter().collect::<Vec<_>>(),
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert_eq!(contract.artifact().as_ptr(), original);
    assert_eq!(budget.reserved_bytes(), output_charge);
    drop(second);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn missing_selector_stays_unprovable_without_allocating_or_relabeling_as_refusal() {
    let contract = prepared();
    let zero = AllocationBudget::new(0);
    assert_eq!(analyze(&contract, Some("missing"), &zero).unwrap(), None);
    assert_eq!(zero.peak_reserved_bytes(), 0);
    assert_eq!(zero.reserved_bytes(), 0);
}

#[test]
fn real_text_index_refusal_releases_earlier_dataflow_owners_and_retries() {
    let contract = prepared();
    let probe = AllocationBudget::new(64 * 1024 * 1024);
    let workspace = Workspace::new(contract.decoded().len(), &probe).unwrap();
    let keys = KeyScratch::new(contract.decoded(), &probe).unwrap();
    let preceding = probe.reserved_bytes();
    let literals = PreparedLiterals::new(&contract, &probe).unwrap();
    let text_bytes = probe.reserved_bytes() - preceding;
    assert!(text_bytes > 0);
    drop((literals, keys, workspace));
    assert_eq!(probe.reserved_bytes(), 0);
    let budget = AllocationBudget::new(preceding + text_bytes - 1);
    assert!(matches!(analyze(&contract, Some("write_one"), &budget),
        Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. }))
            if requested_bytes == text_bytes));
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "prior fact/queue/key scratch is reclaimed"
    );
    budget.set_limit_bytes(64 * 1024 * 1024);
    let result = analyze(&contract, Some("write_one"), &budget)
        .unwrap()
        .unwrap();
    assert!(result.complete && result.has_state_writes);
    assert!(
        result
            .write_keys
            .iter()
            .all(|key| key.starts_with("state:Values/"))
    );
    drop(result);
    assert_eq!(budget.reserved_bytes(), 0);
}
