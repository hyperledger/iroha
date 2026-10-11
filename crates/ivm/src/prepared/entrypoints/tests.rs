//! Borrowed-name lookup, bounded traversal and exact original-pool custody.

use super::*;
use crate::encoding::wide as enc;
use iroha_allocation::AllocationRefusal;

fn descriptor(name: &str, entry_pc: u64) -> EmbeddedEntrypointDescriptor {
    EmbeddedEntrypointDescriptor {
        name: name.into(),
        kind: iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: None,
        return_schema: None,
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: Vec::new(),
        entry_pc,
    }
}

fn decoded(words: &[u32]) -> Vec<DecodedOp> {
    words
        .iter()
        .enumerate()
        .map(|(index, inst)| DecodedOp {
            pc: index as u64 * 4,
            inst: *inst,
        })
        .collect()
}

#[test]
fn sorted_indexes_borrow_original_names_and_reset_private_reachability() {
    let decoded = decoded(&[
        enc::encode_branch(wide::control::BEQ, 2, 3, 2),
        enc::encode_offset24(wide::control::JMP, -1),
        enc::encode_sys(
            wide::system::SCALL,
            crate::syscalls::SYSCALL_GET_PRIVATE_INPUT as u8,
        ),
        enc::encode_halt(),
    ]);
    let graph = PreparedControlFlow::from_decoded(&decoded, None).unwrap();
    let descriptors = [
        descriptor("zeta", 0),
        descriptor("alpha", 12),
        descriptor("middle", 4),
    ];
    let budget = AllocationBudget::new(4096);
    for budget in [None, Some(&budget)] {
        let index = Entrypoints::prepare(&descriptors, &decoded, &graph, 40, budget).unwrap();
        assert_eq!(index.len(), 3);
        for (name, original, pc, private) in [
            ("alpha", 1, 52, false),
            ("middle", 2, 44, true),
            ("zeta", 0, 40, true),
        ] {
            let entry = index.get(&descriptors, name).unwrap();
            assert_eq!(entry.descriptor_index, original);
            assert_eq!(entry.absolute_pc, pc);
            assert_eq!(entry.requires_private_inputs, private);
        }
        assert!(index.get(&descriptors, "absent").is_none());
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn duplicate_successors_cycles_and_indirect_edges_do_not_grow_the_queue() {
    let decoded = decoded(&[
        enc::encode_branch(wide::control::BEQ, 2, 3, 1),
        enc::encode_offset24(wide::control::JMP, -1),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
        enc::encode_syscallx(crate::syscalls::SYSCALL_GET_PRIVATE_INPUT),
        enc::encode_halt(),
    ]);
    let graph = PreparedControlFlow::from_decoded(&decoded, None).unwrap();
    let descriptors = [
        descriptor("cycle", 0),
        descriptor("indirect", 8),
        descriptor("private", 12),
    ];
    let bytes = std::mem::size_of::<EntrypointIndex>() * descriptors.len();
    let scratch = std::mem::size_of::<Visit>() * decoded.len();
    let budget = AllocationBudget::new(bytes + scratch);
    let index = Entrypoints::prepare(&descriptors, &decoded, &graph, 0, Some(&budget)).unwrap();
    assert!(
        !index
            .get(&descriptors, "cycle")
            .unwrap()
            .requires_private_inputs
    );
    assert!(
        !index
            .get(&descriptors, "indirect")
            .unwrap()
            .requires_private_inputs
    );
    assert!(
        index
            .get(&descriptors, "private")
            .unwrap()
            .requires_private_inputs
    );
    assert_eq!(budget.peak_reserved_bytes(), bytes + scratch);
    assert_eq!(
        budget.reserved_bytes(),
        bytes,
        "traversal scratch must be gone before publication"
    );
    drop(index);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_pool_refusals_refund_index_and_retry_the_same_descriptors() {
    let decoded = decoded(&[enc::encode_halt()]);
    let graph = PreparedControlFlow::from_decoded(&decoded, None).unwrap();
    let descriptors = [descriptor("run", 0)];
    let bytes = std::mem::size_of::<EntrypointIndex>();
    let scratch = std::mem::size_of::<Visit>();
    let budget = AllocationBudget::new(0);
    assert!(matches!(
        Entrypoints::prepare(&descriptors, &decoded, &graph, 0, Some(&budget)),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
    assert_eq!(budget.peak_reserved_bytes(), 0);
    budget.set_limit_bytes(bytes + scratch - 1);
    assert!(
        matches!(Entrypoints::prepare(&descriptors, &decoded, &graph, 0, Some(&budget)), Err(VMError::AllocationDeferred(AllocationRefusal::Capacity { requested_bytes, .. })) if requested_bytes == scratch)
    );
    assert_eq!(budget.peak_reserved_bytes(), bytes);
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(bytes + scratch);
    let occupied = budget.try_reserve_bytes(bytes + scratch).unwrap();
    assert!(matches!(
        Entrypoints::prepare(&descriptors, &decoded, &graph, 0, Some(&budget)),
        Err(VMError::AllocationDeferred(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    drop(occupied);
    let index = Entrypoints::prepare(&descriptors, &decoded, &graph, 0, Some(&budget)).unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    budget.set_limit_bytes(0);
    assert_eq!(budget.reserved_bytes(), bytes);
    drop(index);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn malformed_indexes_refund_both_allocations_and_empty_index_needs_no_credit() {
    let decoded = decoded(&[enc::encode_halt()]);
    let graph = PreparedControlFlow::from_decoded(&decoded, None).unwrap();
    let budget = AllocationBudget::new(4096);
    for (descriptors, base) in [
        (vec![descriptor("same", 0), descriptor("same", 0)], 0),
        (vec![descriptor("bad", 2)], 0),
        (vec![descriptor("overflow", 4)], u64::MAX),
    ] {
        assert!(matches!(
            Entrypoints::prepare(&descriptors, &decoded, &graph, base, Some(&budget)),
            Err(VMError::DecodeError)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let zero = AllocationBudget::new(0);
    let index = Entrypoints::prepare(&[], &decoded, &graph, 0, Some(&zero)).unwrap();
    assert_eq!(index.len(), 0);
    assert_eq!(zero.peak_reserved_bytes(), 0);
}
