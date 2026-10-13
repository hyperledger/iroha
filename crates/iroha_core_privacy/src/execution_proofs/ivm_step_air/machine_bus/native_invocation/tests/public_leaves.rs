//! Authentic public-leaf producers, exact schema boundaries and native refusal controls.

use super::*;
use iroha_data_model::smart_contract::entrypoint::{
    EntrypointStructTypeNodeV1, EntrypointValueKindV1, EntrypointValueTypeNodeV1,
    EntrypointValueTypeV1,
};
use ivm::{IVM, VMError, encoding::wide as enc, instruction::wide};
use ivm_abi::{
    call::{CallSchemaV1, CallTypeNodeV1},
    metadata::{LITERAL_SECTION_MAGIC, LiteralKindV1, encode_literal_descriptor},
};

/// Canonical admitted bytes, never a packet, clock or accepted-native factory.
pub(in crate::execution_proofs::ivm_step_air::machine_bus::native_invocation) fn artifact(
    kind: root::PublicLeafKind,
    word: u64,
    frame_bytes: u32,
    initialized: bool,
    nonzero_entry: bool,
) -> PreparedContract {
    let original = private_dispatch::tests::contract(&[], 64, ivm::ivm_mode::ZK);
    let mut interface = original.contract_interface().clone();
    interface.callables[0].frame_bytes = frame_bytes;
    if kind == root::PublicLeafKind::Bool {
        interface.callables[0].results = CallSchemaV1 {
            nodes: vec![CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)],
        };
        interface.entrypoints[0].return_type = Some("bool".into());
        interface.entrypoints[0].return_schema = Some(EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)],
        });
    }
    if nonzero_entry {
        let mut first = interface.entrypoints[0].clone();
        first.name = "first".into();
        interface.entrypoints[0].entry_pc = 4;
        interface.entrypoints.insert(0, first);
        let mut second = interface.callables[0].clone();
        second.entry_pc = 4;
        interface.callables.push(second);
    }
    let mut bytes = original.metadata().encode();
    bytes.extend(interface.encode_section());
    // Use the sole current scalar table codec. Its descriptor is relative to
    // LTLB, and code alignment is calculated from this exact new CNTR prefix.
    let data_offset = 24;
    let post_pad = (4 - (bytes.len() - original.header_len() + data_offset + 8) % 4) % 4;
    bytes.extend(LITERAL_SECTION_MAGIC);
    bytes.extend(1_u32.to_le_bytes());
    bytes.extend((post_pad as u32).to_le_bytes());
    bytes.extend(8_u32.to_le_bytes());
    bytes.extend(
        encode_literal_descriptor(LiteralKindV1::I64, data_offset as u64)
            .unwrap()
            .to_le_bytes(),
    );
    bytes.extend(word.to_le_bytes());
    bytes.resize(bytes.len() + post_pad, 0);
    if nonzero_entry {
        bytes.extend(enc::encode_ri(wide::arithmetic::ADDI, 0, 0, 0).to_le_bytes());
    }
    for instruction in [
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        if initialized {
            enc::encode_store(wide::memory::STORE64, 12, 4, 0)
        } else {
            enc::encode_ri(wide::arithmetic::ADDI, 0, 0, 0)
        },
        enc::encode_ri(wide::arithmetic::ADDI, 10, 12, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 1),
        enc::encode_rr(wide::control::JALR, 0, 1, 0),
    ] {
        bytes.extend(instruction.to_le_bytes());
    }
    ivm::prepare_contract(bytes.into()).expect("canonical public-leaf artifact")
}

fn ordinary(artifact: &PreparedContract, gas: u64) -> IVM {
    let mut vm = IVM::new(gas);
    vm.load_prepared(artifact).unwrap();
    vm.select_entrypoint("main").unwrap();
    vm
}

#[test]
fn authentic_unit_and_bool_leaves_join_every_original_bank_and_history_phase() {
    for (kind, word, frame, nonzero_entry) in [
        (root::PublicLeafKind::Unit, 0, 0, false),
        (root::PublicLeafKind::Bool, 0, 128, false),
        (root::PublicLeafKind::Bool, 1, 128, true),
    ] {
        let contract = artifact(kind, word, frame, true, nonzero_entry);
        let mut expected = ordinary(&contract, 10_000);
        expected.run().unwrap();
        assert_eq!(expected.public_call_result_word(0), Ok(word));
        let (source, budget) = source(contract, "main", 10_000);
        assert_eq!(source.root.leaf_kind(), kind);
        assert_eq!(source.native.entrypoint_index(), usize::from(nonzero_entry));
        assert_eq!(source.native.remaining_gas(), expected.remaining_gas());
        assert_eq!(source.native.cycles(), expected.get_cycle_count());
        let mut history = History::new(&source);
        let mut roots = 0;
        let mut instructions = 0;
        let mut scans = 0;
        let mut history_rows = 0;
        let mut terminal_suffix = 0;
        evaluate(&source, &history.view(), |row, residues| {
            assert!(
                residues.iter().all(|value| *value == F::ZERO),
                "{kind:?}, {row:?}"
            );
            match row {
                Row::Root(_) => roots += 1,
                Row::Instruction(_) => instructions += 1,
                Row::Return(returning::Row::Scan(_)) => scans += 1,
                Row::History(_) => history_rows += 1,
                Row::Terminal(terminal::Row::Unused(_)) => terminal_suffix += 1,
                _ => {}
            }
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(roots, ROOT_SLOTS);
        assert_eq!(instructions, INSTRUCTION_WINDOWS);
        assert_eq!(scans, 4_097);
        assert_eq!(history_rows, PACKET_SLOTS * PHASES);
        assert_eq!(terminal_suffix, 5_973);
        assert_eq!(
            NativeInvocation::allocation_plan()
                .unwrap()
                .requested_bytes(),
            786_432
        );
        assert_eq!(instructions::Instructions::BYTES, 1_002_304);
        assert_eq!(returning::Returning::BYTES, 9_308_384);
        assert_eq!(terminal::Terminal::BYTES, 96);
        // Every typed packet field still equals the same sealed producer,
        // including the true Bool word. Diagnostic history columns are only
        // adversarial equation candidates and cannot replace that owner.
        let clock = ivm::execution_packets::instruction_clocks(ivm::execution_packets::MAX_STEPS)
            .unwrap()[0] as usize
            + 24;
        for field in 0..packet::WIDTH {
            let column = NOTE_COPY_WIDTH_V1 + ORDERED + field;
            let row = clock * PHASES;
            let original = history.columns[column][row];
            history.columns[column][row] = original.add(F::ONE);
            assert!(
                !history.accepts(&source, row),
                "{kind:?}, typed field {field}"
            );
            history.columns[column][row] = original;
        }
        drop(history);
        drop(source);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn one_word_aggregate_and_pointer_schemas_remain_unsupported_before_partition() {
    for (nodes, public_nodes, spelling) in [
        (
            // Tuple(1) is inadmissible in the canonical public schema. This
            // valid empty named product still owns one word, and proves that
            // the profile admits an exact leaf kind rather than its width.
            vec![CallTypeNodeV1::Struct {
                name: "Empty".into(),
                fields: Vec::new(),
            }],
            vec![EntrypointValueTypeNodeV1::Struct(
                EntrypointStructTypeNodeV1 {
                    name: "Empty".into(),
                    fields: Vec::new(),
                },
            )],
            "struct Empty",
        ),
        (
            vec![CallTypeNodeV1::Leaf(EntrypointValueKindV1::Int)],
            vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)],
            "int",
        ),
    ] {
        let original = artifact(root::PublicLeafKind::Bool, 0, 0, true, false);
        let mut interface = original.contract_interface().clone();
        interface.callables[0].results = CallSchemaV1 { nodes };
        assert_eq!(interface.callables[0].results.word_count(), Some(1));
        interface.entrypoints[0].return_type = Some(spelling.into());
        interface.entrypoints[0].return_schema = Some(EntrypointValueTypeV1 {
            nodes: public_nodes,
        });
        let mut bytes = original.metadata().encode();
        bytes.extend(interface.encode_section());
        // This negative artifact needs no scalar table; its native profile is
        // refused from complete metadata before any instruction is executed.
        bytes.extend(crate::ivm_test_support::unit_return());
        let contract = ivm::prepare_contract(bytes.into()).unwrap();
        let budget = AllocationBudget::new(128 * 1024 * 1024);
        let demand = NativeInvocation::allocation_plan().unwrap();
        let mut parent = ExecutionMemoryLease::reserve(&budget, demand).unwrap();
        assert!(matches!(
            NativeInvocation::run_public_leaf_root(
                contract.clone(),
                "main",
                10_000,
                &mut parent,
                &budget
            ),
            Err(ivm::execution_packets::CaptureError::Unsupported)
        ));
        assert_eq!(parent.remaining_bytes(), demand.requested_bytes());
        assert!(matches!(
            root::Plan::derive(&contract, 0, 10_000),
            Err(root::Error::Profile)
        ));
        drop(parent);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn full_word_aliases_and_missing_initialization_are_native_faults_without_owners() {
    for (kind, word, initialized, expected) in [
        (root::PublicLeafKind::Bool, 2, true, VMError::DecodeError),
        (
            root::PublicLeafKind::Bool,
            u64::MAX,
            true,
            VMError::DecodeError,
        ),
        (
            root::PublicLeafKind::Bool,
            0xffff_ffff_0000_0001,
            true,
            VMError::DecodeError,
        ),
        (
            root::PublicLeafKind::Bool,
            0xffff_ffff_0000_0002,
            true,
            VMError::DecodeError,
        ),
        (root::PublicLeafKind::Unit, 1, true, VMError::DecodeError),
        (
            root::PublicLeafKind::Bool,
            0,
            false,
            VMError::AssertionFailed,
        ),
    ] {
        let contract = artifact(kind, word, 0, initialized, false);
        assert!(matches!(
            (ordinary(&contract, 10_000).run(), &expected),
            (Err(VMError::DecodeError), VMError::DecodeError)
                | (Err(VMError::AssertionFailed), VMError::AssertionFailed)
        ));
        let budget = AllocationBudget::new(128 * 1024 * 1024);
        let mut parent =
            ExecutionMemoryLease::reserve(&budget, NativeInvocation::allocation_plan().unwrap())
                .unwrap();
        assert!(matches!(
            (
                NativeInvocation::run_public_leaf_root(
                    contract,
                    "main",
                    10_000,
                    &mut parent,
                    &budget
                ),
                expected
            ),
            (
                Err(ivm::execution_packets::CaptureError::Execution(
                    VMError::DecodeError
                )),
                VMError::DecodeError
            ) | (
                Err(ivm::execution_packets::CaptureError::Execution(
                    VMError::AssertionFailed
                )),
                VMError::AssertionFailed
            )
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn every_public_leaf_gas_prefix_preserves_the_exact_ordinary_outcome() {
    let success = artifact(root::PublicLeafKind::Bool, 1, 0, true, false);
    let mut ordinary_success = ordinary(&success, 10_000);
    ordinary_success.run().unwrap();
    let complete_cost = 10_000 - ordinary_success.remaining_gas();
    for (kind, word) in [
        (root::PublicLeafKind::Unit, 0),
        (root::PublicLeafKind::Bool, 0),
        (root::PublicLeafKind::Bool, 1),
        (root::PublicLeafKind::Bool, 2),
    ] {
        let contract = artifact(kind, word, 0, true, false);
        for gas in 0..=complete_cost {
            let mut expected = ordinary(&contract, gas);
            let verdict = expected.run();
            let budget = AllocationBudget::new(128 * 1024 * 1024);
            let mut parent = ExecutionMemoryLease::reserve(
                &budget,
                NativeInvocation::allocation_plan().unwrap(),
            )
            .unwrap();
            let captured = NativeInvocation::run_public_leaf_root(
                contract.clone(),
                "main",
                gas,
                &mut parent,
                &budget,
            );
            match (verdict, captured) {
                (Ok(()), Ok(native)) => {
                    assert_eq!(expected.public_call_result_word(0), Ok(word));
                    assert_eq!(native.remaining_gas(), expected.remaining_gas());
                    assert_eq!(native.cycles(), expected.get_cycle_count());
                    drop(native);
                }
                (Err(expected), Err(ivm::execution_packets::CaptureError::Execution(actual))) => {
                    assert_eq!(actual, expected, "{kind:?}, word {word}, gas {gas}");
                }
                (_, Err(other)) => panic!("unexpected local refusal at gas {gas}: {other:?}"),
                (Err(error), Ok(_)) => {
                    panic!("native owner published despite ordinary fault: {error:?}")
                }
            }
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }
}
