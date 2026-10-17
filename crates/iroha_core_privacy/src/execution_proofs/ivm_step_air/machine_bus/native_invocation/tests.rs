//! Genuine interpreter producers and initializer/history adversaries.
//!
//! Only history witness arithmetic uses a diagnostic oracle. Original packets
//! are produced by `NativeInvocation`'s sealed ordinary-interpreter constructor;
//! no synthetic first-state writes or reconstructed frame captures are added.

use super::super::{
    E, NOTE_COPY_WIDTH_V1, ORDERED, PREVIOUS, PublicPacketBus, SORTED, permutation,
    private_dispatch, return_copyback,
};
use super::*;
use iroha_allocation::AllocationBudget;
use ivm::{PreparedContract, execution_memory::ExecutionMemoryLease};

fn artifact(frame_bytes: u32) -> PreparedContract {
    let original = private_dispatch::tests::contract(
        &[ivm::encoding::wide::encode_ri(
            ivm::instruction::wide::arithmetic::ADDI,
            4,
            0,
            37,
        )],
        64,
        ivm::ivm_mode::ZK,
    );
    let mut interface = original.contract_interface().clone();
    interface.callables[0].frame_bytes = frame_bytes;
    let mut bytes = original.metadata().encode();
    bytes.extend(interface.encode_section());
    bytes.extend_from_slice(&original.artifact()[original.code_offset()..]);
    ivm::prepare_contract(bytes.into()).unwrap()
}
fn source(artifact: PreparedContract, selector: &str, gas: u64) -> (Source, AllocationBudget) {
    let budget = AllocationBudget::new(128 * 1024 * 1024);
    let mut parent =
        ExecutionMemoryLease::reserve(&budget, NativeInvocation::allocation_plan().unwrap())
            .unwrap();
    let native =
        NativeInvocation::run_public_leaf_root(artifact, selector, gas, &mut parent, &budget)
            .unwrap();
    let reserved = budget.reserved_bytes();
    let source = Source::new(native, &budget).unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        reserved
            + instructions::Instructions::BYTES
            + returning::Returning::BYTES
            + terminal::Terminal::BYTES,
        "source funds its exact private workspace without copying the packet bank"
    );
    (source, budget)
}
fn accepts_root(source: &Source, plan: &root::Plan) -> bool {
    (0..ROOT_SLOTS).all(|clock| {
        let mut residues = Vec::new();
        plan.append_residues(&mut residues, clock, &source.packet(clock).0);
        residues.iter().all(|value| *value == F::ZERO)
    })
}

struct History {
    columns: Vec<Vec<F>>,
    aux: Vec<Vec<F>>,
    challenges: permutation::Challenges,
}
impl History {
    fn new(source: &Source) -> Self {
        let events = source
            .native
            .packets()
            .iter()
            .map(|native| {
                native.space().map(|space| packet::Event {
                    space: match space {
                        ivm::execution_packets::PacketSpace::Memory => packet::Space::Memory,
                        ivm::execution_packets::PacketSpace::Register => packet::Space::Register,
                        ivm::execution_packets::PacketSpace::Initialization => {
                            packet::Space::Initialization
                        }
                        ivm::execution_packets::PacketSpace::Owner => packet::Space::Owner,
                    },
                    vm: 0,
                    generation: native.generation(),
                    index: native.index(),
                    write: native.is_write(),
                    before: *native.before(),
                    after: *native.after(),
                    before_private: native.before_private(),
                    after_private: native.after_private(),
                })
            })
            .collect();
        // Sorting/permutation witness construction is a test-only algebraic
        // oracle. It does not supply or authorize the native source packets.
        let bus = PublicPacketBus::new(events).unwrap();
        assert_eq!(bus.trace_log2, 17);
        let columns = bus.columns();
        let challenges = permutation::Challenges::testing(
            E::canonical([2, 1, 0, 0]).unwrap(),
            E::canonical([7, 0, 1, 0]).unwrap(),
        );
        let aux = permutation::columns(
            &columns[NOTE_COPY_WIDTH_V1 + ORDERED..NOTE_COPY_WIDTH_V1 + SORTED],
            &columns[NOTE_COPY_WIDTH_V1 + SORTED..NOTE_COPY_WIDTH_V1 + PREVIOUS],
            &challenges,
            bus.size(),
        )
        .unwrap();
        Self {
            columns,
            aux,
            challenges,
        }
    }
    fn view(&self) -> private_history::View<'_> {
        private_history::View::new(
            private_history::Schedule::new(17, 1).unwrap(),
            [private_history::Segment::new(
                core::array::from_fn(|column| self.columns[NOTE_COPY_WIDTH_V1 + column].as_slice()),
                core::array::from_fn(|column| self.aux[column].as_slice()),
            )],
            &self.challenges,
        )
        .unwrap()
    }
    fn accepts(&self, source: &Source, index: usize) -> bool {
        let mut residues = Vec::new();
        self.view()
            .append_row(&mut residues, index, &source.packet(index / PHASES).0);
        residues.iter().all(|value| *value == F::ZERO)
    }
}

#[test]
fn public_scalars_literals_and_memory_compose_with_original_root_return_and_history() {
    use ivm::{encoding::wide as enc, instruction::wide};
    let mut body = vec![
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        enc::encode_literal(wide::memory::LDI64, 5, 1),
    ];
    body.extend((u8::MIN..=u8::MAX).filter_map(|opcode| {
        let word = enc::encode_rr(opcode, 6, 4, 5);
        ivm::execution_packets::public_scalar_operands(word).map(|_| word)
    }));
    body.extend([
        enc::encode_store(wide::memory::STORE64, 31, 6, -8),
        enc::encode_ri(wide::memory::LOAD64, 5, 31, -8),
        enc::encode_ri(wide::memory::LOAD64, 0, 31, -8),
    ]);
    let contract = instructions::tests::artifact_with_literals(
        &body,
        16,
        &[u64::MAX, i64::cast_unsigned(i64::MIN)],
    );
    let (source, budget) = source(contract, "main", 10_000);
    let history = History::new(&source);
    evaluate(&source, &history.view(), |row, residues| {
        assert!(residues.iter().all(|value| *value == F::ZERO), "{row:?}");
        Ok::<_, ()>(())
    })
    .unwrap();
    drop(history);
    drop(source);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn native_owner_initializes_all_root_fields_and_refunds_its_original_backing() {
    for (frame, gas) in [(0, 10_000), (128, 100_001), (128, u64::MAX)] {
        let (source, budget) = source(artifact(frame), "main", gas);
        assert!(accepts_root(&source, &source.root));
        assert_eq!(source.native.instructions(), 5);
        assert_eq!(source.native.packets().len(), PACKET_SLOTS);
        for clock in 0..PACKET_SLOTS {
            let fields = source.packet(clock);
            if source.native.packets()[clock].enabled() {
                assert_eq!(fields.0[packet::CLOCK], F(clock as u64));
            } else {
                assert_eq!(fields.0, [F::ZERO; packet::WIDTH]);
            }
        }
        drop(source);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn every_initializer_field_and_reserved_slot_is_constrained() {
    let (source, _) = source(artifact(128), "main", 10_000);
    for clock in 0..ROOT_SLOTS {
        for field in 0..packet::WIDTH {
            let mut fields = source.packet(clock);
            fields.0[field] = fields.0[field].add(F::ONE);
            let mut residues = Vec::new();
            source.root.append_residues(&mut residues, clock, &fields.0);
            assert_eq!(residues.len(), packet::WIDTH);
            assert!(
                residues.iter().any(|value| *value != F::ZERO),
                "clock {clock}, field {field}"
            );
        }
    }
}

#[test]
fn artifact_root_frame_gas_and_relative_pc_cannot_be_substituted() {
    let (source, _) = source(artifact(128), "main", 100_000);
    let original = source.native.artifact();
    assert!(matches!(
        root::Plan::derive(original, 1, 100_000),
        Err(root::Error::Entrypoint)
    ));
    assert!(matches!(
        root::Plan::derive(original, 0, 8),
        Err(root::Error::Gas)
    ));
    assert!(!accepts_root(
        &source,
        &root::Plan::derive(original, 0, 100_001).unwrap()
    ));
    assert!(!accepts_root(
        &source,
        &root::Plan::derive(&artifact(144), 0, 100_000).unwrap()
    ));
    // A private helper is admitted only as an actual direct-call target. Its
    // presence in callables still cannot authorize a second public root.
    let private = private_dispatch::tests::contract(
        &[
            ivm::encoding::wide::encode_jump(ivm::instruction::wide::control::JAL, 1, 2),
            ivm::encoding::wide::encode_ri(ivm::instruction::wide::control::JALR, 0, 1, 0),
        ],
        64,
        ivm::ivm_mode::ZK,
    );
    assert!(matches!(
        root::Plan::derive(&private, 1, 100_000),
        Err(root::Error::Entrypoint)
    ));
    let mut interface = original.contract_interface().clone();
    // The separate second public root has the same shape and its own body.
    let mut alternate = interface.callables[0].clone();
    let alternate_entry = (original.artifact().len() - original.code_offset()) as u64;
    alternate.entry_pc = alternate_entry;
    interface.callables.push(alternate);
    let mut public = interface.entrypoints[0].clone();
    public.name = "other".into();
    public.entry_pc = alternate_entry;
    interface.entrypoints.push(public);
    let mut bytes = original.metadata().encode();
    bytes.extend(interface.encode_section());
    bytes.extend_from_slice(&original.artifact()[original.code_offset()..]);
    bytes.extend_from_slice(&crate::ivm_test_support::unit_return());
    let other = ivm::prepare_contract(bytes.into()).unwrap();
    assert!(!accepts_root(
        &source,
        &root::Plan::derive(&other, 1, 100_000).unwrap()
    ));
    let (different, _) = self::source(other, "other", 100_000);
    assert!(accepts_root(&different, &different.root));
    let fields = different.packet(39);
    assert_eq!(
        packet::half(&fields.0, packet::AFTER, 0),
        alternate_entry,
        "Owner[11] stores the relative callable root"
    );
    let fields = different.packet(1);
    assert_ne!(
        packet::half(&fields.0, packet::AFTER, 0),
        alternate_entry,
        "FETCH PC includes the admitted artifact prefix"
    );
}

#[test]
fn complete_original_history_composes_and_mutations_do_not_reclock_or_replace_it() {
    let (source, _) = source(artifact(128), "main", 10_000);
    let mut history = History::new(&source);
    let mut root_rows = 0;
    let mut instruction_windows = [false; INSTRUCTION_WINDOWS];
    let mut return_cells = [false; return_copyback::CELLS];
    let mut history_rows = 0;
    let mut terminal_padding = 0;
    let mut terminal_unused = 0;
    evaluate(&source, &history.view(), |row, residues| {
        match row {
            Row::Root(_) => root_rows += 1,
            Row::Instruction(index) => instruction_windows[index] = true,
            Row::Return(returning::Row::Scan(index)) => return_cells[index] = true,
            Row::Return(_) => {}
            Row::Terminal(terminal::Row::Padding) => terminal_padding += 1,
            Row::Terminal(terminal::Row::Unused(_)) => terminal_unused += 1,
            Row::History(_) => history_rows += 1,
        }
        assert!(residues.iter().all(|value| *value == F::ZERO), "{row:?}");
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(root_rows, ROOT_SLOTS);
    assert!(instruction_windows.into_iter().all(|seen| seen));
    assert!(return_cells.into_iter().all(|seen| seen));
    assert_eq!(history_rows, PACKET_SLOTS * PHASES);
    assert_eq!(terminal_padding, 1);
    assert_eq!(terminal_unused, 5973);
    // Every field at the first/final slots and every dispatcher port in these
    // active/inactive windows is joined, including prior destination contents,
    // disabled state and tags. Those prior values belong to history rather than
    // each individual opcode bank. Candidate history cannot rebase any clock.
    let clocks = [
        0,
        1,
        9,
        39,
        64,
        70,
        2112,
        2212,
        10409,
        10410,
        10411,
        PACKET_SLOTS - 1,
    ]
    .into_iter()
    .chain(
        [0, 1, INSTRUCTION_WINDOWS - 2, INSTRUCTION_WINDOWS - 1]
            .into_iter()
            .flat_map(|window| ivm::execution_packets::instruction_clocks(window).unwrap())
            .map(|clock| clock as usize),
    )
    // STORE's overwritten prior bytes belong to this same original history.
    // Check both actual effect ports and all nine compact mandatory gaps.
    .chain(
        [0, 1, INSTRUCTION_WINDOWS - 2]
            .into_iter()
            .flat_map(|window| {
                let first = ivm::execution_packets::instruction_clocks(window).unwrap()[0] as usize;
                [6, 7, 20, 21, 22, 23, 27, 28, 29, 30, 31]
                    .into_iter()
                    .map(move |offset| first + offset)
            }),
    );
    for clock in clocks {
        for field in 0..packet::WIDTH {
            let column = NOTE_COPY_WIDTH_V1 + ORDERED + field;
            let index = clock * PHASES;
            let original = history.columns[column][index];
            history.columns[column][index] = original.add(F::ONE);
            assert!(
                !history.accepts(&source, index),
                "clock {clock}, field {field}"
            );
            history.columns[column][index] = original;
        }
    }
    let mut source = source;
    source.root =
        root::Plan::derive(source.native.artifact(), 0, source.native.initial_gas() + 1).unwrap();
    // All history products still match the real native run. An alternate
    // public initializer cannot use that consistency as semantic authority.
    assert!(matches!(
        evaluate(&source, &history.view(), |_, residues| {
            if residues.iter().all(|value| *value == F::ZERO) {
                Ok(())
            } else {
                Err(())
            }
        }),
        Err(EvaluationError::Consumer(()))
    ));
}

#[test]
fn whole_history_shape_and_consumer_refusal_are_checked_without_new_backing() {
    let (source, budget) = source(artifact(0), "main", 10_000);
    let reserved = budget.reserved_bytes();
    let column = vec![F::ZERO; 1 << 13];
    let challenges = permutation::Challenges::testing(E::ONE, E::ONE);
    let view = private_history::View::new(
        private_history::Schedule::new(13, 1).unwrap(),
        [private_history::Segment::new(
            [column.as_slice(); super::super::ROW_WIDTH],
            [column.as_slice(); permutation::WIDTH],
        )],
        &challenges,
    )
    .unwrap();
    let mut touched = false;
    assert!(matches!(
        evaluate(&source, &view, |_, _| {
            touched = true;
            Ok::<_, ()>(())
        }),
        Err(EvaluationError::History(
            private_history::ShapeError::Window
        ))
    ));
    assert!(!touched);
    let column = vec![F::ZERO; 1 << 17];
    let segment = private_history::Segment::new(
        [column.as_slice(); super::super::ROW_WIDTH],
        [column.as_slice(); permutation::WIDTH],
    );
    let oversized = private_history::View::new(
        private_history::Schedule::new(17, 2).unwrap(),
        [segment; 2],
        &challenges,
    )
    .unwrap();
    assert!(matches!(
        evaluate(&source, &oversized, |_, _| Ok::<_, ()>(())),
        Err(EvaluationError::History(
            private_history::ShapeError::Window
        ))
    ));
    let exact = private_history::View::new(
        private_history::Schedule::new(17, 1).unwrap(),
        [segment],
        &challenges,
    )
    .unwrap();
    assert!(matches!(
        evaluate(&source, &exact, |_, _| Err(7)),
        Err(EvaluationError::Consumer(7))
    ));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = evaluate(&source, &exact, |_, _| -> Result<(), ()> {
            panic!("consumer unwind")
        });
    }));
    assert!(unwind.is_err());
    assert_eq!(budget.reserved_bytes(), reserved);
    let mut fields = source.packet(0);
    assert_ne!(fields.0, [F::ZERO; packet::WIDTH]);
    // Run the same erasure path used by Drop, rather than duplicating a loop.
    fields.clear();
    assert_eq!(fields.0, [F::ZERO; packet::WIDTH]);
}

#[test]
fn initializer_equations_have_degree_one_in_original_producer_columns() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let artifact = artifact(128);
    let plan = root::Plan::derive(&artifact, 0, 10_000).unwrap();
    assert_eq!(
        measured_maximum_affine_degree_v1(
            [0xda; 32],
            [packet::WIDTH, 0, 0, 0, 0],
            3,
            1,
            |row, _, _, _, _| {
                let mut residues = Vec::new();
                for clock in 0..ROOT_SLOTS {
                    plan.append_residues(&mut residues, clock, row.try_into().unwrap());
                }
                Ok::<_, core::convert::Infallible>(residues)
            },
        ),
        1
    );
}

#[path = "tests/public_leaves.rs"]
pub(super) mod public_leaves;
