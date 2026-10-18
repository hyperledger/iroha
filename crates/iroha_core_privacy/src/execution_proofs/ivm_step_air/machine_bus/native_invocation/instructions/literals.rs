//! Canonical artifact literals bind the original atomic destination and debit.

use super::{tests::*, *};
use ivm::{encoding::wide as enc, instruction::wide};

#[test]
fn full_scalar_bits_and_sixteen_bit_indexes_join_without_memory_or_tag_events() {
    let mut literals = vec![37; 257];
    literals[0] = 0;
    literals[1] = i64::MAX as u64;
    literals[2] = i64::cast_unsigned(i64::MIN);
    literals[255] = u64::MAX;
    literals[256] = 0x0123_4567_89ab_cdef;
    let indexes = [0, 1, 2, 255, 256];
    let mut body: Vec<_> = indexes
        .into_iter()
        .map(|index| enc::encode_literal(wide::memory::LDI64, 4, index))
        .collect();
    body.push(enc::encode_literal(wide::memory::LDI64, 0, 256));
    let (native, budget) = native(artifact_with_literals(&body, 0, &literals));
    let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
    for window in 0..INSTRUCTION_WINDOWS {
        assert!(check(&instructions, &native, window), "window {window}");
    }
    for (window, index) in indexes.into_iter().enumerate() {
        let first = instruction_clocks(window).unwrap()[0] as usize;
        let destination = &native.packets()[first + 19];
        assert_eq!(
            &destination.after()[..8],
            &literals[usize::from(index)].to_le_bytes()
        );
        assert_eq!(destination.after_private(), 0);
        for offset in [4, 5, 6, 7, 17, 18, 20] {
            assert!(
                !native.packets()[first + offset].enabled(),
                "unused literal port {offset}"
            );
        }
    }
    let zero_first = instruction_clocks(indexes.len()).unwrap()[0] as usize;
    assert!(!native.packets()[zero_first + 19].enabled());
    assert!(
        native.packets()[zero_first + 1].enabled(),
        "r0 still debits gas"
    );
    drop(instructions);
    drop(native);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn different_original_literal_artifact_cannot_authorize_the_same_packets() {
    let body = [enc::encode_literal(wide::memory::LDI64, 4, 0)];
    let (native, budget) = native(artifact_with_literals(&body, 0, &[u64::MAX]));
    let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
    let changed = artifact_with_literals(&body, 0, &[i64::cast_unsigned(i64::MIN)]);
    assert_eq!(native.artifact().code_offset(), changed.code_offset());
    assert_ne!(native.artifact().code_hash(), changed.code_hash());
    let wrong = private_dispatch::Program::new(changed).unwrap();
    let packets = original(&native, 0);
    let schedule = private_dispatch::Schedule::new(0, instruction_clocks(0).unwrap()).unwrap();
    let mut residues = Vec::new();
    private_dispatch::append_residues(
        &mut residues,
        &wrong,
        schedule,
        &instructions.rows.as_slice()[0].0,
        &packets,
    );
    assert!(residues.iter().any(|value| *value != F::ZERO));
    for column in (packet::AFTER..packet::AFTER + 8).chain([
        packet::AFTER_TAG,
        packet::CLOCK,
        packet::INDEX,
        packet::GENERATION,
        packet::WRITE,
        packet::ENABLED,
    ]) {
        let mut changed = original(&native, 0);
        let mut fields = core::array::from_fn(|slot| *changed.producer(slot).unwrap());
        fields[17][column] = fields[17][column].add(F::ONE);
        changed = private_dispatch::OriginalPackets::candidate(fields);
        let mut residues = Vec::new();
        private_dispatch::append_residues(
            &mut residues,
            &instructions.program,
            schedule,
            &instructions.rows.as_slice()[0].0,
            &changed,
        );
        assert!(
            residues.iter().any(|value| *value != F::ZERO),
            "column {column}"
        );
    }
    drop(instructions);
    drop(native);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn literal_and_load_tariffs_reach_exact_zero_and_refund_failed_capture() {
    use ivm::{VMError, execution_memory::ExecutionMemoryLease, execution_packets::CaptureError};
    let body = [
        enc::encode_literal(wide::memory::LDI64, 4, 0),
        enc::encode_store(wide::memory::STORE64, 31, 4, -8),
        enc::encode_ri(wide::memory::LOAD64, 4, 31, -8),
    ];
    // Root allocation/entry and Unit return cost 27 for this 16-byte frame;
    // the three operations cost 1+3+3, followed by 57 one-gas padding cycles.
    for gas in [90, 91] {
        let budget = AllocationBudget::new(128 * 1024 * 1024);
        let mut lease =
            ExecutionMemoryLease::reserve(&budget, NativeInvocation::allocation_plan().unwrap())
                .unwrap();
        let result = NativeInvocation::run_public_leaf_root(
            artifact_with_literals(&body, 16, &[u64::MAX]),
            "main",
            gas,
            &mut lease,
            &budget,
        );
        if gas == 90 {
            assert!(matches!(
                result,
                Err(CaptureError::Execution(VMError::OutOfGas))
            ));
        } else {
            let native = result.unwrap();
            assert_eq!(
                native.remaining_gas(),
                0,
                "comparison only, never a relation coefficient"
            );
            let held = budget.reserved_bytes();
            let short = AllocationBudget::new(Instructions::BYTES - 1);
            assert!(matches!(
                Instructions::new(&native, &root(&native), &short),
                Err(Error::Allocation(_))
            ));
            assert_eq!(short.reserved_bytes(), 0);
            assert_eq!(budget.reserved_bytes(), held);
            let exact = AllocationBudget::new(Instructions::BYTES);
            let instructions = Instructions::new(&native, &root(&native), &exact).unwrap();
            for window in 0..INSTRUCTION_WINDOWS {
                assert!(check(&instructions, &native, window));
            }
            drop(instructions);
            assert_eq!(exact.reserved_bytes(), 0);
            drop(native);
        }
        drop(lease);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn maximum_load_profile_uses_the_same_bounded_stack_and_backing() {
    let mut body = vec![enc::encode_ri(wide::memory::LOAD64, 4, 31, -8); 60];
    body[0] = enc::encode_literal(wide::memory::LDI64, 4, 0);
    body[1] = enc::encode_store(wide::memory::STORE64, 31, 4, -8);
    let (native, budget) = native(artifact_with_literals(
        &body,
        16,
        &[i64::cast_unsigned(i64::MIN)],
    ));
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let held = budget.reserved_bytes();
            let instructions = Instructions::new(&native, &root(&native), &budget).unwrap();
            assert_eq!(budget.reserved_bytes(), held + Instructions::BYTES);
            for window in 0..INSTRUCTION_WINDOWS {
                assert!(check(&instructions, &native, window), "window {window}");
            }
            drop(instructions);
            drop(native);
            assert_eq!(budget.reserved_bytes(), 0);
        })
        .unwrap()
        .join()
        .unwrap();
}
