//! Cleartext reference vectors, state reset and parity with the diagnostic evaluator.

use super::*;
use crate::ram_lfe::{
    HiddenRamFheInstruction as Op,
    canonical::{
        RamLfeAssociatedDataHashV1, RamLfeFunctionIdentityV1, RamLfeProgramKeyV1,
        RamLfeQueryLimitV1,
    },
    clearing::cleared_cells,
};

fn build(instructions: &[Op]) -> HiddenRamFheProgram {
    let mut builder = HiddenRamFheProgram::builder().unwrap();
    for &instruction in instructions {
        builder.push(instruction).unwrap();
    }
    builder.finish().unwrap()
}

fn key(byte: u8) -> RamLfeProgramKeyV1 {
    RamLfeProgramKeyV1::from_bytes([byte; 32]).unwrap()
}

fn limit() -> RamLfeQueryLimitV1 {
    RamLfeQueryLimitV1::new(1000, 3).unwrap()
}

fn commit(
    class: RamLfeClassV1,
    key: &RamLfeProgramKeyV1,
    program: &HiddenRamFheProgram,
) -> RamLfeFunctionIdentityV1 {
    RamLfeFunctionIdentityV1::commit(class, key, program, limit()).unwrap()
}

fn memory(lanes: [u16; 32]) -> RamLfeInitialMemoryV1 {
    RamLfeInitialMemoryV1::from_lanes(&lanes).unwrap()
}

/// Run a bounded program on explicit lanes and return its ordered output.
fn run(instructions: &[Op], lanes: [u16; 32], input: &[u8]) -> Vec<u16> {
    ram_lfe_reference_execute_v1(
        RamLfeClassV1::Bounded,
        &build(instructions),
        &memory(lanes),
        &RamLfeReferenceInputV1::from_bytes(input).unwrap(),
    )
    .unwrap()
    .output()
    .scalars()
    .to_vec()
}

#[test]
fn input_encoding_accepts_exactly_the_admitted_shape() {
    let input = RamLfeReferenceInputV1::from_bytes(b"\x00\xffA").unwrap();
    let mut expected = [0_u16; 64];
    expected[..4].copy_from_slice(&[3, 0, 255, 65]);
    assert_eq!(input.slots(), &expected);
    assert_eq!(format!("{input:?}"), "[REDACTED RAM-LFE reference input]");
    assert_eq!(
        RamLfeReferenceInputV1::from_slots(&expected)
            .unwrap()
            .slots(),
        &expected
    );
    assert_eq!(
        RamLfeReferenceInputV1::from_bytes(b"").unwrap().slots(),
        &[0; 64]
    );
    let full = RamLfeReferenceInputV1::from_bytes(&[200; 63]).unwrap();
    assert_eq!(full.slots()[0], 63);
    assert!(full.slots()[1..].iter().all(|&slot| slot == 200));
    assert!(RamLfeReferenceInputV1::from_bytes(&[0; 64]).is_err());

    let reject = |slots: &[u16], message: &'static str| {
        assert_eq!(
            RamLfeReferenceInputV1::from_slots(slots).unwrap_err(),
            RamLfeError::InvalidCanonicalValue(message)
        );
    };
    reject(&[0; 63], "input requires exactly 64 slots");
    reject(&[0; 65], "input requires exactly 64 slots");
    let mut slots = [0_u16; 64];
    slots[0] = 64;
    reject(&slots, "input length slot exceeds 63");
    slots[0] = 2;
    slots[2] = 256;
    reject(&slots, "input byte slot exceeds 255");
    slots[2] = 255;
    slots[3] = 1;
    reject(&slots, "input slot after the declared length is not zero");
    slots[3] = 0;
    assert!(RamLfeReferenceInputV1::from_slots(&slots).is_ok());
}

#[test]
fn memory_and_output_owners_validate_their_scalars() {
    assert!(RamLfeInitialMemoryV1::from_lanes(&[256; 32]).is_ok());
    assert!(RamLfeInitialMemoryV1::from_lanes(&[257; 32]).is_err());
    assert!(RamLfeInitialMemoryV1::from_lanes(&[0; 31]).is_err());
    assert!(RamLfeInitialMemoryV1::from_lanes(&[0; 33]).is_err());
    assert_eq!(
        format!("{:?}", memory([1; 32])),
        "[REDACTED RAM-LFE initial memory]"
    );

    let output = RamLfeOrderedOutputV1::from_scalars(&[256, 0, 255]).unwrap();
    assert_eq!(output.scalars(), [256, 0, 255]);
    assert_eq!(format!("{output:?}"), "[REDACTED RAM-LFE ordered output]");
    assert!(RamLfeOrderedOutputV1::from_scalars(&[]).is_err());
    assert!(RamLfeOrderedOutputV1::from_scalars(&[0; 64]).is_ok());
    assert!(RamLfeOrderedOutputV1::from_scalars(&[0; 65]).is_err());
    assert!(RamLfeOrderedOutputV1::from_scalars(&[257]).is_err());
}

#[test]
fn every_instruction_has_its_exact_modular_meaning() {
    let mut lanes = [0_u16; 32];
    lanes[7] = 256;
    lanes[8] = 100;
    // Input bytes 255 and 2: slot 0 is the length, slots 1 and 2 the bytes.
    let input = [255_u8, 2];
    let vectors: [(&str, &[Op], &[u16]); 16] = [
        (
            "LoadInput reads the length slot",
            &[Op::LoadInput(0, 0), Op::Output(0)],
            &[2],
        ),
        (
            "LoadInput reads a byte slot",
            &[Op::LoadInput(0, 1), Op::Output(0)],
            &[255],
        ),
        (
            "LoadInput reads zero padding",
            &[Op::LoadInput(0, 63), Op::Output(0)],
            &[0],
        ),
        (
            "LoadState reads an initialized lane",
            &[Op::LoadState(0, 7), Op::Output(0)],
            &[256],
        ),
        (
            "StoreState replaces a lane without changing its source",
            &[
                Op::LoadState(0, 8),
                Op::StoreState(7, 0),
                Op::LoadState(1, 7),
                Op::Output(1),
                Op::Output(0),
            ],
            &[100, 100],
        ),
        (
            "LoadConst keeps the scalar 256",
            &[Op::LoadConst(0, 256), Op::Output(0)],
            &[256],
        ),
        (
            "Add wraps at 257: 256 + 255 = 254",
            &[
                Op::LoadState(0, 7),
                Op::LoadInput(1, 1),
                Op::Add(2, 0, 1),
                Op::Output(2),
            ],
            &[254],
        ),
        (
            "Add doubles 256 to 255",
            &[Op::LoadState(0, 7), Op::Add(0, 0, 0), Op::Output(0)],
            &[255],
        ),
        (
            "AddPlain wraps to zero: 256 + 1 = 0",
            &[Op::LoadState(0, 7), Op::AddPlain(0, 0, 1), Op::Output(0)],
            &[0],
        ),
        (
            "SubPlain borrows below zero: 0 - 1 = 256",
            &[Op::SubPlain(0, 0, 1), Op::Output(0)],
            &[256],
        ),
        (
            "SubPlain by 256 adds one: 0 - 256 = 1",
            &[Op::SubPlain(0, 0, 256), Op::Output(0)],
            &[1],
        ),
        (
            "MulPlain squares minus one: 256 * 256 = 1",
            &[Op::LoadState(0, 7), Op::MulPlain(0, 0, 256), Op::Output(0)],
            &[1],
        ),
        (
            "MulPlain by zero clears",
            &[Op::LoadState(0, 7), Op::MulPlain(0, 0, 0), Op::Output(0)],
            &[0],
        ),
        (
            "Mul reduces the widest product: 256 * 256 = 1 and 255 * 100 = 57",
            &[
                Op::LoadState(0, 7),
                Op::Mul(1, 0, 0),
                Op::Output(1),
                Op::LoadInput(2, 1),
                Op::LoadState(3, 8),
                Op::Mul(1, 2, 3),
                Op::Output(1),
            ],
            &[1, 57],
        ),
        (
            "Mul reaches 256 from 16 * 16",
            &[Op::LoadConst(0, 16), Op::Mul(0, 0, 0), Op::Output(0)],
            &[256],
        ),
        (
            "SelectEqZero takes the zero branch only for zero, including for 256",
            &[
                Op::LoadConst(1, 11),
                Op::LoadConst(2, 22),
                Op::SelectEqZero(3, 0, 1, 2),
                Op::Output(3),
                Op::LoadState(0, 7),
                Op::SelectEqZero(3, 0, 1, 2),
                Op::Output(3),
                Op::LoadInput(0, 2),
                Op::SelectEqZero(3, 0, 1, 2),
                Op::Output(3),
            ],
            &[11, 22, 22],
        ),
    ];
    let mut opcodes = std::collections::BTreeSet::new();
    for (name, tape, expected) in vectors {
        assert_eq!(run(tape, lanes, &input), expected, "{name}");
        opcodes.extend(tape.iter().map(|instruction| instruction.opcode()));
    }
    assert_eq!(opcodes.len(), 11, "the vectors exercise every opcode");
}

#[test]
fn select_formula_is_the_zero_test_for_every_condition() {
    for condition in 0..=256_u16 {
        for if_zero in [0_u16, 1, 128, 255, 256] {
            for if_non_zero in [0_u16, 1, 128, 255, 256] {
                let expected = if condition == 0 { if_zero } else { if_non_zero };
                assert_eq!(select_eq_zero(condition, if_zero, if_non_zero), expected);
            }
        }
    }
}

#[test]
fn modular_helpers_cover_the_whole_field() {
    for lhs in 0..=256_u16 {
        for rhs in 0..=256_u16 {
            let (wide_lhs, wide_rhs) = (u32::from(lhs), u32::from(rhs));
            assert_eq!(u32::from(add(lhs, rhs)), (wide_lhs + wide_rhs) % 257);
            assert_eq!(
                u32::from(subtract(lhs, rhs)),
                (wide_lhs + 257 - wide_rhs) % 257
            );
            assert_eq!(u32::from(multiply(lhs, rhs)), (wide_lhs * wide_rhs) % 257);
            assert_eq!(add(subtract(lhs, rhs), rhs), lhs);
        }
    }
    assert_eq!(reduce(257), 0);
    assert_eq!(reduce(256 * 256), 1);
}

#[test]
fn destination_may_alias_any_source_and_outputs_are_snapshots() {
    // Every source is read before the destination is written.
    assert_eq!(
        run(
            &[
                Op::LoadConst(0, 5),
                Op::LoadConst(1, 9),
                Op::Add(0, 0, 1),
                Op::Output(0),
                Op::Mul(1, 0, 1),
                Op::Output(1),
                Op::LoadConst(2, 0),
                Op::SelectEqZero(2, 2, 0, 1),
                Op::Output(2),
                Op::SelectEqZero(1, 0, 1, 1),
                Op::Output(1),
            ],
            [0; 32],
            b"",
        ),
        [14, 126, 14, 126]
    );
    // A later write to the register does not change an earlier output.
    assert_eq!(
        run(
            &[
                Op::LoadConst(0, 1),
                Op::Output(0),
                Op::LoadConst(0, 2),
                Op::Output(0),
                Op::AddPlain(0, 0, 254),
                Op::Output(0),
            ],
            [0; 32],
            b"",
        ),
        [1, 2, 256]
    );
}

fn stateful_program() -> HiddenRamFheProgram {
    build(&[
        // Registers start at zero and lanes at their initialized values.
        Op::Output(3),
        Op::LoadState(0, 5),
        Op::Output(0),
        // Mutate a register and a lane, then read the lane back.
        Op::LoadConst(3, 77),
        Op::StoreState(5, 3),
        Op::LoadState(1, 5),
        Op::Output(1),
    ])
}

#[test]
fn state_resets_within_each_execution() {
    let program = stateful_program();
    let key = key(11);
    let function = commit(RamLfeClassV1::Affine, &key, &program);
    let input = RamLfeReferenceInputV1::from_bytes(b"abc").unwrap();
    let evaluate = |associated_data: &[u8]| {
        ram_lfe_reference_evaluate_v1(&function, &key, &program, associated_data, &input).unwrap()
    };
    let first = evaluate(b"request");
    let second = evaluate(b"request");
    let lane = first.initial_memory().lanes()[5];
    // The first execution stored 77 into lane 5. The second execution starts
    // from the initialized lane again and from zero registers.
    assert_eq!(first.output().scalars(), [0, lane, 77]);
    assert_eq!(second.output().scalars(), first.output().scalars());
    assert_eq!(second.initial_memory(), first.initial_memory());
    let last = first.trace().step_count();
    assert_eq!(first.trace().snapshot(last).unwrap()[4 + 5], 77);
    assert_eq!(second.trace().snapshot(0).unwrap()[4 + 5], lane);
    assert_eq!(second.trace().snapshot(0).unwrap()[..4], [0; 4]);

    // Explicit lanes behave the same way: the caller's memory is never mutated.
    let lanes = memory([200; 32]);
    let run = || {
        ram_lfe_reference_execute_v1(RamLfeClassV1::Affine, &program, &lanes, &input)
            .unwrap()
            .output()
            .scalars()
            .to_vec()
    };
    assert_eq!(run(), [0, 200, 77]);
    assert_eq!(run(), [0, 200, 77]);
    assert_eq!(lanes.lanes(), &[200; 32]);
}

#[test]
fn initializer_depends_only_on_key_function_identity_and_associated_data() {
    let program = stateful_program();
    let function =
        |byte: u8, class: RamLfeClassV1| commit(class, &key(byte), &program).id().unwrap();
    let context = |bytes: &[u8]| RamLfeAssociatedDataHashV1::commit(bytes).unwrap();
    let base = RamLfeInitialMemoryV1::derive(
        &key(11),
        function(11, RamLfeClassV1::Affine),
        context(b"request"),
    )
    .unwrap();
    assert_eq!(
        base,
        RamLfeInitialMemoryV1::derive(
            &key(11),
            function(11, RamLfeClassV1::Affine),
            context(b"request")
        )
        .unwrap()
    );
    assert!(base.lanes().iter().all(|&lane| lane <= 256));
    // Thirty-two pseudorandom residues are not all equal.
    assert!(base.lanes().iter().any(|&lane| lane != base.lanes()[0]));
    for other in [
        RamLfeInitialMemoryV1::derive(
            &key(12),
            function(11, RamLfeClassV1::Affine),
            context(b"request"),
        ),
        RamLfeInitialMemoryV1::derive(
            &key(11),
            function(11, RamLfeClassV1::Bounded),
            context(b"request"),
        ),
        RamLfeInitialMemoryV1::derive(
            &key(11),
            function(11, RamLfeClassV1::Affine),
            context(b"other request"),
        ),
        // Another query limit is another function identity with other lanes.
        RamLfeInitialMemoryV1::derive(
            &key(11),
            RamLfeFunctionIdentityV1::commit(
                RamLfeClassV1::Affine,
                &key(11),
                &program,
                RamLfeQueryLimitV1::new(1001, 3).unwrap(),
            )
            .unwrap()
            .id()
            .unwrap(),
            context(b"request"),
        ),
    ] {
        assert_ne!(other.unwrap(), base);
    }
}

#[test]
fn initializer_is_the_documented_blake3_stream() {
    #[derive(norito::codec::Encode, norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_crypto::ram_lfe::RamLfeInitializationInputV1",
        frame = "iroha_crypto::ram_lfe::RamLfeInitializationInputV1"
    )]
    struct OwnedInitializationInput {
        function_identity: crate::Hash,
        associated_data_hash: crate::Hash,
        program_key: Vec<u8>,
    }
    let program = stateful_program();
    let function = commit(RamLfeClassV1::Affine, &key(11), &program)
        .id()
        .unwrap();
    let context = RamLfeAssociatedDataHashV1::commit(b"request").unwrap();
    let frame = norito::encode_canonical(&OwnedInitializationInput {
        function_identity: *function.as_hash(),
        associated_data_hash: *context.as_hash(),
        program_key: vec![11; 32],
    })
    .unwrap();
    let mut hasher = blake3::Hasher::new_derive_key("iroha.ram_lfe.v1.initial_state");
    hasher.update(&frame);
    let mut stream = [0_u8; 1024];
    hasher.finalize_xof().fill(&mut stream);
    // Each lane is its 32 bytes read as an unsigned big-endian integer modulo 257.
    let expected: Vec<u16> = stream
        .chunks_exact(32)
        .map(|lane| {
            lane.iter().fold(0_u32, |residue, &byte| {
                (residue * 256 + u32::from(byte)) % 257
            })
        })
        .map(|residue| u16::try_from(residue).unwrap())
        .collect();
    let derived = RamLfeInitialMemoryV1::derive(&key(11), function, context).unwrap();
    assert_eq!(derived.lanes().as_slice(), expected);
}

#[test]
fn evaluation_requires_the_committed_key_program_and_bounded_context() {
    let program = stateful_program();
    let function = commit(RamLfeClassV1::Affine, &key(11), &program);
    let input = RamLfeReferenceInputV1::from_bytes(b"abc").unwrap();
    assert_eq!(
        ram_lfe_reference_evaluate_v1(&function, &key(12), &program, b"", &input).unwrap_err(),
        RamLfeError::CommitmentMismatch
    );
    let other = build(&[Op::LoadInput(0, 0), Op::Output(0)]);
    assert_eq!(
        ram_lfe_reference_evaluate_v1(&function, &key(11), &other, b"", &input).unwrap_err(),
        RamLfeError::CommitmentMismatch
    );
    assert_eq!(
        ram_lfe_reference_evaluate_v1(&function, &key(11), &program, &[0; 513], &input)
            .unwrap_err(),
        RamLfeError::InvalidCanonicalValue("associated data exceeds 512 bytes")
    );
}

#[test]
fn execution_is_gated_by_the_declared_class_and_reports_refreshes() {
    let mut tape = vec![Op::LoadInput(0, 1)];
    tape.extend(std::iter::repeat_n(Op::Mul(0, 0, 0), 20));
    tape.push(Op::Output(0));
    let program = build(&tape);
    let lanes = memory([0; 32]);
    let input = RamLfeReferenceInputV1::from_bytes(&[3]).unwrap();
    for class in [RamLfeClassV1::Affine, RamLfeClassV1::Bounded] {
        assert!(ram_lfe_reference_execute_v1(class, &program, &lanes, &input).is_err());
    }
    let execution =
        ram_lfe_reference_execute_v1(RamLfeClassV1::Refresh, &program, &lanes, &input).unwrap();
    // 3^(2^20) mod 257: 3 has order 256, and 2^20 is a multiple of 256.
    assert_eq!(execution.output().scalars(), [1]);
    // Refresh is the identity on plaintext; only the schedule records it.
    assert_eq!(execution.report().refresh_count(), 1);
    assert_eq!(execution.report().class(), RamLfeClassV1::Refresh);
    assert_eq!(execution.trace().step_count(), 22);
    assert!(execution.trace().snapshot(23).is_none());
    assert_eq!(
        format!("{:?}", execution.trace()),
        "[REDACTED RAM-LFE reference trace]"
    );
}

#[test]
fn trace_rows_are_registers_then_lanes_after_each_instruction() {
    let lanes: [u16; 32] = std::array::from_fn(|lane| u16::try_from(lane + 1).unwrap());
    let program = build(&[
        Op::LoadInput(2, 1),
        Op::StoreState(31, 2),
        Op::LoadState(0, 0),
        Op::Output(0),
    ]);
    let execution = ram_lfe_reference_execute_v1(
        RamLfeClassV1::Affine,
        &program,
        &memory(lanes),
        &RamLfeReferenceInputV1::from_bytes(&[99]).unwrap(),
    )
    .unwrap();
    let trace = execution.trace();
    assert_eq!(trace.step_count(), 4);
    let row = |index: usize| trace.snapshot(index).unwrap().to_vec();
    let mut expected = [0_u16; RAM_LFE_V1_TRACE_ROW_SCALARS];
    expected[4..].copy_from_slice(&lanes);
    assert_eq!(row(0), expected);
    expected[2] = 99;
    assert_eq!(row(1), expected);
    expected[4 + 31] = 99;
    assert_eq!(row(2), expected);
    expected[0] = 1;
    assert_eq!(row(3), expected);
    assert_eq!(row(4), expected);
    assert_eq!(execution.output().scalars(), [1]);
    assert_eq!(execution.initial_memory().lanes(), &lanes);
}

#[test]
fn default_identifier_program_is_affine_and_adds_each_lane_to_its_slot() {
    let program = crate::default_bfv_programmed_hidden_program();
    let lanes: [u16; 32] = std::array::from_fn(|lane| u16::try_from(250 + lane % 7).unwrap());
    let bytes: Vec<u8> = (0..63_u8).map(|index| 200 + index % 56).collect();
    let input = RamLfeReferenceInputV1::from_bytes(&bytes).unwrap();
    let execution =
        ram_lfe_reference_execute_v1(RamLfeClassV1::Affine, &program, &memory(lanes), &input)
            .unwrap();
    let expected: Vec<u16> = (0..64)
        .map(|slot| (input.slots()[slot] + lanes[slot % 32]) % 257)
        .collect();
    assert_eq!(execution.output().scalars(), expected);
    assert_eq!(execution.report().ciphertext_multiplications(), 0);
    assert_eq!(execution.report().output_count(), 64);
}

#[test]
fn reference_vector_is_pinned() {
    let program = build(&[
        Op::LoadInput(0, 1),
        Op::LoadState(1, 0),
        Op::Add(2, 0, 1),
        Op::MulPlain(2, 2, 3),
        Op::Output(2),
        Op::LoadState(3, 31),
        Op::Output(3),
    ]);
    let key = key(0x42);
    let function = commit(RamLfeClassV1::Affine, &key, &program);
    let execution = ram_lfe_reference_evaluate_v1(
        &function,
        &key,
        &program,
        b"reference-vector",
        &RamLfeReferenceInputV1::from_bytes(b"+15551234567").unwrap(),
    )
    .unwrap();
    let lanes = execution.initial_memory().lanes();
    assert_eq!(lanes.as_slice(), PINNED_LANES);
    assert_eq!(
        execution.output().scalars(),
        [(u16::from(b'+') + lanes[0]) * 3 % 257, lanes[31]]
    );
    assert_eq!(execution.output().scalars(), PINNED_OUTPUT);
}

const PINNED_LANES: [u16; 32] = [
    106, 86, 213, 46, 86, 1, 205, 110, 60, 59, 9, 102, 118, 67, 237, 208, 100, 210, 80, 250, 96,
    220, 99, 50, 210, 4, 132, 46, 66, 219, 96, 95,
];
const PINNED_OUTPUT: [u16; 2] = [190, 95];

#[test]
fn cleartext_reference_matches_the_diagnostic_encrypted_interpreter() {
    use crate::ram_lfe::{
        ProgramExecutionContext, execute_hidden_program,
        trace::{OwnedCiphertext, OwnedCiphertexts},
    };
    use crate::{
        BfvEvaluationKeyBundle, BfvIdentifierCiphertext, add_plain_scalar, decrypt,
        derive_identifier_key_material_from_seed, encrypt_identifier_from_seed,
        multiply_plain_scalar, ram_lfe_bfv_parameters_v1, registered_bfv_rns_modulus_chain,
    };

    // All eleven opcodes, with field-edge constants and both select branches.
    let program = build(&[
        Op::LoadInput(0, 1),
        Op::LoadInput(1, 2),
        Op::Add(2, 0, 1),
        Op::Output(2),
        Op::Mul(3, 0, 1),
        Op::Output(3),
        Op::LoadState(2, 7),
        Op::AddPlain(2, 2, 200),
        Op::Output(2),
        Op::SubPlain(2, 2, 256),
        Op::Output(2),
        Op::MulPlain(2, 2, 255),
        Op::Output(2),
        Op::StoreState(9, 2),
        Op::LoadConst(2, 256),
        Op::Output(2),
        Op::LoadState(1, 9),
        Op::Output(1),
        Op::LoadInput(0, 3),
        Op::SelectEqZero(1, 0, 2, 3),
        Op::Output(1),
        Op::LoadInput(0, 1),
        Op::SelectEqZero(1, 0, 2, 3),
        Op::Output(1),
    ]);
    let input_bytes = [250_u8, 13];
    let lanes: [u16; 32] = std::array::from_fn(|lane| match lane {
        7 => 256,
        9 => 5,
        _ => u16::try_from(lane * 3).unwrap(),
    });

    let reference = ram_lfe_reference_execute_v1(
        RamLfeClassV1::Bounded,
        &program,
        &memory(lanes),
        &RamLfeReferenceInputV1::from_bytes(&input_bytes).unwrap(),
    )
    .unwrap();

    let parameters = ram_lfe_bfv_parameters_v1();
    let (public, secret_key, relinearization_key) =
        derive_identifier_key_material_from_seed(&parameters, 63, b"reference-parity", b"context")
            .unwrap();
    let ciphertext =
        encrypt_identifier_from_seed(&public, &input_bytes, b"reference-parity-input").unwrap();
    let zero = multiply_plain_scalar(&parameters, &ciphertext.slots[0], 0).unwrap();
    let mut state = OwnedCiphertexts::with_capacity(32).unwrap();
    for lane in lanes {
        state
            .push(OwnedCiphertext(
                add_plain_scalar(&parameters, &zero, u64::from(lane)).unwrap(),
            ))
            .unwrap();
    }
    let evaluation_keys = BfvEvaluationKeyBundle {
        relinearization_key,
        rotation_keys: Vec::new(),
        galois_keys: Vec::new(),
        bootstrap_key: None,
    };
    let chain = registered_bfv_rns_modulus_chain(&parameters).unwrap();
    let context = ProgramExecutionContext {
        params: &parameters,
        evaluation_keys: &evaluation_keys,
        rns_chain: &chain,
    };
    let encoded =
        execute_hidden_program(&context, &program, &ciphertext.slots, &mut state, None).unwrap();
    let output: BfvIdentifierCiphertext = norito::decode_from_bytes(&encoded).unwrap();
    let decrypted: Vec<u16> = output
        .slots
        .iter()
        .map(|slot| {
            let plaintext = decrypt(&parameters, &secret_key, slot).unwrap();
            assert!(plaintext[1..].iter().all(|&coefficient| coefficient == 0));
            u16::try_from(plaintext[0]).unwrap()
        })
        .collect();

    assert_eq!(decrypted, reference.output().scalars());
    // The vector itself, independent of both interpreters.
    assert_eq!(
        reference.output().scalars(),
        [6, 166, 199, 200, 114, 256, 114, 256, 166]
    );
}

#[test]
fn reference_owners_keep_one_address_and_clear_on_success_error_and_unwind() {
    // A move of an owner moves a pointer: the scalars stay where they are.
    let input = RamLfeReferenceInputV1::from_bytes(b"abc").unwrap();
    let address = input.slots().as_ptr();
    let moved_input = Box::new(input);
    assert_eq!(moved_input.slots().as_ptr(), address);
    let lanes = memory([200; 32]);
    let address = lanes.lanes().as_ptr();
    let moved_lanes = Some(lanes);
    assert_eq!(moved_lanes.as_ref().unwrap().lanes().as_ptr(), address);
    // A clone is a second allocation with the same lanes.
    let clone = moved_lanes.clone().unwrap();
    assert_ne!(clone.lanes().as_ptr(), address);
    assert_eq!(Some(&clone), moved_lanes.as_ref());

    // Success: 64 input slots and twice 32 lanes clear when the owners drop.
    let before = cleared_cells();
    drop(moved_input);
    drop(moved_lanes);
    drop(clone);
    assert_eq!(cleared_cells() - before, 64 + 32 + 32);

    // Success: one execution clears its machine (4 registers and 32 lanes) and
    // its copy of the initial memory, and the caller's input and lanes clear
    // when they drop.
    let before = cleared_cells();
    {
        let input = RamLfeReferenceInputV1::from_bytes(b"abc").unwrap();
        let lanes = memory([200; 32]);
        let execution = ram_lfe_reference_execute_v1(
            RamLfeClassV1::Affine,
            &stateful_program(),
            &lanes,
            &input,
        )
        .unwrap();
        assert_eq!(execution.output().scalars(), [0, 200, 77]);
        // The machine is already cleared while the execution is still held.
        assert_eq!(cleared_cells() - before, 4 + 32);
    }
    assert_eq!(cleared_cells() - before, 4 + 32 + 32 + 64 + 32);

    // Success through the keyed evaluation: the program key, the derived
    // lanes, the machine, the execution's copy and the input.
    let before = cleared_cells();
    {
        let program = stateful_program();
        let key = key(11);
        let function = commit(RamLfeClassV1::Affine, &key, &program);
        let input = RamLfeReferenceInputV1::from_bytes(b"abc").unwrap();
        ram_lfe_reference_evaluate_v1(&function, &key, &program, b"request", &input).unwrap();
    }
    assert_eq!(cleared_cells() - before, 32 + 32 + (4 + 32) + 32 + 64);

    // Error: a rejected input or memory is refused before it is copied.
    let before = cleared_cells();
    assert!(RamLfeReferenceInputV1::from_bytes(&[0; 64]).is_err());
    let mut slots = [0_u16; 64];
    slots[0] = 2;
    slots[2] = 256;
    assert!(RamLfeReferenceInputV1::from_slots(&slots).is_err());
    assert!(RamLfeInitialMemoryV1::from_lanes(&[257; 32]).is_err());
    assert_eq!(cleared_cells() - before, 0);

    // Error: an execution its class refuses clears the owners it was given
    // and creates no machine.
    let refused = || {
        let input = RamLfeReferenceInputV1::from_bytes(&[3]).unwrap();
        let lanes = memory([1; 32]);
        let program = build(&[Op::LoadInput(0, 1), Op::Mul(0, 0, 0), Op::Output(0)]);
        ram_lfe_reference_execute_v1(RamLfeClassV1::Affine, &program, &lanes, &input).map(|_| ())
    };
    assert!(refused().is_err());
    assert_eq!(cleared_cells() - before, 64 + 32);

    // Error: a wrong program key is refused before any lane is derived, and
    // both keys and the input clear.
    let before = cleared_cells();
    let mismatched = || {
        let program = stateful_program();
        let function = commit(RamLfeClassV1::Affine, &key(11), &program);
        let input = RamLfeReferenceInputV1::from_bytes(b"abc").unwrap();
        ram_lfe_reference_evaluate_v1(&function, &key(12), &program, b"", &input).map(|_| ())
    };
    assert_eq!(mismatched(), Err(RamLfeError::CommitmentMismatch));
    assert_eq!(cleared_cells() - before, 32 + 32 + 64);

    // Unwind: a panic while the owners are live clears them.
    let before = cleared_cells();
    assert!(
        std::panic::catch_unwind(|| {
            let _input = RamLfeReferenceInputV1::from_bytes(b"abc").unwrap();
            let _lanes = memory([9; 32]);
            panic!("reference owner unwind control");
        })
        .is_err()
    );
    assert_eq!(cleared_cells() - before, 64 + 32);
}

/// An affine function with input, state and constant terms in both outputs.
fn affine_oracle_program() -> HiddenRamFheProgram {
    build(&[
        Op::LoadInput(0, 0),
        Op::MulPlain(0, 0, 3),
        Op::LoadInput(1, 1),
        Op::MulPlain(1, 1, 200),
        Op::Add(0, 0, 1),
        Op::LoadInput(1, 63),
        Op::MulPlain(1, 1, 7),
        Op::Add(0, 0, 1),
        Op::LoadState(2, 5),
        Op::Add(0, 0, 2),
        Op::AddPlain(0, 0, 91),
        Op::Output(0),
        Op::LoadInput(3, 17),
        Op::LoadState(2, 9),
        Op::MulPlain(2, 2, 2),
        Op::Add(3, 3, 2),
        Op::SubPlain(3, 3, 4),
        Op::Output(3),
    ])
}

#[test]
fn sixty_five_valid_queries_determine_an_affine_function_at_fixed_associated_data_only() {
    let program = affine_oracle_program();
    let key = key(0x33);
    let function = commit(RamLfeClassV1::Affine, &key, &program);
    // What a client sees: the opened output for an input it chose.
    let queries = std::cell::Cell::new(0_usize);
    let oracle = |associated_data: &[u8], bytes: &[u8]| -> Vec<u32> {
        queries.set(queries.get() + 1);
        ram_lfe_reference_evaluate_v1(
            &function,
            &key,
            &program,
            associated_data,
            &RamLfeReferenceInputV1::from_bytes(bytes).unwrap(),
        )
        .unwrap()
        .output()
        .scalars()
        .iter()
        .map(|&scalar| u32::from(scalar))
        .collect()
    };
    let inverse_of_63 = (1..257_u32)
        .find(|inverse| inverse * 63 % 257 == 1)
        .unwrap();

    // Every admitted input is the vector (1, length, byte 1, ..., byte 63).
    // The empty input, 63 zero bytes and the 63 unit byte strings of length 63
    // are 65 valid queries that span it.
    let empty = oracle(b"request", b"");
    let zeros = oracle(b"request", &[0; 63]);
    let units: Vec<Vec<u32>> = (0..63)
        .map(|byte| {
            let mut bytes = [0_u8; 63];
            bytes[byte] = 1;
            oracle(b"request", &bytes)
        })
        .collect();
    assert_eq!(queries.get(), RAM_LFE_V1_INPUT_SLOTS + 1);
    assert_eq!(queries.get(), 65);

    // Per output: the intercept, the coefficient of the length slot and the
    // coefficient of each byte slot.
    let outputs = empty.len();
    let length_coefficient: Vec<u32> = (0..outputs)
        .map(|output| (zeros[output] + 257 - empty[output]) * inverse_of_63 % 257)
        .collect();
    let byte_coefficients: Vec<Vec<u32>> = units
        .iter()
        .map(|unit| {
            (0..outputs)
                .map(|output| (unit[output] + 257 - zeros[output]) % 257)
                .collect()
        })
        .collect();
    let predict = |intercept: &[u32], bytes: &[u8]| -> Vec<u32> {
        (0..outputs)
            .map(|output| {
                let length = u32::try_from(bytes.len()).unwrap();
                let linear: u32 = bytes
                    .iter()
                    .zip(&byte_coefficients)
                    .map(|(&byte, coefficients)| u32::from(byte) * coefficients[output] % 257)
                    .sum();
                (intercept[output] + length * length_coefficient[output] + linear) % 257
            })
            .collect()
    };

    // The client now predicts every output for this associated data without
    // another query.
    let fresh: [&[u8]; 4] = [b"+15551234567", &[255; 63], &[1], b"\x00\xffA"];
    for bytes in fresh {
        assert_eq!(predict(&empty, bytes), oracle(b"request", bytes));
    }

    // Another associated-data value has other state lanes. The 65 queries do
    // not give its intercept: the prediction fails there.
    let other_empty = oracle(b"other request", b"");
    assert_ne!(other_empty, empty);
    assert_ne!(
        predict(&empty, b"+15551234567"),
        oracle(b"other request", b"+15551234567")
    );
    // The linear part is the same in every context, so one more query, the
    // intercept of the new context, completes the map there too.
    for bytes in fresh {
        assert_eq!(
            predict(&other_empty, bytes),
            oracle(b"other request", bytes)
        );
    }
}

/// The ordered-output frame, declared again from the specification.
#[derive(norito::Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_crypto::ram_lfe::RamLfeOrderedOutputInputV1",
    frame = "iroha_crypto::ram_lfe::RamLfeOrderedOutputInputV1"
)]
struct OwnedOrderedOutputFrame {
    blinding: Vec<u8>,
    output_count: u16,
    scalars: Vec<u8>,
}

/// The output commitment of an opening, with the frame recomputed independently.
fn output_commitment(output: &RamLfeOrderedOutputV1, output_count: u16) -> [u8; 32] {
    use crate::ram_lfe::canonical::{RamLfeOutputBlindingV1, RamLfeOutputCommitmentV1};

    let commitment = *RamLfeOutputCommitmentV1::commit(
        output,
        &RamLfeOutputBlindingV1::from_bytes([3; 32]).unwrap(),
    )
    .unwrap()
    .as_bytes();
    let frame = norito::encode_canonical(&OwnedOrderedOutputFrame {
        blinding: vec![3; 32],
        output_count,
        scalars: output
            .scalars()
            .iter()
            .flat_map(|scalar| scalar.to_le_bytes())
            .collect(),
    })
    .unwrap();
    let mut hasher = blake3::Hasher::new_derive_key("iroha.ram_lfe.v1.ordered_output");
    hasher.update(&frame);
    assert_eq!(&commitment, hasher.finalize().as_bytes());
    commitment
}

#[test]
fn an_opening_commits_the_sixty_four_padded_output_slots() {
    let output = |scalars: &[u16]| RamLfeOrderedOutputV1::from_scalars(scalars).unwrap();
    let slots = |scalars: &[u16]| {
        let mut slots = [0_u16; RAM_LFE_V1_MAX_OUTPUTS];
        slots[..scalars.len()].copy_from_slice(scalars);
        slots
    };

    // A short output: the scalars in order, then zeros up to 64 slots. A zero
    // the tape emitted between two scalars keeps its place.
    let short = output(&[7, 0, 256]);
    let padded = short.padded_for_opening();
    assert_eq!(padded.scalars(), slots(&[7, 0, 256]));
    assert_eq!(padded.scalars().len(), 64);
    // The opening commits the 64 slots: `output_count` is 64 in its frame, and
    // the commitment is not the one of the three emitted scalars.
    assert_ne!(output_commitment(&padded, 64), output_commitment(&short, 3));
    // The reference output is unchanged: padding is a rule for openings.
    assert_eq!(short.scalars(), [7, 0, 256]);

    // Trailing zeros the tape emitted are indistinguishable from padding: every
    // output count from the last nonzero slot on gives the same 64 slots and
    // the same commitment under one blinding.
    let opened = output_commitment(&output(&[7]).padded_for_opening(), 64);
    for count in 1..=64 {
        let mut emitted = vec![0_u16; count];
        emitted[0] = 7;
        let padded = output(&emitted).padded_for_opening();
        assert_eq!(padded.scalars(), slots(&[7]));
        assert_eq!(output_commitment(&padded, 64), opened);
        // What the 64 slots do tell: the count reaches the last nonzero slot.
        let last_nonzero = padded.scalars().iter().rposition(|&scalar| scalar != 0);
        assert_eq!(last_nonzero, Some(0));
        assert!(count > last_nonzero.unwrap());
    }
    // An output of zeros only tells nothing about its count.
    for count in [1, 2, 63, 64] {
        assert_eq!(
            output(&vec![0; count]).padded_for_opening().scalars(),
            [0; 64]
        );
    }

    // 64 outputs fill every slot: nothing is added, and the opening commits
    // exactly what the reference output is.
    let full: Vec<u16> = (0..64).map(|slot| 256 - slot).collect();
    let full = output(&full);
    assert_eq!(full.padded_for_opening(), full);
    assert_eq!(
        output_commitment(&full.padded_for_opening(), 64),
        output_commitment(&full, 64)
    );
    // Padding an opened output again changes nothing.
    assert_eq!(padded.padded_for_opening(), padded);
}

#[test]
fn opened_slots_of_two_tapes_differ_only_where_their_outputs_do() {
    // The differential check of an opening against the reference: the 64
    // opened slots equal the reference output padded with zeros.
    let one = [Op::LoadInput(0, 1), Op::AddPlain(0, 0, 1), Op::Output(0)];
    // The same tape followed by two outputs that are zero for every input.
    let mut two = one.to_vec();
    two.extend([Op::LoadConst(1, 0), Op::Output(1), Op::Output(1)]);
    // And one whose second output is zero for exactly one input byte.
    let mut three = one.to_vec();
    three.extend([Op::SubPlain(1, 0, 6), Op::Output(1)]);
    let opened = |tape: &[Op], byte: u8| {
        let execution = ram_lfe_reference_execute_v1(
            RamLfeClassV1::Affine,
            &build(tape),
            &memory([0; 32]),
            &RamLfeReferenceInputV1::from_bytes(&[byte]).unwrap(),
        )
        .unwrap();
        let padded = execution.output().padded_for_opening();
        assert_eq!(padded.scalars().len(), 64);
        assert_eq!(
            padded.scalars()[..execution.output().scalars().len()],
            *execution.output().scalars()
        );
        (execution.output().scalars().len(), padded)
    };
    for byte in 0..=255_u8 {
        let (count_one, slots_one) = opened(&one, byte);
        let (count_two, slots_two) = opened(&two, byte);
        let (count_three, slots_three) = opened(&three, byte);
        assert_eq!((count_one, count_two, count_three), (1, 3, 2));
        // One output or three: the opener and the beneficiary see the same
        // 64 slots for every input, so the count reaches neither of them.
        assert_eq!(slots_one, slots_two);
        // A second output that is not always zero shows where it is not.
        assert_eq!(slots_one == slots_three, byte == 5, "{byte}");
    }
}

#[test]
fn field_slots_bypass_admission_for_tests_only() {
    // 64 scalars no admitted input has: a length slot of 256 and byte slots
    // of 256.
    let slots = [256_u16; RAM_LFE_V1_INPUT_SLOTS];
    assert!(RamLfeReferenceInputV1::from_slots(&slots).is_err());
    let input = RamLfeReferenceInputV1::from_field_slots(&slots);
    assert_eq!(input.slots(), &slots);
    // The interpreter computes on them as on any scalar of the field.
    let execution = ram_lfe_reference_execute_v1(
        RamLfeClassV1::Bounded,
        &build(&[
            Op::LoadInput(0, 0),
            Op::LoadInput(1, 63),
            Op::Mul(2, 0, 1),
            Op::Output(2),
            Op::Output(0),
        ]),
        &memory([0; 32]),
        &input,
    )
    .unwrap();
    assert_eq!(execution.output().scalars(), [1, 256]);
    // An admitted input is the same owner through either constructor.
    let admitted = RamLfeReferenceInputV1::from_bytes(b"ab").unwrap();
    assert_eq!(
        RamLfeReferenceInputV1::from_field_slots(admitted.slots()).slots(),
        admitted.slots()
    );
    // A value outside the field is refused here too.
    let mut outside = [0_u16; RAM_LFE_V1_INPUT_SLOTS];
    outside[9] = 257;
    assert!(
        std::panic::catch_unwind(|| RamLfeReferenceInputV1::from_field_slots(&outside)).is_err()
    );
}
