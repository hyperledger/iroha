//! Exact equality of the normal form with the cleartext reference, folding,
//! boundaries, class shapes and clearing.

use super::*;
use crate::ram_lfe::{
    HiddenRamFheInstruction as Op,
    canonical::{RamLfeFunctionIdentityV1, RamLfeProgramKeyV1, RamLfeQueryLimitV1},
    class::RamLfeRefreshPointV1,
    reference::{ram_lfe_reference_evaluate_v1, ram_lfe_reference_execute_v1},
    specification_tests::repository_file,
};
use rand::{Rng as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;

const BASE: usize = RAM_LFE_V1_NORMAL_BASE_COLUMNS;
const INPUT: usize = RAM_LFE_V1_NORMAL_INPUT_COLUMN;
const LANE: usize = RAM_LFE_V1_NORMAL_LANE_COLUMN;

fn build(instructions: &[Op]) -> HiddenRamFheProgram {
    let mut builder = HiddenRamFheProgram::builder().unwrap();
    for &instruction in instructions {
        builder.push(instruction).unwrap();
    }
    builder.finish().unwrap()
}

fn memory(lanes: [u16; 32]) -> RamLfeInitialMemoryV1 {
    RamLfeInitialMemoryV1::from_lanes(&lanes).unwrap()
}

fn input(bytes: &[u8]) -> RamLfeReferenceInputV1 {
    RamLfeReferenceInputV1::from_bytes(bytes).unwrap()
}

fn normalize(class: RamLfeClassV1, instructions: &[Op]) -> RamLfeNormalFormV1 {
    ram_lfe_reference_normalize_v1(class, &build(instructions)).unwrap()
}

/// An affine form of `columns` coefficients that is zero except at `terms`.
fn form(columns: usize, terms: &[(usize, u16)]) -> Vec<u16> {
    let mut form = vec![0; columns];
    for &(column, coefficient) in terms {
        form[column] = coefficient;
    }
    form
}

/// `base^exponent` modulo 257 by repeated multiplication.
fn power(base: u16, exponent: usize) -> u16 {
    (0..exponent).fold(1, |product, _| multiply(product, base))
}

/// Compare one execution: the ordered output, the 64 slots an opening of it
/// commits and the machine the tape leaves.
fn assert_equal_on(
    class: RamLfeClassV1,
    program: &HiddenRamFheProgram,
    normal: &RamLfeNormalFormV1,
    lanes: &RamLfeInitialMemoryV1,
    input: &RamLfeReferenceInputV1,
) {
    let reference = ram_lfe_reference_execute_v1(class, program, lanes, input).unwrap();
    let output = normal.evaluate(lanes, input).unwrap();
    assert_eq!(output.scalars(), reference.output().scalars());
    // The padded output an opening commits: the reference output, then zeros.
    let opened = output.padded_for_opening();
    let emitted = reference.output().scalars().len();
    assert_eq!(opened.scalars().len(), RAM_LFE_V1_MAX_OUTPUTS);
    assert_eq!(opened.scalars()[..emitted], *reference.output().scalars());
    assert!(opened.scalars()[emitted..].iter().all(|&slot| slot == 0));
    let last = reference.trace().step_count();
    assert_eq!(
        normal
            .evaluate_final_state(lanes, input)
            .unwrap()
            .as_slice(),
        reference.trace().snapshot(last).unwrap()
    );
}

/// Whether two normal forms are one normal form: the same gates with the same
/// operand forms, in order, and the same output forms, in order.
fn same_normal_form(one: &RamLfeNormalFormV1, other: &RamLfeNormalFormV1) -> bool {
    one.gate_count() == other.gate_count()
        && one.output_count() == other.output_count()
        && (0..one.gate_count()).all(|gate| {
            one.gate_kind(gate) == other.gate_kind(gate)
                && (0..GATE_OPERANDS).all(|operand| {
                    one.gate_operand(gate, operand) == other.gate_operand(gate, operand)
                })
        })
        && (0..one.output_count())
            .all(|output| one.output_form(output) == other.output_form(output))
}

/// The gates a tape must leave, from the tape and the canonical schedule alone.
fn expected_gates(
    program: &HiddenRamFheProgram,
    report: &RamLfeClassReportV1,
) -> Vec<RamLfeNormalGateKindV1> {
    let mut expected = Vec::new();
    let mut refreshes = report.refresh_points().peekable();
    for (index, instruction) in program.instructions().enumerate() {
        while refreshes
            .next_if(|point| usize::from(point.instruction) == index)
            .is_some()
        {
            expected.push(RamLfeNormalGateKindV1::Refresh);
        }
        match instruction.opcode() {
            RamLfeOpcodeV1::Mul => expected.push(RamLfeNormalGateKindV1::Mul),
            RamLfeOpcodeV1::SelectEqZero => expected.push(RamLfeNormalGateKindV1::SelectEqZero),
            _ => {}
        }
    }
    assert!(refreshes.next().is_none());
    expected
}

/// What holds for the normal form of every member tape.
fn assert_invariants(
    class: RamLfeClassV1,
    program: &HiddenRamFheProgram,
    normal: &RamLfeNormalFormV1,
) {
    let report = class.membership(program).unwrap();
    let shape = RamLfeNormalShapeV1::of(class);
    let count = |role: RamLfeNormalRoleV1| {
        program
            .instructions()
            .filter(|instruction| RamLfeNormalRoleV1::of(instruction.opcode()) == role)
            .count()
    };
    let nonlinear = count(RamLfeNormalRoleV1::Boundary);
    let refreshes = usize::from(report.refresh_count());

    // Every nonlinear instruction and every scheduled refresh is one gate, in
    // execution order, and nothing else is a gate.
    assert_eq!(normal.class(), class);
    assert_eq!(normal.gate_count(), nonlinear + refreshes);
    let kinds: Vec<_> = (0..normal.gate_count())
        .map(|gate| normal.gate_kind(gate).unwrap())
        .collect();
    assert_eq!(kinds, expected_gates(program, &report));
    assert!(normal.gate_kind(normal.gate_count()).is_none());
    assert_eq!(
        normal.ciphertext_multiplications(),
        report.ciphertext_multiplications()
    );
    assert_eq!(
        normal.report().ciphertext_multiplications(),
        report.ciphertext_multiplications()
    );
    assert_eq!(normal.output_count(), count(RamLfeNormalRoleV1::Snapshot));
    assert_eq!(normal.output_count(), usize::from(report.output_count()));
    assert_eq!(normal.columns(), BASE + normal.gate_count());

    // The form fits the shape of its class, whatever the tape is.
    assert!(nonlinear <= usize::from(shape.nonlinear_gates));
    assert!(refreshes <= usize::from(shape.refreshes));
    assert!(normal.output_count() <= usize::from(shape.outputs));
    assert!(normal.columns() <= usize::from(shape.columns));
    assert!(normal.ciphertext_multiplications() <= shape.ciphertext_multiplications);
    // An output and a nonlinear gate are one instruction each, so the two
    // bounds exclude each other: 64 outputs leave at most 192 gates.
    assert!(nonlinear + normal.output_count() <= RAM_LFE_V1_MAX_INSTRUCTIONS);

    // Logical rank bounds the multiplication depth.
    assert!(normal.depth() <= report.peak_rank());
    assert!(report.peak_rank() <= class.max_rank());
    assert!(normal.depth() <= shape.depth);

    // Every coefficient is reduced, and a gate reads only earlier columns.
    let reduced = |form: &[u16]| form.iter().all(|&coefficient| coefficient <= 256);
    for (gate, kind) in kinds.iter().enumerate() {
        for operand in 0..kind.operand_count() {
            let form = normal.gate_operand(gate, operand).unwrap();
            assert_eq!(form.len(), BASE + gate);
            assert!(reduced(form));
        }
        assert!(normal.gate_operand(gate, kind.operand_count()).is_none());
    }
    for output in 0..normal.output_count() {
        let form = normal.output_form(output).unwrap();
        assert_eq!(form.len(), normal.columns());
        assert!(reduced(form));
    }
    assert!(normal.output_form(normal.output_count()).is_none());
    for register in 0..RAM_LFE_V1_REGISTERS {
        assert!(reduced(normal.register_form(register).unwrap()));
    }
    for lane in 0..RAM_LFE_V1_STATE_LANES {
        assert!(reduced(normal.lane_form(lane).unwrap()));
    }
    assert!(normal.register_form(RAM_LFE_V1_REGISTERS).is_none());
    assert!(normal.lane_form(RAM_LFE_V1_STATE_LANES).is_none());
}

fn random_scalar(rng: &mut ChaCha20Rng) -> u16 {
    const EDGES: [u16; 7] = [0, 1, 2, 128, 129, 255, 256];
    if rng.random_range(0..2) == 0 {
        EDGES[rng.random_range(0..EDGES.len())]
    } else {
        rng.random_range(0..=256)
    }
}

fn random_lanes(rng: &mut ChaCha20Rng) -> RamLfeInitialMemoryV1 {
    memory(std::array::from_fn(|_| random_scalar(rng)))
}

fn random_input(rng: &mut ChaCha20Rng) -> RamLfeReferenceInputV1 {
    let length = match rng.random_range(0..4) {
        0 => 0,
        1 => 63,
        _ => rng.random_range(0..=63),
    };
    let bytes: Vec<u8> = (0..length)
        .map(|_| match rng.random_range(0..4) {
            0 => 0,
            1 => 255,
            _ => rng.random_range(0..=255),
        })
        .collect();
    input(&bytes)
}

/// 64 arbitrary scalars of the field as input slots: not an admitted input.
fn random_field_input(rng: &mut ChaCha20Rng) -> RamLfeReferenceInputV1 {
    RamLfeReferenceInputV1::from_field_slots(&std::array::from_fn(|_| random_scalar(rng)))
}

/// Whether a tape prefix, closed by an output when it has none, is in the class.
fn is_member(class: RamLfeClassV1, tape: &[Op], outputs: usize) -> bool {
    let mut complete = tape.to_vec();
    if outputs == 0 {
        complete.push(Op::Output(0));
    }
    class.membership(&build(&complete)).is_ok()
}

/// A random member tape of exactly `length` instructions.
fn random_tape(rng: &mut ChaCha20Rng, class: RamLfeClassV1, length: usize) -> Vec<Op> {
    let mut tape = Vec::with_capacity(length);
    let mut outputs = 0;
    while tape.len() < length {
        let mut register = || rng.random_range(0..4_u16);
        let (a, b, c, d) = (register(), register(), register(), register());
        let lane = rng.random_range(0..32_u16);
        let slot = rng.random_range(0..64_u16);
        let immediate = u64::from(random_scalar(rng));
        let last = tape.len() + 1 == length;
        let candidate = if last && outputs == 0 {
            Op::Output(a)
        } else {
            match rng.random_range(0..22) {
                0..=1 => Op::LoadInput(a, slot),
                2..=3 => Op::LoadState(a, lane),
                4..=5 => Op::StoreState(lane, a),
                6 => Op::LoadConst(a, immediate),
                7..=9 => Op::Add(a, b, c),
                10..=11 => Op::AddPlain(a, b, immediate),
                12..=13 => Op::SubPlain(a, b, immediate),
                14..=16 => Op::MulPlain(a, b, immediate),
                17..=18 => Op::Mul(a, b, c),
                19 => Op::SelectEqZero(a, b, c, d),
                _ => Op::Output(a),
            }
        };
        let candidate = match candidate.opcode() {
            RamLfeOpcodeV1::Output if outputs == RAM_LFE_V1_MAX_OUTPUTS => Op::LoadInput(a, slot),
            opcode if !class.admits(opcode) => Op::MulPlain(a, b, immediate),
            RamLfeOpcodeV1::Mul | RamLfeOpcodeV1::SelectEqZero => {
                // Keep a nonlinear instruction only while the tape stays in the class.
                tape.push(candidate);
                let member = is_member(class, &tape, outputs);
                tape.pop();
                if member {
                    candidate
                } else {
                    Op::LoadInput(a, slot)
                }
            }
            _ => candidate,
        };
        outputs += usize::from(matches!(candidate, Op::Output(_)));
        tape.push(candidate);
    }
    tape
}

#[test]
fn normal_form_equals_the_reference_on_randomized_tapes_of_every_class() {
    const TAPES: usize = 120;
    for class in RamLfeClassV1::ALL {
        let seed =
            0x5230_0000 + u64::from(class.max_rank()) * 256 + u64::from(class.max_refreshes());
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (mut gates, mut refreshes, mut longest, mut folded) = (0, 0, 0, 0);
        let mut unadmitted = 0;
        for round in 0..TAPES {
            let length = match round % 4 {
                0 => RAM_LFE_V1_MAX_INSTRUCTIONS,
                1 => rng.random_range(1..=12),
                2 => rng.random_range(13..=96),
                _ => rng.random_range(97..RAM_LFE_V1_MAX_INSTRUCTIONS),
            };
            let tape = random_tape(&mut rng, class, length);
            let program = build(&tape);
            let normal = ram_lfe_reference_normalize_v1(class, &program).unwrap();
            assert_invariants(class, &program, &normal);
            for _ in 0..3 {
                assert_equal_on(
                    class,
                    &program,
                    &normal,
                    &random_lanes(&mut rng),
                    &random_input(&mut rng),
                );
            }
            // The identity does not depend on admission: it holds on every 64
            // scalars of the field in the input slots.
            for _ in 0..3 {
                let slots = random_field_input(&mut rng);
                unadmitted +=
                    usize::from(RamLfeReferenceInputV1::from_slots(slots.slots()).is_err());
                assert_equal_on(class, &program, &normal, &random_lanes(&mut rng), &slots);
            }
            // A member tape has one normal form under every class that admits it.
            for larger in RamLfeClassV1::ALL
                .into_iter()
                .filter(|other| *other > class)
            {
                let other = ram_lfe_reference_normalize_v1(larger, &program).unwrap();
                assert!(same_normal_form(&normal, &other), "{class} under {larger}");
                assert_eq!(normal.depth(), other.depth());
            }
            gates += normal.gate_count();
            refreshes += usize::from(normal.report().refresh_count());
            longest = longest.max(program.instruction_count());
            folded += tape
                .iter()
                .filter(|instruction| {
                    RamLfeNormalRoleV1::of(instruction.opcode()) == RamLfeNormalRoleV1::Folded
                })
                .count();
        }
        // The corpus exercised what the class admits, at the maximum length.
        assert_eq!(longest, RAM_LFE_V1_MAX_INSTRUCTIONS);
        assert!(folded > TAPES);
        // No random slot vector happened to be an admitted input.
        assert_eq!(unadmitted, 3 * TAPES);
        assert_eq!(gates > 0, class != RamLfeClassV1::Affine, "{class}");
        assert_eq!(refreshes > 0, class == RamLfeClassV1::Refresh, "{class}");
    }
}

fn repeat(tape: &mut Vec<Op>, count: usize, instruction: Op) {
    tape.extend(std::iter::repeat_n(instruction, count));
}

/// One load, `rank` squarings, `scales` constant multiplications, `outputs` outputs.
fn frontier(rank: usize, scales: usize, outputs: usize) -> Vec<Op> {
    let mut tape = vec![Op::LoadInput(0, 0)];
    repeat(&mut tape, rank, Op::Mul(0, 0, 0));
    repeat(&mut tape, scales, Op::MulPlain(0, 0, 128));
    repeat(&mut tape, outputs, Op::Output(0));
    tape
}

/// The nine maximum-shape tape families of the RNS-BGV cost model, as
/// `crates/iroha_fhe/tests/support/machine.rs` defines them. One test compares
/// their instruction, output and rank counts with the recorded summary;
/// another fails when the definitions there change, so this mirror cannot go
/// stale silently.
fn maximum_shape_families() -> Vec<(&'static str, RamLfeClassV1, Vec<Op>)> {
    let affine_loads = {
        let mut tape: Vec<Op> = (0..255_u16)
            .map(|index| Op::LoadInput(index % 4, index % 64))
            .collect();
        tape.push(Op::Output(254 % 4));
        tape
    };
    let affine_state_and_registers = {
        let mut tape = Vec::new();
        for register in 0..4 {
            tape.push(Op::LoadInput(register, register));
        }
        for lane in 0..32 {
            tape.push(Op::StoreState(lane, lane % 4));
        }
        for round in 0..26 {
            tape.extend([
                Op::LoadState(0, round % 32),
                Op::AddPlain(0, 0, 5),
                Op::SubPlain(0, 0, 3),
                Op::Add(1, 0, 1),
                Op::LoadConst(2, 7),
                Op::Add(3, 2, 3),
            ]);
        }
        for index in 0..64 {
            tape.push(Op::Output(index % 4));
        }
        tape
    };
    let bounded_selects = {
        let mut tape = Vec::new();
        repeat(&mut tape, 255, Op::SelectEqZero(0, 1, 2, 3));
        tape.push(Op::Output(0));
        tape
    };
    let bounded_scaled_rank_chain = {
        let mut tape = vec![Op::LoadInput(0, 0)];
        repeat(&mut tape, 238, Op::MulPlain(0, 0, 128));
        repeat(&mut tape, 16, Op::Mul(0, 0, 0));
        tape.push(Op::Output(0));
        tape
    };
    let bounded_alternating_rank_chain = {
        let mut tape = vec![Op::LoadInput(0, 0)];
        for _ in 0..16 {
            tape.push(Op::MulPlain(0, 0, 128));
            tape.push(Op::Mul(0, 0, 0));
        }
        tape.push(Op::MulPlain(0, 0, 128));
        repeat(&mut tape, 64, Op::Output(0));
        tape
    };
    let bounded_select_then_products = {
        let mut tape = vec![
            Op::LoadInput(0, 5),
            Op::LoadInput(1, 9),
            Op::LoadConst(2, 77),
            Op::SelectEqZero(3, 0, 1, 2),
        ];
        repeat(&mut tape, 6, Op::Mul(3, 3, 3));
        repeat(&mut tape, 64, Op::Output(3));
        tape
    };
    vec![
        ("affine.loads", RamLfeClassV1::Affine, affine_loads),
        (
            "affine.scale_chain",
            RamLfeClassV1::Affine,
            frontier(0, 254, 1),
        ),
        (
            "affine.scale_then_outputs",
            RamLfeClassV1::Affine,
            frontier(0, 191, 64),
        ),
        (
            "affine.state_and_registers",
            RamLfeClassV1::Affine,
            affine_state_and_registers,
        ),
        ("bounded.selects", RamLfeClassV1::Bounded, bounded_selects),
        (
            "bounded.scaled_rank_chain",
            RamLfeClassV1::Bounded,
            bounded_scaled_rank_chain,
        ),
        (
            "bounded.rank_chain_outputs",
            RamLfeClassV1::Bounded,
            frontier(16, 0, 64),
        ),
        (
            "bounded.alternating_rank_chain",
            RamLfeClassV1::Bounded,
            bounded_alternating_rank_chain,
        ),
        (
            "bounded.select_then_products",
            RamLfeClassV1::Bounded,
            bounded_select_then_products,
        ),
    ]
}

fn family(name: &str) -> (RamLfeClassV1, Vec<Op>) {
    maximum_shape_families()
        .into_iter()
        .find(|(candidate, _, _)| *candidate == name)
        .map_or_else(
            || panic!("no maximum-shape family {name}"),
            |(_, class, tape)| (class, tape),
        )
}

#[test]
fn normal_form_equals_the_reference_on_every_maximum_shape_family() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5230_00c3);
    for (name, class, tape) in maximum_shape_families() {
        let program = build(&tape);
        // A tape of a smaller class is a member of every larger class and has
        // the same normal form there: the class decides membership only.
        let smallest = ram_lfe_reference_normalize_v1(class, &program).unwrap();
        for larger in RamLfeClassV1::ALL
            .into_iter()
            .filter(|other| *other >= class)
        {
            let normal = ram_lfe_reference_normalize_v1(larger, &program).unwrap();
            assert_invariants(larger, &program, &normal);
            assert!(same_normal_form(&normal, &smallest), "{name}");
            assert_eq!(normal.depth(), smallest.depth(), "{name}");
            for bytes in [&[][..], &[0; 63], &[255; 63], &[1, 2, 3]] {
                assert_equal_on(
                    larger,
                    &program,
                    &normal,
                    &random_lanes(&mut rng),
                    &input(bytes),
                );
            }
            for _ in 0..4 {
                assert_equal_on(
                    larger,
                    &program,
                    &normal,
                    &random_lanes(&mut rng),
                    &random_input(&mut rng),
                );
                assert_equal_on(
                    larger,
                    &program,
                    &normal,
                    &random_lanes(&mut rng),
                    &random_field_input(&mut rng),
                );
            }
        }
    }
}

#[cfg(feature = "json")]
#[test]
fn maximum_shape_families_are_the_recorded_counterexample_tapes() {
    use crate::ram_lfe::specification_tests::{cost_summary, json_at, json_count};

    let summary = cost_summary();
    let recorded = json_at(&summary, &["tape_lowering", "families"])
        .as_object()
        .expect("families");
    let families = maximum_shape_families();
    assert_eq!(recorded.len(), families.len());
    for (name, class, tape) in families {
        let record = json_at(&summary, &["tape_lowering", "families", name]);
        assert_eq!(
            record.get("class").and_then(norito::json::Value::as_str),
            Some(class.as_str()),
            "{name}"
        );
        let report = class.membership(&build(&tape)).unwrap();
        assert_eq!(
            json_count(record, "instructions"),
            u64::try_from(tape.len()).unwrap(),
            "{name}"
        );
        assert_eq!(
            json_count(record, "outputs"),
            u64::from(report.output_count()),
            "{name}"
        );
        assert_eq!(
            json_count(record, "peak_rank"),
            u64::from(report.peak_rank()),
            "{name}"
        );
    }

    // The shape the cost model plans for is the candidate shape of the classes.
    let shape = json_at(&summary, &["tape_lowering", "shape"]);
    let count = |value: usize| u64::try_from(value).unwrap();
    for (key, expected) in [
        ("registers", count(RAM_LFE_V1_REGISTERS)),
        ("state_lanes", count(RAM_LFE_V1_STATE_LANES)),
        ("input_slots", count(RAM_LFE_V1_INPUT_SLOTS)),
        ("max_instructions", count(RAM_LFE_V1_MAX_INSTRUCTIONS)),
        ("max_outputs", count(RAM_LFE_V1_MAX_OUTPUTS)),
        (
            "bounded_max_rank",
            u64::from(RamLfeClassV1::Bounded.max_rank()),
        ),
        (
            "refresh_max_rank_between_refreshes",
            u64::from(RamLfeClassV1::Refresh.max_rank()),
        ),
        (
            "refresh_max_refreshes",
            u64::from(RamLfeClassV1::Refresh.max_refreshes()),
        ),
        (
            "select_multiplications",
            u64::from(RAM_LFE_V1_SELECT_CONDITION_RANK),
        ),
    ] {
        assert_eq!(json_count(shape, key), expected, "{key}");
    }
}

/// Text between two markers of a source file, the first included.
fn section<'a>(source: &'a str, from: &str, to: Option<&str>) -> &'a str {
    let start = source
        .find(from)
        .unwrap_or_else(|| panic!("the cost model no longer contains `{from}`"));
    let end = to.map_or(source.len(), |to| {
        start
            + source[start..]
                .find(to)
                .unwrap_or_else(|| panic!("the cost model no longer contains `{to}`"))
    });
    &source[start..end]
}

/// Code of a source section, independent of its layout: no comment lines, no
/// whitespace and no trailing comma before a closing bracket.
fn code_only(section: &str) -> String {
    let code: String = section
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .flat_map(str::split_whitespace)
        .collect();
    code.replace(",)", ")")
        .replace(",]", "]")
        .replace(",}", "}")
}

#[test]
fn code_only_drops_comments_and_layout() {
    let source =
        "a\nmod m {\n    /// doc\n    fn f() {\n        // note\n        1\n    }\n}\ntail";
    assert_eq!(
        section(source, "mod m", Some("tail")),
        &source[2..source.len() - 4]
    );
    assert!(section(source, "fn f", None).starts_with("fn f() {"));
    assert!(section(source, "fn f", None).ends_with("}\ntail"));
    assert_eq!(
        code_only(section(source, "mod m", Some("tail"))),
        "modm{fnf(){1}}"
    );
    // Only whole comment lines are dropped, and line endings do not matter.
    assert_eq!(code_only("  x  //kept\r\n//dropped\n\ty"), "x//kepty");
    // A call laid out on one line or on several is one text.
    assert_eq!(code_only("f(\n    a,\n    [b, c,],\n)"), "f(a,[b,c])");
    assert_eq!(code_only("f(a, [b, c])"), "f(a,[b,c])");
}

/// Digest of the code that defines the nine families in the cost model, as it
/// stood when [`maximum_shape_families`] was mirrored from it.
const COST_MODEL_FAMILY_SOURCE_DIGEST: &str =
    "783ec9ca3a11d0ce2635f90e4ba99548f969283ced89c670b9aab760af45e1e5";

#[test]
fn mirrored_maximum_shape_families_follow_the_cost_model_source() {
    // The cost summary records four numbers of each family, so a family could
    // change an operand, a scalar or the order of a run and keep all four. The
    // mirror is therefore tied to the definitions themselves: the family
    // builders and the table that names them, without the per-instruction
    // profile tapes between the two.
    let source = repository_file("crates/iroha_fhe/tests/support/machine.rs");
    let builders = section(
        &source,
        "pub mod families {",
        Some("    /// One instruction of every `affine.v1` opcode"),
    );
    let names = section(
        &source,
        "    /// Every named family with the class it belongs to.",
        None,
    );
    let table = code_only(names);
    let code = format!("{}{table}", code_only(builders));
    assert_eq!(
        hex::encode(crate::Hash::new(code.as_bytes()).as_ref()),
        COST_MODEL_FAMILY_SOURCE_DIGEST,
        "the tape families of the cost model changed: compare the nine tapes of \
         `maximum_shape_families` with crates/iroha_fhe/tests/support/machine.rs, \
         then record the new digest"
    );
    // The table names the nine mirrored families, in the mirrored order, each
    // with its class and its own builder.
    let mirrored = maximum_shape_families();
    let mut rest = table.as_str();
    for (name, class, _) in &mirrored {
        let entry = format!("(\"{class}\",\"{name}\",{}())", name.replace('.', "_"));
        let found = rest.find(&entry).unwrap_or_else(|| {
            panic!("the cost model does not list {entry} in the mirrored order")
        });
        rest = &rest[found + entry.len()..];
    }
    assert_eq!(table.matches("(\"").count(), mirrored.len());
    // The limits the builders are written against are the limits of the classes.
    for constant in [
        format!("pub const REGISTERS: usize = {RAM_LFE_V1_REGISTERS};"),
        format!("pub const STATE_LANES: usize = {RAM_LFE_V1_STATE_LANES};"),
        format!("pub const INPUT_SLOTS: usize = {RAM_LFE_V1_INPUT_SLOTS};"),
        format!("pub const MAX_INSTRUCTIONS: usize = {RAM_LFE_V1_MAX_INSTRUCTIONS};"),
        format!("pub const MAX_OUTPUTS: usize = {RAM_LFE_V1_MAX_OUTPUTS};"),
        format!(
            "pub const BOUNDED_MAX_RANK: usize = {};",
            RamLfeClassV1::Bounded.max_rank()
        ),
        format!(
            "pub const SELECT_SQUARINGS: usize = {};",
            RAM_LFE_V1_SELECT_CONDITION_RANK - 2
        ),
        "pub const SELECT_MULTIPLICATIONS: usize = SELECT_SQUARINGS + 2;".to_owned(),
        "const SCALE: u64 = 128;".to_owned(),
    ] {
        assert!(
            source.contains(&constant),
            "the cost model no longer declares `{constant}`"
        );
    }
}

#[test]
fn plaintext_runs_fold_into_one_reduced_coefficient() {
    // 254 sequential constant multiplications at logical rank zero: the family
    // no existing candidate holds when it is lowered instruction by
    // instruction. Its normal form is one output with one coefficient.
    let (class, tape) = family("affine.scale_chain");
    let scales = tape
        .iter()
        .filter(|instruction| instruction.opcode() == RamLfeOpcodeV1::MulPlain)
        .count();
    assert_eq!(scales, 254);
    let normal = normalize(class, &tape);
    assert_eq!(normal.report().peak_rank(), 0);
    assert_eq!(normal.report().ciphertext_multiplications(), 0);
    assert_eq!((normal.gate_count(), normal.output_count()), (0, 1));
    assert_eq!(normal.depth(), 0);
    let coefficient = power(128, 254);
    assert_eq!(coefficient, 4);
    assert_eq!(
        normal.output_form(0).unwrap(),
        form(BASE, &[(INPUT, coefficient)])
    );

    // 191 multiplications and 64 outputs: 64 equal rows of one coefficient.
    let (class, tape) = family("affine.scale_then_outputs");
    let normal = normalize(class, &tape);
    assert_eq!((normal.gate_count(), normal.output_count()), (0, 64));
    assert_eq!(power(128, 191), 255);
    for output in 0..64 {
        assert_eq!(
            normal.output_form(output).unwrap(),
            form(BASE, &[(INPUT, 255)])
        );
    }

    // 238 multiplications below a rank-16 chain: the run folds into the two
    // operands of the first product, and the sixteen products stay gates.
    let (class, tape) = family("bounded.scaled_rank_chain");
    let normal = normalize(class, &tape);
    assert_eq!((normal.gate_count(), normal.output_count()), (16, 1));
    assert_eq!(normal.depth(), 16);
    assert_eq!(normal.report().peak_rank(), 16);
    let folded = form(BASE, &[(INPUT, power(128, 238))]);
    assert_eq!(normal.gate_operand(0, 0).unwrap(), folded);
    assert_eq!(normal.gate_operand(0, 1).unwrap(), folded);
    for gate in 1..16 {
        let previous = form(BASE + gate, &[(BASE + gate - 1, 1)]);
        assert_eq!(normal.gate_kind(gate), Some(RamLfeNormalGateKindV1::Mul));
        assert_eq!(normal.gate_operand(gate, 0).unwrap(), previous);
        assert_eq!(normal.gate_operand(gate, 1).unwrap(), previous);
    }
    assert_eq!(
        normal.output_form(0).unwrap(),
        form(BASE + 16, &[(BASE + 15, 1)])
    );

    // A constant multiplication between products folds into the next operands.
    let (class, tape) = family("bounded.alternating_rank_chain");
    let normal = normalize(class, &tape);
    assert_eq!(normal.gate_count(), 16);
    for gate in 1..16 {
        assert_eq!(
            normal.gate_operand(gate, 0).unwrap(),
            form(BASE + gate, &[(BASE + gate - 1, 128)])
        );
    }
    assert_eq!(
        normal.output_form(63).unwrap(),
        form(BASE + 16, &[(BASE + 15, 128)])
    );
}

#[test]
fn centered_scalar_is_the_least_magnitude_representative() {
    assert_eq!(RAM_LFE_V1_NORMAL_COEFFICIENT_MAGNITUDE, 128);
    for scalar in 0..=256_u16 {
        let centered = ram_lfe_v1_centered_scalar(scalar);
        assert!(centered.unsigned_abs() <= RAM_LFE_V1_NORMAL_COEFFICIENT_MAGNITUDE);
        assert_eq!(i32::from(centered).rem_euclid(257), i32::from(scalar));
    }
    assert_eq!(ram_lfe_v1_centered_scalar(0), 0);
    assert_eq!(ram_lfe_v1_centered_scalar(128), 128);
    assert_eq!(ram_lfe_v1_centered_scalar(129), -128);
    assert_eq!(ram_lfe_v1_centered_scalar(256), -1);
    // A scalar that is not canonical is reduced first.
    assert_eq!(ram_lfe_v1_centered_scalar(257), 0);
    assert_eq!(ram_lfe_v1_centered_scalar(257 + 129), -128);
}

#[test]
fn plaintext_runs_that_give_the_same_forms_leave_no_trace() {
    // Four ways to output `input[1] + 2`: the instruction count, the opcode mix
    // and the registers and lanes used leave no trace in the normal form.
    let tapes: [&[Op]; 4] = [
        &[Op::LoadInput(0, 1), Op::AddPlain(0, 0, 2), Op::Output(0)],
        &[
            Op::LoadInput(0, 1),
            Op::AddPlain(0, 0, 1),
            Op::AddPlain(0, 0, 1),
            Op::Output(0),
        ],
        &[Op::LoadInput(3, 1), Op::SubPlain(3, 3, 255), Op::Output(3)],
        &[
            Op::LoadInput(2, 1),
            Op::StoreState(9, 2),
            Op::LoadConst(2, 0),
            Op::MulPlain(2, 2, 77),
            Op::LoadState(1, 9),
            Op::LoadConst(0, 129),
            Op::MulPlain(0, 0, 2),
            Op::AddPlain(0, 0, 1),
            Op::Add(3, 1, 0),
            Op::Output(3),
        ],
    ];
    let expected = form(
        BASE,
        &[(RAM_LFE_V1_NORMAL_CONSTANT_COLUMN, 2), (INPUT + 1, 1)],
    );
    for tape in tapes {
        for class in RamLfeClassV1::ALL {
            let normal = normalize(class, tape);
            assert_eq!((normal.gate_count(), normal.output_count()), (0, 1));
            assert_eq!(normal.output_form(0).unwrap(), expected);
            assert!(same_normal_form(
                &normal,
                &normalize(RamLfeClassV1::Affine, tapes[0])
            ));
        }
    }

    // The same holds around a gate: two tapes that bring the same forms to a
    // product through different runs, registers and lanes have one normal form.
    let direct = [
        Op::LoadInput(0, 1),
        Op::AddPlain(0, 0, 2),
        Op::Mul(1, 0, 0),
        Op::Output(1),
    ];
    let roundabout = [
        Op::LoadInput(3, 1),
        Op::AddPlain(3, 3, 1),
        Op::StoreState(4, 3),
        Op::LoadConst(3, 9),
        Op::LoadState(2, 4),
        Op::SubPlain(2, 2, 256),
        Op::Mul(0, 2, 2),
        Op::MulPlain(0, 0, 1),
        Op::Output(0),
    ];
    let (direct, roundabout) = (
        normalize(RamLfeClassV1::Bounded, &direct),
        normalize(RamLfeClassV1::Bounded, &roundabout),
    );
    assert!(same_normal_form(&direct, &roundabout));
    assert_eq!(
        direct.gate_operand(0, 1).unwrap(),
        form(
            BASE,
            &[(RAM_LFE_V1_NORMAL_CONSTANT_COLUMN, 2), (INPUT + 1, 1)]
        )
    );
    assert_eq!(direct.output_form(0).unwrap(), form(BASE + 1, &[(BASE, 1)]));
}

/// Whether two `bounded.v1` tapes that read only input slots 1 to 3 compute one
/// function: every scalar of the field in slot 1, with slots 2 and 3 at the
/// field edges and at random values. Such a slot vector is not an admitted
/// input in general; the comparison is over the field.
fn one_function(one: &[Op], other: &[Op]) -> bool {
    let (one, other) = (build(one), build(other));
    let mut rng = ChaCha20Rng::seed_from_u64(0x5230_0f01);
    for value in 0..=256_u16 {
        for round in 0..6 {
            let mut slots = [0_u16; RAM_LFE_V1_INPUT_SLOTS];
            slots[1] = value;
            (slots[2], slots[3]) = match round {
                0 => (0, 0),
                1 => (256, 0),
                2 => (0, 256),
                _ => (random_scalar(&mut rng), random_scalar(&mut rng)),
            };
            let input = RamLfeReferenceInputV1::from_field_slots(&slots);
            let run = |program: &HiddenRamFheProgram| {
                ram_lfe_reference_execute_v1(
                    RamLfeClassV1::Bounded,
                    program,
                    &memory([0; 32]),
                    &input,
                )
                .unwrap()
                .output()
                .scalars()
                .to_vec()
            };
            if run(&one) != run(&other) {
                return false;
            }
        }
    }
    true
}

#[test]
fn a_normal_form_is_not_canonical_for_the_function_of_its_tape() {
    // A scaling moved across a product stays in the coefficients. The second
    // tape doubles the operand before the product and multiplies the product
    // by 193: 2 * 2 * 193 is 1 modulo 257, so both output the square of slot 1.
    let plain = [Op::LoadInput(0, 1), Op::Mul(1, 0, 0), Op::Output(1)];
    let scaled = [
        Op::LoadInput(0, 1),
        Op::MulPlain(0, 0, 2),
        Op::Mul(1, 0, 0),
        Op::MulPlain(1, 1, 193),
        Op::Output(1),
    ];
    assert_eq!(multiply(multiply(2, 2), 193), 1);
    assert!(one_function(&plain, &scaled));
    let (normal, moved) = (
        normalize(RamLfeClassV1::Bounded, &plain),
        normalize(RamLfeClassV1::Bounded, &scaled),
    );
    assert!(!same_normal_form(&normal, &moved));
    for operand in 0..2 {
        assert_eq!(
            normal.gate_operand(0, operand).unwrap(),
            form(BASE, &[(INPUT + 1, 1)])
        );
        assert_eq!(
            moved.gate_operand(0, operand).unwrap(),
            form(BASE, &[(INPUT + 1, 2)])
        );
    }
    assert_eq!(normal.output_form(0).unwrap(), form(BASE + 1, &[(BASE, 1)]));
    assert_eq!(
        moved.output_form(0).unwrap(),
        form(BASE + 1, &[(BASE, 193)])
    );

    // A nonzero scaling of a selection condition does not change what is
    // selected, and stays in the condition form.
    let select = [
        Op::LoadInput(0, 1),
        Op::LoadInput(1, 2),
        Op::LoadInput(2, 3),
        Op::SelectEqZero(3, 0, 1, 2),
        Op::Output(3),
    ];
    let mut rescaled = select.to_vec();
    rescaled.insert(3, Op::MulPlain(0, 0, 5));
    assert!(one_function(&select, &rescaled));
    let (normal, moved) = (
        normalize(RamLfeClassV1::Bounded, &select),
        normalize(RamLfeClassV1::Bounded, &rescaled),
    );
    assert!(!same_normal_form(&normal, &moved));
    assert_eq!(
        normal.gate_operand(0, 0).unwrap(),
        form(BASE, &[(INPUT + 1, 1)])
    );
    assert_eq!(
        moved.gate_operand(0, 0).unwrap(),
        form(BASE, &[(INPUT + 1, 5)])
    );

    // A gate nothing reads stays a gate, so a dead product separates two tapes
    // of one function as well.
    let mut dead = plain.to_vec();
    dead.insert(2, Op::Mul(2, 0, 0));
    assert!(one_function(&plain, &dead));
    let dead = normalize(RamLfeClassV1::Bounded, &dead);
    assert!(!same_normal_form(&normal_of(&plain), &dead));
    assert_eq!((normal_of(&plain).gate_count(), dead.gate_count()), (1, 2));

    // The control: a tape is one function with itself and has one normal form.
    assert!(one_function(&plain, &plain));
    assert!(same_normal_form(&normal_of(&plain), &normal_of(&plain)));
    // And the comparison does tell two functions apart.
    assert!(!one_function(&plain, &select));
}

/// The normal form of a tape under `bounded.v1`.
fn normal_of(tape: &[Op]) -> RamLfeNormalFormV1 {
    normalize(RamLfeClassV1::Bounded, tape)
}

#[test]
fn state_updates_aliasing_and_output_snapshots_are_resolved_exactly() {
    let tape = [
        Op::LoadInput(0, 1),
        Op::Output(0),
        Op::MulPlain(0, 0, 3),
        Op::Output(0),
        Op::StoreState(5, 0),
        Op::Add(0, 0, 0),
        Op::LoadState(1, 5),
        Op::Output(1),
        Op::LoadState(2, 6),
        Op::StoreState(5, 2),
        Op::LoadState(3, 5),
        Op::SubPlain(3, 3, 1),
        Op::Output(3),
        Op::Output(0),
    ];
    let normal = normalize(RamLfeClassV1::Affine, &tape);
    let outputs: Vec<Vec<u16>> = (0..normal.output_count())
        .map(|output| normal.output_form(output).unwrap().to_vec())
        .collect();
    assert_eq!(
        outputs,
        [
            // A snapshot: the later writes to register 0 do not change it.
            form(BASE, &[(INPUT + 1, 1)]),
            form(BASE, &[(INPUT + 1, 3)]),
            // The lane holds what was stored, not what its source became.
            form(BASE, &[(INPUT + 1, 3)]),
            // The second store replaced the lane; 0 - 1 is 256.
            form(
                BASE,
                &[(RAM_LFE_V1_NORMAL_CONSTANT_COLUMN, 256), (LANE + 6, 1)]
            ),
            // A destination that is both sources: 3 + 3.
            form(BASE, &[(INPUT + 1, 6)]),
        ]
    );
    // The machine the tape leaves: lane 5 was overwritten by lane 6, every
    // other lane is still its own column.
    assert_eq!(
        normal.register_form(0).unwrap(),
        form(BASE, &[(INPUT + 1, 6)])
    );
    assert_eq!(
        normal.register_form(1).unwrap(),
        form(BASE, &[(INPUT + 1, 3)])
    );
    assert_eq!(
        normal.register_form(2).unwrap(),
        form(BASE, &[(LANE + 6, 1)])
    );
    for lane in 0..32 {
        let source = if lane == 5 { 6 } else { lane };
        assert_eq!(
            normal.lane_form(lane).unwrap(),
            form(BASE, &[(LANE + source, 1)])
        );
    }
    let program = build(&tape);
    assert_invariants(RamLfeClassV1::Affine, &program, &normal);
    let lanes: [u16; 32] = std::array::from_fn(|lane| u16::try_from(lane * 8 + 1).unwrap());
    assert_equal_on(
        RamLfeClassV1::Affine,
        &program,
        &normal,
        &memory(lanes),
        &input(&[200, 7]),
    );
    assert_eq!(
        normal
            .evaluate(&memory(lanes), &input(&[200, 7]))
            .unwrap()
            .scalars(),
        [200, 86, 86, 48, 172]
    );
}

#[test]
fn every_instruction_may_alias_its_operands() {
    // Each instruction with a destination, once with the destination equal to
    // every source and once with repeated sources.
    let tape = [
        Op::LoadInput(0, 1),
        Op::LoadInput(1, 2),
        Op::LoadState(2, 4),
        Op::LoadConst(3, 256),
        Op::Add(0, 0, 0),
        Op::Add(1, 0, 1),
        Op::AddPlain(2, 2, 256),
        Op::SubPlain(2, 2, 256),
        Op::MulPlain(1, 1, 256),
        Op::Output(1),
        Op::Mul(0, 0, 0),
        Op::Mul(1, 0, 1),
        Op::Output(0),
        Op::Output(1),
        Op::StoreState(4, 1),
        Op::StoreState(31, 1),
        Op::LoadState(1, 4),
        Op::SelectEqZero(2, 2, 2, 2),
        Op::Output(2),
        Op::LoadInput(2, 3),
        Op::SelectEqZero(3, 2, 3, 1),
        Op::Output(3),
        Op::SelectEqZero(1, 0, 1, 1),
        Op::Output(1),
        Op::LoadState(0, 31),
        Op::Output(0),
    ];
    let program = build(&tape);
    for class in [RamLfeClassV1::Bounded, RamLfeClassV1::Refresh] {
        let normal = ram_lfe_reference_normalize_v1(class, &program).unwrap();
        assert_invariants(class, &program, &normal);
        // Every value of the selecting byte, with lanes at both field edges.
        for byte in 0..=255_u8 {
            for edge in [0_u16, 256] {
                assert_equal_on(
                    class,
                    &program,
                    &normal,
                    &memory([edge; 32]),
                    &input(&[byte, 255 - byte, byte]),
                );
            }
        }
        assert_equal_on(class, &program, &normal, &memory([1; 32]), &input(&[]));
    }
}

#[test]
fn nonlinear_instructions_stay_gates_in_tape_order() {
    let tape = [
        Op::LoadConst(0, 3),
        Op::LoadConst(1, 5),
        // A product of two constants is still a gate.
        Op::Mul(2, 0, 1),
        Op::MulPlain(2, 2, 0),
        // So is a product whose operands folded to zero,
        Op::Mul(3, 2, 2),
        Op::LoadInput(0, 7),
        Op::SelectEqZero(1, 0, 2, 3),
        // and one whose result nothing reads.
        Op::Mul(2, 0, 0),
        Op::Output(1),
    ];
    let normal = normalize(RamLfeClassV1::Bounded, &tape);
    let kinds: Vec<_> = (0..normal.gate_count())
        .map(|gate| normal.gate_kind(gate).unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            RamLfeNormalGateKindV1::Mul,
            RamLfeNormalGateKindV1::Mul,
            RamLfeNormalGateKindV1::SelectEqZero,
            RamLfeNormalGateKindV1::Mul,
        ]
    );
    let constant = |columns, value| form(columns, &[(RAM_LFE_V1_NORMAL_CONSTANT_COLUMN, value)]);
    assert_eq!(normal.gate_operand(0, 0).unwrap(), constant(BASE, 3));
    assert_eq!(normal.gate_operand(0, 1).unwrap(), constant(BASE, 5));
    assert_eq!(normal.gate_operand(1, 0).unwrap(), form(BASE + 1, &[]));
    assert_eq!(normal.gate_operand(1, 1).unwrap(), form(BASE + 1, &[]));
    assert_eq!(
        normal.gate_operand(2, 0).unwrap(),
        form(BASE + 2, &[(INPUT + 7, 1)])
    );
    assert_eq!(normal.gate_operand(2, 1).unwrap(), form(BASE + 2, &[]));
    assert_eq!(
        normal.gate_operand(2, 2).unwrap(),
        form(BASE + 2, &[(BASE + 1, 1)])
    );
    assert_eq!(
        normal.gate_operand(3, 0).unwrap(),
        form(BASE + 3, &[(INPUT + 7, 1)])
    );
    // The output was recorded before the last gate, so it does not read it.
    assert_eq!(
        normal.output_form(0).unwrap(),
        form(BASE + 4, &[(BASE + 2, 1)])
    );
    assert_eq!(normal.ciphertext_multiplications(), 13);
    let program = build(&tape);
    assert_invariants(RamLfeClassV1::Bounded, &program, &normal);
    for byte in [0, 1, 255] {
        let mut bytes = [9_u8; 7];
        bytes[6] = byte;
        assert_equal_on(
            RamLfeClassV1::Bounded,
            &program,
            &normal,
            &memory([3; 32]),
            &input(&bytes),
        );
    }
}

#[test]
fn logical_rank_bounds_the_multiplication_depth_of_the_normal_form() {
    // Without cancellation the depth is the logical rank.
    for (name, rank) in [
        ("bounded.rank_chain_outputs", 16),
        ("bounded.select_then_products", 16),
        ("bounded.selects", 10),
        ("affine.loads", 0),
    ] {
        let (class, tape) = family(name);
        let normal = normalize(class, &tape);
        assert_eq!(normal.report().peak_rank(), rank, "{name}");
        assert_eq!(normal.depth(), rank, "{name}");
    }
    // Rank is counted on the tape. A coefficient that folds to zero removes a
    // dependency, so the depth can be lower than the rank and never higher.
    let tape = [
        Op::LoadInput(0, 1),
        Op::Mul(1, 0, 0),
        Op::MulPlain(1, 1, 0),
        Op::Mul(2, 1, 1),
        Op::Output(2),
    ];
    let normal = normalize(RamLfeClassV1::Bounded, &tape);
    assert_eq!(normal.report().peak_rank(), 2);
    assert_eq!(normal.depth(), 1);
    // The class is decided on the tape: seventeen squarings are refused by
    // `bounded.v1` although sixteen of them could be cancelled afterwards.
    let mut tape = vec![Op::LoadInput(0, 1)];
    repeat(&mut tape, 17, Op::Mul(0, 0, 0));
    tape.extend([Op::MulPlain(0, 0, 0), Op::Output(0)]);
    let program = build(&tape);
    assert_eq!(
        ram_lfe_reference_normalize_v1(RamLfeClassV1::Bounded, &program).unwrap_err(),
        RamLfeClassV1::Bounded.membership(&program).unwrap_err()
    );
}

#[test]
fn rank_sixteen_does_not_bound_the_number_of_ciphertext_multiplications() {
    // 255 independent selects: rank 10, 2,550 ciphertext multiplications.
    let (class, tape) = family("bounded.selects");
    let normal = normalize(class, &tape);
    assert_eq!(normal.report().peak_rank(), 10);
    assert_eq!(normal.ciphertext_multiplications(), 2550);
    assert_eq!(
        normal.ciphertext_multiplications(),
        RamLfeNormalShapeV1::of(class).ciphertext_multiplications
    );
    // 255 independent products: rank 1, 255 ciphertext multiplications.
    let mut tape = Vec::new();
    repeat(&mut tape, 255, Op::Mul(1, 0, 0));
    tape.push(Op::Output(1));
    let normal = normalize(RamLfeClassV1::Bounded, &tape);
    assert_eq!(normal.report().peak_rank(), 1);
    assert_eq!(normal.ciphertext_multiplications(), 255);
    assert!(normal.ciphertext_multiplications() > u32::from(RamLfeClassV1::Bounded.max_rank()));
}

#[test]
fn refresh_points_become_identity_gates_of_the_canonical_schedule() {
    use RamLfeNormalGateKindV1::{Mul, Refresh};

    // Twenty squarings: the seventeenth needs its operand refreshed.
    let mut tape = vec![Op::LoadInput(0, 1)];
    repeat(&mut tape, 20, Op::Mul(0, 0, 0));
    tape.push(Op::Output(0));
    let program = build(&tape);
    let normal = ram_lfe_reference_normalize_v1(RamLfeClassV1::Refresh, &program).unwrap();
    assert_invariants(RamLfeClassV1::Refresh, &program, &normal);
    let points: Vec<_> = normal.report().refresh_points().collect();
    assert_eq!(
        points,
        [RamLfeRefreshPointV1 {
            instruction: 17,
            register: 0
        }]
    );
    assert_eq!(normal.gate_count(), 21);
    for gate in 0..21 {
        let kind = if gate == 16 { Refresh } else { Mul };
        assert_eq!(normal.gate_kind(gate), Some(kind));
    }
    // The refresh reads the sixteenth product, and the next product reads the
    // refresh: the depth starts again at zero.
    assert_eq!(
        normal.gate_operand(16, 0).unwrap(),
        form(BASE + 16, &[(BASE + 15, 1)])
    );
    assert!(normal.gate_operand(16, 1).is_none());
    assert_eq!(
        normal.gate_operand(17, 0).unwrap(),
        form(BASE + 17, &[(BASE + 16, 1)])
    );
    assert_eq!(normal.depth(), 16);
    assert_eq!(normal.ciphertext_multiplications(), 20);
    // Refresh is the identity on plaintext: 3^(2^20) is 1.
    assert_eq!(
        normal
            .evaluate(&memory([0; 32]), &input(&[3]))
            .unwrap()
            .scalars(),
        [1]
    );
    assert_equal_on(
        RamLfeClassV1::Refresh,
        &program,
        &normal,
        &memory([0; 32]),
        &input(&[3]),
    );

    // A refresh is in place: a copy of the value in a lane is not refreshed,
    // a register named twice is refreshed once, and a destination that is an
    // operand reads the refreshed operand.
    let mut tape = vec![Op::LoadInput(0, 1)];
    repeat(&mut tape, 16, Op::Mul(0, 0, 0));
    tape.extend([
        Op::StoreState(3, 0),
        Op::Mul(1, 0, 0),
        Op::LoadState(2, 3),
        Op::Mul(2, 2, 1),
        Op::Output(2),
        Op::Output(0),
    ]);
    let program = build(&tape);
    let normal = ram_lfe_reference_normalize_v1(RamLfeClassV1::Refresh, &program).unwrap();
    assert_invariants(RamLfeClassV1::Refresh, &program, &normal);
    let kinds: Vec<_> = (16..normal.gate_count())
        .map(|gate| normal.gate_kind(gate).unwrap())
        .collect();
    assert_eq!(kinds, [Refresh, Mul, Refresh, Refresh, Mul]);
    let sixteenth = BASE + 15;
    // Register 0, refreshed once for `Mul(1, 0, 0)`.
    assert_eq!(
        normal.gate_operand(16, 0).unwrap(),
        form(BASE + 16, &[(sixteenth, 1)])
    );
    assert_eq!(
        normal.gate_operand(17, 0).unwrap(),
        form(BASE + 17, &[(BASE + 16, 1)])
    );
    assert_eq!(
        normal.gate_operand(17, 1).unwrap(),
        form(BASE + 17, &[(BASE + 16, 1)])
    );
    // The lane still held the unrefreshed sixteenth product.
    assert_eq!(
        normal.gate_operand(18, 0).unwrap(),
        form(BASE + 18, &[(sixteenth, 1)])
    );
    assert_eq!(
        normal.lane_form(3).unwrap(),
        form(BASE + 21, &[(sixteenth, 1)])
    );
    // Register 0 holds its refreshed value at the end.
    assert_eq!(
        normal.register_form(0).unwrap(),
        form(BASE + 21, &[(BASE + 16, 1)])
    );
    for bytes in [&[3_u8][..], &[0], &[255, 1]] {
        assert_equal_on(
            RamLfeClassV1::Refresh,
            &program,
            &normal,
            &memory([7; 32]),
            &input(bytes),
        );
    }
    // The same tape is outside `bounded.v1`, and the refusal is the class's own.
    assert_eq!(
        ram_lfe_reference_normalize_v1(RamLfeClassV1::Bounded, &program).unwrap_err(),
        RamLfeClassV1::Bounded.membership(&program).unwrap_err()
    );
}

/// 65 selects on one register need 64 refreshes; with 190 products and one
/// output the tape has 256 instructions.
fn widest_refresh_tape(selects: usize) -> Vec<Op> {
    let mut tape = Vec::new();
    repeat(&mut tape, selects, Op::SelectEqZero(0, 0, 0, 0));
    repeat(&mut tape, 255 - selects, Op::Mul(1, 2, 2));
    tape.push(Op::Output(0));
    tape
}

/// One member tape of 255 selections and one output that reaches every bound
/// of its class except the output count at once.
///
/// `refresh.v1`: 65 selections of a register by itself need 64 refreshes and
/// leave depth 10; six more that select it as a branch under a fresh condition
/// raise the depth to 16 without another refresh. `bounded.v1`: seven such
/// selections reach depth 16. The remaining selections are independent.
fn joint_maximum_tape(class: RamLfeClassV1) -> Vec<Op> {
    let mut tape = Vec::new();
    let chained = match class {
        RamLfeClassV1::Affine => panic!("affine.v1 has no nonlinear gate"),
        RamLfeClassV1::Bounded => 7,
        RamLfeClassV1::Refresh => {
            repeat(&mut tape, 65, Op::SelectEqZero(0, 0, 0, 0));
            6
        }
    };
    repeat(&mut tape, chained, Op::SelectEqZero(0, 1, 0, 0));
    let independent = 255 - tape.len();
    repeat(&mut tape, independent, Op::SelectEqZero(2, 3, 3, 3));
    tape.push(Op::Output(0));
    tape
}

/// The joint maximum with 64 outputs: the last 63 independent selections give
/// way to 63 more outputs, so 192 nonlinear gates remain.
fn joint_maximum_tape_with_every_output(class: RamLfeClassV1) -> Vec<Op> {
    let mut tape = joint_maximum_tape(class);
    tape.truncate(RAM_LFE_V1_MAX_INSTRUCTIONS - RAM_LFE_V1_MAX_OUTPUTS);
    repeat(&mut tape, RAM_LFE_V1_MAX_OUTPUTS, Op::Output(0));
    tape
}

#[test]
fn class_shape_is_a_function_of_the_class_and_every_bound_is_reached() {
    let shape = RamLfeNormalShapeV1::of;
    assert_eq!(
        shape(RamLfeClassV1::Affine),
        RamLfeNormalShapeV1 {
            nonlinear_gates: 0,
            refreshes: 0,
            outputs: 64,
            columns: 97,
            depth: 0,
            ciphertext_multiplications: 0,
        }
    );
    assert_eq!(
        shape(RamLfeClassV1::Bounded),
        RamLfeNormalShapeV1 {
            nonlinear_gates: 255,
            refreshes: 0,
            outputs: 64,
            columns: 352,
            depth: 16,
            ciphertext_multiplications: 2550,
        }
    );
    assert_eq!(
        shape(RamLfeClassV1::Refresh),
        RamLfeNormalShapeV1 {
            nonlinear_gates: 255,
            refreshes: 64,
            outputs: 64,
            columns: 416,
            depth: 16,
            ciphertext_multiplications: 2550,
        }
    );
    assert_eq!(BASE, 97);
    assert_eq!((INPUT, LANE), (1, 65));
    assert_eq!(shape(RamLfeClassV1::Affine).gates(), 0);
    assert_eq!(shape(RamLfeClassV1::Bounded).gates(), 255);
    assert_eq!(shape(RamLfeClassV1::Refresh).gates(), 319);

    // Every bound is reached by a member tape.
    let reached = |class: RamLfeClassV1, tape: &[Op]| {
        let program = build(tape);
        let normal = ram_lfe_reference_normalize_v1(class, &program).unwrap();
        assert_invariants(class, &program, &normal);
        assert_equal_on(class, &program, &normal, &memory([5; 32]), &input(&[0, 9]));
        normal
    };
    let (_, tape) = family("affine.state_and_registers");
    let normal = reached(RamLfeClassV1::Affine, &tape);
    assert_eq!(normal.output_count(), 64);
    assert_eq!(normal.columns(), 97);

    let (_, tape) = family("bounded.selects");
    let normal = reached(RamLfeClassV1::Bounded, &tape);
    assert_eq!(normal.gate_count(), 255);
    assert_eq!(normal.columns(), 352);
    assert_eq!(normal.ciphertext_multiplications(), 2550);
    let (_, tape) = family("bounded.rank_chain_outputs");
    let normal = reached(RamLfeClassV1::Bounded, &tape);
    assert_eq!((normal.depth(), normal.output_count()), (16, 64));

    let normal = reached(RamLfeClassV1::Refresh, &widest_refresh_tape(65));
    assert_eq!(normal.report().refresh_count(), 64);
    assert_eq!(normal.gate_count(), 319);
    assert_eq!(normal.columns(), 416);

    // The bounds are reached together, not only one by one. One tape of 255
    // nonlinear instructions and one output has the gates, the refreshes, the
    // columns, the depth and the ciphertext multiplications of its class.
    for class in [RamLfeClassV1::Bounded, RamLfeClassV1::Refresh] {
        let shape = shape(class);
        let tape = joint_maximum_tape(class);
        assert_eq!(tape.len(), RAM_LFE_V1_MAX_INSTRUCTIONS);
        let normal = reached(class, &tape);
        assert_eq!(
            RamLfeNormalShapeV1 {
                nonlinear_gates: u16::try_from(
                    normal.gate_count() - usize::from(normal.report().refresh_count())
                )
                .unwrap(),
                refreshes: normal.report().refresh_count(),
                outputs: shape.outputs,
                columns: u16::try_from(normal.columns()).unwrap(),
                depth: normal.depth(),
                ciphertext_multiplications: normal.ciphertext_multiplications(),
            },
            shape,
            "{class}"
        );
        assert_eq!(normal.report().peak_rank(), class.max_rank());
        // Only the output count is missing: the tape has one output.
        assert_eq!(normal.output_count(), 1);

        // The output bound and the gate bound exclude each other, because an
        // output and a nonlinear gate are one instruction each. With all 64
        // outputs a tape keeps 192 nonlinear gates, and with them every other
        // bound it can still reach: the refreshes and the depth.
        let tape = joint_maximum_tape_with_every_output(class);
        assert_eq!(tape.len(), RAM_LFE_V1_MAX_INSTRUCTIONS);
        let normal = reached(class, &tape);
        let refreshes = usize::from(normal.report().refresh_count());
        assert_eq!(normal.output_count(), usize::from(shape.outputs));
        assert_eq!(normal.gate_count() - refreshes, 192);
        assert_eq!(
            normal.gate_count() - refreshes + normal.output_count(),
            RAM_LFE_V1_MAX_INSTRUCTIONS
        );
        assert_eq!(refreshes, usize::from(shape.refreshes));
        assert_eq!(normal.depth(), shape.depth);
        assert_eq!(normal.ciphertext_multiplications(), 1920);
        assert_eq!(normal.columns(), usize::from(shape.columns) - 63);
        // A 257th instruction, gate or output, is not a tape.
        let mut builder = HiddenRamFheProgram::builder().unwrap();
        for &instruction in &tape {
            builder.push(instruction).unwrap();
        }
        assert!(builder.push(Op::SelectEqZero(2, 3, 3, 3)).is_err());
        assert!(builder.push(Op::Output(0)).is_err());
    }
    // `affine.v1` has no gate, so its one tape of 64 outputs reaches its whole
    // shape: `affine.state_and_registers` above.

    // No member tape exceeds a bound: one more refresh is outside the class.
    let program = build(&widest_refresh_tape(66));
    let refusal = RamLfeClassV1::Refresh.membership(&program).unwrap_err();
    assert!(matches!(
        refusal,
        RamLfeError::ClassRefreshLimitExceeded { limit: 64, .. }
    ));
    assert_eq!(
        ram_lfe_reference_normalize_v1(RamLfeClassV1::Refresh, &program).unwrap_err(),
        refusal
    );
}

#[test]
fn normalization_is_gated_by_the_declared_class() {
    let program = build(&[Op::LoadInput(0, 1), Op::Mul(0, 0, 0), Op::Output(0)]);
    assert_eq!(
        ram_lfe_reference_normalize_v1(RamLfeClassV1::Affine, &program).unwrap_err(),
        RamLfeError::InstructionOutsideClass {
            class: RamLfeClassV1::Affine,
            instruction: 1,
            opcode: RamLfeOpcodeV1::Mul,
        }
    );
    let mut tape = vec![Op::LoadInput(0, 1)];
    repeat(&mut tape, 17, Op::Mul(0, 0, 0));
    tape.push(Op::Output(0));
    let program = build(&tape);
    assert_eq!(
        ram_lfe_reference_normalize_v1(RamLfeClassV1::Bounded, &program).unwrap_err(),
        RamLfeError::ClassRankExceeded {
            class: RamLfeClassV1::Bounded,
            instruction: 17,
            rank: 17,
            limit: 16,
        }
    );
    assert!(ram_lfe_reference_normalize_v1(RamLfeClassV1::Refresh, &program).is_ok());
}

#[test]
fn one_normal_form_serves_every_associated_data_value() {
    let tape = [
        Op::LoadInput(0, 1),
        Op::LoadState(1, 0),
        Op::Add(2, 0, 1),
        Op::MulPlain(2, 2, 3),
        Op::Output(2),
        Op::LoadState(3, 31),
        Op::Mul(3, 3, 2),
        Op::Output(3),
    ];
    let program = build(&tape);
    let key = RamLfeProgramKeyV1::from_bytes([0x42; 32]).unwrap();
    let function = RamLfeFunctionIdentityV1::commit(
        RamLfeClassV1::Bounded,
        &key,
        &program,
        RamLfeQueryLimitV1::new(1000, 3).unwrap(),
    )
    .unwrap();
    let normal = ram_lfe_reference_normalize_v1(function.class, &program).unwrap();
    let mut seen = Vec::new();
    for associated_data in [&b"request"[..], b"other request", b""] {
        let input = input(b"+15551234567");
        let reference =
            ram_lfe_reference_evaluate_v1(&function, &key, &program, associated_data, &input)
                .unwrap();
        // The lanes belong to the execution; the normal form belongs to the tape.
        assert_eq!(
            normal
                .evaluate(reference.initial_memory(), &input)
                .unwrap()
                .scalars(),
            reference.output().scalars()
        );
        seen.push(reference.output().scalars().to_vec());
    }
    assert_ne!(seen[0], seen[1]);
}

#[test]
fn roles_and_gate_kinds_are_what_the_classes_and_the_descriptor_state() {
    use RamLfeNormalGateKindV1::{Mul, Refresh, SelectEqZero};

    let role = RamLfeNormalRoleV1::of;
    for opcode in RamLfeOpcodeV1::ALL {
        // `affine.v1` admits exactly the instructions that are not boundaries.
        assert_eq!(
            role(opcode) == RamLfeNormalRoleV1::Boundary,
            !RamLfeClassV1::Affine.admits(opcode)
        );
        assert_eq!(
            role(opcode) == RamLfeNormalRoleV1::Snapshot,
            opcode == RamLfeOpcodeV1::Output
        );
    }
    assert_eq!(RamLfeNormalRoleV1::Folded.to_string(), "folded");
    assert_eq!(RamLfeNormalRoleV1::Boundary.to_string(), "boundary");
    assert_eq!(RamLfeNormalRoleV1::Snapshot.to_string(), "snapshot");

    assert_eq!(RamLfeNormalGateKindV1::ALL, [Mul, SelectEqZero, Refresh]);
    for kind in RamLfeNormalGateKindV1::ALL {
        assert_eq!(RamLfeNormalGateKindV1::from_code(kind.code()), kind);
    }
    assert_eq!(
        [Mul, SelectEqZero, Refresh].map(RamLfeNormalGateKindV1::operand_count),
        [2, 3, 1]
    );
    assert_eq!(
        [Mul, SelectEqZero, Refresh].map(RamLfeNormalGateKindV1::ciphertext_multiplications),
        [1, 10, 0]
    );
    assert_eq!(Mul.to_string(), RamLfeOpcodeV1::Mul.name());
    assert_eq!(
        SelectEqZero.to_string(),
        RamLfeOpcodeV1::SelectEqZero.name()
    );
    assert_eq!(Refresh.to_string(), "Refresh");
    // The depth a gate adds is the rank rule of its opcode in the descriptor.
    assert_eq!([Mul.added_depth(0), Mul.added_depth(1)], [Some(1), Some(1)]);
    assert_eq!(
        [0, 1, 2].map(|operand| SelectEqZero.added_depth(operand)),
        [
            Some(RAM_LFE_V1_SELECT_CONDITION_RANK),
            Some(RAM_LFE_V1_SELECT_BRANCH_RANK),
            Some(RAM_LFE_V1_SELECT_BRANCH_RANK)
        ]
    );
    assert_eq!(Refresh.added_depth(0), None);
}

#[test]
fn dot_product_is_exact_at_the_widest_form() {
    // 416 coefficients of 256 against 416 values of 256: the largest sum.
    let widest = usize::from(RamLfeNormalShapeV1::of(RamLfeClassV1::Refresh).columns);
    assert_eq!(widest, 416);
    assert_eq!(dot(&vec![256; widest], &vec![256; widest]), 416 % 257);
    assert_eq!(dot(&[], &[1, 2]), 0);
    assert_eq!(dot(&[2, 3], &[5, 7, 11]), 31);
    assert_eq!(dot(&[256, 1], &[1, 1]), 0);
}

#[test]
fn normal_form_is_redacted_and_its_buffers_clear_on_success_and_error() {
    let tape = [
        Op::LoadInput(0, 1),
        Op::Mul(1, 0, 0),
        Op::SelectEqZero(2, 0, 1, 1),
        Op::Output(1),
        Op::Output(2),
    ];
    let program = build(&tape);
    // Scalars one normalization writes: the symbolic machine, the column
    // depths, and for two gates and two outputs their kinds and forms.
    let written = |class: RamLfeClassV1, gates: usize, outputs: usize| {
        let stride = usize::from(RamLfeNormalShapeV1::of(class).columns);
        RAM_LFE_V1_TRACE_ROW_SCALARS * stride
            + stride
            + gates
            + gates * GATE_OPERANDS * stride
            + outputs * stride
    };

    // Success: the form, then one evaluation of each kind.
    let before = cleared_scalars();
    {
        let normal = ram_lfe_reference_normalize_v1(RamLfeClassV1::Bounded, &program).unwrap();
        assert_eq!(format!("{normal:?}"), "[REDACTED RAM-LFE normal form]");
        // The folding buffers that are not part of the form are already cleared.
        assert_eq!(
            cleared_scalars() - before,
            usize::from(RamLfeNormalShapeV1::of(RamLfeClassV1::Bounded).columns)
        );
        let lanes = memory([1; 32]);
        let input = input(&[4]);
        assert_eq!(normal.evaluate(&lanes, &input).unwrap().scalars(), [16, 16]);
        normal.evaluate_final_state(&lanes, &input).unwrap();
    }
    let evaluations = (BASE + 2 + 2) + (BASE + 2);
    assert_eq!(
        cleared_scalars() - before,
        written(RamLfeClassV1::Bounded, 2, 2) + evaluations
    );

    // Success with a refresh schedule: its two scalars per point clear too.
    let mut refreshing = vec![Op::LoadInput(0, 1)];
    repeat(&mut refreshing, 17, Op::Mul(0, 0, 0));
    refreshing.push(Op::Output(0));
    let before = cleared_scalars();
    drop(normalize(RamLfeClassV1::Refresh, &refreshing));
    assert_eq!(
        cleared_scalars() - before,
        written(RamLfeClassV1::Refresh, 18, 1) + 2
    );

    // Error before any buffer: a tape its class refuses allocates nothing.
    let before = cleared_scalars();
    assert!(ram_lfe_reference_normalize_v1(RamLfeClassV1::Affine, &program).is_err());
    assert_eq!(cleared_scalars() - before, 0);

    // Error in a caller that holds a form: the form clears as the error returns.
    let before = cleared_scalars();
    let refused = || -> Result<(), RamLfeError> {
        let _normal = ram_lfe_reference_normalize_v1(RamLfeClassV1::Bounded, &program)?;
        ram_lfe_reference_normalize_v1(RamLfeClassV1::Affine, &program).map(|_| ())
    };
    assert!(refused().is_err());
    assert_eq!(
        cleared_scalars() - before,
        written(RamLfeClassV1::Bounded, 2, 2)
    );
}

/// Whether an error is the allocation failure a test asked for.
fn is_refused_allocation<T>(result: Result<T, RamLfeError>) -> bool {
    matches!(
        result,
        Err(RamLfeError::Bfv(message))
            if message.ends_with("normal form allocation failed: refused by the test")
    )
}

#[test]
fn buffers_clear_when_an_error_returns_after_they_were_written() {
    // The only error a normalization or an evaluation returns while a buffer
    // holds data is an allocation failure, so the test refuses one reservation
    // at a time and counts the scalars the earlier buffers clear.
    let mut tape = vec![Op::LoadInput(0, 1)];
    repeat(&mut tape, 17, Op::Mul(0, 0, 0));
    tape.push(Op::Output(0));
    let program = build(&tape);
    let stride = usize::from(RamLfeNormalShapeV1::of(RamLfeClassV1::Refresh).columns);
    // One refresh point: its instruction and its register.
    let schedule = 2;
    let machine = RAM_LFE_V1_TRACE_ROW_SCALARS * stride;
    // A normalization reserves six buffers, in this order: the refresh
    // schedule, the symbolic machine, the column depths, the gate kinds, the
    // operand forms and the output forms.
    for (granted, cleared) in [
        (0, 0),
        (1, schedule),
        (2, schedule + machine),
        (3, schedule + machine + stride),
        (4, schedule + machine + stride),
        (5, schedule + machine + stride),
    ] {
        let before = cleared_scalars();
        refuse_allocation_after(granted);
        assert!(
            is_refused_allocation(ram_lfe_reference_normalize_v1(
                RamLfeClassV1::Refresh,
                &program
            )),
            "reservation {granted}"
        );
        assert_eq!(cleared_scalars() - before, cleared, "reservation {granted}");
    }
    // A refusal disarms itself: the next normalization succeeds.
    let normal = ram_lfe_reference_normalize_v1(RamLfeClassV1::Refresh, &program).unwrap();
    assert_eq!((normal.gate_count(), normal.output_count()), (18, 1));
    let columns = normal.columns();
    assert_eq!(columns, BASE + 18);

    // An evaluation reserves the column values and then its result. When the
    // second reservation is refused the column values hold the plaintext of
    // the execution: one, the input slots, the lanes and every gate result.
    let lanes = memory([9; 32]);
    let input = input(&[3]);
    for (granted, cleared) in [(0, 0), (1, columns)] {
        let before = cleared_scalars();
        refuse_allocation_after(granted);
        assert!(is_refused_allocation(normal.evaluate(&lanes, &input)));
        assert_eq!(cleared_scalars() - before, cleared, "output {granted}");

        let before = cleared_scalars();
        refuse_allocation_after(granted);
        assert!(is_refused_allocation(
            normal.evaluate_final_state(&lanes, &input)
        ));
        assert_eq!(cleared_scalars() - before, cleared, "machine {granted}");
    }
    // Both evaluations succeed again, and the form was not disturbed.
    assert_eq!(normal.evaluate(&lanes, &input).unwrap().scalars(), [1]);
    assert_eq!(normal.evaluate_final_state(&lanes, &input).unwrap()[0], 1);
    // Neither a success nor a class refusal is taken for the refused
    // allocation: seventeen squarings are outside `bounded.v1`.
    assert!(!is_refused_allocation(normal.evaluate(&lanes, &input)));
    let refusal = ram_lfe_reference_normalize_v1(RamLfeClassV1::Bounded, &program);
    assert!(matches!(
        refusal,
        Err(RamLfeError::ClassRankExceeded { .. })
    ));
    assert!(!is_refused_allocation(refusal));

    // A refusal that is never reached refuses nothing and stays armed until a
    // reservation reaches it.
    refuse_allocation_after(2);
    assert_eq!(normal.evaluate(&lanes, &input).unwrap().scalars(), [1]);
    assert!(is_refused_allocation(normal.evaluate(&lanes, &input)));
    assert!(!allocation_refused());
}

#[test]
fn normal_form_buffers_clear_during_unwinding() {
    let tape = [
        Op::LoadInput(0, 1),
        Op::Mul(1, 0, 0),
        Op::SelectEqZero(2, 0, 1, 1),
        Op::Output(1),
        Op::Output(2),
    ];
    let stride = usize::from(RamLfeNormalShapeV1::of(RamLfeClassV1::Bounded).columns);
    let written = RAM_LFE_V1_TRACE_ROW_SCALARS * stride
        + stride
        + 2
        + 2 * GATE_OPERANDS * stride
        + 2 * stride;

    // Unwind: a panic while the form is live clears it.
    let before = cleared_scalars();
    assert!(
        std::panic::catch_unwind(|| {
            let _normal = normalize(RamLfeClassV1::Bounded, &tape);
            panic!("normal form unwind control");
        })
        .is_err()
    );
    assert_eq!(cleared_scalars() - before, written);

    // Unwind during an evaluation: the column values of the execution clear
    // with the form.
    let before = cleared_scalars();
    assert!(
        std::panic::catch_unwind(|| {
            let normal = normalize(RamLfeClassV1::Bounded, &tape);
            let values = normal
                .column_values(&memory([1; 32]), &input(&[4]))
                .unwrap();
            assert_eq!(values.0.len(), BASE + 2);
            panic!("normal form evaluation unwind control");
        })
        .is_err()
    );
    assert_eq!(cleared_scalars() - before, written + BASE + 2);
}
