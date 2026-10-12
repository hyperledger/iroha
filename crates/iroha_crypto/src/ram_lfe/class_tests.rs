//! Class membership, rank and refresh accounting, and the pinned semantics descriptor.

use super::*;
use crate::ram_lfe::program::{from_public_test_parts, instruction_fields};
use HiddenRamFheInstruction as Op;

fn build(instructions: &[Op]) -> HiddenRamFheProgram {
    let mut builder = HiddenRamFheProgram::builder().unwrap();
    for &instruction in instructions {
        builder.push(instruction).unwrap();
    }
    builder.finish().unwrap()
}

/// One structurally valid instruction per opcode, in tag order.
const OPCODES: [Op; 11] = [
    Op::LoadInput(0, 1),
    Op::LoadState(0, 1),
    Op::StoreState(1, 0),
    Op::LoadConst(0, 256),
    Op::Add(0, 1, 2),
    Op::AddPlain(0, 1, 256),
    Op::SubPlain(0, 1, 256),
    Op::MulPlain(0, 1, 256),
    Op::Mul(0, 1, 2),
    Op::SelectEqZero(0, 1, 2, 3),
    Op::Output(0),
];

#[test]
fn opcode_table_is_the_tape_codec_and_covers_every_instruction() {
    assert_eq!(OPCODES.len(), RamLfeOpcodeV1::ALL.len());
    let mut names = std::collections::BTreeSet::new();
    for (index, (instruction, opcode)) in OPCODES.iter().zip(RamLfeOpcodeV1::ALL).enumerate() {
        assert_eq!(instruction.opcode(), opcode);
        assert_eq!(usize::from(opcode.tag()), index);
        assert_eq!(instruction_fields(*instruction)[0], u64::from(opcode.tag()));
        assert_eq!(opcode.to_string(), opcode.name());
        assert!(names.insert(opcode.name()));
    }
}

/// One `opcode=` line of the descriptor: the normative text of one instruction.
struct OpcodeLine {
    opcode: RamLfeOpcodeV1,
    parameters: Vec<&'static str>,
    meaning: &'static str,
    rank: &'static str,
}

impl OpcodeLine {
    fn text(&self) -> String {
        format!(
            "opcode={}:{}({}):{};rank={}",
            self.opcode.tag(),
            self.opcode.name(),
            self.parameters.join(","),
            self.meaning,
            self.rank
        )
    }
}

/// Parse the opcode lines of the compiled descriptor, in tag order.
fn opcode_lines() -> Vec<OpcodeLine> {
    let lines: Vec<OpcodeLine> = RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR
        .lines()
        .filter_map(|line| line.strip_prefix("opcode="))
        .zip(RamLfeOpcodeV1::ALL)
        .map(|(line, opcode)| {
            let (tag, rest) = line.split_once(':').unwrap();
            let (name, rest) = rest.split_once('(').unwrap();
            let (parameters, rest) = rest.split_once("):").unwrap();
            let (meaning, rank) = rest.split_once(";rank=").unwrap();
            assert_eq!(tag, opcode.tag().to_string());
            assert_eq!(name, opcode.name());
            OpcodeLine {
                opcode,
                parameters: parameters.split(',').collect(),
                meaning,
                rank,
            }
        })
        .collect();
    assert_eq!(lines.len(), RamLfeOpcodeV1::ALL.len());
    lines
}

/// Evaluator for the descriptor's expressions: sums, products, constant
/// powers, parentheses, `max(...)`, names and one-level indexing.
struct Expression<'a> {
    text: &'a [u8],
    position: usize,
    modulus: Option<u32>,
    resolve: &'a dyn Fn(&str, Option<&str>) -> u32,
}

impl<'a> Expression<'a> {
    fn evaluate(
        text: &'a str,
        modulus: Option<u32>,
        resolve: &'a dyn Fn(&str, Option<&str>) -> u32,
    ) -> u32 {
        let mut expression = Self {
            text: text.as_bytes(),
            position: 0,
            modulus,
            resolve,
        };
        let value = expression.sum();
        assert_eq!(expression.position, text.len(), "trailing text in `{text}`");
        value
    }

    fn reduce(&self, value: u32) -> u32 {
        self.modulus.map_or(value, |modulus| value % modulus)
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.position).copied()
    }

    fn take(&mut self, byte: u8) -> bool {
        let found = self.peek() == Some(byte);
        self.position += usize::from(found);
        found
    }

    fn word(&mut self, accept: fn(&u8) -> bool) -> &'a str {
        let start = self.position;
        while self.peek().is_some_and(|byte| accept(&byte)) {
            self.position += 1;
        }
        std::str::from_utf8(&self.text[start..self.position]).unwrap()
    }

    fn sum(&mut self) -> u32 {
        let mut value = self.product();
        loop {
            if self.take(b'+') {
                let addend = self.product();
                value = self.reduce(value + addend);
            } else if self.take(b'-') {
                let modulus = self.modulus.expect("subtraction is modular");
                let subtrahend = self.product() % modulus;
                value = (value + modulus - subtrahend) % modulus;
            } else {
                return value;
            }
        }
    }

    fn product(&mut self) -> u32 {
        let mut value = self.power();
        while self.take(b'*') {
            let factor = self.power();
            value = self.reduce(value * factor);
        }
        value
    }

    fn power(&mut self) -> u32 {
        let base = self.atom();
        if !self.take(b'^') {
            return base;
        }
        let exponent: u32 = self.word(u8::is_ascii_digit).parse().unwrap();
        (0..exponent).fold(1, |value, _| self.reduce(value * base))
    }

    fn atom(&mut self) -> u32 {
        if self.take(b'(') {
            let value = self.sum();
            assert!(self.take(b')'));
            return value;
        }
        if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            return self.word(u8::is_ascii_digit).parse().unwrap();
        }
        let name = self.word(u8::is_ascii_alphabetic);
        assert!(!name.is_empty(), "expected a name");
        if name == "max" {
            assert!(self.take(b'('));
            let mut value = self.sum();
            while self.take(b',') {
                value = value.max(self.sum());
            }
            assert!(self.take(b')'));
            return value;
        }
        if self.take(b'[') {
            let index = self.word(u8::is_ascii_alphabetic);
            assert!(self.take(b']'));
            return (self.resolve)(name, Some(index));
        }
        (self.resolve)(name, None)
    }
}

#[test]
fn expression_evaluator_follows_precedence_powers_and_maxima() {
    let resolve = |name: &str, index: Option<&str>| match (name, index) {
        ("a", None) => 200,
        ("b", None) => 100,
        ("table", Some("a")) => 7,
        other => panic!("unbound {other:?}"),
    };
    let modular = |text: &str| Expression::evaluate(text, Some(257), &resolve);
    assert_eq!(modular("a+b"), 43);
    assert_eq!(modular("b-a"), 157);
    assert_eq!(modular("a*b+1"), (200 * 100 + 1) % 257);
    assert_eq!(modular("1+a*b"), (200 * 100 + 1) % 257);
    assert_eq!(modular("(1+a)*b"), (201 * 100) % 257);
    assert_eq!(modular("a^256"), 1);
    assert_eq!(modular("table[a]^2"), 49);
    assert_eq!(modular("0"), 0);
    let plain = |text: &str| Expression::evaluate(text, None, &resolve);
    assert_eq!(plain("max(a,b)+1"), 201);
    assert_eq!(plain("max(a+10,b+1,table[a]+300)"), 307);
}

/// Position of each named operand in the test machine: the register, slot or
/// lane index a parameter is bound to.
fn operand_index(parameter: &str) -> u64 {
    match parameter {
        "dst" => 0,
        "src" | "lhs" | "cond" => 1,
        "rhs" | "zero" | "slot" => 2,
        "nonzero" => 3,
        "lane" => 5,
        other => panic!("descriptor names an unknown parameter `{other}`"),
    }
}

/// Build the typed instruction of one descriptor line, with `imm` bound to
/// `immediate`. The descriptor's parameter order must be the tape word order.
fn typed(line: &OpcodeLine, immediate: u64) -> Op {
    let words: Vec<u64> = line
        .parameters
        .iter()
        .map(|&parameter| match parameter {
            "imm" => immediate,
            other => operand_index(other),
        })
        .collect();
    let index = |word: usize| u16::try_from(words[word]).unwrap();
    let instruction = match line.opcode {
        RamLfeOpcodeV1::LoadInput => Op::LoadInput(index(0), index(1)),
        RamLfeOpcodeV1::LoadState => Op::LoadState(index(0), index(1)),
        RamLfeOpcodeV1::StoreState => Op::StoreState(index(0), index(1)),
        RamLfeOpcodeV1::LoadConst => Op::LoadConst(index(0), words[1]),
        RamLfeOpcodeV1::Add => Op::Add(index(0), index(1), index(2)),
        RamLfeOpcodeV1::AddPlain => Op::AddPlain(index(0), index(1), words[2]),
        RamLfeOpcodeV1::SubPlain => Op::SubPlain(index(0), index(1), words[2]),
        RamLfeOpcodeV1::MulPlain => Op::MulPlain(index(0), index(1), words[2]),
        RamLfeOpcodeV1::Mul => Op::Mul(index(0), index(1), index(2)),
        RamLfeOpcodeV1::SelectEqZero => Op::SelectEqZero(index(0), index(1), index(2), index(3)),
        RamLfeOpcodeV1::Output => Op::Output(index(0)),
    };
    // The canonical tape slot is the tag followed by the parameters in the
    // order the descriptor lists them, then zero words.
    let fields = instruction_fields(instruction);
    assert_eq!(fields[0], u64::from(line.opcode.tag()));
    assert_eq!(&fields[1..=words.len()], words.as_slice());
    assert!(fields[words.len() + 1..].iter().all(|&word| word == 0));
    instruction
}

#[test]
fn descriptor_meanings_are_what_the_reference_interpreter_computes() {
    use crate::ram_lfe::reference::{
        RamLfeInitialMemoryV1, RamLfeReferenceInputV1, ram_lfe_reference_execute_v1,
    };
    // Register contents before the instruction, at the field edges, and the
    // immediates the plain instructions take.
    let registers: [[u16; 4]; 5] = [
        [9, 0, 11, 22],
        [9, 256, 255, 1],
        [9, 5, 256, 256],
        [9, 1, 0, 0],
        [9, 128, 200, 77],
    ];
    let immediates = [0_u64, 1, 200, 256];
    let lanes: [u16; 32] = std::array::from_fn(|lane| u16::try_from(250 + lane % 7).unwrap());
    let memory = RamLfeInitialMemoryV1::from_lanes(&lanes).unwrap();
    let input = RamLfeReferenceInputV1::from_bytes(&[3, 255, 0, 17]).unwrap();
    let mut checked = 0;
    for line in opcode_lines() {
        for before in registers {
            for immediate in immediates {
                let instruction = typed(&line, immediate);
                let mut tape: Vec<Op> = (0..4_u16)
                    .map(|register| {
                        Op::LoadConst(register, u64::from(before[usize::from(register)]))
                    })
                    .collect();
                tape.extend([instruction, Op::Output(0)]);
                let execution = ram_lfe_reference_execute_v1(
                    RamLfeClassV1::Bounded,
                    &build(&tape),
                    &memory,
                    &input,
                )
                .unwrap();
                let trace = execution.trace();
                // Row 4 follows the four loads; row 5 follows the instruction.
                let row = trace.snapshot(4).unwrap();
                assert_eq!(&row[..4], &before);
                assert_eq!(&row[4..], &lanes);
                let resolve = |name: &str, index: Option<&str>| -> u32 {
                    u32::from(match (name, index) {
                        ("imm", None) => u16::try_from(immediate).unwrap(),
                        ("input", Some(slot)) => {
                            input.slots()[usize::try_from(operand_index(slot)).unwrap()]
                        }
                        ("state", Some(lane)) => {
                            row[4 + usize::try_from(operand_index(lane)).unwrap()]
                        }
                        (register, None) => row[usize::try_from(operand_index(register)).unwrap()],
                        other => panic!("descriptor reads an unknown value {other:?}"),
                    })
                };
                let value = |expression: &str| {
                    u16::try_from(Expression::evaluate(expression, Some(257), &resolve)).unwrap()
                };
                let mut expected = row.to_vec();
                let mut outputs = Vec::new();
                if let Some(source) = line
                    .meaning
                    .strip_prefix("append(")
                    .and_then(|rest| rest.strip_suffix(')'))
                {
                    outputs.push(value(source));
                } else {
                    let (target, expression) = line.meaning.split_once('=').unwrap();
                    let cell = match target {
                        "dst" => usize::try_from(operand_index("dst")).unwrap(),
                        "state[lane]" => 4 + usize::try_from(operand_index("lane")).unwrap(),
                        other => panic!("descriptor writes an unknown target `{other}`"),
                    };
                    expected[cell] = value(expression);
                }
                assert_eq!(
                    trace.snapshot(5).unwrap(),
                    expected,
                    "{} with registers {before:?} and immediate {immediate}",
                    line.text()
                );
                // The closing `Output(0)` appends register zero after the instruction.
                outputs.push(expected[0]);
                assert_eq!(execution.output().scalars(), outputs, "{}", line.text());
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 11 * 5 * 4);
}

#[test]
fn descriptor_rank_rules_are_what_class_accounting_computes() {
    // Ranks of the four registers and of the bound lane before the instruction.
    let cases: [([u16; 4], u16); 4] = [
        ([0, 0, 0, 0], 0),
        ([9, 1, 2, 3], 4),
        ([9, 6, 15, 2], 7),
        ([9, 3, 4, 15], 16),
    ];
    let lane = usize::try_from(operand_index("lane")).unwrap();
    let mut checked = 0;
    for line in opcode_lines() {
        for (registers, lane_rank) in cases {
            let mut accounting = Accounting::new(RamLfeClassV1::Bounded, 1).unwrap();
            *accounting.registers = registers;
            accounting.lanes[lane] = lane_rank;
            let resolve = |name: &str, index: Option<&str>| -> u32 {
                u32::from(match (name, index) {
                    ("state", Some(_)) => lane_rank,
                    (register, None) => {
                        registers[usize::try_from(operand_index(register)).unwrap()]
                    }
                    other => panic!("descriptor ranks an unknown value {other:?}"),
                })
            };
            let expected = u16::try_from(Expression::evaluate(line.rank, None, &resolve)).unwrap();
            accounting.step(0, typed(&line, 5)).unwrap();
            let mut ranks = registers;
            let mut lanes = [0_u16; RAM_LFE_V1_STATE_LANES];
            lanes[lane] = lane_rank;
            match line.meaning.split_once('=').map(|(target, _)| target) {
                Some("dst") => ranks[0] = expected,
                Some("state[lane]") => lanes[lane] = expected,
                // An appended output has the rank of its source and stores none.
                _ => assert_eq!(expected, registers[1]),
            }
            assert_eq!(*accounting.registers, ranks, "{}", line.text());
            assert_eq!(*accounting.lanes, lanes, "{}", line.text());
            checked += 1;
        }
    }
    assert_eq!(checked, 44);
}

fn class_line(class: RamLfeClassV1) -> String {
    let opcodes = RamLfeOpcodeV1::ALL
        .into_iter()
        .filter(|&opcode| class.admits(opcode))
        .map(|opcode| opcode.tag().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let (rank, refreshes) = (class.max_rank(), class.max_refreshes());
    format!("class={class};opcodes={opcodes};max-rank={rank};max-refreshes={refreshes}")
}

/// Rebuild the descriptor from the compiled constants and tables. The opcode
/// lines are the descriptor's own, which the two tests above compare with the
/// reference interpreter and with class accounting.
fn descriptor_from_tables() -> String {
    const MODULUS: u16 = RAM_LFE_V1_PLAINTEXT_MODULUS;
    const REGISTERS: usize = RAM_LFE_V1_REGISTERS;
    const LANES: usize = RAM_LFE_V1_STATE_LANES;
    const SLOTS: usize = RAM_LFE_V1_INPUT_SLOTS;
    const BYTES: usize = RAM_LFE_V1_MAX_INPUT_BYTES;
    const INSTRUCTIONS: usize = RAM_LFE_V1_MAX_INSTRUCTIONS;
    const OUTPUTS: usize = RAM_LFE_V1_MAX_OUTPUTS;
    const CONTEXT: &str = crate::ram_lfe::initialization::CONTEXT_V1;
    const STREAM: usize = RAM_LFE_V1_STATE_LANES * 32;
    const ASSOCIATED: usize = crate::RAM_LFE_PROGRAM_ASSOCIATED_DATA_MAX_BYTES;
    let scalar = MODULUS - 1;
    let (frame, fields) = crate::ram_lfe::initialization::INITIALIZATION_FRAME;
    let fields = fields.join(",");
    let mut lines = vec![
        "iroha.ram_lfe.plaintext_semantics.v1".to_owned(),
        format!("field=F{MODULUS};scalar=0..{scalar};arithmetic=mod{MODULUS}"),
        format!(
            "registers={REGISTERS};register-init=0;state-lanes={LANES};state-init=per-execution;state-persistence=none"
        ),
        format!(
            "input-slots={SLOTS};input=slot0:length(0..{BYTES}),slots1..length:byte(0..255),rest:0"
        ),
        format!(
            "instructions=1..{INSTRUCTIONS};outputs=1..{OUTPUTS};output=ordered-scalar(0..{scalar})-snapshot;immediate=0..{scalar}"
        ),
        "tape=48-bytes-per-instruction;words=6*u64le;unused-words=0".to_owned(),
    ];
    lines.extend(opcode_lines().iter().map(OpcodeLine::text));
    lines.extend(RamLfeClassV1::ALL.map(class_line));
    lines.push(
        "refresh=plaintext-identity;schedule=lazy;trigger=result-rank>max-rank;targets=distinct-nonzero-rank-operand-registers;order=operand;effect=rank:=0,in-place"
            .to_owned(),
    );
    lines.push(format!(
        "initializer=blake3-derive-key-xof;context={CONTEXT};frame={frame};fields={fields};stream-bytes={STREAM};lane=32-bytes-unsigned-big-endian-mod{MODULUS};lane-order=ascending"
    ));
    lines.push(format!("associated-data=0..{ASSOCIATED}-bytes"));
    lines.join("\n") + "\n"
}

#[test]
fn descriptor_is_exactly_the_compiled_constants_and_tables() {
    const CONDITION: u16 = RAM_LFE_V1_SELECT_CONDITION_RANK;
    const BRANCH: u16 = RAM_LFE_V1_SELECT_BRANCH_RANK;
    assert_eq!(
        RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR,
        descriptor_from_tables()
    );
    // The select rank rule in the descriptor is the compiled pair of constants.
    assert_eq!(
        opcode_lines()[9].rank,
        format!("max(cond+{CONDITION},zero+{BRANCH},nonzero+{BRANCH})")
    );
}

fn fenced_block<'a>(document: &'a str, marker: &str) -> &'a str {
    let start = document
        .find(marker)
        .unwrap_or_else(|| panic!("specification lacks `{marker}`"));
    let body = &document[start + marker.len()..];
    let open = body.find("```text\n").expect("fenced block follows marker") + "```text\n".len();
    let close = body[open..].find("```").expect("fenced block is closed");
    &body[open..open + close]
}

#[test]
fn specification_carries_the_exact_descriptor() {
    // Read with Unix line endings, whatever the checkout wrote: the descriptor
    // is compared byte for byte.
    let document =
        crate::ram_lfe::specification_tests::repository_file("specs/ram_lfe_execution_proof.md");
    assert_eq!(
        fenced_block(&document, "<!-- ram-lfe-v1-plaintext-semantics -->"),
        RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR
    );
}

#[test]
fn plaintext_semantics_hash_is_pinned_and_domain_separated() {
    let hash = ram_lfe_v1_plaintext_semantics_hash();
    assert_eq!(
        hash,
        Hash::new(
            [
                PLAINTEXT_SEMANTICS_DOMAIN,
                RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR.as_bytes()
            ]
            .concat()
        )
    );
    assert_ne!(
        hash,
        Hash::new(RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR.as_bytes())
    );
    assert_eq!(
        hex::encode(hash.as_ref()),
        "9e9e03d525dbe2b636182afacf550dbc2b9df921d86de2334ccd5f3d6ae26cc5"
    );
}

#[test]
fn class_identifiers_limits_and_codec_are_fixed() {
    let expected = [
        (RamLfeClassV1::Affine, "affine.v1", 0, 0),
        (RamLfeClassV1::Bounded, "bounded.v1", 16, 0),
        (RamLfeClassV1::Refresh, "refresh.v1", 16, 64),
    ];
    assert_eq!(RamLfeClassV1::ALL.len(), expected.len());
    let mut frames = std::collections::BTreeSet::new();
    for (index, ((class, name, rank, refreshes), listed)) in
        expected.into_iter().zip(RamLfeClassV1::ALL).enumerate()
    {
        assert_eq!(class, listed);
        // A class encodes as its declaration index.
        assert_eq!(
            norito::codec::Encode::encode(&class),
            u32::try_from(index).unwrap().to_le_bytes()
        );
        assert_eq!(class.as_str(), name);
        assert_eq!(class.to_string(), name);
        assert_eq!(class.max_rank(), rank);
        assert_eq!(class.max_refreshes(), refreshes);
        let frame = norito::encode_canonical(&class).unwrap();
        assert_eq!(
            norito::decode_canonical::<RamLfeClassV1>(&frame).unwrap(),
            class
        );
        assert!(frames.insert(frame));
    }
}

#[test]
fn class_decoding_rejects_every_unknown_discriminant() {
    // Frame a raw discriminant with the header flags a canonical class frame carries.
    let canonical = norito::encode_canonical(&RamLfeClassV1::Affine).unwrap();
    let flags = norito::core::from_bytes_view(&canonical).unwrap().flags();
    let frame = |discriminant: u32| {
        norito::core::frame_bare_with_header_flags::<RamLfeClassV1>(
            &discriminant.to_le_bytes(),
            flags,
        )
        .unwrap()
    };
    // The hand-built frame is the canonical frame of each declared class.
    for (discriminant, class) in RamLfeClassV1::ALL.into_iter().enumerate() {
        let discriminant = u32::try_from(discriminant).unwrap();
        assert_eq!(
            frame(discriminant),
            norito::encode_canonical(&class).unwrap()
        );
        assert_eq!(
            norito::decode_canonical::<RamLfeClassV1>(&frame(discriminant)).unwrap(),
            class
        );
    }
    // No other discriminant decodes to a class.
    for discriminant in [3_u32, 4, 255, 256, u32::MAX] {
        assert!(
            norito::decode_canonical::<RamLfeClassV1>(&frame(discriminant)).is_err(),
            "discriminant {discriminant} must not decode"
        );
        assert!(
            <RamLfeClassV1 as norito::codec::Decode>::decode(&mut &discriminant.to_le_bytes()[..])
                .is_err()
        );
    }
}

/// Smallest structurally valid tape that contains one instruction of each opcode.
fn single_opcode_program(instruction: Op) -> HiddenRamFheProgram {
    match instruction {
        Op::Output(_) => build(&[instruction]),
        _ => build(&[instruction, Op::Output(0)]),
    }
}

#[test]
fn every_class_accepts_or_rejects_each_of_the_eleven_instructions() {
    use RamLfeOpcodeV1::*;
    let admitted = |class: RamLfeClassV1, opcode: RamLfeOpcodeV1| match class {
        RamLfeClassV1::Affine => [
            LoadInput, LoadState, StoreState, LoadConst, Add, AddPlain, SubPlain, MulPlain, Output,
        ]
        .contains(&opcode),
        RamLfeClassV1::Bounded | RamLfeClassV1::Refresh => true,
    };
    let mut checked = 0;
    for class in RamLfeClassV1::ALL {
        for instruction in OPCODES {
            let opcode = instruction.opcode();
            let program = single_opcode_program(instruction);
            let result = class.membership(&program);
            assert_eq!(class.admits(opcode), admitted(class, opcode));
            if admitted(class, opcode) {
                assert_eq!(
                    result.unwrap().class(),
                    class,
                    "{class} must admit {opcode}"
                );
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    RamLfeError::InstructionOutsideClass {
                        class,
                        instruction: 0,
                        opcode,
                    },
                    "{class} must reject {opcode}"
                );
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 33);
    // Exactly the two ciphertext-multiplying opcodes are outside affine.v1.
    assert_eq!(
        RamLfeOpcodeV1::ALL
            .into_iter()
            .filter(|&opcode| !RamLfeClassV1::Affine.admits(opcode))
            .collect::<Vec<_>>(),
        [Mul, SelectEqZero]
    );
}

#[test]
fn affine_rejects_a_late_multiplication_at_its_exact_position() {
    let program = build(&[
        Op::LoadInput(0, 1),
        Op::AddPlain(0, 0, 3),
        Op::Output(0),
        Op::SelectEqZero(1, 0, 0, 0),
        Op::Output(1),
    ]);
    assert_eq!(
        RamLfeClassV1::Affine.membership(&program).unwrap_err(),
        RamLfeError::InstructionOutsideClass {
            class: RamLfeClassV1::Affine,
            instruction: 3,
            opcode: RamLfeOpcodeV1::SelectEqZero,
        }
    );
    assert!(RamLfeClassV1::Bounded.membership(&program).is_ok());
}

fn multiplication_chain(multiplications: usize) -> HiddenRamFheProgram {
    let mut tape = vec![Op::LoadInput(0, 1)];
    tape.extend(std::iter::repeat_n(Op::Mul(0, 0, 0), multiplications));
    tape.push(Op::Output(0));
    build(&tape)
}

#[test]
fn bounded_admits_rank_sixteen_and_rejects_rank_seventeen() {
    let report = RamLfeClassV1::Bounded
        .membership(&multiplication_chain(16))
        .unwrap();
    assert_eq!(report.peak_rank(), 16);
    assert_eq!(report.ciphertext_multiplications(), 16);
    assert_eq!(report.refresh_count(), 0);
    assert_eq!(report.instruction_count(), 18);
    assert_eq!(report.output_count(), 1);
    assert_eq!(
        RamLfeClassV1::Bounded
            .membership(&multiplication_chain(17))
            .unwrap_err(),
        RamLfeError::ClassRankExceeded {
            class: RamLfeClassV1::Bounded,
            instruction: 17,
            rank: 17,
            limit: 16,
        }
    );
    // The diagnostic evaluator admits exactly the bounded class.
    assert!(crate::validate_hidden_ram_fhe_program(&multiplication_chain(16)).is_ok());
    assert!(
        crate::validate_hidden_ram_fhe_program(&multiplication_chain(17))
            .unwrap_err()
            .to_string()
            .contains("instruction 17 exceeds the RAM-FHE multiplicative-depth budget 16")
    );
}

#[test]
fn select_counts_ten_condition_multiplications_and_one_per_branch() {
    // A rank-zero condition and rank-zero branches give rank ten.
    let report = RamLfeClassV1::Bounded
        .membership(&build(&[
            Op::LoadInput(0, 1),
            Op::SelectEqZero(1, 0, 0, 0),
            Op::Output(1),
        ]))
        .unwrap();
    assert_eq!(report.peak_rank(), 10);
    assert_eq!(report.ciphertext_multiplications(), 10);
    // A rank-six condition reaches exactly sixteen; rank seven does not fit.
    let condition = |rank: usize| {
        let mut tape = vec![Op::LoadInput(0, 1), Op::LoadInput(1, 2)];
        tape.extend(std::iter::repeat_n(Op::Mul(0, 0, 0), rank));
        tape.extend([Op::SelectEqZero(2, 0, 1, 1), Op::Output(2)]);
        build(&tape)
    };
    assert_eq!(
        RamLfeClassV1::Bounded
            .membership(&condition(6))
            .unwrap()
            .peak_rank(),
        16
    );
    assert_eq!(
        RamLfeClassV1::Bounded
            .membership(&condition(7))
            .unwrap_err(),
        RamLfeError::ClassRankExceeded {
            class: RamLfeClassV1::Bounded,
            instruction: 9,
            rank: 17,
            limit: 16,
        }
    );
    // A branch contributes its own rank plus one, for either branch position.
    for branch_is_zero_operand in [true, false] {
        let branch = |rank: usize| {
            let mut tape = vec![Op::LoadInput(0, 1), Op::LoadInput(1, 2)];
            tape.extend(std::iter::repeat_n(Op::Mul(1, 1, 1), rank));
            tape.push(if branch_is_zero_operand {
                Op::SelectEqZero(2, 0, 1, 0)
            } else {
                Op::SelectEqZero(2, 0, 0, 1)
            });
            tape.push(Op::Output(2));
            build(&tape)
        };
        assert_eq!(
            RamLfeClassV1::Bounded
                .membership(&branch(15))
                .unwrap()
                .peak_rank(),
            16
        );
        assert_eq!(
            RamLfeClassV1::Bounded.membership(&branch(16)).unwrap_err(),
            RamLfeError::ClassRankExceeded {
                class: RamLfeClassV1::Bounded,
                instruction: 18,
                rank: 17,
                limit: 16,
            }
        );
    }
}

#[test]
fn rank_follows_operands_memory_and_plain_operations_and_resets_on_loads() {
    // Rank sixteen survives Add, the three plain operations and a memory round trip.
    let carried = |tail: &[Op]| {
        let mut tape = vec![Op::LoadInput(0, 1)];
        tape.extend(std::iter::repeat_n(Op::Mul(0, 0, 0), 16));
        tape.extend_from_slice(tail);
        tape.push(Op::Output(1));
        build(&tape)
    };
    for tail in [
        vec![Op::Add(1, 0, 2), Op::Mul(1, 1, 2)],
        vec![Op::Add(1, 2, 0), Op::Mul(1, 2, 1)],
        vec![Op::AddPlain(1, 0, 5), Op::Mul(1, 1, 1)],
        vec![Op::SubPlain(1, 0, 5), Op::Mul(1, 1, 1)],
        vec![Op::MulPlain(1, 0, 5), Op::Mul(1, 1, 1)],
        vec![
            Op::StoreState(31, 0),
            Op::LoadState(1, 31),
            Op::Mul(1, 1, 2),
        ],
    ] {
        let program = carried(&tail);
        let instruction = program.instruction_count() - 2;
        assert_eq!(
            RamLfeClassV1::Bounded.membership(&program).unwrap_err(),
            RamLfeError::ClassRankExceeded {
                class: RamLfeClassV1::Bounded,
                instruction,
                rank: 17,
                limit: 16,
            }
        );
    }
    // Loading an input or a constant replaces the register's rank with zero, and
    // an untouched lane has rank zero.
    for reset in [
        Op::LoadInput(0, 2),
        Op::LoadConst(0, 9),
        Op::LoadState(0, 30),
    ] {
        let program = carried(&[reset, Op::Mul(1, 0, 0)]);
        assert_eq!(
            RamLfeClassV1::Bounded
                .membership(&program)
                .unwrap()
                .peak_rank(),
            16
        );
    }
}

fn refresh_points(report: &RamLfeClassReportV1) -> Vec<(u16, u16)> {
    report
        .refresh_points()
        .map(|point| (point.instruction, point.register))
        .collect()
}

#[test]
fn refresh_schedule_is_lazy_deduplicated_and_in_operand_order() {
    // The seventeenth squaring refreshes its single distinct operand once.
    let report = RamLfeClassV1::Refresh
        .membership(&multiplication_chain(17))
        .unwrap();
    assert_eq!(refresh_points(&report), [(17, 0)]);
    assert_eq!(report.refresh_count(), 1);
    assert_eq!(report.peak_rank(), 16);
    assert_eq!(report.ciphertext_multiplications(), 17);
    assert_eq!(format!("{report:?}"), "[REDACTED RAM-LFE class report]");
    // No refresh happens while the result fits.
    assert_eq!(
        RamLfeClassV1::Refresh
            .membership(&multiplication_chain(16))
            .unwrap()
            .refresh_count(),
        0
    );

    // Three distinct operands with nonzero rank are refreshed in operand order
    // (condition, zero branch, nonzero branch), not in register order.
    let mut tape = vec![
        Op::LoadInput(1, 1),
        Op::LoadInput(2, 2),
        Op::LoadInput(3, 3),
    ];
    tape.extend(std::iter::repeat_n(Op::Mul(3, 3, 3), 7));
    tape.extend([Op::Mul(1, 1, 1), Op::Mul(2, 2, 2)]);
    tape.extend([Op::SelectEqZero(0, 3, 2, 1), Op::Output(0)]);
    let report = RamLfeClassV1::Refresh.membership(&build(&tape)).unwrap();
    assert_eq!(refresh_points(&report), [(12, 3), (12, 2), (12, 1)]);
    // After the refresh every operand has rank zero, so the result has rank ten.
    assert_eq!(report.peak_rank(), 10);

    // A rank-zero operand is not refreshed, and a repeated operand is refreshed once.
    let mut tape = vec![Op::LoadInput(0, 1), Op::LoadInput(1, 2)];
    tape.extend(std::iter::repeat_n(Op::Mul(0, 0, 0), 7));
    tape.extend([Op::SelectEqZero(2, 0, 1, 0), Op::Output(2)]);
    let report = RamLfeClassV1::Refresh.membership(&build(&tape)).unwrap();
    assert_eq!(refresh_points(&report), [(9, 0)]);
}

#[test]
fn refresh_handles_destination_aliasing_and_rank_through_memory() {
    // The destination aliases the refreshed operand: the operand is refreshed
    // first and the destination then receives the recomputed rank.
    let mut tape = vec![Op::LoadInput(0, 1)];
    tape.extend(std::iter::repeat_n(Op::Mul(0, 0, 0), 16));
    tape.extend([Op::Mul(0, 0, 0), Op::Mul(0, 0, 0), Op::Output(0)]);
    let report = RamLfeClassV1::Refresh.membership(&build(&tape)).unwrap();
    assert_eq!(refresh_points(&report), [(17, 0)]);
    assert_eq!(report.peak_rank(), 16);

    // A stored rank returns through the lane; the refresh acts on the register
    // that was loaded, and the lane keeps its rank for the next load.
    let mut tape = vec![Op::LoadInput(0, 1)];
    tape.extend(std::iter::repeat_n(Op::Mul(0, 0, 0), 16));
    tape.extend([
        Op::StoreState(4, 0),
        Op::LoadConst(0, 1),
        Op::LoadState(1, 4),
        Op::Mul(2, 1, 1),
        Op::LoadState(3, 4),
        Op::Mul(2, 3, 3),
        Op::Output(2),
    ]);
    let report = RamLfeClassV1::Refresh.membership(&build(&tape)).unwrap();
    assert_eq!(refresh_points(&report), [(20, 1), (22, 3)]);
    assert!(RamLfeClassV1::Bounded.membership(&build(&tape)).is_err());
}

fn select_chain(selects: usize) -> HiddenRamFheProgram {
    let mut tape = vec![Op::LoadInput(0, 1)];
    tape.extend(std::iter::repeat_n(Op::SelectEqZero(0, 0, 0, 0), selects));
    tape.push(Op::Output(0));
    build(&tape)
}

#[test]
fn refresh_enforces_the_total_refresh_count() {
    // The first select needs no refresh; every later one needs exactly one.
    let report = RamLfeClassV1::Refresh
        .membership(&select_chain(65))
        .unwrap();
    assert_eq!(report.refresh_count(), 64);
    assert_eq!(report.ciphertext_multiplications(), 650);
    assert_eq!(
        refresh_points(&report),
        (2..=65)
            .map(|instruction| (instruction, 0))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        RamLfeClassV1::Refresh
            .membership(&select_chain(66))
            .unwrap_err(),
        RamLfeError::ClassRefreshLimitExceeded {
            class: RamLfeClassV1::Refresh,
            instruction: 66,
            limit: 64,
        }
    );
}

#[test]
fn classes_are_nested_and_membership_reports_structural_faults() {
    let affine = build(&[Op::LoadInput(0, 1), Op::MulPlain(0, 0, 7), Op::Output(0)]);
    let bounded = multiplication_chain(16);
    let refresh = multiplication_chain(40);
    let admitted = |program: &HiddenRamFheProgram| {
        RamLfeClassV1::ALL.map(|class| class.membership(program).is_ok())
    };
    assert_eq!(admitted(&affine), [true, true, true]);
    assert_eq!(admitted(&bounded), [false, true, true]);
    assert_eq!(admitted(&refresh), [false, false, true]);

    // A malformed tape is a structural error in every class.
    let malformed = from_public_test_parts(1, 4, 32, &[Op::LoadInput(4, 0), Op::Output(0)]);
    for class in RamLfeClassV1::ALL {
        let error = class.membership(&malformed).unwrap_err();
        assert!(error.to_string().contains("register 4 out of bounds"));
    }
}

#[test]
fn maximum_tape_is_accounted_without_overflow() {
    // 255 selects after one load: the densest multiplication workload.
    let mut tape = vec![Op::LoadInput(1, 1)];
    tape.extend(std::iter::repeat_n(Op::SelectEqZero(0, 1, 1, 1), 254));
    tape.push(Op::Output(0));
    let program = build(&tape);
    assert_eq!(program.instruction_count(), RAM_LFE_V1_MAX_INSTRUCTIONS);
    let report = RamLfeClassV1::Bounded.membership(&program).unwrap();
    assert_eq!(report.ciphertext_multiplications(), 2540);
    assert_eq!(report.peak_rank(), 10);
    assert_eq!(report.instruction_count(), 256);
}
