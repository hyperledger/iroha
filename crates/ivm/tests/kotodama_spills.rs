//! Tests that exercise spilled temporaries and nested calls with spills.
use ivm::{
    IVM, LiteralKindV1, ProgramMetadata, decode_literal_descriptor, encoding, host::DefaultHost,
    instruction,
};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn many_locals_force_spills_and_compute() {
    // Create a chain of additions to overflow the allocatable register pool.
    // The allocator reserves 18 regs; this uses ~40 distinct temps.
    let mut body = String::new();
    body.push_str("let a0 = 0;\n");
    for i in 1..40 {
        body.push_str(&format!("let a{} = a{} + 1;\n", i, i - 1));
    }
    body.push_str("return a39;\n");
    let src =
        format!("seiyaku SpillChain {{ view fn main() authorize(anyone) -> int {{\n{body}\n}} }}");
    let code = KotodamaCompiler::new()
        .compile_source(&src)
        .expect("compile spills");
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&code).unwrap();
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("execute spills");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 39);
}
#[test]
fn literal_heavy_set_account_detail_compiles_under_spill_pressure() {
    const COUNT: usize = 256;
    let mut src = String::from(
        "seiyaku SpillLiterals { permission Test;  kotoage fn main() authorize(Test) {\n",
    );
    for i in 0..COUNT {
        src.push_str(&format!(
            "  ledger::account::set_metadata(account: context::authority(), key: Name::parse(\"literal{i}\"), value: Json::parse(\"{{\\\"value\\\":{i}}}\"));\n"
        ));
    }
    src.push_str("}\n}\n");
    KotodamaCompiler::new()
        .compile_source(&src)
        .expect("literal-heavy set_account_detail under spills");
}
#[test]
fn odd_eight_byte_nested_call_frame_is_padded_and_restored() {
    let source = r#"
        seiyaku NestedFrameAlignment {
            fn leaf() {}
            fn middle() { leaf(); }
            view fn main() authorize(anyone) { middle(); }
        }
    "#;
    let (artifact, _manifest, report) = KotodamaCompiler::new()
        .compile_source_with_manifest_and_report(source)
        .expect("compile nested-call alignment fixture");
    let middle = report
        .budget_report
        .iter()
        .find(|function| function.function_name == "middle")
        .expect("middle function budget report");
    assert_eq!(
        middle.frame_bytes, 16,
        "the return-address-only frame must include eight bytes of alignment padding"
    );
    assert!(
        report
            .budget_report
            .iter()
            .all(|function| function.frame_bytes % 16 == 0)
    );
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&artifact)
        .expect("load nested-call alignment fixture");
    let initial_stack_pointer = vm.register(31);
    common::select_kotodama_entrypoint(&mut vm, &artifact, "main");
    vm.run().expect("execute nested-call alignment fixture");
    assert_eq!(vm.register(31), initial_stack_pointer);
}
#[test]
fn frame_and_spill_offsets_above_four_kib_are_bounded_and_execute() {
    const LIVE_VALUES: usize = 700;
    const BLOCK_HEIGHT: u64 = 3;
    let mut body = String::from("let int seed = context::block_height();\n");
    for index in 0..LIVE_VALUES {
        body.push_str(&format!("let int value{index} = seed + {index};\n"));
    }
    body.push_str("var int total = 0;\n");
    for index in 0..LIVE_VALUES {
        body.push_str(&format!("total = total + value{index};\n"));
    }
    body.push_str("return total;\n");
    let source =
        format!("seiyaku WideFrame {{ view fn main() authorize(anyone) -> int {{\n{body}}}\n}}");
    let compiler = KotodamaCompiler::new();
    let (artifact, _manifest, report) = compiler
        .compile_source_with_manifest_and_report(&source)
        .expect("compile >4KiB frame fixture");
    assert_eq!(
        artifact,
        compiler
            .compile_source(&source)
            .expect("repeat >4KiB frame compilation"),
        "wide frame lowering must be deterministic"
    );
    let metadata = ProgramMetadata::parse(&artifact).expect("parse wide-frame artifact");
    let implementation = report
        .budget_report
        .iter()
        .filter(|function| function.frame_bytes > 4096)
        .max_by_key(|function| function.frame_bytes)
        .expect("fixture must force a frame above 4KiB");
    assert_eq!(
        implementation.frame_bytes % 16,
        0,
        "large frames must retain the V1 16-byte stack alignment"
    );
    let frame_bytes = i64::from(implementation.frame_bytes);
    let words = artifact[metadata.code_offset + implementation.pc_start as usize
        ..metadata.code_offset + implementation.pc_end as usize]
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("instruction word")))
        .collect::<Vec<_>>();
    assert_eq!(
        instruction::wide::opcode(words[0]),
        instruction::wide::memory::LDI64,
        "wide prologue adjustment must be one indexed scalar load"
    );
    assert_eq!(
        instruction::wide::opcode(words[1]),
        instruction::wide::arithmetic::ADD,
        "wide prologue adjustment must complete with one ADD"
    );
    assert_eq!(
        instruction::wide::opcode(words[words.len() - 3]),
        instruction::wide::memory::LDI64,
        "wide epilogue adjustment must be one indexed scalar load"
    );
    assert_eq!(
        instruction::wide::opcode(words[words.len() - 2]),
        instruction::wide::arithmetic::ADD,
        "wide epilogue adjustment must complete with one ADD"
    );
    assert_eq!(
        instruction::wide::opcode(words[words.len() - 1]),
        instruction::wide::control::JALR
    );
    let section = metadata.literal_section.expect("wide-frame scalar table");
    let descriptors = (0..section.count)
        .map(|index| {
            let start = section.entries_start + index * 8;
            let raw = u64::from_le_bytes(
                artifact[start..start + 8]
                    .try_into()
                    .expect("literal descriptor"),
            );
            decode_literal_descriptor(raw).expect("validated literal descriptor")
        })
        .collect::<Vec<_>>();
    let scalar_values = descriptors
        .iter()
        .enumerate()
        .filter_map(|(index, (kind, offset))| {
            (*kind == LiteralKindV1::I64).then(|| {
                let start = section.start + usize::try_from(*offset).expect("literal offset");
                let end = descriptors
                    .get(index + 1)
                    .map_or(section.data_end, |(_, next)| {
                        section.start + usize::try_from(*next).expect("literal offset")
                    });
                i64::from_le_bytes(
                    artifact[start..end]
                        .try_into()
                        .expect("i64 literal payload is exactly eight bytes"),
                )
            })
        })
        .collect::<Vec<_>>();
    assert!(scalar_values.contains(&-frame_bytes));
    assert!(scalar_values.contains(&frame_bytes));
    assert!(
        scalar_values.iter().any(|offset| *offset > 4096),
        "large positive spill/address offsets must use indexed scalars"
    );
    let mut host = DefaultHost::new();
    host.set_current_block_height(BLOCK_HEIGHT);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&artifact)
        .expect("load wide-frame artifact");
    common::select_kotodama_entrypoint(&mut vm, &artifact, "main");
    vm.run().expect("execute wide-frame artifact");
    let expected =
        LIVE_VALUES as u64 * BLOCK_HEIGHT + (LIVE_VALUES as u64 * (LIVE_VALUES as u64 - 1)) / 2;
    assert_eq!(
        common::decode_i64_return_word(&vm, 0),
        i64::try_from(expected).expect("bounded fixture result")
    );
    assert!(
        words.windows(3).any(|window| {
            instruction::wide::opcode(window[0]) == instruction::wide::memory::LDI64
                && instruction::wide::opcode(window[1]) == instruction::wide::arithmetic::ADD
                && matches!(
                    instruction::wide::opcode(window[2]),
                    instruction::wide::memory::LOAD64 | instruction::wide::memory::STORE64
                )
        }),
        "large spill offsets must use a bounded three-word address sequence"
    );
    assert!(
        words
            .iter()
            .all(|word| { instruction::wide::opcode(*word) != instruction::wide::arithmetic::SLL })
    );
    let _ = encoding::wide::decode_literal(words[0]);
}
