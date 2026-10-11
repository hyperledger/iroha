//! Exact scalar/production frame traffic and source-bound split lifetime controls.
use super::*;
use crate::session::{CompileOutput, CompileRequest, CompilerSession};
fn compile(source: &str, scalar: bool) -> CompileOutput {
    compile_with_original_zeros(source, scalar, false)
}
fn compile_with_original_zeros(source: &str, scalar: bool, original_zeros: bool) -> CompileOutput {
    crate::session::run_with_compiler_stack(|| {
        let build = || {
            CompilerSession::default()
                .build(CompileRequest {
                    source,
                    source_name: None,
                })
                .expect("complete canonical compiler pipeline")
        };
        let emit = || {
            if scalar {
                local_emission::with_scalar_emission(build)
            } else {
                build()
            }
        };
        if original_zeros {
            numeric_zero::with_original_zeros(emit)
        } else {
            emit()
        }
    })
    .expect("original compiler worker")
}
fn pair(source: &str) -> (CompileOutput, CompileOutput) {
    let before = compile(source, true);
    let after = compile(source, false);
    single_use_private::assert_public_metadata(&before, &after);
    let geometry = |output: &CompileOutput| {
        output
            .report
            .budget_report
            .iter()
            .map(|function| {
                let callable = output
                    .contract_interface
                    .callables
                    .iter()
                    .find(|callable| callable.entry_pc == function.pc_start)
                    .expect("exact authenticated callable owner");
                (
                    function.function_name.clone(),
                    (
                        function.frame_bytes,
                        callable.arguments.clone(),
                        callable.results.clone(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(geometry(&before), geometry(&after));
    assert_eq!(
        before.report.access_hint_diagnostics,
        after.report.access_hint_diagnostics
    );
    for (scalar, original) in [(true, &before), (false, &after)] {
        assert_eq!(
            compile(source, scalar).artifact,
            original.artifact,
            "complete scalar and production artifacts are each deterministic"
        );
    }
    (before, after)
}
fn implementation_ir(source: &str, declaration: &str) -> ir::Function {
    crate::session::run_with_compiler_stack(|| {
        let session = CompilerSession::default();
        let parsed = session
            .parse_compilation_unit(CompileRequest {
                source,
                source_name: None,
            })
            .expect("canonical source parse");
        let resolved = session
            .resolve_compilation_unit(parsed)
            .expect("canonical source resolution");
        let typed = session
            .type_effect_compilation_unit(resolved)
            .expect("canonical type/effect validation");
        let name = typed
            .items
            .iter()
            .find_map(|item| {
                let TypedItem::Function(function) = item;
                (function.name == declaration).then(|| entrypoint_ir_symbol_name(function))
            })
            .expect("original declaration");
        let compiler = Compiler::new();
        let lowered = compiler.lower_typed_program(typed.clone(), None).unwrap();
        let ssa = compiler.construct_ssa_program(lowered).unwrap();
        let optimized = compiler.optimize_ssa_program(ssa).unwrap();
        let mut codegen = compiler.destroy_ssa_program(optimized).unwrap();
        // The production compiler detaches debug-only provenance before physical
        // instruction positions become inputs to layout and register allocation.
        statement_sources::Sources::take(&mut codegen.ir_program, &typed);
        let mut function = codegen
            .ir_program
            .functions
            .into_iter()
            .find(|function| function.name == name)
            .expect("exact production IR function");
        // Allocation follows this original production layout, including every
        // instruction and terminator position. No standalone SSA plan is joined
        // to a separately optimized or differently laid-out emitted function.
        layout_compact_branch_fallthrough(&mut function).unwrap();
        function
    })
    .expect("original compiler worker")
}
fn words(output: &CompileOutput, name: &str, arguments: usize) -> (Vec<u32>, u32) {
    let metadata = ProgramMetadata::parse(&output.artifact).unwrap();
    let budget = output
        .report
        .budget_report
        .iter()
        .find(|entry| entry.function_name == name)
        .expect("original function report");
    let callable = metadata
        .contract_interface
        .as_ref()
        .unwrap()
        .callables
        .iter()
        .find(|callable| callable.entry_pc == budget.pc_start)
        .unwrap();
    assert_eq!(callable.frame_bytes, budget.frame_bytes);
    assert_eq!(callable.argument_word_count(), Some(arguments));
    assert_eq!(callable.result_word_count(), Some(1));
    (
        output.artifact[metadata.code_offset + budget.pc_start as usize
            ..metadata.code_offset + budget.pc_end as usize]
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect(),
        budget.frame_bytes,
    )
}
fn memory(words: &[u32]) -> Vec<u32> {
    words
        .iter()
        .copied()
        .filter(|word| {
            matches!(
                instruction::wide::opcode(*word),
                instruction::wide::memory::LOAD64 | instruction::wide::memory::STORE64
            )
        })
        .collect()
}
fn memory_counts(words: &[u32]) -> (usize, usize) {
    let count = |opcode| {
        words
            .iter()
            .filter(|word| instruction::wide::opcode(**word) == opcode)
            .count()
    };
    (
        count(instruction::wide::memory::LOAD64),
        count(instruction::wide::memory::STORE64),
    )
}
fn syscalls(words: &[u32]) -> Vec<u32> {
    words
        .iter()
        .copied()
        .filter(|word| {
            matches!(
                instruction::wide::opcode(*word),
                instruction::wide::system::SCALL | instruction::wide::system::SYSTEM
            )
        })
        .collect()
}
fn no_spill_or_callee_save(function: &ir::Function) {
    let plan = regalloc::allocate_with_splitting(function);
    assert!(plan.stack.is_empty(), "original values have no spill homes");
    assert_eq!(plan.frame_size, 0);
    assert!(
        plan.used_registers()
            .iter()
            .all(|register| regalloc::CALLER_CLOBBERED_REGS.contains(register)),
        "no original value needs a callee-saved register"
    );
}
pub(super) fn leaf_identity(source: &str) {
    let function = implementation_ir(source, "identity");
    assert!(!regalloc::has_internal_calls(&function));
    no_spill_or_callee_save(&function);
    let plan = regalloc::allocate_with_splitting(&function);
    let frame = crate::call_abi::CallFrameLayout::new(false, plan.frame_size, 0, 0, 0, 0).unwrap();
    assert_eq!(
        frame.bytes, 16,
        "both original saved table slots remain reserved"
    );
    let (before, after) = pair(source);
    let (scalar, scalar_frame) = words(&before, &function.name, 1);
    let (production, production_frame) = words(&after, &function.name, 1);
    assert_eq!((scalar_frame, production_frame), (16, 16));
    assert_eq!(
        memory_counts(&scalar),
        (3, 3),
        "exact original table traffic"
    );
    assert_eq!(
        memory_counts(&production),
        (2, 2),
        "exact production table traffic"
    );
    let saved_base =
        encode_store64_rv(regalloc::SP_REG as u8, 10, frame.argument_base_slot as i16).unwrap();
    let read_saved_base =
        encode_load64_rv(27, regalloc::SP_REG as u8, frame.argument_base_slot as i16).unwrap();
    assert_eq!(scalar.iter().filter(|word| **word == saved_base).count(), 1);
    assert_eq!(
        scalar
            .iter()
            .filter(|word| **word == read_saved_base)
            .count(),
        1
    );
    assert_eq!(
        memory(&scalar)
            .into_iter()
            .filter(|word| *word != saved_base && *word != read_saved_base)
            .collect::<Vec<_>>(),
        memory(&production),
        "only the unused private argument-base roundtrip disappears; exact incoming word and completed result table memory remain"
    );
    assert_eq!(
        production
            .iter()
            .filter(|word| **word == encode_addi(27, 10, 0).unwrap())
            .count(),
        1,
        "one original authenticated incoming base is retained"
    );
    assert_eq!(syscalls(&scalar), syscalls(&production));
    for code in [&scalar, &production] {
        assert_eq!(
            instruction::wide::opcode(*code.last().unwrap()),
            instruction::wide::control::JALR
        );
    }
}
pub(super) fn call_local(source: &str) {
    let function = implementation_ir(source, "run");
    assert!(function.params.is_empty());
    assert!(regalloc::has_internal_calls(&function));
    let mut calls = function
        .blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .filter_map(|instruction| match instruction {
            Instr::Call { callee, args, .. } | Instr::CallMulti { callee, args, .. } => {
                Some((callee.as_str(), args.len()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    calls.sort_unstable();
    assert_eq!(
        calls,
        [("relay", 1), ("relay", 1), ("swap", 2)],
        "original swap and both retained relay calls remain with exact argument counts"
    );
    no_spill_or_callee_save(&function);
    let (before, after) = pair(source);
    let (scalar, scalar_frame) = words(&before, &function.name, 0);
    let (production, production_frame) = words(&after, &function.name, 0);
    assert_eq!(
        (scalar_frame, production_frame),
        (64, 64),
        "return link, saved table bases and reusable outgoing tables retain exact geometry"
    );
    assert_eq!(
        memory_counts(&scalar),
        (6, 8),
        "exact original call table traffic without value spills"
    );
    assert_eq!(
        memory_counts(&production),
        (6, 7),
        "exact production call table traffic without value spills"
    );
    let allocation = regalloc::allocate_with_splitting(&function);
    let frame =
        crate::call_abi::CallFrameLayout::new(true, allocation.frame_size, 0, 0, 2, 2).unwrap();
    assert_eq!(frame.bytes, 64);
    let saved_base = encode_store64_rv(
        regalloc::SP_REG as u8,
        10,
        i16::try_from(frame.argument_base_slot).unwrap(),
    )
    .unwrap();
    assert_eq!(scalar.iter().filter(|word| **word == saved_base).count(), 1);
    assert_eq!(
        memory(&scalar)
            .into_iter()
            .filter(|word| *word != saved_base)
            .collect::<Vec<_>>(),
        memory(&production),
        "only the zero-parameter function's unused private argument-base store disappears; all return-link, argument and result-table memory remains exact"
    );
    assert_eq!(syscalls(&scalar), syscalls(&production));
}
pub(super) fn split_spill(source: &str) {
    let function = implementation_ir(source, "reuse");
    assert!(!regalloc::has_internal_calls(&function));
    let a0 = function
        .blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .find_map(|instruction| match instruction {
            Instr::LoadVar { dest, name } if name == "a0" => Some(*dest),
            _ => None,
        })
        .unwrap();
    let plan = regalloc::allocate_with_splitting(&function);
    let home = *plan.stack.get(&a0).expect("original a0 spill home");
    let split_register = plan
        .first_split_register(a0)
        .expect("actual a0 split register");
    assert!(regalloc::CALLER_CLOBBERED_REGS.contains(&split_register));
    let mut position = 0usize;
    let mut uses = Vec::new();
    for block in &function.blocks {
        for instruction in &block.instrs {
            if let Instr::NumericBinary {
                dest,
                op: BinaryOp::Add,
                left,
                right,
                ..
            } = instruction
            {
                let count = usize::from(*left == a0) + usize::from(*right == a0);
                if count != 0 {
                    uses.push((position, count, *dest));
                }
            }
            position += 1;
        }
        position += 1;
    }
    assert_eq!(
        uses.iter().map(|(_, count, _)| *count).collect::<Vec<_>>(),
        [2, 1, 1],
        "all four original a0 operands belong to their exact three checked additions"
    );
    let reloads = (0..position)
        .flat_map(|at| {
            plan.reloads_at(at)
                .iter()
                .filter(move |reload| reload.temp == a0)
                .map(move |reload| (at, reload.register))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reloads,
        [(uses[0].0, split_register)],
        "exactly one split reload feeds both aliased operands before the original numeric clobber"
    );
    assert_eq!(plan.register_for_use(a0, uses[0].0), Some(split_register));
    for (at, _, _) in &uses[1..] {
        assert_eq!(
            plan.register_for_use(a0, *at),
            None,
            "the first original numeric call ended its caller-saved segment; later reads retain canonical spill authority"
        );
    }
    let local = local_emission::Plan::new(&function, &plan).unwrap();
    let scalar_local = local_emission::with_scalar_emission(|| {
        local_emission::Plan::new(&function, &plan).unwrap()
    });
    for (index, (at, _, dest)) in uses.iter().enumerate() {
        let retained = local
            .output(*dest, *at)
            .expect("unique result retains its exact next original consumer");
        assert_eq!(scalar_local.output(*dest, *at), None);
        assert_eq!(retained.value, *dest);
        assert_eq!(retained.first_use_position, at + 1);
        let mut at = 0usize;
        let mut consumers = Vec::new();
        for block in &function.blocks {
            for instruction in &block.instrs {
                regalloc::visit_instr_uses(instruction, |value| {
                    if value == *dest {
                        consumers.push(at);
                    }
                });
                at += 1;
            }
            regalloc::visit_terminator_uses(&block.terminator, |value| {
                if value == *dest {
                    consumers.push(at);
                }
            });
            at += 1;
        }
        assert_eq!(consumers, [retained.consumer_position]);
        if index < 2 {
            assert_eq!(retained.consumer_position, uses[index + 1].0);
        } else {
            let final_add = function
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .find(|instruction| {
                    matches!(instruction,
                        Instr::NumericBinary { op: BinaryOp::Add, right, .. } if right == dest
                    )
                })
                .expect("the original final addition consumes quad exactly once");
            let Instr::NumericBinary { left, .. } = final_add else {
                unreachable!()
            };
            assert_ne!(*left, a0);
        }
    }
    let (before, after) = pair(source);
    let (scalar, scalar_frame) = words(&before, &function.name, 13);
    let (production, production_frame) = words(&after, &function.name, 13);
    assert_eq!(scalar_frame, production_frame);
    assert_eq!(
        syscalls(&scalar),
        syscalls(&production),
        "every original typed, metered state and numeric consumer stays in exact order"
    );
    let add = encoding::wide::encode_syscallx(syscalls::SYSCALL_INT_ADD);
    let saved_registers = plan
        .used_registers()
        .into_iter()
        .filter(|register| !regalloc::CALLER_CLOBBERED_REGS.contains(register))
        .count();
    assert!(
        function
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .all(|instruction| !matches!(instruction, Instr::StateValueEncode { .. }),)
    );
    let frame =
        crate::call_abi::CallFrameLayout::new(false, plan.frame_size, saved_registers, 0, 0, 0)
            .unwrap();
    assert_eq!(frame.bytes, scalar_frame as usize);
    assert_eq!(frame.spill_base, 16);
    let offset = i16::try_from(frame.spill_base + home).unwrap();
    let original_scalar_output = compile_with_original_zeros(source, true, true);
    let original_production_output = compile_with_original_zeros(source, false, true);
    single_use_private::assert_public_metadata(&before, &original_scalar_output);
    single_use_private::assert_public_metadata(&after, &original_production_output);
    let (original_scalar, original_scalar_frame) =
        words(&original_scalar_output, &function.name, 13);
    let (original_production, original_production_frame) =
        words(&original_production_output, &function.name, 13);
    assert_eq!(original_scalar_frame, scalar_frame);
    assert_eq!(original_production_frame, production_frame);
    for (code, original_zeros) in [
        (&scalar, false),
        (&production, false),
        (&original_scalar, true),
        (&original_production, true),
    ] {
        assert_eq!(
            syscalls(code),
            syscalls(&scalar),
            "all original checked consumers stay in exact order with either zero setup"
        );
        assert_eq!(code.iter().filter(|word| **word == add).count(), 16);
        let loads = code
            .iter()
            .enumerate()
            .filter_map(|(index, word)| {
                let (opcode, destination, base, immediate) = encoding::wide::decode_mem(*word);
                (opcode == instruction::wide::memory::LOAD64
                    && base == regalloc::SP_REG as u8
                    && i16::from(immediate) == offset)
                    .then_some((index, destination))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            loads
                .iter()
                .map(|(_, register)| *register)
                .collect::<Vec<_>>(),
            [split_register as u8, 11, 11],
            "one split reload followed by the two required post-clobber canonical-home reads; no extra a0 reload or stale register reuse"
        );
        let first_call = loads[0].0
            + 1
            + code[loads[0].0 + 1..]
                .iter()
                .position(|word| *word == add)
                .unwrap();
        let mut inputs = vec![
            encode_addi(10, split_register as u8, 0).unwrap(),
            encode_addi(11, split_register as u8, 0).unwrap(),
        ];
        let fresh_zeros = [
            encode_addi(12, 0, 0).unwrap(),
            encode_addi(13, 0, 0).unwrap(),
            encode_addi(14, 0, 0).unwrap(),
        ];
        if original_zeros {
            inputs.extend(fresh_zeros);
        }
        assert_eq!(
            &code[loads[0].0 + 1..first_call],
            inputs,
            "both exact original operands reach the first checked consumer; production omits only the independently proven redundant zero setup"
        );
        for (reload, _) in &loads[1..] {
            let reload = *reload;
            let call = reload
                + 1
                + code[reload + 1..]
                    .iter()
                    .position(|word| *word == add)
                    .unwrap();
            assert_eq!(
                &code[reload + 1..call],
                if original_zeros {
                    fresh_zeros.as_slice()
                } else {
                    &[]
                },
                "original a0 in r11 reaches its exact checked consumer without substitution or clobber"
            );
        }
    }
}
