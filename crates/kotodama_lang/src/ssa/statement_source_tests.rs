//! Source annotations survive SSA without changing executable operations or phi transport.

use super::*;
use crate::{
    ast::SourceLocation,
    ir::{BasicBlock, Instr, Terminator},
    source::{SourceId, SourceRange, TextRange},
};

fn site(start: u32) -> SourceRange {
    SourceRange::new(SourceId(7), TextRange::new(start, start + 5))
}
fn diamond(annotated: bool) -> ir::Program {
    let block = |label, operation, terminator| BasicBlock {
        label: Label(label),
        instrs: annotated
            .then(|| Instr::Source(Some(site(label as u32 * 10))))
            .into_iter()
            .chain(operation)
            .collect(),
        terminator,
    };
    ir::Program {
        functions: vec![ir::Function {
            name: "branch".into(),
            params: vec!["condition".into(), "left".into(), "right".into()],
            entry: Label(0),
            location: SourceLocation { line: 1, column: 1 },
            blocks: vec![
                block(
                    0,
                    Some(Instr::LoadVar {
                        dest: Temp(0),
                        name: "condition".into(),
                    }),
                    Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                ),
                block(
                    1,
                    Some(Instr::LoadVar {
                        dest: Temp(1),
                        name: "left".into(),
                    }),
                    Terminator::Jump(Label(3)),
                ),
                block(
                    2,
                    Some(Instr::LoadVar {
                        dest: Temp(1),
                        name: "right".into(),
                    }),
                    Terminator::Jump(Label(3)),
                ),
                block(3, None, Terminator::Return(Some(Temp(1)))),
            ],
        }],
    }
}
fn without_sources(mut program: ir::Program) -> ir::Program {
    for function in &mut program.functions {
        for block in &mut function.blocks {
            block
                .instrs
                .retain(|instruction| !matches!(instruction, Instr::Source(_)));
        }
    }
    program
}

#[test]
fn generated_phi_copies_do_not_inherit_the_preceding_statement() {
    let output = Program::from_ir(diamond(true)).unwrap().into_ir().unwrap();
    let function = &output.functions[0];
    for label in [Label(1), Label(2)] {
        let block = function
            .blocks
            .iter()
            .find(|block| block.label == label)
            .unwrap();
        let mut active = None;
        let mut copies = 0;
        for instruction in &block.instrs {
            match instruction {
                Instr::Source(source) => active = *source,
                Instr::Copy { .. } => {
                    copies += 1;
                    assert_eq!(active, None, "phi edge transport is generated");
                }
                Instr::LoadVar { .. } => assert_eq!(active, Some(site(label.0 as u32 * 10))),
                _ => {}
            }
        }
        assert!(copies > 0, "exercise actual phi destruction");
        assert_eq!(
            active,
            Some(site(label.0 as u32 * 10)),
            "terminator retains its own source"
        );
    }
    let plain = Program::from_ir(diamond(false)).unwrap().into_ir().unwrap();
    assert_eq!(without_sources(output), plain);
}

#[test]
fn source_annotations_do_not_change_optimizer_decisions() {
    let optimize = |input| {
        let mut program = Program::from_ir(input).unwrap();
        program
            .optimize_and_retain(&BTreeSet::from(["branch".into()]), &BTreeMap::new())
            .unwrap();
        without_sources(program.into_ir().unwrap())
    };
    assert_eq!(optimize(diamond(true)), optimize(diamond(false)));
}
