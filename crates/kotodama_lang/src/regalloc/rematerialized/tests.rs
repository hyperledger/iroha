//! Use-position and pressure controls for numeric literal home omission.

use super::*;
use crate::{
    ast::{BinaryOp, SourceLocation},
    ir::{BasicBlock, DecimalToIntOp, Label, NumericRoundOp},
    regalloc::{allocate, allocate_with_splitting},
};

fn function(instructions: Vec<Instr>, terminator: Terminator) -> Function {
    Function {
        name: "literal_home_fixture".into(),
        params: Vec::new(),
        blocks: vec![BasicBlock {
            label: Label(0),
            instrs: instructions,
            terminator,
        }],
        entry: Label(0),
        location: SourceLocation { line: 1, column: 1 },
    }
}
fn literal(kind: DataRefKind) -> Instr {
    Instr::DataRef {
        dest: Temp(0),
        kind,
        value: "7".into(),
    }
}

#[test]
fn numeric_literal_homes_are_omitted_only_at_audited_rematerialized_uses() {
    let t = Temp(0);
    let other = Temp(1);
    let dest = Temp(2);
    for kind in [
        DataRefKind::Int,
        DataRefKind::Decimal,
        DataRefKind::Quantity,
    ] {
        let numeric = match kind {
            DataRefKind::Int => WideNumericKind::Int,
            DataRefKind::Decimal => WideNumericKind::Decimal,
            DataRefKind::Quantity => WideNumericKind::Quantity,
            _ => unreachable!(),
        };
        let controls = [
            Instr::Copy { dest, src: t },
            Instr::Call {
                dest: Some(dest),
                callee: "sink".into(),
                args: vec![t, t],
            },
            Instr::CallMulti {
                dests: vec![dest],
                callee: "sink".into(),
                args: vec![t],
            },
            Instr::StateValueEncode {
                dest,
                schema: other,
                words: vec![t, t],
            },
            Instr::NumericNeg {
                dest,
                value: t,
                kind: numeric,
            },
            Instr::NumericCompare {
                dest,
                op: BinaryOp::Eq,
                left: t,
                right: t,
                kind: numeric,
            },
            Instr::NumericBinary {
                dest,
                op: BinaryOp::Add,
                left: t,
                right: t,
                left_kind: numeric,
                right_kind: numeric,
                result_kind: numeric,
            },
            Instr::NumericConvert {
                dest,
                value: t,
                source: numeric,
                destination: WideNumericKind::Decimal,
            },
            Instr::NumericTryConvert {
                dest,
                value: t,
                source: numeric,
                destination: WideNumericKind::Quantity,
            },
            Instr::NumericRound {
                dest,
                dividend: t,
                multiplier: Some(t),
                divisor: t,
                scale: t,
                mode: other,
                op: NumericRoundOp::DecimalMulDiv,
                result_kind: numeric,
            },
            Instr::NumericRound {
                dest,
                dividend: t,
                multiplier: None,
                divisor: t,
                scale: t,
                mode: other,
                op: NumericRoundOp::DecimalDiv,
                result_kind: numeric,
            },
        ];
        for instruction in controls {
            let f = function(
                vec![literal(kind), instruction],
                Terminator::Return(Some(t)),
            );
            assert_eq!(numeric_literal_homes(&f), HashSet::from([t]), "{f:?}");
            let allocation = allocate_with_splitting(&f);
            assert!(!allocation.regs.contains_key(&t) && !allocation.stack.contains_key(&t));
            assert_eq!(allocation.register_for_use(t, 1), None);
            assert!(allocation.reloads_at(1).is_empty());
        }
        for terminator in [
            Terminator::Return(Some(t)),
            Terminator::Return2(t, t),
            Terminator::ReturnN(vec![t, t]),
        ] {
            assert_eq!(
                numeric_literal_homes(&function(vec![literal(kind)], terminator)),
                HashSet::from([t])
            );
        }
    }
    for instruction in [
        Instr::IntToI64 { dest, value: t },
        Instr::IntToU64 { dest, value: t },
        Instr::WrappingBinary {
            dest,
            op: BinaryOp::Add,
            left: t,
            right: t,
        },
        Instr::WrappingNeg { dest, operand: t },
    ] {
        assert_eq!(
            numeric_literal_homes(&function(
                vec![literal(DataRefKind::Int), instruction],
                Terminator::Return(None)
            )),
            HashSet::from([t])
        );
    }
    assert_eq!(
        numeric_literal_homes(&function(
            vec![
                literal(DataRefKind::Decimal),
                Instr::DecimalToInt {
                    dest,
                    value: t,
                    mode: Some(other),
                    op: DecimalToIntOp::Round
                }
            ],
            Terminator::Return(None)
        )),
        HashSet::from([t])
    );
}

#[test]
fn literal_homes_remain_for_scalar_aliases_virtual_tuples_and_unrecognized_uses() {
    let t = Temp(0);
    let dest = Temp(2);
    for instruction in [
        Instr::Binary {
            dest,
            op: BinaryOp::Add,
            left: t,
            right: t,
        },
        Instr::TuplePack {
            dest,
            items: vec![t],
        },
        Instr::SetExecutionDepth { value: t },
        Instr::Store64 {
            address: t,
            value: t,
        },
        Instr::NumericRound {
            dest,
            dividend: t,
            multiplier: None,
            divisor: t,
            scale: t,
            mode: t,
            op: NumericRoundOp::DecimalDiv,
            result_kind: WideNumericKind::Decimal,
        },
        Instr::NumericRound {
            dest,
            dividend: t,
            multiplier: Some(t),
            divisor: t,
            scale: t,
            mode: t,
            op: NumericRoundOp::DecimalMulDiv,
            result_kind: WideNumericKind::Decimal,
        },
        Instr::DecimalToInt {
            dest,
            value: t,
            mode: Some(t),
            op: DecimalToIntOp::Round,
        },
        Instr::NumericBinary {
            dest,
            op: BinaryOp::Add,
            left: t,
            right: t,
            left_kind: WideNumericKind::Decimal,
            right_kind: WideNumericKind::Int,
            result_kind: WideNumericKind::Decimal,
        },
    ] {
        let f = function(
            vec![
                literal(DataRefKind::Decimal),
                Instr::Copy {
                    dest: Temp(3),
                    src: t,
                },
                instruction,
            ],
            Terminator::Return(Some(t)),
        );
        assert!(numeric_literal_homes(&f).is_empty(), "{f:?}");
        let allocation = allocate(&f);
        assert!(allocation.regs.contains_key(&t) || allocation.stack.contains_key(&t));
    }
    let branch = function(
        vec![literal(DataRefKind::Int)],
        Terminator::Branch {
            cond: t,
            then_bb: Label(0),
            else_bb: Label(0),
        },
    );
    assert!(numeric_literal_homes(&branch).is_empty());
    for kind in [
        DataRefKind::Name,
        DataRefKind::Blob,
        DataRefKind::NoritoBytes,
    ] {
        assert!(
            numeric_literal_homes(&function(vec![literal(kind)], Terminator::Return(Some(t))))
                .is_empty()
        );
    }
}

#[test]
fn redefined_numeric_literals_keep_homes_across_control_flow_and_multiple_definitions() {
    for replacement in [
        literal(DataRefKind::Int),
        Instr::Const {
            dest: Temp(0),
            value: 9,
        },
        Instr::Copy {
            dest: Temp(0),
            src: Temp(1),
        },
    ] {
        let mut f = function(vec![literal(DataRefKind::Int)], Terminator::Jump(Label(1)));
        f.blocks.push(BasicBlock {
            label: Label(1),
            instrs: vec![replacement],
            terminator: Terminator::Return(Some(Temp(0))),
        });
        assert!(numeric_literal_homes(&f).is_empty(), "{f:?}");
        let allocation = allocate_with_splitting(&f);
        assert!(allocation.regs.contains_key(&Temp(0)) || allocation.stack.contains_key(&Temp(0)));
    }
}

#[test]
fn omitted_literal_homes_reduce_real_spills_and_frame_storage_without_deleting_ir() {
    let mut instructions = Vec::new();
    let mut args = Vec::new();
    for index in 0..24 {
        let temp = Temp(index);
        instructions.push(Instr::DataRef {
            dest: temp,
            kind: DataRefKind::Int,
            value: index.to_string(),
        });
        args.push(temp);
    }
    for index in 24..48 {
        let temp = Temp(index);
        instructions.push(Instr::LoadVar {
            dest: temp,
            name: format!("argument{index}"),
        });
        args.push(temp);
    }
    instructions.push(Instr::Call {
        dest: None,
        callee: "consume".into(),
        args,
    });
    let f = function(instructions, Terminator::Return(None));
    let baseline = with_literal_homes(|| allocate_with_splitting(&f));
    let optimized = allocate_with_splitting(&f);
    assert!(optimized.stack.len() < baseline.stack.len());
    assert!(optimized.frame_size < baseline.frame_size);
    for index in 0..24 {
        assert!(
            !optimized.regs.contains_key(&Temp(index))
                && !optimized.stack.contains_key(&Temp(index))
        );
    }
    for index in 24..48 {
        assert!(
            optimized.regs.contains_key(&Temp(index)) || optimized.stack.contains_key(&Temp(index))
        );
    }
    assert_eq!(
        f.blocks[0]
            .instrs
            .iter()
            .filter(|instruction| matches!(instruction, Instr::DataRef { .. }))
            .count(),
        24
    );
    assert_eq!(
        with_literal_homes(|| allocate_with_splitting(&f)),
        baseline,
        "the test baseline scope must restore its thread-local state"
    );
}

#[test]
fn test_only_literal_home_baseline_restores_on_unwind() {
    let f = function(
        vec![literal(DataRefKind::Int)],
        Terminator::Return(Some(Temp(0))),
    );
    let original = numeric_literal_homes(&f);
    let result = std::panic::catch_unwind(|| {
        with_literal_homes(|| {
            assert!(numeric_literal_homes(&f).is_empty());
            panic!("baseline diagnostic unwind");
        })
    });
    assert!(result.is_err());
    assert_eq!(numeric_literal_homes(&f), original);
}
