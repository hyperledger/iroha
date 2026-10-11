//! IR lowering tests for tuple returns and CallMulti/TuplePack/TupleGet.
use kotodama_lang::{ir, parser::parse, semantic::analyze};
#[test]
fn lower_call_tuple_return_emits_callmulti_and_tuplepack() {
    let src = r#"
        seiyaku TupleCalls {
            fn g(int a, int b) -> (int, int) { return (a, b); }
            fn f(int a, int b) -> (int, int) {
                // Return the tuple produced by g(a,b). Repeated parameter
                // types make the call named-only in Kotodama V1.
                return g(a: a, b: b);
            }
            view fn main() authorize(anyone) -> (int, int) {
                return f(a: 1, b: 2);
            }
        }
    "#;
    let prog = parse(src).expect("parse");
    let typed = analyze(&prog).expect("analyze");
    let irp = ir::lower(&typed).expect("lower");
    // Find f
    let f = irp
        .functions
        .iter()
        .find(|x| x.name == "f")
        .expect("f present");
    let mut saw_callmulti = false;
    let mut saw_tuplepack = false;
    for bb in &f.blocks {
        for ins in &bb.instrs {
            match ins {
                ir::Instr::CallMulti { .. } => saw_callmulti = true,
                ir::Instr::TuplePack { .. } => saw_tuplepack = true,
                _ => {}
            }
        }
    }
    assert!(saw_callmulti && saw_tuplepack);
}
#[test]
fn lower_return_tuple_emits_returnn() {
    let src = r#"
        seiyaku TupleReturns {
            fn h(int a, int b, int c) -> (int, int, int) {
                let t = (a, b);
                // Return three elements via tuple composition
                return (t.0, t.1, c);
            }
            view fn main() authorize(anyone) -> (int, int, int) {
                return h(a: 1, b: 2, c: 3);
            }
        }
    "#;
    let prog = parse(src).expect("parse");
    let typed = analyze(&prog).expect("analyze");
    let irp = ir::lower(&typed).expect("lower");
    let h = irp
        .functions
        .iter()
        .find(|x| x.name == "h")
        .expect("h present");
    assert!(
        matches!(
            h.blocks.last().unwrap().terminator,
            ir::Terminator::ReturnN(_)
        ) || h
            .blocks
            .iter()
            .any(|b| matches!(b.terminator, ir::Terminator::ReturnN(_)))
    );
}
