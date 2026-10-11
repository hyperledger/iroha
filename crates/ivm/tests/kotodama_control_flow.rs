//! Kotodama control-flow codegen coverage for `break`/`continue`.
use ivm::{CoreHost, IVM};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn break_exits_bounded_for_loop() {
    let src = r#"
        seiyaku BreakLoop {
            view fn main() authorize(anyone) -> int {
                var last = 0;
                for i in range(10) {
                    last = i;
                    if i == 3 {
                        break;
                    }
                }
                return last;
            }
        }
    "#;
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile bounded for/break program");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("execute break program");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 3);
}
#[test]
fn continue_skips_range_iteration() {
    let src = r#"
        seiyaku ContinueLoop {
            view fn main() authorize(anyone) -> int {
                var sum = 0;
                for i in range(5) {
                    if i == 2 {
                        continue;
                    }
                    sum = sum + i;
                }
                return sum;
            }
        }
    "#;
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile continue program");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("execute continue program");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 8);
}
