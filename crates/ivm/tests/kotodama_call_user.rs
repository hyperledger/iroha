//! Tests for user-defined function calls in Kotodama.
use ivm::IVM;
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn user_defined_call_returns_42() {
    // Repeated parameter types make the call named-only in V1.
    let src = r#"
        seiyaku UserCalls {
            fn add(int a, int b) -> int { return a + b; }
            view fn main() authorize(anyone) -> int { let z = add(a: 20, b: 22); return z; }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let program = compiler.compile_source(src).expect("compile kotodama");
    let mut vm = IVM::new(10_000);
    vm.load_program(&program).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &program, "main");
    vm.run().expect("run VM");
    // Source `int` values return through typed pointer-ABI registers.
    assert_eq!(common::decode_i64_return_word(&vm, 0), 42);
}
