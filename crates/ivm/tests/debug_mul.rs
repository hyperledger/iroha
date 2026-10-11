//! Regression coverage for scalar multiplication in compiled Kotodama.
mod common;
#[test]
fn debug_mul() {
    let src = r#"
        seiyaku Multiply {
            view fn main() authorize(anyone) -> int {
                let t = 1;
                return t * 2;
            }
        }
    "#;
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(src)
        .expect("compile");
    let mut vm = ivm::IVM::new(u64::MAX);
    vm.load_program(&code).unwrap();
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("run");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 2);
}
