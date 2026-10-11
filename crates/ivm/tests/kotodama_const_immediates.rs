//! Kotodama integer constant lowering regression tests.
use iroha_primitives::bigint::BigInt;
use ivm::{CoreHost, IVM};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
#[test]
fn compile_large_positive_constant_executes() {
    let src = r#"
        seiyaku LargePositiveConstant {
            view fn main() authorize(anyone) -> int {
                let int x = 123_456_789_012;
                return x;
            }
        }
    "#;
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile large positive constant");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code)
        .expect("load large positive constant program");
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("run large positive constant program");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 123_456_789_012);
}
#[test]
fn compile_large_negative_constant_executes() {
    let src = r#"
        seiyaku LargeNegativeConstant {
            view fn main() authorize(anyone) -> int {
                let int x = -987_654_321_098;
                return x;
            }
        }
    "#;
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile large negative constant");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code)
        .expect("load large negative constant program");
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("run large negative constant program");
    assert_eq!(common::decode_i64_return_word(&vm, 0), -987_654_321_098);
}
#[test]
fn signed_512_bit_boundary_constants_are_canonical_and_deterministic() {
    let source = r#"
        seiyaku IndexedConstants {
            view fn minimum() authorize(anyone) -> int {
                return -6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048;
            }
            view fn maximum() authorize(anyone) -> int {
                return 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047;
            }
            view fn maximum_again() authorize(anyone) -> int {
                return 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047;
            }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let artifact = compiler
        .compile_source(source)
        .expect("compile signed boundaries");
    assert_eq!(
        artifact,
        compiler
            .compile_source(source)
            .expect("repeat signed-boundary compilation")
    );
    for (entrypoint, expected) in [
        (
            "minimum",
            "-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048",
        ),
        (
            "maximum",
            "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047",
        ),
        (
            "maximum_again",
            "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047",
        ),
    ] {
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&artifact).expect("load boundary artifact");
        common::select_kotodama_entrypoint(&mut vm, &artifact, entrypoint);
        vm.run().expect("run boundary entrypoint");
        assert_eq!(
            common::decode_int_return_word(&vm, 0),
            expected.parse::<BigInt>().expect("parse expected boundary")
        );
    }
}
