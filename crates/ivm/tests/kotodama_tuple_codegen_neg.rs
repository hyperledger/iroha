//! Call-table return bounds, including products beyond the retired register allocation limit.
#[test]
fn compile_function_returning_fourteen_values_succeeds() {
    use kotodama_lang::compiler::Compiler;
    // Every product word is returned through the same table convention.
    let src = r#"
        seiyaku TooManyReturns {
            view fn h() authorize(anyone) -> (int,int,int,int,int,int,int,int,int,int,int,int,int,int) {
                return (1,2,3,4,5,6,7,8,9,10,11,12,13,14);
            }
        }
    "#;
    Compiler::new()
        .compile_source(src)
        .expect("14-word result fits the V1 table");
}
#[test]
fn callmulti_rejects_one_word_beyond_the_table_bound() {
    // Hit the CallMulti codegen guard via test helper without compiling a callee.
    let err = kotodama_lang::compiler::test_helpers::try_emit_callmulti_guard_only(
        ivm_abi::call::MAX_CALL_WORDS_V1 + 1,
    )
    .expect_err("expected CallMulti guard error");
    assert!(
        err.contains("too many return values in call"),
        "unexpected error message: {err}"
    );
}
#[test]
fn compile_function_returning_thirteen_values_succeeds() {
    use kotodama_lang::compiler::Compiler;
    let src = r#"
        seiyaku MaximumReturns {
            view fn h(int a,int b,int c,int d,int e,int f,int g,int eighth,int i,int j,int k,int l,int m) authorize(anyone) -> (int,int,int,int,int,int,int,int,int,int,int,int,int) {
                return (a,b,c,d,e,f,g,eighth,i,j,k,l,m);
            }
        }
    "#;
    Compiler::new()
        .compile_source(src)
        .expect("expected 13-value return to compile");
}
#[test]
fn callmulti_accepts_the_inclusive_table_word_bound() {
    kotodama_lang::compiler::test_helpers::try_emit_callmulti_guard_only(
        ivm_abi::call::MAX_CALL_WORDS_V1,
    )
    .expect("exact table word bound must pass guard");
}
