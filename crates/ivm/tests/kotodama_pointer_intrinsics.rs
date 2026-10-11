//! Kotodama pointer-ABI intrinsic compilation coverage.
use kotodama_lang::compiler::Compiler;
#[test]
fn raw_axt_pointer_constructors_are_rejected() {
    let src = r#"
        seiyaku RemovedPointerIntrinsics {
            view fn main() authorize(anyone) {
                let desc_bytes = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
                let _desc = axt_descriptor(desc_bytes);
            }
        }
    "#;
    let error = Compiler::new()
        .compile_source(src)
        .expect_err("raw AXT pointer constructors are not part of the V1 source language");
    assert!(
        error.contains("axt_descriptor")
            || error.contains("raw pointer")
            || error.contains("unknown"),
        "unexpected error: {error}"
    );
}
#[test]
fn kotodama_zk_verify_accepts_typed_bytes_parameter() {
    let src = r#"
        seiyaku ZkVerifyIntrinsic { permission VerifyProof;
            kotoage fn verify(bytes env) authorize(VerifyProof) {
                crypto::zk::verify_batch(request: env);
            }
        }
    "#;
    Compiler::new()
        .compile_source(src)
        .expect("compile zk_verify_batch intrinsic");
}
