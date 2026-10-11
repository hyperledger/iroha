//! Regressions for durable `StateMap<Name, int>` runtime behavior.
use iroha_crypto::PublicKey;
use iroha_data_model::prelude::AccountId;
use ivm::mock_wsv::{MockWorldStateView, WsvHost};
use ivm::{CoreHost, IVM};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
use std::str::FromStr;
mod common;
fn run_program(src: &str) -> IVM {
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile kotodama");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("run program");
    vm
}
fn test_subject() -> AccountId {
    AccountId::new(
        PublicKey::from_str(
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03",
        )
        .expect("valid public key"),
    )
}
fn encoded_int_state_path(name: &str, key: i64) -> String {
    let key = common::encode_int_state_value(key);
    format!("{name}/{}", hex::encode(key))
}
fn run_program_with_wsv(src: &str, wsv: MockWorldStateView) -> (IVM, MockWorldStateView) {
    let code = KotodamaCompiler::new()
        .compile_source(src)
        .expect("compile kotodama");
    let subject = test_subject();
    let host = WsvHost::new_with_subject(wsv, subject);
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(host);
    vm.load_program(&code).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &code, "main");
    vm.run().expect("run program");
    let wsv = {
        let host_any = vm.host_mut_any().expect("host available");
        let host = host_any.downcast_mut::<WsvHost>().expect("wsv host");
        host.wsv.clone()
    };
    (vm, wsv)
}
#[test]
fn durable_name_map_roundtrip_read_after_write() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/001.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn durable_name_map_read_modify_write_roundtrip() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/002.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 2);
}
#[test]
fn durable_name_map_if_branch_reassignment_roundtrip() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/003.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn durable_name_map_roundtrip_through_name_parameter() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/004.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn durable_name_map_roundtrip_through_helper() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/005.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn durable_name_map_struct_value_roundtrip_through_helper() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/006.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 42);
}
#[test]
fn missing_mixed_aggregate_option_uses_complete_helper_fallback() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/007.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
#[test]
fn present_mixed_aggregate_option_ignores_fallback_value_without_field_corruption() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/008.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
#[test]
fn mixed_aggregate_unwrap_or_remains_eager_on_the_present_arm() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/009.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (vm, wsv) = run_program_with_wsv(src, MockWorldStateView::new());
    assert_eq!(common::decode_i64_return_word(&vm, 0), 7);
    let fallback_calls = wsv
        .sc_get(&encoded_int_state_path("FallbackCalls", 1))
        .expect("eager fallback must persist its observable state mutation");
    assert_eq!(common::decode_int_state_value(&fallback_calls), 1);
}
#[test]
fn mixed_aggregate_unwrap_or_evaluates_fallback_once_on_the_absent_arm() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/010.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (vm, wsv) = run_program_with_wsv(src, MockWorldStateView::new());
    assert_eq!(common::decode_i64_return_word(&vm, 0), 11);
    let fallback_calls = wsv
        .sc_get(&encoded_int_state_path("FallbackCalls", 1))
        .expect("selected fallback must persist its observable state mutation");
    assert_eq!(common::decode_int_state_value(&fallback_calls), 1);
}
#[test]
fn missing_nested_mixed_aggregate_option_preserves_every_fallback_word() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/011.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
#[test]
fn aggregate_option_rejects_a_different_fallback_shape() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/012.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let error = KotodamaCompiler::new()
        .compile_source(src)
        .expect_err("unwrap_or must reject a fallback with a different aggregate shape");
    assert!(
        error.contains("unwrap_or")
            || error.contains("type mismatch")
            || error.contains("E_TYPE_ANNOTATION_MISMATCH"),
        "unexpected diagnostic: {error}"
    );
}
#[test]
fn durable_name_map_if_branch_roundtrip_through_name_parameter() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/013.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn durable_name_map_roundtrip_across_wsv_invocations() {
    let write_src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/014.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let read_src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/015.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (_, wsv) = run_program_with_wsv(write_src, MockWorldStateView::new());
    let (vm, _) = run_program_with_wsv(read_src, wsv);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn durable_aggregate_get_or_preserves_persisted_bounded_lists() {
    let write_src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/016.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let read_src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/017.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (_, wsv) = run_program_with_wsv(write_src, MockWorldStateView::new());
    let (vm, _) = run_program_with_wsv(read_src, wsv);
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
#[test]
fn durable_aggregate_ensure_preserves_existing_record_words() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/018.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
#[test]
fn durable_name_map_if_branch_roundtrip_across_wsv_invocations() {
    let write_src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/019.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let read_src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/020.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (_, wsv) = run_program_with_wsv(write_src, MockWorldStateView::new());
    let (vm, _) = run_program_with_wsv(read_src, wsv);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn durable_name_to_account_id_map_roundtrip() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/021.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
#[test]
fn durable_name_to_account_id_map_roundtrip_across_wsv_invocations() {
    let write_src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/022.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let read_src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/023.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let (_, wsv) = run_program_with_wsv(write_src, MockWorldStateView::new());
    let (vm, _) = run_program_with_wsv(read_src, wsv);
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
#[test]
fn durable_name_to_blob_map_write_from_json_hex_roundtrip() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/024.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(
        vm.public_call_result_word(0)
            .expect("completed return word"),
        1
    );
}
#[test]
fn durable_name_map_key_survives_function_call() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/025.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn durable_name_map_branch_value_drives_following_state_set() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/026.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 2);
}
#[test]
fn durable_name_map_branch_value_survives_following_addition() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/027.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 2);
}
#[test]
fn durable_name_map_branch_value_survives_path_work() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/028.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 1);
}
#[test]
fn durable_name_map_branch_value_survives_following_state_work() {
    let src = include_str!("../fixtures/koto_v1/kotodama_state_name_map_runtime/029.ko")
        .strip_suffix('\n')
        .expect("fixture sentinel newline");
    let vm = run_program(src);
    assert_eq!(common::decode_i64_return_word(&vm, 0), 2);
}
