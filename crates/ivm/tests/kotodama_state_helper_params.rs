//! Compile-fail coverage for removed first-class durable-state parameters.
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
fn assert_state_parameter_rejected(source: &str) {
    let error = KotodamaCompiler::new()
        .compile_source(source)
        .expect_err("V1 must reject first-class state handles");
    assert!(
        error.contains("error[K1001] parse:")
            && error.contains("state cannot be passed as a parameter")
            && error.contains("functions read and write declared `state` directly by name"),
        "unexpected diagnostic: {error}"
    );
}
#[test]
fn scalar_state_parameter_is_rejected() {
    assert_state_parameter_rejected(
        r#"
        module RemovedScalarStateParameter {
            fn read_counter(state int value) -> int { return value; }
        }
        "#,
    );
}
#[test]
fn state_map_parameter_is_rejected() {
    assert_state_parameter_rejected(
        r#"
        module RemovedMapStateParameter {
            fn read_value(state StateMap<int, int> values, int key) -> int {
                return values.get(key).unwrap_or(0);
            }
        }
        "#,
    );
}
