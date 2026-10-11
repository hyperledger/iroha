//! Durable `StateMap` lowering tests, including struct-valued entries.
use iroha_primitives::{
    bigint::BigInt,
    numeric::{Numeric, Quantity},
};
use ivm::{CoreHost, IVM};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
mod common;
fn execute_int_result(source: &str) -> i64 {
    let program = KotodamaCompiler::new()
        .compile_source(source)
        .expect("compile StateMap contract");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&program).expect("load StateMap contract");
    common::select_kotodama_entrypoint(&mut vm, &program, "main");
    if let Err(error) = vm.run() {
        panic!(
            "execute StateMap contract at pc={} with r10={:#x}, r11={:#x}: {error:?}",
            vm.pc(),
            vm.register(10),
            vm.register(11),
        );
    }
    common::decode_i64_return_word(&vm, 0)
}
fn encoded_order_inversion(quantity: bool) -> (String, String) {
    let mut values = Vec::new();
    for scale in 0..=6 {
        for mantissa in [
            -257_i128, -256, -129, -128, -127, -19, -11, -3, -2, -1, 0, 1, 2, 3, 9, 11, 19, 99,
            127, 128, 129, 255, 256, 257, 1001,
        ] {
            if quantity && mantissa < 0 {
                continue;
            }
            let numeric = Numeric::new(BigInt::from_i128(mantissa), scale);
            let (spelling, envelope) = if quantity {
                let value = Quantity::try_from_numeric(numeric.clone())
                    .expect("non-negative generated quantity");
                (
                    value.to_string(),
                    ivm_abi::numeric_tlv::encode_quantity(&value).expect("encode quantity key"),
                )
            } else {
                (
                    numeric.to_string(),
                    ivm_abi::numeric_tlv::encode_decimal(&numeric).expect("encode decimal key"),
                )
            };
            values.push((numeric, spelling, envelope));
        }
    }
    values.sort_by(|left, right| left.0.cmp(&right.0));
    values.dedup_by(|left, right| left.0 == right.0);
    values
        .windows(2)
        .find_map(|pair| (pair[0].2 > pair[1].2).then(|| (pair[0].1.clone(), pair[1].1.clone())))
        .expect("fixture domain must contain an encoded-order/numeric-order inversion")
}
#[test]
fn state_map_set_get_roundtrip() {
    // Declare state map and perform set/get within a single run.
    let src = r#"
        seiyaku C { permission WriteState;
            state StateMap<int, int> M;
            kotoage fn main() authorize(WriteState) -> int {
                M[1] = 7;
                let x = M.get(1).unwrap_or(0);
                return x;
            }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let prog = compiler.compile_source(src).expect("compile state map");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&prog).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run().expect("state map roundtrip");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 7);
}
#[test]
fn state_map_with_struct_value_roundtrip() {
    // Store and load a struct through a durable state map.
    let src = r#"
        seiyaku C { permission WriteState;
            struct S { int value }
            state StateMap<int, S> values;
            kotoage fn main() authorize(WriteState) -> int {
                values[3] = S { value: 9 };
                let y = values.get(3).unwrap_or(S { value: 0 }).value;
                return y;
            }
        }
    "#;
    let compiler = KotodamaCompiler::new();
    let prog = compiler
        .compile_source(src)
        .expect("compile state map with struct value");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&prog).expect("load program");
    common::select_kotodama_entrypoint(&mut vm, &prog, "main");
    vm.run().expect("state map struct roundtrip");
    assert_eq!(common::decode_i64_return_word(&vm, 0), 9);
}
#[test]
fn decimal_and_quantity_keys_collapse_equivalent_literal_spellings() {
    for numeric_type in ["decimal", "quantity"] {
        let source = format!(
            r#"
            seiyaku CanonicalKeys {{ permission WriteState;
                state StateMap<{numeric_type}, int> Values;
                kotoage fn main() authorize(WriteState) -> int {{
                    Values[7.0] = 11;
                    Values[7.00] = 22;
                    var int count = 0;
                    var int total = 0;
                    for (key, value) in Values.take(4) {{
                        count += 1;
                        total += value;
                    }}
                    let int lookup = Values.get(7.000).unwrap_or(0);
                    return count * 1000 + total * 10 + lookup;
                }}
            }}
            "#,
        );
        assert_eq!(
            execute_int_result(&source),
            1242,
            "{numeric_type} spellings of the same mathematical value must address one canonical key"
        );
    }
}
#[test]
fn decimal_and_quantity_iteration_follow_encoded_key_bytes_not_numeric_magnitude() {
    for (numeric_type, quantity) in [("decimal", false), ("quantity", true)] {
        let (numerically_lower, numerically_higher) = encoded_order_inversion(quantity);
        let source = format!(
            r#"
            seiyaku EncodedOrder {{ permission WriteState;
                state StateMap<{numeric_type}, int> Values;
                kotoage fn main() authorize(WriteState) -> int {{
                    Values[{numerically_lower}] = 11;
                    Values[{numerically_higher}] = 22;
                    var int first = 0;
                    for (key, value) in Values.take(2) {{
                        if first == 0 {{ first = value; }}
                    }}
                    return first;
                }}
            }}
            "#,
        );
        assert_eq!(
            execute_int_result(&source),
            22,
            "{numeric_type} iteration must follow canonical encoded-byte order, whose selected pair is the reverse of numeric magnitude"
        );
    }
}
