//! End-to-end coverage for nominal Kotodama `quantity` lowering and execution.
use iroha_primitives::{numeric::Quantity, numeric_abi::QuantityValueV1};
use ivm::{IVM, PointerType, ProgramMetadata};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
fn execute_rounded(mode: &str) -> Quantity {
    let source = format!(
        r#"
        seiyaku RoundedQuantity {{
            fn rounded(quantity value, decimal divisor, int scale) -> quantity {{
                return value.div_round(
                    divisor: divisor,
                    scale: scale,
                    mode: Rounding::{mode},
                );
            }}

            view fn main() authorize(anyone) -> quantity {{
                return rounded(value: 1, divisor: 8.0, scale: 2);
            }}
        }}
        "#,
    );
    let program = KotodamaCompiler::new()
        .compile_source(&source)
        .expect("compile rounded quantity program");
    let metadata = ProgramMetadata::parse(&program).expect("parse rounded quantity metadata");
    let entrypoint = metadata
        .contract_interface
        .as_ref()
        .expect("rounded quantity contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "main")
        .expect("main entrypoint");
    let entrypoint_pc =
        u64::try_from(metadata.prefix_len()).expect("prefix fits u64") + entrypoint.entry_pc;
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program)
        .expect("load rounded quantity program");
    vm.set_program_counter(entrypoint_pc)
        .expect("select main entrypoint");
    vm.run().expect("execute rounded quantity program");
    let tlv = vm
        .validate_tlv(
            vm.public_call_result_word(0)
                .expect("completed return word"),
        )
        .expect("returned quantity pointer");
    assert_eq!(tlv.type_id, PointerType::Quantity);
    QuantityValueV1::decode_frame(tlv.payload)
        .expect("decode returned canonical quantity")
        .into_quantity()
}
#[test]
fn rounded_quantity_modes_execute_through_the_extended_syscall() {
    for (mode, expected) in [
        ("toward_zero", "0.12"),
        ("away_from_zero", "0.13"),
        ("floor", "0.12"),
        ("ceil", "0.13"),
        ("nearest_even", "0.12"),
        ("nearest_away", "0.13"),
        ("nearest_toward_zero", "0.12"),
    ] {
        let value = execute_rounded(mode);
        assert_eq!(value.to_string(), expected, "Rounding::{mode}");
    }
}
