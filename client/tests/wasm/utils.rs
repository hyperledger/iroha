#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use iroha_core::smartcontracts::wasm;

/// Return string containing exported memory, dummy allocator, and
/// host function imports which you can embed into your wasm module.
///
/// Memory is initialized with the given hex encoded string value
// It's expected that hex value is of even length
#[allow(clippy::integer_division)]
pub fn wasm_template(hex_val: &str) -> String {
    format!(
        r#"
        ;; Import host function to execute instruction
        (import "iroha" "{execute_instruction}"
            (func $exec_isi (param i32 i32)))

        ;; Import host function to execute query
        (import "iroha" "{execute_query}"
            (func $exec_query (param i32 i32) (result i32)))

        ;; Embed ISI into WASM binary memory
        (memory (export "{memory_name}") 1)
        (data (i32.const 0) "{hex_val}")

        ;; Variable which tracks total allocated size
        (global $mem_size (mut i32) i32.const {hex_len})

        ;; Export mock allocator to host. This allocator never frees!
        (func (export "{alloc_fn_name}") (param $size i32) (result i32)
            global.get $mem_size

            (global.set $mem_size
                (i32.add (global.get $mem_size) (local.get $size)))
        )
        "#,
        memory_name = wasm::export::WASM_MEMORY_NAME,
        alloc_fn_name = wasm::export::WASM_ALLOC_FN,
        execute_instruction = wasm::import::EXECUTE_ISI_FN_NAME,
        execute_query = wasm::import::EXECUTE_QUERY_FN_NAME,
        hex_val = escape_hex(hex_val),
        hex_len = hex_val.len() / 2,
    )
}

fn escape_hex(hex_val: &str) -> String {
    let mut isi_hex = String::with_capacity(3 * hex_val.len());

    for (i, c) in hex_val.chars().enumerate() {
        if i % 2 == 0 {
            isi_hex.push('\\');
        }

        isi_hex.push(c);
    }

    isi_hex
}
