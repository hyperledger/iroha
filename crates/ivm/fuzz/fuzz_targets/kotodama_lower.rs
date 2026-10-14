//! Fuzzing for bounded Kotodama parsing, analysis, and IR lowering.

#![no_main]
use kotodama_lang::{ir, parser, semantic};
use libfuzzer_sys::fuzz_target;
const MAX_SRC_LEN: usize = 2048;
fuzz_target!(|data: &[u8]| {
    let len = data.len().min(MAX_SRC_LEN);
    if len == 0 {
        return;
    }
    if let Ok(src) = std::str::from_utf8(&data[..len])
        && let Ok(program) = parser::parse(src)
        && let Ok(typed) = semantic::analyze(&program)
    {
        let _ = ir::lower(&typed);
    }
});
