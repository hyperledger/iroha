//! Generate or check ABI/gas hash goldens and runtime samples. Usage:
//!   cargo run -p ivm --features dev-tools --bin gen_abi_hash_doc -- --write
//!   cargo run -p ivm --features dev-tools --bin gen_abi_hash_doc -- --check
//!   cargo run -p ivm --features dev-tools --bin gen_abi_hash_doc -- --write --root /tmp/ivm-doc-stage
use std::path::{Path, PathBuf};
mod support;
use support::{
    GeneratedOutput, GenerationOptions, parse_generation_options, sync_generated_outputs,
};
const BEGIN: &str = "<!-- BEGIN GENERATED ABI HASHES -->";
const END: &str = "<!-- END GENERATED ABI HASHES -->";
const RUNTIME_HASH_PREFIX: &str = "\"abi_hash_hex\":";
const ABI_V1_GOLDEN_PREFIX: &str = "pub const ABI_V1_HASH_GOLDEN: &str =";
const GAS_SCHEDULE_GOLDEN_PREFIX: &str = "let expected = hex!(";
fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}
fn source_dir(root: &Path) -> PathBuf {
    root.join("specs")
}
fn abi_hash_golden_path(root: &Path) -> PathBuf {
    root.join("crates/iroha_data_model/tests/fixtures/abi_v1_hash.rs")
}
fn gas_schedule_golden_path(root: &Path) -> PathBuf {
    root.join("crates/ivm/tests/gas_schedule_hash.rs")
}
fn header_paths(root: &Path) -> Vec<PathBuf> {
    vec![source_dir(root).join("ivm_header.md")]
}
fn runtime_sample_paths(root: &Path) -> Vec<PathBuf> {
    vec![source_dir(root).join("samples/runtime_abi_hash.md")]
}
fn render_generated_hash_section(text: &str, expected: &str) -> Result<String, String> {
    let begin_matches = text.match_indices(BEGIN).collect::<Vec<_>>();
    if begin_matches.len() != 1 {
        return Err(format!(
            "expected exactly one ABI-hash begin marker `{BEGIN}`, found {}",
            begin_matches.len()
        ));
    }
    let end_matches = text.match_indices(END).collect::<Vec<_>>();
    if end_matches.len() != 1 {
        return Err(format!(
            "expected exactly one ABI-hash end marker `{END}`, found {}",
            end_matches.len()
        ));
    }
    let begin = begin_matches[0].0;
    let end_start = end_matches[0].0;
    if end_start <= begin {
        return Err(format!(
            "ABI-hash end marker `{END}` precedes begin marker `{BEGIN}`"
        ));
    }
    let end = end_start + END.len();
    let mut rendered = text.to_owned();
    rendered.replace_range(begin..end, expected);
    Ok(rendered)
}
fn options_or_exit() -> GenerationOptions {
    match parse_generation_options(std::env::args().skip(1), workspace_root()) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
fn prepare_outputs(
    header_paths: &[PathBuf],
    runtime_sample_paths: &[PathBuf],
    abi_hash_golden_path: &Path,
    gas_schedule_golden_path: &Path,
    expected_hash_section: &str,
    runtime_hash: &str,
    gas_hash: &str,
) -> Result<Vec<GeneratedOutput>, String> {
    let mut outputs = Vec::with_capacity(header_paths.len() + runtime_sample_paths.len() + 2);
    for path in header_paths {
        outputs.push(GeneratedOutput::render(path, |text| {
            render_generated_hash_section(text, expected_hash_section)
        })?);
    }
    for path in runtime_sample_paths {
        outputs.push(GeneratedOutput::render(path, |text| {
            render_runtime_sample(text, runtime_hash).map_err(str::to_owned)
        })?);
    }
    outputs.push(GeneratedOutput::render(abi_hash_golden_path, |text| {
        render_abi_hash_golden(text, runtime_hash).map_err(str::to_owned)
    })?);
    outputs.push(GeneratedOutput::render(gas_schedule_golden_path, |text| {
        render_gas_schedule_golden(text, gas_hash).map_err(str::to_owned)
    })?);
    Ok(outputs)
}
fn main() {
    let options = options_or_exit();
    let table = ivm::syscalls::render_abi_hashes_markdown_table();
    let expected = format!("{BEGIN}\n{table}{END}");
    let header_paths = header_paths(&options.root);
    let runtime_hash = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    assert_eq!(
        runtime_hash[runtime_hash.len() - 1] & 1,
        1,
        "refusing to publish an invalid ABI-surface diagnostic sentinel"
    );
    let runtime_hash = hex::encode(runtime_hash);
    let runtime_sample_paths = runtime_sample_paths(&options.root);
    let gas_hash = hex::encode(ivm::gas::schedule_hash().as_ref());
    let outputs = prepare_outputs(
        &header_paths,
        &runtime_sample_paths,
        &abi_hash_golden_path(&options.root),
        &gas_schedule_golden_path(&options.root),
        &expected,
        &runtime_hash,
        &gas_hash,
    )
    .unwrap_or_else(|error| panic!("render ABI/gas hash outputs: {error}"));
    let regenerate_command =
        "cargo run --locked -p ivm --features dev-tools --bin gen_abi_hash_doc -- --write";
    let updated = sync_generated_outputs(&outputs, options.mode, regenerate_command)
        .unwrap_or_else(|error| panic!("{error}"));
    for path in updated {
        eprintln!("updated: {}", path.display());
    }
}
fn render_runtime_sample(text: &str, hash: &str) -> Result<String, &'static str> {
    render_single_hash(text, RUNTIME_HASH_PREFIX, hash)
}
fn render_abi_hash_golden(text: &str, hash: &str) -> Result<String, &'static str> {
    render_single_hash(text, ABI_V1_GOLDEN_PREFIX, hash)
}
fn render_gas_schedule_golden(text: &str, hash: &str) -> Result<String, &'static str> {
    render_single_hash(text, GAS_SCHEDULE_GOLDEN_PREFIX, hash)
}
fn render_single_hash(text: &str, prefix: &str, hash: &str) -> Result<String, &'static str> {
    let Some(prefix_start) = text.find(prefix) else {
        return Err("ABI hash field not found");
    };
    if text[prefix_start + prefix.len()..].contains(prefix) {
        return Err("multiple ABI hash fields found");
    }
    let tail = text[prefix_start + prefix.len()..].trim_start();
    if !tail.starts_with('"') {
        return Err("ABI hash field is not a quoted string");
    }
    let value_start = text.len() - tail.len() + 1;
    let Some(relative_end) = text[value_start..].find('"') else {
        return Err("unterminated ABI hash field");
    };
    let value_end = value_start + relative_end;
    let current = &text[value_start..value_end];
    if current.len() != 64 || !current.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("ABI hash is not 32-byte hexadecimal");
    }
    let mut rendered = text.to_owned();
    rendered.replace_range(value_start..value_end, hash);
    Ok(rendered)
}
#[cfg(test)]
mod tests {
    use super::{
        BEGIN, END, abi_hash_golden_path, prepare_outputs, render_abi_hash_golden,
        render_gas_schedule_golden, render_generated_hash_section, render_runtime_sample,
    };
    use std::{
        fs,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    #[test]
    fn generated_hash_section_requires_exact_ordered_markers() {
        let expected = format!("{BEGIN}\ncanonical\n{END}");
        let stale = format!("prefix\n{BEGIN}\nstale\n{END}\nsuffix\n");
        assert_eq!(
            render_generated_hash_section(&stale, &expected)
                .expect("replace exact generated section"),
            format!("prefix\n{expected}\nsuffix\n")
        );
        assert!(render_generated_hash_section("no markers", &expected).is_err());
        assert!(
            render_generated_hash_section(
                &format!("{BEGIN}\none\n{END}\n{BEGIN}\ntwo\n{END}"),
                &expected
            )
            .is_err()
        );
        assert!(render_generated_hash_section(&format!("{END}\n{BEGIN}"), &expected).is_err());
    }
    #[test]
    fn runtime_sample_replaces_exactly_one_canonical_hash() {
        let old = "{\n  \"abi_hash_hex\": \"1111111111111111111111111111111111111111111111111111111111111111\"\n}\n";
        let new = "2222222222222222222222222222222222222222222222222222222222222222";
        let rendered = render_runtime_sample(old, new).expect("valid runtime sample");
        assert_eq!(rendered, format!("{{\n  \"abi_hash_hex\": \"{new}\"\n}}\n"));
        assert!(render_runtime_sample("{}", new).is_err());
        assert!(render_runtime_sample(&format!("{old}{old}"), new).is_err());
    }
    #[test]
    fn abi_v1_golden_replaces_exactly_one_canonical_hash() {
        assert_eq!(
            abi_hash_golden_path(Path::new("workspace")),
            Path::new("workspace/crates/iroha_data_model/tests/fixtures/abi_v1_hash.rs")
        );
        let old = "pub const ABI_V1_HASH_GOLDEN: &str =\n    \"1111111111111111111111111111111111111111111111111111111111111111\";\n";
        let new = "2222222222222222222222222222222222222222222222222222222222222222";
        let rendered = render_abi_hash_golden(old, new).expect("valid ABI v1 golden");
        assert_eq!(
            rendered,
            format!("pub const ABI_V1_HASH_GOLDEN: &str =\n    \"{new}\";\n")
        );
        assert!(render_abi_hash_golden("const OTHER: &str = \"00\";\n", new).is_err());
        assert!(render_abi_hash_golden(&format!("{old}{old}"), new).is_err());
        assert!(
            render_abi_hash_golden("pub const ABI_V1_HASH_GOLDEN: &str = HASH;\n", new).is_err()
        );
    }
    #[test]
    fn gas_schedule_golden_replaces_exactly_one_canonical_hash() {
        let old = "let expected = hex!(\"1111111111111111111111111111111111111111111111111111111111111111\");\n";
        let new = "2222222222222222222222222222222222222222222222222222222222222222";
        let rendered = render_gas_schedule_golden(old, new).expect("valid gas hash golden");
        assert_eq!(rendered, format!("let expected = hex!(\"{new}\");\n"));
        assert!(render_gas_schedule_golden("let other = hex!(\"00\");\n", new).is_err());
        assert!(render_gas_schedule_golden(&format!("{old}{old}"), new).is_err());
    }
    #[test]
    fn late_golden_failure_does_not_publish_earlier_outputs() {
        let unique = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ivm-abi-hash-late-failure-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create test directory");
        let header = root.join("header.md");
        let runtime = root.join("runtime.json");
        let abi_golden = root.join("abi.rs");
        let gas_golden = root.join("gas.rs");
        let old_hash = "1".repeat(64);
        let new_hash = "2".repeat(64);
        fs::write(&header, format!("{BEGIN}\nstale\n{END}\n")).expect("write header fixture");
        fs::write(
            &runtime,
            format!("{{\n  \"abi_hash_hex\": \"{old_hash}\"\n}}\n"),
        )
        .expect("write runtime fixture");
        fs::write(
            &abi_golden,
            format!("pub const ABI_V1_HASH_GOLDEN: &str =\n    \"{old_hash}\";\n"),
        )
        .expect("write ABI golden fixture");
        fs::write(&gas_golden, "missing gas hash field\n").expect("write malformed late golden");
        let header_before = fs::read(&header).expect("snapshot header fixture");
        let expected = format!("{BEGIN}\ncurrent\n{END}");
        assert!(
            prepare_outputs(
                &[header.clone()],
                &[runtime],
                &abi_golden,
                &gas_golden,
                &expected,
                &new_hash,
                &new_hash,
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&header).expect("read header after late failure"),
            header_before
        );
        fs::remove_dir_all(root).expect("remove test directory");
    }
}
