//! Exact imported statement provenance remains separate from the executable artifact.

use kotodama_lang::{
    driver::BuildDriver,
    linker::{SourceLinkRequest, SourceModuleUnit},
    session::{CompileOutput, CompilerSession},
};

const ROOT: &str = r#"seiyaku Provenance {
    import "./math.ko" as math;
    view fn select(bool condition, int left, int right) authorize(anyone) -> int {
        let selected = math::choose(condition: condition, left: left, right: right);
        return selected * 3;
    }
}"#;
const HELPER: &str = r#"module Math {
    export fn choose(bool condition, int left, int right) -> int {
        if condition {
            return left + 1;
        }
        return right + 2;
    }
}"#;

fn compile(helper: &str) -> CompileOutput {
    BuildDriver::new(CompilerSession::default(), "statement-provenance-test")
        .compile_project(
            SourceLinkRequest {
                root: SourceModuleUnit {
                    source_name: "contracts/root.ko".into(),
                    source: ROOT.into(),
                },
                sources: vec![SourceModuleUnit {
                    source_name: "contracts/math.ko".into(),
                    source: helper.into(),
                }],
                artifacts: vec![],
                imports: vec![],
                packages: vec![],
            },
            "contracts/root.ko",
        )
        .expect("compile imported helper with branches")
}

#[test]
fn imported_branch_returns_keep_their_own_source_file_and_exact_lines() {
    let output = compile(HELPER);
    let report = &output.report;
    for (path, line, text) in [
        ("contracts/math.ko", 3, "if condition"),
        ("contracts/math.ko", 4, "return left + 1;"),
        ("contracts/math.ko", 6, "return right + 2;"),
        ("contracts/root.ko", 5, "return selected * 3;"),
    ] {
        let entries = report
            .statement_map
            .iter()
            .filter(|entry| {
                entry.source.source_path.as_deref() == Some(path) && entry.source.line == line
            })
            .collect::<Vec<_>>();
        assert!(
            !entries.is_empty(),
            "missing `{text}` at {path}:{line}: {:#?}",
            report.statement_map
        );
        let expected = if path.ends_with("math.ko") {
            HELPER
        } else {
            ROOT
        };
        assert!(
            expected
                .lines()
                .nth(line as usize - 1)
                .unwrap()
                .trim()
                .starts_with(text)
        );
        assert!(entries.iter().all(|entry| entry.pc_start < entry.pc_end));
    }
    let map = report.symbolized_source_map();
    for function in &report.source_map {
        let intervals = map
            .iter()
            .filter(|entry| entry.pc_start >= function.pc_start && entry.pc_end <= function.pc_end)
            .collect::<Vec<_>>();
        assert_eq!(intervals.first().unwrap().pc_start, function.pc_start);
        assert_eq!(intervals.last().unwrap().pc_end, function.pc_end);
        assert!(
            intervals
                .windows(2)
                .all(|pair| pair[0].pc_end == pair[1].pc_start)
        );
    }
    let shifted =
        compile(&HELPER.replace("            return left", "\n\n            return left"));
    assert_eq!(
        output.artifact, shifted.artifact,
        "source-only changes must preserve exact emitted bytes"
    );
    let original = report
        .statement_map
        .iter()
        .find(|entry| {
            entry.source.source_path.as_deref() == Some("contracts/math.ko")
                && entry.source.line == 4
        })
        .unwrap();
    let moved = shifted
        .report
        .statement_map
        .iter()
        .find(|entry| entry.pc_start == original.pc_start)
        .unwrap();
    assert_eq!(moved.source.line, 6);
    assert_eq!(moved.source.source_path, original.source.source_path);
    assert_eq!(moved.function_name, original.function_name);
}
