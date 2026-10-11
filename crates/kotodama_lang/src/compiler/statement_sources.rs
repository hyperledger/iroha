//! Source-only statement provenance, detached before physical code generation.

use super::*;
use crate::source::{SourceId, SourceRange};

/// Exact source site for one emitted instruction interval.
pub(super) struct Seed {
    pub function_name: String,
    pub source: SourceRange,
    pub start: usize,
    pub end: usize,
}

/// Per-operation locations retained through SSA without influencing allocation or emission.
pub(super) struct Sources {
    operations: BTreeMap<String, BTreeMap<(ir::Label, usize), SourceRange>>,
    declarations: BTreeMap<SourceId, BTreeMap<u32, (u32, String)>>,
}

impl Sources {
    pub fn take(program: &mut ir::Program, typed: &TypedProgram) -> Self {
        let mut operations = BTreeMap::<String, BTreeMap<(ir::Label, usize), SourceRange>>::new();
        for function in &mut program.functions {
            let function_operations = operations.entry(function.name.clone()).or_default();
            for block in &mut function.blocks {
                let mut source = None;
                let mut position = 0;
                block.instrs.retain(|instruction| {
                    if let Instr::Source(next) = instruction {
                        source = *next;
                        return false;
                    }
                    if let Some(source) = source {
                        function_operations.insert((block.label, position), source);
                    }
                    position += 1;
                    true
                });
                if let Some(source) = source {
                    function_operations.insert((block.label, position), source);
                }
            }
        }
        let mut declarations = BTreeMap::<SourceId, BTreeMap<u32, (u32, String)>>::new();
        for item in &typed.items {
            let TypedItem::Function(function) = item;
            if let Some(source) = function.source {
                declarations.entry(source.source).or_default().insert(
                    source.range.start,
                    (source.range.end, function.name.clone()),
                );
            }
        }
        Self {
            operations,
            declarations,
        }
    }

    pub fn record(
        &self,
        seeds: &mut Vec<Seed>,
        function: &str,
        block: ir::Label,
        position: usize,
        start: usize,
        end: usize,
    ) {
        if start == end {
            return;
        }
        let Some(&source) = self
            .operations
            .get(function)
            .and_then(|operations| operations.get(&(block, position)))
        else {
            return;
        };
        let function_name = self
            .declarations
            .get(&source.source)
            .and_then(|functions| functions.range(..=source.range.start).next_back())
            .filter(|(_, (end, _))| source.range.end <= *end)
            .map_or(function, |(_, (_, name))| name);
        if let Some(previous) = seeds.last_mut()
            && previous.source == source
            && previous.function_name == function_name
            && previous.end == start
        {
            previous.end = end;
        } else {
            seeds.push(Seed {
                function_name: function_name.to_owned(),
                source,
                start,
                end,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_locations_survive_inlining_and_do_not_change_artifact_bytes() {
        let source = r#"seiyaku StatementLocations {
    fn plus(int value) -> int {
        let shifted = value + 1;
        return shifted;
    }
    view fn inspect(int value) authorize(anyone) -> int {
        let first = plus(value: value);
        return first * 2;
    }
}"#;
        let compiler = Compiler::new();
        let (artifact, _, report) = compiler
            .compile_source_with_manifest_and_report(source)
            .unwrap();
        let shifted_source = source.replace("        let shifted", "\n\n        let shifted");
        let (shifted_artifact, _, shifted_report) = compiler
            .compile_source_with_manifest_and_report(&shifted_source)
            .unwrap();
        assert_eq!(
            artifact, shifted_artifact,
            "debug locations cannot influence executable bytes"
        );
        assert!(!report.statement_map.is_empty());
        let helper = report
            .statement_map
            .iter()
            .find(|entry| entry.function_name == "plus" && entry.source.line == 3)
            .expect("inlined helper operations retain their original statement");
        let moved = shifted_report
            .statement_map
            .iter()
            .find(|entry| entry.pc_start == helper.pc_start)
            .unwrap();
        assert_eq!(moved.source.line, 5);
        assert!(
            report
                .statement_map
                .iter()
                .any(|entry| entry.function_name == "inspect" && entry.source.line == 8)
        );
        let entries = report.symbolized_source_map();
        assert!(
            entries
                .windows(2)
                .all(|pair| pair[0].pc_end == pair[1].pc_start)
        );
        assert_eq!(
            entries.first().unwrap().pc_start,
            report.source_map.first().unwrap().pc_start
        );
        assert_eq!(
            entries.last().unwrap().pc_end,
            report.source_map.last().unwrap().pc_end
        );
        for entry in entries {
            assert!(entry.pc_start < entry.pc_end);
        }
        let sidecar = json::parse_value(&report.render_source_map_json().unwrap()).unwrap();
        let encoded = sidecar
            .get("entries")
            .and_then(json::Value::as_array)
            .unwrap();
        assert!(encoded.iter().any(
            |entry| entry.get("function_name").and_then(json::Value::as_str) == Some("plus")
                && entry.get("line").and_then(json::Value::as_u64) == Some(3)
        ));
    }
}

/// Partition every emitted function into statement intervals and generated-code gaps.
pub(super) fn complete_map(
    functions: &[EmbeddedSourceMapEntryV1],
    statements: &[EmbeddedSourceMapEntryV1],
) -> Vec<EmbeddedSourceMapEntryV1> {
    let mut entries = Vec::new();
    let mut statements = statements.iter().peekable();
    for function in functions {
        let mut cursor = function.pc_start;
        while let Some(statement) = statements.peek()
            && statement.pc_start < function.pc_end
        {
            let statement = statements.next().expect("peeked statement");
            debug_assert!(cursor <= statement.pc_start && statement.pc_end <= function.pc_end);
            if cursor < statement.pc_start {
                let mut generated = function.clone();
                generated.pc_start = cursor;
                generated.pc_end = statement.pc_start;
                entries.push(generated);
            }
            entries.push(statement.clone());
            cursor = statement.pc_end;
        }
        if cursor < function.pc_end {
            let mut generated = function.clone();
            generated.pc_start = cursor;
            entries.push(generated);
        }
    }
    entries
}
