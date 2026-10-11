//! Diagnostic source mapping, lint policy and documentation shared by commands and the editor.
use kotodama_lang::{
    diagnostic::{Diagnostic, SourceSpan},
    driver::ProjectSourceKey,
};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};
fn display_path(path: &Path) -> String {
    let relative = std::env::current_dir().ok().and_then(|cwd| {
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        let absolute = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        absolute.strip_prefix(&cwd).ok().map(Path::to_path_buf)
    });
    relative
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or_else(|| path.to_path_buf())
        .display()
        .to_string()
}
/// Resolve logical names using an unambiguous caller-owned source map.
pub fn remap_project_diagnostic_sources<S: std::hash::BuildHasher>(
    diagnostic: &mut Diagnostic,
    logical_to_uri: &HashMap<String, String, S>,
) {
    let remap = |span: &mut SourceSpan| {
        if let Some(uri) = span
            .source
            .as_ref()
            .and_then(|source| logical_to_uri.get(source))
        {
            span.source = Some(uri.clone());
        }
    };
    if let Some(span) = &mut diagnostic.primary_span {
        remap(span);
    }
    for label in &mut diagnostic.labels {
        remap(&mut label.span);
    }
    for fix in diagnostic
        .fix
        .iter_mut()
        .chain(&mut diagnostic.alternative_fixes)
    {
        remap(&mut fix.span);
    }
}
/// Resolve logical names and package identities to their physical source files.
pub fn remap_locked_project_diagnostic_sources(
    diagnostic: &mut Diagnostic,
    source_paths: &BTreeMap<ProjectSourceKey, PathBuf>,
) {
    let remap = |span: &mut SourceSpan| {
        let Some(source_name) = span.source.as_ref() else {
            return;
        };
        let key = ProjectSourceKey {
            package_identity: span.package_identity.clone(),
            source_name: source_name.clone(),
        };
        if let Some(path) = source_paths.get(&key) {
            span.source = Some(display_path(path));
        }
    };
    if let Some(span) = &mut diagnostic.primary_span {
        remap(span);
    }
    for label in &mut diagnostic.labels {
        remap(&mut label.span);
    }
    for fix in diagnostic
        .fix
        .iter_mut()
        .chain(&mut diagnostic.alternative_fixes)
    {
        remap(&mut fix.span);
    }
}
/// Name root-local sources of a diagnostic (logical paths below `root`) by their
/// working-directory-relative paths, as semantic diagnostics of the same files are named.
pub fn remap_rooted_diagnostic_sources(diagnostic: &mut Diagnostic, root: &Path) {
    let remap = |span: &mut SourceSpan| {
        if span.package_identity.is_some() {
            return;
        }
        let Some(source_name) = span.source.as_deref() else {
            return;
        };
        let path = root.join(source_name);
        if path.is_file() {
            span.source = Some(display_path(&path));
        }
    };
    if let Some(span) = &mut diagnostic.primary_span {
        remap(span);
    }
    for label in &mut diagnostic.labels {
        remap(&mut label.span);
    }
    for fix in diagnostic
        .fix
        .iter_mut()
        .chain(&mut diagnostic.alternative_fixes)
    {
        remap(&mut fix.span);
    }
}

use kotodama_lang::diagnostic::DiagnosticPhase;
/// Published location of the Kotodama V1 language specification.
pub const SPEC_URL: &str =
    "https://github.com/hyperledger-iroha/iroha/blob/main/specs/kotodama_grammar.md";

/// Specification section (a `##` heading of `specs/kotodama_grammar.md`) that owns a code.
pub fn spec_section(code: &str) -> &'static str {
    let has = |prefixes: &[&str]| prefixes.iter().any(|prefix| code.starts_with(prefix));
    if has(&["E_TEST_"]) {
        "Local test mode"
    } else if has(&["E_SECRET_", "E_ZK_"]) {
        "Secrets and ZK seiyaku"
    } else if has(&["E_STATE_", "E_MAP_", "K2005", "K5001", "K5002", "K5008"]) {
        "Durable state"
    } else if has(&["E_LIST_", "E_ITERATION_LIMIT", "E_CONST_CAPACITY"]) {
        "Bounded lists"
    } else if has(&["E_JSON_", "E_LEGACY_JSON"]) {
        "Native JSON values"
    } else if has(&["E_QUERY_"]) {
        "Typed core ledger queries"
    } else if has(&[
        "E_DECIMAL_MANTISSA",
        "E_DECIMAL_SCALE",
        "E_DIVISION_BY_ZERO",
        "E_EXACT_DIVISION",
        "E_IMPLICIT_NUMERIC",
        "E_INEXACT_CONVERSION",
        "E_INT_OVERFLOW",
        "E_INVALID_SCALE",
        "E_NEGATIVE_",
        "E_NON_CANONICAL_NUMERIC",
        "E_NUMERIC_",
        "E_QUANTITY_",
        "E_REPEATING_DECIMAL",
        "E_INTERNAL_NUMERIC",
    ]) {
        "Arithmetic"
    } else if has(&[
        "E_MATCH_",
        "E_PATTERN_",
        "E_IF_",
        "E_BRANCH_",
        "E_BREAK_",
        "E_CONTINUE_",
        "E_UNBOUNDED_",
        "E_FOR_",
        "E_DIVERGING_",
        "E_TAIL_TYPE",
        "E_MISSING_RETURN",
        "E_RETURN_TYPE",
        "K5004",
    ]) {
        "Control flow and expressions"
    } else if has(&[
        "E_ERROR_",
        "E_UNKNOWN_ERROR_VARIANT",
        "E_RESULT_MUST_USE",
        "E_PROPAGATE_",
        "E_CONFLICTING_ERROR",
    ]) {
        "Errors and requirements"
    } else if has(&[
        "E_LOCAL_SHADOWING",
        "E_IMMUTABLE_ASSIGNMENT",
        "E_INVALID_ASSIGNMENT",
        "E_TYPE_ANNOTATION",
        "K2001",
    ]) {
        "Bindings and assignment"
    } else if has(&[
        "E_RETIRED_",
        "E_LEGACY_",
        "E_FORBIDDEN_SOURCE",
        "E_DECIMAL_MALFORMED",
        "E_DECIMAL_EXPONENT",
        "E_INT_LITERAL",
        "K0100",
    ]) {
        "Lexical grammar"
    } else if has(&[
        "K0001",
        "K0002",
        "K0003",
        "K0004",
        "K1004",
        "K2007",
        "K2008",
        "E_PACKAGE_BUDGET",
    ]) {
        "Resource limits"
    } else if has(&[
        "E_PROJECT_",
        "E_PACKAGE_",
        "E_DUPLICATE_PACKAGE",
        "E_UNKNOWN_PACKAGE",
        "E_EMPTY_PACKAGE",
        "K4003",
        "K5",
    ]) {
        "Tooling and build configuration"
    } else if has(&[
        "E_CONTRACT_",
        "E_NON_CANONICAL_BUILTIN",
        "E_INTERNAL_BUILTIN",
        "E_INTRINSIC_",
        "E_QUORUM_",
        "K5009",
    ]) {
        "Namespaced host API"
    } else if has(&["K4"]) {
        "Seiyaku artifact"
    } else if has(&[
        "E_NAMED_",
        "E_POSITIONAL_",
        "E_MISSING_NAMED",
        "E_UNKNOWN_NAMED",
        "E_DUPLICATE_NAMED",
        "E_LIFECYCLE_",
        "E_TRIGGER_",
        "E_RESERVED_DECLARATION",
        "E_DUPLICATE_DECLARATION",
        "K2004",
        "K2006",
    ]) {
        "Declarations"
    } else if has(&[
        "E_SUM_",
        "E_STRUCT_",
        "E_UNKNOWN_STRUCT",
        "E_MISSING_STRUCT",
        "E_TUPLE_",
    ]) {
        "Types"
    } else {
        match kotodama_lang::diagnostic::diagnostic_explanation(code).map(|entry| entry.phase) {
            Some(DiagnosticPhase::Lex) => "Lexical grammar",
            Some(DiagnosticPhase::Parse | DiagnosticPhase::Resolve) => "Source units",
            Some(DiagnosticPhase::Lowering) => "Resource limits",
            Some(DiagnosticPhase::Artifact) => "Seiyaku artifact",
            Some(DiagnosticPhase::Semantic) | None => "Types",
        }
    }
}

/// GitHub heading anchor for a specification section title.
pub fn heading_anchor(title: &str) -> String {
    title
        .chars()
        .filter_map(|character| match character {
            ' ' => Some('-'),
            '-' | '_' => Some(character),
            character if character.is_alphanumeric() => Some(character.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// Documentation link attached to editor diagnostics: the specification section that owns `code`.
pub fn documentation_url(code: &str) -> String {
    format!("{SPEC_URL}#{}", heading_anchor(spec_section(code)))
}

/// Apply the effective lint level to one finding: `None` when it is allowed, otherwise the
/// finding with its severity (`deny` reports an error that fails the check).
pub fn leveled_lint(
    config: &kotodama_lang::session::LintConfig,
    warning: kotodama_lang::lint::LintWarning,
) -> Option<kotodama_lang::lint::LintWarning> {
    match config.level(warning.code) {
        kotodama_lang::lint::LintLevel::Allow => None,
        level => Some(warning.with_level(level)),
    }
}
