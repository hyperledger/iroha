//! Structured adaptation for failures emitted by typed semantic analysis.
//!
//! Name, declaration, type, and call diagnostics are produced by the resolved HIR pass with exact
//! `SourceId`/`TextRange` nodes. Typed analysis joins its AST nodes to the same immutable source
//! table and records exact structured ranges, labels, and fix recipes. Whole-program state
//! invariants use their parser-owned state/lifecycle declaration nodes. This adapter deliberately
//! does not scan diagnostic messages or source tokens to guess a spelling.
#[cfg(test)]
use crate::diagnostic::DiagnosticPhase;
use crate::{
    diagnostic::{
        Diagnostic, DiagnosticBundle, DiagnosticFix, DiagnosticLabel, SourceSpan,
        phase_for_semantic_failure,
    },
    resolved::ResolvedProgram,
    source::{SourceFile, SourceRange},
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SemanticDiagnosticLabel {
    pub(crate) source: SourceRange,
    pub(crate) message: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SemanticFix {
    PositionalStruct {
        name: String,
        fields: Vec<String>,
        arguments: Vec<SourceRange>,
    },
    ListGet {
        target: SourceRange,
        index: SourceRange,
    },
    ListSet {
        target: SourceRange,
        index: SourceRange,
        value: SourceRange,
    },
    Replace {
        replacement: String,
    },
    /// Rewrite one complete expression statement `expr;` as `let _ = expr;`.
    DiscardStatement,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SemanticDiagnostic {
    pub(crate) primary: SourceRange,
    pub(crate) labels: Vec<SemanticDiagnosticLabel>,
    pub(crate) fix: Option<SemanticFix>,
    /// Site-specific help that replaces the registry fallback for the code.
    pub(crate) help: Option<String>,
    /// Additional context rendered as notes.
    pub(crate) notes: Vec<String>,
}
impl SemanticDiagnostic {
    /// Structured metadata with a primary range and optional fix.
    pub(crate) fn at(primary: SourceRange, fix: Option<SemanticFix>) -> Self {
        Self {
            primary,
            labels: Vec::new(),
            fix,
            help: None,
            notes: Vec::new(),
        }
    }
    /// Add one secondary label.
    #[must_use]
    pub(crate) fn with_label(mut self, source: Option<SourceRange>, message: String) -> Self {
        if let Some(source) = source {
            self.labels
                .push(SemanticDiagnosticLabel { source, message });
        }
        self
    }
    /// Replace the registry help with site-specific guidance.
    #[must_use]
    pub(crate) fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
}
fn source_span(source: &SourceFile, range: SourceRange) -> Option<SourceSpan> {
    (source.id() == range.source).then(|| SourceSpan::from_range(source, range.range))
}
fn safe_slice(source: &SourceFile, range: SourceRange) -> Option<&str> {
    (source.id() == range.source)
        .then(|| source.slice(range.range))
        .flatten()
        .filter(|text| !text.contains("//") && !text.contains("/*"))
}
fn strict_child(primary: SourceRange, child: SourceRange) -> bool {
    primary.source == child.source
        && primary.range != child.range
        && !child.range.is_empty()
        && primary.range.contains(child.range)
}
fn materialize_fix(
    source: &SourceFile,
    primary: SourceRange,
    fix: SemanticFix,
) -> Option<DiagnosticFix> {
    let replacement = match fix {
        SemanticFix::PositionalStruct {
            name,
            fields,
            arguments,
        } => {
            if fields.len() != arguments.len()
                || safe_slice(source, primary).is_none()
                || arguments
                    .iter()
                    .any(|argument| !strict_child(primary, *argument))
                || arguments
                    .windows(2)
                    .any(|window| window[0].range.end > window[1].range.start)
            {
                return None;
            }
            let fields = fields
                .iter()
                .zip(arguments)
                .map(|(field, argument)| {
                    safe_slice(source, argument).map(|argument| format!("{field}: {argument}"))
                })
                .collect::<Option<Vec<_>>>()?;
            if fields.is_empty() {
                format!("{name} {{}}")
            } else {
                format!("{name} {{ {}, }}", fields.join(", "))
            }
        }
        SemanticFix::ListGet { target, index } => {
            if safe_slice(source, primary).is_none()
                || !strict_child(primary, target)
                || !strict_child(primary, index)
                || target.range.end > index.range.start
            {
                return None;
            }
            let target = safe_slice(source, target)?;
            let index = safe_slice(source, index)?;
            format!("{target}.get({index})")
        }
        SemanticFix::ListSet {
            target,
            index,
            value,
        } => {
            // Rewriting a complete simple assignment to checked `set` preserves
            // failure visibility. Compound writes and trivia-moving rewrites
            // do not receive an automatic replacement.
            if safe_slice(source, primary).is_none()
                || !strict_child(primary, target)
                || !strict_child(primary, index)
                || !strict_child(primary, value)
                || target.range.end > index.range.start
                || index.range.end > value.range.start
            {
                return None;
            }
            let target = safe_slice(source, target)?;
            let index = safe_slice(source, index)?;
            let value = safe_slice(source, value)?;
            format!("{target}.set(index: {index}, value: {value});")
        }
        SemanticFix::Replace { replacement } => {
            safe_slice(source, primary)?;
            replacement
        }
        SemanticFix::DiscardStatement => {
            let text = safe_slice(source, primary)?.trim_end();
            let expression = text.strip_suffix(';').unwrap_or(text).trim_end();
            if expression.is_empty() {
                return None;
            }
            format!("let _ = {expression};")
        }
    };
    Some(DiagnosticFix {
        span: source_span(source, primary)?,
        replacement,
    })
}
/// Convert failures from typed/effect analysis into canonical diagnostics.
///
/// Structured semantic metadata supplies the primary range, secondary labels, and any fix recipe. A
/// function location is used only as a conservative fallback for failures that predate structured
/// metadata. Known program-wide invariants use resolved declaration nodes; unknown invariants do
/// not invent a zero-width or spelling-based span when no owning node exists.
pub(crate) fn from_semantic_failures(
    failures: crate::semantic::SemanticFailures,
    _source_name: Option<&str>,
    source: Option<&SourceFile>,
    resolved: Option<&ResolvedProgram>,
) -> DiagnosticBundle {
    let owner_source = |range: SourceRange| {
        resolved
            .and_then(|program| {
                program
                    .source_files()
                    .find(|file| file.id() == range.source)
            })
            .or_else(|| source.filter(|file| file.id() == range.source))
    };
    DiagnosticBundle::new(
        failures
            .failures
            .into_iter()
            .map(|failure| {
                let code = failure.error.code;
                let message = failure.error.message;
                let semantic = failure.diagnostic;
                let primary_span = if code == "K0004" {
                    None
                } else {
                    semantic
                        .as_ref()
                        .and_then(|diagnostic| {
                            owner_source(diagnostic.primary)
                                .and_then(|source| source_span(source, diagnostic.primary))
                        })
                        .or_else(|| {
                            failure.location.and_then(|location| {
                                source.zip(resolved).and_then(|(source, resolved)| {
                                    resolved.span_for_location(
                                        source,
                                        location.line,
                                        location.column,
                                    )
                                })
                            })
                        })
                        .or_else(|| {
                            source.zip(resolved).and_then(|(_, resolved)| {
                                let range = match code {
                                    "E_STATE_HAJIMARI_REQUIRED" => {
                                        resolved.first_scalar_state_keyword_source()
                                    }
                                    "E_STATE_HAJIMARI_INCOMPLETE" => {
                                        resolved.hajimari_name_source()
                                    }
                                    _ => None,
                                }?;
                                owner_source(range).and_then(|source| source_span(source, range))
                            })
                        })
                };
                let mut diagnostic = Diagnostic::error(
                    code,
                    phase_for_semantic_failure(code),
                    message,
                    primary_span,
                );
                if let Some(semantic) = semantic {
                    diagnostic.labels = semantic
                        .labels
                        .into_iter()
                        .filter_map(|label| {
                            Some(DiagnosticLabel {
                                span: owner_source(label.source)
                                    .and_then(|source| source_span(source, label.source))?,
                                message: label.message,
                            })
                        })
                        .collect();
                    diagnostic.fix = semantic.fix.and_then(|fix| {
                        owner_source(semantic.primary)
                            .and_then(|source| materialize_fix(source, semantic.primary, fix))
                    });
                    if let Some(help) = semantic.help {
                        diagnostic.help = Some(help);
                    }
                    diagnostic.notes.extend(semantic.notes);
                }
                if let Some(resolved) = resolved {
                    for source in resolved.source_files() {
                        diagnostic.capture_source(source);
                    }
                } else if let Some(source) = source {
                    diagnostic.capture_source(source);
                }
                diagnostic
            })
            .collect(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        session::{CompileRequest, CompilerSession},
        source::{SourceId, TextRange},
    };
    fn range(source: SourceId, text: &str, needle: &str) -> SourceRange {
        let start = text.find(needle).expect("fixture substring");
        SourceRange::new(
            source,
            TextRange::new(
                u32::try_from(start).expect("fixture offset fits u32"),
                u32::try_from(start + needle.len()).expect("fixture end fits u32"),
            ),
        )
    }
    #[test]
    fn stable_error_code_is_independent_of_message_wording() {
        for message in [
            "unknown value `missing`",
            "valeur introuvable `missing`",
            "欠落している値 `missing`",
            "E_OTHER: text that resembles a different diagnostic",
        ] {
            let bundle = from_semantic_failures(
                crate::semantic::SemanticError {
                    code: "K2002",
                    message: message.to_owned(),
                }
                .into(),
                None,
                None,
                None,
            );
            assert_eq!(bundle.diagnostics[0].code, "K2002");
            assert_eq!(bundle.diagnostics[0].phase, DiagnosticPhase::Resolve);
            assert_eq!(bundle.diagnostics[0].message, message);
        }
    }
    #[test]
    fn independent_trigger_failures_retain_their_exact_name_spans() {
        let source = r#"seiyaku Timers {
  view fn inspect() authorize(anyone) {}
  trigger morning -> inspect { on time pre_commit; }
  trigger evening -> inspect { on time pre_commit; }
}"#;
        let diagnostics = CompilerSession::default()
            .check(CompileRequest {
                source,
                source_name: Some("timers.ko"),
            })
            .expect_err("view-targeting triggers must fail semantic analysis");
        let trigger_diagnostics = diagnostics
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "E_TRIGGER_VIEW_TARGET")
            .collect::<Vec<_>>();
        assert_eq!(trigger_diagnostics.len(), 2, "{diagnostics:?}");
        assert_eq!(
            trigger_diagnostics
                .iter()
                .map(|diagnostic| {
                    let range = diagnostic
                        .primary_span
                        .as_ref()
                        .and_then(|span| span.byte_range)
                        .expect("trigger diagnostic must carry an exact byte range");
                    &source[range.start as usize..range.end as usize]
                })
                .collect::<Vec<_>>(),
            ["morning", "evening"]
        );
    }
    #[test]
    fn phase_adapter_only_promotes_registry_owned_resolver_failures() {
        for code in [
            "K2002",
            "E_DUPLICATE_DECLARATION",
            "E_RESERVED_DECLARATION",
            "E_CONFLICTING_ERROR_TYPE",
            "E_INTERNAL_RESOLUTION",
        ] {
            assert_eq!(phase_for_semantic_failure(code), DiagnosticPhase::Resolve);
        }
        for code in ["K0004", "K2003", "E_BRANCH_TYPE_MISMATCH", "UNKNOWN"] {
            assert_eq!(phase_for_semantic_failure(code), DiagnosticPhase::Semantic);
        }
    }
    #[test]
    fn positional_struct_fix_uses_exact_argument_spellings() {
        let text = "Pair(1.250_0, nested(2))";
        let source_id = SourceId(7);
        let source = SourceFile::new(source_id, "pair.ko", text);
        let primary = range(source_id, text, text);
        let fix = materialize_fix(
            &source,
            primary,
            SemanticFix::PositionalStruct {
                name: "Pair".to_owned(),
                fields: vec!["left".to_owned(), "right".to_owned()],
                arguments: vec![
                    range(source_id, text, "1.250_0"),
                    range(source_id, text, "nested(2)"),
                ],
            },
        )
        .expect("safe positional fix");
        assert_eq!(fix.span.byte_range, Some(primary.range));
        assert_eq!(fix.replacement, "Pair { left: 1.250_0, right: nested(2), }");
    }
    #[test]
    fn semantic_fixes_fail_closed_for_comments_or_wrong_sources() {
        let source_id = SourceId(3);
        let text = "Pair(1, /* retain */ 2)";
        let source = SourceFile::new(source_id, "comments.ko", text);
        let primary = range(source_id, text, text);
        assert!(
            materialize_fix(
                &source,
                primary,
                SemanticFix::PositionalStruct {
                    name: "Pair".to_owned(),
                    fields: vec!["left".to_owned(), "right".to_owned()],
                    arguments: vec![range(source_id, text, "1"), range(source_id, text, "2"),],
                },
            )
            .is_none()
        );
        let wrong_source = SourceRange::new(SourceId(99), primary.range);
        assert!(
            materialize_fix(
                &source,
                wrong_source,
                SemanticFix::ListGet {
                    target: wrong_source,
                    index: wrong_source,
                },
            )
            .is_none()
        );
    }
    #[test]
    fn safe_list_read_fix_preserves_receiver_and_index_spelling() {
        let source_id = SourceId(11);
        let text = "values[(offset + 1)]";
        let source = SourceFile::new(source_id, "list.ko", text);
        let primary = range(source_id, text, text);
        let fix = materialize_fix(
            &source,
            primary,
            SemanticFix::ListGet {
                target: range(source_id, text, "values"),
                index: range(source_id, text, "(offset + 1)"),
            },
        )
        .expect("safe list read fix");
        assert_eq!(fix.replacement, "values.get((offset + 1))");
    }
    #[test]
    fn safe_list_write_fix_uses_the_complete_statement_range() {
        let source_id = SourceId(12);
        let text = "values[offset] = replacement;";
        let source = SourceFile::new(source_id, "list-write.ko", text);
        let primary = range(source_id, text, text);
        let fix = materialize_fix(
            &source,
            primary,
            SemanticFix::ListSet {
                target: range(source_id, text, "values"),
                index: range(source_id, text, "offset"),
                value: range(source_id, text, "replacement"),
            },
        )
        .expect("safe List.set fix");
        assert_eq!(fix.span.byte_range, Some(primary.range));
        assert_eq!(
            fix.replacement,
            "values.set(index: offset, value: replacement);"
        );
    }
    #[test]
    fn exact_type_replacement_does_not_rewrite_surrounding_source() {
        let source_id = SourceId(13);
        let text = "let bytes raw = query;";
        let source = SourceFile::new(source_id, "query.ko", text);
        let primary = range(source_id, text, "bytes");
        let fix = materialize_fix(
            &source,
            primary,
            SemanticFix::Replace {
                replacement: "Option<AccountView>".to_owned(),
            },
        )
        .expect("exact type replacement");
        assert_eq!(fix.span.byte_range, Some(primary.range));
        assert_eq!(fix.replacement, "Option<AccountView>");
    }

    fn check_errors(source: &str) -> Vec<crate::diagnostic::Diagnostic> {
        CompilerSession::default()
            .check(CompileRequest {
                source,
                source_name: Some("probe.ko"),
            })
            .expect_err("probe must fail")
            .diagnostics
    }
    fn primary_text<'a>(source: &'a str, diagnostic: &crate::diagnostic::Diagnostic) -> &'a str {
        let range = diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.byte_range)
            .expect("diagnostic must carry an exact range");
        &source[range.start as usize..range.end as usize]
    }
    fn label_texts<'a>(
        source: &'a str,
        diagnostic: &crate::diagnostic::Diagnostic,
    ) -> Vec<&'a str> {
        diagnostic
            .labels
            .iter()
            .map(|label| {
                let range = label.span.byte_range.expect("label range");
                &source[range.start as usize..range.end as usize]
            })
            .collect()
    }
    #[test]
    fn discard_statement_fix_wraps_only_complete_statements() {
        let source_id = SourceId(14);
        let text = "  record(value);";
        let source = SourceFile::new(source_id, "discard.ko", text);
        let primary = range(source_id, text, "record(value);");
        let fix = materialize_fix(&source, primary, SemanticFix::DiscardStatement)
            .expect("expression statement fix");
        assert_eq!(fix.replacement, "let _ = record(value);");
        let empty = range(source_id, text, ";");
        assert!(materialize_fix(&source, empty, SemanticFix::DiscardStatement).is_none());
    }
    #[test]
    fn every_view_violation_is_reported_at_the_offending_statement() {
        let source = r#"seiyaku Views {
    state int count;
    hajimari() {
        count = 0;
    }
    fn bump_inner() {
        count += 1;
    }
    view fn bump() authorize(anyone) -> int {
        count += 1;
        return count;
    }
    view fn peek() authorize(anyone) -> int {
        bump_inner();
        return count;
    }
}"#;
        let diagnostics = check_errors(source);
        let views = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "K2004")
            .collect::<Vec<_>>();
        assert_eq!(views.len(), 2, "{diagnostics:?}");
        assert_eq!(primary_text(source, views[0]), "count += 1;");
        assert_eq!(label_texts(source, views[0]), ["bump"]);
        assert_eq!(primary_text(source, views[1]), "bump_inner();");
        assert_eq!(label_texts(source, views[1]), ["peek", "count += 1;"]);
        let help = views[1].help.as_deref().expect("site help");
        assert!(help.contains("kotoage (言挙げ)"), "{help}");
    }
    #[test]
    fn view_violations_inside_destructuring_loops_point_at_the_write() {
        // The loop pattern lowers to binding statements prepended to the body;
        // provenance must stay aligned so the write, not the loop, is primary.
        let source = r#"seiyaku Loops {
    state int last;
    state StateMap<Name, int> scores;
    hajimari() {
        last = 0;
    }
    view fn scan() authorize(anyone) -> int {
        let items = scores.take(4);
        for (key, value) in items {
            last = value;
        }
        return 0;
    }
}"#;
        let diagnostics = check_errors(source);
        let view = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "K2004")
            .expect("view violation");
        assert_eq!(primary_text(source, view), "last = value;");
    }
    #[test]
    fn unknown_member_fields_list_the_declared_fields() {
        let source = r#"seiyaku Fields {
    struct Point { int x; int y; }
    view fn read() authorize(anyone) -> int {
        let point = Point { x: 1, y: 2 };
        return point.yy;
    }
}"#;
        let diagnostics = check_errors(source);
        let field = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.message.contains("unknown field 'yy'"))
            .expect("unknown field");
        assert_eq!(primary_text(source, field), "point.yy");
        assert_eq!(
            field.help.as_deref(),
            Some("struct `Fields::Point` declares `x`, `y`; read one of those fields.")
        );
    }
    #[test]
    fn direct_calls_to_public_functions_explain_the_private_helper_pattern() {
        let source = r#"seiyaku Calls {
    view fn quote(int x) authorize(anyone) -> int {
        return x;
    }
    view fn twice() authorize(anyone) -> int {
        return quote(1);
    }
}"#;
        let diagnostics = check_errors(source);
        let call = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.message.contains("cannot be called directly"))
            .expect("direct runtime call");
        assert_eq!(primary_text(source, call), "quote(1)");
        let help = call.help.as_deref().expect("site help");
        assert!(help.contains("private `fn`"), "{help}");
    }
    #[test]
    fn dropped_results_point_at_the_statement_or_binding() {
        let source = r#"seiyaku Results {
    error enum E { Bad = 1 }
    fn g(int x) -> Result<int, E> {
        if x > 0 { Result::ok(x) } else { Result::err(E::Bad) }
    }
    fn f(int x) -> int {
        g(x);
        x
    }
    fn h(int x) -> int {
        let r = g(x);
        x
    }
}"#;
        let diagnostics = check_errors(source);
        let must_use = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "E_RESULT_MUST_USE")
            .collect::<Vec<_>>();
        assert_eq!(must_use.len(), 2, "{diagnostics:?}");
        assert_eq!(primary_text(source, must_use[0]), "g(x);");
        assert_eq!(
            must_use[0].fix.as_ref().map(|fix| fix.replacement.as_str()),
            Some("let _ = g(x);")
        );
        assert_eq!(primary_text(source, must_use[1]), "let r = g(x);");
        assert!(must_use[1].fix.is_none());
    }
    #[test]
    fn independent_statement_errors_in_one_function_are_all_reported() {
        let source = r#"seiyaku Many {
    fn f() -> int {
        let int y = true;
        let bool z = 5;
        if z { return y; }
        return y;
    }
}"#;
        let diagnostics = check_errors(source);
        let primaries = diagnostics
            .iter()
            .map(|diagnostic| primary_text(source, diagnostic))
            .collect::<Vec<_>>();
        assert_eq!(
            primaries,
            ["let int y = true;", "let bool z = 5;"],
            "{diagnostics:?}"
        );
    }
    #[test]
    fn numeric_operator_errors_use_source_symbols_and_inferred_labels() {
        let source = r#"seiyaku Acc {
    state StateMap<AccountId, quantity> Balances;
    view fn total() authorize(anyone) -> quantity {
        var sum = 0;
        for (who, amount) in Balances.take(16) {
            sum += amount;
        }
        let _ = sum;
        return 2 * Balances.get(context::authority()).expect(E::Missing);
    }
    error enum E { Missing = 1 }
}"#;
        let diagnostics = check_errors(source);
        let compound = &diagnostics[0];
        assert_eq!(
            compound.message,
            "operator `+=` is not defined for `int` and `quantity`"
        );
        assert_eq!(primary_text(source, compound), "sum += amount;");
        assert_eq!(label_texts(source, compound), ["var sum = 0;"]);
        assert!(
            compound
                .help
                .as_deref()
                .is_some_and(|help| help.contains("quantity::try_from_int"))
        );
    }
    #[test]
    fn require_with_a_message_string_explains_error_enums() {
        let source = r#"seiyaku Req { permission CanDeposit;
    kotoage fn deposit(int amount) authorize(CanDeposit) {
        require(amount > 0, "amount must be positive");
    }
}"#;
        let diagnostics = check_errors(source);
        assert_eq!(diagnostics[0].code, "K2003");
        assert_eq!(
            primary_text(source, &diagnostics[0]),
            "\"amount must be positive\""
        );
        let help = diagnostics[0].help.as_deref().expect("require help");
        assert!(help.contains("error enum"), "{help}");
    }
    #[test]
    fn unknown_argument_labels_list_declared_parameters() {
        let source = r#"seiyaku Pay { permission CanPay;
    kotoage fn pay(AccountId to) authorize(CanPay) {
        ledger::asset::transfer(
            from: context::authority(),
            to: to,
            asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"),
            amount: 1,
            dataspace: DataSpaceId::parse("0"),
        );
    }
}"#;
        let diagnostics = check_errors(source);
        assert_eq!(diagnostics[0].code, "E_UNKNOWN_NAMED_ARGUMENT");
        assert_eq!(
            diagnostics[0].message,
            "call `ledger::asset::transfer` has no parameters named `from` or `to`"
        );
        let help = diagnostics[0].help.as_deref().expect("label help");
        assert!(help.contains("`from:` is spelled `source:`"), "{help}");
        assert!(help.contains("`to:` is spelled `destination:`"), "{help}");
    }
    #[test]
    fn invalid_identifier_literals_are_semantic_errors_on_the_literal() {
        let source = r#"seiyaku Ids {
    view fn space() authorize(anyone) -> DataSpaceId {
        return DataSpaceId::parse("zero");
    }
}"#;
        let diagnostics = check_errors(source);
        assert_eq!(diagnostics[0].code, "E_INVALID_ID_LITERAL");
        assert_eq!(primary_text(source, &diagnostics[0]), "\"zero\"");
        assert!(
            diagnostics[0]
                .help
                .as_deref()
                .is_some_and(|help| help.contains("decimal integers"))
        );
    }
    #[test]
    fn resolution_errors_do_not_hide_type_errors_in_other_functions() {
        let source = r#"seiyaku Mixed {
    fn a() -> bool {
        return 1;
    }
    fn b() -> int {
        return missing_name;
    }
    fn c() {
        let int x = true;
    }
}"#;
        let diagnostics = check_errors(source);
        let codes = diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            [
                "K2002",
                "E_RETURN_TYPE_MISMATCH",
                "E_TYPE_ANNOTATION_MISMATCH"
            ],
            "{diagnostics:?}"
        );
        assert_eq!(primary_text(source, &diagnostics[0]), "missing_name");
        assert_eq!(primary_text(source, &diagnostics[2]), "let int x = true;");
    }
    #[test]
    fn arity_and_argument_type_errors_name_the_parameters() {
        let source = r#"seiyaku Calls {
    fn add(int a, int b) -> int {
        return a + b;
    }
    view fn many() authorize(anyone) -> int {
        return add(1, 2, 3);
    }
    view fn wrong() authorize(anyone) -> int {
        return add(a: 1, b: true);
    }
}"#;
        let diagnostics = check_errors(source);
        assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
        let arity = diagnostics[0].help.as_deref().expect("arity help");
        assert!(arity.contains("`a`, `b`"), "{arity}");
        assert_eq!(diagnostics[1].code, "K2003");
        assert_eq!(
            diagnostics[1].message,
            "argument `b` of `add`: expected `int`, found `bool`"
        );
        assert_eq!(primary_text(source, &diagnostics[1]), "true");
    }
}
