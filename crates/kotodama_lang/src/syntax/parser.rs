//! Canonical single-scan source parser and lossless CST construction.
use super::{
    cst::{SyntaxOutline, SyntaxOutlineBuilder, SyntaxTree, build_tree_from_outline},
    kind::SyntaxKind,
    lexer::lex,
};
use crate::{
    ast::Program,
    diagnostic::{Diagnostic, DiagnosticBundle, DiagnosticPhase},
    source::{FrontendBudget, SourceFile},
};
use std::sync::{Condvar, Mutex, OnceLock};

// Recursive expression grammar is isolated from editor/linker caller stacks.
// The V1 nesting preflight bounds the logical depth at 256; the reserved stack
// is twice the 16 MiB debug-build boundary corpus exercised below. A global
// permit cap keeps concurrent parser workers to at most 64 MiB of reserved
// stack even when the linker has more outer module workers available.
const PARSER_STACK_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_PARSER_WORKERS: usize = 2;

struct ParserWorkerGate {
    active: Mutex<usize>,
    ready: Condvar,
}

impl ParserWorkerGate {
    fn acquire(&'static self) -> ParserWorkerPermit {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while *active >= MAX_PARSER_WORKERS {
            active = self
                .ready
                .wait(active)
                .unwrap_or_else(|poison| poison.into_inner());
        }
        *active = active.saturating_add(1);
        ParserWorkerPermit { gate: self }
    }
}

struct ParserWorkerPermit {
    gate: &'static ParserWorkerGate,
}

impl Drop for ParserWorkerPermit {
    fn drop(&mut self) {
        let mut active = self
            .gate
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *active = active.saturating_sub(1);
        self.gate.ready.notify_one();
    }
}

static PARSER_WORKER_GATE: OnceLock<ParserWorkerGate> = OnceLock::new();

fn acquire_parser_worker() -> ParserWorkerPermit {
    PARSER_WORKER_GATE
        .get_or_init(|| ParserWorkerGate {
            active: Mutex::new(0),
            ready: Condvar::new(),
        })
        .acquire()
}
/// Result of parsing for lossless editor and formatter consumers.
#[derive(Clone, Debug)]
pub struct ParseOutput {
    /// Concrete syntax tree, available even when diagnostics were emitted.
    pub tree: SyntaxTree,
    /// Deterministically ordered, bounded syntax diagnostics.
    pub diagnostics: DiagnosticBundle,
}
impl ParseOutput {
    /// Return whether parsing completed without diagnostics.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.diagnostics.diagnostics.is_empty()
    }
}
/// Canonical compiler parse result.
///
/// `tree` and `program` are derived from the same lossless token stream. A
/// failed parse retains the complete tree and omits the AST, preventing tools
/// from accidentally compiling a source that editor validation rejected.
#[derive(Clone, Debug)]
pub struct ProgramParseOutput {
    /// Complete lossless source tree.
    pub tree: SyntaxTree,
    /// Plain tooling AST parsed from the spanned tokens, present only after
    /// success. Hidden source/resolution provenance is stripped iteratively.
    pub program: Option<Program>,
    /// Wrapper-bearing parser AST consumed only by compiler-internal resolved
    /// HIR construction. Public tooling receives `program`, whose hidden
    /// provenance wrappers have been removed iteratively.
    pub(crate) sourced_program: Option<Program>,
    /// Deterministically ordered, bounded frontend diagnostics.
    pub diagnostics: DiagnosticBundle,
    /// Significant spanned tokens lowered from the same lossless scan.
    ///
    /// Compiler phases use this private stream for exact semantic source ranges; exposing it only
    /// within the crate prevents a second scanner from drifting from the CST.
    pub(crate) tokens: Vec<crate::lexer::Token>,
    /// Stable CST-derived AST source facts for compiler resolution.
    pub(crate) ast_facts: Option<crate::spanned_ast::AstFacts>,
}
impl ProgramParseOutput {
    /// Return whether a valid AST was produced without diagnostics.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.program.is_some() && self.diagnostics.diagnostics.is_empty()
    }
}
/// Parse one source file once, producing both its lossless CST and compiler AST.
#[must_use]
pub fn parse_program(source: &SourceFile, budget: FrontendBudget) -> ProgramParseOutput {
    parse_program_internal(source, budget, true, Some(false))
}
/// Parse bare included declarations while retaining their original source offsets.
#[must_use]
pub fn parse_fragment_program(source: &SourceFile, budget: FrontendBudget) -> ProgramParseOutput {
    parse_program_internal(source, budget, true, Some(true))
}
/// Parse a full source unit or a bare declaration file for source formatting.
///
/// The first significant token selects the grammar; lexing still runs only once.
#[must_use]
pub fn parse_source_or_fragment(source: &SourceFile, budget: FrontendBudget) -> ProgramParseOutput {
    parse_program_internal(source, budget, true, None)
}
pub(crate) fn parse_spanned_program(
    source: &SourceFile,
    budget: FrontendBudget,
) -> Result<(crate::spanned_ast::SpannedProgram, Vec<crate::lexer::Token>), DiagnosticBundle> {
    parse_spanned_program_mode(source, budget, false)
}
pub(crate) fn parse_spanned_fragment_program(
    source: &SourceFile,
    budget: FrontendBudget,
) -> Result<(crate::spanned_ast::SpannedProgram, Vec<crate::lexer::Token>), DiagnosticBundle> {
    parse_spanned_program_mode(source, budget, true)
}
pub(crate) fn parse_spanned_source_or_fragment(
    source: &SourceFile,
    budget: FrontendBudget,
) -> Result<(crate::spanned_ast::SpannedProgram, Vec<crate::lexer::Token>), DiagnosticBundle> {
    spanned_output(parse_program_internal(source, budget, false, None))
}
fn parse_spanned_program_mode(
    source: &SourceFile,
    budget: FrontendBudget,
    fragment: bool,
) -> Result<(crate::spanned_ast::SpannedProgram, Vec<crate::lexer::Token>), DiagnosticBundle> {
    spanned_output(parse_program_internal(
        source,
        budget,
        false,
        Some(fragment),
    ))
}
fn spanned_output(
    output: ProgramParseOutput,
) -> Result<(crate::spanned_ast::SpannedProgram, Vec<crate::lexer::Token>), DiagnosticBundle> {
    match (output.sourced_program, output.ast_facts) {
        (Some(program), Some(facts)) => Ok((
            crate::spanned_ast::SpannedProgram { program, facts },
            output.tokens,
        )),
        _ => Err(output.diagnostics),
    }
}
/// Attach authored prose through exact declaration and lossless-token boundaries.
/// Ordinary comments, blank lines, and significant tokens end a documentation block.
fn attach_documentation(
    source: &SourceFile,
    tokens: &[super::cst::GreenToken],
    facts: &mut crate::spanned_ast::AstFacts,
) {
    for declaration in &mut facts.declarations {
        if declaration.owner.is_some() {
            continue;
        }
        let Some(node) = facts.source_map.node(declaration.node) else {
            continue;
        };
        let mut index = tokens.partition_point(|token| token.range.end <= node.range.start);
        // The item modifier belongs to the declaration even when the AST node
        // begins at its type keyword rather than at `export`.
        if index > 0 {
            let prior = tokens[..index]
                .iter()
                .rposition(|token| !token.kind.is_trivia());
            if let Some(prior) = prior.filter(|prior| tokens[*prior].kind == SyntaxKind::KwExport) {
                index = prior;
            }
        }
        let mut lines = Vec::new();
        while index > 0 {
            index -= 1;
            let token = &tokens[index];
            let text = source.slice(token.range).unwrap_or_default();
            match token.kind {
                SyntaxKind::Whitespace if !text.contains('\n') => {}
                SyntaxKind::DocComment => {
                    lines.push(
                        text[3..]
                            .trim_end_matches(['\n', '\r'])
                            .strip_prefix(' ')
                            .unwrap_or(text[3..].trim_end_matches(['\n', '\r'])),
                    );
                }
                _ => break,
            }
        }
        lines.reverse();
        declaration.documentation = lines.join("\n");
    }
}

fn parse_program_internal(
    source: &SourceFile,
    budget: FrontendBudget,
    produce_plain_program: bool,
    fragment: Option<bool>,
) -> ProgramParseOutput {
    let lexed = lex(source, budget);
    let lossless_tokens = lexed.tokens.clone();
    let (lowered_tokens, mut lexical_diagnostics, mut omitted_lexical_diagnostics) =
        crate::lexer::lower_lexed_recovering_with_omissions(source, budget, lexed);
    let fragment = fragment.unwrap_or_else(|| {
        !matches!(
            lowered_tokens.first().map(|token| &token.kind),
            Some(crate::lexer::TokenKind::Seiyaku | crate::lexer::TokenKind::Module)
        )
    });
    let lexical_failure = !lexical_diagnostics.is_empty() || omitted_lexical_diagnostics != 0;
    let resource_failure = lexical_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.code.as_str(), "K0001" | "K0002" | "K0003"));
    let (
        mut program,
        mut sourced_program,
        mut ast_facts,
        syntax_diagnostics,
        tokens,
        outline,
        missing,
    ) = if resource_failure {
        (
            None,
            None,
            None,
            DiagnosticBundle::new(Vec::new()),
            Vec::new(),
            error_outline(source),
            Vec::new(),
        )
    } else {
        match crate::parser::validate_nesting(source, budget, &lowered_tokens) {
            Ok(()) => match parse_with_bounded_stack(source, budget, &lowered_tokens, fragment) {
                Ok(parsed) => {
                    let (program, sourced_program, ast_facts) =
                        parsed.spanned.map_or((None, None, None), |spanned| {
                            if produce_plain_program {
                                let mut plain = spanned.program;
                                crate::ast::strip_program_provenance(&mut plain);
                                (Some(plain), None, None)
                            } else {
                                (None, Some(spanned.program), Some(spanned.facts))
                            }
                        });
                    let tokens = if produce_plain_program {
                        Vec::new()
                    } else {
                        lowered_tokens
                    };
                    (
                        program,
                        sourced_program,
                        ast_facts,
                        parsed.diagnostics,
                        tokens,
                        parsed.outline,
                        parsed.missing,
                    )
                }
                Err(diagnostics) => (
                    None,
                    None,
                    None,
                    diagnostics,
                    Vec::new(),
                    error_outline(source),
                    Vec::new(),
                ),
            },
            Err(diagnostics) => (
                None,
                None,
                None,
                diagnostics,
                Vec::new(),
                error_outline(source),
                Vec::new(),
            ),
        }
    };
    if let Some(facts) = ast_facts.as_mut() {
        attach_documentation(source, &lossless_tokens, facts);
    }
    if lexical_failure {
        // Recovery trees are tooling output only. No AST containing or
        // surrounding a malformed token can cross into semantic analysis.
        if let Some(program) = program.take() {
            crate::ast::drop_program_iterative(program);
        }
        if let Some(program) = sourced_program.take() {
            crate::ast::drop_program_iterative(program);
        }
        ast_facts = None;
    }
    // Parser recovery after a malformed token exists to preserve CST shape,
    // not to manufacture cascaded user diagnostics from a token that the
    // semantic stream deliberately omitted. Report the authoritative lexical
    // failures first; syntax diagnostics become authoritative only when the
    // token stream itself was valid.
    let diagnostics = if lexical_failure {
        if let Some(nesting) = syntax_diagnostics
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "K0003")
            .cloned()
            && !lexical_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "K0003")
        {
            let retained = budget.max_diagnostics().saturating_sub(1);
            if lexical_diagnostics.len() >= retained && retained != 0 {
                lexical_diagnostics.pop();
                omitted_lexical_diagnostics = omitted_lexical_diagnostics.saturating_add(1);
            }
            if retained != 0 {
                lexical_diagnostics.push(nesting);
            }
        }
        DiagnosticBundle::new(crate::lexer::finalize_recovering_diagnostics(
            lexical_diagnostics,
            omitted_lexical_diagnostics,
        ))
    } else {
        syntax_diagnostics
    };
    let tree = build_tree_from_outline(source.id(), &lossless_tokens, &outline, &missing);
    ProgramParseOutput {
        tree,
        program,
        sourced_program,
        diagnostics,
        tokens,
        ast_facts,
    }
}
fn parse_with_bounded_stack(
    source: &SourceFile,
    budget: FrontendBudget,
    tokens: &[crate::lexer::Token],
    fragment: bool,
) -> Result<crate::parser::GrammarParseOutput, DiagnosticBundle> {
    let parse = || {
        if fragment {
            crate::parser::parse_with_syntax_mode(source, budget, tokens, true)
        } else {
            crate::parser::parse_with_syntax(source, budget, tokens)
        }
    };
    if crate::session::compiler_worker_active() {
        #[cfg(test)]
        crate::parser::record_direct_cst_lowering();
        return Ok(parse());
    }
    let _permit = acquire_parser_worker();
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("kotodama-parser".to_owned())
            .stack_size(PARSER_STACK_BYTES)
            .spawn_scoped(scope, parse);
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                return Err(DiagnosticBundle::single(Diagnostic::error(
                    "K0003",
                    DiagnosticPhase::Parse,
                    "compiler could not allocate the bounded stack required to validate source nesting",
                    None,
                )));
            }
        };
        #[cfg(test)]
        crate::parser::record_direct_cst_lowering();
        match worker.join() {
            Ok(parsed) => Ok(parsed),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}
/// Parse one source file into the canonical lossless CST.
#[must_use]
pub fn parse(source: &SourceFile, budget: FrontendBudget) -> ParseOutput {
    let output = parse_program(source, budget);
    if let Some(program) = output.program {
        crate::ast::drop_program_iterative(program);
    }
    if let Some(program) = output.sourced_program {
        crate::ast::drop_program_iterative(program);
    }
    ParseOutput {
        tree: output.tree,
        diagnostics: output.diagnostics,
    }
}
fn error_outline(source: &SourceFile) -> SyntaxOutline {
    let mut builder = SyntaxOutlineBuilder::default();
    let root = builder.start(SyntaxKind::Root, 0);
    let error = builder.start(SyntaxKind::ErrorNode, 0);
    builder.finish(error, source.full_range().end);
    builder.finish(root, source.full_range().end);
    builder.into_outline()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{MAX_NESTING_DEPTH, SourceId};
    use std::fmt::Write as _;

    const DIRECT_PARSER_TEST_STACK_BYTES: usize = 16 * 1024 * 1024;

    fn nested_expression(depth: usize, opening: &str, closing: &str) -> String {
        format!("{}0{}", opening.repeat(depth), closing.repeat(depth))
    }

    fn nested_calls(depth: usize) -> String {
        format!("{}0{}", "wrap(".repeat(depth), ")".repeat(depth))
    }

    fn nested_if_expressions(depth: usize) -> String {
        let mut expression = String::from("0");
        for _ in 0..depth {
            expression = format!("if true {{ {expression} }} else {{ 0 }}");
        }
        expression
    }

    fn nested_match_expressions(depth: usize) -> String {
        let mut expression = String::from("0");
        for _ in 0..depth {
            expression = format!("match Option::none {{ Option::none => {expression}, }}");
        }
        expression
    }

    fn nested_mixed_expressions(depth: usize) -> String {
        let mut expression = String::from("0");
        for index in 0..depth {
            expression = match index % 6 {
                0 => format!("[{expression}]"),
                1 => format!("wrap({expression})"),
                2 => format!("root[{expression}]"),
                3 => format!("json[{expression}]"),
                4 => format!("json{{ value: {expression} }}"),
                5 => format!("Node {{ value: {expression} }}"),
                _ => unreachable!("modulo constrains the wrapper kind"),
            };
        }
        expression
    }

    fn function_expression_source(expression: &str) -> String {
        format!("seiyaku Margin {{ fn f() {{ let value = {expression}; }} }}")
    }

    fn direct_parse_assertion(text: String, source_id: u32, label: &str, valid: bool) {
        let source = SourceFile::new(SourceId(source_id), format!("{label}.ko"), text.clone());
        let budget = FrontendBudget::v1();
        let lexed = lex(&source, budget);
        assert!(
            lexed.diagnostics.is_empty(),
            "{label}: {:?}",
            lexed.diagnostics
        );
        let lossless_tokens = lexed.tokens.clone();
        let tokens = crate::lexer::lower_lexed(&source, budget, lexed)
            .expect("boundary corpus must lower into significant tokens");
        crate::parser::validate_nesting(&source, budget, &tokens)
            .unwrap_or_else(|diagnostics| panic!("{label}: {diagnostics:?}"));
        let crate::parser::GrammarParseOutput {
            spanned,
            diagnostics,
            outline,
            missing,
        } = crate::parser::parse_with_syntax(&source, budget, &tokens);
        if valid {
            assert!(
                diagnostics.diagnostics.is_empty(),
                "{label}: {diagnostics:?}"
            );
            let spanned = spanned.unwrap_or_else(|| panic!("{label}: missing AST"));
            crate::ast::drop_program_iterative(spanned.program);
        } else {
            assert!(
                spanned.is_none(),
                "{label}: malformed source produced an AST"
            );
            assert!(
                !diagnostics.diagnostics.is_empty(),
                "{label}: malformed source produced no diagnostic"
            );
            assert!(
                diagnostics
                    .diagnostics
                    .iter()
                    .all(|diagnostic| diagnostic.code != "K0003"),
                "{label}: exact-boundary recovery was misclassified: {diagnostics:?}"
            );
        }
        let tree = build_tree_from_outline(source.id(), &lossless_tokens, &outline, &missing);
        assert_eq!(tree.text(&source), text, "{label}");
    }
    fn count_nodes(node: &crate::syntax::GreenNode, kind: SyntaxKind) -> usize {
        let mut count = usize::from(node.kind == kind);
        for child in &node.children {
            if let crate::syntax::GreenElement::Node(child) = child {
                count = count.saturating_add(count_nodes(child, kind));
            }
        }
        count
    }
    fn cst_snapshot(
        node: &crate::syntax::GreenNode,
        source: &SourceFile,
        depth: usize,
        output: &mut String,
    ) {
        let indent = "  ".repeat(depth);
        writeln!(
            output,
            "{indent}{:?}@{}..{}",
            node.kind, node.range.start, node.range.end
        )
        .expect("write CST node snapshot");
        for child in &node.children {
            match child {
                crate::syntax::GreenElement::Node(child) => {
                    cst_snapshot(child, source, depth + 1, output);
                }
                crate::syntax::GreenElement::Token(token)
                    if !token.kind.is_trivia() && token.kind != SyntaxKind::Eof =>
                {
                    if token.is_missing() {
                        writeln!(
                            output,
                            "{indent}  Missing({:?})@{}",
                            token.expected, token.range.start
                        )
                        .expect("write missing-token snapshot");
                    } else {
                        writeln!(
                            output,
                            "{indent}  {:?}={:?}@{}..{}",
                            token.kind,
                            source.slice(token.range).unwrap_or_default(),
                            token.range.start,
                            token.range.end
                        )
                        .expect("write CST token snapshot");
                    }
                }
                crate::syntax::GreenElement::Token(_) => {}
            }
        }
    }
    #[test]
    fn cst_preserves_decimal_literal_text() {
        let text =
            "seiyaku Demo { view fn value() authorize(anyone) -> decimal { return 1.250_0; } }";
        let source = SourceFile::new(SourceId(0), "decimal.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(output.tree.text(&source), text);
        assert!(
            output
                .tree
                .tokens()
                .iter()
                .any(|token| token.kind == SyntaxKind::Decimal)
        );
    }
    #[test]
    fn compiler_uses_one_direct_cst_lowering_without_a_token_only_reparse() {
        crate::parser::reset_direct_cst_lowering_count();
        let text = r#"seiyaku Direct { permission Set;
            struct Pair { int left, int right }
            const int limit = 2;
            state int value;
            hajimari() { value = 0; }
            kotoage fn set(int next) authorize(Set) { value = next; }
            view fn read() authorize(anyone) -> int { value }
        }"#;
        let source = SourceFile::new(SourceId(41), "direct.ko", text);
        let output = parse_program(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(crate::parser::direct_cst_lowering_count(), 1);
        assert_eq!(output.tree.text(&source), text);
    }

    #[test]
    fn direct_grammar_parser_fits_half_the_reserved_stack_at_v1_boundary() {
        std::thread::Builder::new()
            .name("kotodama-direct-parser-stack-margin".to_owned())
            .stack_size(DIRECT_PARSER_TEST_STACK_BYTES)
            .spawn(|| {
                let expression_depth = MAX_NESTING_DEPTH - 2;
                let type_depth = MAX_NESTING_DEPTH - 1;
                let nested_type = format!("{}T{}", "T<".repeat(type_depth), ">".repeat(type_depth));
                let nested_blocks = format!(
                    "seiyaku Margin {{ fn f() {{ {}let value = 0;{} }} }}",
                    "if true { ".repeat(expression_depth),
                    " }".repeat(expression_depth)
                );
                let valid = [
                    (
                        "parentheses",
                        function_expression_source(&nested_expression(expression_depth, "(", ")")),
                    ),
                    (
                        "lists",
                        function_expression_source(&nested_expression(expression_depth, "[", "]")),
                    ),
                    (
                        "calls",
                        function_expression_source(&nested_calls(expression_depth)),
                    ),
                    (
                        "mixed-expressions",
                        function_expression_source(&nested_mixed_expressions(expression_depth)),
                    ),
                    (
                        "if-expressions",
                        function_expression_source(&nested_if_expressions(expression_depth)),
                    ),
                    (
                        "match-expressions",
                        function_expression_source(&nested_match_expressions(expression_depth)),
                    ),
                    (
                        "generic-types",
                        format!("seiyaku Margin {{ state {nested_type} value; }}"),
                    ),
                    ("statement-blocks", nested_blocks),
                ];
                for (index, (label, text)) in valid.into_iter().enumerate() {
                    direct_parse_assertion(text, 100 + index as u32, label, true);
                }

                let malformed_list = format!(
                    "seiyaku Margin {{ fn f() {{ let value = {}0{}; }} }}",
                    "[".repeat(expression_depth),
                    "]".repeat(expression_depth - 1)
                );
                let malformed_type = format!(
                    "seiyaku Margin {{ state {}T{} value; }}",
                    "T<".repeat(type_depth),
                    ">".repeat(type_depth - 1)
                );
                let malformed_blocks = format!(
                    "seiyaku Margin {{ fn f() {{ {}let value = 0;",
                    "if true { ".repeat(expression_depth)
                );
                for (index, (label, text)) in [
                    ("malformed-list", malformed_list),
                    ("malformed-type", malformed_type),
                    ("malformed-blocks", malformed_blocks),
                ]
                .into_iter()
                .enumerate()
                {
                    direct_parse_assertion(text, 120 + index as u32, label, false);
                }
            })
            .expect("spawn direct grammar parser margin worker")
            .join()
            .expect("direct grammar parser must fit the verified 16 MiB stack margin");
    }
    #[test]
    fn public_ast_is_plain_but_internal_ast_retains_direct_node_ids() {
        use crate::ast::{Item, Statement};
        let text = "誓約 Direct { 始まり() { let int value = 1; } }";
        let source = SourceFile::new(SourceId(45), "direct-node-ids.ko", text);
        let public = parse_program(&source, FrontendBudget::v1());
        assert!(public.sourced_program.is_none());
        assert!(public.ast_facts.is_none());
        assert!(public.tokens.is_empty());
        let public_program = public.program.expect("plain public AST");
        let Item::Function(public_function) = &public_program.items[0] else {
            panic!("expected lifecycle function")
        };
        assert!(matches!(
            public_function.body.statements[0],
            Statement::Let { .. }
        ));
        let (spanned, _) = parse_spanned_program(&source, FrontendBudget::v1())
            .expect("wrapper-bearing compiler AST");
        let Item::Function(function) = &spanned.program.items[0] else {
            panic!("expected lifecycle function")
        };
        let Statement::Source {
            node,
            source: statement_source,
            ..
        } = &function.body.statements[0]
        else {
            panic!("compiler AST statement must retain direct provenance")
        };
        assert_eq!(
            spanned
                .facts
                .source_map
                .node(*node)
                .map(|entry| entry.range),
            Some(statement_source.range)
        );
    }
    #[test]
    fn structured_missing_tokens_are_independent_of_diagnostic_wording() {
        let text = "seiyaku Broken { fn bad(int) { return; } }";
        let source = SourceFile::new(SourceId(46), "structured-missing.ko", text);
        let lexed = lex(&source, FrontendBudget::v1());
        let lossless = lexed.tokens.clone();
        let tokens = crate::lexer::lower_lexed(&source, FrontendBudget::v1(), lexed)
            .expect("lower significant token view");
        let mut parsed = crate::parser::parse_with_syntax(&source, FrontendBudget::v1(), &tokens);
        let missing_offset =
            u32::try_from(text.find(')').expect("parameter close")).expect("source budget");
        assert!(parsed.missing.iter().any(|missing| {
            missing.offset == missing_offset && missing.expected == SyntaxKind::Ident
        }));
        for diagnostic in &mut parsed.diagnostics.diagnostics {
            diagnostic.message = "localized parser message without token spelling".into();
        }
        let tree =
            build_tree_from_outline(source.id(), &lossless, &parsed.outline, &parsed.missing);
        assert!(
            tree.tokens()
                .iter()
                .any(|token| { token.is_missing() && token.expected == Some(SyntaxKind::Ident) })
        );
    }
    #[test]
    fn direct_cst_lowering_preserves_every_branded_declaration_form() {
        use crate::ast::{FunctionKind, Item, SourceUnitKind};
        let text = r#"誓約 Branded { permission Apply;
            struct Pair { int left, int right }
            error enum Failure { Bad = 1 }
            const int limit = 2;
            state int value;
            trigger tick -> apply { on time pre_commit; }
            始まり() { value = 0; }
            改善() { value = value + 1; }
            言挙げ fn apply(int next) authorize(Apply) { value = next; }
            view fn read() authorize(anyone) -> int { value }
            fn helper(int value) -> int { value }
        }"#;
        let source = SourceFile::new(SourceId(42), "branded-direct.ko", text);
        let output = parse_program(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        let program = output.program.expect("direct CST AST");
        assert_eq!(program.unit.kind, SourceUnitKind::Seiyaku);
        let functions = program
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Function(function) => Some((function.name.as_str(), function.modifiers.kind)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            functions,
            [
                ("hajimari", FunctionKind::Hajimari),
                ("kaizen", FunctionKind::Kaizen),
                ("apply", FunctionKind::Kotoage),
                ("read", FunctionKind::View),
                ("helper", FunctionKind::Private),
            ]
        );
    }
    #[test]
    fn direct_cst_lowering_recovers_multiple_malformed_items() {
        let text = r#"seiyaku Broken {
            fn first(value int) { return; }
            fn second() { let int missing = ; return; }
            fn third(bool flag) { if flag { return } }
        }"#;
        let source = SourceFile::new(SourceId(43), "multi-error.ko", text);
        let output = parse_program(&source, FrontendBudget::v1());
        assert_eq!(output.tree.text(&source), text);
        assert!(!output.is_ok());
        assert!(
            output.diagnostics.diagnostics.len() >= 2,
            "{:?}",
            output.diagnostics
        );
        assert!(output.diagnostics.diagnostics.iter().all(|diagnostic| {
            diagnostic
                .primary_span
                .as_ref()
                .and_then(|span| span.byte_range)
                .is_some_and(|range| source.slice(range).is_some())
        }));
        assert!(output.tree.tokens().iter().any(|token| token.is_missing()));
    }
    #[test]
    fn japanese_keyword_name_facts_keep_exact_utf8_byte_ranges() {
        let text = "誓約 Demo { 始まり() { let string message = \"雪\"; } }";
        let source = SourceFile::new(SourceId(44), "unicode-spans.ko", text);
        let (spanned, _) =
            parse_spanned_program(&source, FrontendBudget::v1()).expect("direct-ID compiler AST");
        let facts = spanned.facts;
        let lifecycle = facts
            .declarations
            .iter()
            .find(|declaration| declaration.name == "hajimari")
            .expect("hajimari declaration");
        let name = facts
            .source_map
            .node(lifecycle.name_node)
            .expect("lifecycle name node");
        let declaration = facts
            .source_map
            .node(lifecycle.node)
            .expect("lifecycle declaration node");
        assert_eq!(source.slice(name.range), Some("始まり"));
        assert_eq!(
            source.slice(declaration.range),
            Some("始まり() { let string message = \"雪\"; }")
        );
        assert_eq!(
            name.range.start,
            u32::try_from(text.find("始まり").expect("keyword offset"))
                .expect("source budget fits u32")
        );
        assert!(text.is_char_boundary(
            usize::try_from(name.range.start).expect("source budget fits usize")
        ));
        assert!(
            text.is_char_boundary(
                usize::try_from(name.range.end).expect("source budget fits usize")
            )
        );
    }
    #[test]
    fn cst_accepts_and_preserves_unsuffixed_fraction_text() {
        let text = "seiyaku Demo { fn valid() { let value = 1.25; } }";
        let source = SourceFile::new(SourceId(0), "decimal.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(output.tree.text(&source), text);
        assert!(
            output
                .tree
                .tokens()
                .iter()
                .any(|token| token.kind == SyntaxKind::Decimal)
        );
    }
    #[test]
    fn cst_preserves_named_call_and_struct_literal_tokens() {
        let text = "seiyaku Demo { struct Pair { int first, string second } fn build(int first) -> Pair { return Pair { second: \"two\", first, }; } fn call() { build(first: 1,); } }";
        let source = SourceFile::new(SourceId(0), "named.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(output.tree.text(&source), text);
        let kinds = output
            .tree
            .tokens()
            .iter()
            .map(|token| token.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == SyntaxKind::Colon)
                .count(),
            2,
            "only named struct and call arguments use colons in type-first V1 syntax"
        );
        assert!(
            kinds
                .iter()
                .filter(|kind| **kind == SyntaxKind::Comma)
                .count()
                >= 4
        );
    }
    #[test]
    fn named_source_units_do_not_synthesize_missing_tokens() {
        for text in ["seiyaku Demo {}", "誓約 Demo {}", "module Demo {}"] {
            let source = SourceFile::new(SourceId(0), "named-unit.ko", text);
            let output = parse_program(&source, FrontendBudget::v1());
            assert!(output.is_ok(), "{text}: {:?}", output.diagnostics);
            assert_eq!(output.tree.text(&source), text);
            assert!(
                output.tree.tokens().iter().all(|token| !token.is_missing()),
                "valid named source unit synthesized a recovery token: {text}"
            );
        }
    }
    #[test]
    fn statement_boundaries_lower_only_source_tokens() {
        let text = r#"seiyaku Statements { permission Update;
            state int value;
            hajimari() {
                value = 0;
            }
            kotoage fn update(int limit) authorize(Update) {
                var int total = 0;
                for item in range(4) {
                    if item < limit { total += item; } else { continue; }
                }
                value = total;
            }
            view fn read() authorize(anyone) -> int { return value; }
        }"#;
        let source = SourceFile::new(SourceId(0), "statements.ko", text);
        let output = parse_program(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert!(output.tree.tokens().iter().all(|token| !token.is_missing()));
        assert_eq!(output.tree.text(&source), text);
    }
    #[test]
    fn cst_terminated_items_do_not_leak_recovery_tokens_into_the_ast_stream() {
        let text = r#"seiyaku Demo {
    state StateMap<int, int> values;
    const int limit = 2;
    view fn read() authorize(anyone) -> int { values.get(limit).unwrap_or(0) }
}"#;
        let source = SourceFile::new(SourceId(0), "terminated-items.ko", text);
        let output = parse_program(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(output.tree.text(&source), text);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::StateItem), 1);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::ConstItem), 1);
        assert!(output.tree.tokens().iter().all(|token| !token.is_missing()));
    }
    #[test]
    fn cst_terminated_items_track_braced_initializers() {
        let text = r#"seiyaku Demo {
    struct Entry { int value }
    const Json payload = json { value: 1, };
    const Entry entry = Entry { value: 2, };
    view fn read() authorize(anyone) -> int { entry.value }
}"#;
        let source = SourceFile::new(SourceId(0), "braced-consts.ko", text);
        let output = parse_program(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(output.tree.text(&source), text);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::ConstItem), 2);
        assert!(output.tree.tokens().iter().all(|token| !token.is_missing()));
    }
    #[test]
    fn cst_missing_semicolon_recovers_before_an_attributed_item() {
        let text = r#"seiyaku Demo {
    const int limit = 2
    #[test]
    fn check() {}
}"#;
        let source = SourceFile::new(SourceId(0), "attributed-recovery.ko", text);
        let output = parse_program(&source, FrontendBudget::v1());
        assert!(!output.is_ok());
        assert_eq!(output.tree.text(&source), text);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::ConstItem), 1);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::FunctionItem), 1);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::Attribute), 1);
        assert!(output.tree.tokens().iter().any(|token| {
            token.kind == SyntaxKind::Missing && token.expected == Some(SyntaxKind::Semicolon)
        }));
    }
    #[test]
    fn cst_missing_semicolon_recovers_before_a_plain_item() {
        let text = r#"seiyaku Demo {
    const int limit = 2
    fn check() {}
}"#;
        let source = SourceFile::new(SourceId(0), "plain-recovery.ko", text);
        let output = parse_program(&source, FrontendBudget::v1());
        assert!(!output.is_ok());
        assert_eq!(output.tree.text(&source), text);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::ConstItem), 1);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::FunctionItem), 1);
        assert!(output.tree.tokens().iter().any(|token| {
            token.kind == SyntaxKind::Missing && token.expected == Some(SyntaxKind::Semicolon)
        }));
    }
    #[test]
    fn pseudo_item_spellings_remain_ordinary_expression_identifiers() {
        let text = r#"seiyaku Demo {
    const int fixture = 1;
    const int selected = fixture;
    view fn read() authorize(anyone) -> int { selected }
}"#;
        let source = SourceFile::new(SourceId(0), "pseudo-item-identifiers.ko", text);
        let output = parse_program(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(output.tree.text(&source), text);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::ConstItem), 2);
        assert!(output.tree.tokens().iter().all(|token| !token.is_missing()));
    }
    #[test]
    fn cst_recovery_preserves_mixed_call_arguments() {
        let text = "seiyaku Demo { fn invalid() { target(first: 1, 2); } }";
        let source = SourceFile::new(SourceId(0), "mixed.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(!output.is_ok());
        assert_eq!(
            output.diagnostics.diagnostics[0].code,
            "E_POSITIONAL_ARGUMENT_ORDER"
        );
        assert_eq!(output.tree.text(&source), text);
    }
    #[test]
    fn cst_structures_tail_match_arms_and_sum_patterns_losslessly() {
        let text = "seiyaku Demo { fn unwrap(Option<int> value) -> int { match value { Option::some(item) => item, Option::none => 0, } } }";
        let source = SourceFile::new(SourceId(0), "match.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(output.tree.text(&source), text);
        let root = output.tree.root();
        assert_eq!(count_nodes(root, SyntaxKind::TailExpr), 1);
        assert_eq!(count_nodes(root, SyntaxKind::MatchExpr), 1);
        assert_eq!(count_nodes(root, SyntaxKind::MatchArm), 2);
        assert_eq!(count_nodes(root, SyntaxKind::SumPattern), 2);
        assert!(output.tree.tokens().iter().all(|token| !token.is_missing()));
    }
    #[test]
    fn cst_structures_lists_and_comprehensions_losslessly() {
        let text = "seiyaku Demo { fn lists() -> List<int, 4> { let List<int, 4> source = [1, [2].get(0).unwrap_or(0),]; [value * 2 for value in source if value > 0] } }";
        let source = SourceFile::new(SourceId(0), "lists.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(output.tree.text(&source), text);
        let root = output.tree.root();
        assert_eq!(count_nodes(root, SyntaxKind::ListExpr), 2);
        assert_eq!(count_nodes(root, SyntaxKind::ListComprehension), 1);
        assert!(output.tree.tokens().iter().all(|token| !token.is_missing()));
    }
    #[test]
    fn cst_structures_recursive_native_json_losslessly() {
        let text = r#"seiyaku Demo { fn build(string label) -> Json { json { owner: "alice", labels: json ["primary", label], nested: json { "owner": 1, }, } } }"#;
        let source = SourceFile::new(SourceId(0), "json.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(output.is_ok(), "{:?}", output.diagnostics);
        assert_eq!(output.tree.text(&source), text);
        let root = output.tree.root();
        assert_eq!(count_nodes(root, SyntaxKind::JsonObjectExpr), 2);
        assert_eq!(count_nodes(root, SyntaxKind::JsonObjectEntry), 4);
        assert_eq!(count_nodes(root, SyntaxKind::JsonArrayExpr), 1);
        assert!(output.tree.tokens().iter().all(|token| !token.is_missing()));
    }
    #[test]
    fn cst_native_json_recovery_inserts_the_specific_closing_delimiter() {
        let text = "seiyaku Demo { fn invalid() -> Json { json { labels: json [1, 2; } } }";
        let source = SourceFile::new(SourceId(0), "invalid-json.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(!output.is_ok());
        assert_eq!(output.tree.text(&source), text);
        assert_eq!(
            count_nodes(output.tree.root(), SyntaxKind::JsonObjectExpr),
            1
        );
        assert_eq!(
            count_nodes(output.tree.root(), SyntaxKind::JsonArrayExpr),
            1
        );
        assert!(output.tree.tokens().iter().any(|token| {
            token.kind == SyntaxKind::Missing && token.expected == Some(SyntaxKind::RBracket)
        }));
    }
    #[test]
    fn cst_list_recovery_inserts_a_specific_closing_bracket() {
        let text = "seiyaku Demo { fn invalid() { let values = [1, 2; } }";
        let source = SourceFile::new(SourceId(0), "invalid-list.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(!output.is_ok());
        assert_eq!(output.tree.text(&source), text);
        assert_eq!(count_nodes(output.tree.root(), SyntaxKind::ListExpr), 1);
        assert!(output.tree.tokens().iter().any(|token| {
            token.kind == SyntaxKind::Missing && token.expected == Some(SyntaxKind::RBracket)
        }));
    }
    #[test]
    fn cst_snapshot_locks_expression_json_list_and_recovery_structure() {
        let text = "seiyaku C { fn f(Option<int> v) { let choice = v? ? 1 : 2; let payload = json { values: json [1, [x for x in [1, 2] if x > 0]; }; } }";
        let source = SourceFile::new(SourceId(0), "snapshot.ko", text);
        let output = parse(&source, FrontendBudget::v1());
        assert!(!output.is_ok(), "fixture must retain its recovery token");
        assert_eq!(output.tree.text(&source), text);
        let mut snapshot = String::new();
        cst_snapshot(output.tree.root(), &source, 0, &mut snapshot);
        assert_eq!(snapshot, include_str!("fixtures/expression_recovery.snap"),);
    }
}
