//! Kotodama source linter.
//!
//! Provides lightweight static analysis passes that flag common mistakes in Kotodama programs
//! before compiling them to IVM bytecode. The initial set of checks focuses on surface issues such
//! as unused `state` declarations and obviously unreachable statements that follow a `return`.
use super::ast::{Block, Expr, Item, Pattern, PatternBinding, Program, Statement};
use crate::i18n::{self, Language, Message as I18nMessage, StateShadowContext};
use crate::pointer_abi::{self, PointerType};
use crate::{
    source::{SourceFile, SourceRange, TextRange},
    spanned_ast::{AstFacts, DeclarationKind},
};
use iroha_data_model::{
    isi::{
        BurnBox, ExecuteTrigger, GrantBox, InstructionBox, Log, MintBox, RegisterBox,
        RemoveKeyValueBox, RevokeBox, SetKeyValueBox, TransferBox, UnregisterBox,
    },
    query::{QueryRequest, SingularQueryBox},
};
use kotodama_surface::builtins::{Builtin, BuiltinSurface, PointerConstructor};
use std::collections::{BTreeMap, HashMap, HashSet};
/// A lint warning produced by [`lint_program`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintWarning {
    /// Stable identifier for the lint (e.g., `unused-state`).
    pub code: &'static str,
    /// Structured, localizable lint message data.
    pub message: LintMessage,
    /// Machine-readable severity for CLI/editor integrations.
    pub severity: LintSeverity,
    /// Broad lint family for coarse filtering.
    pub category: LintCategory,
    /// Optional source span for inline editor surfacing.
    pub source: Option<LintSourceSpan>,
    /// Site-specific remediation that replaces the registry help.
    pub help: Option<String>,
    /// Related source locations with explanations.
    pub labels: Vec<LintLabel>,
    /// Machine-applicable replacement, when one is safe.
    pub fix: Option<LintFix>,
    range: Option<SourceRange>,
    related: Vec<(SourceRange, String)>,
    recipe: Option<LintFixRecipe>,
}
/// One related source location attached to a lint finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintLabel {
    /// Exact related range.
    pub span: LintSourceSpan,
    /// What the range shows.
    pub message: String,
}
/// One machine-applicable lint replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFix {
    /// Range to replace.
    pub span: LintSourceSpan,
    /// Replacement text.
    pub replacement: String,
}
/// Source-independent description of a lint fix, materialized against the
/// immutable source text once spans are known.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LintFixRecipe {
    /// Replace `range` with `text`.
    Replace { range: SourceRange, text: String },
    /// Insert `{map}[{key}] = {binding};` on its own line after `after`.
    WriteBack {
        after: SourceRange,
        map: String,
        key: Option<SourceRange>,
        binding: String,
    },
    /// Replace the leading `kotoage`/`言挙げ` keyword of a declaration with `view`.
    KotoageToView { declaration: SourceRange },
    /// Discard one struct-pattern binding: `field: _` for the shorthand
    /// `{ field }`, or `_` in place of the binding of `{ field: binding }`.
    StructFieldDiscard { field: SourceRange, name: String },
    /// Replace the leading `var` keyword of a local declaration with `let`.
    VarToLet { statement: SourceRange },
}
impl LintWarning {
    fn new(code: &'static str, message: LintMessage) -> Self {
        Self {
            code,
            message,
            severity: LintSeverity::Warning,
            category: lint_category(code),
            source: None,
            help: None,
            labels: Vec::new(),
            fix: None,
            range: None,
            related: Vec::new(),
            recipe: None,
        }
    }
    fn at_source(mut self, range: Option<SourceRange>) -> Self {
        self.range = range;
        self
    }
    fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
    fn with_related(mut self, range: Option<SourceRange>, message: impl Into<String>) -> Self {
        if let Some(range) = range {
            self.related.push((range, message.into()));
        }
        self
    }
    fn with_recipe(mut self, recipe: Option<LintFixRecipe>) -> Self {
        self.recipe = recipe;
        self
    }
    /// Report this finding at `level`; `Deny` turns it into an error.
    #[must_use]
    pub fn with_level(mut self, level: LintLevel) -> Self {
        self.severity = match level {
            LintLevel::Deny => LintSeverity::Error,
            LintLevel::Allow | LintLevel::Warn => LintSeverity::Warning,
        };
        self
    }
    /// Render the lint message in the requested language.
    pub fn localized_message(&self, lang: Language) -> String {
        self.message.translate(lang)
    }
    /// Stable unified diagnostic code used by `koto check`, LSP, and SDK tools.
    pub fn diagnostic_code(&self) -> &'static str {
        lint_by_slug(self.code).map_or("K5099", |(_, code, _)| code)
    }
    /// Project this lint through the same exact diagnostic model used by compiler failures.
    pub fn to_diagnostic(
        &self,
        source_name: &str,
        package_identity: Option<&str>,
        language: Language,
    ) -> crate::diagnostic::Diagnostic {
        use crate::diagnostic::{Diagnostic, DiagnosticPhase, SourcePosition, SourceSpan};
        let span = self.source.as_ref().map(|span| SourceSpan {
            package_identity: package_identity.map(ToOwned::to_owned),
            source: Some(source_name.to_owned()),
            start: SourcePosition {
                line: span.line,
                column: span.column,
            },
            end: SourcePosition {
                line: span.end_line,
                column: span.end_column,
            },
            byte_range: Some(span.byte_range),
        });
        let to_span = |span: &LintSourceSpan| SourceSpan {
            package_identity: package_identity.map(ToOwned::to_owned),
            source: Some(source_name.to_owned()),
            start: SourcePosition {
                line: span.line,
                column: span.column,
            },
            end: SourcePosition {
                line: span.end_line,
                column: span.end_column,
            },
            byte_range: Some(span.byte_range),
        };
        // The message is the canonical English text; a translation rides along
        // as `localized`, so machine-readable output stays stable and human
        // output never mixes a translated message with English help or notes.
        let english = self.localized_message(Language::English);
        let mut diagnostic = match self.severity {
            LintSeverity::Warning => Diagnostic::warning(
                self.diagnostic_code(),
                DiagnosticPhase::Semantic,
                english,
                span,
            ),
            LintSeverity::Error => Diagnostic::error(
                self.diagnostic_code(),
                DiagnosticPhase::Semantic,
                english,
                span,
            ),
        };
        diagnostic.notes.push(format!(
            "lint `{}` in category `{}`",
            self.code,
            self.category.as_str()
        ));
        if let Some(help) = &self.help {
            diagnostic.help = Some(help.clone());
        }
        for label in &self.labels {
            diagnostic.labels.push(crate::diagnostic::DiagnosticLabel {
                span: to_span(&label.span),
                message: label.message.clone(),
            });
            diagnostic
                .label_sources
                .push(Some(label.span.source_file.clone()));
        }
        diagnostic.fix = self
            .fix
            .as_ref()
            .map(|fix| crate::diagnostic::DiagnosticFix {
                span: to_span(&fix.span),
                replacement: fix.replacement.clone(),
            });
        if let Some(span) = &self.source {
            // The compiler has already authenticated this source; display path remapping
            // does not replace its immutable bytes with a filesystem or open-buffer read.
            diagnostic.primary_source = Some(span.source_file.clone());
        }
        crate::i18n::with_translation(diagnostic, language, self.localized_message(language))
    }
}
/// Reported severity of one lint finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    /// Non-fatal finding (the default for every lint).
    Warning,
    /// Finding promoted to an error by lint configuration.
    Error,
}
impl LintSeverity {
    /// Stable machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}
/// Configured level of one lint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LintLevel {
    /// Do not report the lint.
    Allow,
    /// Report the lint as a warning.
    Warn,
    /// Report the lint as an error that fails the check.
    Deny,
}
impl LintLevel {
    /// Parse `allow`, `warn`, or `deny`.
    pub fn parse(level: &str) -> Option<Self> {
        match level {
            "allow" => Some(Self::Allow),
            "warn" => Some(Self::Warn),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
    /// Stable lowercase spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Deny => "deny",
        }
    }
}
/// Broad lint family for coarse filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintCategory {
    /// Likely bugs or dead code.
    Correctness,
    /// Findings that limit scheduler access precision.
    AccessHints,
    /// Typed identifier and constructor literals.
    TypedLiterals,
    /// Trigger declarations.
    Triggers,
    /// Seiyaku interface and programming-model choices.
    Interface,
    /// Exact numeric arithmetic.
    Numeric,
}
impl LintCategory {
    /// Stable category name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Correctness => "correctness",
            Self::AccessHints => "access-hints",
            Self::TypedLiterals => "typed-literals",
            Self::Triggers => "triggers",
            Self::Interface => "interface",
            Self::Numeric => "numeric",
        }
    }
}
/// Every lint the compiler can report: slug, unified code, and category.
///
/// Slugs are the stable names used by lint configuration and `koto explain`.
pub const LINT_REGISTRY: &[(&str, &str, LintCategory)] = &[
    ("unused-state", "K5001", LintCategory::Correctness),
    ("state-shadowed", "K5002", LintCategory::Correctness),
    ("unused-parameter", "K5003", LintCategory::Correctness),
    ("unreachable-return", "K5004", LintCategory::Correctness),
    (
        "duplicate-pointer-literal",
        "K5005",
        LintCategory::TypedLiterals,
    ),
    (
        "unused-pointer-constructor",
        "K5006",
        LintCategory::TypedLiterals,
    ),
    ("nonliteral-trigger-spec", "K5007", LintCategory::Triggers),
    ("nonliteral-state-path", "K5008", LintCategory::AccessHints),
    ("opaque-access-hints", "K5009", LintCategory::AccessHints),
    ("unpersisted-state-copy", "K5010", LintCategory::Correctness),
    ("kotoage-without-effects", "K5011", LintCategory::Interface),
    ("exact-division", "K5012", LintCategory::Numeric),
    ("unused-local", "K5013", LintCategory::Correctness),
    ("dead-store", "K5014", LintCategory::Correctness),
    (
        "underscore-public-parameter",
        "K5015",
        LintCategory::Interface,
    ),
    ("never-mutated-var", "K5016", LintCategory::Correctness),
    ("unused-private-fn", "K5017", LintCategory::Correctness),
    (
        "seiyaku-without-entrypoint",
        "K5018",
        LintCategory::Interface,
    ),
];
/// Look up a lint slug in [`LINT_REGISTRY`].
pub fn lint_by_slug(slug: &str) -> Option<(&'static str, &'static str, LintCategory)> {
    LINT_REGISTRY
        .iter()
        .copied()
        .find(|(candidate, _, _)| *candidate == slug)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintSourceSpan {
    /// One-based Unicode-scalar start line.
    pub line: usize,
    /// One-based Unicode-scalar start column.
    pub column: usize,
    /// One-based Unicode-scalar end line.
    pub end_line: usize,
    /// One-based Unicode-scalar end column.
    pub end_column: usize,
    /// Exact parser-owned UTF-8 byte range.
    pub byte_range: TextRange,
    /// Immutable source shared by all warnings from this compilation unit.
    pub source_file: SourceFile,
}
/// Attach only parser-owned declarations, bindings, and expression ranges to lint findings.
pub(crate) fn lint_with_sources(
    program: &Program,
    facts: &AstFacts,
    source: &SourceFile,
) -> Vec<LintWarning> {
    let mut functions = BTreeMap::new();
    let mut function_names = BTreeMap::new();
    let mut states = BTreeMap::new();
    let mut parameters = BTreeMap::new();
    for declaration in &facts.declarations {
        let Some(range) = facts.source_map.source_range(declaration.name_node) else {
            continue;
        };
        match declaration.kind {
            DeclarationKind::Function => {
                functions.insert(declaration.name.as_str(), declaration.node);
                function_names.insert(declaration.name.as_str(), range);
            }
            DeclarationKind::State => {
                states.insert(declaration.name.as_str(), range);
            }
            DeclarationKind::Parameter => {
                if let Some(owner) = declaration.owner {
                    parameters.insert((owner, declaration.name.as_str()), range);
                }
            }
            _ => {}
        }
    }
    let mut bindings = BTreeMap::<&str, BTreeMap<u32, SourceRange>>::new();
    for binding in &facts.bindings {
        if let Some(range) = facts.source_map.source_range(binding.name_node) {
            bindings
                .entry(binding.name.as_str())
                .or_default()
                .insert(range.range.start, range);
        }
    }
    let span_of = |range: SourceRange| {
        (range.source == source.id() && source.slice(range.range).is_some()).then(|| {
            let start = source.line_column(range.range.start);
            let end = source.line_column(range.range.end);
            LintSourceSpan {
                line: start.line,
                column: start.column,
                end_line: end.line,
                end_column: end.column,
                byte_range: range.range,
                source_file: source.clone(),
            }
        })
    };
    let mut warnings = lint_program(program);
    for warning in &mut warnings {
        if let LintMessage::KotoageWithoutEffects { func, keyword } = &mut warning.message {
            let declaration = facts
                .declarations
                .iter()
                .find(|fact| fact.kind == DeclarationKind::Function && fact.name == *func)
                .and_then(|fact| facts.source_map.source_range(fact.node));
            if let Some(declaration) = declaration
                && let Some(spelled) = source.slice(declaration.range).and_then(|text| {
                    crate::glossary::by_spelling("kotoage").and_then(|kotoage| {
                        kotoage
                            .spellings()
                            .into_iter()
                            .find(|spelling| text.trim_start().starts_with(spelling))
                    })
                })
            {
                *keyword = spelled.to_owned();
                warning.recipe = Some(LintFixRecipe::KotoageToView { declaration });
            }
            warning.range = function_names.get(func.as_str()).copied().or(warning.range);
        }
        if let LintMessage::UnusedPrivateFunction { func } = &warning.message {
            warning.range = function_names.get(func.as_str()).copied().or(warning.range);
        }
        if let LintMessage::SeiyakuWithoutEntrypoint { keyword, .. } = &mut warning.message
            && let Some(unit) = facts
                .declarations
                .iter()
                .find(|fact| fact.kind == DeclarationKind::SourceUnit)
        {
            if let Some(spelled) = facts
                .source_map
                .source_range(unit.node)
                .and_then(|range| source.slice(range.range))
                .and_then(|text| {
                    crate::glossary::by_spelling("seiyaku").and_then(|seiyaku| {
                        seiyaku
                            .spellings()
                            .into_iter()
                            .find(|spelling| text.trim_start().starts_with(spelling))
                    })
                })
            {
                *keyword = spelled.to_owned();
            }
            warning.range = facts
                .source_map
                .source_range(unit.name_node)
                .or(warning.range);
        }
        let declaration = match &warning.message {
            LintMessage::UnusedState { name } => states.get(name.as_str()),
            LintMessage::UnusedParameter { func, name }
            | LintMessage::UnderscorePublicParameter { func, name, .. }
            | LintMessage::StateShadowed {
                func,
                name,
                context: StateShadowContext::Parameter,
            } => functions
                .get(func.as_str())
                .and_then(|owner| parameters.get(&(*owner, name.as_str()))),
            _ => None,
        };
        let mut range = declaration.copied().or(warning.range);
        if let LintMessage::UnderscorePublicParameter { name, also, .. } = &warning.message {
            if let Some(parameter) = declaration {
                warning.recipe = Some(LintFixRecipe::Replace {
                    range: *parameter,
                    text: name.trim_start_matches('_').to_owned(),
                });
            }
            for other in also {
                if let Some(parameter) = functions
                    .get(other.as_str())
                    .and_then(|owner| parameters.get(&(*owner, name.as_str())))
                {
                    warning
                        .related
                        .push((*parameter, format!("`{other}` declares `{name}` here too")));
                }
            }
        }
        if let LintMessage::UnderscorePublicParameter { func, .. } = &mut warning.message
            && let Some(keyword) = crate::glossary::by_spelling(func)
            && let Some(spelled) = facts
                .declarations
                .iter()
                .find(|fact| fact.kind == DeclarationKind::Function && fact.name == *func)
                .and_then(|fact| facts.source_map.source_range(fact.node))
                .and_then(|range| source.slice(range.range))
                .and_then(|text| {
                    keyword
                        .spellings()
                        .into_iter()
                        .find(|spelling| text.trim_start().starts_with(spelling))
                })
        {
            spelled.clone_into(func);
        }
        let narrowed = match &warning.message {
            LintMessage::StateShadowed { name, .. }
            | LintMessage::UnusedLocal { name, .. }
            | LintMessage::NeverMutatedVar { name }
            | LintMessage::UnpersistedStateCopy { binding: name, .. } => Some(name.as_str()),
            _ => None,
        };
        if let (Some(context), Some(name)) = (range, narrowed)
            && let Some(named) = bindings.get(name)
        {
            let mut candidates = named
                .range(context.range.start..context.range.end)
                .map(|(_, range)| *range)
                .filter(|candidate| {
                    candidate.source == context.source && candidate.range.end <= context.range.end
                });
            if let Some(binding) = candidates.next()
                && candidates.next().is_none()
            {
                range = Some(binding);
            }
        }
        if let LintMessage::UnusedLocal {
            name,
            mutable: false,
        } = &warning.message
            && let Some(binding) = range
            && source.slice(binding.range) == Some(name.as_str())
        {
            warning.recipe = Some(match warning.recipe.take() {
                // Shorthand `{ field }` names the field and the binding with one
                // token; `{ _ }` is not a pattern, so the discard is `field: _`.
                Some(LintFixRecipe::StructFieldDiscard { field, name }) if field == binding => {
                    LintFixRecipe::Replace {
                        range: field,
                        text: format!("{name}: _"),
                    }
                }
                _ => LintFixRecipe::Replace {
                    range: binding,
                    text: "_".to_owned(),
                },
            });
        } else if matches!(
            warning.recipe,
            Some(LintFixRecipe::StructFieldDiscard { .. })
        ) {
            warning.recipe = None;
        }
        warning.source = range.and_then(span_of);
        warning.labels = std::mem::take(&mut warning.related)
            .into_iter()
            .filter_map(|(range, message)| span_of(range).map(|span| LintLabel { span, message }))
            .collect();
        warning.fix = warning
            .recipe
            .take()
            .and_then(|recipe| materialize_lint_fix(source, recipe))
            .and_then(|(range, replacement)| {
                span_of(range).map(|span| LintFix { span, replacement })
            });
    }
    warnings
}
/// Turn a fix recipe into an exact replacement, failing closed when the
/// source does not have the expected shape.
fn materialize_lint_fix(
    source: &SourceFile,
    recipe: LintFixRecipe,
) -> Option<(SourceRange, String)> {
    match recipe {
        LintFixRecipe::Replace { range, text } => {
            source.slice(range.range)?;
            Some((range, text))
        }
        LintFixRecipe::WriteBack {
            after,
            map,
            key,
            binding,
        } => {
            let statement = source.slice(after.range)?;
            let key = match key {
                Some(key) => source.slice(key.range)?.to_owned(),
                None => String::new(),
            };
            let text = source.text();
            let line_start = text[..after.range.start as usize]
                .rfind('\n')
                .map_or(0, |index| index + 1);
            let indent = text[line_start..after.range.start as usize]
                .chars()
                .take_while(|character| matches!(character, ' ' | '\t'))
                .collect::<String>();
            let write = if key.is_empty() {
                format!("{map} = {binding};")
            } else {
                format!("{map}[{key}] = {binding};")
            };
            Some((after, format!("{statement}\n{indent}{write}")))
        }
        // Resolved against the binding range in `lint_with_sources`; an
        // unresolved recipe has no safe replacement.
        LintFixRecipe::StructFieldDiscard { .. } => None,
        LintFixRecipe::VarToLet { statement } => {
            let text = source.slice(statement.range)?;
            let leading = text.len() - text.trim_start().len();
            let rest = text[leading..].strip_prefix("var")?;
            if !rest.starts_with(char::is_whitespace) {
                return None;
            }
            let start = statement.range.start + u32::try_from(leading).ok()?;
            Some((
                SourceRange::new(statement.source, TextRange::new(start, start + 3)),
                "let".to_owned(),
            ))
        }
        LintFixRecipe::KotoageToView { declaration } => {
            let text = source.slice(declaration.range)?;
            let leading = text.len() - text.trim_start().len();
            let keyword = crate::glossary::by_spelling("kotoage")?
                .spellings()
                .into_iter()
                .find(|spelling| text[leading..].starts_with(spelling))?;
            let start = declaration.range.start + u32::try_from(leading).ok()?;
            let end = start + u32::try_from(keyword.len()).ok()?;
            Some((
                SourceRange::new(declaration.source, TextRange::new(start, end)),
                "view".to_owned(),
            ))
        }
    }
}
fn lint_category(code: &str) -> LintCategory {
    lint_by_slug(code).map_or(LintCategory::Correctness, |(_, _, category)| category)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LintMessage {
    UnusedState {
        name: String,
    },
    StateShadowed {
        func: String,
        name: String,
        context: StateShadowContext,
    },
    UnusedParameter {
        func: String,
        name: String,
    },
    UnreachableAfterReturn {
        context: String,
    },
    /// A local binding whose value is never read.
    UnusedLocal {
        name: String,
        /// Whether the binding was declared with `var`.
        mutable: bool,
    },
    /// A value copied out of durable state was changed but never stored back.
    UnpersistedStateCopy {
        binding: String,
        /// The state declaration the value was read from.
        origin: String,
    },
    /// A kotoage that performs no durable, ledger, or host effects.
    KotoageWithoutEffects {
        func: String,
        /// Keyword spelling used by the declaration (`kotoage` or `言挙げ`).
        keyword: String,
    },
    /// A public parameter whose ABI key starts with `_`.
    UnderscorePublicParameter {
        /// First public function, in declaration order, that declares it.
        func: String,
        /// The parameter name.
        name: String,
        /// Later public functions that declare a parameter with the same name.
        also: Vec<String>,
    },
    /// A `var` binding that is never reassigned or mutated.
    NeverMutatedVar {
        /// The binding name.
        name: String,
    },
    /// A private function that nothing in its source unit calls.
    UnusedPrivateFunction {
        /// The function name.
        func: String,
    },
    /// A seiyaku that declares no kotoage, view, or lifecycle function.
    SeiyakuWithoutEntrypoint {
        /// The seiyaku name.
        name: String,
        /// Keyword spelling used by the declaration (`seiyaku` or `誓約`).
        keyword: String,
    },
    Custom {
        message: String,
    },
}
impl LintMessage {
    fn translate(&self, lang: Language) -> String {
        match self {
            LintMessage::UnusedState { name } => i18n::translate(
                lang,
                I18nMessage::LintUnusedState {
                    name: name.as_str(),
                },
            ),
            LintMessage::StateShadowed {
                func,
                name,
                context,
            } => i18n::translate(
                lang,
                I18nMessage::LintStateShadowed {
                    func: func.as_str(),
                    name: name.as_str(),
                    context: *context,
                },
            ),
            LintMessage::UnusedParameter { func, name } => i18n::translate(
                lang,
                I18nMessage::LintUnusedParameter {
                    func: func.as_str(),
                    name: name.as_str(),
                },
            ),
            LintMessage::UnreachableAfterReturn { context } => i18n::translate(
                lang,
                I18nMessage::LintUnreachableAfterReturn {
                    context: context.as_str(),
                },
            ),
            LintMessage::UnusedLocal { name, .. } => {
                format!("local `{name}` is never read")
            }
            LintMessage::UnpersistedStateCopy { binding, origin } => format!(
                "`{binding}` is a copy of `{origin}` that is changed but never written back"
            ),
            LintMessage::KotoageWithoutEffects { func, keyword } => format!(
                "{keyword} `{func}` performs no state, ledger, or host effects; declare it `view fn`"
            ),
            LintMessage::UnderscorePublicParameter { func, name, also } => match also.len() {
                0 => format!(
                    "public parameter `{name}` of `{func}` becomes the ABI argument key `{name}`"
                ),
                others => format!(
                    "public parameter `{name}` of `{func}` and {others} other function{} becomes the ABI argument key `{name}`",
                    if others == 1 { "" } else { "s" }
                ),
            },
            LintMessage::NeverMutatedVar { name } => {
                format!("`{name}` is declared with `var` but never changed")
            }
            LintMessage::UnusedPrivateFunction { func } => {
                format!("private `fn {func}` is never called")
            }
            LintMessage::SeiyakuWithoutEntrypoint { name, keyword } => format!(
                "{keyword} `{name}` declares no kotoage, `view fn`, or lifecycle hook, so nothing can call it"
            ),
            LintMessage::Custom { message } => message.clone(),
        }
    }
}
/// Run the Kotodama lint suite against an AST [`Program`].
pub fn lint_program(program: &Program) -> Vec<LintWarning> {
    crate::session::run_with_compiler_stack(move || lint_program_inline(program))
        .expect("compiler must allocate the bounded stack required to lint source nesting")
}
fn lint_program_inline(program: &Program) -> Vec<LintWarning> {
    let mut warnings = Vec::new();
    lint_unused_state(program, &mut warnings);
    lint_state_shadowing(program, &mut warnings);
    lint_unused_parameters(program, &mut warnings);
    lint_unreachable_after_return(program, &mut warnings);
    lint_pointer_constructor_usage(program, &mut warnings);
    lint_nonliteral_trigger_specs(program, &mut warnings);
    lint_nonliteral_state_paths(program, &mut warnings);
    lint_opaque_access_hints(program, &mut warnings);
    let facts = ProgramFacts::new(program);
    let lost_writes = lint_unpersisted_state_copies(program, &facts, &mut warnings);
    lint_kotoage_without_effects(program, &facts, &lost_writes, &mut warnings);
    lint_exact_division(program, &facts, &mut warnings);
    lint_unused_locals_and_dead_stores(program, &facts, &mut warnings);
    lint_underscore_public_parameters(program, &mut warnings);
    lint_never_mutated_vars(program, &mut warnings);
    // Without an entrypoint every private function is unreachable; the
    // missing entrypoint is the one finding worth reporting.
    if !lint_seiyaku_without_entrypoint(program, &mut warnings) {
        lint_unused_private_functions(program, &facts, &mut warnings);
    }
    warnings
}
const OPAQUE_ACCESS_HINT_CALLS: &[&str] = &[
    Builtin::EscrowOpenOffer.source_name(),
    Builtin::EscrowAccept.source_name(),
    Builtin::EscrowMarkPaymentSent.source_name(),
    Builtin::EscrowRelease.source_name(),
    Builtin::EscrowCancel.source_name(),
    Builtin::EscrowOpenDispute.source_name(),
    Builtin::EscrowResolveDispute.source_name(),
    Builtin::SoracloudReadCommittedState.source_name(),
    Builtin::SoracloudEmitStateMutation.source_name(),
    Builtin::SoracloudEmitMailboxMessage.source_name(),
    Builtin::SoracloudAppendJournal.source_name(),
    Builtin::SoracloudPublishCheckpoint.source_name(),
    Builtin::SoracloudReadConfig.source_name(),
    Builtin::SoracloudReadSecretEnvelope.source_name(),
    Builtin::TransferDomain.source_name(),
    Builtin::RegisterPeer.source_name(),
    Builtin::UnregisterPeer.source_name(),
    Builtin::ScExecuteSubmitBallot.source_name(),
    Builtin::ResolveAccountAlias.source_name(),
    Builtin::AxtBegin.source_name(),
    Builtin::AxtTouch.source_name(),
    Builtin::StageAnchoredSpend.source_name(),
    Builtin::VerifyDsProof.source_name(),
    Builtin::AxtCommit.source_name(),
];
const EXECUTE_INSTRUCTION_CALL: &str = "execute_instruction";
const EXECUTE_QUERY_CALL: &str = "execute_query";
fn decode_hex_or_raw_bytes(raw: &str) -> Option<Vec<u8>> {
    if let Some(trimmed) = raw.strip_prefix("0x") {
        if trimmed.len() % 2 == 0 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut out = Vec::with_capacity(trimmed.len() / 2);
            for chunk in trimmed.as_bytes().chunks(2) {
                let byte_str = std::str::from_utf8(chunk).ok()?;
                let byte = u8::from_str_radix(byte_str, 16).ok()?;
                out.push(byte);
            }
            return Some(out);
        }
        return None;
    }
    Some(raw.as_bytes().to_vec())
}
fn decode_norito_bytes_literal(expr: &Expr) -> Option<Vec<u8>> {
    let raw = match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Expr::Bytes(value) => value.clone(),
        Expr::Call { name, args, .. } if name == "norito_bytes" && args.len() == 1 => {
            match args[0].kind() {
                Expr::Source { .. } | Expr::Resolved { .. } => {
                    unreachable!("kind() strips provenance wrappers")
                }
                Expr::String(value) => decode_hex_or_raw_bytes(value)?,
                Expr::Bytes(value) => value.clone(),
                _ => return None,
            }
        }
        _ => return None,
    };
    let payload = match pointer_abi::validate_tlv_bytes(&raw) {
        Ok(tlv) => {
            if tlv.type_id != PointerType::NoritoBytes {
                return None;
            }
            tlv.payload.to_vec()
        }
        Err(_) => raw,
    };
    Some(payload)
}
fn decode_instruction_box_literal(args: &[Expr]) -> Option<InstructionBox> {
    let payload = decode_norito_bytes_literal(args.first()?)?;
    norito::decode_canonical(&payload).ok()
}
fn decode_query_request_literal(args: &[Expr]) -> Option<QueryRequest> {
    let payload = decode_norito_bytes_literal(args.first()?)?;
    norito::decode_canonical(&payload).ok()
}
fn instruction_box_is_hintable(instr: &InstructionBox) -> bool {
    let any = instr.as_any();
    if any.downcast_ref::<Log>().is_some() {
        return true;
    }
    if any.downcast_ref::<TransferBox>().is_some() {
        return true;
    }
    if any.downcast_ref::<MintBox>().is_some() {
        return true;
    }
    if any.downcast_ref::<BurnBox>().is_some() {
        return true;
    }
    if any.downcast_ref::<SetKeyValueBox>().is_some() {
        return true;
    }
    if any.downcast_ref::<RemoveKeyValueBox>().is_some() {
        return true;
    }
    if let Some(rb) = any.downcast_ref::<RegisterBox>() {
        return !matches!(rb, RegisterBox::Peer(_));
    }
    if let Some(ub) = any.downcast_ref::<UnregisterBox>() {
        return !matches!(ub, UnregisterBox::Peer(_));
    }
    if any.downcast_ref::<GrantBox>().is_some() {
        return true;
    }
    if any.downcast_ref::<RevokeBox>().is_some() {
        return true;
    }
    if any.downcast_ref::<ExecuteTrigger>().is_some() {
        return true;
    }
    {
        use iroha_data_model::isi::escrow as DMEscrow;
        if any.downcast_ref::<DMEscrow::OpenAssetEscrow>().is_some()
            || any.downcast_ref::<DMEscrow::AcceptAssetEscrow>().is_some()
            || any
                .downcast_ref::<DMEscrow::MarkEscrowPaymentSent>()
                .is_some()
            || any.downcast_ref::<DMEscrow::ReleaseAssetEscrow>().is_some()
            || any.downcast_ref::<DMEscrow::CancelAssetEscrow>().is_some()
            || any.downcast_ref::<DMEscrow::OpenEscrowDispute>().is_some()
            || any
                .downcast_ref::<DMEscrow::ResolveEscrowDispute>()
                .is_some()
        {
            return true;
        }
    }
    false
}
fn query_request_is_hintable(request: &QueryRequest) -> bool {
    match request {
        QueryRequest::Singular(query) => matches!(query, SingularQueryBox::FindAssetById(_)),
        QueryRequest::Start(_) | QueryRequest::Continue(_) => false,
    }
}
fn is_literal_name_expr(expr: &Expr) -> bool {
    matches!(
        expr.kind(),
        Expr::Call { name, args, .. }
            if name == Builtin::PointerConstructor(PointerConstructor::Name).source_name()
                && args.len() == 1
                && args.first().is_some_and(|argument| matches!(argument.kind(), Expr::String(_)))
    )
}
fn escrow_call_is_hintable(name: &str, args: &[Expr]) -> Option<bool> {
    if [
        Builtin::EscrowOpenOffer,
        Builtin::EscrowAccept,
        Builtin::EscrowMarkPaymentSent,
        Builtin::EscrowRelease,
        Builtin::EscrowCancel,
        Builtin::EscrowOpenDispute,
        Builtin::EscrowResolveDispute,
    ]
    .into_iter()
    .any(|builtin| builtin.source_name() == name)
    {
        Some(args.first().is_some_and(is_literal_name_expr))
    } else {
        None
    }
}
fn is_literal_domain_expr(expr: &Expr) -> bool {
    let Expr::Call { name, args, .. } = expr.kind() else {
        return false;
    };
    name == Builtin::PointerConstructor(PointerConstructor::DomainId).source_name()
        && args.len() == 1
        && args.first().is_some_and(|argument| {
            matches!(argument.kind(), Expr::String(raw)
                if iroha_model_base::domain::DomainId::parse_fully_qualified(raw).is_ok())
        })
}
fn is_account_access_hint_expr(expr: &Expr) -> bool {
    let Expr::Call { name, args, .. } = expr.kind() else {
        return false;
    };
    if name == Builtin::Authority.source_name() && args.is_empty() {
        return true;
    }
    name == Builtin::PointerConstructor(PointerConstructor::AccountId).source_name()
        && args.len() == 1
        && args.first().is_some_and(|argument| {
            matches!(argument.kind(), Expr::String(raw)
                if iroha_data_model::account::AccountId::parse_encoded(raw).is_ok())
        })
}
fn transfer_domain_call_is_hintable(args: &[Expr]) -> bool {
    args.len() == 3 && is_literal_domain_expr(&args[1]) && is_account_access_hint_expr(&args[2])
}
fn lint_nonliteral_state_paths(program: &Program, warnings: &mut Vec<LintWarning>) {
    for item in &program.items {
        if let Item::Function(func) = item {
            lint_state_path_block(&func.body, warnings);
        }
    }
}
fn lint_state_path_block(block: &Block, warnings: &mut Vec<LintWarning>) {
    for stmt in &block.statements {
        lint_state_path_stmt(stmt, warnings);
    }
    if let Some(tail) = &block.tail {
        lint_state_path_expr(tail, warnings);
    }
}
fn lint_state_path_stmt(stmt: &Statement, warnings: &mut Vec<LintWarning>) {
    match stmt.kind() {
        Statement::Source { .. } | Statement::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Statement::Let { value, .. } => lint_state_path_expr(value, warnings),
        Statement::Assign { value, .. } => lint_state_path_expr(value, warnings),
        Statement::AssignExpr { target, value, .. } => {
            lint_state_path_expr(target, warnings);
            lint_state_path_expr(value, warnings);
        }
        Statement::Expr(expr) | Statement::Emit(expr) => lint_state_path_expr(expr, warnings),
        Statement::Return(Some(expr)) => lint_state_path_expr(expr, warnings),
        Statement::Return(None) | Statement::Break | Statement::Continue => {}
        Statement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            lint_state_path_expr(cond, warnings);
            lint_state_path_block(then_branch, warnings);
            if let Some(b) = else_branch {
                lint_state_path_block(b, warnings);
            }
        }
        Statement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            lint_state_path_expr(value, warnings);
            lint_state_path_block(then_branch, warnings);
            if let Some(block) = else_branch {
                lint_state_path_block(block, warnings);
            }
        }
        Statement::While { cond, body } => {
            lint_state_path_expr(cond, warnings);
            lint_state_path_block(body, warnings);
        }
        Statement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init_stmt) = init {
                lint_state_path_stmt(init_stmt, warnings);
            }
            if let Some(cond_expr) = cond {
                lint_state_path_expr(cond_expr, warnings);
            }
            if let Some(step_stmt) = step {
                lint_state_path_stmt(step_stmt, warnings);
            }
            lint_state_path_block(body, warnings);
        }
        Statement::ForEachMap { map, body, .. } => {
            lint_state_path_expr(map, warnings);
            lint_state_path_block(body, warnings);
        }
    }
}
fn lint_state_path_expr(expr: &Expr, warnings: &mut Vec<LintWarning>) {
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Expr::Call { name, args, .. } => {
            if matches!(
                Builtin::from_source_name(name),
                Some(Builtin::StateGet | Builtin::StateSet | Builtin::StateDel)
            ) && let Some(path) = args.first()
                && !is_literal_state_path(path)
            {
                warnings.push(LintWarning::new(
                    "nonliteral-state-path",
                    LintMessage::Custom {
                        message: format!(
                            "{name} uses a non-literal path; production compilation requires compiler-derived bounded state access"
                        ),
                    },
                ).at_source(expr.source()));
            }
            for arg in args {
                lint_state_path_expr(arg, warnings);
            }
        }
        Expr::Binary { left, right, .. } => {
            lint_state_path_expr(left, warnings);
            lint_state_path_expr(right, warnings);
        }
        Expr::Unary { expr, .. }
        | Expr::OptionSome(expr)
        | Expr::ResultOk(expr)
        | Expr::ResultErr(expr)
        | Expr::Propagate(expr) => lint_state_path_expr(expr, warnings),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            lint_state_path_expr(cond, warnings);
            lint_state_path_expr(then_expr, warnings);
            lint_state_path_expr(else_expr, warnings);
        }
        Expr::If {
            condition,
            then_branch,
            else_branch,
        } => {
            lint_state_path_expr(condition, warnings);
            lint_state_path_block(then_branch, warnings);
            if let Some(block) = else_branch {
                lint_state_path_block(block, warnings);
            }
        }
        Expr::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            lint_state_path_expr(value, warnings);
            lint_state_path_block(then_branch, warnings);
            if let Some(block) = else_branch {
                lint_state_path_block(block, warnings);
            }
        }
        Expr::Match { value, arms } => {
            lint_state_path_expr(value, warnings);
            for arm in arms {
                lint_state_path_block(&arm.body, warnings);
            }
        }
        Expr::Tuple(items) | Expr::List(items) => {
            for item in items {
                lint_state_path_expr(item, warnings);
            }
        }
        Expr::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            lint_state_path_expr(source, warnings);
            lint_state_path_expr(expression, warnings);
            if let Some(condition) = condition {
                lint_state_path_expr(condition, warnings);
            }
        }
        Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => {
            for field in fields {
                lint_state_path_expr(&field.value, warnings);
            }
        }
        Expr::JsonObject(entries) => {
            for entry in entries {
                lint_state_path_expr(&entry.value, warnings);
            }
        }
        Expr::JsonArray(items) => {
            for item in items {
                lint_state_path_expr(item, warnings);
            }
        }
        Expr::Member { object, .. } => lint_state_path_expr(object, warnings),
        Expr::Index { target, index } => {
            lint_state_path_expr(target, warnings);
            lint_state_path_expr(index, warnings);
        }
        Expr::IntLiteral(_)
        | Expr::DecimalLiteral(_)
        | Expr::OptionNone
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::Bytes(_)
        | Expr::Ident(_) => {}
    }
}
fn lint_opaque_access_hints(program: &Program, warnings: &mut Vec<LintWarning>) {
    for item in &program.items {
        if let Item::Function(func) = item {
            lint_opaque_access_block(&func.body, warnings);
        }
    }
}
fn lint_opaque_access_block(block: &Block, warnings: &mut Vec<LintWarning>) {
    for stmt in &block.statements {
        lint_opaque_access_stmt(stmt, warnings);
    }
    if let Some(tail) = &block.tail {
        lint_opaque_access_expr(tail, warnings);
    }
}
fn lint_opaque_access_stmt(stmt: &Statement, warnings: &mut Vec<LintWarning>) {
    match stmt.kind() {
        Statement::Source { .. } | Statement::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Statement::Let { value, .. } => lint_opaque_access_expr(value, warnings),
        Statement::Assign { value, .. } => lint_opaque_access_expr(value, warnings),
        Statement::AssignExpr { target, value, .. } => {
            lint_opaque_access_expr(target, warnings);
            lint_opaque_access_expr(value, warnings);
        }
        Statement::Expr(expr) | Statement::Emit(expr) => lint_opaque_access_expr(expr, warnings),
        Statement::Return(Some(expr)) => lint_opaque_access_expr(expr, warnings),
        Statement::Return(None) | Statement::Break | Statement::Continue => {}
        Statement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            lint_opaque_access_expr(cond, warnings);
            lint_opaque_access_block(then_branch, warnings);
            if let Some(b) = else_branch {
                lint_opaque_access_block(b, warnings);
            }
        }
        Statement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            lint_opaque_access_expr(value, warnings);
            lint_opaque_access_block(then_branch, warnings);
            if let Some(block) = else_branch {
                lint_opaque_access_block(block, warnings);
            }
        }
        Statement::While { cond, body } => {
            lint_opaque_access_expr(cond, warnings);
            lint_opaque_access_block(body, warnings);
        }
        Statement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init_stmt) = init {
                lint_opaque_access_stmt(init_stmt, warnings);
            }
            if let Some(cond_expr) = cond {
                lint_opaque_access_expr(cond_expr, warnings);
            }
            if let Some(step_stmt) = step {
                lint_opaque_access_stmt(step_stmt, warnings);
            }
            lint_opaque_access_block(body, warnings);
        }
        Statement::ForEachMap { map, body, .. } => {
            lint_opaque_access_expr(map, warnings);
            lint_opaque_access_block(body, warnings);
        }
    }
}
fn lint_opaque_access_expr(expr: &Expr, warnings: &mut Vec<LintWarning>) {
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Expr::Call { name, args, .. } => {
            let warn = if name == EXECUTE_INSTRUCTION_CALL {
                !decode_instruction_box_literal(args)
                    .map(|isi| instruction_box_is_hintable(&isi))
                    .unwrap_or(false)
            } else if name == EXECUTE_QUERY_CALL {
                !decode_query_request_literal(args)
                    .map(|query| query_request_is_hintable(&query))
                    .unwrap_or(false)
            } else if name == Builtin::TransferDomain.source_name() {
                !transfer_domain_call_is_hintable(args)
            } else if let Some(hintable) = escrow_call_is_hintable(name, args) {
                !hintable
            } else {
                OPAQUE_ACCESS_HINT_CALLS.contains(&name.as_str())
            };
            if warn {
                warnings.push(LintWarning::new(
                    "opaque-access-hints",
                    LintMessage::Custom {
                        message: format!(
                            "call to `{name}` uses host access the compiler cannot describe precisely, so transactions calling it are scheduled conservatively"
                        ),
                    },
                ).at_source(expr.source()));
            }
            for arg in args {
                lint_opaque_access_expr(arg, warnings);
            }
        }
        Expr::Binary { left, right, .. } => {
            lint_opaque_access_expr(left, warnings);
            lint_opaque_access_expr(right, warnings);
        }
        Expr::Unary { expr, .. }
        | Expr::OptionSome(expr)
        | Expr::ResultOk(expr)
        | Expr::ResultErr(expr)
        | Expr::Propagate(expr) => lint_opaque_access_expr(expr, warnings),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            lint_opaque_access_expr(cond, warnings);
            lint_opaque_access_expr(then_expr, warnings);
            lint_opaque_access_expr(else_expr, warnings);
        }
        Expr::If {
            condition,
            then_branch,
            else_branch,
        } => {
            lint_opaque_access_expr(condition, warnings);
            lint_opaque_access_block(then_branch, warnings);
            if let Some(block) = else_branch {
                lint_opaque_access_block(block, warnings);
            }
        }
        Expr::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            lint_opaque_access_expr(value, warnings);
            lint_opaque_access_block(then_branch, warnings);
            if let Some(block) = else_branch {
                lint_opaque_access_block(block, warnings);
            }
        }
        Expr::Match { value, arms } => {
            lint_opaque_access_expr(value, warnings);
            for arm in arms {
                lint_opaque_access_block(&arm.body, warnings);
            }
        }
        Expr::Tuple(items) | Expr::List(items) => {
            for item in items {
                lint_opaque_access_expr(item, warnings);
            }
        }
        Expr::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            lint_opaque_access_expr(source, warnings);
            lint_opaque_access_expr(expression, warnings);
            if let Some(condition) = condition {
                lint_opaque_access_expr(condition, warnings);
            }
        }
        Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => {
            for field in fields {
                lint_opaque_access_expr(&field.value, warnings);
            }
        }
        Expr::JsonObject(entries) => {
            for entry in entries {
                lint_opaque_access_expr(&entry.value, warnings);
            }
        }
        Expr::JsonArray(items) => {
            for item in items {
                lint_opaque_access_expr(item, warnings);
            }
        }
        Expr::Member { object, .. } => lint_opaque_access_expr(object, warnings),
        Expr::Index { target, index } => {
            lint_opaque_access_expr(target, warnings);
            lint_opaque_access_expr(index, warnings);
        }
        Expr::IntLiteral(_)
        | Expr::DecimalLiteral(_)
        | Expr::OptionNone
        | Expr::Bool(_)
        | Expr::String(_)
        | Expr::Bytes(_)
        | Expr::Ident(_) => {}
    }
}
fn is_literal_state_key(expr: &Expr) -> bool {
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Expr::IntLiteral(_) | Expr::DecimalLiteral(_) | Expr::String(_) | Expr::Bytes(_) => true,
        Expr::Call { name, args, .. } => {
            let literal_arg = args.first().is_some_and(|argument| {
                matches!(argument.kind(), Expr::String(_) | Expr::Bytes(_))
            });
            if !literal_arg || args.len() != 1 {
                return false;
            }
            name == "account"
                || matches!(
                    Builtin::from_source_name(name),
                    Some(Builtin::PointerConstructor(
                        PointerConstructor::AccountId
                            | PointerConstructor::AssetDefinition
                            | PointerConstructor::AssetId
                            | PointerConstructor::NftId
                            | PointerConstructor::Domain
                            | PointerConstructor::DomainId
                            | PointerConstructor::Name
                            | PointerConstructor::Json
                            | PointerConstructor::Blob
                            | PointerConstructor::NoritoBytes
                            | PointerConstructor::DataSpaceId
                            | PointerConstructor::AxtDescriptor
                            | PointerConstructor::ProofBlob
                    ))
                )
        }
        _ => false,
    }
}
fn is_literal_state_base_name(expr: &Expr) -> bool {
    let Expr::Call { name, args, .. } = expr.kind() else {
        return false;
    };
    matches!(
        Builtin::from_source_name(name),
        Some(Builtin::PointerConstructor(PointerConstructor::Name))
    ) && args.len() == 1
        && args
            .first()
            .is_some_and(|argument| matches!(argument.kind(), Expr::String(_) | Expr::Bytes(_)))
}
fn is_literal_state_path(expr: &Expr) -> bool {
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Expr::Call {
            name,
            args,
            implicit_receiver,
            ..
        } => match if *implicit_receiver {
            Builtin::from_name(name).filter(|builtin| {
                matches!(
                    builtin.surface(),
                    BuiltinSurface::MethodOnly | BuiltinSurface::FunctionOrMethod
                )
            })
        } else {
            Builtin::from_source_name(name)
        } {
            Some(Builtin::PointerConstructor(PointerConstructor::NoritoBytes)) => {
                args.len() == 1
                    && args.first().is_some_and(|argument| {
                        matches!(argument.kind(), Expr::String(_) | Expr::Bytes(_))
                    })
            }
            Some(Builtin::Path) => {
                if args.len() != 2 {
                    return false;
                }
                is_literal_state_base_name(&args[0])
                    && (matches!(args[1].kind(), Expr::IntLiteral(_))
                        || is_literal_state_key(&args[1]))
            }
            _ => false,
        },
        _ => false,
    }
}
fn lint_unused_state(program: &Program, warnings: &mut Vec<LintWarning>) {
    let state_names: Vec<String> = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::State(state) => Some(state.name.clone()),
            _ => None,
        })
        .collect();
    if state_names.is_empty() {
        return;
    }
    let state_lookup: HashSet<String> = state_names.iter().cloned().collect();
    let mut used: HashSet<String> = HashSet::new();
    let mut stmt_stack: Vec<&Statement> = Vec::new();
    for item in &program.items {
        if let Item::Function(func) = item {
            if let Some(tail) = &func.body.tail {
                record_expr_idents(tail, &state_lookup, &mut used);
            }
            for stmt in func.body.statements.iter().rev() {
                stmt_stack.push(stmt);
            }
        }
    }
    while let Some(stmt) = stmt_stack.pop() {
        match stmt.kind() {
            Statement::Source { .. } | Statement::Resolved { .. } => {
                unreachable!("kind() strips provenance wrappers")
            }
            Statement::Let { value, .. } => {
                record_expr_idents(value, &state_lookup, &mut used);
            }
            Statement::Assign { name, value } => {
                if state_lookup.contains(name) {
                    used.insert(name.clone());
                }
                record_expr_idents(value, &state_lookup, &mut used);
            }
            Statement::AssignExpr { target, value, .. } => {
                record_expr_idents(target, &state_lookup, &mut used);
                record_expr_idents(value, &state_lookup, &mut used);
            }
            Statement::Expr(expr) | Statement::Emit(expr) => {
                record_expr_idents(expr, &state_lookup, &mut used);
            }
            Statement::Return(Some(expr)) => {
                record_expr_idents(expr, &state_lookup, &mut used);
            }
            Statement::Return(None) | Statement::Break | Statement::Continue => {}
            Statement::If {
                cond,
                then_branch,
                else_branch,
            } => {
                record_expr_idents(cond, &state_lookup, &mut used);
                for stmt in then_branch.statements.iter().rev() {
                    stmt_stack.push(stmt);
                }
                if let Some(else_block) = else_branch {
                    if let Some(tail) = &else_block.tail {
                        record_expr_idents(tail, &state_lookup, &mut used);
                    }
                    for stmt in else_block.statements.iter().rev() {
                        stmt_stack.push(stmt);
                    }
                }
                if let Some(tail) = &then_branch.tail {
                    record_expr_idents(tail, &state_lookup, &mut used);
                }
            }
            Statement::IfLet {
                value,
                then_branch,
                else_branch,
                ..
            } => {
                record_expr_idents(value, &state_lookup, &mut used);
                if let Some(tail) = &then_branch.tail {
                    record_expr_idents(tail, &state_lookup, &mut used);
                }
                for stmt in then_branch.statements.iter().rev() {
                    stmt_stack.push(stmt);
                }
                if let Some(else_block) = else_branch {
                    if let Some(tail) = &else_block.tail {
                        record_expr_idents(tail, &state_lookup, &mut used);
                    }
                    for stmt in else_block.statements.iter().rev() {
                        stmt_stack.push(stmt);
                    }
                }
            }
            Statement::While { cond, body } => {
                record_expr_idents(cond, &state_lookup, &mut used);
                if let Some(tail) = &body.tail {
                    record_expr_idents(tail, &state_lookup, &mut used);
                }
                for stmt in body.statements.iter().rev() {
                    stmt_stack.push(stmt);
                }
            }
            Statement::For {
                line: _,
                init,
                cond,
                step,
                body,
            } => {
                if let Some(init_stmt) = init {
                    stmt_stack.push(&**init_stmt);
                }
                if let Some(cond_expr) = cond {
                    record_expr_idents(cond_expr, &state_lookup, &mut used);
                }
                if let Some(step_stmt) = step {
                    stmt_stack.push(&**step_stmt);
                }
                if let Some(tail) = &body.tail {
                    record_expr_idents(tail, &state_lookup, &mut used);
                }
                for stmt in body.statements.iter().rev() {
                    stmt_stack.push(stmt);
                }
            }
            Statement::ForEachMap { map, body, .. } => {
                record_expr_idents(map, &state_lookup, &mut used);
                if let Some(tail) = &body.tail {
                    record_expr_idents(tail, &state_lookup, &mut used);
                }
                for stmt in body.statements.iter().rev() {
                    stmt_stack.push(stmt);
                }
            }
        }
    }
    for name in state_names {
        if !used.contains(&name) {
            warnings.push(LintWarning::new(
                "unused-state",
                LintMessage::UnusedState { name },
            ));
        }
    }
}
/// States unused across every native file assembled into one source unit.
pub(crate) fn unused_state_names(program: &Program) -> HashSet<String> {
    let mut warnings = Vec::new();
    lint_unused_state(program, &mut warnings);
    warnings
        .into_iter()
        .filter_map(|warning| match warning.message {
            LintMessage::UnusedState { name } => Some(name),
            _ => None,
        })
        .collect()
}
fn lint_state_shadowing(program: &Program, warnings: &mut Vec<LintWarning>) {
    let state_names: HashSet<String> = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::State(state) => Some(state.name.clone()),
            _ => None,
        })
        .collect();
    if state_names.is_empty() {
        return;
    }
    for item in &program.items {
        if let Item::Function(func) = item {
            for param in &func.params {
                let name = &param.name;
                if state_names.contains(name) && !name.starts_with('_') {
                    warnings.push(LintWarning::new(
                        "state-shadowed",
                        LintMessage::StateShadowed {
                            func: func.name.clone(),
                            name: name.clone(),
                            context: StateShadowContext::Parameter,
                        },
                    ));
                }
            }
            lint_statement_shadowing_block(&func.body, &state_names, warnings, &func.name);
        }
    }
}
fn lint_statement_shadowing_block(
    block: &Block,
    state_names: &HashSet<String>,
    warnings: &mut Vec<LintWarning>,
    func_name: &str,
) {
    for stmt in &block.statements {
        lint_statement_state_shadowing(stmt, state_names, warnings, func_name);
    }
}
fn lint_statement_state_shadowing(
    stmt: &Statement,
    state_names: &HashSet<String>,
    warnings: &mut Vec<LintWarning>,
    func_name: &str,
) {
    match stmt.kind() {
        Statement::Source { .. } | Statement::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Statement::Let { pat, .. } => {
            let mut bound_names = Vec::new();
            collect_pattern_names(pat, &mut bound_names);
            for name in bound_names {
                if state_names.contains(name) && !name.starts_with('_') {
                    warnings.push(
                        LintWarning::new(
                            "state-shadowed",
                            LintMessage::StateShadowed {
                                func: func_name.to_owned(),
                                name: name.to_owned(),
                                context: StateShadowContext::Binding,
                            },
                        )
                        .at_source(stmt.source()),
                    );
                }
            }
        }
        Statement::Assign { .. }
        | Statement::AssignExpr { .. }
        | Statement::Expr(_)
        | Statement::Emit(_)
        | Statement::Return(_)
        | Statement::Break
        | Statement::Continue => {}
        Statement::If {
            then_branch,
            else_branch,
            ..
        } => {
            lint_statement_shadowing_block(then_branch, state_names, warnings, func_name);
            if let Some(else_block) = else_branch {
                lint_statement_shadowing_block(else_block, state_names, warnings, func_name);
            }
        }
        Statement::IfLet {
            pattern,
            then_branch,
            else_branch,
            ..
        } => {
            if let Some(PatternBinding::Name(name)) = &pattern.binding
                && state_names.contains(name)
                && !name.starts_with('_')
            {
                warnings.push(
                    LintWarning::new(
                        "state-shadowed",
                        LintMessage::StateShadowed {
                            func: func_name.to_owned(),
                            name: name.clone(),
                            context: StateShadowContext::Binding,
                        },
                    )
                    .at_source(stmt.source()),
                );
            }
            lint_statement_shadowing_block(then_branch, state_names, warnings, func_name);
            if let Some(else_block) = else_branch {
                lint_statement_shadowing_block(else_block, state_names, warnings, func_name);
            }
        }
        Statement::While { body, .. } => {
            lint_statement_shadowing_block(body, state_names, warnings, func_name);
        }
        Statement::For {
            init, step, body, ..
        } => {
            if let Some(init_stmt) = init.as_deref() {
                lint_statement_state_shadowing(init_stmt, state_names, warnings, func_name);
            }
            if let Some(step_stmt) = step.as_deref() {
                lint_statement_state_shadowing(step_stmt, state_names, warnings, func_name);
            }
            lint_statement_shadowing_block(body, state_names, warnings, func_name);
        }
        Statement::ForEachMap { pat, body, .. } => {
            let mut names = Vec::new();
            collect_pattern_names(pat, &mut names);
            for name in names {
                if state_names.contains(name) && !name.starts_with('_') {
                    warnings.push(
                        LintWarning::new(
                            "state-shadowed",
                            LintMessage::StateShadowed {
                                func: func_name.to_owned(),
                                name: name.to_owned(),
                                context: StateShadowContext::MapBinding,
                            },
                        )
                        .at_source(stmt.source()),
                    );
                }
            }
            lint_statement_shadowing_block(body, state_names, warnings, func_name);
        }
    }
}
/// Report unused parameters of private functions.
///
/// Parameters of kotoage, view, and lifecycle declarations are argument keys of
/// the public interface: callers send them whether or not the body reads them,
/// so they are never reported (see `underscore-public-parameter`).
fn lint_unused_parameters(program: &Program, warnings: &mut Vec<LintWarning>) {
    for item in &program.items {
        if let Item::Function(func) = item
            && func.modifiers.kind == crate::ast::FunctionKind::Private
        {
            let param_names: Vec<String> = func
                .params
                .iter()
                .map(|param| param.name.clone())
                .filter(|name| !name.starts_with('_'))
                .collect();
            if param_names.is_empty() {
                continue;
            }
            let lookup: HashSet<String> = param_names.iter().cloned().collect();
            let mut used: HashSet<String> = HashSet::new();
            let mut stmt_stack: Vec<&Statement> = Vec::new();
            if let Some(tail) = &func.body.tail {
                record_expr_idents(tail, &lookup, &mut used);
            }
            for stmt in func.body.statements.iter().rev() {
                stmt_stack.push(stmt);
            }
            while let Some(stmt) = stmt_stack.pop() {
                match stmt.kind() {
                    Statement::Source { .. } | Statement::Resolved { .. } => {
                        unreachable!("kind() strips provenance wrappers")
                    }
                    Statement::Let { value, .. } => {
                        record_expr_idents(value, &lookup, &mut used);
                    }
                    Statement::Assign { name, value } => {
                        if lookup.contains(name) {
                            used.insert(name.clone());
                        }
                        record_expr_idents(value, &lookup, &mut used);
                    }
                    Statement::AssignExpr { target, value, .. } => {
                        record_expr_idents(target, &lookup, &mut used);
                        record_expr_idents(value, &lookup, &mut used);
                    }
                    Statement::Expr(expr) | Statement::Emit(expr) => {
                        record_expr_idents(expr, &lookup, &mut used);
                    }
                    Statement::Return(Some(expr)) => {
                        record_expr_idents(expr, &lookup, &mut used);
                    }
                    Statement::Return(None) | Statement::Break | Statement::Continue => {}
                    Statement::If {
                        cond,
                        then_branch,
                        else_branch,
                    } => {
                        record_expr_idents(cond, &lookup, &mut used);
                        for stmt in then_branch.statements.iter().rev() {
                            stmt_stack.push(stmt);
                        }
                        if let Some(else_block) = else_branch {
                            if let Some(tail) = &else_block.tail {
                                record_expr_idents(tail, &lookup, &mut used);
                            }
                            for stmt in else_block.statements.iter().rev() {
                                stmt_stack.push(stmt);
                            }
                        }
                        if let Some(tail) = &then_branch.tail {
                            record_expr_idents(tail, &lookup, &mut used);
                        }
                    }
                    Statement::IfLet {
                        value,
                        then_branch,
                        else_branch,
                        ..
                    } => {
                        record_expr_idents(value, &lookup, &mut used);
                        if let Some(tail) = &then_branch.tail {
                            record_expr_idents(tail, &lookup, &mut used);
                        }
                        for stmt in then_branch.statements.iter().rev() {
                            stmt_stack.push(stmt);
                        }
                        if let Some(else_block) = else_branch {
                            if let Some(tail) = &else_block.tail {
                                record_expr_idents(tail, &lookup, &mut used);
                            }
                            for stmt in else_block.statements.iter().rev() {
                                stmt_stack.push(stmt);
                            }
                        }
                    }
                    Statement::While { cond, body } => {
                        record_expr_idents(cond, &lookup, &mut used);
                        if let Some(tail) = &body.tail {
                            record_expr_idents(tail, &lookup, &mut used);
                        }
                        for stmt in body.statements.iter().rev() {
                            stmt_stack.push(stmt);
                        }
                    }
                    Statement::For {
                        init,
                        cond,
                        step,
                        body,
                        ..
                    } => {
                        if let Some(init_stmt) = init {
                            stmt_stack.push(&**init_stmt);
                        }
                        if let Some(cond_expr) = cond {
                            record_expr_idents(cond_expr, &lookup, &mut used);
                        }
                        if let Some(step_stmt) = step {
                            stmt_stack.push(&**step_stmt);
                        }
                        if let Some(tail) = &body.tail {
                            record_expr_idents(tail, &lookup, &mut used);
                        }
                        for stmt in body.statements.iter().rev() {
                            stmt_stack.push(stmt);
                        }
                    }
                    Statement::ForEachMap { map, body, .. } => {
                        record_expr_idents(map, &lookup, &mut used);
                        if let Some(tail) = &body.tail {
                            record_expr_idents(tail, &lookup, &mut used);
                        }
                        for stmt in body.statements.iter().rev() {
                            stmt_stack.push(stmt);
                        }
                    }
                }
            }
            for name in param_names {
                if !used.contains(&name) {
                    warnings.push(LintWarning::new(
                        "unused-parameter",
                        LintMessage::UnusedParameter {
                            func: func.name.clone(),
                            name,
                        },
                    ));
                }
            }
        }
    }
}
fn lint_unreachable_after_return(program: &Program, warnings: &mut Vec<LintWarning>) {
    for item in &program.items {
        if let Item::Function(func) = item {
            let mut stack: Vec<(&Block, String)> =
                vec![(&func.body, format!("function `{}`", func.name))];
            while let Some((block, context)) = stack.pop() {
                let mut saw_return = false;
                for stmt in &block.statements {
                    if saw_return {
                        warnings.push(
                            LintWarning::new(
                                "unreachable-return",
                                LintMessage::UnreachableAfterReturn {
                                    context: context.clone(),
                                },
                            )
                            .at_source(stmt.source()),
                        );
                        break;
                    }
                    match stmt.kind() {
                        Statement::Source { .. } | Statement::Resolved { .. } => {
                            unreachable!("kind() strips provenance wrappers")
                        }
                        Statement::Return(_) => {
                            saw_return = true;
                        }
                        Statement::If {
                            then_branch,
                            else_branch,
                            ..
                        } => {
                            stack.push((then_branch, format!("{context} then-branch")));
                            if let Some(else_block) = else_branch {
                                stack.push((else_block, format!("{context} else-branch")));
                            }
                        }
                        Statement::IfLet {
                            then_branch,
                            else_branch,
                            ..
                        } => {
                            stack.push((then_branch, format!("{context} if-let branch")));
                            if let Some(else_block) = else_branch {
                                stack.push((else_block, format!("{context} else-branch")));
                            }
                        }
                        Statement::While { body, .. } => {
                            stack.push((body, format!("{context} while-body")));
                        }
                        Statement::For { body, .. } => {
                            stack.push((body, format!("{context} for-body")));
                        }
                        Statement::ForEachMap { body, .. } => {
                            stack.push((body, format!("{context} foreach-body")));
                        }
                        Statement::Let { .. }
                        | Statement::Assign { .. }
                        | Statement::AssignExpr { .. }
                        | Statement::Expr(_)
                        | Statement::Emit(_)
                        | Statement::Break
                        | Statement::Continue => {}
                    }
                }
            }
        }
    }
}
fn collect_pattern_names<'a>(pattern: &'a Pattern, out: &mut Vec<&'a str>) {
    match pattern {
        Pattern::Name(name) => out.push(name.as_str()),
        Pattern::Struct { fields, .. } => {
            out.extend(fields.iter().map(|field| field.binding.as_str()));
        }
        Pattern::Tuple(names) => {
            for name in names {
                out.push(name.as_str());
            }
        }
    }
}
fn record_expr_idents(expr: &Expr, state_lookup: &HashSet<String>, hits: &mut HashSet<String>) {
    let mut stack = vec![expr];
    while let Some(e) = stack.pop() {
        match e.kind() {
            Expr::Source { .. } | Expr::Resolved { .. } => {
                unreachable!("kind() strips provenance wrappers")
            }
            Expr::Ident(name) => {
                if state_lookup.contains(name) {
                    hits.insert(name.clone());
                }
            }
            Expr::Binary { left, right, .. } => {
                stack.push(left);
                stack.push(right);
            }
            Expr::Unary { expr, .. }
            | Expr::OptionSome(expr)
            | Expr::ResultOk(expr)
            | Expr::ResultErr(expr)
            | Expr::Propagate(expr) => {
                stack.push(expr);
            }
            Expr::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                stack.push(cond);
                stack.push(then_expr);
                stack.push(else_expr);
            }
            Expr::If {
                condition,
                then_branch,
                else_branch,
            } => {
                stack.push(condition);
                record_block_idents(then_branch, state_lookup, hits);
                if let Some(block) = else_branch {
                    record_block_idents(block, state_lookup, hits);
                }
            }
            Expr::IfLet {
                value,
                then_branch,
                else_branch,
                ..
            } => {
                stack.push(value);
                record_block_idents(then_branch, state_lookup, hits);
                if let Some(block) = else_branch {
                    record_block_idents(block, state_lookup, hits);
                }
            }
            Expr::Match { value, arms } => {
                stack.push(value);
                for arm in arms {
                    record_block_idents(&arm.body, state_lookup, hits);
                }
            }
            Expr::Call { args, .. } => {
                for arg in args {
                    stack.push(arg);
                }
            }
            Expr::Tuple(values) | Expr::List(values) => {
                for elem in values {
                    stack.push(elem);
                }
            }
            Expr::ListComprehension {
                expression,
                source,
                condition,
                ..
            } => {
                stack.push(source);
                stack.push(expression);
                if let Some(condition) = condition {
                    stack.push(condition);
                }
            }
            Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => {
                for field in fields {
                    stack.push(&field.value);
                }
            }
            Expr::JsonObject(entries) => {
                for entry in entries {
                    stack.push(&entry.value);
                }
            }
            Expr::JsonArray(items) => {
                for item in items {
                    stack.push(item);
                }
            }
            Expr::Member { object, .. } => {
                stack.push(object);
            }
            Expr::Index { target, index } => {
                stack.push(target);
                stack.push(index);
            }
            Expr::Bool(_)
            | Expr::IntLiteral(_)
            | Expr::DecimalLiteral(_)
            | Expr::OptionNone
            | Expr::String(_)
            | Expr::Bytes(_) => {}
        }
    }
}
fn record_block_idents(block: &Block, lookup: &HashSet<String>, hits: &mut HashSet<String>) {
    for statement in &block.statements {
        record_statement_idents(statement, lookup, hits);
    }
    if let Some(tail) = &block.tail {
        record_expr_idents(tail, lookup, hits);
    }
}
fn record_statement_idents(
    statement: &Statement,
    lookup: &HashSet<String>,
    hits: &mut HashSet<String>,
) {
    match statement.kind() {
        Statement::Source { .. } | Statement::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Statement::Let { value, .. }
        | Statement::Assign { value, .. }
        | Statement::Expr(value)
        | Statement::Emit(value)
        | Statement::Return(Some(value)) => record_expr_idents(value, lookup, hits),
        Statement::AssignExpr { target, value, .. } => {
            record_expr_idents(target, lookup, hits);
            record_expr_idents(value, lookup, hits);
        }
        Statement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            record_expr_idents(cond, lookup, hits);
            record_block_idents(then_branch, lookup, hits);
            if let Some(block) = else_branch {
                record_block_idents(block, lookup, hits);
            }
        }
        Statement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            record_expr_idents(value, lookup, hits);
            record_block_idents(then_branch, lookup, hits);
            if let Some(block) = else_branch {
                record_block_idents(block, lookup, hits);
            }
        }
        Statement::While { cond, body } => {
            record_expr_idents(cond, lookup, hits);
            record_block_idents(body, lookup, hits);
        }
        Statement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(statement) = init {
                record_statement_idents(statement, lookup, hits);
            }
            if let Some(cond) = cond {
                record_expr_idents(cond, lookup, hits);
            }
            if let Some(statement) = step {
                record_statement_idents(statement, lookup, hits);
            }
            record_block_idents(body, lookup, hits);
        }
        Statement::ForEachMap { map, body, .. } => {
            record_expr_idents(map, lookup, hits);
            record_block_idents(body, lookup, hits);
        }
        Statement::Return(None) | Statement::Break | Statement::Continue => {}
    }
}
const POINTER_CONSTRUCTORS: &[PointerConstructor] = &[
    PointerConstructor::AccountId,
    PointerConstructor::AssetDefinition,
    PointerConstructor::AssetId,
    PointerConstructor::NftId,
    PointerConstructor::Name,
    PointerConstructor::DomainId,
    PointerConstructor::Json,
    PointerConstructor::DataSpaceId,
];
/// Literals are reusable only within the same constructor and result type.
/// Each entry lists the source range of every occurrence in source order.
type PointerLiteralOccurrences = BTreeMap<(String, String), Vec<Option<SourceRange>>>;
/// Render a string literal in Kotodama source syntax.
fn kotodama_string_literal(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('"');
    for character in value.chars() {
        match character {
            '"' => rendered.push_str("\\\""),
            '\\' => rendered.push_str("\\\\"),
            '\n' => rendered.push_str("\\n"),
            '\t' => rendered.push_str("\\t"),
            character => rendered.push(character),
        }
    }
    rendered.push('"');
    rendered
}
fn lint_pointer_constructor_usage(program: &Program, warnings: &mut Vec<LintWarning>) {
    let constructors: HashSet<&str> = POINTER_CONSTRUCTORS
        .iter()
        .map(|constructor| Builtin::PointerConstructor(*constructor).source_name())
        .collect();
    let mut literal_counts = PointerLiteralOccurrences::new();
    let mut named = BTreeMap::<(String, String), &str>::new();
    for item in &program.items {
        match item {
            Item::Function(func) => {
                collect_pointer_literals_from_block(&func.body, &constructors, &mut literal_counts);
                lint_unused_pointer_constructor_block(
                    &func.body,
                    &constructors,
                    &func.name,
                    warnings,
                );
            }
            Item::Const(constant) => {
                if let Expr::Call { name, args, .. } = constant.value.kind()
                    && constructors.contains(name.as_str())
                    && let Some(Expr::String(literal)) = args.first().map(Expr::kind)
                {
                    named
                        .entry((literal.clone(), name.clone()))
                        .or_insert(constant.name.as_str());
                }
            }
            _ => {}
        }
    }
    for ((literal, constructor), occurrences) in literal_counts {
        if occurrences.len() < 2 {
            continue;
        }
        let type_name = constructor
            .split("::")
            .next()
            .unwrap_or(constructor.as_str());
        let call = format!("{constructor}({})", kotodama_string_literal(&literal));
        let help = if let Some(existing) = named.get(&(literal.clone(), constructor.clone())) {
            format!(
                "The constant `{existing}` already holds this value; use `{existing}` instead of repeating the literal."
            )
        } else if literal.contains('@') {
            format!("Bind the value once with `let` and reuse the binding: `let id = {call};`.")
        } else {
            format!(
                "Declare the value once and refer to it by name, which keeps every use identical and \
                 lets reviewers see what it stands for: `const {type_name} NAME = {call};`."
            )
        };
        let mut warning = LintWarning::new(
            "duplicate-pointer-literal",
            LintMessage::Custom {
                message: format!(
                    "the same `{constructor}` literal appears {} times in this seiyaku",
                    occurrences.len()
                ),
            },
        )
        .at_source(occurrences[0])
        .with_help(help);
        for occurrence in &occurrences[1..] {
            warning = warning.with_related(*occurrence, "repeated here");
        }
        warnings.push(warning);
    }
}
fn lint_nonliteral_trigger_specs(program: &Program, warnings: &mut Vec<LintWarning>) {
    for item in &program.items {
        if let Item::Function(func) = item {
            lint_trigger_specs_in_block(&func.body, &func.name, warnings);
        }
    }
}
fn lint_trigger_specs_in_block(block: &Block, func_name: &str, warnings: &mut Vec<LintWarning>) {
    for stmt in &block.statements {
        lint_trigger_specs_in_stmt(stmt, func_name, warnings);
    }
    if let Some(tail) = &block.tail {
        lint_trigger_specs_in_expr(tail, func_name, warnings);
    }
}
fn lint_trigger_specs_in_stmt(stmt: &Statement, func_name: &str, warnings: &mut Vec<LintWarning>) {
    match stmt.kind() {
        Statement::Source { .. } | Statement::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Statement::Let { value, .. }
        | Statement::Assign { value, .. }
        | Statement::Expr(value)
        | Statement::Emit(value)
        | Statement::Return(Some(value)) => {
            lint_trigger_specs_in_expr(value, func_name, warnings);
        }
        Statement::AssignExpr { target, value, .. } => {
            lint_trigger_specs_in_expr(target, func_name, warnings);
            lint_trigger_specs_in_expr(value, func_name, warnings);
        }
        Statement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            lint_trigger_specs_in_expr(cond, func_name, warnings);
            lint_trigger_specs_in_block(then_branch, func_name, warnings);
            if let Some(else_block) = else_branch {
                lint_trigger_specs_in_block(else_block, func_name, warnings);
            }
        }
        Statement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            lint_trigger_specs_in_expr(value, func_name, warnings);
            lint_trigger_specs_in_block(then_branch, func_name, warnings);
            if let Some(else_block) = else_branch {
                lint_trigger_specs_in_block(else_block, func_name, warnings);
            }
        }
        Statement::While { cond, body } => {
            lint_trigger_specs_in_expr(cond, func_name, warnings);
            lint_trigger_specs_in_block(body, func_name, warnings);
        }
        Statement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init_stmt) = init {
                lint_trigger_specs_in_stmt(init_stmt, func_name, warnings);
            }
            if let Some(cond_expr) = cond {
                lint_trigger_specs_in_expr(cond_expr, func_name, warnings);
            }
            if let Some(step_stmt) = step {
                lint_trigger_specs_in_stmt(step_stmt, func_name, warnings);
            }
            lint_trigger_specs_in_block(body, func_name, warnings);
        }
        Statement::ForEachMap { map, body, .. } => {
            lint_trigger_specs_in_expr(map, func_name, warnings);
            lint_trigger_specs_in_block(body, func_name, warnings);
        }
        Statement::Return(None) | Statement::Break | Statement::Continue => {}
    }
}
fn lint_trigger_specs_in_expr(expr: &Expr, func_name: &str, warnings: &mut Vec<LintWarning>) {
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Expr::Call { name, args, .. } => {
            if name == Builtin::RegisterTrigger.source_name()
                || name == Builtin::RegisterTrigger.source_name()
            {
                let literal = args.first().is_some_and(is_literal_trigger_spec);
                if !literal {
                    warnings.push(LintWarning::new(
                        "nonliteral-trigger-spec",
                        LintMessage::Custom {
                            message: format!(
                                "trigger spec in `{func_name}` is non-literal; production access metadata requires a canonical Json::parse(\"...\") literal"
                            ),
                        },
                    ).at_source(expr.source()));
                }
            }
            for arg in args {
                lint_trigger_specs_in_expr(arg, func_name, warnings);
            }
        }
        Expr::Binary { left, right, .. } => {
            lint_trigger_specs_in_expr(left, func_name, warnings);
            lint_trigger_specs_in_expr(right, func_name, warnings);
        }
        Expr::Unary { expr, .. }
        | Expr::OptionSome(expr)
        | Expr::ResultOk(expr)
        | Expr::ResultErr(expr)
        | Expr::Propagate(expr) => lint_trigger_specs_in_expr(expr, func_name, warnings),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            lint_trigger_specs_in_expr(cond, func_name, warnings);
            lint_trigger_specs_in_expr(then_expr, func_name, warnings);
            lint_trigger_specs_in_expr(else_expr, func_name, warnings);
        }
        Expr::If {
            condition,
            then_branch,
            else_branch,
        } => {
            lint_trigger_specs_in_expr(condition, func_name, warnings);
            lint_trigger_specs_in_block(then_branch, func_name, warnings);
            if let Some(block) = else_branch {
                lint_trigger_specs_in_block(block, func_name, warnings);
            }
        }
        Expr::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            lint_trigger_specs_in_expr(value, func_name, warnings);
            lint_trigger_specs_in_block(then_branch, func_name, warnings);
            if let Some(block) = else_branch {
                lint_trigger_specs_in_block(block, func_name, warnings);
            }
        }
        Expr::Match { value, arms } => {
            lint_trigger_specs_in_expr(value, func_name, warnings);
            for arm in arms {
                lint_trigger_specs_in_block(&arm.body, func_name, warnings);
            }
        }
        Expr::Tuple(values) | Expr::List(values) => {
            for value in values {
                lint_trigger_specs_in_expr(value, func_name, warnings);
            }
        }
        Expr::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            lint_trigger_specs_in_expr(source, func_name, warnings);
            lint_trigger_specs_in_expr(expression, func_name, warnings);
            if let Some(condition) = condition {
                lint_trigger_specs_in_expr(condition, func_name, warnings);
            }
        }
        Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => {
            for field in fields {
                lint_trigger_specs_in_expr(&field.value, func_name, warnings);
            }
        }
        Expr::JsonObject(entries) => {
            for entry in entries {
                lint_trigger_specs_in_expr(&entry.value, func_name, warnings);
            }
        }
        Expr::JsonArray(items) => {
            for item in items {
                lint_trigger_specs_in_expr(item, func_name, warnings);
            }
        }
        Expr::Member { object, .. } => lint_trigger_specs_in_expr(object, func_name, warnings),
        Expr::Index { target, index } => {
            lint_trigger_specs_in_expr(target, func_name, warnings);
            lint_trigger_specs_in_expr(index, func_name, warnings);
        }
        Expr::Bool(_)
        | Expr::IntLiteral(_)
        | Expr::DecimalLiteral(_)
        | Expr::OptionNone
        | Expr::String(_)
        | Expr::Bytes(_)
        | Expr::Ident(_) => {}
    }
}
fn is_literal_trigger_spec(expr: &Expr) -> bool {
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Expr::Call { name, args, .. }
            if name == Builtin::PointerConstructor(PointerConstructor::Json).source_name() =>
        {
            args.first()
                .is_some_and(|argument| matches!(argument.kind(), Expr::String(_)))
        }
        _ => false,
    }
}
fn collect_pointer_literals_from_stmt(
    stmt: &Statement,
    constructors: &HashSet<&str>,
    counts: &mut PointerLiteralOccurrences,
) {
    match stmt.kind() {
        Statement::Source { .. } | Statement::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Statement::Let { value, .. } => {
            collect_pointer_literals_from_expr(value, constructors, counts);
        }
        Statement::Assign { value, .. } => {
            collect_pointer_literals_from_expr(value, constructors, counts);
        }
        Statement::AssignExpr { target, value, .. } => {
            collect_pointer_literals_from_expr(target, constructors, counts);
            collect_pointer_literals_from_expr(value, constructors, counts);
        }
        Statement::Expr(expr) | Statement::Emit(expr) => {
            collect_pointer_literals_from_expr(expr, constructors, counts);
        }
        Statement::Return(Some(expr)) => {
            collect_pointer_literals_from_expr(expr, constructors, counts);
        }
        Statement::Return(None) | Statement::Break | Statement::Continue => {}
        Statement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            collect_pointer_literals_from_expr(cond, constructors, counts);
            collect_pointer_literals_from_block(then_branch, constructors, counts);
            if let Some(else_block) = else_branch {
                collect_pointer_literals_from_block(else_block, constructors, counts);
            }
        }
        Statement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            collect_pointer_literals_from_expr(value, constructors, counts);
            collect_pointer_literals_from_block(then_branch, constructors, counts);
            if let Some(else_block) = else_branch {
                collect_pointer_literals_from_block(else_block, constructors, counts);
            }
        }
        Statement::While { cond, body } => {
            collect_pointer_literals_from_expr(cond, constructors, counts);
            collect_pointer_literals_from_block(body, constructors, counts);
        }
        Statement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init_stmt) = init {
                collect_pointer_literals_from_stmt(init_stmt, constructors, counts);
            }
            if let Some(cond_expr) = cond {
                collect_pointer_literals_from_expr(cond_expr, constructors, counts);
            }
            if let Some(step_stmt) = step {
                collect_pointer_literals_from_stmt(step_stmt, constructors, counts);
            }
            collect_pointer_literals_from_block(body, constructors, counts);
        }
        Statement::ForEachMap { map, body, .. } => {
            collect_pointer_literals_from_expr(map, constructors, counts);
            collect_pointer_literals_from_block(body, constructors, counts);
        }
    }
}
fn collect_pointer_literals_from_block(
    block: &Block,
    constructors: &HashSet<&str>,
    counts: &mut PointerLiteralOccurrences,
) {
    for stmt in &block.statements {
        collect_pointer_literals_from_stmt(stmt, constructors, counts);
    }
    if let Some(tail) = &block.tail {
        collect_pointer_literals_from_expr(tail, constructors, counts);
    }
}
fn collect_pointer_literals_from_expr(
    expr: &Expr,
    constructors: &HashSet<&str>,
    counts: &mut PointerLiteralOccurrences,
) {
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Expr::Call { name, args, .. } => {
            if constructors.contains(name.as_str())
                && let Some(lit) = args.first().and_then(|argument| match argument.kind() {
                    Expr::String(literal) => Some(literal),
                    Expr::Source { .. } | Expr::Resolved { .. } => {
                        unreachable!("kind() strips provenance wrappers")
                    }
                    _ => None,
                })
            {
                counts
                    .entry((lit.clone(), name.clone()))
                    .or_default()
                    .push(args.first().and_then(Expr::source));
            }
            for (index, arg) in args.iter().enumerate() {
                if index == 1
                    && (name == Builtin::JsonSetInt.source_name()
                        || name == Builtin::JsonSetAccountId.source_name())
                {
                    continue;
                }
                collect_pointer_literals_from_expr(arg, constructors, counts);
            }
        }
        Expr::Binary { left, right, .. } => {
            collect_pointer_literals_from_expr(left, constructors, counts);
            collect_pointer_literals_from_expr(right, constructors, counts);
        }
        Expr::Unary { expr, .. }
        | Expr::OptionSome(expr)
        | Expr::ResultOk(expr)
        | Expr::ResultErr(expr)
        | Expr::Propagate(expr) => collect_pointer_literals_from_expr(expr, constructors, counts),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_pointer_literals_from_expr(cond, constructors, counts);
            collect_pointer_literals_from_expr(then_expr, constructors, counts);
            collect_pointer_literals_from_expr(else_expr, constructors, counts);
        }
        Expr::If {
            condition,
            then_branch,
            else_branch,
        } => {
            collect_pointer_literals_from_expr(condition, constructors, counts);
            collect_pointer_literals_from_block(then_branch, constructors, counts);
            if let Some(block) = else_branch {
                collect_pointer_literals_from_block(block, constructors, counts);
            }
        }
        Expr::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            collect_pointer_literals_from_expr(value, constructors, counts);
            collect_pointer_literals_from_block(then_branch, constructors, counts);
            if let Some(block) = else_branch {
                collect_pointer_literals_from_block(block, constructors, counts);
            }
        }
        Expr::Match { value, arms } => {
            collect_pointer_literals_from_expr(value, constructors, counts);
            for arm in arms {
                collect_pointer_literals_from_block(&arm.body, constructors, counts);
            }
        }
        Expr::Member { object, .. } => {
            collect_pointer_literals_from_expr(object, constructors, counts);
        }
        Expr::Index { target, index } => {
            collect_pointer_literals_from_expr(target, constructors, counts);
            collect_pointer_literals_from_expr(index, constructors, counts);
        }
        Expr::Tuple(values) | Expr::List(values) => {
            for value in values {
                collect_pointer_literals_from_expr(value, constructors, counts);
            }
        }
        Expr::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            collect_pointer_literals_from_expr(source, constructors, counts);
            collect_pointer_literals_from_expr(expression, constructors, counts);
            if let Some(condition) = condition {
                collect_pointer_literals_from_expr(condition, constructors, counts);
            }
        }
        Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => {
            for field in fields {
                collect_pointer_literals_from_expr(&field.value, constructors, counts);
            }
        }
        Expr::JsonObject(entries) => {
            for entry in entries {
                collect_pointer_literals_from_expr(&entry.value, constructors, counts);
            }
        }
        Expr::JsonArray(items) => {
            for item in items {
                collect_pointer_literals_from_expr(item, constructors, counts);
            }
        }
        Expr::Bool(_)
        | Expr::IntLiteral(_)
        | Expr::DecimalLiteral(_)
        | Expr::OptionNone
        | Expr::String(_)
        | Expr::Bytes(_)
        | Expr::Ident(_) => {}
    }
}
fn lint_unused_pointer_constructor(
    stmt: &Statement,
    constructors: &HashSet<&str>,
    func_name: &str,
    warnings: &mut Vec<LintWarning>,
) {
    match stmt.kind() {
        Statement::Source { .. } | Statement::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Statement::Expr(expr) | Statement::Emit(expr) => {
            warn_if_unused_pointer_call(expr, constructors, func_name, warnings)
        }
        // A returned constructor value is consumed by the caller. Only a
        // standalone expression statement discards the pointer value.
        Statement::Return(Some(_)) => {}
        Statement::If {
            then_branch,
            else_branch,
            ..
        } => {
            lint_unused_pointer_constructor_block(then_branch, constructors, func_name, warnings);
            if let Some(else_block) = else_branch {
                lint_unused_pointer_constructor_block(
                    else_block,
                    constructors,
                    func_name,
                    warnings,
                );
            }
        }
        Statement::IfLet {
            then_branch,
            else_branch,
            ..
        } => {
            lint_unused_pointer_constructor_block(then_branch, constructors, func_name, warnings);
            if let Some(else_block) = else_branch {
                lint_unused_pointer_constructor_block(
                    else_block,
                    constructors,
                    func_name,
                    warnings,
                );
            }
        }
        Statement::While { body, .. }
        | Statement::For { body, .. }
        | Statement::ForEachMap { body, .. } => {
            lint_unused_pointer_constructor_block(body, constructors, func_name, warnings);
        }
        Statement::Return(None)
        | Statement::Let { .. }
        | Statement::Assign { .. }
        | Statement::AssignExpr { .. }
        | Statement::Break
        | Statement::Continue => {}
    }
}
fn lint_unused_pointer_constructor_block(
    block: &Block,
    constructors: &HashSet<&str>,
    func_name: &str,
    warnings: &mut Vec<LintWarning>,
) {
    for stmt in &block.statements {
        lint_unused_pointer_constructor(stmt, constructors, func_name, warnings);
    }
}
fn warn_if_unused_pointer_call(
    expr: &Expr,
    constructors: &HashSet<&str>,
    func_name: &str,
    warnings: &mut Vec<LintWarning>,
) {
    if let Expr::Call { name, args, .. } = expr.kind()
        && constructors.contains(name.as_str())
        && args
            .first()
            .is_some_and(|argument| matches!(argument.kind(), Expr::String(_)))
    {
        warnings.push(LintWarning::new(
            "unused-pointer-constructor",
            LintMessage::Custom {
                message: format!(
                    "result of `{name}` is unused in function `{func_name}`; assign it to a `let` binding or pass it to a syscall"
                ),
            },
        ).at_source(expr.source()));
    }
}
/// One node visited by [`walk_block`].
#[derive(Clone, Copy)]
enum Visit<'a> {
    Block(&'a Block),
    Statement(&'a Statement),
    Expr(&'a Expr),
}
/// Visit a block, its statements, and every nested expression in source order.
fn walk_block<'a>(block: &'a Block, visit: &mut dyn FnMut(Visit<'a>)) {
    visit(Visit::Block(block));
    for statement in &block.statements {
        walk_statement(statement, visit);
    }
    if let Some(tail) = &block.tail {
        walk_expr(tail, visit);
    }
}
fn walk_statement<'a>(statement: &'a Statement, visit: &mut dyn FnMut(Visit<'a>)) {
    visit(Visit::Statement(statement));
    match statement.kind() {
        Statement::Source { .. } | Statement::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Statement::Let { value, .. }
        | Statement::Assign { value, .. }
        | Statement::Expr(value)
        | Statement::Emit(value)
        | Statement::Return(Some(value)) => walk_expr(value, visit),
        Statement::AssignExpr { target, value, .. } => {
            walk_expr(target, visit);
            walk_expr(value, visit);
        }
        Statement::Return(None) | Statement::Break | Statement::Continue => {}
        Statement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            walk_expr(cond, visit);
            walk_block(then_branch, visit);
            if let Some(block) = else_branch {
                walk_block(block, visit);
            }
        }
        Statement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            walk_expr(value, visit);
            walk_block(then_branch, visit);
            if let Some(block) = else_branch {
                walk_block(block, visit);
            }
        }
        Statement::While { cond, body } => {
            walk_expr(cond, visit);
            walk_block(body, visit);
        }
        Statement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init) = init {
                walk_statement(init, visit);
            }
            if let Some(cond) = cond {
                walk_expr(cond, visit);
            }
            if let Some(step) = step {
                walk_statement(step, visit);
            }
            walk_block(body, visit);
        }
        Statement::ForEachMap { map, body, .. } => {
            walk_expr(map, visit);
            walk_block(body, visit);
        }
    }
}
fn walk_expr<'a>(expr: &'a Expr, visit: &mut dyn FnMut(Visit<'a>)) {
    visit(Visit::Expr(expr));
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips provenance wrappers")
        }
        Expr::Binary { left, right, .. } => {
            walk_expr(left, visit);
            walk_expr(right, visit);
        }
        Expr::Unary { expr, .. }
        | Expr::OptionSome(expr)
        | Expr::ResultOk(expr)
        | Expr::ResultErr(expr)
        | Expr::Propagate(expr) => walk_expr(expr, visit),
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            walk_expr(cond, visit);
            walk_expr(then_expr, visit);
            walk_expr(else_expr, visit);
        }
        Expr::If {
            condition,
            then_branch,
            else_branch,
        } => {
            walk_expr(condition, visit);
            walk_block(then_branch, visit);
            if let Some(block) = else_branch {
                walk_block(block, visit);
            }
        }
        Expr::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            walk_expr(value, visit);
            walk_block(then_branch, visit);
            if let Some(block) = else_branch {
                walk_block(block, visit);
            }
        }
        Expr::Match { value, arms } => {
            walk_expr(value, visit);
            for arm in arms {
                walk_block(&arm.body, visit);
            }
        }
        Expr::Call { args, .. } => {
            for arg in args {
                walk_expr(arg, visit);
            }
        }
        Expr::StructLiteral { fields, .. } | Expr::ArgumentRecord { fields } => {
            for field in fields {
                walk_expr(&field.value, visit);
            }
        }
        Expr::Member { object, .. } => walk_expr(object, visit),
        Expr::Index { target, index } => {
            walk_expr(target, visit);
            walk_expr(index, visit);
        }
        Expr::Tuple(items) | Expr::List(items) | Expr::JsonArray(items) => {
            for item in items {
                walk_expr(item, visit);
            }
        }
        Expr::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            walk_expr(source, visit);
            walk_expr(expression, visit);
            if let Some(condition) = condition {
                walk_expr(condition, visit);
            }
        }
        Expr::JsonObject(entries) => {
            for entry in entries {
                walk_expr(&entry.value, visit);
            }
        }
        Expr::Bool(_)
        | Expr::IntLiteral(_)
        | Expr::DecimalLiteral(_)
        | Expr::OptionNone
        | Expr::String(_)
        | Expr::Bytes(_)
        | Expr::Ident(_) => {}
    }
}
/// `(name, value)` of a plain `name = value;` assignment.
fn plain_assignment(statement: &Statement) -> Option<(&str, &Expr)> {
    match statement.kind() {
        Statement::Assign { name, value } => Some((name.as_str(), value)),
        Statement::AssignExpr {
            target,
            op: crate::ast::AssignOp::Set,
            value,
        } => match target.kind() {
            Expr::Ident(name) => Some((name.as_str(), value)),
            _ => None,
        },
        _ => None,
    }
}
/// Indexed uses in one block. Each statement is walked once; querying whether
/// a binding is used later never scans the rest of a large block again.
#[derive(Default)]
struct BlockUses<'a> {
    last_read: HashMap<&'a str, usize>,
    last_change: HashMap<&'a str, usize>,
    mentions: HashMap<&'a str, Vec<usize>>,
    exits: Vec<usize>,
}
impl<'a> BlockUses<'a> {
    fn new(block: &'a Block) -> Self {
        let mut uses = Self::default();
        let mut writes = HashSet::<*const Expr>::new();
        let mut visit = |index, node: Visit<'a>| {
            let mut mention = |name| {
                let sites = uses.mentions.entry(name).or_default();
                if sites.last() != Some(&index) {
                    sites.push(index);
                }
            };
            match node {
                Visit::Statement(statement) => match statement.kind() {
                    Statement::Assign { name, .. } => {
                        mention(name.as_str());
                        uses.last_change.insert(name.as_str(), index);
                    }
                    Statement::AssignExpr { target, op, .. } => {
                        if let Some(name) = assignment_root(target) {
                            uses.last_change.insert(name, index);
                        }
                        if *op == crate::ast::AssignOp::Set
                            && matches!(target.kind(), Expr::Ident(_))
                        {
                            writes.insert(target as *const Expr);
                        }
                    }
                    Statement::Break | Statement::Continue | Statement::Return(_) => {
                        if uses.exits.last() != Some(&index) {
                            uses.exits.push(index);
                        }
                    }
                    _ => {}
                },
                Visit::Expr(expr) => match expr.kind() {
                    Expr::Ident(name) => {
                        mention(name.as_str());
                        if !writes.contains(&(expr as *const Expr)) {
                            uses.last_read.insert(name.as_str(), index);
                        }
                    }
                    Expr::Call {
                        name,
                        args,
                        implicit_receiver: true,
                        ..
                    } if !READ_ONLY_METHODS.contains(&name.as_str()) => {
                        if let Some(binding) = args.first().and_then(assignment_root) {
                            uses.last_change.insert(binding, index);
                        }
                    }
                    _ => {}
                },
                Visit::Block(_) => {}
            }
        };
        for (index, statement) in block.statements.iter().enumerate() {
            walk_statement(statement, &mut |node| visit(index, node));
        }
        if let Some(tail) = &block.tail {
            walk_expr(tail, &mut |node| visit(block.statements.len(), node));
        }
        uses
    }
    fn read_after(&self, name: &str, index: usize) -> bool {
        self.last_read.get(name).is_some_and(|last| *last > index)
    }
    fn changed_after(&self, name: &str, index: usize) -> bool {
        self.last_change.get(name).is_some_and(|last| *last > index)
    }
    fn next_mention(&self, name: &str, index: usize) -> Option<usize> {
        let sites = self.mentions.get(name)?;
        sites
            .get(sites.partition_point(|site| *site <= index))
            .copied()
    }
    fn exits_between(&self, start: usize, end: usize) -> bool {
        self.exits
            .get(self.exits.partition_point(|site| *site <= start))
            .is_some_and(|site| *site < end)
    }
}
fn expr_reads(expr: &Expr, name: &str) -> bool {
    let mut found = false;
    walk_expr(expr, &mut |node| {
        if let Visit::Expr(expr) = node
            && matches!(expr.kind(), Expr::Ident(ident) if ident == name)
        {
            found = true;
        }
    });
    found
}
/// Root identifier of a field or index assignment target.
fn assignment_root(target: &Expr) -> Option<&str> {
    let mut current = target;
    loop {
        match current.kind() {
            Expr::Member { object, .. } => current = object,
            Expr::Index { target, .. } => current = target,
            Expr::Ident(name) => return Some(name),
            _ => return None,
        }
    }
}
fn pattern_names(pattern: &Pattern) -> Vec<&str> {
    let mut names = Vec::new();
    collect_pattern_names(pattern, &mut names);
    names
}

/// Seiyaku-level declarations consulted by the extended lints.
struct ProgramFacts<'a> {
    states: BTreeMap<&'a str, &'a crate::ast::TypeExpr>,
    consts: BTreeMap<&'a str, &'a crate::ast::ConstDecl>,
    functions: BTreeMap<&'a str, &'a crate::ast::Function>,
    structs: BTreeMap<&'a str, &'a crate::ast::StructDef>,
    trigger_targets: std::collections::BTreeSet<&'a str>,
}
impl<'a> ProgramFacts<'a> {
    fn new(program: &'a Program) -> Self {
        let mut facts = Self {
            states: BTreeMap::new(),
            consts: BTreeMap::new(),
            functions: BTreeMap::new(),
            structs: BTreeMap::new(),
            trigger_targets: std::collections::BTreeSet::new(),
        };
        for item in &program.items {
            match item {
                Item::State(state) => {
                    facts.states.insert(state.name.as_str(), &state.ty);
                }
                Item::Const(constant) => {
                    facts.consts.insert(constant.name.as_str(), constant);
                }
                Item::Function(function) => {
                    facts.functions.insert(function.name.as_str(), function);
                }
                Item::Struct(definition) | Item::Event(definition) => {
                    facts.structs.insert(definition.name.as_str(), definition);
                }
                Item::Trigger(trigger) => {
                    facts
                        .trigger_targets
                        .insert(trigger.call.entrypoint.as_str());
                }
                Item::Enum(_) => {}
            }
        }
        facts
    }
    fn is_state_map(&self, name: &str) -> bool {
        self.states.get(name).is_some_and(|ty| {
            matches!(ty.kind(), crate::ast::TypeExpr::Generic { base, .. } if base == "StateMap")
        })
    }
}

/// Method calls that return a copy of a stored value without changing state.
const COPYING_READ_METHODS: &[&str] = &["expect", "unwrap_or"];

/// Where a `var` binding's value was copied from durable state.
struct StateCopyOrigin<'a> {
    /// State declaration the value came from.
    state: &'a str,
    /// Map key expression, or `None` for a scalar state.
    key: Option<&'a Expr>,
}
fn state_copy_origin<'a>(value: &'a Expr, facts: &ProgramFacts<'a>) -> Option<StateCopyOrigin<'a>> {
    let mut current = value;
    loop {
        match current.kind() {
            Expr::Ident(name)
                if facts.states.contains_key(name.as_str()) && !facts.is_state_map(name) =>
            {
                let (state, _) = facts.states.get_key_value(name.as_str())?;
                return Some(StateCopyOrigin { state, key: None });
            }
            Expr::Index { target, index } => {
                if let Expr::Ident(name) = target.kind()
                    && facts.is_state_map(name)
                {
                    let (state, _) = facts.states.get_key_value(name.as_str())?;
                    return Some(StateCopyOrigin {
                        state,
                        key: Some(index),
                    });
                }
                return None;
            }
            Expr::Call {
                name,
                args,
                implicit_receiver: true,
                ..
            } => {
                if COPYING_READ_METHODS.contains(&name.as_str()) {
                    current = args.first()?;
                    continue;
                }
                if (name == "get" || name == crate::ast::STATE_MAP_GET_INTRINSIC)
                    && let [receiver, key, ..] = args.as_slice()
                    && let Expr::Ident(map) = receiver.kind()
                    && facts.is_state_map(map)
                {
                    let (state, _) = facts.states.get_key_value(map.as_str())?;
                    return Some(StateCopyOrigin {
                        state,
                        key: Some(key),
                    });
                }
                return None;
            }
            _ => return None,
        }
    }
}
/// A key that can be written again verbatim in a fix-it without changing meaning.
fn simple_key(expr: &Expr) -> bool {
    match expr.kind() {
        Expr::Ident(_)
        | Expr::IntLiteral(_)
        | Expr::DecimalLiteral(_)
        | Expr::String(_)
        | Expr::Bool(_) => true,
        Expr::Member { object, .. } => simple_key(object),
        Expr::Call { args, .. } => args.is_empty(),
        _ => false,
    }
}
/// Root node of a field or index assignment target.
fn assignment_root_node(target: &Expr) -> Option<&Expr> {
    let mut current = target;
    loop {
        match current.kind() {
            Expr::Member { object, .. } => current = object,
            Expr::Index { target, .. } => current = target,
            Expr::Ident(_) => return Some(current),
            _ => return None,
        }
    }
}
/// Whether `binding` is used as a whole value under `statement`, letting the
/// copy escape (passed, returned, stored, or compared). Field reads such as
/// `c.total` and field writes such as `c.total = 1` do not count.
fn binding_escapes(statement: &Statement, binding: &str) -> bool {
    let mut partial: Vec<&Expr> = Vec::new();
    let mut escapes = false;
    walk_statement(statement, &mut |node| match node {
        Visit::Statement(statement) => {
            if let Statement::AssignExpr { target, .. } = statement.kind()
                && let Some(root) = assignment_root_node(target)
            {
                partial.push(root);
            }
        }
        Visit::Expr(expr) => match expr.kind() {
            Expr::Member { object, .. } => partial.push(object),
            Expr::Ident(name)
                if name == binding && !partial.iter().any(|node| std::ptr::eq(*node, expr)) =>
            {
                escapes = true;
            }
            _ => {}
        },
        Visit::Block(_) => {}
    });
    escapes
}
/// Whether `statement` changes `binding` (a field write or whole reassignment).
fn statement_mutates(statement: &Statement, binding: &str) -> bool {
    let mut mutates = false;
    walk_statement(statement, &mut |node| {
        if let Visit::Statement(statement) = node {
            match statement.kind() {
                Statement::AssignExpr { target, .. }
                    if assignment_root(target) == Some(binding) =>
                {
                    mutates = true;
                }
                Statement::Assign { name, .. } if name == binding => mutates = true,
                _ => {}
            }
        }
    });
    mutates
}
/// Report lost writes to copies of durable state and return the functions that have one.
fn lint_unpersisted_state_copies<'a>(
    program: &'a Program,
    facts: &ProgramFacts<'_>,
    warnings: &mut Vec<LintWarning>,
) -> std::collections::BTreeSet<&'a str> {
    let mut functions = std::collections::BTreeSet::new();
    for item in &program.items {
        let Item::Function(function) = item else {
            continue;
        };
        // A view cannot persist anything, so its copies are ordinary locals.
        if function.modifiers.kind == crate::ast::FunctionKind::View {
            continue;
        }
        walk_block(&function.body, &mut |node| {
            let Visit::Block(block) = node else {
                return;
            };
            for (index, statement) in block.statements.iter().enumerate() {
                let Statement::Let {
                    mutable: true,
                    pat: Pattern::Name(binding),
                    value,
                    ..
                } = statement.kind()
                else {
                    continue;
                };
                let Some(origin) = state_copy_origin(value, facts) else {
                    continue;
                };
                let rest = &block.statements[index + 1..];
                let last_mutation = rest
                    .iter()
                    .rposition(|statement| statement_mutates(statement, binding));
                let Some(last_mutation) = last_mutation else {
                    continue;
                };
                // Any store into the same state after the copy (for example a
                // field-by-field rebuild) is treated as an explicit write-back.
                if rest.iter().any(|statement| {
                    binding_escapes(statement, binding)
                        || statement_mutates(statement, origin.state)
                }) || block
                    .tail
                    .as_deref()
                    .is_some_and(|tail| expr_reads(tail, binding))
                {
                    continue;
                }
                let mutation = &rest[last_mutation];
                let write = match origin.key {
                    Some(_) => format!("{}[key] = {binding};", origin.state),
                    None => format!("{} = {binding};", origin.state),
                };
                let recipe = mutation.source().and_then(|after| {
                    let key = match origin.key {
                        Some(key) if simple_key(key) => Some(key.source()?),
                        Some(_) => return None,
                        None => None,
                    };
                    Some(LintFixRecipe::WriteBack {
                        after,
                        map: origin.state.to_owned(),
                        key,
                        binding: binding.clone(),
                    })
                });
                functions.insert(function.name.as_str());
                warnings.push(
                    LintWarning::new(
                        "unpersisted-state-copy",
                        LintMessage::UnpersistedStateCopy {
                            binding: binding.clone(),
                            origin: origin.state.to_owned(),
                        },
                    )
                    .at_source(statement.source())
                    .with_related(mutation.source(), format!("`{binding}` is changed here"))
                    .with_help(format!(
                        "Reading `{}` returns a copy; changes to `{binding}` are lost when the call ends. \
                         Store the updated value with `{write}` after the last change.",
                        origin.state
                    ))
                    .with_recipe(recipe),
                );
            }
        });
    }
    functions
}

/// Method calls whose receiver is only read.
const READ_ONLY_METHODS: &[&str] = &[
    "get",
    crate::ast::STATE_MAP_GET_INTRINSIC,
    "contains",
    "len",
    "take",
    "page",
    "enumerate",
    "is_some",
    "is_none",
    "is_ok",
    "is_err",
    "expect",
    "ok_or",
    "or_err",
    "unwrap_or",
    "unwrap_err_or",
];
fn builtin_has_effects(builtin: Builtin) -> bool {
    let effects = builtin.effects();
    effects.host_side_effects || effects.emits_instructions || effects.mutates_durable_state
}
/// Conservatively decide whether a function may write state, submit ledger
/// instructions, or perform host effects, following calls to other functions.
fn function_may_have_effects(
    name: &str,
    facts: &ProgramFacts<'_>,
    memo: &mut BTreeMap<String, bool>,
    visiting: &mut std::collections::BTreeSet<String>,
) -> bool {
    if let Some(known) = memo.get(name) {
        return *known;
    }
    let Some(function) = facts.functions.get(name) else {
        return true;
    };
    if !visiting.insert(name.to_owned()) {
        return true;
    }
    let mut effects = function.params.iter().any(|param| param.is_state);
    let mut callees = Vec::new();
    walk_block(&function.body, &mut |node| match node {
        Visit::Statement(statement) => match statement.kind() {
            Statement::Assign { name, .. } if facts.states.contains_key(name.as_str()) => {
                effects = true;
            }
            Statement::AssignExpr { target, .. }
                if assignment_root(target).is_some_and(|root| facts.states.contains_key(root)) =>
            {
                effects = true;
            }
            _ => {}
        },
        Visit::Expr(expr) => {
            let Expr::Call {
                name,
                args,
                implicit_receiver,
                ..
            } = expr.kind()
            else {
                return;
            };
            if *implicit_receiver {
                let method_builtin = Builtin::all().find(|builtin| {
                    matches!(
                        builtin.surface(),
                        BuiltinSurface::MethodOnly | BuiltinSurface::FunctionOrMethod
                    ) && (builtin.name() == name.as_str() || builtin.source_name() == name.as_str())
                });
                let state_receiver = args
                    .first()
                    .and_then(assignment_root)
                    .is_some_and(|root| facts.states.contains_key(root));
                if method_builtin.is_some_and(builtin_has_effects)
                    || (state_receiver
                        && method_builtin.is_none()
                        && !READ_ONLY_METHODS.contains(&name.as_str()))
                {
                    effects = true;
                }
            } else if let Some(builtin) = Builtin::from_source_name(name) {
                effects |= builtin_has_effects(builtin);
            } else if facts.functions.contains_key(name.as_str()) {
                callees.push(name.clone());
            } else if facts.structs.contains_key(name.as_str())
                || crate::resolved::is_intrinsic_call(name)
            {
            } else {
                // Imported or unresolved calls are treated as effectful.
                effects = true;
            }
        }
        Visit::Block(_) => {}
    });
    for callee in callees {
        if effects {
            break;
        }
        effects |= function_may_have_effects(&callee, facts, memo, visiting);
    }
    visiting.remove(name);
    memo.insert(name.to_owned(), effects);
    effects
}
fn lint_kotoage_without_effects(
    program: &Program,
    facts: &ProgramFacts<'_>,
    lost_writes: &std::collections::BTreeSet<&str>,
    warnings: &mut Vec<LintWarning>,
) {
    let mut memo = BTreeMap::new();
    for item in &program.items {
        let Item::Function(function) = item else {
            continue;
        };
        // A lost write is the more precise finding; fixing it adds the effect.
        if function.modifiers.kind != crate::ast::FunctionKind::Kotoage
            || function.modifiers.is_test
            || facts.trigger_targets.contains(function.name.as_str())
            || lost_writes.contains(function.name.as_str())
        {
            continue;
        }
        let mut visiting = std::collections::BTreeSet::new();
        if function_may_have_effects(&function.name, facts, &mut memo, &mut visiting) {
            continue;
        }
        let authorize = function.modifiers.authorization.as_deref().map_or_else(
            String::new,
            |permission| format!(" Keep the explicit policy `authorize({permission})` on the view; use `authorize(anyone)` only if every caller may query it."),
        );
        warnings.push(
            LintWarning::new(
                "kotoage-without-effects",
                LintMessage::KotoageWithoutEffects {
                    func: function.name.clone(),
                    keyword: "kotoage".to_owned(),
                },
            )
            .with_help(format!(
                "A `view fn` is answered as a read-only query, so callers need no transaction or fee \
                 to call it.{authorize}"
            )),
        );
    }
}

/// Numeric domain of an expression, as far as the declarations reveal it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NumericKind {
    Int,
    Decimal,
    Quantity,
    /// An unsuffixed literal that adopts its context.
    Literal,
    Struct(String),
    Map(Box<NumericKind>),
    Wrapped(Box<NumericKind>),
    Other,
}
fn numeric_kind_of_type(ty: &crate::ast::TypeExpr, facts: &ProgramFacts<'_>) -> NumericKind {
    match ty.kind() {
        crate::ast::TypeExpr::Path(name) => match name.as_str() {
            "int" => NumericKind::Int,
            "decimal" => NumericKind::Decimal,
            "quantity" => NumericKind::Quantity,
            name if facts.structs.contains_key(name) => NumericKind::Struct(name.to_owned()),
            _ => NumericKind::Other,
        },
        crate::ast::TypeExpr::Generic { base, args } => match (base.as_str(), args.as_slice()) {
            ("StateMap", [_, value]) => {
                NumericKind::Map(Box::new(numeric_kind_of_type(value, facts)))
            }
            ("Option" | "Result", [value, ..]) => {
                NumericKind::Wrapped(Box::new(numeric_kind_of_type(value, facts)))
            }
            _ => NumericKind::Other,
        },
        _ => NumericKind::Other,
    }
}
fn numeric_kind_of_descriptor(descriptor: &str) -> NumericKind {
    match descriptor {
        "int" => NumericKind::Int,
        "decimal" => NumericKind::Decimal,
        "quantity" => NumericKind::Quantity,
        other if other.starts_with("Option<quantity") || other.starts_with("Result<quantity") => {
            NumericKind::Wrapped(Box::new(NumericKind::Quantity))
        }
        other if other.starts_with("Option<decimal") || other.starts_with("Result<decimal") => {
            NumericKind::Wrapped(Box::new(NumericKind::Decimal))
        }
        _ => NumericKind::Other,
    }
}
fn numeric_kind_of(
    expr: &Expr,
    locals: &BTreeMap<String, NumericKind>,
    facts: &ProgramFacts<'_>,
) -> NumericKind {
    match expr.kind() {
        Expr::IntLiteral(_) => NumericKind::Literal,
        Expr::DecimalLiteral(_) => NumericKind::Decimal,
        Expr::Ident(name) => locals
            .get(name)
            .cloned()
            .or_else(|| {
                facts
                    .states
                    .get(name.as_str())
                    .map(|ty| numeric_kind_of_type(ty, facts))
            })
            .or_else(|| {
                facts
                    .consts
                    .get(name.as_str())
                    .and_then(|constant| constant.ty.as_ref())
                    .map(|ty| numeric_kind_of_type(ty, facts))
            })
            .unwrap_or(NumericKind::Other),
        Expr::Unary { expr, .. } => numeric_kind_of(expr, locals, facts),
        Expr::Binary { op, left, right } => {
            use crate::ast::BinaryOp;
            if !matches!(
                op,
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod
            ) {
                return NumericKind::Other;
            }
            let left = numeric_kind_of(left, locals, facts);
            let right = numeric_kind_of(right, locals, facts);
            match (&left, &right) {
                (NumericKind::Quantity, NumericKind::Quantity) if *op == BinaryOp::Div => {
                    NumericKind::Decimal
                }
                (NumericKind::Quantity, _) | (_, NumericKind::Quantity) => NumericKind::Quantity,
                (NumericKind::Decimal, _) | (_, NumericKind::Decimal) => NumericKind::Decimal,
                (
                    NumericKind::Int | NumericKind::Literal,
                    NumericKind::Int | NumericKind::Literal,
                ) => {
                    if left == NumericKind::Literal && right == NumericKind::Literal {
                        NumericKind::Literal
                    } else {
                        NumericKind::Int
                    }
                }
                _ => NumericKind::Other,
            }
        }
        Expr::Conditional { then_expr, .. } => numeric_kind_of(then_expr, locals, facts),
        Expr::Member { object, field } => match numeric_kind_of(object, locals, facts) {
            NumericKind::Struct(name) => facts
                .structs
                .get(name.as_str())
                .and_then(|definition| {
                    definition
                        .fields
                        .iter()
                        .find(|(candidate, _)| candidate == field)
                })
                .map_or(NumericKind::Other, |(_, ty)| {
                    numeric_kind_of_type(ty, facts)
                }),
            _ => NumericKind::Other,
        },
        Expr::Call {
            name,
            args,
            implicit_receiver,
            ..
        } => {
            if *implicit_receiver {
                let receiver = args.first().map_or(NumericKind::Other, |receiver| {
                    numeric_kind_of(receiver, locals, facts)
                });
                return match (name.as_str(), receiver) {
                    ("get" | crate::ast::STATE_MAP_GET_INTRINSIC, NumericKind::Map(value)) => {
                        NumericKind::Wrapped(value)
                    }
                    ("expect" | "unwrap_or", NumericKind::Wrapped(value)) => *value,
                    ("ratio_round", _) => NumericKind::Decimal,
                    ("div_round" | "mul_div_round", receiver) => receiver,
                    _ => NumericKind::Other,
                };
            }
            match name.as_str() {
                "decimal::from_int" | "decimal::from_quantity" => NumericKind::Decimal,
                "quantity::try_from_int" | "quantity::try_from_decimal" => {
                    NumericKind::Wrapped(Box::new(NumericKind::Quantity))
                }
                name => facts
                    .functions
                    .get(name)
                    .and_then(|function| function.ret_ty.as_ref())
                    .map(|ty| numeric_kind_of_type(ty, facts))
                    .or_else(|| {
                        Builtin::from_source_name(name).map(|builtin| {
                            numeric_kind_of_descriptor(builtin.signature().return_type)
                        })
                    })
                    .unwrap_or(NumericKind::Other),
            }
        }
        _ => NumericKind::Other,
    }
}
/// A divisor fixed at compile time: a literal or a declared constant.
fn constant_divisor(expr: &Expr, facts: &ProgramFacts<'_>) -> bool {
    match expr.kind() {
        Expr::IntLiteral(_) | Expr::DecimalLiteral(_) => true,
        Expr::Unary { expr, .. } => constant_divisor(expr, facts),
        Expr::Ident(name) => facts.consts.contains_key(name.as_str()),
        _ => false,
    }
}
fn exact_division_warning(
    left: &NumericKind,
    right: &NumericKind,
    at: Option<SourceRange>,
) -> LintWarning {
    let (domain, method) = match (left, right) {
        (NumericKind::Quantity, NumericKind::Quantity) => ("quantity", "ratio_round"),
        (NumericKind::Quantity, _) => ("quantity", "div_round"),
        _ => ("decimal", "div_round"),
    };
    LintWarning::new(
        "exact-division",
        LintMessage::Custom {
            message: format!(
                "exact `/` on `{domain}` reverts the call when the quotient does not terminate"
            ),
        },
    )
    .at_source(at)
    .with_help(format!(
        "Exact division fails with RepeatingDecimal for divisors such as 3 and with \
         ExactDivisionScaleOverflow beyond 28 fractional digits. Divide with an explicit rounding \
         mode instead, for example `value.{method}(divisor: d, scale: 6, mode: Rounding::floor)`; \
         Kotodama never chooses the scale or rounding mode for you."
    ))
}
fn lint_exact_division(
    program: &Program,
    facts: &ProgramFacts<'_>,
    warnings: &mut Vec<LintWarning>,
) {
    for item in &program.items {
        let Item::Function(function) = item else {
            continue;
        };
        let mut locals = BTreeMap::<String, NumericKind>::new();
        for param in &function.params {
            if let Some(ty) = &param.ty {
                locals.insert(param.name.clone(), numeric_kind_of_type(ty, facts));
            }
        }
        // Locals cannot shadow one another, so one pass collects every binding type.
        walk_block(&function.body, &mut |node| {
            if let Visit::Statement(statement) = node
                && let Statement::Let {
                    pat: Pattern::Name(name),
                    ty,
                    value,
                    ..
                } = statement.kind()
            {
                let kind = match ty {
                    Some(ty) => numeric_kind_of_type(ty, facts),
                    None => match numeric_kind_of(value, &locals, facts) {
                        NumericKind::Literal => NumericKind::Int,
                        kind => kind,
                    },
                };
                locals.insert(name.clone(), kind);
            }
        });
        walk_block(&function.body, &mut |node| match node {
            Visit::Expr(expr) => {
                if let Expr::Binary {
                    op: crate::ast::BinaryOp::Div,
                    left,
                    right,
                } = expr.kind()
                    && !constant_divisor(right, facts)
                {
                    let left_kind = numeric_kind_of(left, &locals, facts);
                    let right_kind = numeric_kind_of(right, &locals, facts);
                    if matches!(left_kind, NumericKind::Decimal | NumericKind::Quantity) {
                        warnings.push(exact_division_warning(
                            &left_kind,
                            &right_kind,
                            expr.source(),
                        ));
                    }
                }
            }
            Visit::Statement(statement) => {
                if let Statement::AssignExpr {
                    target,
                    op: crate::ast::AssignOp::Div,
                    value,
                } = statement.kind()
                    && !constant_divisor(value, facts)
                {
                    let left_kind = numeric_kind_of(target, &locals, facts);
                    if matches!(left_kind, NumericKind::Decimal | NumericKind::Quantity) {
                        let right_kind = numeric_kind_of(value, &locals, facts);
                        warnings.push(exact_division_warning(
                            &left_kind,
                            &right_kind,
                            statement.source(),
                        ));
                    }
                }
            }
            Visit::Block(_) => {}
        });
    }
}

fn lint_unused_locals_and_dead_stores(
    program: &Program,
    facts: &ProgramFacts<'_>,
    warnings: &mut Vec<LintWarning>,
) {
    for item in &program.items {
        let Item::Function(function) = item else {
            continue;
        };
        walk_block(&function.body, &mut |node| {
            let Visit::Block(block) = node else {
                return;
            };
            let uses = BlockUses::new(block);
            for (index, statement) in block.statements.iter().enumerate() {
                if let Statement::Let { mutable, pat, .. } = statement.kind() {
                    let struct_fields = match pat {
                        Pattern::Struct { fields, .. } => fields
                            .iter()
                            .filter_map(|field| {
                                Some((field.binding.as_str(), (field.source?, field.name.as_str())))
                            })
                            .collect::<BTreeMap<_, _>>(),
                        _ => BTreeMap::new(),
                    };
                    for name in pattern_names(pat) {
                        if name == "_" || name.starts_with('_') {
                            continue;
                        }
                        let read = uses.read_after(name, index);
                        if !read {
                            warnings.push(
                                LintWarning::new(
                                    "unused-local",
                                    LintMessage::UnusedLocal {
                                        name: name.to_owned(),
                                        mutable: *mutable,
                                    },
                                )
                                .at_source(statement.source())
                                .with_help(format!(
                                    "Remove `{name}`, use it, or bind the value to `_` to evaluate the expression and discard its result."
                                ))
                                .with_recipe(struct_fields.get(name).map(|(field, field_name)| {
                                    LintFixRecipe::StructFieldDiscard {
                                        field: *field,
                                        name: (*field_name).to_owned(),
                                    }
                                })),
                            );
                        }
                    }
                }
                let stored = match statement.kind() {
                    Statement::Let {
                        mutable: true,
                        pat: Pattern::Name(name),
                        ..
                    } => Some(name.as_str()),
                    _ => plain_assignment(statement).map(|(name, _)| name),
                };
                let Some(name) = stored
                    .filter(|name| !name.starts_with('_') && !facts.states.contains_key(name))
                else {
                    continue;
                };
                let Some(next_index) = uses.next_mention(name, index) else {
                    continue;
                };
                let Some(next) = block.statements.get(next_index) else {
                    continue;
                };
                // A control-flow exit between stores can keep the first value live.
                if let Some((target, value)) = plain_assignment(next)
                    && target == name
                    && !expr_reads(value, name)
                    && !uses.exits_between(index, next_index)
                {
                    warnings.push(
                        LintWarning::new(
                            "dead-store",
                            LintMessage::Custom {
                                message: format!(
                                    "value stored in `{name}` is overwritten before it is read"
                                ),
                            },
                        )
                        .at_source(statement.source())
                        .with_related(next.source(), format!("`{name}` is overwritten here"))
                        .with_help(format!(
                            "Remove this store, or read `{name}` before assigning it again."
                        )),
                    );
                }
            }
        });
    }
}

fn lint_underscore_public_parameters(program: &Program, warnings: &mut Vec<LintWarning>) {
    use crate::ast::FunctionKind;
    // Parameter names in first-declaration order with every declaring function.
    let mut declared: Vec<(&str, Vec<&str>)> = Vec::new();
    for item in &program.items {
        let Item::Function(function) = item else {
            continue;
        };
        if !matches!(
            function.modifiers.kind,
            FunctionKind::Kotoage
                | FunctionKind::View
                | FunctionKind::Hajimari
                | FunctionKind::Kaizen
        ) || function.modifiers.is_test
        {
            continue;
        }
        for param in &function.params {
            let name = param.name.as_str();
            if !name.starts_with('_') || name.trim_start_matches('_').is_empty() {
                continue;
            }
            match declared.iter_mut().find(|(declared, _)| *declared == name) {
                Some((_, functions)) => functions.push(function.name.as_str()),
                None => declared.push((name, vec![function.name.as_str()])),
            }
        }
    }
    // One naming decision shared by several public functions is one finding.
    for (name, functions) in declared {
        let stripped = name.trim_start_matches('_');
        warnings.push(
            LintWarning::new(
                "underscore-public-parameter",
                LintMessage::UnderscorePublicParameter {
                    func: functions[0].to_owned(),
                    name: name.to_owned(),
                    also: functions[1..]
                        .iter()
                        .map(|func| (*func).to_owned())
                        .collect(),
                },
            )
            .with_help(underscore_public_parameter_help(name, stripped)),
        );
    }
}
/// Report `var` bindings that are read but never reassigned or mutated.
fn lint_never_mutated_vars(program: &Program, warnings: &mut Vec<LintWarning>) {
    for item in &program.items {
        let Item::Function(function) = item else {
            continue;
        };
        walk_block(&function.body, &mut |node| {
            let Visit::Block(block) = node else {
                return;
            };
            let uses = BlockUses::new(block);
            for (index, statement) in block.statements.iter().enumerate() {
                let Statement::Let {
                    mutable: true,
                    pat: Pattern::Name(name),
                    ..
                } = statement.kind()
                else {
                    continue;
                };
                if name.starts_with('_') {
                    continue;
                }
                // An unread binding is reported by `unused-local` instead.
                let read = uses.read_after(name, index);
                let changed = uses.changed_after(name, index);
                if !read || changed {
                    continue;
                }
                warnings.push(
                    LintWarning::new(
                        "never-mutated-var",
                        LintMessage::NeverMutatedVar { name: name.clone() },
                    )
                    .at_source(statement.source())
                    .with_help(format!(
                        "`var` declares a binding that is reassigned or mutated later; `{name}` never is. Declare it with `let`."
                    ))
                    .with_recipe(
                        statement
                            .source()
                            .map(|statement| LintFixRecipe::VarToLet { statement }),
                    ),
                );
            }
        });
    }
}
/// Report a seiyaku with no public or lifecycle function; returns whether it did.
fn lint_seiyaku_without_entrypoint(program: &Program, warnings: &mut Vec<LintWarning>) -> bool {
    // Included fragments may declare the entrypoints, and a standalone test
    // module is driven by its tests.
    if program.unit.kind != crate::ast::SourceUnitKind::Seiyaku
        || program.test_target.is_some()
        || !program.directives.is_empty()
        || program.items.iter().any(|item| {
            matches!(item, Item::Function(function)
                if function.modifiers.kind != crate::ast::FunctionKind::Private)
        })
    {
        return false;
    }
    let kotoage = crate::glossary::by_spelling("kotoage").map_or_else(
        || "kotoage".to_owned(),
        crate::glossary::BrandedKeyword::label,
    );
    warnings.push(
        LintWarning::new(
            "seiyaku-without-entrypoint",
            LintMessage::SeiyakuWithoutEntrypoint {
                name: program.unit.name.clone(),
                keyword: "seiyaku".to_owned(),
            },
        )
        .with_help(format!(
            "Private `fn` helpers run only when a public function calls them. Add a {kotoage} \
             function with `authorize(Admin)` for state changes, or a `view fn` for queries."
        )),
    );
    true
}
/// Visitor recording the name of every call except calls to `caller` itself.
fn call_recorder<'c>(
    called: &'c mut std::collections::BTreeSet<String>,
    caller: Option<&'c str>,
) -> impl for<'x> FnMut(Visit<'x>) + 'c {
    move |node| {
        if let Visit::Expr(expr) = node
            && let Expr::Call { name, .. } = expr.kind()
            && Some(name.as_str()) != caller
        {
            called.insert(name.clone());
        }
    }
}
/// Report private functions that nothing in the source unit calls.
fn lint_unused_private_functions(
    program: &Program,
    facts: &ProgramFacts<'_>,
    warnings: &mut Vec<LintWarning>,
) {
    // Included fragments can call into this unit and the unit into them.
    if program.unit.kind == crate::ast::SourceUnitKind::Fragment || !program.directives.is_empty() {
        return;
    }
    // Calls a function makes to itself do not make it used.
    let mut called = std::collections::BTreeSet::<String>::new();
    for item in &program.items {
        match item {
            Item::Function(function) => walk_block(
                &function.body,
                &mut call_recorder(&mut called, Some(function.name.as_str())),
            ),
            Item::Const(constant) => {
                walk_expr(&constant.value, &mut call_recorder(&mut called, None));
            }
            _ => {}
        }
    }
    for fixture in &program.fixtures {
        for action in &fixture.actions {
            for argument in &action.args {
                walk_expr(argument, &mut call_recorder(&mut called, None));
            }
        }
    }
    let exported = program
        .exports
        .iter()
        .map(|export| export.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let module = program.unit.kind == crate::ast::SourceUnitKind::Module;
    for item in &program.items {
        let Item::Function(function) = item else {
            continue;
        };
        let name = function.name.as_str();
        if function.modifiers.kind != crate::ast::FunctionKind::Private
            || function.modifiers.is_test
            || name.starts_with('_')
            || exported.contains(name)
            || facts.trigger_targets.contains(name)
            || called.contains(name)
        {
            continue;
        }
        let help = if module {
            format!(
                "Nothing in this module calls `{name}` and it is not exported. Remove it, call it, \
                 or declare it `export fn` so other units can use it."
            )
        } else {
            format!(
                "Nothing in this seiyaku calls `{name}`, and private functions are not part of its \
                 interface. Remove it, call it from a public function, or prefix its name with `_` \
                 to keep it deliberately."
            )
        };
        warnings.push(
            LintWarning::new(
                "unused-private-fn",
                LintMessage::UnusedPrivateFunction {
                    func: function.name.clone(),
                },
            )
            .with_help(help),
        );
    }
}
/// Help for a public parameter named `name` whose name starts with `_`.
///
/// Public functions are never called from source, so the positional-only form
/// `Type _ name` would not change anything for them: the argument key is the
/// declared name either way. Renaming is the only remedy.
fn underscore_public_parameter_help(name: &str, stripped: &str) -> String {
    format!(
        "Callers send public arguments as a record keyed by parameter name, so `{name}` is part of \
         the interface. Rename it to `{stripped}` in every public function that declares it. \
         Public parameters are never reported as unused, so a leading `_` silences nothing."
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn lint_text(text: &str) -> (SourceFile, Vec<LintWarning>) {
        use crate::source::{FrontendBudget, SourceId};
        let source = SourceFile::new(SourceId(8), "lints.ko", text);
        let (program, _) =
            crate::parser::parse_source_spanned(&source, FrontendBudget::v1()).expect("parses");
        let warnings = lint_with_sources(&program.program, &program.facts, &source);
        (source, warnings)
    }
    fn found<'a>(warnings: &'a [LintWarning], code: &str) -> Vec<&'a LintWarning> {
        warnings
            .iter()
            .filter(|warning| warning.code == code)
            .collect()
    }
    fn spelled<'a>(source: &'a SourceFile, warning: &LintWarning) -> &'a str {
        source
            .slice(warning.source.as_ref().expect("located lint").byte_range)
            .expect("lint range")
    }
    #[test]
    fn state_copies_changed_without_write_back_get_a_write_back_fix() {
        let text = "seiyaku Wb { permission Admin; \n    error enum E { Missing = 1 }\n    struct Config { int fee, bool paused }\n    state StateMap<int, Config> Configs;\n    kotoage fn pause(int id) authorize(Admin) {\n        var c = Configs.get(id).expect(E::Missing);\n        c.paused = true;\n    }\n    kotoage fn persisted(int id) authorize(Admin) {\n        var c = Configs.get(id).expect(E::Missing);\n        c.paused = true;\n        Configs[id] = c;\n    }\n    view fn projected(int id) authorize(anyone) -> Config {\n        var c = Configs.get(id).expect(E::Missing);\n        c.fee = 0;\n        return c;\n    }\n}";
        let (source, warnings) = lint_text(text);
        let lost = found(&warnings, "unpersisted-state-copy");
        assert_eq!(lost.len(), 1, "{warnings:?}");
        assert_eq!(spelled(&source, lost[0]), "c");
        assert_eq!(lost[0].diagnostic_code(), "K5010");
        let fix = lost[0].fix.as_ref().expect("write-back fix");
        assert_eq!(
            fix.replacement,
            "c.paused = true;\n        Configs[id] = c;"
        );
        assert_eq!(lost[0].labels.len(), 1);
        // The lost write is the precise finding; no effect-free kotoage lint as well.
        assert!(found(&warnings, "kotoage-without-effects").is_empty());
    }
    #[test]
    fn effect_free_kotoage_suggests_view_in_the_written_spelling() {
        let text = "誓約 Pure { permission Entry; \n    state int count;\n    言挙げ fn add(int a, int b) authorize(Entry) -> int {\n        return a + b;\n    }\n    kotoage fn bump() authorize(Entry) {\n        count += 1;\n    }\n    kotoage fn relay() authorize(Entry) {\n        helper();\n    }\n    fn helper() {\n        count = 2;\n    }\n}";
        let (source, warnings) = lint_text(text);
        let pure = found(&warnings, "kotoage-without-effects");
        assert_eq!(pure.len(), 1, "{warnings:?}");
        assert_eq!(spelled(&source, pure[0]), "add");
        assert_eq!(
            pure[0].localized_message(Language::English),
            "言挙げ `add` performs no state, ledger, or host effects; declare it `view fn`"
        );
        let fix = pure[0].fix.as_ref().expect("view fix");
        assert_eq!(source.slice(fix.span.byte_range), Some("言挙げ"));
        assert_eq!(fix.replacement, "view");
        assert!(
            pure[0]
                .help
                .as_deref()
                .is_some_and(|help| help.contains("authorize(Entry)"))
        );
    }
    #[test]
    fn exact_division_by_runtime_values_warns_but_literals_do_not() {
        let text = "seiyaku Div {\n    const decimal SCALE = 1000;\n    view fn ratio(decimal total, decimal parts) authorize(anyone) -> decimal {\n        return total / parts;\n    }\n    view fn third(quantity q) authorize(anyone) -> quantity {\n        return q / 3;\n    }\n    view fn scaled(decimal total) authorize(anyone) -> decimal {\n        return total / SCALE;\n    }\n    view fn ints(int a, int b) authorize(anyone) -> int {\n        return a / b;\n    }\n    view fn share(quantity q, quantity r) authorize(anyone) -> decimal {\n        return q / r;\n    }\n}";
        let (source, warnings) = lint_text(text);
        let division = found(&warnings, "exact-division");
        let spelled = division
            .iter()
            .map(|warning| spelled(&source, warning))
            .collect::<Vec<_>>();
        assert_eq!(spelled, ["total / parts", "q / r"], "{warnings:?}");
        assert!(
            division[1]
                .help
                .as_deref()
                .is_some_and(|help| help.contains("ratio_round"))
        );
        assert!(division.iter().all(|warning| warning.fix.is_none()));
    }
    #[test]
    fn unused_locals_and_dead_stores_are_reported() {
        let text = "seiyaku Locals {\n    view fn f(int x) authorize(anyone) -> int {\n        let unused = 3;\n        let _ignored = 4;\n        var acc = 0;\n        acc = 5;\n        var kept = 1;\n        kept += x;\n        return acc + kept;\n    }\n}";
        let (source, warnings) = lint_text(text);
        let unused = found(&warnings, "unused-local");
        assert_eq!(unused.len(), 1, "{warnings:?}");
        assert_eq!(spelled(&source, unused[0]), "unused");
        assert_eq!(
            unused[0].fix.as_ref().map(|fix| fix.replacement.as_str()),
            Some("_")
        );
        let dead = found(&warnings, "dead-store");
        assert_eq!(dead.len(), 1, "{warnings:?}");
        assert_eq!(spelled(&source, dead[0]), "var acc = 0;");
        assert_eq!(dead[0].labels.len(), 1);
    }
    #[test]
    fn indexed_block_uses_distinguish_reads_writes_and_control_flow() {
        let text = r#"seiyaku Uses {
            view fn f(int n) authorize(anyone) -> int {
                var unread = 0;
                unread = 1;
                var counter = 0;
                counter = counter + 1;
                var nested = 0;
                if n > 0 { nested = 2; }
                var tail_only = 3;
                counter + nested + tail_only
            }
        }"#;
        let (_, warnings) = lint_text(text);
        let unused = found(&warnings, "unused-local");
        assert_eq!(unused.len(), 1, "{warnings:?}");
        assert!(
            matches!(&unused[0].message, LintMessage::UnusedLocal { name, .. } if name == "unread")
        );
        let dead = found(&warnings, "dead-store");
        assert_eq!(dead.len(), 1, "{warnings:?}");
        assert!(
            dead[0]
                .localized_message(Language::English)
                .contains("`unread`")
        );
        let never = found(&warnings, "never-mutated-var");
        assert_eq!(never.len(), 1, "{warnings:?}");
        assert!(
            matches!(&never[0].message, LintMessage::NeverMutatedVar { name } if name == "tail_only")
        );
        let (_, returned) = lint_text(
            "seiyaku Exit { view fn f() authorize(anyone) -> int { var x = 1; return 0; x = 2; } }",
        );
        assert!(found(&returned, "dead-store").is_empty());
    }

    #[test]
    fn large_flat_blocks_keep_all_lints_with_exact_source_ranges() {
        let mut text = String::from("seiyaku Large { view fn f() authorize(anyone) -> int { ");
        for index in 0..4096 {
            text.push_str(&format!("let local_{index} = {index}; "));
        }
        text.push_str("return 0; } }");
        let (source, warnings) = lint_text(&text);
        let unused = found(&warnings, "unused-local");
        assert_eq!(unused.len(), 4096);
        assert_eq!(spelled(&source, unused[0]), "local_0");
        assert_eq!(spelled(&source, unused[4095]), "local_4095");
        assert!(unused.iter().all(|warning| warning.fix.is_some()));
    }

    #[test]
    fn underscore_public_parameters_are_abi_keys() {
        let text = "seiyaku Abi {\n    state int value;\n    改善(int _new_impl) {\n        value = _new_impl;\n    }\n    fn private(int _unused) {}\n}";
        let (source, warnings) = lint_text(text);
        let underscore = found(&warnings, "underscore-public-parameter");
        assert_eq!(underscore.len(), 1, "{warnings:?}");
        assert_eq!(spelled(&source, underscore[0]), "_new_impl");
        assert_eq!(
            underscore[0].localized_message(Language::English),
            "public parameter `_new_impl` of `改善` becomes the ABI argument key `_new_impl`"
        );
        assert_eq!(
            underscore[0]
                .fix
                .as_ref()
                .map(|fix| fix.replacement.as_str()),
            Some("new_impl")
        );
        let help = underscore[0].help.as_deref().expect("rename help");
        assert!(help.contains("Rename it to `new_impl`"), "{help}");
        assert!(!help.contains("int _ new_impl"), "{help}");
        // Applying the fix leaves nothing to report: public parameters are
        // interface keys and are never reported as unused.
        let renamed = "seiyaku Abi {\n    改善(int new_impl) {\n    }\n    view fn ignore(int key) authorize(anyone) -> int {\n        return 0;\n    }\n}";
        let (_, warnings) = lint_text(renamed);
        assert!(
            found(&warnings, "underscore-public-parameter").is_empty()
                && found(&warnings, "unused-parameter").is_empty(),
            "{warnings:?}"
        );
    }
    #[test]
    fn a_shared_underscore_parameter_name_is_one_finding() {
        let text = "seiyaku Handlers {\n    view fn health(bytes _body) authorize(anyone) -> int {\n        return 1;\n    }\n    view fn status(bytes _body, int _height) authorize(anyone) -> int {\n        return 2;\n    }\n}";
        let (source, warnings) = lint_text(text);
        let underscore = found(&warnings, "underscore-public-parameter");
        assert_eq!(underscore.len(), 2, "{warnings:?}");
        assert_eq!(
            underscore[0].localized_message(Language::English),
            "public parameter `_body` of `health` and 1 other function becomes the ABI argument key `_body`"
        );
        assert_eq!(spelled(&source, underscore[0]), "_body");
        assert_eq!(underscore[0].labels.len(), 1);
        assert_eq!(
            underscore[0].labels[0].message,
            "`status` declares `_body` here too"
        );
        assert_eq!(
            source.slice(underscore[0].labels[0].span.byte_range),
            Some("_body")
        );
        assert!(underscore[1].labels.is_empty());
    }
    #[test]
    fn unused_parameters_are_reported_only_for_private_functions() {
        let text = "seiyaku Params { permission Entry; \n    state int total;\n    hajimari() {\n        total = 0;\n    }\n    fn helper(int unused) -> int {\n        return 1;\n    }\n    kotoage fn record(int amount) authorize(Entry) {\n        total = helper(unused: 0);\n    }\n}";
        let (source, warnings) = lint_text(text);
        let unused = found(&warnings, "unused-parameter");
        assert_eq!(unused.len(), 1, "{warnings:?}");
        assert_eq!(spelled(&source, unused[0]), "unused");
    }
    #[test]
    fn unused_struct_pattern_bindings_get_a_valid_discard_fix() {
        let text = "seiyaku Fields {\n    struct Point { int x; int y; }\n    view fn shorthand() authorize(anyone) -> int {\n        let Point { x, y } = Point { x: 1, y: 2 };\n        return y;\n    }\n    view fn renamed() authorize(anyone) -> int {\n        let Point { x: px, y } = Point { x: 1, y: 2 };\n        return y;\n    }\n}";
        let (source, warnings) = lint_text(text);
        let fixes = found(&warnings, "unused-local")
            .into_iter()
            .map(|warning| {
                let fix = warning.fix.as_ref().expect("discard fix");
                (
                    source.slice(fix.span.byte_range).expect("fix range"),
                    fix.replacement.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(fixes, [("x", "x: _"), ("px", "_")], "{warnings:?}");
    }
    #[test]
    fn vars_that_never_change_suggest_let() {
        let text = "seiyaku Vars {\n    view fn f(int x) authorize(anyone) -> int {\n        var total = x + 1;\n        var List<int, 4> values = [1];\n        let _ = values.try_push(2);\n        var count = 0;\n        count += 1;\n        var unread = 3;\n        return total + values.len() + count;\n    }\n}";
        let (source, warnings) = lint_text(text);
        let never = found(&warnings, "never-mutated-var");
        assert_eq!(never.len(), 1, "{warnings:?}");
        assert_eq!(spelled(&source, never[0]), "total");
        assert_eq!(never[0].diagnostic_code(), "K5016");
        let fix = never[0].fix.as_ref().expect("var to let fix");
        assert_eq!(source.slice(fix.span.byte_range), Some("var"));
        assert_eq!(fix.replacement, "let");
        // An unread `var` is reported once, as an unused local.
        assert_eq!(found(&warnings, "unused-local").len(), 1, "{warnings:?}");
    }
    #[test]
    fn private_functions_nothing_calls_are_reported() {
        let text = "seiyaku Fns {\n    fn helper() -> int {\n        return 1;\n    }\n    fn orphan() -> int {\n        return 2;\n    }\n    fn spin(int n) -> int {\n        return spin(n: n);\n    }\n    fn _kept() -> int {\n        return 3;\n    }\n    view fn value() authorize(anyone) -> int {\n        return helper();\n    }\n}";
        let (source, warnings) = lint_text(text);
        let unused = found(&warnings, "unused-private-fn")
            .into_iter()
            .map(|warning| spelled(&source, warning))
            .collect::<Vec<_>>();
        assert_eq!(unused, ["orphan", "spin"], "{warnings:?}");
        let module = "module Math {\n    export fn value() -> int {\n        return 7;\n    }\n    fn helper() -> int {\n        return 1;\n    }\n}";
        let (_, warnings) = lint_text(module);
        let unused = found(&warnings, "unused-private-fn");
        assert_eq!(unused.len(), 1, "{warnings:?}");
        assert!(
            unused[0]
                .help
                .as_deref()
                .is_some_and(|help| help.contains("export fn")),
            "{warnings:?}"
        );
    }
    #[test]
    fn seiyaku_without_entrypoints_is_reported_in_the_written_spelling() {
        let text = "誓約 Quiet {\n    fn helper() -> int {\n        return 1;\n    }\n}";
        let (source, warnings) = lint_text(text);
        let missing = found(&warnings, "seiyaku-without-entrypoint");
        assert_eq!(missing.len(), 1, "{warnings:?}");
        assert_eq!(spelled(&source, missing[0]), "Quiet");
        assert!(
            missing[0]
                .localized_message(Language::English)
                .starts_with("誓約 `Quiet` declares no kotoage"),
            "{warnings:?}"
        );
        assert!(
            missing[0]
                .help
                .as_deref()
                .is_some_and(|help| help.contains("kotoage (言挙げ)")),
            "{warnings:?}"
        );
        // The missing entrypoint explains the unreachable helper; it is not
        // reported again as an unused private function.
        assert!(found(&warnings, "unused-private-fn").is_empty());
        let hooks = "seiyaku Hooked {\n    state int total;\n    hajimari() {\n        total = 0;\n    }\n}";
        let (_, warnings) = lint_text(hooks);
        assert!(found(&warnings, "seiyaku-without-entrypoint").is_empty());
    }
    #[test]
    fn dead_stores_stay_live_across_break_and_continue() {
        let text = "seiyaku Loops {\n    view fn last(int n) authorize(anyone) -> int {\n        var x = 0;\n        for i in range(8) {\n            x = 1;\n            if i > n { break; }\n            x = 2;\n        }\n        var y = 0;\n        for j in range(8) {\n            y = 1;\n            if j > n { continue; }\n            y = 2;\n        }\n        var z = 0;\n        for k in range(8) {\n            z = k;\n            z = k + 1;\n        }\n        return x + y + z;\n    }\n}";
        let (source, warnings) = lint_text(text);
        let dead = found(&warnings, "dead-store")
            .into_iter()
            .map(|warning| spelled(&source, warning))
            .collect::<Vec<_>>();
        assert_eq!(dead, ["z = k;"], "{warnings:?}");
    }
    #[test]
    fn repeated_typed_literals_suggest_a_named_constant() {
        let literal = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM";
        let text = format!(
            "seiyaku Ids {{\n    view fn a() authorize(anyone) -> AssetDefinitionId {{ return AssetDefinitionId::parse(\"{literal}\"); }}\n    view fn b() authorize(anyone) -> AssetDefinitionId {{ return AssetDefinitionId::parse(\"{literal}\"); }}\n}}"
        );
        let (_, warnings) = lint_text(&text);
        let repeated = found(&warnings, "duplicate-pointer-literal");
        assert_eq!(repeated.len(), 1, "{warnings:?}");
        assert_eq!(repeated[0].labels.len(), 1);
        assert_eq!(repeated[0].category, LintCategory::TypedLiterals);
        let help = repeated[0].help.as_deref().expect("const help");
        assert!(help.contains("const AssetDefinitionId NAME"), "{help}");
    }
    #[test]
    fn lint_registry_codes_and_levels_are_consistent() {
        let mut codes = HashSet::new();
        for (slug, code, category) in LINT_REGISTRY {
            assert!(codes.insert(*code), "duplicate code {code}");
            let warning = LintWarning::new(
                slug,
                LintMessage::Custom {
                    message: String::new(),
                },
            );
            assert_eq!(warning.diagnostic_code(), *code, "{slug}");
            assert_eq!(warning.category, *category, "{slug}");
            assert!(
                crate::diagnostic::diagnostic_explanation(code).is_some(),
                "{code}"
            );
        }
        for level in [LintLevel::Allow, LintLevel::Warn, LintLevel::Deny] {
            assert_eq!(LintLevel::parse(level.as_str()), Some(level));
        }
        let denied = LintWarning::new(
            "unused-local",
            LintMessage::Custom {
                message: "x".into(),
            },
        )
        .with_level(LintLevel::Deny);
        assert_eq!(denied.severity, LintSeverity::Error);
        let diagnostic = denied.to_diagnostic("x.ko", None, Language::English);
        assert_eq!(diagnostic.severity, crate::diagnostic::Severity::Error);
    }
    #[test]
    fn lint_diagnostics_keep_english_messages_and_carry_translations() {
        let warning = LintWarning::new(
            "unused-state",
            LintMessage::UnusedState {
                name: "total".into(),
            },
        );
        let english = warning.localized_message(Language::English);
        let japanese = warning.localized_message(Language::Japanese);
        assert_ne!(english, japanese, "unused-state must have a translation");
        let diagnostic = warning.to_diagnostic("x.ko", None, Language::Japanese);
        assert_eq!(diagnostic.message, english);
        let localized = diagnostic.localized.expect("translation is attached");
        assert_eq!(localized.language, Language::Japanese.tag());
        assert_eq!(localized.message, japanese);
        let plain = warning.to_diagnostic("x.ko", None, Language::English);
        assert_eq!(plain.message, english);
        assert!(plain.localized.is_none());
    }
    #[test]
    fn lint_provenance_uses_parser_ranges_for_declarations_bindings_and_calls() {
        use crate::source::{FrontendBudget, SourceId};
        let text = format!(
            r#"seiyaku Spans {{
            /* 金庫😀 */ state int untouched;
            state int total;
            fn other(int _ unused) {{ let _ = unused; }}
            fn probe(int total, int unused) {{
                let total = 1;
                Json::parse("{{}}");
                let duplicate = Json::parse("{{}}");
                state::get(path);
                execute_instruction(payload);
                {}(spec);
                return;
                let dead = 0;
            }}
        }}"#,
            Builtin::RegisterTrigger.source_name()
        );
        let source = SourceFile::new(SourceId(7), "spans.ko", &text);
        let (program, _) =
            crate::parser::parse_source_spanned(&source, FrontendBudget::v1()).unwrap();
        let warnings = lint_with_sources(&program.program, &program.facts, &source);
        let expected = [
            ("unused-state", "untouched"),
            ("state-shadowed", "total"),
            ("unused-parameter", "unused"),
            ("unreachable-return", "let dead = 0;"),
            ("duplicate-pointer-literal", "\"{}\""),
            ("unused-pointer-constructor", "Json::parse(\"{}\")"),
            (
                "nonliteral-trigger-spec",
                Builtin::RegisterTrigger.source_name(),
            ),
            ("nonliteral-state-path", "state::get(path)"),
            ("opaque-access-hints", "execute_instruction(payload)"),
        ];
        for (code, expected) in expected {
            assert!(
                warnings
                    .iter()
                    .filter(|warning| warning.code == code)
                    .any(|warning| {
                        let span = warning
                            .source
                            .as_ref()
                            .expect("every compiler lint retains its exact source");
                        source.slice(span.byte_range).unwrap().starts_with(expected)
                    }),
                "missing located {code}: {warnings:?}"
            );
        }
        assert!(warnings.iter().all(|warning| warning.source.is_some()));
        let unused = warnings.iter().find(|warning| matches!(&warning.message, LintMessage::UnusedParameter { func, name } if func == "probe" && name == "unused")).unwrap();
        assert_eq!(
            unused.source.as_ref().unwrap().byte_range.start as usize,
            text.find("int unused)").unwrap() + 4
        );
        let diagnostic = unused.to_diagnostic(
            "file:///日本語.ko",
            Some("example/spans@1.0.0"),
            Language::English,
        );
        assert_eq!(
            diagnostic
                .primary_span
                .as_ref()
                .unwrap()
                .package_identity
                .as_deref(),
            Some("example/spans@1.0.0")
        );
        assert_eq!(diagnostic.primary_source.as_ref().unwrap().text(), text);
        assert!(diagnostic.notes[0].contains("unused-parameter"));
        assert_eq!(
            warnings,
            lint_with_sources(&program.program, &program.facts, &source)
        );
    }
    use crate::{i18n::Language, parser::parse_test_fragment as parse};
    use iroha_model_base::domain::DomainId;

    #[test]
    fn public_lint_handoffs_from_a_small_caller() {
        let depth = crate::source::MAX_NESTING_DEPTH - 2;
        let expression = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let source =
            format!("module StackMargin {{ export fn value() {{ let nested = {expression}; }} }}");
        std::thread::Builder::new()
            .name("kotodama-small-lint-caller".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || {
                let program =
                    crate::parser::parse(&source).expect("boundary-depth lint fixture must parse");
                let warnings = lint_program(&program);
                assert!(
                    warnings
                        .iter()
                        .all(|warning| warning.code == "unused-local"),
                    "{warnings:?}"
                );
                drop(program);
            })
            .expect("spawn small lint caller")
            .join()
            .expect("public linting must not consume the caller stack");
    }

    #[test]
    fn record_expr_idents_collects_only_states() {
        let expr = Expr::Binary {
            op: crate::ast::BinaryOp::Add,
            left: Box::new(Expr::Ident("counter".into())),
            right: Box::new(Expr::Ident("temp".into())),
        };
        let state_lookup: HashSet<String> = [String::from("counter"), String::from("balance")]
            .into_iter()
            .collect();
        let mut hits = HashSet::new();
        record_expr_idents(&expr, &state_lookup, &mut hits);
        assert!(hits.contains("counter"));
        assert!(!hits.contains("temp"));
    }
    #[test]
    fn lint_unused_state_flags_state() {
        let program = parse("state int counter; fn main() { let x = 1; }").unwrap();
        let mut warnings = Vec::new();
        lint_unused_state(&program, &mut warnings);
        assert!(warnings.iter().any(|w| w.code == "unused-state"));
    }
    #[test]
    fn lint_unreachable_after_return_flags_code() {
        let program = parse("fn main() { return; let x = 1; }").unwrap();
        let mut warnings = Vec::new();
        lint_unreachable_after_return(&program, &mut warnings);
        assert!(warnings.iter().any(|w| w.code == "unreachable-return"));
    }
    #[test]
    fn lint_program_combines_checks() {
        let program = parse(
            "state int counter; view fn main() authorize(anyone) { return; let x = counter; }",
        )
        .unwrap();
        let warnings = lint_program(&program);
        let codes = warnings
            .iter()
            .map(|warning| warning.code)
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            ["unreachable-return", "unused-local"],
            "only unreachable code and its unread binding should remain"
        );
    }
    #[test]
    fn lint_state_shadowing_flags_parameter() {
        let program = parse("state int balance; fn main(int balance) {}").unwrap();
        let warnings = lint_program(&program);
        assert!(
            warnings.iter().any(|w| w.code == "state-shadowed"),
            "expected state-shadowed lint when parameter matches state"
        );
    }
    #[test]
    fn lint_unused_parameters_flags_param() {
        let program = parse("fn main(int amount) { return; }").unwrap();
        let warnings = lint_program(&program);
        let warning = warnings
            .iter()
            .find(|warning| warning.code == "unused-parameter")
            .expect("expected unused-parameter lint for unused argument");
        assert_eq!(warning.diagnostic_code(), "K5003");
    }
    #[test]
    fn loop_body_tail_uses_count_for_state_and_parameter_lints() {
        let program = parse(
            "seiyaku Demo { \
                state StateMap<int, int> values; \
                fn sink(Option<int> value) {} \
                fn consume(int amount) { \
                    for index in range(1) { sink(values.get(index + amount)) } \
                } \
            }",
        )
        .expect("parse loop-tail uses");
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|warning| {
                matches!(
                    &warning.message,
                    LintMessage::UnusedState { name } if name == "values"
                )
            }),
            "loop tail must count as a state use: {warnings:?}"
        );
        assert!(
            !warnings.iter().any(|warning| {
                matches!(
                    &warning.message,
                    LintMessage::UnusedParameter { name, .. } if name == "amount"
                )
            }),
            "loop tail must count as a parameter use: {warnings:?}"
        );
    }
    #[test]
    fn lint_unused_parameters_ignores_underscore() {
        let program = parse("fn main(int _unused) {}").unwrap();
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|w| w.code == "unused-parameter"),
            "underscore-prefixed arguments should not trigger unused-parameter lint"
        );
    }
    #[test]
    fn lint_warning_localizes_message() {
        let program = parse("state int counter; fn main() {}").unwrap();
        let warnings = lint_program(&program);
        let msg = warnings
            .iter()
            .find(|w| w.code == "unused-state")
            .expect("unused-state lint should be present")
            .localized_message(Language::English);
        assert!(
            msg.contains("counter"),
            "expected localized message to reference the state name: {msg}"
        );
    }
    #[test]
    fn lint_duplicate_pointer_literals_warns() {
        let program = parse(
            "fn main() { let a = AccountId::parse(\"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV\"); let b = AccountId::parse(\"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV\"); }",
        )
        .unwrap();
        let warnings = lint_program(&program);
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "duplicate-pointer-literal")
        );
    }
    #[test]
    fn duplicate_pointer_help_preserves_constructor_type_and_escaped_literal() {
        for (constructor, literal) in [
            ("AssetDefinitionId::parse", "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"),
            ("DataSpaceId::parse", "0"),
            ("Json::parse", r#"{"金庫":"quoted\\value"}"#),
        ] {
            let call = format!("{constructor}({literal:?})");
            let program = parse(&format!(
                "fn main() {{ let first = {call}; let second = {call}; }}"
            ))
            .unwrap();
            let warnings = lint_program(&program);
            let diagnostic = warnings
                .iter()
                .find(|warning| warning.code == "duplicate-pointer-literal")
                .unwrap()
                .to_diagnostic("example.ko", None, Language::English);
            assert_eq!(diagnostic.code, "K5005");
            let type_name = constructor.split("::").next().unwrap();
            let help = diagnostic.help.as_deref().expect("const help");
            assert!(
                help.contains(&format!("`const {type_name} NAME = {call};`")),
                "{help}"
            );
            assert!(!help.contains("AccountId::parse"));
            assert_eq!(diagnostic.labels.len(), 0, "unlocated labels are dropped");
            parse(&format!("const {type_name} NAME = {call}; fn main() {{}}"))
                .expect("suggested source preserves escaping");
        }
        let program = parse("fn main() { let name = Name::parse(\"0\"); let dataspace = DataSpaceId::parse(\"0\"); }").unwrap();
        assert!(
            !lint_program(&program)
                .iter()
                .any(|warning| warning.code == "duplicate-pointer-literal"),
            "different pointer types cannot share one typed binding"
        );
    }
    #[test]
    fn lint_duplicate_json_name_literals_are_allowed() {
        let program =
            parse(r#"fn main() { let p = json { amount: 1 }; let q = json { amount: 2 }; }"#)
                .unwrap();
        let warnings = lint_program(&program);
        assert!(
            !warnings
                .iter()
                .any(|w| w.code == "duplicate-pointer-literal"),
            "JSON field names are cheap and intentionally repeated across payload builders"
        );
    }
    #[test]
    fn lint_unused_pointer_constructor_warns() {
        let program = parse(
            "fn main() { AccountId::parse(\"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV\"); }",
        )
        .unwrap();
        let warnings = lint_program(&program);
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "unused-pointer-constructor")
        );
    }
    #[test]
    fn lint_returned_pointer_constructor_is_consumed() {
        let program = parse(
            "fn account() -> AccountId { return AccountId::parse(\"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV\"); }",
        )
        .unwrap();
        let warnings = lint_program(&program);
        assert!(
            !warnings
                .iter()
                .any(|warning| warning.code == "unused-pointer-constructor"),
            "return values must not be reported as discarded: {warnings:?}"
        );
    }
    #[test]
    fn lint_nonliteral_trigger_spec_warns() {
        let program =
            parse("fn main() { let spec = Json::parse(\"{}\"); ledger::trigger::register(spec); }")
                .expect("parse trigger");
        let warnings = lint_program(&program);
        assert!(warnings.iter().any(|w| w.code == "nonliteral-trigger-spec"));
    }
    #[test]
    fn lint_literal_trigger_spec_is_silent() {
        let program = parse("fn main() { ledger::trigger::register(Json::parse(\"{}\")); }")
            .expect("parse trigger");
        let warnings = lint_program(&program);
        assert!(!warnings.iter().any(|w| w.code == "nonliteral-trigger-spec"));
    }
    #[test]
    fn lint_nonliteral_state_map_key_is_silent() {
        let program = parse(
            "state StateMap<int, int> Foo; view fn main() authorize(anyone) { let k = 1; let _x = Foo.get(k); }",
        )
        .expect("parse map");
        let warnings = lint_program(&program);
        assert!(warnings.is_empty());
    }
    #[test]
    fn lint_literal_state_map_key_is_silent() {
        let program =
            parse("state StateMap<int, int> Foo; view fn main() authorize(anyone) { let _x = Foo.get(1); }")
                .expect("parse map");
        let warnings = lint_program(&program);
        assert!(warnings.is_empty());
    }
    #[test]
    fn lint_nonliteral_state_map_key_with_explicit_access_is_rejected() {
        let err = parse(
            r#"state StateMap<Name, int> Foo;
#[access(read="*", write="*")]
fn main(Name k) { let _x = Foo.get(k); }"#,
        )
        .expect_err("manual access hints should be rejected");
        assert!(err.contains("manual `#[access(...)]` hints are not supported"));
    }
    #[test]
    fn lint_nonliteral_state_path_warns() {
        for call in ["state::get(p)", "state::set(p, 1)", "state::delete(p)"] {
            let program =
                parse(&format!("fn main(bytes p) {{ {call}; }}")).expect("parse state path");
            let warnings = lint_program(&program);
            assert!(
                warnings.iter().any(|w| w.code == "nonliteral-state-path"),
                "missing canonical state-path warning for {call}"
            );
        }
    }
    #[test]
    fn lint_literal_state_path_is_silent() {
        for call in [
            "state::get(Name::parse(\"foo\").path(1))",
            "state::set(Name::parse(\"foo\").path(1), b\"value\")",
            "state::delete(Name::parse(\"foo\").path(1))",
        ] {
            let program = parse(&format!("fn main() {{ {call}; }}")).expect("parse state path");
            let warnings = lint_program(&program);
            assert!(
                !warnings.iter().any(|w| w.code == "nonliteral-state-path"),
                "literal canonical state path unexpectedly warned for {call}"
            );
        }
    }
    #[test]
    fn lint_opaque_access_hints_warns() {
        let program =
            parse("fn main() { execute_query(Json::parse(\"{}\")); }").expect("parse opaque call");
        let warnings = lint_program(&program);
        assert!(warnings.iter().any(|w| w.code == "opaque-access-hints"));
    }
    #[test]
    fn lint_nft_set_metadata_is_precise_access() {
        let program = parse(
            r#"fn main() {
  nft_set_metadata(NftId::parse("n0$wonderland.universal"), Name::parse("dpn_metadata"), Json::parse("{}"));
}"#,
        )
        .expect("parse nft_set_metadata call");
        let warnings = lint_program(&program);
        assert!(!warnings.iter().any(|w| w.code == "opaque-access-hints"));
    }
    #[test]
    fn lint_asset_registration_helpers_are_precise_access() {
        let program = parse(
            r#"
fn main(AssetDefinitionId asset, AccountId owner) {
  register_asset(asset, "ROSE", 0, 1);
  create_new_asset(asset, "ROSE", 1, owner, 1);
}
"#,
        )
        .expect("parse asset registration helpers");
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "asset registration helpers should use compiler-derived asset keys"
        );
    }
    #[test]
    fn lint_subscription_helpers_are_precise_access() {
        let program = parse(
            r#"
fn main() {
  subscription_bill();
  subscription_record_usage();
}
"#,
        )
        .expect("parse subscription helpers");
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "subscription helpers should use fixed compiler-derived context keys"
        );
    }
    #[test]
    fn lint_inline_submit_ballot_builder_is_precise_access() {
        let program = parse(
            r#"
fn main() {
  let _ballot = build_submit_ballot_inline(
    "election",
    blob("ciphertext"),
    blob("0000000000000000000000000000000000000000000000000000000000000000"),
    "halo2",
    blob("proof"),
    blob("vk")
  );
}
"#,
        )
        .expect("parse inline submit-ballot builder");
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "the inline submit-ballot builder only constructs a payload and should not warn about access hints"
        );
    }
    #[test]
    fn lint_transfer_domain_literal_target_is_precise_access() {
        let program = parse(
            r#"
fn main() {
  ledger::domain::transfer(
    source: context::authority(),
    domain: DomainId::parse("wonderland.universal"),
    destination: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV")
  );
}
"#,
        )
        .expect("parse literal transfer_domain helper");
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "literal transfer_domain access should be compiler-derived"
        );
    }
    #[test]
    fn lint_transfer_domain_dynamic_target_still_warns() {
        let program = parse(
            r#"
fn main() {
  let target = context::authority();
  ledger::domain::transfer(source: context::authority(), domain: DomainId::parse("wonderland.universal"), destination: target);
}
"#,
        )
        .expect("parse dynamic transfer_domain helper");
        let warnings = lint_program(&program);
        assert!(
            warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "dynamic transfer_domain access should still warn"
        );
    }
    #[test]
    fn lint_native_escrow_literal_name_is_precise_access() {
        let program = parse(
            r#"
fn main() {
  ledger::escrow::open_offer(offer: Name::parse("aitai_offer"), asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"), amount: 10);
  ledger::escrow::accept(Name::parse("aitai_offer"));
  ledger::escrow::mark_payment_sent(Name::parse("aitai_offer"));
  ledger::escrow::release(Name::parse("aitai_offer"));
  ledger::escrow::cancel(Name::parse("aitai_offer"));
  ledger::escrow::open_dispute(Name::parse("aitai_offer"));
  ledger::escrow::resolve_dispute(offer: Name::parse("aitai_offer"), buyer_amount: 6, seller_amount: 4);
}
"#,
        )
        .expect("parse native escrow literal helpers");
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "literal native escrow helpers should not warn"
        );
    }
    #[test]
    fn lint_dynamic_escrow_name_still_warns() {
        let program = parse(
            r#"
fn main() {
  let deal = Name::parse("aitai_offer");
  ledger::escrow::accept(deal);
}
"#,
        )
        .expect("parse dynamic escrow helper");
        let warnings = lint_program(&program);
        assert!(
            warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "dynamic escrow names should still warn"
        );
    }
    #[test]
    fn lint_opaque_access_hints_with_explicit_access_is_rejected() {
        let err = parse(
            r#"#[access(read="*", write="*")]
fn main() { subscription_bill(); }"#,
        )
        .expect_err("manual access hints should be rejected");
        assert!(err.contains("manual `#[access(...)]` hints are not supported"));
    }
    #[test]
    fn lint_opaque_access_hints_execute_instruction_literal_is_silent() {
        use iroha_data_model::{
            account::AccountId,
            asset::id::{AssetDefinitionId, AssetId},
            isi::{InstructionBox, Mint},
        };
        let account = AccountId::new(
            "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D"
                .parse()
                .expect("public key"),
        );
        let asset_def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::of(asset_def, account);
        let isi = InstructionBox::from(Mint::asset_quantity(1u32, asset_id));
        let bytes = norito::to_bytes(&isi).expect("encode InstructionBox");
        let hex_payload = format!("0x{}", hex::encode(bytes));
        let src = format!("fn main() {{ execute_instruction(norito_bytes(\"{hex_payload}\")); }}");
        let program = parse(&src).expect("parse execute_instruction literal");
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "literal execute_instruction payloads should not warn"
        );
    }
    #[test]
    fn lint_opaque_access_hints_execute_instruction_escrow_literal_is_silent() {
        use iroha_data_model::{
            asset::AssetDefinitionId,
            isi::{InstructionBox, escrow::OpenAssetEscrow},
        };
        let escrow_name: iroha_model_base::name::Name = "aitai_offer".parse().expect("escrow name");
        let escrow_id = iroha_data_model::escrow::EscrowId::from_kotodama_name(&escrow_name);
        let asset_def: AssetDefinitionId = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"
            .parse()
            .expect("asset definition");
        let isi = InstructionBox::from(OpenAssetEscrow::new(escrow_id, asset_def, 10_u64));
        let bytes = norito::to_bytes(&isi).expect("encode InstructionBox");
        let hex_payload = format!("0x{}", hex::encode(bytes));
        let src = format!("fn main() {{ execute_instruction(norito_bytes(\"{hex_payload}\")); }}");
        let program = parse(&src).expect("parse escrow execute_instruction literal");
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "literal escrow execute_instruction payloads should not warn"
        );
    }
    #[test]
    fn lint_opaque_access_hints_execute_query_literal_is_silent() {
        use iroha_data_model::{
            account::AccountId,
            asset::id::{AssetDefinitionId, AssetId},
            query::asset::FindAssetById,
            query::{QueryRequest, SingularQueryBox},
        };
        let account = AccountId::new(
            "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D"
                .parse()
                .expect("public key"),
        );
        let asset_def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::of(asset_def, account);
        let request = QueryRequest::Singular(SingularQueryBox::FindAssetById(FindAssetById::new(
            asset_id,
        )));
        let bytes = norito::to_bytes(&request).expect("encode QueryRequest");
        let hex_payload = format!("0x{}", hex::encode(bytes));
        let src = format!("fn main() {{ execute_query(norito_bytes(\"{hex_payload}\")); }}");
        let program = parse(&src).expect("parse execute_query literal");
        let warnings = lint_program(&program);
        assert!(
            !warnings.iter().any(|w| w.code == "opaque-access-hints"),
            "literal execute_query payloads should not warn"
        );
    }
}
