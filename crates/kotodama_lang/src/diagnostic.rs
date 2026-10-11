//! Structured diagnostics shared by the Kotodama compiler, CLI, and language tools.
use crate::source::{SourceFile, TextRange};
use norito::json::{self, Value};
use std::{error::Error as StdError, fmt};
mod source_rendering;
pub mod suggest;
/// Maximum number of diagnostics returned for one compilation request.
///
/// The cap bounds memory and renderer work for adversarial source files while
/// reserving the final slot for an explicit truncation diagnostic.
pub const MAX_DIAGNOSTICS: usize = 64;
/// Compiler phase that produced a diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticPhase {
    /// Tokenization failed.
    Lex,
    /// Parsing failed.
    Parse,
    /// Name binding or module resolution failed.
    Resolve,
    /// Type, effect, or policy analysis failed.
    Semantic,
    /// Typed lowering or optimization failed.
    Lowering,
    /// Artifact construction or verification failed.
    Artifact,
}
impl DiagnosticPhase {
    /// Stable machine-readable phase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lex => "lex",
            Self::Parse => "parse",
            Self::Resolve => "resolve",
            Self::Semantic => "semantic",
            Self::Lowering => "lowering",
            Self::Artifact => "artifact",
        }
    }
}
/// Diagnostic severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Compilation cannot continue.
    Error,
    /// Compilation can continue but the source should be changed.
    Warning,
}
impl Severity {
    /// Stable machine-readable severity name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
    const fn sarif_level(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}
/// Stable explanation and remediation for one compiler diagnostic code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticExplanation {
    /// Stable diagnostic identifier.
    pub code: &'static str,
    /// Compiler phase that owns the diagnostic.
    pub phase: DiagnosticPhase,
    /// Short description suitable for command-line help and reference tables.
    pub summary: &'static str,
    /// Concrete remediation guidance. Diagnostics with site-specific help use
    /// this only as a fallback.
    pub help: &'static str,
    /// Minimal source that triggers the diagnostic, when one is registered.
    pub bad_example: Option<&'static str>,
    /// The repaired form of [`Self::bad_example`].
    pub fixed_example: Option<&'static str>,
}
impl DiagnosticExplanation {
    /// Render the explanation as plain text for `koto explain`.
    ///
    /// The layout is deterministic: a header line, the help, and, when
    /// registered, the bad and repaired examples indented by four spaces.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut output = format!(
            "{} [{}]: {}\nhelp: {}",
            self.code,
            self.phase.as_str(),
            self.summary,
            self.help
        );
        for (heading, example) in [("example", self.bad_example), ("fixed", self.fixed_example)] {
            if let Some(example) = example {
                output.push_str("\n\n");
                output.push_str(heading);
                output.push(':');
                for line in example.lines() {
                    output.push_str("\n    ");
                    output.push_str(line);
                }
            }
        }
        output
    }
}
include!(concat!(
    env!("OUT_DIR"),
    "/kotodama_diagnostic_explanations.rs"
));
/// Preserve resolver ownership when a later typed-analysis adapter surfaces a
/// diagnostic whose canonical registry entry belongs to resolution.
///
/// The semantic analyzer consumes resolved HIR and can therefore detect a stale or inconsistent
/// resolver result. Other semantic failures retain their actual semantic phase, including
/// cross-phase fanout diagnostics such as `K0004`.
pub(crate) fn phase_for_semantic_failure(code: &str) -> DiagnosticPhase {
    match diagnostic_explanation(code) {
        Some(explanation) if explanation.phase == DiagnosticPhase::Resolve => {
            DiagnosticPhase::Resolve
        }
        _ => DiagnosticPhase::Semantic,
    }
}
/// Look up a canonical diagnostic explanation by case-insensitive code.
#[must_use]
pub fn diagnostic_explanation(code: &str) -> Option<&'static DiagnosticExplanation> {
    DIAGNOSTIC_EXPLANATIONS
        .iter()
        .find(|explanation| explanation.code.eq_ignore_ascii_case(code))
}
/// One source position using one-based line and column numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourcePosition {
    /// One-based source line.
    pub line: usize,
    /// One-based UTF-8 display column.
    pub column: usize,
}
/// Half-open source range attached to a diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSpan {
    /// Exact locked package identity, when the span belongs to a reusable
    /// package rather than the deployable root.
    pub package_identity: Option<String>,
    /// Logical source path, when known.
    pub source: Option<String>,
    /// First covered position.
    pub start: SourcePosition,
    /// Position immediately after the range.
    pub end: SourcePosition,
    /// Exact half-open UTF-8 byte range when the source text is available.
    ///
    /// Line and column positions are retained for humans and SARIF consumers, while this range
    /// makes diagnostics unambiguous in the presence of multi-byte Unicode text.
    pub byte_range: Option<TextRange>,
}
impl SourceSpan {
    /// Convert an exact source-file byte range into the canonical diagnostic span.
    #[must_use]
    pub fn from_range(source: &SourceFile, range: TextRange) -> Self {
        let start = source.line_column(range.start);
        let end = source.line_column(range.end);
        Self {
            package_identity: source.package_identity().map(str::to_owned),
            source: Some(source.name().to_owned()),
            start: SourcePosition {
                line: start.line,
                column: start.column,
            },
            end: SourcePosition {
                line: end.line,
                column: end.column,
            },
            byte_range: Some(range),
        }
    }
}
/// Secondary source label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticLabel {
    /// Labeled range.
    pub span: SourceSpan,
    /// Explanation for the range.
    pub message: String,
}
/// Machine-applicable source replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticFix {
    /// Range to replace.
    pub span: SourceSpan,
    /// Replacement text.
    pub replacement: String,
}
/// Translated presentation of one diagnostic for human readers.
///
/// Machine-readable records always carry the canonical English `message`; this
/// optional companion is rendered for humans only when it translates every
/// piece of prose in the diagnostic, so one diagnostic never mixes languages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalizedText {
    /// BCP 47 language tag of the translation, for example `ja`.
    pub language: String,
    /// Translated primary message.
    pub message: String,
    /// Translated help, when the diagnostic has help and it is translated.
    pub help: Option<String>,
}
/// One stable, structured compiler diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// Stable Kotodama diagnostic code.
    pub code: String,
    /// Severity.
    pub severity: Severity,
    /// Producing phase.
    pub phase: DiagnosticPhase,
    /// Primary human-readable message.
    pub message: String,
    /// Primary source range, when available.
    pub primary_span: Option<SourceSpan>,
    /// Additional labeled ranges.
    pub labels: Vec<DiagnosticLabel>,
    /// Contextual notes.
    pub notes: Vec<String>,
    /// Suggested next action.
    pub help: Option<String>,
    /// Optional machine-applicable replacement.
    pub fix: Option<DiagnosticFix>,
    /// Further machine-applicable replacements that are equally valid
    /// alternatives to [`Self::fix`], such as the other spelling of a branded
    /// keyword. They are never applied automatically.
    pub alternative_fixes: Vec<DiagnosticFix>,
    /// Optional translated message and help for human rendering.
    pub localized: Option<LocalizedText>,
    /// Immutable source captured when the primary diagnostic was produced.
    ///
    /// Source text is presentation data and is never added to JSON/SARIF records.
    pub primary_source: Option<SourceFile>,
    /// Immutable source for each related label, in label order.
    pub label_sources: Vec<Option<SourceFile>>,
}
impl Diagnostic {
    fn new(
        code: String,
        severity: Severity,
        phase: DiagnosticPhase,
        message: String,
        primary_span: Option<SourceSpan>,
    ) -> Self {
        // Registry help is the fallback; emitters with site-specific guidance
        // replace it through [`Self::with_help`].
        let help = diagnostic_explanation(&code).map(|entry| entry.help.to_owned());
        Self {
            code,
            severity,
            phase,
            message,
            primary_span,
            labels: Vec::new(),
            notes: Vec::new(),
            help,
            fix: None,
            alternative_fixes: Vec::new(),
            localized: None,
            primary_source: None,
            label_sources: Vec::new(),
        }
    }
    /// Construct a native compiler error with an explicit stable code and span.
    pub fn error(
        code: impl Into<String>,
        phase: DiagnosticPhase,
        message: impl Into<String>,
        primary_span: Option<SourceSpan>,
    ) -> Self {
        Self::new(
            code.into(),
            Severity::Error,
            phase,
            message.into(),
            primary_span,
        )
    }
    /// Construct a non-fatal warning with an explicit stable code and span.
    pub fn warning(
        code: impl Into<String>,
        phase: DiagnosticPhase,
        message: impl Into<String>,
        primary_span: Option<SourceSpan>,
    ) -> Self {
        Self::new(
            code.into(),
            Severity::Warning,
            phase,
            message.into(),
            primary_span,
        )
    }
    /// Replace the registry fallback help with site-specific guidance.
    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
    /// Attach a translated presentation.
    ///
    /// `message` stays canonical English for JSON, SARIF and tooling. Human
    /// rendering uses the translation only when it covers the help as well and
    /// the diagnostic has no untranslated notes or labels.
    #[must_use]
    pub fn with_localized(
        mut self,
        language: impl Into<String>,
        message: impl Into<String>,
        help: Option<String>,
    ) -> Self {
        self.localized = Some(LocalizedText {
            language: language.into(),
            message: message.into(),
            help,
        });
        self
    }
    /// The message and help a human reader sees: the translation when it is
    /// complete for this diagnostic, otherwise the canonical English pair.
    #[must_use]
    pub fn presented_text(&self) -> (&str, Option<&str>) {
        match &self.localized {
            Some(localized)
                if (self.help.is_none() || localized.help.is_some())
                    && self.notes.is_empty()
                    && self.labels.is_empty() =>
            {
                (localized.message.as_str(), localized.help.as_deref())
            }
            _ => (self.message.as_str(), self.help.as_deref()),
        }
    }
    /// Every machine-applicable fix, primary first.
    pub fn fixes(&self) -> impl Iterator<Item = &DiagnosticFix> {
        self.fix.iter().chain(&self.alternative_fixes)
    }
    /// Retain source text for matching primary and related locations.
    ///
    /// Capture precedes frontend path remapping, so later rendering cannot accidentally
    /// display an edited file or a different dependency with the same logical path.
    pub fn capture_source(&mut self, source: &SourceFile) {
        let owns = |span: &SourceSpan| {
            span.source.as_deref() == Some(source.name())
                && span.package_identity.as_deref() == source.package_identity()
        };
        if self.primary_span.as_ref().is_some_and(owns) {
            self.primary_source = Some(source.clone());
        }
        self.label_sources.resize(self.labels.len(), None);
        for (label, captured) in self.labels.iter().zip(&mut self.label_sources) {
            if owns(&label.span) {
                *captured = Some(source.clone());
            }
        }
    }
    /// Capture the immutable source while constructing this diagnostic.
    #[must_use]
    pub fn with_source(mut self, source: &SourceFile) -> Self {
        self.capture_source(source);
        self
    }
    /// Return the canonical JSON representation used by every diagnostic renderer.
    pub fn to_json_value(&self) -> Value {
        json_object(vec![
            json_entry("code", Value::from(self.code.clone())),
            json_entry("severity", Value::from(self.severity.as_str())),
            json_entry("phase", Value::from(self.phase.as_str())),
            json_entry("message", Value::from(self.message.clone())),
            json_entry(
                "primary_span",
                self.primary_span
                    .as_ref()
                    .map_or(Value::Null, source_span_to_json),
            ),
            json_entry(
                "labels",
                Value::Array(
                    self.labels
                        .iter()
                        .map(|label| {
                            json_object(vec![
                                json_entry("span", source_span_to_json(&label.span)),
                                json_entry("message", Value::from(label.message.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
            json_entry(
                "notes",
                Value::Array(self.notes.iter().cloned().map(Value::from).collect()),
            ),
            json_entry("help", self.help.clone().map_or(Value::Null, Value::from)),
            json_entry("fix", self.fix.as_ref().map_or(Value::Null, fix_to_json)),
            json_entry(
                "alternative_fixes",
                Value::Array(self.alternative_fixes.iter().map(fix_to_json).collect()),
            ),
            json_entry(
                "localized",
                self.localized.as_ref().map_or(Value::Null, |localized| {
                    json_object(vec![
                        json_entry("language", Value::from(localized.language.clone())),
                        json_entry("message", Value::from(localized.message.clone())),
                        json_entry(
                            "help",
                            localized.help.clone().map_or(Value::Null, Value::from),
                        ),
                    ])
                }),
            ),
        ])
    }
    fn to_sarif_result(&self, rule_index: Option<usize>) -> Value {
        let locations = self.primary_span.as_ref().map_or_else(Vec::new, |span| {
            vec![json_object(vec![json_entry(
                "physicalLocation",
                source_span_to_sarif(span),
            )])]
        });
        let related_locations = self
            .labels
            .iter()
            .enumerate()
            .map(|(index, label)| {
                json_object(vec![
                    json_entry("id", Value::from(index as u64 + 1)),
                    json_entry("physicalLocation", source_span_to_sarif(&label.span)),
                    json_entry(
                        "message",
                        json_object(vec![json_entry("text", Value::from(label.message.clone()))]),
                    ),
                ])
            })
            .collect();
        let fixes = self.fixes().map(fix_to_sarif).collect();
        let mut entries = vec![json_entry("ruleId", Value::from(self.code.clone()))];
        if let Some(rule_index) = rule_index {
            entries.push(json_entry("ruleIndex", Value::from(rule_index as u64)));
        }
        entries.extend([
            json_entry("level", Value::from(self.severity.sarif_level())),
            json_entry(
                "message",
                json_object(vec![json_entry("text", Value::from(self.message.clone()))]),
            ),
            json_entry("locations", Value::Array(locations)),
            json_entry("relatedLocations", Value::Array(related_locations)),
            json_entry("fixes", Value::Array(fixes)),
            // Keeping the canonical record in SARIF properties guarantees that JSON and
            // SARIF consumers observe exactly the same semantic fields, including fixes.
            json_entry(
                "properties",
                json_object(vec![json_entry("kotodama", self.to_json_value())]),
            ),
        ]);
        json_object(entries)
    }
}
fn fix_to_json(fix: &DiagnosticFix) -> Value {
    json_object(vec![
        json_entry("span", source_span_to_json(&fix.span)),
        json_entry("replacement", Value::from(fix.replacement.clone())),
    ])
}
/// One SARIF 2.1.0 `fix` object replacing the fix span with its text.
fn fix_to_sarif(fix: &DiagnosticFix) -> Value {
    let artifact_location = sarif_artifact_location(&fix.span);
    let region = sarif_region(&fix.span);
    let description = if fix.replacement.is_empty() {
        "Delete the highlighted source".to_owned()
    } else {
        format!("Replace with {}", code_literal(&fix.replacement))
    };
    json_object(vec![
        json_entry(
            "description",
            json_object(vec![json_entry("text", Value::from(description))]),
        ),
        json_entry(
            "artifactChanges",
            Value::Array(vec![json_object(vec![
                json_entry("artifactLocation", artifact_location),
                json_entry(
                    "replacements",
                    Value::Array(vec![json_object(vec![
                        json_entry("deletedRegion", region),
                        json_entry(
                            "insertedContent",
                            json_object(vec![json_entry(
                                "text",
                                Value::from(fix.replacement.clone()),
                            )]),
                        ),
                    ])]),
                ),
            ])]),
        ),
    ])
}
/// Quote source text for prose: backticks for single-line text without
/// backticks, a Rust-style escaped string otherwise. Invisible characters
/// (controls, format characters such as bidirectional overrides, and
/// non-ASCII spaces) are written as `<U+XXXX>` so they cannot disturb the
/// terminal, hide in the rendered fix, or be confused with an escape that a
/// fix inserts.
fn code_literal(text: &str) -> String {
    if text.contains(['`', '\n', '\r']) {
        return format!("{text:?}");
    }
    let visible = text
        .chars()
        .map(|character| {
            let invisible = character.is_control()
                || (!character.is_ascii() && character.is_whitespace())
                || matches!(character,
                    '\u{00ad}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}'
                    | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}');
            if invisible {
                format!("<U+{:04X}>", u32::from(character))
            } else {
                character.to_string()
            }
        })
        .collect::<String>();
    format!("`{visible}`")
}
fn json_entry(key: impl Into<String>, value: Value) -> (String, Value) {
    (key.into(), value)
}
fn json_object(entries: Vec<(String, Value)>) -> Value {
    json::object(entries).unwrap_or(Value::Null)
}
fn source_position_to_json(position: SourcePosition) -> Value {
    json_object(vec![
        json_entry("line", Value::from(position.line as u64)),
        json_entry("column", Value::from(position.column as u64)),
    ])
}
fn display_source_span(span: &SourceSpan) -> String {
    let source = span.source.as_deref().unwrap_or("<source>");
    span.package_identity.as_ref().map_or_else(
        || source.to_owned(),
        |package| format!("{package}::{source}"),
    )
}
fn source_span_to_json(span: &SourceSpan) -> Value {
    json_object(vec![
        json_entry(
            "package_identity",
            span.package_identity
                .clone()
                .map_or(Value::Null, Value::from),
        ),
        json_entry(
            "source",
            span.source.clone().map_or(Value::Null, Value::from),
        ),
        json_entry("start", source_position_to_json(span.start)),
        json_entry("end", source_position_to_json(span.end)),
        json_entry(
            "byte_range",
            span.byte_range.map_or(Value::Null, |range| {
                json_object(vec![
                    json_entry("start", Value::from(u64::from(range.start))),
                    json_entry("end", Value::from(u64::from(range.end))),
                ])
            }),
        ),
    ])
}
fn source_span_to_sarif(span: &SourceSpan) -> Value {
    json_object(vec![
        json_entry("artifactLocation", sarif_artifact_location(span)),
        json_entry("region", sarif_region(span)),
    ])
}
fn sarif_artifact_location(span: &SourceSpan) -> Value {
    span.source.as_ref().map_or(Value::Null, |source| {
        json_object(vec![json_entry("uri", Value::from(source.clone()))])
    })
}
fn sarif_region(span: &SourceSpan) -> Value {
    let mut region = vec![
        json_entry("startLine", Value::from(span.start.line as u64)),
        json_entry("startColumn", Value::from(span.start.column as u64)),
        json_entry("endLine", Value::from(span.end.line as u64)),
        json_entry("endColumn", Value::from(span.end.column as u64)),
    ];
    if let Some(range) = span.byte_range {
        region.push(json_entry(
            "byteOffset",
            Value::from(u64::from(range.start)),
        ));
        region.push(json_entry(
            "byteLength",
            Value::from(u64::from(range.len())),
        ));
    }
    json_object(region)
}
/// Collection of diagnostics returned by a failed compiler operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticBundle {
    /// Diagnostics in deterministic source order.
    pub diagnostics: Vec<Diagnostic>,
}
impl DiagnosticBundle {
    /// Attach one immutable source snapshot to every matching diagnostic location.
    pub fn capture_source(&mut self, source: &SourceFile) {
        for diagnostic in &mut self.diagnostics {
            diagnostic.capture_source(source);
        }
    }
    /// Build a bundle and normalize it into deterministic source order.
    pub fn new(mut diagnostics: Vec<Diagnostic>) -> Self {
        fn compare(left: &Diagnostic, right: &Diagnostic) -> std::cmp::Ordering {
            let left_span = left.primary_span.as_ref();
            let right_span = right.primary_span.as_ref();
            left_span
                .is_none()
                .cmp(&right_span.is_none())
                .then_with(|| {
                    left_span
                        .and_then(|span| span.package_identity.as_deref())
                        .cmp(&right_span.and_then(|span| span.package_identity.as_deref()))
                })
                .then_with(|| {
                    left_span
                        .and_then(|span| span.source.as_deref())
                        .cmp(&right_span.and_then(|span| span.source.as_deref()))
                })
                .then_with(|| {
                    left_span
                        .map(|span| (span.start.line, span.start.column))
                        .cmp(&right_span.map(|span| (span.start.line, span.start.column)))
                })
                .then_with(|| left.phase.as_str().cmp(right.phase.as_str()))
                .then_with(|| left.code.cmp(&right.code))
                .then_with(|| left.message.cmp(&right.message))
        }
        if diagnostics.len() > MAX_DIAGNOSTICS {
            let omitted = diagnostics.len() - (MAX_DIAGNOSTICS - 1);
            let has_errors = diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Error);
            diagnostics.sort_by(|left, right| {
                let severity_rank = |severity| match severity {
                    Severity::Error => 0_u8,
                    Severity::Warning => 1_u8,
                };
                severity_rank(left.severity)
                    .cmp(&severity_rank(right.severity))
                    .then_with(|| compare(left, right))
            });
            let phase = diagnostics[MAX_DIAGNOSTICS - 1].phase;
            diagnostics.truncate(MAX_DIAGNOSTICS - 1);
            let message = format!(
                "diagnostic limit reached; {omitted} additional diagnostic(s) were omitted"
            );
            diagnostics.push(if has_errors {
                Diagnostic::error("K0004", phase, message, None)
            } else {
                Diagnostic::warning("K0004", phase, message, None)
            });
        }
        diagnostics.sort_by(compare);
        Self { diagnostics }
    }
    /// Build a bundle containing one native compiler error.
    pub fn single(diagnostic: Diagnostic) -> Self {
        Self::new(vec![diagnostic])
    }
    /// Render deterministic human-readable diagnostics.
    ///
    /// Locations show line and column ranges; exact byte ranges stay in the
    /// JSON and SARIF records. A diagnostic's translation is used only when it
    /// is complete (see [`Diagnostic::presented_text`]).
    pub fn render_human(&self) -> String {
        use std::fmt::Write as _;
        let mut output = String::new();
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            if index != 0 {
                output.push('\n');
            }
            let (message, help) = diagnostic.presented_text();
            let _ = write!(
                output,
                "{}[{}] {}: {}",
                diagnostic.severity.as_str(),
                diagnostic.code,
                diagnostic.phase.as_str(),
                message
            );
            if let Some(span) = &diagnostic.primary_span {
                let _ = write!(output, "\n  --> {}", display_position(span));
                if let Some(source) = &diagnostic.primary_source {
                    source_rendering::render(&mut output, source, span);
                }
            }
            for (index, label) in diagnostic.labels.iter().enumerate() {
                let _ = write!(
                    output,
                    "\n  = label: {}: {}",
                    display_position(&label.span),
                    label.message
                );
                if let Some(Some(source)) = diagnostic.label_sources.get(index) {
                    source_rendering::render(&mut output, source, &label.span);
                }
            }
            for note in &diagnostic.notes {
                let _ = write!(output, "\n  = note: {note}");
            }
            if let Some(help) = help {
                let _ = write!(output, "\n  = help: {help}");
            }
            render_fixes(&mut output, diagnostic);
        }
        output
    }
    /// Rewrite absolute source paths below `base` as `base`-relative paths.
    ///
    /// Command-line tools call this with the working directory so parse and
    /// semantic diagnostics name files the same way. Logical and package
    /// paths are left untouched.
    pub fn relativize_sources(&mut self, base: &std::path::Path) {
        let relativize = |span: &mut SourceSpan| {
            let Some(source) = span.source.as_deref() else {
                return;
            };
            let path = std::path::Path::new(source);
            if !path.is_absolute() {
                return;
            }
            if let Ok(relative) = path.strip_prefix(base)
                && !relative.as_os_str().is_empty()
                && let Some(relative) = relative.to_str()
            {
                span.source = Some(relative.replace(std::path::MAIN_SEPARATOR, "/"));
            }
        };
        for diagnostic in &mut self.diagnostics {
            if let Some(span) = &mut diagnostic.primary_span {
                relativize(span);
            }
            for label in &mut diagnostic.labels {
                relativize(&mut label.span);
            }
            if let Some(fix) = &mut diagnostic.fix {
                relativize(&mut fix.span);
            }
            for fix in &mut diagnostic.alternative_fixes {
                relativize(&mut fix.span);
            }
        }
    }
    /// Render the canonical diagnostic array as pretty JSON.
    pub fn render_json(&self) -> Result<String, json::Error> {
        json::to_string_pretty(&Value::Array(
            self.diagnostics
                .iter()
                .map(Diagnostic::to_json_value)
                .collect(),
        ))
    }
    /// Render SARIF 2.1.0 while preserving the canonical diagnostic records.
    pub fn render_sarif(&self) -> Result<String, json::Error> {
        // One rule per distinct code, in first-occurrence order; results refer
        // to their rule by index.
        let mut rule_codes = Vec::<&str>::new();
        let results = self
            .diagnostics
            .iter()
            .map(|diagnostic| {
                let index = rule_codes
                    .iter()
                    .position(|code| *code == diagnostic.code)
                    .unwrap_or_else(|| {
                        rule_codes.push(&diagnostic.code);
                        rule_codes.len() - 1
                    });
                diagnostic.to_sarif_result(Some(index))
            })
            .collect();
        let rules = rule_codes
            .iter()
            .map(|code| {
                let first = self
                    .diagnostics
                    .iter()
                    .find(|diagnostic| diagnostic.code == *code);
                sarif_rule(code, first)
            })
            .collect();
        let sarif = json_object(vec![
            json_entry("version", Value::from("2.1.0")),
            json_entry(
                "$schema",
                Value::from("https://json.schemastore.org/sarif-2.1.0.json"),
            ),
            json_entry(
                "runs",
                Value::Array(vec![json_object(vec![
                    json_entry(
                        "tool",
                        json_object(vec![json_entry(
                            "driver",
                            json_object(vec![
                                json_entry("name", Value::from("Kotodama")),
                                json_entry("rules", Value::Array(rules)),
                            ]),
                        )]),
                    ),
                    json_entry("results", Value::Array(results)),
                ])]),
            ),
        ]);
        json::to_string_pretty(&sarif)
    }
}
/// SARIF rule metadata for one diagnostic code, taken from the registry.
fn sarif_rule(code: &str, first: Option<&Diagnostic>) -> Value {
    let explanation = diagnostic_explanation(code);
    let short = explanation.map_or_else(
        || first.map_or_else(String::new, |diagnostic| diagnostic.message.clone()),
        |entry| entry.summary.to_owned(),
    );
    let mut entries = vec![
        json_entry("id", Value::from(code.to_owned())),
        json_entry(
            "shortDescription",
            json_object(vec![json_entry("text", Value::from(short))]),
        ),
    ];
    if let Some(explanation) = explanation {
        entries.push(json_entry(
            "fullDescription",
            json_object(vec![json_entry("text", Value::from(explanation.help))]),
        ));
        entries.push(json_entry(
            "help",
            json_object(vec![json_entry(
                "text",
                Value::from(explanation.render_text()),
            )]),
        ));
        entries.push(json_entry(
            "properties",
            json_object(vec![json_entry(
                "phase",
                Value::from(explanation.phase.as_str()),
            )]),
        ));
    }
    json_object(entries)
}
/// `path:line:column`, the human form of where a span starts.
///
/// The underlined excerpt shows the span's extent, so the location names only
/// its start; JSON and SARIF keep the complete range.
fn display_position(span: &SourceSpan) -> String {
    format!(
        "{}:{}:{}",
        display_source_span(span),
        span.start.line,
        span.start.column
    )
}
/// `path:line:column-line:column`, the human form of a complete span, used
/// where no excerpt shows the extent (a fix outside the captured source).
fn display_location(span: &SourceSpan) -> String {
    format!(
        "{}:{}:{}-{}:{}",
        display_source_span(span),
        span.start.line,
        span.start.column,
        span.end.line,
        span.end.column
    )
}
/// Render the primary fix and its alternatives as `= fix:` lines.
///
/// A fix whose span lies on one line of the captured source is shown as an
/// edit of that text (`replace `contract` with `seiyaku``); alternatives on the
/// same span are joined with `or`.
fn render_fixes(output: &mut String, diagnostic: &Diagnostic) {
    use std::fmt::Write as _;
    let Some(primary) = &diagnostic.fix else {
        return;
    };
    let source_text = |fix: &DiagnosticFix| -> Option<String> {
        let source = diagnostic.primary_source.as_ref()?;
        let owner = diagnostic.primary_span.as_ref()?;
        if owner.source != fix.span.source || owner.package_identity != fix.span.package_identity {
            return None;
        }
        let text = source.slice(fix.span.byte_range?)?;
        (!text.contains('\n')).then(|| text.to_owned())
    };
    let describe = |fix: &DiagnosticFix, replacements: &[&str]| -> String {
        // An insertion that starts a new line, such as a missing `}`, reads as
        // "on a new line" rather than as an escaped string.
        if let [replacement] = replacements
            && let Some(rest) = replacement.strip_prefix('\n')
            && !rest.contains('\n')
            && !rest.trim().is_empty()
            && source_text(fix).is_some_and(|original| original.is_empty())
        {
            return format!("insert {} on a new line", code_literal(rest.trim_start()));
        }
        let quoted = replacements
            .iter()
            .map(|replacement| code_literal(replacement))
            .collect::<Vec<_>>();
        let joined = match quoted.split_last() {
            Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
            _ => quoted.concat(),
        };
        match source_text(fix) {
            Some(original) if original.is_empty() => format!("insert {joined}"),
            Some(original) if replacements.iter().all(|r| r.is_empty()) => {
                format!("delete {}", code_literal(&original))
            }
            Some(original) => format!("replace {} with {joined}", code_literal(&original)),
            None => format!("replace {} with {joined}", display_location(&fix.span)),
        }
    };
    let same_span = diagnostic
        .alternative_fixes
        .iter()
        .all(|alternative| alternative.span == primary.span);
    if same_span {
        let replacements = diagnostic
            .fixes()
            .map(|fix| fix.replacement.as_str())
            .collect::<Vec<_>>();
        let _ = write!(output, "\n  = fix: {}", describe(primary, &replacements));
    } else {
        for fix in diagnostic.fixes() {
            let _ = write!(
                output,
                "\n  = fix: {}",
                describe(fix, &[fix.replacement.as_str()])
            );
        }
    }
}
impl fmt::Display for DiagnosticBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render_human())
    }
}
impl StdError for DiagnosticBundle {}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explanation_registry_is_unique_and_case_insensitive() {
        let mut codes = std::collections::BTreeSet::new();
        for explanation in DIAGNOSTIC_EXPLANATIONS {
            assert!(
                codes.insert(explanation.code),
                "duplicate explanation for {}",
                explanation.code
            );
            assert!(!explanation.summary.is_empty());
            assert!(!explanation.help.is_empty());
        }
        assert_eq!(
            diagnostic_explanation("k1001").map(|entry| entry.code),
            Some("K1001")
        );
        assert!(diagnostic_explanation("NOT_A_CODE").is_none());
    }
    #[test]
    fn every_frontend_code_literal_has_a_canonical_explanation() {
        fn is_diagnostic_code(candidate: &str) -> bool {
            (candidate.strip_prefix("E_").is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit()
                    })
            })) || (candidate.len() == 5
                && candidate.starts_with('K')
                && candidate[1..].bytes().all(|byte| byte.is_ascii_digit()))
        }
        let source_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut missing = std::collections::BTreeMap::<String, Vec<String>>::new();
        for entry in std::fs::read_dir(source_dir).expect("read Kotodama frontend sources") {
            let entry = entry.expect("read Kotodama frontend source entry");
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read Kotodama frontend source");
            for (quote, _) in source.match_indices('"') {
                let remainder = &source[quote + 1..];
                let length = remainder
                    .bytes()
                    .take_while(|byte| {
                        byte.is_ascii_uppercase() || *byte == b'_' || byte.is_ascii_digit()
                    })
                    .count();
                if remainder.as_bytes().get(length) != Some(&b'"') {
                    continue;
                }
                let code = &remainder[..length];
                if !is_diagnostic_code(code)
                    || matches!(code, "E_FIRST" | "E_SECOND" | "E_THIRD")
                    || diagnostic_explanation(code).is_some()
                {
                    continue;
                }
                missing.entry(code.to_owned()).or_default().push(
                    path.file_name()
                        .and_then(std::ffi::OsStr::to_str)
                        .unwrap_or("<unknown>")
                        .to_owned(),
                );
            }
        }
        assert!(
            missing.is_empty(),
            "frontend diagnostic codes missing from `koto explain`: {missing:?}"
        );
    }
    #[test]
    fn resolve_explanations_match_public_session_emitters() {
        use crate::session::{CompileRequest, CompilerSession};
        for (code, source) in [
            (
                "K2002",
                "seiyaku Unknown { view fn run() authorize(anyone) -> int { return missing; } }",
            ),
            (
                "E_DUPLICATE_DECLARATION",
                "seiyaku Duplicate { fn repeated() {} fn repeated() {} }",
            ),
            (
                "E_RESERVED_DECLARATION",
                "seiyaku Reserved { fn __kotodama_list_len() -> int { return 1; } }",
            ),
            (
                "E_LOCAL_SHADOWING",
                "seiyaku Shadow { const int limit = 1; view fn run(int limit) authorize(anyone) -> int { return limit; } }",
            ),
        ] {
            let diagnostics = CompilerSession::default()
                .check(CompileRequest {
                    source,
                    source_name: Some("phase-parity.ko"),
                })
                .expect_err("resolver fixture must fail");
            let emitted = diagnostics
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .unwrap_or_else(|| panic!("fixture did not emit {code}: {diagnostics:?}"));
            let explanation = diagnostic_explanation(code)
                .unwrap_or_else(|| panic!("{code} must work with `koto explain`"));
            assert_eq!(emitted.phase, DiagnosticPhase::Resolve, "{code}");
            assert_eq!(explanation.phase, emitted.phase, "{code}");
        }
    }
    #[test]
    fn fixed_source_graph_and_linker_codes_are_explainable() {
        for code in ["K1004", "E_PACKAGE_BUDGET"] {
            let explanation = diagnostic_explanation(code)
                .unwrap_or_else(|| panic!("{code} must work with `koto explain`"));
            assert_eq!(explanation.phase, DiagnosticPhase::Parse, "{code}");
        }
        for code in [
            "K2002",
            "K2099",
            "E_ROOT_MUST_BE_SEIYAKU",
            "E_DEPENDENCY_MUST_BE_MODULE",
            "E_DUPLICATE_PACKAGE",
            "E_EMPTY_PACKAGE",
            "E_DUPLICATE_MODULE",
            "E_DUPLICATE_IMPORT",
            "E_RESERVED_IMPORT",
            "E_DUPLICATE_DECLARATION",
            "E_UNKNOWN_PACKAGE",
            "E_PACKAGE_IMPORT_CYCLE",
            "E_UNKNOWN_IMPORT_ALIAS",
            "E_MULTIPLE_SEIYAKU_ROOTS",
            "E_PROJECT_MANIFEST_REQUIRED",
            "E_PROJECT_MANIFEST",
            "E_UNEXPORTED_SYMBOL",
            "E_MISSING_EXPORT",
            "E_AMBIGUOUS_EXPORT",
            "E_WILDCARD_IMPORT",
            "E_INVALID_IDENTIFIER",
            "E_RESERVED_DECLARATION",
            "E_INVALID_MODULE_ITEM",
            "E_CONFLICTING_ERROR_TYPE",
            "E_DUPLICATE_MESSAGE",
            "E_INVALID_SOURCE_PATH",
            "E_DUPLICATE_SOURCE",
            "E_EMPTY_PACKAGE_GRAPH",
            "E_DUPLICATE_HIR_ID",
            "E_DUPLICATE_SOURCE_ID",
            "E_TEST_TARGET_MISMATCH",
            "E_LOCAL_SHADOWING",
            "E_INTERNAL_RESOLUTION",
        ] {
            let explanation = diagnostic_explanation(code)
                .unwrap_or_else(|| panic!("{code} must work with `koto explain`"));
            assert_eq!(explanation.phase, DiagnosticPhase::Resolve, "{code}");
        }
        assert_eq!(
            diagnostic_explanation("K2098").map(|entry| entry.phase),
            Some(DiagnosticPhase::Semantic),
            "the semantic ABI fallback must not reuse the resolver-owned K2099 code",
        );
    }
    #[test]
    fn v1_data_processing_diagnostics_are_explainable() {
        for code in [
            "E_DIVISION_BY_ZERO",
            "E_REPEATING_DECIMAL",
            "E_EXACT_DIVISION_SCALE_OVERFLOW",
            "E_INEXACT_CONVERSION",
            "E_QUANTITY_UNDERFLOW",
            "E_QUANTITY_REMAINDER",
            "E_QUANTITY_NEGATION",
            "E_QUORUM_RANGE",
            "E_NUMERIC_ROUND_ARITY",
            "E_NUMERIC_ROUND_RECEIVER",
            "E_INVALID_SCALE",
            "E_NUMERIC_ROUNDING_MODE",
            "E_DIVERGING_EXPRESSION_CONTEXT",
            "E_LIST_CONTAINS_COMPARABILITY",
        ] {
            let explanation = diagnostic_explanation(code)
                .unwrap_or_else(|| panic!("{code} must be registered for `koto explain`"));
            assert_eq!(explanation.phase, DiagnosticPhase::Semantic, "{code}");
        }
    }
    #[test]
    fn every_renderer_contains_the_same_canonical_fields() {
        let primary_span = SourceSpan {
            package_identity: Some("std/example@1.0.0".to_owned()),
            source: Some("seiyaku.ko".to_owned()),
            start: SourcePosition { line: 3, column: 5 },
            end: SourcePosition { line: 3, column: 6 },
            byte_range: Some(crate::source::TextRange::new(12, 13)),
        };
        let mut diagnostic = Diagnostic::error(
            "K2001",
            DiagnosticPhase::Semantic,
            "unknown name",
            Some(primary_span),
        );
        diagnostic.labels.push(DiagnosticLabel {
            span: diagnostic.primary_span.clone().expect("span"),
            message: "not declared in this scope".to_owned(),
        });
        diagnostic.notes.push("names are case-sensitive".to_owned());
        diagnostic.help = Some("declare the value before use".to_owned());
        diagnostic.fix = Some(DiagnosticFix {
            span: diagnostic.primary_span.clone().expect("span"),
            replacement: "known_name".to_owned(),
        });
        let bundle = DiagnosticBundle {
            diagnostics: vec![diagnostic.clone()],
        };
        let human = bundle.render_human();
        for expected in [
            "K2001",
            "semantic",
            "seiyaku.ko:3:5",
            "not declared in this scope",
            "names are case-sensitive",
            "declare the value before use",
            "known_name",
        ] {
            assert!(human.contains(expected), "missing {expected:?}: {human}");
        }
        let rendered_json = bundle.render_json().expect("JSON diagnostics");
        let rendered_sarif = bundle.render_sarif().expect("SARIF diagnostics");
        for expected in [
            "K2001",
            "semantic",
            "seiyaku.ko",
            "not declared in this scope",
            "names are case-sensitive",
            "declare the value before use",
            "known_name",
        ] {
            assert!(
                rendered_json.contains(expected),
                "JSON missing {expected:?}"
            );
            assert!(
                rendered_sarif.contains(expected),
                "SARIF missing {expected:?}"
            );
        }
        assert!(rendered_sarif.contains("2.1.0"));
        let json_value: Value =
            json::from_str(&rendered_json).expect("decode canonical JSON diagnostics");
        let sarif_value: Value = json::from_str(&rendered_sarif).expect("decode SARIF diagnostics");
        let canonical = json_value
            .as_array()
            .and_then(|diagnostics| diagnostics.first())
            .expect("one canonical diagnostic");
        let embedded = sarif_value
            .pointer("/runs/0/results/0/properties/kotodama")
            .expect("SARIF embeds the canonical diagnostic");
        assert_eq!(canonical, embedded);
        assert!(human.contains("seiyaku.ko:3:5"));
        assert!(
            !human.contains("--> seiyaku.ko:3:5-3:6")
                && !human.contains("= label: seiyaku.ko:3:5-3:6"),
            "human primary and label locations name the start"
        );
    }
    fn fixture_diagnostic(text: &str, start: usize, end: usize) -> (SourceFile, Diagnostic) {
        let source = SourceFile::new(crate::source::SourceId(0), "fix.ko", text);
        let span = SourceSpan::from_range(&source, TextRange::new(start as u32, end as u32));
        let diagnostic = Diagnostic::error("K1001", DiagnosticPhase::Parse, "message", Some(span))
            .with_source(&source);
        (source, diagnostic)
    }
    #[test]
    fn human_rendering_omits_byte_ranges_and_shows_fixes_as_edits() {
        let (source, mut diagnostic) = fixture_diagnostic("contract S {}", 0, 8);
        let span = diagnostic.primary_span.clone().expect("span");
        diagnostic.fix = Some(DiagnosticFix {
            span: span.clone(),
            replacement: "seiyaku".to_owned(),
        });
        diagnostic.alternative_fixes.push(DiagnosticFix {
            span,
            replacement: "誓約".to_owned(),
        });
        let human = DiagnosticBundle::single(diagnostic).render_human();
        assert!(!human.contains("[bytes"), "{human}");
        assert!(human.contains("--> fix.ko:1:1"), "{human}");
        assert!(
            human.ends_with("= fix: replace `contract` with `seiyaku` or `誓約`"),
            "{human}"
        );
        let insertion = SourceSpan::from_range(&source, TextRange::empty(13));
        let (_, mut diagnostic) = fixture_diagnostic("contract S {}", 12, 13);
        diagnostic.fix = Some(DiagnosticFix {
            span: insertion,
            replacement: ";".to_owned(),
        });
        assert!(
            DiagnosticBundle::single(diagnostic)
                .render_human()
                .ends_with("= fix: insert `;`")
        );
        let (source, mut diagnostic) = fixture_diagnostic("a  b", 1, 3);
        diagnostic.fix = Some(DiagnosticFix {
            span: SourceSpan::from_range(&source, TextRange::new(1, 3)),
            replacement: String::new(),
        });
        assert!(
            DiagnosticBundle::single(diagnostic)
                .render_human()
                .ends_with("= fix: delete `  `")
        );
        // A line-starting insertion is described, not shown as an escaped
        // string.
        let (source, mut diagnostic) = fixture_diagnostic("{\n    x;", 8, 8);
        diagnostic.fix = Some(DiagnosticFix {
            span: SourceSpan::from_range(&source, TextRange::empty(8)),
            replacement: "\n    }".to_owned(),
        });
        let human = DiagnosticBundle::single(diagnostic).render_human();
        assert!(
            human.ends_with("= fix: insert `}` on a new line"),
            "{human}"
        );
    }
    #[test]
    fn sarif_lists_one_rule_per_code_and_standard_fixes() {
        let (_, mut first) = fixture_diagnostic("contract S {}", 0, 8);
        first.fix = Some(DiagnosticFix {
            span: first.primary_span.clone().expect("span"),
            replacement: "seiyaku".to_owned(),
        });
        let (_, second) = fixture_diagnostic("contract S {}", 9, 10);
        let (_, mut third) = fixture_diagnostic("contract S {}", 11, 12);
        third.code = "E_LET_MUT".to_owned();
        let sarif: Value = json::from_str(
            &DiagnosticBundle::new(vec![first, second, third])
                .render_sarif()
                .expect("SARIF"),
        )
        .expect("decode SARIF");
        let rules = sarif
            .pointer("/runs/0/tool/driver/rules")
            .and_then(Value::as_array)
            .expect("rules");
        let ids = rules
            .iter()
            .filter_map(|rule| rule.pointer("/id").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(ids, ["K1001", "E_LET_MUT"]);
        assert_eq!(
            rules[0]
                .pointer("/shortDescription/text")
                .and_then(Value::as_str),
            Some(diagnostic_explanation("K1001").expect("K1001").summary)
        );
        let indices = sarif
            .pointer("/runs/0/results")
            .and_then(Value::as_array)
            .expect("results")
            .iter()
            .map(|result| result.pointer("/ruleIndex").and_then(Value::as_u64))
            .collect::<Vec<_>>();
        assert_eq!(indices, [Some(0), Some(0), Some(1)]);
        let replacement = sarif
            .pointer("/runs/0/results/0/fixes/0/artifactChanges/0/replacements/0")
            .expect("standard SARIF fix");
        assert_eq!(
            replacement
                .pointer("/insertedContent/text")
                .and_then(Value::as_str),
            Some("seiyaku")
        );
        assert_eq!(
            replacement
                .pointer("/deletedRegion/byteLength")
                .and_then(Value::as_u64),
            Some(8)
        );
    }
    #[test]
    fn relativized_paths_match_between_absolute_and_logical_sources() {
        let base = std::path::Path::new("/work/project");
        let span = |source: &str| SourceSpan {
            package_identity: None,
            source: Some(source.to_owned()),
            start: SourcePosition { line: 1, column: 1 },
            end: SourcePosition { line: 1, column: 2 },
            byte_range: None,
        };
        let mut bundle = DiagnosticBundle::new(vec![
            Diagnostic::error(
                "K1001",
                DiagnosticPhase::Parse,
                "a",
                Some(span("/work/project/src/a.ko")),
            ),
            Diagnostic::error("K1001", DiagnosticPhase::Parse, "b", Some(span("src/b.ko"))),
            Diagnostic::error(
                "K1001",
                DiagnosticPhase::Parse,
                "c",
                Some(span("/elsewhere/c.ko")),
            ),
        ]);
        bundle.relativize_sources(base);
        let sources = bundle
            .diagnostics
            .iter()
            .filter_map(|diagnostic| diagnostic.primary_span.as_ref()?.source.clone())
            .collect::<Vec<_>>();
        assert!(sources.contains(&"src/a.ko".to_owned()), "{sources:?}");
        assert!(sources.contains(&"src/b.ko".to_owned()));
        assert!(sources.contains(&"/elsewhere/c.ko".to_owned()));
    }
    #[test]
    fn explanation_text_includes_registered_examples() {
        let explanation = diagnostic_explanation("E_LET_MUT").expect("registered");
        let text = explanation.render_text();
        assert!(text.starts_with("E_LET_MUT [parse]: "), "{text}");
        assert!(
            text.contains("\n\nexample:\n    let mut count = 0;"),
            "{text}"
        );
        assert!(text.contains("\n\nfixed:\n    var count = 0;"), "{text}");
        let without = diagnostic_explanation("K0004").expect("registered");
        assert!(!without.render_text().contains("example:"));
    }
    #[test]
    fn every_parse_and_lex_code_has_targeted_or_fallback_help_without_boilerplate() {
        for explanation in DIAGNOSTIC_EXPLANATIONS {
            assert!(
                !explanation.help.contains("Use the primary span and labels"),
                "{} keeps boilerplate help",
                explanation.code
            );
            if matches!(explanation.phase, DiagnosticPhase::Lex) && explanation.code != "K0100" {
                assert!(!explanation.help.is_empty());
            }
        }
        assert!(
            !diagnostic_explanation("K0100")
                .expect("K0100")
                .help
                .contains("誓約")
        );
    }
    #[test]
    fn captured_source_survives_frontend_path_remapping() {
        let source = SourceFile::new(
            crate::source::SourceId(0),
            "source.ko",
            "let 日本 = missing;\n",
        );
        let start = source.text().find("missing").expect("fixture name") as u32;
        let mut diagnostic = Diagnostic::error(
            "K2002",
            DiagnosticPhase::Resolve,
            "unknown name",
            Some(SourceSpan::from_range(
                &source,
                TextRange::new(start, start + 7),
            )),
        );
        diagnostic.labels.push(DiagnosticLabel {
            span: SourceSpan::from_range(&source, TextRange::new(4, 10)),
            message: "binding is here".to_owned(),
        });
        diagnostic.capture_source(&source);
        diagnostic
            .primary_span
            .as_mut()
            .expect("primary span")
            .source = Some("file:///new/source.ko".to_owned());
        let bundle = DiagnosticBundle::single(diagnostic);
        let human = bundle.render_human();
        assert!(human.contains("let 日本 = missing;\n      |            ^^^^^^^"));
        assert!(human.contains("let 日本 = missing;\n      |     ^^^^"));
        assert!(human.contains("file:///new/source.ko"));
        assert!(!bundle.render_json().expect("JSON").contains("let 日本"));
    }
    #[test]
    fn bundle_order_and_fanout_are_deterministic_and_bounded() {
        let diagnostics = (0..80)
            .rev()
            .map(|index| {
                Diagnostic::error(
                    "K2002",
                    DiagnosticPhase::Resolve,
                    format!("unknown value {index}"),
                    Some(SourceSpan {
                        package_identity: None,
                        source: Some("fanout.ko".to_owned()),
                        start: SourcePosition {
                            line: index + 1,
                            column: 1,
                        },
                        end: SourcePosition {
                            line: index + 1,
                            column: 2,
                        },
                        byte_range: None,
                    }),
                )
            })
            .collect();
        let bundle = DiagnosticBundle::new(diagnostics);
        assert_eq!(bundle.diagnostics.len(), MAX_DIAGNOSTICS);
        let source_lines = bundle
            .diagnostics
            .iter()
            .filter_map(|diagnostic| diagnostic.primary_span.as_ref().map(|span| span.start.line))
            .collect::<Vec<_>>();
        assert!(source_lines.windows(2).all(|pair| pair[0] < pair[1]));
        let limit = bundle.diagnostics.last().expect("limit diagnostic");
        assert_eq!(limit.code, "K0004");
        assert!(limit.message.contains("17 additional diagnostic(s)"));
        assert_eq!(limit.severity, Severity::Error);
    }
    #[test]
    fn fanout_retains_errors_ahead_of_warnings_without_making_warning_only_checks_fail() {
        let warnings = (0..MAX_DIAGNOSTICS + 10).map(|index| {
            Diagnostic::warning(
                "K5003",
                DiagnosticPhase::Semantic,
                format!("unused parameter {index}"),
                None,
            )
        });
        let error = Diagnostic::error(
            "K2002",
            DiagnosticPhase::Resolve,
            "unknown value in a later source",
            None,
        );
        let mixed = DiagnosticBundle::new(warnings.clone().chain([error]).collect());
        assert!(
            mixed
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "K2002"),
            "warning fanout must never hide a real compiler error",
        );
        let warning_only = DiagnosticBundle::new(warnings.collect());
        let limit = warning_only
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "K0004")
            .expect("warning fanout marker");
        assert_eq!(limit.severity, Severity::Warning);
        assert!(
            warning_only
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning),
        );
    }
}
