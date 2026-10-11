//! Stable human and machine output contracts for the Musubi V1 CLI.
//!
//! Human success is routed to stdout; live progress and human failure go to stderr. JSON mode emits exactly
//! one versioned document on stdout and leaves stderr empty, including for command failures. SARIF mode
//! emits exactly one SARIF 2.1.0 document on stdout the same way. Exit status remains independent of
//! the selected presentation mode.
//!
//! Kotodama compiler diagnostics keep their canonical structure: JSON embeds the canonical diagnostic
//! records (codes, spans, labels, notes, help and fixes) and SARIF uses the compiler's own SARIF
//! projection, rather than a rendered string.
use kotodama_lang::diagnostic::DiagnosticBundle;
use norito::json::{Map, Value};
use std::{collections::BTreeMap, fmt::Write as _, io::Write};
/// Stable schema name for one-document Musubi CLI output.
pub const OUTPUT_SCHEMA: &str = "musubi-cli-output";
/// First-release Musubi CLI output schema version.
pub const OUTPUT_VERSION: u64 = 1;
/// Replacement used whenever diagnostic material contains a secret.
pub const REDACTED: &str = "[REDACTED]";
/// User-selected command output format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Concise text intended for an interactive terminal.
    #[default]
    Human,
    /// One deterministic, versioned Norito JSON document.
    Json,
    /// One SARIF 2.1.0 document carrying Kotodama diagnostics or the command failure.
    Sarif,
}
/// Stable Musubi V1 command error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCode {
    /// Command arguments are invalid or incomplete.
    Usage,
    /// `Musubi.toml` is missing, malformed, or violates the V1 schema.
    ManifestInvalid,
    /// Workspace discovery, membership, inheritance, or selection failed.
    WorkspaceInvalid,
    /// `Musubi.lock` is malformed or violates the V1 schema.
    LockfileInvalid,
    /// A retired lockfile schema must be regenerated.
    LockfileLegacy,
    /// `--locked` forbids a required graph change.
    Locked,
    /// `--offline` could not satisfy a request from authenticated local data.
    OfflineMiss,
    /// No exact dependency graph satisfies all requirements.
    ResolutionConflict,
    /// The selected dependency graph contains a cycle.
    DependencyCycle,
    /// A registry query or registry response failed validation.
    Registry,
    /// A network operation failed.
    Network,
    /// The caller is not authorized for the requested operation.
    Unauthorized,
    /// A package source tree or normalized package is invalid.
    PackageInvalid,
    /// An archive, bundle, commitment, or provider readback failed validation.
    ArchiveInvalid,
    /// The immutable local cache is missing or corrupt.
    CacheCorrupt,
    /// Publication did not complete or failed final verification.
    Publish,
    /// An owner, alias, yank, recovery, or other governance operation failed.
    Governance,
    /// Kotodama compilation or typed-interface validation failed.
    Compiler,
    /// Kotodama tests compiled and ran, and at least one test failed.
    TestFailed,
    /// A local filesystem operation failed.
    Io,
    /// An invariant failed without a more specific public classification.
    Internal,
}
impl ErrorCode {
    /// Complete immutable inventory of Musubi V1 error codes.
    #[cfg(test)]
    pub const ALL: &'static [Self] = &[
        Self::Usage,
        Self::ManifestInvalid,
        Self::WorkspaceInvalid,
        Self::LockfileInvalid,
        Self::LockfileLegacy,
        Self::Locked,
        Self::OfflineMiss,
        Self::ResolutionConflict,
        Self::DependencyCycle,
        Self::Registry,
        Self::Network,
        Self::Unauthorized,
        Self::PackageInvalid,
        Self::ArchiveInvalid,
        Self::CacheCorrupt,
        Self::Publish,
        Self::Governance,
        Self::Compiler,
        Self::TestFailed,
        Self::Io,
        Self::Internal,
    ];
    /// Return the stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "MUSUBI_E_USAGE",
            Self::ManifestInvalid => "MUSUBI_E_MANIFEST_INVALID",
            Self::WorkspaceInvalid => "MUSUBI_E_WORKSPACE_INVALID",
            Self::LockfileInvalid => "MUSUBI_E_LOCKFILE_INVALID",
            Self::LockfileLegacy => "MUSUBI_E_LOCKFILE_LEGACY",
            Self::Locked => "MUSUBI_E_LOCKED",
            Self::OfflineMiss => "MUSUBI_E_OFFLINE_MISS",
            Self::ResolutionConflict => "MUSUBI_E_RESOLUTION_CONFLICT",
            Self::DependencyCycle => "MUSUBI_E_DEPENDENCY_CYCLE",
            Self::Registry => "MUSUBI_E_REGISTRY",
            Self::Network => "MUSUBI_E_NETWORK",
            Self::Unauthorized => "MUSUBI_E_UNAUTHORIZED",
            Self::PackageInvalid => "MUSUBI_E_PACKAGE_INVALID",
            Self::ArchiveInvalid => "MUSUBI_E_ARCHIVE_INVALID",
            Self::CacheCorrupt => "MUSUBI_E_CACHE_CORRUPT",
            Self::Publish => "MUSUBI_E_PUBLISH",
            Self::Governance => "MUSUBI_E_GOVERNANCE",
            Self::Compiler => "MUSUBI_E_COMPILER",
            Self::TestFailed => "MUSUBI_E_TEST_FAILED",
            Self::Io => "MUSUBI_E_IO",
            Self::Internal => "MUSUBI_E_INTERNAL",
        }
    }
    /// Return the stable non-zero process exit code for this category.
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Usage | Self::ManifestInvalid | Self::WorkspaceInvalid => 2,
            Self::LockfileInvalid | Self::LockfileLegacy | Self::Locked => 3,
            Self::OfflineMiss | Self::ResolutionConflict | Self::DependencyCycle => 4,
            Self::Registry | Self::Network => 5,
            Self::Unauthorized | Self::Governance => 6,
            Self::PackageInvalid | Self::ArchiveInvalid | Self::CacheCorrupt => 7,
            Self::Compiler => 8,
            Self::Publish => 9,
            Self::Io => 10,
            Self::TestFailed => 11,
            Self::Internal => 70,
        }
    }
}
/// Where human failure details render relative to the one-line summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DetailPlacement {
    /// A primary report (test results, compiler output) that the summary line concludes.
    BeforeSummary,
    /// An explanatory note following the summary line.
    AfterSummary,
}
/// One structured, secret-redacted command diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    code: ErrorCode,
    message: String,
    context: BTreeMap<String, String>,
    help: Option<String>,
    /// Boxed so `Result<_, Diagnostic>` stays small on every command path; details are rare.
    details: Option<Box<(String, Value, DetailPlacement)>>,
    /// Canonical Kotodama compiler diagnostics behind this failure, rendered structurally.
    compiler: Option<Box<DiagnosticBundle>>,
}
impl Diagnostic {
    /// Construct a diagnostic with a stable public code.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: sanitize_diagnostic_text(&message.into()),
            context: BTreeMap::new(),
            help: None,
            details: None,
            compiler: None,
        }
    }
    /// Attach the canonical compiler diagnostics that caused this failure.
    ///
    /// Human output renders them with source excerpts before the Musubi summary line, JSON embeds
    /// their canonical records under `error.diagnostics`, and SARIF reports them as results.
    #[must_use]
    pub fn with_compiler_diagnostics(mut self, diagnostics: DiagnosticBundle) -> Self {
        self.compiler = Some(Box::new(diagnostics));
        self
    }
    /// Return the attached canonical compiler diagnostics.
    #[must_use]
    #[cfg(test)]
    pub fn compiler_diagnostics(&self) -> Option<&DiagnosticBundle> {
        self.compiler.as_deref()
    }
    /// Add deterministic key/value context.
    ///
    /// Secret-named fields are replaced in full. Other values still pass through inline credential,
    /// bearer-token, private-key-block, and control character redaction.
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = sanitize_diagnostic_text(&key.into());
        let value = if is_secret_key(&key) {
            REDACTED.to_owned()
        } else {
            sanitize_diagnostic_text(&value.into())
        };
        self.context.insert(key, value);
        self
    }
    /// Attach an actionable, secret-redacted remediation hint.
    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(sanitize_diagnostic_text(&help.into()));
        self
    }
    /// Preserve a complete operation report on failure in both presentation formats.
    ///
    /// Human details and structured data receive the same redaction as successful output.
    #[must_use]
    pub fn with_details(mut self, human: impl Into<String>, data: &Value) -> Self {
        self.details = Some(Box::new((
            sanitize_diagnostic_text(&human.into()),
            redact_json_value(data),
            DetailPlacement::AfterSummary,
        )));
        self
    }
    /// Preserve the primary report of a failed operation, such as test results or compiler output.
    ///
    /// Human output prints the report first and ends with the summary line, as it does for
    /// compiler diagnostics; JSON carries `data` under `error.details` exactly like
    /// [`Self::with_details`].
    #[must_use]
    pub fn with_report(self, human: impl Into<String>, data: &Value) -> Self {
        let mut diagnostic = self.with_details(human, data);
        if let Some(details) = diagnostic.details.as_deref_mut() {
            details.2 = DetailPlacement::BeforeSummary;
        }
        diagnostic
    }
    /// Return the stable public code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }
    /// Return deterministic already redacted context.
    #[must_use]
    #[cfg(test)]
    pub const fn context(&self) -> &BTreeMap<String, String> {
        &self.context
    }
    fn to_json_value(&self) -> Value {
        let mut diagnostic = Map::new();
        diagnostic.insert("code".to_owned(), Value::from(self.code.as_str()));
        diagnostic.insert("message".to_owned(), Value::from(self.message.clone()));
        diagnostic.insert(
            "context".to_owned(),
            Value::Object(
                self.context
                    .iter()
                    .map(|(key, value)| (key.clone(), Value::from(value.clone())))
                    .collect(),
            ),
        );
        if let Some(help) = &self.help {
            diagnostic.insert("help".to_owned(), Value::from(help.clone()));
        }
        if let Some((_, data, _)) = self.details.as_deref() {
            diagnostic.insert("details".to_owned(), data.clone());
        }
        if let Some(bundle) = self.compiler.as_deref() {
            diagnostic.insert(
                "diagnostics".to_owned(),
                redact_json_value(&canonical_diagnostic_records(bundle)),
            );
        }
        Value::Object(diagnostic)
    }
    pub(crate) fn render_human(&self) -> String {
        let mut rendered = String::new();
        if let Some(bundle) = self.compiler.as_deref() {
            rendered.push_str(&terminated(&sanitize_diagnostic_text(
                &bundle.render_human(),
            )));
        }
        if let Some((human, _, DetailPlacement::BeforeSummary)) = self.details.as_deref() {
            rendered.push_str(&terminated(human));
        }
        let _ = writeln!(rendered, "error[{}]: {}", self.code.as_str(), self.message);
        if let Some((human, _, DetailPlacement::AfterSummary)) = self.details.as_deref() {
            rendered.push_str(&terminated(human));
        }
        for (key, value) in &self.context {
            rendered.push_str("  ");
            rendered.push_str(key);
            rendered.push_str(": ");
            rendered.push_str(value);
            rendered.push('\n');
        }
        if let Some(help) = &self.help {
            rendered.push_str("  help: ");
            rendered.push_str(help);
            rendered.push('\n');
        }
        rendered
    }
}
/// Complete logical result of one Musubi command.
#[derive(Clone, Debug, PartialEq)]
pub struct CommandOutput {
    command: String,
    outcome: CommandOutcome,
    /// Non-fatal compiler diagnostics (lint warnings) reported by a successful command.
    warnings: Option<DiagnosticBundle>,
}
#[derive(Clone, Debug, PartialEq)]
enum CommandOutcome {
    Success { message: String, data: Value },
    Failure(Diagnostic),
}
impl CommandOutput {
    /// Construct a successful command result.
    ///
    /// `message` is the complete human stdout body. `data` is placed in the
    /// JSON envelope after recursively redacting secret-named fields and
    /// diagnostic-like string content. Validated public identity fields retain
    /// their exact canonical text even when that text resembles an assignment.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn success(command: impl Into<String>, message: impl Into<String>, data: Value) -> Self {
        Self {
            command: sanitize_diagnostic_text(&command.into()),
            outcome: CommandOutcome::Success {
                message: sanitize_diagnostic_text(&message.into()),
                data: redact_json_value(&data),
            },
            warnings: None,
        }
    }
    /// Attach non-fatal compiler diagnostics to a successful result for SARIF output.
    ///
    /// Human and JSON success bodies already carry these warnings in their message and data.
    #[must_use]
    pub fn with_warnings(mut self, warnings: DiagnosticBundle) -> Self {
        if !warnings.diagnostics.is_empty() {
            self.warnings = Some(warnings);
        }
        self
    }
    /// Construct a failed command result.
    #[must_use]
    pub fn failure(command: impl Into<String>, diagnostic: Diagnostic) -> Self {
        Self {
            command: sanitize_diagnostic_text(&command.into()),
            outcome: CommandOutcome::Failure(diagnostic),
            warnings: None,
        }
    }
    /// Return the process exit code independent of presentation format.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match &self.outcome {
            CommandOutcome::Success { .. } => 0,
            CommandOutcome::Failure(diagnostic) => diagnostic.code.exit_code(),
        }
    }
    /// Render deterministic stdout and stderr buffers.
    ///
    /// # Errors
    ///
    /// Returns a Norito JSON error only if the already constructed JSON value cannot be serialized.
    pub fn render(&self, format: OutputFormat) -> Result<RenderedOutput, norito::json::Error> {
        match format {
            OutputFormat::Human => Ok(self.render_human()),
            OutputFormat::Json => self.render_json(),
            OutputFormat::Sarif => self.render_sarif(),
        }
    }
    fn render_sarif(&self) -> Result<RenderedOutput, norito::json::Error> {
        let document = match &self.outcome {
            CommandOutcome::Success { .. } => match &self.warnings {
                Some(bundle) => norito::json::from_str::<Value>(&bundle.render_sarif()?)?,
                None => sarif_document("Kotodama", Vec::new(), Vec::new()),
            },
            CommandOutcome::Failure(diagnostic) => {
                if let Some(bundle) = diagnostic.compiler.as_deref() {
                    norito::json::from_str::<Value>(&bundle.render_sarif()?)?
                } else {
                    let mut text = diagnostic.message.clone();
                    for (key, value) in &diagnostic.context {
                        let _ = write!(text, "; {key}: {value}");
                    }
                    if let Some(help) = &diagnostic.help {
                        let _ = write!(text, "; help: {help}");
                    }
                    let code = diagnostic.code.as_str();
                    sarif_document(
                        "Musubi",
                        vec![object_value([
                            ("id", Value::from(code)),
                            (
                                "shortDescription",
                                object_value([("text", Value::from(diagnostic.message.clone()))]),
                            ),
                        ])],
                        vec![object_value([
                            ("ruleId", Value::from(code)),
                            ("level", Value::from("error")),
                            ("message", object_value([("text", Value::from(text))])),
                        ])],
                    )
                }
            }
        };
        let mut stdout = norito::json::to_string(&redact_json_value(&document))?;
        stdout.push('\n');
        Ok(RenderedOutput {
            stdout,
            stderr: String::new(),
            exit_code: self.exit_code(),
        })
    }
    fn render_human(&self) -> RenderedOutput {
        match &self.outcome {
            CommandOutcome::Success { message, .. } => RenderedOutput {
                stdout: terminated(message),
                stderr: String::new(),
                exit_code: 0,
            },
            CommandOutcome::Failure(diagnostic) => RenderedOutput {
                stdout: String::new(),
                stderr: diagnostic.render_human(),
                exit_code: diagnostic.code.exit_code(),
            },
        }
    }
    fn render_json(&self) -> Result<RenderedOutput, norito::json::Error> {
        let mut envelope = Map::new();
        envelope.insert("command".to_owned(), Value::from(self.command.clone()));
        envelope.insert("schema".to_owned(), Value::from(OUTPUT_SCHEMA));
        envelope.insert("version".to_owned(), Value::from(OUTPUT_VERSION));
        match &self.outcome {
            CommandOutcome::Success { message, data } => {
                envelope.insert("ok".to_owned(), Value::from(true));
                envelope.insert("message".to_owned(), Value::from(message.clone()));
                envelope.insert("data".to_owned(), data.clone());
            }
            CommandOutcome::Failure(diagnostic) => {
                envelope.insert("ok".to_owned(), Value::from(false));
                envelope.insert("error".to_owned(), diagnostic.to_json_value());
            }
        }
        let mut stdout = norito::json::to_string(&Value::Object(envelope))?;
        stdout.push('\n');
        Ok(RenderedOutput {
            stdout,
            stderr: String::new(),
            exit_code: self.exit_code(),
        })
    }
}
/// Canonical JSON records of every diagnostic in a compiler bundle.
fn canonical_diagnostic_records(bundle: &DiagnosticBundle) -> Value {
    Value::Array(
        bundle
            .diagnostics
            .iter()
            .map(kotodama_lang::diagnostic::Diagnostic::to_json_value)
            .collect(),
    )
}
fn object_value<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
/// Minimal SARIF 2.1.0 document with one run.
fn sarif_document(tool: &str, rules: Vec<Value>, results: Vec<Value>) -> Value {
    object_value([
        ("version", Value::from("2.1.0")),
        (
            "$schema",
            Value::from("https://json.schemastore.org/sarif-2.1.0.json"),
        ),
        (
            "runs",
            Value::Array(vec![object_value([
                (
                    "tool",
                    object_value([(
                        "driver",
                        object_value([("name", Value::from(tool)), ("rules", Value::Array(rules))]),
                    )]),
                ),
                ("results", Value::Array(results)),
            ])]),
        ),
    ])
}
/// Fully routed bytes and process status for one command result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}
impl RenderedOutput {
    /// Return bytes routed to stdout.
    #[must_use]
    #[cfg(test)]
    pub fn stdout(&self) -> &str {
        &self.stdout
    }
    /// Return bytes routed to stderr.
    #[must_use]
    #[cfg(test)]
    pub fn stderr(&self) -> &str {
        &self.stderr
    }
    /// Return the stable process exit code.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }
    /// Write the routed buffers without adding prefixes or extra documents.
    ///
    /// # Errors
    ///
    /// Returns the first stdout, stderr, or flush error.
    pub fn write_to(
        &self,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> std::io::Result<()> {
        stdout.write_all(self.stdout.as_bytes())?;
        stderr.write_all(self.stderr.as_bytes())?;
        stdout.flush()?;
        stderr.flush()
    }
}
/// Redact secrets and unsafe terminal control characters from diagnostic text.
#[must_use]
pub fn sanitize_diagnostic_text(input: &str) -> String {
    // Match credentials against the same control-free text that can reach a terminal.
    let safe_input = input
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect::<String>();
    let without_private_blocks = redact_private_key_blocks(&safe_input);
    let without_assignments = redact_secret_assignments(&without_private_blocks);
    redact_bearer_tokens(&without_assignments)
}
fn terminated(message: &str) -> String {
    if message.is_empty() || message.ends_with('\n') {
        message.to_owned()
    } else {
        format!("{message}\n")
    }
}
fn redact_json_value(value: &Value) -> Value {
    match value {
        Value::Null => Value::Null,
        Value::Bool(value) => Value::Bool(*value),
        Value::Number(value) => Value::Number(*value),
        Value::String(value) => Value::String(sanitize_diagnostic_text(value)),
        Value::Array(values) => Value::Array(values.iter().map(redact_json_value).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| {
                    let key = sanitize_diagnostic_text(key);
                    let value = if is_secret_key(&key) {
                        Value::from(REDACTED)
                    } else if is_exact_public_string(&key, value) {
                        value.clone()
                    } else {
                        redact_json_value(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
    }
}
fn is_exact_public_string(key: &str, value: &Value) -> bool {
    // `ChainId` is a validated public display/configuration label. Its grammar permits `:`, so
    // values such as `token:dev` can resemble a secret assignment even though redacting them
    // would corrupt generic machine-readable display metadata. Security domains use `NetworkId`.
    key == "chain_id"
        && value
            .as_str()
            .is_some_and(|value| value.parse::<iroha_model_base::chain::ChainId>().is_ok())
}
fn is_secret_key(key: &str) -> bool {
    let normalized = key
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let normalized = String::from_utf8(normalized).expect("ASCII normalization");
    [
        "privatekey",
        "secretkey",
        "streamtoken",
        "bearertoken",
        "accesstoken",
        "refreshtoken",
        "authorization",
        "password",
        "passwd",
        "credential",
        "credentials",
        "token",
        "apikey",
        "clientsecret",
        "seed",
        "mnemonic",
    ]
    .iter()
    .any(|secret| normalized == *secret || normalized.ends_with(secret))
}
fn redact_private_key_blocks(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut private_block = false;
    for line in input.split_inclusive('\n') {
        let uppercase = line.to_ascii_uppercase();
        if !private_block
            && uppercase.contains("-----BEGIN ")
            && uppercase.contains("PRIVATE KEY-----")
        {
            output.push_str("[REDACTED PRIVATE KEY]");
            if line.ends_with('\n') {
                output.push('\n');
            }
            private_block = true;
            continue;
        }
        if private_block {
            if uppercase.contains("-----END ") && uppercase.contains("PRIVATE KEY-----") {
                private_block = false;
            }
            continue;
        }
        output.push_str(line);
    }
    output
}
fn redact_secret_assignments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut copied_through = 0_usize;
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        let Some((key, after_key)) = assignment_key_at(input, cursor) else {
            cursor += input[cursor..].chars().next().map_or(1, char::len_utf8);
            continue;
        };
        let mut separator = after_key;
        while separator < bytes.len() && bytes[separator].is_ascii_whitespace() {
            separator += 1;
        }
        if !bytes
            .get(separator)
            .is_some_and(|byte| matches!(byte, b'=' | b':'))
        {
            cursor = after_key.max(cursor + 1);
            continue;
        }
        if !is_secret_key(key) {
            cursor = separator + 1;
            continue;
        }
        let mut value_start = separator + 1;
        while value_start < bytes.len() && matches!(bytes[value_start], b' ' | b'\t') {
            value_start += 1;
        }
        if value_start >= bytes.len() {
            break;
        }
        let (redaction_start, value_end) = if matches!(bytes[value_start], b'\'' | b'"') {
            let quote = bytes[value_start];
            let content_start = value_start + 1;
            let end = bytes[content_start..]
                .iter()
                .position(|byte| *byte == quote)
                .map_or(bytes.len(), |offset| content_start + offset);
            (content_start, end)
        } else if normalize_key(key).ends_with("authorization") {
            let end = bytes[value_start..]
                .iter()
                .position(|byte| matches!(byte, b'\n' | b',' | b';'))
                .map_or(bytes.len(), |offset| value_start + offset);
            (value_start, end)
        } else {
            let end = bytes[value_start..]
                .iter()
                .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b',' | b';' | b'&'))
                .map_or(bytes.len(), |offset| value_start + offset);
            (value_start, end)
        };
        output.push_str(&input[copied_through..redaction_start]);
        output.push_str(REDACTED);
        copied_through = value_end;
        cursor = value_end.max(cursor + 1);
    }
    output.push_str(&input[copied_through..]);
    output
}
fn assignment_key_at(input: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = input.as_bytes();
    let first = *bytes.get(start)?;
    if matches!(first, b'\'' | b'"') {
        let key_start = start + 1;
        let key_end = bytes[key_start..]
            .iter()
            .position(|byte| *byte == first)
            .map(|offset| key_start + offset)?;
        if key_end == key_start {
            return None;
        }
        return Some((&input[key_start..key_end], key_end + 1));
    }
    if !is_key_byte(first) || first.is_ascii_digit() {
        return None;
    }
    let mut end = start + 1;
    while end < bytes.len() && is_key_byte(bytes[end]) {
        end += 1;
    }
    Some((&input[start..end], end))
}
const fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}
fn normalize_key(key: &str) -> String {
    key.bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect()
}
fn redact_bearer_tokens(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut copied_through = 0_usize;
    let mut cursor = 0_usize;
    while cursor + 6 <= bytes.len() {
        let candidate = &bytes[cursor..cursor + 6];
        let boundary_before = cursor == 0 || !bytes[cursor - 1].is_ascii_alphanumeric();
        if boundary_before && candidate.eq_ignore_ascii_case(b"bearer") {
            let mut token_start = cursor + 6;
            if token_start < bytes.len() && bytes[token_start].is_ascii_whitespace() {
                while token_start < bytes.len() && bytes[token_start].is_ascii_whitespace() {
                    token_start += 1;
                }
                let token_end = bytes[token_start..]
                    .iter()
                    .position(|byte| {
                        byte.is_ascii_whitespace()
                            || matches!(byte, b',' | b';' | b'\'' | b'"' | b'&')
                    })
                    .map_or(bytes.len(), |offset| token_start + offset);
                if token_end > token_start {
                    output.push_str(&input[copied_through..token_start]);
                    output.push_str(REDACTED);
                    copied_through = token_end;
                    cursor = token_end;
                    continue;
                }
            }
        }
        cursor += input[cursor..].chars().next().map_or(1, char::len_utf8);
    }
    output.push_str(&input[copied_through..]);
    output
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    #[test]
    fn v1_error_codes_and_exit_codes_are_stable_and_unique() {
        let spellings = ErrorCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(spellings.len(), ErrorCode::ALL.len());
        assert!(spellings.iter().all(|code| code.starts_with("MUSUBI_E_")));
        assert!(ErrorCode::ALL.iter().all(|code| code.exit_code() > 0));
        assert_eq!(ErrorCode::LockfileLegacy.exit_code(), 3);
        assert_eq!(ErrorCode::Internal.exit_code(), 70);
    }
    fn compiler_bundle() -> DiagnosticBundle {
        use kotodama_lang::diagnostic::{
            Diagnostic as KotodamaDiagnostic, DiagnosticPhase, SourcePosition, SourceSpan,
        };
        let mut diagnostic = KotodamaDiagnostic::error(
            "E_RETURN_TYPE_MISMATCH",
            DiagnosticPhase::Semantic,
            "returned value has type `bool`, expected `int`",
            Some(SourceSpan {
                package_identity: None,
                source: Some("contracts/hello.ko".to_owned()),
                start: SourcePosition { line: 7, column: 9 },
                end: SourcePosition {
                    line: 7,
                    column: 20,
                },
                byte_range: None,
            }),
        );
        diagnostic.help = Some("return an `int` value".to_owned());
        DiagnosticBundle::single(diagnostic)
    }
    #[test]
    fn test_failures_have_their_own_code_and_exit_status() {
        assert_eq!(ErrorCode::TestFailed.as_str(), "MUSUBI_E_TEST_FAILED");
        assert_eq!(ErrorCode::TestFailed.exit_code(), 11);
        assert_ne!(
            ErrorCode::TestFailed.exit_code(),
            ErrorCode::Compiler.exit_code()
        );
        let exit_codes = ErrorCode::ALL
            .iter()
            .filter(|code| **code != ErrorCode::TestFailed)
            .map(|code| code.exit_code())
            .collect::<BTreeSet<_>>();
        assert!(!exit_codes.contains(&11));
    }
    #[test]
    fn compiler_failures_keep_canonical_structure_in_every_format() {
        let diagnostic = Diagnostic::new(
            ErrorCode::Compiler,
            "Kotodama rejected the selected sources with 1 error",
        )
        .with_compiler_diagnostics(compiler_bundle());
        assert_eq!(diagnostic.compiler_diagnostics(), Some(&compiler_bundle()));
        let output = CommandOutput::failure("check", diagnostic);
        let human = output.render(OutputFormat::Human).expect("human");
        assert_eq!(human.exit_code(), 8);
        let stderr = human.stderr();
        assert!(stderr.starts_with("error[E_RETURN_TYPE_MISMATCH] semantic: "));
        assert!(stderr.contains("--> contracts/hello.ko:7:9"));
        assert!(stderr.ends_with(
            "error[MUSUBI_E_COMPILER]: Kotodama rejected the selected sources with 1 error\n"
        ));
        assert_eq!(stderr.matches("error[MUSUBI_E_COMPILER]").count(), 1);
        assert!(!stderr.contains("compiler failed: error["));
        let json: Value =
            norito::json::from_str(output.render(OutputFormat::Json).expect("json").stdout())
                .expect("one document");
        assert_eq!(
            json.pointer("/error/diagnostics/0/code")
                .and_then(Value::as_str),
            Some("E_RETURN_TYPE_MISMATCH")
        );
        assert_eq!(
            json.pointer("/error/diagnostics/0/primary_span/start/line")
                .and_then(Value::as_u64),
            Some(7)
        );
        assert_eq!(
            json.pointer("/error/diagnostics/0/help")
                .and_then(Value::as_str),
            Some("return an `int` value")
        );
        assert!(
            !json
                .pointer("/error/message")
                .and_then(Value::as_str)
                .expect("summary")
                .contains("error[")
        );
        let sarif = output.render(OutputFormat::Sarif).expect("sarif");
        assert_eq!(sarif.exit_code(), 8);
        assert!(sarif.stderr().is_empty());
        let sarif: Value = norito::json::from_str(sarif.stdout()).expect("one SARIF document");
        assert_eq!(sarif.get("version").and_then(Value::as_str), Some("2.1.0"));
        assert_eq!(
            sarif
                .pointer("/runs/0/results/0/ruleId")
                .and_then(Value::as_str),
            Some("E_RETURN_TYPE_MISMATCH")
        );
    }
    #[test]
    fn sarif_reports_non_compiler_failures_and_successful_warnings() {
        let failure = CommandOutput::failure(
            "test",
            Diagnostic::new(ErrorCode::TestFailed, "Kotodama tests failed: 1 failed")
                .with_help("inspect the failing case"),
        )
        .render(OutputFormat::Sarif)
        .expect("sarif failure");
        assert_eq!(failure.exit_code(), 11);
        let document: Value = norito::json::from_str(failure.stdout()).expect("document");
        assert_eq!(
            document
                .pointer("/runs/0/results/0/ruleId")
                .and_then(Value::as_str),
            Some("MUSUBI_E_TEST_FAILED")
        );
        assert!(
            document
                .pointer("/runs/0/results/0/message/text")
                .and_then(Value::as_str)
                .is_some_and(|text| text.contains("help: inspect the failing case"))
        );
        let clean = CommandOutput::success("check", "checked", Value::Null)
            .render(OutputFormat::Sarif)
            .expect("clean sarif");
        let clean: Value = norito::json::from_str(clean.stdout()).expect("clean document");
        assert_eq!(
            clean
                .pointer("/runs/0/results")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        let mut warning = compiler_bundle();
        warning.diagnostics[0].severity = kotodama_lang::diagnostic::Severity::Warning;
        let warned = CommandOutput::success("check", "checked", Value::Null)
            .with_warnings(warning)
            .render(OutputFormat::Sarif)
            .expect("warning sarif");
        assert_eq!(warned.exit_code(), 0);
        let warned: Value = norito::json::from_str(warned.stdout()).expect("warning document");
        assert_eq!(
            warned
                .pointer("/runs/0/results/0/level")
                .and_then(Value::as_str),
            Some("warning")
        );
    }
    #[test]
    fn human_output_routes_success_and_failure_deterministically() {
        let success = CommandOutput::success("metadata", "package = demo", Value::Null)
            .render(OutputFormat::Human)
            .expect("render success");
        assert_eq!(success.stdout(), "package = demo\n");
        assert_eq!(success.stderr(), "");
        assert_eq!(success.exit_code(), 0);
        let failure = CommandOutput::failure(
            "check",
            Diagnostic::new(ErrorCode::Locked, "lockfile would change")
                .with_context("package", "demo/core")
                .with_help("rerun without --locked"),
        )
        .render(OutputFormat::Human)
        .expect("render failure");
        assert_eq!(failure.stdout(), "");
        assert_eq!(failure.exit_code(), 3);
        assert_eq!(
            failure.stderr(),
            "error[MUSUBI_E_LOCKED]: lockfile would change\n  package: demo/core\n  help: rerun without --locked\n"
        );
    }
    #[test]
    fn json_failure_is_one_deterministic_stdout_document() {
        let output = CommandOutput::failure(
            "check",
            Diagnostic::new(ErrorCode::ResolutionConflict, "no solution")
                .with_context("z-parent", "b")
                .with_context("a-parent", "a"),
        );
        let first = output.render(OutputFormat::Json).expect("first render");
        let second = output.render(OutputFormat::Json).expect("second render");
        assert_eq!(first, second);
        assert!(first.stderr().is_empty());
        assert_eq!(first.stdout().matches('\n').count(), 1);
        let document: Value = norito::json::from_str(first.stdout()).expect("one JSON document");
        assert_eq!(
            document.get("schema").and_then(Value::as_str),
            Some(OUTPUT_SCHEMA)
        );
        assert_eq!(document.get("version").and_then(Value::as_u64), Some(1));
        assert_eq!(document.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(
            document.pointer("/error/code").and_then(Value::as_str),
            Some("MUSUBI_E_RESOLUTION_CONFLICT")
        );
    }
    #[test]
    fn failure_details_keep_all_cases_and_redact_secrets_in_both_formats() {
        let details: Value = norito::json::from_str(r#"{"cases":[{"name":"first","failure":"assertion failed: actual 29, expected 30"},{"name":"second","failure":"private_key=secret-test-value"}]}"#).expect("test details");
        let output = CommandOutput::failure(
            "test",
            Diagnostic::new(ErrorCode::Compiler, "tests failed").with_details(
                "FAIL first: actual 29, expected 30\nFAIL second: private_key=secret-test-value",
                &details,
            ),
        );
        for format in [OutputFormat::Human, OutputFormat::Json] {
            let rendered = output.render(format).expect("render failure");
            assert_eq!(rendered.exit_code(), ErrorCode::Compiler.exit_code());
            let text = format!("{}{}", rendered.stdout(), rendered.stderr());
            assert!(text.contains("first") && text.contains("second"));
            assert!(text.contains("actual 29, expected 30"));
            assert!(!text.contains("secret-test-value"));
        }
        let rendered = output.render(OutputFormat::Json).expect("JSON");
        let value: Value = norito::json::from_str(rendered.stdout()).expect("one document");
        assert_eq!(
            value
                .pointer("/error/details/cases/1/name")
                .and_then(Value::as_str),
            Some("second")
        );
    }
    #[test]
    fn reports_precede_the_summary_line_and_notes_follow_it() {
        let data = norito::json!({"failed": 1});
        let report = Diagnostic::new(
            ErrorCode::TestFailed,
            "Kotodama tests failed: 1 of 2 failed",
        )
        .with_report(
            "PASS first\nFAIL second\ntest completed: 1 passed; 1 failed",
            &data,
        )
        .with_help("fix the failing test");
        let human = CommandOutput::failure("test", report.clone())
            .render(OutputFormat::Human)
            .expect("human report");
        assert_eq!(human.exit_code(), 11);
        assert_eq!(
            human.stderr(),
            "PASS first\nFAIL second\ntest completed: 1 passed; 1 failed\n\
             error[MUSUBI_E_TEST_FAILED]: Kotodama tests failed: 1 of 2 failed\n\
             \x20 help: fix the failing test\n"
        );
        let note = Diagnostic::new(ErrorCode::Network, "deployment failed")
            .with_details("Correct the reported cause.", &data);
        assert!(note.render_human().starts_with(
            "error[MUSUBI_E_NETWORK]: deployment failed\nCorrect the reported cause.\n"
        ));
        let json = CommandOutput::failure("test", report)
            .render(OutputFormat::Json)
            .expect("JSON report");
        let value: Value = norito::json::from_str(json.stdout()).expect("one document");
        assert_eq!(
            value
                .pointer("/error/details/failed")
                .and_then(Value::as_u64),
            Some(1)
        );
    }
    #[test]
    fn diagnostics_redact_assignments_bearer_tokens_private_keys_and_controls() {
        let secret = "private_key=deadbeef stream-token='stream-secret' Authorization: Bearer auth-secret\n-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----\nunsafe\u{1b}[31m";
        let redacted = sanitize_diagnostic_text(secret);
        for leaked in ["deadbeef", "stream-secret", "auth-secret", "key-material"] {
            assert!(!redacted.contains(leaked), "leaked {leaked}");
        }
        assert!(!redacted.contains('\u{1b}'));
        assert!(redacted.contains("private_key=[REDACTED]"));
        assert!(redacted.contains("stream-token='[REDACTED]'"));
        assert!(redacted.contains("Authorization: [REDACTED]"));
        assert!(redacted.contains("[REDACTED PRIVATE KEY]"));
        for input in [
            "\u{1b}[31mAuthorization: Bearer prefixed-secret",
            "X-Authorization: Bearer prefixed-secret",
            "private_\u{1b}key=prefixed-secret",
        ] {
            let redacted = sanitize_diagnostic_text(input);
            assert!(!redacted.contains("prefixed-secret"), "leaked: {redacted}");
            assert!(!redacted.contains('\u{1b}'));
        }
    }
    #[test]
    fn json_data_and_context_redact_secret_named_fields_recursively() {
        let mut nested = Map::new();
        nested.insert("stream_token".to_owned(), Value::from("stream-secret"));
        nested.insert(
            "message".to_owned(),
            Value::from("request used Bearer bearer-secret"),
        );
        let output = CommandOutput::success("fetch", "fetched", Value::Object(nested))
            .render(OutputFormat::Json)
            .expect("render JSON");
        assert!(!output.stdout().contains("stream-secret"));
        assert!(!output.stdout().contains("bearer-secret"));
        let document: Value = norito::json::from_str(output.stdout()).expect("parse output");
        assert_eq!(
            document
                .pointer("/data/stream_token")
                .and_then(Value::as_str),
            Some(REDACTED)
        );
        assert_eq!(
            document.pointer("/data/message").and_then(Value::as_str),
            Some("request used Bearer [REDACTED]")
        );
        let diagnostic = Diagnostic::new(ErrorCode::Network, "request failed")
            .with_context("private_key", "never-print-this");
        assert_eq!(
            diagnostic.context().get("private_key"),
            Some(&REDACTED.to_owned())
        );
    }
    #[test]
    fn json_data_preserves_public_chain_display_label_without_weakening_other_redaction() {
        let output = CommandOutput::success(
            "publish",
            "published",
            Value::Object(Map::from_iter([
                ("chain_id".to_owned(), Value::from("token:dev")),
                ("message".to_owned(), Value::from("token:must-not-leak")),
            ])),
        )
        .render(OutputFormat::Json)
        .expect("render JSON");
        let document: Value = norito::json::from_str(output.stdout()).expect("parse output");
        assert_eq!(
            document.pointer("/data/chain_id").and_then(Value::as_str),
            Some("token:dev")
        );
        assert_eq!(
            document.pointer("/data/message").and_then(Value::as_str),
            Some("token:[REDACTED]")
        );
    }
    #[test]
    fn rendered_output_writes_exact_routed_bytes() {
        let rendered =
            CommandOutput::failure("build", Diagnostic::new(ErrorCode::Compiler, "type error"))
                .render(OutputFormat::Human)
                .expect("render");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        rendered
            .write_to(&mut stdout, &mut stderr)
            .expect("write output");
        assert!(stdout.is_empty());
        assert_eq!(stderr, rendered.stderr().as_bytes());
    }
}
