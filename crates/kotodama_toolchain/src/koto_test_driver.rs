//! In-process Kotodama V1 test runner shared by the unified CLI and SDK tools.
//!
//! Public test calls use the production contract artifact and canonical argument-record encoding.
//! `test::invoke_kotoage` retains the current caller; its `_as` variant selects a fixture actor.
#[cfg(test)]
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _};
use ed25519_dalek::{Signer as _, SigningKey};
use iroha_data_model::executor::fault::{IvmFaultPositionV1, IvmFaultV1};
use iroha_data_model::prelude::Mintable;
use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    asset::{AssetBalanceScope, AssetId},
    smart_contract::{
        ContractAddress,
        manifest::{ContractPermissionScopeV1, EntryPointKind, EntrypointAuthorizationV1},
    },
};
use iroha_model_base::topology::DataSpaceId;
use iroha_model_base::{domain::DomainId, name::Name};
#[cfg(test)]
use iroha_primitives::numeric_abi::QuantityValueV1;
use iroha_primitives::{
    json::Json,
    numeric::{Numeric, Quantity},
    numeric_abi::DecimalValueV1,
};
#[cfg(test)]
use ivm::ProgramMetadata;
use ivm::{
    AccountId, AssetDefinitionId, IVM, IVMHost, MockWorldStateView, PermissionToken, PointerType,
    TraceMode, WsvHost,
};
use ivm_abi::entrypoint::EntrypointArgumentSchemaV1;
use ivm_abi::state_value::{
    StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1, StateValueSchemaV1,
    state_value_schema_hash_v1,
};
use kotodama_lang::{
    ast::{Expr, FixtureAction, FixtureDecl, FunctionKind, Item, Program, SourceUnitKind},
    compiler::{CompileReport, CompilerMode, CompilerOptions},
    diagnostic::DiagnosticBundle,
    linker::{
        ImportBinding, MAX_LOGICAL_SOURCE_PATH_BYTES, MAX_MODULE_GRAPH_SOURCE_BYTES,
        ModuleBuildGraph, SourceLinkRequest, SourceModuleUnit, SourcePackageUnit,
    },
    parser,
    session::{CompilerSession, TestCompileOutput, TestSourceUnit},
    source::read_source_file,
};
use norito::json::{self, Value};
use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
#[path = "koto_test_driver_upgrade.rs"]
mod fixture_upgrade;
#[path = "koto_test_driver_source_set.rs"]
mod source_set;
#[path = "koto_test_driver_trace.rs"]
mod trace_capture;
#[cfg(test)]
#[path = "koto_test_driver_vrf.rs"]
mod vrf_fixture_tests;
use source_set::discover_declared_suite_from_source_set;
pub use source_set::{
    declared_test_target_source_v1, discover_declared_test_names_source_set_v1,
    discover_declared_test_names_source_set_with_sources_v1,
    run_tests_structured_source_set_with_modules_v1,
};
const DEFAULT_CALLER: &str = "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
const TEST_SYSCALL_ACTOR_ACCOUNT: u32 = ivm::syscalls::SYSCALL_KOTO_TEST_ACTOR_ACCOUNT;
const TEST_SYSCALL_ACTOR_PUBLIC_KEY: u32 = ivm::syscalls::SYSCALL_KOTO_TEST_ACTOR_PUBLIC_KEY;
const TEST_SYSCALL_ACTOR_SIGN: u32 = ivm::syscalls::SYSCALL_KOTO_TEST_ACTOR_SIGN;
const TEST_SYSCALL_INVOKE_ENTRYPOINT_AS: u32 =
    ivm::syscalls::SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS;
const TEST_SYSCALL_EXPECT_REJECT_AS: u32 = ivm::syscalls::SYSCALL_KOTO_TEST_EXPECT_REJECT_AS;
const TEST_SYSCALL_ASSERT_FAILED: u32 = ivm::syscalls::SYSCALL_KOTO_TEST_ASSERT_FAILED;
const TEST_SYSCALL_SET_BLOCK_HEIGHT: u32 = ivm::syscalls::SYSCALL_KOTO_TEST_SET_BLOCK_HEIGHT;
const TEST_SYSCALL_ADVANCE_BLOCKS: u32 = ivm::syscalls::SYSCALL_KOTO_TEST_ADVANCE_BLOCKS;
const TEST_SYSCALL_SET_TRANSACTION_TIME_MS: u32 =
    ivm::syscalls::SYSCALL_KOTO_TEST_SET_TRANSACTION_TIME_MS;
const TEST_SYSCALL_CALL_SITE: u32 = ivm::syscalls::SYSCALL_KOTO_TEST_CALL_SITE;
const TEST_MAX_RETURN_VALUES: usize = ivm_abi::call::MAX_CALL_WORDS_V1;
#[derive(Clone)]
struct FixtureActor {
    account: AccountId,
    seed: Option<[u8; 32]>,
}
/// Action selected by `koto test`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KotoTestAction {
    /// Compile and run the selected tests.
    Run,
    /// List the discovered tests without compiling them.
    List,
    /// Run the selected tests and report which seiyaku functions executed.
    Coverage,
    /// Run the selected tests and print a per-instruction execution trace.
    Trace,
}
/// Report format written to stdout by `koto test`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KotoTestReportFormat {
    /// Human-readable text.
    #[default]
    Human,
    /// One JSON document (or, for `trace`, one JSON object per executed instruction).
    Json,
    /// `JUnit` XML (`run` only).
    Junit,
}
/// Complete `koto test` invocation after command-line parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KotoTestCliOptions {
    /// Selected action.
    pub action: KotoTestAction,
    /// Seiyaku with inline tests or a standalone `*.test.ko` module.
    pub source: Option<PathBuf>,
    /// Directory that logical source names are relative to. Defaults to the nearest directory
    /// containing both the test module and its `koto_test` target.
    pub source_root: Option<PathBuf>,
    /// Test-name substring (or exact name with [`Self::exact`]).
    pub filter: Option<String>,
    /// Require [`Self::filter`] to match the complete test name.
    pub exact: bool,
    /// Number of tests executed in parallel.
    pub jobs: usize,
    /// Deterministic ordering seed; zero runs tests in name order.
    pub seed: u64,
    /// Account-address chain discriminant used while compiling and executing.
    pub chain_discriminant: u16,
    /// Enable ZK seiyaku compilation.
    pub zk_enabled: bool,
    /// Report format written to stdout.
    pub format: KotoTestReportFormat,
    /// Additional `JUnit` XML report file.
    pub junit: Option<PathBuf>,
    /// Print a per-kotoage gas table after the results.
    pub gas_report: bool,
}
impl KotoTestCliOptions {
    /// Options for `action` with every other field at its documented default.
    #[must_use]
    pub fn new(action: KotoTestAction, chain_discriminant: u16) -> Self {
        Self {
            action,
            source: None,
            source_root: None,
            filter: None,
            exact: false,
            jobs: 1,
            seed: 0,
            chain_discriminant,
            zk_enabled: false,
            format: KotoTestReportFormat::Human,
            junit: None,
            gas_report: false,
        }
    }
}
/// Category of a failed `koto test` invocation; the CLI maps it to a process exit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KotoTestCliErrorKind {
    /// The invocation was malformed or selected nothing.
    Usage,
    /// A source, manifest, or report file could not be read or written.
    Io,
    /// The suite failed to parse, link, or compile; the message is the complete rendered report
    /// (compiler diagnostics, or an `error: ...` line), printed as is.
    Compile,
    /// The suite ran and at least one test failed; the report was already printed.
    TestsFailed,
    /// The runner itself failed.
    Internal,
}
/// A failed `koto test` invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KotoTestCliError {
    /// Failure category.
    pub kind: KotoTestCliErrorKind,
    /// Human-readable detail (rendered diagnostics for [`KotoTestCliErrorKind::Compile`]).
    pub message: String,
}
impl KotoTestCliError {
    fn new(kind: KotoTestCliErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}
impl std::fmt::Display for KotoTestCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for KotoTestCliError {}
/// Error from discovering or compiling a suite, keeping I/O failures apart from source errors.
#[derive(Clone, Debug)]
enum SuiteError {
    /// A file could not be resolved or read.
    Io(String),
    /// The sources are invalid, rendered as text.
    Invalid(String),
    /// Canonical compiler diagnostics.
    Diagnostics(DiagnosticBundle),
}
impl SuiteError {
    fn into_message(self) -> String {
        match self {
            Self::Io(message) | Self::Invalid(message) => message,
            Self::Diagnostics(diagnostics) => diagnostics.render_human(),
        }
    }
    fn into_cli(self) -> KotoTestCliError {
        match self {
            Self::Io(message) => KotoTestCliError::new(KotoTestCliErrorKind::Io, message),
            Self::Invalid(message) => {
                KotoTestCliError::new(KotoTestCliErrorKind::Compile, format!("error: {message}"))
            }
            Self::Diagnostics(diagnostics) => {
                KotoTestCliError::new(KotoTestCliErrorKind::Compile, diagnostics.render_human())
            }
        }
    }
}
impl std::fmt::Display for SuiteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(message) | Self::Invalid(message) => formatter.write_str(message),
            Self::Diagnostics(diagnostics) => formatter.write_str(&diagnostics.render_human()),
        }
    }
}
impl From<String> for SuiteError {
    fn from(message: String) -> Self {
        Self::Invalid(message)
    }
}
impl From<SuiteError> for String {
    fn from(error: SuiteError) -> Self {
        error.into_message()
    }
}
/// Name the suite's own files in compiler diagnostics the way `koto` prints every other path:
/// relative to the working directory when the file lies inside it.
///
/// The compiler identifies the target and test modules by absolute path or by logical name under
/// the source root; package sources keep their package-qualified names.
fn localize_suite_diagnostics(suite: &DiscoveredSuite, error: SuiteError) -> SuiteError {
    let SuiteError::Diagnostics(mut bundle) = error else {
        return error;
    };
    let mut paths = BTreeMap::<String, &Path>::new();
    let files = std::iter::once(suite.target_path.as_path()).chain(
        suite
            .test_modules
            .iter()
            .map(|module| module.path.as_path()),
    );
    for path in files {
        paths.insert(path.display().to_string(), path);
        if let Some(name) = suite
            .source_root
            .as_deref()
            .and_then(|root| kotodama_lang::driver::logical_source_name(path, root).ok())
        {
            paths.insert(name, path);
        }
    }
    let localize = |span: &mut kotodama_lang::diagnostic::SourceSpan| {
        if span.package_identity.is_none()
            && let Some(path) = span.source.as_ref().and_then(|name| paths.get(name))
        {
            span.source = Some(display_path(path));
        }
    };
    for diagnostic in &mut bundle.diagnostics {
        if let Some(span) = &mut diagnostic.primary_span {
            localize(span);
        }
        for label in &mut diagnostic.labels {
            localize(&mut label.span);
        }
        for fix in diagnostic
            .fix
            .iter_mut()
            .chain(diagnostic.alternative_fixes.iter_mut())
        {
            localize(&mut fix.span);
        }
    }
    SuiteError::Diagnostics(bundle)
}
#[derive(Clone, Debug)]
struct TestCase {
    name: String,
    fixture: Option<String>,
    /// Source file declaring the test (the target for inline tests).
    path: PathBuf,
    line: usize,
    column: usize,
}
struct DiscoveredSuite {
    target_path: PathBuf,
    target_source: String,
    target_program: Program,
    test_modules: Vec<DiscoveredTestModule>,
    tests: Vec<TestCase>,
    fixtures: HashMap<String, FixtureDecl>,
    /// Declaring file and action positions of each fixture, for located fixture errors.
    fixture_sites: HashMap<String, FixtureSite>,
    /// `const` declarations visible to fixture arguments.
    fixture_consts: HashMap<String, Expr>,
    sources: Vec<SourceModuleUnit>,
    artifacts: Vec<kotodama_lang::linker::SourceContractArtifact>,
    source_root: Option<PathBuf>,
}
struct DiscoveredTestModule {
    path: PathBuf,
    source: String,
    program: Program,
}
/// Where a fixture is declared: its file and the `line:column` of each action, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FixtureSite {
    path: PathBuf,
    actions: Vec<(usize, usize)>,
}
/// A compiled artifact with its compile report; the suite holds the test-harness capability while
/// the runtime target is an ordinary production contract.
struct CompiledArtifact<P = ivm::PreparedContract> {
    program: P,
    report: CompileReport,
    pc_base: u64,
}
struct CompiledSuite {
    suite: CompiledArtifact<ivm::KotoTestHarnessContract>,
    runtime: Option<CompiledArtifact>,
    runtime_entrypoints: HashMap<String, RuntimeEntrypoint>,
    tests: Vec<CompiledTestCase>,
    fixtures: HashMap<String, FixtureDecl>,
    fixture_sites: HashMap<String, FixtureSite>,
    fixture_consts: HashMap<String, Expr>,
    /// Immutable admitted compiled dependencies captured with this suite.
    artifacts: BTreeMap<String, ivm::PreparedContract>,
    /// Source owner for resolving fixture-relative artifact paths.
    source_root: Option<PathBuf>,
    /// Functions of the runtime seiyaku, or of a pure unit-test target, keyed to runtime PCs.
    coverage_functions: Vec<CoverageFunction>,
    /// Declared seiyaku functions with no code of their own in the profiled artifact.
    codeless_functions: Vec<CodelessFunction>,
    /// Source maps and file text for locating failures.
    context: Arc<SourceContext>,
    /// Chain discriminant used to compile account literals and derive fixture actors.
    chain_discriminant: u16,
}

/// Source map and PC base used for coverage and tracing of seiyaku code: the runtime target when
/// the suite has one, otherwise the suite itself.
fn profile_source<'a>(
    suite: &'a CompiledArtifact<ivm::KotoTestHarnessContract>,
    runtime: Option<&'a CompiledArtifact>,
) -> (&'a CompileReport, u64) {
    runtime.map_or((&suite.report, suite.pc_base), |runtime| {
        (&runtime.report, runtime.pc_base)
    })
}
#[derive(Clone)]
struct RuntimeEntrypoint {
    pc: u64,
    argument_schema: Option<EntrypointArgumentSchemaV1>,
    return_schema: ivm_abi::entrypoint::EntrypointValueTypeV1,
    authorization: EntrypointAuthorizationV1,
}
#[derive(Clone)]
struct CompiledTestCase {
    name: String,
    fixture: Option<String>,
    path: PathBuf,
    line: usize,
    column: usize,
    pc: u64,
}
#[derive(Clone)]
struct CoverageFunction {
    display_name: String,
    line: u32,
    pc_start: u64,
    pc_end: u64,
}
/// A declared seiyaku function that has no code of its own in the profiled artifact: the compiler
/// inlined it into its callers or omitted it as unused, so coverage cannot attribute execution
/// to it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CodelessFunction {
    display_name: String,
    line: u32,
}
/// Gas and cycles consumed by one nested kotoage, view, or lifecycle call made by a test.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EntrypointCall {
    entrypoint: String,
    gas: u64,
    cycles: u64,
    /// Instructions this call contributed to the runtime trace (zero when tracing is off).
    trace_steps: usize,
}
struct TestRunResult {
    name: String,
    path: PathBuf,
    line: usize,
    column: usize,
    elapsed: Duration,
    passed: bool,
    failure: Option<TestFailure>,
    /// Cycles executed by the test function itself, excluding nested seiyaku calls.
    harness_cycles: u64,
    /// Gas of the test function itself when it is the code under test (a pure unit-test target
    /// without a runtime seiyaku); zero otherwise, where only seiyaku calls are charged.
    own_gas: u64,
    /// Seiyaku calls made by the test, in order.
    calls: Vec<EntrypointCall>,
    trace: trace_capture::TestTrace,
}
impl TestRunResult {
    /// Execution gas of the code under test: the seiyaku calls this test made, or the test
    /// function itself for a pure unit-test target.
    fn gas(&self) -> u64 {
        self.calls
            .iter()
            .fold(self.own_gas, |total, call| total.saturating_add(call.gas))
    }
    /// Cycles executed by the test function and its seiyaku calls.
    fn cycles(&self) -> u64 {
        self.calls.iter().fold(self.harness_cycles, |total, call| {
            total.saturating_add(call.cycles)
        })
    }
}
/// What kind of failure ended a test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailureKind {
    /// `test::assert` or `test::assert_eq` did not hold.
    Assertion,
    /// A seiyaku call aborted with a nominal error enum variant.
    Rejected,
    /// The caller lacked a declared or runtime permission.
    PermissionDenied,
    /// Checked arithmetic, conversion, or decimal division faulted.
    NumericFault,
    /// Execution ran out of gas or cycles.
    GasExhausted,
    /// Call arguments did not match the target's argument schema.
    Arguments,
    /// A value failed to decode inside the VM (malformed pointer, Norito, or uninitialized state).
    Decode,
    /// The call violated the seiyaku lifecycle (pending `hajimari`, replayed or unstaged hooks).
    Lifecycle,
    /// `test::expect_reject_as` observed a different outcome than expected.
    Expectation,
    /// Test-harness misuse such as an unknown fixture actor.
    Harness,
    /// Any other VM trap.
    Trap,
}
impl FailureKind {
    /// Stable machine-readable spelling used in JSON and `JUnit` reports.
    const fn slug(self) -> &'static str {
        match self {
            Self::Assertion => "assertion",
            Self::Rejected => "rejected",
            Self::PermissionDenied => "permission_denied",
            Self::NumericFault => "numeric_fault",
            Self::GasExhausted => "gas_exhausted",
            Self::Arguments => "arguments",
            Self::Decode => "decode",
            Self::Lifecycle => "lifecycle",
            Self::Expectation => "expectation",
            Self::Harness => "harness",
            Self::Trap => "trap",
        }
    }
    /// Human headline prefix.
    const fn label(self) -> &'static str {
        match self {
            Self::Assertion => "assertion failed",
            Self::Rejected => "seiyaku call rejected",
            Self::PermissionDenied => "permission denied",
            Self::NumericFault => "numeric fault",
            Self::GasExhausted => "out of gas",
            Self::Arguments => "invalid arguments",
            Self::Decode => "decode error",
            Self::Lifecycle => "lifecycle violation",
            Self::Expectation => "unexpected outcome",
            Self::Harness => "test harness error",
            Self::Trap => "VM trap",
        }
    }
}
/// One located test failure.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TestFailure {
    kind: FailureKind,
    fault: Option<IvmFaultV1>,
    /// `path:line:column` (or `path:line`) of the failing site, when known.
    location: Option<String>,
    /// One-line description following the kind label.
    message: String,
    /// Additional lines: the failing source, actual and expected values, nested context.
    details: Vec<String>,
}
impl TestFailure {
    fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            fault: None,
            location: None,
            message: message.into(),
            details: Vec::new(),
        }
    }
    fn at(mut self, location: Option<String>) -> Self {
        if self.location.is_none() {
            self.location = location;
        }
        self
    }
    fn detail(mut self, line: impl Into<String>) -> Self {
        self.details.push(line.into());
        self
    }
    /// Complete multi-line rendering shared by every report format.
    fn render(&self) -> String {
        let mut rendered = self.kind.label().to_owned();
        if let Some(location) = &self.location {
            rendered.push_str(" at ");
            rendered.push_str(location);
        }
        if !self.message.is_empty() {
            rendered.push_str(": ");
            rendered.push_str(&self.message);
        }
        // Context lines first, then `help:` lines, whatever order they were attached in.
        let (help, context): (Vec<_>, Vec<_>) = self
            .details
            .iter()
            .partition(|line| line.starts_with("help: "));
        for line in context.into_iter().chain(help) {
            rendered.push_str("\n  ");
            rendered.push_str(line);
        }
        rendered
    }
}
/// Logical compiler source names mapped to the files and text they came from.
#[derive(Clone, Debug, Default)]
struct SourceFiles {
    files: BTreeMap<String, (PathBuf, Arc<str>)>,
}
impl SourceFiles {
    fn insert(&mut self, name: impl Into<String>, path: PathBuf, text: &str) {
        self.files.insert(name.into(), (path, Arc::from(text)));
    }
    /// The file and text a compiler source name (logical or absolute) refers to.
    fn get(&self, name: &str) -> Option<(&Path, &str)> {
        self.files
            .get(name)
            .map(|(path, text)| (path.as_path(), text.as_ref()))
            .or_else(|| {
                self.files
                    .values()
                    .find(|(path, _)| path.as_os_str() == name)
                    .map(|(path, text)| (path.as_path(), text.as_ref()))
            })
    }
    /// `path:line:column` for a byte range of a compiler source, plus the trimmed source line.
    fn locate(&self, name: &str, byte_start: usize) -> Option<(String, String)> {
        let (path, text) = self.get(name)?;
        let prefix = text.get(..byte_start)?;
        let line = prefix.matches('\n').count() + 1;
        let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
        let column = prefix[line_start..].chars().count() + 1;
        let line_text = text[line_start..]
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        Some((format!("{}:{line}:{column}", display_path(path)), line_text))
    }
}
/// Display a path relative to the working directory when it lies inside it.
fn display_path(path: &Path) -> String {
    std::env::current_dir()
        .ok()
        .and_then(|cwd| {
            let cwd = cwd.canonicalize().unwrap_or(cwd);
            path.strip_prefix(&cwd).ok().map(Path::to_path_buf)
        })
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or_else(|| path.to_path_buf())
        .display()
        .to_string()
}
/// One deterministic request for the non-printing Kotodama V1 test runner.
///
/// The runner never writes to stdout or stderr. Frontends retain sole ownership
/// of rendering, which lets them produce one structured output document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KotoTestRunRequestV1 {
    /// Target contract or standalone test module to discover and run.
    pub target: PathBuf,
    /// Optional test-name substring (or exact name when [`Self::exact`] is set).
    pub filter: Option<String>,
    /// Require [`Self::filter`] to match the complete test name.
    pub exact: bool,
    /// Maximum number of independent test workers.
    pub jobs: usize,
    /// Deterministic ordering seed; zero requests canonical name order.
    pub seed: u64,
    /// Account-address chain discriminant used while compiling and executing.
    pub chain_discriminant: u16,
    /// Enable the Kotodama ZK compilation surface.
    pub zk_enabled: bool,
}
impl KotoTestRunRequestV1 {
    /// Construct a canonical single-worker request for `target`.
    #[must_use]
    pub fn new(target: impl Into<PathBuf>, chain_discriminant: u16) -> Self {
        Self {
            target: target.into(),
            filter: None,
            exact: false,
            jobs: 1,
            seed: 0,
            chain_discriminant,
            zk_enabled: false,
        }
    }
}
/// Exact external module graph visible to one declared Kotodama test root.
///
/// Import aliases are parent-local and every package identity must be the exact
/// immutable identity selected by the caller's lock graph. Filesystem module
/// discovery is disabled when this graph is used.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KotoTestModuleGraphV1 {
    /// Immutable compiled contract artifacts owned by this exact source root.
    pub artifacts: Vec<kotodama_lang::linker::SourceContractArtifact>,
    /// Explicit companion files shared by the target and selected test sources.
    pub sources: Vec<SourceModuleUnit>,
    /// Direct aliases visible to the declared test root.
    pub imports: Vec<ImportBinding>,
    /// Complete locked package graph, including transitive modules.
    pub packages: Vec<SourcePackageUnit>,
}
/// Stable stage at which a structured Kotodama test request failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KotoTestRunPhaseV1 {
    /// Request fields were inconsistent or outside their V1 bounds.
    Request,
    /// Target and standalone test discovery failed.
    Discovery,
    /// The canonical Kotodama compiler rejected the discovered suite.
    Compilation,
    /// VM preparation or test execution failed before a case outcome existed.
    Execution,
}
/// Structured failure returned by the non-printing Kotodama test runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KotoTestRunErrorV1 {
    /// Stable failure stage.
    pub phase: KotoTestRunPhaseV1,
    /// Human-readable diagnostic detail suitable for a frontend error record.
    pub message: String,
    /// Canonical compiler diagnostics, including source locations and fixes, when available.
    pub diagnostics: Option<DiagnosticBundle>,
}
impl KotoTestRunErrorV1 {
    fn new(phase: KotoTestRunPhaseV1, message: impl Into<String>) -> Self {
        Self {
            phase,
            message: message.into(),
            diagnostics: None,
        }
    }
    fn from_suite(phase: KotoTestRunPhaseV1, error: SuiteError) -> Self {
        match error {
            SuiteError::Diagnostics(diagnostics) => Self {
                phase: KotoTestRunPhaseV1::Compilation,
                message: diagnostics.render_human(),
                diagnostics: Some(diagnostics),
            },
            error => Self::new(phase, error),
        }
    }
}
impl std::fmt::Display for KotoTestRunErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for KotoTestRunErrorV1 {}
/// Deterministic logical outcome of one Kotodama test case.
///
/// Wall-clock timing and VM trace data are intentionally absent: neither is a
/// consensus-stable test result, and frontends can measure an entire invocation
/// separately when operational timing is useful.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KotoTestCaseOutcomeV1 {
    /// Unique test function name.
    pub name: String,
    /// One-based source line of the test declaration.
    pub line: u32,
    /// Whether VM execution completed successfully.
    pub passed: bool,
    /// Canonical execution fault with authenticated origin, absent for application rejections.
    pub fault: Option<IvmFaultV1>,
    /// Rendered VM diagnostic for a failed case.
    pub failure: Option<String>,
}
/// One complete, deterministically ordered Kotodama test report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KotoTestRunReportV1 {
    /// Canonical target path selected during discovery.
    pub target: PathBuf,
    /// Ordering seed copied from the request.
    pub seed: u64,
    /// Case outcomes in deterministic execution order.
    pub cases: Vec<KotoTestCaseOutcomeV1>,
}
impl KotoTestRunReportV1 {
    /// Return the number of successful cases.
    #[must_use]
    pub fn passed(&self) -> usize {
        self.cases.iter().filter(|case| case.passed).count()
    }
    /// Return the number of failed cases.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.cases.len().saturating_sub(self.passed())
    }
    /// Return whether every selected case passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.failed() == 0
    }
}
/// Discover, compile, and run one Kotodama V1 test suite without writing output.
///
/// Case failures are successful report values with `passed = false`. Only an
/// invalid request or a discovery/compiler/runner infrastructure failure is
/// returned as [`KotoTestRunErrorV1`]. Case order is independent of filesystem
/// enumeration and worker scheduling.
///
/// # Errors
///
/// Returns a structured stage-tagged error when request validation, discovery,
/// compilation, or VM execution setup fails.
pub fn run_tests_structured_v1(
    request: &KotoTestRunRequestV1,
) -> Result<KotoTestRunReportV1, KotoTestRunErrorV1> {
    validate_structured_request(request)?;
    let suite = discover_suite(&request.target)
        .map_err(|error| KotoTestRunErrorV1::from_suite(KotoTestRunPhaseV1::Discovery, error))?;
    run_discovered_suite_structured(request, suite, None)
}
/// Run one explicitly declared test root against an exact locked module graph.
///
/// Unlike [`run_tests_structured_v1`], this entry point performs no sibling or
/// recursive test discovery. The supplied root, aliases, and immutable package
/// modules are the complete compilation authority.
///
/// # Errors
///
/// Returns a structured stage-tagged error when request validation, isolated
/// root discovery, exact typed linking, compilation, or VM execution fails.
pub fn run_tests_structured_with_modules_v1(
    request: &KotoTestRunRequestV1,
    modules: &KotoTestModuleGraphV1,
) -> Result<KotoTestRunReportV1, KotoTestRunErrorV1> {
    validate_structured_request(request)?;
    let suite = (|| {
        let path = fs::canonicalize(&request.target).map_err(|error| error.to_string())?;
        let (source, program) = parse_program_file(&path)?;
        if program.test_target.is_some() {
            return Err(SuiteError::Invalid(
                "exact module graphs require a directly declared test root".to_owned(),
            ));
        }
        let source_root = path.parent().map(Path::to_path_buf);
        finalize_suite_with_sources(
            path,
            source,
            program,
            Vec::new(),
            modules.sources.clone(),
            modules.artifacts.clone(),
            source_root,
        )
    })()
    .map_err(|error| KotoTestRunErrorV1::from_suite(KotoTestRunPhaseV1::Discovery, error))?;
    run_discovered_suite_structured(request, suite, Some(modules))
}
/// Run one caller-supplied test root against an exact locked module graph.
///
/// This is the structured source-set boundary for package managers and other authenticated callers.
/// The source text is never reopened from [`KotoTestRunRequestV1::target`], and no sibling or
/// recursive filesystem discovery occurs. The request target must exactly equal the source unit's
/// portable diagnostic name.
///
/// # Errors
///
/// Returns a structured stage-tagged error when the request/source binding is
/// invalid, the supplied root cannot be parsed as a direct test root, exact
/// typed linking fails, or VM execution setup fails.
pub fn run_tests_structured_source_with_modules_v1(
    request: &KotoTestRunRequestV1,
    root: &SourceModuleUnit,
    modules: &KotoTestModuleGraphV1,
) -> Result<KotoTestRunReportV1, KotoTestRunErrorV1> {
    run_tests_structured_source_set_with_modules_v1(request, root, None, modules)
}
/// Discover test names from one explicitly declared root without ambient files.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved or read, the source is not
/// a direct test root, parsing fails, or no `#[test]` function is declared.
pub fn discover_declared_test_names_v1(path: &Path) -> Result<Vec<String>, String> {
    let suite = discover_declared_suite(path)?;
    Ok(suite.tests.into_iter().map(|test| test.name).collect())
}
/// Discover test names from one explicitly supplied direct root.
///
/// No path is opened and no ambient source is discovered. The source name is
/// retained only as a bounded portable diagnostic identity.
///
/// # Errors
///
/// Returns an error when the source identity or text exceeds the typed-module
/// graph bounds, parsing fails, the root is indirect, or no test is declared.
pub fn discover_declared_test_names_source_v1(
    root: &SourceModuleUnit,
) -> Result<Vec<String>, String> {
    validate_structured_source(root)?;
    let suite = discover_declared_suite_from_source(root)?;
    Ok(suite.tests.into_iter().map(|test| test.name).collect())
}
fn run_discovered_suite_structured(
    request: &KotoTestRunRequestV1,
    mut suite: DiscoveredSuite,
    modules: Option<&KotoTestModuleGraphV1>,
) -> Result<KotoTestRunReportV1, KotoTestRunErrorV1> {
    filter_and_order_structured_tests(&mut suite.tests, request);
    if suite.tests.is_empty() {
        return Err(KotoTestRunErrorV1::new(
            KotoTestRunPhaseV1::Discovery,
            "no Kotodama tests matched the requested filter",
        ));
    }
    let compiled = modules
        .map_or_else(
            || compile_suite_for_chain(&suite, request.zk_enabled, request.chain_discriminant),
            |modules| {
                compile_suite_with_modules_for_chain(
                    &suite,
                    modules,
                    request.zk_enabled,
                    request.chain_discriminant,
                )
            },
        )
        .map_err(|error| KotoTestRunErrorV1::from_suite(KotoTestRunPhaseV1::Compilation, error))?;
    let results = execute_suite_for_chain(
        &compiled,
        TraceMode::Off,
        request.jobs,
        request.chain_discriminant,
    )
    .map_err(|error| KotoTestRunErrorV1::new(KotoTestRunPhaseV1::Execution, error))?;
    let cases = results
        .into_iter()
        .map(|result| {
            let line = u32::try_from(result.line).map_err(|_| {
                KotoTestRunErrorV1::new(
                    KotoTestRunPhaseV1::Execution,
                    format!("test `{}` source line exceeds the V1 bound", result.name),
                )
            })?;
            Ok(KotoTestCaseOutcomeV1 {
                name: result.name,
                line,
                passed: result.passed,
                fault: result.failure.as_ref().and_then(|failure| failure.fault),
                failure: result.failure.as_ref().map(TestFailure::render),
            })
        })
        .collect::<Result<Vec<_>, KotoTestRunErrorV1>>()?;
    Ok(KotoTestRunReportV1 {
        target: suite.target_path,
        seed: request.seed,
        cases,
    })
}
fn validate_structured_request(request: &KotoTestRunRequestV1) -> Result<(), KotoTestRunErrorV1> {
    if request.jobs == 0 {
        return Err(KotoTestRunErrorV1::new(
            KotoTestRunPhaseV1::Request,
            "Kotodama test worker count must be greater than zero",
        ));
    }
    if request.chain_discriminant == 0 {
        return Err(KotoTestRunErrorV1::new(
            KotoTestRunPhaseV1::Request,
            "Kotodama test chain discriminant must be in 1..=65535",
        ));
    }
    if request.exact && request.filter.is_none() {
        return Err(KotoTestRunErrorV1::new(
            KotoTestRunPhaseV1::Request,
            "exact Kotodama test selection requires a filter",
        ));
    }
    Ok(())
}
fn validate_structured_source_request(
    request: &KotoTestRunRequestV1,
    root: &SourceModuleUnit,
) -> Result<(), KotoTestRunErrorV1> {
    validate_structured_source(root)
        .map_err(|error| KotoTestRunErrorV1::new(KotoTestRunPhaseV1::Request, error))?;
    if request.target.as_path() != Path::new(&root.source_name) {
        return Err(KotoTestRunErrorV1::new(
            KotoTestRunPhaseV1::Request,
            "Kotodama test request target must equal the supplied source name",
        ));
    }
    Ok(())
}
fn validate_structured_source(root: &SourceModuleUnit) -> Result<(), String> {
    if root.source_name.is_empty()
        || root.source_name.len() > MAX_LOGICAL_SOURCE_PATH_BYTES
        || root.source.is_empty()
        || root.source.len() > MAX_MODULE_GRAPH_SOURCE_BYTES
    {
        return Err(format!(
            "supplied Kotodama test root must have a nonempty bounded source name and at most {MAX_MODULE_GRAPH_SOURCE_BYTES} UTF-8 source bytes"
        ));
    }
    ModuleBuildGraph::fingerprint(&SourceLinkRequest {
        artifacts: Vec::new(),
        sources: Vec::new(),
        root: root.clone(),
        imports: Vec::new(),
        packages: Vec::new(),
    })
    .map_err(|error| error.to_string())?;
    if root.source_name.contains('\\')
        || root
            .source_name
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(
            "supplied Kotodama test root source name must use its canonical logical spelling"
                .to_owned(),
        );
    }
    Ok(())
}
fn filter_and_order_structured_tests(tests: &mut Vec<TestCase>, request: &KotoTestRunRequestV1) {
    if let Some(filter) = request.filter.as_deref() {
        tests.retain(|test| {
            if request.exact {
                test.name == filter
            } else {
                test.name.contains(filter)
            }
        });
    }
    tests.sort_by(|left, right| {
        if request.seed == 0 {
            left.name
                .cmp(&right.name)
                .then_with(|| left.line.cmp(&right.line))
        } else {
            seeded_test_key(request.seed, &left.name)
                .cmp(&seeded_test_key(request.seed, &right.name))
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.line.cmp(&right.line))
        }
    });
}
/// Local diagnostic event only: it carries no chain provenance and cannot be committed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CapturedTestEvent {
    name: Name,
    payload: iroha_data_model::smart_contract::entrypoint::EntrypointReturnRecordV1,
}
struct KotoTestHost {
    inner: WsvHost,
    /// Bounded local owner of argument/return captures retained across nested VMs.
    record_budget: iroha_allocation::AllocationBudget,
    actors: HashMap<String, FixtureActor>,
    events: Vec<CapturedTestEvent>,
    base_public_inputs: BTreeMap<Name, Vec<u8>>,
    entrypoints: HashMap<String, RuntimeEntrypoint>,
    program: Option<ivm::PreparedContract>,
    contract_address: ContractAddress,
    last_failure: Option<TestFailure>,
    supplemental_trace: Option<ivm::zk::RuntimeTraceCapture>,
    lifecycle: Lifecycle,
    fixture_upgrade_staged: bool,
    /// Seiyaku calls made so far, for gas reporting.
    calls: Vec<EntrypointCall>,
    context: Arc<SourceContext>,
    /// Call-site record announced for the next `test::` helper call.
    pending_call_site: Option<kotodama_lang::testing::TestCallSite>,
    /// `path:line:column` and source text of the `test::` helper call in progress.
    active_call_site: Option<(String, Option<String>)>,
}
/// Display alias of the implicit caller used by `test::invoke_kotoage`.
const CURRENT_CALLER: &str = "current caller";
/// Gas limit of nested seiyaku calls; the gas they consume is reported per call.
const NESTED_GAS_LIMIT: u64 = u64::MAX;
/// Run the VM-backed Kotodama test harness for the unified `koto test` command.
///
/// Reports are written to stdout in the requested format; a `JUnit` file is written in addition when
/// requested.
///
/// # Errors
///
/// Returns a categorized error: usage problems, unreadable files, compile failures (with rendered
/// diagnostics), failing tests (after their report was printed), or runner failures.
pub fn run_cli(options: KotoTestCliOptions) -> Result<(), KotoTestCliError> {
    use KotoTestCliErrorKind as Kind;
    if options.jobs == 0 {
        return Err(KotoTestCliError::new(
            Kind::Usage,
            "--jobs must be greater than zero",
        ));
    }
    if options.chain_discriminant == 0 {
        return Err(KotoTestCliError::new(
            Kind::Usage,
            "--chain-discriminant must be in 1..=65535",
        ));
    }
    if options.exact && options.filter.is_none() {
        return Err(KotoTestCliError::new(
            Kind::Usage,
            "--exact requires --filter",
        ));
    }
    if options.format == KotoTestReportFormat::Junit && options.action != KotoTestAction::Run {
        return Err(KotoTestCliError::new(
            Kind::Usage,
            "JUnit output is available for `koto test run` only",
        ));
    }
    let source = options.source.as_ref().ok_or_else(|| KotoTestCliError::new(
        Kind::Usage,
        "koto test expects a seiyaku or standalone test module source; use musubi test for a project",
    ))?;
    let mut suite = discover_suite_with_root(source, options.source_root.as_deref())
        .map_err(SuiteError::into_cli)?;
    filter_and_order_tests(&mut suite.tests, &options);
    if options.action == KotoTestAction::List {
        return print_test_list(&suite, options.format);
    }
    if suite.tests.is_empty() {
        return Err(KotoTestCliError::new(
            Kind::Usage,
            options.filter.as_ref().map_or_else(
                || "no Kotodama tests matched the requested filter".to_owned(),
                |filter| {
                    format!(
                        "no Kotodama tests in {} match the filter `{filter}`",
                        display_path(source)
                    )
                },
            ),
        ));
    }
    let compiled = compile_suite_for_chain(&suite, options.zk_enabled, options.chain_discriminant)
        .map_err(|error| localize_suite_diagnostics(&suite, error).into_cli())?;
    let trace_mode = match options.action {
        KotoTestAction::Run => TraceMode::Off,
        KotoTestAction::Coverage => TraceMode::PcOnly,
        KotoTestAction::Trace => TraceMode::DeltaRegisters,
        KotoTestAction::List => unreachable!("list exits before compilation"),
    };
    let results = execute_suite_for_chain(
        &compiled,
        trace_mode,
        options.jobs,
        options.chain_discriminant,
    )
    .map_err(|error| KotoTestCliError::new(Kind::Internal, error))?;
    match options.action {
        KotoTestAction::Run => {
            emit_test_results(&suite, &results, options.format, options.seed)?;
            if options.gas_report && options.format == KotoTestReportFormat::Human {
                print!("{}", render_gas_report(&results));
            }
        }
        KotoTestAction::Coverage => {
            print_run_summary(&suite, &results);
            print!("{}", render_coverage_report(&compiled, &results));
        }
        KotoTestAction::Trace => {
            print_trace_report(&compiled, &results, options.format)
                .map_err(|error| KotoTestCliError::new(Kind::Internal, error))?;
            if options.format == KotoTestReportFormat::Human {
                print_run_summary(&suite, &results);
            }
        }
        KotoTestAction::List => unreachable!("list exits before execution"),
    }
    if let Some(path) = options.junit {
        fs::write(&path, render_test_junit(&suite, &results, options.seed)).map_err(|error| {
            KotoTestCliError::new(
                Kind::Io,
                format!("write JUnit report {}: {error}", path.display()),
            )
        })?;
    }
    if results.iter().any(|result| !result.passed) {
        return Err(KotoTestCliError::new(
            Kind::TestsFailed,
            "one or more Kotodama tests failed",
        ));
    }
    Ok(())
}
/// Error from [`check_test_module_v1`].
#[derive(Clone, Debug)]
pub enum KotoTestCheckErrorV1 {
    /// The test module or its target failed to compile.
    Diagnostics(DiagnosticBundle),
    /// The module could not be read or is not a valid test module.
    Other(KotoTestCliError),
}
/// Type-check a standalone `koto_test` module in test mode against its declared target.
///
/// This is what `koto check` runs for a `*.test.ko` module: production checks reject test-only
/// syntax by design, so test modules are checked the way `koto test` compiles them, without
/// running anything. Returns the resolved target path.
///
/// # Errors
///
/// Returns compiler diagnostics for invalid sources, or a categorized error when the module or
/// its target cannot be read.
pub fn check_test_module_v1(
    path: &Path,
    source_root: Option<&Path>,
    chain_discriminant: u16,
    zk_enabled: bool,
) -> Result<PathBuf, KotoTestCheckErrorV1> {
    let suite = discover_suite_with_root(path, source_root).map_err(|error| match error {
        SuiteError::Diagnostics(bundle) => KotoTestCheckErrorV1::Diagnostics(bundle),
        other => KotoTestCheckErrorV1::Other(other.into_cli()),
    })?;
    match compile_suite_for_chain(&suite, zk_enabled, chain_discriminant)
        .map_err(|error| localize_suite_diagnostics(&suite, error))
    {
        Ok(_) => Ok(suite.target_path),
        Err(SuiteError::Diagnostics(bundle)) => Err(KotoTestCheckErrorV1::Diagnostics(bundle)),
        Err(other) => Err(KotoTestCheckErrorV1::Other(other.into_cli())),
    }
}
/// Discover the Kotodama test names contributed by one target or standalone test source.
///
/// Developer frontends use this before dispatching filtered runs so a filter
/// that matches a test in one file does not fail early on an unrelated file.
///
/// # Errors
///
/// Returns an error for unreadable sources, invalid target bindings, parsing failures,
/// or a target and its companion modules that declare no tests.
pub fn discover_test_names(path: &Path) -> Result<Vec<String>, String> {
    let suite = discover_suite(path)?;
    Ok(suite.tests.into_iter().map(|test| test.name).collect())
}
fn filter_and_order_tests(tests: &mut Vec<TestCase>, options: &KotoTestCliOptions) {
    if let Some(filter) = options.filter.as_deref() {
        tests.retain(|test| {
            if options.exact {
                test.name == filter
            } else {
                test.name.contains(filter)
            }
        });
    }
    if options.seed != 0 {
        tests.sort_by_key(|test| seeded_test_key(options.seed, &test.name));
    }
}
fn seeded_test_key(seed: u64, name: &str) -> u64 {
    name.bytes()
        .fold(seed ^ 0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}
fn discover_suite(path: &Path) -> Result<DiscoveredSuite, SuiteError> {
    discover_suite_with_root(path, None)
}
/// Discover a suite from a seiyaku with inline tests or from a standalone test module.
///
/// Without an explicit root, a seiyaku's own directory is the source root, and a standalone
/// module uses the nearest directory containing both the module and its `koto_test` target, so
/// the conventional `contracts/` + `tests/` package layout works without `--source-root`.
fn discover_suite_with_root(
    path: &Path,
    source_root: Option<&Path>,
) -> Result<DiscoveredSuite, SuiteError> {
    let input_path = fs::canonicalize(path)
        .map_err(|error| SuiteError::Io(format!("cannot open {}: {error}", path.display())))?;
    let (input_source, input_program) = parse_program_file(&input_path)?;
    let explicit_root = source_root
        .map(|root| {
            fs::canonicalize(root).map_err(|error| {
                SuiteError::Io(format!(
                    "cannot open source root {}: {error}",
                    root.display()
                ))
            })
        })
        .transpose()?;
    if let Some(target_decl) = input_program.test_target.as_ref() {
        let target_path = resolve_target_path(&input_path, &target_decl.target)?;
        let root = explicit_root.unwrap_or_else(|| common_ancestor(&input_path, &target_path));
        discover_suite_from_standalone_test(&input_path, input_source, input_program, Some(&root))
    } else {
        let root = match explicit_root {
            Some(root) => root,
            None => input_path
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| SuiteError::Io(format!("{} has no parent", input_path.display())))?,
        };
        discover_suite_from_target(&input_path, input_source, input_program, Some(&root))
    }
}
/// Deepest directory containing both files.
fn common_ancestor(first: &Path, second: &Path) -> PathBuf {
    let mut ancestor = first.parent().map(Path::to_path_buf).unwrap_or_default();
    while !second.starts_with(&ancestor) {
        if !ancestor.pop() {
            break;
        }
    }
    ancestor
}
fn discover_declared_suite(path: &Path) -> Result<DiscoveredSuite, SuiteError> {
    let input_path = fs::canonicalize(path).map_err(|error| {
        SuiteError::Io(format!("failed to resolve {}: {error}", path.display()))
    })?;
    let (source, program) = parse_program_file(&input_path)?;
    if program.test_target.is_some() {
        return Err(SuiteError::Invalid(format!(
            "{} is an indirect koto_test module; exact module graphs require a directly declared test root",
            input_path.display()
        )));
    }
    finalize_suite(input_path, source, program, Vec::new())
}
fn discover_declared_suite_from_source(
    root: &SourceModuleUnit,
) -> Result<DiscoveredSuite, SuiteError> {
    discover_declared_suite_from_source_set(root, None, &[], &[])
}
fn discover_suite_from_target(
    path: &Path,
    target_source: String,
    target_program: Program,
    source_root: Option<&Path>,
) -> Result<DiscoveredSuite, SuiteError> {
    let standalone_tests = discover_standalone_tests_for_target(path)?;
    for test in &standalone_tests {
        validate_standalone_test_program(&test.path, path, &test.program)?;
    }
    finalize_suite_files(
        path.to_path_buf(),
        target_source,
        target_program,
        standalone_tests,
        source_root,
    )
}
fn discover_suite_from_standalone_test(
    test_path: &Path,
    test_source: String,
    test_program: Program,
    source_root: Option<&Path>,
) -> Result<DiscoveredSuite, SuiteError> {
    let target_decl = test_program.test_target.as_ref().ok_or_else(|| {
        SuiteError::Invalid(format!(
            "{} is missing a koto_test target declaration",
            test_path.display()
        ))
    })?;
    let target_path = resolve_target_path(test_path, &target_decl.target)?;
    let (target_source, target_program) = parse_program_file(&target_path)?;
    validate_standalone_test_program(test_path, &target_path, &test_program)?;
    finalize_suite_files(
        target_path,
        target_source,
        target_program,
        vec![DiscoveredTestModule {
            path: test_path.to_path_buf(),
            source: test_source,
            program: test_program,
        }],
        source_root,
    )
}
fn finalize_suite(
    target_path: PathBuf,
    target_source: String,
    target_program: Program,
    test_modules: Vec<DiscoveredTestModule>,
) -> Result<DiscoveredSuite, SuiteError> {
    finalize_suite_files(
        target_path,
        target_source,
        target_program,
        test_modules,
        None,
    )
}
fn finalize_suite_files(
    target_path: PathBuf,
    target_source: String,
    target_program: Program,
    test_modules: Vec<DiscoveredTestModule>,
    explicit_root: Option<&Path>,
) -> Result<DiscoveredSuite, SuiteError> {
    let source_root = explicit_root
        .map(Path::canonicalize)
        .transpose()
        .map_err(|error| error.to_string())?
        .or_else(|| {
            target_path
                .is_absolute()
                .then(|| target_path.parent().map(Path::to_path_buf))
                .flatten()
        });
    let inventory = if let Some(root) = source_root.as_deref() {
        let logical = |path: &Path| {
            kotodama_lang::driver::logical_source_name(path, root).map_err(|_| {
                format!(
                    "{} is outside the source root {}; pass --source-root <dir> naming a directory that contains both the tests and their koto_test target",
                    path.display(),
                    root.display()
                )
            })
        };
        let mut entries = vec![SourceModuleUnit {
            source_name: logical(&target_path)?,
            source: target_source.clone(),
        }];
        for module in &test_modules {
            entries.push(SourceModuleUnit {
                source_name: logical(&module.path)?,
                source: module.source.clone(),
            });
        }
        kotodama_lang::driver::load_source_inventory(&entries, root, &BTreeMap::new())
            .map_err(suite_build_error)?
    } else {
        kotodama_lang::driver::SourceInventory::default()
    };
    finalize_suite_with_sources(
        target_path,
        target_source,
        target_program,
        test_modules,
        inventory.sources,
        inventory.artifacts,
        source_root,
    )
}
fn finalize_suite_with_sources(
    target_path: PathBuf,
    target_source: String,
    target_program: Program,
    test_modules: Vec<DiscoveredTestModule>,
    sources: Vec<SourceModuleUnit>,
    artifacts: Vec<kotodama_lang::linker::SourceContractArtifact>,
    source_root: Option<PathBuf>,
) -> Result<DiscoveredSuite, SuiteError> {
    let mut tests = Vec::new();
    let mut test_names = HashSet::new();
    let source_name = |path: &Path| {
        source_root.as_deref().map_or_else(
            || Ok(path.display().to_string()),
            |root| {
                kotodama_lang::driver::logical_source_name(path, root)
                    .map_err(|error| error.to_string())
            },
        )
    };
    let mut included_programs = Vec::new();
    collect_included_test_programs(
        &source_name(&target_path)?,
        &target_program,
        &sources,
        &mut BTreeSet::new(),
        &mut included_programs,
    )?;
    for module in &test_modules {
        collect_included_test_programs(
            &source_name(&module.path)?,
            &module.program,
            &sources,
            &mut BTreeSet::new(),
            &mut included_programs,
        )?;
    }
    let included_path = |name: &str| {
        source_root
            .as_deref()
            .map_or_else(|| PathBuf::from(name), |root| root.join(name))
    };
    collect_tests_into(&target_program, &target_path, &mut test_names, &mut tests)?;
    for module in &test_modules {
        collect_tests_into(&module.program, &module.path, &mut test_names, &mut tests)?;
    }
    for (name, program) in &included_programs {
        collect_tests_into(program, &included_path(name), &mut test_names, &mut tests)?;
    }
    if tests.is_empty() {
        return Err(SuiteError::Invalid(format!(
            "no #[test] Kotodama functions were found for {}; tests live in a `*.test.ko` module that declares `koto_test {{ target: \"...\" }}`, so pass that module to `koto test`",
            display_path(&target_path)
        )));
    }
    let fixtures = build_fixture_map(
        &target_program
            .fixtures
            .iter()
            .chain(
                test_modules
                    .iter()
                    .flat_map(|module| module.program.fixtures.iter()),
            )
            .chain(
                included_programs
                    .iter()
                    .flat_map(|(_, program)| program.fixtures.iter()),
            )
            .cloned()
            .collect::<Vec<_>>(),
    )?;
    let mut fixture_sites = locate_fixtures(&target_path, &target_source);
    for module in &test_modules {
        fixture_sites.extend(locate_fixtures(&module.path, &module.source));
    }
    for (name, _) in &included_programs {
        if let Some(source) = sources.iter().find(|source| &source.source_name == name) {
            fixture_sites.extend(locate_fixtures(&included_path(name), &source.source));
        }
    }
    let fixture_consts = std::iter::once(&target_program)
        .chain(test_modules.iter().map(|module| &module.program))
        .chain(included_programs.iter().map(|(_, program)| program))
        .flat_map(|program| program.items.iter())
        .filter_map(|item| match item {
            Item::Const(constant) => Some((constant.name.clone(), constant.value.clone())),
            _ => None,
        })
        .collect();
    Ok(DiscoveredSuite {
        target_path,
        target_source,
        target_program,
        test_modules,
        tests,
        fixtures,
        fixture_sites,
        fixture_consts,
        sources,
        artifacts,
        source_root,
    })
}
/// Find each `fixture NAME { action(...) ... }` declaration and the position of its actions.
///
/// The AST keeps fixture actions without spans, so fixture errors are located from the same
/// token stream the parser consumed.
fn locate_fixtures(path: &Path, source: &str) -> HashMap<String, FixtureSite> {
    use kotodama_lang::lexer::TokenKind;
    let Ok(tokens) = kotodama_lang::lexer::lex(source) else {
        return HashMap::new();
    };
    let mut sites = HashMap::new();
    let mut index = 0;
    while index + 2 < tokens.len() {
        let is_fixture = matches!(&tokens[index].kind, TokenKind::Ident(word) if word == "fixture");
        let (TokenKind::Ident(name), TokenKind::LBrace) =
            (&tokens[index + 1].kind, &tokens[index + 2].kind)
        else {
            index += 1;
            continue;
        };
        if !is_fixture {
            index += 1;
            continue;
        }
        let mut site = FixtureSite {
            path: path.to_path_buf(),
            actions: Vec::new(),
        };
        let mut depth = 1_usize;
        let mut cursor = index + 3;
        while cursor < tokens.len() && depth > 0 {
            match &tokens[cursor].kind {
                TokenKind::LBrace | TokenKind::LParen | TokenKind::LBracket => {
                    if depth == 1
                        && tokens[cursor].kind == TokenKind::LParen
                        && let Some(previous) = cursor.checked_sub(1).map(|at| &tokens[at])
                        && matches!(previous.kind, TokenKind::Ident(_))
                    {
                        site.actions.push((previous.line, previous.column));
                    }
                    depth += 1;
                }
                TokenKind::RBrace | TokenKind::RParen | TokenKind::RBracket => depth -= 1,
                _ => {}
            }
            cursor += 1;
        }
        sites.insert(name.clone(), site);
        index = cursor;
    }
    sites
}
fn collect_included_test_programs(
    source_name: &str,
    program: &Program,
    sources: &[SourceModuleUnit],
    visited: &mut BTreeSet<String>,
    output: &mut Vec<(String, Program)>,
) -> Result<(), SuiteError> {
    let mut pending = vec![(source_name.to_owned(), program.directives.clone())];
    while let Some((name, directives)) = pending.pop() {
        for directive in directives {
            let kotodama_lang::ast::SourceDirectiveKind::Include { path } = directive.kind else {
                continue;
            };
            let name = kotodama_lang::linker::resolve_source_path(&name, &path)
                .map_err(|error| SuiteError::Diagnostics(error.into_diagnostics()))?;
            if !visited.insert(name.clone()) {
                continue;
            }
            let source = sources
                .iter()
                .find(|source| source.source_name == name)
                .ok_or_else(|| format!("missing included test source `{name}`"))?;
            let file = kotodama_lang::source::SourceFile::new(
                kotodama_lang::source::SourceId(0),
                name.as_str(),
                source.source.as_str(),
            );
            let program =
                parser::parse_fragment_source(&file, kotodama_lang::source::FrontendBudget::v1())
                    .map_err(SuiteError::Diagnostics)?;
            pending.push((name.clone(), program.directives.clone()));
            output.push((name, program));
        }
    }
    Ok(())
}
fn suite_build_error(error: kotodama_lang::driver::BuildError) -> SuiteError {
    match error.into_diagnostics() {
        Ok(diagnostics) => SuiteError::Diagnostics(diagnostics),
        Err(error) => SuiteError::Invalid(error.to_string()),
    }
}
fn parse_program_file(path: &Path) -> Result<(String, Program), SuiteError> {
    let src = read_source_file(path)
        .map_err(|err| SuiteError::Io(format!("failed to read {}: {err}", path.display())))?;
    let file = kotodama_lang::source::SourceFile::new(
        kotodama_lang::source::SourceId(0),
        display_path(path),
        src.as_str(),
    );
    let program = parser::parse_source(&file, kotodama_lang::source::FrontendBudget::v1())
        .map_err(SuiteError::Diagnostics)?;
    Ok((src, program))
}
fn resolve_target_path(test_file: &Path, raw_target: &str) -> Result<PathBuf, SuiteError> {
    let parent = test_file.parent().ok_or_else(|| {
        SuiteError::Io(format!("{} has no parent directory", test_file.display()))
    })?;
    let candidate = parent.join(raw_target);
    fs::canonicalize(&candidate).map_err(|err| {
        SuiteError::Io(format!(
            "koto_test target `{raw_target}` declared in {} cannot be opened: {err}",
            display_path(test_file)
        ))
    })
}
fn discover_standalone_tests_for_target(
    target_path: &Path,
) -> Result<Vec<DiscoveredTestModule>, SuiteError> {
    let base_dir = target_path.parent().ok_or_else(|| {
        SuiteError::Io(format!("{} has no parent directory", target_path.display()))
    })?;
    let mut paths = BTreeSet::new();
    for entry in fs::read_dir(base_dir)
        .map_err(|err| SuiteError::Io(format!("failed to read {}: {err}", base_dir.display())))?
    {
        let entry = entry
            .map_err(|err| SuiteError::Io(format!("failed to read directory entry: {err}")))?;
        let path = entry.path();
        if path == target_path {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("ko") {
            continue;
        }
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".test.ko"))
        {
            paths.insert(fs::canonicalize(&path).map_err(|err| {
                SuiteError::Io(format!("failed to resolve {}: {err}", path.display()))
            })?);
        }
    }
    let tests_dir = base_dir.join("tests");
    if tests_dir.exists() {
        collect_ko_files(&tests_dir, &mut paths)?;
    }
    let mut discovered = Vec::new();
    for test_path in paths {
        let (source, program) = parse_program_file(&test_path)?;
        if let Some(test_target) = &program.test_target {
            let resolved = resolve_target_path(&test_path, &test_target.target)?;
            if resolved == target_path {
                discovered.push(DiscoveredTestModule {
                    path: test_path,
                    source,
                    program,
                });
            }
        }
    }
    Ok(discovered)
}
fn collect_ko_files(dir: &Path, out: &mut BTreeSet<PathBuf>) -> Result<(), SuiteError> {
    for entry in fs::read_dir(dir)
        .map_err(|err| SuiteError::Io(format!("failed to read {}: {err}", dir.display())))?
    {
        let entry = entry
            .map_err(|err| SuiteError::Io(format!("failed to read directory entry: {err}")))?;
        let path = entry.path();
        if path.is_dir() {
            collect_ko_files(&path, out)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("ko") {
            continue;
        }
        out.insert(fs::canonicalize(&path).map_err(|err| {
            SuiteError::Io(format!("failed to resolve {}: {err}", path.display()))
        })?);
    }
    Ok(())
}
fn validate_standalone_test_program(
    test_path: &Path,
    target_path: &Path,
    program: &Program,
) -> Result<(), SuiteError> {
    let target_decl = program.test_target.as_ref().ok_or_else(|| {
        SuiteError::Invalid(format!(
            "{} must include `koto_test {{ target: \"...\" }}`",
            test_path.display()
        ))
    })?;
    let resolved_target = resolve_target_path(test_path, &target_decl.target)?;
    if resolved_target != target_path {
        return Err(SuiteError::Invalid(format!(
            "{} targets {}, expected {}",
            test_path.display(),
            resolved_target.display(),
            target_path.display()
        )));
    }
    Ok(validate_standalone_test_items(test_path, program)?)
}
fn validate_standalone_test_items(test_path: &Path, program: &Program) -> Result<(), String> {
    if program.unit.kind != SourceUnitKind::Module {
        return Err(format!(
            "{} must declare a non-deployable module in standalone test mode",
            test_path.display()
        ));
    }
    for item in &program.items {
        match item {
            Item::Function(func) => {
                if func.modifiers.kind != FunctionKind::Private {
                    return Err(format!(
                        "{} contains a non-local function `{}`; standalone test files may only define private helpers and #[test] functions",
                        test_path.display(),
                        func.name
                    ));
                }
            }
            Item::State(_) | Item::Trigger(_) | Item::Event(_) => {
                return Err(format!(
                    "{} may not declare durable state, triggers or events",
                    test_path.display()
                ));
            }
            Item::Struct(_) | Item::Enum(_) | Item::Const(_) => {}
        }
    }
    Ok(())
}
fn collect_tests_into(
    program: &Program,
    path: &Path,
    names: &mut HashSet<String>,
    tests: &mut Vec<TestCase>,
) -> Result<(), String> {
    for item in &program.items {
        let Item::Function(func) = item else {
            continue;
        };
        if !func.modifiers.is_test {
            continue;
        }
        if !names.insert(func.name.clone()) {
            return Err(format!("duplicate test function `{}`", func.name));
        }
        tests.push(TestCase {
            name: func.name.clone(),
            fixture: func.modifiers.test_fixture.clone(),
            path: path.to_path_buf(),
            line: func.location.line,
            column: func.location.column,
        });
    }
    Ok(())
}
fn build_fixture_map(fixtures: &[FixtureDecl]) -> Result<HashMap<String, FixtureDecl>, String> {
    let mut map = HashMap::new();
    for fixture in fixtures {
        if map.contains_key(&fixture.name) {
            return Err(format!("duplicate fixture `{}`", fixture.name));
        }
        map.insert(fixture.name.clone(), fixture.clone());
    }
    Ok(map)
}
#[cfg(test)]
fn compile_suite(suite: &DiscoveredSuite, zk_enabled: bool) -> Result<CompiledSuite, SuiteError> {
    compile_suite_for_chain(
        suite,
        zk_enabled,
        iroha_data_model::account::address::chain_discriminant(),
    )
}
fn compile_suite_for_chain(
    suite: &DiscoveredSuite,
    zk_enabled: bool,
    chain_discriminant: u16,
) -> Result<CompiledSuite, SuiteError> {
    if !suite.sources.is_empty() || !suite.artifacts.is_empty() {
        return compile_suite_with_modules_for_chain(
            suite,
            &KotoTestModuleGraphV1 {
                sources: suite.sources.clone(),
                artifacts: suite.artifacts.clone(),
                ..KotoTestModuleGraphV1::default()
            },
            zk_enabled,
            chain_discriminant,
        );
    }
    let source_name = suite.target_path.display().to_string();
    let test_opts = CompilerOptions {
        force_zk: zk_enabled,
        chain_discriminant,
        mode: CompilerMode::Test,
        ..CompilerOptions::default()
    };
    let target = TestSourceUnit {
        source_name: source_name.clone(),
        source: suite.target_source.clone(),
    };
    let test_modules = suite
        .test_modules
        .iter()
        .map(|module| TestSourceUnit {
            source_name: module.path.display().to_string(),
            source: module.source.clone(),
        })
        .collect::<Vec<_>>();
    let mut source_files = SourceFiles::default();
    source_files.insert(source_name, suite.target_path.clone(), &suite.target_source);
    for module in &suite.test_modules {
        source_files.insert(
            module.path.display().to_string(),
            module.path.clone(),
            &module.source,
        );
    }
    let outputs = CompilerSession::new(test_opts)
        .build_test_sources(&target, &test_modules)
        .map_err(SuiteError::Diagnostics)?;
    prepare_compiled_suite(
        suite,
        outputs,
        source_files,
        chain_discriminant,
        &suite.artifacts,
    )
}
fn compile_suite_with_modules_for_chain(
    suite: &DiscoveredSuite,
    modules: &KotoTestModuleGraphV1,
    zk_enabled: bool,
    chain_discriminant: u16,
) -> Result<CompiledSuite, SuiteError> {
    let source_name = if suite.target_path.is_absolute() {
        let project_root = suite
            .source_root
            .as_deref()
            .or_else(|| suite.target_path.parent())
            .ok_or_else(|| {
                SuiteError::Invalid(format!(
                    "Kotodama test target `{}` has no project parent directory",
                    suite.target_path.display()
                ))
            })?;
        kotodama_lang::driver::logical_source_name(&suite.target_path, project_root)
            .map_err(|error| SuiteError::Invalid(error.to_string()))?
    } else {
        suite.target_path.display().to_string()
    };
    let mut source_files = SourceFiles::default();
    source_files.insert(
        source_name.clone(),
        suite.target_path.clone(),
        &suite.target_source,
    );
    let test_units = suite
        .test_modules
        .iter()
        .map(|module| {
            let name = suite
                .source_root
                .as_deref()
                .map(|root| kotodama_lang::driver::logical_source_name(&module.path, root))
                .transpose()
                .map_err(|error| SuiteError::Invalid(error.to_string()))?
                .unwrap_or_else(|| module.path.display().to_string());
            source_files.insert(name.clone(), module.path.clone(), &module.source);
            Ok(SourceModuleUnit {
                source_name: name,
                source: module.source.clone(),
            })
        })
        .collect::<Result<Vec<_>, SuiteError>>()?;
    for unit in &modules.sources {
        let path = suite.source_root.as_deref().map_or_else(
            || PathBuf::from(&unit.source_name),
            |root| root.join(&unit.source_name),
        );
        source_files.insert(unit.source_name.clone(), path, &unit.source);
    }
    let outputs = ModuleBuildGraph::default()
        .build_test_project_with_sources(
            SourceLinkRequest {
                artifacts: modules.artifacts.clone(),
                sources: modules.sources.clone(),
                root: SourceModuleUnit {
                    source_name: source_name.clone(),
                    source: suite.target_source.clone(),
                },
                imports: modules.imports.clone(),
                packages: modules.packages.clone(),
            },
            &test_units,
            CompilerOptions {
                force_zk: zk_enabled,
                chain_discriminant,
                mode: CompilerMode::Test,
                ..CompilerOptions::default()
            },
            &source_name,
        )
        .map_err(SuiteError::Diagnostics)?;
    prepare_compiled_suite(
        suite,
        outputs,
        source_files,
        chain_discriminant,
        &modules.artifacts,
    )
}
fn prepare_compiled_suite(
    suite: &DiscoveredSuite,
    outputs: TestCompileOutput,
    source_files: SourceFiles,
    chain_discriminant: u16,
    artifacts: &[kotodama_lang::linker::SourceContractArtifact],
) -> Result<CompiledSuite, SuiteError> {
    let internal = |message: String| SuiteError::Invalid(message);
    let artifacts = artifacts
        .iter()
        .map(|artifact| {
            ivm::prepare_contract(Arc::from(artifact.artifact.clone()))
                .map(|prepared| (artifact.source_name.clone(), prepared))
                .map_err(|error| {
                    internal(format!(
                        "invalid captured fixture artifact `{}`: {error}",
                        artifact.source_name
                    ))
                })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let test_output = outputs.suite;
    let test_contract_interface = test_output.contract_interface().clone();
    let test_report = test_output.report;
    let suite_program =
        ivm::prepare_koto_test_contract(Arc::from(test_output.artifact), test_contract_interface)
            .map_err(|err| {
            internal(format!(
                "failed to prepare compiled Kotodama test suite: {err}"
            ))
        })?;
    if suite_program.prepared().code_hash() != test_report.artifact_hash {
        return Err(internal(format!(
            "compiled suite artifact hash mismatch: expected {}, got {}",
            test_report.artifact_hash,
            suite_program.prepared().code_hash()
        )));
    }
    let test_pc_base = suite_program.prepared().instruction_entry_pc();
    let suite_artifact = CompiledArtifact {
        program: suite_program,
        report: test_report,
        pc_base: test_pc_base,
    };
    let (runtime, runtime_entrypoints) = if let Some(runtime_output) = outputs.runtime {
        let runtime_report = runtime_output.report;
        let runtime_program =
            ivm::prepare_contract(Arc::from(runtime_output.artifact)).map_err(|err| {
                internal(format!(
                    "failed to prepare compiled runtime contract: {err}"
                ))
            })?;
        if runtime_program.code_hash() != runtime_report.artifact_hash {
            return Err(internal(format!(
                "compiled runtime artifact hash mismatch: expected {}, got {}",
                runtime_report.artifact_hash,
                runtime_program.code_hash()
            )));
        }
        let runtime_pc_base = runtime_program.instruction_entry_pc();
        let runtime_entrypoints = runtime_program
            .contract_interface()
            .entrypoints
            .iter()
            .map(|entry| {
                let pc = runtime_program
                    .entrypoint_pc(&entry.name)
                    .expect("prepared runtime indexes every validated entrypoint");
                (
                    entry.name.clone(),
                    RuntimeEntrypoint {
                        pc,
                        argument_schema: entry.argument_schema.clone(),
                        return_schema: entry
                            .return_schema
                            .clone()
                            .expect("validated runtime return schema"),
                        authorization: entry.authorization.clone(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        (
            Some(CompiledArtifact {
                program: runtime_program,
                report: runtime_report,
                pc_base: runtime_pc_base,
            }),
            runtime_entrypoints,
        )
    } else {
        (None, HashMap::new())
    };
    let mut test_pcs = HashMap::new();
    for entry in &suite_artifact.report.budget_report {
        test_pcs
            .entry(entry.function_name.clone())
            .or_insert_with(|| test_pc_base.saturating_add(entry.pc_start));
    }
    let tests = suite
        .tests
        .iter()
        .map(|test| {
            let pc = test_pcs
                .get(&test.name)
                .copied()
                .ok_or_else(|| internal(format!("missing debug info for test `{}`", test.name)))?;
            Ok(CompiledTestCase {
                name: test.name.clone(),
                fixture: test.fixture.clone(),
                path: test.path.clone(),
                line: test.line,
                column: test.column,
                pc,
            })
        })
        .collect::<Result<Vec<_>, SuiteError>>()?;
    let source_names = suite_artifact
        .report
        .symbolized_source_map()
        .into_iter()
        .chain(
            runtime
                .iter()
                .flat_map(|runtime| runtime.report.symbolized_source_map()),
        )
        .filter_map(|entry| {
            entry
                .source
                .source_path
                .clone()
                .map(|path| (entry.source.source_id, path))
        })
        .collect();
    let context = Arc::new(SourceContext {
        seiyaku_name: suite.target_program.unit.name.clone(),
        files: source_files,
        source_names,
        harness: suite_artifact.report.symbolized_source_map(),
        harness_base: suite_artifact.pc_base,
        runtime: runtime
            .as_ref()
            .map(|runtime| runtime.report.symbolized_source_map())
            .unwrap_or_default(),
        runtime_base: runtime.as_ref().map_or(0, |runtime| runtime.pc_base),
        runtime_hash: runtime.as_ref().map(|runtime| runtime.report.artifact_hash),
        harness_hash: Some(suite_artifact.report.artifact_hash),
    });
    let (profile_report, profile_pc_base) = profile_source(&suite_artifact, runtime.as_ref());
    let mut coverage_functions =
        build_coverage_functions(&suite.target_program, profile_report, profile_pc_base);
    coverage_functions.retain(|function| {
        !suite
            .tests
            .iter()
            .any(|test| test.name == function.display_name)
    });
    let codeless_functions = codeless_functions(&suite.target_program, &coverage_functions);
    Ok(CompiledSuite {
        suite: suite_artifact,
        runtime,
        runtime_entrypoints,
        tests,
        fixtures: suite.fixtures.clone(),
        fixture_sites: suite.fixture_sites.clone(),
        fixture_consts: suite.fixture_consts.clone(),
        artifacts,
        source_root: suite.source_root.clone(),
        coverage_functions,
        codeless_functions,
        context,
        chain_discriminant,
    })
}
/// Declared non-test functions of the seiyaku under test that emitted no code of their own.
fn codeless_functions(program: &Program, emitted: &[CoverageFunction]) -> Vec<CodelessFunction> {
    let mut functions = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Function(function)
                if !function.modifiers.is_test
                    && !emitted
                        .iter()
                        .any(|emitted| emitted.display_name == function.name) =>
            {
                Some(CodelessFunction {
                    display_name: function.name.clone(),
                    line: u32::try_from(function.location.line).unwrap_or(u32::MAX),
                })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    functions.sort_by(|left, right| {
        (left.line, &left.display_name).cmp(&(right.line, &right.display_name))
    });
    functions
}
fn build_coverage_functions(
    program: &Program,
    report: &CompileReport,
    pc_base: u64,
) -> Vec<CoverageFunction> {
    let test_names = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Function(func) if func.modifiers.is_test => Some(func.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut functions = report
        .budget_report
        .iter()
        .filter_map(|entry| {
            let display_name = normalize_user_function_name(&entry.function_name)?;
            if test_names.contains(display_name) {
                return None;
            }
            Some(CoverageFunction {
                display_name: display_name.to_string(),
                line: entry.source.as_ref().map_or(0, |source| source.line),
                pc_start: pc_base.saturating_add(entry.pc_start),
                pc_end: pc_base.saturating_add(entry.pc_end),
            })
        })
        .collect::<Vec<_>>();
    functions.sort_by_key(|function| (function.line, function.display_name.clone()));
    functions
}
fn normalize_user_function_name(name: &str) -> Option<&str> {
    if name.starts_with("__") {
        return None;
    }
    Some(name)
}
#[cfg(test)]
fn execute_suite(
    compiled: &CompiledSuite,
    trace_mode: TraceMode,
    jobs: usize,
) -> Result<Vec<TestRunResult>, String> {
    execute_suite_for_chain(
        compiled,
        trace_mode,
        jobs,
        iroha_data_model::account::address::chain_discriminant(),
    )
}
fn execute_suite_for_chain(
    compiled: &CompiledSuite,
    trace_mode: TraceMode,
    jobs: usize,
    chain_discriminant: u16,
) -> Result<Vec<TestRunResult>, String> {
    let worker_count = jobs.min(compiled.tests.len().max(1));
    if worker_count == 1 {
        let _chain_discriminant = ChainDiscriminantGuard::enter(chain_discriminant);
        return compiled
            .tests
            .iter()
            .map(|test| execute_test(compiled, test, trace_mode))
            .collect();
    }
    let joined = std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(worker_count);
        for worker in 0..worker_count {
            workers.push(scope.spawn(move || {
                let _chain_discriminant = ChainDiscriminantGuard::enter(chain_discriminant);
                compiled
                    .tests
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| index % worker_count == worker)
                    .map(|(index, test)| {
                        execute_test(compiled, test, trace_mode).map(|result| (index, result))
                    })
                    .collect::<Result<Vec<_>, String>>()
            }));
        }
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| "Kotodama test worker panicked".to_owned())?
            })
            .collect::<Result<Vec<_>, String>>()
    })?;
    let mut indexed = joined.into_iter().flatten().collect::<Vec<_>>();
    indexed.sort_by_key(|(index, _)| *index);
    Ok(indexed.into_iter().map(|(_, result)| result).collect())
}
fn execute_test(
    compiled: &CompiledSuite,
    test: &CompiledTestCase,
    trace_mode: TraceMode,
) -> Result<TestRunResult, String> {
    let result = |elapsed,
                  failure: Option<TestFailure>,
                  (harness_cycles, own_gas): (u64, u64),
                  calls,
                  trace| TestRunResult {
        name: test.name.clone(),
        path: test.path.clone(),
        line: test.line,
        column: test.column,
        elapsed,
        passed: failure.is_none(),
        failure,
        harness_cycles,
        own_gas,
        calls,
        trace,
    };
    let mut host = match build_host_for_fixture(compiled, test.fixture.as_deref()) {
        Ok(host) => host,
        Err(failure) => {
            // A failing action names its own line; an unknown fixture names the test using it.
            let test_site = test_location(&test.path, test.line, test.column);
            return Ok(result(
                Duration::ZERO,
                Some(failure.at(Some(test_site))),
                (0, 0),
                Vec::new(),
                trace_capture::TestTrace::default(),
            ));
        }
    };
    let mut vm = IVM::try_new(u64::MAX)
        .map_err(|err| format!("failed to allocate Kotodama test VM: {err}"))?;
    vm.load_koto_test_harness(&compiled.suite.program)
        .map_err(|err| format!("failed to load compiled suite: {err}"))?;
    vm.set_program_counter(test.pc)
        .map_err(|err| format!("failed to jump to test `{}`: {err}", test.name))?;
    vm.set_trace_mode(trace_mode);
    let started = Instant::now();
    let outcome = vm.run_with_host(&mut host);
    let elapsed = started.elapsed();
    if let Err(error) = &outcome
        && error.execution_deferral().is_some()
    {
        return Err(format!(
            "Kotodama test `{}` execution deferred: {error}",
            test.name
        ));
    }
    let failure = outcome
        .err()
        .map(|error| harness_failure(compiled, test, &vm, &mut host, &error));
    let trace = trace_capture::capture_report(&vm, host.supplemental_trace.as_ref())
        .map_err(|err| format!("failed to retain test `{}` trace: {err}", test.name))?;
    let harness_cycles = vm.get_cycle_count();
    let own_gas = if compiled.runtime.is_none() {
        u64::MAX.saturating_sub(vm.remaining_gas())
    } else {
        0
    };
    Ok(result(
        elapsed,
        failure,
        (harness_cycles, own_gas),
        std::mem::take(&mut host.calls),
        trace,
    ))
}
/// Explain why the test function stopped, preferring the host's own failure record.
fn harness_failure(
    compiled: &CompiledSuite,
    test: &CompiledTestCase,
    vm: &IVM,
    host: &mut KotoTestHost,
    error: &ivm::VMError,
) -> TestFailure {
    let test_site = format!("{}:{}:{}", display_path(&test.path), test.line, test.column);
    if let Some(failure) = host.last_failure.take() {
        return failure.at(Some(test_site));
    }
    let diagnostic = vm.last_diagnostic();
    let trap = diagnostic.map(|diagnostic| diagnostic.trap_kind);
    let mut failure = classify_vm_error(error, trap);
    failure.fault = vm.execution_fault(error, IvmFaultPositionV1::ReturnValidation);
    let source_pc = match failure.fault {
        Some(fault) if Some(fault.site.code_hash) == compiled.context.harness_hash => {
            match fault.site.position {
                IvmFaultPositionV1::Execute { pc_offset } => {
                    Some(compiled.context.harness_base.saturating_add(pc_offset))
                }
                _ => None,
            }
        }
        Some(_) => None,
        None => diagnostic.map(|diagnostic| diagnostic.pc),
    };
    let function = source_pc
        .and_then(|pc| compiled.context.harness_function(pc))
        .map(|entry| entry.function_name.clone());
    if failure.kind == FailureKind::Assertion {
        // `test::assert`/`test::assert_eq` report through the host-private assertion helper and
        // never reach this path; a bare VM assertion trap names only the enclosing function.
        failure.message = match function {
            Some(function) if function != test.name => format!("in helper `{function}`"),
            _ => String::new(),
        };
    } else if failure.kind == FailureKind::Decode && host.lifecycle == Lifecycle::PendingHajimari {
        failure = failure.detail(format!(
            "help: durable state of `{}` is uninitialized until `hajimari` runs; invoke it first",
            compiled.context.seiyaku_name
        ));
    } else if let Some(function) = function
        && function != test.name
    {
        failure.message = format!("{} in helper `{function}`", failure.message);
    }
    failure.at(Some(test_site))
}
#[expect(
    clippy::result_large_err,
    reason = "Preserve the structured failure and authenticated fault origin inline without allocating an extra error box."
)]
fn build_host_for_fixture(
    compiled: &CompiledSuite,
    fixture_name: Option<&str>,
) -> Result<KotoTestHost, TestFailure> {
    let caller =
        default_caller_account().map_err(|error| TestFailure::new(FailureKind::Harness, error))?;
    let base_host = WsvHost::new_with_subject(MockWorldStateView::default(), caller);
    let mut host = KotoTestHost::new(
        base_host,
        compiled
            .runtime
            .as_ref()
            .map(|artifact| artifact.program.clone()),
        compiled.runtime_entrypoints.clone(),
        Arc::clone(&compiled.context),
    );
    let mut public_inputs = BTreeMap::new();
    if let Some(name) = fixture_name {
        let fixture = compiled.fixtures.get(name).ok_or_else(|| {
            let mut declared = compiled
                .fixtures
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            declared.sort_unstable();
            let mut message = if declared.is_empty() {
                format!("unknown fixture `{name}`; this suite declares no fixtures")
            } else {
                format!(
                    "unknown fixture `{name}`; declared fixtures: {}",
                    declared
                        .iter()
                        .map(|fixture| format!("`{fixture}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            if let Some(closest) = closest_name(name, &declared) {
                let _ = write!(message, "; did you mean `{closest}`?");
            }
            TestFailure::new(FailureKind::Harness, message)
        })?;
        let site = compiled.fixture_sites.get(name);
        let source_name = site
            .map(|site| {
                compiled.source_root.as_deref().map_or_else(
                    || Ok(site.path.display().to_string()),
                    |root| {
                        kotodama_lang::driver::logical_source_name(&site.path, root)
                            .map_err(|error| error.to_string())
                    },
                )
            })
            .transpose()
            .map_err(|error| TestFailure::new(FailureKind::Harness, error))?;
        let environment = FixtureEnvironment {
            consts: &compiled.fixture_consts,
            artifacts: &compiled.artifacts,
            source_name: source_name.as_deref(),
            chain_discriminant: compiled.chain_discriminant,
        };
        for (index, action) in fixture.actions.iter().enumerate() {
            apply_fixture_action(action, &mut host, &mut public_inputs, &environment).map_err(
                |error| {
                    let location = site.and_then(|site| {
                        site.actions.get(index).map(|(line, column)| {
                            format!("{}:{line}:{column}", display_path(&site.path))
                        })
                    });
                    TestFailure::new(
                        FailureKind::Harness,
                        format!("fixture `{name}` action `{}`: {error}", action.name),
                    )
                    .at(location)
                },
            )?;
        }
    }
    host.base_public_inputs = public_inputs.clone();
    host.inner_mut().set_public_inputs(public_inputs);
    Ok(host)
}
fn apply_fixture_action(
    action: &FixtureAction,
    host: &mut KotoTestHost,
    public_inputs: &mut BTreeMap<Name, Vec<u8>>,
    environment: &FixtureEnvironment<'_>,
) -> Result<(), String> {
    match action.name.as_str() {
        "actor" => {
            if !(1..=3).contains(&action.args.len()) {
                return Err(format!(
                    "expects `actor(\"alias\")`, `actor(\"alias\", account)` or `actor(\"alias\", account, seed)`, got {} arguments",
                    action.args.len()
                ));
            }
            let alias = eval_actor_alias_expr(&action.args[0])?;
            if action.args.len() == 1 {
                let seed = derived_actor_seed(&alias, environment.chain_discriminant);
                let account = account_for_seed(&seed)?;
                host.register_actor(alias.clone(), account)?;
                return host.set_actor_seed(&alias, seed);
            }
            let account = eval_account_expr(&action.args[1])?;
            let seed = if action.args.len() == 3 {
                Some(eval_seed_expr(&action.args[2])?)
            } else {
                None
            };
            host.register_actor(alias.clone(), account)?;
            if let Some(seed) = seed {
                host.set_actor_seed(&alias, seed)?;
            }
            Ok(())
        }
        "caller" => {
            expect_arg_count(action, 1)?;
            let caller = eval_fixture_account_or_actor(&action.args[0], host)?;
            host.set_caller_subject(caller);
            Ok(())
        }
        "register_account" => {
            expect_arg_count(action, 1)?;
            let account = eval_fixture_account_or_actor(&action.args[0], host)?;
            host.inner_mut().wsv.add_account_unchecked(account);
            Ok(())
        }
        "grant_permission" => {
            if action.args.len() == 1 {
                let permission = eval_permission_expr(&action.args[0], host)?;
                let caller = host.caller_subject();
                host.inner_mut().wsv.grant_permission(&caller, permission);
                return Ok(());
            }
            if action.args.len() == 2 {
                let account = eval_fixture_account_or_actor(&action.args[0], host)?;
                let permission = eval_permission_expr(&action.args[1], host)?;
                host.inner_mut().wsv.grant_permission(&account, permission);
                return Ok(());
            }
            Err(format!(
                "expects `grant_permission(permission)` or `grant_permission(account, permission)`, got {} arguments",
                action.args.len()
            ))
        }
        "grant_seiyaku_permission" => {
            expect_arg_count(action, 2)?;
            let account = eval_fixture_account_or_actor(&action.args[0], host)?;
            let name = eval_string_expr(&action.args[1])?
                .parse::<Name>()
                .map_err(|error| format!("invalid declared permission name: {error}"))?;
            let permission = host.declared_permission(&name)?;
            host.inner_mut().wsv.grant_permission(&account, permission);
            Ok(())
        }
        "grant_seiyaku_lifecycle_permission" => {
            expect_arg_count(action, 2)?;
            let account = eval_fixture_account_or_actor(&action.args[0], host)?;
            let entrypoint = eval_string_expr(&action.args[1])?;
            if !host.entrypoints.get(&entrypoint).is_some_and(|entry| {
                entry.authorization == EntrypointAuthorizationV1::RuntimeLifecycle
            }) {
                return Err("requires a declared lifecycle hook name".to_owned());
            }
            let permission = PermissionToken::ContractEntrypoint {
                contract: host.contract_address.clone(),
                entrypoint,
            };
            host.inner_mut().wsv.grant_permission(&account, permission);
            Ok(())
        }
        "grant_seiyaku_effect_permission" => {
            expect_arg_count(action, 1)?;
            let permission = eval_permission_expr(&action.args[0], host)?;
            let contract_subject = host.contract_subject();
            host.inner_mut()
                .wsv
                .grant_permission(&contract_subject, permission);
            Ok(())
        }
        "grant_seiyaku_transfer_effect_permission" => {
            expect_arg_count(action, 3)?;
            let source = eval_fixture_account_or_actor(&action.args[0], host)?;
            let asset_definition = eval_asset_definition_expr(&action.args[1])?;
            let dataspace = DataSpaceId::new(eval_u64_expr(&action.args[2], environment)?);
            let permission = PermissionToken::TransferAssetBucket(AssetId::with_scope(
                asset_definition,
                source,
                AssetBalanceScope::Dataspace(dataspace),
            ));
            let contract_subject = host.contract_subject();
            host.inner_mut()
                .wsv
                .grant_permission(&contract_subject, permission);
            Ok(())
        }
        "register_account_alias" => {
            if !(2..=3).contains(&action.args.len()) {
                return Err(format!(
                    "expects `register_account_alias(alias, account[, dataspace])`, got {} arguments",
                    action.args.len()
                ));
            }
            let alias = eval_string_expr(&action.args[0])?;
            let account = eval_fixture_account_or_actor(&action.args[1], host)?;
            let dataspace = action
                .args
                .get(2)
                .map(|expr| eval_u64_expr(expr, environment))
                .transpose()?
                .map(DataSpaceId::new);
            host.inner_mut()
                .register_account_alias_with_dataspace(alias, account, dataspace)
        }
        "register_domain" => {
            expect_arg_count(action, 1)?;
            let domain = eval_domain_expr(&action.args[0])?;
            let caller = host.caller_subject();
            let inner = host.inner_mut();
            inner
                .wsv
                .grant_permission(&caller, PermissionToken::RegisterDomain);
            if inner.wsv.register_domain(&caller, domain.clone()) {
                return Ok(());
            }
            Err(format!("failed to register domain `{domain}`"))
        }
        "register_asset_definition" => {
            if !(1..=2).contains(&action.args.len()) {
                return Err(format!(
                    "expects `register_asset_definition(asset_definition[, mintability])`, got {} arguments",
                    action.args.len()
                ));
            }
            let asset = eval_asset_definition_expr(&action.args[0])?;
            let mintable = if action.args.len() == 2 {
                eval_mintable_expr(&action.args[1])?
            } else {
                Mintable::Infinitely
            };
            let caller = host.caller_subject();
            let inner = host.inner_mut();
            inner
                .wsv
                .grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
            let _ = inner
                .wsv
                .register_asset_definition(&caller, asset.clone(), mintable);
            Ok(())
        }
        "set_balance" => {
            expect_arg_count(action, 3)?;
            let account = eval_fixture_account_or_actor(&action.args[0], host)?;
            let asset = eval_asset_definition_expr(&action.args[1])?;
            let amount = eval_quantity_expr(&action.args[2], environment)?;
            let caller = host.caller_subject();
            let inner = host.inner_mut();
            inner.wsv.add_account_unchecked(account.clone());
            inner
                .wsv
                .grant_permission(&caller, PermissionToken::RegisterAssetDefinition);
            let _ =
                inner
                    .wsv
                    .register_asset_definition(&caller, asset.clone(), Mintable::Infinitely);
            inner
                .wsv
                .grant_permission(&caller, PermissionToken::MintAsset(asset.clone()));
            if inner
                .wsv
                .mint(&caller, account.clone(), asset.clone(), amount.clone())
            {
                return Ok(());
            }
            Err(format!(
                "failed to set balance `{amount}` for `{account}` on `{asset}`"
            ))
        }
        "set_account_metadata" => {
            expect_arg_count(action, 3)?;
            let account = eval_fixture_account_or_actor(&action.args[0], host)?;
            let key = eval_string_expr(&action.args[1])?;
            let value = eval_metadata_bytes(&action.args[2])?;
            let caller = host.caller_subject();
            let inner = host.inner_mut();
            inner.wsv.add_account_unchecked(account.clone());
            if caller != account {
                inner
                    .wsv
                    .grant_permission(&caller, PermissionToken::SetAccountDetail(account.clone()));
            }
            if inner.wsv.set_account_detail(&caller, &account, &key, value) {
                return Ok(());
            }
            Err(format!(
                "failed to set account metadata `{key}` for `{account}`"
            ))
        }
        "upgrade_from" => {
            expect_arg_count(action, 1)?;
            let relative = eval_string_expr(&action.args[0])?;
            let name = kotodama_lang::linker::resolve_contract_artifact_path(
                environment
                    .source_name
                    .ok_or("fixture source identity is missing")?,
                &relative,
            )
            .map_err(|error| error.to_string())?;
            let prior = environment.artifacts.get(&name).ok_or_else(|| {
                format!("compiled artifact `{name}` is absent from the captured suite inventory")
            })?;
            host.upgrade_fixture_from(prior)
        }
        "vrf_epoch_seed" => {
            expect_arg_count(action, 2)?;
            let epoch = eval_u64_expr(&action.args[0], environment)?;
            let seed = eval_seed_expr(&action.args[1])?;
            host.inner_mut().wsv.set_vrf_epoch_seed_fixture(epoch, seed);
            Ok(())
        }
        "state_set" => {
            expect_arg_count(action, 2)?;
            let logical = eval_string_expr(&action.args[0])?;
            let path = if host.program.is_some() {
                let logical = logical
                    .parse()
                    .map_err(|error| format!("invalid state path: {error}"))?;
                ivm::mock_wsv::contract_state_path(&host.contract_address, &logical)
                    .map_err(|error| error.to_string())?
                    .to_string()
            } else {
                logical
            };
            let value = eval_state_payload_expr(&action.args[1])?;
            host.inner_mut()
                .wsv
                .sc_set(&path, value)
                .map_err(|err| format!("failed to seed state `{path}`: {err}"))
        }
        "public_input" => {
            expect_arg_count(action, 2)?;
            let name = eval_name_expr(&action.args[0])?;
            let value = eval_envelope_expr(&action.args[1])?;
            public_inputs.insert(name, value);
            Ok(())
        }
        other => Err(closest_name(other, FIXTURE_ACTIONS).map_or_else(
            || {
                format!(
                    "unknown fixture action `{other}`; the fixture actions are {}",
                    FIXTURE_ACTIONS
                        .iter()
                        .map(|name| format!("`{name}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
            |closest| format!("unknown fixture action `{other}`; did you mean `{closest}`?"),
        )),
    }
}
/// Every fixture action the runner understands, in documentation order.
const FIXTURE_ACTIONS: &[&str] = &[
    "actor",
    "caller",
    "register_account",
    "register_account_alias",
    "register_domain",
    "register_asset_definition",
    "set_balance",
    "set_account_metadata",
    "grant_permission",
    "grant_seiyaku_permission",
    "grant_seiyaku_lifecycle_permission",
    "grant_seiyaku_effect_permission",
    "grant_seiyaku_transfer_effect_permission",
    "state_set",
    "upgrade_from",
    "vrf_epoch_seed",
    "public_input",
];
/// Compile-time values visible to fixture arguments.
struct FixtureEnvironment<'a> {
    artifacts: &'a BTreeMap<String, ivm::PreparedContract>,
    source_name: Option<&'a str>,
    /// `const` declarations of the target and test modules, by name.
    consts: &'a HashMap<String, Expr>,
    /// Chain discriminant used to derive named actors.
    chain_discriminant: u16,
}
/// Readable description of a fixture argument for error messages.
fn describe_expr(expr: &Expr) -> String {
    match expr {
        Expr::Source { expression, .. } | Expr::Resolved { expression, .. } => {
            describe_expr(expression)
        }
        Expr::String(raw) => format!("the string \"{raw}\""),
        Expr::Ident(name) => format!("`{name}`"),
        Expr::IntLiteral(value) => format!("the integer {value}"),
        Expr::DecimalLiteral(raw) => format!("the decimal {raw}"),
        Expr::Bool(value) => format!("`{value}`"),
        Expr::Bytes(bytes) => format!("{} bytes", bytes.len()),
        Expr::Call { name, .. } => format!("a call to `{name}`"),
        Expr::Binary { .. } | Expr::Unary { .. } => "an operator expression".to_owned(),
        Expr::StructLiteral { name, .. } => format!("a `{name}` literal"),
        Expr::Tuple(_) => "a tuple".to_owned(),
        Expr::List(_) | Expr::ListComprehension { .. } => "a list".to_owned(),
        Expr::JsonObject(_) | Expr::JsonArray(_) => "a `json` literal".to_owned(),
        Expr::OptionSome(_) | Expr::OptionNone => "an `Option` value".to_owned(),
        Expr::ResultOk(_) | Expr::ResultErr(_) => "a `Result` value".to_owned(),
        _ => "a runtime expression".to_owned(),
    }
}
/// Exact fixed-point value of a constant fixture expression: `mantissa * 10^-scale`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FixtureNumber {
    mantissa: iroha_primitives::bigint::BigInt,
    scale: u32,
}
impl FixtureNumber {
    fn rescale(&self, scale: u32) -> Option<iroha_primitives::bigint::BigInt> {
        let factor = iroha_primitives::bigint::BigInt::pow10(scale.checked_sub(self.scale)?)?;
        self.mantissa.checked_mul(&factor).ok()
    }
    fn into_numeric(self) -> Result<Numeric, String> {
        format_fixed_point(&self.mantissa, self.scale)
            .parse::<Numeric>()
            .map_err(|_| {
                format!(
                    "value {} is outside the numeric domain",
                    format_fixed_point(&self.mantissa, self.scale)
                )
            })
    }
}
fn format_fixed_point(mantissa: &iroha_primitives::bigint::BigInt, scale: u32) -> String {
    let digits = mantissa.to_string();
    let (sign, digits) = digits
        .strip_prefix('-')
        .map_or(("", digits.as_str()), |rest| ("-", rest));
    let scale = scale as usize;
    if scale == 0 {
        return format!("{sign}{digits}");
    }
    let padded = format!("{digits:0>width$}", width = scale + 1);
    let (whole, fraction) = padded.split_at(padded.len() - scale);
    format!("{sign}{whole}.{fraction}")
}
/// Evaluate a constant numeric fixture argument: literals, `const` names, unary `-`, and
/// `+`, `-`, `*` (bounded depth, exact arithmetic).
fn eval_constant_number(
    expr: &Expr,
    environment: &FixtureEnvironment<'_>,
    depth: usize,
) -> Result<FixtureNumber, String> {
    const MAX_DEPTH: usize = 32;
    if depth > MAX_DEPTH {
        return Err("constant expression is nested too deeply".to_owned());
    }
    let overflow = || "constant expression overflows the numeric domain".to_owned();
    match expr {
        Expr::Source { expression, .. } | Expr::Resolved { expression, .. } => {
            eval_constant_number(expression, environment, depth)
        }
        Expr::IntLiteral(value) => Ok(FixtureNumber {
            mantissa: value.clone(),
            scale: 0,
        }),
        Expr::DecimalLiteral(raw) | Expr::String(raw) => {
            let cleaned = raw.replace('_', "");
            let numeric = cleaned
                .parse::<Numeric>()
                .map_err(|_| format!("invalid numeric value `{raw}`"))?;
            Ok(FixtureNumber {
                mantissa: numeric.mantissa().clone(),
                scale: numeric.scale(),
            })
        }
        Expr::Ident(name) => {
            let value = environment.consts.get(name).ok_or_else(|| {
                format!("`{name}` is not a constant; fixture values must be literals, `const` names, or `+ - *` of them")
            })?;
            eval_constant_number(value, environment, depth + 1)
        }
        Expr::Unary {
            op: kotodama_lang::ast::UnaryOp::Neg,
            expr,
        } => {
            let value = eval_constant_number(expr, environment, depth + 1)?;
            Ok(FixtureNumber {
                mantissa: value.mantissa.checked_neg().map_err(|_| overflow())?,
                scale: value.scale,
            })
        }
        Expr::Binary { op, left, right } => {
            let left = eval_constant_number(left, environment, depth + 1)?;
            let right = eval_constant_number(right, environment, depth + 1)?;
            match op {
                kotodama_lang::ast::BinaryOp::Add | kotodama_lang::ast::BinaryOp::Sub => {
                    let scale = left.scale.max(right.scale);
                    let left_mantissa = left.rescale(scale).ok_or_else(overflow)?;
                    let right_mantissa = right.rescale(scale).ok_or_else(overflow)?;
                    let mantissa = if *op == kotodama_lang::ast::BinaryOp::Add {
                        left_mantissa.checked_add(&right_mantissa)
                    } else {
                        left_mantissa.checked_sub(&right_mantissa)
                    }
                    .map_err(|_| overflow())?;
                    Ok(FixtureNumber { mantissa, scale })
                }
                kotodama_lang::ast::BinaryOp::Mul => Ok(FixtureNumber {
                    mantissa: left
                        .mantissa
                        .checked_mul(&right.mantissa)
                        .map_err(|_| overflow())?,
                    scale: left.scale.checked_add(right.scale).ok_or_else(overflow)?,
                }),
                _ => Err(
                    "fixture constants support only `+`, `-` and `*`; compute other values in the test"
                        .to_owned(),
                ),
            }
        }
        other => Err(format!(
            "expected a constant number, got {}",
            describe_expr(other)
        )),
    }
}
struct KotoTestHostSnapshot {
    inner: Box<dyn Any + Send>,
    actors: HashMap<String, FixtureActor>,
    events: Vec<CapturedTestEvent>,
    last_failure: Option<TestFailure>,
    supplemental_trace: Option<ivm::zk::RuntimeTraceCapture>,
    lifecycle: Lifecycle,
}
/// Lifecycle of the seiyaku under test, modelled on the chain's activation rules.
///
/// Activating code that declares `hajimari`/`始まり` stages one transition that must be consumed
/// by an explicit call before any other call or view is accepted. An `upgrade_from` fixture
/// replaces an admitted prior artifact and stages the current code's `kaizen`/`改善` hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    /// `hajimari` is declared and has not run yet.
    PendingHajimari,
    /// Replacement code declares `kaizen`, which has not completed successfully.
    PendingKaizen,
    /// The seiyaku accepts calls.
    Active,
}
impl KotoTestHost {
    fn new(
        inner: WsvHost,
        program: Option<ivm::PreparedContract>,
        entrypoints: HashMap<String, RuntimeEntrypoint>,
        context: Arc<SourceContext>,
    ) -> Self {
        let contract_address = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .expect("canonical test network id"),
            &inner.caller_subject(),
            0,
            DataSpaceId::UNIVERSAL,
        )
        .expect("Kotodama test contract address derivation must be deterministic");
        let mut inner = inner;
        inner
            .wsv
            .add_account_unchecked(contract_address.subject_id());
        let lifecycle = if entrypoints.contains_key("hajimari") {
            Lifecycle::PendingHajimari
        } else {
            Lifecycle::Active
        };
        if let Some(prepared) = &program {
            let mut control = iroha_data_model::smart_contract::ContractLifecycleControlV1::direct(
                inner.caller_subject(),
            );
            control.active_code_hash = Some(prepared.code_hash());
            control.retained_code_hash = Some(prepared.code_hash());
            inner
                .install_contract_fixture(
                    contract_address.clone(),
                    prepared.artifact().to_vec(),
                    control,
                    (lifecycle == Lifecycle::PendingHajimari).then_some(EntryPointKind::Hajimari),
                )
                .expect("already admitted runtime artifact forms a valid local fixture");
            inner
                .set_contract_fixture_state_scope(Some(contract_address.clone()))
                .expect("the admitted root fixture owns the test state namespace");
        }
        Self {
            inner,
            record_budget: iroha_allocation::AllocationBudget::new(16 * 1024 * 1024),
            actors: HashMap::new(),
            events: Vec::new(),
            base_public_inputs: BTreeMap::new(),
            entrypoints,
            program,
            contract_address,
            last_failure: None,
            supplemental_trace: None,
            lifecycle,
            fixture_upgrade_staged: false,
            calls: Vec::new(),
            context,
            pending_call_site: None,
            active_call_site: None,
        }
    }
    #[cfg(test)]
    fn fixture_state(&self, logical: &str) -> Option<Vec<u8>> {
        if self.program.is_none() {
            return self.inner.wsv.sc_get(logical);
        }
        let logical = logical.parse().ok()?;
        let scoped = ivm::mock_wsv::contract_state_path(&self.contract_address, &logical).ok()?;
        self.inner.wsv.sc_get(scoped.as_ref())
    }
    fn inner_mut(&mut self) -> &mut WsvHost {
        &mut self.inner
    }
    fn caller_subject(&self) -> AccountId {
        self.inner.caller_subject()
    }
    fn set_caller_subject(&mut self, caller: AccountId) {
        self.inner.set_caller_subject(caller);
    }
    fn contract_subject(&self) -> AccountId {
        self.contract_address.subject_id()
    }
    fn declared_permission(&self, name: &Name) -> Result<PermissionToken, String> {
        let declaration = self
            .program
            .as_ref()
            .and_then(|program| {
                program
                    .contract_interface()
                    .permissions
                    .iter()
                    .find(|declaration| declaration.name == *name)
            })
            .ok_or_else(|| format!("seiyaku has no declared permission `{name}`"))?;
        Ok(match &declaration.scope {
            ContractPermissionScopeV1::Instance => PermissionToken::ContractPermission {
                contract: self.contract_address.clone(),
                permission: name.clone(),
            },
            ContractPermissionScopeV1::Chain { permission_name } => {
                PermissionToken::Custom(permission_name.to_string())
            }
        })
    }
    fn actor_account(&self, alias: &str) -> Option<AccountId> {
        self.actors.get(alias).map(|actor| actor.account.clone())
    }
    /// Alias of the fixture actor owning `account`, used to annotate rendered values.
    fn actor_alias(&self, account: &AccountId) -> Option<&str> {
        let mut aliases = self
            .actors
            .iter()
            .filter(|(_, actor)| &actor.account == account)
            .map(|(alias, _)| alias.as_str())
            .collect::<Vec<_>>();
        aliases.sort_unstable();
        aliases.first().copied()
    }
    fn register_actor(&mut self, alias: String, account: AccountId) -> Result<(), String> {
        if self.actors.contains_key(&alias) {
            return Err(format!("duplicate actor `{alias}`"));
        }
        self.inner.wsv.add_account_unchecked(account.clone());
        self.actors.insert(
            alias,
            FixtureActor {
                account,
                seed: None,
            },
        );
        Ok(())
    }
    fn set_actor_seed(&mut self, alias: &str, seed: [u8; 32]) -> Result<(), String> {
        let derived_account = account_for_seed(&seed).map_err(|err| {
            format!("failed to derive Ed25519 public key for actor `{alias}`: {err}")
        })?;
        let actor = self
            .actors
            .get_mut(alias)
            .ok_or_else(|| format!("unknown actor `{alias}`"))?;
        if actor.account != derived_account {
            return Err(format!(
                "actor `{alias}`: the seed derives account `{derived_account}`, but the fixture binds `{}`; drop the account argument to use the derived one",
                actor.account
            ));
        }
        actor.seed = Some(seed);
        Ok(())
    }
    /// Message of the most recent harness failure, if any.
    #[cfg(test)]
    fn last_test_error(&self) -> Option<String> {
        self.last_failure.as_ref().map(TestFailure::render)
    }
    fn clear_test_error(&mut self) {
        self.last_failure = None;
    }
    fn restore_public_inputs(&mut self) {
        self.inner
            .set_public_inputs(self.base_public_inputs.clone());
    }
    /// Record why the test failed and stop the harness.
    ///
    /// A failure inside a `test::` helper call is located at that call when the compiler announced
    /// its site, with the call's source text as the first detail line.
    fn fail_test<T>(&mut self, mut failure: TestFailure) -> Result<T, ivm::VMError> {
        if failure.location.is_none()
            && let Some((location, snippet)) = self.active_call_site.take()
        {
            failure.location = Some(location);
            if let Some(snippet) = snippet {
                failure.details.insert(0, snippet);
            }
        }
        self.last_failure = Some(failure);
        Err(ivm::VMError::AssertionFailed)
    }
    /// Make the most recently announced call site the site of the helper call now starting.
    fn begin_helper_call(&mut self) {
        self.active_call_site = self.pending_call_site.take().and_then(|site| {
            let (location, line) = self
                .context
                .locate_site(site.source_id, site.byte_start as usize)?;
            let snippet = self
                .context
                .site_text(
                    site.source_id,
                    site.byte_start as usize,
                    site.byte_end as usize,
                )
                .or(Some(line));
            Some((location, snippet))
        });
    }
    /// Record the call-site announcement in `x10` for the next helper call.
    fn record_call_site(&mut self, vm: &IVM) -> Result<u64, ivm::VMError> {
        use kotodama_lang::testing::TestCallSite;
        let bytes = Self::decode_bytes_arg(vm, 10)?;
        if bytes.len() > TestCallSite::MAX_ENCODED_BYTES {
            return Err(ivm::VMError::NoritoInvalid);
        }
        let site: TestCallSite =
            norito::decode_canonical(&bytes).map_err(|_| ivm::VMError::NoritoInvalid)?;
        self.pending_call_site = Some(site);
        Ok(0)
    }
    /// Fail the test for harness misuse, such as an unknown fixture actor.
    fn fail_harness<T>(&mut self, message: impl Into<String>) -> Result<T, ivm::VMError> {
        self.fail_test(TestFailure::new(FailureKind::Harness, message))
    }
    fn decode_alias_arg(vm: &IVM, reg: usize, label: &str) -> Result<String, ivm::VMError> {
        let ptr = vm.register(reg);
        if ptr == 0 {
            return Err(ivm::VMError::NoritoInvalid);
        }
        let tlv = vm.validate_tlv(ptr)?;
        match tlv.type_id {
            PointerType::Blob | PointerType::NoritoBytes => {
                String::from_utf8(tlv.payload.to_vec()).map_err(|_| ivm::VMError::DecodeError)
            }
            PointerType::Name => {
                let name: Name =
                    norito::decode_canonical(tlv.payload).map_err(|_| ivm::VMError::DecodeError)?;
                Ok(name.as_ref().to_string())
            }
            _ => {
                let _ = label;
                Err(ivm::VMError::NoritoInvalid)
            }
        }
    }
    fn decode_bytes_arg(vm: &IVM, reg: usize) -> Result<Vec<u8>, ivm::VMError> {
        let ptr = vm.register(reg);
        if ptr == 0 {
            return Err(ivm::VMError::NoritoInvalid);
        }
        let tlv = vm.validate_tlv(ptr)?;
        match tlv.type_id {
            PointerType::Blob | PointerType::NoritoBytes => Ok(tlv.payload.to_vec()),
            _ => Err(ivm::VMError::NoritoInvalid),
        }
    }
    fn alloc_pointer_result(
        vm: &mut IVM,
        pointer_type: PointerType,
        payload: &[u8],
    ) -> Result<u64, ivm::VMError> {
        let tlv = make_tlv(pointer_type, payload);
        vm.alloc_host_tlv(&tlv)
    }
    /// Explain an unknown fixture actor: the declared actors and the closest spelling, or how to
    /// declare one when the test's fixture has none.
    fn unknown_actor_message(&self, alias: &str) -> String {
        let mut declared = self.actors.keys().map(String::as_str).collect::<Vec<_>>();
        declared.sort_unstable();
        if declared.is_empty() {
            return format!(
                "unknown actor `{alias}`: the test's fixture declares no actors; add `actor(\"{alias}\");` to a fixture and use `#[test(fixture = \"...\")]`"
            );
        }
        let mut message = format!(
            "unknown actor `{alias}`; declared actors: {}",
            declared
                .iter()
                .map(|name| format!("`{name}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Some(closest) = closest_name(alias, &declared) {
            let _ = write!(message, "; did you mean `{closest}`?");
        }
        message
    }
    /// Describe the caller for messages: ``actor `alice` `` or `the current caller`.
    fn describe_caller(actor_alias: &str) -> String {
        if actor_alias == CURRENT_CALLER {
            "the current caller".to_owned()
        } else {
            format!("actor `{actor_alias}`")
        }
    }
    /// Lifecycle rule violated by calling `entrypoint` now, if any.
    fn lifecycle_violation(&self, entrypoint: &str) -> Option<String> {
        let label = |romaji: &str| {
            kotodama_lang::glossary::by_spelling(romaji).map_or_else(
                || romaji.to_owned(),
                kotodama_lang::glossary::BrandedKeyword::label,
            )
        };
        let seiyaku = &self.context.seiyaku_name;
        match (entrypoint, self.lifecycle) {
            ("hajimari", Lifecycle::PendingHajimari) | ("kaizen", Lifecycle::PendingKaizen) => None,
            ("hajimari", _) => Some(format!(
                "{} of seiyaku `{seiyaku}` already ran; a consumed lifecycle hook cannot be replayed",
                label("hajimari")
            )),
            ("kaizen", _) => Some(format!(
                "{} runs only after an active seiyaku's code is replaced in place; no kaizen transition is pending for `{seiyaku}`",
                label("kaizen")
            )),
            (_, Lifecycle::PendingHajimari | Lifecycle::PendingKaizen) => {
                let hook = if self.lifecycle == Lifecycle::PendingHajimari {
                    "hajimari"
                } else {
                    "kaizen"
                };
                Some(format!(
                    "seiyaku `{seiyaku}` has a pending {} transition; invoke `{hook}` before `{entrypoint}`",
                    label(hook)
                ))
            }
            (_, Lifecycle::Active) => None,
        }
    }
    /// Accept a pre-execution rejection when the test expected one, or fail with a mismatch.
    fn accept_expected_rejection(
        &mut self,
        vm: &mut IVM,
        expectation: Option<&kotodama_lang::testing::RejectionExpectation>,
        accepted: &[kotodama_lang::testing::RejectionExpectation],
        observed: &TestFailure,
        entrypoint: &str,
    ) -> Result<u64, ivm::VMError> {
        let expected = expectation.expect("rejection expectation");
        if matches!(expected, kotodama_lang::testing::RejectionExpectation::Any)
            || accepted.contains(expected)
        {
            vm.set_register(10, 0);
            return Ok(0);
        }
        self.fail_test(
            TestFailure::new(
                FailureKind::Expectation,
                format!(
                    "expected `{entrypoint}` to reject with {}, but it was rejected earlier",
                    expected.description()
                ),
            )
            .detail(format!("observed: {}", observed.render())),
        )
    }
    fn invoke_entrypoint(
        &mut self,
        vm: &mut IVM,
        expect_reject: bool,
    ) -> Result<u64, ivm::VMError> {
        use kotodama_lang::testing::RejectionExpectation;
        self.clear_test_error();
        let expectation = if expect_reject {
            if vm.register(15) != 0 {
                return self.fail_harness("rejection expectation has nonzero reserved operands");
            }
            let bytes = Self::decode_bytes_arg(vm, 14)?;
            if bytes.len() > 64 * 1024 {
                return self.fail_harness("rejection expectation exceeds the test metadata budget");
            }
            let expectation: RejectionExpectation =
                norito::decode_canonical(&bytes).map_err(|_| ivm::VMError::NoritoInvalid)?;
            if !expectation.validate() {
                return self.fail_harness("invalid nominal rejection expectation");
            }
            Some(expectation)
        } else {
            None
        };
        let (actor_alias, actor) = if !expect_reject && vm.register(10) == 0 {
            (
                CURRENT_CALLER.to_owned(),
                FixtureActor {
                    account: self.inner.caller_subject(),
                    seed: None,
                },
            )
        } else {
            let alias = Self::decode_alias_arg(vm, 10, "actor").map_err(|error| {
                ivm::error::preserve_execution_deferral(error, ivm::VMError::NoritoInvalid)
            })?;
            let Some(actor) = self.actors.get(&alias).cloned() else {
                return self.fail_harness(self.unknown_actor_message(&alias));
            };
            (alias, actor)
        };
        let caller = Self::describe_caller(&actor_alias);
        let entrypoint = Self::decode_alias_arg(vm, 11, "kotoage").map_err(|error| {
            ivm::error::preserve_execution_deferral(error, ivm::VMError::NoritoInvalid)
        })?;
        let argument_table = vm.register(12);
        let argument_words = usize::try_from(vm.register(13)).unwrap_or(usize::MAX);
        let result_table = if expect_reject { 0 } else { vm.register(14) };
        let return_arity = if expect_reject {
            1
        } else {
            usize::try_from(vm.register(15)).unwrap_or(TEST_MAX_RETURN_VALUES + 1)
        };
        if return_arity == 0 || return_arity > TEST_MAX_RETURN_VALUES {
            return self.fail_harness(format!(
                "{caller} calling `{entrypoint}` requested unsupported return arity {return_arity}"
            ));
        }
        let runtime_entrypoint = match self.entrypoints.get(&entrypoint).cloned() {
            Some(entrypoint) => entrypoint,
            None => {
                return self.fail_harness(format!(
                    "seiyaku `{}` has no kotoage, view, or lifecycle declaration named `{entrypoint}`",
                    self.context.seiyaku_name
                ));
            }
        };
        if let Some(violation) = self.lifecycle_violation(&entrypoint) {
            let failure = TestFailure::new(FailureKind::Lifecycle, violation);
            if expect_reject {
                return self.accept_expected_rejection(
                    vm,
                    expectation.as_ref(),
                    &[],
                    &failure,
                    &entrypoint,
                );
            }
            return self.fail_test(failure);
        }
        let fixture_actor = if actor_alias == CURRENT_CALLER {
            format!("AccountId::parse(\"{}\")", actor.account)
        } else {
            format!("\"{actor_alias}\"")
        };
        let required_permission = match &runtime_entrypoint.authorization {
            EntrypointAuthorizationV1::Anyone => None,
            EntrypointAuthorizationV1::RuntimeLifecycle => Some((
                "runtime lifecycle".to_owned(),
                PermissionToken::ContractEntrypoint {
                    contract: self.contract_address.clone(),
                    entrypoint: entrypoint.clone(),
                },
                format!("grant_seiyaku_lifecycle_permission({fixture_actor}, \"{entrypoint}\");"),
            )),
            EntrypointAuthorizationV1::Permission(name) => {
                let permission = match self.declared_permission(name) {
                    Ok(permission) => permission,
                    Err(message) => return self.fail_harness(message),
                };
                Some((
                    name.to_string(),
                    permission,
                    format!("grant_seiyaku_permission({fixture_actor}, \"{name}\");"),
                ))
            }
        };
        if let Some((permission_name, permission, fixture_grant)) = required_permission
            && !self.inner.wsv.has_permission(&actor.account, &permission)
        {
            let failure = TestFailure::new(
                FailureKind::PermissionDenied,
                format!(
                    "{caller} lacks the `{permission_name}` permission required by `{entrypoint}`"
                ),
            )
            .detail(format!(
                "help: grant the exact declared permission in the test fixture: `{fixture_grant}`"
            ));
            if expect_reject {
                return self.accept_expected_rejection(
                    vm,
                    expectation.as_ref(),
                    &[RejectionExpectation::PermissionDenied],
                    &failure,
                    &entrypoint,
                );
            }
            return self.fail_test(failure);
        }
        let Some(program) = self.program.as_ref() else {
            return self.fail_harness(format!("`{entrypoint}` has no compiled runtime artifact"));
        };
        let nested_inputs = self.base_public_inputs.clone();
        let mut boundary_gas = 0u64;
        let captured_arguments = match runtime_entrypoint.argument_schema.as_ref() {
            Some(schema) => ivm::value_record::quote_argument_record(
                vm,
                schema,
                argument_table,
                argument_words,
                vm.remaining_gas(),
            )
            .and_then(|quote| {
                boundary_gas = quote.gas;
                ivm::value_record::capture_argument_record_funded(
                    vm,
                    schema,
                    argument_table,
                    argument_words,
                    &self.record_budget,
                )
                .map(Some)
            }),
            None if argument_table == 0 && argument_words == 0 => Ok(None),
            None => Err(ivm::VMError::DecodeError),
        };
        let captured_arguments = match captured_arguments {
            Ok(captured) => captured,
            Err(error) if error.execution_deferral().is_some() => return Err(error),
            Err(error) => {
                let reason = if runtime_entrypoint.argument_schema.is_none() {
                    format!(
                        "`{entrypoint}` takes no arguments, so its argument table must have zero base and zero words"
                    )
                } else {
                    format!("invalid canonical argument table: {error}")
                };
                let failure = TestFailure::new(
                    FailureKind::Arguments,
                    format!("{caller} calling `{entrypoint}`: {reason}"),
                )
                .detail(format!(
                    "argument table: {argument_words} words at {argument_table:#x}"
                ));
                if expect_reject {
                    return self.accept_expected_rejection(
                        vm,
                        expectation.as_ref(),
                        &[RejectionExpectation::InvalidArguments],
                        &failure,
                        &entrypoint,
                    );
                }
                return self.fail_test(failure);
            }
        };
        if !expect_reject {
            if runtime_entrypoint.return_schema.word_count() != Some(return_arity) {
                return Err(ivm::VMError::DecodeError);
            }
            ivm::value_record::validate_return_destination(vm, result_table, return_arity)?;
        }
        let mut nested_vm = vm.try_new_in_same_memory_pool(NESTED_GAS_LIMIT)?;
        nested_vm.reset()?;
        let clear = [0u8; 7 + iroha_crypto::Hash::LENGTH];
        nested_vm.memory.preload_input(0, &clear).map_err(|error| {
            ivm::error::preserve_execution_deferral(error, ivm::VMError::DecodeError)
        })?;
        nested_vm.load_prepared(program).map_err(|error| {
            ivm::error::preserve_execution_deferral(error, ivm::VMError::DecodeError)
        })?;
        nested_vm.set_program_counter(runtime_entrypoint.pc)?;
        let actual_return_words = runtime_entrypoint
            .return_schema
            .word_count()
            .ok_or(ivm::VMError::DecodeError)?;
        if let Some(captured) = captured_arguments.as_ref() {
            ivm::value_record::install_captured_arguments(
                captured,
                runtime_entrypoint
                    .argument_schema
                    .as_ref()
                    .expect("captured parameter schema"),
                &mut nested_vm,
                actual_return_words,
                &self.record_budget,
            )?;
        } else {
            ivm::value_record::install_empty_captured_arguments(
                &mut nested_vm,
                actual_return_words,
            )?;
        }
        drop(captured_arguments);

        nested_vm.set_trace_mode(vm.trace_mode());
        nested_vm.set_max_cycles(0);
        let event_checkpoint = self.events.len();
        let rollback = self
            .inner
            .checkpoint()
            .ok_or(ivm::VMError::HostUnavailable)?;
        let previous_caller = self.inner.caller_subject();
        if let Err(message) = self.inner.bind_contract_runtime_context(
            actor.account.clone(),
            self.contract_address.clone(),
            entrypoint.clone(),
        ) {
            return self.fail_harness(message);
        }
        self.inner.set_public_inputs(nested_inputs);
        let nested_outcome = match nested_vm.run_with_host(self) {
            Err(error) if error.execution_deferral().is_some() => {
                self.inner.restore(rollback.as_ref())?;
                self.events.truncate(event_checkpoint);
                self.inner.clear_contract_runtime_context(previous_caller);
                self.restore_public_inputs();
                return Err(error);
            }
            completed => completed,
        };
        let trace_steps = match self.record_nested_trace(&nested_vm) {
            Ok(steps) => steps,
            Err(error) => {
                self.inner.restore(rollback.as_ref())?;
                self.events.truncate(event_checkpoint);
                self.inner.clear_contract_runtime_context(previous_caller);
                self.restore_public_inputs();
                return Err(error);
            }
        };
        self.calls.push(EntrypointCall {
            entrypoint: entrypoint.clone(),
            gas: NESTED_GAS_LIMIT.saturating_sub(nested_vm.remaining_gas()),
            cycles: nested_vm.get_cycle_count(),
            trace_steps,
        });
        match nested_outcome {
            Ok(()) if expect_reject => {
                self.inner.restore(rollback.as_ref())?;
                self.events.truncate(event_checkpoint);
                self.fail_test(
                    TestFailure::new(
                        FailureKind::Expectation,
                        format!(
                            "expected {caller} calling `{entrypoint}` to reject with {}, but the call succeeded",
                            expectation
                                .as_ref()
                                .expect("rejection expectation")
                                .description()
                        ),
                    )
                    .detail(format!("argument table: {argument_words} words")),
                )
            }
            Ok(()) => {
                let transfer = (|| {
                    let quote = ivm::value_record::quote_completed_return_record(
                        &nested_vm, &runtime_entrypoint.return_schema,
                        vm.remaining_gas().saturating_sub(boundary_gas),
                    )?;
                    boundary_gas = boundary_gas.checked_add(quote.gas)
                        .ok_or(ivm::VMError::OutOfGas)?;
                    let captured = ivm::value_record::capture_completed_return_funded(
                        &nested_vm, &runtime_entrypoint.return_schema, &self.record_budget,
                    )?;
                    let cost = ivm::value_record::transfer_return_record_funded(
                        &captured, &runtime_entrypoint.return_schema, vm,
                        result_table, return_arity,
                        vm.remaining_gas().saturating_sub(boundary_gas),
                        &self.record_budget,
                    )?;
                    boundary_gas = boundary_gas.checked_add(cost).ok_or(ivm::VMError::OutOfGas)?;
                    vm.set_register(10, result_table);
                    vm.set_register(11, return_arity as u64);
                    Ok::<(), ivm::VMError>(())
                })();
                if let Err(error) = transfer {
                    vm.inherit_execution_fault(
                        &nested_vm,
                        &error,
                        IvmFaultPositionV1::ReturnValidation,
                    );
                    self.inner.restore(rollback.as_ref())?;
                    self.events.truncate(event_checkpoint);
                    self.inner.clear_contract_runtime_context(previous_caller);
                    self.restore_public_inputs();
                    return Err(error);
                }
                // A returned Err is recoverable data, but all state and ledger effects
                // of that invocation are discarded. Transfer has validated the complete
                // public value before this classification; its owned return survives.
                let returned_error = match ivm::sum::entrypoint_return_is_error(
                    &nested_vm,
                    &runtime_entrypoint.return_schema,
                ) {
                    Ok(returned_error) => returned_error,
                    Err(error) => {
                        vm.inherit_execution_fault(
                            &nested_vm,
                            &error,
                            IvmFaultPositionV1::ReturnValidation,
                        );
                        self.inner.restore(rollback.as_ref())?;
                        self.events.truncate(event_checkpoint);
                        self.inner.clear_contract_runtime_context(previous_caller);
                        self.restore_public_inputs();
                        return Err(error);
                    }
                };
                if returned_error {
                    self.inner.restore(rollback.as_ref())?;
                    self.events.truncate(event_checkpoint);
                } else if matches!(entrypoint.as_str(), "hajimari" | "kaizen") {
                    let kind = if entrypoint == "hajimari" { EntryPointKind::Hajimari } else { EntryPointKind::Kaizen };
                    if let Err(error) = self.inner.finish_contract_fixture_hook(&self.contract_address, kind) {
                        self.inner.restore(rollback.as_ref())?;
                        self.events.truncate(event_checkpoint);
                        self.inner.clear_contract_runtime_context(previous_caller);
                        self.restore_public_inputs();
                        return Err(error);
                    }
                    self.lifecycle = Lifecycle::Active;
                }
                self.inner.clear_contract_runtime_context(previous_caller);
                self.restore_public_inputs();
                Ok(0)
            }
            Err(err) if expect_reject => {
                self.inner.restore(rollback.as_ref())?;
                self.events.truncate(event_checkpoint);
                let expected = expectation.as_ref().expect("rejection expectation");
                if !expected.matches_runtime(
                    &err,
                    nested_vm
                        .last_diagnostic()
                        .map(|diagnostic| diagnostic.trap_kind),
                ) {
                    let observed = self.context.classify_runtime_failure(&nested_vm, &err);
                    let mut mismatch = TestFailure::new(
                        FailureKind::Expectation,
                        format!(
                            "expected {caller} calling `{entrypoint}` to reject with {}",
                            expected.description()
                        ),
                    )
                    .detail(format!("observed: {}", observed.render()));
                    mismatch.fault = observed.fault;
                    return self.fail_test(mismatch);
                }
                vm.set_register(10, 0);
                Ok(0)
            }
            Err(err) => {
                self.inner.restore(rollback.as_ref())?;
                self.events.truncate(event_checkpoint);
                let failure = self
                    .context
                    .classify_runtime_failure(&nested_vm, &err)
                    .detail(format!(
                        "while {caller} called `{entrypoint}` with {argument_words} argument words"
                    ));
                self.fail_test(failure)
            }
        }.map(|cost: u64| cost.saturating_add(boundary_gas))
    }
}
impl IVMHost for KotoTestHost {
    fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, ivm::VMError> {
        if number == ivm::syscalls::SYSCALL_EMIT_CONTRACT_EVENT {
            let ordinal =
                usize::try_from(vm.register(10)).map_err(|_| ivm::VMError::DecodeError)?;
            let words = usize::try_from(vm.register(12)).map_err(|_| ivm::VMError::DecodeError)?;
            let event = vm
                .contract_interface()
                .and_then(|interface| interface.events.get(ordinal))
                .ok_or(ivm::VMError::DecodeError)?;
            return ivm::value_record::quote_value_record(
                vm,
                &event.payload_type,
                vm.register(11),
                words,
                vm.remaining_gas(),
            )
            .map(|quote| quote.gas);
        }
        if matches!(
            number,
            TEST_SYSCALL_INVOKE_ENTRYPOINT_AS | TEST_SYSCALL_EXPECT_REJECT_AS
        ) {
            // Argument and returned active values determine the exact copying
            // work. Reserve caller gas before any nested mutation; the helper
            // returns the actual funded capture/materialization cost.
            return ivm::host::reserve_available_syscall_gas_at_least(vm, 0);
        }
        if ivm::syscalls::is_koto_test_syscall(number) {
            Ok(0)
        } else {
            self.inner.prepare_syscall(number, vm)
        }
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, ivm::VMError> {
        if matches!(
            number,
            TEST_SYSCALL_ACTOR_ACCOUNT
                | TEST_SYSCALL_ACTOR_PUBLIC_KEY
                | TEST_SYSCALL_ACTOR_SIGN
                | TEST_SYSCALL_INVOKE_ENTRYPOINT_AS
                | TEST_SYSCALL_EXPECT_REJECT_AS
        ) {
            self.begin_helper_call();
            let outcome = self.helper_syscall(number, vm);
            self.active_call_site = None;
            return outcome;
        }
        match number {
            ivm::syscalls::SYSCALL_CALL_CONTRACT => {
                let outcome = self.inner.syscall(number, vm);
                self.events
                    .extend(self.inner.drain_contract_events().into_iter().map(|event| {
                        CapturedTestEvent {
                            name: event.name().clone(),
                            payload: event.payload().clone(),
                        }
                    }));
                outcome
            }
            ivm::syscalls::SYSCALL_EMIT_CONTRACT_EVENT => {
                let ordinal =
                    usize::try_from(vm.register(10)).map_err(|_| ivm::VMError::DecodeError)?;
                let words =
                    usize::try_from(vm.register(12)).map_err(|_| ivm::VMError::DecodeError)?;
                let event = vm
                    .contract_interface()
                    .and_then(|interface| interface.events.get(ordinal))
                    .ok_or(ivm::VMError::DecodeError)?;
                let payload = ivm::value_record::capture_value_record(
                    vm,
                    &event.payload_type,
                    vm.register(11),
                    words,
                )?;
                self.events.push(CapturedTestEvent {
                    name: event.name.clone(),
                    payload,
                });
                Ok(0)
            }
            TEST_SYSCALL_CALL_SITE => self.record_call_site(vm),
            TEST_SYSCALL_ASSERT_FAILED => self.assertion_failed(vm),
            TEST_SYSCALL_SET_BLOCK_HEIGHT => {
                self.clear_test_error();
                self.inner.wsv.set_current_block_height(vm.register(10));
                Ok(0)
            }
            TEST_SYSCALL_ADVANCE_BLOCKS => {
                self.clear_test_error();
                let current = self.inner.wsv.current_block_height();
                let Some(height) = current.checked_add(vm.register(10)) else {
                    return self.fail_harness(format!(
                        "advancing block height {current} by {} blocks overflows u64",
                        vm.register(10)
                    ));
                };
                self.inner.wsv.set_current_block_height(height);
                Ok(0)
            }
            TEST_SYSCALL_SET_TRANSACTION_TIME_MS => {
                self.clear_test_error();
                self.inner.set_current_time_ms(vm.register(10));
                Ok(0)
            }
            _ => self.inner.syscall(number, vm),
        }
    }
    fn allows_syscall(&self, policy: ivm::SyscallPolicy, number: u32) -> bool {
        ivm::syscalls::is_koto_test_syscall(number)
            || ivm::syscalls::is_syscall_allowed(policy, number)
    }
    fn as_any(&mut self) -> &mut dyn Any
    where
        Self: 'static,
    {
        self
    }
    fn begin_tx(&mut self, declared: &ivm::parallel::StateAccessSet) -> Result<(), ivm::VMError> {
        self.inner.begin_tx(declared)
    }
    fn finish_tx(&mut self) -> Result<ivm::host::AccessLog, ivm::VMError> {
        self.inner.finish_tx()
    }
    fn checkpoint(&self) -> Option<Box<dyn Any + Send>> {
        let inner = self.inner.checkpoint()?;
        Some(Box::new(KotoTestHostSnapshot {
            inner,
            actors: self.actors.clone(),
            events: self.events.clone(),
            last_failure: self.last_failure.clone(),
            supplemental_trace: self.supplemental_trace.clone(),
            lifecycle: self.lifecycle,
        }))
    }
    fn restore(&mut self, snapshot: &dyn Any) -> Result<(), ivm::VMError> {
        let snapshot = snapshot
            .downcast_ref::<KotoTestHostSnapshot>()
            .ok_or(ivm::VMError::HostUnavailable)?;
        self.inner.restore(snapshot.inner.as_ref())?;
        self.actors.clone_from(&snapshot.actors);
        self.events.clone_from(&snapshot.events);
        self.last_failure.clone_from(&snapshot.last_failure);
        self.supplemental_trace
            .clone_from(&snapshot.supplemental_trace);
        self.lifecycle = snapshot.lifecycle;
        Ok(())
    }
    fn access_logging_supported(&self) -> bool {
        self.inner.access_logging_supported()
    }
}
impl KotoTestHost {
    /// Dispatch a fixture-actor or seiyaku-call helper; [`IVMHost::syscall`] brackets it with the
    /// announced call site.
    fn helper_syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, ivm::VMError> {
        match number {
            TEST_SYSCALL_ACTOR_ACCOUNT => {
                self.clear_test_error();
                let alias = Self::decode_alias_arg(vm, 10, "actor")?;
                let Some(actor) = self.actors.get(&alias) else {
                    return self.fail_harness(self.unknown_actor_message(&alias));
                };
                let payload = norito::encode_canonical(&actor.account)
                    .map_err(|_| ivm::VMError::NoritoInvalid)?;
                let ptr = Self::alloc_pointer_result(vm, PointerType::AccountId, &payload)?;
                vm.set_register(10, ptr);
                Ok(0)
            }
            TEST_SYSCALL_ACTOR_PUBLIC_KEY => {
                self.clear_test_error();
                let alias = Self::decode_alias_arg(vm, 10, "actor")?;
                let Some(actor) = self.actors.get(&alias) else {
                    return self.fail_harness(self.unknown_actor_message(&alias));
                };
                let Some(seed) = actor.seed else {
                    return self.fail_harness(format!(
                        "actor `{alias}` does not have a deterministic signing seed"
                    ));
                };
                let signing_key = SigningKey::from_bytes(&seed);
                let ptr = Self::alloc_pointer_result(
                    vm,
                    PointerType::Blob,
                    signing_key.verifying_key().as_bytes(),
                )?;
                vm.set_register(10, ptr);
                Ok(0)
            }
            TEST_SYSCALL_ACTOR_SIGN => {
                self.clear_test_error();
                let alias = Self::decode_alias_arg(vm, 10, "actor")?;
                let Some(actor) = self.actors.get(&alias) else {
                    return self.fail_harness(self.unknown_actor_message(&alias));
                };
                let Some(seed) = actor.seed else {
                    return self.fail_harness(format!(
                        "actor `{alias}` does not have a deterministic signing seed"
                    ));
                };
                let message = Self::decode_bytes_arg(vm, 11)?;
                let signing_key = SigningKey::from_bytes(&seed);
                let signature = signing_key.sign(&message);
                let ptr = Self::alloc_pointer_result(vm, PointerType::Blob, &signature.to_bytes())?;
                vm.set_register(10, ptr);
                Ok(0)
            }
            TEST_SYSCALL_INVOKE_ENTRYPOINT_AS => self.invoke_entrypoint(vm, false),
            TEST_SYSCALL_EXPECT_REJECT_AS => self.invoke_entrypoint(vm, true),
            _ => self.inner.syscall(number, vm),
        }
    }
    /// Turn a failed `test::assert`/`test::assert_eq` into a located failure report.
    fn assertion_failed(&mut self, vm: &IVM) -> Result<u64, ivm::VMError> {
        use kotodama_lang::testing::{AssertionKind, AssertionSite};
        let site_bytes = Self::decode_bytes_arg(vm, 10)?;
        if site_bytes.len() > AssertionSite::MAX_ENCODED_BYTES {
            return Err(ivm::VMError::NoritoInvalid);
        }
        let site: AssertionSite =
            norito::decode_canonical(&site_bytes).map_err(|_| ivm::VMError::NoritoInvalid)?;
        let (location, line_text) = self
            .context
            .locate_site(site.source_id, site.byte_start as usize)
            .map_or((None, None), |(location, line)| {
                (Some(location), Some(line))
            });
        let snippet = self
            .context
            .site_text(
                site.source_id,
                site.byte_start as usize,
                site.byte_end as usize,
            )
            .or(line_text);
        let mut failure = TestFailure::new(FailureKind::Assertion, String::new()).at(location);
        let dynamic_message = match vm.register(14) {
            0 => None,
            pointer => Some(self.render_pointer_text(vm, pointer)),
        };
        if let Some(message) = site.message.clone().or(dynamic_message) {
            failure.message = message;
        }
        if let Some(snippet) = snippet {
            failure = failure.detail(snippet);
        }
        if site.kind == AssertionKind::AssertEq {
            match self.render_compared_values(vm) {
                Ok(Some((actual, expected))) => {
                    failure = failure
                        .detail(format!("actual:   {actual}"))
                        .detail(format!("expected: {expected}"));
                }
                Ok(None) => {
                    failure = failure.detail(format!(
                        "the compared `{}` values have no printable form",
                        site.value_type.as_deref().unwrap_or("value")
                    ));
                }
                Err(error) => {
                    failure = failure
                        .detail(format!("the compared values could not be decoded: {error}"));
                }
            }
        }
        self.fail_test(failure)
    }
    /// Decode the actual/expected state-value records in `x11`/`x12` with the schema in `x13`.
    fn render_compared_values(&self, vm: &IVM) -> Result<Option<(String, String)>, String> {
        let (actual, expected, schema) = (vm.register(11), vm.register(12), vm.register(13));
        if actual == 0 || expected == 0 || schema == 0 {
            return Ok(None);
        }
        let payload = |pointer: u64| {
            vm.validate_tlv(pointer)
                .map(|tlv| tlv.payload.to_vec())
                .map_err(|error| error.to_string())
        };
        let schema: StateValueSchemaV1 = norito::decode_canonical(&payload(schema)?)
            .map_err(|error| format!("invalid value schema: {error}"))?;
        let render = |pointer: u64| -> Result<String, String> {
            let record: StateValueRecordV1 = norito::decode_canonical(&payload(pointer)?)
                .map_err(|error| format!("invalid value record: {error}"))?;
            if !schema.validate_atoms(&record.atoms) {
                return Err("value record does not match its schema".to_owned());
            }
            let mut atoms = record.atoms.iter();
            let mut index = 0;
            let rendered = self.render_value(&schema.nodes, &mut index, &mut atoms)?;
            Ok(rendered)
        };
        Ok(Some((render(actual)?, render(expected)?)))
    }
    /// Text of a dynamic `message:` argument: a string, or an int rendered in decimal.
    fn render_pointer_text(&self, vm: &IVM, pointer: u64) -> String {
        let Ok(tlv) = vm.validate_tlv(pointer) else {
            return "<unreadable message>".to_owned();
        };
        if tlv.type_id == PointerType::Blob {
            String::from_utf8_lossy(tlv.payload).into_owned()
        } else {
            let envelope = make_tlv(tlv.type_id, tlv.payload);
            self.render_leaf(StateValueKindV1::Int, &envelope)
                .unwrap_or_else(|_| "<unreadable message>".to_owned())
        }
    }
    /// Render one state value in Kotodama literal syntax.
    fn render_value<'a>(
        &self,
        nodes: &'a [StateValueNodeV1],
        index: &mut usize,
        atoms: &mut impl Iterator<Item = &'a StateValueAtomV1>,
    ) -> Result<String, String> {
        let truncated = || "value record ended early".to_owned();
        let node = nodes.get(*index).ok_or_else(truncated)?;
        *index += 1;
        match node {
            StateValueNodeV1::Unit => {
                atoms.next().ok_or_else(truncated)?;
                Ok("()".to_owned())
            }
            StateValueNodeV1::Error(error) => match atoms.next() {
                Some(StateValueAtomV1::ErrorCode(code)) => {
                    let enum_name = error
                        .identity
                        .rsplit("::")
                        .next()
                        .unwrap_or(&error.identity);
                    Ok(error.variant(*code).map_or_else(
                        || format!("{enum_name}::<code {code}>"),
                        |variant| format!("{enum_name}::{}", variant.name),
                    ))
                }
                _ => Err(truncated()),
            },
            StateValueNodeV1::Enum(error) => match atoms.next() {
                Some(StateValueAtomV1::EnumCode(code)) => {
                    let enum_name = error
                        .identity
                        .rsplit("::")
                        .next()
                        .unwrap_or(&error.identity);
                    Ok(error.variant(*code).map_or_else(
                        || format!("{enum_name}::<code {code}>"),
                        |variant| format!("{enum_name}::{}", variant.name),
                    ))
                }
                _ => Err(truncated()),
            },
            StateValueNodeV1::StateCursor(_) => match atoms.next() {
                Some(StateValueAtomV1::Pointer(envelope)) => {
                    Ok(render_state_cursor(tlv_payload(envelope)))
                }
                _ => Err(truncated()),
            },
            StateValueNodeV1::Struct { name, fields } => {
                let short = name.rsplit("::").next().unwrap_or(name);
                if fields.is_empty() {
                    return Ok(format!("{short} {{}}"));
                }
                let mut rendered = Vec::with_capacity(fields.len());
                for field in fields {
                    rendered.push(format!(
                        "{field}: {}",
                        self.render_value(nodes, index, atoms)?
                    ));
                }
                Ok(format!("{short} {{ {} }}", rendered.join(", ")))
            }
            StateValueNodeV1::Tuple { arity } => {
                let mut rendered = Vec::with_capacity(usize::from(*arity));
                for _ in 0..*arity {
                    rendered.push(self.render_value(nodes, index, atoms)?);
                }
                Ok(format!("({})", rendered.join(", ")))
            }
            StateValueNodeV1::Option => match atoms.next() {
                Some(StateValueAtomV1::Tag(true)) => Ok(format!(
                    "Option::some({})",
                    self.render_value(nodes, index, atoms)?
                )),
                Some(StateValueAtomV1::Tag(false)) => {
                    skip_value_node(nodes, index)?;
                    Ok("Option::none".to_owned())
                }
                _ => Err(truncated()),
            },
            StateValueNodeV1::Result => match atoms.next() {
                Some(StateValueAtomV1::Tag(true)) => {
                    let ok = self.render_value(nodes, index, atoms)?;
                    skip_value_node(nodes, index)?;
                    Ok(format!("Result::ok({ok})"))
                }
                Some(StateValueAtomV1::Tag(false)) => {
                    skip_value_node(nodes, index)?;
                    Ok(format!(
                        "Result::err({})",
                        self.render_value(nodes, index, atoms)?
                    ))
                }
                _ => Err(truncated()),
            },
            StateValueNodeV1::List { element, .. } => match atoms.next() {
                Some(StateValueAtomV1::List(items)) => {
                    let mut rendered = Vec::with_capacity(items.len());
                    for item in items {
                        let mut item_atoms = item.iter();
                        let mut item_index = 0;
                        rendered.push(self.render_value(
                            &element.nodes,
                            &mut item_index,
                            &mut item_atoms,
                        )?);
                    }
                    Ok(format!("[{}]", rendered.join(", ")))
                }
                _ => Err(truncated()),
            },
            StateValueNodeV1::Leaf(kind) => match atoms.next() {
                Some(StateValueAtomV1::Bool(value)) => Ok(value.to_string()),
                Some(StateValueAtomV1::Pointer(envelope)) => self.render_leaf(*kind, envelope),
                _ => Err(truncated()),
            },
        }
    }
    /// Render one scalar pointer value in Kotodama literal syntax.
    fn render_leaf(&self, kind: StateValueKindV1, envelope: &[u8]) -> Result<String, String> {
        let payload = tlv_payload(envelope);
        let quoted = |text: &str| kotodama_string_literal(text);
        let parsed =
            |constructor: &str, text: String| format!("{constructor}::parse({})", quoted(&text));
        Ok(match kind {
            StateValueKindV1::Int => ivm::numeric_tlv::decode_int_bytes(envelope)
                .map_err(|error| error.to_string())?
                .to_string(),
            StateValueKindV1::Decimal => ivm::numeric_tlv::decode_decimal_bytes(envelope)
                .map_err(|error| error.to_string())?
                .to_string(),
            StateValueKindV1::Quantity => ivm::numeric_tlv::decode_quantity_bytes(envelope)
                .map_err(|error| error.to_string())?
                .to_string(),
            StateValueKindV1::Bool => {
                return Err("bool values are not pointers".to_owned());
            }
            StateValueKindV1::String => quoted(&String::from_utf8_lossy(payload)),
            StateValueKindV1::Bytes => kotodama_bytes_literal(payload),
            StateValueKindV1::Json => {
                let json: Json =
                    norito::decode_canonical(payload).map_err(|error| error.to_string())?;
                format!("Json::parse({})", quoted(json.get()))
            }
            StateValueKindV1::AccountId => {
                let account: AccountId =
                    norito::decode_canonical(payload).map_err(|error| error.to_string())?;
                let mut rendered = parsed("AccountId", account.to_string());
                if let Some(alias) = self.actor_alias(&account) {
                    let _ = write!(rendered, " /* actor \"{alias}\" */");
                } else if account == self.contract_subject() {
                    rendered.push_str(" /* seiyaku_subject */");
                }
                rendered
            }
            StateValueKindV1::AssetDefinitionId => {
                let asset: AssetDefinitionId =
                    norito::decode_canonical(payload).map_err(|error| error.to_string())?;
                parsed("AssetDefinitionId", asset.to_string())
            }
            StateValueKindV1::AssetId => {
                let asset: AssetId =
                    norito::decode_canonical(payload).map_err(|error| error.to_string())?;
                parsed("AssetId", asset.to_string())
            }
            StateValueKindV1::DomainId => {
                let domain: DomainId =
                    norito::decode_canonical(payload).map_err(|error| error.to_string())?;
                parsed("DomainId", domain.to_string())
            }
            StateValueKindV1::Name => {
                let name: Name =
                    norito::decode_canonical(payload).map_err(|error| error.to_string())?;
                parsed("Name", name.to_string())
            }
            StateValueKindV1::DataSpaceId => {
                let dataspace: DataSpaceId =
                    norito::decode_canonical(payload).map_err(|error| error.to_string())?;
                parsed("DataSpaceId", dataspace.as_u64().to_string())
            }
            other => format!(
                "<{} value, {} bytes>",
                state_kind_name(other),
                payload.len()
            ),
        })
    }
}
/// Opaque display of a state cursor. Cursors have no source literal; their canonical boundary
/// form is the `0x`-prefixed hexadecimal string, shown in full for short cursors and abbreviated
/// with its byte length otherwise.
fn render_state_cursor(bytes: &[u8]) -> String {
    const SHOWN_BYTES: usize = 8;
    if bytes.len() <= 2 * SHOWN_BYTES {
        return format!("StateCursor(0x{})", hex_lower(bytes));
    }
    format!(
        "StateCursor(0x{}\u{2026} /* {} bytes */)",
        hex_lower(&bytes[..SHOWN_BYTES]),
        bytes.len()
    )
}
/// Kotodama source name of a state-value leaf kind.
fn state_kind_name(kind: StateValueKindV1) -> &'static str {
    match kind {
        StateValueKindV1::Int => "int",
        StateValueKindV1::Decimal => "decimal",
        StateValueKindV1::Quantity => "quantity",
        StateValueKindV1::Bool => "bool",
        StateValueKindV1::String => "string",
        StateValueKindV1::Json => "Json",
        StateValueKindV1::Bytes => "bytes",
        StateValueKindV1::AccountId => "AccountId",
        StateValueKindV1::AssetDefinitionId => "AssetDefinitionId",
        StateValueKindV1::AssetId => "AssetId",
        StateValueKindV1::DomainId => "DomainId",
        StateValueKindV1::NftId => "NftId",
        StateValueKindV1::Name => "Name",
        StateValueKindV1::DataSpaceId => "DataSpaceId",
        StateValueKindV1::AxtDescriptor => "AxtDescriptor",
        StateValueKindV1::ProofBlob => "ProofBlob",
        StateValueKindV1::SoracloudRequest => "SoracloudRequest",
        StateValueKindV1::SoracloudResponse => "SoracloudResponse",
    }
}
/// Advance `index` past one complete schema subtree without consuming atoms.
fn skip_value_node(nodes: &[StateValueNodeV1], index: &mut usize) -> Result<(), String> {
    let mut remaining = 1_usize;
    while remaining > 0 {
        let node = nodes
            .get(*index)
            .ok_or_else(|| "value schema ended early".to_owned())?;
        *index += 1;
        remaining -= 1;
        remaining += match node {
            StateValueNodeV1::Struct { fields, .. } => fields.len(),
            StateValueNodeV1::Tuple { arity } => usize::from(*arity),
            StateValueNodeV1::Option => 1,
            StateValueNodeV1::Result => 2,
            _ => 0,
        };
    }
    Ok(())
}
/// Payload of a pointer-ABI TLV envelope (type, version, length, payload, hash).
fn tlv_payload(envelope: &[u8]) -> &[u8] {
    let Some(length) = envelope
        .get(3..7)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
    else {
        return &[];
    };
    envelope.get(7..7 + length as usize).unwrap_or(&[])
}
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
/// Kotodama string literal for `text`, using the language's escape set.
fn kotodama_string_literal(text: &str) -> String {
    let mut literal = String::with_capacity(text.len() + 2);
    literal.push('"');
    for character in text.chars() {
        match character {
            '\\' => literal.push_str("\\\\"),
            '"' => literal.push_str("\\\""),
            '\n' => literal.push_str("\\n"),
            '\r' => literal.push_str("\\r"),
            '\t' => literal.push_str("\\t"),
            '\0' => literal.push_str("\\0"),
            character if character.is_control() => {
                let _ = write!(literal, "\\u{{{:x}}}", u32::from(character));
            }
            character => literal.push(character),
        }
    }
    literal.push('"');
    literal
}
/// Kotodama byte-string literal (`b"..."`) for `bytes`, escaping non-printable bytes as `\xNN`.
fn kotodama_bytes_literal(bytes: &[u8]) -> String {
    let mut literal = String::from("b\"");
    for byte in bytes {
        match byte {
            b'\\' => literal.push_str("\\\\"),
            b'"' => literal.push_str("\\\""),
            0x20..=0x7e => literal.push(char::from(*byte)),
            other => {
                let _ = write!(literal, "\\x{other:02x}");
            }
        }
    }
    literal.push('"');
    literal
}
/// Ed25519 account controlled by a 32-byte fixture seed.
fn account_for_seed(seed: &[u8; 32]) -> Result<AccountId, String> {
    let signing_key = SigningKey::from_bytes(seed);
    let public_key = iroha_crypto::PublicKey::from_bytes(
        iroha_crypto::Algorithm::Ed25519,
        signing_key.verifying_key().as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    Ok(AccountId::new(public_key))
}
/// Deterministic signing seed for a named fixture actor.
///
/// The seed binds the alias and the chain discriminant under a fixed domain, so `actor("alice")`
/// gives the same account in every run and on every machine, and suites compiled for different
/// networks never share actor keys. These keys are test-only and never valid on any network.
fn derived_actor_seed(alias: &str, chain_discriminant: u16) -> [u8; 32] {
    let mut preimage = b"iroha:kotodama:koto-test:actor:v1\0".to_vec();
    preimage.extend_from_slice(&chain_discriminant.to_le_bytes());
    preimage.extend_from_slice(alias.as_bytes());
    iroha_crypto::Hash::new(&preimage).into()
}
/// Source maps and file text used to locate failures and trace steps.
struct SourceContext {
    seiyaku_name: String,
    files: SourceFiles,
    /// Compiler source identities mapped to their logical source names.
    source_names: BTreeMap<u32, String>,
    harness: Vec<ivm_abi::metadata::EmbeddedSourceMapEntryV1>,
    harness_base: u64,
    runtime: Vec<ivm_abi::metadata::EmbeddedSourceMapEntryV1>,
    runtime_base: u64,
    runtime_hash: Option<iroha_crypto::Hash>,
    harness_hash: Option<iroha_crypto::Hash>,
}
impl SourceContext {
    /// Context with no source maps, for hosts built outside a compiled suite.
    #[cfg(test)]
    fn empty(seiyaku_name: &str) -> Self {
        Self {
            seiyaku_name: seiyaku_name.to_owned(),
            files: SourceFiles::default(),
            source_names: BTreeMap::new(),
            harness: Vec::new(),
            harness_base: 0,
            runtime: Vec::new(),
            runtime_base: 0,
            runtime_hash: None,
            harness_hash: None,
        }
    }
    fn lookup(
        map: &[ivm_abi::metadata::EmbeddedSourceMapEntryV1],
        base: u64,
        pc: u64,
    ) -> Option<&ivm_abi::metadata::EmbeddedSourceMapEntryV1> {
        map.iter().find(|entry| {
            base.saturating_add(entry.pc_start) <= pc && pc < base.saturating_add(entry.pc_end)
        })
    }
    /// `path:line:column` and trimmed source line of a byte offset in a compiler source.
    fn locate_site(&self, source_id: u32, byte_start: usize) -> Option<(String, String)> {
        let name = self.source_names.get(&source_id)?;
        self.files.locate(name, byte_start)
    }
    /// Source text of a byte range on one line (see [`one_line_source`]).
    fn site_text(&self, source_id: u32, start: usize, end: usize) -> Option<String> {
        let name = self.source_names.get(&source_id)?;
        let (_, text) = self.files.get(name)?;
        let snippet = text
            .get(start..end)
            .filter(|snippet| !snippet.trim().is_empty())?;
        Some(one_line_source(snippet))
    }
    /// Source-map entry of the harness function executing at `pc`.
    fn harness_function(&self, pc: u64) -> Option<&ivm_abi::metadata::EmbeddedSourceMapEntryV1> {
        Self::lookup(&self.harness, self.harness_base, pc)
    }
    /// Source-map entry of the seiyaku function executing at `pc`.
    fn runtime_function(&self, pc: u64) -> Option<&ivm_abi::metadata::EmbeddedSourceMapEntryV1> {
        Self::lookup(&self.runtime, self.runtime_base, pc)
    }
    /// `path:line:column` of a source-map entry's declaration.
    fn entry_location(&self, entry: &ivm_abi::metadata::EmbeddedSourceMapEntryV1) -> String {
        let path = entry
            .source
            .source_path
            .as_deref()
            .and_then(|name| self.files.get(name))
            .map_or_else(
                || entry.source.source_path.clone().unwrap_or_default(),
                |(path, _)| display_path(path),
            );
        format!("{path}:{}:{}", entry.source.line, entry.source.column)
    }
    /// ``in `withdraw` (contracts/vault.ko:15:5)`` for a seiyaku PC.
    fn runtime_site(&self, pc: u64) -> Option<String> {
        self.runtime_function(pc).map(|entry| {
            format!(
                "in `{}` ({})",
                entry.function_name,
                self.entry_location(entry)
            )
        })
    }
    /// Classify a nested seiyaku failure and locate it in seiyaku source.
    fn classify_runtime_failure(&self, vm: &IVM, error: &ivm::VMError) -> TestFailure {
        let diagnostic = vm.last_diagnostic();
        let trap = diagnostic.map(|diagnostic| diagnostic.trap_kind);
        // Nominal aborts end execution without a trap snapshot; the stopped PC still names the
        // aborting function.
        let pc = diagnostic.map_or_else(|| vm.pc(), |diagnostic| diagnostic.pc);
        let fault = vm.execution_fault(error, IvmFaultPositionV1::ReturnValidation);
        let site = match fault {
            Some(fault) if Some(fault.site.code_hash) == self.runtime_hash => {
                match fault.site.position {
                    IvmFaultPositionV1::Execute { pc_offset } => {
                        self.runtime_site(self.runtime_base.saturating_add(pc_offset))
                    }
                    _ => None,
                }
            }
            Some(_) => None,
            None => self.runtime_site(pc),
        };
        let mut failure = classify_vm_error(error, trap);
        failure.fault = fault;
        if let Some(site) = site {
            failure.message = if failure.message.is_empty() {
                site
            } else {
                format!("{} {site}", failure.message)
            };
        }
        failure
    }
}
/// The candidate closest to `name` by the compiler's suggestion distance (insertions, deletions,
/// substitutions and adjacent transpositions, ASCII case-insensitive), when it is a plausible
/// misspelling: at most two edits, or one third of the name, whichever is smaller. Ties keep the
/// earliest candidate.
fn closest_name<'a>(name: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let limit = (name.chars().count() / 3).clamp(1, 2);
    candidates
        .iter()
        .filter_map(|candidate| {
            kotodama_lang::diagnostic::suggest::edit_distance(name, candidate, limit)
                .map(|distance| (distance, *candidate))
        })
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate)
}
/// Render a possibly multi-line source excerpt on one line, as a call would be written inline.
///
/// A single-line excerpt is kept as written. In a multi-line one, outside string literals, line
/// comments are dropped, runs of whitespace become one space, no space follows an opening `(` or
/// `[` or precedes a closing one, a closing `}` keeps one space before it, and a trailing comma
/// before a closing bracket is dropped. String literals, including raw `r"..."` and `br"..."`
/// strings whose backslashes are not escapes, are copied unchanged.
fn one_line_source(snippet: &str) -> String {
    let snippet = snippet.trim();
    if !snippet.contains('\n') {
        return snippet.to_owned();
    }
    let mut out = String::with_capacity(snippet.len());
    // `Some(raw)` while inside a string literal.
    let mut string = None::<bool>;
    let mut escaped = false;
    let mut pending_space = false;
    let mut characters = snippet.chars().peekable();
    while let Some(character) = characters.next() {
        if let Some(raw) = string {
            out.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' && !raw {
                escaped = true;
            } else if character == '"' {
                string = None;
            }
            continue;
        }
        if character == '/' && characters.peek() == Some(&'/') {
            for skipped in characters.by_ref() {
                if skipped == '\n' {
                    break;
                }
            }
            pending_space = true;
            continue;
        }
        if character.is_whitespace() {
            pending_space = true;
            continue;
        }
        if matches!(character, ')' | ']' | '}') {
            while out.ends_with(' ') {
                out.pop();
            }
            if out.ends_with(',') {
                out.pop();
            }
            if character == '}' && !out.ends_with('{') {
                out.push(' ');
            }
        } else if pending_space && !out.ends_with(['(', '[']) && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        if character == '"' {
            string = Some(opens_raw_string(&out));
        }
        out.push(character);
    }
    out
}
/// Whether a string literal opening right after `prefix` is raw (`r"..."` or `br"..."`).
fn opens_raw_string(prefix: &str) -> bool {
    let Some(rest) = prefix.strip_suffix('r') else {
        return false;
    };
    let rest = rest.strip_suffix('b').unwrap_or(rest);
    !rest.ends_with(|character: char| character.is_alphanumeric() || character == '_')
}
/// Map a VM error to a failure kind with a readable message (no Rust debug formatting).
fn classify_vm_error(
    error: &ivm::VMError,
    trap: Option<ivm_abi::error::VmTrapKind>,
) -> TestFailure {
    use ivm_abi::error::VmTrapKind as Trap;
    if let ivm::VMError::ContractAbort {
        name,
        error_type,
        code,
        message,
        ..
    } = error.as_unmetered()
    {
        let mut failure = TestFailure::new(
            FailureKind::Rejected,
            format!("aborted with `{error_type}::{name}` (code {code})"),
        );
        if let Some(message) = message {
            failure = failure.detail(format!("message: {message}"));
        }
        return failure;
    }
    if let ivm::VMError::NumericFault(fault) = error.as_unmetered() {
        return numeric_fault_failure(*fault);
    }
    let kind = match trap {
        Some(Trap::PermissionDenied) => FailureKind::PermissionDenied,
        Some(Trap::NumericFault) => FailureKind::NumericFault,
        Some(Trap::OutOfGas | Trap::ExceededMaxCycles | Trap::SyscallGasQuoteExceeded) => {
            FailureKind::GasExhausted
        }
        Some(
            Trap::DecodeError
            | Trap::NoritoInvalid
            | Trap::PointerAbiFault
            | Trap::AbiTypeNotAllowed,
        ) => FailureKind::Decode,
        Some(Trap::AssertionFailed) => FailureKind::Assertion,
        _ => FailureKind::Trap,
    };
    let detail = error.to_string();
    let mut failure = TestFailure::new(kind, String::new());
    if !detail.is_empty() {
        failure.message = detail;
    }
    failure
}
/// Classify a numeric fault: its `kotodama::NumericError` variant and what went wrong, plus a
/// `help:` line where the source has a direct remedy.
///
/// Faults that only a malformed program can raise (an unknown rounding or failure mode, a
/// nonzero reserved register) are not source-visible errors and are reported by their ABI tag.
fn numeric_fault_failure(fault: ivm_abi::numeric::NumericFaultV1) -> TestFailure {
    use ivm_abi::numeric::NumericFaultV1 as Fault;
    const DIV_ROUND_HELP: &str = "help: choose a result scale and rounding with `div_round`";
    let (explanation, help) = match fault {
        Fault::MantissaOverflow => ("the result exceeds the 512-bit integer range", None),
        Fault::ScaleOverflow => (
            "the exact decimal result needs more than 28 decimal places",
            None,
        ),
        Fault::DivisionByZero => ("division by zero", None),
        Fault::RepeatingDecimal => (
            "the exact quotient has a non-terminating decimal expansion",
            Some(DIV_ROUND_HELP),
        ),
        Fault::ExactDivisionScaleOverflow => (
            "the exact quotient needs more than 28 decimal places",
            Some(DIV_ROUND_HELP),
        ),
        Fault::InvalidScale => ("a requested scale is outside 0..=28", None),
        Fault::InexactConversion => (
            "the conversion would discard a fractional part or exceed the target type",
            None,
        ),
        Fault::NegativeQuantity => ("a negative value cannot become a `quantity`", None),
        Fault::QuantityUnderflow => ("`quantity` subtraction would go below zero", None),
        Fault::NegativeSquareRoot => ("the square root operand is negative", None),
        Fault::InvalidRoundingMode | Fault::InvalidFailureMode | Fault::ReservedRegisterNonZero => {
            return TestFailure::new(
                FailureKind::NumericFault,
                format!(
                    "a numeric instruction violated its VM contract (ABI fault {})",
                    fault.tag()
                ),
            )
            .detail("help: this is a toolchain defect; report it with a minimal reproducer");
        }
    };
    let descriptor = ivm_abi::error_types::numeric_error_type();
    let message = u32::try_from(fault.tag())
        .ok()
        .and_then(|code| descriptor.variant(code))
        .map_or_else(
            || format!("{explanation} (ABI fault {})", fault.tag()),
            |variant| {
                format!(
                    "`{}::{}` ({explanation})",
                    descriptor.identity, variant.name
                )
            },
        );
    let failure = TestFailure::new(FailureKind::NumericFault, message);
    match help {
        Some(help) => failure.detail(help),
        None => failure,
    }
}
fn expect_arg_count(action: &FixtureAction, expected: usize) -> Result<(), String> {
    if action.args.len() == expected {
        return Ok(());
    }
    Err(format!(
        "fixture action `{}` expects {} arguments, got {}",
        action.name,
        expected,
        action.args.len()
    ))
}
fn eval_actor_alias_expr(expr: &Expr) -> Result<String, String> {
    match expr {
        Expr::String(raw) | Expr::Ident(raw) => Ok(raw.clone()),
        other => Err(format!(
            "expected an actor alias string such as \"alice\", got {}",
            describe_expr(other)
        )),
    }
}
/// Resolve an account argument: a declared actor alias, `seiyaku_subject`, or an account literal.
fn resolve_fixture_account(raw: &str, host: &KotoTestHost) -> Result<AccountId, String> {
    if raw == "seiyaku_subject" {
        return Ok(host.contract_subject());
    }
    if let Some(account) = host.actor_account(raw) {
        return Ok(account);
    }
    parse_account_literal(raw).map_err(|_| {
        let mut actors = host.actors.keys().cloned().collect::<Vec<_>>();
        actors.sort();
        if actors.is_empty() {
            format!(
                "`{raw}` is neither a declared actor nor an account literal; declare it first with `actor(\"{raw}\");`"
            )
        } else {
            format!(
                "`{raw}` is neither a declared actor nor an account literal; declared actors: {}",
                actors
                    .iter()
                    .map(|actor| format!("`{actor}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    })
}
fn eval_fixture_account_or_actor(expr: &Expr, host: &KotoTestHost) -> Result<AccountId, String> {
    match expr {
        Expr::String(raw) | Expr::Ident(raw) => resolve_fixture_account(raw, host),
        Expr::Call { name, args, .. } if name == "AccountId::parse" => {
            if args.len() != 1 {
                return Err(format!("`{name}` expects exactly one argument"));
            }
            resolve_fixture_account(&eval_string_expr(&args[0])?, host)
        }
        other => Err(format!(
            "expected an actor alias, `seiyaku_subject`, or `AccountId::parse(\"...\")`, got {}",
            describe_expr(other)
        )),
    }
}
fn decode_hex_or_raw_bytes(raw: &str) -> Result<Vec<u8>, String> {
    if let Some(hex) = raw.strip_prefix("0x") {
        if hex.len() % 2 != 0 {
            return Err(format!(
                "invalid hex literal `{raw}`: expected even-length hex digits"
            ));
        }
        let mut out = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.as_bytes().chunks(2) {
            let byte_str = std::str::from_utf8(chunk)
                .map_err(|err| format!("invalid hex literal `{raw}`: {err}"))?;
            let byte = u8::from_str_radix(byte_str, 16)
                .map_err(|err| format!("invalid hex literal `{raw}`: {err}"))?;
            out.push(byte);
        }
        return Ok(out);
    }
    Ok(raw.as_bytes().to_vec())
}
fn eval_seed_expr(expr: &Expr) -> Result<[u8; 32], String> {
    let bytes = match expr {
        Expr::Bytes(bytes) => bytes.clone(),
        Expr::String(raw) | Expr::Ident(raw) => decode_hex_or_raw_bytes(raw)?,
        other => {
            return Err(format!(
                "expected a 32-byte seed as a \"0x...\" hex string, got {}",
                describe_expr(other)
            ));
        }
    };
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("seed must be exactly 32 bytes, got {}", bytes.len()))
}
fn eval_account_expr(expr: &Expr) -> Result<AccountId, String> {
    match expr {
        Expr::String(raw) | Expr::Ident(raw) => parse_account_literal(raw),
        Expr::Call { name, args, .. } if name == "AccountId::parse" => {
            if args.len() != 1 {
                return Err(format!("`{name}` expects exactly one argument"));
            }
            let raw = eval_string_expr(&args[0])?;
            parse_account_literal(&raw)
        }
        other => Err(format!(
            "expected `AccountId::parse(\"...\")` or an account literal, got {}",
            describe_expr(other)
        )),
    }
}
fn eval_domain_expr(expr: &Expr) -> Result<DomainId, String> {
    match expr {
        Expr::String(raw) | Expr::Ident(raw) => parse_domain_literal(raw),
        Expr::Call { name, args, .. } if name == "DomainId::parse" => {
            if args.len() != 1 {
                return Err(format!("`{name}` expects exactly one argument"));
            }
            let raw = eval_string_expr(&args[0])?;
            parse_domain_literal(&raw)
        }
        other => Err(format!(
            "expected `DomainId::parse(\"...\")`, got {}",
            describe_expr(other)
        )),
    }
}
fn eval_asset_definition_expr(expr: &Expr) -> Result<AssetDefinitionId, String> {
    match expr {
        Expr::String(raw) | Expr::Ident(raw) => AssetDefinitionId::parse_address_literal(raw)
            .map_err(|_| format!("invalid asset definition id `{raw}`")),
        Expr::Call { name, args, .. } if name == "AssetDefinitionId::parse" => {
            if args.len() != 1 {
                return Err("`AssetDefinitionId::parse` expects exactly one argument".to_string());
            }
            let raw = eval_string_expr(&args[0])?;
            AssetDefinitionId::parse_address_literal(&raw)
                .map_err(|_| format!("invalid asset definition id `{raw}`"))
        }
        other => Err(format!(
            "expected `AssetDefinitionId::parse(\"...\")`, got {}",
            describe_expr(other)
        )),
    }
}
fn eval_name_expr(expr: &Expr) -> Result<Name, String> {
    match expr {
        Expr::String(raw) | Expr::Ident(raw) => {
            Name::from_str(raw).map_err(|_| format!("invalid name `{raw}`"))
        }
        Expr::Call { name, args, .. } if name == "Name::parse" => {
            if args.len() != 1 {
                return Err("`Name::parse` expects exactly one argument".to_string());
            }
            let raw = eval_string_expr(&args[0])?;
            Name::from_str(&raw).map_err(|_| format!("invalid name `{raw}`"))
        }
        other => Err(format!(
            "expected `Name::parse(\"...\")`, got {}",
            describe_expr(other)
        )),
    }
}
fn eval_string_expr(expr: &Expr) -> Result<String, String> {
    match expr {
        Expr::String(raw) | Expr::Ident(raw) | Expr::DecimalLiteral(raw) => Ok(raw.clone()),
        Expr::IntLiteral(value) => Ok(value.to_string()),
        Expr::Bool(value) => Ok(value.to_string()),
        other => Err(format!(
            "expected a string literal, got {}",
            describe_expr(other)
        )),
    }
}
fn eval_numeric_expr(expr: &Expr, environment: &FixtureEnvironment<'_>) -> Result<Numeric, String> {
    let value = eval_constant_number(expr, environment, 0)?;
    if value.mantissa.is_negative() {
        return Err(format!(
            "negative balances are not allowed: {}",
            format_fixed_point(&value.mantissa, value.scale)
        ));
    }
    value.into_numeric()
}
fn eval_quantity_expr(
    expr: &Expr,
    environment: &FixtureEnvironment<'_>,
) -> Result<Quantity, String> {
    let numeric = eval_numeric_expr(expr, environment)?;
    Quantity::try_from_numeric(numeric)
        .map_err(|error| format!("balance must be a non-negative quantity: {error}"))
}
fn eval_u64_expr(expr: &Expr, environment: &FixtureEnvironment<'_>) -> Result<u64, String> {
    let value = eval_constant_number(expr, environment, 0)?;
    if value.scale != 0 {
        return Err(format!(
            "expected an unsigned integer, got {}",
            format_fixed_point(&value.mantissa, value.scale)
        ));
    }
    value.mantissa.try_to_u64().ok_or_else(|| {
        format!(
            "expected an unsigned 64-bit integer, got {}",
            value.mantissa
        )
    })
}
fn eval_mintable_expr(expr: &Expr) -> Result<Mintable, String> {
    let raw = eval_string_expr(expr)?.to_ascii_lowercase();
    match raw.as_str() {
        "+" | "infinite" | "infinitely" => Ok(Mintable::Infinitely),
        "=" | "once" => Ok(Mintable::Once),
        "-" | "not" | "never" => Ok(Mintable::Not),
        other => Err(format!("unsupported mintability `{other}`")),
    }
}
fn eval_permission_expr(expr: &Expr, host: &KotoTestHost) -> Result<PermissionToken, String> {
    let account = |raw: &str| resolve_fixture_account(raw, host);
    match expr {
        Expr::String(raw) | Expr::Ident(raw) => parse_permission_token_name(raw, &account),
        Expr::Call { name, args, .. } if name == "Json::parse" => {
            if args.len() != 1 {
                return Err("`Json::parse` expects exactly one argument".to_string());
            }
            let payload = eval_json_payload(args)?;
            parse_permission_token_json(&payload, &account)
        }
        other => Err(format!(
            "expected a permission name or `Json::parse(\"...\")`, got {}",
            describe_expr(other)
        )),
    }
}
fn eval_metadata_bytes(expr: &Expr) -> Result<Vec<u8>, String> {
    match expr {
        Expr::String(raw) | Expr::DecimalLiteral(raw) | Expr::Ident(raw) => {
            Ok(raw.as_bytes().to_vec())
        }
        Expr::IntLiteral(value) => Ok(value.to_string().into_bytes()),
        Expr::Bool(value) => Ok(value.to_string().into_bytes()),
        Expr::Call { name, args, .. } if name == "Json::parse" => {
            Ok(eval_json_payload(args)?.into_bytes())
        }
        other => Err(format!(
            "unsupported account metadata value: {}",
            describe_expr(other)
        )),
    }
}
fn eval_state_payload_expr(expr: &Expr) -> Result<Vec<u8>, String> {
    let (kind, atom) = match expr {
        Expr::Bool(value) => (StateValueKindV1::Bool, StateValueAtomV1::Bool(*value)),
        Expr::IntLiteral(value) => (
            StateValueKindV1::Int,
            StateValueAtomV1::Pointer(
                ivm_abi::numeric_tlv::encode_int(value)
                    .map_err(|error| format!("invalid int state value: {error}"))?,
            ),
        ),
        Expr::DecimalLiteral(raw) => {
            let value = raw
                .replace('_', "")
                .parse::<Numeric>()
                .map_err(|_| format!("invalid decimal state fixture `{raw}`"))?;
            let value = DecimalValueV1::try_from_numeric(value)
                .map_err(|error| format!("invalid decimal state value: {error}"))?;
            (
                StateValueKindV1::Decimal,
                StateValueAtomV1::Pointer(
                    ivm_abi::numeric_tlv::encode_decimal(value.as_numeric())
                        .map_err(|error| format!("invalid decimal state value: {error}"))?,
                ),
            )
        }
        Expr::String(raw) | Expr::Ident(raw) => (
            StateValueKindV1::String,
            StateValueAtomV1::Pointer(make_tlv(PointerType::Blob, raw.as_bytes())),
        ),
        Expr::Bytes(bytes) => (
            StateValueKindV1::Bytes,
            StateValueAtomV1::Pointer(make_tlv(PointerType::Blob, bytes)),
        ),
        Expr::Call { name, .. } if name == "Json::parse" => (
            StateValueKindV1::Json,
            StateValueAtomV1::Pointer(eval_envelope_expr(expr)?),
        ),
        Expr::Call { name, .. } if name == "AccountId::parse" => (
            StateValueKindV1::AccountId,
            StateValueAtomV1::Pointer(eval_envelope_expr(expr)?),
        ),
        Expr::Call { name, .. } if name == "AssetDefinitionId::parse" => (
            StateValueKindV1::AssetDefinitionId,
            StateValueAtomV1::Pointer(eval_envelope_expr(expr)?),
        ),
        Expr::Call { name, .. } if name == "DomainId::parse" => (
            StateValueKindV1::DomainId,
            StateValueAtomV1::Pointer(eval_envelope_expr(expr)?),
        ),
        Expr::Call { name, .. } if name == "Name::parse" => (
            StateValueKindV1::Name,
            StateValueAtomV1::Pointer(eval_envelope_expr(expr)?),
        ),
        other => {
            return Err(format!("unsupported state value: {}", describe_expr(other)));
        }
    };
    encode_state_leaf(kind, atom)
}
fn encode_state_leaf(kind: StateValueKindV1, atom: StateValueAtomV1) -> Result<Vec<u8>, String> {
    let schema = StateValueSchemaV1 {
        nodes: vec![StateValueNodeV1::Leaf(kind)],
    };
    if !schema.validate_atoms(std::slice::from_ref(&atom)) {
        return Err(format!("invalid {} state value", state_kind_name(kind)));
    }
    let schema_bytes = norito::encode_canonical(&schema)
        .map_err(|error| format!("failed to encode state fixture schema: {error}"))?;
    norito::encode_canonical(&StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&schema_bytes),
        atoms: vec![atom],
    })
    .map_err(|error| format!("failed to encode state fixture record: {error}"))
}
fn eval_envelope_expr(expr: &Expr) -> Result<Vec<u8>, String> {
    match expr {
        Expr::Bool(value) => make_norito_envelope(value),
        Expr::IntLiteral(value) => ivm_abi::numeric_tlv::encode_int(value)
            .map_err(|error| format!("invalid int fixture value: {error}")),
        Expr::DecimalLiteral(raw) => {
            let value = raw
                .replace('_', "")
                .parse::<Numeric>()
                .map_err(|_| format!("invalid decimal fixture value `{raw}`"))?;
            ivm_abi::numeric_tlv::encode_decimal(&value)
                .map_err(|error| format!("invalid decimal fixture value: {error}"))
        }
        Expr::String(raw) | Expr::Ident(raw) => Ok(make_tlv(PointerType::Blob, raw.as_bytes())),
        Expr::Bytes(bytes) => Ok(make_tlv(PointerType::Blob, bytes)),
        Expr::Call { name, args, .. } if name == "Json::parse" => {
            let payload = eval_json_payload(args)?;
            let value = Json::from_str_norito(&payload)
                .map_err(|error| format!("invalid JSON fixture value: {error}"))?;
            let encoded = norito::encode_canonical(&value)
                .map_err(|error| format!("failed to encode JSON fixture value: {error}"))?;
            Ok(make_tlv(PointerType::Json, &encoded))
        }
        Expr::Call { name, args, .. } if name == "AccountId::parse" => {
            if args.len() != 1 {
                return Err(format!("`{name}` expects exactly one argument"));
            }
            let account = eval_account_expr(expr)?;
            let bytes = norito::encode_canonical(&account)
                .map_err(|err| format!("failed to encode account id: {err}"))?;
            Ok(make_tlv(PointerType::AccountId, &bytes))
        }
        Expr::Call { name, args, .. } if name == "AssetDefinitionId::parse" => {
            if args.len() != 1 {
                return Err("`AssetDefinitionId::parse` expects exactly one argument".to_string());
            }
            let asset = eval_asset_definition_expr(expr)?;
            let bytes = norito::encode_canonical(&asset)
                .map_err(|err| format!("failed to encode asset definition id: {err}"))?;
            Ok(make_tlv(PointerType::AssetDefinitionId, &bytes))
        }
        Expr::Call { name, args, .. } if name == "DomainId::parse" => {
            if args.len() != 1 {
                return Err(format!("`{name}` expects exactly one argument"));
            }
            let domain = eval_domain_expr(expr)?;
            let bytes = norito::encode_canonical(&domain)
                .map_err(|err| format!("failed to encode domain id: {err}"))?;
            Ok(make_tlv(PointerType::DomainId, &bytes))
        }
        Expr::Call { name, args, .. } if name == "Name::parse" => {
            if args.len() != 1 {
                return Err("`Name::parse` expects exactly one argument".to_string());
            }
            let name = eval_name_expr(expr)?;
            let bytes = norito::encode_canonical(&name)
                .map_err(|err| format!("failed to encode name: {err}"))?;
            Ok(make_tlv(PointerType::Name, &bytes))
        }
        other => Err(format!(
            "unsupported fixture value: {}",
            describe_expr(other)
        )),
    }
}
fn eval_json_payload(args: &[Expr]) -> Result<String, String> {
    if args.len() != 1 {
        return Err("`Json::parse` expects exactly one argument".to_string());
    }
    match &args[0] {
        Expr::String(raw) => Ok(raw.clone()),
        other => Err(format!(
            "`Json::parse` expects a string literal, got {}",
            describe_expr(other)
        )),
    }
}
fn make_norito_envelope<T: norito::NoritoSerialize>(value: &T) -> Result<Vec<u8>, String> {
    let bytes = norito::encode_canonical(value)
        .map_err(|err| format!("failed to encode canonical Norito value: {err}"))?;
    Ok(make_tlv(PointerType::NoritoBytes, &bytes))
}
fn make_tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    // All callers pass bounded source literals, canonical fixture values, or VM-validated TLVs.
    let payload_len = u32::try_from(payload.len()).expect("test pointer payload exceeds V1 bound");
    let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(payload);
    let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    out.extend_from_slice(&hash);
    out
}
fn parse_account_literal(raw: &str) -> Result<AccountId, String> {
    AccountId::parse_encoded(raw)
        .or_else(|_| {
            raw.parse::<iroha_data_model::smart_contract::ContractAddress>()
                .map(|address| address.subject_id())
        })
        .or_else(|_| raw.parse::<iroha_crypto::PublicKey>().map(AccountId::new))
        .map_err(|_| format!("invalid account id `{raw}`"))
}
fn default_caller_account() -> Result<AccountId, String> {
    let _chain_discriminant = ChainDiscriminantGuard::enter(753);
    parse_account_literal(DEFAULT_CALLER)
}
fn parse_domain_literal(raw: &str) -> Result<DomainId, String> {
    if raw.contains('.') {
        return DomainId::parse_fully_qualified(raw)
            .map_err(|_| format!("invalid domain id `{raw}`"));
    }
    DomainId::try_new(raw, "universal").map_err(|_| format!("invalid domain id `{raw}`"))
}
fn parse_permission_token_name(
    raw: &str,
    parse_account_literal: &dyn Fn(&str) -> Result<AccountId, String>,
) -> Result<PermissionToken, String> {
    if raw == "register_domain" {
        return Ok(PermissionToken::RegisterDomain);
    }
    if raw == "register_account" {
        return Ok(PermissionToken::RegisterAccount);
    }
    if raw == "register_asset_definition" {
        return Ok(PermissionToken::RegisterAssetDefinition);
    }
    if let Some(rest) = raw.strip_prefix("read_assets:") {
        return Ok(PermissionToken::ReadAccountAssets(parse_account_literal(
            rest,
        )?));
    }
    if let Some(rest) = raw.strip_prefix("add_signatory:") {
        return Ok(PermissionToken::AddSignatory(parse_account_literal(rest)?));
    }
    if let Some(rest) = raw.strip_prefix("remove_signatory:") {
        return Ok(PermissionToken::RemoveSignatory(parse_account_literal(
            rest,
        )?));
    }
    if let Some(rest) = raw.strip_prefix("set_account_quorum:") {
        return Ok(PermissionToken::SetAccountQuorum(parse_account_literal(
            rest,
        )?));
    }
    if let Some(rest) = raw.strip_prefix("set_account_metadata:") {
        return Ok(PermissionToken::SetAccountDetail(parse_account_literal(
            rest,
        )?));
    }
    if let Some(rest) = raw.strip_prefix("register_zk_asset:") {
        return Ok(PermissionToken::RegisterZkAsset(
            AssetDefinitionId::parse_address_literal(rest)
                .map_err(|_| format!("invalid asset definition id `{rest}`"))?,
        ));
    }
    if let Some(rest) = raw.strip_prefix("mint_asset:") {
        return Ok(PermissionToken::MintAsset(
            AssetDefinitionId::parse_address_literal(rest)
                .map_err(|_| format!("invalid asset definition id `{rest}`"))?,
        ));
    }
    if let Some(rest) = raw.strip_prefix("burn_asset:") {
        return Ok(PermissionToken::BurnAsset(
            AssetDefinitionId::parse_address_literal(rest)
                .map_err(|_| format!("invalid asset definition id `{rest}`"))?,
        ));
    }
    if let Some(rest) = raw.strip_prefix("transfer_asset:") {
        return Ok(PermissionToken::TransferAsset(
            AssetDefinitionId::parse_address_literal(rest)
                .map_err(|_| format!("invalid asset definition id `{rest}`"))?,
        ));
    }
    match raw {
        "manage_roles" => Ok(PermissionToken::ManageRoles),
        "manage_permissions" => Ok(PermissionToken::ManagePermissions),
        "manage_triggers" => Ok(PermissionToken::ManageTriggers),
        "manage_peers" => Ok(PermissionToken::ManagePeers),
        _ if !raw.is_empty() => Ok(PermissionToken::Custom(raw.to_string())),
        _ => Err("permission name must not be empty".to_string()),
    }
}
fn parse_permission_token_json(
    raw: &str,
    parse_account_literal: &dyn Fn(&str) -> Result<AccountId, String>,
) -> Result<PermissionToken, String> {
    let value: Value =
        json::from_str(raw).map_err(|err| format!("invalid permission json: {err}"))?;
    let map = value
        .as_object()
        .ok_or_else(|| "permission json must be an object".to_string())?;
    let kind = map
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "permission json is missing `type`".to_string())?;
    let target = |field: &str| -> Result<&str, String> {
        map.get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("permission json is missing `{field}`"))
    };
    let transfer_control_scope = || -> Result<(AssetDefinitionId, Name, DataSpaceId), String> {
        if map.len() != 4
            || !map.contains_key("type")
            || !map.contains_key("asset_definition")
            || !map.contains_key("account_domain")
            || !map.contains_key("account_dataspace")
        {
            return Err(
                "transfer-control permission json requires exactly type, asset_definition, account_domain, and account_dataspace"
                    .to_owned(),
            );
        }
        let asset_literal = target("asset_definition")?;
        let asset_definition = AssetDefinitionId::parse_address_literal(asset_literal)
            .map_err(|_| "invalid `asset_definition` canonical id".to_owned())?;
        let domain_literal = target("account_domain")?;
        let account_domain = Name::from_str(domain_literal)
            .map_err(|_| "invalid `account_domain` canonical Name".to_owned())?;
        if account_domain.as_ref() != domain_literal {
            return Err("`account_domain` is not canonically encoded".to_owned());
        }
        let account_dataspace = map
            .get("account_dataspace")
            .and_then(Value::as_u64)
            .map(DataSpaceId::new)
            .ok_or_else(|| "`account_dataspace` must be an unsigned integer".to_owned())?;
        Ok((asset_definition, account_domain, account_dataspace))
    };
    let exact_transfer_bucket = || -> Result<AssetId, String> {
        if map.len() != 2 || !map.contains_key("type") || !map.contains_key("asset") {
            return Err(
                "CanTransferAsset permission json requires exactly type and asset".to_owned(),
            );
        }
        let literal = target("asset")?;
        let asset = AssetId::parse_literal(literal)
            .map_err(|_| "invalid canonical `asset` balance-bucket id".to_owned())?;
        if asset.canonical_literal() != literal {
            return Err("`asset` balance-bucket id is not canonically encoded".to_owned());
        }
        Ok(asset)
    };
    let exact_account_asset_target =
        |permission: &str| -> Result<(AccountId, AssetDefinitionId), String> {
            if map.len() != 3
                || !map.contains_key("type")
                || !map.contains_key("account")
                || !map.contains_key("asset_definition")
            {
                return Err(format!(
                    "{permission} permission json requires exactly type, account, and asset_definition"
                ));
            }
            let account = parse_account_literal(target("account")?)?;
            let asset_definition =
                AssetDefinitionId::parse_address_literal(target("asset_definition")?)
                    .map_err(|_| "invalid `asset_definition` canonical id".to_owned())?;
            Ok((account, asset_definition))
        };
    match kind {
        "register_domain" => Ok(PermissionToken::RegisterDomain),
        "register_account" => Ok(PermissionToken::RegisterAccount),
        "register_asset_definition" => Ok(PermissionToken::RegisterAssetDefinition),
        "register_zk_asset" => Ok(PermissionToken::RegisterZkAsset(
            AssetDefinitionId::parse_address_literal(target("target")?)
                .map_err(|_| "invalid `target` asset definition id".to_string())?,
        )),
        "read_assets" => Ok(PermissionToken::ReadAccountAssets(parse_account_literal(
            target("target")?,
        )?)),
        "add_signatory" => Ok(PermissionToken::AddSignatory(parse_account_literal(
            target("target")?,
        )?)),
        "remove_signatory" => Ok(PermissionToken::RemoveSignatory(parse_account_literal(
            target("target")?,
        )?)),
        "set_account_quorum" => Ok(PermissionToken::SetAccountQuorum(parse_account_literal(
            target("target")?,
        )?)),
        "set_account_metadata" => Ok(PermissionToken::SetAccountDetail(parse_account_literal(
            target("target")?,
        )?)),
        "mint_asset" => Ok(PermissionToken::MintAsset(
            AssetDefinitionId::parse_address_literal(target("target")?)
                .map_err(|_| "invalid `target` asset definition id".to_string())?,
        )),
        "burn_asset" => Ok(PermissionToken::BurnAsset(
            AssetDefinitionId::parse_address_literal(target("target")?)
                .map_err(|_| "invalid `target` asset definition id".to_string())?,
        )),
        "transfer_asset" => Ok(PermissionToken::TransferAsset(
            AssetDefinitionId::parse_address_literal(target("target")?)
                .map_err(|_| "invalid `target` asset definition id".to_string())?,
        )),
        "CanTransferAsset" => Ok(PermissionToken::TransferAssetBucket(
            exact_transfer_bucket()?
        )),
        "CanSetAssetTransferAvailability" => {
            let (account, asset_definition) =
                exact_account_asset_target("CanSetAssetTransferAvailability")?;
            Ok(PermissionToken::SetAssetTransferAvailability {
                account,
                asset_definition,
            })
        }
        "CanSetAssetTransferDailyLimit" => {
            let (asset_definition, account_domain, account_dataspace) = transfer_control_scope()?;
            Ok(PermissionToken::SetAssetTransferDailyLimit {
                asset_definition,
                account_domain,
                account_dataspace,
            })
        }
        "CanSetAssetHoldingLimit" => {
            let (account, asset_definition) =
                exact_account_asset_target("CanSetAssetHoldingLimit")?;
            Ok(PermissionToken::SetAssetHoldingLimit {
                account,
                asset_definition,
            })
        }
        "manage_roles" => Ok(PermissionToken::ManageRoles),
        "manage_permissions" => Ok(PermissionToken::ManagePermissions),
        "manage_triggers" => Ok(PermissionToken::ManageTriggers),
        "manage_peers" => Ok(PermissionToken::ManagePeers),
        "custom" => Ok(PermissionToken::Custom(target("name")?.to_string())),
        other => Err(format!("unsupported permission type `{other}`")),
    }
}
/// `path:line:column` of a test declaration for display.
fn test_location(path: &Path, line: usize, column: usize) -> String {
    format!("{}:{line}:{column}", display_path(path))
}
/// Group decimal digits in threes for readable gas and cycle counts.
fn group_digits(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}
fn render_run_summary(suite: &DiscoveredSuite, results: &[TestRunResult]) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    let _ = writeln!(
        output,
        "running {} test{} for seiyaku `{}` ({})\n",
        results.len(),
        if results.len() == 1 { "" } else { "s" },
        suite.target_program.unit.name,
        display_path(&suite.target_path)
    );
    let locations = results
        .iter()
        .map(|result| test_location(&result.path, result.line, result.column))
        .collect::<Vec<_>>();
    let location_width = locations
        .iter()
        .map(|location| location.chars().count())
        .max()
        .unwrap_or(0);
    let width = results
        .iter()
        .map(|result| result.name.chars().count())
        .max()
        .unwrap_or(0);
    for (result, location) in results.iter().zip(&locations) {
        let status = if result.passed { "ok" } else { "FAILED" };
        let _ = writeln!(
            output,
            "{status:>6}  {location:<location_width$}  {:<width$}  gas {}, cycles {}, {:.2?}",
            result.name,
            group_digits(result.gas()),
            group_digits(result.cycles()),
            result.elapsed,
        );
    }
    let failed = results
        .iter()
        .filter(|result| !result.passed)
        .collect::<Vec<_>>();
    if !failed.is_empty() {
        output.push_str("\nfailures:\n");
        for result in &failed {
            let _ = writeln!(
                output,
                "\n---- {} ({}) ----",
                result.name,
                test_location(&result.path, result.line, result.column)
            );
            if let Some(failure) = &result.failure {
                let _ = writeln!(output, "{}", failure.render());
            }
        }
    }
    let passed = results.len() - failed.len();
    let _ = writeln!(
        output,
        "\nresult: {}. {passed} passed; {} failed; gas {}",
        if failed.is_empty() { "ok" } else { "FAILED" },
        failed.len(),
        group_digits(
            results
                .iter()
                .fold(0_u64, |total, result| total.saturating_add(result.gas()))
        )
    );
    output
}
fn print_run_summary(suite: &DiscoveredSuite, results: &[TestRunResult]) {
    print!("{}", render_run_summary(suite, results));
}
fn print_test_list(
    suite: &DiscoveredSuite,
    format: KotoTestReportFormat,
) -> Result<(), KotoTestCliError> {
    match format {
        KotoTestReportFormat::Human => {
            for test in &suite.tests {
                println!(
                    "{}: {}",
                    test_location(&test.path, test.line, test.column),
                    test.name
                );
            }
        }
        KotoTestReportFormat::Json => {
            let tests = suite
                .tests
                .iter()
                .map(|test| {
                    json::object(vec![
                        ("name".to_owned(), Value::from(test.name.clone())),
                        ("file".to_owned(), Value::from(display_path(&test.path))),
                        ("line".to_owned(), Value::from(test.line as u64)),
                        ("column".to_owned(), Value::from(test.column as u64)),
                        (
                            "fixture".to_owned(),
                            test.fixture.clone().map_or(Value::Null, Value::from),
                        ),
                    ])
                    .unwrap_or(Value::Null)
                })
                .collect();
            let value = json::object(vec![
                (
                    "target".to_owned(),
                    Value::from(display_path(&suite.target_path)),
                ),
                (
                    "seiyaku".to_owned(),
                    Value::from(suite.target_program.unit.name.clone()),
                ),
                ("tests".to_owned(), Value::Array(tests)),
            ])
            .map_err(|error| {
                KotoTestCliError::new(
                    KotoTestCliErrorKind::Internal,
                    format!("build test-list JSON: {error}"),
                )
            })?;
            println!(
                "{}",
                json::to_string_pretty(&value).map_err(|error| KotoTestCliError::new(
                    KotoTestCliErrorKind::Internal,
                    format!("serialize test-list JSON: {error}")
                ))?
            );
        }
        KotoTestReportFormat::Junit => {
            return Err(KotoTestCliError::new(
                KotoTestCliErrorKind::Usage,
                "JUnit output is not meaningful for `koto test list`",
            ));
        }
    }
    Ok(())
}
fn emit_test_results(
    suite: &DiscoveredSuite,
    results: &[TestRunResult],
    format: KotoTestReportFormat,
    seed: u64,
) -> Result<(), KotoTestCliError> {
    match format {
        KotoTestReportFormat::Human => print_run_summary(suite, results),
        KotoTestReportFormat::Json => println!(
            "{}",
            render_test_json(suite, results, seed)
                .map_err(|error| KotoTestCliError::new(KotoTestCliErrorKind::Internal, error))?
        ),
        KotoTestReportFormat::Junit => print!("{}", render_test_junit(suite, results, seed)),
    }
    Ok(())
}
fn failure_json(failure: &TestFailure) -> Value {
    json::object(vec![
        ("kind".to_owned(), Value::from(failure.kind.slug())),
        ("fault".to_owned(), norito::json!(failure.fault)),
        (
            "location".to_owned(),
            failure.location.clone().map_or(Value::Null, Value::from),
        ),
        ("message".to_owned(), Value::from(failure.message.clone())),
        (
            "details".to_owned(),
            Value::Array(failure.details.iter().cloned().map(Value::from).collect()),
        ),
        ("rendered".to_owned(), Value::from(failure.render())),
    ])
    .unwrap_or(Value::Null)
}
fn render_test_json(
    suite: &DiscoveredSuite,
    results: &[TestRunResult],
    seed: u64,
) -> Result<String, String> {
    let passed = results.iter().filter(|result| result.passed).count();
    let tests = results
        .iter()
        .map(|result| {
            json::object(vec![
                ("name".to_owned(), Value::from(result.name.clone())),
                ("file".to_owned(), Value::from(display_path(&result.path))),
                ("line".to_owned(), Value::from(result.line as u64)),
                ("column".to_owned(), Value::from(result.column as u64)),
                ("passed".to_owned(), Value::from(result.passed)),
                (
                    "duration_ns".to_owned(),
                    Value::from(u64::try_from(result.elapsed.as_nanos()).unwrap_or(u64::MAX)),
                ),
                ("gas".to_owned(), Value::from(result.gas())),
                ("cycles".to_owned(), Value::from(result.cycles())),
                (
                    "calls".to_owned(),
                    Value::Array(
                        result
                            .calls
                            .iter()
                            .map(|call| {
                                json::object(vec![
                                    ("kotoage".to_owned(), Value::from(call.entrypoint.clone())),
                                    ("gas".to_owned(), Value::from(call.gas)),
                                    ("cycles".to_owned(), Value::from(call.cycles)),
                                ])
                                .unwrap_or(Value::Null)
                            })
                            .collect(),
                    ),
                ),
                (
                    "failure".to_owned(),
                    result.failure.as_ref().map_or(Value::Null, failure_json),
                ),
            ])
            .unwrap_or(Value::Null)
        })
        .collect();
    let value = json::object(vec![
        (
            "target".to_owned(),
            Value::from(display_path(&suite.target_path)),
        ),
        (
            "seiyaku".to_owned(),
            Value::from(suite.target_program.unit.name.clone()),
        ),
        ("seed".to_owned(), Value::from(seed)),
        ("passed".to_owned(), Value::from(passed as u64)),
        (
            "failed".to_owned(),
            Value::from(results.len().saturating_sub(passed) as u64),
        ),
        ("tests".to_owned(), Value::Array(tests)),
    ])
    .map_err(|error| format!("build test JSON: {error}"))?;
    json::to_string_pretty(&value).map_err(|error| format!("serialize test JSON: {error}"))
}
fn render_test_junit(suite: &DiscoveredSuite, results: &[TestRunResult], seed: u64) -> String {
    use std::fmt::Write as _;
    let failed = results.iter().filter(|result| !result.passed).count();
    let duration = results
        .iter()
        .map(|result| result.elapsed.as_secs_f64())
        .sum::<f64>();
    let mut output = String::new();
    let _ = writeln!(output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let _ = writeln!(
        output,
        "<testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" time=\"{duration:.9}\" seed=\"{seed}\">",
        escape_xml(&suite.target_program.unit.name),
        results.len(),
        failed
    );
    for result in results {
        let file = display_path(&result.path);
        let _ = writeln!(
            output,
            "  <testcase name=\"{}\" classname=\"{}\" file=\"{}\" line=\"{}\" time=\"{:.9}\">",
            escape_xml(&result.name),
            escape_xml(&file),
            escape_xml(&file),
            result.line,
            result.elapsed.as_secs_f64()
        );
        let _ = writeln!(
            output,
            "    <properties>\n      <property name=\"gas\" value=\"{}\"/>\n      <property name=\"cycles\" value=\"{}\"/>\n    </properties>",
            result.gas(),
            result.cycles()
        );
        if let Some(failure) = &result.failure {
            let headline = failure.location.as_ref().map_or_else(
                || failure.kind.label().to_owned(),
                |location| format!("{} at {location}", failure.kind.label()),
            );
            let _ = writeln!(
                output,
                "    <failure type=\"{}\" message=\"{}\">{}</failure>",
                failure.kind.slug(),
                escape_xml(&headline),
                escape_xml(&failure.render())
            );
        }
        let _ = writeln!(output, "  </testcase>");
    }
    output.push_str("</testsuite>\n");
    output
}
fn escape_xml(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}
/// Per-kotoage gas table: calls, minimum, mean (rounded down), and maximum execution gas.
fn render_gas_report(results: &[TestRunResult]) -> String {
    use std::fmt::Write as _;
    let mut per_entrypoint = BTreeMap::<&str, Vec<u64>>::new();
    for call in results.iter().flat_map(|result| &result.calls) {
        per_entrypoint
            .entry(call.entrypoint.as_str())
            .or_default()
            .push(call.gas);
    }
    let mut output = String::from(
        "\ngas report: execution gas per seiyaku call (transaction admission fees excluded)\n",
    );
    if per_entrypoint.is_empty() {
        output.push_str("  no seiyaku calls were made\n");
        return output;
    }
    let width = per_entrypoint
        .keys()
        .map(|name| name.chars().count())
        .max()
        .unwrap_or(0)
        .max("kotoage".len());
    let _ = writeln!(
        output,
        "  {:<width$}  {:>6}  {:>12}  {:>12}  {:>12}",
        "kotoage", "calls", "min", "mean", "max"
    );
    for (entrypoint, gas) in per_entrypoint {
        let total = gas
            .iter()
            .fold(0_u128, |total, value| total + u128::from(*value));
        let mean = u64::try_from(total / gas.len() as u128).unwrap_or(u64::MAX);
        let _ = writeln!(
            output,
            "  {:<width$}  {:>6}  {:>12}  {:>12}  {:>12}",
            entrypoint,
            gas.len(),
            group_digits(gas.iter().copied().min().unwrap_or(0)),
            group_digits(mean),
            group_digits(gas.iter().copied().max().unwrap_or(0)),
        );
    }
    output
}
/// Function coverage of the seiyaku under test, computed only from seiyaku execution: nested
/// calls for a contract-backed suite, or the test projection for a pure unit-test target.
///
/// Each function row also counts the instructions it executed across the selected tests, a
/// function-level execution profile.
fn render_coverage_report(compiled: &CompiledSuite, results: &[TestRunResult]) -> String {
    use std::fmt::Write as _;
    let mut executions = BTreeMap::<u64, u64>::new();
    for result in results {
        let capture = if compiled.runtime.is_some() {
            result.trace.runtime.as_ref()
        } else {
            result.trace.harness.as_ref()
        };
        if let Some(trace) = capture {
            for pc in trace.pcs() {
                *executions.entry(*pc).or_default() += 1;
            }
        }
    }
    let executed_pcs = executions.keys().copied().collect::<HashSet<_>>();
    let total_functions = compiled.coverage_functions.len();
    let covered_functions = compiled
        .coverage_functions
        .iter()
        .filter(|function| function_hit(function, &executed_pcs))
        .count();
    let total_bytes = compiled
        .coverage_functions
        .iter()
        .map(|function| function.pc_end.saturating_sub(function.pc_start))
        .sum::<u64>();
    let covered_bytes = compiled
        .coverage_functions
        .iter()
        .filter(|function| function_hit(function, &executed_pcs))
        .map(|function| function.pc_end.saturating_sub(function.pc_start))
        .sum::<u64>();
    let function_pct = percentage(covered_functions as u64, total_functions as u64);
    let byte_pct = percentage(covered_bytes, total_bytes);
    let mut output = String::new();
    let _ = write!(
        output,
        "\ncoverage: {covered_functions}/{total_functions} functions ({function_pct:.1}%), {covered_bytes}/{total_bytes} bytecode-bytes ({byte_pct:.1}%)"
    );
    match compiled.codeless_functions.len() {
        0 => output.push('\n'),
        1 => output.push_str("; 1 more function has no code of its own\n"),
        count => {
            let _ = writeln!(output, "; {count} more functions have no code of their own");
        }
    }
    output.push_str("covered  line  instructions  function\n");
    let mut rows = compiled
        .coverage_functions
        .iter()
        .map(|function| {
            let covered = if function_hit(function, &executed_pcs) {
                "yes"
            } else {
                "no "
            };
            (
                function.line,
                format!(
                    "{covered:>7}  {:>4}  {:>12}  {}",
                    function.line,
                    group_digits(executed_instructions(function, &executions)),
                    function.display_name
                ),
            )
        })
        .collect::<Vec<_>>();
    // Inlined or unused functions are listed, not hidden, but have no coverage of their own.
    rows.extend(compiled.codeless_functions.iter().map(|function| {
        (
            function.line,
            format!(
                "{:>7}  {:>4}  {:>12}  {} (no code of its own: inlined into its callers or unused)",
                "-", function.line, "-", function.display_name
            ),
        )
    }));
    rows.sort_by_key(|(line, _)| *line);
    for (_, row) in rows {
        output.push_str(&row);
        output.push('\n');
    }
    output
}
/// Instructions executed inside one function's PC range, from per-PC execution counts.
fn executed_instructions(function: &CoverageFunction, executions: &BTreeMap<u64, u64>) -> u64 {
    executions
        .range(function.pc_start..function.pc_end)
        .fold(0_u64, |total, (_, count)| total.saturating_add(*count))
}
fn function_hit(function: &CoverageFunction, executed_pcs: &HashSet<u64>) -> bool {
    executed_pcs
        .iter()
        .any(|pc| function.pc_start <= *pc && *pc < function.pc_end)
}
#[expect(
    clippy::cast_precision_loss,
    reason = "Coverage percentages are display-only floating-point ratios; exact execution counters remain u64."
)]
fn percentage(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        100.0
    } else {
        (numerator as f64 / denominator as f64) * 100.0
    }
}
/// One executed instruction in `koto test trace` output.
struct TraceStep<'a> {
    segment: String,
    step: usize,
    pc: u64,
    function: Option<&'a str>,
    source: Option<String>,
    registers: Vec<(u64, u64)>,
}
/// Split a test's trace into the test function's steps and each seiyaku call's steps.
///
/// Statement locations survive SSA and inlining in the compiler's hash-bound source map.
/// Compiler-generated prologues and epilogues retain their containing function's location.
fn trace_steps<'a>(compiled: &'a CompiledSuite, result: &TestRunResult) -> Vec<TraceStep<'a>> {
    let context = &compiled.context;
    let mut steps = Vec::new();
    let mut push_capture = |capture: &ivm::zk::RuntimeTraceCapture,
                            segments: &mut dyn Iterator<Item = (String, usize)>,
                            runtime: bool| {
        let (mut segment, mut remaining) = segments
            .next()
            .unwrap_or_else(|| ("test".to_owned(), usize::MAX));
        let mut step = 0_usize;
        for (index, entry) in capture.deltas().enumerate() {
            while remaining == 0 {
                let (next, count) = segments
                    .next()
                    .unwrap_or_else(|| ("call".to_owned(), usize::MAX));
                segment = next;
                remaining = count;
                step = 0;
            }
            let mapped = if runtime {
                context.runtime_function(entry.pc)
            } else {
                context.harness_function(entry.pc)
            };
            let registers = entry
                .changes
                .iter()
                // The first recorded step snapshots every register; keep only nonzero ones.
                .filter(|(_, value, _)| index > 0 || *value != 0)
                .map(|(register, value, _)| (*register as u64, *value))
                .collect();
            steps.push(TraceStep {
                segment: segment.clone(),
                step,
                pc: entry.pc,
                function: mapped.map(|entry| entry.function_name.as_str()),
                source: mapped.map(|entry| context.entry_location(entry)),
                registers,
            });
            step += 1;
            remaining = remaining.saturating_sub(1);
        }
    };
    if let Some(harness) = &result.trace.harness {
        push_capture(
            harness,
            &mut std::iter::once(("test".to_owned(), usize::MAX)),
            false,
        );
    }
    if let Some(runtime) = &result.trace.runtime {
        let mut segments = result.calls.iter().enumerate().map(|(index, call)| {
            (
                format!("call {} `{}`", index + 1, call.entrypoint),
                call.trace_steps,
            )
        });
        push_capture(runtime, &mut segments, true);
    }
    steps
}
fn print_trace_report(
    compiled: &CompiledSuite,
    results: &[TestRunResult],
    format: KotoTestReportFormat,
) -> Result<(), String> {
    use std::fmt::Write as _;
    for result in results {
        let steps = trace_steps(compiled, result);
        match format {
            KotoTestReportFormat::Json => {
                for step in steps {
                    let value = json::object(vec![
                        ("test".to_owned(), Value::from(result.name.clone())),
                        ("segment".to_owned(), Value::from(step.segment)),
                        ("step".to_owned(), Value::from(step.step as u64)),
                        ("pc".to_owned(), Value::from(step.pc)),
                        (
                            "function".to_owned(),
                            step.function.map_or(Value::Null, Value::from),
                        ),
                        (
                            "source".to_owned(),
                            step.source.map_or(Value::Null, Value::from),
                        ),
                        (
                            "changed_registers".to_owned(),
                            Value::Array(
                                step.registers
                                    .iter()
                                    .map(|(register, value)| {
                                        json::object(vec![
                                            ("register".to_owned(), Value::from(*register)),
                                            ("value".to_owned(), Value::from(*value)),
                                        ])
                                        .unwrap_or(Value::Null)
                                    })
                                    .collect(),
                            ),
                        ),
                    ])
                    .map_err(|err| format!("failed to build trace record: {err}"))?;
                    println!(
                        "{}",
                        json::to_string(&value)
                            .map_err(|err| format!("failed to serialize trace record: {err}"))?
                    );
                }
            }
            KotoTestReportFormat::Human | KotoTestReportFormat::Junit => {
                let mut output = format!(
                    "trace {} ({})\n",
                    result.name,
                    test_location(&result.path, result.line, result.column)
                );
                let mut current = None::<String>;
                for step in steps {
                    if current.as_deref() != Some(step.segment.as_str()) {
                        let _ = writeln!(output, "  {}:", step.segment);
                        current = Some(step.segment.clone());
                    }
                    let registers = step
                        .registers
                        .iter()
                        .map(|(register, value)| format!("x{register}={value:#x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let _ = writeln!(
                        output,
                        "    {:>5}  pc {:#07x}  {:<20}  {:<28}  {registers}",
                        step.step,
                        step.pc,
                        step.function.unwrap_or("-"),
                        step.source.as_deref().unwrap_or("-"),
                    );
                }
                println!("{output}");
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::topology::DataSpaceId;
    include!("koto_test_driver_tests.rs");
}
